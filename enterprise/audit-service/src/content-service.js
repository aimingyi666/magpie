import crypto from "node:crypto";

import { ContentGrantError } from "./content-grant.js";
import { ContentRetrievalError } from "./content-retrieval.js";
import {
  AuditContentValidationError,
  CONTENT_PURPOSES,
  publicContentStream,
  validateContentRef,
  validateContentStreamRequest,
} from "./content-schema.js";
import { ContentStreamError } from "./content-streams.js";

const SCHEMA_VERSION = 1;
const IDEMPOTENCY_KEY_PATTERN = /^[\u0021-\u007e]{1,128}$/;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const ADMIN_SESSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{7,255}$/;
const APPROVAL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{7,127}$/;
const MAX_ACCESS_REASON_LENGTH = 1024;
const GRANT_REQUEST_FIELDS = new Set(["purpose", "reason", "approvalId", "ttlSeconds"]);
const PURPOSE_SET = new Set(CONTENT_PURPOSES);
const HOLD_ID_PATTERN = /^hld_[A-Za-z0-9_-]{43}$/;
const DELETION_ID_PATTERN = /^del_[A-Za-z0-9_-]{43}$/;
const EXPORT_ID_PATTERN = /^exp_[A-Za-z0-9_-]{43}$/;
const EFFECTIVE_HOLD_STATUSES = new Set([
  "active",
  "scheduled",
  "expired",
  "released",
]);

export class ContentApiError extends Error {
  constructor(statusCode, code, message, retryable = false) {
    super(message);
    this.name = "ContentApiError";
    this.statusCode = statusCode;
    this.code = code;
    this.retryable = retryable;
  }
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function bearerToken(req) {
  const match = /^Bearer\s+(\S+)$/i.exec(String(req.headers.authorization || "").trim());
  return match ? match[1] : "";
}

function jsonResponse(res, statusCode, value, reqId, headers = {}) {
  const body = JSON.stringify(value);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-request-id": reqId,
    ...headers,
  });
  res.end(body);
}

function idempotencyKey(req) {
  const key = String(req.headers["idempotency-key"] || "").trim();
  if (!IDEMPOTENCY_KEY_PATTERN.test(key)) {
    throw new ContentApiError(
      400,
      "idempotency_key_required",
      "A valid Idempotency-Key header is required",
    );
  }
  return key;
}

function queryValue(url, name, pattern, maximum = 192) {
  const value = url.searchParams.get(name);
  if (value == null || value === "") return "";
  if (value.length > maximum || !pattern.test(value)) {
    throw new ContentApiError(400, "invalid_query", `${name} is invalid`);
  }
  return value;
}

function queryTimestamp(url, name) {
  const value = url.searchParams.get(name);
  if (value == null || value === "") return "";
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new ContentApiError(400, "invalid_query", `${name} is invalid`);
  }
  return value;
}

function queryLimit(url, fallback = 100) {
  const value = url.searchParams.get("limit");
  if (value == null || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 500) {
    throw new ContentApiError(400, "invalid_query", "limit is invalid");
  }
  return parsed;
}

async function readJsonBody(req, maximumBytes) {
  const contentType = String(req.headers["content-type"] || "");
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new ContentApiError(415, "unsupported_media_type", "Content-Type must be application/json");
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > maximumBytes) {
      throw new ContentApiError(413, "content_request_too_large", "The content request exceeds the configured limit");
    }
    chunks.push(chunk);
  }
  if (bytes === 0) {
    throw new ContentApiError(400, "invalid_content_request", "A JSON request body is required");
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new ContentApiError(400, "invalid_json", "The request body must be valid JSON");
  }
}

function requireMethod(req, expected) {
  if (req.method !== expected) {
    throw new ContentApiError(405, "method_not_allowed", "Method not allowed");
  }
}

function accessReasonFromGrant(value) {
  if (typeof value !== "string"
      || value.length < 8
      || value.length > MAX_ACCESS_REASON_LENGTH
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new ContentApiError(
      400,
      "content_grant_reason_required",
      "A valid grant reason is required",
    );
  }
  return value;
}

function validateGrantRequest(value) {
  if (!value
      || typeof value !== "object"
      || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new ContentApiError(
      400,
      "invalid_content_grant",
      "The content grant request must be a JSON object",
    );
  }
  const unknown = Object.keys(value).find((key) => !GRANT_REQUEST_FIELDS.has(key));
  if (unknown) {
    throw new ContentApiError(
      400,
      "invalid_content_grant",
      `The content grant request contains an unknown field: ${unknown}`,
    );
  }
  if (!PURPOSE_SET.has(value.purpose)) {
    throw new ContentApiError(
      400,
      "content_grant_purpose_invalid",
      "A supported grant purpose is required",
    );
  }
  if (!APPROVAL_ID_PATTERN.test(String(value.approvalId || ""))) {
    throw new ContentApiError(
      400,
      "content_grant_approval_required",
      "A valid approvalId is required",
    );
  }
  if (value.ttlSeconds !== undefined
      && (!Number.isSafeInteger(value.ttlSeconds)
        || value.ttlSeconds < 15
        || value.ttlSeconds > 300)) {
    throw new ContentApiError(
      400,
      "content_grant_ttl_invalid",
      "ttlSeconds must be from 15 to 300",
    );
  }
  return {
    purpose: value.purpose,
    reason: accessReasonFromGrant(value.reason),
    approvalId: value.approvalId,
    ...(value.ttlSeconds !== undefined ? { ttlSeconds: value.ttlSeconds } : {}),
  };
}

function sourceHash(req, config) {
  const secret = config.contentEncryptionKey || config.serviceToken;
  const source = req.socket.remoteAddress || "unknown";
  return `sha256:${crypto.createHmac("sha256", secret).update(source).digest("hex")}`;
}

function publicFinalized(streamId, result) {
  const stream = result?.stream || result || {};
  return {
    streamId: stream.streamId || streamId,
    status: "finalized",
    contentRef: stream.contentRef,
    ...(stream.finalizedAt ? { finalizedAt: stream.finalizedAt } : {}),
    ...(stream.redaction ? { redaction: structuredClone(stream.redaction) } : {}),
    ...(stream.plaintextSha256 ? { plaintextSha256: stream.plaintextSha256 } : {}),
    ...(Number.isSafeInteger(stream.bytes) ? { bytes: stream.bytes } : {}),
  };
}

function publicReadResult(result) {
  const stream = result?.stream || result?.metadata || {};
  const content = result?.content ?? result?.text ?? result?.redactedText;
  if (typeof content !== "string") {
    throw new Error("content object did not contain redacted text");
  }
  return {
    contentRef: result.contentRef || stream.contentRef,
    streamId: result.streamId || stream.streamId,
    requestId: stream.requestId,
    sessionId: stream.sessionId,
    contentKind: result.contentKind || stream.contentKind,
    mediaType: "text/plain",
    auditLevel: "L2",
    content,
    ...(result.redaction || stream.redaction
      ? { redaction: structuredClone(result.redaction || stream.redaction) }
      : {}),
    ...(result.plaintextSha256 || stream.plaintextSha256
      ? { plaintextSha256: result.plaintextSha256 || stream.plaintextSha256 }
      : {}),
    ...(result.accessedAt ? { accessedAt: result.accessedAt } : {}),
  };
}

export function normalizeContentError(error) {
  if (error instanceof ContentApiError) return error;
  if (error instanceof ContentStreamError
      || error instanceof ContentGrantError
      || error instanceof ContentRetrievalError) {
    return new ContentApiError(error.statusCode, error.code, error.message, error.retryable);
  }
  if (error instanceof AuditContentValidationError) {
    return new ContentApiError(400, error.code, error.message);
  }
  if (error
      && Number.isInteger(error.statusCode)
      && error.statusCode >= 400
      && error.statusCode <= 599
      && typeof error.code === "string"
      && /^[a-z][a-z0-9._-]{0,63}$/.test(error.code)) {
    return new ContentApiError(
      error.statusCode,
      error.code,
      typeof error.message === "string" ? error.message : "The content request failed",
      error.retryable === true,
    );
  }
  return error;
}

export function contentRoute(pathname) {
  if (pathname === "/api/v1/internal/audit/content/streams") {
    return { name: "content_streams" };
  }
  if (pathname === "/api/v1/admin/audit/content/streams") {
    return { name: "content_admin_streams" };
  }
  if (pathname === "/api/v1/admin/audit/content/retention/run") {
    return { name: "content_retention_run" };
  }
  if (pathname === "/api/v1/admin/audit/content/deletions") {
    return { name: "content_deletions" };
  }
  if (pathname === "/api/v1/admin/audit/content/legal-holds") {
    return { name: "content_legal_holds" };
  }
  if (pathname === "/api/v1/admin/audit/content/exports") {
    return { name: "content_exports" };
  }
  const chunks = /^\/api\/v1\/internal\/audit\/content\/streams\/(str_[A-Za-z0-9_-]{43})\/chunks$/
    .exec(pathname);
  if (chunks) return { name: "content_chunks", streamId: chunks[1] };
  const stream = /^\/api\/v1\/admin\/audit\/content\/streams\/(str_[A-Za-z0-9_-]{43})$/
    .exec(pathname);
  if (stream) return { name: "content_stream", streamId: stream[1] };
  const grants = /^\/api\/v1\/admin\/audit\/content\/(ct_[A-Za-z0-9_-]{43})\/grants$/
    .exec(pathname);
  if (grants) return { name: "content_grant", contentRef: grants[1] };
  const deletionVerify = /^\/api\/v1\/admin\/audit\/content\/deletions\/(del_[A-Za-z0-9_-]{43})\/verify$/
    .exec(pathname);
  if (deletionVerify) {
    return { name: "content_deletion_verify", deletionId: deletionVerify[1] };
  }
  const deletion = /^\/api\/v1\/admin\/audit\/content\/deletions\/(del_[A-Za-z0-9_-]{43})$/
    .exec(pathname);
  if (deletion) {
    return { name: "content_deletion", deletionId: deletion[1] };
  }
  const release = /^\/api\/v1\/admin\/audit\/content\/legal-holds\/(hld_[A-Za-z0-9_-]{43})\/release$/
    .exec(pathname);
  if (release) {
    return { name: "content_legal_hold_release", holdId: release[1] };
  }
  const download = /^\/api\/v1\/admin\/audit\/content\/exports\/(exp_[A-Za-z0-9_-]{43})\/download$/
    .exec(pathname);
  if (download) {
    return { name: "content_export_download", exportId: download[1] };
  }
  const content = /^\/api\/v1\/admin\/audit\/content\/(ct_[A-Za-z0-9_-]{43})$/
    .exec(pathname);
  if (content) return { name: "content_object", contentRef: content[1] };
  return null;
}

function requireServiceAuth(req, config) {
  if (!safeEqual(bearerToken(req), config.serviceToken)) {
    throw new ContentApiError(401, "unauthorized", "A valid service token is required");
  }
}

function administratorIdentity(req, content) {
  const adminId = String(req.headers["x-audit-admin-id"] || "").trim();
  if (!SAFE_ID_PATTERN.test(adminId)) {
    throw new ContentApiError(
      400,
      "content_admin_identity_required",
      "A valid X-Audit-Admin-Id header is required",
    );
  }
  const organizationId = String(req.headers["x-audit-organization-id"] || "").trim();
  if (!SAFE_ID_PATTERN.test(organizationId)
      || !safeEqual(organizationId, content.organizationId)) {
    throw new ContentApiError(
      403,
      "content_admin_scope_mismatch",
      "The administrator organization scope is invalid",
    );
  }
  const sessionId = String(req.headers["x-audit-admin-session"] || "").trim();
  if (!ADMIN_SESSION_PATTERN.test(sessionId)) {
    throw new ContentApiError(
      400,
      "content_admin_session_required",
      "A valid X-Audit-Admin-Session header is required",
    );
  }
  return {
    adminId,
    organizationId,
    sessionId,
  };
}

function adminContext(req, content) {
  if (!content.adminEnabled) {
    throw new ContentApiError(
      503,
      "content_admin_disabled",
      "Content administration is disabled",
    );
  }
  if (!safeEqual(bearerToken(req), content.adminToken)) {
    throw new ContentApiError(
      401,
      "content_admin_unauthorized",
      "A valid content administrator token is required",
    );
  }
  return administratorIdentity(req, content);
}

function governanceContext(req, content) {
  if (!content.governanceEnabled) {
    throw new ContentApiError(
      503,
      "content_governance_disabled",
      "Content governance is disabled",
    );
  }
  if (!safeEqual(bearerToken(req), content.governanceToken)) {
    throw new ContentApiError(
      401,
      "content_governance_unauthorized",
      "A valid content governance token is required",
    );
  }
  return administratorIdentity(req, content);
}

export async function handleContentRoute(context) {
  const {
    req,
    res,
    route,
    config,
    content,
    reqId,
  } = context;
  try {
    if (!content?.enabled) {
      throw new ContentApiError(
        503,
        "content_audit_disabled",
        "Content audit is disabled",
      );
    }
    if (route.name === "content_streams") {
      requireServiceAuth(req, config);
      requireMethod(req, "POST");
      const key = idempotencyKey(req);
      const body = await readJsonBody(req, config.contentMaxBodyBytes);
      const request = validateContentStreamRequest(body);
      const result = await content.manager.create(request, key);
      jsonResponse(res, result.duplicate ? 200 : 202, {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        accepted: true,
        duplicate: result.duplicate === true,
        stream: publicContentStream(result.stream),
      }, reqId);
      return;
    }
    if (route.name === "content_chunks") {
      requireServiceAuth(req, config);
      requireMethod(req, "POST");
      const key = idempotencyKey(req);
      const body = await readJsonBody(req, config.contentMaxBodyBytes);
      const result = await content.manager.append(route.streamId, body, key);
      const value = {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        accepted: true,
        duplicate: result.duplicate === true,
      };
      if (result.finalized) {
        Object.assign(value, {
          finalized: true,
          stream: publicFinalized(route.streamId, result),
        });
      } else if (result.stream) {
        value.stream = publicContentStream(result.stream);
      }
      jsonResponse(res, 200, value, reqId);
      return;
    }
    if (route.name === "content_admin_streams") {
      requireMethod(req, "GET");
      adminContext(req, content);
      const result = await content.retrieval.list(new URL(req.url || "/", "http://localhost"));
      jsonResponse(res, 200, {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        ...result,
      }, reqId);
      return;
    }
    if (route.name === "content_retention_run") {
      requireMethod(req, "POST");
      const administrator = governanceContext(req, content);
      const body = await readJsonBody(req, config.contentMaxBodyBytes);
      const summary = await content.retention.run(body, {
        requestId: reqId,
        sourceHash: sourceHash(req, config),
        organizationId: administrator.organizationId,
      });
      jsonResponse(res, 200, {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        summary,
      }, reqId);
      return;
    }
    if (route.name === "content_deletions") {
      requireMethod(req, "GET");
      const administrator = governanceContext(req, content);
      const url = new URL(req.url || "/", "http://localhost");
      const from = queryTimestamp(url, "from");
      const to = queryTimestamp(url, "to");
      if (from && to && from > to) {
        throw new ContentApiError(400, "invalid_query", "from must not be after to");
      }
      const deletions = await content.deletion.list({
        organizationId: administrator.organizationId,
        contentRef: queryValue(url, "contentRef", /^ct_[A-Za-z0-9_-]{43}$/, 46),
        from,
        to,
        limit: queryLimit(url),
      });
      jsonResponse(res, 200, {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        deletions,
      }, reqId);
      return;
    }
    if (route.name === "content_deletion") {
      requireMethod(req, "GET");
      const administrator = governanceContext(req, content);
      const deletion = await content.deletion.get(route.deletionId);
      if (deletion.organizationId !== administrator.organizationId) {
        throw new ContentApiError(
          403,
          "content_admin_scope_mismatch",
          "The administrator organization scope is invalid",
        );
      }
      jsonResponse(res, 200, {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        deletion,
      }, reqId);
      return;
    }
    if (route.name === "content_deletion_verify") {
      requireMethod(req, "POST");
      const administrator = governanceContext(req, content);
      const deletion = await content.deletion.get(route.deletionId);
      if (deletion.organizationId !== administrator.organizationId) {
        throw new ContentApiError(
          403,
          "content_admin_scope_mismatch",
          "The administrator organization scope is invalid",
        );
      }
      const verification = await content.deletion.verify(route.deletionId);
      jsonResponse(res, 200, {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        verification,
      }, reqId);
      return;
    }
    if (route.name === "content_legal_holds") {
      const administrator = governanceContext(req, content);
      if (req.method === "POST") {
        const body = await readJsonBody(req, config.contentMaxBodyBytes);
        const result = await content.legalHolds.create(
          administrator,
          body,
          idempotencyKey(req),
        );
        jsonResponse(res, result.duplicate ? 200 : 201, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          duplicate: result.duplicate,
          hold: result.hold,
        }, reqId);
        return;
      }
      requireMethod(req, "GET");
      const url = new URL(req.url || "/", "http://localhost");
      const effectiveStatus = queryValue(
        url,
        "effectiveStatus",
        /^(?:active|scheduled|expired|released)$/,
        16,
      );
      if (effectiveStatus && !EFFECTIVE_HOLD_STATUSES.has(effectiveStatus)) {
        throw new ContentApiError(400, "invalid_query", "effectiveStatus is invalid");
      }
      const holds = await content.legalHolds.list({
        organizationId: administrator.organizationId,
        contentRef: queryValue(url, "contentRef", /^ct_[A-Za-z0-9_-]{43}$/, 46),
        effectiveStatus,
        limit: queryLimit(url),
      });
      jsonResponse(res, 200, {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        holds,
      }, reqId);
      return;
    }
    if (route.name === "content_legal_hold_release") {
      requireMethod(req, "POST");
      const administrator = governanceContext(req, content);
      const body = await readJsonBody(req, config.contentMaxBodyBytes);
      const result = await content.legalHolds.release(
        administrator,
        route.holdId,
        body,
      );
      jsonResponse(res, 200, {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        hold: result.hold,
      }, reqId);
      return;
    }
    if (route.name === "content_exports") {
      const administrator = governanceContext(req, content);
      if (!content.exportEnabled || !content.export) {
        throw new ContentApiError(
          503,
          "content_export_disabled",
          "Content export is disabled",
        );
      }
      if (req.method === "POST") {
        const body = await readJsonBody(req, config.contentMaxBodyBytes);
        const result = await content.export.create(
          administrator,
          body,
          idempotencyKey(req),
          {
            requestId: reqId,
            sourceHash: sourceHash(req, config),
          },
        );
        jsonResponse(res, result.duplicate ? 200 : 201, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          duplicate: result.duplicate,
          export: result.export,
          token: result.token,
        }, reqId);
        return;
      }
      requireMethod(req, "GET");
      const url = new URL(req.url || "/", "http://localhost");
      const exports = await content.export.list({
        organizationId: administrator.organizationId,
        status: queryValue(
          url,
          "status",
          /^(?:active|downloaded|expired)$/,
          16,
        ),
        limit: queryLimit(url),
      });
      jsonResponse(res, 200, {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        exports,
      }, reqId);
      return;
    }
    if (route.name === "content_export_download") {
      requireMethod(req, "GET");
      const administrator = governanceContext(req, content);
      if (!content.exportEnabled || !content.export) {
        throw new ContentApiError(
          503,
          "content_export_disabled",
          "Content export is disabled",
        );
      }
      const token = String(req.headers["x-audit-export-token"] || "").trim();
      const result = await content.export.download(
        route.exportId,
        administrator,
        token,
      );
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "content-length": result.bytes.length,
        "content-disposition": `attachment; filename="magpie-export-${route.exportId}.mge"`,
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "x-request-id": reqId,
        "x-audit-watermark": result.watermark,
      });
      res.end(result.bytes);
      return;
    }
    if (route.name === "content_stream") {
      requireMethod(req, "GET");
      adminContext(req, content);
      const stream = await content.manager.get(route.streamId);
      if (!stream) {
        throw new ContentApiError(404, "content_stream_not_found", "Content stream not found");
      }
      jsonResponse(res, 200, {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        stream: publicContentStream(stream),
      }, reqId);
      return;
    }
    if (route.name === "content_grant") {
      requireMethod(req, "POST");
      const administrator = adminContext(req, content);
      const contentRef = validateContentRef(route.contentRef);
      if (!await content.store.hasObject(contentRef)) {
        throw new ContentApiError(404, "content_object_not_found", "Content object not found");
      }
      const request = validateGrantRequest(
        await readJsonBody(req, config.contentMaxBodyBytes),
      );
      const issued = await content.grants.issue({
        ...administrator,
        contentRef,
        ...request,
      });
      jsonResponse(res, 201, {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        grant: issued.grant,
        grantId: issued.grantId,
        contentRef: issued.contentRef,
        issuedAt: issued.issuedAt,
        expiresAt: issued.expiresAt,
      }, reqId);
      return;
    }
    if (route.name === "content_object") {
      if (req.method === "DELETE") {
        const administrator = governanceContext(req, content);
        const contentRef = validateContentRef(route.contentRef);
        const result = await content.deletion.delete(
          contentRef,
          administrator,
          await readJsonBody(req, config.contentMaxBodyBytes),
          idempotencyKey(req),
          {
            requestId: reqId,
            sourceHash: sourceHash(req, config),
          },
        );
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          duplicate: result.duplicate,
          deletion: result.proof,
        }, reqId);
        return;
      }
      requireMethod(req, "GET");
      const administrator = adminContext(req, content);
      const contentRef = validateContentRef(route.contentRef);
      const grantToken = String(req.headers["x-audit-content-grant"] || "").trim();
      if (!grantToken) {
        throw new ContentApiError(
          401,
          "content_grant_required",
          "A one-time content grant is required",
        );
      }
      const grant = await content.grants.consume(grantToken, {
        ...administrator,
        contentRef,
      });
      const accessedAt = content.store.timestamp();
      const result = await content.store.readObject(contentRef, {
        reason: grant.reason,
        authorizationId: grant.approvalId,
        approvalId: grant.approvalId,
        grantId: grant.grantId,
        adminId: grant.adminId,
        organizationId: grant.organizationId,
        purpose: grant.purpose,
        accessedAt,
        requestId: reqId,
        sourceHash: sourceHash(req, config),
      });
      const value = publicReadResult(result);
      jsonResponse(res, 200, {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        ...value,
      }, reqId, {
        "x-audit-watermark": `MAGPIE-AUDIT-CONTENT ${contentRef} ${accessedAt}`,
      });
      return;
    }
    throw new ContentApiError(404, "not_found", "Route not found");
  } catch (error) {
    throw normalizeContentError(error);
  }
}
