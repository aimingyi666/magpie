import crypto from "node:crypto";

import {
  AuditContentValidationError,
  publicContentStream,
  validateContentRef,
  validateContentStreamRequest,
} from "./content-schema.js";
import { ContentStreamError } from "./content-streams.js";

const SCHEMA_VERSION = 1;
const IDEMPOTENCY_KEY_PATTERN = /^[\u0021-\u007e]{1,128}$/;
const AUTHORIZATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{7,127}$/;
const MAX_ACCESS_REASON_LENGTH = 1024;

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

function accessReason(req) {
  const value = String(req.headers["x-audit-content-reason"] || "").trim();
  if (value.length < 8
      || value.length > MAX_ACCESS_REASON_LENGTH
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new ContentApiError(
      400,
      "content_access_reason_required",
      "A valid X-Audit-Content-Reason header is required",
    );
  }
  return value;
}

function accessAuthorization(req) {
  const value = String(req.headers["x-audit-content-authorization"] || "").trim();
  if (!AUTHORIZATION_ID_PATTERN.test(value)) {
    throw new ContentApiError(
      400,
      "content_access_authorization_required",
      "A valid X-Audit-Content-Authorization header is required",
    );
  }
  return value;
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
  if (error instanceof ContentStreamError) {
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
  const chunks = /^\/api\/v1\/internal\/audit\/content\/streams\/(str_[A-Za-z0-9_-]{43})\/chunks$/
    .exec(pathname);
  if (chunks) return { name: "content_chunks", streamId: chunks[1] };
  const stream = /^\/api\/v1\/admin\/audit\/content\/streams\/(str_[A-Za-z0-9_-]{43})$/
    .exec(pathname);
  if (stream) return { name: "content_stream", streamId: stream[1] };
  const content = /^\/api\/v1\/admin\/audit\/content\/(ct_[A-Za-z0-9_-]{43})$/
    .exec(pathname);
  if (content) return { name: "content_object", contentRef: content[1] };
  return null;
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
    if (route.name === "content_stream") {
      requireMethod(req, "GET");
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
    if (route.name === "content_object") {
      requireMethod(req, "GET");
      assertContentReadAllowed(req, config);
      const contentRef = validateContentRef(route.contentRef);
      const reason = accessReason(req);
      const authorizationId = accessAuthorization(req);
      const accessedAt = new Date().toISOString();
      const result = await content.store.readObject(contentRef, {
        reason,
        authorizationId,
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

function assertContentReadAllowed(req, config) {
  if (!config.contentReadToken) {
    throw new ContentApiError(
      503,
      "content_read_disabled",
      "Content read access is disabled",
    );
  }
  const token = String(req.headers["x-audit-content-token"] || "").trim();
  if (!safeEqual(token, config.contentReadToken)) {
    throw new ContentApiError(
      401,
      "content_read_unauthorized",
      "A valid content read token is required",
    );
  }
}
