// Server-side client for the audit-service content boundary (M4-E). The
// browser never receives either service token, and raw content grants and
// export tokens are returned only to the caller for immediate use.

const DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_EXPORT_BYTES = 32 * 1024 * 1024;
const CONTENT_REF_PATTERN = /^ct_[A-Za-z0-9_-]{43}$/;
const STREAM_ID_PATTERN = /^str_[A-Za-z0-9_-]{43}$/;
const DELETION_ID_PATTERN = /^del_[A-Za-z0-9_-]{43}$/;
const HOLD_ID_PATTERN = /^hld_[A-Za-z0-9_-]{43}$/;
const EXPORT_ID_PATTERN = /^exp_[A-Za-z0-9_-]{43}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{16,4096}\.[A-Za-z0-9_-]{43}$/;
const SAFE_CODE_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const QUERY_FIELDS = new Set([
  "userId",
  "departmentId",
  "deviceId",
  "agentId",
  "modelId",
  "mcpServerId",
  "toolName",
  "contentKind",
  "status",
  "from",
  "to",
  "limit",
  "cursor",
  "effectiveStatus",
  "contentRef",
]);

export class AuditContentServiceError extends Error {
  constructor(message = "The audit content service is unavailable", options = {}) {
    super(message);
    this.name = "AuditContentServiceError";
    this.statusCode = Number.isInteger(options.statusCode) ? options.statusCode : 503;
    this.code = typeof options.code === "string" && SAFE_CODE_PATTERN.test(options.code)
      ? options.code
      : "audit_content_unavailable";
  }
}

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function requiredString(value, name, pattern, maximum = 4096) {
  if (typeof value !== "string"
      || value.length === 0
      || value.length > maximum
      || !pattern.test(value)) {
    throw invalidResponse(`${name} is invalid`);
  }
  return value;
}

function optionalString(value, name, pattern, maximum = 4096) {
  if (value === undefined || value === null || value === "") return "";
  return requiredString(value, name, pattern, maximum);
}

function safeInteger(value, name, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw invalidResponse(`${name} is invalid`);
  }
  return value;
}

function invalidResponse(message = "The audit content service returned an invalid response") {
  return new AuditContentServiceError(message, {
    statusCode: 502,
    code: "audit_content_invalid_response",
  });
}

function notFound(message = "The audit content service did not find the record") {
  return new AuditContentServiceError(message, {
    statusCode: 404,
    code: "not_found",
  });
}

function rejected() {
  return new AuditContentServiceError("The audit content service rejected the request", {
    statusCode: 502,
    code: "audit_content_rejected",
  });
}

function conflict(code, message) {
  return new AuditContentServiceError(message, {
    statusCode: 409,
    code,
  });
}

function unavailable() {
  return new AuditContentServiceError();
}

function timeoutError() {
  return new AuditContentServiceError("The audit content service timed out", {
    statusCode: 504,
    code: "audit_content_timeout",
  });
}

function redirectError() {
  return new AuditContentServiceError("The audit content service redirected the request", {
    statusCode: 502,
    code: "audit_content_redirect_rejected",
  });
}

function tooLarge() {
  return new AuditContentServiceError("The audit content service response is too large", {
    statusCode: 502,
    code: "audit_content_response_too_large",
  });
}

function cancelBody(response) {
  try {
    response?.body?.cancel?.().catch?.(() => {});
  } catch {
    // The response has already completed or was replaced before cancellation.
  }
}

async function readBytes(response, maxBytes) {
  const declared = Number(response.headers?.get?.("content-length") || 0);
  if (Number.isFinite(declared) && declared > maxBytes) {
    cancelBody(response);
    throw tooLarge();
  }
  const reader = response.body?.getReader?.();
  if (!reader) throw invalidResponse("The audit content service response is unreadable");
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw tooLarge();
      }
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    if (error instanceof AuditContentServiceError) throw error;
    throw invalidResponse("The audit content service response could not be read");
  }
  return Buffer.concat(chunks, total);
}

async function readJson(response, maxBytes) {
  const bytes = await readBytes(response, maxBytes);
  try {
    return JSON.parse(new TextDecoder("utf8", { fatal: true }).decode(bytes));
  } catch {
    throw invalidResponse("The audit content service response is not valid JSON");
  }
}

function expectOk(payload) {
  if (!plainObject(payload) || payload.ok !== true || payload.schemaVersion !== 1) {
    throw invalidResponse();
  }
  return payload;
}

function expectArray(value, name) {
  if (!Array.isArray(value)) throw invalidResponse(`${name} is invalid`);
  return value;
}

function expectObject(value, name) {
  if (!plainObject(value)) throw invalidResponse(`${name} is invalid`);
  return value;
}

function expectId(value, name, pattern) {
  return requiredString(value, name, pattern, 64);
}

function expectToken(value, name) {
  return requiredString(value, name, TOKEN_PATTERN);
}

function expectContentRead(value, contentRef) {
  const result = expectObject(value, "content");
  if (result.contentRef !== contentRef
      || !STREAM_ID_PATTERN.test(String(result.streamId || ""))
      || typeof result.content !== "string"
      || result.mediaType !== "text/plain"
      || result.auditLevel !== "L2") {
    throw invalidResponse("The content read response is invalid");
  }
  return result;
}

function expectDeletion(value) {
  const deletion = expectObject(value, "deletion");
  expectId(deletion.deletionId, "deletionId", DELETION_ID_PATTERN);
  if (!CONTENT_REF_PATTERN.test(String(deletion.contentRef || ""))) {
    throw invalidResponse("deletion.contentRef is invalid");
  }
  return deletion;
}

function expectHold(value) {
  const hold = expectObject(value, "hold");
  expectId(hold.holdId, "holdId", HOLD_ID_PATTERN);
  return hold;
}

function expectExport(value) {
  const record = expectObject(value, "export");
  expectId(record.exportId, "exportId", EXPORT_ID_PATTERN);
  return record;
}

function queryString(query) {
  if (query == null) return "";
  if (!plainObject(query)) throw new TypeError("query must be a plain object");
  const params = new URLSearchParams();
  for (const [name, value] of Object.entries(query)) {
    if (!QUERY_FIELDS.has(name)) throw new TypeError(`query.${name} is not supported`);
    if (value === undefined || value === null || value === "") continue;
    if (Array.isArray(value) || typeof value === "object") {
      throw new TypeError(`query.${name} must be a scalar`);
    }
    params.set(name, String(value));
  }
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

export class AuditContentServiceClient {
  constructor(config = {}, options = {}) {
    this.config = config;
    this.requestImpl = options.requestImpl || fetch;
    this.now = options.now || Date.now;
  }

  get enabled() {
    return Boolean(this.config?.enabled);
  }

  get maxResponseBytes() {
    return Number.isFinite(Number(this.config?.maxResponseBytes))
      && Number(this.config.maxResponseBytes) > 0
      ? Number(this.config.maxResponseBytes)
      : DEFAULT_MAX_RESPONSE_BYTES;
  }

  get maxExportBytes() {
    return Number.isFinite(Number(this.config?.maxExportBytes))
      && Number(this.config.maxExportBytes) > 0
      ? Number(this.config.maxExportBytes)
      : DEFAULT_MAX_EXPORT_BYTES;
  }

  headers(identity, role, extra = {}) {
    if (!this.enabled) throw unavailable();
    if (!plainObject(identity)) throw invalidResponse("The audit administrator identity is invalid");
    const adminId = requiredString(
      identity.adminId,
      "identity.adminId",
      /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/,
      128,
    );
    const sessionHash = requiredString(
      identity.sessionHash,
      "identity.sessionHash",
      /^[A-Za-z0-9][A-Za-z0-9._:@+-]{7,255}$/,
      256,
    );
    const organizationId = requiredString(
      this.config.organizationId,
      "organizationId",
      /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/,
      128,
    );
    const token = role === "governance"
      ? this.config.governanceToken
      : this.config.adminToken;
    if (typeof token !== "string" || token.length < 32) throw unavailable();
    return {
      accept: "application/json",
      authorization: `Bearer ${token}`,
      "x-audit-admin-id": adminId,
      "x-audit-organization-id": organizationId,
      "x-audit-admin-session": sessionHash,
      ...extra,
    };
  }

  async request(pathname, options = {}) {
    if (!this.enabled) throw unavailable();
    let response;
    try {
      response = await this.requestImpl(new URL(pathname, this.config.url), {
        method: options.method || "GET",
        headers: options.headers || {},
        body: options.body,
        redirect: "error",
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch (error) {
      if (error?.name === "TimeoutError" || error?.name === "AbortError") {
        throw timeoutError();
      }
      const cause = String(error?.cause?.message || error?.message || "");
      if (/redirect/i.test(cause)) throw redirectError();
      throw unavailable();
    }
    if (response.status === 404) {
      cancelBody(response);
      throw notFound();
    }
    if (response.status >= 500) {
      cancelBody(response);
      throw unavailable();
    }
    if (!response.ok) {
      cancelBody(response);
      if (response.status === 409 && options.conflictCode) {
        throw conflict(options.conflictCode, options.conflictMessage);
      }
      throw rejected();
    }
    return response;
  }

  async requestJson(pathname, options = {}, maxBytes = this.maxResponseBytes) {
    const response = await this.request(pathname, options);
    return expectOk(await readJson(response, maxBytes));
  }

  async listStreams(identity, query = {}) {
    const payload = await this.requestJson(
      `/api/v1/admin/audit/content/streams${queryString(query)}`,
      { headers: this.headers(identity, "admin") },
    );
    return {
      streams: expectArray(payload.streams, "streams"),
      nextCursor: payload.nextCursor == null
        ? null
        : requiredString(payload.nextCursor, "nextCursor", /^[A-Za-z0-9_.-]{1,8192}$/, 8192),
    };
  }

  async getStream(identity, streamId) {
    const id = expectId(streamId, "streamId", STREAM_ID_PATTERN);
    const payload = await this.requestJson(
      `/api/v1/admin/audit/content/streams/${encodeURIComponent(id)}`,
      { headers: this.headers(identity, "admin") },
    );
    return expectObject(payload.stream, "stream");
  }

  async issueGrant(identity, contentRef, body) {
    const ref = expectId(contentRef, "contentRef", CONTENT_REF_PATTERN);
    const payload = await this.requestJson(
      `/api/v1/admin/audit/content/${encodeURIComponent(ref)}/grants`,
      {
        method: "POST",
        headers: this.headers(identity, "admin", {
          "content-type": "application/json",
        }),
        body: JSON.stringify(body),
      },
    );
    return {
      grant: expectToken(payload.grant, "grant"),
      grantId: expectId(payload.grantId, "grantId", /^grt_[A-Za-z0-9_-]{43}$/),
      contentRef: ref,
      issuedAt: requiredString(payload.issuedAt, "issuedAt", /^\d{4}-\d{2}-\d{2}T/, 64),
      expiresAt: requiredString(payload.expiresAt, "expiresAt", /^\d{4}-\d{2}-\d{2}T/, 64),
    };
  }

  async readContent(identity, contentRef, grant) {
    const ref = expectId(contentRef, "contentRef", CONTENT_REF_PATTERN);
    const token = expectToken(grant, "grant");
    const payload = await this.requestJson(
      `/api/v1/admin/audit/content/${encodeURIComponent(ref)}`,
      {
        conflictCode: "content_read_replayed",
        conflictMessage: "The content grant has already been used",
        headers: this.headers(identity, "admin", {
          "x-audit-content-grant": token,
        }),
      },
    );
    // Deliberately return a fresh object and do not retain the body anywhere
    // in this client. The caller must emit it once and discard it.
    return structuredClone(expectContentRead(payload, ref));
  }

  async runRetention(identity, body) {
    const payload = await this.requestJson(
      "/api/v1/admin/audit/content/retention/run",
      {
        method: "POST",
        headers: this.headers(identity, "governance", {
          "content-type": "application/json",
        }),
        body: JSON.stringify(body),
      },
    );
    return expectObject(payload.summary, "summary");
  }

  async deleteContent(identity, contentRef, body, idempotencyKey) {
    const ref = expectId(contentRef, "contentRef", CONTENT_REF_PATTERN);
    const key = requiredString(
      idempotencyKey,
      "idempotencyKey",
      /^[\u0021-\u007e]{1,128}$/,
      128,
    );
    const payload = await this.requestJson(
      `/api/v1/admin/audit/content/${encodeURIComponent(ref)}`,
      {
        method: "DELETE",
        headers: this.headers(identity, "governance", {
          "content-type": "application/json",
          "idempotency-key": key,
        }),
        body: JSON.stringify(body),
      },
    );
    return {
      duplicate: payload.duplicate === true,
      deletion: expectDeletion(payload.deletion),
    };
  }

  async listDeletions(identity, query = {}) {
    const payload = await this.requestJson(
      `/api/v1/admin/audit/content/deletions${queryString(query)}`,
      { headers: this.headers(identity, "governance") },
    );
    return expectArray(payload.deletions, "deletions").map(expectDeletion);
  }

  async getDeletion(identity, deletionId) {
    const id = expectId(deletionId, "deletionId", DELETION_ID_PATTERN);
    const payload = await this.requestJson(
      `/api/v1/admin/audit/content/deletions/${encodeURIComponent(id)}`,
      { headers: this.headers(identity, "governance") },
    );
    return expectDeletion(payload.deletion);
  }

  async verifyDeletion(identity, deletionId) {
    const id = expectId(deletionId, "deletionId", DELETION_ID_PATTERN);
    const payload = await this.requestJson(
      `/api/v1/admin/audit/content/deletions/${encodeURIComponent(id)}/verify`,
      {
        method: "POST",
        headers: this.headers(identity, "governance"),
      },
    );
    return expectObject(payload.verification, "verification");
  }

  async createLegalHold(identity, body, idempotencyKey) {
    const key = requiredString(
      idempotencyKey,
      "idempotencyKey",
      /^[\u0021-\u007e]{1,128}$/,
      128,
    );
    const payload = await this.requestJson(
      "/api/v1/admin/audit/content/legal-holds",
      {
        method: "POST",
        headers: this.headers(identity, "governance", {
          "content-type": "application/json",
          "idempotency-key": key,
        }),
        body: JSON.stringify(body),
      },
    );
    return {
      duplicate: payload.duplicate === true,
      hold: expectHold(payload.hold),
    };
  }

  async listLegalHolds(identity, query = {}) {
    const payload = await this.requestJson(
      `/api/v1/admin/audit/content/legal-holds${queryString(query)}`,
      { headers: this.headers(identity, "governance") },
    );
    return expectArray(payload.holds, "holds").map(expectHold);
  }

  async releaseLegalHold(identity, holdId, body) {
    const id = expectId(holdId, "holdId", HOLD_ID_PATTERN);
    const payload = await this.requestJson(
      `/api/v1/admin/audit/content/legal-holds/${encodeURIComponent(id)}/release`,
      {
        method: "POST",
        headers: this.headers(identity, "governance", {
          "content-type": "application/json",
        }),
        body: JSON.stringify(body),
      },
    );
    return expectHold(payload.hold);
  }

  async createExport(identity, body, idempotencyKey) {
    const key = requiredString(
      idempotencyKey,
      "idempotencyKey",
      /^[\u0021-\u007e]{1,128}$/,
      128,
    );
    const payload = await this.requestJson(
      "/api/v1/admin/audit/content/exports",
      {
        method: "POST",
        headers: this.headers(identity, "governance", {
          "content-type": "application/json",
          "idempotency-key": key,
        }),
        body: JSON.stringify(body),
      },
    );
    return {
      duplicate: payload.duplicate === true,
      export: expectExport(payload.export),
      token: expectToken(payload.token, "token"),
    };
  }

  async listExports(identity, query = {}) {
    const payload = await this.requestJson(
      `/api/v1/admin/audit/content/exports${queryString(query)}`,
      { headers: this.headers(identity, "governance") },
    );
    return expectArray(payload.exports, "exports").map(expectExport);
  }

  async downloadExport(identity, exportId, token) {
    const id = expectId(exportId, "exportId", EXPORT_ID_PATTERN);
    const exportToken = expectToken(token, "exportToken");
    const response = await this.request(
      `/api/v1/admin/audit/content/exports/${encodeURIComponent(id)}/download`,
      {
        conflictCode: "content_export_token_reused",
        conflictMessage: "The export token has already been used",
        headers: this.headers(identity, "governance", {
          accept: "application/octet-stream",
          "x-audit-export-token": exportToken,
        }),
      },
    );
    const bytes = await readBytes(response, this.maxExportBytes);
    const contentType = String(response.headers?.get?.("content-type") || "");
    if (contentType !== "application/octet-stream") {
      throw invalidResponse("The export response has an unexpected content type");
    }
    return {
      bytes,
      contentType,
      watermark: String(response.headers?.get?.("x-audit-watermark") || ""),
      requestId: String(response.headers?.get?.("x-request-id") || ""),
      receivedAt: new Date(this.now()).toISOString(),
    };
  }
}
