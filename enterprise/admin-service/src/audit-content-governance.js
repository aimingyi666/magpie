import crypto from "node:crypto";

export const AUDIT_CONTENT_ACTIONS = Object.freeze([
  "audit.content.read_request",
  "audit.content.retention.run",
  "audit.content.delete",
  "audit.content.legal_hold.create",
  "audit.content.legal_hold.release",
  "audit.content.export.create",
]);

export const CONTENT_PURPOSES = Object.freeze([
  "security_investigation",
  "incident_response",
  "compliance_review",
  "legal_investigation",
]);

export const CONTENT_ACTION_PERMISSIONS = Object.freeze({
  "audit.content.read_request": "audit.content.read",
  "audit.content.retention.run": "audit.content.retention",
  "audit.content.delete": "audit.content.delete",
  "audit.content.legal_hold.create": "audit.content.legal_hold",
  "audit.content.legal_hold.release": "audit.content.legal_hold",
  "audit.content.export.create": "audit.content.export",
});

export const CONTENT_ACTION_TARGETS = Object.freeze({
  "audit.content.read_request": "content",
  "audit.content.retention.run": "content_retention",
  "audit.content.delete": "content",
  "audit.content.legal_hold.create": "content_hold",
  "audit.content.legal_hold.release": "content_hold",
  "audit.content.export.create": "content_export",
});

const CONTENT_REF_PATTERN = /^ct_[A-Za-z0-9_-]{43}$/;
const STREAM_ID_PATTERN = /^str_[A-Za-z0-9_-]{43}$/;
const HOLD_ID_PATTERN = /^hld_[A-Za-z0-9_-]{43}$/;
const DELETION_ID_PATTERN = /^del_[A-Za-z0-9_-]{43}$/;
const UPSTREAM_EXPORT_ID_PATTERN = /^exp_[A-Za-z0-9_-]{43}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,127}$/;
const LOCAL_EXPORT_ID_PATTERN = /^cexp_[A-Za-z0-9_-]{24,96}$/;
const UTC_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const LEGAL_HOLD_SCOPE_FIELDS = new Set([
  "contentRef",
  "streamId",
  "userId",
  "departmentId",
  "deviceId",
  "agentId",
]);
const EXPORT_SCOPE_FIELDS = new Set([
  "contentRefs",
  "userId",
  "departmentId",
  "from",
  "to",
]);
const ACTION_FIELDS = Object.freeze({
  "audit.content.read_request": new Set(["contentRef", "purpose", "ttlSeconds"]),
  "audit.content.retention.run": new Set(["dryRun", "limit"]),
  "audit.content.delete": new Set(["contentRef", "force"]),
  "audit.content.legal_hold.create": new Set([
    "scope",
    "custodianId",
    "startsAt",
    "expiresAt",
  ]),
  "audit.content.legal_hold.release": new Set(["holdId"]),
  "audit.content.export.create": new Set(["scope", "purpose", "ttlSeconds"]),
});

export class AuditContentValidationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AuditContentValidationError";
    this.code = code;
  }
}

function invalid(code, message) {
  throw new AuditContentValidationError(code, message);
}

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .filter((key) => value[key] !== undefined)
        .map((key) => [key, canonicalValue(value[key])]),
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function digest(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function requiredString(value, name, pattern = IDENTIFIER_PATTERN) {
  if (typeof value !== "string" || !value || !pattern.test(value)) {
    invalid("invalid_content_request", `${name} is invalid`);
  }
  return value;
}

function optionalInteger(value, name, minimum, maximum) {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid("invalid_content_request", `${name} must be between ${minimum} and ${maximum}`);
  }
  return value;
}

function canonicalTimestamp(value, name, required = false) {
  if (value === undefined) {
    if (required) invalid("invalid_content_request", `${name} is required`);
    return "";
  }
  if (typeof value !== "string" || !UTC_TIMESTAMP_PATTERN.test(value)) {
    invalid("invalid_content_request", `${name} must be a canonical UTC timestamp`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    invalid("invalid_content_request", `${name} must be a canonical UTC timestamp`);
  }
  return value;
}

function purpose(value) {
  const selected = value;
  if (!CONTENT_PURPOSES.includes(selected)) {
    invalid("invalid_content_purpose", "purpose is not allowed");
  }
  return selected;
}

function rejectUnknownFields(value, allowed, name = "payload") {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    invalid("invalid_content_request", `${name} contains an unsupported field`);
  }
}

function legalHoldScope(value) {
  if (!plainObject(value)) {
    invalid("invalid_content_scope", "scope must be an object");
  }
  const keys = Object.keys(value);
  if (keys.length === 0 || keys.some((key) => !LEGAL_HOLD_SCOPE_FIELDS.has(key))) {
    invalid("invalid_content_scope", "legal hold scope must name supported targets");
  }
  const normalized = {};
  for (const key of keys) {
    let pattern = IDENTIFIER_PATTERN;
    if (key === "contentRef") pattern = CONTENT_REF_PATTERN;
    if (key === "streamId") pattern = STREAM_ID_PATTERN;
    normalized[key] = requiredString(value[key], `scope.${key}`, pattern);
  }
  // Multiple fields are matched with AND: every supplied selector must match.
  return normalized;
}

function exportScope(value) {
  if (!plainObject(value)) {
    invalid("invalid_content_scope", "scope must be an object");
  }
  const keys = Object.keys(value);
  if (keys.length === 0) {
    invalid("invalid_content_scope", "export scope is invalid");
  }
  rejectUnknownFields(value, EXPORT_SCOPE_FIELDS, "scope");
  const normalized = {};
  if (value.contentRefs !== undefined) {
    if (!Array.isArray(value.contentRefs)
        || value.contentRefs.length < 1
        || value.contentRefs.length > 100) {
      invalid("invalid_content_scope", "scope.contentRefs must contain 1 to 100 references");
    }
    normalized.contentRefs = [...new Set(value.contentRefs.map((item) => (
      requiredString(item, "scope.contentRefs[]", CONTENT_REF_PATTERN)
    )))].sort();
  }
  for (const key of ["userId", "departmentId"]) {
    if (value[key] !== undefined) normalized[key] = requiredString(value[key], `scope.${key}`);
  }
  const from = value.from === undefined ? "" : canonicalTimestamp(value.from, "scope.from");
  const to = value.to === undefined ? "" : canonicalTimestamp(value.to, "scope.to");
  if (Boolean(from) !== Boolean(to)) {
    invalid("invalid_content_scope", "scope.from and scope.to must be provided together");
  }
  if (from && Date.parse(from) >= Date.parse(to)) {
    invalid("invalid_content_scope", "scope.from must be before scope.to");
  }
  if (from) normalized.from = from;
  if (to) normalized.to = to;
  if (Object.keys(normalized).length === 0) {
    invalid("invalid_content_scope", "export scope must select content");
  }
  return normalized;
}

export function isAuditContentAction(action) {
  return AUDIT_CONTENT_ACTIONS.includes(String(action || ""));
}

export function normalizeContentReason(value) {
  if (typeof value !== "string") {
    invalid("invalid_content_reason", "reason must be between 8 and 1024 characters");
  }
  const length = [...value].length;
  if (length < 8 || length > 1024 || /[\u0000-\u001f\u007f-\u009f]/.test(value)) {
    invalid("invalid_content_reason", "reason must be between 8 and 1024 characters");
  }
  return value;
}

export function normalizeContentRef(value) {
  return requiredString(value, "contentRef", CONTENT_REF_PATTERN);
}

export function normalizeHoldId(value) {
  return requiredString(value, "holdId", HOLD_ID_PATTERN);
}

export function normalizeDeletionId(value) {
  return requiredString(value, "deletionId", DELETION_ID_PATTERN);
}

export function normalizeUpstreamExportId(value) {
  return requiredString(value, "exportId", UPSTREAM_EXPORT_ID_PATTERN);
}

export function normalizeStreamId(value) {
  return requiredString(value, "streamId", STREAM_ID_PATTERN);
}

export function normalizeLocalExportId(value) {
  return requiredString(value, "content exportId", LOCAL_EXPORT_ID_PATTERN);
}

export function normalizeAuditContentPayload(action, value = {}) {
  if (!isAuditContentAction(action)) {
    invalid("invalid_content_action", "The content action is not supported");
  }
  if (!plainObject(value)) {
    invalid("invalid_content_request", "Content request payload must be an object");
  }
  rejectUnknownFields(value, ACTION_FIELDS[action]);
  if (action === "audit.content.read_request") {
    const ttlSeconds = optionalInteger(value.ttlSeconds, "ttlSeconds", 15, 300);
    return {
      contentRef: normalizeContentRef(value.contentRef),
      purpose: purpose(value.purpose),
      ...(ttlSeconds === undefined ? {} : { ttlSeconds }),
    };
  }
  if (action === "audit.content.retention.run") {
    const limit = optionalInteger(value.limit, "limit", 1, 500);
    if (value.dryRun !== undefined && typeof value.dryRun !== "boolean") {
      invalid("invalid_content_request", "dryRun must be a boolean");
    }
    return {
      dryRun: value.dryRun === true,
      ...(limit === undefined ? {} : { limit }),
    };
  }
  if (action === "audit.content.delete") {
    if (value.force !== undefined && typeof value.force !== "boolean") {
      invalid("invalid_content_request", "force must be a boolean");
    }
    return {
      contentRef: normalizeContentRef(value.contentRef),
      force: value.force === true,
    };
  }
  if (action === "audit.content.legal_hold.create") {
    const startsAt = canonicalTimestamp(value.startsAt, "startsAt");
    const expiresAt = canonicalTimestamp(value.expiresAt, "expiresAt", true);
    if (startsAt && Date.parse(startsAt) >= Date.parse(expiresAt)) {
      invalid("invalid_content_request", "startsAt must be before expiresAt");
    }
    return {
      scope: legalHoldScope(value.scope),
      custodianId: requiredString(value.custodianId, "custodianId"),
      ...(startsAt ? { startsAt } : {}),
      expiresAt,
    };
  }
  if (action === "audit.content.legal_hold.release") {
    return { holdId: normalizeHoldId(value.holdId) };
  }
  const ttlSeconds = optionalInteger(value.ttlSeconds, "ttlSeconds", 15, 300);
  return {
    scope: exportScope(value.scope),
    purpose: purpose(value.purpose),
    ...(ttlSeconds === undefined ? {} : { ttlSeconds }),
  };
}

export function contentApprovalTargetId(action, payload) {
  if (action === "audit.content.read_request" || action === "audit.content.delete") {
    return normalizeContentRef(payload?.contentRef);
  }
  if (action === "audit.content.retention.run") return "retention_run";
  if (action === "audit.content.legal_hold.release") {
    return normalizeHoldId(payload?.holdId);
  }
  const normalized = normalizeAuditContentPayload(action, payload);
  const prefix = action === "audit.content.legal_hold.create"
    ? "content_hold_"
    : "content_export_";
  return `${prefix}${digest(canonicalJson(normalized))}`;
}

export function contentRequestFingerprint(action, payload, approvalId, reason) {
  return digest(canonicalJson({
    action,
    payload: normalizeAuditContentPayload(action, payload),
    approvalId: String(approvalId || ""),
    reason: String(reason || ""),
  }));
}

export function canonicalContentJson(value) {
  return canonicalJson(value);
}

export function sha256ContentDigest(value) {
  return digest(value);
}

export function isCanonicalUtcTimestamp(value) {
  const text = String(value || "");
  return UTC_TIMESTAMP_PATTERN.test(text)
    && Number.isFinite(Date.parse(text))
    && new Date(Date.parse(text)).toISOString() === text;
}

export function isContentBase64(value, exactBytes = 0) {
  if (typeof value !== "string" || !value || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    return false;
  }
  let bytes;
  try {
    bytes = Buffer.from(value, "base64");
  } catch {
    return false;
  }
  return bytes.toString("base64") === value
    && (exactBytes === 0 || bytes.length === exactBytes);
}

export function contentExportAad(record) {
  return canonicalJson({
    version: 1,
    exportId: String(record.exportId || ""),
    actorSubjectId: String(record.actorSubjectId || ""),
    sessionHash: String(record.sessionHash || ""),
    organizationId: String(record.organizationId || ""),
    upstreamExportId: String(record.upstreamExportId || ""),
  });
}

export function encryptContentExport(key, plaintext, aad) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error("content export key must be 32 bytes");
  }
  if (!Buffer.isBuffer(plaintext)) {
    throw new TypeError("content export plaintext must be a Buffer");
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(String(aad), "utf8"), {
    plaintextLength: plaintext.length,
  });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    digest: digest(ciphertext),
    byteLength: plaintext.length,
  };
}

export function decryptContentExport(key, encrypted, aad) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new Error("content export key must be 32 bytes");
  }
  if (!plainObject(encrypted)
      || !isContentBase64(encrypted.ciphertext)
      || !isContentBase64(encrypted.iv, 12)
      || !isContentBase64(encrypted.tag, 16)) {
    throw new Error("encrypted content export is invalid");
  }
  const ciphertext = Buffer.from(encrypted.ciphertext, "base64");
  if (digest(ciphertext) !== encrypted.digest) {
    throw new Error("encrypted content export digest mismatch");
  }
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(encrypted.iv, "base64"),
  );
  decipher.setAAD(Buffer.from(String(aad), "utf8"), {
    plaintextLength: ciphertext.length,
  });
  decipher.setAuthTag(Buffer.from(encrypted.tag, "base64"));
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
