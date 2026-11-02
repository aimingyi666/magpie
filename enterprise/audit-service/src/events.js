import crypto from "node:crypto";

export const AUDIT_EVENT_SCHEMA_VERSION = 1;
export const AUDIT_LEVELS = Object.freeze(["L0", "L1"]);
export const EVENT_KINDS = Object.freeze(["request", "response", "tool_call", "policy_decision"]);
export const REQUEST_KINDS = Object.freeze(["chat", "responses", "messages", "mcp"]);
export const EVENT_STATUSES = Object.freeze(["started", "success", "blocked", "error"]);

const EVENT_ID_PATTERN = /^evt_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const REQUEST_ID_PATTERN = /^req_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const SESSION_ID_PATTERN = /^ses_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const SAFE_CODE_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/;
const TOOL_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const CATEGORY_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const MODEL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._:@+-]{0,159}$/;
const CLIENT_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;
const SOURCE_IP_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SECRET_PATTERNS = Object.freeze([
  /-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
  /\bBearer\s+[A-Za-z0-9._~-]{20,}\b/i,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
]);

const REQUIRED_FIELDS = Object.freeze([
  "schemaVersion",
  "eventId",
  "requestId",
  "sessionId",
  "eventKind",
  "auditLevel",
  "occurredAt",
  "userId",
  "departmentId",
  "deviceId",
  "agentId",
  "clientVersion",
  "requestKind",
  "status",
]);
const OPTIONAL_FIELDS = Object.freeze([
  "modelId",
  "providerId",
  "mcpServerId",
  "toolName",
  "parameterCategories",
  "errorCode",
  "inputTokens",
  "outputTokens",
  "cost",
  "latencyMs",
  "sourceIpHash",
  "policyHits",
]);
const EVENT_FIELDS = new Set([...REQUIRED_FIELDS, ...OPTIONAL_FIELDS]);
const EVENT_KIND_SET = new Set(EVENT_KINDS);
const AUDIT_LEVEL_SET = new Set(AUDIT_LEVELS);
const REQUEST_KIND_SET = new Set(REQUEST_KINDS);
const STATUS_SET = new Set(EVENT_STATUSES);

export class AuditEventValidationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AuditEventValidationError";
    this.code = code;
  }
}

function invalid(message) {
  throw new AuditEventValidationError("invalid_audit_event", message);
}

export function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

export function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (plainObject(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])]),
    );
  }
  if (value === null || ["string", "boolean"].includes(typeof value)) return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  throw new AuditEventValidationError("invalid_audit_event", "The event contains an unsupported JSON value");
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function sha256Text(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function requiredText(value, name, pattern, maximum = 128) {
  if (typeof value !== "string"
      || value.length === 0
      || value.length > maximum
      || !pattern.test(value)) {
    invalid(`${name} is invalid`);
  }
  return value;
}

function optionalText(value, name, pattern, maximum = 128) {
  if (value === undefined) return undefined;
  return requiredText(value, name, pattern, maximum);
}

function safeInteger(value, name, maximum) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    invalid(`${name} is invalid`);
  }
  return value;
}

function uniqueCodes(value, name, maximum, pattern = SAFE_CODE_PATTERN) {
  if (!Array.isArray(value) || value.length > maximum) {
    invalid(`${name} must contain at most ${maximum} entries`);
  }
  for (const item of value) requiredText(item, name, pattern);
  if (new Set(value).size !== value.length) invalid(`${name} must not contain duplicates`);
  return [...value];
}

function scanSecrets(value) {
  const text = canonicalJson(value);
  if (SECRET_PATTERNS.some((pattern) => pattern.test(text))) {
    throw new AuditEventValidationError(
      "audit_secret_detected",
      "Audit events must not contain credentials, tokens or private keys",
    );
  }
}

export function validateTimestamp(value, name = "occurredAt") {
  if (typeof value !== "string"
      || !TIMESTAMP_PATTERN.test(value)
      || !Number.isFinite(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    invalid(`${name} is invalid`);
  }
  return value;
}

export function validateAuditEvent(value) {
  if (!plainObject(value)) invalid("The event must be a JSON object");
  const unknown = Object.keys(value).find((key) => !EVENT_FIELDS.has(key));
  if (unknown) invalid(`The event contains an unknown field: ${unknown}`);
  for (const field of REQUIRED_FIELDS) {
    if (!(field in value)) invalid(`The event is missing required field: ${field}`);
  }

  if (value.schemaVersion !== AUDIT_EVENT_SCHEMA_VERSION) {
    invalid("schemaVersion is unsupported");
  }
  const event = {
    schemaVersion: AUDIT_EVENT_SCHEMA_VERSION,
    eventId: requiredText(value.eventId, "eventId", EVENT_ID_PATTERN),
    requestId: requiredText(value.requestId, "requestId", REQUEST_ID_PATTERN),
    sessionId: requiredText(value.sessionId, "sessionId", SESSION_ID_PATTERN),
    eventKind: requiredText(value.eventKind, "eventKind", SAFE_CODE_PATTERN),
    auditLevel: requiredText(value.auditLevel, "auditLevel", /^L[01]$/),
    occurredAt: validateTimestamp(value.occurredAt),
    userId: requiredText(value.userId, "userId", SAFE_ID_PATTERN),
    departmentId: requiredText(value.departmentId, "departmentId", SAFE_ID_PATTERN),
    deviceId: requiredText(value.deviceId, "deviceId", SAFE_ID_PATTERN),
    agentId: requiredText(value.agentId, "agentId", SAFE_ID_PATTERN),
    clientVersion: requiredText(value.clientVersion, "clientVersion", CLIENT_VERSION_PATTERN),
    requestKind: requiredText(value.requestKind, "requestKind", SAFE_CODE_PATTERN),
    status: requiredText(value.status, "status", SAFE_CODE_PATTERN),
  };

  if (!EVENT_KIND_SET.has(event.eventKind)) invalid("eventKind is unsupported");
  if (!AUDIT_LEVEL_SET.has(event.auditLevel)) invalid("auditLevel is unsupported");
  if (!REQUEST_KIND_SET.has(event.requestKind)) invalid("requestKind is unsupported");
  if (!STATUS_SET.has(event.status)) invalid("status is unsupported");

  const optional = [
    ["modelId", value.modelId, MODEL_ID_PATTERN, 192],
    ["providerId", value.providerId, SAFE_ID_PATTERN, 128],
    ["mcpServerId", value.mcpServerId, SAFE_ID_PATTERN, 128],
    ["toolName", value.toolName, TOOL_NAME_PATTERN, 128],
    ["errorCode", value.errorCode, SAFE_CODE_PATTERN, 128],
  ];
  for (const [name, item, pattern, maximum] of optional) {
    const normalized = optionalText(item, name, pattern, maximum);
    if (normalized !== undefined) event[name] = normalized;
  }
  if (value.parameterCategories !== undefined) {
    event.parameterCategories = uniqueCodes(value.parameterCategories, "parameterCategories", 16, CATEGORY_PATTERN);
  }
  if (value.policyHits !== undefined) {
    event.policyHits = uniqueCodes(value.policyHits, "policyHits", 32);
  }
  for (const [name, maximum] of [["inputTokens", 1_000_000_000_000], ["outputTokens", 1_000_000_000_000], ["latencyMs", 86_400_000]]) {
    if (value[name] !== undefined) event[name] = safeInteger(value[name], name, maximum);
  }
  if (value.cost !== undefined) {
    if (typeof value.cost !== "number" || !Number.isFinite(value.cost) || value.cost < 0 || value.cost > 1_000_000_000) {
      invalid("cost is invalid");
    }
    event.cost = value.cost;
  }
  if (value.sourceIpHash !== undefined) {
    event.sourceIpHash = requiredText(value.sourceIpHash, "sourceIpHash", SOURCE_IP_HASH_PATTERN, 71);
  }

  if (event.eventKind === "response" && event.status === "started") {
    invalid("response events cannot have started status");
  }
  if (event.eventKind === "tool_call") {
    if (event.auditLevel !== "L1" || event.requestKind !== "mcp") {
      invalid("tool_call events must be L1 mcp events");
    }
    if (!event.toolName || !event.parameterCategories) {
      invalid("tool_call events require toolName and parameterCategories");
    }
    if (event.status === "started") invalid("tool_call events require a terminal status");
  }
  if (event.eventKind === "policy_decision") {
    if (!event.policyHits || event.policyHits.length === 0) {
      invalid("policy_decision events require policyHits");
    }
    if (event.status === "started") invalid("policy_decision events require a terminal status");
  }
  if (event.auditLevel === "L0"
      && (event.toolName !== undefined || event.parameterCategories !== undefined)) {
    invalid("L0 events must not contain tool names or parameter categories");
  }

  scanSecrets(event);
  return canonicalValue(event);
}
