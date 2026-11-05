import crypto from "node:crypto";

export const DETECTION_EVENT_SCHEMA_VERSION = 1;
export const SUBJECT_TYPES = Object.freeze(["user", "device", "agent", "service"]);
export const AUTHORIZATION_DIMENSIONS = Object.freeze([
  "gateway",
  "mcp",
  "model",
  "organization",
  "provider",
  "scope",
  "tool",
]);
export const CONNECTION_ROUTES = Object.freeze([
  "direct_provider",
  "enterprise_gateway",
  "unknown",
]);
export const DEVICE_COMPLIANCE_STATES = Object.freeze([
  "compliant",
  "noncompliant",
  "unknown",
]);
export const SENSITIVE_CATEGORIES = Object.freeze([
  "api_key",
  "bank_card",
  "bearer_token",
  "cloud_access_key",
  "credential",
  "email",
  "national_id",
  "other_sensitive",
  "password",
  "phone",
  "private_key",
]);

const EVENT_ID_PATTERN = /^devt_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const REQUEST_ID_PATTERN = /^req_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const SESSION_ID_PATTERN = /^ses_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const SAFE_CODE_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
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

const EVENT_FIELDS = new Set([
  "schemaVersion",
  "eventId",
  "occurredAt",
  "organizationId",
  "subject",
  "requestId",
  "sessionId",
  "usage",
  "source",
  "authorization",
  "connection",
  "device",
  "content",
]);
const SIGNAL_FIELDS = Object.freeze([
  "usage",
  "source",
  "authorization",
  "connection",
  "device",
  "content",
]);
const SUBJECT_FIELDS = new Set(["type", "id", "orgUnitId"]);
const USAGE_FIELDS = new Set([
  "totalTokens",
  "baselineTokens",
  "cost",
  "baselineCost",
  "budgetLimit",
  "budgetUsed",
]);
const SOURCE_FIELDS = new Set(["region", "ipHash"]);
const AUTHORIZATION_FIELDS = new Set(["decision", "dimension", "policyId"]);
const CONNECTION_FIELDS = new Set(["route", "managedAgent"]);
const DEVICE_FIELDS = new Set(["complianceState", "reasonCodes"]);
const CONTENT_FIELDS = new Set(["sensitiveCategories", "matchCount"]);

export class DetectionEventValidationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "DetectionEventValidationError";
    this.code = code;
  }
}

function invalid(message) {
  throw new DetectionEventValidationError("invalid_detection_event", message);
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
  throw new DetectionEventValidationError(
    "invalid_detection_event",
    "The event contains an unsupported JSON value",
  );
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function sha256Text(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
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

function assertPlainObject(value, name) {
  if (!plainObject(value)) invalid(`${name} must be an object`);
  return value;
}

function rejectUnknownFields(value, allowed, name) {
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) invalid(`${name} contains an unknown field: ${unknown}`);
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

function safeNumber(value, name, maximum) {
  if (typeof value !== "number"
      || !Number.isFinite(value)
      || value < 0
      || value > maximum) {
    invalid(`${name} is invalid`);
  }
  return value;
}

function codeList(value, name, allowed, maximum = 32) {
  if (!Array.isArray(value) || value.length === 0 || value.length > maximum) {
    invalid(`${name} must contain between 1 and ${maximum} entries`);
  }
  for (const item of value) {
    requiredText(item, name, SAFE_CODE_PATTERN, 64);
    if (allowed && !allowed.has(item)) invalid(`${name} contains an unsupported value`);
  }
  if (new Set(value).size !== value.length) invalid(`${name} must not contain duplicates`);
  return [...value];
}

export function hasSecretMaterial(value) {
  const text = canonicalJson(value);
  return SECRET_PATTERNS.some((pattern) => pattern.test(text));
}

function scanSecrets(value) {
  if (hasSecretMaterial(value)) {
    throw new DetectionEventValidationError(
      "detection_secret_detected",
      "Detection events must not contain credentials, tokens or private keys",
    );
  }
}

function normalizeSubject(value) {
  const input = assertPlainObject(value, "subject");
  rejectUnknownFields(input, SUBJECT_FIELDS, "subject");
  const type = requiredText(input.type, "subject.type", SAFE_CODE_PATTERN);
  if (!SUBJECT_TYPES.includes(type)) invalid("subject.type is unsupported");
  const subject = {
    type,
    id: requiredText(input.id, "subject.id", SAFE_ID_PATTERN),
  };
  const orgUnitId = optionalText(input.orgUnitId, "subject.orgUnitId", SAFE_ID_PATTERN);
  if (orgUnitId !== undefined) subject.orgUnitId = orgUnitId;
  return subject;
}

function normalizeUsage(value) {
  const input = assertPlainObject(value, "usage");
  rejectUnknownFields(input, USAGE_FIELDS, "usage");
  const usage = {};
  if (input.totalTokens !== undefined) {
    usage.totalTokens = safeInteger(input.totalTokens, "usage.totalTokens", 1_000_000_000_000);
  }
  if (input.baselineTokens !== undefined) {
    usage.baselineTokens = safeInteger(
      input.baselineTokens,
      "usage.baselineTokens",
      1_000_000_000_000,
    );
  }
  if (input.cost !== undefined) usage.cost = safeNumber(input.cost, "usage.cost", 1_000_000_000);
  if (input.baselineCost !== undefined) {
    usage.baselineCost = safeNumber(input.baselineCost, "usage.baselineCost", 1_000_000_000);
  }
  if (input.budgetLimit !== undefined) {
    usage.budgetLimit = safeNumber(input.budgetLimit, "usage.budgetLimit", 1_000_000_000);
    if (usage.budgetLimit === 0) invalid("usage.budgetLimit must be greater than zero");
  }
  if (input.budgetUsed !== undefined) {
    usage.budgetUsed = safeNumber(input.budgetUsed, "usage.budgetUsed", 1_000_000_000);
  }
  if (Object.keys(usage).length === 0) invalid("usage must contain at least one field");
  return usage;
}

function normalizeSource(value) {
  const input = assertPlainObject(value, "source");
  rejectUnknownFields(input, SOURCE_FIELDS, "source");
  const source = {};
  const region = optionalText(input.region, "source.region", SAFE_CODE_PATTERN, 64);
  if (region !== undefined) source.region = region;
  if (input.ipHash !== undefined) {
    source.ipHash = requiredText(
      input.ipHash,
      "source.ipHash",
      SOURCE_IP_HASH_PATTERN,
      71,
    );
  }
  if (!source.region && !source.ipHash) invalid("source requires region or ipHash");
  return source;
}

function normalizeAuthorization(value) {
  const input = assertPlainObject(value, "authorization");
  rejectUnknownFields(input, AUTHORIZATION_FIELDS, "authorization");
  const decision = requiredText(input.decision, "authorization.decision", SAFE_CODE_PATTERN);
  if (!["allowed", "denied"].includes(decision)) {
    invalid("authorization.decision is unsupported");
  }
  const dimension = requiredText(
    input.dimension,
    "authorization.dimension",
    SAFE_CODE_PATTERN,
  );
  if (!AUTHORIZATION_DIMENSIONS.includes(dimension)) {
    invalid("authorization.dimension is unsupported");
  }
  const authorization = { decision, dimension };
  const policyId = optionalText(
    input.policyId,
    "authorization.policyId",
    SAFE_CODE_PATTERN,
    128,
  );
  if (policyId !== undefined) authorization.policyId = policyId;
  return authorization;
}

function normalizeConnection(value) {
  const input = assertPlainObject(value, "connection");
  rejectUnknownFields(input, CONNECTION_FIELDS, "connection");
  const route = requiredText(input.route, "connection.route", SAFE_CODE_PATTERN);
  if (!CONNECTION_ROUTES.includes(route)) invalid("connection.route is unsupported");
  if (typeof input.managedAgent !== "boolean") {
    invalid("connection.managedAgent must be a boolean");
  }
  return {
    route,
    managedAgent: input.managedAgent,
  };
}

function normalizeDevice(value) {
  const input = assertPlainObject(value, "device");
  rejectUnknownFields(input, DEVICE_FIELDS, "device");
  const complianceState = requiredText(
    input.complianceState,
    "device.complianceState",
    SAFE_CODE_PATTERN,
  );
  if (!DEVICE_COMPLIANCE_STATES.includes(complianceState)) {
    invalid("device.complianceState is unsupported");
  }
  const device = { complianceState };
  if (input.reasonCodes !== undefined) {
    device.reasonCodes = codeList(input.reasonCodes, "device.reasonCodes");
  }
  if (complianceState === "noncompliant" && !device.reasonCodes) {
    invalid("noncompliant devices require reasonCodes");
  }
  return device;
}

function normalizeContent(value) {
  const input = assertPlainObject(value, "content");
  rejectUnknownFields(input, CONTENT_FIELDS, "content");
  const allowed = new Set(SENSITIVE_CATEGORIES);
  const sensitiveCategories = codeList(
    input.sensitiveCategories,
    "content.sensitiveCategories",
    allowed,
  );
  const matchCount = input.matchCount === undefined
    ? 1
    : safeInteger(input.matchCount, "content.matchCount", 1_000_000);
  if (matchCount < 1) invalid("content.matchCount must be greater than zero");
  return { sensitiveCategories, matchCount };
}

export function validateDetectionEvent(value) {
  const input = assertPlainObject(value, "event");
  scanSecrets(input);
  rejectUnknownFields(input, EVENT_FIELDS, "event");
  const required = ["schemaVersion", "eventId", "occurredAt", "organizationId", "subject"];
  for (const field of required) {
    if (!(field in input)) invalid(`The event is missing required field: ${field}`);
  }
  if (input.schemaVersion !== DETECTION_EVENT_SCHEMA_VERSION) {
    invalid("schemaVersion is unsupported");
  }
  if (!SIGNAL_FIELDS.some((field) => input[field] !== undefined)) {
    invalid("The event must contain at least one detection signal");
  }

  const event = {
    schemaVersion: DETECTION_EVENT_SCHEMA_VERSION,
    eventId: requiredText(input.eventId, "eventId", EVENT_ID_PATTERN),
    occurredAt: validateTimestamp(input.occurredAt),
    organizationId: requiredText(input.organizationId, "organizationId", SAFE_ID_PATTERN),
    subject: normalizeSubject(input.subject),
  };
  const requestId = optionalText(input.requestId, "requestId", REQUEST_ID_PATTERN);
  const sessionId = optionalText(input.sessionId, "sessionId", SESSION_ID_PATTERN);
  if (requestId !== undefined) event.requestId = requestId;
  if (sessionId !== undefined) event.sessionId = sessionId;
  if (input.usage !== undefined) event.usage = normalizeUsage(input.usage);
  if (input.source !== undefined) event.source = normalizeSource(input.source);
  if (input.authorization !== undefined) {
    event.authorization = normalizeAuthorization(input.authorization);
  }
  if (input.connection !== undefined) event.connection = normalizeConnection(input.connection);
  if (input.device !== undefined) event.device = normalizeDevice(input.device);
  if (input.content !== undefined) event.content = normalizeContent(input.content);

  return canonicalValue(event);
}
