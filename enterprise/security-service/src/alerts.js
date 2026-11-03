import {
  canonicalJson,
  hasSecretMaterial,
  plainObject,
  sha256Text,
} from "./events.js";

export const ALERT_SCHEMA_VERSION = 1;
export const ALERT_STATUSES = Object.freeze(["open", "acknowledged", "resolved"]);
export const ALERT_EVENTS = Object.freeze([
  "opened",
  "assigned",
  "acknowledged",
  "resolved",
  "reopened",
]);
export const ALERT_OPERATIONS = Object.freeze([
  "create",
  "assign",
  "acknowledge",
  "resolve",
  "reopen",
]);
export const ALERT_SEVERITIES = Object.freeze(["warning", "high", "critical"]);
export const ALERT_SLA_SECONDS = Object.freeze({
  critical: 300,
  high: 3_600,
  warning: 86_400,
});

const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const SAFE_CODE_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const ALERT_ID_PATTERN = /^sal_[a-f0-9]{24}$/;
const AUDIT_ID_PATTERN = /^saa_[a-f0-9]{24}$/;
const SOURCE_ID_PATTERN = /^(?:sdf|sag)_[a-f0-9]{24}$/;
const RULE_ID_PATTERN = /^sec\.[a-z0-9._-]+$/;
const REQUEST_ID_PATTERN = /^req_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const SOURCE_TYPES = new Set(["finding", "aggregate"]);
const SUBJECT_TYPES = new Set(["user", "device", "agent", "service"]);

const ALERT_FIELDS = new Set([
  "schemaVersion",
  "alertId",
  "status",
  "severity",
  "ruleId",
  "organizationId",
  "source",
  "subject",
  "detectedAt",
  "createdAt",
  "updatedAt",
  "revision",
  "assigneeSubjectId",
  "acknowledgedAt",
  "resolvedAt",
  "resolutionCode",
  "slaDueAt",
  "lastRequestId",
]);
const SOURCE_FIELDS = new Set(["type", "id"]);
const SUBJECT_FIELDS = new Set(["type", "id", "orgUnitId"]);
const AUDIT_FIELDS = new Set([
  "auditId",
  "alertId",
  "sequence",
  "event",
  "status",
  "actorSubjectId",
  "reason",
  "assigneeSubjectId",
  "resolutionCode",
  "at",
  "requestId",
  "previousHash",
  "hash",
]);
const IDEMPOTENCY_FIELDS = new Set([
  "keyHash",
  "alertId",
  "operation",
  "requestDigest",
  "createdAt",
]);
const CREATE_FIELDS = new Set([
  "source",
  "organizationId",
  "actorSubjectId",
  "assigneeSubjectId",
  "reason",
]);
const ACTOR_FIELDS = new Set(["actorSubjectId", "reason"]);
const ASSIGN_FIELDS = new Set(["actorSubjectId", "assigneeSubjectId", "reason"]);
const RESOLVE_FIELDS = new Set(["actorSubjectId", "reason", "resolutionCode"]);

export class AlertValidationError extends Error {
  constructor(statusCode, code, message, retryable = false) {
    super(message);
    this.name = "AlertValidationError";
    this.statusCode = statusCode;
    this.code = code;
    this.retryable = retryable;
  }
}

function invalid(message, code = "invalid_alert") {
  throw new AlertValidationError(400, code, message);
}

export function alertConflict(message, code = "alert_transition_conflict") {
  throw new AlertValidationError(409, code, message);
}

function timestamp(value) {
  return typeof value === "string"
    && TIMESTAMP_PATTERN.test(value)
    && Number.isFinite(Date.parse(value))
    && new Date(value).toISOString() === value;
}

function exactObject(value, allowed, name) {
  if (!plainObject(value)
      || Object.keys(value).some((key) => !allowed.has(key))) {
    invalid(`${name} is invalid`);
  }
  return value;
}

function safeId(value, name) {
  if (typeof value !== "string" || !SAFE_ID_PATTERN.test(value)) {
    invalid(`${name} is invalid`);
  }
  return value;
}

function reasonText(value, name = "reason") {
  if (typeof value !== "string"
      || value.trim() !== value
      || value.length < 8
      || value.length > 512
      || /[\u0000-\u001f\u007f]/.test(value)
      || hasSecretMaterial({ value })) {
    invalid(`${name} must be 8-512 printable characters without secret material`);
  }
  return value;
}

function exactTimestamp(value, name) {
  if (!timestamp(value)) invalid(`${name} is invalid`);
  return value;
}

function sourceValue(value) {
  exactObject(value, SOURCE_FIELDS, "source");
  if (!SOURCE_TYPES.has(value.type)) invalid("source.type is invalid");
  if (typeof value.id !== "string" || !SOURCE_ID_PATTERN.test(value.id)) {
    invalid("source.id is invalid");
  }
  return { type: value.type, id: value.id };
}

function subjectValue(value) {
  exactObject(value, SUBJECT_FIELDS, "subject");
  if (!SUBJECT_TYPES.has(value.type)) invalid("subject.type is invalid");
  const normalized = {
    type: value.type,
    id: safeId(value.id, "subject.id"),
  };
  if (value.orgUnitId !== undefined) {
    normalized.orgUnitId = safeId(value.orgUnitId, "subject.orgUnitId");
  }
  return normalized;
}

function optionalActor(value, name) {
  if (value === "") return "";
  return safeId(value, name);
}

export function normalizeIdempotencyKey(value) {
  if (typeof value !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/.test(value)) {
    invalid(
      "Idempotency-Key must be 16-128 letters, digits, dots, colons, underscores or dashes",
      "invalid_idempotency_key",
    );
  }
  return value;
}

export function alertIdempotencyHash(value) {
  return sha256Text(`alert-idempotency:${value}`);
}

export function alertRequestDigest(operation, organizationId, alertId, body) {
  return sha256Text(canonicalJson({
    schemaVersion: ALERT_SCHEMA_VERSION,
    operation,
    organizationId,
    alertId,
    body,
  }));
}

export function normalizeAlertCreateRequest(value) {
  exactObject(value, CREATE_FIELDS, "alert request");
  const assigneeSubjectId = optionalActor(
    value.assigneeSubjectId ?? "",
    "assigneeSubjectId",
  );
  return {
    source: sourceValue(value.source),
    organizationId: safeId(value.organizationId, "organizationId"),
    actorSubjectId: safeId(value.actorSubjectId, "actorSubjectId"),
    assigneeSubjectId,
    reason: reasonText(value.reason),
  };
}

export function normalizeAlertAssignRequest(value) {
  exactObject(value, ASSIGN_FIELDS, "alert assignment");
  return {
    actorSubjectId: safeId(value.actorSubjectId, "actorSubjectId"),
    assigneeSubjectId: safeId(value.assigneeSubjectId, "assigneeSubjectId"),
    reason: reasonText(value.reason),
  };
}

export function normalizeAlertActorRequest(value) {
  exactObject(value, ACTOR_FIELDS, "alert operation");
  return {
    actorSubjectId: safeId(value.actorSubjectId, "actorSubjectId"),
    reason: reasonText(value.reason),
  };
}

export function normalizeAlertResolveRequest(value) {
  exactObject(value, RESOLVE_FIELDS, "alert resolution");
  const resolutionCode = String(value.resolutionCode || "");
  if (!SAFE_CODE_PATTERN.test(resolutionCode)) invalid("resolutionCode is invalid");
  return {
    actorSubjectId: safeId(value.actorSubjectId, "actorSubjectId"),
    reason: reasonText(value.reason),
    resolutionCode,
  };
}

export function alertIdFor({ organizationId, source, ruleId, severity }) {
  return `sal_${sha256Text(canonicalJson({
    schemaVersion: ALERT_SCHEMA_VERSION,
    organizationId,
    source,
    ruleId,
    severity,
  })).slice(0, 24)}`;
}

export function alertAuditEntry(input) {
  const base = {
    auditId: "",
    alertId: input.alertId,
    sequence: input.sequence,
    event: input.event,
    status: input.status,
    actorSubjectId: input.actorSubjectId,
    reason: input.reason,
    assigneeSubjectId: input.assigneeSubjectId || "",
    resolutionCode: input.resolutionCode || "",
    at: input.at,
    requestId: input.requestId,
    previousHash: input.previousHash,
    hash: "",
  };
  base.auditId = `saa_${sha256Text(canonicalJson(base)).slice(0, 24)}`;
  base.hash = sha256Text(canonicalJson(base));
  return base;
}

export function publicAlert(alert) {
  return structuredClone(alert);
}

export function publicAlertAudit(entry) {
  return { ...entry };
}

export function isAlertId(value) {
  return ALERT_ID_PATTERN.test(value || "");
}

export function isAlertStatus(value) {
  return ALERT_STATUSES.includes(value);
}

export function isAlertSeverity(value) {
  return ALERT_SEVERITIES.includes(value);
}

export function isAlertSourceId(value) {
  return SOURCE_ID_PATTERN.test(value || "");
}

export function validateAlertRecord(value) {
  exactObject(value, ALERT_FIELDS, "alert");
  if (value.schemaVersion !== ALERT_SCHEMA_VERSION
      || !isAlertId(value.alertId)
      || !isAlertStatus(value.status)
      || !isAlertSeverity(value.severity)
      || !RULE_ID_PATTERN.test(value.ruleId || "")
      || !SAFE_ID_PATTERN.test(value.organizationId || "")
      || !timestamp(value.detectedAt)
      || !timestamp(value.createdAt)
      || !timestamp(value.updatedAt)
      || value.detectedAt > value.createdAt
      || value.createdAt > value.updatedAt
      || !Number.isSafeInteger(value.revision)
      || value.revision < 1
      || !timestamp(value.slaDueAt)
      || !REQUEST_ID_PATTERN.test(value.lastRequestId || "")
      || !hasSafeText(value)) {
    invalid("stored alert is invalid", "security_store_invalid");
  }
  const source = sourceValue(value.source);
  const subject = subjectValue(value.subject);
  const assigneeSubjectId = optionalActor(
    value.assigneeSubjectId,
    "assigneeSubjectId",
  );
  const acknowledgedAt = value.acknowledgedAt === ""
    ? ""
    : exactTimestamp(value.acknowledgedAt, "acknowledgedAt");
  const resolvedAt = value.resolvedAt === ""
    ? ""
    : exactTimestamp(value.resolvedAt, "resolvedAt");
  const resolutionCode = value.resolutionCode === ""
    ? ""
    : (SAFE_CODE_PATTERN.test(value.resolutionCode)
      ? value.resolutionCode
      : invalid("resolutionCode is invalid"));

  if (value.status === "open") {
    if (acknowledgedAt !== "" || resolvedAt !== "" || resolutionCode !== "") {
      invalid("open alert state is inconsistent", "security_store_invalid");
    }
  } else if (value.status === "acknowledged") {
    if (acknowledgedAt === "" || resolvedAt !== "" || resolutionCode !== "") {
      invalid("acknowledged alert state is inconsistent", "security_store_invalid");
    }
  } else if (acknowledgedAt === "" || resolvedAt === "" || resolutionCode === "") {
    invalid("resolved alert state is inconsistent", "security_store_invalid");
  }
  if ((acknowledgedAt && acknowledgedAt < value.createdAt)
      || (resolvedAt
        && (resolvedAt < value.createdAt
          || (acknowledgedAt && resolvedAt < acknowledgedAt)))) {
    invalid("alert transition times are inconsistent", "security_store_invalid");
  }
  return {
    ...value,
    source,
    subject,
    assigneeSubjectId,
    acknowledgedAt,
    resolvedAt,
    resolutionCode,
  };
}

function hasSafeText(value) {
  return !hasSecretMaterial({
    alertId: value.alertId,
    ruleId: value.ruleId,
    organizationId: value.organizationId,
    subject: value.subject,
  });
}

export function validateAlertAuditChain(alert, audits) {
  if (!Array.isArray(audits) || audits.length === 0) {
    invalid("alert audit chain is empty", "security_store_invalid");
  }
  let previousHash = "0".repeat(64);
  let status = "open";
  let assigneeSubjectId = "";
  let acknowledgedAt = "";
  let resolvedAt = "";
  let resolutionCode = "";
  for (const [index, raw] of audits.entries()) {
    exactObject(raw, AUDIT_FIELDS, "alert audit");
    if (!AUDIT_ID_PATTERN.test(raw.auditId || "")
        || raw.alertId !== alert.alertId
        || raw.sequence !== index + 1
        || !ALERT_EVENTS.includes(raw.event)
        || !isAlertStatus(raw.status)
        || !SAFE_ID_PATTERN.test(raw.actorSubjectId || "")
        || (raw.assigneeSubjectId !== ""
          && !SAFE_ID_PATTERN.test(raw.assigneeSubjectId || ""))
        || (raw.resolutionCode !== ""
          && !SAFE_CODE_PATTERN.test(raw.resolutionCode || ""))
        || !timestamp(raw.at)
        || !REQUEST_ID_PATTERN.test(raw.requestId || "")
        || raw.previousHash !== previousHash
        || !HASH_PATTERN.test(raw.hash || "")
        || hasSecretMaterial(raw)) {
      invalid("alert audit is invalid", "security_store_invalid");
    }
    reasonText(raw.reason);
    const expected = alertAuditEntry({
      alertId: raw.alertId,
      sequence: raw.sequence,
      event: raw.event,
      status: raw.status,
      actorSubjectId: raw.actorSubjectId,
      reason: raw.reason,
      assigneeSubjectId: raw.assigneeSubjectId,
      resolutionCode: raw.resolutionCode,
      at: raw.at,
      requestId: raw.requestId,
      previousHash: raw.previousHash,
    });
    if (expected.hash !== raw.hash || expected.auditId !== raw.auditId) {
      invalid("alert audit hash is invalid", "security_store_invalid");
    }

    if (index === 0) {
      if (raw.event !== "opened"
          || raw.status !== "open"
          || raw.at !== alert.createdAt
          || raw.resolutionCode !== "") {
        invalid("alert audit chronology is invalid", "security_store_invalid");
      }
      assigneeSubjectId = raw.assigneeSubjectId;
    } else if (raw.event === "assigned") {
      if (!raw.assigneeSubjectId || raw.resolutionCode !== "") {
        invalid("alert assignment audit is invalid", "security_store_invalid");
      }
      assigneeSubjectId = raw.assigneeSubjectId;
    } else if (raw.event === "acknowledged") {
      if (status !== "open"
          || raw.assigneeSubjectId !== ""
          || raw.resolutionCode !== "") {
        invalid("alert acknowledgement order is invalid", "security_store_invalid");
      }
      status = "acknowledged";
      acknowledgedAt = raw.at;
    } else if (raw.event === "resolved") {
      if (!["open", "acknowledged"].includes(status)
          || raw.assigneeSubjectId !== "") {
        invalid("alert resolution order is invalid", "security_store_invalid");
      }
      status = "resolved";
      if (acknowledgedAt === "") acknowledgedAt = raw.at;
      resolvedAt = raw.at;
      resolutionCode = raw.resolutionCode;
      if (!resolutionCode) {
        invalid("alert resolution audit is invalid", "security_store_invalid");
      }
    } else if (raw.event === "reopened") {
      if (status !== "resolved"
          || raw.assigneeSubjectId !== ""
          || raw.resolutionCode !== "") {
        invalid("alert reopen order is invalid", "security_store_invalid");
      }
      status = "open";
      acknowledgedAt = "";
      resolvedAt = "";
      resolutionCode = "";
    } else if (raw.event === "opened") {
      invalid("alert has more than one open event", "security_store_invalid");
    }
    if (raw.status !== status) {
      invalid("alert audit status is inconsistent", "security_store_invalid");
    }
    previousHash = raw.hash;
  }
  const last = audits.at(-1);
  if (last.status !== alert.status
      || last.at !== alert.updatedAt
      || audits.length !== alert.revision
      || assigneeSubjectId !== alert.assigneeSubjectId
      || acknowledgedAt !== alert.acknowledgedAt
      || resolvedAt !== alert.resolvedAt
      || resolutionCode !== alert.resolutionCode) {
    invalid("alert audit does not match the alert state", "security_store_invalid");
  }
  return audits;
}

export function validateAlertIdempotencyRecord(keyHash, value) {
  exactObject(value, IDEMPOTENCY_FIELDS, "alert idempotency record");
  if (!HASH_PATTERN.test(keyHash || "")
      || value.keyHash !== keyHash
      || !isAlertId(value.alertId)
      || !ALERT_OPERATIONS.includes(value.operation)
      || !HASH_PATTERN.test(value.requestDigest || "")
      || !timestamp(value.createdAt)) {
    invalid("alert idempotency record is invalid", "security_store_invalid");
  }
  return { ...value };
}
