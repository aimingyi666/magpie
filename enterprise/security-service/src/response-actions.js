import {
  canonicalJson,
  hasSecretMaterial,
  plainObject,
  sha256Text,
} from "./events.js";

export const RESPONSE_ACTION_SCHEMA_VERSION = 1;
export const RESPONSE_ACTION_TYPES = Object.freeze([
  "rate_limit",
  "block",
  "revoke_key",
  "lock_device",
  "open_ticket",
]);
export const RESPONSE_ACTION_STATUSES = Object.freeze([
  "requested",
  "approved",
  "active",
  "reverted",
  "expired",
  "failed",
]);
export const RESPONSE_ACTION_EVENTS = Object.freeze([
  "requested",
  "approved",
  "activated",
  "activation_failed",
  "reverted",
  "revert_failed",
  "expired",
]);
export const RESPONSE_ACTION_OPERATIONS = Object.freeze([
  "create",
  "approve",
  "activate",
  "revert",
  "expire",
]);

const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const SAFE_CODE_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const IP_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const ACTION_ID_PATTERN = /^sra_[a-f0-9]{24}$/;
const AUDIT_ID_PATTERN = /^sae_[a-f0-9]{24}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;
const TARGET_TYPES = new Set([
  "user",
  "device",
  "agent",
  "service",
  "gateway_key",
  "ip_hash",
]);
const SOURCE_TYPES = new Set(["finding", "aggregate"]);
const AUTHORIZATION_MODES = new Set(["approval", "break_glass"]);
const REQUEST_ID_PATTERN = /^req_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const ZERO_HASH = "0".repeat(64);

const EVENT_STATUS = new Map([
  ["requested", "requested"],
  ["approved", "approved"],
  ["activated", "active"],
  ["activation_failed", "failed"],
  ["reverted", "reverted"],
  ["revert_failed", "active"],
  ["expired", "expired"],
]);

const ALLOWED_TRANSITIONS = new Map([
  ["requested", new Map([
    ["approved", "approved"],
    ["expired", "expired"],
  ])],
  ["approved", new Map([
    ["activated", "active"],
    ["activation_failed", "failed"],
    ["expired", "expired"],
  ])],
  ["active", new Map([
    ["reverted", "reverted"],
    ["revert_failed", "active"],
  ])],
  ["reverted", new Map()],
  ["expired", new Map()],
  ["failed", new Map()],
]);

const OPERATION_EVENTS = new Map([
  ["create", new Set(["requested"])],
  ["approve", new Set(["approved"])],
  ["activate", new Set(["activated", "activation_failed"])],
  ["revert", new Set(["reverted", "revert_failed"])],
  ["expire", new Set(["expired"])],
]);

const ACTION_TARGET_TYPES = new Map([
  ["rate_limit", new Set(["user", "device", "agent", "service", "gateway_key", "ip_hash"])],
  ["block", new Set(["user", "device", "agent", "service", "ip_hash"])],
  ["revoke_key", new Set(["gateway_key"])],
  ["lock_device", new Set(["device"])],
  ["open_ticket", new Set(["user", "device", "agent", "service", "gateway_key", "ip_hash"])],
]);

const REQUEST_FIELDS = new Set([
  "actionType",
  "source",
  "organizationId",
  "target",
  "reason",
  "requestedBySubjectId",
  "durationSeconds",
]);
const SOURCE_FIELDS = new Set(["type", "id"]);
const TARGET_FIELDS = new Set(["type", "id"]);
const APPROVE_FIELDS = new Set(["actorSubjectId", "reason", "authorization"]);
const AUTHORIZATION_FIELDS = new Set([
  "mode",
  "reference",
  "actorSubjectId",
  "incidentId",
  "stepUpReference",
  "approvedAt",
  "expiresAt",
]);
const ACTOR_FIELDS = new Set(["actorSubjectId", "reason"]);

export const RESPONSE_ACTION_FIELDS = new Set([
  "schemaVersion",
  "actionId",
  "status",
  "actionType",
  "source",
  "organizationId",
  "target",
  "reason",
  "requestedBySubjectId",
  "requestedAt",
  "updatedAt",
  "revision",
  "startsAt",
  "expiresAt",
  "authorization",
  "execution",
  "idempotencyKeyHash",
  "requestDigest",
  "lastRequestId",
]);
export const RESPONSE_AUDIT_FIELDS = new Set([
  "auditId",
  "actionId",
  "sequence",
  "event",
  "status",
  "actorSubjectId",
  "reason",
  "at",
  "requestId",
  "previousHash",
  "hash",
]);
export const RESPONSE_IDEMPOTENCY_FIELDS = new Set([
  "keyHash",
  "actionId",
  "operation",
  "requestDigest",
  "createdAt",
]);

export class ResponseActionValidationError extends Error {
  constructor(statusCode, code, message, retryable = false) {
    super(message);
    this.name = "ResponseActionValidationError";
    this.statusCode = statusCode;
    this.code = code;
    this.retryable = retryable;
  }
}

function invalid(message, code = "invalid_response_action") {
  throw new ResponseActionValidationError(400, code, message);
}

function conflict(code, message) {
  throw new ResponseActionValidationError(409, code, message);
}

function timestamp(value, name = "timestamp") {
  return typeof value === "string"
    && TIMESTAMP_PATTERN.test(value)
    && Number.isFinite(Date.parse(value))
    && new Date(value).toISOString() === value;
}

function text(value, name, pattern, maximum = 128) {
  if (typeof value !== "string"
      || value.length === 0
      || value.length > maximum
      || !pattern.test(value)) {
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

export function isResponseReason(value) {
  try {
    reasonText(value);
    return true;
  } catch {
    return false;
  }
}

function exactObject(value, allowed, name) {
  if (!plainObject(value)
      || Object.keys(value).some((key) => !allowed.has(key))) {
    invalid(`${name} is invalid`);
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
  return {
    type: value.type,
    id: text(value.id, "source.id", /^(?:sdf|sag)_[a-f0-9]{24}$/),
  };
}

function targetValue(value) {
  exactObject(value, TARGET_FIELDS, "target");
  if (!TARGET_TYPES.has(value.type)) invalid("target.type is invalid");
  const pattern = value.type === "ip_hash" ? IP_HASH_PATTERN : SAFE_ID_PATTERN;
  return {
    type: value.type,
    id: text(value.id, "target.id", pattern),
  };
}

export function normalizeResponseActionRequest(value) {
  exactObject(value, REQUEST_FIELDS, "response action request");
  if (!RESPONSE_ACTION_TYPES.includes(value.actionType)) {
    invalid("actionType is invalid");
  }
  const source = sourceValue(value.source);
  const target = targetValue(value.target);
  if (!ACTION_TARGET_TYPES.get(value.actionType).has(target.type)) {
    invalid(`target.type is not valid for ${value.actionType}`);
  }
  if (!Number.isSafeInteger(value.durationSeconds)
      || value.durationSeconds < 60
      || value.durationSeconds > 2_592_000) {
    invalid("durationSeconds must be an integer from 60 to 2592000");
  }
  const result = {
    actionType: value.actionType,
    source,
    organizationId: text(value.organizationId, "organizationId", SAFE_ID_PATTERN),
    target,
    reason: reasonText(value.reason),
    requestedBySubjectId: text(
      value.requestedBySubjectId,
      "requestedBySubjectId",
      SAFE_ID_PATTERN,
    ),
    durationSeconds: value.durationSeconds,
  };
  if (hasSecretMaterial(result)) invalid("response action request contains secret material");
  return result;
}

export function normalizeApprovalRequest(value) {
  exactObject(value, APPROVE_FIELDS, "approval request");
  const authorization = exactObject(
    value.authorization,
    AUTHORIZATION_FIELDS,
    "authorization",
  );
  if (!AUTHORIZATION_MODES.has(authorization.mode)) {
    invalid("authorization.mode is invalid");
  }
  const normalized = {
    mode: authorization.mode,
    reference: text(authorization.reference, "authorization.reference", SAFE_ID_PATTERN),
    actorSubjectId: text(
      authorization.actorSubjectId,
      "authorization.actorSubjectId",
      SAFE_ID_PATTERN,
    ),
    incidentId: "",
    stepUpReference: text(
      authorization.stepUpReference,
      "authorization.stepUpReference",
      SAFE_ID_PATTERN,
    ),
    approvedAt: exactTimestamp(authorization.approvedAt, "authorization.approvedAt"),
    expiresAt: exactTimestamp(authorization.expiresAt, "authorization.expiresAt"),
  };
  if (authorization.mode === "break_glass") {
    normalized.incidentId = text(
      authorization.incidentId,
      "authorization.incidentId",
      SAFE_ID_PATTERN,
    );
  } else if (authorization.incidentId !== undefined && authorization.incidentId !== "") {
    invalid("authorization.incidentId is only valid for break_glass");
  }
  if (normalized.expiresAt <= normalized.approvedAt) {
    invalid("authorization.expiresAt must be after approvedAt");
  }
  const result = {
    actorSubjectId: text(value.actorSubjectId, "actorSubjectId", SAFE_ID_PATTERN),
    reason: reasonText(value.reason),
    authorization: normalized,
  };
  if (result.actorSubjectId !== normalized.actorSubjectId) {
    invalid("actorSubjectId must match authorization.actorSubjectId");
  }
  if (hasSecretMaterial(result)) invalid("approval request contains secret material");
  return result;
}

export function normalizeActorRequest(value) {
  exactObject(value, ACTOR_FIELDS, "response action request");
  const result = {
    actorSubjectId: text(value.actorSubjectId, "actorSubjectId", SAFE_ID_PATTERN),
    reason: reasonText(value.reason),
  };
  if (hasSecretMaterial(result)) invalid("response action request contains secret material");
  return result;
}

export function normalizeIdempotencyKey(value) {
  if (typeof value !== "string" || !IDEMPOTENCY_KEY_PATTERN.test(value)) {
    throw new ResponseActionValidationError(
      400,
      "invalid_idempotency_key",
      "Idempotency-Key must be 16-128 safe characters",
    );
  }
  return value;
}

export function responseRequestDigest(operation, organizationId, actionId, value) {
  return sha256Text(canonicalJson({
    operation,
    organizationId,
    actionId: actionId || "",
    value,
  }));
}

export function responseIdempotencyHash(value) {
  return sha256Text(value);
}

export function responseActionId(input) {
  return `sra_${sha256Text(canonicalJson({
    organizationId: input.organizationId,
    actionType: input.actionType,
    source: input.source,
    target: input.target,
    idempotencyKeyHash: input.idempotencyKeyHash,
  })).slice(0, 24)}`;
}

export function emptyExecution() {
  return {
    activation: null,
    reversion: null,
  };
}

export function normalizeExecution(value, expectedState, at) {
  if (!plainObject(value)
      || typeof value.policyApplied !== "boolean"
      || value.policyApplied !== true
      || typeof value.gatewayApplied !== "boolean"
      || typeof value.adapter !== "string"
      || !SAFE_CODE_PATTERN.test(value.adapter)
      || typeof value.resultCode !== "string"
      || !SAFE_CODE_PATTERN.test(value.resultCode)
      || typeof value.evidenceRef !== "string"
      || (value.evidenceRef !== ""
        && !SAFE_ID_PATTERN.test(value.evidenceRef))
      || hasSecretMaterial(value)) {
    throw new Error("response executor returned an invalid result");
  }
  exactTimestamp(at, "execution.at");
  return {
    state: expectedState,
    policyApplied: value.policyApplied,
    gatewayApplied: value.gatewayApplied,
    adapter: value.adapter,
    resultCode: value.resultCode,
    evidenceRef: value.evidenceRef,
    at,
  };
}

export function failedExecution(errorCode, at) {
  const code = typeof errorCode === "string" && SAFE_CODE_PATTERN.test(errorCode)
    ? errorCode
    : "response_executor_failed";
  exactTimestamp(at, "execution.at");
  return {
    state: "failed",
    policyApplied: false,
    gatewayApplied: false,
    adapter: "controlled_executor",
    resultCode: code,
    evidenceRef: "",
    at,
  };
}

export function responseAuditEntry(input) {
  const base = {
    auditId: "",
    actionId: input.actionId,
    sequence: input.sequence,
    event: input.event,
    status: input.status,
    actorSubjectId: input.actorSubjectId,
    reason: input.reason,
    at: input.at,
    requestId: input.requestId,
    previousHash: input.previousHash,
    hash: "",
  };
  base.auditId = `sae_${sha256Text(canonicalJson(base)).slice(0, 24)}`;
  base.hash = sha256Text(canonicalJson(base));
  return base;
}

export function publicResponseAction(action) {
  const activation = action.execution?.activation;
  return {
    schemaVersion: action.schemaVersion,
    actionId: action.actionId,
    status: action.status,
    actionType: action.actionType,
    source: { ...action.source },
    organizationId: action.organizationId,
    target: { ...action.target },
    reason: action.reason,
    requestedBySubjectId: action.requestedBySubjectId,
    requestedAt: action.requestedAt,
    updatedAt: action.updatedAt,
    revision: action.revision,
    startsAt: action.startsAt,
    expiresAt: action.expiresAt,
    authorization: action.authorization
      ? { ...action.authorization }
      : null,
    execution: structuredClone(action.execution),
    enforcement: activation?.state === "succeeded"
      ? activation.gatewayApplied
        ? "enforced"
        : "simulated"
      : "none",
  };
}

export function publicResponseAudit(entry) {
  return { ...entry };
}

export function isResponseActionId(value) {
  return ACTION_ID_PATTERN.test(value || "");
}

export function isResponseAuditId(value) {
  return AUDIT_ID_PATTERN.test(value || "");
}

export function isResponseHash(value) {
  return HASH_PATTERN.test(value || "");
}

export function isResponseTimestamp(value) {
  return timestamp(value);
}

export function isSafeResponseCode(value) {
  return typeof value === "string" && SAFE_CODE_PATTERN.test(value);
}

export function isSafeResponseId(value) {
  return typeof value === "string" && SAFE_ID_PATTERN.test(value);
}

export function isResponseActionEvent(value) {
  return RESPONSE_ACTION_EVENTS.includes(value);
}

export function isResponseActionStatus(value) {
  return RESPONSE_ACTION_STATUSES.includes(value);
}

export function normalizeLoadedAuthorization(value) {
  if (value === null) return null;
  exactObject(value, AUTHORIZATION_FIELDS, "authorization");
  if (!AUTHORIZATION_MODES.has(value.mode)
      || !isSafeResponseId(value.reference)
      || !isSafeResponseId(value.actorSubjectId)
      || !isSafeResponseId(value.stepUpReference)
      || !isResponseTimestamp(value.approvedAt)
      || !isResponseTimestamp(value.expiresAt)
      || value.expiresAt <= value.approvedAt
      || (value.mode === "break_glass"
        ? !isSafeResponseId(value.incidentId)
        : value.incidentId !== "")) {
    throw new Error("authorization is invalid");
  }
  return { ...value };
}

export function normalizeLoadedExecution(value) {
  exactObject(value, new Set(["activation", "reversion"]), "execution");
  const normalizePart = (part) => {
    if (part === null) return null;
    exactObject(
      part,
      new Set([
        "state",
        "policyApplied",
        "gatewayApplied",
        "adapter",
        "resultCode",
        "evidenceRef",
        "at",
      ]),
      "execution part",
    );
    if (!["succeeded", "failed"].includes(part.state)
        || typeof part.policyApplied !== "boolean"
        || typeof part.gatewayApplied !== "boolean"
        || !isSafeResponseCode(part.adapter)
        || !isSafeResponseCode(part.resultCode)
        || (part.evidenceRef !== "" && !isSafeResponseId(part.evidenceRef))
        || (part.at !== "" && !isResponseTimestamp(part.at))
        || (part.state === "succeeded" && part.at === "")) {
      throw new Error("execution part is invalid");
    }
    return { ...part };
  };
  return {
    activation: normalizePart(value.activation),
    reversion: normalizePart(value.reversion),
  };
}

export function validateResponseActionRecord(value) {
  exactObject(value, RESPONSE_ACTION_FIELDS, "response action");
  if (value.schemaVersion !== RESPONSE_ACTION_SCHEMA_VERSION
      || !isResponseActionId(value.actionId)
      || !isResponseActionStatus(value.status)
      || !RESPONSE_ACTION_TYPES.includes(value.actionType)
      || !isSafeResponseId(value.organizationId)
      || !isSafeResponseId(value.requestedBySubjectId)
      || !isResponseTimestamp(value.requestedAt)
      || !isResponseTimestamp(value.updatedAt)
      || value.updatedAt < value.requestedAt
      || !Number.isSafeInteger(value.revision)
      || value.revision < 1
      || !isResponseTimestamp(value.expiresAt)
      || value.expiresAt <= value.requestedAt
      || !isResponseHash(value.idempotencyKeyHash)
      || !isResponseHash(value.requestDigest)
      || !REQUEST_ID_PATTERN.test(value.lastRequestId || "")) {
    throw new Error("response action is invalid");
  }
  const source = sourceValue(value.source);
  const target = targetValue(value.target);
  if (!ACTION_TARGET_TYPES.get(value.actionType).has(target.type)) {
    throw new Error("response action target is invalid");
  }
  const reason = reasonText(value.reason);
  const authorization = normalizeLoadedAuthorization(value.authorization);
  const execution = normalizeLoadedExecution(value.execution);
  const startsAt = value.startsAt === ""
    ? ""
    : exactTimestamp(value.startsAt, "startsAt");
  const activation = execution.activation;
  const reversion = execution.reversion;

  if (value.status === "requested") {
    if (authorization !== null || activation !== null || reversion !== null || startsAt !== "") {
      throw new Error("requested response action state is inconsistent");
    }
  } else if (value.status === "approved") {
    if (authorization === null || activation !== null || reversion !== null || startsAt !== "") {
      throw new Error("approved response action state is inconsistent");
    }
  } else if (value.status === "active") {
    if (authorization === null
        || activation?.state !== "succeeded"
        || reversion !== null
        || startsAt === ""
        || activation.at !== startsAt) {
      throw new Error("active response action state is inconsistent");
    }
  } else if (value.status === "reverted") {
    if (authorization === null
        || activation?.state !== "succeeded"
        || reversion?.state !== "succeeded"
        || startsAt === ""
        || activation.at !== startsAt) {
      throw new Error("reverted response action state is inconsistent");
    }
  } else if (value.status === "failed") {
    if (authorization === null
        || activation?.state !== "failed"
        || activation.policyApplied !== false
        || activation.gatewayApplied !== false
        || reversion !== null
        || startsAt !== "") {
      throw new Error("failed response action state is inconsistent");
    }
  } else if (authorization === null && activation === null && reversion === null) {
    if (startsAt !== "") throw new Error("expired response action state is inconsistent");
  } else if (activation !== null || reversion !== null || startsAt !== "") {
    throw new Error("expired response action state is inconsistent");
  }

  if (startsAt !== ""
      && (startsAt < value.requestedAt || startsAt > value.updatedAt)) {
    throw new Error("response action startsAt is inconsistent");
  }
  if (activation?.state === "succeeded"
      && activation.policyApplied !== true) {
    throw new Error("activation execution is inconsistent");
  }
  if (reversion?.state === "succeeded"
      && reversion.policyApplied !== true) {
    throw new Error("reversion execution is inconsistent");
  }

  return {
    ...structuredClone(value),
    source,
    target,
    reason,
    startsAt,
    authorization,
    execution,
  };
}

export function validateResponseAuditRecord(value) {
  exactObject(value, RESPONSE_AUDIT_FIELDS, "response audit");
  if (!isResponseAuditId(value.auditId)
      || !isResponseActionId(value.actionId)
      || !Number.isSafeInteger(value.sequence)
      || value.sequence < 1
      || !isResponseActionEvent(value.event)
      || !isResponseActionStatus(value.status)
      || EVENT_STATUS.get(value.event) !== value.status
      || !isSafeResponseId(value.actorSubjectId)
      || !isResponseReason(value.reason)
      || !isResponseTimestamp(value.at)
      || !REQUEST_ID_PATTERN.test(value.requestId || "")
      || !isResponseHash(value.previousHash)
      || !isResponseHash(value.hash)) {
    throw new Error("response audit is invalid");
  }
  const baseForId = { ...value, auditId: "", hash: "" };
  const expectedAuditId = `sae_${sha256Text(canonicalJson(baseForId)).slice(0, 24)}`;
  const expectedHash = sha256Text(canonicalJson({ ...value, hash: "" }));
  if (value.auditId !== expectedAuditId || value.hash !== expectedHash) {
    throw new Error("response audit hash is invalid");
  }
  return { ...structuredClone(value) };
}

export function validateResponseAuditChain(action, audits) {
  if (!Array.isArray(audits)
      || audits.length !== action.revision
      || audits.length === 0
      || audits.length > 10_000) {
    throw new Error("response audit chain is invalid");
  }
  let status = "";
  let previousHash = ZERO_HASH;
  let approvedAt = "";
  let approvedActor = "";
  let activatedAt = "";
  for (const [index, rawAudit] of audits.entries()) {
    const audit = validateResponseAuditRecord(rawAudit);
    if (audit.actionId !== action.actionId
        || audit.sequence !== index + 1
        || audit.previousHash !== previousHash) {
      throw new Error("response audit chain is invalid");
    }
    if (index === 0) {
      if (audit.event !== "requested"
          || audit.status !== "requested"
          || audit.actorSubjectId !== action.requestedBySubjectId
          || audit.at !== action.requestedAt
          || audit.reason !== action.reason) {
        throw new Error("response audit chain does not start with the request");
      }
    } else if (ALLOWED_TRANSITIONS.get(status)?.get(audit.event) !== audit.status) {
      throw new Error("response audit transition is invalid");
    }
    if (audit.event === "approved") {
      approvedAt = audit.at;
      approvedActor = audit.actorSubjectId;
    }
    if (audit.event === "activated") activatedAt = audit.at;
    if (audit.event === "expired" && audit.at < action.expiresAt) {
      throw new Error("response action expired before its deadline");
    }
    status = audit.status;
    previousHash = audit.hash;
  }
  const last = audits.at(-1);
  if (status !== action.status
      || last.at !== action.updatedAt
      || last.requestId !== action.lastRequestId) {
    throw new Error("response action does not match its audit chain");
  }
  if (action.authorization !== null) {
    if (approvedAt === ""
        || approvedActor !== action.authorization.actorSubjectId
        || action.authorization.approvedAt < action.requestedAt
        || action.authorization.approvedAt > approvedAt
        || action.authorization.expiresAt <= approvedAt
        || (activatedAt !== "" && action.authorization.expiresAt <= activatedAt)) {
      throw new Error("response authorization does not match its audit chain");
    }
  } else if (approvedAt !== "") {
    throw new Error("response authorization is missing");
  }
  if (activatedAt !== "" && action.startsAt !== activatedAt) {
    throw new Error("response activation time does not match its audit chain");
  }
  const reversionAt = action.execution.reversion?.at || "";
  if (reversionAt !== "" && reversionAt < activatedAt) {
    throw new Error("response reversion time precedes activation");
  }
  return structuredClone(audits);
}

export function validateResponseIdempotencyRecord(keyHash, value) {
  exactObject(value, RESPONSE_IDEMPOTENCY_FIELDS, "response idempotency record");
  if (!isResponseHash(keyHash)
      || value.keyHash !== keyHash
      || !isResponseActionId(value.actionId)
      || !RESPONSE_ACTION_OPERATIONS.includes(value.operation)
      || !isResponseHash(value.requestDigest)
      || !isResponseTimestamp(value.createdAt)) {
    throw new Error("response idempotency record is invalid");
  }
  return { ...value };
}

export function operationMatchesEvent(operation, event) {
  return OPERATION_EVENTS.get(operation)?.has(event) || false;
}

export function transitionConflict(message, code = "response_action_transition_conflict") {
  conflict(code, message);
}

export const simulatedResponseExecutor = Object.freeze({
  activate() {
    return {
      policyApplied: true,
      gatewayApplied: false,
      adapter: "simulation",
      resultCode: "policy_applied_without_gateway_enforcement",
      evidenceRef: "",
    };
  },
  revert() {
    return {
      policyApplied: true,
      gatewayApplied: false,
      adapter: "simulation",
      resultCode: "policy_reverted_without_gateway_enforcement",
      evidenceRef: "",
    };
  },
});
