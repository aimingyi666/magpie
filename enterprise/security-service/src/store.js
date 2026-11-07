import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import {
  ALERT_OPERATIONS,
  ALERT_SLA_SECONDS,
  AlertValidationError,
  alertAuditEntry,
  alertConflict,
  alertIdFor,
  isAlertId,
  normalizeAlertCreateRequest,
  validateAlertAuditChain,
  validateAlertIdempotencyRecord,
  validateAlertRecord,
} from "./alerts.js";
import {
  canonicalJson,
  hasSecretMaterial,
  plainObject,
  sha256Text,
  validateDetectionEvent,
} from "./events.js";
import {
  ResponseActionValidationError,
  emptyExecution,
  failedExecution,
  normalizeExecution,
  operationMatchesEvent,
  responseActionId,
  responseAuditEntry,
  simulatedResponseExecutor,
  transitionConflict,
  validateResponseActionRecord,
  validateResponseAuditChain,
  validateResponseIdempotencyRecord,
} from "./response-actions.js";

export const SECURITY_STORE_SCHEMA_VERSION = 3;
const FINDING_ID_PATTERN = /^sdf_[a-f0-9]{24}$/;
const AGGREGATE_ID_PATTERN = /^sag_[a-f0-9]{24}$/;
const DEDUPE_KEY_PATTERN = /^sdk_[a-f0-9]{24}$/;
const RULE_ID_PATTERN = /^sec\.[a-z0-9._-]+$/;
const SUBJECT_TYPE_PATTERN = /^(?:user|device|agent|service)$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const STATE_FIELDS = new Set([
  "version",
  "events",
  "findings",
  "aggregates",
  "suppressions",
  "alerts",
  "alertAudits",
  "alertIdempotency",
  "responseActions",
  "responseAudits",
  "responseIdempotency",
  "stats",
]);
const EVENT_RECORD_FIELDS = new Set(["event", "fingerprint", "receivedAt"]);
const FINDING_RECORD_FIELDS = new Set(["finding", "fingerprint", "storedAt"]);
const AGGREGATE_FIELDS = new Set([
  "aggregateId",
  "ruleId",
  "ruleVersion",
  "organizationId",
  "subjectType",
  "subjectId",
  "count",
  "firstDetectedAt",
  "lastDetectedAt",
  "lastFindingId",
]);
const SUPPRESSION_FIELDS = new Set([
  "dedupeKey",
  "ruleId",
  "organizationId",
  "subjectType",
  "subjectId",
  "count",
  "firstDetectedAt",
  "lastDetectedAt",
  "lastFindingId",
  "suppressedUntil",
]);
const STATS_FIELDS = new Set([
  "acceptedEvents",
  "duplicateEvents",
  "findings",
  "suppressedFindings",
]);
const FINDING_FIELDS = new Set([
  "findingId",
  "eventId",
  "ruleId",
  "ruleVersion",
  "ruleKind",
  "severity",
  "organizationId",
  "subject",
  "requestId",
  "sessionId",
  "detectedAt",
  "evaluatedAt",
  "evidence",
  "dedupeKey",
  "aggregateId",
  "suppressed",
  "suppressionUntil",
]);
const SUBJECT_FIELDS = new Set(["type", "id", "orgUnitId"]);
const EVIDENCE_FIELDS = new Map([
  ["sec.client.direct_bypass", new Set(["route", "managedAgent"])],
  ["sec.content.sensitive", new Set(["sensitiveCategories", "matchCount"])],
  ["sec.device.noncompliant", new Set(["complianceState", "reasonCodes"])],
  ["sec.authorization.scope_violation", new Set(["decision", "dimension", "policyId"])],
  ["sec.source.untrusted_ip", new Set(["ipHash", "trustedAddressCount"])],
  ["sec.source.untrusted_region", new Set(["region", "trustedRegionCount"])],
  ["sec.usage.anomaly", new Set([
    "totalTokens",
    "baselineTokens",
    "tokenMultiplier",
    "tokenThreshold",
    "minimumTokens",
    "cost",
    "baselineCost",
    "costMultiplier",
    "costThreshold",
    "minimumCost",
    "triggeredBy",
  ])],
  ["sec.usage.budget_threshold", new Set([
    "budgetLimit",
    "budgetUsed",
    "ratio",
    "warningRatio",
    "criticalRatio",
  ])],
]);
const SUBJECT_TYPES = new Set(["user", "device", "agent", "service"]);
const CONNECTION_ROUTES = new Set(["direct_provider", "enterprise_gateway", "unknown"]);
const AUTHORIZATION_DIMENSIONS = new Set([
  "gateway",
  "mcp",
  "model",
  "organization",
  "provider",
  "scope",
  "tool",
]);
const SENSITIVE_CATEGORIES = new Set([
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

export class SecurityStoreError extends Error {
  constructor(code, message, statusCode = 500, retryable = false) {
    super(message);
    this.name = "SecurityStoreError";
    this.code = code;
    this.statusCode = statusCode;
    this.retryable = retryable;
  }
}

function timestamp(value) {
  return typeof value === "string"
    && TIMESTAMP_PATTERN.test(value)
    && Number.isFinite(Date.parse(value))
    && new Date(value).toISOString() === value;
}

function safeIdentifier(value) {
  return typeof value === "string"
    && /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/.test(value);
}

function safeCode(value, maximum = 64) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximum
    && /^[a-z][a-z0-9._-]*$/.test(value);
}

function safeCodeList(value) {
  return Array.isArray(value)
    && value.length > 0
    && value.length <= 32
    && value.every((item) => safeCode(item))
    && new Set(value).size === value.length;
}

function finiteNumber(value, minimum = 0) {
  return typeof value === "number"
    && Number.isFinite(value)
    && value >= minimum;
}

function emptyStore() {
  return {
    version: SECURITY_STORE_SCHEMA_VERSION,
    events: {},
    findings: {},
    aggregates: {},
    suppressions: {},
    alerts: {},
    alertAudits: {},
    alertIdempotency: {},
    responseActions: {},
    responseAudits: {},
    responseIdempotency: {},
    stats: {
      acceptedEvents: 0,
      duplicateEvents: 0,
      findings: 0,
      suppressedFindings: 0,
    },
  };
}

function assertRecord(value, allowedFields, name) {
  if (!plainObject(value)
      || Object.keys(value).some((key) => !allowedFields.has(key))) {
    throw new SecurityStoreError("security_store_invalid", `${name} is invalid`);
  }
}

function verifyFingerprint(value, fingerprint, name) {
  if (typeof fingerprint !== "string"
      || !/^[a-f0-9]{64}$/.test(fingerprint)
      || sha256Text(canonicalJson(value)) !== fingerprint) {
    throw new SecurityStoreError("security_store_invalid", `${name} fingerprint is invalid`);
  }
}

export function validateFindingValue(finding) {
  if (!plainObject(finding)
      || Object.keys(finding).some((key) => !FINDING_FIELDS.has(key))
      || !FINDING_ID_PATTERN.test(finding.findingId || "")
      || !/^devt_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(finding.eventId || "")
      || typeof finding.ruleId !== "string"
      || !RULE_ID_PATTERN.test(finding.ruleId)
      || !Number.isSafeInteger(finding.ruleVersion)
      || finding.ruleVersion < 1
      || !safeCode(finding.ruleKind)
      || !["warning", "high", "critical"].includes(finding.severity)
      || !safeIdentifier(finding.organizationId)
      || !plainObject(finding.subject)
      || Object.keys(finding.subject).some((key) => !SUBJECT_FIELDS.has(key))
      || !SUBJECT_TYPES.has(finding.subject.type)
      || !safeIdentifier(finding.subject.id)
      || (finding.subject.orgUnitId !== undefined
        && !safeIdentifier(finding.subject.orgUnitId))
      || typeof finding.requestId !== "string"
      || (finding.requestId !== ""
        && !/^req_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(finding.requestId))
      || typeof finding.sessionId !== "string"
      || (finding.sessionId !== ""
        && !/^ses_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(finding.sessionId))
      || !timestamp(finding.detectedAt)
      || !timestamp(finding.evaluatedAt)
      || !plainObject(finding.evidence)
      || !DEDUPE_KEY_PATTERN.test(finding.dedupeKey || "")
      || !AGGREGATE_ID_PATTERN.test(finding.aggregateId || "")
      || typeof finding.suppressed !== "boolean"
      || (finding.suppressionUntil !== "" && !timestamp(finding.suppressionUntil))
      || hasSecretMaterial(finding)) {
    return false;
  }

  const allowedEvidence = EVIDENCE_FIELDS.get(finding.ruleId);
  if (!allowedEvidence
      || Object.keys(finding.evidence).length === 0
      || Object.keys(finding.evidence).some((key) => !allowedEvidence.has(key))) {
    return false;
  }
  return validateEvidence(finding);
}

function validateEvidence(finding) {
  const evidence = finding.evidence;
  if (finding.ruleId === "sec.client.direct_bypass") {
    return CONNECTION_ROUTES.has(evidence.route)
      && typeof evidence.managedAgent === "boolean";
  }
  if (finding.ruleId === "sec.content.sensitive") {
    return Array.isArray(evidence.sensitiveCategories)
      && evidence.sensitiveCategories.length > 0
      && evidence.sensitiveCategories.every((category) => SENSITIVE_CATEGORIES.has(category))
      && Number.isSafeInteger(evidence.matchCount)
      && evidence.matchCount > 0;
  }
  if (finding.ruleId === "sec.device.noncompliant") {
    return evidence.complianceState === "noncompliant"
      && safeCodeList(evidence.reasonCodes);
  }
  if (finding.ruleId === "sec.authorization.scope_violation") {
    return evidence.decision === "denied"
      && AUTHORIZATION_DIMENSIONS.has(evidence.dimension)
      && (evidence.policyId === "" || safeCode(evidence.policyId, 128));
  }
  if (finding.ruleId === "sec.source.untrusted_ip") {
    return /^sha256:[a-f0-9]{64}$/.test(evidence.ipHash || "")
      && Number.isSafeInteger(evidence.trustedAddressCount)
      && evidence.trustedAddressCount > 0;
  }
  if (finding.ruleId === "sec.source.untrusted_region") {
    return safeCode(evidence.region)
      && Number.isSafeInteger(evidence.trustedRegionCount)
      && evidence.trustedRegionCount > 0;
  }
  if (finding.ruleId === "sec.usage.anomaly") {
    const tokenTriggered = evidence.triggeredBy?.includes("tokens");
    const costTriggered = evidence.triggeredBy?.includes("cost");
    return Array.isArray(evidence.triggeredBy)
      && evidence.triggeredBy.length > 0
      && evidence.triggeredBy.every((item) => item === "tokens" || item === "cost")
      && new Set(evidence.triggeredBy).size === evidence.triggeredBy.length
      && (!tokenTriggered || (
        Number.isSafeInteger(evidence.totalTokens)
        && Number.isSafeInteger(evidence.baselineTokens)
        && evidence.baselineTokens > 0
        && finiteNumber(evidence.tokenMultiplier, 1.01)
        && finiteNumber(evidence.tokenThreshold, 1.01)
        && Number.isSafeInteger(evidence.minimumTokens)
      ))
      && (!costTriggered || (
        finiteNumber(evidence.cost)
        && finiteNumber(evidence.baselineCost)
        && evidence.baselineCost > 0
        && finiteNumber(evidence.costMultiplier, 1.01)
        && finiteNumber(evidence.costThreshold, 1.01)
        && finiteNumber(evidence.minimumCost, 0.01)
      ));
  }
  if (finding.ruleId === "sec.usage.budget_threshold") {
    return finiteNumber(evidence.budgetLimit, Number.MIN_VALUE)
      && finiteNumber(evidence.budgetUsed)
      && finiteNumber(evidence.ratio)
      && finiteNumber(evidence.warningRatio, 0.01)
      && finiteNumber(evidence.criticalRatio, evidence.warningRatio)
      && evidence.criticalRatio >= evidence.warningRatio
      && evidence.ratio >= evidence.warningRatio;
  }
  return false;
}

function validateStats(stats) {
  if (!plainObject(stats)
      || Object.keys(stats).some((key) => !STATS_FIELDS.has(key))
      || Object.values(stats).some((value) => !Number.isSafeInteger(value) || value < 0)) {
    throw new SecurityStoreError("security_store_invalid", "security store stats are invalid");
  }
}

function validateAggregate(aggregateId, aggregate) {
  assertRecord(aggregate, AGGREGATE_FIELDS, `aggregate ${aggregateId}`);
  if (!AGGREGATE_ID_PATTERN.test(aggregateId)
      || aggregate.aggregateId !== aggregateId
      || !RULE_ID_PATTERN.test(aggregate.ruleId || "")
      || !Number.isSafeInteger(aggregate.ruleVersion)
      || aggregate.ruleVersion < 1
      || !safeIdentifier(aggregate.organizationId)
      || !SUBJECT_TYPE_PATTERN.test(aggregate.subjectType || "")
      || !safeIdentifier(aggregate.subjectId)
      || !Number.isSafeInteger(aggregate.count)
      || aggregate.count < 1
      || !timestamp(aggregate.firstDetectedAt)
      || !timestamp(aggregate.lastDetectedAt)
      || aggregate.firstDetectedAt > aggregate.lastDetectedAt
      || !FINDING_ID_PATTERN.test(aggregate.lastFindingId || "")) {
    throw new SecurityStoreError("security_store_invalid", `aggregate ${aggregateId} is invalid`);
  }
}

function validateSuppression(dedupeKey, suppression) {
  assertRecord(suppression, SUPPRESSION_FIELDS, `suppression ${dedupeKey}`);
  if (!DEDUPE_KEY_PATTERN.test(dedupeKey)
      || suppression.dedupeKey !== dedupeKey
      || !RULE_ID_PATTERN.test(suppression.ruleId || "")
      || !safeIdentifier(suppression.organizationId)
      || !SUBJECT_TYPE_PATTERN.test(suppression.subjectType || "")
      || !safeIdentifier(suppression.subjectId)
      || !Number.isSafeInteger(suppression.count)
      || suppression.count < 1
      || !timestamp(suppression.firstDetectedAt)
      || !timestamp(suppression.lastDetectedAt)
      || suppression.firstDetectedAt > suppression.lastDetectedAt
      || !FINDING_ID_PATTERN.test(suppression.lastFindingId || "")
      || !timestamp(suppression.suppressedUntil)) {
    throw new SecurityStoreError(
      "security_store_invalid",
      `suppression ${dedupeKey} is invalid`,
    );
  }
}

function alertSourceContext(alert, state) {
  if (alert.source.type === "finding") {
    const record = state.findings[alert.source.id];
    return record ? { finding: record.finding, aggregate: null } : null;
  }
  const aggregate = state.aggregates[alert.source.id];
  if (!aggregate) return null;
  const record = state.findings[aggregate.lastFindingId];
  return record ? { finding: record.finding, aggregate } : null;
}

function alertMatchesSource(alert, context) {
  if (!context) return false;
  const { finding, aggregate } = context;
  if (finding.organizationId !== alert.organizationId
      || finding.ruleId !== alert.ruleId
      || finding.severity !== alert.severity
      || finding.subject.type !== alert.subject.type
      || finding.subject.id !== alert.subject.id
      || finding.detectedAt !== alert.detectedAt
      || (finding.subject.orgUnitId || "") !== (alert.subject.orgUnitId || "")
      || (aggregate
        && (aggregate.organizationId !== alert.organizationId
          || aggregate.ruleId !== alert.ruleId
          || aggregate.subjectType !== alert.subject.type
          || aggregate.subjectId !== alert.subject.id))) {
    return false;
  }
  const expectedId = alertIdFor({
    organizationId: alert.organizationId,
    source: { type: alert.source.type, id: alert.source.id },
    ruleId: alert.ruleId,
    severity: alert.severity,
  });
  return expectedId === alert.alertId;
}

const ALERT_OPERATION_EVENTS = new Map([
  ["create", "opened"],
  ["assign", "assigned"],
  ["acknowledge", "acknowledged"],
  ["resolve", "resolved"],
  ["reopen", "reopened"],
]);

function validateAlertState(data, limits) {
  if (Object.keys(data.alerts).length > limits.maxAlerts) {
    throw new SecurityStoreError(
      "security_store_invalid",
      "security store exceeds the configured alert limit",
    );
  }
  const recordsByAlert = new Map();
  for (const [alertId, rawAlert] of Object.entries(data.alerts)) {
    let alert;
    try {
      alert = validateAlertRecord(rawAlert);
    } catch {
      throw new SecurityStoreError(
        "security_store_invalid",
        `alert ${alertId} is invalid`,
      );
    }
    if (alert.alertId !== alertId) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `alert ${alertId} has a mismatched id`,
      );
    }
    const context = alertSourceContext(alert, data);
    if (!alertMatchesSource(alert, context)) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `alert ${alertId} does not match its source`,
      );
    }
    const expectedDue = new Date(
      Date.parse(alert.detectedAt) + ALERT_SLA_SECONDS[alert.severity] * 1000,
    ).toISOString();
    if (alert.slaDueAt !== expectedDue) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `alert ${alertId} has an invalid SLA deadline`,
      );
    }
    data.alerts[alertId] = alert;
  }

  for (const [alertId, audits] of Object.entries(data.alertAudits)) {
    const alert = data.alerts[alertId];
    if (!alert) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `alert audits ${alertId} do not reference a stored alert`,
      );
    }
    try {
      validateAlertAuditChain(alert, audits);
    } catch {
      throw new SecurityStoreError(
        "security_store_invalid",
        `alert audits ${alertId} are invalid`,
      );
    }
  }
  for (const alertId of Object.keys(data.alerts)) {
    if (!data.alertAudits[alertId]) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `alert ${alertId} has no audit chain`,
      );
    }
  }

  for (const [keyHash, rawRecord] of Object.entries(data.alertIdempotency)) {
    let record;
    try {
      record = validateAlertIdempotencyRecord(keyHash, rawRecord);
    } catch {
      throw new SecurityStoreError(
        "security_store_invalid",
        `alert idempotency record ${keyHash} is invalid`,
      );
    }
    const alert = data.alerts[record.alertId];
    if (!alert) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `alert idempotency record ${keyHash} references a missing alert`,
      );
    }
    const records = recordsByAlert.get(record.alertId) || [];
    records.push(record);
    recordsByAlert.set(record.alertId, records);
  }
  for (const [alertId, alert] of Object.entries(data.alerts)) {
    const records = recordsByAlert.get(alertId) || [];
    const audits = data.alertAudits[alertId];
    const used = new Set();
    for (const record of records) {
      const expectedEvent = ALERT_OPERATION_EVENTS.get(record.operation);
      const index = audits.findIndex((audit, candidateIndex) => (
        !used.has(candidateIndex)
        && audit.event === expectedEvent
        && audit.at === record.createdAt
      ));
      if (index < 0) {
        throw new SecurityStoreError(
          "security_store_invalid",
          `alert ${alertId} idempotency operation does not match its audit chain`,
        );
      }
      used.add(index);
    }
    for (let index = 1; index < audits.length; index += 1) {
      if (!used.has(index)) {
        throw new SecurityStoreError(
          "security_store_invalid",
          `alert ${alertId} transition has no idempotency record`,
        );
      }
    }
  }
}

function responseSourceContext(action, state) {
  if (action.source.type === "finding") {
    const record = state.findings[action.source.id];
    return record ? { finding: record.finding, aggregate: null } : null;
  }
  const aggregate = state.aggregates[action.source.id];
  if (!aggregate) return null;
  const record = state.findings[aggregate.lastFindingId];
  return record ? { finding: record.finding, aggregate } : null;
}

function targetMatchesSource(action, context) {
  if (!context) return false;
  const { finding, aggregate } = context;
  if (finding.organizationId !== action.organizationId
      || (aggregate && aggregate.organizationId !== action.organizationId)) {
    return false;
  }
  if (action.target.type === "ip_hash") {
    return finding.ruleId === "sec.source.untrusted_ip"
      && finding.evidence.ipHash === action.target.id;
  }
  if (action.target.type === "gateway_key") return false;
  return finding.subject.type === action.target.type
    && finding.subject.id === action.target.id;
}

function validateResponseState(data, limits) {
  if (Object.keys(data.responseActions).length > limits.maxResponseActions) {
    throw new SecurityStoreError(
      "security_store_invalid",
      "security store exceeds the configured response action limit",
    );
  }
  const auditsByAction = new Map();
  for (const [actionId, rawAction] of Object.entries(data.responseActions)) {
    let action;
    try {
      action = validateResponseActionRecord(rawAction);
    } catch {
      throw new SecurityStoreError(
        "security_store_invalid",
        `response action ${actionId} is invalid`,
      );
    }
    if (action.actionId !== actionId) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `response action ${actionId} has a mismatched id`,
      );
    }
    const context = responseSourceContext(action, data);
    if (!targetMatchesSource(action, context)) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `response action ${actionId} does not match its source`,
      );
    }
    data.responseActions[actionId] = action;
  }

  for (const [actionId, audits] of Object.entries(data.responseAudits)) {
    const action = data.responseActions[actionId];
    if (!action) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `response audits ${actionId} do not reference a stored action`,
      );
    }
    try {
      validateResponseAuditChain(action, audits);
    } catch {
      throw new SecurityStoreError(
        "security_store_invalid",
        `response audits ${actionId} are invalid`,
      );
    }
    auditsByAction.set(actionId, audits);
  }
  for (const actionId of Object.keys(data.responseActions)) {
    if (!auditsByAction.has(actionId)) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `response action ${actionId} has no audit chain`,
      );
    }
  }

  const operationsByAction = new Map();
  for (const [keyHash, rawRecord] of Object.entries(data.responseIdempotency)) {
    let record;
    try {
      record = validateResponseIdempotencyRecord(keyHash, rawRecord);
    } catch {
      throw new SecurityStoreError(
        "security_store_invalid",
        `response idempotency record ${keyHash} is invalid`,
      );
    }
    if (!data.responseActions[record.actionId]) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `response idempotency record ${keyHash} references a missing action`,
      );
    }
    const records = operationsByAction.get(record.actionId) || [];
    records.push(record);
    operationsByAction.set(record.actionId, records);
  }
  for (const [actionId, action] of Object.entries(data.responseActions)) {
    const records = operationsByAction.get(actionId) || [];
    const audits = auditsByAction.get(actionId);
    if (records.length !== audits.length) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `response action ${actionId} idempotency records do not match its audit chain`,
      );
    }
    const used = new Set();
    for (const record of records) {
      const index = audits.findIndex((audit, candidateIndex) => (
        !used.has(candidateIndex)
        && operationMatchesEvent(record.operation, audit.event)
      ));
      if (index < 0 || audits[index].at !== record.createdAt) {
        throw new SecurityStoreError(
          "security_store_invalid",
          `response action ${actionId} idempotency operation does not match its audit chain`,
        );
      }
      if (record.operation === "create" && record.keyHash !== action.idempotencyKeyHash) {
        throw new SecurityStoreError(
          "security_store_invalid",
          `response action ${actionId} create idempotency key does not match the action`,
        );
      }
      used.add(index);
    }
    const last = audits.at(-1);
    const lastRecord = records.find((record) => (
      record.createdAt === last.at
      && operationMatchesEvent(record.operation, last.event)
    ));
    if (!lastRecord || lastRecord.requestDigest !== action.requestDigest) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `response action ${actionId} request digest does not match its final audit`,
      );
    }
  }
  return data;
}

function validateLoadedStateV2(data, limits) {
  if (!plainObject(data)) {
    throw new SecurityStoreError("security_store_invalid", "security store must be an object");
  }
  if (data.version !== SECURITY_STORE_SCHEMA_VERSION) {
    throw new SecurityStoreError(
      "security_store_invalid",
      `security store schema ${data.version} is unsupported`,
    );
  }
  if (Object.keys(data).some((key) => !STATE_FIELDS.has(key))) {
    throw new SecurityStoreError("security_store_invalid", "security store has unknown fields");
  }
  for (const key of [
    "events",
    "findings",
    "aggregates",
    "suppressions",
    "alerts",
    "alertAudits",
    "alertIdempotency",
    "responseActions",
    "responseAudits",
    "responseIdempotency",
    "stats",
  ]) {
    if (!plainObject(data[key])) {
      throw new SecurityStoreError("security_store_invalid", `security store ${key} is invalid`);
    }
  }
  if (Object.keys(data.events).length > limits.maxEvents) {
    throw new SecurityStoreError(
      "security_store_invalid",
      "security store exceeds the configured event limit",
    );
  }
  if (Object.keys(data.findings).length > limits.maxFindings) {
    throw new SecurityStoreError(
      "security_store_invalid",
      "security store exceeds the configured finding limit",
    );
  }
  validateStats(data.stats);

  for (const [eventId, record] of Object.entries(data.events)) {
    assertRecord(record, EVENT_RECORD_FIELDS, `event ${eventId}`);
    let event;
    try {
      event = validateDetectionEvent(record.event);
    } catch {
      throw new SecurityStoreError(
        "security_store_invalid",
        `event ${eventId} contains an invalid detection event`,
      );
    }
    if (event.eventId !== eventId || !timestamp(record.receivedAt)) {
      throw new SecurityStoreError("security_store_invalid", `event ${eventId} is invalid`);
    }
    verifyFingerprint(event, record.fingerprint, `event ${eventId}`);
  }

  for (const [findingId, record] of Object.entries(data.findings)) {
    assertRecord(record, FINDING_RECORD_FIELDS, `finding ${findingId}`);
    if (!validateFindingValue(record.finding)
        || record.finding.findingId !== findingId
        || !timestamp(record.storedAt)) {
      throw new SecurityStoreError("security_store_invalid", `finding ${findingId} is invalid`);
    }
    verifyFingerprint(record.finding, record.fingerprint, `finding ${findingId}`);
    if (!data.events[record.finding.eventId]) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `finding ${findingId} does not reference a stored event`,
      );
    }
  }

  for (const [aggregateId, aggregate] of Object.entries(data.aggregates)) {
    validateAggregate(aggregateId, aggregate);
    if (!data.findings[aggregate.lastFindingId]) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `aggregate ${aggregateId} references a missing finding`,
      );
    }
  }

  for (const [dedupeKey, suppression] of Object.entries(data.suppressions)) {
    validateSuppression(dedupeKey, suppression);
    if (!data.findings[suppression.lastFindingId]) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `suppression ${dedupeKey} references a missing finding`,
      );
    }
  }
  validateAlertState(data, limits);
  validateResponseState(data, limits);
  return data;
}

function validateLoadedState(data, limits) {
  if (plainObject(data) && data.version === 1) {
    const migrated = {
      ...data,
      version: SECURITY_STORE_SCHEMA_VERSION,
      alerts: {},
      alertAudits: {},
      alertIdempotency: {},
      responseActions: {},
      responseAudits: {},
      responseIdempotency: {},
    };
    validateLoadedStateV2(migrated, limits);
    return { state: migrated, migrated: true };
  }
  if (plainObject(data) && data.version === 2) {
    const migrated = {
      ...data,
      version: SECURITY_STORE_SCHEMA_VERSION,
      alerts: {},
      alertAudits: {},
      alertIdempotency: {},
    };
    validateLoadedStateV2(migrated, limits);
    return { state: migrated, migrated: true };
  }
  return { state: validateLoadedStateV2(data, limits), migrated: false };
}

function matchesFinding(finding, filters) {
  if (filters.ruleId && finding.ruleId !== filters.ruleId) return false;
  if (filters.severity && finding.severity !== filters.severity) return false;
  if (filters.organizationId && finding.organizationId !== filters.organizationId) return false;
  if (filters.subjectId && finding.subject.id !== filters.subjectId) return false;
  if (filters.since && finding.detectedAt < filters.since) return false;
  return true;
}

export class SecurityStore {
  constructor(storePath, limits = {}) {
    this.path = path.resolve(String(storePath));
    this.maxEvents = limits.maxEvents ?? 1_000_000;
    this.maxFindings = limits.maxFindings ?? 2_000_000;
    this.maxAlerts = limits.maxAlerts ?? 2_000_000;
    this.maxResponseActions = limits.maxResponseActions ?? 200_000;
    this.maxStoreBytes = limits.maxStoreBytes ?? 536_870_912;
    this.now = typeof limits.now === "function" ? limits.now : Date.now;
    this.executor = limits.executor || simulatedResponseExecutor;
    this.state = emptyStore();
    this.queue = Promise.resolve();
    this.initialized = false;
    // A subject's mean usage over the events this store holds. Built once
    // from the loaded state, then kept up to date; it is not persisted, so
    // a restart rebuilds it rather than trusting a second copy.
    this.usageBaselines = null;
  }

  // usageBaseline says what this subject's calls usually cost, from the
  // events already accepted. Fewer than five samples is "unknown": a
  // baseline made of one call would call the next one an anomaly.
  usageBaseline(subject) {
    if (!subject || typeof subject.type !== "string" || typeof subject.id !== "string") {
      return { tokens: null, cost: null, samples: 0 };
    }
    if (!this.usageBaselines) this.#rebuildUsageBaselines();
    const entry = this.usageBaselines.get(`${subject.type}\u0000${subject.id}`);
    if (!entry || entry.tokensCount < 5) return { tokens: null, cost: null, samples: entry?.tokensCount || 0 };
    return {
      tokens: entry.tokensSum / entry.tokensCount,
      cost: entry.costCount >= 5 ? entry.costSum / entry.costCount : null,
      samples: entry.tokensCount,
    };
  }

  #rebuildUsageBaselines() {
    this.usageBaselines = new Map();
    for (const record of Object.values(this.state.events)) {
      this.#noteUsageBaseline(record.event);
    }
  }

  #noteUsageBaseline(event) {
    const usage = event?.usage;
    if (!usage || !event.subject) return;
    const key = `${event.subject.type}\u0000${event.subject.id}`;
    let entry = this.usageBaselines.get(key);
    if (!entry) {
      entry = { tokensSum: 0, tokensCount: 0, costSum: 0, costCount: 0 };
      this.usageBaselines.set(key, entry);
    }
    if (finiteNumber(usage.totalTokens) && usage.totalTokens > 0) {
      entry.tokensSum += usage.totalTokens;
      entry.tokensCount += 1;
    }
    if (finiteNumber(usage.cost) && usage.cost > 0) {
      entry.costSum += usage.cost;
      entry.costCount += 1;
    }
  }

  async init() {
    if (this.initialized) return this;
    await fs.mkdir(path.dirname(this.path), { recursive: true });
    let text;
    try {
      const stat = await fs.stat(this.path);
      if (stat.size > this.maxStoreBytes) {
        throw new SecurityStoreError(
          "security_store_invalid",
          "security store exceeds the configured file-size limit",
        );
      }
      text = await fs.readFile(this.path, "utf8");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      this.initialized = true;
      return this;
    }
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new SecurityStoreError("security_store_invalid", "security store is not valid JSON");
    }
    const loaded = validateLoadedState(parsed, this);
    this.state = loaded.state;
    if (loaded.migrated) await this.#persist(this.state);
    this.initialized = true;
    return this;
  }

  #enqueue(operation) {
    if (!this.initialized) {
      return Promise.reject(new SecurityStoreError(
        "security_store_not_ready",
        "security store is not initialized",
        503,
        true,
      ));
    }
    const run = this.queue.then(operation, operation);
    this.queue = run.catch(() => {});
    return run;
  }

  async #persist(state) {
    const temporary = `${this.path}.${process.pid}.${crypto.randomUUID()}.tmp`;
    let handle;
    try {
      handle = await fs.open(temporary, "wx", 0o600);
      await handle.writeFile(JSON.stringify(state));
      await handle.sync();
      await handle.close();
      handle = null;
      await fs.rename(temporary, this.path);
    } catch (error) {
      if (handle) await handle.close().catch(() => {});
      await fs.unlink(temporary).catch(() => {});
      throw new SecurityStoreError(
        "security_store_write_failed",
        "The security store could not be persisted",
        503,
        true,
      );
    }
  }

  ingest(event, options = {}) {
    return this.#enqueue(async () => {
      const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
      if (!Number.isFinite(now.getTime())) {
        throw new SecurityStoreError("invalid_evaluation_time", "Evaluation time is invalid", 400);
      }
      const receivedAt = now.toISOString();
      const eventFingerprint = sha256Text(canonicalJson(event));
      const existing = this.state.events[event.eventId];
      if (existing) {
        if (existing.fingerprint !== eventFingerprint) {
          throw new SecurityStoreError(
            "detection_event_conflict",
            "The eventId is already stored with different content",
            409,
          );
        }
        const nextDuplicateState = {
          ...this.state,
          stats: {
            ...this.state.stats,
            duplicateEvents: this.state.stats.duplicateEvents + 1,
          },
        };
        await this.#persist(nextDuplicateState);
        this.state = nextDuplicateState;
        return {
          duplicate: true,
          findings: [],
          aggregateIds: [],
          alertIds: [],
        };
      }
      if (Object.keys(this.state.events).length >= this.maxEvents) {
        throw new SecurityStoreError(
          "security_event_capacity_exceeded",
          "The configured detection event capacity has been reached",
          507,
        );
      }

      const evaluated = options.evaluate(event, { now });
      if (!Array.isArray(evaluated)) throw new Error("rule evaluator must return an array");
      if (Object.keys(this.state.findings).length + evaluated.length > this.maxFindings) {
        throw new SecurityStoreError(
          "security_finding_capacity_exceeded",
          "The configured detection finding capacity has been reached",
          507,
        );
      }

      const next = {
        ...this.state,
        events: { ...this.state.events },
        findings: { ...this.state.findings },
        aggregates: { ...this.state.aggregates },
        suppressions: { ...this.state.suppressions },
        stats: { ...this.state.stats },
      };
      next.events[event.eventId] = {
        event,
        fingerprint: eventFingerprint,
        receivedAt,
      };
      next.stats.acceptedEvents += 1;
      // This event is now part of the subject's baseline for the next one.
      if (!this.usageBaselines) this.#rebuildUsageBaselines();
      this.#noteUsageBaseline(event);

      const storedFindings = [];
      const aggregateIds = [];
      const alertIds = [];
      const windowSeconds = options.suppressionWindowSeconds ?? 300;
      const windowMs = windowSeconds * 1000;
      for (const rawFinding of evaluated) {
        if (!validateFindingValue(rawFinding)) {
          throw new Error("rule evaluator returned an invalid finding");
        }
        const priorSuppression = next.suppressions[rawFinding.dedupeKey];
        const suppressed = Boolean(
          windowMs > 0
          && priorSuppression
          && Date.parse(priorSuppression.suppressedUntil) > now.getTime(),
        );
        const suppressionUntil = suppressed
          ? priorSuppression.suppressedUntil
          : new Date(now.getTime() + windowMs).toISOString();
        const finding = {
          ...rawFinding,
          suppressed,
          suppressionUntil: windowMs > 0 ? suppressionUntil : "",
        };
        const fingerprint = sha256Text(canonicalJson(finding));
        next.findings[finding.findingId] = {
          finding,
          fingerprint,
          storedAt: receivedAt,
        };
        next.stats.findings += 1;
        if (suppressed) next.stats.suppressedFindings += 1;
        storedFindings.push(finding);
        aggregateIds.push(finding.aggregateId);

        const aggregate = next.aggregates[finding.aggregateId] || {
          aggregateId: finding.aggregateId,
          ruleId: finding.ruleId,
          ruleVersion: finding.ruleVersion,
          organizationId: finding.organizationId,
          subjectType: finding.subject.type,
          subjectId: finding.subject.id,
          count: 0,
          firstDetectedAt: finding.detectedAt,
          lastDetectedAt: finding.detectedAt,
          lastFindingId: finding.findingId,
        };
        next.aggregates[finding.aggregateId] = {
          ...aggregate,
          count: aggregate.count + 1,
          firstDetectedAt: aggregate.firstDetectedAt < finding.detectedAt
            ? aggregate.firstDetectedAt
            : finding.detectedAt,
          lastDetectedAt: aggregate.lastDetectedAt > finding.detectedAt
            ? aggregate.lastDetectedAt
            : finding.detectedAt,
          lastFindingId: finding.findingId,
        };

        if (windowMs > 0) {
          const prior = next.suppressions[finding.dedupeKey];
          next.suppressions[finding.dedupeKey] = {
            dedupeKey: finding.dedupeKey,
            ruleId: finding.ruleId,
            organizationId: finding.organizationId,
            subjectType: finding.subject.type,
            subjectId: finding.subject.id,
            count: (prior?.count || 0) + 1,
            firstDetectedAt: prior?.firstDetectedAt || finding.detectedAt,
            lastDetectedAt: prior?.lastDetectedAt
              && prior.lastDetectedAt > finding.detectedAt
              ? prior.lastDetectedAt
              : finding.detectedAt,
            lastFindingId: finding.findingId,
            suppressedUntil: suppressed
              ? suppressionUntil
              : new Date(now.getTime() + windowMs).toISOString(),
          };
        }

        if (!suppressed && ["high", "critical"].includes(finding.severity)) {
          const alert = this.#openAlertInState(
            next,
            { type: "finding", id: finding.findingId },
            finding,
            receivedAt,
            options.requestId || "req_security_system",
          );
          if (alert) alertIds.push(alert.alertId);
        }
      }

      await this.#persist(next);
      this.state = next;
      return {
        duplicate: false,
        findings: structuredClone(storedFindings),
        aggregateIds: [...new Set(aggregateIds)],
        alertIds: [...new Set(alertIds)],
      };
    });
  }

  #alertTime(value) {
    const now = value instanceof Date
      ? value
      : new Date(value === undefined ? this.now() : value);
    if (!Number.isFinite(now.getTime())) {
      throw new AlertValidationError(400, "invalid_evaluation_time", "Time is invalid");
    }
    return now.toISOString();
  }

  #alertState() {
    return {
      ...this.state,
      alerts: { ...this.state.alerts },
      alertAudits: { ...this.state.alertAudits },
      alertIdempotency: { ...this.state.alertIdempotency },
    };
  }

  #appendAlertAudit(state, input) {
    const chain = state.alertAudits[input.alertId] || [];
    const audit = alertAuditEntry({
      ...input,
      sequence: chain.length + 1,
      previousHash: chain.at(-1)?.hash || "0".repeat(64),
    });
    state.alertAudits[input.alertId] = [...chain, audit];
    return audit;
  }

  #openAlertInState(state, source, finding, at, requestId, options = {}) {
    const alertId = alertIdFor({
      organizationId: finding.organizationId,
      source,
      ruleId: finding.ruleId,
      severity: finding.severity,
    });
    if (state.alerts[alertId]) return null;
    if (Object.keys(state.alerts).length >= this.maxAlerts) {
      throw new SecurityStoreError(
        "security_alert_capacity_exceeded",
        "The configured alert capacity has been reached",
        507,
      );
    }
    const reason = options.reason || "Automatically opened from a detection finding";
    const assigneeSubjectId = options.assigneeSubjectId || "";
    const actorSubjectId = options.actorSubjectId || "system";
    const alert = {
      schemaVersion: 1,
      alertId,
      status: "open",
      severity: finding.severity,
      ruleId: finding.ruleId,
      organizationId: finding.organizationId,
      source,
      subject: { ...finding.subject },
      detectedAt: finding.detectedAt,
      createdAt: at,
      updatedAt: at,
      revision: 1,
      assigneeSubjectId,
      acknowledgedAt: "",
      resolvedAt: "",
      resolutionCode: "",
      slaDueAt: new Date(
        Date.parse(finding.detectedAt) + ALERT_SLA_SECONDS[finding.severity] * 1000,
      ).toISOString(),
      lastRequestId: requestId,
    };
    state.alerts[alertId] = alert;
    state.alertAudits[alertId] = [];
    this.#appendAlertAudit(state, {
      alertId,
      event: "opened",
      status: "open",
      actorSubjectId,
      reason,
      assigneeSubjectId,
      resolutionCode: "",
      at,
      requestId,
    });
    return alert;
  }

  #alert(actionId, organizationId) {
    const alert = this.state.alerts[actionId];
    if (!alert || alert.organizationId !== organizationId) {
      throw new AlertValidationError(404, "alert_not_found", "Alert not found");
    }
    return alert;
  }

  #alertReplay(keyHash, requestDigest, operation, organizationId) {
    const record = this.state.alertIdempotency[keyHash];
    if (!record) return null;
    if (record.operation !== operation || record.requestDigest !== requestDigest) {
      alertConflict(
        "The Idempotency-Key was already used for a different request",
        "alert_idempotency_conflict",
      );
    }
    const alert = this.state.alerts[record.alertId];
    if (!alert || alert.organizationId !== organizationId) {
      throw new SecurityStoreError(
        "security_store_invalid",
        "alert idempotency state is inconsistent",
      );
    }
    const audits = this.state.alertAudits[record.alertId] || [];
    const expectedEvent = ALERT_OPERATION_EVENTS.get(record.operation);
    const auditIndex = audits.findIndex((audit) => (
      audit.event === expectedEvent && audit.at === record.createdAt
    ));
    if (auditIndex < 0) {
      throw new SecurityStoreError(
        "security_store_invalid",
        "alert idempotency state has no matching audit",
      );
    }
    let assigneeSubjectId = "";
    let acknowledgedAt = "";
    let resolvedAt = "";
    let resolutionCode = "";
    for (const audit of audits.slice(0, auditIndex + 1)) {
      if (audit.event === "opened" || audit.event === "assigned") {
        assigneeSubjectId = audit.assigneeSubjectId;
      } else if (audit.event === "acknowledged") {
        acknowledgedAt = audit.at;
      } else if (audit.event === "resolved") {
        if (acknowledgedAt === "") acknowledgedAt = audit.at;
        resolvedAt = audit.at;
        resolutionCode = audit.resolutionCode;
      } else if (audit.event === "reopened") {
        acknowledgedAt = "";
        resolvedAt = "";
        resolutionCode = "";
      }
    }
    const audit = audits[auditIndex];
    return {
      alert: {
        ...alert,
        status: audit.status,
        updatedAt: audit.at,
        revision: auditIndex + 1,
        assigneeSubjectId,
        acknowledgedAt,
        resolvedAt,
        resolutionCode,
        lastRequestId: audit.requestId,
      },
      replayed: true,
    };
  }

  #recordAlertIdempotency(state, input) {
    state.alertIdempotency[input.keyHash] = {
      keyHash: input.keyHash,
      alertId: input.alertId,
      operation: input.operation,
      requestDigest: input.requestDigest,
      createdAt: input.at,
    };
  }

  #assertAlertOperationInput(input) {
    if (!/^[a-f0-9]{64}$/.test(input.idempotencyKeyHash || "")
        || !/^[a-f0-9]{64}$/.test(input.requestDigest || "")) {
      throw new AlertValidationError(
        400,
        "invalid_alert_operation",
        "Alert operation hashes are invalid",
      );
    }
    if (typeof input.requestId !== "string"
        || !/^req_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(input.requestId)) {
      throw new AlertValidationError(
        400,
        "invalid_alert_operation",
        "Alert request id is invalid",
      );
    }
  }

  createAlert(request, input) {
    return this.#enqueue(async () => {
      this.#assertAlertOperationInput(input);
      const at = this.#alertTime(input.now);
      const replay = this.#alertReplay(
        input.idempotencyKeyHash,
        input.requestDigest,
        "create",
        request.organizationId,
      );
      if (replay) return replay;
      const context = request.source.type === "finding"
        ? responseSourceContext({ source: request.source }, this.state)
        : responseSourceContext({ source: request.source }, this.state);
      if (!context
          || context.finding.organizationId !== request.organizationId
          || (context.aggregate
            && context.aggregate.organizationId !== request.organizationId)) {
        throw new AlertValidationError(
          400,
          "alert_source_invalid",
          "The source finding or aggregate does not exist in the organization",
        );
      }
      const alertId = alertIdFor({
        organizationId: request.organizationId,
        source: request.source,
        ruleId: context.finding.ruleId,
        severity: context.finding.severity,
      });
      if (this.state.alerts[alertId]) {
        alertConflict("An alert already exists for this source", "alert_already_exists");
      }
      const state = this.#alertState();
      const alert = this.#openAlertInState(
        state,
        request.source,
        context.finding,
        at,
        input.requestId,
        {
          actorSubjectId: request.actorSubjectId,
          assigneeSubjectId: request.assigneeSubjectId,
          reason: request.reason,
        },
      );
      if (!alert) {
        alertConflict("An alert already exists for this source", "alert_already_exists");
      }
      this.#recordAlertIdempotency(state, {
        keyHash: input.idempotencyKeyHash,
        alertId,
        operation: "create",
        requestDigest: input.requestDigest,
        at,
      });
      await this.#persist(state);
      this.state = state;
      return { alert: structuredClone(alert), replayed: false };
    });
  }

  assignAlert(alertId, request, input) {
    return this.#enqueue(async () => {
      this.#assertAlertOperationInput(input);
      const at = this.#alertTime(input.now);
      const replay = this.#alertReplay(
        input.idempotencyKeyHash,
        input.requestDigest,
        "assign",
        input.organizationId,
      );
      if (replay) return replay;
      const alert = this.#alert(alertId, input.organizationId);
      if (alert.status === "resolved") {
        alertConflict("A resolved alert must be reopened before assignment");
      }
      if (alert.assigneeSubjectId === request.assigneeSubjectId) {
        alertConflict("The alert already has this assignee", "alert_assignee_unchanged");
      }
      const state = this.#alertState();
      const next = {
        ...alert,
        assigneeSubjectId: request.assigneeSubjectId,
        updatedAt: at,
        revision: alert.revision + 1,
        lastRequestId: input.requestId,
      };
      state.alerts[alertId] = next;
      this.#appendAlertAudit(state, {
        alertId,
        event: "assigned",
        status: next.status,
        actorSubjectId: request.actorSubjectId,
        reason: request.reason,
        assigneeSubjectId: request.assigneeSubjectId,
        resolutionCode: "",
        at,
        requestId: input.requestId,
      });
      this.#recordAlertIdempotency(state, {
        keyHash: input.idempotencyKeyHash,
        alertId,
        operation: "assign",
        requestDigest: input.requestDigest,
        at,
      });
      await this.#persist(state);
      this.state = state;
      return { alert: structuredClone(next), replayed: false };
    });
  }

  acknowledgeAlert(alertId, request, input) {
    return this.#enqueue(async () => {
      this.#assertAlertOperationInput(input);
      const at = this.#alertTime(input.now);
      const replay = this.#alertReplay(
        input.idempotencyKeyHash,
        input.requestDigest,
        "acknowledge",
        input.organizationId,
      );
      if (replay) return replay;
      const alert = this.#alert(alertId, input.organizationId);
      if (alert.status !== "open") {
        alertConflict("Only an open alert can be acknowledged");
      }
      const state = this.#alertState();
      const next = {
        ...alert,
        status: "acknowledged",
        acknowledgedAt: at,
        updatedAt: at,
        revision: alert.revision + 1,
        lastRequestId: input.requestId,
      };
      state.alerts[alertId] = next;
      this.#appendAlertAudit(state, {
        alertId,
        event: "acknowledged",
        status: "acknowledged",
        actorSubjectId: request.actorSubjectId,
        reason: request.reason,
        assigneeSubjectId: "",
        resolutionCode: "",
        at,
        requestId: input.requestId,
      });
      this.#recordAlertIdempotency(state, {
        keyHash: input.idempotencyKeyHash,
        alertId,
        operation: "acknowledge",
        requestDigest: input.requestDigest,
        at,
      });
      await this.#persist(state);
      this.state = state;
      return { alert: structuredClone(next), replayed: false };
    });
  }

  resolveAlert(alertId, request, input) {
    return this.#enqueue(async () => {
      this.#assertAlertOperationInput(input);
      const at = this.#alertTime(input.now);
      const replay = this.#alertReplay(
        input.idempotencyKeyHash,
        input.requestDigest,
        "resolve",
        input.organizationId,
      );
      if (replay) return replay;
      const alert = this.#alert(alertId, input.organizationId);
      if (!["open", "acknowledged"].includes(alert.status)) {
        alertConflict("Only an open or acknowledged alert can be resolved");
      }
      const state = this.#alertState();
      const next = {
        ...alert,
        status: "resolved",
        acknowledgedAt: alert.acknowledgedAt || at,
        resolvedAt: at,
        resolutionCode: request.resolutionCode,
        updatedAt: at,
        revision: alert.revision + 1,
        lastRequestId: input.requestId,
      };
      state.alerts[alertId] = next;
      this.#appendAlertAudit(state, {
        alertId,
        event: "resolved",
        status: "resolved",
        actorSubjectId: request.actorSubjectId,
        reason: request.reason,
        assigneeSubjectId: "",
        resolutionCode: request.resolutionCode,
        at,
        requestId: input.requestId,
      });
      this.#recordAlertIdempotency(state, {
        keyHash: input.idempotencyKeyHash,
        alertId,
        operation: "resolve",
        requestDigest: input.requestDigest,
        at,
      });
      await this.#persist(state);
      this.state = state;
      return { alert: structuredClone(next), replayed: false };
    });
  }

  reopenAlert(alertId, request, input) {
    return this.#enqueue(async () => {
      this.#assertAlertOperationInput(input);
      const at = this.#alertTime(input.now);
      const replay = this.#alertReplay(
        input.idempotencyKeyHash,
        input.requestDigest,
        "reopen",
        input.organizationId,
      );
      if (replay) return replay;
      const alert = this.#alert(alertId, input.organizationId);
      if (alert.status !== "resolved") {
        alertConflict("Only a resolved alert can be reopened");
      }
      const state = this.#alertState();
      const next = {
        ...alert,
        status: "open",
        acknowledgedAt: "",
        resolvedAt: "",
        resolutionCode: "",
        updatedAt: at,
        revision: alert.revision + 1,
        lastRequestId: input.requestId,
      };
      state.alerts[alertId] = next;
      this.#appendAlertAudit(state, {
        alertId,
        event: "reopened",
        status: "open",
        actorSubjectId: request.actorSubjectId,
        reason: request.reason,
        assigneeSubjectId: "",
        resolutionCode: "",
        at,
        requestId: input.requestId,
      });
      this.#recordAlertIdempotency(state, {
        keyHash: input.idempotencyKeyHash,
        alertId,
        operation: "reopen",
        requestDigest: input.requestDigest,
        at,
      });
      await this.#persist(state);
      this.state = state;
      return { alert: structuredClone(next), replayed: false };
    });
  }

  #responseTime(value) {
    const now = value instanceof Date
      ? value
      : new Date(value === undefined ? this.now() : value);
    if (!Number.isFinite(now.getTime())) {
      throw new ResponseActionValidationError(400, "invalid_evaluation_time", "Time is invalid");
    }
    return now.toISOString();
  }

  #responseState() {
    return {
      ...this.state,
      responseActions: { ...this.state.responseActions },
      responseAudits: { ...this.state.responseAudits },
      responseIdempotency: { ...this.state.responseIdempotency },
    };
  }

  #responseAction(actionId, organizationId) {
    const action = this.state.responseActions[actionId];
    if (!action || action.organizationId !== organizationId) {
      throw new ResponseActionValidationError(
        404,
        "response_action_not_found",
        "Response action not found",
      );
    }
    return action;
  }

  #responseReplay(keyHash, requestDigest, operation, organizationId) {
    const record = this.state.responseIdempotency[keyHash];
    if (!record) return null;
    if (record.operation !== operation || record.requestDigest !== requestDigest) {
      transitionConflict(
        "The Idempotency-Key was already used for a different request",
        "response_idempotency_conflict",
      );
    }
    const action = this.state.responseActions[record.actionId];
    if (!action || action.organizationId !== organizationId) {
      throw new SecurityStoreError(
        "security_store_invalid",
        "response idempotency state is inconsistent",
      );
    }
    const audits = this.state.responseAudits[record.actionId] || [];
    const auditIndex = audits.findIndex((audit) => (
      audit.at === record.createdAt
      && operationMatchesEvent(record.operation, audit.event)
    ));
    if (auditIndex < 0) {
      throw new SecurityStoreError(
        "security_store_invalid",
        "response idempotency state has no matching audit",
      );
    }
    const audit = audits[auditIndex];
    const snapshot = {
      ...action,
      status: audit.status,
      updatedAt: audit.at,
      revision: auditIndex + 1,
      requestDigest: record.requestDigest,
      lastRequestId: audit.requestId,
    };
    if (record.operation === "create") {
      snapshot.authorization = null;
      snapshot.startsAt = "";
      snapshot.execution = emptyExecution();
    } else if (record.operation === "approve") {
      snapshot.startsAt = "";
      snapshot.execution = emptyExecution();
    } else if (record.operation === "activate") {
      snapshot.startsAt = audit.event === "activated" ? audit.at : "";
      snapshot.execution = {
        activation: action.execution.activation,
        reversion: null,
      };
    } else if (record.operation === "revert") {
      snapshot.startsAt = action.startsAt;
      snapshot.execution = {
        activation: action.execution.activation,
        reversion: audit.event === "reverted" ? action.execution.reversion : null,
      };
    } else {
      snapshot.startsAt = "";
      snapshot.execution = emptyExecution();
    }
    return {
      action: structuredClone(snapshot),
      replayed: true,
    };
  }

  #appendResponseAudit(state, input) {
    const chain = state.responseAudits[input.actionId] || [];
    const audit = responseAuditEntry({
      ...input,
      sequence: chain.length + 1,
      previousHash: chain.at(-1)?.hash || "0".repeat(64),
    });
    state.responseAudits[input.actionId] = [...chain, audit];
  }

  #recordResponseIdempotency(state, input) {
    state.responseIdempotency[input.keyHash] = {
      keyHash: input.keyHash,
      actionId: input.actionId,
      operation: input.operation,
      requestDigest: input.requestDigest,
      createdAt: input.at,
    };
  }

  #assertResponseSource(action) {
    const context = responseSourceContext(action, this.state);
    if (!context || context.finding.organizationId !== action.organizationId) {
      throw new ResponseActionValidationError(
        400,
        "response_action_source_invalid",
        "The source finding or aggregate does not exist in the organization",
      );
    }
    if (!targetMatchesSource(action, context)) {
      throw new ResponseActionValidationError(
        400,
        action.target.type === "gateway_key"
          ? "response_action_target_unverifiable"
          : "response_action_target_mismatch",
        action.target.type === "gateway_key"
          ? "A gateway_key target cannot be verified from the current finding evidence"
          : "The response action target does not match the source finding",
      );
    }
  }

  #assertResponseOperationInput(input) {
    if (!/^[a-f0-9]{64}$/.test(input.idempotencyKeyHash || "")
        || !/^[a-f0-9]{64}$/.test(input.requestDigest || "")) {
      throw new ResponseActionValidationError(
        400,
        "invalid_response_action_operation",
        "Response action operation hashes are invalid",
      );
    }
    if (typeof input.requestId !== "string"
        || !/^req_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(input.requestId)) {
      throw new ResponseActionValidationError(
        400,
        "invalid_response_action_operation",
        "Response action request id is invalid",
      );
    }
  }

  createResponseAction(request, input) {
    return this.#enqueue(async () => {
      this.#assertResponseOperationInput(input);
      const at = this.#responseTime(input.now);
      const replay = this.#responseReplay(
        input.idempotencyKeyHash,
        input.requestDigest,
        "create",
        request.organizationId,
      );
      if (replay) return replay;
      if (Object.keys(this.state.responseActions).length >= this.maxResponseActions) {
        throw new SecurityStoreError(
          "security_response_action_capacity_exceeded",
          "The configured response action capacity has been reached",
          507,
        );
      }
      const actionId = responseActionId({
        ...request,
        idempotencyKeyHash: input.idempotencyKeyHash,
      });
      if (this.state.responseActions[actionId]) {
        transitionConflict(
          "The response action id is already in use",
          "response_action_conflict",
        );
      }
      const action = {
        schemaVersion: 1,
        actionId,
        status: "requested",
        actionType: request.actionType,
        source: { ...request.source },
        organizationId: request.organizationId,
        target: { ...request.target },
        reason: request.reason,
        requestedBySubjectId: request.requestedBySubjectId,
        requestedAt: at,
        updatedAt: at,
        revision: 1,
        startsAt: "",
        expiresAt: new Date(
          Date.parse(at) + request.durationSeconds * 1000,
        ).toISOString(),
        authorization: null,
        execution: emptyExecution(),
        idempotencyKeyHash: input.idempotencyKeyHash,
        requestDigest: input.requestDigest,
        lastRequestId: input.requestId,
      };
      this.#assertResponseSource(action);

      const state = this.#responseState();
      state.responseActions[actionId] = action;
      state.responseAudits[actionId] = [];
      this.#appendResponseAudit(state, {
        actionId,
        event: "requested",
        status: "requested",
        actorSubjectId: request.requestedBySubjectId,
        reason: request.reason,
        at,
        requestId: input.requestId,
      });
      this.#recordResponseIdempotency(state, {
        keyHash: input.idempotencyKeyHash,
        actionId,
        operation: "create",
        requestDigest: input.requestDigest,
        at,
      });
      await this.#persist(state);
      this.state = state;
      return { action: structuredClone(action), replayed: false };
    });
  }

  approveResponseAction(actionId, approval, input) {
    return this.#enqueue(async () => {
      this.#assertResponseOperationInput(input);
      const at = this.#responseTime(input.now);
      const replay = this.#responseReplay(
        input.idempotencyKeyHash,
        input.requestDigest,
        "approve",
        input.organizationId,
      );
      if (replay) return replay;
      const action = this.#responseAction(actionId, input.organizationId);
      if (action.status !== "requested") {
        transitionConflict("Only a requested response action can be approved");
      }
      if (approval.actorSubjectId === action.requestedBySubjectId) {
        transitionConflict(
          "The requester cannot approve their own response action",
          "response_action_self_approval",
        );
      }
      if (approval.authorization.approvedAt > at) {
        transitionConflict(
          "The authorization approval time is in the future",
          "response_authorization_not_yet_valid",
        );
      }
      if (approval.authorization.approvedAt < action.requestedAt) {
        transitionConflict(
          "The authorization approval time precedes the response action request",
          "response_authorization_before_request",
        );
      }
      if (approval.authorization.expiresAt <= at) {
        transitionConflict(
          "The authorization has expired",
          "response_authorization_expired",
        );
      }
      if (action.expiresAt <= at) {
        transitionConflict(
          "The response action has expired",
          "response_action_expired",
        );
      }

      const state = this.#responseState();
      const next = {
        ...action,
        status: "approved",
        updatedAt: at,
        revision: action.revision + 1,
        authorization: structuredClone(approval.authorization),
        requestDigest: input.requestDigest,
        lastRequestId: input.requestId,
      };
      state.responseActions[actionId] = next;
      this.#appendResponseAudit(state, {
        actionId,
        event: "approved",
        status: "approved",
        actorSubjectId: approval.actorSubjectId,
        reason: approval.reason,
        at,
        requestId: input.requestId,
      });
      this.#recordResponseIdempotency(state, {
        keyHash: input.idempotencyKeyHash,
        actionId,
        operation: "approve",
        requestDigest: input.requestDigest,
        at,
      });
      await this.#persist(state);
      this.state = state;
      return { action: structuredClone(next), replayed: false };
    });
  }

  activateResponseAction(actionId, actor, input) {
    return this.#enqueue(async () => {
      this.#assertResponseOperationInput(input);
      const at = this.#responseTime(input.now);
      const replay = this.#responseReplay(
        input.idempotencyKeyHash,
        input.requestDigest,
        "activate",
        input.organizationId,
      );
      if (replay) return replay;
      const action = this.#responseAction(actionId, input.organizationId);
      if (action.status !== "approved") {
        transitionConflict("Only an approved response action can be activated");
      }
      if (action.authorization.expiresAt <= at) {
        transitionConflict(
          "The authorization has expired",
          "response_authorization_expired",
        );
      }
      if (action.expiresAt <= at) {
        transitionConflict(
          "The response action has expired",
          "response_action_expired",
        );
      }

      let execution;
      let status;
      let event;
      let startsAt;
      try {
        const result = await this.executor.activate(structuredClone(action), {
          now: at,
          requestId: input.requestId,
        });
        execution = normalizeExecution(result, "succeeded", at);
        status = "active";
        event = "activated";
        startsAt = at;
      } catch (error) {
        execution = failedExecution(error?.code || "response_executor_failed", at);
        status = "failed";
        event = "activation_failed";
        startsAt = "";
      }

      const state = this.#responseState();
      const next = {
        ...action,
        status,
        updatedAt: at,
        revision: action.revision + 1,
        startsAt,
        execution: {
          ...action.execution,
          activation: execution,
        },
        requestDigest: input.requestDigest,
        lastRequestId: input.requestId,
      };
      state.responseActions[actionId] = next;
      this.#appendResponseAudit(state, {
        actionId,
        event,
        status,
        actorSubjectId: actor.actorSubjectId,
        reason: actor.reason,
        at,
        requestId: input.requestId,
      });
      this.#recordResponseIdempotency(state, {
        keyHash: input.idempotencyKeyHash,
        actionId,
        operation: "activate",
        requestDigest: input.requestDigest,
        at,
      });
      await this.#persist(state);
      this.state = state;
      return { action: structuredClone(next), replayed: false };
    });
  }

  revertResponseAction(actionId, actor, input) {
    return this.#enqueue(async () => {
      this.#assertResponseOperationInput(input);
      const at = this.#responseTime(input.now);
      const replay = this.#responseReplay(
        input.idempotencyKeyHash,
        input.requestDigest,
        "revert",
        input.organizationId,
      );
      if (replay) return replay;
      const action = this.#responseAction(actionId, input.organizationId);
      if (action.status !== "active") {
        transitionConflict("Only an active response action can be reverted");
      }

      let status = "active";
      let event = "revert_failed";
      let reversion = null;
      try {
        const result = await this.executor.revert(structuredClone(action), {
          now: at,
          requestId: input.requestId,
        });
        reversion = normalizeExecution(result, "succeeded", at);
        status = "reverted";
        event = "reverted";
      } catch {
        status = "active";
        event = "revert_failed";
      }

      const state = this.#responseState();
      const next = {
        ...action,
        status,
        updatedAt: at,
        revision: action.revision + 1,
        execution: {
          ...action.execution,
          reversion,
        },
        requestDigest: input.requestDigest,
        lastRequestId: input.requestId,
      };
      state.responseActions[actionId] = next;
      this.#appendResponseAudit(state, {
        actionId,
        event,
        status,
        actorSubjectId: actor.actorSubjectId,
        reason: actor.reason,
        at,
        requestId: input.requestId,
      });
      this.#recordResponseIdempotency(state, {
        keyHash: input.idempotencyKeyHash,
        actionId,
        operation: "revert",
        requestDigest: input.requestDigest,
        at,
      });
      await this.#persist(state);
      this.state = state;
      return { action: structuredClone(next), replayed: false };
    });
  }

  expireResponseAction(actionId, actor, input) {
    return this.#enqueue(async () => {
      this.#assertResponseOperationInput(input);
      const at = this.#responseTime(input.now);
      const replay = this.#responseReplay(
        input.idempotencyKeyHash,
        input.requestDigest,
        "expire",
        input.organizationId,
      );
      if (replay) return replay;
      const action = this.#responseAction(actionId, input.organizationId);
      if (!["requested", "approved"].includes(action.status)) {
        transitionConflict("Only a pending response action can expire");
      }
      if (at < action.expiresAt) {
        transitionConflict(
          "The response action has not reached its expiration time",
          "response_action_not_expired",
        );
      }

      const state = this.#responseState();
      const next = {
        ...action,
        status: "expired",
        updatedAt: at,
        revision: action.revision + 1,
        requestDigest: input.requestDigest,
        lastRequestId: input.requestId,
      };
      state.responseActions[actionId] = next;
      this.#appendResponseAudit(state, {
        actionId,
        event: "expired",
        status: "expired",
        actorSubjectId: actor.actorSubjectId,
        reason: actor.reason,
        at,
        requestId: input.requestId,
      });
      this.#recordResponseIdempotency(state, {
        keyHash: input.idempotencyKeyHash,
        actionId,
        operation: "expire",
        requestDigest: input.requestDigest,
        at,
      });
      await this.#persist(state);
      this.state = state;
      return { action: structuredClone(next), replayed: false };
    });
  }

  read(operation) {
    return this.#enqueue(async () => operation(structuredClone(this.state)));
  }

  stats() {
    return this.read((state) => {
      const now = this.now();
      const alerts = Object.values(state.alerts);
      return {
        eventCount: Object.keys(state.events).length,
        findingCount: Object.keys(state.findings).length,
        aggregateCount: Object.keys(state.aggregates).length,
        suppressionCount: Object.keys(state.suppressions).length,
        alertCount: alerts.length,
        alertAuditCount: Object.values(state.alertAudits)
          .reduce((total, audits) => total + audits.length, 0),
        openAlertCount: alerts.filter((alert) => alert.status !== "resolved").length,
        unassignedAlertCount: alerts.filter((alert) => (
          alert.status !== "resolved" && alert.assigneeSubjectId === ""
        )).length,
        overdueAlertCount: alerts.filter((alert) => (
          alert.status !== "resolved" && Date.parse(alert.slaDueAt) <= now
        )).length,
        responseActionCount: Object.keys(state.responseActions).length,
        responseAuditCount: Object.values(state.responseAudits)
          .reduce((total, audits) => total + audits.length, 0),
        responseIdempotencyCount: Object.keys(state.responseIdempotency).length,
        activeSuppressionCount: Object.values(state.suppressions)
          .filter((item) => Date.parse(item.suppressedUntil) > now).length,
        stats: { ...state.stats },
        limits: {
          maxEvents: this.maxEvents,
          maxFindings: this.maxFindings,
          maxAlerts: this.maxAlerts,
          maxResponseActions: this.maxResponseActions,
        },
      };
    });
  }

  listFindings(filters = {}) {
    const limit = Math.min(Math.max(Number(filters.limit) || 100, 1), 500);
    return this.read((state) => Object.values(state.findings)
      .map((record) => record.finding)
      .filter((finding) => matchesFinding(finding, filters))
      .sort((left, right) => {
        const byTime = right.detectedAt.localeCompare(left.detectedAt);
        return byTime || left.findingId.localeCompare(right.findingId);
      })
      .slice(0, limit));
  }

  listAggregates(filters = {}) {
    const limit = Math.min(Math.max(Number(filters.limit) || 100, 1), 500);
    return this.read((state) => Object.values(state.aggregates)
      .filter((aggregate) => (
        (!filters.ruleId || aggregate.ruleId === filters.ruleId)
        && (!filters.organizationId || aggregate.organizationId === filters.organizationId)
        && (!filters.subjectId || aggregate.subjectId === filters.subjectId)
      ))
      .sort((left, right) => right.lastDetectedAt.localeCompare(left.lastDetectedAt))
      .slice(0, limit));
  }

  listSuppressions(filters = {}) {
    const limit = Math.min(Math.max(Number(filters.limit) || 100, 1), 500);
    const now = this.now();
    return this.read((state) => Object.values(state.suppressions)
      .filter((suppression) => (
        (!filters.ruleId || suppression.ruleId === filters.ruleId)
        && (!filters.organizationId || suppression.organizationId === filters.organizationId)
        && (!filters.subjectId || suppression.subjectId === filters.subjectId)
        && (!filters.activeOnly || Date.parse(suppression.suppressedUntil) > now)
      ))
      .sort((left, right) => right.lastDetectedAt.localeCompare(left.lastDetectedAt))
      .slice(0, limit));
  }

  getResponseAction(actionId, organizationId) {
    return this.read((state) => {
      const action = state.responseActions[actionId];
      return action && action.organizationId === organizationId
        ? action
        : null;
    });
  }

  listResponseActions(filters = {}) {
    const limit = Math.min(Math.max(Number(filters.limit) || 100, 1), 500);
    return this.read((state) => Object.values(state.responseActions)
      .filter((action) => (
        (!filters.organizationId || action.organizationId === filters.organizationId)
        && (!filters.status || action.status === filters.status)
        && (!filters.actionType || action.actionType === filters.actionType)
        && (!filters.sourceType || action.source.type === filters.sourceType)
        && (!filters.sourceId || action.source.id === filters.sourceId)
        && (!filters.targetType || action.target.type === filters.targetType)
        && (!filters.targetId || action.target.id === filters.targetId)
      ))
      .sort((left, right) => {
        const byTime = right.updatedAt.localeCompare(left.updatedAt);
        return byTime || left.actionId.localeCompare(right.actionId);
      })
      .slice(0, limit));
  }

  listResponseAudits(actionId, organizationId) {
    return this.read((state) => {
      const action = state.responseActions[actionId];
      if (!action || action.organizationId !== organizationId) return null;
      return [...(state.responseAudits[actionId] || [])];
    });
  }

  getAlert(alertId, organizationId) {
    return this.read((state) => {
      const alert = state.alerts[alertId];
      return alert && alert.organizationId === organizationId ? alert : null;
    });
  }

  listAlerts(filters = {}) {
    const limit = Math.min(Math.max(Number(filters.limit) || 100, 1), 500);
    return this.read((state) => Object.values(state.alerts)
      .filter((alert) => (
        (!filters.organizationId || alert.organizationId === filters.organizationId)
        && (!filters.status || alert.status === filters.status)
        && (!filters.severity || alert.severity === filters.severity)
        && (!filters.ruleId || alert.ruleId === filters.ruleId)
        && (!filters.subjectId || alert.subject.id === filters.subjectId)
        && (!filters.assigneeSubjectId
          || alert.assigneeSubjectId === filters.assigneeSubjectId)
        && (!filters.unassigned || alert.assigneeSubjectId === "")
        && (!filters.overdue || Date.parse(alert.slaDueAt) <= this.now())
        && (!filters.activeOnly || alert.status !== "resolved")
      ))
      .sort((left, right) => {
        const byTime = right.updatedAt.localeCompare(left.updatedAt);
        return byTime || left.alertId.localeCompare(right.alertId);
      })
      .slice(0, limit));
  }

  listAlertAudits(alertId, organizationId) {
    return this.read((state) => {
      const alert = state.alerts[alertId];
      if (!alert || alert.organizationId !== organizationId) return null;
      return [...(state.alertAudits[alertId] || [])];
    });
  }

  metricsSnapshot() {
    return this.read((state) => {
      const now = this.now();
      const alerts = Object.values(state.alerts);
      const byStatus = { open: 0, acknowledged: 0, resolved: 0 };
      const bySeverity = { warning: 0, high: 0, critical: 0 };
      const unassigned = { warning: 0, high: 0, critical: 0 };
      const oldest = { warning: 0, high: 0, critical: 0 };
      const overdue = { warning: 0, high: 0, critical: 0 };
      for (const alert of alerts) {
        byStatus[alert.status] += 1;
        bySeverity[alert.severity] += 1;
        if (alert.status !== "resolved") {
          if (alert.assigneeSubjectId === "") unassigned[alert.severity] += 1;
          const age = Math.max(0, Math.floor((now - Date.parse(alert.createdAt)) / 1000));
          oldest[alert.severity] = Math.max(oldest[alert.severity], age);
          if (Date.parse(alert.slaDueAt) <= now) overdue[alert.severity] += 1;
        }
      }
      return {
        acceptedEvents: state.stats.acceptedEvents,
        duplicateEvents: state.stats.duplicateEvents,
        findings: state.stats.findings,
        suppressedFindings: state.stats.suppressedFindings,
        alerts: { byStatus, bySeverity, unassigned, oldest, overdue },
        responseActions: Object.values(state.responseActions)
          .reduce((counts, action) => {
            counts[action.status] = (counts[action.status] || 0) + 1;
            return counts;
          }, {}),
        store: {
          events: Object.keys(state.events).length,
          findings: Object.keys(state.findings).length,
          alerts: alerts.length,
          responseActions: Object.keys(state.responseActions).length,
        },
      };
    });
  }
}
