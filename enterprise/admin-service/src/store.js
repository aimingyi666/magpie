import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import {
  APPROVAL_STATUSES,
  APPROVAL_STEP_STATUSES,
  ensureApprovalWorkflow,
} from "./approval.js";
import {
  BREAK_GLASS_STATUSES,
  BREAK_GLASS_REVIEW_CONCLUSIONS,
  breakGlassExpectedBinding,
} from "./break-glass.js";
import {
  NOTIFICATION_EVENT_TYPES,
  NOTIFICATION_SEVERITIES,
  NOTIFICATION_STATUSES,
} from "./notification-outbox.js";
import { validateNotificationChannelStore } from "./notification-channels.js";
import { validateNotificationRuleStore } from "./notification-rules.js";
import {
  AUDIT_CONTENT_ACTIONS,
  CONTENT_ACTION_TARGETS,
  isCanonicalUtcTimestamp,
  isContentBase64,
} from "./audit-content-governance.js";

const CONTENT_ACTIONS = new Set(AUDIT_CONTENT_ACTIONS);
const CONTENT_REQUEST_STATUSES = new Set(["reserved", "succeeded", "failed"]);
const CONTENT_EXPORT_STATUSES = new Set(["ready", "consumed", "expired"]);
const CONTENT_REF_PATTERN = /^ct_[A-Za-z0-9_-]{43}$/;
const CONTENT_HOLD_ID_PATTERN = /^hld_[A-Za-z0-9_-]{43}$/;
const CONTENT_STREAM_ID_PATTERN = /^str_[A-Za-z0-9_-]{43}$/;
const CONTENT_DELETION_ID_PATTERN = /^del_[A-Za-z0-9_-]{43}$/;
const CONTENT_UPSTREAM_EXPORT_ID_PATTERN = /^exp_[A-Za-z0-9_-]{43}$/;
const CONTENT_LOCAL_EXPORT_ID_PATTERN = /^cexp_[A-Za-z0-9_-]{24,96}$/;
const CONTENT_DOWNLOAD_PATH_PATTERN =
  /^\/api\/v1\/admin\/audit\/content\/exports\/cexp_[A-Za-z0-9_-]{24,96}\/download$/;
const CONTENT_REQUEST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,135}$/;
const CONTENT_ORGANIZATION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const CONTENT_POLICY_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const CONTENT_READ_REQUEST_FIELDS = new Set([
  "id",
  "requestHash",
  "requestFingerprint",
  "action",
  "contentRef",
  "approvalId",
  "actorSubjectId",
  "actorEmail",
  "sessionHash",
  "status",
  "createdAt",
  "updatedAt",
]);
const CONTENT_GOVERNANCE_REQUEST_FIELDS = new Set([
  "id",
  "requestHash",
  "requestFingerprint",
  "action",
  "targetType",
  "targetId",
  "approvalId",
  "actorSubjectId",
  "sessionHash",
  "status",
  "result",
  "createdAt",
  "updatedAt",
]);
const CONTENT_RESULT_FIELDS = Object.freeze({
  "audit.content.retention.run": new Set(["summary"]),
  "audit.content.delete": new Set(["duplicate", "deletion"]),
  "audit.content.legal_hold.create": new Set(["duplicate", "hold"]),
  "audit.content.legal_hold.release": new Set(["hold"]),
  "audit.content.export.create": new Set([
    "exportId",
    "status",
    "fileName",
    "contentType",
    "byteLength",
    "createdAt",
    "expiresAt",
    "consumedAt",
    "downloadPath",
  ]),
});
const CONTENT_RETENTION_SUMMARY_FIELDS = new Set([
  "dryRun",
  "scanned",
  "contentDeleted",
  "metadataRedacted",
  "skippedLegalHold",
  "exportsExpired",
  "errors",
]);
const CONTENT_DELETION_FIELDS = new Set([
  "deletionId",
  "contentRef",
  "streamId",
  "deletedAt",
  "plaintextSha256",
  "objectBytes",
  "retentionExpiresAt",
  "actorType",
  "actorId",
  "organizationId",
  "requestId",
  "reason",
  "approvalId",
  "policyVersion",
]);
const CONTENT_HOLD_REQUIRED_FIELDS = new Set([
  "holdId",
  "scope",
  "reason",
  "approvalId",
  "custodianId",
  "startsAt",
  "expiresAt",
  "createdAt",
  "createdBy",
  "organizationId",
  "status",
  "effectiveStatus",
]);
const CONTENT_HOLD_RELEASE_FIELDS = new Set([
  "releasedAt",
  "releasedBy",
  "releaseReason",
  "releaseApprovalId",
]);
const CONTENT_HOLD_SCOPE_FIELDS = new Set([
  "contentRef",
  "streamId",
  "userId",
  "departmentId",
  "deviceId",
  "agentId",
]);
const CONTENT_EXPORT_RECORD_FIELDS = new Set([
  "id",
  "exportId",
  "actorSubjectId",
  "actorEmail",
  "sessionHash",
  "organizationId",
  "upstreamExportId",
  "fileName",
  "contentType",
  "byteLength",
  "objectCount",
  "ciphertext",
  "iv",
  "tag",
  "digest",
  "status",
  "createdAt",
  "updatedAt",
  "expiresAt",
  "consumedAt",
]);
const CONTENT_EXPORT_TOKEN_FIELDS = new Set([
  "tokenHash",
  "exportId",
  "actorSubjectId",
  "actorEmail",
  "sessionHash",
  "createdAt",
  "expiresAt",
  "consumedAt",
]);
function emptyStore() {
  return {
    version: 1,
    orgUnits: {},
    userOrgUnits: {},
    roleBindings: {},
    adminSessions: {},
    desktopTickets: {},
    desktopTokens: {},
    adminAuditLogs: [],
    adminSystemAuditLogs: [],
    adminOperations: {},
    adminIdempotency: {},
    approvalRequests: {},
    approvalDecisions: {},
    approvalConsumptions: {},
    approvalCallbackEvents: {},
    approvalCallbackNonces: {},
    breakGlassGrants: {},
    breakGlassReviews: {},
    breakGlassReviewRequests: {},
    stepUpAssertions: {},
    notificationDeliveries: {},
    notificationReplayRequests: {},
    notificationChannels: {},
    notificationChannelTests: {},
    notificationChannelRequests: {},
    notificationRules: {},
    notificationRuleRequests: {},
    notificationSuppressions: {},
    notificationAggregates: {},
    notificationEscalations: {},
    adminExports: {},
    adminExportTokens: {},
    adminExportRequests: {},
    adminContentReadRequests: {},
    adminContentGovernanceRequests: {},
    adminContentExports: {},
    adminContentExportTokens: {},
  };
}

async function writeAtomic(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  const handle = await fs.open(temporary, "w", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(temporary, file);
}

function isPlainRecord(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function isSha256Hex(value) {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function isCanonicalTimestamp(value, optional = false) {
  if (value === "" && optional) return true;
  return isCanonicalUtcTimestamp(value);
}

function requireCanonicalTimestamp(value, message, optional = false) {
  if (!isCanonicalTimestamp(value, optional)) throw new Error(message);
}

function requireContentRequestBase(requestHash, request, prefix, message) {
  if (!isSha256Hex(requestHash)
      || !isPlainRecord(request)
      || request.requestHash !== requestHash
      || request.id !== `${prefix}${requestHash.slice(0, 32)}`
      || !/^apr_[A-Za-z0-9_-]{1,124}$/.test(String(request.approvalId || ""))
      || typeof request.actorSubjectId !== "string"
      || !request.actorSubjectId
      || !isSha256Hex(request.sessionHash)
      || !isSha256Hex(request.requestFingerprint)
      || !CONTENT_REQUEST_STATUSES.has(request.status)
      || !isCanonicalTimestamp(request.createdAt)
      || !isCanonicalTimestamp(request.updatedAt)) {
    throw new Error(message);
  }
}

function requireExactContentKeys(value, required, allowed, message) {
  if (!isPlainRecord(value)) throw new Error(message);
  const keys = Object.keys(value);
  if (keys.some((key) => !allowed.has(key))
      || [...required].some((key) => !Object.prototype.hasOwnProperty.call(value, key))) {
    throw new Error(message);
  }
}

function validContentEmail(value) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 320
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validContentTimestampOrder(createdAt, updatedAt) {
  return Date.parse(updatedAt) >= Date.parse(createdAt);
}

function requireContentScope(scope, message) {
  if (!isPlainRecord(scope) || Object.keys(scope).length === 0) throw new Error(message);
  for (const [key, item] of Object.entries(scope)) {
    if (!CONTENT_HOLD_SCOPE_FIELDS.has(key) || typeof item !== "string" || !item) {
      throw new Error(message);
    }
    if (key === "contentRef" && !CONTENT_REF_PATTERN.test(item)) throw new Error(message);
    if (key === "streamId" && !CONTENT_STREAM_ID_PATTERN.test(item)) throw new Error(message);
  }
}

function requireContentDeletion(value, message) {
  requireExactContentKeys(value, CONTENT_DELETION_FIELDS, CONTENT_DELETION_FIELDS, message);
  if (!CONTENT_DELETION_ID_PATTERN.test(String(value.deletionId || ""))
      || !CONTENT_REF_PATTERN.test(String(value.contentRef || ""))
      || !CONTENT_STREAM_ID_PATTERN.test(String(value.streamId || ""))
      || !isCanonicalTimestamp(value.deletedAt)
      || !isSha256Hex(value.plaintextSha256)
      || !Number.isSafeInteger(value.objectBytes)
      || value.objectBytes < 0
      || !isCanonicalTimestamp(value.retentionExpiresAt)
      || !["manual", "system"].includes(value.actorType)
      || typeof value.actorId !== "string"
      || !value.actorId
      || !CONTENT_ORGANIZATION_PATTERN.test(String(value.organizationId || ""))
      || !CONTENT_REQUEST_ID_PATTERN.test(String(value.requestId || ""))
      || typeof value.reason !== "string"
      || value.reason.length < 8
      || value.reason.length > 1024
      || !/^apr_[A-Za-z0-9_-]{1,124}$/.test(String(value.approvalId || ""))
      || !CONTENT_POLICY_VERSION_PATTERN.test(String(value.policyVersion || ""))) {
    throw new Error(message);
  }
}

function requireRetentionSummary(value, message) {
  requireExactContentKeys(
    value,
    CONTENT_RETENTION_SUMMARY_FIELDS,
    CONTENT_RETENTION_SUMMARY_FIELDS,
    message,
  );
  if (typeof value.dryRun !== "boolean") throw new Error(message);
  for (const key of [
    "scanned",
    "contentDeleted",
    "metadataRedacted",
    "skippedLegalHold",
    "exportsExpired",
    "errors",
  ]) {
    if (!Number.isSafeInteger(value[key]) || value[key] < 0) throw new Error(message);
  }
}

function requireContentHold(value, action, requestUpdatedAt, message) {
  const allowed = new Set([...CONTENT_HOLD_REQUIRED_FIELDS, ...CONTENT_HOLD_RELEASE_FIELDS]);
  requireExactContentKeys(value, CONTENT_HOLD_REQUIRED_FIELDS, allowed, message);
  requireContentScope(value.scope, message);
  if (!CONTENT_HOLD_ID_PATTERN.test(String(value.holdId || ""))
      || typeof value.reason !== "string"
      || value.reason.length < 8
      || value.reason.length > 1024
      || !/^apr_[A-Za-z0-9_-]{1,124}$/.test(String(value.approvalId || ""))
      || !CONTENT_ORGANIZATION_PATTERN.test(String(value.custodianId || ""))
      || !isCanonicalTimestamp(value.startsAt)
      || !isCanonicalTimestamp(value.expiresAt)
      || Date.parse(value.startsAt) >= Date.parse(value.expiresAt)
      || !isCanonicalTimestamp(value.createdAt)
      || !CONTENT_ORGANIZATION_PATTERN.test(String(value.createdBy || ""))
      || !CONTENT_ORGANIZATION_PATTERN.test(String(value.organizationId || ""))
      || !["active", "released"].includes(value.status)
      || !["active", "scheduled", "expired", "released"].includes(value.effectiveStatus)) {
    throw new Error(message);
  }
  const hasReleaseField = [...CONTENT_HOLD_RELEASE_FIELDS]
    .some((key) => Object.prototype.hasOwnProperty.call(value, key));
  if (value.status === "released") {
    if (value.effectiveStatus !== "released"
        || !isCanonicalTimestamp(value.releasedAt)
        || Date.parse(value.releasedAt) < Date.parse(value.createdAt)
        || Date.parse(value.releasedAt) > Date.parse(requestUpdatedAt)
        || !CONTENT_ORGANIZATION_PATTERN.test(String(value.releasedBy || ""))
        || typeof value.releaseReason !== "string"
        || value.releaseReason.length < 8
        || value.releaseReason.length > 1024
        || !/^apr_[A-Za-z0-9_-]{1,124}$/.test(String(value.releaseApprovalId || ""))) {
      throw new Error(message);
    }
  } else if (hasReleaseField) {
    throw new Error(message);
  }
  const expectedEffectiveStatus = Date.parse(value.startsAt) > Date.parse(requestUpdatedAt)
    ? "scheduled"
    : Date.parse(value.expiresAt) <= Date.parse(requestUpdatedAt)
      ? "expired"
      : "active";
  if (action === "audit.content.legal_hold.create") {
    if (value.status === "released" || hasReleaseField) throw new Error(message);
    if (value.status !== "active" || value.effectiveStatus !== expectedEffectiveStatus) {
      throw new Error(message);
    }
    return;
  }
  if (value.status !== "released"
      || value.effectiveStatus !== "released"
      || !hasReleaseField) {
    throw new Error(message);
  }
}

function requireContentExportResult(value, message) {
  const required = new Set([
    "exportId",
    "status",
    "fileName",
    "contentType",
    "byteLength",
    "createdAt",
    "expiresAt",
  ]);
  requireExactContentKeys(value, required, CONTENT_RESULT_FIELDS["audit.content.export.create"], message);
  if (!CONTENT_LOCAL_EXPORT_ID_PATTERN.test(String(value.exportId || ""))
      || !["ready", "consumed", "expired"].includes(value.status)
      || value.fileName !== `${value.exportId}.mge.enc`
      || value.contentType !== "application/octet-stream"
      || !Number.isSafeInteger(value.byteLength)
      || value.byteLength < 0
      || !isCanonicalTimestamp(value.createdAt)
      || !isCanonicalTimestamp(value.expiresAt)
      || Date.parse(value.expiresAt) <= Date.parse(value.createdAt)
      || (value.status === "ready" && !CONTENT_DOWNLOAD_PATH_PATTERN.test(String(value.downloadPath || "")))
      || (value.status !== "ready" && value.downloadPath)
      || (value.status === "consumed" && !isCanonicalTimestamp(value.consumedAt))
      || (value.status !== "consumed" && value.consumedAt)) {
    throw new Error(message);
  }
}

function requireContentResult(action, value, message) {
  const allowed = CONTENT_RESULT_FIELDS[action];
  if (!allowed || !isPlainRecord(value) || Object.keys(value).length === 0) {
    throw new Error(message);
  }
  if (Object.keys(value).some((key) => !allowed.has(key))) throw new Error(message);
  if (action === "audit.content.retention.run") {
    requireExactContentKeys(
      value,
      CONTENT_RESULT_FIELDS[action],
      CONTENT_RESULT_FIELDS[action],
      message,
    );
    requireRetentionSummary(value.summary, message);
    return;
  }
  if (action === "audit.content.delete") {
    requireExactContentKeys(
      value,
      CONTENT_RESULT_FIELDS[action],
      CONTENT_RESULT_FIELDS[action],
      message,
    );
    if (typeof value.duplicate !== "boolean") throw new Error(message);
    requireContentDeletion(value.deletion, message);
    return;
  }
  if (action === "audit.content.legal_hold.create") {
    requireExactContentKeys(
      value,
      CONTENT_RESULT_FIELDS[action],
      CONTENT_RESULT_FIELDS[action],
      message,
    );
    if (typeof value.duplicate !== "boolean") throw new Error(message);
    requireContentHold(value.hold, action, value.hold.createdAt, message);
    return;
  }
  if (action === "audit.content.legal_hold.release") {
    requireExactContentKeys(
      value,
      CONTENT_RESULT_FIELDS[action],
      CONTENT_RESULT_FIELDS[action],
      message,
    );
    requireContentHold(value.hold, action, value.hold.releasedAt, message);
    return;
  }
  if (action === "audit.content.export.create") {
    requireContentExportResult(value, message);
  }
}

function validateContentResultCrossRecords(value, request, message) {
  if (request.action !== "audit.content.export.create" || request.status !== "succeeded") {
    return;
  }
  const record = value.adminContentExports[request.result.exportId];
  if (!isPlainRecord(record)
      || record.actorSubjectId !== request.actorSubjectId
      || record.sessionHash !== request.sessionHash
      || record.status !== request.result.status
      || record.consumedAt !== (request.result.consumedAt || "")
      || record.fileName !== request.result.fileName
      || record.contentType !== request.result.contentType
      || record.byteLength !== request.result.byteLength
      || record.createdAt !== request.result.createdAt
      || record.expiresAt !== request.result.expiresAt
      || !Object.values(value.adminContentExportTokens)
        .some((token) => token.exportId === request.result.exportId
          && token.actorSubjectId === record.actorSubjectId
          && token.actorEmail === record.actorEmail
          && token.sessionHash === record.sessionHash
          && token.createdAt === record.createdAt
          && token.expiresAt === record.expiresAt
          && token.consumedAt === record.consumedAt)
      || (request.result.downloadPath
        && request.result.downloadPath
          !== `/api/v1/admin/audit/content/exports/${encodeURIComponent(record.id)}/download`)) {
    throw new Error(message);
  }
}

function validateContentActionTarget(action, targetType, targetId) {
  if (!CONTENT_ACTIONS.has(action) || CONTENT_ACTION_TARGETS[action] !== targetType) {
    return false;
  }
  if (action === "audit.content.read_request" || action === "audit.content.delete") {
    return CONTENT_REF_PATTERN.test(targetId);
  }
  if (action === "audit.content.retention.run") return targetId === "retention_run";
  if (action === "audit.content.legal_hold.release") {
    return CONTENT_HOLD_ID_PATTERN.test(targetId);
  }
  if (action === "audit.content.legal_hold.create") {
    return /^content_hold_[a-f0-9]{64}$/.test(targetId);
  }
  return /^content_export_[a-f0-9]{64}$/.test(targetId);
}

function validateContentApprovalBinding(value, request) {
  const approval = value.approvalRequests[request.approvalId];
  if (!isPlainRecord(approval)
      || approval.requesterSubjectId !== request.actorSubjectId
      || approval.action !== request.action
      || approval.targetOrgUnitId !== "*") {
    return false;
  }
  if (request.action === "audit.content.read_request") {
    return approval.targetType === "content"
      && approval.targetId === request.contentRef;
  }
  return approval.targetType === request.targetType
    && approval.targetId === request.targetId;
}

function validateLoaded(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("admin store must be a JSON object");
  }
  if (value.version !== 1) throw new Error(`unsupported admin store version ${value.version}`);
  for (const key of Object.keys(emptyStore())) {
    if (value[key] == null) value[key] = emptyStore()[key];
  }
  for (const key of [
    "orgUnits",
    "userOrgUnits",
    "roleBindings",
    "adminSessions",
    "desktopTickets",
    "desktopTokens",
    "adminOperations",
    "adminIdempotency",
    "approvalRequests",
    "approvalDecisions",
    "approvalConsumptions",
    "approvalCallbackEvents",
    "approvalCallbackNonces",
    "breakGlassGrants",
    "breakGlassReviews",
    "breakGlassReviewRequests",
    "stepUpAssertions",
    "notificationDeliveries",
    "notificationReplayRequests",
    "notificationChannels",
    "notificationChannelTests",
    "notificationChannelRequests",
    "notificationRules",
    "notificationRuleRequests",
    "notificationSuppressions",
    "notificationAggregates",
    "notificationEscalations",
    "adminExports",
    "adminExportTokens",
    "adminExportRequests",
    "adminContentReadRequests",
    "adminContentGovernanceRequests",
    "adminContentExports",
    "adminContentExportTokens",
  ]) {
    if (!value[key] || typeof value[key] !== "object" || Array.isArray(value[key])) {
      throw new Error(`admin store ${key} must be an object`);
    }
  }
  for (const [userId, orgUnitId] of Object.entries(value.userOrgUnits)) {
    if (!userId || typeof orgUnitId !== "string" || !orgUnitId) {
      throw new Error("admin store userOrgUnits values must be non-empty organization IDs");
    }
  }
  if (!Array.isArray(value.adminAuditLogs)) {
    throw new Error("admin store adminAuditLogs must be an array");
  }
  if (!Array.isArray(value.adminSystemAuditLogs)) {
    throw new Error("admin store adminSystemAuditLogs must be an array");
  }
  const approvalStatuses = new Set(APPROVAL_STATUSES);
  const approvalStepStatuses = new Set(APPROVAL_STEP_STATUSES);
  for (const [approvalId, approval] of Object.entries(value.approvalRequests)) {
    if (!approval || typeof approval !== "object" || Array.isArray(approval)) {
      throw new Error("admin store approvalRequests values must be objects");
    }
    if (approval.id !== approvalId || !approvalId.startsWith("apr_")) {
      throw new Error("admin store approval request IDs must be stable apr_ IDs");
    }
    if (!approvalStatuses.has(approval.status)) {
      throw new Error("admin store approval request has an unsupported status");
    }
    for (const key of [
      "environmentId",
      "policyVersion",
      "requesterSubjectId",
      "action",
      "targetType",
      "targetId",
      "targetOrgUnitId",
      "riskLevel",
      "reason",
      "payloadDigest",
      "bindingDigest",
      "createdAt",
      "updatedAt",
      "expiresAt",
    ]) {
      if (typeof approval[key] !== "string" || !approval[key]) {
        throw new Error(`admin store approval request ${key} must be a non-empty string`);
      }
    }
    if (![approval.payloadDigest, approval.bindingDigest]
      .every((digest) => /^[a-f0-9]{64}$/.test(digest))) {
      throw new Error("admin store approval request digests must be SHA-256 hex");
    }
    if (!Array.isArray(approval.stateHistory) || approval.stateHistory.length === 0) {
      throw new Error("admin store approval request stateHistory must be a non-empty array");
    }
    ensureApprovalWorkflow(approval);
    if (approval.workflowVersion !== 1
        || !["serial", "parallel"].includes(approval.workflowKind)
        || !Array.isArray(approval.steps)
        || approval.steps.length === 0) {
      throw new Error("admin store approval request has an invalid workflow");
    }
    const stepIds = new Set();
    for (const step of approval.steps) {
      if (!step
          || typeof step !== "object"
          || Array.isArray(step)
          || typeof step.stepId !== "string"
          || !/^stp_[A-Za-z0-9_-]{1,60}$/.test(step.stepId)
          || stepIds.has(step.stepId)
          || !["serial", "parallel"].includes(step.mode)
          || !approvalStepStatuses.has(step.status)
          || !Number.isSafeInteger(step.order)
          || step.order < 1
          || !Number.isSafeInteger(step.requiredApprovers)
          || step.requiredApprovers < 1
          || !Number.isSafeInteger(step.quorum)
          || step.quorum < 1
          || step.quorum > step.requiredApprovers) {
        throw new Error("admin store approval request has an invalid workflow step");
      }
      stepIds.add(step.stepId);
      for (const key of [
        "eligibleSubjectIds",
        "eligibleRoles",
        "ineligibleSubjectIds",
        "decidedBySubjectIds",
      ]) {
        if (!Array.isArray(step[key])
            || step[key].some((item) => typeof item !== "string" || !item)) {
          throw new Error(`admin store approval step ${key} is invalid`);
        }
      }
      if (!Array.isArray(step.transferHistory)
          || step.transferHistory.some((entry) => (
            !entry
            || typeof entry !== "object"
            || Array.isArray(entry)
            || !["fromSubjectId", "toSubjectId", "actorSubjectId", "reason", "at"]
              .every((key) => typeof entry[key] === "string")
          ))) {
        throw new Error("admin store approval step transferHistory is invalid");
      }
    }
  }
  for (const [decisionId, decision] of Object.entries(value.approvalDecisions)) {
    if (!decision || typeof decision !== "object" || Array.isArray(decision)
        || decision.id !== decisionId
        || !value.approvalRequests[decision.approvalId]) {
      throw new Error("admin store approvalDecisions must reference a stored approval");
    }
    if (decision.stepId != null
        && (typeof decision.stepId !== "string"
          || !value.approvalRequests[decision.approvalId].steps
            .some((step) => step.stepId === decision.stepId))) {
      throw new Error("admin store approvalDecisions must reference a stored workflow step");
    }
  }
  for (const [approvalId, consumption] of Object.entries(value.approvalConsumptions)) {
    if (!value.approvalRequests[approvalId]
        || !consumption
        || typeof consumption !== "object"
        || Array.isArray(consumption)
        || consumption.approvalId !== approvalId
        || typeof consumption.operationId !== "string"
        || !consumption.operationId) {
      throw new Error("admin store approvalConsumptions must reference an approval and operation");
    }
  }
  for (const [eventId, event] of Object.entries(value.approvalCallbackEvents)) {
    if (!event
        || typeof event !== "object"
        || Array.isArray(event)
        || event.eventId !== eventId
        || !value.approvalRequests[event.approvalId]
        || !/^[a-f0-9]{64}$/.test(String(event.eventDigest || ""))
        || !/^[a-f0-9]{64}$/.test(String(event.nonceDigest || ""))
        || !["approved", "rejected", "step_progressed"].includes(event.outcome)) {
      throw new Error("admin store approvalCallbackEvents contains an invalid event");
    }
    for (const key of [
      "issuer",
      "audience",
      "externalReference",
      "actorSubjectId",
      "decisionId",
      "receivedAt",
    ]) {
      if (typeof event[key] !== "string" || !event[key]) {
        throw new Error(`admin store approval callback event ${key} is invalid`);
      }
    }
    if (!Number.isFinite(Date.parse(event.receivedAt))) {
      throw new Error("admin store approval callback event receivedAt is invalid");
    }
  }
  for (const [nonceDigest, nonce] of Object.entries(value.approvalCallbackNonces)) {
    if (!nonce
        || typeof nonce !== "object"
        || Array.isArray(nonce)
        || nonce.nonceDigest !== nonceDigest
        || !/^[a-f0-9]{64}$/.test(nonceDigest)
        || !value.approvalCallbackEvents[nonce.eventId]
        || !Number.isFinite(Date.parse(nonce.receivedAt))
        || !Number.isFinite(Date.parse(nonce.expiresAt))) {
      throw new Error("admin store approvalCallbackNonces contains an invalid nonce");
    }
  }
  const breakGlassReviewConclusions = new Set(BREAK_GLASS_REVIEW_CONCLUSIONS);
  const breakGlassStatuses = new Set(BREAK_GLASS_STATUSES);
  const reviewedGrantIds = new Set();
  for (const [grantId, grant] of Object.entries(value.breakGlassGrants)) {
    if (!grant
        || typeof grant !== "object"
        || Array.isArray(grant)
        || grant.id !== grantId
        || !grantId.startsWith("bgr_")) {
      throw new Error("admin store breakGlassGrants contains an invalid grant");
    }
    for (const key of [
      "requesterSubjectId",
      "requesterEmail",
      "action",
      "targetType",
      "targetId",
      "targetOrgUnitId",
      "riskLevel",
      "environmentId",
      "policyVersion",
      "incidentId",
      "reason",
      "payloadDigest",
      "bindingDigest",
      "createdAt",
      "updatedAt",
      "expiresAt",
    ]) {
      if (typeof grant[key] !== "string" || !grant[key]) {
        throw new Error(`admin store break-glass grant ${key} is invalid`);
      }
    }
    for (const key of [
      "consumedAt",
      "consumedBySubjectId",
      "operationId",
      "reviewDueAt",
      "reviewOverdueAt",
      "reviewedAt",
    ]) {
      if (typeof grant[key] !== "string") {
        throw new Error(`admin store break-glass grant ${key} is invalid`);
      }
    }
    if (!grant.payloadSummary
        || typeof grant.payloadSummary !== "object"
        || Array.isArray(grant.payloadSummary)
        || !/^[a-f0-9]{64}$/.test(grant.payloadDigest)
        || !/^[a-f0-9]{64}$/.test(grant.bindingDigest)
        || !Number.isFinite(Date.parse(grant.createdAt))
        || !Number.isFinite(Date.parse(grant.updatedAt))
        || !Number.isFinite(Date.parse(grant.expiresAt))) {
      throw new Error("admin store break-glass grant metadata is invalid");
    }
    if ((grant.consumedAt && !Number.isFinite(Date.parse(grant.consumedAt)))
        || (grant.reviewDueAt && !Number.isFinite(Date.parse(grant.reviewDueAt)))
        || (grant.reviewOverdueAt && !Number.isFinite(Date.parse(grant.reviewOverdueAt)))
        || (grant.reviewedAt && !Number.isFinite(Date.parse(grant.reviewedAt)))) {
      throw new Error("admin store break-glass grant timestamp is invalid");
    }
    if (grant.consumedAt) {
      if (!grant.consumedBySubjectId
          || !grant.operationId
          || !grant.reviewDueAt
          || Date.parse(grant.reviewDueAt) <= Date.parse(grant.consumedAt)) {
        throw new Error(
          "admin store consumed break-glass grants require an actor, operation, and review due time",
        );
      }
    }
    if (!grant.notificationEventIds
        || typeof grant.notificationEventIds !== "object"
        || Array.isArray(grant.notificationEventIds)
        || !["used", "reviewDue", "reviewOverdue", "reviewed"].every(
          (key) => typeof grant.notificationEventIds[key] === "string",
        )
        || !Array.isArray(grant.stateHistory)
        || grant.stateHistory.length === 0) {
      throw new Error("admin store break-glass grant history is invalid");
    }
    for (const entry of grant.stateHistory) {
      if (!entry
          || typeof entry !== "object"
          || Array.isArray(entry)
          || !breakGlassStatuses.has(entry.status)
          || typeof entry.at !== "string"
          || !Number.isFinite(Date.parse(entry.at))
          || typeof entry.actorSubjectId !== "string"
          || typeof entry.reason !== "string") {
        throw new Error("admin store break-glass grant state history is invalid");
      }
    }
    let expected;
    try {
      expected = breakGlassExpectedBinding({
        environmentId: grant.environmentId,
        policyVersion: grant.policyVersion,
        requesterSubjectId: grant.requesterSubjectId,
        action: grant.action,
        targetType: grant.targetType,
        targetId: grant.targetId,
        targetOrgUnitId: grant.targetOrgUnitId,
        riskLevel: grant.riskLevel,
        reason: grant.reason,
        payload: grant.payloadSummary,
      });
    } catch {
      throw new Error("admin store break-glass grant payload is invalid");
    }
    if (grant.payloadDigest !== expected.payloadDigest
        || grant.bindingDigest !== expected.bindingDigest) {
      throw new Error("admin store break-glass grant digests do not match its binding");
    }
  }
  for (const [reviewId, review] of Object.entries(value.breakGlassReviews)) {
    const grant = review?.grantId ? value.breakGlassGrants[review.grantId] : null;
    if (!grant
        || !review
        || typeof review !== "object"
        || Array.isArray(review)
        || review.id !== reviewId
        || !reviewId.startsWith("bgrv_")
        || reviewedGrantIds.has(review.grantId)
        || !breakGlassReviewConclusions.has(review.conclusion)
        || review.reviewerSubjectId === grant.requesterSubjectId) {
      throw new Error("admin store breakGlassReviews contains an invalid review");
    }
    for (const key of [
      "grantId",
      "reviewerSubjectId",
      "reviewerEmail",
      "conclusion",
      "reason",
      "reviewedAt",
      "notificationEventId",
    ]) {
      if (typeof review[key] !== "string" || !review[key]) {
        throw new Error(`admin store break-glass review ${key} is invalid`);
      }
    }
    if (!Number.isFinite(Date.parse(review.reviewedAt)) || !grant.consumedAt) {
      throw new Error("admin store break-glass review must follow a consumed grant");
    }
    reviewedGrantIds.add(review.grantId);
  }
  for (const [requestHash, request] of Object.entries(value.breakGlassReviewRequests)) {
    const review = request?.reviewId ? value.breakGlassReviews[request.reviewId] : null;
    if (!/^[a-f0-9]{64}$/.test(requestHash)
        || !request
        || typeof request !== "object"
        || Array.isArray(request)
        || request.requestHash !== requestHash
        || typeof request.grantId !== "string"
        || !value.breakGlassGrants[request.grantId]
        || !review
        || review.grantId !== request.grantId
        || !/^[a-f0-9]{64}$/.test(String(request.requestFingerprint || ""))
        || !Number.isFinite(Date.parse(request.createdAt))) {
      throw new Error("admin store breakGlassReviewRequests contains an invalid request");
    }
  }
  for (const [sessionHash, assertion] of Object.entries(value.stepUpAssertions)) {
    if (!/^[a-f0-9]{64}$/.test(sessionHash)
        || !assertion
        || typeof assertion !== "object"
        || Array.isArray(assertion)
        || assertion.sessionHash !== sessionHash
        || typeof assertion.subjectId !== "string"
        || !assertion.subjectId) {
      throw new Error("admin store stepUpAssertions contains an invalid assertion");
    }
    for (const key of [
      "acr",
      "ip",
      "userAgentHash",
      "accessDigest",
      "verifiedAt",
      "expiresAt",
      "criticalExpiresAt",
    ]) {
      if (typeof assertion[key] !== "string") {
        throw new Error(`admin store step-up assertion ${key} is invalid`);
      }
    }
    if (!Array.isArray(assertion.amr)
        || assertion.amr.some((method) => typeof method !== "string")
        || !Number.isSafeInteger(assertion.authTime)
        || assertion.authTime <= 0
        || !/^[a-f0-9]{64}$/.test(assertion.userAgentHash)
        || !/^[a-f0-9]{64}$/.test(assertion.accessDigest)
        || !Number.isFinite(Date.parse(assertion.verifiedAt))
        || !Number.isFinite(Date.parse(assertion.expiresAt))
        || !Number.isFinite(Date.parse(assertion.criticalExpiresAt))) {
      throw new Error("admin store step-up assertion has invalid fields");
    }
  }
  const notificationStatuses = new Set(NOTIFICATION_STATUSES);
  const notificationEventTypes = new Set(NOTIFICATION_EVENT_TYPES);
  const notificationSeverities = new Set(NOTIFICATION_SEVERITIES);
  for (const [deliveryId, delivery] of Object.entries(value.notificationDeliveries)) {
    if (!delivery
        || typeof delivery !== "object"
        || Array.isArray(delivery)
        || delivery.deliveryId !== deliveryId
        || !/^ntd_[a-f0-9]{32}$/.test(deliveryId)
        || typeof delivery.eventId !== "string"
        || !/^evt_[A-Za-z0-9_.:-]{4,195}$/.test(delivery.eventId)
        || delivery.schemaVersion !== 1
        || (delivery.channelId != null
          && (typeof delivery.channelId !== "string"
            || (delivery.channelId && !/^nch_[a-f0-9]{24}$/.test(delivery.channelId))))
        || !notificationEventTypes.has(delivery.eventType)
        || !notificationSeverities.has(delivery.severity)
        || !notificationStatuses.has(delivery.status)
        || delivery.dataClassification !== "L0") {
      throw new Error("admin store notificationDeliveries contains an invalid delivery");
    }
    if (!Number.isSafeInteger(delivery.attemptCount) || delivery.attemptCount < 0
        || !Number.isSafeInteger(delivery.maxAttempts) || delivery.maxAttempts < 1
        || delivery.attemptCount > delivery.maxAttempts + 1
        || !Number.isSafeInteger(delivery.replayCount) || delivery.replayCount < 0) {
      throw new Error("admin store notification delivery counters are invalid");
    }
    for (const key of [
      "occurredAt",
      "organizationId",
      "actorSubjectId",
      "actorEmail",
      "targetType",
      "targetId",
      "targetOrgUnitId",
      "operationId",
      "requestId",
      "errorCode",
      "summary",
      "createdAt",
      "updatedAt",
      "deliveredAt",
      "nextAttemptAt",
      "leaseOwner",
      "leaseExpiresAt",
      "lastErrorCode",
      "lastReplayAt",
    ]) {
      if (typeof delivery[key] !== "string") {
        throw new Error(`admin store notification delivery ${key} is invalid`);
      }
    }
    if (!delivery.summary
        || delivery.summary.length > 240
        || !Number.isFinite(Date.parse(delivery.occurredAt))
        || !Number.isFinite(Date.parse(delivery.createdAt))
        || !Number.isFinite(Date.parse(delivery.updatedAt))) {
      throw new Error("admin store notification delivery metadata is invalid");
    }
    if (delivery.nextAttemptAt && !Number.isFinite(Date.parse(delivery.nextAttemptAt))) {
      throw new Error("admin store notification delivery nextAttemptAt is invalid");
    }
    if (delivery.leaseExpiresAt && !Number.isFinite(Date.parse(delivery.leaseExpiresAt))) {
      throw new Error("admin store notification delivery leaseExpiresAt is invalid");
    }
    if (delivery.deliveredAt && !Number.isFinite(Date.parse(delivery.deliveredAt))) {
      throw new Error("admin store notification delivery deliveredAt is invalid");
    }
    if (delivery.status === "delivered" && !delivery.deliveredAt) {
      throw new Error("admin store delivered notification is missing deliveredAt");
    }
  }
  for (const [idempotencyKeyHash, replay] of Object.entries(value.notificationReplayRequests)) {
    if (!/^[a-f0-9]{64}$/.test(idempotencyKeyHash)
        || !replay
        || typeof replay !== "object"
        || Array.isArray(replay)
        || replay.idempotencyKeyHash !== idempotencyKeyHash
        || typeof replay.replayRequestId !== "string"
        || !/^ntr_[a-f0-9]{32}$/.test(replay.replayRequestId)
        || !value.notificationDeliveries[replay.deliveryId]
        || !/^[a-f0-9]{64}$/.test(String(replay.requestFingerprint || ""))) {
      throw new Error("admin store notificationReplayRequests contains an invalid request");
    }
    for (const key of ["deliveryId", "reason", "actorSubjectId", "actorEmail", "createdAt"]) {
      if (typeof replay[key] !== "string" || !replay[key]) {
        throw new Error(`admin store notification replay request ${key} is invalid`);
      }
    }
    if (!Number.isFinite(Date.parse(replay.createdAt))) {
      throw new Error("admin store notification replay request createdAt is invalid");
    }
  }
  validateNotificationChannelStore(value);
  validateNotificationRuleStore(value);
  for (const [exportId, exportRecord] of Object.entries(value.adminExports)) {
    if (!exportRecord
        || typeof exportRecord !== "object"
        || Array.isArray(exportRecord)
        || exportRecord.id !== exportId
        || !/^exp_[a-f0-9-]{36}$/.test(exportId)
        || !["usage", "audit"].includes(exportRecord.kind)
        || !["ready", "consumed", "expired"].includes(exportRecord.status)) {
      throw new Error("admin store adminExports contains an invalid export");
    }
    for (const key of [
      "actorSubjectId",
      "actorEmail",
      "sessionHash",
      "scopeOrgUnitId",
      "fileName",
      "contentType",
      "content",
      "createdAt",
      "expiresAt",
      "consumedAt",
    ]) {
      if (typeof exportRecord[key] !== "string") {
        throw new Error(`admin store export ${key} is invalid`);
      }
    }
    if (!/^[a-f0-9]{64}$/.test(exportRecord.sessionHash)
        || !Number.isSafeInteger(exportRecord.rowCount)
        || exportRecord.rowCount < 0
        || !Number.isSafeInteger(exportRecord.byteLength)
        || exportRecord.byteLength < 0
        || !Number.isFinite(Date.parse(exportRecord.createdAt))
        || !Number.isFinite(Date.parse(exportRecord.expiresAt))) {
      throw new Error("admin store export metadata is invalid");
    }
  }
  for (const [tokenHash, token] of Object.entries(value.adminExportTokens)) {
    if (!/^[a-f0-9]{64}$/.test(tokenHash)
        || !token
        || typeof token !== "object"
        || Array.isArray(token)
        || token.tokenHash !== tokenHash
        || !value.adminExports[token.exportId]
        || typeof token.actorSubjectId !== "string"
        || !token.actorSubjectId
        || !/^[a-f0-9]{64}$/.test(String(token.sessionHash || ""))
        || !Number.isFinite(Date.parse(token.expiresAt))
        || typeof token.consumedAt !== "string") {
      throw new Error("admin store adminExportTokens contains an invalid token");
    }
  }
  for (const [requestHash, request] of Object.entries(value.adminExportRequests)) {
    if (!/^[a-f0-9]{64}$/.test(requestHash)
        || !request
        || typeof request !== "object"
        || Array.isArray(request)
        || request.requestHash !== requestHash
        || !value.adminExports[request.exportId]
        || !/^[a-f0-9]{64}$/.test(String(request.requestFingerprint || ""))
        || !Number.isFinite(Date.parse(request.createdAt))) {
      throw new Error("admin store adminExportRequests contains an invalid request");
    }
  }
  for (const [requestHash, request] of Object.entries(value.adminContentReadRequests)) {
    const message = "admin store adminContentReadRequests contains an invalid request";
    requireContentRequestBase(
      requestHash,
      request,
      "crr_",
      message,
    );
    requireExactContentKeys(
      request,
      CONTENT_READ_REQUEST_FIELDS,
      CONTENT_READ_REQUEST_FIELDS,
      message,
    );
    if (request.action !== "audit.content.read_request"
        || !CONTENT_REF_PATTERN.test(String(request.contentRef || ""))
        || !validContentEmail(request.actorEmail)
        || !validContentTimestampOrder(request.createdAt, request.updatedAt)
        || !validateContentApprovalBinding(value, request)) {
      throw new Error(message);
    }
  }
  for (const [requestHash, request] of Object.entries(
    value.adminContentGovernanceRequests,
  )) {
    const message = "admin store adminContentGovernanceRequests contains an invalid request";
    requireContentRequestBase(
      requestHash,
      request,
      "gcr_",
      message,
    );
    requireExactContentKeys(
      request,
      CONTENT_GOVERNANCE_REQUEST_FIELDS,
      CONTENT_GOVERNANCE_REQUEST_FIELDS,
      message,
    );
    if (request.action === "audit.content.read_request"
        || !validateContentActionTarget(
          request.action,
          request.targetType,
          request.targetId,
        )
        || !validateContentApprovalBinding(value, request)
        || !validContentTimestampOrder(request.createdAt, request.updatedAt)) {
      throw new Error(message);
    }
    if ((request.status === "reserved" || request.status === "failed")
        && Object.keys(request.result).length !== 0) {
      throw new Error("admin store content request result does not match its status");
    }
    if (request.status === "succeeded") {
      requireContentResult(request.action, request.result, message);
      validateContentResultCrossRecords(value, request, message);
    } else if (!isPlainRecord(request.result)) {
      throw new Error(message);
    }
  }
  for (const [exportId, record] of Object.entries(value.adminContentExports)) {
    const message = "admin store adminContentExports contains an invalid export";
    requireExactContentKeys(
      record,
      CONTENT_EXPORT_RECORD_FIELDS,
      CONTENT_EXPORT_RECORD_FIELDS,
      message,
    );
    if (!isPlainRecord(record)
        || record.id !== exportId
        || record.exportId !== exportId
        || !CONTENT_LOCAL_EXPORT_ID_PATTERN.test(exportId)
        || typeof record.actorSubjectId !== "string"
        || !record.actorSubjectId
        || typeof record.actorEmail !== "string"
        || !record.actorEmail
        || !isSha256Hex(record.sessionHash)
        || typeof record.organizationId !== "string"
        || !/^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/.test(record.organizationId)
        || !CONTENT_UPSTREAM_EXPORT_ID_PATTERN.test(String(record.upstreamExportId || ""))
        || record.fileName !== `${exportId}.mge.enc`
        || record.contentType !== "application/octet-stream"
        || !Number.isSafeInteger(record.byteLength)
        || record.byteLength < 0
        || !Number.isSafeInteger(record.objectCount)
        || record.objectCount < 0
        || !CONTENT_EXPORT_STATUSES.has(record.status)
        || !isCanonicalTimestamp(record.createdAt)
        || !isCanonicalTimestamp(record.updatedAt)
        || !isCanonicalTimestamp(record.expiresAt)
        || !isCanonicalTimestamp(record.consumedAt, true)
        || typeof record.ciphertext !== "string"
        || !isContentBase64(record.iv, 12)
        || !isContentBase64(record.tag, 16)
        || !isSha256Hex(record.digest)
        || !validContentTimestampOrder(record.createdAt, record.updatedAt)
        || Date.parse(record.expiresAt) <= Date.parse(record.createdAt)) {
      throw new Error(message);
    }
    const ciphertextBytes = Buffer.from(record.ciphertext, "base64");
    if ((record.ciphertext === ""
          ? record.byteLength !== 0
          : !isContentBase64(record.ciphertext))
        || ciphertextBytes.length !== record.byteLength
        || crypto.createHash("sha256").update(ciphertextBytes).digest("hex")
          !== record.digest
        || (record.status === "consumed" && !record.consumedAt)
        || (record.status !== "consumed" && record.consumedAt)
        || (record.status === "consumed" && record.updatedAt !== record.consumedAt)) {
      throw new Error(`${message} encrypted payload`);
    }
  }
  for (const [tokenHash, token] of Object.entries(
    value.adminContentExportTokens,
  )) {
    const message = "admin store adminContentExportTokens contains an invalid token";
    requireExactContentKeys(
      token,
      CONTENT_EXPORT_TOKEN_FIELDS,
      CONTENT_EXPORT_TOKEN_FIELDS,
      message,
    );
    if (!isSha256Hex(tokenHash)
        || !isPlainRecord(token)
        || token.tokenHash !== tokenHash
        || !isPlainRecord(value.adminContentExports[token.exportId])
        || typeof token.actorSubjectId !== "string"
        || !token.actorSubjectId
        || !validContentEmail(token.actorEmail)
        || !isSha256Hex(token.sessionHash)
        || !isCanonicalTimestamp(token.createdAt)
        || !isCanonicalTimestamp(token.expiresAt)
        || !isCanonicalTimestamp(token.consumedAt, true)) {
      throw new Error(message);
    }
    const record = value.adminContentExports[token.exportId];
    if (record.actorSubjectId !== token.actorSubjectId
        || record.actorEmail !== token.actorEmail
        || record.sessionHash !== token.sessionHash
        || record.createdAt !== token.createdAt
        || record.expiresAt !== token.expiresAt
        || record.consumedAt !== token.consumedAt) {
      throw new Error("admin store content export token does not match its export");
    }
  }
  return value;
}

export class JsonStore {
  constructor(file) {
    this.file = file;
    this.data = emptyStore();
    this.queue = Promise.resolve();
  }

  async load() {
    try {
      this.data = validateLoaded(JSON.parse(await fs.readFile(this.file, "utf8")));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await writeAtomic(this.file, this.data);
    }
    return this.data;
  }

  async read(fn) {
    await this.queue;
    return fn(this.data);
  }

  mutate(fn) {
    const run = this.queue.then(async () => {
      const draft = structuredClone(this.data);
      const result = await fn(draft);
      validateLoaded(draft);
      await writeAtomic(this.file, draft);
      this.data = draft;
      return result;
    });
    this.queue = run.catch(() => {});
    return run;
  }
}
