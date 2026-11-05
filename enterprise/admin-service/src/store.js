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
