import crypto from "node:crypto";
import {
  isAuditContentAction,
  normalizeAuditContentPayload,
} from "./audit-content-governance.js";

export const APPROVAL_POLICY_VERSION = "APR-01a-v1";

export const RISK_LEVELS = Object.freeze(["L", "M", "H", "C"]);

export const APPROVAL_STATUSES = Object.freeze([
  "requested",
  "pending_approval",
  "approved",
  "rejected",
  "expired",
  "revoked",
  "withdrawn",
  "reserved",
  "consumed",
]);

export const APPROVAL_STEP_STATUSES = Object.freeze([
  "pending",
  "in_progress",
  "approved",
  "rejected",
  "cancelled",
]);

const ACTION_RISK = Object.freeze({
  "user.enable": "L",
  "credential.rotate": "M",
  "user.policy.quota": "M",
  "user.disable": "H",
  "device.revoke": "H",
  "user.policy.models": "H",
  "usage.export.create": "H",
  "audit.export.create": "H",
  "audit.content.read_request": "C",
  "audit.content.retention.run": "C",
  "audit.content.delete": "C",
  "audit.content.legal_hold.create": "H",
  "audit.content.legal_hold.release": "C",
  "audit.content.export.create": "C",
  "operation.reconcile": "C",
  "gateway.provider.create": "M",
  "gateway.provider.update": "M",
  "gateway.provider.delete": "H",
  "gateway.routing.create": "M",
  "gateway.routing.update": "M",
  "gateway.routing.delete": "M",
  "gateway.key.create": "M",
  "gateway.key.update": "M",
  "gateway.key.policy": "H",
  "gateway.key.rotate": "H",
  "gateway.key.remove": "H",
  // Publishing to every assigned device is an approval, not a fresh
  // sign-in alone: a hook runs on the employee's machine.
  "resource.publish": "M",
  "resource.rollback": "M",
});

const LOW_RISK_ACTIONS = new Set(["user.enable"]);

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

export function sha256Value(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function riskForAction(action) {
  return ACTION_RISK[action] || "";
}

export function approvalRequiredForAction(action) {
  const risk = riskForAction(action);
  if (!risk) throw new Error(`Unknown approval action: ${action}`);
  // A gateway write is a configuration edit, not a user-facing
  // entitlement: medium-risk ones take a fresh sign-in (step-up) alone,
  // and only the destructive ones ask an approver as well.
  if (action.startsWith("gateway.")) return risk === "H";
  return !LOW_RISK_ACTIONS.has(action);
}

function sortedStrings(value) {
  return Array.isArray(value)
    ? [...new Set(value.map(String).filter(Boolean))].sort()
    : [];
}

function sortedLimits(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map((limit) => (limit && typeof limit === "object" && !Array.isArray(limit)
      ? canonicalValue(limit)
      : {}))
    .sort((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
}

export function normalizedApprovalPayload(action, value = {}) {
  if (action === "user.policy.quota") {
    return {
      expectedVersion: Number(value.expectedVersion),
      limits: sortedLimits(value.limits),
    };
  }
  if (action === "user.policy.models") {
    return {
      expectedVersion: Number(value.expectedVersion),
      models: sortedStrings(value.models),
    };
  }
  if (action === "resource.publish" || action === "resource.rollback") {
    return {
      releaseId: String(value.releaseId || ""),
      expectedUpdatedAt: String(value.expectedUpdatedAt || ""),
    };
  }
  if (action === "operation.reconcile") {
    return {
      parentOperationId: String(value.parentOperationId || ""),
      reconciliationAction: String(value.reconciliationAction || ""),
      evidenceRef: String(value.evidenceRef || ""),
    };
  }
  if (action === "usage.export.create" || action === "audit.export.create") {
    return {
      exportType: String(value.exportType || ""),
      orgUnitId: String(value.orgUnitId || ""),
      from: String(value.from || ""),
      to: String(value.to || ""),
      filters: value.filters && typeof value.filters === "object"
        && !Array.isArray(value.filters)
        ? canonicalValue(value.filters)
        : {},
    };
  }
  if (action.startsWith("gateway.")) {
    return {
      expectedRevision: String(value.expectedRevision || ""),
      body: canonicalValue(
        value.body && typeof value.body === "object" && !Array.isArray(value.body)
          ? value.body
          : {},
      ),
    };
  }
  if (isAuditContentAction(action)) {
    return normalizeAuditContentPayload(action, value);
  }
  if ([
    "user.disable",
    "user.enable",
    "device.revoke",
    "credential.rotate",
  ].includes(action)) {
    return {};
  }
  throw new Error(`Unknown approval action: ${action}`);
}

export function approvalPayloadDigest(action, value) {
  return sha256Value(canonicalJson(normalizedApprovalPayload(action, value)));
}

export function approvalBindingDigest(input) {
  return sha256Value(canonicalJson({
    environmentId: String(input.environmentId || ""),
    policyVersion: String(input.policyVersion || ""),
    requesterSubjectId: String(input.requesterSubjectId || ""),
    action: String(input.action || ""),
    targetType: String(input.targetType || ""),
    targetId: String(input.targetId || ""),
    targetOrgUnitId: String(input.targetOrgUnitId || ""),
    riskLevel: String(input.riskLevel || ""),
    reason: String(input.reason || ""),
    payloadDigest: String(input.payloadDigest || ""),
  }));
}

export function approvalIsExpired(approval, now = Date.now()) {
  const expiresAt = Date.parse(approval?.expiresAt || "");
  return !Number.isFinite(expiresAt) || expiresAt <= now;
}

function stringIds(value) {
  return Array.isArray(value)
    ? [...new Set(value.map(String).filter(Boolean))].sort()
    : [];
}

export function ensureApprovalWorkflow(approval) {
  if (!approval || typeof approval !== "object" || Array.isArray(approval)) return approval;
  approval.workflowVersion = Number.isSafeInteger(approval.workflowVersion)
    ? approval.workflowVersion
    : 1;
  approval.workflowKind = ["serial", "parallel"].includes(approval.workflowKind)
    ? approval.workflowKind
    : "serial";
  approval.withdrawnAt = typeof approval.withdrawnAt === "string" ? approval.withdrawnAt : "";
  approval.withdrawnBySubjectId = typeof approval.withdrawnBySubjectId === "string"
    ? approval.withdrawnBySubjectId
    : "";
  if (Array.isArray(approval.steps) && approval.steps.length > 0) {
    const normalizedSteps = approval.steps.map((step, index) => {
      const normalized = step && typeof step === "object" && !Array.isArray(step)
        ? step
        : {};
      const mode = step?.mode === "parallel" ? "parallel" : "serial";
      const requiredApprovers = Number.isSafeInteger(step?.requiredApprovers)
        ? Math.max(1, step.requiredApprovers)
        : 1;
      const quorum = Number.isSafeInteger(step?.quorum)
        ? Math.min(requiredApprovers, Math.max(1, step.quorum))
        : 1;
      normalized.stepId = String(step?.stepId || `stp_${index + 1}`);
      normalized.mode = mode;
      normalized.requiredApprovers = requiredApprovers;
      normalized.quorum = quorum;
      normalized.order = Number.isSafeInteger(step?.order) ? step.order : index + 1;
      normalized.status = APPROVAL_STEP_STATUSES.includes(step?.status)
        ? step.status
        : "pending";
      normalized.eligibleSubjectIds = stringIds(step?.eligibleSubjectIds);
      normalized.eligibleRoles = stringIds(step?.eligibleRoles);
      normalized.ineligibleSubjectIds = stringIds(step?.ineligibleSubjectIds);
      normalized.decidedBySubjectIds = stringIds(step?.decidedBySubjectIds);
      normalized.transferHistory = Array.isArray(step?.transferHistory)
        ? step.transferHistory.map((entry) => ({
          fromSubjectId: String(entry?.fromSubjectId || ""),
          toSubjectId: String(entry?.toSubjectId || ""),
          actorSubjectId: String(entry?.actorSubjectId || ""),
          reason: String(entry?.reason || ""),
          at: String(entry?.at || ""),
        }))
        : [];
      return normalized;
    });
    approval.steps = normalizedSteps.sort((left, right) => left.order - right.order);
    return approval;
  }

  let stepStatus = "in_progress";
  let decidedBySubjectIds = [];
  if (["approved", "reserved", "consumed"].includes(approval.status)) {
    stepStatus = "approved";
    decidedBySubjectIds = stringIds([approval.approvedBySubjectId]);
  } else if (approval.status === "rejected") {
    stepStatus = "rejected";
    decidedBySubjectIds = stringIds([approval.rejectedBySubjectId]);
  } else if (["expired", "revoked", "withdrawn"].includes(approval.status)) {
    stepStatus = "cancelled";
  }
  approval.steps = [{
    stepId: "stp_1",
    mode: "serial",
    requiredApprovers: 1,
    quorum: 1,
    order: 1,
    status: stepStatus,
    eligibleSubjectIds: [],
    eligibleRoles: [],
    ineligibleSubjectIds: [],
    decidedBySubjectIds,
    transferHistory: [],
  }];
  return approval;
}

export function approvalActiveStepIds(approval) {
  ensureApprovalWorkflow(approval);
  return (approval?.steps || [])
    .filter((step) => step.status === "in_progress")
    .map((step) => step.stepId);
}

export function approvalWorkflowFailure(approval) {
  if (!approval) return "approval_invalid";
  ensureApprovalWorkflow(approval);
  if (!Array.isArray(approval.steps) || approval.steps.length === 0) {
    return "approval_invalid";
  }
  for (const step of approval.steps) {
    if (step.status !== "approved") return "approval_incomplete";
    const approvers = [...new Set(step.decidedBySubjectIds)]
      .filter((subjectId) => subjectId && subjectId !== approval.requesterSubjectId);
    if (approvers.length < step.quorum) return "approval_incomplete";
    if (approvers.length !== step.decidedBySubjectIds.length) {
      return "approval_incomplete";
    }
  }
  return "";
}

export function approvalConsumptionFailure(approval, expected, now = Date.now()) {
  if (!approval) return "approval_invalid";
  if (approval.environmentId !== expected.environmentId) return "approval_invalid";
  if (approval.status === "reserved" || approval.status === "consumed") {
    return "approval_consumed";
  }
  if (approval.status === "revoked") return "approval_revoked";
  if (approval.status === "withdrawn") return "approval_withdrawn";
  if (approval.status === "expired" || approvalIsExpired(approval, now)) {
    return "approval_expired";
  }
  if (approval.status !== "approved") return "approval_unavailable";
  const workflowFailure = approvalWorkflowFailure(approval);
  if (workflowFailure) return workflowFailure;
  if (!approval.approvedBySubjectId
      || approval.approvedBySubjectId === approval.requesterSubjectId) {
    return "approval_separation_required";
  }
  if (approval.action !== expected.action
      || approval.targetType !== expected.targetType
      || approval.targetId !== expected.targetId
      || approval.targetOrgUnitId !== expected.targetOrgUnitId
      || approval.requesterSubjectId !== expected.requesterSubjectId
      || approval.riskLevel !== expected.riskLevel) {
    return "approval_target_mismatch";
  }
  if (approval.payloadDigest !== expected.payloadDigest
      || approval.bindingDigest !== expected.bindingDigest
      || approval.policyVersion !== expected.policyVersion) {
    return "approval_payload_mismatch";
  }
  return "";
}

export function publicApproval(approval, decisions = []) {
  ensureApprovalWorkflow(approval);
  return {
    approvalId: String(approval.id || ""),
    status: String(approval.status || "requested"),
    riskLevel: String(approval.riskLevel || ""),
    action: String(approval.action || ""),
    targetType: String(approval.targetType || ""),
    targetId: String(approval.targetId || ""),
    targetOrgUnitId: String(approval.targetOrgUnitId || ""),
    requesterSubjectId: String(approval.requesterSubjectId || ""),
    requesterEmail: String(approval.requesterEmail || ""),
    reason: String(approval.reason || ""),
    payloadDigest: String(approval.payloadDigest || ""),
    bindingDigest: String(approval.bindingDigest || ""),
    policyVersion: String(approval.policyVersion || ""),
    environmentId: String(approval.environmentId || ""),
    payloadSummary: approval.payloadSummary && typeof approval.payloadSummary === "object"
      ? canonicalValue(approval.payloadSummary)
      : {},
    createdAt: String(approval.createdAt || ""),
    updatedAt: String(approval.updatedAt || ""),
    expiresAt: String(approval.expiresAt || ""),
    approvedAt: String(approval.approvedAt || ""),
    approvedBySubjectId: String(approval.approvedBySubjectId || ""),
    approvedByEmail: String(approval.approvedByEmail || ""),
    rejectedBySubjectId: String(approval.rejectedBySubjectId || ""),
    rejectedByEmail: String(approval.rejectedByEmail || ""),
    externalReference: String(approval.externalReference || ""),
    externalEventId: String(approval.externalEventId || ""),
    decisionSource: String(approval.decisionSource || ""),
    rejectedAt: String(approval.rejectedAt || ""),
    revokedAt: String(approval.revokedAt || ""),
    withdrawnAt: String(approval.withdrawnAt || ""),
    withdrawnBySubjectId: String(approval.withdrawnBySubjectId || ""),
    operationId: String(approval.operationId || ""),
    consumedAt: String(approval.consumedAt || ""),
    workflowVersion: Number.isSafeInteger(approval.workflowVersion)
      ? approval.workflowVersion
      : 1,
    workflowKind: String(approval.workflowKind || "serial"),
    activeStepIds: approvalActiveStepIds(approval),
    steps: approval.steps.map((step) => ({
      stepId: String(step.stepId || ""),
      mode: String(step.mode || "serial"),
      requiredApprovers: Number.isSafeInteger(step.requiredApprovers)
        ? step.requiredApprovers
        : 1,
      quorum: Number.isSafeInteger(step.quorum) ? step.quorum : 1,
      order: Number.isSafeInteger(step.order) ? step.order : 1,
      status: String(step.status || "pending"),
      eligibleSubjectIds: stringIds(step.eligibleSubjectIds),
      eligibleRoles: stringIds(step.eligibleRoles),
      ineligibleSubjectIds: stringIds(step.ineligibleSubjectIds),
      decidedBySubjectIds: stringIds(step.decidedBySubjectIds),
      transferHistory: Array.isArray(step.transferHistory)
        ? step.transferHistory.map((entry) => ({
          fromSubjectId: String(entry.fromSubjectId || ""),
          toSubjectId: String(entry.toSubjectId || ""),
          actorSubjectId: String(entry.actorSubjectId || ""),
          reason: String(entry.reason || ""),
          at: String(entry.at || ""),
        }))
        : [],
    })),
    stateHistory: Array.isArray(approval.stateHistory)
      ? approval.stateHistory.map((entry) => ({
        status: String(entry.status || ""),
        at: String(entry.at || ""),
        actorSubjectId: String(entry.actorSubjectId || ""),
        reason: String(entry.reason || ""),
      }))
      : [],
    decisions: decisions.map((decision) => ({
      decisionId: String(decision.id || ""),
      decision: String(decision.decision || ""),
      actorSubjectId: String(decision.actorSubjectId || ""),
      actorEmail: String(decision.actorEmail || ""),
      source: String(decision.source || "admin"),
      eventId: String(decision.eventId || ""),
      externalReference: String(decision.externalReference || ""),
      issuer: String(decision.issuer || ""),
      stepId: String(decision.stepId || ""),
      workflowVersion: Number.isSafeInteger(decision.workflowVersion)
        ? decision.workflowVersion
        : 1,
      reason: String(decision.reason || ""),
      createdAt: String(decision.createdAt || ""),
    })),
  };
}
