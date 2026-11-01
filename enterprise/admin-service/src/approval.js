import crypto from "node:crypto";

export const APPROVAL_POLICY_VERSION = "APR-01a-v1";

export const RISK_LEVELS = Object.freeze(["L", "M", "H", "C"]);

export const APPROVAL_STATUSES = Object.freeze([
  "requested",
  "pending_approval",
  "approved",
  "rejected",
  "expired",
  "revoked",
  "reserved",
  "consumed",
]);

const ACTION_RISK = Object.freeze({
  "user.enable": "L",
  "credential.rotate": "M",
  "user.policy.quota": "M",
  "user.disable": "H",
  "device.revoke": "H",
  "user.policy.models": "H",
  "operation.reconcile": "C",
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
  if (action === "operation.reconcile") {
    return {
      parentOperationId: String(value.parentOperationId || ""),
      reconciliationAction: String(value.reconciliationAction || ""),
      evidenceRef: String(value.evidenceRef || ""),
    };
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

export function approvalConsumptionFailure(approval, expected, now = Date.now()) {
  if (!approval) return "approval_invalid";
  if (approval.environmentId !== expected.environmentId) return "approval_invalid";
  if (approval.status === "reserved" || approval.status === "consumed") {
    return "approval_consumed";
  }
  if (approval.status === "revoked") return "approval_revoked";
  if (approval.status === "expired" || approvalIsExpired(approval, now)) {
    return "approval_expired";
  }
  if (approval.status !== "approved") return "approval_unavailable";
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
    rejectedAt: String(approval.rejectedAt || ""),
    revokedAt: String(approval.revokedAt || ""),
    operationId: String(approval.operationId || ""),
    consumedAt: String(approval.consumedAt || ""),
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
      reason: String(decision.reason || ""),
      createdAt: String(decision.createdAt || ""),
    })),
  };
}
