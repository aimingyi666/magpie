import crypto from "node:crypto";

import { canonicalJson } from "./events.js";
import {
  DETECTION_RULE_CATALOG,
  ruleIsConfigured,
} from "./rules.js";

const CRITICAL_CONTENT_CATEGORIES = new Set([
  "api_key",
  "bearer_token",
  "cloud_access_key",
  "credential",
  "password",
  "private_key",
]);

function digest(prefix, value) {
  return `${prefix}_${crypto.createHash("sha256").update(value).digest("hex").slice(0, 24)}`;
}

function findingId(event, rule) {
  return digest(
    "sdf",
    `${event.eventId}\u0000${rule.ruleId}\u0000${rule.ruleVersion}`,
  );
}

function stableFindingScope(event, rule, discriminator) {
  return digest(
    "sdk",
    [
      rule.ruleId,
      rule.ruleVersion,
      event.organizationId,
      event.subject.type,
      event.subject.id,
      discriminator,
    ].join("\u0000"),
  );
}

function aggregateId(dedupeKey) {
  return `sag_${dedupeKey.slice(4)}`;
}

function createFinding(rule, event, severity, evidence, discriminator, evaluatedAt) {
  const dedupeKey = stableFindingScope(event, rule, discriminator);
  return {
    findingId: findingId(event, rule),
    eventId: event.eventId,
    ruleId: rule.ruleId,
    ruleVersion: rule.ruleVersion,
    ruleKind: rule.ruleKind,
    severity,
    organizationId: event.organizationId,
    subject: { ...event.subject },
    requestId: event.requestId || "",
    sessionId: event.sessionId || "",
    detectedAt: event.occurredAt,
    evaluatedAt,
    evidence,
    dedupeKey,
    aggregateId: aggregateId(dedupeKey),
    suppressed: false,
    suppressionUntil: "",
  };
}

function usageAnomalyFinding(rule, event, policy, evaluatedAt) {
  const usage = event.usage;
  if (!usage) return null;
  const triggeredBy = [];
  const evidence = {};
  const tokenThreshold = policy.usageAnomaly.minimumTokens;
  const costThreshold = policy.usageAnomaly.minimumCost;

  if (Number.isFinite(usage.totalTokens)
      && Number.isFinite(usage.baselineTokens)
      && usage.baselineTokens > 0) {
    const multiplier = usage.totalTokens / usage.baselineTokens;
    if (usage.totalTokens >= tokenThreshold
        && multiplier >= policy.usageAnomaly.tokenMultiplier) {
      triggeredBy.push("tokens");
      evidence.totalTokens = usage.totalTokens;
      evidence.baselineTokens = usage.baselineTokens;
      evidence.tokenMultiplier = multiplier;
      evidence.tokenThreshold = policy.usageAnomaly.tokenMultiplier;
      evidence.minimumTokens = tokenThreshold;
    }
  }

  if (Number.isFinite(usage.cost)
      && Number.isFinite(usage.baselineCost)
      && usage.baselineCost > 0) {
    const multiplier = usage.cost / usage.baselineCost;
    if (usage.cost >= costThreshold
        && multiplier >= policy.usageAnomaly.costMultiplier) {
      triggeredBy.push("cost");
      evidence.cost = usage.cost;
      evidence.baselineCost = usage.baselineCost;
      evidence.costMultiplier = multiplier;
      evidence.costThreshold = policy.usageAnomaly.costMultiplier;
      evidence.minimumCost = costThreshold;
    }
  }

  if (triggeredBy.length === 0) return null;
  evidence.triggeredBy = triggeredBy;
  return createFinding(rule, event, "high", evidence, "usage", evaluatedAt);
}

function budgetThresholdFinding(rule, event, policy, evaluatedAt) {
  const usage = event.usage;
  if (!usage
      || !Number.isFinite(usage.budgetLimit)
      || !Number.isFinite(usage.budgetUsed)) {
    return null;
  }
  const ratio = usage.budgetUsed / usage.budgetLimit;
  if (ratio < policy.budget.warningRatio) return null;
  const severity = ratio >= policy.budget.criticalRatio ? "critical" : "warning";
  return createFinding(rule, event, severity, {
    budgetLimit: usage.budgetLimit,
    budgetUsed: usage.budgetUsed,
    ratio,
    warningRatio: policy.budget.warningRatio,
    criticalRatio: policy.budget.criticalRatio,
  }, "budget", evaluatedAt);
}

function untrustedRegionFinding(rule, event, policy, evaluatedAt) {
  const region = event.source?.region;
  if (!region || policy.trustedRegions.length === 0) return null;
  if (policy.trustedRegions.includes(region)) return null;
  return createFinding(rule, event, "high", {
    region,
    trustedRegionCount: policy.trustedRegions.length,
  }, "region", evaluatedAt);
}

function untrustedIpFinding(rule, event, policy, evaluatedAt) {
  const ipHash = event.source?.ipHash;
  if (!ipHash || policy.trustedSourceIpHashes.length === 0) return null;
  if (policy.trustedSourceIpHashes.includes(ipHash)) return null;
  return createFinding(rule, event, "high", {
    ipHash,
    trustedAddressCount: policy.trustedSourceIpHashes.length,
  }, "ip", evaluatedAt);
}

function scopeViolationFinding(rule, event, _policy, evaluatedAt) {
  if (event.authorization?.decision !== "denied") return null;
  return createFinding(rule, event, "high", {
    decision: "denied",
    dimension: event.authorization.dimension,
    policyId: event.authorization.policyId || "",
  }, `authorization:${event.authorization.dimension}`, evaluatedAt);
}

function directBypassFinding(rule, event, _policy, evaluatedAt) {
  const connection = event.connection;
  if (!connection) return null;
  if (connection.route === "enterprise_gateway" && connection.managedAgent) return null;
  return createFinding(rule, event, "critical", {
    route: connection.route,
    managedAgent: connection.managedAgent,
  }, "connection", evaluatedAt);
}

function deviceNoncomplianceFinding(rule, event, _policy, evaluatedAt) {
  if (event.device?.complianceState !== "noncompliant") return null;
  return createFinding(rule, event, "high", {
    complianceState: "noncompliant",
    reasonCodes: [...event.device.reasonCodes],
  }, "device", evaluatedAt);
}

function sensitiveContentFinding(rule, event, _policy, evaluatedAt) {
  const content = event.content;
  if (!content || content.sensitiveCategories.length === 0) return null;
  const critical = content.sensitiveCategories.some(
    (category) => CRITICAL_CONTENT_CATEGORIES.has(category),
  );
  return createFinding(rule, event, critical ? "critical" : "high", {
    sensitiveCategories: [...content.sensitiveCategories],
    matchCount: content.matchCount,
  }, `content:${content.sensitiveCategories.join(",")}`, evaluatedAt);
}

const EVALUATORS = new Map([
  ["sec.client.direct_bypass", directBypassFinding],
  ["sec.content.sensitive", sensitiveContentFinding],
  ["sec.device.noncompliant", deviceNoncomplianceFinding],
  ["sec.authorization.scope_violation", scopeViolationFinding],
  ["sec.source.untrusted_ip", untrustedIpFinding],
  ["sec.source.untrusted_region", untrustedRegionFinding],
  ["sec.usage.anomaly", usageAnomalyFinding],
  ["sec.usage.budget_threshold", budgetThresholdFinding],
]);

export function evaluateDetectionEvent(event, policy, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  if (!Number.isFinite(now.getTime())) throw new Error("evaluation time is invalid");
  const evaluatedAt = now.toISOString();
  const findings = [];
  for (const rule of DETECTION_RULE_CATALOG) {
    if (!ruleIsConfigured(rule, policy)) continue;
    const evaluator = EVALUATORS.get(rule.ruleId);
    if (!evaluator) throw new Error(`no evaluator for rule ${rule.ruleId}`);
    const finding = evaluator(rule, event, policy, evaluatedAt);
    if (finding) findings.push(finding);
  }
  findings.sort((left, right) => left.ruleId.localeCompare(right.ruleId));
  return findings;
}

export function findingFingerprint(finding) {
  return crypto.createHash("sha256").update(canonicalJson(finding)).digest("hex");
}
