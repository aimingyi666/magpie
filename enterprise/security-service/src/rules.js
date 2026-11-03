export const DETECTION_RULE_CATALOG = Object.freeze([
  Object.freeze({
    ruleId: "sec.client.direct_bypass",
    ruleVersion: 1,
    ruleKind: "client.direct_bypass",
    defaultSeverity: "critical",
    title: "Agent traffic bypasses the enterprise gateway",
  }),
  Object.freeze({
    ruleId: "sec.content.sensitive",
    ruleVersion: 1,
    ruleKind: "content.sensitive_pattern",
    defaultSeverity: "high",
    title: "Sensitive data categories were detected",
  }),
  Object.freeze({
    ruleId: "sec.device.noncompliant",
    ruleVersion: 1,
    ruleKind: "device.noncompliant",
    defaultSeverity: "high",
    title: "A noncompliant device is used",
  }),
  Object.freeze({
    ruleId: "sec.authorization.scope_violation",
    ruleVersion: 1,
    ruleKind: "authorization.scope_violation",
    defaultSeverity: "high",
    title: "A request exceeded an authorized scope",
  }),
  Object.freeze({
    ruleId: "sec.source.untrusted_ip",
    ruleVersion: 1,
    ruleKind: "source.untrusted_ip",
    defaultSeverity: "high",
    title: "A request came from an untrusted source address",
  }),
  Object.freeze({
    ruleId: "sec.source.untrusted_region",
    ruleVersion: 1,
    ruleKind: "source.untrusted_region",
    defaultSeverity: "high",
    title: "A request came from an untrusted region",
  }),
  Object.freeze({
    ruleId: "sec.usage.anomaly",
    ruleVersion: 1,
    ruleKind: "usage.anomaly",
    defaultSeverity: "high",
    title: "Token or cost usage is anomalous against the baseline",
  }),
  Object.freeze({
    ruleId: "sec.usage.budget_threshold",
    ruleVersion: 1,
    ruleKind: "usage.budget_threshold",
    defaultSeverity: "warning",
    title: "A usage budget crossed a warning or critical threshold",
  }),
]);

function finiteNumber(value, name, minimum, maximum) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < minimum || number > maximum) {
    throw new Error(`${name} must be a number from ${minimum} to ${maximum}`);
  }
  return number;
}

function positiveInteger(value, name, maximum) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1 || number > maximum) {
    throw new Error(`${name} must be an integer from 1 to ${maximum}`);
  }
  return number;
}

function nonNegativeInteger(value, name, maximum) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0 || number > maximum) {
    throw new Error(`${name} must be an integer from 0 to ${maximum}`);
  }
  return number;
}

function stringList(value, name) {
  if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
  const result = [...new Set(value.map((item) => String(item).trim()).filter(Boolean))].sort();
  return result;
}

function freeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const item of Object.values(value)) freeze(item);
  return Object.freeze(value);
}

export function createDetectionPolicy(config = {}) {
  const warningRatio = finiteNumber(
    config.budgetWarningRatio ?? 0.9,
    "budgetWarningRatio",
    0.01,
    1,
  );
  const criticalRatio = finiteNumber(
    config.budgetCriticalRatio ?? 1,
    "budgetCriticalRatio",
    warningRatio,
    100,
  );
  return freeze({
    suppressionWindowSeconds: nonNegativeInteger(
      config.suppressionWindowSeconds ?? 300,
      "suppressionWindowSeconds",
      86_400,
    ),
    usageAnomaly: {
      tokenMultiplier: finiteNumber(
        config.usageTokenMultiplier ?? 5,
        "usageTokenMultiplier",
        1.01,
        10_000,
      ),
      costMultiplier: finiteNumber(
        config.usageCostMultiplier ?? 5,
        "usageCostMultiplier",
        1.01,
        10_000,
      ),
      minimumTokens: positiveInteger(
        config.usageMinimumTokens ?? 100_000,
        "usageMinimumTokens",
        1_000_000_000_000,
      ),
      minimumCost: finiteNumber(
        config.usageMinimumCost ?? 10,
        "usageMinimumCost",
        0.01,
        1_000_000_000,
      ),
    },
    budget: {
      warningRatio,
      criticalRatio,
    },
    trustedRegions: stringList(config.trustedRegions ?? [], "trustedRegions"),
    trustedSourceIpHashes: stringList(
      config.trustedSourceIpHashes ?? [],
      "trustedSourceIpHashes",
    ),
  });
}

export function ruleIsConfigured(rule, policy) {
  if (rule.ruleKind === "source.untrusted_region") return policy.trustedRegions.length > 0;
  if (rule.ruleKind === "source.untrusted_ip") {
    return policy.trustedSourceIpHashes.length > 0;
  }
  return true;
}

export function describeRules(policy) {
  return DETECTION_RULE_CATALOG.map((rule) => ({
    ...rule,
    enabled: ruleIsConfigured(rule, policy),
  }));
}
