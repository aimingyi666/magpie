/**
 * M7 - Quota Control Module for Gateway Content Control
 * 
 * Provides usage quota tracking and enforcement for gateway keys.
 */

const QUOTA_TYPE_TOKENS = "tokens";
const QUOTA_TYPE_COST = "cost";
const QUOTA_PERIOD_DAY = "day";
const QUOTA_PERIOD_WEEK = "week";
const QUOTA_PERIOD_MONTH = "month";
const QUOTA_PERIOD_DAYS = "days";
const QUOTA_PERIOD_HOURS = "hours";
const PERIOD_SET = new Set([QUOTA_PERIOD_DAY, QUOTA_PERIOD_WEEK, QUOTA_PERIOD_MONTH, QUOTA_PERIOD_DAYS, QUOTA_PERIOD_HOURS]);

export class QuotaControlError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export const EMPTY_QUOTA = Object.freeze({
  tokens: 0,
  cost: 0,
  usedTokens: 0,
  usedCost: 0,
  remainingTokens: 0,
  remainingCost: 0,
  period: "",
  limit: 0,
});

export function createQuotaSnapshot(keyId, usageRecords, quotaConfig) {
  if (!keyId || typeof keyId !== "string") {
    throw new QuotaControlError("invalid_key_id", "keyId is required");
  }
  if (!quotaConfig || typeof quotaConfig !== "object") {
    return { keyId, ...EMPTY_QUOTA };
  }
  
  const { period, tokens, cost } = quotaConfig;
  const records = Array.isArray(usageRecords) ? usageRecords : [];
  
  let usedTokens = 0;
  let usedCost = 0;
  
  for (const record of records) {
    if (!record || typeof record !== "object") continue;
    const tokensUsed = Number(record.tokens || record.inputTokens + record.outputTokens);
    const costUsed = Number(record.cost || record.costUsd || 0);
    if (Number.isFinite(tokensUsed)) usedTokens += tokensUsed;
    if (Number.isFinite(costUsed)) usedCost += costUsed;
  }
  
  return {
    keyId,
    period,
    limit: tokens || cost || 0,
    usedTokens,
    usedCost: Math.round(usedCost * 10000) / 10000,
    remainingTokens: Math.max(0, tokens - usedTokens),
    remainingCost: Math.max(0, cost - usedCost),
  };
}

export function checkQuotaRemaining(snapshot) {
  if (!snapshot || snapshot.limit === 0) return { exceeded: false, reason: "" };
  
  if (snapshot.tokens > 0 && snapshot.usedTokens >= snapshot.tokens) {
    return { exceeded: true, reason: "token_limit_exceeded" };
  }
  if (snapshot.cost > 0 && snapshot.usedCost >= snapshot.cost) {
    return { exceeded: true, reason: "cost_limit_exceeded" };
  }
  return { exceeded: false, reason: "" };
}

export function addQuotaUsage(snapshot, tokens, cost) {
  if (!snapshot) throw new QuotaControlError("invalid_snapshot", "snapshot is required");
  const snapshotTokens = Number(tokens || 0);
  const snapshotCost = Number(cost || 0);
  return {
    ...snapshot,
    usedTokens: snapshot.usedTokens + (Number.isFinite(snapshotTokens) ? snapshotTokens : 0),
    usedCost: Math.round((snapshot.usedCost + (Number.isFinite(snapshotCost) ? snapshotCost : 0)) * 10000) / 10000,
    remainingTokens: Math.max(0, snapshot.tokens - snapshot.usedTokens - snapshotTokens),
    remainingCost: Math.max(0, snapshot.cost - snapshot.usedCost - snapshotCost),
  };
}

export function resetQuotaWindow(snapshot, period) {
  if (!snapshot) return null;
  const newSnapshot = { ...snapshot, usedTokens: 0, usedCost: 0 };
  if (period && PERIOD_SET.has(period)) {
    newSnapshot.period = period;
  }
  newSnapshot.remainingTokens = snapshot.tokens;
  newSnapshot.remainingCost = snapshot.cost;
  return newSnapshot;
}

export { QUOTA_TYPE_TOKENS, QUOTA_TYPE_COST, QUOTA_PERIOD_DAY, QUOTA_PERIOD_WEEK, QUOTA_PERIOD_MONTH, QUOTA_PERIOD_DAYS, QUOTA_PERIOD_HOURS, PERIOD_SET };
