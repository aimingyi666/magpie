/**
 * Employee Portal - Usage Statistics Module
 * Aggregates usage data from the usage log and optional upstream service.
 */

export class UsageError extends Error {
  constructor(message = "usage error", options = {}) {
    super(message);
    this.name = "UsageError";
    this.statusCode = options.statusCode || 500;
    this.code = options.code || "usage_error";
  }
}

export async function getPersonalUsage(store, userId, orgUnit, options = {}) {
  const data = await store.read();
  const log = data.usageLog || [];
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const monthStart = new Date(today.getFullYear(), today.getMonth(), 1);

  const userLogs = log.filter(
    (e) => e.userId === userId && (!orgUnit || e.orgUnit === orgUnit)
  );

  const summarize = (fromDate) =>
    userLogs
      .filter((e) => new Date(e.timestamp) >= fromDate)
      .reduce(
        (acc, e) => {
          acc.tokens += Number(e.tokens || 0);
          acc.costUsd += Number(e.costUsd || 0);
          acc.requests += 1;
          if (e.modelId) acc.models[e.modelId] = (acc.models[e.modelId] || 0) + 1;
          return acc;
        },
        { tokens: 0, costUsd: 0, requests: 0, models: {} }
      );

  return {
    today: summarize(today),
    thisMonth: summarize(monthStart),
  };
}

export async function fetchUpstreamUsage(config, userId, orgUnit) {
  if (!config.usageServiceUrl) {
    throw new UsageError("Usage service not configured", { statusCode: 503, code: "usage_service_unavailable" });
  }
  const url = new URL("/api/v1/usage/personal", config.usageServiceUrl);
  url.searchParams.set("userId", userId);
  if (orgUnit) url.searchParams.set("orgUnit", orgUnit);
  const headers = {};
  if (config.usageServiceToken) {
    headers["authorization"] = `Bearer ${config.usageServiceToken}`;
  }
  const resp = await fetch(url.toString(), { headers });
  if (!resp.ok) {
    throw new UsageError(`Usage service returned ${resp.status}`, {
      statusCode: resp.status,
      code: "usage_fetch_failed",
    });
  }
  return resp.json();
}
