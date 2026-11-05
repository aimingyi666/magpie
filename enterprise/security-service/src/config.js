import path from "node:path";

const MIN_SECRET_LENGTH = 32;
const SAFE_CODE_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const SOURCE_IP_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;

function required(env, name) {
  const value = String(env[name] || "").trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function secret(env, name) {
  const value = required(env, name);
  if (value.length < MIN_SECRET_LENGTH) {
    throw new Error(`${name} must be at least ${MIN_SECRET_LENGTH} characters`);
  }
  return value;
}

function integer(env, name, fallback, minimum, maximum) {
  const value = env[name] == null || env[name] === "" ? fallback : Number(env[name]);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return value;
}

function number(env, name, fallback, minimum, maximum) {
  const value = env[name] == null || env[name] === "" ? fallback : Number(env[name]);
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be a number from ${minimum} to ${maximum}`);
  }
  return value;
}

function list(env, name) {
  return [...new Set(String(env[name] || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean))].sort();
}

function safeCodes(env, name) {
  const values = list(env, name);
  for (const value of values) {
    if (!SAFE_CODE_PATTERN.test(value)) throw new Error(`${name} contains an invalid value`);
  }
  return values;
}

function sourceHashes(env, name) {
  const values = list(env, name);
  for (const value of values) {
    if (!SOURCE_IP_HASH_PATTERN.test(value)) throw new Error(`${name} contains an invalid hash`);
  }
  return values;
}

export function loadConfig(env = process.env) {
  const ingestToken = secret(env, "SECURITY_INGEST_TOKEN");
  const readToken = secret(env, "SECURITY_READ_TOKEN");
  const controlToken = secret(env, "SECURITY_CONTROL_TOKEN");
  if (new Set([ingestToken, readToken, controlToken]).size !== 3) {
    throw new Error(
      "SECURITY_INGEST_TOKEN, SECURITY_READ_TOKEN and SECURITY_CONTROL_TOKEN must differ",
    );
  }
  const budgetWarningRatio = number(env, "SECURITY_BUDGET_WARNING_RATIO", 0.9, 0.01, 1);
  const budgetCriticalRatio = number(
    env,
    "SECURITY_BUDGET_CRITICAL_RATIO",
    1,
    budgetWarningRatio,
    100,
  );
  return {
    bind: String(env.SECURITY_BIND || "127.0.0.1").trim(),
    port: integer(env, "SECURITY_PORT", 3450, 1, 65535),
    ingestToken,
    readToken,
    controlToken,
    storePath: path.resolve(String(env.SECURITY_STORE_PATH || "security-store.json").trim()),
    maxBodyBytes: integer(env, "SECURITY_MAX_BODY_BYTES", 65_536, 1_024, 1_048_576),
    maxEvents: integer(env, "SECURITY_MAX_EVENTS", 1_000_000, 1, 10_000_000),
    maxFindings: integer(env, "SECURITY_MAX_FINDINGS", 2_000_000, 1, 20_000_000),
    maxResponseActions: integer(
      env,
      "SECURITY_MAX_RESPONSE_ACTIONS",
      200_000,
      1,
      2_000_000,
    ),
    maxAlerts: integer(
      env,
      "SECURITY_MAX_ALERTS",
      200_000,
      1,
      2_000_000,
    ),
    maxStoreBytes: integer(
      env,
      "SECURITY_MAX_STORE_BYTES",
      536_870_912,
      1_048_576,
      4_294_967_296,
    ),
    rateLimitPerMinute: integer(
      env,
      "SECURITY_RATE_LIMIT_PER_MINUTE",
      6_000,
      1,
      1_000_000,
    ),
    policy: {
      suppressionWindowSeconds: integer(
        env,
        "SECURITY_SUPPRESSION_SECONDS",
        300,
        0,
        86_400,
      ),
      usageTokenMultiplier: number(env, "SECURITY_USAGE_TOKEN_MULTIPLIER", 5, 1.01, 10_000),
      usageCostMultiplier: number(env, "SECURITY_USAGE_COST_MULTIPLIER", 5, 1.01, 10_000),
      usageMinimumTokens: integer(
        env,
        "SECURITY_USAGE_MINIMUM_TOKENS",
        100_000,
        1,
        1_000_000_000_000,
      ),
      usageMinimumCost: number(env, "SECURITY_USAGE_MINIMUM_COST", 10, 0.01, 1_000_000_000),
      budgetWarningRatio,
      budgetCriticalRatio,
      trustedRegions: safeCodes(env, "SECURITY_TRUSTED_REGIONS"),
      trustedSourceIpHashes: sourceHashes(env, "SECURITY_TRUSTED_SOURCE_IP_HASHES"),
    },
  };
}
