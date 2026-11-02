import path from "node:path";

const MIN_SECRET_LENGTH = 32;

function required(env, name) {
  const value = String(env[name] || "").trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function integer(env, name, fallback, min, max) {
  const raw = env[name] == null || env[name] === "" ? fallback : Number(env[name]);
  if (!Number.isSafeInteger(raw) || raw < min || raw > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return raw;
}

function bindAddress(env) {
  const value = String(env.AUDIT_BIND || "0.0.0.0").trim();
  if (!value
      || value.length > 255
      || !/^[A-Za-z0-9.:[\]_-]+$/.test(value)) {
    throw new Error("AUDIT_BIND must be a valid host name or IP address");
  }
  return value;
}

export function loadConfig(env = process.env) {
  const serviceToken = required(env, "AUDIT_SERVICE_TOKEN");
  if (serviceToken.length < MIN_SECRET_LENGTH) {
    throw new Error(`AUDIT_SERVICE_TOKEN must be at least ${MIN_SECRET_LENGTH} characters`);
  }
  return {
    bind: bindAddress(env),
    port: integer(env, "AUDIT_PORT", 3449, 1, 65535),
    serviceToken,
    storePath: path.resolve(String(env.AUDIT_STORE_PATH || "./data/audit-store.json")),
    maxBodyBytes: integer(env, "AUDIT_MAX_BODY_BYTES", 32 * 1024, 4096, 128 * 1024),
    maxEvents: integer(env, "AUDIT_MAX_EVENTS", 1_000_000, 1, 10_000_000),
    maxQueueEvents: integer(env, "AUDIT_MAX_QUEUE_EVENTS", 100_000, 1, 1_000_000),
    maxSessions: integer(env, "AUDIT_MAX_SESSIONS", 100_000, 1, 1_000_000),
    flushIntervalMs: integer(env, "AUDIT_FLUSH_INTERVAL_MS", 1000, 100, 60_000),
    batchSize: integer(env, "AUDIT_BATCH_SIZE", 200, 1, 5000),
    rateLimitPerMinute: integer(env, "AUDIT_RATE_LIMIT_PER_MINUTE", 6000, 10, 1_000_000),
  };
}
