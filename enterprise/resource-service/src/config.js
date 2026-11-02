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

function keyId(value) {
  const normalized = String(value || "").trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$/.test(normalized)) {
    throw new Error("RESOURCE_SIGNING_KEY_ID must be 1-100 safe identifier characters");
  }
  return normalized;
}

export function loadConfig(env = process.env) {
  const serviceToken = required(env, "RESOURCE_SERVICE_TOKEN");
  if (serviceToken.length < MIN_SECRET_LENGTH) {
    throw new Error(`RESOURCE_SERVICE_TOKEN must be at least ${MIN_SECRET_LENGTH} characters`);
  }
  const maxContentBytes = integer(env, "RESOURCE_MAX_CONTENT_BYTES", 1024 * 1024, 1024, 16 * 1024 * 1024);
  const maxResources = integer(env, "RESOURCE_MAX_RESOURCES", 1000, 1, 100000);
  const maxReleasesPerResource = integer(env, "RESOURCE_MAX_RELEASES_PER_RESOURCE", 200, 1, 10000);
  return {
    bind: String(env.RESOURCE_BIND || "0.0.0.0").trim(),
    port: integer(env, "RESOURCE_PORT", 3447, 1, 65535),
    serviceToken,
    storePath: path.resolve(String(env.RESOURCE_STORE_PATH || "./data/resource-store.json")),
    contentPath: path.resolve(String(env.RESOURCE_CONTENT_PATH || "./data/objects")),
    signingPrivateKeyPath: path.resolve(required(env, "RESOURCE_SIGNING_PRIVATE_KEY_PATH")),
    signingKeyId: keyId(required(env, "RESOURCE_SIGNING_KEY_ID")),
    maxContentBytes,
    maxBodyBytes: 2 * maxContentBytes + 64 * 1024,
    maxResources,
    maxReleasesPerResource,
    rateLimitPerMinute: integer(env, "RESOURCE_RATE_LIMIT_PER_MINUTE", 600, 10, 100000),
  };
}
