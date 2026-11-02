import path from "node:path";

const MIN_SECRET_LENGTH = 32;

function required(env, name) {
  const value = String(env[name] || "").trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function optionalSecret(env, name) {
  const value = String(env[name] || "").trim();
  if (!value) return "";
  if (value.length < MIN_SECRET_LENGTH || value.length > 4096) {
    throw new Error(`${name} must be from ${MIN_SECRET_LENGTH} to 4096 characters`);
  }
  return value;
}

function integer(env, name, fallback, min, max) {
  const raw = env[name] == null || env[name] === "" ? fallback : Number(env[name]);
  if (!Number.isSafeInteger(raw) || raw < min || raw > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return raw;
}

function boolean(env, name, fallback) {
  const raw = String(env[name] ?? fallback).trim().toLowerCase();
  if (raw !== "true" && raw !== "false") {
    throw new Error(`${name} must be true or false`);
  }
  return raw === "true";
}

function contentEncryptionKey(env) {
  const value = required(env, "AUDIT_CONTENT_ENCRYPTION_KEY");
  let key;
  if (/^[a-f0-9]{64}$/i.test(value)) {
    key = Buffer.from(value, "hex");
  } else {
    try {
      key = Buffer.from(value, "base64");
    } catch {
      key = Buffer.alloc(0);
    }
  }
  if (key.length !== 32) {
    throw new Error("AUDIT_CONTENT_ENCRYPTION_KEY must encode exactly 32 bytes as base64 or 64 hex characters");
  }
  return key;
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
  const contentEnabled = boolean(env, "AUDIT_CONTENT_ENABLED", false);
  const contentAdminEnabled = boolean(env, "AUDIT_CONTENT_ADMIN_ENABLED", false);
  if (contentAdminEnabled && !contentEnabled) {
    throw new Error("AUDIT_CONTENT_ADMIN_ENABLED=true requires AUDIT_CONTENT_ENABLED=true");
  }
  if (String(env.AUDIT_CONTENT_READ_TOKEN || "").trim()) {
    throw new Error(
      "AUDIT_CONTENT_READ_TOKEN is retired; content body reads require a one-time content grant",
    );
  }
  const contentEncryptionKeyValue = contentEnabled ? contentEncryptionKey(env) : null;
  const contentAdminToken = contentAdminEnabled
    ? optionalSecret(env, "AUDIT_CONTENT_ADMIN_TOKEN")
    : "";
  if (contentAdminEnabled && !contentAdminToken) {
    throw new Error("AUDIT_CONTENT_ADMIN_TOKEN is required when AUDIT_CONTENT_ADMIN_ENABLED=true");
  }
  const contentGrantSecretValue = contentAdminEnabled
    ? optionalSecret(env, "AUDIT_CONTENT_GRANT_SECRET")
    : "";
  if (contentAdminEnabled && !contentGrantSecretValue) {
    throw new Error("AUDIT_CONTENT_GRANT_SECRET is required when AUDIT_CONTENT_ADMIN_ENABLED=true");
  }
  const contentCursorSecret = contentAdminEnabled
    ? optionalSecret(env, "AUDIT_CONTENT_CURSOR_SECRET")
    : "";
  if (contentAdminEnabled && !contentCursorSecret) {
    throw new Error("AUDIT_CONTENT_CURSOR_SECRET is required when AUDIT_CONTENT_ADMIN_ENABLED=true");
  }
  const contentOrganizationId = contentAdminEnabled
    ? String(env.AUDIT_CONTENT_ORGANIZATION_ID || "").trim()
    : "";
  if (contentAdminEnabled
      && (!contentOrganizationId
        || contentOrganizationId.length > 128
        || !/^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/.test(contentOrganizationId))) {
    throw new Error(
      "AUDIT_CONTENT_ORGANIZATION_ID must be a valid organization id when AUDIT_CONTENT_ADMIN_ENABLED=true",
    );
  }
  const secrets = [
    ["AUDIT_SERVICE_TOKEN", serviceToken],
    ["AUDIT_CONTENT_ADMIN_TOKEN", contentAdminToken],
    ["AUDIT_CONTENT_GRANT_SECRET", contentGrantSecretValue],
    ["AUDIT_CONTENT_CURSOR_SECRET", contentCursorSecret],
  ].filter(([, value]) => value);
  for (let left = 0; left < secrets.length; left += 1) {
    for (let right = left + 1; right < secrets.length; right += 1) {
      if (secrets[left][1] === secrets[right][1]) {
        throw new Error(`${secrets[left][0]} must differ from ${secrets[right][0]}`);
      }
    }
  }
  const contentMaxChunkBytes = integer(
    env,
    "AUDIT_CONTENT_MAX_CHUNK_BYTES",
    256 * 1024,
    1024,
    4 * 1024 * 1024,
  );
  const contentMaxStreamBytes = integer(
    env,
    "AUDIT_CONTENT_MAX_STREAM_BYTES",
    1024 * 1024,
    1024,
    32 * 1024 * 1024,
  );
  if (contentMaxChunkBytes > contentMaxStreamBytes) {
    throw new Error("AUDIT_CONTENT_MAX_CHUNK_BYTES must not exceed AUDIT_CONTENT_MAX_STREAM_BYTES");
  }
  const contentMaxBodyBytes = integer(
    env,
    "AUDIT_CONTENT_MAX_BODY_BYTES",
    384 * 1024,
    1024,
    64 * 1024 * 1024,
  );
  const contentStoreDir = path.resolve(
    String(env.AUDIT_CONTENT_STORE_DIR || "./data/audit-content"),
  );
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
    contentEnabled,
    contentAdminEnabled,
    contentEncryptionKey: contentEncryptionKeyValue,
    contentAdminToken,
    contentGrantSecret: contentGrantSecretValue,
    contentCursorSecret,
    contentOrganizationId,
    contentGrantTtlSeconds: integer(
      env,
      "AUDIT_CONTENT_GRANT_TTL_SECONDS",
      120,
      15,
      300,
    ),
    contentGrantStorePath: path.join(contentStoreDir, "content-grants.json"),
    contentStoreDir,
    contentMaxBodyBytes,
    contentMaxChunkBytes,
    contentMaxStreamBytes,
    contentMaxBufferBytes: integer(
      env,
      "AUDIT_CONTENT_MAX_BUFFER_BYTES",
      64 * 1024 * 1024,
      contentMaxStreamBytes,
      1024 * 1024 * 1024,
    ),
    contentMaxActiveStreams: integer(
      env,
      "AUDIT_CONTENT_MAX_ACTIVE_STREAMS",
      256,
      1,
      100_000,
    ),
    contentStreamTtlMs: integer(
      env,
      "AUDIT_CONTENT_STREAM_TTL_MS",
      15 * 60 * 1000,
      10_000,
      24 * 60 * 60 * 1000,
    ),
  };
}
