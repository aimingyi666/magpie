import fs from "node:fs";
import path from "node:path";

const MIN_SECRET_LENGTH = 32;

function required(env, name) {
  const value = String(env[name] || "").trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function integer(env, name, fallback, min, max) {
  const value = env[name] == null || env[name] === "" ? fallback : Number(env[name]);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function bool(env, name, fallback) {
  const value = env[name];
  if (value == null || value === "") return fallback;
  if (/^(1|true|yes)$/i.test(value)) return true;
  if (/^(0|false|no)$/i.test(value)) return false;
  throw new Error(`${name} must be true or false`);
}

function list(env, name) {
  return [...new Set(String(env[name] || "")
    .split(",")
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean))];
}

function optionalSecret(env, name) {
  const value = String(env[name] || "").trim();
  if (!value) return "";
  if (value.length < MIN_SECRET_LENGTH) {
    throw new Error(`${name} must be at least ${MIN_SECRET_LENGTH} characters when set`);
  }
  return value;
}

function readCa(file) {
  if (!file) return undefined;
  try {
    return fs.readFileSync(file);
  } catch {
    throw new Error("MCP_UPSTREAM_CA_PATH must point to a readable PEM file");
  }
}

export function loadConfig(env = process.env) {
  const serviceToken = required(env, "MCP_SERVICE_TOKEN");
  if (serviceToken.length < MIN_SECRET_LENGTH) {
    throw new Error(`MCP_SERVICE_TOKEN must be at least ${MIN_SECRET_LENGTH} characters`);
  }
  const approvalSecret = optionalSecret(env, "MCP_APPROVAL_HMAC_SECRET");
  const caPath = String(env.MCP_UPSTREAM_CA_PATH || "").trim()
    ? path.resolve(String(env.MCP_UPSTREAM_CA_PATH).trim())
    : "";

  return {
    bind: String(env.MCP_BIND || "0.0.0.0").trim(),
    port: integer(env, "MCP_PORT", 3448, 1, 65535),
    publicUrl: String(env.MCP_PUBLIC_URL || "").trim().replace(/\/+$/, ""),
    serviceToken,
    storePath: path.resolve(String(env.MCP_STORE_PATH || "./data/mcp-registry.json")),
    auditPath: path.resolve(String(env.MCP_AUDIT_PATH || "./data/mcp-audit.jsonl")),
    maxBodyBytes: integer(env, "MCP_MAX_BODY_BYTES", 256 * 1024, 1024, 4 * 1024 * 1024),
    maxServers: integer(env, "MCP_MAX_SERVERS", 500, 1, 10000),
    maxClients: integer(env, "MCP_MAX_CLIENTS", 10000, 1, 1000000),
    maxToolsPerServer: integer(env, "MCP_MAX_TOOLS_PER_SERVER", 500, 1, 5000),
    catalogTtlMs: integer(env, "MCP_CATALOG_TTL_MS", 60000, 1000, 3600000),
    upstreamTimeoutMs: integer(env, "MCP_UPSTREAM_TIMEOUT_MS", 10000, 500, 120000),
    upstreamMaxResponseBytes: integer(
      env,
      "MCP_UPSTREAM_MAX_RESPONSE_BYTES",
      1024 * 1024,
      1024,
      16 * 1024 * 1024,
    ),
    healthIntervalMs: integer(env, "MCP_HEALTH_INTERVAL_MS", 30000, 1000, 3600000),
    healthTimeoutMs: integer(env, "MCP_HEALTH_TIMEOUT_MS", 5000, 500, 60000),
    breakerFailureThreshold: integer(env, "MCP_BREAKER_FAILURE_THRESHOLD", 3, 1, 100),
    breakerCooldownMs: integer(env, "MCP_BREAKER_COOLDOWN_MS", 30000, 1000, 3600000),
    rateLimitPerMinute: integer(env, "MCP_RATE_LIMIT_PER_MINUTE", 600, 10, 100000),
    authRateLimitPerMinute: integer(env, "MCP_AUTH_RATE_LIMIT_PER_MINUTE", 60, 5, 10000),
    clientTokenTtlMs: integer(env, "MCP_CLIENT_TOKEN_TTL_DAYS", 30, 1, 365) * 86400000,
    allowedOrigins: list(env, "MCP_ALLOWED_ORIGINS"),
    upstreamAllowedHosts: list(env, "MCP_UPSTREAM_ALLOWED_HOSTS"),
    allowHttpUpstreams: bool(env, "MCP_ALLOW_HTTP_UPSTREAMS", false),
    allowPrivateUpstreams: bool(env, "MCP_ALLOW_PRIVATE_UPSTREAMS", false),
    upstreamCa: readCa(caPath),
    upstreamCaPath: caPath,
    protocolVersion: String(env.MCP_PROTOCOL_VERSION || "2025-06-18").trim(),
    approvalHmacSecret: approvalSecret,
    approvalMaxTtlSeconds: integer(env, "MCP_APPROVAL_MAX_TTL_SECONDS", 900, 30, 3600),
    secretEnv: { ...env },
  };
}
