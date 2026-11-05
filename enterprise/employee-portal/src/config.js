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

function optionalSecret(env, name) {
  const value = String(env[name] || "").trim();
  if (!value) return "";
  if (value.length < MIN_SECRET_LENGTH) {
    throw new Error(`${name} must be at least ${MIN_SECRET_LENGTH} characters when set`);
  }
  return value;
}

export function loadConfig(env = process.env) {
  const serviceToken = required(env, "EMPLOYEE_PORTAL_SERVICE_TOKEN");
  if (serviceToken.length < MIN_SECRET_LENGTH) {
    throw new Error(`EMPLOYEE_PORTAL_SERVICE_TOKEN must be at least ${MIN_SECRET_LENGTH} characters`);
  }

  return {
    bind: String(env.EMPLOYEE_PORTAL_BIND || "0.0.0.0").trim(),
    port: integer(env, "EMPLOYEE_PORTAL_PORT", 3007, 1, 65535),
    publicUrl: String(env.EMPLOYEE_PORTAL_PUBLIC_URL || "").trim().replace(/\/+$/, ""),
    serviceToken,
    storePath: path.resolve(String(env.EMPLOYEE_PORTAL_STORE_PATH || "./data/employee-portal.json")),
    adminServiceUrl: String(env.ADMIN_SERVICE_URL || "").trim(),
    adminServiceToken: optionalSecret(env, "ADMIN_SERVICE_TOKEN"),
    modelCatalogUrl: String(env.ADMIN_MODEL_CATALOG_URL || "").trim(),
    usageStorePath: path.resolve(String(env.EMPLOYEE_PORTAL_USAGE_STORE_PATH || "./data/usage.json")),
    ticketStorePath: path.resolve(String(env.EMPLOYEE_PORTAL_TICKET_STORE_PATH || "./data/tickets.json")),
    rateLimitPerMinute: integer(env, "EMPLOYEE_PORTAL_RATE_LIMIT_PER_MINUTE", 600, 10, 100000),
    sessionTtlMs: integer(env, "EMPLOYEE_PORTAL_SESSION_TTL_MS", 30 * 60 * 1000, 60000, 24 * 60 * 60 * 1000),
  };
}
