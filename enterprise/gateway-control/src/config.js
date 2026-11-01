import fs from "node:fs";
import path from "node:path";

const MIN_SECRET_LENGTH = 32;
const MAX_TIMEOUT_MS = 30000;

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

function integer(env, name, fallback, min, max) {
  const value = env[name] == null || env[name] === "" ? fallback : Number(env[name]);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function absoluteEntry(env, name, wantDirectory) {
  const raw = required(env, name);
  if (!path.isAbsolute(raw)) {
    throw new Error(`${name} must be an absolute path`);
  }
  const resolved = path.resolve(raw);
  let stat;
  try {
    stat = fs.statSync(resolved);
  } catch {
    throw new Error(`${name} does not exist`);
  }
  if (wantDirectory ? !stat.isDirectory() : !stat.isFile()) {
    throw new Error(`${name} must name a ${wantDirectory ? "directory" : "file"}`);
  }
  return resolved;
}

function rejectReusedToken(env, token) {
  const forbidden = [
    "AUTH_COOKIE_SECRET",
    "AUTH_ADMIN_TOKEN",
    "AUTH_INTERNAL_ADMIN_TOKEN",
    "ADMIN_SESSION_SECRET",
    "ADMIN_OIDC_CLIENT_SECRET",
    "OIDC_CLIENT_SECRET",
    "MAGPIE_ISSUER_KEY",
  ];
  for (const name of forbidden) {
    const value = String(env[name] || "").trim();
    if (value && value === token) {
      throw new Error(`GATEWAY_CONTROL_TOKEN must not reuse ${name}`);
    }
  }
}

export function loadConfig(env = process.env) {
  const token = secret(env, "GATEWAY_CONTROL_TOKEN");
  rejectReusedToken(env, token);

  const config = {
    bind: String(env.GATEWAY_CONTROL_BIND || "127.0.0.1").trim(),
    port: integer(env, "GATEWAY_CONTROL_PORT", 3446, 1, 65535),
    token,
    magpiePath: absoluteEntry(env, "GATEWAY_CONTROL_MAGPIE", false),
    configHome: absoluteEntry(env, "GATEWAY_CONTROL_CONFIG_HOME", true),
    timeoutMs: integer(env, "GATEWAY_CONTROL_TIMEOUT_MS", 10000, 500, MAX_TIMEOUT_MS),
    maxBodyBytes: 64 << 10,
    maxOutputBytes: 64 << 10,
  };
  if (!config.bind) throw new Error("GATEWAY_CONTROL_BIND must not be empty");
  return config;
}
