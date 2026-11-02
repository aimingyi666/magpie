import path from "node:path";

const MIN_SECRET_LENGTH = 32;

function required(env, name) {
  const value = String(env[name] || "").trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function bool(env, name, fallback) {
  const value = env[name];
  if (value == null || value === "") return fallback;
  if (/^(1|true|yes)$/i.test(value)) return true;
  if (/^(0|false|no)$/i.test(value)) return false;
  throw new Error(`${name} must be true or false`);
}

function integer(env, name, fallback, min, max) {
  const value = env[name] == null || env[name] === "" ? fallback : Number(env[name]);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function number(env, name, fallback) {
  if (env[name] == null || env[name] === "") return fallback;
  const value = Number(env[name]);
  if (!Number.isFinite(value) || value < 0) throw new Error(`${name} must be a non-negative number`);
  return value;
}

function list(env, name) {
  return String(env[name] || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function ttlSeconds(raw) {
  const value = String(raw || "").trim();
  const match = /^(\d+)(m|h)$/.exec(value);
  if (!match) throw new Error("MAGPIE_KEY_TTL must be a duration such as 30m or 8h");
  const seconds = Number(match[1]) * (match[2] === "h" ? 3600 : 60);
  if (seconds < 60 || seconds > 8 * 3600) {
    throw new Error("MAGPIE_KEY_TTL must be from 1 minute to 8 hours");
  }
  return seconds;
}

function url(env, name, fallback) {
  const raw = String(env[name] || fallback || "").trim().replace(/\/+$/, "");
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`${name} must use http or https`);
  }
  return parsed.toString().replace(/\/+$/, "");
}

export function loadConfig(env = process.env) {
  const port = integer(env, "AUTH_PORT", 3444, 1, 65535);
  const publicUrl = url(env, "AUTH_PUBLIC_URL", `http://127.0.0.1:${port}`);
  const cookieSecret = required(env, "AUTH_COOKIE_SECRET");
  const adminToken = required(env, "AUTH_ADMIN_TOKEN");
  const internalAdminToken = required(env, "AUTH_INTERNAL_ADMIN_TOKEN");
  const issuerKey = required(env, "MAGPIE_ISSUER_KEY");
  const gatewayControlToken = required(env, "GATEWAY_CONTROL_TOKEN");
  const clientSecret = required(env, "OIDC_CLIENT_SECRET");
  const syncTokenSecret = required(env, "SYNC_TOKEN_SECRET");

  for (const [name, value] of [
    ["AUTH_COOKIE_SECRET", cookieSecret],
    ["AUTH_ADMIN_TOKEN", adminToken],
    ["AUTH_INTERNAL_ADMIN_TOKEN", internalAdminToken],
    ["MAGPIE_ISSUER_KEY", issuerKey],
    ["GATEWAY_CONTROL_TOKEN", gatewayControlToken],
    ["OIDC_CLIENT_SECRET", clientSecret],
    ["SYNC_TOKEN_SECRET", syncTokenSecret],
  ]) {
    if (value.length < MIN_SECRET_LENGTH) {
      throw new Error(`${name} must be at least ${MIN_SECRET_LENGTH} characters`);
    }
  }

  const config = {
    bind: String(env.AUTH_BIND || "0.0.0.0").trim(),
    port,
    publicUrl,
    storePath: path.resolve(String(env.AUTH_STORE_PATH || "./data/auth-store.json")),
    cookieSecret,
    adminToken,
    internalAdminToken,
    cookieName: "magpie_enterprise_session",
    secureCookie: bool(env, "AUTH_SECURE_COOKIE", publicUrl.startsWith("https://")),
    sessionTtlSeconds: integer(env, "AUTH_SESSION_TTL_HOURS", 12, 1, 72) * 3600,
    deviceTokenTtlSeconds: integer(env, "AUTH_DEVICE_TOKEN_TTL_DAYS", 30, 1, 365) * 86400,
    rateLimitPerMinute: integer(env, "AUTH_RATE_LIMIT_PER_MINUTE", 120, 10, 10000),
    allowedReturnOrigins: list(env, "AUTH_ALLOWED_RETURN_ORIGINS"),
    oidc: {
      issuer: url(env, "OIDC_ISSUER"),
      clientId: required(env, "OIDC_CLIENT_ID"),
      clientSecret,
      redirectUri: url(env, "OIDC_REDIRECT_URI", `${publicUrl}/oauth/callback`),
      scopes: list(env, "OIDC_SCOPES").length ? list(env, "OIDC_SCOPES") : ["openid", "profile", "email"],
      tokenAuthMethod: String(env.OIDC_TOKEN_AUTH_METHOD || "client_secret_basic").trim(),
      allowedEmailDomains: list(env, "OIDC_ALLOWED_EMAIL_DOMAINS").map((value) => value.toLowerCase()),
      emailClaim: String(env.OIDC_EMAIL_CLAIM || "email").trim(),
      nameClaim: String(env.OIDC_NAME_CLAIM || "name").trim(),
      groupsClaim: String(env.OIDC_GROUPS_CLAIM || "groups").trim(),
    },
    magpie: {
      gatewayUrl: url(env, "MAGPIE_GATEWAY_URL"),
      publicUrl: url(env, "MAGPIE_GATEWAY_PUBLIC_URL", env.MAGPIE_GATEWAY_URL),
      issuerKey,
      keyTtlSeconds: ttlSeconds(env.MAGPIE_KEY_TTL || "8h"),
      models: list(env, "MAGPIE_KEY_MODELS"),
      tokens: integer(env, "MAGPIE_KEY_TOKENS", 0, 0, Number.MAX_SAFE_INTEGER),
      cost: number(env, "MAGPIE_KEY_COST", 0),
    },
    gatewayControl: {
      url: url(env, "GATEWAY_CONTROL_URL"),
      token: gatewayControlToken,
      timeoutMs: integer(env, "GATEWAY_CONTROL_TIMEOUT_MS", 10000, 500, 30000),
    },
    sync: {
      tokenSecret: syncTokenSecret,
      tokenTtlSeconds: integer(env, "SYNC_TOKEN_TTL_SECONDS", 300, 60, 900),
      tokenAudience: String(env.SYNC_TOKEN_AUDIENCE || "magpie-enterprise-resource").trim(),
    },
  };

  if (config.oidc.tokenAuthMethod !== "client_secret_basic" && config.oidc.tokenAuthMethod !== "client_secret_post") {
    throw new Error("OIDC_TOKEN_AUTH_METHOD must be client_secret_basic or client_secret_post");
  }
  if (!config.oidc.scopes.includes("openid")) {
    throw new Error("OIDC_SCOPES must include openid");
  }
  if (config.gatewayControl.token === config.magpie.issuerKey) {
    throw new Error("GATEWAY_CONTROL_TOKEN must not reuse MAGPIE_ISSUER_KEY");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(config.sync.tokenAudience)) {
    throw new Error("SYNC_TOKEN_AUDIENCE is invalid");
  }
  const distinctSecrets = new Set([
    config.cookieSecret,
    config.adminToken,
    config.internalAdminToken,
    config.magpie.issuerKey,
    config.gatewayControl.token,
    config.sync.tokenSecret,
  ]);
  if (distinctSecrets.size !== 6) {
    throw new Error("authentication and service secrets must not reuse the same value");
  }
  return config;
}
