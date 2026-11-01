import path from "node:path";
import { parseAllowedIp } from "./ip.js";

const MIN_SECRET_LENGTH = 32;

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

function optionalSecret(env, name) {
  const value = String(env[name] || "").trim();
  if (!value) return "";
  if (value.length < MIN_SECRET_LENGTH) {
    throw new Error(`${name} must be at least ${MIN_SECRET_LENGTH} characters`);
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

function integer(env, name, fallback, min, max) {
  const value = env[name] == null || env[name] === "" ? fallback : Number(env[name]);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function list(env, name) {
  return String(env[name] || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
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
  const port = integer(env, "ADMIN_PORT", 3445, 1, 65535);
  const publicUrl = url(env, "ADMIN_PUBLIC_URL", `http://127.0.0.1:${port}`);
  const allowedIpsText = list(env, "ADMIN_ALLOWED_IPS");
  const allowedIpValues = allowedIpsText.length > 0
    ? allowedIpsText
    : ["127.0.0.1/32", "::1/128"];
  const approvalCallbackSecret = optionalSecret(env, "ADMIN_APPROVAL_CALLBACK_SECRET");
  const approvalCallbackIssuer = String(env.ADMIN_APPROVAL_CALLBACK_ISSUER || "").trim();
  const approvalCallbackAudience = String(env.ADMIN_APPROVAL_CALLBACK_AUDIENCE || "").trim();
  const approvalCallbackMaxSkewSeconds = integer(
    env,
    "ADMIN_APPROVAL_CALLBACK_MAX_SKEW_SECONDS",
    300,
    1,
    3600,
  );
  const approvalCallbackNonceTtlSeconds = integer(
    env,
    "ADMIN_APPROVAL_CALLBACK_NONCE_TTL_SECONDS",
    600,
    60,
    604800,
  );
  const stepUpClientId = String(env.ADMIN_STEP_UP_OIDC_CLIENT_ID || "").trim();
  const stepUpClientSecret = String(env.ADMIN_STEP_UP_OIDC_CLIENT_SECRET || "").trim();
  const stepUpRedirectUri = String(env.ADMIN_STEP_UP_REDIRECT_URI || "").trim();
  const stepUpConfigured = Boolean(stepUpClientId || stepUpClientSecret || stepUpRedirectUri);
  const stepUpTtlSeconds = integer(
    env,
    "ADMIN_STEP_UP_TTL_SECONDS",
    600,
    60,
    3600,
  );
  const stepUpCriticalTtlSeconds = integer(
    env,
    "ADMIN_STEP_UP_CRITICAL_TTL_SECONDS",
    300,
    30,
    3600,
  );
  const stepUpAuthTimeMaxAgeSeconds = integer(
    env,
    "ADMIN_STEP_UP_AUTH_TIME_MAX_AGE_SECONDS",
    120,
    30,
    900,
  );
  if (stepUpCriticalTtlSeconds > stepUpTtlSeconds) {
    throw new Error(
      "ADMIN_STEP_UP_CRITICAL_TTL_SECONDS must not exceed ADMIN_STEP_UP_TTL_SECONDS",
    );
  }
  if (stepUpConfigured && (!stepUpClientId || !stepUpClientSecret)) {
    throw new Error(
      "ADMIN_STEP_UP_OIDC_CLIENT_ID and ADMIN_STEP_UP_OIDC_CLIENT_SECRET "
      + "are required when step-up authentication is configured",
    );
  }
  if (stepUpClientSecret && stepUpClientSecret.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `ADMIN_STEP_UP_OIDC_CLIENT_SECRET must be at least ${MIN_SECRET_LENGTH} characters`,
    );
  }
  if (!approvalCallbackSecret
      && (approvalCallbackIssuer || approvalCallbackAudience)) {
    throw new Error(
      "ADMIN_APPROVAL_CALLBACK_SECRET is required when callback issuer or audience is set",
    );
  }
  if (approvalCallbackSecret
      && (!approvalCallbackIssuer || !approvalCallbackAudience)) {
    throw new Error(
      "ADMIN_APPROVAL_CALLBACK_ISSUER and ADMIN_APPROVAL_CALLBACK_AUDIENCE are required",
    );
  }
  if (approvalCallbackNonceTtlSeconds < approvalCallbackMaxSkewSeconds) {
    throw new Error(
      "ADMIN_APPROVAL_CALLBACK_NONCE_TTL_SECONDS must be at least "
      + "ADMIN_APPROVAL_CALLBACK_MAX_SKEW_SECONDS",
    );
  }

  const oidc = {
    issuer: url(env, "ADMIN_OIDC_ISSUER"),
    clientId: required(env, "ADMIN_OIDC_CLIENT_ID"),
    clientSecret: secret(env, "ADMIN_OIDC_CLIENT_SECRET"),
    redirectUri: url(env, "ADMIN_OIDC_REDIRECT_URI", `${publicUrl}/admin/oauth/callback`),
    scopes: list(env, "ADMIN_OIDC_SCOPES").length
      ? list(env, "ADMIN_OIDC_SCOPES")
      : ["openid", "profile", "email"],
    tokenAuthMethod: String(env.ADMIN_OIDC_TOKEN_AUTH_METHOD || "client_secret_basic").trim(),
    allowedEmailDomains: list(env, "ADMIN_ALLOWED_EMAIL_DOMAINS").map((value) => value.toLowerCase()),
    emailClaim: String(env.ADMIN_EMAIL_CLAIM || "email").trim(),
    nameClaim: String(env.ADMIN_NAME_CLAIM || "name").trim(),
    requireMfa: bool(env, "ADMIN_REQUIRE_MFA", true),
    requireVerifiedEmail: bool(env, "ADMIN_REQUIRE_VERIFIED_EMAIL", true),
    allowedAcrValues: list(env, "ADMIN_ALLOWED_ACR_VALUES"),
  };
  let stepUpOidc = null;
  if (stepUpConfigured) {
    const redirectUri = url(
      env,
      "ADMIN_STEP_UP_REDIRECT_URI",
      `${publicUrl}/admin/oauth/step-up/callback`,
    );
    const scopes = list(env, "ADMIN_STEP_UP_OIDC_SCOPES").length
      ? list(env, "ADMIN_STEP_UP_OIDC_SCOPES")
      : oidc.scopes;
    if (!scopes.includes("openid")) {
      throw new Error("ADMIN_STEP_UP_OIDC_SCOPES must include openid");
    }
    if (stepUpClientId === oidc.clientId) {
      throw new Error("ADMIN_STEP_UP_OIDC_CLIENT_ID must differ from ADMIN_OIDC_CLIENT_ID");
    }
    if (redirectUri === oidc.redirectUri) {
      throw new Error("ADMIN_STEP_UP_REDIRECT_URI must differ from ADMIN_OIDC_REDIRECT_URI");
    }
    stepUpOidc = {
      issuer: oidc.issuer,
      clientId: stepUpClientId,
      clientSecret: stepUpClientSecret,
      redirectUri,
      scopes,
      tokenAuthMethod: oidc.tokenAuthMethod,
      allowedEmailDomains: oidc.allowedEmailDomains,
      emailClaim: oidc.emailClaim,
      nameClaim: oidc.nameClaim,
      requireMfa: true,
      requireVerifiedEmail: oidc.requireVerifiedEmail,
      allowedAcrValues: list(env, "ADMIN_STEP_UP_ALLOWED_ACR_VALUES"),
      authTimeMaxAgeSeconds: stepUpAuthTimeMaxAgeSeconds,
      ttlSeconds: stepUpTtlSeconds,
      criticalTtlSeconds: stepUpCriticalTtlSeconds,
    };
  }

  const config = {
    bind: String(env.ADMIN_BIND || "0.0.0.0").trim(),
    port,
    publicUrl,
    storePath: path.resolve(String(env.ADMIN_STORE_PATH || "./data/admin-store.json")),
    sessionSecret: secret(env, "ADMIN_SESSION_SECRET"),
    sessionCookieName: "magpie_enterprise_admin_session",
    csrfCookieName: "magpie_enterprise_admin_csrf",
    loginCookieName: "magpie_enterprise_admin_login",
    stepUpCookieName: "magpie_enterprise_admin_step_up",
    secureCookie: bool(env, "ADMIN_SECURE_COOKIE", publicUrl.startsWith("https://")),
    sessionTtlSeconds: integer(env, "ADMIN_SESSION_TTL_HOURS", 8, 1, 8) * 3600,
    idleTimeoutSeconds: integer(env, "ADMIN_IDLE_TIMEOUT_MINUTES", 30, 5, 120) * 60,
    rateLimitPerMinute: integer(env, "ADMIN_RATE_LIMIT_PER_MINUTE", 120, 10, 10000),
    allowedIps: allowedIpValues.map((value) => parseAllowedIp(value)),
    bootstrap: {
      subjectIds: list(env, "ADMIN_BOOTSTRAP_SUBJECTS"),
      emails: list(env, "ADMIN_BOOTSTRAP_EMAILS").map((value) => value.toLowerCase()),
      validHours: integer(env, "ADMIN_BOOTSTRAP_VALID_HOURS", 24, 1, 168),
    },
    oidc,
    stepUpOidc,
    authService: {
      url: url(env, "ADMIN_AUTH_SERVICE_URL"),
      token: secret(env, "ADMIN_AUTH_SERVICE_TOKEN"),
      timeoutMs: integer(env, "ADMIN_AUTH_SERVICE_TIMEOUT_MS", 5000, 500, 30000),
    },
    approvalCallback: {
      enabled: Boolean(approvalCallbackSecret),
      secret: approvalCallbackSecret,
      issuer: approvalCallbackIssuer,
      audience: approvalCallbackAudience,
      maxSkewSeconds: approvalCallbackMaxSkewSeconds,
      nonceTtlSeconds: approvalCallbackNonceTtlSeconds,
    },
    models: list(env, "ADMIN_MODELS"),
    modelCatalog: {
      path: String(env.ADMIN_MODEL_CATALOG_PATH || "").trim(),
      expectedDigest: String(env.ADMIN_MODEL_CATALOG_DIGEST || "").trim().toLowerCase(),
    },
    usage: {
      path: String(env.ADMIN_USAGE_PATH || "").trim()
        ? path.resolve(String(env.ADMIN_USAGE_PATH).trim())
        : "",
      maxBytes: integer(env, "ADMIN_USAGE_MAX_BYTES", 256 * 1024 * 1024, 1024, 2 * 1024 * 1024 * 1024),
      maxLineBytes: integer(env, "ADMIN_USAGE_MAX_LINE_BYTES", 1024 * 1024, 1024, 16 * 1024 * 1024),
      maxRecords: integer(env, "ADMIN_USAGE_MAX_RECORDS", 1000000, 1, 10000000),
      maxFields: integer(env, "ADMIN_USAGE_MAX_FIELDS", 256, 16, 1024),
      maxRangeDays: integer(env, "ADMIN_USAGE_MAX_RANGE_DAYS", 366, 1, 3660),
    },
  };

  if (config.oidc.tokenAuthMethod !== "client_secret_basic"
      && config.oidc.tokenAuthMethod !== "client_secret_post") {
    throw new Error("ADMIN_OIDC_TOKEN_AUTH_METHOD must be client_secret_basic or client_secret_post");
  }
  if (!config.oidc.scopes.includes("openid")) {
    throw new Error("ADMIN_OIDC_SCOPES must include openid");
  }
  if (config.modelCatalog.path && !path.isAbsolute(config.modelCatalog.path)) {
    throw new Error("ADMIN_MODEL_CATALOG_PATH must be an absolute path");
  }
  if (config.modelCatalog.expectedDigest) {
    const digest = config.modelCatalog.expectedDigest.replace(/^sha256:/, "");
    if (!/^[a-f0-9]{64}$/.test(digest)) {
      throw new Error("ADMIN_MODEL_CATALOG_DIGEST must be a SHA-256 digest");
    }
  }
  if (config.bootstrap.subjectIds.length === 0 && config.bootstrap.emails.length === 0) {
    console.warn("ADMIN_BOOTSTRAP_SUBJECTS/EMAILS are empty; seed role bindings before use");
  }
  return config;
}
