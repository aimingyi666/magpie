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

function hostAllowlist(env, name) {
  const values = list(env, name).map((value) => value.toLowerCase().replace(/\.$/, ""));
  for (const value of values) {
    const hostname = value.startsWith("*.") ? value.slice(2) : value;
    if (!/^(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|\[[0-9a-f:.]+\])$/.test(hostname)
        || hostname.includes("..")) {
      throw new Error(`${name} contains an invalid hostname`);
    }
  }
  return [...new Set(values)].sort();
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
  if (parsed.username || parsed.password) {
    throw new Error(`${name} must not contain credentials`);
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
  // M3-C-2: optional read-only link to the resource catalog and client sync
  // control plane. The URL and token are configured together or not at all,
  // so a half-configured dependency cannot silently read a wrong endpoint.
  const resourceServiceUrl = String(env.ADMIN_RESOURCE_SERVICE_URL || "").trim();
  const resourceServiceToken = String(env.ADMIN_RESOURCE_SERVICE_TOKEN || "").trim();
  if (Boolean(resourceServiceUrl) !== Boolean(resourceServiceToken)) {
    throw new Error(
      "ADMIN_RESOURCE_SERVICE_URL and ADMIN_RESOURCE_SERVICE_TOKEN are required together",
    );
  }
  if (resourceServiceToken && resourceServiceToken.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `ADMIN_RESOURCE_SERVICE_TOKEN must be at least ${MIN_SECRET_LENGTH} characters`,
    );
  }
  // The gateway's own administration API: an internal address and a token
  // of its own, together or not at all.
  const gatewayAdminUrl = String(env.ADMIN_GATEWAY_ADMIN_URL || "").trim();
  const gatewayAdminToken = String(env.ADMIN_GATEWAY_ADMIN_TOKEN || "").trim();
  if (Boolean(gatewayAdminUrl) !== Boolean(gatewayAdminToken)) {
    throw new Error(
      "ADMIN_GATEWAY_ADMIN_URL and ADMIN_GATEWAY_ADMIN_TOKEN are required together",
    );
  }
  if (gatewayAdminToken && gatewayAdminToken.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `ADMIN_GATEWAY_ADMIN_TOKEN must be at least ${MIN_SECRET_LENGTH} characters`,
    );
  }
  if (gatewayAdminUrl) {
    const parsed = new URL(gatewayAdminUrl);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error("ADMIN_GATEWAY_ADMIN_URL must use http or https");
    }
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new Error("ADMIN_GATEWAY_ADMIN_URL must not carry credentials, a query or a fragment");
    }
  }
  // M4-E: the admin UI reaches audit-service only through this optional
  // content boundary. Metadata/body access uses the admin token; retention,
  // deletion, legal holds and exports use the governance token.
  const auditContentServiceUrl = String(
    env.ADMIN_AUDIT_CONTENT_SERVICE_URL || "",
  ).trim();
  const auditContentServiceAdminToken = String(
    env.ADMIN_AUDIT_CONTENT_SERVICE_ADMIN_TOKEN || "",
  ).trim();
  const auditContentServiceGovernanceToken = String(
    env.ADMIN_AUDIT_CONTENT_SERVICE_GOVERNANCE_TOKEN || "",
  ).trim();
  const auditContentServiceOrganizationId = String(
    env.ADMIN_AUDIT_CONTENT_SERVICE_ORGANIZATION_ID || "",
  ).trim();
  const auditContentServiceExportKey = String(
    env.ADMIN_AUDIT_CONTENT_EXPORT_KEY || "",
  ).trim();
  const auditContentServiceValues = [
    auditContentServiceUrl,
    auditContentServiceAdminToken,
    auditContentServiceGovernanceToken,
    auditContentServiceOrganizationId,
    auditContentServiceExportKey,
  ];
  if (auditContentServiceValues.some(Boolean)
      && !auditContentServiceValues.every(Boolean)) {
    throw new Error(
      "ADMIN_AUDIT_CONTENT_SERVICE_URL, ADMIN_AUDIT_CONTENT_SERVICE_ADMIN_TOKEN, "
      + "ADMIN_AUDIT_CONTENT_SERVICE_GOVERNANCE_TOKEN, "
      + "ADMIN_AUDIT_CONTENT_SERVICE_ORGANIZATION_ID and "
      + "ADMIN_AUDIT_CONTENT_EXPORT_KEY are required together",
    );
  }
  if (auditContentServiceAdminToken
      && auditContentServiceAdminToken.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `ADMIN_AUDIT_CONTENT_SERVICE_ADMIN_TOKEN must be at least ${MIN_SECRET_LENGTH} characters`,
    );
  }
  if (auditContentServiceGovernanceToken
      && auditContentServiceGovernanceToken.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `ADMIN_AUDIT_CONTENT_SERVICE_GOVERNANCE_TOKEN must be at least ${MIN_SECRET_LENGTH} characters`,
    );
  }
  if (auditContentServiceAdminToken
      && auditContentServiceAdminToken === auditContentServiceGovernanceToken) {
    throw new Error(
      "ADMIN_AUDIT_CONTENT_SERVICE_ADMIN_TOKEN and "
      + "ADMIN_AUDIT_CONTENT_SERVICE_GOVERNANCE_TOKEN must differ",
    );
  }
  if (auditContentServiceOrganizationId
      && !/^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/.test(
        auditContentServiceOrganizationId,
      )) {
    throw new Error("ADMIN_AUDIT_CONTENT_SERVICE_ORGANIZATION_ID is invalid");
  }
  let auditContentServiceExportKeyBytes = Buffer.alloc(0);
  if (auditContentServiceExportKey) {
    if (/^[a-f0-9]{64}$/i.test(auditContentServiceExportKey)) {
      auditContentServiceExportKeyBytes = Buffer.from(auditContentServiceExportKey, "hex");
    } else {
      try {
        auditContentServiceExportKeyBytes = Buffer.from(auditContentServiceExportKey, "base64");
      } catch {
        throw new Error("ADMIN_AUDIT_CONTENT_EXPORT_KEY must be 32-byte base64 or hex");
      }
      const canonical = auditContentServiceExportKeyBytes.toString("base64");
      if (canonical !== auditContentServiceExportKey) {
        throw new Error("ADMIN_AUDIT_CONTENT_EXPORT_KEY must be 32-byte base64 or hex");
      }
    }
    if (auditContentServiceExportKeyBytes.length !== 32) {
      throw new Error("ADMIN_AUDIT_CONTENT_EXPORT_KEY must be 32-byte base64 or hex");
    }
  }
  // Automatic content capture: the gateway hands over a caller key and a
  // text, and this service resolves the person, applies the standing
  // collection policy and writes audit-service. Off unless every part is
  // configured: a half-configured capture would either drop every stream or
  // write one under the wrong authorization.
  const contentCaptureEnabled = bool(env, "ADMIN_CONTENT_CAPTURE_ENABLED", false);
  const contentCaptureToken = String(env.ADMIN_CONTENT_CAPTURE_TOKEN || "").trim();
  const contentCapturePurpose = String(
    env.ADMIN_CONTENT_CAPTURE_PURPOSE || "security_investigation",
  ).trim();
  const contentCaptureAuthorizationId = String(
    env.ADMIN_CONTENT_CAPTURE_AUTHORIZATION_ID || "",
  ).trim();
  const contentCaptureRetentionDays = integer(
    env,
    "ADMIN_CONTENT_CAPTURE_RETENTION_DAYS",
    30,
    1,
    3650,
  );
  const auditContentIngestToken = String(
    env.ADMIN_AUDIT_CONTENT_INGEST_TOKEN || "",
  ).trim();
  if (contentCaptureEnabled) {
    if (contentCaptureToken.length < MIN_SECRET_LENGTH) {
      throw new Error(
        `ADMIN_CONTENT_CAPTURE_TOKEN must be at least ${MIN_SECRET_LENGTH} characters`,
      );
    }
    if (auditContentIngestToken.length < MIN_SECRET_LENGTH) {
      throw new Error(
        `ADMIN_AUDIT_CONTENT_INGEST_TOKEN must be at least ${MIN_SECRET_LENGTH} characters`,
      );
    }
    if (contentCaptureToken === auditContentIngestToken) {
      throw new Error(
        "ADMIN_CONTENT_CAPTURE_TOKEN and ADMIN_AUDIT_CONTENT_INGEST_TOKEN must differ",
      );
    }
    if (!auditContentServiceUrl) {
      throw new Error(
        "ADMIN_AUDIT_CONTENT_SERVICE_URL is required when content capture is on",
      );
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._:@-]{7,127}$/.test(contentCaptureAuthorizationId)) {
      throw new Error("ADMIN_CONTENT_CAPTURE_AUTHORIZATION_ID is invalid");
    }
    if (!["security_investigation", "incident_response", "compliance_review",
      "legal_investigation"].includes(contentCapturePurpose)) {
      throw new Error("ADMIN_CONTENT_CAPTURE_PURPOSE is unsupported");
    }
  }
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
    desktop: {
      // Where a desktop admin signs in from. The callback must be a
      // loopback address: the ticket lands in the browser's address bar,
      // and only the machine asking for it may receive it.
      enabled: bool(env, "ADMIN_DESKTOP_LOGIN_ENABLED", true),
      allowedCallbackHosts: list(env, "ADMIN_DESKTOP_CALLBACK_HOSTS").length
        ? list(env, "ADMIN_DESKTOP_CALLBACK_HOSTS").map((value) => value.toLowerCase())
        : ["127.0.0.1", "localhost", "[::1]"],
      allowedCallbackPorts: list(env, "ADMIN_DESKTOP_CALLBACK_PORTS")
        .map((value) => Number(value))
        .filter((value) => Number.isInteger(value) && value > 0 && value <= 65535),
      ticketTtlSeconds: integer(env, "ADMIN_DESKTOP_TICKET_TTL_SECONDS", 120, 30, 600),
      tokenTtlSeconds: integer(env, "ADMIN_DESKTOP_TOKEN_TTL_HOURS", 8, 1, 8) * 3600,
      idleTimeoutSeconds: integer(env, "ADMIN_DESKTOP_IDLE_MINUTES", 30, 5, 120) * 60,
    },
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
    resourceService: {
      enabled: Boolean(resourceServiceUrl),
      url: resourceServiceUrl ? url(env, "ADMIN_RESOURCE_SERVICE_URL") : "",
      token: resourceServiceToken,
      timeoutMs: integer(env, "ADMIN_RESOURCE_SERVICE_TIMEOUT_MS", 5000, 500, 30000),
      maxResponseBytes: integer(
        env,
        "ADMIN_RESOURCE_SERVICE_MAX_RESPONSE_BYTES",
        4 * 1024 * 1024,
        16 * 1024,
        32 * 1024 * 1024,
      ),
    },
    gatewayAdmin: {
      enabled: Boolean(gatewayAdminUrl),
      url: gatewayAdminUrl ? url(env, "ADMIN_GATEWAY_ADMIN_URL") : "",
      token: gatewayAdminToken,
      timeoutMs: integer(env, "ADMIN_GATEWAY_ADMIN_TIMEOUT_MS", 10000, 500, 60000),
      maxResponseBytes: integer(
        env,
        "ADMIN_GATEWAY_ADMIN_MAX_RESPONSE_BYTES",
        4 * 1024 * 1024,
        16 * 1024,
        32 * 1024 * 1024,
      ),
    },
    contentCapture: {
      enabled: contentCaptureEnabled,
      token: contentCaptureToken,
      purpose: contentCapturePurpose,
      authorizationId: contentCaptureAuthorizationId,
      retentionDays: contentCaptureRetentionDays,
      ingestToken: auditContentIngestToken,
      url: auditContentServiceUrl,
      timeoutMs: integer(env, "ADMIN_CONTENT_CAPTURE_TIMEOUT_MS", 5000, 500, 30000),
      maxTextBytes: integer(
        env,
        "ADMIN_CONTENT_CAPTURE_MAX_TEXT_BYTES",
        256 * 1024,
        1024,
        4 * 1024 * 1024,
      ),
    },
    auditContentService: {
      enabled: Boolean(auditContentServiceUrl),
      url: auditContentServiceUrl
        ? url(env, "ADMIN_AUDIT_CONTENT_SERVICE_URL")
        : "",
      adminToken: auditContentServiceAdminToken,
      governanceToken: auditContentServiceGovernanceToken,
      organizationId: auditContentServiceOrganizationId,
      exportKey: auditContentServiceExportKeyBytes,
      timeoutMs: integer(
        env,
        "ADMIN_AUDIT_CONTENT_SERVICE_TIMEOUT_MS",
        5000,
        500,
        30000,
      ),
      maxResponseBytes: integer(
        env,
        "ADMIN_AUDIT_CONTENT_SERVICE_MAX_RESPONSE_BYTES",
        4 * 1024 * 1024,
        16 * 1024,
        32 * 1024 * 1024,
      ),
      maxExportBytes: integer(
        env,
        "ADMIN_AUDIT_CONTENT_SERVICE_MAX_EXPORT_BYTES",
        32 * 1024 * 1024,
        64 * 1024,
        128 * 1024 * 1024,
      ),
    },
     securityService: {
       enabled: Boolean(String(env.ADMIN_SECURITY_SERVICE_URL || "").trim()),
       url: String(env.ADMIN_SECURITY_SERVICE_URL || "").trim()
         ? url(env, "ADMIN_SECURITY_SERVICE_URL")
         : "",
       token: String(env.ADMIN_SECURITY_SERVICE_TOKEN || "").trim(),
       timeoutMs: integer(
         env,
         "ADMIN_SECURITY_SERVICE_TIMEOUT_MS",
         5000,
         500,
         30000,
       ),
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
    exports: {
      ttlSeconds: integer(env, "ADMIN_EXPORT_TTL_SECONDS", 900, 60, 86400),
      maxBytes: integer(
        env,
        "ADMIN_EXPORT_MAX_BYTES",
        5 * 1024 * 1024,
        64 * 1024,
        32 * 1024 * 1024,
      ),
      maxRecords: integer(env, "ADMIN_EXPORT_MAX_RECORDS", 100000, 1, 1000000),
    },
    notifications: {
      pollIntervalMs: integer(
        env,
        "ADMIN_NOTIFICATION_OUTBOX_POLL_SECONDS",
        30,
        1,
        300,
      ) * 1000,
      escalationPollIntervalMs: integer(
        env,
        "ADMIN_NOTIFICATION_ESCALATION_POLL_SECONDS",
        30,
        1,
        300,
      ) * 1000,
      leaseMs: integer(
        env,
        "ADMIN_NOTIFICATION_OUTBOX_LEASE_SECONDS",
        60,
        10,
        3600,
      ) * 1000,
      maxAttempts: integer(
        env,
        "ADMIN_NOTIFICATION_OUTBOX_MAX_ATTEMPTS",
        6,
        1,
        20,
      ),
      batchSize: integer(
        env,
        "ADMIN_NOTIFICATION_OUTBOX_BATCH_SIZE",
        20,
        1,
        200,
      ),
      channels: {
        enabled: bool(env, "ADMIN_NOTIFICATION_CHANNELS_ENABLED", false),
        outboundAllowlist: hostAllowlist(env, "ADMIN_NOTIFICATION_OUTBOUND_ALLOWLIST"),
        emailRecipientDomains: list(
          env,
          "ADMIN_NOTIFICATION_EMAIL_RECIPIENT_DOMAINS",
        ).map((value) => value.toLowerCase()),
        httpTimeoutMs: integer(
          env,
          "ADMIN_NOTIFICATION_HTTP_TIMEOUT_MS",
          5000,
          500,
          30000,
        ),
        httpMaxResponseBytes: integer(
          env,
          "ADMIN_NOTIFICATION_HTTP_MAX_RESPONSE_BYTES",
          64 * 1024,
          1024,
          1024 * 1024,
        ),
        httpMaxRedirects: integer(
          env,
          "ADMIN_NOTIFICATION_HTTP_MAX_REDIRECTS",
          3,
          0,
          3,
        ),
        maxSiemEventBytes: integer(
          env,
          "ADMIN_NOTIFICATION_SIEM_MAX_EVENT_BYTES",
          32 * 1024,
          1024,
          64 * 1024,
        ),
      },
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
