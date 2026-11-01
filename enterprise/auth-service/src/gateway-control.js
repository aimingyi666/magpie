const SCHEMA_VERSION = 1;
const POLICY_REVISION = /^sha256:[0-9a-f]{64}$/;
const KEY_ID = /^[A-Za-z0-9_-]{1,64}$/;
const KEY_STATES = new Set(["enabled", "disabled", "expired"]);
const MODEL_MODES = new Set(["all", "restricted", "accounts_only"]);
const LIMIT_PERIODS = new Set(["day", "week", "month", "days", "hours"]);

export class GatewayControlError extends Error {
  constructor(code, message, options = {}) {
    super(message);
    this.name = "GatewayControlError";
    this.code = code;
    this.statusCode = options.statusCode || 502;
    this.state = options.state || "failed";
    this.retryable = options.retryable === true;
  }
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function safeInteger(value, min, max) {
  return Number.isSafeInteger(value) && value >= min && value <= max;
}

function stringAt(value, maxLength) {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

function pending(message = "The gateway policy result is not confirmed") {
  return new GatewayControlError("gateway_control_pending", message, {
    state: "pending",
    retryable: true,
  });
}

function invalidOutput(message = "gateway-control returned an invalid response") {
  return new GatewayControlError("gateway_control_invalid_output", message, {
    state: "pending",
    retryable: true,
  });
}

function canonicalLimit(raw) {
  if (!plainObject(raw) || !LIMIT_PERIODS.has(raw.period)) throw invalidOutput();
  const days = raw.days == null ? 0 : raw.days;
  const hours = raw.hours == null ? 0 : raw.hours;
  const tokens = raw.tokens == null ? 0 : raw.tokens;
  const cost = raw.cost == null ? 0 : raw.cost;
  const cacheReads = raw.cacheReads == null ? false : raw.cacheReads;
  if (!safeInteger(days, 0, 3650) || !safeInteger(hours, 0, 8760)) throw invalidOutput();
  if (!safeInteger(tokens, 0, Number.MAX_SAFE_INTEGER)) throw invalidOutput();
  if (!Number.isFinite(cost) || cost < 0) throw invalidOutput();
  if (typeof cacheReads !== "boolean") throw invalidOutput();
  return {
    period: raw.period,
    days,
    hours,
    tokens,
    cost: Math.round(cost * 1e4) / 1e4,
    cacheReads,
  };
}

function canonicalPolicy(policy) {
  if (!plainObject(policy)) throw invalidOutput("The requested gateway policy is invalid");
  if (!Array.isArray(policy.models) || policy.models.length === 0) throw invalidOutput();
  if (!Array.isArray(policy.limits)) throw invalidOutput();
  return {
    models: policy.models.map((value) => {
      if (!stringAt(value, 300)) throw invalidOutput();
      return value;
    }),
    limits: policy.limits.map(canonicalLimit),
  };
}

function validateDescribe(value, expectedId) {
  if (!plainObject(value) || value.schemaVersion !== SCHEMA_VERSION || value.ok !== true) {
    throw invalidOutput();
  }
  if (!stringAt(value.observedAt, 80) || !plainObject(value.key)) throw invalidOutput();
  if (value.key.id !== expectedId || !KEY_ID.test(value.key.id)) throw invalidOutput();
  if (!stringAt(value.key.name, 500) || !KEY_STATES.has(value.key.state)) throw invalidOutput();
  if (typeof value.key.readOnly !== "boolean") throw invalidOutput();
  if (!plainObject(value.models) || !MODEL_MODES.has(value.models.mode)) throw invalidOutput();
  if (!Array.isArray(value.models.patterns) || value.models.patterns.length > 500) throw invalidOutput();
  const models = value.models.patterns.map((pattern) => {
    if (!stringAt(pattern, 300)) throw invalidOutput();
    return pattern;
  });
  if (!Array.isArray(value.limits) || value.limits.length > 5) throw invalidOutput();
  const limits = value.limits.map(canonicalLimit);
  if (!plainObject(value.accounts) || typeof value.accounts.restricted !== "boolean") throw invalidOutput();
  if (!stringAt(value.policyRevision, 100) || !POLICY_REVISION.test(value.policyRevision)) {
    throw invalidOutput();
  }
  return {
    observedAt: value.observedAt,
    key: {
      id: value.key.id,
      state: value.key.state,
      readOnly: value.key.readOnly,
    },
    models,
    limits,
    policyRevision: value.policyRevision,
  };
}

function samePolicy(readback, expected) {
  return JSON.stringify({ models: readback.models, limits: readback.limits })
    === JSON.stringify(expected);
}

function errorFromResponse(response, payload) {
  const state = payload?.state === "pending"
    ? "pending"
    : (response.status >= 500 ? "pending" : "failed");
  return new GatewayControlError(
    typeof payload?.error?.code === "string" ? payload.error.code : "gateway_control_failed",
    typeof payload?.error?.message === "string"
      ? payload.error.message.slice(0, 500)
      : `gateway-control returned HTTP ${response.status}`,
    {
      statusCode: response.status >= 400 && response.status <= 599 ? response.status : 502,
      state,
      retryable: payload?.error?.retryable === true || state === "pending",
    },
  );
}

export class GatewayControlClient {
  constructor(config, fetchImpl = fetch) {
    this.config = config;
    this.fetch = fetchImpl;
  }

  async request(pathname, method, body) {
    const headers = {
      accept: "application/json",
      authorization: `Bearer ${this.config.token}`,
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    let response;
    try {
      response = await this.fetch(`${this.config.url}${pathname}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch (error) {
      const message = error?.name === "TimeoutError" || error?.name === "AbortError"
        ? "gateway-control timed out; the policy result is unknown"
        : "gateway-control could not be reached; the policy result is unknown";
      throw pending(message);
    }
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw pending("gateway-control returned an unreadable result; the policy result is unknown");
    }
    if (!response.ok) throw errorFromResponse(response, payload);
    return payload;
  }

  async describe(keyId) {
    const payload = await this.request(`/api/v1/gateway-keys/${encodeURIComponent(keyId)}`, "GET");
    return validateDescribe(payload, keyId);
  }

  async apply(keyId, policy) {
    const expected = canonicalPolicy(policy);
    const before = await this.describe(keyId);
    if (before.key.state !== "enabled") {
      throw new GatewayControlError(
        "gateway_key_not_enabled",
        "The issued gateway key is not enabled",
        { state: "failed" },
      );
    }

    const acknowledgement = await this.request(
      `/api/v1/gateway-keys/${encodeURIComponent(keyId)}/policy`,
      "POST",
      {
        schemaVersion: SCHEMA_VERSION,
        expectedPolicyRevision: before.policyRevision,
        models: expected.models,
        limits: expected.limits,
      },
    );
    if (!plainObject(acknowledgement)
      || acknowledgement.schemaVersion !== SCHEMA_VERSION
      || acknowledgement.ok !== true
      || acknowledgement.state !== "applied"
      || !stringAt(acknowledgement.requestId, 128)
      || !plainObject(acknowledgement.readback)
      || acknowledgement.readback.verified !== true
      || !stringAt(acknowledgement.readback.observedAt, 80)
      || !stringAt(acknowledgement.readback.policyRevision, 100)
      || !POLICY_REVISION.test(acknowledgement.readback.policyRevision)) {
      throw pending("gateway-control did not provide an authoritative applied acknowledgement");
    }

    const readback = await this.describe(keyId);
    if (readback.key.state !== "enabled" || !samePolicy(readback, expected)) {
      throw pending("The independent gateway readback did not match the requested policy");
    }
    return {
      gatewayControlRequestId: acknowledgement.requestId,
      observedAt: readback.observedAt,
      policyRevision: readback.policyRevision,
      models: readback.models,
      limits: readback.limits,
    };
  }
}
