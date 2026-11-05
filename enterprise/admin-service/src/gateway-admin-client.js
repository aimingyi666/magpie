// Client for the gateway's dedicated administration API
// (internal/gateway/admin.go). The gateway listens on an internal address
// the management service alone reaches, with a bearer token of its own; a
// gateway key, an employee's device token or a browser cookie never opens
// it.
//
// Every call fails closed. A redirect is refused rather than followed (a
// 30x could send the token somewhere else), the body is capped, and a
// timeout is a 504 rather than an empty list an operator would read as
// "nothing is configured".

const DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10000;

export class GatewayAdminError extends Error {
  constructor(message = "The gateway administration API is unavailable", options = {}) {
    super(message);
    this.name = "GatewayAdminError";
    this.statusCode = Number.isInteger(options.statusCode) ? options.statusCode : 503;
    this.code = typeof options.code === "string" && options.code
      ? options.code
      : "gateway_unavailable";
  }
}

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype
      || Object.getPrototypeOf(value) === null);
}

async function readJson(response, maxBytes) {
  const declared = Number(response.headers?.get?.("content-length") || 0);
  if (Number.isFinite(declared) && declared > maxBytes) {
    response.body?.cancel?.().catch?.(() => {});
    throw new GatewayAdminError("The gateway answer is too large", {
      statusCode: 502,
      code: "gateway_invalid_response",
    });
  }
  const reader = response.body?.getReader?.();
  if (!reader) {
    throw new GatewayAdminError("The gateway answer is unreadable", {
      statusCode: 502,
      code: "gateway_invalid_response",
    });
  }
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      reader.cancel().catch(() => {});
      throw new GatewayAdminError("The gateway answer is too large", {
        statusCode: 502,
        code: "gateway_invalid_response",
      });
    }
    chunks.push(Buffer.from(value));
  }
  const text = Buffer.concat(chunks).toString("utf8");
  try {
    return JSON.parse(text);
  } catch {
    throw new GatewayAdminError("The gateway answer is not JSON", {
      statusCode: 502,
      code: "gateway_invalid_response",
    });
  }
}

// A gateway error code is passed on only when it is one this API defines,
// and its message is replaced with ours: a gateway's own message could
// quote a credential.
const PASS_THROUGH_CODE = /^(?:unauthorized|forbidden|not_found|revision_conflict|invalid_[a-z_]{1,40}|gateway_[a-z_]{1,40}|unavailable|timeout)$/;

function failureFrom(status, payload) {
  const upstream = plainObject(payload?.error) ? payload.error : {};
  const code = typeof upstream.code === "string" && PASS_THROUGH_CODE.test(upstream.code)
    ? upstream.code
    : "gateway_invalid_response";
  const statusCode = status === 404
    ? 404
    : status === 409
      ? 409
      : status === 401 || status === 403
        ? 403
        : status === 503
          ? 503
          : 422;
  const messages = {
    not_found: "The gateway has no such record",
    revision_conflict: "The gateway configuration changed; read it again",
    unauthorized: "The gateway refused the management service",
    forbidden: "The gateway refused this administration call",
    unavailable: "The gateway administration API is unavailable",
    timeout: "The gateway did not answer in time",
  };
  return new GatewayAdminError(messages[code] || "The gateway rejected the request", {
    statusCode: code === "unauthorized" || code === "forbidden" ? 502 : statusCode,
    code: code === "unauthorized" || code === "forbidden" ? "gateway_refused" : code,
  });
}

export class GatewayAdminClient {
  constructor(config = {}) {
    this.config = {
      enabled: Boolean(config.url && config.token),
      url: String(config.url || ""),
      token: String(config.token || ""),
      timeoutMs: Number.isFinite(Number(config.timeoutMs)) && Number(config.timeoutMs) > 0
        ? Number(config.timeoutMs)
        : DEFAULT_TIMEOUT_MS,
      maxResponseBytes: Number.isFinite(Number(config.maxResponseBytes))
        && Number(config.maxResponseBytes) > 0
        ? Number(config.maxResponseBytes)
        : DEFAULT_MAX_RESPONSE_BYTES,
    };
  }

  get enabled() {
    return this.config.enabled;
  }

  async request(method, pathname, { body, expectedRevision } = {}) {
    if (!this.enabled) {
      throw new GatewayAdminError("Gateway administration is not configured", {
        statusCode: 503,
        code: "gateway_unavailable",
      });
    }
    const headers = {
      accept: "application/json",
      authorization: `Bearer ${this.config.token}`,
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    if (expectedRevision) headers["if-match"] = String(expectedRevision);
    let response;
    try {
      response = await fetch(new URL(pathname, this.config.url), {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch (error) {
      if (error?.name === "TimeoutError" || error?.name === "AbortError") {
        throw new GatewayAdminError("The gateway did not answer in time", {
          statusCode: 504,
          code: "timeout",
        });
      }
      throw new GatewayAdminError();
    }
    let payload;
    try {
      payload = await readJson(response, this.config.maxResponseBytes);
    } catch (error) {
      if (error instanceof GatewayAdminError) throw error;
      throw new GatewayAdminError();
    }
    if (!plainObject(payload)) {
      throw new GatewayAdminError("The gateway answer has an unexpected shape", {
        statusCode: 502,
        code: "gateway_invalid_response",
      });
    }
    if (!response.ok || payload.ok !== true) {
      throw failureFrom(response.status, payload);
    }
    return payload;
  }

  // --- providers -------------------------------------------------------

  async listProviders() {
    const payload = await this.request("GET", "/v1/magpie/admin/providers");
    if (!Array.isArray(payload.providers)) throw new GatewayAdminError();
    return payload.providers;
  }

  async createProvider(provider) {
    const payload = await this.request("POST", "/v1/magpie/admin/providers", { body: provider });
    if (!plainObject(payload.provider)) throw new GatewayAdminError();
    return payload.provider;
  }

  async updateProvider(id, patch, expectedRevision) {
    const payload = await this.request(
      "PATCH",
      `/v1/magpie/admin/providers/${encodeURIComponent(id)}`,
      {
        body: { ...patch, expectedRevision },
        expectedRevision,
      },
    );
    if (!plainObject(payload.provider)) throw new GatewayAdminError();
    return payload.provider;
  }

  async deleteProvider(id, expectedRevision) {
    return this.request(
      "DELETE",
      `/v1/magpie/admin/providers/${encodeURIComponent(id)}`,
      { expectedRevision },
    );
  }

  // --- routing groups --------------------------------------------------

  async listRoutingGroups() {
    const payload = await this.request("GET", "/v1/magpie/admin/routing-groups");
    if (!Array.isArray(payload.groups)) throw new GatewayAdminError();
    return payload.groups;
  }

  async createRoutingGroup(group) {
    const payload = await this.request("POST", "/v1/magpie/admin/routing-groups", { body: group });
    if (!plainObject(payload.group)) throw new GatewayAdminError();
    return payload.group;
  }

  async updateRoutingGroup(id, patch, expectedRevision) {
    const payload = await this.request(
      "PATCH",
      `/v1/magpie/admin/routing-groups/${encodeURIComponent(id)}`,
      { body: { ...patch, expectedRevision }, expectedRevision },
    );
    if (!plainObject(payload.group)) throw new GatewayAdminError();
    return payload.group;
  }

  async deleteRoutingGroup(id, expectedRevision) {
    return this.request(
      "DELETE",
      `/v1/magpie/admin/routing-groups/${encodeURIComponent(id)}`,
      { expectedRevision },
    );
  }

  // --- gateway and its keys -------------------------------------------

  async gatewayState() {
    const payload = await this.request("GET", "/v1/magpie/admin/gateway");
    if (!plainObject(payload.gateway)) throw new GatewayAdminError();
    return payload.gateway;
  }

  async listGatewayKeys() {
    const payload = await this.request("GET", "/v1/magpie/admin/gateway/keys");
    if (!Array.isArray(payload.keys)) throw new GatewayAdminError();
    return payload.keys;
  }

  async createGatewayKey(key) {
    const payload = await this.request("POST", "/v1/magpie/admin/gateway/keys", { body: key });
    if (!plainObject(payload.key) || typeof payload.secret !== "string") {
      throw new GatewayAdminError();
    }
    return { key: payload.key, secret: payload.secret };
  }

  async updateGatewayKey(id, patch, expectedRevision) {
    const payload = await this.request(
      "PATCH",
      `/v1/magpie/admin/gateway/keys/${encodeURIComponent(id)}`,
      { body: { ...patch, expectedRevision }, expectedRevision },
    );
    return {
      key: plainObject(payload.key) ? payload.key : null,
      keys: Array.isArray(payload.keys) ? payload.keys : [],
      secret: typeof payload.secret === "string" ? payload.secret : "",
    };
  }

  // --- telemetry ------------------------------------------------------

  async requestPage(searchParams) {
    const query = searchParams instanceof URLSearchParams
      ? searchParams.toString()
      : new URLSearchParams(searchParams || {}).toString();
    const payload = await this.request(
      "GET",
      `/v1/magpie/admin/telemetry/requests${query ? `?${query}` : ""}`,
    );
    if (!Array.isArray(payload.rows)) throw new GatewayAdminError();
    return payload;
  }

  async routeTrace(routeId) {
    const payload = await this.request(
      "GET",
      `/v1/magpie/admin/telemetry/routes/${encodeURIComponent(routeId)}`,
    );
    if (!plainObject(payload.route)) throw new GatewayAdminError();
    return payload.route;
  }
}
