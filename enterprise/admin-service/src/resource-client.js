// Read-only client for the enterprise resource catalog and client sync
// control plane (M3-C-2). It only issues GET requests with the service token
// and never returns resource bodies, signing keys, or the token itself.

const DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

export class ResourceServiceError extends Error {
  constructor(message = "The resource service is unavailable", options = {}) {
    super(message);
    this.name = "ResourceServiceError";
    this.statusCode = Number.isInteger(options.statusCode) ? options.statusCode : 503;
    this.code = typeof options.code === "string" && options.code
      ? options.code
      : "resource_service_unavailable";
  }
}

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

async function readJson(response, maxBytes) {
  const declared = Number(response.headers?.get?.("content-length") || 0);
  if (Number.isFinite(declared) && declared > maxBytes) {
    response.body?.cancel?.();
    throw new ResourceServiceError("The resource service response is too large");
  }
  const reader = response.body?.getReader?.();
  if (!reader) throw new ResourceServiceError("The resource service response is unreadable");
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      reader.cancel().catch(() => {});
      throw new ResourceServiceError("The resource service response is too large");
    }
    chunks.push(value);
  }
  const text = new TextDecoder("utf8").decode(Buffer.concat(chunks.map((c) => Buffer.from(c))));
  return JSON.parse(text);
}

export class ResourceServiceClient {
  constructor(config) {
    this.config = config;
  }

  get enabled() {
    return Boolean(this.config?.enabled);
  }

  // A 404 from the upstream is a real answer about one record and is passed
  // through as its own error code; everything else (timeout, non-JSON,
  // oversized body, 5xx, unexpected shape) fails closed as unavailable and is
  // never rendered as an empty catalog.
  async get(pathname) {
    if (!this.enabled) {
      throw new ResourceServiceError();
    }
    const maxBytes = Number.isFinite(Number(this.config.maxResponseBytes))
      && this.config.maxResponseBytes > 0
      ? this.config.maxResponseBytes
      : DEFAULT_MAX_RESPONSE_BYTES;
    let response;
    try {
      response = await fetch(new URL(pathname, this.config.url), {
        method: "GET",
        headers: {
          accept: "application/json",
          authorization: `Bearer ${this.config.token}`,
        },
        redirect: "error",
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch {
      throw new ResourceServiceError();
    }
    if (response.status === 404) {
      response.body?.cancel?.().catch?.(() => {});
      throw new ResourceServiceError("The resource service did not find the record", {
        statusCode: 404,
        code: "not_found",
      });
    }
    let payload;
    try {
      payload = await readJson(response, maxBytes);
    } catch {
      throw new ResourceServiceError();
    }
    if (!response.ok || response.status >= 500 || !plainObject(payload) || payload.ok !== true) {
      throw new ResourceServiceError();
    }
    return payload;
  }

  async listResources() {
    const payload = await this.get("/api/v1/admin/resources");
    if (!Array.isArray(payload.resources)) throw new ResourceServiceError();
    return payload.resources;
  }

  async getResource(resourceId) {
    const payload = await this.get(
      `/api/v1/admin/resources/${encodeURIComponent(resourceId)}`,
    );
    if (!plainObject(payload.resource)) throw new ResourceServiceError();
    return payload;
  }

  async listSyncReports() {
    const payload = await this.get("/api/v1/admin/sync-reports");
    if (!Array.isArray(payload.reports)) throw new ResourceServiceError();
    return payload.reports;
  }

  async getSyncReport(deviceId) {
    const payload = await this.get(
      `/api/v1/admin/sync-reports/${encodeURIComponent(deviceId)}`,
    );
    if (!plainObject(payload.report)) throw new ResourceServiceError();
    return payload.report;
  }

  // A write names its actor and idempotency key: the resource service
  // audits both, and a retried write with the same key changes nothing
  // twice. Upstream validation codes are passed through where they are
  // safe to show; a 5xx is "unavailable" and never a success.
  async send(pathname, body, { actor, idempotencyKey }) {
    if (!this.enabled) {
      throw new ResourceServiceError();
    }
    let response;
    try {
      response = await fetch(new URL(pathname, this.config.url), {
        method: "POST",
        headers: {
          accept: "application/json",
          "content-type": "application/json",
          authorization: `Bearer ${this.config.token}`,
          "x-magpie-actor": actor,
          "idempotency-key": idempotencyKey,
        },
        body: JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch {
      throw new ResourceServiceError();
    }
    let payload;
    try {
      payload = await readJson(response, DEFAULT_MAX_RESPONSE_BYTES);
    } catch {
      payload = null;
    }
    if (response.status === 404) {
      throw new ResourceServiceError("The resource service did not find the record", {
        statusCode: 404,
        code: "not_found",
      });
    }
    if (!response.ok) {
      const code = typeof payload?.error?.code === "string"
        && /^[a-z][a-z0-9_.-]{0,63}$/.test(payload.error.code)
        ? payload.error.code
        : "resource_service_rejected";
      throw new ResourceServiceError("The resource service rejected the change", {
        statusCode: response.status >= 500 ? 503 : response.status,
        code,
      });
    }
    if (!plainObject(payload) || payload.ok !== true) throw new ResourceServiceError();
    return payload;
  }

  createResource(body, options) {
    return this.send("/api/v1/admin/resources", body, options);
  }

  createRelease(resourceId, body, options) {
    return this.send(
      `/api/v1/admin/resources/${encodeURIComponent(resourceId)}/releases`,
      body,
      options,
    );
  }

  publishRelease(resourceId, body, options) {
    return this.send(
      `/api/v1/admin/resources/${encodeURIComponent(resourceId)}/publish`,
      body,
      options,
    );
  }

  rollbackRelease(resourceId, body, options) {
    return this.send(
      `/api/v1/admin/resources/${encodeURIComponent(resourceId)}/rollback`,
      body,
      options,
    );
  }
}
