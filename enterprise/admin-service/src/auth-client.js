export class DependencyError extends Error {
  constructor(message = "The authentication service is unavailable", options = {}) {
    super(message);
    this.name = "DependencyError";
    this.statusCode = Number.isInteger(options.statusCode) ? options.statusCode : 502;
    this.code = typeof options.code === "string" && options.code
      ? options.code
      : "dependency_unavailable";
  }
}

export class AuthServiceClient {
  constructor(config) {
    this.config = config;
  }

  async request(pathname, method, collection, body) {
    let response;
    try {
      const headers = {
        accept: "application/json",
        authorization: `Bearer ${this.config.token}`,
      };
      if (body !== undefined) headers["content-type"] = "application/json";
      response = await fetch(new URL(pathname, this.config.url), {
        method,
        headers,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch {
      throw new DependencyError();
    }
    let responseBody;
    try {
      responseBody = await response.json();
    } catch {
      if (!response.ok) {
        throw new DependencyError("The authentication service rejected the request", {
          statusCode: response.status,
          code: "dependency_rejected",
        });
      }
      throw new DependencyError("The authentication service returned malformed JSON");
    }
    if (!response.ok) {
      const error = responseBody?.error;
      if (response.status >= 500) throw new DependencyError();
      throw new DependencyError(
        typeof error?.message === "string" && error.message
          ? error.message
          : "The authentication service rejected the request",
        {
          statusCode: response.status,
          code: typeof error?.code === "string" && error.code
            ? error.code
            : "dependency_rejected",
        },
      );
    }
    if (!responseBody || responseBody.ok !== true) throw new DependencyError();
    if (collection && !Array.isArray(responseBody[collection])) throw new DependencyError();
    return responseBody;
  }

  async get(pathname, collection) {
    return this.request(pathname, "GET", collection);
  }

  async post(pathname, body) {
    return this.request(pathname, "POST", "", body);
  }

  async put(pathname, body) {
    return this.request(pathname, "PUT", "", body);
  }

  async patch(pathname, body) {
    return this.request(pathname, "PATCH", "", body);
  }

  status() {
    return this.get("/api/v1/internal/admin/status");
  }

  users() {
    return this.get("/api/v1/internal/admin/users", "users");
  }

  devices() {
    return this.get("/api/v1/internal/admin/devices", "devices");
  }

  credentials() {
    return this.get("/api/v1/internal/admin/credentials", "credentials");
  }

  disableUser(userId) {
    return this.post(`/api/v1/internal/admin/users/${encodeURIComponent(userId)}/disable`);
  }

  enableUser(userId) {
    return this.post(`/api/v1/internal/admin/users/${encodeURIComponent(userId)}/enable`);
  }

  revokeDevice(deviceId) {
    return this.post(`/api/v1/internal/admin/devices/${encodeURIComponent(deviceId)}/revoke`);
  }

  rotateCredential(credentialId) {
    return this.post(`/api/v1/internal/admin/credentials/${encodeURIComponent(credentialId)}/rotate`);
  }

  updateQuota(userId, body) {
    return this.put(
      `/api/v1/internal/admin/users/${encodeURIComponent(userId)}/policy/quota`,
      body,
    );
  }

  updateModels(userId, body) {
    return this.patch(
      `/api/v1/internal/admin/users/${encodeURIComponent(userId)}/policy/models`,
      body,
    );
  }

  reconcilePolicy(userId, body) {
    return this.post(
      `/api/v1/internal/admin/users/${encodeURIComponent(userId)}/policy/reconcile`,
      body,
    );
  }
}
