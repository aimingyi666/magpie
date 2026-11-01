export class DependencyError extends Error {
  constructor(message = "The authentication service is unavailable") {
    super(message);
    this.statusCode = 502;
    this.code = "dependency_unavailable";
  }
}

export class AuthServiceClient {
  constructor(config) {
    this.config = config;
  }

  async request(pathname, method, collection) {
    let response;
    try {
      response = await fetch(new URL(pathname, this.config.url), {
        method,
        headers: {
          accept: "application/json",
          authorization: `Bearer ${this.config.token}`,
        },
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch {
      throw new DependencyError();
    }
    if (!response.ok) throw new DependencyError();
    let body;
    try {
      body = await response.json();
    } catch {
      throw new DependencyError();
    }
    if (!body || body.ok !== true) throw new DependencyError();
    if (collection && !Array.isArray(body[collection])) throw new DependencyError();
    return body;
  }

  async get(pathname, collection) {
    return this.request(pathname, "GET", collection);
  }

  async post(pathname) {
    return this.request(pathname, "POST");
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
}
