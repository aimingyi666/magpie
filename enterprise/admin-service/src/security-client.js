/**
 * M8 - Security Service Client for Admin Console
 * 
 * Provides integration with the security-service alerts and findings APIs.
 */

export class SecurityServiceError extends Error {
  constructor(message = "The security service is unavailable", options = {}) {
    super(message);
    this.name = "SecurityServiceError";
    this.statusCode = Number.isInteger(options.statusCode) ? options.statusCode : 502;
    this.code = typeof options.code === "string" && options.code
      ? options.code
      : "dependency_unavailable";
  }
}

export class SecurityServiceClient {
  constructor(config) {
    this.config = config;
  }

  async request(pathname, method, body) {
    let response;
    try {
      const headers = {
        accept: "application/json",
        authorization: `Bearer ${this.config.token}`,
        "content-type": "application/json",
      };
      response = await fetch(new URL(pathname, this.config.url), {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch {
      throw new SecurityServiceError();
    }
    let responseBody;
    try {
      responseBody = await response.json();
    } catch {
      if (!response.ok) {
        throw new SecurityServiceError("The security service returned an error", {
          statusCode: response.status,
          code: "security_rejected",
        });
      }
      throw new SecurityServiceError("The security service returned malformed JSON");
    }
    if (!response.ok) {
      const error = responseBody?.error;
      if (response.status >= 500) throw new SecurityServiceError();
      throw new SecurityServiceError(
        typeof error?.message === "string" && error.message
          ? error.message
          : "The security service rejected the request",
        {
          statusCode: response.status,
          code: typeof error?.code === "string" && error.code
            ? error.code
            : "security_rejected",
        },
      );
    }
    return responseBody;
  }

  // Alert endpoints
  async listAlerts(params = {}) {
    const searchParams = new URLSearchParams();
    if (params.status) searchParams.set("status", params.status);
    if (params.severity) searchParams.set("severity", params.severity);
    if (params.ruleId) searchParams.set("ruleId", params.ruleId);
    if (params.subjectId) searchParams.set("subjectId", params.subjectId);
    if (params.assigneeSubjectId) searchParams.set("assigneeSubjectId", params.assigneeSubjectId);
    if (params.unassigned !== undefined) searchParams.set("unassigned", String(params.unassigned));
    if (params.overdue !== undefined) searchParams.set("overdue", String(params.overdue));
    if (params.activeOnly !== undefined) searchParams.set("activeOnly", String(params.activeOnly));
    if (params.limit) searchParams.set("limit", String(params.limit));
    
    const url = `/api/v1/alerts?${searchParams.toString()}`;
    return this.request(url, "GET");
  }

  async getAlert(alertId) {
    return this.request(`/api/v1/alerts/${encodeURIComponent(alertId)}`, "GET");
  }

  async getAlertAudit(alertId) {
    return this.request(`/api/v1/alerts/${encodeURIComponent(alertId)}/audit`, "GET");
  }

  async assignAlert(alertId, body) {
    return this.request(`/api/v1/alerts/${encodeURIComponent(alertId)}/assign`, "POST", body);
  }

  async acknowledgeAlert(alertId, body) {
    return this.request(`/api/v1/alerts/${encodeURIComponent(alertId)}/acknowledge`, "POST", body);
  }

  async resolveAlert(alertId, body) {
    return this.request(`/api/v1/alerts/${encodeURIComponent(alertId)}/resolve`, "POST", body);
  }

  async reopenAlert(alertId, body) {
    return this.request(`/api/v1/alerts/${encodeURIComponent(alertId)}/reopen`, "POST", body);
  }

  // Findings endpoints
  async listFindings(params = {}) {
    const searchParams = new URLSearchParams();
    if (params.ruleId) searchParams.set("ruleId", params.ruleId);
    if (params.severity) searchParams.set("severity", params.severity);
    if (params.subjectId) searchParams.set("subjectId", params.subjectId);
    if (params.limit) searchParams.set("limit", String(params.limit));
    
    const url = `/api/v1/findings?${searchParams.toString()}`;
    return this.request(url, "GET");
  }

  // Rules endpoints
  async describeRules() {
    return this.request("/api/v1/rules", "GET");
  }

  // Metrics endpoint
  async getMetrics() {
    return this.request("/metrics", "GET");
  }
}
