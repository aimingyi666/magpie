export class MagpieKeyClientError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = "MagpieKeyClientError";
    this.statusCode = options.statusCode || 502;
    this.code = options.code || "magpie_key_failed";
  }
}

export class MagpieKeyClient {
  constructor(config, fetchImpl = fetch) {
    this.config = config;
    this.fetch = fetchImpl;
  }

  async issue({ name, models, tokens, cost, enterpriseIssuanceId }) {
    const body = {
      name,
      ttl: this.config.keyTtlSeconds,
      models,
    };
    if (tokens > 0) body.tokens = tokens;
    if (cost > 0) body.cost = cost;
    if (enterpriseIssuanceId) body.enterpriseIssuanceId = enterpriseIssuanceId;
    let response;
    try {
      response = await this.fetch(`${this.config.gatewayUrl}/v1/magpie/keys`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.config.issuerKey}`,
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10000),
      });
    } catch (error) {
      const timedOut = error?.name === "TimeoutError" || error?.name === "AbortError";
      throw new MagpieKeyClientError(
        timedOut
          ? "Magpie key issuance timed out; the gateway result is unknown"
          : "Magpie key issuance could not be confirmed; the gateway result is unknown",
        {
          statusCode: 502,
          code: timedOut ? "magpie_issuance_timeout" : "magpie_issuance_unknown",
        },
      );
    }
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = payload?.error?.message || payload?.error || `HTTP ${response.status}`;
      const code = response.status === 409
        ? "enterprise_issuance_conflict"
        : (response.status === 400 ? "enterprise_issuance_invalid" : "magpie_key_failed");
      throw new MagpieKeyClientError(`Magpie could not issue a gateway key: ${message}`, {
        statusCode: response.status >= 400 && response.status <= 599 ? response.status : 502,
        code,
      });
    }
    for (const field of ["id", "key", "expires"]) {
      if (!payload[field]) {
        throw new MagpieKeyClientError(`Magpie key response is missing ${field}`);
      }
    }
    return payload;
  }

  async revoke(id) {
    if (!id) return;
    const response = await this.fetch(`${this.config.gatewayUrl}/v1/magpie/keys/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: {
        authorization: `Bearer ${this.config.issuerKey}`,
        accept: "application/json",
      },
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok && response.status !== 404) {
      const payload = await response.json().catch(() => ({}));
      const message = payload?.error?.message || payload?.error || `HTTP ${response.status}`;
      throw new Error(`Magpie could not revoke gateway key ${id}: ${message}`);
    }
  }
}
