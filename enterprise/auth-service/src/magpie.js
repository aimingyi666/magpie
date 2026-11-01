export class MagpieKeyClient {
  constructor(config, fetchImpl = fetch) {
    this.config = config;
    this.fetch = fetchImpl;
  }

  async issue({ name, models, tokens, cost }) {
    const body = {
      name,
      ttl: this.config.keyTtlSeconds,
      models,
    };
    if (tokens > 0) body.tokens = tokens;
    if (cost > 0) body.cost = cost;
    const response = await this.fetch(`${this.config.gatewayUrl}/v1/magpie/keys`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.config.issuerKey}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10000),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = payload?.error?.message || payload?.error || `HTTP ${response.status}`;
      throw new Error(`Magpie could not issue a gateway key: ${message}`);
    }
    for (const field of ["id", "key", "expires"]) {
      if (!payload[field]) throw new Error(`Magpie key response is missing ${field}`);
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
