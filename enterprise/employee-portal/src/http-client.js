/**
 * Employee Portal - HTTP client wrapper for upstream services
 */

export class HttpError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = "HttpError";
    this.statusCode = options.statusCode || 500;
    this.code = options.code || "http_error";
  }
}

/**
 * Fetch JSON from an upstream service.
 */
export async function fetchJson(url, options = {}) {
  const { headers = {}, timeoutMs = 10000 } = options;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      ...options,
      headers: { "content-type": "application/json", ...headers },
      signal: controller.signal,
    });
    let body;
    try {
      body = await resp.json();
    } catch {
      if (!resp.ok) throw new HttpError(`HTTP ${resp.status}`, { statusCode: resp.status });
      return null;
    }
    if (!resp.ok) {
      const err = body?.error;
      throw new HttpError(
        err?.message || `HTTP ${resp.status}`,
        { statusCode: resp.status, code: err?.code || "upstream_error" }
      );
    }
    return body;
  } finally {
    clearTimeout(timeout);
  }
}
