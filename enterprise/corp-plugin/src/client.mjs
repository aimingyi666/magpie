// The one way this plugin talks to the corporate server.
//
// Every call is a JSON request against the base the server published,
// authenticated with the device token, with a deadline and at most one
// retry when the answer said it was retryable. Redirects are refused: a
// device token must not be carried to a host nobody pinned.
import { safeBase } from "./config.mjs";

export class CorpError extends Error {
  constructor(code, message, { status = 0, retryable = false } = {}) {
    super(message || code);
    this.name = "CorpError";
    this.code = code;
    this.status = status;
    this.retryable = retryable;
  }
}

const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
const MAX_BODY = 8 << 20;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function createClient({ baseUrl, getToken, timeoutMs = 15000, retries = 1, now = Date.now }) {
  const base = safeBase(baseUrl);
  if (!base) throw new CorpError("base_url_required", "The corporate server address is missing or is not https");

  async function once(pathname, { method = "GET", body, token, headers = {}, signal } = {}) {
    const url = new URL(pathname.replace(/^\/+/, ""), `${base}/`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    if (signal) signal.addEventListener("abort", () => controller.abort(), { once: true });
    const sent = {
      accept: "application/json",
      ...headers,
    };
    if (body !== undefined) sent["content-type"] = "application/json";
    const bearer = token === undefined ? await getToken?.() : token;
    if (bearer) sent.authorization = `Bearer ${bearer}`;
    try {
      const response = await fetch(url, {
        method,
        headers: sent,
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "error",
        signal: controller.signal,
      });
      const text = await response.text();
      if (text.length > MAX_BODY) throw new CorpError("response_too_large", "The server answered more than this client reads");
      let payload = null;
      if (text.trim()) {
        try {
          payload = JSON.parse(text);
        } catch {
          throw new CorpError("bad_response", `The server answered something this client can't read (${response.status})`, { status: response.status });
        }
      }
      if (response.status === 304) return { status: 304, payload: null };
      if (response.ok) return { status: response.status, payload };
      const code = payload?.error?.code || `http_${response.status}`;
      const retryable = payload?.error?.retryable === true || RETRYABLE_STATUS.has(response.status);
      throw new CorpError(code, payload?.error?.message || `The server answered ${response.status}`, {
        status: response.status,
        retryable,
      });
    } catch (error) {
      if (error instanceof CorpError) throw error;
      if (error?.name === "AbortError") {
        throw new CorpError("timeout", "The corporate server didn't answer in time", { retryable: true });
      }
      throw new CorpError("unreachable", "The corporate server is unreachable", { retryable: true });
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    base,
    // request is once, then once more when the answer said the same
    // request may work later.
    async request(pathname, options = {}) {
      let last;
      for (let attempt = 0; attempt <= retries; attempt++) {
        try {
          return await once(pathname, options);
        } catch (error) {
          last = error;
          if (!(error instanceof CorpError) || !error.retryable || attempt === retries) throw error;
          await sleep(400 * (attempt + 1));
        }
      }
      throw last;
    },

    // discover reads what the server says about itself. No token: this is
    // how a machine learns where to sign in.
    async discover() {
      const { payload } = await once("/api/v1/corp/config", { token: "" });
      return payload;
    },
  };
}
