// The desktop administrator session.
//
// The page never holds the management token, the OIDC secret or a provider
// key: this process keeps the token in memory, talks to the management
// service, and answers the page with a projection. Sign-in happens in the
// system browser; the management service returns a one-time ticket to this
// loopback service, which exchanges it with a PKCE verifier that never left
// this process.

import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { readCredential, readSyncConfig } from "./config.mjs";

export const ADMIN_PREFIX = "/v1/admin";
export const LOGIN_CALLBACK_PATH = "/v1/admin/login/callback";

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 15000;

export class AdminError extends Error {
  constructor(message, { status = 502, code = "admin_unavailable" } = {}) {
    super(message);
    this.name = "AdminError";
    this.status = status;
    this.code = code;
  }
}

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

// adminBaseUrl is where the management service answers. An enterprise can
// pin it in enterprise-sync.json or the device credential; the credential's
// auth URL's origin is the last resort, and is only used when it is https
// or a loopback address.
export function adminBaseUrl({ env = process.env, config = null, credential = null } = {}) {
  const candidates = [
    env.MAGPIE_ENTERPRISE_ADMIN_URL,
    config?.adminBaseUrl,
    credential?.adminUrl,
  ];
  for (const candidate of candidates) {
    const value = String(candidate || "").trim();
    if (!value) continue;
    try {
      const url = new URL(value);
      if (url.protocol !== "https:" && url.protocol !== "http:") continue;
      if (url.protocol === "http:" && !isLoopback(url.hostname)) continue;
      if (url.username || url.password) continue;
      return url.toString().replace(/\/+$/, "");
    } catch {
      continue;
    }
  }
  return "";
}

function isLoopback(host) {
  return host === "127.0.0.1" || host === "localhost" || host === "[::1]" || host === "::1";
}

// adminConfiguredFromState finds the management console address on this
// machine: enterprise-sync.json first, then the joined device credential's
// auth URL. It answers "" rather than guessing; a wrong address would send
// an administrator's token to a stranger.
export function adminConfiguredFromState(dir) {
  const sync = readSyncConfig(dir);
  if (sync.state === "ok" && sync.adminBaseUrl) return sync.adminBaseUrl;
  const credential = readCredential(dir);
  if (credential.state === "ok") return adminBaseUrl({ credential: credential.data });
  return "";
}

async function readJson(response, maxBytes) {
  const declared = Number(response.headers?.get?.("content-length") || 0);
  if (Number.isFinite(declared) && declared > maxBytes) {
    response.body?.cancel?.().catch?.(() => {});
    throw new AdminError("The management service answer is too large", {
      status: 502,
      code: "admin_invalid_response",
    });
  }
  const reader = response.body?.getReader?.();
  if (!reader) {
    throw new AdminError("The management service answer is unreadable", {
      status: 502,
      code: "admin_invalid_response",
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
      throw new AdminError("The management service answer is too large", {
        status: 502,
        code: "admin_invalid_response",
      });
    }
    chunks.push(Buffer.from(value));
  }
  const text = Buffer.concat(chunks).toString("utf8");
  try {
    return JSON.parse(text);
  } catch {
    throw new AdminError("The management service answer is not JSON", {
      status: 502,
      code: "admin_invalid_response",
    });
  }
}

const PASS_THROUGH = /^(?:not_signed_in|session_expired|session_idle|session_binding_mismatch|csrf_invalid|forbidden_role|forbidden_scope|step_up_required|step_up_expired|step_up_unavailable|step_up_binding_mismatch|approval_required|revision_conflict|revision_required|invalid_[a-z_]{1,40}|not_found|gateway_[a-z_]{1,40}|desktop_[a-z_]{1,40}|ambiguous_session|timeout|unavailable)$/;

function failureFrom(status, payload) {
  const upstream = plainObject(payload?.error) ? payload.error : {};
  const code = typeof upstream.code === "string" && PASS_THROUGH.test(upstream.code)
    ? upstream.code
    : "admin_invalid_response";
  const messages = {
    not_signed_in: "Sign in to the management console",
    session_expired: "The administrator session expired; sign in again",
    session_idle: "The administrator session went idle; sign in again",
    desktop_token_expired: "The administrator session expired; sign in again",
    desktop_token_idle: "The administrator session went idle; sign in again",
    desktop_token_invalid: "The administrator session is no longer valid; sign in again",
    desktop_token_revoked: "The administrator signed out or was revoked; sign in again",
    revision_conflict: "The configuration changed; refresh and try again",
    step_up_required: "Re-authenticate before this change",
    step_up_expired: "Recent authentication expired; re-authenticate",
    approval_required: "This change needs an approved approvalId",
    gateway_unavailable: "The enterprise gateway is unreachable",
    timeout: "The enterprise gateway did not answer in time",
  };
  return new AdminError(messages[code] || "The management service refused the request", {
    status,
    code,
  });
}

// transportFailure keeps a timeout or a refused redirect from looking like
// an unreachable console: each is a closed failure with its own code, so
// the page can say what happened without guessing.
function transportFailure(error) {
  const name = String(error?.name || "");
  const message = `${error?.message || ""} ${error?.cause?.message || ""}`;
  if (name === "TimeoutError" || name === "AbortError") {
    return new AdminError("The management service did not answer in time", {
      status: 504,
      code: "timeout",
    });
  }
  if (/redirect/i.test(message)) {
    return new AdminError("The management service answered with a redirect", {
      status: 502,
      code: "admin_invalid_response",
    });
  }
  return new AdminError("The management service is unreachable", {
    status: 503,
    code: "admin_unavailable",
  });
}

export class AdminSession {
  constructor({
    baseUrl,
    resolveBaseUrl = null,
    openBrowser = openInBrowser,
    log = () => {},
    timeoutMs = DEFAULT_TIMEOUT_MS,
  } = {}) {
    // baseUrl is what was pinned when the service started, kept for a
    // newly configured console to be found without restarting Magpie;
    // resolveBaseUrl is read again on every status, so an address written
    // into enterprise-sync.json takes effect at once.
    this.pinnedBaseUrl = String(baseUrl || "");
    this.resolveBaseUrl = typeof resolveBaseUrl === "function" ? resolveBaseUrl : null;
    this.timeoutMs = timeoutMs;
    this.lastBaseUrl = this.pinnedBaseUrl;
    this.openBrowser = openBrowser;
    this.log = log;
    this.token = "";
    this.expiresAt = "";
    this.user = null;
    this.roles = [];
    this.permissions = [];
    this.pending = null;
  }

  // baseUrl is where the management service answers now. A token belongs
  // to one console: if the address changes the session is dropped, since
  // the token would otherwise be sent to a different server.
  get baseUrl() {
    let found = this.pinnedBaseUrl;
    if (this.resolveBaseUrl) {
      try {
        found = String(this.resolveBaseUrl() || "") || found;
      } catch {
        found = this.pinnedBaseUrl;
      }
    }
    if (this.lastBaseUrl && found !== this.lastBaseUrl) {
      this.forgetSession();
    }
    if (found) this.lastBaseUrl = found;
    return found;
  }

  forgetSession() {
    this.token = "";
    this.expiresAt = "";
    this.user = null;
    this.roles = [];
    this.permissions = [];
    this.pending = null;
  }

  get configured() {
    return Boolean(this.baseUrl);
  }

  status() {
    const baseUrl = this.baseUrl;
    return {
      configured: Boolean(baseUrl),
      signedIn: Boolean(this.token),
      expiresAt: this.expiresAt || null,
      user: this.user,
      roles: this.roles,
      permissions: this.permissions,
      loginPending: Boolean(this.pending),
      adminUrl: baseUrl,
    };
  }

  // startLogin makes the PKCE verifier, tells the management service where
  // to send the ticket, and opens the system browser. The callback lands on
  // this service, which finishes the exchange.
  async startLogin(callbackUrl) {
    if (!this.configured) {
      throw new AdminError("The management console address is not configured", {
        status: 409,
        code: "admin_not_configured",
      });
    }
    const verifier = crypto.randomBytes(48).toString("base64url");
    const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
    this.pending = { verifier, createdAt: Date.now() };
    const target = new URL("/admin/desktop/login", this.baseUrl);
    target.searchParams.set("callbackUrl", callbackUrl);
    target.searchParams.set("codeChallenge", challenge);
    try {
      await this.openBrowser(target.toString());
    } catch (error) {
      this.pending = null;
      throw new AdminError("The browser could not be opened", {
        status: 500,
        code: "browser_unavailable",
      });
    }
    this.log("enterprise admin sign-in started in the system browser");
    return { loginUrl: target.toString() };
  }

  // finishLogin takes the one-time ticket the browser brought back.
  async finishLogin(ticket) {
    if (!this.pending || Date.now() - this.pending.createdAt > 10 * 60 * 1000) {
      this.pending = null;
      throw new AdminError("The sign-in did not start here, or expired", {
        status: 400,
        code: "desktop_ticket_invalid",
      });
    }
    const verifier = this.pending.verifier;
    this.pending = null;
    let response;
    try {
      response = await fetch(new URL("/api/v1/desktop/token", this.baseUrl), {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({ ticket, codeVerifier: verifier }),
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw transportFailure(error);
    }
    let payload;
    try {
      payload = await readJson(response, MAX_RESPONSE_BYTES);
    } catch (error) {
      // A refusal is still a refusal when its body is not JSON; a success
      // that cannot be read is not a success.
      if (response.ok) {
        throw error instanceof AdminError ? error : transportFailure(error);
      }
      payload = null;
    }
    if (!response.ok || !plainObject(payload) || typeof payload.token !== "string") {
      throw failureFrom(response.status, payload);
    }
    this.token = payload.token;
    this.expiresAt = String(payload.expiresAt || "");
    this.user = plainObject(payload.user) ? payload.user : null;
    await this.refreshMe().catch(() => {});
    return this.status();
  }

  async refreshMe() {
    const payload = await this.request("GET", "/api/v1/desktop/me");
    this.user = plainObject(payload.user) ? payload.user : this.user;
    this.roles = Array.isArray(payload.roles) ? payload.roles.map(String) : [];
    this.permissions = Array.isArray(payload.permissions) ? payload.permissions.map(String) : [];
    if (payload.expiresAt) this.expiresAt = String(payload.expiresAt);
    return payload;
  }

  async signOut() {
    if (this.token) {
      await this.request("DELETE", "/api/v1/desktop/token").catch(() => {});
    }
    this.token = "";
    this.expiresAt = "";
    this.user = null;
    this.roles = [];
    this.permissions = [];
    this.pending = null;
  }

  // request is the only way the page's actions reach the management
  // service. It refuses to run without a token and drops the token the
  // moment the service says it is no longer valid.
  async request(method, pathname, body) {
    if (!this.configured) {
      throw new AdminError("The management console address is not configured", {
        status: 409,
        code: "admin_not_configured",
      });
    }
    if (!this.token) {
      throw new AdminError("Sign in to the management console", {
        status: 401,
        code: "not_signed_in",
      });
    }
    if (!pathname.startsWith("/api/v1/")) {
      throw new AdminError("Not an administration route", { status: 404, code: "not_found" });
    }
    const headers = {
      accept: "application/json",
      authorization: `Bearer ${this.token}`,
    };
    if (body !== undefined) headers["content-type"] = "application/json";
    let response;
    try {
      response = await fetch(new URL(pathname, this.baseUrl), {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw transportFailure(error);
    }
    let payload;
    try {
      payload = await readJson(response, MAX_RESPONSE_BYTES);
    } catch (error) {
      if (response.ok) {
        throw error instanceof AdminError ? error : transportFailure(error);
      }
      payload = null;
    }
    if (!response.ok) {
      if (response.status === 401) {
        this.token = "";
        this.expiresAt = "";
        this.user = null;
        this.roles = [];
        this.permissions = [];
      }
      throw failureFrom(response.status, payload);
    }
    return payload;
  }
}

// openInBrowser hands the URL to the operating system. A desktop app should
// sign in where the user's password manager and MFA live, not in a web
// view this plugin controls.
export function openInBrowser(url) {
  return new Promise((resolve, reject) => {
    let command;
    let args;
    if (process.platform === "win32") {
      command = "rundll32.exe";
      args = ["url.dll,FileProtocolHandler", url];
    } else if (process.platform === "darwin") {
      command = "open";
      args = [url];
    } else {
      command = "xdg-open";
      args = [url];
    }
    const child = spawn(command, args, {
      windowsHide: true,
      stdio: "ignore",
      detached: true,
    });
    child.once("error", reject);
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}
