// Signing in: OIDC Authorization Code + PKCE in the system browser, the
// code handed to the corporate server, and the device token it answers
// kept as this machine's gateway key.
//
// The server exchanges the code with the identity provider, so its client
// secret never reaches an employee's computer; this side holds only the
// verifier it made and the token it is given.
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { CorpError, createClient } from "./client.mjs";
import { deviceUsable } from "./store.mjs";

const JOIN_TIMEOUT_MS = 180000;

function base64url(buffer) {
  return Buffer.from(buffer).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomToken(bytes) {
  return base64url(crypto.randomBytes(bytes));
}

export async function pkce() {
  const verifier = randomToken(32);
  const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

// openBrowser hands a URL to the system's default browser. A machine with
// no browser (a headless build) gets the address back to show instead.
export function openBrowser(url, { platform = process.platform, spawnFn = spawn } = {}) {
  try {
    if (platform === "win32") {
      // the URL is quoted for cmd: an unquoted "&" in a query string would
      // end the command, and the browser would open a truncated address
      spawnFn("cmd", ["/c", "start", "", `"${url}"`], { detached: true, stdio: "ignore", windowsVerbatimArguments: true }).unref?.();
    } else if (platform === "darwin") {
      spawnFn("open", [url], { detached: true, stdio: "ignore" }).unref?.();
    } else {
      spawnFn("xdg-open", [url], { detached: true, stdio: "ignore" }).unref?.();
    }
    return true;
  } catch {
    return false;
  }
}

export function createJoiner({ config, store, dir }) {
  let pending = null;

  function client(token) {
    return createClient({
      baseUrl: config.baseUrl,
      getToken: () => token,
    });
  }

  // signIn runs the whole flow and answers the device token. Called from
  // the sign-in magpie shows for this provider, so the browser is already
  // what the user expects to see.
  async function signIn() {
    if (pending) return pending.promise;
    if (!config.baseUrl) {
      throw new CorpError("base_url_required", "Set the corporate server address first (in this plugin's options)");
    }
    const { verifier, challenge } = await pkce();
    const state = randomToken(24);
    const nonce = randomToken(24);
    const redirectUri = `http://127.0.0.1:${config.servicePort}/oidc/callback`;
    const authority = config.oidc;
    if (!authority?.authorizationEndpoint || !authority?.clientId) {
      throw new CorpError("oidc_not_configured", "The server hasn't published its sign-in yet; sync once with it reachable");
    }
    const url = new URL(authority.authorizationEndpoint);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", authority.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("scope", (authority.scopes || ["openid", "profile", "email"]).join(" "));
    url.searchParams.set("state", state);
    url.searchParams.set("nonce", nonce);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
    if (authority.acrValues) url.searchParams.set("acr_values", authority.acrValues);

    let settle;
    const promise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending = null;
        reject(new CorpError("sign_in_timeout", "The browser didn't finish signing in"));
      }, JOIN_TIMEOUT_MS);
      settle = {
        resolve: (value) => {
          clearTimeout(timer);
          pending = null;
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          pending = null;
          reject(error);
        },
      };
    });
    pending = { state, verifier, redirectUri, promise, settle };
    pending.nonce = nonce;

    if (!openBrowser(url.toString())) {
      settle?.reject?.(new CorpError("no_browser", `Open this address to sign in: ${url.toString()}`));
      return promise;
    }
    return promise;
  }

  // handleCallback is the loopback service's /oidc/callback: it checks the
  // state, trades the code for a device token, and answers the page's
  // redirect.
  async function handleCallback(params) {
    if (!pending) return { ok: false, code: "no_sign_in", message: "No sign-in is waiting" };
    const state = String(params.get("state") || "");
    if (state !== pending.state) return { ok: false, code: "invalid_state", message: "This sign-in answer isn't the one that was asked for" };
    const failed = params.get("error");
    if (failed) {
      pending.settle.reject(new CorpError(String(failed), String(params.get("error_description") || failed)));
      return { ok: false, code: "denied", message: String(failed) };
    }
    const code = String(params.get("code") || "");
    if (!code) {
      pending.settle.reject(new CorpError("no_code", "The identity provider sent no code"));
      return { ok: false, code: "no_code", message: "The identity provider sent no code" };
    }
    try {
      const device = await enroll({
        code,
        codeVerifier: pending.verifier,
        redirectUri: pending.redirectUri,
        nonce: pending.nonce,
      });
      store.saveDevice(device);
      pending.settle.resolve(device.deviceToken);
      return { ok: true, device };
    } catch (error) {
      const said = error instanceof CorpError ? error : new CorpError("enroll_failed", String(error?.message || error));
      pending.settle.reject(said);
      return { ok: false, code: said.code, message: said.message };
    }
  }

  async function enroll({ code, codeVerifier, redirectUri, nonce }) {
    const api = client("");
    const { payload } = await api.request("/api/v1/device/enroll", {
      method: "POST",
      token: "",
      body: {
        schemaVersion: 1,
        code,
        codeVerifier,
        redirectUri,
        ...(nonce ? { nonce } : {}),
        device: {
          name: hostName(),
          platform: process.platform,
          clientVersion: "corp-plugin-0.1.0",
        },
      },
    });
    if (!payload || typeof payload.deviceToken !== "string" || !payload.deviceToken) {
      throw new CorpError("bad_enroll", "The server enrolled this device without a token");
    }
    return {
      deviceId: String(payload.deviceId || ""),
      deviceToken: payload.deviceToken,
      expiresAt: String(payload.expiresAt || ""),
      refreshAfter: String(payload.refreshAfter || ""),
      user: payload.user || null,
      gateway: payload.gateway || null,
      enrolledAt: new Date().toISOString(),
    };
  }

  // demoSignIn enrolls without a browser when the server published
  // demoSignIn. The "code" is demo:<email>; production refuses this the
  // moment a client secret is configured.
  async function demoSignIn(email, { admin = false } = {}) {
    const address = String(email || "").trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(address)) {
      throw new CorpError("demo_email_invalid", "Use an email like someone@corp.example");
    }
    const device = await enroll({
      code: `${admin ? "demo-admin" : "demo"}:${address}`,
      codeVerifier: "",
      redirectUri: `http://127.0.0.1:${config.servicePort}/oidc/callback`,
    });
    store.saveDevice(device);
    return device;
  }

  // current answers the device in use, signing in first when there is
  // none that still works.
  async function current() {
    const device = store.device();
    if (deviceUsable(device)) return device;
    const token = await signIn();
    return store.device() || { deviceToken: token };
  }

  // refresh asks the corporate server for a new gateway key and keeps the
  // device record. Magpie calls this with the oauth-shaped sign-in it
  // stored from authorize; the answer is the fields to keep over it.
  async function refresh(stored) {
    const token = String(stored?.refresh || stored?.access || store.device()?.deviceToken || "");
    if (!token) {
      const err = new CorpError("not_enrolled", "No device token to refresh");
      err.signIn = "expired";
      throw err;
    }
    const api = client(token);
    let payload;
    try {
      ({ payload } = await api.request("/api/v1/device/refresh", {
        method: "POST",
        token,
        body: { schemaVersion: 1, deviceToken: token },
      }));
    } catch (error) {
      if (error instanceof CorpError && (error.code === "device_token_expired" || error.code === "invalid_device_token" || error.status === 401)) {
        error.signIn = "expired";
      }
      throw error;
    }
    if (!payload || typeof payload.deviceToken !== "string" || !payload.deviceToken) {
      throw new CorpError("bad_refresh", "The server refreshed this device without a token");
    }
    const previous = store.device() || {};
    const device = {
      ...previous,
      deviceId: String(payload.deviceId || previous.deviceId || ""),
      deviceToken: payload.deviceToken,
      expiresAt: String(payload.expiresAt || ""),
      refreshAfter: String(payload.refreshAfter || ""),
      user: payload.user || previous.user || null,
      gateway: payload.gateway || previous.gateway || null,
      enrolledAt: previous.enrolledAt || new Date().toISOString(),
    };
    store.saveDevice(device);
    const expires = Date.parse(device.expiresAt);
    return {
      type: "success",
      refresh: device.deviceToken,
      access: device.deviceToken,
      expires: Number.isFinite(expires) ? expires : Date.now() + 90 * 24 * 3600 * 1000,
    };
  }

  function status() {
    const device = store.device();
    return {
      enrolled: Boolean(device),
      usable: deviceUsable(device),
      deviceId: device?.deviceId || "",
      email: device?.user?.email || "",
      name: device?.user?.name || "",
      department: device?.user?.department || "",
      groups: Array.isArray(device?.user?.groups) ? device.user.groups : [],
      role: device?.user?.role || "member",
      gateway: device?.gateway?.baseUrl || "",
      enrolledAt: device?.enrolledAt || "",
      refreshAfter: device?.refreshAfter || "",
      expiresAt: device?.expiresAt || "",
    };
  }

  return { signIn, demoSignIn, handleCallback, current, refresh, status };
}

function hostName() {
  try {
    return process.env.COMPUTERNAME || process.env.HOSTNAME || "";
  } catch {
    return "";
  }
}
