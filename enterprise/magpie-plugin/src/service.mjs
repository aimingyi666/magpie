import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_SERVICE_PORT,
  readCredential,
  readSyncConfig,
  setSyncAdminBaseUrl,
  stateDirectory,
} from "./config.mjs";
import { readSyncState, resourceRows } from "./status.mjs";
import { syncInProgress, syncNow } from "./sync.mjs";
import {
  ADMIN_PREFIX,
  AdminError,
  AdminSession,
  LOGIN_CALLBACK_PATH,
  adminConfiguredFromState,
  adminBaseUrl,
} from "./admin.mjs";

const PLUGIN_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PAGE_DIR = path.join(PLUGIN_ROOT, "page");

// The page is navigated here from the plugin's own page because magpie
// serves that page with connect-src 'none'. The service gives the page a
// per-run token; without it another sandboxed page on the web could read
// this computer's enterprise status by asking loopback.
const PAGE_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'self' wails://localhost http://wails.localhost https://wails.localhost",
].join("; ");

export function startService({
  port = DEFAULT_SERVICE_PORT,
  host = "127.0.0.1",
  log = () => {},
  openBrowser,
  adminUrl,
  adminTimeoutMs,
} = {}) {
  const accessToken = crypto.randomBytes(32).toString("hex");
  const admin = new AdminSession({
    baseUrl: adminUrl || adminBaseUrl() || adminConfiguredFromState(),
    resolveBaseUrl: () => adminUrl || adminBaseUrl() || adminConfiguredFromState(),
    openBrowser,
    log,
    ...(Number.isInteger(adminTimeoutMs) && adminTimeoutMs > 0 ? { timeoutMs: adminTimeoutMs } : {}),
  });
  const server = http.createServer((req, res) => {
    handle(req, res, { accessToken, admin, host }).catch((error) => {
      if (error instanceof AdminError) {
        return sendError(res, error.status, error.code, error.message);
      }
      sendError(res, 500, "internal_error", String(error?.message || error));
    });
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;
  server.keepAliveTimeout = 5_000;

  return new Promise((resolve, reject) => {
    const failed = (error) => {
      server.off("listening", listened);
      reject(error);
    };
    const listened = () => {
      server.off("error", failed);
      const actual = server.address();
      const actualPort = actual && typeof actual === "object" ? actual.port : port;
      log(`enterprise plugin service listening on http://${host}:${actualPort}`);
      resolve({
        server,
        port: actualPort,
        admin,
        close: () => new Promise((done) => server.close(() => done())),
      });
    };
    server.once("error", failed);
    server.once("listening", listened);
    server.listen(port, host);
  });
}

async function handle(req, res, { accessToken, admin, host }) {
  const port = req.socket.localPort;
  if (!hostAllowed(req, port)) {
    return sendError(res, 403, "forbidden_host", "the Host header is not this service's");
  }
  const origin = originAllowed(req, port);
  if (origin === false) {
    return sendError(res, 403, "forbidden_origin", "the request is from another site");
  }
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
    res.setHeader("Access-Control-Allow-Headers", "x-magpie-enterprise, content-type");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE");
    res.setHeader("Vary", "Origin");
  }

  if (req.method === "OPTIONS") {
    if (!origin) return sendError(res, 403, "forbidden_origin", "the request is from another site");
    res.writeHead(204, { "cache-control": "no-store" });
    res.end();
    return;
  }

  const url = new URL(req.url, "http://127.0.0.1");

  // The administrator's browser callback. It is a top-level navigation,
  // so there is no Origin and no page token; the one-time ticket is the
  // proof, and it is exchanged by this process with its own verifier.
  if (url.pathname === LOGIN_CALLBACK_PATH) {
    if (req.method !== "GET") return sendError(res, 405, "method_not_allowed", "GET only");
    return finishAdminLogin(res, url, admin);
  }

  switch (url.pathname) {
    case "/":
    case "/ui.html":
      return sendUi(res, url, accessToken);
    case "/ui.js":
      return sendFile(res, path.join(PAGE_DIR, "ui.js"), "text/javascript; charset=utf-8");
    case "/ui.css":
      return sendFile(res, path.join(PAGE_DIR, "ui.css"), "text/css; charset=utf-8");
    case "/icon.svg":
      return sendFile(res, path.join(PAGE_DIR, "icon.svg"), "image/svg+xml");
    case "/healthz":
      return sendJson(res, 200, { ok: true });
    case "/v1/status":
      if (req.method !== "GET") return sendError(res, 405, "method_not_allowed", "GET only");
      if (!tokenAllowed(req, accessToken)) {
        return sendError(res, 403, "forbidden_token", "the request is not from the enterprise page");
      }
      return sendJson(res, 200, statusPayload());
    case "/v1/sync":
      if (req.method !== "POST") return sendError(res, 405, "method_not_allowed", "POST only");
      if (!tokenAllowed(req, accessToken)) {
        return sendError(res, 403, "forbidden_token", "the request is not from the enterprise page");
      }
      return runSync(res);
    default:
      if (url.pathname.startsWith(`${ADMIN_PREFIX}/`)) {
        if (!tokenAllowed(req, accessToken)) {
          return sendError(res, 403, "forbidden_token", "the request is not from the enterprise page");
        }
        return handleAdmin(req, res, url, { admin, host, port });
      }
      return sendError(res, 404, "not_found", "no such route");
  }
}

// hostAllowed refuses a name that resolves to this machine: the service is
// on loopback, and only loopback names reach it.
function hostAllowed(req, port) {
  const host = String(req.headers.host || "").toLowerCase();
  return host === `127.0.0.1:${port}` || host === `localhost:${port}` || host === `[::1]:${port}`;
}

// originAllowed is true when the request comes with a CORS origin this
// service may answer, false when it is another site's, and undefined when
// there is none: a navigation, a same-origin GET, or magpie web's proxy.
// The page's frame is sandboxed, so its own fetches carry Origin: null.
function originAllowed(req, port) {
  const value = req.headers.origin;
  if (value === undefined) return undefined;
  if (value === "null") return true;
  try {
    const origin = new URL(value);
    if (origin.protocol !== "http:" && origin.protocol !== "https:") return false;
    if (origin.hostname === "127.0.0.1" || origin.hostname === "localhost" || origin.hostname === "[::1]") {
      return Number(origin.port || (origin.protocol === "https:" ? 443 : 80)) === port;
    }
  } catch {
    return false;
  }
  return false;
}

function tokenAllowed(req, accessToken) {
  const given = req.headers["x-magpie-enterprise"];
  if (typeof given !== "string") return false;
  const a = Buffer.from(given, "utf8");
  const b = Buffer.from(accessToken, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function statusPayload() {
  const dir = stateDirectory();
  const credential = readCredential(dir);
  const config = readSyncConfig(dir);
  const payload = {
    schemaVersion: 1,
    configured: credential.state === "ok" && config.state === "ok",
    canSync: false,
    joined: null,
    credential: { state: credential.state, reason: credential.reason || credential.code || null },
    syncConfig: { state: config.state, reason: config.reason || config.code || null },
    sync: { state: "not_configured", busy: syncInProgress() },
    resources: [],
  };

  if (credential.state === "ok") {
    const data = credential.data;
    payload.joined = {
      email: text(data.email),
      userId: text(data.userId),
      deviceId: text(data.deviceId),
      deviceName: text(data.deviceName),
      providerId: text(data.providerId),
      authUrl: text(data.authUrl),
      gatewayUrl: text(data.gatewayUrl),
      clientVersion: text(data.clientVersion),
      tokenExpiresAt: text(data.tokenExpiresAt) || null,
    };
  }

  if (config.state !== "ok") return payload;

  const state = readSyncState(config.rootDir);
  if (state.state === "never") {
    payload.canSync = credential.state === "ok";
    payload.sync = { state: "never", busy: syncInProgress() };
    return payload;
  }
  if (state.state !== "ok") {
    payload.canSync = credential.state === "ok";
    payload.sync = { state: "unknown", reason: state.reason || state.code || state.state, busy: syncInProgress() };
    return payload;
  }

  payload.canSync = credential.state === "ok";
  payload.sync = {
    state: state.lastError ? "error" : "ok",
    busy: syncInProgress(),
    revision: state.revision,
    desiredRevision: state.desiredRevision,
    lastSuccessfulSyncAt: state.lastSuccessfulSyncAt,
    lastAttemptAt: state.lastAttemptAt,
    lastError: state.lastError,
  };
  payload.resources = resourceRows(state, config.displayNames);
  return payload;
}

async function runSync(res) {
  const dir = stateDirectory();
  const credential = readCredential(dir);
  const config = readSyncConfig(dir);
  if (credential.state !== "ok") {
    return sendError(res, 409, "not_joined", "no enterprise device credential was found; join the enterprise first");
  }
  if (config.state !== "ok") {
    return sendError(res, 409, "sync_not_configured", `enterprise-sync.json: ${config.reason || config.state}`);
  }

  let result;
  try {
    result = await syncNow({ config, credential: credential.data });
  } catch (error) {
    result = { status: "failed", error: { code: error?.code || "sync_failed" } };
  }
  return sendJson(res, 200, { ...statusPayload(), result });
}

// handleAdmin is the page's only path to the management service. Every
// route is named here; the page cannot ask for an arbitrary URL.
async function handleAdmin(req, res, url, { admin, host, port }) {
  const path = url.pathname;
  if (path === `${ADMIN_PREFIX}/status` && req.method === "GET") {
    return sendJson(res, 200, admin.status());
  }
  if (path === `${ADMIN_PREFIX}/login` && req.method === "POST") {
    const callback = `http://${host}:${port}${LOGIN_CALLBACK_PATH}`;
    const started = await admin.startLogin(callback);
    return sendJson(res, 200, { ...admin.status(), loginUrl: started.loginUrl });
  }
  // The console's address can be set here rather than by editing the
  // sync file: a device whose administrator signs in for the first time
  // has no reason to know that file exists.
  if (path === `${ADMIN_PREFIX}/console` && req.method === "PUT") {
    const body = await readRequestBody(req);
    const saved = setSyncAdminBaseUrl(stateDirectory(), body.adminUrl);
    if (saved.error === "missing") {
      return sendError(res, 409, "sync_not_configured", "join the enterprise first; there is no enterprise-sync.json");
    }
    if (saved.error === "invalid" || saved.error === "write") {
      return sendError(res, 422, "invalid_admin_url", "enterprise-sync.json could not be updated");
    }
    if (saved.error) {
      return sendError(res, 422, "invalid_admin_url", "use https, or http on this machine only");
    }
    return sendJson(res, 200, admin.status());
  }
  if (path === `${ADMIN_PREFIX}/logout` && req.method === "POST") {
    await admin.signOut();
    return sendJson(res, 200, admin.status());
  }
  if (path === `${ADMIN_PREFIX}/me` && req.method === "GET") {
    return sendJson(res, 200, await admin.request("GET", "/api/v1/desktop/me"));
  }
  // The page's reads and writes, one route per management API it may use.
  const routes = [
    ["GET", /^\/overview$/, () => admin.request("GET", "/api/v1/admin/gateway/overview")],
    ["GET", /^\/providers$/, () => admin.request("GET", "/api/v1/admin/gateway/providers")],
    ["POST", /^\/providers$/, (body) => admin.request("POST", "/api/v1/admin/gateway/providers", body)],
    ["PATCH", /^\/providers\/([a-z0-9][a-z0-9-]{0,63})$/, (body, m) =>
      admin.request("PATCH", `/api/v1/admin/gateway/providers/${m[1]}`, body)],
    ["DELETE", /^\/providers\/([a-z0-9][a-z0-9-]{0,63})$/, (body, m) =>
      admin.request("DELETE", `/api/v1/admin/gateway/providers/${m[1]}`, body)],
    ["GET", /^\/routing-groups$/, () => admin.request("GET", "/api/v1/admin/gateway/routing-groups")],
    ["POST", /^\/routing-groups$/, (body) => admin.request("POST", "/api/v1/admin/gateway/routing-groups", body)],
    ["PATCH", /^\/routing-groups\/([a-z0-9][a-z0-9.-]{0,63})$/, (body, m) =>
      admin.request("PATCH", `/api/v1/admin/gateway/routing-groups/${m[1]}`, body)],
    ["DELETE", /^\/routing-groups\/([a-z0-9][a-z0-9.-]{0,63})$/, (body, m) =>
      admin.request("DELETE", `/api/v1/admin/gateway/routing-groups/${m[1]}`, body)],
    ["GET", /^\/gateway$/, () => admin.request("GET", "/api/v1/admin/gateway")],
    ["GET", /^\/gateway\/keys$/, () => admin.request("GET", "/api/v1/admin/gateway/keys")],
    ["POST", /^\/gateway\/keys$/, (body) => admin.request("POST", "/api/v1/admin/gateway/keys", body)],
    ["PATCH", /^\/gateway\/keys\/([A-Za-z0-9_-]{1,64})$/, (body, m) =>
      admin.request("PATCH", `/api/v1/admin/gateway/keys/${m[1]}`, body)],
    // The employees' devices, as the gateway page lists them: the
    // management service scopes them to the administrator's organization.
    ["GET", /^\/devices$/, () => admin.request("GET", "/api/v1/admin/devices")],
    ["GET", /^\/requests$/, () => {
      const query = new URLSearchParams();
      for (const name of ["period", "offset", "limit", "day", "agent", "model", "provider", "callerKeyId"]) {
        const value = url.searchParams.get(name);
        if (value) query.set(name, value);
      }
      const suffix = query.toString();
      return admin.request("GET", `/api/v1/admin/gateway/requests${suffix ? `?${suffix}` : ""}`);
    }],
    ["GET", /^\/routes\/(\d{1,19})$/, (_body, m) =>
      admin.request("GET", `/api/v1/admin/gateway/routes/${m[1]}`)],
  ];
  const suffix = path.slice(ADMIN_PREFIX.length);
  for (const [method, pattern, call] of routes) {
    if (req.method !== method) continue;
    const match = pattern.exec(suffix);
    if (!match) continue;
    const body = method === "POST" || method === "PATCH" || method === "DELETE"
      ? await readRequestBody(req)
      : undefined;
    return sendJson(res, 200, await call(body, match));
  }
  return sendError(res, 404, "not_found", "no such administration route");
}

async function finishAdminLogin(res, url, admin) {
  const ticket = String(url.searchParams.get("ticket") || "").trim();
  if (!ticket) {
    return sendHtml(res, 400, loginPage(false, "The sign-in answer carried no ticket."));
  }
  try {
    const status = await admin.finishLogin(ticket);
    return sendHtml(res, 200, loginPage(true, status.user?.email || ""));
  } catch (error) {
    return sendHtml(res, 400, loginPage(false, error?.message || "The sign-in could not be completed."));
  }
}

function loginPage(ok, detail) {
  const title = ok ? "Signed in" : "Sign-in failed";
  const body = ok
    ? `You are signed in${detail ? ` as ${escapeHtml(detail)}` : ""}. You can close this tab and return to Magpie.`
    : escapeHtml(detail);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">`
    + `<meta name="viewport" content="width=device-width, initial-scale=1">`
    + `<title>${title}</title><style>`
    + `body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f5f1;color:#20211f;`
    + `font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}`
    + `main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.25rem;margin:0 0 .5rem}`
    + `p{margin:0;color:#6b6d67}</style></head><body><main><h1>${title}</h1><p>${body}</p></main></body></html>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// readRequestBody takes a bounded JSON object. The page sends small
// patches; a provider's model list is the largest of them.
async function readRequestBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > 256 * 1024) {
      throw new AdminError("The request is too large", { status: 413, code: "request_too_large" });
    }
    chunks.push(chunk);
  }
  if (total === 0) return {};
  try {
    const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("shape");
    return value;
  } catch {
    throw new AdminError("The request body is not a JSON object", {
      status: 422,
      code: "invalid_json",
    });
  }
}

function sendUi(res, url, accessToken) {
  let html;
  try {
    html = fs.readFileSync(path.join(PAGE_DIR, "ui.html"), "utf8");
  } catch {
    return sendError(res, 404, "not_found", "no such file");
  }
  const lang = normalizeLang(url.searchParams.get("lang"));
  const theme = url.searchParams.get("theme") === "dark" ? "dark" : "light";
  const body = Buffer.from(
    html
      .replaceAll("{{MAGPIE_TOKEN}}", accessToken)
      .replaceAll("{{MAGPIE_LANG}}", lang)
      .replaceAll("{{MAGPIE_THEME}}", theme),
    "utf8",
  );
  res.writeHead(200, {
    "content-type": "text/html; charset=utf-8",
    "content-length": body.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": PAGE_CSP,
  });
  res.end(body);
}

function normalizeLang(value) {
  const raw = String(value || "").trim().toLowerCase();
  if (raw.startsWith("zh-tw") || raw.startsWith("zh-hk") || raw.startsWith("zh-hant")) return "zh-TW";
  if (raw.startsWith("zh")) return "zh";
  if (raw.startsWith("ja")) return "ja";
  if (raw.startsWith("de")) return "de";
  return "en";
}

function text(value) {
  return typeof value === "string" ? value : "";
}

function sendJson(res, status, body) {
  const data = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": data.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
  });
  res.end(data);
}

function sendError(res, status, code, message) {
  sendJson(res, status, { error: { code, message } });
}

function sendFile(res, file, type) {
  let data;
  try {
    data = fs.readFileSync(file);
  } catch {
    return sendError(res, 404, "not_found", "no such file");
  }
  res.writeHead(200, {
    "content-type": type,
    "content-length": data.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": PAGE_CSP,
  });
  res.end(data);
}

function sendHtml(res, status, html) {
  const data = Buffer.from(html, "utf8");
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": data.length,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": [
      "default-src 'none'",
      "style-src 'unsafe-inline'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
      "form-action 'none'",
    ].join("; "),
  });
  res.end(data);
}
