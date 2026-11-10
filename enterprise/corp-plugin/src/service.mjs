// The loopback service behind this plugin's page.
//
// magpie hands a plugin's page a frame that may connect to nothing, so the
// page is served here instead: page/index.html redirects to it, and the
// service draws the page and answers it. The page never holds the device
// token — it asks this service, which holds it, for what it shows.
import http from "node:http";
import crypto from "node:crypto";
import { readBundle, enabledProviders } from "./providers.mjs";
import { syncBundle } from "./sync.mjs";

const MAX_BODY = 64 << 10;
const SYNC_EVERY_MS = 5 * 60 * 1000;

function sendJson(res, status, body, extra = {}) {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(payload.length),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    ...extra,
  });
  res.end(payload);
}

function sendHtml(res, status, body) {
  const payload = Buffer.from(body, "utf8");
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": String(payload.length),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
  });
  res.end(payload);
}

export function statusOf({ config, store, joiner }) {
  const bundle = readBundle(store.dir);
  const state = store.state();
  return {
    configured: Boolean(config.baseUrl),
    baseUrl: config.baseUrl,
    provider: config.providerId,
    device: joiner.status(),
    revision: state.revision || bundle?.revision || "",
    lastSyncAt: state.lastSyncAt,
    lastSyncError: state.lastSyncError,
    providers: enabledProviders(bundle).map((entry) => ({
      id: entry.id,
      name: entry.name || entry.id,
      models: Array.isArray(entry.models) ? entry.models.length : 0,
    })),
    cursors: state.cursors,
    lastUploadAt: state.lastUploadAt,
    upload: config.upload,
  };
}

export function startService({ config, store, joiner, dir, port = config.servicePort }) {
  const pageToken = crypto.randomBytes(32).toString("hex");
  let syncing = null;
  let timer = null;
  let server = null;
  let boundPort = port;

  const allowedHost = (req) => {
    const host = String(req.headers.host || "").toLowerCase();
    return host === `127.0.0.1:${boundPort}` || host === `localhost:${boundPort}` || host === `[::1]:${boundPort}`;
  };

  const authorised = (req, url) =>
    req.headers["x-page-token"] === pageToken || url.searchParams.get("t") === pageToken;

  async function readBody(req) {
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
      total += chunk.length;
      if (total > MAX_BODY) throw new Error("request too large");
      chunks.push(chunk);
    }
    if (!total) return {};
    try {
      return JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      return {};
    }
  }

  function once() {
    if (syncing) return syncing;
    syncing = syncBundle({ config, store })
      .catch((error) => ({ errors: [{ code: error?.code || "sync_failed", message: String(error?.message || error) }] }))
      .finally(() => {
        syncing = null;
      });
    return syncing;
  }

  server = http.createServer(async (req, res) => {
    const url = new URL(req.url || "/", `http://127.0.0.1:${boundPort}`);
    if (!allowedHost(req)) {
      sendJson(res, 403, { error: { code: "host_not_allowed", message: "This service answers this computer only" } });
      return;
    }

    if (url.pathname === "/healthz") {
      sendJson(res, 200, { ok: true });
      return;
    }

    // The identity provider's redirect lands here. Its state is the check,
    // not the page token: a browser navigation carries neither.
    if (req.method === "GET" && url.pathname === "/oidc/callback") {
      const result = await joiner.handleCallback(url.searchParams);
      sendHtml(res, result.ok ? 200 : 400, callbackPage(result));
      return;
    }

    if (url.pathname === "/" || url.pathname === "/index.html") {
      sendHtml(res, 200, page({ token: pageToken, status: statusOf({ config, store, joiner }) }));
      return;
    }

    if (!url.pathname.startsWith("/v1/")) {
      sendJson(res, 404, { error: { code: "not_found", message: "no such path" } });
      return;
    }
    if (!authorised(req, url)) {
      sendJson(res, 403, { error: { code: "page_token_required", message: "This service answers its own page only" } });
      return;
    }

    if (req.method === "GET" && url.pathname === "/v1/status") {
      sendJson(res, 200, statusOf({ config, store, joiner }));
      return;
    }

    if (req.method === "POST" && url.pathname === "/v1/sync") {
      const summary = await once();
      sendJson(res, 200, { status: statusOf({ config, store, joiner }), summary });
      return;
    }

    if (req.method === "POST" && url.pathname === "/v1/login") {
      if (!config.baseUrl) {
        sendJson(res, 409, { error: { code: "base_url_required", message: "Set the corporate server address first" } });
        return;
      }
      if (!config.oidc) {
        // Learn where to sign in from the server before sending the
        // browser anywhere on a guess.
        try {
          const { createClient } = await import("./client.mjs");
          const discovered = await createClient({ baseUrl: config.baseUrl, getToken: () => "" }).discover();
          if (discovered?.oidc) config.oidc = discovered.oidc;
        } catch (error) {
          sendJson(res, 502, { error: { code: "discovery_failed", message: String(error?.message || error) } });
          return;
        }
      }
      if (!config.oidc?.authorizationEndpoint) {
        sendJson(res, 502, { error: { code: "oidc_not_configured", message: "The server published no sign-in endpoint" } });
        return;
      }
      joiner.signIn().catch(() => {});
      sendJson(res, 202, { started: true });
      return;
    }

    if (req.method === "POST" && url.pathname === "/v1/config") {
      const body = await readBody(req);
      const { saveCorpConfig } = await import("./config.mjs");
      const saved = saveCorpConfig(dir, { ...config, ...body });
      config.baseUrl = saved.baseUrl;
      config.providerId = saved.provider;
      if (saved.oidc) config.oidc = saved.oidc;
      sendJson(res, 200, { status: statusOf({ config, store, joiner }) });
      return;
    }

    sendJson(res, 404, { error: { code: "not_found", message: "no such path" } });
  });

  const ready = new Promise((resolve, reject) => {
    server.once("error", (error) => reject(error));
    server.listen(port, "127.0.0.1", () => {
      boundPort = server.address().port;
      // A pass every few minutes keeps providers, resources and usage
      // current without the reader pressing anything. It does nothing
      // until a device is signed in.
      timer = setInterval(() => {
        if (config.baseUrl && store.device()) once().catch(() => {});
      }, SYNC_EVERY_MS);
      timer.unref?.();
      resolve();
    });
  });

  return {
    ready,
    port: () => boundPort,
    token: () => pageToken,
    sync: once,
    close() {
      if (timer) clearInterval(timer);
      server?.close();
    },
  };
}

function callbackPage(result) {
  const title = result.ok ? "Signed in" : "Sign-in failed";
  const body = result.ok ? "You can close this tab and go back to magpie." : String(result.message || "");
  return [
    '<!doctype html><html lang="en"><head><meta charset="utf-8">',
    `<title>${escapeHtml(title)}</title>`,
    "<style>body{font:14px/1.5 system-ui,sans-serif;margin:48px;color:#111}",
    "@media (prefers-color-scheme:dark){body{background:#111;color:#eee}}</style></head><body>",
    `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(body)}</p></body></html>`,
  ].join("");
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

// The page itself. Nothing of it interpolates a server's words into the
// script: the status arrives as JSON, and every value is put in as text.
const PAGE_STYLE = `
:root{color-scheme:light dark}
body{font:13px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;padding:20px;color:#111}
@media (prefers-color-scheme:dark){body{background:#161616;color:#eee}}
h1{font-size:15px;margin:0 0 4px}
.sub{opacity:.65;margin:0 0 18px}
.card{border:1px solid rgba(128,128,128,.3);border-radius:10px;padding:12px 14px;margin-bottom:12px}
.row{display:flex;justify-content:space-between;gap:12px;padding:3px 0}
.row span:first-child{opacity:.65}
code{font:.92em ui-monospace,SFMono-Regular,Consolas,monospace;opacity:.85}
button{font:inherit;padding:6px 12px;border-radius:8px;border:1px solid rgba(128,128,128,.45);background:transparent;color:inherit;cursor:pointer}
button.primary{background:#2563eb;border-color:#2563eb;color:#fff}
button:disabled{opacity:.5;cursor:default}
.actions{display:flex;gap:8px;margin:14px 0}
ul{margin:6px 0 0;padding-left:18px}
.note{opacity:.75;margin-top:10px;font-size:12px}
.err{color:#c0392b}
`;

const PAGE_SCRIPT = `
var TOKEN = window.__CORP_TOKEN;
var INITIAL = window.__CORP_STATUS;
function text(v){ return (v === undefined || v === null || v === "") ? "\\u2014" : String(v); }
function esc(s){ return String(s === undefined || s === null ? "" : s).replace(/[&<>"']/g, function(c){ return ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]; }); }
function rows(s){
  var d = s.device || {};
  var list = [
    ["Server", s.baseUrl || "not set"],
    ["Signed in", d.enrolled ? (d.usable ? "yes" : "expired") : "no"],
    ["Account", [d.email, d.department].filter(Boolean).join(" \\u00b7 ")],
    ["Expires", d.expiresAt ? new Date(d.expiresAt).toLocaleString() : "\\u2014"],
    ["Bundle", s.revision || "not synced"],
    ["Last sync", s.lastSyncAt ? new Date(s.lastSyncAt).toLocaleString() : "never"]
  ];
  return list.map(function(pair){
    return '<div class="row"><span>' + esc(pair[0]) + '</span><span>' + esc(text(pair[1])) + '</span></div>';
  }).join("");
}
function draw(s){
  var providers = (s.providers || []).map(function(p){
    return '<li><code>' + esc(p.id) + '</code> ' + esc(p.name) + ' \\u00b7 ' + p.models + ' models</li>';
  }).join("");
  var error = s.lastSyncError ? '<div class="row err"><span>Last error</span><span>' + esc(s.lastSyncError) + '</span></div>' : "";
  document.getElementById("app").innerHTML =
    '<div class="card">' + rows(s) + error + '</div>' +
    '<div class="card"><div class="row"><span>Providers</span><span>' + (s.providers || []).length + '</span></div><ul>' + (providers || "<li>none yet</li>") + '</ul></div>';
  document.getElementById("note").textContent = s.configured ? "" : "Set the corporate server address in this plugin's options, then sign in.";
}
function call(path, method){
  return fetch(path, { method: method || "GET", headers: { "x-page-token": TOKEN } }).then(function(r){ return r.json().catch(function(){ return {}; }); });
}
document.getElementById("login").addEventListener("click", function(event){
  var button = event.target;
  button.disabled = true;
  call("/v1/login", "POST").then(function(r){
    button.disabled = false;
    document.getElementById("note").textContent = (r && r.error && r.error.message) || "The browser should have opened. Finish signing in there.";
  });
});
document.getElementById("sync").addEventListener("click", function(event){
  var button = event.target;
  button.disabled = true;
  call("/v1/sync", "POST").then(function(r){
    button.disabled = false;
    if (r && r.status) draw(r.status);
    var errors = (r && r.summary && r.summary.errors ? r.summary.errors : []).map(function(e){ return e.message; }).join("; ");
    document.getElementById("note").textContent = errors || "Synced.";
  });
});
draw(INITIAL);
setInterval(function(){
  call("/v1/status").then(function(s){ if (s && s.device) draw(s); });
}, 15000);
`;

function page({ token, status }) {
  const boot = `window.__CORP_TOKEN=${JSON.stringify(token)};window.__CORP_STATUS=${JSON.stringify(status).replace(/</g, "\\u003c")};`;
  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    "<title>Corp</title>",
    `<style>${PAGE_STYLE}</style></head><body>`,
    "<h1>Corp</h1>",
    '<p class="sub">What this machine gets from the corporation, and what it sends back.</p>',
    '<div id="app"></div>',
    '<div class="actions"><button id="login">Sign in</button><button id="sync" class="primary">Sync now</button></div>',
    '<p class="note" id="note"></p>',
    `<script>${boot}</script>`,
    `<script>${PAGE_SCRIPT}</script>`,
    "</body></html>",
  ].join("\n");
}
