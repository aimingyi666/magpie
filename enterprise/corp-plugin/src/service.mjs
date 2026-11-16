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
import { createClient, CorpError } from "./client.mjs";
import { renderPage } from "./page.mjs";
import { openBrowser } from "./auth.mjs";
import {
  magpieConfigDir,
  nativeProviders,
  nativeKeys,
  shareNativeProviders,
  localWorkbuddyAccounts,
  localWorkbuddySignIn,
  localGatewayAddress,
} from "./native.mjs";

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
  const device = store.device();
  const named = (value) => String(value || "").trim();
  let localWorkbuddy = [];
  if (device) {
    try {
      localWorkbuddy = localWorkbuddyAccounts(config);
    } catch {
      // a config dir this process can't read is not an error the page shows
    }
  }
  const resources = {
    instructions: (Array.isArray(bundle?.instructions) ? bundle.instructions : [])
      .filter((item) => item && item.enabled !== false)
      .map((item) => named(item.title) || named(item.id) || "shared"),
    mcp: (Array.isArray(bundle?.mcp) ? bundle.mcp : [])
      .filter((item) => item && item.enabled !== false && named(item.name))
      .map((item) => named(item.name)),
    skills: (Array.isArray(bundle?.skills) ? bundle.skills : [])
      .filter((item) => item && item.enabled !== false && named(item.name))
      .map((item) => named(item.name)),
  };
  return {
    configured: Boolean(config.baseUrl),
    baseUrl: config.baseUrl,
    corporate: config.corporateName || "",
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
    sharing: {
      mode: String(bundle?.sharing?.mode || ""),
      updatedAt: String(bundle?.sharing?.updatedAt || ""),
      sources: (Array.isArray(bundle?.sharing?.sources) ? bundle.sharing.sources : []).map((source) => ({
        id: String(source?.id || ""),
        name: String(source?.name || source?.id || ""),
        models: Array.isArray(source?.models) ? source.models.length : 0,
      })),
    },
    role: String(device?.user?.role || "member"),
    plugins: (Array.isArray(bundle?.plugins) ? bundle.plugins : [])
      .filter((item) => item && item.enabled !== false && named(item.id))
      .map((item) => ({
        id: named(item.id),
        name: named(item.name) || named(item.id),
        model: named(item.model),
      })),
    appliedPlugins: Array.isArray(state.appliedPlugins) ? state.appliedPlugins : [],
    localWorkbuddy,
    resources,
    cursors: state.cursors,
    lastUploadAt: state.lastUploadAt,
    upload: config.upload,
    demoSignIn: config.demoSignIn === true,
  };
}

export function startService({ config, store, joiner, dir, port = config.servicePort, openUrl = openBrowser, client = null }) {
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

  // The administrator routes ask the corporate server as this device.
  // The page token is not enough: the server decides from the signed-in
  // person's groups whether the request may do anything at all.
  function corpClient() {
    const device = store.device();
    if (!config.baseUrl) throw new CorpError("base_url_required", "请先填写企业服务端地址");
    if (!device?.deviceToken) throw new CorpError("not_signed_in", "请先登录企业账号");
    return createClient({ baseUrl: config.baseUrl, getToken: () => device.deviceToken });
  }

  function corpFailure(res, error) {
    const status = error?.status
      || (error?.code === "base_url_required" ? 409 : error?.code === "not_signed_in" ? 401 : 502);
    sendJson(res, status, {
      error: { code: error?.code || "admin_failed", message: String(error?.message || error) },
    });
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

    // Each page has its own URL, so the plugin frame, a bookmark, or the
    // browser tab an identity provider sends the employee back to all land
    // somewhere whole: a sign-in page while this computer has no device, the
    // overview, the personal page, and the administrator's view.
    const pages = { "/": "overview", "/login": "login", "/me": "me", "/admin": "admin" };
    const asked = url.searchParams.get("theme");
    const theme = asked === "dark" || asked === "light" ? asked : "";
    const keep = theme ? "?theme=" + theme : "";
    if (req.method === "GET" && (url.pathname in pages || url.pathname === "/index.html")) {
      if (url.pathname === "/index.html") {
        res.writeHead(302, { location: "/" + keep });
        res.end();
        return;
      }
      const status = statusOf({ config, store, joiner });
      const signedIn = Boolean(status.device?.enrolled && status.device?.usable);
      if (url.pathname === "/login" && signedIn && url.searchParams.get("renew") !== "1") {
        res.writeHead(302, { location: "/" + keep });
        res.end();
        return;
      }
      if (url.pathname !== "/login" && !status.device?.enrolled) {
        res.writeHead(302, { location: "/login" + keep });
        res.end();
        return;
      }
      sendHtml(res, 200, renderPage({ token: pageToken, status, page: pages[url.pathname], theme }));
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
      if (config.baseUrl && config.demoSignIn === undefined) {
        try {
          const { createClient } = await import("./client.mjs");
          const discovered = await createClient({ baseUrl: config.baseUrl, getToken: () => "" }).discover();
          config.demoSignIn = discovered?.demoSignIn === true;
          if (discovered?.oidc) config.oidc = discovered.oidc;
          if (discovered?.corporate) config.corporateName = String(discovered.corporate);
        } catch {
          // status still answers what we know locally
        }
      }
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
          config.demoSignIn = discovered?.demoSignIn === true;
          if (discovered?.corporate) config.corporateName = String(discovered.corporate);
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

    if (req.method === "POST" && url.pathname === "/v1/demo-login") {
      if (!config.baseUrl) {
        sendJson(res, 409, { error: { code: "base_url_required", message: "Set the corporate server address first" } });
        return;
      }
      try {
        const { createClient } = await import("./client.mjs");
        const discovered = await createClient({ baseUrl: config.baseUrl, getToken: () => "" }).discover();
        config.demoSignIn = discovered?.demoSignIn === true;
        if (discovered?.oidc) config.oidc = discovered.oidc;
        if (discovered?.corporate) config.corporateName = String(discovered.corporate);
      } catch (error) {
        sendJson(res, 502, { error: { code: "discovery_failed", message: String(error?.message || error) } });
        return;
      }
      if (!config.demoSignIn) {
        sendJson(res, 403, { error: { code: "demo_signin_disabled", message: "This server is not in demo sign-in mode" } });
        return;
      }
      const body = await readBody(req);
      try {
        await joiner.demoSignIn(body.email, { admin: body.role === "admin" });
        sendJson(res, 200, { status: statusOf({ config, store, joiner }) });
      } catch (error) {
        sendJson(res, error?.status || 400, {
          error: { code: error?.code || "demo_signin_failed", message: String(error?.message || error) },
        });
      }
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

    // ---- an employee shares their own WorkBuddy account -----------------
    //
    // The page never holds the vendor's URL for longer than it shows it,
    // and holds no token at all: this service starts the sign-in at the
    // corporate server, which drives the gateway's plugin, and passes the
    // URL and the outcome back. An account this computer's magpie already
    // has is imported instead: the tokens are read here, sent once to the
    // corporate gateway, and this computer's copy is signed out after.

    if (req.method === "POST" && url.pathname === "/v1/share/workbuddy/start") {
      const body = await readBody(req);
      const provider = String(body.provider || "workbuddy").trim();
      try {
        const { payload } = await corpClient().request("/api/v1/share/workbuddy/start", {
          method: "POST",
          body: { provider },
        });
        // magpie shows this page in a sandboxed frame that can't open a
        // tab, so the machine's own browser opens the vendor's page, as
        // the corporate sign-in does. `opened` tells the page whether it
        // worked, so it can offer the address to copy instead.
        const url = payload?.share?.url;
        const opened = url ? openUrl(url) : false;
        sendJson(res, 200, { ...(payload || {}), opened });
      } catch (error) {
        corpFailure(res, error);
      }
      return;
    }

    if (req.method === "POST" && url.pathname === "/v1/share/workbuddy/import") {
      const body = await readBody(req);
      const provider = String(body.provider || "workbuddy").trim().toLowerCase();
      const account = String(body.account || "").trim();
      if (provider !== "workbuddy" && provider !== "workbuddy-ai") {
        sendJson(res, 422, { error: { code: "invalid_provider", message: "provider is workbuddy or workbuddy-ai" } });
        return;
      }
      if (!account) {
        sendJson(res, 422, { error: { code: "no_account", message: "请选择本机已登录的 WorkBuddy 账号" } });
        return;
      }
      let local = null;
      try {
        local = localWorkbuddySignIn(provider, account, config);
      } catch {
        local = null;
      }
      if (!local) {
        sendJson(res, 404, {
          error: { code: "local_signin_not_found", message: "本机 magpie 里已经没有这个 WorkBuddy 登录，请刷新后重试" },
        });
        return;
      }
      try {
        const { payload } = await corpClient().request("/api/v1/share/workbuddy/import", {
          method: "POST",
          body: { provider, account: local.account || account, auth: local.auth },
        });
        // The gateway has it now. This computer's copy goes, so one token
        // is renewed in one place; a copy that couldn't be removed is
        // reported, and the page says to sign it out in magpie.
        let removed = false;
        if (client?.auth?.remove) {
          try {
            await client.auth.remove({ path: { id: local.key } });
            removed = true;
          } catch {
            removed = false;
          }
        }
        sendJson(res, 200, { ...(payload || {}), removed });
      } catch (error) {
        corpFailure(res, error);
      }
      return;
    }

    if (req.method === "GET" && url.pathname === "/v1/share/workbuddy") {
      try {
        const { payload } = await corpClient().request("/api/v1/device/me");
        sendJson(res, 200, { shares: payload?.workbuddy?.shares || [] });
      } catch (error) {
        corpFailure(res, error);
      }
      return;
    }

    if (url.pathname.startsWith("/v1/share/workbuddy/")) {
      const rest = url.pathname.slice("/v1/share/workbuddy/".length);
      const cancel = req.method === "POST" && rest.endsWith("/cancel");
      let id = "";
      try {
        id = decodeURIComponent(cancel ? rest.slice(0, -"/cancel".length) : rest);
      } catch {
        sendJson(res, 422, { error: { code: "invalid_share", message: "共享 id 不合法" } });
        return;
      }
      if (!/^shr_[0-9a-f]{8,64}$/.test(id) || (!cancel && req.method !== "GET")) {
        sendJson(res, 422, { error: { code: "invalid_share", message: "共享 id 不合法" } });
        return;
      }
      try {
        const { payload } = await corpClient().request(
          `/api/v1/share/workbuddy/${encodeURIComponent(id)}${cancel ? "/cancel" : ""}`,
          cancel ? { method: "POST" } : {},
        );
        sendJson(res, 200, payload || {});
      } catch (error) {
        corpFailure(res, error);
      }
      return;
    }

    // ---- the administrator's view -------------------------------------
    //
    // These answer the page only after the corporate server has said the
    // signed-in person is an administrator. The native magpie's providers
    // are read here, on this computer, and their keys are handed to the
    // local service alone: they never pass through the page.

    if (req.method === "GET" && url.pathname === "/v1/admin/session") {
      let me;
      try {
        ({ payload: me } = await corpClient().request("/api/v1/device/me"));
      } catch (error) {
        corpFailure(res, error);
        return;
      }
      const admin = me?.user?.role === "admin";
      let native = null;
      if (admin) {
        try {
          native = {
            configDir: magpieConfigDir(config),
            providers: nativeProviders(config),
            keys: nativeKeys(config),
            gateway: localGatewayAddress(),
          };
        } catch (error) {
          native = {
            configDir: magpieConfigDir(config),
            providers: [],
            keys: [],
            gateway: localGatewayAddress(),
            error: String(error?.message || error),
          };
        }
      }
      sendJson(res, 200, {
        admin,
        reason: admin ? "" : "当前账号不是企业管理员。管理员身份来自登录令牌里的 groups，或服务端配置的 CORP_ADMIN_EMAILS。",
        user: me?.user || null,
        device: me?.device || null,
        gateway: { baseUrl: config.baseUrl, local: localGatewayAddress() },
        sharing: me?.sharing || { mode: "", updatedAt: "", catalog: [], sources: [] },
        catalog: Array.isArray(me?.sharing?.catalog) ? me.sharing.catalog : [],
        native,
      });
      return;
    }

    if (req.method === "POST" && url.pathname === "/v1/admin/share/native") {
      const body = await readBody(req);
      const ids = Array.isArray(body.ids) ? body.ids.map((id) => String(id)) : [];
      if (!ids.length) {
        sendJson(res, 422, { error: { code: "no_selection", message: "请选择要分享的供应商" } });
        return;
      }
      const picked = shareNativeProviders(ids, config);
      if (!picked.providers.length) {
        sendJson(res, 400, {
          error: { code: "no_shareable_providers", message: "选中的供应商都不能分享", skipped: picked.skipped },
        });
        return;
      }
      try {
        const { payload } = await corpClient().request("/api/v1/admin/sharing", {
          method: "PUT",
          body: { mode: "native", providers: picked.providers },
        });
        sendJson(res, 200, {
          sharing: payload?.sharing || null,
          catalog: payload?.catalog || [],
          skipped: picked.skipped,
        });
      } catch (error) {
        corpFailure(res, error);
      }
      return;
    }

    if (req.method === "POST" && url.pathname === "/v1/admin/share/remote") {
      const body = await readBody(req);
      const models = Array.isArray(body.models)
        ? body.models.map((model) => String(model))
        : String(body.models || "").split(",").map((model) => model.trim()).filter(Boolean);
      try {
        const { payload } = await corpClient().request("/api/v1/admin/sharing", {
          method: "PUT",
          body: { mode: "remote", models },
        });
        sendJson(res, 200, { sharing: payload?.sharing || null, catalog: payload?.catalog || [] });
      } catch (error) {
        corpFailure(res, error);
      }
      return;
    }

    if (req.method === "POST" && url.pathname === "/v1/admin/share/off") {
      try {
        const { payload } = await corpClient().request("/api/v1/admin/sharing", {
          method: "PUT",
          body: { mode: "off" },
        });
        sendJson(res, 200, { sharing: payload?.sharing || null, catalog: [] });
      } catch (error) {
        corpFailure(res, error);
      }
      return;
    }

    // ---- the WorkBuddy accounts employees shared ---------------------
    //
    // The page ticks which of a shared account's models the corporation
    // hands out. The accounts themselves are the corporate server's; this
    // only passes the selection on.
    if (url.pathname === "/v1/admin/workbuddy") {
      if (req.method === "GET") {
        try {
          const { payload } = await corpClient().request("/api/v1/admin/workbuddy");
          sendJson(res, 200, payload || {});
        } catch (error) {
          corpFailure(res, error);
        }
        return;
      }
      if (req.method === "PUT") {
        const body = await readBody(req);
        const provider = String(body.provider || "").trim();
        if (provider !== "workbuddy" && provider !== "workbuddy-ai") {
          sendJson(res, 422, { error: { code: "invalid_provider", message: "provider is workbuddy or workbuddy-ai" } });
          return;
        }
        const models = Array.isArray(body.models) ? body.models.map((model) => String(model)) : null;
        if (!models) {
          sendJson(res, 422, { error: { code: "invalid_models", message: "models must be a list" } });
          return;
        }
        try {
          const { payload } = await corpClient().request("/api/v1/admin/workbuddy", {
            method: "PUT",
            body: { provider, models },
          });
          sendJson(res, 200, payload || {});
        } catch (error) {
          corpFailure(res, error);
        }
        return;
      }
      sendJson(res, 405, { error: { code: "method_not_allowed", message: "read the shared accounts, or PUT the models to hand out" } });
      return;
    }

    if (req.method === "GET" && url.pathname === "/v1/admin/people") {
      try {
        const { payload } = await corpClient().request("/api/v1/admin/people");
        sendJson(res, 200, payload || {});
      } catch (error) {
        corpFailure(res, error);
      }
      return;
    }

    if (req.method === "PATCH" && url.pathname.startsWith("/v1/admin/people/")) {
      const deviceId = decodeURIComponent(url.pathname.slice("/v1/admin/people/".length));
      if (!/^[A-Za-z0-9_-]{1,64}$/.test(deviceId)) {
        sendJson(res, 422, { error: { code: "invalid_device", message: "设备 id 不合法" } });
        return;
      }
      const body = await readBody(req);
      const patch = {};
      for (const name of ["name", "models", "readOnly", "off", "limit"]) {
        if (Object.prototype.hasOwnProperty.call(body, name)) patch[name] = body[name];
      }
      if (!Object.keys(patch).length) {
        sendJson(res, 422, { error: { code: "nothing_to_change", message: "没有要修改的内容" } });
        return;
      }
      try {
        const { payload } = await corpClient().request(`/api/v1/admin/people/${encodeURIComponent(deviceId)}`, {
          method: "PATCH",
          body: patch,
        });
        sendJson(res, 200, payload || {});
      } catch (error) {
        corpFailure(res, error);
      }
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
  const title = result.ok ? "登录成功" : "登录失败";
  const body = result.ok ? "可以关闭此标签，回到 magpie。" : String(result.message || "");
  return [
    '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">',
    `<title>${escapeHtml(title)}</title>`,
    "<style>body{font:14px/1.5 system-ui,sans-serif;margin:48px;color:#111}",
    "@media (prefers-color-scheme:dark){body{background:#111;color:#eee}}</style></head><body>",
    `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(body)}</p></body></html>`,
  ].join("");
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
