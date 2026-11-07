import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { startService } from "../src/service.mjs";

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "magpie-enterprise-admin-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

// useStateDir keeps every test off the real ~/.config and local state.
function useStateDir(t) {
  const dir = tempDir(t);
  const prior = process.env.MAGPIE_ENTERPRISE_STATE_DIR;
  const priorAdmin = process.env.MAGPIE_ENTERPRISE_ADMIN_URL;
  process.env.MAGPIE_ENTERPRISE_STATE_DIR = dir;
  delete process.env.MAGPIE_ENTERPRISE_ADMIN_URL;
  t.after(() => {
    if (prior === undefined) delete process.env.MAGPIE_ENTERPRISE_STATE_DIR;
    else process.env.MAGPIE_ENTERPRISE_STATE_DIR = prior;
    if (priorAdmin === undefined) delete process.env.MAGPIE_ENTERPRISE_ADMIN_URL;
    else process.env.MAGPIE_ENTERPRISE_ADMIN_URL = priorAdmin;
  });
  return dir;
}

function request(port, pathname, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(body);
    const req = http.request({
      host: "127.0.0.1",
      port,
      path: pathname,
      method,
      headers: {
        ...(payload ? { "content-length": payload.length } : {}),
        ...headers,
      },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        });
      });
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function json(response) {
  return JSON.parse(response.body);
}

async function pageToken(port) {
  const response = await request(port, "/");
  assert.equal(response.status, 200);
  const match = response.body.match(/<meta name="magpie-enterprise-token" content="([a-f0-9]{64})">/);
  assert.ok(match, "the page should carry its service token");
  return match[1];
}

function adminHeaders(token) {
  return { "x-magpie-enterprise": token };
}

// mockAdmin is the management service the plugin talks to: it issues a
// desktop token for a PKCE verifier, and answers the proxied routes.
async function mockAdmin(t, { routes = {}, timeoutMs = 0 } = {}) {
  const calls = [];
  let challenge = "";
  let issuedToken = "";
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString("utf8");
    let body = null;
    try {
      body = raw ? JSON.parse(raw) : null;
    } catch {
      body = null;
    }
    calls.push({ method: req.method, url: req.url, headers: req.headers, body });
    const send = (status, payload, headers = {}) => {
      const data = Buffer.from(typeof payload === "string" ? payload : JSON.stringify(payload), "utf8");
      res.writeHead(status, {
        "content-type": "application/json",
        "content-length": data.length,
        ...headers,
      });
      res.end(data);
    };
    if (timeoutMs) await new Promise((resolve) => setTimeout(resolve, timeoutMs));
    if (req.method === "POST" && req.url === "/api/v1/desktop/token") {
      const computed = crypto.createHash("sha256")
        .update(String(body?.codeVerifier || ""))
        .digest("base64url");
      if (computed !== challenge) {
        send(403, { error: { code: "desktop_ticket_mismatch", message: "PKCE mismatch" } });
        return;
      }
      issuedToken = "desktop-token-value";
      send(200, {
        token: issuedToken,
        expiresAt: new Date(Date.now() + 8 * 3600_000).toISOString(),
        user: { id: "admin-1", email: "admin@example.com", name: "Admin" },
      });
      return;
    }
    if (req.method === "GET" && req.url === "/api/v1/desktop/me") {
      send(200, {
        user: { id: "admin-1", email: "admin@example.com", name: "Admin" },
        roles: ["super_admin"],
        permissions: ["gateway.read"],
        expiresAt: new Date(Date.now() + 8 * 3600_000).toISOString(),
      });
      return;
    }
    const handler = routes[`${req.method} ${req.url.split("?")[0]}`];
    if (handler) {
      handler(req, res, send, body);
      return;
    }
    send(404, { error: { code: "not_found", message: "no such route" } });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return {
    baseUrl: `http://127.0.0.1:${server.address().port}`,
    calls,
    setChallenge(value) {
      challenge = value;
    },
    get token() {
      return issuedToken;
    },
  };
}

// signIn performs a real PKCE round trip against the mock service.
async function signIn(t, service, mock, { pinned = true } = {}) {
  let opened = "";
  const plugin = service ?? await startService({
    port: 0,
    // A pinned address wins over the sync file; without one the file (or
    // here, the device credential) is what the service reads.
    ...(pinned ? { adminUrl: mock.baseUrl } : {}),
    openBrowser: async (url) => {
      opened = url;
    },
  });
  if (!service) t.after(() => plugin.close());
  const token = await pageToken(plugin.port);
  const started = await request(plugin.port, "/v1/admin/login", {
    method: "POST",
    headers: adminHeaders(token),
  });
  assert.equal(started.status, 200);
  assert.ok(opened, "the system browser should be opened");
  const login = new URL(opened);
  assert.equal(login.pathname, "/admin/desktop/login");
  assert.ok(!opened.includes("secret"), "the login URL carries no secret");
  const callback = new URL(login.searchParams.get("callbackUrl"));
  mock.setChallenge(login.searchParams.get("codeChallenge"));
  callback.searchParams.set("ticket", "one-time-ticket");
  const done = await request(plugin.port, `${callback.pathname}${callback.search}`);
  assert.equal(done.status, 200);
  const status = await request(plugin.port, "/v1/admin/status", {
    headers: adminHeaders(token),
  });
  assert.equal(status.status, 200);
  assert.equal(json(status).signedIn, true);
  return { plugin, token, opened };
}

test("administration endpoints require this page's token", async (t) => {
  useStateDir(t);
  const service = await startService({ port: 0, openBrowser: async () => {} });
  t.after(() => service.close());

  for (const pathname of ["/v1/admin/status", "/v1/admin/providers"]) {
    const response = await request(service.port, pathname);
    assert.equal(response.status, 403);
    assert.equal(json(response).error.code, "forbidden_token");
  }
  const wrong = await request(service.port, "/v1/admin/status", {
    headers: { "x-magpie-enterprise": "0".repeat(64) },
  });
  assert.equal(wrong.status, 403);
  assert.equal(json(wrong).error.code, "forbidden_token");
});

test("login says the console is not configured, and a callback without a ticket fails", async (t) => {
  useStateDir(t);
  const service = await startService({ port: 0, openBrowser: async () => {} });
  t.after(() => service.close());
  const token = await pageToken(service.port);

  const response = await request(service.port, "/v1/admin/login", {
    method: "POST",
    headers: adminHeaders(token),
  });
  assert.equal(response.status, 409);
  assert.equal(json(response).error.code, "admin_not_configured");

  const callback = await request(service.port, "/v1/admin/login/callback");
  assert.equal(callback.status, 400);
  assert.match(callback.body, /no ticket/);
});

test("a desktop ticket is exchanged with PKCE and never reaches the page", async (t) => {
  useStateDir(t);
  const mock = await mockAdmin(t);
  const { plugin, token } = await signIn(t, null, mock);

  assert.ok(!mock.calls.some((call) => call.url.includes("ticket")),
    "the ticket goes to the callback, not to a management API");
  const exchange = mock.calls.find((call) => call.url === "/api/v1/desktop/token");
  assert.ok(exchange, "the service should exchange the ticket");
  assert.equal(exchange.body.ticket, "one-time-ticket");
  assert.match(exchange.body.codeVerifier, /^[A-Za-z0-9_-]{43,128}$/);

  const page = await request(plugin.port, "/");
  assert.ok(!page.body.includes(mock.token), "the desktop token must not reach the page");
  assert.ok(!page.body.includes("one-time-ticket"));

  const me = await request(plugin.port, "/v1/admin/me", { headers: adminHeaders(token) });
  assert.equal(me.status, 200);
  assert.equal(json(me).roles[0], "super_admin");
});

test("the page's routes reach the named management APIs only", async (t) => {
  useStateDir(t);
  const providers = { providers: [{ id: "openai", name: "OpenAI", keys: [] }] };
  const groups = { groups: [{ id: "default", members: ["openai/gpt-4o"] }] };
  const gateway = { gateway: { ok: true, models: ["gpt-4o"] }, keys: [] };
  const devices = { devices: [{ id: "device-1", userId: "user-1", status: "active" }] };
  const requests = { rows: [{ time: "2026-11-05T00:00:00.000Z", routeId: 7, status: 200 }] };
  const route = { route: { id: 7, source: "usage", attempts: [{ status: 200 }] } };
  const mock = await mockAdmin(t, {
    routes: {
      "GET /api/v1/admin/gateway/overview": (_req, _res, send) => send(200, {
        gateway: { ok: true },
        counts: { requests: 1 },
        recent: [{ routeId: 7, status: 200 }],
      }),
      "GET /api/v1/admin/gateway/providers": (_req, _res, send) => send(200, providers),
      "POST /api/v1/admin/gateway/providers": (_req, _res, send) => send(201, { provider: providers.providers[0] }),
      "PATCH /api/v1/admin/gateway/providers/openai": (_req, _res, send) => send(200, { provider: providers.providers[0] }),
      "DELETE /api/v1/admin/gateway/providers/openai": (_req, _res, send) => send(200, { ok: true }),
      "GET /api/v1/admin/gateway/routing-groups": (_req, _res, send) => send(200, groups),
      "GET /api/v1/admin/gateway": (_req, _res, send) => send(200, gateway),
      "GET /api/v1/admin/gateway/keys": (_req, _res, send) => send(200, { keys: [] }),
      "GET /api/v1/admin/devices": (_req, _res, send) => send(200, devices),
      "GET /api/v1/admin/gateway/requests": (_req, _res, send) => send(200, requests),
      "GET /api/v1/admin/gateway/routes/7": (_req, _res, send) => send(200, route),
      "GET /api/v1/admin/resources": (_req, _res, send) => send(200, {
        resources: [{ id: "res_ssssssssssssssss", kind: "skill", name: "Release check" }],
      }),
      "POST /api/v1/admin/resources": (_req, _res, send) => send(201, {
        resource: { id: "res_ssssssssssssssss", updatedAt: "2026-11-07T00:00:00.000Z" },
      }),
      "POST /api/v1/admin/resources/res_ssssssssssssssss/releases": (_req, _res, send) => send(201, {
        resource: { id: "res_ssssssssssssssss", updatedAt: "2026-11-07T00:00:01.000Z" },
        release: { id: "rel_ssssssssssssssss", status: "candidate" },
      }),
      "POST /api/v1/admin/resources/res_ssssssssssssssss/publish": (_req, _res, send) => send(200, {
        resource: { id: "res_ssssssssssssssss", status: "published" },
        release: { id: "rel_ssssssssssssssss", status: "published" },
      }),
      "POST /api/v1/admin/resources/res_ssssssssssssssss/rollback": (_req, _res, send) => send(200, {
        resource: { id: "res_ssssssssssssssss", status: "published" },
        release: { id: "rel_ssssssssssssssss", status: "published" },
      }),
    },
  });
  const { plugin, token } = await signIn(t, null, mock);
  const headers = adminHeaders(token);

  const cases = [
    ["/v1/admin/overview", "GET"],
    ["/v1/admin/providers", "GET"],
    ["/v1/admin/routing-groups", "GET"],
    ["/v1/admin/gateway", "GET"],
    ["/v1/admin/gateway/keys", "GET"],
    ["/v1/admin/devices", "GET"],
    ["/v1/admin/requests?period=week&limit=100", "GET"],
    ["/v1/admin/routes/7", "GET"],
  ];
  for (const [pathname, method] of cases) {
    const response = await request(plugin.port, pathname, { method, headers });
    assert.equal(response.status, 200, `${pathname} should proxy: ${response.body}`);
  }
  const gatewayCall = mock.calls.find((call) => call.url === "/api/v1/admin/gateway");
  assert.equal(gatewayCall.headers.authorization, `Bearer ${mock.token}`);

  const query = mock.calls.find((call) => call.url.startsWith("/api/v1/admin/gateway/requests"));
  assert.match(query.url, /period=week/);

  let response = await request(plugin.port, "/v1/admin/providers", {
    method: "POST",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({ name: "OpenAI", reason: "test" }),
  });
  // The page's service answers 200 for a proxied write; the management
  // service's own 201 is not part of this interface.
  assert.equal(response.status, 200);

  response = await request(plugin.port, "/v1/admin/providers/openai", {
    method: "PATCH",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({ expectedRevision: "r1", reason: "test" }),
  });
  assert.equal(response.status, 200);

  response = await request(plugin.port, "/v1/admin/providers/openai", {
    method: "DELETE",
    headers: headers,
  });
  assert.equal(response.status, 200);

  // Publishing a resource is three writes the page can drive itself.
  for (const [pathname, body] of [
    ["/v1/admin/resources", { kind: "skill", name: "Release check", reason: "pilot" }],
    ["/v1/admin/resources/res_ssssssssssssssss/releases", {
      resourceVersion: "2026.11.1", content: "# check", reason: "pilot",
    }],
    ["/v1/admin/resources/res_ssssssssssssssss/publish", {
      releaseId: "rel_ssssssssssssssss", reason: "pilot",
    }],
    ["/v1/admin/resources/res_ssssssssssssssss/rollback", {
      releaseId: "rel_ssssssssssssssss", reason: "pilot",
    }],
  ]) {
    response = await request(plugin.port, pathname, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    assert.equal(response.status, 200, `${pathname}: ${response.body}`);
  }

  response = await request(plugin.port, "/v1/admin/anything", { headers });
  assert.equal(response.status, 404);
  assert.equal(json(response).error.code, "not_found");
});

test("a refusal crosses to the page with its code, and an unknown answer closes", async (t) => {
  useStateDir(t);
  const mock = await mockAdmin(t, {
    routes: {
      "GET /api/v1/admin/gateway/providers": (_req, _res, send) => send(409, {
        error: { code: "revision_conflict", message: "changed" },
      }),
      "GET /api/v1/admin/gateway/routing-groups": (_req, _res, send) => send(200, "not json"),
      "GET /api/v1/admin/gateway": () => {},
      "GET /api/v1/admin/gateway/keys": (_req, _res, send) => send(302, "", {
        location: "https://evil.example/",
      }),
      "GET /api/v1/admin/devices": (_req, _res, send) => send(500, {
        error: { code: "gateway_unavailable", message: "down" },
      }),
      "GET /api/v1/admin/gateway/requests": (_req, _res) => {
        // A declared body larger than the service will read.
        _res.writeHead(200, { "content-type": "application/json", "content-length": 9 * 1024 * 1024 });
        _res.write("{");
      },
    },
  });
  const { plugin, token } = await signIn(t, null, mock);
  const headers = adminHeaders(token);

  let response = await request(plugin.port, "/v1/admin/providers", { headers });
  assert.equal(response.status, 409);
  assert.equal(json(response).error.code, "revision_conflict");

  response = await request(plugin.port, "/v1/admin/routing-groups", { headers });
  assert.equal(response.status, 502);
  assert.equal(json(response).error.code, "admin_invalid_response");

  response = await request(plugin.port, "/v1/admin/gateway/keys", { headers });
  assert.equal(response.status, 502);
  assert.equal(json(response).error.code, "admin_invalid_response");

  response = await request(plugin.port, "/v1/admin/devices", { headers });
  assert.equal(response.status, 500);
  assert.equal(json(response).error.code, "gateway_unavailable");

  response = await request(plugin.port, "/v1/admin/requests", { headers });
  assert.equal(response.status, 502);
  assert.equal(json(response).error.code, "admin_invalid_response");
});

test("a slow management service times out instead of hanging the page", async (t) => {
  useStateDir(t);
  const mock = await mockAdmin(t, {
    timeoutMs: 300,
    routes: {
      "GET /api/v1/admin/gateway/overview": (_req, _res, send) => send(200, {}),
    },
  });
  const service = await startService({
    port: 0,
    adminUrl: mock.baseUrl,
    adminTimeoutMs: 50,
    openBrowser: async () => {},
  });
  t.after(() => service.close());
  const token = await pageToken(service.port);

  let opened = "";
  const started = await request(service.port, "/v1/admin/login", {
    method: "POST",
    headers: adminHeaders(token),
  });
  assert.equal(started.status, 200);
  const login = new URL(json(started).loginUrl);
  mock.setChallenge(login.searchParams.get("codeChallenge"));
  // The exchange itself times out, so the callback says so and no token
  // is installed.
  const callback = new URL(login.searchParams.get("callbackUrl"));
  callback.searchParams.set("ticket", "one-time-ticket");
  const done = await request(service.port, `${callback.pathname}${callback.search}`);
  assert.equal(done.status, 400);
  assert.match(done.body, /did not answer in time/);
  const status = await request(service.port, "/v1/admin/status", {
    headers: adminHeaders(token),
  });
  assert.equal(json(status).signedIn, false);
  assert.equal(opened, "");
});

test("administration never changes the employee status or sync routes", async (t) => {
  useStateDir(t);
  const mock = await mockAdmin(t);
  const { plugin, token } = await signIn(t, null, mock);
  const headers = adminHeaders(token);

  let response = await request(plugin.port, "/v1/status", { headers });
  assert.equal(response.status, 200);
  assert.equal(json(response).credential.state, "missing");

  response = await request(plugin.port, "/v1/sync", { method: "POST", headers });
  assert.equal(response.status, 409);
  assert.equal(json(response).error.code, "not_joined");
});

test("a console address can be saved from the page and takes effect at once", async (t) => {
  const dir = useStateDir(t);
  fs.writeFileSync(
    path.join(dir, "enterprise-sync.json"),
    `${JSON.stringify({
      resourceBaseUrl: "https://resource.example.com",
      signingKeys: { "resource-1": { publicKeyPem: "-----BEGIN PUBLIC KEY-----\nk\n-----END PUBLIC KEY-----\n" } },
      displayNames: { res_1: "Kept" },
    }, null, 2)}\n`,
  );
  // The service starts with no address, as a freshly joined device has.
  const service = await startService({ port: 0, openBrowser: async () => {} });
  t.after(() => service.close());
  const token = await pageToken(service.port);
  let status = await request(service.port, "/v1/admin/status", { headers: adminHeaders(token) });
  assert.equal(json(status).configured, false);

  let response = await request(service.port, "/v1/admin/console", {
    method: "PUT",
    headers: { ...adminHeaders(token), "content-type": "application/json" },
    body: JSON.stringify({ adminUrl: "https://admin.corp.example" }),
  });
  assert.equal(response.status, 200);
  assert.equal(json(response).configured, true);
  assert.equal(json(response).adminUrl, "https://admin.corp.example");

  const saved = JSON.parse(fs.readFileSync(path.join(dir, "enterprise-sync.json"), "utf8"));
  assert.equal(saved.adminBaseUrl, "https://admin.corp.example");
  assert.equal(saved.resourceBaseUrl, "https://resource.example.com");
  assert.deepEqual(saved.displayNames, { res_1: "Kept" });
  assert.ok(saved.signingKeys["resource-1"].publicKeyPem.includes("BEGIN PUBLIC KEY"));

  status = await request(service.port, "/v1/admin/status", { headers: adminHeaders(token) });
  assert.equal(json(status).configured, true);

  // Plain http is only for this machine: a token must never go across a
  // network in the clear.
  for (const [value, code] of [
    ["http://admin.corp.example", "invalid_admin_url"],
    ["ftp://admin.corp.example", "invalid_admin_url"],
    ["https://user:pass@admin.corp.example", "invalid_admin_url"],
    ["not a url", "invalid_admin_url"],
  ]) {
    response = await request(service.port, "/v1/admin/console", {
      method: "PUT",
      headers: { ...adminHeaders(token), "content-type": "application/json" },
      body: JSON.stringify({ adminUrl: value }),
    });
    assert.equal(response.status, 422, `${value} should be refused`);
    assert.equal(json(response).error.code, code);
  }
  assert.equal(
    JSON.parse(fs.readFileSync(path.join(dir, "enterprise-sync.json"), "utf8")).adminBaseUrl,
    "https://admin.corp.example",
    "a refused address must not be written",
  );
});

test("a console address without a sync file is refused, not written", async (t) => {
  useStateDir(t);
  const service = await startService({ port: 0, openBrowser: async () => {} });
  t.after(() => service.close());
  const token = await pageToken(service.port);
  const response = await request(service.port, "/v1/admin/console", {
    method: "PUT",
    headers: { ...adminHeaders(token), "content-type": "application/json" },
    body: JSON.stringify({ adminUrl: "https://admin.corp.example" }),
  });
  assert.equal(response.status, 409);
  assert.equal(json(response).error.code, "sync_not_configured");
});

test("changing the console address drops the old administrator session", async (t) => {
  const dir = useStateDir(t);
  const mock = await mockAdmin(t);
  // The signed-in device has a sync file: signing in does not write one.
  fs.writeFileSync(
    path.join(dir, "enterprise-sync.json"),
    `${JSON.stringify({
      resourceBaseUrl: "https://resource.example.com",
      adminBaseUrl: mock.baseUrl,
      signingKeys: { "resource-1": { publicKeyPem: "-----BEGIN PUBLIC KEY-----\nk\n-----END PUBLIC KEY-----\n" } },
    }, null, 2)}\n`,
  );
  // Pinned to nothing: the address is only the file's, so saving another
  // one changes what the session is for.
  const { plugin, token } = await signIn(t, null, mock, { pinned: false });
  let status = await request(plugin.port, "/v1/admin/status", { headers: adminHeaders(token) });
  assert.equal(json(status).signedIn, true);

  const saved = await request(plugin.port, "/v1/admin/console", {
    method: "PUT",
    headers: { ...adminHeaders(token), "content-type": "application/json" },
    body: JSON.stringify({ adminUrl: "http://127.0.0.1:3999" }),
  });
  assert.equal(saved.status, 200);
  status = await request(plugin.port, "/v1/admin/status", { headers: adminHeaders(token) });
  assert.equal(json(status).signedIn, false, "a token for one console must not go to another");
  assert.equal(json(status).adminUrl, "http://127.0.0.1:3999");
});
