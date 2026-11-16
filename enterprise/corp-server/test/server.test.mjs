// The promises this server makes.
//
// Two ways to run it: against a live server at CORP_BASE (a system test,
// with a gateway behind it where CORP_GATEWAY_ADMIN_URL is set), or, when
// CORP_BASE is unset, by starting this file's server on a port of its own.
// A sign-in needs the gateway, so with no gateway the enroll cases say so
// and the contract cases run alone.
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

let BASE = process.env.CORP_BASE || "";
const LIVE = Boolean(process.env.CORP_BASE);
const GATEWAY_ADMIN = process.env.CORP_GATEWAY_ADMIN_URL || "http://127.0.0.1:3501";
const TOKEN = String(process.env.CORP_GATEWAY_ADMIN_TOKEN || "").trim();
const HAVE_GATEWAY = Boolean(TOKEN);

// The local run seeds one administrator and one member, so the routes that
// need no gateway can be exercised without an identity provider.
const ADMIN_TOKEN = "sk-admin-device-token";
const MEMBER_TOKEN = "sk-member-device-token";
const seeded = LIVE
  ? ""
  : path.join(fs.mkdtempSync(path.join(os.tmpdir(), "corp-server-")), "state.json");

if (!BASE) {
  // a server of this test's own, on a free port, with its state in a
  // temporary folder: no gateway, so only the parts that need none run
  const stateFile = seeded;
  process.env.CORP_STATE_FILE = stateFile;
  process.env.CORP_ALLOW_DEMO_SIGNIN = "true";
  process.env.CORP_DEMO_ADMIN = "true";
  process.env.CORP_PORT = "0";
  process.env.CORP_GATEWAY_ADMIN_TOKEN = "";
  const digest = (value) => crypto.createHash("sha256").update(value).digest("hex");
  fs.writeFileSync(stateFile, JSON.stringify({
    version: 1,
    devices: {
      dev_admin: {
        id: "dev_admin", userId: "usr_admin", name: "Admin PC", platform: "windows",
        state: "active", gatewayKeyID: "key_admin", gatewayKeyDigest: "",
        tokenDigest: digest(ADMIN_TOKEN), createdAt: "2026-11-16T00:00:00.000Z", expiresAt: "",
      },
      dev_member: {
        id: "dev_member", userId: "usr_member", name: "Member PC", platform: "windows",
        state: "active", gatewayKeyID: "key_member", gatewayKeyDigest: "",
        tokenDigest: digest(MEMBER_TOKEN), createdAt: "2026-11-16T00:00:00.000Z", expiresAt: "",
      },
    },
    users: {
      usr_admin: {
        id: "usr_admin", subject: "demo:admin@corp.example", email: "admin@corp.example",
        name: "Admin", groups: ["engineering"], lastSeenAt: "",
      },
      usr_member: {
        id: "usr_member", subject: "sso:member", email: "member@corp.example",
        name: "Member", groups: ["engineering"], lastSeenAt: "",
      },
    },
    bundleRevision: "rev_1",
    bundles: {},
    sharing: { mode: "", updatedAt: "", providers: [], installed: [], catalog: [] },
    usage: [],
    masking: [],
  }));
  const { startServer } = await import("../src/server.mjs");
  const started = startServer({ port: 0 });
  before(async () => {
    const port = await started.listening;
    BASE = `http://127.0.0.1:${port}`;
  });
  after(() => started.server.close());
}

async function call(pathname, { method = "GET", body, token, headers = {} } = {}) {
  const response = await fetch(new URL(pathname, `${BASE}/`), {
    method,
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "error",
  });
  const text = await response.text();
  let payload = null;
  try {
    payload = text.trim() ? JSON.parse(text) : null;
  } catch {
    payload = text;
  }
  return { status: response.status, payload };
}

async function enroll(email) {
  const r = await call("/api/v1/device/enroll", {
    method: "POST",
    body: {
      schemaVersion: 1,
      code: `demo:${email}`,
      redirectUri: "http://127.0.0.1:3488/oidc/callback",
      device: { name: "TEST-PC", platform: "windows" },
    },
  });
  assert.equal(r.status, 200, `enroll ${email}: ${JSON.stringify(r.payload)}`);
  return r.payload;
}

async function gatewayKeys() {
  if (!TOKEN) return null;
  const response = await fetch(new URL("/v1/magpie/admin/gateway/keys", `${GATEWAY_ADMIN}/`), {
    headers: { authorization: `Bearer ${TOKEN}` },
  });
  if (!response.ok) return null;
  const payload = await response.json();
  return Array.isArray(payload.keys) ? payload.keys : [];
}

test("discovery says where to sign in, with no token", async () => {
  const r = await call("/api/v1/corp/config");
  assert.equal(r.status, 200);
  assert.equal(r.payload.schemaVersion, 1);
  assert.ok(r.payload.oidc.authorizationEndpoint);
  assert.ok(r.payload.gateway.baseUrl);
});

test("a device enrolls, and its token is a gateway key", { skip: !HAVE_GATEWAY && "no gateway admin token: an enroll needs one" }, async () => {
  const device = await enroll("unit-token@corp.example");
  assert.match(device.deviceToken, /^sk-/);
  assert.ok(device.expiresAt);

  const keys = await gatewayKeys();
  if (keys) {
    const key = keys.find((k) => k.id && k.name.includes("unit-token@corp.example"));
    assert.ok(key, "the gateway has a key named for this device's user");
    assert.equal(key.state, "enabled");
  }

  // the token opens the bundle
  const bundle = await call("/api/v1/client/bundle", { token: device.deviceToken });
  assert.equal(bundle.status, 200);
  assert.ok(Array.isArray(bundle.payload.providers));
});

test("enrolling again replaces the device's key, and the old one stops working", { skip: !HAVE_GATEWAY && "no gateway admin token" }, async () => {
  const first = await enroll("unit-again@corp.example");
  const second = await enroll("unit-again@corp.example");
  assert.notEqual(first.deviceId, second.deviceId);
  assert.equal(first.user.id, second.user.id, "one person, two devices");

  const stale = await call("/api/v1/client/bundle", { token: first.deviceToken });
  assert.equal(stale.status, 401, "the device before it is no longer known here");

  const fresh = await call("/api/v1/client/bundle", { token: second.deviceToken });
  assert.equal(fresh.status, 200);
});

test("a device refreshes its token, and the old one stops working", { skip: !HAVE_GATEWAY && "no gateway admin token" }, async () => {
  const first = await enroll("unit-refresh@corp.example");
  const refreshed = await call("/api/v1/device/refresh", {
    method: "POST",
    token: first.deviceToken,
    body: { schemaVersion: 1, deviceToken: first.deviceToken },
  });
  assert.equal(refreshed.status, 200, JSON.stringify(refreshed.payload));
  assert.equal(refreshed.payload.deviceId, first.deviceId);
  assert.notEqual(refreshed.payload.deviceToken, first.deviceToken);
  assert.ok(refreshed.payload.expiresAt);

  const stale = await call("/api/v1/client/bundle", { token: first.deviceToken });
  assert.equal(stale.status, 401, "the token before the refresh is no longer known");

  const fresh = await call("/api/v1/client/bundle", { token: refreshed.payload.deviceToken });
  assert.equal(fresh.status, 200);
});

test("a bad token is refused with a stable code", async () => {
  const r = await call("/api/v1/client/bundle", { token: "sk-magpie-key-not-real" });
  assert.equal(r.status, 401);
  assert.equal(r.payload.error.code, "invalid_device_token");
  assert.equal(r.payload.error.retryable, false);

  const refresh = await call("/api/v1/device/refresh", {
    method: "POST",
    body: { schemaVersion: 1, deviceToken: "sk-magpie-key-not-real" },
  });
  assert.equal(refresh.status, 401);
  assert.equal(refresh.payload.error.code, "invalid_device_token");
});

test("the bundle answers 304 for the revision it already gave", { skip: !HAVE_GATEWAY && "a sign-in needs a gateway" }, async () => {
  const device = await enroll("unit-etag@corp.example");
  const first = await call("/api/v1/client/bundle", { token: device.deviceToken });
  const again = await call("/api/v1/client/bundle", {
    token: device.deviceToken,
    headers: { "if-none-match": `"${first.payload.revision}"` },
  });
  assert.equal(again.status, 304);
});

test("usage is taken once per row, however many times it is sent", { skip: !HAVE_GATEWAY && "a sign-in needs a gateway" }, async () => {
  const device = await enroll("unit-usage@corp.example");
  const row = {
    rowId: "sha256:unit-row", at: "2026-11-09T00:00:00Z", agent: "claude",
    provider: "corp", model: "deepseek-flash", kind: "chat",
    sessionId: "s-unit", input: 100, output: 20, cacheRead: 0, ms: 500, status: 200, error: "",
  };
  const send = () =>
    call("/api/v1/telemetry/usage", {
      method: "POST", token: device.deviceToken,
      body: { schemaVersion: 1, batchId: "b", cursor: { from: "", to: "2026-11-09T00:10:00Z" }, rows: [row] },
    });
  const first = await send();
  assert.equal(first.payload.accepted, 1);
  const again = await send();
  assert.equal(again.payload.accepted, 0);
  assert.equal(again.payload.duplicates, 1, "the same row twice counts once");
});

test("a usage row is stored only as the fields the protocol names", { skip: !HAVE_GATEWAY && "a sign-in needs a gateway" }, async () => {
  const device = await enroll("unit-fields@corp.example");
  await call("/api/v1/telemetry/usage", {
    method: "POST", token: device.deviceToken,
    body: {
      schemaVersion: 1, batchId: "b", cursor: { from: "", to: "2026-11-09T01:00:00Z" },
      rows: [{
        rowId: "sha256:unit-fields", at: "2026-11-09T00:30:00Z", agent: "claude",
        provider: "corp", model: "deepseek-flash", input: 1, output: 1, status: 200,
        prompt: "the user's secret prompt", providerAccount: "someone@vendor.example",
        host: "internal.vendor.example", cookie: "session=abc",
      }],
    },
  });
  const summary = await call("/__admin/summary");
  const stored = JSON.stringify(summary.payload.usage);
  assert.ok(!stored.includes("the user's secret prompt"), "a prompt never reaches this server");
  assert.ok(!stored.includes("someone@vendor.example"), "the vendor's account never does either");
  assert.ok(!stored.includes("internal.vendor.example"), "nor the vendor's host");
});

test("masking arrives as kinds and placeholders, never a value", { skip: !HAVE_GATEWAY && "a sign-in needs a gateway" }, async () => {
  const device = await enroll("unit-masking@corp.example");
  const r = await call("/api/v1/telemetry/masking", {
    method: "POST", token: device.deviceToken,
    body: {
      schemaVersion: 1, batchId: "b", cursor: { from: "", to: "2026-11-09T01:00:00Z" },
      hits: [{
        at: "2026-11-09T00:30:00Z", agent: "claude", provider: "corp", model: "deepseek-flash",
        what: "chat", count: 1, kinds: ["API_KEY"], placeholders: ["{{API_KEY_1}}"], lengths: [51],
        snips: { "{{API_KEY_1}}": "sk-live-should-not-be-stored" },
      }],
    },
  });
  assert.equal(r.status, 200);
  const summary = await call("/__admin/summary");
  assert.ok(!JSON.stringify(summary.payload).includes("sk-live-should-not-be-stored"));
});

test("a body over the limit is refused, not read", { skip: !HAVE_GATEWAY && "a sign-in needs a gateway" }, async () => {
  const device = await enroll("unit-large@corp.example");
  const r = await call("/api/v1/telemetry/usage", {
    method: "POST", token: device.deviceToken,
    body: { schemaVersion: 1, batchId: "b", rows: [{ filler: "x".repeat(5 << 20) }] },
  });
  assert.equal(r.status, 413);
});

test("the admin summary says which resources the bundle hands out", async () => {
  const summary = await call("/__admin/summary");
  assert.equal(summary.status, 200);
  assert.deepEqual(summary.payload.resources, { instructions: [], mcp: [], skills: [] });
});

// ---- the administrator's control plane ----------------------------------
//
// These use the seeded devices above, so they run without an identity
// provider or a gateway. A live run (CORP_BASE set) has neither seeded
// device, and they are skipped.

const localOnly = LIVE ? "the seeded directory exists only in the local run" : false;

test("a device asks who it is, and the administrator is told", { skip: localOnly }, async () => {
  const admin = await call("/api/v1/device/me", { token: ADMIN_TOKEN });
  assert.equal(admin.status, 200);
  assert.equal(admin.payload.user.email, "admin@corp.example");
  assert.equal(admin.payload.user.role, "admin");
  assert.equal(admin.payload.device.id, "dev_admin");
  assert.ok(admin.payload.sharing && Array.isArray(admin.payload.sharing.catalog));

  const member = await call("/api/v1/device/me", { token: MEMBER_TOKEN });
  assert.equal(member.status, 200);
  assert.equal(member.payload.user.role, "member");
});

test("administrator routes refuse a member's device token", { skip: localOnly }, async () => {
  const attempts = [
    ["GET", "/api/v1/admin/sharing", undefined],
    ["GET", "/api/v1/admin/people", undefined],
    ["PUT", "/api/v1/admin/sharing", { mode: "off" }],
    ["PATCH", "/api/v1/admin/people/dev_member", { models: [] }],
  ];
  for (const [method, pathname, body] of attempts) {
    const r = await call(pathname, { method, token: MEMBER_TOKEN, body });
    assert.equal(r.status, 403, `${method} ${pathname}`);
    assert.equal(r.payload.error.code, "forbidden_admin");
  }
});

test("turning sharing off publishes no enterprise provider", { skip: localOnly }, async () => {
  const changed = await call("/api/v1/admin/sharing", {
    method: "PUT", token: ADMIN_TOKEN, body: { mode: "off" },
  });
  assert.equal(changed.status, 200);
  assert.equal(changed.payload.sharing.mode, "off");

  const bundle = await call("/api/v1/client/bundle", { token: MEMBER_TOKEN });
  assert.equal(bundle.status, 200);
  assert.deepEqual(bundle.payload.providers, []);
  assert.equal(bundle.payload.sharing.mode, "off");
});

test("sharing the gateway as a Remote magpie publishes the models named", { skip: localOnly }, async () => {
  const changed = await call("/api/v1/admin/sharing", {
    method: "PUT",
    token: ADMIN_TOKEN,
    body: { mode: "remote", models: ["deepseek-v4-pro", "kimi-k3", "deepseek-v4-pro"] },
  });
  assert.equal(changed.status, 200);
  assert.equal(changed.payload.sharing.mode, "remote");
  assert.deepEqual(changed.payload.catalog, ["deepseek-v4-pro", "kimi-k3"], "a model is named once");

  const bundle = await call("/api/v1/client/bundle", { token: MEMBER_TOKEN });
  assert.equal(bundle.payload.providers[0].id, "corp");
  assert.equal(bundle.payload.providers[0].mode, "gateway");
  assert.deepEqual(bundle.payload.providers[0].models, ["deepseek-v4-pro", "kimi-k3"]);
  assert.equal(bundle.payload.sharing.sources[0].id, "corp");

  const sharing = await call("/api/v1/admin/sharing", { token: ADMIN_TOKEN });
  assert.equal(sharing.status, 200);
  assert.equal(sharing.payload.sharing.mode, "remote");
  assert.equal(sharing.payload.gateway.adminConfigured, false);
});

test("an unknown sharing mode is refused", { skip: localOnly }, async () => {
  const r = await call("/api/v1/admin/sharing", {
    method: "PUT", token: ADMIN_TOKEN, body: { mode: "sideways" },
  });
  assert.equal(r.status, 422);
  assert.equal(r.payload.error.code, "invalid_mode");
});

test("sharing native providers fails closed without a gateway", { skip: localOnly }, async () => {
  const r = await call("/api/v1/admin/sharing", {
    method: "PUT",
    token: ADMIN_TOKEN,
    body: {
      mode: "native",
      providers: [{
        id: "alpha", name: "Alpha", chat: "https://api.alpha.example/v1",
        models: ["alpha-1"], key: "sk-alpha-secret",
      }],
    },
  });
  assert.equal(r.status, 502);
  assert.match(r.payload.error.message, /CORP_GATEWAY_ADMIN_TOKEN/);
});

test("the administrator reads people, and a key edit without a gateway fails closed", { skip: localOnly }, async () => {
  const listed = await call("/api/v1/admin/people", { token: ADMIN_TOKEN });
  assert.equal(listed.status, 200);
  assert.equal(listed.payload.gateway.keysReadable, false);
  assert.ok(listed.payload.gateway.error, "the page is told why no key is shown");
  const admin = listed.payload.people.find((person) => person.email === "admin@corp.example");
  assert.equal(admin.role, "admin");
  assert.equal(admin.devices[0].key, null);

  const edit = await call("/api/v1/admin/people/dev_admin", {
    method: "PATCH", token: ADMIN_TOKEN, body: { models: ["alpha-1"], readOnly: true },
  });
  assert.equal(edit.status, 502);
  assert.equal(edit.payload.error.code, "gateway_not_configured");
});
