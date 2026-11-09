// The promises this server makes.
//
// Two ways to run it: against a live server at CORP_BASE (a system test,
// with a gateway behind it where CORP_GATEWAY_ADMIN_URL is set), or, when
// CORP_BASE is unset, by starting this file's server on a port of its own.
// A sign-in needs the gateway, so with no gateway the enroll cases say so
// and the contract cases run alone.
import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

let BASE = process.env.CORP_BASE || "";
const GATEWAY_ADMIN = process.env.CORP_GATEWAY_ADMIN_URL || "http://127.0.0.1:3501";
const TOKEN = String(process.env.CORP_GATEWAY_ADMIN_TOKEN || "").trim();
const HAVE_GATEWAY = Boolean(TOKEN);

if (!BASE) {
  // a server of this test's own, on a free port, with its state in a
  // temporary folder: no gateway, so only the parts that need none run
  const stateFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "corp-server-")), "state.json");
  process.env.CORP_STATE_FILE = stateFile;
  process.env.CORP_ALLOW_DEMO_SIGNIN = "true";
  process.env.CORP_PORT = "0";
  process.env.CORP_GATEWAY_ADMIN_TOKEN = "";
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

test("a bad token is refused with a stable code", async () => {
  const r = await call("/api/v1/client/bundle", { token: "sk-magpie-key-not-real" });
  assert.equal(r.status, 401);
  assert.equal(r.payload.error.code, "invalid_device_token");
  assert.equal(r.payload.error.retryable, false);
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
