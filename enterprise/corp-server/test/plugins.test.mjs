// Who a plugin policy names, and what the bundle then carries.
//
// The pure function is tested alone; the routes are tested against a
// server of this file's own with two made-up devices and no gateway.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { before, after } from "node:test";
import assert from "node:assert/strict";

const sha256 = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");

const STATE_FILE = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "corp-plugins-")), "state.json");
const TOKEN_A = "token-alice";
const TOKEN_B = "token-bob";

fs.writeFileSync(STATE_FILE, JSON.stringify({
  version: 1,
  devices: {
    dev_a: { id: "dev_a", userId: "usr_a", name: "ALICE-PC", state: "active", tokenDigest: sha256(TOKEN_A), expiresAt: "" },
    dev_b: { id: "dev_b", userId: "usr_b", name: "BOB-PC", state: "active", tokenDigest: sha256(TOKEN_B), expiresAt: "" },
  },
  users: {
    usr_a: { id: "usr_a", email: "alice@corp.example", name: "Alice", groups: ["研发"], lastSeenAt: "" },
    usr_b: { id: "usr_b", email: "bob@corp.example", name: "Bob", groups: ["销售"], lastSeenAt: "" },
  },
  bundleRevision: "rev_3",
  bundles: {},
  sharing: { mode: "", updatedAt: "", providers: [], installed: [], catalog: [] },
  pluginPolicy: null,
  usage: [],
  masking: [],
}, null, 2));

process.env.CORP_STATE_FILE = STATE_FILE;
process.env.CORP_PORT = "0";
process.env.CORP_GATEWAY_ADMIN_TOKEN = "";
process.env.CORP_ADMIN_TOKEN = "";
process.env.CORP_CURSOR_BRIDGE = "off";

const { cursorBridgeFor, startServer } = await import("../src/server.mjs");

let BASE = "";
let started = null;

before(async () => {
  started = startServer({ port: 0 });
  BASE = `http://127.0.0.1:${await started.listening}`;
});

after(() => started?.server.close());

async function call(pathname, { method = "GET", body, token } = {}) {
  const response = await fetch(new URL(pathname, `${BASE}/`), {
    method,
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "error",
  });
  const text = await response.text();
  return { status: response.status, payload: text.trim() ? JSON.parse(text) : null };
}

const BUNDLE = {
  revision: "rev_3",
  providers: [{ id: "corp", models: ["deepseek-v4-pro", "deepseek-flash"], defaultModel: "deepseek-v4-pro", enabled: true }],
};

const POLICY = { enabled: true, users: ["alice@corp.example"], groups: [], model: "" };

test("a disabled policy names nobody", () => {
  for (const user of [{ email: "alice@corp.example" }, { email: "anyone@corp.example" }]) {
    assert.equal(cursorBridgeFor(user, { ...POLICY, enabled: false }, BUNDLE), null);
  }
});

test("a named email gets the bridge, on the corp provider's default model", () => {
  const entry = cursorBridgeFor({ email: "Alice@Corp.Example" }, POLICY, BUNDLE);
  assert.equal(entry.id, "cursor-bridge");
  assert.equal(entry.model, "corp/deepseek-v4-pro");
  assert.equal(entry.enabled, true);
});

test("a person the policy doesn't name gets nothing", () => {
  assert.equal(cursorBridgeFor({ email: "bob@corp.example", groups: ["销售"] }, POLICY, BUNDLE), null);
});

test("a named group gets the bridge, and everyone does too", () => {
  const byGroup = cursorBridgeFor(
    { email: "bob@corp.example", groups: ["研发"] },
    { ...POLICY, users: [], groups: ["研发"] },
    BUNDLE,
  );
  assert.equal(byGroup.id, "cursor-bridge");

  const everyone = cursorBridgeFor({ email: "nobody@corp.example" }, { ...POLICY, users: ["*"] }, BUNDLE);
  assert.equal(everyone.id, "cursor-bridge");
});

test("a named model is used as it is, or under the corp provider", () => {
  assert.equal(cursorBridgeFor({ email: "alice@corp.example" }, { ...POLICY, model: "deepseek-flash" }, BUNDLE).model, "corp/deepseek-flash");
  assert.equal(cursorBridgeFor({ email: "alice@corp.example" }, { ...POLICY, model: "corp/other" }, BUNDLE).model, "corp/other");
});

test("a bundle with no provider cannot carry a bridge", () => {
  assert.equal(cursorBridgeFor({ email: "alice@corp.example" }, POLICY, { ...BUNDLE, providers: [] }), null);
});

test("the bundle carries the bridge only for the person the policy names", async () => {
  const saved = await call("/__admin/plugins/cursor-bridge", { method: "POST", body: POLICY });
  assert.equal(saved.status, 200, JSON.stringify(saved.payload));
  assert.equal(saved.payload.cursorBridge.enabled, true);
  assert.deepEqual(saved.payload.assigned.map((person) => person.email), ["alice@corp.example"]);

  const alice = await call("/api/v1/client/bundle?revision=rev_3", { token: TOKEN_A });
  assert.equal(alice.status, 200, "a policy change publishes a new revision");
  assert.notEqual(alice.payload.revision, "rev_3");
  assert.deepEqual(alice.payload.plugins.map((plugin) => [plugin.id, plugin.model]), [["cursor-bridge", "corp/deepseek-v4-pro"]]);

  const bob = await call("/api/v1/client/bundle?revision=rev_3", { token: TOKEN_B });
  assert.equal(bob.status, 200);
  assert.deepEqual(bob.payload.plugins, []);
});

test("the admin summary tells the same policy", async () => {
  const summary = await call("/__admin/summary");
  assert.equal(summary.status, 200);
  assert.equal(summary.payload.plugins.cursorBridge.enabled, true);
  assert.deepEqual(summary.payload.plugins.assigned, ["alice@corp.example"]);
});

test("a policy the server can't store is refused whole", async () => {
  const cases = [
    [{ enabled: "yes" }, "enabled"],
    [{ enabled: true, users: "alice@corp.example" }, "users"],
    [{ enabled: true, users: [42] }, "strings"],
    [{ enabled: true, model: "not a model!" }, "model"],
  ];
  for (const [body] of cases) {
    const r = await call("/__admin/plugins/cursor-bridge", { method: "POST", body });
    assert.equal(r.status, 422, JSON.stringify(body));
    assert.equal(r.payload.error.code, "invalid_plugin_policy");
  }

  const read = await call("/__admin/plugins");
  assert.equal(read.payload.cursorBridge.enabled, true, "the refused writes changed nothing");
});

test("turning the policy off reaches the device, then settles", async () => {
  const before = await call("/api/v1/client/bundle", { token: TOKEN_A });
  assert.equal(before.status, 200);
  assert.equal(before.payload.plugins.length, 1);
  const carrying = before.payload.revision;

  const off = await call("/__admin/plugins/cursor-bridge", {
    method: "POST",
    body: { enabled: false, users: [], groups: [], model: "" },
  });
  assert.equal(off.status, 200);
  assert.deepEqual(off.payload.assigned, []);

  // A device holding the revision that carried the bridge is handed the
  // withdrawal, not 304 — otherwise it would keep the plugin forever.
  const after = await call(`/api/v1/client/bundle?revision=${carrying}`, { token: TOKEN_A });
  assert.equal(after.status, 200);
  assert.deepEqual(after.payload.plugins, []);
  assert.notEqual(after.payload.revision, carrying);

  // The withdrawal is now what it applied, so the next ask settles.
  const settled = await call(`/api/v1/client/bundle?revision=${after.payload.revision}`, { token: TOKEN_A });
  assert.equal(settled.status, 304);

  const read = await call("/__admin/plugins");
  assert.equal(read.payload.cursorBridge.enabled, false);
  assert.deepEqual(read.payload.assigned, []);
});
