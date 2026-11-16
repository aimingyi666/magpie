// An employee sharing their own WorkBuddy account.
//
// A stand-in gateway runs the sign-in the way the real one does: the
// plugin-signin route answers a vendor URL and a state, the signin route
// reports that state until it is done, and the provider's models come back
// as the plugin listed them (one unticked). The corporate server must hand
// the page only the URL and the outcome, import the models that are on,
// and keep the account it read out of anything a page can see.
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test, { after, before } from "node:test";
import assert from "node:assert/strict";

const sha256 = (value) => crypto.createHash("sha256").update(String(value)).digest("hex");
const ADMIN_TOKEN = "y".repeat(32);
const ALICE = "token-alice";
const BOB = "token-bob";
const ADMIN_DEVICE = "token-admin-device";

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      if (!chunks.length) return resolve(null);
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

// The models a WorkBuddy account serves once it is signed in. wb-2 is
// unticked in its owner's editor, so it must not reach the corporation.
const MODELS = [
  { id: "wb-1", name: "WorkBuddy 1", on: true },
  { id: "wb-2", name: "WorkBuddy 2", on: false },
  { id: "wb-3", name: "WorkBuddy 3", on: true },
];

// What the international build lists once a sign-in is imported into it.
const IMPORT_MODELS = [
  { id: "wbai-1", name: "WorkBuddy AI 1", on: true },
  { id: "wbai-2", name: "WorkBuddy AI 2", on: false },
];

function fakeGateway() {
  const signIns = new Map();
  const received = [];
  const importedAuths = [];
  let seq = 0;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const body = await readBody(req);
    received.push({ method: req.method, path: url.pathname, body });
    const json = (status, payload) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
    };

    if (req.headers.authorization !== `Bearer ${ADMIN_TOKEN}`) {
      return json(401, { ok: false, error: { code: "unauthorized", message: "token" } });
    }

    if (req.method === "POST" && url.pathname === "/v1/magpie/admin/plugin-signin") {
      // the international build is a plugin this gateway does not have
      if (body?.provider !== "workbuddy" || body.method !== 0 || body.concurrent !== true) {
        return json(400, { ok: false, error: { code: "invalid_provider", message: "the plugin has no such way to sign in" } });
      }
      const id = `sig_${++seq}`;
      const state = {
        id,
        agent: "workbuddy",
        url: `https://copilot.tencent.com/login?state=${id}`,
        state: "waiting",
        instructions: "扫描页面上的二维码登录 WorkBuddy",
        user: "",
        // a vendor secret that must never be copied anywhere
        token: "wb-access-secret",
      };
      signIns.set(id, state);
      return json(200, { ...state, opened: false });
    }

    if (req.method === "GET" && url.pathname.startsWith("/v1/magpie/admin/signin/")) {
      const id = decodeURIComponent(url.pathname.split("/").pop());
      const state = signIns.get(id);
      // the real gateway answers an unknown sign-in with its 404 page
      if (!state) {
        res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
        return res.end("404 page not found\n");
      }
      return json(200, state);
    }

    if (req.method === "POST" && url.pathname.endsWith("/cancel")) {
      const id = decodeURIComponent(url.pathname.split("/").slice(-2)[0]);
      const state = signIns.get(id);
      if (state) state.state = "canceled";
      res.writeHead(204);
      return res.end();
    }

    if (req.method === "POST" && url.pathname === "/v1/magpie/admin/provider/models") {
      const lists = { workbuddy: MODELS, "workbuddy-ai": IMPORT_MODELS };
      const names = { workbuddy: "WorkBuddy", "workbuddy-ai": "WorkBuddy AI" };
      const models = lists[body?.id];
      if (!models) {
        return json(400, { ok: false, error: { code: "unknown_provider", message: `no provider ${body?.id}` } });
      }
      return json(200, {
        count: models.length,
        provider: { id: body.id, name: names[body.id], models, token: "wb-access-secret" },
      });
    }

    // a sign-in imported from an employee's own magpie
    if (req.method === "POST" && url.pathname === "/v1/magpie/admin/plugin-import") {
      if (body?.provider !== "workbuddy" && body?.provider !== "workbuddy-ai") {
        return json(400, { ok: false, error: { code: "invalid_provider", message: "no such plugin" } });
      }
      if (!body.auth || body.auth.type !== "oauth" || !body.auth.refresh) {
        return json(400, { ok: false, error: { code: "invalid_auth", message: "auth" } });
      }
      importedAuths.push(body);
      return json(200, { account: `${body.provider}#imported` });
    }

    if (req.method === "GET" && url.pathname === "/v1/magpie/admin/providers") {
      return json(200, { ok: true, providers: [{ id: "workbuddy", name: "WorkBuddy", models: ["wb-1", "wb-3"] }] });
    }

    return json(404, { ok: false, error: { code: "not_found", message: "path" } });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, base: `http://127.0.0.1:${server.address().port}`, signIns, received, importedAuths });
    });
  });
}

const STATE_FILE = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "corp-workbuddy-")), "state.json");
fs.writeFileSync(STATE_FILE, JSON.stringify({
  version: 1,
  devices: {
    dev_a: { id: "dev_a", userId: "usr_a", name: "ALICE-PC", state: "active", tokenDigest: sha256(ALICE), expiresAt: "" },
    dev_b: { id: "dev_b", userId: "usr_b", name: "BOB-PC", state: "active", tokenDigest: sha256(BOB), expiresAt: "" },
    dev_admin: { id: "dev_admin", userId: "usr_admin", name: "ADMIN-PC", state: "active", tokenDigest: sha256(ADMIN_DEVICE), expiresAt: "" },
  },
  users: {
    usr_a: { id: "usr_a", email: "alice@corp.example", name: "Alice", groups: ["研发"], lastSeenAt: "" },
    usr_b: { id: "usr_b", email: "bob@corp.example", name: "Bob", groups: ["销售"], lastSeenAt: "" },
    usr_admin: { id: "usr_admin", email: "root@corp.example", name: "Root", groups: ["admins"], lastSeenAt: "" },
  },
  bundleRevision: "rev_3",
  bundles: {},
  sharing: { mode: "remote", updatedAt: "", providers: [], installed: [], catalog: ["alpha-1"] },
  pluginPolicy: null,
  usage: [],
  masking: [],
}, null, 2));

const gateway = await fakeGateway();

process.env.CORP_STATE_FILE = STATE_FILE;
process.env.CORP_PORT = "0";
process.env.CORP_ALLOW_DEMO_SIGNIN = "true";
process.env.CORP_GATEWAY_ADMIN_URL = gateway.base;
process.env.CORP_GATEWAY_ADMIN_TOKEN = ADMIN_TOKEN;
process.env.CORP_GATEWAY_PUBLIC_URL = "http://127.0.0.1:3499/v1";

const { startServer } = await import("../src/server.mjs");
const started = startServer({ port: 0 });
let BASE = "";
before(async () => {
  BASE = `http://127.0.0.1:${await started.listening}`;
});
after(() => {
  started.server.close();
  gateway.server.close();
});

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

let shareId = "";

test("an employee starts a WorkBuddy sign-in and gets the vendor's page, not a token", async () => {
  const startedShare = await call("/api/v1/share/workbuddy/start", {
    method: "POST",
    token: ALICE,
    body: { provider: "workbuddy" },
  });
  assert.equal(startedShare.status, 200, JSON.stringify(startedShare.payload));
  assert.match(startedShare.payload.share.id, /^shr_[0-9a-f]{24}$/);
  assert.equal(startedShare.payload.share.provider, "workbuddy");
  assert.equal(startedShare.payload.share.providerName, "WorkBuddy（国内版）");
  assert.equal(startedShare.payload.share.state, "waiting");
  assert.match(startedShare.payload.share.url, /^https:\/\/copilot\.tencent\.com\/login\?state=sig_1$/);
  assert.match(startedShare.payload.instructions, /二维码/);
  shareId = startedShare.payload.share.id;

  const asked = gateway.received.find((item) => item.path === "/v1/magpie/admin/plugin-signin");
  assert.deepEqual(asked.body, { provider: "workbuddy", method: 0, concurrent: true },
    "two employees can be scanning for the same provider at once");
  assert.ok(!JSON.stringify(startedShare.payload).includes("wb-access-secret"));
});

test("another person's share is not this device's to read", async () => {
  const other = await call(`/api/v1/share/workbuddy/${shareId}`, { token: BOB });
  assert.equal(other.status, 404);
  assert.equal(other.payload.error.code, "not_found");
});

test("polling while the page is open answers waiting, and the URL stays", async () => {
  const polled = await call(`/api/v1/share/workbuddy/${shareId}`, { token: ALICE });
  assert.equal(polled.status, 200, JSON.stringify(polled.payload));
  assert.equal(polled.payload.share.state, "waiting");
  assert.match(polled.payload.share.url, /copilot\.tencent\.com/);
  assert.match(polled.payload.instructions, /二维码/);
});

test("a finished sign-in records the models that are on, and hands none out yet", async () => {
  const signIn = gateway.signIns.get("sig_1");
  signIn.state = "done";
  signIn.user = "alice@wb.example";

  const polled = await call(`/api/v1/share/workbuddy/${shareId}`, { token: ALICE });
  assert.equal(polled.status, 200, JSON.stringify(polled.payload));
  assert.equal(polled.payload.share.state, "done");
  assert.equal(polled.payload.share.account, "alice@wb.example");
  assert.deepEqual(polled.payload.share.models, ["wb-1", "wb-3"],
    "a model its owner unticked is not handed out");
  assert.ok(polled.payload.share.completedAt);

  const bundle = await call("/api/v1/client/bundle", { token: BOB });
  assert.equal(bundle.status, 200, JSON.stringify(bundle.payload));
  assert.deepEqual(bundle.payload.providers[0].models, ["alpha-1"],
    "an employee's share waits for the administrator, it does not open every model");
  assert.ok(!bundle.payload.sharing.sources.some((source) => source.name.includes("WorkBuddy")),
    "nothing is handed out until the administrator ticks it");

  const summary = await call("/__admin/summary");
  assert.equal(summary.payload.workbuddy.served, true);
  assert.equal(summary.payload.workbuddy.imported[0].provider, "workbuddy");
  assert.equal(summary.payload.workbuddy.imported[0].models, 2);
  assert.equal(summary.payload.workbuddy.imported[0].selected, 0);
  assert.deepEqual(summary.payload.workbuddy.imported[0].accounts, ["alice@corp.example"]);
});

test("the administrator ticks which shared models are handed out", async () => {
  const member = await call("/api/v1/admin/workbuddy", { token: ALICE });
  assert.equal(member.status, 403, "a member can't choose what the corporation hands out");

  const shared = await call("/api/v1/admin/workbuddy", { token: ADMIN_DEVICE });
  assert.equal(shared.status, 200, JSON.stringify(shared.payload));
  assert.deepEqual(shared.payload.sources[0].models, ["wb-1", "wb-3"]);
  assert.deepEqual(shared.payload.sources[0].selected, []);
  assert.deepEqual(shared.payload.sources[0].accounts.map((item) => item.account), ["alice@wb.example"]);

  const ticked = await call("/api/v1/admin/workbuddy", {
    method: "PUT",
    token: ADMIN_DEVICE,
    body: { provider: "workbuddy", models: ["wb-1"] },
  });
  assert.equal(ticked.status, 200, JSON.stringify(ticked.payload));
  assert.deepEqual(ticked.payload.sources[0].selected, ["wb-1"]);

  const bundle = await call("/api/v1/client/bundle", { token: BOB });
  assert.deepEqual(bundle.payload.providers[0].models, ["alpha-1", "wb-1"],
    "only the model the administrator ticked reaches devices");
  const source = bundle.payload.sharing.sources.find((item) => item.name.includes("WorkBuddy"));
  assert.ok(source, "a device can see where the model came from");
  assert.deepEqual(source.models, ["wb-1"]);

  const unknown = await call("/api/v1/admin/workbuddy", {
    method: "PUT",
    token: ADMIN_DEVICE,
    body: { provider: "workbuddy", models: ["wb-not-listed"] },
  });
  assert.equal(unknown.status, 422);
  assert.equal(unknown.payload.error.code, "unknown_model");
});

test("a share that is done is not polled again, and its import stays put", async () => {
  const before = gateway.received.filter((item) => item.method === "GET" && item.path.startsWith("/v1/magpie/admin/signin/")).length;
  const polled = await call(`/api/v1/share/workbuddy/${shareId}`, { token: ALICE });
  assert.equal(polled.payload.share.state, "done");
  const after = gateway.received.filter((item) => item.method === "GET" && item.path.startsWith("/v1/magpie/admin/signin/")).length;
  assert.equal(after, before, "a finished share is answered from what was recorded");
});

test("a share can be canceled, and the gateway is told", async () => {
  const startedShare = await call("/api/v1/share/workbuddy/start", {
    method: "POST", token: ALICE, body: { provider: "workbuddy" },
  });
  const id = startedShare.payload.share.id;
  const canceled = await call(`/api/v1/share/workbuddy/${id}/cancel`, { method: "POST", token: ALICE });
  assert.equal(canceled.status, 200, JSON.stringify(canceled.payload));
  assert.equal(canceled.payload.share.state, "canceled");
  assert.ok(gateway.received.some((item) => item.method === "POST" && item.path === "/v1/magpie/admin/signin/sig_2/cancel"));

  const polled = await call(`/api/v1/share/workbuddy/${id}`, { token: ALICE });
  assert.equal(polled.payload.share.state, "canceled");
});

test("a device's own shares come back with its details, and nobody else's", async () => {
  const alice = await call("/api/v1/device/me", { token: ALICE });
  assert.equal(alice.status, 200, JSON.stringify(alice.payload));
  assert.equal(alice.payload.workbuddy.shares.length, 2);
  assert.ok(alice.payload.workbuddy.shares.some((item) => item.state === "done"));
  assert.ok(alice.payload.workbuddy.shares.some((item) => item.state === "canceled"));

  const bob = await call("/api/v1/device/me", { token: BOB });
  assert.deepEqual(bob.payload.workbuddy.shares, []);
});

test("a provider this server doesn't share says so, and an unknown one is refused", async () => {
  const unknown = await call("/api/v1/share/workbuddy/start", {
    method: "POST", token: ALICE, body: { provider: "not-a-provider" },
  });
  assert.equal(unknown.status, 422);
  assert.equal(unknown.payload.error.code, "invalid_provider");

  const missing = await call("/api/v1/share/workbuddy/start", {
    method: "POST", token: ALICE, body: { provider: "workbuddy-ai" },
  });
  assert.equal(missing.status, 409, JSON.stringify(missing.payload));
  assert.equal(missing.payload.error.code, "workbuddy_unavailable");
  assert.match(missing.payload.error.message, /WorkBuddy 插件/);
});

test("no WorkBuddy token is written to this server's state", async () => {
  const saved = fs.readFileSync(STATE_FILE, "utf8");
  assert.ok(!saved.includes("wb-access-secret"), "a vendor field this server doesn't name is dropped");
  assert.ok(!saved.includes("copilot.tencent.com/login?state=sig_2"), "a canceled share keeps no page to reopen");
});

test("the administrator's summary names who shared and what came in", async () => {
  const summary = await call("/__admin/summary");
  assert.equal(summary.status, 200);
  const shares = summary.payload.workbuddy.shares;
  assert.ok(shares.some((share) => share.email === "alice@corp.example" && share.state === "done"));
  assert.ok(!JSON.stringify(summary.payload).includes("wb-access-secret"));
});

test("a sign-in this computer already has is imported instead of scanned again", async () => {
  const secret = "wb-local-refresh-token-canary";
  const imported = await call("/api/v1/share/workbuddy/import", {
    method: "POST",
    token: ALICE,
    body: {
      provider: "workbuddy-ai",
      account: "152****6538",
      auth: {
        type: "oauth",
        refresh: secret,
        access: "wb-local-access",
        accountId: "152****6538",
        expires: 9999999999999,
      },
    },
  });
  assert.equal(imported.status, 200, JSON.stringify(imported.payload));
  assert.equal(imported.payload.share.provider, "workbuddy-ai");
  assert.equal(imported.payload.share.state, "done");
  assert.deepEqual(imported.payload.share.models, ["wbai-1"],
    "a model its owner unticked is not handed out");
  assert.equal(imported.payload.share.account, "152****6538");
  assert.ok(!JSON.stringify(imported.payload).includes(secret), "the sign-in is not answered back");

  const sent = gateway.importedAuths.at(-1);
  assert.equal(sent.provider, "workbuddy-ai");
  assert.equal(sent.auth.refresh, secret, "the sign-in reached the gateway");

  // the server writes no part of it: what it keeps is the account's name
  assert.ok(!fs.readFileSync(STATE_FILE, "utf8").includes(secret), "the state file holds a token");
  const summary = await call("/__admin/summary");
  assert.ok(!JSON.stringify(summary.payload).includes(secret), "the summary holds a token");

  // another person's import is not this device's to read
  const other = await call(`/api/v1/share/workbuddy/${imported.payload.share.id}`, { token: BOB });
  assert.equal(other.status, 404);

  // an import that isn't an OAuth sign-in, or names no WorkBuddy, is refused
  for (const body of [
    { provider: "workbuddy", account: "x", auth: { type: "api", key: "k" } },
    { provider: "workbuddy", account: "x" },
    { provider: "another", account: "x", auth: { type: "oauth", refresh: secret } },
  ]) {
    const refused = await call("/api/v1/share/workbuddy/import", { method: "POST", token: ALICE, body });
    assert.equal(refused.status, 422, JSON.stringify(refused.payload));
  }
});

test("an imported sign-in waits for the administrator, then is handed out", async () => {
  const before = await call("/api/v1/admin/workbuddy", { token: ADMIN_DEVICE });
  const source = before.payload.sources.find((item) => item.provider === "workbuddy-ai");
  assert.ok(source, "the administrator sees the imported provider");
  assert.deepEqual(source.models, ["wbai-1"]);
  assert.deepEqual(source.selected, [], "nothing is handed out before the tick");
  assert.deepEqual(source.accounts.map((item) => item.account), ["152****6538"]);

  const bundle = await call("/api/v1/client/bundle", { token: BOB });
  assert.ok(!bundle.payload.providers[0].models.includes("wbai-1"),
    "an imported account opens no model by itself");

  const ticked = await call("/api/v1/admin/workbuddy", {
    method: "PUT",
    token: ADMIN_DEVICE,
    body: { provider: "workbuddy-ai", models: ["wbai-1"] },
  });
  assert.equal(ticked.status, 200, JSON.stringify(ticked.payload));
  assert.deepEqual(
    ticked.payload.sources.find((item) => item.provider === "workbuddy-ai").selected,
    ["wbai-1"],
  );

  const after = await call("/api/v1/client/bundle", { token: BOB });
  assert.ok(after.payload.providers[0].models.includes("wbai-1"),
    "the model the administrator ticked reaches devices");
});
