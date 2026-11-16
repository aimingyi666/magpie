import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import { safeBase, stateDirectory, loadCorpConfig } from "../src/config.mjs";
import { deviceUsable } from "../src/store.mjs";
import { toUsageRow, toMaskingRow, sessionsOf, rowID, readUsageRows } from "../src/upload.mjs";
import { enabledProviders, providerConfig, providerModels, defaultModel } from "../src/providers.mjs";
import { applyResources } from "../src/resources.mjs";
import { magpieConfigDir, nativeProviders, nativeKeys, shareNativeProviders } from "../src/native.mjs";
import { readBundle } from "../src/providers.mjs";
import { createStore } from "../src/store.mjs";
import { syncBundle } from "../src/sync.mjs";

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "corp-plugin-"));
}

test("only https, or plain http on loopback, is a server address", () => {
  assert.equal(safeBase("https://ai.corp.example/"), "https://ai.corp.example");
  assert.equal(safeBase("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
  assert.equal(safeBase("http://localhost:8080/"), "http://localhost:8080");
  assert.equal(safeBase("http://ai.corp.example"), "", "clear http off loopback would send a device token in the open");
  assert.equal(safeBase("  "), "");
  assert.equal(safeBase("not a url"), "");
});

test("the state directory is per platform and can be moved", () => {
  assert.equal(stateDirectory({ MAGPIE_CORP_DIR: "/tmp/x" }), path.resolve("/tmp/x"));
  assert.match(stateDirectory({ LOCALAPPDATA: "C:\\Users\\a\\AppData\\Local" }), /MagpieCorp$/);
});

test("a device token with no expiry is usable, an expired one isn't", () => {
  const now = Date.parse("2026-11-08T00:00:00Z");
  assert.equal(deviceUsable({ deviceToken: "t" }, now), true);
  assert.equal(deviceUsable({ deviceToken: "t", expiresAt: "2026-11-07T00:00:00Z" }, now), false);
  assert.equal(deviceUsable({ deviceToken: "t", expiresAt: "2026-11-08T00:01:00Z" }, now), false, "five minutes of skew is spent");
  assert.equal(deviceUsable(null, now), false);
});

test("a usage row carries metadata and nothing else", () => {
  const row = toUsageRow({
    t: "2026-11-08T00:31:12Z",
    agent: "claude",
    provider: "corp",
    model: "kimi-k2.5",
    session: "s_1",
    in: 1200,
    out: 340,
    cache_read: 800,
    ms: 1830,
    status: 200,
    err: "the vendor said something about the user's prompt",
    err_type: "rate_limit",
    providerAccount: "someone@corp.example",
    host: "internal.vendor.example",
    callerKeyName: "alice",
  });
  assert.equal(row.input, 1200);
  assert.equal(row.cacheRead, 800);
  assert.equal(row.error, "rate_limit", "only the error's kind, never its text");
  assert.equal(row.providerAccount, undefined);
  assert.equal(row.host, undefined);
  assert.equal(row.callerKeyName, undefined);
  assert.match(row.rowId, /^sha256:[0-9a-f]{32}$/);
  assert.equal(rowID(row), row.rowId, "the id is stable for a resend");
});

test("a masking row keeps no value, only what magpie already made harmless", () => {
  const row = toMaskingRow({
    t: "2026-11-08T00:31:12Z",
    agent: "claude",
    what: "chat",
    n: 2,
    snips: { "{{API_KEY_1}}": "sk-live-abcd" },
    values: [{ p: "{{API_KEY_1}}", k: "API_KEY", b: "rule", h: "s", l: 51, n: 2 }],
  });
  assert.deepEqual(row.kinds, ["API_KEY"]);
  assert.deepEqual(row.placeholders, ["{{API_KEY_1}}"]);
  assert.deepEqual(row.lengths, [51]);
  assert.equal(row.snips, undefined, "a snippet of the real value never leaves");
});

test("sessions fold from usage rows without any content", () => {
  const rows = [
    { sessionId: "s_1", agent: "claude", at: "2026-11-08T00:00:00Z", model: "a", input: 10, output: 2, status: 200 },
    { sessionId: "s_1", agent: "claude", at: "2026-11-08T00:01:00Z", model: "b", input: 5, output: 1, status: 500 },
    { sessionId: "", agent: "claude", at: "2026-11-08T00:02:00Z", model: "a", input: 1, output: 1, status: 200 },
  ];
  const [session] = sessionsOf(rows);
  assert.equal(sessionsOf(rows).length, 1, "a row with no session is nobody's conversation");
  assert.equal(session.turns, 2);
  assert.equal(session.input, 15);
  assert.equal(session.errors, 1);
  assert.deepEqual(session.models, ["a", "b"]);
});

test("the ledger is read from a cursor, oldest first, and a broken line skipped", () => {
  const dir = tempDir();
  const lines = [
    { t: "2026-11-08T00:02:00Z", agent: "a", model: "m", in: 2, out: 1, status: 200 },
    "{ not json",
    { t: "2026-11-08T00:01:00Z", agent: "a", model: "m", in: 1, out: 1, status: 200 },
  ].map((v) => (typeof v === "string" ? v : JSON.stringify(v)));
  fs.writeFileSync(path.join(dir, "usage.jsonl"), lines.join("\n"));
  const all = readUsageRows(dir, "");
  assert.equal(all.length, 2);
  assert.equal(all[0].at, "2026-11-08T00:01:00Z");
  // A cursor is exclusive of earlier rows and inclusive of the same timestamp:
  // the server dedupes by rowId, so a same-second row must not be dropped.
  assert.equal(readUsageRows(dir, "2026-11-08T00:01:00Z").length, 2);
  assert.equal(readUsageRows(dir, "2026-11-08T00:01:00Z")[0].at, "2026-11-08T00:01:00Z");
  assert.equal(readUsageRows(dir, "2026-11-08T00:02:00Z").length, 1);
});

test("the bundle's provider is written as magpie's config", () => {
  const dir = tempDir();
  fs.writeFileSync(
    path.join(dir, "bundle.json"),
    JSON.stringify({
      revision: "rev_1",
      providers: [
        { id: "corp", name: "Corp Gateway", mode: "gateway", baseUrl: "https://ai.corp.example/v1", models: ["kimi-k2.5"], defaultModel: "kimi-k2.5" },
        { id: "corp-old", name: "Withdrawn", enabled: false, models: ["x"] },
      ],
    }),
  );
  const config = { baseUrl: "https://ai.corp.example/v1" };
  let saved = { appliedProviders: ["corp-old"] };
  const store = {
    state: () => saved,
    update: (fn) => (saved = fn({ ...saved })),
  };
  const cfg = { provider: { "corp-old": { name: "stale" }, mine: { name: "added by hand" } } };
  providerConfig(cfg, { provider: "corp", dir, config, store });
  assert.equal(cfg.provider["corp-old"], undefined, "a provider this plugin wrote and the corporation withdrew is taken away");
  assert.ok(cfg.provider.mine, "a provider the reader added by hand is never touched");
  assert.equal(cfg.provider.corp.name, "Corp Gateway");
  assert.equal(cfg.provider.corp.options.baseURL, "https://ai.corp.example/v1");
  assert.equal(cfg.provider.corp.api, "https://ai.corp.example/v1");
  assert.deepEqual(Object.keys(cfg.provider.corp.models), ["kimi-k2.5"]);
  assert.deepEqual(saved.appliedProviders, ["corp"]);
  assert.equal(defaultModel({ providers: [{ id: "corp", models: ["a", "b"] }] }, "corp"), "corp/a");
});

test("a model listing carries its own base, so a fresh host still works", async () => {
  const dir = tempDir();
  fs.writeFileSync(
    path.join(dir, "bundle.json"),
    JSON.stringify({ providers: [{ id: "corp", baseUrl: "https://ai.corp.example/v1", models: ["m1"] }] }),
  );
  const models = await providerModels({ provider: "corp", dir, config: { baseUrl: "" } });
  assert.equal(models.m1.provider.api, "https://ai.corp.example/v1");
  assert.equal(enabledProviders({ providers: [{ id: "corp" }, { id: "BAD ID" }] }).length, 1);
});

test("resources land in magpie's library, and only what this plugin added is removed", async () => {
  const dir = tempDir();
  const calls = [];
  const run = async (_bin, args) => {
    calls.push(args.join(" "));
    return { ok: true, code: "", message: "" };
  };
  const bundle = {
    instructions: [{ id: "ins_corp", content: "# Rules\n", agents: ["*"] }],
    mcp: [{
      name: "corp-kb",
      transport: "http",
      url: "https://mcp.corp.example/kb",
      headers: { Authorization: "Bearer corp" },
      agents: ["*"],
    }],
    skills: [{ name: "corp-report", agents: ["claude"], files: [{ path: "SKILL.md", content: "# Report\n" }] }],
  };
  const result = await applyResources(bundle, {
    configDir: dir,
    magpieBin: "magpie",
    applied: { mcp: ["gone-one"], skills: [], instructions: [] },
    run,
  });
  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.applied, { instructions: ["shared"], mcp: ["corp-kb"], skills: ["corp-report"] });
  assert.ok(calls.some((c) => c.startsWith("library instructions set")), "instructions go through the CLI");
  assert.ok(calls.some((c) => c === "library mcp rm gone-one"), "a withdrawn server this plugin added is removed");
  assert.ok(calls.some((c) => c.startsWith("library mcp add corp-kb https://mcp.corp.example/kb")), "a server is added with its agents");
  assert.ok(
    calls.some((c) => c.includes("header=Authorization:Bearer corp") && !c.includes("agents=")),
    "MCP headers go through as header=Name:value; * means every agent so agents= is omitted",
  );
  assert.ok(
    calls.some((c) => c.startsWith("library skill from ") && c.endsWith("agents=claude")),
    "a skill is installed through the CLI from a staged folder, given to the agents the bundle names",
  );
  assert.ok(calls.includes("library sync"), "one sync writes everything into the agents");
});

test("a skill the corporation withdrew is taken out through the CLI", async () => {
  const dir = tempDir();
  const calls = [];
  const result = await applyResources(
    { skills: [] },
    {
      configDir: dir,
      magpieBin: "magpie",
      applied: { mcp: [], skills: ["corp-report"], instructions: [] },
      run: async (_b, args) => (calls.push(args.join(" ")), { ok: true }),
    },
  );
  assert.deepEqual(result.errors, []);
  assert.ok(calls.includes("library skill rm corp-report"), "the library is the CLI's to change");
});

test("nothing is written when magpie's folder isn't known", async () => {
  const result = await applyResources({ mcp: [{ name: "x", url: "https://x" }] }, { configDir: "", magpieBin: "magpie", run: async () => ({ ok: true }) });
  assert.equal(result.errors[0].code, "config_dir_unknown");
});

test("a name that isn't a name is never a command", async () => {
  const dir = tempDir();
  const calls = [];
  await applyResources(
    { mcp: [{ name: "ok; rm -rf /", url: "https://x" }, { name: "--agents", url: "https://y" }] },
    { configDir: dir, magpieBin: "magpie", run: async (_b, args) => (calls.push(args.join(" ")), { ok: true }) },
  );
  assert.deepEqual(calls, [], "a name that isn't a bare key is dropped, not passed on");
});

test("config comes from the file, the environment and the options, in that order of trust", () => {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "corp.json"), JSON.stringify({ baseUrl: "https://file.example", provider: "fromfile" }));
  assert.equal(loadCorpConfig(dir, {}, {}).baseUrl, "https://file.example");
  assert.equal(loadCorpConfig(dir, { baseUrl: "https://option.example" }, {}).baseUrl, "https://option.example");
  assert.equal(loadCorpConfig(dir, {}, { MAGPIE_CORP_URL: "https://env.example" }).baseUrl, "https://env.example");
  assert.equal(loadCorpConfig(dir, {}, {}).providerId, "fromfile");
});

test("the native magpie's providers are listed without their keys", () => {
  const dir = tempDir();
  fs.writeFileSync(
    path.join(dir, "providers.json"),
    JSON.stringify({
      providers: [
        {
          id: "alpha",
          name: "Alpha",
          preset: "openai",
          chat: "https://api.alpha.example/v1",
          key: "sk-alpha-secret",
          models: ["alpha-1", "alpha-2"],
        },
        { id: "subscription", name: "Subscription", account: { id: "acct" }, models: ["sub-1"] },
        { id: "bare", name: "Bare", key: "sk-bare-secret", models: [] },
      ],
    }),
  );
  assert.equal(magpieConfigDir({ configDir: dir }, {}), path.resolve(dir));

  const providers = nativeProviders({ configDir: dir }, {});
  assert.equal(providers.length, 3);
  const alpha = providers.find((provider) => provider.id === "alpha");
  assert.equal(alpha.shareable, true);
  assert.equal(alpha.modelCount, 2);
  assert.equal(alpha.keyCount, 1);
  assert.deepEqual(alpha.maskedKeys, ["…secret"]);
  assert.ok(!JSON.stringify(providers).includes("sk-alpha-secret"), "a key's value never reaches the page");

  const subscription = providers.find((provider) => provider.id === "subscription");
  assert.equal(subscription.shareable, false);
  assert.match(subscription.reason, /API Key/);
  const bare = providers.find((provider) => provider.id === "bare");
  assert.match(bare.reason, /模型/);
});

test("sharing a native provider hands its key upward, never to the page", () => {
  const dir = tempDir();
  fs.writeFileSync(
    path.join(dir, "providers.json"),
    JSON.stringify({
      providers: [
        {
          id: "alpha",
          name: "Alpha",
          preset: "openai",
          chat: "https://api.alpha.example/v1",
          key: "sk-alpha-one",
          keys: [{ key: "sk-alpha-two" }],
          models: ["alpha-1"],
        },
      ],
    }),
  );
  const shared = shareNativeProviders(["alpha", "missing"], { configDir: dir }, {});
  assert.equal(shared.providers.length, 1);
  assert.equal(shared.providers[0].key, "sk-alpha-one");
  assert.deepEqual(shared.providers[0].keys, ["sk-alpha-two"]);
  assert.equal(shared.providers[0].chat, "https://api.alpha.example/v1");
  assert.ok(shared.skipped.some((item) => item.id === "missing"), "an id the native magpie lacks is reported, not invented");
  assert.ok(!JSON.stringify(nativeProviders({ configDir: dir }, {})).includes("sk-alpha-one"));
});

test("the native magpie's gateway keys are listed masked and with what they may use", () => {
  const dir = tempDir();
  fs.writeFileSync(
    path.join(dir, "caller-keys.json"),
    JSON.stringify([
      { id: "key_1", name: "Alice", secret: "sk-caller-alice", models: ["alpha-1"], readOnly: false },
      { id: "key_2", name: "Bob", secret: "sk-caller-bob", readOnly: true },
      { id: "key_3", name: "Off", secret: "sk-caller-off", off: true },
    ]),
  );
  const keys = nativeKeys({ configDir: dir }, {});
  assert.equal(keys.length, 3);
  const alice = keys.find((key) => key.id === "key_1");
  assert.equal(alice.masked, "…-alice");
  assert.equal(alice.usable, true);
  assert.deepEqual(alice.models, ["alpha-1"]);
  assert.equal(keys.find((key) => key.id === "key_2").usable, false, "a read-only key cannot send a chat");
  assert.equal(keys.find((key) => key.id === "key_3").usable, false);
  assert.ok(!JSON.stringify(keys).includes("sk-caller"), "a gateway key's value never reaches the page");
});

test("a sync keeps the sharing summary the corporation sent", async () => {
  const dir = tempDir();
  const bundle = {
    revision: "rev_9",
    providers: [{ id: "corp", name: "企业网关 · Remote magpie", baseUrl: "https://ai.corp.example/v1", models: ["m1", "m2"] }],
    sharing: {
      mode: "remote",
      updatedAt: "2026-11-16T00:00:00.000Z",
      sources: [{ id: "corp", name: "企业网关 · Remote magpie", models: ["m1", "m2"] }],
    },
    instructions: [],
    mcp: [],
    skills: [],
  };
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(bundle));
  });
  const port = await new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
  try {
    const store = createStore(dir);
    store.saveDevice({ deviceToken: "device-token", expiresAt: "" });
    const summary = await syncBundle({
      config: {
        baseUrl: `http://127.0.0.1:${port}`,
        providerId: "corp",
        configDir: dir,
        magpieBin: "magpie",
        upload: { usage: false, masking: false, sessions: false },
      },
      store,
      run: async () => ({ ok: true, code: "", message: "" }),
    });
    assert.deepEqual(summary.errors, []);
    const saved = readBundle(dir);
    assert.equal(saved.revision, "rev_9");
    assert.equal(saved.sharing.mode, "remote");
    assert.equal(saved.sharing.sources[0].id, "corp");
  } finally {
    server.close();
  }
});
