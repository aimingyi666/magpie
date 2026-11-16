// What a bundle's plugin list does to this machine: install, turn on,
// connect, and — when the corporation withdraws it — disconnect.
//
// Every test runs against temporary folders and a stand-in for the magpie
// CLI, so nothing here touches a real magpie or the network.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import { applyPlugins, wantedPlugins, knownPlugins } from "../src/plugins.mjs";

const SPEC = "github:932633145/magpie-agent-cursor-bridge";
const MODEL = "corp/deepseek-v4-pro";

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "corp-plugins-"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function configDir(plugins = []) {
  const dir = tempDir();
  writeJson(path.join(dir, "plugins.json"), { plugins });
  return dir;
}

function connection(home, value) {
  writeJson(path.join(home, ".config", "magpie-cursor-bridge", "connection.json"), value);
}

function bundle(plugins, { model = "deepseek-v4-pro" } = {}) {
  return {
    providers: [{ id: "corp", models: [model], defaultModel: model, enabled: true }],
    plugins,
  };
}

// A run that records each command and answers what the test told it to.
function fakeRun(answer = () => ({ ok: true })) {
  const calls = [];
  const run = async (bin, args, options) => {
    calls.push({ bin, args, options });
    return answer(args) || { ok: true };
  };
  return { calls, run };
}

test("only the plugins this client knows can be named", () => {
  assert.deepEqual(Object.keys(knownPlugins), ["cursor-bridge"]);

  const bad = wantedPlugins(bundle([{ id: "made-up", enabled: true, model: MODEL }]));
  assert.equal(bad.wanted.length, 0);
  assert.equal(bad.errors[0].code, "unknown_plugin");

  const noModel = wantedPlugins({ providers: [], plugins: [{ id: "cursor-bridge" }] });
  assert.equal(noModel.wanted.length, 0);
  assert.equal(noModel.errors[0].code, "plugin_model_invalid");
});

test("a bare model is taken as the corp provider's", () => {
  const { wanted } = wantedPlugins(bundle([{ id: "cursor-bridge", model: "deepseek-flash" }]));
  assert.equal(wanted[0].model, "corp/deepseek-flash");
});

test("an installed, connected bridge is left alone", async () => {
  const home = tempDir();
  const dir = configDir([{ spec: SPEC }]);
  connection(home, { enabled: true, model: MODEL });
  const { calls, run } = fakeRun();

  const result = await applyPlugins(bundle([{ id: "cursor-bridge", model: MODEL }]), {
    magpieBin: "magpie",
    configDir: dir,
    home,
    run,
  });

  assert.deepEqual(result.errors, []);
  assert.deepEqual(result.applied, ["cursor-bridge"]);
  assert.equal(calls.length, 0, "nothing to run");
});

test("a bridge that isn't installed is added and connected", async () => {
  const home = tempDir();
  const dir = configDir();
  const { calls, run } = fakeRun();

  const result = await applyPlugins(bundle([{ id: "cursor-bridge", model: MODEL }]), {
    magpieBin: "magpie",
    configDir: dir,
    home,
    run,
  });

  assert.deepEqual(result.errors, []);
  assert.deepEqual(calls.map((call) => call.args), [
    ["plugin", "add", SPEC],
    ["cursor-bridge", MODEL],
  ]);
  assert.equal(calls[0].options.configDir, dir, "the CLI is pointed at the same config folder");
  assert.equal(calls[0].options.timeoutMs, 10 * 60_000, "an install may fetch a repository");
  assert.deepEqual(result.applied, ["cursor-bridge"]);
});

test("a turned-off entry is turned on, not added again", async () => {
  const home = tempDir();
  const dir = configDir([{ spec: SPEC, off: true }]);
  connection(home, { enabled: true, model: MODEL });
  const { calls, run } = fakeRun();

  await applyPlugins(bundle([{ id: "cursor-bridge", model: MODEL }]), {
    magpieBin: "magpie",
    configDir: dir,
    home,
    run,
  });

  assert.deepEqual(calls.map((call) => call.args), [["plugin", "on", SPEC]]);
});

test("another model reconnects the agent", async () => {
  const home = tempDir();
  const dir = configDir([{ spec: `${SPEC}#v0.2.7` }]);
  connection(home, { enabled: true, model: "corp/other-model" });
  const { calls, run } = fakeRun();

  await applyPlugins(bundle([{ id: "cursor-bridge", model: MODEL }]), {
    magpieBin: "magpie",
    configDir: dir,
    home,
    run,
  });

  assert.deepEqual(calls.map((call) => call.args), [["cursor-bridge", MODEL]]);
});

test("a withdrawn bridge is disconnected, and kept installed", async () => {
  const home = tempDir();
  const dir = configDir([{ spec: SPEC }]);
  connection(home, { enabled: true, model: MODEL });
  const { calls, run } = fakeRun();

  const result = await applyPlugins(bundle([]), {
    magpieBin: "magpie",
    configDir: dir,
    home,
    applied: ["cursor-bridge"],
    run,
  });

  assert.deepEqual(result.errors, []);
  assert.deepEqual(calls.map((call) => call.args), [["cursor-bridge", "default"]]);
  assert.deepEqual(result.applied, [], "no longer applied");
  assert.ok(
    JSON.parse(fs.readFileSync(path.join(dir, "plugins.json"), "utf8")).plugins.some((entry) => entry.spec === SPEC),
    "the plugin itself is not removed",
  );
});

test("an agent already disconnected is not called again", async () => {
  const home = tempDir();
  const dir = configDir([{ spec: SPEC }]);
  connection(home, { enabled: false, model: MODEL });
  const { calls, run } = fakeRun();

  await applyPlugins(bundle([]), {
    magpieBin: "magpie",
    configDir: dir,
    home,
    applied: ["cursor-bridge"],
    run,
  });

  assert.equal(calls.length, 0);
});

test("an unknown plugin in a bundle never reaches the CLI", async () => {
  const home = tempDir();
  const dir = configDir();
  const { calls, run } = fakeRun();

  const result = await applyPlugins(bundle([{ id: "evil", model: MODEL }]), {
    magpieBin: "magpie",
    configDir: dir,
    home,
    run,
  });

  assert.equal(result.errors[0].code, "unknown_plugin");
  assert.equal(calls.length, 0);
});

test("a failed connect is reported and the plugin stays managed", async () => {
  const home = tempDir();
  const dir = configDir([{ spec: SPEC }]);
  const { run } = fakeRun((args) =>
    args[0] === "cursor-bridge" ? { ok: false, message: "bridge said no" } : { ok: true });

  const result = await applyPlugins(bundle([{ id: "cursor-bridge", model: MODEL }]), {
    magpieBin: "magpie",
    configDir: dir,
    home,
    applied: ["cursor-bridge"],
    run,
  });

  assert.equal(result.errors[0].code, "plugin_connect_failed");
  assert.deepEqual(result.applied, ["cursor-bridge"], "a later withdrawal can still disconnect it");
});

test("a failed install is not recorded as applied", async () => {
  const home = tempDir();
  const dir = configDir();
  const { run } = fakeRun(() => ({ ok: false, message: "no network" }));

  const result = await applyPlugins(bundle([{ id: "cursor-bridge", model: MODEL }]), {
    magpieBin: "magpie",
    configDir: dir,
    home,
    run,
  });

  assert.equal(result.errors[0].code, "plugin_add_failed");
  assert.deepEqual(result.applied, []);
});

test("without a config folder nothing is guessed", async () => {
  const { calls, run } = fakeRun();
  const result = await applyPlugins(bundle([{ id: "cursor-bridge", model: MODEL }]), {
    magpieBin: "magpie",
    configDir: "",
    home: tempDir(),
    run,
  });

  assert.equal(result.errors[0].code, "config_dir_unknown");
  assert.equal(calls.length, 0);
});
