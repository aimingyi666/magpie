import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  applyCodexAgentConfig,
  inspectCodexAgentConfig,
  LocalMcpError,
  removeCodexAgentConfig,
  setupLocalMcpClient,
} from "../src/index.js";

const RESOURCE_ID = "res_local_echo_setup";
const TOKEN = ["local-mcp", "setup", "token", "0123456789"].join("-");
const BRIDGE_PATH = fileURLToPath(new URL("../bin/local-mcp-bridge.mjs", import.meta.url));

function assertError(code) {
  return (error) => error instanceof LocalMcpError && error.code === code;
}

function temporaryRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "magpie-client-setup-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function fakeHelper(overrides = {}) {
  const calls = [];
  const packageEntry = {
    resourceId: RESOURCE_ID,
    releaseId: "rel_local_echo_setup_1",
    packageId: "local-echo",
    packageReleaseId: "2026.11.1",
  };
  return {
    calls,
    host: { rootDir: "" },
    async synchronize() {
      calls.push("synchronize");
      return {
        status: "ready",
        sync: { status: "up_to_date", revision: "desired-setup-1" },
      };
    },
    async reconcile() {
      calls.push("reconcile");
      return { status: "ready" };
    },
    async snapshot() {
      calls.push("snapshot");
      return {
        status: "ready",
        packages: [packageEntry],
        blocked: [],
      };
    },
    async listTools(resourceId) {
      calls.push(["listTools", resourceId]);
      return {
        resourceId,
        tools: [{ name: "echo", description: "Echo", risk: "low", capabilities: [] }],
      };
    },
    async callTool() {
      throw new Error("not used");
    },
    ...overrides,
  };
}

function setupOptions(t, helper, overrides = {}) {
  const root = temporaryRoot(t);
  helper.host.rootDir = path.join(root, "mcp");
  return {
    helper,
    configPath: path.join(root, ".codex", "config.toml"),
    nodePath: process.execPath,
    bridgePath: BRIDGE_PATH,
    rootDir: helper.host.rootDir,
    token: TOKEN,
    injectLaunchEnvironment: async () => ({ status: "ready" }),
    ...overrides,
  };
}

function lockPath(options) {
  return path.join(options.rootDir, "state", "helper.lock");
}

test("setup synchronizes, installs, serves, writes Codex config and injects launch environment", async (t) => {
  const helper = fakeHelper();
  let injected;
  const options = setupOptions(t, helper, {
    injectLaunchEnvironment: async (value) => {
      injected = value;
      return { status: "ready" };
    },
  });

  const result = await setupLocalMcpClient(options);
  t.after(() => result.uninstall().catch(() => {}));

  assert.equal(result.status, "ready");
  assert.equal(result.resourceId, RESOURCE_ID);
  assert.equal(result.serverName, "magpie_local_mcp");
  assert.equal(result.tokenEnvName, "MAGPIE_LOCAL_MCP_HELPER_TOKEN");
  assert.equal(result.toolCount, 1);
  assert.equal(result.sync.revision, "desired-setup-1");
  assert.deepEqual(helper.calls.slice(0, 3), ["synchronize", "reconcile", "snapshot"]);
  assert.equal(fs.existsSync(lockPath(options)), true);

  assert.equal(JSON.stringify(result).includes(TOKEN), false);
  assert.equal(injected.resourceId, RESOURCE_ID);
  assert.equal(injected.helperUrl, result.helperUrl);
  assert.equal(injected.environment.MAGPIE_LOCAL_MCP_HELPER_TOKEN, TOKEN);
  assert.equal(injected.environment.MAGPIE_LOCAL_MCP_HELPER_URL, result.helperUrl);
  assert.equal(injected.environment.MAGPIE_LOCAL_MCP_RESOURCE_ID, RESOURCE_ID);

  const text = fs.readFileSync(options.configPath, "utf8");
  assert.equal(text.includes(TOKEN), false);
  const inspected = await inspectCodexAgentConfig({
    configPath: options.configPath,
    serverName: result.serverName,
  });
  assert.equal(inspected.status, "managed");
  assert.equal(inspected.managed.nodePath, path.resolve(options.nodePath));
  assert.equal(inspected.managed.bridgePath, path.resolve(options.bridgePath));
  assert.equal(inspected.managed.helperUrl, result.helperUrl);
  assert.equal(inspected.managed.resourceId, RESOURCE_ID);
  assert.equal(inspected.managed.tokenEnvName, result.tokenEnvName);
  assert.equal(inspected.managed.startupTimeoutSec, 20);

  await result.close();
  assert.equal(fs.existsSync(lockPath(options)), false);
  assert.equal(fs.existsSync(options.configPath), true);
  const removed = await result.uninstall();
  assert.equal(removed.status, "removed");
  assert.equal(
    (await inspectCodexAgentConfig({ configPath: options.configPath })).status,
    "absent",
  );
});

test("setup refuses to start without a controlled token injector", async (t) => {
  const helper = fakeHelper();
  const options = setupOptions(t, helper);
  delete options.injectLaunchEnvironment;

  await assert.rejects(
    () => setupLocalMcpClient(options),
    assertError("token_injection_required"),
  );
  assert.deepEqual(helper.calls, []);
  assert.equal(fs.existsSync(options.configPath), false);
  assert.equal(fs.existsSync(lockPath(options)), false);
});

test("setup generates a process-only helper token when none is supplied", async (t) => {
  const helper = fakeHelper();
  let environment;
  const options = setupOptions(t, helper, {
    injectLaunchEnvironment: async (value) => {
      environment = value.environment;
      return { status: "ready" };
    },
  });
  delete options.token;

  const result = await setupLocalMcpClient(options);
  t.after(() => result.uninstall().catch(() => {}));
  const token = environment.MAGPIE_LOCAL_MCP_HELPER_TOKEN;
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(JSON.stringify(result).includes(token), false);
  assert.equal(fs.readFileSync(options.configPath, "utf8").includes(token), false);
});

test("sync failure stops setup before reconciliation or configuration", async (t) => {
  const helper = fakeHelper({
    async synchronize() {
      this.calls.push("synchronize");
      return { status: "degraded", sync: { status: "failed" } };
    },
  });
  const options = setupOptions(t, helper);

  await assert.rejects(
    () => setupLocalMcpClient(options),
    assertError("client_setup_sync_failed"),
  );
  assert.deepEqual(helper.calls, ["synchronize"]);
  assert.equal(fs.existsSync(options.configPath), false);
  assert.equal(fs.existsSync(lockPath(options)), false);
});

test("reconcile failure stops setup before resource selection", async (t) => {
  const helper = fakeHelper({
    async reconcile() {
      this.calls.push("reconcile");
      return { status: "degraded" };
    },
  });
  const options = setupOptions(t, helper);

  await assert.rejects(
    () => setupLocalMcpClient(options),
    assertError("client_setup_reconcile_failed"),
  );
  assert.deepEqual(helper.calls, ["synchronize", "reconcile"]);
  assert.equal(fs.existsSync(options.configPath), false);
  assert.equal(fs.existsSync(lockPath(options)), false);
});

test("multiple active resources require an explicit resource id", async (t) => {
  const helper = fakeHelper({
    async snapshot() {
      this.calls.push("snapshot");
      return {
        status: "ready",
        packages: [
          { resourceId: RESOURCE_ID },
          { resourceId: "res_local_second" },
        ],
        blocked: [],
      };
    },
  });
  const options = setupOptions(t, helper);

  await assert.rejects(
    () => setupLocalMcpClient(options),
    assertError("client_setup_resource_required"),
  );
  assert.equal(fs.existsSync(options.configPath), false);
  assert.equal(fs.existsSync(lockPath(options)), false);
});

test("a helper listen failure releases its lock and leaves Codex untouched", async (t) => {
  const blocker = http.createServer((req, res) => res.end("occupied"));
  await new Promise((resolve, reject) => {
    blocker.once("error", reject);
    blocker.listen(0, "127.0.0.1", resolve);
  });
  t.after(() => new Promise((resolve) => blocker.close(resolve)));
  const port = blocker.address().port;
  const helper = fakeHelper();
  const options = setupOptions(t, helper, { port });

  await assert.rejects(
    () => setupLocalMcpClient(options),
    assertError("client_setup_server_failed"),
  );
  assert.equal(fs.existsSync(options.configPath), false);
  assert.equal(fs.existsSync(lockPath(options)), false);
});

test("an unmanaged Codex conflict closes the helper and preserves the user file", async (t) => {
  const helper = fakeHelper();
  const options = setupOptions(t, helper);
  fs.mkdirSync(path.dirname(options.configPath), { recursive: true });
  const original = "[mcp_servers.magpie_local_mcp]\ncommand = \"user-owned\"\n";
  fs.writeFileSync(options.configPath, original);

  await assert.rejects(
    () => setupLocalMcpClient(options),
    assertError("agent_config_conflict"),
  );
  assert.equal(fs.readFileSync(options.configPath, "utf8"), original);
  assert.equal(fs.existsSync(lockPath(options)), false);
});

test("injection failure removes the managed block and keeps unrelated config", async (t) => {
  const helper = fakeHelper();
  const options = setupOptions(t, helper, {
    injectLaunchEnvironment: async () => ({ status: "failed" }),
  });
  fs.mkdirSync(path.dirname(options.configPath), { recursive: true });
  fs.writeFileSync(options.configPath, "model = \"gpt-5.5\"\n");

  await assert.rejects(
    () => setupLocalMcpClient(options),
    assertError("client_setup_injection_failed"),
  );
  assert.equal(fs.readFileSync(options.configPath, "utf8"), "model = \"gpt-5.5\"\n");
  assert.equal(fs.existsSync(lockPath(options)), false);
});

test("configuration readback failures fail closed and clean up the server", async (t) => {
  const helper = fakeHelper();
  const options = setupOptions(t, helper, {
    agentConfig: {
      apply: applyCodexAgentConfig,
      inspect: async ({ serverName }) => ({
        status: "managed",
        serverName,
        managed: {
          helperUrl: "http://127.0.0.1:1",
          resourceId: RESOURCE_ID,
          tokenEnvName: "MAGPIE_LOCAL_MCP_HELPER_TOKEN",
        },
      }),
      remove: removeCodexAgentConfig,
    },
  });

  await assert.rejects(
    () => setupLocalMcpClient(options),
    assertError("client_setup_readback_failed"),
  );
  assert.equal(
    (await inspectCodexAgentConfig({ configPath: options.configPath })).status,
    "absent",
  );
  assert.equal(fs.existsSync(lockPath(options)), false);
});
