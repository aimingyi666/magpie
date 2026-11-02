import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  applyCodexAgentConfig,
  codexConfigPath,
  DEFAULT_CODEX_MCP_SERVER_NAME,
  inspectCodexAgentConfig,
  removeCodexAgentConfig,
  renderCodexAgentConfig,
} from "../src/agent-config.js";
import { LocalMcpError } from "../src/errors.js";

function assertError(code) {
  return (error) => error instanceof LocalMcpError && error.code === code;
}

function temporaryConfig(t, text = "") {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "magpie-agent-config-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const configPath = path.join(root, ".codex", "config.toml");
  if (text) {
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, text);
  }
  return { root, configPath };
}

function options(configPath) {
  return {
    configPath,
    nodePath: process.execPath,
    bridgePath: fileURLToPath(new URL("../bin/local-mcp-bridge.mjs", import.meta.url)),
    helperUrl: "http://127.0.0.1:43123",
    resourceId: "res_local_echo",
    tokenEnvName: "MAGPIE_LOCAL_MCP_HELPER_TOKEN",
  };
}

test("Codex config mapping preserves user entries and never stores the token value", async (t) => {
  const original = [
    "model = \"gpt-5.5\"",
    "",
    "[mcp_servers.mine]",
    "command = \"uvx\"",
    "args = [\"mine\"]",
    "",
  ].join("\n");
  const { configPath } = temporaryConfig(t, original);
  const applied = await applyCodexAgentConfig(options(configPath));
  assert.equal(applied.status, "applied");
  const text = fs.readFileSync(configPath, "utf8");
  assert.equal(text.startsWith(original), true);
  assert.match(text, /\[mcp_servers\.magpie_local_mcp\]/);
  assert.match(text, /env_vars = \["MAGPIE_LOCAL_MCP_HELPER_TOKEN"\]/);
  assert.match(text, /MAGPIE_LOCAL_MCP_HELPER_URL = "http:\/\/127\.0\.0\.1:43123"/);
  assert.equal(text.includes("TOP-SECRET"), false);

  const unchanged = await applyCodexAgentConfig(options(configPath));
  assert.equal(unchanged.status, "unchanged");
  assert.equal(fs.readFileSync(configPath, "utf8"), text);

  const inspected = await inspectCodexAgentConfig({ configPath });
  assert.equal(inspected.status, "managed");
  assert.equal(inspected.managed.nodePath, path.resolve(process.execPath));
  assert.equal(
    inspected.managed.bridgePath,
    path.resolve(fileURLToPath(new URL("../bin/local-mcp-bridge.mjs", import.meta.url))),
  );
  assert.equal(inspected.managed.helperUrl, "http://127.0.0.1:43123");
  assert.equal(inspected.managed.resourceId, "res_local_echo");
  assert.equal(inspected.managed.tokenEnvName, "MAGPIE_LOCAL_MCP_HELPER_TOKEN");
  assert.equal(inspected.managed.startupTimeoutSec, 20);
});

test("Codex config mapping preserves BOM and CRLF outside its managed block", async (t) => {
  const original = "\ufeffmodel = \"gpt-5.5\"\r\n\r\n[mcp_servers.mine]\r\ncommand = \"uvx\"\r\n";
  const { configPath } = temporaryConfig(t, original);
  await applyCodexAgentConfig(options(configPath));
  const raw = fs.readFileSync(configPath);
  assert.deepEqual([...raw.subarray(0, 3)], [0xef, 0xbb, 0xbf]);
  const text = raw.subarray(3).toString("utf8");
  assert.equal(text.startsWith("model = \"gpt-5.5\"\r\n\r\n[mcp_servers.mine]\r\n"), true);
  assert.match(text, /\[mcp_servers\.mine\]\r\ncommand = "uvx"/);
});

test("an unmanaged same-name entry is never overwritten", async (t) => {
  const { configPath } = temporaryConfig(
    t,
    "[mcp_servers.magpie_local_mcp]\ncommand = \"user-owned\"\n",
  );
  await assert.rejects(
    () => applyCodexAgentConfig(options(configPath)),
    assertError("agent_config_conflict"),
  );
  assert.equal(
    fs.readFileSync(configPath, "utf8"),
    "[mcp_servers.magpie_local_mcp]\ncommand = \"user-owned\"\n",
  );
  const inspected = await inspectCodexAgentConfig({ configPath });
  assert.equal(inspected.status, "unmanaged");
});

test("managed drift fails closed unless an explicit forced update is requested", async (t) => {
  const { configPath } = temporaryConfig(t, "model = \"gpt-5.5\"\n");
  await applyCodexAgentConfig(options(configPath));
  const drifted = fs.readFileSync(configPath, "utf8")
    .replace("startup_timeout_sec = 20", "startup_timeout_sec = 99");
  fs.writeFileSync(configPath, drifted);

  await assert.rejects(
    () => applyCodexAgentConfig(options(configPath)),
    assertError("agent_config_drift"),
  );
  const updated = await applyCodexAgentConfig({
    ...options(configPath),
    force: true,
  });
  assert.equal(updated.status, "updated");
  assert.match(fs.readFileSync(configPath, "utf8"), /startup_timeout_sec = 20/);
  assert.equal(fs.readFileSync(configPath, "utf8").includes("startup_timeout_sec = 99"), false);
});

test("managed markers must occupy complete lines even during a forced update", async (t) => {
  const { configPath } = temporaryConfig(t, "model = \"gpt-5.5\"\n");
  await applyCodexAgentConfig(options(configPath));
  const malformed = fs.readFileSync(configPath, "utf8")
    .replace(
      "# <<< magpie-managed MCP server: magpie_local_mcp",
      "# <<< magpie-managed MCP server: magpie_local_mcp trailing",
    );
  fs.writeFileSync(configPath, malformed);
  await assert.rejects(
    () => applyCodexAgentConfig({ ...options(configPath), force: true }),
    assertError("agent_config_malformed"),
  );
  assert.equal(fs.readFileSync(configPath, "utf8"), malformed);
});

test("removal deletes only the managed block and leaves user entries intact", async (t) => {
  const original = "model = \"gpt-5.5\"\n\n[mcp_servers.mine]\ncommand = \"uvx\"\n";
  const { configPath } = temporaryConfig(t, original);
  await applyCodexAgentConfig(options(configPath));
  const removed = await removeCodexAgentConfig({ configPath });
  assert.equal(removed.status, "removed");
  const text = fs.readFileSync(configPath, "utf8");
  assert.equal(text.includes("magpie-managed"), false);
  assert.equal(text.includes("[mcp_servers.mine]"), true);
  assert.equal(text.includes("command = \"uvx\""), true);
  assert.equal((await inspectCodexAgentConfig({ configPath })).status, "absent");
  assert.equal((await removeCodexAgentConfig({ configPath })).status, "absent");
});

test("CODEX_HOME is honored and rendering is deterministic", () => {
  const codexHome = path.join(os.tmpdir(), "magpie-codex-home-test");
  assert.equal(
    codexConfigPath({ home: "C:\\Users\\ignored", env: { CODEX_HOME: codexHome } }),
    path.join(codexHome, "config.toml"),
  );
  const rendered = renderCodexAgentConfig({
    ...options(path.join(codexHome, "config.toml")),
  });
  assert.match(rendered, new RegExp(`magpie-managed MCP server: ${DEFAULT_CODEX_MCP_SERVER_NAME}`));
  assert.match(rendered, /env = \{ MAGPIE_LOCAL_MCP_HELPER_URL/);
  assert.equal(rendered.includes("HELPER_TOKEN ="), false);
});
