import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { spawn } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  buildSignedManifest,
  publicKeyFingerprint as resourceKeyFingerprint,
} from "../../resource-service/src/manifest.js";
import { ClientSyncEngine } from "../../client-sync/src/index.js";
import {
  inspectCodexAgentConfig,
  LocalMcpHelper,
  setupLocalMcpClient,
} from "../src/index.js";
import {
  CLIENT_VERSION,
  createHost,
  createIdentity,
  createPackage,
} from "./helpers.mjs";

const RESOURCE_KEY_ID = "enterprise-resource-e2e-v1";
const RESOURCE_ID = "res_local_echo_e2e";
const RESOURCE_RELEASE_ID = "rel_local_echo_e2e_1";
const HELPER_TOKEN = ["local-mcp", "e2e", "token", "0123456789"].join("-");
const BRIDGE_PATH = fileURLToPath(new URL("../bin/local-mcp-bridge.mjs", import.meta.url));

function temporaryRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "magpie-local-mcp-e2e-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function resourceIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    privateKey,
    publicKeys: {
      [RESOURCE_KEY_ID]: publicKey.export({ type: "spki", format: "pem" }),
    },
    keyFingerprints: {
      [RESOURCE_KEY_ID]: resourceKeyFingerprint(publicKey),
    },
  };
}

function signedMcpResource(identity, signedPackage) {
  const content = Buffer.from(JSON.stringify(signedPackage), "utf8");
  const manifest = buildSignedManifest({
    resourceId: RESOURCE_ID,
    releaseId: RESOURCE_RELEASE_ID,
    resourceVersion: "2026.11.1",
    kind: "mcp",
    hash: `sha256:${crypto.createHash("sha256").update(content).digest("hex")}`,
    contentBytes: content.length,
    mediaType: "application/vnd.magpie.local-mcp-package+json",
    publisher: "enterprise-platform",
    createdAt: "2026-11-02T00:00:00.000Z",
    assignments: ["org_engineering"],
    deliveryMode: "forced",
    compatibility: { minClientVersion: "1.0.0" },
    previousReleaseId: "",
    signingKeyId: RESOURCE_KEY_ID,
  }, identity.privateKey);
  return { manifest, content };
}

function desiredState(resource) {
  return {
    schemaVersion: 1,
    revision: "desired-local-mcp-e2e-1",
    generatedAt: "2026-11-02T00:01:00.000Z",
    resources: [resource],
  };
}

function jsonRpcClient(child) {
  const pending = new Map();
  let nextId = 1;
  let stderr = "";
  const lines = readline.createInterface({
    input: child.stdout,
    crlfDelay: Infinity,
  });
  lines.on("line", (line) => {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      return;
    }
    if (!message || typeof message.id !== "number") return;
    const waiter = pending.get(message.id);
    if (!waiter) return;
    pending.delete(message.id);
    clearTimeout(waiter.timer);
    waiter.resolve(message);
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk.toString("utf8");
  });
  child.once("exit", (code, signal) => {
    for (const waiter of pending.values()) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error(
        `bridge exited before responding (code=${code}, signal=${signal}, stderr=${stderr})`,
      ));
    }
    pending.clear();
  });

  return {
    request(method, params = {}) {
      return new Promise((resolve, reject) => {
        const id = nextId;
        nextId += 1;
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`bridge request timed out: ${method}; stderr=${stderr}`));
        }, 10_000);
        timer.unref?.();
        pending.set(id, { resolve, reject, timer });
        child.stdin.write(JSON.stringify({
          jsonrpc: "2.0",
          id,
          method,
          params,
        }) + "\n");
      });
    },
    stderr() {
      return stderr;
    },
  };
}

function waitForExit(child) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("bridge did not exit after stdin closed"));
    }, 10_000);
    timer.unref?.();
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

test("signed resource, local host, helper HTTP and agent bridge work end to end", async (t) => {
  const root = temporaryRoot(t);
  const syncRoot = path.join(root, "client-sync");
  const mcpRoot = path.join(root, "local-mcp");
  const packageIdentity = createIdentity();
  const signedPackage = createPackage(packageIdentity);
  const resourceSigner = resourceIdentity();
  const resource = signedMcpResource(resourceSigner, signedPackage);
  const host = createHost(packageIdentity, mcpRoot);
  let helper;
  const clientSync = new ClientSyncEngine({
    rootDir: syncRoot,
    publicKeys: resourceSigner.publicKeys,
    keyFingerprints: resourceSigner.keyFingerprints,
    clientVersion: CLIENT_VERSION,
    fetchDesiredState: async () => desiredState(resource),
    validateInstalled: (entry) => helper.validateClientResource(entry),
    now: () => Date.parse("2026-11-02T00:02:00.000Z"),
  });
  helper = new LocalMcpHelper({
    clientSync,
    host,
    now: () => Date.parse("2026-11-02T00:02:00.000Z"),
  });

  const configPath = path.join(root, "codex-home", "config.toml");
  let child;
  const setup = await setupLocalMcpClient({
    helper,
    configPath,
    nodePath: process.execPath,
    bridgePath: BRIDGE_PATH,
    rootDir: mcpRoot,
    token: HELPER_TOKEN,
    port: 0,
    async injectLaunchEnvironment({ environment }) {
      child = spawn(process.execPath, [BRIDGE_PATH], {
        env: { ...process.env, ...environment },
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
      return { status: "ready" };
    },
  });
  t.after(() => setup.uninstall().catch(() => {}));
  assert.equal(setup.status, "ready");
  assert.equal(setup.resourceId, RESOURCE_ID);
  assert.equal(setup.helperUrl.startsWith("http://127.0.0.1:"), true);
  assert.equal(fs.readFileSync(configPath, "utf8").includes(HELPER_TOKEN), false);
  const inspected = await inspectCodexAgentConfig({ configPath });
  assert.equal(inspected.status, "managed");
  assert.equal(inspected.managed.resourceId, RESOURCE_ID);
  assert.equal(inspected.managed.helperUrl, setup.helperUrl);

  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
  });
  const rpc = jsonRpcClient(child);

  const initialized = await rpc.request("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "e2e-test", version: "1.0.0" },
  });
  assert.equal(initialized.result.serverInfo.name, "magpie-local-mcp");
  child.stdin.write(JSON.stringify({
    jsonrpc: "2.0",
    method: "notifications/initialized",
    params: {},
  }) + "\n");

  const listed = await rpc.request("tools/list");
  assert.deepEqual(listed.result.tools, [{
    name: "echo",
    description: "Echo test input",
    inputSchema: { type: "object", additionalProperties: true },
  }]);

  const called = await rpc.request("tools/call", {
    name: "echo",
    arguments: { echo: "through-the-whole-chain" },
  });
  assert.equal(called.result.isError, false);
  assert.equal(called.result.structuredContent.echo, "through-the-whole-chain");

  const exiting = waitForExit(child);
  child.stdin.end();
  const exit = await exiting;
  assert.equal(exit.code, 0, rpc.stderr());
  assert.equal(exit.signal, null);

  const audit = fs.readFileSync(path.join(mcpRoot, "audit.jsonl"), "utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  assert.ok(audit.some((entry) => entry.event === "local_mcp.tool_finished"
    && entry.toolName === "echo"
    && entry.status === "succeeded"));
});
