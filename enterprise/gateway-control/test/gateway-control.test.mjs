import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { loadConfig } from "../src/config.js";
import { createMagpieRunner } from "../src/runner.js";
import { createGatewayControlServer } from "../src/service.js";

const TOKEN = ["test", "service", "token", "for", "unit", "tests"].join("-");
const REVISION = `sha256:${"a".repeat(64)}`;
const NEXT_REVISION = `sha256:${"b".repeat(64)}`;

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-gateway-control-"));
}

function baseConfig(root, overrides = {}) {
  return {
    bind: "127.0.0.1",
    port: 0,
    token: TOKEN,
    magpiePath: process.execPath,
    configHome: root,
    timeoutMs: 1000,
    maxBodyBytes: 64 << 10,
    maxOutputBytes: 64 << 10,
    ...overrides,
  };
}

function limit(tokens = 5_000_000, cost = 10) {
  return {
    period: "month",
    days: 0,
    hours: 0,
    tokens,
    cost,
    cacheReads: false,
    cycleStartedAt: null,
  };
}

function describeFixture(id, overrides = {}) {
  return {
    schemaVersion: 1,
    ok: true,
    observedAt: "2026-11-01T00:00:00Z",
    key: {
      id,
      name: "Alice",
      state: "enabled",
      readOnly: false,
      expiresAt: null,
    },
    models: {
      mode: "restricted",
      patterns: ["deepseek/deepseek-chat"],
    },
    limits: [limit()],
    accounts: {
      restricted: false,
      count: 0,
      digest: null,
    },
    policyRevision: REVISION,
    ...overrides,
  };
}

function result(value, exitCode = 0) {
  return {
    exitCode,
    signal: null,
    stdout: `${JSON.stringify(value)}\n`,
    stderr: "",
    elapsedMs: 1,
  };
}

function failure(code, retryable = false) {
  return result({
    schemaVersion: 1,
    ok: false,
    error: {
      code,
      message: "fixture error",
      retryable,
    },
  }, 1);
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

async function close(server) {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
}

async function request(base, route, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.token !== null) {
    headers.authorization = `Bearer ${options.token ?? TOKEN}`;
  }
  if (options.body != null && headers["content-type"] == null) {
    headers["content-type"] = "application/json";
  }
  return fetch(`${base}${route}`, {
    method: options.method || "GET",
    headers,
    body: options.body,
  });
}

async function responseJson(response) {
  return JSON.parse(await response.text());
}

function scriptRunner(root, script, overrides = {}) {
  const spawnScript = (_command, args, options) => spawn(process.execPath, [script, ...args], options);
  return createMagpieRunner(baseConfig(root, overrides), { spawn: spawnScript });
}

function processExists(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitForExit(pid, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!processExists(pid)) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return !processExists(pid);
}

test("healthz is public and does not require the service token", async () => {
  const root = tempDirectory();
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner: { describe: async () => assert.fail("runner must not be called"), apply: async () => assert.fail() },
    logger: () => {},
  });
  const base = await listen(server);
  try {
    const response = await request(base, "/healthz", { token: null });
    assert.equal(response.status, 200);
    const body = await responseJson(response);
    assert.equal(body.ok, true);
    assert.equal(body.service, "gateway-control");
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("API routes reject missing and incorrect service tokens", async () => {
  const root = tempDirectory();
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner: { describe: async () => assert.fail("runner must not be called"), apply: async () => assert.fail() },
    logger: () => {},
  });
  const base = await listen(server);
  try {
    const missing = await request(base, "/api/v1/gateway-keys/alice", { token: null });
    assert.equal(missing.status, 401);
    assert.equal((await responseJson(missing)).error.code, "unauthorized");

    const wrong = await request(base, "/api/v1/gateway-keys/alice", { token: "wrong-token" });
    assert.equal(wrong.status, 401);
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("describe returns a safe schema-v1 projection and never logs secret fields", async () => {
  const root = tempDirectory();
  const logs = [];
  const value = describeFixture("alice", {
    key: {
      id: "alice",
      name: "Alice",
      state: "enabled",
      readOnly: false,
      expiresAt: null,
      secret: "sk-live-secret",
      masked: "magpie…secret",
      tokenHash: "token-hash-secret",
    },
    accounts: {
      restricted: true,
      count: 1,
      digest: `sha256:${"c".repeat(64)}`,
      ids: ["account-secret"],
    },
    deviceToken: "device-token-secret",
  });
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner: {
      describe: async () => result(value),
      apply: async () => assert.fail("apply must not be called"),
    },
    logger: (entry) => logs.push(entry),
  });
  const base = await listen(server);
  try {
    const response = await request(base, "/api/v1/gateway-keys/alice");
    assert.equal(response.status, 200);
    const text = await response.text();
    const body = JSON.parse(text);
    assert.equal(body.schemaVersion, 1);
    assert.equal(body.policyRevision, REVISION);
    assert.equal(body.accounts.digest, `sha256:${"c".repeat(64)}`);
    for (const forbidden of [
      "sk-live-secret",
      "magpie…secret",
      "token-hash-secret",
      "account-secret",
      "device-token-secret",
    ]) {
      assert.equal(text.includes(forbidden), false);
      assert.equal(JSON.stringify(logs).includes(forbidden), false);
    }
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("invalid key ids and unknown routes fail without invoking Magpie", async () => {
  const root = tempDirectory();
  let calls = 0;
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner: {
      describe: async () => { calls += 1; },
      apply: async () => { calls += 1; },
    },
    logger: () => {},
  });
  const base = await listen(server);
  try {
    const injected = await request(base, "/api/v1/gateway-keys/a%3Brm-rf");
    assert.equal(injected.status, 400);
    assert.equal((await responseJson(injected)).error.code, "invalid_key_id");

    const unknown = await request(base, "/api/v1/admin/users/alice");
    assert.equal(unknown.status, 404);
    assert.equal((await responseJson(unknown)).error.code, "not_found");
    assert.equal(calls, 0);
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("missing keys and invalid command output map to stable errors", async () => {
  const root = tempDirectory();
  let next = failure("gateway_key_not_found");
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner: {
      describe: async () => next,
      apply: async () => assert.fail("apply must not be called"),
    },
    logger: () => {},
  });
  const base = await listen(server);
  try {
    const missing = await request(base, "/api/v1/gateway-keys/missing");
    assert.equal(missing.status, 404);
    assert.equal((await responseJson(missing)).error.code, "gateway_key_not_found");

    next = {
      exitCode: 0,
      signal: null,
      stdout: "not-json\n",
      stderr: "",
      elapsedMs: 1,
    };
    const invalid = await request(base, "/api/v1/gateway-keys/alice");
    assert.equal(invalid.status, 502);
    assert.equal((await responseJson(invalid)).error.code, "gateway_output_invalid");
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("request body limit, content type and schema validation fail closed", async () => {
  const root = tempDirectory();
  let calls = 0;
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner: {
      describe: async () => { calls += 1; },
      apply: async () => { calls += 1; },
    },
    logger: () => {},
  });
  const base = await listen(server);
  try {
    const large = await request(base, "/api/v1/gateway-keys/alice/policy", {
      method: "POST",
      body: "x".repeat((64 << 10) + 1),
    });
    assert.equal(large.status, 413);
    assert.equal((await responseJson(large)).error.code, "request_too_large");

    const contentType = await request(base, "/api/v1/gateway-keys/alice/policy", {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "{}",
    });
    assert.equal(contentType.status, 415);
    assert.equal((await responseJson(contentType)).error.code, "invalid_content_type");

    const unsupported = await request(base, "/api/v1/gateway-keys/alice/policy", {
      method: "POST",
      body: JSON.stringify({
        schemaVersion: 2,
        expectedPolicyRevision: REVISION,
        models: ["deepseek/deepseek-chat"],
        limits: [],
      }),
    });
    assert.equal(unsupported.status, 422);
    assert.equal((await responseJson(unsupported)).error.code, "gateway_schema_unsupported");

    const badRevision = await request(base, "/api/v1/gateway-keys/alice/policy", {
      method: "POST",
      body: JSON.stringify({
        schemaVersion: 1,
        expectedPolicyRevision: "old",
        models: ["deepseek/deepseek-chat"],
        limits: [],
      }),
    });
    assert.equal(badRevision.status, 422);
    assert.equal((await responseJson(badRevision)).error.code, "gateway_output_invalid");
    assert.equal(calls, 0);
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("apply sends the original json, then performs an independent matching describe", async () => {
  const root = tempDirectory();
  const body = JSON.stringify({
    schemaVersion: 1,
    expectedPolicyRevision: REVISION,
    models: ["deepseek/deepseek-chat"],
    limits: [{ period: "month", tokens: 5_000_000, cost: 10, cacheReads: false }],
  });
  const calls = [];
  const readback = describeFixture("alice", { policyRevision: NEXT_REVISION });
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner: {
      apply: async (id, raw) => {
        calls.push({ action: "apply", id, raw });
        return result(readback);
      },
      describe: async (id) => {
        calls.push({ action: "describe", id });
        return result(readback);
      },
    },
    logger: () => {},
  });
  const base = await listen(server);
  try {
    const response = await request(base, "/api/v1/gateway-keys/alice/policy", {
      method: "POST",
      body,
    });
    assert.equal(response.status, 200);
    const value = await responseJson(response);
    assert.equal(value.state, "applied");
    assert.equal(value.readback.verified, true);
    assert.equal(value.readback.policyRevision, NEXT_REVISION);
    assert.equal(calls.length, 2);
    assert.deepEqual(calls[0], { action: "apply", id: "alice", raw: body });
    assert.deepEqual(calls[1], { action: "describe", id: "alice" });
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("an invalid apply acknowledgement with a matching readback is pending, not success", async () => {
  const root = tempDirectory();
  const body = JSON.stringify({
    schemaVersion: 1,
    expectedPolicyRevision: REVISION,
    models: ["deepseek/deepseek-chat"],
    limits: [{ period: "month", tokens: 5_000_000, cost: 10, cacheReads: false }],
  });
  const readback = describeFixture("alice", { policyRevision: NEXT_REVISION });
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner: {
      apply: async () => ({
        exitCode: 0,
        signal: null,
        stdout: "not-json\n",
        stderr: "",
        elapsedMs: 1,
      }),
      describe: async () => result(readback),
    },
    logger: () => {},
  });
  const base = await listen(server);
  try {
    const response = await request(base, "/api/v1/gateway-keys/alice/policy", {
      method: "POST",
      body,
    });
    assert.equal(response.status, 502);
    const value = await responseJson(response);
    assert.equal(value.state, "pending");
    assert.equal(value.error.code, "gateway_policy_unknown");
    assert.equal(value.error.retryable, true);
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("apply timeout or storage failure with a matching readback remains pending", async () => {
  const root = tempDirectory();
  const body = JSON.stringify({
    schemaVersion: 1,
    expectedPolicyRevision: REVISION,
    models: ["deepseek/deepseek-chat"],
    limits: [{ period: "month", tokens: 5_000_000, cost: 10, cacheReads: false }],
  });
  const readback = describeFixture("alice", { policyRevision: NEXT_REVISION });
  let applyFailure;
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner: {
      apply: async () => {
        throw applyFailure;
      },
      describe: async () => result(readback),
    },
    logger: () => {},
  });
  const base = await listen(server);
  try {
    for (const error of [
      Object.assign(new Error("timed out"), {
        code: "gateway_timeout",
        retryable: true,
      }),
      Object.assign(new Error("storage unavailable"), {
        code: "gateway_storage_unavailable",
        retryable: true,
      }),
    ]) {
      applyFailure = error;
      const response = await request(base, "/api/v1/gateway-keys/alice/policy", {
        method: "POST",
        body,
      });
      assert.equal(response.status, 502);
      const value = await responseJson(response);
      assert.equal(value.state, "pending");
      assert.equal(value.error.code, "gateway_policy_unknown");
      assert.equal(value.error.retryable, true);
    }
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("definite apply failures return immediately without a readback", async () => {
  const root = tempDirectory();
  const body = JSON.stringify({
    schemaVersion: 1,
    expectedPolicyRevision: REVISION,
    models: ["deepseek/deepseek-chat"],
    limits: [{ period: "month", tokens: 5_000_000, cost: 10, cacheReads: false }],
  });
  let describeCalls = 0;
  let applyResult = failure("gateway_key_not_found");
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner: {
      apply: async () => applyResult,
      describe: async () => {
        describeCalls += 1;
        throw new Error("describe must not be called for a definite apply failure");
      },
    },
    logger: () => {},
  });
  const base = await listen(server);
  try {
    const missing = await request(base, "/api/v1/gateway-keys/missing/policy", {
      method: "POST",
      body,
    });
    assert.equal(missing.status, 404);
    assert.equal((await responseJson(missing)).error.code, "gateway_key_not_found");
    assert.equal(describeCalls, 0);

    applyResult = failure("gateway_policy_conflict");
    const conflict = await request(base, "/api/v1/gateway-keys/alice/policy", {
      method: "POST",
      body,
    });
    assert.equal(conflict.status, 409);
    const conflictBody = await responseJson(conflict);
    assert.equal(conflictBody.state, "failed");
    assert.equal(conflictBody.error.code, "gateway_policy_conflict");
    assert.equal(describeCalls, 0);
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("tiny cost limits cannot round down to an empty policy limit", async () => {
  const root = tempDirectory();
  let calls = 0;
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner: {
      describe: async () => {
        calls += 1;
      },
      apply: async () => {
        calls += 1;
      },
    },
    logger: () => {},
  });
  const base = await listen(server);
  try {
    const response = await request(base, "/api/v1/gateway-keys/alice/policy", {
      method: "POST",
      body: JSON.stringify({
        schemaVersion: 1,
        expectedPolicyRevision: REVISION,
        models: ["deepseek/deepseek-chat"],
        limits: [{
          period: "month",
          tokens: 0,
          cost: 0.00004,
          cacheReads: false,
        }],
      }),
    });
    assert.equal(response.status, 422);
    assert.equal((await responseJson(response)).error.code, "gateway_output_invalid");
    assert.equal(calls, 0);
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("readback mismatch or failure remains pending and never reports applied", async () => {
  const root = tempDirectory();
  const body = JSON.stringify({
    schemaVersion: 1,
    expectedPolicyRevision: REVISION,
    models: ["deepseek/deepseek-chat"],
    limits: [{ period: "month", tokens: 5_000_000, cost: 10, cacheReads: false }],
  });
  let describeResult = result(describeFixture("alice", {
    models: { mode: "restricted", patterns: ["openai/gpt-5"] },
    policyRevision: NEXT_REVISION,
  }));
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner: {
      apply: async () => result(describeFixture("alice", { policyRevision: NEXT_REVISION })),
      describe: async () => describeResult,
    },
    logger: () => {},
  });
  const base = await listen(server);
  try {
    const mismatch = await request(base, "/api/v1/gateway-keys/alice/policy", {
      method: "POST",
      body,
    });
    assert.equal(mismatch.status, 502);
    const mismatchBody = await responseJson(mismatch);
    assert.equal(mismatchBody.state, "pending");
    assert.equal(mismatchBody.error.code, "gateway_readback_failed");

    describeResult = failure("gateway_timeout", true);
    const unavailable = await request(base, "/api/v1/gateway-keys/alice/policy", {
      method: "POST",
      body,
    });
    assert.equal(unavailable.status, 502);
    const unavailableBody = await responseJson(unavailable);
    assert.equal(unavailableBody.state, "pending");
    assert.equal(unavailableBody.error.code, "gateway_policy_unknown");
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("runner maps an oversized child output to gateway_output_too_large", async () => {
  const root = tempDirectory();
  const script = path.join(root, "large-output.mjs");
  fs.writeFileSync(script, [
    'process.stdout.write("x".repeat(70 * 1024));',
    "setInterval(() => {}, 1000);",
  ].join("\n"));
  const runner = scriptRunner(root, script, { timeoutMs: 2000 });
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner,
    logger: () => {},
  });
  const base = await listen(server);
  try {
    const response = await request(base, "/api/v1/gateway-keys/alice");
    assert.equal(response.status, 502);
    assert.equal((await responseJson(response)).error.code, "gateway_output_too_large");
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("runner times out and terminates the Magpie child process", async () => {
  const root = tempDirectory();
  const pidFile = path.join(root, "child.pid");
  const script = path.join(root, "timeout.mjs");
  fs.writeFileSync(script, [
    'import fs from "node:fs";',
    `fs.writeFileSync(${JSON.stringify(pidFile)}, String(process.pid));`,
    "process.on('SIGTERM', () => {});",
    "setInterval(() => {}, 1000);",
  ].join("\n"));
  const runner = scriptRunner(root, script, { timeoutMs: 200 });
  const { server } = createGatewayControlServer(baseConfig(root), {
    runner,
    logger: () => {},
  });
  const base = await listen(server);
  try {
    const response = await request(base, "/api/v1/gateway-keys/alice");
    assert.equal(response.status, 504);
    assert.equal((await responseJson(response)).error.code, "gateway_timeout");

    assert.equal(fs.existsSync(pidFile), true);
    const pid = Number(fs.readFileSync(pidFile, "utf8"));
    assert.ok(Number.isInteger(pid) && pid > 0);
    assert.equal(await waitForExit(pid), true);
  } finally {
    await close(server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("configuration rejects reused secrets and relative paths", () => {
  const root = tempDirectory();
  const common = {
    GATEWAY_CONTROL_TOKEN: "x".repeat(40),
    GATEWAY_CONTROL_MAGPIE: process.execPath,
    GATEWAY_CONTROL_CONFIG_HOME: root,
  };
  try {
    assert.throws(
      () => loadConfig({ ...common, AUTH_COOKIE_SECRET: common.GATEWAY_CONTROL_TOKEN }),
      /must not reuse AUTH_COOKIE_SECRET/,
    );
    assert.throws(
      () => loadConfig({ ...common, GATEWAY_CONTROL_MAGPIE: "magpie" }),
      /must be an absolute path/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
