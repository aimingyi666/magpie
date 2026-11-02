import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  LocalMcpError,
  createLocalMcpServer,
} from "../src/index.js";

const TOKEN = ["local-mcp", "test-token", "0123456789"].join("-");

function temporaryRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "magpie-local-mcp-server-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function fakeHelper(overrides = {}) {
  const calls = [];
  return {
    calls,
    async snapshot() {
      return {
        schemaVersion: 1,
        status: "ready",
        revision: "desired-1",
        packages: [{ resourceId: "res_local_echo", packageId: "local-echo" }],
        blocked: [],
      };
    },
    async listTools(resourceId) {
      return {
        resourceId,
        releaseId: "rel_local_echo_1",
        packageId: "local-echo",
        packageReleaseId: "2026.11.1",
        tools: [{ name: "echo", description: "Echo", risk: "low", capabilities: [] }],
      };
    },
    async callTool(resourceId, toolName, args, options) {
      calls.push({ resourceId, toolName, args, options });
      return {
        status: "succeeded",
        result: { structuredContent: { echo: args.echo } },
      };
    },
    ...overrides,
  };
}

async function startServer(t, {
  helper = fakeHelper(),
  token = TOKEN,
  rootDir = temporaryRoot(t),
  ...overrides
} = {}) {
  const instance = await createLocalMcpServer({
    helper,
    token,
    rootDir,
    port: 0,
    now: () => Date.parse("2026-11-02T00:00:00.000Z"),
    ...overrides,
  });
  t.after(() => instance.close());
  const address = await instance.listen();
  return {
    instance,
    helper,
    rootDir,
    baseUrl: `http://127.0.0.1:${address.port}`,
    lockFile: instance.lockFile,
  };
}

async function jsonRequest(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  return {
    response,
    text,
    body: text ? JSON.parse(text) : null,
  };
}

function authHeaders(extra = {}) {
  return {
    authorization: `Bearer ${TOKEN}`,
    ...extra,
  };
}

test("healthz is public while status and tool routes require a bearer token", async (t) => {
  const server = await startServer(t);
  const health = await jsonRequest(`${server.baseUrl}/healthz`);
  assert.equal(health.response.status, 200);
  assert.equal(health.body.status, "ready");

  const missing = await jsonRequest(`${server.baseUrl}/api/v1/local-mcp/status`);
  assert.equal(missing.response.status, 401);
  assert.equal(missing.body.error.code, "unauthorized");

  const wrong = await jsonRequest(`${server.baseUrl}/api/v1/local-mcp/status`, {
    headers: { authorization: "Bearer wrong-token-0123456789" },
  });
  assert.equal(wrong.response.status, 401);

  const status = await jsonRequest(`${server.baseUrl}/api/v1/local-mcp/status`, {
    headers: authHeaders(),
  });
  assert.equal(status.response.status, 200);
  assert.equal(status.body.packages[0].resourceId, "res_local_echo");
});

test("tools and call routes map resource and tool identity", async (t) => {
  const server = await startServer(t);
  const tools = await jsonRequest(
    `${server.baseUrl}/api/v1/local-mcp/resources/res_local_echo/tools`,
    { headers: authHeaders() },
  );
  assert.equal(tools.response.status, 200);
  assert.equal(tools.body.packageId, "local-echo");

  const call = await jsonRequest(
    `${server.baseUrl}/api/v1/local-mcp/resources/res_local_echo/tools/echo/call`,
    {
      method: "POST",
      headers: authHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({
        args: { echo: "hello" },
        approval: { token: "approval-test-token" },
      }),
    },
  );
  assert.equal(call.response.status, 200);
  assert.equal(call.body.result.structuredContent.echo, "hello");
  assert.deepEqual(server.helper.calls, [{
    resourceId: "res_local_echo",
    toolName: "echo",
    args: { echo: "hello" },
    options: { approval: { token: "approval-test-token" } },
  }]);
});

test("request validation rejects unsafe paths, media types and fields", async (t) => {
  const server = await startServer(t);
  const invalidResource = await jsonRequest(
    `${server.baseUrl}/api/v1/local-mcp/resources/res%20bad/tools`,
    { headers: authHeaders() },
  );
  assert.equal(invalidResource.response.status, 400);
  assert.equal(invalidResource.body.error.code, "invalid_resource_id");

  const mediaType = await jsonRequest(
    `${server.baseUrl}/api/v1/local-mcp/resources/res_local_echo/tools/echo/call`,
    {
      method: "POST",
      headers: authHeaders({ "content-type": "text/plain" }),
      body: JSON.stringify({ args: {} }),
    },
  );
  assert.equal(mediaType.response.status, 415);
  assert.equal(mediaType.body.error.code, "unsupported_media_type");

  const unknownField = await jsonRequest(
    `${server.baseUrl}/api/v1/local-mcp/resources/res_local_echo/tools/echo/call`,
    {
      method: "POST",
      headers: authHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({ args: {}, packageId: "attacker-package" }),
    },
  );
  assert.equal(unknownField.response.status, 400);
  assert.equal(unknownField.body.error.code, "unknown_field");

  const malformed = await jsonRequest(
    `${server.baseUrl}/api/v1/local-mcp/resources/res_local_echo/tools/echo/call`,
    {
      method: "POST",
      headers: authHeaders({ "content-type": "application/json" }),
      body: "{\"args\":",
    },
  );
  assert.equal(malformed.response.status, 400);
  assert.equal(malformed.body.error.code, "invalid_json");
});

test("oversized request bodies fail with 413 and do not reach the helper", async (t) => {
  const server = await startServer(t, { maxBodyBytes: 1024 });
  const result = await jsonRequest(
    `${server.baseUrl}/api/v1/local-mcp/resources/res_local_echo/tools/echo/call`,
    {
      method: "POST",
      headers: authHeaders({ "content-type": "application/json" }),
      body: JSON.stringify({ args: { echo: "x".repeat(2048) } }),
    },
  );
  assert.equal(result.response.status, 413);
  assert.equal(result.body.error.code, "request_too_large");
  assert.deepEqual(server.helper.calls, []);
});

test("internal errors are converted to stable codes without leaking details", async (t) => {
  const helper = fakeHelper({
    async listTools() {
      throw new Error("C:\\secret\\token.txt TOP-SECRET");
    },
  });
  const server = await startServer(t, { helper });
  const result = await jsonRequest(
    `${server.baseUrl}/api/v1/local-mcp/resources/res_local_echo/tools`,
    { headers: authHeaders() },
  );
  assert.equal(result.response.status, 500);
  assert.deepEqual(result.body, {
    schemaVersion: 1,
    ok: false,
    error: { code: "internal_error" },
  });
  assert.equal(result.text.includes("secret"), false);
  assert.equal(result.text.includes("TOP-SECRET"), false);
});

test("known helper failures map to stable HTTP statuses", async (t) => {
  const cases = [
    ["publisher_denied", 403],
    ["resource_drift", 409],
    ["secret_unavailable", 503],
    ["process_timeout", 504],
    ["tool_failed", 502],
  ];
  for (const [code, status] of cases) {
    const helper = fakeHelper({
      async listTools() {
        throw new LocalMcpError(code, "failure detail must not leak");
      },
    });
    const server = await startServer(t, { helper });
    const result = await jsonRequest(
      `${server.baseUrl}/api/v1/local-mcp/resources/res_local_echo/tools`,
      { headers: authHeaders() },
    );
    assert.equal(result.response.status, status);
    assert.equal(result.body.error.code, code);
    assert.equal(result.text.includes("failure detail"), false);
  }
});

test("only loopback bind addresses are accepted", async () => {
  await assert.rejects(
    () => createLocalMcpServer({
      helper: fakeHelper(),
      token: TOKEN,
      bind: "0.0.0.0",
      rootDir: path.join(os.tmpdir(), "unused-magpie-local-mcp"),
    }),
    (error) => error instanceof LocalMcpError && error.code === "invalid_config",
  );
});

test("a helper lock prevents overlapping servers and close is idempotent", async (t) => {
  const rootDir = temporaryRoot(t);
  const server = await startServer(t, { rootDir });
  assert.equal(fs.existsSync(server.lockFile), true);

  await assert.rejects(
    () => createLocalMcpServer({
      helper: fakeHelper(),
      token: TOKEN,
      rootDir,
      port: 0,
      now: () => Date.parse("2026-11-02T00:00:00.000Z"),
    }),
    (error) => error instanceof LocalMcpError && error.code === "helper_locked",
  );

  const firstClose = server.instance.close();
  const secondClose = server.instance.close();
  assert.equal(firstClose, secondClose);
  await firstClose;
  await server.instance.close();
  assert.equal(fs.existsSync(server.lockFile), false);
});

test("server responses include no CORS or cache permission", async (t) => {
  const server = await startServer(t);
  const result = await jsonRequest(`${server.baseUrl}/api/v1/local-mcp/status`, {
    headers: authHeaders({ origin: "https://evil.example" }),
  });
  assert.equal(result.response.status, 200);
  assert.equal(result.response.headers.get("access-control-allow-origin"), null);
  assert.equal(result.response.headers.get("cache-control"), "no-store");
  assert.equal(result.response.headers.get("x-content-type-options"), "nosniff");
});
