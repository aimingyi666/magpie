import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { issueApprovalToken } from "../src/approval.js";
import { McpAuditLog } from "../src/audit.js";
import { isUnsafeAddress, NetworkPolicyError, safeRequest, validateUpstreamUrl } from "../src/network.js";
import { createMcpGatewayServer } from "../src/service.js";
import { McpRegistryStore } from "../src/store.js";

const SERVICE_TOKEN = ["mcp", "service", "integration", "token", "not", "real"].join("-");
const APPROVAL_SECRET = ["mcp", "approval", "integration", "secret", "not", "real"].join("-");
const UPSTREAM_SECRET = ["upstream", "credential", "must", "stay", "private"].join("-");

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-mcp-gateway-"));
}

function baseConfig(root, overrides = {}) {
  return {
    bind: "127.0.0.1",
    port: 0,
    publicUrl: "http://127.0.0.1",
    serviceToken: SERVICE_TOKEN,
    storePath: path.join(root, "mcp-registry.json"),
    auditPath: path.join(root, "mcp-audit.jsonl"),
    maxBodyBytes: 256 * 1024,
    maxServers: 100,
    maxClients: 100,
    maxToolsPerServer: 100,
    catalogTtlMs: 60000,
    upstreamTimeoutMs: 1000,
    upstreamMaxResponseBytes: 1024 * 1024,
    healthIntervalMs: 3600000,
    healthTimeoutMs: 500,
    breakerFailureThreshold: 3,
    breakerCooldownMs: 30000,
    rateLimitPerMinute: 10000,
    authRateLimitPerMinute: 10000,
    clientTokenTtlMs: 30 * 86400000,
    allowedOrigins: [],
    upstreamAllowedHosts: ["127.0.0.1"],
    allowHttpUpstreams: true,
    allowPrivateUpstreams: true,
    upstreamCa: undefined,
    protocolVersion: "2025-06-18",
    approvalHmacSecret: APPROVAL_SECRET,
    approvalMaxTtlSeconds: 900,
    secretEnv: {
      MCP_UPSTREAM_TOKEN: UPSTREAM_SECRET,
    },
    ...overrides,
  };
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return `http://127.0.0.1:${server.address().port}`;
}

async function close(server) {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        reject(new Error("invalid request"));
      }
    });
    req.on("error", reject);
  });
}

function writeJson(res, statusCode, body, headers = {}) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(statusCode, {
    "content-type": "application/json",
    "content-length": String(payload.length),
    ...headers,
  });
  res.end(payload);
}

async function createMockMcp() {
  const authorizations = [];
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname === "/large") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(Buffer.alloc(4096, 32));
      return;
    }
    if (url.pathname === "/redirect") {
      res.writeHead(302, { location: "http://127.0.0.1:1/private" });
      res.end();
      return;
    }
    if (url.pathname === "/broken") {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "broken" }));
      return;
    }
    if (url.pathname === "/slow") {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    const message = await readJson(req);
    authorizations.push(String(req.headers.authorization || ""));
    const responseHeaders = { "mcp-session-id": `session-${url.pathname.slice(1) || "root"}` };
    if (message.method === "initialize") {
      return writeJson(res, 200, {
        jsonrpc: "2.0",
        id: message.id,
        result: {
          protocolVersion: "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "mock-mcp", version: "1.0" },
        },
      }, responseHeaders);
    }
    if (message.method === "notifications/initialized") {
      res.writeHead(202, responseHeaders);
      res.end();
      return;
    }
    if (message.method === "tools/list") {
      const tools = url.pathname === "/search"
        ? [
          { name: "lookup", description: "Look up a record", inputSchema: { type: "object" } },
          { name: "delete_record", description: "Delete a record", inputSchema: { type: "object" } },
          { name: "secret_tool", description: "Hidden tool", inputSchema: { type: "object" } },
          { name: "explode", description: "Always fails", inputSchema: { type: "object" } },
        ]
        : url.pathname === "/docs"
          ? [{ name: "read_doc", description: "Read a document", inputSchema: { type: "object" } }]
          : [{ name: "echo", description: "Echo input", inputSchema: { type: "object" } }];
      return writeJson(res, 200, {
        jsonrpc: "2.0",
        id: message.id,
        result: { tools },
      }, responseHeaders);
    }
    if (message.method === "tools/call") {
      if (message.params?.name === "explode") {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "tool failed" }));
        return;
      }
      return writeJson(res, 200, {
        jsonrpc: "2.0",
        id: message.id,
        result: {
          content: [{
            type: "text",
            text: `${message.params.name}:${JSON.stringify(message.params.arguments || {})}`,
          }],
        },
      }, responseHeaders);
    }
    writeJson(res, 200, {
      jsonrpc: "2.0",
      id: message.id,
      error: { code: -32601, message: "unknown method" },
    }, responseHeaders);
  });
  const base = await listen(server);
  return { server, base, authorizations };
}

async function startApp(root, upstreamBase, overrides = {}) {
  const result = await createMcpGatewayServer(baseConfig(root, overrides), { logger: () => {} });
  const base = await listen(result.server);
  return { ...result, base, upstreamBase };
}

async function adminRequest(app, route, {
  method = "GET",
  body,
  key,
  token = SERVICE_TOKEN,
  actor = "admin-service",
} = {}) {
  const headers = {};
  if (token !== null) headers.authorization = `Bearer ${token}`;
  if (actor !== null) headers["x-magpie-actor"] = actor;
  if (key) headers["idempotency-key"] = key;
  let payload;
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    payload = JSON.stringify(body);
  }
  return fetch(`${app.base}${route}`, { method, headers, body: payload });
}

async function responseJson(response) {
  return JSON.parse(await response.text());
}

function serverPayload(upstreamBase, endpointPath, overrides = {}) {
  return {
    namespace: "search",
    name: "Enterprise search",
    description: "Search enterprise records",
    endpoint: `${upstreamBase}${endpointPath}`,
    secretRef: "MCP_UPSTREAM_TOKEN",
    assignments: ["org:engineering"],
    status: "active",
    toolPolicies: [
      { tool: "delete_record", access: "allow", risk: "high", visible: true },
      { tool: "secret_tool", access: "deny", risk: "low", visible: false },
      { tool: "explode", access: "allow", risk: "low", visible: true },
    ],
    operationId: `op_server_${crypto.randomUUID()}`,
    reason: "Register an enterprise MCP server",
    ...overrides,
  };
}

async function createServer(app, payload) {
  const response = await adminRequest(app, "/api/v1/admin/mcp/servers", {
    method: "POST",
    key: crypto.randomUUID(),
    body: payload,
  });
  const body = await responseJson(response);
  assert.equal(response.status, 201, JSON.stringify(body));
  return body.server;
}

async function issueClient(app, overrides = {}) {
  const response = await adminRequest(app, "/api/v1/admin/mcp/clients", {
    method: "POST",
    key: crypto.randomUUID(),
    body: {
      name: "Alice laptop",
      subjectId: "user-alice",
      orgIds: ["engineering"],
      deviceIds: ["device-alice"],
      serverScopes: ["*"],
      ttlDays: 30,
      operationId: `op_client_${crypto.randomUUID()}`,
      reason: "Issue a scoped employee credential",
      ...overrides,
    },
  });
  const body = await responseJson(response);
  assert.equal(response.status, 201, JSON.stringify(body));
  return body;
}

async function mcpRequest(app, token, body, headers = {}) {
  return fetch(`${app.base}/mcp/enterprise`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

async function setupGovernedApp(root, upstreamBase, overrides = {}) {
  const app = await startApp(root, upstreamBase, overrides);
  const search = await createServer(app, serverPayload(upstreamBase, "/search"));
  const docs = await createServer(app, serverPayload(upstreamBase, "/docs", {
    namespace: "docs",
    name: "Documentation",
    description: "Enterprise documentation",
    assignments: ["device:device-alice"],
    toolPolicies: [],
  }));
  const personal = await createServer(app, serverPayload(upstreamBase, "/personal", {
    namespace: "personal",
    name: "Personal context",
    description: "User-scoped context",
    assignments: ["user:user-alice"],
    toolPolicies: [],
  }));
  const broken = await createServer(app, serverPayload(upstreamBase, "/broken", {
    namespace: "broken",
    name: "Broken service",
    description: "An unhealthy service",
    assignments: ["org:operations"],
    toolPolicies: [],
  }));
  const slow = await createServer(app, serverPayload(upstreamBase, "/slow", {
    namespace: "slow",
    name: "Slow service",
    description: "A timing-out service",
    assignments: ["org:operations"],
    toolPolicies: [],
  }));
  return { app, search, docs, personal, broken, slow };
}

test("admin routes require a service token, actor and idempotent writes", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const app = await startApp(root, upstream.base);
  try {
    const unauthorized = await adminRequest(app, "/api/v1/admin/mcp/servers", {
      token: null,
      actor: null,
    });
    assert.equal(unauthorized.status, 401);
    assert.equal((await responseJson(unauthorized)).error.code, "unauthorized");

    const noActor = await adminRequest(app, "/api/v1/admin/mcp/servers", { actor: null });
    assert.equal(noActor.status, 400);
    assert.equal((await responseJson(noActor)).error.code, "invalid_actor");

    const payload = serverPayload(upstream.base, "/search");
    const key = crypto.randomUUID();
    const first = await adminRequest(app, "/api/v1/admin/mcp/servers", {
      method: "POST",
      key,
      body: payload,
    });
    const firstBody = await responseJson(first);
    assert.equal(first.status, 201);
    assert.match(firstBody.server.id, /^srv_[a-z0-9]{16,64}$/);
    assert.equal(firstBody.server.secretConfigured, true);

    const replay = await adminRequest(app, "/api/v1/admin/mcp/servers", {
      method: "POST",
      key,
      body: payload,
    });
    const replayBody = await responseJson(replay);
    assert.equal(replay.status, 201);
    assert.equal(replay.headers.get("idempotent-replay"), "true");
    assert.equal(replayBody.server.id, firstBody.server.id);

    const conflict = await adminRequest(app, "/api/v1/admin/mcp/servers", {
      method: "POST",
      key,
      body: { ...payload, namespace: "other" },
    });
    assert.equal(conflict.status, 409);
    assert.equal((await responseJson(conflict)).error.code, "idempotency_conflict");
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("server updates use optimistic concurrency and reject namespace conflicts", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const app = await startApp(root, upstream.base);
  try {
    const search = await createServer(app, serverPayload(upstream.base, "/search"));
    const updateKey = crypto.randomUUID();
    const update = await adminRequest(app, `/api/v1/admin/mcp/servers/${search.id}`, {
      method: "PUT",
      key: updateKey,
      body: serverPayload(upstream.base, "/search", {
        name: "Enterprise search v2",
        expectedUpdatedAt: search.updatedAt,
      }),
    });
    const updateBody = await responseJson(update);
    assert.equal(update.status, 200, JSON.stringify(updateBody));
    assert.equal(updateBody.server.name, "Enterprise search v2");
    assert.notEqual(updateBody.server.updatedAt, search.updatedAt);

    const stale = await adminRequest(app, `/api/v1/admin/mcp/servers/${search.id}`, {
      method: "PUT",
      key: crypto.randomUUID(),
      body: serverPayload(upstream.base, "/search", {
        name: "Stale update",
        expectedUpdatedAt: search.updatedAt,
      }),
    });
    assert.equal(stale.status, 409);
    assert.equal((await responseJson(stale)).error.code, "update_conflict");

    const conflict = await adminRequest(app, "/api/v1/admin/mcp/servers", {
      method: "POST",
      key: crypto.randomUUID(),
      body: serverPayload(upstream.base, "/docs"),
    });
    assert.equal(conflict.status, 409);
    assert.equal((await responseJson(conflict)).error.code, "namespace_conflict");
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("org, device, user and server scopes control visibility and calls", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const { app } = await setupGovernedApp(root, upstream.base);
  try {
    const alice = await issueClient(app);
    const finance = await issueClient(app, {
      name: "Finance laptop",
      subjectId: "user-finance",
      orgIds: ["finance"],
      deviceIds: ["device-finance"],
    });

    const aliceList = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {},
    });
    const aliceBody = await responseJson(aliceList);
    const names = aliceBody.result.tools.map((tool) => tool.name);
    assert.deepEqual(names.sort(), [
      "docs__read_doc",
      "personal__echo",
      "search__delete_record",
      "search__explode",
      "search__lookup",
    ]);
    assert.equal(names.includes("search__secret_tool"), false);

    const financeList = await mcpRequest(app, finance.token, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    });
    assert.deepEqual((await responseJson(financeList)).result.tools, []);

    const hiddenCall = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "search__secret_tool", arguments: {} },
    });
    const hiddenBody = await responseJson(hiddenCall);
    assert.equal(hiddenBody.error.code, -32602);
    assert.equal(hiddenBody.error.message, "The tool was not found");

    const allowedCall = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "docs__read_doc", arguments: { id: "doc-1" } },
    });
    const allowedBody = await responseJson(allowedCall);
    assert.equal(allowedBody.result.content[0].text, 'read_doc:{"id":"doc-1"}');
    assert.equal(upstream.authorizations.at(-1), `Bearer ${UPSTREAM_SECRET}`);

    const revoke = await adminRequest(app, `/api/v1/admin/mcp/clients/${alice.client.id}/revoke`, {
      method: "POST",
      key: crypto.randomUUID(),
      body: {
        operationId: "op_revoke_alice",
        reason: "Employee left the company",
      },
    });
    assert.equal(revoke.status, 200);
    const afterRevoke = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 5,
      method: "ping",
    });
    assert.equal(afterRevoke.status, 401);
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("high-risk calls require a bound one-time approval token", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const { app, search } = await setupGovernedApp(root, upstream.base);
  try {
    const alice = await issueClient(app);
    const missing = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "search__delete_record", arguments: { id: "record-1" } },
    });
    assert.equal((await responseJson(missing)).error.code, -32002);

    const now = Math.floor(Date.now() / 1000);
    const token = issueApprovalToken(APPROVAL_SECRET, {
      approvalId: "approval-1",
      clientId: alice.client.id,
      serverId: search.id,
      tool: "delete_record",
      iat: now,
      exp: now + 60,
      nonce: crypto.randomUUID(),
    });
    const tampered = `${token.slice(0, -1)}${token.endsWith("A") ? "B" : "A"}`;
    const tamperedResponse = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 20,
      method: "tools/call",
      params: { name: "search__delete_record", arguments: {} },
    }, { "x-magpie-approval-token": tampered });
    assert.equal((await responseJson(tamperedResponse)).error.code, -32002);

    const approved = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "search__delete_record", arguments: { id: "record-1" } },
    }, { "x-magpie-approval-token": token });
    assert.equal((await responseJson(approved)).result.content[0].type, "text");

    const replay = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "search__delete_record", arguments: { id: "record-1" } },
    }, { "x-magpie-approval-token": token });
    assert.equal((await responseJson(replay)).error.code, -32002);

    const wrongBinding = issueApprovalToken(APPROVAL_SECRET, {
      approvalId: "approval-2",
      clientId: alice.client.id,
      serverId: search.id,
      tool: "another_tool",
      iat: now,
      exp: now + 60,
      nonce: crypto.randomUUID(),
    });
    const denied = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "search__delete_record", arguments: {} },
    }, { "x-magpie-approval-token": wrongBinding });
    assert.equal((await responseJson(denied)).error.code, -32002);

    const expired = issueApprovalToken(APPROVAL_SECRET, {
      approvalId: "approval-3",
      clientId: alice.client.id,
      serverId: search.id,
      tool: "delete_record",
      iat: now - 120,
      exp: now - 60,
      nonce: crypto.randomUUID(),
    });
    const expiredResponse = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "search__delete_record", arguments: {} },
    }, { "x-magpie-approval-token": expired });
    assert.equal((await responseJson(expiredResponse)).error.code, -32002);
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("missing approval signing configuration fails closed for high-risk tools", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const { app } = await setupGovernedApp(root, upstream.base, {
    approvalHmacSecret: "",
  });
  try {
    const alice = await issueClient(app);
    const response = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "search__delete_record", arguments: {} },
    }, { "x-magpie-approval-token": "unavailable" });
    assert.equal((await responseJson(response)).error.code, -32002);
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("unknown methods, batch requests and denied calls have explicit protocol boundaries", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const { app } = await setupGovernedApp(root, upstream.base);
  try {
    const alice = await issueClient(app);
    const unknown = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 1,
      method: "resources/list",
    });
    assert.equal(unknown.status, 200);
    assert.equal((await responseJson(unknown)).error.code, -32601);

    const batch = await mcpRequest(app, alice.token, [{
      jsonrpc: "2.0",
      id: 2,
      method: "ping",
    }]);
    assert.equal(batch.status, 400);
    assert.equal((await responseJson(batch)).error.code, "batch_not_supported");

    const invalidParams = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "search__lookup", arguments: [] },
    });
    assert.equal((await responseJson(invalidParams)).error.code, -32602);

    const denied = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "search__secret_tool", arguments: {} },
    });
    assert.equal((await responseJson(denied)).error.code, -32602);

    const listed = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/list",
      params: {},
    });
    assert.equal(listed.status, 200);

    const audit = await adminRequest(app, "/api/v1/admin/mcp/audit-logs");
    const actions = (await responseJson(audit)).auditLogs.map((entry) => entry.action);
    assert.equal(actions.includes("mcp.denied"), true);
    assert.equal(actions.includes("mcp.list"), true);
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("one failing server and an open circuit do not hide a healthy server", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const { app, search } = await setupGovernedApp(root, upstream.base, {
    breakerFailureThreshold: 1,
    breakerCooldownMs: 30000,
  });
  try {
    const alice = await issueClient(app);
    const failed = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "search__explode", arguments: {} },
    });
    assert.equal((await responseJson(failed)).error.code, -32001);

    const open = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "search__lookup", arguments: {} },
    });
    assert.equal((await responseJson(open)).error.code, -32001);

    const healthy = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "docs__read_doc", arguments: { id: "doc-2" } },
    });
    assert.equal((await responseJson(healthy)).result.content[0].type, "text");

    const check = await adminRequest(app, `/api/v1/admin/mcp/servers/${search.id}/check`, {
      method: "POST",
      key: crypto.randomUUID(),
      body: {
        operationId: "op_check_search",
        reason: "Check after a transient failure",
      },
    });
    assert.equal((await responseJson(check)).health.state, "healthy");

    const recovered = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "search__lookup", arguments: {} },
    });
    assert.equal((await responseJson(recovered)).result.content[0].type, "text");
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("health checks time out and mark only the slow server unhealthy", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const { app, slow, docs } = await setupGovernedApp(root, upstream.base, {
    healthTimeoutMs: 20,
  });
  try {
    const slowCheck = await adminRequest(app, `/api/v1/admin/mcp/servers/${slow.id}/check`, {
      method: "POST",
      key: crypto.randomUUID(),
      body: {
        operationId: "op_check_slow",
        reason: "Check slow server",
      },
    });
    const slowHealth = (await responseJson(slowCheck)).health;
    assert.equal(slowHealth.state, "unhealthy");
    assert.equal(slowHealth.errorCode, "upstream_timeout");

    const docsCheck = await adminRequest(app, `/api/v1/admin/mcp/servers/${docs.id}/check`, {
      method: "POST",
      key: crypto.randomUUID(),
      body: {
        operationId: "op_check_docs",
        reason: "Check docs server",
      },
    });
    assert.equal((await responseJson(docsCheck)).health.state, "healthy");
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("request, upstream response, redirect and rate boundaries fail closed", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const app = await startApp(root, upstream.base, {
    maxBodyBytes: 1024,
    rateLimitPerMinute: 2,
    upstreamMaxResponseBytes: 1024,
  });
  try {
    const alice = await issueClient(app);
    const tooLarge = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 1,
      method: "ping",
      padding: "x".repeat(2048),
    });
    assert.equal(tooLarge.status, 413);

    for (let index = 0; index < 1; index += 1) {
      const response = await mcpRequest(app, alice.token, {
        jsonrpc: "2.0",
        id: index + 2,
        method: "ping",
      });
      assert.equal(response.status, 200);
    }
    const limited = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 5,
      method: "ping",
    });
    assert.equal(limited.status, 429);

    const networkConfig = baseConfig(root, {
      upstreamMaxResponseBytes: 1024,
      allowPrivateUpstreams: true,
      healthTimeoutMs: 20,
    });
    await assert.rejects(
      safeRequest(`${upstream.base}/large`, { config: networkConfig, body: "{}" }),
      (error) => error instanceof NetworkPolicyError && error.code === "upstream_response_too_large",
    );
    await assert.rejects(
      safeRequest(`${upstream.base}/redirect`, { config: networkConfig, body: "{}" }),
      (error) => error instanceof NetworkPolicyError && error.code === "upstream_redirect_refused",
    );
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("browser origins are denied unless explicitly allowed", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const app = await startApp(root, upstream.base);
  try {
    const alice = await issueClient(app);
    const denied = await mcpRequest(app, alice.token, {
      jsonrpc: "2.0",
      id: 1,
      method: "ping",
    }, { origin: "null" });
    assert.equal(denied.status, 403);
    assert.equal((await responseJson(denied)).error.code, "origin_denied");
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("private, loopback, link-local and metadata targets are rejected by default", async () => {
  const root = tempDirectory();
  const config = baseConfig(root, {
    allowHttpUpstreams: true,
    allowPrivateUpstreams: false,
    upstreamAllowedHosts: ["example.test"],
  });
  assert.equal(isUnsafeAddress("127.0.0.1"), true);
  assert.equal(isUnsafeAddress("10.0.0.1"), true);
  assert.equal(isUnsafeAddress("169.254.169.254"), true);
  assert.equal(isUnsafeAddress("::1"), true);
  assert.equal(isUnsafeAddress("fe80::1"), true);
  assert.equal(isUnsafeAddress("fd00::1"), true);
  assert.equal(isUnsafeAddress("2001:db8::1"), true);
  assert.equal(isUnsafeAddress("::ffff:7f00:1"), true);
  assert.equal(isUnsafeAddress("::ffff:10.0.0.1"), true);
  assert.equal(isUnsafeAddress("64:ff9b::7f00:1"), true);
  assert.equal(isUnsafeAddress("2002:7f00:1::"), true);
  assert.equal(isUnsafeAddress("::ffff:808:808"), false);
  assert.equal(isUnsafeAddress("8.8.8.8"), false);

  await assert.rejects(
    safeRequest("http://example.test/mcp", {
      config,
      resolver: async () => [{ address: "127.0.0.1", family: 4 }],
      body: "{}",
    }),
    (error) => error instanceof NetworkPolicyError && error.code === "unsafe_upstream_address",
  );
  assert.throws(
    () => validateUpstreamUrl("http://example.test.evil/mcp", config),
    (error) => error instanceof NetworkPolicyError && error.code === "upstream_host_not_allowed",
  );
});

test("malformed registry and audit files, plaintext credentials and unknown fields fail closed", async () => {
  const root = tempDirectory();
  const storePath = path.join(root, "bad-store.json");
  fs.writeFileSync(storePath, JSON.stringify({
    version: 1,
    servers: {},
    clients: {},
    idempotency: {},
    token: "plaintext",
  }));
  await assert.rejects(
    new McpRegistryStore(storePath).load(),
    /schema fields|unknown|exactly/i,
  );

  const secretStorePath = path.join(root, "secret-store.json");
  fs.writeFileSync(secretStorePath, JSON.stringify({
    version: 1,
    servers: {
      srv_1234567890abcdef: {
        id: "srv_1234567890abcdef",
        namespace: "search",
        name: "Search",
        description: "",
        endpoint: "https://example.test/mcp",
        secretRef: `sk-${"a".repeat(40)}`,
        assignments: ["*"],
        status: "active",
        toolPolicies: [],
        createdAt: "2026-11-02T00:00:00.000Z",
        updatedAt: "2026-11-02T00:00:00.000Z",
        createdBy: "admin",
        updatedBy: "admin",
      },
    },
    clients: {},
    idempotency: {},
  }));
  await assert.rejects(new McpRegistryStore(secretStorePath).load(), /invalid|credential/i);

  const auditPath = path.join(root, "bad-audit.jsonl");
  fs.writeFileSync(auditPath, "{not-json}\n");
  await assert.rejects(new McpAuditLog(auditPath).load(), /malformed/i);
});

test("client and admin projections plus audit never contain credential values", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const { app } = await setupGovernedApp(root, upstream.base);
  try {
    const issued = await issueClient(app);
    const storeText = fs.readFileSync(app.store.file, "utf8");
    assert.equal(storeText.includes(issued.token), false);
    const clients = await adminRequest(app, "/api/v1/admin/mcp/clients");
    const clientsText = await clients.text();
    assert.equal(clientsText.includes(issued.token), false);
    assert.equal(clientsText.includes(UPSTREAM_SECRET), false);

    await mcpRequest(app, issued.token, {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {},
    });
    const servers = await adminRequest(app, "/api/v1/admin/mcp/servers");
    const serversText = await servers.text();
    assert.equal(serversText.includes(UPSTREAM_SECRET), false);

    const audit = await adminRequest(app, "/api/v1/admin/mcp/audit-logs");
    const auditText = await audit.text();
    assert.equal(auditText.includes(issued.token), false);
    assert.equal(auditText.includes(UPSTREAM_SECRET), false);
    assert.equal(auditText.includes('"arguments"'), false);
    assert.equal(auditText.includes('"content"'), false);
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("expired and replayed client credentials fail closed", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const app = await startApp(root, upstream.base);
  try {
    const key = crypto.randomUUID();
    const issuedResponse = await adminRequest(app, "/api/v1/admin/mcp/clients", {
      method: "POST",
      key,
      body: {
        name: "Alice laptop",
        subjectId: "user-alice",
        orgIds: ["engineering"],
        deviceIds: ["device-alice"],
        serverScopes: ["*"],
        operationId: "op_client_expiry",
        reason: "Test expiry",
      },
    });
    const issued = await responseJson(issuedResponse);
    assert.equal(issuedResponse.status, 201);

    const replay = await adminRequest(app, "/api/v1/admin/mcp/clients", {
      method: "POST",
      key,
      body: {
        name: "Alice laptop",
        subjectId: "user-alice",
        orgIds: ["engineering"],
        deviceIds: ["device-alice"],
        serverScopes: ["*"],
        operationId: "op_client_expiry",
        reason: "Test expiry",
      },
    });
    const replayBody = await responseJson(replay);
    assert.equal(replay.headers.get("idempotent-replay"), "true");
    assert.equal(Object.hasOwn(replayBody, "token"), false);

    await app.store.mutate((data) => {
      data.clients[issued.client.id].expiresAt = new Date(Date.now() - 1000).toISOString();
    });
    const expired = await mcpRequest(app, issued.token, {
      jsonrpc: "2.0",
      id: 1,
      method: "ping",
    });
    assert.equal(expired.status, 401);
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});
