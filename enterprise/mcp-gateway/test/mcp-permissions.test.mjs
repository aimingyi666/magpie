import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { issueApprovalToken } from "../src/approval.js";
import { McpAuditLog } from "../src/audit.js";
import { createMcpGatewayServer } from "../src/service.js";
import { McpRegistryStore } from "../src/store.js";

const SERVICE_TOKEN = ["mcp", "service", "integration", "token", "not", "real"].join("-");
const UPSTREAM_SECRET = ["upstream", "credential", "must", "stay", "private"].join("-");

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-mcp-permissions-"));
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
  const server = http.createServer(async (req, res) => {
    const message = await readJson(req);
    if (message.method === "initialize") {
      return writeJson(res, 200, {
        jsonrpc: "2.0",
        id: message.id,
        result: {
          protocolVersion: "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "mock-mcp", version: "1.0" },
        },
      });
    }
    if (message.method === "tools/list") {
      return writeJson(res, 200, {
        jsonrpc: "2.0",
        id: message.id,
        result: {
          tools: [{ name: "lookup", description: "Look up", inputSchema: { type: "object" } }],
        },
      });
    }
    if (message.method === "tools/call") {
      return writeJson(res, 200, {
        jsonrpc: "2.0",
        id: message.id,
        result: {
          content: [{ type: "text", text: `ok:${message.params.name}` }],
        },
      });
    }
    writeJson(res, 200, {
      jsonrpc: "2.0",
      id: message.id,
      error: { code: -32601, message: "unknown method" },
    });
  });
  const base = await listen(server);
  return { server, base };
}

async function startApp(root, upstreamBase, overrides = {}) {
  const result = await createMcpGatewayServer({
    bind: "127.0.0.1",
    port: 0,
    publicUrl: "http://127.0.0.1",
    serviceToken: SERVICE_TOKEN,
    storePath: path.join(root, "mcp-registry.json"),
    auditPath: path.join(root, "mcp-audit.jsonl"),
    maxBodyBytes: 256 * 1024,
    upstreamTimeoutMs: 1000,
    upstreamMaxResponseBytes: 1024 * 1024,
    healthIntervalMs: 3600000,
    healthTimeoutMs: 5000,
    breakerFailureThreshold: 3,
    breakerCooldownMs: 30000,
    rateLimitPerMinute: 10000,
    authRateLimitPerMinute: 10000,
    allowedOrigins: [],
    upstreamAllowedHosts: ["127.0.0.1"],
    allowHttpUpstreams: true,
    allowPrivateUpstreams: true,
    upstreamCa: undefined,
    protocolVersion: "2025-06-18",
    approvalHmacSecret: undefined,
    approvalMaxTtlSeconds: 900,
    secretEnv: { MCP_UPSTREAM_TOKEN: UPSTREAM_SECRET },
    ...overrides,
  });
  const base = await listen(result.server);
  return { ...result, base, upstreamBase };
}

async function responseJson(response) {
  return JSON.parse(await response.text());
}

async function adminRequest(app, route, { method = "GET", body, key, token = SERVICE_TOKEN, actor = "admin-service" } = {}) {
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

async function createServer(app, overrides = {}) {
  const response = await adminRequest(app, "/api/v1/admin/mcp/servers", {
    method: "POST",
    key: crypto.randomUUID(),
    body: {
      namespace: `test-${crypto.randomUUID().slice(0, 8)}`,
      name: "Test MCP",
      description: "A test MCP server",
    endpoint: `${app.upstreamBase || app.base}/mcp`,
      secretRef: "MCP_UPSTREAM_TOKEN",
      assignments: ["org:engineering"],
      status: "active",
      toolPolicies: [{ tool: "lookup", access: "allow", risk: "low", visible: true }],
      operationId: `op_server_${crypto.randomUUID()}`,
      reason: "Register test MCP server",
      ...overrides,
    },
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
      reason: "Issue employee credential",
      ...overrides,
    },
  });
  const body = await responseJson(response);
  assert.equal(response.status, 201, JSON.stringify(body));
  return body;
}

test("permissions: create and list permission rules", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const app = await startApp(root, upstream.base);
  try {
    await createServer(app);
    const alice = await issueClient(app);

    const created = await adminRequest(app, "/api/v1/admin/mcp/permissions", {
      method: "POST",
      key: crypto.randomUUID(),
      body: {
        mcpServerId: "srv_test",
        allowedRoles: ["employee"],
        allowedOrgUnits: ["engineering"],
        description: "Allow engineering employees",
        operationId: `op_perm_${crypto.randomUUID()}`,
        reason: "Test permission",
      },
    });
    assert.equal(created.status, 201);
    const createdBody = await responseJson(created);
    assert.match(createdBody.permission.id, /^mcp_perm_[a-z0-9]{16,64}$/);
    assert.equal(createdBody.permission.mcpServerId, "srv_test");

    const list = await adminRequest(app, "/api/v1/admin/mcp/permissions");
    assert.equal(list.status, 200);
    const listBody = await responseJson(list);
    assert.equal(listBody.permissions.length, 1);
    assert.equal(listBody.permissions[0].id, createdBody.permission.id);
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("permissions: delete permission rule", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const app = await startApp(root, upstream.base);
  try {
    const created = await adminRequest(app, "/api/v1/admin/mcp/permissions", {
      method: "POST",
      key: crypto.randomUUID(),
      body: {
        mcpServerId: "srv_test",
        allowedRoles: ["employee"],
        allowedOrgUnits: ["engineering"],
        operationId: `op_perm_${crypto.randomUUID()}`,
        reason: "Test permission",
      },
    });
    const createdBody = await responseJson(created);
    const permissionId = createdBody.permission.id;

    const deleted = await adminRequest(app, `/api/v1/admin/mcp/permissions/${permissionId}`, {
      method: "DELETE",
      key: crypto.randomUUID(),
    });
    assert.equal(deleted.status, 200);

    const list = await adminRequest(app, "/api/v1/admin/mcp/permissions");
    const listBody = await responseJson(list);
    assert.equal(listBody.permissions.length, 0);
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("call audit: list and get call audit entries", async () => {
  const root = tempDirectory();
  const upstream = await createMockMcp();
  const app = await startApp(root, upstream.base);
  try {
    const list = await adminRequest(app, "/api/v1/admin/mcp/call-audit");
    assert.equal(list.status, 200);
    const listBody = await responseJson(list);
    assert.ok(Array.isArray(listBody.callAudit));
  } finally {
    await close(app.server);
    await close(upstream.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});
