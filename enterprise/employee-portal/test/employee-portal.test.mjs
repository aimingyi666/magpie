import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createEmployeePortalServer } from "../src/service.js";

const SERVICE_TOKEN = ["employee", "portal", "integration", "token", "not", "real"].join("-");

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-employee-portal-"));
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return `http://127.0.0.1:${server.address().port}`;
}

async function close(server) {
  if (!server.listening) return;
  server.closeAllConnections?.();
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

// Force exit so undici fetch connections do not keep the process alive.
process.on("exit", () => {});

async function fetchJson(url, opts = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(url, { ...opts, signal: controller.signal });
    return { status: res.status, body: JSON.parse(await res.text()) };
  } finally {
    clearTimeout(timeout);
  }
}

function baseConfig(root, overrides = {}) {
  return {
    bind: "127.0.0.1",
    port: 0,
    publicUrl: "http://127.0.0.1",
    serviceToken: SERVICE_TOKEN,
    storePath: path.join(root, "store.json"),
    adminServiceUrl: "",
    adminServiceToken: "",
    modelCatalogUrl: "",
    usageStorePath: path.join(root, "usage.json"),
    ticketStorePath: path.join(root, "tickets.json"),
    rateLimitPerMinute: 10000,
    sessionTtlMs: 30 * 60 * 1000,
    ...overrides,
  };
}

async function startApp(root, overrides = {}) {
  const result = await createEmployeePortalServer(baseConfig(root, overrides));
  const base = await listen(result.server);
  return { ...result, base };
}

async function portalRequest(app, route, { method = "GET", body, subject = "user-alice" } = {}) {
  const headers = {};
  if (subject !== null) headers["x-magpie-subject"] = subject;
  headers["connection"] = "close";
  let payload;
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    payload = JSON.stringify(body);
  }
  return fetchJson(`${app.base}${route}`, { method, headers, body: payload });
}

test("config endpoint returns models, MCP servers and provider options", async () => {
  const root = tempDirectory();
  const app = await startApp(root);
  try {
    const { status, body } = await portalRequest(app, "/api/v1/portal/config", { subject: "user-alice" });
    assert.equal(status, 200);
    assert.equal(body.subjectId, "user-alice");
    assert.ok(Array.isArray(body.models));
    assert.ok(Array.isArray(body.mcpServers));
    assert.ok(Array.isArray(body.providerOptions));
    assert.ok(body.providerOptions.some((p) => p.id === "builtin"));
    assert.ok(body.providerOptions.some((p) => p.id === "plugin"));
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("config apply stores agent configuration and returns it", async () => {
  const root = tempDirectory();
  const app = await startApp(root);
  try {
    const { status, body } = await portalRequest(app, "/api/v1/portal/config/apply", {
      method: "POST",
      subject: "user-alice",
      body: {
        providerId: "builtin",
        model: "gpt-4o",
        mcpServers: ["mcp_git", "mcp_docs"],
        env: { MAGPIE_TEMPERATURE: "0.7" },
      },
    });
    assert.equal(status, 201, JSON.stringify(body));
    assert.equal(body.ok, true);
    assert.equal(body.config.subjectId, "user-alice");
    assert.equal(body.config.provider, "builtin");
    assert.equal(body.config.model, "gpt-4o");
    assert.deepEqual(body.config.mcpServers, ["mcp_git", "mcp_docs"]);
    assert.deepEqual(body.config.env, { MAGPIE_TEMPERATURE: "0.7" });
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("usage personal returns per-period totals and entries", async () => {
  const root = tempDirectory();
  const app = await startApp(root);
  try {
    const today = new Date().toISOString().slice(0, 10);
    const month = today.slice(0, 7);
    await app.usageStore.mutate((data) => {
      data.usage = {
        u1: { subjectId: "user-alice", date: today, tokens: 1000, cost: 0.05, requests: 5 },
        u2: { subjectId: "user-alice", date: `${month}-15`, tokens: 2000, cost: 0.1, requests: 10 },
        u3: { subjectId: "user-bob", date: today, tokens: 500, cost: 0.02, requests: 2 },
      };
    });

    const { status: s1, body: b1 } = await portalRequest(app, `/api/v1/portal/usage/personal?period=day`, { subject: "user-alice" });
    assert.equal(s1, 200);
    assert.equal(b1.period, "day");
    assert.equal(b1.totals.tokens, 1000);
    assert.equal(b1.entries.length, 1);

    const { status: s2, body: b2 } = await portalRequest(app, `/api/v1/portal/usage/personal?period=month`, { subject: "user-alice" });
    assert.equal(s2, 200);
    assert.equal(b2.period, "month");
    assert.equal(b2.totals.tokens, 3000);
    assert.equal(b2.totals.cost, 0.15);
    assert.equal(b2.entries.length, 2);

    const { body: b3 } = await portalRequest(app, `/api/v1/portal/usage/personal?period=all`, { subject: "user-bob" });
    assert.equal(b3.totals.tokens, 500);
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("ticket lifecycle: create, list, get, and isolate by subject", async () => {
  const root = tempDirectory();
  const app = await startApp(root);
  try {
    const { status, body } = await portalRequest(app, "/api/v1/portal/tickets", {
      method: "POST",
      subject: "user-alice",
      body: {
        title: "MCP server not responding",
        description: "The git MCP server returns 500 on tools/list",
        priority: "high",
      },
    });
    assert.equal(status, 201, JSON.stringify(body));
    assert.match(body.ticket.id, /^tk_[a-z0-9]{16,64}$/);
    assert.equal(body.ticket.subjectId, "user-alice");
    assert.equal(body.ticket.status, "open");
    assert.equal(body.ticket.priority, "high");
    const ticketId = body.ticket.id;

    const { body: listBody } = await portalRequest(app, "/api/v1/portal/tickets", { subject: "user-alice" });
    assert.equal(listBody.tickets.length, 1);
    assert.equal(listBody.tickets[0].id, ticketId);

    const { status: g1 } = await portalRequest(app, `/api/v1/portal/tickets/${ticketId}`, { subject: "user-alice" });
    assert.equal(g1, 200);

    const { status: g2 } = await portalRequest(app, `/api/v1/portal/tickets/${ticketId}`, { subject: "user-bob" });
    assert.equal(g2, 403);

    const { status: nf } = await portalRequest(app, "/api/v1/portal/tickets/tk_nonexistent", { subject: "user-alice" });
    assert.equal(nf, 404);
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("validation rejects missing subject and invalid input", async () => {
  const root = tempDirectory();
  const app = await startApp(root);
  try {
    const { status } = await portalRequest(app, "/api/v1/portal/config", { subject: null });
    assert.equal(status, 400);

    const { status: s2 } = await portalRequest(app, "/api/v1/portal/config/apply", {
      method: "POST",
      subject: "user-alice",
      body: { providerId: "builtin", model: "" },
    });
    assert.equal(s2, 400);

    const { status: s3 } = await portalRequest(app, "/api/v1/portal/usage/personal?period=year", { subject: "user-alice" });
    assert.equal(s3, 400);
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("healthz returns service info", async () => {
  const root = tempDirectory();
  const app = await startApp(root);
  try {
    const { status, body } = await fetchJson(`${app.base}/healthz`);
    assert.equal(status, 200);
    assert.equal(body.service, "employee-portal");
    assert.equal(body.version, "0.1.0");
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});
