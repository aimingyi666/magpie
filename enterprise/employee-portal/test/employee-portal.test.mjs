import assert from "node:assert/strict";
import test from "node:test";
import { applyAgentConfig, getAgentConfig, listAgentConfigs } from "../src/agent-config.js";
import { JsonStore, generateId } from "../src/store.js";
import { createTicket, listTickets, getTicket } from "../src/tickets.js";
import { getPersonalUsage } from "../src/usage.js";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";

function tmpPath() {
  return path.join(os.tmpdir(), "portal-test-" + Date.now() + "-" + Math.random().toString(36).slice(2) + ".json");
}

async function freshStore() {
  const p = tmpPath();
  return { store: new JsonStore(p), path: p };
}

test("applyAgentConfig creates and persists config", async () => {
  const { store } = await freshStore();
  const config = {
    modelId: "gpt-4o",
    mcpServers: [{ name: "git-mcp", endpoint: "http://git-mcp.local" }],
    providers: [{ id: "openai", enabled: true }],
    envOverrides: { OPENAI_API_KEY: "sk-test" },
  };
  const applied = await applyAgentConfig(config, store, "usr_1", "eng");
  assert.equal(applied.userId, "usr_1");
  assert.equal(applied.orgUnit, "eng");
  assert.equal(applied.modelId, "gpt-4o");
  assert.equal(applied.mcpServers.length, 1);
  assert.equal(applied.providers.length, 1);
  const fetched = await getAgentConfig(store, "usr_1", "eng");
  assert.equal(fetched.id, applied.id);
  assert.equal(fetched.modelId, "gpt-4o");
});

test("applyAgentConfig upserts existing config", async () => {
  const { store } = await freshStore();
  const config1 = { modelId: "claude-3", providers: [], mcpServers: [], envOverrides: {} };
  const applied1 = await applyAgentConfig(config1, store, "usr_1", "eng");
  const config2 = { modelId: "gpt-4o", providers: [], mcpServers: [], envOverrides: {} };
  const applied2 = await applyAgentConfig(config2, store, "usr_1", "eng");
  assert.equal(applied2.id, applied1.id);
  assert.equal(applied2.modelId, "gpt-4o");
  const fetched = await getAgentConfig(store, "usr_1", "eng");
  assert.equal(fetched.modelId, "gpt-4o");
});

test("applyAgentConfig rejects missing modelId", async () => {
  const { store } = await freshStore();
  await assert.rejects(
    applyAgentConfig({ providers: [] }, store, "usr_1", "eng"),
    (err) => err.code === "agent_config_error" && err.statusCode === 400
  );
});

test("listAgentConfigs filters by orgUnit", async () => {
  const { store } = await freshStore();
  await applyAgentConfig({ modelId: "a" }, store, "usr_1", "eng");
  await applyAgentConfig({ modelId: "b" }, store, "usr_2", "sales");
  const eng = await listAgentConfigs(store, "eng");
  assert.equal(eng.length, 1);
  assert.equal(eng[0].modelId, "a");
  const all = await listAgentConfigs(store);
  assert.equal(all.length, 2);
});

test("getAgentConfig returns null when not found", async () => {
  const { store } = await freshStore();
  const result = await getAgentConfig(store, "usr_missing", "eng");
  assert.equal(result, null);
});

test("createTicket persists ticket", async () => {
  const { store } = await freshStore();
  const body = { title: "Bug report", description: "Something broke", type: "bug", priority: "high" };
  const ticket = await createTicket(body, store, "usr_1", "eng");
  assert.equal(ticket.title, "Bug report");
  assert.equal(ticket.status, "open");
  assert.equal(ticket.priority, "high");
  assert.equal(ticket.createdBy, "usr_1");
});

test("listTickets returns own tickets only", async () => {
  const { store } = await freshStore();
  await createTicket({ title: "T1", description: "d", type: "question", priority: "low" }, store, "usr_1", "eng");
  await createTicket({ title: "T2", description: "d", type: "question", priority: "low" }, store, "usr_2", "eng");
  const tickets = await listTickets(store, "usr_1");
  assert.equal(tickets.length, 1);
  assert.equal(tickets[0].title, "T1");
});

test("getTicket returns ticket for owner", async () => {
  const { store } = await freshStore();
  const t = await createTicket({ title: "T", description: "d", type: "other", priority: "medium" }, store, "usr_1", "eng");
  const fetched = await getTicket(store, t.id, "usr_1");
  assert.equal(fetched.id, t.id);
  assert.equal(await getTicket(store, t.id, "usr_2"), null);
});

test("createTicket rejects empty title", async () => {
  const { store } = await freshStore();
  await assert.rejects(
    createTicket({ title: "", description: "d", type: "question" }, store, "usr_1", "eng"),
    (err) => err.code === "invalid_title" && err.statusCode === 400
  );
});

test("createTicket rejects invalid type", async () => {
  const { store } = await freshStore();
  await assert.rejects(
    createTicket({ title: "T", description: "d", type: "invalid_type" }, store, "usr_1", "eng"),
    (err) => err.code === "invalid_type" && err.statusCode === 400
  );
});

test("listTickets supports type filter", async () => {
  const { store } = await freshStore();
  await createTicket({ title: "Bug1", description: "d", type: "bug", priority: "low" }, store, "usr_1", "eng");
  await createTicket({ title: "Quest1", description: "d", type: "question", priority: "low" }, store, "usr_1", "eng");
  const bugs = await listTickets(store, "usr_1", { type: "bug" });
  assert.equal(bugs.length, 1);
  assert.equal(bugs[0].title, "Bug1");
  const questions = await listTickets(store, "usr_1", { type: "question" });
  assert.equal(questions.length, 1);
});

test("getPersonalUsage summarizes today and month", async () => {
  const { store } = await freshStore();
  const now = new Date().toISOString();
  await store.mutate((data) => {
    data.usageLog.push({ userId: "usr_1", orgUnit: "eng", modelId: "gpt-4o", tokens: 100, costUsd: 0.5, timestamp: now });
  });
  const usage = await getPersonalUsage(store, "usr_1", "eng");
  assert.equal(usage.today.requests, 1);
  assert.equal(usage.today.tokens, 100);
  assert.equal(usage.today.costUsd, 0.5);
  assert.equal(usage.thisMonth.requests, 1);
});

test("getPersonalUsage excludes other users", async () => {
  const { store } = await freshStore();
  const now = new Date().toISOString();
  await store.mutate((data) => {
    data.usageLog.push({ userId: "usr_1", orgUnit: "eng", tokens: 100, costUsd: 0.5, timestamp: now });
    data.usageLog.push({ userId: "usr_2", orgUnit: "eng", tokens: 200, costUsd: 1.0, timestamp: now });
  });
  const usage = await getPersonalUsage(store, "usr_1", "eng");
  assert.equal(usage.today.requests, 1);
  assert.equal(usage.today.tokens, 100);
});

test("JsonStore atomically writes data", async () => {
  const { store, path: p } = await freshStore();
  await store.mutate((data) => {
    data.agents.push({ id: "agent_1", userId: "usr_1" });
  });
  const data = await store.read();
  assert.equal(data.agents.length, 1);
  assert.equal(data.agents[0].id, "agent_1");
  assert.ok(fs.existsSync(p));
await fsp.unlink(p);
});

test("JsonStore returns defaults when missing", async () => {
  const store = new JsonStore(path.join(os.tmpdir(), "portal-nonexistent-" + Date.now() + ".json"));
  const data = await store.read();
  assert.equal(data.version, 1);
  assert.deepEqual(data.agents, []);
});

test("generateId generates prefixed IDs", () => {
  const id1 = generateId("ticket");
  const id2 = generateId("ticket");
  assert.ok(id1.startsWith("ticket_"));
  assert.notEqual(id1, id2);
});
