import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { AuditPipeline } from "../src/pipeline.js";
import { createAuditServer } from "../src/service.js";
import { AuditStore } from "../src/store.js";

const SERVICE_TOKEN = ["audit", "service", "test", "token", "not", "real", "123456789"].join("-");
const PROMPT_TEXT = "employee prompt must never be persisted";
const SECRET_TEXT = `sk-${"a".repeat(24)}`;

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-audit-service-"));
}

function baseConfig(root, overrides = {}) {
  return {
    bind: "127.0.0.1",
    port: 0,
    serviceToken: SERVICE_TOKEN,
    storePath: path.join(root, "audit-store.json"),
    maxBodyBytes: 32 * 1024,
    maxEvents: 1000,
    maxQueueEvents: 100,
    maxSessions: 100,
    flushIntervalMs: 60_000,
    batchSize: 50,
    rateLimitPerMinute: 10_000,
    ...overrides,
  };
}

function auditEvent(overrides = {}) {
  return {
    schemaVersion: 1,
    eventId: `evt_${crypto.randomUUID()}`,
    requestId: `req_${crypto.randomUUID()}`,
    sessionId: `ses_${crypto.randomUUID()}`,
    eventKind: "request",
    auditLevel: "L0",
    occurredAt: "2026-11-01T08:00:00.000Z",
    userId: "user_alice",
    departmentId: "dept_engineering",
    deviceId: "device_workstation_01",
    agentId: "codex",
    clientVersion: "1.0.0",
    requestKind: "chat",
    status: "started",
    modelId: "openai/gpt-5.1",
    inputTokens: 12,
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

async function start(root, overrides = {}, options = {}) {
  const result = await createAuditServer(baseConfig(root, overrides), {
    startPipeline: false,
    logger: () => {},
    ...options,
  });
  const base = await listen(result.server);
  return { ...result, base };
}

async function request(base, route, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.token !== null) {
    headers.authorization = `Bearer ${options.token ?? SERVICE_TOKEN}`;
  }
  if (options.idempotency !== null) {
    headers["idempotency-key"] = options.idempotency ?? crypto.randomUUID();
  }
  let body;
  if (options.body !== undefined) {
    headers["content-type"] = options.contentType || "application/json";
    body = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
  }
  return fetch(`${base}${route}`, {
    method: options.method || (body === undefined ? "GET" : "POST"),
    headers,
    body,
  });
}

async function responseJson(response) {
  return JSON.parse(await response.text());
}

async function ingest(base, event, idempotency = crypto.randomUUID(), token = SERVICE_TOKEN) {
  const response = await request(base, "/api/v1/internal/audit/events", {
    token,
    idempotency,
    body: event,
  });
  return { response, body: await responseJson(response) };
}

function noOpPipeline(store) {
  return {
    start() {},
    stop() {},
    async drainSafely() {
      return true;
    },
    async drainAll() {
      return { committed: 0, queued: 0 };
    },
    async status() {
      return {
        queueDepth: await store.read((data) => Object.keys(data.queue).length),
        oldestQueuedAt: null,
        committedCount: await store.read((data) => Object.keys(data.events).length),
        sessionCount: await store.read((data) => Object.keys(data.sessions).length),
        stats: {},
        consecutiveFailures: 0,
        lastFailure: null,
        lastSuccessAt: null,
      };
    },
  };
}

test("healthz is public while ingest and admin routes require the service token", async () => {
  const app = await start(tempDirectory());
  try {
    const health = await request(app.base, "/healthz", { token: null, idempotency: null });
    assert.equal(health.status, 200);
    assert.equal((await responseJson(health)).status, "ready");

    for (const [route, token] of [
      ["/api/v1/internal/audit/events", null],
      ["/api/v1/internal/audit/events", ["wrong", "token"].join("-")],
      ["/api/v1/admin/audit/events", null],
      ["/api/v1/admin/audit/sessions", ["wrong", "token"].join("-")],
      ["/api/v1/admin/audit/stats", null],
    ]) {
      const response = await request(app.base, route, {
        token,
        idempotency: null,
        body: route.includes("/internal/") ? auditEvent() : undefined,
      });
      assert.equal(response.status, 401);
      assert.equal((await responseJson(response)).error.code, "unauthorized");
    }
  } finally {
    await app.close();
  }
});

test("valid L0 events commit into request and session indexes", async () => {
  const app = await start(tempDirectory());
  const event = auditEvent({
    eventId: "evt_l0_lifecycle_0001",
    requestId: "req_l0_lifecycle_0001",
    sessionId: "ses_l0_lifecycle_0001",
    occurredAt: "2026-11-01T08:00:00.000Z",
  });
  try {
    const result = await ingest(app.base, event);
    assert.equal(result.response.status, 202);
    assert.equal(result.body.ok, true);
    assert.equal(result.body.duplicate, false);
    assert.equal(result.body.status, "queued");

    await app.pipeline.drainAll();

    const events = await request(app.base, `/api/v1/admin/audit/events?requestId=${event.requestId}`);
    const eventBody = await responseJson(events);
    assert.equal(events.status, 200);
    assert.equal(eventBody.events.length, 1);
    assert.deepEqual(eventBody.events[0], event);

    const sessions = await request(app.base, `/api/v1/admin/audit/sessions?departmentId=${event.departmentId}`);
    const sessionBody = await responseJson(sessions);
    assert.equal(sessionBody.sessions.length, 1);
    assert.equal(sessionBody.sessions[0].sessionId, event.sessionId);
    assert.equal(sessionBody.sessions[0].eventCount, 1);
    assert.deepEqual(sessionBody.sessions[0].requestIds, [event.requestId]);

    const detail = await request(app.base, `/api/v1/admin/audit/sessions/${event.sessionId}`);
    const detailBody = await responseJson(detail);
    assert.equal(detail.status, 200);
    assert.equal(detailBody.session.sessionId, event.sessionId);
    assert.equal(detailBody.events.length, 1);
    assert.equal(detailBody.events[0].eventId, event.eventId);
  } finally {
    await app.close();
  }
});

test("L1 tool and policy summary events are searchable without body fields", async () => {
  const app = await start(tempDirectory());
  const sessionId = "ses_l1_tool_policy_0001";
  const toolEvent = auditEvent({
    eventId: "evt_l1_tool_call_0001",
    requestId: "req_l1_tool_call_0001",
    sessionId,
    eventKind: "tool_call",
    auditLevel: "L1",
    requestKind: "mcp",
    status: "success",
    mcpServerId: "mcp_search",
    toolName: "search.web",
    parameterCategories: ["query", "scope"],
    latencyMs: 42,
  });
  const policyEvent = auditEvent({
    eventId: "evt_l1_policy_decision_0001",
    requestId: "req_l1_policy_decision_0001",
    sessionId,
    eventKind: "policy_decision",
    auditLevel: "L1",
    requestKind: "mcp",
    status: "blocked",
    policyHits: ["mcp.private_data", "resident.retention"],
    errorCode: "policy_denied",
  });
  try {
    assert.equal((await ingest(app.base, toolEvent)).response.status, 202);
    assert.equal((await ingest(app.base, policyEvent)).response.status, 202);
    await app.pipeline.drainAll();

    const byTool = await request(app.base, "/api/v1/admin/audit/events?toolName=search.web");
    const toolBody = await responseJson(byTool);
    assert.equal(toolBody.events.length, 1);
    assert.deepEqual(toolBody.events[0].parameterCategories, ["query", "scope"]);
    assert.equal(Object.hasOwn(toolBody.events[0], "prompt"), false);

    const bySession = await request(app.base, `/api/v1/admin/audit/sessions/${sessionId}`);
    const sessionBody = await responseJson(bySession);
    assert.equal(sessionBody.session.eventCount, 2);
    assert.deepEqual(sessionBody.session.toolNames, ["search.web"]);
    assert.equal(sessionBody.events.length, 2);
  } finally {
    await app.close();
  }
});

test("mandatory IDs and idempotency key fail closed", async () => {
  const app = await start(tempDirectory());
  try {
    for (const field of ["eventId", "requestId", "sessionId"]) {
      const event = auditEvent();
      delete event[field];
      const result = await ingest(app.base, event);
      assert.equal(result.response.status, 400);
      assert.equal(result.body.error.code, "invalid_audit_event");
    }

    const missingKey = await request(app.base, "/api/v1/internal/audit/events", {
      idempotency: null,
      body: auditEvent(),
    });
    assert.equal(missingKey.status, 400);
    assert.equal((await responseJson(missingKey)).error.code, "idempotency_key_required");
  } finally {
    await app.close();
  }
});

test("unknown and body-like fields are rejected before persistence", async () => {
  const app = await start(tempDirectory());
  try {
    for (const injected of [
      { prompt: PROMPT_TEXT },
      { response: "assistant output must not be accepted at L0" },
      { content: "attachment content" },
      { message: "unexpected metadata" },
    ]) {
      const result = await ingest(app.base, auditEvent(injected));
      assert.equal(result.response.status, 400);
      assert.equal(result.body.error.code, "invalid_audit_event");
      assert.equal(JSON.stringify(result.body).includes(PROMPT_TEXT), false);
    }
  } finally {
    await app.close();
  }
});

test("secret patterns, malformed timestamps and invalid summary shapes fail closed", async () => {
  const app = await start(tempDirectory());
  try {
    const secret = await ingest(app.base, auditEvent({ errorCode: SECRET_TEXT }));
    assert.equal(secret.response.status, 400);
    assert.equal(secret.body.error.code, "audit_secret_detected");

    const timestamp = await ingest(app.base, auditEvent({ occurredAt: "2026-11-01T08:00:00Z" }));
    assert.equal(timestamp.response.status, 400);
    assert.equal(timestamp.body.error.code, "invalid_audit_event");

    const responseStarted = await ingest(app.base, auditEvent({
      eventKind: "response",
      status: "started",
    }));
    assert.equal(responseStarted.response.status, 400);

    const l0Tool = await ingest(app.base, auditEvent({
      toolName: "search.web",
      parameterCategories: ["query"],
    }));
    assert.equal(l0Tool.response.status, 400);
  } finally {
    await app.close();
  }
});

test("tool_call events require L1 MCP metadata and terminal status", async () => {
  const app = await start(tempDirectory());
  try {
    const invalidToolEvents = [
      auditEvent({
        eventKind: "tool_call",
        auditLevel: "L0",
        requestKind: "mcp",
        status: "success",
        toolName: "search.web",
        parameterCategories: ["query"],
      }),
      auditEvent({
        eventKind: "tool_call",
        auditLevel: "L1",
        requestKind: "chat",
        status: "success",
        toolName: "search.web",
        parameterCategories: ["query"],
      }),
      auditEvent({
        eventKind: "tool_call",
        auditLevel: "L1",
        requestKind: "mcp",
        status: "success",
        parameterCategories: ["query"],
      }),
      auditEvent({
        eventKind: "tool_call",
        auditLevel: "L1",
        requestKind: "mcp",
        status: "started",
        toolName: "search.web",
        parameterCategories: ["query"],
      }),
    ];
    for (const event of invalidToolEvents) {
      const result = await ingest(app.base, event);
      assert.equal(result.response.status, 400);
      assert.equal(result.body.error.code, "invalid_audit_event");
    }
  } finally {
    await app.close();
  }
});

test("idempotent replay, same-key conflicts and duplicate event IDs are separated", async () => {
  const app = await start(tempDirectory());
  const key = crypto.randomUUID();
  const event = auditEvent({ eventId: "evt_idempotent_replay_0001" });
  try {
    const first = await ingest(app.base, event, key);
    assert.equal(first.response.status, 202);
    assert.equal(first.body.duplicate, false);

    const replay = await ingest(app.base, event, key);
    assert.equal(replay.response.status, 200);
    assert.equal(replay.body.duplicate, true);
    assert.equal(replay.body.eventId, event.eventId);

    const sameKeyDifferentBody = await ingest(app.base, {
      ...event,
      occurredAt: "2026-11-01T08:00:01.000Z",
    }, key);
    assert.equal(sameKeyDifferentBody.response.status, 409);
    assert.equal(sameKeyDifferentBody.body.error.code, "idempotency_conflict");

    const duplicateEvent = await ingest(app.base, event, crypto.randomUUID());
    assert.equal(duplicateEvent.response.status, 409);
    assert.equal(duplicateEvent.body.error.code, "event_id_conflict");

    await app.pipeline.drainAll();
    const events = await request(app.base, `/api/v1/admin/audit/events?requestId=${event.requestId}`);
    const body = await responseJson(events);
    assert.equal(body.events.length, 1);
  } finally {
    await app.close();
  }
});

test("ordered cursor pagination, filters and missing-session errors are stable", async () => {
  const app = await start(tempDirectory());
  const sessionId = "ses_cursor_query_0001";
  const requestIds = [
    "req_cursor_query_0001",
    "req_cursor_query_0002",
    "req_cursor_query_0003",
    "req_cursor_query_0004",
  ];
  const times = [
    "2026-11-01T08:00:00.000Z",
    "2026-11-01T09:00:00.000Z",
    "2026-11-01T10:00:00.000Z",
    "2026-11-01T11:00:00.000Z",
  ];
  try {
    for (let index = 0; index < 4; index += 1) {
      const result = await ingest(app.base, auditEvent({
        eventId: `evt_cursor_query_000${index + 1}`,
        requestId: requestIds[index],
        sessionId,
        occurredAt: times[index],
        status: index === 1 ? "error" : "started",
      }));
      assert.equal(result.response.status, 202);
    }
    await app.pipeline.drainAll();

    const firstPageResponse = await request(app.base, "/api/v1/admin/audit/events?limit=2");
    const firstPage = await responseJson(firstPageResponse);
    assert.deepEqual(firstPage.events.map((event) => event.eventId), [
      "evt_cursor_query_0004",
      "evt_cursor_query_0003",
    ]);
    assert.ok(firstPage.nextCursor);

    const secondPageResponse = await request(
      app.base,
      `/api/v1/admin/audit/events?limit=2&cursor=${encodeURIComponent(firstPage.nextCursor)}`,
    );
    const secondPage = await responseJson(secondPageResponse);
    assert.deepEqual(secondPage.events.map((event) => event.eventId), [
      "evt_cursor_query_0002",
      "evt_cursor_query_0001",
    ]);
    assert.equal(secondPage.nextCursor, null);

    const filtered = await responseJson(await request(
      app.base,
      `/api/v1/admin/audit/events?requestId=${requestIds[1]}&status=error`,
    ));
    assert.equal(filtered.events.length, 1);
    assert.equal(filtered.events[0].eventId, "evt_cursor_query_0002");

    const missingSession = await request(
      app.base,
      "/api/v1/admin/audit/sessions/ses_does_not_exist_0001",
    );
    assert.equal(missingSession.status, 404);
    assert.equal((await responseJson(missingSession)).error.code, "audit_session_not_found");

    const badCursor = await request(app.base, "/api/v1/admin/audit/events?cursor=not-a-cursor");
    assert.equal(badCursor.status, 400);
    assert.equal((await responseJson(badCursor)).error.code, "invalid_cursor");

    const badRange = await request(
      app.base,
      "/api/v1/admin/audit/events?from=2026-11-02T00:00:00.000Z&to=2026-11-01T00:00:00.000Z",
    );
    assert.equal(badRange.status, 400);
    assert.equal((await responseJson(badRange)).error.code, "invalid_query");
  } finally {
    await app.close();
  }
});

test("concurrent enqueue mutations are serialized and committed in batches", async () => {
  const root = tempDirectory();
  const store = new AuditStore(path.join(root, "audit-store.json"), {
    maxEvents: 100,
    maxQueueEvents: 100,
    maxSessions: 10,
  });
  await store.load();

  const sessionId = "ses_concurrent_store_0001";
  const accepted = await Promise.all(Array.from({ length: 25 }, (_, index) => store.enqueue(
    auditEvent({
      eventId: `evt_concurrent_store_${String(index).padStart(4, "0")}`,
      requestId: `req_concurrent_store_${String(index).padStart(4, "0")}`,
      sessionId,
      occurredAt: `2026-11-01T08:00:${String(index).padStart(2, "0")}.000Z`,
    }),
    crypto.randomUUID(),
  )));
  assert.equal(accepted.every((result) => result.duplicate === false), true);
  assert.equal(await store.read((data) => Object.keys(data.queue).length), 25);

  assert.deepEqual(await store.commitQueued(10), { committed: 10, queued: 15 });
  assert.deepEqual(await store.commitQueued(100), { committed: 15, queued: 0 });
  const snapshot = await store.read((data) => ({
    events: Object.keys(data.events).length,
    sessions: Object.keys(data.sessions).length,
    eventCount: data.sessions[sessionId].eventCount,
  }));
  assert.deepEqual(snapshot, { events: 25, sessions: 1, eventCount: 25 });
});

test("a full queue rejects ingestion with a retryable 503", async () => {
  const root = tempDirectory();
  const store = new AuditStore(path.join(root, "audit-store.json"), {
    maxEvents: 10,
    maxQueueEvents: 1,
    maxSessions: 10,
  });
  await store.load();
  const app = await start(root, { maxQueueEvents: 1 }, {
    store,
    pipeline: noOpPipeline(store),
  });
  try {
    const first = await ingest(app.base, auditEvent());
    assert.equal(first.response.status, 202);

    const second = await ingest(app.base, auditEvent());
    assert.equal(second.response.status, 503);
    assert.equal(second.body.error.code, "audit_queue_full");
    assert.equal(second.body.error.retryable, true);
    assert.equal(await store.read((data) => Object.keys(data.queue).length), 1);
  } finally {
    await app.close();
  }
});

test("a transient writer failure leaves memory unchanged and a later write recovers", async () => {
  const root = tempDirectory();
  const store = new AuditStore(path.join(root, "audit-store.json"), {
    maxEvents: 10,
    maxQueueEvents: 10,
    maxSessions: 10,
  });
  await store.load();
  const atomicWriter = store.writer;
  let failNext = true;
  store.writer = async (file, value) => {
    if (failNext) {
      failNext = false;
      throw Object.assign(new Error("simulated disk full"), { code: "ENOSPC" });
    }
    return atomicWriter(file, value);
  };

  const event = auditEvent({ eventId: "evt_writer_recovery_0001" });
  const key = crypto.randomUUID();
  await assert.rejects(store.enqueue(event, key), /simulated disk full/);
  assert.equal(await store.read((data) => Object.keys(data.queue).length), 0);
  assert.equal(await store.read((data) => Object.keys(data.idempotency).length), 0);

  const recovered = await store.enqueue(event, key);
  assert.equal(recovered.duplicate, false);
  assert.equal(await store.read((data) => Object.keys(data.queue).length), 1);
});

test("queued events and idempotency proofs survive restart", async () => {
  const root = tempDirectory();
  const file = path.join(root, "audit-store.json");
  const event = auditEvent({
    eventId: "evt_restart_queued_0001",
    requestId: "req_restart_queued_0001",
    sessionId: "ses_restart_queued_0001",
  });
  const key = crypto.randomUUID();
  const first = new AuditStore(file, { maxEvents: 10, maxQueueEvents: 10, maxSessions: 10 });
  await first.load();
  await first.enqueue(event, key);

  const second = new AuditStore(file, { maxEvents: 10, maxQueueEvents: 10, maxSessions: 10 });
  await second.load();
  assert.equal(await second.read((data) => Object.keys(data.queue).length), 1);
  const replay = await second.enqueue(event, key);
  assert.equal(replay.duplicate, true);
  await new AuditPipeline(second, { batchSize: 10 }).drainAll();

  const third = new AuditStore(file, { maxEvents: 10, maxQueueEvents: 10, maxSessions: 10 });
  await third.load();
  const snapshot = await third.read((data) => ({
    events: Object.keys(data.events).length,
    queue: Object.keys(data.queue).length,
    sessions: data.sessions[event.sessionId].eventCount,
    idempotencyStatus: Object.values(data.idempotency)[0].status,
  }));
  assert.deepEqual(snapshot, {
    events: 1,
    queue: 0,
    sessions: 1,
    idempotencyStatus: "committed",
  });
});

test("startup rejects corrupted schemas and cross-index inconsistencies", async () => {
  const root = tempDirectory();
  const source = path.join(root, "source.json");
  const event = auditEvent({
    eventId: "evt_corrupt_fixture_0001",
    requestId: "req_corrupt_fixture_0001",
    sessionId: "ses_corrupt_fixture_0001",
  });
  const sourceStore = new AuditStore(source, { maxEvents: 10, maxQueueEvents: 10, maxSessions: 10 });
  await sourceStore.load();
  await sourceStore.enqueue(event, crypto.randomUUID());
  const fixture = JSON.parse(fs.readFileSync(source, "utf8"));

  const sessionFixture = {
    sessionId: event.sessionId,
    firstOccurredAt: event.occurredAt,
    lastOccurredAt: event.occurredAt,
    eventCount: 1,
    requestIds: [event.requestId],
    userIds: [event.userId],
    departmentIds: [event.departmentId],
    deviceIds: [event.deviceId],
    agentIds: [event.agentId],
    modelIds: [event.modelId],
    toolNames: [],
    truncated: false,
  };
  const cases = [
    {
      name: "unsupported schema",
      mutate: (data) => { data.version = 99; },
      error: /unsupported/,
    },
    {
      name: "unknown root field",
      mutate: (data) => { data.unexpected = true; },
      error: /unknown fields/,
    },
    {
      name: "invalid stats",
      mutate: (data) => { data.stats.accepted = -1; },
      error: /stats are invalid/,
    },
    {
      name: "invalid queued event",
      mutate: (data) => {
        data.queue[event.eventId].event.eventKind = "response";
        data.queue[event.eventId].event.status = "started";
      },
      error: /invalid event/,
    },
    {
      name: "bad queue fingerprint",
      mutate: (data) => { data.queue[event.eventId].fingerprint = "0".repeat(64); },
      error: /invalid fingerprint/,
    },
    {
      name: "missing idempotency proof",
      mutate: (data) => { data.idempotency = {}; },
      error: /no idempotency record/,
    },
    {
      name: "queue-event overlap",
      mutate: (data) => {
        data.events[event.eventId] = structuredClone(data.queue[event.eventId].event);
      },
      error: /both queued and committed/,
    },
    {
      name: "session mismatch",
      mutate: (data) => {
        data.sessions[event.sessionId] = sessionFixture;
      },
      error: /sessions do not match/,
    },
    {
      name: "idempotency status mismatch",
      mutate: (data) => {
        Object.values(data.idempotency)[0].status = "committed";
      },
      error: /idempotency record does not match/,
    },
  ];

  for (const [index, item] of cases.entries()) {
    const target = path.join(root, `corrupt-${index}.json`);
    const data = structuredClone(fixture);
    item.mutate(data);
    fs.writeFileSync(target, JSON.stringify(data));
    await assert.rejects(
      new AuditStore(target, { maxEvents: 10, maxQueueEvents: 10, maxSessions: 10 }).load(),
      item.error,
      item.name,
    );
  }
});

test("responses, logs and persistent JSON never contain the service token or prompt text", async () => {
  const root = tempDirectory();
  const logs = [];
  const app = await start(root, {}, { logger: (entry) => logs.push(entry) });
  try {
    const rejected = await ingest(app.base, auditEvent({ prompt: PROMPT_TEXT }));
    assert.equal(rejected.response.status, 400);
    const rejectedText = JSON.stringify(rejected.body);
    assert.equal(rejectedText.includes(PROMPT_TEXT), false);
    assert.equal(rejectedText.includes(SERVICE_TOKEN), false);

    const secret = await ingest(app.base, auditEvent({ errorCode: SECRET_TEXT }));
    assert.equal(secret.response.status, 400);
    assert.equal(JSON.stringify(secret.body).includes(SECRET_TEXT), false);

    const accepted = await ingest(app.base, auditEvent({
      eventId: "evt_no_secret_persistence_0001",
      requestId: "req_no_secret_persistence_0001",
      sessionId: "ses_no_secret_persistence_0001",
    }));
    assert.equal(accepted.response.status, 202);
    assert.equal(JSON.stringify(accepted.body).includes(SERVICE_TOKEN), false);
    await app.pipeline.drainAll();

    const persisted = fs.readFileSync(path.join(root, "audit-store.json"), "utf8");
    assert.equal(persisted.includes(SERVICE_TOKEN), false);
    assert.equal(persisted.includes(PROMPT_TEXT), false);
    assert.equal(persisted.includes(SECRET_TEXT), false);
    assert.equal(JSON.stringify(logs).includes(SERVICE_TOKEN), false);
    assert.equal(JSON.stringify(logs).includes(PROMPT_TEXT), false);
  } finally {
    await app.close();
  }
});
