import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { ContentRetrieval, ContentRetrievalError } from "../src/content-retrieval.js";
import { ContentStore } from "../src/content-store.js";

const KEY = Buffer.alloc(32, 0x4c);
const CURSOR_SECRET = ["content", "retrieval", "cursor", "test", "secret", "0123456789"].join("-");
const REDACTION = {
  ruleVersion: "m4b-redaction-v1",
  replacements: 0,
  categories: {},
};
const BODIES = [
  "prompt body that must never appear in metadata",
  "failed prompt body that must never appear in metadata",
  "tool result body that must never appear in metadata",
  "response body that must never appear in metadata",
  "tool arguments body that must never appear in metadata",
  "failed tool result body that must never appear in metadata",
];

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-content-retrieval-"));
}

function request(overrides = {}) {
  return {
    schemaVersion: 1,
    requestId: "req_content_filter_0001",
    sessionId: "ses_content_filter_0001",
    userId: "usr_alice",
    departmentId: "dept_engineering",
    deviceId: "dev_workstation_01",
    agentId: "codex",
    modelId: "openai/gpt-5.1",
    mcpServerId: "mcp_filesystem",
    toolName: "shell.exec",
    contentKind: "prompt",
    mediaType: "text/plain",
    auditLevel: "L2",
    collection: {
      purpose: "security_investigation",
      authorizationId: "apr_content_filter_0001",
      confirmed: true,
      retentionDays: 7,
    },
    ...overrides,
  };
}

function errorIs(statusCode, code) {
  return (error) => error instanceof ContentRetrievalError
    && error.statusCode === statusCode
    && error.code === code;
}

function ordered(items) {
  return items
    .slice()
    .sort((left, right) => {
      if (left.createdAt !== right.createdAt) {
        return left.createdAt < right.createdAt ? 1 : -1;
      }
      if (left.streamId === right.streamId) return 0;
      return left.streamId < right.streamId ? 1 : -1;
    })
    .map((item) => item.streamId);
}

async function fixture() {
  let now = Date.parse("2026-11-02T10:00:00.000Z");
  const store = new ContentStore({
    directory: tempDirectory(),
    key: KEY,
    maxStreamBytes: 4096,
    now: () => now,
  });
  await store.load();
  const streams = {};

  async function add(id, at, overrides, status = "finalized", bodyIndex = 0) {
    now = Date.parse(at);
    const value = request({
      requestId: `req_content_filter_${id}`,
      sessionId: `ses_content_filter_${id}`,
      ...overrides,
    });
    for (const [key, field] of Object.entries(value)) {
      if (field === undefined) delete value[key];
    }
    const created = await store.createStream(
      value,
      `create-content-filter-${id}`,
    );
    const streamId = created.stream.streamId;
    if (status === "finalized") {
      await store.finalizeStream(streamId, BODIES[bodyIndex], REDACTION);
    } else {
      await store.failStream(streamId, "content_stream_empty");
    }
    streams[id] = {
      streamId,
      createdAt: created.stream.createdAt,
      status,
    };
  }

  await add("a", "2026-11-02T10:00:00.000Z", {}, "finalized", 0);
  await add("b", "2026-11-02T10:01:00.000Z", {
    userId: "usr_bob",
    departmentId: "dept_finance",
    deviceId: "dev_workstation_02",
    agentId: "claude",
    modelId: "anthropic/claude-3-7-sonnet",
    mcpServerId: undefined,
    toolName: undefined,
  }, "failed", 1);
  await add("c", "2026-11-02T10:02:00.000Z", {
    departmentId: "dept_finance",
    mcpServerId: "mcp_database",
    toolName: "db.query",
    contentKind: "tool_result",
  }, "finalized", 2);
  await add("d", "2026-11-02T10:03:00.000Z", {
    deviceId: "dev_workstation_03",
    agentId: "opencode",
    mcpServerId: undefined,
    toolName: undefined,
    contentKind: "response",
  }, "finalized", 3);
  await add("e", "2026-11-02T10:03:00.000Z", {
    userId: "usr_bob",
    contentKind: "tool_arguments",
    mcpServerId: "mcp_filesystem",
    toolName: "shell.exec",
  }, "finalized", 4);
  await add("f", "2026-11-02T10:04:00.000Z", {
    userId: "usr_carol",
    contentKind: "tool_result",
    mcpServerId: "mcp_filesystem",
    toolName: "shell.exec",
  }, "failed", 5);

  return {
    store,
    streams,
    retrieval: new ContentRetrieval(store, { cursorSecret: CURSOR_SECRET }),
  };
}

async function list(retrieval, query = "") {
  return retrieval.list(new URL(`http://localhost/api/v1/admin/audit/content/streams${query}`));
}

function ids(result) {
  return result.streams.map((stream) => stream.streamId);
}

test("content metadata filters across every supported dimension with inclusive time bounds", async () => {
  const { retrieval, streams } = await fixture();
  const cases = [
    ["?userId=usr_alice", ordered([streams.a, streams.c, streams.d])],
    ["?departmentId=dept_finance", ordered([streams.b, streams.c])],
    ["?deviceId=dev_workstation_01", ordered([streams.a, streams.c, streams.e, streams.f])],
    ["?agentId=codex", ordered([streams.a, streams.c, streams.e, streams.f])],
    ["?modelId=openai%2Fgpt-5.1", ordered([streams.a, streams.c, streams.d, streams.e, streams.f])],
    ["?mcpServerId=mcp_filesystem", ordered([streams.a, streams.e, streams.f])],
    ["?toolName=shell.exec", ordered([streams.a, streams.e, streams.f])],
    ["?contentKind=tool_result", ordered([streams.c, streams.f])],
    ["?status=failed", ordered([streams.b, streams.f])],
    [
      "?from=2026-11-02T10:02:00.000Z&to=2026-11-02T10:03:00.000Z",
      ordered([streams.c, streams.d, streams.e]),
    ],
  ];

  for (const [query, expected] of cases) {
    const result = await list(retrieval, query);
    assert.deepEqual(ids(result), expected, query);
    assert.equal(result.nextCursor, null, query);
  }

  const empty = await list(retrieval, "?userId=usr_missing");
  assert.deepEqual(empty, { streams: [], nextCursor: null });
});

test("content pagination is stable and cursors are bound to filters", async () => {
  const { retrieval, streams } = await fixture();
  const all = ordered(Object.values(streams));
  const first = await list(retrieval, "?limit=2");
  assert.deepEqual(ids(first), all.slice(0, 2));
  assert.ok(first.nextCursor);

  const second = await list(
    retrieval,
    `?limit=2&cursor=${encodeURIComponent(first.nextCursor)}`,
  );
  assert.deepEqual(ids(second), all.slice(2, 4));
  assert.ok(second.nextCursor);

  const third = await list(
    retrieval,
    `?limit=2&cursor=${encodeURIComponent(second.nextCursor)}`,
  );
  assert.deepEqual(ids(third), all.slice(4, 6));
  assert.equal(third.nextCursor, null);

  const sameTime = ordered([streams.d, streams.e]);
  const page = await list(
    retrieval,
    "?from=2026-11-02T10:03:00.000Z&to=2026-11-02T10:03:00.000Z&limit=1",
  );
  assert.deepEqual(ids(page), sameTime.slice(0, 1));
  const next = await list(
    retrieval,
    `?from=2026-11-02T10:03:00.000Z&to=2026-11-02T10:03:00.000Z&limit=1&cursor=${encodeURIComponent(page.nextCursor)}`,
  );
  assert.deepEqual(ids(next), sameTime.slice(1));
  assert.equal(next.nextCursor, null);

  await assert.rejects(
    list(retrieval, `?userId=usr_bob&cursor=${encodeURIComponent(first.nextCursor)}`),
    errorIs(400, "invalid_cursor"),
  );
});

test("content cursors reject tampering, duplicate filters and unsupported queries", async () => {
  const { retrieval } = await fixture();
  const first = await list(retrieval, "?limit=1");
  const cursor = first.nextCursor;
  const tampered = `${cursor.slice(0, -1)}${cursor.endsWith("A") ? "B" : "A"}`;
  await assert.rejects(
    list(retrieval, `?cursor=${encodeURIComponent(tampered)}`),
    errorIs(400, "invalid_cursor"),
  );
  await assert.rejects(
    list(retrieval, "?cursor=not-a-cursor"),
    errorIs(400, "invalid_cursor"),
  );
  await assert.rejects(
    list(retrieval, "?userId=usr_alice&userId=usr_bob"),
    errorIs(400, "invalid_query"),
  );
  await assert.rejects(
    list(retrieval, "?unknown=value"),
    errorIs(400, "invalid_query"),
  );
  await assert.rejects(
    list(retrieval, "?limit=0"),
    errorIs(400, "invalid_query"),
  );
  await assert.rejects(
    list(retrieval, "?contentKind=secret"),
    errorIs(400, "invalid_query"),
  );
  await assert.rejects(
    list(
      retrieval,
      "?from=2026-11-02T10:04:00.000Z&to=2026-11-02T10:03:00.000Z",
    ),
    errorIs(400, "invalid_query"),
  );
});

test("content metadata never exposes bodies, object paths or secrets", async () => {
  const { retrieval, streams } = await fixture();
  const result = await list(retrieval, "?limit=200");
  assert.deepEqual(ids(result), ordered(Object.values(streams)));
  assert.equal(result.streams.length, BODIES.length);
  const serialized = JSON.stringify(result);
  for (const body of BODIES) {
    assert.equal(serialized.includes(body), false);
  }
  assert.equal(serialized.includes(".bin"), false);
  assert.equal(serialized.includes("objects/"), false);
  assert.equal(serialized.includes(CURSOR_SECRET), false);
  for (const stream of result.streams) {
    assert.equal(Object.hasOwn(stream, "content"), false);
    assert.equal(Object.hasOwn(stream, "chunks"), false);
  }
});

test("content retrieval rejects an unsafe cursor secret", () => {
  assert.throws(
    () => new ContentRetrieval({}, { cursorSecret: "too-short" }),
    /cursorSecret must be at least 32 characters/,
  );
});
