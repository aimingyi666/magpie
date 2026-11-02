import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { validateContentStreamRequest } from "../src/content-schema.js";
import { ContentStore } from "../src/content-store.js";
import {
  ContentStreamError,
  ContentStreamManager,
} from "../src/content-streams.js";

const KEY = Buffer.alloc(32, 0x21);

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-content-streams-"));
}

function request(requestId = "req_m4b_stream_0001") {
  return validateContentStreamRequest({
    schemaVersion: 1,
    requestId,
    sessionId: "ses_m4b_stream_0001",
    userId: "usr_alice",
    departmentId: "dept_engineering",
    deviceId: "dev_workstation_01",
    agentId: "codex",
    contentKind: "prompt",
    mediaType: "text/plain",
    auditLevel: "L2",
    collection: {
      purpose: "security_investigation",
      authorizationId: "apr_m4b_stream_0001",
      confirmed: true,
      retentionDays: 7,
    },
  });
}

function chunk(sequence, text, final = false) {
  return {
    schemaVersion: 1,
    sequence,
    text,
    final,
  };
}

async function manager(options = {}) {
  const store = new ContentStore({
    directory: tempDirectory(),
    key: KEY,
    maxStreamBytes: options.maxStreamBytes ?? 4096,
    now: options.now,
  });
  await store.load();
  return {
    store,
    manager: new ContentStreamManager(store, {
      maxChunkBytes: 1024,
      maxStreamBytes: options.maxStreamBytes ?? 4096,
      maxTotalBufferBytes: 4096,
      maxActiveStreams: 4,
      streamTtlMs: 60_000,
      ...options,
    }),
  };
}

test("streams redact secrets spanning chunks only after complete assembly", async () => {
  const { store, manager: streams } = await manager();
  const created = await streams.create(request(), "create-stream-0001");
  await streams.append(
    created.stream.streamId,
    chunk(0, "contact alice@example.com and "),
    crypto.randomUUID(),
  );
  const result = await streams.append(
    created.stream.streamId,
    chunk(1, `token sk-${"z".repeat(24)}`, true),
    crypto.randomUUID(),
  );

  assert.equal(result.finalized, true);
  assert.equal(result.redaction.categories.email, 1);
  assert.equal(result.redaction.categories.api_key, 1);
  const read = await store.readObject(result.contentRef, {
    reason: "security investigation case 77",
    authorizationId: "apr_read_stream_0001",
    requestId: "req_read_stream_0001",
    sourceHash: `sha256:${"b".repeat(64)}`,
  });
  assert.equal(read.content.includes("alice@example.com"), false);
  assert.equal(read.content.includes("sk-"), false);
  assert.equal(read.content.includes("[REDACTED:email]"), true);
});

test("capacity, empty stream, size and buffer limits fail without an object", async () => {
  const capacity = await manager({ maxActiveStreams: 1 });
  const first = await capacity.manager.create(request(), "create-stream-0002");
  await assert.rejects(
    capacity.manager.create(
      request("req_m4b_stream_0002"),
      "create-stream-0003",
    ),
    (error) => error instanceof ContentStreamError
      && error.statusCode === 503
      && error.code === "content_stream_capacity",
  );
  assert.equal(
    (await capacity.store.getStream(first.stream.streamId)).status,
    "collecting",
  );

  const empty = await manager();
  const emptyStream = await empty.manager.create(request(), "create-stream-0004");
  await assert.rejects(
    empty.manager.append(
      emptyStream.stream.streamId,
      chunk(0, "", true),
      crypto.randomUUID(),
    ),
    (error) => error instanceof ContentStreamError
      && error.statusCode === 400
      && error.code === "content_stream_empty",
  );
  assert.equal(
    (await empty.store.getStream(emptyStream.stream.streamId)).status,
    "failed",
  );
  assert.equal((await empty.store.status()).objects, 0);

  const oversized = await manager({ maxStreamBytes: 4, maxChunkBytes: 8 });
  const oversizedStream = await oversized.manager.create(request(), "create-stream-0005");
  await assert.rejects(
    oversized.manager.append(
      oversizedStream.stream.streamId,
      chunk(0, "12345", false),
      crypto.randomUUID(),
    ),
    (error) => error.code === "content_stream_too_large",
  );

  const buffered = await manager({ maxTotalBufferBytes: 5, maxStreamBytes: 100 });
  const bufferedStream = await buffered.manager.create(request(), "create-stream-0006");
  await buffered.manager.append(
    bufferedStream.stream.streamId,
    chunk(0, "123", false),
    crypto.randomUUID(),
  );
  await assert.rejects(
    buffered.manager.append(
      bufferedStream.stream.streamId,
      chunk(1, "456", false),
      crypto.randomUUID(),
    ),
    (error) => error.code === "content_buffer_full",
  );
  assert.equal(
    (await buffered.store.getStream(bufferedStream.stream.streamId)).failureCode,
    "content_buffer_full",
  );
});

test("expired streams are marked failed by the manager timer path", async () => {
  let now = Date.parse("2026-11-02T00:00:00.000Z");
  const { store, manager: streams } = await manager({
    streamTtlMs: 100,
    now: () => now,
  });
  const created = await streams.create(request(), "create-stream-0007");
  now += 101;
  await streams.pruneExpired();
  const expired = await store.getStream(created.stream.streamId);
  assert.equal(expired.status, "failed");
  assert.equal(expired.failureCode, "content_stream_expired");
  assert.equal(streams.status().activeStreams, 0);
});
