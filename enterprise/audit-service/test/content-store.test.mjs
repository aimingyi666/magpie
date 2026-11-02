import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  contentChunkFingerprint,
  validateContentChunk,
  validateContentStreamRequest,
} from "../src/content-schema.js";
import { ContentStore, ContentStoreError } from "../src/content-store.js";

const KEY = Buffer.alloc(32, 0x4d);
const EMPTY_REDACTION = {
  ruleVersion: "m4b-redaction-v1",
  replacements: 0,
  categories: {},
};

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-content-store-"));
}

function request(overrides = {}) {
  return validateContentStreamRequest({
    schemaVersion: 1,
    requestId: "req_m4b_store_0001",
    sessionId: "ses_m4b_store_0001",
    userId: "usr_alice",
    departmentId: "dept_engineering",
    deviceId: "dev_workstation_01",
    agentId: "codex",
    modelId: "openai/gpt-5.1",
    contentKind: "prompt",
    mediaType: "text/plain",
    auditLevel: "L2",
    collection: {
      purpose: "security_investigation",
      authorizationId: "apr_m4b_store_0001",
      confirmed: true,
      retentionDays: 7,
    },
    ...overrides,
  });
}

function accessContext(overrides = {}) {
  return {
    reason: "security investigation case 42",
    authorizationId: "apr_read_store_0001",
    requestId: "req_read_store_0001",
    sourceHash: `sha256:${"a".repeat(64)}`,
    ...overrides,
  };
}

async function openStore(directory, options = {}) {
  const store = new ContentStore({
    directory,
    key: KEY,
    maxStreamBytes: 4096,
    ...options,
  });
  await store.load();
  return store;
}

async function accept(store, streamId, sequence, text, final, key = crypto.randomUUID()) {
  const chunk = validateContentChunk({
    schemaVersion: 1,
    sequence,
    text,
    final,
  });
  return store.acceptChunk(
    streamId,
    sequence,
    contentChunkFingerprint(chunk),
    key,
    Buffer.byteLength(text, "utf8"),
  );
}

test("finalized objects are encrypted, randomly referenced and recover after restart", async () => {
  const directory = tempDirectory();
  const store = await openStore(directory);
  const created = await store.createStream(request(), "create-store-0001");
  await accept(store, created.stream.streamId, 0, "redacted body", true);
  const redactedText = "contact [REDACTED:email]";
  const finalized = await store.finalizeStream(created.stream.streamId, redactedText, {
    ruleVersion: "m4b-redaction-v1",
    replacements: 1,
    categories: { email: 1 },
  });

  assert.match(finalized.contentRef, /^ct_[A-Za-z0-9_-]{43}$/);
  assert.notEqual(finalized.contentRef, created.stream.streamId);

  const indexText = fs.readFileSync(path.join(directory, "index.json"), "utf8");
  const payload = fs.readFileSync(path.join(directory, "objects", `${finalized.contentRef}.bin`));
  assert.equal(indexText.includes(redactedText), false);
  assert.equal(payload.includes(Buffer.from(redactedText)), false);

  const restored = await openStore(directory);
  const read = await restored.readObject(finalized.contentRef, accessContext());
  assert.equal(read.content, redactedText);
  assert.equal(read.requestId, "req_m4b_store_0001");
  assert.equal(read.sessionId, "ses_m4b_store_0001");
  assert.deepEqual(read.redaction.categories, { email: 1 });
  const access = await restored.listAccess(finalized.contentRef);
  assert.equal(access.length, 1);
  assert.equal(access[0].outcome, "success");
  assert.equal(access[0].reason, "security investigation case 42");
});

test("missing and tampered objects fail closed and leave failed access records", async () => {
  const directory = tempDirectory();
  const store = await openStore(directory);
  const created = await store.createStream(request(), "create-store-0002");
  const finalized = await store.finalizeStream(created.stream.streamId, "protected body", EMPTY_REDACTION);
  const missingRef = `ct_${crypto.randomBytes(32).toString("base64url")}`;

  await assert.rejects(
    store.readObject(missingRef, accessContext({
      requestId: "req_read_missing_0001",
    })),
    (error) => error instanceof ContentStoreError
      && error.statusCode === 404
      && error.code === "content_object_not_found",
  );
  const missingAccess = await store.listAccess(missingRef);
  assert.equal(missingAccess.length, 1);
  assert.equal(missingAccess[0].outcome, "failed");
  assert.equal(missingAccess[0].errorCode, "content_object_not_found");

  const objectPath = path.join(directory, "objects", `${finalized.contentRef}.bin`);
  const payload = fs.readFileSync(objectPath);
  payload[payload.length - 1] ^= 0xff;
  fs.writeFileSync(objectPath, payload);

  await assert.rejects(
    store.readObject(finalized.contentRef, accessContext({
      requestId: "req_read_tampered_0001",
    })),
    (error) => error instanceof ContentStoreError
      && error.statusCode === 500
      && error.code === "content_integrity_failed",
  );
  const access = await store.listAccess(finalized.contentRef);
  assert.equal(access.length, 1);
  assert.equal(access[0].outcome, "failed");
  assert.equal(access[0].errorCode, "content_integrity_failed");
});

test("chunk idempotency, conflicts, ordering and final replays are explicit", async () => {
  const store = await openStore(tempDirectory());
  const created = await store.createStream(request(), "create-store-0003");
  const streamId = created.stream.streamId;

  await accept(store, streamId, 0, "first", false, "chunk-store-0001");
  assert.equal(
    (await accept(store, streamId, 0, "first", false, "chunk-store-0001")).duplicate,
    true,
  );
  assert.equal(
    (await accept(store, streamId, 0, "first", false, "chunk-store-0002")).duplicate,
    true,
  );
  assert.equal(
    (await accept(store, streamId, 0, "different", false, "chunk-store-0003")).conflict,
    "chunk",
  );
  assert.equal(
    (await accept(store, streamId, 2, "third", false, "chunk-store-0004")).outOfOrder,
    true,
  );

  const final = await accept(store, streamId, 1, " final", true, "chunk-store-0005");
  assert.equal(final.duplicate, false);
  const finalized = await store.finalizeStream(streamId, "first final", EMPTY_REDACTION);
  assert.match(finalized.contentRef, /^ct_/);
  const replay = await accept(store, streamId, 1, " final", true, "chunk-store-0005");
  assert.equal(replay.duplicate, true);
  assert.equal(replay.stream.status, "finalized");

  const flagConflictStore = await openStore(tempDirectory());
  const second = await flagConflictStore.createStream(
    request({ requestId: "req_m4b_store_0004" }),
    "create-store-0004",
  );
  await accept(flagConflictStore, second.stream.streamId, 0, "same", false, "chunk-store-0006");
  const flagConflict = await accept(
    flagConflictStore,
    second.stream.streamId,
    0,
    "same",
    true,
    "chunk-store-0007",
  );
  assert.equal(flagConflict.conflict, "chunk");
});

test("restart interrupts collecting streams once and keeps failed chunks valid", async () => {
  const directory = tempDirectory();
  const first = await openStore(directory);
  const created = await first.createStream(request(), "create-store-0005");
  await accept(first, created.stream.streamId, 0, "partial", false);

  const second = await openStore(directory);
  const interrupted = await second.getStream(created.stream.streamId);
  assert.equal(interrupted.status, "failed");
  assert.equal(interrupted.failureCode, "content_stream_interrupted");
  assert.equal((await second.status()).stats.streamsFailed, 1);
  assert.equal((await second.status()).objects, 0);

  const third = await openStore(directory);
  assert.equal((await third.status()).stats.streamsFailed, 1);
  assert.equal((await third.getStream(created.stream.streamId)).failureCode, "content_stream_interrupted");
});
