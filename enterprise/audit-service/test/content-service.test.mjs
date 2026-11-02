import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { loadConfig } from "../src/config.js";
import { createAuditServer } from "../src/service.js";

const SERVICE_TOKEN = ["audit", "content", "service", "test", "token", "123456789"].join("-");
const READ_TOKEN = ["audit", "content", "read", "test", "token", "123456789"].join("-");
const ENCRYPTION_KEY = Buffer.alloc(32, 0x5a);
const EMAIL = "employee.real@example.com";
const API_KEY = `sk-${"q".repeat(24)}`;

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-content-service-"));
}

function contentRequest(overrides = {}) {
  return {
    schemaVersion: 1,
    requestId: "req_m4b_service_0001",
    sessionId: "ses_m4b_service_0001",
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
      authorizationId: "apr_m4b_service_0001",
      confirmed: true,
      retentionDays: 7,
    },
    ...overrides,
  };
}

function chunk(sequence, text, final = false) {
  return { schemaVersion: 1, sequence, text, final };
}

function config(root, overrides = {}) {
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
    contentEnabled: true,
    contentEncryptionKey: ENCRYPTION_KEY,
    contentReadToken: READ_TOKEN,
    contentStoreDir: path.join(root, "audit-content"),
    contentMaxBodyBytes: 64 * 1024,
    contentMaxChunkBytes: 1024,
    contentMaxStreamBytes: 4096,
    contentMaxBufferBytes: 8192,
    contentMaxActiveStreams: 4,
    contentStreamTtlMs: 60_000,
    ...overrides,
  };
}

async function start(root, overrides = {}) {
  const app = await createAuditServer(config(root, overrides), {
    startPipeline: false,
    logger: () => {},
  });
  await new Promise((resolve, reject) => {
    app.server.once("error", reject);
    app.server.listen(0, "127.0.0.1", resolve);
  });
  return {
    ...app,
    base: `http://127.0.0.1:${app.server.address().port}`,
  };
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
    headers["content-type"] = "application/json";
    body = JSON.stringify(options.body);
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

function filesUnder(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...filesUnder(target));
    else files.push(target);
  }
  return files;
}

test("content APIs are closed by default and create no content directory", async () => {
  const root = tempDirectory();
  const app = await start(root, {
    contentEnabled: false,
    contentEncryptionKey: null,
  });
  try {
    const response = await request(app.base, "/api/v1/internal/audit/content/streams", {
      body: contentRequest(),
    });
    assert.equal(response.status, 503);
    assert.equal((await responseJson(response)).error.code, "content_audit_disabled");
    assert.equal(fs.existsSync(path.join(root, "audit-content")), false);
  } finally {
    await app.close();
  }
});

test("full L2 flow is idempotent, redacts before persistence and audits reads", async () => {
  const root = tempDirectory();
  const app = await start(root);
  const createKey = "create-content-service-0001";
  try {
    const created = await request(app.base, "/api/v1/internal/audit/content/streams", {
      idempotency: createKey,
      body: contentRequest(),
    });
    const createdBody = await responseJson(created);
    assert.equal(created.status, 202);
    assert.equal(createdBody.stream.requestId, "req_m4b_service_0001");
    assert.equal(createdBody.stream.nextSequence, 0);
    assert.equal(createdBody.stream.auditLevel, "L2");
    const streamId = createdBody.stream.streamId;

    const replay = await request(app.base, "/api/v1/internal/audit/content/streams", {
      idempotency: createKey,
      body: contentRequest(),
    });
    const replayBody = await responseJson(replay);
    assert.equal(replay.status, 200);
    assert.equal(replayBody.duplicate, true);
    assert.equal(replayBody.stream.streamId, streamId);

    const conflict = await request(app.base, "/api/v1/internal/audit/content/streams", {
      idempotency: createKey,
      body: contentRequest({ requestId: "req_m4b_service_conflict" }),
    });
    assert.equal(conflict.status, 409);
    assert.equal((await responseJson(conflict)).error.code, "content_idempotency_conflict");

    const chunkRoute = `/api/v1/internal/audit/content/streams/${streamId}/chunks`;
    const first = await request(app.base, chunkRoute, {
      idempotency: "chunk-content-service-0001",
      body: chunk(0, `employee ${EMAIL} authenticated with `),
    });
    assert.equal(first.status, 200);
    assert.equal((await responseJson(first)).accepted, true);

    const duplicateChunk = await request(app.base, chunkRoute, {
      idempotency: "chunk-content-service-0001",
      body: chunk(0, `employee ${EMAIL} authenticated with `),
    });
    assert.equal((await responseJson(duplicateChunk)).duplicate, true);

    const outOfOrder = await request(app.base, chunkRoute, {
      idempotency: "chunk-content-service-0002",
      body: chunk(2, "too early", false),
    });
    assert.equal(outOfOrder.status, 409);
    assert.equal((await responseJson(outOfOrder)).error.code, "content_sequence_out_of_order");

    const finalChunk = await request(app.base, chunkRoute, {
      idempotency: "chunk-content-service-0003",
      body: chunk(1, `API key ${API_KEY}`, true),
    });
    const finalBody = await responseJson(finalChunk);
    assert.equal(finalChunk.status, 200);
    assert.equal(finalBody.finalized, true);
    assert.match(finalBody.stream.contentRef, /^ct_[A-Za-z0-9_-]{43}$/);
    assert.equal(finalBody.stream.redaction.categories.email, 1);
    assert.equal(finalBody.stream.redaction.categories.api_key, 1);
    const contentRef = finalBody.stream.contentRef;

    const metadata = await request(
      app.base,
      `/api/v1/admin/audit/content/streams/${streamId}`,
    );
    const metadataBody = await responseJson(metadata);
    assert.equal(metadata.status, 200);
    assert.equal(metadataBody.stream.status, "finalized");
    assert.equal(metadataBody.stream.contentRef, contentRef);
    assert.equal(Object.hasOwn(metadataBody.stream, "content"), false);

    const noReadToken = await request(app.base, `/api/v1/admin/audit/content/${contentRef}`);
    assert.equal(noReadToken.status, 401);
    assert.equal((await responseJson(noReadToken)).error.code, "content_read_unauthorized");

    const noReason = await request(app.base, `/api/v1/admin/audit/content/${contentRef}`, {
      headers: { "x-audit-content-token": READ_TOKEN },
    });
    assert.equal(noReason.status, 400);
    assert.equal((await responseJson(noReason)).error.code, "content_access_reason_required");

    const noAuthorization = await request(app.base, `/api/v1/admin/audit/content/${contentRef}`, {
      headers: {
        "x-audit-content-token": READ_TOKEN,
        "x-audit-content-reason": "security case 42",
      },
    });
    assert.equal(noAuthorization.status, 400);
    assert.equal(
      (await responseJson(noAuthorization)).error.code,
      "content_access_authorization_required",
    );

    const read = await request(app.base, `/api/v1/admin/audit/content/${contentRef}`, {
      headers: {
        "x-audit-content-token": READ_TOKEN,
        "x-audit-content-reason": "security case 42",
        "x-audit-content-authorization": "apr_read_service_0001",
      },
    });
    const readBody = await responseJson(read);
    assert.equal(read.status, 200);
    assert.equal(readBody.content.includes(EMAIL), false);
    assert.equal(readBody.content.includes(API_KEY), false);
    assert.equal(readBody.content.includes("[REDACTED:email]"), true);
    assert.match(read.headers.get("x-audit-watermark"), /^MAGPIE-AUDIT-CONTENT ct_/);
    assert.equal((await app.contentStore.listAccess(contentRef))[0].outcome, "success");

    const missingRef = `ct_${crypto.randomBytes(32).toString("base64url")}`;
    const missing = await request(app.base, `/api/v1/admin/audit/content/${missingRef}`, {
      headers: {
        "x-audit-content-token": READ_TOKEN,
        "x-audit-content-reason": "security case 43",
        "x-audit-content-authorization": "apr_read_service_0002",
      },
    });
    assert.equal(missing.status, 404);
    const failedAccess = await app.contentStore.listAccess(missingRef);
    assert.equal(failedAccess.length, 1);
    assert.equal(failedAccess[0].outcome, "failed");
    assert.equal(failedAccess[0].errorCode, "content_object_not_found");

    for (const file of filesUnder(root)) {
      const data = fs.readFileSync(file);
      assert.equal(data.includes(Buffer.from(EMAIL)), false, `raw email persisted in ${file}`);
      assert.equal(data.includes(Buffer.from(API_KEY)), false, `raw API key persisted in ${file}`);
      assert.equal(data.includes(Buffer.from(SERVICE_TOKEN)), false, `service token persisted in ${file}`);
      assert.equal(data.includes(Buffer.from(READ_TOKEN)), false, `read token persisted in ${file}`);
    }
  } finally {
    await app.close();
  }
});

test("content routes require the service token and oversized requests fail closed", async () => {
  const root = tempDirectory();
  const app = await start(root, { contentMaxBodyBytes: 1024 });
  try {
    const unauthorized = await request(
      app.base,
      "/api/v1/internal/audit/content/streams",
      {
        token: ["wrong", "content", "service", "token", "123456789"].join("-"),
        body: contentRequest(),
      },
    );
    assert.equal(unauthorized.status, 401);

    const oversized = await request(
      app.base,
      "/api/v1/internal/audit/content/streams",
      {
        body: contentRequest({ agentId: `agent_${"x".repeat(2000)}` }),
      },
    );
    assert.equal(oversized.status, 413);
    assert.equal((await responseJson(oversized)).error.code, "content_request_too_large");
    assert.equal((await app.contentStore.status()).streams, 0);
  } finally {
    await app.close();
  }
});

test("content configuration fails closed when encryption or read secrets are invalid", () => {
  const base = {
    AUDIT_SERVICE_TOKEN: SERVICE_TOKEN,
    AUDIT_CONTENT_ENABLED: "false",
  };
  assert.equal(loadConfig(base).contentEncryptionKey, null);
  assert.throws(
    () => loadConfig({ ...base, AUDIT_CONTENT_ENABLED: "true" }),
    /AUDIT_CONTENT_ENCRYPTION_KEY is required/,
  );
  assert.throws(
    () => loadConfig({
      ...base,
      AUDIT_CONTENT_ENABLED: "true",
      AUDIT_CONTENT_ENCRYPTION_KEY: Buffer.alloc(31).toString("base64"),
    }),
    /must encode exactly 32 bytes/,
  );
  assert.throws(
    () => loadConfig({
      ...base,
      AUDIT_CONTENT_ENABLED: "true",
      AUDIT_CONTENT_ENCRYPTION_KEY: ENCRYPTION_KEY.toString("hex"),
    }),
    /AUDIT_CONTENT_READ_TOKEN is required when AUDIT_CONTENT_ENABLED=true/,
  );
  assert.throws(
    () => loadConfig({
      ...base,
      AUDIT_CONTENT_ENABLED: "true",
      AUDIT_CONTENT_ENCRYPTION_KEY: ENCRYPTION_KEY.toString("hex"),
      AUDIT_CONTENT_READ_TOKEN: SERVICE_TOKEN,
    }),
    /AUDIT_CONTENT_READ_TOKEN must differ from AUDIT_SERVICE_TOKEN/,
  );
  assert.throws(
    () => loadConfig({ ...base, AUDIT_CONTENT_READ_TOKEN: "too-short" }),
    /AUDIT_CONTENT_READ_TOKEN must be at least 32 characters/,
  );
  const loaded = loadConfig({
    ...base,
    AUDIT_CONTENT_ENABLED: "true",
    AUDIT_CONTENT_ENCRYPTION_KEY: ENCRYPTION_KEY.toString("hex"),
    AUDIT_CONTENT_READ_TOKEN: READ_TOKEN,
  });
  assert.equal(loaded.contentEncryptionKey.length, 32);
  assert.equal(loaded.contentReadToken, READ_TOKEN);
});
