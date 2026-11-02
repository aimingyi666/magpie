import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { ContentExportManager } from "../src/content-export.js";
import {
  ContentStore,
  ContentStoreError,
} from "../src/content-store.js";
import { sha256Text } from "../src/events.js";

const CONTENT_KEY = Buffer.alloc(32, 0x71);
const EXPORT_KEY = Buffer.alloc(32, 0x2c);
const PROOF_SECRET = ["export", "proof", "test", "secret", "123456789"].join("-");
const EXPORT_SECRET = ["export", "download", "test", "secret", "123456789"].join("-");
const ORGANIZATION_ID = "org_export";
const ADMIN = {
  adminId: "admin_export_001",
  organizationId: ORGANIZATION_ID,
  sessionId: "session_export_001",
};
const SOURCE_HASH = `sha256:${"b".repeat(64)}`;
const EXPORT_MAGIC = Buffer.from("MAGPIE-EXPORT-1", "utf8");
const REDACTION = {
  ruleVersion: "m4b-redaction-v1",
  replacements: 0,
  categories: {},
};
const DAY_MS = 24 * 60 * 60 * 1000;

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-content-export-"));
}

function contentRequest(overrides = {}) {
  return {
    schemaVersion: 1,
    requestId: "req_export_0001",
    sessionId: "ses_export_0001",
    userId: "usr_export_alice",
    departmentId: "dept_export",
    deviceId: "dev_export_01",
    agentId: "codex",
    modelId: "openai/gpt-5.1",
    providerId: "openai",
    mcpServerId: "mcp_export",
    toolName: "search.read",
    contentKind: "prompt",
    mediaType: "text/plain",
    auditLevel: "L2",
    collection: {
      purpose: "security_investigation",
      authorizationId: "apr_export_collect_0001",
      confirmed: true,
      retentionDays: 7,
      metadataRetentionDays: 14,
    },
    ...overrides,
  };
}

function exportRequest(overrides = {}) {
  return {
    scope: { contentRefs: [] },
    purpose: "compliance_review",
    reason: "regulator request 2026-42",
    approvalId: "apr_export_2026_42",
    ttlSeconds: 60,
    ...overrides,
  };
}

function errorIs(statusCode, code) {
  return (error) => error instanceof ContentStoreError
    && error.statusCode === statusCode
    && error.code === code;
}

async function setup() {
  const directory = tempDirectory();
  let now = new Date("2026-11-02T00:00:00.000Z").getTime();
  const store = new ContentStore({
    directory,
    key: CONTENT_KEY,
    proofSecret: PROOF_SECRET,
    now: () => now,
  });
  await store.load();
  const manager = new ContentExportManager(store, {
    secret: EXPORT_SECRET,
    key: EXPORT_KEY,
    organizationId: ORGANIZATION_ID,
    defaultTtlSeconds: 60,
    now: () => now,
  });
  let sequence = 0;

  async function createObject(overrides = {}, body = "redacted export body") {
    sequence += 1;
    const value = contentRequest({
      requestId: `req_export_${String(sequence).padStart(4, "0")}`,
      sessionId: `ses_export_${String(sequence).padStart(4, "0")}`,
      ...overrides,
    });
    const created = await store.createStream(
      value,
      `export-create-${sequence}`,
    );
    const finalized = await store.finalizeStream(
      created.stream.streamId,
      body,
      REDACTION,
    );
    return {
      contentRef: finalized.contentRef,
      streamId: created.stream.streamId,
      body,
    };
  }

  return {
    directory,
    store,
    manager,
    createObject,
    now: () => now,
    advance(ms) {
      now += ms;
    },
  };
}

async function createExport(manager, object, key, overrides = {}) {
  return manager.create(
    ADMIN,
    exportRequest({
      scope: { contentRefs: [object.contentRef] },
      ...overrides,
    }),
    key,
    {
      requestId: `req_${key.replace(/[^A-Za-z0-9]/g, "")}`.slice(0, 136),
      sourceHash: SOURCE_HASH,
    },
  );
}

function exportFiles(directory) {
  try {
    return fs.readdirSync(directory)
      .filter((name) => name.endsWith(".mge"));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

test("exports return encrypted bytes with redacted content and complete metadata", async () => {
  const app = await setup();
  const alice = await app.createObject(
    {},
    "alice redacted prompt body that must remain encrypted",
  );
  const bob = await app.createObject({
    requestId: "req_export_bob_0001",
    sessionId: "ses_export_bob_0001",
    userId: "usr_export_bob",
    departmentId: "dept_finance",
    deviceId: "dev_export_02",
    agentId: "opencode",
    modelId: "anthropic/claude-3-7-sonnet",
    providerId: "anthropic",
    mcpServerId: "mcp_database",
    toolName: "db.query",
    contentKind: "tool_result",
  }, "bob redacted result body");
  const result = await app.manager.create(
    ADMIN,
    exportRequest({
      scope: {
        contentRefs: [alice.contentRef, bob.contentRef],
      },
    }),
    "export-positive-0001",
    {
      requestId: "req_export_positive_0001",
      sourceHash: SOURCE_HASH,
    },
  );
  assert.equal(result.duplicate, false);
  assert.equal(result.export.objectCount, 2);
  assert.equal(result.export.downloadCount, 0);
  assert.equal(result.export.status, "active");
  assert.match(result.token, /^[A-Za-z0-9_-]{16,4096}\.[A-Za-z0-9_-]{43}$/);
  assert.equal(JSON.stringify(result.export).includes(result.token), false);

  const downloaded = await app.manager.download(
    result.export.exportId,
    ADMIN,
    result.token,
  );
  assert.equal(Buffer.isBuffer(downloaded.bytes), true);
  assert.equal(
    downloaded.bytes.subarray(0, EXPORT_MAGIC.length).equals(EXPORT_MAGIC),
    true,
  );
  assert.equal(downloaded.bytes.includes(Buffer.from(alice.body)), false);
  assert.equal(downloaded.bytes.includes(Buffer.from(bob.body)), false);
  assert.equal(downloaded.bytes.includes(Buffer.from(app.directory)), false);
  assert.equal(downloaded.bytes.includes(Buffer.from(result.token)), false);
  assert.equal(downloaded.bytes.includes(EXPORT_KEY), false);
  assert.match(downloaded.watermark, /MAGPIE-AUDIT-EXPORT exp_/);

  const packageValue = JSON.parse(
    app.manager.decryptPackage(
      downloaded.bytes,
      result.export.exportId,
    ).toString("utf8"),
  );
  assert.equal(packageValue.format, "magpie-content-export-v1");
  assert.equal(packageValue.exportId, result.export.exportId);
  assert.equal(packageValue.organizationId, ORGANIZATION_ID);
  assert.equal(packageValue.objects.length, 2);
  const exportedAlice = packageValue.objects.find(
    (item) => item.contentRef === alice.contentRef,
  );
  assert.equal(exportedAlice.content, alice.body);
  assert.equal(exportedAlice.userId, "usr_export_alice");
  assert.equal(exportedAlice.departmentId, "dept_export");
  assert.equal(exportedAlice.deviceId, "dev_export_01");
  assert.equal(exportedAlice.agentId, "codex");
  assert.equal(exportedAlice.modelId, "openai/gpt-5.1");
  assert.equal(exportedAlice.providerId, "openai");
  assert.equal(exportedAlice.mcpServerId, "mcp_export");
  assert.equal(exportedAlice.toolName, "search.read");

  const listed = await app.manager.list({ organizationId: ORGANIZATION_ID });
  assert.equal(listed.length, 1);
  assert.equal(listed[0].status, "downloaded");
  const serializedList = JSON.stringify(listed);
  assert.equal(serializedList.includes(alice.body), false);
  assert.equal(serializedList.includes(result.token), false);
  assert.equal(serializedList.includes(EXPORT_KEY.toString("hex")), false);
  assert.equal(serializedList.includes(app.directory), false);

  const serializedIndex = fs.readFileSync(app.store.indexPath, "utf8");
  assert.equal(serializedIndex.includes(alice.body), false);
  assert.equal(serializedIndex.includes(result.token), false);
  assert.equal(serializedIndex.includes(EXPORT_KEY.toString("hex")), false);
  assert.equal(serializedIndex.includes(app.directory), false);
});

test("download refuses missing, tampered, and context-mismatched tokens", async () => {
  const app = await setup();
  const object = await app.createObject();
  const first = await createExport(
    app.manager,
    object,
    "export-context-0001",
  );
  const second = await createExport(
    app.manager,
    object,
    "export-context-0002",
  );

  await assert.rejects(
    app.manager.download(first.export.exportId, ADMIN, ""),
    errorIs(401, "content_export_token_required"),
  );
  const tampered = `${first.token.slice(0, -1)}${first.token.endsWith("A") ? "B" : "A"}`;
  await assert.rejects(
    app.manager.download(first.export.exportId, ADMIN, tampered),
    errorIs(401, "content_export_token_invalid"),
  );
  await assert.rejects(
    app.manager.download(second.export.exportId, ADMIN, first.token),
    errorIs(403, "content_export_token_invalid"),
  );

  for (const administrator of [
    { ...ADMIN, adminId: "admin_export_other" },
    { ...ADMIN, organizationId: "org_export_other" },
    { ...ADMIN, sessionId: "session_export_other" },
  ]) {
    await assert.rejects(
      app.manager.download(first.export.exportId, administrator, first.token),
      errorIs(403, "content_export_token_invalid"),
    );
  }

  const record = app.store.index.exports[first.export.exportId];
  const originalScopeHash = record.scopeHash;
  record.scopeHash = sha256Text("different exported scope");
  try {
    await assert.rejects(
      app.manager.download(first.export.exportId, ADMIN, first.token),
      errorIs(403, "content_export_token_invalid"),
    );
  } finally {
    record.scopeHash = originalScopeHash;
  }
});

test("download is one-time and an expired export returns 410 while removing its file", async () => {
  const app = await setup();
  const object = await app.createObject();
  const first = await createExport(
    app.manager,
    object,
    "export-one-time-0001",
    { ttlSeconds: 15 },
  );
  await app.manager.download(
    first.export.exportId,
    ADMIN,
    first.token,
  );
  await assert.rejects(
    app.manager.download(first.export.exportId, ADMIN, first.token),
    errorIs(409, "content_export_token_reused"),
  );

  const second = await createExport(
    app.manager,
    object,
    "export-expired-0001",
    { ttlSeconds: 15 },
  );
  const exportPath = path.join(
    app.store.directory,
    "exports",
    `${second.export.exportId}.mge`,
  );
  assert.equal(fs.existsSync(exportPath), true);
  app.advance(16_000);
  await assert.rejects(
    app.manager.download(second.export.exportId, ADMIN, second.token),
    errorIs(410, "content_export_expired"),
  );
  assert.equal(fs.existsSync(exportPath), false);
  assert.equal(
    app.store.index.exports[second.export.exportId].status,
    "expired",
  );
  await assert.rejects(
    app.manager.download(second.export.exportId, ADMIN, second.token),
    errorIs(410, "content_export_expired"),
  );
});

test("export audit persistence failure returns 503 and leaves the export unconsumed", async () => {
  const app = await setup();
  const object = await app.createObject();
  const created = await createExport(
    app.manager,
    object,
    "export-persist-failure-0001",
  );
  const originalPersist = app.store.persist.bind(app.store);
  app.store.persist = async () => {
    throw new Error("simulated export audit persistence failure");
  };
  try {
    await assert.rejects(
      app.manager.download(
        created.export.exportId,
        ADMIN,
        created.token,
      ),
      errorIs(503, "content_store_unavailable"),
    );
    const record = app.store.index.exports[created.export.exportId];
    assert.equal(record.status, "active");
    assert.equal(record.downloadCount, 0);
    assert.equal(Object.hasOwn(record, "downloadConsumedAt"), false);
  } finally {
    app.store.persist = originalPersist;
  }
  await app.manager.download(
    created.export.exportId,
    ADMIN,
    created.token,
  );
  assert.equal(
    app.store.index.exports[created.export.exportId].status,
    "downloaded",
  );
});

test("content changes during preparation fail the export closed", async () => {
  const app = await setup();
  const object = await app.createObject();
  const originalRead = app.store.readObject.bind(app.store);
  app.store.readObject = async (...args) => {
    const result = await originalRead(...args);
    app.store.index.objects[object.contentRef] = {
      ...app.store.index.objects[object.contentRef],
      plaintextSha256: sha256Text("changed while exporting"),
    };
    return result;
  };
  try {
    await assert.rejects(
      createExport(
        app.manager,
        object,
        "export-changed-during-create-0001",
      ),
      errorIs(409, "content_export_not_available"),
    );
  } finally {
    app.store.readObject = originalRead;
  }
  assert.equal(Object.keys(app.store.index.exports).length, 0);
  assert.deepEqual(
    exportFiles(path.join(app.store.directory, "exports")),
    [],
  );
});

test("concurrent export retries with one idempotency key create one record and one file", async () => {
  const app = await setup();
  const object = await app.createObject();
  const request = exportRequest({
    scope: { contentRefs: [object.contentRef] },
  });
  const create = () => app.manager.create(
    ADMIN,
    request,
    "export-concurrent-0001",
    {
      requestId: "req_export_concurrent_0001",
      sourceHash: SOURCE_HASH,
    },
  );
  const [left, right] = await Promise.all([create(), create()]);
  assert.deepEqual(
    [left.duplicate, right.duplicate].sort(),
    [false, true],
  );
  assert.equal(left.export.exportId, right.export.exportId);
  assert.equal(left.token, right.token);
  assert.equal(Object.keys(app.store.index.exports).length, 1);
  assert.equal(
    Object.keys(app.store.index.governanceIdempotency).length,
    1,
  );
  assert.equal(
    exportFiles(path.join(app.store.directory, "exports")).length,
    1,
  );
});

test("orphan cleanup removes stale exports and temporary files but preserves recent active work", async () => {
  const app = await setup();
  const directory = path.join(app.store.directory, "exports");
  fs.mkdirSync(directory, { recursive: true });
  const orphan = `exp_${crypto.randomBytes(32).toString("base64url")}.mge`;
  const oldTemp = ".tmp-old-failed-write";
  const recentTemp = ".tmp-recent-work";
  const activeTemp = ".tmp-active-work";
  for (const name of [orphan, oldTemp, recentTemp, activeTemp]) {
    fs.writeFileSync(path.join(directory, name), "orphan");
  }
  const old = new Date(app.now() - 2 * 60 * 60 * 1000);
  fs.utimesSync(path.join(directory, oldTemp), old, old);
  fs.utimesSync(path.join(directory, activeTemp), old, old);
  app.manager.activeFiles.add(activeTemp);

  const cleaned = await app.manager.cleanupOrphanedFiles();
  assert.equal(cleaned.cleaned, 2);
  assert.equal(fs.existsSync(path.join(directory, orphan)), false);
  assert.equal(fs.existsSync(path.join(directory, oldTemp)), false);
  assert.equal(fs.existsSync(path.join(directory, recentTemp)), true);
  assert.equal(fs.existsSync(path.join(directory, activeTemp)), true);
});
