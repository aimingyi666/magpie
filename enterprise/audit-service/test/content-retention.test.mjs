import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { ContentDeletionManager } from "../src/content-deletion.js";
import { ContentLegalHoldManager } from "../src/content-legal-hold.js";
import { ContentRetentionManager } from "../src/content-retention.js";
import {
  validateContentStreamRequest,
} from "../src/content-schema.js";
import { ContentStore, ContentStoreError } from "../src/content-store.js";

const KEY = Buffer.alloc(32, 0x6d);
const PROOF_SECRET = ["retention", "proof", "test", "secret", "123456789"].join("-");
const ORGANIZATION_ID = "org_retention";
const ADMIN = {
  adminId: "admin_retention_001",
  organizationId: ORGANIZATION_ID,
  sessionId: "session_retention_001",
};
const SOURCE_HASH = `sha256:${"a".repeat(64)}`;
const EMPTY_REDACTION = {
  ruleVersion: "m4b-redaction-v1",
  replacements: 0,
  categories: {},
};
const DAY_MS = 24 * 60 * 60 * 1000;

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-content-retention-"));
}

function request(overrides = {}) {
  return validateContentStreamRequest({
    schemaVersion: 1,
    requestId: "req_retention_0001",
    sessionId: "ses_retention_0001",
    userId: "usr_retention_alice",
    departmentId: "dept_retention",
    deviceId: "dev_retention_01",
    agentId: "codex",
    modelId: "openai/gpt-5.1",
    providerId: "openai",
    mcpServerId: "mcp_retention",
    toolName: "search.read",
    contentKind: "tool_arguments",
    mediaType: "text/plain",
    auditLevel: "L2",
    collection: {
      purpose: "security_investigation",
      authorizationId: "apr_retention_collect_0001",
      confirmed: true,
      retentionDays: 1,
      metadataRetentionDays: 2,
    },
    ...overrides,
  });
}

async function setup(options = {}) {
  const directory = tempDirectory();
  let now = new Date("2026-11-01T00:00:00.000Z").getTime();
  const store = new ContentStore({
    directory,
    key: KEY,
    proofSecret: PROOF_SECRET,
    now: () => now,
  });
  await store.load();
  const legalHolds = new ContentLegalHoldManager(store, {
    sessionSecret: PROOF_SECRET,
    organizationId: ORGANIZATION_ID,
    now: () => now,
  });
  const deletion = new ContentDeletionManager(store, {
    proofSecret: PROOF_SECRET,
    legalHolds,
    now: () => now,
  });
  const retention = new ContentRetentionManager(store, {
    deletion,
    legalHolds,
    organizationId: ORGANIZATION_ID,
    intervalMs: 60_000,
    now: () => now,
    logger: () => {},
  });
  let sequence = 0;
  const createObject = async (requestOverrides = {}) => {
    sequence += 1;
    const content = request(requestOverrides);
    const created = await store.createStream(
      content,
      `retention-create-${sequence}`,
    );
    const finalized = await store.finalizeStream(
      created.stream.streamId,
      `redacted retention body ${sequence}`,
      EMPTY_REDACTION,
    );
    return {
      contentRef: finalized.contentRef,
      streamId: created.stream.streamId,
      object: store.clone(store.index.objects[finalized.contentRef]),
      stream: store.clone(store.index.streams[created.stream.streamId]),
    };
  };
  return {
    directory,
    store,
    legalHolds,
    deletion,
    retention,
    createObject,
    now: () => now,
    advance(ms) {
      now += ms;
    },
  };
}

async function runRetention(retention, overrides = {}) {
  return retention.run({
    dryRun: false,
    limit: 100,
    ...overrides,
  }, {
    requestId: "req_retention_manual_0001",
    sourceHash: SOURCE_HASH,
  });
}

function holdRequest(content, overrides = {}) {
  return {
    scope: { contentRef: content.contentRef },
    reason: "litigation hold for retention test",
    approvalId: "apr_legal_hold_0001",
    custodianId: "custodian_001",
    expiresAt: new Date(
      new Date("2026-11-01T00:00:00.000Z").getTime() + 30 * DAY_MS,
    ).toISOString(),
    ...overrides,
  };
}

test("content and metadata retention are independent and metadata is redacted last", async () => {
  const app = await setup();
  const content = await app.createObject();

  app.advance(DAY_MS + 1);
  const first = await runRetention(app.retention);
  assert.equal(first.contentDeleted, 1);
  assert.equal(first.metadataRedacted, 0);
  assert.equal(await app.store.hasObject(content.contentRef), false);
  assert.equal(app.store.index.streams[content.streamId].status, "deleted");
  assert.equal(
    app.store.index.streams[content.streamId].request.userId,
    "usr_retention_alice",
  );
  await assert.rejects(
    app.store.readObject(content.contentRef, {
      reason: "retention object is gone",
      authorizationId: "apr_retention_read_0001",
      requestId: "req_retention_read_0001",
      sourceHash: SOURCE_HASH,
    }),
    (error) => error instanceof ContentStoreError
      && error.code === "content_object_not_found",
  );

  app.advance(DAY_MS);
  const second = await runRetention(app.retention);
  assert.equal(second.metadataRedacted, 1);
  const stream = app.store.index.streams[content.streamId];
  assert.match(stream.metadataRedactedAt, /^\d{4}-\d{2}-\d{2}T/);
  for (const field of [
    "requestId",
    "sessionId",
    "userId",
    "departmentId",
    "deviceId",
    "agentId",
  ]) {
    assert.equal(
      ["req_redacted0000", "ses_redacted0000", "redacted"].includes(
        stream.request[field],
      ),
      true,
      `${field} was not redacted`,
    );
  }
  for (const field of ["modelId", "providerId", "mcpServerId", "toolName"]) {
    assert.equal(Object.hasOwn(stream.request, field), false, `${field} was retained`);
  }
  assert.equal(stream.request.collection.authorizationId, "apr_redacted");
  assert.equal(stream.request.collection.purpose, "security_investigation");
  assert.equal(stream.request.contentKind, "tool_arguments");
  assert.equal(stream.request.collection.retentionDays, 1);
  assert.equal(stream.request.collection.metadataRetentionDays, 2);
});

test("dry-run reports due work without mutating the store", async () => {
  const app = await setup();
  const content = await app.createObject();
  app.advance(3 * DAY_MS);

  const summary = await runRetention(app.retention, { dryRun: true });
  assert.equal(summary.dryRun, true);
  assert.equal(summary.contentDeleted, 1);
  assert.equal(summary.metadataRedacted, 1);
  assert.equal(await app.store.hasObject(content.contentRef), true);
  assert.equal(app.store.index.streams[content.streamId].status, "finalized");
  assert.equal(app.store.index.deletionProofs && Object.keys(app.store.index.deletionProofs).length, 0);
});

test("active legal holds block deletion and metadata redaction, including force", async () => {
  const app = await setup();
  const content = await app.createObject({
    collection: {
      purpose: "security_investigation",
      authorizationId: "apr_retention_collect_0001",
      confirmed: true,
      retentionDays: 1,
      metadataRetentionDays: 1,
    },
  });
  const created = await app.legalHolds.create(
    ADMIN,
    holdRequest(content, { scope: { userId: "usr_retention_alice" } }),
    "legal-hold-create-0001",
  );
  assert.equal(created.hold.effectiveStatus, "active");

  app.advance(2 * DAY_MS);
  const skipped = await runRetention(app.retention);
  assert.equal(skipped.contentDeleted, 0);
  assert.equal(skipped.metadataRedacted, 0);
  assert.equal(skipped.skippedLegalHold, 2);
  assert.equal(await app.store.hasObject(content.contentRef), true);
  assert.equal(app.store.index.streams[content.streamId].status, "finalized");

  await assert.rejects(
    app.deletion.delete(
      content.contentRef,
      ADMIN,
      {
        reason: "force delete must not bypass legal hold",
        approvalId: "apr_force_delete_0001",
        force: true,
      },
      "force-delete-0001",
      {
        requestId: "req_force_delete_0001",
        sourceHash: SOURCE_HASH,
      },
    ),
    (error) => error instanceof ContentStoreError
      && error.code === "content_legal_hold_active",
  );

  const released = await app.legalHolds.release(
    ADMIN,
    created.hold.holdId,
    {
      reason: "legal case has closed",
      approvalId: "apr_release_hold_0001",
    },
  );
  assert.equal(released.hold.effectiveStatus, "released");
  const completed = await runRetention(app.retention);
  assert.equal(completed.contentDeleted, 1);
  assert.equal(completed.metadataRedacted, 1);
});

test("an expired legal hold no longer prevents retention", async () => {
  const app = await setup();
  const content = await app.createObject();
  const created = await app.legalHolds.create(
    ADMIN,
    holdRequest(content, {
      expiresAt: new Date(app.now() + 60 * 60 * 1000).toISOString(),
    }),
    "legal-hold-create-0002",
  );
  assert.equal(created.hold.effectiveStatus, "active");
  app.advance(2 * DAY_MS);
  const holds = await app.legalHolds.list({
    organizationId: ORGANIZATION_ID,
    effectiveStatus: "expired",
  });
  assert.equal(holds.length, 1);
  const summary = await runRetention(app.retention);
  assert.equal(summary.contentDeleted, 1);
  assert.equal(await app.store.hasObject(content.contentRef), false);
});

test("metadata retention cannot be shorter than content retention", () => {
  assert.throws(
    () => request({
      collection: {
        purpose: "security_investigation",
        authorizationId: "apr_retention_collect_0001",
        confirmed: true,
        retentionDays: 2,
        metadataRetentionDays: 1,
      },
    }),
    (error) => error.code === "invalid_content_collection",
  );
});

test("persistence failure rolls back deletion and fails the sweep closed", async () => {
  const app = await setup();
  const content = await app.createObject();
  app.advance(2 * DAY_MS);
  const originalPersist = app.store.persist.bind(app.store);
  app.store.persist = async () => {
    throw new Error("simulated retention persistence failure");
  };
  try {
    await assert.rejects(
      runRetention(app.retention),
      (error) => error instanceof ContentStoreError
        && error.code === "content_store_unavailable"
        && error.statusCode === 503,
    );
    assert.equal(await app.store.hasObject(content.contentRef), true);
    assert.equal(app.store.index.streams[content.streamId].status, "finalized");
    assert.equal(Object.keys(app.store.index.deletionProofs).length, 0);
    assert.equal(
      fs.existsSync(path.join(
        app.store.objectsDirectory,
        `${content.contentRef}.bin`,
      )),
      true,
    );
    assert.equal(
      fs.readdirSync(app.store.objectsDirectory)
        .some((name) => name.startsWith(".staging-")),
      false,
    );
  } finally {
    app.store.persist = originalPersist;
  }
});

test("staging recovery restores referenced objects and removes orphans", async () => {
  const app = await setup();
  const content = await app.createObject();
  const deletionId = `del_${crypto.randomBytes(32).toString("base64url")}`;
  const objectPath = path.join(
    app.store.objectsDirectory,
    `${content.contentRef}.bin`,
  );
  const stagingPath = path.join(
    app.store.objectsDirectory,
    `.staging-${content.contentRef}-${deletionId}.bin`,
  );
  fs.renameSync(objectPath, stagingPath);

  const restored = new ContentStore({
    directory: app.directory,
    key: KEY,
    proofSecret: PROOF_SECRET,
    now: app.now,
  });
  await restored.load();
  assert.equal(fs.existsSync(objectPath), true);
  assert.equal(fs.existsSync(stagingPath), false);
  const read = await restored.readObject(content.contentRef, {
    reason: "read after staging recovery",
    authorizationId: "apr_retention_read_0002",
    requestId: "req_retention_recovery_0001",
    sourceHash: SOURCE_HASH,
  });
  assert.match(read.content, /redacted retention body/);

  const orphanRef = `ct_${crypto.randomBytes(32).toString("base64url")}`;
  const orphanStaging = path.join(
    restored.objectsDirectory,
    `.staging-${orphanRef}-${deletionId}.bin`,
  );
  fs.writeFileSync(orphanStaging, "orphan");
  const second = new ContentStore({
    directory: app.directory,
    key: KEY,
    proofSecret: PROOF_SECRET,
    now: app.now,
  });
  await second.load();
  assert.equal(fs.existsSync(orphanStaging), false);
});

test("v1 indexes migrate to v2 and retain readable content", async () => {
  const app = await setup();
  const content = await app.createObject();
  const indexPath = app.store.indexPath;
  const newIndex = JSON.parse(fs.readFileSync(indexPath, "utf8"));
  newIndex.version = 1;
  delete newIndex.legalHolds;
  delete newIndex.deletionProofs;
  delete newIndex.exports;
  delete newIndex.governanceIdempotency;
  delete newIndex.stats.contentDeleted;
  delete newIndex.stats.metadataRedacted;
  delete newIndex.stats.exportsCreated;
  for (const stream of Object.values(newIndex.streams)) {
    delete stream.contentRetentionExpiresAt;
    delete stream.metadataRetentionExpiresAt;
  }
  for (const object of Object.values(newIndex.objects)) {
    delete object.contentRetentionExpiresAt;
    delete object.metadataRetentionExpiresAt;
  }
  fs.writeFileSync(indexPath, `${JSON.stringify(newIndex)}\n`);

  const migrated = new ContentStore({
    directory: app.directory,
    key: KEY,
    proofSecret: PROOF_SECRET,
    now: app.now,
  });
  await migrated.load();
  const persisted = JSON.parse(fs.readFileSync(indexPath, "utf8"));
  assert.equal(persisted.version, 2);
  assert.equal(typeof persisted.objects[content.contentRef].contentRetentionExpiresAt, "string");
  assert.equal(
    typeof persisted.objects[content.contentRef].metadataRetentionExpiresAt,
    "string",
  );
  const read = await migrated.readObject(content.contentRef, {
    reason: "read migrated v1 content",
    authorizationId: "apr_retention_read_0003",
    requestId: "req_retention_migrate_0001",
    sourceHash: SOURCE_HASH,
  });
  assert.match(read.content, /redacted retention body/);
});
