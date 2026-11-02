import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ContentStore,
  ContentStoreError,
} from "../src/content-store.js";
import { createAuditServer } from "../src/service.js";

const SERVICE_TOKEN = ["audit", "governance", "service", "test", "123456789"].join("-");
const ADMIN_TOKEN = ["audit", "governance", "admin", "test", "123456789"].join("-");
const GOVERNANCE_TOKEN = ["audit", "governance", "control", "test", "123456789"].join("-");
const GRANT_SECRET = ["audit", "governance", "grant", "test", "123456789"].join("-");
const CURSOR_SECRET = ["audit", "governance", "cursor", "test", "123456789"].join("-");
const PROOF_SECRET = ["audit", "governance", "proof", "test", "123456789"].join("-");
const EXPORT_SECRET = ["audit", "governance", "export", "test", "123456789"].join("-");
const CONTENT_KEY = Buffer.alloc(32, 0x5e);
const EXPORT_KEY = Buffer.alloc(32, 0x3b);
const ORGANIZATION_ID = "org_governance";
const ADMIN_ID = "admin_governance_001";
const ADMIN_SESSION = "session_governance_001";
const EXPORT_MAGIC = Buffer.from("MAGPIE-EXPORT-1", "utf8");
const REDACTION = {
  ruleVersion: "m4b-redaction-v1",
  replacements: 0,
  categories: {},
};
const DAY_MS = 24 * 60 * 60 * 1000;

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-content-governance-"));
}

function contentRequest(overrides = {}) {
  return {
    schemaVersion: 1,
    requestId: "req_governance_0001",
    sessionId: "ses_governance_0001",
    userId: "usr_governance_alice",
    departmentId: "dept_governance",
    deviceId: "dev_governance_01",
    agentId: "codex",
    modelId: "openai/gpt-5.1",
    providerId: "openai",
    mcpServerId: "mcp_governance",
    toolName: "search.read",
    contentKind: "prompt",
    mediaType: "text/plain",
    auditLevel: "L2",
    collection: {
      purpose: "security_investigation",
      authorizationId: "apr_governance_collect_0001",
      confirmed: true,
      retentionDays: 1,
      metadataRetentionDays: 2,
    },
    ...overrides,
  };
}

function config(root, options) {
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
    contentAdminEnabled: true,
    contentGovernanceEnabled: true,
    contentEncryptionKey: CONTENT_KEY,
    contentAdminToken: ADMIN_TOKEN,
    contentGovernanceToken: GOVERNANCE_TOKEN,
    contentProofSecret: PROOF_SECRET,
    contentExportEnabled: true,
    contentExportSecret: EXPORT_SECRET,
    contentExportKey: EXPORT_KEY,
    contentGrantSecret: GRANT_SECRET,
    contentCursorSecret: CURSOR_SECRET,
    contentOrganizationId: ORGANIZATION_ID,
    contentGrantTtlSeconds: 60,
    contentExportTtlSeconds: 60,
    contentRetentionSweepIntervalMs: 60_000,
    contentStoreDir: path.join(root, "audit-content"),
    contentGrantStorePath: path.join(root, "audit-content", "content-grants.json"),
    contentMaxBodyBytes: 64 * 1024,
    contentMaxChunkBytes: 1024,
    contentMaxStreamBytes: 4096,
    contentMaxBufferBytes: 8192,
    contentMaxActiveStreams: 4,
    contentStreamTtlMs: 60_000,
    ...options,
  };
}

async function start() {
  const root = tempDirectory();
  let now = new Date("2026-11-02T00:00:00.000Z").getTime();
  const app = await createAuditServer(config(root, {}), {
    startPipeline: false,
    logger: () => {},
    nowMs: () => now,
  });
  await new Promise((resolve, reject) => {
    app.server.once("error", reject);
    app.server.listen(0, "127.0.0.1", resolve);
  });
  return {
    ...app,
    root,
    base: `http://127.0.0.1:${app.server.address().port}`,
    now: () => now,
    advance(ms) {
      now += ms;
    },
  };
}

function adminHeaders(token = GOVERNANCE_TOKEN, overrides = {}) {
  return {
    authorization: `Bearer ${token}`,
    "x-audit-admin-id": ADMIN_ID,
    "x-audit-organization-id": ORGANIZATION_ID,
    "x-audit-admin-session": ADMIN_SESSION,
    ...overrides,
  };
}

async function request(base, route, options = {}) {
  const headers = {
    ...(options.headers || {}),
  };
  let body;
  if (options.body !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(options.body);
  }
  if (options.idempotency) {
    headers["idempotency-key"] = options.idempotency;
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

async function addObject(app, overrides = {}, body = "redacted governance body") {
  const requestValue = contentRequest(overrides);
  const created = await app.contentStore.createStream(
    requestValue,
    crypto.randomUUID(),
  );
  const finalized = await app.contentStore.finalizeStream(
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

function errorCode(body) {
  return body?.error?.code;
}

test("content administration and governance tokens cannot cross route boundaries", async () => {
  const app = await start();
  try {
    const object = await addObject(app);
    const governanceRead = await request(
      app.base,
      "/api/v1/admin/audit/content/streams",
      { headers: adminHeaders(GOVERNANCE_TOKEN) },
    );
    assert.equal(governanceRead.status, 401);
    assert.equal(
      errorCode(await responseJson(governanceRead)),
      "content_admin_unauthorized",
    );

    const adminRead = await request(
      app.base,
      "/api/v1/admin/audit/content/streams",
      { headers: adminHeaders(ADMIN_TOKEN) },
    );
    assert.equal(adminRead.status, 200);

    for (const [method, route, body] of [
      ["POST", "/api/v1/admin/audit/content/retention/run", { dryRun: true }],
      ["GET", "/api/v1/admin/audit/content/deletions"],
      ["POST", "/api/v1/admin/audit/content/legal-holds", {
        scope: { contentRef: object.contentRef },
        reason: "legal hold token boundary test",
        approvalId: "apr_governance_hold_0001",
        custodianId: "custodian_governance",
        expiresAt: "2026-12-02T00:00:00.000Z",
      }],
      ["GET", "/api/v1/admin/audit/content/exports"],
    ]) {
      const response = await request(app.base, route, {
        method,
        body,
        idempotency: body ? `admin-governance-boundary-${method}` : undefined,
        headers: adminHeaders(ADMIN_TOKEN),
      });
      assert.equal(response.status, 401, `${method} ${route}`);
      assert.equal(
        errorCode(await responseJson(response)),
        "content_governance_unauthorized",
        `${method} ${route}`,
      );
    }

    const adminDelete = await request(
      app.base,
      `/api/v1/admin/audit/content/${object.contentRef}`,
      {
        method: "DELETE",
        body: {
          reason: "administrator cannot delete without governance",
          approvalId: "apr_governance_delete_0001",
          force: true,
        },
        idempotency: "admin-delete-boundary-0001",
        headers: adminHeaders(ADMIN_TOKEN),
      },
    );
    assert.equal(adminDelete.status, 401);
    assert.equal(
      errorCode(await responseJson(adminDelete)),
      "content_governance_unauthorized",
    );

    const governanceBodyRead = await request(
      app.base,
      `/api/v1/admin/audit/content/${object.contentRef}`,
      {
        headers: adminHeaders(GOVERNANCE_TOKEN, {
          "x-audit-content-grant": "not-a-real-grant",
        }),
      },
    );
    assert.equal(governanceBodyRead.status, 401);
    assert.equal(
      errorCode(await responseJson(governanceBodyRead)),
      "content_admin_unauthorized",
    );
  } finally {
    await app.close();
  }
});

test("deletion proofs list, get, verify, and detect tampering", async () => {
  const app = await start();
  let originalReason;
  try {
    const object = await addObject(app);
    const deletion = await request(
      app.base,
      `/api/v1/admin/audit/content/${object.contentRef}`,
      {
        method: "DELETE",
        body: {
          reason: "data subject deletion request",
          approvalId: "apr_governance_delete_0002",
          force: true,
        },
        idempotency: "governance-proof-delete-0001",
        headers: adminHeaders(GOVERNANCE_TOKEN),
      },
    );
    const deletionBody = await responseJson(deletion);
    assert.equal(deletion.status, 200);
    assert.equal(deletionBody.deletion.contentRef, object.contentRef);
    assert.equal(Object.hasOwn(deletionBody.deletion, "proofMac"), false);
    const deletionId = deletionBody.deletion.deletionId;

    const listed = await request(
      app.base,
      "/api/v1/admin/audit/content/deletions",
      { headers: adminHeaders(GOVERNANCE_TOKEN) },
    );
    const listBody = await responseJson(listed);
    assert.equal(listed.status, 200);
    assert.equal(listBody.deletions.length, 1);
    const serialized = JSON.stringify(listBody);
    assert.equal(serialized.includes(object.body), false);
    assert.equal(serialized.includes("proofMac"), false);
    assert.equal(serialized.includes(app.root), false);
    assert.equal(serialized.includes(GOVERNANCE_TOKEN), false);

    const detail = await request(
      app.base,
      `/api/v1/admin/audit/content/deletions/${deletionId}`,
      { headers: adminHeaders(GOVERNANCE_TOKEN) },
    );
    assert.equal(detail.status, 200);
    assert.equal(
      (await responseJson(detail)).deletion.deletionId,
      deletionId,
    );

    const verified = await request(
      app.base,
      `/api/v1/admin/audit/content/deletions/${deletionId}/verify`,
      {
        method: "POST",
        headers: adminHeaders(GOVERNANCE_TOKEN),
      },
    );
    assert.equal(verified.status, 200);
    assert.equal((await responseJson(verified)).verification.valid, true);

    const proof = app.contentStore.index.deletionProofs[deletionId];
    originalReason = proof.reason;
    proof.reason = "tampered deletion proof reason";
    const tampered = await request(
      app.base,
      `/api/v1/admin/audit/content/deletions/${deletionId}/verify`,
      {
        method: "POST",
        headers: adminHeaders(GOVERNANCE_TOKEN),
      },
    );
    assert.equal(tampered.status, 200);
    assert.equal((await responseJson(tampered)).verification.valid, false);
  } finally {
    if (originalReason) {
      for (const proof of Object.values(app.contentStore.index.deletionProofs)) {
        if (proof.reason === "tampered deletion proof reason") {
          proof.reason = originalReason;
        }
      }
    }
    await app.close();
  }
});

test("export download returns encrypted .mge bytes with safe headers and list projections", async () => {
  const app = await start();
  try {
    const object = await addObject(
      app,
      {},
      "export plaintext that must never be returned by HTTP",
    );
    const created = await request(
      app.base,
      "/api/v1/admin/audit/content/exports",
      {
        body: {
          scope: { contentRefs: [object.contentRef] },
          purpose: "compliance_review",
          reason: "regulator export request 2026-42",
          approvalId: "apr_governance_export_0001",
          ttlSeconds: 60,
        },
        idempotency: "governance-export-create-0001",
        headers: adminHeaders(GOVERNANCE_TOKEN),
      },
    );
    const createdBody = await responseJson(created);
    assert.equal(created.status, 201);
    const { exportId } = createdBody.export;
    const { token } = createdBody;
    assert.match(exportId, /^exp_/);
    assert.match(token, /^[A-Za-z0-9_-]{16,4096}\.[A-Za-z0-9_-]{43}$/);

    const listed = await request(
      app.base,
      "/api/v1/admin/audit/content/exports",
      { headers: adminHeaders(GOVERNANCE_TOKEN) },
    );
    const listText = await listed.text();
    assert.equal(listed.status, 200);
    assert.equal(listText.includes(object.body), false);
    assert.equal(listText.includes(token), false);
    assert.equal(listText.includes(EXPORT_KEY.toString("hex")), false);
    assert.equal(listText.includes(app.root), false);

    const download = await request(
      app.base,
      `/api/v1/admin/audit/content/exports/${exportId}/download`,
      {
        headers: adminHeaders(GOVERNANCE_TOKEN, {
          "x-audit-export-token": token,
        }),
      },
    );
    assert.equal(download.status, 200);
    assert.equal(
      download.headers.get("content-type"),
      "application/octet-stream",
    );
    assert.match(
      download.headers.get("content-disposition"),
      new RegExp(`filename="magpie-export-${exportId}\\.mge"`),
    );
    assert.equal(download.headers.get("cache-control"), "no-store");
    assert.match(
      download.headers.get("x-audit-watermark"),
      /MAGPIE-AUDIT-EXPORT exp_/,
    );
    const headers = JSON.stringify(Object.fromEntries(download.headers));
    assert.equal(headers.includes(token), false);
    assert.equal(headers.includes(EXPORT_KEY.toString("hex")), false);
    assert.equal(headers.includes(object.body), false);

    const bytes = Buffer.from(await download.arrayBuffer());
    assert.equal(
      bytes.subarray(0, EXPORT_MAGIC.length).equals(EXPORT_MAGIC),
      true,
    );
    assert.equal(bytes.includes(Buffer.from(object.body)), false);
    assert.equal(bytes.includes(Buffer.from(token)), false);
    const packageValue = JSON.parse(
      app.contentExport.decryptPackage(bytes, exportId).toString("utf8"),
    );
    assert.equal(packageValue.objects[0].content, object.body);

    const reused = await request(
      app.base,
      `/api/v1/admin/audit/content/exports/${exportId}/download`,
      {
        headers: adminHeaders(GOVERNANCE_TOKEN, {
          "x-audit-export-token": token,
        }),
      },
    );
    assert.equal(reused.status, 409);
    assert.equal(
      errorCode(await responseJson(reused)),
      "content_export_token_reused",
    );
  } finally {
    await app.close();
  }
});

test("export persistence failure returns no file bytes over HTTP", async () => {
  const app = await start();
  try {
    const object = await addObject(
      app,
      {},
      "export persistence failure plaintext",
    );
    const created = await request(
      app.base,
      "/api/v1/admin/audit/content/exports",
      {
        body: {
          scope: { contentRefs: [object.contentRef] },
          purpose: "compliance_review",
          reason: "regulator export persistence test",
          approvalId: "apr_governance_export_0002",
          ttlSeconds: 60,
        },
        idempotency: "governance-export-persist-0001",
        headers: adminHeaders(GOVERNANCE_TOKEN),
      },
    );
    const createdBody = await responseJson(created);
    assert.equal(created.status, 201);
    const { exportId } = createdBody.export;
    const { token } = createdBody;

    const originalPersist = app.contentStore.persist.bind(app.contentStore);
    app.contentStore.persist = async () => {
      throw new Error("simulated HTTP export audit persistence failure");
    };
    try {
      const failed = await request(
        app.base,
        `/api/v1/admin/audit/content/exports/${exportId}/download`,
        {
          headers: adminHeaders(GOVERNANCE_TOKEN, {
            "x-audit-export-token": token,
          }),
        },
      );
      const failedText = await failed.text();
      assert.equal(failed.status, 503);
      assert.match(failed.headers.get("content-type"), /^application\/json/);
      assert.equal(failedText.includes(object.body), false);
      assert.equal(
        failedText.includes(EXPORT_MAGIC.toString("utf8")),
        false,
      );
      assert.equal(
        app.contentStore.index.exports[exportId].status,
        "active",
      );
    } finally {
      app.contentStore.persist = originalPersist;
    }

    const retry = await request(
      app.base,
      `/api/v1/admin/audit/content/exports/${exportId}/download`,
      {
        headers: adminHeaders(GOVERNANCE_TOKEN, {
          "x-audit-export-token": token,
        }),
      },
    );
    assert.equal(retry.status, 200);
  } finally {
    await app.close();
  }
});

test("corrupt indexes, invalid retention timestamps, and inverted windows fail closed", async () => {
  const variants = [
    (index) => {
      delete index.governanceIdempotency;
    },
    (index, object) => {
      index.objects[object.contentRef].contentRetentionExpiresAt = "not-a-date";
    },
    (index, object) => {
      index.objects[object.contentRef].metadataRetentionExpiresAt = new Date(
        new Date(index.objects[object.contentRef].contentRetentionExpiresAt)
          .getTime() - DAY_MS,
      ).toISOString();
    },
  ];

  for (const corrupt of variants) {
    const directory = tempDirectory();
    const store = new ContentStore({
      directory,
      key: CONTENT_KEY,
      proofSecret: PROOF_SECRET,
      now: () => new Date("2026-11-02T00:00:00.000Z").getTime(),
    });
    await store.load();
    const created = await store.createStream(
      contentRequest(),
      crypto.randomUUID(),
    );
    const finalized = await store.finalizeStream(
      created.stream.streamId,
      "retention corruption test body",
      REDACTION,
    );
    const index = JSON.parse(fs.readFileSync(store.indexPath, "utf8"));
    corrupt(index, { contentRef: finalized.contentRef });
    fs.writeFileSync(store.indexPath, `${JSON.stringify(index)}\n`);

    const corrupted = new ContentStore({
      directory,
      key: CONTENT_KEY,
      proofSecret: PROOF_SECRET,
    });
    await assert.rejects(
      corrupted.load(),
      (error) => error instanceof ContentStoreError
        && error.statusCode === 500
        && error.code === "content_store_corrupt",
    );
  }
});
