import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { loadConfig } from "../src/config.js";
import { createAuditServer } from "../src/service.js";

const SERVICE_TOKEN = ["audit", "content", "service", "test", "token", "123456789"].join("-");
const ADMIN_TOKEN = ["audit", "content", "admin", "test", "token", "123456789"].join("-");
const GRANT_SECRET = ["audit", "content", "grant", "test", "secret", "123456789"].join("-");
const CURSOR_SECRET = ["audit", "content", "cursor", "test", "secret", "123456789"].join("-");
const ENCRYPTION_KEY = Buffer.alloc(32, 0x5a);
const ADMIN_ID = "admin_audit_001";
const ORGANIZATION_ID = "org_example";
const ADMIN_SESSION = "session_admin_001";
const EMAIL = "employee.real@example.com";
const API_KEY = `sk-${"q".repeat(24)}`;
const REDACTION = {
  ruleVersion: "m4b-redaction-v1",
  replacements: 2,
  categories: { email: 1, api_key: 1 },
};

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
    contentAdminEnabled: true,
    contentEncryptionKey: ENCRYPTION_KEY,
    contentAdminToken: ADMIN_TOKEN,
    contentGrantSecret: GRANT_SECRET,
    contentCursorSecret: CURSOR_SECRET,
    contentOrganizationId: ORGANIZATION_ID,
    contentGrantTtlSeconds: 60,
    contentStoreDir: path.join(root, "audit-content"),
    contentGrantStorePath: path.join(root, "audit-content", "content-grants.json"),
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

function adminHeaders(overrides = {}) {
  return {
    authorization: `Bearer ${ADMIN_TOKEN}`,
    "x-audit-admin-id": ADMIN_ID,
    "x-audit-organization-id": ORGANIZATION_ID,
    "x-audit-admin-session": ADMIN_SESSION,
    ...overrides,
  };
}

function adminRequest(base, route, options = {}) {
  return request(base, route, {
    ...options,
    token: null,
    headers: {
      ...adminHeaders(options.headers),
    },
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

async function finalizeContent(app, options = {}) {
  const createKey = options.createKey || crypto.randomUUID();
  const created = await request(app.base, "/api/v1/internal/audit/content/streams", {
    idempotency: createKey,
    body: contentRequest(options.request),
  });
  const createdBody = await responseJson(created);
  assert.equal(created.status, 202);
  const streamId = createdBody.stream.streamId;
  const chunkRoute = `/api/v1/internal/audit/content/streams/${streamId}/chunks`;
  const first = await request(app.base, chunkRoute, {
    idempotency: crypto.randomUUID(),
    body: chunk(0, options.first || `employee ${EMAIL} authenticated with `),
  });
  assert.equal(first.status, 200);
  const finalChunk = await request(app.base, chunkRoute, {
    idempotency: crypto.randomUUID(),
    body: chunk(1, options.last || `API key ${API_KEY}`, true),
  });
  const finalBody = await responseJson(finalChunk);
  assert.equal(finalChunk.status, 200);
  assert.equal(finalBody.finalized, true);
  return {
    streamId,
    contentRef: finalBody.stream.contentRef,
    stream: finalBody.stream,
    createKey,
  };
}

async function issueGrant(app, contentRef, overrides = {}) {
  const response = await adminRequest(
    app.base,
    `/api/v1/admin/audit/content/${contentRef}/grants`,
    {
      body: {
        purpose: "security_investigation",
        reason: "security case 42",
        approvalId: "apr_read_service_0001",
        ttlSeconds: 30,
        ...overrides,
      },
    },
  );
  return { response, body: await responseJson(response) };
}

test("content APIs are closed by default and create no content directory", async () => {
  const root = tempDirectory();
  const app = await start(root, {
    contentEnabled: false,
    contentAdminEnabled: false,
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

test("content administration stays disabled and creates no grant ledger by default", async () => {
  const root = tempDirectory();
  const app = await start(root, {
    contentAdminEnabled: false,
    contentAdminToken: "",
    contentGrantSecret: "",
    contentCursorSecret: "",
    contentOrganizationId: "",
  });
  try {
    const response = await adminRequest(
      app.base,
      "/api/v1/admin/audit/content/streams",
    );
    assert.equal(response.status, 503);
    assert.equal((await responseJson(response)).error.code, "content_admin_disabled");
    assert.equal(fs.existsSync(path.join(root, "audit-content", "content-grants.json")), false);
  } finally {
    await app.close();
  }
});

test("L2 flow requires administrator identity, issues a one-time grant and audits reads", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const content = await finalizeContent(app);
    const streamId = content.streamId;
    const contentRef = content.contentRef;
    assert.match(contentRef, /^ct_[A-Za-z0-9_-]{43}$/);
    assert.equal(content.stream.redaction.categories.email, 1);
    assert.equal(content.stream.redaction.categories.api_key, 1);

    const noAdminToken = await request(
      app.base,
      `/api/v1/admin/audit/content/streams/${streamId}`,
      { token: null, headers: {} },
    );
    assert.equal(noAdminToken.status, 401);
    assert.equal((await responseJson(noAdminToken)).error.code, "content_admin_unauthorized");

    const noAdminIdentity = await adminRequest(
      app.base,
      `/api/v1/admin/audit/content/streams/${streamId}`,
      { headers: { "x-audit-admin-id": "" } },
    );
    assert.equal(noAdminIdentity.status, 400);
    assert.equal(
      (await responseJson(noAdminIdentity)).error.code,
      "content_admin_identity_required",
    );

    const wrongOrganization = await adminRequest(
      app.base,
      `/api/v1/admin/audit/content/streams/${streamId}`,
      { headers: { "x-audit-organization-id": "org_other" } },
    );
    assert.equal(wrongOrganization.status, 403);
    assert.equal(
      (await responseJson(wrongOrganization)).error.code,
      "content_admin_scope_mismatch",
    );

    const metadata = await adminRequest(
      app.base,
      `/api/v1/admin/audit/content/streams/${streamId}`,
    );
    const metadataBody = await responseJson(metadata);
    assert.equal(metadata.status, 200);
    assert.equal(metadataBody.stream.status, "finalized");
    assert.equal(metadataBody.stream.contentRef, contentRef);
    assert.equal(Object.hasOwn(metadataBody.stream, "content"), false);

    const noGrant = await adminRequest(app.base, `/api/v1/admin/audit/content/${contentRef}`);
    assert.equal(noGrant.status, 401);
    assert.equal((await responseJson(noGrant)).error.code, "content_grant_required");

    const invalidGrantRequest = await adminRequest(
      app.base,
      `/api/v1/admin/audit/content/${contentRef}/grants`,
      {
        body: {
          purpose: "security_investigation",
          reason: "security case 42",
          approvalId: "short",
        },
      },
    );
    assert.equal(invalidGrantRequest.status, 400);
    assert.equal(
      (await responseJson(invalidGrantRequest)).error.code,
      "content_grant_approval_required",
    );

    const missingRef = `ct_${crypto.randomBytes(32).toString("base64url")}`;
    const missingGrant = await issueGrant(app, missingRef);
    assert.equal(missingGrant.response.status, 404);
    assert.equal(missingGrant.body.error.code, "content_object_not_found");

    const issued = await issueGrant(app, contentRef);
    assert.equal(issued.response.status, 201);
    assert.match(issued.body.grant, /^mcg1_/);
    assert.equal(issued.body.contentRef, contentRef);

    const read = await adminRequest(app.base, `/api/v1/admin/audit/content/${contentRef}`, {
      headers: { "x-audit-content-grant": issued.body.grant },
    });
    const readBody = await responseJson(read);
    assert.equal(read.status, 200);
    assert.equal(readBody.content.includes(EMAIL), false);
    assert.equal(readBody.content.includes(API_KEY), false);
    assert.equal(readBody.content.includes("[REDACTED:email]"), true);
    assert.match(read.headers.get("x-audit-watermark"), /^MAGPIE-AUDIT-CONTENT ct_/);

    const access = await app.contentStore.listAccess(contentRef);
    assert.equal(access.length, 1);
    assert.equal(access[0].outcome, "success");
    assert.equal(access[0].approvalId, "apr_read_service_0001");
    assert.equal(access[0].authorizationId, "apr_read_service_0001");
    assert.equal(access[0].adminId, ADMIN_ID);
    assert.equal(access[0].organizationId, ORGANIZATION_ID);
    assert.equal(access[0].purpose, "security_investigation");
    assert.match(access[0].grantId, /^grt_/);

    const replay = await adminRequest(app.base, `/api/v1/admin/audit/content/${contentRef}`, {
      headers: { "x-audit-content-grant": issued.body.grant },
    });
    assert.equal(replay.status, 409);
    assert.equal((await responseJson(replay)).error.code, "content_grant_reused");

    for (const file of filesUnder(root)) {
      const data = fs.readFileSync(file);
      assert.equal(data.includes(Buffer.from(EMAIL)), false, `raw email persisted in ${file}`);
      assert.equal(data.includes(Buffer.from(API_KEY)), false, `raw API key persisted in ${file}`);
      assert.equal(data.includes(Buffer.from(SERVICE_TOKEN)), false, `service token persisted in ${file}`);
      assert.equal(data.includes(Buffer.from(ADMIN_TOKEN)), false, `admin token persisted in ${file}`);
      assert.equal(data.includes(Buffer.from(GRANT_SECRET)), false, `grant secret persisted in ${file}`);
      assert.equal(data.includes(Buffer.from(CURSOR_SECRET)), false, `cursor secret persisted in ${file}`);
    }
  } finally {
    await app.close();
  }
});

test("failed, missing and tampered content reads are audited without leaking bodies", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const content = await finalizeContent(app, {
      request: {
        requestId: "req_m4b_service_failure_0001",
        sessionId: "ses_m4b_service_failure_0001",
      },
    });
    const missingRef = `ct_${crypto.randomBytes(32).toString("base64url")}`;
    const missingGrant = await app.contentGrants.issue({
      contentRef: missingRef,
      adminId: ADMIN_ID,
      organizationId: ORGANIZATION_ID,
      sessionId: ADMIN_SESSION,
      purpose: "security_investigation",
      reason: "missing object access",
      approvalId: "apr_read_missing_0001",
      ttlSeconds: 30,
    });
    const missing = await adminRequest(app.base, `/api/v1/admin/audit/content/${missingRef}`, {
      headers: { "x-audit-content-grant": missingGrant.grant },
    });
    assert.equal(missing.status, 404);
    assert.equal((await responseJson(missing)).error.code, "content_object_not_found");
    const missingAccess = await app.contentStore.listAccess(missingRef);
    assert.equal(missingAccess.length, 1);
    assert.equal(missingAccess[0].outcome, "failed");
    assert.equal(missingAccess[0].errorCode, "content_object_not_found");

    const objectPath = path.join(
      root,
      "audit-content",
      "objects",
      `${content.contentRef}.bin`,
    );
    const payload = fs.readFileSync(objectPath);
    payload[payload.length - 1] ^= 0xff;
    fs.writeFileSync(objectPath, payload);

    const tamperedGrant = await issueGrant(app, content.contentRef, {
      reason: "tampered object access",
      approvalId: "apr_read_tampered_0001",
    });
    assert.equal(tamperedGrant.response.status, 201);
    const tampered = await adminRequest(
      app.base,
      `/api/v1/admin/audit/content/${content.contentRef}`,
      { headers: { "x-audit-content-grant": tamperedGrant.body.grant } },
    );
    const tamperedBody = await responseJson(tampered);
    assert.equal(tampered.status, 500);
    assert.equal(tamperedBody.error.code, "content_integrity_failed");
    assert.equal(JSON.stringify(tamperedBody).includes(EMAIL), false);
    const tamperedAccess = await app.contentStore.listAccess(content.contentRef);
    assert.equal(tamperedAccess[0].outcome, "failed");
    assert.equal(tamperedAccess[0].errorCode, "content_integrity_failed");
  } finally {
    await app.close();
  }
});

test("content body is withheld when the access audit cannot be persisted", async () => {
  const root = tempDirectory();
  const app = await start(root);
  const originalPersist = app.contentStore.persist.bind(app.contentStore);
  try {
    const content = await finalizeContent(app, {
      request: {
        requestId: "req_m4b_service_audit_failure_0001",
        sessionId: "ses_m4b_service_audit_failure_0001",
      },
    });
    const issued = await issueGrant(app, content.contentRef);
    assert.equal(issued.response.status, 201);

    app.contentStore.persist = async () => {
      throw new Error("simulated audit index write failure");
    };
    const read = await adminRequest(app.base, `/api/v1/admin/audit/content/${content.contentRef}`, {
      headers: { "x-audit-content-grant": issued.body.grant },
    });
    const body = await responseJson(read);
    assert.equal(read.status, 503);
    assert.equal(body.error.code, "content_store_unavailable");
    assert.equal(JSON.stringify(body).includes(EMAIL), false);
    assert.equal(JSON.stringify(body).includes("[REDACTED:email]"), false);
  } finally {
    app.contentStore.persist = originalPersist;
    await app.close();
  }
});

test("content routes require their service or administrator token and fail closed", async () => {
  const root = tempDirectory();
  const app = await start(root, { contentMaxBodyBytes: 1024 });
  try {
    const unauthorized = await request(
      app.base,
      "/api/v1/internal/audit/content/streams",
      {
        token: ADMIN_TOKEN,
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

    const serviceOnAdmin = await request(
      app.base,
      "/api/v1/admin/audit/content/streams",
    );
    assert.equal(serviceOnAdmin.status, 401);
    assert.equal(
      (await responseJson(serviceOnAdmin)).error.code,
      "content_admin_unauthorized",
    );
  } finally {
    await app.close();
  }
});

test("content configuration fails closed for retired, missing and reused secrets", () => {
  const base = {
    AUDIT_SERVICE_TOKEN: SERVICE_TOKEN,
    AUDIT_CONTENT_ENABLED: "false",
  };
  assert.equal(loadConfig(base).contentEncryptionKey, null);
  assert.equal(loadConfig(base).contentAdminEnabled, false);
  assert.throws(
    () => loadConfig({
      ...base,
      AUDIT_CONTENT_READ_TOKEN: ["retired", "content", "read", "token", "123456789"].join("-"),
    }),
    /AUDIT_CONTENT_READ_TOKEN is retired/,
  );
  assert.throws(
    () => loadConfig({ ...base, AUDIT_CONTENT_ADMIN_ENABLED: "true" }),
    /AUDIT_CONTENT_ADMIN_ENABLED=true requires AUDIT_CONTENT_ENABLED=true/,
  );
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

  const adminBase = {
    ...base,
    AUDIT_CONTENT_ENABLED: "true",
    AUDIT_CONTENT_ADMIN_ENABLED: "true",
    AUDIT_CONTENT_ENCRYPTION_KEY: ENCRYPTION_KEY.toString("hex"),
    AUDIT_CONTENT_ORGANIZATION_ID: ORGANIZATION_ID,
  };
  assert.throws(
    () => loadConfig({
      ...adminBase,
      AUDIT_CONTENT_ADMIN_TOKEN: ADMIN_TOKEN,
    }),
    /AUDIT_CONTENT_GRANT_SECRET is required/,
  );
  assert.throws(
    () => loadConfig({
      ...adminBase,
      AUDIT_CONTENT_ADMIN_TOKEN: ADMIN_TOKEN,
      AUDIT_CONTENT_GRANT_SECRET: GRANT_SECRET,
    }),
    /AUDIT_CONTENT_CURSOR_SECRET is required/,
  );
  assert.throws(
    () => loadConfig({
      ...adminBase,
      AUDIT_CONTENT_ADMIN_TOKEN: ADMIN_TOKEN,
      AUDIT_CONTENT_GRANT_SECRET: GRANT_SECRET,
      AUDIT_CONTENT_CURSOR_SECRET: CURSOR_SECRET,
      AUDIT_CONTENT_ORGANIZATION_ID: "",
    }),
    /AUDIT_CONTENT_ORGANIZATION_ID must be a valid organization id/,
  );
  assert.throws(
    () => loadConfig({
      ...adminBase,
      AUDIT_CONTENT_ADMIN_TOKEN: SERVICE_TOKEN,
      AUDIT_CONTENT_GRANT_SECRET: GRANT_SECRET,
      AUDIT_CONTENT_CURSOR_SECRET: CURSOR_SECRET,
    }),
    /AUDIT_SERVICE_TOKEN must differ from AUDIT_CONTENT_ADMIN_TOKEN/,
  );
  assert.throws(
    () => loadConfig({
      ...adminBase,
      AUDIT_CONTENT_ADMIN_TOKEN: ADMIN_TOKEN,
      AUDIT_CONTENT_GRANT_SECRET: CURSOR_SECRET,
      AUDIT_CONTENT_CURSOR_SECRET: CURSOR_SECRET,
    }),
    /AUDIT_CONTENT_GRANT_SECRET must differ from AUDIT_CONTENT_CURSOR_SECRET/,
  );

  const loaded = loadConfig({
    ...adminBase,
    AUDIT_CONTENT_ADMIN_TOKEN: ADMIN_TOKEN,
    AUDIT_CONTENT_GRANT_SECRET: GRANT_SECRET,
    AUDIT_CONTENT_CURSOR_SECRET: CURSOR_SECRET,
    AUDIT_CONTENT_GRANT_TTL_SECONDS: "45",
  });
  assert.equal(loaded.contentEncryptionKey.length, 32);
  assert.equal(loaded.contentAdminEnabled, true);
  assert.equal(loaded.contentAdminToken, ADMIN_TOKEN);
  assert.equal(loaded.contentGrantSecret, GRANT_SECRET);
  assert.equal(loaded.contentCursorSecret, CURSOR_SECRET);
  assert.equal(loaded.contentOrganizationId, ORGANIZATION_ID);
  assert.equal(loaded.contentGrantTtlSeconds, 45);
  assert.equal(
    loaded.contentGrantStorePath,
    path.join(loaded.contentStoreDir, "content-grants.json"),
  );
});
