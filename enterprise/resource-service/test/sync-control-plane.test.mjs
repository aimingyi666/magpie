import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { mintSyncToken } from "../../lib/sync-token.js";
import { verifySignedManifest } from "../src/manifest.js";
import { createResourceServer } from "../src/service.js";

const SERVICE_TOKEN = ["sync", "control", "service", "token", "test"].join("-");
const SYNC_TOKEN_SECRET = ["sync", "control", "shared", "secret", "test", "fixture"].join("-");
const AUDIENCE = "magpie-enterprise-resource";

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-sync-control-"));
}

function writeSigningKey(root) {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const keyPath = path.join(root, "resource-signing-key.pem");
  fs.writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  return keyPath;
}

function configFor(root, overrides = {}) {
  return {
    bind: "127.0.0.1",
    port: 0,
    serviceToken: SERVICE_TOKEN,
    syncTokenSecret: SYNC_TOKEN_SECRET,
    syncTokenAudience: AUDIENCE,
    syncReportPath: path.join(root, "sync-reports.json"),
    storePath: path.join(root, "resource-store.json"),
    contentPath: path.join(root, "objects"),
    signingPrivateKeyPath: writeSigningKey(root),
    signingKeyId: "sync-control-test-v1",
    maxContentBytes: 1024 * 1024,
    maxBodyBytes: 2 * 1024 * 1024 + 64 * 1024,
    maxResources: 20,
    maxReleasesPerResource: 20,
    maxSnapshotBytes: 8 * 1024 * 1024,
    maxSnapshotResources: 200,
    maxSyncReportBytes: 256 * 1024,
    rateLimitPerMinute: 1000,
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

async function close(server) {
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
}

async function start(root, overrides = {}) {
  const result = await createResourceServer(configFor(root, overrides), { logger: () => {} });
  return { ...result, base: await listen(result.server) };
}

function idempotencyKey() {
  return crypto.randomUUID();
}

async function request(base, route, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.token !== null) headers.authorization = `Bearer ${options.token ?? SERVICE_TOKEN}`;
  if (options.actor !== null) headers["x-magpie-actor"] = options.actor ?? "admin_platform";
  if (options.idempotency) headers["idempotency-key"] = options.idempotency;
  let body;
  if (options.body !== undefined) {
    headers["content-type"] = "application/json";
    body = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
  }
  return fetch(`${base}${route}`, {
    method: options.method || (body === undefined ? "GET" : "POST"),
    headers,
    body,
  });
}

async function jsonBody(response) {
  return JSON.parse(await response.text());
}

function syncToken({
  organizationIds = ["org_engineering"],
  userId = "usr_alice",
  deviceId = "dev_alice_windows",
  audience = AUDIENCE,
  now = new Date(),
  ttlSeconds = 300,
} = {}) {
  return mintSyncToken({
    secret: SYNC_TOKEN_SECRET,
    userId,
    deviceId,
    organizationIds,
    audience,
    now,
    ttlSeconds,
  }).token;
}

async function createAndPublish(base, {
  name = "Engineering baseline",
  assignments = ["org_engineering"],
  content = "# Engineering baseline\n\nUse signed enterprise resources.\n",
  resourceVersion = `2026.11.${crypto.randomInt(1, 100000)}`,
} = {}) {
  const createdResponse = await request(base, "/api/v1/admin/resources", {
    idempotency: idempotencyKey(),
    body: {
      kind: "instructions",
      name,
      description: "Shared engineering instructions",
      publisher: "enterprise-platform",
      deliveryMode: "forced",
      assignments,
      compatibility: { minClientVersion: "0.2.0" },
      operationId: `op_create_${crypto.randomUUID()}`,
      reason: "Create a resource for sync testing",
    },
  });
  const created = await jsonBody(createdResponse);
  assert.equal(createdResponse.status, 201, JSON.stringify(created));

  const releaseResponse = await request(
    base,
    `/api/v1/admin/resources/${created.resource.id}/releases`,
    {
      idempotency: idempotencyKey(),
      body: {
        resourceVersion,
        mediaType: "text/markdown",
        contentBase64: Buffer.from(content).toString("base64"),
        operationId: `op_release_${crypto.randomUUID()}`,
        reason: "Create an immutable candidate",
        expectedUpdatedAt: created.resource.updatedAt,
      },
    },
  );
  const release = await jsonBody(releaseResponse);
  assert.equal(releaseResponse.status, 201, JSON.stringify(release));

  const publishResponse = await request(
    base,
    `/api/v1/admin/resources/${created.resource.id}/publish`,
    {
      idempotency: idempotencyKey(),
      body: {
        releaseId: release.release.id,
        approvalId: `apr_${crypto.randomUUID()}`,
        operationId: `op_publish_${crypto.randomUUID()}`,
        reason: "Publish the approved test resource",
        expectedUpdatedAt: release.resource.updatedAt,
      },
    },
  );
  const published = await jsonBody(publishResponse);
  assert.equal(publishResponse.status, 200, JSON.stringify(published));
  return published;
}

test("desired state requires a short-lived sync credential and only returns assigned published resources", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const engineering = await createAndPublish(app.base, { name: "Engineering only" });
    await createAndPublish(app.base, {
      name: "Sales only",
      assignments: ["org_sales"],
      resourceVersion: "2026.11.2",
    });
    const draftResponse = await request(app.base, "/api/v1/admin/resources", {
      idempotency: idempotencyKey(),
      body: {
        kind: "skill",
        name: "Draft resource",
        description: "Must not reach clients",
        publisher: "enterprise-platform",
        deliveryMode: "recommended",
        assignments: ["org_engineering"],
        compatibility: { minClientVersion: "0.2.0" },
        operationId: `op_draft_${crypto.randomUUID()}`,
        reason: "Create a draft test resource",
      },
    });
    assert.equal(draftResponse.status, 201);

    const token = syncToken();
    const response = await request(app.base, "/api/v1/client/sync/desired-state", { token });
    const desired = await jsonBody(response);
    assert.equal(response.status, 200, JSON.stringify(desired));
    assert.deepEqual(Object.keys(desired).sort(), ["generatedAt", "resources", "revision", "schemaVersion"]);
    assert.match(desired.revision, /^sha256:[a-f0-9]{64}$/);
    assert.equal(desired.resources.length, 1);
    assert.equal(desired.resources[0].manifest.resourceId, engineering.resource.id);
    const content = Buffer.from(desired.resources[0].contentBase64, "base64");
    assert.equal(
      verifySignedManifest(app.service.signing.publicKey, desired.resources[0].manifest, content).valid,
      true,
    );

    const etag = response.headers.get("etag");
    assert.equal(etag, `"${desired.revision}"`);
    const notModified = await request(app.base, "/api/v1/client/sync/desired-state", {
      token,
      headers: { "if-none-match": etag },
    });
    assert.equal(notModified.status, 304);
    assert.equal((await notModified.text()).length, 0);

    const second = await request(app.base, "/api/v1/client/sync/desired-state", { token });
    assert.equal((await jsonBody(second)).revision, desired.revision);

    const missing = await request(app.base, "/api/v1/client/sync/desired-state", { token: null });
    assert.equal(missing.status, 401);
    assert.equal((await jsonBody(missing)).error.code, "missing_sync_credential");

    const serviceCredential = await request(app.base, "/api/v1/client/sync/desired-state");
    assert.equal(serviceCredential.status, 401);
    assert.equal((await jsonBody(serviceCredential)).error.code, "invalid_sync_token");

    const adminWithSyncToken = await request(app.base, "/api/v1/admin/resources", { token });
    assert.equal(adminWithSyncToken.status, 401);
    assert.equal((await jsonBody(adminWithSyncToken)).error.code, "unauthorized");

    const tampered = `${token.slice(0, -1)}${token.endsWith("A") ? "B" : "A"}`;
    const tamperedResponse = await request(app.base, "/api/v1/client/sync/desired-state", { token: tampered });
    assert.equal(tamperedResponse.status, 401);
    assert.equal((await jsonBody(tamperedResponse)).error.code, "invalid_sync_token");

    const wrongAudience = syncToken({ audience: "magpie-enterprise-other" });
    const wrongAudienceResponse = await request(app.base, "/api/v1/client/sync/desired-state", {
      token: wrongAudience,
    });
    assert.equal(wrongAudienceResponse.status, 401);
    assert.equal((await jsonBody(wrongAudienceResponse)).error.code, "invalid_sync_token");

    const expired = syncToken({ now: new Date(Date.now() - 10 * 60 * 1000), ttlSeconds: 60 });
    const expiredResponse = await request(app.base, "/api/v1/client/sync/desired-state", { token: expired });
    assert.equal(expiredResponse.status, 401);
    assert.equal((await jsonBody(expiredResponse)).error.code, "sync_token_expired");
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("sync reports bind identity to the credential and admin reads them with the service token only", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const published = await createAndPublish(app.base);
    const token = syncToken();
    const desiredResponse = await request(app.base, "/api/v1/client/sync/desired-state", { token });
    const desired = await jsonBody(desiredResponse);
    const resource = desired.resources[0].manifest;
    const reportBody = {
      schemaVersion: 1,
      revision: desired.revision,
      clientVersion: "1.4.0",
      status: "synced",
      installed: [{
        resourceId: resource.resourceId,
        releaseId: resource.releaseId,
        manifestDigest: resource.manifestDigest,
      }],
      drift: [],
      reportedAt: new Date().toISOString(),
    };

    const rejectedIdentity = await request(app.base, "/api/v1/client/sync/report", {
      token,
      body: { ...reportBody, userId: "usr_mallory", deviceId: "dev_other" },
    });
    assert.equal(rejectedIdentity.status, 400);
    assert.equal((await jsonBody(rejectedIdentity)).error.code, "invalid_request");

    const accepted = await request(app.base, "/api/v1/client/sync/report", {
      token,
      body: reportBody,
    });
    const acceptedBody = await jsonBody(accepted);
    assert.equal(accepted.status, 202, JSON.stringify(acceptedBody));

    const admin = await request(app.base, "/api/v1/admin/sync-reports");
    assert.equal(admin.status, 200);
    const reports = (await jsonBody(admin)).reports;
    assert.equal(reports.length, 1);
    assert.equal(reports[0].userId, "usr_alice");
    assert.equal(reports[0].deviceId, "dev_alice_windows");
    assert.equal(reports[0].revision, desired.revision);
    assert.equal(reports[0].installed[0].resourceId, published.resource.id);

    const byDevice = await request(app.base, "/api/v1/admin/sync-reports/dev_alice_windows");
    assert.equal(byDevice.status, 200);
    assert.equal((await jsonBody(byDevice)).report.deviceId, "dev_alice_windows");

    const adminWithSyncOnly = await request(app.base, "/api/v1/admin/sync-reports", { token });
    assert.equal(adminWithSyncOnly.status, 401);

    const persisted = fs.readFileSync(path.join(root, "sync-reports.json"), "utf8");
    assert.equal(persisted.includes("mss1."), false);
    assert.equal(persisted.includes("Engineering baseline"), false);
    assert.equal(persisted.includes(Buffer.from("# Engineering baseline").toString("base64")), false);
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("snapshot and report limits fail closed without exposing token or resource content", async () => {
  const root = tempDirectory();
  const app = await start(root, { maxSnapshotResources: 1 });
  try {
    await createAndPublish(app.base, { name: "First", resourceVersion: "2026.12.1" });
    await createAndPublish(app.base, { name: "Second", resourceVersion: "2026.12.2" });
    const token = syncToken();
    const limited = await request(app.base, "/api/v1/client/sync/desired-state", { token });
    assert.equal(limited.status, 409);
    assert.equal((await jsonBody(limited)).error.code, "sync_snapshot_limit_reached");

    const oversizedInstalled = Array.from({ length: 501 }, (_, index) => ({
      resourceId: `res_${String(index).padStart(16, "0")}`,
      releaseId: `rel_${String(index).padStart(16, "0")}`,
      manifestDigest: `sha256:${"0".repeat(64)}`,
    }));
    const tooMany = await request(app.base, "/api/v1/client/sync/report", {
      token,
      body: {
        schemaVersion: 1,
        revision: `sha256:${"1".repeat(64)}`,
        clientVersion: "1.4.0",
        status: "synced",
        installed: oversizedInstalled,
        drift: [],
        reportedAt: new Date().toISOString(),
      },
    });
    assert.equal(tooMany.status, 400);
    assert.equal((await jsonBody(tooMany)).error.code, "invalid_sync_report");

    const freeText = await request(app.base, "/api/v1/client/sync/report", {
      token,
      body: {
        schemaVersion: 1,
        revision: `sha256:${"1".repeat(64)}`,
        clientVersion: "1.4.0",
        status: "synced",
        installed: [],
        drift: [],
        reportedAt: new Date().toISOString(),
        note: "arbitrary text must not be stored",
      },
    });
    assert.equal(freeText.status, 400);
    assert.equal((await jsonBody(freeText)).error.code, "invalid_request");
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("oversized desired-state payloads fail before an incomplete snapshot is returned", async () => {
  const root = tempDirectory();
  const app = await start(root, { maxSnapshotBytes: 64 * 1024 });
  try {
    const content = "x".repeat(50 * 1024);
    await createAndPublish(app.base, { content, resourceVersion: "2026.12.3" });
    const response = await request(app.base, "/api/v1/client/sync/desired-state", {
      token: syncToken(),
    });
    assert.equal(response.status, 409);
    assert.equal((await jsonBody(response)).error.code, "sync_snapshot_too_large");
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});
