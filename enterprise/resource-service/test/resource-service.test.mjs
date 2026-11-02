import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildSignedManifest,
  verifySignedManifest,
} from "../src/manifest.js";
import { ResourceStore } from "../src/store.js";
import { createResourceServer } from "../src/service.js";

const TOKEN = ["resource", "service", "test", "token", "not", "real"].join("-");

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-resource-service-"));
}

function writeSigningKey(root) {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const keyPath = path.join(root, "resource-signing-key.pem");
  fs.writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  return keyPath;
}

function baseConfig(root, overrides = {}) {
  return {
    bind: "127.0.0.1",
    port: 0,
    serviceToken: TOKEN,
    storePath: path.join(root, "resource-store.json"),
    contentPath: path.join(root, "objects"),
    signingPrivateKeyPath: writeSigningKey(root),
    signingKeyId: "resource-test-v1",
    maxContentBytes: 1024 * 1024,
    maxBodyBytes: 2 * 1024 * 1024 + 64 * 1024,
    maxResources: 20,
    maxReleasesPerResource: 20,
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
  const serverResult = await createResourceServer(baseConfig(root, overrides), { logger: () => {} });
  const base = await listen(serverResult.server);
  return { ...serverResult, base };
}

async function request(base, route, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.token !== null) headers.authorization = `Bearer ${options.token ?? TOKEN}`;
  if (options.actor !== null) headers["x-magpie-actor"] = options.actor ?? "admin_platform";
  if (options.idempotency) headers["idempotency-key"] = options.idempotency;
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

function idempotencyKey() {
  return crypto.randomUUID();
}

function createPayload(overrides = {}) {
  return {
    kind: "instructions",
    name: "Engineering baseline",
    description: "Shared engineering instructions",
    publisher: "enterprise-platform",
    deliveryMode: "forced",
    assignments: ["org_engineering"],
    compatibility: { minClientVersion: "0.2.0" },
    operationId: `op_create_${crypto.randomUUID()}`,
    reason: "Create the engineering baseline resource",
    ...overrides,
  };
}

async function createResource(base, overrides = {}, key = idempotencyKey()) {
  const response = await request(base, "/api/v1/admin/resources", {
    idempotency: key,
    body: createPayload(overrides),
  });
  const body = await responseJson(response);
  return { response, body, key };
}

function releasePayload(expectedUpdatedAt, overrides = {}) {
  const content = Buffer.from("# Engineering baseline\n\nUse signed enterprise resources.\n");
  return {
    resourceVersion: "2026.11.1",
    mediaType: "text/markdown",
    contentBase64: content.toString("base64"),
    operationId: `op_release_${crypto.randomUUID()}`,
    reason: "Create an immutable resource candidate",
    expectedUpdatedAt,
    ...overrides,
  };
}

async function createRelease(base, resourceId, expectedUpdatedAt, overrides = {}, key = idempotencyKey()) {
  const response = await request(base, `/api/v1/admin/resources/${resourceId}/releases`, {
    idempotency: key,
    body: releasePayload(expectedUpdatedAt, overrides),
  });
  const body = await responseJson(response);
  return { response, body, key };
}

async function publishRelease(base, resourceId, releaseId, expectedUpdatedAt, overrides = {}, key = idempotencyKey()) {
  const response = await request(base, `/api/v1/admin/resources/${resourceId}/publish`, {
    idempotency: key,
    body: {
      releaseId,
      approvalId: `apr_${crypto.randomUUID()}`,
      operationId: `op_publish_${crypto.randomUUID()}`,
      reason: "Publish the approved resource release",
      expectedUpdatedAt,
      ...overrides,
    },
  });
  const body = await responseJson(response);
  return { response, body, key };
}

async function rollbackRelease(base, resourceId, releaseId, expectedUpdatedAt, overrides = {}, key = idempotencyKey()) {
  const response = await request(base, `/api/v1/admin/resources/${resourceId}/rollback`, {
    idempotency: key,
    body: {
      releaseId,
      approvalId: `apr_${crypto.randomUUID()}`,
      operationId: `op_rollback_${crypto.randomUUID()}`,
      reason: "Restore the previous approved resource release",
      expectedUpdatedAt,
      ...overrides,
    },
  });
  const body = await responseJson(response);
  return { response, body, key };
}

test("healthz is public while management routes require the service token", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const health = await request(app.base, "/healthz", { token: null, actor: null });
    assert.equal(health.status, 200);
    assert.equal((await responseJson(health)).service, "resource-service");

    const missing = await request(app.base, "/api/v1/admin/resources", { token: null, actor: null });
    assert.equal(missing.status, 401);
    assert.equal((await responseJson(missing)).error.code, "unauthorized");

    const wrong = await request(app.base, "/api/v1/admin/resources", { token: "wrong", actor: null });
    assert.equal(wrong.status, 401);

    const signing = await request(app.base, "/api/v1/admin/signing-key");
    assert.equal(signing.status, 200);
    const text = await signing.text();
    const body = JSON.parse(text);
    assert.equal(body.signingKey.algorithm, "ed25519");
    assert.match(body.signingKey.fingerprint, /^sha256:[a-f0-9]{64}$/);
    assert.equal(text.includes("PRIVATE KEY"), false);
    assert.equal(text.includes("privateKey"), false);
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("a release can be published and exposes a manifest whose signature verifies", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const created = await createResource(app.base);
    assert.equal(created.response.status, 201);
    const resourceId = created.body.resource.id;
    const release = await createRelease(app.base, resourceId, created.body.resource.updatedAt);
    assert.equal(release.response.status, 201, JSON.stringify(release.body));
    const releaseId = release.body.release.id;
    assert.equal(release.body.release.status, "candidate");

    const published = await publishRelease(
      app.base,
      resourceId,
      releaseId,
      release.body.resource.updatedAt,
    );
    assert.equal(published.response.status, 200);
    assert.equal(published.body.resource.currentReleaseId, releaseId);

    const manifestResponse = await request(
      app.base,
      `/api/v1/admin/resources/${resourceId}/releases/${releaseId}/manifest`,
    );
    assert.equal(manifestResponse.status, 200);
    const manifestBody = await responseJson(manifestResponse);
    assert.equal(manifestBody.verified, true);
    const contentResponse = await request(
      app.base,
      `/api/v1/admin/resources/${resourceId}/releases/${releaseId}/content`,
    );
    assert.equal(contentResponse.status, 200);
    const content = Buffer.from(await contentResponse.arrayBuffer());
    assert.equal(
      verifySignedManifest(app.service.signing.publicKey, manifestBody.manifest, content).valid,
      true,
    );
    assert.equal(contentResponse.headers.get("x-content-sha256"), manifestBody.manifest.hash);
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("manifest and object-content tampering fail closed", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const created = await createResource(app.base);
    const release = await createRelease(app.base, created.body.resource.id, created.body.resource.updatedAt);
    const releaseId = release.body.release.id;
    const resourceId = created.body.resource.id;
    const manifestResponse = await request(
      app.base,
      `/api/v1/admin/resources/${resourceId}/releases/${releaseId}/manifest`,
    );
    const manifest = (await responseJson(manifestResponse)).manifest;
    const content = Buffer.from("# Engineering baseline\n\nUse signed enterprise resources.\n");

    const changed = structuredClone(manifest);
    changed.publisher = "attacker";
    assert.equal(verifySignedManifest(app.service.signing.publicKey, changed, content).valid, false);
    const extra = { ...manifest, unexpected: true };
    assert.equal(verifySignedManifest(app.service.signing.publicKey, extra, content).valid, false);

    const objectPath = app.service.objects.pathFor(manifest.hash);
    fs.writeFileSync(objectPath, Buffer.from("tampered resource content"));
    const tampered = await request(
      app.base,
      `/api/v1/admin/resources/${resourceId}/releases/${releaseId}/content`,
    );
    assert.equal(tampered.status, 409);
    assert.equal((await responseJson(tampered)).error.code, "release_integrity_failed");
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("release versions are immutable, idempotent replays are stable, and key reuse conflicts", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const created = await createResource(app.base);
    const resourceId = created.body.resource.id;
    const key = idempotencyKey();
    const replayPayload = {
      operationId: `op_replay_${crypto.randomUUID()}`,
    };
    const first = await createRelease(
      app.base,
      resourceId,
      created.body.resource.updatedAt,
      replayPayload,
      key,
    );
    assert.equal(first.response.status, 201);

    const replay = await createRelease(
      app.base,
      resourceId,
      created.body.resource.updatedAt,
      replayPayload,
      key,
    );
    assert.equal(replay.response.status, 201);
    assert.equal(replay.response.headers.get("x-idempotent-replay"), "true");
    assert.equal(replay.body.release.id, first.body.release.id);

    const conflict = await createRelease(
      app.base,
      resourceId,
      first.body.resource.updatedAt,
      { resourceVersion: "2026.11.2" },
      key,
    );
    assert.equal(conflict.response.status, 409);
    assert.equal(conflict.body.error.code, "idempotency_conflict");

    const otherActor = await request(
      app.base,
      `/api/v1/admin/resources/${resourceId}/releases`,
      {
        actor: "admin_other",
        idempotency: first.key,
        body: releasePayload(created.body.resource.updatedAt),
      },
    );
    assert.equal(otherActor.status, 409);
    assert.equal((await responseJson(otherActor)).error.code, "idempotency_conflict");

    const duplicateVersion = await createRelease(
      app.base,
      resourceId,
      first.body.resource.updatedAt,
      { operationId: `op_duplicate_${crypto.randomUUID()}` },
    );
    assert.equal(duplicateVersion.response.status, 409);
    assert.equal(duplicateVersion.body.error.code, "resource_version_exists");
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("stale expectedUpdatedAt values are rejected", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const created = await createResource(app.base);
    const resourceId = created.body.resource.id;
    const staleTime = created.body.resource.updatedAt;
    const first = await createRelease(app.base, resourceId, staleTime);
    assert.equal(first.response.status, 201);
    const second = await createRelease(app.base, resourceId, first.body.resource.updatedAt, {
      resourceVersion: "2026.11.2",
    });
    assert.equal(second.response.status, 201);

    const stale = await createRelease(app.base, resourceId, staleTime, {
      resourceVersion: "2026.11.3",
    });
    assert.equal(stale.response.status, 409);
    assert.equal(stale.body.error.code, "stale_resource");
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("concurrent publication of sibling candidates allows only one winner", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const created = await createResource(app.base);
    const resourceId = created.body.resource.id;
    const first = await createRelease(app.base, resourceId, created.body.resource.updatedAt, {
      resourceVersion: "2026.11.1",
    });
    const second = await createRelease(app.base, resourceId, first.body.resource.updatedAt, {
      resourceVersion: "2026.11.2",
    });
    const expectedUpdatedAt = second.body.resource.updatedAt;
    const [left, right] = await Promise.all([
      publishRelease(app.base, resourceId, first.body.release.id, expectedUpdatedAt),
      publishRelease(app.base, resourceId, second.body.release.id, expectedUpdatedAt),
    ]);
    const statuses = [left.response.status, right.response.status].sort();
    assert.deepEqual(statuses, [200, 409]);
    const winner = left.response.status === 200 ? left : right;
    const overview = await request(app.base, `/api/v1/admin/resources/${resourceId}`);
    const current = await responseJson(overview);
    assert.equal(current.resource.currentReleaseId, winner.body.release.id);
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("rollback restores a historical release and appends a complete audit trail", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const created = await createResource(app.base);
    const resourceId = created.body.resource.id;
    const first = await createRelease(app.base, resourceId, created.body.resource.updatedAt, {
      resourceVersion: "2026.11.1",
    });
    const firstPublished = await publishRelease(
      app.base,
      resourceId,
      first.body.release.id,
      first.body.resource.updatedAt,
    );
    const second = await createRelease(app.base, resourceId, firstPublished.body.resource.updatedAt, {
      resourceVersion: "2026.11.2",
    });
    const secondPublished = await publishRelease(
      app.base,
      resourceId,
      second.body.release.id,
      second.body.resource.updatedAt,
    );
    const restored = await rollbackRelease(
      app.base,
      resourceId,
      first.body.release.id,
      secondPublished.body.resource.updatedAt,
    );
    assert.equal(restored.response.status, 200);
    assert.equal(restored.body.resource.currentReleaseId, first.body.release.id);

    const auditResponse = await request(
      app.base,
      `/api/v1/admin/resources/${resourceId}/audit-logs`,
    );
    assert.equal(auditResponse.status, 200);
    const logs = (await responseJson(auditResponse)).auditLogs;
    assert.deepEqual(
      logs.map((entry) => entry.action).reverse(),
      [
        "resource.create",
        "release.create",
        "release.publish",
        "release.create",
        "release.publish",
        "release.rollback",
      ],
    );
    assert.ok(logs.every((entry) => entry.result === "committed"));
    assert.match(logs[0].approvalId, /^apr_/);
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("publication without approval evidence fails closed", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const created = await createResource(app.base);
    const release = await createRelease(app.base, created.body.resource.id, created.body.resource.updatedAt);
    const denied = await publishRelease(
      app.base,
      created.body.resource.id,
      release.body.release.id,
      release.body.resource.updatedAt,
      { approvalId: "" },
    );
    assert.equal(denied.response.status, 400);
    assert.equal(denied.body.error.code, "approval_required");
    const overview = await request(app.base, `/api/v1/admin/resources/${created.body.resource.id}`);
    assert.equal((await responseJson(overview)).resource.currentReleaseId, "");
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("plaintext secrets, private keys and oversized requests are rejected", async () => {
  const root = tempDirectory();
  const app = await start(root, {
    maxContentBytes: 1024,
    maxBodyBytes: 70 * 1024,
  });
  try {
    const created = await createResource(app.base);
    const resourceId = created.body.resource.id;
    const privateKey = `-----BEGIN ${"PRIVATE KEY"}-----\nnot-real-test-material\n-----END ${"PRIVATE KEY"}-----`;
    const keyRelease = await createRelease(app.base, resourceId, created.body.resource.updatedAt, {
      mediaType: "text/plain",
      contentBase64: Buffer.from(privateKey).toString("base64"),
    });
    assert.equal(keyRelease.response.status, 400);
    assert.equal(keyRelease.body.error.code, "content_secret_detected");

    const jsonSecret = await createRelease(app.base, resourceId, created.body.resource.updatedAt, {
      mediaType: "application/json",
      contentBase64: Buffer.from(JSON.stringify({ apiKey: "plaintext-live-secret" })).toString("base64"),
    });
    assert.equal(jsonSecret.response.status, 400);
    assert.equal(jsonSecret.body.error.code, "content_secret_detected");

    const tooLarge = await request(app.base, `/api/v1/admin/resources/${resourceId}/releases`, {
      idempotency: idempotencyKey(),
      body: {
        ...releasePayload(created.body.resource.updatedAt),
        contentBase64: Buffer.alloc(80 * 1024, 65).toString("base64"),
      },
    });
    assert.equal(tooLarge.status, 413);
    assert.equal((await responseJson(tooLarge)).error.code, "request_too_large");
  } finally {
    await close(app.server);
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("a corrupted resource store fails closed", async () => {
  const root = tempDirectory();
  const storePath = path.join(root, "corrupt-store.json");
  fs.writeFileSync(storePath, JSON.stringify({
    version: 1,
    resources: {},
    releases: {},
    idempotency: {},
    resourceAuditLogs: [],
    unexpected: true,
  }));
  const store = new ResourceStore(storePath);
  await assert.rejects(() => store.load(), /unknown fields/);
  fs.rmSync(root, { recursive: true, force: true });
});

test("Ed25519 manifest helper rejects unsigned mutations and invalid key types", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const content = Buffer.from("signed content");
  const manifest = buildSignedManifest({
    resourceId: "res_0123456789abcdef0123456789abcdef",
    releaseId: "rel_0123456789abcdef0123456789abcdef",
    resourceVersion: "2026.11.1",
    kind: "skill",
    hash: `sha256:${crypto.createHash("sha256").update(content).digest("hex")}`,
    contentBytes: content.length,
    mediaType: "text/plain",
    publisher: "enterprise-platform",
    createdAt: "2026-11-02T00:00:00.000Z",
    assignments: ["org_engineering"],
    deliveryMode: "recommended",
    compatibility: { minClientVersion: "0.2.0" },
    previousReleaseId: "",
    signingKeyId: "resource-test-v1",
  }, privateKey);
  assert.equal(verifySignedManifest(publicKey, manifest, content).valid, true);
  const wrongContent = Buffer.from("tampered content");
  assert.equal(verifySignedManifest(publicKey, manifest, wrongContent).valid, false);
});
