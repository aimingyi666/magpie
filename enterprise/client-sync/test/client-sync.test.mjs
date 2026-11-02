import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildSignedManifest,
  publicKeyFingerprint,
} from "../../resource-service/src/manifest.js";
import {
  ClientSyncEngine,
  ClientSyncError,
  DEFAULT_SYNC_INTERVAL_MS,
  MAX_SYNC_INTERVAL_MS,
} from "../src/index.js";

const KEY_ID = "enterprise-resource-test-v1";
const CLIENT_VERSION = "1.4.0";

function temporaryRoot(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "magpie-client-sync-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return path.join(root, "managed");
}

function newSigningIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKey,
    privateKey,
    publicKeys: { [KEY_ID]: publicKey.export({ type: "spki", format: "pem" }) },
    keyFingerprints: { [KEY_ID]: publicKeyFingerprint(publicKey) },
  };
}

function signedResource(identity, {
  resourceId = "res_engineering_instructions",
  releaseId = "rel_2026_11_1",
  resourceVersion = "2026.11.1",
  kind = "instructions",
  deliveryMode = "forced",
  content = "# Engineering baseline\n\nUse only approved tools.\n",
  signingKeyId = KEY_ID,
  minClientVersion = "1.0.0",
} = {}) {
  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
  const manifest = buildSignedManifest({
    resourceId,
    releaseId,
    resourceVersion,
    kind,
    hash: `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`,
    contentBytes: bytes.length,
    mediaType: kind === "instructions" ? "text/markdown" : "application/octet-stream",
    publisher: "enterprise-platform",
    createdAt: "2026-11-02T00:00:00.000Z",
    assignments: ["org_engineering"],
    deliveryMode,
    compatibility: { minClientVersion },
    previousReleaseId: "",
    signingKeyId,
  }, identity.privateKey);
  return { manifest, content: bytes };
}

function desired(resources, revision = "desired-1") {
  return {
    schemaVersion: 1,
    revision,
    generatedAt: "2026-11-02T00:01:00.000Z",
    resources,
  };
}

function engineFor(root, identity, fetchDesiredState, overrides = {}) {
  return new ClientSyncEngine({
    rootDir: root,
    publicKeys: identity.publicKeys,
    keyFingerprints: identity.keyFingerprints,
    clientVersion: CLIENT_VERSION,
    fetchDesiredState,
    now: () => Date.parse("2026-11-02T00:02:00.000Z"),
    ...overrides,
  });
}

function readState(root) {
  return JSON.parse(fs.readFileSync(path.join(root, "state.json"), "utf8"));
}

test("valid signed resources install atomically and inspect cleanly", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const resource = signedResource(identity, {
    content: "# Baseline\n\nSigned enterprise instructions.\n",
  });
  const engine = engineFor(root, identity, async () => desired([resource]));

  const first = await engine.syncOnce();
  assert.equal(first.status, "synced", JSON.stringify(first));
  assert.deepEqual(first.installed, [resource.manifest.resourceId]);
  assert.deepEqual(first.drift, []);

  const contentPath = path.join(
    root,
    "releases",
    resource.manifest.resourceId,
    resource.manifest.releaseId,
    "content",
  );
  assert.deepEqual(fs.readFileSync(contentPath), resource.content);
  const state = readState(root);
  assert.equal(state.revision, "desired-1");
  assert.equal(state.resources[0].releaseId, resource.manifest.releaseId);
  assert.equal(state.resources[0].deliveryMode, "forced");
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(path.join(root, "state.json")).mode & 0o777, 0o600);
    assert.equal(fs.statSync(contentPath).mode & 0o777, 0o600);
  }

  const second = await engine.syncOnce();
  assert.equal(second.status, "up_to_date", JSON.stringify(second));
  const inspected = await engine.inspect();
  assert.equal(inspected.status, "in_sync");
  assert.deepEqual(inspected.drift, []);
});

test("a tampered manifest or content fails closed without activation", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const resource = signedResource(identity);

  const manifestTamper = structuredClone(resource);
  manifestTamper.manifest.publisher = "attacker";
  const manifestEngine = engineFor(root, identity, async () => desired([manifestTamper]));
  const manifestResult = await manifestEngine.syncOnce();
  assert.equal(manifestResult.status, "failed");
  assert.equal(manifestResult.error.code, "manifest_invalid");
  assert.deepEqual(readState(root).resources, []);

  const contentRoot = temporaryRoot(t);
  const contentTamper = { ...resource, content: Buffer.from("tampered content") };
  const contentEngine = engineFor(contentRoot, identity, async () => desired([contentTamper]));
  const contentResult = await contentEngine.syncOnce();
  assert.equal(contentResult.status, "failed");
  assert.equal(contentResult.error.code, "content_invalid");
  assert.deepEqual(readState(contentRoot).resources, []);
});

test("a failed new release preserves the previous active release and reports drift", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const firstResource = signedResource(identity, {
    releaseId: "rel_2026_11_1",
    content: "first release\n",
  });
  const secondResource = signedResource(identity, {
    releaseId: "rel_2026_11_2",
    resourceVersion: "2026.11.2",
    content: "second release\n",
  });
  let current = desired([firstResource], "desired-1");
  const engine = engineFor(root, identity, async () => current, {
    validateInstalled: async ({ manifest }) => {
      if (manifest.releaseId === "rel_2026_11_2") {
        throw new Error("simulated post-download validation failure");
      }
    },
  });

  assert.equal((await engine.syncOnce()).status, "synced");
  current = desired([secondResource], "desired-2");
  const failed = await engine.syncOnce();
  assert.equal(failed.status, "failed");
  assert.equal(failed.error.code, "install_validation_failed");
  assert.equal(failed.state.resources[0].releaseId, "rel_2026_11_1");
  assert.deepEqual(failed.drift.map((item) => item.state), ["version_mismatch"]);

  const inspected = await engine.inspect();
  assert.equal(inspected.status, "drift");
  assert.equal(inspected.resources[0].releaseId, "rel_2026_11_1");
  assert.equal(inspected.desired.resources[0].releaseId, "rel_2026_11_2");
  const contentPath = path.join(root, "releases", firstResource.manifest.resourceId, "rel_2026_11_1", "content");
  assert.equal(fs.readFileSync(contentPath, "utf8"), "first release\n");
});

test("offline sync keeps the last verified release active", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const resource = signedResource(identity);
  let fail = false;
  const engine = engineFor(root, identity, async () => {
    if (fail) throw new Error("network unavailable");
    return desired([resource]);
  });

  assert.equal((await engine.syncOnce()).status, "synced");
  fail = true;
  const offline = await engine.syncOnce();
  assert.equal(offline.status, "offline");
  assert.equal(offline.error.code, "desired_state_unavailable");
  assert.equal(offline.state.resources[0].releaseId, resource.manifest.releaseId);
  assert.equal(offline.state.lastError.code, "desired_state_unavailable");
  assert.equal((await engine.inspect()).status, "last_sync_failed");
});

test("forced resources cannot be disabled while recommended resources can", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const forced = signedResource(identity);
  const forcedEngine = engineFor(root, identity, async () => desired([forced]));
  assert.equal((await forcedEngine.syncOnce()).status, "synced");
  await assert.rejects(
    forcedEngine.setRecommendedEnabled(forced.manifest.resourceId, false),
    (error) => error instanceof ClientSyncError && error.code === "forced_resource",
  );

  const recommendedRoot = temporaryRoot(t);
  const recommendedV1 = signedResource(identity, {
    releaseId: "rel_rec_1",
    resourceVersion: "1.0.0",
    deliveryMode: "recommended",
    content: "recommended v1\n",
  });
  const recommendedV2 = signedResource(identity, {
    releaseId: "rel_rec_2",
    resourceVersion: "2.0.0",
    deliveryMode: "recommended",
    content: "recommended v2\n",
  });
  let recommendedDesired = desired([recommendedV1], "rec-1");
  const recommendedEngine = engineFor(recommendedRoot, identity, async () => recommendedDesired);
  assert.equal((await recommendedEngine.syncOnce()).status, "synced");
  await recommendedEngine.setRecommendedEnabled(recommendedV1.manifest.resourceId, false);
  recommendedDesired = desired([recommendedV2], "rec-2");
  const skipped = await recommendedEngine.syncOnce();
  assert.equal(skipped.status, "synced");
  assert.deepEqual(skipped.skipped, [recommendedV1.manifest.resourceId]);
  assert.equal(skipped.state.resources[0].releaseId, "rel_rec_1");
  assert.equal((await recommendedEngine.inspect()).status, "in_sync");
});

test("a resource changed from recommended to forced overrides a user disable", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const v1 = signedResource(identity, {
    releaseId: "rel_policy_1",
    resourceVersion: "1.0.0",
    deliveryMode: "recommended",
    content: "recommended\n",
  });
  const v2 = signedResource(identity, {
    releaseId: "rel_policy_2",
    resourceVersion: "2.0.0",
    deliveryMode: "forced",
    content: "forced\n",
  });
  let current = desired([v1], "policy-1");
  const engine = engineFor(root, identity, async () => current);
  assert.equal((await engine.syncOnce()).status, "synced");
  await engine.setRecommendedEnabled(v1.manifest.resourceId, false);

  current = desired([v2], "policy-2");
  const forced = await engine.syncOnce();
  assert.equal(forced.status, "synced");
  assert.equal(forced.state.resources[0].releaseId, "rel_policy_2");
  assert.deepEqual(forced.state.disabledRecommended, []);
});

test("path traversal and unknown signing keys are rejected before installation", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const traversal = signedResource(identity, {
    resourceId: "../escape",
    releaseId: "rel_escape",
  });
  const traversalEngine = engineFor(root, identity, async () => desired([traversal]));
  const rejected = await traversalEngine.syncOnce();
  assert.equal(rejected.status, "failed");
  assert.equal(rejected.error.code, "path_traversal");
  assert.equal(fs.existsSync(path.join(path.dirname(root), "escape")), false);

  const unknownKey = signedResource(identity, {
    releaseId: "rel_unknown_key",
    signingKeyId: "not-pinned",
  });
  const unknownEngine = engineFor(root, identity, async () => desired([unknownKey]));
  const unknown = await unknownEngine.syncOnce();
  assert.equal(unknown.status, "failed");
  assert.equal(unknown.error.code, "manifest_key_unknown");
});

test("symbolic links in the managed release path fail closed", async (t) => {
  const root = temporaryRoot(t);
  fs.mkdirSync(path.join(root, "releases"), { recursive: true });
  const outside = path.join(path.dirname(root), "outside-release");
  fs.mkdirSync(outside, { recursive: true });
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  try {
    fs.symlinkSync(outside, path.join(root, "releases", "res_engineering_instructions"), "junction");
  } catch (error) {
    if (["EPERM", "EACCES", "UNKNOWN"].includes(error.code)) {
      t.skip(`symbolic links unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
  const identity = newSigningIdentity();
  const resource = signedResource(identity);
  const engine = engineFor(root, identity, async () => desired([resource]));
  const result = await engine.syncOnce();
  assert.equal(result.status, "failed");
  assert.equal(result.error.code, "path_symlink");
  assert.equal(fs.existsSync(path.join(outside, resource.manifest.releaseId)), false);
});

test("tampered caches are visible as drift and never silently overwritten", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const resource = signedResource(identity);
  const engine = engineFor(root, identity, async () => desired([resource]));
  assert.equal((await engine.syncOnce()).status, "synced");

  const metadataPath = path.join(
    root,
    "releases",
    resource.manifest.resourceId,
    resource.manifest.releaseId,
    "metadata.json",
  );
  fs.writeFileSync(metadataPath, "{}\n");
  const inspected = await engine.inspect();
  assert.equal(inspected.status, "drift");
  assert.equal(inspected.drift[0].state, "content_invalid");

  const repeated = await engine.syncOnce();
  assert.equal(repeated.status, "failed");
  assert.equal(repeated.error.code, "cache_conflict");
  assert.equal(repeated.state.resources[0].releaseId, resource.manifest.releaseId);
});

test("reusing a release id with different signed metadata is a conflict", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const first = signedResource(identity, {
    releaseId: "rel_same",
    content: "first bytes\n",
  });
  const different = signedResource(identity, {
    releaseId: "rel_same",
    content: "different bytes\n",
  });
  let current = desired([first], "same-1");
  const engine = engineFor(root, identity, async () => current);
  assert.equal((await engine.syncOnce()).status, "synced");
  current = desired([different], "same-2");
  const result = await engine.syncOnce();
  assert.equal(result.status, "failed");
  assert.equal(result.error.code, "cache_conflict");
  assert.equal(result.state.resources[0].hash, first.manifest.hash);
});

test("concurrent sync is prevented by the process lock", async (t) => {
  const root = temporaryRoot(t);
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, "sync.lock"), JSON.stringify({ nonce: "other" }), { mode: 0o600 });
  const identity = newSigningIdentity();
  let fetched = false;
  const engine = engineFor(root, identity, async () => {
    fetched = true;
    return desired([signedResource(identity)]);
  });
  const result = await engine.syncOnce();
  assert.equal(result.status, "busy");
  assert.equal(result.error.code, "sync_locked");
  assert.equal(fetched, false);
});

test("state and reports never contain private keys or resource content", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const secretLikeContent = "TOP-SECRET-CONTENT-THAT-MUST-NOT-BE-IN-STATE";
  const resource = signedResource(identity, { content: secretLikeContent });
  const engine = engineFor(root, identity, async () => desired([resource]));
  const result = await engine.syncOnce();
  const serializedState = fs.readFileSync(path.join(root, "state.json"), "utf8");
  const serializedReport = JSON.stringify(result);
  const serializedInspect = JSON.stringify(await engine.inspect());
  for (const value of [serializedState, serializedReport, serializedInspect]) {
    assert.equal(value.includes(secretLikeContent), false);
    assert.equal(value.includes("PRIVATE KEY"), false);
  }
});

test("duplicate resources, incompatible clients and bad fingerprints fail closed", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const duplicate = signedResource(identity);
  const duplicateEngine = engineFor(root, identity, async () => desired([duplicate, duplicate]));
  const duplicateResult = await duplicateEngine.syncOnce();
  assert.equal(duplicateResult.status, "failed");
  assert.equal(duplicateResult.error.code, "desired_state_invalid");

  const newer = signedResource(identity, {
    releaseId: "rel_newer",
    minClientVersion: "9.0.0",
  });
  const newerEngine = engineFor(root, identity, async () => desired([newer]));
  const newerResult = await newerEngine.syncOnce();
  assert.equal(newerResult.status, "failed");
  assert.equal(newerResult.error.code, "client_version_incompatible");

  assert.throws(
    () => new ClientSyncEngine({
      rootDir: root,
      publicKeys: identity.publicKeys,
      keyFingerprints: { [KEY_ID]: `sha256:${"0".repeat(64)}` },
      clientVersion: CLIENT_VERSION,
      fetchDesiredState: async () => desired([]),
    }),
    (error) => error instanceof ClientSyncError && error.code === "invalid_config",
  );
});

test("an oversized manifest is rejected before installation", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const oversized = signedResource(identity);
  oversized.manifest = buildSignedManifest({
    resourceId: oversized.manifest.resourceId,
    releaseId: "rel_oversized_manifest",
    resourceVersion: "2026.11.2",
    kind: oversized.manifest.kind,
    hash: oversized.manifest.hash,
    contentBytes: oversized.manifest.contentBytes,
    mediaType: oversized.manifest.mediaType,
    publisher: oversized.manifest.publisher,
    createdAt: oversized.manifest.createdAt,
    assignments: Array.from({ length: 20_000 }, (_, index) => `assignment_${index}`),
    deliveryMode: oversized.manifest.deliveryMode,
    compatibility: oversized.manifest.compatibility,
    previousReleaseId: "",
    signingKeyId: KEY_ID,
  }, identity.privateKey);
  const engine = engineFor(root, identity, async () => desired([oversized]));

  const result = await engine.syncOnce();
  assert.equal(result.status, "failed");
  assert.equal(result.error.code, "manifest_invalid");
  assert.deepEqual(readState(root).resources, []);
});

test("a state write failure reports the last committed active release", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const first = signedResource(identity, {
    releaseId: "rel_state_1",
    content: "state v1\n",
  });
  const second = signedResource(identity, {
    releaseId: "rel_state_2",
    resourceVersion: "2026.11.2",
    content: "state v2\n",
  });
  let current = desired([first], "state-1");
  const engine = engineFor(root, identity, async () => current);
  assert.equal((await engine.syncOnce()).status, "synced");

  current = desired([second], "state-2");
  const statePath = path.join(root, "state.json");
  const failingEngine = engineFor(root, identity, async () => {
    fs.rmSync(statePath);
    fs.mkdirSync(statePath);
    return current;
  });
  const failed = await failingEngine.syncOnce();

  assert.equal(failed.status, "failed");
  assert.equal(failed.error.code, "state_write_failed");
  assert.equal(failed.state.revision, "state-1");
  assert.equal(failed.state.resources[0].releaseId, first.manifest.releaseId);
  assert.equal(failed.state.desired.resources[0].releaseId, first.manifest.releaseId);
});

test("the maximum periodic sync interval is five minutes", () => {
  assert.ok(DEFAULT_SYNC_INTERVAL_MS <= MAX_SYNC_INTERVAL_MS);
  const identity = newSigningIdentity();
  assert.throws(
    () => new ClientSyncEngine({
      rootDir: path.join(os.tmpdir(), "unused-client-sync-root"),
      publicKeys: identity.publicKeys,
      clientVersion: CLIENT_VERSION,
      fetchDesiredState: async () => desired([]),
      syncIntervalMs: MAX_SYNC_INTERVAL_MS + 1,
    }),
    (error) => error instanceof ClientSyncError && error.code === "invalid_config",
  );
});

test("readActiveResource returns only a re-verified active release", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const resource = signedResource(identity, {
    content: "# Verified active release\n",
  });
  const engine = engineFor(root, identity, async () => desired([resource]));
  assert.equal((await engine.syncOnce()).status, "synced");

  const active = await engine.readActiveResource(resource.manifest.resourceId);
  assert.deepEqual(active.manifest, resource.manifest);
  assert.deepEqual(active.content, resource.content);
  assert.equal(active.record.releaseId, resource.manifest.releaseId);
  assert.equal(active.record.kind, "instructions");

  await assert.rejects(
    () => engine.readActiveResource("res_not_active"),
    (error) => error instanceof ClientSyncError && error.code === "resource_not_installed",
  );
  await assert.rejects(
    () => engine.readActiveResource("../escape"),
    (error) => error instanceof ClientSyncError && error.code === "path_traversal",
  );
});

test("readActiveResource fails closed after content or path tampering", async (t) => {
  const root = temporaryRoot(t);
  const identity = newSigningIdentity();
  const resource = signedResource(identity);
  const engine = engineFor(root, identity, async () => desired([resource]));
  assert.equal((await engine.syncOnce()).status, "synced");

  const contentPath = path.join(
    root,
    "releases",
    resource.manifest.resourceId,
    resource.manifest.releaseId,
    "content",
  );
  fs.writeFileSync(contentPath, "tampered after activation\n");
  await assert.rejects(
    () => engine.readActiveResource(resource.manifest.resourceId),
    (error) => error instanceof ClientSyncError && error.code === "content_invalid",
  );

  const symlinkRoot = temporaryRoot(t);
  const symlinkEngine = engineFor(symlinkRoot, identity, async () => desired([resource]));
  assert.equal((await symlinkEngine.syncOnce()).status, "synced");
  const symlinkContent = path.join(
    symlinkRoot,
    "releases",
    resource.manifest.resourceId,
    resource.manifest.releaseId,
    "content",
  );
  const outside = path.join(path.dirname(symlinkRoot), "outside-content");
  fs.writeFileSync(outside, resource.content);
  fs.rmSync(symlinkContent);
  try {
    fs.symlinkSync(outside, symlinkContent, "file");
  } catch (error) {
    if (["EPERM", "EACCES", "UNKNOWN"].includes(error.code)) {
      t.skip(`symbolic links unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
  await assert.rejects(
    () => symlinkEngine.readActiveResource(resource.manifest.resourceId),
    (error) => error instanceof ClientSyncError && error.code === "content_invalid",
  );
});
