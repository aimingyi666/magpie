import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import {
  canonicalJson,
  publicKeyFingerprint,
  validateManifestShape,
  verifySignedManifest,
} from "../../resource-service/src/manifest.js";
import { ClientSyncError, asClientSyncError, publicError } from "./errors.js";
import {
  assertSafeSegment,
  readClientSyncState,
  stateWithAttempt,
  writeClientSyncState,
} from "./state.js";
import { assertClientVersionSupported } from "./version.js";

export const DEFAULT_SYNC_INTERVAL_MS = 60_000;
export const MAX_SYNC_INTERVAL_MS = 300_000;
export const MIN_SYNC_INTERVAL_MS = 1_000;
export const DEFAULT_MAX_RESOURCE_BYTES = 10 * 1024 * 1024;
export const DEFAULT_LOCK_STALE_MS = 15 * 60 * 1000;

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_MANIFEST_BYTES = 256 * 1024;
const MANIFEST_FILE = "metadata.json";
const CONTENT_FILE = "content";
const DESIRED_STATE_FIELDS = new Set(["schemaVersion", "revision", "generatedAt", "resources"]);
const DESIRED_RESOURCE_FIELDS = new Set(["manifest", "content"]);

async function lstatOrNull(target) {
  try {
    return await fs.lstat(target);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function ensureDirectory(target) {
  const stat = await lstatOrNull(target);
  if (!stat) {
    await fs.mkdir(target, { recursive: false, mode: 0o700 });
    return ensureDirectory(target);
  }
  if (stat.isSymbolicLink()) {
    throw new ClientSyncError("path_symlink", "managed directories must not be symbolic links");
  }
  if (!stat.isDirectory()) {
    throw new ClientSyncError("invalid_state", "managed path is not a directory");
  }
}

function relativeInside(root, target) {
  const relative = path.relative(root, target);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new ClientSyncError("path_traversal", "path escapes the managed root");
  }
  return relative;
}

async function assertNoSymlinkAncestors(root, target) {
  relativeInside(root, target);
  const relative = path.relative(root, target);
  let current = root;
  for (const segment of relative.split(path.sep)) {
    current = path.join(current, segment);
    const stat = await lstatOrNull(current);
    if (!stat) return;
    if (stat.isSymbolicLink()) {
      throw new ClientSyncError("path_symlink", "managed path contains a symbolic link");
    }
  }
}

async function ensureManagedDirectory(root, target) {
  await assertNoSymlinkAncestors(root, target);
  const parent = path.dirname(target);
  if (parent !== root) await ensureManagedDirectory(root, parent);
  await ensureDirectory(target);
  await assertNoSymlinkAncestors(root, target);
}

async function ensureRoot(root) {
  const stat = await lstatOrNull(root);
  if (!stat) {
    await fs.mkdir(root, { recursive: true, mode: 0o700 });
  }
  const created = await lstatOrNull(root);
  if (!created || created.isSymbolicLink() || !created.isDirectory()) {
    throw new ClientSyncError("invalid_config", "rootDir must be a real directory");
  }
  await ensureDirectory(path.join(root, "releases"));
  await ensureDirectory(path.join(root, "staging"));
}

async function writeFileSynced(file, data) {
  const handle = await fs.open(file, "wx", 0o600);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function syncDirectory(directory) {
  try {
    const handle = await fs.open(directory, "r");
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (!["EINVAL", "EISDIR", "EPERM", "ENOTSUP", "EACCES"].includes(error.code)) throw error;
  }
}

async function removeStaging(root) {
  const staging = path.join(root, "staging");
  await ensureDirectory(staging);
  const entries = await fs.readdir(staging, { withFileTypes: true });
  for (const entry of entries) {
    const target = path.join(staging, entry.name);
    const stat = await fs.lstat(target);
    if (stat.isSymbolicLink()) {
      await fs.unlink(target);
    } else {
      await fs.rm(target, { recursive: true, force: true });
    }
  }
}

function normalizeNow(now) {
  if (typeof now !== "function") throw new ClientSyncError("invalid_config", "now must be a function");
  return () => {
    const value = now();
    const milliseconds = value instanceof Date ? value.getTime() : Number(value);
    if (!Number.isFinite(milliseconds)) {
      throw new ClientSyncError("invalid_config", "now must return a date or timestamp");
    }
    return milliseconds;
  };
}

function normalizeKeys(publicKeys, keyFingerprints) {
  const entries = publicKeys instanceof Map
    ? [...publicKeys.entries()]
    : publicKeys && typeof publicKeys === "object" && !Array.isArray(publicKeys)
      ? Object.entries(publicKeys)
      : null;
  if (!entries || entries.length === 0) {
    throw new ClientSyncError("invalid_config", "publicKeys must contain at least one key");
  }
  const fingerprints = keyFingerprints instanceof Map
    ? new Map(keyFingerprints)
    : keyFingerprints && typeof keyFingerprints === "object" && !Array.isArray(keyFingerprints)
      ? new Map(Object.entries(keyFingerprints))
      : new Map();
  const keys = new Map();
  for (const [keyId, input] of entries) {
    if (!KEY_ID.test(keyId)) throw new ClientSyncError("invalid_config", "signing key id is invalid");
    let key;
    try {
      if (input?.type === "private") {
        throw new Error("private key");
      }
      if (typeof input === "string" || Buffer.isBuffer(input)) {
        const text = Buffer.isBuffer(input) ? input.toString("utf8") : input;
        if (text.includes("PRIVATE KEY")) throw new Error("private key");
        key = crypto.createPublicKey(text);
      } else {
        key = crypto.createPublicKey(input);
      }
    } catch {
      throw new ClientSyncError("invalid_config", "public key could not be loaded");
    }
    if (key.asymmetricKeyType !== "ed25519") {
      throw new ClientSyncError("invalid_config", "public key must be Ed25519");
    }
    const fingerprint = publicKeyFingerprint(key);
    const expected = fingerprints.get(keyId);
    if (expected !== undefined && expected !== fingerprint) {
      throw new ClientSyncError("invalid_config", "public key fingerprint does not match");
    }
    keys.set(keyId, { key, fingerprint });
  }
  return keys;
}

function validateDesiredState(value, clientVersion, maxResourceBytes) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ClientSyncError("desired_state_invalid", "desired state must be an object");
  }
  const fields = Object.keys(value);
  if (fields.some((field) => !DESIRED_STATE_FIELDS.has(field))
      || !Object.hasOwn(value, "schemaVersion")
      || !Object.hasOwn(value, "revision")
      || !Object.hasOwn(value, "resources")) {
    throw new ClientSyncError("desired_state_invalid", "desired state fields are invalid");
  }
  if (value.schemaVersion !== 1) {
    throw new ClientSyncError("desired_state_invalid", "desired state schemaVersion is unsupported");
  }
  if (typeof value.revision !== "string"
      || !value.revision
      || value.revision.length > 512
      || /[\u0000-\u001f\u007f]/.test(value.revision)) {
    throw new ClientSyncError("desired_state_invalid", "desired state revision is invalid");
  }
  if (value.generatedAt !== undefined
      && (typeof value.generatedAt !== "string" || Number.isNaN(Date.parse(value.generatedAt)))) {
    throw new ClientSyncError("desired_state_invalid", "desired state generatedAt is invalid");
  }
  if (!Array.isArray(value.resources)) {
    throw new ClientSyncError("desired_state_invalid", "desired state resources must be an array");
  }
  const seen = new Set();
  const resources = value.resources.map((resource) => {
    if (!resource || typeof resource !== "object" || Array.isArray(resource)) {
      throw new ClientSyncError("desired_state_invalid", "desired resource must be an object");
    }
    const resourceFields = Object.keys(resource);
    if (resourceFields.some((field) => !DESIRED_RESOURCE_FIELDS.has(field))
        || !Object.hasOwn(resource, "manifest")
        || !Object.hasOwn(resource, "content")) {
      throw new ClientSyncError("desired_state_invalid", "desired resource fields are invalid");
    }
    let manifest;
    try {
      manifest = validateManifestShape(resource.manifest);
    } catch {
      throw new ClientSyncError("manifest_invalid", "manifest shape is invalid");
    }
    if (Buffer.byteLength(canonicalJson(manifest), "utf8") > MAX_MANIFEST_BYTES) {
      throw new ClientSyncError("manifest_invalid", "manifest exceeds the client limit");
    }
    assertSafeSegment(manifest.resourceId, "manifest.resourceId");
    assertSafeSegment(manifest.releaseId, "manifest.releaseId");
    assertClientVersionSupported(clientVersion, manifest);
    let content;
    if (Buffer.isBuffer(resource.content)) {
      content = Buffer.from(resource.content);
    } else if (resource.content instanceof Uint8Array) {
      content = Buffer.from(resource.content);
    } else {
      throw new ClientSyncError("content_invalid", "resource content must be a Buffer or Uint8Array");
    }
    if (content.length > maxResourceBytes) {
      throw new ClientSyncError("content_too_large", "resource content exceeds the client limit");
    }
    if (seen.has(manifest.resourceId)) {
      throw new ClientSyncError("desired_state_invalid", "desired state contains duplicate resources");
    }
    seen.add(manifest.resourceId);
    return { manifest: { ...manifest }, content };
  });
  return {
    schemaVersion: 1,
    revision: value.revision,
    generatedAt: value.generatedAt,
    resources,
  };
}

function verifyResource(keys, manifest, content) {
  const key = keys.get(manifest.signingKeyId);
  if (!key) throw new ClientSyncError("manifest_key_unknown", "manifest signing key is not pinned");
  const result = verifySignedManifest(key.key, manifest, content);
  if (!result.valid) {
    throw new ClientSyncError(
      result.reason === "content_hash_mismatch" || result.reason === "content_size_mismatch"
        ? "content_invalid"
        : "manifest_invalid",
      "manifest signature or content verification failed",
    );
  }
}

function desiredRecord(manifest) {
  return {
    resourceId: manifest.resourceId,
    releaseId: manifest.releaseId,
    resourceVersion: manifest.resourceVersion,
    kind: manifest.kind,
    deliveryMode: manifest.deliveryMode,
    hash: manifest.hash,
    manifestDigest: manifest.manifestDigest,
    signingKeyId: manifest.signingKeyId,
  };
}

function activeRecord(manifest, at) {
  return {
    ...desiredRecord(manifest),
    installedAt: at,
    directory: `releases/${manifest.resourceId}/${manifest.releaseId}`,
  };
}

function recordsMatch(left, right) {
  return Boolean(left)
    && left.releaseId === right.releaseId
    && left.hash === right.hash
    && left.manifestDigest === right.manifestDigest
    && left.signingKeyId === right.signingKeyId;
}

function computeDrift(state, desiredResources, disabledRecommended) {
  const current = new Map(state.resources.map((record) => [record.resourceId, record]));
  const disabled = new Set(disabledRecommended);
  const desired = new Map(desiredResources.map((record) => [record.resourceId, record]));
  const drift = [];
  for (const record of desiredResources) {
    if (disabled.has(record.resourceId) && record.deliveryMode === "recommended") continue;
    const actual = current.get(record.resourceId);
    if (!recordsMatch(actual, record)) {
      drift.push({
        resourceId: record.resourceId,
        expectedReleaseId: record.releaseId,
        actualReleaseId: actual?.releaseId ?? null,
        state: actual ? "version_mismatch" : "missing",
      });
    }
  }
  for (const record of state.resources) {
    if (!desired.has(record.resourceId)) {
      drift.push({
        resourceId: record.resourceId,
        expectedReleaseId: null,
        actualReleaseId: record.releaseId,
        state: "not_in_desired_state",
      });
    }
  }
  return drift;
}

function stateForReport(state) {
  return {
    revision: state.revision,
    resources: state.resources.map((record) => ({ ...record })),
    desired: state.desired
      ? {
        revision: state.desired.revision,
        resources: state.desired.resources.map((record) => ({ ...record })),
      }
      : null,
    disabledRecommended: [...state.disabledRecommended],
    lastSuccessfulSyncAt: state.lastSuccessfulSyncAt,
    lastAttemptAt: state.lastAttemptAt,
    lastError: state.lastError ? { ...state.lastError } : null,
  };
}

async function releasePath(root, record) {
  const resourceId = assertSafeSegment(record.resourceId, "resourceId");
  const releaseId = assertSafeSegment(record.releaseId, "releaseId");
  const target = path.join(root, "releases", resourceId, releaseId);
  relativeInside(root, target);
  return target;
}

async function readCachedRelease(root, keys, manifest) {
  try {
    const directory = await releasePath(root, manifest);
    await assertNoSymlinkAncestors(root, directory);
    const metadataPath = path.join(directory, MANIFEST_FILE);
    const contentPath = path.join(directory, CONTENT_FILE);
    for (const target of [directory, metadataPath, contentPath]) {
      const stat = await lstatOrNull(target);
      if (!stat || stat.isSymbolicLink()) {
        throw new ClientSyncError("cache_conflict", "cached release is missing or unsafe");
      }
    }
    const metadataStat = await fs.lstat(metadataPath);
    const contentStat = await fs.lstat(contentPath);
    if (!metadataStat.isFile()
        || metadataStat.size > 1024 * 1024
        || !contentStat.isFile()) {
      throw new ClientSyncError("cache_conflict", "cached release files are invalid");
    }
    let cachedManifest;
    try {
      cachedManifest = JSON.parse(await fs.readFile(metadataPath, "utf8"));
      validateManifestShape(cachedManifest);
    } catch {
      throw new ClientSyncError("cache_conflict", "cached release metadata is invalid");
    }
    if (canonicalJson(cachedManifest) !== canonicalJson(manifest)) {
      throw new ClientSyncError("cache_conflict", "release id already has different metadata");
    }
    const content = await fs.readFile(contentPath);
    verifyResource(keys, cachedManifest, content);
    return content;
  } catch (error) {
    if (error instanceof ClientSyncError) throw error;
    throw new ClientSyncError("cache_conflict", "cached release could not be verified");
  }
}

async function stageRelease(root, keys, resource, previous, at, validateInstalled) {
  const { manifest, content } = resource;
  const directory = await releasePath(root, manifest);
  const existing = await lstatOrNull(directory);
  if (existing) {
    if (existing.isSymbolicLink()) {
      throw new ClientSyncError("path_symlink", "cached release must not be a symbolic link");
    }
    await readCachedRelease(root, keys, manifest);
    return {
      record: previous && recordsMatch(previous, desiredRecord(manifest))
        ? { ...previous }
        : activeRecord(manifest, at),
      cached: true,
    };
  }

  const resourceDirectory = path.dirname(directory);
  await ensureManagedDirectory(root, resourceDirectory);
  const stagingDirectory = path.join(root, "staging", crypto.randomUUID());
  await ensureDirectory(stagingDirectory);
  const metadataPath = path.join(stagingDirectory, MANIFEST_FILE);
  const contentPath = path.join(stagingDirectory, CONTENT_FILE);
  try {
    await writeFileSynced(contentPath, content);
    await writeFileSynced(metadataPath, `${canonicalJson(manifest)}\n`);
    const writtenContent = await fs.readFile(contentPath);
    const writtenManifest = JSON.parse(await fs.readFile(metadataPath, "utf8"));
    verifyResource(keys, writtenManifest, writtenContent);
    if (validateInstalled) {
      try {
        await validateInstalled({
          manifest: writtenManifest,
          content: writtenContent,
          directory: stagingDirectory,
          contentPath,
          metadataPath,
        });
      } catch (error) {
        if (error instanceof ClientSyncError) throw error;
        throw new ClientSyncError(
          "install_validation_failed",
          "installed resource validation failed",
        );
      }
      verifyResource(keys, JSON.parse(await fs.readFile(metadataPath, "utf8")), await fs.readFile(contentPath));
    }
    await assertNoSymlinkAncestors(root, directory);
    await fs.rename(stagingDirectory, directory);
    await syncDirectory(resourceDirectory);
    return { record: activeRecord(manifest, at), cached: false };
  } catch (error) {
    await fs.rm(stagingDirectory, { recursive: true, force: true });
    if (error instanceof ClientSyncError) throw error;
    throw new ClientSyncError("install_failed", "resource could not be staged");
  }
}

async function verifyActiveRecord(root, keys, record) {
  try {
    const directory = await releasePath(root, record);
    await assertNoSymlinkAncestors(root, directory);
    const metadataPath = path.join(directory, MANIFEST_FILE);
    const contentPath = path.join(directory, CONTENT_FILE);
    for (const target of [directory, metadataPath, contentPath]) {
      const stat = await fs.lstat(target);
      if (stat.isSymbolicLink()) {
        return { state: "path_symlink" };
      }
    }
    const manifest = JSON.parse(await fs.readFile(metadataPath, "utf8"));
    validateManifestShape(manifest);
    const content = await fs.readFile(contentPath);
    verifyResource(keys, manifest, content);
    const expected = desiredRecord(manifest);
    return recordsMatch(record, expected) ? null : { state: "metadata_mismatch" };
  } catch (error) {
    const code = asClientSyncError(error).code;
    return { state: code === "path_symlink" ? "path_symlink" : "content_invalid" };
  }
}

function abortableSleep(milliseconds, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new ClientSyncError("sync_aborted", "client sync was aborted"));
      return;
    }
    const done = () => {
      signal?.removeEventListener("abort", abort);
      resolve();
    };
    const timeout = setTimeout(done, milliseconds);
    const abort = () => {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
      reject(new ClientSyncError("sync_aborted", "client sync was aborted"));
    };
    signal?.addEventListener("abort", abort, { once: true });
    timeout.unref?.();
  });
}

export class ClientSyncEngine {
  constructor({
    rootDir,
    publicKeys,
    keyFingerprints,
    clientVersion,
    fetchDesiredState,
    validateInstalled,
    now = Date.now,
    sleep = abortableSleep,
    syncIntervalMs = DEFAULT_SYNC_INTERVAL_MS,
    maxResourceBytes = DEFAULT_MAX_RESOURCE_BYTES,
    lockStaleMs = DEFAULT_LOCK_STALE_MS,
  }) {
    if (typeof rootDir !== "string" || !path.isAbsolute(rootDir)) {
      throw new ClientSyncError("invalid_config", "rootDir must be an absolute path");
    }
    if (typeof clientVersion !== "string") {
      throw new ClientSyncError("invalid_config", "clientVersion must be a string");
    }
    if (typeof fetchDesiredState !== "function") {
      throw new ClientSyncError("invalid_config", "fetchDesiredState must be a function");
    }
    if (validateInstalled !== undefined && typeof validateInstalled !== "function") {
      throw new ClientSyncError("invalid_config", "validateInstalled must be a function");
    }
    if (!Number.isSafeInteger(syncIntervalMs)
        || syncIntervalMs < MIN_SYNC_INTERVAL_MS
        || syncIntervalMs > MAX_SYNC_INTERVAL_MS) {
      throw new ClientSyncError("invalid_config", "syncIntervalMs must be 1000-300000");
    }
    if (!Number.isSafeInteger(maxResourceBytes) || maxResourceBytes < 1) {
      throw new ClientSyncError("invalid_config", "maxResourceBytes must be a positive integer");
    }
    if (!Number.isSafeInteger(lockStaleMs) || lockStaleMs < 1) {
      throw new ClientSyncError("invalid_config", "lockStaleMs must be a positive integer");
    }
    this.rootDir = path.resolve(rootDir);
    this.keys = normalizeKeys(publicKeys, keyFingerprints);
    this.clientVersion = clientVersion;
    this.fetchDesiredState = fetchDesiredState;
    this.validateInstalled = validateInstalled;
    this.now = normalizeNow(now);
    this.sleep = sleep;
    this.syncIntervalMs = syncIntervalMs;
    this.maxResourceBytes = maxResourceBytes;
    this.lockStaleMs = lockStaleMs;
  }

  nowIso() {
    return new Date(this.now()).toISOString();
  }

  async acquireLock() {
    const lockPath = path.join(this.rootDir, "sync.lock");
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const nonce = crypto.randomUUID();
      try {
        const handle = await fs.open(lockPath, "wx", 0o600);
        try {
          await handle.writeFile(JSON.stringify({
            schemaVersion: 1,
            pid: process.pid,
            createdAt: this.nowIso(),
            nonce,
          }));
          await handle.sync();
        } finally {
          await handle.close();
        }
        return { lockPath, nonce };
      } catch (error) {
        if (error.code !== "EEXIST") {
          throw error;
        }
        const stat = await fs.lstat(lockPath);
        if (stat.isSymbolicLink()) {
          throw new ClientSyncError("path_symlink", "sync.lock must not be a symbolic link");
        }
        if (this.now() - stat.mtimeMs <= this.lockStaleMs) return null;
        await fs.unlink(lockPath);
      }
    }
    return null;
  }

  async releaseLock(lock) {
    try {
      const parsed = JSON.parse(await fs.readFile(lock.lockPath, "utf8"));
      if (parsed.nonce === lock.nonce) await fs.unlink(lock.lockPath);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }

  async syncOnce({ signal } = {}) {
    try {
      await ensureRoot(this.rootDir);
    } catch (error) {
      return { status: "failed", error: publicError(error), drift: [] };
    }
    let lock;
    try {
      lock = await this.acquireLock();
    } catch (error) {
      return { status: "failed", error: publicError(error), drift: [] };
    }
    if (!lock) {
      return {
        status: "busy",
        error: { code: "sync_locked" },
        drift: [],
      };
    }
    try {
      await removeStaging(this.rootDir);
      let state;
      try {
        state = await readClientSyncState(this.rootDir);
      } catch (error) {
        return { status: "failed", error: publicError(error), drift: [] };
      }
      if (signal?.aborted) {
        return {
          status: "failed",
          error: { code: "sync_aborted" },
          drift: [],
          state: stateForReport(state),
        };
      }
      const at = this.nowIso();
      let rawDesired;
      try {
        rawDesired = await this.fetchDesiredState({
          revision: state.revision,
          clientVersion: this.clientVersion,
          signal,
        });
        if (signal?.aborted) {
          throw new ClientSyncError("sync_aborted", "client sync was aborted");
        }
      } catch (error) {
        const code = error?.name === "AbortError" || signal?.aborted
          ? "sync_aborted"
          : "desired_state_unavailable";
        const next = stateWithAttempt(state, {
          at,
          status: code === "sync_aborted" ? "failed" : "offline",
          errorCode: code,
        });
        try {
          await writeClientSyncState(this.rootDir, next);
        } catch (writeError) {
          return {
            status: "failed",
            error: publicError(writeError),
            drift: [],
            state: stateForReport(state),
          };
        }
        return {
          status: code === "sync_aborted" ? "failed" : "offline",
          error: { code },
          drift: computeDrift(state, state.desired?.resources ?? [], state.disabledRecommended),
          state: stateForReport(next),
        };
      }
      let desired;
      try {
        desired = validateDesiredState(rawDesired, this.clientVersion, this.maxResourceBytes);
      } catch (error) {
        const syncError = asClientSyncError(error);
        await removeStaging(this.rootDir).catch(() => {});
        const next = stateWithAttempt(state, {
          at,
          status: "failed",
          errorCode: syncError.code,
        });
        let finalError = syncError;
        let reportedState = next;
        try {
          await writeClientSyncState(this.rootDir, next);
        } catch (writeError) {
          finalError = asClientSyncError(writeError);
          reportedState = state;
        }
        return {
          status: "failed",
          error: publicError(finalError),
          drift: computeDrift(state, state.desired?.resources ?? [], state.disabledRecommended),
          state: stateForReport(reportedState),
        };
      }

      const desiredResources = desired.resources.map(({ manifest }) => desiredRecord(manifest));
      const desiredById = new Map(desiredResources.map((record) => [record.resourceId, record]));
      const disabledRecommended = state.disabledRecommended.filter((id) => {
        const record = desiredById.get(id);
        return record && record.deliveryMode === "recommended";
      });
      const disabled = new Set(disabledRecommended);
      const drift = computeDrift(state, desiredResources, disabledRecommended);
      const currentById = new Map(state.resources.map((record) => [record.resourceId, record]));
      const installed = [];
      const unchanged = [];
      const skipped = [];
      const nextResources = [];
      try {
        for (const resource of desired.resources) {
          const { manifest } = resource;
          if (disabled.has(manifest.resourceId) && manifest.deliveryMode === "recommended") {
            skipped.push(manifest.resourceId);
            const previous = currentById.get(manifest.resourceId);
            if (previous) nextResources.push(previous);
            continue;
          }
          verifyResource(this.keys, manifest, resource.content);
          const result = await stageRelease(
            this.rootDir,
            this.keys,
            resource,
            currentById.get(manifest.resourceId),
            at,
            this.validateInstalled,
          );
          const previous = currentById.get(manifest.resourceId);
          if (recordsMatch(previous, result.record)) {
            unchanged.push(manifest.resourceId);
          } else {
            installed.push(manifest.resourceId);
          }
          nextResources.push(result.record);
        }

        const status = state.revision === desired.revision
          && installed.length === 0
          && skipped.length === 0
          && drift.length === 0
          ? "up_to_date"
          : "synced";
        const next = stateWithAttempt(state, {
          at,
          status,
          revision: desired.revision,
          desired: { revision: desired.revision, resources: desiredResources },
          resources: nextResources,
          disabledRecommended,
        });
        await writeClientSyncState(this.rootDir, next);
        return {
          status,
          revision: desired.revision,
          installed,
          unchanged,
          skipped,
          drift: [],
          state: stateForReport(next),
        };
      } catch (error) {
        const syncError = asClientSyncError(error);
        const next = stateWithAttempt(state, {
          at,
          status: "failed",
          errorCode: syncError.code,
          desired: { revision: desired.revision, resources: desiredResources },
          disabledRecommended,
        });
        let finalError = syncError;
        let reportedState = next;
        try {
          await writeClientSyncState(this.rootDir, next);
        } catch (writeError) {
          finalError = asClientSyncError(writeError);
          reportedState = state;
        }
        return {
          status: "failed",
          error: publicError(finalError),
          drift,
          state: stateForReport(reportedState),
        };
      }
    } catch (error) {
      return {
        status: "failed",
        error: publicError(error),
        drift: [],
      };
    } finally {
      try {
        await this.releaseLock(lock);
      } catch {
        // A cleanup failure must not hide the sync result.
      }
    }
  }

  async inspect() {
    await ensureRoot(this.rootDir);
    const state = await readClientSyncState(this.rootDir);
    const drift = [];
    for (const record of state.resources) {
      const actual = await verifyActiveRecord(this.rootDir, this.keys, record);
      if (actual) {
        drift.push({
          resourceId: record.resourceId,
          expectedReleaseId: record.releaseId,
          actualReleaseId: record.releaseId,
          state: actual.state,
        });
      }
    }
    if (state.desired) {
      for (const entry of computeDrift(
        { resources: state.resources },
        state.desired.resources,
        state.disabledRecommended,
      )) {
        if (!drift.some((item) => item.resourceId === entry.resourceId)) drift.push(entry);
      }
    }
    return {
      status: drift.length > 0 ? "drift" : state.lastError ? "last_sync_failed" : "in_sync",
      ...stateForReport(state),
      drift,
    };
  }

  async setRecommendedEnabled(resourceId, enabled) {
    if (typeof enabled !== "boolean") {
      throw new ClientSyncError("invalid_config", "enabled must be a boolean");
    }
    assertSafeSegment(resourceId, "resourceId");
    await ensureRoot(this.rootDir);
    const lock = await this.acquireLock();
    if (!lock) throw new ClientSyncError("sync_locked", "another sync is running");
    try {
      const state = await readClientSyncState(this.rootDir);
      const record = state.resources.find((item) => item.resourceId === resourceId);
      if (!record) throw new ClientSyncError("resource_not_installed", "resource is not installed");
      if (record.deliveryMode === "forced") {
        throw new ClientSyncError("forced_resource", "forced resources cannot be disabled");
      }
      const disabled = new Set(state.disabledRecommended);
      if (enabled) disabled.delete(resourceId);
      else disabled.add(resourceId);
      const next = { ...state, disabledRecommended: [...disabled].sort() };
      await writeClientSyncState(this.rootDir, next);
      return stateForReport(next);
    } finally {
      await this.releaseLock(lock);
    }
  }

  async run({ signal, onResult = () => {} } = {}) {
    if (typeof onResult !== "function") {
      throw new ClientSyncError("invalid_config", "onResult must be a function");
    }
    while (!signal?.aborted) {
      const result = await this.syncOnce({ signal });
      await onResult(result);
      if (signal?.aborted) return;
      try {
        await this.sleep(this.syncIntervalMs, signal);
      } catch (error) {
        if (asClientSyncError(error).code === "sync_aborted") return;
        throw error;
      }
    }
  }
}
