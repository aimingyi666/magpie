import fs from "node:fs/promises";
import path from "node:path";

import {
  RESOURCE_DELIVERY_MODES,
  RESOURCE_KINDS,
  validateManifestShape,
} from "./manifest.js";

export const STORE_SCHEMA_VERSION = 1;
export const RESOURCE_STATUSES = Object.freeze(["draft", "published"]);
export const RELEASE_STATUSES = Object.freeze(["candidate", "published", "superseded"]);

const STORE_FIELDS = new Set([
  "version",
  "resources",
  "releases",
  "idempotency",
  "resourceAuditLogs",
]);
const RESOURCE_STATUS_SET = new Set(RESOURCE_STATUSES);
const RELEASE_STATUS_SET = new Set(RELEASE_STATUSES);
const RESOURCE_KIND_SET = new Set(RESOURCE_KINDS);
const DELIVERY_MODE_SET = new Set(RESOURCE_DELIVERY_MODES);

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function safeText(value, maximum = 500) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function timestamp(value) {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function stableId(value, prefix) {
  return typeof value === "string" && new RegExp(`^${prefix}[a-z0-9]{16,64}$`).test(value);
}

function textArray(value, maximum) {
  return Array.isArray(value)
    && value.length > 0
    && value.length <= maximum
    && value.every((item) => safeText(item, 128))
    && new Set(value).size === value.length;
}

function emptyStore() {
  return {
    version: STORE_SCHEMA_VERSION,
    resources: {},
    releases: {},
    idempotency: {},
    resourceAuditLogs: [],
  };
}

function validateResource(resourceId, resource) {
  if (!plainObject(resource) || resource.id !== resourceId || !stableId(resourceId, "res_")) {
    throw new Error("resource store contains an invalid resource id");
  }
  if (!RESOURCE_KIND_SET.has(resource.kind)
      || !DELIVERY_MODE_SET.has(resource.deliveryMode)
      || !RESOURCE_STATUS_SET.has(resource.status)) {
    throw new Error(`resource store resource ${resourceId} has invalid state`);
  }
  if (!safeText(resource.name, 200)
      || typeof resource.description !== "string"
      || resource.description.length > 2000
      || !safeText(resource.publisher, 128)
      || !textArray(resource.assignments, 100)) {
    throw new Error(`resource store resource ${resourceId} has invalid metadata`);
  }
  if (!plainObject(resource.compatibility)
      || Object.keys(resource.compatibility).length !== 1
      || !safeText(resource.compatibility.minClientVersion, 64)) {
    throw new Error(`resource store resource ${resourceId} has invalid compatibility`);
  }
  if (typeof resource.currentReleaseId !== "string"
      || (resource.currentReleaseId && !stableId(resource.currentReleaseId, "rel_"))
      || !timestamp(resource.createdAt)
      || !timestamp(resource.updatedAt)
      || !safeText(resource.createdBy, 128)
      || !safeText(resource.updatedBy, 128)) {
    throw new Error(`resource store resource ${resourceId} has invalid lifecycle metadata`);
  }
  if (resource.status === "published" && !resource.currentReleaseId) {
    throw new Error(`resource store resource ${resourceId} is published without a release`);
  }
  if (resource.status === "draft" && resource.currentReleaseId) {
    throw new Error(`resource store resource ${resourceId} is a draft with a current release`);
  }
}

function validateRelease(releaseId, release, resources) {
  if (!plainObject(release) || release.id !== releaseId || !stableId(releaseId, "rel_")) {
    throw new Error("resource store contains an invalid release id");
  }
  const resource = resources[release.resourceId];
  if (!resource) throw new Error(`resource store release ${releaseId} has no resource`);
  if (!safeText(release.resourceVersion, 128)
      || !safeText(release.mediaType, 128)
      || !RELEASE_STATUS_SET.has(release.status)
      || !Number.isSafeInteger(release.contentBytes)
      || release.contentBytes < 1
      || !/^sha256:[a-f0-9]{64}$/.test(release.hash)
      || !timestamp(release.createdAt)
      || !safeText(release.createdBy, 128)) {
    throw new Error(`resource store release ${releaseId} has invalid metadata`);
  }
  try {
    validateManifestShape(release.manifest);
  } catch {
    throw new Error(`resource store release ${releaseId} has an invalid manifest`);
  }
  const manifest = release.manifest;
  if (manifest.resourceId !== release.resourceId
      || manifest.releaseId !== release.id
      || manifest.resourceVersion !== release.resourceVersion
      || manifest.kind !== resource.kind
      || manifest.hash !== release.hash
      || manifest.contentBytes !== release.contentBytes
      || manifest.mediaType !== release.mediaType
      || manifest.publisher !== resource.publisher
      || manifest.assignments.length !== resource.assignments.length
      || manifest.assignments.some((item, index) => item !== resource.assignments[index])) {
    throw new Error(`resource store release ${releaseId} manifest does not match its record`);
  }
  if (release.status === "published" && release.resourceId === resource.id
      && resource.currentReleaseId !== release.id) {
    throw new Error(`resource store release ${releaseId} is published but not current`);
  }
}

function validateIdempotency(key, record) {
  if (!/^[a-f0-9]{64}$/.test(key)
      || !plainObject(record)
      || !/^sha256:[a-f0-9]{64}$/.test(record.fingerprint)
      || !safeText(record.operationId, 128)
      || !["POST"].includes(record.method)
      || !safeText(record.path, 1024)
      || !Number.isInteger(record.statusCode)
      || record.statusCode < 200
      || record.statusCode > 299
      || !plainObject(record.responseBody)
      || !timestamp(record.createdAt)) {
    throw new Error("resource store contains an invalid idempotency record");
  }
}

function validateAudit(entry, resources, releases) {
  if (!plainObject(entry)
      || !stableId(entry.id, "raud_")
      || !resources[entry.resourceId]
      || (entry.releaseId && !releases[entry.releaseId])
      || !["resource.create", "release.create", "release.publish", "release.rollback"].includes(entry.action)
      || !safeText(entry.actor, 128)
      || !safeText(entry.operationId, 128)
      || !safeText(entry.reason, 500)
      || typeof entry.approvalId !== "string"
      || entry.approvalId.length > 128
      || !timestamp(entry.at)
      || entry.result !== "committed") {
    throw new Error("resource store resourceAuditLogs contains an invalid entry");
  }
}

function migrateLoaded(data) {
  if (!plainObject(data)) throw new Error("resource store must be a JSON object");
  if (!Number.isInteger(data.version) || data.version > STORE_SCHEMA_VERSION) {
    throw new Error(`resource store schema ${data.version} is unsupported`);
  }
  if (Object.keys(data).some((key) => !STORE_FIELDS.has(key))) {
    throw new Error("resource store contains unknown fields");
  }
  for (const key of Object.keys(emptyStore())) {
    if (data[key] == null) data[key] = emptyStore()[key];
  }
  if (!plainObject(data.resources)
      || !plainObject(data.releases)
      || !plainObject(data.idempotency)
      || !Array.isArray(data.resourceAuditLogs)) {
    throw new Error("resource store collection types are invalid");
  }
  for (const [resourceId, resource] of Object.entries(data.resources)) {
    validateResource(resourceId, resource);
  }
  for (const [releaseId, release] of Object.entries(data.releases)) {
    validateRelease(releaseId, release, data.resources);
  }
  for (const resource of Object.values(data.resources)) {
    if (resource.currentReleaseId && !data.releases[resource.currentReleaseId]) {
      throw new Error(`resource store resource ${resource.id} references a missing release`);
    }
  }
  for (const [key, record] of Object.entries(data.idempotency)) {
    validateIdempotency(key, record);
  }
  for (const entry of data.resourceAuditLogs) {
    validateAudit(entry, data.resources, data.releases);
  }
  if (JSON.stringify(data).includes("-----BEGIN PRIVATE KEY-----")
      || JSON.stringify(data).includes("-----BEGIN OPENSSH PRIVATE KEY-----")) {
    throw new Error("resource store must not contain a private key");
  }
  data.version = STORE_SCHEMA_VERSION;
  return data;
}

async function writeAtomic(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`;
  const handle = await fs.open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(temporary, file);
}

export class ResourceStore {
  constructor(file) {
    this.file = file;
    this.data = emptyStore();
    this.queue = Promise.resolve();
  }

  async load() {
    try {
      this.data = migrateLoaded(JSON.parse(await fs.readFile(this.file, "utf8")));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await writeAtomic(this.file, this.data);
    }
    return this.data;
  }

  async read(fn) {
    await this.queue;
    return fn(this.data);
  }

  mutate(fn) {
    const run = this.queue.then(async () => {
      const draft = structuredClone(this.data);
      const result = await fn(draft);
      migrateLoaded(draft);
      await writeAtomic(this.file, draft);
      this.data = draft;
      return result;
    });
    this.queue = run.catch(() => {});
    return run;
  }
}
