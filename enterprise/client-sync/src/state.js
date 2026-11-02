import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import { ClientSyncError } from "./errors.js";

export const CLIENT_SYNC_STATE_SCHEMA_VERSION = 1;
export const MAX_STATE_BYTES = 1024 * 1024;

const ACTIVE_FIELDS = new Set([
  "resourceId",
  "releaseId",
  "resourceVersion",
  "kind",
  "deliveryMode",
  "hash",
  "manifestDigest",
  "signingKeyId",
  "installedAt",
  "directory",
]);
const DESIRED_FIELDS = new Set([
  "resourceId",
  "releaseId",
  "resourceVersion",
  "kind",
  "deliveryMode",
  "hash",
  "manifestDigest",
  "signingKeyId",
]);
const STATE_FIELDS = new Set([
  "schemaVersion",
  "revision",
  "lastSuccessfulSyncAt",
  "lastAttemptAt",
  "lastError",
  "desired",
  "resources",
  "disabledRecommended",
]);
const ERROR_FIELDS = new Set(["code", "at"]);
const DESIRED_STATE_FIELDS = new Set(["revision", "resources"]);
const SAFE_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function assertSafeSegment(value, label) {
  if (typeof value !== "string"
      || !SAFE_SEGMENT.test(value)
      || value === "."
      || value === "..") {
    throw new ClientSyncError("path_traversal", `${label} is not a safe path segment`);
  }
  return value;
}

function assertIsoTimestamp(value, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    throw new ClientSyncError("invalid_state", `${label} must be an ISO timestamp`);
  }
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !/^sha256:[a-f0-9]{64}$/.test(value)) {
    throw new ClientSyncError("invalid_state", `${label} must be a SHA-256 digest`);
  }
}

function assertExactFields(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ClientSyncError("invalid_state", `${label} must be an object`);
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !fields.has(key))
      || [...fields].some((key) => !Object.hasOwn(value, key))) {
    throw new ClientSyncError("invalid_state", `${label} fields are invalid`);
  }
}

function accountRecord(value, label, desired) {
  assertExactFields(value, desired ? DESIRED_FIELDS : ACTIVE_FIELDS, label);
  for (const key of ["resourceId", "releaseId", "resourceVersion", "kind", "deliveryMode", "signingKeyId"]) {
    if (typeof value[key] !== "string" || !value[key]) {
      throw new ClientSyncError("invalid_state", `${label}.${key} must be a string`);
    }
  }
  assertSafeSegment(value.resourceId, `${label}.resourceId`);
  assertSafeSegment(value.releaseId, `${label}.releaseId`);
  if (value.deliveryMode !== "forced" && value.deliveryMode !== "recommended") {
    throw new ClientSyncError("invalid_state", `${label}.deliveryMode is invalid`);
  }
  assertDigest(value.hash, `${label}.hash`);
  assertDigest(value.manifestDigest, `${label}.manifestDigest`);
  if (!desired) {
    assertIsoTimestamp(value.installedAt, `${label}.installedAt`);
    if (typeof value.directory !== "string" || !value.directory) {
      throw new ClientSyncError("invalid_state", `${label}.directory must be a string`);
    }
    const expected = `releases/${value.resourceId}/${value.releaseId}`;
    if (value.directory !== expected) {
      throw new ClientSyncError("invalid_state", `${label}.directory is invalid`);
    }
  }
  return { ...value };
}

export function initialClientSyncState() {
  return {
    schemaVersion: CLIENT_SYNC_STATE_SCHEMA_VERSION,
    revision: null,
    lastSuccessfulSyncAt: null,
    lastAttemptAt: null,
    lastError: null,
    desired: null,
    resources: [],
    disabledRecommended: [],
  };
}

export function validateClientSyncState(state) {
  assertExactFields(state, STATE_FIELDS, "state");
  if (state.schemaVersion !== CLIENT_SYNC_STATE_SCHEMA_VERSION) {
    throw new ClientSyncError("invalid_state", "state schemaVersion is unsupported");
  }
  if (state.revision !== null && (typeof state.revision !== "string" || !state.revision)) {
    throw new ClientSyncError("invalid_state", "state.revision must be a string or null");
  }
  if (state.lastSuccessfulSyncAt !== null) assertIsoTimestamp(state.lastSuccessfulSyncAt, "state.lastSuccessfulSyncAt");
  if (state.lastAttemptAt !== null) assertIsoTimestamp(state.lastAttemptAt, "state.lastAttemptAt");
  if (state.lastError !== null) {
    assertExactFields(state.lastError, ERROR_FIELDS, "state.lastError");
    if (!SAFE_CODE.test(state.lastError.code)) {
      throw new ClientSyncError("invalid_state", "state.lastError.code is invalid");
    }
    assertIsoTimestamp(state.lastError.at, "state.lastError.at");
  }
  if (!Array.isArray(state.resources)) {
    throw new ClientSyncError("invalid_state", "state.resources must be an array");
  }
  const resourceIds = new Set();
  const resources = state.resources.map((record, index) => {
    const parsed = accountRecord(record, `state.resources[${index}]`, false);
    if (resourceIds.has(parsed.resourceId)) {
      throw new ClientSyncError("invalid_state", "state.resources has duplicate resource ids");
    }
    resourceIds.add(parsed.resourceId);
    return parsed;
  });
  if (!Array.isArray(state.disabledRecommended)
      || state.disabledRecommended.some((id) => typeof id !== "string")
      || new Set(state.disabledRecommended).size !== state.disabledRecommended.length) {
    throw new ClientSyncError("invalid_state", "state.disabledRecommended is invalid");
  }
  const disabledRecommended = state.disabledRecommended.map((id) => assertSafeSegment(id, "disabled resource"));
  let desired = null;
  if (state.desired !== null) {
    assertExactFields(state.desired, DESIRED_STATE_FIELDS, "state.desired");
    if (typeof state.desired.revision !== "string" || !state.desired.revision) {
      throw new ClientSyncError("invalid_state", "state.desired.revision is invalid");
    }
    if (!Array.isArray(state.desired.resources)) {
      throw new ClientSyncError("invalid_state", "state.desired.resources is invalid");
    }
    const desiredIds = new Set();
    const desiredResources = state.desired.resources.map((record, index) => {
      const parsed = accountRecord(record, `state.desired.resources[${index}]`, true);
      if (desiredIds.has(parsed.resourceId)) {
        throw new ClientSyncError("invalid_state", "state.desired.resources has duplicate resource ids");
      }
      desiredIds.add(parsed.resourceId);
      return parsed;
    });
    desired = { revision: state.desired.revision, resources: desiredResources };
  }
  return {
    schemaVersion: CLIENT_SYNC_STATE_SCHEMA_VERSION,
    revision: state.revision,
    lastSuccessfulSyncAt: state.lastSuccessfulSyncAt,
    lastAttemptAt: state.lastAttemptAt,
    lastError: state.lastError ? { ...state.lastError } : null,
    desired,
    resources,
    disabledRecommended,
  };
}

async function lstatOrNull(file) {
  try {
    return await fs.lstat(file);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

export async function readClientSyncState(root) {
  const statePath = path.join(root, "state.json");
  const stat = await lstatOrNull(statePath);
  if (!stat) return initialClientSyncState();
  if (stat.isSymbolicLink()) {
    throw new ClientSyncError("path_symlink", "state.json must not be a symbolic link");
  }
  if (!stat.isFile() || stat.size > MAX_STATE_BYTES) {
    throw new ClientSyncError("invalid_state", "state.json is not a valid state file");
  }
  let parsed;
  try {
    parsed = JSON.parse(await fs.readFile(statePath, "utf8"));
  } catch {
    throw new ClientSyncError("invalid_state", "state.json is not valid JSON");
  }
  return validateClientSyncState(parsed);
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

export async function writeClientSyncState(root, state) {
  const validated = validateClientSyncState(state);
  const statePath = path.join(root, "state.json");
  const temporary = path.join(
    root,
    `.state.json.${process.pid}.${crypto.randomUUID()}.tmp`,
  );
  const body = `${JSON.stringify(validated)}\n`;
  try {
    const handle = await fs.open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(body, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.rename(temporary, statePath);
    await syncDirectory(root);
  } catch {
    await fs.rm(temporary, { force: true });
    throw new ClientSyncError("state_write_failed", "state.json could not be committed");
  }
}

export function stateWithAttempt(state, {
  at,
  status,
  errorCode = status,
  revision = state.revision,
  desired = state.desired,
  resources = state.resources,
  disabledRecommended = state.disabledRecommended,
}) {
  const successful = status === "synced" || status === "up_to_date";
  return validateClientSyncState({
    ...state,
    revision: successful ? revision : state.revision,
    lastSuccessfulSyncAt: successful ? at : state.lastSuccessfulSyncAt,
    lastAttemptAt: at,
    lastError: successful ? null : { code: errorCode, at },
    desired,
    resources,
    disabledRecommended,
  });
}
