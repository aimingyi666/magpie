import fs from "node:fs/promises";
import path from "node:path";
import { createUnknownPolicy, normalizeStoredPolicy } from "./policy.js";

export const STORE_SCHEMA_VERSION = 3;
export const POLICY_MIGRATION_VERSION = 1;
export const ISSUANCE_STATES = Object.freeze([
  "preparing",
  "issued",
  "syncing",
  "synced",
  "committed",
  "failed",
  "unknown",
]);
const ISSUANCE_STATE_SET = new Set(ISSUANCE_STATES);

function emptyStore() {
  return {
    version: STORE_SCHEMA_VERSION,
    policyMigrationVersion: POLICY_MIGRATION_VERSION,
    users: {},
    devices: {},
    credentials: {},
    sessions: {},
    pendingRevocations: [],
    issuanceJournal: [],
  };
}

function migrateLoaded(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("auth store must be a JSON object");
  }
  if (Number.isInteger(data.version) && data.version > STORE_SCHEMA_VERSION) {
    throw new Error(`auth store schema ${data.version} is newer than supported ${STORE_SCHEMA_VERSION}`);
  }
  for (const key of Object.keys(emptyStore())) {
    if (data[key] == null) data[key] = emptyStore()[key];
  }
  for (const key of ["users", "devices", "credentials", "sessions"]) {
    if (!data[key] || typeof data[key] !== "object" || Array.isArray(data[key])) {
      throw new Error(`auth store ${key} must be an object`);
    }
  }
  if (!Array.isArray(data.pendingRevocations)) {
    throw new Error("auth store pendingRevocations must be an array");
  }
  if (!Array.isArray(data.issuanceJournal)) {
    throw new Error("auth store issuanceJournal must be an array");
  }
  for (const entry of data.issuanceJournal) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error("auth store issuanceJournal must contain objects");
    }
    if (!entry.id || !entry.enterpriseIssuanceId || !ISSUANCE_STATE_SET.has(entry.state)) {
      throw new Error("auth store issuanceJournal entry is invalid");
    }
    if (entry.keySecret || entry.deviceToken || entry.tokenHash) {
      throw new Error("auth store issuanceJournal must not contain credentials");
    }
  }
  for (const entry of data.pendingRevocations) {
    if (!entry || typeof entry !== "object" || !entry.id) {
      throw new Error("auth store pendingRevocations must contain key ids");
    }
  }

  // Older M1 stores kept only each device's current Gateway Key ID. Keep that
  // key visible to read-only administration without inventing any history.
  const now = new Date().toISOString();
  for (const [userId, user] of Object.entries(data.users)) {
    if (!user || typeof user !== "object" || Array.isArray(user)) {
      throw new Error(`auth store user ${userId} must be an object`);
    }
    const source = user.gatewayPolicy ? "store_repair" : "m1_unknown";
    user.gatewayPolicy = normalizeStoredPolicy(user.gatewayPolicy, now, source);
  }

  for (const device of Object.values(data.devices)) {
    if (!device || !device.id || !device.userId || !device.gatewayKeyId) continue;
    if (data.credentials[device.gatewayKeyId]) continue;
    data.credentials[device.gatewayKeyId] = {
      id: device.gatewayKeyId,
      userId: device.userId,
      deviceId: device.id,
      status: device.status === "active" ? "active" : "revoked",
      createdAt: device.createdAt || now,
      expiresAt: device.gatewayKeyExpiresAt || "",
      ...(device.status === "active" ? {} : { revokedAt: device.revokedAt || now }),
    };
  }
  for (const credential of Object.values(data.credentials)) {
    if (!credential || typeof credential !== "object" || Array.isArray(credential)) {
      throw new Error("auth store credentials must contain objects");
    }
    const user = data.users[credential.userId];
    const policy = user?.gatewayPolicy || createUnknownPolicy(now, "m1_unknown");
    if (!Number.isSafeInteger(credential.policyVersion) || credential.policyVersion < 0) {
      credential.policyVersion = policy.version;
    }
    if (!["pending", "synced", "failed", "partial", "unknown"].includes(credential.policySyncState)) {
      credential.policySyncState = "pending";
      credential.lastPolicyErrorCode = "policy_setup_required";
    }
  }
  data.version = STORE_SCHEMA_VERSION;
  data.policyMigrationVersion = POLICY_MIGRATION_VERSION;
  return data;
}

async function writeAtomic(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  const handle = await fs.open(temporary, "w", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(temporary, file);
}

export class JsonStore {
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
