import fs from "node:fs/promises";
import path from "node:path";
import { APPROVAL_STATUSES } from "./approval.js";

function emptyStore() {
  return {
    version: 1,
    orgUnits: {},
    userOrgUnits: {},
    roleBindings: {},
    adminSessions: {},
    adminAuditLogs: [],
    adminSystemAuditLogs: [],
    adminOperations: {},
    adminIdempotency: {},
    approvalRequests: {},
    approvalDecisions: {},
    approvalConsumptions: {},
    approvalCallbackEvents: {},
    approvalCallbackNonces: {},
  };
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

function validateLoaded(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("admin store must be a JSON object");
  }
  if (value.version !== 1) throw new Error(`unsupported admin store version ${value.version}`);
  for (const key of Object.keys(emptyStore())) {
    if (value[key] == null) value[key] = emptyStore()[key];
  }
  for (const key of [
    "orgUnits",
    "userOrgUnits",
    "roleBindings",
    "adminSessions",
    "adminOperations",
    "adminIdempotency",
    "approvalRequests",
    "approvalDecisions",
    "approvalConsumptions",
    "approvalCallbackEvents",
    "approvalCallbackNonces",
  ]) {
    if (!value[key] || typeof value[key] !== "object" || Array.isArray(value[key])) {
      throw new Error(`admin store ${key} must be an object`);
    }
  }
  for (const [userId, orgUnitId] of Object.entries(value.userOrgUnits)) {
    if (!userId || typeof orgUnitId !== "string" || !orgUnitId) {
      throw new Error("admin store userOrgUnits values must be non-empty organization IDs");
    }
  }
  if (!Array.isArray(value.adminAuditLogs)) {
    throw new Error("admin store adminAuditLogs must be an array");
  }
  if (!Array.isArray(value.adminSystemAuditLogs)) {
    throw new Error("admin store adminSystemAuditLogs must be an array");
  }
  const approvalStatuses = new Set(APPROVAL_STATUSES);
  for (const [approvalId, approval] of Object.entries(value.approvalRequests)) {
    if (!approval || typeof approval !== "object" || Array.isArray(approval)) {
      throw new Error("admin store approvalRequests values must be objects");
    }
    if (approval.id !== approvalId || !approvalId.startsWith("apr_")) {
      throw new Error("admin store approval request IDs must be stable apr_ IDs");
    }
    if (!approvalStatuses.has(approval.status)) {
      throw new Error("admin store approval request has an unsupported status");
    }
    for (const key of [
      "environmentId",
      "policyVersion",
      "requesterSubjectId",
      "action",
      "targetType",
      "targetId",
      "targetOrgUnitId",
      "riskLevel",
      "reason",
      "payloadDigest",
      "bindingDigest",
      "createdAt",
      "updatedAt",
      "expiresAt",
    ]) {
      if (typeof approval[key] !== "string" || !approval[key]) {
        throw new Error(`admin store approval request ${key} must be a non-empty string`);
      }
    }
    if (![approval.payloadDigest, approval.bindingDigest]
      .every((digest) => /^[a-f0-9]{64}$/.test(digest))) {
      throw new Error("admin store approval request digests must be SHA-256 hex");
    }
    if (!Array.isArray(approval.stateHistory) || approval.stateHistory.length === 0) {
      throw new Error("admin store approval request stateHistory must be a non-empty array");
    }
  }
  for (const [decisionId, decision] of Object.entries(value.approvalDecisions)) {
    if (!decision || typeof decision !== "object" || Array.isArray(decision)
        || decision.id !== decisionId
        || !value.approvalRequests[decision.approvalId]) {
      throw new Error("admin store approvalDecisions must reference a stored approval");
    }
  }
  for (const [approvalId, consumption] of Object.entries(value.approvalConsumptions)) {
    if (!value.approvalRequests[approvalId]
        || !consumption
        || typeof consumption !== "object"
        || Array.isArray(consumption)
        || consumption.approvalId !== approvalId
        || typeof consumption.operationId !== "string"
        || !consumption.operationId) {
      throw new Error("admin store approvalConsumptions must reference an approval and operation");
    }
  }
  for (const [eventId, event] of Object.entries(value.approvalCallbackEvents)) {
    if (!event
        || typeof event !== "object"
        || Array.isArray(event)
        || event.eventId !== eventId
        || !value.approvalRequests[event.approvalId]
        || !/^[a-f0-9]{64}$/.test(String(event.eventDigest || ""))
        || !/^[a-f0-9]{64}$/.test(String(event.nonceDigest || ""))
        || !["approved", "rejected"].includes(event.outcome)) {
      throw new Error("admin store approvalCallbackEvents contains an invalid event");
    }
    for (const key of [
      "issuer",
      "audience",
      "externalReference",
      "actorSubjectId",
      "decisionId",
      "receivedAt",
    ]) {
      if (typeof event[key] !== "string" || !event[key]) {
        throw new Error(`admin store approval callback event ${key} is invalid`);
      }
    }
    if (!Number.isFinite(Date.parse(event.receivedAt))) {
      throw new Error("admin store approval callback event receivedAt is invalid");
    }
  }
  for (const [nonceDigest, nonce] of Object.entries(value.approvalCallbackNonces)) {
    if (!nonce
        || typeof nonce !== "object"
        || Array.isArray(nonce)
        || nonce.nonceDigest !== nonceDigest
        || !/^[a-f0-9]{64}$/.test(nonceDigest)
        || !value.approvalCallbackEvents[nonce.eventId]
        || !Number.isFinite(Date.parse(nonce.receivedAt))
        || !Number.isFinite(Date.parse(nonce.expiresAt))) {
      throw new Error("admin store approvalCallbackNonces contains an invalid nonce");
    }
  }
  return value;
}

export class JsonStore {
  constructor(file) {
    this.file = file;
    this.data = emptyStore();
    this.queue = Promise.resolve();
  }

  async load() {
    try {
      this.data = validateLoaded(JSON.parse(await fs.readFile(this.file, "utf8")));
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
      validateLoaded(draft);
      await writeAtomic(this.file, draft);
      this.data = draft;
      return result;
    });
    this.queue = run.catch(() => {});
    return run;
  }
}
