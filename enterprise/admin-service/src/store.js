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
