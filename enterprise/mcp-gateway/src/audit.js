import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const AUDIT_FIELDS = new Set([
  "id",
  "at",
  "action",
  "actor",
  "requestId",
  "operationId",
  "reason",
  "result",
  "targetType",
  "targetId",
  "metadata",
]);
const AUDIT_ACTIONS = new Set([
  "server.create",
  "server.update",
  "server.check",
  "client.issue",
  "client.revoke",
  "mcp.list",
  "mcp.call",
  "mcp.denied",
]);
const AUDIT_RESULTS = new Set(["allowed", "denied", "succeeded", "failed"]);
const TARGET_TYPES = new Set(["server", "client", "endpoint"]);
const SECRET_VALUE_PATTERNS = Object.freeze([
  /-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/i,
]);

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function safeText(value, maximum = 500, allowEmpty = false) {
  return typeof value === "string"
    && value.length <= maximum
    && (allowEmpty || value.length > 0)
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function timestamp(value) {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function validateMetadata(metadata) {
  if (!plainObject(metadata) || Object.keys(metadata).length > 32) return false;
  return Object.entries(metadata).every(([key, value]) => {
    if (!/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(key)) return false;
    return value === null
      || typeof value === "boolean"
      || (typeof value === "number" && Number.isFinite(value))
      || safeText(value, 1000, true);
  });
}

export function validateAuditEntry(entry) {
  if (!plainObject(entry)
      || Object.keys(entry).length !== AUDIT_FIELDS.size
      || Object.keys(entry).some((key) => !AUDIT_FIELDS.has(key))
      || !/^maud_[a-z0-9]{16,64}$/.test(entry.id)
      || !timestamp(entry.at)
      || !AUDIT_ACTIONS.has(entry.action)
      || !safeText(entry.actor, 200)
      || !safeText(entry.requestId, 128)
      || !safeText(entry.operationId, 128)
      || !safeText(entry.reason, 500)
      || !AUDIT_RESULTS.has(entry.result)
      || !TARGET_TYPES.has(entry.targetType)
      || !safeText(entry.targetId, 200, true)
      || !validateMetadata(entry.metadata)) {
    throw new Error("MCP audit log contains an invalid entry");
  }
  const serialized = JSON.stringify(entry);
  if (SECRET_VALUE_PATTERNS.some((pattern) => pattern.test(serialized))) {
    throw new Error("MCP audit log must not contain credential values");
  }
  return entry;
}

export class McpAuditLog {
  constructor(file) {
    this.file = file;
    this.entries = [];
    this.queue = Promise.resolve();
  }

  async load() {
    let text;
    try {
      text = await fs.readFile(this.file, "utf8");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await fs.mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
      await fs.writeFile(this.file, "", { flag: "a", mode: 0o600 });
      this.entries = [];
      return;
    }
    if (text && !text.endsWith("\n")) {
      throw new Error("MCP audit log has an incomplete final record");
    }
    this.entries = text
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        try {
          return validateAuditEntry(JSON.parse(line));
        } catch {
          throw new Error("MCP audit log contains a malformed record");
        }
      });
  }

  append(entry) {
    const record = validateAuditEntry({
      id: `maud_${crypto.randomUUID().replaceAll("-", "")}`,
      at: new Date().toISOString(),
      ...entry,
    });
    const run = this.queue.then(async () => {
      await fs.mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
      const handle = await fs.open(this.file, "a", 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(record)}\n`, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      this.entries.push(record);
      return record;
    });
    this.queue = run.catch(() => {});
    return run;
  }

  async list(limit = 100) {
    await this.queue;
    return this.entries.slice(-limit).reverse();
  }
}
