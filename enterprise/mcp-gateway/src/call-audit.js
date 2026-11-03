/**
 * M10 - MCP Resource Library: MCP Call Audit Logging
 *
 * Append-only audit log for MCP tool calls (employees calling through the
 * private MCP gateway). Integrates with the existing McpAuditLog format but
 * scopes to call-level metadata.
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const CALL_AUDIT_FIELDS = new Set([
  "id",
  "at",
  "actor",
  "requestId",
  "operationId",
  "mcpServerId",
  "toolName",
  "orgUnit",
  "userId",
  "requestParamsHash",
  "responseStatus",
  "durationMs",
  "errorMessage",
  "metadata",
]);

const CALL_RESULTS = new Set(["allowed", "denied", "succeeded", "failed"]);

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

function identityId(value) {
  return typeof value === "string"
    && /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(value);
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

export function validateCallAuditEntry(entry) {
  if (!plainObject(entry)
      || Object.keys(entry).length !== CALL_AUDIT_FIELDS.size
      || Object.keys(entry).some((key) => !CALL_AUDIT_FIELDS.has(key))
      || !/^maud_call_[a-z0-9]{16,64}$/.test(entry.id)
      || !timestamp(entry.at)
      || !safeText(entry.actor, 200)
      || !safeText(entry.requestId, 128)
      || !safeText(entry.operationId, 128)
      || !safeText(entry.mcpServerId, 200)
      || !safeText(entry.toolName, 128)
      || !safeText(entry.orgUnit, 200, true)
      || !identityId(entry.userId)
      || !safeText(entry.requestParamsHash, 64)
      || !CALL_RESULTS.has(entry.responseStatus)
      || !Number.isFinite(entry.durationMs)
      || entry.durationMs < 0
      || (entry.errorMessage != null && !safeText(entry.errorMessage, 1000))
      || !validateMetadata(entry.metadata)) {
    throw new Error("MCP call audit entry is invalid");
  }
  return entry;
}

export class McpCallAuditStore {
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
      throw new Error("MCP call audit log has an incomplete final record");
    }
    this.entries = text
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        try {
          return validateCallAuditEntry(JSON.parse(line));
        } catch {
          throw new Error("MCP call audit log contains a malformed record");
        }
      });
  }

  append(entry) {
    const record = validateCallAuditEntry({
      id: `maud_call_${crypto.randomUUID().replaceAll("-", "")}`,
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

  async get(callAuditId) {
    await this.queue;
    return this.entries.find((entry) => entry.id === callAuditId) ?? null;
  }
}