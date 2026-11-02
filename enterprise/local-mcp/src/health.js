import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import { LOCAL_MCP_RISKS } from "./package.js";
import { LocalMcpError } from "./errors.js";

export const LOCAL_MCP_HEALTH_SCHEMA_VERSION = 1;
export const MAX_HEALTH_BYTES = 2 * 1024 * 1024;

const SAFE_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const RUNTIME_STATUSES = new Set(["stopped", "starting", "running", "failed", "timeout"]);
const TOOL_STATUSES = new Set(["started", "succeeded", "failed", "denied"]);

function initialHealth() {
  return {
    schemaVersion: LOCAL_MCP_HEALTH_SCHEMA_VERSION,
    updatedAt: null,
    packages: [],
  };
}

function assertPackageId(packageId, releaseId) {
  if (!SAFE_SEGMENT.test(packageId) || !SAFE_SEGMENT.test(releaseId)) {
    throw new LocalMcpError("invalid_config", "health package identity is invalid");
  }
}

function assertCode(value, label) {
  if (value !== null && !SAFE_CODE.test(value)) {
    throw new LocalMcpError("invalid_config", `${label} is invalid`);
  }
}

function assertInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 2 ** 32) {
    throw new LocalMcpError("invalid_config", `${label} is invalid`);
  }
}

function validateHealth(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new LocalMcpError("invalid_health", "health state must be an object");
  }
  if (Object.keys(value).sort().join(",") !== "packages,schemaVersion,updatedAt"
      || value.schemaVersion !== LOCAL_MCP_HEALTH_SCHEMA_VERSION
      || !Array.isArray(value.packages)) {
    throw new LocalMcpError("invalid_health", "health state schema is invalid");
  }
  const identities = new Set();
  const packages = value.packages.map((record) => {
    assertPackageId(record.packageId, record.releaseId);
    const identity = `${record.packageId}\0${record.releaseId}`;
    if (identities.has(identity)) {
      throw new LocalMcpError("invalid_health", "health state contains duplicate packages");
    }
    identities.add(identity);
    if (!RUNTIME_STATUSES.has(record.runtimeStatus)
        || !["unknown", "healthy", "degraded", "unhealthy"].includes(record.health)
        || !Array.isArray(record.tools)
        || typeof record.updatedAt !== "string"
        || Number.isNaN(Date.parse(record.updatedAt))) {
      throw new LocalMcpError("invalid_health", "health package record is invalid");
    }
    assertCode(record.lastErrorCode ?? null, "health.lastErrorCode");
    return record;
  });
  return {
    schemaVersion: LOCAL_MCP_HEALTH_SCHEMA_VERSION,
    updatedAt: value.updatedAt,
    packages,
  };
}

async function readOrInitial(file) {
  try {
    const stat = await fs.lstat(file);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > MAX_HEALTH_BYTES) {
      throw new LocalMcpError("invalid_health", "health state file is unsafe");
    }
    return validateHealth(JSON.parse(await fs.readFile(file, "utf8")));
  } catch (error) {
    if (error.code === "ENOENT") return initialHealth();
    if (error instanceof LocalMcpError) throw error;
    throw new LocalMcpError("invalid_health", "health state could not be read");
  }
}

async function writeAtomic(file, state) {
  const temporary = `${file}.${process.pid}.${crypto.randomUUID()}.tmp`;
  let handle;
  try {
    handle = await fs.open(temporary, "wx", 0o600);
    await handle.writeFile(`${JSON.stringify(state)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, file);
  } catch {
    await handle?.close().catch(() => {});
    await fs.rm(temporary, { force: true });
    throw new LocalMcpError("health_write_failed", "health state could not be committed");
  }
}

export class LocalMcpHealthStore {
  constructor(rootDir, { now = () => Date.now() } = {}) {
    if (typeof rootDir !== "string" || !path.isAbsolute(rootDir)) {
      throw new LocalMcpError("invalid_config", "health rootDir must be absolute");
    }
    if (typeof now !== "function") {
      throw new LocalMcpError("invalid_config", "health now must be a function");
    }
    this.file = path.join(rootDir, "health.json");
    this.now = now;
    this.queue = Promise.resolve();
  }

  timestamp() {
    const value = this.now();
    const milliseconds = value instanceof Date ? value.getTime() : Number(value);
    if (!Number.isFinite(milliseconds)) {
      throw new LocalMcpError("invalid_config", "health now returned an invalid value");
    }
    return new Date(milliseconds).toISOString();
  }

  async read() {
    await this.queue.catch(() => {});
    return readOrInitial(this.file);
  }

  async report() {
    return this.read();
  }

  mutate(operation) {
    this.queue = this.queue.then(async () => {
      await fs.mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
      const state = await readOrInitial(this.file);
      const result = operation(state);
      state.updatedAt = this.timestamp();
      await writeAtomic(this.file, validateHealth(state));
      return result;
    });
    return this.queue;
  }

  recordInstalled(manifest) {
    return this.mutate((state) => {
      const packages = state.packages.filter(
        (item) => item.packageId !== manifest.packageId || item.releaseId !== manifest.releaseId,
      );
      packages.push({
        packageId: manifest.packageId,
        releaseId: manifest.releaseId,
        packageVersion: manifest.packageVersion,
        packageDigest: manifest.packageDigest,
        publisher: manifest.publisher,
        signingKeyId: manifest.signingKeyId,
        installStatus: "installed",
        runtimeStatus: "stopped",
        health: "unknown",
        lastErrorCode: null,
        lastExit: null,
        tools: manifest.tools.map((tool) => ({
          name: tool.name,
          risk: tool.risk,
          calls: 0,
          successes: 0,
          failures: 0,
          denied: 0,
          lastStatus: null,
          lastErrorCode: null,
          lastCalledAt: null,
        })),
        updatedAt: this.timestamp(),
      });
      state.packages = packages;
    });
  }

  recordRuntime(packageId, releaseId, {
    runtimeStatus,
    health,
    errorCode = null,
    exitCode = null,
    signal = null,
  }) {
    assertPackageId(packageId, releaseId);
    if (!RUNTIME_STATUSES.has(runtimeStatus)) {
      throw new LocalMcpError("invalid_config", "health runtimeStatus is invalid");
    }
    if (!["unknown", "healthy", "degraded", "unhealthy"].includes(health)) {
      throw new LocalMcpError("invalid_config", "health status is invalid");
    }
    assertCode(errorCode, "health errorCode");
    if (exitCode !== null && (!Number.isInteger(exitCode) || exitCode < 0)) {
      throw new LocalMcpError("invalid_config", "health exitCode is invalid");
    }
    if (signal !== null && (typeof signal !== "string" || signal.length > 32)) {
      throw new LocalMcpError("invalid_config", "health signal is invalid");
    }
    return this.mutate((state) => {
      const record = state.packages.find(
        (item) => item.packageId === packageId && item.releaseId === releaseId,
      );
      if (!record) throw new LocalMcpError("invalid_health", "health package is not installed");
      record.runtimeStatus = runtimeStatus;
      record.health = health;
      record.lastErrorCode = errorCode;
      if (exitCode !== null || signal !== null) {
        record.lastExit = { code: exitCode, signal, at: this.timestamp() };
      }
      record.updatedAt = this.timestamp();
    });
  }

  recordTool(packageId, releaseId, toolName, {
    status,
    errorCode = null,
    durationMs = 0,
    responseBytes = 0,
  }) {
    assertPackageId(packageId, releaseId);
    if (!TOOL_STATUSES.has(status)) {
      throw new LocalMcpError("invalid_config", "health tool status is invalid");
    }
    assertCode(errorCode, "health tool errorCode");
    assertInteger(durationMs, "health durationMs");
    assertInteger(responseBytes, "health responseBytes");
    return this.mutate((state) => {
      const record = state.packages.find(
        (item) => item.packageId === packageId && item.releaseId === releaseId,
      );
      const tool = record?.tools.find((item) => item.name === toolName);
      if (!tool || !LOCAL_MCP_RISKS.includes(tool.risk)) {
        throw new LocalMcpError("invalid_health", "health tool is not registered");
      }
      if (status === "started") tool.calls += 1;
      if (status === "succeeded") tool.successes += 1;
      if (status === "failed") tool.failures += 1;
      if (status === "denied") tool.denied += 1;
      tool.lastStatus = status;
      tool.lastErrorCode = errorCode;
      tool.lastCalledAt = this.timestamp();
      tool.lastDurationMs = durationMs;
      tool.lastResponseBytes = responseBytes;
      record.updatedAt = this.timestamp();
    });
  }
}
