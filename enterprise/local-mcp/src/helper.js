import {
  LocalMcpError,
  asLocalMcpError,
  publicError,
} from "./errors.js";

export const LOCAL_MCP_HELPER_SCHEMA_VERSION = 1;

const SAFE_RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function fail(code, message) {
  throw new LocalMcpError(code, message);
}

function assertResourceId(resourceId) {
  if (typeof resourceId !== "string"
      || !SAFE_RESOURCE_ID.test(resourceId)
      || resourceId === "."
      || resourceId === "..") {
    fail("invalid_resource_id", "resourceId is invalid");
  }
}

function safeCode(error) {
  const code = asLocalMcpError(error).code;
  return typeof code === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(code)
    ? code
    : "internal_error";
}

function copyHealthTool(tool) {
  return {
    name: tool.name,
    risk: tool.risk,
    calls: tool.calls,
    successes: tool.successes,
    failures: tool.failures,
    denied: tool.denied,
    lastStatus: tool.lastStatus,
    lastErrorCode: tool.lastErrorCode,
    lastCalledAt: tool.lastCalledAt,
  };
}

export class LocalMcpHelper {
  constructor({
    clientSync,
    host,
    now = Date.now,
  } = {}) {
    if (!clientSync
        || typeof clientSync.inspect !== "function"
        || typeof clientSync.readActiveResource !== "function"
        || typeof clientSync.syncOnce !== "function") {
      fail("invalid_config", "clientSync must provide inspect(), readActiveResource() and syncOnce()");
    }
    if (!host
        || typeof host.install !== "function"
        || typeof host.verifyPackage !== "function"
        || typeof host.loadInstalled !== "function"
        || typeof host.listTools !== "function"
        || typeof host.callTool !== "function"
        || typeof host.health !== "function") {
      fail("invalid_config", "host must provide the local MCP runtime interface");
    }
    if (typeof now !== "function") fail("invalid_config", "now must be a function");
    this.clientSync = clientSync;
    this.host = host;
    this.now = now;
  }

  timestamp() {
    const value = this.now();
    const milliseconds = value instanceof Date ? value.getTime() : Number(value);
    if (!Number.isFinite(milliseconds)) fail("invalid_config", "now returned an invalid value");
    return new Date(milliseconds).toISOString();
  }

  // Pass this function as ClientSyncEngine.validateInstalled. Non-MCP
  // resources remain owned by client-sync, while MCP package contents are
  // verified and installed by the local runtime before activation.
  async validateClientResource({ manifest, content } = {}) {
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
      fail("invalid_client_resource", "client resource manifest is invalid");
    }
    if (manifest.kind !== "mcp") return;
    if (!Buffer.isBuffer(content) && !(content instanceof Uint8Array)) {
      fail("invalid_client_resource", "client resource content is invalid");
    }
    await this.host.install(Buffer.from(content));
  }

  async inspectedState() {
    let inspected;
    try {
      inspected = await this.clientSync.inspect();
    } catch {
      fail("helper_state_unavailable", "client sync state is unavailable");
    }
    if (!inspected
        || typeof inspected !== "object"
        || !Array.isArray(inspected.resources)
        || !Array.isArray(inspected.drift)) {
      fail("helper_state_invalid", "client sync state is invalid");
    }
    return inspected;
  }

  driftFor(inspected, resourceId) {
    return inspected.drift.find((entry) => entry?.resourceId === resourceId) ?? null;
  }

  async readActiveMcp(resourceId, inspected = null) {
    assertResourceId(resourceId);
    const state = inspected ?? await this.inspectedState();
    const record = state.resources.find((entry) => entry?.resourceId === resourceId);
    if (!record) fail("resource_not_active", "resource is not active in client sync");
    if (this.driftFor(state, resourceId)) {
      fail("resource_drift", "resource is not in the verified desired state");
    }
    if (record.kind !== "mcp") fail("resource_not_mcp", "resource is not a local MCP package");
    let active;
    try {
      active = await this.clientSync.readActiveResource(resourceId);
    } catch {
      fail("resource_invalid", "active resource content could not be verified");
    }
    if (!active?.manifest || !Buffer.isBuffer(active.content)) {
      fail("resource_invalid", "active resource content is invalid");
    }
    if (active.manifest.resourceId !== resourceId || active.manifest.kind !== "mcp") {
      fail("resource_invalid", "active resource does not match the requested MCP resource");
    }
    return active;
  }

  async verifiedPackage(active) {
    let verified;
    try {
      verified = await this.host.verifyPackage(active.content);
    } catch (error) {
      throw asLocalMcpError(error, "package_invalid");
    }
    return verified;
  }

  async reconcile() {
    const inspected = await this.inspectedState();
    const packages = [];
    const installed = [];
    const unchanged = [];
    const blocked = [];
    for (const record of inspected.resources.filter((entry) => entry?.kind === "mcp")) {
      try {
        const active = await this.readActiveMcp(record.resourceId, inspected);
        const verified = await this.verifiedPackage(active);
        const result = await this.host.install(active.content);
        if (!result
            || result.packageId !== verified.manifest.packageId
            || result.releaseId !== verified.manifest.releaseId) {
          fail("package_identity_mismatch", "installed package identity is inconsistent");
        }
        packages.push({
          resourceId: record.resourceId,
          releaseId: record.releaseId,
          packageId: result.packageId,
          packageReleaseId: result.releaseId,
          packageDigest: result.packageDigest,
        });
        if (result.status === "already_installed") unchanged.push(record.resourceId);
        else installed.push(record.resourceId);
      } catch (error) {
        blocked.push({
          resourceId: record.resourceId,
          releaseId: record.releaseId,
          error: publicError(error),
        });
      }
    }
    return {
      schemaVersion: LOCAL_MCP_HELPER_SCHEMA_VERSION,
      generatedAt: this.timestamp(),
      status: blocked.length ? "degraded" : "ready",
      installed,
      unchanged,
      blocked,
      packages,
    };
  }

  async synchronize({ signal } = {}) {
    let sync;
    try {
      sync = await this.clientSync.syncOnce({ signal });
    } catch (error) {
      sync = {
        status: "failed",
        error: publicError(error),
        drift: [],
      };
    }
    if (!sync || typeof sync !== "object" || typeof sync.status !== "string") {
      fail("helper_sync_invalid", "client sync returned an invalid result");
    }
    const localMcp = await this.reconcile();
    const syncOk = sync.status === "synced" || sync.status === "up_to_date";
    return {
      schemaVersion: LOCAL_MCP_HELPER_SCHEMA_VERSION,
      generatedAt: this.timestamp(),
      status: syncOk && localMcp.status === "ready" ? "ready" : "degraded",
      sync: {
        status: sync.status,
        revision: typeof sync.revision === "string" ? sync.revision : null,
        installed: Array.isArray(sync.installed) ? [...sync.installed] : [],
        unchanged: Array.isArray(sync.unchanged) ? [...sync.unchanged] : [],
        skipped: Array.isArray(sync.skipped) ? [...sync.skipped] : [],
        error: sync.error && typeof sync.error.code === "string"
          ? { code: sync.error.code }
          : null,
      },
      localMcp,
    };
  }

  async snapshot() {
    const inspected = await this.inspectedState();
    let health;
    try {
      health = await this.host.health();
    } catch {
      health = { packages: [] };
    }
    const healthByIdentity = new Map(
      (Array.isArray(health.packages) ? health.packages : [])
        .map((entry) => [`${entry.packageId}\0${entry.releaseId}`, entry]),
    );
    const packages = [];
    const blocked = [];
    for (const record of inspected.resources.filter((entry) => entry?.kind === "mcp")) {
      try {
        const active = await this.readActiveMcp(record.resourceId, inspected);
        const verified = await this.verifiedPackage(active);
        await this.host.loadInstalled(
          verified.manifest.packageId,
          verified.manifest.releaseId,
        );
        const healthRecord = healthByIdentity.get(
          `${verified.manifest.packageId}\0${verified.manifest.releaseId}`,
        );
        packages.push({
          resourceId: record.resourceId,
          releaseId: record.releaseId,
          resourceVersion: record.resourceVersion,
          deliveryMode: record.deliveryMode,
          packageId: verified.manifest.packageId,
          packageReleaseId: verified.manifest.releaseId,
          packageVersion: verified.manifest.packageVersion,
          packageDigest: verified.manifest.packageDigest,
          publisher: verified.manifest.publisher,
          signingKeyId: verified.manifest.signingKeyId,
          runtimeStatus: healthRecord?.runtimeStatus ?? "stopped",
          health: healthRecord?.health ?? "unknown",
          lastErrorCode: healthRecord?.lastErrorCode ?? null,
          tools: Array.isArray(healthRecord?.tools)
            ? healthRecord.tools
              .filter((tool) => SAFE_SEGMENT.test(tool.name))
              .map(copyHealthTool)
            : [],
        });
      } catch (error) {
        blocked.push({
          resourceId: record.resourceId,
          releaseId: record.releaseId,
          error: publicError(error),
        });
      }
    }
    const degraded = blocked.length > 0
      || inspected.status === "drift"
      || inspected.status === "last_sync_failed";
    return {
      schemaVersion: LOCAL_MCP_HELPER_SCHEMA_VERSION,
      generatedAt: this.timestamp(),
      status: degraded ? "degraded" : packages.length ? "ready" : "empty",
      syncStatus: inspected.status,
      revision: typeof inspected.revision === "string" ? inspected.revision : null,
      packages,
      blocked,
    };
  }

  async listTools(resourceId) {
    const active = await this.readActiveMcp(resourceId);
    const verified = await this.verifiedPackage(active);
    try {
      await this.host.loadInstalled(
        verified.manifest.packageId,
        verified.manifest.releaseId,
      );
    } catch {
      fail("package_not_installed", "local MCP package is not installed");
    }
    return {
      resourceId,
      releaseId: active.manifest.releaseId,
      packageId: verified.manifest.packageId,
      packageReleaseId: verified.manifest.releaseId,
      tools: await this.host.listTools(
        verified.manifest.packageId,
        verified.manifest.releaseId,
      ),
    };
  }

  async callTool(resourceId, toolName, args, options = {}) {
    if (typeof toolName !== "string" || !SAFE_SEGMENT.test(toolName)) {
      fail("invalid_tool_name", "toolName is invalid");
    }
    const active = await this.readActiveMcp(resourceId);
    const verified = await this.verifiedPackage(active);
    try {
      await this.host.loadInstalled(
        verified.manifest.packageId,
        verified.manifest.releaseId,
      );
    } catch {
      fail("package_not_installed", "local MCP package is not installed");
    }
    return this.host.callTool(
      verified.manifest.packageId,
      verified.manifest.releaseId,
      toolName,
      args,
      options,
    );
  }
}
