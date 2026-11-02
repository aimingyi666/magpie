import crypto from "node:crypto";
import path from "node:path";

import {
  applyCodexAgentConfig,
  DEFAULT_CODEX_MCP_SERVER_NAME,
  DEFAULT_CODEX_STARTUP_TIMEOUT_SEC,
  DEFAULT_CODEX_TOKEN_ENV,
  inspectCodexAgentConfig,
  removeCodexAgentConfig,
} from "./agent-config.js";
import {
  HELPER_URL_ENV,
  LoopbackHelperClient,
  normalizeLoopbackHelperUrl,
  RESOURCE_ID_ENV,
} from "./bridge.js";
import {
  LocalMcpError,
  asLocalMcpError,
} from "./errors.js";
import { createLocalMcpServer } from "./server.js";

export const LOCAL_MCP_CLIENT_SETUP_SCHEMA_VERSION = 1;
export const DEFAULT_CLIENT_SETUP_TOKEN_BYTES = 32;

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_SERVER_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const MAX_TOKEN_BYTES = 4096;

const DEFAULT_CONFIG_ADAPTER = Object.freeze({
  apply: applyCodexAgentConfig,
  inspect: inspectCodexAgentConfig,
  remove: removeCodexAgentConfig,
});

function fail(code, message) {
  throw new LocalMcpError(code, message);
}

function assertAbsolutePath(value, label) {
  if (typeof value !== "string"
      || !value
      || Buffer.byteLength(value, "utf8") > 4096
      || /[\0\r\n]/.test(value)
      || !path.isAbsolute(value)) {
    fail("invalid_config", `${label} must be an absolute path`);
  }
  return path.resolve(value);
}

function assertHelper(helper) {
  const methods = ["synchronize", "reconcile", "snapshot", "listTools"];
  if (!helper || methods.some((method) => typeof helper[method] !== "function")) {
    fail(
      "invalid_config",
      "helper must provide synchronize(), reconcile(), snapshot() and listTools()",
    );
  }
}

function assertInjector(injectLaunchEnvironment) {
  if (typeof injectLaunchEnvironment !== "function") {
    fail(
      "token_injection_required",
      "a controlled launch-environment injector is required for setup",
    );
  }
}

function normalizeToken(token) {
  if (token === undefined) {
    return crypto
      .randomBytes(DEFAULT_CLIENT_SETUP_TOKEN_BYTES)
      .toString("base64url");
  }
  if (typeof token !== "string"
      || Buffer.byteLength(token, "utf8") < 16
      || Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES
      || /[\0\r\n]/.test(token)) {
    fail("invalid_config", "token must be a 16-4096 byte opaque value");
  }
  return token;
}

function normalizeConfigAdapter(value) {
  if (value === undefined) return DEFAULT_CONFIG_ADAPTER;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("invalid_config", "agentConfig must be an object");
  }
  const adapter = {
    apply: value.apply ?? DEFAULT_CONFIG_ADAPTER.apply,
    inspect: value.inspect ?? DEFAULT_CONFIG_ADAPTER.inspect,
    remove: value.remove ?? DEFAULT_CONFIG_ADAPTER.remove,
  };
  if (Object.values(adapter).some((method) => typeof method !== "function")) {
    fail("invalid_config", "agentConfig must provide apply(), inspect() and remove()");
  }
  return adapter;
}

function normalizeOptions(options = {}) {
  const resourceId = options.resourceId ?? "";
  if (resourceId
      && (typeof resourceId !== "string"
        || !RESOURCE_ID.test(resourceId)
        || resourceId === "."
        || resourceId === "..")) {
    fail("invalid_config", "resourceId is invalid");
  }
  const tokenEnvName = options.tokenEnvName ?? DEFAULT_CODEX_TOKEN_ENV;
  if (typeof tokenEnvName !== "string" || !ENV_NAME.test(tokenEnvName)) {
    fail("invalid_config", "tokenEnvName is invalid");
  }
  if (tokenEnvName === HELPER_URL_ENV || tokenEnvName === RESOURCE_ID_ENV) {
    fail("invalid_config", "tokenEnvName conflicts with a bridge environment variable");
  }
  const serverName = options.serverName ?? DEFAULT_CODEX_MCP_SERVER_NAME;
  if (typeof serverName !== "string" || !SAFE_SERVER_NAME.test(serverName)) {
    fail("invalid_config", "serverName is invalid");
  }
  const rootDir = options.rootDir ?? options.helper?.host?.rootDir;
  if (!rootDir) fail("invalid_config", "rootDir is required");
  const port = options.port ?? 0;
  if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
    fail("invalid_config", "port is invalid");
  }
  return {
    helper: options.helper,
    configPath: assertAbsolutePath(options.configPath, "configPath"),
    nodePath: assertAbsolutePath(options.nodePath, "nodePath"),
    bridgePath: assertAbsolutePath(options.bridgePath, "bridgePath"),
    rootDir: assertAbsolutePath(rootDir, "rootDir"),
    resourceId,
    tokenEnvName,
    serverName,
    startupTimeoutSec: options.startupTimeoutSec
      ?? DEFAULT_CODEX_STARTUP_TIMEOUT_SEC,
    bind: options.bind ?? "127.0.0.1",
    port,
    token: normalizeToken(options.token),
    agentConfig: normalizeConfigAdapter(options.agentConfig),
    injectLaunchEnvironment: options.injectLaunchEnvironment,
    now: options.now ?? Date.now,
    logger: options.logger,
  };
}

function choosePackage(snapshot, requestedResourceId) {
  if (!snapshot
      || typeof snapshot !== "object"
      || !Array.isArray(snapshot.packages)
      || !Array.isArray(snapshot.blocked)) {
    fail("client_setup_state_invalid", "local MCP snapshot is invalid");
  }
  if (requestedResourceId) {
    const blocked = snapshot.blocked.find(
      (entry) => entry?.resourceId === requestedResourceId,
    );
    if (blocked) fail("client_setup_resource_blocked", "requested resource is blocked");
    const selected = snapshot.packages.find(
      (entry) => entry?.resourceId === requestedResourceId,
    );
    if (!selected) fail("client_setup_resource_not_found", "requested resource is not active");
    return selected;
  }
  if (snapshot.packages.length === 0) {
    fail("client_setup_no_resources", "no active local MCP resource is available");
  }
  if (snapshot.packages.length > 1) {
    fail(
      "client_setup_resource_required",
      "resourceId is required when more than one MCP resource is active",
    );
  }
  return snapshot.packages[0];
}

function helperUrlFor(address) {
  if (!address
      || !Number.isSafeInteger(address.port)
      || address.port < 1
      || address.port > 65_535) {
    fail("client_setup_server_failed", "helper server did not return a usable address");
  }
  const host = address.address === "::1" ? "[::1]" : address.address;
  return normalizeLoopbackHelperUrl(`http://${host}:${address.port}`);
}

function configMatches(inspected, expected) {
  return inspected?.status === "managed"
    && inspected.serverName === expected.serverName
    && inspected.managed?.nodePath === expected.nodePath
    && inspected.managed?.bridgePath === expected.bridgePath
    && inspected.managed?.helperUrl === expected.helperUrl
    && inspected.managed?.resourceId === expected.resourceId
    && inspected.managed?.tokenEnvName === expected.tokenEnvName
    && inspected.managed?.startupTimeoutSec === expected.startupTimeoutSec;
}

export async function setupLocalMcpClient(options = {}) {
  assertInjector(options.injectLaunchEnvironment);
  const normalized = normalizeOptions(options);
  assertHelper(normalized.helper);

  let server = null;
  let configApplied = false;
  const cleanup = async () => {
    if (configApplied) {
      try {
        await normalized.agentConfig.remove({
          configPath: normalized.configPath,
          serverName: normalized.serverName,
        });
      } catch {
        // Preserve the original setup error; the caller gets a failed setup.
      }
    }
    if (server) {
      try {
        await server.close();
      } catch {
        // The original error remains the only public failure.
      }
    }
  };

  try {
    const synchronized = await normalized.helper.synchronize();
    if (synchronized?.status !== "ready") {
      fail("client_setup_sync_failed", "client resources did not synchronize");
    }
    const reconciled = await normalized.helper.reconcile();
    if (reconciled?.status !== "ready") {
      fail("client_setup_reconcile_failed", "local MCP packages did not reconcile");
    }
    const snapshot = await normalized.helper.snapshot();
    const selected = choosePackage(snapshot, normalized.resourceId);
    const resourceId = selected.resourceId;
    const tools = await normalized.helper.listTools(resourceId);
    if (!tools || !Array.isArray(tools.tools)) {
      fail("client_setup_tools_invalid", "local MCP tool listing is invalid");
    }
    if (tools.tools.length === 0) {
      fail("client_setup_no_tools", "local MCP resource has no available tools");
    }

    try {
      server = await createLocalMcpServer({
        helper: normalized.helper,
        token: normalized.token,
        bind: normalized.bind,
        port: normalized.port,
        rootDir: normalized.rootDir,
        now: normalized.now,
        logger: normalized.logger,
      });
      const address = await server.listen();
      const helperUrl = helperUrlFor(address);
      const probe = new LoopbackHelperClient({
        helperUrl,
        token: normalized.token,
        resourceId,
      });
      await probe.listTools();

      await normalized.agentConfig.apply({
        configPath: normalized.configPath,
        nodePath: normalized.nodePath,
        bridgePath: normalized.bridgePath,
        helperUrl,
        resourceId,
        tokenEnvName: normalized.tokenEnvName,
        serverName: normalized.serverName,
        startupTimeoutSec: normalized.startupTimeoutSec,
      });
      configApplied = true;

      const inspected = await normalized.agentConfig.inspect({
        configPath: normalized.configPath,
        serverName: normalized.serverName,
      });
      const expected = {
        serverName: normalized.serverName,
        nodePath: normalized.nodePath,
        bridgePath: normalized.bridgePath,
        helperUrl,
        resourceId,
        tokenEnvName: normalized.tokenEnvName,
        startupTimeoutSec: normalized.startupTimeoutSec,
      };
      if (!configMatches(inspected, expected)) {
        fail("client_setup_readback_failed", "Codex MCP configuration did not read back");
      }

      let injected;
      try {
        injected = await normalized.injectLaunchEnvironment({
          configPath: normalized.configPath,
          serverName: normalized.serverName,
          resourceId,
          helperUrl,
          tokenEnvName: normalized.tokenEnvName,
          environment: Object.freeze({
            [normalized.tokenEnvName]: normalized.token,
            [HELPER_URL_ENV]: helperUrl,
            [RESOURCE_ID_ENV]: resourceId,
          }),
        });
      } catch {
        fail(
          "client_setup_injection_failed",
          "the controlled launcher did not accept the helper environment",
        );
      }
      if (injected?.status !== "ready") {
        fail(
          "client_setup_injection_failed",
          "the controlled launcher did not confirm helper injection",
        );
      }

      let closePromise = null;
      const close = () => {
        if (!closePromise) {
          closePromise = server.close().catch((error) => {
            closePromise = null;
            throw error;
          });
        }
        return closePromise;
      };
      return Object.freeze({
        schemaVersion: LOCAL_MCP_CLIENT_SETUP_SCHEMA_VERSION,
        status: "ready",
        serverName: normalized.serverName,
        resourceId,
        helperUrl,
        tokenEnvName: normalized.tokenEnvName,
        toolCount: tools.tools.length,
        sync: {
          status: synchronized.sync?.status ?? synchronized.status,
          revision: synchronized.sync?.revision ?? null,
        },
        launch: { status: "ready" },
        close,
        async uninstall() {
          try {
            return await normalized.agentConfig.remove({
              configPath: normalized.configPath,
              serverName: normalized.serverName,
            });
          } finally {
            await close();
          }
        },
      });
    } catch (error) {
      await cleanup();
      if (error instanceof LocalMcpError) throw error;
      if (server) {
        throw new LocalMcpError(
          "client_setup_server_failed",
          "local MCP helper server failed",
        );
      }
      throw asLocalMcpError(error, "client_setup_failed");
    }
  } catch (error) {
    if (error instanceof LocalMcpError) throw error;
    throw asLocalMcpError(error, "client_setup_failed");
  }
}
