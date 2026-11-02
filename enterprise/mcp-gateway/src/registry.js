import crypto from "node:crypto";

import { ApprovalError, ApprovalVerifier } from "./approval.js";
import { validateUpstreamUrl } from "./network.js";
import {
  RISK_LEVELS,
  SERVER_STATUSES,
  TOOL_ACCESS,
} from "./store.js";

const SERVER_INPUT_FIELDS = new Set([
  "namespace",
  "name",
  "description",
  "endpoint",
  "secretRef",
  "assignments",
  "status",
  "toolPolicies",
]);
const TOOL_POLICY_FIELDS = new Set(["tool", "access", "risk", "visible"]);
const CLIENT_INPUT_FIELDS = new Set([
  "name",
  "subjectId",
  "orgIds",
  "deviceIds",
  "serverScopes",
  "ttlDays",
]);
const SERVER_STATUS_SET = new Set(SERVER_STATUSES);
const TOOL_ACCESS_SET = new Set(TOOL_ACCESS);
const RISK_LEVEL_SET = new Set(RISK_LEVELS);
const HIGH_RISK = new Set(["high", "critical"]);
const TOKEN_ENCODING = "base" + "64url";

export class ApiError extends Error {
  constructor(statusCode, code, message, retryable = false) {
    super(message);
    this.name = "ApiError";
    this.statusCode = statusCode;
    this.code = code;
    this.retryable = retryable;
  }
}

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactInput(value, fields) {
  return plainObject(value)
    && Object.keys(value).every((key) => fields.has(key))
    && [...fields].every((key) => key in value);
}

function hasOnlyFields(value, fields) {
  return plainObject(value) && Object.keys(value).every((key) => fields.has(key));
}

function text(value, name, maximum = 200, allowEmpty = false) {
  if (typeof value !== "string"
      || value.length > maximum
      || (!allowEmpty && value.length === 0)
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new ApiError(400, "invalid_request", `${name} is invalid`);
  }
  return value;
}

function textArray(value, name, maximum, validate) {
  if (!Array.isArray(value) || value.length > maximum || !value.every(validate)
      || new Set(value).size !== value.length) {
    throw new ApiError(400, "invalid_request", `${name} is invalid`);
  }
  return [...value];
}

function assignment(value) {
  return value === "*"
    || (typeof value === "string"
      && /^(?:user|org|device):[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(value));
}

function identity(value) {
  return typeof value === "string"
    && /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(value);
}

function toolPolicy(value) {
  if (!exactInput(value, TOOL_POLICY_FIELDS)) {
    throw new ApiError(400, "invalid_request", "toolPolicies contains an invalid item");
  }
  const tool = text(value.tool, "toolPolicies.tool", 128);
  if (tool.includes("__")) {
    throw new ApiError(400, "invalid_request", "tool names must not contain a namespace separator");
  }
  if (!TOOL_ACCESS_SET.has(value.access)
      || !RISK_LEVEL_SET.has(value.risk)
      || typeof value.visible !== "boolean"
      || (value.access === "deny" && value.visible)) {
    throw new ApiError(400, "invalid_request", "toolPolicies contains invalid policy values");
  }
  return {
    tool,
    access: value.access,
    risk: value.risk,
    visible: value.visible,
  };
}

function shortId(prefix) {
  return `${prefix}${crypto.randomUUID().replaceAll("-", "")}`;
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function safeTokenEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function serverProjection(server, health) {
  return {
    id: server.id,
    namespace: server.namespace,
    name: server.name,
    description: server.description,
    endpoint: server.endpoint,
    secretRef: server.secretRef,
    secretConfigured: server.secretRef !== "",
    assignments: [...server.assignments],
    status: server.status,
    toolPolicies: server.toolPolicies.map((policy) => ({ ...policy })),
    health: { ...health },
    createdAt: server.createdAt,
    updatedAt: server.updatedAt,
    createdBy: server.createdBy,
    updatedBy: server.updatedBy,
  };
}

function clientProjection(client) {
  return {
    id: client.id,
    name: client.name,
    subjectId: client.subjectId,
    orgIds: [...client.orgIds],
    deviceIds: [...client.deviceIds],
    serverScopes: [...client.serverScopes],
    status: client.status,
    expiresAt: client.expiresAt,
    createdAt: client.createdAt,
    createdBy: client.createdBy,
    revokedAt: client.revokedAt,
    revokedBy: client.revokedBy,
  };
}

function policyFor(server, toolName) {
  return server.toolPolicies.find((policy) => policy.tool === toolName) || {
    tool: toolName,
    access: "allow",
    risk: "medium",
    visible: true,
  };
}

function clientCanAccessServer(server, client) {
  if (server.status !== "active") return false;
  if (!client.serverScopes.includes("*") && !client.serverScopes.includes(server.id)) {
    return false;
  }
  return server.assignments.some((selector) => {
    if (selector === "*") return true;
    if (selector === `user:${client.subjectId}`) return true;
    if (selector.startsWith("org:") && client.orgIds.includes(selector.slice(4))) return true;
    if (selector.startsWith("device:") && client.deviceIds.includes(selector.slice(7))) return true;
    return false;
  });
}

function exposedTool(server, tool, policy) {
  return {
    name: `${server.namespace}__${tool.name}`,
    description: tool.description || "",
    inputSchema: tool.inputSchema || { type: "object" },
    annotations: {
      risk: policy.risk,
    },
  };
}

export class McpGatewayRegistry {
  constructor(config, { store, audit, upstream, resolver, logger = () => {} }) {
    this.config = config;
    this.store = store;
    this.audit = audit;
    this.upstream = upstream;
    this.logger = logger;
    this.health = new Map();
    this.catalogs = new Map();
    this.breakers = new Map();
    this.approval = new ApprovalVerifier({
      secret: config.approvalHmacSecret,
      maximumTtlSeconds: config.approvalMaxTtlSeconds,
    });
    this.resolver = resolver;
  }

  async initialize() {
    await this.store.load();
    await this.audit.load();
  }

  healthFor(serverId) {
    return this.health.get(serverId) || {
      state: "unknown",
      checkedAt: "",
      latencyMs: 0,
      errorCode: "",
    };
  }

  parseServerInput(body) {
    if (!exactInput(body, SERVER_INPUT_FIELDS)) {
      throw new ApiError(400, "invalid_request", "The server body has missing or unknown fields");
    }
    const namespace = text(body.namespace, "namespace", 32);
    if (!/^[a-z][a-z0-9-]{1,31}$/.test(namespace)) {
      throw new ApiError(400, "invalid_request", "namespace is invalid");
    }
    const endpoint = text(body.endpoint, "endpoint", 2048);
    try {
      validateUpstreamUrl(endpoint, this.config);
    } catch (error) {
      throw new ApiError(400, error.code || "invalid_endpoint", error.message);
    }
    const secretRef = text(body.secretRef, "secretRef", 128, true);
    if (secretRef && !/^[A-Z][A-Z0-9_]{2,127}$/.test(secretRef)) {
      throw new ApiError(400, "invalid_request", "secretRef must be an environment variable name");
    }
    const assignments = textArray(body.assignments, "assignments", 100, assignment);
    if (!assignments.length) {
      throw new ApiError(400, "invalid_request", "assignments must not be empty");
    }
    if (!SERVER_STATUS_SET.has(body.status)) {
      throw new ApiError(400, "invalid_request", "status is invalid");
    }
    if (!Array.isArray(body.toolPolicies)
        || body.toolPolicies.length > this.config.maxToolsPerServer) {
      throw new ApiError(400, "invalid_request", "toolPolicies is invalid");
    }
    const toolPolicies = body.toolPolicies.map(toolPolicy);
    if (new Set(toolPolicies.map((policy) => policy.tool)).size !== toolPolicies.length) {
      throw new ApiError(400, "invalid_request", "toolPolicies contains duplicate tools");
    }
    return {
      namespace,
      name: text(body.name, "name", 200),
      description: text(body.description, "description", 2000, true),
      endpoint,
      secretRef,
      assignments,
      status: body.status,
      toolPolicies,
    };
  }

  async createServer(input, actor, auditContext) {
    const normalized = this.parseServerInput(input);
    const at = new Date().toISOString();
    return this.store.mutate((data) => {
      if (Object.keys(data.servers).length >= this.config.maxServers) {
        throw new ApiError(409, "server_limit_reached", "The MCP server limit was reached");
      }
      if (Object.values(data.servers).some((server) => server.namespace === normalized.namespace)) {
        throw new ApiError(409, "namespace_conflict", "The namespace is already in use");
      }
      const server = {
        id: shortId("srv_"),
        ...normalized,
        createdAt: at,
        updatedAt: at,
        createdBy: actor,
        updatedBy: actor,
      };
      data.servers[server.id] = server;
      return serverProjection(server, this.healthFor(server.id));
    }).then(async (result) => {
      await this.audit.append({
        action: "server.create",
        actor,
        requestId: auditContext.requestId,
        operationId: auditContext.operationId,
        reason: auditContext.reason,
        result: "succeeded",
        targetType: "server",
        targetId: result.id,
        metadata: { namespace: result.namespace, status: result.status },
      });
      return result;
    });
  }

  async listServers() {
    return this.store.read((data) => Object.values(data.servers)
      .map((server) => serverProjection(server, this.healthFor(server.id)))
      .sort((left, right) => left.namespace.localeCompare(right.namespace)));
  }

  async getServer(serverId) {
    return this.store.read((data) => {
      const server = data.servers[serverId];
      if (!server) throw new ApiError(404, "not_found", "The MCP server was not found");
      return serverProjection(server, this.healthFor(server.id));
    });
  }

  async updateServer(serverId, body, actor, auditContext) {
    if (!hasOnlyFields(body, new Set([...SERVER_INPUT_FIELDS, "expectedUpdatedAt"]))) {
      throw new ApiError(400, "invalid_request", "The update body has unknown fields");
    }
    const expectedUpdatedAt = text(body.expectedUpdatedAt, "expectedUpdatedAt", 64);
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(expectedUpdatedAt)
        || !Number.isFinite(Date.parse(expectedUpdatedAt))) {
      throw new ApiError(400, "invalid_request", "expectedUpdatedAt is invalid");
    }
    const input = { ...body };
    delete input.expectedUpdatedAt;
    const normalized = this.parseServerInput(input);
    return this.store.mutate((data) => {
      const existing = data.servers[serverId];
      if (!existing) throw new ApiError(404, "not_found", "The MCP server was not found");
      if (existing.updatedAt !== expectedUpdatedAt) {
        throw new ApiError(409, "update_conflict", "The server changed after it was read");
      }
      if (Object.values(data.servers).some((server) => (
        server.id !== serverId && server.namespace === normalized.namespace
      ))) {
        throw new ApiError(409, "namespace_conflict", "The namespace is already in use");
      }
      const updated = {
        ...existing,
        ...normalized,
        updatedAt: new Date().toISOString(),
        updatedBy: actor,
      };
      data.servers[serverId] = updated;
      return serverProjection(updated, this.healthFor(serverId));
    }).then(async (result) => {
      this.catalogs.delete(serverId);
      this.breakers.delete(serverId);
      this.upstream.forget(serverId);
      await this.audit.append({
        action: "server.update",
        actor,
        requestId: auditContext.requestId,
        operationId: auditContext.operationId,
        reason: auditContext.reason,
        result: "succeeded",
        targetType: "server",
        targetId: result.id,
        metadata: { namespace: result.namespace, status: result.status },
      });
      return result;
    });
  }

  recordFailure(serverId) {
    const breaker = this.breakers.get(serverId) || { failures: 0, openUntil: 0 };
    breaker.failures += 1;
    if (breaker.failures >= this.config.breakerFailureThreshold) {
      breaker.openUntil = Date.now() + this.config.breakerCooldownMs;
    }
    this.breakers.set(serverId, breaker);
  }

  recordSuccess(serverId) {
    this.breakers.set(serverId, { failures: 0, openUntil: 0 });
  }

  assertCircuitClosed(serverId) {
    const breaker = this.breakers.get(serverId);
    if (breaker?.openUntil > Date.now()) {
      throw new ApiError(503, "upstream_circuit_open", "The upstream is temporarily unavailable", true);
    }
  }

  async loadCatalog(server, { force = false, timeoutMs } = {}) {
    const cached = this.catalogs.get(server.id);
    if (!force
        && cached
        && Date.now() - cached.at < this.config.catalogTtlMs) {
      return cached.tools;
    }
    this.assertCircuitClosed(server.id);
    try {
      const tools = await this.upstream.listTools(server, { force, timeoutMs });
      this.catalogs.set(server.id, { at: Date.now(), tools });
      this.health.set(server.id, {
        state: "healthy",
        checkedAt: new Date().toISOString(),
        latencyMs: 0,
        errorCode: "",
      });
      this.recordSuccess(server.id);
      return tools;
    } catch (error) {
      this.recordFailure(server.id);
      this.health.set(server.id, {
        state: "unhealthy",
        checkedAt: new Date().toISOString(),
        latencyMs: 0,
        errorCode: error.code || "upstream_error",
      });
      throw error;
    }
  }

  async checkServer(serverId, actor, auditContext) {
    const server = await this.store.read((data) => {
      const found = data.servers[serverId];
      if (!found) throw new ApiError(404, "not_found", "The MCP server was not found");
      return structuredClone(found);
    });
    const started = Date.now();
    try {
      await this.upstream.listTools(server, {
        force: true,
        timeoutMs: this.config.healthTimeoutMs,
      });
      const health = {
        state: "healthy",
        checkedAt: new Date().toISOString(),
        latencyMs: Date.now() - started,
        errorCode: "",
      };
      this.health.set(serverId, health);
      this.catalogs.delete(serverId);
      this.recordSuccess(serverId);
      await this.audit.append({
        action: "server.check",
        actor,
        requestId: auditContext.requestId,
        operationId: auditContext.operationId,
        reason: auditContext.reason,
        result: "succeeded",
        targetType: "server",
        targetId: serverId,
        metadata: { state: "healthy", latencyMs: health.latencyMs },
      });
      return { ...health };
    } catch (error) {
      const health = {
        state: "unhealthy",
        checkedAt: new Date().toISOString(),
        latencyMs: Date.now() - started,
        errorCode: error.code || "upstream_error",
      };
      this.health.set(serverId, health);
      this.recordFailure(serverId);
      await this.audit.append({
        action: "server.check",
        actor,
        requestId: auditContext.requestId,
        operationId: auditContext.operationId,
        reason: auditContext.reason,
        result: "failed",
        targetType: "server",
        targetId: serverId,
        metadata: { state: "unhealthy", errorCode: health.errorCode },
      });
      return { ...health };
    }
  }

  async issueClient(body, actor, auditContext) {
    if (!hasOnlyFields(body, CLIENT_INPUT_FIELDS)
        || !["name", "subjectId", "orgIds", "deviceIds", "serverScopes"]
          .every((field) => field in body)) {
      throw new ApiError(400, "invalid_request", "The client body has missing or unknown fields");
    }
    const maximumTtlDays = Math.max(1, Math.floor(this.config.clientTokenTtlMs / 86400000));
    const ttlDays = body.ttlDays == null ? maximumTtlDays : body.ttlDays;
    if (!Number.isInteger(ttlDays) || ttlDays < 1 || ttlDays > maximumTtlDays) {
      throw new ApiError(400, "invalid_request", "ttlDays is invalid");
    }
    const serverScopes = textArray(body.serverScopes, "serverScopes", 1000, (value) => (
      value === "*" || /^srv_[a-z0-9]{16,64}$/.test(value)
    ));
    if (!serverScopes.length) {
      throw new ApiError(400, "invalid_request", "serverScopes must not be empty");
    }
    const rawToken = `mcp_${crypto.randomBytes(32).toString(TOKEN_ENCODING)}`;
    const now = Date.now();
    const client = await this.store.mutate((data) => {
      if (Object.keys(data.clients).length >= this.config.maxClients) {
        throw new ApiError(409, "client_limit_reached", "The MCP client limit was reached");
      }
      for (const scope of serverScopes) {
        if (scope !== "*" && !data.servers[scope]) {
          throw new ApiError(400, "invalid_request", "serverScopes references an unknown server");
        }
      }
      const record = {
        id: shortId("cli_"),
        name: text(body.name, "name", 200),
        subjectId: text(body.subjectId, "subjectId", 128),
        orgIds: textArray(body.orgIds, "orgIds", 100, identity),
        deviceIds: textArray(body.deviceIds, "deviceIds", 100, identity),
        serverScopes,
        tokenDigest: sha256(rawToken),
        status: "active",
        expiresAt: new Date(now + ttlDays * 86400000).toISOString(),
        createdAt: new Date(now).toISOString(),
        createdBy: actor,
        revokedAt: "",
        revokedBy: "",
      };
      data.clients[record.id] = record;
      return record;
    });
    await this.audit.append({
      action: "client.issue",
      actor,
      requestId: auditContext.requestId,
      operationId: auditContext.operationId,
      reason: auditContext.reason,
      result: "succeeded",
      targetType: "client",
      targetId: client.id,
      metadata: { subjectId: client.subjectId, serverScopeCount: serverScopes.length },
    });
    return {
      client: clientProjection(client),
      token: rawToken,
    };
  }

  async listClients() {
    return this.store.read((data) => Object.values(data.clients)
      .map(clientProjection)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt)));
  }

  async revokeClient(clientId, actor, auditContext) {
    const client = await this.store.mutate((data) => {
      const found = data.clients[clientId];
      if (!found) throw new ApiError(404, "not_found", "The MCP client was not found");
      if (found.status === "revoked") return structuredClone(found);
      found.status = "revoked";
      found.revokedAt = new Date().toISOString();
      found.revokedBy = actor;
      return structuredClone(found);
    });
    await this.audit.append({
      action: "client.revoke",
      actor,
      requestId: auditContext.requestId,
      operationId: auditContext.operationId,
      reason: auditContext.reason,
      result: "succeeded",
      targetType: "client",
      targetId: clientId,
      metadata: { subjectId: client.subjectId },
    });
    return clientProjection(client);
  }

  async authenticateClient(rawToken) {
    if (typeof rawToken !== "string" || !/^mcp_[A-Za-z0-9_-]{32,256}$/.test(rawToken)) {
      return null;
    }
    const digest = sha256(rawToken);
    return this.store.read((data) => {
      const client = Object.values(data.clients).find((candidate) => (
        safeTokenEqual(candidate.tokenDigest, digest)
      ));
      if (!client
          || client.status !== "active"
          || Date.parse(client.expiresAt) <= Date.now()) {
        return null;
      }
      return structuredClone(client);
    });
  }

  async authorizedServers(client) {
    return this.store.read((data) => Object.values(data.servers)
      .filter((server) => clientCanAccessServer(server, client))
      .map((server) => structuredClone(server)));
  }

  async listExposedTools(client, auditContext) {
    const servers = await this.authorizedServers(client);
    const tools = [];
    const failedServers = [];
    for (const server of servers) {
      try {
        const catalog = await this.loadCatalog(server);
        for (const tool of catalog) {
          const policy = policyFor(server, tool.name);
          if (policy.access !== "allow" || !policy.visible) continue;
          tools.push(exposedTool(server, tool, policy));
        }
      } catch {
        failedServers.push(server.namespace);
      }
    }
    await this.audit.append({
      action: "mcp.list",
      actor: `client:${client.id}`,
      requestId: auditContext.requestId,
      operationId: auditContext.operationId,
      reason: "tools/list",
      result: "succeeded",
      targetType: "endpoint",
      targetId: "/mcp/enterprise",
      metadata: {
        clientId: client.id,
        toolCount: tools.length,
        failedServerCount: failedServers.length,
      },
    });
    return tools;
  }

  async resolveCall(client, exposedName) {
    if (typeof exposedName !== "string" || exposedName.length > 300) {
      throw new ApiError(404, "tool_not_found", "The tool was not found");
    }
    const separator = exposedName.indexOf("__");
    if (separator < 1) throw new ApiError(404, "tool_not_found", "The tool was not found");
    const namespace = exposedName.slice(0, separator);
    const toolName = exposedName.slice(separator + 2);
    if (!toolName) throw new ApiError(404, "tool_not_found", "The tool was not found");
    const server = await this.store.read((data) => {
      const found = Object.values(data.servers).find((candidate) => (
        candidate.namespace === namespace
      ));
      return found ? structuredClone(found) : null;
    });
    if (!server || !clientCanAccessServer(server, client)) {
      throw new ApiError(404, "tool_not_found", "The tool was not found");
    }
    const policy = policyFor(server, toolName);
    if (policy.access !== "allow" || !policy.visible) {
      throw new ApiError(404, "tool_not_found", "The tool was not found");
    }
    const catalog = await this.loadCatalog(server);
    if (!catalog.some((tool) => tool.name === toolName)) {
      throw new ApiError(404, "tool_not_found", "The tool was not found");
    }
    return { server, toolName, policy };
  }

  async callTool(client, exposedName, argumentsValue, approvalToken, auditContext) {
    const { server, toolName, policy } = await this.resolveCall(client, exposedName);
    if (HIGH_RISK.has(policy.risk)) {
      try {
        this.approval.verify(approvalToken, {
          clientId: client.id,
          serverId: server.id,
          tool: toolName,
        });
      } catch (error) {
        if (!(error instanceof ApprovalError)) throw error;
        throw new ApiError(403, error.code, error.message);
      }
    }
    this.assertCircuitClosed(server.id);
    await this.audit.append({
      action: "mcp.call",
      actor: `client:${client.id}`,
      requestId: auditContext.requestId,
      operationId: auditContext.operationId,
      reason: "tools/call",
      result: "allowed",
      targetType: "server",
      targetId: server.id,
      metadata: {
        clientId: client.id,
        tool: toolName,
        risk: policy.risk,
      },
    });
    const started = Date.now();
    try {
      const result = await this.upstream.callTool(server, toolName, argumentsValue);
      this.recordSuccess(server.id);
      this.health.set(server.id, {
        state: "healthy",
        checkedAt: new Date().toISOString(),
        latencyMs: Date.now() - started,
        errorCode: "",
      });
      await this.audit.append({
        action: "mcp.call",
        actor: `client:${client.id}`,
        requestId: auditContext.requestId,
        operationId: auditContext.operationId,
        reason: "tools/call",
        result: "succeeded",
        targetType: "server",
        targetId: server.id,
        metadata: {
          clientId: client.id,
          tool: toolName,
          risk: policy.risk,
          latencyMs: Date.now() - started,
        },
      });
      return result;
    } catch (error) {
      this.recordFailure(server.id);
      this.health.set(server.id, {
        state: "unhealthy",
        checkedAt: new Date().toISOString(),
        latencyMs: Date.now() - started,
        errorCode: error.code || "upstream_error",
      });
      await this.audit.append({
        action: "mcp.call",
        actor: `client:${client.id}`,
        requestId: auditContext.requestId,
        operationId: auditContext.operationId,
        reason: "tools/call",
        result: "failed",
        targetType: "server",
        targetId: server.id,
        metadata: {
          clientId: client.id,
          tool: toolName,
          risk: policy.risk,
          errorCode: error.code || "upstream_error",
          latencyMs: Date.now() - started,
        },
      });
      throw error;
    }
  }

  async auditLogs(limit = 100) {
    return this.audit.list(limit);
  }

  async auditDenied(client, exposedName, error, auditContext) {
    await this.audit.append({
      action: "mcp.denied",
      actor: `client:${client.id}`,
      requestId: auditContext.requestId,
      operationId: auditContext.operationId,
      reason: "tools/call",
      result: "denied",
      targetType: "endpoint",
      targetId: "/mcp/enterprise",
      metadata: {
        clientId: client.id,
        tool: typeof exposedName === "string" ? exposedName.slice(0, 200) : "",
        errorCode: error.code || "denied",
      },
    });
  }

  async runHealthChecks() {
    const servers = await this.store.read((data) => Object.values(data.servers)
      .filter((server) => server.status === "active")
      .map((server) => structuredClone(server)));
    for (const server of servers) {
      try {
        await this.upstream.listTools(server, {
          force: true,
          timeoutMs: this.config.healthTimeoutMs,
        });
        this.health.set(server.id, {
          state: "healthy",
          checkedAt: new Date().toISOString(),
          latencyMs: 0,
          errorCode: "",
        });
        this.recordSuccess(server.id);
      } catch (error) {
        this.health.set(server.id, {
          state: "unhealthy",
          checkedAt: new Date().toISOString(),
          latencyMs: 0,
          errorCode: error.code || "upstream_error",
        });
        this.recordFailure(server.id);
      }
    }
  }
}
