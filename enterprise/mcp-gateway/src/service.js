import crypto from "node:crypto";
import http from "node:http";
import path from "node:path";

import { McpAuditLog } from "./audit.js";
import { ApiError, McpGatewayRegistry } from "./registry.js";
import { McpRegistryStore } from "./store.js";
import { McpPermissionStore, McpPermissionChecker } from "./permissions.js";
import { McpCallAuditStore } from "./call-audit.js";
import { UpstreamError, UpstreamMcpClient } from "./upstream.js";

const SERVER_VERSION = "0.1.0";
const ADMIN_PREFIX = "/api/v1/admin/mcp";
const DATA_PREFIX = "/api/v1/mcp";
const IDEMPOTENCY_KEY = /^[\u0021-\u007e]{1,128}$/;

class FixedWindowRateLimiter {
  constructor(limit, windowMs = 60000) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.buckets = new Map();
  }

  consume(key) {
    const now = Date.now();
    let bucket = this.buckets.get(key);
    if (!bucket || now - bucket.startedAt >= this.windowMs) {
      bucket = { startedAt: now, count: 0 };
      this.buckets.set(key, bucket);
    }
    bucket.count += 1;
    if (this.buckets.size > 10000) {
      for (const [bucketKey, value] of this.buckets) {
        if (now - value.startedAt >= this.windowMs) this.buckets.delete(bucketKey);
      }
    }
    return bucket.count <= this.limit;
  }
}

function requestId() {
  return crypto.randomUUID();
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(Object.keys(value).sort()
      .map((key) => [key, canonicalValue(value[key])]));
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function sendJson(res, statusCode, body, extraHeaders = {}) {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(payload.length),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    ...extraHeaders,
  });
  res.end(payload);
}

function sendEmpty(res, statusCode, extraHeaders = {}) {
  res.writeHead(statusCode, {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...extraHeaders,
  });
  res.end();
}

function apiErrorBody(error) {
  return {
    error: {
      code: error.code,
      message: error.message,
      retryable: Boolean(error.retryable),
    },
  };
}

async function readBody(req, maximum) {
  const contentType = String(req.headers["content-type"] || "").toLowerCase();
  if (!contentType.startsWith("application/json")) {
    throw new ApiError(415, "unsupported_media_type", "Content-Type must be application/json");
  }
  const declared = Number(req.headers["content-length"] || 0);
  if (Number.isFinite(declared) && declared > maximum) {
    req.resume();
    throw new ApiError(413, "body_too_large", "The request body is too large");
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maximum) {
      req.resume();
      throw new ApiError(413, "body_too_large", "The request body is too large");
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new ApiError(400, "invalid_json", "The request body is not valid JSON");
  }
}

function adminActor(req) {
  const actor = String(req.headers["x-magpie-actor"] || "");
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(actor)) {
    throw new ApiError(400, "invalid_actor", "X-Magpie-Actor is required and invalid");
  }
  return actor;
}

function adminOperation(body) {
  if (!body
      || typeof body.operationId !== "string"
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(body.operationId)
      || typeof body.reason !== "string"
      || !body.reason.trim()
      || body.reason.length > 500
      || /[\u0000-\u001f\u007f]/.test(body.reason)) {
    throw new ApiError(400, "invalid_request", "operationId and reason are required");
  }
  return { operationId: body.operationId, reason: body.reason.trim() };
}

function originAllowed(req, config) {
  const origin = req.headers.origin;
  if (origin == null) return true;
  return config.allowedOrigins.length > 0
    && config.allowedOrigins.includes(String(origin).toLowerCase());
}

function bearer(req) {
  const match = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ""));
  return match ? match[1] : "";
}

function parseAdminRoute(pathname) {
  if (pathname === `${ADMIN_PREFIX}/servers`) return { name: "servers" };
  if (pathname === `${ADMIN_PREFIX}/clients`) return { name: "clients" };
  if (pathname === `${ADMIN_PREFIX}/audit-logs`) return { name: "audit-logs" };
  if (pathname === `${ADMIN_PREFIX}/permissions`) return { name: "permissions" };
  if (pathname === `${ADMIN_PREFIX}/call-audit`) return { name: "call-audit" };
  let match = /^\/api\/v1\/admin\/mcp\/permissions\/(mcp_perm_[a-z0-9]{16,64})$/.exec(pathname);
  if (match) return { name: "permission", permissionId: match[1] };
  match = /^\/api\/v1\/admin\/mcp\/call-audit\/(maud_call_[a-z0-9]{16,64})$/.exec(pathname);
  if (match) return { name: "call-audit-detail", callAuditId: match[1] };
  match = /^\/api\/v1\/admin\/mcp\/servers\/(srv_[a-z0-9]{16,64})$/.exec(pathname);
  if (match) return { name: "server", serverId: match[1] };
  match = /^\/api\/v1\/admin\/mcp\/servers\/(srv_[a-z0-9]{16,64})\/check$/.exec(pathname);
  if (match) return { name: "server-check", serverId: match[1] };
  match = /^\/api\/v1\/admin\/mcp\/clients\/(cli_[a-z0-9]{16,64})\/revoke$/.exec(pathname);
  if (match) return { name: "client-revoke", clientId: match[1] };
  return null;
}

function parseDataRoute(pathname) {
  if (pathname === `${DATA_PREFIX}/available`) return { name: "available" };
  if (pathname === `${DATA_PREFIX}/call`) return { name: "call" };
  return null;
}

function methodNotAllowed(allowed) {
  throw new ApiError(405, "method_not_allowed", `Use ${allowed}`);
}

function rpcErrorCode(error) {
  if (["tool_not_found", "invalid_params"].includes(error.code)) return -32602;
  if (error.code === "method_not_found") return -32601;
  if (error.code === "rate_limited") return -32000;
  if (["approval_required", "invalid_approval", "approval_replayed", "approval_unavailable"].includes(error.code)) {
    return -32002;
  }
  return -32001;
}

function rpcError(id, error) {
  return {
    jsonrpc: "2.0",
    id: id ?? null,
    error: {
      code: rpcErrorCode(error),
      message: error.message || "The request failed",
    },
  };
}

function rpcResult(id, result) {
  return {
    jsonrpc: "2.0",
    id,
    result,
  };
}

function projectToolList(tools) {
  return { tools };
}

function sanitizeStoredResponse(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return body;
  const copy = structuredClone(body);
  if (typeof copy.token === "string") {
    delete copy.token;
    copy.tokenIssued = true;
    copy.tokenReplayUnavailable = true;
  }
  return copy;
}

function validateRpcRequest(body) {
  if (Array.isArray(body)) {
    throw new ApiError(400, "batch_not_supported", "JSON-RPC batching is not supported");
  }
  const notification = body
    && typeof body === "object"
    && typeof body.method === "string"
    && body.method.startsWith("notifications/");
  if (!body
      || typeof body !== "object"
      || body.jsonrpc !== "2.0"
      || typeof body.method !== "string"
      || body.method.length === 0
      || body.method.length > 128
      || (!notification && !Object.hasOwn(body, "id"))
      || (Object.hasOwn(body, "id")
        && !["string", "number"].includes(typeof body.id)
        && body.id !== null)) {
    throw new ApiError(400, "invalid_json_rpc", "The JSON-RPC request is invalid");
  }
  return body;
}

export async function createMcpGatewayServer(config, {
  store = new McpRegistryStore(config.storePath),
  audit = new McpAuditLog(config.auditPath),
  upstream = new UpstreamMcpClient(config),
  permissionStore = new McpPermissionStore(store),
  callAuditStore = new McpCallAuditStore(config.auditPath || path.join(path.dirname(config.storePath), "mcp-call-audit.jsonl")),
  resolver,
  logger = () => {},
} = {}) {
  const permissions = new McpPermissionChecker(permissionStore);
  const registry = new McpGatewayRegistry(config, {
    store,
    audit,
    upstream,
    resolver,
    logger,
  });
  await registry.initialize();

  const adminLimiter = new FixedWindowRateLimiter(config.rateLimitPerMinute);
  const dataLimiter = new FixedWindowRateLimiter(config.rateLimitPerMinute);
  const authLimiter = new FixedWindowRateLimiter(config.authRateLimitPerMinute);
  let adminQueue = Promise.resolve();

  async function withIdempotency(req, { method, path, actor, body }, operation) {
    const key = String(req.headers["idempotency-key"] || "");
    if (!IDEMPOTENCY_KEY.test(key)) {
      throw new ApiError(400, "invalid_idempotency_key", "Idempotency-Key is required");
    }
    const hash = sha256(`${actor}\n${key}`);
    const fingerprint = sha256(canonicalJson({
      method,
      path,
      actor,
      body,
    }));
    const run = adminQueue.then(async () => {
      const previous = await store.read((data) => data.idempotency[hash]
        ? structuredClone(data.idempotency[hash])
        : null);
      if (previous) {
        if (previous.fingerprint !== fingerprint) {
          throw new ApiError(
            409,
            "idempotency_conflict",
            "The idempotency key was used for another request",
          );
        }
        return {
          statusCode: previous.statusCode,
          body: previous.responseBody,
          replayed: true,
        };
      }
      const result = await operation();
      await store.mutate((data) => {
        data.idempotency[hash] = {
          fingerprint,
          method,
          path,
          statusCode: result.statusCode,
          responseBody: sanitizeStoredResponse(result.body),
          operationId: result.operationId,
          createdAt: new Date().toISOString(),
        };
      });
      return { ...result, replayed: false };
    });
    adminQueue = run.catch(() => {});
    return run;
  }

  async function handleAdmin(req, res, route, pathname, context) {
    if (!safeEqual(bearer(req), config.serviceToken)) {
      throw new ApiError(401, "unauthorized", "A valid service token is required");
    }
    const actor = adminActor(req);
    const limitKey = `${context.remoteAddress}:admin`;
    if (!adminLimiter.consume(limitKey)) {
      throw new ApiError(429, "rate_limited", "Too many requests", true);
    }

    if (route.name === "servers") {
      if (req.method === "GET") {
        return sendJson(res, 200, { servers: await registry.listServers() });
      }
      if (req.method !== "POST") methodNotAllowed("GET or POST");
      const body = await readBody(req, config.maxBodyBytes);
      const operation = adminOperation(body);
      const result = await withIdempotency(req, {
        method: req.method,
        path: pathname,
        actor,
        body,
      }, async () => {
        const { operationId: _, reason: __, ...input } = body;
        const server = await registry.createServer(input, actor, {
          requestId: context.requestId,
          ...operation,
        });
        return {
          statusCode: 201,
          body: { server },
          operationId: operation.operationId,
        };
      });
      return sendJson(res, result.statusCode, result.body, {
        ...(result.replayed ? { "idempotent-replay": "true" } : {}),
      });
    }

    if (route.name === "server") {
      if (req.method === "GET") {
        return sendJson(res, 200, { server: await registry.getServer(route.serverId) });
      }
      if (req.method !== "PUT") methodNotAllowed("GET or PUT");
      const body = await readBody(req, config.maxBodyBytes);
      const operation = adminOperation(body);
      const result = await withIdempotency(req, {
        method: req.method,
        path: pathname,
        actor,
        body,
      }, async () => {
        const { operationId: _, reason: __, ...updateInput } = body;
        const server = await registry.updateServer(route.serverId, updateInput, actor, {
          requestId: context.requestId,
          ...operation,
        });
        return {
          statusCode: 200,
          body: { server },
          operationId: operation.operationId,
        };
      });
      return sendJson(res, result.statusCode, result.body, {
        ...(result.replayed ? { "idempotent-replay": "true" } : {}),
      });
    }

    if (route.name === "server-check") {
      if (req.method !== "POST") methodNotAllowed("POST");
      const body = await readBody(req, config.maxBodyBytes);
      const operation = adminOperation(body);
      const result = await withIdempotency(req, {
        method: req.method,
        path: pathname,
        actor,
        body,
      }, async () => ({
        statusCode: 200,
        body: { health: await registry.checkServer(route.serverId, actor, {
          requestId: context.requestId,
          ...operation,
        }) },
        operationId: operation.operationId,
      }));
      return sendJson(res, result.statusCode, result.body, {
        ...(result.replayed ? { "idempotent-replay": "true" } : {}),
      });
    }

    if (route.name === "clients") {
      if (req.method === "GET") {
        return sendJson(res, 200, { clients: await registry.listClients() });
      }
      if (req.method !== "POST") methodNotAllowed("GET or POST");
      const body = await readBody(req, config.maxBodyBytes);
      const operation = adminOperation(body);
      const result = await withIdempotency(req, {
        method: req.method,
        path: pathname,
        actor,
        body,
      }, async () => {
        const { operationId: _, reason: __, ...input } = body;
        const issued = await registry.issueClient(input, actor, {
          requestId: context.requestId,
          ...operation,
        });
        return {
          statusCode: 201,
          body: issued,
          operationId: operation.operationId,
        };
      });
      return sendJson(res, result.statusCode, result.body, {
        "cache-control": "no-store",
        ...(result.replayed ? { "idempotent-replay": "true" } : {}),
      });
    }

    if (route.name === "client-revoke") {
      if (req.method !== "POST") methodNotAllowed("POST");
      const body = await readBody(req, config.maxBodyBytes);
      const operation = adminOperation(body);
      const result = await withIdempotency(req, {
        method: req.method,
        path: pathname,
        actor,
        body,
      }, async () => ({
        statusCode: 200,
        body: { client: await registry.revokeClient(route.clientId, actor, {
          requestId: context.requestId,
          ...operation,
        }) },
        operationId: operation.operationId,
      }));
      return sendJson(res, result.statusCode, result.body, {
        ...(result.replayed ? { "idempotent-replay": "true" } : {}),
      });
    }

    if (route.name === "audit-logs") {
      if (req.method !== "GET") methodNotAllowed("GET");
      const url = new URL(req.url, "http://localhost");
      const limit = Number(url.searchParams.get("limit") || 100);
      if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
        throw new ApiError(400, "invalid_request", "limit must be from 1 to 1000");
      }
      return sendJson(res, 200, { auditLogs: await registry.auditLogs(limit) });
    }

    throw new ApiError(404, "not_found", "The admin route was not found");
  }

  async function handlePermissions(req, res, route, pathname, context) {
    if (!safeEqual(bearer(req), config.serviceToken)) {
      throw new ApiError(401, "unauthorized", "A valid service token is required");
    }
    const actor = adminActor(req);
    const limitKey = `${context.remoteAddress}:admin`;
    if (!adminLimiter.consume(limitKey)) {
      throw new ApiError(429, "rate_limited", "Too many requests", true);
    }

    if (route.name === "permissions") {
      if (req.method === "GET") {
        const all = await permissionStore.list();
        return sendJson(res, 200, { permissions: all });
      }
      if (req.method !== "POST") methodNotAllowed("GET or POST");
      const body = await readBody(req, config.maxBodyBytes);
      const operation = adminOperation(body);
      const permissionId = String(body.permissionId || `mcp_perm_${crypto.randomUUID().replaceAll("-", "")}`);
      const { operationId: _, reason: __, permissionId: ___, ...input } = body;
      const permission = await permissionStore.create(permissionId, input);
      return sendJson(res, 201, { permission }, {
        "cache-control": "no-store",
      });
    }

    if (route.name === "permission") {
      if (req.method === "DELETE") {
        const deleted = await permissionStore.delete(route.permissionId);
        return sendJson(res, 200, { permission: deleted });
      }
      methodNotAllowed("DELETE");
    }

    if (route.name === "call-audit") {
      if (req.method !== "GET") methodNotAllowed("GET");
      const url = new URL(req.url, "http://localhost");
      const limit = Number(url.searchParams.get("limit") || 100);
      if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
        throw new ApiError(400, "invalid_request", "limit must be from 1 to 1000");
      }
      const entries = await callAuditStore.list(limit);
      return sendJson(res, 200, { callAudit: entries });
    }

    if (route.name === "call-audit-detail") {
      if (req.method !== "GET") methodNotAllowed("GET");
      const entry = await callAuditStore.get(route.callAuditId);
      if (!entry) {
        throw new ApiError(404, "not_found", "The call audit entry was not found");
      }
      return sendJson(res, 200, { callAudit: entry });
    }

    throw new ApiError(404, "not_found", "The admin route was not found");
  }

  async function handleDataRoute(req, res, route, pathname, context) {
    const rawToken = bearer(req);
    const client = await registry.authenticateClient(rawToken);
    if (!client) {
      throw new ApiError(401, "unauthorized", "A valid MCP client credential is required");
    }

    if (route.name === "available") {
      if (req.method !== "GET") methodNotAllowed("GET");
      const servers = await registry.authorizedServers(client);
      return sendJson(res, 200, { servers });
    }

    if (route.name === "call") {
      if (req.method !== "POST") methodNotAllowed("POST");
      const body = await readBody(req, config.maxBodyBytes);
      if (!body
          || typeof body.serverId !== "string"
          || typeof body.tool !== "string"
          || body.arguments != null && typeof body.arguments !== "object") {
        throw new ApiError(400, "invalid_request", "serverId, tool and optional arguments are required");
      }
      const exposedName = `${body.serverId}__${body.tool}`;
      const auditContext = {
        requestId: context.requestId,
        operationId: `${client.id}:${crypto.randomUUID()}`,
      };
      let result;
      try {
        result = await registry.callTool(
          client,
          exposedName,
          body.arguments || {},
          String(req.headers["x-magpie-approval-token"] || ""),
          auditContext,
        );
      } catch (error) {
        if (error instanceof ApiError
            && error.code === "tool_not_found") {
          throw new ApiError(404, "tool_not_found", "The MCP tool was not found");
        }
        throw error;
      }
      return sendJson(res, 200, { result });
    }

    throw new ApiError(404, "not_found", "The data route was not found");
  }

  async function handleData(req, res, context) {
    if (req.method !== "POST") methodNotAllowed("POST");
    if (!originAllowed(req, config)) {
      throw new ApiError(403, "origin_denied", "Browser origins are not allowed");
    }
    const authKey = `${context.remoteAddress}:auth`;
    if (!authLimiter.consume(authKey)) {
      throw new ApiError(429, "rate_limited", "Too many authentication attempts", true);
    }
    const rawToken = bearer(req);
    const client = await registry.authenticateClient(rawToken);
    if (!client) {
      throw new ApiError(401, "unauthorized", "A valid MCP client credential is required");
    }
    if (!dataLimiter.consume(client.id)) {
      throw new ApiError(429, "rate_limited", "The MCP request rate limit was exceeded", true);
    }
    const body = await readBody(req, config.maxBodyBytes);
    const message = validateRpcRequest(body);
    const auditContext = {
      requestId: context.requestId,
      operationId: `${client.id}:${String(message.id ?? "notification")}`,
    };
    try {
      if (message.method === "initialize") {
        return sendJson(res, 200, rpcResult(message.id, {
          protocolVersion: config.protocolVersion,
          capabilities: {
            tools: {
              listChanged: false,
            },
          },
          serverInfo: {
            name: "magpie-enterprise-mcp-gateway",
            version: SERVER_VERSION,
          },
        }), {
          "mcp-protocol-version": config.protocolVersion,
        });
      }
      if (message.method === "notifications/initialized"
          || message.method === "notifications/cancelled") {
        return sendEmpty(res, 202);
      }
      if (message.method === "ping") {
        return sendJson(res, 200, rpcResult(message.id, {}));
      }
      if (message.method === "tools/list") {
        const tools = await registry.listExposedTools(client, auditContext);
        return sendJson(res, 200, rpcResult(message.id, projectToolList(tools)), {
          "mcp-protocol-version": config.protocolVersion,
        });
      }
      if (message.method === "tools/call") {
        if (!message.params
            || typeof message.params !== "object"
            || Array.isArray(message.params)
            || typeof message.params.name !== "string"
            || (message.params.arguments != null
              && (typeof message.params.arguments !== "object"
                || Array.isArray(message.params.arguments)))) {
          throw new ApiError(400, "invalid_params", "tools/call params are invalid");
        }
        let result;
        try {
          result = await registry.callTool(
            client,
            message.params.name,
            message.params.arguments || {},
            String(req.headers["x-magpie-approval-token"] || ""),
            auditContext,
          );
        } catch (error) {
          if (error instanceof ApiError
              && ["tool_not_found", "invalid_approval", "approval_replayed", "approval_unavailable"]
                .includes(error.code)) {
            await registry.auditDenied(client, message.params.name, error, auditContext);
          }
          throw error;
        }
        return sendJson(res, 200, rpcResult(message.id, result));
      }
      throw new ApiError(404, "method_not_found", "The MCP method is not supported");
    } catch (error) {
      if (error instanceof ApiError) {
        return sendJson(res, 200, rpcError(message.id, error));
      }
      if (error instanceof UpstreamError) {
        return sendJson(res, 200, rpcError(message.id, new ApiError(
          error.statusCode,
          error.code,
          error.message,
          true,
        )));
      }
      throw error;
    }
  }

  const server = http.createServer(async (req, res) => {
    const context = {
      requestId: requestId(),
      remoteAddress: String(req.socket.remoteAddress || "unknown"),
    };
    try {
      const url = new URL(req.url || "/", "http://localhost");
      if (url.pathname === "/healthz") {
        if (req.method !== "GET") methodNotAllowed("GET");
        return sendJson(res, 200, {
          service: "mcp-gateway",
          version: SERVER_VERSION,
        });
      }
      if (url.pathname === "/mcp/enterprise") {
        return await handleData(req, res, context);
      }
      const route = parseAdminRoute(url.pathname);
      if (route) {
        return await handleAdmin(req, res, route, url.pathname, context);
      }
      const dataRoute = parseDataRoute(url.pathname);
      if (dataRoute) {
        return await handleDataRoute(req, res, dataRoute, url.pathname, context);
      }
      throw new ApiError(404, "not_found", "The route was not found");
    } catch (error) {
      const safe = error instanceof ApiError
        ? error
        : new ApiError(500, "internal_error", "The request failed");
      if (!(error instanceof ApiError)) {
        logger({
          requestId: context.requestId,
          code: safe.code,
          errorName: error?.name || "Error",
        });
      }
      if (!res.headersSent) sendJson(res, safe.statusCode, apiErrorBody(safe));
      else res.destroy();
    }
  });

  const healthTimer = setInterval(() => {
    registry.runHealthChecks().catch((error) => {
      logger({ code: "health_check_failed", errorName: error?.name || "Error" });
    });
  }, config.healthIntervalMs);
  healthTimer.unref();
  server.on("close", () => clearInterval(healthTimer));

  return { server, registry, store, audit, upstream };
}
