import { NetworkPolicyError, safeRequest } from "./network.js";

export class UpstreamError extends Error {
  constructor(code, message, statusCode = 502) {
    super(message);
    this.name = "UpstreamError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

function parseSseEvents(text) {
  const values = [];
  const events = text.split(/\r?\n\r?\n/);
  for (const event of events) {
    const data = event
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trimStart())
      .join("\n");
    if (!data) continue;
    try {
      values.push(JSON.parse(data));
    } catch {
      throw new UpstreamError("upstream_invalid_response", "The upstream returned invalid SSE data");
    }
  }
  return values;
}

function parseRpcResponse(response, expectedId) {
  const contentType = String(response.headers["content-type"] || "").toLowerCase();
  if (response.statusCode < 200 || response.statusCode >= 300) {
    const status = response.statusCode;
    throw new UpstreamError(
      status === 401 || status === 403 ? "upstream_unauthorized" : "upstream_http_error",
      "The upstream MCP server rejected the request",
      status === 401 || status === 403 ? 502 : 502,
    );
  }
  const text = response.body.toString("utf8");
  let values;
  if (contentType.includes("text/event-stream")) {
    values = parseSseEvents(text);
  } else if (contentType.includes("application/json")) {
    try {
      values = [JSON.parse(text)];
    } catch {
      throw new UpstreamError("upstream_invalid_response", "The upstream returned invalid JSON");
    }
  } else {
    throw new UpstreamError("upstream_invalid_response", "The upstream content type is unsupported");
  }
  const message = values.find((value) => value
    && value.jsonrpc === "2.0"
    && value.id === expectedId);
  if (!message) {
    throw new UpstreamError("upstream_invalid_response", "The upstream returned no matching response");
  }
  if (message.error) {
    const code = typeof message.error.code === "number" ? message.error.code : -32603;
    const text = typeof message.error.message === "string"
      ? message.error.message.slice(0, 500)
      : "The upstream tool call failed";
    throw new UpstreamError("upstream_rpc_error", text, code);
  }
  return message.result;
}

function validateTool(tool) {
  return Boolean(tool)
    && typeof tool === "object"
    && !Array.isArray(tool)
    && typeof tool.name === "string"
    && tool.name.length > 0
    && tool.name.length <= 128
    && !tool.name.includes("__")
    && !/[\u0000-\u001f\u007f]/.test(tool.name)
    && (tool.description == null || (typeof tool.description === "string"
      && tool.description.length <= 4000))
    && (tool.inputSchema == null || (typeof tool.inputSchema === "object"
      && !Array.isArray(tool.inputSchema)));
}

export class UpstreamMcpClient {
  constructor(config, { resolver, logger = () => {} } = {}) {
    this.config = config;
    this.resolver = resolver;
    this.logger = logger;
    this.sessions = new Map();
    this.requestIds = new Map();
  }

  nextId(serverId) {
    const next = (this.requestIds.get(serverId) || 0) + 1;
    this.requestIds.set(serverId, next);
    return next;
  }

  headers(server, sessionId) {
    const headers = {
      "content-type": "application/json",
    };
    if (sessionId) headers["mcp-session-id"] = sessionId;
    if (server.secretRef) {
      const secret = this.config.secretEnv[server.secretRef];
      if (typeof secret !== "string" || !secret) {
        throw new UpstreamError(
          "upstream_credentials_unavailable",
          "The upstream credential is unavailable",
          503,
        );
      }
      headers.authorization = `Bearer ${secret}`;
    }
    return headers;
  }

  async post(server, message, { timeoutMs = this.config.upstreamTimeoutMs, sessionId } = {}) {
    let response;
    try {
      response = await safeRequest(server.endpoint, {
        config: this.config,
        resolver: this.resolver,
        timeoutMs,
        maxResponseBytes: this.config.upstreamMaxResponseBytes,
        headers: this.headers(server, sessionId),
        body: JSON.stringify(message),
      });
    } catch (error) {
      if (error.code === "upstream_timeout" || error.code === "upstream_response_too_large") {
        throw new UpstreamError(error.code, error.message);
      }
      if (error instanceof NetworkPolicyError) {
        throw new UpstreamError("upstream_network_rejected", error.message);
      }
      throw new UpstreamError("upstream_unavailable", "The upstream MCP server is unavailable");
    }
    return response;
  }

  async initialize(server, { timeoutMs, force = false } = {}) {
    const existing = this.sessions.get(server.id);
    if (!force && existing && Date.now() - existing.at < this.config.catalogTtlMs) {
      return existing;
    }
    const initializeId = this.nextId(server.id);
    const response = await this.post(server, {
      jsonrpc: "2.0",
      id: initializeId,
      method: "initialize",
      params: {
        protocolVersion: this.config.protocolVersion,
        capabilities: {},
        clientInfo: {
          name: "magpie-enterprise-mcp-gateway",
          version: "0.1.0",
        },
      },
    }, { timeoutMs });
    const result = parseRpcResponse(response, initializeId);
    if (!result || typeof result !== "object" || Array.isArray(result)) {
      throw new UpstreamError("upstream_invalid_response", "The upstream initialize result is invalid");
    }
    const sessionId = String(response.headers["mcp-session-id"] || "");
    const session = {
      id: sessionId,
      protocolVersion: typeof result.protocolVersion === "string"
        ? result.protocolVersion
        : this.config.protocolVersion,
      at: Date.now(),
    };
    this.sessions.set(server.id, session);
    if (sessionId) {
      await this.post(server, {
        jsonrpc: "2.0",
        method: "notifications/initialized",
      }, { timeoutMs, sessionId }).catch((error) => {
        this.logger({
          serverId: server.id,
          code: error.code || "initialized_notification_failed",
        });
      });
    }
    return session;
  }

  async listTools(server, { timeoutMs = this.config.upstreamTimeoutMs, force = false } = {}) {
    const session = await this.initialize(server, { timeoutMs, force });
    const id = this.nextId(server.id);
    const response = await this.post(server, {
      jsonrpc: "2.0",
      id,
      method: "tools/list",
      params: {},
    }, { timeoutMs, sessionId: session.id });
    const result = parseRpcResponse(response, id);
    if (!result
        || typeof result !== "object"
        || !Array.isArray(result.tools)
        || result.tools.length > this.config.maxToolsPerServer
        || !result.tools.every(validateTool)
        || new Set(result.tools.map((tool) => tool.name)).size !== result.tools.length) {
      throw new UpstreamError("upstream_invalid_response", "The upstream tools list is invalid");
    }
    return result.tools.map((tool) => ({
      name: tool.name,
      description: tool.description || "",
      inputSchema: tool.inputSchema || { type: "object" },
    }));
  }

  async callTool(server, toolName, input, { timeoutMs = this.config.upstreamTimeoutMs } = {}) {
    const session = await this.initialize(server, { timeoutMs });
    const id = this.nextId(server.id);
    const response = await this.post(server, {
      jsonrpc: "2.0",
      id,
      method: "tools/call",
      params: {
        name: toolName,
        arguments: input,
      },
    }, { timeoutMs, sessionId: session.id });
    const result = parseRpcResponse(response, id);
    if (!result || typeof result !== "object" || Array.isArray(result)) {
      throw new UpstreamError("upstream_invalid_response", "The upstream tool result is invalid");
    }
    return result;
  }

  forget(serverId) {
    this.sessions.delete(serverId);
    this.requestIds.delete(serverId);
  }
}
