import http from "node:http";
import readline from "node:readline";

import { LocalMcpError, asLocalMcpError } from "./errors.js";

export const LOCAL_MCP_BRIDGE_SCHEMA_VERSION = 1;
export const MCP_PROTOCOL_VERSION = "2025-06-18";
export const DEFAULT_HELPER_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_HELPER_RESPONSE_BYTES = 1024 * 1024;
export const DEFAULT_MAX_BRIDGE_MESSAGE_BYTES = 1024 * 1024;
export const HELPER_URL_ENV = "MAGPIE_LOCAL_MCP_HELPER_URL";
export const HELPER_TOKEN_ENV = "MAGPIE_LOCAL_MCP_HELPER_TOKEN";
export const RESOURCE_ID_ENV = "MAGPIE_LOCAL_MCP_RESOURCE_ID";

const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_TOOL_NAME = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;
const SAFE_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "[::1]"]);
const MAX_TOKEN_BYTES = 4096;
const GENERIC_INPUT_SCHEMA = Object.freeze({
  type: "object",
  additionalProperties: true,
});

function fail(code, message) {
  throw new LocalMcpError(code, message);
}

function safeCode(error, fallback = "helper_unavailable") {
  const code = asLocalMcpError(error, fallback).code;
  return SAFE_CODE.test(code) ? code : fallback;
}

function assertResourceId(resourceId) {
  if (typeof resourceId !== "string"
      || !SAFE_SEGMENT.test(resourceId)
      || resourceId === "."
      || resourceId === "..") {
    fail("invalid_resource_id", "resource id is invalid");
  }
}

function assertToken(token) {
  if (typeof token !== "string"
      || Buffer.byteLength(token, "utf8") < 16
      || Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES
      || /[\0\r\n]/.test(token)) {
    fail("invalid_config", "helper token is invalid");
  }
}

function assertPositiveInteger(value, label, lower, upper) {
  if (!Number.isSafeInteger(value) || value < lower || value > upper) {
    fail("invalid_config", `${label} is invalid`);
  }
}

// The helper must be reached directly. URL credentials, paths, redirects and
// non-loopback hosts are rejected so a signed package cannot be redirected to
// an enterprise gateway or the public network by local configuration.
export function normalizeLoopbackHelperUrl(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 8 * 1024) {
    fail("invalid_config", "helper URL is invalid");
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    fail("invalid_config", "helper URL is invalid");
  }
  if (url.protocol !== "http:"
      || !LOOPBACK_HOSTS.has(url.hostname)
      || url.username
      || url.password
      || (url.pathname !== "/" && url.pathname !== "")
      || url.search
      || url.hash) {
    fail("invalid_config", "helper URL must be an http loopback origin");
  }
  return url.origin;
}

function decodeSafeCode(text) {
  try {
    const body = JSON.parse(text);
    const code = body?.error?.code;
    return typeof code === "string" && SAFE_CODE.test(code)
      ? code
      : "helper_unavailable";
  } catch {
    return "helper_unavailable";
  }
}

function readResponse(res, maxResponseBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    res.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxResponseBytes) {
        res.destroy();
        reject(new LocalMcpError("protocol_too_large", "helper response is too large"));
        return;
      }
      chunks.push(chunk);
    });
    res.once("error", () => reject(new LocalMcpError(
      "helper_unavailable",
      "helper response failed",
    )));
    res.once("end", () => resolve(Buffer.concat(chunks, total).toString("utf8")));
  });
}

export class LoopbackHelperClient {
  constructor({
    helperUrl,
    token,
    resourceId,
    timeoutMs = DEFAULT_HELPER_TIMEOUT_MS,
    maxResponseBytes = DEFAULT_MAX_HELPER_RESPONSE_BYTES,
    request = http.request,
  } = {}) {
    this.helperUrl = normalizeLoopbackHelperUrl(helperUrl);
    assertToken(token);
    assertResourceId(resourceId);
    assertPositiveInteger(timeoutMs, "timeoutMs", 100, 120_000);
    assertPositiveInteger(
      maxResponseBytes,
      "maxResponseBytes",
      1024,
      16 * 1024 * 1024,
    );
    if (typeof request !== "function") fail("invalid_config", "request must be a function");
    this.token = token;
    this.resourceId = resourceId;
    this.timeoutMs = timeoutMs;
    this.maxResponseBytes = maxResponseBytes;
    this.request = request;
  }

  async requestJson(method, path, body) {
    const data = body === undefined ? null : Buffer.from(JSON.stringify(body), "utf8");
    const headers = {
      accept: "application/json",
      authorization: `Bearer ${this.token}`,
    };
    if (data) {
      headers["content-type"] = "application/json";
      headers["content-length"] = String(data.length);
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        if (error) reject(error);
        else resolve(value);
      };
      let req;
      try {
        req = this.request(`${this.helperUrl}${path}`, {
          method,
          headers,
          agent: false,
        }, (res) => {
          if (res.statusCode !== 200) {
            readResponse(res, this.maxResponseBytes)
              .then((text) => finish(new LocalMcpError(
                decodeSafeCode(text),
                "helper rejected the request",
              )))
              .catch((error) => finish(error));
            return;
          }
          readResponse(res, this.maxResponseBytes)
            .then((text) => {
              try {
                const value = JSON.parse(text);
                if (!value || typeof value !== "object" || Array.isArray(value)) {
                  throw new Error("not an object");
                }
                finish(null, value);
              } catch {
                finish(new LocalMcpError(
                  "protocol_invalid",
                  "helper response is not valid JSON",
                ));
              }
            })
            .catch((error) => finish(error));
        });
      } catch {
        finish(new LocalMcpError("helper_unavailable", "helper request failed"));
        return;
      }
      req.setTimeout(this.timeoutMs, () => {
        req.destroy();
        finish(new LocalMcpError("process_timeout", "helper request timed out"));
      });
      req.once("error", () => finish(new LocalMcpError(
        "helper_unavailable",
        "helper request failed",
      )));
      req.end(data);
    });
  }

  async listTools() {
    const response = await this.requestJson(
      "GET",
      `/api/v1/local-mcp/resources/${encodeURIComponent(this.resourceId)}/tools`,
    );
    if (!Array.isArray(response.tools)
        || response.tools.length > 128
        || response.tools.some((tool) => !tool
          || typeof tool !== "object"
          || Array.isArray(tool)
          || typeof tool.name !== "string"
          || !SAFE_TOOL_NAME.test(tool.name))) {
      fail("protocol_invalid", "helper tools response is invalid");
    }
    return response.tools;
  }

  async callTool(name, args) {
    return this.requestJson(
      "POST",
      `/api/v1/local-mcp/resources/${encodeURIComponent(this.resourceId)}`
        + `/tools/${encodeURIComponent(name)}/call`,
      { args },
    );
  }
}

function jsonRpcError(id, code, message, errorCode) {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message,
      data: errorCode ? { code: errorCode } : undefined,
    },
  };
}

function validId(id) {
  return typeof id === "string" || (typeof id === "number" && Number.isFinite(id));
}

function assertParams(params) {
  if (params === undefined) return {};
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    fail("invalid_request", "params must be an object");
  }
  return params;
}

export class LocalMcpBridge {
  constructor({
    client,
    resourceId,
    version = "0.1.0",
  } = {}) {
    if (!client
        || typeof client.listTools !== "function"
        || typeof client.callTool !== "function") {
      fail("invalid_config", "client must provide listTools() and callTool()");
    }
    assertResourceId(resourceId);
    if (typeof version !== "string" || !/^[0-9A-Za-z.+_-]{1,64}$/.test(version)) {
      fail("invalid_config", "version is invalid");
    }
    this.client = client;
    this.resourceId = resourceId;
    this.version = version;
  }

  async handle(request) {
    if (!request || typeof request !== "object" || Array.isArray(request)) {
      return jsonRpcError(null, -32600, "Invalid Request", "invalid_request");
    }
    const id = request.id;
    const notification = id === undefined || id === null;
    if (request.jsonrpc !== "2.0"
        || typeof request.method !== "string"
        || (!notification && !validId(id))) {
      return jsonRpcError(
        validId(id) ? id : null,
        -32600,
        "Invalid Request",
        "invalid_request",
      );
    }

    // MCP clients send initialized as a notification. It has no result and
    // needs no state because this bridge exposes a fixed, read/call surface.
    if (notification) return null;

    try {
      if (request.method === "initialize") {
        assertParams(request.params);
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: MCP_PROTOCOL_VERSION,
            capabilities: { tools: {} },
            serverInfo: {
              name: "magpie-local-mcp",
              version: this.version,
            },
          },
        };
      }
      if (request.method === "tools/list") {
        assertParams(request.params);
        const tools = await this.client.listTools();
        return {
          jsonrpc: "2.0",
          id,
          result: {
            tools: tools.map((tool) => ({
              name: tool.name,
              description: typeof tool.description === "string"
                ? tool.description
                : "",
              inputSchema: { ...GENERIC_INPUT_SCHEMA },
            })),
          },
        };
      }
      if (request.method === "tools/call") {
        const params = assertParams(request.params);
        if (typeof params.name !== "string" || !SAFE_TOOL_NAME.test(params.name)) {
          return jsonRpcError(id, -32602, "Invalid params", "invalid_tool_name");
        }
        const args = params.arguments === undefined ? {} : params.arguments;
        if (!args || typeof args !== "object" || Array.isArray(args)) {
          return jsonRpcError(id, -32602, "Invalid params", "invalid_request");
        }
        const response = await this.client.callTool(params.name, args);
        if (!response.result || typeof response.result !== "object"
            || Array.isArray(response.result)) {
          return jsonRpcError(id, -32002, "Local MCP result is invalid", "protocol_invalid");
        }
        return {
          jsonrpc: "2.0",
          id,
          result: response.result,
        };
      }
      return jsonRpcError(id, -32601, "Method not found", "method_not_found");
    } catch (error) {
      const code = safeCode(error, "internal_error");
      if (code === "invalid_request"
          || code === "invalid_resource_id"
          || code === "invalid_tool_name") {
        return jsonRpcError(id, -32602, "Invalid params", code);
      }
      return jsonRpcError(id, -32001, "Local MCP helper unavailable", code);
    }
  }
}

export function bridgeFromEnvironment(env = process.env) {
  const helperUrl = env?.[HELPER_URL_ENV];
  const token = env?.[HELPER_TOKEN_ENV];
  const resourceId = env?.[RESOURCE_ID_ENV];
  if (typeof helperUrl !== "string" || typeof token !== "string"
      || typeof resourceId !== "string") {
    fail("invalid_config", "required local MCP bridge environment is missing");
  }
  const client = new LoopbackHelperClient({ helperUrl, token, resourceId });
  return new LocalMcpBridge({
    client,
    resourceId,
    version: "0.1.0",
  });
}

function writeMessage(output, message, maxMessageBytes) {
  const line = `${JSON.stringify(message)}\n`;
  if (Buffer.byteLength(line, "utf8") > maxMessageBytes) {
    output.write(`${JSON.stringify(jsonRpcError(
      null,
      -32603,
      "Response is too large",
      "protocol_too_large",
    ))}\n`);
    return false;
  }
  output.write(line);
  return true;
}

export function runBridgeStdio({
  bridge,
  input = process.stdin,
  output = process.stdout,
  error = process.stderr,
  maxMessageBytes = DEFAULT_MAX_BRIDGE_MESSAGE_BYTES,
} = {}) {
  if (!bridge || typeof bridge.handle !== "function") {
    fail("invalid_config", "bridge must provide handle()");
  }
  assertPositiveInteger(
    maxMessageBytes,
    "maxMessageBytes",
    1024,
    16 * 1024 * 1024,
  );
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  let queue = Promise.resolve();
  let resolveClosed;
  let rejectClosed;
  const closed = new Promise((resolve, reject) => {
    resolveClosed = resolve;
    rejectClosed = reject;
  });
  lines.once("close", resolveClosed);
  input.once("error", rejectClosed);
  lines.on("line", (line) => {
    queue = queue.then(async () => {
      if (!line.trim()) return;
      if (Buffer.byteLength(line, "utf8") > maxMessageBytes) {
        writeMessage(output, jsonRpcError(
          null,
          -32700,
          "Parse error",
          "protocol_too_large",
        ), maxMessageBytes);
        return;
      }
      let request;
      try {
        request = JSON.parse(line);
      } catch {
        writeMessage(output, jsonRpcError(
          null,
          -32700,
          "Parse error",
          "parse_error",
        ), maxMessageBytes);
        return;
      }
      try {
        const response = await bridge.handle(request);
        if (response) writeMessage(output, response, maxMessageBytes);
      } catch (caught) {
        error.write(`local MCP bridge failed: ${safeCode(caught)}\n`);
        writeMessage(output, jsonRpcError(
          validId(request?.id) ? request.id : null,
          -32603,
          "Internal error",
          "internal_error",
        ), maxMessageBytes);
      }
    });
  });
  return closed.then(() => queue);
}
