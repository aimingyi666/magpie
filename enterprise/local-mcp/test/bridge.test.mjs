import assert from "node:assert/strict";
import test from "node:test";

import {
  LocalMcpBridge,
  LoopbackHelperClient,
  MCP_PROTOCOL_VERSION,
  normalizeLoopbackHelperUrl,
} from "../src/bridge.js";
import { LocalMcpError } from "../src/errors.js";

const RESOURCE_ID = "res_local_echo";
const TOKEN = ["bridge", "test", "token", "0123456789"].join("-");

function assertError(code) {
  return (error) => error instanceof LocalMcpError && error.code === code;
}

function fakeClient(overrides = {}) {
  const calls = [];
  return {
    calls,
    async listTools() {
      return [{
        name: "echo",
        description: "Echo test input",
        risk: "low",
        capabilities: [],
      }];
    },
    async callTool(name, args) {
      calls.push({ name, args });
      return {
        status: "succeeded",
        result: {
          isError: false,
          content: [{ type: "text", text: "ok" }],
          structuredContent: { echo: args.echo },
        },
      };
    },
    ...overrides,
  };
}

function bridgeFor(client) {
  return new LocalMcpBridge({ client, resourceId: RESOURCE_ID });
}

test("helper URL policy accepts only direct loopback HTTP origins", () => {
  assert.equal(
    normalizeLoopbackHelperUrl("http://127.0.0.1:43123"),
    "http://127.0.0.1:43123",
  );
  assert.equal(
    normalizeLoopbackHelperUrl("http://[::1]:43123"),
    "http://[::1]:43123",
  );
  for (const value of [
    "https://127.0.0.1:43123",
    "http://localhost:43123",
    "http://0.0.0.0:43123",
    "http://127.0.0.2:43123",
    "http://example.com:43123",
    "http://user:pass@127.0.0.1:43123",
    "http://127.0.0.1:43123/path",
    "http://127.0.0.1:43123/?query=1",
  ]) {
    assert.throws(
      () => normalizeLoopbackHelperUrl(value),
      assertError("invalid_config"),
      value,
    );
  }
});

test("bridge exposes initialize, tools/list and tools/call over MCP shapes", async () => {
  const client = fakeClient();
  const bridge = bridgeFor(client);

  const initialized = await bridge.handle({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "test", version: "1.0.0" },
    },
  });
  assert.equal(initialized.result.protocolVersion, MCP_PROTOCOL_VERSION);
  assert.deepEqual(initialized.result.capabilities, { tools: {} });
  assert.equal(initialized.result.serverInfo.name, "magpie-local-mcp");

  const listed = await bridge.handle({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
    params: {},
  });
  assert.deepEqual(listed.result.tools, [{
    name: "echo",
    description: "Echo test input",
    inputSchema: { type: "object", additionalProperties: true },
  }]);

  const called = await bridge.handle({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "echo", arguments: { echo: "hello" } },
  });
  assert.equal(called.result.structuredContent.echo, "hello");
  assert.deepEqual(client.calls, [{ name: "echo", args: { echo: "hello" } }]);
});

test("notifications are silent and unsupported or invalid requests stay bounded", async () => {
  const bridge = bridgeFor(fakeClient());
  assert.equal(await bridge.handle({
    jsonrpc: "2.0",
    method: "notifications/initialized",
    params: {},
  }), null);

  const unsupported = await bridge.handle({
    jsonrpc: "2.0",
    id: "a",
    method: "resources/list",
    params: {},
  });
  assert.equal(unsupported.error.code, -32601);
  assert.equal(unsupported.error.data.code, "method_not_found");

  const badTool = await bridge.handle({
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: { name: "../escape", arguments: {} },
  });
  assert.equal(badTool.error.code, -32602);
  assert.equal(badTool.error.data.code, "invalid_tool_name");

  const badArgs = await bridge.handle({
    jsonrpc: "2.0",
    id: 5,
    method: "tools/call",
    params: { name: "echo", arguments: [] },
  });
  assert.equal(badArgs.error.code, -32602);
  assert.equal(badArgs.error.data.code, "invalid_request");
});

test("helper failures omit paths, tokens and exception messages from JSON-RPC", async () => {
  const bridge = bridgeFor(fakeClient({
    async listTools() {
      throw new Error("C:\\secret\\token.txt TOP-SECRET");
    },
  }));
  const response = await bridge.handle({
    jsonrpc: "2.0",
    id: 7,
    method: "tools/list",
    params: {},
  });
  assert.equal(response.error.code, -32001);
  assert.deepEqual(response.error.data, { code: "internal_error" });
  assert.equal(JSON.stringify(response).includes("secret"), false);
  assert.equal(JSON.stringify(response).includes("TOP-SECRET"), false);
});

test("the loopback HTTP client pins resource, method, body and bearer token", async () => {
  const requests = [];
  const request = (url, options, callback) => {
    const chunks = [];
    const req = {
      setTimeout() {},
      once() {},
      end(data) {
        if (data) chunks.push(data);
        const body = JSON.stringify(url.endsWith("/tools")
          ? { tools: [{ name: "echo", description: "Echo" }] }
          : { status: "succeeded", result: { content: [] } });
        const res = {
          statusCode: 200,
          on(event, handler) {
            if (event === "data") handler(Buffer.from(body));
          },
          once(event, handler) {
            if (event === "end") queueMicrotask(handler);
          },
          destroy() {},
        };
        requests.push({
          url,
          options,
          body: Buffer.concat(chunks).toString("utf8"),
        });
        callback(res);
      },
    };
    return req;
  };
  const client = new LoopbackHelperClient({
    helperUrl: "http://127.0.0.1:43123",
    token: TOKEN,
    resourceId: RESOURCE_ID,
    request,
  });

  assert.deepEqual(await client.listTools(), [{ name: "echo", description: "Echo" }]);
  const called = await client.callTool("echo", { echo: "hello" });
  assert.equal(called.status, "succeeded");
  assert.equal(
    requests[0].url,
    `http://127.0.0.1:43123/api/v1/local-mcp/resources/${RESOURCE_ID}/tools`,
  );
  assert.equal(requests[0].options.method, "GET");
  assert.equal(requests[0].options.headers.authorization, `Bearer ${TOKEN}`);
  assert.equal(
    requests[1].url,
    `http://127.0.0.1:43123/api/v1/local-mcp/resources/${RESOURCE_ID}/tools/echo/call`,
  );
  assert.equal(requests[1].options.method, "POST");
  assert.deepEqual(JSON.parse(requests[1].body), { args: { echo: "hello" } });
});
