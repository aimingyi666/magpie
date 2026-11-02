import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  LocalMcpHost,
  buildSignedPackage,
  publicKeyFingerprint,
} from "../src/index.js";

export const KEY_ID = "enterprise-local-mcp-test-v1";
export const PUBLISHER = "enterprise-platform";
export const CLIENT_VERSION = "1.0.0";

export const MCP_SERVER_SOURCE = `import readline from "node:readline";

const modes = new Set(process.argv.slice(2));
const tools = modes.has("mismatch")
  ? [{ name: "other", description: "Mismatched tool", inputSchema: { type: "object" } }]
  : [{ name: "echo", description: "Echo test input", inputSchema: { type: "object" } }];
const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

function send(message) {
  process.stdout.write(JSON.stringify(message) + "\\n");
}

input.on("line", (line) => {
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
    return;
  }
  if (request.id === undefined || request.id === null) return;
  if (request.method === "initialize") {
    send({
      jsonrpc: "2.0",
      id: request.id,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "local-mcp-test", version: "1.0.0" },
      },
    });
    return;
  }
  if (request.method === "tools/list") {
    send({ jsonrpc: "2.0", id: request.id, result: { tools } });
    return;
  }
  if (request.method !== "tools/call") {
    send({ jsonrpc: "2.0", id: request.id, error: { code: -32601, message: "not found" } });
    return;
  }
  if (modes.has("timeout")) return;
  if (modes.has("rpc-error")) {
    send({ jsonrpc: "2.0", id: request.id, error: { code: -32000, message: "forced error" } });
    return;
  }
  if (modes.has("malformed")) {
    process.stdout.write("{not-json}\\n");
    return;
  }
  if (modes.has("large-response")) {
    send({
      jsonrpc: "2.0",
      id: request.id,
      result: { content: [{ type: "text", text: "x".repeat(4096) }] },
    });
    return;
  }
  send({
    jsonrpc: "2.0",
    id: request.id,
    result: {
      isError: modes.has("result-error"),
      content: [{
        type: "text",
        text: modes.has("result-error") ? "forced tool error" : "ok",
      }],
      structuredContent: {
        echo: request.params?.arguments?.echo ?? null,
        secret: process.env.CORP_TOKEN ?? null,
      },
    },
  });
});
`;

export function createIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKey,
    privateKey,
    publicKeys: { [KEY_ID]: publicKey.export({ type: "spki", format: "pem" }) },
    keyFingerprints: { [KEY_ID]: publicKeyFingerprint(publicKey) },
  };
}

export function packageFields(overrides = {}) {
  const {
    runtime,
    permissions,
    secrets,
    tools,
    compatibility,
    ...rest
  } = overrides;
  return {
    packageId: "local-echo",
    releaseId: "2026.11.1",
    packageVersion: "1.0.0",
    publisher: PUBLISHER,
    createdAt: "2026-11-02T00:00:00.000Z",
    description: "Local MCP test package",
    signingKeyId: KEY_ID,
    ...rest,
    runtime: {
      interpreter: "node",
      entrypoint: "server.mjs",
      args: [],
      protocol: "stdio-jsonrpc",
      ...(runtime ?? {}),
    },
    permissions: {
      capabilities: [],
      networkHosts: [],
      ...(permissions ?? {}),
    },
    secrets: secrets ?? [],
    tools: tools ?? [{
      name: "echo",
      description: "Echo test input",
      risk: "low",
      capabilities: [],
    }],
    compatibility: {
      minClientVersion: "1.0.0",
      platforms: [process.platform],
      architectures: [process.arch],
      ...(compatibility ?? {}),
    },
  };
}

export function createPackage(identity, overrides = {}, files = null) {
  return buildSignedPackage(
    packageFields(overrides),
    files ?? {
      "server.mjs": MCP_SERVER_SOURCE,
      "README.txt": "Signed local MCP test fixture.\n",
    },
    identity.privateKey,
  );
}

export function hostOptions(identity, rootDir, overrides = {}) {
  return {
    rootDir,
    publicKeys: identity.publicKeys,
    keyFingerprints: identity.keyFingerprints,
    allowedPublishers: [PUBLISHER],
    allowedTools: ["*"],
    maxRisk: "critical",
    allowedCapabilities: [],
    allowedNetworkHosts: [],
    interpreterAliases: { node: process.execPath },
    clientVersion: CLIENT_VERSION,
    platform: process.platform,
    architecture: process.arch,
    maxProcessMs: 1_000,
    ...overrides,
  };
}

export function createHost(identity, rootDir, overrides = {}) {
  return new LocalMcpHost(hostOptions(identity, rootDir, overrides));
}

export function temporaryRoot(t, prefix = "magpie-local-mcp-") {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return path.join(parent, "managed");
}

export async function readJsonLines(file) {
  const text = await fs.promises.readFile(file, "utf8");
  return text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}
