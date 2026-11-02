import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { normalizeLoopbackHelperUrl } from "./bridge.js";
import { LocalMcpError } from "./errors.js";

export const DEFAULT_CODEX_MCP_SERVER_NAME = "magpie_local_mcp";
export const DEFAULT_CODEX_TOKEN_ENV = "MAGPIE_LOCAL_MCP_HELPER_TOKEN";
export const DEFAULT_CODEX_STARTUP_TIMEOUT_SEC = 20;
export const MAX_CODEX_CONFIG_BYTES = 4 * 1024 * 1024;

const SERVER_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const HELPER_URL_ENV = "MAGPIE_LOCAL_MCP_HELPER_URL";
const RESOURCE_ID_ENV = "MAGPIE_LOCAL_MCP_RESOURCE_ID";

function fail(code, message) {
  throw new LocalMcpError(code, message);
}

function assertSafeString(value, label, maxBytes = 16 * 1024) {
  if (typeof value !== "string"
      || !value
      || Buffer.byteLength(value, "utf8") > maxBytes
      || /[\0\r\n]/.test(value)) {
    fail("invalid_config", `${label} is invalid`);
  }
}

function assertAbsolutePath(value, label) {
  assertSafeString(value, label, 4096);
  if (!path.isAbsolute(value)) fail("invalid_config", `${label} must be absolute`);
}

function normalizeOptions({
  configPath,
  nodePath,
  bridgePath,
  helperUrl,
  resourceId,
  tokenEnvName = DEFAULT_CODEX_TOKEN_ENV,
  serverName = DEFAULT_CODEX_MCP_SERVER_NAME,
  startupTimeoutSec = DEFAULT_CODEX_STARTUP_TIMEOUT_SEC,
} = {}) {
  assertAbsolutePath(configPath, "configPath");
  assertAbsolutePath(nodePath, "nodePath");
  assertAbsolutePath(bridgePath, "bridgePath");
  if (typeof resourceId !== "string"
      || !RESOURCE_ID.test(resourceId)
      || resourceId === "."
      || resourceId === "..") {
    fail("invalid_config", "resourceId is invalid");
  }
  if (typeof tokenEnvName !== "string" || !ENV_NAME.test(tokenEnvName)) {
    fail("invalid_config", "tokenEnvName is invalid");
  }
  if (typeof serverName !== "string" || !SERVER_NAME.test(serverName)) {
    fail("invalid_config", "serverName is invalid");
  }
  if (!Number.isSafeInteger(startupTimeoutSec)
      || startupTimeoutSec < 1
      || startupTimeoutSec > 300) {
    fail("invalid_config", "startupTimeoutSec is invalid");
  }
  return {
    configPath: path.resolve(configPath),
    nodePath: path.resolve(nodePath),
    bridgePath: path.resolve(bridgePath),
    helperUrl: normalizeLoopbackHelperUrl(helperUrl),
    resourceId,
    tokenEnvName,
    serverName,
    startupTimeoutSec,
  };
}

export function codexConfigPath({
  home = os.homedir(),
  env = process.env,
} = {}) {
  const codexHome = env?.CODEX_HOME;
  if (codexHome !== undefined) {
    if (typeof codexHome !== "string" || !codexHome || !path.isAbsolute(codexHome)) {
      fail("invalid_config", "CODEX_HOME must be an absolute path");
    }
    return path.join(codexHome, "config.toml");
  }
  if (typeof home !== "string" || !home || !path.isAbsolute(home)) {
    fail("invalid_config", "home must be an absolute path");
  }
  return path.join(home, ".codex", "config.toml");
}

function tomlString(value) {
  let output = '"';
  for (const character of value) {
    const code = character.codePointAt(0);
    switch (character) {
      case "\\": output += "\\\\"; break;
      case "\"": output += "\\\""; break;
      case "\b": output += "\\b"; break;
      case "\t": output += "\\t"; break;
      case "\n": output += "\\n"; break;
      case "\f": output += "\\f"; break;
      case "\r": output += "\\r"; break;
      default:
        if (code < 0x20 || code === 0x7f) {
          output += `\\u${code.toString(16).padStart(4, "0")}`;
        } else {
          output += character;
        }
    }
  }
  return `${output}"`;
}

function markerLines(serverName) {
  if (typeof serverName !== "string" || !SERVER_NAME.test(serverName)) {
    fail("invalid_config", "serverName is invalid");
  }
  return {
    begin: `# >>> magpie-managed MCP server: ${serverName} (do not edit)`,
    end: `# <<< magpie-managed MCP server: ${serverName}`,
  };
}

function renderBlock(options) {
  const markers = markerLines(options.serverName);
  return [
    markers.begin,
    "[mcp_servers." + options.serverName + "]",
    `command = ${tomlString(options.nodePath)}`,
    `args = [${tomlString(options.bridgePath)}]`,
    "env = { "
      + `${HELPER_URL_ENV} = ${tomlString(options.helperUrl)}, `
      + `${RESOURCE_ID_ENV} = ${tomlString(options.resourceId)} }`,
    `env_vars = [${tomlString(options.tokenEnvName)}]`,
    `startup_timeout_sec = ${options.startupTimeoutSec}`,
    markers.end,
  ].join("\n");
}

function normalizeNewlines(value) {
  return value.replace(/\r\n/g, "\n");
}

function countOccurrences(text, needle) {
  let count = 0;
  let from = 0;
  while (true) {
    const index = text.indexOf(needle, from);
    if (index < 0) return count;
    count += 1;
    from = index + needle.length;
  }
}

function locatedAtLineStart(text, index) {
  return index === 0 || text[index - 1] === "\n" || text[index - 1] === "\r";
}

function locatedAtLineEnd(text, index) {
  return index >= text.length || text[index] === "\n" || text[index] === "\r";
}

function locateManagedBlock(text, serverName) {
  const markers = markerLines(serverName);
  if (countOccurrences(text, markers.begin) > 1
      || countOccurrences(text, markers.end) > 1) {
    fail("agent_config_malformed", "managed MCP marker appears more than once");
  }
  const begin = text.indexOf(markers.begin);
  const end = text.indexOf(markers.end);
  if ((begin < 0) !== (end < 0)) {
    fail("agent_config_malformed", "managed MCP markers are incomplete");
  }
  if (begin < 0) return null;
  if (!locatedAtLineStart(text, begin)) {
    fail("agent_config_malformed", "managed MCP begin marker is not on its own line");
  }
  if (!locatedAtLineEnd(text, begin + markers.begin.length)) {
    fail("agent_config_malformed", "managed MCP begin marker is not on its own line");
  }
  const endAtLineStart = locatedAtLineStart(text, end);
  if (!endAtLineStart
      || !locatedAtLineEnd(text, end + markers.end.length)
      || end < begin) {
    fail("agent_config_malformed", "managed MCP end marker is invalid");
  }
  return {
    begin,
    end: end + markers.end.length,
    value: normalizeNewlines(text.slice(begin, end + markers.end.length)),
  };
}

function escapedBareKey(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function hasServerTable(text, serverName) {
  const lines = text.split(/\r?\n/);
  const quoted = escapedBareKey(serverName);
  const direct = new RegExp(
    `^\\s*\\[\\[?\\s*mcp_servers\\s*\\.\\s*(?:${quoted}|"${quoted}"|'${quoted}')`
      + "(?:\\s*\\.\\s*[^\\]]+)?\\s*\\]\\]?\\s*(?:#.*)?$",
  );
  let inMcpServers = false;
  const inlineAssignment = new RegExp(`^\\s*${quoted}\\s*=`);
  for (const line of lines) {
    const trimmed = line.trim();
    if (direct.test(line)) return true;
    if (/^\s*\[\[\s*mcp_servers\s*\]\]\s*(?:#.*)?$/.test(line)
        || /^\s*\[mcp_servers\s*\]\s*(?:#.*)?$/.test(line)) {
      inMcpServers = true;
      continue;
    }
    if (/^\s*\[/.test(trimmed)) {
      inMcpServers = false;
      continue;
    }
    if (inMcpServers && inlineAssignment.test(trimmed)) return true;
  }
  return false;
}

async function lstatOrNull(target) {
  try {
    return await fs.lstat(target);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function readConfig(configPath) {
  const stat = await lstatOrNull(configPath);
  if (!stat) return { text: "", bom: false };
  if (stat.isSymbolicLink()) {
    fail("path_symlink", "Codex config must not be a symbolic link");
  }
  if (!stat.isFile()) fail("invalid_config", "Codex config is not a regular file");
  if (stat.size > MAX_CODEX_CONFIG_BYTES) {
    fail("invalid_config", "Codex config is too large");
  }
  const raw = await fs.readFile(configPath);
  const bom = raw.length >= 3
    && raw[0] === 0xef
    && raw[1] === 0xbb
    && raw[2] === 0xbf;
  try {
    return {
      text: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
        bom ? raw.subarray(3) : raw,
      ),
      bom,
    };
  } catch {
    fail("invalid_config", "Codex config is not valid UTF-8");
  }
}

async function atomicWrite(configPath, text, bom) {
  const parent = path.dirname(configPath);
  const parentBefore = await lstatOrNull(parent);
  if (parentBefore?.isSymbolicLink()) {
    fail("path_symlink", "Codex config directory must not be a symbolic link");
  }
  if (!parentBefore) await fs.mkdir(parent, { recursive: true, mode: 0o700 });
  const parentAfter = await lstatOrNull(parent);
  if (!parentAfter || parentAfter.isSymbolicLink() || !parentAfter.isDirectory()) {
    fail("invalid_config", "Codex config directory is unsafe");
  }
  const temporary = path.join(
    parent,
    `.${path.basename(configPath)}.${process.pid}.${crypto.randomUUID()}.tmp`,
  );
  const data = Buffer.concat([
    ...(bom ? [Buffer.from([0xef, 0xbb, 0xbf])] : []),
    Buffer.from(text, "utf8"),
  ]);
  let handle;
  try {
    handle = await fs.open(temporary, "wx", 0o600);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, configPath);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    if (error instanceof LocalMcpError) throw error;
    fail("agent_config_write_failed", "Codex config could not be written atomically");
  }
}

function appendBlock(text, block) {
  if (!text) return `${block}\n`;
  const ending = text.endsWith("\n") ? "\n" : "\n\n";
  return `${text}${ending}${block}\n`;
}

function removeLocatedBlock(text, located) {
  let before = text.slice(0, located.begin);
  let after = text.slice(located.end);
  if (before.endsWith("\r\n")) before = before.slice(0, -2);
  else if (before.endsWith("\n")) before = before.slice(0, -1);
  if (after.startsWith("\r\n")) after = after.slice(2);
  else if (after.startsWith("\n")) after = after.slice(1);
  if (before && after && !before.endsWith("\n") && !before.endsWith("\r")) {
    before += "\n";
  }
  return before + after;
}

function parseBasicString(text, start) {
  if (text[start] !== "\"") {
    fail("agent_config_malformed", "managed MCP value is not a basic string");
  }
  let output = "";
  for (let index = start + 1; index < text.length; index += 1) {
    const character = text[index];
    if (character === "\"") return { value: output, end: index + 1 };
    if (character !== "\\") {
      output += character;
      continue;
    }
    index += 1;
    if (index >= text.length) break;
    const escaped = text[index];
    switch (escaped) {
      case "\\": output += "\\"; break;
      case "\"": output += "\""; break;
      case "b": output += "\b"; break;
      case "t": output += "\t"; break;
      case "n": output += "\n"; break;
      case "f": output += "\f"; break;
      case "r": output += "\r"; break;
      case "u": {
        const hex = text.slice(index + 1, index + 5);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          fail("agent_config_malformed", "managed MCP unicode escape is invalid");
        }
        output += String.fromCodePoint(Number.parseInt(hex, 16));
        index += 4;
        break;
      }
      default:
        fail("agent_config_malformed", "managed MCP string escape is invalid");
    }
  }
  fail("agent_config_malformed", "managed MCP basic string is incomplete");
}

function parseManagedDetails(value, serverName) {
  const markers = markerLines(serverName);
  const lines = normalizeNewlines(value).split("\n");
  if (lines.length !== 8
      || lines[0] !== markers.begin
      || lines[1] !== `[mcp_servers.${serverName}]`
      || lines[7] !== markers.end) {
    fail("agent_config_malformed", "managed MCP block has an unexpected shape");
  }

  const parseLine = (line, prefix) => {
    if (!line.startsWith(prefix)) {
      fail("agent_config_malformed", "managed MCP field is missing");
    }
    return parseBasicString(line, prefix.length);
  };

  const command = parseLine(lines[2], "command = ");
  if (command.end !== lines[2].length) {
    fail("agent_config_malformed", "managed MCP command has trailing content");
  }
  if (!lines[3].startsWith("args = [")) {
    fail("agent_config_malformed", "managed MCP args are missing");
  }
  const args = parseBasicString(lines[3], "args = [".length);
  if (args.end >= lines[3].length || lines[3].slice(args.end) !== "]") {
    fail("agent_config_malformed", "managed MCP args have an unexpected shape");
  }

  const envPrefix = `env = { ${HELPER_URL_ENV} = `;
  if (!lines[4].startsWith(envPrefix)) {
    fail("agent_config_malformed", "managed MCP helper URL is missing");
  }
  const helperUrl = parseBasicString(lines[4], envPrefix.length);
  const resourcePrefix = `, ${RESOURCE_ID_ENV} = `;
  if (!lines[4].startsWith(resourcePrefix, helperUrl.end)) {
    fail("agent_config_malformed", "managed MCP resource id is missing");
  }
  const resourceId = parseBasicString(
    lines[4],
    helperUrl.end + resourcePrefix.length,
  );
  if (lines[4].slice(resourceId.end) !== " }") {
    fail("agent_config_malformed", "managed MCP env has an unexpected shape");
  }

  const envVars = parseLine(lines[5], "env_vars = [");
  if (envVars.end >= lines[5].length || lines[5].slice(envVars.end) !== "]") {
    fail("agent_config_malformed", "managed MCP env_vars have an unexpected shape");
  }

  const timeout = /^startup_timeout_sec = ([1-9][0-9]*)$/.exec(lines[6]);
  if (!timeout) {
    fail("agent_config_malformed", "managed MCP startup timeout is invalid");
  }
  return {
    nodePath: command.value,
    bridgePath: args.value,
    helperUrl: helperUrl.value,
    resourceId: resourceId.value,
    tokenEnvName: envVars.value,
    startupTimeoutSec: Number(timeout[1]),
  };
}

export async function applyCodexAgentConfig(options = {}) {
  const normalized = normalizeOptions(options);
  const block = renderBlock(normalized);
  const { text, bom } = await readConfig(normalized.configPath);
  const located = locateManagedBlock(text, normalized.serverName);
  const tablePresent = hasServerTable(text, normalized.serverName);
  if (located) {
    if (located.value === block) {
      return {
        status: "unchanged",
        serverName: normalized.serverName,
        resourceId: normalized.resourceId,
      };
    }
    if (options.force !== true) {
      fail("agent_config_drift", "managed Codex MCP entry changed outside Magpie");
    }
    const next = text.slice(0, located.begin) + block + text.slice(located.end);
    await atomicWrite(normalized.configPath, next, bom);
    return {
      status: "updated",
      serverName: normalized.serverName,
      resourceId: normalized.resourceId,
    };
  }
  if (tablePresent) {
    fail("agent_config_conflict", "Codex already has an unmanaged MCP server with this name");
  }
  await atomicWrite(
    normalized.configPath,
    appendBlock(text, block),
    bom,
  );
  return {
    status: "applied",
    serverName: normalized.serverName,
    resourceId: normalized.resourceId,
  };
}

export async function inspectCodexAgentConfig({
  configPath,
  serverName = DEFAULT_CODEX_MCP_SERVER_NAME,
} = {}) {
  assertAbsolutePath(configPath, "configPath");
  markerLines(serverName);
  const { text } = await readConfig(path.resolve(configPath));
  const located = locateManagedBlock(text, serverName);
  const tablePresent = hasServerTable(text, serverName);
  return {
    status: located ? "managed" : tablePresent ? "unmanaged" : "absent",
    serverName,
    managed: located ? parseManagedDetails(located.value, serverName) : null,
  };
}

export async function removeCodexAgentConfig({
  configPath,
  serverName = DEFAULT_CODEX_MCP_SERVER_NAME,
} = {}) {
  assertAbsolutePath(configPath, "configPath");
  markerLines(serverName);
  const { text, bom } = await readConfig(path.resolve(configPath));
  const located = locateManagedBlock(text, serverName);
  if (!located) {
    if (hasServerTable(text, serverName)) {
      fail("agent_config_conflict", "Codex MCP entry is not owned by Magpie");
    }
    return { status: "absent", serverName };
  }
  await atomicWrite(
    path.resolve(configPath),
    removeLocatedBlock(text, located),
    bom,
  );
  return { status: "removed", serverName };
}

export function renderCodexAgentConfig(options = {}) {
  return renderBlock(normalizeOptions(options));
}
