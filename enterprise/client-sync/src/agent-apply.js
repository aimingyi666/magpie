// Writing an enterprise instruction into an agent's own file.
//
// The resource stays the enterprise's; the file stays the employee's. A
// resource is one managed block between two markers, so it can be replaced
// or removed without touching anything the employee wrote around it. The
// write is atomic and keeps the file's BOM and line endings; a file that is
// a symlink, or whose markers are damaged, is refused rather than guessed.

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_BLOCK_BYTES = 1024 * 1024;
const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

// Which file an agent reads its standing instructions from.
export const INSTRUCTION_FILES = Object.freeze({
  claude: "CLAUDE.md",
  codex: "AGENTS.md",
});

export class AgentApplyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "AgentApplyError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new AgentApplyError(code, message);
}

function beginMarker(resourceId) {
  return `<!-- magpie:managed:begin ${resourceId} -->`;
}

function endMarker(resourceId) {
  return `<!-- magpie:managed:end ${resourceId} -->`;
}

function blockOf(resourceId, text, eol) {
  const body = String(text).replace(/\r\n/g, "\n").split("\n").join(eol);
  return `${beginMarker(resourceId)}${eol}${body}${eol}${endMarker(resourceId)}`;
}

function count(haystack, needle) {
  let total = 0;
  for (let at = haystack.indexOf(needle); at >= 0; at = haystack.indexOf(needle, at + 1)) {
    total += 1;
  }
  return total;
}

// assertMarkersWhole refuses text whose markers do not pair up: a half
// block cannot be replaced without risking the employee's text.
function assertMarkersWhole(text) {
  const begins = count(text, "<!-- magpie:managed:begin ");
  const ends = count(text, "<!-- magpie:managed:end ");
  if (begins !== ends) {
    fail("agent_config_malformed", "A managed block is missing its end marker");
  }
}

function existingBlock(text, resourceId) {
  const begin = beginMarker(resourceId);
  const end = endMarker(resourceId);
  const begins = count(text, begin);
  const ends = count(text, end);
  if (begins !== ends) {
    fail("agent_config_malformed", `The block for ${resourceId} is damaged`);
  }
  if (begins > 1) {
    fail("agent_config_malformed", `The block for ${resourceId} appears more than once`);
  }
  if (begins === 0) return null;
  const from = text.indexOf(begin);
  const to = text.indexOf(end, from);
  if (to < 0) fail("agent_config_malformed", `The block for ${resourceId} is damaged`);
  return { from, to: to + end.length };
}

async function lstatOrNull(target) {
  try {
    return await fs.lstat(target);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    throw error;
  }
}

async function readFile(target) {
  const stat = await lstatOrNull(target);
  if (!stat) return { text: "", bom: false };
  if (stat.isSymbolicLink()) fail("path_symlink", "The agent file must not be a symbolic link");
  if (!stat.isFile()) fail("invalid_agent_file", "The agent file is not a regular file");
  if (stat.size > MAX_FILE_BYTES) fail("invalid_agent_file", "The agent file is too large");
  const raw = await fs.readFile(target);
  const bom = raw.length >= 3 && raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf;
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      bom ? raw.subarray(3) : raw,
    );
  } catch {
    fail("invalid_agent_file", "The agent file is not valid UTF-8");
  }
  return { text, bom };
}

async function writeFile(target, text, bom) {
  const parent = path.dirname(target);
  const parentStat = await lstatOrNull(parent);
  if (parentStat?.isSymbolicLink()) {
    fail("path_symlink", "The agent directory must not be a symbolic link");
  }
  if (!parentStat) await fs.mkdir(parent, { recursive: true, mode: 0o700 });
  const temporary = path.join(
    parent,
    `.${path.basename(target)}.${process.pid}.${crypto.randomUUID()}.tmp`,
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
    await fs.rename(temporary, target);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    if (error instanceof AgentApplyError) throw error;
    fail("agent_file_write_failed", "The agent file could not be written");
  }
}

function agentFile(agent) {
  const name = INSTRUCTION_FILES[agent];
  if (!name) fail("unknown_agent", `No instruction file is known for ${agent}`);
  return name;
}

// applyInstruction writes text as the resource's managed block, replacing
// the block it wrote before and leaving the rest of the file alone.
export async function applyInstruction({ agent, root, resourceId, text }) {
  const file = agentFile(agent);
  if (!RESOURCE_ID.test(String(resourceId || ""))) {
    fail("invalid_resource_id", "The resource id is invalid");
  }
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > MAX_BLOCK_BYTES) {
    fail("invalid_resource_content", "The instruction text is invalid or too large");
  }
  if (!root) fail("invalid_root", "The agent root is required");
  const target = path.join(root, file);
  const { text: current, bom } = await readFile(target);
  assertMarkersWhole(current);
  const eol = current.includes("\r\n") ? "\r\n" : "\n";
  const block = blockOf(resourceId, text, eol);
  const existing = existingBlock(current, resourceId);
  let next;
  if (existing) {
    next = current.slice(0, existing.from) + block + current.slice(existing.to);
  } else if (current.trim() === "") {
    next = `${block}${eol}`;
  } else {
    next = `${current}${current.endsWith(eol) ? eol : eol + eol}${block}${eol}`;
  }
  await writeFile(target, next, bom);
  return { state: "applied", file: target, bytes: Buffer.byteLength(block, "utf8") };
}

// applyInstructionResource applies one synced instructions resource to the
// agents whose roots were given. The content comes from the engine's active
// copy, which was signature-checked on sync; a kind other than instructions
// is refused rather than written into an instruction file.
export async function applyInstructionResource({ engine, resourceId, agents }) {
  const active = await engine.readActiveResource(resourceId);
  if (active.manifest?.kind !== "instructions") {
    fail("unsupported_kind", `${resourceId} is not an instructions resource`);
  }
  const text = Buffer.isBuffer(active.content)
    ? active.content.toString("utf8")
    : String(active.content ?? "");
  const applied = [];
  for (const [agent, root] of Object.entries(agents || {})) {
    if (!root) continue;
    applied.push(await applyInstruction({ agent, root, resourceId, text }));
  }
  return { resourceId, applied };
}

// removeInstructionResource takes the resource's block out of every agent
// root given. A root whose file has no such block is reported as absent.
export async function removeInstructionResource({ resourceId, agents }) {
  const removed = [];
  for (const [agent, root] of Object.entries(agents || {})) {
    if (!root) continue;
    removed.push(await removeInstruction({ agent, root, resourceId }));
  }
  return { resourceId, removed };
}

// --- skills, subagents, MCP servers and hooks --------------------------
//
// These are files of their own: a skill is a directory, a subagent is one
// markdown file, MCP servers share a config file with whatever the employee
// configured, and hooks share one too. An agent root is the agent's own
// config folder (~/.claude, ~/.codex).
//
// Every file this module writes carries a marker naming the resource that
// owns it, so a second resource with the same name is refused rather than
// overwritten, and a removal takes back only what magpie wrote. Hooks are
// the exception an agent's own file cannot carry a marker for, so the sync
// records the exact entry it wrote beside its state.

const SKILL_DIR = "skills";
const SUBAGENT_DIR = "agents"; // Claude Code only: Codex has no file magpie knows
const MCP_TOML_AGENTS = new Set(["codex"]);
const HOOK_FILES = Object.freeze({ claude: "settings.json", codex: "hooks.json" });
const HOOK_EVENTS = Object.freeze({
  claude: {
    "turn-end": "Stop",
    "after-tool": "PostToolUse",
    "before-tool": "PreToolUse",
    "prompt": "UserPromptSubmit",
    "session-start": "SessionStart",
  },
  codex: {
    "turn-end": "Stop",
    "after-tool": "PostToolUse",
    "before-tool": "PreToolUse",
    "prompt": "UserPromptSubmit",
    "session-start": "SessionStart",
  },
});
const HOOK_NATIVE = Object.freeze({
  claude: new Set(["PreToolUse", "PostToolUse", "PostToolUseFailure", "PostToolBatch", "Notification",
    "UserPromptSubmit", "UserPromptExpansion", "SessionStart", "SessionEnd", "Stop", "StopFailure",
    "SubagentStart", "SubagentStop", "PreCompact", "PostCompact", "PreModelSwitch", "PostModelSwitch",
    "PermissionRequest", "PermissionDenied", "Setup", "TeammateIdle", "TaskCreated", "TaskCompleted",
    "Elicitation", "ElicitationResult", "ConfigChange", "WorktreeCreate", "WorktreeRemove",
    "InstructionsLoaded", "CwdChanged", "FileChanged", "DirectoryAdded", "MessageDisplay"]),
  codex: new Set(["PreToolUse", "PermissionRequest", "PostToolUse", "PreCompact", "PostCompact",
    "SessionStart", "SessionEnd", "UserPromptSubmit", "SubagentStart", "SubagentStop", "Stop", "Interrupt"]),
});
const HOOK_TOOLS = Object.freeze({
  claude: { shell: "Bash", edit: "Edit|Write|MultiEdit" },
  codex: { shell: "Bash", edit: "apply_patch" },
});
const HOOK_TOOL_EVENTS = new Set(["after-tool", "before-tool"]);
const AGENT_NAME = /^[a-z0-9][a-z0-9-]{0,63}$/;
const MAX_RESOURCE_BYTES = 1024 * 1024;
const MAX_HOOK_COMMAND = 4000;
const MCP_MARKER = "x-magpie-resource";

function managedNote(resourceId) {
  return `<!-- magpie:managed:resource ${resourceId} -->`;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function resourceText(content) {
  const text = Buffer.isBuffer(content) ? content.toString("utf8") : String(content ?? "");
  if (Buffer.byteLength(text, "utf8") > MAX_RESOURCE_BYTES) {
    fail("invalid_resource_content", "The resource content is too large");
  }
  return text;
}

// A skill or subagent names itself in its frontmatter. Without one, the
// resource id is used in a form an agent accepts as a name.
export function resourceName(resourceId, text) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(text);
  const line = match ? match[1].split(/\r?\n/).find((entry) => /^name\s*:/.test(entry)) : "";
  const declared = line ? line.replace(/^name\s*:\s*/, "").trim().replace(/^["']|["']$/g, "") : "";
  const name = declared || String(resourceId).toLowerCase()
    .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
  if (!AGENT_NAME.test(name)) {
    fail("invalid_resource_name", `The resource name ${JSON.stringify(name)} is not usable as an agent file name`);
  }
  return name;
}

async function ensureAgentRoot(root) {
  if (!root) fail("invalid_root", "The agent root is required");
  const stat = await lstatOrNull(root);
  if (!stat) {
    await fs.mkdir(root, { recursive: true, mode: 0o700 });
    return;
  }
  if (stat.isSymbolicLink()) fail("path_symlink", "The agent root must not be a symbolic link");
  if (!stat.isDirectory()) fail("invalid_agent_file", "The agent root is not a directory");
}

// ensureRealDirectory walks the directory it is about to write into: a
// symbolic link anywhere between the agent root and the target is refused.
async function ensureRealDirectory(root, dir) {
  const relative = path.relative(root, dir);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    fail("path_traversal", "The agent path escapes the agent root");
  }
  await ensureAgentRoot(root);
  let current = root;
  for (const segment of relative.split(path.sep)) {
    current = path.join(current, segment);
    const stat = await lstatOrNull(current);
    if (!stat) {
      await fs.mkdir(current, { mode: 0o700 });
      continue;
    }
    if (stat.isSymbolicLink()) fail("path_symlink", "The agent directory must not be a symbolic link");
    if (!stat.isDirectory()) fail("invalid_agent_file", "The agent path is not a directory");
  }
}

async function writeManagedFile(target, text, resourceId) {
  const { text: current, bom } = await readFile(target);
  if (current.trim() !== "" && !current.includes(managedNote(resourceId))) {
    fail("agent_config_conflict", "A file of that name is already there, and magpie did not write it");
  }
  const body = text.replace(/\s+$/, "");
  await writeFile(target, `${body}\n\n${managedNote(resourceId)}\n`, bom);
}

// applySkill writes a skill as <root>/skills/<name>/SKILL.md; the delivered
// content is the skill's own file, and a later delivery replaces it.
export async function applySkill({ agent, root, resourceId, content }) {
  if (!["claude", "codex"].includes(agent)) return { state: "unsupported", agent };
  if (!RESOURCE_ID.test(String(resourceId || ""))) {
    fail("invalid_resource_id", "The resource id is invalid");
  }
  const text = resourceText(content);
  const name = resourceName(resourceId, text);
  const dir = path.join(root, SKILL_DIR, name);
  await ensureRealDirectory(root, dir);
  const target = path.join(dir, "SKILL.md");
  await writeManagedFile(target, text, resourceId);
  return { state: "applied", agent, name, file: target };
}

// removeSkill deletes the skill's own file and its directory when nothing
// else lives there. A file magpie did not write is left alone.
export async function removeSkill({ agent, root, resourceId, content }) {
  if (!["claude", "codex"].includes(agent)) return { state: "unsupported", agent };
  if (!root) fail("invalid_root", "The agent root is required");
  const name = resourceName(resourceId, resourceText(content));
  const dir = path.join(root, SKILL_DIR, name);
  const target = path.join(dir, "SKILL.md");
  const { text: current } = await readFile(target);
  if (!current.includes(managedNote(resourceId))) return { state: "absent", agent, name, file: target };
  await fs.unlink(target);
  try {
    await fs.rmdir(dir);
  } catch (error) {
    if (!["ENOTEMPTY", "EEXIST", "ENOENT", "EPERM"].includes(error.code)) throw error;
  }
  return { state: "removed", agent, name, file: target };
}

// A subagent is one markdown file: <root>/agents/<name>.md. Codex has no
// user-wide subagent file magpie knows, so it is Claude Code's only.
export async function applySubagent({ agent, root, resourceId, content }) {
  if (agent !== "claude") return { state: "unsupported", agent };
  if (!RESOURCE_ID.test(String(resourceId || ""))) {
    fail("invalid_resource_id", "The resource id is invalid");
  }
  const text = resourceText(content);
  const name = resourceName(resourceId, text);
  const dir = path.join(root, SUBAGENT_DIR);
  await ensureRealDirectory(root, dir);
  const target = path.join(dir, `${name}.md`);
  await writeManagedFile(target, text, resourceId);
  return { state: "applied", agent, name, file: target };
}

export async function removeSubagent({ agent, root, resourceId, content }) {
  if (agent !== "claude") return { state: "unsupported", agent };
  if (!root) fail("invalid_root", "The agent root is required");
  const name = resourceName(resourceId, resourceText(content));
  const target = path.join(root, SUBAGENT_DIR, `${name}.md`);
  const { text: current } = await readFile(target);
  if (!current.includes(managedNote(resourceId))) return { state: "absent", agent, name, file: target };
  await fs.unlink(target);
  return { state: "removed", agent, name, file: target };
}

// mcpServerFromContent reads the delivered JSON: {name, server} names one
// server and carries its settings; a bare object with a name is taken as
// the settings themselves.
export function mcpServerFromContent(content) {
  let value;
  try {
    value = JSON.parse(resourceText(content));
  } catch {
    fail("invalid_resource_content", "An MCP server resource must be JSON");
  }
  if (!isPlainObject(value)) fail("invalid_resource_content", "An MCP server resource must be a JSON object");
  const name = typeof value.name === "string" ? value.name.trim() : "";
  if (!AGENT_NAME.test(name)) {
    fail("invalid_resource_name", "An MCP server resource needs a name an agent accepts");
  }
  const server = isPlainObject(value.server)
    ? value.server
    : Object.fromEntries(Object.entries(value).filter(([key]) => key !== "name"));
  if (Object.keys(server).length === 0) {
    fail("invalid_resource_content", "An MCP server resource has no settings");
  }
  return { name, server };
}

function parseJsonObject(text, code, message) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail(code, message);
  }
  if (!isPlainObject(value)) fail(code, message);
  return value;
}

// Claude Code reads its user-wide servers from ~/.claude.json, beside its
// folder; an agent root that is not ~/.claude keeps a project-style
// .mcp.json inside it.
function claudeMCPFile(root) {
  return path.basename(root) === ".claude"
    ? path.join(path.dirname(root), ".claude.json")
    : path.join(root, ".mcp.json");
}

// applyMcpServer merges one server into the agent's own file, leaving the
// employee's entries and every other key alone.
export async function applyMcpServer({ agent, root, resourceId, content }) {
  if (!RESOURCE_ID.test(String(resourceId || ""))) {
    fail("invalid_resource_id", "The resource id is invalid");
  }
  const { name, server } = mcpServerFromContent(content);
  if (MCP_TOML_AGENTS.has(agent)) return applyCodexMcpServer({ root, resourceId, name, server });
  if (agent !== "claude") return { state: "unsupported", agent };
  await ensureAgentRoot(root);
  const target = claudeMCPFile(root);
  const { text: current, bom } = await readFile(target);
  const parsed = current.trim() === ""
    ? {}
    : parseJsonObject(current, "agent_config_malformed", "The agent's MCP file is not a JSON object");
  const servers = parsed.mcpServers === undefined ? {} : parsed.mcpServers;
  if (!isPlainObject(servers)) {
    fail("agent_config_malformed", "The agent's MCP server list is not an object");
  }
  const existing = servers[name];
  if (existing !== undefined
      && (!isPlainObject(existing) || existing[MCP_MARKER] !== resourceId)) {
    fail("agent_config_conflict", `An MCP server named ${name} is already configured`);
  }
  servers[name] = { ...server, [MCP_MARKER]: resourceId };
  parsed.mcpServers = servers;
  await writeFile(target, `${JSON.stringify(parsed, null, 2)}\n`, bom);
  return { state: "applied", agent, name, file: target };
}

export async function removeMcpServer({ agent, root, resourceId }) {
  if (!root) fail("invalid_root", "The agent root is required");
  if (MCP_TOML_AGENTS.has(agent)) return removeCodexMcpServer({ root, resourceId });
  if (agent !== "claude") return { state: "unsupported", agent };
  const target = claudeMCPFile(root);
  const { text: current, bom } = await readFile(target);
  if (current.trim() === "") return { state: "absent", agent, file: target };
  const parsed = parseJsonObject(current, "agent_config_malformed", "The agent's MCP file is not a JSON object");
  const servers = parsed.mcpServers;
  if (!isPlainObject(servers)) return { state: "absent", agent, file: target };
  let removed = 0;
  for (const [name, server] of Object.entries(servers)) {
    if (isPlainObject(server) && server[MCP_MARKER] === resourceId) {
      delete servers[name];
      removed += 1;
    }
  }
  if (removed === 0) return { state: "absent", agent, file: target };
  await writeFile(target, `${JSON.stringify(parsed, null, 2)}\n`, bom);
  return { state: "removed", agent, removed, file: target };
}

// --- Codex's config.toml ------------------------------------------------
//
// Codex keeps its MCP servers as [mcp_servers.<name>] tables. Each one
// magpie writes sits between markers naming its resource, so a removal
// takes back that block and nothing else. Only keys Codex documents are
// written; anything else refuses the resource.

const CODEX_MCP_KEYS = new Map([
  ["command", "string"],
  ["args", "strings"],
  ["env", "table"],
  ["env_vars", "strings"],
  ["url", "string"],
  ["headers", "table"],
  ["startup_timeout_sec", "number"],
  ["tool_timeout_sec", "number"],
]);

function tomlString(value) {
  let output = "\"";
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
        output += code < 0x20 || code === 0x7f ? `\\u${code.toString(16).padStart(4, "0")}` : character;
    }
  }
  return `${output}"`;
}

function tomlTable(value) {
  if (!isPlainObject(value)) {
    fail("invalid_resource_content", "An MCP server's env or headers must be an object");
  }
  const entries = Object.entries(value);
  for (const [key, item] of entries) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || typeof item !== "string") {
      fail("invalid_resource_content", "An MCP server's env or headers must hold string values with plain names");
    }
  }
  return `{ ${entries.map(([key, item]) => `${key} = ${tomlString(item)}`).join(", ")} }`;
}

function codexMCPBlock(resourceId, name, server) {
  const lines = [
    `# >>> magpie-managed MCP server resource ${resourceId}`,
    `[mcp_servers.${name}]`,
  ];
  for (const [key, value] of Object.entries(server)) {
    const kind = CODEX_MCP_KEYS.get(key);
    if (!kind) fail("invalid_resource_content", `An MCP server setting ${key} is not supported for Codex`);
    if (kind === "string") {
      if (typeof value !== "string") fail("invalid_resource_content", `An MCP server's ${key} must be a string`);
      lines.push(`${key} = ${tomlString(value)}`);
    } else if (kind === "strings") {
      if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
        fail("invalid_resource_content", `An MCP server's ${key} must be a list of strings`);
      }
      lines.push(`${key} = [${value.map(tomlString).join(", ")}]`);
    } else if (kind === "table") {
      lines.push(`${key} = ${tomlTable(value)}`);
    } else {
      if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
        fail("invalid_resource_content", `An MCP server's ${key} must be a number`);
      }
      lines.push(`${key} = ${value}`);
    }
  }
  lines.push(`# <<< magpie-managed MCP server resource ${resourceId}`);
  return lines.join("\n");
}

function codexMCPMarkers(resourceId) {
  return {
    begin: `# >>> magpie-managed MCP server resource ${resourceId}`,
    end: `# <<< magpie-managed MCP server resource ${resourceId}`,
  };
}

function locateBlock(text, markers) {
  const from = text.indexOf(markers.begin);
  const to = text.indexOf(markers.end, from);
  if (from < 0 || to < 0) fail("agent_config_malformed", "The managed MCP block is damaged");
  return { from, to: to + markers.end.length };
}

async function applyCodexMcpServer({ root, resourceId, name, server }) {
  await ensureAgentRoot(root);
  const target = path.join(root, "config.toml");
  const { text: current, bom } = await readFile(target);
  const markers = codexMCPMarkers(resourceId);
  if (current.includes(markers.begin) !== current.includes(markers.end)) {
    fail("agent_config_malformed", "The managed MCP block for this resource is damaged");
  }
  if (current.includes(markers.begin)) {
    const { from, to } = locateBlock(current, markers);
    const next = current.slice(0, from) + codexMCPBlock(resourceId, name, server) + current.slice(to);
    await writeFile(target, next, bom);
    return { state: "applied", agent: "codex", name, file: target };
  }
  if (new RegExp(`^\\s*\\[mcp_servers\\.${name}\\]\\s*$`, "m").test(current)) {
    fail("agent_config_conflict", `An MCP server named ${name} is already configured`);
  }
  const eol = current.includes("\r\n") ? "\r\n" : "\n";
  const block = codexMCPBlock(resourceId, name, server).replace(/\n/g, eol);
  const next = current.trim() === ""
    ? `${block}${eol}`
    : `${current}${current.endsWith(eol) ? eol : eol + eol}${block}${eol}`;
  await writeFile(target, next, bom);
  return { state: "applied", agent: "codex", name, file: target };
}

async function removeCodexMcpServer({ root, resourceId }) {
  const target = path.join(root, "config.toml");
  const { text: current, bom } = await readFile(target);
  const markers = codexMCPMarkers(resourceId);
  if (!current.includes(markers.begin) && !current.includes(markers.end)) {
    return { state: "absent", agent: "codex", file: target };
  }
  if (current.includes(markers.begin) !== current.includes(markers.end)) {
    fail("agent_config_malformed", "The managed MCP block for this resource is damaged");
  }
  const { from, to } = locateBlock(current, markers);
  let next = current.slice(0, from) + current.slice(to);
  next = next.replace(/\n{3,}/g, "\n\n").replace(/^\n+/, "");
  await writeFile(target, next, bom);
  return { state: "removed", agent: "codex", file: target };
}

// --- hooks --------------------------------------------------------------
//
// A hook resource names an event, a command and optionally a matcher:
//   {"event":"turn-end","command":"notify-send done","timeout":10}
// "turn-end", "after-tool", "before-tool", "prompt" and "session-start"
// are the same moment in each agent under its own name; "claude:Stop" or
// "codex:PermissionRequest" is one agent's own event. The command runs on
// the employee's machine, so the enterprise must have approved the
// resource before it is published; the sync only writes what it received.

const PORTABLE_HOOKS = new Set(Object.keys(HOOK_EVENTS.claude));

export function hookFromContent(content) {
  let value;
  try {
    value = JSON.parse(resourceText(content));
  } catch {
    fail("invalid_resource_content", "A hook resource must be JSON");
  }
  if (!isPlainObject(value)) fail("invalid_resource_content", "A hook resource must be a JSON object");
  const event = typeof value.event === "string" ? value.event.trim() : "";
  const command = typeof value.command === "string" ? value.command.trim() : "";
  const matcher = typeof value.matcher === "string" ? value.matcher.trim() : "";
  const timeout = value.timeout === undefined ? 0 : value.timeout;
  if (!event) fail("invalid_resource_content", "A hook resource needs an event");
  if (!command || command.length > MAX_HOOK_COMMAND || command.includes("\u0000")) {
    fail("invalid_resource_content", "A hook resource needs a command of at most 4000 characters");
  }
  if (matcher.length > 200 || matcher.includes("\u0000")) {
    fail("invalid_resource_content", "A hook matcher is invalid");
  }
  if (!Number.isInteger(timeout) || timeout < 0 || timeout > 3600) {
    fail("invalid_resource_content", "A hook timeout is 0 to 3600 seconds");
  }
  return { event, command, matcher, timeout };
}

// hookEventFor says which of the agent's own events a hook lands under, or
// null when the hook is another agent's.
function hookEventFor(agent, hook) {
  if (hook.event.includes(":")) {
    const [only, native] = hook.event.split(":", 2);
    if (only !== agent) return null;
    if (!HOOK_NATIVE[agent]?.has(native)) {
      fail("invalid_resource_content", `${agent} has no hook event called ${native}`);
    }
    return { native, matcher: hook.matcher };
  }
  if (!PORTABLE_HOOKS.has(hook.event)) {
    fail("invalid_resource_content", `${hook.event} is not a portable hook event`);
  }
  const native = HOOK_EVENTS[agent][hook.event];
  let matcher = "";
  if (HOOK_TOOL_EVENTS.has(hook.event)) {
    if (!hook.matcher) fail("invalid_resource_content", "A tool hook needs a matcher: shell or edit");
    matcher = HOOK_TOOLS[agent][hook.matcher];
    if (!matcher) fail("invalid_resource_content", "A tool hook matches shell or edit");
  }
  return { native, matcher };
}

function hookEntry(hook, matcher) {
  return {
    ...(matcher ? { matcher } : {}),
    hooks: [{
      type: "command",
      command: hook.command,
      ...(hook.timeout ? { timeout: hook.timeout } : {}),
    }],
  };
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

// applyHook adds the hook to the agent's file and answers the exact entry
// it wrote, so the sync can take back that entry and no other.
export async function applyHook({ agent, root, resourceId, content, prior }) {
  if (!HOOK_FILES[agent]) return { state: "unsupported", agent };
  if (!RESOURCE_ID.test(String(resourceId || ""))) {
    fail("invalid_resource_id", "The resource id is invalid");
  }
  const hook = hookFromContent(content);
  const event = hookEventFor(agent, hook);
  if (!event) return { state: "skipped", agent };
  await ensureAgentRoot(root);
  const target = path.join(root, HOOK_FILES[agent]);
  const { text: current, bom } = await readFile(target);
  const parsed = current.trim() === ""
    ? {}
    : parseJsonObject(current, "agent_config_malformed", "The agent's hook file is not a JSON object");
  const hooks = parsed.hooks === undefined ? {} : parsed.hooks;
  if (!isPlainObject(hooks)) fail("agent_config_malformed", "The agent's hooks are not an object");
  const list = hooks[event.native] === undefined ? [] : hooks[event.native];
  if (!Array.isArray(list)) fail("agent_config_malformed", `The agent's ${event.native} hooks are not a list`);
  const entry = hookEntry(hook, event.matcher);
  if (prior) {
    // Take the entry the last delivery wrote out first, under whichever
    // event it was then; an entry the employee changed is left alone.
    const previous = hooks[prior.event];
    if (Array.isArray(previous)) {
      hooks[prior.event] = previous.filter((item) => !sameJson(item, prior.entry));
    }
  } else if (list.some((item) => sameJson(item, entry))) {
    fail("agent_config_conflict", "That hook is already configured");
  }
  const kept = Array.isArray(hooks[event.native]) ? hooks[event.native] : [];
  hooks[event.native] = [...kept, entry];
  parsed.hooks = hooks;
  await writeFile(target, `${JSON.stringify(parsed, null, 2)}\n`, bom);
  return { state: "applied", agent, file: target, event: event.native, entry };
}

// removeHook takes back the entry the sync recorded. An entry the employee
// changed is theirs now and stays.
export async function removeHook({ agent, root, prior }) {
  if (!HOOK_FILES[agent] || !prior) return { state: "absent", agent };
  if (!root) return { state: "absent", agent };
  const target = path.join(root, HOOK_FILES[agent]);
  const { text: current, bom } = await readFile(target);
  if (current.trim() === "") return { state: "absent", agent };
  const parsed = parseJsonObject(current, "agent_config_malformed", "The agent's hook file is not a JSON object");
  const list = parsed.hooks?.[prior.event];
  if (!Array.isArray(list)) return { state: "absent", agent };
  const next = list.filter((item) => !sameJson(item, prior.entry));
  if (next.length === list.length) return { state: "absent", agent };
  parsed.hooks[prior.event] = next;
  await writeFile(target, `${JSON.stringify(parsed, null, 2)}\n`, bom);
  return { state: "removed", agent };
}

// removeInstruction takes the block back out. A file left empty stays, so
// nothing the employee opened disappears without them.
export async function removeInstruction({ agent, root, resourceId }) {
  const file = agentFile(agent);
  if (!RESOURCE_ID.test(String(resourceId || ""))) {
    fail("invalid_resource_id", "The resource id is invalid");
  }
  if (!root) fail("invalid_root", "The agent root is required");
  const target = path.join(root, file);
  const { text: current, bom } = await readFile(target);
  assertMarkersWhole(current);
  const existing = existingBlock(current, resourceId);
  if (!existing) return { state: "absent", file: target };
  let next = current.slice(0, existing.from) + current.slice(existing.to);
  next = next.replace(/\n{3,}/g, "\n\n").replace(/^\n+/, "");
  await writeFile(target, next, bom);
  return { state: "removed", file: target };
}
