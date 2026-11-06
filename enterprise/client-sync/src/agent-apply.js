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
