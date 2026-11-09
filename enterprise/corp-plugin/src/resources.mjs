// The resource library the corporation hands out: shared instructions, MCP
// servers and skills.
//
// It lands where magpie keeps them, not in files of magpie's own making:
// instructions through `magpie library instructions set`, MCP servers
// through `magpie library mcp add`, skills as folders under
// `<config>/library/skills/`, and one `magpie library sync` at the end to
// write them into each agent's own files.
//
// Only what this plugin added is ever taken away: the applied list is
// kept here, and a name nobody applied is never removed.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";

const NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const SKILL_FILE = "SKILL.md";

function cleanName(value) {
  const name = String(value || "").trim();
  return NAME.test(name) ? name : "";
}

function agentsOf(value) {
  const list = Array.isArray(value) ? value : [];
  const ids = list.map((v) => String(v || "").trim()).filter(Boolean);
  return ids.length ? ids.join(",") : "none";
}

// runMagpie runs the CLI with a fixed argv array, never a shell: a name
// from the server can't turn into another command. Its output goes to a
// file rather than a pipe, so a restricted environment that refuses a
// child's pipes still runs it, and a child that writes a lot can't block
// on a full pipe.
export function runMagpie(bin, args, { configDir = "", timeoutMs = 60000 } = {}) {
  return new Promise((resolve) => {
    let child;
    let fd = -1;
    let capture = "";
    try {
      capture = path.join(os.tmpdir(), `magpie-corp-${process.pid}-${++runs}.log`);
      fd = fs.openSync(capture, "w");
    } catch {
      fd = -1;
    }
    try {
      child = spawn(bin, args, {
        stdio: ["ignore", fd >= 0 ? fd : "ignore", fd >= 0 ? fd : "ignore"],
        shell: false,
        env: { ...process.env, ...(configDir ? { MAGPIE_CONFIG_DIR: configDir } : {}) },
      });
    } catch (error) {
      if (fd >= 0) closeQuietly(fd);
      resolve({ ok: false, code: "magpie_unavailable", message: String(error?.message || error) });
      return;
    }
    const done = (result) => {
      if (fd >= 0) closeQuietly(fd);
      resolve(result);
    };
    const timer = setTimeout(() => {
      try {
        child.kill();
      } catch {
        // it is already gone
      }
      done({ ok: false, code: "magpie_timeout", message: `${bin} ${args.join(" ")} didn't finish in time` });
    }, timeoutMs);
    child.on("error", (error) => {
      clearTimeout(timer);
      done({ ok: false, code: "magpie_unavailable", message: String(error?.message || error) });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      done({
        ok: code === 0,
        code: code === 0 ? "" : `magpie_exit_${code}`,
        message: code === 0 ? "" : lastLines(capture, 4),
      });
    });
  });
}

// runs counts the capture files of this process.
let runs = 0;

// lastLines is the end of a capture file, where a CLI says what went wrong.
function lastLines(file, n) {
  if (!file) return "";
  try {
    const text = fs.readFileSync(file, "utf8").trim();
    fs.unlinkSync(file);
    return text.split("\n").slice(-n).join(" ").slice(0, 500);
  } catch {
    return "";
  }
}

function closeQuietly(fd) {
  try {
    fs.closeSync(fd);
  } catch {
    // an fd already closed is fine
  }
}

function writeFileIn(dir, relative, content) {
  const full = path.join(dir, relative);
  const root = path.resolve(dir);
  if (!path.resolve(full).startsWith(root + path.sep)) return false;
  fs.mkdirSync(path.dirname(full), { recursive: true, mode: 0o700 });
  fs.writeFileSync(full, String(content ?? ""), { mode: 0o600 });
  return true;
}

export function libraryDir(configDir) {
  return configDir ? path.join(configDir, "library") : "";
}

// applyResources writes the bundle's resources and answers what was applied
// and what failed. Nothing is applied when magpie's config folder is
// unknown: guessing it would write into someone else's library.
export async function applyResources(bundle, { configDir, magpieBin, dir = "", applied = {}, run = runMagpie, log = () => {} }) {
  if (!configDir) {
    return { applied, errors: [{ code: "config_dir_unknown", message: "magpie didn't say where its files are (MAGPIE_CONFIG_DIR)" }] };
  }
  const errors = [];
  const next = {
    instructions: [],
    mcp: [],
    skills: [],
  };
  const call = (args) => run(magpieBin, args, { configDir });

  // --- instructions -----------------------------------------------------
  const instructions = (Array.isArray(bundle?.instructions) ? bundle.instructions : [])
    .filter((item) => item && item.enabled !== false && typeof item.content === "string");
  const shared = instructions.filter((item) => item.shared === true || item.id === "shared");
  if (shared.length) {
    const body = shared.map((item) => item.content).join("\n\n");
    const file = path.join(configDir, "corp-instructions.md");
    try {
      fs.mkdirSync(configDir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(file, body, { mode: 0o600 });
      const result = await call(["library", "instructions", "set", file]);
      if (result.ok) {
        next.instructions.push("shared");
        const agents = agentsOf(shared[0].agents);
        if (agents !== "none") await call(["library", "instructions", "agents", agents]);
      } else {
        errors.push({ code: result.code, message: `instructions: ${result.message}` });
      }
    } catch (error) {
      errors.push({ code: "instructions_write_failed", message: String(error?.message || error) });
    }
  }

  // --- MCP servers ------------------------------------------------------
  const servers = (Array.isArray(bundle?.mcp) ? bundle.mcp : [])
    .filter((item) => item && item.enabled !== false)
    .map((item) => ({ ...item, name: cleanName(item.name) }))
    .filter((item) => item.name);
  for (const server of servers) {
    // a server applied before is replaced whole, so adding never says
    // "already there" and a changed address actually changes
    await call(["library", "mcp", "rm", server.name]);
    const spec = server.transport === "stdio"
      ? [String(server.command || ""), ...(Array.isArray(server.args) ? server.args.map(String) : [])]
      : [String(server.url || "")];
    if (!spec[0]) {
      errors.push({ code: "mcp_incomplete", message: `${server.name}: no url or command` });
      continue;
    }
    const result = await call(["library", "mcp", "add", server.name, ...spec, `agents=${agentsOf(server.agents)}`]);
    if (result.ok) next.mcp.push(server.name);
    else errors.push({ code: result.code, message: `${server.name}: ${result.message}` });
  }
  // servers the corporation withdrew, and only those this plugin added
  for (const name of Array.isArray(applied.mcp) ? applied.mcp : []) {
    if (!next.mcp.includes(name)) await call(["library", "mcp", "rm", name]);
  }

  // --- skills -----------------------------------------------------------
  // A skill is installed from a folder of its own through the CLI, which
  // is what the Library page does; the library keeps the copy and writes
  // it into each agent.
  //
  // The bundle's files are staged under the plugin's own state folder and
  // kept there, not in a temporary folder that is swept away: a skill
  // installed from a folder is a link to that folder, so a staging folder
  // taken away leaves the library's copy and every agent's link pointing
  // at nothing.
  const stagingRoot = path.join(dir, "skills");
  const skills = (Array.isArray(bundle?.skills) ? bundle.skills : [])
    .filter((item) => item && item.enabled !== false)
    .map((item) => ({ ...item, name: cleanName(item.name) }))
    .filter((item) => item.name);
  for (const skill of skills) {
    const files = Array.isArray(skill.files) ? skill.files : [];
    if (!files.some((file) => String(file?.path || "") === SKILL_FILE)) {
      errors.push({ code: "skill_incomplete", message: `${skill.name}: no ${SKILL_FILE}` });
      continue;
    }
    // stage the bundle's files in a folder of its own, the shape a skill
    // is installed from
    const stage = path.join(stagingRoot, skill.name);
    try {
      fs.rmSync(stage, { recursive: true, force: true });
      fs.mkdirSync(stage, { recursive: true, mode: 0o700 });
      for (const file of files) {
        const relative = String(file?.path || "").replace(/\\/g, "/");
        if (!relative || relative.startsWith("/") || relative.includes("..")) continue;
        writeFileIn(stage, relative, file.content);
      }
    } catch (error) {
      errors.push({ code: "skill_write_failed", message: `${skill.name}: ${String(error?.message || error)}` });
      continue;
    }
    const given = agentsOf(skill.agents);
    const install = () => call(["library", "skill", "from", stage, ...(given === "none" ? [] : [`agents=${given}`])]);
    let result = await install();
    if (!result.ok) {
      // A skill of the same name already here, from a pass before this
      // one or from its own source: the bundle's is the truth now, so the
      // library's copy is replaced rather than kept beside it.
      await call(["library", "skill", "rm", skill.name]);
      result = await install();
      if (!result.ok) {
        errors.push({ code: result.code, message: `${skill.name}: ${result.message}` });
        continue;
      }
    }
    next.skills.push(skill.name);
  }
  // a staged copy of a skill the bundle no longer carries goes with it
  try {
    for (const name of fs.readdirSync(stagingRoot)) {
      if (!next.skills.includes(name)) fs.rmSync(path.join(stagingRoot, name), { recursive: true, force: true });
    }
  } catch {
    // no staging folder yet is nothing to clean
  }
  for (const name of Array.isArray(applied.skills) ? applied.skills : []) {
    if (!next.skills.includes(name)) {
      // the library is the CLI's to change, so a withdrawn skill goes
      // through the same door
      await call(["library", "skill", "rm", name]);
    }
  }

  // one sync at the end, so every agent gets what changed in one pass
  if (next.mcp.length || next.skills.length || next.instructions.length) {
    const result = await call(["library", "sync"]);
    if (!result.ok) errors.push({ code: result.code, message: `sync: ${result.message}` });
    else log("library synced");
  }

  return { applied: next, errors };
}
