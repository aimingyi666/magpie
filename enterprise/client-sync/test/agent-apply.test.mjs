import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  applyHook,
  applyInstruction,
  applyInstructionResource,
  applyMcpServer,
  applySkill,
  applySubagent,
  removeHook,
  removeInstruction,
  removeInstructionResource,
  removeMcpServer,
  removeSkill,
  removeSubagent,
  resourceName,
} from "../src/agent-apply.js";

const RES = "res_aaaaaaaaaaaaaaaa";
const OTHER = "res_bbbbbbbbbbbbbbbb";

async function root(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-agent-apply-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  return dir;
}

async function read(dir, file = "CLAUDE.md") {
  return fs.readFile(path.join(dir, file), "utf8");
}

test("an instruction becomes a managed block in Claude Code's file", async (t) => {
  const dir = await root(t);
  const result = await applyInstruction({
    agent: "claude", root: dir, resourceId: RES, text: "Always answer in Chinese.",
  });
  assert.equal(result.state, "applied");
  const text = await read(dir);
  assert.match(text, /<!-- magpie:managed:begin res_aaaaaaaaaaaaaaaa -->/);
  assert.match(text, /Always answer in Chinese\./);
  assert.match(text, /<!-- magpie:managed:end res_aaaaaaaaaaaaaaaa -->/);
});

test("Codex reads its instructions from AGENTS.md", async (t) => {
  const dir = await root(t);
  await applyInstruction({ agent: "codex", root: dir, resourceId: RES, text: "Be brief." });
  assert.match(await read(dir, "AGENTS.md"), /Be brief\./);
});

test("a second apply replaces the block and leaves the employee's text", async (t) => {
  const dir = await root(t);
  await fs.writeFile(path.join(dir, "CLAUDE.md"), "my own line\n", "utf8");
  await applyInstruction({ agent: "claude", root: dir, resourceId: RES, text: "version one" });
  await applyInstruction({ agent: "claude", root: dir, resourceId: RES, text: "version two" });
  const text = await read(dir);
  assert.match(text, /my own line/);
  assert.match(text, /version two/);
  assert.doesNotMatch(text, /version one/);
  assert.equal((text.match(/magpie:managed:begin res_aaaaaaaaaaaaaaaa/g) || []).length, 1);
});

test("two resources each keep their own block", async (t) => {
  const dir = await root(t);
  await applyInstruction({ agent: "claude", root: dir, resourceId: RES, text: "first" });
  await applyInstruction({ agent: "claude", root: dir, resourceId: OTHER, text: "second" });
  const text = await read(dir);
  assert.match(text, /first/);
  assert.match(text, /second/);
  await removeInstruction({ agent: "claude", root: dir, resourceId: RES });
  const after = await read(dir);
  assert.doesNotMatch(after, /first/);
  assert.match(after, /second/);
});

test("a removal leaves the employee's own text and an absent block is a no-op", async (t) => {
  const dir = await root(t);
  await fs.writeFile(path.join(dir, "CLAUDE.md"), "before\n", "utf8");
  await applyInstruction({ agent: "claude", root: dir, resourceId: RES, text: "enterprise" });
  await applyInstruction({ agent: "claude", root: dir, resourceId: OTHER, text: "other" });
  await removeInstruction({ agent: "claude", root: dir, resourceId: RES });
  await removeInstruction({ agent: "claude", root: dir, resourceId: OTHER });
  const text = await read(dir);
  assert.match(text, /before/);
  assert.doesNotMatch(text, /enterprise|other/);
  assert.equal((await removeInstruction({
    agent: "claude", root: dir, resourceId: RES,
  })).state, "absent");
});

test("the file's BOM and CRLF line endings survive", async (t) => {
  const dir = await root(t);
  const bom = Buffer.from([0xef, 0xbb, 0xbf]);
  await fs.writeFile(
    path.join(dir, "CLAUDE.md"),
    Buffer.concat([bom, Buffer.from("old\r\nlines\r\n", "utf8")]),
  );
  await applyInstruction({ agent: "claude", root: dir, resourceId: RES, text: "one\ntwo" });
  const raw = await fs.readFile(path.join(dir, "CLAUDE.md"));
  assert.deepEqual([...raw.subarray(0, 3)], [0xef, 0xbb, 0xbf]);
  const text = raw.subarray(3).toString("utf8");
  assert.match(text, /old\r\nlines/);
  assert.match(text, /one\r\ntwo/);
});

test("a half-managed file is refused instead of being rewritten", async (t) => {
  const dir = await root(t);
  const damaged = "mine\n<!-- magpie:managed:begin res_aaaaaaaaaaaaaaaa -->\ntext\n";
  await fs.writeFile(path.join(dir, "CLAUDE.md"), damaged, "utf8");
  await assert.rejects(
    () => applyInstruction({ agent: "claude", root: dir, resourceId: RES, text: "new" }),
    (error) => error.code === "agent_config_malformed",
  );
  assert.equal(await read(dir), damaged);
});

test("an unknown agent and a bad resource id are refused", async (t) => {
  const dir = await root(t);
  await assert.rejects(
    () => applyInstruction({ agent: "nobody", root: dir, resourceId: RES, text: "x" }),
    (error) => error.code === "unknown_agent",
  );
  await assert.rejects(
    () => applyInstruction({ agent: "claude", root: dir, resourceId: "not a res", text: "x" }),
    (error) => error.code === "invalid_resource_id",
  );
});

test("a symbolic-link file is refused", async (t) => {
  const dir = await root(t);
  const real = path.join(dir, "real.md");
  await fs.writeFile(real, "x\n", "utf8");
  try {
    await fs.symlink(real, path.join(dir, "CLAUDE.md"));
  } catch (error) {
    if (error.code === "EPERM" || error.code === "EACCES") {
      t.skip("this Windows session cannot create a symbolic link");
      return;
    }
    throw error;
  }
  await assert.rejects(
    () => applyInstruction({ agent: "claude", root: dir, resourceId: RES, text: "x" }),
    (error) => error.code === "path_symlink",
  );
});

test("a synced instructions resource reaches each agent's own file", async (t) => {
  const dir = await root(t);
  const claudeRoot = path.join(dir, "claude");
  const codexRoot = path.join(dir, "codex");
  const engine = {
    async readActiveResource(resourceId) {
      assert.equal(resourceId, RES);
      return {
        manifest: { kind: "instructions", resourceId },
        content: Buffer.from("Answer in Chinese.", "utf8"),
      };
    },
  };
  const result = await applyInstructionResource({
    engine,
    resourceId: RES,
    agents: { claude: claudeRoot, codex: codexRoot },
  });
  assert.equal(result.applied.length, 2);
  assert.match(await fs.readFile(path.join(claudeRoot, "CLAUDE.md"), "utf8"), /Answer in Chinese\./);
  assert.match(await fs.readFile(path.join(codexRoot, "AGENTS.md"), "utf8"), /Answer in Chinese\./);
});

test("a resource that is not instructions is refused, and removal reaches every root", async (t) => {
  const dir = await root(t);
  const claudeRoot = path.join(dir, "claude");
  const wrong = {
    async readActiveResource() {
      return { manifest: { kind: "skill" }, content: Buffer.from("x") };
    },
  };
  await assert.rejects(
    () => applyInstructionResource({ engine: wrong, resourceId: RES, agents: { claude: claudeRoot } }),
    (error) => error.code === "unsupported_kind",
  );
  await fs.rm(claudeRoot, { recursive: true, force: true });

  const engine = {
    async readActiveResource() {
      return { manifest: { kind: "instructions" }, content: Buffer.from("text") };
    },
  };
  await applyInstructionResource({ engine, resourceId: RES, agents: { claude: claudeRoot } });
  const removed = await removeInstructionResource({
    resourceId: RES, agents: { claude: claudeRoot },
  });
  assert.equal(removed.removed[0].state, "removed");
  assert.doesNotMatch(await fs.readFile(path.join(claudeRoot, "CLAUDE.md"), "utf8"), /text/);
});

test("a skill lands in .claude/skills/<name>/SKILL.md", async (t) => {
  const dir = await root(t);
  const content = Buffer.from(
    "---\nname: release-check\ndescription: Check a release\n---\n\nRun the checklist.\n",
    "utf8",
  );
  const result = await applySkill({ agent: "claude", root: dir, resourceId: RES, content });
  assert.equal(result.state, "applied");
  assert.equal(result.name, "release-check");
  const file = path.join(dir, "skills", "release-check", "SKILL.md");
  const text = await fs.readFile(file, "utf8");
  assert.match(text, /Run the checklist\./);
  assert.match(text, /magpie:managed:resource res_aaaaaaaaaaaaaaaa/);

  // A second delivery replaces the file, marker and all.
  await applySkill({
    agent: "claude", root: dir, resourceId: RES,
    content: Buffer.from("---\nname: release-check\n---\n\nNew body.\n", "utf8"),
  });
  const replaced = await fs.readFile(file, "utf8");
  assert.match(replaced, /New body\./);
  assert.doesNotMatch(replaced, /Run the checklist\./);
  assert.equal((replaced.match(/magpie:managed:resource/g) || []).length, 1);

  const removed = await removeSkill({
    agent: "claude", root: dir, resourceId: RES, content,
  });
  assert.equal(removed.state, "removed");
  await assert.rejects(() => fs.stat(path.dirname(file)), (error) => error.code === "ENOENT");
});

test("a skill without a frontmatter name uses its resource id", async (t) => {
  const dir = await root(t);
  assert.equal(resourceName("res_aaaaaaaaaaaaaaaa", "no frontmatter"), "res-aaaaaaaaaaaaaaaa");
  const result = await applySkill({
    agent: "claude", root: dir, resourceId: RES, content: Buffer.from("body\n", "utf8"),
  });
  assert.equal(result.name, "res-aaaaaaaaaaaaaaaa");
  assert.match(
    await fs.readFile(path.join(dir, "skills", result.name, "SKILL.md"), "utf8"),
    /body/,
  );
});

test("a file the enterprise did not write is never overwritten or removed", async (t) => {
  const dir = await root(t);
  const mine = path.join(dir, "skills", "release-check", "SKILL.md");
  await fs.mkdir(path.dirname(mine), { recursive: true });
  await fs.writeFile(mine, "my own skill\n", "utf8");

  await assert.rejects(
    () => applySkill({
      agent: "claude", root: dir, resourceId: RES,
      content: Buffer.from("---\nname: release-check\n---\nbody\n", "utf8"),
    }),
    (error) => error.code === "agent_config_conflict",
  );
  assert.equal(await fs.readFile(mine, "utf8"), "my own skill\n");
  const removed = await removeSkill({
    agent: "claude", root: dir, resourceId: RES,
    content: Buffer.from("---\nname: release-check\n---\nbody\n", "utf8"),
  });
  assert.equal(removed.state, "absent");
  assert.equal(await fs.readFile(mine, "utf8"), "my own skill\n");
});

test("a subagent lands in .claude/agents/<name>.md and comes back out", async (t) => {
  const dir = await root(t);
  const content = Buffer.from("---\nname: reviewer\n---\n\nReview the diff.\n", "utf8");
  const result = await applySubagent({ agent: "claude", root: dir, resourceId: RES, content });
  assert.equal(result.state, "applied");
  const file = path.join(dir, "agents", "reviewer.md");
  assert.match(await fs.readFile(file, "utf8"), /Review the diff\./);
  const removed = await removeSubagent({ agent: "claude", root: dir, resourceId: RES, content });
  assert.equal(removed.state, "removed");
  await assert.rejects(() => fs.stat(file), (error) => error.code === "ENOENT");
});

test("an MCP server merges into .mcp.json and takes only its own entry back", async (t) => {
  const dir = await root(t);
  await fs.writeFile(
    path.join(dir, ".mcp.json"),
    JSON.stringify({
      mcpServers: { mine: { command: "my-server" } },
      otherKey: true,
    }, null, 2),
    "utf8",
  );
  const content = Buffer.from(JSON.stringify({
    name: "context7",
    server: { command: "npx", args: ["-y", "@upstash/context7-mcp"] },
  }), "utf8");
  const applied = await applyMcpServer({ agent: "claude", root: dir, resourceId: RES, content });
  assert.equal(applied.state, "applied");

  const file = path.join(dir, ".mcp.json");
  const parsed = JSON.parse(await fs.readFile(file, "utf8"));
  assert.equal(parsed.otherKey, true);
  assert.equal(parsed.mcpServers.mine.command, "my-server");
  assert.deepEqual(parsed.mcpServers.context7.args, ["-y", "@upstash/context7-mcp"]);
  assert.equal(parsed.mcpServers.context7["x-magpie-resource"], RES);

  const removed = await removeMcpServer({ agent: "claude", root: dir, resourceId: RES });
  assert.equal(removed.state, "removed");
  const after = JSON.parse(await fs.readFile(file, "utf8"));
  assert.equal(after.mcpServers.context7, undefined);
  assert.equal(after.mcpServers.mine.command, "my-server");
  assert.equal(after.otherKey, true);
});

test("an MCP server name the employee already uses is a conflict", async (t) => {
  const dir = await root(t);
  await fs.writeFile(
    path.join(dir, ".mcp.json"),
    JSON.stringify({ mcpServers: { context7: { command: "mine" } } }),
    "utf8",
  );
  const content = Buffer.from(JSON.stringify({ name: "context7", command: "theirs" }), "utf8");
  await assert.rejects(
    () => applyMcpServer({ agent: "claude", root: dir, resourceId: RES, content }),
    (error) => error.code === "agent_config_conflict",
  );
  const parsed = JSON.parse(await fs.readFile(path.join(dir, ".mcp.json"), "utf8"));
  assert.equal(parsed.mcpServers.context7.command, "mine");
});

test("a broken .mcp.json is refused rather than replaced", async (t) => {
  const dir = await root(t);
  const file = path.join(dir, ".mcp.json");
  await fs.writeFile(file, "{ not json", "utf8");
  await assert.rejects(
    () => applyMcpServer({
      agent: "claude", root: dir, resourceId: RES,
      content: Buffer.from(JSON.stringify({ name: "x", command: "y" }), "utf8"),
    }),
    (error) => error.code === "agent_config_malformed",
  );
  assert.equal(await fs.readFile(file, "utf8"), "{ not json");
});

test("Codex gets a skill and an MCP server, but no subagent", async (t) => {
  const dir = await root(t);
  const skill = await applySkill({
    agent: "codex", root: dir, resourceId: RES,
    content: Buffer.from("---\nname: release-check\n---\nbody\n"),
  });
  assert.equal(skill.state, "applied");
  assert.match(await fs.readFile(path.join(dir, "skills", "release-check", "SKILL.md"), "utf8"), /body/);

  const mcp = await applyMcpServer({
    agent: "codex", root: dir, resourceId: RES,
    content: Buffer.from(JSON.stringify({
      name: "context7", command: "npx", args: ["-y", "context7-mcp"],
      env: { MODE: "ro" }, startup_timeout_sec: 20,
    })),
  });
  assert.equal(mcp.state, "applied");
  const toml = await fs.readFile(path.join(dir, "config.toml"), "utf8");
  assert.match(toml, /^\[mcp_servers\.context7\]$/m);
  assert.match(toml, /command = "npx"/);
  assert.match(toml, /args = \["-y", "context7-mcp"\]/);
  assert.match(toml, /env = \{ MODE = "ro" \}/);
  assert.match(toml, /startup_timeout_sec = 20/);
  assert.match(toml, /magpie-managed MCP server resource res_aaaaaaaaaaaaaaaa/);

  const removed = await removeMcpServer({ agent: "codex", root: dir, resourceId: RES });
  assert.equal(removed.state, "removed");
  assert.doesNotMatch(await fs.readFile(path.join(dir, "config.toml"), "utf8"), /mcp_servers\.context7/);

  assert.equal((await applySubagent({
    agent: "codex", root: dir, resourceId: RES, content: Buffer.from("x"),
  })).state, "unsupported");
});

test("a Codex MCP server the employee already has is a conflict", async (t) => {
  const dir = await root(t);
  await fs.writeFile(path.join(dir, "config.toml"), '[mcp_servers.context7]\ncommand = "mine"\n', "utf8");
  await assert.rejects(
    () => applyMcpServer({
      agent: "codex", root: dir, resourceId: RES,
      content: Buffer.from(JSON.stringify({ name: "context7", command: "theirs" })),
    }),
    (error) => error.code === "agent_config_conflict",
  );
  const toml = await fs.readFile(path.join(dir, "config.toml"), "utf8");
  assert.match(toml, /command = "mine"/);
});

test("a hook lands in Claude Code's settings.json and comes back out", async (t) => {
  const dir = await root(t);
  const content = Buffer.from(JSON.stringify({
    event: "turn-end", command: "notify-send done", timeout: 10,
  }));
  const applied = await applyHook({ agent: "claude", root: dir, resourceId: RES, content });
  assert.equal(applied.state, "applied");
  assert.equal(applied.event, "Stop");
  const file = path.join(dir, "settings.json");
  const parsed = JSON.parse(await fs.readFile(file, "utf8"));
  assert.deepEqual(parsed.hooks.Stop, [{
    hooks: [{ type: "command", command: "notify-send done", timeout: 10 }],
  }]);

  const removed = await removeHook({
    agent: "claude", root: dir,
    prior: { event: applied.event, entry: applied.entry },
  });
  assert.equal(removed.state, "removed");
  const after = JSON.parse(await fs.readFile(file, "utf8"));
  assert.deepEqual(after.hooks.Stop, []);
});

test("a tool hook maps to each agent's own matcher", async (t) => {
  const dir = await root(t);
  const content = Buffer.from(JSON.stringify({
    event: "after-tool", matcher: "edit", command: "format",
  }));
  const claude = await applyHook({ agent: "claude", root: dir, resourceId: RES, content });
  assert.equal(claude.event, "PostToolUse");
  assert.equal(claude.entry.matcher, "Edit|Write|MultiEdit");
  const codex = await applyHook({ agent: "codex", root: dir, resourceId: RES, content });
  assert.equal(codex.event, "PostToolUse");
  assert.equal(codex.entry.matcher, "apply_patch");
  const hooks = JSON.parse(await fs.readFile(path.join(dir, "hooks.json"), "utf8"));
  assert.deepEqual(hooks.hooks.PostToolUse[0].matcher, "apply_patch");
});

test("a hook the employee changed is left alone on removal", async (t) => {
  const dir = await root(t);
  const content = Buffer.from(JSON.stringify({ event: "turn-end", command: "notify-send done" }));
  const applied = await applyHook({ agent: "claude", root: dir, resourceId: RES, content });
  const file = path.join(dir, "settings.json");
  const parsed = JSON.parse(await fs.readFile(file, "utf8"));
  parsed.hooks.Stop[0].hooks[0].command = "echo mine";
  await fs.writeFile(file, JSON.stringify(parsed), "utf8");
  const removed = await removeHook({
    agent: "claude", root: dir, prior: { event: applied.event, entry: applied.entry },
  });
  assert.equal(removed.state, "absent");
  const after = JSON.parse(await fs.readFile(file, "utf8"));
  assert.equal(after.hooks.Stop[0].hooks[0].command, "echo mine");
});

test("a hook for another agent's event goes only to that agent", async (t) => {
  const dir = await root(t);
  const content = Buffer.from(JSON.stringify({
    event: "codex:PermissionRequest", command: "log",
  }));
  const claude = await applyHook({ agent: "claude", root: dir, resourceId: RES, content });
  assert.equal(claude.state, "skipped");
  await assert.rejects(() => fs.stat(path.join(dir, "settings.json")), (error) => error.code === "ENOENT");
  const codex = await applyHook({ agent: "codex", root: dir, resourceId: RES, content });
  assert.equal(codex.event, "PermissionRequest");
});
