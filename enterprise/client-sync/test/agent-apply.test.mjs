import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  applyInstruction,
  applyInstructionResource,
  removeInstruction,
  removeInstructionResource,
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
