import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  LocalMcpError,
  buildSandboxCommand,
  verifySignedPackage,
} from "../src/index.js";
import {
  createIdentity,
  createPackage,
} from "./helpers.mjs";

function sandboxFixture(t, capabilities, networkHosts = []) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "magpie-local-mcp-sandbox-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const identity = createIdentity();
  const verified = verifySignedPackage(
    identity.publicKey,
    createPackage(identity, { permissions: { capabilities, networkHosts } }),
  );
  return {
    manifest: verified.manifest,
    packageDir: path.join(parent, "package"),
    workspaceDir: path.join(parent, "workspace"),
    tempDir: path.join(parent, "temp"),
  };
}

test("Node sandbox flags and environment follow signed capabilities", (t) => {
  const fixture = sandboxFixture(t, [
    "fs.read",
    "fs.write",
    "process.spawn",
    "worker.start",
    "native.addon",
    "native.ffi",
  ]);
  const command = buildSandboxCommand({
    ...fixture,
    interpreter: process.execPath,
    environment: { SystemRoot: process.env.SystemRoot ?? "C:\\Windows" },
  });

  assert.equal(command.command, process.execPath);
  assert.equal(command.mode, "node-permission");
  assert.ok(command.args.includes("--permission"));
  assert.ok(command.args.includes(`--allow-fs-read=${fixture.packageDir}`));
  assert.ok(command.args.includes(`--allow-fs-read=${fixture.workspaceDir}`));
  assert.ok(command.args.includes(`--allow-fs-write=${fixture.workspaceDir}`));
  assert.ok(command.args.includes(`--allow-fs-write=${fixture.tempDir}`));
  assert.ok(command.args.includes("--allow-child-process"));
  assert.ok(command.args.includes("--allow-worker"));
  assert.ok(command.args.includes("--allow-addons"));
  assert.ok(command.args.includes("--allow-ffi"));
  assert.equal(command.env.TEMP, fixture.tempDir);
  assert.equal(command.env.MAGPIE_LOCAL_MCP_PACKAGE_ID, "local-echo");
  assert.deepEqual(command.profile.capabilities, fixture.manifest.permissions.capabilities);
});

test("network, clipboard and desktop access require an external sandbox adapter", (t) => {
  const fixture = sandboxFixture(
    t,
    ["network.connect", "clipboard.read", "desktop.control"],
    ["api.corp.example"],
  );
  assert.throws(
    () => buildSandboxCommand({
      ...fixture,
      interpreter: process.execPath,
      environment: {},
    }),
    (error) => error instanceof LocalMcpError && error.code === "sandbox_unavailable",
  );

  const wrapped = buildSandboxCommand({
    ...fixture,
    interpreter: process.execPath,
    environment: {},
    sandboxAdapter: {
      wrap: ({ command, args, cwd, env, profile }) => ({
        command,
        args: ["sandbox-run", profile.packageId, "--", ...args],
        env: { ...env, EXTERNAL_SANDBOX: "1" },
        cwd,
      }),
    },
  });
  assert.equal(wrapped.mode, "external-adapter+node-permission");
  assert.equal(wrapped.args[0], "sandbox-run");
  assert.equal(wrapped.env.EXTERNAL_SANDBOX, "1");
  assert.ok(wrapped.args.includes("--allow-net"));
});

test("shell interpreters and writes without a scope are rejected", (t) => {
  const fixture = sandboxFixture(t, ["fs.write"]);
  assert.throws(
    () => buildSandboxCommand({
      ...fixture,
      workspaceDir: null,
      tempDir: null,
      interpreter: process.execPath,
      environment: {},
    }),
    (error) => error instanceof LocalMcpError && error.code === "sandbox_unavailable",
  );

  assert.throws(
    () => buildSandboxCommand({
      ...fixture,
      interpreter: path.join(path.dirname(process.execPath), "pwsh.exe"),
      environment: {},
    }),
    (error) => error instanceof LocalMcpError && error.code === "sandbox_unavailable",
  );
});
