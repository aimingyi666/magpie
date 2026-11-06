import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import { syncNow } from "../src/sync.mjs";

const MODULE = `
export class ClientSyncEngine {
  static last = null;
  constructor(options) {
    ClientSyncEngine.last = options;
  }
  async syncOnce() {
    return {
      status: "synced",
      revision: "r1",
      installed: ["res_a"],
      unchanged: [],
      skipped: [],
      drift: [],
      applied: [{ resourceId: "res_a", agent: "claude", file: "/home/me/CLAUDE.md" }],
      applyErrors: [],
    };
  }
}
export function createEnterpriseSyncTransport() {
  return {
    fetchDesiredState: async () => ({
      schemaVersion: 1, revision: "r1", generatedAt: "", resources: [],
    }),
    reportResult: async () => ({ ok: true }),
  };
}
`;

function workspace(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "magpie-plugin-sync-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const modulePath = path.join(dir, "client-sync.mjs");
  fs.writeFileSync(modulePath, MODULE, "utf8");
  return { dir, modulePath };
}

function configFor(dir, modulePath, extra = {}) {
  return {
    clientSyncModule: modulePath,
    rootDir: path.join(dir, "resources"),
    publicKeys: { "resource-2026-11": "pem" },
    keyFingerprints: {},
    clientVersion: "1.0.0",
    ...extra,
  };
}

const credential = {
  authUrl: "https://auth.example.com",
  deviceToken: "device-token",
  clientVersion: "1.0.0",
};

async function engineModule(modulePath) {
  return import(pathToFileURL(modulePath).href);
}

test("a sync hands the engine where each agent's files are", async (t) => {
  const { dir, modulePath } = workspace(t);
  const agents = { claude: path.join(dir, "home-claude") };
  const result = await syncNow({
    config: configFor(dir, modulePath, { agents }),
    credential,
  });
  assert.equal(result.status, "synced");
  assert.deepEqual(result.applied, [
    { resourceId: "res_a", agent: "claude", file: "/home/me/CLAUDE.md" },
  ]);
  assert.deepEqual(result.applyErrors, []);

  const loaded = await engineModule(modulePath);
  assert.deepEqual(loaded.ClientSyncEngine.last.agents, agents);
});

test("a sync without agent roots leaves the engine untouched", async (t) => {
  const { dir, modulePath } = workspace(t);
  const result = await syncNow({ config: configFor(dir, modulePath), credential });
  assert.equal(result.status, "synced");
  const loaded = await engineModule(modulePath);
  assert.equal("agents" in loaded.ClientSyncEngine.last, false);
});
