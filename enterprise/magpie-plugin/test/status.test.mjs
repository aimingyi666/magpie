import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  readCredential,
  readSyncConfig,
} from "../src/config.mjs";
import { readSyncState, resourceRows } from "../src/status.mjs";

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "magpie-enterprise-plugin-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function credential(email) {
  return {
    version: 1,
    authUrl: "https://auth.example.com",
    userId: "user-1",
    email,
    deviceId: "device-1",
    deviceName: "PC-1",
    clientVersion: "enterprise-1.0.0",
    deviceToken: "device-token-must-not-reach-the-page",
    providerId: "enterprise-gateway",
    gatewayUrl: "https://gateway.example.com",
  };
}

function stateRecord(overrides = {}) {
  return {
    resourceId: "res-1",
    releaseId: "rel-1",
    resourceVersion: "1.0.0",
    kind: "mcp",
    deliveryMode: "forced",
    hash: `sha256:${"a".repeat(64)}`,
    manifestDigest: `sha256:${"b".repeat(64)}`,
    signingKeyId: "resource-2026-11",
    installedAt: "2026-11-04T02:00:00.000Z",
    ...overrides,
  };
}

test("readCredential distinguishes missing, unreadable, invalid and joined", (t) => {
  const dir = tempDir(t);
  assert.deepEqual(readCredential(dir), { state: "missing", dir });

  const filePath = path.join(dir, "not-a-directory");
  fs.writeFileSync(filePath, "x");
  assert.equal(readCredential(filePath).state, "unreadable");

  const bad = path.join(dir, "bad-device.json");
  fs.writeFileSync(bad, "{");
  assert.deepEqual(readCredential(dir), { state: "invalid", dir, file: bad, reason: "json" });

  fs.writeFileSync(bad, JSON.stringify({ authUrl: "https://auth.example.com" }));
  assert.equal(readCredential(dir).reason, "fields");
  fs.rmSync(bad);

  const older = path.join(dir, "older-device.json");
  const newer = path.join(dir, "newer-device.json");
  writeJson(older, credential("older@example.com"));
  writeJson(newer, credential("newer@example.com"));
  fs.utimesSync(older, new Date("2026-11-01T00:00:00Z"), new Date("2026-11-01T00:00:00Z"));
  fs.utimesSync(newer, new Date("2026-11-02T00:00:00Z"), new Date("2026-11-02T00:00:00Z"));

  const joined = readCredential(dir);
  assert.equal(joined.state, "ok");
  assert.equal(joined.data.email, "newer@example.com");
  assert.equal(joined.data.deviceToken, "device-token-must-not-reach-the-page");
});

test("readSyncConfig validates the endpoint and pinned signing keys", (t) => {
  const dir = tempDir(t);
  assert.equal(readSyncConfig(dir).state, "missing");

  const file = path.join(dir, "enterprise-sync.json");
  fs.writeFileSync(file, "{");
  assert.equal(readSyncConfig(dir).reason, "json");

  writeJson(file, { resourceBaseUrl: "", signingKeys: {} });
  assert.equal(readSyncConfig(dir).reason, "resourceBaseUrl");

  writeJson(file, { resourceBaseUrl: "ftp://resource.example.com", signingKeys: {} });
  assert.equal(readSyncConfig(dir).reason, "resourceBaseUrl");

  writeJson(file, {
    resourceBaseUrl: "https://resource.example.com",
    signingKeys: {},
  });
  assert.equal(readSyncConfig(dir).reason, "signingKeys");

  writeJson(file, {
    resourceBaseUrl: "https://resource.example.com",
    rootDir: "./synced",
    displayNames: {
      "res-1": "研发知识库 MCP",
      "../escape": "not a resource",
      "res-2": 7,
    },
    signingKeys: {
      "resource-2026-11": {
        publicKeyPem: "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n",
        fingerprint: `sha256:${"c".repeat(64)}`,
      },
    },
  });
  const config = readSyncConfig(dir);
  assert.equal(config.state, "ok");
  assert.equal(config.rootDir, path.join(dir, "synced"));
  assert.equal(config.keyFingerprints["resource-2026-11"], `sha256:${"c".repeat(64)}`);
  assert.equal(config.maxResourceBytes, 4 * 1024 * 1024);
  assert.deepEqual(config.displayNames, { "res-1": "研发知识库 MCP" });
});

test("readSyncConfig reads where each agent's own files are", (t) => {
  const dir = tempDir(t);
  const file = path.join(dir, "enterprise-sync.json");
  writeJson(file, {
    resourceBaseUrl: "https://resource.example.com",
    signingKeys: {
      "resource-2026-11": {
        publicKeyPem: "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n",
      },
    },
    agents: {
      claude: "home-claude",
      codex: "/opt/codex",
      other: "not an agent",
      bad: 7,
    },
  });
  const config = readSyncConfig(dir);
  assert.equal(config.state, "ok");
  assert.deepEqual(config.agents, {
    claude: path.join(dir, "home-claude"),
    codex: path.resolve("/opt/codex"),
  });
});

test("readSyncState treats a missing file as never and a bad file as unknown", (t) => {
  const dir = tempDir(t);
  assert.deepEqual(readSyncState(dir), { state: "never" });

  fs.writeFileSync(path.join(dir, "state.json"), "{");
  assert.deepEqual(readSyncState(dir), { state: "invalid", reason: "json" });

  writeJson(path.join(dir, "state.json"), { schemaVersion: 2 });
  assert.deepEqual(readSyncState(dir), { state: "invalid", reason: "schema" });
});

test("resourceRows shows installed, changed, missing, disabled and orphaned resources", (t) => {
  const dir = tempDir(t);
  const desired = [
    stateRecord({ resourceId: "res-installed" }),
    stateRecord({ resourceId: "res-drift", releaseId: "rel-2", hash: `sha256:${"d".repeat(64)}` }),
    stateRecord({ resourceId: "res-missing", releaseId: "rel-3" }),
    stateRecord({
      resourceId: "res-disabled",
      releaseId: "rel-4",
      deliveryMode: "recommended",
    }),
  ];
  writeJson(path.join(dir, "state.json"), {
    schemaVersion: 1,
    revision: "rev-2",
    lastSuccessfulSyncAt: "2026-11-04T03:00:00.000Z",
    lastAttemptAt: "2026-11-04T03:00:00.000Z",
    lastError: null,
    desired: { revision: "rev-2", resources: desired },
    resources: [
      stateRecord({ resourceId: "res-installed", directory: "releases/res-installed/rel-1" }),
      stateRecord({
        resourceId: "res-drift",
        releaseId: "rel-1",
        hash: `sha256:${"e".repeat(64)}`,
        directory: "releases/res-drift/rel-1",
      }),
      stateRecord({
        resourceId: "res-disabled",
        releaseId: "rel-4",
        deliveryMode: "recommended",
        hash: `sha256:${"f".repeat(64)}`,
        directory: "releases/res-disabled/rel-4",
      }),
      stateRecord({ resourceId: "res-orphaned", releaseId: "rel-9", directory: "releases/res-orphaned/rel-9" }),
    ],
    disabledRecommended: ["res-disabled"],
  });

  const state = readSyncState(dir);
  assert.equal(state.state, "ok");
  assert.equal(state.lastSuccessfulSyncAt, "2026-11-04T03:00:00.000Z");
  assert.ok(state.active.every((record) => !("directory" in record)));

  const rows = resourceRows(state);
  assert.deepEqual(
    rows.map((row) => [row.resourceId, row.status]),
    [
      ["res-installed", "installed"],
      ["res-drift", "drift"],
      ["res-missing", "missing"],
      ["res-disabled", "disabled"],
      ["res-orphaned", "orphaned"],
    ],
  );
});

test("resourceRows returns nothing when the state is unknown", () => {
  assert.deepEqual(resourceRows({ state: "invalid", reason: "json" }), []);
});

test("resourceRows names a resource from its metadata or its first heading", (t) => {
  const dir = tempDir(t);
  const fromHeading = stateRecord({ resourceId: "res-heading", releaseId: "rel-1" });
  const fromMetadata = stateRecord({ resourceId: "res-named", releaseId: "rel-2", kind: "skill" });
  const release = (record) => path.join(dir, "releases", record.resourceId, record.releaseId);

  fs.mkdirSync(release(fromHeading), { recursive: true });
  fs.writeFileSync(path.join(release(fromHeading), "content"), "# Engineering knowledge MCP\n\nUse the endpoint.\n");
  writeJson(path.join(release(fromHeading), "metadata.json"), { kind: "mcp" });

  fs.mkdirSync(release(fromMetadata), { recursive: true });
  fs.writeFileSync(path.join(release(fromMetadata), "content"), "# An older heading\n");
  writeJson(path.join(release(fromMetadata), "metadata.json"), { title: "Code review standard" });

  writeJson(path.join(dir, "state.json"), {
    schemaVersion: 1,
    desired: { resources: [fromHeading, fromMetadata] },
    resources: [fromHeading, fromMetadata],
  });

  const rows = resourceRows(readSyncState(dir));
  assert.deepEqual(
    rows.map((row) => [row.resourceId, row.title]),
    [
      ["res-heading", "Engineering knowledge MCP"],
      ["res-named", "Code review standard"],
    ],
  );
});

test("a configured display name wins over the release's own title", (t) => {
  const dir = tempDir(t);
  const record = stateRecord({ resourceId: "res-1", releaseId: "rel-1" });
  writeJson(path.join(dir, "state.json"), {
    schemaVersion: 1,
    desired: { resources: [record] },
    resources: [record],
  });

  const rows = resourceRows(readSyncState(dir), { "res-1": "研发知识库 MCP" });
  assert.equal(rows[0].title, "研发知识库 MCP");
});
