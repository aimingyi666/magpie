import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import { startService } from "../src/service.mjs";

function tempDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "magpie-enterprise-service-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function useStateDir(t) {
  const dir = tempDir(t);
  const prior = process.env.MAGPIE_ENTERPRISE_STATE_DIR;
  process.env.MAGPIE_ENTERPRISE_STATE_DIR = dir;
  t.after(() => {
    if (prior === undefined) delete process.env.MAGPIE_ENTERPRISE_STATE_DIR;
    else process.env.MAGPIE_ENTERPRISE_STATE_DIR = prior;
  });
  return dir;
}

async function serve(t) {
  const service = await startService({ port: 0 });
  t.after(() => service.close());
  return service;
}

function request(port, pathname, { method = "GET", headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port,
      path: pathname,
      method,
      headers,
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

function json(response) {
  return JSON.parse(response.body);
}

async function pageToken(port, query = "") {
  const response = await request(port, `/${query}`);
  assert.equal(response.status, 200);
  const match = response.body.match(/<meta name="magpie-enterprise-token" content="([a-f0-9]{64})">/);
  assert.ok(match, "the page should carry its service token");
  return match[1];
}

function credential(overrides = {}) {
  return {
    version: 1,
    authUrl: "https://auth.example.com",
    userId: "user-1",
    email: "employee@example.com",
    deviceId: "device-1",
    deviceName: "PC-1",
    clientVersion: "enterprise-1.0.0",
    deviceToken: "device-token-must-not-reach-the-page",
    privateKeyFile: "C:\\secret\\device-key.pem",
    providerId: "enterprise-gateway",
    gatewayUrl: "https://gateway.example.com",
    ...overrides,
  };
}

function writeCredential(dir, overrides = {}) {
  fs.writeFileSync(
    path.join(dir, "enterprise-gateway-device.json"),
    `${JSON.stringify(credential(overrides), null, 2)}\n`,
  );
}

function writeConfig(dir, overrides = {}) {
  fs.writeFileSync(
    path.join(dir, "enterprise-sync.json"),
    `${JSON.stringify({
      resourceBaseUrl: "https://resource.example.com",
      signingKeys: {
        "resource-2026-11": {
          publicKeyPem: "-----BEGIN PUBLIC KEY-----\nkey\n-----END PUBLIC KEY-----\n",
          fingerprint: `sha256:${"c".repeat(64)}`,
        },
      },
      ...overrides,
    }, null, 2)}\n`,
  );
}

function writeState(rootDir) {
  fs.mkdirSync(rootDir, { recursive: true });
  const record = {
    resourceId: "res-1",
    releaseId: "rel-1",
    resourceVersion: "1.0.0",
    kind: "mcp",
    deliveryMode: "forced",
    hash: `sha256:${"a".repeat(64)}`,
    manifestDigest: `sha256:${"b".repeat(64)}`,
    signingKeyId: "resource-2026-11",
    installedAt: "2026-11-04T02:00:00.000Z",
    directory: "releases/res-1/rel-1",
  };
  fs.writeFileSync(path.join(rootDir, "state.json"), `${JSON.stringify({
    schemaVersion: 1,
    revision: "rev-1",
    lastSuccessfulSyncAt: "2026-11-04T02:00:00.000Z",
    lastAttemptAt: "2026-11-04T02:00:00.000Z",
    lastError: null,
    desired: { revision: "rev-1", resources: [record] },
    resources: [record],
    disabledRecommended: [],
  })}\n`);
}

test("the page carries a token and loopback status checks that token", async (t) => {
  const dir = useStateDir(t);
  const service = await serve(t);
  const token = await pageToken(service.port, "?lang=zh&theme=dark");

  const page = await request(service.port, "/?lang=zh&theme=dark");
  assert.match(page.body, /<html lang="zh" data-theme="dark">/);
  assert.match(page.body, /<title>Enterprise<\/title>/);

  let response = await request(service.port, "/v1/status");
  assert.equal(response.status, 403);
  assert.equal(json(response).error.code, "forbidden_token");

  response = await request(service.port, "/v1/status", {
    headers: { "x-magpie-enterprise": "wrong" },
  });
  assert.equal(response.status, 403);
  assert.equal(json(response).error.code, "forbidden_token");

  response = await request(service.port, "/v1/status", {
    headers: { "x-magpie-enterprise": token },
  });
  assert.equal(response.status, 200);
  const status = json(response);
  assert.equal(status.configured, false);
  assert.equal(status.credential.state, "missing");
  assert.equal(status.syncConfig.state, "missing");
  assert.ok(!response.body.includes(dir));

  response = await request(service.port, "/v1/status", {
    headers: { host: `evil.example:${service.port}` },
  });
  assert.equal(response.status, 403);
  assert.equal(json(response).error.code, "forbidden_host");

  response = await request(service.port, "/v1/status", {
    headers: { origin: "https://evil.example" },
  });
  assert.equal(response.status, 403);
  assert.equal(json(response).error.code, "forbidden_origin");

  response = await request(service.port, "/v1/status", {
    method: "OPTIONS",
    headers: {
      origin: "null",
      "access-control-request-method": "GET",
      "access-control-request-headers": "x-magpie-enterprise",
    },
  });
  assert.equal(response.status, 204);
  assert.equal(response.headers["access-control-allow-origin"], "null");
});

test("status shows joined device and resources without secrets or paths", async (t) => {
  const dir = useStateDir(t);
  writeCredential(dir);
  const rootDir = path.join(dir, "resources");
  writeConfig(dir, { rootDir });
  writeState(rootDir);
  const service = await serve(t);
  const token = await pageToken(service.port);

  const response = await request(service.port, "/v1/status", {
    headers: { "x-magpie-enterprise": token },
  });
  assert.equal(response.status, 200);
  const status = json(response);
  assert.equal(status.configured, true);
  assert.equal(status.canSync, true);
  assert.equal(status.joined.email, "employee@example.com");
  assert.equal(status.joined.deviceName, "PC-1");
  assert.equal(status.sync.state, "ok");
  assert.equal(status.resources.length, 1);
  assert.equal(status.resources[0].status, "installed");
  assert.equal(status.resources[0].resourceId, "res-1");

  for (const secret of [
    "device-token-must-not-reach-the-page",
    "device-key.pem",
    rootDir,
    dir,
  ]) {
    assert.ok(!response.body.includes(secret), `the page status leaked ${secret}`);
  }
  assert.ok(!Object.hasOwn(status.resources[0], "directory"));
});

test("sync refuses a device that is not joined or has no sync configuration", async (t) => {
  const dir = useStateDir(t);
  const service = await serve(t);
  const token = await pageToken(service.port);

  let response = await request(service.port, "/v1/sync", {
    method: "POST",
    headers: { "x-magpie-enterprise": token },
  });
  assert.equal(response.status, 409);
  assert.equal(json(response).error.code, "not_joined");

  writeCredential(dir);
  response = await request(service.port, "/v1/sync", {
    method: "POST",
    headers: { "x-magpie-enterprise": token },
  });
  assert.equal(response.status, 409);
  assert.equal(json(response).error.code, "sync_not_configured");
});

test("a second sync answers busy while the first is running", async (t) => {
  const dir = useStateDir(t);
  writeCredential(dir);
  const fake = path.join(dir, "fake-sync.mjs");
  fs.writeFileSync(fake, `
let enteredResolve;
const entered = new Promise((resolve) => { enteredResolve = resolve; });
let releaseResolve;
const gate = new Promise((resolve) => { releaseResolve = resolve; });

export function waitEntered() { return entered; }
export function release() { releaseResolve(); }
export let lastOptions;

export class ClientSyncEngine {
  constructor(options) { lastOptions = options; }
  async syncOnce() {
    enteredResolve();
    await gate;
    return {
      status: "up_to_date",
      revision: "rev-test",
      installed: [],
      unchanged: [],
      skipped: [],
      drift: [],
      state: { revision: "rev-test", resources: [] },
    };
  }
}

export function createEnterpriseSyncTransport() {
  return {
    fetchDesiredState: async () => ({}),
    reportResult: async () => ({ skipped: true, reason: "test" }),
  };
}
`);
  writeConfig(dir, {
    rootDir: path.join(dir, "resources"),
    clientSyncModule: path.basename(fake),
  });
  const fakeModule = await import(pathToFileURL(fake).href);
  const service = await serve(t);
  const token = await pageToken(service.port);

  let first;
  try {
    first = request(service.port, "/v1/sync", {
      method: "POST",
      headers: { "x-magpie-enterprise": token },
    });
    await Promise.race([
      fakeModule.waitEntered(),
      new Promise((_, reject) => setTimeout(() => reject(new Error("first sync did not start")), 3_000)),
    ]);

    const second = await request(service.port, "/v1/sync", {
      method: "POST",
      headers: { "x-magpie-enterprise": token },
    });
    assert.equal(second.status, 200);
    const busy = json(second);
    assert.equal(busy.result.status, "busy");
    assert.equal(busy.result.error.code, "sync_busy");

    fakeModule.release();
    const done = await first;
    assert.equal(done.status, 200);
    assert.equal(json(done).result.status, "up_to_date");
    assert.equal(typeof fakeModule.lastOptions?.fetchDesiredState, "function");
    assert.equal(fakeModule.lastOptions?.clientVersion, "1.0.0");
  } finally {
    fakeModule.release();
    if (first) await first.catch(() => {});
  }
});
