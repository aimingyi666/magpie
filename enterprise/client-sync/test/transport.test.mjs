import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import test from "node:test";

import { createEnterpriseSyncTransport } from "../src/transport.js";

const DEVICE_TOKEN = ["device", "token", "fixture", "material"].join("-");
const SYNC_CREDENTIAL = [
  "mss1",
  Buffer.from(JSON.stringify({
    schemaVersion: 1,
    purpose: "magpie-resource-sync",
    issuer: "magpie-enterprise-auth",
    audience: "magpie-enterprise-resource",
    userId: "usr_alice",
    deviceId: "dev_alice_pc",
    organizationIds: ["org_engineering"],
    issuedAt: 1800000000,
    expiresAt: 1800000300,
    nonce: "abcdefghijklmnopqrst",
  }), "utf8").toString(["base", "64", "url"].join("")),
  "fixturepart",
].join(".");
const REVISION = `sha256:${crypto.createHash("sha256").update("snapshot").digest("hex")}`;
const NOW = () => Date.parse("2026-11-02T00:01:00.000Z");

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}

function close(server) {
  return new Promise((resolve) => server.close(() => resolve()));
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks);
}

function json(res, status, body, headers = {}) {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": String(payload.length),
    ...headers,
  });
  res.end(payload);
}

function makeResourceServer(overrides = {}) {
  const state = {
    desiredRequests: [],
    reportRequests: [],
    desiredStatus: 200,
    desiredPadding: 0,
    reportStatus: 202,
    ...overrides,
  };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (url.pathname === "/api/v1/client/sync/desired-state") {
      state.desiredRequests.push({
        authorization: req.headers.authorization,
        ifNoneMatch: req.headers["if-none-match"] || null,
      });
      if (state.desiredStatus === 304) {
        res.writeHead(304, { etag: `"${REVISION}"` });
        res.end();
        return;
      }
      if (state.desiredStatus !== 200) {
        json(res, state.desiredStatus, { error: { code: "invalid_sync_token" } });
        return;
      }
      json(res, 200, {
        schemaVersion: 1,
        revision: REVISION,
        generatedAt: "2026-11-02T00:00:00.000Z",
        resources: [{
          manifest: {
            resourceId: "res_baseline",
            padding: "x".repeat(state.desiredPadding),
          },
          contentBase64: Buffer.from("# baseline\n", "utf8").toString("base64"),
        }],
      });
      return;
    }
    if (url.pathname === "/api/v1/client/sync/report") {
      const raw = await readBody(req);
      state.reportRequests.push({
        authorization: req.headers.authorization,
        body: raw.length ? JSON.parse(raw.toString("utf8")) : null,
        raw: raw.toString("utf8"),
      });
      json(res, state.reportStatus, { schemaVersion: 1, ok: true, accepted: true });
      return;
    }
    json(res, 404, { error: { code: "not_found" } });
  });
  return { server, state };
}

function makeAuthServer(overrides = {}) {
  const state = {
    requests: [],
    status: 200,
    ...overrides,
  };
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (url.pathname !== "/api/v1/devices/sync-credential") {
      json(res, 404, { error: { code: "not_found" } });
      return;
    }
    state.requests.push({ authorization: req.headers.authorization });
    if (state.status !== 200) {
      json(res, state.status, { error: { code: "device_token_rejected" } });
      return;
    }
    json(res, 200, {
      schemaVersion: 1,
      credential: SYNC_CREDENTIAL,
      expiresAt: "2026-11-02T00:10:00.000Z",
      audience: "magpie-enterprise-resource",
    });
  });
  return { server, state };
}

async function fixture(t, {
  authOverrides = {},
  resourceOverrides = {},
  transportOverrides = {},
} = {}) {
  const auth = makeAuthServer(authOverrides);
  const resource = makeResourceServer(resourceOverrides);
  const authPort = await listen(auth.server);
  const resourcePort = await listen(resource.server);
  t.after(async () => {
    await close(auth.server);
    await close(resource.server);
  });
  const authBaseUrl = `http://127.0.0.1:${authPort}`;
  const resourceBaseUrl = `http://127.0.0.1:${resourcePort}`;
  return {
    auth,
    resource,
    transport: createEnterpriseSyncTransport({
      authBaseUrl,
      resourceBaseUrl,
      deviceToken: DEVICE_TOKEN,
      clientVersion: "1.4.0",
      now: NOW,
      ...transportOverrides,
    }),
  };
}

test("the transport mints a credential at auth-service and never sends the device token to resource-service", async (t) => {
  const f = await fixture(t);
  const snapshot = await f.transport.fetchDesiredState({});

  assert.equal(f.auth.state.requests.length, 1);
  assert.equal(f.auth.state.requests[0].authorization, `Bearer ${DEVICE_TOKEN}`);
  assert.equal(f.resource.state.desiredRequests.length, 1);
  assert.equal(f.resource.state.desiredRequests[0].authorization, `Bearer ${SYNC_CREDENTIAL}`);
  assert.ok(!JSON.stringify(f.resource.state.desiredRequests).includes(DEVICE_TOKEN));
  assert.equal(snapshot.revision, REVISION);
  assert.equal(snapshot.resources[0].content.toString("utf8"), "# baseline\n");
  assert.ok(Buffer.isBuffer(snapshot.resources[0].content));
});

test("the transport reuses the credential and answers 304 from the cached snapshot", async (t) => {
  const f = await fixture(t);
  await f.transport.fetchDesiredState({});
  f.resource.state.desiredStatus = 304;
  const second = await f.transport.fetchDesiredState({ revision: REVISION });

  assert.equal(f.auth.state.requests.length, 1);
  assert.equal(second.revision, REVISION);
  assert.equal(f.resource.state.desiredRequests[1].ifNoneMatch, `"${REVISION}"`);
});

test("a rejected credential is re-minted once and the request is retried", async (t) => {
  const f = await fixture(t, { resourceOverrides: { desiredStatus: 401 } });
  await assert.rejects(
    () => f.transport.fetchDesiredState({}),
    (error) => error.code === "desired_state_unavailable",
  );
  assert.equal(f.auth.state.requests.length, 2);
  assert.equal(f.resource.state.desiredRequests.length, 2);
});

test("a device report carries only identifiers, digests, status and drift", async (t) => {
  const f = await fixture(t);
  const result = await f.transport.reportResult({
    status: "synced",
    revision: REVISION,
    state: {
      resources: [{
        resourceId: "res_baseline",
        releaseId: "rel_2026_11_1",
        manifestDigest: REVISION,
        content: "must never be uploaded",
        directory: "releases/res_baseline/rel_2026_11_1",
      }],
    },
    drift: [{
      resourceId: "res_baseline",
      state: "version_mismatch",
      expectedReleaseId: null,
      actualReleaseId: "rel_old",
    }],
  });

  assert.equal(result.accepted, true);
  assert.equal(f.resource.state.reportRequests.length, 1);
  const body = f.resource.state.reportRequests[0].body;
  assert.equal(body.schemaVersion, 1);
  assert.equal(body.revision, REVISION);
  assert.equal(body.clientVersion, "1.4.0");
  assert.equal(body.status, "synced");
  assert.deepEqual(body.installed, [{
    resourceId: "res_baseline",
    releaseId: "rel_2026_11_1",
    manifestDigest: REVISION,
  }]);
  assert.deepEqual(body.drift, [{
    resourceId: "res_baseline",
    state: "version_mismatch",
    expectedReleaseId: "",
    actualReleaseId: "rel_old",
  }]);
  assert.ok(!f.resource.state.reportRequests[0].raw.includes("must never be uploaded"));
  assert.ok(!f.resource.state.reportRequests[0].raw.includes(DEVICE_TOKEN));
  assert.ok(!f.resource.state.reportRequests[0].raw.includes(SYNC_CREDENTIAL));
});

test("a device without a successful sync does not report a fake revision", async (t) => {
  const f = await fixture(t);
  const result = await f.transport.reportResult({ status: "offline", state: { resources: [] } });
  assert.deepEqual(result, { skipped: true, reason: "no_revision" });
  assert.equal(f.resource.state.reportRequests.length, 0);
});

test("the transport rejects plaintext transport to a non-loopback host", () => {
  assert.throws(
    () => createEnterpriseSyncTransport({
      authBaseUrl: "http://auth.corp.example",
      resourceBaseUrl: "https://resource.corp.example",
      deviceToken: DEVICE_TOKEN,
      clientVersion: "1.4.0",
    }),
    (error) => error.code === "invalid_config",
  );
});

test("an oversized desired state is refused before it reaches the engine", async (t) => {
  const f = await fixture(t, {
    resourceOverrides: { desiredPadding: 4096 },
    transportOverrides: { maxResponseBytes: 1024 },
  });
  await assert.rejects(
    () => f.transport.fetchDesiredState({}),
    (error) => error.code === "response_too_large",
  );
});

test("a rejected device token fails closed and leaks no credential", async (t) => {
  const f = await fixture(t, { authOverrides: { status: 401 } });
  await assert.rejects(
    () => f.transport.fetchDesiredState({}),
    (error) => {
      assert.equal(error.code, "sync_credential_unavailable");
      assert.ok(!error.message.includes(DEVICE_TOKEN));
      assert.ok(!error.message.includes(SYNC_CREDENTIAL));
      return true;
    },
  );
  assert.equal(f.resource.state.desiredRequests.length, 0);
});
