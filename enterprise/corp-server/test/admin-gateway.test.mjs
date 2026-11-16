// The administrator's control plane against a stand-in gateway.
//
// This is the one place the real admin API's shape matters: a provider is
// written with its keys, a Remote magpie replace takes the previous
// providers away, and a person's caller key is patched with the revision
// the gateway last answered. The fake below refuses a field the real
// gateway would refuse, so a misspelled one fails here rather than in a
// deployment.
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

const ADMIN_TOKEN = "x".repeat(32);

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      if (!chunks.length) return resolve(null);
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

// The provider fields the real API names. A write carrying anything else
// is refused by DisallowUnknownFields, so the fake refuses it too.
const PROVIDER_FIELDS = new Set([
  "expectedRevision", "name", "chat", "responses", "anthropic", "gemini",
  "baseAPI", "models", "modelsSet", "off", "unlisted", "routing", "fallback",
  "fallbackSet", "key", "clearKey", "preset", "addKeys", "addKey", "keys", "removeKeys",
]);

function fakeGateway() {
  const providers = [];
  const keys = [];
  const received = [];
  let providerSeq = 0;
  let keySeq = 0;

  const keyView = (key) => ({
    id: key.id, name: key.name, state: key.off ? "disabled" : "enabled",
    masked: key.masked, models: key.models, readOnly: key.readOnly,
    limit: key.limit || undefined, revision: key.revision,
  });

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const body = await readBody(req);
    received.push({ method: req.method, path: url.pathname, body });
    const send = (status, payload) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
    };

    if (req.headers.authorization !== `Bearer ${ADMIN_TOKEN}`) {
      return send(401, { ok: false, error: { code: "unauthorized", message: "token" } });
    }

    if (req.method === "GET" && url.pathname === "/v1/magpie/admin/providers") {
      return send(200, { ok: true, providers });
    }
    if (req.method === "POST" && url.pathname === "/v1/magpie/admin/providers") {
      for (const name of Object.keys(body || {})) {
        if (!PROVIDER_FIELDS.has(name)) {
          return send(422, { ok: false, error: { code: "invalid_json", message: `unknown field ${name}` } });
        }
      }
      const provider = {
        id: `gw_${++providerSeq}`,
        name: body.name,
        chat: body.chat || "",
        models: Array.isArray(body.models) ? body.models : [],
        off: false,
        revision: `prov_${providerSeq}`,
        keyCount: 1 + (Array.isArray(body.addKeys) ? body.addKeys.length : 0),
      };
      providers.push(provider);
      return send(201, { ok: true, provider });
    }
    if (req.method === "DELETE" && url.pathname.startsWith("/v1/magpie/admin/providers/")) {
      const id = decodeURIComponent(url.pathname.split("/").pop());
      const index = providers.findIndex((provider) => provider.id === id);
      if (index < 0) return send(404, { ok: false, error: { code: "not_found", message: "provider" } });
      if (!body?.expectedRevision || body.expectedRevision !== providers[index].revision) {
        return send(409, { ok: false, error: { code: "revision_conflict", message: "provider" } });
      }
      providers.splice(index, 1);
      return send(200, { ok: true });
    }
    if (req.method === "GET" && url.pathname === "/v1/magpie/admin/gateway/keys") {
      return send(200, { ok: true, keys: keys.map(keyView) });
    }
    if (req.method === "POST" && url.pathname === "/v1/magpie/admin/gateway/keys") {
      const id = `key_${++keySeq}`;
      const key = {
        id, name: body?.name || "", masked: `…${id}`,
        models: Array.isArray(body?.models) ? body.models : [],
        readOnly: false, off: false,
        limit: body?.limit || null,
        revision: `key_rev_${keySeq}`,
      };
      keys.push(key);
      return send(201, { ok: true, key: keyView(key), secret: `sk-issued-${keySeq}` });
    }
    if (req.method === "PATCH" && url.pathname.startsWith("/v1/magpie/admin/gateway/keys/")) {
      const id = decodeURIComponent(url.pathname.split("/").pop());
      const key = keys.find((item) => item.id === id);
      if (!key) return send(404, { ok: false, error: { code: "not_found", message: "key" } });
      if (!body?.expectedRevision || body.expectedRevision !== key.revision) {
        return send(409, { ok: false, error: { code: "revision_conflict", message: "key" } });
      }
      if (body.name !== undefined) key.name = body.name;
      if (body.modelsSet) key.models = body.models || [];
      if (body.readOnly !== undefined) key.readOnly = body.readOnly;
      if (body.off !== undefined) key.off = body.off;
      if (body.limitSet) key.limit = body.limit || null;
      key.revision = `key_rev_${++keySeq}`;
      return send(200, { ok: true, key: keyView(key) });
    }
    return send(404, { ok: false, error: { code: "not_found", message: "path" } });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        server,
        base: `http://127.0.0.1:${server.address().port}`,
        providers,
        keys,
        received,
      });
    });
  });
}

const stateFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "corp-admin-")), "state.json");
const gateway = await fakeGateway();

process.env.CORP_STATE_FILE = stateFile;
process.env.CORP_PORT = "0";
process.env.CORP_ALLOW_DEMO_SIGNIN = "true";
process.env.CORP_DEMO_ADMIN = "true";
process.env.CORP_GATEWAY_ADMIN_URL = gateway.base;
process.env.CORP_GATEWAY_ADMIN_TOKEN = ADMIN_TOKEN;
process.env.CORP_GATEWAY_PUBLIC_URL = "http://127.0.0.1:3499/v1";

const { startServer } = await import("../src/server.mjs");
const started = startServer({ port: 0 });
let BASE = "";
before(async () => {
  const port = await started.listening;
  BASE = `http://127.0.0.1:${port}`;
});
after(() => {
  started.server.close();
  gateway.server.close();
});

async function call(pathname, { method = "GET", body, token } = {}) {
  const response = await fetch(new URL(pathname, `${BASE}/`), {
    method,
    headers: {
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, payload: text.trim() ? JSON.parse(text) : null };
}

let adminToken = "";

test("an administrator enrolls and their token is a gateway key", async () => {
  const enrolled = await call("/api/v1/device/enroll", {
    method: "POST",
    body: {
      schemaVersion: 1,
      code: "demo:admin@corp.example",
      redirectUri: "http://127.0.0.1:3488/oidc/callback",
      device: { name: "ADMIN-PC", platform: "windows" },
    },
  });
  assert.equal(enrolled.status, 200, JSON.stringify(enrolled.payload));
  assert.equal(enrolled.payload.user.role, "admin");
  assert.match(enrolled.payload.deviceToken, /^sk-issued-/);
  adminToken = enrolled.payload.deviceToken;
  assert.equal(gateway.keys.length, 1);
});

test("the administrator reads the person and their caller key", async () => {
  const listed = await call("/api/v1/admin/people", { token: adminToken });
  assert.equal(listed.status, 200, JSON.stringify(listed.payload));
  assert.equal(listed.payload.gateway.keysReadable, true);
  const person = listed.payload.people.find((item) => item.email === "admin@corp.example");
  assert.equal(person.role, "admin");
  assert.equal(person.devices.length, 1);
  assert.equal(person.devices[0].key.id, gateway.keys[0].id);
  assert.equal(person.devices[0].key.state, "enabled");
  assert.ok(!JSON.stringify(listed.payload).includes("sk-issued-"), "a key's value is never listed");
});

test("a native share writes providers and keys into the gateway", async () => {
  const shared = await call("/api/v1/admin/sharing", {
    method: "PUT",
    token: adminToken,
    body: {
      mode: "native",
      providers: [{
        id: "alpha",
        name: "Alpha",
        preset: "openai",
        chat: "https://api.alpha.example/v1",
        models: ["alpha-1", "alpha-2"],
        key: "sk-alpha-secret",
        keys: ["sk-alpha-second"],
      }],
    },
  });
  assert.equal(shared.status, 200, JSON.stringify(shared.payload));
  assert.equal(shared.payload.sharing.mode, "native");
  assert.deepEqual(shared.payload.catalog, ["alpha-1", "alpha-2"]);
  assert.equal(shared.payload.sharing.sources[0].gatewayProviderId, "gw_1");
  assert.equal(shared.payload.sharing.sources[0].keyMasked, "…secret");
  assert.equal(shared.payload.sharing.sources[0].keyCount, 2);
  assert.ok(!JSON.stringify(shared.payload).includes("sk-alpha-secret"));

  assert.equal(gateway.providers.length, 1);
  assert.equal(gateway.providers[0].name, "Alpha");
  assert.deepEqual(gateway.providers[0].models, ["alpha-1", "alpha-2"]);
  const write = gateway.received.find((item) => item.method === "POST" && item.path.endsWith("/providers"));
  assert.equal(write.body.key, "sk-alpha-secret");
  assert.deepEqual(write.body.addKeys, ["sk-alpha-second"]);
  assert.equal(write.body.modelsSet, true);

  const bundle = await call("/api/v1/client/bundle", { token: adminToken });
  assert.deepEqual(bundle.payload.providers[0].models, ["alpha-1", "alpha-2"]);
  assert.equal(bundle.payload.providers[0].name, "企业网关");
});

test("a person's caller key is patched with the gateway's revision", async () => {
  const device = (await call("/api/v1/admin/people", { token: adminToken })).payload.people[0].devices[0];
  const changed = await call(`/api/v1/admin/people/${device.id}`, {
    method: "PATCH",
    token: adminToken,
    body: {
      models: ["alpha-1"],
      readOnly: true,
      limit: { period: "month", cost: 5 },
      off: false,
    },
  });
  assert.equal(changed.status, 200, JSON.stringify(changed.payload));
  assert.deepEqual(changed.payload.key.models, ["alpha-1"]);
  assert.equal(changed.payload.key.readOnly, true);
  assert.equal(changed.payload.key.limit.cost, 5);

  const key = gateway.keys[0];
  assert.deepEqual(key.models, ["alpha-1"]);
  assert.equal(key.readOnly, true);
  assert.equal(key.limit.period, "month");
  const patch = gateway.received.filter((item) => item.method === "PATCH").at(-1);
  assert.equal(patch.body.expectedRevision, "key_rev_1");
  assert.equal(patch.body.limitSet, true);
});

test("switching to Remote magpie takes the native providers back out", async () => {
  const shared = await call("/api/v1/admin/sharing", {
    method: "PUT",
    token: adminToken,
    body: { mode: "remote", models: ["alpha-1"] },
  });
  assert.equal(shared.status, 200, JSON.stringify(shared.payload));
  assert.equal(shared.payload.sharing.mode, "remote");
  assert.equal(gateway.providers.length, 0, "a provider this server wrote is removed");
  const bundle = await call("/api/v1/client/bundle", { token: adminToken });
  assert.equal(bundle.payload.providers[0].name, "企业网关 · Remote magpie");
  assert.deepEqual(bundle.payload.providers[0].models, ["alpha-1"]);
});

test("a native share that the gateway refuses leaves the previous sharing in place", async () => {
  const before = await call("/api/v1/admin/sharing", { token: adminToken });
  const refused = await call("/api/v1/admin/sharing", {
    method: "PUT",
    token: adminToken,
    body: {
      mode: "native",
      providers: [{ id: "alpha", name: "Alpha", models: ["alpha-1"] }],
    },
  });
  assert.equal(refused.status, 502, "a provider with no key is refused before it is written");
  const after = await call("/api/v1/admin/sharing", { token: adminToken });
  assert.equal(after.payload.sharing.mode, before.payload.sharing.mode);
});
