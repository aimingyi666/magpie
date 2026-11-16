// A demo sign-in can name its own role: `demo-admin:` is the demo
// directory's administrator, and a plain `demo:` never is.
//
// CORP_DEMO_ADMIN is off here on purpose. The prefix is read only in the
// demo branch of exchangeCode, which is refused as soon as an identity
// provider is configured.
import test, { after, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

const ADMIN_TOKEN = "d".repeat(32);

// Only the two routes an enroll uses: create a caller key, and list them.
function fakeGateway() {
  const keys = [];
  let seq = 0;
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    for await (const chunk of req);
    const send = (status, payload) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    if (req.headers.authorization !== `Bearer ${ADMIN_TOKEN}`) return send(401, { ok: false });
    if (req.method === "GET" && url.pathname === "/v1/magpie/admin/gateway/keys") {
      return send(200, { ok: true, keys });
    }
    if (req.method === "POST" && url.pathname === "/v1/magpie/admin/gateway/keys") {
      const id = `key_${++seq}`;
      const key = {
        id, name: "", masked: `…${id}`, models: [], readOnly: false,
        off: false, limit: null, revision: `rev_${seq}`,
      };
      keys.push(key);
      return send(201, { ok: true, key, secret: `sk-demo-${seq}` });
    }
    return send(404, { ok: false });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, base: `http://127.0.0.1:${server.address().port}` });
    });
  });
}

const gateway = await fakeGateway();
process.env.CORP_STATE_FILE = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "corp-demo-admin-")), "state.json");
process.env.CORP_PORT = "0";
process.env.CORP_ALLOW_DEMO_SIGNIN = "true";
process.env.CORP_DEMO_ADMIN = "false";
process.env.CORP_GATEWAY_ADMIN_URL = gateway.base;
process.env.CORP_GATEWAY_ADMIN_TOKEN = ADMIN_TOKEN;

const { startServer } = await import("../src/server.mjs");
const started = startServer({ port: 0 });
let BASE = "";
before(async () => {
  BASE = `http://127.0.0.1:${await started.listening}`;
});
after(() => {
  started.server.close();
  gateway.server.close();
});

async function enroll(code) {
  const response = await fetch(new URL("/api/v1/device/enroll", `${BASE}/`), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      schemaVersion: 1,
      code,
      redirectUri: "http://127.0.0.1:3488/oidc/callback",
      device: { name: "TEST-PC", platform: "windows" },
    }),
  });
  const payload = await response.json();
  assert.equal(response.status, 200, JSON.stringify(payload));
  return payload;
}

test("a plain demo sign-in is a member", async () => {
  const device = await enroll("demo:member@corp.example");
  assert.equal(device.user.role, "member");
  assert.deepEqual(device.user.groups, ["engineering"]);
});

test("a demo-admin sign-in is an administrator, without CORP_DEMO_ADMIN", async () => {
  const device = await enroll("demo-admin:admin@corp.example");
  assert.equal(device.user.role, "admin");
  assert.ok(device.user.groups.includes("corp-admins"));
});

test("the same demo address is one person, whichever entry signed in", async () => {
  const admin = await enroll("demo-admin:shared@corp.example");
  assert.equal(admin.user.role, "admin");
  const member = await enroll("demo:shared@corp.example");
  assert.equal(member.user.id, admin.user.id, "the administrator is the same demo person");
  assert.equal(member.user.role, "member", "a later plain sign-in is not left an administrator");
});
