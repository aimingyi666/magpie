import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";

import { createStore } from "../src/store.mjs";
import { startService } from "../src/service.mjs";

// A service with a made-up device and a bundle on disk: no network, no
// magpie, just the loopback the page talks to.
async function service(fields = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "corp-service-"));
  fs.writeFileSync(
    path.join(dir, "bundle.json"),
    JSON.stringify({
      revision: "rev_7",
      providers: [{ id: "corp", name: "Corp Gateway", baseUrl: "https://ai.corp.example/v1", models: ["m1", "m2"] }],
    }),
  );
  const store = createStore(dir);
  store.saveDevice({ deviceId: "dev_1", deviceToken: "secret-token", expiresAt: "", user: { email: "a@corp.example" } });
  const config = {
    baseUrl: "https://ai.corp.example",
    providerId: "corp",
    oidc: null,
    servicePort: 0,
    configDir: dir,
    magpieBin: "magpie",
    upload: { usage: false, masking: false, sessions: false },
    ...fields,
  };
  const joiner = {
    status: () => ({ enrolled: true, usable: true, email: "a@corp.example", department: "研发", expiresAt: "" }),
    handleCallback: async () => ({ ok: false, code: "no_sign_in", message: "none waiting" }),
    signIn: async () => {
      throw new Error("not in this test");
    },
  };
  const started = startService({ config, store, joiner, dir, port: 0 });
  await started.ready;
  return { started, store, config, dir, base: `http://127.0.0.1:${started.port()}` };
}

test("the page is served with its own token, and the device token never is", async () => {
  const { started, base } = await service();
  try {
    const page = await fetch(`${base}/`);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /Corp/);
    assert.match(html, /__CORP_TOKEN/);
    assert.ok(!html.includes("secret-token"), "the page never carries the device's key");

    const denied = await fetch(`${base}/v1/status`);
    assert.equal(denied.status, 403, "the API answers its own page only");

    const status = await fetch(`${base}/v1/status`, { headers: { "x-page-token": started.token() } });
    assert.equal(status.status, 200);
    const body = await status.json();
    assert.equal(body.revision, "rev_7");
    assert.equal(body.providers[0].models, 2);
    assert.equal(body.device.email, "a@corp.example");
    assert.equal(body.device.deviceToken, undefined, "the status says nothing of the key");
  } finally {
    started.close();
  }
});

test("a request from another host is turned away", async () => {
  const { started, base } = await service();
  try {
    const port = new URL(base).port;
    const body = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: "127.0.0.1", port, path: `/v1/status?t=${started.token()}`, headers: { host: "evil.example" } },
        (res) => {
          let text = "";
          res.on("data", (chunk) => {
            text += chunk;
          });
          res.on("end", () => resolve({ status: res.statusCode, text }));
        },
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(body.status, 403);
    assert.match(body.text, /host_not_allowed/);
  } finally {
    started.close();
  }
});

test("a sign-in callback with no sign-in waiting is refused, without failing the page", async () => {
  const { started, base } = await service();
  try {
    const response = await fetch(`${base}/oidc/callback?state=x&code=y`);
    assert.equal(response.status, 400);
    assert.match(await response.text(), /Sign-in failed/);
  } finally {
    started.close();
  }
});
