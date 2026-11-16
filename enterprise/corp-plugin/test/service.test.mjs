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
async function service(fields = {}, { openUrl, client } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "corp-service-"));
  fs.writeFileSync(
    path.join(dir, "bundle.json"),
    JSON.stringify({
      revision: "rev_7",
      providers: [{ id: "corp", name: "Corp Gateway", baseUrl: "https://ai.corp.example/v1", models: ["m1", "m2"] }],
      instructions: [{ id: "ins_corp", title: "Corp rules", content: "# rules", enabled: true }],
      mcp: [{ name: "corp-kb", url: "https://kb.corp.example", enabled: true }],
      skills: [{ name: "corp-report", enabled: true }],
    }),
  );
  const store = createStore(dir);
  if (!fields.noDevice) {
    store.saveDevice({
      deviceId: "dev_1",
      deviceToken: "secret-token",
      expiresAt: "",
      enrolledAt: "2026-11-01T08:00:00.000Z",
      user: { email: "a@corp.example", name: "Alice", department: "研发", groups: ["engineering"], role: "admin" },
    });
  }
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
  const demoCalls = [];
  const joiner = {
    status: () => (fields.noDevice
      ? { enrolled: false, usable: false }
      : { enrolled: true, usable: true, email: "a@corp.example", department: "研发", expiresAt: "" }),
    handleCallback: async () => ({ ok: false, code: "no_sign_in", message: "none waiting" }),
    signIn: async () => {
      throw new Error("not in this test");
    },
    demoSignIn: async (email, options) => {
      demoCalls.push({ email, options });
      return {};
    },
  };
  const started = startService({
    config, store, joiner, dir, port: 0,
    ...(openUrl ? { openUrl } : {}),
    ...(client ? { client } : {}),
  });
  await started.ready;
  return { started, store, config, dir, demoCalls, base: `http://127.0.0.1:${started.port()}` };
}

// A stand-in for the corporate server: it records what the local service
// sends it, so a test can see that a key went up and never came back.
function fakeCorp(handler) {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : null;
    const request = {
      method: req.method,
      path: url.pathname,
      body,
      authorization: String(req.headers.authorization || ""),
      requests,
    };
    requests.push(request);
    const answer = handler(request);
    if (!answer) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end("{}");
      return;
    }
    res.writeHead(answer.status || 200, { "content-type": "application/json" });
    res.end(JSON.stringify(answer.body === undefined ? {} : answer.body));
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, base: `http://127.0.0.1:${server.address().port}`, requests });
    });
  });
}

test("the page is served with its own token, and the device token never is", async () => {
  const { started, base } = await service();
  try {
    const page = await fetch(`${base}/`);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /Corp/);
    assert.match(html, /__CORP_TOKEN/);
    assert.match(html, /概览/);
    assert.match(html, /个人信息/);
    assert.match(html, /管理员/);
    assert.match(html, /id="userWorkbuddy"/);
    assert.match(html, /共享 WorkBuddy/);
    assert.match(html, /data-wb-local/, "the page offers this computer's own sign-ins for import");
    assert.match(html, /\/v1\/share\/workbuddy\/import/, "and asks this service to move one");
    assert.match(html, /指令/);
    assert.match(html, /MCP 服务/);
    assert.match(html, /技能/);
    assert.ok(!html.includes("secret-token"), "the page never carries the device's key");

    const personal = await fetch(`${base}/me`);
    assert.equal(personal.status, 200);
    const personalHtml = await personal.text();
    assert.match(personalHtml, /id="meName"/);
    assert.match(personalHtml, /id="meDevice"/);
    assert.match(personalHtml, /id="meResources"/);
    assert.match(personalHtml, /__CORP_PAGE="me"/);
    assert.ok(!personalHtml.includes("secret-token"), "the personal page never carries the device's key");

    const admin = await fetch(`${base}/admin`);
    assert.equal(admin.status, 200);
    const adminHtml = await admin.text();
    assert.match(adminHtml, /id="nativeShare"/);
    assert.match(adminHtml, /id="wbAdminSave"/);
    assert.match(adminHtml, /员工共享的 WorkBuddy/);
    assert.match(adminHtml, /__CORP_PAGE="admin"/);
    assert.ok(!adminHtml.includes("secret-token"), "the administrator page never carries the device's key");

    const signIn = await fetch(`${base}/login`, { redirect: "manual" });
    assert.equal(signIn.status, 302, "a signed-in computer goes from the sign-in page to the overview");
    assert.equal(signIn.headers.get("location"), "/");

    const denied = await fetch(`${base}/v1/status`);
    assert.equal(denied.status, 403, "the API answers its own page only");

    const status = await fetch(`${base}/v1/status`, { headers: { "x-page-token": started.token() } });
    assert.equal(status.status, 200);
    const body = await status.json();
    assert.equal(body.revision, "rev_7");
    assert.equal(body.providers[0].models, 2);
  assert.deepEqual(body.resources.instructions, ["Corp rules"]);
  assert.deepEqual(body.resources.mcp, ["corp-kb"]);
  assert.deepEqual(body.resources.skills, ["corp-report"]);
    assert.equal(body.device.email, "a@corp.example");
    assert.equal(body.device.deviceToken, undefined, "the status says nothing of the key");
  } finally {
    started.close();
  }
});

test("a computer without a device lands on the sign-in page, and the overview sends it there", async () => {
  const { started, base } = await service({ noDevice: true, demoSignIn: true });
  try {
    const overview = await fetch(`${base}/`, { redirect: "manual" });
    assert.equal(overview.status, 302);
    assert.equal(overview.headers.get("location"), "/login");

    const personal = await fetch(`${base}/me`, { redirect: "manual" });
    assert.equal(personal.status, 302, "the personal page needs a signed-in device");
    assert.equal(personal.headers.get("location"), "/login");

    const signIn = await fetch(`${base}/login`);
    assert.equal(signIn.status, 200);
    const html = await signIn.text();
    assert.match(html, /id="login"/);
    assert.match(html, /使用企业账号登录/);
    assert.match(html, /id="demo-login"/);
    assert.match(html, /__CORP_PAGE="login"/);
    assert.ok(!html.includes("secret-token"), "the sign-in page carries no device key");

    const renew = await fetch(`${base}/login?renew=1`, { redirect: "manual" });
    assert.equal(renew.status, 200, "renew stays on the sign-in page");
  } finally {
    started.close();
  }
});

test("a demo sign-in can ask for the administrator role, and a plain one cannot", async () => {
  const fake = await fakeCorp(({ path: requestPath }) => {
    if (requestPath === "/api/v1/corp/config") {
      return { body: { schemaVersion: 1, demoSignIn: true } };
    }
    return null;
  });
  const { started, base, demoCalls } = await service({ baseUrl: fake.base });
  try {
    const headers = { "x-page-token": started.token(), "content-type": "application/json" };
    const member = await fetch(`${base}/v1/demo-login`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: "alice@corp.example" }),
    });
    assert.equal(member.status, 200);
    assert.deepEqual(demoCalls[0], { email: "alice@corp.example", options: { admin: false } });

    const admin = await fetch(`${base}/v1/demo-login`, {
      method: "POST",
      headers,
      body: JSON.stringify({ email: "alice@corp.example", role: "admin" }),
    });
    assert.equal(admin.status, 200);
    assert.deepEqual(demoCalls[1], {
      email: "alice@corp.example",
      options: { admin: true },
    });
  } finally {
    started.close();
    fake.server.close();
  }
});

test("the administrator view reads this computer's magpie, and its keys stay out of the answer", async () => {
  const fake = await fakeCorp(({ path: requestPath }) => {
    if (requestPath === "/api/v1/device/me") {
      return {
        body: {
          user: { id: "usr_1", email: "admin@corp.example", name: "Admin", role: "admin" },
          device: { id: "dev_1", name: "ADMIN-PC" },
          sharing: { mode: "remote", updatedAt: "", catalog: ["alpha-1"], sources: [] },
          gateway: { baseUrl: "https://ai.corp.example/v1" },
        },
      };
    }
    return null;
  });
  const { started, base, dir } = await service({ baseUrl: fake.base });
  try {
    fs.writeFileSync(
      path.join(dir, "providers.json"),
      JSON.stringify({
        providers: [{ id: "alpha", name: "Alpha", key: "sk-native-secret", models: ["alpha-1"] }],
      }),
    );
    fs.writeFileSync(
      path.join(dir, "caller-keys.json"),
      JSON.stringify([{ id: "key_1", name: "Alice", secret: "sk-caller-secret" }]),
    );

    const denied = await fetch(`${base}/v1/admin/session`);
    assert.equal(denied.status, 403, "the API answers its own page only");

    const response = await fetch(`${base}/v1/admin/session`, { headers: { "x-page-token": started.token() } });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.admin, true);
    assert.equal(body.native.providers[0].id, "alpha");
    assert.equal(body.native.keys[0].id, "key_1");
    const raw = JSON.stringify(body);
    assert.ok(!raw.includes("sk-native-secret"), "a provider key never reaches the page");
    assert.ok(!raw.includes("sk-caller-secret"), "a gateway key never reaches the page");
    assert.equal(fake.requests.at(-1).authorization, "Bearer secret-token", "the service asks as this device");
  } finally {
    started.close();
    fake.server.close();
  }
});

test("a member's administrator view says so and reads nothing from the native magpie", async () => {
  const fake = await fakeCorp(({ path: requestPath }) => {
    if (requestPath === "/api/v1/device/me") {
      return {
        body: {
          user: { id: "usr_2", email: "member@corp.example", role: "member" },
          device: { id: "dev_2" },
          sharing: { mode: "", catalog: [], sources: [] },
        },
      };
    }
    return null;
  });
  const { started, base } = await service({ baseUrl: fake.base });
  try {
    const response = await fetch(`${base}/v1/admin/session`, { headers: { "x-page-token": started.token() } });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.admin, false);
    assert.equal(body.native, null);
    assert.match(body.reason, /管理员/);
  } finally {
    started.close();
    fake.server.close();
  }
});

test("sharing a WorkBuddy account goes through the corporate server, and only a URL comes back", async () => {
  const SHARE_ID = "shr_0123456789abcdef01234567";
  const fake = await fakeCorp(({ path: requestPath, method }) => {
    if (requestPath === "/api/v1/share/workbuddy/start" && method === "POST") {
      return {
        body: {
          schemaVersion: 1,
          share: {
            id: SHARE_ID, provider: "workbuddy", providerName: "WorkBuddy（国内版）",
            state: "waiting", url: "https://copilot.tencent.com/login?state=abc",
            account: "", models: [], error: "", createdAt: "", updatedAt: "", completedAt: "",
          },
          instructions: "扫描页面上的二维码",
        },
      };
    }
    if (requestPath === `/api/v1/share/workbuddy/${SHARE_ID}` && method === "GET") {
      return {
        body: {
          share: {
            id: SHARE_ID, provider: "workbuddy", providerName: "WorkBuddy（国内版）",
            state: "done", url: "", account: "alice@wb.example", models: ["wb-1", "wb-3"],
            error: "", createdAt: "", updatedAt: "", completedAt: "2026-11-16T00:00:00.000Z",
          },
        },
      };
    }
    if (requestPath === `/api/v1/share/workbuddy/${SHARE_ID}/cancel` && method === "POST") {
      return { body: { share: { id: SHARE_ID, provider: "workbuddy", state: "canceled", models: [] } } };
    }
    if (requestPath === "/api/v1/device/me" && method === "GET") {
      return { body: { workbuddy: { shares: [{ id: SHARE_ID, state: "done", account: "alice@wb.example" }] } } };
    }
    return null;
  });
  const opened = [];
  const { started, base } = await service(
    { baseUrl: fake.base },
    { openUrl: (url) => { opened.push(url); return true; } },
  );
  const headers = { "x-page-token": started.token(), "content-type": "application/json" };
  try {
    const startedShare = await fetch(`${base}/v1/share/workbuddy/start`, {
      method: "POST", headers, body: JSON.stringify({ provider: "workbuddy" }),
    });
    assert.equal(startedShare.status, 200);
    const share = await startedShare.json();
    assert.equal(share.share.state, "waiting");
    assert.match(share.share.url, /^https:\/\/copilot\.tencent\.com\//);
    assert.match(share.instructions, /二维码/);
    assert.equal(share.opened, true, "the frame can't open a tab, so this computer's browser does");
    assert.deepEqual(opened, [share.share.url], "the vendor's page is handed to the browser once");
    assert.ok(!JSON.stringify(share).includes("secret-token"), "the device's key never reaches the page");
    const sent = fake.requests.find((request) => request.path === "/api/v1/share/workbuddy/start");
    assert.deepEqual(sent.body, { provider: "workbuddy" });
    assert.equal(sent.authorization, "Bearer secret-token", "the service asks as this device");

    const polled = await fetch(`${base}/v1/share/workbuddy/${SHARE_ID}`, { headers });
    assert.equal(polled.status, 200);
    const done = await polled.json();
    assert.equal(done.share.state, "done");
    assert.deepEqual(done.share.models, ["wb-1", "wb-3"]);

    const canceled = await fetch(`${base}/v1/share/workbuddy/${SHARE_ID}/cancel`, { method: "POST", headers });
    assert.equal(canceled.status, 200);
    assert.equal((await canceled.json()).share.state, "canceled");
    assert.ok(fake.requests.some((request) => request.method === "POST" && request.path.endsWith("/cancel")));

    const listed = await fetch(`${base}/v1/share/workbuddy`, { headers });
    assert.equal(listed.status, 200);
    assert.deepEqual((await listed.json()).shares, [{ id: SHARE_ID, state: "done", account: "alice@wb.example" }]);

    const bad = await fetch(`${base}/v1/share/workbuddy/not-a-share`, { headers });
    assert.equal(bad.status, 422, "an id this service didn't make is refused before any request goes up");
    assert.ok(!fake.requests.some((request) => request.path.includes("not-a-share")));
  } finally {
    started.close();
    fake.server.close();
  }
});

test("a WorkBuddy share without a signed-in device is refused, not sent", async () => {
  const fake = await fakeCorp(() => ({ body: {} }));
  const { started, base } = await service({ baseUrl: fake.base, noDevice: true });
  try {
    const response = await fetch(`${base}/v1/share/workbuddy/start`, {
      method: "POST",
      headers: { "x-page-token": started.token(), "content-type": "application/json" },
      body: JSON.stringify({ provider: "workbuddy" }),
    });
    assert.equal(response.status, 401);
    assert.equal((await response.json()).error.code, "not_signed_in");
    assert.ok(!fake.requests.some((request) => request.path.includes("workbuddy")),
      "nothing is sent to the corporate server without a device");
  } finally {
    started.close();
    fake.server.close();
  }
});

test("this computer's WorkBuddy sign-ins are named, and their tokens stay put", async () => {
  const { started, base, dir } = await service();
  fs.writeFileSync(path.join(dir, "plugin-auth.json"), JSON.stringify({
    workbuddy: { type: "oauth", accountId: "138****1234", access: "wb-access-secret", refresh: "wb-refresh-secret" },
    "workbuddy#gfcok5": { type: "oauth", accountId: "152****6538", access: "wb-access-second" },
    "workbuddy-ai": { type: "oauth", accountId: "intl@wb.example", access: "wb-access-intl" },
    cursor: { type: "oauth", accountId: "someone@example.com", access: "cursor-secret" },
  }));
  try {
    const headers = { "x-page-token": started.token() };
    const status = await fetch(`${base}/v1/status`, { headers });
    assert.equal(status.status, 200);
    const body = await status.json();
    assert.deepEqual(body.localWorkbuddy, [
      { provider: "workbuddy", account: "138****1234" },
      { provider: "workbuddy", account: "152****6538" },
      { provider: "workbuddy-ai", account: "intl@wb.example" },
    ], "the accounts this computer already has signed in are named, other providers are not");
    const said = JSON.stringify(body);
    assert.ok(!said.includes("wb-access-secret"), "a token beside an account is read past, never sent");
    assert.ok(!said.includes("wb-refresh-secret"));
    assert.ok(!said.includes("cursor-secret"));
  } finally {
    started.close();
  }
});

test("a sign-in this computer already has is imported once, then signed out here", async () => {
  const SHARE_ID = "shr_0123456789abcdef01234567";
  const fake = await fakeCorp(({ path: requestPath, method, body }) => {
    if (requestPath === "/api/v1/share/workbuddy/import" && method === "POST") {
      if (body.provider === "workbuddy-ai") {
        return { status: 503, body: { error: { code: "workbuddy_unavailable", message: "企业网关还没装插件" } } };
      }
      return {
        body: {
          schemaVersion: 1,
          share: {
            id: SHARE_ID, provider: "workbuddy", providerName: "WorkBuddy（国内版）",
            state: "done", account: "138****1234", models: ["wb-1"],
            error: "", createdAt: "", updatedAt: "", completedAt: "2026-11-16T00:00:00.000Z",
          },
        },
      };
    }
    return null;
  });
  const removed = [];
  const client = { auth: { remove: async ({ path: target }) => { removed.push(target.id); } } };
  const { started, base, dir } = await service({ baseUrl: fake.base }, { client });
  fs.writeFileSync(path.join(dir, "plugin-auth.json"), JSON.stringify({
    workbuddy: { type: "oauth", accountId: "138****1234", access: "wb-access-secret", refresh: "wb-refresh-secret" },
    "workbuddy-ai": { type: "oauth", accountId: "intl@wb.example", access: "wb-access-intl" },
  }));
  const headers = { "x-page-token": started.token(), "content-type": "application/json" };
  try {
    const response = await fetch(`${base}/v1/share/workbuddy/import`, {
      method: "POST", headers, body: JSON.stringify({ provider: "workbuddy", account: "138****1234" }),
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.share.state, "done");
    assert.equal(body.removed, true);
    assert.ok(!JSON.stringify(body).includes("wb-refresh-secret"), "no token comes back");
    const sent = fake.requests.find((request) => request.path === "/api/v1/share/workbuddy/import");
    assert.equal(sent.body.provider, "workbuddy");
    assert.equal(sent.body.auth.refresh, "wb-refresh-secret", "the sign-in reached the corporate gateway");
    assert.equal(sent.authorization, "Bearer secret-token", "the service asks as this device");
    assert.deepEqual(removed, ["workbuddy"], "this computer's copy goes once the gateway has it");

    // the gateway refusing leaves this computer's copy where it was
    const failed = await fetch(`${base}/v1/share/workbuddy/import`, {
      method: "POST", headers, body: JSON.stringify({ provider: "workbuddy-ai", account: "intl@wb.example" }),
    });
    assert.equal(failed.status, 503);
    assert.equal((await failed.json()).error.code, "workbuddy_unavailable");
    assert.deepEqual(removed, ["workbuddy"], "a failed import signs nothing out here");

    // an account this computer doesn't have goes nowhere
    const sentBefore = fake.requests.filter((request) => request.path === "/api/v1/share/workbuddy/import").length;
    const missing = await fetch(`${base}/v1/share/workbuddy/import`, {
      method: "POST", headers, body: JSON.stringify({ provider: "workbuddy", account: "nobody@wb.example" }),
    });
    assert.equal(missing.status, 404);
    assert.equal((await missing.json()).error.code, "local_signin_not_found");
    assert.equal(
      fake.requests.filter((request) => request.path === "/api/v1/share/workbuddy/import").length,
      sentBefore,
      "nothing is sent up for an account this computer doesn't have",
    );

    // and a provider that isn't WorkBuddy is refused
    const refused = await fetch(`${base}/v1/share/workbuddy/import`, {
      method: "POST", headers, body: JSON.stringify({ provider: "cursor", account: "138****1234" }),
    });
    assert.equal(refused.status, 422);
  } finally {
    started.close();
    fake.server.close();
  }
});

test("the administrator ticks which shared WorkBuddy models are handed out", async () => {
  const fake = await fakeCorp(({ path: requestPath, method, body }) => {
    if (requestPath === "/api/v1/admin/workbuddy" && method === "GET") {
      return {
        body: {
          serving: true,
          sources: [{
            provider: "workbuddy", name: "WorkBuddy（国内版）",
            models: ["wb-1", "wb-3"], selected: ["wb-1"],
            accounts: [{ account: "alice@wb.example", email: "a@corp.example" }],
          }],
        },
      };
    }
    if (requestPath === "/api/v1/admin/workbuddy" && method === "PUT") {
      return { body: { serving: true, sources: [{ provider: body.provider, models: ["wb-1", "wb-3"], selected: body.models }] } };
    }
    return null;
  });
  const { started, base } = await service({ baseUrl: fake.base });
  const headers = { "x-page-token": started.token(), "content-type": "application/json" };
  try {
    const listed = await fetch(`${base}/v1/admin/workbuddy`, { headers });
    assert.equal(listed.status, 200);
    const shared = await listed.json();
    assert.deepEqual(shared.sources[0].models, ["wb-1", "wb-3"]);
    assert.deepEqual(shared.sources[0].selected, ["wb-1"]);

    const put = await fetch(`${base}/v1/admin/workbuddy`, {
      method: "PUT", headers,
      body: JSON.stringify({ provider: "workbuddy", models: ["wb-3"] }),
    });
    assert.equal(put.status, 200);
    assert.deepEqual((await put.json()).sources[0].selected, ["wb-3"]);
    const sent = fake.requests.find((request) => request.method === "PUT");
    assert.deepEqual(sent.body, { provider: "workbuddy", models: ["wb-3"] });
    assert.equal(sent.authorization, "Bearer secret-token", "the service asks as this device");

    const bad = await fetch(`${base}/v1/admin/workbuddy`, {
      method: "PUT", headers,
      body: JSON.stringify({ provider: "not-workbuddy", models: [] }),
    });
    assert.equal(bad.status, 422);
    assert.equal(fake.requests.filter((request) => request.method === "PUT").length, 1,
      "a provider this corporation doesn't share is refused here");
  } finally {
    started.close();
    fake.server.close();
  }
});

test("sharing native providers sends their keys upward but never answers with them", async () => {
  const fake = await fakeCorp(({ path: requestPath, method }) => {
    if (requestPath === "/api/v1/admin/sharing" && method === "PUT") {
      return {
        body: {
          sharing: {
            mode: "native",
            updatedAt: "2026-11-16T00:00:00.000Z",
            catalog: ["alpha-1"],
            sources: [{ id: "alpha", name: "Alpha", models: ["alpha-1"], modelCount: 1, keyCount: 1, keyMasked: "…secret" }],
          },
          catalog: ["alpha-1"],
        },
      };
    }
    return null;
  });
  const { started, base, dir } = await service({ baseUrl: fake.base });
  try {
    fs.writeFileSync(
      path.join(dir, "providers.json"),
      JSON.stringify({
        providers: [{
          id: "alpha", name: "Alpha", chat: "https://api.alpha.example/v1",
          key: "sk-native-secret", models: ["alpha-1"],
        }],
      }),
    );
    const response = await fetch(`${base}/v1/admin/share/native`, {
      method: "POST",
      headers: { "x-page-token": started.token(), "content-type": "application/json" },
      body: JSON.stringify({ ids: ["alpha"] }),
    });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.sharing.mode, "native");
    assert.ok(!JSON.stringify(body).includes("sk-native-secret"), "the answer never repeats the key");
    const sent = fake.requests.find((request) => request.path === "/api/v1/admin/sharing");
    assert.equal(sent.body.mode, "native");
    assert.equal(sent.body.providers[0].key, "sk-native-secret", "the gateway needs the key");
  } finally {
    started.close();
    fake.server.close();
  }
});

test("the administrator's per-person key edits are passed to the corporate server", async () => {
  const fake = await fakeCorp(({ path: requestPath, method, body }) => {
    if (requestPath === "/api/v1/admin/people" && method === "GET") {
      return {
        body: {
          people: [{
            id: "usr_1", email: "alice@corp.example", role: "member",
            devices: [{ id: "dev_1", name: "PC", key: { id: "key_1", name: "corp:alice", models: ["alpha-1"], state: "enabled", revision: "r1" } }],
          }],
          catalog: ["alpha-1"],
        },
      };
    }
    if (requestPath === "/api/v1/admin/people/dev_1" && method === "PATCH") {
      return { body: { key: { id: "key_1", name: "corp:alice", models: body.models || [] }, deviceId: "dev_1" } };
    }
    return null;
  });
  const { started, base } = await service({ baseUrl: fake.base });
  try {
    const listed = await fetch(`${base}/v1/admin/people`, { headers: { "x-page-token": started.token() } });
    assert.equal(listed.status, 200);
    const people = await listed.json();
    assert.equal(people.people[0].devices[0].key.id, "key_1");

    const patch = { models: ["alpha-1", "alpha-2"], readOnly: true, limit: { period: "month", cost: 5 } };
    const saved = await fetch(`${base}/v1/admin/people/dev_1`, {
      method: "PATCH",
      headers: { "x-page-token": started.token(), "content-type": "application/json" },
      body: JSON.stringify(patch),
    });
    assert.equal(saved.status, 200);
    const forwarded = fake.requests.find((request) => request.method === "PATCH");
    assert.deepEqual(forwarded.body, patch, "only the fields the page may set are forwarded");
  } finally {
    started.close();
    fake.server.close();
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
    assert.match(await response.text(), /登录失败/);
  } finally {
    started.close();
  }
});
