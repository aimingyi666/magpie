import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { createEnterpriseAuthServer } from "../src/service.js";
import { pkceChallenge } from "../src/security.js";
import { JsonStore } from "../src/store.js";
import { validateLimits, validateModels } from "../src/policy.js";

function listen(server, host = "127.0.0.1") {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, () => {
      server.off("error", reject);
      resolve(`http://${host}:${server.address().port}`);
    });
  });
}

function close(server) {
  return new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close(resolve);
    server.closeAllConnections?.();
  });
}

async function jsonBody(response) {
  return response.json();
}

class CookieJar {
  constructor() {
    this.cookies = new Map();
  }

  absorb(response) {
    const values = response.headers.getSetCookie ? response.headers.getSetCookie() : [];
    for (const value of values) {
      const [pair, ...attributes] = value.split(";");
      const separator = pair.indexOf("=");
      const name = pair.slice(0, separator).trim();
      const content = pair.slice(separator + 1).trim();
      const expired = attributes.some((attribute) => /^\s*max-age=0\s*$/i.test(attribute));
      if (expired) this.cookies.delete(name);
      else this.cookies.set(name, content);
    }
  }

  header() {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }
}

function createMockOidc() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = "test-key";
  jwk.use = "sig";
  jwk.alg = "RS256";
  const codes = new Map();
  const clientId = "magpie-enterprise-test";
  const clientSecret = "test-oidc-client-secret-0123456789abcdef";
  let base = "";

  function token(claims) {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "test-key" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const signature = crypto.sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), privateKey).toString("base64url");
    return `${header}.${payload}.${signature}`;
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, base || "http://localhost");
    if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        issuer: base,
        authorization_endpoint: `${base}/authorize`,
        token_endpoint: `${base}/token`,
        jwks_uri: `${base}/jwks`,
      }));
      return;
    }
    if (req.method === "GET" && url.pathname === "/jwks") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    if (req.method === "GET" && url.pathname === "/authorize") {
      const code = `oidc_${crypto.randomBytes(18).toString("base64url")}`;
      codes.set(code, {
        redirectUri: url.searchParams.get("redirect_uri"),
        nonce: url.searchParams.get("nonce"),
        codeChallenge: url.searchParams.get("code_challenge"),
        createdAt: Date.now(),
      });
      const target = new URL(url.searchParams.get("redirect_uri"));
      target.searchParams.set("code", code);
      target.searchParams.set("state", url.searchParams.get("state"));
      res.writeHead(302, { location: target.toString() });
      res.end();
      return;
    }
    if (req.method === "POST" && url.pathname === "/token") {
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const form = new URLSearchParams(raw);
      const basic = /^Basic\s+(.+)$/i.exec(String(req.headers.authorization || ""));
      const supplied = basic ? Buffer.from(basic[1], "base64").toString("utf8") : "";
      const expected = `${clientId}:${clientSecret}`;
      const code = codes.get(form.get("code"));
      const pkceOk = code && pkceChallenge(form.get("code_verifier") || "") === code.codeChallenge;
      if (!code || !pkceOk || Date.now() - code.createdAt > 60000 || supplied !== expected) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "invalid_grant" }));
        return;
      }
      codes.delete(form.get("code"));
      const now = Math.floor(Date.now() / 1000);
      const idToken = token({
        iss: base,
        aud: clientId,
        sub: "employee-alice",
        email: "alice@corp.example",
        name: "Alice Zhang",
        nonce: code.nonce,
        iat: now,
        exp: now + 300,
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        access_token: "mock-access-token",
        token_type: "Bearer",
        expires_in: 300,
        id_token: idToken,
      }));
      return;
    }
    res.writeHead(404);
    res.end();
  });

  return {
    server,
    clientId,
    clientSecret,
    get base() { return base; },
    setBase(value) { base = value; },
  };
}

function createMockMagpie(issuerKey) {
  const issued = new Map();
  const revoked = [];
  const issuances = new Map();
  let issueAttempts = 0;
  let sequence = 0;
  const server = http.createServer(async (req, res) => {
    if (req.headers.authorization !== `Bearer ${issuerKey}`) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "bad issuer" } }));
      return;
    }
    const url = new URL(req.url, "http://localhost");
    if (req.method === "POST" && url.pathname === "/v1/magpie/keys") {
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const body = JSON.parse(raw);
      issueAttempts += 1;
      const fingerprint = JSON.stringify(body);
      const existing = issuances.get(body.enterpriseIssuanceId);
      if (existing) {
        if (existing.fingerprint !== fingerprint) {
          res.writeHead(409, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: { message: "enterpriseIssuanceId conflict" } }));
          return;
        }
        res.writeHead(201, { "content-type": "application/json" });
        res.end(JSON.stringify(existing.record));
        return;
      }
      sequence += 1;
      const id = `key-${sequence}`;
      const record = {
        id,
        name: body.name,
        key: `sk-magpie-issued-${sequence}-${crypto.randomBytes(8).toString("hex")}`,
        expires: new Date(Date.now() + Number(body.ttl) * 1000).toISOString(),
        models: body.models,
      };
      issued.set(id, record);
      if (body.enterpriseIssuanceId) {
        issuances.set(body.enterpriseIssuanceId, { fingerprint, record: structuredClone(record) });
      }
      res.writeHead(201, { "content-type": "application/json" });
      res.end(JSON.stringify(record));
      return;
    }
    const match = /^\/v1\/magpie\/keys\/([^/]+)$/.exec(url.pathname);
    if (req.method === "DELETE" && match) {
      if (!issued.has(match[1])) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { message: "not found" } }));
        return;
      }
      issued.delete(match[1]);
      revoked.push(match[1]);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ revoked: match[1] }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  return {
    server,
    issued,
    revoked,
    issuances,
    get issueAttempts() { return issueAttempts; },
    setBase(value) { this.base = value; },
    base: "",
  };
}

function createMockGatewayControl(expectedToken) {
  const keys = new Map();
  const applyCalls = [];
  const failures = {
    timeoutOnce: false,
    mismatchOnce: false,
    rejectApplyOnce: false,
  };
  let requestSequence = 0;

  function revision() {
    return `sha256:${crypto.createHash("sha256").update(crypto.randomUUID()).digest("hex")}`;
  }

  function keyState(id) {
    if (!keys.has(id)) {
      keys.set(id, {
        name: `Gateway key ${id}`,
        state: "enabled",
        readOnly: false,
        policyRevision: revision(),
        models: ["deepseek/deepseek-chat"],
        limits: [],
        observedAt: new Date().toISOString(),
      });
    }
    return keys.get(id);
  }

  function describe(id) {
    const state = keyState(id);
    state.observedAt = new Date().toISOString();
    return {
      schemaVersion: 1,
      ok: true,
      key: {
        id,
        name: state.name,
        state: state.state,
        readOnly: state.readOnly,
      },
      models: { mode: "restricted", patterns: [...state.models] },
      limits: structuredClone(state.limits),
      accounts: { restricted: false },
      policyRevision: state.policyRevision,
      observedAt: state.observedAt,
    };
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    if (req.headers.authorization !== `Bearer ${expectedToken}`) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { code: "invalid_gateway_control_token" } }));
      return;
    }
    const getMatch = /^\/api\/v1\/gateway-keys\/([^/]+)$/.exec(url.pathname);
    if (req.method === "GET" && getMatch) {
      const payload = describe(decodeURIComponent(getMatch[1]));
      if (failures.mismatchOnce) {
        failures.mismatchOnce = false;
        payload.models.patterns = ["wrong/model"];
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
      return;
    }
    const applyMatch = /^\/api\/v1\/gateway-keys\/([^/]+)\/policy$/.exec(url.pathname);
    if (req.method === "POST" && applyMatch) {
      let raw = "";
      for await (const chunk of req) raw += chunk;
      const body = JSON.parse(raw);
      const id = decodeURIComponent(applyMatch[1]);
      applyCalls.push({ id, body: structuredClone(body) });
      if (failures.timeoutOnce) {
        failures.timeoutOnce = false;
        await new Promise((resolve) => setTimeout(resolve, 250));
        res.writeHead(504, { "content-type": "application/json" });
        res.end(JSON.stringify({
          state: "pending",
          error: { code: "apply_unknown", message: "apply timed out" },
        }));
        return;
      }
      if (failures.rejectApplyOnce) {
        failures.rejectApplyOnce = false;
        res.writeHead(409, { "content-type": "application/json" });
        res.end(JSON.stringify({
          state: "failed",
          error: { code: "revision_conflict", message: "policy revision changed" },
        }));
        return;
      }
      const state = keyState(id);
      if (body.schemaVersion !== 1 || body.expectedPolicyRevision !== state.policyRevision) {
        res.writeHead(409, { "content-type": "application/json" });
        res.end(JSON.stringify({
          state: "failed",
          error: { code: "revision_conflict", message: "policy revision changed" },
        }));
        return;
      }
      state.models = body.models.map(String);
      state.limits = structuredClone(body.limits);
      state.policyRevision = revision();
      state.observedAt = new Date().toISOString();
      requestSequence += 1;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        schemaVersion: 1,
        ok: true,
        state: "applied",
        requestId: `req_${requestSequence}`,
        readback: {
          verified: true,
          observedAt: state.observedAt,
          policyRevision: state.policyRevision,
        },
      }));
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: { code: "not_found" } }));
  });

  return {
    server,
    keys,
    applyCalls,
    failures,
    get base() { return this._base || ""; },
    set base(value) { this._base = value; },
  };
}

async function fixture() {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-auth-test-"));
  const oidc = createMockOidc();
  oidc.setBase(await listen(oidc.server));
  const issuerKey = "issuer-key-abcdefghijklmnopqrstuvwxyz-123456";
  const magpie = createMockMagpie(issuerKey);
  magpie.base = await listen(magpie.server);
  const gatewayControlToken = "gateway-control-service-token-for-tests-0001";
  const gatewayControl = createMockGatewayControl(gatewayControlToken);
  gatewayControl.base = await listen(gatewayControl.server);
  const cookieSecret = "test-cookie-secret-0123456789abcdef";
  const adminToken = "test-admin-token-0123456789abcdef";
  const internalAdminToken = "{{SECRET_internal_admin_service_token}}";
  const config = loadConfig({
    AUTH_PUBLIC_URL: "http://127.0.0.1:3999",
    AUTH_PORT: "3999",
    AUTH_STORE_PATH: path.join(temp, "auth-store.json"),
    AUTH_COOKIE_SECRET: cookieSecret,
    AUTH_ADMIN_TOKEN: adminToken,
    AUTH_INTERNAL_ADMIN_TOKEN: internalAdminToken,
    AUTH_SECURE_COOKIE: "false",
    AUTH_RATE_LIMIT_PER_MINUTE: "1000",
    OIDC_ISSUER: oidc.base,
    OIDC_CLIENT_ID: oidc.clientId,
    OIDC_CLIENT_SECRET: oidc.clientSecret,
    OIDC_REDIRECT_URI: "http://127.0.0.1:3999/oauth/callback",
    OIDC_ALLOWED_EMAIL_DOMAINS: "corp.example",
    MAGPIE_GATEWAY_URL: magpie.base,
    MAGPIE_GATEWAY_PUBLIC_URL: "https://ai.corp.example",
    MAGPIE_ISSUER_KEY: issuerKey,
    GATEWAY_CONTROL_URL: gatewayControl.base,
    GATEWAY_CONTROL_TOKEN: gatewayControlToken,
    GATEWAY_CONTROL_TIMEOUT_MS: "500",
    MAGPIE_KEY_TTL: "8h",
    MAGPIE_KEY_MODELS: "deepseek/deepseek-chat",
    AUTH_DEVICE_TOKEN_TTL_DAYS: "30",
  });
  const auth = await createEnterpriseAuthServer(config);
  await auth.startupRecovery;
  const authBase = await listen(auth.server);
  const authPort = new URL(authBase).port;
  config.publicUrl = authBase;
  config.port = Number(authPort);
  config.oidc.redirectUri = `${authBase}/oauth/callback`;
  return {
    temp,
    oidc,
    magpie,
    gatewayControl,
    auth,
    config,
    authBase,
    issues: { adminToken, internalAdminToken, issuerKey, gatewayControlToken },
    async close() {
      await close(auth.server);
      await close(oidc.server);
      await close(magpie.server);
      await close(gatewayControl.server);
      await fs.rm(temp, { recursive: true, force: true });
    },
  };
}

async function oidcLogin(authBase, jar, returnTo = "") {
  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = pkceChallenge(verifier);
  const localCallback = returnTo || "http://127.0.0.1:45678/callback";
  const login = new URL(`${authBase}/login`);
  login.searchParams.set("return_to", localCallback);
  login.searchParams.set("state", "client-state");
  login.searchParams.set("code_challenge", challenge);

  const started = await fetch(login, { redirect: "manual" });
  jar.absorb(started);
  assert.equal(started.status, 302);
  const authorize = await fetch(started.headers.get("location"), {
    redirect: "manual",
    headers: { cookie: jar.header() },
  });
  assert.equal(authorize.status, 302);
  const callbackUrl = authorize.headers.get("location");
  const callback = await fetch(callbackUrl, {
    redirect: "manual",
    headers: { cookie: jar.header() },
  });
  jar.absorb(callback);
  assert.equal(callback.status, 302);
  const joined = new URL(callback.headers.get("location"));
  assert.equal(joined.searchParams.get("state"), "client-state");
  return {
    verifier,
    code: joined.searchParams.get("code"),
    location: joined.toString(),
  };
}

async function internalJson(f, pathname, method, body, headers = {}) {
  const response = await fetch(`${f.authBase}${pathname}`, {
    method,
    headers: {
      authorization: `Bearer ${f.issues.internalAdminToken}`,
      "content-type": "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  });
  return { response, body: await jsonBody(response) };
}

function operationId(label = "test") {
  return `op_${label}_${crypto.randomUUID()}`;
}

async function exchangeJoin(f, login, name) {
  const response = await fetch(`${f.authBase}/api/v1/join/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      code: login.code,
      codeVerifier: login.verifier,
      device: {
        name,
        platform: "windows",
        clientVersion: "1.0.0",
      },
    }),
  });
  return { response, body: await jsonBody(response) };
}

async function userByEmail(f, email = "alice@corp.example") {
  return f.auth.store.read(
    (data) => structuredClone(Object.values(data.users).find((user) => user.email === email)),
  );
}

async function initializePolicy(
  f,
  userId,
  { models = ["deepseek/deepseek-chat"], limits = [] } = {},
) {
  let user = await f.auth.store.read((data) => structuredClone(data.users[userId]));
  if (!user) throw new Error(`missing test user ${userId}`);
  if (!Array.isArray(user.gatewayPolicy.models)) {
    const modelsWrite = await internalJson(
      f,
      `/api/v1/internal/admin/users/${userId}/policy/models`,
      "PATCH",
      {
        expectedVersion: user.gatewayPolicy.version,
        operationId: `op_test_models_${crypto.randomUUID()}`,
        models,
      },
    );
    assert.equal(modelsWrite.response.status, 200, JSON.stringify(modelsWrite.body));
    user = await f.auth.store.read((data) => structuredClone(data.users[userId]));
  }
  if (!Array.isArray(user.gatewayPolicy.limits)) {
    const quotaWrite = await internalJson(
      f,
      `/api/v1/internal/admin/users/${userId}/policy/quota`,
      "PUT",
      {
        expectedVersion: user.gatewayPolicy.version,
        operationId: `op_test_quota_${crypto.randomUUID()}`,
        limits,
      },
    );
    assert.equal(quotaWrite.response.status, 200, JSON.stringify(quotaWrite.body));
  }
  return f.auth.store.read((data) => structuredClone(data.users[userId].gatewayPolicy));
}

async function joinDevice(f, name = "Alice PC") {
  const jar = new CookieJar();
  const login = await oidcLogin(f.authBase, jar);
  const user = await userByEmail(f);
  await initializePolicy(f, user.id);
  const exchanged = await fetch(`${f.authBase}/api/v1/join/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      code: login.code,
      codeVerifier: login.verifier,
      device: {
        name,
        platform: "windows",
        clientVersion: "1.0.0",
      },
    }),
  });
  assert.equal(exchanged.status, 201);
  return jsonBody(exchanged);
}

async function browserLogin(f) {
  const jar = new CookieJar();
  const started = await fetch(`${f.authBase}/login`, { redirect: "manual" });
  jar.absorb(started);
  assert.equal(started.status, 302);
  const authorized = await fetch(started.headers.get("location"), {
    redirect: "manual",
    headers: { cookie: jar.header() },
  });
  assert.equal(authorized.status, 302);
  const callback = await fetch(authorized.headers.get("location"), {
    redirect: "manual",
    headers: { cookie: jar.header() },
  });
  jar.absorb(callback);
  assert.equal(callback.status, 302);
  assert.equal(callback.headers.get("location"), "/");
  return jar;
}

function internalAction(f, pathname) {
  return fetch(`${f.authBase}${pathname}`, {
    method: "POST",
    headers: { authorization: `Bearer ${f.issues.internalAdminToken}` },
  });
}

function assertNoPrivateValues(value, f, extra = []) {
  const text = JSON.stringify(value);
  for (const secret of [
    f.issues.internalAdminToken,
    f.issues.adminToken,
    f.issues.issuerKey,
    ...extra,
  ].filter(Boolean)) {
    assert.ok(!text.includes(secret));
  }
  assert.ok(!text.includes("tokenHash"));
  assert.ok(!text.includes("BEGIN PUBLIC KEY"));
}

test("OIDC join, device lifecycle, revocation and session", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  const invalidKeyJar = new CookieJar();
  const invalidKeyLogin = await oidcLogin(f.authBase, invalidKeyJar);
  const invalidKey = await fetch(`${f.authBase}/api/v1/join/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      code: invalidKeyLogin.code,
      codeVerifier: invalidKeyLogin.verifier,
      device: {
        name: "Invalid Key PC",
        platform: "windows",
        clientVersion: "1.0.0",
        publicKey: "-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----",
      },
    }),
  });
  assert.equal(invalidKey.status, 400);
  assert.equal((await jsonBody(invalidKey)).error.code, "invalid_public_key");

  const jar = new CookieJar();
  const login = await oidcLogin(f.authBase, jar);
  assert.match(login.code, /^mjoin_/);
  const policyUser = await userByEmail(f);
  await initializePolicy(f, policyUser.id);

  const wrong = await fetch(`${f.authBase}/api/v1/join/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      code: login.code,
      codeVerifier: crypto.randomBytes(48).toString("base64url"),
      device: { name: "Alice PC", platform: "windows", clientVersion: "1.0.0" },
    }),
  });
  assert.equal(wrong.status, 400);
  assert.equal((await jsonBody(wrong)).error.code, "pkce_mismatch");

  const deviceKeys = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const devicePublicKey = deviceKeys.publicKey.export({ type: "spki", format: "pem" });
  const exchanged = await fetch(`${f.authBase}/api/v1/join/exchange`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      code: login.code,
      codeVerifier: login.verifier,
      device: {
        name: "Alice PC",
        platform: "windows",
        clientVersion: "1.0.0",
        publicKey: devicePublicKey,
      },
    }),
  });
  assert.equal(exchanged.status, 201);
  const joined = await jsonBody(exchanged);
  assert.equal(joined.user.email, "alice@corp.example");
  assert.equal(joined.gateway.url, "https://ai.corp.example");
  assert.match(joined.gateway.key, /^sk-magpie-issued-/);
  assert.match(joined.deviceToken, /^mdev_/);
  assert.ok(Number.isSafeInteger(joined.policyVersion));

  const heartbeat = await fetch(`${f.authBase}/api/v1/devices/heartbeat`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${joined.deviceToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ clientVersion: "1.0.1" }),
  });
  assert.equal(heartbeat.status, 200);
  assert.equal((await jsonBody(heartbeat)).ok, true);

  const refreshCount = f.magpie.issued.size;
  const originalMutate = f.auth.store.mutate.bind(f.auth.store);
  f.auth.store.mutate = async () => {
    f.auth.store.mutate = originalMutate;
    throw new Error("injected durable store failure");
  };
  const failedRefresh = await fetch(`${f.authBase}/api/v1/devices/refresh`, {
    method: "POST",
    headers: { authorization: `Bearer ${joined.deviceToken}` },
  });
  assert.equal(failedRefresh.status, 500);
  assert.equal(f.magpie.issued.size, refreshCount);

  const refreshed = await fetch(`${f.authBase}/api/v1/devices/refresh`, {
    method: "POST",
    headers: { authorization: `Bearer ${joined.deviceToken}` },
  });
  assert.equal(refreshed.status, 200);
  const refreshBody = await jsonBody(refreshed);
  assert.notEqual(refreshBody.gateway.keyId, joined.gateway.keyId);
  assert.ok(f.magpie.revoked.includes(joined.gateway.keyId));

  const users = await fetch(`${f.authBase}/api/v1/admin/users`, {
    headers: { authorization: `Bearer ${f.issues.adminToken}` },
  });
  assert.equal(users.status, 200);
  const user = (await jsonBody(users)).users[0];
  assert.equal(user.email, "alice@corp.example");

  const browserJar = new CookieJar();
  const browserLogin = new URL(`${f.authBase}/login`);
  const browserStart = await fetch(browserLogin, { redirect: "manual" });
  browserJar.absorb(browserStart);
  const browserAuthorize = await fetch(browserStart.headers.get("location"), {
    redirect: "manual",
    headers: { cookie: browserJar.header() },
  });
  const browserCallback = await fetch(browserAuthorize.headers.get("location"), {
    redirect: "manual",
    headers: { cookie: browserJar.header() },
  });
  browserJar.absorb(browserCallback);
  assert.equal(browserCallback.status, 302);
  assert.equal(browserCallback.headers.get("location"), "/");
  const me = await fetch(`${f.authBase}/api/v1/me`, { headers: { cookie: browserJar.header() } });
  assert.equal(me.status, 200);
  assert.equal((await jsonBody(me)).user.email, "alice@corp.example");

  await f.auth.store.mutate((data) => {
    const device = data.devices[joined.device.id];
    device.tokenExpiresAt = new Date(Date.now() - 1000).toISOString();
  });
  const expired = await fetch(`${f.authBase}/api/v1/devices/heartbeat`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${joined.deviceToken}`,
      "content-type": "application/json",
    },
    body: "{}",
  });
  assert.equal(expired.status, 401);
  assert.equal((await jsonBody(expired)).error.code, "device_token_expired");

  const disabled = await fetch(`${f.authBase}/api/v1/admin/users/${user.id}/disable`, {
    method: "POST",
    headers: { authorization: `Bearer ${f.issues.adminToken}` },
  });
  assert.equal(disabled.status, 200);
  assert.ok(f.magpie.revoked.includes(refreshBody.gateway.keyId));

  const denied = await fetch(`${f.authBase}/api/v1/devices/heartbeat`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${joined.deviceToken}`,
      "content-type": "application/json",
    },
    body: "{}",
  });
  assert.equal(denied.status, 403);

  const retained = await fs.readFile(f.config.storePath, "utf8");
  assert.ok(!retained.includes(joined.gateway.key));
  assert.ok(!retained.includes(joined.deviceToken));
  assert.ok(!retained.includes(f.issues.issuerKey));
  assert.equal(f.auth.handoffs.size, 0);
});

test("employee portal shows only the signed-in user's policy and credential evidence", {
  timeout: 30000,
}, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  const joined = await joinDevice(f, "Alice Portal PC");
  const alice = await userByEmail(f);
  await f.auth.store.mutate((data) => {
    data.users.usr_bob = {
      id: "usr_bob",
      subject: "employee-bob",
      email: "bob@corp.example",
      name: "Bob Private",
      status: "active",
      createdAt: "2026-10-01T00:00:00.000Z",
      lastLoginAt: "2026-10-31T00:00:00.000Z",
      gatewayPolicy: {
        version: 1,
        limits: [{ period: "month", tokens: 999999, cost: 99 }],
        models: ["private/bob-model"],
        quotaStatus: "known",
        modelStatus: "known",
        including: ["quota", "models"],
        missing: [],
        updatedAt: "2026-10-31T00:00:00.000Z",
        confirmedAt: "2026-10-31T00:01:00.000Z",
        operationId: "op_bob_private",
      },
    };
    data.devices.dev_bob_private = {
      id: "dev_bob_private",
      userId: "usr_bob",
      name: "Bob Private PC",
      platform: "windows",
      clientVersion: "9.9.9",
      status: "active",
      createdAt: "2026-10-31T00:00:00.000Z",
      lastSeenAt: "2026-10-31T01:00:00.000Z",
      gatewayKeyId: "key-bob-private",
      gatewayKeyExpiresAt: "2026-11-01T00:00:00.000Z",
      tokenHash: "bob-token-hash-must-not-leak",
    };
    data.credentials["key-bob-private"] = {
      id: "key-bob-private",
      userId: "usr_bob",
      deviceId: "dev_bob_private",
      status: "active",
      createdAt: "2026-10-31T00:00:00.000Z",
      expiresAt: "2026-11-01T00:00:00.000Z",
      policyVersion: 1,
      policySyncState: "synced",
      lastPolicySyncedAt: "2026-10-31T00:01:00.000Z",
    };
  });

  const jar = await browserLogin(f);
  const me = await fetch(`${f.authBase}/api/v1/me`, { headers: { cookie: jar.header() } });
  assert.equal(me.status, 200);
  const body = await jsonBody(me);
  assert.equal(body.user.email, "alice@corp.example");
  assert.ok(body.devices.every((device) => device.userId === alice.id));
  assert.ok(body.credentials.every((credential) => credential.userId === alice.id));
  assert.equal(body.evidence.policyKnown, true);
  assert.equal(body.evidence.activeCredentialsSynced, true);
  assert.ok(body.evidence.activeCredentialCount >= 1);
  assertNoPrivateValues(body, f, [joined.gateway.key, joined.deviceToken]);
  assert.ok(!JSON.stringify(body).includes("Bob Private"));
  assert.ok(!JSON.stringify(body).includes("bob-token-hash-must-not-leak"));

  const page = await fetch(`${f.authBase}/`, { headers: { cookie: jar.header() } });
  assert.equal(page.status, 200);
  const html = await page.text();
  for (const expected of [
    "alice@corp.example",
    "Alice Portal PC",
    "deepseek/deepseek-chat",
    "Policy confirmed after independent gateway readback.",
    "Credentials",
    "Devices",
    "The browser never writes Agent files",
  ]) {
    assert.ok(html.includes(expected), `page should include ${expected}`);
  }
  assert.ok(!html.includes("Bob Private"));
  assert.ok(!html.includes("private/bob-model"));
  assert.ok(!html.includes(joined.gateway.key));
  assert.ok(!html.includes(joined.deviceToken));
  assert.ok(!html.includes("tokenHash"));
});

test("employee portal labels historical quota and model scope as unknown", {
  timeout: 30000,
}, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  const jar = await browserLogin(f);
  const me = await fetch(`${f.authBase}/api/v1/me`, { headers: { cookie: jar.header() } });
  assert.equal(me.status, 200);
  const body = await jsonBody(me);
  assert.equal(body.evidence.policyKnown, false);
  assert.equal(body.evidence.activeCredentialsSynced, false);
  assert.equal(body.evidence.activeCredentialCount, 0);

  const page = await fetch(`${f.authBase}/`, { headers: { cookie: jar.header() } });
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.ok(html.includes("Historical quota unknown."));
  assert.ok(html.includes("Historical model scope unknown."));
  assert.ok(!html.includes("Policy confirmed after independent gateway readback."));
  assert.ok(!html.includes("tokens, $"));
});

test("internal admin status requires its own service token", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  for (const pathname of ["status", "users", "devices", "credentials"]) {
    const missing = await fetch(`${f.authBase}/api/v1/internal/admin/${pathname}`);
    assert.equal(missing.status, 401);
    assert.equal((await jsonBody(missing)).error.code, "invalid_service_token");

    const wrong = await fetch(`${f.authBase}/api/v1/internal/admin/${pathname}`, {
      headers: { authorization: `Bearer ${f.issues.adminToken}` },
    });
    assert.equal(wrong.status, 401);
    assert.equal((await jsonBody(wrong)).error.code, "invalid_service_token");
  }

  const status = await fetch(`${f.authBase}/api/v1/internal/admin/status`, {
    headers: { authorization: `Bearer ${f.issues.internalAdminToken}` },
  });
  assert.equal(status.status, 200);
  assert.deepEqual(await jsonBody(status), {
    ok: true,
    service: "auth",
    users: 0,
    devices: 0,
    credentials: 0,
    pendingRevocations: 0,
    activeCredentials: 0,
    pendingPolicyCredentials: 0,
    failedPolicyCredentials: 0,
    unknownPolicyCredentials: 0,
    unknownPolicyUsers: 0,
    pendingPolicyUsers: 0,
    knownPolicyUsers: 0,
    issuanceJournal: {
      preparing: 0,
      issued: 0,
      syncing: 0,
      synced: 0,
      committed: 0,
      failed: 0,
      unknown: 0,
    },
  });

  for (const collection of ["users", "devices", "credentials"]) {
    const response = await fetch(`${f.authBase}/api/v1/internal/admin/${collection}`, {
      headers: { authorization: `Bearer ${f.issues.internalAdminToken}` },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await jsonBody(response), { ok: true, [collection]: [] });
  }
});

test("credential metadata follows refresh and revocation without exposing secrets", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const joined = await joinDevice(f, "Credential Lifecycle PC");

  async function credentials() {
    const response = await fetch(`${f.authBase}/api/v1/internal/admin/credentials`, {
      headers: { authorization: `Bearer ${f.issues.internalAdminToken}` },
    });
    assert.equal(response.status, 200);
    return (await jsonBody(response)).credentials;
  }

  const initial = await credentials();
  const first = initial.find((credential) => credential.id === joined.gateway.keyId);
  assert.ok(first);
  assert.equal(first.status, "active");
  assert.equal(first.userId, joined.user.id);
  assert.equal(first.deviceId, joined.device.id);
  assert.deepEqual(first.models, ["deepseek/deepseek-chat"]);

  const initialJson = JSON.stringify(initial);
  assert.ok(!initialJson.includes(joined.gateway.key));
  assert.ok(!initialJson.includes(joined.deviceToken));
  assert.ok(!initialJson.includes(f.issues.issuerKey));
  assert.ok(!initialJson.includes("tokenHash"));
  assert.ok(!initialJson.includes("BEGIN PUBLIC KEY"));

  const refreshed = await fetch(`${f.authBase}/api/v1/devices/refresh`, {
    method: "POST",
    headers: { authorization: `Bearer ${joined.deviceToken}` },
  });
  assert.equal(refreshed.status, 200);
  const refreshBody = await jsonBody(refreshed);
  const afterRefresh = await credentials();
  assert.equal(
    afterRefresh.find((credential) => credential.id === joined.gateway.keyId).status,
    "revoked",
  );
  assert.equal(
    afterRefresh.find((credential) => credential.id === refreshBody.gateway.keyId).status,
    "active",
  );

  const revoked = await fetch(`${f.authBase}/api/v1/devices/revoke`, {
    method: "POST",
    headers: { authorization: `Bearer ${joined.deviceToken}` },
  });
  assert.equal(revoked.status, 200);
  const afterRevoke = await credentials();
  assert.ok(afterRevoke
    .filter((credential) => credential.deviceId === joined.device.id)
    .every((credential) => credential.status === "revoked"));

  const second = await joinDevice(f, "Credential Disable PC");
  const users = await fetch(`${f.authBase}/api/v1/admin/users`, {
    headers: { authorization: `Bearer ${f.issues.adminToken}` },
  });
  assert.equal(users.status, 200);
  const user = (await jsonBody(users)).users[0];
  const disabled = await fetch(`${f.authBase}/api/v1/admin/users/${user.id}/disable`, {
    method: "POST",
    headers: { authorization: `Bearer ${f.issues.adminToken}` },
  });
  assert.equal(disabled.status, 200);
  const afterDisable = await credentials();
  assert.equal(
    afterDisable.find((credential) => credential.id === second.gateway.keyId).status,
    "revoked",
  );
});

test("an M1 store without credentials is migrated without inventing history", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-auth-store-"));
  try {
    const file = path.join(temp, "auth-store.json");
    await fs.writeFile(file, JSON.stringify({
      version: 1,
      users: {
        usr_legacy: {
          id: "usr_legacy",
          subject: "legacy",
          email: "legacy@corp.example",
          name: "Legacy",
          status: "active",
          createdAt: "2026-10-01T00:00:00.000Z",
          lastLoginAt: "2026-10-01T00:00:00.000Z",
        },
      },
      devices: {
        dev_legacy: {
          id: "dev_legacy",
          userId: "usr_legacy",
          name: "Legacy PC",
          platform: "windows",
          clientVersion: "1.0.0",
          status: "active",
          createdAt: "2026-10-02T00:00:00.000Z",
          lastSeenAt: "2026-10-02T00:00:00.000Z",
          gatewayKeyId: "key-legacy",
          gatewayKeyExpiresAt: "2026-10-03T00:00:00.000Z",
        },
      },
      sessions: {},
      pendingRevocations: [],
    }), "utf8");

    const store = new JsonStore(file);
    await store.load();
    const migrated = await store.read((data) => structuredClone({
      user: data.users.usr_legacy,
      credential: data.credentials["key-legacy"],
    }));
    assert.deepEqual(migrated.credential, {
      id: "key-legacy",
      userId: "usr_legacy",
      deviceId: "dev_legacy",
      status: "active",
      createdAt: "2026-10-02T00:00:00.000Z",
      expiresAt: "2026-10-03T00:00:00.000Z",
      policyVersion: 0,
      policySyncState: "pending",
      lastPolicyErrorCode: "policy_setup_required",
    });
    assert.equal(migrated.user.gatewayPolicy.quotaStatus, "unknown");
    assert.equal(migrated.user.gatewayPolicy.modelStatus, "unknown");
    assert.equal(migrated.user.gatewayPolicy.version, 0);
    assert.equal(migrated.user.gatewayPolicy.initializationSource, "m1_unknown");
    const stored = JSON.parse(await fs.readFile(file, "utf8"));
    assert.equal(stored.credentials, undefined);
  } finally {
    await fs.rm(temp, { recursive: true, force: true });
  }
});

test("new users need quota and models before joining, in either write order", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  const jar = new CookieJar();
  const login = await oidcLogin(f.authBase, jar);
  const user = await userByEmail(f);
  assert.equal(user.gatewayPolicy.version, 0);
  assert.equal(user.gatewayPolicy.quotaStatus, "unknown");
  assert.equal(user.gatewayPolicy.modelStatus, "unknown");
  assert.equal(user.gatewayPolicy.initializationSource, "new_user_unknown");

  const initialStatus = await fetch(`${f.authBase}/api/v1/internal/admin/status`, {
    headers: { authorization: `Bearer ${f.issues.internalAdminToken}` },
  });
  assert.equal(initialStatus.status, 200);
  assert.equal((await jsonBody(initialStatus)).unknownPolicyUsers, 1);

  const blockedJoin = await exchangeJoin(f, login, "Policy Missing PC");
  assert.equal(blockedJoin.response.status, 409);
  assert.equal(blockedJoin.body.error.code, "policy_setup_required");
  assert.deepEqual(blockedJoin.body.error.missing, ["quota", "models"]);
  assert.equal(f.magpie.issued.size, 0);

  const modelsWrite = await internalJson(
    f,
    `/api/v1/internal/admin/users/${user.id}/policy/models`,
    "PATCH",
    {
      expectedVersion: 0,
      operationId: operationId("models_first"),
      models: ["deepseek/deepseek-chat"],
    },
  );
  assert.equal(modelsWrite.response.status, 200, JSON.stringify(modelsWrite.body));
  assert.equal(modelsWrite.body.data.state, "pending_sync");
  assert.equal(modelsWrite.body.data.requiresReconciliation, true);
  assert.equal(modelsWrite.body.data.policy.version, 1);
  assert.equal(modelsWrite.body.data.policy.quotaStatus, "unknown");
  assert.equal(modelsWrite.body.data.policy.modelStatus, "pending");
  assert.deepEqual(modelsWrite.body.data.policy.including, ["models"]);
  assert.deepEqual(modelsWrite.body.data.policy.missing, ["quota"]);
  assert.deepEqual(modelsWrite.body.data.credentials, {
    total: 0,
    succeeded: 0,
    failed: 0,
    pending: 0,
    unknown: 0,
    failedOnly: 0,
    failedItems: [],
  });
  assertNoPrivateValues(modelsWrite.body, f);

  const secondLogin = await oidcLogin(f.authBase, new CookieJar());
  const stillBlocked = await exchangeJoin(f, secondLogin, "Policy Missing PC 2");
  assert.equal(stillBlocked.response.status, 409);
  assert.equal(stillBlocked.body.error.code, "policy_setup_required");
  assert.deepEqual(stillBlocked.body.error.missing, ["quota"]);
  assert.equal(f.magpie.issued.size, 0);

  const quotaWrite = await internalJson(
    f,
    `/api/v1/internal/admin/users/${user.id}/policy/quota`,
    "PUT",
    {
      expectedVersion: 1,
      operationId: operationId("quota_second"),
      limits: [],
    },
  );
  assert.equal(quotaWrite.response.status, 200, JSON.stringify(quotaWrite.body));
  assert.equal(quotaWrite.body.data.state, "succeeded");
  assert.equal(quotaWrite.body.data.requiresReconciliation, false);
  assert.equal(quotaWrite.body.data.policy.version, 2);
  assert.equal(quotaWrite.body.data.policy.quotaStatus, "known");
  assert.equal(quotaWrite.body.data.policy.modelStatus, "known");
  assert.deepEqual(quotaWrite.body.data.policy.including, ["quota", "models"]);
  assert.deepEqual(quotaWrite.body.data.policy.missing, []);
  assertNoPrivateValues(quotaWrite.body, f);

  const joined = await joinDevice(f, "Policy Ready PC");
  assert.equal(joined.policyVersion, 2);
  assert.deepEqual(joined.gateway.models, ["deepseek/deepseek-chat"]);
  assert.equal(f.magpie.issued.size, 1);

  const finalStatus = await fetch(`${f.authBase}/api/v1/internal/admin/status`, {
    headers: { authorization: `Bearer ${f.issues.internalAdminToken}` },
  });
  assert.equal(finalStatus.status, 200);
  assert.equal((await jsonBody(finalStatus)).unknownPolicyUsers, 0);

  const quotaFirstFixture = await fixture();
  t.after(() => quotaFirstFixture.close());
  const quotaFirstLogin = await oidcLogin(quotaFirstFixture.authBase, new CookieJar());
  assert.ok(quotaFirstLogin.code);
  const quotaFirstUser = await userByEmail(quotaFirstFixture);

  const firstQuota = await internalJson(
    quotaFirstFixture,
    `/api/v1/internal/admin/users/${quotaFirstUser.id}/policy/quota`,
    "PUT",
    {
      expectedVersion: 0,
      operationId: operationId("quota_first"),
      limits: [],
    },
  );
  assert.equal(firstQuota.response.status, 200, JSON.stringify(firstQuota.body));
  assert.equal(firstQuota.body.data.policy.version, 1);
  assert.equal(firstQuota.body.data.policy.quotaStatus, "pending");
  assert.equal(firstQuota.body.data.policy.modelStatus, "unknown");
  assert.deepEqual(firstQuota.body.data.policy.missing, ["models"]);

  const thenModels = await internalJson(
    quotaFirstFixture,
    `/api/v1/internal/admin/users/${quotaFirstUser.id}/policy/models`,
    "PATCH",
    {
      expectedVersion: 1,
      operationId: operationId("models_second"),
      models: ["deepseek/deepseek-chat"],
    },
  );
  assert.equal(thenModels.response.status, 200, JSON.stringify(thenModels.body));
  assert.equal(thenModels.body.data.state, "succeeded");
  assert.equal(thenModels.body.data.policy.version, 2);
  assert.equal(thenModels.body.data.policy.quotaStatus, "known");
  assert.equal(thenModels.body.data.policy.modelStatus, "known");
  assert.deepEqual(thenModels.body.data.policy.missing, []);
});

test("policy reconciliation atomically updates models and limits for every active credential", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  const first = await joinDevice(f, "Reconcile PC One");
  const second = await joinDevice(f, "Reconcile PC Two");
  const user = await userByEmail(f);
  const beforeVersion = user.gatewayPolicy.version;
  const beforeApplyCalls = f.gatewayControl.applyCalls.length;
  const limits = [{ period: "month", tokens: 250000, cost: 12.5, cacheReads: true }];
  const models = ["deepseek/deepseek-chat", "deepseek/deepseek-reasoner"];

  const reconciled = await internalJson(
    f,
    `/api/v1/internal/admin/users/${user.id}/policy/reconcile`,
    "POST",
    {
      expectedVersion: beforeVersion,
      operationId: operationId("reconcile"),
      models,
      limits,
    },
  );
  assert.equal(reconciled.response.status, 200, JSON.stringify(reconciled.body));
  assert.equal(reconciled.body.data.state, "succeeded");
  assert.equal(reconciled.body.data.requiresReconciliation, false);
  assert.equal(reconciled.body.data.policy.version, beforeVersion + 1);
  assert.deepEqual(reconciled.body.data.policy.models, models);
  assert.deepEqual(reconciled.body.data.policy.limits, limits);
  assert.equal(reconciled.body.data.policy.quotaStatus, "known");
  assert.equal(reconciled.body.data.policy.modelStatus, "known");
  assert.equal(reconciled.body.data.credentials.total, 2);
  assert.equal(reconciled.body.data.credentials.succeeded, 2);
  assertNoPrivateValues(reconciled.body, f);

  const stored = await f.auth.store.read((data) => structuredClone({
    policy: data.users[user.id].gatewayPolicy,
    credentials: Object.values(data.credentials).filter(
      (credential) => credential.userId === user.id && credential.status === "active",
    ),
  }));
  assert.equal(stored.policy.version, beforeVersion + 1);
  assert.deepEqual(stored.policy.models, models);
  assert.deepEqual(stored.policy.limits, limits);
  assert.equal(stored.credentials.length, 2);
  assert.ok(stored.credentials.every((credential) => credential.policyVersion === beforeVersion + 1));
  assert.ok(stored.credentials.every((credential) => credential.policySyncState === "synced"));

  const newApplyCalls = f.gatewayControl.applyCalls.slice(beforeApplyCalls);
  assert.equal(newApplyCalls.length, 2);
  assert.equal(new Set(newApplyCalls.map((call) => call.id)).size, 2);
  assert.ok(newApplyCalls.every((call) => JSON.stringify(call.body.models) === JSON.stringify(models)));
  assert.ok(newApplyCalls.every((call) => JSON.stringify(call.body.limits) === JSON.stringify([
    { period: "month", days: 0, hours: 0, tokens: 250000, cost: 12.5, cacheReads: true },
  ])));
  assert.ok([first, second].every((joined) => joined.policyVersion === 2));

  const stale = await internalJson(
    f,
    `/api/v1/internal/admin/users/${user.id}/policy/reconcile`,
    "POST",
    {
      expectedVersion: beforeVersion,
      operationId: operationId("reconcile_stale"),
      models: ["deepseek/deepseek-chat"],
      limits: [],
    },
  );
  assert.equal(stale.response.status, 409);
  assert.equal(stale.body.error.code, "policy_version_conflict");
  assert.equal(stale.body.error.currentVersion, beforeVersion + 1);
  assert.equal(f.gatewayControl.applyCalls.length, beforeApplyCalls + 2);
  assertNoPrivateValues(stale.body, f);
});

test("concurrent policy reconciliation serializes and applies only once", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  await joinDevice(f, "Concurrent Reconcile PC");
  const user = await userByEmail(f);
  const expectedVersion = user.gatewayPolicy.version;
  const beforeApplyCalls = f.gatewayControl.applyCalls.length;
  const base = {
    expectedVersion,
    models: ["deepseek/deepseek-chat"],
    limits: [{ period: "day", tokens: 10000 }],
  };
  const results = await Promise.all([
    internalJson(
      f,
      `/api/v1/internal/admin/users/${user.id}/policy/reconcile`,
      "POST",
      { ...base, operationId: operationId("reconcile_concurrent_a") },
    ),
    internalJson(
      f,
      `/api/v1/internal/admin/users/${user.id}/policy/reconcile`,
      "POST",
      { ...base, operationId: operationId("reconcile_concurrent_b") },
    ),
  ]);
  results.sort((left, right) => left.response.status - right.response.status);
  assert.deepEqual(results.map((result) => result.response.status), [200, 409]);
  assert.equal(results[0].body.data.policy.version, expectedVersion + 1);
  assert.equal(results[1].body.error.code, "policy_version_conflict");
  assert.equal(f.gatewayControl.applyCalls.length, beforeApplyCalls + 1);

  const stored = await f.auth.store.read((data) => structuredClone(data.users[user.id].gatewayPolicy));
  assert.equal(stored.version, expectedVersion + 1);
  assert.deepEqual(stored.limits, [
    { period: "day", tokens: 10000, cost: 0, cacheReads: false },
  ]);
});

test("issuance journal commits only after gateway apply and readback", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  const joined = await joinDevice(f, "Journal Commit PC");
  assert.equal(joined.gateway.keyId, "key-1");
  assert.equal(f.gatewayControl.applyCalls.length, 1);
  assert.deepEqual(f.gatewayControl.applyCalls[0].body.models, ["deepseek/deepseek-chat"]);
  assert.deepEqual(f.gatewayControl.applyCalls[0].body.limits, []);

  const stored = await f.auth.store.read((data) => structuredClone({
    journal: data.issuanceJournal,
    credential: data.credentials[joined.gateway.keyId],
  }));
  assert.equal(stored.journal.length, 1);
  assert.equal(stored.journal[0].state, "committed");
  assert.equal(stored.journal[0].keyId, joined.gateway.keyId);
  assert.equal(stored.journal[0].policyVersion, joined.policyVersion);
  assert.match(stored.journal[0].enterpriseIssuanceId, /^eiss_/);
  assert.match(stored.journal[0].policyRevision, /^sha256:[0-9a-f]{64}$/);
  assert.ok(stored.journal[0].committedAt);
  assert.equal(stored.credential.policySyncState, "synced");
  assert.equal(stored.credential.policyVersion, joined.policyVersion);
  assert.equal(stored.credential.lastPolicyRevision, stored.journal[0].policyRevision);
  assertNoPrivateValues(stored, f);
});

test("gateway apply failure revokes the issued key and never returns it", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  const jar = new CookieJar();
  const login = await oidcLogin(f.authBase, jar);
  const user = await userByEmail(f);
  await initializePolicy(f, user.id);
  f.gatewayControl.failures.rejectApplyOnce = true;

  const failed = await exchangeJoin(f, login, "Journal Failure PC");
  assert.equal(failed.response.status, 409);
  assert.equal(failed.body.error.code, "revision_conflict");
  assert.equal(failed.body.gateway, undefined);

  const stored = await f.auth.store.read((data) => structuredClone({
    journal: data.issuanceJournal,
    credentials: data.credentials,
    devices: data.devices,
  }));
  assert.equal(stored.journal.length, 1);
  assert.equal(stored.journal[0].state, "failed");
  assert.equal(stored.journal[0].errorCode, "revision_conflict");
  assert.equal(stored.journal[0].revocationResult, "revoked");
  assert.ok(stored.journal[0].revokedAt);
  assert.ok(f.magpie.revoked.includes(stored.journal[0].keyId));
  assert.equal(Object.values(stored.credentials).filter((item) => item.status === "active").length, 0);
  assert.equal(Object.values(stored.devices).filter((item) => item.status === "active").length, 0);
  assertNoPrivateValues(stored, f);
});

test("uncertain revocation stays unknown and startup recovery revokes a preparing orphan", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  const jar = new CookieJar();
  const login = await oidcLogin(f.authBase, jar);
  const user = await userByEmail(f);
  await initializePolicy(f, user.id);
  f.gatewayControl.failures.rejectApplyOnce = true;
  const originalRevoke = f.auth.magpie.revoke.bind(f.auth.magpie);
  f.auth.magpie.revoke = async () => {
    throw new Error("injected revoke uncertainty");
  };

  const failed = await exchangeJoin(f, login, "Journal Unknown PC");
  assert.equal(failed.response.status, 409);
  const unknown = await f.auth.store.read(
    (data) => structuredClone(data.issuanceJournal[0]),
  );
  assert.equal(unknown.state, "unknown");
  assert.equal(unknown.revocationResult, "unknown");
  assert.ok(unknown.revocationErrorCode);

  f.auth.magpie.revoke = originalRevoke;
  const orphan = {
    id: "eij_recovery_test",
    enterpriseIssuanceId: "eiss_recovery_test",
    userId: user.id,
    purpose: "join",
    deviceId: "",
    credentialId: "",
    policyVersion: 2,
    policyOperationId: "",
    request: {
      name: "Recovery orphan",
      models: ["deepseek/deepseek-chat"],
      limits: [],
    },
    state: "preparing",
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  await f.auth.store.mutate((data) => {
    data.issuanceJournal.push(orphan);
  });

  const recovery = await f.auth.recoverIssuanceJournal();
  assert.ok(recovery.recovered >= 1);
  const recovered = await f.auth.store.read(
    (data) => structuredClone(data.issuanceJournal.find((entry) => entry.id === orphan.id)),
  );
  assert.equal(recovered.state, "failed");
  assert.equal(recovered.errorCode, "recovered_orphan_revoked");
  assert.equal(recovered.revocationResult, "revoked");
  assert.ok(f.magpie.revoked.includes(recovered.keyId));

  const originalFetch = f.auth.magpie.fetch;
  f.auth.magpie.fetch = async () => {
    throw new TypeError("injected issue transport failure");
  };
  let ambiguous;
  try {
    const secondLogin = await oidcLogin(f.authBase, new CookieJar());
    ambiguous = await exchangeJoin(f, secondLogin, "Network Unknown PC");
  } finally {
    f.auth.magpie.fetch = originalFetch;
  }
  assert.notEqual(ambiguous.response.status, 201);
  const transportUnknown = await f.auth.store.read(
    (data) => structuredClone(data.issuanceJournal.find(
      (entry) => entry.id !== orphan.id && entry.id !== unknown.id,
    )),
  );
  assert.equal(transportUnknown.state, "unknown");
  assert.equal(transportUnknown.errorCode, "magpie_issuance_unknown");
  assert.equal(transportUnknown.keyId, undefined);
});

test("policy writes reject invalid payloads, stale versions and non-object JSON", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const jar = new CookieJar();
  await oidcLogin(f.authBase, jar);
  const user = await userByEmail(f);
  const base = `/api/v1/internal/admin/users/${user.id}/policy`;

  for (const [body, code] of [
    [null, "invalid_request"],
    [[], "invalid_request"],
    [{ operationId: operationId("missing_version"), models: ["deepseek/deepseek-chat"] }, "version_required"],
  ]) {
    const result = await internalJson(f, `${base}/models`, "PATCH", body);
    assert.equal(result.response.status, 400, JSON.stringify(result.body));
    assert.equal(result.body.error.code, code);
  }

  const ifMatchMismatch = await internalJson(
    f,
    `${base}/models`,
    "PATCH",
    {
      expectedVersion: 0,
      operationId: operationId("if_match"),
      models: ["deepseek/deepseek-chat"],
    },
    { "if-match": '"1"' },
  );
  assert.equal(ifMatchMismatch.response.status, 409);
  assert.equal(ifMatchMismatch.body.error.code, "policy_version_conflict");

  const invalidModels = [
    [],
    ["*"],
    ["group/team-a"],
    ["deepseek/*/chat"],
    ["deepseek/"],
    ["deepseek/deepseek chat"],
    ["/deepseek-chat"],
    [`deepseek/${"x".repeat(250)}`],
  ];
  for (const models of invalidModels) {
    const result = await internalJson(f, `${base}/models`, "PATCH", {
      expectedVersion: 0,
      operationId: operationId("bad_models"),
      models,
    });
    assert.equal(result.response.status, 400, JSON.stringify(result.body));
    assert.equal(result.body.error.code, "invalid_models");
  }

  const duplicateModels = await internalJson(f, `${base}/models`, "PATCH", {
    expectedVersion: 0,
    operationId: operationId("dedupe"),
    models: ["deepseek/deepseek-chat", "deepseek/deepseek-chat", "deepseek/*"],
  });
  assert.equal(duplicateModels.response.status, 200, JSON.stringify(duplicateModels.body));
  assert.equal(duplicateModels.body.data.policy.version, 1);
  assert.deepEqual(duplicateModels.body.data.policy.models, [
    "deepseek/deepseek-chat",
    "deepseek/*",
  ]);

  const stale = await internalJson(f, `${base}/models`, "PATCH", {
    expectedVersion: 0,
    operationId: operationId("stale"),
    models: ["deepseek/deepseek-chat"],
  });
  assert.equal(stale.response.status, 409);
  assert.equal(stale.body.error.code, "policy_version_conflict");
  assert.equal(stale.body.error.currentVersion, 1);
  assert.equal(stale.body.error.expectedVersion, 0);

  const staleHeader = await internalJson(
    f,
    `${base}/models`,
    "PATCH",
    {
      expectedVersion: 1,
      operationId: operationId("stale_header"),
      models: ["deepseek/deepseek-chat"],
    },
    { "if-match": '"0"' },
  );
  assert.equal(staleHeader.response.status, 409);
  assert.equal(staleHeader.body.error.code, "policy_version_conflict");

  const invalidLimits = [
    [{ period: "year", tokens: 1, cost: 0 }],
    [{ period: "month", tokens: -1, cost: 0 }],
    [{ period: "month", tokens: 1, cost: 0.00001 }],
    [{ period: "days", days: 0, tokens: 1, cost: 0 }],
    [{ period: "hours", hours: 1.5, tokens: 1, cost: 0 }],
    [{ period: "month", tokens: 1, cost: 0 }, { period: "month", tokens: 2, cost: 0 }],
    [
      { period: "days", days: 1, tokens: 1, cost: 0 },
      { period: "days", days: 2, tokens: 1, cost: 0 },
      { period: "days", days: 3, tokens: 1, cost: 0 },
      { period: "days", days: 4, tokens: 1, cost: 0 },
      { period: "days", days: 5, tokens: 1, cost: 0 },
      { period: "days", days: 6, tokens: 1, cost: 0 },
    ],
  ];
  for (const limits of invalidLimits) {
    const result = await internalJson(f, `${base}/quota`, "PUT", {
      expectedVersion: 1,
      operationId: operationId("bad_quota"),
      limits,
    });
    assert.equal(result.response.status, 400, JSON.stringify(result.body));
    assert.equal(result.body.error.code, "invalid_quota");
  }

  const quota = await internalJson(f, `${base}/quota`, "PUT", {
    expectedVersion: 1,
    operationId: operationId("valid_quota"),
    limits: [{ period: "month", tokens: 1000, cost: 1.2345, cacheReads: true }],
  });
  assert.equal(quota.response.status, 200, JSON.stringify(quota.body));
  assert.equal(quota.body.data.policy.version, 2);
  assert.deepEqual(quota.body.data.policy.models, ["deepseek/deepseek-chat", "deepseek/*"]);
  assert.deepEqual(quota.body.data.policy.limits, [
    { period: "month", tokens: 1000, cost: 1.2345, cacheReads: true },
  ]);
  assert.equal(f.magpie.issued.size, 0);
  assertNoPrivateValues(quota.body, f);
});

test("M1 policy migration is idempotent and preserves known and pending state", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-auth-policy-migration-"));
  try {
    const file = path.join(temp, "auth-store.json");
    const knownPolicy = {
      version: 7,
      models: ["deepseek/deepseek-chat"],
      limits: [],
      quotaStatus: "known",
      modelStatus: "known",
      updatedAt: "2026-10-20T00:00:00.000Z",
      confirmedAt: "2026-10-20T00:00:00.000Z",
      initializationSource: "admin",
    };
    const pendingPolicy = {
      version: 2,
      models: ["deepseek/deepseek-chat"],
      limits: [],
      quotaStatus: "pending",
      modelStatus: "pending",
      updatedAt: "2026-10-21T00:00:00.000Z",
      initializationSource: "admin",
    };
    await fs.writeFile(file, JSON.stringify({
      version: 1,
      users: {
        usr_known: {
          id: "usr_known",
          subject: "known",
          email: "known@corp.example",
          name: "Known",
          status: "active",
          gatewayPolicy: knownPolicy,
        },
        usr_pending: {
          id: "usr_pending",
          subject: "pending",
          email: "pending@corp.example",
          name: "Pending",
          status: "active",
          gatewayPolicy: pendingPolicy,
        },
        usr_legacy: {
          id: "usr_legacy",
          subject: "legacy",
          email: "legacy@corp.example",
          name: "Legacy",
          status: "active",
        },
      },
      devices: {
        dev_known: {
          id: "dev_known",
          userId: "usr_known",
          name: "Known PC",
          status: "active",
          gatewayKeyId: "key-known",
        },
        dev_legacy: {
          id: "dev_legacy",
          userId: "usr_legacy",
          name: "Legacy PC",
          status: "active",
          gatewayKeyId: "key-legacy",
        },
      },
      credentials: {
        "key-known": {
          id: "key-known",
          userId: "usr_known",
          deviceId: "dev_known",
          status: "active",
          createdAt: "2026-10-20T00:00:00.000Z",
          expiresAt: "2026-11-20T00:00:00.000Z",
          policyVersion: 7,
          policySyncState: "synced",
          lastPolicySyncedAt: "2026-10-20T00:00:00.000Z",
        },
        "key-pending": {
          id: "key-pending",
          userId: "usr_pending",
          deviceId: "dev_pending",
          status: "active",
          createdAt: "2026-10-21T00:00:00.000Z",
          expiresAt: "2026-11-21T00:00:00.000Z",
          policyVersion: 2,
          policySyncState: "pending",
          lastPolicyErrorCode: "policy_sync_in_progress",
        },
      },
      sessions: {},
      pendingRevocations: [],
    }), "utf8");

    const first = new JsonStore(file);
    await first.load();
    const migrated = await first.read((data) => structuredClone({
      known: data.users.usr_known.gatewayPolicy,
      pending: data.users.usr_pending.gatewayPolicy,
      legacy: data.users.usr_legacy.gatewayPolicy,
      knownCredential: data.credentials["key-known"],
      pendingCredential: data.credentials["key-pending"],
      legacyCredential: data.credentials["key-legacy"],
    }));
    assert.deepEqual(migrated.known, knownPolicy);
    assert.deepEqual(migrated.pending, pendingPolicy);
    assert.equal(migrated.legacy.version, 0);
    assert.equal(migrated.legacy.quotaStatus, "unknown");
    assert.equal(migrated.legacy.modelStatus, "unknown");
    assert.equal(migrated.legacy.initializationSource, "m1_unknown");
    assert.equal(migrated.knownCredential.policyVersion, 7);
    assert.equal(migrated.knownCredential.policySyncState, "synced");
    assert.equal(migrated.pendingCredential.policyVersion, 2);
    assert.equal(migrated.pendingCredential.policySyncState, "pending");
    assert.equal(migrated.legacyCredential.policyVersion, 0);
    assert.equal(migrated.legacyCredential.policySyncState, "pending");
    assert.equal(migrated.legacyCredential.lastPolicyErrorCode, "policy_setup_required");

    await first.mutate(() => {});
    const stored = JSON.parse(await fs.readFile(file, "utf8"));
    assert.equal(stored.version, 3);
    assert.equal(stored.policyMigrationVersion, 1);

    const second = new JsonStore(file);
    await second.load();
    const reloaded = await second.read((data) => structuredClone({
      known: data.users.usr_known.gatewayPolicy,
      pending: data.users.usr_pending.gatewayPolicy,
      legacy: data.users.usr_legacy.gatewayPolicy,
      knownCredential: data.credentials["key-known"],
      pendingCredential: data.credentials["key-pending"],
      legacyCredential: data.credentials["key-legacy"],
    }));
    assert.deepEqual(reloaded, migrated);
  } finally {
    await fs.rm(temp, { recursive: true, force: true });
  }
});

test("unknown and pending policies fail closed before any gateway key is issued", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  let issueCalls = 0;
  const originalIssue = f.auth.magpie.issue.bind(f.auth.magpie);
  f.auth.magpie.issue = async (...args) => {
    issueCalls += 1;
    return originalIssue(...args);
  };

  const firstLogin = await oidcLogin(f.authBase, new CookieJar());
  const unknownJoin = await exchangeJoin(f, firstLogin, "Unknown Policy PC");
  assert.equal(unknownJoin.response.status, 409);
  assert.equal(unknownJoin.body.error.code, "policy_setup_required");
  assert.equal(issueCalls, 0);

  const user = await userByEmail(f);
  await initializePolicy(f, user.id);
  const joined = await joinDevice(f, "Known Policy PC");
  assert.equal(issueCalls, 1);

  const changed = await internalJson(
    f,
    `/api/v1/internal/admin/users/${user.id}/policy/models`,
    "PATCH",
    {
      expectedVersion: joined.policyVersion,
      operationId: operationId("pending_gate"),
      models: ["deepseek/deepseek-reasoner"],
    },
  );
  assert.equal(changed.response.status, 200, JSON.stringify(changed.body));
  assert.equal(changed.body.data.state, "succeeded");
  assert.equal(changed.body.data.credentials.failed, 0);

  const refreshed = await fetch(`${f.authBase}/api/v1/devices/refresh`, {
    method: "POST",
    headers: { authorization: `Bearer ${joined.deviceToken}` },
  });
  assert.equal(refreshed.status, 200);
  const refreshedBody = await jsonBody(refreshed);
  assert.deepEqual(refreshedBody.gateway.models, ["deepseek/deepseek-reasoner"]);
  assert.equal(issueCalls, 2);

  await f.auth.store.mutate((data) => {
    const current = data.users[user.id].gatewayPolicy;
    data.users[user.id].gatewayPolicy = {
      version: current.version + 1,
      models: null,
      limits: null,
      quotaStatus: "unknown",
      modelStatus: "unknown",
      updatedAt: new Date().toISOString(),
      initializationSource: "test_unknown",
    };
  });

  for (const response of [
    await fetch(`${f.authBase}/api/v1/devices/refresh`, {
      method: "POST",
      headers: { authorization: `Bearer ${joined.deviceToken}` },
    }),
    await internalAction(
      f,
      `/api/v1/internal/admin/credentials/${refreshedBody.gateway.keyId}/rotate`,
    ),
  ]) {
    assert.equal(response.status, 409);
    const error = await jsonBody(response);
    assert.equal(error.error.code, "policy_setup_required");
    assert.deepEqual(error.error.missing, ["quota", "models"]);
  }
  assert.equal(issueCalls, 2);

  const unknownAgain = await exchangeJoin(
    f,
    await oidcLogin(f.authBase, new CookieJar()),
    "Unknown Policy PC 2",
  );
  assert.equal(unknownAgain.response.status, 409);
  assert.equal(unknownAgain.body.error.code, "policy_setup_required");
  assert.equal(issueCalls, 2);
  assert.equal(f.magpie.issued.size, 1);
});

test("credential policy confirmation requires an exact, safe gateway readback", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const joined = await joinDevice(f, "Readback PC");
  const reasonerModels = ["deepseek/deepseek-reasoner"];
  const changed = await internalJson(
    f,
    `/api/v1/internal/admin/users/${joined.user.id}/policy/models`,
    "PATCH",
    {
      expectedVersion: joined.policyVersion,
      operationId: operationId("readback_change"),
      models: reasonerModels,
    },
  );
  assert.equal(changed.response.status, 200, JSON.stringify(changed.body));
  const currentVersion = changed.body.data.policy.version;
  const credentialId = joined.gateway.keyId;
  const base = `/api/v1/internal/admin/users/${joined.user.id}/policy/confirm-credential`;
  const readback = () => ({
    schemaVersion: 1,
    gatewayControlRequestId: `gcr_${crypto.randomUUID()}`,
    observedAt: new Date().toISOString(),
    policyRevision: `rev_${crypto.randomUUID()}`,
    models: reasonerModels,
    limits: [],
  });
  const confirm = (value, expectedVersion = currentVersion) => internalJson(f, base, "POST", {
    credentialId,
    expectedVersion,
    operationId: operationId("confirm"),
    readback: value,
  });

  const extraField = { ...readback(), gatewayKey: "must-not-be-accepted" };
  let result = await confirm(extraField);
  assert.equal(result.response.status, 400);
  assert.equal(result.body.error.code, "invalid_readback");

  result = await confirm({ ...readback(), models: ["deepseek/deepseek-chat"] });
  assert.equal(result.response.status, 409);
  assert.equal(result.body.error.code, "policy_version_conflict");

  result = await confirm({
    ...readback(),
    limits: [{ period: "month", tokens: 100, cost: 0 }],
  });
  assert.equal(result.response.status, 409);
  assert.equal(result.body.error.code, "policy_version_conflict");

  result = await confirm({ ...readback(), schemaVersion: 2 });
  assert.equal(result.response.status, 400);
  assert.equal(result.body.error.code, "invalid_readback");

  result = await confirm({
    ...readback(),
    observedAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
  });
  assert.equal(result.response.status, 400);
  assert.equal(result.body.error.code, "invalid_readback");

  result = await confirm({ ...readback(), gatewayControlRequestId: "bad id" });
  assert.equal(result.response.status, 400);
  assert.equal(result.body.error.code, "invalid_readback");

  result = await confirm(readback(), joined.policyVersion);
  assert.equal(result.response.status, 409);
  assert.equal(result.body.error.code, "policy_version_conflict");

  const validReadback = readback();
  result = await confirm(validReadback);
  assert.equal(result.response.status, 200, JSON.stringify(result.body));
  assert.equal(result.body.data.state, "succeeded");
  assert.equal(result.body.data.requiresReconciliation, false);
  assert.equal(result.body.data.policy.version, currentVersion);
  assert.equal(result.body.data.policy.quotaStatus, "known");
  assert.equal(result.body.data.policy.modelStatus, "known");
  assert.deepEqual(result.body.data.credentials, {
    total: 1,
    succeeded: 1,
    failed: 0,
    pending: 0,
    unknown: 0,
    failedOnly: 0,
    failedItems: [],
  });
  assert.equal(result.body.data.credential.credentialId, credentialId);
  assert.equal(result.body.data.credential.policyVersion, currentVersion);
  assert.equal(result.body.data.credential.policySyncState, "synced");
  assert.equal(result.body.data.readback.policyRevision, validReadback.policyRevision);
  assertNoPrivateValues(result.body, f, [joined.gateway.key, joined.deviceToken]);

  const state = await f.auth.store.read((data) => structuredClone({
    policy: data.users[joined.user.id].gatewayPolicy,
    credential: data.credentials[credentialId],
  }));
  assert.equal(state.policy.quotaStatus, "known");
  assert.equal(state.policy.modelStatus, "known");
  assert.equal(state.credential.policyVersion, currentVersion);
  assert.equal(state.credential.policySyncState, "synced");
  assert.equal(state.credential.lastPolicyRevision, validReadback.policyRevision);
  assert.equal(state.credential.lastPolicyGatewayRequestId, validReadback.gatewayControlRequestId);
  assert.equal(state.credential.lastPolicyErrorCode, undefined);

  const credentialsResponse = await fetch(`${f.authBase}/api/v1/internal/admin/credentials`, {
    headers: { authorization: `Bearer ${f.issues.internalAdminToken}` },
  });
  assert.equal(credentialsResponse.status, 200);
  const credentialsBody = await jsonBody(credentialsResponse);
  const publicCredential = credentialsBody.credentials.find((credential) => credential.id === credentialId);
  assert.equal(publicCredential.policyVersion, currentVersion);
  assert.equal(publicCredential.policySyncState, "synced");
  assert.equal(publicCredential.lastPolicyErrorCode, "");
  assertNoPrivateValues(credentialsBody, f, [joined.gateway.key, joined.deviceToken]);

  const staleConfirmation = await confirm(readback(), joined.policyVersion);
  assert.equal(staleConfirmation.response.status, 409);
  assert.equal(staleConfirmation.body.error.code, "policy_version_conflict");
});

test("policy value validation rejects non-finite, over-precision and oversized input", () => {
  assert.deepEqual(
    validateModels(["deepseek/deepseek-chat", "deepseek/deepseek-chat", "deepseek/*"]),
    ["deepseek/deepseek-chat", "deepseek/*"],
  );
  for (const models of [
    [],
    ["*"],
    ["group/team-a"],
    ["deepseek/*/chat"],
    ["deepseek/"],
    ["deepseek/deepseek chat"],
  ]) {
    assert.throws(() => validateModels(models));
  }

  for (const limits of [
    [{ period: "month", tokens: NaN, cost: 0 }],
    [{ period: "month", tokens: Infinity, cost: 0 }],
    [{ period: "month", tokens: 1, cost: Infinity }],
    [{ period: "month", tokens: 1, cost: NaN }],
    [{ period: "month", tokens: 1, cost: 0.00001 }],
    [{ period: "days", days: 1.5, tokens: 1, cost: 0 }],
    [{ period: "hours", hours: 0, tokens: 1, cost: 0 }],
    [{ period: "month", tokens: 1, cost: 0 }, { period: "month", tokens: 2, cost: 0 }],
    Array.from({ length: 6 }, (_, index) => ({
      period: "days",
      days: index + 1,
      tokens: 1,
      cost: 0,
    })),
  ]) {
    assert.throws(() => validateLimits(limits));
  }

  const fiveWindows = validateLimits([
    { period: "day", tokens: 1, cost: 0 },
    { period: "week", tokens: 1, cost: 0 },
    { period: "month", tokens: 1, cost: 0.0001 },
    { period: "days", days: 3650, tokens: 1, cost: 0 },
    { period: "hours", hours: 8760, tokens: 1, cost: 0 },
  ]);
  assert.equal(fiveWindows.length, 5);
});

test("concurrent refresh keeps exactly one active key per device", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  const joined = await joinDevice(f, "Concurrent PC");
  const responses = await Promise.all(
    Array.from({ length: 5 }, () =>
      fetch(`${f.authBase}/api/v1/devices/refresh`, {
        method: "POST",
        headers: { authorization: `Bearer ${joined.deviceToken}` },
      }),
    ),
  );

  const bodies = [];
  for (const response of responses) {
    assert.equal(response.status, 200);
    bodies.push(await jsonBody(response));
  }
  const issuedIds = bodies.map((body) => body.gateway.keyId);
  assert.equal(new Set(issuedIds).size, 5);

  const activeKeyId = await f.auth.store.read(
    (data) => data.devices[joined.device.id].gatewayKeyId,
  );
  assert.ok(issuedIds.includes(activeKeyId));
  assert.equal(f.magpie.issued.size, 1);
  assert.ok(f.magpie.issued.has(activeKeyId));
  for (const id of issuedIds) {
    if (id !== activeKeyId) assert.ok(f.magpie.revoked.includes(id));
  }

  const users = await fetch(`${f.authBase}/api/v1/admin/users`, {
    headers: { authorization: `Bearer ${f.issues.adminToken}` },
  });
  assert.equal(users.status, 200);
  const user = (await jsonBody(users)).users[0];
  const disabled = await fetch(`${f.authBase}/api/v1/admin/users/${user.id}/disable`, {
    method: "POST",
    headers: { authorization: `Bearer ${f.issues.adminToken}` },
  });
  assert.equal(disabled.status, 200);
  assert.ok(f.magpie.revoked.includes(activeKeyId));
  assert.equal(f.magpie.issued.size, 0);

  const deniedRefresh = await fetch(`${f.authBase}/api/v1/devices/refresh`, {
    method: "POST",
    headers: { authorization: `Bearer ${joined.deviceToken}` },
  });
  assert.equal(deniedRefresh.status, 403);
  assert.equal((await jsonBody(deniedRefresh)).error.code, "device_disabled");

  const deniedHeartbeat = await fetch(`${f.authBase}/api/v1/devices/heartbeat`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${joined.deviceToken}`,
      "content-type": "application/json",
    },
    body: "{}",
  });
  assert.equal(deniedHeartbeat.status, 403);
  assert.equal((await jsonBody(deniedHeartbeat)).error.code, "device_disabled");
});

test("disable during refresh revokes the newly issued key", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  const joined = await joinDevice(f, "Disable During Refresh PC");
  const users = await fetch(`${f.authBase}/api/v1/admin/users`, {
    headers: { authorization: `Bearer ${f.issues.adminToken}` },
  });
  assert.equal(users.status, 200);
  const user = (await jsonBody(users)).users[0];

  const issuedBefore = new Set(f.magpie.issued.keys());
  let releaseIssue;
  let issueStarted;
  const started = new Promise((resolve) => {
    issueStarted = resolve;
  });
  const released = new Promise((resolve) => {
    releaseIssue = resolve;
  });
  const originalIssue = f.auth.magpie.issue.bind(f.auth.magpie);
  f.auth.magpie.issue = async (...args) => {
    issueStarted();
    await released;
    return originalIssue(...args);
  };

  const refreshPromise = fetch(`${f.authBase}/api/v1/devices/refresh`, {
    method: "POST",
    headers: { authorization: `Bearer ${joined.deviceToken}` },
  });
  await started;

  const disabled = await fetch(`${f.authBase}/api/v1/admin/users/${user.id}/disable`, {
    method: "POST",
    headers: { authorization: `Bearer ${f.issues.adminToken}` },
  });
  assert.equal(disabled.status, 200);
  releaseIssue();

  const refresh = await refreshPromise;
  assert.equal(refresh.status, 403);
  const refreshError = await jsonBody(refresh);
  assert.ok(["device_disabled", "user_disabled"].includes(refreshError.error.code));

  const newlyIssued = [...f.magpie.revoked].filter((id) => !issuedBefore.has(id));
  assert.equal(newlyIssued.length, 1);
  assert.equal(f.magpie.issued.size, 0);
  const device = await f.auth.store.read((data) => data.devices[joined.device.id]);
  assert.equal(device.status, "disabled");
  assert.ok(f.magpie.revoked.includes(device.gatewayKeyId));
});

test("internal write routes require the internal service token", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  const actions = [
    "/api/v1/internal/admin/users/usr_missing/disable",
    "/api/v1/internal/admin/users/usr_missing/enable",
    "/api/v1/internal/admin/devices/dev_missing/revoke",
    "/api/v1/internal/admin/credentials/key-missing/rotate",
  ];
  for (const pathname of actions) {
    for (const token of ["", f.issues.adminToken, "wrong-service-token"]) {
      const response = await fetch(`${f.authBase}${pathname}`, {
        method: "POST",
        headers: token ? { authorization: `Bearer ${token}` } : {},
      });
      assert.equal(response.status, 401);
      const body = await jsonBody(response);
      assert.equal(body.error.code, "invalid_service_token");
      assert.ok(!JSON.stringify(body).includes(f.issues.internalAdminToken));
    }
  }
});

test("internal disable revokes access and enable requires devices to join again", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const joined = await joinDevice(f, "Internal Disable PC");
  const jar = await browserLogin(f);
  const me = await fetch(`${f.authBase}/api/v1/me`, { headers: { cookie: jar.header() } });
  assert.equal(me.status, 200);

  const disabled = await internalAction(f, `/api/v1/internal/admin/users/${joined.user.id}/disable`);
  assert.equal(disabled.status, 200);
  const disabledBody = await jsonBody(disabled);
  assertNoPrivateValues(disabledBody, f, [joined.gateway.key, joined.deviceToken]);
  assert.equal(disabledBody.data.user.status, "disabled");
  assert.equal(disabledBody.data.affectedDevices, 1);
  assert.equal(disabledBody.data.affectedSessions, 1);
  assert.equal(disabledBody.data.affectedCredentials, 1);
  assert.ok(f.magpie.revoked.includes(joined.gateway.keyId));
  assert.ok(!f.magpie.issued.has(joined.gateway.keyId));

  const state = await f.auth.store.read((data) => structuredClone({
    user: data.users[joined.user.id],
    device: data.devices[joined.device.id],
    credential: data.credentials[joined.gateway.keyId],
    sessions: Object.values(data.sessions).filter((session) => session.userId === joined.user.id),
  }));
  assert.equal(state.user.status, "disabled");
  assert.equal(state.device.status, "disabled");
  assert.equal(state.credential.status, "revoked");
  assert.equal(state.sessions.length, 0);

  const expiredSession = await fetch(`${f.authBase}/api/v1/me`, { headers: { cookie: jar.header() } });
  assert.equal(expiredSession.status, 401);
  const heartbeat = await fetch(`${f.authBase}/api/v1/devices/heartbeat`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${joined.deviceToken}`,
      "content-type": "application/json",
    },
    body: "{}",
  });
  assert.equal(heartbeat.status, 403);
  const refresh = await fetch(`${f.authBase}/api/v1/devices/refresh`, {
    method: "POST",
    headers: { authorization: `Bearer ${joined.deviceToken}` },
  });
  assert.equal(refresh.status, 403);

  const enabled = await internalAction(f, `/api/v1/internal/admin/users/${joined.user.id}/enable`);
  assert.equal(enabled.status, 200);
  const enabledBody = await jsonBody(enabled);
  assertNoPrivateValues(enabledBody, f, [joined.gateway.key, joined.deviceToken]);
  assert.equal(enabledBody.data.user.status, "active");
  assert.equal(enabledBody.data.devicesRestored, 0);
  assert.equal(enabledBody.data.credentialsRestored, 0);
  assert.equal(enabledBody.data.requiresDeviceJoin, true);

  const oldDevice = await f.auth.store.read((data) => structuredClone(data.devices[joined.device.id]));
  assert.equal(oldDevice.status, "disabled");
  const deniedRefresh = await fetch(`${f.authBase}/api/v1/devices/refresh`, {
    method: "POST",
    headers: { authorization: `Bearer ${joined.deviceToken}` },
  });
  assert.equal(deniedRefresh.status, 403);
  assert.equal((await jsonBody(deniedRefresh)).error.code, "device_disabled");

  const rejoined = await joinDevice(f, "Internal Rejoin PC");
  assert.notEqual(rejoined.device.id, joined.device.id);
});

test("internal device revoke isolates one device and rejects missing devices", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const first = await joinDevice(f, "Revoke First PC");
  const second = await joinDevice(f, "Revoke Second PC");

  const revoked = await internalAction(f, `/api/v1/internal/admin/devices/${first.device.id}/revoke`);
  assert.equal(revoked.status, 200);
  const body = await jsonBody(revoked);
  assertNoPrivateValues(body, f, [first.gateway.key, first.deviceToken, second.gateway.key, second.deviceToken]);
  assert.equal(body.data.device.status, "revoked");
  assert.equal(body.data.affectedCredentials, 1);
  assert.ok(f.magpie.revoked.includes(first.gateway.keyId));
  assert.ok(f.magpie.issued.has(second.gateway.keyId));

  const state = await f.auth.store.read((data) => structuredClone({
    revokedDevice: data.devices[first.device.id],
    revokedCredential: data.credentials[first.gateway.keyId],
    otherCredential: data.credentials[second.gateway.keyId],
  }));
  assert.equal(state.revokedDevice.status, "revoked");
  assert.equal(state.revokedCredential.status, "revoked");
  assert.equal(state.otherCredential.status, "active");

  for (const [pathname, bodyValue] of [
    ["/api/v1/devices/heartbeat", "{}"],
    ["/api/v1/devices/refresh", undefined],
  ]) {
    const response = await fetch(`${f.authBase}${pathname}`, {
      method: "POST",
      headers: bodyValue
        ? { authorization: `Bearer ${first.deviceToken}`, "content-type": "application/json" }
        : { authorization: `Bearer ${first.deviceToken}` },
      body: bodyValue,
    });
    assert.equal(response.status, 403);
    assert.equal((await jsonBody(response)).error.code, "device_disabled");
  }

  const missing = await internalAction(f, "/api/v1/internal/admin/devices/dev_missing/revoke");
  assert.equal(missing.status, 404);
  assert.equal((await jsonBody(missing)).error.code, "device_not_found");
});

test("internal credential rotation replaces the current key without returning it", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const joined = await joinDevice(f, "Rotate PC");

  const rotated = await internalAction(
    f,
    `/api/v1/internal/admin/credentials/${joined.gateway.keyId}/rotate`,
  );
  assert.equal(rotated.status, 200);
  const body = await jsonBody(rotated);
  assertNoPrivateValues(body, f, [joined.gateway.key, joined.deviceToken]);
  assert.equal(body.data.credentialId, joined.gateway.keyId);
  assert.notEqual(body.data.newCredentialId, joined.gateway.keyId);
  assert.equal(body.data.userId, joined.user.id);
  assert.equal(body.data.deviceId, joined.device.id);
  assert.equal(body.data.status, "awaiting_device_refresh");

  const state = await f.auth.store.read((data) => structuredClone({
    oldCredential: data.credentials[joined.gateway.keyId],
    newCredential: data.credentials[body.data.newCredentialId],
    device: data.devices[joined.device.id],
  }));
  assert.equal(state.oldCredential.status, "revoked");
  assert.equal(state.newCredential.status, "active");
  assert.equal(state.device.gatewayKeyId, body.data.newCredentialId);
  assert.ok(f.magpie.revoked.includes(joined.gateway.keyId));
  assert.ok(!f.magpie.issued.has(joined.gateway.keyId));
  assert.ok(f.magpie.issued.has(body.data.newCredentialId));

  const missing = await internalAction(f, "/api/v1/internal/admin/credentials/key_missing/rotate");
  assert.equal(missing.status, 404);
  assert.equal((await jsonBody(missing)).error.code, "credential_not_found");

  const old = await internalAction(f, `/api/v1/internal/admin/credentials/${joined.gateway.keyId}/rotate`);
  assert.equal(old.status, 409);
  assert.equal((await jsonBody(old)).error.code, "credential_not_active");

  await f.auth.store.mutate((data) => {
    data.credentials["key-not-current"] = {
      id: "key-not-current",
      userId: joined.user.id,
      deviceId: joined.device.id,
      status: "active",
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60000).toISOString(),
    };
  });
  const notCurrent = await internalAction(f, "/api/v1/internal/admin/credentials/key-not-current/rotate");
  assert.equal(notCurrent.status, 409);
  assert.equal((await jsonBody(notCurrent)).error.code, "credential_not_current");

  await f.auth.store.mutate((data) => {
    data.credentials["key-no-device"] = {
      id: "key-no-device",
      userId: joined.user.id,
      deviceId: "dev_missing",
      status: "active",
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60000).toISOString(),
    };
  });
  const noDevice = await internalAction(f, "/api/v1/internal/admin/credentials/key-no-device/rotate");
  assert.equal(noDevice.status, 404);
  assert.equal((await jsonBody(noDevice)).error.code, "device_not_found");
});

test("failed internal rotation revokes the orphan key", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const joined = await joinDevice(f, "Rotate Failure PC");
  let attemptedKeyId = "";
  const originalIssue = f.auth.magpie.issue.bind(f.auth.magpie);
  f.auth.magpie.issue = async (...args) => {
    const issued = await originalIssue(...args);
    attemptedKeyId = issued.id;
    return issued;
  };

  const originalMutate = f.auth.store.mutate.bind(f.auth.store);
  let mutateCalls = 0;
  f.auth.store.mutate = async (...args) => {
    mutateCalls += 1;
    if (mutateCalls === 5) {
      f.auth.store.mutate = originalMutate;
      throw new Error("injected rotation commit failure");
    }
    return originalMutate(...args);
  };

  const rotated = await internalAction(
    f,
    `/api/v1/internal/admin/credentials/${joined.gateway.keyId}/rotate`,
  );
  assert.equal(rotated.status, 500);
  assert.equal((await jsonBody(rotated)).error.code, "internal_error");
  assert.match(attemptedKeyId, /^key-/);
  assert.ok(f.magpie.revoked.includes(attemptedKeyId));
  assert.ok(!f.magpie.issued.has(attemptedKeyId));
  assert.ok(f.magpie.issued.has(joined.gateway.keyId));
  const unchanged = await f.auth.store.read((data) => data.devices[joined.device.id].gatewayKeyId);
  assert.equal(unchanged, joined.gateway.keyId);
});

test("concurrent internal rotation and refresh leave one active key", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const joined = await joinDevice(f, "Rotate Race PC");

  const [rotated, refreshed] = await Promise.all([
    internalAction(f, `/api/v1/internal/admin/credentials/${joined.gateway.keyId}/rotate`),
    fetch(`${f.authBase}/api/v1/devices/refresh`, {
      method: "POST",
      headers: { authorization: `Bearer ${joined.deviceToken}` },
    }),
  ]);
  assert.equal(refreshed.status, 200);
  assert.ok([200, 409].includes(rotated.status));
  if (rotated.status === 409) {
    const error = await jsonBody(rotated);
    assert.ok(["credential_not_active", "credential_not_current"].includes(error.error.code));
  } else {
    assert.equal((await jsonBody(rotated)).ok, true);
  }

  const state = await f.auth.store.read((data) => ({
    gatewayKeyId: data.devices[joined.device.id].gatewayKeyId,
    activeCredentials: Object.values(data.credentials)
      .filter((credential) => credential.deviceId === joined.device.id && credential.status === "active")
      .map((credential) => credential.id),
  }));
  assert.deepEqual(state.activeCredentials, [state.gatewayKeyId]);
  assert.equal(f.magpie.issued.size, 1);
  assert.ok(f.magpie.issued.has(state.gatewayKeyId));
});
