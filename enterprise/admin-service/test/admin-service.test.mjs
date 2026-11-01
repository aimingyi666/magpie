import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { loadModelCatalog } from "../src/model-catalog.js";
import { JsonStore } from "../src/store.js";
import { createEnterpriseAdminServer } from "../src/service.js";

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
  return new Promise((resolve) => server.close(resolve));
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

function createMockOidc(options = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = "test-key";
  jwk.use = "sig";
  jwk.alg = "RS256";
  const codes = new Map();
  const clientId = "magpie-enterprise-admin-test";
  const clientSecret = "{{SECRET_adminoidcclient}}-test-only-padding-0001";
  let base = "";
  let lastAuthorize = null;

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
      lastAuthorize = new URL(url);
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
      const pkceOk = code && crypto.createHash("sha256")
        .update(form.get("code_verifier") || "")
        .digest("base64url") === code.codeChallenge;
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
        sub: "admin-alice",
        email: "admin@corp.example",
        email_verified: true,
        name: "Admin Alice",
        amr: ["pwd", "mfa"],
        nonce: code.nonce,
        iat: now,
        exp: now + 300,
        ...options.claims,
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
    get lastAuthorize() { return lastAuthorize; },
    setBase(value) { base = value; },
  };
}

function createMockAuthService(expectedToken) {
  let failing = false;
  let writeFailing = false;
  let writeDelayMs = 0;
  const writeCalls = [];
  const users = [
    {
      id: "usr_alice",
      email: "alice@corp.example",
      name: "Alice",
      status: "active",
      createdAt: "2026-10-01T00:00:00.000Z",
      lastLoginAt: "2026-10-31T08:00:00.000Z",
    },
    {
      id: "usr_bob",
      email: "bob@corp.example",
      name: "Bob",
      status: "active",
      createdAt: "2026-10-02T00:00:00.000Z",
      lastLoginAt: "2026-10-31T09:00:00.000Z",
    },
    {
      id: "usr_carol",
      email: "carol@corp.example",
      name: "Carol",
      status: "active",
      createdAt: "2026-10-03T00:00:00.000Z",
      lastLoginAt: "2026-10-31T10:00:00.000Z",
    },
    {
      id: "usr_unmapped",
      email: "unmapped@corp.example",
      name: "Unmapped",
      status: "active",
      createdAt: "2026-10-04T00:00:00.000Z",
      lastLoginAt: "2026-10-31T11:00:00.000Z",
    },
  ];
  const devices = [
    {
      id: "dev_alice",
      userId: "usr_alice",
      name: "Alice PC",
      platform: "windows",
      clientVersion: "1.0.0",
      status: "active",
      createdAt: "2026-10-20T00:00:00.000Z",
      lastSeenAt: "2026-10-31T08:00:00.000Z",
      gatewayKeyId: "key-alice-new",
      keyExpiresAt: "2026-11-01T08:00:00.000Z",
    },
    {
      id: "dev_bob",
      userId: "usr_bob",
      name: "Bob Mac",
      platform: "macos",
      clientVersion: "1.0.0",
      status: "active",
      createdAt: "2026-10-21T00:00:00.000Z",
      lastSeenAt: "2026-10-31T09:00:00.000Z",
      gatewayKeyId: "key-bob",
      keyExpiresAt: "2026-11-01T09:00:00.000Z",
    },
    {
      id: "dev_carol",
      userId: "usr_carol",
      name: "Carol PC",
      platform: "windows",
      clientVersion: "1.0.0",
      status: "active",
      createdAt: "2026-10-22T00:00:00.000Z",
      lastSeenAt: "2026-10-31T10:00:00.000Z",
      gatewayKeyId: "key-carol",
      keyExpiresAt: "2026-11-01T10:00:00.000Z",
    },
  ];
  const credentials = [
    {
      id: "key-alice-new",
      userId: "usr_alice",
      deviceId: "dev_alice",
      deviceName: "Alice PC",
      deviceStatus: "active",
      status: "active",
      createdAt: "2026-10-31T00:00:00.000Z",
      expiresAt: "2026-11-01T08:00:00.000Z",
      deviceTokenExpiresAt: "2026-11-30T00:00:00.000Z",
      lastSeenAt: "2026-10-31T08:00:00.000Z",
      publicKeySha256: "alice-public-key-sha256",
      models: ["deepseek/deepseek-chat"],
    },
    {
      id: "key-alice-old",
      userId: "usr_alice",
      deviceId: "dev_alice",
      deviceName: "Alice PC",
      deviceStatus: "active",
      status: "revoked",
      createdAt: "2026-10-30T00:00:00.000Z",
      expiresAt: "2026-10-31T00:00:00.000Z",
      revokedAt: "2026-10-31T00:00:00.000Z",
      deviceTokenExpiresAt: "2026-11-30T00:00:00.000Z",
      lastSeenAt: "2026-10-31T08:00:00.000Z",
      publicKeySha256: "alice-public-key-sha256",
      models: ["deepseek/deepseek-chat"],
    },
    {
      id: "key-bob",
      userId: "usr_bob",
      deviceId: "dev_bob",
      deviceName: "Bob Mac",
      deviceStatus: "active",
      status: "active",
      createdAt: "2026-10-31T01:00:00.000Z",
      expiresAt: "2026-11-01T09:00:00.000Z",
      deviceTokenExpiresAt: "2026-11-30T00:00:00.000Z",
      lastSeenAt: "2026-10-31T09:00:00.000Z",
      publicKeySha256: "bob-public-key-sha256",
      models: ["openai/gpt-test"],
    },
    {
      id: "key-carol",
      userId: "usr_carol",
      deviceId: "dev_carol",
      deviceName: "Carol PC",
      deviceStatus: "active",
      status: "active",
      createdAt: "2026-10-31T02:00:00.000Z",
      expiresAt: "2026-11-01T10:00:00.000Z",
      deviceTokenExpiresAt: "2026-11-30T00:00:00.000Z",
      lastSeenAt: "2026-10-31T10:00:00.000Z",
      publicKeySha256: "carol-public-key-sha256",
      models: ["deepseek/deepseek-chat"],
    },
  ];
  async function delayWrite() {
    if (writeDelayMs <= 0) return;
    await new Promise((resolve) => setTimeout(resolve, writeDelayMs));
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    if (!url.pathname.startsWith("/api/v1/internal/admin/")) {
      res.writeHead(404);
      res.end();
      return;
    }
    if (req.headers.authorization !== `Bearer ${expectedToken}`) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { code: "invalid_service_token" } }));
      return;
    }
    if (failing) {
      res.writeHead(503, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { code: "unavailable" } }));
      return;
    }
    function ok(value) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(value));
    }
    const userWrite = /^\/api\/v1\/internal\/admin\/users\/([A-Za-z0-9_-]+)\/(disable|enable)$/.exec(
      url.pathname,
    );
    if (req.method === "POST" && userWrite) {
      writeCalls.push({ method: req.method, pathname: url.pathname });
      if (writeFailing) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "write_unavailable" } }));
        return;
      }
      await delayWrite();
      const user = users.find((candidate) => candidate.id === userWrite[1]);
      if (!user) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "user_not_found" } }));
        return;
      }
      user.status = userWrite[2] === "disable" ? "disabled" : "active";
      ok({
        ok: true,
        data: {
          user: { ...user },
          affectedDevices: userWrite[2] === "disable" ? 1 : 0,
          affectedSessions: userWrite[2] === "disable" ? 1 : 0,
          affectedCredentials: userWrite[2] === "disable" ? 1 : 0,
          requiresDeviceJoin: userWrite[2] === "enable",
          revocations: { revoked: ["key-alice-new"], pending: 0 },
          gatewayKey: "should-not-leak-gateway-key",
          deviceToken: "should-not-leak-device-token",
          tokenHash: "should-not-leak-token-hash",
          publicKey: "-----BEGIN PUBLIC KEY-----",
          serviceToken: expectedToken,
        },
      });
      return;
    }
    const deviceWrite = /^\/api\/v1\/internal\/admin\/devices\/([A-Za-z0-9_-]+)\/revoke$/.exec(
      url.pathname,
    );
    if (req.method === "POST" && deviceWrite) {
      writeCalls.push({ method: req.method, pathname: url.pathname });
      if (writeFailing) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "write_unavailable" } }));
        return;
      }
      await delayWrite();
      const device = devices.find((candidate) => candidate.id === deviceWrite[1]);
      if (!device) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "device_not_found" } }));
        return;
      }
      device.status = "revoked";
      ok({
        ok: true,
        data: {
          device: { ...device },
          affectedCredentials: 1,
          revocations: { revoked: [device.gatewayKeyId], pending: 0 },
          gatewayKey: "should-not-leak-gateway-key",
          deviceToken: "should-not-leak-device-token",
          tokenHash: "should-not-leak-token-hash",
          publicKey: "-----BEGIN PUBLIC KEY-----",
          serviceToken: expectedToken,
        },
      });
      return;
    }
    const credentialWrite = /^\/api\/v1\/internal\/admin\/credentials\/([A-Za-z0-9_-]+)\/rotate$/.exec(
      url.pathname,
    );
    if (req.method === "POST" && credentialWrite) {
      writeCalls.push({ method: req.method, pathname: url.pathname });
      if (writeFailing) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "write_unavailable" } }));
        return;
      }
      await delayWrite();
      const credential = credentials.find((candidate) => candidate.id === credentialWrite[1]);
      if (!credential) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "credential_not_found" } }));
        return;
      }
      ok({
        ok: true,
        data: {
          credentialId: credential.id,
          newCredentialId: `key-rotated-${credential.id}`,
          userId: credential.userId,
          deviceId: credential.deviceId,
          status: "awaiting_device_refresh",
          expiresAt: "2026-11-01T12:00:00.000Z",
          revocations: { revoked: [credential.id], pending: 0 },
          gatewayKey: "should-not-leak-gateway-key",
          deviceToken: "should-not-leak-device-token",
          tokenHash: "should-not-leak-token-hash",
          publicKey: "-----BEGIN PUBLIC KEY-----",
          serviceToken: expectedToken,
        },
      });
      return;
    }
    if (req.method !== "GET") {
      res.writeHead(404);
      res.end();
      return;
    }
    if (url.pathname === "/api/v1/internal/admin/status") {
      ok({
        ok: true,
        service: "auth",
        users: users.length,
        devices: devices.length,
        credentials: credentials.length,
        pendingRevocations: 0,
      });
      return;
    }
    if (url.pathname === "/api/v1/internal/admin/users") {
      ok({ ok: true, users });
      return;
    }
    if (url.pathname === "/api/v1/internal/admin/devices") {
      ok({ ok: true, devices });
      return;
    }
    if (url.pathname === "/api/v1/internal/admin/credentials") {
      ok({ ok: true, credentials });
      return;
    }
    res.writeHead(404);
    res.end();
  });
  return {
    server,
    setFailing(value) { failing = value; },
    setWriteFailing(value) { writeFailing = value; },
    setWriteDelay(value) { writeDelayMs = value; },
    get writeCalls() { return writeCalls; },
  };
}

async function fixture(options = {}) {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-admin-test-"));
  let oidc = null;
  let auth = null;
  let admin = null;
  try {
    const usagePath = path.join(temp, "usage.jsonl");
    await fs.writeFile(usagePath, options.usageContent || "", "utf8");
    const catalogPath = options.catalogContent === undefined
      ? ""
      : path.join(temp, "model-catalog.json");
    if (catalogPath) await fs.writeFile(catalogPath, options.catalogContent, "utf8");
    oidc = createMockOidc(options);
    oidc.setBase(await listen(oidc.server));
    const serviceToken = "{{SECRET_adminservicetoken}}-test-only-padding-0001";
    auth = createMockAuthService(serviceToken);
    const authBase = await listen(auth.server);
    const config = loadConfig({
      ADMIN_PUBLIC_URL: "http://127.0.0.1:3998",
      ADMIN_PORT: "3998",
      ADMIN_STORE_PATH: path.join(temp, "admin-store.json"),
      ADMIN_SESSION_SECRET: "{{SECRET_adminsessionsecret}}-test-only-padding-0001",
      ADMIN_SECURE_COOKIE: "false",
      ADMIN_ALLOWED_IPS: options.allowedIps || "127.0.0.1/32,::1/128",
      ADMIN_RATE_LIMIT_PER_MINUTE: "1000",
      ADMIN_SESSION_TTL_HOURS: "8",
      ADMIN_IDLE_TIMEOUT_MINUTES: "30",
      ADMIN_OIDC_ISSUER: oidc.base,
      ADMIN_OIDC_CLIENT_ID: oidc.clientId,
      ADMIN_OIDC_CLIENT_SECRET: oidc.clientSecret,
      ADMIN_OIDC_REDIRECT_URI: "http://127.0.0.1:3998/admin/oauth/callback",
      ADMIN_ALLOWED_EMAIL_DOMAINS: "corp.example",
      ADMIN_REQUIRE_MFA: "true",
      ADMIN_REQUIRE_VERIFIED_EMAIL: "true",
      ADMIN_ALLOWED_ACR_VALUES: options.allowedAcrValues || "",
      ADMIN_BOOTSTRAP_EMAILS: "admin@corp.example",
      ADMIN_BOOTSTRAP_VALID_HOURS: "24",
      ADMIN_AUTH_SERVICE_URL: authBase,
      ADMIN_AUTH_SERVICE_TOKEN: serviceToken,
      ADMIN_AUTH_SERVICE_TIMEOUT_MS: "1000",
      ADMIN_MODELS: options.models || "deepseek/deepseek-chat,openai/gpt-test",
      ADMIN_MODEL_CATALOG_PATH: catalogPath,
      ADMIN_MODEL_CATALOG_DIGEST: options.catalogDigest || "",
      ADMIN_USAGE_PATH: usagePath,
      ADMIN_USAGE_MAX_BYTES: options.maxBytes || String(256 * 1024 * 1024),
      ADMIN_USAGE_MAX_LINE_BYTES: options.maxLineBytes || String(1024 * 1024),
      ADMIN_USAGE_MAX_RECORDS: options.maxRecords || "1000000",
      ADMIN_USAGE_MAX_FIELDS: options.maxFields || "256",
      ADMIN_USAGE_MAX_RANGE_DAYS: "366",
    });
    admin = await createEnterpriseAdminServer(config);
    const base = await listen(admin.server);
    config.publicUrl = base;
    config.oidc.redirectUri = `${base}/admin/oauth/callback`;
    return {
      temp,
      oidc,
      auth,
      config,
      admin,
      base,
      usagePath,
      catalogPath,
      secrets: {
        oidcClientSecret: oidc.clientSecret,
        serviceToken,
        sessionSecret: config.sessionSecret,
      },
      async close() {
        await close(admin.server);
        await close(oidc.server);
        await close(auth.server);
        await fs.rm(temp, { recursive: true, force: true });
      },
    };
  } catch (error) {
    if (admin?.server?.listening) await close(admin.server);
    if (oidc?.server?.listening) await close(oidc.server);
    if (auth?.server?.listening) await close(auth.server);
    await fs.rm(temp, { recursive: true, force: true });
    throw error;
  }
}

async function adminLogin(f, jar = new CookieJar()) {
  const started = await fetch(`${f.base}/admin/login`, { redirect: "manual" });
  jar.absorb(started);
  assert.equal(started.status, 302);
  const authorize = await fetch(started.headers.get("location"), {
    redirect: "manual",
    headers: { cookie: jar.header() },
  });
  assert.equal(authorize.status, 302);
  const callback = await fetch(authorize.headers.get("location"), {
    redirect: "manual",
    headers: { cookie: jar.header() },
  });
  jar.absorb(callback);
  assert.equal(callback.status, 302);
  assert.equal(callback.headers.get("location"), "/admin/");
  return jar;
}

async function me(f, jar) {
  const response = await fetch(`${f.base}/api/v1/admin/me`, {
    headers: { cookie: jar.header() },
  });
  return { response, body: await response.json() };
}

function seedOrganizations(f) {
  return f.admin.store.mutate((data) => {
    data.orgUnits = {
      "org-root": {
        id: "org-root",
        parentId: "",
        name: "Engineering",
        path: "/engineering",
        externalId: "idp-engineering",
        status: "active",
      },
      "org-platform": {
        id: "org-platform",
        parentId: "org-root",
        name: "Platform",
        path: "/engineering/platform",
        externalId: "idp-platform",
        status: "active",
      },
      "org-sales": {
        id: "org-sales",
        parentId: "",
        name: "Sales",
        path: "/sales",
        externalId: "idp-sales",
        status: "active",
      },
    };
    data.userOrgUnits = {
      usr_alice: "org-platform",
      usr_bob: "org-platform",
      usr_carol: "org-sales",
    };
  });
}

function bindRole(f, subjectId, role, scopeOrgUnitId, extraPermissions = []) {
  return f.admin.store.mutate((data) => {
    data.roleBindings = {
      "rb-test": {
        id: "rb-test",
        subjectType: "admin",
        subjectId,
        role,
        scopeOrgUnitId,
        validFrom: new Date(Date.now() - 60000).toISOString(),
        validTo: new Date(Date.now() + 3600000).toISOString(),
        createdBy: "test",
        extraPermissions,
      },
    };
  });
}

function usageLines() {
  const now = Date.now();
  const record = (hoursAgo, value) => JSON.stringify({
    t: new Date(now - hoursAgo * 3600 * 1000).toISOString(),
    ...value,
  });
  return [
    record(1, {
      callerKeyId: "key-alice-new",
      callerKeyName: "Alice new",
      agent: "claude",
      provider: "deepseek",
      req: "deepseek/deepseek-chat",
      status: 200,
      in: 100,
      out: 50,
      cache_read: 10,
      cost: 0.12,
    }),
    record(2, {
      callerKeyId: "key-alice-old",
      callerKeyName: "Alice old",
      agent: "codex",
      provider: "deepseek",
      req: "deepseek/deepseek-chat",
      status: 200,
      in: 20,
      out: 10,
      cost: 0.02,
    }),
    record(3, {
      callerKeyId: "key-bob",
      callerKeyName: "Bob",
      agent: "claude",
      provider: "openai",
      req: "openai/gpt-test",
      status: 500,
      in: 20,
      out: 0,
      cost: 0.03,
    }),
    record(4, {
      callerKeyId: "key-carol",
      callerKeyName: "Carol",
      agent: "opencode",
      provider: "deepseek",
      req: "deepseek/deepseek-chat",
      status: 200,
      in: 50,
      out: 25,
      cost: 0.05,
    }),
    record(5, {
      callerKeyId: "key-unattributed",
      agent: "unknown",
      req: "deepseek/deepseek-chat",
      status: 200,
      in: 7,
      out: 3,
      cost: 0.01,
    }),
  ].join("\n") + "\n";
}

function modelCatalogContent() {
  return JSON.stringify({
    schemaVersion: 1,
    models: [
      {
        id: "openai/gpt-5.2",
        provider: "openai",
        displayName: "GPT-5.2",
      },
      {
        id: "anthropic/claude-sonnet-5",
        provider: "anthropic",
        displayName: "Claude Sonnet 5",
      },
    ],
    providerWildcards: ["company-model"],
    groups: {
      "engineering-approved": [
        "openai/gpt-5.2",
        "anthropic/claude-sonnet-5",
      ],
    },
  });
}

async function adminGet(f, jar, pathname) {
  const response = await fetch(`${f.base}${pathname}`, {
    headers: { cookie: jar.header() },
  });
  return { response, body: await response.json() };
}

async function adminPost(f, jar, pathname, body, csrfToken = "", extraHeaders = {}) {
  const headers = {
    cookie: jar.header(),
    origin: f.base,
    "content-type": "application/json",
    ...extraHeaders,
  };
  if (csrfToken) headers["x-csrf-token"] = csrfToken;
  const response = await fetch(`${f.base}${pathname}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

function assertNoWriteSecrets(value, f, jar) {
  const serialized = JSON.stringify(value);
  for (const forbidden of [
    "should-not-leak-gateway-key",
    "should-not-leak-device-token",
    "should-not-leak-token-hash",
    "BEGIN PUBLIC KEY",
    "sk-magpie-issued-",
    "mdev_",
    "tokenHash",
    f.secrets.serviceToken,
    f.secrets.oidcClientSecret,
    jar.cookies.get(f.config.sessionCookieName) || "__no_cookie__",
  ]) {
    assert.ok(!serialized.includes(forbidden), `response must not contain ${forbidden}`);
  }
}

function readAdminData(f) {
  return f.admin.store.read((data) => structuredClone(data));
}

test("management OIDC login, CSRF, role removal and credential-safe storage", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const unauth = await fetch(`${f.base}/api/v1/admin/me`);
  assert.equal(unauth.status, 401);
  assert.equal((await unauth.json()).error.code, "not_signed_in");

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  assert.equal(current.response.status, 200);
  assert.equal(current.body.user.email, "admin@corp.example");
  assert.ok(current.body.roles.includes("super_admin"));
  assert.ok(current.body.permissions.includes("system.read"));
  assert.ok(current.body.scopeOrgUnitIds.includes("*"));
  assert.match(current.body.csrfToken, /^[A-Za-z0-9_-]+$/);
  assert.ok(!JSON.stringify(current.body).includes(f.secrets.oidcClientSecret));
  assert.ok(!JSON.stringify(current.body).includes(f.secrets.serviceToken));

  const page = await fetch(`${f.base}/admin/`, { headers: { cookie: jar.header() } });
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Engineering/);

  const health = await fetch(`${f.base}/api/v1/admin/health`, {
    headers: { cookie: jar.header() },
  });
  assert.equal(health.status, 200);
  assert.equal((await health.json()).auth.service, "auth");

  const noCsrf = await fetch(`${f.base}/api/v1/admin/logout`, {
    method: "POST",
    headers: {
      cookie: jar.header(),
      origin: f.base,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: "",
  });
  assert.equal(noCsrf.status, 403);
  assert.equal((await noCsrf.json()).error.code, "csrf_invalid");

  await f.admin.store.mutate((data) => {
    data.roleBindings = {};
  });
  const removed = await fetch(`${f.base}/api/v1/admin/health`, {
    headers: { cookie: jar.header() },
  });
  assert.equal(removed.status, 403);
  assert.equal((await removed.json()).error.code, "forbidden_role");

  const logout = await fetch(`${f.base}/api/v1/admin/logout`, {
    method: "POST",
    headers: {
      cookie: jar.header(),
      origin: f.base,
      "x-csrf-token": current.body.csrfToken,
    },
  });
  assert.equal(logout.status, 200);
  jar.absorb(logout);
  const afterLogout = await fetch(`${f.base}/api/v1/admin/me`, {
    headers: { cookie: jar.header() },
  });
  assert.equal(afterLogout.status, 401);

  const stored = await fs.readFile(f.config.storePath, "utf8");
  assert.ok(!stored.includes(f.secrets.oidcClientSecret));
  assert.ok(!stored.includes(f.secrets.serviceToken));
  assert.ok(!stored.includes(current.body.csrfToken));
  const sessionCookieValue = jar.cookies.get(f.config.sessionCookieName);
  if (sessionCookieValue) assert.ok(!stored.includes(sessionCookieValue));
});

test("department scope allows its subtree and rejects a sibling", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  assert.equal(current.response.status, 200);

  await f.admin.store.mutate((data) => {
    data.roleBindings = {
      "rb-dept": {
        id: "rb-dept",
        subjectType: "admin",
        subjectId: current.body.user.id,
        role: "department_admin",
        scopeOrgUnitId: "org-root",
        validFrom: new Date(Date.now() - 60000).toISOString(),
        validTo: new Date(Date.now() + 3600000).toISOString(),
        createdBy: "test",
        extraPermissions: [],
      },
    };
  });

  const list = await fetch(`${f.base}/api/v1/admin/org-units`, {
    headers: { cookie: jar.header() },
  });
  assert.equal(list.status, 200);
  const listed = (await list.json()).orgUnits.map((org) => org.id);
  assert.deepEqual(listed.sort(), ["org-platform", "org-root"]);

  const own = await fetch(`${f.base}/api/v1/admin/org-units/org-platform`, {
    headers: { cookie: jar.header() },
  });
  assert.equal(own.status, 200);

  const sibling = await fetch(`${f.base}/api/v1/admin/org-units/org-sales`, {
    headers: { cookie: jar.header() },
  });
  assert.equal(sibling.status, 403);
  assert.equal((await sibling.json()).error.code, "forbidden_scope");

  await f.admin.store.mutate((data) => {
    delete data.roleBindings["rb-dept"];
  });
  const denied = await fetch(`${f.base}/api/v1/admin/org-units`, {
    headers: { cookie: jar.header() },
  });
  assert.equal(denied.status, 403);
  assert.equal((await denied.json()).error.code, "forbidden_role");
});

test("M2-B read-only data is attributed and filtered by organization scope", { timeout: 30000 }, async (t) => {
  const f = await fixture({ usageContent: usageLines() });
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  assert.equal(current.response.status, 200);

  const users = await adminGet(f, jar, "/api/v1/admin/users");
  assert.equal(users.response.status, 200);
  assert.deepEqual(
    users.body.users.map((user) => user.id).sort(),
    ["usr_alice", "usr_bob", "usr_carol", "usr_unmapped"],
  );
  assert.equal(users.body.users.find((user) => user.id === "usr_alice").orgUnit.path, "/engineering/platform");

  const departments = await adminGet(f, jar, "/api/v1/admin/departments");
  assert.equal(departments.response.status, 200);
  assert.deepEqual(
    departments.body.departments.map((department) => department.id).sort(),
    ["org-platform", "org-root", "org-sales"],
  );

  const devices = await adminGet(f, jar, "/api/v1/admin/devices");
  assert.equal(devices.response.status, 200);
  assert.deepEqual(
    devices.body.devices.map((device) => device.id).sort(),
    ["dev_alice", "dev_bob", "dev_carol"],
  );

  const credentials = await adminGet(f, jar, "/api/v1/admin/credentials");
  assert.equal(credentials.response.status, 200);
  assert.deepEqual(
    credentials.body.credentials.map((credential) => credential.id).sort(),
    ["key-alice-new", "key-alice-old", "key-bob", "key-carol"],
  );
  const serializedCredentials = JSON.stringify(credentials.body);
  assert.ok(!serializedCredentials.includes("sk-magpie-issued-"));
  assert.ok(!serializedCredentials.includes("mdev_"));
  assert.ok(!serializedCredentials.includes("tokenHash"));
  assert.ok(!serializedCredentials.includes("BEGIN PUBLIC KEY"));

  const models = await adminGet(f, jar, "/api/v1/admin/models");
  assert.equal(models.response.status, 200);
  assert.deepEqual(models.body.models, [
    { id: "deepseek/deepseek-chat" },
    { id: "openai/gpt-test" },
  ]);
  assert.deepEqual(models.body.catalog, {
    source: "legacy_env",
    authorizationReady: false,
    catalogVersion: 0,
    catalogDigest: "",
    loadedAt: models.body.catalog.loadedAt,
    modelCount: 2,
    groupCount: 0,
    providerWildcardCount: 0,
  });
  assert.ok(Number.isFinite(Date.parse(models.body.catalog.loadedAt)));

  const summary = await adminGet(f, jar, "/api/v1/admin/usage/summary");
  assert.equal(summary.response.status, 200);
  assert.deepEqual(summary.body.totals, {
    requests: 4,
    successfulRequests: 3,
    errors: 1,
    rejected: 0,
    handedOn: 0,
    inputTokens: 190,
    outputTokens: 85,
    cacheReadTokens: 10,
    cacheWriteTokens: 0,
    totalTokens: 285,
    costUsd: 0.22,
    costKnownRecords: 4,
  });
  assert.deepEqual(summary.body.source, {
    bytes: Buffer.byteLength(usageLines()),
    lines: 5,
    recordsInWindow: 5,
    matchedRecords: 4,
    unattributedRecords: 1,
    outsideScopeRecords: 0,
  });
  assert.deepEqual(
    summary.body.dimensions.department.map((group) => [group.orgUnitId, group.requests]),
    [["org-platform", 3], ["org-sales", 1]],
  );
  assert.deepEqual(
    summary.body.dimensions.user.map((group) => [group.userId, group.requests]).sort(),
    [["usr_alice", 2], ["usr_bob", 1], ["usr_carol", 1]],
  );

  const page = await fetch(`${f.base}/admin/`, { headers: { cookie: jar.header() } });
  assert.equal(page.status, 200);
  const html = await page.text();
  for (const expected of ["Usage overview", "Users", "Devices", "Models", "Credentials", "Alice", "Carol"]) {
    assert.ok(html.includes(expected), `page should include ${expected}`);
  }
  assert.ok(!html.includes(f.secrets.serviceToken));
  assert.ok(!html.includes(f.secrets.oidcClientSecret));
  assert.ok(!html.includes(jar.cookies.get(f.config.sessionCookieName) || "__no_cookie__"));
  assert.ok(!html.includes("sk-magpie-issued-"));

  await bindRole(f, current.body.user.id, "department_admin", "org-root");
  const effective = await me(f, jar);
  assert.equal(effective.response.status, 200);
  assert.deepEqual(effective.body.roles, ["department_admin"]);

  const scopedUsers = await adminGet(f, jar, "/api/v1/admin/users");
  assert.equal(scopedUsers.response.status, 200);
  assert.deepEqual(
    scopedUsers.body.users.map((user) => user.id).sort(),
    ["usr_alice", "usr_bob"],
  );

  const scopedDevices = await adminGet(f, jar, "/api/v1/admin/devices");
  assert.equal(scopedDevices.response.status, 200);
  assert.deepEqual(
    scopedDevices.body.devices.map((device) => device.id).sort(),
    ["dev_alice", "dev_bob"],
  );

  const scopedCredentials = await adminGet(f, jar, "/api/v1/admin/credentials");
  assert.equal(scopedCredentials.response.status, 200);
  assert.deepEqual(
    scopedCredentials.body.credentials.map((credential) => credential.id).sort(),
    ["key-alice-new", "key-alice-old", "key-bob"],
  );

  const ownScopeUser = await adminGet(f, jar, "/api/v1/admin/users/usr_alice");
  assert.equal(ownScopeUser.response.status, 200);
  assert.equal(ownScopeUser.body.user.orgUnit.id, "org-platform");
  const crossScopeUser = await adminGet(f, jar, "/api/v1/admin/users/usr_carol");
  assert.equal(crossScopeUser.response.status, 403);
  assert.equal(crossScopeUser.body.error.code, "forbidden_scope");
  const missingUser = await adminGet(f, jar, "/api/v1/admin/users/usr_missing");
  assert.equal(missingUser.response.status, 404);
  assert.equal(missingUser.body.error.code, "target_not_found");

  const scopedSummary = await adminGet(f, jar, "/api/v1/admin/usage/summary");
  assert.equal(scopedSummary.response.status, 200);
  assert.deepEqual(scopedSummary.body.totals, {
    requests: 3,
    successfulRequests: 2,
    errors: 1,
    rejected: 0,
    handedOn: 0,
    inputTokens: 140,
    outputTokens: 60,
    cacheReadTokens: 10,
    cacheWriteTokens: 0,
    totalTokens: 210,
    costUsd: 0.17,
    costKnownRecords: 3,
  });
  assert.deepEqual(scopedSummary.body.source, {
    bytes: Buffer.byteLength(usageLines()),
    lines: 5,
    recordsInWindow: 5,
    matchedRecords: 3,
    unattributedRecords: 1,
    outsideScopeRecords: 1,
  });
  assert.deepEqual(
    scopedSummary.body.dimensions.department.map((group) => [group.orgUnitId, group.requests]),
    [["org-platform", 3]],
  );

  const from = new Date(Date.now() - 6 * 24 * 3600 * 1000).toISOString();
  const to = new Date(Date.now() + 60 * 1000).toISOString();
  const timeseries = await adminGet(
    f,
    jar,
    `/api/v1/admin/usage/timeseries?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&bucket=day&groupBy=department`,
  );
  assert.equal(timeseries.response.status, 200);
  assert.equal(timeseries.body.timezone, "UTC");
  assert.equal(timeseries.body.bucket, "day");
  assert.equal(timeseries.body.groupBy, "department");
  assert.equal(
    timeseries.body.points.reduce((sum, point) => sum + point.totals.requests, 0),
    3,
  );
  const groupedIds = timeseries.body.points.flatMap((point) => point.groups.map((group) => group.orgUnitId));
  assert.ok(groupedIds.length > 0);
  assert.ok(groupedIds.every((id) => id === "org-platform"));

  const scopedPage = await fetch(`${f.base}/admin/`, { headers: { cookie: jar.header() } });
  assert.equal(scopedPage.status, 200);
  const scopedHtml = await scopedPage.text();
  assert.ok(scopedHtml.includes("Alice"));
  assert.ok(scopedHtml.includes("Bob"));
  assert.ok(!scopedHtml.includes("Carol"));
});

test("C4-03a loads a pinned read-only model catalog and exposes only safe status", { timeout: 30000 }, async (t) => {
  const catalogContent = modelCatalogContent();
  const catalogDigest = `sha256:${crypto.createHash("sha256").update(catalogContent).digest("hex")}`;
  const f = await fixture({ catalogContent, catalogDigest });
  t.after(() => f.close());

  const jar = await adminLogin(f);
  const models = await adminGet(f, jar, "/api/v1/admin/models");
  assert.equal(models.response.status, 200);
  assert.deepEqual(models.body.models, [
    { id: "openai/gpt-5.2" },
    { id: "anthropic/claude-sonnet-5" },
  ]);
  assert.deepEqual(models.body.providerWildcards, ["company-model"]);
  assert.deepEqual(models.body.groups, [{
    name: "engineering-approved",
    models: ["openai/gpt-5.2", "anthropic/claude-sonnet-5"],
  }]);
  assert.deepEqual(models.body.catalog, {
    source: "file",
    authorizationReady: true,
    catalogVersion: 1,
    catalogDigest,
    loadedAt: models.body.catalog.loadedAt,
    modelCount: 2,
    groupCount: 1,
    providerWildcardCount: 1,
  });
  assert.ok(Number.isFinite(Date.parse(models.body.catalog.loadedAt)));

  const serializedModels = JSON.stringify(models.body);
  assert.ok(!serializedModels.includes("GPT-5.2"));
  assert.ok(!serializedModels.includes("Claude Sonnet 5"));
  assert.ok(!serializedModels.includes(f.catalogPath));

  const health = await adminGet(f, jar, "/api/v1/admin/health");
  assert.equal(health.response.status, 200);
  assert.deepEqual(health.body.modelCatalog, models.body.catalog);

  const healthz = await fetch(`${f.base}/healthz`);
  assert.equal(healthz.status, 200);
  const healthzBody = await healthz.json();
  assert.equal(healthzBody.ok, true);
  assert.deepEqual(healthzBody.modelCatalog, models.body.catalog);
  assert.ok(!JSON.stringify(healthzBody).includes(f.catalogPath));

  const page = await fetch(`${f.base}/admin/`, { headers: { cookie: jar.header() } });
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.ok(html.includes("Read-only model catalog loaded for authorization."));
  assert.ok(html.includes(catalogDigest));
  assert.ok(html.includes("2 models"));
  assert.ok(html.includes("1 groups"));
  assert.ok(!html.includes(f.catalogPath));

  const data = await readAdminData(f);
  const audits = data.adminSystemAuditLogs.filter((entry) => entry.action === "model_catalog.load");
  assert.equal(audits.length, 1);
  assert.equal(audits[0].result, "succeeded");
  assert.equal(audits[0].source, "file");
  assert.equal(audits[0].authorizationReady, true);
  assert.equal(audits[0].catalogVersion, 1);
  assert.equal(audits[0].catalogDigest, catalogDigest);
  assert.equal(audits[0].modelCount, 2);
  assert.equal(audits[0].groupCount, 1);
  assert.equal(audits[0].providerWildcardCount, 1);
  assert.ok(!JSON.stringify(audits[0]).includes(f.catalogPath));
});

test("C4-03a fails closed before serving when the catalog is invalid or has a bad digest", { timeout: 30000 }, async () => {
  await assert.rejects(
    () => fixture({ catalogContent: "{\"schemaVersion\":1}" }),
    (error) => error?.code === "model_catalog_invalid",
  );

  const catalogContent = modelCatalogContent();
  await assert.rejects(
    () => fixture({
      catalogContent,
      catalogDigest: `sha256:${"0".repeat(64)}`,
    }),
    (error) => error?.code === "model_catalog_digest_mismatch",
  );
});

test("auditor reads only permitted metadata and has no write permissions", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  await bindRole(f, current.body.user.id, "auditor", "org-sales");

  const effective = await me(f, jar);
  assert.equal(effective.response.status, 200);
  assert.equal(effective.body.user.id, current.body.user.id);
  for (const permission of ["users.disable", "devices.revoke", "credentials.rotate", "models.write", "roles.write"]) {
    assert.ok(!effective.body.permissions.includes(permission));
  }

  const users = await adminGet(f, jar, "/api/v1/admin/users");
  assert.equal(users.response.status, 200);
  assert.deepEqual(users.body.users.map((user) => user.id), ["usr_carol"]);

  const devices = await adminGet(f, jar, "/api/v1/admin/devices");
  assert.equal(devices.response.status, 200);
  assert.deepEqual(devices.body.devices.map((device) => device.id), ["dev_carol"]);

  const usage = await adminGet(f, jar, "/api/v1/admin/usage/summary");
  assert.equal(usage.response.status, 200);
  assert.equal(usage.body.totals.requests, 0);

  const credentials = await adminGet(f, jar, "/api/v1/admin/credentials");
  assert.equal(credentials.response.status, 403);
  assert.equal(credentials.body.error.code, "forbidden_role");
  const models = await adminGet(f, jar, "/api/v1/admin/models");
  assert.equal(models.response.status, 403);
  assert.equal(models.body.error.code, "forbidden_role");

  const crossScopeUser = await adminGet(f, jar, "/api/v1/admin/users/usr_alice");
  assert.equal(crossScopeUser.response.status, 403);
  assert.equal(crossScopeUser.body.error.code, "forbidden_scope");
});

test("M2-C2 global admin write routes call auth-service and return only safe fields", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  assert.equal(current.response.status, 200);
  assert.ok(current.body.permissions.includes("users.disable"));
  assert.ok(current.body.permissions.includes("devices.revoke"));
  assert.ok(current.body.permissions.includes("credentials.rotate"));

  const disabled = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    { reason: "Employee reported a lost laptop" },
    current.body.csrfToken,
    { "idempotency-key": "m2c2-global-disable-1" },
  );
  assert.equal(disabled.response.status, 200);
  assert.equal(disabled.body.action, "user.disable");
  assert.equal(disabled.body.targetId, "usr_alice");
  assert.equal(disabled.body.result.user.status, "disabled");
  assert.equal(disabled.body.result.affectedDevices, 1);
  assert.equal(disabled.body.result.affectedSessions, 1);
  assert.equal(disabled.body.result.affectedCredentials, 1);
  assert.deepEqual(disabled.body.result.revocations, {
    revoked: ["key-alice-new"],
    pending: 0,
  });

  const enabled = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/enable",
    { reason: "Device recovered and identity re-verified" },
    current.body.csrfToken,
  );
  assert.equal(enabled.response.status, 200);
  assert.equal(enabled.body.action, "user.enable");
  assert.equal(enabled.body.result.user.status, "active");
  assert.equal(enabled.body.result.requiresDeviceJoin, true);

  const revoked = await adminPost(
    f,
    jar,
    "/api/v1/admin/devices/dev_alice/revoke",
    { reason: "Device is no longer managed" },
    current.body.csrfToken,
  );
  assert.equal(revoked.response.status, 200);
  assert.equal(revoked.body.action, "device.revoke");
  assert.equal(revoked.body.result.device.id, "dev_alice");
  assert.equal(revoked.body.result.device.status, "revoked");
  assert.equal(revoked.body.result.affectedCredentials, 1);

  const rotated = await adminPost(
    f,
    jar,
    "/api/v1/admin/credentials/key-alice-new/rotate",
    { reason: "Routine credential rotation" },
    current.body.csrfToken,
  );
  assert.equal(rotated.response.status, 200);
  assert.equal(rotated.body.action, "credential.rotate");
  assert.equal(rotated.body.result.credentialId, "key-alice-new");
  assert.equal(rotated.body.result.newCredentialId, "key-rotated-key-alice-new");
  assert.equal(rotated.body.result.status, "awaiting_device_refresh");

  assert.deepEqual(f.auth.writeCalls, [
    { method: "POST", pathname: "/api/v1/internal/admin/users/usr_alice/disable" },
    { method: "POST", pathname: "/api/v1/internal/admin/users/usr_alice/enable" },
    { method: "POST", pathname: "/api/v1/internal/admin/devices/dev_alice/revoke" },
    { method: "POST", pathname: "/api/v1/internal/admin/credentials/key-alice-new/rotate" },
  ]);
  assertNoWriteSecrets(
    [disabled.body, enabled.body, revoked.body, rotated.body],
    f,
    jar,
  );
  const stored = await fs.readFile(f.config.storePath, "utf8");
  assertNoWriteSecrets(stored, f, jar);
});

test("M2-C2 scoped writes allow the subtree and reject siblings before dependency calls", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  await bindRole(f, current.body.user.id, "enterprise_admin", "org-root");
  const scoped = await me(f, jar);
  assert.equal(scoped.response.status, 200);
  assert.deepEqual(scoped.body.roles, ["enterprise_admin"]);
  assert.deepEqual(scoped.body.scopeOrgUnitIds.sort(), ["org-platform", "org-root"]);

  const ownUser = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_bob/disable",
    { reason: "Scoped administrator action" },
    scoped.body.csrfToken,
  );
  assert.equal(ownUser.response.status, 200);
  const ownDevice = await adminPost(
    f,
    jar,
    "/api/v1/admin/devices/dev_bob/revoke",
    { reason: "Scoped device revocation" },
    scoped.body.csrfToken,
  );
  assert.equal(ownDevice.response.status, 200);
  const ownCredential = await adminPost(
    f,
    jar,
    "/api/v1/admin/credentials/key-bob/rotate",
    { reason: "Scoped credential rotation" },
    scoped.body.csrfToken,
  );
  assert.equal(ownCredential.response.status, 200);
  assert.equal(f.auth.writeCalls.length, 3);

  const siblingUser = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_carol/disable",
    { reason: "Cross-scope attempt" },
    scoped.body.csrfToken,
  );
  assert.equal(siblingUser.response.status, 403);
  assert.equal(siblingUser.body.error.code, "forbidden_scope");

  const siblingDevice = await adminPost(
    f,
    jar,
    "/api/v1/admin/devices/dev_carol/revoke",
    { reason: "Cross-scope attempt" },
    scoped.body.csrfToken,
  );
  assert.equal(siblingDevice.response.status, 403);
  assert.equal(siblingDevice.body.error.code, "forbidden_scope");

  const siblingCredential = await adminPost(
    f,
    jar,
    "/api/v1/admin/credentials/key-carol/rotate",
    { reason: "Cross-scope attempt" },
    scoped.body.csrfToken,
  );
  assert.equal(siblingCredential.response.status, 403);
  assert.equal(siblingCredential.body.error.code, "forbidden_scope");
  assert.equal(f.auth.writeCalls.length, 3);

  const missingTarget = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_missing/disable",
    { reason: "Target does not exist" },
    scoped.body.csrfToken,
  );
  assert.equal(missingTarget.response.status, 404);
  assert.equal(missingTarget.body.error.code, "target_not_found");
  assert.equal(f.auth.writeCalls.length, 3);

  await bindRole(f, current.body.user.id, "auditor", "org-sales");
  const auditor = await me(f, jar);
  const auditorWrite = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_carol/disable",
    { reason: "Auditors are read-only" },
    auditor.body.csrfToken,
  );
  assert.equal(auditorWrite.response.status, 403);
  assert.equal(auditorWrite.body.error.code, "forbidden_role");
  assert.equal(f.auth.writeCalls.length, 3);
});

test("M2-C2 write validation fails closed before calling auth-service", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const csrfToken = current.body.csrfToken;

  const noCsrf = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    { reason: "Missing CSRF token" },
  );
  assert.equal(noCsrf.response.status, 403);
  assert.equal(noCsrf.body.error.code, "csrf_invalid");

  const noReason = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    { reason: "" },
    csrfToken,
  );
  assert.equal(noReason.response.status, 400);
  assert.equal(noReason.body.error.code, "invalid_reason");

  const badIdempotency = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    { reason: "Idempotency key is too long" },
    csrfToken,
    { "idempotency-key": "x".repeat(129) },
  );
  assert.equal(badIdempotency.response.status, 400);
  assert.equal(badIdempotency.body.error.code, "invalid_idempotency_key");

  const malformed = await fetch(`${f.base}/api/v1/admin/users/usr_alice/disable`, {
    method: "POST",
    headers: {
      cookie: jar.header(),
      origin: f.base,
      "content-type": "application/json",
      "x-csrf-token": csrfToken,
    },
    body: "{",
  });
  assert.equal(malformed.status, 400);
  assert.equal((await malformed.json()).error.code, "invalid_json");

  const missing = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_missing/disable",
    { reason: "Target does not exist" },
    csrfToken,
  );
  assert.equal(missing.response.status, 404);
  assert.equal(missing.body.error.code, "target_not_found");
  assert.equal(f.auth.writeCalls.length, 0);

  f.auth.setFailing(true);
  const unavailable = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    { reason: "Dependency failure" },
    csrfToken,
  );
  assert.equal(unavailable.response.status, 502);
  assert.equal(unavailable.body.error.code, "dependency_unavailable");
  assertNoWriteSecrets(unavailable.body, f, jar);
  assert.equal(f.auth.writeCalls.length, 0);
});

test("M2-C3 writes persist operation state and intent/result management audits", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const idempotencyKey = "m2c3-audit-key-1";
  const disabled = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    { reason: "Lost device requires immediate suspension", approvalId: "INC-1001" },
    current.body.csrfToken,
    { "idempotency-key": idempotencyKey },
  );
  assert.equal(disabled.response.status, 200);
  assert.match(disabled.body.operationId, /^op_/);
  assert.equal(disabled.body.requestId, disabled.response.headers.get("x-request-id"));

  const enabled = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/enable",
    { reason: "Identity and device were re-verified" },
    current.body.csrfToken,
  );
  assert.equal(enabled.response.status, 200);
  assert.match(enabled.body.operationId, /^op_/);
  assert.notEqual(enabled.body.operationId, disabled.body.operationId);

  const data = await readAdminData(f);
  const operation = data.adminOperations[disabled.body.operationId];
  assert.ok(operation);
  assert.equal(operation.status, "succeeded");
  assert.equal(operation.actorSubjectId, current.body.user.id);
  assert.equal(operation.actorEmail, "admin@corp.example");
  assert.equal(operation.action, "user.disable");
  assert.equal(operation.targetId, "usr_alice");
  assert.equal(operation.reason, "Lost device requires immediate suspension");
  assert.equal(operation.approvalId, "INC-1001");
  assert.equal(operation.responseStatus, 200);
  assert.equal(operation.responseBody.operationId, disabled.body.operationId);
  assert.equal(operation.beforeSummary.status, "active");
  assert.ok(operation.userAgentHash);
  assert.equal(Object.keys(data.adminIdempotency).length, 1);
  assert.ok(!JSON.stringify(data).includes(idempotencyKey));

  const audits = data.adminAuditLogs.filter((audit) => audit.operationId === operation.id);
  assert.deepEqual(audits.map((audit) => audit.phase), ["intent", "result"]);
  assert.equal(audits[0].result, "pending");
  assert.equal(audits[0].reason, "Lost device requires immediate suspension");
  assert.equal(audits[0].approvalId, "INC-1001");
  assert.equal(audits[1].result, "succeeded");
  assert.equal(audits[1].afterSummary.user.id, "usr_alice");
  assert.ok(audits.every((audit) => audit.requestId === disabled.body.requestId));
  const enabledOperation = data.adminOperations[enabled.body.operationId];
  assert.equal(enabledOperation.status, "succeeded");
  assert.equal(enabledOperation.idempotencyKeyHash, "");
  assert.deepEqual(
    data.adminAuditLogs
      .filter((audit) => audit.operationId === enabledOperation.id)
      .map((audit) => audit.phase),
    ["intent", "result"],
  );
  assertNoWriteSecrets(disabled.body, f, jar);
  assertNoWriteSecrets(data, f, jar);
});

test("M2-C3 replays successful writes, rejects key conflicts, and runs concurrent writes once", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const idempotencyKey = "m2c3-replay-key-1";
  const pathName = "/api/v1/admin/users/usr_alice/disable";
  const body = { reason: "Replay-safe suspension" };

  const first = await adminPost(
    f,
    jar,
    pathName,
    body,
    current.body.csrfToken,
    { "idempotency-key": idempotencyKey },
  );
  assert.equal(first.response.status, 200);
  assert.equal(f.auth.writeCalls.length, 1);

  const replay = await adminPost(
    f,
    jar,
    pathName,
    body,
    current.body.csrfToken,
    { "idempotency-key": idempotencyKey },
  );
  assert.equal(replay.response.status, 200);
  assert.equal(replay.body.operationId, first.body.operationId);
  assert.equal(replay.body.requestId, first.body.requestId);
  assert.equal(f.auth.writeCalls.length, 1);

  const conflict = await adminPost(
    f,
    jar,
    pathName,
    { reason: "A different request must not reuse the key" },
    current.body.csrfToken,
    { "idempotency-key": idempotencyKey },
  );
  assert.equal(conflict.response.status, 409);
  assert.equal(conflict.body.error.code, "idempotency_conflict");
  assert.equal(conflict.body.error.operationId, first.body.operationId);
  assert.equal(f.auth.writeCalls.length, 1);

  f.auth.setWriteDelay(400);
  const concurrentKey = "m2c3-concurrent-key-1";
  const concurrentPath = "/api/v1/admin/devices/dev_bob/revoke";
  const concurrentBody = { reason: "Concurrent idempotency check" };
  const concurrent = await Promise.all([
    adminPost(
      f,
      jar,
      concurrentPath,
      concurrentBody,
      current.body.csrfToken,
      { "idempotency-key": concurrentKey },
    ),
    adminPost(
      f,
      jar,
      concurrentPath,
      concurrentBody,
      current.body.csrfToken,
      { "idempotency-key": concurrentKey },
    ),
  ]);
  concurrent.sort((left, right) => left.response.status - right.response.status);
  assert.deepEqual(concurrent.map((result) => result.response.status), [200, 409]);
  assert.equal(concurrent[0].body.action, "device.revoke");
  assert.equal(concurrent[1].body.error.code, "operation_in_progress");
  assert.equal(concurrent[1].body.error.operationId, concurrent[0].body.operationId);
  assert.equal(f.auth.writeCalls.length, 2);

  const data = await readAdminData(f);
  const concurrentAudits = data.adminAuditLogs.filter(
    (audit) => audit.operationId === concurrent[0].body.operationId,
  );
  assert.deepEqual(concurrentAudits.map((audit) => audit.phase), ["intent", "result"]);
  assertNoWriteSecrets([first.body, replay.body, conflict.body, concurrent[0].body, concurrent[1].body], f, jar);
});

test("M2-C3 intent audit failure blocks the auth-service call", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const originalMutate = f.admin.store.mutate.bind(f.admin.store);
  f.admin.store.mutate = (fn) => originalMutate((draft) => {
    const operationsBefore = Object.keys(draft.adminOperations).length;
    const result = fn(draft);
    if (Object.keys(draft.adminOperations).length > operationsBefore) {
      throw new Error("simulated audit write failure");
    }
    return result;
  });

  const response = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    { reason: "Intent audit must fail closed" },
    current.body.csrfToken,
    { "idempotency-key": "m2c3-intent-failure-1" },
  );
  assert.equal(response.response.status, 503);
  assert.equal(response.body.error.code, "audit_unavailable");
  assert.equal(f.auth.writeCalls.length, 0);

  const data = await readAdminData(f);
  assert.deepEqual(data.adminOperations, {});
  assert.deepEqual(data.adminAuditLogs, []);
});

test("M2-C3 dependency failures are result-audited before the stable error is returned", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  f.auth.setWriteFailing(true);
  const response = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    { reason: "Dependency failure must be audited" },
    current.body.csrfToken,
    { "idempotency-key": "m2c3-result-failure-1" },
  );
  assert.equal(response.response.status, 502);
  assert.equal(response.body.error.code, "dependency_unavailable");
  assert.match(response.body.error.operationId, /^op_/);

  const data = await readAdminData(f);
  const operation = data.adminOperations[response.body.error.operationId];
  assert.equal(operation.status, "failed");
  assert.equal(operation.responseStatus, 502);
  assert.equal(operation.errorCode, "dependency_unavailable");
  const audits = data.adminAuditLogs.filter((audit) => audit.operationId === operation.id);
  assert.deepEqual(audits.map((audit) => audit.phase), ["intent", "result"]);
  assert.equal(audits[1].result, "failed");
  assert.equal(audits[1].errorCode, "dependency_unavailable");

  const replay = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    { reason: "Dependency failure must be audited" },
    current.body.csrfToken,
    { "idempotency-key": "m2c3-result-failure-1" },
  );
  assert.equal(replay.response.status, 502);
  assert.equal(replay.body.error.code, "dependency_unavailable");
  assert.equal(replay.body.error.operationId, operation.id);
  assert.equal(f.auth.writeCalls.length, 1);
  assertNoWriteSecrets(data, f, jar);
});

test("M2-C3 result audit failure never returns success and leaves the operation incomplete", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const originalMutate = f.admin.store.mutate.bind(f.admin.store);
  let failResultCommit = true;
  f.admin.store.mutate = (fn) => originalMutate((draft) => {
    const statusesBefore = Object.fromEntries(
      Object.entries(draft.adminOperations).map(([id, operation]) => [id, operation.status]),
    );
    const result = fn(draft);
    const completed = Object.entries(draft.adminOperations).some(([id, operation]) => (
      statusesBefore[id] === "dependency_invoked"
      && (operation.status === "succeeded" || operation.status === "failed")
    ));
    if (failResultCommit && completed) {
      failResultCommit = false;
      throw new Error("simulated result audit write failure");
    }
    return result;
  });

  const response = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    { reason: "The result audit must fail closed" },
    current.body.csrfToken,
    { "idempotency-key": "m2c3-result-audit-failure-1" },
  );
  assert.equal(response.response.status, 503);
  assert.equal(response.body.error.code, "audit_unavailable");
  assert.match(response.body.error.operationId, /^op_/);
  assert.equal(f.auth.writeCalls.length, 1);

  const data = await readAdminData(f);
  const operation = data.adminOperations[response.body.error.operationId];
  assert.equal(operation.status, "dependency_invoked");
  assert.equal(operation.responseStatus, 0);
  assert.equal(operation.responseBody, null);
  assert.equal(operation.resultAuditId, "");
  const audits = data.adminAuditLogs.filter((audit) => audit.operationId === operation.id);
  assert.deepEqual(audits.map((audit) => audit.phase), ["intent"]);
  assert.equal(audits[0].result, "pending");
  assertNoWriteSecrets(data, f, jar);
});

test("usage storage failures are not rendered as partial reports", { timeout: 30000 }, async (t) => {
  const f = await fixture({ maxLineBytes: "1024", maxFields: "16", maxRecords: "2" });
  t.after(() => f.close());
  const jar = await adminLogin(f);

  async function expectUnavailable() {
    const response = await adminGet(f, jar, "/api/v1/admin/usage/summary");
    assert.equal(response.response.status, 503);
    assert.equal(response.body.error.code, "storage_unavailable");
  }

  await fs.unlink(f.usagePath);
  await expectUnavailable();
  const page = await fetch(`${f.base}/admin/`, { headers: { cookie: jar.header() } });
  assert.equal(page.status, 200);
  assert.match(await page.text(), /storage_unavailable/);

  await fs.writeFile(f.usagePath, "{not-json\n", "utf8");
  await expectUnavailable();

  const valid = JSON.stringify({
    t: new Date().toISOString(),
    callerKeyId: "key-alice-new",
  });
  await fs.writeFile(f.usagePath, valid, "utf8");
  await expectUnavailable();

  await fs.writeFile(f.usagePath, `${JSON.stringify({ t: new Date().toISOString(), padding: "x".repeat(1100) })}\n`, "utf8");
  await expectUnavailable();

  const manyFields = { t: new Date().toISOString() };
  for (let index = 0; index < 16; index += 1) manyFields[`f${index}`] = index;
  await fs.writeFile(f.usagePath, `${JSON.stringify(manyFields)}\n`, "utf8");
  await expectUnavailable();

  const oneRecord = `${JSON.stringify({ t: new Date().toISOString(), callerKeyId: "key-alice-new" })}\n`;
  await fs.writeFile(f.usagePath, oneRecord.repeat(3), "utf8");
  await expectUnavailable();
});

test("usage query parameters are validated at the service boundary", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const jar = await adminLogin(f);

  const invalidBucket = await adminGet(f, jar, "/api/v1/admin/usage/timeseries?bucket=week");
  assert.equal(invalidBucket.response.status, 400);
  assert.equal(invalidBucket.body.error.code, "invalid_bucket");

  const invalidGroupBy = await adminGet(f, jar, "/api/v1/admin/usage/timeseries?groupBy=project");
  assert.equal(invalidGroupBy.response.status, 400);
  assert.equal(invalidGroupBy.body.error.code, "invalid_group_by");

  const invalidRange = await adminGet(
    f,
    jar,
    "/api/v1/admin/usage/summary?from=2026-11-02T00%3A00%3A00Z&to=2026-11-01T00%3A00%3A00Z",
  );
  assert.equal(invalidRange.response.status, 400);
  assert.equal(invalidRange.body.error.code, "invalid_time_range");

  const tooLarge = await adminGet(
    f,
    jar,
    "/api/v1/admin/usage/summary?from=2024-01-01T00%3A00%3A00Z&to=2026-11-01T00%3A00%3A00Z",
  );
  assert.equal(tooLarge.response.status, 400);
  assert.equal(tooLarge.body.error.code, "time_range_too_large");
});

test("absolute and idle session expiry return stable errors", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());

  const absoluteJar = await adminLogin(f);
  await f.admin.store.mutate((data) => {
    const session = Object.values(data.adminSessions)[0];
    session.expiresAt = new Date(Date.now() - 1000).toISOString();
  });
  const expired = await fetch(`${f.base}/api/v1/admin/me`, {
    headers: { cookie: absoluteJar.header() },
  });
  assert.equal(expired.status, 401);
  assert.equal((await expired.json()).error.code, "session_expired");
  assert.ok(expired.headers.getSetCookie().some((value) => value.startsWith(`${f.config.sessionCookieName}=;`)
    && /Max-Age=0/i.test(value)));

  const idleJar = await adminLogin(f);
  await f.admin.store.mutate((data) => {
    const session = Object.values(data.adminSessions)[0];
    session.lastSeenAt = new Date(Date.now() - 31 * 60 * 1000).toISOString();
    session.expiresAt = new Date(Date.now() + 3600000).toISOString();
  });
  const idle = await fetch(`${f.base}/api/v1/admin/me`, {
    headers: { cookie: idleJar.header() },
  });
  assert.equal(idle.status, 401);
  assert.equal((await idle.json()).error.code, "session_idle");
});

test("management MFA is required", { timeout: 30000 }, async (t) => {
  const f = await fixture({ claims: { amr: ["pwd"] } });
  t.after(() => f.close());

  const jar = new CookieJar();
  const started = await fetch(`${f.base}/admin/login`, { redirect: "manual" });
  jar.absorb(started);
  const authorize = await fetch(started.headers.get("location"), {
    redirect: "manual",
    headers: { cookie: jar.header() },
  });
  const callback = await fetch(authorize.headers.get("location"), {
    redirect: "manual",
    headers: { cookie: jar.header() },
  });
  assert.equal(callback.status, 403);
  assert.equal((await callback.json()).error.code, "mfa_required");
});

test("management identity requires a verified email", { timeout: 30000 }, async (t) => {
  const f = await fixture({ claims: { email_verified: false } });
  t.after(() => f.close());

  const jar = new CookieJar();
  const started = await fetch(`${f.base}/admin/login`, { redirect: "manual" });
  jar.absorb(started);
  const authorize = await fetch(started.headers.get("location"), {
    redirect: "manual",
    headers: { cookie: jar.header() },
  });
  const callback = await fetch(authorize.headers.get("location"), {
    redirect: "manual",
    headers: { cookie: jar.header() },
  });
  assert.equal(callback.status, 403);
  assert.equal((await callback.json()).error.code, "email_not_verified");
});

test("configured ACR values are requested from the IdP", { timeout: 30000 }, async (t) => {
  const f = await fixture({
    allowedAcrValues: "urn:corp:mfa",
    claims: { acr: "urn:corp:mfa" },
  });
  t.after(() => f.close());

  await adminLogin(f);
  assert.equal(f.oidc.lastAuthorize.searchParams.get("acr_values"), "urn:corp:mfa");
  const claims = JSON.parse(f.oidc.lastAuthorize.searchParams.get("claims"));
  assert.deepEqual(claims.id_token.acr.values, ["urn:corp:mfa"]);
  assert.equal(claims.id_token.acr.essential, true);
});

test("IP allow list fails closed and rejects invalid CIDR", async () => {
  assert.throws(() => loadConfig({
    ADMIN_SESSION_SECRET: "{{SECRET_adminsessionsecret}}-test-only-padding-0001",
    ADMIN_OIDC_ISSUER: "https://idp.example",
    ADMIN_OIDC_CLIENT_ID: "admin",
    ADMIN_OIDC_CLIENT_SECRET: "{{SECRET_adminoidcclient}}-test-only-padding-0001",
    ADMIN_AUTH_SERVICE_URL: "http://127.0.0.1:3444",
    ADMIN_AUTH_SERVICE_TOKEN: "{{SECRET_adminservicetoken}}-test-only-padding-0001",
    ADMIN_ALLOWED_IPS: "not-a-network",
  }), /ADMIN_ALLOWED_IPS/);

  const f = await fixture({ allowedIps: "10.0.0.0/8" });
  try {
    const denied = await fetch(`${f.base}/healthz`);
    assert.equal(denied.status, 403);
    assert.equal((await denied.json()).error.code, "ip_not_allowed");
  } finally {
    await f.close();
  }
});

test("auth-service failure is dependency_unavailable without secret logs", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const jar = await adminLogin(f);
  f.auth.setFailing(true);

  const errors = [];
  const originalError = console.error;
  console.error = (...values) => errors.push(values.join(" "));
  t.after(() => {
    console.error = originalError;
  });

  const response = await fetch(`${f.base}/api/v1/admin/health`, {
    headers: { cookie: jar.header() },
  });
  assert.equal(response.status, 502);
  assert.equal((await response.json()).error.code, "dependency_unavailable");
  const usage = await fetch(`${f.base}/api/v1/admin/usage/summary`, {
    headers: { cookie: jar.header() },
  });
  assert.equal(usage.status, 502);
  assert.equal((await usage.json()).error.code, "dependency_unavailable");
  const logs = errors.join("\n");
  assert.ok(!logs.includes(f.secrets.serviceToken));
  assert.ok(!logs.includes(f.secrets.oidcClientSecret));
  assert.ok(!logs.includes(jar.cookies.get(f.config.sessionCookieName) || "__no_cookie__"));
});

test("an older admin store gains operation collections without losing its existing state", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-admin-store-upgrade-"));
  try {
    const file = path.join(temp, "admin-store.json");
    const older = {
      version: 1,
      orgUnits: {
        "org-kept": {
          id: "org-kept",
          parentId: "",
          name: "Kept",
          path: "/kept",
          status: "active",
        },
      },
      userOrgUnits: { usr_kept: "org-kept" },
      roleBindings: {},
      adminSessions: {},
      adminAuditLogs: [],
    };
    await fs.writeFile(file, `${JSON.stringify(older)}\n`, "utf8");
    const store = new JsonStore(file);
    const loaded = await store.load();
    assert.equal(loaded.orgUnits["org-kept"].name, "Kept");
    assert.deepEqual(loaded.adminOperations, {});
    assert.deepEqual(loaded.adminIdempotency, {});
  } finally {
    await fs.rm(temp, { recursive: true, force: true });
  }
});

test("a malformed admin store is not treated as empty", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-admin-store-"));
  try {
    const file = path.join(temp, "admin-store.json");
    await fs.writeFile(file, "{not-json", "utf8");
    const store = new JsonStore(file);
    await assert.rejects(() => store.load());
    assert.equal(await fs.readFile(file, "utf8"), "{not-json");
  } finally {
    await fs.rm(temp, { recursive: true, force: true });
  }
});
