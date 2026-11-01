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
import {
  approvalBindingDigest,
  approvalPayloadDigest,
  normalizedApprovalPayload,
  riskForAction,
} from "../src/approval.js";

const CALLBACK_SECRET = "approval-callback-test-secret-0000000001";
const CALLBACK_ISSUER = "https://approval.corp.example";
const CALLBACK_AUDIENCE = "magpie-enterprise-admin-test";

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
  let loginClaims = options.claims || {};

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
        claims: structuredClone(loginClaims),
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
        ...code.claims,
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
    setClaims(value) { loginClaims = value || options.claims || {}; },
  };
}

function createMockAuthService(expectedToken) {
  let failing = false;
  let writeFailing = false;
  let writeDelayMs = 0;
  const writeCalls = [];
  const reconcileCalls = [];
  const users = [
    {
      id: "usr_alice",
      email: "alice@corp.example",
      name: "Alice",
      status: "active",
      createdAt: "2026-10-01T00:00:00.000Z",
      lastLoginAt: "2026-10-31T08:00:00.000Z",
      policy: {
        version: 2,
        models: ["deepseek/deepseek-chat"],
        limits: [],
        quotaStatus: "known",
        modelStatus: "known",
        including: ["quota", "models"],
        missing: [],
        updatedAt: "2026-10-31T08:00:00.000Z",
        confirmedAt: "2026-10-31T08:01:00.000Z",
        operationId: "op_mock_policy_ready",
      },
    },
    {
      id: "usr_bob",
      email: "bob@corp.example",
      name: "Bob",
      status: "active",
      createdAt: "2026-10-02T00:00:00.000Z",
      lastLoginAt: "2026-10-31T09:00:00.000Z",
      policy: {
        version: 1,
        models: null,
        limits: [],
        quotaStatus: "known",
        modelStatus: "unknown",
        including: ["quota"],
        missing: ["models"],
        updatedAt: "2026-10-31T09:00:00.000Z",
        confirmedAt: "",
        operationId: "op_mock_policy_pending",
      },
    },
    {
      id: "usr_carol",
      email: "carol@corp.example",
      name: "Carol",
      status: "active",
      createdAt: "2026-10-03T00:00:00.000Z",
      lastLoginAt: "2026-10-31T10:00:00.000Z",
      policy: {
        version: 0,
        models: null,
        limits: null,
        quotaStatus: "unknown",
        modelStatus: "unknown",
        including: [],
        missing: ["quota", "models"],
        updatedAt: "",
        confirmedAt: "",
        operationId: "",
      },
    },
    {
      id: "usr_unmapped",
      email: "unmapped@corp.example",
      name: "Unmapped",
      status: "active",
      createdAt: "2026-10-04T00:00:00.000Z",
      lastLoginAt: "2026-10-31T11:00:00.000Z",
      policy: {
        version: 0,
        models: null,
        limits: null,
        quotaStatus: "unknown",
        modelStatus: "unknown",
        including: [],
        missing: ["quota", "models"],
        updatedAt: "",
        confirmedAt: "",
        operationId: "",
      },
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
      policyVersion: 2,
      policySyncState: "synced",
      lastPolicyResult: "synced",
      lastPolicySyncedAt: "2026-10-31T08:01:00.000Z",
      lastPolicyOperationId: "op_mock_policy_ready",
      lastPolicyGatewayRequestId: "gwreq_mock_alice",
      lastPolicyRevision: "policy:mock:2",
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
      policyVersion: 1,
      policySyncState: "synced",
      lastPolicyResult: "synced",
      lastPolicySyncedAt: "2026-10-30T00:01:00.000Z",
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
      policyVersion: 1,
      policySyncState: "pending",
      lastPolicyResult: "pending",
      lastPolicyErrorCode: "policy_sync_in_progress",
      lastPolicyAttemptedAt: "2026-10-31T09:01:00.000Z",
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
      policyVersion: 0,
      policySyncState: "unknown",
      lastPolicyResult: "unknown",
      lastPolicyErrorCode: "policy_unknown",
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
    let parsedBody = null;
    async function requestBody() {
      if (parsedBody !== null) return parsedBody;
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const text = Buffer.concat(chunks).toString("utf8");
      parsedBody = text ? JSON.parse(text) : {};
      return parsedBody;
    }
    const reconcileWrite = /^\/api\/v1\/internal\/admin\/users\/([A-Za-z0-9_-]+)\/policy\/reconcile$/.exec(
      url.pathname,
    );
    if (req.method === "POST" && reconcileWrite) {
      const body = await requestBody();
      reconcileCalls.push({ method: req.method, pathname: url.pathname, body });
      if (writeFailing) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "write_unavailable" } }));
        return;
      }
      await delayWrite();
      const user = users.find((candidate) => candidate.id === reconcileWrite[1]);
      if (!user) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "user_not_found" } }));
        return;
      }
      if (body.expectedVersion !== user.policy.version) {
        res.writeHead(409, { "content-type": "application/json" });
        res.end(JSON.stringify({
          error: {
            code: "policy_version_conflict",
            message: "The user policy changed; reload it and retry",
            currentVersion: user.policy.version,
            expectedVersion: body.expectedVersion,
          },
        }));
        return;
      }
      user.policy.models = body.models;
      user.policy.limits = body.limits;
      user.policy.version += 1;
      user.policy.quotaStatus = "known";
      user.policy.modelStatus = "known";
      user.policy.including = ["quota", "models"];
      user.policy.missing = [];
      user.policy.updatedAt = "2026-10-31T12:00:00.000Z";
      user.policy.confirmedAt = "2026-10-31T12:00:01.000Z";
      user.policy.operationId = body.operationId;
      for (const credential of credentials) {
        if (credential.userId !== user.id || credential.status !== "active") continue;
        credential.policyVersion = user.policy.version;
        credential.policySyncState = "synced";
        credential.models = [...user.policy.models];
        credential.lastPolicyOperationId = body.operationId;
      }
      ok({
        ok: true,
        data: {
          operationId: body.operationId,
          state: "succeeded",
          policy: { ...user.policy },
          credentials: {
            total: 1,
            succeeded: 1,
            failed: 0,
            pending: 0,
            unknown: 0,
            failedOnly: 0,
            failedItems: [],
          },
          requiresReconciliation: false,
          gatewayKey: "should-not-leak-gateway-key",
          tokenHash: "should-not-leak-token-hash",
          requestBody: "must-not-leak",
          prompt: "must-not-leak",
        },
      });
      return;
    }
    const policyWrite = /^\/api\/v1\/internal\/admin\/users\/([A-Za-z0-9_-]+)\/policy\/(quota|models)$/.exec(
      url.pathname,
    );
    if (policyWrite
        && ((policyWrite[2] === "quota" && req.method === "PUT")
          || (policyWrite[2] === "models" && req.method === "PATCH"))) {
      const body = await requestBody();
      writeCalls.push({ method: req.method, pathname: url.pathname, body });
      if (writeFailing) {
        res.writeHead(503, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "write_unavailable" } }));
        return;
      }
      await delayWrite();
      const user = users.find((candidate) => candidate.id === policyWrite[1]);
      if (!user) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: "user_not_found" } }));
        return;
      }
      if (body.expectedVersion !== user.policy.version) {
        res.writeHead(409, { "content-type": "application/json" });
        res.end(JSON.stringify({
          error: {
            code: "policy_version_conflict",
            message: "The user policy changed; reload it and retry",
            currentVersion: user.policy.version,
            expectedVersion: body.expectedVersion,
          },
        }));
        return;
      }
      if (policyWrite[2] === "quota") user.policy.limits = body.limits;
      else user.policy.models = body.models;
      user.policy.version += 1;
      user.policy.quotaStatus = Array.isArray(user.policy.limits) ? "known" : "unknown";
      user.policy.modelStatus = Array.isArray(user.policy.models) ? "known" : "unknown";
      user.policy.including = [
        ...(Array.isArray(user.policy.limits) ? ["quota"] : []),
        ...(Array.isArray(user.policy.models) ? ["models"] : []),
      ];
      user.policy.missing = [
        ...(Array.isArray(user.policy.limits) ? [] : ["quota"]),
        ...(Array.isArray(user.policy.models) ? [] : ["models"]),
      ];
      user.policy.updatedAt = "2026-10-31T12:00:00.000Z";
      user.policy.confirmedAt = user.policy.missing.length === 0
        ? "2026-10-31T12:00:01.000Z"
        : "";
      user.policy.operationId = body.operationId;
      ok({
        ok: true,
        data: {
          operationId: body.operationId,
          state: user.policy.missing.length === 0 ? "succeeded" : "pending_sync",
          policy: { ...user.policy },
          credentials: {
            total: 1,
            succeeded: user.policy.missing.length === 0 ? 1 : 0,
            failed: user.policy.missing.length === 0 ? 0 : 1,
            pending: user.policy.missing.length === 0 ? 0 : 1,
            unknown: 0,
            failedOnly: 0,
            failedItems: user.policy.missing.length === 0 ? [] : [{
              credentialId: `key-${user.id}`,
              deviceId: `dev-${user.id}`,
              errorCode: "policy_sync_in_progress",
            }],
          },
          requiresReconciliation: user.policy.missing.length !== 0,
          gatewayKey: "should-not-leak-gateway-key",
          tokenHash: "should-not-leak-token-hash",
        },
      });
      return;
    }
    const userWrite = /^\/api\/v1\/internal\/admin\/users\/([A-Za-z0-9_-]+)\/(disable|enable)$/.exec(
      url.pathname,
    );
    if (req.method === "POST" && userWrite) {
      const body = await requestBody();
      writeCalls.push({ method: req.method, pathname: url.pathname, body });
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
      const body = await requestBody();
      writeCalls.push({ method: req.method, pathname: url.pathname, body });
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
      const body = await requestBody();
      writeCalls.push({ method: req.method, pathname: url.pathname, body });
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
    get reconcileCalls() { return reconcileCalls; },
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
    const callbackDisabled = options.callbackEnabled === false;
    const callbackSecret = options.callbackSecret !== undefined
      ? options.callbackSecret
      : (callbackDisabled ? "" : CALLBACK_SECRET);
    const callbackIssuer = options.callbackIssuer !== undefined
      ? options.callbackIssuer
      : (callbackDisabled ? "" : CALLBACK_ISSUER);
    const callbackAudience = options.callbackAudience !== undefined
      ? options.callbackAudience
      : (callbackDisabled ? "" : CALLBACK_AUDIENCE);
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
      ADMIN_APPROVAL_CALLBACK_SECRET: callbackSecret,
      ADMIN_APPROVAL_CALLBACK_ISSUER: callbackIssuer,
      ADMIN_APPROVAL_CALLBACK_AUDIENCE: callbackAudience,
      ADMIN_APPROVAL_CALLBACK_MAX_SKEW_SECONDS: "300",
      ADMIN_APPROVAL_CALLBACK_NONCE_TTL_SECONDS: "600",
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
        callbackSecret,
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

async function adminLogin(f, jar = new CookieJar(), claims = undefined) {
  f.oidc.setClaims(claims);
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

function addRoleBinding(f, id, subjectId, role, scopeOrgUnitId, extraPermissions = []) {
  return f.admin.store.mutate((data) => {
    data.roleBindings[id] = {
      id,
      subjectType: "admin",
      subjectId,
      role,
      scopeOrgUnitId,
      validFrom: new Date(Date.now() - 60000).toISOString(),
      validTo: new Date(Date.now() + 3600000).toISOString(),
      createdBy: "test",
      extraPermissions,
    };
  });
}

async function independentApprover(f, options = {}) {
  const suffix = options.suffix || crypto.randomUUID().slice(0, 12);
  const jar = new CookieJar();
  await adminLogin(f, jar, {
    sub: `admin-${suffix}`,
    email: `${suffix}@corp.example`,
    name: options.name || `Approver ${suffix}`,
  });
  let current = await me(f, jar);
  await addRoleBinding(
    f,
    `rb-approver-${suffix}`,
    current.body.user.id,
    options.role || "enterprise_admin",
    options.scopeOrgUnitId || "*",
  );
  current = await me(f, jar);
  assert.equal(current.response.status, 200);
  return { jar, current, suffix };
}

async function requestApproval(f, jar, current, body) {
  const result = await adminPost(
    f,
    jar,
    "/api/v1/admin/approvals",
    body,
    current.body.csrfToken,
  );
  assert.equal(result.response.status, 201, JSON.stringify(result.body));
  assert.match(result.body.approval.approvalId, /^apr_/);
  return result.body.approval;
}

async function decideApproval(f, approver, approvalId, decision = "approve", reason = "Independent review") {
  const result = await adminPost(
    f,
    approver.jar,
    `/api/v1/admin/approvals/${approvalId}/decisions`,
    { decision, reason },
    approver.current.body.csrfToken,
  );
  assert.equal(result.response.status, 200, JSON.stringify(result.body));
  return result.body.approval;
}

function callbackPayload(approvalId, overrides = {}) {
  return {
    schemaVersion: 1,
    eventId: `evt_${crypto.randomUUID()}`,
    issuer: CALLBACK_ISSUER,
    audience: CALLBACK_AUDIENCE,
    approvalId,
    decision: "approve",
    actorSubjectId: "admin-external-reviewer",
    actorEmail: "reviewer@corp.example",
    externalReference: `OA-${crypto.randomUUID()}`,
    reason: "External approval board approved this request",
    ...overrides,
  };
}

async function postApprovalCallback(f, payload, options = {}) {
  const rawBody = typeof payload === "string" ? payload : JSON.stringify(payload);
  const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
  const nonce = options.nonce ?? `nonce_${crypto.randomUUID()}`;
  const signature = options.signature ?? crypto.createHmac(
    "sha256",
    options.secret ?? f.secrets.callbackSecret,
  )
    .update(`${timestamp}.${nonce}.`)
    .update(rawBody)
    .digest("hex");
  const headers = {
    "content-type": options.contentType ?? "application/json",
  };
  if (!options.omitTimestamp) headers["x-magpie-timestamp"] = String(timestamp);
  if (!options.omitNonce) headers["x-magpie-nonce"] = nonce;
  if (!options.omitSignature) headers["x-magpie-signature"] = `sha256=${signature}`;
  const response = await fetch(`${f.base}/api/v1/integrations/approvals/callback`, {
    method: "POST",
    headers,
    body: rawBody,
  });
  return {
    response,
    body: await response.json(),
    rawBody,
    timestamp,
    nonce,
    signature,
  };
}

async function approveReconciliation(
  f,
  jar,
  current,
  approver,
  parent,
  reconciliationAction,
  reason,
  evidenceRef = "",
) {
  const approval = await requestApproval(f, jar, current, {
    action: "operation.reconcile",
    targetId: parent.id,
    parentOperationId: parent.id,
    reconciliationAction,
    reason,
    ...(evidenceRef ? { evidenceRef } : {}),
  });
  await decideApproval(f, approver, approval.approvalId);
  return approval;
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

async function adminRequest(f, jar, method, pathname, body, csrfToken = "", extraHeaders = {}) {
  const headers = {
    cookie: jar.header(),
    origin: f.base,
    "content-type": "application/json",
    ...extraHeaders,
  };
  if (csrfToken) headers["x-csrf-token"] = csrfToken;
  const response = await fetch(`${f.base}${pathname}`, {
    method,
    headers,
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

function adminPost(f, jar, pathname, body, csrfToken = "", extraHeaders = {}) {
  return adminRequest(f, jar, "POST", pathname, body, csrfToken, extraHeaders);
}

function adminPut(f, jar, pathname, body, csrfToken = "", extraHeaders = {}) {
  return adminRequest(f, jar, "PUT", pathname, body, csrfToken, extraHeaders);
}

function adminPatch(f, jar, pathname, body, csrfToken = "", extraHeaders = {}) {
  return adminRequest(f, jar, "PATCH", pathname, body, csrfToken, extraHeaders);
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
    ...(f.secrets.callbackSecret ? [f.secrets.callbackSecret] : []),
    jar.cookies.get(f.config.sessionCookieName) || "__no_cookie__",
  ]) {
    assert.ok(!serialized.includes(forbidden), `response must not contain ${forbidden}`);
  }
}

function readAdminData(f) {
  return f.admin.store.read((data) => structuredClone(data));
}

async function seedAdminOperation(f, input = {}) {
  const {
    audit = true,
    ...overrides
  } = input;
  const id = overrides.id || `op_seed_${crypto.randomUUID()}`;
  const createdAt = overrides.createdAt || "2026-10-20T00:00:00.000Z";
  const beforeSummary = overrides.beforeSummary === undefined
    ? {
      id: "usr_alice",
      email: "alice@corp.example",
      status: "active",
      version: 2,
      models: ["deepseek/deepseek-chat"],
      limits: [],
      quotaStatus: "known",
      modelStatus: "known",
      updatedAt: "2026-10-19T00:00:00.000Z",
      confirmedAt: "2026-10-19T00:01:00.000Z",
      operationId: "op_seed_previous_policy",
      including: ["quota", "models"],
      missing: [],
    }
    : overrides.beforeSummary;
  const responseBody = overrides.responseBody === undefined
    ? {
      result: {
        state: "pending_sync",
        requiresReconciliation: true,
        credentials: {
          total: 1,
          succeeded: 0,
          failed: 1,
          pending: 1,
          unknown: 0,
          failedOnly: 0,
          failedItems: [{
            credentialId: "key-alice-new",
            deviceId: "dev_alice",
            errorCode: "policy_sync_in_progress",
          }],
        },
      },
    }
    : overrides.responseBody;
  const operation = {
    id,
    requestId: `req_${id}`,
    idempotencyKeyHash: "",
    requestFingerprint: "",
    actorSubjectId: "adm_seed",
    actorEmail: "seed-admin@corp.example",
    roles: ["super_admin"],
    scopeOrgUnitIds: ["*"],
    action: "user.policy.models",
    targetType: "user",
    targetId: "usr_alice",
    reason: "Seeded operation for reconciliation tests",
    approvalId: "CHG-SEED-1",
    beforeSummary,
    status: "failed",
    createdAt,
    updatedAt: createdAt,
    dependencyInvokedAt: createdAt,
    completedAt: createdAt,
    intentAuditId: "",
    resultAuditId: "",
    responseStatus: 502,
    responseBody,
    errorCode: "dependency_unavailable",
    sourceIp: "127.0.0.1",
    userAgentHash: "seed-agent-hash",
    ...overrides,
    id,
    beforeSummary,
    responseBody,
  };
  await f.admin.store.mutate((data) => {
    data.adminOperations[id] = structuredClone(operation);
    if (!audit) return;
    for (const [index, phase] of ["intent", "result"].entries()) {
      data.adminAuditLogs.push({
        id: `audit_${id}_${phase}`,
        operationId: id,
        requestId: operation.requestId,
        timestamp: new Date(Date.parse(createdAt) + index * 1000).toISOString(),
        phase,
        actorSubject: operation.actorSubjectId,
        actorSubjectId: operation.actorSubjectId,
        actorEmail: operation.actorEmail,
        roles: [...operation.roles],
        scopeOrgUnitIds: [...operation.scopeOrgUnitIds],
        action: operation.action,
        targetType: operation.targetType,
        targetId: operation.targetId,
        beforeSummary: structuredClone(operation.beforeSummary),
        afterSummary: phase === "result"
          ? structuredClone(operation.responseBody?.result || {})
          : {},
        result: phase === "result" ? "failed" : "pending",
        errorCode: phase === "result" ? operation.errorCode : "",
        sourceIp: operation.sourceIp,
        userAgentHash: operation.userAgentHash,
        reason: operation.reason,
        approvalId: operation.approvalId,
        parentOperationId: "",
        reconciliationAction: "",
        evidenceRef: "",
      });
    }
  });
  return structuredClone(operation);
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

test("policy management expands catalog selectors and reports credential sync state", { timeout: 30000 }, async (t) => {
  const catalogContent = modelCatalogContent();
  const catalogDigest = `sha256:${crypto.createHash("sha256").update(catalogContent).digest("hex")}`;
  const f = await fixture({ catalogContent, catalogDigest });
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);
  assert.ok(current.body.permissions.includes("quota.write"));
  assert.ok(current.body.permissions.includes("models.write"));

  const quotaApproval = await requestApproval(f, jar, current, {
    action: "user.policy.quota",
    targetId: "usr_bob",
    reason: "Apply the engineering monthly allowance",
    expectedVersion: 1,
    limits: [{ period: "month", tokens: 100000, cost: 25 }],
  });
  await decideApproval(f, approver, quotaApproval.approvalId);
  const quota = await adminPut(
    f,
    jar,
    "/api/v1/admin/users/usr_bob/policy/quota",
    {
      reason: "Apply the engineering monthly allowance",
      expectedVersion: 1,
      limits: [{ period: "month", tokens: 100000, cost: 25 }],
      approvalId: quotaApproval.approvalId,
    },
    current.body.csrfToken,
    { "idempotency-key": "policy-quota-push-1" },
  );
  assert.equal(quota.response.status, 200, JSON.stringify(quota.body));
  assert.match(quota.body.operationId, /^op_/);
  assert.equal(quota.body.result.operationId, quota.body.operationId);
  assert.equal(quota.body.result.state, "pending_sync");
  assert.equal(quota.body.result.policy.version, 2);
  assert.equal(quota.body.result.policy.quotaStatus, "known");
  assert.equal(quota.body.result.policy.modelStatus, "unknown");
  assert.deepEqual(quota.body.result.policy.missing, ["models"]);
  assert.equal(quota.body.result.requiresReconciliation, true);
  assert.equal(quota.body.result.credentials.pending, 1);

  const modelsApproval = await requestApproval(f, jar, current, {
    action: "user.policy.models",
    targetId: "usr_bob",
    reason: "Grant the approved engineering model group",
    expectedVersion: 2,
    models: ["group/engineering-approved", "company-model/*"],
  });
  await decideApproval(f, approver, modelsApproval.approvalId);
  const models = await adminPatch(
    f,
    jar,
    "/api/v1/admin/users/usr_bob/policy/models",
    {
      reason: "Grant the approved engineering model group",
      expectedVersion: 2,
      models: ["group/engineering-approved", "company-model/*"],
      approvalId: modelsApproval.approvalId,
    },
    current.body.csrfToken,
    { "idempotency-key": "policy-models-push-1" },
  );
  assert.equal(models.response.status, 200, JSON.stringify(models.body));
  assert.equal(models.body.result.operationId, models.body.operationId);
  assert.equal(models.body.result.state, "succeeded");
  assert.equal(models.body.result.policy.version, 3);
  assert.equal(models.body.result.policy.quotaStatus, "known");
  assert.equal(models.body.result.policy.modelStatus, "known");
  assert.deepEqual(models.body.result.policy.including, ["quota", "models"]);
  assert.deepEqual(models.body.result.policy.missing, []);
  assert.equal(models.body.result.requiresReconciliation, false);
  assert.equal(models.body.result.credentials.succeeded, 1);
  assert.deepEqual(models.body.result.policy.models, [
    "openai/gpt-5.2",
    "anthropic/claude-sonnet-5",
    "company-model/*",
  ]);

  assert.equal(f.auth.writeCalls.length, 2);
  assert.equal(f.auth.writeCalls[0].method, "PUT");
  assert.equal(
    f.auth.writeCalls[0].pathname,
    "/api/v1/internal/admin/users/usr_bob/policy/quota",
  );
  assert.deepEqual(f.auth.writeCalls[0].body, {
    expectedVersion: 1,
    limits: [{ period: "month", tokens: 100000, cost: 25 }],
    operationId: quota.body.operationId,
  });
  assert.equal(f.auth.writeCalls[1].method, "PATCH");
  assert.equal(
    f.auth.writeCalls[1].pathname,
    "/api/v1/internal/admin/users/usr_bob/policy/models",
  );
  assert.deepEqual(f.auth.writeCalls[1].body, {
    expectedVersion: 2,
    models: [
      "openai/gpt-5.2",
      "anthropic/claude-sonnet-5",
      "company-model/*",
    ],
    operationId: models.body.operationId,
  });

  const page = await fetch(`${f.base}/admin/`, { headers: { cookie: jar.header() } });
  assert.equal(page.status, 200);
  const html = await page.text();
  for (const expected of [
    "Policy",
    "Quota",
    "Models",
    "Sync",
    "Policy sync",
    "known",
    "synced",
    "pending",
    "policy_unknown",
    "Policy operations",
    "Manage bob@corp.example",
    "Set quota windows",
    "Set model authorization",
  ]) {
    assert.ok(html.includes(expected), `page should include ${expected}`);
  }
  assert.ok(html.includes('src="/admin/app.js"'));
  assert.ok(html.includes('name="csrf-token"'));
  assert.ok(!html.includes("Applied and verified."));
  const script = await fetch(`${f.base}/admin/app.js`);
  assert.equal(script.status, 200);
  assert.match(script.headers.get("content-type"), /^text\/javascript/);
  const scriptText = await script.text();
  assert.ok(scriptText.includes("idempotency-key"));
  assert.ok(scriptText.includes("Do not retry automatically"));
  assertNoWriteSecrets([quota.body, models.body], f, jar);
  assertNoWriteSecrets(await fs.readFile(f.config.storePath, "utf8"), f, jar);
});

test("admin page shows verified policy only with a complete evidence chain", {
  timeout: 30000,
}, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);
  await f.admin.store.mutate((data) => {
    data.adminOperations.op_mock_policy_ready = {
      id: "op_mock_policy_ready",
      action: "user.policy.models",
      targetType: "user",
      targetId: "usr_alice",
      status: "succeeded",
      createdAt: "2026-10-31T08:01:00.000Z",
      updatedAt: "2026-10-31T08:01:01.000Z",
      completedAt: "2026-10-31T08:01:01.000Z",
      responseBody: {
        result: {
          state: "succeeded",
          requiresReconciliation: false,
          credentials: {
            total: 1,
            succeeded: 1,
            failed: 0,
            pending: 0,
            unknown: 0,
          },
        },
      },
    };
  });

  const jar = await adminLogin(f);
  const page = await fetch(`${f.base}/admin/`, { headers: { cookie: jar.header() } });
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.ok(html.includes("Applied and verified."));
  assert.ok(html.includes("Policy v2; 1 active credentials verified by independent readback."));
  assert.ok(html.includes("op_mock_policy_ready"));
  assert.ok(!html.includes("should-not-leak-gateway-key"));
  assert.ok(!html.includes("should-not-leak-token-hash"));
});

test("policy writes replay by payload and reject conflicting idempotency reuse", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);
  const pathname = "/api/v1/admin/users/usr_alice/policy/quota";
  const requestBody = {
    reason: "Replay-safe quota update",
    expectedVersion: 2,
    limits: [{ period: "month", tokens: 50000, cost: 10 }],
  };
  const approval = await requestApproval(f, jar, current, {
    action: "user.policy.quota",
    targetId: "usr_alice",
    ...requestBody,
  });
  await decideApproval(f, approver, approval.approvalId);
  const body = { ...requestBody, approvalId: approval.approvalId };
  const headers = { "idempotency-key": "policy-idempotency-1" };

  const first = await adminPut(f, jar, pathname, body, current.body.csrfToken, headers);
  assert.equal(first.response.status, 200, JSON.stringify(first.body));
  assert.equal(f.auth.writeCalls.length, 1);

  const replay = await adminPut(f, jar, pathname, body, current.body.csrfToken, headers);
  assert.equal(replay.response.status, 200);
  assert.equal(replay.body.operationId, first.body.operationId);
  assert.equal(replay.body.result.operationId, first.body.result.operationId);
  assert.equal(f.auth.writeCalls.length, 1);

  const conflict = await adminPut(
    f,
    jar,
    pathname,
    {
      ...body,
      limits: [{ period: "month", tokens: 99999, cost: 10 }],
    },
    current.body.csrfToken,
    headers,
  );
  assert.equal(conflict.response.status, 409);
  assert.equal(conflict.body.error.code, "idempotency_conflict");
  assert.equal(conflict.body.error.operationId, first.body.operationId);
  assert.equal(f.auth.writeCalls.length, 1);

  await bindRole(f, current.body.user.id, "auditor", "org-root");
  const auditor = await me(f, jar);
  const forbidden = await adminPut(
    f,
    jar,
    pathname,
    {
      reason: "Auditors cannot change quotas",
      expectedVersion: 3,
      limits: [],
    },
    auditor.body.csrfToken,
  );
  assert.equal(forbidden.response.status, 403);
  assert.equal(forbidden.body.error.code, "forbidden_role");
  assert.equal(f.auth.writeCalls.length, 1);
});

test("policy version conflicts stay 409 and are result-audited by the admin service", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);
  const requestBody = {
    reason: "Stale policy update must fail closed",
    expectedVersion: 0,
    models: ["openai/gpt-test"],
  };
  const approval = await requestApproval(f, jar, current, {
    action: "user.policy.models",
    targetId: "usr_bob",
    ...requestBody,
  });
  await decideApproval(f, approver, approval.approvalId);
  const response = await adminPatch(
    f,
    jar,
    "/api/v1/admin/users/usr_bob/policy/models",
    {
      ...requestBody,
      approvalId: approval.approvalId,
    },
    current.body.csrfToken,
    { "idempotency-key": "policy-stale-1" },
  );
  assert.equal(response.response.status, 409, JSON.stringify(response.body));
  assert.equal(response.body.error.code, "policy_version_conflict");
  assert.match(response.body.error.operationId, /^op_/);
  assert.equal(f.auth.writeCalls.length, 1);

  const data = await readAdminData(f);
  const operation = data.adminOperations[response.body.error.operationId];
  assert.equal(operation.status, "failed");
  assert.equal(operation.responseStatus, 409);
  assert.equal(operation.errorCode, "policy_version_conflict");
  const audits = data.adminAuditLogs.filter((audit) => audit.operationId === operation.id);
  assert.deepEqual(audits.map((audit) => audit.phase), ["intent", "result"]);
  assert.equal(audits[1].errorCode, "policy_version_conflict");
  assertNoWriteSecrets([response.body, data], f, jar);
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

  const page = await fetch(`${f.base}/admin/`, { headers: { cookie: jar.header() } });
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.ok(html.includes("Read-only access. Your role cannot change user policies."));
  assert.ok(!html.includes("policy-write-form"));
  assert.ok(!html.includes("Save quota"));
  assert.ok(!html.includes("Save models"));
});

test("M2-C2 global admin write routes call auth-service and return only safe fields", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);
  assert.equal(current.response.status, 200);
  assert.ok(current.body.permissions.includes("users.disable"));
  assert.ok(current.body.permissions.includes("devices.revoke"));
  assert.ok(current.body.permissions.includes("credentials.rotate"));

  const disableApproval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason: "Employee reported a lost laptop",
  });
  await decideApproval(f, approver, disableApproval.approvalId);
  const disabled = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    {
      reason: "Employee reported a lost laptop",
      approvalId: disableApproval.approvalId,
    },
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

  const revokeApproval = await requestApproval(f, jar, current, {
    action: "device.revoke",
    targetId: "dev_alice",
    reason: "Device is no longer managed",
  });
  await decideApproval(f, approver, revokeApproval.approvalId);
  const revoked = await adminPost(
    f,
    jar,
    "/api/v1/admin/devices/dev_alice/revoke",
    {
      reason: "Device is no longer managed",
      approvalId: revokeApproval.approvalId,
    },
    current.body.csrfToken,
  );
  assert.equal(revoked.response.status, 200);
  assert.equal(revoked.body.action, "device.revoke");
  assert.equal(revoked.body.result.device.id, "dev_alice");
  assert.equal(revoked.body.result.device.status, "revoked");
  assert.equal(revoked.body.result.affectedCredentials, 1);

  const rotateApproval = await requestApproval(f, jar, current, {
    action: "credential.rotate",
    targetId: "key-alice-new",
    reason: "Routine credential rotation",
  });
  await decideApproval(f, approver, rotateApproval.approvalId);
  const rotated = await adminPost(
    f,
    jar,
    "/api/v1/admin/credentials/key-alice-new/rotate",
    {
      reason: "Routine credential rotation",
      approvalId: rotateApproval.approvalId,
    },
    current.body.csrfToken,
  );
  assert.equal(rotated.response.status, 200);
  assert.equal(rotated.body.action, "credential.rotate");
  assert.equal(rotated.body.result.credentialId, "key-alice-new");
  assert.equal(rotated.body.result.newCredentialId, "key-rotated-key-alice-new");
  assert.equal(rotated.body.result.status, "awaiting_device_refresh");

  assert.deepEqual(f.auth.writeCalls, [
    {
      method: "POST",
      pathname: "/api/v1/internal/admin/users/usr_alice/disable",
      body: {},
    },
    {
      method: "POST",
      pathname: "/api/v1/internal/admin/users/usr_alice/enable",
      body: {},
    },
    {
      method: "POST",
      pathname: "/api/v1/internal/admin/devices/dev_alice/revoke",
      body: {},
    },
    {
      method: "POST",
      pathname: "/api/v1/internal/admin/credentials/key-alice-new/rotate",
      body: {},
    },
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
  const approver = await independentApprover(f, {
    role: "enterprise_admin",
    scopeOrgUnitId: "org-root",
  });
  assert.equal(scoped.response.status, 200);
  assert.deepEqual(scoped.body.roles, ["enterprise_admin"]);
  assert.deepEqual(scoped.body.scopeOrgUnitIds.sort(), ["org-platform", "org-root"]);

  const disableApproval = await requestApproval(f, jar, scoped, {
    action: "user.disable",
    targetId: "usr_bob",
    reason: "Scoped administrator action",
  });
  await decideApproval(f, approver, disableApproval.approvalId);
  const ownUser = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_bob/disable",
    {
      reason: "Scoped administrator action",
      approvalId: disableApproval.approvalId,
    },
    scoped.body.csrfToken,
  );
  assert.equal(ownUser.response.status, 200);
  const revokeApproval = await requestApproval(f, jar, scoped, {
    action: "device.revoke",
    targetId: "dev_bob",
    reason: "Scoped device revocation",
  });
  await decideApproval(f, approver, revokeApproval.approvalId);
  const ownDevice = await adminPost(
    f,
    jar,
    "/api/v1/admin/devices/dev_bob/revoke",
    {
      reason: "Scoped device revocation",
      approvalId: revokeApproval.approvalId,
    },
    scoped.body.csrfToken,
  );
  assert.equal(ownDevice.response.status, 200);
  const rotateApproval = await requestApproval(f, jar, scoped, {
    action: "credential.rotate",
    targetId: "key-bob",
    reason: "Scoped credential rotation",
  });
  await decideApproval(f, approver, rotateApproval.approvalId);
  const ownCredential = await adminPost(
    f,
    jar,
    "/api/v1/admin/credentials/key-bob/rotate",
    {
      reason: "Scoped credential rotation",
      approvalId: rotateApproval.approvalId,
    },
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
  const approver = await independentApprover(f);
  const approval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason: "Lost device requires immediate suspension",
  });
  await decideApproval(f, approver, approval.approvalId);
  const idempotencyKey = "m2c3-audit-key-1";
  const disabled = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    {
      reason: "Lost device requires immediate suspension",
      approvalId: approval.approvalId,
    },
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
  assert.equal(operation.approvalId, approval.approvalId);
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
  assert.equal(audits[0].approvalId, approval.approvalId);
  assert.equal(audits[1].result, "succeeded");
  assert.equal(audits[1].afterSummary.user.id, "usr_alice");
  assert.ok(audits.every((audit) => audit.requestId === disabled.body.requestId));
  assert.equal(data.approvalRequests[approval.approvalId].status, "consumed");
  assert.equal(
    data.approvalRequests[approval.approvalId].operationId,
    disabled.body.operationId,
  );
  assert.equal(
    data.approvalConsumptions[approval.approvalId].outcome,
    "succeeded",
  );
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
  const approver = await independentApprover(f);
  const idempotencyKey = "m2c3-replay-key-1";
  const pathName = "/api/v1/admin/users/usr_alice/disable";
  const reason = "Replay-safe suspension";
  const approval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason,
  });
  await decideApproval(f, approver, approval.approvalId);
  const body = { reason, approvalId: approval.approvalId };

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
    {
      reason: "A different request must not reuse the key",
      approvalId: approval.approvalId,
    },
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
  const concurrentReason = "Concurrent idempotency check";
  const concurrentApproval = await requestApproval(f, jar, current, {
    action: "device.revoke",
    targetId: "dev_bob",
    reason: concurrentReason,
  });
  await decideApproval(f, approver, concurrentApproval.approvalId);
  const concurrentBody = {
    reason: concurrentReason,
    approvalId: concurrentApproval.approvalId,
  };
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
  const approver = await independentApprover(f);
  const reason = "Intent audit must fail closed";
  const approval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason,
  });
  await decideApproval(f, approver, approval.approvalId);
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
    { reason, approvalId: approval.approvalId },
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
  const approver = await independentApprover(f);
  const reason = "Dependency failure must be audited";
  const approval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason,
  });
  await decideApproval(f, approver, approval.approvalId);
  const body = { reason, approvalId: approval.approvalId };
  f.auth.setWriteFailing(true);
  const response = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    body,
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
    body,
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
  const approver = await independentApprover(f);
  const reason = "The result audit must fail closed";
  const approval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason,
  });
  await decideApproval(f, approver, approval.approvalId);
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
    { reason, approvalId: approval.approvalId },
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

test("M2-C5 operation details enforce permissions and organization scope", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const aliceOperation = await seedAdminOperation(f, { id: "op_detail_alice" });

  const detail = await adminGet(f, jar, `/api/v1/admin/operations/${aliceOperation.id}`);
  assert.equal(detail.response.status, 200);
  assert.equal(detail.body.operation.operationId, aliceOperation.id);
  assert.equal(detail.body.operation.targetId, "usr_alice");
  assert.equal(detail.body.operation.reconciliationState, "pending");
  assert.equal(detail.body.operation.requiresReconciliation, true);
  assert.equal(detail.body.operation.credentialSummary.total, 1);
  assertNoWriteSecrets(detail.body, f, jar);

  await seedAdminOperation(f, {
    id: "op_detail_missing_target",
    targetId: "usr_missing",
    beforeSummary: { id: "usr_missing", version: 0, models: [], limits: [] },
  });
  const missingTarget = await adminGet(
    f,
    jar,
    "/api/v1/admin/operations/op_detail_missing_target",
  );
  assert.equal(missingTarget.response.status, 404);
  assert.equal(missingTarget.body.error.code, "operation_target_unavailable");

  await bindRole(f, current.body.user.id, "department_admin", "org-root");
  const ownScope = await adminGet(f, jar, `/api/v1/admin/operations/${aliceOperation.id}`);
  assert.equal(ownScope.response.status, 200);

  await seedAdminOperation(f, {
    id: "op_detail_sales",
    targetId: "usr_carol",
    beforeSummary: {
      id: "usr_carol",
      version: 0,
      models: ["openai/gpt-test"],
      limits: [],
    },
  });
  const crossScope = await adminGet(f, jar, "/api/v1/admin/operations/op_detail_sales");
  assert.equal(crossScope.response.status, 403);
  assert.equal(crossScope.body.error.code, "forbidden_scope");

  await bindRole(f, current.body.user.id, "auditor", "org-root");
  const auditorDetail = await adminGet(f, jar, `/api/v1/admin/operations/${aliceOperation.id}`);
  assert.equal(auditorDetail.response.status, 403);
  assert.equal(auditorDetail.body.error.code, "forbidden_role");
});

test("M2-C5 audit logs paginate stably and bind cursors to the session and query", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const baseTime = Date.parse("2026-10-20T00:00:00.000Z");
  for (let index = 0; index < 55; index += 1) {
    await seedAdminOperation(f, {
      id: `op_page_${String(index).padStart(3, "0")}`,
      targetId: index % 2 === 0 ? "usr_alice" : "usr_bob",
      createdAt: new Date(baseTime + index * 1000).toISOString(),
    });
  }
  await f.admin.store.mutate((data) => {
    const legacy = data.adminAuditLogs.find(
      (record) => record.id === "audit_op_page_000_result",
    );
    legacy.actorSubject = "adm_legacy";
    delete legacy.actorSubjectId;
  });

  const defaultPage = await adminGet(f, jar, "/api/v1/admin/audit-logs");
  assert.equal(defaultPage.response.status, 200);
  assert.equal(defaultPage.body.auditLogs.length, 50);
  assert.ok(defaultPage.body.nextCursor);

  const maximumPage = await adminGet(f, jar, "/api/v1/admin/audit-logs?limit=200");
  assert.equal(maximumPage.response.status, 200);
  assert.equal(maximumPage.body.auditLogs.length, 110);
  assert.equal(maximumPage.body.nextCursor, "");

  for (const limit of ["0", "201", "1.5", "-1"]) {
    const invalid = await adminGet(f, jar, `/api/v1/admin/audit-logs?limit=${limit}`);
    assert.equal(invalid.response.status, 400);
    assert.equal(invalid.body.error.code, "invalid_limit");
  }

  const firstPage = await adminGet(f, jar, "/api/v1/admin/audit-logs?limit=37");
  assert.equal(firstPage.response.status, 200);
  assert.equal(firstPage.body.auditLogs.length, 37);
  assert.ok(firstPage.body.nextCursor);
  const cursor = firstPage.body.nextCursor;

  const tampered = await adminGet(
    f,
    jar,
    `/api/v1/admin/audit-logs?limit=37&cursor=${encodeURIComponent(`${cursor.slice(0, -1)}A`)}`,
  );
  assert.equal(tampered.response.status, 400);
  assert.equal(tampered.body.error.code, "invalid_cursor");

  const changedQuery = await adminGet(
    f,
    jar,
    `/api/v1/admin/audit-logs?limit=38&cursor=${encodeURIComponent(cursor)}`,
  );
  assert.equal(changedQuery.response.status, 400);
  assert.equal(changedQuery.body.error.code, "invalid_cursor");

  const seen = new Set();
  let nextCursor = "";
  let pages = 0;
  do {
    const pathname = `/api/v1/admin/audit-logs?limit=37${nextCursor
      ? `&cursor=${encodeURIComponent(nextCursor)}`
      : ""}`;
    const page = await adminGet(f, jar, pathname);
    assert.equal(page.response.status, 200);
    for (const record of page.body.auditLogs) {
      assert.ok(!seen.has(record.id), `duplicate audit record ${record.id}`);
      seen.add(record.id);
    }
    nextCursor = page.body.nextCursor;
    pages += 1;
    assert.ok(pages < 10);
  } while (nextCursor);
  assert.equal(seen.size, 110);

  const legacy = await adminGet(
    f,
    jar,
    "/api/v1/admin/audit-logs?actorSubjectId=adm_legacy&limit=10",
  );
  assert.equal(legacy.response.status, 200);
  assert.deepEqual(legacy.body.auditLogs.map((record) => record.id), [
    "audit_op_page_000_result",
  ]);
  assert.equal(legacy.body.auditLogs[0].actorSubjectId, "adm_legacy");

  await bindRole(f, "adm_cursor_other", "super_admin", "*");
  await f.admin.store.mutate((data) => {
    const session = Object.values(data.adminSessions)[0];
    session.subjectId = "adm_cursor_other";
  });
  const changedSubject = await adminGet(
    f,
    jar,
    `/api/v1/admin/audit-logs?limit=37&cursor=${encodeURIComponent(cursor)}`,
  );
  assert.equal(changedSubject.response.status, 400);
  assert.equal(changedSubject.body.error.code, "invalid_cursor");
  assert.notEqual(current.body.user.id, "adm_cursor_other");
});

test("M2-C5 audit and operation reads redact content and credential material", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const marker = "M2C5-TOP-SECRET-VALUE";
  const operation = await seedAdminOperation(f, {
    id: "op_redaction",
    beforeSummary: {
      id: "usr_alice",
      version: 2,
      models: ["deepseek/deepseek-chat"],
      limits: [],
      secret: marker,
      prompt: marker,
      conversation: marker,
      requestBody: marker,
      responseBody: marker,
      content: marker,
      message: marker,
      messages: [marker],
      transcript: marker,
      completion: marker,
      dialogue: marker,
      apiKey: marker,
      nested: { cookie: marker, safe: "visible-metadata" },
    },
    responseBody: {
      result: {
        state: "pending_sync",
        requiresReconciliation: true,
        secret: marker,
        prompt: marker,
        conversation: marker,
        requestBody: marker,
        responseBody: marker,
        content: marker,
        message: marker,
        messages: [marker],
        transcript: marker,
        completion: marker,
        dialogue: marker,
        apiKey: marker,
        nested: { authorization: marker, safe: "visible-metadata" },
      },
    },
  });

  const audits = await adminGet(
    f,
    jar,
    `/api/v1/admin/audit-logs?operationId=${operation.id}&limit=10`,
  );
  assert.equal(audits.response.status, 200);
  assert.equal(audits.body.auditLogs.length, 2);
  assert.ok(JSON.stringify(audits.body).includes("visible-metadata"));
  assert.ok(!JSON.stringify(audits.body).includes(marker));

  const detail = await adminGet(f, jar, `/api/v1/admin/operations/${operation.id}`);
  assert.equal(detail.response.status, 200);
  assert.ok(JSON.stringify(detail.body).includes("visible-metadata"));
  assert.ok(!JSON.stringify(detail.body).includes(marker));
  assertNoWriteSecrets(audits.body, f, jar);
  assertNoWriteSecrets(detail.body, f, jar);
});

test("M2-C5 reconciliation fails closed on missing approval, CSRF, evidence, and idempotency", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const operation = await seedAdminOperation(f, { id: "op_reconcile_validation" });
  const pathname = `/api/v1/admin/operations/${operation.id}/reconcile`;
  const complete = {
    reason: "Reconcile after the gateway incident",
    approvalId: "CHG-2001",
    action: "retry_desired",
  };

  const noCsrf = await adminPost(
    f,
    jar,
    pathname,
    complete,
    "",
    { "idempotency-key": "m2c5-validation-csrf" },
  );
  assert.equal(noCsrf.response.status, 403);
  assert.equal(noCsrf.body.error.code, "csrf_invalid");

  const noReason = await adminPost(
    f,
    jar,
    pathname,
    { approvalId: "CHG-2001", action: "retry_desired" },
    current.body.csrfToken,
    { "idempotency-key": "m2c5-validation-reason" },
  );
  assert.equal(noReason.response.status, 400);
  assert.equal(noReason.body.error.code, "invalid_reason");

  const noApproval = await adminPost(
    f,
    jar,
    pathname,
    { reason: "Reconcile after the gateway incident", action: "retry_desired" },
    current.body.csrfToken,
    { "idempotency-key": "m2c5-validation-approval" },
  );
  assert.equal(noApproval.response.status, 400);
  assert.equal(noApproval.body.error.code, "approval_required");

  const noIdempotency = await adminPost(
    f,
    jar,
    pathname,
    complete,
    current.body.csrfToken,
  );
  assert.equal(noIdempotency.response.status, 400);
  assert.equal(noIdempotency.body.error.code, "idempotency_key_required");

  const noEvidence = await adminPost(
    f,
    jar,
    pathname,
    { ...complete, action: "confirm_applied" },
    current.body.csrfToken,
    { "idempotency-key": "m2c5-validation-evidence" },
  );
  assert.equal(noEvidence.response.status, 400);
  assert.equal(noEvidence.body.error.code, "evidence_required");

  const invalidAction = await adminPost(
    f,
    jar,
    pathname,
    { ...complete, action: "assume_success" },
    current.body.csrfToken,
    { "idempotency-key": "m2c5-validation-action" },
  );
  assert.equal(invalidAction.response.status, 400);
  assert.equal(invalidAction.body.error.code, "invalid_reconciliation_action");

  const data = await readAdminData(f);
  assert.deepEqual(Object.keys(data.adminOperations), [operation.id]);
  assert.equal(f.auth.reconcileCalls.length, 0);
});

test("M2-C5 supports all four reconciliation actions without rewriting the parent result", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);
  const operationIds = [
    "op_reconcile_applied",
    "op_reconcile_not_applied",
    "op_reconcile_retry",
    "op_reconcile_rollback",
  ];
  for (const id of operationIds) {
    await seedAdminOperation(f, {
      id,
      beforeSummary: id === "op_reconcile_rollback"
        ? {
          id: "usr_alice",
          version: 2,
          models: ["openai/gpt-test"],
          limits: [{ period: "month", tokens: 1000, cost: 1, cacheReads: false }],
          quotaStatus: "known",
          modelStatus: "known",
        }
        : undefined,
    });
  }
  const approvalCases = {
    op_reconcile_applied: {
      action: "confirm_applied",
      reason: "Controlled confirm_applied reconciliation",
      evidenceRef: "ticket:CHG-APPLIED",
    },
    op_reconcile_not_applied: {
      action: "confirm_not_applied",
      reason: "Controlled confirm_not_applied reconciliation",
      evidenceRef: "ticket:CHG-NOT-APPLIED",
    },
    op_reconcile_retry: {
      action: "retry_desired",
      reason: "Controlled retry_desired reconciliation",
      evidenceRef: "",
    },
    op_reconcile_rollback: {
      action: "rollback_previous",
      reason: "Controlled rollback_previous reconciliation",
      evidenceRef: "",
    },
  };
  const approvals = {};
  for (const [operationId, approvalCase] of Object.entries(approvalCases)) {
    approvals[operationId] = await approveReconciliation(
      f,
      jar,
      current,
      approver,
      { id: operationId },
      approvalCase.action,
      approvalCase.reason,
      approvalCase.evidenceRef,
    );
  }
  const before = await readAdminData(f);
  const parentAudits = Object.fromEntries(operationIds.map((id) => [
    id,
    before.adminAuditLogs.filter((audit) => audit.operationId === id),
  ]));

  async function reconcile(operationId, action, key, evidenceRef = "") {
    const approvalCase = approvalCases[operationId];
    return adminPost(
      f,
      jar,
      `/api/v1/admin/operations/${operationId}/reconcile`,
      {
        reason: approvalCase.reason,
        approvalId: approvals[operationId].approvalId,
        action,
        ...(evidenceRef ? { evidenceRef } : {}),
      },
      current.body.csrfToken,
      { "idempotency-key": key },
    );
  }

  const applied = await reconcile(
    "op_reconcile_applied",
    "confirm_applied",
    "m2c5-applied",
    "ticket:CHG-APPLIED",
  );
  assert.equal(applied.response.status, 200, JSON.stringify(applied.body));
  assert.equal(applied.body.result.manualEvidenceOnly, true);
  assert.equal(applied.body.result.parentOperationId, "op_reconcile_applied");

  const replay = await reconcile(
    "op_reconcile_applied",
    "confirm_applied",
    "m2c5-applied",
    "ticket:CHG-APPLIED",
  );
  assert.equal(replay.response.status, 200);
  assert.equal(replay.body.operationId, applied.body.operationId);

  const notApplied = await reconcile(
    "op_reconcile_not_applied",
    "confirm_not_applied",
    "m2c5-not-applied",
    "ticket:CHG-NOT-APPLIED",
  );
  assert.equal(notApplied.response.status, 200, JSON.stringify(notApplied.body));

  const retried = await reconcile(
    "op_reconcile_retry",
    "retry_desired",
    "m2c5-retry",
  );
  assert.equal(retried.response.status, 200, JSON.stringify(retried.body));
  assert.equal(retried.body.result.state, "succeeded");

  const rolledBack = await reconcile(
    "op_reconcile_rollback",
    "rollback_previous",
    "m2c5-rollback",
  );
  assert.equal(rolledBack.response.status, 200, JSON.stringify(rolledBack.body));
  assert.equal(f.auth.reconcileCalls.length, 2);
  assert.deepEqual(f.auth.reconcileCalls[0].body.models, ["deepseek/deepseek-chat"]);
  assert.deepEqual(f.auth.reconcileCalls[1].body.models, ["openai/gpt-test"]);
  assert.deepEqual(f.auth.reconcileCalls[1].body.limits, [
    { period: "month", tokens: 1000, cost: 1, cacheReads: false },
  ]);

  const after = await readAdminData(f);
  const expectedStates = {
    op_reconcile_applied: "confirmed_applied",
    op_reconcile_not_applied: "confirmed_not_applied",
    op_reconcile_retry: "not_required",
    op_reconcile_rollback: "compensated",
  };
  for (const id of operationIds) {
    const original = before.adminOperations[id];
    const parent = after.adminOperations[id];
    assert.equal(parent.reconciliationState, expectedStates[id]);
    assert.equal(parent.status, original.status);
    assert.deepEqual(parent.responseBody, original.responseBody);
    assert.deepEqual(
      after.adminAuditLogs.filter((audit) => audit.operationId === id),
      parentAudits[id],
    );
  }

  const childIds = Object.values(after.adminOperations)
    .filter((operation) => operation.action === "operation.reconcile")
    .map((operation) => operation.id);
  assert.equal(childIds.length, 4);
  for (const childId of childIds) {
    const child = after.adminOperations[childId];
    assert.ok(operationIds.includes(child.parentOperationId));
    const childAudits = after.adminAuditLogs.filter((audit) => audit.operationId === childId);
    assert.deepEqual(childAudits.map((audit) => audit.phase), ["intent", "result"]);
    assert.ok(childAudits.every((audit) => audit.parentOperationId === child.parentOperationId));
    assert.ok(childAudits.every((audit) => audit.reconciliationAction === child.reconciliationAction));
  }
  assertNoWriteSecrets(after, f, jar);
});

test("M2-C5 rollback refuses an incomplete trusted policy snapshot", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const operation = await seedAdminOperation(f, {
    id: "op_reconcile_bad_snapshot",
    beforeSummary: {
      id: "usr_alice",
      version: 2,
      models: ["openai/gpt-test"],
      limits: [{ period: "month", days: 1, tokens: 1000, cost: 1, cacheReads: false }],
    },
  });
  const response = await adminPost(
    f,
    jar,
    `/api/v1/admin/operations/${operation.id}/reconcile`,
    {
      reason: "Rollback requires a complete snapshot",
      approvalId: "CHG-SNAPSHOT",
      action: "rollback_previous",
    },
    current.body.csrfToken,
    { "idempotency-key": "m2c5-bad-snapshot" },
  );
  assert.equal(response.response.status, 409);
  assert.equal(response.body.error.code, "trusted_snapshot_unavailable");
  assert.equal(f.auth.reconcileCalls.length, 0);

  const data = await readAdminData(f);
  assert.deepEqual(Object.keys(data.adminOperations), [operation.id]);
  assert.equal(data.adminOperations[operation.id].reconciliationState, undefined);
  assert.equal(
    data.adminAuditLogs.filter((audit) => audit.operationId === operation.id).length,
    2,
  );
});

test("M2-C5 reconciliation dependency failures are result-audited and idempotent", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const parent = await seedAdminOperation(f, { id: "op_reconcile_dependency_failure" });
  const approver = await independentApprover(f);
  const reason = "Dependency failure must remain auditable";
  const approval = await approveReconciliation(
    f,
    jar,
    current,
    approver,
    parent,
    "retry_desired",
    reason,
  );
  const pathname = `/api/v1/admin/operations/${parent.id}/reconcile`;
  const body = {
    reason,
    approvalId: approval.approvalId,
    action: "retry_desired",
  };
  const headers = { "idempotency-key": "m2c5-dependency-failure" };
  f.auth.setWriteFailing(true);

  const failed = await adminPost(
    f,
    jar,
    pathname,
    body,
    current.body.csrfToken,
    headers,
  );
  assert.equal(failed.response.status, 502);
  assert.equal(failed.body.error.code, "dependency_unavailable");
  assert.match(failed.body.error.operationId, /^op_/);

  const replay = await adminPost(
    f,
    jar,
    pathname,
    body,
    current.body.csrfToken,
    headers,
  );
  assert.equal(replay.response.status, 502);
  assert.equal(replay.body.error.operationId, failed.body.error.operationId);

  const conflict = await adminPost(
    f,
    jar,
    pathname,
    { ...body, reason: "A different request must not reuse the key" },
    current.body.csrfToken,
    headers,
  );
  assert.equal(conflict.response.status, 409);
  assert.equal(conflict.body.error.code, "idempotency_conflict");
  assert.equal(conflict.body.error.operationId, failed.body.error.operationId);
  assert.equal(f.auth.reconcileCalls.length, 1);

  const data = await readAdminData(f);
  const child = data.adminOperations[failed.body.error.operationId];
  assert.equal(child.status, "failed");
  assert.equal(child.errorCode, "dependency_unavailable");
  assert.equal(child.parentOperationId, parent.id);
  assert.deepEqual(
    data.adminAuditLogs
      .filter((audit) => audit.operationId === child.id)
      .map((audit) => audit.phase),
    ["intent", "result"],
  );
  const parentAfter = data.adminOperations[parent.id];
  assert.equal(parentAfter.status, parent.status);
  assert.deepEqual(parentAfter.responseBody, parent.responseBody);
  assert.equal(parentAfter.reconciliationState, "pending");
  assertNoWriteSecrets(data, f, jar);
});

test("M2-C5 intent audit failure blocks reconciliation before the dependency call", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const parent = await seedAdminOperation(f, { id: "op_reconcile_intent_failure" });
  const approver = await independentApprover(f);
  const reason = "Intent audit must fail closed";
  const approval = await approveReconciliation(
    f,
    jar,
    current,
    approver,
    parent,
    "retry_desired",
    reason,
  );
  const originalMutate = f.admin.store.mutate.bind(f.admin.store);
  f.admin.store.mutate = (fn) => originalMutate((draft) => {
    const before = Object.keys(draft.adminOperations).length;
    const result = fn(draft);
    if (Object.keys(draft.adminOperations).length > before) {
      throw new Error("simulated reconciliation intent audit failure");
    }
    return result;
  });

  const response = await adminPost(
    f,
    jar,
    `/api/v1/admin/operations/${parent.id}/reconcile`,
    {
      reason,
      approvalId: approval.approvalId,
      action: "retry_desired",
    },
    current.body.csrfToken,
    { "idempotency-key": "m2c5-intent-failure" },
  );
  assert.equal(response.response.status, 503);
  assert.equal(response.body.error.code, "audit_unavailable");
  assert.equal(f.auth.reconcileCalls.length, 0);

  const data = await readAdminData(f);
  assert.deepEqual(Object.keys(data.adminOperations), [parent.id]);
  assert.equal(data.adminOperations[parent.id].reconciliationState, undefined);
});

test("M2-C5 result audit failure leaves reconciliation incomplete and does not acknowledge success", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const parent = await seedAdminOperation(f, { id: "op_reconcile_result_failure" });
  const approver = await independentApprover(f);
  const reason = "Result audit must fail closed";
  const approval = await approveReconciliation(
    f,
    jar,
    current,
    approver,
    parent,
    "retry_desired",
    reason,
  );
  const originalMutate = f.admin.store.mutate.bind(f.admin.store);
  let failResultCommit = true;
  f.admin.store.mutate = (fn) => originalMutate((draft) => {
    const statuses = new Map(Object.entries(draft.adminOperations).map(
      ([id, operation]) => [id, operation.status],
    ));
    const result = fn(draft);
    const completedChild = Object.values(draft.adminOperations).some((operation) => (
      operation.parentOperationId
      && statuses.get(operation.id) === "dependency_invoked"
      && (operation.status === "succeeded" || operation.status === "failed")
    ));
    if (failResultCommit && completedChild) {
      failResultCommit = false;
      throw new Error("simulated reconciliation result audit failure");
    }
    return result;
  });

  const response = await adminPost(
    f,
    jar,
    `/api/v1/admin/operations/${parent.id}/reconcile`,
    {
      reason,
      approvalId: approval.approvalId,
      action: "retry_desired",
    },
    current.body.csrfToken,
    { "idempotency-key": "m2c5-result-failure" },
  );
  assert.equal(response.response.status, 503);
  assert.equal(response.body.error.code, "audit_unavailable");
  assert.match(response.body.error.operationId, /^op_/);
  assert.equal(f.auth.reconcileCalls.length, 1);

  const data = await readAdminData(f);
  const child = data.adminOperations[response.body.error.operationId];
  assert.equal(child.status, "dependency_invoked");
  assert.equal(child.resultAuditId, "");
  assert.deepEqual(
    data.adminAuditLogs
      .filter((audit) => audit.operationId === child.id)
      .map((audit) => audit.phase),
    ["intent"],
  );
  assert.equal(data.adminOperations[parent.id].reconciliationState, undefined);
});

test("approval risk levels and canonical digests are stable", () => {
  assert.deepEqual(
    [
      "user.enable",
      "credential.rotate",
      "user.policy.quota",
      "user.disable",
      "device.revoke",
      "user.policy.models",
      "operation.reconcile",
    ].map(riskForAction),
    ["L", "M", "M", "H", "H", "H", "C"],
  );
  assert.equal(riskForAction("unknown.action"), "");

  assert.deepEqual(
    normalizedApprovalPayload("user.policy.models", {
      expectedVersion: 3,
      models: ["openai/gpt-test", "deepseek/deepseek-chat", "openai/gpt-test"],
    }),
    {
      expectedVersion: 3,
      models: ["deepseek/deepseek-chat", "openai/gpt-test"],
    },
  );
  assert.equal(
    approvalPayloadDigest("user.policy.quota", {
      expectedVersion: 2,
      limits: [
        { cost: 1, period: "month", tokens: 1000 },
        { tokens: 50, period: "day" },
      ],
    }),
    approvalPayloadDigest("user.policy.quota", {
      limits: [
        { period: "day", tokens: 50 },
        { tokens: 1000, period: "month", cost: 1 },
      ],
      expectedVersion: 2,
    }),
  );

  const binding = {
    environmentId: "env_test",
    policyVersion: "policy-v1",
    requesterSubjectId: "adm_requester",
    action: "user.disable",
    targetType: "user",
    targetId: "usr_alice",
    targetOrgUnitId: "org-platform",
    riskLevel: "H",
    reason: "Lost laptop",
    payloadDigest: approvalPayloadDigest("user.disable", {}),
  };
  assert.equal(approvalBindingDigest(binding), approvalBindingDigest({ ...binding }));
  assert.notEqual(
    approvalBindingDigest(binding),
    approvalBindingDigest({ ...binding, policyVersion: "policy-v2" }),
  );
  assert.notEqual(
    approvalBindingDigest(binding),
    approvalBindingDigest({ ...binding, targetOrgUnitId: "org-sales" }),
  );
});

test("approval APIs enforce CSRF, separation of duty, permissions, and organization scope", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);
  const salesDepartmentAdmin = await independentApprover(f, {
    role: "department_admin",
    scopeOrgUnitId: "org-sales",
  });
  const engineeringDepartmentAdmin = await independentApprover(f, {
    role: "department_admin",
    scopeOrgUnitId: "org-root",
  });

  const noCsrf = await adminPost(
    f,
    jar,
    "/api/v1/admin/approvals",
    {
      action: "user.disable",
      targetId: "usr_bob",
      reason: "CSRF must protect approval creation",
    },
    "",
  );
  assert.equal(noCsrf.response.status, 403);
  assert.equal(noCsrf.body.error.code, "csrf_invalid");

  const lowRisk = await adminPost(
    f,
    jar,
    "/api/v1/admin/approvals",
    {
      action: "user.enable",
      targetId: "usr_bob",
      reason: "Enabling is low risk",
    },
    current.body.csrfToken,
  );
  assert.equal(lowRisk.response.status, 400);
  assert.equal(lowRisk.body.error.code, "approval_not_required");

  const approval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_bob",
    reason: "Separation-of-duty test",
  });

  const selfDecision = await adminPost(
    f,
    jar,
    `/api/v1/admin/approvals/${approval.approvalId}/decisions`,
    { decision: "approve", reason: "I approve my own request" },
    current.body.csrfToken,
  );
  assert.equal(selfDecision.response.status, 403);
  assert.equal(selfDecision.body.error.code, "approval_separation_required");

  const noDecisionCsrf = await adminPost(
    f,
    approver.jar,
    `/api/v1/admin/approvals/${approval.approvalId}/decisions`,
    { decision: "approve", reason: "Missing CSRF" },
    "",
  );
  assert.equal(noDecisionCsrf.response.status, 403);
  assert.equal(noDecisionCsrf.body.error.code, "csrf_invalid");

  const crossScopeRead = await adminGet(
    f,
    salesDepartmentAdmin.jar,
    `/api/v1/admin/approvals/${approval.approvalId}`,
  );
  assert.equal(crossScopeRead.response.status, 403);
  assert.equal(crossScopeRead.body.error.code, "forbidden_scope");

  const readOnlyDecision = await adminPost(
    f,
    engineeringDepartmentAdmin.jar,
    `/api/v1/admin/approvals/${approval.approvalId}/decisions`,
    { decision: "approve", reason: "Department admins are read-only" },
    engineeringDepartmentAdmin.current.body.csrfToken,
  );
  assert.equal(readOnlyDecision.response.status, 403);
  assert.equal(readOnlyDecision.body.error.code, "forbidden_role");

  const approved = await decideApproval(
    f,
    approver,
    approval.approvalId,
    "approve",
    "Independent security review",
  );
  assert.equal(approved.status, "approved");
  assert.equal(approved.decisions.length, 1);
  assert.equal(approved.decisions[0].actorSubjectId, approver.current.body.user.id);
  assertNoWriteSecrets(approved, f, jar);
});

test("external approval callbacks verify HMAC, time, issuer, audience, event idempotency, and nonce replay", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_bob",
    reason: "Validate an external approval callback",
  });

  const missingSignature = await postApprovalCallback(
    f,
    callbackPayload(approval.approvalId),
    { omitSignature: true },
  );
  assert.equal(missingSignature.response.status, 400);
  assert.equal(missingSignature.body.error.code, "approval_callback_invalid");

  const missingTimestamp = await postApprovalCallback(
    f,
    callbackPayload(approval.approvalId),
    { omitTimestamp: true },
  );
  assert.equal(missingTimestamp.response.status, 400);
  assert.equal(missingTimestamp.body.error.code, "approval_callback_invalid");

  const missingNonce = await postApprovalCallback(
    f,
    callbackPayload(approval.approvalId),
    { omitNonce: true },
  );
  assert.equal(missingNonce.response.status, 400);
  assert.equal(missingNonce.body.error.code, "approval_callback_invalid");

  const wrongSignature = await postApprovalCallback(
    f,
    callbackPayload(approval.approvalId),
    { signature: "0".repeat(64) },
  );
  assert.equal(wrongSignature.response.status, 401);
  assert.equal(wrongSignature.body.error.code, "approval_callback_signature_invalid");

  const stale = await postApprovalCallback(
    f,
    callbackPayload(approval.approvalId),
    { timestamp: Math.floor(Date.now() / 1000) - 3600 },
  );
  assert.equal(stale.response.status, 401);
  assert.equal(stale.body.error.code, "approval_callback_timestamp_invalid");

  const future = await postApprovalCallback(
    f,
    callbackPayload(approval.approvalId),
    { timestamp: Math.floor(Date.now() / 1000) + 3600 },
  );
  assert.equal(future.response.status, 401);
  assert.equal(future.body.error.code, "approval_callback_timestamp_invalid");

  const wrongIssuer = await postApprovalCallback(
    f,
    callbackPayload(approval.approvalId, { issuer: "https://untrusted.example" }),
  );
  assert.equal(wrongIssuer.response.status, 403);
  assert.equal(wrongIssuer.body.error.code, "approval_callback_issuer_invalid");

  const wrongAudience = await postApprovalCallback(
    f,
    callbackPayload(approval.approvalId, { audience: "another-service" }),
  );
  assert.equal(wrongAudience.response.status, 403);
  assert.equal(wrongAudience.body.error.code, "approval_callback_audience_invalid");

  const wrongContentType = await postApprovalCallback(
    f,
    callbackPayload(approval.approvalId),
    { contentType: "text/plain" },
  );
  assert.equal(wrongContentType.response.status, 415);
  assert.equal(wrongContentType.body.error.code, "unsupported_media_type");

  const invalidSchema = await postApprovalCallback(
    f,
    callbackPayload(approval.approvalId, { schemaVersion: 2 }),
  );
  assert.equal(invalidSchema.response.status, 400);
  assert.equal(invalidSchema.body.error.code, "approval_callback_invalid");

  let data = await readAdminData(f);
  assert.deepEqual(data.approvalCallbackEvents, {});
  assert.deepEqual(data.approvalCallbackNonces, {});

  const acceptedPayload = callbackPayload(approval.approvalId);
  const accepted = await postApprovalCallback(f, acceptedPayload);
  assert.equal(accepted.response.status, 200, JSON.stringify(accepted.body));
  assert.equal(accepted.body.idempotent, false);
  assert.equal(accepted.body.approval.status, "approved");
  assert.equal(accepted.body.approval.decisionSource, "external");
  assert.equal(accepted.body.approval.externalEventId, acceptedPayload.eventId);
  assert.equal(accepted.body.approval.decisions.length, 1);
  assert.equal(accepted.body.approval.decisions[0].source, "external");
  assert.equal(accepted.body.approval.decisions[0].eventId, acceptedPayload.eventId);
  assert.equal(accepted.body.approval.decisions[0].issuer, CALLBACK_ISSUER);

  const idempotent = await postApprovalCallback(f, acceptedPayload);
  assert.equal(idempotent.response.status, 200);
  assert.equal(idempotent.body.idempotent, true);
  assert.equal(idempotent.body.approval.decisions.length, 1);

  const conflict = await postApprovalCallback(f, {
    ...acceptedPayload,
    externalReference: "OA-conflicting-payload",
  });
  assert.equal(conflict.response.status, 409);
  assert.equal(conflict.body.error.code, "approval_callback_conflict");

  const replayedNonce = await postApprovalCallback(
    f,
    callbackPayload(approval.approvalId),
    { nonce: accepted.nonce },
  );
  assert.equal(replayedNonce.response.status, 409);
  assert.equal(replayedNonce.body.error.code, "approval_callback_replay");

  data = await readAdminData(f);
  assert.equal(Object.keys(data.approvalCallbackEvents).length, 1);
  assert.equal(Object.keys(data.approvalCallbackNonces).length, 1);
  assert.equal(
    Object.values(data.approvalDecisions)
      .filter((decision) => decision.approvalId === approval.approvalId)
      .length,
    1,
  );
  assert.equal(
    data.adminSystemAuditLogs.filter((audit) => (
      audit.action === "approval.approved"
      && audit.approvalId === approval.approvalId
    )).length,
    1,
  );
  assertNoWriteSecrets(
    [accepted.body, idempotent.body, data, await fs.readFile(f.config.storePath, "utf8")],
    f,
    jar,
  );
});

test("external callbacks enforce scope, separation of duty, binding, and one-time business consumption", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const reason = "External approval must still bind to one business action";
  const limits = [{ period: "month", tokens: 1000, cost: 1 }];
  const approval = await requestApproval(f, jar, current, {
    action: "user.policy.quota",
    targetId: "usr_alice",
    reason,
    expectedVersion: 2,
    limits,
  });

  const selfBySubject = await postApprovalCallback(f, callbackPayload(approval.approvalId, {
    actorSubjectId: current.body.user.id,
  }));
  assert.equal(selfBySubject.response.status, 403);
  assert.equal(selfBySubject.body.error.code, "approval_separation_required");

  const selfByEmail = await postApprovalCallback(f, callbackPayload(approval.approvalId, {
    actorSubjectId: "admin-external-reviewer-email",
    actorEmail: current.body.user.email,
  }));
  assert.equal(selfByEmail.response.status, 403);
  assert.equal(selfByEmail.body.error.code, "approval_separation_required");

  const unknown = await postApprovalCallback(
    f,
    callbackPayload(`apr_${crypto.randomUUID()}`),
  );
  assert.equal(unknown.response.status, 404);
  assert.equal(unknown.body.error.code, "approval_not_found");

  const crossEnvironment = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_bob",
    reason: "Cross-environment callback must fail",
  });
  await f.admin.store.mutate((data) => {
    data.approvalRequests[crossEnvironment.approvalId].environmentId = "env_other_environment";
  });
  const cross = await postApprovalCallback(
    f,
    callbackPayload(crossEnvironment.approvalId),
  );
  assert.equal(cross.response.status, 403);
  assert.equal(cross.body.error.code, "approval_callback_scope");

  const tampered = await requestApproval(f, jar, current, {
    action: "device.revoke",
    targetId: "dev_bob",
    reason: "Tampered approval binding must fail",
  });
  await f.admin.store.mutate((data) => {
    data.approvalRequests[tampered.approvalId].reason = "Tampered after creation";
  });
  const tamperedResult = await postApprovalCallback(
    f,
    callbackPayload(tampered.approvalId),
  );
  assert.equal(tamperedResult.response.status, 403);
  assert.equal(tamperedResult.body.error.code, "approval_callback_scope");

  const accepted = await postApprovalCallback(f, callbackPayload(approval.approvalId));
  assert.equal(accepted.response.status, 200, JSON.stringify(accepted.body));
  assert.equal(accepted.body.approval.status, "approved");
  assert.equal(f.auth.writeCalls.length, 0);

  const changedPayload = await adminPut(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/policy/quota",
    {
      reason,
      expectedVersion: 2,
      limits: [{ period: "month", tokens: 2000, cost: 2 }],
      approvalId: approval.approvalId,
    },
    current.body.csrfToken,
  );
  assert.equal(changedPayload.response.status, 409);
  assert.equal(changedPayload.body.error.code, "approval_payload_mismatch");
  assert.equal(f.auth.writeCalls.length, 0);

  const body = { reason, expectedVersion: 2, limits, approvalId: approval.approvalId };
  const written = await adminPut(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/policy/quota",
    body,
    current.body.csrfToken,
  );
  assert.equal(written.response.status, 200, JSON.stringify(written.body));
  assert.equal(f.auth.writeCalls.length, 1);

  const consumed = await adminPut(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/policy/quota",
    body,
    current.body.csrfToken,
  );
  assert.equal(consumed.response.status, 409);
  assert.equal(consumed.body.error.code, "approval_consumed");
  assert.equal(f.auth.writeCalls.length, 1);

  const replayAfterConsumption = await postApprovalCallback(
    f,
    callbackPayload(approval.approvalId),
  );
  assert.equal(replayAfterConsumption.response.status, 409);
  assert.equal(replayAfterConsumption.body.error.code, "approval_consumed");

  const data = await readAdminData(f);
  assert.equal(data.approvalRequests[approval.approvalId].status, "consumed");
  assert.equal(Object.keys(data.approvalCallbackEvents).length, 1);
  assert.equal(Object.keys(data.approvalCallbackNonces).length, 1);
  assertNoWriteSecrets([written.body, data], f, jar);
});

test("external callbacks fail closed for disabled configuration and unavailable approval states", { timeout: 30000 }, async (t) => {
  const disabled = await fixture({ callbackEnabled: false });
  t.after(() => disabled.close());
  const disabledResult = await postApprovalCallback(
    disabled,
    callbackPayload(`apr_${crypto.randomUUID()}`),
    { secret: CALLBACK_SECRET },
  );
  assert.equal(disabledResult.response.status, 503);
  assert.equal(disabledResult.body.error.code, "approval_callback_unavailable");

  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);
  const jar = await adminLogin(f);
  const current = await me(f, jar);

  const expired = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason: "Expired external approval",
  });
  await f.admin.store.mutate((data) => {
    data.approvalRequests[expired.approvalId].expiresAt = "2000-01-01T00:00:00.000Z";
  });
  const expiredResult = await postApprovalCallback(
    f,
    callbackPayload(expired.approvalId),
  );
  assert.equal(expiredResult.response.status, 403);
  assert.equal(expiredResult.body.error.code, "approval_expired");

  const revoked = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason: "Revoked external approval",
  });
  await f.admin.store.mutate((data) => {
    data.approvalRequests[revoked.approvalId].status = "revoked";
  });
  const revokedResult = await postApprovalCallback(
    f,
    callbackPayload(revoked.approvalId),
  );
  assert.equal(revokedResult.response.status, 403);
  assert.equal(revokedResult.body.error.code, "approval_revoked");

  const reserved = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason: "Reserved external approval",
  });
  await f.admin.store.mutate((data) => {
    data.approvalRequests[reserved.approvalId].status = "reserved";
  });
  const reservedResult = await postApprovalCallback(
    f,
    callbackPayload(reserved.approvalId),
  );
  assert.equal(reservedResult.response.status, 409);
  assert.equal(reservedResult.body.error.code, "approval_consumed");

  const rejected = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason: "External rejection path",
  });
  const rejectedResult = await postApprovalCallback(
    f,
    callbackPayload(rejected.approvalId, { decision: "reject" }),
  );
  assert.equal(rejectedResult.response.status, 200, JSON.stringify(rejectedResult.body));
  assert.equal(rejectedResult.body.approval.status, "rejected");
  assert.equal(rejectedResult.body.approval.rejectedBySubjectId, "admin-external-reviewer");
  assert.equal(rejectedResult.body.approval.decisions[0].decision, "reject");

  const alreadyDecided = await postApprovalCallback(
    f,
    callbackPayload(rejected.approvalId),
  );
  assert.equal(alreadyDecided.response.status, 503);
  assert.equal(alreadyDecided.body.error.code, "approval_unavailable");

  const data = await readAdminData(f);
  assert.equal(data.approvalRequests[expired.approvalId].status, "expired");
  assert.equal(Object.keys(data.approvalCallbackEvents).length, 1);
  assert.equal(Object.keys(data.approvalCallbackNonces).length, 1);
});

test("callback configuration fails closed unless secret, issuer, and audience are configured together", async () => {
  await assert.rejects(
    () => fixture({ callbackAudience: "" }),
    /ADMIN_APPROVAL_CALLBACK_ISSUER and ADMIN_APPROVAL_CALLBACK_AUDIENCE are required/,
  );
  await assert.rejects(
    () => fixture({ callbackEnabled: false, callbackIssuer: CALLBACK_ISSUER }),
    /ADMIN_APPROVAL_CALLBACK_SECRET is required when callback issuer or audience is set/,
  );
});

test("write approvals bind action, target, reason, payload, and policy version, and are consumed once", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);
  const reason = "Apply the approved monthly quota";
  const limits = [{ period: "month", tokens: 1000, cost: 1 }];
  const approval = await requestApproval(f, jar, current, {
    action: "user.policy.quota",
    targetId: "usr_alice",
    reason,
    expectedVersion: 2,
    limits,
  });
  await decideApproval(f, approver, approval.approvalId);

  const crossAction = await adminPost(
    f,
    jar,
    "/api/v1/admin/devices/dev_alice/revoke",
    { reason, approvalId: approval.approvalId },
    current.body.csrfToken,
  );
  assert.equal(crossAction.response.status, 403);
  assert.equal(crossAction.body.error.code, "approval_target_mismatch");

  const crossTarget = await adminPut(
    f,
    jar,
    "/api/v1/admin/users/usr_bob/policy/quota",
    {
      reason,
      expectedVersion: 1,
      limits,
      approvalId: approval.approvalId,
    },
    current.body.csrfToken,
  );
  assert.equal(crossTarget.response.status, 403);
  assert.equal(crossTarget.body.error.code, "approval_target_mismatch");

  const changedPayload = await adminPut(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/policy/quota",
    {
      reason,
      expectedVersion: 2,
      limits: [{ period: "month", tokens: 2000, cost: 2 }],
      approvalId: approval.approvalId,
    },
    current.body.csrfToken,
  );
  assert.equal(changedPayload.response.status, 409);
  assert.equal(changedPayload.body.error.code, "approval_payload_mismatch");

  const changedReason = await adminPut(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/policy/quota",
    {
      reason: "A different reason must not reuse the approval",
      expectedVersion: 2,
      limits,
      approvalId: approval.approvalId,
    },
    current.body.csrfToken,
  );
  assert.equal(changedReason.response.status, 409);
  assert.equal(changedReason.body.error.code, "approval_payload_mismatch");

  await f.admin.store.mutate((data) => {
    data.approvalRequests[approval.approvalId].policyVersion = "tampered-policy";
  });
  const changedPolicyVersion = await adminPut(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/policy/quota",
    { reason, expectedVersion: 2, limits, approvalId: approval.approvalId },
    current.body.csrfToken,
  );
  assert.equal(changedPolicyVersion.response.status, 409);
  assert.equal(changedPolicyVersion.body.error.code, "approval_payload_mismatch");
  await f.admin.store.mutate((data) => {
    data.approvalRequests[approval.approvalId].policyVersion = approval.policyVersion;
  });
  assert.equal(f.auth.writeCalls.length, 0);

  const idempotencyKey = "approval-consume-once";
  const body = { reason, expectedVersion: 2, limits, approvalId: approval.approvalId };
  const written = await adminPut(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/policy/quota",
    body,
    current.body.csrfToken,
    { "idempotency-key": idempotencyKey },
  );
  assert.equal(written.response.status, 200, JSON.stringify(written.body));
  assert.equal(f.auth.writeCalls.length, 1);

  const replay = await adminPut(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/policy/quota",
    body,
    current.body.csrfToken,
    { "idempotency-key": idempotencyKey },
  );
  assert.equal(replay.response.status, 200);
  assert.equal(replay.body.operationId, written.body.operationId);
  assert.equal(f.auth.writeCalls.length, 1);

  const consumed = await adminPut(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/policy/quota",
    body,
    current.body.csrfToken,
  );
  assert.equal(consumed.response.status, 409);
  assert.equal(consumed.body.error.code, "approval_consumed");
  assert.equal(f.auth.writeCalls.length, 1);

  const lowRiskWithApproval = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/enable",
    { reason: "Low-risk enable", approvalId: approval.approvalId },
    current.body.csrfToken,
  );
  assert.equal(lowRiskWithApproval.response.status, 403);
  assert.equal(lowRiskWithApproval.body.error.code, "approval_invalid");
  assert.equal(f.auth.writeCalls.length, 1);

  const data = await readAdminData(f);
  assert.equal(data.approvalRequests[approval.approvalId].status, "consumed");
  assert.equal(
    data.approvalRequests[approval.approvalId].operationId,
    written.body.operationId,
  );
  assert.equal(data.approvalConsumptions[approval.approvalId].outcome, "succeeded");
  const consumedAudit = data.adminSystemAuditLogs.find((audit) => (
    audit.action === "approval.consumed"
    && audit.approvalId === approval.approvalId
  ));
  assert.equal(consumedAudit.operationId, written.body.operationId);
  assertNoWriteSecrets(data, f, jar);
});

test("expired and revoked approvals fail closed, and concurrent operations cannot share one approval", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);

  const expiredReason = "Expired approvals cannot authorize writes";
  const expiredApproval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason: expiredReason,
  });
  await decideApproval(f, approver, expiredApproval.approvalId);
  await f.admin.store.mutate((data) => {
    data.approvalRequests[expiredApproval.approvalId].expiresAt = "2000-01-01T00:00:00.000Z";
  });
  const expired = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    { reason: expiredReason, approvalId: expiredApproval.approvalId },
    current.body.csrfToken,
  );
  assert.equal(expired.response.status, 403);
  assert.equal(expired.body.error.code, "approval_expired");
  assert.equal(f.auth.writeCalls.length, 0);

  const revokedReason = "Revoked approvals cannot authorize writes";
  const revokedApproval = await requestApproval(f, jar, current, {
    action: "device.revoke",
    targetId: "dev_bob",
    reason: revokedReason,
  });
  await decideApproval(f, approver, revokedApproval.approvalId);
  const revoked = await adminPost(
    f,
    approver.jar,
    `/api/v1/admin/approvals/${revokedApproval.approvalId}/revoke`,
    { reason: "Security reviewer withdrew the approval" },
    approver.current.body.csrfToken,
  );
  assert.equal(revoked.response.status, 200);
  assert.equal(revoked.body.approval.status, "revoked");
  const revokedWrite = await adminPost(
    f,
    jar,
    "/api/v1/admin/devices/dev_bob/revoke",
    { reason: revokedReason, approvalId: revokedApproval.approvalId },
    current.body.csrfToken,
  );
  assert.equal(revokedWrite.response.status, 403);
  assert.equal(revokedWrite.body.error.code, "approval_revoked");
  assert.equal(f.auth.writeCalls.length, 0);

  const concurrentReason = "Only one concurrent operation may consume this approval";
  const concurrentApproval = await requestApproval(f, jar, current, {
    action: "credential.rotate",
    targetId: "key-bob",
    reason: concurrentReason,
  });
  await decideApproval(f, approver, concurrentApproval.approvalId);
  f.auth.setWriteDelay(250);
  const concurrentBody = {
    reason: concurrentReason,
    approvalId: concurrentApproval.approvalId,
  };
  const concurrent = await Promise.all([
    adminPost(
      f,
      jar,
      "/api/v1/admin/credentials/key-bob/rotate",
      concurrentBody,
      current.body.csrfToken,
      { "idempotency-key": "approval-race-left" },
    ),
    adminPost(
      f,
      jar,
      "/api/v1/admin/credentials/key-bob/rotate",
      concurrentBody,
      current.body.csrfToken,
      { "idempotency-key": "approval-race-right" },
    ),
  ]);
  concurrent.sort((left, right) => left.response.status - right.response.status);
  assert.deepEqual(concurrent.map((result) => result.response.status), [200, 409]);
  assert.equal(concurrent[1].body.error.code, "approval_consumed");
  assert.equal(f.auth.writeCalls.length, 1);

  const data = await readAdminData(f);
  assert.equal(data.approvalRequests[concurrentApproval.approvalId].status, "consumed");
  assert.equal(data.adminOperations[concurrent[0].body.operationId].status, "succeeded");
  assertNoWriteSecrets(data, f, jar);
});

test("startup recovery turns a reserved approval into a fail-closed consumed approval", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);
  const approval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason: "Restart recovery test",
  });
  await decideApproval(f, approver, approval.approvalId);
  await f.admin.store.mutate((data) => {
    const stored = data.approvalRequests[approval.approvalId];
    stored.status = "reserved";
    stored.operationId = "op_recovered_reservation";
    stored.stateHistory.push({
      status: "reserved",
      at: new Date().toISOString(),
      actorSubjectId: current.body.user.id,
      reason: "simulated process interruption",
    });
    data.approvalConsumptions[approval.approvalId] = {
      approvalId: approval.approvalId,
      operationId: "op_recovered_reservation",
      reservedAt: new Date().toISOString(),
      consumedAt: "",
      outcome: "reserved",
    };
  });

  const restarted = await createEnterpriseAdminServer(f.config);
  const recovered = await restarted.store.read((data) => ({
    approval: structuredClone(data.approvalRequests[approval.approvalId]),
    consumption: structuredClone(data.approvalConsumptions[approval.approvalId]),
    audits: structuredClone(data.adminSystemAuditLogs),
  }));
  assert.equal(recovered.approval.status, "consumed");
  assert.match(recovered.approval.consumedAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(recovered.approval.recoveredAt, recovered.approval.consumedAt);
  assert.equal(recovered.consumption.outcome, "unknown_recovered");
  assert.equal(recovered.consumption.operationId, "op_recovered_reservation");
  assert.ok(recovered.audits.some((audit) => (
    audit.action === "approval.recovered_reserved"
    && audit.approvalId === approval.approvalId
    && audit.result === "failed_closed"
  )));
  assertNoWriteSecrets(recovered, f, jar);
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
    assert.deepEqual(loaded.approvalCallbackEvents, {});
    assert.deepEqual(loaded.approvalCallbackNonces, {});
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
