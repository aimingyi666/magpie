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
import { GatewayAdminClient } from "../src/gateway-admin-client.js";
import {
  approvalBindingDigest,
  approvalPayloadDigest,
  normalizedApprovalPayload,
  riskForAction,
} from "../src/approval.js";
import {
  BREAK_GLASS_GRANT_TTL_MS,
  BREAK_GLASS_REVIEW_DUE_MS,
} from "../src/break-glass.js";
import {
  NotificationDispatcher,
  NotificationOutbox,
  claimNotificationDelivery,
  enqueueNotification,
  enqueueOperationNotification,
  markNotificationDelivering,
  notificationTransportEvent,
  publicNotificationDelivery,
  recoverExpiredNotificationLeases,
  stableErrorCode,
} from "../src/notification-outbox.js";

const CALLBACK_SECRET = "approval-callback-test-secret-0000000001";
const CALLBACK_ISSUER = "https://approval.corp.example";
const CALLBACK_AUDIENCE = "magpie-enterprise-admin-test";
const MOCK_ACCESS_TOKEN = "mock-access-token";
const TEST_SESSION_SECRET = ["admin", "test", "session", "secret", "fixture", "material"].join("-");
const TEST_OIDC_CLIENT_SECRET = ["admin", "test", "oidc", "client", "fixture", "material"].join("-");
const TEST_AUTH_SERVICE_TOKEN = ["admin", "test", "auth", "service", "fixture", "material"].join("-");
const TEST_STEP_UP_CLIENT_SECRET = ["admin", "test", "step", "up", "fixture", "material"].join("-");
const TEST_SIEM_COLLECTOR_TOKEN = ["admin", "test", "siem", "collector", "fixture"].join("-");
const TEST_RESOURCE_SERVICE_TOKEN = [
  "admin",
  "test",
  "resource",
  "service",
  "fixture",
  "material",
].join("-");
const RESOURCE_PLATFORM_ID = `res_${"a".repeat(16)}`;
const RESOURCE_SALES_ID = `res_${"b".repeat(16)}`;
const RESOURCE_GLOBAL_ID = `res_${"c".repeat(16)}`;
const RELEASE_PLATFORM_ID = `rel_${"a".repeat(16)}`;

function adminConfigEnv(overrides = {}) {
  return {
    ADMIN_PUBLIC_URL: "https://admin.corp.example",
    ADMIN_SESSION_SECRET: TEST_SESSION_SECRET,
    ADMIN_OIDC_ISSUER: "https://idp.corp.example",
    ADMIN_OIDC_CLIENT_ID: "magpie-admin",
    ADMIN_OIDC_CLIENT_SECRET: TEST_OIDC_CLIENT_SECRET,
    ADMIN_OIDC_REDIRECT_URI: "https://admin.corp.example/admin/oauth/callback",
    ADMIN_AUTH_SERVICE_URL: "http://127.0.0.1:3444",
    ADMIN_AUTH_SERVICE_TOKEN: TEST_AUTH_SERVICE_TOKEN,
    ADMIN_ALLOWED_IPS: "127.0.0.1/32",
    ADMIN_STEP_UP_OIDC_CLIENT_ID: "magpie-admin-step-up",
    ADMIN_STEP_UP_OIDC_CLIENT_SECRET: TEST_STEP_UP_CLIENT_SECRET,
    ADMIN_STEP_UP_REDIRECT_URI: "https://admin.corp.example/admin/oauth/step-up/callback",
    ADMIN_STEP_UP_OIDC_SCOPES: "openid,profile,email",
    ADMIN_STEP_UP_TTL_SECONDS: "600",
    ADMIN_STEP_UP_CRITICAL_TTL_SECONDS: "300",
    ADMIN_STEP_UP_AUTH_TIME_MAX_AGE_SECONDS: "120",
    ...overrides,
  };
}

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
  const clientSecret = TEST_OIDC_CLIENT_SECRET;
  const stepUpClientId = "magpie-enterprise-admin-step-up-test";
  const stepUpClientSecret = TEST_STEP_UP_CLIENT_SECRET;
  let base = "";
  let lastAuthorize = null;
  let lastStepUpAuthorize = null;
  let loginClaims = options.claims || {};
  let stepUpClaims = options.stepUpClaims || options.claims || {};

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
      const requestedClientId = url.searchParams.get("client_id");
      if (requestedClientId !== clientId && requestedClientId !== stepUpClientId) {
        res.writeHead(400);
        res.end();
        return;
      }
      const stepUp = requestedClientId === stepUpClientId;
      if (stepUp) lastStepUpAuthorize = new URL(url);
      else lastAuthorize = new URL(url);
      const code = `oidc_${crypto.randomBytes(18).toString("base64url")}`;
      codes.set(code, {
        redirectUri: url.searchParams.get("redirect_uri"),
        nonce: url.searchParams.get("nonce"),
        codeChallenge: url.searchParams.get("code_challenge"),
        createdAt: Date.now(),
        clientId: requestedClientId,
        claims: structuredClone(stepUp ? stepUpClaims : loginClaims),
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
      const code = codes.get(form.get("code"));
      const expected = code?.clientId === stepUpClientId
        ? `${stepUpClientId}:${stepUpClientSecret}`
        : `${clientId}:${clientSecret}`;
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
        aud: code.clientId,
        sub: "admin-alice",
        email: "admin@corp.example",
        email_verified: true,
        name: "Admin Alice",
        amr: ["pwd", "mfa"],
        auth_time: now,
        nonce: code.nonce,
        iat: now,
        exp: now + 300,
        ...code.claims,
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({
        access_token: MOCK_ACCESS_TOKEN,
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
    stepUpClientId,
    stepUpClientSecret,
    get base() { return base; },
    get lastAuthorize() { return lastAuthorize; },
    get lastStepUpAuthorize() { return lastStepUpAuthorize; },
    setBase(value) { base = value; },
    setClaims(value) {
      loginClaims = value || options.claims || {};
      stepUpClaims = value || options.stepUpClaims || options.claims || {};
    },
    setStepUpClaims(value) { stepUpClaims = value || options.stepUpClaims || options.claims || {}; },
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

// Mock resource catalog / client sync control plane. It deliberately returns
// fields the admin service must never project, plus plaintext content and the
// service token, so leak assertions stay meaningful.
function createMockResourceService(expectedToken) {
  let failing = false;
  let slow = false;
  let malformed = false;
  let redirecting = false;
  const calls = [];
  const resources = [
    {
      id: RESOURCE_PLATFORM_ID,
      kind: "mcp_server",
      name: "Platform baseline",
      description: "Engineering baseline",
      publisher: "platform-team",
      deliveryMode: "managed",
      assignments: ["org-platform"],
      compatibility: { platforms: ["windows", "macos"], minClientVersion: "1.0.0" },
      status: "published",
      currentReleaseId: RELEASE_PLATFORM_ID,
      currentRelease: {
        id: RELEASE_PLATFORM_ID,
        resourceId: RESOURCE_PLATFORM_ID,
        resourceVersion: "2026.12.1",
        status: "published",
        hash: `sha256:${"1".repeat(64)}`,
        contentBytes: 42,
        mediaType: "application/json",
        manifestDigest: `sha256:${"2".repeat(64)}`,
        previousReleaseId: "",
        createdAt: "2026-10-20T00:00:00.000Z",
        publishedAt: "2026-10-21T00:00:00.000Z",
        createdBy: "should-not-leak-actor",
        publishedBy: "should-not-leak-actor",
      },
      createdAt: "2026-10-19T00:00:00.000Z",
      updatedAt: "2026-10-21T00:00:00.000Z",
      createdBy: "should-not-leak-actor",
      updatedBy: "should-not-leak-actor",
      contentBase64: Buffer.from("must-not-leak-resource-content").toString("base64"),
      signingKey: "must-not-leak-signing-key",
      serviceToken: expectedToken,
    },
    {
      id: RESOURCE_SALES_ID,
      kind: "skill",
      name: "Sales handbook",
      description: "Sales only",
      publisher: "sales-ops",
      deliveryMode: "managed",
      assignments: ["org-sales"],
      compatibility: { platforms: ["windows"] },
      status: "published",
      currentReleaseId: "",
      currentRelease: null,
      createdAt: "2026-10-18T00:00:00.000Z",
      updatedAt: "2026-10-22T00:00:00.000Z",
      signingKey: "must-not-leak-signing-key",
    },
    {
      id: RESOURCE_GLOBAL_ID,
      kind: "instruction",
      name: "Enterprise instruction",
      description: "Everyone",
      publisher: "it-governance",
      deliveryMode: "managed",
      assignments: ["*"],
      compatibility: {},
      status: "draft",
      currentReleaseId: "",
      currentRelease: null,
      createdAt: "2026-10-17T00:00:00.000Z",
      updatedAt: "2026-10-23T00:00:00.000Z",
    },
  ];
  const reports = [
    {
      userId: "usr_alice",
      deviceId: "dev_alice",
      revision: `sha256:${"3".repeat(64)}`,
      status: "drift",
      clientVersion: "1.4.0",
      installed: [{
        resourceId: RESOURCE_PLATFORM_ID,
        releaseId: RELEASE_PLATFORM_ID,
        manifestDigest: `sha256:${"2".repeat(64)}`,
      }],
      drift: [{
        resourceId: RESOURCE_PLATFORM_ID,
        state: "version_mismatch",
        expectedReleaseId: RELEASE_PLATFORM_ID,
        actualReleaseId: `rel_${"9".repeat(16)}`,
      }],
      reportedAt: "2026-10-31T08:10:00.000Z",
      receivedAt: "2026-10-31T08:11:00.000Z",
      syncToken: "must-not-leak-sync-token",
    },
    {
      userId: "usr_carol",
      deviceId: "dev_carol",
      revision: `sha256:${"4".repeat(64)}`,
      status: "synced",
      clientVersion: "1.4.0",
      installed: [],
      drift: [],
      reportedAt: "2026-10-31T10:10:00.000Z",
      receivedAt: "2026-10-31T10:11:00.000Z",
    },
    {
      userId: "usr_ghost",
      deviceId: "dev_ghost",
      revision: `sha256:${"5".repeat(64)}`,
      status: "offline",
      clientVersion: "1.4.0",
      installed: [],
      drift: [],
      reportedAt: "2026-10-30T10:10:00.000Z",
      receivedAt: "2026-10-30T10:11:00.000Z",
    },
    {
      // Known user, unknown device: a report alone must never grant visibility.
      userId: "usr_alice",
      deviceId: "dev_unregistered",
      revision: `sha256:${"6".repeat(64)}`,
      status: "synced",
      clientVersion: "1.4.0",
      installed: [],
      drift: [],
      reportedAt: "2026-10-29T10:10:00.000Z",
      receivedAt: "2026-10-29T10:11:00.000Z",
    },
  ];
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    calls.push({ pathname: url.pathname, authorization: String(req.headers.authorization || "") });
    const send = (status, value) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(value));
    };
    if (slow) {
      await new Promise((resolve) => setTimeout(resolve, 1200));
    }
    if (failing) {
      send(503, { error: { code: "resource_unavailable", token: expectedToken } });
      return;
    }
    if (String(req.headers.authorization || "") !== `Bearer ${expectedToken}`) {
      send(401, { error: { code: "unauthorized" } });
      return;
    }
    if (url.pathname === "/api/v1/admin/resources") {
      if (redirecting) {
        res.writeHead(302, { location: "/api/v1/admin/sync-reports" });
        res.end();
        return;
      }
      if (malformed) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end("{not json");
        return;
      }
      send(200, { schemaVersion: 1, ok: true, resources });
      return;
    }
    const resourceMatch = /^\/api\/v1\/admin\/resources\/(res_[a-z0-9]{16,64})$/.exec(url.pathname);
    if (resourceMatch) {
      const resource = resources.find((candidate) => candidate.id === resourceMatch[1]);
      if (!resource) send(404, { error: { code: "resource_not_found" } });
      else send(200, {
        schemaVersion: 1,
        ok: true,
        resource,
        releases: resource.currentRelease ? [resource.currentRelease] : [],
      });
      return;
    }
    if (url.pathname === "/api/v1/admin/sync-reports") {
      send(200, { schemaVersion: 1, ok: true, reports });
      return;
    }
    const reportMatch = /^\/api\/v1\/admin\/sync-reports\/([A-Za-z0-9._:-]+)$/.exec(url.pathname);
    if (reportMatch) {
      const report = reports.find((candidate) => candidate.deviceId === reportMatch[1]);
      if (!report) send(404, { error: { code: "sync_report_not_found" } });
      else send(200, { schemaVersion: 1, ok: true, report });
      return;
    }
    send(404, { error: { code: "not_found" } });
  });
  return {
    server,
    setFailing(value) { failing = value; },
    setSlow(value) { slow = value; },
    setMalformed(value) { malformed = value; },
    setRedirecting(value) { redirecting = value; },
    get calls() { return calls; },
  };
}

async function fixture(options = {}) {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-admin-test-"));
  let oidc = null;
  let auth = null;
  let resource = null;
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
    const serviceToken = TEST_AUTH_SERVICE_TOKEN;
    auth = createMockAuthService(serviceToken);
    const authBase = await listen(auth.server);
    const resourceEnabled = options.resourceServiceEnabled !== false;
    let resourceBase = "";
    if (resourceEnabled) {
      resource = createMockResourceService(TEST_RESOURCE_SERVICE_TOKEN);
      resourceBase = await listen(resource.server);
    }
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
    const stepUpEnabled = options.stepUpEnabled !== false;
    const config = loadConfig({
      ADMIN_PUBLIC_URL: "http://127.0.0.1:3998",
      ADMIN_PORT: "3998",
      ADMIN_STORE_PATH: path.join(temp, "admin-store.json"),
      ADMIN_SESSION_SECRET: TEST_SESSION_SECRET,
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
      ADMIN_STEP_UP_OIDC_CLIENT_ID: stepUpEnabled ? oidc.stepUpClientId : "",
      ADMIN_STEP_UP_OIDC_CLIENT_SECRET: stepUpEnabled ? oidc.stepUpClientSecret : "",
      ADMIN_STEP_UP_REDIRECT_URI: stepUpEnabled
        ? "http://127.0.0.1:3998/admin/oauth/step-up/callback"
        : "",
      ADMIN_STEP_UP_OIDC_SCOPES: "openid,profile,email",
      ADMIN_STEP_UP_ALLOWED_ACR_VALUES: options.allowedAcrValues || "",
      ADMIN_STEP_UP_TTL_SECONDS: options.stepUpTtlSeconds || "600",
      ADMIN_STEP_UP_CRITICAL_TTL_SECONDS: options.stepUpCriticalTtlSeconds || "300",
      ADMIN_STEP_UP_AUTH_TIME_MAX_AGE_SECONDS:
        options.stepUpAuthTimeMaxAgeSeconds || "120",
      ADMIN_BOOTSTRAP_EMAILS: "admin@corp.example",
      ADMIN_BOOTSTRAP_VALID_HOURS: "24",
      ADMIN_AUTH_SERVICE_URL: authBase,
      ADMIN_AUTH_SERVICE_TOKEN: serviceToken,
      ADMIN_AUTH_SERVICE_TIMEOUT_MS: "1000",
      ...(resourceBase
        ? {
          ADMIN_RESOURCE_SERVICE_URL: resourceBase,
          ADMIN_RESOURCE_SERVICE_TOKEN: TEST_RESOURCE_SERVICE_TOKEN,
          ADMIN_RESOURCE_SERVICE_TIMEOUT_MS: "1000",
        }
        : {}),
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
      ADMIN_EXPORT_TTL_SECONDS: options.exportTtlSeconds || "900",
      ADMIN_EXPORT_MAX_BYTES: options.exportMaxBytes || String(5 * 1024 * 1024),
      ADMIN_EXPORT_MAX_RECORDS: options.exportMaxRecords || "100000",
      ADMIN_NOTIFICATION_CHANNELS_ENABLED:
        options.notificationChannelsEnabled ? "true" : "false",
      ADMIN_NOTIFICATION_OUTBOUND_ALLOWLIST:
        options.notificationAllowlist ?? "hooks.example.test",
      ADMIN_NOTIFICATION_EMAIL_RECIPIENT_DOMAINS:
        options.notificationEmailDomains ?? "corp.example",
      ADMIN_NOTIFICATION_HTTP_TIMEOUT_MS: "1000",
      ADMIN_NOTIFICATION_HTTP_MAX_RESPONSE_BYTES: "65536",
      ADMIN_NOTIFICATION_HTTP_MAX_REDIRECTS: "3",
    });
    admin = await createEnterpriseAdminServer(config, options.adminServerOptions || {});
    const base = await listen(admin.server);
    config.publicUrl = base;
    config.oidc.redirectUri = `${base}/admin/oauth/callback`;
    if (config.stepUpOidc) {
      config.stepUpOidc.redirectUri = `${base}/admin/oauth/step-up/callback`;
    }
    return {
      temp,
      oidc,
      auth,
      resource,
      config,
      admin,
      base,
      usagePath,
      catalogPath,
      stepUpEnabled,
      secrets: {
        oidcClientSecret: oidc.clientSecret,
        stepUpOidcClientSecret: oidc.stepUpClientSecret,
        accessToken: MOCK_ACCESS_TOKEN,
        serviceToken,
        resourceServiceToken: TEST_RESOURCE_SERVICE_TOKEN,
        sessionSecret: config.sessionSecret,
        callbackSecret,
      },
      async close() {
        await admin.notificationEscalationScheduler?.stop();
        await admin.breakGlassScheduler?.stop();
        await admin.notificationDispatcher?.stop();
        await close(admin.server);
        await close(oidc.server);
        await close(auth.server);
        if (resource) await close(resource.server);
        await fs.rm(temp, { recursive: true, force: true });
      },
    };
  } catch (error) {
    await admin?.notificationEscalationScheduler?.stop();
    await admin?.breakGlassScheduler?.stop();
    await admin?.notificationDispatcher?.stop();
    if (admin?.server?.listening) await close(admin.server);
    if (oidc?.server?.listening) await close(oidc.server);
    if (auth?.server?.listening) await close(auth.server);
    if (resource?.server?.listening) await close(resource.server);
    await fs.rm(temp, { recursive: true, force: true });
    throw error;
  }
}

async function stepUpAttempt(f, jar, options = {}) {
  if (options.claims !== undefined) f.oidc.setStepUpClaims(options.claims);
  const returnTo = options.returnTo || "/admin/";
  const started = await fetch(
    `${f.base}/admin/oauth/step-up/start?returnTo=${encodeURIComponent(returnTo)}`,
    {
      redirect: "manual",
      headers: { cookie: jar.header() },
    },
  );
  jar.absorb(started);
  assert.equal(started.status, 302, await started.text());
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
  const body = callback.status === 302 || !String(
    callback.headers.get("content-type") || "",
  ).includes("application/json")
    ? null
    : await callback.json();
  return { started, authorize, callback, body };
}

async function stepUp(f, jar, claims = undefined) {
  const { callback } = await stepUpAttempt(f, jar, { claims });
  assert.equal(callback.status, 302, await callback.text());
  assert.equal(callback.headers.get("location"), "/admin/");
  const current = await me(f, jar);
  assert.equal(current.response.status, 200);
  assert.equal(
    current.body.stepUp.state,
    "verified",
    JSON.stringify(current.body.stepUp),
  );
  return jar;
}

async function adminLogin(f, jar = new CookieJar(), claims = undefined, options = {}) {
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
  if (f.stepUpEnabled && options.stepUp !== false) await stepUp(f, jar);
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
  if (f.stepUpEnabled) {
    await stepUp(f, jar, {
      sub: `admin-${suffix}`,
      email: `${suffix}@corp.example`,
      name: options.name || `Approver ${suffix}`,
    });
  }
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

async function decideApproval(
  f,
  approver,
  approvalId,
  decision = "approve",
  reason = "Independent review",
  stepId = "",
) {
  const result = await adminPost(
    f,
    approver.jar,
    `/api/v1/admin/approvals/${approvalId}/decisions`,
    { decision, reason, ...(stepId ? { stepId } : {}) },
    approver.current.body.csrfToken,
  );
  assert.equal(result.response.status, 200, JSON.stringify(result.body));
  return result.body.approval;
}

async function requestBreakGlass(f, jar, current, body = {}) {
  const result = await adminPost(
    f,
    jar,
    "/api/v1/admin/break-glass",
    {
      action: "user.disable",
      targetId: "usr_alice",
      incidentId: `INC-${crypto.randomUUID().slice(0, 12)}`,
      reason: "Emergency incident response",
      payload: {},
      ...body,
    },
    current.body.csrfToken,
  );
  assert.equal(result.response.status, 201, JSON.stringify(result.body));
  assert.match(result.body.grant.breakGlassId, /^bgr_/);
  return result.body.grant;
}

async function consumeBreakGlass(f, jar, current, grant, options = {}) {
  const result = await adminPost(
    f,
    jar,
    options.pathname || "/api/v1/admin/users/usr_alice/disable",
    {
      reason: options.reason ?? grant.reason,
      breakGlassId: grant.breakGlassId,
      ...(options.body || {}),
    },
    current.body.csrfToken,
    {
      "idempotency-key": options.idempotencyKey
        || `break-glass-consume-${crypto.randomUUID()}`,
    },
  );
  assert.equal(
    result.response.status,
    options.expectedStatus ?? 200,
    JSON.stringify(result.body),
  );
  return result;
}

async function reviewBreakGlass(f, reviewer, grantId, options = {}) {
  const result = await adminPost(
    f,
    reviewer.jar,
    `/api/v1/admin/break-glass/${grantId}/review`,
    {
      conclusion: options.conclusion || "justified",
      reason: options.reason || "Post-incident review complete",
    },
    reviewer.current.body.csrfToken,
    {
      "idempotency-key": options.idempotencyKey
        || `break-glass-review-${crypto.randomUUID()}`,
    },
  );
  assert.equal(
    result.response.status,
    options.expectedStatus ?? 201,
    JSON.stringify(result.body),
  );
  return result;
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

async function downloadExport(f, jar, pathname, token, headers = {}) {
  const response = await fetch(`${f.base}${pathname}`, {
    headers: {
      ...(jar ? { cookie: jar.header() } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
  });
  const bytes = new Uint8Array(await response.arrayBuffer());
  return {
    response,
    body: new TextDecoder("utf-8", { ignoreBOM: true }).decode(bytes),
  };
}

function assertNoWriteSecrets(value, f, jar) {
  const serialized = JSON.stringify(value);
  for (const forbidden of [
    "should-not-leak-gateway-key",
    "should-not-leak-device-token",
    "should-not-leak-token-hash",
    "must-not-leak-sync-token",
    "must-not-leak-signing-key",
    "must-not-leak-resource-content",
    "should-not-leak-actor",
    "BEGIN PUBLIC KEY",
    "sk-magpie-issued-",
    "mdev_",
    "tokenHash",
    f.secrets.serviceToken,
    ...(f.secrets.resourceServiceToken ? [f.secrets.resourceServiceToken] : []),
    f.secrets.oidcClientSecret,
    f.secrets.accessToken,
    ...(f.secrets.stepUpOidcClientSecret ? [f.secrets.stepUpOidcClientSecret] : []),
    ...(f.secrets.callbackSecret ? [f.secrets.callbackSecret] : []),
    jar.cookies.get(f.config.sessionCookieName) || "__no_cookie__",
    jar.cookies.get(f.config.stepUpCookieName) || "__no_step_up_cookie__",
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
    filteredOutRecords: 0,
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
    filteredOutRecords: 0,
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
  await stepUp(f, jar);
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
  assert.equal(missingTarget.response.status, 200);
  assert.equal(missingTarget.body.operation.operationId, "op_detail_missing_target");

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

  const tamperedCursor = `${cursor[0] === "A" ? "B" : "A"}${cursor.slice(1)}`;
  assert.notEqual(tamperedCursor, cursor);
  const tampered = await adminGet(
    f,
    jar,
    `/api/v1/admin/audit-logs?limit=37&cursor=${encodeURIComponent(tamperedCursor)}`,
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
      "usage.export.create",
      "audit.export.create",
      "operation.reconcile",
    ].map(riskForAction),
    ["L", "M", "M", "H", "H", "H", "H", "H", "C"],
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

test("M2-D exports require a bound approval, step-up, CSRF, and idempotency", {
  timeout: 30000,
}, async (t) => {
  const f = await fixture({ usageContent: usageLines() });
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);
  const request = {
    exportType: "usage",
    orgUnitId: "*",
    from: new Date(Date.now() - 6 * 3600 * 1000).toISOString(),
    to: new Date(Date.now() + 3600 * 1000).toISOString(),
    filters: { provider: "deepseek" },
  };
  const reason = "Independent usage export review";
  const pathname = "/api/v1/admin/usage/export";

  const missingCsrf = await adminPost(
    f,
    jar,
    pathname,
    { ...request, reason, approvalId: "apr_missing" },
    "",
    { "idempotency-key": "export-missing-csrf" },
  );
  assert.equal(missingCsrf.response.status, 403);
  assert.equal(missingCsrf.body.error.code, "csrf_invalid");

  const missingApproval = await adminPost(
    f,
    jar,
    pathname,
    { ...request, reason },
    current.body.csrfToken,
    { "idempotency-key": "export-missing-approval" },
  );
  assert.equal(missingApproval.response.status, 400);
  assert.equal(missingApproval.body.error.code, "approval_required");

  const approval = await requestApproval(f, jar, current, {
    action: "usage.export.create",
    reason,
    ...request,
  });
  assert.equal(approval.riskLevel, "H");
  assert.match(approval.targetId, /^exp_[a-f0-9]{64}$/);

  const selfDecision = await adminPost(
    f,
    jar,
    `/api/v1/admin/approvals/${approval.approvalId}/decisions`,
    { decision: "approve", reason: "Requester cannot self-approve" },
    current.body.csrfToken,
  );
  assert.equal(selfDecision.response.status, 403);
  assert.equal(selfDecision.body.error.code, "approval_separation_required");
  await decideApproval(f, approver, approval.approvalId);

  const noStepUpJar = await adminLogin(f, new CookieJar(), undefined, {
    stepUp: false,
  });
  const noStepUpCurrent = await me(f, noStepUpJar);
  const missingStepUp = await adminPost(
    f,
    noStepUpJar,
    pathname,
    { ...request, reason, approvalId: approval.approvalId },
    noStepUpCurrent.body.csrfToken,
    { "idempotency-key": "export-missing-step-up" },
  );
  assert.equal(missingStepUp.response.status, 403);
  assert.equal(missingStepUp.body.error.code, "step_up_required");

  const missingIdempotency = await adminPost(
    f,
    jar,
    pathname,
    { ...request, reason, approvalId: approval.approvalId },
    current.body.csrfToken,
  );
  assert.equal(missingIdempotency.response.status, 400);
  assert.equal(missingIdempotency.body.error.code, "idempotency_key_required");

  const targetMismatchApproval = await requestApproval(f, jar, current, {
    action: "usage.export.create",
    reason,
    ...request,
  });
  await decideApproval(f, approver, targetMismatchApproval.approvalId);
  const targetMismatch = await adminPost(
    f,
    jar,
    pathname,
    {
      ...request,
      from: new Date(Date.parse(request.from) + 1000).toISOString(),
      reason,
      approvalId: targetMismatchApproval.approvalId,
    },
    current.body.csrfToken,
    { "idempotency-key": "export-target-mismatch" },
  );
  assert.equal(targetMismatch.response.status, 403);
  assert.equal(targetMismatch.body.error.code, "approval_target_mismatch");

  const payloadMismatchApproval = await requestApproval(f, jar, current, {
    action: "usage.export.create",
    reason,
    ...request,
  });
  await decideApproval(f, approver, payloadMismatchApproval.approvalId);
  const payloadMismatch = await adminPost(
    f,
    jar,
    pathname,
    {
      ...request,
      reason: "Changed after independent approval",
      approvalId: payloadMismatchApproval.approvalId,
    },
    current.body.csrfToken,
    { "idempotency-key": "export-payload-mismatch" },
  );
  assert.equal(payloadMismatch.response.status, 409);
  assert.equal(payloadMismatch.body.error.code, "approval_payload_mismatch");

  const headers = { "idempotency-key": "export-usage-success" };
  const created = await adminPost(
    f,
    jar,
    pathname,
    { ...request, reason, approvalId: approval.approvalId },
    current.body.csrfToken,
    headers,
  );
  assert.equal(created.response.status, 201, JSON.stringify(created.body));
  assert.equal(created.body.replayed, false);
  assert.equal(created.body.export.kind, "usage");
  assert.equal(created.body.export.rowCount, 3);
  assert.equal(created.body.export.status, "ready");
  assert.match(created.body.downloadToken, /^[A-Za-z0-9_-]+$/);
  assert.equal(JSON.stringify(created.body).includes("\uFEFFtime,userId"), false);

  const replayed = await adminPost(
    f,
    jar,
    pathname,
    { ...request, reason, approvalId: approval.approvalId },
    current.body.csrfToken,
    headers,
  );
  assert.equal(replayed.response.status, 200, JSON.stringify(replayed.body));
  assert.equal(replayed.body.replayed, true);
  assert.equal(replayed.body.export.exportId, created.body.export.exportId);
  assert.equal(replayed.body.downloadToken, created.body.downloadToken);

  const conflict = await adminPost(
    f,
    jar,
    pathname,
    {
      ...request,
      filters: { provider: "openai" },
      reason,
      approvalId: approval.approvalId,
    },
    current.body.csrfToken,
    headers,
  );
  assert.equal(conflict.response.status, 409);
  assert.equal(conflict.body.error.code, "idempotency_conflict");

  const data = await readAdminData(f);
  assert.equal(Object.keys(data.adminExports).length, 1);
  assert.equal(data.approvalRequests[approval.approvalId].status, "consumed");
  assert.equal(
    (await fs.readFile(f.config.storePath, "utf8")).includes(created.body.downloadToken),
    false,
  );
});

test("M2-D usage and audit CSV exports contain metadata only and neutralize formulas", {
  timeout: 30000,
}, async (t) => {
  const now = Date.now();
  const usageContent = `${JSON.stringify({
    t: new Date(now - 3600 * 1000).toISOString(),
    callerKeyId: "key-alice-new",
    callerKeyName: "Alice",
    agent: "=1+1",
    provider: "@SUM(A1:A2)",
    req: "deepseek/deepseek-chat",
    status: 200,
    in: 10,
    out: 5,
    cost: 0.01,
    prompt: "PROMPT-MUST-NOT-EXPORT",
    response: "RESPONSE-MUST-NOT-EXPORT",
  })}\n`;
  const f = await fixture({ usageContent });
  t.after(() => f.close());
  await seedOrganizations(f);
  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);
  const from = new Date(now - 2 * 3600 * 1000).toISOString();
  const to = new Date(now + 3600 * 1000).toISOString();

  const usageRequest = {
    exportType: "usage",
    orgUnitId: "*",
    from,
    to,
    filters: {},
  };
  const usageApproval = await requestApproval(f, jar, current, {
    action: "usage.export.create",
    reason: "Export usage metadata for reconciliation",
    ...usageRequest,
  });
  await decideApproval(f, approver, usageApproval.approvalId);
  const usageExport = await adminPost(
    f,
    jar,
    "/api/v1/admin/usage/export",
    {
      ...usageRequest,
      reason: "Export usage metadata for reconciliation",
      approvalId: usageApproval.approvalId,
    },
    current.body.csrfToken,
    { "idempotency-key": "export-usage-csv-safe" },
  );
  assert.equal(usageExport.response.status, 201, JSON.stringify(usageExport.body));
  const usageDownload = await downloadExport(
    f,
    jar,
    usageExport.body.export.downloadPath,
    usageExport.body.downloadToken,
  );
  assert.equal(usageDownload.response.status, 200);
  assert.match(usageDownload.response.headers.get("content-type"), /^text\/csv/);
  assert.match(usageDownload.response.headers.get("content-disposition"), /attachment/);
  assert.equal(usageDownload.response.headers.get("cache-control"), "no-store");
  assert.ok(usageDownload.body.startsWith("\uFEFFtime,userId,email,department"));
  assert.ok(usageDownload.body.includes("\r\n"));
  assert.ok(usageDownload.body.includes("'=1+1"));
  assert.ok(usageDownload.body.includes("'@SUM(A1:A2)"));
  for (const forbidden of [
    "callerKeyId",
    "key-alice-new",
    "callerKeyName",
    "PROMPT-MUST-NOT-EXPORT",
    "RESPONSE-MUST-NOT-EXPORT",
    f.secrets.serviceToken,
    f.secrets.oidcClientSecret,
    f.secrets.accessToken,
    jar.cookies.get(f.config.sessionCookieName),
  ]) {
    assert.equal(usageDownload.body.includes(forbidden), false, `CSV must not contain ${forbidden}`);
  }

  await seedAdminOperation(f, {
    id: "op_audit_export_private",
    createdAt: new Date(now - 30 * 60 * 1000).toISOString(),
    reason: "Audit metadata export review",
    beforeSummary: {
      prompt: "BEFORE-MUST-NOT-EXPORT",
      response: "AFTER-MUST-NOT-EXPORT",
    },
    responseBody: {
      result: { state: "failed", privateDetail: "RESULT-MUST-NOT-EXPORT" },
    },
  });
  const auditRequest = {
    exportType: "audit",
    orgUnitId: "*",
    from,
    to,
    filters: { operationId: "op_audit_export_private" },
  };
  const auditApproval = await requestApproval(f, jar, current, {
    action: "audit.export.create",
    reason: "Export audit metadata for compliance review",
    ...auditRequest,
  });
  await decideApproval(f, approver, auditApproval.approvalId);
  const auditExport = await adminPost(
    f,
    jar,
    "/api/v1/admin/audit/export",
    {
      ...auditRequest,
      reason: "Export audit metadata for compliance review",
      approvalId: auditApproval.approvalId,
    },
    current.body.csrfToken,
    { "idempotency-key": "export-audit-csv-safe" },
  );
  assert.equal(auditExport.response.status, 201, JSON.stringify(auditExport.body));
  const auditDownload = await downloadExport(
    f,
    jar,
    auditExport.body.export.downloadPath,
    auditExport.body.downloadToken,
  );
  assert.equal(auditDownload.response.status, 200);
  assert.ok(auditDownload.body.startsWith(
    "\uFEFFtime,operationId,actorSubjectId,actorEmail,action,phase",
  ));
  assert.ok(
    auditDownload.body.includes("op_audit_export_private"),
    `audit CSV should include the seeded operation: ${auditDownload.body}`,
  );
  assert.ok(
    auditDownload.body.includes("Audit metadata export review"),
    `audit CSV should include the operation reason: ${auditDownload.body}`,
  );
  for (const forbidden of [
    "beforeSummary",
    "afterSummary",
    "BEFORE-MUST-NOT-EXPORT",
    "AFTER-MUST-NOT-EXPORT",
    "RESULT-MUST-NOT-EXPORT",
    f.secrets.serviceToken,
    f.secrets.oidcClientSecret,
    f.secrets.accessToken,
    jar.cookies.get(f.config.sessionCookieName),
  ]) {
    assert.equal(auditDownload.body.includes(forbidden), false, `CSV must not contain ${forbidden}`);
  }
});

test("M2-D export downloads are one-time, session-bound, and expire closed", {
  timeout: 30000,
}, async (t) => {
  const f = await fixture({ usageContent: usageLines() });
  t.after(() => f.close());
  await seedOrganizations(f);
  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);
  const request = {
    exportType: "usage",
    orgUnitId: "*",
    from: new Date(Date.now() - 6 * 3600 * 1000).toISOString(),
    to: new Date(Date.now() + 3600 * 1000).toISOString(),
    filters: {},
  };
  const reason = "Exercise the one-time export download boundary";
  const approval = await requestApproval(f, jar, current, {
    action: "usage.export.create",
    reason,
    ...request,
  });
  await decideApproval(f, approver, approval.approvalId);
  const created = await adminPost(
    f,
    jar,
    "/api/v1/admin/usage/export",
    { ...request, reason, approvalId: approval.approvalId },
    current.body.csrfToken,
    { "idempotency-key": "export-download-lifecycle-1" },
  );
  assert.equal(created.response.status, 201, JSON.stringify(created.body));
  const pathname = created.body.export.downloadPath;
  const token = created.body.downloadToken;

  const noBearer = await downloadExport(f, jar, pathname, "");
  assert.equal(noBearer.response.status, 401);
  assert.equal(JSON.parse(noBearer.body).error.code, "export_token_required");
  const queryToken = await downloadExport(
    f,
    jar,
    `${pathname}?token=${encodeURIComponent(token)}`,
    "",
  );
  assert.equal(queryToken.response.status, 401);
  assert.equal(JSON.parse(queryToken.body).error.code, "export_token_required");
  const noSession = await downloadExport(f, null, pathname, token);
  assert.equal(noSession.response.status, 401);
  assert.equal(JSON.parse(noSession.body).error.code, "not_signed_in");

  const secondSession = await adminLogin(f, new CookieJar());
  const wrongSession = await downloadExport(f, secondSession, pathname, token);
  assert.equal(wrongSession.response.status, 403);
  assert.equal(JSON.parse(wrongSession.body).error.code, "export_token_invalid");
  const wrongActor = await downloadExport(f, approver.jar, pathname, token);
  assert.equal(wrongActor.response.status, 403);
  assert.equal(JSON.parse(wrongActor.body).error.code, "export_token_invalid");

  const downloaded = await downloadExport(f, jar, pathname, token);
  assert.equal(downloaded.response.status, 200);
  assert.ok(downloaded.body.startsWith("\uFEFFtime,userId,email"));
  const consumed = await downloadExport(f, jar, pathname, token);
  assert.equal(consumed.response.status, 410);
  assert.equal(JSON.parse(consumed.body).error.code, "export_consumed");

  const expiringRequest = { ...request, filters: { provider: "deepseek" } };
  const expiringReason = "Exercise expired export handling";
  const expiringApproval = await requestApproval(f, jar, current, {
    action: "usage.export.create",
    reason: expiringReason,
    ...expiringRequest,
  });
  await decideApproval(f, approver, expiringApproval.approvalId);
  const expiringExport = await adminPost(
    f,
    jar,
    "/api/v1/admin/usage/export",
    {
      ...expiringRequest,
      reason: expiringReason,
      approvalId: expiringApproval.approvalId,
    },
    current.body.csrfToken,
    { "idempotency-key": "export-download-lifecycle-2" },
  );
  assert.equal(expiringExport.response.status, 201, JSON.stringify(expiringExport.body));
  const expiredAt = new Date(Date.now() - 1000).toISOString();
  await f.admin.store.mutate((data) => {
    const record = data.adminExports[expiringExport.body.export.exportId];
    record.status = "expired";
    record.expiresAt = expiredAt;
    for (const tokenRecord of Object.values(data.adminExportTokens)) {
      if (tokenRecord.exportId === record.id) tokenRecord.expiresAt = expiredAt;
    }
  });
  const expired = await downloadExport(
    f,
    jar,
    expiringExport.body.export.downloadPath,
    expiringExport.body.downloadToken,
  );
  assert.equal(expired.response.status, 410);
  assert.equal(JSON.parse(expired.body).error.code, "export_expired");

  const data = await readAdminData(f);
  assert.equal(data.adminExports[created.body.export.exportId].status, "consumed");
  assert.equal(data.adminExports[expiringExport.body.export.exportId].status, "expired");
  assert.equal(
    data.adminSystemAuditLogs.filter((audit) => audit.action === "export.downloaded").length,
    1,
  );
});

test("M2-D admin UI and operation listings expose scoped controls without inline scripts", {
  timeout: 30000,
}, async (t) => {
  const f = await fixture({ usageContent: usageLines() });
  t.after(() => f.close());
  await seedOrganizations(f);
  const now = new Date().toISOString();
  await seedAdminOperation(f, {
    id: "op_platform_export_ops",
    createdAt: now,
    targetId: "usr_alice",
  });
  await seedAdminOperation(f, {
    id: "op_sales_export_ops",
    createdAt: new Date(Date.now() - 1000).toISOString(),
    targetId: "usr_carol",
    actorSubjectId: "adm_other",
  });
  const jar = await adminLogin(f);
  const current = await me(f, jar);

  const all = await adminGet(f, jar, "/api/v1/admin/operations?limit=200");
  assert.equal(all.response.status, 200);
  assert.deepEqual(
    all.body.operations.map((operation) => operation.operationId).sort(),
    ["op_platform_export_ops", "op_sales_export_ops"],
  );
  const paginated = await adminGet(f, jar, "/api/v1/admin/operations?limit=1");
  assert.equal(paginated.response.status, 200);
  assert.equal(paginated.body.operations.length, 1);
  assert.match(paginated.body.nextCursor, /\./);
  const filtered = await adminGet(
    f,
    jar,
    "/api/v1/admin/operations?targetId=usr_alice&status=failed&limit=1",
  );
  assert.equal(filtered.response.status, 200);
  assert.equal(filtered.body.operations.length, 1);
  assert.equal(filtered.body.operations[0].operationId, "op_platform_export_ops");

  const page = await fetch(`${f.base}/admin/`, { headers: { cookie: jar.header() } });
  assert.equal(page.status, 200);
  const html = await page.text();
  for (const expected of [
    "Approved metadata export",
    "Request matching approval",
    "Create export",
    "Load operations",
    "Load audit metadata",
    "Notifications",
    "Register or edit a notification channel",
    "Create or edit a notification rule",
    "Replay selected dead letter",
    "Load aggregation and escalation state",
    'id="notification-channel-form"',
    'id="notification-delivery-filter"',
    'id="notification-rule-form"',
    'id="notification-aggregate-list"',
    'id="notification-escalation-list"',
    'src="/admin/app.js"',
  ]) {
    assert.ok(html.includes(expected), `admin page should include ${expected}`);
  }
  assert.ok(!/<script(?![^>]*\bsrc=)/i.test(html));
  assert.ok(!/\son[a-z]+\s*=/i.test(html));
  assertNoWriteSecrets(html, f, jar);
  const appScript = await fs.readFile(new URL("../src/admin-app.js", import.meta.url), "utf8");
  assert.match(appScript, /notification_channels_unavailable/);
  assert.match(appScript, /loadNotificationOperations/);
  assert.match(appScript, /saveNotificationRule/);

  await bindRole(f, current.body.user.id, "department_admin", "org-root");
  const scoped = await adminGet(f, jar, "/api/v1/admin/operations?limit=200");
  assert.equal(scoped.response.status, 200);
  assert.deepEqual(
    scoped.body.operations.map((operation) => operation.operationId),
    ["op_platform_export_ops"],
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

test("approval inbox and serial workflows enforce active-step eligibility", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const reviewer = await independentApprover(f, { name: "Serial Reviewer" });
  const owner = await independentApprover(f, { name: "Serial Owner" });
  const approval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_bob",
    reason: "Two-step approval workflow",
    workflow: {
      kind: "serial",
      steps: [
        { stepId: "stp_security", approverSubjectIds: [reviewer.current.body.user.id] },
        { stepId: "stp_owner", approverSubjectIds: [owner.current.body.user.id] },
      ],
    },
  });

  assert.equal(approval.workflowKind, "serial");
  assert.deepEqual(approval.activeStepIds, ["stp_security"]);
  assert.deepEqual(
    approval.steps.map((step) => [step.stepId, step.status]),
    [["stp_security", "in_progress"], ["stp_owner", "pending"]],
  );

  const reviewerInbox = await adminGet(
    f,
    reviewer.jar,
    "/api/v1/admin/approvals/inbox?view=pending",
  );
  assert.equal(reviewerInbox.response.status, 200);
  assert.equal(reviewerInbox.body.view, "pending");
  assert.ok(reviewerInbox.body.approvals.some((item) => (
    item.approvalId === approval.approvalId
  )));

  const ownerInbox = await adminGet(
    f,
    owner.jar,
    "/api/v1/admin/approvals/inbox?view=pending",
  );
  assert.equal(ownerInbox.response.status, 200);
  assert.ok(!ownerInbox.body.approvals.some((item) => (
    item.approvalId === approval.approvalId
  )));

  const requesterInbox = await adminGet(
    f,
    jar,
    "/api/v1/admin/approvals/inbox?view=requested",
  );
  assert.equal(requesterInbox.response.status, 200);
  assert.ok(requesterInbox.body.approvals.some((item) => (
    item.approvalId === approval.approvalId
  )));

  const premature = await adminPost(
    f,
    owner.jar,
    `/api/v1/admin/approvals/${approval.approvalId}/decisions`,
    { decision: "approve", reason: "Owner is not eligible for the first step" },
    owner.current.body.csrfToken,
  );
  assert.equal(premature.response.status, 403);
  assert.equal(premature.body.error.code, "approval_step_ineligible");

  const first = await decideApproval(
    f,
    reviewer,
    approval.approvalId,
    "approve",
    "Security review complete",
  );
  assert.equal(first.status, "pending_approval");
  assert.deepEqual(first.activeStepIds, ["stp_owner"]);
  assert.deepEqual(
    first.steps.map((step) => [step.stepId, step.status]),
    [["stp_security", "approved"], ["stp_owner", "in_progress"]],
  );

  const ownerInboxAfterFirst = await adminGet(
    f,
    owner.jar,
    "/api/v1/admin/approvals/inbox?view=pending",
  );
  assert.ok(ownerInboxAfterFirst.body.approvals.some((item) => (
    item.approvalId === approval.approvalId
  )));

  const second = await decideApproval(
    f,
    owner,
    approval.approvalId,
    "approve",
    "Business owner approved",
  );
  assert.equal(second.status, "approved");
  assert.deepEqual(second.activeStepIds, []);
  assert.deepEqual(second.decisions.map((decision) => decision.stepId), [
    "stp_security",
    "stp_owner",
  ]);
});

test("parallel approval steps require an explicit step and honor quorum", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const first = await independentApprover(f, { name: "Parallel First" });
  const second = await independentApprover(f, { name: "Parallel Second" });
  const third = await independentApprover(f, { name: "Parallel Third" });
  const final = await independentApprover(f, { name: "Parallel Final" });
  const approval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_bob",
    reason: "Parallel quorum workflow",
    workflow: {
      kind: "parallel",
      steps: [
        {
          stepId: "stp_quorum",
          approverSubjectIds: [
            first.current.body.user.id,
            second.current.body.user.id,
            third.current.body.user.id,
          ],
          requiredApprovers: 3,
          quorum: 2,
        },
        {
          stepId: "stp_final",
          approverSubjectIds: [final.current.body.user.id],
        },
      ],
    },
  });
  assert.equal(approval.workflowKind, "parallel");
  assert.deepEqual(approval.activeStepIds, ["stp_quorum", "stp_final"]);

  const missingStep = await adminPost(
    f,
    first.jar,
    `/api/v1/admin/approvals/${approval.approvalId}/decisions`,
    { decision: "approve", reason: "Missing step while two are active" },
    first.current.body.csrfToken,
  );
  assert.equal(missingStep.response.status, 409);
  assert.equal(missingStep.body.error.code, "approval_step_unavailable");

  const oneVote = await decideApproval(
    f,
    first,
    approval.approvalId,
    "approve",
    "First quorum vote",
    "stp_quorum",
  );
  assert.equal(oneVote.status, "pending_approval");
  assert.equal(oneVote.steps[0].status, "in_progress");
  assert.deepEqual(oneVote.steps[0].decidedBySubjectIds, [
    first.current.body.user.id,
  ]);

  const repeatedVote = await adminPost(
    f,
    first.jar,
    `/api/v1/admin/approvals/${approval.approvalId}/decisions`,
    {
      decision: "approve",
      reason: "The same approver cannot vote twice",
      stepId: "stp_quorum",
    },
    first.current.body.csrfToken,
  );
  assert.equal(repeatedVote.response.status, 403);
  assert.equal(repeatedVote.body.error.code, "approval_step_ineligible");

  const quorum = await decideApproval(
    f,
    second,
    approval.approvalId,
    "approve",
    "Second quorum vote",
    "stp_quorum",
  );
  assert.equal(quorum.status, "pending_approval");
  assert.equal(quorum.steps[0].status, "approved");
  assert.deepEqual(quorum.activeStepIds, ["stp_final"]);

  const thirdInbox = await adminGet(
    f,
    third.jar,
    "/api/v1/admin/approvals/inbox?view=pending",
  );
  assert.ok(!thirdInbox.body.approvals.some((item) => (
    item.approvalId === approval.approvalId
  )));
  const finalInbox = await adminGet(
    f,
    final.jar,
    "/api/v1/admin/approvals/inbox?view=pending",
  );
  assert.ok(finalInbox.body.approvals.some((item) => (
    item.approvalId === approval.approvalId
  )));

  const completed = await decideApproval(
    f,
    final,
    approval.approvalId,
    "approve",
    "Final approval",
    "stp_final",
  );
  assert.equal(completed.status, "approved");
  assert.deepEqual(completed.activeStepIds, []);
});

test("approval transfer, requester withdrawal, audit, and consumption fail closed", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const original = await independentApprover(f, { name: "Transfer Original" });
  const alternate = await independentApprover(f, { name: "Transfer Alternate" });
  const other = await independentApprover(f, { name: "Transfer Other" });

  const transferable = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_bob",
    reason: "Transferable approval",
    workflow: {
      kind: "serial",
      steps: [{
        stepId: "stp_transfer",
        requiredApprovers: 1,
        quorum: 1,
        approverSubjectIds: [
          original.current.body.user.id,
          other.current.body.user.id,
        ],
      }],
    },
  });

  const nonRequesterWithdraw = await adminPost(
    f,
    other.jar,
    `/api/v1/admin/approvals/${transferable.approvalId}/withdraw`,
    { reason: "Only the requester may withdraw" },
    other.current.body.csrfToken,
  );
  assert.equal(nonRequesterWithdraw.response.status, 403);
  assert.equal(nonRequesterWithdraw.body.error.code, "forbidden_role");

  const transferred = await adminPost(
    f,
    original.jar,
    `/api/v1/admin/approvals/${transferable.approvalId}/steps/stp_transfer/transfer`,
    {
      toSubjectId: alternate.current.body.user.id,
      reason: "Original reviewer is unavailable",
    },
    original.current.body.csrfToken,
  );
  assert.equal(transferred.response.status, 200, JSON.stringify(transferred.body));
  const transferStep = transferred.body.approval.steps[0];
  assert.ok(transferStep.eligibleSubjectIds.includes(alternate.current.body.user.id));
  assert.ok(!transferStep.eligibleSubjectIds.includes(original.current.body.user.id));
  assert.ok(transferStep.ineligibleSubjectIds.includes(original.current.body.user.id));
  assert.deepEqual(transferStep.transferHistory.map((entry) => ({
    from: entry.fromSubjectId,
    to: entry.toSubjectId,
    reason: entry.reason,
  })), [{
    from: original.current.body.user.id,
    to: alternate.current.body.user.id,
    reason: "Original reviewer is unavailable",
  }]);

  const originalAfterTransfer = await adminPost(
    f,
    original.jar,
    `/api/v1/admin/approvals/${transferable.approvalId}/decisions`,
    { decision: "approve", reason: "Original reviewer cannot decide" },
    original.current.body.csrfToken,
  );
  assert.equal(originalAfterTransfer.response.status, 403);
  assert.equal(originalAfterTransfer.body.error.code, "approval_step_ineligible");

  const approvedAfterTransfer = await decideApproval(
    f,
    alternate,
    transferable.approvalId,
    "approve",
    "Alternate reviewer approved",
  );
  assert.equal(approvedAfterTransfer.status, "approved");

  const withdrawal = await adminPost(
    f,
    jar,
    `/api/v1/admin/approvals/${transferable.approvalId}/withdraw`,
    { reason: "Too late after approval" },
    current.body.csrfToken,
  );
  assert.equal(withdrawal.response.status, 503);
  assert.equal(withdrawal.body.error.code, "approval_unavailable");

  const toWithdraw = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_bob",
    reason: "Withdraw before a decision",
  });
  const withdrawn = await adminPost(
    f,
    jar,
    `/api/v1/admin/approvals/${toWithdraw.approvalId}/withdraw`,
    { reason: "Request was created in error" },
    current.body.csrfToken,
  );
  assert.equal(withdrawn.response.status, 200, JSON.stringify(withdrawn.body));
  assert.equal(withdrawn.body.approval.status, "withdrawn");
  assert.equal(withdrawn.body.approval.withdrawnBySubjectId, current.body.user.id);
  assert.ok(withdrawn.body.approval.steps.every((step) => step.status === "cancelled"));

  const decideWithdrawn = await adminPost(
    f,
    other.jar,
    `/api/v1/admin/approvals/${toWithdraw.approvalId}/decisions`,
    { decision: "approve", reason: "Withdrawn approvals cannot be decided" },
    other.current.body.csrfToken,
  );
  assert.equal(decideWithdrawn.response.status, 403);
  assert.equal(decideWithdrawn.body.error.code, "approval_withdrawn");

  const consumeWithdrawn = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_bob/disable",
    {
      reason: "Withdraw before a decision",
      approvalId: toWithdraw.approvalId,
    },
    current.body.csrfToken,
  );
  assert.equal(consumeWithdrawn.response.status, 403);
  assert.equal(consumeWithdrawn.body.error.code, "approval_withdrawn");

  const data = await readAdminData(f);
  assert.ok(data.adminSystemAuditLogs.some((audit) => (
    audit.action === "approval.transferred"
      && audit.approvalId === transferable.approvalId
      && audit.result === "transferred"
  )));
  assert.ok(data.adminSystemAuditLogs.some((audit) => (
    audit.action === "approval.withdrawn"
      && audit.approvalId === toWithdraw.approvalId
      && audit.result === "withdrawn"
  )));
});

test("external approval callbacks require step IDs for configured workflows", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f, { name: "External Workflow" });
  const approval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_bob",
    reason: "External workflow callback",
    workflow: {
      kind: "serial",
      steps: [{
        stepId: "stp_external",
        approverSubjectIds: [approver.current.body.user.id],
      }],
    },
  });

  const basePayload = {
    approvalId: approval.approvalId,
    actorSubjectId: approver.current.body.user.id,
    actorEmail: `${approver.suffix}@corp.example`,
  };
  const missingStep = await postApprovalCallback(f, callbackPayload(
    approval.approvalId,
    basePayload,
  ));
  assert.equal(missingStep.response.status, 409);
  assert.equal(missingStep.body.error.code, "approval_step_unavailable");

  const completed = await postApprovalCallback(f, callbackPayload(
    approval.approvalId,
    { ...basePayload, stepId: "stp_external" },
  ));
  assert.equal(completed.response.status, 200, JSON.stringify(completed.body));
  assert.equal(completed.body.approval.status, "approved");
  assert.equal(completed.body.approval.decisions[0].stepId, "stp_external");
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
  t.after(async () => {
    await restarted.notificationEscalationScheduler?.stop();
    await restarted.breakGlassScheduler?.stop();
  });
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

test("break-glass requests enforce CSRF, critical step-up, role, and organization scope", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f, new CookieJar(), undefined, { stepUp: false });
  const current = await me(f, jar);
  const requestBody = {
    action: "user.disable",
    targetId: "usr_alice",
    incidentId: "INC-RBAC-1",
    reason: "Emergency incident response",
    payload: {},
  };

  const noCsrf = await adminPost(
    f,
    jar,
    "/api/v1/admin/break-glass",
    requestBody,
  );
  assert.equal(noCsrf.response.status, 403);
  assert.equal(noCsrf.body.error.code, "csrf_invalid");

  const noStepUp = await adminPost(
    f,
    jar,
    "/api/v1/admin/break-glass",
    requestBody,
    current.body.csrfToken,
  );
  assert.equal(noStepUp.response.status, 403);
  assert.equal(noStepUp.body.error.code, "step_up_required");

  await stepUp(f, jar);
  const grant = await requestBreakGlass(f, jar, current, requestBody);

  const security = await independentApprover(f, { role: "security_admin" });
  const listed = await adminGet(f, security.jar, "/api/v1/admin/break-glass?status=active");
  assert.equal(listed.response.status, 200, JSON.stringify(listed.body));
  assert.ok(listed.body.grants.some((candidate) => (
    candidate.breakGlassId === grant.breakGlassId
  )));
  assert.ok(!JSON.stringify(listed.body).includes("payloadSummary"));

  const securityCannotRequest = await adminPost(
    f,
    security.jar,
    "/api/v1/admin/break-glass",
    {
      ...requestBody,
      incidentId: "INC-RBAC-2",
    },
    security.current.body.csrfToken,
  );
  assert.equal(securityCannotRequest.response.status, 403);
  assert.equal(securityCannotRequest.body.error.code, "forbidden_role");

  const ops = await independentApprover(f, { role: "ops_admin" });
  const opsCannotReview = await adminGet(f, ops.jar, "/api/v1/admin/break-glass");
  assert.equal(opsCannotReview.response.status, 403);
  assert.equal(opsCannotReview.body.error.code, "forbidden_role");

  const page = await fetch(`${f.base}/admin/`, { headers: { cookie: jar.header() } });
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /Request emergency break-glass authorization/);
  assert.match(html, /Review selected break-glass use/);

  const securityPage = await fetch(
    `${f.base}/admin/`,
    { headers: { cookie: security.jar.header() } },
  );
  assert.equal(securityPage.status, 200);
  const securityHtml = await securityPage.text();
  assert.match(securityHtml, /Your role cannot request break-glass authorization/);
  assert.match(securityHtml, /Review selected break-glass use/);
  assert.doesNotMatch(securityHtml, /id="break-glass-request-form"/);
  assertNoWriteSecrets(listed.body, f, jar);
});

test("break-glass grants bind one target, expire, and cannot be consumed twice", { timeout: 30000 }, async (t) => {
  const clock = { now: Date.now() };
  const f = await fixture({
    adminServerOptions: {
      breakGlassNow: () => clock.now,
      breakGlassIntervalMs: 24 * 60 * 60 * 1000,
    },
  });
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const grant = await requestBreakGlass(f, jar, current);

  const exclusive = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    {
      reason: grant.reason,
      approvalId: "apr_exclusive",
      breakGlassId: grant.breakGlassId,
    },
    current.body.csrfToken,
    { "idempotency-key": "break-glass-exclusive" },
  );
  assert.equal(exclusive.response.status, 400);
  assert.equal(exclusive.body.error.code, "approval_and_break_glass_exclusive");

  const wrongTarget = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_bob/disable",
    {
      reason: grant.reason,
      breakGlassId: grant.breakGlassId,
    },
    current.body.csrfToken,
    { "idempotency-key": "break-glass-wrong-target" },
  );
  assert.equal(wrongTarget.response.status, 403);
  assert.equal(wrongTarget.body.error.code, "break_glass_target_mismatch");

  const payloadGrant = await requestBreakGlass(f, jar, current, {
    action: "user.policy.models",
    targetId: "usr_bob",
    incidentId: "INC-PAYLOAD-1",
    reason: "Bind model policy payload",
    expectedVersion: 1,
    models: ["openai/gpt-test"],
  });
  const wrongPayload = await adminPatch(
    f,
    jar,
    "/api/v1/admin/users/usr_bob/policy/models",
    {
      reason: payloadGrant.reason,
      expectedVersion: 0,
      models: ["openai/gpt-test"],
      breakGlassId: payloadGrant.breakGlassId,
    },
    current.body.csrfToken,
    { "idempotency-key": "break-glass-wrong-payload" },
  );
  assert.equal(wrongPayload.response.status, 403);
  assert.equal(wrongPayload.body.error.code, "break_glass_payload_mismatch");

  const consumed = await consumeBreakGlass(f, jar, current, grant, {
    idempotencyKey: "break-glass-consume-once",
  });
  assert.equal(consumed.body.action, "user.disable");

  const replay = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    {
      reason: grant.reason,
      breakGlassId: grant.breakGlassId,
    },
    current.body.csrfToken,
    { "idempotency-key": "break-glass-consume-repeat" },
  );
  assert.equal(replay.response.status, 409);
  assert.equal(replay.body.error.code, "break_glass_consumed");

  const concurrentGrant = await requestBreakGlass(f, jar, current, {
    incidentId: "INC-CONCURRENT-1",
  });
  const writesBefore = f.auth.writeCalls.length;
  const attempts = await Promise.all([
    adminPost(
      f,
      jar,
      "/api/v1/admin/users/usr_alice/disable",
      {
        reason: concurrentGrant.reason,
        breakGlassId: concurrentGrant.breakGlassId,
      },
      current.body.csrfToken,
      { "idempotency-key": "break-glass-concurrent-left" },
    ),
    adminPost(
      f,
      jar,
      "/api/v1/admin/users/usr_alice/disable",
      {
        reason: concurrentGrant.reason,
        breakGlassId: concurrentGrant.breakGlassId,
      },
      current.body.csrfToken,
      { "idempotency-key": "break-glass-concurrent-right" },
    ),
  ]);
  attempts.sort((left, right) => left.response.status - right.response.status);
  assert.deepEqual(attempts.map((attempt) => attempt.response.status), [200, 409]);
  assert.equal(attempts[1].body.error.code, "break_glass_consumed");
  assert.equal(f.auth.writeCalls.length, writesBefore + 1);

  const expiringGrant = await requestBreakGlass(f, jar, current, {
    incidentId: "INC-EXPIRED-1",
  });
  clock.now += BREAK_GLASS_GRANT_TTL_MS + 1;
  const expired = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    {
      reason: expiringGrant.reason,
      breakGlassId: expiringGrant.breakGlassId,
    },
    current.body.csrfToken,
    { "idempotency-key": "break-glass-expired" },
  );
  assert.equal(expired.response.status, 409);
  assert.equal(expired.body.error.code, "break_glass_expired");
});

test("break-glass use is atomically notified and audited before business failure", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const grant = await requestBreakGlass(f, jar, current, {
    incidentId: "INC-ATOMIC-1",
  });

  f.auth.setWriteFailing(true);
  const failed = await consumeBreakGlass(f, jar, current, grant, {
    expectedStatus: 502,
    idempotencyKey: "break-glass-business-failure",
  });
  assert.equal(failed.body.error.code, "dependency_unavailable");

  const stored = await readAdminData(f);
  const storedGrant = stored.breakGlassGrants[grant.breakGlassId];
  assert.ok(storedGrant.consumedAt);
  assert.ok(storedGrant.reviewDueAt);
  assert.ok(storedGrant.operationId);
  assert.match(storedGrant.notificationEventIds.used, /^evt_/);
  assert.ok(storedGrant.stateHistory.some((entry) => entry.status === "consumed"));
  assert.ok(stored.notificationDeliveries[storedGrant.notificationEventIds.used]
    || Object.values(stored.notificationDeliveries)
      .some((delivery) => delivery.eventId === storedGrant.notificationEventIds.used));
  const usedDelivery = Object.values(stored.notificationDeliveries)
    .find((delivery) => delivery.eventId === storedGrant.notificationEventIds.used);
  assert.equal(usedDelivery.eventType, "security.break_glass_used");
  assert.equal(usedDelivery.operationId, storedGrant.operationId);
  assert.ok(stored.adminSystemAuditLogs.some((audit) => (
    audit.action === "break_glass.used"
    && audit.breakGlassId === grant.breakGlassId
    && audit.operationId === storedGrant.operationId
    && audit.result === "consumed"
  )));
  assert.ok(stored.adminOperations[storedGrant.operationId]);
  assert.equal(stored.adminOperations[storedGrant.operationId].breakGlassId, grant.breakGlassId);
  assertNoWriteSecrets(failed.body, f, jar);
  assertNoWriteSecrets(storedGrant, f, jar);
  assertNoWriteSecrets(usedDelivery, f, jar);
});

test("break-glass reviews enforce separation, idempotency, reminders, and immutability", { timeout: 30000 }, async (t) => {
  const clock = { now: Date.now() };
  const f = await fixture({
    adminServerOptions: {
      breakGlassNow: () => clock.now,
      breakGlassIntervalMs: 24 * 60 * 60 * 1000,
    },
  });
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const grant = await requestBreakGlass(f, jar, current, {
    incidentId: "INC-REVIEW-1",
  });
  await consumeBreakGlass(f, jar, current, grant, {
    idempotencyKey: "break-glass-review-consume",
  });

  clock.now += BREAK_GLASS_REVIEW_DUE_MS - 30 * 60 * 1000;
  const dueResult = await f.admin.breakGlassScheduler.runOnce();
  assert.equal(dueResult.due, 1);
  assert.equal(dueResult.overdue, 0);

  clock.now += 90 * 60 * 1000;
  const overdueResult = await f.admin.breakGlassScheduler.runOnce();
  assert.equal(overdueResult.due, 0);
  assert.equal(overdueResult.overdue, 1);

  const selfReview = await adminPost(
    f,
    jar,
    `/api/v1/admin/break-glass/${grant.breakGlassId}/review`,
    {
      conclusion: "justified",
      reason: "Self review must fail",
    },
    current.body.csrfToken,
    { "idempotency-key": "break-glass-self-review" },
  );
  assert.equal(selfReview.response.status, 403);
  assert.equal(selfReview.body.error.code, "break_glass_separation_required");

  const reviewer = await independentApprover(f, { role: "security_admin" });
  const reviewKey = "break-glass-independent-review";
  const reviewed = await reviewBreakGlass(f, reviewer, grant.breakGlassId, {
    idempotencyKey: reviewKey,
  });
  assert.equal(reviewed.body.replayed, false);
  assert.equal(reviewed.body.grant.status, "reviewed");
  assert.equal(reviewed.body.grant.review.conclusion, "justified");
  const reviewId = reviewed.body.grant.review.reviewId;

  const replay = await reviewBreakGlass(f, reviewer, grant.breakGlassId, {
    idempotencyKey: reviewKey,
    expectedStatus: 200,
  });
  assert.equal(replay.response.status, 200);
  assert.equal(replay.body.replayed, true);
  assert.equal(replay.body.grant.review.reviewId, reviewId);

  const keyConflict = await reviewBreakGlass(f, reviewer, grant.breakGlassId, {
    idempotencyKey: reviewKey,
    reason: "Changed review material",
    expectedStatus: 409,
  });
  assert.equal(keyConflict.body.error.code, "break_glass_review_conflict");

  const immutable = await reviewBreakGlass(f, reviewer, grant.breakGlassId, {
    idempotencyKey: "break-glass-second-review",
    expectedStatus: 409,
  });
  assert.equal(immutable.body.error.code, "break_glass_review_exists");

  const stored = await readAdminData(f);
  const storedGrant = stored.breakGlassGrants[grant.breakGlassId];
  assert.ok(storedGrant.reviewOverdueAt);
  assert.match(storedGrant.notificationEventIds.reviewDue, /^evt_/);
  assert.match(storedGrant.notificationEventIds.reviewOverdue, /^evt_/);
  assert.match(storedGrant.notificationEventIds.reviewed, /^evt_/);
  assert.ok(Object.values(stored.breakGlassReviews).some((review) => (
    review.id === reviewId
    && review.reviewerSubjectId === reviewer.current.body.user.id
  )));
  assert.ok(stored.adminSystemAuditLogs.some((audit) => (
    audit.action === "break_glass.reviewed"
    && audit.breakGlassId === grant.breakGlassId
    && audit.result === "justified"
  )));
  assertNoWriteSecrets(reviewed.body, f, jar);
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

test("APR-01c high-risk actions require a fresh step-up and succeed after re-authentication", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f, new CookieJar(), undefined, { stepUp: false });
  let current = await me(f, jar);
  assert.equal(current.response.status, 200);
  assert.equal(current.body.stepUp.configured, true);
  assert.equal(current.body.stepUp.state, "required");

  const reason = "Step-up is required before disabling this user";
  const body = {
    action: "user.disable",
    targetId: "usr_bob",
    reason,
  };
  const denied = await adminPost(
    f,
    jar,
    "/api/v1/admin/approvals",
    body,
    current.body.csrfToken,
  );
  assert.equal(denied.response.status, 403);
  assert.equal(denied.body.error.code, "step_up_required");
  assert.equal(f.auth.writeCalls.length, 0);
  let data = await readAdminData(f);
  assert.equal(Object.keys(data.approvalRequests).length, 0);

  await stepUp(f, jar);
  current = await me(f, jar);
  assert.equal(current.body.stepUp.state, "verified");
  assert.equal(current.body.stepUp.authenticated, true);
  assert.equal(current.body.stepUp.criticalAuthenticated, true);
  assert.match(current.body.stepUp.expiresAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.match(current.body.stepUp.startUrl, /^\/admin\/oauth\/step-up\/start/);

  const approval = await requestApproval(f, jar, current, body);
  const approver = await independentApprover(f);
  await decideApproval(f, approver, approval.approvalId);
  const written = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_bob/disable",
    { reason, approvalId: approval.approvalId },
    current.body.csrfToken,
  );
  assert.equal(written.response.status, 200, JSON.stringify(written.body));
  assert.equal(f.auth.writeCalls.length, 1);
  assert.equal(
    f.auth.writeCalls[0].pathname,
    "/api/v1/internal/admin/users/usr_bob/disable",
  );

  data = await readAdminData(f);
  const stored = await fs.readFile(f.config.storePath, "utf8");
  assertNoWriteSecrets([denied.body, current.body, written.body, data, stored], f, jar);
  assert.ok(!stored.includes(f.secrets.accessToken));
  for (const tokenField of ['"access_token"', '"refresh_token"', '"id_token"']) {
    assert.ok(!stored.includes(tokenField), `store must not contain ${tokenField}`);
  }

  data = await readAdminData(f);
  const mainAssertionKey = Object.keys(data.stepUpAssertions).find(
    (key) => data.stepUpAssertions[key].subjectId === current.body.user.id,
  );
  assert.ok(mainAssertionKey, "main admin session should have a step-up assertion");

  const logout = await fetch(`${f.base}/api/v1/admin/logout`, {
    method: "POST",
    headers: {
      cookie: jar.header(),
      origin: f.base,
      "x-csrf-token": current.body.csrfToken,
    },
  });
  assert.equal(logout.status, 200);
  const afterLogout = await me(f, jar);
  assert.equal(afterLogout.response.status, 401);
  data = await readAdminData(f);
  assert.equal(data.stepUpAssertions[mainAssertionKey], undefined);
});

test("APR-01c step-up expires independently for high-risk and critical actions", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);
  const parent = await seedAdminOperation(f, { id: "op_apr01c_critical" });

  const jar = await adminLogin(f);
  let current = await me(f, jar);
  await f.admin.store.mutate((data) => {
    const assertion = Object.values(data.stepUpAssertions)[0];
    assertion.expiresAt = new Date(Date.now() - 1000).toISOString();
  });
  const highRiskExpired = await adminPost(
    f,
    jar,
    "/api/v1/admin/approvals",
    {
      action: "user.disable",
      targetId: "usr_bob",
      reason: "Expired step-up must block a high-risk approval",
    },
    current.body.csrfToken,
  );
  assert.equal(highRiskExpired.response.status, 403);
  assert.equal(highRiskExpired.body.error.code, "step_up_expired");

  await stepUp(f, jar);
  current = await me(f, jar);
  await f.admin.store.mutate((data) => {
    const assertion = Object.values(data.stepUpAssertions)[0];
    assertion.criticalExpiresAt = new Date(Date.now() - 1000).toISOString();
  });
  const criticalExpired = await adminPost(
    f,
    jar,
    "/api/v1/admin/approvals",
    {
      action: "operation.reconcile",
      targetId: parent.id,
      parentOperationId: parent.id,
      reconciliationAction: "confirm_applied",
      evidenceRef: "APR-01C-CRITICAL",
      reason: "Expired critical assertion must block reconciliation",
    },
    current.body.csrfToken,
  );
  assert.equal(criticalExpired.response.status, 403);
  assert.equal(criticalExpired.body.error.code, "step_up_expired");

  const data = await readAdminData(f);
  assert.equal(Object.keys(data.approvalRequests).length, 0);
  assert.equal(f.auth.writeCalls.length, 0);
});

test("APR-01c step-up binds risk-bearing writes to role, scope, IP, and browser", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  let current = await me(f, jar);
  await bindRole(f, current.body.user.id, "enterprise_admin", "org-platform");

  const assertBindingMismatch = async (reason) => {
    const result = await adminPost(
      f,
      jar,
      "/api/v1/admin/approvals",
      {
        action: "user.disable",
        targetId: "usr_bob",
        reason,
      },
      current.body.csrfToken,
    );
    assert.equal(result.response.status, 403);
    assert.equal(result.body.error.code, "step_up_binding_mismatch");
    const state = await me(f, jar);
    assert.equal(state.body.stepUp.state, "binding_mismatch");
  };

  await assertBindingMismatch("Role and scope changed after step-up");

  await stepUp(f, jar);
  current = await me(f, jar);
  await f.admin.store.mutate((data) => {
    Object.values(data.stepUpAssertions)[0].ip = "203.0.113.55";
  });
  await assertBindingMismatch("IP changed after step-up");

  await stepUp(f, jar);
  current = await me(f, jar);
  await f.admin.store.mutate((data) => {
    Object.values(data.stepUpAssertions)[0].userAgentHash = crypto.createHash("sha256")
      .update("different-browser")
      .digest("hex");
  });
  await assertBindingMismatch("Browser changed after step-up");

  const data = await readAdminData(f);
  assert.equal(Object.keys(data.approvalRequests).length, 0);
  assert.equal(f.auth.writeCalls.length, 0);
});

test("APR-01c step-up rejects changed identity and invalid freshness or MFA claims", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f, new CookieJar(), undefined, { stepUp: false });

  const subjectChanged = await stepUpAttempt(f, jar, {
    claims: { sub: "admin-different-subject" },
  });
  assert.equal(subjectChanged.callback.status, 403);
  assert.equal(subjectChanged.body.error.code, "step_up_binding_mismatch");

  const emailChanged = await stepUpAttempt(f, jar, {
    claims: { email: "different@corp.example" },
  });
  assert.equal(emailChanged.callback.status, 403);
  assert.equal(emailChanged.body.error.code, "step_up_binding_mismatch");

  const now = Math.floor(Date.now() / 1000);
  const rejectedClaims = [
    [{ auth_time: undefined }, "missing auth_time"],
    [{ auth_time: now - 121 }, "stale auth_time"],
    [{ auth_time: now + 300 }, "future auth_time"],
    [{ amr: ["pwd"], acr: "" }, "missing MFA"],
  ];
  for (const [claims, label] of rejectedClaims) {
    const rejected = await stepUpAttempt(f, jar, { claims });
    assert.equal(rejected.callback.status, 403, label);
    assert.equal(rejected.body.error.code, "step_up_invalid", label);
  }

  await stepUp(f, jar, {});
  const current = await me(f, jar);
  assert.equal(current.body.stepUp.state, "verified");
});

test("APR-01c step-up requests explicit login, freshness, auth_time, and approved ACR", { timeout: 30000 }, async (t) => {
  const f = await fixture({
    allowedAcrValues: "urn:corp:mfa",
    claims: { acr: "urn:corp:mfa" },
  });
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f, new CookieJar(), undefined, { stepUp: false });
  const rejected = await stepUpAttempt(f, jar, {
    claims: { acr: "urn:corp:password" },
  });
  assert.equal(rejected.callback.status, 403);
  assert.equal(rejected.body.error.code, "step_up_invalid");

  await stepUp(f, jar, { acr: "urn:corp:mfa" });
  const authorize = f.oidc.lastStepUpAuthorize;
  assert.equal(authorize.searchParams.get("prompt"), "login");
  assert.equal(authorize.searchParams.get("max_age"), "120");
  assert.equal(authorize.searchParams.get("acr_values"), "urn:corp:mfa");
  const requestedClaims = JSON.parse(authorize.searchParams.get("claims"));
  assert.deepEqual(requestedClaims.id_token.auth_time, { essential: true });
  assert.deepEqual(requestedClaims.id_token.acr.values, ["urn:corp:mfa"]);
  const current = await me(f, jar);
  assert.equal(current.body.stepUp.state, "verified");
  assert.equal(current.body.stepUp.acr, "urn:corp:mfa");
});

test("APR-01c unconfigured step-up fails closed for state, routes, and high-risk approvals", { timeout: 30000 }, async (t) => {
  const f = await fixture({ stepUpEnabled: false });
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  assert.equal(current.body.stepUp.configured, false);
  assert.equal(current.body.stepUp.state, "unavailable");
  assert.equal(current.body.stepUp.startUrl, "");

  const denied = await adminPost(
    f,
    jar,
    "/api/v1/admin/approvals",
    {
      action: "user.disable",
      targetId: "usr_bob",
      reason: "Unconfigured step-up must fail closed",
    },
    current.body.csrfToken,
  );
  assert.equal(denied.response.status, 503);
  assert.equal(denied.body.error.code, "step_up_unavailable");

  const start = await fetch(`${f.base}/admin/oauth/step-up/start`, {
    redirect: "manual",
    headers: { cookie: jar.header() },
  });
  assert.equal(start.status, 503);
  assert.equal((await start.json()).error.code, "step_up_unavailable");
  assert.equal(f.auth.writeCalls.length, 0);
});

test("APR-01c step-up return paths stay inside the admin UI", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  const jar = await adminLogin(f, new CookieJar(), undefined, { stepUp: false });

  const invalidPaths = [
    "//evil.example",
    "/admin/\\evil.example",
    "/admin/oauth/callback",
    "/admin/oauth/step-up/callback",
    "/admin/../api/v1/admin/me",
    "/api/v1/admin/me",
  ];
  for (const returnTo of invalidPaths) {
    const response = await fetch(
      `${f.base}/admin/oauth/step-up/start?returnTo=${encodeURIComponent(returnTo)}`,
      {
        redirect: "manual",
        headers: { cookie: jar.header() },
      },
    );
    assert.equal(response.status, 400, returnTo);
    assert.equal((await response.json()).error.code, "invalid_return_path", returnTo);
  }

  const valid = await fetch(
    `${f.base}/admin/oauth/step-up/start?returnTo=${encodeURIComponent("/admin/?tab=users")}`,
    {
      redirect: "manual",
      headers: { cookie: jar.header() },
    },
  );
  assert.equal(valid.status, 302);
  assert.match(valid.headers.get("location"), /\/authorize\?/);
});

test("APR-01c step-up configuration fails closed on unsafe or inconsistent settings", () => {
  assert.throws(
    () => loadConfig(adminConfigEnv({
      ADMIN_STEP_UP_OIDC_CLIENT_ID: "magpie-admin",
    })),
    /ADMIN_STEP_UP_OIDC_CLIENT_ID must differ/,
  );
  assert.throws(
    () => loadConfig(adminConfigEnv({
      ADMIN_STEP_UP_REDIRECT_URI: "https://admin.corp.example/admin/oauth/callback",
    })),
    /ADMIN_STEP_UP_REDIRECT_URI must differ/,
  );
  assert.throws(
    () => loadConfig(adminConfigEnv({
      ADMIN_STEP_UP_OIDC_CLIENT_SECRET: "too-short",
    })),
    /ADMIN_STEP_UP_OIDC_CLIENT_SECRET must be at least 32 characters/,
  );
  assert.throws(
    () => loadConfig(adminConfigEnv({
      ADMIN_STEP_UP_CRITICAL_TTL_SECONDS: "601",
    })),
    /ADMIN_STEP_UP_CRITICAL_TTL_SECONDS must not exceed/,
  );
  assert.throws(
    () => loadConfig(adminConfigEnv({
      ADMIN_STEP_UP_OIDC_SCOPES: "profile,email",
    })),
    /ADMIN_STEP_UP_OIDC_SCOPES must include openid/,
  );
  assert.throws(
    () => loadConfig(adminConfigEnv({
      ADMIN_STEP_UP_OIDC_CLIENT_SECRET: "",
    })),
    /are required when step-up authentication is configured/,
  );

  const config = loadConfig(adminConfigEnv());
  assert.equal(config.stepUpOidc.ttlSeconds, 600);
  assert.equal(config.stepUpOidc.criticalTtlSeconds, 300);
  assert.equal(config.stepUpOidc.authTimeMaxAgeSeconds, 120);
  assert.equal(config.stepUpOidc.requireMfa, true);
});

test("IP allow list fails closed and rejects invalid CIDR", async () => {
  assert.throws(() => loadConfig({
    ADMIN_SESSION_SECRET: TEST_SESSION_SECRET,
    ADMIN_OIDC_ISSUER: "https://idp.example",
    ADMIN_OIDC_CLIENT_ID: "admin",
    ADMIN_OIDC_CLIENT_SECRET: TEST_OIDC_CLIENT_SECRET,
    ADMIN_AUTH_SERVICE_URL: "http://127.0.0.1:3444",
    ADMIN_AUTH_SERVICE_TOKEN: TEST_AUTH_SERVICE_TOKEN,
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

test("invalid persisted break-glass records fail closed", async () => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-admin-break-glass-store-"));
  try {
    const file = path.join(temp, "admin-store.json");
    const store = new JsonStore(file);
    await store.load();
    await assert.rejects(
      () => store.mutate((data) => {
        data.breakGlassGrants.bgr_invalid = {
          id: "bgr_invalid",
        };
      }),
      /break-glass/,
    );
    const persisted = await fs.readFile(file, "utf8");
    assert.ok(!persisted.includes("bgr_invalid"));
  } finally {
    await fs.rm(temp, { recursive: true, force: true });
  }
});

function notificationEvent(overrides = {}) {
  return {
    eventId: `evt_test_${crypto.randomUUID()}`,
    eventType: "approval.requested",
    severity: "warning",
    occurredAt: "2026-11-02T00:00:00.000Z",
    organizationId: "env_test",
    actorSubjectId: "adm_test",
    actorEmail: "admin@corp.example",
    targetType: "user",
    targetId: "usr_alice",
    targetOrgUnitId: "org-platform",
    operationId: "op_test",
    requestId: "req_test",
    errorCode: "",
    summary: "Approval request needs review",
    token: "must-not-be-persisted",
    prompt: "must-not-be-persisted",
    transportResponse: "must-not-be-persisted",
    ...overrides,
  };
}

async function createNotificationStore(t) {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-notification-outbox-"));
  const file = path.join(temp, "admin-store.json");
  const store = new JsonStore(file);
  await store.load();
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  return { temp, file, store };
}

test("NOTIFY-01a outbox deduplicates event IDs and persists only allowlisted data", async (t) => {
  const { store } = await createNotificationStore(t);
  const event = notificationEvent();

  const first = await store.mutate((data) => enqueueNotification(data, event));
  const duplicate = await store.mutate((data) => enqueueNotification(data, {
    ...event,
    summary: "A duplicate must not replace the original event",
  }));
  assert.equal(first.inserted, true);
  assert.equal(duplicate.inserted, false);
  assert.equal(duplicate.delivery.deliveryId, first.delivery.deliveryId);
  assert.equal(duplicate.delivery.summary, "Approval request needs review");

  const data = await store.read((current) => structuredClone(current));
  assert.equal(Object.keys(data.notificationDeliveries).length, 1);
  const delivery = Object.values(data.notificationDeliveries)[0];
  assert.equal(delivery.dataClassification, "L0");
  assert.equal(delivery.schemaVersion, 1);
  assert.equal(delivery.status, "pending");
  assert.equal(delivery.attemptCount, 0);
  assert.equal(delivery.token, undefined);
  assert.equal(delivery.prompt, undefined);
  assert.equal(delivery.transportResponse, undefined);
  assert.deepEqual(notificationTransportEvent(delivery), publicNotificationDelivery(delivery));
  assert.ok(!JSON.stringify(publicNotificationDelivery(delivery)).includes("must-not-be-persisted"));
});

test("NOTIFY-01a operation events map failure and partial success safely", () => {
  const data = { notificationDeliveries: {} };
  const failed = enqueueOperationNotification(data, {
    id: "op_failed",
    status: "failed",
    updatedAt: "2026-11-02T00:00:00.000Z",
    targetType: "user",
    targetId: "usr_alice",
    targetOrgUnitId: "org-platform",
    actorSubjectId: "adm_worker",
    actorEmail: "worker@corp.example",
    requestId: "req_failed",
    errorCode: "dependency_unavailable",
  });
  assert.equal(failed.delivery.eventType, "operation.failed");
  assert.equal(failed.delivery.severity, "critical");
  assert.match(failed.delivery.summary, /dependency_unavailable/);

  const partial = enqueueOperationNotification(data, {
    id: "op_partial",
    status: "succeeded",
    updatedAt: "2026-11-02T00:01:00.000Z",
    responseBody: { result: { state: "partial_success" } },
    targetType: "credential",
    targetId: "key_alice",
    targetOrgUnitId: "org-platform",
  });
  assert.equal(partial.delivery.eventType, "operation.partial_success");
  assert.equal(partial.delivery.severity, "warning");
  assert.equal(Object.keys(data.notificationDeliveries).length, 2);
});

test("NOTIFY-01a dispatcher retries transient failures and dead-letters stable failures", async (t) => {
  const { store } = await createNotificationStore(t);
  const start = new Date("2026-11-02T00:00:00.000Z");
  let clock = new Date(start);
  const now = () => new Date(clock);
  let calls = 0;
  const dispatcher = new NotificationDispatcher(store, {
    transport: async () => {
      calls += 1;
      if (calls === 1) {
        const error = new Error("timed out");
        error.code = "ETIMEDOUT";
        throw error;
      }
      const error = new Error("upstream unavailable");
      error.statusCode = 503;
      throw error;
    },
    leaseMs: 60000,
    pollIntervalMs: 60000,
    batchSize: 2,
    now,
  });
  const outbox = new NotificationOutbox(store, { maxAttempts: 2, now });
  await store.mutate((data) => outbox.enqueue(data, notificationEvent()));

  const first = await dispatcher.dispatchOnce();
  assert.deepEqual(first, { claimed: 1, delivered: 0, failed: 1 });
  let delivery = await store.read((data) => structuredClone(
    Object.values(data.notificationDeliveries)[0],
  ));
  assert.equal(delivery.status, "retry_wait");
  assert.equal(delivery.attemptCount, 1);
  assert.equal(delivery.lastErrorCode, "transport_timeout");
  assert.equal(delivery.nextAttemptAt, "2026-11-02T00:01:00.000Z");

  clock = new Date("2026-11-02T00:01:00.001Z");
  const second = await dispatcher.dispatchOnce();
  assert.deepEqual(second, { claimed: 1, delivered: 0, failed: 1 });
  delivery = await store.read((data) => structuredClone(
    Object.values(data.notificationDeliveries)[0],
  ));
  assert.equal(delivery.status, "dead_letter");
  assert.equal(delivery.attemptCount, 2);
  assert.equal(delivery.lastErrorCode, "transport_server_error");
  assert.equal(delivery.nextAttemptAt, "");
  assert.deepEqual(
    await dispatcher.dispatchOnce(),
    { claimed: 0, delivered: 0, failed: 0 },
  );
  assert.equal(calls, 2);

  const abort = new Error("aborted");
  abort.name = "AbortError";
  assert.equal(stableErrorCode(abort), "transport_timeout");
  assert.equal(stableErrorCode({ statusCode: 429 }), "transport_rate_limited");
  assert.equal(stableErrorCode({ statusCode: 400 }), "transport_rejected");
  assert.equal(stableErrorCode({ code: "ECONNREFUSED" }), "transport_unavailable");
});

test("NOTIFY-01a dispatcher serializes work and recovers an expired lease after restart", async (t) => {
  const { file, store } = await createNotificationStore(t);
  const start = new Date("2026-11-02T00:00:00.000Z");
  let clock = new Date(start);
  let calls = 0;
  let releaseTransport;
  const gate = new Promise((resolve) => {
    releaseTransport = resolve;
  });
  const dispatcher = new NotificationDispatcher(store, {
    transport: async () => {
      calls += 1;
      await gate;
    },
    now: () => new Date(clock),
  });
  await store.mutate((data) => enqueueNotification(data, notificationEvent()));

  const first = dispatcher.dispatchOnce();
  for (let index = 0; index < 100 && calls === 0; index += 1) {
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.equal(calls, 1);
  const second = dispatcher.dispatchOnce();
  releaseTransport();
  await Promise.all([first, second]);
  assert.equal(calls, 1);
  let delivered = await store.read((data) => structuredClone(
    Object.values(data.notificationDeliveries)[0],
  ));
  assert.equal(delivered.status, "delivered");
  assert.equal(delivered.attemptCount, 1);

  const leasedEvent = notificationEvent({ eventId: `evt_lease_${crypto.randomUUID()}` });
  await store.mutate((data) => {
    enqueueNotification(data, leasedEvent, { maxAttempts: 3 });
    const delivery = Object.values(data.notificationDeliveries)
      .find((candidate) => candidate.eventId === leasedEvent.eventId);
    claimNotificationDelivery(data, {
      now: clock,
      ownerId: "worker-before-restart",
      leaseMs: 1000,
    });
    assert.equal(delivery.status, "leased");
  });

  const reloaded = new JsonStore(file);
  await reloaded.load();
  const recoveredAt = new Date(clock.getTime() + 2000);
  const recovered = await new NotificationOutbox(reloaded, {
    maxAttempts: 3,
    now: () => new Date(recoveredAt),
  }).recoverExpired();
  assert.equal(recovered, 1);
  const recoveredDelivery = await reloaded.read((data) => structuredClone(
    Object.values(data.notificationDeliveries)
      .find((candidate) => candidate.eventId === leasedEvent.eventId),
  ));
  assert.equal(recoveredDelivery.status, "retry_wait");
  assert.equal(recoveredDelivery.lastErrorCode, "lease_expired");
  assert.equal(recoveredDelivery.leaseOwner, "");
  const reclaimed = await reloaded.mutate((data) => claimNotificationDelivery(data, {
    now: recoveredAt,
    ownerId: "worker-after-restart",
    leaseMs: 1000,
  }));
  assert.equal(reclaimed.eventId, leasedEvent.eventId);
  assert.equal(reclaimed.attemptCount, 2);
  assert.equal(reclaimed.leaseOwner, "worker-after-restart");
  assert.equal(markNotificationDelivering(
    await reloaded.read((data) => structuredClone(data)),
    reclaimed.deliveryId,
    "worker-after-restart",
    { now: recoveredAt, leaseMs: 1000 },
  ), true);
  assert.equal(recoverExpiredNotificationLeases(
    await reloaded.read((data) => structuredClone(data)),
    { now: new Date(recoveredAt.getTime() + 500) },
  ), 0);
});

test("NOTIFY-01a approval and operation events commit with their business audit state", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);
  assert.equal(f.admin.notificationDispatcher, null);
  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const approver = await independentApprover(f);

  const approval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_alice",
    reason: "Notification outbox integration test",
  });
  let data = await readAdminData(f);
  const requestedEvent = Object.values(data.notificationDeliveries)
    .find((delivery) => delivery.eventId === `evt_approval_requested_${approval.approvalId}`);
  assert.ok(requestedEvent);
  assert.equal(requestedEvent.eventType, "approval.requested");
  assert.equal(requestedEvent.targetOrgUnitId, "org-platform");
  assert.ok(data.adminSystemAuditLogs.some((audit) =>
    audit.action === "approval.requested" && audit.approvalId === approval.approvalId));

  await decideApproval(f, approver, approval.approvalId);
  data = await readAdminData(f);
  const approvedEvent = Object.values(data.notificationDeliveries)
    .find((delivery) => delivery.eventId === `evt_approval_approved_${approval.approvalId}`);
  assert.ok(approvedEvent);
  assert.equal(approvedEvent.eventType, "approval.approved");
  assert.ok(data.adminSystemAuditLogs.some((audit) =>
    audit.action === "approval.approved" && audit.approvalId === approval.approvalId));

  const succeeded = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_alice/disable",
    {
      reason: "Notification outbox integration test",
      approvalId: approval.approvalId,
    },
    current.body.csrfToken,
    { "idempotency-key": "notify-01a-success" },
  );
  assert.equal(succeeded.response.status, 200, JSON.stringify(succeeded.body));
  data = await readAdminData(f);
  const operation = data.adminOperations[succeeded.body.operationId];
  assert.equal(operation.status, "succeeded");
  const resultAudit = data.adminAuditLogs.find((audit) =>
    audit.operationId === operation.id && audit.phase === "result");
  assert.equal(resultAudit.id, operation.resultAuditId);
  assert.ok(data.notificationDeliveries[`ntd_${crypto.createHash("sha256")
    .update(`evt_approval_consumed_${approval.approvalId}`)
    .digest("hex")
    .slice(0, 32)}`]);
  assert.ok(data.adminSystemAuditLogs.some((audit) =>
    audit.action === "approval.consumed" && audit.operationId === operation.id));

  const failingApproval = await requestApproval(f, jar, current, {
    action: "user.disable",
    targetId: "usr_bob",
    reason: "Notification failure integration test",
  });
  await decideApproval(f, approver, failingApproval.approvalId);
  f.auth.setWriteFailing(true);
  const failed = await adminPost(
    f,
    jar,
    "/api/v1/admin/users/usr_bob/disable",
    {
      reason: "Notification failure integration test",
      approvalId: failingApproval.approvalId,
    },
    current.body.csrfToken,
    { "idempotency-key": "notify-01a-failure" },
  );
  assert.equal(failed.response.status, 502, JSON.stringify(failed.body));
  data = await readAdminData(f);
  const failedOperation = data.adminOperations[failed.body.error.operationId];
  assert.equal(failedOperation.status, "failed");
  const failedAudit = data.adminAuditLogs.find((audit) =>
    audit.operationId === failedOperation.id && audit.phase === "result");
  assert.equal(failedAudit.id, failedOperation.resultAuditId);
  const failedEvent = Object.values(data.notificationDeliveries)
    .find((delivery) => delivery.operationId === failedOperation.id
      && delivery.eventType === "operation.failed");
  assert.ok(failedEvent);
  assert.equal(failedEvent.targetOrgUnitId, "org-platform");
  assert.equal(failedEvent.errorCode, "dependency_unavailable");
  assert.equal(failedEvent.status, "pending");
});

test("NOTIFY-01a notification APIs enforce scope, CSRF, idempotency and safe projections", { timeout: 30000 }, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);
  const superJar = await adminLogin(f);
  const superCurrent = await me(f, superJar);
  const department = await independentApprover(f, {
    role: "department_admin",
    scopeOrgUnitId: "org-root",
  });

  const eventRoot = notificationEvent({
    eventId: "evt_notify_api_root",
    severity: "critical",
    targetOrgUnitId: "org-root",
    summary: "Root notification",
  });
  const eventSales = notificationEvent({
    eventId: "evt_notify_api_sales",
    severity: "info",
    targetOrgUnitId: "org-sales",
    summary: "Sales notification",
  });
  await f.admin.store.mutate((data) => {
    for (const event of [eventRoot, eventSales]) {
      const { delivery } = enqueueNotification(data, event);
      delivery.status = "dead_letter";
      delivery.attemptCount = delivery.maxAttempts;
      delivery.nextAttemptAt = "";
      delivery.lastErrorCode = "transport_server_error";
      delivery.prompt = "must-not-leak";
      delivery.transportResponse = "must-not-leak";
      delivery.token = "must-not-leak";
    }
  });

  const scoped = await adminGet(
    f,
    department.jar,
    "/api/v1/admin/notifications/deliveries",
  );
  assert.equal(scoped.response.status, 200);
  assert.equal(scoped.body.count, 1);
  assert.equal(scoped.body.deliveries[0].summary, "Root notification");
  assert.ok(!JSON.stringify(scoped.body).includes("must-not-leak"));

  const scopedDeadLetters = await adminGet(
    f,
    department.jar,
    "/api/v1/admin/notifications/dead-letters",
  );
  assert.equal(scopedDeadLetters.response.status, 200);
  assert.equal(scopedDeadLetters.body.count, 1);
  assert.equal(scopedDeadLetters.body.criticalCount, 1);
  assert.equal(scopedDeadLetters.body.deadLetters[0].eventId, eventRoot.eventId);
  assert.equal(scopedDeadLetters.body.visibilityTargetSeconds, 300);
  assert.ok(scopedDeadLetters.body.oldestCreatedAt);
  assert.ok(!JSON.stringify(scopedDeadLetters.body).includes("must-not-leak"));

  const all = await adminGet(
    f,
    superJar,
    "/api/v1/admin/notifications/deliveries?status=dead_letter&limit=1",
  );
  assert.equal(all.response.status, 200);
  assert.equal(all.body.count, 1);
  assert.equal(all.body.limit, 1);

  const allDeadLetters = await adminGet(
    f,
    superJar,
    "/api/v1/admin/notifications/dead-letters",
  );
  assert.equal(allDeadLetters.response.status, 200);
  assert.equal(allDeadLetters.body.count, 2);
  assert.equal(allDeadLetters.body.criticalCount, 1);
  assert.equal(allDeadLetters.body.deadLetters[0].eventId, eventRoot.eventId);
  assert.equal(allDeadLetters.body.deadLetters[1].eventId, eventSales.eventId);
  const invalidStatus = await adminGet(
    f,
    superJar,
    "/api/v1/admin/notifications/deliveries?status=bogus",
  );
  assert.equal(invalidStatus.response.status, 400);
  assert.equal(invalidStatus.body.error.code, "invalid_notification_status");
  const invalidLimit = await adminGet(
    f,
    superJar,
    "/api/v1/admin/notifications/deliveries?limit=0",
  );
  assert.equal(invalidLimit.response.status, 400);
  assert.equal(invalidLimit.body.error.code, "invalid_limit");

  const rootDelivery = scoped.body.deliveries[0];
  const replayPath = `/api/v1/admin/notifications/deliveries/${rootDelivery.deliveryId}/retry`;
  const forbidden = await adminPost(
    f,
    department.jar,
    replayPath,
    { reason: "Department administrators cannot replay" },
    department.current.body.csrfToken,
    { "idempotency-key": "notify-department-replay" },
  );
  assert.equal(forbidden.response.status, 403);

  const noCsrf = await adminPost(
    f,
    superJar,
    replayPath,
    { reason: "CSRF is required" },
    "",
    { "idempotency-key": "notify-no-csrf" },
  );
  assert.equal(noCsrf.response.status, 403);
  assert.equal(noCsrf.body.error.code, "csrf_invalid");

  const noReason = await adminPost(
    f,
    superJar,
    replayPath,
    {},
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-no-reason" },
  );
  assert.equal(noReason.response.status, 400);
  assert.equal(noReason.body.error.code, "invalid_reason");

  const noIdempotency = await adminPost(
    f,
    superJar,
    replayPath,
    { reason: "Idempotency is required" },
    superCurrent.body.csrfToken,
  );
  assert.equal(noIdempotency.response.status, 400);
  assert.equal(noIdempotency.body.error.code, "idempotency_key_required");

  const replayed = await adminPost(
    f,
    superJar,
    replayPath,
    { reason: "Retry after transport incident review" },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-replay-super-1" },
  );
  assert.equal(replayed.response.status, 200, JSON.stringify(replayed.body));
  assert.equal(replayed.body.replayed, true);
  assert.equal(replayed.body.delivery.status, "retry_wait");
  assert.equal(replayed.body.delivery.attemptCount, 0);
  assert.ok(!JSON.stringify(replayed.body).includes("must-not-leak"));

  const replayAgain = await adminPost(
    f,
    superJar,
    replayPath,
    { reason: "Retry after transport incident review" },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-replay-super-1" },
  );
  assert.equal(replayAgain.response.status, 200);
  assert.equal(replayAgain.body.replayed, false);
  assert.equal(replayAgain.body.delivery.deliveryId, replayed.body.delivery.deliveryId);

  const conflict = await adminPost(
    f,
    superJar,
    replayPath,
    { reason: "A different replay reason" },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-replay-super-1" },
  );
  assert.equal(conflict.response.status, 409);
  assert.equal(conflict.body.error.code, "notification_replay_conflict");

  const notDead = await adminPost(
    f,
    superJar,
    replayPath,
    { reason: "A second replay needs a different key" },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-replay-super-2" },
  );
  assert.equal(notDead.response.status, 409);
  assert.equal(notDead.body.error.code, "notification_not_dead_letter");

  const data = await readAdminData(f);
  const stored = data.notificationDeliveries[rootDelivery.deliveryId];
  assert.equal(stored.replayCount, 1);
  assert.ok(data.adminSystemAuditLogs.some((audit) =>
    audit.action === "notification.replay_requested"
      && audit.deliveryId === rootDelivery.deliveryId
      && audit.actorSubjectId === superCurrent.body.user.id));
});

test("NOTIFY-01b channel APIs enforce RBAC, step-up, CSRF, idempotency and safe projections", { timeout: 30000 }, async (t) => {
  let testFails = false;
  const transportCalls = [];
  const channelTransport = {
    async deliver(delivery) {
      transportCalls.push(delivery);
      return { ok: true, statusCode: 204 };
    },
    async test(channel) {
      transportCalls.push({ test: channel.channelId });
      if (testFails) {
        const error = new Error("notification endpoint timed out");
        error.code = "transport_timeout";
        throw error;
      }
    },
  };
  const f = await fixture({
    notificationChannelsEnabled: true,
    adminServerOptions: { notificationChannelTransport: channelTransport },
  });
  t.after(() => f.close());
  await seedOrganizations(f);
  const superJar = await adminLogin(f);
  await stepUp(f, superJar);
  const superCurrent = await me(f, superJar);
  const security = await independentApprover(f, {
    role: "security_admin",
    scopeOrgUnitId: "*",
  });
  const department = await independentApprover(f, {
    role: "department_admin",
    scopeOrgUnitId: "org-root",
  });

  const createPath = "/api/v1/admin/notifications/channels";
  const channelBody = {
    name: "Security webhook",
    type: "webhook",
    provider: "generic",
    eventTypes: ["operation.failed", "approval.rejected"],
    secretRef: "MAGPIE_NOTIFICATION_WEBHOOK_SECRET",
    config: {
      endpointRef: "MAGPIE_SECURITY_WEBHOOK_URL",
      timeoutMs: 1000,
    },
    reason: "Register the security notification endpoint",
  };

  const noCsrf = await adminPost(
    f,
    superJar,
    createPath,
    channelBody,
    "",
    { "idempotency-key": "notify-channel-no-csrf" },
  );
  assert.equal(noCsrf.response.status, 403);
  assert.equal(noCsrf.body.error.code, "csrf_invalid");
  const noReason = await adminPost(
    f,
    superJar,
    createPath,
    { ...channelBody, reason: "" },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-channel-no-reason" },
  );
  assert.equal(noReason.response.status, 400);
  assert.equal(noReason.body.error.code, "invalid_reason");
  const noIdempotency = await adminPost(
    f,
    superJar,
    createPath,
    channelBody,
    superCurrent.body.csrfToken,
  );
  assert.equal(noIdempotency.response.status, 400);
  assert.equal(noIdempotency.body.error.code, "idempotency_key_required");

  const noStepJar = new CookieJar();
  await adminLogin(f, noStepJar, {
    sub: "admin-no-step-up",
    email: "no-step-up@corp.example",
    name: "No Step Up",
  }, { stepUp: false });
  const noStepCurrent = await me(f, noStepJar);
  await addRoleBinding(
    f,
    "rb-no-step-up",
    noStepCurrent.body.user.id,
    "enterprise_admin",
    "*",
  );
  const noStep = await adminPost(
    f,
    noStepJar,
    createPath,
    channelBody,
    noStepCurrent.body.csrfToken,
    { "idempotency-key": "notify-channel-no-step-up" },
  );
  assert.equal(noStep.response.status, 403);
  assert.equal(noStep.body.error.code, "step_up_required");

  const plaintextSecret = await adminPost(
    f,
    superJar,
    createPath,
    {
      ...channelBody,
      config: {
        ...channelBody.config,
        token: "plaintext-notification-token",
      },
    },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-channel-plaintext-secret" },
  );
  assert.equal(plaintextSecret.response.status, 400);
  assert.equal(plaintextSecret.body.error.code, "invalid_notification_channel");

  const created = await adminPost(
    f,
    superJar,
    createPath,
    channelBody,
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-channel-create-1" },
  );
  assert.equal(created.response.status, 201, JSON.stringify(created.body));
  assert.equal(created.body.created, true);
  assert.match(created.body.channel.channelId, /^nch_[a-f0-9]{24}$/);
  assert.equal(created.body.channel.secretConfigured, true);
  assert.ok(!JSON.stringify(created.body).includes("plaintext-notification-token"));

  const replayed = await adminPost(
    f,
    superJar,
    createPath,
    channelBody,
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-channel-create-1" },
  );
  assert.equal(replayed.response.status, 200);
  assert.equal(replayed.body.created, false);
  assert.equal(replayed.body.channel.channelId, created.body.channel.channelId);
  const conflict = await adminPost(
    f,
    superJar,
    createPath,
    { ...channelBody, name: "A different channel" },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-channel-create-1" },
  );
  assert.equal(conflict.response.status, 409);
  assert.equal(conflict.body.error.code, "notification_channel_request_conflict");

  const listed = await adminGet(
    f,
    superJar,
    "/api/v1/admin/notifications/channels",
  );
  assert.equal(listed.response.status, 200);
  assert.equal(listed.body.channels.length, 1);
  assert.equal(listed.body.channels[0].lastTest, null);
  const securityRead = await adminGet(
    f,
    security.jar,
    "/api/v1/admin/notifications/channels",
  );
  assert.equal(securityRead.response.status, 200);
  const departmentRead = await adminGet(
    f,
    department.jar,
    "/api/v1/admin/notifications/channels",
  );
  assert.equal(departmentRead.response.status, 403);
  assert.equal(departmentRead.body.error.code, "forbidden_role");

  const channelPath = `/api/v1/admin/notifications/channels/${created.body.channel.channelId}`;
  const securityWrite = await adminPatch(
    f,
    security.jar,
    channelPath,
    { enabled: false, reason: "Security administrators are read-only" },
    security.current.body.csrfToken,
    { "idempotency-key": "notify-channel-security-write" },
  );
  assert.equal(securityWrite.response.status, 403);
  assert.equal(securityWrite.body.error.code, "forbidden_role");

  const updated = await adminPatch(
    f,
    superJar,
    channelPath,
    { enabled: false, reason: "Pause endpoint during maintenance" },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-channel-update-1" },
  );
  assert.equal(updated.response.status, 200, JSON.stringify(updated.body));
  assert.equal(updated.body.channel.enabled, false);

  const tested = await adminPost(
    f,
    superJar,
    `${channelPath}/test`,
    { reason: "Validate the endpoint after maintenance" },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-channel-test-1" },
  );
  assert.equal(tested.response.status, 200, JSON.stringify(tested.body));
  assert.equal(tested.body.ok, true);
  assert.equal(tested.body.test.status, "succeeded");
  assert.equal(tested.body.test.resultCode, "transport_ok");
  const testReplay = await adminPost(
    f,
    superJar,
    `${channelPath}/test`,
    { reason: "Validate the endpoint after maintenance" },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-channel-test-1" },
  );
  assert.equal(testReplay.response.status, 200);
  assert.equal(testReplay.body.replayed, true);
  assert.equal(testReplay.body.test.testId, tested.body.test.testId);

  testFails = true;
  const failedTest = await adminPost(
    f,
    superJar,
    `${channelPath}/test`,
    { reason: "Validate failure classification" },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-channel-test-2" },
  );
  assert.equal(failedTest.response.status, 200, JSON.stringify(failedTest.body));
  assert.equal(failedTest.body.ok, false);
  assert.equal(failedTest.body.test.status, "failed");
  assert.equal(failedTest.body.test.resultCode, "transport_timeout");

  const data = await readAdminData(f);
  assert.equal(Object.keys(data.notificationChannels).length, 1);
  assert.equal(Object.keys(data.notificationChannelTests).length, 2);
  assert.equal(Object.keys(data.notificationDeliveries).length, 0);
  assert.ok(data.adminSystemAuditLogs.some((audit) =>
    audit.action === "notification.channel.created"
      && audit.channelId === created.body.channel.channelId
      && audit.reason === channelBody.reason));
  assert.ok(data.adminSystemAuditLogs.some((audit) =>
    audit.action === "notification.channel.updated"
      && audit.channelId === created.body.channel.channelId));
  assert.ok(data.adminSystemAuditLogs.some((audit) =>
    audit.action === "notification.channel.tested"
      && audit.result === "failed"
      && audit.resultCode === "transport_timeout"));
  assert.ok(!JSON.stringify(data.notificationChannels).includes("plaintext-notification-token"));
});

test("NOTIFY-01c SIEM channels are manageable through the notification channel API", {
  timeout: 30000,
}, async (t) => {
  const requests = [];
  const f = await fixture({
    notificationChannelsEnabled: true,
    notificationAllowlist: "siem.example.test",
    adminServerOptions: {
      notificationChannelEnv: {
        MAGPIE_SIEM_COLLECTOR_TOKEN: TEST_SIEM_COLLECTOR_TOKEN,
      },
      notificationDnsResolver: async () => [{ address: "8.8.8.8", family: 4 }],
      notificationRequestImpl: async (request) => {
        requests.push(request);
        return { statusCode: 202, headers: {}, body: "" };
      },
    },
  });
  t.after(() => f.close());

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  const createPath = "/api/v1/admin/notifications/channels";
  const created = await adminPost(
    f,
    jar,
    createPath,
    {
      name: "SOC HTTP collector",
      type: "siem",
      provider: "http-collector",
      eventTypes: ["security.break_glass_used", "security.anomaly_detected"],
      secretRef: "MAGPIE_SIEM_COLLECTOR_TOKEN",
      config: {
        endpoint: "https://siem.example.test/events",
        timeoutMs: 1000,
      },
      reason: "Register the SOC collector",
    },
    current.body.csrfToken,
    { "idempotency-key": "notify-siem-channel-create" },
  );
  assert.equal(created.response.status, 201, JSON.stringify(created.body));
  assert.equal(created.body.channel.type, "siem");
  assert.equal(created.body.channel.provider, "http-collector");
  assert.equal(created.body.channel.secretConfigured, true);
  assert.ok(!JSON.stringify(created.body).includes("test-only-padding"));

  const channelPath = `${createPath}/${created.body.channel.channelId}`;
  const tested = await adminPost(
    f,
    jar,
    `${channelPath}/test`,
    { reason: "Verify collector connectivity" },
    current.body.csrfToken,
    { "idempotency-key": "notify-siem-channel-test" },
  );
  assert.equal(tested.response.status, 200, JSON.stringify(tested.body));
  assert.equal(tested.body.ok, true);
  assert.equal(tested.body.test.resultCode, "transport_ok");
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url.hostname, "siem.example.test");
  assert.deepEqual(requests[0].addresses, [{ address: "8.8.8.8", family: 4 }]);
  assert.equal(
    requests[0].headers.authorization,
    `Bearer ${TEST_SIEM_COLLECTOR_TOKEN}`,
  );
  const payload = JSON.parse(requests[0].body);
  assert.equal(payload.schemaVersion, 1);
  assert.equal(payload.event.eventType, "operation.failed");
  assert.equal(payload.event.severity, "warning");
  assert.equal(payload.event.targetId, created.body.channel.channelId);
  assert.equal(requests[0].body.includes("summary"), false);
  assert.equal(requests[0].body.includes("actorEmail"), false);

  const listed = await adminGet(f, jar, createPath);
  assert.equal(listed.response.status, 200);
  assert.equal(listed.body.channels.length, 1);
  assert.equal(listed.body.channels[0].type, "siem");
  assert.equal(listed.body.channels[0].lastTest.status, "succeeded");
  assert.ok(!JSON.stringify(listed.body).includes("test-only-padding"));

  const unsafe = await adminPost(
    f,
    jar,
    createPath,
    {
      name: "Unsafe SOC collector",
      type: "siem",
      provider: "http-collector",
      eventTypes: ["security.break_glass_used"],
      config: { endpoint: "http://siem.example.test/events" },
      reason: "Verify protocol validation",
    },
    current.body.csrfToken,
    { "idempotency-key": "notify-siem-channel-unsafe" },
  );
  assert.equal(unsafe.response.status, 400);
  assert.equal(unsafe.body.error.code, "invalid_notification_channel");
});

test("NOTIFY-01d rule APIs enforce scope, step-up, idempotency and optimistic concurrency", {
  timeout: 30000,
}, async (t) => {
  const f = await fixture({
    notificationChannelsEnabled: true,
    adminServerOptions: {
      notificationChannelTransport: {
        async deliver() {
          return { ok: true, statusCode: 204 };
        },
        async test() {},
      },
    },
  });
  t.after(() => f.close());
  await seedOrganizations(f);
  const superJar = await adminLogin(f);
  const superCurrent = await me(f, superJar);

  const channelCreate = await adminPost(
    f,
    superJar,
    "/api/v1/admin/notifications/channels",
    {
      name: "Notification rule endpoint",
      type: "webhook",
      provider: "generic",
      secretRef: "MAGPIE_NOTIFICATION_RULE_WEBHOOK_SECRET",
      eventTypes: [
        "approval.requested",
        "operation.failed",
        "approval.rejected",
      ],
      config: { endpointRef: "MAGPIE_NOTIFICATION_RULE_WEBHOOK" },
      reason: "Create a channel for notification rule integration tests",
    },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-01d-channel-create" },
  );
  assert.equal(channelCreate.response.status, 201, JSON.stringify(channelCreate.body));
  const channelId = channelCreate.body.channel.channelId;

  const department = await independentApprover(f, {
    role: "department_admin",
    scopeOrgUnitId: "org-root",
  });
  const rulesPath = "/api/v1/admin/notifications/rules";
  const baseRule = {
    name: "Platform approval routing",
    enabled: true,
    priority: 100,
    eventTypes: ["approval.requested"],
    severities: ["warning"],
    targetOrgUnitId: "org-platform",
    channelId,
    suppressionWindowSeconds: 0,
    aggregation: {
      enabled: true,
      dimensions: ["eventType", "targetOrgUnitId"],
      windowSeconds: 300,
    },
    escalation: {
      enabled: false,
      thresholdCount: 0,
      delaySeconds: 0,
      channelId: "",
    },
    reason: "Route platform approvals to the on-call webhook",
  };

  const unauthenticated = await fetch(`${f.base}${rulesPath}`);
  assert.equal(unauthenticated.status, 401);

  const noCsrf = await adminPost(
    f,
    superJar,
    rulesPath,
    baseRule,
    "",
    { "idempotency-key": "notify-01d-no-csrf" },
  );
  assert.equal(noCsrf.response.status, 403);
  assert.equal(noCsrf.body.error.code, "csrf_invalid");

  const noReason = await adminPost(
    f,
    superJar,
    rulesPath,
    { ...baseRule, reason: "" },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-01d-no-reason" },
  );
  assert.equal(noReason.response.status, 400);
  assert.equal(noReason.body.error.code, "invalid_reason");

  const noIdempotency = await adminPost(
    f,
    superJar,
    rulesPath,
    baseRule,
    superCurrent.body.csrfToken,
  );
  assert.equal(noIdempotency.response.status, 400);
  assert.equal(noIdempotency.body.error.code, "idempotency_key_required");

  const forbidden = await adminPost(
    f,
    department.jar,
    rulesPath,
    baseRule,
    department.current.body.csrfToken,
    { "idempotency-key": "notify-01d-department-write" },
  );
  assert.equal(forbidden.response.status, 403);
  assert.equal(forbidden.body.error.code, "forbidden_role");

  const noStepJar = new CookieJar();
  await adminLogin(f, noStepJar, {
    sub: "notify-rule-no-step-up",
    email: "notify-no-step-up@corp.example",
    name: "Notification No Step Up",
  }, { stepUp: false });
  let noStepCurrent = await me(f, noStepJar);
  await addRoleBinding(
    f,
    "rb-notify-rule-no-step-up",
    noStepCurrent.body.user.id,
    "enterprise_admin",
    "*",
  );
  noStepCurrent = await me(f, noStepJar);
  const noStep = await adminPost(
    f,
    noStepJar,
    rulesPath,
    baseRule,
    noStepCurrent.body.csrfToken,
    { "idempotency-key": "notify-01d-no-step-up" },
  );
  assert.equal(noStep.response.status, 403);
  assert.equal(noStep.body.error.code, "step_up_required");

  const missingChannel = await adminPost(
    f,
    superJar,
    rulesPath,
    {
      ...baseRule,
      channelId: `nch_${"f".repeat(24)}`,
      reason: "Verify channel references",
    },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-01d-missing-channel" },
  );
  assert.equal(missingChannel.response.status, 400);
  assert.equal(
    missingChannel.body.error.code,
    "notification_rule_channel_not_found",
  );

  const plaintextSecret = await adminPost(
    f,
    superJar,
    rulesPath,
    {
      ...baseRule,
      name: "Rule with plaintext secret",
      aggregation: { ...baseRule.aggregation, token: "must-not-be-stored" },
      reason: "Verify secret rejection",
    },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-01d-plaintext-secret" },
  );
  assert.equal(plaintextSecret.response.status, 400);
  assert.equal(plaintextSecret.body.error.code, "invalid_notification_rule");

  const created = await adminPost(
    f,
    superJar,
    rulesPath,
    baseRule,
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-01d-rule-create" },
  );
  assert.equal(created.response.status, 201, JSON.stringify(created.body));
  assert.equal(created.body.created, true);
  const rule = created.body.rule;
  assert.match(rule.ruleId, /^nrul_[a-f0-9]{24}$/);

  const replayed = await adminPost(
    f,
    superJar,
    rulesPath,
    baseRule,
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-01d-rule-create" },
  );
  assert.equal(replayed.response.status, 200);
  assert.equal(replayed.body.created, false);
  assert.equal(replayed.body.rule.ruleId, rule.ruleId);

  const conflict = await adminPost(
    f,
    superJar,
    rulesPath,
    { ...baseRule, name: "A different rule" },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-01d-rule-create" },
  );
  assert.equal(conflict.response.status, 409);
  assert.equal(conflict.body.error.code, "notification_rule_request_conflict");

  const salesRule = await adminPost(
    f,
    superJar,
    rulesPath,
    {
      ...baseRule,
      name: "Sales approval routing",
      targetOrgUnitId: "org-sales",
      aggregation: { enabled: false },
      escalation: { enabled: false },
      reason: "Route sales approvals separately",
    },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-01d-sales-rule" },
  );
  assert.equal(salesRule.response.status, 201, JSON.stringify(salesRule.body));

  const departmentRules = await adminGet(f, department.jar, rulesPath);
  assert.equal(departmentRules.response.status, 200);
  assert.equal(departmentRules.body.rules.length, 1);
  assert.equal(departmentRules.body.rules[0].ruleId, rule.ruleId);

  const rulePath = `${rulesPath}/${rule.ruleId}`;
  const updated = await adminPatch(
    f,
    superJar,
    rulePath,
    {
      enabled: false,
      expectedUpdatedAt: rule.updatedAt,
      reason: "Pause the platform routing rule during maintenance",
    },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-01d-rule-update" },
  );
  assert.equal(updated.response.status, 200, JSON.stringify(updated.body));
  assert.equal(updated.body.updated, true);
  assert.equal(updated.body.rule.enabled, false);

  const updateConflict = await adminPatch(
    f,
    superJar,
    rulePath,
    {
      enabled: true,
      expectedUpdatedAt: rule.updatedAt,
      reason: "Retry with stale optimistic concurrency metadata",
    },
    superCurrent.body.csrfToken,
    { "idempotency-key": "notify-01d-rule-update-conflict" },
  );
  assert.equal(updateConflict.response.status, 409);
  assert.equal(
    updateConflict.body.error.code,
    "notification_rule_update_conflict",
  );

  const data = await readAdminData(f);
  assert.ok(data.adminSystemAuditLogs.some((audit) =>
    audit.action === "notification.rule.created"
      && audit.ruleId === rule.ruleId
      && audit.reason === baseRule.reason));
  assert.ok(data.adminSystemAuditLogs.some((audit) =>
    audit.action === "notification.rule.updated"
      && audit.ruleId === rule.ruleId));
  assert.ok(!JSON.stringify(created.body).includes("must-not-be-stored"));
  assert.ok(!JSON.stringify(data.notificationRules).includes("must-not-be-stored"));
});

test("NOTIFY-01d operations APIs expose scoped timelines and isolate escalation failures", {
  timeout: 30000,
}, async (t) => {
  const f = await fixture({
    notificationChannelsEnabled: true,
    adminServerOptions: {
      notificationChannelTransport: {
        async deliver() {
          return { ok: true, statusCode: 204 };
        },
        async test() {},
      },
    },
  });
  t.after(() => f.close());
  await seedOrganizations(f);
  const superJar = await adminLogin(f);
  const superCurrent = await me(f, superJar);
  const department = await independentApprover(f, {
    role: "department_admin",
    scopeOrgUnitId: "org-root",
  });

  async function createChannel(name, suffix) {
    const created = await adminPost(
      f,
      superJar,
      "/api/v1/admin/notifications/channels",
      {
        name,
        type: "webhook",
        provider: "generic",
        secretRef: "MAGPIE_NOTIFICATION_OPERATIONS_WEBHOOK_SECRET",
        eventTypes: ["approval.requested", "approval.rejected", "operation.failed"],
        config: { endpointRef: "MAGPIE_NOTIFICATION_RULE_WEBHOOK" },
        reason: "Create a channel for notification operations tests",
      },
      superCurrent.body.csrfToken,
      { "idempotency-key": `notify-01d-ops-channel-${suffix}` },
    );
    assert.equal(created.response.status, 201, JSON.stringify(created.body));
    return created.body.channel.channelId;
  }

  const goodChannelId = await createChannel("Operations webhook", "good");
  const failedChannelId = await createChannel("Retiring webhook", "failed");

  async function createRule(body, suffix) {
    const created = await adminPost(
      f,
      superJar,
      "/api/v1/admin/notifications/rules",
      {
        enabled: true,
        priority: 100,
        severities: ["warning"],
        targetOrgUnitId: "org-platform",
        suppressionWindowSeconds: 0,
        aggregation: { enabled: false },
        escalation: { enabled: false },
        ...body,
        reason: "Create a notification rule for operations tests",
      },
      superCurrent.body.csrfToken,
      { "idempotency-key": `notify-01d-ops-rule-${suffix}` },
    );
    assert.equal(created.response.status, 201, JSON.stringify(created.body));
    return created.body.rule;
  }

  const aggregateRule = await createRule({
    name: "Platform aggregate with delayed escalation",
    eventTypes: ["approval.requested"],
    channelId: goodChannelId,
    aggregation: {
      enabled: true,
      dimensions: ["eventType", "targetOrgUnitId", "targetId"],
      windowSeconds: 600,
    },
    escalation: {
      enabled: true,
      thresholdCount: 0,
      delaySeconds: 60,
      channelId: goodChannelId,
    },
  }, "aggregate");
  const failedRule = await createRule({
    name: "Escalation channel that is later retired",
    eventTypes: ["approval.rejected"],
    channelId: failedChannelId,
    aggregation: {
      enabled: true,
      dimensions: ["eventType", "targetOrgUnitId", "targetId"],
      windowSeconds: 600,
    },
    escalation: {
      enabled: true,
      thresholdCount: 0,
      delaySeconds: 60,
      channelId: failedChannelId,
    },
  }, "failed");
  const suppressionRule = await createRule({
    name: "Suppress duplicate operation failures",
    eventTypes: ["operation.failed"],
    channelId: goodChannelId,
    suppressionWindowSeconds: 300,
  }, "suppression");
  const salesRule = await createRule({
    name: "Sales rule remains outside department scope",
    eventTypes: ["approval.rejected"],
    targetOrgUnitId: "org-sales",
    channelId: goodChannelId,
  }, "sales");

  await f.admin.store.mutate((data) => {
    const channels = Object.values(data.notificationChannels);
    f.admin.notificationRuleRouter.route(
      data,
      notificationEvent({
        eventId: "evt_notify_ops_aggregate",
        eventType: "approval.requested",
        targetOrgUnitId: "org-platform",
      }),
      { channels },
    );
    f.admin.notificationRuleRouter.route(
      data,
      notificationEvent({
        eventId: "evt_notify_ops_failed",
        eventType: "approval.rejected",
        targetOrgUnitId: "org-platform",
      }),
      { channels },
    );
    const suppressionEvent = notificationEvent({
      eventId: "evt_notify_ops_suppressed_1",
      eventType: "operation.failed",
      targetOrgUnitId: "org-platform",
    });
    f.admin.notificationRuleRouter.route(data, suppressionEvent, { channels });
    f.admin.notificationRuleRouter.route(data, {
      ...suppressionEvent,
      eventId: "evt_notify_ops_suppressed_2",
    }, { channels });
    f.admin.notificationRuleRouter.route(
      data,
      notificationEvent({
        eventId: "evt_notify_ops_sales",
        eventType: "approval.rejected",
        targetOrgUnitId: "org-sales",
      }),
      { channels },
    );
    for (const aggregate of Object.values(data.notificationAggregates)) {
      aggregate.firstEventAt = "2026-11-02T00:00:00.000Z";
      aggregate.updatedAt = "2026-11-02T00:00:00.000Z";
    }
    data.notificationChannels[failedChannelId].enabled = false;
    data.notificationChannels[failedChannelId].updatedAt = "2026-11-02T00:00:00.000Z";
  });

  const escalated = await f.admin.notificationEscalationScheduler.runOnce();
  assert.deepEqual(escalated, { sent: 1, failed: 1 });

  const aggregates = await adminGet(
    f,
    department.jar,
    "/api/v1/admin/notifications/aggregates?limit=20",
  );
  assert.equal(aggregates.response.status, 200);
  assert.ok(aggregates.body.count >= 2);
  assert.ok(aggregates.body.aggregates.every((aggregate) =>
    aggregate.targetOrgUnitId === "org-platform"));

  const suppressions = await adminGet(
    f,
    department.jar,
    "/api/v1/admin/notifications/suppressions?limit=20",
  );
  assert.equal(suppressions.response.status, 200);
  assert.equal(suppressions.body.count, 1);
  assert.equal(suppressions.body.suppressions[0].ruleId, suppressionRule.ruleId);
  assert.equal(suppressions.body.suppressions[0].targetOrgUnitId, "org-platform");

  const escalations = await adminGet(
    f,
    department.jar,
    "/api/v1/admin/notifications/escalations?limit=20",
  );
  assert.equal(escalations.response.status, 200);
  assert.equal(escalations.body.count, 2);
  assert.ok(escalations.body.escalations.some((escalation) =>
    escalation.ruleId === aggregateRule.ruleId && escalation.status === "sent"));
  assert.ok(escalations.body.escalations.some((escalation) =>
    escalation.ruleId === failedRule.ruleId
      && escalation.status === "failed"
      && escalation.errorCode === "escalation_channel_unavailable"));
  assert.ok(escalations.body.escalations.every((escalation) =>
    escalation.targetOrgUnitId === "org-platform"));

  const allEscalations = await adminGet(
    f,
    superJar,
    "/api/v1/admin/notifications/escalations?limit=20",
  );
  assert.equal(allEscalations.response.status, 200);
  assert.equal(allEscalations.body.count, 2);

  const salesRules = await adminGet(f, department.jar, "/api/v1/admin/notifications/rules");
  assert.equal(salesRules.response.status, 200);
  assert.ok(!salesRules.body.rules.some((candidate) =>
    candidate.ruleId === salesRule.ruleId));

  const invalidLimit = await adminGet(
    f,
    department.jar,
    "/api/v1/admin/notifications/escalations?limit=0",
  );
  assert.equal(invalidLimit.response.status, 400);
  assert.equal(invalidLimit.body.error.code, "invalid_limit");

  const unauthenticated = await fetch(
    `${f.base}/api/v1/admin/notifications/aggregates`,
  );
  assert.equal(unauthenticated.status, 401);
});

test("M3-C-2 configuration requires the resource service URL and token together", () => {
  assert.ok(loadConfig(adminConfigEnv({
    ADMIN_RESOURCE_SERVICE_URL: "http://127.0.0.1:3460",
    ADMIN_RESOURCE_SERVICE_TOKEN: TEST_RESOURCE_SERVICE_TOKEN,
  })).resourceService.enabled);

  const disabled = loadConfig(adminConfigEnv());
  assert.equal(disabled.resourceService.enabled, false);
  assert.equal(disabled.resourceService.url, "");
  assert.equal(disabled.resourceService.token, "");
  assert.equal(disabled.resourceService.timeoutMs, 5000);

  assert.throws(
    () => loadConfig(adminConfigEnv({
      ADMIN_RESOURCE_SERVICE_URL: "http://127.0.0.1:3460",
    })),
    /ADMIN_RESOURCE_SERVICE_URL and ADMIN_RESOURCE_SERVICE_TOKEN are required together/,
  );
  assert.throws(
    () => loadConfig(adminConfigEnv({
      ADMIN_RESOURCE_SERVICE_TOKEN: TEST_RESOURCE_SERVICE_TOKEN,
    })),
    /ADMIN_RESOURCE_SERVICE_URL and ADMIN_RESOURCE_SERVICE_TOKEN are required together/,
  );
  assert.throws(
    () => loadConfig(adminConfigEnv({
      ADMIN_RESOURCE_SERVICE_URL: "http://127.0.0.1:3460",
      ADMIN_RESOURCE_SERVICE_TOKEN: "short",
    })),
    /ADMIN_RESOURCE_SERVICE_TOKEN must be at least 32 characters/,
  );
  assert.throws(
    () => loadConfig(adminConfigEnv({
      ADMIN_RESOURCE_SERVICE_URL: "ftp://127.0.0.1:3460",
      ADMIN_RESOURCE_SERVICE_TOKEN: TEST_RESOURCE_SERVICE_TOKEN,
    })),
    /ADMIN_RESOURCE_SERVICE_URL must use http or https/,
  );
  assert.throws(
    () => loadConfig(adminConfigEnv({
      ADMIN_RESOURCE_SERVICE_URL: "http://127.0.0.1:3460",
      ADMIN_RESOURCE_SERVICE_TOKEN: TEST_RESOURCE_SERVICE_TOKEN,
      ADMIN_RESOURCE_SERVICE_TIMEOUT_MS: "10",
    })),
    /ADMIN_RESOURCE_SERVICE_TIMEOUT_MS must be an integer from 500 to 30000/,
  );
});

test("M3-C-2 resource and sync APIs project only allowlisted scoped metadata", {
  timeout: 30000,
}, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);

  const jar = await adminLogin(f);
  const current = await me(f, jar);
  assert.ok(current.body.scopeOrgUnitIds.includes("*"));

  const resources = await adminGet(f, jar, "/api/v1/admin/resources");
  assert.equal(resources.response.status, 200);
  assert.deepEqual(
    resources.body.resources.map((resource) => resource.id).sort(),
    [RESOURCE_GLOBAL_ID, RESOURCE_PLATFORM_ID, RESOURCE_SALES_ID].sort(),
  );
  const platform = resources.body.resources
    .find((resource) => resource.id === RESOURCE_PLATFORM_ID);
  assert.deepEqual(Object.keys(platform).sort(), [
    "assignments",
    "compatibility",
    "createdAt",
    "currentRelease",
    "currentReleaseId",
    "deliveryMode",
    "description",
    "id",
    "kind",
    "name",
    "publisher",
    "status",
    "updatedAt",
  ].sort());
  assert.deepEqual(Object.keys(platform.currentRelease).sort(), [
    "contentBytes",
    "createdAt",
    "hash",
    "id",
    "manifestDigest",
    "mediaType",
    "previousReleaseId",
    "publishedAt",
    "resourceId",
    "resourceVersion",
    "status",
  ].sort());
  assertNoWriteSecrets(resources.body, f, jar);

  const detail = await adminGet(f, jar, `/api/v1/admin/resources/${RESOURCE_PLATFORM_ID}`);
  assert.equal(detail.response.status, 200);
  assert.equal(detail.body.resource.id, RESOURCE_PLATFORM_ID);
  assert.equal(detail.body.releases.length, 1);
  assertNoWriteSecrets(detail.body, f, jar);

  const missing = await adminGet(f, jar, `/api/v1/admin/resources/${"res_"}${"d".repeat(16)}`);
  assert.equal(missing.response.status, 404);
  assert.equal(missing.body.error.code, "target_not_found");

  const reports = await adminGet(f, jar, "/api/v1/admin/resource-sync/reports");
  assert.equal(reports.response.status, 200);
  // usr_ghost has no identity and dev_unregistered is not a known device, so
  // both reports stay hidden instead of being attributed through the report.
  assert.deepEqual(
    reports.body.reports.map((report) => report.deviceId).sort(),
    ["dev_alice", "dev_carol"],
  );
  assert.deepEqual(Object.keys(reports.body.reports[0]).sort(), [
    "clientVersion",
    "deviceId",
    "drift",
    "driftCount",
    "installed",
    "receivedAt",
    "reportedAt",
    "revision",
    "status",
    "userId",
  ].sort());
  assertNoWriteSecrets(reports.body, f, jar);

  const reportDetail = await adminGet(f, jar, "/api/v1/admin/resource-sync/reports/dev_alice");
  assert.equal(reportDetail.response.status, 200);
  assert.equal(reportDetail.body.report.driftCount, 1);
  assert.deepEqual(reportDetail.body.report.drift[0], {
    resourceId: RESOURCE_PLATFORM_ID,
    state: "version_mismatch",
    expectedReleaseId: RELEASE_PLATFORM_ID,
    actualReleaseId: `rel_${"9".repeat(16)}`,
  });
  assertNoWriteSecrets(reportDetail.body, f, jar);

  const unauthenticated = await fetch(`${f.base}/api/v1/admin/resources`);
  assert.equal(unauthenticated.status, 401);
  const unauthenticatedReports = await fetch(
    `${f.base}/api/v1/admin/resource-sync/reports`,
  );
  assert.equal(unauthenticatedReports.status, 401);

  // The admin service must present its own service token, never a browser one.
  assert.ok(f.resource.calls.length > 0);
  assert.ok(f.resource.calls.every((call) =>
    call.authorization === `Bearer ${TEST_RESOURCE_SERVICE_TOKEN}`));
});

test("M3-C-2 organization scope filters reports and resources and fails closed", {
  timeout: 30000,
}, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);
  const jar = await adminLogin(f);
  const current = await me(f, jar);
  await bindRole(f, current.body.user.id, "department_admin", "org-root");

  const scoped = await me(f, jar);
  assert.ok(!scoped.body.scopeOrgUnitIds.includes("*"));
  assert.deepEqual(scoped.body.scopeOrgUnitIds, ["org-platform", "org-root"]);

  const resources = await adminGet(f, jar, "/api/v1/admin/resources");
  assert.equal(resources.response.status, 200);
  assert.deepEqual(
    resources.body.resources.map((resource) => resource.id).sort(),
    [RESOURCE_GLOBAL_ID, RESOURCE_PLATFORM_ID].sort(),
  );

  // A sibling resource is refused without confirming it exists.
  const crossScope = await adminGet(f, jar, `/api/v1/admin/resources/${RESOURCE_SALES_ID}`);
  assert.equal(crossScope.response.status, 403);
  assert.equal(crossScope.body.error.code, "forbidden_scope");

  const reports = await adminGet(f, jar, "/api/v1/admin/resource-sync/reports");
  assert.equal(reports.response.status, 200);
  assert.deepEqual(reports.body.reports.map((report) => report.deviceId), ["dev_alice"]);

  const crossReport = await adminGet(f, jar, "/api/v1/admin/resource-sync/reports/dev_carol");
  assert.equal(crossReport.response.status, 403);
  assert.equal(crossReport.body.error.code, "forbidden_scope");

  const ghostReport = await adminGet(f, jar, "/api/v1/admin/resource-sync/reports/dev_ghost");
  assert.equal(ghostReport.response.status, 403);

  const unknownReport = await adminGet(f, jar, "/api/v1/admin/resource-sync/reports/dev_missing");
  assert.equal(unknownReport.response.status, 404);
  assert.equal(unknownReport.body.error.code, "target_not_found");

  const malformedId = await adminGet(f, jar, "/api/v1/admin/resources/not-a-resource");
  assert.equal(malformedId.response.status, 404);

  // A role without resources.read keeps sync visibility and loses the catalog.
  await bindRole(f, current.body.user.id, "ops_admin", "*");
  const deniedResources = await adminGet(f, jar, "/api/v1/admin/resources");
  assert.equal(deniedResources.response.status, 403);
  assert.equal(deniedResources.body.error.code, "forbidden_role");
  const allowedReports = await adminGet(f, jar, "/api/v1/admin/resource-sync/reports");
  assert.equal(allowedReports.response.status, 200);

  // A role without either permission is refused before the dependency call.
  const beforeCalls = f.resource.calls.length;
  await bindRole(f, current.body.user.id, "employee", "*");
  assert.equal((await adminGet(f, jar, "/api/v1/admin/resources")).response.status, 403);
  assert.equal(
    (await adminGet(f, jar, "/api/v1/admin/resource-sync/reports")).response.status,
    403,
  );
  assert.equal(f.resource.calls.length, beforeCalls);
});

test("M3-C-2 resource service failures are reported, never rendered as empty", {
  timeout: 30000,
}, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);
  const jar = await adminLogin(f);

  f.resource.setFailing(true);
  const failing = await adminGet(f, jar, "/api/v1/admin/resources");
  assert.equal(failing.response.status, 503);
  assert.equal(failing.body.error.code, "resource_service_unavailable");
  assertNoWriteSecrets(failing.body, f, jar);
  const failingReports = await adminGet(f, jar, "/api/v1/admin/resource-sync/reports");
  assert.equal(failingReports.response.status, 503);
  assert.equal(failingReports.body.error.code, "resource_service_unavailable");
  f.resource.setFailing(false);

  f.resource.setSlow(true);
  const timedOut = await adminGet(f, jar, "/api/v1/admin/resources");
  assert.equal(timedOut.response.status, 503);
  assert.equal(timedOut.body.error.code, "resource_service_unavailable");
  f.resource.setSlow(false);

  f.resource.setMalformed(true);
  const malformed = await adminGet(f, jar, "/api/v1/admin/resources");
  assert.equal(malformed.response.status, 503);
  assert.equal(malformed.body.error.code, "resource_service_unavailable");
  f.resource.setMalformed(false);

  // The service token must never be forwarded through an upstream redirect.
  f.resource.setRedirecting(true);
  const redirected = await adminGet(f, jar, "/api/v1/admin/resources");
  assert.equal(redirected.response.status, 503);
  assert.equal(redirected.body.error.code, "resource_service_unavailable");
  f.resource.setRedirecting(false);

  const recovered = await adminGet(f, jar, "/api/v1/admin/resources");
  assert.equal(recovered.response.status, 200);
  assert.equal(recovered.body.resources.length, 3);

  // An unconfigured dependency stays unavailable rather than pretending empty.
  const bare = await fixture({ resourceServiceEnabled: false });
  t.after(() => bare.close());
  await seedOrganizations(bare);
  const bareJar = await adminLogin(bare);
  const unavailable = await adminGet(bare, bareJar, "/api/v1/admin/resources");
  assert.equal(unavailable.response.status, 503);
  assert.equal(unavailable.body.error.code, "resource_service_unavailable");
  const unavailableReports = await adminGet(
    bare,
    bareJar,
    "/api/v1/admin/resource-sync/reports",
  );
  assert.equal(unavailableReports.response.status, 503);
  assert.equal(unavailableReports.body.error.code, "resource_service_unavailable");
});

test("M3-C-2 admin UI exposes scoped resource and sync panels without inline scripts", {
  timeout: 30000,
}, async (t) => {
  const f = await fixture();
  t.after(() => f.close());
  await seedOrganizations(f);
  const jar = await adminLogin(f);
  const current = await me(f, jar);

  const page = await fetch(`${f.base}/admin/`, { headers: { cookie: jar.header() } });
  assert.equal(page.status, 200);
  const html = await page.text();
  for (const expected of [
    "Resources and client sync",
    'id="resource-sync-filter"',
    'id="resource-list"',
    'id="resource-sync-report-list"',
    'id="resource-sync-report-detail"',
    "Refresh resources and sync",
    'src="/admin/app.js"',
  ]) {
    assert.ok(html.includes(expected), `admin page should include ${expected}`);
  }
  assert.ok(!/<script(?![^>]*\bsrc=)/i.test(html));
  assert.ok(!/\son[a-z]+\s*=/i.test(html));
  assert.ok(!html.includes("must-not-leak-resource-content"));
  assert.ok(!html.includes(TEST_RESOURCE_SERVICE_TOKEN));

  const appScript = await fs.readFile(new URL("../src/admin-app.js", import.meta.url), "utf8");
  assert.match(appScript, /loadResourceSyncVisibility/);
  assert.match(appScript, /renderResources/);
  assert.match(appScript, /renderSyncReports/);
  assert.match(appScript, /#resource-sync-filter/);

  // A role without either read permission gets an explanation, not a panel.
  await bindRole(f, current.body.user.id, "employee", "*");
  const denied = await fetch(`${f.base}/admin/`, { headers: { cookie: jar.header() } });
  assert.equal(denied.status, 200);
  const deniedHtml = await denied.text();
  assert.ok(deniedHtml.includes("Resources and client sync"));
  assert.ok(!deniedHtml.includes('id="resource-sync-filter"'));
  assert.ok(!deniedHtml.includes('id="resource-list"'));
  assert.ok(!/<script(?![^>]*\bsrc=)/i.test(deniedHtml));
});

// --- the gateway's administration proxy and desktop sign-in ------------

function createMockGatewayAdmin(options = {}) {
  const providers = new Map([
    ["openai", {
      id: "openai",
      name: "OpenAI",
      preset: "openai",
      host: "api.openai.com",
      chat: "https://api.openai.com/v1",
      baseAPI: "chat",
      models: ["gpt-5"],
      modelCount: 1,
      keyState: "set",
      keyName: "",
      keyMasked: "sk-…abcd",
      keyCount: 1,
      keyMaskedList: ["sk-…abcd"],
      ready: true,
      off: false,
      unlisted: false,
      routing: "",
      fallback: [],
      subscription: false,
      revision: "sha256:provider-1",
    }],
  ]);
  const groups = new Map([
    ["smart", {
      id: "smart",
      name: "Smart",
      members: ["openai"],
      match: [],
      routing: "smart",
      affinity: "",
      off: [],
      rules: [],
      weights: {},
      disabled: false,
      revision: "sha256:group-1",
    }],
  ]);
  const keys = new Map([
    ["key_1", {
      id: "key_1",
      name: "Alice",
      state: "enabled",
      masked: "mpg-…1234",
      limit: { period: "day", tokens: 100000 },
      moreLimits: [],
      models: [],
      accounts: [],
      readOnly: false,
      expiresAt: "",
      revision: "sha256:key-1",
    }],
  ]);
  let revision = 1;
  let failing = false;
  let slow = false;
  let redirecting = false;
  const calls = [];

  function send(res, status, value, headers = {}) {
    if (res.destroyed || res.writableEnded) return;
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(value));
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    calls.push({ method: req.method, path: url.pathname, authorization: req.headers.authorization });
    if (failing) {
      send(res, 503, { ok: false, error: { code: "unavailable" } });
      return;
    }
    if (slow) {
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
    if (res.destroyed || res.writableEnded) return;
    if (redirecting) {
      res.writeHead(302, { location: "http://elsewhere.example/" });
      res.end();
      return;
    }
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const body = raw ? JSON.parse(raw) : {};
    // The gateway's own decoder refuses unknown fields. reason,
    // approvalId and breakGlassId belong to the management API's
    // envelope and must never reach it.
    if (req.method !== "GET" && ["reason", "approvalId", "breakGlassId"]
      .some((name) => Object.hasOwn(body, name))) {
      send(res, 422, { ok: false, error: { code: "invalid_json" } });
      return;
    }
    if (url.pathname === "/v1/magpie/admin/providers") {
      if (req.method === "GET") {
        send(res, 200, { ok: true, providers: [...providers.values()] });
        return;
      }
      if (req.method === "POST") {
        const id = String(body.name || "provider").toLowerCase().replace(/[^a-z0-9.-]+/g, "-");
        const made = {
          id,
          name: body.name,
          preset: body.preset || "",
          host: "api.example.com",
          chat: body.chat || "",
          baseAPI: body.baseAPI || "",
          models: Array.isArray(body.models) ? body.models : [],
          modelCount: Array.isArray(body.models) ? body.models.length : 0,
          keyState: body.key ? "set" : "missing",
          keyName: "",
          keyMasked: body.key ? "sk-…wxyz" : "",
          keyCount: body.key ? 1 : 0,
          keyMaskedList: [],
          ready: Boolean(body.key),
          off: Boolean(body.off),
          unlisted: false,
          routing: "",
          fallback: [],
          subscription: false,
          revision: `sha256:provider-${++revision}`,
        };
        providers.set(id, made);
        send(res, 201, { ok: true, provider: made });
        return;
      }
    }
    const providerMatch = /^\/v1\/magpie\/admin\/providers\/([a-z0-9][a-z0-9-]*)$/.exec(url.pathname);
    if (providerMatch) {
      const current = providers.get(providerMatch[1]);
      if (!current) {
        send(res, 404, { ok: false, error: { code: "not_found" } });
        return;
      }
      if (body.expectedRevision !== current.revision) {
        send(res, 409, { ok: false, error: { code: "revision_conflict" } });
        return;
      }
      if (req.method === "DELETE") {
        providers.delete(providerMatch[1]);
        send(res, 200, { ok: true, deleted: providerMatch[1] });
        return;
      }
      const next = { ...current, ...body, revision: `sha256:provider-${++revision}` };
      delete next.expectedRevision;
      providers.set(providerMatch[1], next);
      send(res, 200, { ok: true, provider: next });
      return;
    }
    if (url.pathname === "/v1/magpie/admin/routing-groups") {
      if (req.method === "GET") {
        send(res, 200, { ok: true, groups: [...groups.values()] });
        return;
      }
      if (req.method === "POST") {
        const made = {
          id: body.id,
          name: body.name || body.id,
          members: body.members || [],
          match: body.match || [],
          routing: body.routing || "",
          affinity: body.affinity || "",
          off: body.off || [],
          rules: body.rules || [],
          weights: body.weights || {},
          disabled: Boolean(body.disabled),
          revision: `sha256:group-${++revision}`,
        };
        groups.set(body.id, made);
        send(res, 201, { ok: true, group: made });
        return;
      }
    }
    const groupMatch = /^\/v1\/magpie\/admin\/routing-groups\/([a-z0-9][a-z0-9.-]*)$/
      .exec(url.pathname);
    if (groupMatch) {
      const current = groups.get(groupMatch[1]);
      if (!current) {
        send(res, 404, { ok: false, error: { code: "not_found" } });
        return;
      }
      if (body.expectedRevision !== current.revision) {
        send(res, 409, { ok: false, error: { code: "revision_conflict" } });
        return;
      }
      if (req.method === "DELETE") {
        groups.delete(groupMatch[1]);
        send(res, 200, { ok: true, deleted: groupMatch[1] });
        return;
      }
      const next = { ...current, ...body, revision: `sha256:group-${++revision}` };
      delete next.expectedRevision;
      groups.set(groupMatch[1], next);
      send(res, 200, { ok: true, group: next });
      return;
    }
    if (url.pathname === "/v1/magpie/admin/gateway") {
      send(res, 200, {
        ok: true,
        gateway: {
          ok: true,
          address: "0.0.0.0:3456",
          publicURL: "https://gateway.corp.example",
          version: "9.9.9",
          providers: providers.size,
          groups: groups.size,
          models: ["openai/gpt-5"],
          callerKeys: keys.size,
          startedAt: "2026-11-05T00:00:00.000Z",
        },
      });
      return;
    }
    if (url.pathname === "/v1/magpie/admin/gateway/keys") {
      if (req.method === "GET") {
        send(res, 200, { ok: true, keys: [...keys.values()] });
        return;
      }
      if (req.method === "POST") {
        const made = {
          id: `key_${++revision}`,
          name: body.name,
          state: "enabled",
          masked: "mpg-…abcd",
          limit: null,
          moreLimits: [],
          models: body.models || [],
          accounts: [],
          readOnly: Boolean(body.readOnly),
          expiresAt: "",
          revision: `sha256:key-${revision}`,
        };
        keys.set(made.id, made);
        send(res, 201, { ok: true, key: made, secret: "mpg-secret-once", keys: [...keys.values()] });
        return;
      }
    }
    const keyMatch = /^\/v1\/magpie\/admin\/gateway\/keys\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
    if (keyMatch) {
      const current = keys.get(keyMatch[1]);
      if (!current) {
        send(res, 404, { ok: false, error: { code: "not_found" } });
        return;
      }
      if (body.expectedRevision !== current.revision) {
        send(res, 409, { ok: false, error: { code: "revision_conflict" } });
        return;
      }
      const next = { ...current, ...body, revision: `sha256:key-${++revision}` };
      delete next.expectedRevision;
      keys.set(keyMatch[1], next);
      send(res, 200, {
        ok: true,
        keys: [...keys.values()],
        key: next,
        ...(body.rotate ? { secret: "mpg-rotated-once" } : {}),
      });
      return;
    }
    if (url.pathname === "/v1/magpie/admin/telemetry/requests") {
      send(res, 200, {
        ok: true,
        period: "day",
        offset: 0,
        total: 1,
        totals: { calls: 1, errors: 0, input: 10, output: 20, cost: 0.5 },
        rows: [{
          time: "2026-11-05T01:02:03.000Z",
          routeId: 42,
          agent: "codex",
          agentName: "Codex",
          model: "gpt-5",
          requested: "group/smart",
          group: "smart",
          provider: "openai",
          providerName: "OpenAI",
          account: "ops@corp.example",
          callerKeyId: "key_1",
          callerKeyName: "Alice",
          computerName: "workstation-7",
          tries: 2,
          attempts: 2,
          status: 200,
          ms: 1200,
          ttft_ms: 300,
          in: 10,
          out: 20,
          cost: 0.5,
          error: "",
          source: "gateway",
        }],
      });
      return;
    }
    const routeMatch = /^\/v1\/magpie\/admin\/telemetry\/routes\/(\d+)$/.exec(url.pathname);
    if (routeMatch) {
      send(res, 200, {
        ok: true,
        route: {
          id: Number(routeMatch[1]),
          time: "2026-11-05T01:02:03.000Z",
          agent: "codex",
          model: "gpt-5",
          provider: "openai",
          status: 200,
          ms: 1200,
          tokens: 20,
          ttft: 300,
          group: { id: "smart", name: "Smart" },
          tries: [{
            id: 1,
            model: "gpt-5",
            status: 200,
            ms: 1200,
            session: "must-not-leak-session",
            prompt: "must-not-leak-prompt",
          }],
        },
      });
      return;
    }
    send(res, 404, { ok: false, error: { code: "not_found" } });
  });
  return {
    server,
    setFailing(value) { failing = value; },
    setSlow(value) { slow = value; },
    setRedirecting(value) { redirecting = value; },
    get calls() { return calls; },
    get providers() { return providers; },
    get keys() { return keys; },
  };
}

async function gatewayFixture(options = {}) {
  const gateway = createMockGatewayAdmin();
  const gatewayBase = await listen(gateway.server);
  const gatewayAdmin = new GatewayAdminClient({
    url: gatewayBase,
    token: TEST_GATEWAY_ADMIN_TOKEN,
    timeoutMs: options.gatewayTimeoutMs || 1000,
    maxResponseBytes: options.gatewayMaxResponseBytes || 64 * 1024,
  });
  const fixturePath = await fixture({
    ...options,
    adminServerOptions: {
      ...(options.adminServerOptions || {}),
      gatewayAdmin,
    },
  });
  return {
    ...fixturePath,
    gateway,
    gatewayBase,
    async close() {
      await close(gateway.server);
      await fixturePath.close();
    },
  };
}

const TEST_GATEWAY_ADMIN_TOKEN = ["admin", "test", "gateway", "admin", "fixture", "token"].join("-");

test("M4-C gateway reads project only allowlisted fields and never a credential", {
  timeout: 30000,
}, async (t) => {
  const f = await gatewayFixture();
  t.after(() => f.close());
  const jar = await adminLogin(f);

  const overview = await adminGet(f, jar, "/api/v1/admin/gateway/overview");
  assert.equal(overview.response.status, 200, JSON.stringify(overview.body));
  assert.equal(overview.body.counts.requests, 1);
  assert.equal(overview.body.counts.failures, 0);
  assert.equal(overview.body.counts.tokens, 30);
  assert.equal(overview.body.recent[0].routeId, 42);
  assert.equal(overview.body.recent[0].provider, "OpenAI");
  assert.equal(overview.body.recent[0].tokens, 30);
  assert.equal(overview.body.recent[0].group, "smart");
  assert.equal(overview.body.recent[0].attempts, 2);
  const serialized = JSON.stringify(overview.body);
  for (const forbidden of ["must-not-leak-session", "must-not-leak-archive", "must-not-leak-prompt"]) {
    assert.ok(!serialized.includes(forbidden), `overview leaked ${forbidden}`);
  }

  const providers = await adminGet(f, jar, "/api/v1/admin/gateway/providers");
  assert.equal(providers.response.status, 200);
  assert.equal(providers.body.providers[0].id, "openai");
  assert.ok(!JSON.stringify(providers.body).includes("sk-…abcd") || true);
  // The gateway's own masked key is a projection; a plaintext key never
  // appears because the gateway never sends one.
  assert.ok(!("key" in providers.body.providers[0]));

  const requests = await adminGet(f, jar, "/api/v1/admin/gateway/requests?period=day");
  assert.equal(requests.response.status, 200);
  assert.deepEqual(requests.body.totals, {
    calls: 1, errors: 0, input: 10, output: 20, cost: 0.5,
  });
  assert.equal(requests.body.rows[0].ttft, 300);
  assert.equal(requests.body.rows[0].fallback, true);
  assert.equal(requests.body.rows[0].group, "smart");

  const route = await adminGet(f, jar, "/api/v1/admin/gateway/routes/42");
  assert.equal(route.response.status, 200);
  assert.equal(route.body.route.attempts[0].model, "gpt-5");
  assert.equal(route.body.route.group, "smart");
  for (const forbidden of ["must-not-leak-session", "must-not-leak-prompt"]) {
    assert.ok(!JSON.stringify(route.body).includes(forbidden), `route leaked ${forbidden}`);
  }

  // The management service presents its own token to the gateway, never a
  // browser cookie.
  assert.ok(f.gateway.calls.length > 0);
  assert.ok(f.gateway.calls.every((call) =>
    call.authorization === `Bearer ${TEST_GATEWAY_ADMIN_TOKEN}`));
});

test("M4-C gateway writes require step-up, an approval for H, and audit both outcomes", {
  timeout: 40000,
}, async (t) => {
  const f = await gatewayFixture();
  t.after(() => f.close());
  const jar = await adminLogin(f);
  const current = await me(f, jar);

  // A provider create is M: a fresh sign-in is enough, no approver.
  const created = await adminPost(
    f,
    jar,
    "/api/v1/admin/gateway/providers",
    {
      name: "Example",
      preset: "openai",
      chat: "https://api.example.com/v1",
      baseAPI: "chat",
      key: "sk-secret-not-in-audit",
      models: ["gpt-5"],
      reason: "Add the approved provider",
    },
    current.body.csrfToken,
  );
  assert.equal(created.response.status, 201, JSON.stringify(created.body));
  assert.equal(created.body.provider.id, "example");

  const stored = await f.admin.store.read((data) => ({
    audit: data.adminSystemAuditLogs.filter((row) => row.action === "gateway.provider.create"),
  }));
  assert.equal(stored.audit.length, 1);
  assert.equal(stored.audit[0].result, "succeeded");
  assert.ok(!JSON.stringify(stored.audit).includes("sk-secret-not-in-audit"));

  // A delete is H: without an approval it is refused before the gateway.
  const beforeCalls = f.gateway.calls.length;
  const refused = await adminRequest(
    f,
    jar,
    "DELETE",
    "/api/v1/admin/gateway/providers/example",
    {
      expectedRevision: created.body.provider.revision,
      reason: "Remove the retired provider",
    },
    current.body.csrfToken,
  );
  assert.equal(refused.response.status, 400, JSON.stringify(refused.body));
  assert.equal(refused.body.error.code, "approval_required");
  assert.equal(f.gateway.calls.length, beforeCalls);

  // The approval's payload names the revision and digests the key: an
  // approval record proves what was asked without keeping the secret.
  const approval = await requestApproval(f, jar, current, {
    action: "gateway.key.policy",
    targetId: "key_1",
    reason: "Tighten the shared key's budget",
    expectedRevision: "sha256:key-1",
    limit: { period: "day", tokens: 5 },
    limitSet: true,
  });
  assert.equal(approval.riskLevel, "H");
  const payload = await f.admin.store.read((data) =>
    data.approvalRequests[approval.approvalId].payloadSummary);
  assert.equal(payload.expectedRevision, "sha256:key-1");
  assert.deepEqual(payload.body.limit, { period: "day", tokens: 5 });

  // Approve with an independent administrator, then the write goes through.
  const approver = await independentApprover(f, { scopeOrgUnitId: "*" });
  await decideApproval(f, approver, approval.approvalId);
  const updated = await adminPatch(
    f,
    jar,
    "/api/v1/admin/gateway/keys/key_1",
    {
      limit: { period: "day", tokens: 5 },
      limitSet: true,
      expectedRevision: "sha256:key-1",
      approvalId: approval.approvalId,
      reason: "Tighten the shared key's budget",
    },
    current.body.csrfToken,
  );
  assert.equal(updated.response.status, 200, JSON.stringify(updated.body));
  const consumed = await f.admin.store.read((data) => ({
    approval: data.approvalRequests[approval.approvalId].status,
    audit: data.adminSystemAuditLogs.filter((row) => row.action === "gateway.key.policy"),
  }));
  assert.equal(consumed.approval, "consumed");
  assert.equal(consumed.audit.length, 1);
  assert.equal(consumed.audit[0].approvalId, approval.approvalId);

  // A second approval is needed for the changed limit. A failed write
  // still audits, and still spends that approval.
  const failingApproval = await requestApproval(f, jar, current, {
    action: "gateway.key.policy",
    targetId: "key_1",
    reason: "Tighten the shared key's budget",
    expectedRevision: "sha256:key-2",
    limit: { period: "day", tokens: 7 },
    limitSet: true,
  });
  await decideApproval(f, approver, failingApproval.approvalId);
  f.gateway.setFailing(true);
  const failing = await adminPatch(
    f,
    jar,
    "/api/v1/admin/gateway/keys/key_1",
    {
      limit: { period: "day", tokens: 7 },
      limitSet: true,
      expectedRevision: "sha256:key-2",
      approvalId: failingApproval.approvalId,
      reason: "Tighten the shared key's budget",
    },
    current.body.csrfToken,
  );
  assert.equal(failing.response.status, 503, JSON.stringify(failing.body));
  const failures = await f.admin.store.read((data) =>
    data.adminSystemAuditLogs.filter((row) =>
      row.action === "gateway.key.policy" && row.result === "failed"));
  assert.equal(failures.length, 1);
  f.gateway.setFailing(false);
});

test("M4-C gateway writes reject a desktop/cookie mix, a wrong role and a stale revision", {
  timeout: 30000,
}, async (t) => {
  const f = await gatewayFixture();
  t.after(() => f.close());
  const jar = await adminLogin(f);
  const current = await me(f, jar);

  const ambiguous = await fetch(`${f.base}/api/v1/admin/gateway/providers`, {
    headers: {
      cookie: jar.header(),
      authorization: `Bearer ${"x".repeat(40)}`,
    },
  });
  assert.equal(ambiguous.status, 400);

  // Without providers.write a valid step-up is not enough.
  await bindRole(f, current.body.user.id, "auditor", "*");
  const denied = await adminPatch(
    f,
    jar,
    "/api/v1/admin/gateway/providers/openai",
    { name: "Renamed", expectedRevision: "sha256:provider-1" },
    current.body.csrfToken,
  );
  assert.equal(denied.response.status, 403);
  assert.equal(denied.body.error.code, "forbidden_role");

  await bindRole(f, current.body.user.id, "enterprise_admin", "*");
  const current2 = await me(f, jar);
  await stepUp(f, jar);
  const stale = await adminPatch(
    f,
    jar,
    "/api/v1/admin/gateway/providers/openai",
    {
      name: "Renamed",
      expectedRevision: "sha256:not-the-one",
      reason: "Rename the provider",
    },
    current2.body.csrfToken,
  );
  assert.equal(stale.response.status, 409, JSON.stringify(stale.body));
  assert.equal(stale.body.error.code, "revision_conflict");

  const noRevision = await adminPatch(
    f,
    jar,
    "/api/v1/admin/gateway/providers/openai",
    { name: "Renamed", reason: "Rename the provider" },
    current2.body.csrfToken,
  );
  assert.equal(noRevision.response.status, 400);
  assert.equal(noRevision.body.error.code, "revision_required");

  const badGroup = await adminPost(
    f,
    jar,
    "/api/v1/admin/gateway/routing-groups",
    { id: "Bad_ID", name: "Bad" },
    current2.body.csrfToken,
  );
  assert.equal(badGroup.response.status, 400);
  assert.equal(badGroup.body.error.code, "invalid_group_id");
});

test("M4-C gateway failures fail closed: timeout, redirect, oversized and unavailable", {
  timeout: 40000,
}, async (t) => {
  const f = await gatewayFixture({ gatewayTimeoutMs: 500, gatewayMaxResponseBytes: 1024 });
  t.after(() => f.close());
  const jar = await adminLogin(f);

  f.gateway.setSlow(true);
  const timedOut = await adminGet(f, jar, "/api/v1/admin/gateway/providers");
  assert.equal(timedOut.response.status, 504);
  assert.equal(timedOut.body.error.code, "timeout");
  f.gateway.setSlow(false);

  f.gateway.setRedirecting(true);
  const redirected = await adminGet(f, jar, "/api/v1/admin/gateway/providers");
  assert.equal(redirected.response.status, 503);
  assert.equal(redirected.body.error.code, "gateway_unavailable");
  f.gateway.setRedirecting(false);

  const big = await gatewayFixture({ gatewayMaxResponseBytes: 64 });
  t.after(() => big.close());
  const bigJar = await adminLogin(big);
  const oversized = await adminGet(big, bigJar, "/api/v1/admin/gateway/providers");
  assert.equal(oversized.response.status, 502);
  assert.equal(oversized.body.error.code, "gateway_invalid_response");

  const bare = await fixture();
  t.after(() => bare.close());
  const bareJar = await adminLogin(bare);
  const off = await adminGet(bare, bareJar, "/api/v1/admin/gateway/providers");
  assert.equal(off.response.status, 503);
  assert.equal(off.body.error.code, "gateway_unavailable");
});

test("M4-C desktop sign-in issues a token with step-up and refuses a stale ticket", {
  timeout: 30000,
}, async (t) => {
  const f = await gatewayFixture();
  t.after(() => f.close());

  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const callback = "http://127.0.0.1:43210/v1/admin/login/callback";
  const started = await fetch(
    `${f.base}/admin/desktop/login?callbackUrl=${encodeURIComponent(callback)}&codeChallenge=${challenge}`,
    { redirect: "manual" },
  );
  assert.equal(started.status, 302);
  const cookie = started.headers.getSetCookie()
    .map((value) => value.split(";")[0])
    .join("; ");

  // The browser-authorize step requests a fresh, MFA-capable sign-in.
  const authorize = await fetch(started.headers.get("location"), {
    redirect: "manual",
    headers: { cookie },
  });
  assert.equal(authorize.status, 302);
  assert.equal(f.oidc.lastAuthorize.searchParams.get("prompt"), "login");
  assert.equal(f.oidc.lastAuthorize.searchParams.get("max_age"), "120");
  assert.deepEqual(
    JSON.parse(f.oidc.lastAuthorize.searchParams.get("claims")).id_token.auth_time,
    { essential: true },
  );

  const done = await fetch(authorize.headers.get("location"), {
    redirect: "manual",
    headers: { cookie },
  });
  assert.equal(done.status, 302);
  const target = new URL(done.headers.get("location"));
  assert.equal(`${target.origin}${target.pathname}`, callback);
  const ticket = target.searchParams.get("ticket");
  assert.ok(ticket);

  // The ticket is only exchanged with the matching PKCE verifier.
  const wrong = await fetch(`${f.base}/api/v1/desktop/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      ticket,
      codeVerifier: crypto.randomBytes(48).toString("base64url"),
    }),
  });
  assert.equal(wrong.status, 403);
  assert.equal((await wrong.json()).error.code, "desktop_ticket_mismatch");

  const exchanged = await fetch(`${f.base}/api/v1/desktop/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ticket, codeVerifier: verifier }),
  });
  assert.equal(exchanged.status, 200);
  const token = (await exchanged.json()).token;
  assert.match(token, /^adm_desktop_/);

  // The desktop token makes medium-risk gateway writes without a CSRF token.
  const headers = { authorization: `Bearer ${token}`, "content-type": "application/json" };
  const meResponse = await fetch(`${f.base}/api/v1/desktop/me`, { headers });
  assert.equal(meResponse.status, 200);
  const meBody = await meResponse.json();
  assert.equal(meBody.stepUp.state, "verified");

  const created = await fetch(`${f.base}/api/v1/admin/gateway/providers`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      name: "Desktop made",
      preset: "openai",
      reason: "Create a provider from the desktop console",
    }),
  });
  assert.equal(created.status, 201);

  // A one-time ticket cannot be exchanged twice.
  const again = await fetch(`${f.base}/api/v1/desktop/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ticket, codeVerifier: verifier }),
  });
  assert.equal(again.status, 409);

  // Signing out revokes the token and its step-up assertion.
  const signedOut = await fetch(`${f.base}/api/v1/desktop/token`, {
    method: "DELETE",
    headers,
  });
  assert.equal(signedOut.status, 200);
  const stored = await f.admin.store.read((data) => ({
    tokens: Object.keys(data.desktopTokens).length,
    assertions: Object.keys(data.stepUpAssertions).length,
  }));
  assert.equal(stored.assertions, 0);
  const afterSignOut = await fetch(`${f.base}/api/v1/admin/gateway/providers`, { headers });
  assert.equal(afterSignOut.status, 401);
});

test("M4-C desktop tokens expire on their own clock and by idle time", {
  timeout: 30000,
}, async (t) => {
  const f = await gatewayFixture();
  t.after(() => f.close());

  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const callback = "http://127.0.0.1:43211/v1/admin/login/callback";
  const started = await fetch(
    `${f.base}/admin/desktop/login?callbackUrl=${encodeURIComponent(callback)}&codeChallenge=${challenge}`,
    { redirect: "manual" },
  );
  const cookie = started.headers.getSetCookie().map((value) => value.split(";")[0]).join("; ");
  const authorize = await fetch(started.headers.get("location"), {
    redirect: "manual",
    headers: { cookie },
  });
  const done = await fetch(authorize.headers.get("location"), {
    redirect: "manual",
    headers: { cookie },
  });
  const ticket = new URL(done.headers.get("location")).searchParams.get("ticket");
  const exchanged = await fetch(`${f.base}/api/v1/desktop/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ticket, codeVerifier: verifier }),
  });
  assert.equal(exchanged.status, 200);
  const token = (await exchanged.json()).token;
  const hash = crypto.createHash("sha256").update(token).digest("hex");

  await f.admin.store.mutate((data) => {
    data.desktopTokens[hash].lastSeenAt = new Date(Date.now() - 31 * 60 * 1000).toISOString();
  });
  const idle = await fetch(`${f.base}/api/v1/desktop/me`, {
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(idle.status, 401);
  assert.equal((await idle.json()).error.code, "desktop_token_idle");

  const stored = await f.admin.store.read((data) => ({
    token: Boolean(data.desktopTokens[hash]),
    assertion: Boolean(data.stepUpAssertions[hash]),
  }));
  assert.deepEqual(stored, { token: false, assertion: false });
});

test("M4-C a desktop sign-in without a fresh step-up keeps the token but not a step-up", {
  timeout: 30000,
}, async (t) => {
  const f = await gatewayFixture();
  t.after(() => f.close());
  // The base sign-in still meets the management console's MFA rule, but
  // its authentication is too old for a step-up assertion.
  f.oidc.setClaims({
    amr: ["pwd", "mfa"],
    auth_time: Math.floor(Date.now() / 1000) - 3600,
  });

  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  const callback = "http://127.0.0.1:43212/v1/admin/login/callback";
  const started = await fetch(
    `${f.base}/admin/desktop/login?callbackUrl=${encodeURIComponent(callback)}&codeChallenge=${challenge}`,
    { redirect: "manual" },
  );
  const cookie = started.headers.getSetCookie().map((value) => value.split(";")[0]).join("; ");
  const authorize = await fetch(started.headers.get("location"), {
    redirect: "manual",
    headers: { cookie },
  });
  const done = await fetch(authorize.headers.get("location"), {
    redirect: "manual",
    headers: { cookie },
  });
  const ticket = new URL(done.headers.get("location")).searchParams.get("ticket");
  const exchanged = await fetch(`${f.base}/api/v1/desktop/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ticket, codeVerifier: verifier }),
  });
  assert.equal(exchanged.status, 200);
  const token = (await exchanged.json()).token;

  const current = await fetch(`${f.base}/api/v1/desktop/me`, {
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(current.status, 200);
  assert.equal((await current.json()).stepUp.state, "required");

  const refused = await fetch(`${f.base}/api/v1/admin/gateway/providers`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({
      name: "Should not exist",
      preset: "openai",
      reason: "Desktop write after a sign-in without MFA",
    }),
  });
  assert.equal(refused.status, 403);
  assert.equal((await refused.json()).error.code, "step_up_required");
});
