// A local preview of the management console, from this repository's
// admin-service. The OIDC provider and auth-service below are the preview
// doubles the earlier preview script used; they are not for production.
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const dataDir = path.resolve(here, "..", "data", "preview");
const tokenFile = path.join(dataDir, "gateway-admin-token");
const gatewayAdminUrl = String(process.env.ADMIN_GATEWAY_ADMIN_URL || "").trim();
// The gateway's administration token is a deployment secret. For this
// preview it comes from a file beside the store, so the gateway and this
// service can be started from different shells with the same value.
const gatewayAdminToken = String(process.env.ADMIN_GATEWAY_ADMIN_TOKEN || "").trim()
  || (fs.existsSync(tokenFile) ? fs.readFileSync(tokenFile, "utf8").trim() : "");
const oidcBase = "http://127.0.0.1:3444";
const authBase = "http://127.0.0.1:3446";
const adminBase = "http://127.0.0.1:3445";
const pluginPort = Number(process.env.MAGPIE_ENTERPRISE_PLUGIN_PORT || 3477);

const secrets = {
  session: "preview-admin-session-secret-not-for-production",
  oidc: "preview-oidc-client-secret-not-for-production",
  stepUp: "preview-step-up-client-secret-not-for-production",
  auth: "preview-auth-service-token-not-for-production",
};

function listen(server, port) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function sendJson(res, statusCode, body) {
  const payload = Buffer.from(JSON.stringify(body));
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(payload.length),
    "cache-control": "no-store",
  });
  res.end(payload);
}

function createOidc() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  jwk.kid = "preview-key";
  jwk.use = "sig";
  jwk.alg = "RS256";
  const codes = new Map();
  const clients = {
    "magpie-admin": secrets.oidc,
    "magpie-admin-step-up": secrets.stepUp,
  };

  function token(claims) {
    const header = Buffer.from(JSON.stringify({
      alg: "RS256",
      typ: "JWT",
      kid: "preview-key",
    })).toString("base64url");
    const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const signature = crypto.sign("RSA-SHA256", Buffer.from(`${header}.${payload}`), privateKey)
      .toString("base64url");
    return `${header}.${payload}.${signature}`;
  }

  return http.createServer(async (req, res) => {
    const url = new URL(req.url, oidcBase);
    if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
      sendJson(res, 200, {
        issuer: oidcBase,
        authorization_endpoint: `${oidcBase}/authorize`,
        token_endpoint: `${oidcBase}/token`,
        jwks_uri: `${oidcBase}/jwks`,
      });
      return;
    }
    if (req.method === "GET" && url.pathname === "/jwks") {
      sendJson(res, 200, { keys: [jwk] });
      return;
    }
    if (req.method === "GET" && url.pathname === "/authorize") {
      const clientId = url.searchParams.get("client_id");
      if (!clients[clientId]) {
        res.writeHead(400);
        res.end("unknown client");
        return;
      }
      const code = `oidc_${crypto.randomBytes(18).toString("base64url")}`;
      codes.set(code, {
        clientId,
        redirectUri: url.searchParams.get("redirect_uri"),
        nonce: url.searchParams.get("nonce"),
        codeChallenge: url.searchParams.get("code_challenge"),
        createdAt: Date.now(),
      });
      const target = new URL(url.searchParams.get("redirect_uri"));
      target.searchParams.set("code", code);
      target.searchParams.set("state", url.searchParams.get("state") || "");
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
      const expected = code ? `${code.clientId}:${clients[code.clientId]}` : "";
      const pkceOk = code && crypto.createHash("sha256")
        .update(form.get("code_verifier") || "")
        .digest("base64url") === code.codeChallenge;
      if (!code || !pkceOk || Date.now() - code.createdAt > 60000 || supplied !== expected) {
        sendJson(res, 400, { error: "invalid_grant" });
        return;
      }
      codes.delete(form.get("code"));
      const now = Math.floor(Date.now() / 1000);
      sendJson(res, 200, {
        access_token: "preview-access-token",
        token_type: "Bearer",
        expires_in: 300,
        id_token: token({
          iss: oidcBase,
          aud: code.clientId,
          sub: "admin-alice",
          email: "admin@corp.example",
          email_verified: true,
          name: "Admin Alice",
          amr: ["pwd", "mfa"],
          acr: "mfa",
          auth_time: now,
          nonce: code.nonce,
          iat: now,
          exp: now + 300,
        }),
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });
}

function createAuth() {
  const users = [
    user("usr_alice", "alice@corp.example", "Alice", 2, ["deepseek/deepseek-chat", "openai/gpt-4o"]),
    user("usr_bob", "bob@corp.example", "Bob", 1, ["deepseek/deepseek-chat"]),
    user("usr_carol", "carol@corp.example", "Carol", 1, ["openai/gpt-4o"]),
  ];
  const devices = [
    device("dev_alice", "usr_alice", "Alice PC", "windows", "key-alice"),
    device("dev_bob", "usr_bob", "Bob Mac", "macos", "key-bob"),
    device("dev_carol", "usr_carol", "Carol PC", "windows", "key-carol"),
  ];
  const credentials = [
    credential("key-alice", "usr_alice", "dev_alice", "Alice PC"),
    credential("key-bob", "usr_bob", "dev_bob", "Bob Mac"),
    credential("key-carol", "usr_carol", "dev_carol", "Carol PC"),
  ];

  return http.createServer(async (req, res) => {
    const url = new URL(req.url, authBase);
    if (!url.pathname.startsWith("/api/v1/internal/admin/")) {
      res.writeHead(404);
      res.end();
      return;
    }
    if (req.headers.authorization !== `Bearer ${secrets.auth}`) {
      sendJson(res, 401, { error: { code: "invalid_service_token", message: "Unauthorized" } });
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/v1/internal/admin/status") {
      sendJson(res, 200, {
        ok: true,
        service: "auth",
        users: users.length,
        devices: devices.length,
        credentials: credentials.length,
        pendingRevocations: 0,
      });
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/v1/internal/admin/users") {
      sendJson(res, 200, { ok: true, users });
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/v1/internal/admin/devices") {
      sendJson(res, 200, { ok: true, devices });
      return;
    }
    if (req.method === "GET" && url.pathname === "/api/v1/internal/admin/credentials") {
      sendJson(res, 200, { ok: true, credentials });
      return;
    }
    const userWrite = /^\/api\/v1\/internal\/admin\/users\/([A-Za-z0-9_-]+)\/(disable|enable)$/.exec(url.pathname);
    if (req.method === "POST" && userWrite) {
      const found = users.find((item) => item.id === userWrite[1]);
      if (!found) {
        sendJson(res, 404, { error: { code: "user_not_found", message: "User not found" } });
        return;
      }
      found.status = userWrite[2] === "disable" ? "disabled" : "active";
      sendJson(res, 200, { ok: true, data: { userId: found.id, status: found.status } });
      return;
    }
    res.writeHead(404);
    res.end();
  });
}

function user(id, email, name, version, models) {
  return {
    id,
    email,
    name,
    status: "active",
    createdAt: "2026-10-01T00:00:00.000Z",
    lastLoginAt: new Date().toISOString(),
    policy: {
      version,
      models,
      limits: [{ metric: "tokens", period: "month", amount: 2000000 }],
      quotaStatus: "known",
      modelStatus: "known",
      including: ["quota", "models"],
      missing: [],
      updatedAt: new Date().toISOString(),
      confirmedAt: new Date().toISOString(),
      operationId: `op_${id}`,
    },
  };
}

function device(id, userId, name, platform, gatewayKeyId) {
  return {
    id,
    userId,
    name,
    platform,
    clientVersion: "preview",
    status: "active",
    createdAt: "2026-10-20T00:00:00.000Z",
    lastSeenAt: new Date().toISOString(),
    gatewayKeyId,
    keyExpiresAt: "2026-12-01T00:00:00.000Z",
  };
}

function credential(id, userId, deviceId, deviceName) {
  return {
    id,
    userId,
    deviceId,
    deviceName,
    deviceStatus: "active",
    status: "active",
    createdAt: "2026-10-31T00:00:00.000Z",
    expiresAt: "2026-12-01T00:00:00.000Z",
    lastSeenAt: new Date().toISOString(),
    models: ["deepseek/deepseek-chat"],
    policyVersion: 1,
    policySyncState: "synced",
    lastPolicyResult: "synced",
  };
}


const oidc = createOidc();
const auth = createAuth();
await listen(oidc, 3444);
await listen(auth, 3446);

Object.assign(process.env, {
  ADMIN_BIND: "127.0.0.1",
  ADMIN_PORT: "3445",
  ADMIN_PUBLIC_URL: adminBase,
  ADMIN_STORE_PATH: path.join(dataDir, "admin-store.json"),
  ADMIN_SESSION_SECRET: secrets.session,
  ADMIN_SECURE_COOKIE: "false",
  ADMIN_OIDC_ISSUER: oidcBase,
  ADMIN_OIDC_CLIENT_ID: "magpie-admin",
  ADMIN_OIDC_CLIENT_SECRET: secrets.oidc,
  ADMIN_OIDC_REDIRECT_URI: adminBase + "/admin/oauth/callback",
  ADMIN_AUTH_SERVICE_URL: authBase,
  ADMIN_AUTH_SERVICE_TOKEN: secrets.auth,
  ADMIN_ALLOWED_IPS: "127.0.0.1/32,::1/128",
  ADMIN_BOOTSTRAP_EMAILS: "admin@corp.example",
  ADMIN_REQUIRE_MFA: "true",
  ADMIN_REQUIRE_VERIFIED_EMAIL: "true",
  ADMIN_STEP_UP_OIDC_CLIENT_ID: "magpie-admin-step-up",
  ADMIN_STEP_UP_OIDC_CLIENT_SECRET: secrets.stepUp,
  ADMIN_STEP_UP_REDIRECT_URI: adminBase + "/admin/oauth/step-up/callback",
  ADMIN_MODELS: "deepseek/deepseek-chat,openai/gpt-4o,anthropic/claude-3-5-sonnet",
  ADMIN_USAGE_PATH: path.join(dataDir, "usage.jsonl"),
  ADMIN_DESKTOP_LOGIN_ENABLED: "true",
  ADMIN_DESKTOP_CALLBACK_HOSTS: "127.0.0.1,localhost",
  ADMIN_DESKTOP_CALLBACK_PORTS: String(pluginPort),
  ...(gatewayAdminUrl && gatewayAdminToken ? {
    ADMIN_GATEWAY_ADMIN_URL: gatewayAdminUrl,
    ADMIN_GATEWAY_ADMIN_TOKEN: gatewayAdminToken,
    ADMIN_GATEWAY_ADMIN_TIMEOUT_MS: "10000",
  } : {}),
});

const { loadConfig } = await import("../admin-service/src/config.js");
const { createEnterpriseAdminServer } = await import("../admin-service/src/service.js");
const adminConfig = loadConfig(process.env);
const admin = await createEnterpriseAdminServer(adminConfig);
await listen(admin.server, 3445);

console.log("Magpie enterprise admin preview is running");
console.log("Admin console: " + adminBase + "/admin");
console.log("Desktop sign-in returns to the plugin on 127.0.0.1:" + pluginPort);
console.log(gatewayAdminUrl
  ? "Gateway administration API: " + gatewayAdminUrl
  : "Gateway administration API: not configured (set ADMIN_GATEWAY_ADMIN_URL and ADMIN_GATEWAY_ADMIN_TOKEN)");
