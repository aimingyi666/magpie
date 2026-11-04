import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dataDir = path.join(root, "data", "preview");
const oidcBase = "http://127.0.0.1:3444";
const authBase = "http://127.0.0.1:3446";
const adminBase = "http://127.0.0.1:3445";
const portalBase = "http://127.0.0.1:3007";

const secrets = {
  session: "preview-admin-session-secret-not-for-production",
  oidc: "preview-oidc-client-secret-not-for-production",
  stepUp: "preview-step-up-client-secret-not-for-production",
  auth: "preview-auth-service-token-not-for-production",
  portal: "preview-employee-portal-token-not-for-production",
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

async function seedFiles() {
  await fs.mkdir(dataDir, { recursive: true });
  const today = new Date().toISOString().slice(0, 10);
  const usage = {
    usage: {
      alice_today: { subjectId: "usr_alice", date: today, tokens: 186420, cost: 1.284, requests: 46 },
      bob_today: { subjectId: "usr_bob", date: today, tokens: 42310, cost: 0.216, requests: 12 },
      carol_today: { subjectId: "usr_carol", date: today, tokens: 9800, cost: 0.074, requests: 4 },
    },
  };
  const tickets = {
    tickets: {
      tk_previewalice0001: {
        id: "tk_previewalice0001",
        subjectId: "usr_alice",
        title: "申请 Claude 3.5 编码权限",
        description: "架构评审需要更强的代码模型。",
        priority: "high",
        status: "open",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    },
  };
  await fs.writeFile(path.join(dataDir, "employee-usage.json"), `${JSON.stringify(usage, null, 2)}\n`);
  await fs.writeFile(path.join(dataDir, "employee-tickets.json"), `${JSON.stringify(tickets, null, 2)}\n`);
  const usagePath = path.join(dataDir, "usage.jsonl");
  const now = new Date().toISOString();
  const lines = [
    { t: now, agent: "codex", provider: "deepseek", key: "key-alice", req: "deepseek/deepseek-chat", status: 200, in: 12000, out: 3400, cost: 0.082 },
    { t: now, agent: "opencode", provider: "openai", key: "key-bob", req: "openai/gpt-4o", status: 200, in: 8000, out: 2100, cost: 0.064 },
    { t: now, agent: "cursor", provider: "openai", key: "key-carol", req: "openai/gpt-4o", status: 200, in: 2600, out: 700, cost: 0.018 },
  ];
  await fs.writeFile(usagePath, `${lines.map((line) => JSON.stringify(line)).join("\n")}\n`);
  const adminStorePath = path.join(dataDir, "admin-store.json");
  let adminStore = {};
  try {
    adminStore = JSON.parse(await fs.readFile(adminStorePath, "utf8"));
  } catch {
    adminStore = {};
  }
  adminStore.orgUnits = {
    "org-engineering": {
      id: "org-engineering",
      parentId: "",
      name: "研发中心",
      path: "/研发中心",
      externalId: "idp-engineering",
      status: "active",
    },
    "org-architecture": {
      id: "org-architecture",
      parentId: "org-engineering",
      name: "研发架构组",
      path: "/研发中心/研发架构组",
      externalId: "idp-architecture",
      status: "active",
    },
    "org-efficiency": {
      id: "org-efficiency",
      parentId: "org-engineering",
      name: "工程效能组",
      path: "/研发中心/工程效能组",
      externalId: "idp-efficiency",
      status: "active",
    },
    "org-marketing": {
      id: "org-marketing",
      parentId: "",
      name: "市场部",
      path: "/市场部",
      externalId: "idp-marketing",
      status: "active",
    },
  };
  adminStore.userOrgUnits = {
    usr_alice: "org-architecture",
    usr_bob: "org-efficiency",
    usr_carol: "org-marketing",
  };
  await fs.writeFile(adminStorePath, `${JSON.stringify(adminStore, null, 2)}\n`);
  return usagePath;
}

const usagePath = await seedFiles();
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
  ADMIN_OIDC_REDIRECT_URI: `${adminBase}/admin/oauth/callback`,
  ADMIN_AUTH_SERVICE_URL: authBase,
  ADMIN_AUTH_SERVICE_TOKEN: secrets.auth,
  ADMIN_ALLOWED_IPS: "127.0.0.1/32,::1/128",
  ADMIN_BOOTSTRAP_EMAILS: "admin@corp.example",
  ADMIN_REQUIRE_MFA: "true",
  ADMIN_REQUIRE_VERIFIED_EMAIL: "true",
  ADMIN_STEP_UP_OIDC_CLIENT_ID: "magpie-admin-step-up",
  ADMIN_STEP_UP_OIDC_CLIENT_SECRET: secrets.stepUp,
  ADMIN_STEP_UP_REDIRECT_URI: `${adminBase}/admin/oauth/step-up/callback`,
  ADMIN_MODELS: "deepseek/deepseek-chat,openai/gpt-4o,anthropic/claude-3-5-sonnet",
  ADMIN_USAGE_PATH: usagePath,
  EMPLOYEE_PORTAL_BIND: "127.0.0.1",
  EMPLOYEE_PORTAL_PORT: "3007",
  EMPLOYEE_PORTAL_PUBLIC_URL: portalBase,
  EMPLOYEE_PORTAL_SERVICE_TOKEN: secrets.portal,
  EMPLOYEE_PORTAL_STORE_PATH: path.join(dataDir, "employee-portal.json"),
  EMPLOYEE_PORTAL_USAGE_STORE_PATH: path.join(dataDir, "employee-usage.json"),
  EMPLOYEE_PORTAL_TICKET_STORE_PATH: path.join(dataDir, "employee-tickets.json"),
});

const oidc = createOidc();
const auth = createAuth();
await listen(oidc, 3444);
await listen(auth, 3446);

const { loadConfig } = await import("../admin-service/src/config.js");
const { createEnterpriseAdminServer } = await import("../admin-service/src/service.js");
const { loadConfig: loadPortalConfig } = await import("../employee-portal/src/config.js");
const { createEmployeePortalServer } = await import("../employee-portal/src/service.js");

const adminConfig = loadConfig(process.env);
const portalConfig = loadPortalConfig(process.env);
const admin = await createEnterpriseAdminServer(adminConfig);
const portal = await createEmployeePortalServer(portalConfig);
await listen(admin.server, 3445);
await listen(portal.server, 3007);

console.log("Magpie enterprise preview is running");
console.log(`Admin console: ${adminBase}/admin`);
console.log(`Employee portal: ${portalBase}/`);
console.log("Preview login is automatic: admin@corp.example");
