// A local development stack of the enterprise server services.
//
//   node build/dev-server.mjs          start (logs under build/server-dev/logs)
//   node build/dev-server.mjs --stop   stop what this script started
//
// No Docker is needed. The model gateway, gateway-control, nginx and a real
// IdP are not part of this stack: employee OIDC sign-in and key issuance
// need them. Everything else answers on 127.0.0.1.

import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "..");
const STATE = path.join(HERE, "server-dev");
const LOGS = path.join(STATE, "logs");
const SECRETS_FILE = path.join(STATE, "secrets.json");
const PIDS_FILE = path.join(STATE, "pids.json");
const KEY_FILE = path.join(STATE, "signing-key.pem");

// 3450 is left alone: a running magpie uses it for its administration
// listener, and a health answer there is not this stack's.
const SERVICES = [
  { id: "oidc", script: "devtools/dev-oidc.mjs", port: 3999, health: "/healthz", expect: "dev-oidc" },
  { id: "auth", dir: "auth-service", port: 3444, health: "/healthz", expect: '"service":"auth"' },
  { id: "admin", dir: "admin-service", port: 3445, health: "/healthz", expect: '"service":"admin"' },
  { id: "resource", dir: "resource-service", port: 3447, health: "/healthz", expect: "resource-service" },
  { id: "mcp", dir: "mcp-gateway", port: 3448, health: "/healthz", expect: "mcp-gateway" },
  { id: "audit", dir: "audit-service", port: 3449, health: "/healthz", expect: "audit-service" },
  { id: "security", dir: "security-service", port: 3452, health: "/healthz", expect: "security-service" },
  { id: "portal", dir: "employee-portal", port: 3007, health: "/healthz", expect: "employee-portal" },
];

function secret(name) {
  return `${name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${crypto.randomBytes(24).toString("hex")}`;
}

function loadSecrets() {
  fs.mkdirSync(STATE, { recursive: true });
  if (fs.existsSync(SECRETS_FILE)) {
    return JSON.parse(fs.readFileSync(SECRETS_FILE, "utf8"));
  }
  const values = {
    AUTH_COOKIE_SECRET: secret("auth cookie"),
    AUTH_ADMIN_TOKEN: secret("auth admin"),
    AUTH_INTERNAL_ADMIN_TOKEN: secret("auth internal"),
    GATEWAY_CONTROL_TOKEN: secret("gateway control"),
    OIDC_CLIENT_SECRET: secret("oidc client"),
    SYNC_TOKEN_SECRET: secret("sync token"),
    ADMIN_SESSION_SECRET: secret("admin session"),
    ADMIN_OIDC_CLIENT_SECRET: secret("admin oidc"),
    RESOURCE_SERVICE_TOKEN: secret("resource service"),
    SECURITY_INGEST_TOKEN: secret("security ingest"),
    SECURITY_READ_TOKEN: secret("security read"),
    SECURITY_CONTROL_TOKEN: secret("security control"),
    AUDIT_SERVICE_TOKEN: secret("audit service"),
    MCP_SERVICE_TOKEN: secret("mcp service"),
    EMPLOYEE_PORTAL_SERVICE_TOKEN: secret("employee portal"),
    MAGPIE_ISSUER_KEY: secret("magpie issuer"),
  };
  fs.writeFileSync(SECRETS_FILE, `${JSON.stringify(values, null, 2)}\n`, { mode: 0o600 });
  return values;
}

function ensureSigningKey() {
  if (fs.existsSync(KEY_FILE)) return;
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(KEY_FILE, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
}


function serviceEnv(id, secrets) {
  const env = { ...process.env, NODE_ENV: "development", ...secrets };
  env.RESOURCE_SIGNING_PRIVATE_KEY_PATH = KEY_FILE;
  env.RESOURCE_SIGNING_KEY_ID = "dev-signing-key";
  env.RESOURCE_SYNC_TOKEN_SECRET = secrets.SYNC_TOKEN_SECRET;
  env.SYNC_TOKEN_SECRET = secrets.SYNC_TOKEN_SECRET;
  env.SYNC_TOKEN_AUDIENCE = "magpie-enterprise-resource";
  const data = (name) => path.join(STATE, name);
  if (id === "auth") Object.assign(env, {
    AUTH_BIND: "127.0.0.1",
    AUTH_PORT: "3444",
    AUTH_PUBLIC_URL: "http://127.0.0.1:3444",
    AUTH_SECURE_COOKIE: "false",
    AUTH_STORE_PATH: data("auth-store.json"),
    AUTH_ALLOWED_RETURN_ORIGINS: "http://127.0.0.1:3445",
    OIDC_ISSUER: "http://127.0.0.1:3999",
    OIDC_CLIENT_ID: "magpie-enterprise",
    OIDC_REDIRECT_URI: "http://127.0.0.1:3444/oauth/callback",
    OIDC_ALLOWED_EMAIL_DOMAINS: "corp.example",
    GATEWAY_CONTROL_URL: "http://127.0.0.1:3446",
    MAGPIE_GATEWAY_URL: "http://127.0.0.1:3425",
    MAGPIE_GATEWAY_PUBLIC_URL: "http://127.0.0.1:3425",
    MAGPIE_KEY_TTL: "8h",
    MAGPIE_KEY_MODELS: "deepseek/deepseek-chat",
    SYNC_TOKEN_TTL_SECONDS: "300",
  });
  if (id === "admin") Object.assign(env, {
    ADMIN_BIND: "127.0.0.1",
    ADMIN_PORT: "3445",
    ADMIN_PUBLIC_URL: "http://127.0.0.1:3445",
    ADMIN_SECURE_COOKIE: "false",
    ADMIN_STORE_PATH: data("admin-store.json"),
    ADMIN_USAGE_PATH: data("usage.jsonl"),
    ADMIN_ALLOWED_IPS: "127.0.0.1/32,::1/128",
    ADMIN_MODELS: "deepseek/deepseek-chat",
    ADMIN_BOOTSTRAP_EMAILS: "admin@corp.example",
    ADMIN_BOOTSTRAP_VALID_HOURS: "24",
    ADMIN_OIDC_ISSUER: "http://127.0.0.1:3999",
    ADMIN_OIDC_CLIENT_ID: "magpie-enterprise-admin",
    ADMIN_OIDC_REDIRECT_URI: "http://127.0.0.1:3445/admin/oauth/callback",
    ADMIN_ALLOWED_EMAIL_DOMAINS: "corp.example",
    ADMIN_REQUIRE_MFA: "false",
    ADMIN_REQUIRE_VERIFIED_EMAIL: "false",
    ADMIN_AUTH_SERVICE_URL: "http://127.0.0.1:3444",
    ADMIN_AUTH_SERVICE_TOKEN: secrets.AUTH_INTERNAL_ADMIN_TOKEN,
    ADMIN_RESOURCE_SERVICE_URL: "http://127.0.0.1:3447",
    ADMIN_RESOURCE_SERVICE_TOKEN: secrets.RESOURCE_SERVICE_TOKEN,
    ADMIN_SECURITY_SERVICE_URL: "http://127.0.0.1:3452",
    ADMIN_SECURITY_SERVICE_TOKEN: secrets.SECURITY_READ_TOKEN,
    ADMIN_NOTIFICATION_CHANNELS_ENABLED: "false",
  });
  if (id === "resource") Object.assign(env, {
    RESOURCE_BIND: "127.0.0.1",
    RESOURCE_PORT: "3447",
    RESOURCE_STORE_PATH: data("resource-store.json"),
    RESOURCE_CONTENT_PATH: data("objects"),
    RESOURCE_SYNC_REPORT_PATH: data("sync-reports.json"),
  });
  if (id === "mcp") Object.assign(env, {
    MCP_BIND: "127.0.0.1",
    MCP_PORT: "3448",
    MCP_PUBLIC_URL: "http://127.0.0.1:3448",
    MCP_STORE_PATH: data("mcp-registry.json"),
    MCP_AUDIT_PATH: data("mcp-audit.jsonl"),
  });
  if (id === "audit") Object.assign(env, {
    AUDIT_BIND: "127.0.0.1",
    AUDIT_PORT: "3449",
    AUDIT_STORE_PATH: data("audit-store.json"),
  });
  if (id === "security") Object.assign(env, {
    SECURITY_BIND: "127.0.0.1",
    SECURITY_PORT: "3452",
    SECURITY_STORE_PATH: data("security-store.json"),
  });
  if (id === "portal") Object.assign(env, {
    EMPLOYEE_PORTAL_BIND: "127.0.0.1",
    EMPLOYEE_PORTAL_PORT: "3007",
    EMPLOYEE_PORTAL_STORE_PATH: data("employee-portal.json"),
    EMPLOYEE_PORTAL_USAGE_STORE_PATH: data("portal-usage.json"),
    EMPLOYEE_PORTAL_TICKET_STORE_PATH: data("portal-tickets.json"),
    ADMIN_SERVICE_URL: "http://127.0.0.1:3445",
  });
  return env;
}

async function healthy(service) {
  try {
    const response = await fetch(`http://127.0.0.1:${service.port}${service.health}`, {
      signal: AbortSignal.timeout(1200),
    });
    if (!response.ok) return false;
    const text = await response.text();
    return text.includes(service.expect);
  } catch {
    return false;
  }
}

async function stop() {
  if (!fs.existsSync(PIDS_FILE)) {
    console.log("nothing to stop");
    return;
  }
  const pids = JSON.parse(fs.readFileSync(PIDS_FILE, "utf8"));
  for (const [id, pid] of Object.entries(pids)) {
    try {
      process.kill(pid);
      console.log(`stopped ${id} (${pid})`);
    } catch (error) {
      console.log(`${id} (${pid}): ${error.code || error.message}`);
    }
  }
  fs.rmSync(PIDS_FILE, { force: true });
}

async function main() {
  if (process.argv.includes("--stop")) return stop();
  await fsp.mkdir(LOGS, { recursive: true });
  ensureSigningKey();
  // The management service reads the gateway's usage ledger; an empty file
  // is a readable ledger, a missing one is a storage error.
  fs.closeSync(fs.openSync(path.join(STATE, "usage.jsonl"), "a"));
  const secrets = loadSecrets();
  const previousPids = fs.existsSync(PIDS_FILE)
    ? JSON.parse(fs.readFileSync(PIDS_FILE, "utf8"))
    : {};
  const pids = {};
  const children = [];

  for (const service of SERVICES) {
    if (await healthy(service)) {
      if (previousPids[service.id]) pids[service.id] = previousPids[service.id];
      console.log(`${service.id.padEnd(9)} already listening on ${service.port}`);
      continue;
    }
    const fd = fs.openSync(path.join(LOGS, `${service.id}.log`), "a");
    const child = spawn(process.execPath, [service.script || "src/server.js"], {
      cwd: service.script ? REPO : path.join(REPO, "enterprise", service.dir),
      env: serviceEnv(service.id, secrets),
      stdio: ["ignore", fd, fd],
      detached: true,
      windowsHide: true,
    });
    child.unref();
    children.push({ service, child });
    pids[service.id] = child.pid;
    console.log(`${service.id.padEnd(9)} starting on ${service.port} (pid ${child.pid})`);
  }

  fs.writeFileSync(PIDS_FILE, `${JSON.stringify(pids, null, 2)}\n`);

  const deadline = Date.now() + 15_000;
  const pending = new Set(children.map((c) => c.service.id));
  while (pending.size > 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 400));
    for (const id of [...pending]) {
      const service = SERVICES.find((s) => s.id === id);
      if (await healthy(service)) pending.delete(id);
    }
  }

  console.log("\nstate:");
  for (const service of SERVICES) {
    const entry = children.find((c) => c.service.id === service.id);
    const ok = await healthy(service);
    const note = ok ? "ready" : entry ? "NOT READY" : "already running";
    console.log(`  ${service.id.padEnd(9)} http://127.0.0.1:${service.port}  ${note}`);
  }
  if (pending.size > 0) {
    console.log("\nfailed to start: " + [...pending].join(", "));
    for (const id of pending) {
      const entry = children.find((c) => c.service.id === id);
      if (!entry) continue;
      const text = await fsp.readFile(path.join(LOGS, `${id}.log`), "utf8");
      console.log(`\n--- ${id}.log (tail) ---`);
      console.log(text.split("\n").slice(-15).join("\n"));
    }
  }
  console.log(`\nlogs: ${LOGS}`);
  console.log("stop: node devtools/dev-server.mjs --stop");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
