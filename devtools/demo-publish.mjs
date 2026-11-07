// A runnable end-to-end demo: real resource-service + real admin-service,
// an administrator publishes resources through the admin API, a device's
// sync token fetches the desired state, and the real client-sync engine
// writes them into Claude Code's and Codex's files.
//
// The administrator session is seeded directly (no IdP is running here);
// everything after that is the production code path.

import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { loadConfig as loadResourceConfig } from "../enterprise/resource-service/src/config.js";
import { createResourceServer } from "../enterprise/resource-service/src/service.js";
import { loadConfig as loadAdminConfig } from "../enterprise/admin-service/src/config.js";
import { createEnterpriseAdminServer } from "../enterprise/admin-service/src/service.js";
import { randomToken, sha256, signCookie } from "../enterprise/admin-service/src/security.js";
import { mintSyncToken } from "../enterprise/lib/sync-token.js";
import { ClientSyncEngine } from "../enterprise/client-sync/src/index.js";

const ROOT = await fs.mkdtemp(path.join(os.tmpdir(), "magpie-publish-demo-"));
const RESOURCE_TOKEN = ["demo", "resource", "service", "token"].join("-").padEnd(40, "x");
const SYNC_SECRET = ["demo", "sync", "token", "secret"].join("-").padEnd(40, "y");
const ADMIN_SECRET = ["demo", "admin", "session", "secret"].join("-").padEnd(40, "z");
const OIDC_SECRET = ["demo", "oidc", "client", "secret"].join("-").padEnd(40, "o");
const AUTH_TOKEN = ["demo", "auth", "service", "token"].join("-").padEnd(40, "a");
const ORG = "org-engineering";
const UA = "magpie-demo/1.0";

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}`));
  });
}

// 1. The resource service, with a fresh signing key.
const keyPath = path.join(ROOT, "signing-key.pem");
const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
await fs.writeFile(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
const resourceConfig = loadResourceConfig({
  RESOURCE_BIND: "127.0.0.1",
  RESOURCE_PORT: "3447",
  RESOURCE_SERVICE_TOKEN: RESOURCE_TOKEN,
  RESOURCE_SYNC_TOKEN_SECRET: SYNC_SECRET,
  RESOURCE_SYNC_TOKEN_AUDIENCE: "magpie-enterprise-resource",
  RESOURCE_SIGNING_PRIVATE_KEY_PATH: keyPath,
  RESOURCE_SIGNING_KEY_ID: "demo-signing-key",
  RESOURCE_STORE_PATH: path.join(ROOT, "resource-store.json"),
  RESOURCE_CONTENT_PATH: path.join(ROOT, "objects"),
  RESOURCE_SYNC_REPORT_PATH: path.join(ROOT, "sync-reports.json"),
});
const { server: resourceServer } = await createResourceServer(resourceConfig);
const resourceBase = await listen(resourceServer);

// 2. The management service, pointed at it. OIDC is configured but never
// called: the demo seeds its administrator session directly.
const adminConfig = loadAdminConfig({
  ADMIN_PORT: "3999",
  ADMIN_PUBLIC_URL: "http://127.0.0.1:3999",
  ADMIN_SESSION_SECRET: ADMIN_SECRET,
  ADMIN_SECURE_COOKIE: "false",
  ADMIN_STORE_PATH: path.join(ROOT, "admin-store.json"),
  ADMIN_ALLOWED_IPS: "127.0.0.1/32",
  ADMIN_OIDC_ISSUER: "http://127.0.0.1:9",
  ADMIN_OIDC_CLIENT_ID: "demo-admin",
  ADMIN_OIDC_CLIENT_SECRET: OIDC_SECRET,
  ADMIN_OIDC_REDIRECT_URI: "http://127.0.0.1:3999/admin/oauth/callback",
  ADMIN_BOOTSTRAP_EMAILS: "admin@corp.example",
  ADMIN_AUTH_SERVICE_URL: "http://127.0.0.1:9",
  ADMIN_AUTH_SERVICE_TOKEN: AUTH_TOKEN,
  ADMIN_RESOURCE_SERVICE_URL: resourceBase,
  ADMIN_RESOURCE_SERVICE_TOKEN: RESOURCE_TOKEN,
  ADMIN_USAGE_PATH: path.join(ROOT, "usage.jsonl"),
  ADMIN_MODELS: "deepseek/deepseek-chat",
  ADMIN_NOTIFICATION_CHANNELS_ENABLED: "false",
});
const admin = await createEnterpriseAdminServer(adminConfig);
const adminBase = await listen(admin.server);

const subjectId = `adm_${sha256("demo|admin").slice(0, 24)}`;
const sid = `asess_${randomToken(32)}`;
const csrf = randomToken(32);
const now = new Date();
await admin.store.mutate((data) => {
  data.adminSessions[sha256(sid)] = {
    subjectId,
    subject: "demo-admin",
    email: "admin@corp.example",
    name: "Demo Admin",
    createdAt: now.toISOString(),
    lastSeenAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3600_000).toISOString(),
    ip: "127.0.0.1",
    userAgentHash: sha256(UA),
    csrfHash: sha256(csrf),
    revokedAt: "",
  };
  data.roleBindings["rb_demo_super_admin"] = {
    id: "rb_demo_super_admin",
    subjectType: "admin",
    subjectId,
    role: "super_admin",
    scopeOrgUnitId: "*",
    validFrom: new Date(now.getTime() - 3600_000).toISOString(),
    validTo: new Date(now.getTime() + 86_400_000).toISOString(),
  };
});
const cookie = `${adminConfig.sessionCookieName}=${encodeURIComponent(signCookie(sid, adminConfig.sessionSecret))}`;
// A second administrator to approve: the requester cannot decide their own.
const approverSubjectId = `adm_${sha256("demo|approver").slice(0, 24)}`;
const approverSid = `asess_${randomToken(32)}`;
const approverCsrf = randomToken(32);
const approverUA = "magpie-demo-approver/1.0";
await admin.store.mutate((data) => {
  data.adminSessions[sha256(approverSid)] = {
    subjectId: approverSubjectId,
    subject: "demo-approver",
    email: "approver@corp.example",
    name: "Demo Approver",
    createdAt: now.toISOString(),
    lastSeenAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 3600_000).toISOString(),
    ip: "127.0.0.1",
    userAgentHash: sha256(approverUA),
    csrfHash: sha256(approverCsrf),
    revokedAt: "",
  };
  data.roleBindings["rb_demo_approver"] = {
    id: "rb_demo_approver",
    subjectType: "admin",
    subjectId: approverSubjectId,
    role: "super_admin",
    scopeOrgUnitId: "*",
    validFrom: new Date(now.getTime() - 3600_000).toISOString(),
    validTo: new Date(now.getTime() + 86_400_000).toISOString(),
  };
});
const approverCookie = `${adminConfig.sessionCookieName}=${encodeURIComponent(signCookie(approverSid, adminConfig.sessionSecret))}`;

async function approve(approvalId) {
  const response = await fetch(`${adminBase}/api/v1/admin/approvals/${approvalId}/decisions`, {
    method: "POST",
    headers: {
      cookie: approverCookie,
      origin: adminConfig.publicUrl,
      "content-type": "application/json",
      "x-csrf-token": approverCsrf,
      "user-agent": approverUA,
    },
    body: JSON.stringify({ decision: "approve", reason: "Reviewed the release" }),
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) throw new Error(`approve -> ${response.status} ${JSON.stringify(payload)}`);
  return payload;
}

async function adminPost(pathname, body) {
  const response = await fetch(`${adminBase}${pathname}`, {
    method: "POST",
    headers: {
      cookie,
      origin: adminConfig.publicUrl,
      "content-type": "application/json",
      "x-csrf-token": csrf,
      "user-agent": UA,
    },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(`${pathname} -> ${response.status} ${JSON.stringify(payload)}`);
  }
  return payload;
}

// 3. Publish a set that exercises every kind.
const REASON = "Pilot onboarding";
const RELEASES = [
  {
    kind: "instructions",
    name: "Engineering baseline",
    content: "# Baseline\n\nUse only approved tools.\n",
  },
  {
    kind: "skill",
    name: "Release checklist",
    content: "---\nname: release-check\ndescription: Check a release\n---\n\n1. Run the tests.\n2. Read the diff.\n",
  },
  {
    kind: "subagent",
    name: "Reviewer",
    content: "---\nname: reviewer\n---\n\nReview the diff and report risks.\n",
  },
  {
    kind: "mcp",
    name: "Context7",
    content: JSON.stringify({ name: "context7", command: "npx", args: ["-y", "@upstash/context7-mcp"] }),
  },
  {
    kind: "hook",
    name: "Turn-end notice",
    content: JSON.stringify({ event: "turn-end", command: "notify-send 'magpie: turn finished'" }),
  },
  {
    kind: "redact",
    name: "Acme key rule",
    content: JSON.stringify({
      schemaVersion: 1,
      requireBaseline: true,
      rules: [{ kind: "acme key", prefix: "acme_" }],
    }),
  },
];

console.log(`resource-service ${resourceBase}`);
console.log(`admin-service    ${adminBase}\n`);
console.log("Publisher: admin@corp.example (super_admin), reason: " + REASON + "\n");

for (const release of RELEASES) {
  const created = await adminPost("/api/v1/admin/resources", {
    kind: release.kind,
    name: release.name,
    deliveryMode: "forced",
    assignments: [ORG],
    compatibility: { minClientVersion: "1.0.0" },
    reason: REASON,
  });
  const candidate = await adminPost(
    `/api/v1/admin/resources/${created.resource.id}/releases`,
    {
      resourceVersion: "2026.11.1",
      content: release.content,
      reason: REASON,
      expectedUpdatedAt: created.resource.updatedAt,
    },
  );
  const request = await adminPost("/api/v1/admin/approvals", {
    action: "resource.publish",
    targetId: created.resource.id,
    reason: REASON,
    releaseId: candidate.release.id,
    expectedUpdatedAt: candidate.resource.updatedAt,
  });
  const approvalId = request.approval.approvalId;
  await approve(approvalId);
  const published = await adminPost(
    `/api/v1/admin/resources/${created.resource.id}/publish`,
    {
      releaseId: candidate.release.id,
      approvalId,
      reason: REASON,
      expectedUpdatedAt: candidate.resource.updatedAt,
    },
  );
  console.log(
    `published ${release.kind.padEnd(12)} ${release.name.padEnd(22)} `
      + `${published.resource.id} / ${published.release.resourceVersion} (${published.release.mediaType}) `
      + `approval ${approvalId.slice(0, 12)}…`,
  );
}

// 4. A device of that organization fetches the desired state with a sync
// token minted exactly as auth-service mints one.
const sync = mintSyncToken({
  secret: SYNC_SECRET,
  userId: "usr_demo",
  deviceId: "dev_demo",
  organizationIds: [ORG],
  ttlSeconds: 300,
  audience: "magpie-enterprise-resource",
});
const desiredResponse = await fetch(`${resourceBase}/api/v1/client/sync/desired-state`, {
  headers: { authorization: `Bearer ${sync.token}` },
});
const desired = await desiredResponse.json();
console.log(
  `\ndesired-state ${desiredResponse.status}: ${desired.resources.length} resources, `
    + `revision ${desired.revision.slice(0, 23)}…`,
);

const keyInfoResponse = await fetch(`${resourceBase}/api/v1/admin/signing-key`, {
  headers: { authorization: `Bearer ${RESOURCE_TOKEN}` },
});
const { signingKey } = await keyInfoResponse.json();

// 5. The real sync engine writes them into the agents' own files.
const home = path.join(ROOT, "home");
const engine = new ClientSyncEngine({
  rootDir: path.join(ROOT, "managed"),
  publicKeys: { [signingKey.keyId]: signingKey.publicKeyPem },
  keyFingerprints: { [signingKey.keyId]: signingKey.fingerprint },
  clientVersion: "1.4.0",
  fetchDesiredState: async () => ({
    schemaVersion: desired.schemaVersion,
    revision: desired.revision,
    generatedAt: desired.generatedAt,
    resources: desired.resources.map(({ manifest, contentBase64 }) => ({
      manifest,
      content: Buffer.from(contentBase64, "base64"),
    })),
  }),
  agents: {
    claude: path.join(home, ".claude"),
    codex: path.join(home, ".codex"),
  },
  managedRedactPath: path.join(ROOT, "magpie-config", "managed-redact.json"),
});
const result = await engine.syncOnce();
console.log(
  `sync ${result.status}: applied ${(result.applied || []).length}, errors ${(result.applyErrors || []).length}`,
);
for (const error of result.applyErrors || []) console.log(`  applyError ${error.resourceId}: ${error.code}`);

async function tree(dir, prefix = "") {
  const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const full = path.join(dir, entry.name);
    console.log(`${prefix}${entry.isDirectory() ? "[d] " : "    "}${path.relative(ROOT, full)}`);
    if (entry.isDirectory()) await tree(full, `${prefix}  `);
  }
}
await tree(home);
await tree(path.join(ROOT, "magpie-config"));

console.log("\n--- home/.claude/settings.json (hook) ---");
console.log(await fs.readFile(path.join(home, ".claude", "settings.json"), "utf8"));
console.log("--- magpie-config/managed-redact.json ---");
console.log(await fs.readFile(path.join(ROOT, "magpie-config", "managed-redact.json"), "utf8"));
console.log("--- home/.codex/config.toml (MCP) ---");
console.log(await fs.readFile(path.join(home, ".codex", "config.toml"), "utf8"));

await new Promise((resolve) => admin.server.close(resolve));
await new Promise((resolve) => resourceServer.close(resolve));
console.log(`\ndemo files under ${ROOT}`);
