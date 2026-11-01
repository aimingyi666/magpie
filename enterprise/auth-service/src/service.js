import http from "node:http";
import crypto from "node:crypto";
import { OidcClient, normalizeIdentity } from "./oidc.js";
import { MagpieKeyClient, MagpieKeyClientError } from "./magpie.js";
import { GatewayControlClient, GatewayControlError } from "./gateway-control.js";
import {
  parseCookies,
  pkceChallenge,
  randomToken,
  safeEqual,
  sha256,
  signCookie,
  verifyCookie,
} from "./security.js";
import { JsonStore } from "./store.js";
import {
  PolicyValidationError,
  createUnknownPolicy,
  policyIsComplete,
  policyIsKnown,
  policyMissing,
  policySections,
  policyStatusView,
  publicPolicy,
  samePolicyContent,
  validateLimits,
  validateModels,
} from "./policy.js";

const MAX_BODY = 64 * 1024;
const HANDOFF_TTL_MS = 2 * 60 * 1000;
const POLICY_SYNC_STATES = new Set(["pending", "synced", "failed", "partial", "unknown"]);

class HttpError extends Error {
  constructor(statusCode, code, message, details = {}) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

function apiError(res, requestId, statusCode, code, message, details = {}) {
  res.writeHead(statusCode, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify({ error: { ...details, code, message, requestId } }));
}

const SAFE_ERROR_DETAIL_KEYS = new Set([
  "credentialId",
  "currentVersion",
  "deviceId",
  "expectedVersion",
  "including",
  "missing",
  "operationId",
  "policySyncState",
  "policyVersion",
]);

function safeErrorDetails(details) {
  const out = {};
  if (!details || typeof details !== "object" || Array.isArray(details)) return out;
  for (const [key, value] of Object.entries(details)) {
    if (!SAFE_ERROR_DETAIL_KEYS.has(key)) continue;
    if (value == null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      out[key] = value;
      continue;
    }
    if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) {
      out[key] = [...value];
    }
  }
  return out;
}

function json(res, statusCode, value, headers = {}) {
  res.writeHead(statusCode, { "content-type": "application/json; charset=utf-8", ...headers });
  res.end(JSON.stringify(value));
}

function redirect(res, location, headers = {}) {
  res.writeHead(302, { ...headers, location });
  res.end();
}

function bearer(req) {
  const match = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || "").trim());
  return match ? match[1].trim() : "";
}

function cleanText(value, name, maxLength, required = true) {
  const text = String(value || "").replace(/[\u0000-\u001f\u007f]/g, "").trim();
  if (required && !text) throw new HttpError(400, "invalid_request", `${name} is required`);
  if ([...text].length > maxLength) throw new HttpError(400, "invalid_request", `${name} is too long`);
  return text;
}

function clientIp(req) {
  return String(req.socket.remoteAddress || "");
}

function cookieHeader(config, value, maxAge) {
  const secure = config.secureCookie ? "; Secure" : "";
  return `${config.cookieName}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

function clientFlowAllowed(returnTo, config) {
  let target;
  try {
    target = new URL(returnTo);
  } catch {
    return false;
  }
  if (target.protocol !== "http:") return false;
  const origin = target.origin;
  if (config.allowedReturnOrigins.includes(origin)) return true;
  return target.hostname === "127.0.0.1" || target.hostname === "::1" || target.hostname === "localhost";
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    status: user.status,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt,
    policy: publicPolicy(user.gatewayPolicy),
  };
}

function publicDevice(device) {
  return {
    id: device.id,
    userId: device.userId,
    name: device.name,
    platform: device.platform,
    clientVersion: device.clientVersion,
    status: device.status,
    createdAt: device.createdAt,
    lastSeenAt: device.lastSeenAt,
    gatewayKeyId: device.gatewayKeyId,
    keyExpiresAt: device.gatewayKeyExpiresAt,
  };
}

function publicCredential(credential, devices) {
  const device = devices[credential.deviceId];
  return {
    id: credential.id,
    userId: credential.userId,
    deviceId: credential.deviceId,
    deviceName: device?.name || "",
    deviceStatus: device?.status || "unknown",
    status: credential.status,
    createdAt: credential.createdAt || "",
    expiresAt: credential.expiresAt || "",
    revokedAt: credential.revokedAt || "",
    deviceTokenExpiresAt: device?.tokenExpiresAt || "",
    lastSeenAt: device?.lastSeenAt || "",
    publicKeySha256: device?.publicKeySha256 || "",
    models: Array.isArray(credential.models) ? credential.models : [],
    policyVersion: Number.isSafeInteger(credential.policyVersion) ? credential.policyVersion : 0,
    policySyncState: POLICY_SYNC_STATES.has(credential.policySyncState)
      ? credential.policySyncState
      : "pending",
    lastPolicyResult: credential.lastPolicyResult || credential.policySyncState || "pending",
    lastPolicyErrorCode: credential.lastPolicyErrorCode || "",
    lastPolicyAttemptedAt: credential.lastPolicyAttemptedAt || "",
    lastPolicySyncedAt: credential.lastPolicySyncedAt || "",
    lastPolicyOperationId: credential.lastPolicyOperationId || "",
    lastPolicyGatewayRequestId: credential.lastPolicyGatewayRequestId || "",
    lastPolicyRevision: credential.lastPolicyRevision || "",
  };
}

function publicSelfView(data, user) {
  const devices = Object.values(data.devices)
    .filter((device) => device.userId === user.id)
    .map(publicDevice);
  const credentials = Object.values(data.credentials)
    .filter((credential) => credential.userId === user.id)
    .map((credential) => publicCredential(credential, data.devices));
  const activeCredentials = credentials.filter((credential) => credential.status === "active");
  return {
    user: publicUser(user),
    devices,
    credentials,
    evidence: {
      policyKnown: policyIsKnown(user.gatewayPolicy),
      activeCredentialCount: activeCredentials.length,
      activeCredentialsSynced: activeCredentials.length > 0 && activeCredentials.every(
        (credential) => credential.policyVersion === user.gatewayPolicy?.version
          && credential.policySyncState === "synced",
      ),
      confirmedAt: user.gatewayPolicy?.confirmedAt || "",
    },
  };
}

function keyName(user, deviceName) {
  const value = `Enterprise · ${user.email} · ${deviceName}`;
  return [...value].slice(0, 120).join("");
}

function policyGateError(policy) {
  const sections = policySections(policy);
  if (sections.missing.length > 0) {
    return new HttpError(
      409,
      "policy_setup_required",
      "An administrator must set both quota and models before this user can receive a gateway key",
      { ...sections, policyVersion: Number.isSafeInteger(policy?.version) ? policy.version : 0 },
    );
  }
  return null;
}

function requireCompletePolicy(user) {
  const error = policyGateError(user.gatewayPolicy);
  if (error) throw error;
}

function expectedVersion(req, body) {
  const value = body.expectedVersion;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new HttpError(400, "version_required", "expectedVersion must be the user's current policy version");
  }
  const ifMatch = String(req.headers["if-match"] || "").trim();
  if (ifMatch) {
    const match = /^(?:W\/)?"?(\d+)"?$/.exec(ifMatch);
    if (!match || Number(match[1]) !== value) {
      throw new HttpError(
        409,
        "policy_version_conflict",
        "If-Match does not match expectedVersion",
        { expectedVersion: value },
      );
    }
  }
  return value;
}

function policyOperationId(body) {
  if (body.operationId == null || body.operationId === "") {
    return `op_${crypto.randomUUID()}`;
  }
  const operationId = cleanText(body.operationId, "operationId", 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(operationId)) {
    throw new HttpError(400, "invalid_request", "operationId is not a safe operation identifier");
  }
  return operationId;
}

function policyValidationHttpError(error) {
  if (error instanceof PolicyValidationError) {
    return new HttpError(400, error.code, error.message);
  }
  return error;
}

function requireJsonObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "invalid_request", "Request body must be a JSON object");
  }
  return value;
}

function activeCredentialsForUser(data, userId) {
  return Object.values(data.credentials).filter(
    (credential) => credential.userId === userId && credential.status === "active",
  );
}

function assertPolicyVersion(policy, expected) {
  if (policy.version !== expected) {
    throw new HttpError(
      409,
      "policy_version_conflict",
      "The user policy changed; reload it and retry",
      { currentVersion: policy.version, expectedVersion: expected },
    );
  }
}

function policyUser(data, userId) {
  const user = data.users[userId];
  if (!user) throw new HttpError(404, "user_not_found", "User not found");
  return user;
}

function markActiveCredentialsPending(userId, data, operationId, now) {
  for (const credential of activeCredentialsForUser(data, userId)) {
    credential.policySyncState = "pending";
    credential.lastPolicyErrorCode = "policy_sync_in_progress";
    delete credential.lastPolicySyncedAt;
    credential.lastPolicyOperationId = operationId;
  }
}

function refreshPolicyKnownState(user, data, now) {
  const policy = user.gatewayPolicy;
  const credentials = activeCredentialsForUser(data, user.id);
  const allSynced = credentials.every(
    (credential) => credential.policyVersion === policy.version
      && credential.policySyncState === "synced",
  );
  if (policyIsComplete(policy) && allSynced) {
    policy.quotaStatus = "known";
    policy.modelStatus = "known";
    policy.confirmedAt = now;
    for (const credential of credentials) delete credential.lastPolicyErrorCode;
    return true;
  }
  if (policyIsComplete(policy)) {
    policy.quotaStatus = "pending";
    policy.modelStatus = "pending";
    delete policy.confirmedAt;
  }
  return false;
}

function credentialsSummary(data, user, policyVersion) {
  const credentials = activeCredentialsForUser(data, user.id);
  const pending = credentials.filter(
    (credential) => credential.policyVersion !== policyVersion
      || credential.policySyncState === "pending"
      || credential.policySyncState === "partial",
  ).length;
  const unknown = credentials.filter(
    (credential) => credential.policySyncState === "unknown",
  ).length;
  const failedOnly = credentials.filter(
    (credential) => credential.policySyncState === "failed",
  ).length;
  const failedItems = credentials.filter(
    (credential) => !(credential.policyVersion === policyVersion
      && credential.policySyncState === "synced"),
  ).map((credential) => ({
    credentialId: credential.id,
    deviceId: credential.deviceId,
    errorCode: credential.lastPolicyErrorCode || "policy_sync_in_progress",
  }));
  const succeeded = credentials.filter(
    (credential) => credential.policyVersion === policyVersion
      && credential.policySyncState === "synced",
  ).length;
  return {
    total: credentials.length,
    succeeded,
    failed: credentials.length - succeeded,
    pending,
    unknown,
    failedOnly,
    failedItems,
  };
}

function statusSummary(data) {
  const credentials = Object.values(data.credentials);
  const active = credentials.filter((credential) => credential.status === "active");
  const issuanceJournal = Object.fromEntries(
    ["preparing", "issued", "syncing", "synced", "committed", "failed", "unknown"]
      .map((state) => [
        state,
        data.issuanceJournal.filter((entry) => entry.state === state).length,
      ]),
  );
  const users = Object.values(data.users);
  return {
    activeCredentials: active.length,
    pendingPolicyCredentials: active.filter(
      (credential) => credential.policySyncState === "pending"
        || credential.policySyncState === "partial",
    ).length,
    failedPolicyCredentials: active.filter(
      (credential) => credential.policySyncState === "failed",
    ).length,
    unknownPolicyCredentials: active.filter(
      (credential) => credential.policySyncState === "unknown",
    ).length,
    unknownPolicyUsers: users.filter(
      (user) => user.gatewayPolicy?.quotaStatus === "unknown"
        || user.gatewayPolicy?.modelStatus === "unknown",
    ).length,
    pendingPolicyUsers: users.filter(
      (user) => user.gatewayPolicy?.quotaStatus === "pending"
        || user.gatewayPolicy?.modelStatus === "pending",
    ).length,
    knownPolicyUsers: users.filter((user) => policyIsKnown(user.gatewayPolicy)).length,
    issuanceJournal,
  };
}

function policyWriteResult(operationId, user, data, state = "") {
  const policy = user.gatewayPolicy;
  const resolvedState = state || (policyIsKnown(policy) ? "succeeded" : "pending_sync");
  return {
    operationId,
    state: resolvedState,
    policy: {
      ...publicPolicy(policy),
      ...policyStatusView(policy),
    },
    credentials: credentialsSummary(data, user, policy.version),
    requiresReconciliation: !policyIsKnown(policy),
  };
}

function validateCredentialReadback(value, policy) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "invalid_readback", "readback must be a structured gateway readback");
  }
  const allowed = new Set([
    "schemaVersion",
    "gatewayControlRequestId",
    "observedAt",
    "policyRevision",
    "models",
    "limits",
  ]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      throw new HttpError(400, "invalid_readback", "readback contains an unsupported field");
    }
  }
  if (value.schemaVersion !== 1) {
    throw new HttpError(400, "invalid_readback", "readback.schemaVersion must be 1");
  }
  const gatewayControlRequestId = cleanText(
    value.gatewayControlRequestId,
    "readback.gatewayControlRequestId",
    128,
  );
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(gatewayControlRequestId)) {
    throw new HttpError(400, "invalid_readback", "gatewayControlRequestId is not safe");
  }
  const observedAt = cleanText(value.observedAt, "readback.observedAt", 80);
  const observedTime = Date.parse(observedAt);
  if (!Number.isFinite(observedTime) || observedTime > Date.now() + 5 * 60 * 1000) {
    throw new HttpError(400, "invalid_readback", "observedAt must be a valid RFC3339 time not in the future");
  }
  const policyRevision = cleanText(value.policyRevision, "readback.policyRevision", 160);
  if (!/^[A-Za-z0-9:._-]{8,160}$/.test(policyRevision)) {
    throw new HttpError(400, "invalid_readback", "policyRevision is not a safe revision identifier");
  }

  let models;
  let limits;
  try {
    models = validateModels(value.models);
    limits = validateLimits(value.limits);
  } catch (error) {
    throw policyValidationHttpError(error);
  }
  if (!samePolicyContent(policy, models, limits)) {
    throw new HttpError(
      409,
      "policy_version_conflict",
      "The gateway readback does not match the current user policy",
      { policyVersion: policy.version },
    );
  }
  return {
    gatewayControlRequestId,
    observedAt: new Date(observedTime).toISOString(),
    policyRevision,
  };
}

function updatePolicyPart(user, part, value, operationId, now) {
  const policy = user.gatewayPolicy;
  policy[part] = value;
  policy.version += 1;
  policy.quotaStatus = Array.isArray(policy.limits) ? "pending" : "unknown";
  policy.modelStatus = Array.isArray(policy.models) ? "pending" : "unknown";
  policy.updatedAt = now;
  policy.operationId = operationId;
  delete policy.confirmedAt;
  return policy;
}

function assertIssuancePolicyCurrent(data, userId, policyVersion) {
  const user = policyUser(data, userId);
  requireCompletePolicy(user);
  if (user.gatewayPolicy.version !== policyVersion) {
    throw new HttpError(
      409,
      "policy_version_conflict",
      "The user policy changed while the gateway key was being issued",
      { currentVersion: user.gatewayPolicy.version, expectedVersion: policyVersion },
    );
  }
  return user;
}

function issuancePolicySnapshot(policy) {
  return {
    models: structuredClone(policy.models),
    limits: structuredClone(policy.limits),
  };
}

function credentialPolicyMetadata(policy, now, readback = null) {
  return {
    models: structuredClone(policy.models),
    policyVersion: policy.version,
    policySyncState: "synced",
    lastPolicyResult: "synced",
    lastPolicySyncedAt: readback?.observedAt || now,
    ...(readback?.gatewayControlRequestId
      ? { lastPolicyGatewayRequestId: readback.gatewayControlRequestId }
      : {}),
    ...(readback?.policyRevision ? { lastPolicyRevision: readback.policyRevision } : {}),
    ...(policy.operationId ? { lastPolicyOperationId: policy.operationId } : {}),
  };
}

async function readJson(req) {
  if (!/^application\/json(?:\s*;|$)/i.test(String(req.headers["content-type"] || ""))) {
    throw new HttpError(415, "unsupported_media_type", "Content-Type must be application/json");
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new HttpError(413, "request_too_large", "Request body is too large");
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  } catch {
    throw new HttpError(400, "invalid_json", "Request body must be valid JSON");
  }
}

function credentialRows(credentials) {
  if (credentials.length === 0) return "<p>No credentials have been issued to this account.</p>";
  return `<div class="table-wrap"><table><thead><tr>
    <th>Key</th><th>Device</th><th>Status</th><th>Policy</th><th>Sync</th><th>Last error</th><th>Last synced</th>
  </tr></thead><tbody>${credentials.map((credential) => `<tr>
    <td><code>${escapeHtml(credential.id)}</code></td>
    <td>${escapeHtml(credential.deviceName || credential.deviceId)}</td>
    <td>${escapeHtml(credential.status)}</td>
    <td>v${escapeHtml(credential.policyVersion)}</td>
    <td>${escapeHtml(credential.policySyncState)}</td>
    <td>${escapeHtml(credential.lastPolicyErrorCode || "")}</td>
    <td>${escapeHtml(credential.lastPolicySyncedAt || "")}</td>
  </tr>`).join("")}</tbody></table></div>`;
}

function deviceRows(devices) {
  if (devices.length === 0) return "<p>No active device has joined this account.</p>";
  return `<div class="table-wrap"><table><thead><tr>
    <th>Device</th><th>Platform</th><th>Status</th><th>Last seen</th><th>Key ID</th>
  </tr></thead><tbody>${devices.map((device) => `<tr>
    <td>${escapeHtml(device.name)}</td>
    <td>${escapeHtml(device.platform)}</td>
    <td>${escapeHtml(device.status)}</td>
    <td>${escapeHtml(device.lastSeenAt || "")}</td>
    <td><code>${escapeHtml(device.gatewayKeyId || "")}</code></td>
  </tr>`).join("")}</tbody></table></div>`;
}

function htmlPage(view) {
  if (!view) {
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Magpie Enterprise</title>
  <style>
    body{margin:0;background:#f2efe6;color:#172018;font:18px/1.6 Georgia,serif}
    main{max-width:720px;margin:10vh auto;padding:48px;background:#fffdf5;border:1px solid #d6cfbd;box-shadow:12px 12px 0 #d8c9a6}
    h1{font-size:44px;line-height:1.05;margin:0 0 24px} a{color:#9e2518}
  </style>
</head>
<body><main><h1>Magpie Enterprise</h1>
  <p>Sign in with your company account, or start the Magpie enterprise join command.</p>
  <p><a href="/login">Sign in</a></p>
</main></body>
</html>`;
  }
  const { user, devices, credentials, evidence } = view;
  const policy = user.policy;
  const ready = evidence.policyKnown
    && evidence.activeCredentialsSynced
    && Boolean(evidence.confirmedAt);
  const noActiveCredentials = Number(evidence.activeCredentialCount) === 0;
  const quotaUnknown = !Array.isArray(policy?.limits);
  const modelsUnknown = !Array.isArray(policy?.models);
  const quota = quotaUnknown
    ? "<p><strong>Historical quota unknown.</strong> No value is inferred from old data.</p>"
    : `<ul>${policy.limits.map((limit) => `<li><code>${escapeHtml(limit.period)}</code>`
      + `: ${escapeHtml(limit.tokens)} tokens, $${escapeHtml(limit.cost)}`
      + `${limit.cacheReads ? ", cache reads counted" : ""}</li>`).join("")}</ul>`;
  const models = modelsUnknown
    ? "<p><strong>Historical model scope unknown.</strong> Ask an administrator to set it before joining.</p>"
    : `<ul>${policy.models.map((model) => `<li><code>${escapeHtml(model)}</code></li>`).join("")}</ul>`;
  const stateText = ready
    ? "Policy confirmed after independent gateway readback."
    : policy?.quotaStatus === "pending" || policy?.modelStatus === "pending"
      ? "Policy synchronization is pending. Check the failed credential evidence below."
      : !evidence.policyKnown
        ? "Your policy is incomplete or historical. An administrator must set quota and models."
        : noActiveCredentials
          ? "No active credential has joined yet. Run the enterprise join command on your computer."
          : "Your active credentials have not all confirmed the current policy.";
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Magpie Enterprise</title>
  <style>
    :root{--ink:#172018;--paper:#f2efe6;--card:#fffdf5;--line:#d6cfbd;--accent:#9e2518;--ok:#17643a}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#e8dcc0,transparent 36%),var(--paper);color:var(--ink);font:18px/1.6 Georgia,serif}
    main{max-width:960px;margin:7vh auto;padding:clamp(24px,5vw,52px);background:var(--card);border:1px solid var(--line);box-shadow:12px 12px 0 #d8c9a6}
    h1{font-size:clamp(40px,7vw,68px);line-height:.95;margin:0 0 20px}h2{margin-top:32px;border-bottom:1px solid var(--line);padding-bottom:7px}
    code{background:#e9e1cd;padding:2px 6px;overflow-wrap:anywhere}.status{border-left:5px solid ${ready ? "var(--ok)" : "var(--accent)"};padding:10px 14px;background:#f8f0df}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}.box{border:1px solid var(--line);padding:16px}
    .table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);white-space:nowrap}
    button{border:0;background:var(--ink);color:white;padding:11px 16px;font:700 14px Georgia,serif;cursor:pointer}
  </style>
</head>
<body><main>
  <h1>Magpie Enterprise</h1>
  <p>Signed in as <strong>${escapeHtml(user.email)}</strong>.</p>
  <p class="status">${escapeHtml(stateText)}</p>
  <div class="grid">
    <section class="box"><h2>Identity</h2><p>${escapeHtml(user.name)}<br><code>${escapeHtml(user.id)}</code></p></section>
    <section class="box"><h2>Policy</h2><p>Version ${escapeHtml(policy?.version ?? 0)}</p>
      <p>Quota: <code>${escapeHtml(policy?.quotaStatus || "unknown")}</code><br>
      Models: <code>${escapeHtml(policy?.modelStatus || "unknown")}</code></p>
      <p>Last confirmed: ${escapeHtml(evidence.confirmedAt || "not confirmed")}</p>
    </section>
  </div>
  <h2>Quota</h2>${quota}
  <h2>Authorized models</h2>${models}
  <h2>Credentials</h2>${credentialRows(credentials)}
  <h2>Devices</h2>${deviceRows(devices)}
  <h2>Join another computer</h2>
  <p>Run the enterprise join command on the computer that runs Magpie. The browser never writes Agent files or exposes a Gateway Key.</p>
  <form method="post" action="/api/v1/logout"><button type="submit">Sign out</button></form>
</main></body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export async function createEnterpriseAuthServer(config, options = {}) {
  const store = options.store || new JsonStore(config.storePath);
  await store.load();
  const oidc = options.oidc || new OidcClient(config.oidc);
  const magpie = options.magpie || new MagpieKeyClient(config.magpie);
  const gatewayControl = options.gatewayControl || new GatewayControlClient(config.gatewayControl);
  const handoffs = new Map();
  const rate = new Map();
  const deviceRefreshes = new Map();
  const policyWrites = new Map();

  function serializeByDevice(deviceId, operation) {
    const previous = deviceRefreshes.get(deviceId) || Promise.resolve();
    const current = previous.then(operation, operation);
    deviceRefreshes.set(deviceId, current);
    return current.finally(() => {
      if (deviceRefreshes.get(deviceId) === current) deviceRefreshes.delete(deviceId);
    });
  }

  function serializePolicyWrite(userId, operation) {
    const previous = policyWrites.get(userId) || Promise.resolve();
    const current = previous.then(operation, operation);
    policyWrites.set(userId, current);
    return current.finally(() => {
      if (policyWrites.get(userId) === current) policyWrites.delete(userId);
    });
  }

  async function userForSession(req) {
    const cookies = parseCookies(req.headers.cookie);
    const sid = verifyCookie(cookies[config.cookieName], config.cookieSecret);
    if (!sid) return null;
    return store.read((data) => {
      const session = data.sessions[sha256(sid)];
      if (!session || Date.parse(session.expiresAt) <= Date.now()) return null;
      const user = data.users[session.userId];
      if (!user || user.status !== "active") return null;
      return { sid, session, user };
    });
  }

  async function createSession(userId) {
    const sid = `msess_${randomToken(32)}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + config.sessionTtlSeconds * 1000);
    await store.mutate((data) => {
      data.sessions[sha256(sid)] = {
        userId,
        createdAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
      };
    });
    return { sid, expiresAt };
  }

  function deviceFromToken(data, token) {
    const hash = sha256(token);
    const device = Object.values(data.devices).find((candidate) => candidate.tokenHash === hash);
    if (!device) throw new HttpError(401, "invalid_device_token", "Device token is not valid");
    if (device.status !== "active") throw new HttpError(403, "device_disabled", "This device is not active");
    if (Date.parse(device.tokenExpiresAt) <= Date.now()) {
      throw new HttpError(401, "device_token_expired", "Device token has expired");
    }
    const user = data.users[device.userId];
    if (!user || user.status !== "active") {
      throw new HttpError(403, "user_disabled", "This employee account is not active");
    }
    return { device, user };
  }

  async function requireDevice(req) {
    const token = bearer(req);
    if (!token) throw new HttpError(401, "missing_device_token", "Send Authorization: Bearer <device token>");
    return store.read((data) => deviceFromToken(data, token));
  }

  function issuanceStateForError(error) {
    if (error instanceof GatewayControlError && error.state === "pending") return "unknown";
    if (error instanceof MagpieKeyClientError && error.statusCode >= 500) return "unknown";
    return "failed";
  }

  async function recordIssuanceState(journalId, patch) {
    return store.mutate((data) => {
      const entry = data.issuanceJournal.find((candidate) => candidate.id === journalId);
      if (!entry) throw new Error(`issuance journal ${journalId} disappeared`);
      Object.assign(entry, structuredClone(patch), { updatedAt: new Date().toISOString() });
      return structuredClone(entry);
    });
  }

  function validateIssuedKey(issued, expectedModels) {
    if (!issued || typeof issued !== "object"
      || typeof issued.id !== "string" || !/^[A-Za-z0-9_-]{1,256}$/.test(issued.id)
      || typeof issued.key !== "string" || issued.key.length < 8
      || typeof issued.expires !== "string" || !Number.isFinite(Date.parse(issued.expires))
      || !Array.isArray(issued.models)
      || JSON.stringify(issued.models) !== JSON.stringify(expectedModels)) {
      throw new HttpError(
        502,
        "gateway_policy_unconfirmed",
        "The gateway did not return a usable key with the exact requested model policy",
      );
    }
  }

  async function compensateIssuance(journalId, keyId, error) {
    const state = issuanceStateForError(error);
    try {
      await recordIssuanceState(journalId, {
        state,
        errorCode: String(error?.code || "issuance_failed").slice(0, 128),
        failedAt: new Date().toISOString(),
      });
    } catch (journalError) {
      console.error(`issuance journal ${journalId} could not record failure: ${journalError.message}`);
    }
    if (!keyId) return;
    try {
      await magpie.revoke(keyId);
      await recordIssuanceState(journalId, {
        revokedAt: new Date().toISOString(),
        revocationResult: "revoked",
      });
    } catch (revokeError) {
      console.error(`orphaned gateway key ${keyId} could not be revoked: ${revokeError.message}`);
      try {
        await recordIssuanceState(journalId, {
          state: "unknown",
          revocationResult: "unknown",
          revocationErrorCode: String(revokeError.code || "revocation_failed").slice(0, 128),
        });
      } catch {
        // The original issuance error is the actionable failure.
      }
    }
  }

  async function issueDeviceCredential({ user, deviceId = "", credentialId = "", purpose, deviceName, commit }) {
    const journal = await store.mutate((data) => {
      const currentUser = data.users[user.id];
      if (!currentUser || currentUser.status !== "active") {
        throw new HttpError(403, "user_disabled", "This employee account is not active");
      }
      requireCompletePolicy(currentUser);
      const policy = currentUser.gatewayPolicy;
      const now = new Date().toISOString();
      const entry = {
        id: `eij_${crypto.randomUUID()}`,
        enterpriseIssuanceId: `eiss_${randomToken(24)}`,
        userId: currentUser.id,
        purpose,
        deviceId,
        credentialId,
        policyVersion: policy.version,
        policyOperationId: policy.operationId || "",
        request: {
          name: keyName(currentUser, deviceName),
          models: structuredClone(policy.models),
          limits: structuredClone(policy.limits),
        },
        state: "preparing",
        createdAt: now,
        updatedAt: now,
      };
      data.issuanceJournal.push(entry);
      return structuredClone(entry);
    });

    let issued = null;
    try {
      issued = await magpie.issue({
        name: journal.request.name,
        models: journal.request.models,
        tokens: 0,
        cost: 0,
        enterpriseIssuanceId: journal.enterpriseIssuanceId,
      });
      validateIssuedKey(issued, journal.request.models);
      await recordIssuanceState(journal.id, {
        state: "issued",
        keyId: issued.id,
        keyExpiresAt: issued.expires,
        issuedAt: new Date().toISOString(),
      });
      await recordIssuanceState(journal.id, {
        state: "syncing",
        syncingAt: new Date().toISOString(),
      });
      const readback = await gatewayControl.apply(issued.id, {
        models: journal.request.models,
        limits: journal.request.limits,
      });
      await recordIssuanceState(journal.id, {
        state: "synced",
        gatewayControlRequestId: readback.gatewayControlRequestId,
        policyRevision: readback.policyRevision,
        observedAt: readback.observedAt,
        syncedAt: new Date().toISOString(),
      });

      let committed;
      try {
        committed = await store.mutate((data) => {
          const currentUser = assertIssuancePolicyCurrent(data, user.id, journal.policyVersion);
          if (!samePolicyContent(
            currentUser.gatewayPolicy,
            journal.request.models,
            journal.request.limits,
          )) {
            throw new HttpError(
              409,
              "policy_version_conflict",
              "The user policy changed while the gateway key was being issued",
              {
                currentVersion: currentUser.gatewayPolicy.version,
                expectedVersion: journal.policyVersion,
              },
            );
          }
          const now = new Date().toISOString();
          const result = commit(data, {
            issued: structuredClone(issued),
            journal,
            policy: currentUser.gatewayPolicy,
            readback,
            now,
          });
          const entry = data.issuanceJournal.find((candidate) => candidate.id === journal.id);
          if (!entry) throw new Error(`issuance journal ${journal.id} disappeared`);
          Object.assign(entry, {
            state: "committed",
            committedAt: now,
            updatedAt: now,
          });
          return structuredClone(result);
        });
      } catch (error) {
        throw error;
      }
      return {
        ...committed,
        issued,
        policyVersion: journal.policyVersion,
        policyOperationId: journal.policyOperationId,
        readback,
        issuanceId: journal.enterpriseIssuanceId,
      };
    } catch (error) {
      await compensateIssuance(journal.id, issued?.id || "", error);
      throw error;
    }
  }

  async function recoverIssuanceJournal() {
    const pending = await store.read((data) => data.issuanceJournal
      .filter((entry) => entry.state !== "committed")
      .map((entry) => structuredClone(entry)));
    let recovered = 0;
    let failed = 0;
    for (const entry of pending) {
      let keyId = entry.keyId || "";
      let keyExpiresAt = entry.keyExpiresAt || "";
      if (entry.state === "preparing" || (entry.state === "unknown" && !keyId)) {
        try {
          const issued = await magpie.issue({
            name: entry.request.name,
            models: entry.request.models,
            tokens: 0,
            cost: 0,
            enterpriseIssuanceId: entry.enterpriseIssuanceId,
          });
          validateIssuedKey(issued, entry.request.models);
          keyId = issued.id;
          keyExpiresAt = issued.expires;
          await recordIssuanceState(entry.id, {
            state: "issued",
            keyId,
            keyExpiresAt,
            recoveredIssuedAt: new Date().toISOString(),
          });
        } catch (error) {
          failed += 1;
          try {
            await recordIssuanceState(entry.id, {
              state: "unknown",
              errorCode: String(error?.code || "recovery_issue_unknown").slice(0, 128),
              recoveryFailedAt: new Date().toISOString(),
            });
          } catch {
            // Leave the durable journal unchanged when it cannot be updated.
          }
          continue;
        }
      }
      if (!keyId) {
        failed += 1;
        continue;
      }
      try {
        await magpie.revoke(keyId);
        await recordIssuanceState(entry.id, {
          state: "failed",
          keyId,
          keyExpiresAt,
          errorCode: "recovered_orphan_revoked",
          revokedAt: new Date().toISOString(),
          revocationResult: "revoked",
          recoveredAt: new Date().toISOString(),
        });
        recovered += 1;
      } catch (error) {
        failed += 1;
        try {
          await recordIssuanceState(entry.id, {
            state: "unknown",
            keyId,
            keyExpiresAt,
            errorCode: String(error?.code || "recovery_revoke_unknown").slice(0, 128),
            revocationResult: "unknown",
            recoveredAt: new Date().toISOString(),
          });
        } catch {
          // A later startup retries the same idempotent revocation.
        }
      }
    }
    return { recovered, failed };
  }

  async function enqueueRevocations(ids) {
    const unique = [...new Set(ids.filter(Boolean))];
    if (unique.length === 0) return;
    await store.mutate((data) => {
      for (const id of unique) {
        if (!data.pendingRevocations.some((entry) => entry.id === id)) {
          data.pendingRevocations.push({ id, queuedAt: new Date().toISOString() });
        }
      }
    });
  }

  async function drainRevocations() {
    const pending = await store.read((data) => structuredClone(data.pendingRevocations));
    const revoked = [];
    for (const entry of pending) {
      try {
        await magpie.revoke(entry.id);
        revoked.push(entry.id);
      } catch (error) {
        console.error(`gateway key revoke ${entry.id} failed: ${error.message}`);
      }
    }
    if (revoked.length > 0) {
      await store.mutate((data) => {
        data.pendingRevocations = data.pendingRevocations.filter((entry) => !revoked.includes(entry.id));
      });
    }
    return { revoked, pending: pending.length - revoked.length };
  }

  function requireInternalAdmin(req) {
    if (!safeEqual(bearer(req), config.internalAdminToken)) {
      throw new HttpError(401, "invalid_service_token", "Service token is not valid");
    }
  }

  async function disableUser(userId) {
    const keys = [];
    const result = await store.mutate((data) => {
      const user = data.users[userId];
      if (!user) throw new HttpError(404, "user_not_found", "User not found");

      const disabledAt = new Date().toISOString();
      user.status = "disabled";
      user.disabledAt = disabledAt;

      let affectedDevices = 0;
      for (const device of Object.values(data.devices)) {
        if (device.userId !== userId) continue;
        affectedDevices += 1;
        device.status = "disabled";
        device.disabledAt = disabledAt;
        if (device.gatewayKeyId) keys.push(device.gatewayKeyId);
      }

      let affectedSessions = 0;
      for (const [sessionHash, session] of Object.entries(data.sessions)) {
        if (session.userId !== userId) continue;
        delete data.sessions[sessionHash];
        affectedSessions += 1;
      }

      let affectedCredentials = 0;
      for (const credential of Object.values(data.credentials)) {
        if (credential.userId !== userId || credential.status !== "active") continue;
        credential.status = "revoked";
        credential.revokedAt = disabledAt;
        affectedCredentials += 1;
        keys.push(credential.id);
      }

      return {
        user: publicUser(data.users[userId]),
        affectedDevices,
        affectedSessions,
        affectedCredentials,
      };
    });
    await enqueueRevocations(keys);
    result.revocations = await drainRevocations();
    return result;
  }

  async function enableUser(userId) {
    return store.mutate((data) => {
      const user = data.users[userId];
      if (!user) throw new HttpError(404, "user_not_found", "User not found");
      user.status = "active";
      delete user.disabledAt;
      return {
        user: publicUser(user),
        devicesRestored: 0,
        credentialsRestored: 0,
        requiresDeviceJoin: true,
      };
    });
  }

  async function recordCredentialPolicyResult(userId, credentialId, policyVersion, result) {
    return store.mutate((data) => {
      const user = policyUser(data, userId);
      if (user.gatewayPolicy.version !== policyVersion) return { superseded: true };
      const credential = data.credentials[credentialId];
      if (!credential || credential.userId !== userId || credential.status !== "active") {
        return { skipped: true };
      }
      const now = new Date().toISOString();
      credential.policyVersion = policyVersion;
      credential.lastPolicyOperationId = user.gatewayPolicy.operationId || "";
      credential.lastPolicyAttemptedAt = now;
      if (result.ok) {
        credential.models = structuredClone(user.gatewayPolicy.models);
        credential.policySyncState = "synced";
        credential.lastPolicyResult = "synced";
        credential.lastPolicySyncedAt = result.observedAt || now;
        credential.lastPolicyGatewayRequestId = result.gatewayControlRequestId;
        credential.lastPolicyRevision = result.policyRevision;
        delete credential.lastPolicyErrorCode;
      } else {
        credential.policySyncState = result.state;
        credential.lastPolicyResult = result.state;
        credential.lastPolicyErrorCode = result.errorCode;
      }
      refreshPolicyKnownState(user, data, now);
      return { ok: result.ok === true };
    });
  }

  async function syncPolicyToCredentials(userId, policyVersion, operationId) {
    const snapshot = await store.read((data) => {
      const user = policyUser(data, userId);
      if (user.gatewayPolicy.version !== policyVersion) return { superseded: true };
      return {
        policy: structuredClone(user.gatewayPolicy),
        credentials: activeCredentialsForUser(data, userId).map((credential) => credential.id),
      };
    });
    if (snapshot.superseded) {
      return store.read((data) => {
        const user = policyUser(data, userId);
        const result = policyWriteResult(operationId, user, data, "pending_sync");
        result.superseded = true;
        return result;
      });
    }

    for (const credentialId of snapshot.credentials) {
      let result;
      try {
        const readback = await gatewayControl.apply(credentialId, {
          models: snapshot.policy.models,
          limits: snapshot.policy.limits,
        });
        result = {
          ok: true,
          gatewayControlRequestId: readback.gatewayControlRequestId,
          observedAt: readback.observedAt,
          policyRevision: readback.policyRevision,
        };
      } catch (error) {
        const state = error instanceof GatewayControlError && error.state === "pending"
          ? "unknown"
          : "failed";
        result = {
          ok: false,
          state,
          errorCode: String(error?.code || "gateway_control_failed").slice(0, 128),
        };
      }
      const recorded = await recordCredentialPolicyResult(
        userId,
        credentialId,
        policyVersion,
        result,
      );
      if (recorded.superseded) break;
    }

    return store.mutate((data) => {
      const user = policyUser(data, userId);
      const now = new Date().toISOString();
      refreshPolicyKnownState(user, data, now);
      const summary = credentialsSummary(data, user, policyVersion);
      let state = "pending_sync";
      if (user.gatewayPolicy.version !== policyVersion) state = "pending_sync";
      else if (policyIsKnown(user.gatewayPolicy)) state = "succeeded";
      else if (summary.succeeded > 0) state = "partial_success";
      else if (summary.unknown > 0) state = "unknown";
      const result = policyWriteResult(operationId, user, data, state);
      if (user.gatewayPolicy.version !== policyVersion) result.superseded = true;
      return result;
    });
  }

  async function updatePolicy(userId, expected, part, value, operationId) {
    return serializePolicyWrite(userId, async () => {
      const updated = await store.mutate((data) => {
        const user = policyUser(data, userId);
        assertPolicyVersion(user.gatewayPolicy, expected);
        const now = new Date().toISOString();
        const policy = updatePolicyPart(user, part, value, operationId, now);
        markActiveCredentialsPending(user.id, data, operationId, now);
        refreshPolicyKnownState(user, data, now);
        return {
          policyVersion: policy.version,
          policy: structuredClone(policy),
        };
      });
      return syncPolicyToCredentials(userId, updated.policyVersion, operationId);
    });
  }

  async function updateQuotaPolicy(userId, expected, limits, operationId) {
    return updatePolicy(userId, expected, "limits", limits, operationId);
  }

  async function updateModelsPolicy(userId, expected, models, operationId) {
    return updatePolicy(userId, expected, "models", models, operationId);
  }

  async function confirmCredentialPolicy(userId, credentialId, expected, operationId, readback) {
    return store.mutate((data) => {
      const user = policyUser(data, userId);
      assertPolicyVersion(user.gatewayPolicy, expected);
      const policy = user.gatewayPolicy;
      if (!policyIsComplete(policy)) throw policyGateError(policy);

      const credential = data.credentials[credentialId];
      if (!credential || credential.userId !== userId) {
        throw new HttpError(404, "credential_not_found", "Credential not found");
      }
      if (credential.status !== "active") {
        throw new HttpError(409, "credential_not_active", "Credential is not active");
      }

      const validatedReadback = validateCredentialReadback(readback, policy);
      const now = new Date().toISOString();
      credential.policyVersion = policy.version;
      credential.policySyncState = "synced";
      credential.lastPolicyAttemptedAt = now;
      credential.lastPolicyResult = "synced";
      credential.lastPolicySyncedAt = validatedReadback.observedAt;
      credential.lastPolicyOperationId = operationId;
      credential.lastPolicyGatewayRequestId = validatedReadback.gatewayControlRequestId;
      credential.lastPolicyRevision = validatedReadback.policyRevision;
      delete credential.lastPolicyErrorCode;
      refreshPolicyKnownState(user, data, now);

      const result = policyWriteResult(operationId, user, data);
      result.credential = {
        credentialId,
        policyVersion: credential.policyVersion,
        policySyncState: credential.policySyncState,
        lastPolicySyncedAt: credential.lastPolicySyncedAt,
      };
      result.readback = {
        gatewayControlRequestId: validatedReadback.gatewayControlRequestId,
        observedAt: validatedReadback.observedAt,
        policyRevision: validatedReadback.policyRevision,
      };
      return result;
    });
  }

  async function revokeDeviceById(deviceId) {
    return serializeByDevice(deviceId, async () => {
      const keys = [];
      const result = await store.mutate((data) => {
        const device = data.devices[deviceId];
        if (!device) throw new HttpError(404, "device_not_found", "Device not found");

        const revokedAt = new Date().toISOString();
        device.status = "revoked";
        device.revokedAt = revokedAt;
        if (device.gatewayKeyId) keys.push(device.gatewayKeyId);

        let affectedCredentials = 0;
        for (const credential of Object.values(data.credentials)) {
          if (credential.deviceId !== deviceId || credential.status !== "active") continue;
          credential.status = "revoked";
          credential.revokedAt = revokedAt;
          affectedCredentials += 1;
          keys.push(credential.id);
        }

        return {
          device: publicDevice(data.devices[deviceId]),
          affectedCredentials,
        };
      });
      await enqueueRevocations(keys);
      result.revocations = await drainRevocations();
      return result;
    });
  }

  function rotationState(data, credentialId) {
    const credential = data.credentials[credentialId];
    if (!credential) throw new HttpError(404, "credential_not_found", "Credential not found");

    const device = data.devices[credential.deviceId];
    if (!device) throw new HttpError(404, "device_not_found", "Device not found");
    if (device.userId !== credential.userId) {
      throw new HttpError(409, "credential_owner_mismatch", "Credential owner does not match its device");
    }

    const user = data.users[credential.userId];
    if (!user) throw new HttpError(404, "user_not_found", "User not found");
    if (user.status !== "active") {
      throw new HttpError(403, "user_disabled", "This employee account is not active");
    }
    if (device.status !== "active") {
      throw new HttpError(403, "device_disabled", "This device is not active");
    }
    if (credential.status !== "active") {
      throw new HttpError(409, "credential_not_active", "Credential is not active");
    }
    if (device.gatewayKeyId !== credentialId) {
      throw new HttpError(409, "credential_not_current", "Credential is not the device's current key");
    }
    return { credential, device, user };
  }

  async function rotateCredential(credentialId) {
    const deviceId = await store.read((data) => rotationState(data, credentialId).device.id);
    return serializeByDevice(deviceId, async () => {
      // Re-read after taking the device lock so a queued refresh, revoke or
      // rotate cannot make this decision from stale state.
      const current = await store.read((data) => rotationState(data, credentialId));
      const issuedEnvelope = await issueDeviceCredential({
        user: current.user,
        deviceId: current.device.id,
        credentialId,
        purpose: "rotate",
        deviceName: current.device.name,
        commit: (data, { issued, policy, readback, now }) => {
          const latest = rotationState(data, credentialId);
          latest.credential.status = "revoked";
          latest.credential.revokedAt = now;
          latest.device.gatewayKeyId = issued.id;
          latest.device.gatewayKeyExpiresAt = issued.expires;
          latest.device.lastSeenAt = now;
          data.credentials[issued.id] = {
            id: issued.id,
            userId: latest.user.id,
            deviceId: latest.device.id,
            status: "active",
            createdAt: now,
            expiresAt: issued.expires,
            ...credentialPolicyMetadata(policy, now, readback),
          };
          if (!data.pendingRevocations.some((entry) => entry.id === credentialId)) {
            data.pendingRevocations.push({ id: credentialId, queuedAt: now });
          }
          return {
            credentialId,
            newCredentialId: issued.id,
            userId: latest.user.id,
            deviceId: latest.device.id,
            status: "awaiting_device_refresh",
            expiresAt: issued.expires,
          };
        },
      });

      const drained = await drainRevocations();
      return {
        ...issuedEnvelope,
        policyVersion: issuedEnvelope.policyVersion,
        policyOperationId: issuedEnvelope.policyOperationId,
        revocations: drained,
      };
    });
  }

  function allowRequest(req) {
    const now = Date.now();
    const key = `${clientIp(req)}:${req.method}:${new URL(req.url, "http://localhost").pathname}`;
    let bucket = rate.get(key);
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + 60000 };
      rate.set(key, bucket);
    }
    bucket.count += 1;
    return bucket.count <= config.rateLimitPerMinute;
  }

  async function handle(req, res) {
    const requestId = crypto.randomUUID();
    res.setHeader("x-request-id", requestId);
    res.setHeader("x-content-type-options", "nosniff");
    res.setHeader("referrer-policy", "no-referrer");
    res.setHeader("cache-control", "no-store");
    res.setHeader(
      "content-security-policy",
      "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    );

    const url = new URL(req.url, "http://localhost");
    if (url.pathname !== "/healthz" && !allowRequest(req)) {
      apiError(res, requestId, 429, "rate_limited", "Too many requests; try again shortly");
      return;
    }

    if (req.method === "GET" && url.pathname === "/healthz") {
      const status = await store.read((data) => ({
        ok: true,
        service: "auth",
        users: Object.keys(data.users).length,
        devices: Object.keys(data.devices).length,
        credentials: Object.keys(data.credentials).length,
        pendingRevocations: data.pendingRevocations.length,
        ...statusSummary(data),
      }));
      json(res, 200, status);
      return;
    }

    if (url.pathname.startsWith("/api/v1/internal/admin/")) {
      requireInternalAdmin(req);
      if (req.method === "GET" && url.pathname === "/api/v1/internal/admin/status") {
        const status = await store.read((data) => ({
          ok: true,
          service: "auth",
          users: Object.keys(data.users).length,
          devices: Object.keys(data.devices).length,
          credentials: Object.keys(data.credentials).length,
          pendingRevocations: data.pendingRevocations.length,
          ...statusSummary(data),
        }));
        json(res, 200, status);
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/internal/admin/users") {
        const users = await store.read((data) => Object.values(data.users).map(publicUser));
        json(res, 200, { ok: true, users });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/internal/admin/devices") {
        const devices = await store.read((data) => Object.values(data.devices).map(publicDevice));
        json(res, 200, { ok: true, devices });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/internal/admin/credentials") {
        const credentials = await store.read((data) =>
          Object.values(data.credentials).map((credential) => publicCredential(credential, data.devices)),
        );
        json(res, 200, { ok: true, credentials });
        return;
      }

      const policyRoute = /^\/api\/v1\/internal\/admin\/users\/(usr_[A-Za-z0-9_-]+)\/policy\/(quota|models|confirm-credential)$/.exec(
        url.pathname,
      );
      if (policyRoute && (
        (policyRoute[2] === "quota" && req.method === "PUT")
        || (policyRoute[2] === "models" && req.method === "PATCH")
        || (policyRoute[2] === "confirm-credential" && req.method === "POST")
      )) {
        const body = requireJsonObject(await readJson(req));
        const userId = policyRoute[1];
        const action = policyRoute[2];
        const expected = expectedVersion(req, body);
        const operationId = policyOperationId(body);
        let result;
        if (action === "quota") {
          let limits;
          try {
            limits = validateLimits(body.limits);
          } catch (error) {
            throw policyValidationHttpError(error);
          }
          result = await updateQuotaPolicy(userId, expected, limits, operationId);
        } else if (action === "models") {
          let models;
          try {
            models = validateModels(body.models);
          } catch (error) {
            throw policyValidationHttpError(error);
          }
          result = await updateModelsPolicy(userId, expected, models, operationId);
        } else {
          const credentialId = cleanText(body.credentialId, "credentialId", 256);
          result = await confirmCredentialPolicy(
            userId,
            credentialId,
            expected,
            operationId,
            body.readback,
          );
        }
        json(res, 200, { ok: true, data: result });
        return;
      }

      const userAction = /^\/api\/v1\/internal\/admin\/users\/(usr_[A-Za-z0-9_-]+)\/(disable|enable)$/.exec(
        url.pathname,
      );
      if (req.method === "POST" && userAction) {
        const result = userAction[2] === "disable"
          ? await disableUser(userAction[1])
          : await enableUser(userAction[1]);
        json(res, 200, { ok: true, data: result });
        return;
      }

      const deviceAction = /^\/api\/v1\/internal\/admin\/devices\/(dev_[A-Za-z0-9_-]+)\/revoke$/.exec(
        url.pathname,
      );
      if (req.method === "POST" && deviceAction) {
        json(res, 200, { ok: true, data: await revokeDeviceById(deviceAction[1]) });
        return;
      }

      const credentialAction = /^\/api\/v1\/internal\/admin\/credentials\/([A-Za-z0-9_-]+)\/rotate$/.exec(
        url.pathname,
      );
      if (req.method === "POST" && credentialAction) {
        json(res, 200, { ok: true, data: await rotateCredential(credentialAction[1]) });
        return;
      }
      throw new HttpError(404, "not_found", "Internal route not found");
    }

    if (req.method === "GET" && url.pathname === "/") {
      const current = await userForSession(req);
      const view = current
        ? await store.read((data) => publicSelfView(data, data.users[current.user.id]))
        : null;
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(htmlPage(view));
      return;
    }

    if (req.method === "GET" && url.pathname === "/login") {
      const returnTo = String(url.searchParams.get("return_to") || "").trim();
      const clientState = cleanText(url.searchParams.get("state") || randomToken(18), "state", 256);
      const codeChallenge = cleanText(url.searchParams.get("code_challenge") || "", "code_challenge", 128, Boolean(returnTo));
      if (returnTo && !clientFlowAllowed(returnTo, config)) {
        throw new HttpError(400, "invalid_return_to", "return_to must be a loopback or configured origin");
      }
      if (returnTo && !/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge)) {
        throw new HttpError(400, "invalid_code_challenge", "Client joins must use an S256 PKCE code_challenge");
      }
      const started = await oidc.begin({
        redirectUri: config.oidc.redirectUri,
        clientState,
        codeChallenge,
      });
      const transaction = signCookie(JSON.stringify({ ...started.transaction, returnTo }), config.cookieSecret);
      redirect(res, started.url, {
        "set-cookie": cookieHeader(config, transaction, 600),
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/oauth/callback") {
      const cookies = parseCookies(req.headers.cookie);
      const raw = verifyCookie(cookies[config.cookieName], config.cookieSecret);
      if (!raw) throw new HttpError(400, "login_expired", "Login transaction is missing or expired");
      let transaction;
      try {
        transaction = JSON.parse(raw);
      } catch {
        throw new HttpError(400, "login_expired", "Login transaction is invalid");
      }
      if (!safeEqual(url.searchParams.get("state") || "", transaction.state)) {
        throw new HttpError(400, "invalid_oidc_state", "OIDC state does not match");
      }
      const completed = await oidc.complete(url.searchParams.get("code") || "", transaction);
      const identity = normalizeIdentity(completed.claims, config.oidc);
      const user = await store.mutate((data) => {
        let existing = Object.values(data.users).find((candidate) => candidate.subject === identity.subject);
        const now = new Date().toISOString();
        if (!existing) {
          const id = `usr_${sha256(`${config.oidc.issuer}|${identity.subject}`).slice(0, 24)}`;
          existing = {
            id,
            subject: identity.subject,
            email: identity.email,
            name: identity.name,
            status: "active",
            createdAt: now,
            lastLoginAt: now,
            gatewayPolicy: createUnknownPolicy(now, "new_user_unknown"),
          };
          data.users[id] = existing;
        } else {
          if (existing.status !== "active") {
            throw new HttpError(403, "user_disabled", "This employee account is disabled");
          }
          existing.email = identity.email;
          existing.name = identity.name;
          existing.lastLoginAt = now;
        }
        return structuredClone(existing);
      });

      const clearCookie = { "set-cookie": cookieHeader(config, "", 0) };
      if (transaction.returnTo) {
        const code = `mjoin_${randomToken(32)}`;
        handoffs.set(code, {
          userId: user.id,
          codeChallenge: transaction.codeChallenge,
          expiresAt: Date.now() + HANDOFF_TTL_MS,
        });
        const target = new URL(transaction.returnTo);
        target.searchParams.set("code", code);
        target.searchParams.set("state", transaction.clientState);
        redirect(res, target.toString(), clearCookie);
      } else {
        const session = await createSession(user.id);
        redirect(res, "/", {
          "set-cookie": [
            cookieHeader(config, signCookie(session.sid, config.cookieSecret), config.sessionTtlSeconds),
          ],
        });
      }
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/me") {
      const current = await userForSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your company account");
      const view = await store.read((data) => publicSelfView(data, data.users[current.user.id]));
      json(res, 200, view);
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/v1/logout") {
      const current = await userForSession(req);
      if (current) {
        await store.mutate((data) => {
          delete data.sessions[sha256(current.sid)];
        });
      }
      json(res, 200, { ok: true }, { "set-cookie": cookieHeader(config, "", 0) });
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/v1/join/exchange") {
      const body = await readJson(req);
      const code = cleanText(body.code, "code", 256);
      const verifier = cleanText(body.codeVerifier, "codeVerifier", 128);
      const handoff = handoffs.get(code);
      if (!handoff || handoff.expiresAt <= Date.now()) {
        handoffs.delete(code);
        throw new HttpError(400, "join_code_invalid", "Join code is invalid or expired");
      }
      if (!/^[A-Za-z0-9_-]{43,128}$/.test(verifier) || !safeEqual(pkceChallenge(verifier), handoff.codeChallenge)) {
        throw new HttpError(400, "pkce_mismatch", "Join code does not match this client");
      }
      handoffs.delete(code);

      const user = await store.read((data) => data.users[handoff.userId]);
      if (!user || user.status !== "active") {
        throw new HttpError(403, "user_disabled", "This employee account is not active");
      }
      const deviceInput = body.device || {};
      const deviceName = cleanText(deviceInput.name, "device.name", 120);
      const platform = cleanText(deviceInput.platform, "device.platform", 80);
      const clientVersion = cleanText(deviceInput.clientVersion, "device.clientVersion", 80);
      const publicKey = String(deviceInput.publicKey || "").trim();
      if ([...publicKey].length > 8192) {
        throw new HttpError(400, "invalid_public_key", "device.publicKey is too long");
      }
      if (publicKey) {
        try {
          crypto.createPublicKey(publicKey);
        } catch {
          throw new HttpError(400, "invalid_public_key", "device.publicKey must be a valid PEM public key");
        }
      }

      const deviceId = `dev_${randomToken(15)}`;
      const deviceToken = `mdev_${randomToken(32)}`;
      const now = new Date();
      const tokenExpiresAt = new Date(now.getTime() + config.deviceTokenTtlSeconds * 1000);
      const issuedEnvelope = await issueDeviceCredential({
        user,
        deviceId,
        purpose: "join",
        deviceName,
        commit: (data, { issued, policy, readback, now: committedAt }) => {
          const currentUser = assertIssuancePolicyCurrent(
            data,
            user.id,
            policy.version,
          );
          if (currentUser.status !== "active") {
            throw new HttpError(403, "user_disabled", "This employee account is not active");
          }
          data.devices[deviceId] = {
            id: deviceId,
            userId: user.id,
            name: deviceName,
            platform,
            clientVersion,
            publicKey: publicKey || undefined,
            publicKeySha256: publicKey ? sha256(publicKey) : undefined,
            tokenHash: sha256(deviceToken),
            tokenExpiresAt: tokenExpiresAt.toISOString(),
            gatewayKeyId: issued.id,
            gatewayKeyExpiresAt: issued.expires,
            status: "active",
            createdAt: committedAt,
            lastSeenAt: committedAt,
          };
          data.credentials[issued.id] = {
            id: issued.id,
            userId: user.id,
            deviceId,
            status: "active",
            createdAt: committedAt,
            expiresAt: issued.expires,
            ...credentialPolicyMetadata(policy, committedAt, readback),
          };
          return { deviceId };
        },
      });
      const issued = issuedEnvelope.issued;
      json(res, 201, {
        user: publicUser(user),
        device: {
          id: deviceId,
          name: deviceName,
          status: "active",
          tokenExpiresAt: tokenExpiresAt.toISOString(),
        },
        deviceToken,
        gateway: {
          url: config.magpie.publicUrl,
          key: issued.key,
          keyId: issued.id,
          expiresAt: issued.expires,
          models: issued.models,
        },
        policyVersion: issuedEnvelope.policyVersion,
        policyOperationId: issuedEnvelope.policyOperationId,
      });
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/v1/devices/heartbeat") {
      const { device, user } = await requireDevice(req);
      const body = await readJson(req);
      const clientVersion = cleanText(body.clientVersion || device.clientVersion, "clientVersion", 80, false);
      await store.mutate((data) => {
        const current = data.devices[device.id];
        current.lastSeenAt = new Date().toISOString();
        if (clientVersion) current.clientVersion = clientVersion;
      });
      json(res, 200, {
        ok: true,
        user: { id: user.id, status: user.status },
        device: { id: device.id, status: device.status },
        gatewayKeyExpiresAt: device.gatewayKeyExpiresAt,
      });
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/v1/devices/refresh") {
      const token = bearer(req);
      if (!token) throw new HttpError(401, "missing_device_token", "Send Authorization: Bearer <device token>");
      const deviceId = await store.read((data) => deviceFromToken(data, token).device.id);
      const payload = await serializeByDevice(deviceId, async () => {
        // Re-read inside the per-device lock. A queued refresh must not use the
        // device or user state that was current when its HTTP request arrived.
        const { device, user } = await requireDevice(req);
        const oldKeyId = device.gatewayKeyId;
        const issuedEnvelope = await issueDeviceCredential({
          user,
          deviceId: device.id,
          credentialId: oldKeyId,
          purpose: "refresh",
          deviceName: device.name,
          commit: (data, { issued, policy, readback, now }) => {
            const current = data.devices[device.id];
            if (!current || current.tokenHash !== device.tokenHash) {
              throw new HttpError(401, "invalid_device_token", "Device token is not valid");
            }
            if (current.status !== "active") {
              throw new HttpError(403, "device_disabled", "This device is not active");
            }
            if (Date.parse(current.tokenExpiresAt) <= Date.now()) {
              throw new HttpError(401, "device_token_expired", "Device token has expired");
            }
            const currentUser = assertIssuancePolicyCurrent(
              data,
              current.userId,
              policy.version,
            );
            if (currentUser.status !== "active") {
              throw new HttpError(403, "user_disabled", "This employee account is not active");
            }
            if (current.gatewayKeyId !== oldKeyId) {
              throw new HttpError(409, "device_key_changed", "The device key changed during refresh; retry");
            }
            if (oldKeyId) {
              const oldCredential = data.credentials[oldKeyId];
              if (!oldCredential || oldCredential.status !== "active") {
                throw new HttpError(409, "credential_not_active", "Credential is not active");
              }
              oldCredential.status = "revoked";
              oldCredential.revokedAt = now;
            }
            current.gatewayKeyId = issued.id;
            current.gatewayKeyExpiresAt = issued.expires;
            current.lastSeenAt = now;
            data.credentials[issued.id] = {
              id: issued.id,
              userId: current.userId,
              deviceId: current.id,
              status: "active",
              createdAt: now,
              expiresAt: issued.expires,
              ...credentialPolicyMetadata(policy, now, readback),
            };
            if (oldKeyId && !data.pendingRevocations.some((entry) => entry.id === oldKeyId)) {
              data.pendingRevocations.push({ id: oldKeyId, queuedAt: now });
            }
            return { deviceId: current.id };
          },
        });
        const issued = issuedEnvelope.issued;
        const drained = await drainRevocations();
        return {
          gateway: {
            url: config.magpie.publicUrl,
            key: issued.key,
            keyId: issued.id,
            expiresAt: issued.expires,
            models: issued.models,
          },
          policyVersion: issuedEnvelope.policyVersion,
          policyOperationId: issuedEnvelope.policyOperationId,
          pendingRevocations: drained.pending,
        };
      });
      json(res, 200, payload);
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/v1/devices/revoke") {
      const { device } = await requireDevice(req);
      await store.mutate((data) => {
        const current = data.devices[device.id];
        current.status = "revoked";
        current.revokedAt = new Date().toISOString();
        for (const credential of Object.values(data.credentials)) {
          if (credential.deviceId === current.id && credential.status === "active") {
            credential.status = "revoked";
            credential.revokedAt = current.revokedAt;
          }
        }
      });
      await enqueueRevocations([device.gatewayKeyId]);
      const drained = await drainRevocations();
      json(res, 200, { ok: true, pendingRevocations: drained.pending });
      return;
    }

    if (url.pathname.startsWith("/api/v1/admin/")) {
      if (!safeEqual(bearer(req), config.adminToken)) {
        throw new HttpError(401, "invalid_admin_token", "Admin token is not valid");
      }
      if (req.method === "GET" && url.pathname === "/api/v1/admin/users") {
        const users = await store.read((data) => Object.values(data.users).map(publicUser));
        json(res, 200, { users });
        return;
      }
      if (req.method === "GET" && url.pathname === "/api/v1/admin/devices") {
        const devices = await store.read((data) => Object.values(data.devices).map(publicDevice));
        json(res, 200, { devices });
        return;
      }
      const userAction = /^\/api\/v1\/admin\/users\/(usr_[A-Za-z0-9_-]+)\/(disable|enable)$/.exec(url.pathname);
      if (req.method === "POST" && userAction) {
        const userId = userAction[1];
        const action = userAction[2];
        const keys = [];
        const result = await store.mutate((data) => {
          const user = data.users[userId];
          if (!user) throw new HttpError(404, "user_not_found", "User not found");
          if (action === "disable") {
            user.status = "disabled";
            user.disabledAt = new Date().toISOString();
            for (const device of Object.values(data.devices).filter((candidate) => candidate.userId === userId)) {
              device.status = "disabled";
              device.disabledAt = user.disabledAt;
              if (device.gatewayKeyId) keys.push(device.gatewayKeyId);
            }
            for (const [sessionHash, session] of Object.entries(data.sessions)) {
              if (session.userId === userId) delete data.sessions[sessionHash];
            }
            for (const credential of Object.values(data.credentials)) {
              if (credential.userId === userId && credential.status === "active") {
                credential.status = "revoked";
                credential.revokedAt = user.disabledAt;
              }
            }
          } else {
            user.status = "active";
            delete user.disabledAt;
          }
          return { user: publicUser(data.users[userId]), affectedKeys: keys.length };
        });
        if (action === "disable") {
          await enqueueRevocations(keys);
          result.revocations = await drainRevocations();
        }
        json(res, 200, result);
        return;
      }
    }

    apiError(res, requestId, 404, "not_found", "Route not found");
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((error) => {
      const statusCode = error.statusCode || 500;
      const code = error.code || (statusCode >= 500 ? "internal_error" : "request_failed");
      const message = statusCode >= 500 ? "The authentication service could not complete the request" : error.message;
      if (statusCode >= 500) console.error(`${req.method} ${req.url}: ${error.stack || error.message}`);
      if (!res.headersSent) {
        apiError(
          res,
          res.getHeader("x-request-id") || "",
          statusCode,
          code,
          message,
          safeErrorDetails(error.details),
        );
      }
      else res.destroy();
    });
  });
  server.requestTimeout = 30000;
  server.headersTimeout = 10000;
  server.on("listening", () => {
    drainRevocations().catch((error) => console.error(`startup revocation drain failed: ${error.message}`));
  });
  const startupRecovery = recoverIssuanceJournal()
    .catch((error) => {
      console.error(`startup issuance recovery failed: ${error.message}`);
      return { recovered: 0, failed: 1 };
    });
  return {
    server,
    store,
    oidc,
    magpie,
    gatewayControl,
    handoffs,
    drainRevocations,
    recoverIssuanceJournal,
    startupRecovery,
  };
}
