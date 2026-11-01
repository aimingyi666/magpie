import http from "node:http";
import crypto from "node:crypto";
import { AuthServiceClient } from "./auth-client.js";
import { normalizeAdminIdentity, OidcClient } from "./oidc.js";
import {
  adminSubjectId,
  authorize,
  effectiveAccess,
  visibleOrgUnits,
} from "./rbac.js";
import {
  csrfCookie,
  cookieHeader,
  newSession,
  requestAllowed,
  sessionCookie,
  sessionState,
  validCsrf,
} from "./session.js";
import {
  legacyModelCatalog,
  loadModelCatalog,
  modelCatalogStartupAudit,
  publicModelCatalog,
} from "./model-catalog.js";
import {
  parseCookies,
  randomToken,
  safeEqual,
  sha256,
  signCookie,
  verifyCookie,
} from "./security.js";
import { JsonStore } from "./store.js";
import { readUsageFile } from "./usage-reader.js";

const MAX_BODY = 16 * 1024;
const DEFAULT_USAGE_WINDOW_DAYS = 7;
const MAX_TIMESERIES_POINTS = 10000;

class HttpError extends Error {
  constructor(statusCode, code, message) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

function apiError(res, requestId, statusCode, code, message, operationId = "") {
  res.writeHead(statusCode, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify({
    error: {
      code,
      message,
      requestId,
      ...(operationId ? { operationId } : {}),
    },
  }));
}

function json(res, statusCode, value, headers = {}) {
  res.writeHead(statusCode, { "content-type": "application/json; charset=utf-8", ...headers });
  res.end(JSON.stringify(value));
}

function redirect(res, location, headers = {}) {
  res.writeHead(302, { ...headers, location });
  res.end();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function publicIdentity(session) {
  return {
    id: session.subjectId,
    subject: session.subject,
    email: session.email,
    name: session.name,
  };
}

function bootstrapBinding(identity, config) {
  const subjectMatch = config.bootstrap.subjectIds.includes(identity.subject);
  const emailMatch = config.bootstrap.emails.includes(identity.email.toLowerCase());
  if (!subjectMatch && !emailMatch) return null;
  const now = new Date();
  return {
    id: `rb_bootstrap_${sha256(identity.id).slice(0, 16)}`,
    subjectType: "admin",
    subjectId: identity.id,
    role: "super_admin",
    scopeOrgUnitId: "*",
    validFrom: now.toISOString(),
    validTo: new Date(now.getTime() + config.bootstrap.validHours * 3600 * 1000).toISOString(),
    createdBy: "bootstrap",
    extraPermissions: ["roles.write"],
    createdAt: now.toISOString(),
  };
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new HttpError(413, "request_too_large", "Request body is too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function readForm(req) {
  if (!/^application\/x-www-form-urlencoded(?:\s*;|$)/i.test(String(req.headers["content-type"] || ""))) {
    return new URLSearchParams();
  }
  return new URLSearchParams(await readBody(req));
}

async function readJsonBody(req) {
  if (!/^application\/json(?:\s*;|$)/i.test(String(req.headers["content-type"] || ""))) {
    throw new HttpError(415, "unsupported_media_type", "Content-Type must be application/json");
  }
  let value;
  try {
    value = JSON.parse(await readBody(req) || "{}");
  } catch {
    throw new HttpError(400, "invalid_json", "Request body must be valid JSON");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(400, "invalid_request", "Request body must be a JSON object");
  }
  return value;
}

function cleanReason(value) {
  const reason = String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, "").trim();
  if (!reason) throw new HttpError(400, "invalid_reason", "reason is required");
  if ([...reason].length > 500) {
    throw new HttpError(400, "invalid_reason", "reason must be at most 500 characters");
  }
  return reason;
}

function validateOptionalIdempotencyKey(req) {
  const value = String(req.headers["idempotency-key"] || "").trim();
  if (!value) return "";
  if ([...value].length > 128 || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new HttpError(400, "invalid_idempotency_key", "Idempotency-Key is invalid");
  }
  return value;
}

function cleanOptionalApprovalId(value) {
  const approvalId = String(value ?? "").trim();
  if (!approvalId) return "";
  if ([...approvalId].length > 128 || /[\u0000-\u001f\u007f]/.test(approvalId)) {
    throw new HttpError(400, "invalid_approval_id", "approvalId is invalid");
  }
  return approvalId;
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .filter((key) => value[key] !== undefined)
        .map((key) => [key, canonicalValue(value[key])]),
    );
  }
  return value;
}

function writeRequestFingerprint(action, targetType, targetId, reason, approvalId) {
  return sha256(JSON.stringify(canonicalValue({
    action,
    targetType,
    targetId,
    reason,
    approvalId,
  })));
}

function writeTargetSnapshot(targetType, target) {
  if (targetType === "user") {
    return {
      id: String(target.id || ""),
      email: String(target.email || ""),
      status: String(target.status || ""),
    };
  }
  if (targetType === "device") {
    return {
      id: String(target.id || ""),
      userId: String(target.userId || ""),
      status: String(target.status || ""),
      platform: String(target.platform || ""),
    };
  }
  return {
    id: String(target.id || ""),
    userId: String(target.userId || ""),
    deviceId: String(target.deviceId || ""),
    status: String(target.status || ""),
    expiresAt: String(target.expiresAt || ""),
  };
}

function sessionInfo(session) {
  return {
    expiresAt: session.expiresAt,
    lastSeenAt: session.lastSeenAt,
  };
}

function hasGlobalScope(access) {
  return access.scopeOrgUnitIds.includes("*");
}

function activeUserOrgUnit(data, userId) {
  const orgUnitId = data.userOrgUnits[userId];
  const org = orgUnitId ? data.orgUnits[orgUnitId] : null;
  return org?.status === "active" ? orgUnitId : "";
}

function userInScope(data, access, userId) {
  const orgUnitId = activeUserOrgUnit(data, userId);
  if (!orgUnitId) return hasGlobalScope(access);
  return hasGlobalScope(access) || access.scopeOrgUnitIds.includes(orgUnitId);
}

function visibleUserIds(data, access, users) {
  return new Set(
    users
      .filter((user) => userInScope(data, access, user.id))
      .map((user) => user.id),
  );
}

function orgUnitSummary(org) {
  return {
    id: org.id,
    parentId: org.parentId || "",
    name: org.name,
    path: org.path,
    status: org.status,
  };
}

function finiteWindow(searchParams, maxRangeDays) {
  const now = Date.now();
  const to = searchParams.get("to") ? new Date(searchParams.get("to")) : new Date(now);
  const from = searchParams.get("from")
    ? new Date(searchParams.get("from"))
    : new Date(to.getTime() - DEFAULT_USAGE_WINDOW_DAYS * 24 * 3600 * 1000);
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from >= to) {
    throw new HttpError(400, "invalid_time_range", "from and to must be a valid ascending time range");
  }
  if (to.getTime() - from.getTime() > maxRangeDays * 24 * 3600 * 1000) {
    throw new HttpError(400, "time_range_too_large", "The requested time range is too large");
  }
  return {
    from: from.toISOString(),
    to: to.toISOString(),
    fromMs: from.getTime(),
    toMs: to.getTime(),
  };
}

function table(headers, rows) {
  if (rows.length === 0) return "<p>No records.</p>";
  const head = headers.map((value) => `<th>${escapeHtml(value)}</th>`).join("");
  const body = rows
    .map((row) => `<tr>${row.map((value) => `<td>${escapeHtml(value)}</td>`).join("")}</tr>`)
    .join("");
  return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
}

function emptyUsageTotals() {
  return {
    requests: 0,
    successfulRequests: 0,
    errors: 0,
    rejected: 0,
    handedOn: 0,
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    totalTokens: 0,
    costUsd: 0,
    costKnownRecords: 0,
  };
}

function addUsageRecord(totals, record) {
  totals.requests += 1;
  if (record.status >= 200 && record.status < 400) totals.successfulRequests += 1;
  if (record.status >= 400 || record.rejected) totals.errors += 1;
  if (record.rejected) totals.rejected += 1;
  if (record.handedOn) totals.handedOn += 1;
  totals.inputTokens += record.inputTokens;
  totals.outputTokens += record.outputTokens;
  totals.cacheReadTokens += record.cacheReadTokens;
  totals.cacheWriteTokens += record.cacheWriteTokens;
  totals.totalTokens += record.inputTokens
    + record.outputTokens
    + record.cacheReadTokens
    + record.cacheWriteTokens;
  if (record.costUsd != null) {
    totals.costUsd += record.costUsd;
    totals.costKnownRecords += 1;
  }
}

function usageTotals(entries) {
  const totals = emptyUsageTotals();
  for (const { record } of entries) addUsageRecord(totals, record);
  totals.costUsd = Number(totals.costUsd.toFixed(8));
  return totals;
}

function usageDimension(entry, dimension, data) {
  if (dimension === "user") {
    return {
      key: entry.user.id,
      label: entry.user.name || entry.user.email,
      userId: entry.user.id,
      email: entry.user.email,
    };
  }
  if (dimension === "department") {
    const orgUnitId = activeUserOrgUnit(data, entry.user.id);
    const org = orgUnitId ? data.orgUnits[orgUnitId] : null;
    return {
      key: orgUnitId || "unmapped",
      label: org?.name || "Unmapped",
      orgUnitId,
      path: org?.path || "",
    };
  }
  if (dimension === "model") {
    const model = entry.record.model || "(unknown)";
    return { key: model, label: model, model };
  }
  if (dimension === "agent") {
    const agent = entry.record.agent || "(unknown)";
    return { key: agent, label: agent, agent };
  }
  return { key: "all", label: "All" };
}

function groupedUsage(entries, dimension, data) {
  const groups = new Map();
  for (const entry of entries) {
    const identity = usageDimension(entry, dimension, data);
    let group = groups.get(identity.key);
    if (!group) {
      group = { ...identity, totals: emptyUsageTotals() };
      groups.set(identity.key, group);
    }
    addUsageRecord(group.totals, entry.record);
  }
  return [...groups.values()]
    .map((group) => ({
      ...group,
      ...group.totals,
      costUsd: Number(group.totals.costUsd.toFixed(8)),
      totals: undefined,
    }))
    .sort((left, right) => right.requests - left.requests
      || String(left.label).localeCompare(String(right.label)));
}

function usageSource(result, recordsInWindow, unattributedRecords) {
  return {
    bytes: result.usage.bytes,
    lines: result.usage.lines,
    recordsInWindow,
    matchedRecords: result.matched.length,
    unattributedRecords,
    outsideScopeRecords: recordsInWindow - result.matched.length - unattributedRecords,
  };
}

function usageSummaryResponse(result) {
  const totals = usageTotals(result.matched);
  return {
    ok: true,
    window: { from: result.window.from, to: result.window.to },
    totals,
    dimensions: {
      all: [{ key: "all", label: "All", ...totals }],
      user: groupedUsage(result.matched, "user", result.data),
      department: groupedUsage(result.matched, "department", result.data),
      model: groupedUsage(result.matched, "model", result.data),
      agent: groupedUsage(result.matched, "agent", result.data),
    },
    source: usageSource(result, result.usage.records.length, result.unattributedRecords),
  };
}

function bucketStart(time, bucket) {
  const value = new Date(time);
  if (bucket === "hour") {
    return Date.UTC(
      value.getUTCFullYear(),
      value.getUTCMonth(),
      value.getUTCDate(),
      value.getUTCHours(),
    );
  }
  return Date.UTC(value.getUTCFullYear(), value.getUTCMonth(), value.getUTCDate());
}

function usageTimeseriesResponse(result) {
  const duration = result.bucket === "hour" ? 3600 * 1000 : 24 * 3600 * 1000;
  const points = [];
  for (let start = bucketStart(result.window.fromMs, result.bucket);
    start < result.window.toMs;
    start += duration) {
    points.push({
      start: new Date(start).toISOString(),
      end: new Date(start + duration).toISOString(),
      totals: emptyUsageTotals(),
      groups: new Map(),
    });
  }
  if (points.length > MAX_TIMESERIES_POINTS) {
    throw new HttpError(400, "too_many_buckets", "The requested time range has too many buckets");
  }

  for (const entry of result.matched) {
    const start = bucketStart(entry.record.time, result.bucket);
    const point = points[(start - bucketStart(result.window.fromMs, result.bucket)) / duration];
    if (!point) continue;
    addUsageRecord(point.totals, entry.record);
    const identity = usageDimension(entry, result.groupBy, result.data);
    let group = point.groups.get(identity.key);
    if (!group) {
      group = { ...identity, totals: emptyUsageTotals() };
      point.groups.set(identity.key, group);
    }
    addUsageRecord(group.totals, entry.record);
  }

  return {
    ok: true,
    window: { from: result.window.from, to: result.window.to },
    timezone: "UTC",
    bucket: result.bucket,
    groupBy: result.groupBy,
    points: points.map((point) => ({
      start: point.start,
      end: point.end,
      totals: {
        ...point.totals,
        costUsd: Number(point.totals.costUsd.toFixed(8)),
      },
      groups: [...point.groups.values()]
        .map((group) => ({
          ...group,
          ...group.totals,
          costUsd: Number(group.totals.costUsd.toFixed(8)),
          totals: undefined,
        }))
        .sort((left, right) => right.requests - left.requests
          || String(left.label).localeCompare(String(right.label))),
    })),
    source: usageSource(result, result.usage.records.length, result.unattributedRecords),
  };
}

function overviewError(error, fallback) {
  const code = error?.code || error?.statusCode || "unavailable";
  return `${fallback} (${String(code)}).`;
}

function adminPage(session, access, orgUnits, csrfToken, overview) {
  const roles = access.roles.length > 0 ? access.roles.join(", ") : "No active role";
  const scopes = access.scopeOrgUnitIds.length > 0 ? access.scopeOrgUnitIds.join(", ") : "None";
  const orgRows = orgUnits.length > 0
    ? orgUnits.map((org) => `<li><strong>${escapeHtml(org.name)}</strong> <code>${escapeHtml(org.path)}</code></li>`).join("")
    : "<li>No organization scope</li>";
  const usage = overview.usage;
  const usageBox = usage
    ? `<div class="grid">
        <section class="box"><h2>Requests</h2><p class="figure">${escapeHtml(usage.totals.requests)}</p></section>
        <section class="box"><h2>Errors</h2><p class="figure">${escapeHtml(usage.totals.errors)}</p></section>
        <section class="box"><h2>Tokens</h2><p class="figure">${escapeHtml(usage.totals.inputTokens + usage.totals.outputTokens + usage.totals.cacheReadTokens + usage.totals.cacheWriteTokens)}</p></section>
        <section class="box"><h2>Cost (USD)</h2><p class="figure">${escapeHtml(usage.totals.costUsd.toFixed(4))}</p></section>
      </div>
      <p>Window: ${escapeHtml(usage.window.from)} to ${escapeHtml(usage.window.to)} (UTC).</p>`
    : `<p class="notice">${escapeHtml(overview.usageError || "Usage is not available.")}</p>`;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Magpie Enterprise Admin</title>
  <style>
    :root{--ink:#172018;--paper:#f4f0e4;--card:#fffdf6;--line:#d7cfb9;--accent:#b93c2b}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#e6d9b8,transparent 38%),var(--paper);color:var(--ink);font:17px/1.55 Georgia,serif}
    main{width:min(960px,calc(100% - 32px));margin:6vh auto;padding:clamp(24px,5vw,56px);background:var(--card);border:1px solid var(--line);box-shadow:14px 14px 0 #dbca9d}
    h1{font-size:clamp(38px,7vw,74px);line-height:.92;margin:0 0 12px;letter-spacing:-.04em}
    h2{font-size:22px;margin:36px 0 10px;border-bottom:1px solid var(--line);padding-bottom:8px}
    .eyebrow{text-transform:uppercase;letter-spacing:.18em;font:700 12px/1.4 Georgia,serif;color:var(--accent)}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}.box{border:1px solid var(--line);padding:18px;background:#faf5e7}
    code{background:#ece3cc;padding:2px 6px;overflow-wrap:anywhere}ul{padding-left:22px}
    .figure{font-size:38px;line-height:1;margin:8px 0 0}.notice{border-left:4px solid var(--accent);padding:10px 14px;background:#faf5e7}
    .table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font:14px/1.4 Georgia,serif}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);white-space:nowrap}
    button{appearance:none;border:0;background:var(--ink);color:white;padding:12px 18px;font:700 14px/1 Georgia,serif;cursor:pointer}
  </style>
</head>
<body><main>
  <p class="eyebrow">Magpie Enterprise · Management plane</p>
  <h1>Administration</h1>
  <p>Signed in as <strong>${escapeHtml(session.email)}</strong>.</p>
  <div class="grid">
    <section class="box"><h2>Roles</h2><p>${escapeHtml(roles)}</p></section>
    <section class="box"><h2>Organization scope</h2><p><code>${escapeHtml(scopes)}</code></p></section>
  </div>
  <h2>Usage overview</h2>${usageBox}
  <h2>Users</h2>
  <p class="notice">${escapeHtml(overview.usersError || "Current organization-scoped identities.")}</p>
  ${table(
    ["Name", "Email", "Status", "Department"],
    overview.users.map((user) => [user.name, user.email, user.status, user.orgUnit?.path || "Unmapped"]),
  )}
  <h2>Devices</h2>
  <p class="notice">${escapeHtml(overview.devicesError || "No device token or Gateway Key is exposed.")}</p>
  ${table(
    ["Device", "Platform", "Status", "Last seen", "Key ID"],
    overview.devices.map((device) => [
      device.name,
      device.platform,
      device.status,
      device.lastSeenAt || "",
      device.gatewayKeyId || "",
    ]),
  )}
  <h2>Models</h2>
  <p class="notice">${escapeHtml(
    overview.modelsError
      || (overview.modelCatalog.authorizationReady
        ? "Read-only model catalog loaded for authorization."
        : "Legacy ADMIN_MODELS display list; it is not an authorization source."),
  )}</p>
  <p><code>schema ${escapeHtml(overview.modelCatalog.catalogVersion)} · ${escapeHtml(
    overview.modelCatalog.catalogDigest || "legacy display list",
  )} · ${escapeHtml(String(overview.modelCatalog.modelCount))} models · ${escapeHtml(
    String(overview.modelCatalog.groupCount),
  )} groups</code></p>
  ${table(
    ["Model ID", "Provider", "Display name"],
    overview.models.map((model) => [model.id, model.provider, model.displayName || ""]),
  )}
  <h2>Credentials</h2>
  <p class="notice">${escapeHtml(overview.credentialsError || "Gateway Key metadata only.")}</p>
  ${table(
    ["Key ID", "Device", "Status", "Expires"],
    overview.credentials.map((credential) => [
      credential.id,
      credential.deviceName || credential.deviceId,
      credential.status,
      credential.expiresAt || "",
    ]),
  )}
  <h2>Visible organization units</h2><ul>${orgRows}</ul>
  <h2>Session</h2>
  <p>Expires at ${escapeHtml(session.expiresAt)}. Every request recalculates roles from the store.</p>
  <form method="post" action="/api/v1/admin/logout">
    <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}">
    <button type="submit">Sign out</button>
  </form>
</main></body></html>`;
}

function clearedSessionCookies(config) {
  return [
    cookieHeader(config, config.sessionCookieName, "", 0),
    cookieHeader(config, config.csrfCookieName, "", 0, { httpOnly: false }),
  ];
}

export async function createEnterpriseAdminServer(config, options = {}) {
  const store = options.store || new JsonStore(config.storePath);
  await store.load();
  const modelCatalog = options.modelCatalog || (
    config.modelCatalog?.path
      ? await loadModelCatalog({
        filePath: config.modelCatalog.path,
        expectedDigest: config.modelCatalog.expectedDigest,
      })
      : legacyModelCatalog(config.models)
  );
  await store.mutate((data) => {
    data.adminSystemAuditLogs.push(modelCatalogStartupAudit(modelCatalog));
  });
  const oidc = options.oidc || new OidcClient(config.oidc);
  const authService = options.authService || new AuthServiceClient(config.authService);
  const rate = new Map();

  function allowRequest(req) {
    const now = Date.now();
    const key = `${req.socket.remoteAddress}:${req.method}:${new URL(req.url, "http://localhost").pathname}`;
    let bucket = rate.get(key);
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + 60000 };
      rate.set(key, bucket);
    }
    bucket.count += 1;
    return bucket.count <= config.rateLimitPerMinute;
  }

  async function currentSession(req) {
    const sid = sessionCookie(req, config);
    if (!sid) return null;
    const sidHash = sha256(sid);
    const result = await store.mutate((data) => {
      const session = data.adminSessions[sidHash];
      const state = sessionState(session, req, config);
      if (!state.ok) {
        if (session) delete data.adminSessions[sidHash];
        return { error: state.code };
      }
      session.lastSeenAt = new Date().toISOString();
      return { sidHash, session: structuredClone(session) };
    });
    if (result.error) {
      throw new HttpError(401, result.error, "The management session is no longer valid");
    }
    return result;
  }

  async function requirePermission(session, permission, targetOrgUnitId = "") {
    const result = await store.read((data) => {
      const access = effectiveAccess(data, session.subjectId);
      const decision = authorize(data, session.subjectId, permission, targetOrgUnitId);
      return { data, access, decision };
    });
    if (!result.decision.allowed) {
      throw new HttpError(403, result.decision.reason, "This action is not allowed");
    }
    return result;
  }

  function publicAuthUser(data, user) {
    const orgUnitId = activeUserOrgUnit(data, user.id);
    const org = orgUnitId ? data.orgUnits[orgUnitId] : null;
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      status: user.status,
      createdAt: user.createdAt || "",
      lastLoginAt: user.lastLoginAt || "",
      orgUnitId,
      orgUnit: org ? orgUnitSummary(org) : null,
    };
  }

  function publicAdminDevice(device) {
    return {
      id: device.id,
      userId: device.userId,
      name: device.name,
      platform: device.platform,
      clientVersion: device.clientVersion,
      status: device.status,
      createdAt: device.createdAt || "",
      lastSeenAt: device.lastSeenAt || "",
      gatewayKeyId: device.gatewayKeyId || "",
      keyExpiresAt: device.keyExpiresAt || "",
    };
  }

  function publicAdminCredential(credential) {
    return {
      id: credential.id,
      userId: credential.userId,
      deviceId: credential.deviceId,
      deviceName: credential.deviceName || "",
      deviceStatus: credential.deviceStatus || "unknown",
      status: credential.status,
      createdAt: credential.createdAt || "",
      expiresAt: credential.expiresAt || "",
      revokedAt: credential.revokedAt || "",
      deviceTokenExpiresAt: credential.deviceTokenExpiresAt || "",
      lastSeenAt: credential.lastSeenAt || "",
      publicKeySha256: credential.publicKeySha256 || "",
      models: Array.isArray(credential.models) ? credential.models.map(String) : [],
    };
  }

  function safeRevocations(value) {
    if (!value || typeof value !== "object") return { revoked: [], pending: 0 };
    return {
      revoked: Array.isArray(value.revoked) ? value.revoked.map(String) : [],
      pending: Number.isFinite(Number(value.pending)) ? Number(value.pending) : 0,
    };
  }

  function safeNumber(value) {
    return Number.isFinite(Number(value)) ? Number(value) : 0;
  }

  function safeWriteResult(action, value, data) {
    if (!value || typeof value !== "object") return {};
    if (action === "user.disable" || action === "user.enable") {
      return {
        user: value.user ? publicAuthUser(data, value.user) : null,
        affectedDevices: safeNumber(value.affectedDevices),
        affectedSessions: safeNumber(value.affectedSessions),
        affectedCredentials: safeNumber(value.affectedCredentials),
        devicesRestored: safeNumber(value.devicesRestored),
        credentialsRestored: safeNumber(value.credentialsRestored),
        requiresDeviceJoin: Boolean(value.requiresDeviceJoin),
        revocations: safeRevocations(value.revocations),
      };
    }
    if (action === "device.revoke") {
      return {
        device: value.device ? publicAdminDevice(value.device) : null,
        affectedCredentials: safeNumber(value.affectedCredentials),
        revocations: safeRevocations(value.revocations),
      };
    }
    return {
      credentialId: String(value.credentialId || ""),
      newCredentialId: String(value.newCredentialId || ""),
      userId: String(value.userId || ""),
      deviceId: String(value.deviceId || ""),
      status: String(value.status || ""),
      expiresAt: String(value.expiresAt || ""),
      revocations: safeRevocations(value.revocations),
    };
  }

  async function scopedUsers(session) {
    const result = await requirePermission(session, "users.read");
    const { users } = await authService.users();
    return {
      ...result,
      users: users
        .map((user) => publicAuthUser(result.data, user))
        .filter((user) => userInScope(result.data, result.access, user.id))
        .sort((left, right) => String(left.name || left.email)
          .localeCompare(String(right.name || right.email))),
    };
  }

  async function scopedUserDetail(session, userId) {
    const result = await requirePermission(session, "users.read");
    const { users } = await authService.users();
    const user = users.find((candidate) => candidate.id === userId);
    if (!user) throw new HttpError(404, "target_not_found", "User not found");
    if (!userInScope(result.data, result.access, user.id)) {
      throw new HttpError(403, "forbidden_scope", "This user is outside your organization scope");
    }
    return {
      ...result,
      user: publicAuthUser(result.data, user),
    };
  }

  async function scopedDevices(session) {
    const result = await requirePermission(session, "devices.read");
    const [{ users }, { devices }] = await Promise.all([authService.users(), authService.devices()]);
    const visible = visibleUserIds(result.data, result.access, users);
    return {
      ...result,
      devices: devices
        .filter((device) => visible.has(device.userId))
        .map(publicAdminDevice)
        .sort((left, right) => String(right.lastSeenAt)
          .localeCompare(String(left.lastSeenAt))),
    };
  }

  async function scopedCredentials(session) {
    const result = await requirePermission(session, "credentials.read");
    const [{ users }, { credentials }] = await Promise.all([
      authService.users(),
      authService.credentials(),
    ]);
    const visible = visibleUserIds(result.data, result.access, users);
    return {
      ...result,
      credentials: credentials
        .filter((credential) => visible.has(credential.userId))
        .map(publicAdminCredential)
        .sort((left, right) => String(right.createdAt)
          .localeCompare(String(left.createdAt))),
    };
  }

  async function writeTarget(session, permission, targetType, targetId) {
    const result = await requirePermission(session, permission);
    let target;
    if (targetType === "user") {
      const { users } = await authService.users();
      target = users.find((candidate) => candidate.id === targetId);
    } else if (targetType === "device") {
      const [{ users }, { devices }] = await Promise.all([
        authService.users(),
        authService.devices(),
      ]);
      target = devices.find((candidate) => candidate.id === targetId);
      if (target) {
        const user = users.find((candidate) => candidate.id === target.userId);
        if (!user) target = null;
      }
    } else {
      const [{ users }, { credentials }] = await Promise.all([
        authService.users(),
        authService.credentials(),
      ]);
      target = credentials.find((candidate) => candidate.id === targetId);
      if (target) {
        const user = users.find((candidate) => candidate.id === target.userId);
        if (!user) target = null;
      }
    }
    if (!target) throw new HttpError(404, "target_not_found", "Target not found");
    const userId = targetType === "user" ? target.id : target.userId;
    if (!userInScope(result.data, result.access, userId)) {
      throw new HttpError(403, "forbidden_scope", "This target is outside your organization scope");
    }
    return { ...result, target };
  }

  function auditRecord(operation, phase, result, options = {}) {
    return {
      id: `audit_${crypto.randomUUID()}`,
      operationId: operation.id,
      requestId: operation.requestId,
      timestamp: new Date().toISOString(),
      phase,
      actorSubject: operation.actorSubjectId,
      actorEmail: operation.actorEmail,
      roles: [...operation.roles],
      scopeOrgUnitIds: [...operation.scopeOrgUnitIds],
      action: operation.action,
      targetType: operation.targetType,
      targetId: operation.targetId,
      beforeSummary: structuredClone(operation.beforeSummary),
      afterSummary: phase === "result" ? structuredClone(options.afterSummary || {}) : {},
      result,
      errorCode: String(options.errorCode || ""),
      sourceIp: operation.sourceIp,
      userAgentHash: operation.userAgentHash,
      reason: operation.reason,
      approvalId: operation.approvalId,
    };
  }

  async function performWrite(req, res, requestId, options) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const reason = cleanReason(body.reason);
    const approvalId = cleanOptionalApprovalId(body.approvalId);
    const idempotencyKey = validateOptionalIdempotencyKey(req);

    const targetResult = await writeTarget(
      current.session,
      options.permission,
      options.targetType,
      options.targetId,
    );
    const targetId = targetResult.target.id;
    const requestFingerprint = writeRequestFingerprint(
      options.action,
      options.targetType,
      targetId,
      reason,
      approvalId,
    );
    const idempotencyKeyHash = idempotencyKey
      ? sha256(`${current.session.subjectId}\u0000${idempotencyKey}`)
      : "";
    const now = new Date().toISOString();
    const operation = {
      id: `op_${crypto.randomUUID()}`,
      requestId,
      idempotencyKeyHash,
      requestFingerprint,
      actorSubjectId: current.session.subjectId,
      actorEmail: current.session.email,
      roles: [...targetResult.access.roles],
      scopeOrgUnitIds: [...targetResult.access.scopeOrgUnitIds],
      action: options.action,
      targetType: options.targetType,
      targetId,
      reason,
      approvalId,
      beforeSummary: writeTargetSnapshot(options.targetType, targetResult.target),
      status: "received",
      createdAt: now,
      updatedAt: now,
      completedAt: "",
      intentAuditId: "",
      resultAuditId: "",
      responseStatus: 0,
      responseBody: null,
      errorCode: "",
      sourceIp: String(req.socket.remoteAddress || ""),
      userAgentHash: sha256(String(req.headers["user-agent"] || "")),
    };

    let reservation;
    try {
      reservation = await store.mutate((data) => {
        if (idempotencyKeyHash) {
          const existingEntry = data.adminIdempotency[idempotencyKeyHash];
          if (existingEntry) {
            const existing = data.adminOperations[existingEntry.operationId];
            if (!existing) {
              throw new HttpError(
                503,
                "storage_unavailable",
                "The idempotency record points to a missing operation",
              );
            }
            if (existingEntry.requestFingerprint !== requestFingerprint) {
              const conflict = new HttpError(
                409,
                "idempotency_conflict",
                "Idempotency-Key was already used for a different request",
              );
              conflict.operationId = existing.id;
              throw conflict;
            }
            return { kind: "existing", operation: structuredClone(existing) };
          }
        }

        data.adminOperations[operation.id] = structuredClone(operation);
        if (idempotencyKeyHash) {
          data.adminIdempotency[idempotencyKeyHash] = {
            operationId: operation.id,
            requestFingerprint,
            createdAt: now,
          };
        }
        const intent = auditRecord(operation, "intent", "pending");
        data.adminAuditLogs.push(intent);
        const stored = data.adminOperations[operation.id];
        stored.status = "dependency_invoked";
        stored.updatedAt = intent.timestamp;
        stored.intentAuditId = intent.id;
        return { kind: "created", operation: structuredClone(stored) };
      });
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw new HttpError(503, "audit_unavailable", "Management audit is unavailable");
    }

    if (reservation.kind === "existing") {
      const existing = reservation.operation;
      if (existing.status === "succeeded") {
        if (existing.responseBody && Number(existing.responseStatus) >= 200
            && Number(existing.responseStatus) < 300) {
          json(res, Number(existing.responseStatus), existing.responseBody);
          return;
        }
        throw new HttpError(503, "storage_unavailable", "The stored operation result is incomplete");
      }
      if (existing.status === "failed") {
        const failure = new HttpError(
          Number(existing.responseStatus) || 500,
          existing.errorCode || "operation_failed",
          "The original operation failed",
        );
        failure.operationId = existing.id;
        throw failure;
      }
      const inProgress = new HttpError(
        409,
        "operation_in_progress",
        "An operation with this Idempotency-Key is still in progress",
      );
      inProgress.operationId = existing.id;
      throw inProgress;
    }

    let responseBody = null;
    let responseStatus = 200;
    let errorCode = "";
    let operationError = null;
    try {
      const dependencyResponse = await options.call(targetId);
      responseBody = {
        ok: true,
        requestId,
        operationId: operation.id,
        action: options.action,
        targetId,
        result: safeWriteResult(options.action, dependencyResponse.data, targetResult.data),
      };
    } catch (error) {
      operationError = error instanceof Error ? error : new Error("The dependency call failed");
      responseStatus = Number.isInteger(operationError.statusCode)
        ? operationError.statusCode
        : 500;
      errorCode = typeof operationError.code === "string" && operationError.code
        ? operationError.code
        : (responseStatus >= 500 ? "internal_error" : "operation_failed");
    }

    try {
      await store.mutate((data) => {
        const stored = data.adminOperations[operation.id];
        if (!stored) throw new Error("write operation disappeared before its result");
        const completedAt = new Date().toISOString();
        stored.status = operationError ? "failed" : "succeeded";
        stored.updatedAt = completedAt;
        stored.completedAt = completedAt;
        stored.responseStatus = responseStatus;
        stored.responseBody = responseBody;
        stored.errorCode = errorCode;
        const resultAudit = auditRecord(operation, "result", stored.status, {
          afterSummary: responseBody?.result || {},
          errorCode,
        });
        data.adminAuditLogs.push(resultAudit);
        stored.resultAuditId = resultAudit.id;
      });
    } catch {
      const auditFailure = new HttpError(
        503,
        "audit_unavailable",
        "The operation result could not be audited",
      );
      auditFailure.operationId = operation.id;
      throw auditFailure;
    }

    if (operationError) {
      operationError.operationId = operation.id;
      throw operationError;
    }
    json(res, 200, responseBody);
  }

  async function usageReport(session, searchParams, grouped) {
    const result = await requirePermission(session, "usage.read");
    const window = finiteWindow(searchParams, config.usage.maxRangeDays);
    const bucket = grouped
      ? String(searchParams.get("bucket") || "day").toLowerCase()
      : "";
    if (grouped && bucket !== "hour" && bucket !== "day") {
      throw new HttpError(400, "invalid_bucket", "bucket must be hour or day");
    }
    const groupBy = grouped
      ? String(searchParams.get("groupBy") || "all").toLowerCase()
      : "all";
    if (grouped && !["all", "user", "department", "model", "agent"].includes(groupBy)) {
      throw new HttpError(400, "invalid_group_by", "groupBy is not supported");
    }
    const [{ users }, { credentials }] = await Promise.all([
      authService.users(),
      authService.credentials(),
    ]);
    const usage = await readUsageFile(config.usage, window);
    const userById = new Map(users.map((user) => [user.id, user]));
    const credentialById = new Map(credentials.map((credential) => [credential.id, credential]));
    const visible = visibleUserIds(result.data, result.access, users);
    const matched = [];
    let unattributedRecords = 0;
    for (const record of usage.records) {
      const credential = credentialById.get(record.callerKeyId);
      const user = credential ? userById.get(credential.userId) : null;
      if (!user) {
        unattributedRecords += 1;
        continue;
      }
      if (!visible.has(user.id)) continue;
      matched.push({ record, credential, user });
    }

    return {
      ...result,
      window,
      usage,
      matched,
      unattributedRecords,
      userById,
      credentialById,
      bucket,
      groupBy,
    };
  }

  async function adminOverview(session) {
    async function capture(operation, fallback) {
      try {
        return { value: await operation(), error: "" };
      } catch (error) {
        return { value: fallback, error: overviewError(error, "Unavailable") };
      }
    }

    const [users, devices, credentials, models, usage] = await Promise.all([
      capture(() => scopedUsers(session), []),
      capture(() => scopedDevices(session), []),
      capture(() => scopedCredentials(session), []),
      capture(async () => {
        await requirePermission(session, "models.read");
        return modelCatalog.models.map((model) => ({
          id: model.id,
          provider: model.provider,
          displayName: model.displayName,
        }));
      }, []),
      capture(() => usageReport(session, new URLSearchParams(), false), null),
    ]);

    return {
      users: users.value.users || [],
      usersError: users.error,
      devices: devices.value.devices || [],
      devicesError: devices.error,
      credentials: credentials.value.credentials || [],
      credentialsError: credentials.error,
      models: models.value,
      modelsError: models.error,
      modelCatalog: { ...modelCatalog.status },
      usage: usage.value ? usageSummaryResponse(usage.value) : null,
      usageError: usage.error,
    };
  }

  async function requireCsrf(req, session, formToken = "") {
    const origin = String(req.headers.origin || "");
    if (origin && origin !== new URL(config.publicUrl).origin) {
      throw new HttpError(403, "csrf_invalid", "Request origin is not allowed");
    }
    const token = String(req.headers["x-csrf-token"] || formToken || "");
    if (!validCsrf(session, token)) {
      throw new HttpError(403, "csrf_invalid", "A valid CSRF token is required");
    }
  }

  async function mePayload(req, session) {
    let token = csrfCookie(req, config);
    const headers = {};
    if (!validCsrf(session, token)) {
      token = randomToken(32);
      await store.mutate((data) => {
        const current = data.adminSessions[sha256(sessionCookie(req, config))];
        if (!current) throw new HttpError(401, "not_signed_in", "The management session is no longer valid");
        current.csrfHash = sha256(token);
      });
      headers["set-cookie"] = cookieHeader(
        config,
        config.csrfCookieName,
        signCookie(token, config.sessionSecret),
        config.sessionTtlSeconds,
        { httpOnly: false },
      );
    }
    const data = await store.read((current) => {
      const access = effectiveAccess(current, session.subjectId);
      return {
        access,
        orgUnits: visibleOrgUnits(current, access),
      };
    });
    return {
      value: {
        user: publicIdentity(session),
        roles: data.access.roles,
        permissions: data.access.permissions,
        scopeOrgUnitIds: data.access.scopeOrgUnitIds,
        orgUnits: data.orgUnits,
        session: sessionInfo(session),
        csrfToken: token,
      },
      headers,
    };
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

    if (!requestAllowed(req, config)) {
      apiError(res, requestId, 403, "ip_not_allowed", "This client address is not allowed");
      return;
    }

    const url = new URL(req.url, "http://localhost");
    if (url.pathname !== "/healthz" && !allowRequest(req)) {
      apiError(res, requestId, 429, "rate_limited", "Too many requests; try again shortly");
      return;
    }

    if (req.method === "GET" && url.pathname === "/healthz") {
      const status = await store.read((data) => ({
        ok: true,
        service: "admin",
        orgUnits: Object.keys(data.orgUnits).length,
        roleBindings: Object.keys(data.roleBindings).length,
      }));
      json(res, 200, {
        ...status,
        modelCatalog: { ...modelCatalog.status },
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/admin") {
      redirect(res, "/admin/");
      return;
    }

    if (req.method === "GET" && url.pathname === "/admin/login") {
      if (sessionCookie(req, config)) {
        try {
          if (await currentSession(req)) {
            redirect(res, "/admin/");
            return;
          }
        } catch {
          // The stale cookie is cleared below before starting a new login.
        }
      }
      const started = await oidc.begin();
      redirect(res, started.url, {
        "set-cookie": [
          cookieHeader(
            config,
            config.loginCookieName,
            signCookie(JSON.stringify(started.transaction), config.sessionSecret),
            600,
          ),
          ...(sessionCookie(req, config) ? clearedSessionCookies(config) : []),
        ],
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/admin/oauth/callback") {
      const cookies = parseCookies(req.headers.cookie);
      const raw = verifyCookie(cookies[config.loginCookieName], config.sessionSecret);
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
      const identity = normalizeAdminIdentity(completed.claims, config.oidc);
      identity.id = adminSubjectId(config.oidc.issuer, identity.subject);
      const created = newSession(identity, req, config);
      await store.mutate((data) => {
        const binding = bootstrapBinding(identity, config);
        if (binding && !Object.values(data.roleBindings).some((candidate) =>
          candidate.subjectId === binding.subjectId
          && candidate.role === binding.role
          && candidate.scopeOrgUnitId === binding.scopeOrgUnitId)) {
          data.roleBindings[binding.id] = binding;
        }
        data.adminSessions[sha256(created.sid)] = created.session;
      });
      redirect(res, "/admin/", {
        "set-cookie": [
          cookieHeader(
            config,
            config.sessionCookieName,
            signCookie(created.sid, config.sessionSecret),
            config.sessionTtlSeconds,
          ),
          cookieHeader(
            config,
            config.csrfCookieName,
            signCookie(created.csrfToken, config.sessionSecret),
            config.sessionTtlSeconds,
            { httpOnly: false },
          ),
          cookieHeader(config, config.loginCookieName, "", 0),
        ],
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/admin/") {
      let current;
      try {
        current = await currentSession(req);
      } catch {
        redirect(res, "/admin/login", { "set-cookie": clearedSessionCookies(config) });
        return;
      }
      if (!current) {
        redirect(res, "/admin/login");
        return;
      }
      const payload = await mePayload(req, current.session);
      const overview = await adminOverview(current.session);
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(adminPage(
        current.session,
        {
          roles: payload.value.roles,
          scopeOrgUnitIds: payload.value.scopeOrgUnitIds,
        },
        payload.value.orgUnits,
        payload.value.csrfToken,
        overview,
      ));
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/me") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const payload = await mePayload(req, current.session);
      json(res, 200, payload.value, payload.headers);
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/v1/admin/logout") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const htmlForm = /^application\/x-www-form-urlencoded(?:\s*;|$)/i
        .test(String(req.headers["content-type"] || ""));
      const form = await readForm(req);
      await requireCsrf(req, current.session, form.get("_csrf") || "");
      await store.mutate((data) => {
        delete data.adminSessions[current.sidHash];
      });
      const headers = { "set-cookie": clearedSessionCookies(config) };
      if (htmlForm) {
        redirect(res, "/admin/login", headers);
      } else {
        json(res, 200, { ok: true }, headers);
      }
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/org-units") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const result = await requirePermission(current.session, "users.read");
      json(res, 200, { orgUnits: visibleOrgUnits(result.data, result.access) });
      return;
    }

    const orgUnitMatch = /^\/api\/v1\/admin\/org-units\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
    if (req.method === "GET" && orgUnitMatch) {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const targetId = orgUnitMatch[1];
      const target = await store.read((data) => data.orgUnits[targetId] || null);
      if (!target) throw new HttpError(404, "target_not_found", "Organization unit not found");
      await requirePermission(current.session, "users.read", targetId);
      json(res, 200, {
        orgUnit: {
          id: target.id,
          parentId: target.parentId || "",
          name: target.name,
          path: target.path,
          status: target.status,
        },
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/departments") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const result = await requirePermission(current.session, "users.read");
      json(res, 200, { departments: visibleOrgUnits(result.data, result.access) });
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/users") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const result = await scopedUsers(current.session);
      json(res, 200, { users: result.users });
      return;
    }

    const userMatch = /^\/api\/v1\/admin\/users\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
    if (req.method === "GET" && userMatch) {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const result = await scopedUserDetail(current.session, userMatch[1]);
      json(res, 200, { user: result.user });
      return;
    }

    const userWriteMatch = /^\/api\/v1\/admin\/users\/([A-Za-z0-9_-]+)\/(disable|enable)$/.exec(
      url.pathname,
    );
    if (req.method === "POST" && userWriteMatch) {
      const disable = userWriteMatch[2] === "disable";
      await performWrite(req, res, requestId, {
        action: disable ? "user.disable" : "user.enable",
        permission: "users.disable",
        targetType: "user",
        targetId: userWriteMatch[1],
        call: disable
          ? (id) => authService.disableUser(id)
          : (id) => authService.enableUser(id),
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/devices") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const result = await scopedDevices(current.session);
      json(res, 200, { devices: result.devices });
      return;
    }

    const deviceWriteMatch = /^\/api\/v1\/admin\/devices\/([A-Za-z0-9_-]+)\/revoke$/.exec(
      url.pathname,
    );
    if (req.method === "POST" && deviceWriteMatch) {
      await performWrite(req, res, requestId, {
        action: "device.revoke",
        permission: "devices.revoke",
        targetType: "device",
        targetId: deviceWriteMatch[1],
        call: (id) => authService.revokeDevice(id),
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/credentials") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const result = await scopedCredentials(current.session);
      json(res, 200, { credentials: result.credentials });
      return;
    }

    const credentialWriteMatch = /^\/api\/v1\/admin\/credentials\/([A-Za-z0-9_-]+)\/rotate$/.exec(
      url.pathname,
    );
    if (req.method === "POST" && credentialWriteMatch) {
      await performWrite(req, res, requestId, {
        action: "credential.rotate",
        permission: "credentials.rotate",
        targetType: "credential",
        targetId: credentialWriteMatch[1],
        call: (id) => authService.rotateCredential(id),
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/models") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      await requirePermission(current.session, "models.read");
      json(res, 200, publicModelCatalog(modelCatalog));
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/usage/summary") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const result = await usageReport(current.session, url.searchParams, false);
      json(res, 200, usageSummaryResponse(result));
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/usage/timeseries") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const result = await usageReport(current.session, url.searchParams, true);
      json(res, 200, usageTimeseriesResponse(result));
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/health") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      await requirePermission(current.session, "system.read");
      const auth = await authService.status();
      json(res, 200, {
        ok: true,
        auth,
        modelCatalog: { ...modelCatalog.status },
      });
      return;
    }

    apiError(res, requestId, 404, "not_found", "Route not found");
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((error) => {
      const statusCode = error.statusCode || 500;
      const code = error.code || (statusCode >= 500 ? "internal_error" : "request_failed");
      const message = statusCode >= 500
        ? "The management service could not complete the request"
        : error.message;
      if (statusCode >= 500) {
        console.error(`${req.method} ${req.url}: ${error.name}: ${error.message}`);
      }
      if (!res.headersSent) {
        if (statusCode === 401
            && ["not_signed_in", "session_expired", "session_idle", "session_revoked", "session_binding_mismatch"].includes(code)) {
          res.setHeader("set-cookie", clearedSessionCookies(config));
        }
        apiError(
          res,
          res.getHeader("x-request-id") || "",
          statusCode,
          code,
          message,
          error.operationId || "",
        );
      } else {
        res.destroy();
      }
    });
  });
  server.requestTimeout = 30000;
  server.headersTimeout = 10000;
  return { server, store, oidc, authService, modelCatalog };
}
