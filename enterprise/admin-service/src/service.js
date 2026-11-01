import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
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
import {
  APPROVAL_POLICY_VERSION,
  approvalBindingDigest,
  approvalConsumptionFailure,
  approvalIsExpired,
  approvalPayloadDigest,
  approvalRequiredForAction,
  normalizedApprovalPayload,
  publicApproval,
  riskForAction,
} from "./approval.js";
import { JsonStore } from "./store.js";
import { readUsageFile } from "./usage-reader.js";

const MAX_BODY = 16 * 1024;
const DEFAULT_USAGE_WINDOW_DAYS = 7;
const MAX_TIMESERIES_POINTS = 10000;
const DEFAULT_AUDIT_LIMIT = 50;
const MAX_AUDIT_LIMIT = 200;
const MAX_AUDIT_CURSOR = 4096;
const APPROVAL_TTL_MS = 24 * 60 * 60 * 1000;
const ADMIN_APP_JS = await fs.readFile(new URL("./admin-app.js", import.meta.url), "utf8");

const OPERATION_PERMISSIONS = Object.freeze({
  "user.disable": "users.disable",
  "user.enable": "users.disable",
  "device.revoke": "devices.revoke",
  "credential.rotate": "credentials.rotate",
  "user.policy.quota": "quota.write",
  "user.policy.models": "models.write",
  "operation.reconcile": "operations.reconcile",
});

const APPROVAL_ACTION_TARGETS = Object.freeze({
  "user.disable": { targetType: "user", permission: "users.disable" },
  "user.enable": { targetType: "user", permission: "users.disable" },
  "device.revoke": { targetType: "device", permission: "devices.revoke" },
  "credential.rotate": { targetType: "credential", permission: "credentials.rotate" },
  "user.policy.quota": { targetType: "user", permission: "quota.write" },
  "user.policy.models": { targetType: "user", permission: "models.write" },
  "operation.reconcile": { targetType: "operation", permission: "operations.reconcile" },
});

const POLICY_ACTIONS = new Set([
  "user.policy.quota",
  "user.policy.models",
]);

const RECONCILIATION_ACTIONS = new Set([
  "retry_desired",
  "rollback_previous",
  "confirm_applied",
  "confirm_not_applied",
]);

const RECONCILIATION_STATES = new Set([
  "not_required",
  "pending",
  "confirmed_applied",
  "confirmed_not_applied",
  "compensated",
]);

const NON_RETRYABLE_OPERATION_ERRORS = new Set([
  "approval_required",
  "approval_invalid",
  "approval_expired",
  "approval_revoked",
  "approval_consumed",
  "approval_target_mismatch",
  "approval_payload_mismatch",
  "approval_separation_required",
  "approval_unavailable",
  "csrf_invalid",
  "forbidden_role",
  "forbidden_scope",
  "idempotency_conflict",
  "invalid_approval_id",
  "invalid_approval_action",
  "invalid_json",
  "invalid_reason",
  "invalid_request",
  "target_org_required",
  "target_not_found",
]);

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

function validateRequiredIdempotencyKey(req) {
  const value = validateOptionalIdempotencyKey(req);
  if (!value) {
    throw new HttpError(400, "idempotency_key_required", "Idempotency-Key is required");
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

function cleanIdentifier(value, name, code = "invalid_request") {
  const identifier = String(value ?? "").trim();
  if (!identifier) throw new HttpError(400, code, `${name} is required`);
  if ([...identifier].length > 128 || /[\u0000-\u001f\u007f]/.test(identifier)) {
    throw new HttpError(400, code, `${name} is invalid`);
  }
  return identifier;
}

function cleanEvidenceRef(value, required = false) {
  const evidenceRef = String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, "").trim();
  if (!evidenceRef) {
    if (required) throw new HttpError(400, "evidence_required", "evidenceRef is required");
    return "";
  }
  if ([...evidenceRef].length > 500) {
    throw new HttpError(400, "invalid_evidence_ref", "evidenceRef must be at most 500 characters");
  }
  return evidenceRef;
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

function safeStringList(value) {
  return Array.isArray(value) ? value.map(String) : [];
}

function safePolicyLimits(limits) {
  if (!Array.isArray(limits)) return null;
  return limits.map((limit) => {
    if (!limit || typeof limit !== "object" || Array.isArray(limit)) return {};
    const output = {
      period: String(limit.period || ""),
    };
    for (const key of ["days", "hours", "tokens", "cost"]) {
      if (Number.isFinite(Number(limit[key]))) output[key] = Number(limit[key]);
    }
    if (typeof limit.cacheReads === "boolean") output.cacheReads = limit.cacheReads;
    return output;
  });
}

function policyLimitsAreValid(limits) {
  if (!Array.isArray(limits) || limits.length > 5) return false;
  const seen = new Set();
  for (const limit of limits) {
    if (!limit || typeof limit !== "object" || Array.isArray(limit)) return false;
    if (!["day", "week", "month", "days", "hours"].includes(limit.period)) return false;
    const tokens = limit.tokens == null ? 0 : limit.tokens;
    const cost = limit.cost == null ? 0 : limit.cost;
    if (!Number.isSafeInteger(tokens) || tokens < 0) return false;
    if (!Number.isFinite(cost) || cost < 0) return false;
    if (Math.abs(cost * 10000 - Math.round(cost * 10000)) > 1e-7) return false;
    if (tokens <= 0 && cost <= 0) return false;
    if (limit.cacheReads != null && typeof limit.cacheReads !== "boolean") return false;
    if (limit.period === "days") {
      if (!Number.isInteger(limit.days) || limit.days < 1 || limit.days > 3650) return false;
      if (limit.hours != null) return false;
    } else if (limit.period === "hours") {
      if (!Number.isInteger(limit.hours) || limit.hours < 1 || limit.hours > 8760) return false;
      if (limit.days != null) return false;
    } else if (limit.days != null || limit.hours != null) {
      return false;
    }
    const windowKey = `${limit.period}|${limit.days || ""}|${limit.hours || ""}`;
    if (seen.has(windowKey)) return false;
    seen.add(windowKey);
  }
  return true;
}

function safeAuditValue(value, depth = 0) {
  if (value == null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  if (typeof value === "string") return value.slice(0, 1000);
  if (depth >= 5) return null;
  if (Array.isArray(value)) {
    return value.slice(0, 100).map((entry) => safeAuditValue(entry, depth + 1));
  }
  if (typeof value !== "object") return String(value).slice(0, 1000);
  const output = {};
  for (const [key, entry] of Object.entries(value).slice(0, 50)) {
    const normalizedKey = key.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
    if (key.length > 80
        || [
          "gatewaykey",
          "devicetoken",
          "credential",
          "servicetoken",
          "accesstoken",
          "refreshtoken",
          "requestbody",
          "responsebody",
          "body",
          "rawbody",
          "content",
          "message",
          "messages",
          "transcript",
          "completion",
          "dialogue",
          "apikey",
        ].includes(normalizedKey)
        || /token|secret|password|cookie|authorization|privatekey|publickey|prompt|conversation/.test(normalizedKey)) {
      continue;
    }
    output[key] = safeAuditValue(entry, depth + 1);
  }
  return output;
}

function operationState(operation) {
  const resultState = String(operation?.responseBody?.result?.state || "");
  return resultState || String(operation?.status || "unknown");
}

function operationRetryable(operation) {
  const state = operationState(operation);
  if (["partial_success", "pending_sync", "unknown"].includes(state)) return true;
  if (operation?.status !== "failed") return false;
  return !NON_RETRYABLE_OPERATION_ERRORS.has(String(operation.errorCode || ""));
}

function explicitReconciliationState(operation) {
  const state = String(operation?.reconciliationState || "");
  return RECONCILIATION_STATES.has(state) ? state : "";
}

function operationRequiresReconciliation(operation) {
  const reconciliationState = explicitReconciliationState(operation);
  if (["confirmed_applied", "confirmed_not_applied", "compensated"].includes(reconciliationState)) {
    return false;
  }
  if (reconciliationState === "pending") return true;
  const state = operationState(operation);
  if (state === "dependency_invoked"
      || state === "partial_success"
      || state === "pending_sync"
      || state === "unknown") {
    return true;
  }
  if (operation?.responseBody?.result?.requiresReconciliation === true) return true;
  return operation?.status === "failed" && operationRetryable(operation);
}

function compareAuditRecords(left, right) {
  const timestampOrder = String(right.timestamp || "").localeCompare(String(left.timestamp || ""));
  if (timestampOrder !== 0) return timestampOrder;
  return String(right.id || "").localeCompare(String(left.id || ""));
}

function writeRequestFingerprint(action, targetType, targetId, reason, approvalId, payload = {}) {
  return sha256(JSON.stringify(canonicalValue({
    action,
    targetType,
    targetId,
    reason,
    approvalId,
    payload,
  })));
}

function writeTargetSnapshot(targetType, target) {
  if (targetType === "user") {
    const policy = target.policy && typeof target.policy === "object" && !Array.isArray(target.policy)
      ? target.policy
      : {};
    return {
      id: String(target.id || ""),
      email: String(target.email || ""),
      status: String(target.status || ""),
      version: Number.isSafeInteger(policy.version) ? policy.version : 0,
      models: Array.isArray(policy.models) ? safeStringList(policy.models) : null,
      limits: safePolicyLimits(policy.limits),
      quotaStatus: String(policy.quotaStatus || "unknown"),
      modelStatus: String(policy.modelStatus || "unknown"),
      updatedAt: String(policy.updatedAt || ""),
      confirmedAt: String(policy.confirmedAt || ""),
      operationId: String(policy.operationId || ""),
      including: safeStringList(policy.including),
      missing: safeStringList(policy.missing),
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

function policyEvidence(user, credentials, operation) {
  const policy = user.policy;
  if (!policy) {
    return {
      verified: false,
      label: "No policy record",
      detail: "This identity has no gateway policy. Do not infer quota or model access.",
    };
  }
  if (policy.quotaStatus === "unknown" || policy.modelStatus === "unknown") {
    return {
      verified: false,
      label: "Historical state unknown",
      detail: `Unknown sections: ${policy.missing?.length ? policy.missing.join(", ") : "quota, models"}. `
        + "Set both sections before a client can join.",
    };
  }
  const active = credentials.filter((credential) => credential.userId === user.id
    && credential.status === "active");
  const hasActiveCredentials = active.length > 0;
  const allSynced = hasActiveCredentials
    && active.every((credential) => credential.policyVersion === policy.version
    && credential.policySyncState === "synced");
  const operationMatches = Boolean(operation
    && operation.operationId
    && operation.operationId === policy.operationId);
  const verified = policy.quotaStatus === "known"
    && policy.modelStatus === "known"
    && hasActiveCredentials
    && allSynced
    && operationMatches
    && operation.state === "succeeded"
    && !operation.requiresReconciliation;
  if (verified) {
    return {
      verified: true,
      label: "Applied and verified",
      detail: `Policy v${policy.version}; ${active.length} active credentials verified by independent readback.`,
    };
  }
  if (operationMatches && operation.state === "unknown") {
    return {
      verified: false,
      label: "Gateway result unknown",
      detail: `Operation ${operation.operationId} invoked the gateway but its result is unconfirmed. `
        + "Do not retry automatically.",
    };
  }
  if (operationMatches && operation.state === "dependency_invoked") {
    return {
      verified: false,
      label: "Gateway invoked, awaiting evidence",
      detail: `Operation ${operation.operationId} has not recorded a confirmed result. `
        + "Do not retry automatically.",
    };
  }
  if (!hasActiveCredentials) {
    return {
      verified: false,
      label: "Policy saved; no active credentials",
      detail: "No active credential exists to verify by gateway readback. "
        + "The next join will apply this policy before delivering a key.",
    };
  }
  return {
    verified: false,
    label: allSynced ? "Operation evidence incomplete" : "Pending gateway sync",
    detail: `${active.length} active credentials; ${active.filter((credential) => credential.policySyncState !== "synced"
      || credential.policyVersion !== policy.version).length} pending or unknown.`,
  };
}

function policyEditor(user, evidence, operation, access) {
  const canQuota = access.permissions.includes("quota.write");
  const canModels = access.permissions.includes("models.write");
  if (!canQuota && !canModels) {
    return `<p class="notice">Read-only access. Your role cannot change user policies.</p>`;
  }
  const policy = user.policy;
  if (!policy) {
    return `<p class="notice">No policy record is available for this user.</p>`;
  }
  const currentLimits = Array.isArray(policy.limits)
    ? JSON.stringify(policy.limits, null, 2)
    : "";
  const currentModels = Array.isArray(policy.models) ? policy.models.join("\n") : "";
  const operationLine = operation
    ? `<p><strong>Latest operation:</strong> <code>${escapeHtml(operation.operationId)}</code> `
      + `state <code>${escapeHtml(operation.state)}</code>`
      + `${operation.errorCode ? ` error <code>${escapeHtml(operation.errorCode)}</code>` : ""}</p>`
    : `<p>No management operation evidence is stored for this policy version.</p>`;
  const quotaForm = canQuota
    ? `<form class="policy-write-form" data-part="quota"
        data-endpoint="/api/v1/admin/users/${encodeURIComponent(user.id)}/policy/quota"
        data-method="PUT" data-version="${escapeHtml(policy.version)}">
        <h4>Set quota windows</h4>
        <p>Use a JSON array with 0-5 windows. Unknown history is not replaced by a default.</p>
        <label>Quota JSON
          <textarea name="limits" rows="7" required
            placeholder='[{&quot;period&quot;:&quot;month&quot;,&quot;tokens&quot;:100000,&quot;cost&quot;:25}]'>${escapeHtml(currentLimits)}</textarea>
        </label>
        <label>Reason <input name="reason" maxlength="500" required></label>
        <label>Approval ID (optional) <input name="approvalId" maxlength="128"></label>
        <input type="hidden" name="expectedVersion" value="${escapeHtml(policy.version)}">
        <button type="submit">Save quota</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>`
    : `<p class="notice">Your role cannot change quota.</p>`;
  const modelsForm = canModels
    ? `<form class="policy-write-form" data-part="models"
        data-endpoint="/api/v1/admin/users/${encodeURIComponent(user.id)}/policy/models"
        data-method="PATCH" data-version="${escapeHtml(policy.version)}">
        <h4>Set model authorization</h4>
        <p>One selector per line or comma-separated. Groups and explicit provider wildcards are expanded by the catalog.</p>
        <label>Model selectors
          <textarea name="selectors" rows="6" required
            placeholder="group/engineering-approved&#10;company-model/*">${escapeHtml(currentModels)}</textarea>
        </label>
        <label>Reason <input name="reason" maxlength="500" required></label>
        <label>Approval ID (optional) <input name="approvalId" maxlength="128"></label>
        <input type="hidden" name="expectedVersion" value="${escapeHtml(policy.version)}">
        <button type="submit">Save models</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>`
    : `<p class="notice">Your role cannot change model authorization.</p>`;
  return `<details class="policy-editor">
    <summary>Manage ${escapeHtml(user.email)}</summary>
    <p><strong>Policy evidence:</strong> ${escapeHtml(evidence.label)}. ${escapeHtml(evidence.detail)}</p>
    ${operationLine}
    <div class="editor-grid">${quotaForm}${modelsForm}</div>
  </details>`;
}

function adminPage(session, access, orgUnits, csrfToken, overview) {
  const roles = access.roles.length > 0 ? access.roles.join(", ") : "No active role";
  const scopes = access.scopeOrgUnitIds.length > 0 ? access.scopeOrgUnitIds.join(", ") : "None";
  const orgRows = orgUnits.length > 0
    ? orgUnits.map((org) => `<li><strong>${escapeHtml(org.name)}</strong> <code>${escapeHtml(org.path)}</code></li>`).join("")
    : "<li>No organization scope</li>";
  const usage = overview.usage;
  const editors = overview.users.map((user) => {
    const operation = overview.operationsByUser[user.id] || null;
    const evidence = policyEvidence(user, overview.credentials, operation);
    return policyEditor(user, evidence, operation, access);
  }).join("");
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
  <meta name="csrf-token" content="${escapeHtml(csrfToken)}">
  <title>Magpie Enterprise Admin</title>
  <style>
    :root{--ink:#172018;--paper:#f4f0e4;--card:#fffdf6;--line:#d7cfb9;--accent:#b93c2b;--ok:#17643a;--warn:#9a5b00;--danger:#9e2518}
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
    .policy-editor{margin:14px 0;border:1px solid var(--line);background:#faf5e7;padding:14px}.policy-editor summary{cursor:pointer;font-weight:700}
    .editor-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px}.editor-grid form{border-top:1px solid var(--line);padding-top:12px}
    label{display:grid;gap:6px;margin:10px 0;font-weight:700}input,textarea{width:100%;border:1px solid var(--line);background:var(--card);padding:10px;font:15px/1.4 ui-monospace,monospace}
    .write-result{min-height:3em;border-left:4px solid var(--line);padding:8px 12px}.write-result[data-tone="error"]{border-color:var(--danger)}.write-result[data-tone="unknown"]{border-color:var(--warn)}.write-result[data-tone="result"]{border-color:var(--ok)}
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
    ["Name", "Email", "Status", "Department", "Policy", "Quota", "Models", "Sync"],
    overview.users.map((user) => [
      user.name,
      user.email,
      user.status,
      user.orgUnit?.path || "Unmapped",
      user.policy ? `v${user.policy.version}` : "Missing",
      user.policy?.quotaStatus || "unknown",
      user.policy?.modelStatus || "unknown",
      policyEvidence(
        user,
        overview.credentials,
        overview.operationsByUser[user.id] || null,
      ).label,
    ]),
  )}
  <h2>Policy operations</h2>
  <p class="notice">Only a complete evidence chain permits the verified state. Pending, partial, and unknown results are never converted into success by this page.</p>
  ${editors || "<p>No users available in your organization scope.</p>"}
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
    ["Key ID", "Device", "Status", "Policy", "Policy sync", "Last synced", "Last error", "Expires"],
    overview.credentials.map((credential) => [
      credential.id,
      credential.deviceName || credential.deviceId,
      credential.status,
      `v${credential.policyVersion}`,
      credential.policySyncState,
      credential.lastPolicySyncedAt || credential.lastPolicyAttemptedAt || "",
      credential.lastPolicyErrorCode || "",
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
</main><script src="/admin/app.js" defer></script></body></html>`;
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
  const approvalEnvironmentId = `env_${sha256(new URL(config.publicUrl).origin).slice(0, 24)}`;

  function currentApprovalPolicyVersion() {
    const catalogVersion = Number.isSafeInteger(modelCatalog.status.catalogVersion)
      ? modelCatalog.status.catalogVersion
      : 0;
    return `${APPROVAL_POLICY_VERSION}:catalog=${catalogVersion}:${
      modelCatalog.status.catalogDigest || "legacy"
    }`;
  }

  function appendApprovalSystemAudit(data, action, approval, options = {}) {
    data.adminSystemAuditLogs.push({
      id: `audit_${crypto.randomUUID()}`,
      action,
      timestamp: new Date().toISOString(),
      approvalId: String(approval?.id || ""),
      result: String(options.result || ""),
      errorCode: String(options.errorCode || ""),
      actorSubjectId: String(options.actorSubjectId || ""),
      actorEmail: String(options.actorEmail || ""),
      requesterSubjectId: String(approval?.requesterSubjectId || ""),
      approvalAction: String(approval?.action || options.approvalAction || ""),
      targetType: String(approval?.targetType || options.targetType || ""),
      targetId: String(approval?.targetId || options.targetId || ""),
      targetOrgUnitId: String(approval?.targetOrgUnitId || options.targetOrgUnitId || ""),
      riskLevel: String(approval?.riskLevel || options.riskLevel || ""),
      payloadDigest: String(approval?.payloadDigest || options.payloadDigest || ""),
      operationId: String(options.operationId || approval?.operationId || ""),
      reason: String(options.reason || ""),
    });
  }

  function transitionApproval(approval, status, actorSubjectId, reason = "") {
    if (!approval || !status) return;
    const at = new Date().toISOString();
    approval.status = status;
    approval.updatedAt = at;
    approval.stateHistory.push({
      status,
      at,
      actorSubjectId: String(actorSubjectId || ""),
      reason: String(reason || ""),
    });
  }

  function recoverApprovals(data) {
    const now = Date.now();
    for (const approval of Object.values(data.approvalRequests)) {
      if (approval.status === "reserved") {
        approval.recoveredAt = new Date(now).toISOString();
        const consumption = data.approvalConsumptions[approval.id];
        if (consumption) {
          if (!consumption.outcome || consumption.outcome === "reserved") {
            consumption.outcome = "unknown_recovered";
          }
          consumption.consumedAt = consumption.consumedAt || approval.recoveredAt;
        }
        transitionApproval(approval, "consumed", "system_recovery", "reserved at restart");
        approval.consumedAt = approval.recoveredAt;
        appendApprovalSystemAudit(data, "approval.recovered_reserved", approval, {
          result: "failed_closed",
          errorCode: "approval_consumed",
          operationId: consumption?.operationId || approval.operationId,
        });
        continue;
      }
      if (["requested", "pending_approval", "approved"].includes(approval.status)
          && approvalIsExpired(approval, now)) {
        transitionApproval(approval, "expired", "system_expiry", "approval expired");
        appendApprovalSystemAudit(data, "approval.expired", approval, {
          result: "expired",
          errorCode: "approval_expired",
        });
      }
    }
  }

  await store.mutate(recoverApprovals);

  function approvalExpectedBinding(input) {
    const payloadDigest = approvalPayloadDigest(input.action, input.payload);
    const bindingDigest = approvalBindingDigest({
      environmentId: approvalEnvironmentId,
      policyVersion: currentApprovalPolicyVersion(),
      requesterSubjectId: input.requesterSubjectId,
      action: input.action,
      targetType: input.targetType,
      targetId: input.targetId,
      targetOrgUnitId: input.targetOrgUnitId,
      riskLevel: input.riskLevel,
      reason: input.reason,
      payloadDigest,
    });
    return {
      environmentId: approvalEnvironmentId,
      policyVersion: currentApprovalPolicyVersion(),
      requesterSubjectId: String(input.requesterSubjectId || ""),
      action: String(input.action || ""),
      targetType: String(input.targetType || ""),
      targetId: String(input.targetId || ""),
      targetOrgUnitId: String(input.targetOrgUnitId || ""),
      riskLevel: String(input.riskLevel || ""),
      reason: String(input.reason || ""),
      payload: normalizedApprovalPayload(input.action, input.payload),
      payloadDigest,
      bindingDigest,
    };
  }

  function approvalHttpError(code, message = "Approval validation failed") {
    const statusCode = code === "approval_required"
      ? 400
      : code === "approval_consumed" || code === "approval_payload_mismatch"
        ? 409
        : code === "approval_unavailable"
          ? 503
          : 403;
    return new HttpError(statusCode, code, message);
  }

  function approvalActionDefinition(action) {
    const definition = APPROVAL_ACTION_TARGETS[action];
    if (!definition || !riskForAction(action)) {
      throw new HttpError(400, "invalid_approval_action", "action is not supported");
    }
    return definition;
  }

  function approvalBusinessPayload(action, body) {
    if (action === "user.policy.quota") {
      if (!Number.isSafeInteger(body.expectedVersion) || body.expectedVersion < 0) {
        throw new HttpError(400, "version_required", "expectedVersion must be a non-negative integer");
      }
      if (!policyLimitsAreValid(body.limits)) {
        throw new HttpError(400, "invalid_quota", "limits are invalid");
      }
      return {
        expectedVersion: body.expectedVersion,
        limits: body.limits,
      };
    }
    if (action === "user.policy.models") {
      if (!Number.isSafeInteger(body.expectedVersion) || body.expectedVersion < 0) {
        throw new HttpError(400, "version_required", "expectedVersion must be a non-negative integer");
      }
      try {
        return {
          expectedVersion: body.expectedVersion,
          models: [...modelCatalog.expandSelectors(body.models)],
        };
      } catch (error) {
        if (error?.name === "ModelCatalogError") {
          throw new HttpError(400, error.code || "invalid_models", error.message);
        }
        throw error;
      }
    }
    if (action === "operation.reconcile") {
      const reconciliationAction = String(body.reconciliationAction || "").trim();
      if (!RECONCILIATION_ACTIONS.has(reconciliationAction)) {
        throw new HttpError(
          400,
          "invalid_reconciliation_action",
          "reconciliationAction is not supported",
        );
      }
      return {
        parentOperationId: cleanIdentifier(
          body.parentOperationId,
          "parentOperationId",
          "invalid_reconciliation_action",
        ),
        reconciliationAction,
        evidenceRef: cleanEvidenceRef(
          body.evidenceRef,
          reconciliationAction === "confirm_applied"
            || reconciliationAction === "confirm_not_applied",
        ),
      };
    }
    return {};
  }

  async function resolveApprovalTarget(session, action, targetId, payload) {
    const definition = approvalActionDefinition(action);
    if (action === "operation.reconcile") {
      if (payload.parentOperationId !== targetId) {
        throw new HttpError(
          400,
          "invalid_reconciliation_action",
          "targetId and parentOperationId must identify the same operation",
        );
      }
      const parent = await store.read((data) => {
        const operation = data.adminOperations[targetId];
        return operation ? structuredClone(operation) : null;
      });
      if (!parent) throw new HttpError(404, "operation_not_found", "Operation not found");
      if (parent.action === "operation.reconcile") {
        throw new HttpError(
          409,
          "operation_action_unsupported",
          "A reconciliation operation cannot be reconciled",
        );
      }
      if (!operationRequiresReconciliation(parent)) {
        throw new HttpError(
          409,
          "reconciliation_not_required",
          "This operation does not require reconciliation",
        );
      }
      const targetResult = await operationTarget(session, parent, definition.permission);
      const targetOrgUnitId = activeUserOrgUnit(targetResult.data, targetResult.userId);
      if (!targetOrgUnitId) {
        throw new HttpError(
          409,
          "target_org_required",
          "An approval target must belong to an active organization unit",
        );
      }
      return {
        targetType: parent.targetType,
        targetId: parent.targetId,
        targetOrgUnitId,
        target: targetResult.target,
      };
    }
    const targetResult = await writeTarget(
      session,
      definition.permission,
      definition.targetType,
      targetId,
    );
    const userId = definition.targetType === "user"
      ? targetResult.target.id
      : targetResult.target.userId;
    const targetOrgUnitId = activeUserOrgUnit(targetResult.data, userId);
    if (!targetOrgUnitId) {
      throw new HttpError(
        409,
        "target_org_required",
        "An approval target must belong to an active organization unit",
      );
    }
    return {
      targetType: definition.targetType,
      targetId,
      targetOrgUnitId,
      target: targetResult.target,
    };
  }

  function approvalDecisionList(data, approvalId) {
    return Object.values(data.approvalDecisions)
      .filter((decision) => decision.approvalId === approvalId)
      .sort((left, right) => String(left.createdAt).localeCompare(String(right.createdAt)));
  }

  async function createApproval(req, res) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const action = String(body.action || "").trim();
    approvalActionDefinition(action);
    if (!approvalRequiredForAction(action)) {
      throw new HttpError(400, "approval_not_required", "This action does not require approval");
    }
    const targetId = cleanIdentifier(body.targetId, "targetId", "invalid_request");
    const reason = cleanReason(body.reason);
    const payload = approvalBusinessPayload(action, body);
    const target = await resolveApprovalTarget(current.session, action, targetId, payload);
    const expected = approvalExpectedBinding({
      requesterSubjectId: current.session.subjectId,
      action,
      targetType: target.targetType,
      targetId: target.targetId,
      targetOrgUnitId: target.targetOrgUnitId,
      riskLevel: riskForAction(action),
      reason,
      payload,
    });
    const now = new Date();
    const approval = {
      id: `apr_${crypto.randomUUID()}`,
      status: "requested",
      environmentId: expected.environmentId,
      policyVersion: expected.policyVersion,
      requesterSubjectId: current.session.subjectId,
      requesterEmail: current.session.email,
      action,
      targetType: target.targetType,
      targetId: target.targetId,
      targetOrgUnitId: target.targetOrgUnitId,
      riskLevel: expected.riskLevel,
      reason,
      payloadDigest: expected.payloadDigest,
      bindingDigest: expected.bindingDigest,
      payloadSummary: expected.payload,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + APPROVAL_TTL_MS).toISOString(),
      approvedAt: "",
      approvedBySubjectId: "",
      rejectedAt: "",
      revokedAt: "",
      operationId: "",
      consumedAt: "",
      stateHistory: [{
        status: "requested",
        at: now.toISOString(),
        actorSubjectId: current.session.subjectId,
        reason: "approval requested",
      }],
    };
    await store.mutate((data) => {
      data.approvalRequests[approval.id] = structuredClone(approval);
      appendApprovalSystemAudit(data, "approval.requested", approval, {
        result: "requested",
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
      });
    });
    json(res, 201, { approval: publicApproval(approval) });
  }

  async function getApproval(req, res, approvalId) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    const found = await store.read((data) => {
      const approval = data.approvalRequests[approvalId];
      return approval
        ? {
          approval: structuredClone(approval),
          decisions: structuredClone(approvalDecisionList(data, approvalId)),
        }
        : null;
    });
    if (!found) throw new HttpError(404, "approval_not_found", "Approval not found");
    await requirePermission(
      current.session,
      "approvals.read",
      found.approval.targetOrgUnitId,
    );
    json(res, 200, {
      approval: publicApproval(found.approval, found.decisions),
    });
  }

  async function decideApproval(req, res, approvalId) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const decision = String(body.decision || "").trim();
    if (decision !== "approve" && decision !== "reject") {
      throw new HttpError(400, "invalid_decision", "decision must be approve or reject");
    }
    const reason = cleanReason(body.reason);
    const storedApproval = await store.read((data) => {
      const approval = data.approvalRequests[approvalId];
      return approval ? structuredClone(approval) : null;
    });
    if (!storedApproval) throw new HttpError(404, "approval_not_found", "Approval not found");
    const definition = approvalActionDefinition(storedApproval.action);
    await requirePermission(
      current.session,
      "approvals.decide",
      storedApproval.targetOrgUnitId,
    );
    await requirePermission(
      current.session,
      definition.permission,
      storedApproval.targetOrgUnitId,
    );
    if (storedApproval.requesterSubjectId === current.session.subjectId) {
      throw approvalHttpError(
        "approval_separation_required",
        "The requester cannot decide their own approval",
      );
    }

    const outcome = await store.mutate((data) => {
      const approval = data.approvalRequests[approvalId];
      if (!approval) {
        return { error: approvalHttpError("approval_invalid", "Approval is not available") };
      }
      if (!["requested", "pending_approval"].includes(approval.status)) {
        if (approvalIsExpired(approval)) {
          transitionApproval(approval, "expired", "system_expiry", "approval expired");
          appendApprovalSystemAudit(data, "approval.expired", approval, {
            result: "expired",
            errorCode: "approval_expired",
          });
          return { error: approvalHttpError("approval_expired", "Approval has expired") };
        }
        if (approval.status === "revoked") {
          return { error: approvalHttpError("approval_revoked", "Approval was revoked") };
        }
        if (approval.status === "reserved" || approval.status === "consumed") {
          return { error: approvalHttpError("approval_consumed", "Approval was already consumed") };
        }
        return {
          error: approvalHttpError(
            "approval_unavailable",
            "Approval is not awaiting a decision",
          ),
        };
      }
      if (approvalIsExpired(approval)) {
        transitionApproval(approval, "expired", "system_expiry", "approval expired");
        appendApprovalSystemAudit(data, "approval.expired", approval, {
          result: "expired",
          errorCode: "approval_expired",
        });
        return { error: approvalHttpError("approval_expired", "Approval has expired") };
      }
      if (approval.requesterSubjectId === current.session.subjectId) {
        return {
          error: approvalHttpError(
            "approval_separation_required",
            "The requester cannot decide their own approval",
          ),
        };
      }
      const createdAt = new Date().toISOString();
      const record = {
        id: `apd_${crypto.randomUUID()}`,
        approvalId,
        decision,
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        reason,
        createdAt,
      };
      data.approvalDecisions[record.id] = record;
      if (decision === "approve") {
        transitionApproval(approval, "approved", current.session.subjectId, "approved");
        approval.approvedAt = createdAt;
        approval.approvedBySubjectId = current.session.subjectId;
      } else {
        transitionApproval(approval, "rejected", current.session.subjectId, "rejected");
        approval.rejectedAt = createdAt;
      }
      appendApprovalSystemAudit(
        data,
        decision === "approve" ? "approval.approved" : "approval.rejected",
        approval,
        {
          result: decision === "approve" ? "approved" : "rejected",
          actorSubjectId: current.session.subjectId,
          actorEmail: current.session.email,
          reason,
        },
      );
      return {
        approval: structuredClone(approval),
        decisions: structuredClone(approvalDecisionList(data, approvalId)),
      };
    });
    if (outcome.error) throw outcome.error;
    json(res, 200, {
      approval: publicApproval(outcome.approval, outcome.decisions),
    });
  }

  async function revokeApproval(req, res, approvalId) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const reason = cleanReason(body.reason);
    const storedApproval = await store.read((data) => {
      const approval = data.approvalRequests[approvalId];
      return approval ? structuredClone(approval) : null;
    });
    if (!storedApproval) throw new HttpError(404, "approval_not_found", "Approval not found");
    await requirePermission(
      current.session,
      "approvals.revoke",
      storedApproval.targetOrgUnitId,
    );
    const outcome = await store.mutate((data) => {
      const approval = data.approvalRequests[approvalId];
      if (!approval) {
        return { error: approvalHttpError("approval_invalid", "Approval is not available") };
      }
      if (approvalIsExpired(approval)) {
        if (["requested", "pending_approval", "approved"].includes(approval.status)) {
          transitionApproval(approval, "expired", "system_expiry", "approval expired");
          appendApprovalSystemAudit(data, "approval.expired", approval, {
            result: "expired",
            errorCode: "approval_expired",
          });
        }
        return { error: approvalHttpError("approval_expired", "Approval has expired") };
      }
      if (!["requested", "pending_approval", "approved"].includes(approval.status)) {
        if (approval.status === "reserved" || approval.status === "consumed") {
          return { error: approvalHttpError("approval_consumed", "Approval was already consumed") };
        }
        if (approval.status === "revoked") {
          return { error: approvalHttpError("approval_revoked", "Approval was already revoked") };
        }
        return {
          error: approvalHttpError(
            "approval_unavailable",
            "Approval cannot be revoked in its current state",
          ),
        };
      }
      const revokedAt = new Date().toISOString();
      transitionApproval(approval, "revoked", current.session.subjectId, "revoked");
      approval.revokedAt = revokedAt;
      appendApprovalSystemAudit(data, "approval.revoked", approval, {
        result: "revoked",
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        reason,
      });
      return {
        approval: structuredClone(approval),
        decisions: structuredClone(approvalDecisionList(data, approvalId)),
      };
    });
    if (outcome.error) throw outcome.error;
    json(res, 200, {
      approval: publicApproval(outcome.approval, outcome.decisions),
    });
  }

  function reserveApprovalForOperation(data, approvalId, expected, operation) {
    const approval = data.approvalRequests[approvalId];
    const failure = data.approvalConsumptions[approvalId]
      ? "approval_consumed"
      : approvalConsumptionFailure(approval, expected);
    if (failure) {
      throw approvalHttpError(failure, "Approval cannot be consumed for this operation");
    }
    transitionApproval(approval, "reserved", operation.actorSubjectId, "reserved by operation");
    approval.operationId = operation.id;
    data.approvalConsumptions[approvalId] = {
      approvalId,
      operationId: operation.id,
      reservedAt: approval.updatedAt,
      consumedAt: "",
      outcome: "reserved",
    };
    appendApprovalSystemAudit(data, "approval.reserved", approval, {
      result: "reserved",
      operationId: operation.id,
      actorSubjectId: operation.actorSubjectId,
      actorEmail: operation.actorEmail,
    });
  }

  function consumeApprovalForOperation(data, approvalId, operation, outcome) {
    if (!approvalId) return;
    const approval = data.approvalRequests[approvalId];
    const consumption = data.approvalConsumptions[approvalId];
    if (!approval || !consumption || consumption.operationId !== operation.id) {
      throw new Error("Approval reservation is missing before operation completion");
    }
    if (approval.status !== "reserved") {
      throw new Error("Approval reservation is no longer available");
    }
    transitionApproval(approval, "consumed", "system_operation", "operation completed");
    approval.consumedAt = approval.updatedAt;
    approval.operationId = operation.id;
    consumption.consumedAt = approval.updatedAt;
    consumption.outcome = outcome;
    appendApprovalSystemAudit(data, "approval.consumed", approval, {
      result: outcome,
      operationId: operation.id,
      actorSubjectId: operation.actorSubjectId,
      actorEmail: operation.actorEmail,
    });
  }

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

  function safeStringList(value) {
    return Array.isArray(value) ? value.map(String) : [];
  }

  function safePolicySummary(policy) {
    if (!policy || typeof policy !== "object" || Array.isArray(policy)) return null;
    return {
      version: Number.isSafeInteger(policy.version) ? policy.version : 0,
      models: Array.isArray(policy.models) ? safeStringList(policy.models) : null,
      limits: Array.isArray(policy.limits) ? safePolicyLimits(policy.limits) : null,
      quotaStatus: String(policy.quotaStatus || "unknown"),
      modelStatus: String(policy.modelStatus || "unknown"),
      updatedAt: String(policy.updatedAt || ""),
      confirmedAt: String(policy.confirmedAt || ""),
      operationId: String(policy.operationId || ""),
      including: safeStringList(policy.including),
      missing: safeStringList(policy.missing),
    };
  }

  function safePolicyLimits(limits) {
    return limits.map((limit) => {
      if (!limit || typeof limit !== "object" || Array.isArray(limit)) return {};
      const output = {
        period: String(limit.period || ""),
      };
      for (const key of ["days", "hours", "tokens", "cost"]) {
        if (Number.isFinite(Number(limit[key]))) output[key] = Number(limit[key]);
      }
      if (typeof limit.cacheReads === "boolean") output.cacheReads = limit.cacheReads;
      return output;
    });
  }

  function safePolicyCredentialSummary(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    return {
      total: safeNumber(value.total),
      succeeded: safeNumber(value.succeeded),
      failed: safeNumber(value.failed),
      pending: safeNumber(value.pending),
      unknown: safeNumber(value.unknown),
      failedOnly: safeNumber(value.failedOnly),
      failedItems: Array.isArray(value.failedItems)
        ? value.failedItems.map((item) => ({
          credentialId: String(item?.credentialId || ""),
          deviceId: String(item?.deviceId || ""),
          errorCode: String(item?.errorCode || ""),
        }))
        : [],
    };
  }

  function safeOperationSummary(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    const result = value.responseBody?.result;
    return {
      operationId: String(value.id || ""),
      action: String(value.action || ""),
      targetId: String(value.targetId || ""),
      status: String(value.status || "unknown"),
      state: String(result?.state || value.status || "unknown"),
      createdAt: String(value.createdAt || ""),
      updatedAt: String(value.updatedAt || ""),
      completedAt: String(value.completedAt || ""),
      errorCode: String(value.errorCode || ""),
      requiresReconciliation: Boolean(result?.requiresReconciliation),
      credentials: safePolicyCredentialSummary(result?.credentials),
    };
  }

  function safeOperationDetail(operation, dependencyInvokedAt = "") {
    const result = operation.responseBody?.result;
    const credentials = safePolicyCredentialSummary(result?.credentials);
    const reconciliationState = explicitReconciliationState(operation)
      || (operationRequiresReconciliation(operation) ? "pending" : "not_required");
    return {
      operationId: String(operation.id || ""),
      requestId: String(operation.requestId || ""),
      action: String(operation.action || ""),
      targetType: String(operation.targetType || ""),
      targetId: String(operation.targetId || ""),
      state: operationState(operation),
      errorCode: String(operation.errorCode || ""),
      retryable: operationRetryable(operation),
      requiresReconciliation: reconciliationState === "pending",
      actorSubjectId: String(operation.actorSubjectId || ""),
      role: String(operation.roles?.[0] || ""),
      roles: safeStringList(operation.roles),
      scopeOrgUnitIds: safeStringList(operation.scopeOrgUnitIds),
      createdAt: String(operation.createdAt || ""),
      updatedAt: String(operation.updatedAt || ""),
      dependencyInvokedAt: String(operation.dependencyInvokedAt || dependencyInvokedAt || ""),
      completedAt: String(operation.completedAt || ""),
      policyVersion: Number.isSafeInteger(result?.policy?.version)
        ? result.policy.version
        : safeNumber(operation.beforeSummary?.version),
      credentialSummary: credentials,
      failedItems: credentials?.failedItems || [],
      reconciliationState,
      reconciliationAction: String(operation.reconciliationAction || ""),
      evidenceRef: String(operation.reconciliationEvidenceRef || ""),
      reconciledAt: String(operation.reconciledAt || ""),
      reconciledByOperationId: String(operation.reconciledByOperationId || ""),
      parentOperationId: String(operation.parentOperationId || ""),
      beforeSummary: safeAuditValue(operation.beforeSummary),
      afterSummary: safeAuditValue(result || {}),
    };
  }

  function auditQuery(searchParams) {
    const one = (name, maxLength = 256) => {
      const value = String(searchParams.get(name) || "").trim();
      if ([...value].length > maxLength || /[\u0000-\u001f\u007f]/.test(value)) {
        throw new HttpError(400, "invalid_audit_filter", `${name} is invalid`);
      }
      return value;
    };
    const timestamp = (name) => {
      const value = one(name, 80);
      if (!value) return "";
      const parsed = Date.parse(value);
      if (!Number.isFinite(parsed)) {
        throw new HttpError(400, "invalid_time_range", `${name} must be a valid timestamp`);
      }
      return new Date(parsed).toISOString();
    };
    const rawLimit = one("limit", 20);
    if (rawLimit && !/^[1-9]\d*$/.test(rawLimit)) {
      throw new HttpError(400, "invalid_limit", "limit must be a positive integer");
    }
    const limit = rawLimit ? Number(rawLimit) : DEFAULT_AUDIT_LIMIT;
    if (!Number.isSafeInteger(limit) || limit > MAX_AUDIT_LIMIT) {
      throw new HttpError(400, "invalid_limit", `limit must not exceed ${MAX_AUDIT_LIMIT}`);
    }
    const from = timestamp("from");
    const to = timestamp("to");
    if (from && to && Date.parse(from) > Date.parse(to)) {
      throw new HttpError(400, "invalid_time_range", "from must not be after to");
    }
    const normalized = {
      operationId: one("operationId", 128),
      actorSubjectId: one("actorSubjectId", 128),
      action: one("action", 128),
      targetType: one("targetType", 32),
      targetId: one("targetId", 128),
      result: one("result", 64),
      from,
      to,
      limit,
    };
    if (normalized.targetType && !["user", "device", "credential"].includes(normalized.targetType)) {
      throw new HttpError(400, "invalid_audit_filter", "targetType is not supported");
    }
    return {
      ...normalized,
      cursor: one("cursor", MAX_AUDIT_CURSOR),
      queryHash: sha256(JSON.stringify(canonicalValue(normalized))),
    };
  }

  function auditCursorSignature(payload) {
    return crypto.createHmac("sha256", config.sessionSecret)
      .update(payload)
      .digest("base64url");
  }

  function encodeAuditCursor(query, session, record) {
    const payload = Buffer.from(JSON.stringify({
      v: 1,
      sub: session.subjectId,
      qh: query.queryHash,
      t: String(record.timestamp || ""),
      id: String(record.id || ""),
    })).toString("base64url");
    return `${payload}.${auditCursorSignature(payload)}`;
  }

  function decodeAuditCursor(cursor, query, session) {
    if (!cursor) return null;
    const parts = cursor.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      throw new HttpError(400, "invalid_cursor", "cursor is invalid");
    }
    const expected = auditCursorSignature(parts[0]);
    if (!safeEqual(parts[1], expected)) {
      throw new HttpError(400, "invalid_cursor", "cursor is invalid");
    }
    let parsed;
    try {
      parsed = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    } catch {
      throw new HttpError(400, "invalid_cursor", "cursor is invalid");
    }
    if (parsed?.v !== 1
        || parsed.sub !== session.subjectId
        || parsed.qh !== query.queryHash
        || typeof parsed.t !== "string"
        || typeof parsed.id !== "string"
        || !parsed.id) {
      throw new HttpError(400, "invalid_cursor", "cursor does not match this query");
    }
    const time = Date.parse(parsed.t);
    if (!Number.isFinite(time)) throw new HttpError(400, "invalid_cursor", "cursor is invalid");
    return { time, timestamp: new Date(time).toISOString(), id: parsed.id };
  }

  async function auditTargetMaps() {
    const [{ users }, { devices }, { credentials }] = await Promise.all([
      authService.users(),
      authService.devices(),
      authService.credentials(),
    ]);
    return {
      users: new Map(users.map((user) => [user.id, user])),
      devices: new Map(devices.map((device) => [device.id, device])),
      credentials: new Map(credentials.map((credential) => [credential.id, credential])),
    };
  }

  function targetUserId(maps, targetType, targetId) {
    if (targetType === "user") return maps.users.has(targetId) ? targetId : "";
    if (targetType === "device") return String(maps.devices.get(targetId)?.userId || "");
    if (targetType === "credential") {
      return String(maps.credentials.get(targetId)?.userId || "");
    }
    return "";
  }

  function safeAuditRecord(record) {
    return {
      id: String(record.id || ""),
      operationId: String(record.operationId || ""),
      requestId: String(record.requestId || ""),
      timestamp: String(record.timestamp || ""),
      phase: String(record.phase || ""),
      actorSubjectId: String(record.actorSubjectId || record.actorSubject || ""),
      actorEmail: String(record.actorEmail || ""),
      role: String(record.roles?.[0] || ""),
      roles: safeStringList(record.roles),
      scopeOrgUnitIds: safeStringList(record.scopeOrgUnitIds),
      action: String(record.action || ""),
      targetType: String(record.targetType || ""),
      targetId: String(record.targetId || ""),
      beforeSummary: safeAuditValue(record.beforeSummary),
      afterSummary: safeAuditValue(record.afterSummary),
      result: String(record.result || ""),
      errorCode: String(record.errorCode || ""),
      sourceIp: String(record.sourceIp || ""),
      userAgentHash: String(record.userAgentHash || ""),
      reason: String(record.reason || ""),
      approvalId: String(record.approvalId || ""),
      parentOperationId: String(record.parentOperationId || ""),
      reconciliationAction: String(record.reconciliationAction || ""),
      evidenceRef: String(record.evidenceRef || ""),
    };
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
      policy: safePolicySummary(user.policy),
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
      policyVersion: Number.isSafeInteger(credential.policyVersion) ? credential.policyVersion : 0,
      policySyncState: String(credential.policySyncState || "pending"),
      lastPolicyResult: String(credential.lastPolicyResult || credential.policySyncState || "pending"),
      lastPolicyErrorCode: String(credential.lastPolicyErrorCode || ""),
      lastPolicyAttemptedAt: String(credential.lastPolicyAttemptedAt || ""),
      lastPolicySyncedAt: String(credential.lastPolicySyncedAt || ""),
      lastPolicyOperationId: String(credential.lastPolicyOperationId || ""),
      lastPolicyGatewayRequestId: String(credential.lastPolicyGatewayRequestId || ""),
      lastPolicyRevision: String(credential.lastPolicyRevision || ""),
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
    if (action === "user.policy.quota" || action === "user.policy.models") {
      return {
        operationId: String(value.operationId || ""),
        state: String(value.state || ""),
        policy: safePolicySummary(value.policy),
        credentials: safePolicyCredentialSummary(value.credentials),
        requiresReconciliation: Boolean(value.requiresReconciliation),
        superseded: Boolean(value.superseded),
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
      actorSubjectId: operation.actorSubjectId,
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
      parentOperationId: String(options.parentOperationId || operation.parentOperationId || ""),
      reconciliationAction: String(
        options.reconciliationAction || operation.reconciliationAction || "",
      ),
      evidenceRef: String(
        options.evidenceRef || operation.reconciliationEvidenceRef || "",
      ),
    };
  }

  function safeReconcileResult(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};
    return {
      operationId: String(value.operationId || ""),
      state: String(value.state || ""),
      policy: safePolicySummary(value.policy),
      credentials: safePolicyCredentialSummary(value.credentials),
      requiresReconciliation: Boolean(value.requiresReconciliation),
      superseded: Boolean(value.superseded),
      parentOperationId: String(value.parentOperationId || ""),
      reconciliationAction: String(value.reconciliationAction || ""),
      evidenceRef: String(value.evidenceRef || ""),
      manualEvidenceOnly: Boolean(value.manualEvidenceOnly),
    };
  }

  function replayReconciliation(res, existing) {
    if (existing.status === "succeeded" && existing.responseBody
        && Number(existing.responseStatus) >= 200 && Number(existing.responseStatus) < 300) {
      json(res, Number(existing.responseStatus), existing.responseBody);
      return;
    }
    if (existing.status === "failed") {
      const failure = new HttpError(
        Number(existing.responseStatus) || 500,
        existing.errorCode || "operation_failed",
        "The original reconciliation failed",
      );
      failure.operationId = existing.id;
      throw failure;
    }
    const inProgress = new HttpError(
      409,
      "operation_in_progress",
      "A reconciliation with this Idempotency-Key is still in progress",
    );
    inProgress.operationId = existing.id;
    throw inProgress;
  }

  async function operationTarget(session, operation, permission = "") {
    const requiredPermission = permission || OPERATION_PERMISSIONS[operation.action];
    if (!requiredPermission) {
      throw new HttpError(409, "operation_action_unsupported", "The operation action is not supported");
    }
    const result = await requirePermission(session, requiredPermission);
    let target;
    if (operation.targetType === "user") {
      const { users } = await authService.users();
      target = users.find((candidate) => candidate.id === operation.targetId);
    } else if (operation.targetType === "device") {
      const [{ users }, { devices }] = await Promise.all([
        authService.users(),
        authService.devices(),
      ]);
      target = devices.find((candidate) => candidate.id === operation.targetId);
      if (target && !users.some((candidate) => candidate.id === target.userId)) target = null;
    } else if (operation.targetType === "credential") {
      const [{ users }, { credentials }] = await Promise.all([
        authService.users(),
        authService.credentials(),
      ]);
      target = credentials.find((candidate) => candidate.id === operation.targetId);
      if (target && !users.some((candidate) => candidate.id === target.userId)) target = null;
    } else {
      throw new HttpError(409, "operation_action_unsupported", "The operation target is not supported");
    }
    if (!target) {
      throw new HttpError(404, "operation_target_unavailable", "The operation target can no longer be resolved");
    }
    const userId = operation.targetType === "user" ? target.id : target.userId;
    if (!userInScope(result.data, result.access, userId)) {
      throw new HttpError(403, "forbidden_scope", "This operation target is outside your organization scope");
    }
    return { ...result, target, userId };
  }

  function trustedPolicySnapshot(operation) {
    if (!POLICY_ACTIONS.has(operation.action) || operation.targetType !== "user") return null;
    const snapshot = operation.beforeSummary;
    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) return null;
    if (snapshot.id !== operation.targetId) return null;
    if (!Number.isSafeInteger(snapshot.version) || snapshot.version < 0) return null;
    if (!Array.isArray(snapshot.models) || !policyLimitsAreValid(snapshot.limits)) return null;
    return {
      version: snapshot.version,
      models: safeStringList(snapshot.models),
      limits: safePolicyLimits(snapshot.limits),
    };
  }

  function reconciliationOutcome(action, responseBody, operationError) {
    if (action === "confirm_applied") return "confirmed_applied";
    if (action === "confirm_not_applied") return "confirmed_not_applied";
    if (operationError) return "pending";
    const state = String(responseBody?.result?.state || "");
    if (state !== "succeeded") return "pending";
    return action === "rollback_previous" ? "compensated" : "not_required";
  }

  async function auditLogPage(session, searchParams) {
    const query = auditQuery(searchParams);
    const result = await requirePermission(session, "audit.read");
    const maps = await auditTargetMaps();
    const cursor = decodeAuditCursor(query.cursor, query, session);
    const visible = await store.read((data) => {
      const records = [];
      for (const record of data.adminAuditLogs) {
        if (query.operationId && record.operationId !== query.operationId) continue;
        if (query.actorSubjectId
            && (record.actorSubjectId || record.actorSubject) !== query.actorSubjectId) continue;
        if (query.action && record.action !== query.action) continue;
        if (query.targetType && record.targetType !== query.targetType) continue;
        if (query.targetId && record.targetId !== query.targetId) continue;
        if (query.result && record.result !== query.result) continue;
        if (query.from && String(record.timestamp || "") < query.from) continue;
        if (query.to && String(record.timestamp || "") > query.to) continue;
        const userId = targetUserId(maps, record.targetType, record.targetId);
        if (!userId) continue;
        if (!userInScope(result.data, result.access, userId)) continue;
        if (cursor && (
          String(record.timestamp || "") > cursor.timestamp
          || (String(record.timestamp || "") === cursor.timestamp && String(record.id || "") >= cursor.id)
        )) {
          continue;
        }
        records.push(record);
      }
      return records.sort(compareAuditRecords);
    });
    const page = visible.slice(0, query.limit);
    const nextCursor = visible.length > query.limit && page.length > 0
      ? encodeAuditCursor(query, session, page[page.length - 1])
      : "";
    return {
      auditLogs: page.map(safeAuditRecord),
      nextCursor,
    };
  }

  async function performReconciliation(req, res, requestId, operationId) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const reason = cleanReason(body.reason);
    const approvalId = cleanOptionalApprovalId(body.approvalId);
    if (!approvalId) throw new HttpError(400, "approval_required", "approvalId is required");
    const idempotencyKey = validateRequiredIdempotencyKey(req);
    const reconciliationAction = String(body.action || "").trim();
    if (!RECONCILIATION_ACTIONS.has(reconciliationAction)) {
      throw new HttpError(400, "invalid_reconciliation_action", "action is not supported");
    }
    const evidenceRef = cleanEvidenceRef(
      body.evidenceRef,
      reconciliationAction === "confirm_applied" || reconciliationAction === "confirm_not_applied",
    );

    const parent = await store.read((data) => {
      const operation = data.adminOperations[operationId];
      return operation ? structuredClone(operation) : null;
    });
    if (!parent) throw new HttpError(404, "operation_not_found", "Operation not found");
    if (parent.action === "operation.reconcile") {
      throw new HttpError(409, "operation_action_unsupported", "A reconciliation operation cannot be reconciled");
    }

    await requirePermission(current.session, "operations.reconcile");
    const targetResult = await operationTarget(current.session, parent);

    const requestFingerprint = writeRequestFingerprint(
      "operation.reconcile",
      parent.targetType,
      parent.targetId,
      reason,
      approvalId,
      { parentOperationId: parent.id, reconciliationAction, evidenceRef },
    );
    const idempotencyKeyHash = sha256(`${current.session.subjectId}\u0000${idempotencyKey}`);
    const existingOperation = await store.read((data) => {
      const entry = data.adminIdempotency[idempotencyKeyHash];
      if (!entry) return null;
      const existing = data.adminOperations[entry.operationId];
      if (!existing) {
        throw new HttpError(
          503,
          "storage_unavailable",
          "The idempotency record points to a missing operation",
        );
      }
      if (entry.requestFingerprint !== requestFingerprint) {
        const conflict = new HttpError(
          409,
          "idempotency_conflict",
          "Idempotency-Key was already used for a different request",
        );
        conflict.operationId = existing.id;
        throw conflict;
      }
      return structuredClone(existing);
    });
    if (existingOperation) {
      replayReconciliation(res, existingOperation);
      return;
    }
    if (!operationRequiresReconciliation(parent)) {
      throw new HttpError(409, "reconciliation_not_required", "This operation does not require reconciliation");
    }

    let desiredModels;
    let desiredLimits;
    if (reconciliationAction === "retry_desired") {
      if (!POLICY_ACTIONS.has(parent.action)) {
        throw new HttpError(409, "reconciliation_action_unsupported", "retry_desired is only supported for policy operations");
      }
      if (targetResult.target.status !== "active") {
        throw new HttpError(409, "target_not_active", "A disabled user cannot receive a policy retry");
      }
      if (!Array.isArray(targetResult.target.policy?.models)
          || !policyLimitsAreValid(targetResult.target.policy?.limits)) {
        throw new HttpError(409, "desired_policy_incomplete", "The current desired policy is incomplete");
      }
      desiredModels = safeStringList(targetResult.target.policy.models);
      desiredLimits = safePolicyLimits(targetResult.target.policy.limits);
    } else if (reconciliationAction === "rollback_previous") {
      if (!POLICY_ACTIONS.has(parent.action)) {
        throw new HttpError(409, "reconciliation_action_unsupported", "rollback_previous is only supported for policy operations");
      }
      if (targetResult.target.status !== "active") {
        throw new HttpError(409, "target_not_active", "A disabled user cannot have a policy restored");
      }
      const snapshot = trustedPolicySnapshot(parent);
      if (!snapshot) {
        throw new HttpError(409, "trusted_snapshot_unavailable", "A complete trusted prior policy snapshot is not available");
      }
      desiredModels = snapshot.models;
      desiredLimits = snapshot.limits;
    }

    const now = new Date().toISOString();
    const targetOrgUnitId = activeUserOrgUnit(targetResult.data, targetResult.userId);
    if (!targetOrgUnitId) {
      throw new HttpError(
        409,
        "target_org_required",
        "A reconciliation target must belong to an active organization unit",
      );
    }
    const childOperation = {
      id: `op_${crypto.randomUUID()}`,
      requestId,
      idempotencyKeyHash,
      requestFingerprint,
      actorSubjectId: current.session.subjectId,
      actorEmail: current.session.email,
      roles: [...targetResult.access.roles],
      scopeOrgUnitIds: [...targetResult.access.scopeOrgUnitIds],
      action: "operation.reconcile",
      targetType: parent.targetType,
      targetId: parent.targetId,
      targetOrgUnitId,
      reason,
      approvalId,
      parentOperationId: parent.id,
      reconciliationAction,
      reconciliationEvidenceRef: evidenceRef,
      beforeSummary: writeTargetSnapshot(parent.targetType, targetResult.target),
      status: "received",
      createdAt: now,
      updatedAt: now,
      dependencyInvokedAt: "",
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
        const existingEntry = data.adminIdempotency[idempotencyKeyHash];
        if (existingEntry) {
          const existing = data.adminOperations[existingEntry.operationId];
          if (!existing) {
            throw new HttpError(503, "storage_unavailable", "The idempotency record points to a missing operation");
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
        const currentParent = data.adminOperations[parent.id];
        if (!currentParent) {
          throw new HttpError(404, "operation_not_found", "Operation not found");
        }
        const finalState = explicitReconciliationState(currentParent);
        if (["confirmed_applied", "confirmed_not_applied", "compensated", "not_required"].includes(finalState)) {
          throw new HttpError(409, "operation_already_reconciled", "This operation was already reconciled");
        }
        const inProgress = Object.values(data.adminOperations).some((candidate) => (
          candidate.parentOperationId === parent.id
          && candidate.status !== "failed"
          && candidate.status !== "succeeded"
        ));
        if (inProgress) {
          throw new HttpError(409, "reconciliation_in_progress", "Another reconciliation is still in progress");
        }
        const expected = approvalExpectedBinding({
          requesterSubjectId: current.session.subjectId,
          action: "operation.reconcile",
          targetType: parent.targetType,
          targetId: parent.targetId,
          targetOrgUnitId,
          riskLevel: riskForAction("operation.reconcile"),
          reason,
          payload: {
            parentOperationId: parent.id,
            reconciliationAction,
            evidenceRef,
          },
        });
        reserveApprovalForOperation(data, approvalId, expected, childOperation);
        data.adminOperations[childOperation.id] = structuredClone(childOperation);
        data.adminIdempotency[idempotencyKeyHash] = {
          operationId: childOperation.id,
          requestFingerprint,
          createdAt: now,
        };
        const intent = auditRecord(childOperation, "intent", "pending");
        data.adminAuditLogs.push(intent);
        const stored = data.adminOperations[childOperation.id];
        stored.status = "dependency_invoked";
        stored.updatedAt = intent.timestamp;
        stored.dependencyInvokedAt = intent.timestamp;
        stored.intentAuditId = intent.id;
        return { kind: "created", operation: structuredClone(stored) };
      });
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw new HttpError(503, "audit_unavailable", "Management audit is unavailable");
    }

    if (reservation.kind === "existing") {
      replayReconciliation(res, reservation.operation);
      return;
    }

    let responseBody;
    let responseStatus = 200;
    let errorCode = "";
    let operationError = null;
    try {
      if (reconciliationAction === "confirm_applied" || reconciliationAction === "confirm_not_applied") {
        responseBody = {
          ok: true,
          requestId,
          operationId: childOperation.id,
          action: "operation.reconcile",
          targetId: parent.targetId,
          result: {
            operationId: childOperation.id,
            state: "succeeded",
            policy: safePolicySummary(targetResult.target.policy),
            credentials: null,
            requiresReconciliation: false,
            superseded: false,
            parentOperationId: parent.id,
            reconciliationAction,
            evidenceRef,
            manualEvidenceOnly: true,
          },
        };
      } else {
        const dependencyResponse = await authService.reconcilePolicy(targetResult.userId, {
          expectedVersion: Number(targetResult.target.policy?.version),
          models: desiredModels,
          limits: desiredLimits,
          operationId: childOperation.id,
        });
        responseBody = {
          ok: true,
          requestId,
          operationId: childOperation.id,
          action: "operation.reconcile",
          targetId: parent.targetId,
          result: safeReconcileResult(dependencyResponse.data),
        };
      }
    } catch (error) {
      operationError = error instanceof Error ? error : new Error("The reconciliation dependency call failed");
      responseStatus = Number.isInteger(operationError.statusCode) ? operationError.statusCode : 500;
      errorCode = typeof operationError.code === "string" && operationError.code
        ? operationError.code
        : (responseStatus >= 500 ? "internal_error" : "operation_failed");
    }

    try {
      await store.mutate((data) => {
        const stored = data.adminOperations[childOperation.id];
        if (!stored) throw new Error("reconciliation operation disappeared before its result");
        const completedAt = new Date().toISOString();
        stored.status = operationError ? "failed" : "succeeded";
        stored.updatedAt = completedAt;
        stored.completedAt = completedAt;
        stored.responseStatus = responseStatus;
        stored.responseBody = responseBody || null;
        stored.errorCode = errorCode;
        const resultAudit = auditRecord(childOperation, "result", stored.status, {
          afterSummary: responseBody?.result || {},
          errorCode,
        });
        consumeApprovalForOperation(
          data,
          childOperation.approvalId,
          childOperation,
          operationError ? "failed" : "succeeded",
        );
        data.adminAuditLogs.push(resultAudit);
        stored.resultAuditId = resultAudit.id;

        const parentStored = data.adminOperations[parent.id];
        if (!parentStored) throw new Error("parent operation disappeared during reconciliation");
        parentStored.reconciliationState = reconciliationOutcome(
          reconciliationAction,
          responseBody,
          operationError,
        );
        parentStored.reconciliationAction = reconciliationAction;
        parentStored.reconciliationEvidenceRef = evidenceRef;
        parentStored.reconciledAt = completedAt;
        parentStored.reconciledByOperationId = childOperation.id;
        parentStored.updatedAt = completedAt;
      });
    } catch {
      const auditFailure = new HttpError(503, "audit_unavailable", "The reconciliation result could not be audited");
      auditFailure.operationId = childOperation.id;
      throw auditFailure;
    }

    if (operationError) {
      operationError.operationId = childOperation.id;
      throw operationError;
    }
    json(res, 200, responseBody);
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
    const targetUserId = options.targetType === "user"
      ? targetResult.target.id
      : targetResult.target.userId;
    const targetOrgUnitId = activeUserOrgUnit(targetResult.data, targetUserId);
    const prepared = options.prepare
      ? options.prepare(body, targetResult.target)
      : {};
    const requestFingerprint = writeRequestFingerprint(
      options.action,
      options.targetType,
      targetId,
      reason,
      approvalId,
      prepared,
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
      targetOrgUnitId,
      reason,
      approvalId,
      beforeSummary: writeTargetSnapshot(options.targetType, targetResult.target),
      status: "received",
      createdAt: now,
      updatedAt: now,
      dependencyInvokedAt: "",
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

        if (approvalRequiredForAction(options.action)) {
          if (!approvalId) {
            throw approvalHttpError(
              "approval_required",
              "approvalId is required for this action",
            );
          }
          if (!targetOrgUnitId) {
            throw new HttpError(
              409,
              "target_org_required",
              "An approval target must belong to an active organization unit",
            );
          }
          const expected = approvalExpectedBinding({
            requesterSubjectId: current.session.subjectId,
            action: options.action,
            targetType: options.targetType,
            targetId,
            targetOrgUnitId,
            riskLevel: riskForAction(options.action),
            reason,
            payload: prepared,
          });
          reserveApprovalForOperation(data, approvalId, expected, operation);
        } else if (approvalId) {
          throw approvalHttpError(
            "approval_invalid",
            "This action must not consume an approval",
          );
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
        stored.dependencyInvokedAt = intent.timestamp;
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
      const dependencyResponse = await options.call(targetId, operation.id, prepared);
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
        consumeApprovalForOperation(
          data,
          operation.approvalId,
          operation,
          operationError ? "failed" : "succeeded",
        );
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
    const visibleUserIds = new Set((users.value.users || []).map((user) => user.id));
    const operationsByUser = await store.read((data) => {
      const latest = {};
      for (const operation of Object.values(data.adminOperations)) {
        if (!visibleUserIds.has(operation.targetId)) continue;
        if (!String(operation.action || "").startsWith("user.policy.")) continue;
        const current = latest[operation.targetId];
        if (!current || String(operation.createdAt) > String(current.createdAt)) {
          latest[operation.targetId] = safeOperationSummary(operation);
        }
      }
      return latest;
    });

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
      operationsByUser,
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
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
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

    if (req.method === "GET" && url.pathname === "/admin/app.js") {
      res.writeHead(200, {
        "content-type": "text/javascript; charset=utf-8",
        "content-length": Buffer.byteLength(ADMIN_APP_JS),
      });
      res.end(ADMIN_APP_JS);
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
          permissions: payload.value.permissions,
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

    if (req.method === "POST" && url.pathname === "/api/v1/admin/approvals") {
      await createApproval(req, res);
      return;
    }

    const approvalDecisionMatch =
      /^\/api\/v1\/admin\/approvals\/([A-Za-z0-9_-]+)\/decisions$/.exec(url.pathname);
    if (req.method === "POST" && approvalDecisionMatch) {
      await decideApproval(req, res, approvalDecisionMatch[1]);
      return;
    }

    const approvalRevokeMatch =
      /^\/api\/v1\/admin\/approvals\/([A-Za-z0-9_-]+)\/revoke$/.exec(url.pathname);
    if (req.method === "POST" && approvalRevokeMatch) {
      await revokeApproval(req, res, approvalRevokeMatch[1]);
      return;
    }

    const approvalMatch = /^\/api\/v1\/admin\/approvals\/([A-Za-z0-9_-]+)$/.exec(
      url.pathname,
    );
    if (req.method === "GET" && approvalMatch) {
      await getApproval(req, res, approvalMatch[1]);
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

    const policyWriteMatch = /^\/api\/v1\/admin\/users\/([A-Za-z0-9_-]+)\/policy\/(quota|models)$/.exec(
      url.pathname,
    );
    if (policyWriteMatch
        && ((policyWriteMatch[2] === "quota" && req.method === "PUT")
          || (policyWriteMatch[2] === "models" && req.method === "PATCH"))) {
      const policyPart = policyWriteMatch[2];
      await performWrite(req, res, requestId, {
        action: `user.policy.${policyPart}`,
        permission: policyPart === "quota" ? "quota.write" : "models.write",
        targetType: "user",
        targetId: policyWriteMatch[1],
        prepare: (body) => {
          if (!Number.isSafeInteger(body.expectedVersion) || body.expectedVersion < 0) {
            throw new HttpError(
              400,
              "version_required",
              "expectedVersion must be the user's current policy version",
            );
          }
          if (policyPart === "quota") {
            if (!policyLimitsAreValid(body.limits)) {
              throw new HttpError(400, "invalid_quota", "limits are invalid");
            }
            return {
              expectedVersion: body.expectedVersion,
              limits: body.limits,
            };
          }
          try {
            return {
              expectedVersion: body.expectedVersion,
              models: [...modelCatalog.expandSelectors(body.models)],
            };
          } catch (error) {
            if (error?.name === "ModelCatalogError") {
              throw new HttpError(400, error.code || "invalid_models", error.message);
            }
            throw error;
          }
        },
        call: (id, operationId, prepared) => (
          policyPart === "quota"
            ? authService.updateQuota(id, { ...prepared, operationId })
            : authService.updateModels(id, { ...prepared, operationId })
        ),
      });
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

    const reconcileMatch = /^\/api\/v1\/admin\/operations\/([A-Za-z0-9_-]+)\/reconcile$/.exec(
      url.pathname,
    );
    if (req.method === "POST" && reconcileMatch) {
      await performReconciliation(req, res, requestId, reconcileMatch[1]);
      return;
    }

    const operationMatch = /^\/api\/v1\/admin\/operations\/([A-Za-z0-9_-]+)$/.exec(
      url.pathname,
    );
    if (req.method === "GET" && operationMatch) {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const operation = await store.read((data) => {
        const stored = data.adminOperations[operationMatch[1]];
        return stored ? structuredClone(stored) : null;
      });
      if (!operation) throw new HttpError(404, "operation_not_found", "Operation not found");
      await operationTarget(current.session, operation);
      json(res, 200, { operation: safeOperationDetail(operation) });
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/audit-logs") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      json(res, 200, await auditLogPage(current.session, url.searchParams));
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
