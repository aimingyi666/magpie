import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import { AuthServiceClient } from "./auth-client.js";
import {
  normalizeAdminIdentity,
  OidcClient,
  validateStepUpAuthentication,
} from "./oidc.js";
import {
  adminSubjectId,
  authorize,
  effectiveAccess,
  ROLES,
  visibleOrgUnits,
} from "./rbac.js";
import {
  csrfCookie,
  cookieHeader,
  newSession,
  requestAllowed,
  sessionCookie,
  sessionState,
  userAgentHash,
  validCsrf,
} from "./session.js";
import { clientIp } from "./ip.js";
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
  APPROVAL_STATUSES,
  approvalActiveStepIds,
  approvalBindingDigest,
  approvalConsumptionFailure,
  approvalIsExpired,
  approvalPayloadDigest,
  approvalRequiredForAction,
  approvalWorkflowFailure,
  ensureApprovalWorkflow,
  normalizedApprovalPayload,
  publicApproval,
  riskForAction,
} from "./approval.js";
import {
  ApprovalCallbackError,
  parseApprovalCallback,
} from "./external-approval.js";
import { JsonStore } from "./store.js";
import { readUsageFile } from "./usage-reader.js";
import {
  NotificationDispatcher,
  NotificationOutbox,
  NOTIFICATION_STATUSES,
  publicNotificationDelivery,
  stableErrorCode,
} from "./notification-outbox.js";
import {
  NotificationChannelTransport,
  channelProviderFromData,
  createNotificationChannel,
  publicNotificationChannel,
  updateNotificationChannel,
} from "./notification-channels.js";
import { SIEM_CRITICAL_VISIBILITY_TARGET_MS } from "./notification-siem.js";
import {
  BREAK_GLASS_GRANT_TTL_MS,
  BREAK_GLASS_POLICY_VERSION,
  BREAK_GLASS_REVIEW_CONCLUSIONS,
  BREAK_GLASS_STATUSES,
  BreakGlassReviewScheduler,
  breakGlassConsumptionFailure,
  breakGlassExpectedBinding,
  breakGlassReviewDueAt,
  projectedBreakGlassStatus,
  publicBreakGlassGrant,
} from "./break-glass.js";

const MAX_BODY = 16 * 1024;
const DEFAULT_USAGE_WINDOW_DAYS = 7;
const MAX_TIMESERIES_POINTS = 10000;
const DEFAULT_AUDIT_LIMIT = 50;
const MAX_AUDIT_LIMIT = 200;
const MAX_AUDIT_CURSOR = 4096;
const DEFAULT_OPERATION_LIMIT = 50;
const MAX_OPERATION_LIMIT = 200;
const MAX_OPERATION_CURSOR = 4096;
const MAX_EXPORT_TOKEN_BYTES = 512;
const APPROVAL_TTL_MS = 24 * 60 * 60 * 1000;
const ADMIN_APP_JS = await fs.readFile(new URL("./admin-app.js", import.meta.url), "utf8");

const OPERATION_PERMISSIONS = Object.freeze({
  "user.disable": "users.disable",
  "user.enable": "users.disable",
  "device.revoke": "devices.revoke",
  "credential.rotate": "credentials.rotate",
  "user.policy.quota": "quota.write",
  "user.policy.models": "models.write",
  "usage.export.create": "usage.export",
  "audit.export.create": "audit.export",
  "operation.reconcile": "operations.reconcile",
});

const APPROVAL_ACTION_TARGETS = Object.freeze({
  "user.disable": { targetType: "user", permission: "users.disable" },
  "user.enable": { targetType: "user", permission: "users.disable" },
  "device.revoke": { targetType: "device", permission: "devices.revoke" },
  "credential.rotate": { targetType: "credential", permission: "credentials.rotate" },
  "user.policy.quota": { targetType: "user", permission: "quota.write" },
  "user.policy.models": { targetType: "user", permission: "models.write" },
  "usage.export.create": { targetType: "export", permission: "usage.export" },
  "audit.export.create": { targetType: "export", permission: "audit.export" },
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
  "approval_withdrawn",
  "approval_consumed",
  "approval_incomplete",
  "approval_target_mismatch",
  "approval_payload_mismatch",
  "approval_separation_required",
  "approval_step_ineligible",
  "approval_step_unavailable",
  "approval_unavailable",
  "approval_and_break_glass_exclusive",
  "break_glass_required",
  "break_glass_invalid",
  "break_glass_expired",
  "break_glass_consumed",
  "break_glass_target_mismatch",
  "break_glass_payload_mismatch",
  "break_glass_separation_required",
  "break_glass_review_exists",
  "csrf_invalid",
  "forbidden_role",
  "forbidden_scope",
  "idempotency_conflict",
  "invalid_approval_id",
  "invalid_approval_action",
  "invalid_break_glass_id",
  "invalid_json",
  "invalid_reason",
  "invalid_request",
  "target_org_required",
  "target_not_found",
  "step_up_required",
  "step_up_expired",
  "step_up_binding_mismatch",
  "step_up_unavailable",
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

function accessDigest(access) {
  return sha256(JSON.stringify({
    roles: [...new Set((access.roles || []).map(String))].sort(),
    permissions: [...new Set((access.permissions || []).map(String))].sort(),
    scopeOrgUnitIds: [...new Set((access.scopeOrgUnitIds || []).map(String))].sort(),
  }));
}

function stepUpReturnPath(value) {
  const candidate = String(value || "/admin/").trim();
  if (!candidate.startsWith("/admin/")
      || candidate.startsWith("//")
      || candidate.includes("\\")
      || candidate.includes("\r")
      || candidate.includes("\n")) {
    throw new HttpError(400, "invalid_return_path", "Step-up return path is not allowed");
  }
  const parsed = new URL(candidate, "http://localhost");
  if (parsed.origin !== "http://localhost"
      || !parsed.pathname.startsWith("/admin/")
      || parsed.pathname.startsWith("/admin/step-up")
      || parsed.pathname.startsWith("/admin/oauth/")) {
    throw new HttpError(400, "invalid_return_path", "Step-up return path is not allowed");
  }
  return `${parsed.pathname}${parsed.search}`;
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

async function readRawBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new HttpError(413, "request_too_large", "Request body is too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readBody(req) {
  return (await readRawBody(req)).toString("utf8");
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

function cleanOptionalBreakGlassId(value) {
  const breakGlassId = String(value ?? "").trim();
  if (!breakGlassId) return "";
  if (!breakGlassId.startsWith("bgr_")
      || [...breakGlassId].length > 128
      || /[\u0000-\u001f\u007f]/.test(breakGlassId)) {
    throw new HttpError(400, "invalid_break_glass_id", "breakGlassId is invalid");
  }
  return breakGlassId;
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

function writeRequestFingerprint(
  action,
  targetType,
  targetId,
  reason,
  approvalId,
  breakGlassId,
  payload = {},
) {
  return sha256(JSON.stringify(canonicalValue({
    action,
    targetType,
    targetId,
    reason,
    approvalId,
    breakGlassId,
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

function table(headers, rows, options = {}) {
  if (rows.length === 0) return "<p>No records.</p>";
  const htmlColumns = new Set(options.htmlColumns || []);
  const head = headers.map((value) => `<th>${escapeHtml(value)}</th>`).join("");
  const body = rows
    .map((row) => `<tr>${row.map((value, index) => (
      `<td>${htmlColumns.has(index) ? String(value) : escapeHtml(value)}</td>`
    )).join("")}</tr>`)
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
    outsideScopeRecords: result.outsideScopeRecords || 0,
    filteredOutRecords: result.filteredOutRecords || 0,
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
        <label>Break-glass ID (optional) <input name="breakGlassId" maxlength="128"></label>
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
        <label>Break-glass ID (optional) <input name="breakGlassId" maxlength="128"></label>
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

function adminPage(session, access, orgUnits, csrfToken, overview, stepUp) {
  const roles = access.roles.length > 0 ? access.roles.join(", ") : "No active role";
  const scopes = access.scopeOrgUnitIds.length > 0 ? access.scopeOrgUnitIds.join(", ") : "None";
  const can = (permission) => access.permissions.includes(permission);
  const orgRows = orgUnits.length > 0
    ? orgUnits.map((org) => `<li><strong>${escapeHtml(org.name)}</strong> <code>${escapeHtml(org.path)}</code></li>`).join("")
    : "<li>No organization scope</li>";
  const orgOptions = [
    ...(hasGlobalScope(access) ? ['<option value="*">Entire enterprise</option>'] : []),
    ...orgUnits.map((org) => (
      `<option value="${escapeHtml(org.id)}">${escapeHtml(org.name)} · ${escapeHtml(org.path)}</option>`
    )),
  ].join("");
  const rowAction = (label, action, targetType, targetId, permission) => (
    can(permission)
      ? `<button type="button" class="row-action" data-write-action="${escapeHtml(action)}" `
        + `data-target-type="${escapeHtml(targetType)}" data-target-id="${escapeHtml(targetId)}">`
        + `${escapeHtml(label)}</button>`
      : ""
  );
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
  const stepUpLabel = stepUp.authenticated
    ? (stepUp.criticalAuthenticated
      ? `verified until ${stepUp.criticalExpiresAt} for critical actions`
      : `valid for high-risk actions until ${stepUp.expiresAt}; critical actions require re-authentication`)
    : ({
      expired: "expired; re-authenticate before the next high-risk action",
      critical_expired: "expired for critical actions; re-authenticate before continuing",
      binding_mismatch: "no longer matches this session, role, scope, IP, or browser",
      unavailable: "not configured; high-risk writes fail closed",
    }[stepUp.state] || "required before high-risk actions");
  const stepUpAction = stepUp.startUrl
    ? ` <a href="${escapeHtml(stepUp.startUrl)}">Re-authenticate</a>.`
    : "";
  const approvalActions = [
    ["user.disable", "Disable user", can("users.disable")],
    ["device.revoke", "Revoke device", can("devices.revoke")],
    ["credential.rotate", "Rotate credential", can("credentials.rotate")],
    ["user.policy.quota", "Change quota", can("quota.write")],
    ["user.policy.models", "Change models", can("models.write")],
    ["usage.export.create", "Create usage export", can("usage.export")],
    ["audit.export.create", "Create audit export", can("audit.export")],
    ["operation.reconcile", "Reconcile operation", can("operations.reconcile")],
  ].filter((entry) => entry[2]);
  const exportKinds = [
    ["usage", "Usage metadata", can("usage.export")],
    ["audit", "Audit metadata", can("audit.export")],
  ].filter((entry) => entry[2]);
  const operationPermissions = [
    "users.disable",
    "devices.revoke",
    "credentials.rotate",
    "quota.write",
    "models.write",
    "usage.export",
    "audit.export",
    "operations.reconcile",
  ];
  const canReadOperations = operationPermissions.some(can);
  const usageExplorer = can("usage.read")
    ? `<form id="usage-filter" class="toolbar">
        <label>From <input name="from" placeholder="2026-10-01T00:00:00Z"></label>
        <label>To <input name="to" placeholder="2026-10-08T00:00:00Z"></label>
        <label>User <input name="userId" maxlength="128"></label>
        <label>Department <select name="departmentId"><option value="">All visible</option>${orgOptions}</select></label>
        <label>Agent <input name="agent" maxlength="160"></label>
        <label>Model <input name="model" maxlength="240"></label>
        <label>Provider <input name="provider" maxlength="160"></label>
        <label>Caller key <input name="callerKeyId" maxlength="240"></label>
        <label>HTTP status <input name="status" inputmode="numeric"></label>
        <button type="submit">Refresh usage</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>
      <div id="usage-summary" class="grid" aria-live="polite"></div>
      <div id="usage-chart" class="chart" aria-label="Usage request trend"></div>`
    : `<p class="notice">Your role cannot read usage metadata.</p>`;
  const approvalRequest = approvalActions.length > 0
    ? `<form id="approval-request-form" class="stack-form">
        <h3>Create approval request</h3>
        <p>Export target IDs are derived from the query. Other actions require a target ID.</p>
        <label>Action
          <select name="action">${approvalActions.map(([value, label]) => (
            `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`
          )).join("")}</select>
        </label>
        <label>Target ID <input name="targetId" maxlength="128"></label>
        <label>Reason <input name="reason" maxlength="500" required></label>
        <label>Business payload (JSON)
          <textarea name="payload" rows="5" placeholder='{"orgUnitId":"org-platform","from":"2026-10-01T00:00:00Z","to":"2026-10-02T00:00:00Z","filters":{}}'>{}</textarea>
        </label>
        <button type="submit">Request independent approval</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>`
    : "";
  const approvalList = can("approvals.read")
    ? `<form id="approval-filter" class="toolbar">
        <label>View
          <select name="view">
            <option value="pending">My approval inbox</option>
            <option value="requested">Requested by me</option>
            <option value="completed">Completed</option>
            <option value="closed">Closed</option>
            <option value="">All approvals</option>
          </select>
        </label>
        <label>Status
          <select name="status">
            <option value="">All states</option>
            <option value="requested">Requested</option>
            <option value="pending_approval">Pending approval</option>
            <option value="approved">Approved</option>
            <option value="rejected">Rejected</option>
            <option value="revoked">Revoked</option>
            <option value="withdrawn">Withdrawn</option>
            <option value="expired">Expired</option>
            <option value="reserved">Reserved</option>
            <option value="consumed">Consumed</option>
          </select>
        </label>
        <label>Action <input name="action" maxlength="128"></label>
        <label>Target type
          <select name="targetType">
            <option value="">All targets</option>
            <option value="user">User</option>
            <option value="device">Device</option>
            <option value="credential">Credential</option>
            <option value="operation">Operation</option>
            <option value="export">Export</option>
          </select>
        </label>
        <label>Requester subject <input name="requesterSubjectId" maxlength="128"></label>
        <button type="submit">Load approvals</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>
      <div id="approval-list" aria-live="polite"></div>`
    : `<p class="notice">Your role cannot read approval requests.</p>`;
  const approvalDecision = approvalActions.length > 0
    ? `<form id="approval-decision-form" class="stack-form">
        <h3>Decide selected approval</h3>
        <p id="approval-selection">No approval selected.</p>
        <label>Step ID (required when several steps are active)
          <input name="stepId" maxlength="64" placeholder="stp_security">
        </label>
        <label>Decision
          <select name="decision"><option value="approve">Approve</option><option value="reject">Reject</option></select>
        </label>
        <label>Decision reason <input name="reason" maxlength="500" required></label>
        <button type="submit">Record decision</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>`
    : "";
  const approvalRevoke = can("approvals.revoke")
    ? `<form id="approval-revoke-form" class="stack-form">
        <h3>Revoke selected approval</h3>
        <p id="approval-revoke-selection">No approval selected.</p>
        <label>Revocation reason <input name="reason" maxlength="500" required></label>
        <button type="submit">Revoke approval</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>`
    : "";
  const approvalWithdraw = can("approvals.read")
    ? `<form id="approval-withdraw-form" class="stack-form">
        <h3>Withdraw my approval request</h3>
        <p id="approval-withdraw-selection">No approval selected.</p>
        <label>Withdrawal reason <input name="reason" maxlength="500" required></label>
        <button type="submit">Withdraw request</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>`
    : "";
  const approvalTransfer = can("approvals.decide")
    ? `<form id="approval-transfer-form" class="stack-form">
        <h3>Transfer an active step</h3>
        <p id="approval-transfer-selection">No approval selected.</p>
        <label>Step ID <input name="stepId" maxlength="64" placeholder="stp_security" required></label>
        <label>Target administrator subject ID
          <input name="toSubjectId" maxlength="64" placeholder="adm_..." required>
        </label>
        <label>Transfer reason <input name="reason" maxlength="500" required></label>
        <button type="submit">Transfer step</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>`
    : "";
  const canRequestBreakGlass = can("breakglass.request") && approvalActions.length > 0;
  const breakGlassRequest = canRequestBreakGlass
    ? `<form id="break-glass-request-form" class="stack-form">
        <h3>Request emergency break-glass authorization</h3>
        <p>Requests are short-lived and single-use. The requester cannot review their own use.</p>
        <label>Action
          <select name="action">${approvalActions.map(([value, label]) => (
            `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`
          )).join("")}</select>
        </label>
        <label>Target ID <input name="targetId" maxlength="128"></label>
        <label>Incident ID <input name="incidentId" maxlength="128" required></label>
        <label>Emergency reason <input name="reason" maxlength="500" required></label>
        <label>Business payload (JSON)
          <textarea name="payload" rows="5" placeholder='{"orgUnitId":"org-platform","from":"2026-10-01T00:00:00Z","to":"2026-10-02T00:00:00Z","filters":{}}'>{}</textarea>
        </label>
        <button type="submit">Request break-glass grant</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>`
    : `<p class="notice">Your role cannot request break-glass authorization.</p>`;
  const breakGlassList = can("breakglass.review")
    ? `<form id="break-glass-filter" class="toolbar">
        <label>Status
          <select name="status">
            <option value="">All states</option>
            <option value="active">Active</option>
            <option value="expired">Expired</option>
            <option value="consumed">Consumed</option>
            <option value="review_overdue">Review overdue</option>
            <option value="reviewed">Reviewed</option>
          </select>
        </label>
        <label>Action <input name="action" maxlength="128"></label>
        <label>Incident ID <input name="incidentId" maxlength="128"></label>
        <label>Requester subject <input name="requesterSubjectId" maxlength="128"></label>
        <label>Target ID <input name="targetId" maxlength="128"></label>
        <button type="submit">Load break-glass grants</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>
      <div id="break-glass-list" aria-live="polite"></div>
      <section class="detail-panel">
        <h3>Break-glass detail</h3>
        <pre id="break-glass-detail">Select a grant to inspect its safe metadata.</pre>
      </section>`
    : `<p class="notice">Your role cannot review break-glass grants.</p>`;
  const breakGlassReview = can("breakglass.review")
    ? `<form id="break-glass-review-form" class="stack-form">
        <h3>Review selected break-glass use</h3>
        <p id="break-glass-selection">No break-glass grant selected.</p>
        <label>Conclusion
          <select name="conclusion">
            <option value="justified">Justified</option>
            <option value="not_justified">Not justified</option>
          </select>
        </label>
        <label>Review reason <input name="reason" maxlength="500" required></label>
        <button type="submit">Record post-incident review</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>`
    : "";
  const exportPanel = exportKinds.length > 0
    ? `<form id="export-form" class="stack-form">
        <h3>Approved metadata export</h3>
        <p>Exports require an approved request, recent authentication, organization scope, and a one-time download token.</p>
        <label>Dataset
          <select name="kind">${exportKinds.map(([value, label]) => (
            `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`
          )).join("")}</select>
        </label>
        <label>Organization scope <select name="orgUnitId" required>${orgOptions}</select></label>
        <label>From <input name="from" placeholder="2026-10-01T00:00:00Z" required></label>
        <label>To <input name="to" placeholder="2026-10-08T00:00:00Z" required></label>
        <label>Filters (JSON) <textarea name="filters" rows="3">{}</textarea></label>
        <label>Reason <input name="reason" maxlength="500" required></label>
        <label>Approved approval ID <input name="approvalId" maxlength="128"></label>
        <label>Break-glass ID <input name="breakGlassId" maxlength="128"></label>
        <label>Idempotency key <input name="idempotencyKey" maxlength="200" placeholder="Leave blank to generate one"></label>
        <div class="button-row">
          <button type="button" id="export-request-approval">Request matching approval</button>
          <button type="submit">Create export</button>
        </div>
        <p class="write-result" role="status" aria-live="polite"></p>
        <div id="export-result" aria-live="polite"></div>
      </form>`
    : `<p class="notice">Your role cannot export usage or audit metadata.</p>`;
  const operationPanel = canReadOperations
    ? `<form id="operation-filter" class="toolbar">
        <label>Operation ID <input name="operationId" maxlength="128"></label>
        <label>Actor subject <input name="actorSubjectId" maxlength="128"></label>
        <label>Action <input name="action" maxlength="128"></label>
        <label>Target type
          <select name="targetType"><option value="">All targets</option><option value="user">User</option><option value="device">Device</option><option value="credential">Credential</option><option value="operation">Operation</option><option value="export">Export</option></select>
        </label>
        <label>Status <input name="status" maxlength="64"></label>
        <label>From <input name="from" placeholder="2026-10-01T00:00:00Z"></label>
        <label>To <input name="to" placeholder="2026-10-08T00:00:00Z"></label>
        <label>Limit <input name="limit" type="number" min="1" max="200" value="50"></label>
        <button type="submit">Load operations</button>
        <button type="button" id="operation-next" hidden>Next page</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>
      <div id="operation-list" aria-live="polite"></div>
      <section class="detail-panel">
        <h3>Operation detail</h3>
        <pre id="operation-detail">Select an operation to inspect its safe metadata.</pre>
      </section>
      <form id="reconcile-form" class="stack-form">
        <h3>Reconcile selected operation</h3>
        <p id="reconcile-selection">No operation selected.</p>
        <label>Reconciliation action
          <select name="action"><option value="retry_desired">Retry desired state</option><option value="rollback_previous">Roll back previous state</option><option value="confirm_applied">Confirm applied</option><option value="confirm_not_applied">Confirm not applied</option></select>
        </label>
        <label>Evidence reference <input name="evidenceRef" maxlength="500"></label>
        <label>Reason <input name="reason" maxlength="500" required></label>
        <label>Approved approval ID <input name="approvalId" maxlength="128"></label>
        <label>Break-glass ID <input name="breakGlassId" maxlength="128"></label>
        <button type="submit">Reconcile</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>`
    : `<p class="notice">Your role cannot read management operations.</p>`;
  const auditPanel = can("audit.read")
    ? `<form id="audit-filter" class="toolbar">
        <label>Operation ID <input name="operationId" maxlength="128"></label>
        <label>Actor subject <input name="actorSubjectId" maxlength="128"></label>
        <label>Action <input name="action" maxlength="128"></label>
        <label>Target type
          <select name="targetType"><option value="">All targets</option><option value="user">User</option><option value="device">Device</option><option value="credential">Credential</option><option value="operation">Operation</option><option value="export">Export</option></select>
        </label>
        <label>Result <input name="result" maxlength="64"></label>
        <label>Phase <input name="phase" maxlength="32"></label>
        <label>Organization <select name="orgUnitId"><option value="">All visible</option>${orgOptions}</select></label>
        <label>From <input name="from" placeholder="2026-10-01T00:00:00Z"></label>
        <label>To <input name="to" placeholder="2026-10-08T00:00:00Z"></label>
        <label>Limit <input name="limit" type="number" min="1" max="200" value="50"></label>
        <button type="submit">Load audit metadata</button>
        <button type="button" id="audit-next" hidden>Next page</button>
        <p class="write-result" role="status" aria-live="polite"></p>
      </form>
      <div id="audit-list" aria-live="polite"></div>`
    : `<p class="notice">Your role cannot read audit metadata.</p>`;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf-token" content="${escapeHtml(csrfToken)}">
  <meta name="admin-permissions" content="${escapeHtml(access.permissions.join(" "))}">
  <meta name="step-up-state" content="${escapeHtml(stepUp.state)}">
  <meta name="step-up-start-url" content="${escapeHtml(stepUp.startUrl)}">
  <title>Magpie Enterprise Admin</title>
  <style>
    :root{--ink:#172018;--paper:#f4f0e4;--card:#fffdf6;--line:#d7cfb9;--accent:#b93c2b;--ok:#17643a;--warn:#9a5b00;--danger:#9e2518}
    *{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#e6d9b8,transparent 38%),var(--paper);color:var(--ink);font:17px/1.55 Georgia,serif}
    main{width:min(1180px,calc(100% - 32px));margin:5vh auto;padding:clamp(24px,5vw,56px);background:var(--card);border:1px solid var(--line);box-shadow:14px 14px 0 #dbca9d}
    h1{font-size:clamp(38px,7vw,74px);line-height:.92;margin:0 0 12px;letter-spacing:-.04em}
    h2{font-size:22px;margin:36px 0 10px;border-bottom:1px solid var(--line);padding-bottom:8px}h3{font-size:18px;margin:0 0 8px}
    .eyebrow{text-transform:uppercase;letter-spacing:.18em;font:700 12px/1.4 Georgia,serif;color:var(--accent)}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px}.box{border:1px solid var(--line);padding:18px;background:#faf5e7}
    code{background:#ece3cc;padding:2px 6px;overflow-wrap:anywhere}ul{padding-left:22px}
    .figure{font-size:38px;line-height:1;margin:8px 0 0}.notice{border-left:4px solid var(--accent);padding:10px 14px;background:#faf5e7}
    .table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font:14px/1.4 Georgia,serif}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);white-space:nowrap}
    button{appearance:none;border:0;background:var(--ink);color:white;padding:12px 18px;font:700 14px/1 Georgia,serif;cursor:pointer}
    button:disabled{opacity:.55;cursor:wait}.row-action{padding:7px 10px;font-size:12px;margin:2px}.button-row{display:flex;gap:10px;flex-wrap:wrap}
    .policy-editor{margin:14px 0;border:1px solid var(--line);background:#faf5e7;padding:14px}.policy-editor summary{cursor:pointer;font-weight:700}
    .editor-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px}.editor-grid form{border-top:1px solid var(--line);padding-top:12px}
    label{display:grid;gap:6px;margin:10px 0;font-weight:700}input,textarea,select{width:100%;border:1px solid var(--line);background:var(--card);padding:10px;font:15px/1.4 ui-monospace,monospace}
    .write-result{min-height:3em;border-left:4px solid var(--line);padding:8px 12px}.write-result[data-tone="error"]{border-color:var(--danger)}.write-result[data-tone="unknown"]{border-color:var(--warn)}.write-result[data-tone="result"]{border-color:var(--ok)}
    .toolbar{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px 14px;align-items:end;border:1px solid var(--line);padding:14px;background:#faf5e7}.toolbar .write-result{grid-column:1/-1}
    .stack-form{border:1px solid var(--line);padding:16px;background:#faf5e7;margin:14px 0}.detail-panel{border-left:4px solid var(--line);padding:8px 14px;background:#faf5e7}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:13px/1.5 ui-monospace,monospace}
    .chart{min-height:150px;margin:16px 0;border:1px solid var(--line);padding:12px;background:#faf5e7}.chart svg{display:block;width:100%;height:auto}.status{display:inline-block;padding:2px 7px;border:1px solid currentColor;font-size:12px}.status[data-tone="ok"]{color:var(--ok)}.status[data-tone="warn"]{color:var(--warn)}.status[data-tone="danger"]{color:var(--danger)}
  </style>
</head>
<body><main>
  <p class="eyebrow">Magpie Enterprise · Management plane</p>
  <h1>Administration</h1>
  <p>Signed in as <strong>${escapeHtml(session.email)}</strong>.</p>
  <p class="notice">This browser console cannot directly change an employee device's local Agent configuration. Employees still need the Agent one-click enrollment flow to write local settings; the admin console controls policy, models, MCP, resources, and access.</p>
  <div class="grid">
    <section class="box"><h2>Roles</h2><p>${escapeHtml(roles)}</p></section>
    <section class="box"><h2>Organization scope</h2><p><code>${escapeHtml(scopes)}</code></p></section>
  </div>
  <h2>Usage explorer</h2>${usageExplorer}
  <h2>Approvals</h2>${approvalRequest}${approvalList}${approvalDecision}${approvalRevoke}${approvalWithdraw}${approvalTransfer}
  <h2>Break-glass</h2>${breakGlassRequest}${breakGlassList}${breakGlassReview}
  <h2>Exports</h2>${exportPanel}
  <h2>Operations</h2>${operationPanel}
  <h2>Audit metadata</h2>${auditPanel}
  <h2>Usage overview</h2>${usageBox}
  <h2>Users</h2>
  <p class="notice">${escapeHtml(overview.usersError || "Current organization-scoped identities.")}</p>
  ${table(
    ["Name", "Email", "Status", "Department", "Policy", "Quota", "Models", "Sync", "Action"],
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
      user.status === "active"
        ? rowAction("Disable", "user.disable", "user", user.id, "users.disable")
        : rowAction("Enable", "user.enable", "user", user.id, "users.disable"),
    ]),
    { htmlColumns: [8] },
  )}
  <form id="operation-write-form" class="stack-form">
    <h3>Apply selected account, device, or credential action</h3>
    <p id="operation-write-selection">Select a row action above.</p>
    <label>Reason <input name="reason" maxlength="500" required></label>
    <label>Approved approval ID <input name="approvalId" maxlength="128"></label>
    <label>Break-glass ID <input name="breakGlassId" maxlength="128"></label>
    <button type="submit">Apply action</button>
    <p class="write-result" role="status" aria-live="polite"></p>
  </form>
  <h2>Policy operations</h2>
  <p class="notice">Only a complete evidence chain permits the verified state. Pending, partial, and unknown results are never converted into success by this page.</p>
  ${editors || "<p>No users available in your organization scope.</p>"}
  <h2>Devices</h2>
  <p class="notice">${escapeHtml(overview.devicesError || "No device token or Gateway Key is exposed.")}</p>
  ${table(
    ["Device", "Platform", "Status", "Last seen", "Key ID", "Action"],
    overview.devices.map((device) => [
      device.name,
      device.platform,
      device.status,
      device.lastSeenAt || "",
      device.gatewayKeyId || "",
      rowAction("Revoke", "device.revoke", "device", device.id, "devices.revoke"),
    ]),
    { htmlColumns: [5] },
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
    ["Key ID", "Device", "Status", "Policy", "Policy sync", "Last synced", "Last error", "Expires", "Action"],
    overview.credentials.map((credential) => [
      credential.id,
      credential.deviceName || credential.deviceId,
      credential.status,
      `v${credential.policyVersion}`,
      credential.policySyncState,
      credential.lastPolicySyncedAt || credential.lastPolicyAttemptedAt || "",
      credential.lastPolicyErrorCode || "",
      credential.expiresAt || "",
      rowAction("Rotate", "credential.rotate", "credential", credential.id, "credentials.rotate"),
    ]),
    { htmlColumns: [8] },
  )}
  <h2>Visible organization units</h2><ul>${orgRows}</ul>
  <h2>Session</h2>
  <p>Expires at ${escapeHtml(session.expiresAt)}. Every request recalculates roles from the store.</p>
  <p class="step-up-state">Recent authentication: <strong>${escapeHtml(stepUpLabel)}</strong>.${stepUpAction}</p>
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
    cookieHeader(config, config.stepUpCookieName, "", 0),
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
  const stepUpOidc = config.stepUpOidc
    ? (options.stepUpOidc || new OidcClient(config.stepUpOidc))
    : null;
  const authService = options.authService || new AuthServiceClient(config.authService);
  const notificationChannelSettings = config.notifications?.channels || {};
  const notificationChannelTransport = options.notificationChannelTransport || (
    notificationChannelSettings.enabled
      ? new NotificationChannelTransport(store, {
        env: options.notificationChannelEnv || process.env,
        allowlist: notificationChannelSettings.outboundAllowlist || [],
        emailRecipientDomains: notificationChannelSettings.emailRecipientDomains || [],
        timeoutMs: notificationChannelSettings.httpTimeoutMs,
        maxResponseBytes: notificationChannelSettings.httpMaxResponseBytes,
        maxSiemEventBytes: notificationChannelSettings.maxSiemEventBytes,
        maxRedirects: notificationChannelSettings.httpMaxRedirects,
        dnsResolver: options.notificationDnsResolver,
        requestImpl: options.notificationRequestImpl,
        now: options.notificationNow,
      })
      : null
  );
  const notificationOutbox = options.notificationOutbox || new NotificationOutbox(store, {
    maxAttempts: config.notifications?.maxAttempts || 6,
    now: options.notificationNow,
    channelProvider: notificationChannelSettings.enabled
      ? channelProviderFromData
      : null,
  });
  const notificationTransport = options.notificationTransport || (
    notificationChannelTransport
      ? (delivery) => notificationChannelTransport.deliver(delivery)
      : null
  );
  const notificationDispatcher = options.notificationDispatcher || (
    notificationTransport
      ? new NotificationDispatcher(store, {
        transport: notificationTransport,
        leaseMs: config.notifications?.leaseMs || 60 * 1000,
        pollIntervalMs: config.notifications?.pollIntervalMs || 30 * 1000,
        batchSize: config.notifications?.batchSize || 20,
        now: options.notificationNow,
      })
      : null
  );
  const rate = new Map();
  const approvalEnvironmentId = `env_${sha256(new URL(config.publicUrl).origin).slice(0, 24)}`;
  await notificationOutbox.recoverExpired();

  function breakGlassNow() {
    if (typeof options.breakGlassNow === "function") {
      return new Date(options.breakGlassNow());
    }
    if (options.breakGlassNow != null) return new Date(options.breakGlassNow);
    return new Date();
  }

  function currentApprovalPolicyVersion() {
    const catalogVersion = Number.isSafeInteger(modelCatalog.status.catalogVersion)
      ? modelCatalog.status.catalogVersion
      : 0;
    return `${APPROVAL_POLICY_VERSION}:catalog=${catalogVersion}:${
      modelCatalog.status.catalogDigest || "legacy"
    }`;
  }

  function appendApprovalSystemAudit(data, action, approval, options = {}) {
    const record = {
      id: `audit_${crypto.randomUUID()}`,
      action,
      timestamp: new Date().toISOString(),
      approvalId: String(approval?.id || ""),
      result: String(options.result || ""),
      errorCode: String(options.errorCode || ""),
      actorSubjectId: String(options.actorSubjectId || ""),
      actorEmail: String(options.actorEmail || ""),
      source: String(options.source || ""),
      eventId: String(options.eventId || ""),
      externalReference: String(options.externalReference || ""),
      requesterSubjectId: String(approval?.requesterSubjectId || ""),
      approvalAction: String(approval?.action || options.approvalAction || ""),
      targetType: String(approval?.targetType || options.targetType || ""),
      targetId: String(approval?.targetId || options.targetId || ""),
      targetOrgUnitId: String(approval?.targetOrgUnitId || options.targetOrgUnitId || ""),
      riskLevel: String(approval?.riskLevel || options.riskLevel || ""),
      payloadDigest: String(approval?.payloadDigest || options.payloadDigest || ""),
      operationId: String(options.operationId || approval?.operationId || ""),
      reason: String(options.reason || ""),
    };
    data.adminSystemAuditLogs.push(record);
    notificationOutbox.enqueueApproval(data, action, approval, {
      ...options,
      eventKey: ["approval.step_progressed", "approval.transferred"].includes(action)
        ? options.eventKey
        : "",
      occurredAt: record.timestamp,
      organizationId: approvalEnvironmentId,
      requestId: options.requestId || "",
    });
  }

  function breakGlassHttpError(code, message = "Break-glass authorization failed") {
    const statusCode = code === "break_glass_invalid"
      ? 404
      : ["break_glass_expired", "break_glass_consumed"].includes(code)
        ? 409
        : 403;
    return new HttpError(statusCode, code, message);
  }

  function appendBreakGlassSystemAudit(data, action, grant, options = {}) {
    const record = {
      id: `audit_${crypto.randomUUID()}`,
      action,
      timestamp: String(options.timestamp || new Date().toISOString()),
      breakGlassId: String(grant?.id || ""),
      incidentId: String(grant?.incidentId || ""),
      result: String(options.result || action.split(".").at(-1) || ""),
      errorCode: String(options.errorCode || ""),
      actorSubjectId: String(options.actorSubjectId || ""),
      actorEmail: String(options.actorEmail || ""),
      requesterSubjectId: String(grant?.requesterSubjectId || ""),
      breakGlassAction: String(grant?.action || ""),
      targetType: String(grant?.targetType || ""),
      targetId: String(grant?.targetId || ""),
      targetOrgUnitId: String(grant?.targetOrgUnitId || ""),
      riskLevel: String(grant?.riskLevel || ""),
      payloadDigest: String(grant?.payloadDigest || ""),
      bindingDigest: String(grant?.bindingDigest || ""),
      operationId: String(options.operationId || grant?.operationId || ""),
      reason: String(options.reason || ""),
    };
    data.adminSystemAuditLogs.push(record);
  }

  function consumeBreakGlassForOperation(data, breakGlassId, expected, operation, nowDate) {
    const grant = data.breakGlassGrants[breakGlassId];
    const now = nowDate instanceof Date ? nowDate : new Date(nowDate);
    const nowMs = now.getTime();
    if (!Number.isFinite(nowMs)) {
      throw new HttpError(503, "storage_unavailable", "Break-glass consumption time is invalid");
    }
    const failure = breakGlassConsumptionFailure(grant, expected, nowMs);
    if (failure) {
      throw breakGlassHttpError(failure);
    }
    const consumedAt = now.toISOString();
    grant.consumedAt = consumedAt;
    grant.consumedBySubjectId = String(operation.actorSubjectId || "");
    grant.operationId = String(operation.id || "");
    grant.reviewDueAt = breakGlassReviewDueAt(consumedAt);
    grant.updatedAt = consumedAt;
    grant.stateHistory.push({
      status: "consumed",
      at: consumedAt,
      actorSubjectId: grant.consumedBySubjectId,
      reason: `consumed by ${operation.action}`,
    });
    notificationOutbox.enqueueBreakGlass(data, "used", grant, {
      occurredAt: consumedAt,
      actorSubjectId: operation.actorSubjectId,
      actorEmail: operation.actorEmail,
      operationId: operation.id,
      requestId: operation.requestId,
      organizationId: approvalEnvironmentId,
    });
    appendBreakGlassSystemAudit(data, "break_glass.used", grant, {
      timestamp: consumedAt,
      result: "consumed",
      actorSubjectId: operation.actorSubjectId,
      actorEmail: operation.actorEmail,
      operationId: operation.id,
      reason: operation.reason,
    });
    return grant;
  }

  function approvalStepById(approval, stepId) {
    ensureApprovalWorkflow(approval);
    return (approval.steps || []).find((step) => step.stepId === stepId) || null;
  }

  function approvalSubjectMatchesStep(step, subjectId, roles) {
    if (!step || step.ineligibleSubjectIds.includes(subjectId)) return false;
    if (step.eligibleSubjectIds.length === 0 && step.eligibleRoles.length === 0) return true;
    if (step.eligibleSubjectIds.includes(subjectId)) return true;
    return step.eligibleRoles.some((role) => roles.includes(role));
  }

  function approvalStepIdInput(value) {
    const stepId = String(value ?? "").trim();
    if (!stepId) return "";
    if (!/^stp_[A-Za-z0-9_-]{1,60}$/.test(stepId)) {
      throw new HttpError(400, "invalid_approval_step", "stepId is invalid");
    }
    return stepId;
  }

  function cancelUnfinishedApprovalSteps(approval) {
    ensureApprovalWorkflow(approval);
    for (const step of approval.steps) {
      if (step.status === "pending" || step.status === "in_progress") {
        step.status = "cancelled";
      }
    }
  }

  function activateNextSerialApprovalStep(approval) {
    ensureApprovalWorkflow(approval);
    if (approval.workflowKind !== "serial") return;
    if (approval.steps.some((step) => step.status === "in_progress")) return;
    const next = approval.steps.find((step) => step.status === "pending");
    if (next) next.status = "in_progress";
  }

  function approvalDecisionStep(approval, requestedStepId = "") {
    ensureApprovalWorkflow(approval);
    if (requestedStepId) {
      const step = approvalStepById(approval, requestedStepId);
      if (!step || step.status !== "in_progress") {
        return {
          error: approvalHttpError(
            "approval_step_unavailable",
            "The requested approval step is not awaiting a decision",
          ),
        };
      }
      return { step };
    }
    const active = approval.steps.filter((step) => step.status === "in_progress");
    if (active.length === 1) return { step: active[0] };
    if (active.length > 1) {
      return {
        error: approvalHttpError(
          "approval_step_unavailable",
          "stepId is required while multiple approval steps are active",
        ),
      };
    }
    return {
      error: approvalHttpError(
        "approval_step_unavailable",
        "Approval has no step awaiting a decision",
      ),
    };
  }

  function recordApprovalDecision(data, approval, input) {
    ensureApprovalWorkflow(approval);
    const step = input.step;
    const createdAt = input.createdAt || new Date().toISOString();
    const record = {
      id: `apd_${crypto.randomUUID()}`,
      approvalId: approval.id,
      decision: input.decision,
      actorSubjectId: input.actorSubjectId,
      actorEmail: String(input.actorEmail || ""),
      source: String(input.source || "admin"),
      eventId: String(input.eventId || ""),
      externalReference: String(input.externalReference || ""),
      issuer: String(input.issuer || ""),
      stepId: step.stepId,
      workflowVersion: approval.workflowVersion,
      reason: String(input.reason || ""),
      createdAt,
    };
    data.approvalDecisions[record.id] = record;
    step.decidedBySubjectIds = [
      ...new Set([...step.decidedBySubjectIds, input.actorSubjectId]),
    ].sort();

    if (input.decision === "reject") {
      step.status = "rejected";
      cancelUnfinishedApprovalSteps(approval);
      transitionApproval(approval, "rejected", input.actorSubjectId, "rejected");
      approval.rejectedAt = createdAt;
      approval.rejectedBySubjectId = input.actorSubjectId;
      approval.rejectedByEmail = String(input.actorEmail || "");
      return {
        record,
        step,
        stepCompleted: true,
        workflowCompleted: false,
        finalStatus: approval.status,
      };
    }

    const stepCompleted = step.decidedBySubjectIds.length >= step.quorum;
    if (stepCompleted) {
      step.status = "approved";
      activateNextSerialApprovalStep(approval);
    } else {
      step.status = "in_progress";
    }
    const workflowCompleted = stepCompleted
      && !approvalWorkflowFailure({ ...approval, status: "approved" });
    if (workflowCompleted) {
      transitionApproval(approval, "approved", input.actorSubjectId, "approved");
      approval.approvedAt = createdAt;
      approval.approvedBySubjectId = input.actorSubjectId;
      approval.approvedByEmail = String(input.actorEmail || "");
    } else if (approval.status === "requested") {
      transitionApproval(
        approval,
        "pending_approval",
        input.actorSubjectId,
        "approval workflow in progress",
      );
    } else {
      approval.updatedAt = createdAt;
      approval.status = "pending_approval";
    }
    return {
      record,
      step,
      stepCompleted,
      workflowCompleted,
      finalStatus: approval.status,
    };
  }

  function approvalActorFailure(data, approval, subjectId, permission) {
    const decision = authorize(data, subjectId, "approvals.decide", approval.targetOrgUnitId);
    if (!decision.allowed) return decision.reason;
    const business = authorize(data, subjectId, permission, approval.targetOrgUnitId);
    if (!business.allowed) return business.reason;
    return "";
  }

  function approvalStepActorFailure(data, approval, step, subjectId, permission) {
    const access = effectiveAccess(data, subjectId);
    if (!approvalSubjectMatchesStep(step, subjectId, access.roles)
        || step.decidedBySubjectIds.includes(subjectId)) {
      return "approval_step_ineligible";
    }
    return approvalActorFailure(data, approval, subjectId, permission);
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
    for (const [nonceDigest, nonce] of Object.entries(data.approvalCallbackNonces)) {
      const expiresAt = Date.parse(nonce?.expiresAt || "");
      if (!Number.isFinite(expiresAt) || expiresAt <= now) {
        delete data.approvalCallbackNonces[nonceDigest];
      }
    }
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
        ensureApprovalWorkflow(approval);
        cancelUnfinishedApprovalSteps(approval);
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

  function approvalStoredBindingIsValid(approval) {
    const definition = APPROVAL_ACTION_TARGETS[approval.action];
    if (!definition
        || definition.targetType !== approval.targetType
        || riskForAction(approval.action) !== approval.riskLevel
        || !approval.payloadSummary
        || typeof approval.payloadSummary !== "object"
        || Array.isArray(approval.payloadSummary)) {
      return false;
    }
    let payload;
    try {
      payload = normalizedApprovalPayload(approval.action, approval.payloadSummary);
    } catch {
      return false;
    }
    const payloadDigest = approvalPayloadDigest(approval.action, payload);
    const bindingDigest = approvalBindingDigest({
      environmentId: approval.environmentId,
      policyVersion: approval.policyVersion,
      requesterSubjectId: approval.requesterSubjectId,
      action: approval.action,
      targetType: approval.targetType,
      targetId: approval.targetId,
      targetOrgUnitId: approval.targetOrgUnitId,
      riskLevel: approval.riskLevel,
      reason: approval.reason,
      payloadDigest,
    });
    return approval.payloadDigest === payloadDigest
      && approval.bindingDigest === bindingDigest;
  }

  function approvalWorkflowText(value, name, maxLength = 64) {
    const text = String(value ?? "").trim();
    if (!text
        || [...text].length > maxLength
        || !/^[A-Za-z0-9_-]+$/.test(text)) {
      throw new HttpError(
        400,
        "invalid_approval_workflow",
        `${name} must be a bounded identifier`,
      );
    }
    return text;
  }

  function approvalWorkflowSubjectIds(value, name) {
    if (value == null) return [];
    if (!Array.isArray(value) || value.length > 20) {
      throw new HttpError(400, "invalid_approval_workflow", `${name} must be an array`);
    }
    const ids = [...new Set(value.map((entry) => approvalWorkflowText(entry, name, 64)))];
    if (ids.some((id) => !/^adm_[a-z0-9]{24}$/.test(id))) {
      throw new HttpError(
        400,
        "invalid_approval_workflow",
        `${name} must contain admin subject IDs`,
      );
    }
    return ids.sort();
  }

  function approvalWorkflowRoles(value, name) {
    if (value == null) return [];
    if (!Array.isArray(value) || value.length > 20) {
      throw new HttpError(400, "invalid_approval_workflow", `${name} must be an array`);
    }
    const roles = [...new Set(value.map((entry) => approvalWorkflowText(entry, name, 64)))];
    if (roles.some((role) => !ROLES[role])) {
      throw new HttpError(400, "invalid_approval_workflow", `${name} contains an unknown role`);
    }
    return roles.sort();
  }

  function approvalWorkflowFromRequest(data, input, binding) {
    const explicit = input.workflow != null || input.approverSubjectIds != null;
    if (!explicit) {
      return {
        workflowVersion: 1,
        workflowKind: "serial",
        steps: [{
          stepId: "stp_1",
          mode: "serial",
          requiredApprovers: 1,
          quorum: 1,
          order: 1,
          status: "in_progress",
          eligibleSubjectIds: [],
          eligibleRoles: [],
          ineligibleSubjectIds: [],
          decidedBySubjectIds: [],
          transferHistory: [],
        }],
      };
    }
    const source = input.workflow == null
      ? { kind: "serial", steps: [{ approverSubjectIds: input.approverSubjectIds }] }
      : input.workflow;
    if (!source || typeof source !== "object" || Array.isArray(source)) {
      throw new HttpError(400, "invalid_approval_workflow", "workflow must be an object");
    }
    const workflowKind = String(source.kind || "serial");
    if (!["serial", "parallel"].includes(workflowKind)) {
      throw new HttpError(400, "invalid_approval_workflow", "workflow.kind is not supported");
    }
    if (!Array.isArray(source.steps) || source.steps.length < 1 || source.steps.length > 10) {
      throw new HttpError(
        400,
        "invalid_approval_workflow",
        "workflow.steps must contain between 1 and 10 steps",
      );
    }
    const stepIds = new Set();
    const steps = source.steps.map((raw, index) => {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
        throw new HttpError(400, "invalid_approval_workflow", "workflow step is invalid");
      }
      const stepId = raw.stepId == null
        ? `stp_${index + 1}`
        : approvalWorkflowText(raw.stepId, "workflow.stepId", 64);
      if (!/^stp_[A-Za-z0-9_-]{1,60}$/.test(stepId)) {
        throw new HttpError(
          400,
          "invalid_approval_workflow",
          "workflow.stepId must use the stp_ identifier format",
        );
      }
      if (stepIds.has(stepId)) {
        throw new HttpError(400, "invalid_approval_workflow", "workflow step IDs must be unique");
      }
      stepIds.add(stepId);
      const eligibleSubjectIds = approvalWorkflowSubjectIds(
        raw.approverSubjectIds ?? raw.eligibleSubjectIds,
        "workflow approverSubjectIds",
      );
      if (eligibleSubjectIds.includes(binding.requesterSubjectId)) {
        throw new HttpError(
          400,
          "invalid_approval_workflow",
          "The requester cannot be an eligible approver",
        );
      }
      const eligibleRoles = approvalWorkflowRoles(
        raw.eligibleRoles,
        "workflow eligibleRoles",
      );
      if (eligibleSubjectIds.length === 0 && eligibleRoles.length === 0) {
        throw new HttpError(
          400,
          "invalid_approval_workflow",
          "Each workflow step must name eligible subjects or roles",
        );
      }
      const requiredApprovers = raw.requiredApprovers == null
        ? Math.max(1, eligibleSubjectIds.length || 1)
        : Number(raw.requiredApprovers);
      const quorum = raw.quorum == null ? requiredApprovers : Number(raw.quorum);
      if (!Number.isSafeInteger(requiredApprovers) || requiredApprovers < 1
          || requiredApprovers > 20
          || !Number.isSafeInteger(quorum) || quorum < 1
          || quorum > requiredApprovers) {
        throw new HttpError(
          400,
          "invalid_approval_workflow",
          "workflow approver counts are invalid",
        );
      }
      if (eligibleSubjectIds.length > 0 && quorum > eligibleSubjectIds.length
          && eligibleRoles.length === 0) {
        throw new HttpError(
          400,
          "invalid_approval_workflow",
          "workflow quorum exceeds the named approvers",
        );
      }
      for (const subjectId of eligibleSubjectIds) {
        const failure = approvalActorFailure(
          data,
          binding,
          subjectId,
          APPROVAL_ACTION_TARGETS[binding.action].permission,
        );
        if (failure) {
          throw new HttpError(
            400,
            "invalid_approval_workflow",
            "A named approver lacks decision permission or organization scope",
          );
        }
      }
      return {
        stepId,
        mode: workflowKind === "parallel" || raw.mode === "parallel" ? "parallel" : "serial",
        requiredApprovers,
        quorum,
        order: index + 1,
        status: workflowKind === "parallel" || index === 0 ? "in_progress" : "pending",
        eligibleSubjectIds,
        eligibleRoles,
        ineligibleSubjectIds: [],
        decidedBySubjectIds: [],
        transferHistory: [],
      };
    });
    return {
      workflowVersion: 1,
      workflowKind,
      steps,
    };
  }

  function approvalHttpError(code, message = "Approval validation failed") {
    const statusCode = code === "approval_required"
      ? 400
      : ["approval_consumed", "approval_payload_mismatch", "approval_incomplete",
        "approval_step_unavailable"].includes(code)
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

  function exportKindForAction(action) {
    if (action === "usage.export.create") return "usage";
    if (action === "audit.export.create") return "audit";
    return "";
  }

  function cleanExportFilterValue(value, name) {
    if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        throw new HttpError(400, "invalid_export_filter", `${name} is invalid`);
      }
      return value;
    }
    if (typeof value !== "string") {
      throw new HttpError(400, "invalid_export_filter", `${name} is invalid`);
    }
    const normalized = value.trim();
    if ([...normalized].length > 256 || /[\u0000-\u001f\u007f]/.test(normalized)) {
      throw new HttpError(400, "invalid_export_filter", `${name} is invalid`);
    }
    return normalized;
  }

  function normalizedExportFilters(kind, value) {
    if (value == null) return {};
    if (typeof value !== "object" || Array.isArray(value)) {
      throw new HttpError(400, "invalid_export_filter", "filters must be an object");
    }
    const allowed = kind === "usage"
      ? new Set([
        "userId",
        "departmentId",
        "agent",
        "model",
        "provider",
        "callerKeyId",
        "status",
      ])
      : new Set([
        "operationId",
        "actorSubjectId",
        "action",
        "targetType",
        "targetId",
        "result",
        "phase",
      ]);
    const entries = Object.entries(value);
    if (entries.length > 20) {
      throw new HttpError(400, "invalid_export_filter", "Too many export filters");
    }
    const output = {};
    for (const [key, entry] of entries) {
      if (!/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(key) || !allowed.has(key)) {
        throw new HttpError(400, "invalid_export_filter", `filters.${key} is not supported`);
      }
      const normalized = cleanExportFilterValue(entry, `filters.${key}`);
      if (normalized !== "") output[key] = normalized;
    }
    return canonicalValue(output);
  }

  function normalizedExportRequest(action, value = {}) {
    const kind = exportKindForAction(action);
    if (!kind) {
      throw new HttpError(400, "invalid_export_type", "The export action is not supported");
    }
    const exportType = String(value.exportType || kind).trim().toLowerCase();
    if (exportType !== kind) {
      throw new HttpError(400, "invalid_export_type", "exportType does not match the action");
    }
    const orgUnitId = cleanIdentifier(
      value.orgUnitId,
      "orgUnitId",
      "invalid_export_scope",
    );
    const fromValue = String(value.from || "").trim();
    const toValue = String(value.to || "").trim();
    const fromTime = Date.parse(fromValue);
    const toTime = Date.parse(toValue);
    if (!Number.isFinite(fromTime) || !Number.isFinite(toTime) || fromTime >= toTime) {
      throw new HttpError(400, "invalid_time_range", "from and to must be an ascending time range");
    }
    if (toTime - fromTime > config.usage.maxRangeDays * 24 * 3600 * 1000) {
      throw new HttpError(400, "time_range_too_large", "The requested time range is too large");
    }
    return {
      exportType: kind,
      orgUnitId,
      from: new Date(fromTime).toISOString(),
      to: new Date(toTime).toISOString(),
      filters: normalizedExportFilters(kind, value.filters),
    };
  }

  function exportTargetId(action, request) {
    return `exp_${sha256(JSON.stringify(canonicalValue({
      action,
      ...request,
    })))}`;
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
    if (action === "usage.export.create" || action === "audit.export.create") {
      return normalizedExportRequest(action, body);
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
    if (action === "usage.export.create" || action === "audit.export.create") {
      const request = normalizedExportRequest(action, payload);
      const expectedTargetId = exportTargetId(action, request);
      if (expectedTargetId !== targetId) {
        throw new HttpError(
          400,
          "invalid_export_target",
          "targetId does not match the export query",
        );
      }
      const sessionAccess = await requirePermission(session, definition.permission);
      if (request.orgUnitId === "*") {
        if (!hasGlobalScope(sessionAccess.access)) {
          throw new HttpError(403, "forbidden_scope", "Global export scope is not allowed");
        }
      } else {
        const org = sessionAccess.data.orgUnits[request.orgUnitId];
        if (!org || org.status !== "active") {
          throw new HttpError(400, "invalid_export_scope", "orgUnitId is not active");
        }
        if (!sessionAccess.access.scopeOrgUnitIds.includes("*")
            && !sessionAccess.access.scopeOrgUnitIds.includes(request.orgUnitId)) {
          throw new HttpError(403, "forbidden_scope", "The export scope is outside your access");
        }
      }
      return {
        targetType: "export",
        targetId: expectedTargetId,
        targetOrgUnitId: request.orgUnitId,
        target: {
          id: expectedTargetId,
          exportType: request.exportType,
          orgUnitId: request.orgUnitId,
        },
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

  async function externalApprovalCallback(req, res) {
    if (!config.approvalCallback.enabled) {
      throw new ApprovalCallbackError(
        503,
        "approval_callback_unavailable",
        "External approval callbacks are not configured",
      );
    }
    if (!/^application\/json(?:\s*;|$)/i.test(String(req.headers["content-type"] || ""))) {
      throw new HttpError(415, "unsupported_media_type", "Content-Type must be application/json");
    }
    const rawBody = await readRawBody(req);
    const callback = parseApprovalCallback(config, req.headers, rawBody);
    const outcome = await store.mutate((data) => {
      const existingEvent = data.approvalCallbackEvents[callback.body.eventId];
      if (existingEvent) {
        if (existingEvent.eventDigest !== callback.eventDigest) {
          return {
            error: new ApprovalCallbackError(
              409,
              "approval_callback_conflict",
              "This event ID was already used with a different payload",
            ),
          };
        }
        const approval = data.approvalRequests[existingEvent.approvalId];
        if (!approval) {
          return {
            error: new ApprovalCallbackError(
              409,
              "approval_callback_conflict",
              "The original callback approval is no longer available",
            ),
          };
        }
        return {
          approval: structuredClone(approval),
          decisions: structuredClone(approvalDecisionList(data, approval.id)),
          idempotent: true,
        };
      }

      const existingNonce = data.approvalCallbackNonces[callback.nonceDigest];
      if (existingNonce) {
        if (Date.parse(existingNonce.expiresAt) > Date.now()) {
          return {
            error: new ApprovalCallbackError(
              409,
              "approval_callback_replay",
              "This callback nonce was already used",
            ),
          };
        }
        delete data.approvalCallbackNonces[callback.nonceDigest];
      }

      const approval = data.approvalRequests[callback.body.approvalId];
      if (!approval) {
        return {
          error: new ApprovalCallbackError(404, "approval_not_found", "Approval not found"),
        };
      }
      if (approval.environmentId !== approvalEnvironmentId
          || !approvalStoredBindingIsValid(approval)) {
        return {
          error: new ApprovalCallbackError(
            403,
            "approval_callback_scope",
            "Approval does not belong to this environment or has invalid binding data",
          ),
        };
      }
      const targetOrgUnit = approval.targetOrgUnitId === "*"
        ? { status: "active" }
        : data.orgUnits[approval.targetOrgUnitId];
      if (!targetOrgUnit || targetOrgUnit.status !== "active") {
        return {
          error: new ApprovalCallbackError(
            403,
            "approval_callback_scope",
            "The approval target organization is not active",
          ),
        };
      }
      if (approval.requesterSubjectId === callback.body.actorSubjectId
          || (callback.body.actorEmail
            && approval.requesterEmail
            && callback.body.actorEmail.toLowerCase() === approval.requesterEmail.toLowerCase())) {
        return {
          error: approvalHttpError(
            "approval_separation_required",
            "The requester cannot decide their own approval",
          ),
        };
      }
      if (approvalIsExpired(approval)) {
        ensureApprovalWorkflow(approval);
        cancelUnfinishedApprovalSteps(approval);
        transitionApproval(approval, "expired", "system_expiry", "approval expired");
        appendApprovalSystemAudit(data, "approval.expired", approval, {
          result: "expired",
          errorCode: "approval_expired",
          source: "external",
          eventId: callback.body.eventId,
          externalReference: callback.body.externalReference,
        });
        return { error: approvalHttpError("approval_expired", "Approval has expired") };
      }
      if (approval.status === "revoked") {
        return { error: approvalHttpError("approval_revoked", "Approval was revoked") };
      }
      if (approval.status === "withdrawn") {
        return { error: approvalHttpError("approval_withdrawn", "Approval was withdrawn") };
      }
      if (approval.status === "reserved"
          || approval.status === "consumed"
          || data.approvalConsumptions[approval.id]) {
        return { error: approvalHttpError("approval_consumed", "Approval was already consumed") };
      }
      if (!["requested", "pending_approval"].includes(approval.status)) {
        return {
          error: approvalHttpError(
            "approval_unavailable",
            "Approval is not awaiting a decision",
          ),
        };
      }

      ensureApprovalWorkflow(approval);
      const legacyExternalStep = approval.workflowKind === "serial"
        && approval.steps.length === 1
        && approval.steps[0].stepId === "stp_1"
        && approval.steps[0].eligibleSubjectIds.length === 0
        && approval.steps[0].eligibleRoles.length === 0
        && approval.steps[0].ineligibleSubjectIds.length === 0
        && approval.steps[0].transferHistory.length === 0;
      if (!legacyExternalStep && !callback.body.stepId) {
        return {
          error: approvalHttpError(
            "approval_step_unavailable",
            "stepId is required for an externally configured approval workflow",
          ),
        };
      }
      const stepDecision = approvalDecisionStep(approval, callback.body.stepId);
      if (stepDecision.error) return { error: stepDecision.error };
      if (!legacyExternalStep) {
        const definition = approvalActionDefinition(approval.action);
        const stepFailure = approvalStepActorFailure(
          data,
          approval,
          stepDecision.step,
          callback.body.actorSubjectId,
          definition.permission,
        );
        if (stepFailure === "approval_step_ineligible") {
          return {
            error: approvalHttpError(
              "approval_step_ineligible",
              "The external approver is not eligible for this step",
            ),
          };
        }
        if (stepFailure) {
          return {
            error: new ApprovalCallbackError(
              403,
              "approval_callback_scope",
              "The external approver lacks decision permission or organization scope",
            ),
          };
        }
      }
      const createdAt = callback.receivedAt;
      const decisionResult = recordApprovalDecision(data, approval, {
        decision: callback.body.decision,
        step: stepDecision.step,
        actorSubjectId: callback.body.actorSubjectId,
        actorEmail: callback.body.actorEmail,
        source: "external",
        eventId: callback.body.eventId,
        externalReference: callback.body.externalReference,
        issuer: callback.body.issuer,
        reason: callback.body.reason,
        createdAt,
      });
      const decisionId = decisionResult.record.id;
      approval.decisionSource = "external";
      approval.externalReference = callback.body.externalReference;
      approval.externalEventId = callback.body.eventId;
      const auditAction = callback.body.decision === "reject"
        ? "approval.rejected"
        : (decisionResult.workflowCompleted
          ? "approval.approved"
          : "approval.step_progressed");
      appendApprovalSystemAudit(
        data,
        auditAction,
        approval,
        {
          result: callback.body.decision === "reject"
            ? "rejected"
            : (decisionResult.workflowCompleted ? "approved" : "step_progressed"),
          actorSubjectId: callback.body.actorSubjectId,
          actorEmail: callback.body.actorEmail,
          reason: callback.body.reason,
          source: "external",
          eventId: callback.body.eventId,
          externalReference: callback.body.externalReference,
          eventKey: `${stepDecision.step.stepId}_${decisionId}`,
        },
      );
      const event = {
        eventId: callback.body.eventId,
        eventDigest: callback.eventDigest,
        approvalId: approval.id,
        nonceDigest: callback.nonceDigest,
        outcome: callback.body.decision === "reject"
          ? "rejected"
          : (decisionResult.workflowCompleted ? "approved" : "step_progressed"),
        issuer: callback.body.issuer,
        audience: callback.body.audience,
        externalReference: callback.body.externalReference,
        actorSubjectId: callback.body.actorSubjectId,
        decisionId,
        receivedAt: createdAt,
      };
      data.approvalCallbackEvents[event.eventId] = event;
      data.approvalCallbackNonces[callback.nonceDigest] = {
        nonceDigest: callback.nonceDigest,
        eventId: event.eventId,
        receivedAt: createdAt,
        expiresAt: new Date(
          Date.parse(createdAt) + config.approvalCallback.nonceTtlSeconds * 1000,
        ).toISOString(),
      };
      return {
        approval: structuredClone(approval),
        decisions: structuredClone(approvalDecisionList(data, approval.id)),
        idempotent: false,
      };
    });
    if (outcome.error) throw outcome.error;
    json(res, 200, {
      ok: true,
      idempotent: outcome.idempotent,
      approval: publicApproval(outcome.approval, outcome.decisions),
    });
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
    const reason = cleanReason(body.reason);
    const payload = approvalBusinessPayload(action, body);
    let targetId;
    if (action === "usage.export.create" || action === "audit.export.create") {
      targetId = exportTargetId(action, payload);
      if (body.targetId != null && String(body.targetId).trim()) {
        const suppliedTargetId = cleanIdentifier(
          body.targetId,
          "targetId",
          "invalid_request",
        );
        if (suppliedTargetId !== targetId) {
          throw new HttpError(
            400,
            "invalid_export_target",
            "targetId does not match the export query",
          );
        }
      }
    } else {
      targetId = cleanIdentifier(body.targetId, "targetId", "invalid_request");
    }
    const target = await resolveApprovalTarget(current.session, action, targetId, payload);
    await requireStepUp(current, req, action);
    const explicitWorkflow = body.workflow != null || body.approverSubjectIds != null;
    if (explicitWorkflow) {
      await requirePermission(current.session, "approvals.configure");
    }
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
    const workflow = await store.read((data) => approvalWorkflowFromRequest(
      data,
      body,
      expected,
    ));
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
      approvedByEmail: "",
      rejectedAt: "",
      rejectedBySubjectId: "",
      rejectedByEmail: "",
      revokedAt: "",
      withdrawnAt: "",
      withdrawnBySubjectId: "",
      operationId: "",
      consumedAt: "",
      workflowVersion: workflow.workflowVersion,
      workflowKind: workflow.workflowKind,
      steps: workflow.steps,
      stateHistory: [{
        status: "requested",
        at: now.toISOString(),
        actorSubjectId: current.session.subjectId,
        reason: "approval requested",
      }],
    };
    await store.mutate((data) => {
      if (explicitWorkflow
          && !authorize(
            data,
            current.session.subjectId,
            "approvals.configure",
            expected.targetOrgUnitId,
          ).allowed) {
        throw new HttpError(
          403,
          "forbidden_role",
          "Only an authorized administrator can configure approval steps",
        );
      }
      const currentWorkflow = approvalWorkflowFromRequest(data, body, expected);
      approval.workflowVersion = currentWorkflow.workflowVersion;
      approval.workflowKind = currentWorkflow.workflowKind;
      approval.steps = currentWorkflow.steps;
      data.approvalRequests[approval.id] = structuredClone(approval);
      appendApprovalSystemAudit(data, "approval.requested", approval, {
        result: "requested",
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
      });
    });
    json(res, 201, { approval: publicApproval(approval) });
  }

  function breakGlassQuery(searchParams) {
    const one = (name, maxLength = 256) => {
      const value = String(searchParams.get(name) || "").trim();
      if ([...value].length > maxLength || /[\u0000-\u001f\u007f]/.test(value)) {
        throw new HttpError(400, "invalid_break_glass_filter", `${name} is invalid`);
      }
      return value;
    };
    const rawLimit = one("limit", 20);
    if (rawLimit && !/^[1-9]\d*$/.test(rawLimit)) {
      throw new HttpError(400, "invalid_limit", "limit must be a positive integer");
    }
    const limit = rawLimit ? Number(rawLimit) : DEFAULT_OPERATION_LIMIT;
    if (!Number.isSafeInteger(limit) || limit > MAX_OPERATION_LIMIT) {
      throw new HttpError(400, "invalid_limit", `limit must not exceed ${MAX_OPERATION_LIMIT}`);
    }
    const status = one("status", 32);
    if (status && !BREAK_GLASS_STATUSES.includes(status)) {
      throw new HttpError(400, "invalid_break_glass_filter", "status is not supported");
    }
    const action = one("action", 128);
    if (action) approvalActionDefinition(action);
    return {
      status,
      action,
      incidentId: one("incidentId", 128),
      requesterSubjectId: one("requesterSubjectId", 128),
      targetId: one("targetId", 128),
      limit,
    };
  }

  async function listBreakGlassGrants(req, res, searchParams) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    const result = await requirePermission(current.session, "breakglass.review");
    const query = breakGlassQuery(searchParams);
    const now = breakGlassNow().getTime();
    const grants = await store.read((data) => Object.values(data.breakGlassGrants)
      .filter((grant) => {
        if (query.action && grant.action !== query.action) return false;
        if (query.incidentId && grant.incidentId !== query.incidentId) return false;
        if (query.requesterSubjectId
            && grant.requesterSubjectId !== query.requesterSubjectId) return false;
        if (query.targetId && grant.targetId !== query.targetId) return false;
        if (!organizationScopeAllows(result.access, grant.targetOrgUnitId)) return false;
        const review = Object.values(data.breakGlassReviews)
          .find((candidate) => candidate.grantId === grant.id) || null;
        if (query.status
            && projectedBreakGlassStatus(grant, review, now) !== query.status) return false;
        return true;
      })
      .sort((left, right) => String(right.createdAt || "")
        .localeCompare(String(left.createdAt || ""))
        || String(right.id || "").localeCompare(String(left.id || "")))
      .slice(0, query.limit)
      .map((grant) => publicBreakGlassGrant(
        structuredClone(grant),
        Object.values(data.breakGlassReviews)
          .find((candidate) => candidate.grantId === grant.id) || null,
        now,
      )));
    json(res, 200, { grants });
  }

  async function getBreakGlassGrant(req, res, breakGlassId) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    const found = await store.read((data) => {
      const grant = data.breakGlassGrants[breakGlassId];
      if (!grant) return null;
      return {
        grant: structuredClone(grant),
        review: Object.values(data.breakGlassReviews)
          .find((candidate) => candidate.grantId === breakGlassId) || null,
      };
    });
    if (!found) throw new HttpError(404, "break_glass_invalid", "Break-glass grant not found");
    await requirePermission(current.session, "breakglass.review", found.grant.targetOrgUnitId);
    json(res, 200, {
      grant: publicBreakGlassGrant(
        found.grant,
        found.review,
        breakGlassNow().getTime(),
      ),
    });
  }

  async function createBreakGlassGrant(req, res) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const action = String(body.action || "").trim();
    approvalActionDefinition(action);
    if (!approvalRequiredForAction(action)) {
      throw new HttpError(
        400,
        "break_glass_not_required",
        "This action does not require break-glass authorization",
      );
    }
    const incidentId = cleanIdentifier(body.incidentId, "incidentId", "incident_required");
    const reason = cleanReason(body.reason);
    const payload = approvalBusinessPayload(action, body);
    let targetId;
    if (action === "usage.export.create" || action === "audit.export.create") {
      targetId = exportTargetId(action, payload);
      if (body.targetId != null && String(body.targetId).trim()) {
        const suppliedTargetId = cleanIdentifier(body.targetId, "targetId", "invalid_request");
        if (suppliedTargetId !== targetId) {
          throw new HttpError(
            400,
            "invalid_export_target",
            "targetId does not match the export query",
          );
        }
      }
    } else {
      targetId = cleanIdentifier(body.targetId, "targetId", "invalid_request");
    }
    const target = await resolveApprovalTarget(current.session, action, targetId, payload);
    await requirePermission(current.session, "breakglass.request", target.targetOrgUnitId);
    await requireStepUp(current, req, action, "C");
    const expected = breakGlassExpectedBinding({
      environmentId: approvalEnvironmentId,
      policyVersion: BREAK_GLASS_POLICY_VERSION,
      requesterSubjectId: current.session.subjectId,
      action,
      targetType: target.targetType,
      targetId: target.targetId,
      targetOrgUnitId: target.targetOrgUnitId,
      riskLevel: riskForAction(action),
      reason,
      payload,
    });
    const now = breakGlassNow();
    if (!Number.isFinite(now.getTime())) {
      throw new HttpError(503, "storage_unavailable", "Break-glass clock is invalid");
    }
    const createdAt = now.toISOString();
    const grant = {
      id: `bgr_${crypto.randomUUID()}`,
      requesterSubjectId: current.session.subjectId,
      requesterEmail: current.session.email,
      action,
      targetType: target.targetType,
      targetId: target.targetId,
      targetOrgUnitId: target.targetOrgUnitId,
      riskLevel: riskForAction(action),
      environmentId: approvalEnvironmentId,
      policyVersion: BREAK_GLASS_POLICY_VERSION,
      incidentId,
      reason,
      payloadDigest: expected.payloadDigest,
      bindingDigest: expected.bindingDigest,
      payloadSummary: expected.payload,
      createdAt,
      updatedAt: createdAt,
      expiresAt: new Date(now.getTime() + BREAK_GLASS_GRANT_TTL_MS).toISOString(),
      consumedAt: "",
      consumedBySubjectId: "",
      operationId: "",
      reviewDueAt: "",
      reviewOverdueAt: "",
      reviewedAt: "",
      notificationEventIds: {
        used: "",
        reviewDue: "",
        reviewOverdue: "",
        reviewed: "",
      },
      stateHistory: [{
        status: "active",
        at: createdAt,
        actorSubjectId: current.session.subjectId,
        reason: "break-glass requested",
      }],
    };
    await store.mutate((data) => {
      data.breakGlassGrants[grant.id] = structuredClone(grant);
      appendBreakGlassSystemAudit(data, "break_glass.requested", grant, {
        timestamp: createdAt,
        result: "requested",
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        reason,
      });
    });
    json(res, 201, {
      grant: publicBreakGlassGrant(grant, null, now.getTime()),
    });
  }

  async function reviewBreakGlassGrant(req, res, breakGlassId) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const conclusion = String(body.conclusion || "").trim();
    if (!BREAK_GLASS_REVIEW_CONCLUSIONS.includes(conclusion)) {
      throw new HttpError(
        400,
        "invalid_break_glass_review",
        "conclusion must be justified or not_justified",
      );
    }
    const reason = cleanReason(body.reason);
    const idempotencyKey = validateRequiredIdempotencyKey(req);
    const storedGrant = await store.read((data) => {
      const grant = data.breakGlassGrants[breakGlassId];
      return grant ? structuredClone(grant) : null;
    });
    if (!storedGrant) throw new HttpError(404, "break_glass_invalid", "Break-glass grant not found");
    await requirePermission(current.session, "breakglass.review", storedGrant.targetOrgUnitId);
    if (storedGrant.requesterSubjectId === current.session.subjectId) {
      throw new HttpError(
        403,
        "break_glass_separation_required",
        "The requester cannot review their own break-glass use",
      );
    }
    await requireStepUp(current, req, "break_glass.review", "C");
    const idempotencyKeyHash = sha256(`${current.session.subjectId}\u0000${idempotencyKey}`);
    const requestFingerprint = sha256(JSON.stringify(canonicalValue({
      grantId: breakGlassId,
      conclusion,
      reason,
    })));
    const now = breakGlassNow();
    if (!Number.isFinite(now.getTime())) {
      throw new HttpError(503, "storage_unavailable", "Break-glass clock is invalid");
    }
    const outcome = await store.mutate((data) => {
      const existingRequest = data.breakGlassReviewRequests[idempotencyKeyHash];
      if (existingRequest) {
        if (existingRequest.requestFingerprint !== requestFingerprint) {
          throw new HttpError(
            409,
            "break_glass_review_conflict",
            "Idempotency-Key was already used for a different break-glass review",
          );
        }
        const existingReview = data.breakGlassReviews[existingRequest.reviewId];
        if (!existingReview) {
          throw new HttpError(
            503,
            "storage_unavailable",
            "The break-glass review record is unavailable",
          );
        }
        return {
          replayed: true,
          grant: structuredClone(data.breakGlassGrants[existingRequest.grantId]),
          review: structuredClone(existingReview),
        };
      }
      const grant = data.breakGlassGrants[breakGlassId];
      if (!grant) throw new HttpError(404, "break_glass_invalid", "Break-glass grant not found");
      if (grant.requesterSubjectId === current.session.subjectId) {
        throw new HttpError(
          403,
          "break_glass_separation_required",
          "The requester cannot review their own break-glass use",
        );
      }
      if (!grant.consumedAt) {
        throw new HttpError(
          409,
          "break_glass_review_unavailable",
          "Break-glass review requires a consumed grant",
        );
      }
      if (Object.values(data.breakGlassReviews)
        .some((candidate) => candidate.grantId === breakGlassId)) {
        throw new HttpError(
          409,
          "break_glass_review_exists",
          "This break-glass grant was already reviewed",
        );
      }
      const reviewedAt = now.toISOString();
      const review = {
        id: `bgrv_${crypto.randomUUID()}`,
        grantId: breakGlassId,
        reviewerSubjectId: current.session.subjectId,
        reviewerEmail: current.session.email,
        conclusion,
        reason,
        reviewedAt,
        notificationEventId: "",
      };
      data.breakGlassReviews[review.id] = review;
      data.breakGlassReviewRequests[idempotencyKeyHash] = {
        requestHash: idempotencyKeyHash,
        requestFingerprint,
        grantId: breakGlassId,
        reviewId: review.id,
        createdAt: reviewedAt,
      };
      grant.reviewedAt = reviewedAt;
      grant.updatedAt = reviewedAt;
      grant.stateHistory.push({
        status: "reviewed",
        at: reviewedAt,
        actorSubjectId: current.session.subjectId,
        reason: conclusion,
      });
      notificationOutbox.enqueueBreakGlass(data, "reviewed", grant, {
        occurredAt: reviewedAt,
        eventKey: review.id,
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        organizationId: approvalEnvironmentId,
      });
      review.notificationEventId = grant.notificationEventIds.reviewed;
      appendBreakGlassSystemAudit(data, "break_glass.reviewed", grant, {
        timestamp: reviewedAt,
        result: conclusion,
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        reason,
      });
      return {
        replayed: false,
        grant: structuredClone(grant),
        review: structuredClone(review),
      };
    });
    json(res, outcome.replayed ? 200 : 201, {
      replayed: outcome.replayed,
      grant: publicBreakGlassGrant(outcome.grant, outcome.review, now.getTime()),
    });
  }

  function approvalQuery(searchParams) {
    const one = (name, maxLength = 256) => {
      const value = String(searchParams.get(name) || "").trim();
      if ([...value].length > maxLength || /[\u0000-\u001f\u007f]/.test(value)) {
        throw new HttpError(400, "invalid_approval_filter", `${name} is invalid`);
      }
      return value;
    };
    const rawLimit = one("limit", 20);
    if (rawLimit && !/^[1-9]\d*$/.test(rawLimit)) {
      throw new HttpError(400, "invalid_limit", "limit must be a positive integer");
    }
    const limit = rawLimit ? Number(rawLimit) : DEFAULT_OPERATION_LIMIT;
    if (!Number.isSafeInteger(limit) || limit > MAX_OPERATION_LIMIT) {
      throw new HttpError(400, "invalid_limit", `limit must not exceed ${MAX_OPERATION_LIMIT}`);
    }
    const status = one("status", 64);
    if (status && !APPROVAL_STATUSES.includes(status)) {
      throw new HttpError(400, "invalid_approval_filter", "status is not supported");
    }
    const action = one("action", 128);
    if (action) approvalActionDefinition(action);
    const targetType = one("targetType", 32);
    if (targetType
        && !["user", "device", "credential", "operation", "export"].includes(targetType)) {
      throw new HttpError(400, "invalid_approval_filter", "targetType is not supported");
    }
    return {
      status,
      action,
      targetType,
      requesterSubjectId: one("requesterSubjectId", 128),
      limit,
    };
  }

  async function listApprovals(req, res, searchParams) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    const result = await requirePermission(current.session, "approvals.read");
    const query = approvalQuery(searchParams);
    const approvals = await store.read((data) => Object.values(data.approvalRequests)
      .filter((approval) => {
        if (query.status && approval.status !== query.status) return false;
        if (query.action && approval.action !== query.action) return false;
        if (query.targetType && approval.targetType !== query.targetType) return false;
        if (query.requesterSubjectId
            && approval.requesterSubjectId !== query.requesterSubjectId) return false;
        return organizationScopeAllows(result.access, approval.targetOrgUnitId);
      })
      .sort((left, right) => String(right.createdAt || "")
        .localeCompare(String(left.createdAt || ""))
        || String(right.id || "").localeCompare(String(left.id || "")))
      .slice(0, query.limit)
      .map((approval) => publicApproval(
        structuredClone(approval),
        structuredClone(approvalDecisionList(data, approval.id)),
      )));
    json(res, 200, { approvals });
  }

  function approvalInboxQuery(searchParams) {
    const view = String(searchParams.get("view") || "pending").trim();
    if (!["pending", "requested", "completed", "closed"].includes(view)) {
      throw new HttpError(400, "invalid_approval_filter", "view is not supported");
    }
    const base = approvalQuery(searchParams);
    return { ...base, view };
  }

  async function listApprovalInbox(req, res, searchParams) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    const result = await requirePermission(current.session, "approvals.read");
    const query = approvalInboxQuery(searchParams);
    const approvals = await store.read((data) => Object.values(data.approvalRequests)
      .filter((approval) => {
        if (!organizationScopeAllows(result.access, approval.targetOrgUnitId)) return false;
        if (query.status && approval.status !== query.status) return false;
        if (query.action && approval.action !== query.action) return false;
        if (query.targetType && approval.targetType !== query.targetType) return false;
        if (query.requesterSubjectId
            && approval.requesterSubjectId !== query.requesterSubjectId) return false;
        if (query.view === "requested") {
          return approval.requesterSubjectId === current.session.subjectId;
        }
        if (query.view === "completed") {
          return ["approved", "reserved", "consumed"].includes(approval.status);
        }
        if (query.view === "closed") {
          return ["rejected", "expired", "revoked", "withdrawn"].includes(approval.status)
            || (approval.status !== "approved"
              && approval.status !== "reserved"
              && approval.status !== "consumed"
              && approvalIsExpired(approval));
        }
        if (!["requested", "pending_approval"].includes(approval.status)
            || approvalIsExpired(approval)
            || approval.requesterSubjectId === current.session.subjectId) {
          return false;
        }
        ensureApprovalWorkflow(approval);
        const definition = approvalActionDefinition(approval.action);
        return approval.steps
          .filter((step) => step.status === "in_progress")
          .some((step) => (
            !approvalStepActorFailure(
              data,
              approval,
              step,
              current.session.subjectId,
              definition.permission,
            )
          ));
      })
      .sort((left, right) => String(right.createdAt || "")
        .localeCompare(String(left.createdAt || ""))
        || String(right.id || "").localeCompare(String(left.id || "")))
      .slice(0, query.limit)
      .map((approval) => publicApproval(
        structuredClone(approval),
        structuredClone(approvalDecisionList(data, approval.id)),
      )));
    json(res, 200, { view: query.view, approvals });
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
    const requestedStepId = approvalStepIdInput(body.stepId);
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
    if (storedApproval.status === "withdrawn") {
      throw approvalHttpError("approval_withdrawn", "Approval was withdrawn");
    }
    if (storedApproval.status === "revoked") {
      throw approvalHttpError("approval_revoked", "Approval was revoked");
    }
    if (storedApproval.status === "reserved" || storedApproval.status === "consumed") {
      throw approvalHttpError("approval_consumed", "Approval was already consumed");
    }
    const selected = approvalDecisionStep(storedApproval, requestedStepId);
    if (selected.error) throw selected.error;
    const earlyStepFailure = approvalStepActorFailure(
      await store.read((data) => data),
      storedApproval,
      selected.step,
      current.session.subjectId,
      definition.permission,
    );
    if (earlyStepFailure === "approval_step_ineligible") {
      throw approvalHttpError(
        "approval_step_ineligible",
        "Your account is not eligible to decide this approval step",
      );
    }
    if (earlyStepFailure) {
      throw new HttpError(403, earlyStepFailure, "This approval step is outside your authority");
    }
    await requireStepUp(current, req, storedApproval.action);

    const outcome = await store.mutate((data) => {
      const approval = data.approvalRequests[approvalId];
      if (!approval) {
        return { error: approvalHttpError("approval_invalid", "Approval is not available") };
      }
      if (approval.environmentId !== approvalEnvironmentId) {
        return { error: approvalHttpError("approval_invalid", "Approval is not valid here") };
      }
      if (approval.status === "withdrawn") {
        return { error: approvalHttpError("approval_withdrawn", "Approval was withdrawn") };
      }
      if (approval.status === "revoked") {
        return { error: approvalHttpError("approval_revoked", "Approval was revoked") };
      }
      if (approval.status === "reserved" || approval.status === "consumed"
          || data.approvalConsumptions[approval.id]) {
        return { error: approvalHttpError("approval_consumed", "Approval was already consumed") };
      }
      if (approvalIsExpired(approval)) {
        ensureApprovalWorkflow(approval);
        cancelUnfinishedApprovalSteps(approval);
        transitionApproval(approval, "expired", "system_expiry", "approval expired");
        appendApprovalSystemAudit(data, "approval.expired", approval, {
          result: "expired",
          errorCode: "approval_expired",
        });
        return { error: approvalHttpError("approval_expired", "Approval has expired") };
      }
      if (!["requested", "pending_approval"].includes(approval.status)) {
        return {
          error: approvalHttpError(
            "approval_unavailable",
            "Approval is not awaiting a decision",
          ),
        };
      }
      if (approval.requesterSubjectId === current.session.subjectId) {
        return {
          error: approvalHttpError(
            "approval_separation_required",
            "The requester cannot decide their own approval",
          ),
        };
      }
      const stepDecision = approvalDecisionStep(approval, requestedStepId);
      if (stepDecision.error) return { error: stepDecision.error };
      const stepFailure = approvalStepActorFailure(
        data,
        approval,
        stepDecision.step,
        current.session.subjectId,
        definition.permission,
      );
      if (stepFailure === "approval_step_ineligible") {
        return {
          error: approvalHttpError(
            "approval_step_ineligible",
            "Your account is not eligible to decide this approval step",
          ),
        };
      }
      if (stepFailure) {
        return {
          error: new HttpError(403, stepFailure, "This approval step is outside your authority"),
        };
      }
      const createdAt = new Date().toISOString();
      const result = recordApprovalDecision(data, approval, {
        decision,
        step: stepDecision.step,
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        reason,
        createdAt,
        source: "admin",
      });
      approval.decisionSource = "admin";
      const auditAction = decision === "reject"
        ? "approval.rejected"
        : (result.workflowCompleted ? "approval.approved" : "approval.step_progressed");
      appendApprovalSystemAudit(
        data,
        auditAction,
        approval,
        {
          result: decision === "reject"
            ? "rejected"
            : (result.workflowCompleted ? "approved" : "step_progressed"),
          actorSubjectId: current.session.subjectId,
          actorEmail: current.session.email,
          reason,
          eventKey: `${stepDecision.step.stepId}_${result.record.id}`,
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
      if (approval.environmentId !== approvalEnvironmentId) {
        return { error: approvalHttpError("approval_invalid", "Approval is not valid here") };
      }
      if (approvalIsExpired(approval)) {
        if (["requested", "pending_approval", "approved"].includes(approval.status)) {
          ensureApprovalWorkflow(approval);
          cancelUnfinishedApprovalSteps(approval);
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
        if (approval.status === "withdrawn") {
          return { error: approvalHttpError("approval_withdrawn", "Approval was withdrawn") };
        }
        return {
          error: approvalHttpError(
            "approval_unavailable",
            "Approval cannot be revoked in its current state",
          ),
        };
      }
      const revokedAt = new Date().toISOString();
      ensureApprovalWorkflow(approval);
      cancelUnfinishedApprovalSteps(approval);
      transitionApproval(approval, "revoked", current.session.subjectId, "revoked");
      approval.revokedAt = revokedAt;
      approval.revokedBySubjectId = current.session.subjectId;
      approval.revokedByEmail = current.session.email;
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

  async function withdrawApproval(req, res, approvalId) {
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
    if (storedApproval.requesterSubjectId !== current.session.subjectId) {
      throw new HttpError(
        403,
        "forbidden_role",
        "Only the requester can withdraw this approval",
      );
    }
    const outcome = await store.mutate((data) => {
      const approval = data.approvalRequests[approvalId];
      if (!approval) {
        return { error: approvalHttpError("approval_invalid", "Approval is not available") };
      }
      if (approval.environmentId !== approvalEnvironmentId
          || approval.requesterSubjectId !== current.session.subjectId) {
        return { error: approvalHttpError("approval_invalid", "Approval is not valid here") };
      }
      if (approval.status === "withdrawn") {
        return { error: approvalHttpError("approval_withdrawn", "Approval was withdrawn") };
      }
      if (approval.status === "revoked") {
        return { error: approvalHttpError("approval_revoked", "Approval was revoked") };
      }
      if (approval.status === "reserved" || approval.status === "consumed"
          || data.approvalConsumptions[approval.id]) {
        return { error: approvalHttpError("approval_consumed", "Approval was already consumed") };
      }
      if (approvalIsExpired(approval)) {
        ensureApprovalWorkflow(approval);
        cancelUnfinishedApprovalSteps(approval);
        transitionApproval(approval, "expired", "system_expiry", "approval expired");
        appendApprovalSystemAudit(data, "approval.expired", approval, {
          result: "expired",
          errorCode: "approval_expired",
        });
        return { error: approvalHttpError("approval_expired", "Approval has expired") };
      }
      if (!["requested", "pending_approval"].includes(approval.status)) {
        return {
          error: approvalHttpError(
            "approval_unavailable",
            "Approval cannot be withdrawn in its current state",
          ),
        };
      }
      const withdrawnAt = new Date().toISOString();
      ensureApprovalWorkflow(approval);
      cancelUnfinishedApprovalSteps(approval);
      transitionApproval(approval, "withdrawn", current.session.subjectId, "withdrawn");
      approval.withdrawnAt = withdrawnAt;
      approval.withdrawnBySubjectId = current.session.subjectId;
      appendApprovalSystemAudit(data, "approval.withdrawn", approval, {
        result: "withdrawn",
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

  async function transferApprovalStep(req, res, approvalId, stepId) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const reason = cleanReason(body.reason);
    const targetSubjectId = approvalWorkflowSubjectIds(
      [body.toSubjectId],
      "toSubjectId",
    )[0];
    if (!targetSubjectId) {
      throw new HttpError(400, "invalid_approval_step", "toSubjectId is required");
    }
    const requestedStepId = approvalStepIdInput(stepId);
    const storedApproval = await store.read((data) => {
      const approval = data.approvalRequests[approvalId];
      return approval ? structuredClone(approval) : null;
    });
    if (!storedApproval) throw new HttpError(404, "approval_not_found", "Approval not found");
    const storedStep = approvalStepById(storedApproval, requestedStepId);
    if (!storedStep || storedStep.status !== "in_progress") {
      throw approvalHttpError(
        "approval_step_unavailable",
        "The requested approval step is not awaiting a decision",
      );
    }
    const outcome = await store.mutate((data) => {
      const approval = data.approvalRequests[approvalId];
      if (!approval) {
        return { error: approvalHttpError("approval_invalid", "Approval is not available") };
      }
      if (approval.environmentId !== approvalEnvironmentId) {
        return { error: approvalHttpError("approval_invalid", "Approval is not valid here") };
      }
      if (approvalIsExpired(approval)) {
        ensureApprovalWorkflow(approval);
        cancelUnfinishedApprovalSteps(approval);
        transitionApproval(approval, "expired", "system_expiry", "approval expired");
        appendApprovalSystemAudit(data, "approval.expired", approval, {
          result: "expired",
          errorCode: "approval_expired",
        });
        return { error: approvalHttpError("approval_expired", "Approval has expired") };
      }
      if (!["requested", "pending_approval"].includes(approval.status)) {
        if (approval.status === "withdrawn") {
          return { error: approvalHttpError("approval_withdrawn", "Approval was withdrawn") };
        }
        if (approval.status === "revoked") {
          return { error: approvalHttpError("approval_revoked", "Approval was revoked") };
        }
        if (approval.status === "reserved" || approval.status === "consumed") {
          return { error: approvalHttpError("approval_consumed", "Approval was consumed") };
        }
        return {
          error: approvalHttpError(
            "approval_unavailable",
            "Approval cannot be transferred in its current state",
          ),
        };
      }
      if (approval.requesterSubjectId === current.session.subjectId) {
        return {
          error: approvalHttpError(
            "approval_separation_required",
            "The requester cannot transfer an approval step",
          ),
        };
      }
      const step = approvalStepById(approval, requestedStepId);
      if (!step || step.status !== "in_progress") {
        return {
          error: approvalHttpError(
            "approval_step_unavailable",
            "The requested approval step is not awaiting a decision",
          ),
        };
      }
      const definition = approvalActionDefinition(approval.action);
      const actorFailure = approvalStepActorFailure(
        data,
        approval,
        step,
        current.session.subjectId,
        definition.permission,
      );
      if (actorFailure) {
        return {
          error: actorFailure === "approval_step_ineligible"
            ? approvalHttpError(
              "approval_step_ineligible",
              "Your account cannot transfer this approval step",
            )
            : new HttpError(403, actorFailure, "This approval step is outside your authority"),
        };
      }
      if (targetSubjectId === current.session.subjectId) {
        return {
          error: new HttpError(
            400,
            "invalid_approval_step",
            "The target approver must be a different administrator",
          ),
        };
      }
      if (targetSubjectId === approval.requesterSubjectId) {
        return {
          error: approvalHttpError(
            "approval_separation_required",
            "The requester cannot be an approver",
          ),
        };
      }
      if (step.decidedBySubjectIds.includes(targetSubjectId)) {
        return {
          error: approvalHttpError(
            "approval_step_ineligible",
            "The target approver already decided this step",
          ),
        };
      }
      const targetAccess = effectiveAccess(data, targetSubjectId);
      if (step.eligibleRoles.length > 0
          && !step.eligibleRoles.some((role) => targetAccess.roles.includes(role))) {
        return {
          error: approvalHttpError(
            "approval_step_ineligible",
            "The target approver does not hold an eligible role",
          ),
        };
      }
      const targetFailure = approvalActorFailure(
        data,
        approval,
        targetSubjectId,
        definition.permission,
      );
      if (targetFailure) {
        return {
          error: new HttpError(
            403,
            targetFailure,
            "The target approver lacks decision permission or organization scope",
          ),
        };
      }
      const transferredAt = new Date().toISOString();
      step.eligibleSubjectIds = [
        ...new Set([
          ...step.eligibleSubjectIds.filter((subjectId) => subjectId !== current.session.subjectId),
          targetSubjectId,
        ]),
      ].sort();
      step.ineligibleSubjectIds = [
        ...new Set([
          ...step.ineligibleSubjectIds.filter((subjectId) => subjectId !== targetSubjectId),
          current.session.subjectId,
        ]),
      ].sort();
      step.transferHistory.push({
        fromSubjectId: current.session.subjectId,
        toSubjectId: targetSubjectId,
        actorSubjectId: current.session.subjectId,
        reason,
        at: transferredAt,
      });
      approval.updatedAt = transferredAt;
      appendApprovalSystemAudit(data, "approval.transferred", approval, {
        result: "transferred",
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        reason,
        eventKey: `${step.stepId}_${step.transferHistory.length}`,
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
        if (session) {
          delete data.adminSessions[sidHash];
          delete data.stepUpAssertions[sidHash];
        }
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

  async function stepUpState(current, req) {
    const { sidHash, session } = current;
    if (!config.stepUpOidc || !stepUpOidc) {
      return {
        configured: false,
        state: "unavailable",
        authenticated: false,
        criticalAuthenticated: false,
      };
    }
    return store.read((data) => {
      const assertion = data.stepUpAssertions[sidHash];
      const access = effectiveAccess(data, session.subjectId);
      const now = Date.now();
      const base = {
        configured: true,
        authenticated: false,
        criticalAuthenticated: false,
        state: "required",
      };
      if (!assertion) return base;
      const publicFields = {
        verifiedAt: assertion.verifiedAt,
        expiresAt: assertion.expiresAt,
        criticalExpiresAt: assertion.criticalExpiresAt,
        acr: assertion.acr,
        amr: [...assertion.amr],
        authTime: assertion.authTime,
      };
      if (assertion.sessionHash !== sidHash
          || assertion.subjectId !== session.subjectId
          || assertion.ip !== clientIp(req)
          || assertion.userAgentHash !== userAgentHash(req)
          || assertion.accessDigest !== accessDigest(access)) {
        return { ...base, ...publicFields, state: "binding_mismatch" };
      }
      if (!Number.isFinite(Date.parse(assertion.expiresAt))
          || Date.parse(assertion.expiresAt) <= now) {
        return { ...base, ...publicFields, state: "expired" };
      }
      const criticalValid = Number.isFinite(Date.parse(assertion.criticalExpiresAt))
        && Date.parse(assertion.criticalExpiresAt) > now;
      return {
        ...base,
        ...publicFields,
        state: criticalValid ? "verified" : "critical_expired",
        authenticated: true,
        criticalAuthenticated: criticalValid,
      };
    });
  }

  async function requireStepUp(current, req, action, riskOverride = "") {
    const { sidHash, session } = current;
    const risk = riskOverride || riskForAction(action);
    if (!["H", "C"].includes(risk)) return null;
    if (!config.stepUpOidc || !stepUpOidc) {
      throw new HttpError(
        503,
        "step_up_unavailable",
        "Step-up authentication is not configured",
      );
    }
    const result = await store.read((data) => {
      const assertion = data.stepUpAssertions[sidHash];
      const access = effectiveAccess(data, session.subjectId);
      if (!assertion) return { code: "step_up_required" };
      if (assertion.sessionHash !== sidHash
          || assertion.subjectId !== session.subjectId
          || assertion.ip !== clientIp(req)
          || assertion.userAgentHash !== userAgentHash(req)
          || assertion.accessDigest !== accessDigest(access)) {
        return { code: "step_up_binding_mismatch" };
      }
      const expiry = risk === "C" ? assertion.criticalExpiresAt : assertion.expiresAt;
      if (!Number.isFinite(Date.parse(expiry || "")) || Date.parse(expiry) <= Date.now()) {
        return { code: "step_up_expired" };
      }
      return {
        assertion: {
          authTime: assertion.authTime,
          acr: assertion.acr,
          amr: [...assertion.amr],
          expiresAt: assertion.expiresAt,
          criticalExpiresAt: assertion.criticalExpiresAt,
        },
      };
    });
    if (result.code) {
      const messages = {
        step_up_required: "Re-authenticate before this high-risk action",
        step_up_expired: "Your recent authentication has expired",
        step_up_binding_mismatch: "Your session, role, scope, IP, or browser changed",
      };
      throw new HttpError(403, result.code, messages[result.code]);
    }
    return result.assertion;
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
    const reconciliationState = explicitReconciliationState(value)
      || (operationRequiresReconciliation(value) ? "pending" : "not_required");
    return {
      operationId: String(value.id || ""),
      action: String(value.action || ""),
      targetType: String(value.targetType || ""),
      targetId: String(value.targetId || ""),
      targetOrgUnitId: String(value.targetOrgUnitId || ""),
      actorSubjectId: String(value.actorSubjectId || ""),
      actorEmail: String(value.actorEmail || ""),
      reason: String(value.reason || ""),
      approvalId: String(value.approvalId || ""),
      breakGlassId: String(value.breakGlassId || ""),
      status: String(value.status || "unknown"),
      state: String(result?.state || value.status || "unknown"),
      createdAt: String(value.createdAt || ""),
      updatedAt: String(value.updatedAt || ""),
      completedAt: String(value.completedAt || ""),
      errorCode: String(value.errorCode || ""),
      retryable: operationRetryable(value),
      requiresReconciliation: Boolean(result?.requiresReconciliation),
      reconciliationState,
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
      targetOrgUnitId: String(operation.targetOrgUnitId || ""),
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
      approvalId: String(operation.approvalId || ""),
      breakGlassId: String(operation.breakGlassId || ""),
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

  function operationSnapshotOrgUnitId(operation) {
    const targetOrgUnitId = String(operation?.targetOrgUnitId || "");
    if (targetOrgUnitId) return targetOrgUnitId;
    const scopes = safeStringList(operation?.scopeOrgUnitIds);
    return scopes.length === 1 && scopes[0] !== "*" ? scopes[0] : "";
  }

  function historicalScopeAllows(data, access, targetOrgUnitId, scopeOrgUnitIds) {
    const scopes = safeStringList(scopeOrgUnitIds);
    if (targetOrgUnitId) {
      return targetOrgUnitId === "*"
        ? access.scopeOrgUnitIds.includes("*")
        : access.scopeOrgUnitIds.includes("*")
          || access.scopeOrgUnitIds.includes(targetOrgUnitId);
    }
    if (scopes.includes("*")) return access.scopeOrgUnitIds.includes("*");
    return scopes.some((scope) => access.scopeOrgUnitIds.includes("*")
      || access.scopeOrgUnitIds.includes(scope));
  }

  function operationHistoryOrgUnitId(data, maps, operation) {
    const snapshot = operationSnapshotOrgUnitId(operation);
    if (snapshot) return snapshot;
    const userId = targetUserId(maps, operation.targetType, operation.targetId);
    if (userId) {
      const current = activeUserOrgUnit(data, userId);
      if (current) return current;
    }
    const scopes = safeStringList(operation.scopeOrgUnitIds);
    return scopes.includes("*") ? "*" : (scopes.length === 1 ? scopes[0] : "");
  }

  async function operationReadContext(session, operation) {
    const permission = OPERATION_PERMISSIONS[operation.action];
    if (!permission) {
      throw new HttpError(
        409,
        "operation_action_unsupported",
        "The operation action is not supported",
      );
    }
    const result = await requirePermission(session, permission);
    const maps = await auditTargetMaps();
    const targetOrgUnitId = operationHistoryOrgUnitId(result.data, maps, operation);
    if (!historicalScopeAllows(
      result.data,
      result.access,
      targetOrgUnitId,
      operation.scopeOrgUnitIds,
    )) {
      throw new HttpError(
        403,
        "forbidden_scope",
        "This operation is outside your organization history scope",
      );
    }
    return result;
  }

  function operationQuery(searchParams) {
    const one = (name, maxLength = 256) => {
      const value = String(searchParams.get(name) || "").trim();
      if ([...value].length > maxLength || /[\u0000-\u001f\u007f]/.test(value)) {
        throw new HttpError(400, "invalid_operation_filter", `${name} is invalid`);
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
    const limit = rawLimit ? Number(rawLimit) : DEFAULT_OPERATION_LIMIT;
    if (!Number.isSafeInteger(limit) || limit > MAX_OPERATION_LIMIT) {
      throw new HttpError(400, "invalid_limit", `limit must not exceed ${MAX_OPERATION_LIMIT}`);
    }
    const from = timestamp("from");
    const to = timestamp("to");
    if (from && to && Date.parse(from) > Date.parse(to)) {
      throw new HttpError(400, "invalid_time_range", "from must not be after to");
    }
    const targetType = one("targetType", 32);
    if (targetType
        && !["user", "device", "credential", "operation", "export"].includes(targetType)) {
      throw new HttpError(400, "invalid_operation_filter", "targetType is not supported");
    }
    const normalized = {
      operationId: one("operationId", 128),
      actorSubjectId: one("actorSubjectId", 128),
      action: one("action", 128),
      targetType,
      targetId: one("targetId", 128),
      status: one("status", 64),
      from,
      to,
      limit,
    };
    return {
      ...normalized,
      cursor: one("cursor", MAX_OPERATION_CURSOR),
      queryHash: sha256(JSON.stringify(canonicalValue(normalized))),
    };
  }

  function operationCursorSignature(payload) {
    return crypto.createHmac("sha256", config.sessionSecret)
      .update(payload)
      .digest("base64url");
  }

  function encodeOperationCursor(query, session, operation) {
    const payload = Buffer.from(JSON.stringify({
      v: 1,
      sub: session.subjectId,
      qh: query.queryHash,
      t: String(operation.createdAt || ""),
      id: String(operation.id || ""),
    })).toString("base64url");
    return `${payload}.${operationCursorSignature(payload)}`;
  }

  function decodeOperationCursor(cursor, query, session) {
    if (!cursor) return null;
    const parts = cursor.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      throw new HttpError(400, "invalid_cursor", "cursor is invalid");
    }
    if (!safeEqual(parts[1], operationCursorSignature(parts[0]))) {
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
    return { time, createdAt: new Date(time).toISOString(), id: parsed.id };
  }

  function compareOperations(left, right) {
    const timeOrder = String(right.createdAt || "").localeCompare(String(left.createdAt || ""));
    if (timeOrder !== 0) return timeOrder;
    return String(right.id || "").localeCompare(String(left.id || ""));
  }

  async function operationPage(session, searchParams) {
    const query = operationQuery(searchParams);
    const cursor = decodeOperationCursor(query.cursor, query, session);
    const maps = await auditTargetMaps();
    const visible = await store.read((data) => {
      const access = effectiveAccess(data, session.subjectId);
      return Object.values(data.adminOperations)
        .filter((operation) => {
          if (query.operationId && operation.id !== query.operationId) return false;
          if (query.actorSubjectId && operation.actorSubjectId !== query.actorSubjectId) {
            return false;
          }
          if (query.action && operation.action !== query.action) return false;
          if (query.targetType && operation.targetType !== query.targetType) return false;
          if (query.targetId && operation.targetId !== query.targetId) return false;
          if (query.status && operationState(operation) !== query.status
              && operation.status !== query.status) {
            return false;
          }
          if (query.from && String(operation.createdAt || "") < query.from) return false;
          if (query.to && String(operation.createdAt || "") >= query.to) return false;
          if (cursor && (
            String(operation.createdAt || "") > cursor.createdAt
            || (String(operation.createdAt || "") === cursor.createdAt
              && String(operation.id || "") >= cursor.id)
          )) {
            return false;
          }
          const permission = OPERATION_PERMISSIONS[operation.action];
          if (!permission || !access.permissions.includes(permission)) return false;
          return historicalScopeAllows(
            data,
            access,
            operationHistoryOrgUnitId(data, maps, operation),
            operation.scopeOrgUnitIds,
          );
        })
        .map((operation) => structuredClone(operation))
        .sort(compareOperations);
    });
    const page = visible.slice(0, query.limit);
    const nextCursor = visible.length > query.limit && page.length > 0
      ? encodeOperationCursor(query, session, page[page.length - 1])
      : "";
    return {
      operations: page.map(safeOperationSummary),
      nextCursor,
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
      phase: one("phase", 32),
      orgUnitId: one("orgUnitId", 128),
      from,
      to,
      limit,
    };
    if (normalized.targetType
        && !["user", "device", "credential", "operation", "export"].includes(
          normalized.targetType,
        )) {
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

  function organizationScopeAllows(access, targetOrgUnitId) {
    if (!targetOrgUnitId) return false;
    if (targetOrgUnitId === "*") return access.scopeOrgUnitIds.includes("*");
    return access.scopeOrgUnitIds.includes("*")
      || access.scopeOrgUnitIds.includes(targetOrgUnitId);
  }

  function orgUnitWithinQuery(data, queryOrgUnitId, targetOrgUnitId) {
    if (!queryOrgUnitId || queryOrgUnitId === "*") return true;
    if (!targetOrgUnitId) return false;
    if (targetOrgUnitId === queryOrgUnitId) return true;
    const queryOrg = data.orgUnits[queryOrgUnitId];
    const targetOrg = data.orgUnits[targetOrgUnitId];
    if (!queryOrg || !targetOrg) return false;
    return String(targetOrg.path || "").startsWith(`${queryOrg.path}/`);
  }

  function auditRecordOrgUnitId(data, maps, record, fallbackOrgUnitId = "") {
    if (record.targetOrgUnitId) return String(record.targetOrgUnitId);
    const operation = data.adminOperations[record.operationId];
    if (operation) {
      const snapshot = operationHistoryOrgUnitId(data, maps, operation);
      if (snapshot) return snapshot;
    }
    const userId = targetUserId(maps, record.targetType, record.targetId);
    if (userId) {
      const current = activeUserOrgUnit(data, userId);
      if (current) return current;
    }
    return fallbackOrgUnitId;
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
      targetOrgUnitId: String(record.targetOrgUnitId || ""),
      beforeSummary: safeAuditValue(record.beforeSummary),
      afterSummary: safeAuditValue(record.afterSummary),
      result: String(record.result || ""),
      errorCode: String(record.errorCode || ""),
      sourceIp: String(record.sourceIp || ""),
      userAgentHash: String(record.userAgentHash || ""),
      reason: String(record.reason || ""),
      approvalId: String(record.approvalId || ""),
      breakGlassId: String(record.breakGlassId || ""),
      approvalAction: String(record.approvalAction || ""),
      riskLevel: String(record.riskLevel || ""),
      payloadDigest: String(record.payloadDigest || ""),
      source: String(record.source || ""),
      eventId: String(record.eventId || ""),
      externalReference: String(record.externalReference || ""),
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
      targetOrgUnitId: String(operation.targetOrgUnitId || ""),
      beforeSummary: structuredClone(operation.beforeSummary),
      afterSummary: phase === "result" ? structuredClone(options.afterSummary || {}) : {},
      result,
      errorCode: String(options.errorCode || ""),
      sourceIp: operation.sourceIp,
      userAgentHash: operation.userAgentHash,
      reason: operation.reason,
      approvalId: operation.approvalId,
      breakGlassId: operation.breakGlassId,
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

  function notificationDeliveryVisible(access, delivery) {
    const targetOrgUnitId = String(delivery?.targetOrgUnitId || "");
    if (!targetOrgUnitId) return access.scopeOrgUnitIds.includes("*");
    return access.scopeOrgUnitIds.includes("*")
      || access.scopeOrgUnitIds.includes(targetOrgUnitId);
  }

  function notificationQuery(searchParams) {
    const status = String(searchParams.get("status") || "").trim();
    if (status && !NOTIFICATION_STATUSES.includes(status)) {
      throw new HttpError(400, "invalid_notification_status", "status is not supported");
    }
    const rawLimit = String(searchParams.get("limit") || "50").trim();
    const limit = Number(rawLimit);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200) {
      throw new HttpError(400, "invalid_limit", "limit must be an integer from 1 to 200");
    }
    return { status, limit };
  }

  async function listNotificationDeliveries(session, searchParams) {
    const query = notificationQuery(searchParams);
    const result = await requirePermission(session, "notifications.read");
    const deliveries = await store.read((data) => Object.values(data.notificationDeliveries)
      .filter((delivery) => !query.status || delivery.status === query.status)
      .filter((delivery) => notificationDeliveryVisible(result.access, delivery))
      .sort((left, right) => {
        const byCreated = String(right.createdAt || "").localeCompare(String(left.createdAt || ""));
        if (byCreated !== 0) return byCreated;
        return String(right.deliveryId || "").localeCompare(String(left.deliveryId || ""));
      })
      .slice(0, query.limit)
      .map(publicNotificationDelivery));
    return {
      deliveries,
      count: deliveries.length,
      limit: query.limit,
    };
  }

  async function listNotificationDeadLetters(session, searchParams) {
    const query = notificationQuery(searchParams);
    const result = await requirePermission(session, "notifications.read");
    const deliveries = await store.read((data) => Object.values(data.notificationDeliveries)
      .filter((delivery) => delivery.status === "dead_letter")
      .filter((delivery) => notificationDeliveryVisible(result.access, delivery))
      .sort((left, right) => {
        const severityOrder = { critical: 0, warning: 1, info: 2 };
        const bySeverity = (severityOrder[left.severity] ?? 3)
          - (severityOrder[right.severity] ?? 3);
        if (bySeverity !== 0) return bySeverity;
        return String(left.createdAt || "").localeCompare(String(right.createdAt || ""));
      })
      .slice(0, query.limit)
      .map(publicNotificationDelivery));
    return {
      deadLetters: deliveries,
      count: deliveries.length,
      criticalCount: deliveries.filter((delivery) => delivery.severity === "critical").length,
      oldestCreatedAt: deliveries[0]?.createdAt || "",
      visibilityTargetSeconds: SIEM_CRITICAL_VISIBILITY_TARGET_MS / 1000,
    };
  }

  async function replayNotificationDelivery(req, res, deliveryId) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const reason = cleanReason(body.reason);
    const idempotencyKey = validateRequiredIdempotencyKey(req);
    const stored = await store.read((data) => {
      const delivery = data.notificationDeliveries[deliveryId];
      return delivery ? structuredClone(delivery) : null;
    });
    if (!stored) throw new HttpError(404, "notification_delivery_not_found", "Delivery not found");
    await requirePermission(
      current.session,
      "notifications.replay",
      stored.targetOrgUnitId,
    );
    const idempotencyKeyHash = sha256(`${current.session.subjectId}\u0000${idempotencyKey}`);
    const requestFingerprint = sha256(JSON.stringify(canonicalValue({
      deliveryId,
      reason,
    })));
    const outcome = await store.mutate((data) => {
      const existing = data.notificationReplayRequests[idempotencyKeyHash];
      if (existing) {
        const delivery = data.notificationDeliveries[existing.deliveryId];
        if (!delivery) {
          throw new HttpError(
            503,
            "storage_unavailable",
            "The notification replay record points to a missing delivery",
          );
        }
        if (existing.requestFingerprint !== requestFingerprint) {
          throw new HttpError(
            409,
            "notification_replay_conflict",
            "Idempotency-Key was already used for a different notification replay",
          );
        }
        return {
          replayed: false,
          delivery: structuredClone(delivery),
        };
      }
      const delivery = data.notificationDeliveries[deliveryId];
      if (!delivery) {
        throw new HttpError(404, "notification_delivery_not_found", "Delivery not found");
      }
      if (delivery.status !== "dead_letter") {
        throw new HttpError(
          409,
          "notification_not_dead_letter",
          "Only a dead-letter delivery can be replayed",
        );
      }
      const now = new Date().toISOString();
      delivery.status = "retry_wait";
      delivery.attemptCount = 0;
      delivery.nextAttemptAt = now;
      delivery.leaseOwner = "";
      delivery.leaseExpiresAt = "";
      delivery.lastErrorCode = "";
      delivery.deliveredAt = "";
      delivery.replayCount += 1;
      delivery.lastReplayAt = now;
      delivery.updatedAt = now;
      const replayRequestId = `ntr_${sha256(
        `${idempotencyKeyHash}\u0000${deliveryId}`,
      ).slice(0, 32)}`;
      data.notificationReplayRequests[idempotencyKeyHash] = {
        replayRequestId,
        idempotencyKeyHash,
        deliveryId,
        eventId: delivery.eventId,
        requestFingerprint,
        reason,
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        createdAt: now,
      };
      data.adminSystemAuditLogs.push({
        id: `audit_${crypto.randomUUID()}`,
        action: "notification.replay_requested",
        timestamp: now,
        deliveryId,
        eventId: delivery.eventId,
        eventType: delivery.eventType,
        targetType: delivery.targetType,
        targetId: delivery.targetId,
        targetOrgUnitId: delivery.targetOrgUnitId,
        operationId: delivery.operationId,
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        reason,
        result: "requeued",
        replayRequestId,
      });
      return {
        replayed: true,
        delivery: structuredClone(delivery),
      };
    });
    json(res, 200, {
      ok: true,
      replayed: outcome.replayed,
      delivery: publicNotificationDelivery(outcome.delivery),
    });
  }

  function requireNotificationChannels() {
    if (!config.notifications?.channels?.enabled || !notificationChannelTransport) {
      throw new HttpError(
        503,
        "notification_channels_unavailable",
        "Notification channel delivery is not configured",
      );
    }
  }

  function notificationChannelInput(body, update = false) {
    const allowed = new Set([
      "reason",
      "name",
      "type",
      "provider",
      "enabled",
      "eventTypes",
      "secretRef",
      "config",
    ]);
    const unexpected = Object.keys(body).find((key) => !allowed.has(key));
    if (unexpected) {
      throw new HttpError(
        400,
        "invalid_request",
        `Unexpected notification channel field: ${unexpected}`,
      );
    }
    const input = {};
    for (const key of allowed) {
      if (key !== "reason" && body[key] !== undefined) input[key] = body[key];
    }
    if (update && Object.keys(input).length === 0) {
      throw new HttpError(400, "invalid_request", "Notification channel update is empty");
    }
    return input;
  }

  function notificationChannelFingerprint(action, channelId, reason, payload) {
    return sha256(JSON.stringify(canonicalValue({
      action,
      channelId,
      reason,
      payload,
    })));
  }

  function normalizedChannelPayload(channel) {
    return {
      name: channel.name,
      type: channel.type,
      provider: channel.provider,
      enabled: channel.enabled,
      eventTypes: channel.eventTypes,
      secretRef: channel.secretRef,
      config: channel.config,
    };
  }

  function publicNotificationChannelTest(result) {
    if (!result) return null;
    return {
      testId: String(result.testId || ""),
      channelId: String(result.channelId || ""),
      status: String(result.status || ""),
      resultCode: String(result.resultCode || ""),
      createdAt: String(result.createdAt || ""),
    };
  }

  async function listNotificationChannels(session) {
    requireNotificationChannels();
    await requirePermission(session, "notifications.channels.read");
    return store.read((data) => {
      const testsByChannel = new Map();
      for (const result of Object.values(data.notificationChannelTests)) {
        const previous = testsByChannel.get(result.channelId);
        if (!previous || String(result.createdAt).localeCompare(String(previous.createdAt)) > 0) {
          testsByChannel.set(result.channelId, result);
        }
      }
      return Object.values(data.notificationChannels)
        .sort((left, right) => String(left.name).localeCompare(String(right.name)))
        .map((channel) => ({
          ...publicNotificationChannel(channel),
          lastTest: publicNotificationChannelTest(testsByChannel.get(channel.channelId)),
        }));
    });
  }

  async function createNotificationChannelResource(req, res) {
    requireNotificationChannels();
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const reason = cleanReason(body.reason);
    const idempotencyKey = validateRequiredIdempotencyKey(req);
    await requirePermission(current.session, "notifications.channels.write");
    await requireStepUp(current, req, "notification.channel.create", "H");
    const input = notificationChannelInput(body);
    let candidate;
    try {
      candidate = createNotificationChannel(input, {
        allowlist: config.notifications?.channels?.outboundAllowlist || [],
        emailRecipientDomains: config.notifications?.channels?.emailRecipientDomains || [],
        actorSubjectId: current.session.subjectId,
      });
    } catch (error) {
      throw new HttpError(400, "invalid_notification_channel", error.message);
    }
    const payload = normalizedChannelPayload(candidate);
    const requestFingerprint = notificationChannelFingerprint(
      "notification.channel.create",
      "",
      reason,
      payload,
    );
    const idempotencyKeyHash = sha256(`${current.session.subjectId}\u0000${idempotencyKey}`);
    const outcome = await store.mutate((data) => {
      const existing = data.notificationChannelRequests[idempotencyKeyHash];
      if (existing) {
        if (existing.requestFingerprint !== requestFingerprint) {
          throw new HttpError(
            409,
            "notification_channel_request_conflict",
            "Idempotency-Key was already used for a different notification channel request",
          );
        }
        const channel = data.notificationChannels[existing.channelId];
        if (!channel) {
          throw new HttpError(
            503,
            "storage_unavailable",
            "The notification channel request points to a missing channel",
          );
        }
        return { channel: structuredClone(channel), created: false };
      }
      if (data.notificationChannels[candidate.channelId]) {
        throw new HttpError(409, "notification_channel_conflict", "Channel already exists");
      }
      data.notificationChannels[candidate.channelId] = candidate;
      const now = candidate.createdAt;
      data.notificationChannelRequests[idempotencyKeyHash] = {
        idempotencyKeyHash,
        requestFingerprint,
        action: "notification.channel.create",
        channelId: candidate.channelId,
        status: "succeeded",
        createdAt: now,
        updatedAt: now,
      };
      data.adminSystemAuditLogs.push({
        id: `audit_${crypto.randomUUID()}`,
        action: "notification.channel.created",
        timestamp: now,
        channelId: candidate.channelId,
        channelType: candidate.type,
        provider: candidate.provider,
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        reason,
        result: "succeeded",
      });
      return { channel: structuredClone(candidate), created: true };
    });
    json(res, outcome.created ? 201 : 200, {
      ok: true,
      created: outcome.created,
      channel: publicNotificationChannel(outcome.channel),
    });
  }

  async function updateNotificationChannelResource(req, res, channelId) {
    requireNotificationChannels();
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const reason = cleanReason(body.reason);
    const idempotencyKey = validateRequiredIdempotencyKey(req);
    await requirePermission(current.session, "notifications.channels.write");
    await requireStepUp(current, req, "notification.channel.update", "H");
    const patch = notificationChannelInput(body, true);
    const existing = await store.read((data) => {
      const channel = data.notificationChannels[channelId];
      return channel ? structuredClone(channel) : null;
    });
    if (!existing) throw new HttpError(404, "notification_channel_not_found", "Channel not found");
    let updated;
    try {
      updated = updateNotificationChannel(existing, patch, {
        allowlist: config.notifications?.channels?.outboundAllowlist || [],
        emailRecipientDomains: config.notifications?.channels?.emailRecipientDomains || [],
        actorSubjectId: current.session.subjectId,
      });
    } catch (error) {
      throw new HttpError(400, "invalid_notification_channel", error.message);
    }
    const requestFingerprint = notificationChannelFingerprint(
      "notification.channel.update",
      channelId,
      reason,
      patch,
    );
    const idempotencyKeyHash = sha256(`${current.session.subjectId}\u0000${idempotencyKey}`);
    const outcome = await store.mutate((data) => {
      const existingRequest = data.notificationChannelRequests[idempotencyKeyHash];
      if (existingRequest) {
        if (existingRequest.requestFingerprint !== requestFingerprint) {
          throw new HttpError(
            409,
            "notification_channel_request_conflict",
            "Idempotency-Key was already used for a different notification channel request",
          );
        }
        const channel = data.notificationChannels[existingRequest.channelId];
        if (!channel) {
          throw new HttpError(
            503,
            "storage_unavailable",
            "The notification channel request points to a missing channel",
          );
        }
        return { channel: structuredClone(channel), updated: false };
      }
      if (!data.notificationChannels[channelId]) {
        throw new HttpError(404, "notification_channel_not_found", "Channel not found");
      }
      data.notificationChannels[channelId] = updated;
      data.notificationChannelRequests[idempotencyKeyHash] = {
        idempotencyKeyHash,
        requestFingerprint,
        action: "notification.channel.update",
        channelId,
        status: "succeeded",
        createdAt: updated.updatedAt,
        updatedAt: updated.updatedAt,
      };
      data.adminSystemAuditLogs.push({
        id: `audit_${crypto.randomUUID()}`,
        action: "notification.channel.updated",
        timestamp: updated.updatedAt,
        channelId,
        channelType: updated.type,
        provider: updated.provider,
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        reason,
        result: "succeeded",
      });
      return { channel: structuredClone(updated), updated: true };
    });
    json(res, 200, {
      ok: true,
      updated: outcome.updated,
      channel: publicNotificationChannel(outcome.channel),
    });
  }

  async function testNotificationChannelResource(req, res, channelId) {
    requireNotificationChannels();
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const reason = cleanReason(body.reason);
    const idempotencyKey = validateRequiredIdempotencyKey(req);
    await requirePermission(current.session, "notifications.channels.test");
    await requireStepUp(current, req, "notification.channel.test", "H");
    const channel = await store.read((data) => {
      const stored = data.notificationChannels[channelId];
      return stored ? structuredClone(stored) : null;
    });
    if (!channel) throw new HttpError(404, "notification_channel_not_found", "Channel not found");
    const requestFingerprint = notificationChannelFingerprint(
      "notification.channel.test",
      channelId,
      reason,
      {},
    );
    const idempotencyKeyHash = sha256(`${current.session.subjectId}\u0000${idempotencyKey}`);
    const reservation = await store.mutate((data) => {
      const existing = data.notificationChannelRequests[idempotencyKeyHash];
      if (existing) {
        if (existing.requestFingerprint !== requestFingerprint) {
          throw new HttpError(
            409,
            "notification_channel_request_conflict",
            "Idempotency-Key was already used for a different notification channel request",
          );
        }
        if (existing.status === "in_progress") {
          throw new HttpError(
            409,
            "notification_channel_test_in_progress",
            "This notification channel test is still in progress",
          );
        }
        return {
          existing: true,
          testId: existing.testId || "",
          createdAt: existing.createdAt,
        };
      }
      const now = new Date().toISOString();
      const testId = `nct_${sha256(
        `${idempotencyKeyHash}\u0000${channelId}\u0000${now}`,
      ).slice(0, 24)}`;
      data.notificationChannelRequests[idempotencyKeyHash] = {
        idempotencyKeyHash,
        requestFingerprint,
        action: "notification.channel.test",
        channelId,
        status: "in_progress",
        testId,
        createdAt: now,
        updatedAt: now,
      };
      return { existing: false, testId, createdAt: now };
    });
    if (reservation.existing) {
      const result = await store.read((data) => (
        data.notificationChannelTests[reservation.testId]
          ? structuredClone(data.notificationChannelTests[reservation.testId])
          : null
      ));
      if (!result) {
        throw new HttpError(
          503,
          "storage_unavailable",
          "The notification channel test result is unavailable",
        );
      }
      json(res, 200, {
        ok: result.status === "succeeded",
        replayed: true,
        test: publicNotificationChannelTest(result),
      });
      return;
    }
    let status = "succeeded";
    let resultCode = "transport_ok";
    try {
      await notificationChannelTransport.test(channel);
    } catch (error) {
      status = "failed";
      resultCode = stableErrorCode(error);
    }
    const result = await store.mutate((data) => {
      const now = new Date().toISOString();
      const stored = {
        testId: reservation.testId,
        channelId,
        status,
        resultCode,
        actorSubjectId: current.session.subjectId,
        createdAt: now,
      };
      data.notificationChannelTests[reservation.testId] = stored;
      const request = data.notificationChannelRequests[idempotencyKeyHash];
      if (!request || request.status !== "in_progress") {
        throw new HttpError(
          503,
          "storage_unavailable",
          "The notification channel test reservation was lost",
        );
      }
      request.status = "succeeded";
      request.testId = reservation.testId;
      request.updatedAt = now;
      data.adminSystemAuditLogs.push({
        id: `audit_${crypto.randomUUID()}`,
        action: "notification.channel.tested",
        timestamp: now,
        channelId,
        testId: reservation.testId,
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        reason,
        result: status,
        resultCode,
      });
      return stored;
    });
    json(res, 200, {
      ok: result.status === "succeeded",
      replayed: false,
      test: publicNotificationChannelTest(result),
    });
  }

  async function auditLogPage(session, searchParams) {
    const query = auditQuery(searchParams);
    const result = await requirePermission(
      session,
      "audit.read",
      query.orgUnitId && query.orgUnitId !== "*" ? query.orgUnitId : "",
    );
    if (query.orgUnitId === "*" && !hasGlobalScope(result.access)) {
      throw new HttpError(403, "forbidden_scope", "Global audit scope is not allowed");
    }
    if (query.orgUnitId && query.orgUnitId !== "*"
        && !result.data.orgUnits[query.orgUnitId]) {
      throw new HttpError(400, "invalid_audit_filter", "orgUnitId is not available");
    }
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
        if (query.phase && record.phase !== query.phase) continue;
        if (query.from && String(record.timestamp || "") < query.from) continue;
        if (query.to && String(record.timestamp || "") > query.to) continue;
        const orgUnitId = auditRecordOrgUnitId(
          data,
          maps,
          record,
          query.orgUnitId === "*" ? "*" : query.orgUnitId,
        );
        if (!organizationScopeAllows(result.access, orgUnitId)) continue;
        if (query.orgUnitId
            && !orgUnitWithinQuery(data, query.orgUnitId, orgUnitId)) continue;
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

  function csvCell(value) {
    let text = value == null ? "" : String(value);
    if (typeof value === "string" && /^[=+\-@]/.test(text)) text = `'${text}`;
    if (/[",\r\n]/.test(text) || /^\s|\s$/.test(text)) {
      return `"${text.replaceAll('"', '""')}"`;
    }
    return text;
  }

  function csvContent(headers, rows) {
    return `\uFEFF${[headers, ...rows]
      .map((row) => row.map(csvCell).join(","))
      .join("\r\n")}\r\n`;
  }

  function exportFileName(kind, createdAt) {
    const stamp = createdAt.replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
    return `magpie-${kind}-${stamp}.csv`;
  }

  function publicExportRecord(record) {
    return {
      exportId: String(record.id || ""),
      kind: String(record.kind || ""),
      status: String(record.status || ""),
      fileName: String(record.fileName || ""),
      contentType: String(record.contentType || ""),
      rowCount: Number(record.rowCount || 0),
      byteLength: Number(record.byteLength || 0),
      createdAt: String(record.createdAt || ""),
      expiresAt: String(record.expiresAt || ""),
      consumedAt: String(record.consumedAt || ""),
      downloadPath: `/api/v1/admin/exports/${encodeURIComponent(record.id)}/download`,
    };
  }

  function exportToken(exportId, sessionHash, actorSubjectId) {
    return crypto.createHmac("sha256", config.sessionSecret)
      .update(`${exportId}\u0000${sessionHash}\u0000${actorSubjectId}`)
      .digest("base64url");
  }

  function assertExportSize(content, rowCount) {
    if (rowCount > config.exports.maxRecords) {
      throw new HttpError(
        413,
        "export_too_large",
        "The export exceeds the configured record limit",
      );
    }
    if (Buffer.byteLength(content, "utf8") > config.exports.maxBytes) {
      throw new HttpError(
        413,
        "export_too_large",
        "The export exceeds the configured byte limit",
      );
    }
  }

  async function usageExportContent(session, request) {
    const params = new URLSearchParams({
      from: request.from,
      to: request.to,
    });
    for (const [key, value] of Object.entries(request.filters)) {
      if (value !== "") params.set(key, String(value));
    }
    const report = await usageReport(session, params, false);
    const rows = report.matched.map(({ record, user }) => {
      const orgUnitId = activeUserOrgUnit(report.data, user.id);
      const department = orgUnitId ? report.data.orgUnits[orgUnitId]?.path || "" : "";
      return [
        new Date(record.time).toISOString(),
        user.id,
        user.email,
        department,
        record.agent,
        record.provider,
        record.model,
        record.status,
        record.inputTokens
          + record.outputTokens
          + record.cacheReadTokens
          + record.cacheWriteTokens,
        record.costUsd == null ? "" : record.costUsd,
        record.rejected ? "true" : "false",
        record.handedOn ? "true" : "false",
      ];
    });
    const content = csvContent([
      "time",
      "userId",
      "email",
      "department",
      "agent",
      "provider",
      "model",
      "status",
      "tokens",
      "cost",
      "rejected",
      "handedOn",
    ], rows);
    assertExportSize(content, rows.length);
    return { content, rowCount: rows.length };
  }

  async function auditExportContent(session, request) {
    const result = await requirePermission(
      session,
      "audit.export",
      request.orgUnitId === "*" ? "" : request.orgUnitId,
    );
    if (request.orgUnitId === "*" && !hasGlobalScope(result.access)) {
      throw new HttpError(403, "forbidden_scope", "Global audit scope is not allowed");
    }
    if (request.orgUnitId !== "*" && !result.data.orgUnits[request.orgUnitId]) {
      throw new HttpError(400, "invalid_audit_filter", "orgUnitId is not available");
    }
    const maps = await auditTargetMaps();
    const records = await store.read((data) => data.adminAuditLogs
      .filter((record) => {
        for (const key of [
          "operationId",
          "actorSubjectId",
          "action",
          "targetType",
          "targetId",
          "result",
          "phase",
        ]) {
          if (!request.filters[key]) continue;
          const value = key === "actorSubjectId"
            ? record.actorSubjectId || record.actorSubject
            : record[key];
          if (value !== request.filters[key]) return false;
        }
        if (String(record.timestamp || "") < request.from
            || String(record.timestamp || "") > request.to) {
          return false;
        }
        const orgUnitId = auditRecordOrgUnitId(
          data,
          maps,
          record,
          request.orgUnitId === "*" ? "*" : request.orgUnitId,
        );
        return organizationScopeAllows(result.access, orgUnitId)
          && orgUnitWithinQuery(data, request.orgUnitId, orgUnitId);
      })
      .sort(compareAuditRecords)
      .map((record) => structuredClone(record)));
    const rows = records.map((record) => [
      record.timestamp,
      record.operationId || "",
      record.actorSubjectId || record.actorSubject || "",
      record.actorEmail || "",
      record.action || "",
      record.phase || "",
      record.targetType || "",
      record.targetId || "",
      record.targetOrgUnitId || "",
      record.result || "",
      record.errorCode || "",
      record.approvalId || "",
      record.breakGlassId || "",
      record.parentOperationId || "",
      record.reason || "",
    ]);
    const content = csvContent([
      "time",
      "operationId",
      "actorSubjectId",
      "actorEmail",
      "action",
      "phase",
      "targetType",
      "targetId",
      "targetOrgUnitId",
      "result",
      "errorCode",
      "approvalId",
      "breakGlassId",
      "parentOperationId",
      "reason",
    ], rows);
    assertExportSize(content, rows.length);
    return { content, rowCount: rows.length };
  }

  function replayExport(res, current, existing, replayed) {
    if (existing.exportRecord.sessionHash !== current.sidHash
        || existing.exportRecord.actorSubjectId !== current.session.subjectId) {
      throw new HttpError(
        403,
        "export_session_mismatch",
        "This export belongs to a different management session",
      );
    }
    if (existing.exportRecord.status === "consumed") {
      throw new HttpError(410, "export_consumed", "This export was already downloaded");
    }
    if (existing.exportRecord.status === "expired"
        || Date.parse(existing.exportRecord.expiresAt) <= Date.now()) {
      throw new HttpError(410, "export_expired", "This export has expired");
    }
    const token = exportToken(
      existing.exportRecord.id,
      current.sidHash,
      current.session.subjectId,
    );
    if (!existing.tokenRecord
        || existing.tokenRecord.tokenHash !== sha256(token)
        || existing.tokenRecord.consumedAt) {
      throw new HttpError(503, "storage_unavailable", "The export token is unavailable");
    }
    json(res, replayed ? 200 : 201, {
      ok: true,
      replayed,
      export: publicExportRecord(existing.exportRecord),
      downloadToken: token,
    });
  }

  async function performExport(req, res, requestId, action) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const reason = cleanReason(body.reason);
    const approvalId = cleanOptionalApprovalId(body.approvalId);
    const breakGlassId = cleanOptionalBreakGlassId(body.breakGlassId);
    if (approvalId && breakGlassId) {
      throw new HttpError(
        400,
        "approval_and_break_glass_exclusive",
        "approvalId and breakGlassId cannot be used together",
      );
    }
    if (!approvalId && !breakGlassId) {
      throw new HttpError(400, "approval_required", "approvalId or breakGlassId is required");
    }
    const idempotencyKey = validateRequiredIdempotencyKey(req);
    const request = normalizedExportRequest(action, body);
    const definition = approvalActionDefinition(action);
    await requirePermission(
      current.session,
      definition.permission,
      request.orgUnitId === "*" ? "" : request.orgUnitId,
    );
    if (request.orgUnitId === "*") {
      const access = await requirePermission(current.session, definition.permission);
      if (!hasGlobalScope(access.access)) {
        throw new HttpError(403, "forbidden_scope", "Global export scope is not allowed");
      }
    } else {
      const target = await store.read((data) => data.orgUnits[request.orgUnitId] || null);
      if (!target || target.status !== "active") {
        throw new HttpError(400, "invalid_export_scope", "orgUnitId is not active");
      }
    }
    await requireStepUp(current, req, action);

    const targetId = exportTargetId(action, request);
    const requestFingerprint = writeRequestFingerprint(
      action,
      "export",
      targetId,
      reason,
      approvalId,
      breakGlassId,
      request,
    );
    const idempotencyKeyHash = sha256(`${current.session.subjectId}\u0000${idempotencyKey}`);
    const existing = await store.read((data) => {
      const entry = data.adminExportRequests[idempotencyKeyHash];
      if (!entry) {
        if (data.adminIdempotency[idempotencyKeyHash]) {
          throw new HttpError(
            409,
            "idempotency_conflict",
            "Idempotency-Key was already used for a different request",
          );
        }
        return null;
      }
      const exportRecord = data.adminExports[entry.exportId];
      if (!exportRecord) {
        throw new HttpError(
          503,
          "storage_unavailable",
          "The idempotency record points to a missing export",
        );
      }
      if (entry.requestFingerprint !== requestFingerprint) {
        const conflict = new HttpError(
          409,
          "idempotency_conflict",
          "Idempotency-Key was already used for a different request",
        );
        conflict.operationId = entry.operationId;
        throw conflict;
      }
      const tokenRecord = data.adminExportTokens[sha256(exportToken(
        exportRecord.id,
        current.sidHash,
        current.session.subjectId,
      ))];
      return {
        exportRecord: structuredClone(exportRecord),
        tokenRecord: tokenRecord ? structuredClone(tokenRecord) : null,
      };
    });
    if (existing) {
      replayExport(res, current, existing, true);
      return;
    }

    const generated = request.exportType === "usage"
      ? await usageExportContent(current.session, request)
      : await auditExportContent(current.session, request);
    let outcome;
    try {
      outcome = await store.mutate((data) => {
        const raced = data.adminExportRequests[idempotencyKeyHash];
        if (raced) {
          const exportRecord = data.adminExports[raced.exportId];
          if (!exportRecord || raced.requestFingerprint !== requestFingerprint) {
            throw new HttpError(
              409,
              "idempotency_conflict",
              "Idempotency-Key was already used for a different request",
            );
          }
          const tokenRecord = data.adminExportTokens[sha256(exportToken(
            exportRecord.id,
            current.sidHash,
            current.session.subjectId,
          ))];
          return {
            replayed: true,
            exportRecord: structuredClone(exportRecord),
            tokenRecord: tokenRecord ? structuredClone(tokenRecord) : null,
          };
        }
        if (data.adminIdempotency[idempotencyKeyHash]) {
          throw new HttpError(
            409,
            "idempotency_conflict",
            "Idempotency-Key was already used for a different request",
          );
        }

        const now = new Date();
        const createdAt = now.toISOString();
        const exportId = `exp_${crypto.randomUUID()}`;
        const expiresAt = new Date(
          now.getTime() + config.exports.ttlSeconds * 1000,
        ).toISOString();
        const operation = {
          id: `op_${crypto.randomUUID()}`,
          requestId,
          idempotencyKeyHash,
          requestFingerprint,
          actorSubjectId: current.session.subjectId,
          actorEmail: current.session.email,
          roles: [...effectiveAccess(data, current.session.subjectId).roles],
          scopeOrgUnitIds: [...effectiveAccess(
            data,
            current.session.subjectId,
          ).scopeOrgUnitIds],
          action,
          targetType: "export",
          targetId,
          targetOrgUnitId: request.orgUnitId,
          reason,
          approvalId,
          breakGlassId,
          beforeSummary: {
            id: targetId,
            exportType: request.exportType,
            orgUnitId: request.orgUnitId,
            from: request.from,
            to: request.to,
            filters: request.filters,
          },
          status: "succeeded",
          createdAt,
          updatedAt: createdAt,
          dependencyInvokedAt: createdAt,
          completedAt: createdAt,
          intentAuditId: "",
          resultAuditId: "",
          responseStatus: 201,
          responseBody: null,
          errorCode: "",
          sourceIp: String(req.socket.remoteAddress || ""),
          userAgentHash: sha256(String(req.headers["user-agent"] || "")),
        };
        if (breakGlassId) {
          const expected = breakGlassExpectedBinding({
            environmentId: approvalEnvironmentId,
            policyVersion: BREAK_GLASS_POLICY_VERSION,
            requesterSubjectId: current.session.subjectId,
            action,
            targetType: "export",
            targetId,
            targetOrgUnitId: request.orgUnitId,
            riskLevel: riskForAction(action),
            reason,
            payload: request,
          });
          consumeBreakGlassForOperation(
            data,
            breakGlassId,
            expected,
            operation,
            breakGlassNow(),
          );
        } else {
          const expected = approvalExpectedBinding({
            requesterSubjectId: current.session.subjectId,
            action,
            targetType: "export",
            targetId,
            targetOrgUnitId: request.orgUnitId,
            riskLevel: riskForAction(action),
            reason,
            payload: request,
          });
          reserveApprovalForOperation(data, approvalId, expected, operation);
        }

        const token = exportToken(
          exportId,
          current.sidHash,
          current.session.subjectId,
        );
        if (Buffer.byteLength(token, "utf8") > MAX_EXPORT_TOKEN_BYTES) {
          throw new Error("Derived export token exceeds the supported size");
        }
        const tokenHash = sha256(token);
        const exportRecord = {
          id: exportId,
          kind: request.exportType,
          status: "ready",
          actorSubjectId: current.session.subjectId,
          actorEmail: current.session.email,
          sessionHash: current.sidHash,
          scopeOrgUnitId: request.orgUnitId,
          fileName: exportFileName(request.exportType, createdAt),
          contentType: "text/csv; charset=utf-8",
          content: generated.content,
          rowCount: generated.rowCount,
          byteLength: Buffer.byteLength(generated.content, "utf8"),
          createdAt,
          expiresAt,
          consumedAt: "",
        };
        operation.responseBody = {
          ok: true,
          requestId,
          operationId: operation.id,
          action,
          targetId,
          result: {
            state: "succeeded",
            exportId,
            exportType: request.exportType,
            rowCount: generated.rowCount,
            byteLength: exportRecord.byteLength,
            expiresAt,
          },
        };
        const intent = auditRecord(operation, "intent", "pending");
        data.adminOperations[operation.id] = operation;
        const result = auditRecord(operation, "result", "succeeded", {
          afterSummary: operation.responseBody.result,
        });
        operation.intentAuditId = intent.id;
        operation.resultAuditId = result.id;
        data.adminAuditLogs.push(intent, result);
        if (approvalId) {
          consumeApprovalForOperation(data, approvalId, operation, "succeeded");
        }
        data.adminExports[exportId] = exportRecord;
        data.adminExportTokens[tokenHash] = {
          tokenHash,
          exportId,
          actorSubjectId: current.session.subjectId,
          sessionHash: current.sidHash,
          expiresAt,
          consumedAt: "",
        };
        data.adminExportRequests[idempotencyKeyHash] = {
          requestHash: idempotencyKeyHash,
          exportId,
          operationId: operation.id,
          requestFingerprint,
          createdAt,
        };
        data.adminIdempotency[idempotencyKeyHash] = {
          operationId: operation.id,
          requestFingerprint,
          createdAt,
          exportId,
        };
        notificationOutbox.enqueueOperation(data, operation, {
          occurredAt: createdAt,
          state: "succeeded",
        });
        return {
          replayed: false,
          exportRecord: structuredClone(exportRecord),
          tokenRecord: structuredClone(data.adminExportTokens[tokenHash]),
        };
      });
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw new HttpError(503, "audit_unavailable", "The export could not be committed");
    }
    if (outcome.replayed) {
      replayExport(res, current, outcome, true);
      return;
    }
    json(res, 201, {
      ok: true,
      replayed: false,
      export: publicExportRecord(outcome.exportRecord),
      downloadToken: exportToken(
        outcome.exportRecord.id,
        current.sidHash,
        current.session.subjectId,
      ),
    });
  }

  async function downloadExport(req, res, exportId) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    const authorization = String(req.headers.authorization || "");
    const match = /^Bearer ([A-Za-z0-9_-]+)$/.exec(authorization);
    if (!match || Buffer.byteLength(match[1], "utf8") > MAX_EXPORT_TOKEN_BYTES) {
      throw new HttpError(401, "export_token_required", "A Bearer export token is required");
    }
    const token = match[1];
    const tokenHash = sha256(token);
    const downloaded = await store.mutate((data) => {
      const exportRecord = data.adminExports[exportId];
      if (!exportRecord) {
        throw new HttpError(404, "export_not_found", "Export not found");
      }
      const tokenRecord = data.adminExportTokens[tokenHash];
      if (!tokenRecord
          || tokenRecord.exportId !== exportId
          || tokenRecord.sessionHash !== current.sidHash
          || tokenRecord.actorSubjectId !== current.session.subjectId
          || exportRecord.sessionHash !== current.sidHash
          || exportRecord.actorSubjectId !== current.session.subjectId) {
        throw new HttpError(403, "export_token_invalid", "The export token is not valid");
      }
      if (exportRecord.status === "consumed" || tokenRecord.consumedAt) {
        throw new HttpError(410, "export_consumed", "This export was already downloaded");
      }
      if (exportRecord.status !== "ready"
          || Date.parse(exportRecord.expiresAt) <= Date.now()) {
        throw new HttpError(410, "export_expired", "This export has expired");
      }
      const consumedAt = new Date().toISOString();
      exportRecord.status = "consumed";
      exportRecord.consumedAt = consumedAt;
      tokenRecord.consumedAt = consumedAt;
      data.adminSystemAuditLogs.push({
        id: `audit_${crypto.randomUUID()}`,
        action: "export.downloaded",
        timestamp: consumedAt,
        actorSubjectId: current.session.subjectId,
        actorEmail: current.session.email,
        exportId,
        exportType: exportRecord.kind,
        targetOrgUnitId: exportRecord.scopeOrgUnitId,
        rowCount: exportRecord.rowCount,
        byteLength: exportRecord.byteLength,
        result: "succeeded",
      });
      return {
        content: exportRecord.content,
        contentType: exportRecord.contentType,
        fileName: exportRecord.fileName,
        byteLength: exportRecord.byteLength,
      };
    });
    const body = Buffer.from(downloaded.content, "utf8");
    if (body.length !== downloaded.byteLength) {
      throw new HttpError(503, "storage_unavailable", "The stored export is inconsistent");
    }
    res.writeHead(200, {
      "content-type": downloaded.contentType,
      "content-disposition": `attachment; filename="${downloaded.fileName.replaceAll('"', "")}"`,
      "content-length": body.length,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    });
    res.end(body);
  }

  async function performReconciliation(req, res, requestId, operationId) {
    const current = await currentSession(req);
    if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
    await requireCsrf(req, current.session);
    const body = await readJsonBody(req);
    const reason = cleanReason(body.reason);
    const approvalId = cleanOptionalApprovalId(body.approvalId);
    const breakGlassId = cleanOptionalBreakGlassId(body.breakGlassId);
    if (approvalId && breakGlassId) {
      throw new HttpError(
        400,
        "approval_and_break_glass_exclusive",
        "approvalId and breakGlassId cannot be used together",
      );
    }
    if (!approvalId && !breakGlassId) {
      throw new HttpError(400, "approval_required", "approvalId or breakGlassId is required");
    }
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
    await requireStepUp(current, req, "operation.reconcile");

    const requestFingerprint = writeRequestFingerprint(
      "operation.reconcile",
      parent.targetType,
      parent.targetId,
      reason,
      approvalId,
      breakGlassId,
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
      breakGlassId,
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
        const payload = {
          parentOperationId: parent.id,
          reconciliationAction,
          evidenceRef,
        };
        if (breakGlassId) {
          const expected = breakGlassExpectedBinding({
            environmentId: approvalEnvironmentId,
            policyVersion: BREAK_GLASS_POLICY_VERSION,
            requesterSubjectId: current.session.subjectId,
            action: "operation.reconcile",
            targetType: parent.targetType,
            targetId: parent.targetId,
            targetOrgUnitId,
            riskLevel: riskForAction("operation.reconcile"),
            reason,
            payload,
          });
          consumeBreakGlassForOperation(data, breakGlassId, expected, childOperation, breakGlassNow());
        } else {
          const expected = approvalExpectedBinding({
            requesterSubjectId: current.session.subjectId,
            action: "operation.reconcile",
            targetType: parent.targetType,
            targetId: parent.targetId,
            targetOrgUnitId,
            riskLevel: riskForAction("operation.reconcile"),
            reason,
            payload,
          });
          reserveApprovalForOperation(data, approvalId, expected, childOperation);
        }
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
        notificationOutbox.enqueueOperation(data, stored, {
          occurredAt: completedAt,
          state: responseBody?.result?.state || "",
        });
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
    const breakGlassId = cleanOptionalBreakGlassId(body.breakGlassId);
    if (approvalId && breakGlassId) {
      throw new HttpError(
        400,
        "approval_and_break_glass_exclusive",
        "approvalId and breakGlassId cannot be used together",
      );
    }
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
    await requireStepUp(current, req, options.action);
    const prepared = options.prepare
      ? options.prepare(body, targetResult.target)
      : {};
    const requestFingerprint = writeRequestFingerprint(
      options.action,
      options.targetType,
      targetId,
      reason,
      approvalId,
      breakGlassId,
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
      breakGlassId,
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
          if (!approvalId && !breakGlassId) {
            throw approvalHttpError(
              "approval_required",
              "approvalId or breakGlassId is required for this action",
            );
          }
          if (!targetOrgUnitId) {
            throw new HttpError(
              409,
              "target_org_required",
              "An approval target must belong to an active organization unit",
            );
          }
          if (breakGlassId) {
            const expected = breakGlassExpectedBinding({
              environmentId: approvalEnvironmentId,
              policyVersion: BREAK_GLASS_POLICY_VERSION,
              requesterSubjectId: current.session.subjectId,
              action: options.action,
              targetType: options.targetType,
              targetId,
              targetOrgUnitId,
              riskLevel: riskForAction(options.action),
              reason,
              payload: prepared,
            });
            consumeBreakGlassForOperation(data, breakGlassId, expected, operation, breakGlassNow());
          } else {
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
          }
        } else if (approvalId || breakGlassId) {
          throw approvalHttpError(
            "approval_invalid",
            "This action must not consume an approval or break-glass grant",
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
        if (operation.approvalId) {
          consumeApprovalForOperation(
            data,
            operation.approvalId,
            operation,
            operationError ? "failed" : "succeeded",
          );
        }
        data.adminAuditLogs.push(resultAudit);
        stored.resultAuditId = resultAudit.id;
        notificationOutbox.enqueueOperation(data, stored, {
          occurredAt: completedAt,
          state: responseBody?.result?.state || "",
        });
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

  function usageFilters(searchParams) {
    const value = (names, maxLength = 256) => {
      for (const name of names) {
        const candidate = String(searchParams.get(name) || "").trim();
        if (!candidate) continue;
        if ([...candidate].length > maxLength || /[\u0000-\u001f\u007f]/.test(candidate)) {
          throw new HttpError(400, "invalid_usage_filter", `${name} is invalid`);
        }
        return candidate;
      }
      return "";
    };
    const statusValue = value(["status"], 20);
    if (statusValue && !/^\d+$/.test(statusValue)) {
      throw new HttpError(400, "invalid_usage_filter", "status must be a number");
    }
    return {
      userId: value(["userId", "user"], 128),
      departmentId: value(["departmentId", "department", "orgUnitId"], 128),
      agent: value(["agent"], 160),
      model: value(["model"], 240),
      provider: value(["provider"], 160),
      callerKeyId: value(["callerKeyId"], 240),
      status: statusValue ? Number(statusValue) : null,
    };
  }

  function usageRecordMatches(result, entry, filters) {
    if (filters.userId && entry.user.id !== filters.userId) return false;
    if (filters.departmentId) {
      const orgUnitId = activeUserOrgUnit(result.data, entry.user.id);
      if (!orgUnitWithinQuery(result.data, filters.departmentId, orgUnitId)) return false;
    }
    if (filters.agent && entry.record.agent !== filters.agent) return false;
    if (filters.model && entry.record.model !== filters.model) return false;
    if (filters.provider && entry.record.provider !== filters.provider) return false;
    if (filters.callerKeyId && entry.record.callerKeyId !== filters.callerKeyId) return false;
    if (filters.status != null && entry.record.status !== filters.status) return false;
    return true;
  }

  async function usageReport(session, searchParams, grouped) {
    const result = await requirePermission(session, "usage.read");
    const window = finiteWindow(searchParams, config.usage.maxRangeDays);
    const filters = usageFilters(searchParams);
    if (filters.departmentId && filters.departmentId !== "*"
        && !result.data.orgUnits[filters.departmentId]) {
      throw new HttpError(400, "invalid_usage_filter", "departmentId is not available");
    }
    if (filters.departmentId === "*" && !hasGlobalScope(result.access)) {
      throw new HttpError(403, "forbidden_scope", "Global department scope is not allowed");
    }
    if (filters.departmentId && filters.departmentId !== "*"
        && !result.access.scopeOrgUnitIds.includes("*")
        && !result.access.scopeOrgUnitIds.includes(filters.departmentId)) {
      throw new HttpError(403, "forbidden_scope", "The department filter is outside your access");
    }
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
    let outsideScopeRecords = 0;
    let filteredOutRecords = 0;
    for (const record of usage.records) {
      const credential = credentialById.get(record.callerKeyId);
      const user = credential ? userById.get(credential.userId) : null;
      if (!user) {
        unattributedRecords += 1;
        continue;
      }
      if (!visible.has(user.id)) {
        outsideScopeRecords += 1;
        continue;
      }
      const entry = { record, credential, user };
      if (!usageRecordMatches(result, entry, filters)) {
        filteredOutRecords += 1;
        continue;
      }
      matched.push(entry);
    }

    return {
      ...result,
      window,
      usage,
      matched,
      unattributedRecords,
      outsideScopeRecords,
      filteredOutRecords,
      filters,
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

  async function mePayload(req, current) {
    const { session } = current;
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
    const stepUp = await stepUpState(current, req);
    return {
      value: {
        user: publicIdentity(session),
        roles: data.access.roles,
        permissions: data.access.permissions,
        scopeOrgUnitIds: data.access.scopeOrgUnitIds,
        orgUnits: data.orgUnits,
        session: sessionInfo(session),
        stepUp: {
          ...stepUp,
          startUrl: stepUp.configured
            ? `/admin/oauth/step-up/start?returnTo=${encodeURIComponent("/admin/")}`
            : "",
        },
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

    if (req.method === "POST" && url.pathname === "/api/v1/integrations/approvals/callback") {
      await externalApprovalCallback(req, res);
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

    if (req.method === "GET" && url.pathname === "/admin/oauth/step-up/start") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      if (!config.stepUpOidc || !stepUpOidc) {
        throw new HttpError(
          503,
          "step_up_unavailable",
          "Step-up authentication is not configured",
        );
      }
      const returnTo = stepUpReturnPath(url.searchParams.get("returnTo"));
      const started = await stepUpOidc.begin({
        promptLogin: true,
        maxAgeSeconds: config.stepUpOidc.authTimeMaxAgeSeconds,
        requireAuthTime: true,
      });
      const transaction = {
        ...started.transaction,
        returnTo,
        sidHash: current.sidHash,
        subjectId: current.session.subjectId,
      };
      redirect(res, started.url, {
        "set-cookie": [
          cookieHeader(
            config,
            config.stepUpCookieName,
            signCookie(JSON.stringify(transaction), config.sessionSecret),
            600,
          ),
        ],
      });
      return;
    }

    if (req.method === "GET" && url.pathname === "/admin/oauth/step-up/callback") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      if (!config.stepUpOidc || !stepUpOidc) {
        throw new HttpError(
          503,
          "step_up_unavailable",
          "Step-up authentication is not configured",
        );
      }
      const cookies = parseCookies(req.headers.cookie);
      const raw = verifyCookie(cookies[config.stepUpCookieName], config.sessionSecret);
      if (!raw) throw new HttpError(400, "step_up_expired", "Step-up transaction is missing or expired");
      let transaction;
      try {
        transaction = JSON.parse(raw);
      } catch {
        throw new HttpError(400, "step_up_expired", "Step-up transaction is invalid");
      }
      if (!safeEqual(url.searchParams.get("state") || "", transaction.state)
          || transaction.sidHash !== current.sidHash
          || transaction.subjectId !== current.session.subjectId) {
        throw new HttpError(
          403,
          "step_up_binding_mismatch",
          "Step-up transaction does not belong to this management session",
        );
      }
      const returnTo = stepUpReturnPath(transaction.returnTo);
      const completed = await stepUpOidc.complete(url.searchParams.get("code") || "", transaction);
      let authentication;
      let identity;
      try {
        authentication = validateStepUpAuthentication(
          completed.claims,
          config.stepUpOidc,
        );
        identity = normalizeAdminIdentity(completed.claims, config.stepUpOidc);
      } catch (error) {
        throw new HttpError(
          403,
          "step_up_invalid",
          error instanceof Error ? error.message : "Step-up authentication is invalid",
        );
      }
      if (identity.subject !== current.session.subject
          || identity.email !== current.session.email) {
        throw new HttpError(
          403,
          "step_up_binding_mismatch",
          "Step-up identity does not match the management session",
        );
      }
      const verifiedAt = new Date();
      const expiresAt = new Date(
        verifiedAt.getTime() + config.stepUpOidc.ttlSeconds * 1000,
      );
      const criticalExpiresAt = new Date(
        Math.min(
          expiresAt.getTime(),
          verifiedAt.getTime() + config.stepUpOidc.criticalTtlSeconds * 1000,
        ),
      );
      await store.mutate((data) => {
        const access = effectiveAccess(data, current.session.subjectId);
        data.stepUpAssertions[current.sidHash] = {
          sessionHash: current.sidHash,
          subjectId: current.session.subjectId,
          acr: authentication.acr,
          amr: [...authentication.amr],
          authTime: authentication.authTime,
          verifiedAt: verifiedAt.toISOString(),
          expiresAt: expiresAt.toISOString(),
          criticalExpiresAt: criticalExpiresAt.toISOString(),
          ip: clientIp(req),
          userAgentHash: userAgentHash(req),
          accessDigest: accessDigest(access),
        };
        data.adminSystemAuditLogs.push({
          id: `audit_${crypto.randomUUID()}`,
          action: "step_up.verified",
          timestamp: verifiedAt.toISOString(),
          actorSubjectId: current.session.subjectId,
          actorEmail: current.session.email,
          acr: authentication.acr,
          amr: [...authentication.amr],
          authTime: authentication.authTime,
          expiresAt: expiresAt.toISOString(),
          criticalExpiresAt: criticalExpiresAt.toISOString(),
          result: "verified",
        });
      });
      redirect(res, returnTo, {
        "set-cookie": [cookieHeader(config, config.stepUpCookieName, "", 0)],
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
      const payload = await mePayload(req, current);
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
        payload.value.stepUp,
      ));
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/me") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      const payload = await mePayload(req, current);
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
        delete data.stepUpAssertions[current.sidHash];
      });
      const headers = { "set-cookie": clearedSessionCookies(config) };
      if (htmlForm) {
        redirect(res, "/admin/login", headers);
      } else {
        json(res, 200, { ok: true }, headers);
      }
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/break-glass") {
      await listBreakGlassGrants(req, res, url.searchParams);
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/v1/admin/break-glass") {
      await createBreakGlassGrant(req, res);
      return;
    }

    const breakGlassReviewMatch =
      /^\/api\/v1\/admin\/break-glass\/(bgr_[A-Za-z0-9_-]+)\/review$/.exec(url.pathname);
    if (req.method === "POST" && breakGlassReviewMatch) {
      await reviewBreakGlassGrant(req, res, breakGlassReviewMatch[1]);
      return;
    }

    const breakGlassMatch =
      /^\/api\/v1\/admin\/break-glass\/(bgr_[A-Za-z0-9_-]+)$/.exec(url.pathname);
    if (req.method === "GET" && breakGlassMatch) {
      await getBreakGlassGrant(req, res, breakGlassMatch[1]);
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/approvals") {
      await listApprovals(req, res, url.searchParams);
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/v1/admin/approvals") {
      await createApproval(req, res);
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/approvals/inbox") {
      await listApprovalInbox(req, res, url.searchParams);
      return;
    }

    const approvalDecisionMatch =
      /^\/api\/v1\/admin\/approvals\/([A-Za-z0-9_-]+)\/decisions$/.exec(url.pathname);
    if (req.method === "POST" && approvalDecisionMatch) {
      await decideApproval(req, res, approvalDecisionMatch[1]);
      return;
    }

    const approvalWithdrawMatch =
      /^\/api\/v1\/admin\/approvals\/([A-Za-z0-9_-]+)\/withdraw$/.exec(url.pathname);
    if (req.method === "POST" && approvalWithdrawMatch) {
      await withdrawApproval(req, res, approvalWithdrawMatch[1]);
      return;
    }

    const approvalTransferMatch =
      /^\/api\/v1\/admin\/approvals\/([A-Za-z0-9_-]+)\/steps\/(stp_[A-Za-z0-9_-]{1,60})\/transfer$/
        .exec(url.pathname);
    if (req.method === "POST" && approvalTransferMatch) {
      await transferApprovalStep(req, res, approvalTransferMatch[1], approvalTransferMatch[2]);
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

    if (req.method === "GET" && url.pathname === "/api/v1/admin/notifications/deliveries") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      json(res, 200, await listNotificationDeliveries(current.session, url.searchParams));
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/notifications/dead-letters") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      json(res, 200, await listNotificationDeadLetters(current.session, url.searchParams));
      return;
    }

    if (req.method === "GET" && url.pathname === "/api/v1/admin/notifications/channels") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      json(res, 200, {
        channels: await listNotificationChannels(current.session),
      });
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/v1/admin/notifications/channels") {
      await createNotificationChannelResource(req, res);
      return;
    }

    const notificationChannelMatch =
      /^\/api\/v1\/admin\/notifications\/channels\/(nch_[a-f0-9]{24})$/.exec(
        url.pathname,
      );
    if (req.method === "PATCH" && notificationChannelMatch) {
      await updateNotificationChannelResource(req, res, notificationChannelMatch[1]);
      return;
    }

    const notificationChannelTestMatch =
      /^\/api\/v1\/admin\/notifications\/channels\/(nch_[a-f0-9]{24})\/test$/.exec(
        url.pathname,
      );
    if (req.method === "POST" && notificationChannelTestMatch) {
      await testNotificationChannelResource(req, res, notificationChannelTestMatch[1]);
      return;
    }

    const notificationRetryMatch =
      /^\/api\/v1\/admin\/notifications\/deliveries\/(ntd_[a-f0-9]{32})\/retry$/.exec(
        url.pathname,
      );
    if (req.method === "POST" && notificationRetryMatch) {
      await replayNotificationDelivery(req, res, notificationRetryMatch[1]);
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

    if (req.method === "POST" && url.pathname === "/api/v1/admin/usage/export") {
      await performExport(req, res, requestId, "usage.export.create");
      return;
    }

    if (req.method === "POST" && url.pathname === "/api/v1/admin/audit/export") {
      await performExport(req, res, requestId, "audit.export.create");
      return;
    }

    const exportDownloadMatch =
      /^\/api\/v1\/admin\/exports\/(exp_[a-f0-9-]{36})\/download$/.exec(url.pathname);
    if (req.method === "GET" && exportDownloadMatch) {
      await downloadExport(req, res, exportDownloadMatch[1]);
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

    if (req.method === "GET" && url.pathname === "/api/v1/admin/operations") {
      const current = await currentSession(req);
      if (!current) throw new HttpError(401, "not_signed_in", "Sign in with your management account");
      json(res, 200, await operationPage(current.session, url.searchParams));
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
      await operationReadContext(current.session, operation);
      if (operation.action === "operation.reconcile") {
        await operationTarget(current.session, operation, "operations.reconcile");
      }
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
  notificationDispatcher?.start();
  const breakGlassScheduler = new BreakGlassReviewScheduler(
    store,
    notificationOutbox,
    {
      now: () => breakGlassNow().getTime(),
      intervalMs: options.breakGlassIntervalMs,
    },
  );
  breakGlassScheduler.start();
  return {
    server,
    store,
    oidc,
    authService,
    modelCatalog,
    notificationOutbox,
    notificationDispatcher,
    breakGlassScheduler,
  };
}
