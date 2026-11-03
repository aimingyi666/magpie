import crypto from "node:crypto";
import http from "node:http";

import {
  DetectionEventValidationError,
  validateDetectionEvent,
  validateTimestamp,
} from "./events.js";
import { evaluateDetectionEvent } from "./evaluator.js";
import {
  RESPONSE_ACTION_STATUSES,
  RESPONSE_ACTION_TYPES,
  ResponseActionValidationError,
  isResponseActionId,
  normalizeActorRequest,
  normalizeApprovalRequest,
  normalizeIdempotencyKey,
  normalizeResponseActionRequest,
  publicResponseAction,
  publicResponseAudit,
  responseIdempotencyHash,
  responseRequestDigest,
} from "./response-actions.js";
import {
  ALERT_STATUSES,
  ALERT_SEVERITIES,
  AlertValidationError,
  alertConflict,
  alertIdempotencyHash,
  alertRequestDigest,
  normalizeAlertAssignRequest,
  normalizeAlertActorRequest,
  normalizeAlertCreateRequest,
  normalizeAlertResolveRequest,
  isAlertId,
  publicAlert,
  publicAlertAudit,
} from "./alerts.js";
const ALERT_ID_PATTERN = /^sal_[a-f0-9]{24}$/;
const ALERT_STATUSES_SET = new Set(ALERT_STATUSES);
const ALERT_SEVERITIES_SET = new Set(ALERT_SEVERITIES);
import { createDetectionPolicy, describeRules } from "./rules.js";
import { renderPrometheusMetrics } from "./metrics.js";
import { SecurityStore, SecurityStoreError } from "./store.js";

const SCHEMA_VERSION = 1;
const RULE_ID_PATTERN = /^sec\.[a-z0-9._-]+$/;
const FILTER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const SEVERITIES = new Set(["warning", "high", "critical"]);
const RESPONSE_ACTION_TYPE_SET = new Set(RESPONSE_ACTION_TYPES);
const RESPONSE_ACTION_STATUS_SET = new Set(RESPONSE_ACTION_STATUSES);
const RESPONSE_SOURCE_TYPES = new Set(["finding", "aggregate"]);
const RESPONSE_TARGET_TYPES = new Set([
  "user",
  "device",
  "agent",
  "service",
  "gateway_key",
  "ip_hash",
]);
const MAX_QUERY_LIMIT = 500;

class SecurityApiError extends Error {
  constructor(statusCode, code, message, retryable = false) {
    super(message);
    this.name = "SecurityApiError";
    this.statusCode = statusCode;
    this.code = code;
    this.retryable = retryable;
  }
}

function requestId() {
  return `req_${crypto.randomUUID()}`;
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function bearerToken(req) {
  const match = /^Bearer\s+(\S+)$/i.exec(String(req.headers.authorization || "").trim());
  return match ? match[1] : "";
}

function jsonResponse(res, statusCode, value, reqId, headers = {}) {
  const body = JSON.stringify(value);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-request-id": reqId,
    ...headers,
  });
  res.end(body);
}

function errorResponse(res, reqId, error, logger) {
  const known = error instanceof SecurityApiError
    || error instanceof DetectionEventValidationError
    || error instanceof ResponseActionValidationError
    || error instanceof SecurityStoreError;
  const normalized = known
    ? error
    : new SecurityApiError(
      500,
      "internal_error",
      "The security service could not complete the request",
      true,
    );
  if (!known && logger) {
    logger({
      requestId: reqId,
      code: normalized.code,
      errorName: error?.name || "Error",
    });
  }
  jsonResponse(res, normalized.statusCode || 400, {
    schemaVersion: SCHEMA_VERSION,
    ok: false,
    requestId: reqId,
    error: {
      code: normalized.code,
      message: normalized.message,
      retryable: normalized.retryable || false,
    },
  }, reqId);
}

async function readJsonBody(req, maximumBytes) {
  if (!/^application\/json(?:\s*;|$)/i.test(String(req.headers["content-type"] || ""))) {
    throw new SecurityApiError(
      415,
      "unsupported_media_type",
      "Content-Type must be application/json",
    );
  }
  const declaredLength = Number(req.headers["content-length"]);
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new SecurityApiError(
      413,
      "request_too_large",
      "The detection event exceeds the configured size limit",
    );
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > maximumBytes) {
      throw new SecurityApiError(
        413,
        "request_too_large",
        "The detection event exceeds the configured size limit",
      );
    }
    chunks.push(chunk);
  }
  if (bytes === 0) {
    throw new SecurityApiError(400, "invalid_request", "A JSON request body is required");
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new SecurityApiError(400, "invalid_json", "The request body must be valid JSON");
  }
}

function assertQueryKeys(url, allowed) {
  for (const key of url.searchParams.keys()) {
    if (!allowed.has(key)) {
      throw new SecurityApiError(400, "invalid_query", `Unknown query parameter: ${key}`);
    }
  }
}

function queryValue(url, name, pattern, maximum = 128) {
  const value = url.searchParams.get(name);
  if (value == null || value === "") return "";
  if (value.length > maximum || !pattern.test(value)) {
    throw new SecurityApiError(400, "invalid_query", `${name} is invalid`);
  }
  return value;
}

function timestampQuery(url, name) {
  const value = url.searchParams.get(name);
  if (value == null || value === "") return "";
  try {
    return validateTimestamp(value, name);
  } catch {
    throw new SecurityApiError(400, "invalid_query", `${name} is invalid`);
  }
}

function integerQuery(url, name, fallback) {
  const raw = url.searchParams.get(name);
  if (raw == null || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_QUERY_LIMIT) {
    throw new SecurityApiError(400, "invalid_query", `${name} is invalid`);
  }
  return value;
}

function booleanQuery(url, name) {
  const raw = url.searchParams.get(name);
  if (raw == null || raw === "") return false;
  if (raw !== "true" && raw !== "false") {
    throw new SecurityApiError(400, "invalid_query", `${name} is invalid`);
  }
  return raw === "true";
}

function findingFilters(url, ruleIds) {
  assertQueryKeys(url, new Set([
    "ruleId",
    "severity",
    "organizationId",
    "subjectId",
    "since",
    "limit",
  ]));
  const ruleId = queryValue(url, "ruleId", RULE_ID_PATTERN);
  if (ruleId && !ruleIds.has(ruleId)) {
    throw new SecurityApiError(400, "invalid_query", "ruleId is unknown");
  }
  const severity = queryValue(url, "severity", /^[a-z]+$/, 16);
  if (severity && !SEVERITIES.has(severity)) {
    throw new SecurityApiError(400, "invalid_query", "severity is invalid");
  }
  return {
    ruleId,
    severity,
    organizationId: queryValue(url, "organizationId", FILTER_PATTERN),
    subjectId: queryValue(url, "subjectId", FILTER_PATTERN),
    since: timestampQuery(url, "since"),
    limit: integerQuery(url, "limit", 100),
  };
}

function aggregateFilters(url, ruleIds, includeActiveOnly) {
  const allowed = new Set(["ruleId", "organizationId", "subjectId", "limit"]);
  if (includeActiveOnly) allowed.add("activeOnly");
  assertQueryKeys(url, allowed);
  const ruleId = queryValue(url, "ruleId", RULE_ID_PATTERN);
  if (ruleId && !ruleIds.has(ruleId)) {
    throw new SecurityApiError(400, "invalid_query", "ruleId is unknown");
  }
  return {
    ruleId,
    organizationId: queryValue(url, "organizationId", FILTER_PATTERN),
    subjectId: queryValue(url, "subjectId", FILTER_PATTERN),
    limit: integerQuery(url, "limit", 100),
    activeOnly: includeActiveOnly ? booleanQuery(url, "activeOnly") : false,
  };
}

function publicIngestResult(eventId, result) {
  return {
    accepted: true,
    duplicate: result.duplicate,
    eventId,
    alertIds: result.alertIds,
    findingIds: result.findings.map((finding) => finding.findingId),
    aggregateIds: result.aggregateIds,
  };
}

function controlOrganization(req) {
  const value = String(req.headers["x-magpie-organization"] || "").trim();
  if (!value || value.length > 128 || !FILTER_PATTERN.test(value)) {
    throw new SecurityApiError(
      400,
      "invalid_organization",
      "X-Magpie-Organization must be a valid organization id",
    );
  }
  return value;
}

function idempotencyKey(req) {
  return normalizeIdempotencyKey(String(req.headers["idempotency-key"] || "").trim());
}

function responseActionFilters(url) {
  assertQueryKeys(url, new Set([
    "status",
    "actionType",
    "sourceType",
    "sourceId",
    "targetType",
    "targetId",
    "limit",
  ]));
  const status = queryValue(url, "status", /^[a-z]+$/, 32);
  if (status && !RESPONSE_ACTION_STATUS_SET.has(status)) {
    throw new SecurityApiError(400, "invalid_query", "status is invalid");
  }
  const actionType = queryValue(url, "actionType", /^[a-z_]+$/, 32);
  if (actionType && !RESPONSE_ACTION_TYPE_SET.has(actionType)) {
    throw new SecurityApiError(400, "invalid_query", "actionType is invalid");
  }
  const sourceType = queryValue(url, "sourceType", /^[a-z]+$/, 16);
  if (sourceType && !RESPONSE_SOURCE_TYPES.has(sourceType)) {
    throw new SecurityApiError(400, "invalid_query", "sourceType is invalid");
  }
  const targetType = queryValue(url, "targetType", /^[a-z_]+$/, 32);
  if (targetType && !RESPONSE_TARGET_TYPES.has(targetType)) {
    throw new SecurityApiError(400, "invalid_query", "targetType is invalid");
  }
  return {
    status,
    actionType,
    sourceType,
    sourceId: queryValue(url, "sourceId", FILTER_PATTERN),
    targetType,
    targetId: queryValue(url, "targetId", FILTER_PATTERN),
    limit: integerQuery(url, "limit", 100),
  };
}

function responseActionResult(result) {
  const action = publicResponseAction(result.action);
  return {
    action,
    enforcement: action.enforcement,
    replayed: result.replayed,
  };
}

function routeOf(pathname) {
  if (pathname === "/healthz") return { name: "health" };
  if (pathname === "/api/v1/detection-events") return { name: "ingest", access: "write" };
  if (pathname === "/api/v1/rules") return { name: "rules", access: "read" };
  if (pathname === "/api/v1/stats") return { name: "stats", access: "read" };
  if (pathname === "/api/v1/findings") return { name: "findings", access: "read" };
  if (pathname === "/api/v1/aggregates") return { name: "aggregates", access: "read" };
  if (pathname === "/api/v1/suppressions") return { name: "suppressions", access: "read" };
  if (pathname === "/metrics") return { name: "metrics", access: "read" };
  if (pathname === "/api/v1/response-actions") {
    return { name: "response-actions", access: "control" };
  }
  const responseActionMatch = /^\/api\/v1\/response-actions\/([^/]+)(?:\/(approve|activate|revert|expire|audit))?$/.exec(pathname);
  if (responseActionMatch) {
    return {
      name: responseActionMatch[2] || "response-action",
      actionId: responseActionMatch[1],
      access: "control",
    };
  }
  const alertMatch = /^\/api\/v1\/alerts(?:\/([^/]+))?(?:\/(audit|assign|acknowledge|resolve|reopen))?$/.exec(pathname);
  if (alertMatch) {
    return {
      name: alertMatch[3]
        ? `alert-${alertMatch[3]}`
        : alertMatch[1]
          ? "alert"
          : "alerts",
      alertId: alertMatch[1],
      access: "alert",
    };
  }
  return { name: "not_found" };
}

class FixedWindowRateLimiter {
  constructor(perMinute, now) {
    this.perMinute = perMinute;
    this.now = now;
    this.windowStart = 0;
    this.counts = new Map();
  }

  allow(key) {
    const windowStart = Math.floor(this.now() / 60_000) * 60_000;
    if (windowStart !== this.windowStart) {
      this.windowStart = windowStart;
      this.counts.clear();
    }
    const count = (this.counts.get(key) || 0) + 1;
    this.counts.set(key, count);
    return count <= this.perMinute;
  }
}

export async function createSecurityServer(config, options = {}) {
  const policy = createDetectionPolicy(config.policy);
  const ruleIds = new Set(describeRules(policy).map((rule) => rule.ruleId));
  const clock = typeof options.now === "function" ? options.now : Date.now;
  const store = options.store || new SecurityStore(config.storePath, {
    maxEvents: config.maxEvents,
    maxFindings: config.maxFindings,
    maxResponseActions: config.maxResponseActions,
    maxStoreBytes: config.maxStoreBytes,
    maxAlerts: config.maxAlerts,
    now: clock,
    executor: options.responseExecutor,
  });
  if (!options.store) await store.init();
  const logger = options.logger || (() => {});
  const limiter = new FixedWindowRateLimiter(config.rateLimitPerMinute, clock);

  const server = http.createServer(async (req, res) => {
    const reqId = requestId();
    try {
      const url = new URL(req.url || "/", "http://localhost");
      const route = routeOf(url.pathname);

      if (route.name === "health") {
        if (req.method !== "GET") {
          throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
        }
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          service: "security-service",
          status: "ready",
        }, reqId);
        return;
      }

      if (!limiter.allow(req.socket.remoteAddress || "unknown")) {
        throw new SecurityApiError(429, "rate_limited", "Too many requests", true);
      }

      if (route.name === "not_found") {
        throw new SecurityApiError(404, "not_found", "Route not found");
      }
      const expectedToken = route.access === "write"
        ? config.ingestToken
        : route.access === "control"
          ? config.controlToken
          : route.access === "alert"
            ? route.name === "alerts" || route.name === "alert"
              ? config.readToken
              : config.controlToken
            : config.readToken;
      if (!safeEqual(bearerToken(req), expectedToken)) {
        throw new SecurityApiError(
          401,
          "unauthorized",
          route.access === "write"
            ? "A valid ingest token is required"
            : route.access === "control"
              ? "A valid control token is required"
              : route.access === "alert"
                ? "A valid alert token is required"
                : "A valid read token is required",
        );
      }

      if (route.name === "ingest") {
        if (req.method !== "POST") {
          throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
        }
        const body = await readJsonBody(req, config.maxBodyBytes);
        const event = validateDetectionEvent(body);
        const result = await store.ingest(event, {
          requestId: reqId,
          now: new Date(clock()),
          evaluate: (detectionEvent, { now }) => {
            const findings = evaluateDetectionEvent(detectionEvent, policy, { now });
            if (findings.some((finding) => finding.eventId !== detectionEvent.eventId)) {
              throw new Error("rule evaluator returned a finding for another event");
            }
            return findings;
          },
          suppressionWindowSeconds: policy.suppressionWindowSeconds,
        });
        jsonResponse(res, result.duplicate ? 200 : 202, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          ...publicIngestResult(event.eventId, result),
        }, reqId);
        return;
      }

      if (route.name === "rules") {
        if (req.method !== "GET") {
          throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
        }
        assertQueryKeys(url, new Set());
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          suppressionWindowSeconds: policy.suppressionWindowSeconds,
          rules: describeRules(policy),
        }, reqId);
        return;
      }

      if (route.name === "stats") {
        if (req.method !== "GET") {
          throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
        }
        assertQueryKeys(url, new Set());
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          ...(await store.stats()),
        }, reqId);
        return;
      }

      if (route.name === "metrics") {
        if (req.method !== "GET") {
          throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
        }
        assertQueryKeys(url, new Set());
        const snapshot = await store.metricsSnapshot();
        const body = renderPrometheusMetrics(snapshot);
        res.writeHead(200, {
          "content-type": "text/plain; version=0.0.4; charset=utf-8",
          "cache-control": "no-store",
          "content-length": Buffer.byteLength(body),
          "x-content-type-options": "nosniff",
          "x-request-id": reqId,
        });
        res.end(body);
        return;
      }

      if (route.name === "findings") {
        if (req.method !== "GET") {
          throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
        }
        const findings = await store.listFindings(findingFilters(url, ruleIds));
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          findings,
        }, reqId);
        return;
      }

      if (route.name === "aggregates") {
        if (req.method !== "GET") {
          throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
        }
        const aggregates = await store.listAggregates(aggregateFilters(url, ruleIds, false));
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          aggregates,
        }, reqId);
        return;
      }

      if (route.name === "suppressions") {
        if (req.method !== "GET") {
          throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
        }
        const suppressions = await store.listSuppressions(
          aggregateFilters(url, ruleIds, true),
        );
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          suppressions,
        }, reqId);
        return;
      }

      if (route.name === "alerts" || route.name === "alert") {
        const organizationId = controlOrganization(req);
        if (route.name === "alerts") {
          if (req.method === "GET") {
            assertQueryKeys(url, new Set([
              "status",
              "severity",
              "ruleId",
              "subjectId",
              "assigneeSubjectId",
              "unassigned",
              "overdue",
              "activeOnly",
              "limit",
            ]));
            const filters = {
              organizationId,
              status: queryValue(url, "status", /^[a-z]+$/, 32),
              severity: queryValue(url, "severity", /^[a-z]+$/, 16),
              ruleId: queryValue(url, "ruleId", RULE_ID_PATTERN),
              subjectId: queryValue(url, "subjectId", FILTER_PATTERN),
              assigneeSubjectId: queryValue(url, "assigneeSubjectId", FILTER_PATTERN),
              unassigned: booleanQuery(url, "unassigned"),
              overdue: booleanQuery(url, "overdue"),
              activeOnly: booleanQuery(url, "activeOnly"),
              limit: integerQuery(url, "limit", 100),
            };
            if (filters.status && !ALERT_STATUSES_SET.has(filters.status)) {
              throw new SecurityApiError(400, "invalid_query", "status is invalid");
            }
            if (filters.severity && !ALERT_SEVERITIES_SET.has(filters.severity)) {
              throw new SecurityApiError(400, "invalid_query", "severity is invalid");
            }
            const alerts = await store.listAlerts(filters);
            jsonResponse(res, 200, {
              schemaVersion: SCHEMA_VERSION,
              ok: true,
              alerts: alerts.map(publicAlert),
            }, reqId);
            return;
          }
          if (req.method !== "POST") {
            throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
          }
          assertQueryKeys(url, new Set());
          const key = idempotencyKey(req);
          const body = normalizeAlertCreateRequest(
            await readJsonBody(req, config.maxBodyBytes),
          );
          if (body.organizationId !== organizationId) {
            throw new SecurityApiError(
              403,
              "organization_mismatch",
              "X-Magpie-Organization does not match the request organization",
            );
          }
          const result = await store.createAlert({
            organizationId: body.organizationId,
            source: body.source,
            actorSubjectId: body.actorSubjectId,
            assigneeSubjectId: body.assigneeSubjectId,
            reason: body.reason,
          }, {
            idempotencyKeyHash: alertIdempotencyHash(key),
            requestDigest: alertRequestDigest("create", organizationId, "", body),
            requestId: reqId,
            now: new Date(clock()),
            organizationId,
          });
          jsonResponse(res, result.replayed ? 200 : 201, {
            schemaVersion: SCHEMA_VERSION,
            ok: true,
            alert: publicAlert(result.alert),
            replayed: result.replayed,
          }, reqId);
          return;
        }
        if (!isAlertId(route.alertId)) {
          throw new SecurityApiError(400, "invalid_alert_id", "Alert id is invalid");
        }
        if (req.method !== "GET") {
          throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
        }
        assertQueryKeys(url, new Set());
        const alert = await store.getAlert(route.alertId, organizationId);
        if (!alert) {
          throw new SecurityApiError(404, "alert_not_found", "Alert not found");
        }
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          alert: publicAlert(alert),
        }, reqId);
        return;
      }

      if (["alert-audit", "alert-assign", "alert-acknowledge", "alert-resolve", "alert-reopen"].includes(route.name)) {
        const organizationId = controlOrganization(req);
        if (!isAlertId(route.alertId)) {
          throw new SecurityApiError(400, "invalid_alert_id", "Alert id is invalid");
        }
        if (route.name === "alert-audit") {
          if (req.method !== "GET") {
            throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
          }
          assertQueryKeys(url, new Set());
          const audits = await store.listAlertAudits(route.alertId, organizationId);
          if (!audits) {
            throw new SecurityApiError(404, "alert_not_found", "Alert not found");
          }
          jsonResponse(res, 200, {
            schemaVersion: SCHEMA_VERSION,
            ok: true,
            alertId: route.alertId,
            audits: audits.map(publicAlertAudit),
          }, reqId);
          return;
        }
        if (req.method !== "POST") {
          throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
        }
        assertQueryKeys(url, new Set());
        const key = idempotencyKey(req);
        const rawBody = await readJsonBody(req, config.maxBodyBytes);
        let result;
        if (route.name === "alert-assign") {
          const body = normalizeAlertAssignRequest(rawBody);
          result = await store.assignAlert(route.alertId, {
            organizationId,
            assigneeSubjectId: body.assigneeSubjectId,
            actorSubjectId: body.actorSubjectId,
            reason: body.reason,
            source: { type: "finding", id: "" },
          }, {
            idempotencyKeyHash: alertIdempotencyHash(key),
            requestDigest: alertRequestDigest("assign", organizationId, route.alertId, body),
            requestId: reqId,
            now: new Date(clock()),
            organizationId,
          });
        } else if (route.name === "alert-acknowledge") {
          const body = normalizeAlertActorRequest(rawBody);
          result = await store.acknowledgeAlert(route.alertId, {
            organizationId,
            actorSubjectId: body.actorSubjectId,
            reason: body.reason,
            source: { type: "finding", id: "" },
          }, {
            idempotencyKeyHash: alertIdempotencyHash(key),
            requestDigest: alertRequestDigest("acknowledge", organizationId, route.alertId, body),
            requestId: reqId,
            now: new Date(clock()),
            organizationId,
          });
        } else if (route.name === "alert-resolve") {
          const body = normalizeAlertResolveRequest(rawBody);
          result = await store.resolveAlert(route.alertId, {
            organizationId,
            actorSubjectId: body.actorSubjectId,
            reason: body.reason,
            resolutionCode: body.resolutionCode,
            source: { type: "finding", id: "" },
          }, {
            idempotencyKeyHash: alertIdempotencyHash(key),
            requestDigest: alertRequestDigest("resolve", organizationId, route.alertId, body),
            requestId: reqId,
            now: new Date(clock()),
            organizationId,
          });
        } else if (route.name === "alert-reopen") {
          const body = normalizeAlertActorRequest(rawBody);
          result = await store.reopenAlert(route.alertId, {
            organizationId,
            actorSubjectId: body.actorSubjectId,
            reason: body.reason,
            source: { type: "finding", id: "" },
          }, {
            idempotencyKeyHash: alertIdempotencyHash(key),
            requestDigest: alertRequestDigest("reopen", organizationId, route.alertId, body),
            requestId: reqId,
            now: new Date(clock()),
            organizationId,
          });
        }
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          alert: publicAlert(result.alert),
          replayed: result.replayed,
        }, reqId);
        return;
      }

      if (route.name === "response-actions") {
        const organizationId = controlOrganization(req);
        if (req.method === "GET") {
          const actions = await store.listResponseActions({
            ...responseActionFilters(url),
            organizationId,
          });
          jsonResponse(res, 200, {
            schemaVersion: SCHEMA_VERSION,
            ok: true,
            actions: actions.map(publicResponseAction),
          }, reqId);
          return;
        }
        if (req.method !== "POST") {
          throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
        }
        assertQueryKeys(url, new Set());
        const key = idempotencyKey(req);
        const body = normalizeResponseActionRequest(
          await readJsonBody(req, config.maxBodyBytes),
        );
        if (body.organizationId !== organizationId) {
          throw new SecurityApiError(
            403,
            "organization_mismatch",
            "X-Magpie-Organization does not match the request organization",
          );
        }
        const result = await store.createResponseAction(body, {
          idempotencyKeyHash: responseIdempotencyHash(key),
          requestDigest: responseRequestDigest("create", organizationId, "", body),
          requestId: reqId,
          now: new Date(clock()),
        });
        jsonResponse(res, result.replayed ? 200 : 201, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          ...responseActionResult(result),
        }, reqId);
        return;
      }

      if ([
        "response-action",
        "approve",
        "activate",
        "revert",
        "expire",
        "audit",
      ].includes(route.name)) {
        if (!isResponseActionId(route.actionId)) {
          throw new SecurityApiError(
            400,
            "invalid_response_action_id",
            "Response action id is invalid",
          );
        }
        const organizationId = controlOrganization(req);
        if (route.name === "response-action") {
          if (req.method !== "GET") {
            throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
          }
          assertQueryKeys(url, new Set());
          const action = await store.getResponseAction(route.actionId, organizationId);
          if (!action) {
            throw new SecurityApiError(
              404,
              "response_action_not_found",
              "Response action not found",
            );
          }
          const publicAction = publicResponseAction(action);
          jsonResponse(res, 200, {
            schemaVersion: SCHEMA_VERSION,
            ok: true,
            action: publicAction,
            enforcement: publicAction.enforcement,
          }, reqId);
          return;
        }
        if (route.name === "audit") {
          if (req.method !== "GET") {
            throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
          }
          assertQueryKeys(url, new Set());
          const audits = await store.listResponseAudits(route.actionId, organizationId);
          if (!audits) {
            throw new SecurityApiError(
              404,
              "response_action_not_found",
              "Response action not found",
            );
          }
          jsonResponse(res, 200, {
            schemaVersion: SCHEMA_VERSION,
            ok: true,
            actionId: route.actionId,
            audits: audits.map(publicResponseAudit),
          }, reqId);
          return;
        }
        if (req.method !== "POST") {
          throw new SecurityApiError(405, "method_not_allowed", "Method not allowed");
        }
        assertQueryKeys(url, new Set());
        const key = idempotencyKey(req);
        const rawBody = await readJsonBody(req, config.maxBodyBytes);
        let result;
        if (route.name === "approve") {
          const body = normalizeApprovalRequest(rawBody);
          result = await store.approveResponseAction(route.actionId, body, {
            idempotencyKeyHash: responseIdempotencyHash(key),
            requestDigest: responseRequestDigest(
              "approve",
              organizationId,
              route.actionId,
              body,
            ),
            requestId: reqId,
            now: new Date(clock()),
            organizationId,
          });
        } else {
          const body = normalizeActorRequest(rawBody);
          const operation = route.name;
          const operationInput = {
            idempotencyKeyHash: responseIdempotencyHash(key),
            requestDigest: responseRequestDigest(
              operation,
              organizationId,
              route.actionId,
              body,
            ),
            requestId: reqId,
            now: new Date(clock()),
            organizationId,
          };
          if (route.name === "activate") {
            result = await store.activateResponseAction(
              route.actionId,
              body,
              operationInput,
            );
          } else if (route.name === "revert") {
            result = await store.revertResponseAction(
              route.actionId,
              body,
              operationInput,
            );
          } else {
            result = await store.expireResponseAction(
              route.actionId,
              body,
              operationInput,
            );
          }
        }
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          ...responseActionResult(result),
        }, reqId);
        return;
      }

      throw new SecurityApiError(404, "not_found", "Route not found");
    } catch (error) {
      errorResponse(res, reqId, error, logger);
    }
  });

  const close = async () => {
    if (!server.listening) return;
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  };

  return {
    server,
    store,
    policy,
    close,
  };
}
