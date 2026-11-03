import crypto from "node:crypto";
import http from "node:http";

import {
  DetectionEventValidationError,
  validateDetectionEvent,
  validateTimestamp,
} from "./events.js";
import { evaluateDetectionEvent } from "./evaluator.js";
import { createDetectionPolicy, describeRules } from "./rules.js";
import { SecurityStore, SecurityStoreError } from "./store.js";

const SCHEMA_VERSION = 1;
const RULE_ID_PATTERN = /^sec\.[a-z0-9._-]+$/;
const FILTER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const SEVERITIES = new Set(["warning", "high", "critical"]);
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
    findingIds: result.findings.map((finding) => finding.findingId),
    aggregateIds: result.aggregateIds,
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
    maxStoreBytes: config.maxStoreBytes,
    now: clock,
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
      const expectedToken = route.access === "write" ? config.ingestToken : config.readToken;
      if (!safeEqual(bearerToken(req), expectedToken)) {
        throw new SecurityApiError(
          401,
          "unauthorized",
          route.access === "write"
            ? "A valid ingest token is required"
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
