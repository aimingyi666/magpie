import crypto from "node:crypto";
import http from "node:http";

import { ContentStore } from "./content-store.js";
import {
  ContentApiError,
  contentRoute,
  handleContentRoute,
} from "./content-service.js";
import { ContentGrantManager } from "./content-grant.js";
import { ContentDeletionManager } from "./content-deletion.js";
import { ContentExportManager } from "./content-export.js";
import { ContentLegalHoldManager } from "./content-legal-hold.js";
import { ContentRetentionManager } from "./content-retention.js";
import { ContentRetrieval } from "./content-retrieval.js";
import { ContentStreamManager } from "./content-streams.js";
import { AuditPipeline } from "./pipeline.js";
import { AuditStore } from "./store.js";
import {
  AUDIT_EVENT_SCHEMA_VERSION,
  AuditEventValidationError,
  validateAuditEvent,
  validateTimestamp,
} from "./events.js";

const SCHEMA_VERSION = 1;
const IDEMPOTENCY_KEY_PATTERN = /^[\u0021-\u007e]{1,128}$/;
const FILTER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,191}$/;
const STATUS_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const MAX_QUERY_LIMIT = 500;

class ApiError extends Error {
  constructor(statusCode, code, message, retryable = false) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.retryable = retryable;
  }
}

function requestId() {
  return crypto.randomUUID();
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
  const normalized = error instanceof ApiError
    || error instanceof AuditEventValidationError
    || error instanceof ContentApiError
    ? error
    : new ApiError(500, "internal_error", "The audit service could not complete the request", true);
  if (!(error instanceof ApiError)
      && !(error instanceof AuditEventValidationError)
      && !(error instanceof ContentApiError)
      && logger) {
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

function idempotencyKey(req) {
  const key = String(req.headers["idempotency-key"] || "").trim();
  if (!IDEMPOTENCY_KEY_PATTERN.test(key)) {
    throw new ApiError(400, "idempotency_key_required", "A valid Idempotency-Key header is required");
  }
  return key;
}

async function readJsonBody(req, maximumBytes) {
  const contentType = String(req.headers["content-type"] || "");
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new ApiError(415, "unsupported_media_type", "Content-Type must be application/json");
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > maximumBytes) {
      throw new ApiError(413, "request_too_large", "Audit event exceeds the configured size limit");
    }
    chunks.push(chunk);
  }
  if (bytes === 0) throw new ApiError(400, "invalid_request", "A JSON request body is required");
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new ApiError(400, "invalid_json", "The request body must be valid JSON");
  }
}

function queryValue(url, name, pattern, maximum = 192) {
  const value = url.searchParams.get(name);
  if (value == null || value === "") return "";
  if (value.length > maximum || !pattern.test(value)) {
    throw new ApiError(400, "invalid_query", `${name} is invalid`);
  }
  return value;
}

function timestampQuery(url, name) {
  const value = url.searchParams.get(name);
  if (value == null || value === "") return "";
  try {
    return validateTimestamp(value, name);
  } catch {
    throw new ApiError(400, "invalid_query", `${name} is invalid`);
  }
}

function integerQuery(url, name, fallback, maximum) {
  const raw = url.searchParams.get(name);
  if (raw == null || raw === "") return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new ApiError(400, "invalid_query", `${name} is invalid`);
  }
  return value;
}

function encodeCursor(event) {
  return Buffer.from(JSON.stringify({
    occurredAt: event.occurredAt,
    eventId: event.eventId,
  })).toString("base64url");
}

function decodeCursor(value) {
  if (!value) return null;
  if (!/^[A-Za-z0-9_-]{16,512}$/.test(value)) {
    throw new ApiError(400, "invalid_cursor", "cursor is invalid");
  }
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
    if (!parsed
        || typeof parsed !== "object"
        || typeof parsed.eventId !== "string"
        || !/^evt_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(parsed.eventId)) {
      throw new Error("invalid cursor");
    }
    return {
      occurredAt: validateTimestamp(parsed.occurredAt, "cursor"),
      eventId: parsed.eventId,
    };
  } catch {
    throw new ApiError(400, "invalid_cursor", "cursor is invalid");
  }
}

function afterCursor(event, cursor) {
  if (!cursor) return true;
  return event.occurredAt < cursor.occurredAt
    || (event.occurredAt === cursor.occurredAt && event.eventId < cursor.eventId);
}

function eventMatches(event, filters) {
  return (!filters.requestId || event.requestId === filters.requestId)
    && (!filters.sessionId || event.sessionId === filters.sessionId)
    && (!filters.userId || event.userId === filters.userId)
    && (!filters.departmentId || event.departmentId === filters.departmentId)
    && (!filters.deviceId || event.deviceId === filters.deviceId)
    && (!filters.modelId || event.modelId === filters.modelId)
    && (!filters.toolName || event.toolName === filters.toolName)
    && (!filters.status || event.status === filters.status)
    && (!filters.from || event.occurredAt >= filters.from)
    && (!filters.to || event.occurredAt <= filters.to);
}

function publicEvent(event) {
  return structuredClone(event);
}

function publicSession(session) {
  return structuredClone(session);
}

function parseFilters(url) {
  const filters = {
    requestId: queryValue(url, "requestId", /^req_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/, 135),
    sessionId: queryValue(url, "sessionId", /^ses_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/, 135),
    userId: queryValue(url, "userId", FILTER_PATTERN),
    departmentId: queryValue(url, "departmentId", FILTER_PATTERN),
    deviceId: queryValue(url, "deviceId", FILTER_PATTERN),
    modelId: queryValue(url, "modelId", /^[A-Za-z0-9][A-Za-z0-9._@:+-]*\/[A-Za-z0-9][A-Za-z0-9._:@+-]{0,191}$/, 256),
    toolName: queryValue(url, "toolName", FILTER_PATTERN),
    status: queryValue(url, "status", STATUS_PATTERN, 64),
    from: timestampQuery(url, "from"),
    to: timestampQuery(url, "to"),
  };
  if (filters.from && filters.to && filters.from > filters.to) {
    throw new ApiError(400, "invalid_query", "from must not be after to");
  }
  return filters;
}

function eventList(store, url) {
  const filters = parseFilters(url);
  const limit = integerQuery(url, "limit", 100, MAX_QUERY_LIMIT);
  const cursor = decodeCursor(url.searchParams.get("cursor"));
  return store.read((data) => {
    const matching = Object.values(data.events)
      .filter((event) => eventMatches(event, filters))
      .sort((left, right) => right.occurredAt.localeCompare(left.occurredAt)
        || right.eventId.localeCompare(left.eventId))
      .filter((event) => afterCursor(event, cursor));
    const page = matching.slice(0, limit);
    return {
      events: page.map(publicEvent),
      nextCursor: matching.length > limit ? encodeCursor(page[page.length - 1]) : null,
    };
  });
}

function sessionList(store, url) {
  const userId = queryValue(url, "userId", FILTER_PATTERN);
  const departmentId = queryValue(url, "departmentId", FILTER_PATTERN);
  const limit = integerQuery(url, "limit", 100, MAX_QUERY_LIMIT);
  return store.read((data) => ({
    sessions: Object.values(data.sessions)
      .filter((session) => (!userId || session.userIds.includes(userId))
        && (!departmentId || session.departmentIds.includes(departmentId)))
      .sort((left, right) => right.lastOccurredAt.localeCompare(left.lastOccurredAt)
        || right.sessionId.localeCompare(left.sessionId))
      .slice(0, limit)
      .map(publicSession),
  }));
}

class FixedWindowRateLimiter {
  constructor(perMinute, now = Date.now) {
    this.perMinute = perMinute;
    this.now = now;
    this.windowStart = 0;
    this.counts = new Map();
  }

  allow(key) {
    const now = this.now();
    const windowStart = Math.floor(now / 60_000) * 60_000;
    if (windowStart !== this.windowStart) {
      this.windowStart = windowStart;
      this.counts.clear();
    }
    const count = (this.counts.get(key) || 0) + 1;
    this.counts.set(key, count);
    return count <= this.perMinute;
  }
}

function routeOf(pathname) {
  if (pathname === "/healthz") return { name: "health" };
  if (pathname === "/api/v1/internal/audit/events") return { name: "ingest" };
  if (pathname === "/api/v1/admin/audit/events") return { name: "events" };
  if (pathname === "/api/v1/admin/audit/sessions") return { name: "sessions" };
  if (pathname === "/api/v1/admin/audit/stats") return { name: "stats" };
  const session = /^\/api\/v1\/admin\/audit\/sessions\/(ses_[A-Za-z0-9][A-Za-z0-9._:-]{7,127})$/.exec(pathname);
  if (session) return { name: "session", sessionId: session[1] };
  const content = contentRoute(pathname);
  if (content) return content;
  return { name: "not_found" };
}

export async function createAuditServer(config, options = {}) {
  if (config.contentGovernanceEnabled && !config.contentAdminEnabled) {
    throw new Error(
      "Content governance requires content administration to be enabled",
    );
  }
  if (config.contentExportEnabled && !config.contentGovernanceEnabled) {
    throw new Error(
      "Content export requires content governance to be enabled",
    );
  }
  const store = options.store || new AuditStore(config.storePath, {
    maxEvents: config.maxEvents,
    maxQueueEvents: config.maxQueueEvents,
    maxSessions: config.maxSessions,
  });
  await store.load();
  const logger = options.logger || (() => {});
  const pipeline = options.pipeline || new AuditPipeline(store, {
    batchSize: config.batchSize,
    intervalMs: config.flushIntervalMs,
    logger,
  });
  const limiter = new FixedWindowRateLimiter(config.rateLimitPerMinute, options.nowMs || Date.now);
  let contentStore = null;
  let contentManager = null;
  let contentGrants = null;
  let contentRetrieval = null;
  let contentLegalHolds = null;
  let contentDeletion = null;
  let contentRetention = null;
  let contentExport = null;
  if (config.contentEnabled) {
    contentStore = options.contentStore || new ContentStore({
      directory: config.contentStoreDir,
      key: config.contentEncryptionKey,
      proofSecret: config.contentProofSecret,
      maxStreamBytes: config.contentMaxStreamBytes,
      now: options.nowMs || Date.now,
    });
    if (!options.contentStore) await contentStore.load();
    contentManager = options.contentManager || new ContentStreamManager(contentStore, {
      maxChunkBytes: config.contentMaxChunkBytes,
      maxStreamBytes: config.contentMaxStreamBytes,
      maxTotalBufferBytes: config.contentMaxBufferBytes,
      maxActiveStreams: config.contentMaxActiveStreams,
      streamTtlMs: config.contentStreamTtlMs,
      now: options.nowMs || Date.now,
    });
    if (!options.contentManager) contentManager.start();
    if (config.contentAdminEnabled) {
      contentGrants = options.contentGrants || new ContentGrantManager({
        filePath: config.contentGrantStorePath,
        secret: config.contentGrantSecret,
        defaultTtlSeconds: config.contentGrantTtlSeconds,
        maxTtlSeconds: 300,
        now: options.nowMs || Date.now,
      });
      if (!options.contentGrants) await contentGrants.load();
      contentRetrieval = options.contentRetrieval || new ContentRetrieval(contentStore, {
        cursorSecret: config.contentCursorSecret,
      });
    }
  }
  if (config.contentGovernanceEnabled) {
    contentLegalHolds = options.contentLegalHolds || new ContentLegalHoldManager(
      contentStore,
      {
        sessionSecret: config.contentProofSecret,
        organizationId: config.contentOrganizationId,
        now: options.nowMs || Date.now,
      },
    );
    contentDeletion = options.contentDeletion || new ContentDeletionManager(
      contentStore,
      {
        proofSecret: config.contentProofSecret,
        legalHolds: contentLegalHolds,
        now: options.nowMs || Date.now,
      },
    );
    if (config.contentExportEnabled) {
      contentExport = options.contentExport || new ContentExportManager(
        contentStore,
        {
          secret: config.contentExportSecret,
          key: config.contentExportKey,
          organizationId: config.contentOrganizationId,
          defaultTtlSeconds: config.contentExportTtlSeconds,
          now: options.nowMs || Date.now,
        },
      );
    }
    contentRetention = options.contentRetention || new ContentRetentionManager(
      contentStore,
      {
        deletion: contentDeletion,
        legalHolds: contentLegalHolds,
        exports: contentExport,
        organizationId: config.contentOrganizationId,
        intervalMs: config.contentRetentionSweepIntervalMs,
        now: options.nowMs || Date.now,
        logger,
      },
    );
    if (!options.contentRetention) contentRetention.start();
  }
  const content = {
    enabled: Boolean(config.contentEnabled),
    adminEnabled: Boolean(config.contentAdminEnabled),
    governanceEnabled: Boolean(config.contentGovernanceEnabled),
    exportEnabled: Boolean(config.contentExportEnabled),
    organizationId: config.contentOrganizationId,
    adminToken: config.contentAdminToken,
    governanceToken: config.contentGovernanceToken,
    store: contentStore,
    manager: contentManager,
    grants: contentGrants,
    retrieval: contentRetrieval,
    legalHolds: contentLegalHolds,
    deletion: contentDeletion,
    retention: contentRetention,
    export: contentExport,
  };

  const server = http.createServer(async (req, res) => {
    const reqId = requestId();
    try {
      const url = new URL(req.url || "/", "http://localhost");
      const route = routeOf(url.pathname);
      if (route.name === "health") {
        if (req.method !== "GET") throw new ApiError(405, "method_not_allowed", "Method not allowed");
        const status = await pipeline.status();
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          service: "audit-service",
          status: status.consecutiveFailures > 0 || status.queueDepth > 0 ? "degraded" : "ready",
          queueDepth: status.queueDepth,
        }, reqId);
        return;
      }
      if (!limiter.allow(req.socket.remoteAddress || "unknown")) {
        throw new ApiError(429, "rate_limited", "Too many requests", true);
      }
      if (!route.name.startsWith("content_")
          && !safeEqual(bearerToken(req), config.serviceToken)) {
        throw new ApiError(401, "unauthorized", "A valid service token is required");
      }

      if (route.name.startsWith("content_")) {
        await handleContentRoute({
          req,
          res,
          route,
          config,
          content,
          reqId,
        });
        return;
      }

      if (route.name === "ingest") {
        if (req.method !== "POST") throw new ApiError(405, "method_not_allowed", "Method not allowed");
        const key = idempotencyKey(req);
        const body = await readJsonBody(req, config.maxBodyBytes);
        let event;
        try {
          event = validateAuditEvent(body);
        } catch (error) {
          if (error instanceof AuditEventValidationError) {
            throw new ApiError(400, error.code, error.message);
          }
          throw error;
        }
        const result = await store.enqueue(event, key);
        if (result.conflict) {
          const code = result.reason === "event_id" ? "event_id_conflict" : "idempotency_conflict";
          throw new ApiError(409, code, "The event conflicts with an existing audit record");
        }
        if (result.queueFull) {
          throw new ApiError(503, "audit_queue_full", "The audit queue is full", true);
        }
        setImmediate(() => {
          void pipeline.drainSafely();
        });
        jsonResponse(res, result.duplicate ? 200 : 202, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          accepted: true,
          duplicate: result.duplicate,
          eventId: result.eventId,
          status: result.status,
        }, reqId);
        return;
      }

      if (route.name === "events") {
        if (req.method !== "GET") throw new ApiError(405, "method_not_allowed", "Method not allowed");
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          ...(await eventList(store, url)),
        }, reqId);
        return;
      }

      if (route.name === "sessions") {
        if (req.method !== "GET") throw new ApiError(405, "method_not_allowed", "Method not allowed");
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          ...(await sessionList(store, url)),
        }, reqId);
        return;
      }

      if (route.name === "session") {
        if (req.method !== "GET") throw new ApiError(405, "method_not_allowed", "Method not allowed");
        const result = await store.read((data) => {
          const session = data.sessions[route.sessionId];
          if (!session) return null;
          return {
            session: publicSession(session),
            events: Object.values(data.events)
              .filter((event) => event.sessionId === route.sessionId)
              .sort((left, right) => left.occurredAt.localeCompare(right.occurredAt)
                || left.eventId.localeCompare(right.eventId))
              .slice(0, 1000)
              .map(publicEvent),
          };
        });
        if (!result) throw new ApiError(404, "audit_session_not_found", "Audit session not found");
        jsonResponse(res, 200, { schemaVersion: SCHEMA_VERSION, ok: true, ...result }, reqId);
        return;
      }

      if (route.name === "stats") {
        if (req.method !== "GET") throw new ApiError(405, "method_not_allowed", "Method not allowed");
        const response = {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          ...(await pipeline.status()),
        };
        if (content.enabled) {
          response.content = {
            ...(await content.store.status()),
            ...content.manager.status(),
            ...(content.grants ? await content.grants.status() : {}),
          };
          response.contentGovernanceEnabled = Boolean(content.governanceEnabled);
          response.contentExportEnabled = Boolean(content.exportEnabled);
        }
        jsonResponse(res, 200, response, reqId);
        return;
      }

      throw new ApiError(404, "not_found", "Route not found");
    } catch (error) {
      errorResponse(res, reqId, error, logger);
    }
  });
  server.on("close", () => pipeline.stop());
  if (options.startPipeline !== false) pipeline.start();
  const close = async () => {
    pipeline.stop();
    if (server.listening) {
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
    if (content.retention) await content.retention.close();
    if (content.manager) await content.manager.close();
    if (content.grants) await content.grants.close();
    if (content.store) await content.store.close();
    await pipeline.drainAll();
  };
  return {
    server,
    store,
    pipeline,
    contentStore,
    contentManager,
    contentGrants,
    contentRetrieval,
    contentLegalHolds,
    contentDeletion,
    contentRetention,
    contentExport,
    contentStatus: () => (content.manager ? content.manager.status() : null),
    close,
  };
}
