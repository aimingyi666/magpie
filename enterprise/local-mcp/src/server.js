import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";

import {
  LocalMcpError,
  asLocalMcpError,
} from "./errors.js";

export const LOCAL_MCP_SERVER_SCHEMA_VERSION = 1;
export const DEFAULT_MAX_BODY_BYTES = 256 * 1024;
export const DEFAULT_HELPER_LOCK_STALE_MS = 15 * 60 * 1000;

const LOOPBACK_BINDS = new Set(["127.0.0.1", "::1"]);
const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MAX_URL_BYTES = 8 * 1024;
const MAX_TOKEN_BYTES = 4 * 1024;

class HttpError extends Error {
  constructor(status, code) {
    super(code);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
  }
}

function fail(code, message) {
  throw new LocalMcpError(code, message);
}

function requestId() {
  return crypto.randomUUID();
}

function canonicalScalar(value) {
  return value === undefined || value === null ? "" : String(value);
}

function digest(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest();
}

function timingSafeTokenMatch(presented, expected) {
  if (typeof presented !== "string"
      || typeof expected !== "string"
      || !presented
      || !expected
      || Buffer.byteLength(presented, "utf8") > MAX_TOKEN_BYTES) {
    return false;
  }
  return crypto.timingSafeEqual(digest(presented), digest(expected));
}

function isLoopbackAddress(address) {
  const value = canonicalScalar(address).toLowerCase();
  return value === "127.0.0.1"
    || value === "::1"
    || value === "::ffff:127.0.0.1";
}

function bearerToken(req) {
  const match = /^Bearer ([^\s]+)$/i.exec(canonicalScalar(req.headers.authorization));
  return match?.[1] ?? "";
}

function jsonResponse(res, id, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body, "utf8"),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-request-id": id,
  });
  res.end(body);
}

function errorResponse(res, id, error) {
  jsonResponse(res, id, error.status, {
    schemaVersion: LOCAL_MCP_SERVER_SCHEMA_VERSION,
    ok: false,
    error: { code: error.code },
  });
}

function statusForCode(code, fallback = 500) {
  switch (code) {
    case "invalid_resource_id":
    case "invalid_tool_name":
    case "invalid_request":
    case "invalid_json":
    case "unknown_field":
      return 400;
    case "unauthorized":
      return 401;
    case "key_unknown":
    case "publisher_denied":
    case "policy_denied":
    case "tool_denied":
    case "approval_required":
    case "approval_invalid":
      return 403;
    case "tool_not_found":
      return 404;
    case "resource_not_active":
    case "resource_not_mcp":
    case "resource_invalid":
    case "resource_drift":
    case "package_not_installed":
    case "package_invalid":
    case "package_conflict":
    case "package_tampered":
    case "metadata_mismatch":
    case "invalid_package":
    case "signature_invalid":
    case "path_traversal":
    case "path_symlink":
    case "duplicate_file":
    case "package_too_large":
    case "install_locked":
    case "client_version_incompatible":
    case "platform_incompatible":
    case "runtime_not_supported":
    case "helper_locked":
      return 409;
    case "request_too_large":
      return 413;
    case "unsupported_media_type":
      return 415;
    case "method_not_allowed":
      return 405;
    case "helper_state_unavailable":
    case "helper_state_invalid":
    case "helper_sync_invalid":
    case "secret_unavailable":
    case "secret_expired":
    case "audit_unavailable":
    case "health_write_failed":
      return 503;
    case "process_timeout":
      return 504;
    case "tool_failed":
    case "process_failed":
    case "protocol_invalid":
    case "protocol_too_large":
      return 502;
    default:
      return fallback;
  }
}

function normalizeError(error) {
  if (error instanceof HttpError) return error;
  const local = asLocalMcpError(error);
  return new HttpError(
    statusForCode(local.code),
    local.code,
  );
}

function assertToken(token) {
  if (typeof token !== "string"
      || Buffer.byteLength(token, "utf8") < 16
      || Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES
      || token.includes("\0")
      || token.includes("\n")
      || token.includes("\r")) {
    fail("invalid_config", "token must be a 16-4096 byte opaque value");
  }
}

function assertHelper(helper) {
  if (!helper
      || typeof helper.snapshot !== "function"
      || typeof helper.listTools !== "function"
      || typeof helper.callTool !== "function") {
    fail("invalid_config", "helper must provide snapshot(), listTools() and callTool()");
  }
}

function assertLoopbackBind(bind) {
  if (!LOOPBACK_BINDS.has(bind)) {
    fail("invalid_config", "bind must be a loopback address");
  }
}

function normalizeNow(now) {
  if (typeof now !== "function") fail("invalid_config", "now must be a function");
  return () => {
    const value = now();
    const milliseconds = value instanceof Date ? value.getTime() : Number(value);
    if (!Number.isFinite(milliseconds)) fail("invalid_config", "now returned an invalid value");
    return milliseconds;
  };
}

async function lstatOrNull(target) {
  try {
    return await fs.lstat(target);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function acquireHelperLock({
  helper,
  lockFile,
  rootDir,
  lockStaleMs,
  now,
}) {
  const resolvedRoot = rootDir || helper?.host?.rootDir;
  const target = lockFile
    ? path.resolve(lockFile)
    : typeof resolvedRoot === "string"
      ? path.join(path.resolve(resolvedRoot), "state", "helper.lock")
      : "";
  if (!target || !path.isAbsolute(target)) {
    fail("invalid_config", "a lockFile or local MCP rootDir is required");
  }
  await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
  const nonce = crypto.randomUUID();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const handle = await fs.open(target, "wx", 0o600);
      try {
        await handle.writeFile(JSON.stringify({
          schemaVersion: 1,
          pid: process.pid,
          createdAt: new Date(now()).toISOString(),
          nonce,
        }));
        await handle.sync();
      } finally {
        await handle.close();
      }
      return {
        lockFile: target,
        async release() {
          try {
            const parsed = JSON.parse(await fs.readFile(target, "utf8"));
            if (parsed.nonce === nonce) await fs.unlink(target);
          } catch (error) {
            if (error.code !== "ENOENT") throw error;
          }
        },
      };
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      const stat = await lstatOrNull(target);
      if (!stat || stat.isSymbolicLink() || !stat.isFile()) {
        fail("helper_locked", "helper lock path is unsafe or unavailable");
      }
      if (now() - stat.mtimeMs <= lockStaleMs) {
        fail("helper_locked", "another local MCP helper is already running");
      }
      await fs.unlink(target);
    }
  }
  fail("helper_locked", "another local MCP helper is already running");
}

async function readBody(req, maxBodyBytes) {
  const declared = req.headers["content-length"];
  if (declared !== undefined) {
    if (!/^\d+$/.test(canonicalScalar(declared))) {
      throw new HttpError(400, "invalid_request");
    }
    if (Number(declared) > maxBodyBytes) {
      throw new HttpError(413, "request_too_large");
    }
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBodyBytes) {
      req.resume();
      throw new HttpError(413, "request_too_large");
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, total);
}

function decodeJson(buffer) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
  } catch {
    throw new HttpError(400, "invalid_json");
  }
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("not an object");
    }
    return value;
  } catch {
    throw new HttpError(400, "invalid_json");
  }
}

function requireJsonBody(req) {
  const contentType = canonicalScalar(req.headers["content-type"]);
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) {
    throw new HttpError(415, "unsupported_media_type");
  }
}

function assertCallBody(body) {
  const fields = Object.keys(body);
  if (fields.some((field) => field !== "args" && field !== "approval")) {
    throw new HttpError(400, "unknown_field");
  }
  if (!Object.hasOwn(body, "args")
      || !body.args
      || typeof body.args !== "object"
      || Array.isArray(body.args)) {
    throw new HttpError(400, "invalid_request");
  }
  if (Object.hasOwn(body, "approval")
      && (!body.approval
        || typeof body.approval !== "object"
        || Array.isArray(body.approval))) {
    throw new HttpError(400, "invalid_request");
  }
}

function routeOf(pathname) {
  if (pathname === "/healthz") return { name: "health" };
  if (pathname === "/api/v1/local-mcp/status") return { name: "status" };
  const tools = /^\/api\/v1\/local-mcp\/resources\/([^/]+)\/tools$/.exec(pathname);
  if (tools) return { name: "tools", resourceId: tools[1] };
  const call = /^\/api\/v1\/local-mcp\/resources\/([^/]+)\/tools\/([^/]+)\/call$/.exec(pathname);
  if (call) return { name: "call", resourceId: call[1], toolName: call[2] };
  return { name: "not_found" };
}

function assertSafeRouteSegment(value, code) {
  if (typeof value !== "string" || !SAFE_SEGMENT.test(value)) {
    throw new HttpError(400, code);
  }
}

function safeLogger(logger, entry) {
  if (typeof logger !== "function") return;
  try {
    logger(entry);
  } catch {
    // Logging must not change the response.
  }
}

export async function createLocalMcpServer({
  helper,
  token,
  bind = "127.0.0.1",
  port = 0,
  lockFile = "",
  rootDir = "",
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
  lockStaleMs = DEFAULT_HELPER_LOCK_STALE_MS,
  now = Date.now,
  logger,
} = {}) {
  assertHelper(helper);
  assertToken(token);
  assertLoopbackBind(bind);
  if (!Number.isSafeInteger(maxBodyBytes)
      || maxBodyBytes < 1024
      || maxBodyBytes > 1024 * 1024) {
    fail("invalid_config", "maxBodyBytes must be 1-1024 KiB");
  }
  if (!Number.isSafeInteger(lockStaleMs) || lockStaleMs < 1000) {
    fail("invalid_config", "lockStaleMs is invalid");
  }
  const clock = normalizeNow(now);
  const lock = await acquireHelperLock({
    helper,
    lockFile,
    rootDir,
    lockStaleMs,
    now: clock,
  });

  const server = http.createServer(async (req, res) => {
    const id = requestId();
    const startedAt = Date.now();
    let routeName = "route";
    let code = "ok";
    const finish = () => safeLogger(logger, {
      time: new Date(clock()).toISOString(),
      requestId: id,
      method: req.method,
      route: routeName,
      status: res.statusCode,
      code,
      durationMs: Date.now() - startedAt,
    });
    try {
      if (!isLoopbackAddress(req.socket.remoteAddress)) {
        throw new HttpError(403, "loopback_only");
      }
      if (canonicalScalar(req.url).length > MAX_URL_BYTES) {
        throw new HttpError(414, "request_too_large");
      }
      const url = new URL(req.url || "/", "http://local-mcp.invalid");
      const route = routeOf(url.pathname);
      routeName = route.name;

      if (route.name === "health") {
        if (req.method !== "GET") throw new HttpError(405, "method_not_allowed");
        jsonResponse(res, id, 200, {
          schemaVersion: LOCAL_MCP_SERVER_SCHEMA_VERSION,
          ok: true,
          service: "local-mcp-helper",
          status: "ready",
        });
        return;
      }

      if (route.name === "not_found") {
        throw new HttpError(404, "not_found");
      }
      if (!timingSafeTokenMatch(bearerToken(req), token)) {
        throw new HttpError(401, "unauthorized");
      }

      if (route.name === "status") {
        if (req.method !== "GET") throw new HttpError(405, "method_not_allowed");
        jsonResponse(res, id, 200, await helper.snapshot());
        return;
      }

      assertSafeRouteSegment(route.resourceId, "invalid_resource_id");
      if (route.name === "tools") {
        if (req.method !== "GET") throw new HttpError(405, "method_not_allowed");
        jsonResponse(res, id, 200, await helper.listTools(route.resourceId));
        return;
      }

      assertSafeRouteSegment(route.toolName, "invalid_tool_name");
      if (req.method !== "POST") throw new HttpError(405, "method_not_allowed");
      requireJsonBody(req);
      const body = decodeJson(await readBody(req, maxBodyBytes));
      assertCallBody(body);
      const result = await helper.callTool(
        route.resourceId,
        route.toolName,
        body.args,
        body.approval === undefined ? {} : { approval: body.approval },
      );
      jsonResponse(res, id, 200, result);
    } catch (error) {
      const normalized = normalizeError(error);
      code = normalized.code;
      if (normalized.status === 413 && !req.complete) {
        res.shouldKeepAlive = false;
        req.resume();
      }
      if (!res.headersSent) errorResponse(res, id, normalized);
    } finally {
      finish();
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 100;
  server.setTimeout(30_000);

  let closePromise = null;
  const close = () => {
    if (closePromise) return closePromise;
    closePromise = (async () => {
      await new Promise((resolve) => {
        if (!server.listening) {
          resolve();
          return;
        }
        server.close(() => resolve());
      });
      await lock.release();
    })().catch((error) => {
      closePromise = null;
      throw error;
    });
    return closePromise;
  };

  const listen = () => new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      close().catch(() => {}).finally(() => reject(error));
    };
    const onListening = () => {
      server.off("error", onError);
      resolve(server.address());
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(port, bind);
  });

  return {
    server,
    lockFile: lock.lockFile,
    close,
    listen,
  };
}
