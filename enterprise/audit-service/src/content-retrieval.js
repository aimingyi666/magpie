import crypto from "node:crypto";

import {
  CONTENT_KINDS,
  publicContentStream,
  validateContentStreamId,
} from "./content-schema.js";
import { canonicalJson, validateTimestamp } from "./events.js";

const CURSOR_VERSION = 1;
const SORT_VERSION = "content-stream-createdAt-desc-v1";
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const MODEL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._:@+-]{0,159}$/;
const TOOL_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const STREAM_STATUSES = new Set(["collecting", "finalized", "failed"]);
const CONTENT_KIND_SET = new Set(CONTENT_KINDS);
const CURSOR_TOKEN_PATTERN = /^([A-Za-z0-9_-]{16,4096})\.([A-Za-z0-9_-]{43})$/;
const CURSOR_FIELDS = new Set(["v", "s", "f", "a"]);
const CURSOR_AFTER_FIELDS = new Set(["createdAt", "streamId"]);
const FILTER_NAMES = new Set([
  "userId",
  "departmentId",
  "deviceId",
  "agentId",
  "modelId",
  "mcpServerId",
  "toolName",
  "contentKind",
  "status",
  "from",
  "to",
]);
const QUERY_NAMES = new Set([...FILTER_NAMES, "limit", "cursor"]);

export class ContentRetrievalError extends Error {
  constructor(statusCode, code, message, retryable = false) {
    super(message);
    this.name = "ContentRetrievalError";
    this.statusCode = statusCode;
    this.code = code;
    this.retryable = retryable;
  }
}

function invalidQuery(name) {
  throw new ContentRetrievalError(400, "invalid_query", `${name} is invalid`);
}

function invalidCursor() {
  throw new ContentRetrievalError(400, "invalid_cursor", "cursor is invalid");
}

function singleQueryValue(url, name) {
  const values = url.searchParams.getAll(name);
  if (values.length > 1) invalidQuery(name);
  return values.length === 0 ? "" : values[0];
}

function filterValue(url, name, pattern, maximum = 128) {
  const value = singleQueryValue(url, name);
  if (!value) return "";
  if (value.length > maximum || !pattern.test(value)) invalidQuery(name);
  return value;
}

function timestampFilter(url, name) {
  const value = singleQueryValue(url, name);
  if (!value) return "";
  try {
    return validateTimestamp(value, name);
  } catch {
    invalidQuery(name);
  }
}

function enumFilter(url, name, values) {
  const value = singleQueryValue(url, name);
  if (!value) return "";
  if (!values.has(value)) invalidQuery(name);
  return value;
}

function limitFilter(url) {
  const raw = singleQueryValue(url, "limit");
  if (!raw) return DEFAULT_LIMIT;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_LIMIT) {
    invalidQuery("limit");
  }
  return value;
}

function parseFilters(url) {
  for (const name of url.searchParams.keys()) {
    if (!QUERY_NAMES.has(name)) invalidQuery(name);
  }
  const filters = {
    userId: filterValue(url, "userId", SAFE_ID_PATTERN),
    departmentId: filterValue(url, "departmentId", SAFE_ID_PATTERN),
    deviceId: filterValue(url, "deviceId", SAFE_ID_PATTERN),
    agentId: filterValue(url, "agentId", SAFE_ID_PATTERN),
    modelId: filterValue(url, "modelId", MODEL_ID_PATTERN, 192),
    mcpServerId: filterValue(url, "mcpServerId", SAFE_ID_PATTERN),
    toolName: filterValue(url, "toolName", TOOL_NAME_PATTERN),
    contentKind: enumFilter(url, "contentKind", CONTENT_KIND_SET),
    status: enumFilter(url, "status", STREAM_STATUSES),
    from: timestampFilter(url, "from"),
    to: timestampFilter(url, "to"),
  };
  if (filters.from && filters.to && filters.from > filters.to) {
    invalidQuery("from");
  }
  return Object.fromEntries(Object.entries(filters).filter(([, value]) => value));
}

function safeEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sign(encoded, secret) {
  return crypto.createHmac("sha256", secret).update(encoded).digest("base64url");
}

function encodeCursor(filters, item, secret) {
  const payload = {
    v: CURSOR_VERSION,
    s: SORT_VERSION,
    f: filters,
    a: {
      createdAt: item.createdAt,
      streamId: item.streamId,
    },
  };
  const encoded = Buffer.from(canonicalJson(payload), "utf8").toString("base64url");
  return `${encoded}.${sign(encoded, secret)}`;
}

function decodeCursor(value, filters, secret) {
  if (!value) return null;
  const match = CURSOR_TOKEN_PATTERN.exec(value);
  if (!match || !safeEqual(match[2], sign(match[1], secret))) invalidCursor();
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(match[1], "base64url").toString("utf8"));
  } catch {
    invalidCursor();
  }
  if (!parsed
      || typeof parsed !== "object"
      || Array.isArray(parsed)
      || Object.keys(parsed).length !== CURSOR_FIELDS.size
      || Object.keys(parsed).some((key) => !CURSOR_FIELDS.has(key))
      || parsed.v !== CURSOR_VERSION
      || parsed.s !== SORT_VERSION
      || !parsed.a
      || typeof parsed.a !== "object"
      || Array.isArray(parsed.a)
      || Object.keys(parsed.a).length !== CURSOR_AFTER_FIELDS.size
      || Object.keys(parsed.a).some((key) => !CURSOR_AFTER_FIELDS.has(key))
      || !parsed.f
      || typeof parsed.f !== "object"
      || Array.isArray(parsed.f)
      || Object.keys(parsed.f).some((key) => !FILTER_NAMES.has(key))) {
    invalidCursor();
  }
  try {
    validateContentStreamId(parsed.a.streamId);
    parsed.a.createdAt = validateTimestamp(parsed.a.createdAt, "cursor");
  } catch {
    invalidCursor();
  }
  if (canonicalJson(parsed.f || {}) !== canonicalJson(filters)) invalidCursor();
  return parsed.a;
}

export class ContentRetrieval {
  constructor(store, options = {}) {
    if (!store) throw new Error("ContentRetrieval store is required");
    if (typeof options.cursorSecret !== "string"
        || options.cursorSecret.length < 32) {
      throw new Error("ContentRetrieval cursorSecret must be at least 32 characters");
    }
    this.store = store;
    this.cursorSecret = options.cursorSecret;
  }

  async list(url) {
    const filters = parseFilters(url);
    const limit = limitFilter(url);
    const after = decodeCursor(
      singleQueryValue(url, "cursor"),
      filters,
      this.cursorSecret,
    );
    const result = await this.store.searchStreams(filters, after, limit + 1);
    const hasMore = result.length > limit;
    const page = hasMore ? result.slice(0, limit) : result;
    return {
      streams: page.map(publicContentStream),
      nextCursor: hasMore
        ? encodeCursor(filters, page[page.length - 1], this.cursorSecret)
        : null,
    };
  }
}
