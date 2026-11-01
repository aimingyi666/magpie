import crypto from "node:crypto";
import http from "node:http";
import { createMagpieRunner } from "./runner.js";

const SCHEMA_VERSION = 1;
const KEY_ID = /^[A-Za-z0-9_-]{1,64}$/;
const POLICY_REVISION = /^sha256:[0-9a-f]{64}$/;
const LIMIT_PERIODS = new Set(["day", "week", "month", "days", "hours"]);
const KEY_STATES = new Set(["enabled", "disabled", "expired"]);
const MODEL_MODES = new Set(["all", "restricted", "accounts_only"]);
const POLICY_FIELDS = new Set(["schemaVersion", "expectedPolicyRevision", "models", "limits"]);
const LIMIT_FIELDS = new Set(["period", "days", "hours", "tokens", "cost", "cacheReads"]);
const DEFINITE_APPLY_FAILURES = new Set([
  "gateway_key_not_found",
  "gateway_policy_conflict",
  "gateway_schema_unsupported",
  "gateway_output_invalid",
]);

export class GatewayControlProtocolError extends Error {
  constructor(code, message, statusCode = 502, retryable = false, state = "failed") {
    super(message);
    this.name = "GatewayControlProtocolError";
    this.code = code;
    this.statusCode = statusCode;
    this.retryable = retryable;
    this.state = state;
  }
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalidPolicy(message = "The gateway policy is invalid") {
  return new GatewayControlProtocolError("gateway_output_invalid", message, 422, false);
}

function schemaUnsupported() {
  return new GatewayControlProtocolError(
    "gateway_schema_unsupported",
    "This gateway-control service does not support that schema",
    422,
    false,
  );
}

function outputInvalid() {
  return new GatewayControlProtocolError(
    "gateway_output_invalid",
    "Magpie produced an invalid gateway policy response",
    502,
    false,
  );
}

function errorStatus(code) {
  switch (code) {
    case "gateway_key_not_found": return 404;
    case "gateway_policy_conflict": return 409;
    case "gateway_schema_unsupported": return 422;
    case "gateway_output_invalid": return 422;
    case "gateway_output_too_large": return 502;
    case "gateway_storage_unavailable": return 503;
    case "gateway_timeout": return 504;
    case "gateway_readback_failed":
    case "gateway_policy_unknown":
    case "gateway_command_failed":
    default: return 502;
  }
}

function knownCode(code) {
  return new Set([
    "gateway_key_not_found",
    "gateway_policy_conflict",
    "gateway_schema_unsupported",
    "gateway_output_invalid",
    "gateway_output_too_large",
    "gateway_storage_unavailable",
    "gateway_command_failed",
    "gateway_timeout",
  ]).has(code);
}

function normalizeError(error) {
  if (error instanceof GatewayControlProtocolError) return error;
  if (error && knownCode(error.code)) {
    return new GatewayControlProtocolError(
      error.code,
      String(error.message || "The gateway command failed").slice(0, 500),
      errorStatus(error.code),
      Boolean(error.retryable),
    );
  }
  return new GatewayControlProtocolError(
    "gateway_command_failed",
    "The gateway command failed",
    502,
    true,
  );
}

function parseOutput(text) {
  if (!text || !text.trim()) return { kind: "empty" };
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return { kind: "invalid" };
  }
  if (!plainObject(value) || !Number.isInteger(value.schemaVersion)) {
    return { kind: "invalid" };
  }
  if (value.schemaVersion !== SCHEMA_VERSION) return { kind: "unsupported" };
  if (value.ok === false && plainObject(value.error) && typeof value.error.code === "string") {
    return { kind: "failure", value };
  }
  if (value.ok === true) return { kind: "success", value };
  return { kind: "invalid" };
}

function failureError(value) {
  const code = value.error.code;
  if (!knownCode(code)) {
    return new GatewayControlProtocolError(
      "gateway_command_failed",
      "Magpie returned an unknown gateway error",
      502,
      false,
    );
  }
  const message = typeof value.error.message === "string" && value.error.message.trim()
    ? value.error.message.slice(0, 500)
    : "Magpie could not complete the gateway command";
  return new GatewayControlProtocolError(
    code,
    message,
    errorStatus(code),
    Boolean(value.error.retryable),
  );
}

function commandResult(result, allowInvalidForReadback = false) {
  const parsed = parseOutput(result.stdout);
  if (parsed.kind === "unsupported") throw schemaUnsupported();
  if (parsed.kind === "failure") throw failureError(parsed.value);
  if (parsed.kind === "success") {
    if (result.exitCode !== 0) {
      throw new GatewayControlProtocolError(
        "gateway_command_failed",
        "Magpie reported success but exited unsuccessfully",
        502,
        true,
      );
    }
    return parsed.value;
  }
  if (allowInvalidForReadback && result.exitCode === 0) {
    throw outputInvalid();
  }
  if (result.exitCode !== 0) {
    throw new GatewayControlProtocolError(
      "gateway_command_failed",
      "The gateway command failed",
      502,
      true,
    );
  }
  throw outputInvalid();
}

function stringAt(value, maxLength = 1000) {
  return typeof value === "string" && value.length <= maxLength;
}

function nullableString(value, maxLength = 200) {
  return value === null || stringAt(value, maxLength);
}

function safeInteger(value, min, max) {
  return Number.isSafeInteger(value) && value >= min && value <= max;
}

function sanitizeLimit(limit) {
  if (!plainObject(limit) || !LIMIT_PERIODS.has(limit.period)) throw outputInvalid();
  const days = limit.days == null ? 0 : limit.days;
  const hours = limit.hours == null ? 0 : limit.hours;
  const tokens = limit.tokens == null ? 0 : limit.tokens;
  const cost = limit.cost == null ? 0 : limit.cost;
  if (!safeInteger(days, 0, 3650) || !safeInteger(hours, 0, 8760)) throw outputInvalid();
  if (!safeInteger(tokens, 0, Number.MAX_SAFE_INTEGER)) throw outputInvalid();
  if (typeof cost !== "number" || !Number.isFinite(cost) || cost < 0) throw outputInvalid();
  if (typeof limit.cacheReads !== "boolean") throw outputInvalid();
  if (!nullableString(limit.cycleStartedAt)) throw outputInvalid();
  return {
    period: limit.period,
    days,
    hours,
    tokens,
    cost,
    cacheReads: limit.cacheReads,
    cycleStartedAt: limit.cycleStartedAt ?? null,
  };
}

function sanitizeDescribe(value, expectedId) {
  if (!plainObject(value) || value.schemaVersion !== SCHEMA_VERSION || value.ok !== true) {
    throw outputInvalid();
  }
  if (!stringAt(value.observedAt, 80)) throw outputInvalid();
  if (!plainObject(value.key)) throw outputInvalid();
  const key = value.key;
  if (!stringAt(key.id, 64) || key.id !== expectedId || !KEY_ID.test(key.id)) throw outputInvalid();
  if (!stringAt(key.name, 500) || !KEY_STATES.has(key.state)) throw outputInvalid();
  if (typeof key.readOnly !== "boolean" || !nullableString(key.expiresAt, 80)) throw outputInvalid();

  if (!plainObject(value.models) || !MODEL_MODES.has(value.models.mode)) throw outputInvalid();
  if (!Array.isArray(value.models.patterns) || value.models.patterns.length > 500) throw outputInvalid();
  const patterns = value.models.patterns.map((pattern) => {
    if (!stringAt(pattern, 300)) throw outputInvalid();
    return pattern;
  });

  if (!Array.isArray(value.limits) || value.limits.length > 5) throw outputInvalid();
  const limits = value.limits.map(sanitizeLimit);

  if (!plainObject(value.accounts)) throw outputInvalid();
  if (typeof value.accounts.restricted !== "boolean") throw outputInvalid();
  if (!safeInteger(value.accounts.count, 0, 1000000)) throw outputInvalid();
  if (!nullableString(value.accounts.digest, 100)) throw outputInvalid();
  if (!stringAt(value.policyRevision, 100) || !POLICY_REVISION.test(value.policyRevision)) {
    throw outputInvalid();
  }

  return {
    observedAt: value.observedAt,
    key: {
      id: key.id,
      name: key.name,
      state: key.state,
      readOnly: key.readOnly,
      expiresAt: key.expiresAt ?? null,
    },
    models: {
      mode: value.models.mode,
      patterns,
    },
    limits,
    accounts: {
      restricted: value.accounts.restricted,
      count: value.accounts.count,
      digest: value.accounts.digest ?? null,
    },
    policyRevision: value.policyRevision,
  };
}

function normalizePolicy(body) {
  if (!plainObject(body)) throw invalidPolicy("The gateway policy must be a JSON object");
  if (Object.keys(body).some((key) => !POLICY_FIELDS.has(key))) {
    throw invalidPolicy("The gateway policy has an unknown field");
  }
  if (body.schemaVersion !== SCHEMA_VERSION) throw schemaUnsupported();
  if (!stringAt(body.expectedPolicyRevision, 100)
      || !POLICY_REVISION.test(body.expectedPolicyRevision)) {
    throw invalidPolicy("expectedPolicyRevision is required");
  }
  if (!Array.isArray(body.models)) throw invalidPolicy("models must be an array");
  if (!Array.isArray(body.limits)) throw invalidPolicy("limits must be an array");

  const models = [];
  for (const input of body.models) {
    if (!stringAt(input, 300)) throw invalidPolicy("Every model must be a string of at most 300 characters");
    const model = input.trim();
    if (!model) continue;
    if (models.some((seen) => seen.toLowerCase() === model.toLowerCase())) continue;
    if (!model.includes("/") || model.startsWith("/") || model.endsWith("/")) {
      throw invalidPolicy("A model must look like provider/model or provider/*");
    }
    models.push(model);
  }
  if (models.length === 0) throw invalidPolicy("A gateway policy must name at least one model");
  if (models.length > 500) throw invalidPolicy("A gateway policy can name at most 500 models");

  if (body.limits.length > 5) throw invalidPolicy("A gateway policy can have at most 5 limits");
  const limits = [];
  for (const raw of body.limits) {
    if (!plainObject(raw) || Object.keys(raw).some((key) => !LIMIT_FIELDS.has(key))) {
      throw invalidPolicy("A gateway policy limit is invalid");
    }
    if (!LIMIT_PERIODS.has(raw.period)) throw invalidPolicy("A limit period is invalid");
    const days = raw.days == null ? 0 : raw.days;
    const hours = raw.hours == null ? 0 : raw.hours;
    const tokens = raw.tokens == null ? 0 : raw.tokens;
    const cost = raw.cost == null ? 0 : raw.cost;
    const cacheReads = raw.cacheReads == null ? false : raw.cacheReads;
    if (!safeInteger(days, 0, 3650) || !safeInteger(hours, 0, 8760)) {
      throw invalidPolicy("A limit cycle is out of range");
    }
    if (!safeInteger(tokens, 0, Number.MAX_SAFE_INTEGER)) throw invalidPolicy("A token limit is invalid");
    if (typeof cost !== "number" || !Number.isFinite(cost) || cost < 0) {
      throw invalidPolicy("A cost limit is invalid");
    }
    if (typeof cacheReads !== "boolean") throw invalidPolicy("cacheReads must be a boolean");
    const normalizedCost = Math.round(cost * 1e4) / 1e4;
    if (tokens === 0 && normalizedCost === 0) {
      throw invalidPolicy("Every limit must cap tokens, cost or both");
    }

    let normalizedDays = 0;
    let normalizedHours = 0;
    if (raw.period === "days") {
      if (days < 1 || days > 3650) throw invalidPolicy("A day cycle is out of range");
      normalizedDays = days;
    } else if (raw.period === "hours") {
      if (hours < 1 || hours > 8760) throw invalidPolicy("An hour cycle is out of range");
      normalizedHours = hours;
    }
    const next = {
      period: raw.period,
      days: normalizedDays,
      hours: normalizedHours,
      tokens,
      cost: normalizedCost,
      cacheReads,
    };
    if (limits.some((seen) => seen.period === next.period
      && seen.days === next.days && seen.hours === next.hours)) {
      throw invalidPolicy("A gateway policy cannot repeat the same limit window");
    }
    limits.push(next);
  }
  return { models, limits };
}

function samePolicyPolicy(describe, expected) {
  const got = {
    models: describe.models.patterns,
    limits: describe.limits.map((limit) => ({
      period: limit.period,
      days: limit.days,
      hours: limit.hours,
      tokens: limit.tokens,
      cost: limit.cost,
      cacheReads: limit.cacheReads,
    })),
  };
  return JSON.stringify(got) === JSON.stringify(expected);
}

function unauthorized() {
  return new GatewayControlProtocolError("unauthorized", "A valid service token is required", 401, false);
}

function notFound() {
  return new GatewayControlProtocolError("not_found", "Route not found", 404, false);
}

function invalidJson() {
  return new GatewayControlProtocolError("invalid_json", "The request body is not valid JSON", 400, false);
}

function invalidContentType() {
  return new GatewayControlProtocolError(
    "invalid_content_type",
    "The request content type must be application/json",
    415,
    false,
  );
}

function requestTooLarge() {
  return new GatewayControlProtocolError("request_too_large", "The request body is larger than 64 KiB", 413, false);
}

function invalidKeyId() {
  return new GatewayControlProtocolError("invalid_key_id", "The gateway key id is invalid", 400, false);
}

function jsonResponse(res, requestId, statusCode, value) {
  const body = Buffer.from(`${JSON.stringify(value)}\n`);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(body.length),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-request-id": requestId,
  });
  res.end(body);
}

function errorResponse(res, requestId, error) {
  const normalized = normalizeError(error);
  jsonResponse(res, requestId, normalized.statusCode, {
    schemaVersion: SCHEMA_VERSION,
    ok: false,
    state: normalized.state,
    requestId,
    error: {
      code: normalized.code,
      message: normalized.message,
      retryable: normalized.retryable,
    },
  });
}

function tokenMatches(req, expected) {
  const header = String(req.headers.authorization || "");
  const match = /^Bearer\s+(.+)$/i.exec(header);
  if (!match) return false;
  const supplied = Buffer.from(match[1]);
  const wanted = Buffer.from(expected);
  return supplied.length === wanted.length && crypto.timingSafeEqual(supplied, wanted);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const length = Number(req.headers["content-length"] || 0);
    if (Number.isFinite(length) && length > limit) {
      req.resume();
      reject(requestTooLarge());
      return;
    }
    const chunks = [];
    let total = 0;
    let tooLarge = false;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > limit) {
        tooLarge = true;
        return;
      }
      if (!tooLarge) chunks.push(chunk);
    });
    req.on("end", () => {
      if (tooLarge) reject(requestTooLarge());
      else resolve(Buffer.concat(chunks));
    });
    req.on("error", () => reject(new GatewayControlProtocolError(
      "request_failed",
      "The request body could not be read",
      400,
      true,
    )));
  });
}

function decodeJson(body) {
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw invalidJson();
  }
  try {
    return { value: JSON.parse(text), text };
  } catch {
    throw invalidJson();
  }
}

function makeRequestId() {
  return crypto.randomUUID();
}

function logRequest(logger, entry) {
  if (!logger) return;
  try {
    logger(entry);
  } catch {
    // Logging must never change the response.
  }
}

export function createGatewayControlServer(config, options = {}) {
  const runner = options.runner || createMagpieRunner(config);
  const logger = options.logger || ((entry) => console.log(JSON.stringify(entry)));

  async function describe(id) {
    const result = await runner.describe(id);
    return sanitizeDescribe(commandResult(result, true), id);
  }

  async function applyPolicy(id, body, raw) {
    const expected = normalizePolicy(body);
    let result = null;
    let acknowledgementError = null;
    try {
      result = await runner.apply(id, raw);
      commandResult(result, false);
    } catch (error) {
      const normalized = normalizeError(error);
      const parsed = result ? parseOutput(result.stdout) : { kind: "empty" };
      const definite = parsed.kind === "failure" && DEFINITE_APPLY_FAILURES.has(normalized.code);
      if (definite) {
        throw normalized;
      }
      acknowledgementError = normalized;
    }

    let readback;
    try {
      readback = await describe(id);
    } catch (error) {
      const normalized = normalizeError(error);
      throw new GatewayControlProtocolError(
        "gateway_policy_unknown",
        "The policy was sent but could not be verified by an independent readback",
        502,
        true,
        "pending",
      );
    }
    if (!samePolicyPolicy(readback, expected)) {
      throw new GatewayControlProtocolError(
        "gateway_readback_failed",
        "The independent readback did not match the requested policy",
        502,
        true,
        "pending",
      );
    }
    if (acknowledgementError) {
      throw new GatewayControlProtocolError(
        "gateway_policy_unknown",
        "The policy is visible, but Magpie's apply result was not authoritative",
        502,
        true,
        "pending",
      );
    }
    return readback;
  }

  const server = http.createServer(async (req, res) => {
    const requestId = makeRequestId();
    res.setHeader("x-request-id", requestId);
    const startedAt = Date.now();
    let action = "route";
    let keyId = "";
    let code = "ok";

    try {
      const url = new URL(req.url || "/", "http://gateway-control.invalid");
      if (req.method === "GET" && url.pathname === "/healthz") {
        action = "health";
        jsonResponse(res, requestId, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          service: "gateway-control",
          version: "0.1.0",
        });
        return;
      }

      action = "authorize";
      if (!tokenMatches(req, config.token)) throw unauthorized();

      const describeMatch = /^\/api\/v1\/gateway-keys\/([^/]+)$/.exec(url.pathname);
      if (req.method === "GET" && describeMatch) {
        action = "describe";
        keyId = describeMatch[1];
        if (!KEY_ID.test(keyId)) throw invalidKeyId();
        const policy = await describe(keyId);
        jsonResponse(res, requestId, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          requestId,
          ...policy,
        });
        return;
      }

      const applyMatch = /^\/api\/v1\/gateway-keys\/([^/]+)\/policy$/.exec(url.pathname);
      if (req.method === "POST" && applyMatch) {
        action = "apply";
        keyId = applyMatch[1];
        if (!KEY_ID.test(keyId)) throw invalidKeyId();
        const contentType = String(req.headers["content-type"] || "");
        if (!/^application\/json(?:\s*;|$)/i.test(contentType)) throw invalidContentType();
        const body = await readBody(req, config.maxBodyBytes);
        const decoded = decodeJson(body);
        const policy = await applyPolicy(keyId, decoded.value, decoded.text);
        jsonResponse(res, requestId, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          state: "applied",
          requestId,
          readback: {
            verified: true,
            observedAt: policy.observedAt,
            policyRevision: policy.policyRevision,
          },
          policy: {
            key: policy.key,
            models: policy.models,
            limits: policy.limits,
            accounts: policy.accounts,
          },
        });
        return;
      }

      throw notFound();
    } catch (error) {
      const normalized = normalizeError(error);
      code = normalized.code;
      errorResponse(res, requestId, normalized);
    } finally {
      logRequest(logger, {
        time: new Date().toISOString(),
        action,
        keyId,
        requestId,
        status: res.statusCode,
        code,
        durationMs: Date.now() - startedAt,
      });
    }
  });
  server.headersTimeout = 15000;
  server.requestTimeout = 30000;
  server.keepAliveTimeout = 5000;

  return { server, runner };
}
