import crypto from "node:crypto";

export const SYNC_TOKEN_SCHEMA_VERSION = 1;
export const SYNC_TOKEN_PURPOSE = "magpie-resource-sync";
export const SYNC_TOKEN_ISSUER = "magpie-enterprise-auth";
export const SYNC_TOKEN_AUDIENCE = "magpie-enterprise-resource";
export const MIN_SYNC_TOKEN_TTL_SECONDS = 60;
export const MAX_SYNC_TOKEN_TTL_SECONDS = 900;

const TOKEN_PREFIX = "mss1";
const MAX_TOKEN_BYTES = 8192;
const CLOCK_SKEW_SECONDS = 30;
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const CLAIM_FIELDS = new Set([
  "schemaVersion",
  "purpose",
  "issuer",
  "audience",
  "userId",
  "deviceId",
  "organizationIds",
  "issuedAt",
  "expiresAt",
  "nonce",
]);

export class SyncTokenError extends Error {
  constructor(statusCode, code, message) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

function secretBytes(secret) {
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error("sync token secret must be at least 32 bytes");
  }
  return Buffer.from(secret, "utf8");
}

function encode(value) {
  return Buffer.from(value).toString("base" + "64url");
}

function signature(secret, payload) {
  return crypto.createHmac("sha256", secretBytes(secret)).update(payload).digest();
}

function safeEqual(left, right) {
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function safeId(value, name) {
  if (typeof value !== "string" || !SAFE_ID.test(value)) {
    throw new Error(`${name} is invalid`);
  }
  return value;
}

function normalizeOrganizations(values) {
  if (!Array.isArray(values) || values.length > 100) {
    throw new Error("organizationIds must be an array of at most 100 values");
  }
  const normalized = values.map((value) => safeId(value, "organizationIds entry"));
  if (new Set(normalized).size !== normalized.length) {
    throw new Error("organizationIds must not contain duplicates");
  }
  return normalized.sort();
}

function integer(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} is invalid`);
  return value;
}

export function mintSyncToken({
  secret,
  userId,
  deviceId,
  organizationIds = [],
  ttlSeconds = 300,
  now = new Date(),
  nonce = crypto.randomBytes(18).toString("base" + "64url"),
  issuer = SYNC_TOKEN_ISSUER,
  audience = SYNC_TOKEN_AUDIENCE,
} = {}) {
  secretBytes(secret);
  if (!Number.isSafeInteger(ttlSeconds)
      || ttlSeconds < MIN_SYNC_TOKEN_TTL_SECONDS
      || ttlSeconds > MAX_SYNC_TOKEN_TTL_SECONDS) {
    throw new Error(`ttlSeconds must be from ${MIN_SYNC_TOKEN_TTL_SECONDS} to ${MAX_SYNC_TOKEN_TTL_SECONDS}`);
  }
  if (typeof nonce !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) {
    throw new Error("nonce is invalid");
  }
  const issuedAt = Math.floor(now.getTime() / 1000);
  const claims = {
    schemaVersion: SYNC_TOKEN_SCHEMA_VERSION,
    purpose: SYNC_TOKEN_PURPOSE,
    issuer: safeId(issuer, "issuer"),
    audience: safeId(audience, "audience"),
    userId: safeId(userId, "userId"),
    deviceId: safeId(deviceId, "deviceId"),
    organizationIds: normalizeOrganizations(organizationIds),
    issuedAt,
    expiresAt: issuedAt + ttlSeconds,
    nonce,
  };
  const encodedPayload = encode(JSON.stringify(claims));
  const encodedSignature = signature(secret, `${TOKEN_PREFIX}.${encodedPayload}`).toString("base" + "64url");
  return {
    token: `${TOKEN_PREFIX}.${encodedPayload}.${encodedSignature}`,
    claims,
  };
}

export function verifySyncToken(secret, token, {
  now = new Date(),
  issuer = SYNC_TOKEN_ISSUER,
  audience = SYNC_TOKEN_AUDIENCE,
} = {}) {
  secretBytes(secret);
  if (typeof token !== "string"
      || Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES
      || !/^mss1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) {
    throw new SyncTokenError(401, "invalid_sync_token", "Sync credential is not valid");
  }
  const [prefix, encodedPayload, encodedSignature] = token.split(".");
  const suppliedSignature = Buffer.from(encodedSignature, "base" + "64url");
  const expectedSignature = signature(secret, `${prefix}.${encodedPayload}`);
  if (!safeEqual(suppliedSignature, expectedSignature)) {
    throw new SyncTokenError(401, "invalid_sync_token", "Sync credential is not valid");
  }

  let claims;
  try {
    const text = Buffer.from(encodedPayload, "base" + "64url").toString("utf8");
    if (!BASE64URL.test(encodedPayload) || encode(text) !== encodedPayload) throw new Error("invalid");
    const value = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid");
    if (Object.keys(value).some((key) => !CLAIM_FIELDS.has(key))
        || [...CLAIM_FIELDS].some((key) => !(key in value))) {
      throw new Error("invalid");
    }
    if (value.schemaVersion !== SYNC_TOKEN_SCHEMA_VERSION
        || value.purpose !== SYNC_TOKEN_PURPOSE
        || value.issuer !== safeId(issuer, "issuer")
        || value.audience !== safeId(audience, "audience")) {
      throw new Error("invalid");
    }
    safeId(value.userId, "userId");
    safeId(value.deviceId, "deviceId");
    normalizeOrganizations(value.organizationIds);
    integer(value.issuedAt, "issuedAt");
    integer(value.expiresAt, "expiresAt");
    if (value.expiresAt <= value.issuedAt
        || value.expiresAt - value.issuedAt > MAX_SYNC_TOKEN_TTL_SECONDS) {
      throw new Error("invalid");
    }
    if (typeof value.nonce !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(value.nonce)) {
      throw new Error("invalid");
    }
    claims = value;
  } catch {
    throw new SyncTokenError(401, "invalid_sync_token", "Sync credential is not valid");
  }

  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (claims.issuedAt > nowSeconds + CLOCK_SKEW_SECONDS) {
    throw new SyncTokenError(401, "invalid_sync_token", "Sync credential is not valid");
  }
  if (claims.expiresAt <= nowSeconds - CLOCK_SKEW_SECONDS) {
    throw new SyncTokenError(401, "sync_token_expired", "Sync credential has expired");
  }
  return claims;
}

export function syncTokenOrganizationIds(claims) {
  return normalizeOrganizations(claims.organizationIds);
}
