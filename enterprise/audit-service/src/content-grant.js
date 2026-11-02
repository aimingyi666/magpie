import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import { CONTENT_PURPOSES, validateContentRef } from "./content-schema.js";
import { validateTimestamp } from "./events.js";

const GRANT_VERSION = 1;
const STORE_VERSION = 1;
const GRANT_PREFIX = "mcg1_";
const GRANT_ID_PATTERN = /^grt_[A-Za-z0-9_-]{43}$/;
const GRANT_TOKEN_PATTERN = /^mcg1_([A-Za-z0-9_-]{16,4096})\.([A-Za-z0-9_-]{43})$/;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const SESSION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{7,255}$/;
const APPROVAL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{7,127}$/;
const PURPOSE_SET = new Set(CONTENT_PURPOSES);
const PAYLOAD_FIELDS = new Set([
  "v",
  "gid",
  "cr",
  "aid",
  "org",
  "pur",
  "rea",
  "apr",
  "ses",
  "iat",
  "exp",
]);
const RECORD_FIELDS = new Set([
  "contentRef",
  "issuedAt",
  "expiresAt",
  "consumedAt",
]);

export class ContentGrantError extends Error {
  constructor(statusCode, code, message, retryable = false) {
    super(message);
    this.name = "ContentGrantError";
    this.statusCode = statusCode;
    this.code = code;
    this.retryable = retryable;
  }
}

function isPlainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function validateIdentity(value, name, pattern) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new ContentGrantError(400, "invalid_content_grant", `${name} is invalid`);
  }
  return value;
}

function validateReason(value) {
  if (typeof value !== "string"
      || value.length < 8
      || value.length > 1024
      || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new ContentGrantError(
      400,
      "content_grant_reason_required",
      "A valid grant reason is required",
    );
  }
  return value;
}

function timestamp(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("ContentGrant clock returned an invalid date");
  return date.toISOString();
}

function emptyStore() {
  return {
    version: STORE_VERSION,
    grants: {},
  };
}

function validateRecord(grantId, record) {
  if (!GRANT_ID_PATTERN.test(grantId)
      || !isPlainObject(record)
      || Object.keys(record).some((key) => !RECORD_FIELDS.has(key))
      || typeof record.contentRef !== "string"
      || typeof record.issuedAt !== "string"
      || typeof record.expiresAt !== "string"
      || typeof record.consumedAt !== "string") {
    throw new ContentGrantError(
      500,
      "content_grant_store_corrupt",
      "Content grant store is invalid",
    );
  }
  try {
    validateContentRef(record.contentRef);
    validateTimestamp(record.issuedAt, "issuedAt");
    validateTimestamp(record.expiresAt, "expiresAt");
    validateTimestamp(record.consumedAt, "consumedAt");
  } catch {
    throw new ContentGrantError(
      500,
      "content_grant_store_corrupt",
      "Content grant store is invalid",
    );
  }
}

function validateStore(value) {
  if (!isPlainObject(value)
      || Object.keys(value).length !== 2
      || !Object.hasOwn(value, "version")
      || !Object.hasOwn(value, "grants")
      || value.version !== STORE_VERSION
      || !isPlainObject(value.grants)) {
    throw new ContentGrantError(
      500,
      "content_grant_store_corrupt",
      "Content grant store is invalid",
    );
  }
  for (const [grantId, record] of Object.entries(value.grants)) {
    validateRecord(grantId, record);
  }
}

async function writeFileAtomic(filePath, data, mode) {
  const directory = path.dirname(filePath);
  const temporary = path.join(
    directory,
    `.tmp-${process.pid}-${crypto.randomBytes(12).toString("hex")}`,
  );
  let handle;
  try {
    handle = await fs.open(temporary, "wx", mode);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, filePath);
    await fs.chmod(filePath, mode);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
}

export class ContentGrantManager {
  constructor(options = {}) {
    if (!options.filePath) throw new Error("ContentGrantManager filePath is required");
    if (typeof options.secret !== "string" || options.secret.length < 32) {
      throw new Error("ContentGrantManager secret must be at least 32 characters");
    }
    this.filePath = path.resolve(options.filePath);
    this.secret = options.secret;
    this.now = options.now || Date.now;
    this.maxTtlSeconds = options.maxTtlSeconds ?? 300;
    this.defaultTtlSeconds = options.defaultTtlSeconds ?? 120;
    if (!Number.isSafeInteger(this.maxTtlSeconds)
        || this.maxTtlSeconds < 15
        || this.maxTtlSeconds > 300) {
      throw new Error("ContentGrantManager maxTtlSeconds must be from 15 to 300");
    }
    if (!Number.isSafeInteger(this.defaultTtlSeconds)
        || this.defaultTtlSeconds < 15
        || this.defaultTtlSeconds > this.maxTtlSeconds) {
      throw new Error("ContentGrantManager defaultTtlSeconds is invalid");
    }
    this.store = null;
    this.operation = Promise.resolve();
  }

  async load() {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    let raw;
    try {
      raw = await fs.readFile(this.filePath, "utf8");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      this.store = emptyStore();
      await this.persist();
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new ContentGrantError(
        500,
        "content_grant_store_corrupt",
        "Content grant store is not valid JSON",
      );
    }
    validateStore(parsed);
    this.store = parsed;
    const now = timestamp(this.now());
    let changed = false;
    for (const [grantId, record] of Object.entries(this.store.grants)) {
      if (record.expiresAt < now) {
        delete this.store.grants[grantId];
        changed = true;
      }
    }
    if (changed) await this.persist();
  }

  assertLoaded() {
    if (!this.store) throw new Error("ContentGrantManager.load() must complete first");
  }

  async persist() {
    await writeFileAtomic(
      this.filePath,
      `${JSON.stringify(this.store)}\n`,
      0o600,
    );
  }

  withMutation(fn) {
    this.assertLoaded();
    const run = this.operation.then(fn);
    this.operation = run.catch(() => {});
    return run;
  }

  sign(encoded) {
    return crypto.createHmac("sha256", this.secret).update(encoded).digest("base64url");
  }

  sessionDigest(adminId, organizationId, sessionId) {
    return crypto.createHmac("sha256", this.secret)
      .update(`session\u0000${adminId}\u0000${organizationId}\u0000${sessionId}`)
      .digest("base64url");
  }

  async issue(context) {
    const contentRef = validateContentRef(context.contentRef);
    const adminId = validateIdentity(context.adminId, "adminId", SAFE_ID_PATTERN);
    const organizationId = validateIdentity(
      context.organizationId,
      "organizationId",
      SAFE_ID_PATTERN,
    );
    const sessionId = validateIdentity(context.sessionId, "sessionId", SESSION_ID_PATTERN);
    const approvalId = validateIdentity(
      context.approvalId,
      "approvalId",
      APPROVAL_ID_PATTERN,
    );
    const reason = validateReason(context.reason);
    if (typeof context.purpose !== "string" || !PURPOSE_SET.has(context.purpose)) {
      throw new ContentGrantError(
        400,
        "content_grant_purpose_invalid",
        "A supported grant purpose is required",
      );
    }
    const ttlSeconds = context.ttlSeconds ?? this.defaultTtlSeconds;
    if (!Number.isSafeInteger(ttlSeconds)
        || ttlSeconds < 15
        || ttlSeconds > this.maxTtlSeconds) {
      throw new ContentGrantError(
        400,
        "content_grant_ttl_invalid",
        `ttlSeconds must be from 15 to ${this.maxTtlSeconds}`,
      );
    }
    const issuedAtMs = new Date(this.now()).getTime();
    const expiresAtMs = issuedAtMs + ttlSeconds * 1000;
    const grantId = `grt_${crypto.randomBytes(32).toString("base64url")}`;
    const payload = {
      v: GRANT_VERSION,
      gid: grantId,
      cr: contentRef,
      aid: adminId,
      org: organizationId,
      pur: context.purpose,
      rea: reason,
      apr: approvalId,
      ses: this.sessionDigest(adminId, organizationId, sessionId),
      iat: new Date(issuedAtMs).toISOString(),
      exp: new Date(expiresAtMs).toISOString(),
    };
    const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
    return {
      grant: `${GRANT_PREFIX}${encoded}.${this.sign(encoded)}`,
      grantId,
      contentRef,
      issuedAt: payload.iat,
      expiresAt: payload.exp,
    };
  }

  decode(token) {
    if (typeof token !== "string" || token.length > 8192) {
      throw new ContentGrantError(
        401,
        "content_grant_invalid",
        "A valid content grant is required",
      );
    }
    const match = GRANT_TOKEN_PATTERN.exec(token.trim());
    if (!match || !safeEqual(match[2], this.sign(match[1]))) {
      throw new ContentGrantError(
        401,
        "content_grant_invalid",
        "A valid content grant is required",
      );
    }
    let payload;
    try {
      payload = JSON.parse(Buffer.from(match[1], "base64url").toString("utf8"));
    } catch {
      throw new ContentGrantError(
        401,
        "content_grant_invalid",
        "A valid content grant is required",
      );
    }
    if (!isPlainObject(payload)
        || Object.keys(payload).length !== PAYLOAD_FIELDS.size
        || Object.keys(payload).some((key) => !PAYLOAD_FIELDS.has(key))
        || payload.v !== GRANT_VERSION
        || !GRANT_ID_PATTERN.test(payload.gid || "")
        || !SAFE_ID_PATTERN.test(payload.aid || "")
        || !SAFE_ID_PATTERN.test(payload.org || "")
        || !PURPOSE_SET.has(payload.pur)
        || typeof payload.rea !== "string"
        || payload.rea.length < 8
        || payload.rea.length > 1024
        || /[\u0000-\u001f\u007f]/.test(payload.rea)
        || !APPROVAL_ID_PATTERN.test(payload.apr || "")
        || !/^[A-Za-z0-9_-]{43}$/.test(payload.ses || "")) {
      throw new ContentGrantError(
        401,
        "content_grant_invalid",
        "A valid content grant is required",
      );
    }
    try {
      validateContentRef(payload.cr);
      payload.iat = validateTimestamp(payload.iat, "issuedAt");
      payload.exp = validateTimestamp(payload.exp, "expiresAt");
    } catch {
      throw new ContentGrantError(
        401,
        "content_grant_invalid",
        "A valid content grant is required",
      );
    }
    const issuedAtMs = new Date(payload.iat).getTime();
    const expiresAtMs = new Date(payload.exp).getTime();
    const nowMs = new Date(this.now()).getTime();
    if (expiresAtMs <= issuedAtMs
        || expiresAtMs - issuedAtMs > this.maxTtlSeconds * 1000) {
      throw new ContentGrantError(
        401,
        "content_grant_invalid",
        "A valid content grant is required",
      );
    }
    if (issuedAtMs > nowMs + 60_000) {
      throw new ContentGrantError(
        401,
        "content_grant_invalid",
        "A valid content grant is required",
      );
    }
    if (nowMs >= expiresAtMs) {
      throw new ContentGrantError(
        401,
        "content_grant_expired",
        "The content grant has expired",
      );
    }
    return payload;
  }

  async consume(token, expected) {
    const payload = this.decode(token);
    if (!safeEqual(payload.cr, expected.contentRef)
        || !safeEqual(payload.aid, expected.adminId)
        || !safeEqual(payload.org, expected.organizationId)
        || !safeEqual(
          payload.ses,
          this.sessionDigest(
            expected.adminId,
            expected.organizationId,
            expected.sessionId,
          ),
        )) {
      throw new ContentGrantError(
        403,
        "content_grant_scope_mismatch",
        "The content grant does not match this administrator, organization, session or target",
      );
    }
    return this.withMutation(async () => {
      if (this.store.grants[payload.gid]) {
        throw new ContentGrantError(
          409,
          "content_grant_reused",
          "The content grant has already been used",
        );
      }
      const record = {
        contentRef: payload.cr,
        issuedAt: payload.iat,
        expiresAt: payload.exp,
        consumedAt: timestamp(this.now()),
      };
      this.store.grants[payload.gid] = record;
      try {
        await this.persist();
      } catch {
        delete this.store.grants[payload.gid];
        throw new ContentGrantError(
          503,
          "content_grant_store_unavailable",
          "The content grant could not be consumed",
          true,
        );
      }
      return {
        grantId: payload.gid,
        contentRef: payload.cr,
        adminId: payload.aid,
        organizationId: payload.org,
        purpose: payload.pur,
        reason: payload.rea,
        approvalId: payload.apr,
        issuedAt: payload.iat,
        expiresAt: payload.exp,
        consumedAt: record.consumedAt,
      };
    });
  }

  async status() {
    this.assertLoaded();
    return {
      grants: Object.keys(this.store.grants).length,
    };
  }

  async close() {
    await this.operation;
  }
}
