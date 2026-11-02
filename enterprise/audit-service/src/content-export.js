import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import { CONTENT_PURPOSES } from "./content-schema.js";
import {
  ContentStoreError,
  contentSessionHash,
} from "./content-store.js";
import { canonicalJson, sha256Text } from "./events.js";

const EXPORT_MAGIC = Buffer.from("MAGPIE-EXPORT-1", "utf8");
const EXPORT_ID_PATTERN = /^exp_[A-Za-z0-9_-]{43}$/;
const CONTENT_REF_PATTERN = /^ct_[A-Za-z0-9_-]{43}$/;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const AUTHORIZATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@_-]{7,127}$/;
const IDEMPOTENCY_KEY_PATTERN = /^[\u0021-\u007e]{1,128}$/;
const EVENT_ID_PATTERN = /^evt_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{16,4096}\.[A-Za-z0-9_-]{43}$/;
const EXPORT_FILE_PATTERN = /^exp_[A-Za-z0-9_-]{43}\.mge$/;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const CREATE_FIELDS = new Set([
  "scope",
  "purpose",
  "reason",
  "approvalId",
  "ttlSeconds",
]);
const SCOPE_FIELDS = new Set([
  "contentRefs",
  "userId",
  "departmentId",
  "from",
  "to",
]);
const PURPOSE_SET = new Set(CONTENT_PURPOSES);

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function invalid(message) {
  throw new ContentStoreError(
    400,
    "invalid_content_export",
    message,
  );
}

function validText(value, minimum, maximum) {
  return typeof value === "string"
    && value.length >= minimum
    && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function canonicalTimestamp(value, name) {
  if (typeof value !== "string") invalid(`${name} must be a timestamp`);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    invalid(`${name} must be a canonical UTC timestamp`);
  }
  return value;
}

function validateScope(value) {
  if (!plainObject(value)
      || Object.keys(value).length === 0
      || Object.keys(value).some((key) => !SCOPE_FIELDS.has(key))) {
    invalid("scope must contain supported fields");
  }
  const scope = {};
  if (value.contentRefs !== undefined) {
    if (!Array.isArray(value.contentRefs)
        || value.contentRefs.length === 0
        || value.contentRefs.length > 100
        || value.contentRefs.some((ref) => !CONTENT_REF_PATTERN.test(ref))
        || new Set(value.contentRefs).size !== value.contentRefs.length) {
      throw new ContentStoreError(
        413,
        "content_export_scope_too_large",
        "contentRefs must contain from 1 to 100 unique content refs",
      );
    }
    scope.contentRefs = [...value.contentRefs];
  }
  for (const field of ["userId", "departmentId"]) {
    if (value[field] !== undefined) {
      if (!SAFE_ID_PATTERN.test(value[field])) invalid(`scope.${field} is invalid`);
      scope[field] = value[field];
    }
  }
  for (const field of ["from", "to"]) {
    if (value[field] !== undefined) {
      scope[field] = canonicalTimestamp(value[field], `scope.${field}`);
    }
  }
  if (scope.from && scope.to && scope.from > scope.to) {
    invalid("scope.from must not be after scope.to");
  }
  return scope;
}

function validateCreate(value) {
  if (!plainObject(value)
      || Object.keys(value).some((key) => !CREATE_FIELDS.has(key))) {
    invalid("The export request contains an unknown field");
  }
  const scope = validateScope(value.scope);
  if (!PURPOSE_SET.has(value.purpose)) invalid("purpose is unsupported");
  if (!validText(value.reason, 8, 1024)) {
    invalid("reason must be from 8 to 1024 characters");
  }
  if (!AUTHORIZATION_ID_PATTERN.test(value.approvalId || "")) {
    invalid("approvalId is invalid");
  }
  if (value.ttlSeconds !== undefined
      && (!Number.isSafeInteger(value.ttlSeconds)
        || value.ttlSeconds < 15
        || value.ttlSeconds > 300)) {
    invalid("ttlSeconds must be from 15 to 300");
  }
  return {
    scope,
    purpose: value.purpose,
    reason: value.reason,
    approvalId: value.approvalId,
    ttlSeconds: value.ttlSeconds,
  };
}

function exportKeyHash(key) {
  return sha256Text(`export_create\u0000${key}`);
}

function randomEventId() {
  return `evt_m4d_${crypto.randomBytes(24).toString("hex")}`;
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function writeFileAtomic(filePath, data) {
  const temporary = path.join(
    path.dirname(filePath),
    `.tmp-${process.pid}-${crypto.randomBytes(12).toString("hex")}`,
  );
  let handle;
  try {
    handle = await fs.open(temporary, "wx", 0o600);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.rename(temporary, filePath);
    await fs.chmod(filePath, 0o600);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await fs.unlink(temporary).catch(() => {});
    throw error;
  }
}

function publicExport(record) {
  return {
    exportId: record.exportId,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    organizationId: record.organizationId,
    adminId: record.adminId,
    purpose: record.purpose,
    reason: record.reason,
    approvalId: record.approvalId,
    scope: structuredClone(record.scope),
    auditEventId: record.auditEventId,
    watermark: record.watermark,
    objectCount: record.objectCount,
    bytes: record.bytes,
    status: record.status,
    ...(record.downloadConsumedAt
      ? { downloadConsumedAt: record.downloadConsumedAt }
      : {}),
    downloadCount: record.downloadCount,
  };
}

export class ContentExportManager {
  constructor(store, options = {}) {
    if (!store) throw new Error("ContentExportManager store is required");
    if (!validText(options.secret, 32, 4096)) {
      throw new Error("ContentExportManager secret is invalid");
    }
    if (!Buffer.isBuffer(options.key) || options.key.length !== 32) {
      throw new Error("ContentExportManager key must be a 32-byte Buffer");
    }
    if (!SAFE_ID_PATTERN.test(options.organizationId || "")) {
      throw new Error("ContentExportManager organizationId is invalid");
    }
    this.store = store;
    this.secret = options.secret;
    this.key = Buffer.from(options.key);
    this.organizationId = options.organizationId;
    this.defaultTtlSeconds = options.defaultTtlSeconds ?? 120;
    this.exportsDirectory = path.join(store.directory, "exports");
    this.now = options.now || Date.now;
    this.tempMaxAgeMs = options.tempMaxAgeMs ?? 60 * 60 * 1000;
    this.activeFiles = new Set();
  }

  nowMs() {
    const value = this.now();
    return value instanceof Date ? value.getTime() : Number(value);
  }

  sessionHash(administrator) {
    return contentSessionHash(
      this.secret,
      administrator.adminId,
      administrator.organizationId,
      administrator.sessionId,
    );
  }

  tokenFor(record) {
    const payload = {
      exportId: record.exportId,
      adminId: record.adminId,
      organizationId: record.organizationId,
      sessionHash: record.sessionHash,
      scopeHash: record.scopeHash,
      auditEventId: record.auditEventId,
      issuedAt: record.createdAt,
      expiresAt: record.expiresAt,
    };
    const encoded = Buffer.from(canonicalJson(payload), "utf8").toString("base64url");
    const mac = crypto.createHmac("sha256", this.secret)
      .update(encoded)
      .digest("base64url");
    return `${encoded}.${mac}`;
  }

  decodeToken(token) {
    if (typeof token !== "string" || !TOKEN_PATTERN.test(token)) {
      throw new ContentStoreError(
        401,
        "content_export_token_invalid",
        "The export token is invalid",
      );
    }
    const [encoded, mac] = token.split(".");
    const expected = crypto.createHmac("sha256", this.secret)
      .update(encoded)
      .digest("base64url");
    if (!safeEqual(mac, expected)) {
      throw new ContentStoreError(
        401,
        "content_export_token_invalid",
        "The export token is invalid",
      );
    }
    let payload;
    try {
      payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    } catch {
      throw new ContentStoreError(
        401,
        "content_export_token_invalid",
        "The export token is invalid",
      );
    }
    if (!plainObject(payload)
        || !EXPORT_ID_PATTERN.test(payload.exportId || "")
        || !SAFE_ID_PATTERN.test(payload.adminId || "")
        || !SAFE_ID_PATTERN.test(payload.organizationId || "")
        || !/^[a-f0-9]{64}$/.test(payload.sessionHash || "")
        || !/^[a-f0-9]{64}$/.test(payload.scopeHash || "")
        || !EVENT_ID_PATTERN.test(payload.auditEventId || "")
        || !validText(payload.issuedAt, 1, 64)
        || !validText(payload.expiresAt, 1, 64)) {
      throw new ContentStoreError(
        401,
        "content_export_token_invalid",
        "The export token is invalid",
      );
    }
    return payload;
  }

  encryptPackage(value, exportId) {
    const nonce = crypto.randomBytes(NONCE_BYTES);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.key, nonce, {
      authTagLength: TAG_BYTES,
    });
    cipher.setAAD(Buffer.from(`MAGPIE-EXPORT-1:${exportId}`, "utf8"));
    const ciphertext = Buffer.concat([
      cipher.update(canonicalJson(value), "utf8"),
      cipher.final(),
    ]);
    return Buffer.concat([EXPORT_MAGIC, nonce, cipher.getAuthTag(), ciphertext]);
  }

  decryptPackage(payload, exportId) {
    if (!Buffer.isBuffer(payload)
        || payload.length < EXPORT_MAGIC.length + NONCE_BYTES + TAG_BYTES
        || !payload.subarray(0, EXPORT_MAGIC.length).equals(EXPORT_MAGIC)) {
      throw new ContentStoreError(
        409,
        "content_export_not_available",
        "The export package is not available",
      );
    }
    const nonceStart = EXPORT_MAGIC.length;
    const tagStart = nonceStart + NONCE_BYTES;
    const ciphertextStart = tagStart + TAG_BYTES;
    try {
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        this.key,
        payload.subarray(nonceStart, tagStart),
        { authTagLength: TAG_BYTES },
      );
      decipher.setAAD(Buffer.from(`MAGPIE-EXPORT-1:${exportId}`, "utf8"));
      decipher.setAuthTag(payload.subarray(tagStart, ciphertextStart));
      return Buffer.concat([
        decipher.update(payload.subarray(ciphertextStart)),
        decipher.final(),
      ]);
    } catch {
      throw new ContentStoreError(
        409,
        "content_export_not_available",
        "The export package is not available",
      );
    }
  }

  matchingObjects(scope) {
    this.store.assertLoaded();
    const explicit = scope.contentRefs ? new Set(scope.contentRefs) : null;
    const objects = Object.values(this.store.index.objects)
      .filter((object) => !explicit || explicit.has(object.contentRef))
      .filter((object) => {
        const stream = this.store.index.streams[object.streamId];
        const request = stream?.request;
        if (!request) return false;
        return (!scope.userId || request.userId === scope.userId)
          && (!scope.departmentId || request.departmentId === scope.departmentId)
          && (!scope.from || object.createdAt >= scope.from)
          && (!scope.to || object.createdAt <= scope.to);
      })
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt)
        || left.contentRef.localeCompare(right.contentRef));
    if (explicit) {
      const found = new Set(objects.map((object) => object.contentRef));
      if ([...explicit].some((ref) => !found.has(ref))) {
        throw new ContentStoreError(
          409,
          "content_export_not_available",
          "One or more requested content objects are not available",
        );
      }
    }
    return objects;
  }

  async create(administrator, request, idempotencyKey, auditContext) {
    if (!IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey || "")) {
      invalid("A valid Idempotency-Key is required");
    }
    const validated = validateCreate(request);
    const ttlSeconds = validated.ttlSeconds ?? this.defaultTtlSeconds;
    const scopeHash = sha256Text(canonicalJson(validated.scope));
    const sessionHash = this.sessionHash(administrator);
    const fingerprint = sha256Text(canonicalJson({
      operation: "export_create",
      adminId: administrator.adminId,
      organizationId: administrator.organizationId,
      sessionHash,
      scope: validated.scope,
      purpose: validated.purpose,
      reason: validated.reason,
      approvalId: validated.approvalId,
      ttlSeconds,
    }));
    const keyHash = exportKeyHash(idempotencyKey);
    this.store.assertLoaded();
    await this.cleanupOrphanedFiles();
    const previous = this.store.index.governanceIdempotency[keyHash];
    if (previous) {
      if (previous.operation !== "export_create"
          || previous.fingerprint !== fingerprint) {
        throw new ContentStoreError(
          409,
          "content_export_not_available",
          "The idempotency key conflicts with an existing export",
        );
      }
      const record = this.store.index.exports[previous.resultId];
      if (!record) {
        throw new ContentStoreError(
          500,
          "content_store_corrupt",
          "The export idempotency index points to a missing export",
        );
      }
      return {
        duplicate: true,
        export: publicExport(record),
        token: this.tokenFor(record),
      };
    }

    const objects = this.matchingObjects(validated.scope);
    if (objects.length === 0) {
      throw new ContentStoreError(
        409,
        "content_export_not_available",
        "No readable content matches the export scope",
      );
    }
    if (objects.length > 100) {
      throw new ContentStoreError(
        413,
        "content_export_scope_too_large",
        "The export scope matches more than 100 content objects",
      );
    }

    const readObjects = [];
    for (const object of objects) {
      const read = await this.store.readObject(object.contentRef, {
        reason: validated.reason,
        authorizationId: validated.approvalId,
        approvalId: validated.approvalId,
        adminId: administrator.adminId,
        organizationId: administrator.organizationId,
        purpose: validated.purpose,
        requestId: auditContext.requestId,
        sourceHash: auditContext.sourceHash,
        accessedAt: new Date(this.nowMs()).toISOString(),
      });
      readObjects.push({
        contentRef: read.contentRef,
        streamId: read.streamId,
        requestId: read.requestId,
        sessionId: read.sessionId,
        userId: read.stream?.userId,
        departmentId: read.stream?.departmentId,
        deviceId: read.stream?.deviceId,
        agentId: read.stream?.agentId,
        ...(read.stream?.modelId ? { modelId: read.stream.modelId } : {}),
        ...(read.stream?.providerId ? { providerId: read.stream.providerId } : {}),
        ...(read.stream?.mcpServerId
          ? { mcpServerId: read.stream.mcpServerId }
          : {}),
        ...(read.stream?.toolName ? { toolName: read.stream.toolName } : {}),
        contentKind: read.contentKind,
        mediaType: read.mediaType,
        auditLevel: read.auditLevel,
        content: read.content,
        redaction: read.redaction,
        plaintextSha256: read.plaintextSha256,
        bytes: Buffer.byteLength(read.content, "utf8"),
        createdAt: object.createdAt,
      });
    }

    const exportId = `exp_${crypto.randomBytes(32).toString("base64url")}`;
    const createdAt = new Date(this.nowMs()).toISOString();
    const expiresAt = new Date(this.nowMs() + ttlSeconds * 1000).toISOString();
    const auditEventId = randomEventId();
    const watermark = `MAGPIE-AUDIT-EXPORT ${exportId}`;
    const packageValue = {
      format: "magpie-content-export-v1",
      exportId,
      generatedAt: createdAt,
      organizationId: administrator.organizationId,
      watermark,
      auditEventId,
      scopeHash,
      scope: validated.scope,
      objects: readObjects,
    };
    const payload = this.encryptPackage(packageValue, exportId);
    await fs.mkdir(this.exportsDirectory, { recursive: true, mode: 0o700 });
    const exportFile = `${exportId}.mge`;
    const exportPath = path.join(this.exportsDirectory, exportFile);
    const record = {
      exportId,
      createdAt,
      expiresAt,
      organizationId: administrator.organizationId,
      adminId: administrator.adminId,
      sessionHash,
      purpose: validated.purpose,
      reason: validated.reason,
      approvalId: validated.approvalId,
      scope: validated.scope,
      scopeHash,
      auditEventId,
      watermark,
      objectCount: readObjects.length,
      bytes: payload.length,
      objectFile: exportFile,
      status: "active",
      downloadCount: 0,
      events: [{
        eventId: randomEventId(),
        type: "created",
        occurredAt: createdAt,
        actorId: administrator.adminId,
        reason: validated.reason,
      }],
    };
    this.activeFiles.add(exportFile);
    try {
      await writeFileAtomic(exportPath, payload);
      return await this.store.withMutation(async () => {
        const raced = this.store.index.governanceIdempotency[keyHash];
        if (raced) {
          if (raced.operation !== "export_create"
              || raced.fingerprint !== fingerprint) {
            throw new ContentStoreError(
              409,
              "content_export_not_available",
              "The idempotency key conflicts with an existing export",
            );
          }
          const existing = this.store.index.exports[raced.resultId];
          if (!existing) {
            throw new ContentStoreError(
              500,
              "content_store_corrupt",
              "The export idempotency index points to a missing export",
            );
          }
          await fs.unlink(exportPath).catch(() => {});
          return {
            duplicate: true,
            export: publicExport(existing),
            token: this.tokenFor(existing),
          };
        }
        for (const object of objects) {
          const current = this.store.index.objects[object.contentRef];
          if (!current
              || current.plaintextSha256 !== object.plaintextSha256
              || current.bytes !== object.bytes) {
            throw new ContentStoreError(
              409,
              "content_export_not_available",
              "Content changed while the export was being prepared",
            );
          }
        }
        this.store.index.exports[exportId] = record;
        this.store.index.governanceIdempotency[keyHash] = {
          operation: "export_create",
          fingerprint,
          resultId: exportId,
        };
        this.store.index.stats.exportsCreated += 1;
        try {
          await this.store.persist();
        } catch (error) {
          delete this.store.index.exports[exportId];
          delete this.store.index.governanceIdempotency[keyHash];
          this.store.index.stats.exportsCreated -= 1;
          throw error;
        }
        return {
          duplicate: false,
          export: publicExport(record),
          token: this.tokenFor(record),
        };
      });
    } catch (error) {
      await fs.unlink(exportPath).catch(() => {});
      throw error;
    } finally {
      this.activeFiles.delete(exportFile);
    }
  }

  async list(options = {}) {
    this.store.assertLoaded();
    const limit = options.limit ?? 100;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
      invalid("limit must be from 1 to 500");
    }
    return Object.values(this.store.index.exports)
      .filter((record) => !options.organizationId
        || record.organizationId === options.organizationId)
      .filter((record) => !options.status || record.status === options.status)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt)
        || right.exportId.localeCompare(left.exportId))
      .slice(0, limit)
      .map(publicExport);
  }

  async download(exportId, administrator, token) {
    if (!EXPORT_ID_PATTERN.test(exportId || "")) {
      invalid("exportId is invalid");
    }
    if (!token) {
      throw new ContentStoreError(
        401,
        "content_export_token_required",
        "An export token is required",
      );
    }
    const payload = this.decodeToken(token);
    if (payload.exportId !== exportId) {
      throw new ContentStoreError(
        403,
        "content_export_token_invalid",
        "The export token does not match this export",
      );
    }
    const identityHash = this.sessionHash(administrator);
    if (payload.adminId !== administrator.adminId
        || payload.organizationId !== administrator.organizationId
        || payload.sessionHash !== identityHash) {
      throw new ContentStoreError(
        403,
        "content_export_token_invalid",
        "The export token is bound to a different administrator context",
      );
    }
    return this.store.withMutation(async () => {
      const record = this.store.index.exports[exportId];
      if (!record) {
        throw new ContentStoreError(
          409,
          "content_export_not_available",
          "The export is not available",
        );
      }
      if (record.status === "downloaded") {
        throw new ContentStoreError(
          409,
          "content_export_token_reused",
          "The export token has already been used",
        );
      }
      if (record.status === "expired"
          || this.nowMs() >= new Date(record.expiresAt).getTime()) {
        if (record.status !== "expired") {
          const previous = structuredClone(record);
          record.status = "expired";
          record.events.push({
            eventId: randomEventId(),
            type: "expired",
            occurredAt: new Date(this.nowMs()).toISOString(),
            actorId: "system_retention",
          });
          try {
            await this.store.persist();
          } catch {
            this.store.index.exports[exportId] = previous;
            throw new ContentStoreError(
              503,
              "content_store_unavailable",
              "Export expiry could not be persisted",
              true,
            );
          }
          await fs.unlink(
            path.join(this.exportsDirectory, record.objectFile),
          ).catch(() => {});
        }
        throw new ContentStoreError(
          410,
          "content_export_expired",
          "The export has expired",
        );
      }
      if (record.organizationId !== administrator.organizationId
          || record.adminId !== administrator.adminId
          || record.sessionHash !== identityHash
          || record.scopeHash !== payload.scopeHash
          || record.auditEventId !== payload.auditEventId
          || record.createdAt !== payload.issuedAt
          || record.expiresAt !== payload.expiresAt) {
        throw new ContentStoreError(
          403,
          "content_export_token_invalid",
          "The export token is invalid for this export",
        );
      }
      const exportPath = path.join(this.exportsDirectory, record.objectFile);
      let encrypted;
      try {
        encrypted = await fs.readFile(exportPath);
      } catch {
        throw new ContentStoreError(
          409,
          "content_export_not_available",
          "The export package is not available",
        );
      }
      const plaintext = this.decryptPackage(encrypted, exportId);
      let packageValue;
      try {
        packageValue = JSON.parse(plaintext.toString("utf8"));
      } catch {
        throw new ContentStoreError(
          409,
          "content_export_not_available",
          "The export package is not available",
        );
      }
      if (!plainObject(packageValue)
          || packageValue.format !== "magpie-content-export-v1"
          || packageValue.exportId !== exportId
          || packageValue.scopeHash !== record.scopeHash
          || packageValue.organizationId !== record.organizationId
          || packageValue.auditEventId !== record.auditEventId
          || packageValue.watermark !== record.watermark
          || !Array.isArray(packageValue.objects)
          || packageValue.objects.length !== record.objectCount) {
        throw new ContentStoreError(
          409,
          "content_export_not_available",
          "The export package is not available",
        );
      }
      const previous = structuredClone(record);
      const downloadedAt = new Date(this.nowMs()).toISOString();
      Object.assign(record, {
        status: "downloaded",
        downloadConsumedAt: downloadedAt,
        downloadCount: record.downloadCount + 1,
      });
      record.events.push({
        eventId: randomEventId(),
        type: "downloaded",
        occurredAt: downloadedAt,
        actorId: administrator.adminId,
        reason: "one-time export download",
      });
      try {
        await this.store.persist();
      } catch {
        this.store.index.exports[exportId] = previous;
        throw new ContentStoreError(
          503,
          "content_store_unavailable",
          "Export download audit could not be persisted",
          true,
        );
      }
      return {
        exportId,
        bytes: encrypted,
        watermark: `${record.watermark} ${downloadedAt}`,
      };
    });
  }

  async cleanupExpired() {
    return this.store.withMutation(async () => {
      const nowMs = this.nowMs();
      const expired = Object.values(this.store.index.exports)
        .filter((record) => record.status !== "expired"
          && nowMs >= new Date(record.expiresAt).getTime());
      if (expired.length === 0) return { cleaned: 0 };
      const previous = new Map();
      for (const record of expired) {
        previous.set(record.exportId, structuredClone(record));
        record.status = "expired";
        record.events.push({
          eventId: randomEventId(),
          type: "expired",
          occurredAt: new Date(nowMs).toISOString(),
          actorId: "system_retention",
          reason: "export retention expired",
        });
      }
      try {
        await this.store.persist();
      } catch (error) {
        for (const [exportId, record] of previous) {
          this.store.index.exports[exportId] = record;
        }
        throw error;
      }
      for (const record of expired) {
        await fs.unlink(
          path.join(this.exportsDirectory, record.objectFile),
        ).catch(() => {});
      }
      return { cleaned: expired.length };
    });
  }

  async cleanupOrphanedFiles() {
    let entries;
    try {
      entries = await fs.readdir(this.exportsDirectory, { withFileTypes: true });
    } catch (error) {
      if (error.code === "ENOENT") return { cleaned: 0 };
      throw error;
    }
    const known = new Set(
      Object.values(this.store.index.exports).map((record) => record.objectFile),
    );
    let cleaned = 0;
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const isExport = EXPORT_FILE_PATTERN.test(entry.name);
      const isTemporary = entry.name.startsWith(".tmp-");
      if ((!isExport && !isTemporary)
          || known.has(entry.name)
          || this.activeFiles.has(entry.name)) {
        continue;
      }
      if (isTemporary) {
        let ageMs = 0;
        try {
          const stat = await fs.stat(path.join(this.exportsDirectory, entry.name));
          ageMs = this.nowMs() - stat.mtimeMs;
        } catch {
          continue;
        }
        if (ageMs < this.tempMaxAgeMs) continue;
      }
      await fs.unlink(path.join(this.exportsDirectory, entry.name)).catch(() => {});
      cleaned += 1;
    }
    return { cleaned };
  }
}
