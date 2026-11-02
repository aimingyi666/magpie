import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import {
  AUDIT_CONTENT_SCHEMA_VERSION,
  contentFingerprint,
  publicContentStream,
  validateContentRef,
  validateContentStreamId,
  validateContentStreamRequest,
} from "./content-schema.js";
import { sha256Text } from "./events.js";

const STORE_VERSION = 1;
const MAGIC = Buffer.from("MAGPIE-CONTENT-1", "utf8");
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const STREAM_ID_PATTERN = /^str_[A-Za-z0-9_-]{43}$/;
const CONTENT_REF_PATTERN = /^ct_[A-Za-z0-9_-]{43}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const AUTHORIZATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{7,127}$/;
const SOURCE_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const ERROR_CODE_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const MAX_ACCESS_RECORDS = 10_000;

export class ContentStoreError extends Error {
  constructor(statusCode, code, message, retryable = false) {
    super(message);
    this.name = "ContentStoreError";
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

function requiredString(value, maximum = 1024) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function safeInteger(value, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function randomId(prefix) {
  return `${prefix}${crypto.randomBytes(32).toString("base64url")}`;
}

function idempotencyKeyHash(scope, key) {
  return sha256Text(`${scope}\u0000${key}`);
}

function redactionSummary(value) {
  if (!isPlainObject(value)
      || !requiredString(value.ruleVersion, 64)
      || !safeInteger(value.replacements)
      || !isPlainObject(value.categories)) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content store redaction metadata is invalid");
  }
  const categories = {};
  for (const [category, count] of Object.entries(value.categories)) {
    if (!ERROR_CODE_PATTERN.test(category) || !safeInteger(count)) {
      throw new ContentStoreError(500, "content_store_corrupt", "Content store redaction metadata is invalid");
    }
    categories[category] = count;
  }
  return {
    ruleVersion: value.ruleVersion,
    replacements: value.replacements,
    categories,
  };
}

function emptyIndex() {
  return {
    version: STORE_VERSION,
    streams: {},
    objects: {},
    access: {},
    idempotency: {},
    stats: {
      streamsCreated: 0,
      chunksAccepted: 0,
      objectsFinalized: 0,
      streamsFailed: 0,
    },
  };
}

function streamFields() {
  return new Set([
    "streamId",
    "request",
    "status",
    "createdAt",
    "updatedAt",
    "nextSequence",
    "chunkCount",
    "bytes",
    "chunks",
    "contentRef",
    "redaction",
    "plaintextSha256",
    "finalizedAt",
    "failureCode",
  ]);
}

function objectFields() {
  return new Set([
    "contentRef",
    "streamId",
    "objectFile",
    "plaintextSha256",
    "bytes",
    "mediaType",
    "auditLevel",
    "contentKind",
    "requestId",
    "sessionId",
    "redaction",
    "createdAt",
    "retentionDays",
  ]);
}

function validateStream(streamId, stream) {
  if (!STREAM_ID_PATTERN.test(streamId)
      || !isPlainObject(stream)
      || Object.keys(stream).some((key) => !streamFields().has(key))
      || stream.streamId !== streamId
      || !["collecting", "finalized", "failed"].includes(stream.status)
      || !requiredString(stream.createdAt, 64)
      || !requiredString(stream.updatedAt, 64)
      || !safeInteger(stream.nextSequence, 0, 99_999)
      || !safeInteger(stream.chunkCount, 0, 99_999)
      || !safeInteger(stream.bytes, 0, 32 * 1024 * 1024)
      || !Array.isArray(stream.chunks)
      || stream.chunks.length !== stream.nextSequence
      || stream.chunks.some((chunk, index) => !isPlainObject(chunk)
        || Object.keys(chunk).some((key) => !["sequence", "fingerprint", "bytes"].includes(key))
        || chunk.sequence !== index
        || !SHA256_PATTERN.test(chunk.fingerprint || "")
        || !safeInteger(chunk.bytes, 0, 4 * 1024 * 1024))) {
    throw new ContentStoreError(500, "content_store_corrupt", `Content stream ${streamId} is invalid`);
  }
  try {
    validateContentStreamRequest(stream.request);
  } catch {
    throw new ContentStoreError(500, "content_store_corrupt", `Content stream ${streamId} request is invalid`);
  }
  if (stream.status === "finalized") {
    if (!CONTENT_REF_PATTERN.test(stream.contentRef || "")
        || !SHA256_PATTERN.test(stream.plaintextSha256 || "")
        || !requiredString(stream.finalizedAt, 64)
        || stream.failureCode !== undefined) {
      throw new ContentStoreError(500, "content_store_corrupt", `Content stream ${streamId} final state is invalid`);
    }
    redactionSummary(stream.redaction);
  }
  if (stream.status === "failed"
      && !ERROR_CODE_PATTERN.test(stream.failureCode || "")) {
    throw new ContentStoreError(500, "content_store_corrupt", `Content stream ${streamId} failure state is invalid`);
  }
}

function validateObject(contentRef, object) {
  if (!CONTENT_REF_PATTERN.test(contentRef)
      || !isPlainObject(object)
      || Object.keys(object).some((key) => !objectFields().has(key))
      || object.contentRef !== contentRef
      || !STREAM_ID_PATTERN.test(object.streamId || "")
      || object.objectFile !== `${contentRef}.bin`
      || !SHA256_PATTERN.test(object.plaintextSha256 || "")
      || !safeInteger(object.bytes)
      || object.mediaType !== "text/plain"
      || object.auditLevel !== "L2"
      || !requiredString(object.contentKind, 64)
      || !requiredString(object.requestId, 136)
      || !requiredString(object.sessionId, 136)
      || !requiredString(object.createdAt, 64)
      || !safeInteger(object.retentionDays, 1, 3650)) {
    throw new ContentStoreError(500, "content_store_corrupt", `Content object ${contentRef} is invalid`);
  }
  redactionSummary(object.redaction);
}

function validateAccessRecord(record) {
  if (!isPlainObject(record)
      || Object.keys(record).some((key) => ![
        "accessId",
        "accessedAt",
        "reason",
        "authorizationId",
        "requestId",
        "sourceHash",
        "outcome",
        "errorCode",
      ].includes(key))
      || !/^acc_[A-Za-z0-9_-]{43}$/.test(record.accessId || "")
      || !requiredString(record.accessedAt, 64)
      || !requiredString(record.reason, 1024)
      || record.reason.length < 8
      || !AUTHORIZATION_ID_PATTERN.test(record.authorizationId || "")
      || !requiredString(record.requestId, 136)
      || !SOURCE_HASH_PATTERN.test(record.sourceHash || "")
      || !["success", "failed"].includes(record.outcome)
      || (record.outcome === "failed" && !ERROR_CODE_PATTERN.test(record.errorCode || ""))
      || (record.outcome === "success" && record.errorCode !== undefined)) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content access audit is invalid");
  }
}

function validateIndex(index) {
  if (!isPlainObject(index)
      || Object.keys(index).some((key) => !["version", "streams", "objects", "access", "idempotency", "stats"].includes(key))
      || index.version !== STORE_VERSION
      || !isPlainObject(index.streams)
      || !isPlainObject(index.objects)
      || !isPlainObject(index.access)
      || !isPlainObject(index.idempotency)
      || !isPlainObject(index.stats)) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content store index is invalid");
  }
  for (const [streamId, stream] of Object.entries(index.streams)) validateStream(streamId, stream);
  for (const [contentRef, object] of Object.entries(index.objects)) validateObject(contentRef, object);
  for (const [contentRef, records] of Object.entries(index.access)) {
    if (!CONTENT_REF_PATTERN.test(contentRef)
        || !Array.isArray(records)
        || records.length > MAX_ACCESS_RECORDS) {
      throw new ContentStoreError(500, "content_store_corrupt", "Content access index is invalid");
    }
    records.forEach(validateAccessRecord);
  }
  for (const [key, record] of Object.entries(index.idempotency)) {
    if (!SHA256_PATTERN.test(key)
        || !isPlainObject(record)
        || Object.keys(record).some((field) => !["scope", "fingerprint", "streamId", "sequence"].includes(field))
        || !["create", "chunk"].includes(record.scope)
        || !SHA256_PATTERN.test(record.fingerprint || "")
        || !STREAM_ID_PATTERN.test(record.streamId || "")
        || (record.scope === "chunk" && !safeInteger(record.sequence, 0, 99_999))
        || (record.scope === "create" && record.sequence !== undefined)) {
      throw new ContentStoreError(500, "content_store_corrupt", "Content idempotency index is invalid");
    }
  }
  for (const key of ["streamsCreated", "chunksAccepted", "objectsFinalized", "streamsFailed"]) {
    if (!safeInteger(index.stats[key])) {
      throw new ContentStoreError(500, "content_store_corrupt", "Content store statistics are invalid");
    }
  }
}

async function writeFileAtomic(filePath, data, mode) {
  const directory = path.dirname(filePath);
  const temporary = path.join(directory, `.tmp-${process.pid}-${crypto.randomBytes(12).toString("hex")}`);
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

export class ContentStore {
  constructor(directoryOrOptions, maybeOptions = {}) {
    const options = typeof directoryOrOptions === "string"
      ? { ...maybeOptions, directory: directoryOrOptions }
      : (directoryOrOptions || {});
    if (!options.directory) throw new Error("ContentStore directory is required");
    if (!Buffer.isBuffer(options.key) || options.key.length !== 32) {
      throw new Error("ContentStore key must be a 32-byte Buffer");
    }
    this.directory = path.resolve(options.directory);
    this.objectsDirectory = path.join(this.directory, "objects");
    this.indexPath = path.join(this.directory, "index.json");
    this.key = Buffer.from(options.key);
    this.now = options.now || Date.now;
    this.maxStreamBytes = options.maxStreamBytes ?? 1024 * 1024;
    this.index = null;
    this.operation = Promise.resolve();
  }

  timestamp() {
    const value = this.now();
    return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
  }

  async load() {
    await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
    await fs.mkdir(this.objectsDirectory, { recursive: true, mode: 0o700 });
    let raw;
    try {
      raw = await fs.readFile(this.indexPath, "utf8");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      this.index = emptyIndex();
      await this.persist();
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new ContentStoreError(500, "content_store_corrupt", "Content store index is not valid JSON");
    }
    validateIndex(parsed);
    this.index = parsed;
    let changed = false;
    for (const stream of Object.values(this.index.streams)) {
      if (stream.status === "collecting") {
        stream.status = "failed";
        stream.failureCode = "content_stream_interrupted";
        stream.updatedAt = this.timestamp();
        this.index.stats.streamsFailed += 1;
        changed = true;
      }
    }
    if (changed) await this.persist();
  }

  assertLoaded() {
    if (!this.index) throw new Error("ContentStore.load() must complete first");
  }

  async withMutation(fn) {
    this.assertLoaded();
    const run = this.operation.then(fn);
    this.operation = run.catch(() => {});
    return run;
  }

  async persist() {
    await writeFileAtomic(this.indexPath, `${JSON.stringify(this.index)}\n`, 0o600);
  }

  clone(value) {
    return structuredClone(value);
  }

  async createStream(request, idempotencyKey) {
    return this.withMutation(async () => {
      const fingerprint = contentFingerprint(request);
      const idempotencyId = idempotencyKeyHash("create", idempotencyKey);
      const previous = this.index.idempotency[idempotencyId];
      if (previous) {
        if (previous.scope !== "create" || previous.fingerprint !== fingerprint) {
          throw new ContentStoreError(409, "content_idempotency_conflict", "The idempotency key conflicts with an existing request");
        }
        const stream = this.index.streams[previous.streamId];
        if (!stream) {
          throw new ContentStoreError(500, "content_store_corrupt", "The content idempotency index points to a missing stream");
        }
        return { duplicate: true, stream: this.clone(stream) };
      }

      const streamId = randomId("str_");
      const now = this.timestamp();
      const stream = {
        streamId,
        request: this.clone(request),
        status: "collecting",
        createdAt: now,
        updatedAt: now,
        nextSequence: 0,
        chunkCount: 0,
        bytes: 0,
        chunks: [],
      };
      const idempotency = {
        scope: "create",
        fingerprint,
        streamId,
      };
      this.index.streams[streamId] = stream;
      this.index.idempotency[idempotencyId] = idempotency;
      this.index.stats.streamsCreated += 1;
      try {
        await this.persist();
      } catch (error) {
        delete this.index.streams[streamId];
        delete this.index.idempotency[idempotencyId];
        this.index.stats.streamsCreated -= 1;
        throw error;
      }
      return { duplicate: false, stream: this.clone(stream) };
    });
  }

  async getStream(streamId) {
    this.assertLoaded();
    const normalized = validateContentStreamId(streamId);
    const stream = this.index.streams[normalized];
    return stream ? this.clone(stream) : null;
  }

  async acceptChunk(streamId, sequence, chunkFingerprintSha256, idempotencyKey, byteLength) {
    return this.withMutation(async () => {
      const normalized = validateContentStreamId(streamId);
      if (!safeInteger(sequence, 0, 99_999)
          || !SHA256_PATTERN.test(chunkFingerprintSha256 || "")
          || !safeInteger(byteLength, 0, 4 * 1024 * 1024)) {
        throw new ContentStoreError(400, "invalid_content_chunk", "The content chunk record is invalid");
      }
      const stream = this.index.streams[normalized];
      if (!stream) {
        throw new ContentStoreError(404, "content_stream_not_found", "Content stream not found");
      }
      const idempotencyId = idempotencyKeyHash("chunk", `${normalized}\u0000${idempotencyKey}`);
      const previous = this.index.idempotency[idempotencyId];
      if (previous) {
        if (previous.scope !== "chunk"
            || previous.streamId !== normalized
            || previous.sequence !== sequence
            || previous.fingerprint !== chunkFingerprintSha256) {
          return { conflict: "idempotency", stream: this.clone(stream) };
        }
        return { duplicate: true, stream: this.clone(stream) };
      }
      if (stream.status !== "collecting") {
        throw new ContentStoreError(409, "content_stream_closed", "Content stream is not collecting");
      }

      if (sequence < stream.nextSequence) {
        const existing = stream.chunks[sequence];
        if (existing?.fingerprint === chunkFingerprintSha256) {
          return { duplicate: true, stream: this.clone(stream) };
        }
        return { conflict: "chunk", stream: this.clone(stream) };
      }
      if (sequence > stream.nextSequence) {
        return { outOfOrder: true, stream: this.clone(stream) };
      }
      if (stream.bytes + byteLength > this.maxStreamBytes) {
        throw new ContentStoreError(413, "content_stream_too_large", "The content stream exceeds the configured limit");
      }

      const chunk = {
        sequence,
        fingerprint: chunkFingerprintSha256,
        bytes: byteLength,
      };
      const idempotency = {
        scope: "chunk",
        fingerprint: chunkFingerprintSha256,
        streamId: normalized,
        sequence,
      };
      stream.chunks.push(chunk);
      stream.nextSequence += 1;
      stream.chunkCount += 1;
      stream.bytes += byteLength;
      stream.updatedAt = this.timestamp();
      this.index.idempotency[idempotencyId] = idempotency;
      this.index.stats.chunksAccepted += 1;
      try {
        await this.persist();
      } catch (error) {
        stream.chunks.pop();
        stream.nextSequence -= 1;
        stream.chunkCount -= 1;
        stream.bytes -= byteLength;
        delete this.index.idempotency[idempotencyId];
        this.index.stats.chunksAccepted -= 1;
        throw error;
      }
      return { duplicate: false, stream: this.clone(stream) };
    });
  }

  encrypt(redactedText, contentRef) {
    const nonce = crypto.randomBytes(NONCE_BYTES);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.key, nonce, {
      authTagLength: TAG_BYTES,
    });
    cipher.setAAD(Buffer.from(`MAGPIE-CONTENT-1:${contentRef}`, "utf8"));
    const ciphertext = Buffer.concat([
      cipher.update(redactedText, "utf8"),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([MAGIC, nonce, tag, ciphertext]);
  }

  decrypt(payload, contentRef) {
    if (!Buffer.isBuffer(payload)
        || payload.length < MAGIC.length + NONCE_BYTES + TAG_BYTES
        || !payload.subarray(0, MAGIC.length).equals(MAGIC)) {
      throw new ContentStoreError(500, "content_integrity_failed", "Content object is corrupt");
    }
    const nonceStart = MAGIC.length;
    const tagStart = nonceStart + NONCE_BYTES;
    const ciphertextStart = tagStart + TAG_BYTES;
    try {
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        this.key,
        payload.subarray(nonceStart, tagStart),
        { authTagLength: TAG_BYTES },
      );
      decipher.setAAD(Buffer.from(`MAGPIE-CONTENT-1:${contentRef}`, "utf8"));
      decipher.setAuthTag(payload.subarray(tagStart, ciphertextStart));
      return Buffer.concat([
        decipher.update(payload.subarray(ciphertextStart)),
        decipher.final(),
      ]).toString("utf8");
    } catch {
      throw new ContentStoreError(500, "content_integrity_failed", "Content object failed integrity verification");
    }
  }

  async finalizeStream(streamId, redactedText, redaction) {
    return this.withMutation(async () => {
      const normalized = validateContentStreamId(streamId);
      const stream = this.index.streams[normalized];
      if (!stream) {
        throw new ContentStoreError(404, "content_stream_not_found", "Content stream not found");
      }
      if (stream.status !== "collecting") {
        throw new ContentStoreError(409, "content_stream_closed", "Content stream is not collecting");
      }
      if (typeof redactedText !== "string") {
        throw new ContentStoreError(400, "invalid_content_chunk", "Redacted content must be a string");
      }
      const summary = redactionSummary(redaction);
      const contentRef = randomId("ct_");
      const plaintextSha256 = sha256Text(redactedText);
      const bytes = Buffer.byteLength(redactedText, "utf8");
      if (bytes > this.maxStreamBytes) {
        throw new ContentStoreError(413, "content_stream_too_large", "The content stream exceeds the configured limit");
      }
      const objectFile = `${contentRef}.bin`;
      const objectPath = path.join(this.objectsDirectory, objectFile);
      const payload = this.encrypt(redactedText, contentRef);
      await writeFileAtomic(objectPath, payload, 0o600);

      const now = this.timestamp();
      const oldStream = this.clone(stream);
      const object = {
        contentRef,
        streamId: normalized,
        objectFile,
        plaintextSha256,
        bytes,
        mediaType: "text/plain",
        auditLevel: "L2",
        contentKind: stream.request.contentKind,
        requestId: stream.request.requestId,
        sessionId: stream.request.sessionId,
        redaction: summary,
        createdAt: now,
        retentionDays: stream.request.collection.retentionDays,
      };
      Object.assign(stream, {
        status: "finalized",
        contentRef,
        redaction: summary,
        plaintextSha256,
        bytes,
        updatedAt: now,
        finalizedAt: now,
      });
      delete stream.failureCode;
      this.index.objects[contentRef] = object;
      this.index.stats.objectsFinalized += 1;
      try {
        await this.persist();
      } catch (error) {
        this.index.streams[normalized] = oldStream;
        delete this.index.objects[contentRef];
        this.index.stats.objectsFinalized -= 1;
        await fs.unlink(objectPath).catch(() => {});
        throw error;
      }
      return {
        stream: this.clone(stream),
        contentRef,
        redaction: this.clone(summary),
        plaintextSha256,
        finalizedAt: now,
        bytes,
      };
    });
  }

  async failStream(streamId, failureCode) {
    return this.withMutation(async () => {
      const normalized = validateContentStreamId(streamId);
      if (!ERROR_CODE_PATTERN.test(failureCode || "")) {
        throw new ContentStoreError(400, "invalid_content_failure", "Content failure code is invalid");
      }
      const stream = this.index.streams[normalized];
      if (!stream) return { stream: null, changed: false };
      if (stream.status !== "collecting") {
        return { stream: this.clone(stream), changed: false };
      }
      const previous = this.clone(stream);
      stream.status = "failed";
      stream.failureCode = failureCode;
      stream.updatedAt = this.timestamp();
      this.index.stats.streamsFailed += 1;
      try {
        await this.persist();
      } catch (error) {
        this.index.streams[normalized] = previous;
        this.index.stats.streamsFailed -= 1;
        throw error;
      }
      return { stream: this.clone(stream), changed: true };
    });
  }

  async recordAccess(contentRef, context, outcome, errorCode) {
    const now = context.accessedAt || this.timestamp();
    const record = {
      accessId: randomId("acc_"),
      accessedAt: now,
      reason: context.reason,
      authorizationId: context.authorizationId,
      requestId: context.requestId,
      sourceHash: context.sourceHash,
      outcome,
      ...(errorCode ? { errorCode } : {}),
    };
    validateAccessRecord(record);
    const records = this.index.access[contentRef] || [];
    records.push(record);
    if (records.length > MAX_ACCESS_RECORDS) {
      records.splice(0, records.length - MAX_ACCESS_RECORDS);
    }
    this.index.access[contentRef] = records;
    await this.persist();
    return this.clone(record);
  }

  validateAccessContext(context) {
    if (!isPlainObject(context)
        || !requiredString(context.reason, 1024)
        || context.reason.length < 8
        || !AUTHORIZATION_ID_PATTERN.test(context.authorizationId || "")
        || !requiredString(context.requestId, 136)
        || !SOURCE_HASH_PATTERN.test(context.sourceHash || "")) {
      throw new ContentStoreError(400, "invalid_content_access", "Content access context is invalid");
    }
  }

  async readObject(contentRef, accessContext) {
    return this.withMutation(async () => {
      const normalized = validateContentRef(contentRef);
      this.validateAccessContext(accessContext);
      const persistAccess = async (outcome, errorCode) => {
        try {
          return await this.recordAccess(normalized, accessContext, outcome, errorCode);
        } catch {
          throw new ContentStoreError(
            503,
            "content_store_unavailable",
            "Content access audit could not be persisted",
            true,
          );
        }
      };
      const object = this.index.objects[normalized];
      if (!object) {
        await persistAccess("failed", "content_object_not_found");
        throw new ContentStoreError(404, "content_object_not_found", "Content object not found");
      }
      const objectPath = path.join(this.objectsDirectory, object.objectFile);
      if (path.dirname(path.resolve(objectPath)) !== path.resolve(this.objectsDirectory)) {
        throw new ContentStoreError(500, "content_object_not_found", "Content object not found");
      }
      let text;
      try {
        const payload = await fs.readFile(objectPath);
        text = this.decrypt(payload, normalized);
        if (sha256Text(text) !== object.plaintextSha256
            || Buffer.byteLength(text, "utf8") !== object.bytes) {
          throw new ContentStoreError(500, "content_integrity_failed", "Content object failed integrity verification");
        }
      } catch (error) {
        const code = error instanceof ContentStoreError
          ? error.code
          : "content_integrity_failed";
        await persistAccess("failed", code);
        if (error instanceof ContentStoreError) throw error;
        throw new ContentStoreError(500, "content_integrity_failed", "Content object failed integrity verification");
      }
      const access = await persistAccess("success");
      const stream = this.index.streams[object.streamId] || null;
      return {
        contentRef: normalized,
        streamId: object.streamId,
        requestId: object.requestId,
        sessionId: object.sessionId,
        contentKind: object.contentKind,
        mediaType: object.mediaType,
        auditLevel: object.auditLevel,
        content: text,
        redaction: this.clone(object.redaction),
        plaintextSha256: object.plaintextSha256,
        accessedAt: access.accessedAt,
        stream: stream ? publicContentStream(stream) : null,
      };
    });
  }

  async listAccess(contentRef, limit = 100) {
    this.assertLoaded();
    const normalized = validateContentRef(contentRef);
    if (!safeInteger(limit, 1, 500)) {
      throw new ContentStoreError(400, "invalid_content_access", "Access limit is invalid");
    }
    return this.clone((this.index.access[normalized] || [])
      .slice()
      .sort((left, right) => right.accessedAt.localeCompare(left.accessedAt)
        || right.accessId.localeCompare(left.accessId))
      .slice(0, limit));
  }

  async status() {
    this.assertLoaded();
    return {
      schemaVersion: AUDIT_CONTENT_SCHEMA_VERSION,
      streams: Object.keys(this.index.streams).length,
      objects: Object.keys(this.index.objects).length,
      collecting: Object.values(this.index.streams)
        .filter((stream) => stream.status === "collecting").length,
      stats: this.clone(this.index.stats),
    };
  }

  async close() {
    await this.operation;
  }
}
