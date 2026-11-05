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
import { canonicalJson, sha256Text } from "./events.js";

const STORE_VERSION = 2;
const MAGIC = Buffer.from("MAGPIE-CONTENT-1", "utf8");
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const STREAM_ID_PATTERN = /^str_[A-Za-z0-9_-]{43}$/;
const CONTENT_REF_PATTERN = /^ct_[A-Za-z0-9_-]{43}$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const AUTHORIZATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@_-]{7,127}$/;
const GRANT_ID_PATTERN = /^grt_[A-Za-z0-9_-]{43}$/;
const HOLD_ID_PATTERN = /^hld_[A-Za-z0-9_-]{43}$/;
const DELETION_ID_PATTERN = /^del_[A-Za-z0-9_-]{43}$/;
const EXPORT_ID_PATTERN = /^exp_[A-Za-z0-9_-]{43}$/;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const PURPOSE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const SOURCE_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const ERROR_CODE_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const PROOF_MAC_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const SESSION_HASH_PATTERN = /^[a-f0-9]{64}$/;
const STAGING_PATTERN = /^\.staging-(ct_[A-Za-z0-9_-]{43})-(del_[A-Za-z0-9_-]{43})\.bin$/;
const MAX_ACCESS_RECORDS = 10_000;
const DELETION_POLICY_VERSION = "m4d-retention-v1";

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

function timestamp(value) {
  if (!requiredString(value, 64)) return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value;
}

function retentionWindow(contentExpiresAt, metadataExpiresAt) {
  if (!timestamp(contentExpiresAt) || !timestamp(metadataExpiresAt)) return false;
  return new Date(metadataExpiresAt).getTime()
    >= new Date(contentExpiresAt).getTime();
}

function safeInteger(value, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function randomId(prefix) {
  return `${prefix}${crypto.randomBytes(32).toString("base64url")}`;
}

function redactedRequest(request) {
  return {
    schemaVersion: AUDIT_CONTENT_SCHEMA_VERSION,
    requestId: "req_redacted0000",
    sessionId: "ses_redacted0000",
    userId: "redacted",
    departmentId: "redacted",
    deviceId: "redacted",
    agentId: "redacted",
    contentKind: request.contentKind,
    mediaType: "text/plain",
    auditLevel: "L2",
    collection: {
      purpose: request.collection.purpose,
      authorizationId: "apr_redacted",
      confirmed: true,
      retentionDays: request.collection.retentionDays,
      metadataRetentionDays: request.collection.metadataRetentionDays
        ?? request.collection.retentionDays,
    },
  };
}

function expiresAt(startedAt, days) {
  const started = new Date(startedAt).getTime();
  if (!Number.isFinite(started)) throw new Error("Invalid content retention start");
  return new Date(started + days * 24 * 60 * 60 * 1000).toISOString();
}

function sessionHash(secret, adminId, organizationId, sessionId) {
  return crypto.createHmac("sha256", secret)
    .update(`session\u0000${adminId}\u0000${organizationId}\u0000${sessionId}`)
    .digest("hex");
}

function proofFields(proof) {
  return {
    deletionId: proof.deletionId,
    contentRef: proof.contentRef,
    streamId: proof.streamId,
    deletedAt: proof.deletedAt,
    plaintextSha256: proof.plaintextSha256,
    objectBytes: proof.objectBytes,
    retentionExpiresAt: proof.retentionExpiresAt,
    actorType: proof.actorType,
    actorId: proof.actorId,
    organizationId: proof.organizationId,
    sessionHash: proof.sessionHash,
    requestId: proof.requestId,
    sourceHash: proof.sourceHash,
    reason: proof.reason,
    approvalId: proof.approvalId,
    policyVersion: proof.policyVersion,
  };
}

function proofMac(secret, proof) {
  return crypto.createHmac("sha256", secret)
    .update(canonicalJson(proofFields(proof)))
    .digest("base64url");
}

export function contentSessionHash(secret, adminId, organizationId, sessionId) {
  return sessionHash(secret, adminId, organizationId, sessionId);
}

export function contentDeletionProofMac(secret, proof) {
  return proofMac(secret, proof);
}

function compareStreamsDesc(left, right) {
  if (left.createdAt !== right.createdAt) {
    return left.createdAt < right.createdAt ? 1 : -1;
  }
  if (left.streamId === right.streamId) return 0;
  return left.streamId < right.streamId ? 1 : -1;
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
    legalHolds: {},
    deletionProofs: {},
    exports: {},
    governanceIdempotency: {},
    stats: {
      streamsCreated: 0,
      chunksAccepted: 0,
      objectsFinalized: 0,
      streamsFailed: 0,
      contentDeleted: 0,
      metadataRedacted: 0,
      exportsCreated: 0,
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
    "contentRetentionExpiresAt",
    "metadataRetentionExpiresAt",
    "deletedAt",
    "deletionId",
    "metadataRedactedAt",
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
    "contentRetentionExpiresAt",
    "metadataRetentionExpiresAt",
  ]);
}

function validateStream(streamId, stream, version = STORE_VERSION) {
  if (!STREAM_ID_PATTERN.test(streamId)
      || !isPlainObject(stream)
      || Object.keys(stream).some((key) => !streamFields().has(key))
      || stream.streamId !== streamId
      || !["collecting", "finalized", "failed", "deleted"].includes(stream.status)
      || !timestamp(stream.createdAt)
      || !timestamp(stream.updatedAt)
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
  if (stream.status === "finalized" || stream.status === "deleted") {
    if (!CONTENT_REF_PATTERN.test(stream.contentRef || "")
        || !SHA256_PATTERN.test(stream.plaintextSha256 || "")
        || !timestamp(stream.finalizedAt)
        || stream.failureCode !== undefined
        || (version >= 2
          && !retentionWindow(
            stream.contentRetentionExpiresAt,
            stream.metadataRetentionExpiresAt,
          ))) {
      throw new ContentStoreError(500, "content_store_corrupt", `Content stream ${streamId} final state is invalid`);
    }
    redactionSummary(stream.redaction);
  }
  if (stream.status === "deleted"
      && (!DELETION_ID_PATTERN.test(stream.deletionId || "")
        || !timestamp(stream.deletedAt))) {
    throw new ContentStoreError(500, "content_store_corrupt", `Content stream ${streamId} deletion state is invalid`);
  }
  if (stream.status !== "deleted"
      && (stream.deletionId !== undefined || stream.deletedAt !== undefined)) {
    throw new ContentStoreError(500, "content_store_corrupt", `Content stream ${streamId} deletion state is invalid`);
  }
  if (stream.metadataRedactedAt !== undefined
      && (!timestamp(stream.metadataRedactedAt) || stream.status !== "deleted")) {
    throw new ContentStoreError(500, "content_store_corrupt", `Content stream ${streamId} metadata redaction state is invalid`);
  }
  if (stream.status === "failed"
      && !ERROR_CODE_PATTERN.test(stream.failureCode || "")) {
    throw new ContentStoreError(500, "content_store_corrupt", `Content stream ${streamId} failure state is invalid`);
  }
}

function validateObject(contentRef, object, version = STORE_VERSION) {
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
      || !timestamp(object.createdAt)
      || !safeInteger(object.retentionDays, 1, 3650)
      || (version >= 2
        && !retentionWindow(
          object.contentRetentionExpiresAt,
          object.metadataRetentionExpiresAt,
        ))) {
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
        "grantId",
        "adminId",
        "organizationId",
        "purpose",
        "approvalId",
      ].includes(key))
      || !/^acc_[A-Za-z0-9_-]{43}$/.test(record.accessId || "")
      || !requiredString(record.accessedAt, 64)
      || !requiredString(record.reason, 1024)
      || record.reason.length < 8
      || !AUTHORIZATION_ID_PATTERN.test(record.authorizationId || "")
      || !requiredString(record.requestId, 136)
      || !SOURCE_HASH_PATTERN.test(record.sourceHash || "")
      || !["success", "failed"].includes(record.outcome)
      || (record.grantId !== undefined && !GRANT_ID_PATTERN.test(record.grantId))
      || (record.adminId !== undefined && !SAFE_ID_PATTERN.test(record.adminId))
      || (record.organizationId !== undefined && !SAFE_ID_PATTERN.test(record.organizationId))
      || (record.purpose !== undefined && !PURPOSE_PATTERN.test(record.purpose))
      || (record.approvalId !== undefined
        && !AUTHORIZATION_ID_PATTERN.test(record.approvalId))
      || (record.outcome === "failed" && !ERROR_CODE_PATTERN.test(record.errorCode || ""))
      || (record.outcome === "success" && record.errorCode !== undefined)) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content access audit is invalid");
  }
}

const HOLD_SCOPE_FIELDS = new Set([
  "contentRef",
  "streamId",
  "userId",
  "departmentId",
  "deviceId",
  "agentId",
]);
const HOLD_FIELDS = new Set([
  "holdId",
  "scope",
  "reason",
  "approvalId",
  "custodianId",
  "startsAt",
  "expiresAt",
  "createdAt",
  "createdBy",
  "organizationId",
  "sessionHash",
  "status",
  "releasedAt",
  "releasedBy",
  "releaseReason",
  "releaseApprovalId",
]);
const PROOF_FIELDS = new Set([
  "deletionId",
  "contentRef",
  "streamId",
  "deletedAt",
  "plaintextSha256",
  "objectBytes",
  "retentionExpiresAt",
  "actorType",
  "actorId",
  "organizationId",
  "sessionHash",
  "requestId",
  "sourceHash",
  "reason",
  "approvalId",
  "policyVersion",
  "proofMac",
]);
const EXPORT_SCOPE_FIELDS = new Set([
  "contentRefs",
  "userId",
  "departmentId",
  "from",
  "to",
]);
const EXPORT_EVENT_FIELDS = new Set([
  "eventId",
  "type",
  "occurredAt",
  "actorId",
  "reason",
]);
const EXPORT_FIELDS = new Set([
  "exportId",
  "createdAt",
  "expiresAt",
  "organizationId",
  "adminId",
  "sessionHash",
  "purpose",
  "reason",
  "approvalId",
  "scope",
  "scopeHash",
  "auditEventId",
  "watermark",
  "objectCount",
  "bytes",
  "objectFile",
  "status",
  "downloadConsumedAt",
  "downloadCount",
  "events",
]);
const EVENT_ID_PATTERN = /^evt_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;

function validateScope(scope) {
  if (!isPlainObject(scope)
      || Object.keys(scope).length === 0
      || Object.keys(scope).some((key) => !HOLD_SCOPE_FIELDS.has(key))) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content legal hold scope is invalid");
  }
  if (scope.contentRef !== undefined && !CONTENT_REF_PATTERN.test(scope.contentRef)) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content legal hold scope is invalid");
  }
  if (scope.streamId !== undefined && !STREAM_ID_PATTERN.test(scope.streamId)) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content legal hold scope is invalid");
  }
  for (const field of ["userId", "departmentId", "deviceId", "agentId"]) {
    if (scope[field] !== undefined && !SAFE_ID_PATTERN.test(scope[field])) {
      throw new ContentStoreError(500, "content_store_corrupt", "Content legal hold scope is invalid");
    }
  }
}

function validateLegalHold(holdId, hold) {
  if (!HOLD_ID_PATTERN.test(holdId)
      || !isPlainObject(hold)
      || Object.keys(hold).some((key) => !HOLD_FIELDS.has(key))
      || hold.holdId !== holdId
      || !requiredString(hold.reason, 1024)
      || hold.reason.length < 8
      || !AUTHORIZATION_ID_PATTERN.test(hold.approvalId || "")
      || !SAFE_ID_PATTERN.test(hold.custodianId || "")
      || !timestamp(hold.createdAt)
      || !SAFE_ID_PATTERN.test(hold.createdBy || "")
      || !SAFE_ID_PATTERN.test(hold.organizationId || "")
      || !SESSION_HASH_PATTERN.test(hold.sessionHash || "")
      || !["active", "released"].includes(hold.status)) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content legal hold is invalid");
  }
  validateScope(hold.scope);
  try {
    if (!timestamp(hold.startsAt) || !timestamp(hold.expiresAt)) {
      throw new Error("invalid legal hold time");
    }
    const startsAt = new Date(hold.startsAt).getTime();
    const expiresAtMs = new Date(hold.expiresAt).getTime();
    if (!Number.isFinite(startsAt) || !Number.isFinite(expiresAtMs) || expiresAtMs <= startsAt) {
      throw new Error("invalid legal hold range");
    }
  } catch {
    throw new ContentStoreError(500, "content_store_corrupt", "Content legal hold is invalid");
  }
  if (hold.status === "released") {
    if (!timestamp(hold.releasedAt)
        || !SAFE_ID_PATTERN.test(hold.releasedBy || "")
        || !requiredString(hold.releaseReason, 1024)
        || hold.releaseReason.length < 8
        || !AUTHORIZATION_ID_PATTERN.test(hold.releaseApprovalId || "")) {
      throw new ContentStoreError(500, "content_store_corrupt", "Content legal hold release is invalid");
    }
  } else if (hold.releasedAt !== undefined
      || hold.releasedBy !== undefined
      || hold.releaseReason !== undefined
      || hold.releaseApprovalId !== undefined) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content legal hold release is invalid");
  }
}

function validateDeletionProof(deletionId, proof, secret) {
  if (!DELETION_ID_PATTERN.test(deletionId)
      || !isPlainObject(proof)
      || Object.keys(proof).some((key) => !PROOF_FIELDS.has(key))
      || proof.deletionId !== deletionId
      || !CONTENT_REF_PATTERN.test(proof.contentRef || "")
      || !STREAM_ID_PATTERN.test(proof.streamId || "")
      || !timestamp(proof.deletedAt)
      || !SHA256_PATTERN.test(proof.plaintextSha256 || "")
      || !safeInteger(proof.objectBytes)
      || !timestamp(proof.retentionExpiresAt)
      || !["manual", "system"].includes(proof.actorType)
      || !SAFE_ID_PATTERN.test(proof.actorId || "")
      || !SAFE_ID_PATTERN.test(proof.organizationId || "")
      || !SESSION_HASH_PATTERN.test(proof.sessionHash || "")
      || !requiredString(proof.requestId, 136)
      || !SOURCE_HASH_PATTERN.test(proof.sourceHash || "")
      || !requiredString(proof.reason, 1024)
      || proof.reason.length < 8
      || !AUTHORIZATION_ID_PATTERN.test(proof.approvalId || "")
      || proof.policyVersion !== DELETION_POLICY_VERSION
      || !PROOF_MAC_PATTERN.test(proof.proofMac || "")) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content deletion proof is invalid");
  }
  if (secret && proof.proofMac !== proofMac(secret, proof)) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content deletion proof failed verification");
  }
}

function validateExportScope(scope) {
  if (!isPlainObject(scope)
      || Object.keys(scope).length === 0
      || Object.keys(scope).some((key) => !EXPORT_SCOPE_FIELDS.has(key))) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content export scope is invalid");
  }
  if (scope.contentRefs !== undefined
      && (!Array.isArray(scope.contentRefs)
        || scope.contentRefs.length === 0
        || scope.contentRefs.length > 100
        || scope.contentRefs.some((value) => !CONTENT_REF_PATTERN.test(value))
        || new Set(scope.contentRefs).size !== scope.contentRefs.length)) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content export scope is invalid");
  }
  for (const field of ["userId", "departmentId"]) {
    if (scope[field] !== undefined && !SAFE_ID_PATTERN.test(scope[field])) {
      throw new ContentStoreError(500, "content_store_corrupt", "Content export scope is invalid");
    }
  }
  for (const field of ["from", "to"]) {
    if (scope[field] !== undefined && !timestamp(scope[field])) {
      throw new ContentStoreError(500, "content_store_corrupt", "Content export scope is invalid");
    }
  }
  if (scope.from && scope.to && scope.from > scope.to) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content export scope is invalid");
  }
}

function validateExportEvent(event) {
  if (!isPlainObject(event)
      || Object.keys(event).some((key) => !EXPORT_EVENT_FIELDS.has(key))
      || !EVENT_ID_PATTERN.test(event.eventId || "")
      || !["created", "downloaded", "download_rejected", "expired"].includes(event.type)
      || !timestamp(event.occurredAt)
      || !SAFE_ID_PATTERN.test(event.actorId || "")
      || (event.reason !== undefined
        && (!requiredString(event.reason, 1024) || event.reason.length < 8))) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content export event is invalid");
  }
}

function validateExport(exportId, record) {
  if (!EXPORT_ID_PATTERN.test(exportId)
      || !isPlainObject(record)
      || Object.keys(record).some((key) => !EXPORT_FIELDS.has(key))
      || record.exportId !== exportId
      || !timestamp(record.createdAt)
      || !timestamp(record.expiresAt)
      || record.expiresAt <= record.createdAt
      || !SAFE_ID_PATTERN.test(record.organizationId || "")
      || !SAFE_ID_PATTERN.test(record.adminId || "")
      || !SESSION_HASH_PATTERN.test(record.sessionHash || "")
      || !PURPOSE_PATTERN.test(record.purpose || "")
      || !requiredString(record.reason, 1024)
      || record.reason.length < 8
      || !AUTHORIZATION_ID_PATTERN.test(record.approvalId || "")
      || !SHA256_PATTERN.test(record.scopeHash || "")
      || !EVENT_ID_PATTERN.test(record.auditEventId || "")
      || !requiredString(record.watermark, 256)
      || !safeInteger(record.objectCount, 1, 100)
      || !safeInteger(record.bytes)
      || record.objectFile !== `${exportId}.mge`
      || !["active", "downloaded", "expired"].includes(record.status)
      || !safeInteger(record.downloadCount)
      || !Array.isArray(record.events)
      || record.events.length === 0
      || record.events.length > 10_000) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content export is invalid");
  }
  validateExportScope(record.scope);
  record.events.forEach(validateExportEvent);
  if (record.status === "active" && record.downloadConsumedAt !== undefined) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content export download state is invalid");
  }
  if (record.status === "downloaded" && record.downloadConsumedAt === undefined) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content export download state is invalid");
  }
  if (record.downloadConsumedAt !== undefined && !timestamp(record.downloadConsumedAt)) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content export download state is invalid");
  }
}

function validateGovernanceIdempotency(record) {
  if (!isPlainObject(record)
      || Object.keys(record).some((key) => !["operation", "fingerprint", "resultId"].includes(key))
      || !["legal_hold_create", "content_delete", "export_create"].includes(record.operation)
      || !SHA256_PATTERN.test(record.fingerprint || "")) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content governance idempotency index is invalid");
  }
  const patterns = {
    legal_hold_create: HOLD_ID_PATTERN,
    content_delete: DELETION_ID_PATTERN,
    export_create: EXPORT_ID_PATTERN,
  };
  if (!patterns[record.operation].test(record.resultId || "")) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content governance idempotency index is invalid");
  }
}

function validateIndex(index, version = STORE_VERSION, options = {}) {
  if (!isPlainObject(index)
      || Object.keys(index).some((key) => ![
        "version",
        "streams",
        "objects",
        "access",
        "idempotency",
        "legalHolds",
        "deletionProofs",
        "exports",
        "governanceIdempotency",
        "stats",
      ].includes(key))
      || index.version !== version
      || !isPlainObject(index.streams)
      || !isPlainObject(index.objects)
      || !isPlainObject(index.access)
      || !isPlainObject(index.idempotency)
      || !isPlainObject(index.stats)) {
    throw new ContentStoreError(500, "content_store_corrupt", "Content store index is invalid");
  }
  if (version === 1) {
    for (const [streamId, stream] of Object.entries(index.streams)) validateStream(streamId, stream, 1);
    for (const [contentRef, object] of Object.entries(index.objects)) validateObject(contentRef, object, 1);
  } else {
    if (!isPlainObject(index.legalHolds)
        || !isPlainObject(index.deletionProofs)
        || !isPlainObject(index.exports)
        || !isPlainObject(index.governanceIdempotency)) {
      throw new ContentStoreError(500, "content_store_corrupt", "Content store index is invalid");
    }
    for (const [streamId, stream] of Object.entries(index.streams)) validateStream(streamId, stream);
    for (const [contentRef, object] of Object.entries(index.objects)) validateObject(contentRef, object);
    for (const [holdId, hold] of Object.entries(index.legalHolds)) validateLegalHold(holdId, hold);
    for (const [deletionId, proof] of Object.entries(index.deletionProofs)) {
      validateDeletionProof(deletionId, proof, options.proofSecret);
    }
    for (const [exportId, record] of Object.entries(index.exports)) validateExport(exportId, record);
    for (const [key, record] of Object.entries(index.governanceIdempotency)) {
      if (!SHA256_PATTERN.test(key)) {
        throw new ContentStoreError(500, "content_store_corrupt", "Content governance idempotency index is invalid");
      }
      validateGovernanceIdempotency(record);
    }
  }
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
  const stats = version === 1
    ? ["streamsCreated", "chunksAccepted", "objectsFinalized", "streamsFailed"]
    : [
        "streamsCreated",
        "chunksAccepted",
        "objectsFinalized",
        "streamsFailed",
        "contentDeleted",
        "metadataRedacted",
        "exportsCreated",
      ];
  for (const key of stats) {
    if (!safeInteger(index.stats[key])) {
      throw new ContentStoreError(500, "content_store_corrupt", "Content store statistics are invalid");
    }
  }
}

function migrateV1(index) {
  for (const [contentRef, object] of Object.entries(index.objects)) {
    const stream = index.streams[object.streamId];
    const startedAt = stream?.finalizedAt || object.createdAt;
    object.contentRetentionExpiresAt = expiresAt(startedAt, object.retentionDays);
    object.metadataRetentionExpiresAt = object.contentRetentionExpiresAt;
    if (!CONTENT_REF_PATTERN.test(contentRef)) {
      throw new ContentStoreError(500, "content_store_corrupt", "Content store index is invalid");
    }
  }
  for (const stream of Object.values(index.streams)) {
    if (stream.request?.collection
        && stream.request.collection.metadataRetentionDays === undefined) {
      stream.request.collection.metadataRetentionDays = stream.request.collection.retentionDays;
    }
    if (stream.status === "finalized"
        && stream.contentRetentionExpiresAt === undefined) {
      const retentionDays = stream.request.collection.retentionDays;
      const metadataRetentionDays = stream.request.collection.metadataRetentionDays;
      stream.contentRetentionExpiresAt = expiresAt(stream.finalizedAt, retentionDays);
      stream.metadataRetentionExpiresAt = expiresAt(stream.finalizedAt, metadataRetentionDays);
    }
  }
  index.version = STORE_VERSION;
  index.legalHolds = {};
  index.deletionProofs = {};
  index.exports = {};
  index.governanceIdempotency = {};
  index.stats.contentDeleted = 0;
  index.stats.metadataRedacted = 0;
  index.stats.exportsCreated = 0;
  return index;
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
    if (options.proofSecret !== undefined
        && (typeof options.proofSecret !== "string"
          || options.proofSecret.length < 32
          || options.proofSecret.length > 4096)) {
      throw new Error("ContentStore proofSecret must be from 32 to 4096 characters");
    }
    this.proofSecret = options.proofSecret || "";
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
      await this.recoverStagingFiles();
      await this.persist();
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new ContentStoreError(500, "content_store_corrupt", "Content store index is not valid JSON");
    }
    if (!isPlainObject(parsed)
        || ![1, STORE_VERSION].includes(parsed.version)) {
      throw new ContentStoreError(500, "content_store_corrupt", "Content store index is invalid");
    }
    let changed = false;
    if (parsed.version === 1) {
      validateIndex(parsed, 1);
      this.index = migrateV1(parsed);
      validateIndex(this.index, STORE_VERSION, { proofSecret: this.proofSecret || undefined });
      changed = true;
    } else {
      validateIndex(parsed, STORE_VERSION, { proofSecret: this.proofSecret || undefined });
      this.index = parsed;
    }
    changed = await this.recoverStagingFiles() || changed;
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

  async recoverStagingFiles() {
    let changed = false;
    const entries = await fs.readdir(this.objectsDirectory, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const match = STAGING_PATTERN.exec(entry.name);
      if (!match) continue;
      const [, contentRef, deletionId] = match;
      const stagingPath = path.join(this.objectsDirectory, entry.name);
      const object = this.index.objects[contentRef];
      const proof = this.index.deletionProofs[deletionId];
      if (!object || (proof && proof.contentRef !== contentRef)) {
        await fs.unlink(stagingPath).catch(() => {});
        changed = true;
        continue;
      }
      const objectPath = path.join(this.objectsDirectory, object.objectFile);
      try {
        await fs.access(objectPath);
        await fs.unlink(stagingPath);
        changed = true;
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
        try {
          await fs.rename(stagingPath, objectPath);
        } catch (renameError) {
          if (renameError.code !== "ENOENT") throw renameError;
        }
      }
    }
    return changed;
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

  async searchStreams(filters = {}, after = null, limit = 51) {
    this.assertLoaded();
    if (!safeInteger(limit, 1, 201)) {
      throw new ContentStoreError(400, "invalid_content_query", "Content query limit is invalid");
    }
    const matches = (stream) => {
      const request = stream.request || {};
      return (!filters.userId || request.userId === filters.userId)
        && (!filters.departmentId || request.departmentId === filters.departmentId)
        && (!filters.deviceId || request.deviceId === filters.deviceId)
        && (!filters.agentId || request.agentId === filters.agentId)
        && (!filters.modelId || request.modelId === filters.modelId)
        && (!filters.mcpServerId || request.mcpServerId === filters.mcpServerId)
        && (!filters.toolName || request.toolName === filters.toolName)
        && (!filters.contentKind || request.contentKind === filters.contentKind)
        && (!filters.status || stream.status === filters.status)
        && (!filters.from || stream.createdAt >= filters.from)
        && (!filters.to || stream.createdAt <= filters.to);
    };
    return Object.values(this.index.streams)
      .filter(matches)
      .sort(compareStreamsDesc)
      .filter((stream) => !after || stream.createdAt < after.createdAt
        || (stream.createdAt === after.createdAt && stream.streamId < after.streamId))
      .slice(0, limit)
      .map((stream) => this.clone(stream));
  }

  async hasObject(contentRef) {
    this.assertLoaded();
    const normalized = validateContentRef(contentRef);
    return Boolean(this.index.objects[normalized]);
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
        contentRetentionExpiresAt: expiresAt(
          now,
          stream.request.collection.retentionDays,
        ),
        metadataRetentionExpiresAt: expiresAt(
          now,
          stream.request.collection.metadataRetentionDays
            ?? stream.request.collection.retentionDays,
        ),
      };
      Object.assign(stream, {
        status: "finalized",
        contentRef,
        redaction: summary,
        plaintextSha256,
        bytes,
        updatedAt: now,
        finalizedAt: now,
        contentRetentionExpiresAt: object.contentRetentionExpiresAt,
        metadataRetentionExpiresAt: object.metadataRetentionExpiresAt,
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
      ...(context.grantId ? { grantId: context.grantId } : {}),
      ...(context.adminId ? { adminId: context.adminId } : {}),
      ...(context.organizationId ? { organizationId: context.organizationId } : {}),
      ...(context.purpose ? { purpose: context.purpose } : {}),
      ...(context.approvalId ? { approvalId: context.approvalId } : {}),
    };
    validateAccessRecord(record);
    const existing = this.index.access[contentRef];
    const records = existing ? existing.slice() : [];
    if (existing) this.index.access[contentRef] = records;
    else this.index.access[contentRef] = records;
    records.push(record);
    if (records.length > MAX_ACCESS_RECORDS) {
      records.splice(0, records.length - MAX_ACCESS_RECORDS);
    }
    try {
      await this.persist();
    } catch (error) {
      if (existing) this.index.access[contentRef] = existing;
      else delete this.index.access[contentRef];
      throw error;
    }
    return this.clone(record);
  }

  validateAccessContext(context) {
    if (!isPlainObject(context)
        || !requiredString(context.reason, 1024)
        || context.reason.length < 8
        || !AUTHORIZATION_ID_PATTERN.test(context.authorizationId || "")
        || !requiredString(context.requestId, 136)
        || !SOURCE_HASH_PATTERN.test(context.sourceHash || "")
        || (context.grantId !== undefined && !GRANT_ID_PATTERN.test(context.grantId))
        || (context.adminId !== undefined && !SAFE_ID_PATTERN.test(context.adminId))
        || (context.organizationId !== undefined && !SAFE_ID_PATTERN.test(context.organizationId))
        || (context.purpose !== undefined && !PURPOSE_PATTERN.test(context.purpose))
        || (context.approvalId !== undefined
          && !AUTHORIZATION_ID_PATTERN.test(context.approvalId))) {
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

  async redactStreamMetadata(streamId, redactedAt = this.timestamp(), guard = null) {
    return this.withMutation(async () => {
      const normalized = validateContentStreamId(streamId);
      const stream = this.index.streams[normalized];
      if (!stream) {
        throw new ContentStoreError(404, "content_stream_not_found", "Content stream not found");
      }
      if (stream.status !== "deleted") {
        throw new ContentStoreError(409, "content_object_not_deleted", "Content must be deleted before metadata redaction");
      }
      if (stream.metadataRedactedAt) {
        return { stream: this.clone(stream), redacted: false };
      }
      if (guard) guard(this.clone(stream));
      if (!requiredString(redactedAt, 64)) {
        throw new ContentStoreError(400, "invalid_content_governance_request", "Metadata redaction time is invalid");
      }
      const previous = this.clone(stream);
      stream.request = redactedRequest(stream.request);
      stream.metadataRedactedAt = redactedAt;
      stream.updatedAt = redactedAt;
      this.index.stats.metadataRedacted += 1;
      try {
        await this.persist();
      } catch (error) {
        this.index.streams[normalized] = previous;
        this.index.stats.metadataRedacted -= 1;
        throw error;
      }
      return { stream: this.clone(stream), redacted: true };
    });
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
      legalHolds: Object.keys(this.index.legalHolds).length,
      deletionProofs: Object.keys(this.index.deletionProofs).length,
      exports: Object.keys(this.index.exports).length,
    };
  }

  async close() {
    await this.operation;
  }
}
