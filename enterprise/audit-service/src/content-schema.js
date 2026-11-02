import {
  AuditEventValidationError,
  canonicalJson,
  plainObject,
  sha256Text,
} from "./events.js";

export const AUDIT_CONTENT_SCHEMA_VERSION = 1;
export const AUDIT_CONTENT_LEVELS = Object.freeze(["L2"]);
export const CONTENT_KINDS = Object.freeze([
  "prompt",
  "response",
  "tool_arguments",
  "tool_result",
]);
export const CONTENT_PURPOSES = Object.freeze([
  "security_investigation",
  "incident_response",
  "compliance_review",
  "legal_investigation",
]);

const STREAM_ID_PATTERN = /^str_[A-Za-z0-9_-]{43}$/;
const CONTENT_REF_PATTERN = /^ct_[A-Za-z0-9_-]{43}$/;
const REQUEST_ID_PATTERN = /^req_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const SESSION_ID_PATTERN = /^ses_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const SAFE_CODE_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const MODEL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*\/[A-Za-z0-9][A-Za-z0-9._:@+-]{0,159}$/;
const TOOL_NAME_PATTERN = /^[A-Za-z][A-Za-z0-9._:-]{0,127}$/;
const AUTHORIZATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{7,127}$/;
const MAX_SEQUENCE = 99_999;
const MAX_CHUNK_TEXT_LENGTH = 1024 * 1024;

const STREAM_FIELDS = new Set([
  "schemaVersion",
  "requestId",
  "sessionId",
  "userId",
  "departmentId",
  "deviceId",
  "agentId",
  "modelId",
  "providerId",
  "mcpServerId",
  "toolName",
  "contentKind",
  "mediaType",
  "auditLevel",
  "collection",
]);
const COLLECTION_FIELDS = new Set([
  "purpose",
  "authorizationId",
  "confirmed",
  "retentionDays",
]);
const CHUNK_FIELDS = new Set(["schemaVersion", "sequence", "text", "final"]);
const CONTENT_KIND_SET = new Set(CONTENT_KINDS);
const CONTENT_PURPOSE_SET = new Set(CONTENT_PURPOSES);

export class AuditContentValidationError extends AuditEventValidationError {
  constructor(code, message) {
    super(code, message);
    this.name = "AuditContentValidationError";
  }
}

function invalid(code, message) {
  throw new AuditContentValidationError(code, message);
}

function requiredText(value, name, pattern, maximum = 128, code = "invalid_content_request") {
  if (typeof value !== "string"
      || value.length === 0
      || value.length > maximum
      || !pattern.test(value)) {
    invalid(code, `${name} is invalid`);
  }
  return value;
}

function optionalText(value, name, pattern, maximum = 128) {
  if (value === undefined) return undefined;
  return requiredText(value, name, pattern, maximum);
}

function safeInteger(value, name, minimum, maximum, code = "invalid_content_request") {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    invalid(code, `${name} is invalid`);
  }
  return value;
}

function hasForbiddenControlCharacters(value) {
  return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
}

export function validateContentStreamId(value) {
  return requiredText(value, "streamId", STREAM_ID_PATTERN, 47, "invalid_content_stream_id");
}

export function validateContentRef(value) {
  return requiredText(value, "contentRef", CONTENT_REF_PATTERN, 46, "invalid_content_ref");
}

export function validateContentStreamRequest(value) {
  if (!plainObject(value)) invalid("invalid_content_request", "The content stream must be a JSON object");
  const unknown = Object.keys(value).find((key) => !STREAM_FIELDS.has(key));
  if (unknown) invalid("invalid_content_request", `The content stream contains an unknown field: ${unknown}`);

  if (value.schemaVersion !== AUDIT_CONTENT_SCHEMA_VERSION) {
    invalid("invalid_content_request", "schemaVersion is unsupported");
  }
  for (const field of [
    "requestId",
    "sessionId",
    "userId",
    "departmentId",
    "deviceId",
    "agentId",
    "contentKind",
    "mediaType",
    "auditLevel",
    "collection",
  ]) {
    if (!(field in value)) invalid("invalid_content_request", `The content stream is missing required field: ${field}`);
  }
  if (value.auditLevel === "L3") {
    invalid("content_level_not_supported", "L3 raw content capture is disabled");
  }
  if (value.auditLevel !== "L2") {
    invalid("content_level_not_supported", "Only L2 redacted content capture is supported");
  }
  if (value.mediaType !== "text/plain") {
    invalid("content_media_type_unsupported", "Only text/plain content is supported");
  }
  if (!CONTENT_KIND_SET.has(value.contentKind)) {
    invalid("invalid_content_request", "contentKind is unsupported");
  }
  if (!plainObject(value.collection)) {
    invalid("invalid_content_collection", "collection must be a JSON object");
  }
  const unknownCollection = Object.keys(value.collection)
    .find((key) => !COLLECTION_FIELDS.has(key));
  if (unknownCollection) {
    invalid("invalid_content_collection", `collection contains an unknown field: ${unknownCollection}`);
  }
  for (const field of ["purpose", "authorizationId", "confirmed", "retentionDays"]) {
    if (!(field in value.collection)) {
      invalid("invalid_content_collection", `collection is missing required field: ${field}`);
    }
  }
  if (!CONTENT_PURPOSE_SET.has(value.collection.purpose)) {
    invalid("invalid_content_collection", "collection.purpose is unsupported");
  }
  if (value.collection.confirmed !== true) {
    invalid("content_confirmation_required", "collection.confirmed must be true");
  }
  const authorizationId = requiredText(
    value.collection.authorizationId,
    "collection.authorizationId",
    AUTHORIZATION_ID_PATTERN,
    128,
    "invalid_content_collection",
  );
  const retentionDays = safeInteger(
    value.collection.retentionDays,
    "collection.retentionDays",
    1,
    3650,
    "invalid_content_collection",
  );

  const request = {
    schemaVersion: AUDIT_CONTENT_SCHEMA_VERSION,
    requestId: requiredText(value.requestId, "requestId", REQUEST_ID_PATTERN, 135),
    sessionId: requiredText(value.sessionId, "sessionId", SESSION_ID_PATTERN, 135),
    userId: requiredText(value.userId, "userId", SAFE_ID_PATTERN),
    departmentId: requiredText(value.departmentId, "departmentId", SAFE_ID_PATTERN),
    deviceId: requiredText(value.deviceId, "deviceId", SAFE_ID_PATTERN),
    agentId: requiredText(value.agentId, "agentId", SAFE_ID_PATTERN),
    contentKind: value.contentKind,
    mediaType: "text/plain",
    auditLevel: "L2",
    collection: {
      purpose: value.collection.purpose,
      authorizationId,
      confirmed: true,
      retentionDays,
    },
  };
  for (const [name, pattern, maximum] of [
    ["modelId", MODEL_ID_PATTERN, 192],
    ["providerId", SAFE_ID_PATTERN, 128],
    ["mcpServerId", SAFE_ID_PATTERN, 128],
    ["toolName", TOOL_NAME_PATTERN, 128],
  ]) {
    const normalized = optionalText(value[name], name, pattern, maximum);
    if (normalized !== undefined) request[name] = normalized;
  }
  if (request.contentKind === "tool_arguments" || request.contentKind === "tool_result") {
    if (!request.toolName) {
      invalid("invalid_content_request", "Tool content requires toolName");
    }
  }
  return canonicalize(request);
}

export function validateContentChunk(value) {
  if (!plainObject(value)) invalid("invalid_content_chunk", "The content chunk must be a JSON object");
  const unknown = Object.keys(value).find((key) => !CHUNK_FIELDS.has(key));
  if (unknown) invalid("invalid_content_chunk", `The content chunk contains an unknown field: ${unknown}`);
  if (value.schemaVersion !== AUDIT_CONTENT_SCHEMA_VERSION) {
    invalid("invalid_content_chunk", "schemaVersion is unsupported");
  }
  const sequence = safeInteger(
    value.sequence,
    "sequence",
    0,
    MAX_SEQUENCE,
    "invalid_content_chunk",
  );
  if (typeof value.text !== "string" || value.text.length > MAX_CHUNK_TEXT_LENGTH) {
    invalid("invalid_content_chunk", "text is invalid");
  }
  if (value.text.length === 0 && value.final !== true) {
    invalid("invalid_content_chunk", "Only the final chunk may be empty");
  }
  if (hasForbiddenControlCharacters(value.text)) {
    invalid("invalid_content_chunk", "text contains unsupported control characters");
  }
  if (typeof value.final !== "boolean") {
    invalid("invalid_content_chunk", "final must be a boolean");
  }
  return {
    schemaVersion: AUDIT_CONTENT_SCHEMA_VERSION,
    sequence,
    text: value.text,
    final: value.final,
  };
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (plainObject(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

export function contentFingerprint(value) {
  return sha256Text(canonicalJson(value));
}

export function contentChunkFingerprint(chunk) {
  return sha256Text(canonicalJson(chunk));
}

export function publicContentStream(stream) {
  const metadata = plainObject(stream?.request)
    ? {
        ...stream.request,
        status: stream.status,
        createdAt: stream.createdAt,
        updatedAt: stream.updatedAt,
        nextSequence: stream.nextSequence,
        chunkCount: stream.chunkCount,
        bytes: stream.bytes,
        contentRef: stream.contentRef,
        redaction: stream.redaction,
        failureCode: stream.failureCode,
        finalizedAt: stream.finalizedAt,
      }
    : stream;
  if (!plainObject(metadata)) return null;
  return {
    streamId: stream.streamId,
    requestId: metadata.requestId,
    sessionId: metadata.sessionId,
    userId: metadata.userId,
    departmentId: metadata.departmentId,
    deviceId: metadata.deviceId,
    agentId: metadata.agentId,
    ...(metadata.modelId ? { modelId: metadata.modelId } : {}),
    ...(metadata.providerId ? { providerId: metadata.providerId } : {}),
    ...(metadata.mcpServerId ? { mcpServerId: metadata.mcpServerId } : {}),
    ...(metadata.toolName ? { toolName: metadata.toolName } : {}),
    contentKind: metadata.contentKind,
    mediaType: metadata.mediaType,
    auditLevel: metadata.auditLevel,
    collection: structuredClone(metadata.collection),
    status: metadata.status,
    createdAt: metadata.createdAt,
    updatedAt: metadata.updatedAt,
    nextSequence: metadata.nextSequence,
    chunkCount: metadata.chunkCount,
    bytes: metadata.bytes,
    ...(metadata.contentRef ? { contentRef: metadata.contentRef } : {}),
    ...(metadata.redaction ? { redaction: structuredClone(metadata.redaction) } : {}),
    ...(metadata.failureCode ? { failureCode: metadata.failureCode } : {}),
    ...(metadata.finalizedAt ? { finalizedAt: metadata.finalizedAt } : {}),
  };
}

export function isSafeContentCode(value) {
  return typeof value === "string" && SAFE_CODE_PATTERN.test(value);
}
