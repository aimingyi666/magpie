import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";

import {
  RESOURCE_DELIVERY_MODES,
  RESOURCE_KINDS,
  buildSignedManifest,
  publicKeyFingerprint,
  sha256Digest,
  verifySignedManifest,
} from "./manifest.js";
import { FileObjectStore } from "./object-store.js";
import { ResourceStore } from "./store.js";

const SCHEMA_VERSION = 1;
const RESOURCE_ID_PATTERN = /^res_[a-z0-9]{16,64}$/;
const RELEASE_ID_PATTERN = /^rel_[a-z0-9]{16,64}$/;
const IDEMPOTENCY_KEY_PATTERN = /^[\u0021-\u007e]{1,128}$/;
const OPERATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SAFE_TEXT_PATTERN = /^[^\u0000-\u001f\u007f]*$/;
const KIND_SET = new Set(RESOURCE_KINDS);
const DELIVERY_MODE_SET = new Set(RESOURCE_DELIVERY_MODES);
const DANGEROUS_JSON_KEYS = new Set([
  "privatekey",
  "clientsecret",
  "password",
  "apikey",
  "accesstoken",
  "refreshtoken",
  "bearertoken",
  "secret",
  "token",
  "authorization",
]);
const PRIVATE_KEY_PATTERN = /-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/;
const LITERAL_SECRET_PATTERNS = Object.freeze([
  PRIVATE_KEY_PATTERN,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
]);

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

function newStableId(prefix) {
  return `${prefix}${crypto.randomUUID().replaceAll("-", "")}`;
}

function sha256Text(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (plainObject(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalValue(value[key])]),
    );
  }
  if (value === null || ["string", "boolean"].includes(typeof value)) return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  throw new ApiError(400, "invalid_request", "The request contains an unsupported JSON value");
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function requestFingerprint(method, path, actorValue, body) {
  return sha256Digest(Buffer.from(canonicalJson({
    method,
    path,
    actor: actorValue,
    body,
  }), "utf8"));
}

function assertExactFields(value, required, optional = []) {
  if (!plainObject(value)) {
    throw new ApiError(400, "invalid_request", "The request body must be a JSON object");
  }
  const allowed = new Set([...required, ...optional]);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new ApiError(400, "invalid_request", "The request contains an unknown field");
  }
  if (required.some((key) => !(key in value))) {
    throw new ApiError(400, "invalid_request", "The request is missing a required field");
  }
}

function requiredText(value, name, maximum = 128) {
  if (typeof value !== "string"
      || value.length === 0
      || value.length > maximum
      || !SAFE_TEXT_PATTERN.test(value)) {
    throw new ApiError(400, "invalid_request", `${name} is invalid`);
  }
  return value;
}

function cleanReason(value) {
  const reason = requiredText(value, "reason", 500).trim();
  if (!reason) throw new ApiError(400, "invalid_reason", "reason is required");
  return reason;
}

function cleanOperationId(value) {
  if (typeof value !== "string" || !OPERATION_ID_PATTERN.test(value)) {
    throw new ApiError(400, "invalid_operation_id", "operationId is invalid");
  }
  return value;
}

function cleanExpectedUpdatedAt(value) {
  const timestamp = requiredText(value, "expectedUpdatedAt", 64);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(timestamp)
      || !Number.isFinite(Date.parse(timestamp))) {
    throw new ApiError(400, "invalid_expected_updated_at", "expectedUpdatedAt is invalid");
  }
  return timestamp;
}

function cleanApprovalId(value) {
  if (typeof value !== "string" || !value.trim()) {
    throw new ApiError(400, "approval_required", "approvalId is required");
  }
  const approvalId = requiredText(value, "approvalId", 128).trim();
  return approvalId;
}

function cleanVersion(value) {
  const version = requiredText(value, "resourceVersion", 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/.test(version)) {
    throw new ApiError(400, "invalid_resource_version", "resourceVersion is invalid");
  }
  return version;
}

function cleanMediaType(value) {
  const mediaType = requiredText(value, "mediaType", 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*(?:; charset=utf-8)?$/.test(mediaType)) {
    throw new ApiError(400, "invalid_media_type", "mediaType is invalid");
  }
  return mediaType.toLowerCase();
}

function cleanAssignments(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) {
    throw new ApiError(400, "invalid_assignments", "assignments must contain 1-100 identifiers");
  }
  const assignments = value.map((item) => requiredText(item, "assignment", 128));
  if (new Set(assignments).size !== assignments.length) {
    throw new ApiError(400, "invalid_assignments", "assignments must not contain duplicates");
  }
  return [...assignments].sort();
}

function cleanCompatibility(value) {
  if (!plainObject(value)
      || Object.keys(value).length !== 1
      || !("minClientVersion" in value)) {
    throw new ApiError(400, "invalid_compatibility", "compatibility.minClientVersion is required");
  }
  return {
    minClientVersion: requiredText(value.minClientVersion, "minClientVersion", 64),
  };
}

function decodeContent(value, maximumBytes) {
  if (typeof value !== "string" || !value) {
    throw new ApiError(400, "invalid_content", "contentBase64 is required");
  }
  if (value.length % 4 !== 0
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new ApiError(400, "invalid_content", "contentBase64 is invalid");
  }
  const content = Buffer.from(value, "base64");
  if (content.length === 0) {
    throw new ApiError(400, "invalid_content", "resource content must not be empty");
  }
  if (content.length > maximumBytes) {
    throw new ApiError(413, "content_too_large", "Resource content is too large");
  }
  if (content.toString("base64") !== value) {
    throw new ApiError(400, "invalid_content", "contentBase64 is not canonical");
  }
  return content;
}

function referenceLike(value) {
  const text = value.trim();
  return text === ""
    || /^\$\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(text)
    || /^\{\{[A-Za-z_][A-Za-z0-9_]*\}\}$/.test(text)
    || /^<[^>]+>$/.test(text)
    || /^(?:env|secret|vault|kms):\/\/[A-Za-z0-9._:/-]+$/.test(text)
    || /^\$[A-Z_][A-Z0-9_]*$/.test(text)
    || /^Bearer\s+\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(text);
}

function scanJsonSecrets(value, depth = 0) {
  if (depth > 20) throw new ApiError(400, "content_secret_detected", "Resource content is too deeply nested");
  if (Array.isArray(value)) {
    for (const item of value) scanJsonSecrets(item, depth + 1);
    return;
  }
  if (!plainObject(value)) return;
  for (const [key, item] of Object.entries(value)) {
    if (DANGEROUS_JSON_KEYS.has(key.toLowerCase())
        && typeof item === "string"
        && item.length >= 8
        && !referenceLike(item)) {
      throw new ApiError(400, "content_secret_detected", "Resource content must use a Secret Reference");
    }
    scanJsonSecrets(item, depth + 1);
  }
}

function scanForSecrets(content, metadata = {}) {
  const text = content.toString("utf8");
  for (const pattern of LITERAL_SECRET_PATTERNS) {
    if (pattern.test(text)) {
      throw new ApiError(400, "content_secret_detected", "Resource content contains a plaintext secret");
    }
  }
  try {
    scanJsonSecrets(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(content)));
  } catch (error) {
    if (error instanceof ApiError) throw error;
  }
  const metadataText = JSON.stringify(metadata);
  for (const pattern of LITERAL_SECRET_PATTERNS) {
    if (pattern.test(metadataText)) {
      throw new ApiError(400, "content_secret_detected", "Request metadata contains a plaintext secret");
    }
  }
}

function publicRelease(release) {
  return {
    id: release.id,
    resourceId: release.resourceId,
    resourceVersion: release.resourceVersion,
    status: release.status,
    hash: release.hash,
    contentBytes: release.contentBytes,
    mediaType: release.mediaType,
    manifestDigest: release.manifest.manifestDigest,
    previousReleaseId: release.manifest.previousReleaseId,
    createdAt: release.createdAt,
    createdBy: release.createdBy,
    publishedAt: release.publishedAt || "",
    publishedBy: release.publishedBy || "",
  };
}

function publicResource(resource, releases) {
  const current = resource.currentReleaseId ? releases[resource.currentReleaseId] : null;
  return {
    id: resource.id,
    kind: resource.kind,
    name: resource.name,
    description: resource.description,
    publisher: resource.publisher,
    deliveryMode: resource.deliveryMode,
    assignments: [...resource.assignments],
    compatibility: { ...resource.compatibility },
    status: resource.status,
    currentReleaseId: resource.currentReleaseId,
    createdAt: resource.createdAt,
    createdBy: resource.createdBy,
    updatedAt: resource.updatedAt,
    updatedBy: resource.updatedBy,
    currentRelease: current ? publicRelease(current) : null,
  };
}

function releaseBelongsTo(release, resourceId) {
  return release && release.resourceId === resourceId;
}

function idempotencyKey(req) {
  const value = String(req.headers["idempotency-key"] || "").trim();
  if (!value) throw new ApiError(400, "idempotency_key_required", "Idempotency-Key is required");
  if (!IDEMPOTENCY_KEY_PATTERN.test(value)) {
    throw new ApiError(400, "invalid_idempotency_key", "Idempotency-Key is invalid");
  }
  return value;
}

function actor(req) {
  return requiredText(String(req.headers["x-magpie-actor"] || "").trim(), "X-Magpie-Actor", 128);
}

function idempotencyRecord(data, keyHash, fingerprint) {
  const existing = data.idempotency[keyHash];
  if (!existing) return null;
  if (existing.fingerprint !== fingerprint) {
    throw new ApiError(409, "idempotency_conflict", "Idempotency-Key was used for another request");
  }
  return {
    replay: true,
    statusCode: existing.statusCode,
    responseBody: existing.responseBody,
  };
}

async function lookupIdempotency(store, keyHash, fingerprint) {
  return store.read((data) => idempotencyRecord(data, keyHash, fingerprint));
}

function persistIdempotency(data, keyHash, fingerprint, operationId, path, statusCode, responseBody, now) {
  data.idempotency[keyHash] = {
    fingerprint,
    operationId,
    method: "POST",
    path,
    statusCode,
    responseBody,
    createdAt: now,
  };
}

function assertExpectedUpdatedAt(resource, expectedUpdatedAt) {
  if (resource.updatedAt !== expectedUpdatedAt) {
    throw new ApiError(409, "stale_resource", "The resource changed; refresh and try again");
  }
}

function jsonResponse(res, statusCode, value, requestIdValue, extraHeaders = {}) {
  const body = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(body.length),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-request-id": requestIdValue,
    ...extraHeaders,
  });
  res.end(body);
}

function errorResponse(res, requestIdValue, error, logger) {
  const normalized = error instanceof ApiError
    ? error
    : new ApiError(500, "internal_error", "The resource service could not complete the request", true);
  if (!(error instanceof ApiError) && logger) {
    logger({
      requestId: requestIdValue,
      code: normalized.code,
      errorName: error?.name || "Error",
    });
  }
  jsonResponse(res, normalized.statusCode, {
    schemaVersion: SCHEMA_VERSION,
    ok: false,
    requestId: requestIdValue,
    error: {
      code: normalized.code,
      message: normalized.message,
      retryable: normalized.retryable,
    },
  }, requestIdValue);
}

function bearerMatches(req, expected) {
  const match = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ""));
  return Boolean(match) && safeEqual(match[1], expected);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers["content-length"] || 0);
    if (Number.isFinite(declared) && declared > limit) {
      req.resume();
      reject(new ApiError(413, "request_too_large", "The request body is too large"));
      return;
    }
    const chunks = [];
    let total = 0;
    let overflow = false;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > limit) {
        overflow = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (overflow) reject(new ApiError(413, "request_too_large", "The request body is too large"));
      else resolve(Buffer.concat(chunks));
    });
    req.on("error", () => {
      reject(new ApiError(400, "request_failed", "The request body could not be read", true));
    });
  });
}

async function readJsonBody(req, limit) {
  if (!/^application\/json(?:\s*;|$)/i.test(String(req.headers["content-type"] || ""))) {
    throw new ApiError(415, "unsupported_media_type", "Content-Type must be application/json");
  }
  const body = await readBody(req, limit);
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new ApiError(400, "invalid_json", "The request body must be UTF-8 JSON");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ApiError(400, "invalid_json", "The request body must be valid JSON");
  }
  if (!plainObject(value)) {
    throw new ApiError(400, "invalid_request", "The request body must be a JSON object");
  }
  return value;
}

function routeOf(pathname) {
  if (pathname === "/healthz") return { name: "health" };
  if (pathname === "/api/v1/admin/resources") return { name: "resources" };
  if (pathname === "/api/v1/admin/signing-key") return { name: "signing-key" };
  if (pathname === "/api/v1/admin/audit-logs") return { name: "audit-logs" };
  let match = /^\/api\/v1\/admin\/resources\/(res_[a-z0-9]{16,64})$/.exec(pathname);
  if (match) return { name: "resource", resourceId: match[1] };
  match = /^\/api\/v1\/admin\/resources\/(res_[a-z0-9]{16,64})\/releases$/.exec(pathname);
  if (match) return { name: "releases", resourceId: match[1] };
  match = /^\/api\/v1\/admin\/resources\/(res_[a-z0-9]{16,64})\/publish$/.exec(pathname);
  if (match) return { name: "publish", resourceId: match[1] };
  match = /^\/api\/v1\/admin\/resources\/(res_[a-z0-9]{16,64})\/rollback$/.exec(pathname);
  if (match) return { name: "rollback", resourceId: match[1] };
  match = /^\/api\/v1\/admin\/resources\/(res_[a-z0-9]{16,64})\/audit-logs$/.exec(pathname);
  if (match) return { name: "resource-audit-logs", resourceId: match[1] };
  match = /^\/api\/v1\/admin\/resources\/(res_[a-z0-9]{16,64})\/releases\/(rel_[a-z0-9]{16,64})\/manifest$/.exec(pathname);
  if (match) return { name: "manifest", resourceId: match[1], releaseId: match[2] };
  match = /^\/api\/v1\/admin\/resources\/(res_[a-z0-9]{16,64})\/releases\/(rel_[a-z0-9]{16,64})\/content$/.exec(pathname);
  if (match) return { name: "content", resourceId: match[1], releaseId: match[2] };
  return { name: "not-found" };
}

class FixedWindowRateLimiter {
  constructor(limit, windowMs = 60_000) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.clients = new Map();
  }

  allow(key, now = Date.now()) {
    const window = Math.floor(now / this.windowMs);
    const entry = this.clients.get(key);
    if (!entry || entry.window !== window) {
      this.clients.set(key, { window, count: 1 });
      if (this.clients.size > 10_000) {
        for (const [client, value] of this.clients) {
          if (value.window !== window) this.clients.delete(client);
        }
      }
      return true;
    }
    if (entry.count >= this.limit) return false;
    entry.count += 1;
    return true;
  }
}

async function loadSigningKey(config) {
  let bytes;
  try {
    const stat = await fs.stat(config.signingPrivateKeyPath);
    if (!stat.isFile() || stat.size < 1 || stat.size > 32 * 1024) {
      throw new Error("signing key file has an invalid size");
    }
    if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
      throw new Error("signing key file permissions must be 0600 or stricter");
    }
    bytes = await fs.readFile(config.signingPrivateKeyPath);
  } catch {
    throw new Error("RESOURCE_SIGNING_PRIVATE_KEY_PATH could not be loaded");
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey(bytes);
  } catch {
    throw new Error("RESOURCE_SIGNING_PRIVATE_KEY_PATH is not a valid private key");
  }
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("RESOURCE_SIGNING_PRIVATE_KEY_PATH must contain an Ed25519 key");
  }
  const publicKey = crypto.createPublicKey(privateKey);
  return {
    privateKey,
    publicKey,
    keyId: config.signingKeyId,
    algorithm: "ed25519",
    fingerprint: publicKeyFingerprint(publicKey),
  };
}

export class ResourceCatalogService {
  constructor(config, options = {}) {
    this.config = config;
    this.store = options.store || new ResourceStore(config.storePath);
    this.objects = options.objects || new FileObjectStore(config.contentPath);
    this.signing = options.signing || null;
    this.now = options.now || (() => new Date());
  }

  async initialize() {
    await this.objects.load();
    await this.store.load();
    if (!this.signing) this.signing = await loadSigningKey(this.config);
    const releases = await this.store.read((data) => Object.values(data.releases));
    for (const release of releases) {
      if (release.manifest.signingKeyId !== this.signing.keyId) {
        throw new Error(`stored release ${release.id} uses a different signing key`);
      }
      await this.readVerifiedRelease(release);
    }
    return this;
  }

  signingKeyInfo() {
    return {
      keyId: this.signing.keyId,
      algorithm: this.signing.algorithm,
      fingerprint: this.signing.fingerprint,
      publicKeyPem: this.signing.publicKey.export({ type: "spki", format: "pem" }).toString(),
      publicKeyBase64: this.signing.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    };
  }

  async readVerifiedRelease(release) {
    let content;
    try {
      content = await this.objects.get(release.hash);
    } catch {
      throw new ApiError(409, "release_integrity_failed", "Release content is unavailable");
    }
    const verdict = verifySignedManifest(this.signing.publicKey, release.manifest, content);
    if (!verdict.valid
        || release.hash !== release.manifest.hash
        || release.contentBytes !== release.manifest.contentBytes) {
      throw new ApiError(409, "release_integrity_failed", "Release signature or hash verification failed");
    }
    return { release, content };
  }

  async createResource(body, actorValue, keyHash, fingerprint, path) {
    assertExactFields(body, [
      "kind",
      "name",
      "publisher",
      "deliveryMode",
      "assignments",
      "compatibility",
      "operationId",
      "reason",
    ], ["description"]);
    if (!KIND_SET.has(body.kind)) throw new ApiError(400, "invalid_kind", "kind is unsupported");
    if (!DELIVERY_MODE_SET.has(body.deliveryMode)) {
      throw new ApiError(400, "invalid_delivery_mode", "deliveryMode is unsupported");
    }
    const name = requiredText(body.name, "name", 200);
    const description = body.description == null
      ? ""
      : requiredText(body.description, "description", 2000);
    const publisher = requiredText(body.publisher, "publisher", 128);
    const assignments = cleanAssignments(body.assignments);
    const compatibility = cleanCompatibility(body.compatibility);
    const operationId = cleanOperationId(body.operationId);
    const reason = cleanReason(body.reason);
    scanForSecrets(Buffer.from(JSON.stringify({
      name,
      description,
      publisher,
      assignments,
      compatibility,
    })));
    const nowDate = this.now();
    const now = nowDate.toISOString();
    const resource = {
      id: newStableId("res_"),
      kind: body.kind,
      name,
      description,
      publisher,
      deliveryMode: body.deliveryMode,
      assignments,
      compatibility,
      status: "draft",
      currentReleaseId: "",
      createdAt: now,
      createdBy: actorValue,
      updatedAt: now,
      updatedBy: actorValue,
    };
    const outcome = await this.store.mutate((data) => {
      const replay = idempotencyRecord(data, keyHash, fingerprint);
      if (replay) return replay;
      if (Object.keys(data.resources).length >= this.config.maxResources) {
        throw new ApiError(409, "resource_limit_reached", "The resource limit has been reached");
      }
      if (data.resources[resource.id]) throw new ApiError(500, "id_collision", "Resource id collision");
      data.resources[resource.id] = resource;
      data.resourceAuditLogs.push({
        id: newStableId("raud_"),
        resourceId: resource.id,
        releaseId: "",
        action: "resource.create",
        actor: actorValue,
        operationId,
        reason,
        approvalId: "",
        at: now,
        result: "committed",
      });
      const responseBody = {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        operationId,
        resource: publicResource(resource, data.releases),
      };
      persistIdempotency(data, keyHash, fingerprint, operationId, path, 201, responseBody, now);
      return { replay: false, statusCode: 201, responseBody };
    });
    return outcome;
  }

  async createRelease(resourceId, body, actorValue, keyHash, fingerprint, path) {
    assertExactFields(body, [
      "resourceVersion",
      "mediaType",
      "contentBase64",
      "operationId",
      "reason",
      "expectedUpdatedAt",
    ]);
    const resourceVersion = cleanVersion(body.resourceVersion);
    const mediaType = cleanMediaType(body.mediaType);
    const content = decodeContent(body.contentBase64, this.config.maxContentBytes);
    const operationId = cleanOperationId(body.operationId);
    const reason = cleanReason(body.reason);
    const expectedUpdatedAt = cleanExpectedUpdatedAt(body.expectedUpdatedAt);
    scanForSecrets(content, {
      resourceVersion,
      mediaType,
      operationId,
      reason,
      expectedUpdatedAt,
    });

    const replay = await lookupIdempotency(this.store, keyHash, fingerprint);
    if (replay) return replay;
    const storedObject = await this.objects.put(content);
    const now = this.now().toISOString();
    const releaseId = newStableId("rel_");
    const outcome = await this.store.mutate((data) => {
      const duplicate = idempotencyRecord(data, keyHash, fingerprint);
      if (duplicate) return duplicate;
      const resource = data.resources[resourceId];
      if (!resource) throw new ApiError(404, "resource_not_found", "Resource not found");
      assertExpectedUpdatedAt(resource, expectedUpdatedAt);
      if (Object.values(data.releases).some((release) => (
        release.resourceId === resourceId && release.resourceVersion === resourceVersion
      ))) {
        throw new ApiError(409, "resource_version_exists", "resourceVersion already exists");
      }
      if (Object.values(data.releases).filter((release) => release.resourceId === resourceId).length
          >= this.config.maxReleasesPerResource) {
        throw new ApiError(409, "release_limit_reached", "The release limit has been reached");
      }
      const manifest = buildSignedManifest({
        resourceId,
        releaseId,
        resourceVersion,
        kind: resource.kind,
        hash: sha256Digest(content),
        contentBytes: content.length,
        mediaType,
        publisher: resource.publisher,
        createdAt: now,
        assignments: resource.assignments,
        deliveryMode: resource.deliveryMode,
        compatibility: resource.compatibility,
        previousReleaseId: resource.currentReleaseId,
        signingKeyId: this.signing.keyId,
      }, this.signing.privateKey);
      const release = {
        id: releaseId,
        resourceId,
        resourceVersion,
        mediaType,
        contentBytes: content.length,
        hash: `sha256:${storedObject.hash}`,
        manifest,
        status: "candidate",
        createdAt: now,
        createdBy: actorValue,
      };
      resource.updatedAt = now;
      resource.updatedBy = actorValue;
      data.releases[releaseId] = release;
      data.resourceAuditLogs.push({
        id: newStableId("raud_"),
        resourceId,
        releaseId,
        action: "release.create",
        actor: actorValue,
        operationId,
        reason,
        approvalId: "",
        at: now,
        result: "committed",
      });
      const responseBody = {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        operationId,
        resource: publicResource(resource, data.releases),
        release: publicRelease(release),
      };
      persistIdempotency(data, keyHash, fingerprint, operationId, path, 201, responseBody, now);
      return { replay: false, statusCode: 201, responseBody };
    });
    return outcome;
  }

  async publishRelease(resourceId, body, actorValue, keyHash, fingerprint, path) {
    assertExactFields(body, [
      "releaseId",
      "approvalId",
      "operationId",
      "reason",
      "expectedUpdatedAt",
    ]);
    const releaseId = requiredText(body.releaseId, "releaseId", 128);
    if (!RELEASE_ID_PATTERN.test(releaseId)) {
      throw new ApiError(400, "invalid_release_id", "releaseId is invalid");
    }
    const approvalId = cleanApprovalId(body.approvalId);
    const operationId = cleanOperationId(body.operationId);
    const reason = cleanReason(body.reason);
    const expectedUpdatedAt = cleanExpectedUpdatedAt(body.expectedUpdatedAt);
    scanForSecrets(Buffer.from(JSON.stringify({
      releaseId,
      approvalId,
      operationId,
      reason,
      expectedUpdatedAt,
    })));
    const replay = await lookupIdempotency(this.store, keyHash, fingerprint);
    if (replay) return replay;
    const outcome = await this.store.mutate(async (data) => {
      const duplicate = idempotencyRecord(data, keyHash, fingerprint);
      if (duplicate) return duplicate;
      const resource = data.resources[resourceId];
      if (!resource) throw new ApiError(404, "resource_not_found", "Resource not found");
      assertExpectedUpdatedAt(resource, expectedUpdatedAt);
      const release = data.releases[releaseId];
      if (!releaseBelongsTo(release, resourceId)) {
        throw new ApiError(404, "release_not_found", "Release not found");
      }
      if (release.status !== "candidate") {
        throw new ApiError(409, "release_not_candidate", "Only a candidate release can be published");
      }
      if (release.manifest.previousReleaseId !== resource.currentReleaseId) {
        throw new ApiError(409, "release_stale", "The candidate was created from an older release");
      }
      await this.readVerifiedRelease(release);
      const now = this.now().toISOString();
      if (resource.currentReleaseId && data.releases[resource.currentReleaseId]) {
        data.releases[resource.currentReleaseId].status = "superseded";
      }
      release.status = "published";
      release.publishedAt = now;
      release.publishedBy = actorValue;
      resource.status = "published";
      resource.currentReleaseId = release.id;
      resource.updatedAt = now;
      resource.updatedBy = actorValue;
      data.resourceAuditLogs.push({
        id: newStableId("raud_"),
        resourceId,
        releaseId,
        action: "release.publish",
        actor: actorValue,
        operationId,
        reason,
        approvalId,
        at: now,
        result: "committed",
      });
      const responseBody = {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        operationId,
        resource: publicResource(resource, data.releases),
        release: publicRelease(release),
      };
      persistIdempotency(data, keyHash, fingerprint, operationId, path, 200, responseBody, now);
      return { replay: false, statusCode: 200, responseBody };
    });
    return outcome;
  }

  async rollbackRelease(resourceId, body, actorValue, keyHash, fingerprint, path) {
    assertExactFields(body, [
      "releaseId",
      "approvalId",
      "operationId",
      "reason",
      "expectedUpdatedAt",
    ]);
    const releaseId = requiredText(body.releaseId, "releaseId", 128);
    if (!RELEASE_ID_PATTERN.test(releaseId)) {
      throw new ApiError(400, "invalid_release_id", "releaseId is invalid");
    }
    const approvalId = cleanApprovalId(body.approvalId);
    const operationId = cleanOperationId(body.operationId);
    const reason = cleanReason(body.reason);
    const expectedUpdatedAt = cleanExpectedUpdatedAt(body.expectedUpdatedAt);
    scanForSecrets(Buffer.from(JSON.stringify({
      releaseId,
      approvalId,
      operationId,
      reason,
      expectedUpdatedAt,
    })));
    const replay = await lookupIdempotency(this.store, keyHash, fingerprint);
    if (replay) return replay;
    const outcome = await this.store.mutate(async (data) => {
      const duplicate = idempotencyRecord(data, keyHash, fingerprint);
      if (duplicate) return duplicate;
      const resource = data.resources[resourceId];
      if (!resource) throw new ApiError(404, "resource_not_found", "Resource not found");
      assertExpectedUpdatedAt(resource, expectedUpdatedAt);
      const release = data.releases[releaseId];
      if (!releaseBelongsTo(release, resourceId)) {
        throw new ApiError(404, "release_not_found", "Release not found");
      }
      if (resource.currentReleaseId === releaseId) {
        throw new ApiError(409, "release_already_current", "The release is already current");
      }
      if (!release.publishedAt) {
        throw new ApiError(409, "release_not_historical", "Only a previously published release can be restored");
      }
      await this.readVerifiedRelease(release);
      const now = this.now().toISOString();
      if (resource.currentReleaseId && data.releases[resource.currentReleaseId]) {
        data.releases[resource.currentReleaseId].status = "superseded";
      }
      release.status = "published";
      resource.status = "published";
      resource.currentReleaseId = release.id;
      resource.updatedAt = now;
      resource.updatedBy = actorValue;
      data.resourceAuditLogs.push({
        id: newStableId("raud_"),
        resourceId,
        releaseId,
        action: "release.rollback",
        actor: actorValue,
        operationId,
        reason,
        approvalId,
        at: now,
        result: "committed",
      });
      const responseBody = {
        schemaVersion: SCHEMA_VERSION,
        ok: true,
        operationId,
        resource: publicResource(resource, data.releases),
        release: publicRelease(release),
      };
      persistIdempotency(data, keyHash, fingerprint, operationId, path, 200, responseBody, now);
      return { replay: false, statusCode: 200, responseBody };
    });
    return outcome;
  }
}

function sendMutationOutcome(res, outcome, requestIdValue) {
  jsonResponse(
    res,
    outcome.statusCode,
    outcome.responseBody,
    requestIdValue,
    outcome.replay ? { "x-idempotent-replay": "true" } : {},
  );
}

export async function createResourceServer(config, options = {}) {
  const service = await new ResourceCatalogService(config, options).initialize();
  const limiter = new FixedWindowRateLimiter(config.rateLimitPerMinute);
  const logger = options.logger || (() => {});

  const server = http.createServer(async (req, res) => {
    const reqId = requestId();
    try {
      const url = new URL(req.url || "/", "http://localhost");
      const route = routeOf(url.pathname);
      if (route.name === "health") {
        if (req.method !== "GET") {
          throw new ApiError(405, "method_not_allowed", "Method not allowed");
        }
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          service: "resource-service",
          status: "ready",
        }, reqId);
        return;
      }
      if (!limiter.allow(req.socket.remoteAddress || "unknown")) {
        throw new ApiError(429, "rate_limited", "Too many requests", true);
      }
      if (!bearerMatches(req, config.serviceToken)) {
        throw new ApiError(401, "unauthorized", "A valid service token is required");
      }

      if (route.name === "signing-key") {
        if (req.method !== "GET") throw new ApiError(405, "method_not_allowed", "Method not allowed");
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          signingKey: service.signingKeyInfo(),
        }, reqId);
        return;
      }

      if (route.name === "resources") {
        if (req.method === "GET") {
          const result = await service.store.read((data) => ({
            resources: Object.values(data.resources)
              .map((resource) => publicResource(resource, data.releases))
              .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt)),
          }));
          jsonResponse(res, 200, {
            schemaVersion: SCHEMA_VERSION,
            ok: true,
            ...result,
          }, reqId);
          return;
        }
        if (req.method === "POST") {
          const key = idempotencyKey(req);
          const keyHash = sha256Text(key);
          const body = await readJsonBody(req, config.maxBodyBytes);
          const actorValue = actor(req);
          const fingerprint = requestFingerprint("POST", url.pathname, actorValue, body);
          const outcome = await service.createResource(body, actorValue, keyHash, fingerprint, url.pathname);
          sendMutationOutcome(res, outcome, reqId);
          return;
        }
        throw new ApiError(405, "method_not_allowed", "Method not allowed");
      }

      if (route.name === "audit-logs") {
        if (req.method !== "GET") throw new ApiError(405, "method_not_allowed", "Method not allowed");
        const requestedResource = String(url.searchParams.get("resourceId") || "");
        const result = await service.store.read((data) => ({
          auditLogs: data.resourceAuditLogs
            .filter((entry) => !requestedResource || entry.resourceId === requestedResource)
            .slice()
            .reverse(),
        }));
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          ...result,
        }, reqId);
        return;
      }

      if (route.name === "resource") {
        if (req.method !== "GET") throw new ApiError(405, "method_not_allowed", "Method not allowed");
        const result = await service.store.read((data) => {
          const resource = data.resources[route.resourceId];
          if (!resource) return null;
          return {
            resource: publicResource(resource, data.releases),
            releases: Object.values(data.releases)
              .filter((release) => release.resourceId === route.resourceId)
              .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
              .map(publicRelease),
          };
        });
        if (!result) throw new ApiError(404, "resource_not_found", "Resource not found");
        jsonResponse(res, 200, { schemaVersion: SCHEMA_VERSION, ok: true, ...result }, reqId);
        return;
      }

      if (route.name === "releases") {
        if (req.method === "GET") {
          const result = await service.store.read((data) => {
            if (!data.resources[route.resourceId]) return null;
            return Object.values(data.releases)
              .filter((release) => release.resourceId === route.resourceId)
              .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
              .map(publicRelease);
          });
          if (!result) throw new ApiError(404, "resource_not_found", "Resource not found");
          jsonResponse(res, 200, {
            schemaVersion: SCHEMA_VERSION,
            ok: true,
            releases: result,
          }, reqId);
          return;
        }
        if (req.method === "POST") {
          const key = idempotencyKey(req);
          const keyHash = sha256Text(key);
          const body = await readJsonBody(req, config.maxBodyBytes);
          const actorValue = actor(req);
          const fingerprint = requestFingerprint("POST", url.pathname, actorValue, body);
          const outcome = await service.createRelease(
            route.resourceId,
            body,
            actorValue,
            keyHash,
            fingerprint,
            url.pathname,
          );
          sendMutationOutcome(res, outcome, reqId);
          return;
        }
        throw new ApiError(405, "method_not_allowed", "Method not allowed");
      }

      if (route.name === "publish" || route.name === "rollback") {
        if (req.method !== "POST") throw new ApiError(405, "method_not_allowed", "Method not allowed");
        const key = idempotencyKey(req);
        const keyHash = sha256Text(key);
        const body = await readJsonBody(req, config.maxBodyBytes);
        const actorValue = actor(req);
        const fingerprint = requestFingerprint("POST", url.pathname, actorValue, body);
        const operation = route.name === "publish"
          ? service.publishRelease.bind(service)
          : service.rollbackRelease.bind(service);
        const outcome = await operation(
          route.resourceId,
          body,
          actorValue,
          keyHash,
          fingerprint,
          url.pathname,
        );
        sendMutationOutcome(res, outcome, reqId);
        return;
      }

      if (route.name === "resource-audit-logs") {
        if (req.method !== "GET") throw new ApiError(405, "method_not_allowed", "Method not allowed");
        const result = await service.store.read((data) => {
          if (!data.resources[route.resourceId]) return null;
          return data.resourceAuditLogs
            .filter((entry) => entry.resourceId === route.resourceId)
            .slice()
            .reverse();
        });
        if (!result) throw new ApiError(404, "resource_not_found", "Resource not found");
        jsonResponse(res, 200, {
          schemaVersion: SCHEMA_VERSION,
          ok: true,
          auditLogs: result,
        }, reqId);
        return;
      }

      if (route.name === "manifest" || route.name === "content") {
        if (req.method !== "GET") throw new ApiError(405, "method_not_allowed", "Method not allowed");
        const release = await service.store.read((data) => (
          releaseBelongsTo(data.releases[route.releaseId], route.resourceId)
            ? data.releases[route.releaseId]
            : null
        ));
        if (!release) throw new ApiError(404, "release_not_found", "Release not found");
        const verified = await service.readVerifiedRelease(release);
        if (route.name === "manifest") {
          jsonResponse(res, 200, {
            schemaVersion: SCHEMA_VERSION,
            ok: true,
            verified: true,
            manifest: verified.release.manifest,
          }, reqId);
          return;
        }
        res.writeHead(200, {
          "content-type": release.mediaType,
          "content-length": String(verified.content.length),
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
          "x-request-id": reqId,
          "x-content-sha256": release.hash,
          etag: `"${release.hash}"`,
        });
        res.end(verified.content);
        return;
      }

      throw new ApiError(404, "not_found", "Route not found");
    } catch (error) {
      errorResponse(res, reqId, error, logger);
    }
  });

  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.on("clientError", (_error, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
  });
  return { server, service };
}
