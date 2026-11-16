import crypto from "node:crypto";

export const RESOURCE_MANIFEST_SCHEMA_VERSION = 1;
export const RESOURCE_SIGNATURE_ALGORITHM = "ed25519";
export const RESOURCE_KINDS = Object.freeze([
  "mcp",
  "skill",
  "instructions",
  "subagent",
  "template",
  // A redact resource is the enterprise's masking policy: rules added to
  // the user's own, and whether the baseline categories may be turned off.
  // The client writes it beside magpie's settings, never into an agent.
  "redact",
  // A hook is executable code delivered to an agent, so it is the highest
  // risk kind: the catalog accepts it, and the client must not apply one
  // without its own approval. Publishing it here does not execute it.
  "hook",
]);
export const RESOURCE_DELIVERY_MODES = Object.freeze(["forced", "recommended"]);
const MANIFEST_FIELDS = new Set([
  "schemaVersion",
  "resourceId",
  "releaseId",
  "resourceVersion",
  "kind",
  "hash",
  "contentBytes",
  "mediaType",
  "publisher",
  "createdAt",
  "assignments",
  "deliveryMode",
  "compatibility",
  "previousReleaseId",
  "signingKeyId",
  "signatureAlgorithm",
  "manifestDigest",
  "signature",
]);
const COMPATIBILITY_FIELDS = new Set(["minClientVersion"]);

function canonicalValue(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonical JSON does not support non-finite numbers");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error("canonical JSON only supports plain objects and arrays");
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] === undefined) throw new Error("canonical JSON does not support undefined values");
    out[key] = canonicalValue(value[key]);
  }
  return out;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function sha256Digest(value) {
  return `sha256:${sha256Hex(value)}`;
}

export function publicKeyFingerprint(publicKey) {
  const der = publicKey.export({ type: "spki", format: "der" });
  return sha256Digest(der);
}

function manifestBase(fields) {
  return {
    schemaVersion: RESOURCE_MANIFEST_SCHEMA_VERSION,
    resourceId: fields.resourceId,
    releaseId: fields.releaseId,
    resourceVersion: fields.resourceVersion,
    kind: fields.kind,
    hash: fields.hash,
    contentBytes: fields.contentBytes,
    mediaType: fields.mediaType,
    publisher: fields.publisher,
    createdAt: fields.createdAt,
    assignments: fields.assignments,
    deliveryMode: fields.deliveryMode,
    compatibility: fields.compatibility,
    previousReleaseId: fields.previousReleaseId,
    signingKeyId: fields.signingKeyId,
    signatureAlgorithm: RESOURCE_SIGNATURE_ALGORITHM,
  };
}

export function buildSignedManifest(fields, privateKey) {
  const base = manifestBase(fields);
  const manifestDigest = sha256Digest(Buffer.from(canonicalJson(base), "utf8"));
  const signedBody = { ...base, manifestDigest };
  const signature = crypto.sign(null, Buffer.from(canonicalJson(signedBody), "utf8"), privateKey);
  return {
    ...signedBody,
    signature: `base64:${signature.toString("base64")}`,
  };
}

export function validateManifestShape(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new Error("manifest must be an object");
  }
  if (Object.keys(manifest).some((key) => !MANIFEST_FIELDS.has(key))
      || [...MANIFEST_FIELDS].some((key) => !(key in manifest))) {
    throw new Error("manifest fields are invalid");
  }
  if (manifest.schemaVersion !== RESOURCE_MANIFEST_SCHEMA_VERSION) {
    throw new Error("manifest schemaVersion is unsupported");
  }
  for (const key of [
    "resourceId",
    "releaseId",
    "resourceVersion",
    "kind",
    "hash",
    "mediaType",
    "publisher",
    "createdAt",
    "deliveryMode",
    "signingKeyId",
    "manifestDigest",
    "signature",
  ]) {
    if (typeof manifest[key] !== "string" || !manifest[key]) {
      throw new Error(`manifest ${key} must be a non-empty string`);
    }
  }
  if (!/^sha256:[a-f0-9]{64}$/.test(manifest.hash)
      || !/^sha256:[a-f0-9]{64}$/.test(manifest.manifestDigest)) {
    throw new Error("manifest digests must be SHA-256 values");
  }
  if (!RESOURCE_KINDS.includes(manifest.kind)) {
    throw new Error("manifest kind is unsupported");
  }
  if (!RESOURCE_DELIVERY_MODES.includes(manifest.deliveryMode)) {
    throw new Error("manifest deliveryMode is unsupported");
  }
  if (!Number.isSafeInteger(manifest.contentBytes) || manifest.contentBytes < 1) {
    throw new Error("manifest contentBytes must be a positive integer");
  }
  if (!Array.isArray(manifest.assignments)
      || manifest.assignments.length === 0
      || manifest.assignments.some((item) => typeof item !== "string" || !item)
      || new Set(manifest.assignments).size !== manifest.assignments.length) {
    throw new Error("manifest assignments must be strings");
  }
  if (!manifest.compatibility
      || typeof manifest.compatibility !== "object"
      || Array.isArray(manifest.compatibility)
      || Object.keys(manifest.compatibility).some((key) => !COMPATIBILITY_FIELDS.has(key))
      || typeof manifest.compatibility.minClientVersion !== "string"
      || !manifest.compatibility.minClientVersion) {
    throw new Error("manifest compatibility is invalid");
  }
  if (typeof manifest.previousReleaseId !== "string") {
    throw new Error("manifest previousReleaseId must be a string");
  }
  if (manifest.signatureAlgorithm !== RESOURCE_SIGNATURE_ALGORITHM) {
    throw new Error("manifest signatureAlgorithm is unsupported");
  }
  if (!/^base64:[A-Za-z0-9+/]{86}==$/.test(manifest.signature)) {
    throw new Error("manifest signature is invalid");
  }
  return manifest;
}

export function verifySignedManifest(publicKey, manifest, content) {
  try {
    validateManifestShape(manifest);
    const { signature, ...signedBody } = manifest;
    if (Object.keys(signedBody).length !== MANIFEST_FIELDS.size - 1) {
      return { valid: false, reason: "manifest_invalid" };
    }

    // Rebuild the unsigned base explicitly so adding unknown fields cannot
    // change what is accepted as the signed document.
    const base = manifestBase({
      resourceId: manifest.resourceId,
      releaseId: manifest.releaseId,
      resourceVersion: manifest.resourceVersion,
      kind: manifest.kind,
      hash: manifest.hash,
      contentBytes: manifest.contentBytes,
      mediaType: manifest.mediaType,
      publisher: manifest.publisher,
      createdAt: manifest.createdAt,
      assignments: manifest.assignments,
      deliveryMode: manifest.deliveryMode,
      compatibility: manifest.compatibility,
      previousReleaseId: manifest.previousReleaseId,
      signingKeyId: manifest.signingKeyId,
    });
    const actualDigest = sha256Digest(Buffer.from(canonicalJson(base), "utf8"));
    if (actualDigest !== manifest.manifestDigest) {
      return { valid: false, reason: "manifest_digest_mismatch" };
    }
    const signatureBytes = Buffer.from(signature.slice("base64:".length), "base64");
    if (signatureBytes.length !== 64) {
      return { valid: false, reason: "manifest_signature_invalid" };
    }
    const validSignature = crypto.verify(
      null,
      Buffer.from(canonicalJson({ ...base, manifestDigest: manifest.manifestDigest }), "utf8"),
      publicKey,
      signatureBytes,
    );
    if (!validSignature) return { valid: false, reason: "manifest_signature_invalid" };
    if (!Buffer.isBuffer(content)) return { valid: false, reason: "content_unavailable" };
    if (content.length !== manifest.contentBytes) return { valid: false, reason: "content_size_mismatch" };
    if (sha256Digest(content) !== manifest.hash) return { valid: false, reason: "content_hash_mismatch" };
    return { valid: true, reason: "" };
  } catch {
    return { valid: false, reason: "manifest_invalid" };
  }
}
