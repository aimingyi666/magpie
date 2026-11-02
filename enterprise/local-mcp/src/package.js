import crypto from "node:crypto";
import path from "node:path";

import { LocalMcpError } from "./errors.js";

export const LOCAL_MCP_PACKAGE_SCHEMA_VERSION = 1;
export const LOCAL_MCP_SIGNATURE_ALGORITHM = "ed25519";
export const LOCAL_MCP_PROTOCOLS = Object.freeze(["stdio-jsonrpc"]);
export const LOCAL_MCP_RISKS = Object.freeze(["low", "medium", "high", "critical"]);
export const LOCAL_MCP_CAPABILITIES = Object.freeze([
  "fs.read",
  "fs.write",
  "fs.delete",
  "network.connect",
  "process.spawn",
  "worker.start",
  "native.addon",
  "native.ffi",
  "clipboard.read",
  "clipboard.write",
  "desktop.control",
]);

export const DEFAULT_MAX_PACKAGE_BYTES = 20 * 1024 * 1024;
export const DEFAULT_MAX_PACKAGE_FILES = 256;
export const MAX_MANIFEST_BYTES = 512 * 1024;

const PACKAGE_FIELDS = new Set(["schemaVersion", "manifest", "files"]);
const MANIFEST_FIELDS = new Set([
  "schemaVersion",
  "packageId",
  "releaseId",
  "packageVersion",
  "publisher",
  "createdAt",
  "description",
  "signingKeyId",
  "signatureAlgorithm",
  "runtime",
  "permissions",
  "secrets",
  "tools",
  "compatibility",
  "files",
  "packageDigest",
  "manifestDigest",
  "signature",
]);
const RUNTIME_FIELDS = new Set(["interpreter", "entrypoint", "args", "protocol"]);
const PERMISSION_FIELDS = new Set(["capabilities", "networkHosts"]);
const SECRET_FIELDS = new Set(["name", "reference", "required"]);
const TOOL_FIELDS = new Set(["name", "description", "risk", "capabilities"]);
const COMPATIBILITY_FIELDS = new Set(["minClientVersion", "platforms", "architectures"]);
const FILE_FIELDS = new Set(["path", "bytes", "hash"]);
const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SAFE_TOOL_NAME = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;
const SAFE_INTERPRETER = /^[a-z][a-z0-9-]{0,31}$/;
const SAFE_ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/;
const SECRET_REFERENCE = /^secret:\/\/[a-z0-9][a-z0-9._/-]{0,511}$/;
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$/;
const WINDOWS_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i;

function canonicalValue(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error("canonical JSON only supports plain values");
  }
  const output = {};
  for (const key of Object.keys(value).sort()) {
    if (value[key] === undefined) throw new Error("undefined is not supported");
    output[key] = canonicalValue(value[key]);
  }
  return output;
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
  return sha256Digest(publicKey.export({ type: "spki", format: "der" }));
}

function fail(code, message) {
  throw new LocalMcpError(code, message);
}

function assertExactFields(value, fields, label, code = "invalid_package") {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(code, `${label} must be an object`);
  }
  const keys = Object.keys(value);
  if (keys.some((key) => !fields.has(key))
      || [...fields].some((key) => !Object.hasOwn(value, key))) {
    fail(code, `${label} fields are invalid`);
  }
}

function assertStringList(value, label, { allowEmpty = true, max = 64 } = {}) {
  if (!Array.isArray(value)
      || (!allowEmpty && value.length === 0)
      || value.length > max
      || value.some((item) => typeof item !== "string" || !item)
      || new Set(value).size !== value.length) {
    fail("invalid_package", `${label} is invalid`);
  }
}

export function assertSafePackagePath(value, label = "file path") {
  if (typeof value !== "string"
      || !value
      || value.length > 240
      || value.includes("\\")
      || value.includes("\0")
      || value.includes(":")
      || value.startsWith("/")
      || value.endsWith("/")
      || value.includes("//")) {
    fail("path_traversal", `${label} is unsafe`);
  }
  const segments = value.split("/");
  if (segments.some((segment) => {
    if (!segment || segment === "." || segment === ".." || /[\u0000-\u001f\u007f]/.test(segment)) {
      return true;
    }
    if (segment.endsWith(".") || segment.endsWith(" ") || WINDOWS_RESERVED.test(segment)) return true;
    return false;
  })) {
    fail("path_traversal", `${label} is unsafe`);
  }
  const normalized = path.posix.normalize(value);
  if (normalized !== value || normalized.startsWith("../")) {
    fail("path_traversal", `${label} is unsafe`);
  }
  return value;
}

function decodeBase64File(value, filePath) {
  if (typeof value !== "string" || !value.startsWith("base64:")) {
    fail("invalid_package", `file ${filePath} must be base64 encoded`);
  }
  const encoded = value.slice("base64:".length);
  if (!encoded || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded) || encoded.length % 4 !== 0) {
    fail("invalid_package", `file ${filePath} has invalid base64`);
  }
  const bytes = Buffer.from(encoded, "base64");
  if (bytes.toString("base64") !== encoded) {
    fail("invalid_package", `file ${filePath} has non-canonical base64`);
  }
  return bytes;
}

function normalizeFilesInput(files) {
  const entries = files instanceof Map
    ? [...files.entries()]
    : files && typeof files === "object" && !Array.isArray(files)
      ? Object.entries(files)
      : null;
  if (!entries || entries.length === 0) fail("invalid_package", "package must contain files");
  const normalized = new Map();
  const folded = new Set();
  for (const [filePath, content] of entries) {
    assertSafePackagePath(filePath);
    const key = filePath.toLowerCase();
    if (folded.has(key)) fail("duplicate_file", "package file paths must be unique ignoring case");
    folded.add(key);
    let bytes;
    if (Buffer.isBuffer(content)) bytes = Buffer.from(content);
    else if (content instanceof Uint8Array) bytes = Buffer.from(content);
    else if (typeof content === "string") bytes = Buffer.from(content, "utf8");
    else fail("invalid_package", "package file content must be bytes or a string");
    normalized.set(filePath, bytes);
  }
  return normalized;
}

function fileDescriptors(files) {
  return [...files.entries()]
    .map(([filePath, content]) => ({
      path: filePath,
      bytes: content.length,
      hash: sha256Digest(content),
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
}

function packageDigestFor(descriptors) {
  return sha256Digest(Buffer.from(canonicalJson(descriptors), "utf8"));
}

function validateRuntime(runtime) {
  assertExactFields(runtime, RUNTIME_FIELDS, "runtime");
  if (typeof runtime.interpreter !== "string" || !SAFE_INTERPRETER.test(runtime.interpreter)) {
    fail("invalid_package", "runtime.interpreter is invalid");
  }
  assertSafePackagePath(runtime.entrypoint, "runtime.entrypoint");
  if (!Array.isArray(runtime.args)
      || runtime.args.length > 32
      || runtime.args.some((arg) => typeof arg !== "string" || arg.length > 1024 || arg.includes("\0"))) {
    fail("invalid_package", "runtime.args is invalid");
  }
  if (!LOCAL_MCP_PROTOCOLS.includes(runtime.protocol)) {
    fail("invalid_package", "runtime.protocol is unsupported");
  }
  return {
    interpreter: runtime.interpreter,
    entrypoint: runtime.entrypoint,
    args: [...runtime.args],
    protocol: runtime.protocol,
  };
}

function validatePermissions(permissions) {
  assertExactFields(permissions, PERMISSION_FIELDS, "permissions");
  assertStringList(permissions.capabilities, "permissions.capabilities", { max: LOCAL_MCP_CAPABILITIES.length });
  if (permissions.capabilities.some((item) => !LOCAL_MCP_CAPABILITIES.includes(item))) {
    fail("invalid_package", "permissions.capabilities contains an unsupported capability");
  }
  assertStringList(permissions.networkHosts, "permissions.networkHosts", { max: 64 });
  for (const host of permissions.networkHosts) {
    if (host.length > 253
        || !/^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host)
        || host.includes("..")) {
      fail("invalid_package", "permissions.networkHosts contains an invalid host");
    }
  }
  if (!permissions.capabilities.includes("network.connect") && permissions.networkHosts.length) {
    fail("invalid_package", "networkHosts requires network.connect");
  }
  return {
    capabilities: [...permissions.capabilities],
    networkHosts: [...permissions.networkHosts],
  };
}

function validateSecrets(secrets) {
  if (!Array.isArray(secrets) || secrets.length > 64) fail("invalid_package", "secrets is invalid");
  const names = new Set();
  const references = new Set();
  return secrets.map((secret) => {
    assertExactFields(secret, SECRET_FIELDS, "secret");
    if (typeof secret.name !== "string" || !SAFE_ENV_NAME.test(secret.name)) {
      fail("invalid_package", "secret.name is invalid");
    }
    if (typeof secret.reference !== "string"
        || !SECRET_REFERENCE.test(secret.reference)
        || secret.reference.endsWith("/")
        || secret.reference.includes("..")) {
      fail("secret_ref_invalid", "secret.reference is invalid");
    }
    if (typeof secret.required !== "boolean") fail("invalid_package", "secret.required is invalid");
    if (names.has(secret.name) || references.has(secret.reference)) {
      fail("invalid_package", "secrets must be unique by name and reference");
    }
    names.add(secret.name);
    references.add(secret.reference);
    return { name: secret.name, reference: secret.reference, required: secret.required };
  });
}

function validateTools(tools, capabilities) {
  if (!Array.isArray(tools) || tools.length === 0 || tools.length > 128) {
    fail("invalid_package", "tools must contain between 1 and 128 entries");
  }
  const names = new Set();
  return tools.map((tool) => {
    assertExactFields(tool, TOOL_FIELDS, "tool");
    if (typeof tool.name !== "string" || !SAFE_TOOL_NAME.test(tool.name)) {
      fail("invalid_package", "tool.name is invalid");
    }
    if (typeof tool.description !== "string" || tool.description.length > 2048) {
      fail("invalid_package", "tool.description is invalid");
    }
    if (!LOCAL_MCP_RISKS.includes(tool.risk)) fail("invalid_package", "tool.risk is unsupported");
    assertStringList(tool.capabilities, "tool.capabilities", { max: LOCAL_MCP_CAPABILITIES.length });
    if (tool.capabilities.some((item) => !LOCAL_MCP_CAPABILITIES.includes(item)
        || !capabilities.includes(item))) {
      fail("policy_denied", "a tool requires a capability absent from package permissions");
    }
    if (names.has(tool.name)) fail("invalid_package", "tool names must be unique");
    names.add(tool.name);
    return {
      name: tool.name,
      description: tool.description,
      risk: tool.risk,
      capabilities: [...tool.capabilities],
    };
  });
}

function validateCompatibility(compatibility) {
  assertExactFields(compatibility, COMPATIBILITY_FIELDS, "compatibility");
  if (typeof compatibility.minClientVersion !== "string"
      || !SEMVER.test(compatibility.minClientVersion)) {
    fail("invalid_package", "compatibility.minClientVersion is invalid");
  }
  assertStringList(compatibility.platforms, "compatibility.platforms", { allowEmpty: false, max: 3 });
  assertStringList(
    compatibility.architectures,
    "compatibility.architectures",
    { allowEmpty: false, max: 8 },
  );
  if (compatibility.platforms.some((item) => !["win32", "darwin", "linux"].includes(item))
      || compatibility.architectures.some((item) => !/^[a-z0-9_]{2,32}$/.test(item))) {
    fail("invalid_package", "compatibility platform or architecture is invalid");
  }
  return {
    minClientVersion: compatibility.minClientVersion,
    platforms: [...compatibility.platforms],
    architectures: [...compatibility.architectures],
  };
}

function validateFileDescriptors(files, limits) {
  if (!Array.isArray(files) || files.length === 0 || files.length > limits.maxFiles) {
    fail("invalid_package", "package file count is invalid");
  }
  const paths = new Set();
  const folded = new Set();
  let total = 0;
  return files.map((file) => {
    assertExactFields(file, FILE_FIELDS, "file");
    assertSafePackagePath(file.path);
    if (paths.has(file.path)) fail("duplicate_file", "package file descriptor is duplicated");
    const foldedPath = file.path.toLowerCase();
    if (folded.has(foldedPath)) fail("duplicate_file", "package file paths collide ignoring case");
    paths.add(file.path);
    folded.add(foldedPath);
    if (!Number.isSafeInteger(file.bytes) || file.bytes < 0 || file.bytes > limits.maxBytes) {
      fail("package_too_large", "package file size exceeds the limit");
    }
    total += file.bytes;
    if (!Number.isSafeInteger(total) || total > limits.maxBytes) {
      fail("package_too_large", "package size exceeds the limit");
    }
    if (typeof file.hash !== "string" || !/^sha256:[a-f0-9]{64}$/.test(file.hash)) {
      fail("invalid_package", "package file hash is invalid");
    }
    return { path: file.path, bytes: file.bytes, hash: file.hash };
  });
}

export function buildSignedPackage(fields, filesInput, privateKey) {
  let privateKeyValue;
  try {
    privateKeyValue = privateKey instanceof crypto.KeyObject
      ? privateKey
      : crypto.createPrivateKey(privateKey);
  } catch {
    fail("invalid_config", "private key could not be loaded");
  }
  if (privateKeyValue.asymmetricKeyType !== "ed25519") {
    fail("invalid_config", "private key must be Ed25519");
  }
  const files = normalizeFilesInput(filesInput);
  const descriptors = fileDescriptors(files);
  const permissions = validatePermissions(fields.permissions ?? { capabilities: [], networkHosts: [] });
  const runtime = validateRuntime(fields.runtime);
  const tools = validateTools(fields.tools ?? [], permissions.capabilities);
  const secrets = validateSecrets(fields.secrets ?? []);
  const compatibility = validateCompatibility(fields.compatibility);
  const base = {
    schemaVersion: LOCAL_MCP_PACKAGE_SCHEMA_VERSION,
    packageId: fields.packageId,
    releaseId: fields.releaseId,
    packageVersion: fields.packageVersion,
    publisher: fields.publisher,
    createdAt: fields.createdAt,
    description: fields.description ?? "",
    signingKeyId: fields.signingKeyId,
    signatureAlgorithm: LOCAL_MCP_SIGNATURE_ALGORITHM,
    runtime,
    permissions,
    secrets,
    tools,
    compatibility,
    files: descriptors,
  };
  validateManifestBase(base);
  const packageDigest = packageDigestFor(descriptors);
  const manifestDigest = sha256Digest(
    Buffer.from(canonicalJson({ ...base, packageDigest }), "utf8"),
  );
  const signature = crypto.sign(
    null,
    Buffer.from(canonicalJson({ ...base, packageDigest, manifestDigest }), "utf8"),
    privateKeyValue,
  );
  const encodedFiles = {};
  for (const descriptor of descriptors) {
    encodedFiles[descriptor.path] = `base64:${files.get(descriptor.path).toString("base64")}`;
  }
  return {
    schemaVersion: LOCAL_MCP_PACKAGE_SCHEMA_VERSION,
    manifest: {
      ...base,
      packageDigest,
      manifestDigest,
      signature: `base64:${signature.toString("base64")}`,
    },
    files: encodedFiles,
  };
}

function validateManifestBase(base) {
  if (typeof base.packageId !== "string" || !SAFE_SEGMENT.test(base.packageId)) {
    fail("invalid_package", "packageId is invalid");
  }
  if (typeof base.releaseId !== "string" || !SAFE_SEGMENT.test(base.releaseId)) {
    fail("invalid_package", "releaseId is invalid");
  }
  if (typeof base.packageVersion !== "string" || base.packageVersion.length > 128 || !base.packageVersion) {
    fail("invalid_package", "packageVersion is invalid");
  }
  if (typeof base.publisher !== "string"
      || base.publisher.length > 128
      || !/^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$/.test(base.publisher)) {
    fail("invalid_package", "publisher is invalid");
  }
  if (typeof base.createdAt !== "string" || Number.isNaN(Date.parse(base.createdAt))) {
    fail("invalid_package", "createdAt is invalid");
  }
  if (typeof base.description !== "string" || base.description.length > 4096) {
    fail("invalid_package", "description is invalid");
  }
  if (typeof base.signingKeyId !== "string" || !SAFE_KEY_ID.test(base.signingKeyId)) {
    fail("invalid_package", "signingKeyId is invalid");
  }
}

export function validateManifestShape(manifest, limits = {}) {
  const effectiveLimits = {
    maxBytes: limits.maxBytes ?? DEFAULT_MAX_PACKAGE_BYTES,
    maxFiles: limits.maxFiles ?? DEFAULT_MAX_PACKAGE_FILES,
  };
  assertExactFields(manifest, MANIFEST_FIELDS, "manifest");
  if (manifest.schemaVersion !== LOCAL_MCP_PACKAGE_SCHEMA_VERSION) {
    fail("invalid_package", "manifest schemaVersion is unsupported");
  }
  const permissions = validatePermissions(manifest.permissions);
  const runtime = validateRuntime(manifest.runtime);
  const tools = validateTools(manifest.tools, permissions.capabilities);
  const secrets = validateSecrets(manifest.secrets);
  const compatibility = validateCompatibility(manifest.compatibility);
  const files = validateFileDescriptors(manifest.files, effectiveLimits);
  const base = {
    schemaVersion: LOCAL_MCP_PACKAGE_SCHEMA_VERSION,
    packageId: manifest.packageId,
    releaseId: manifest.releaseId,
    packageVersion: manifest.packageVersion,
    publisher: manifest.publisher,
    createdAt: manifest.createdAt,
    description: manifest.description,
    signingKeyId: manifest.signingKeyId,
    signatureAlgorithm: manifest.signatureAlgorithm,
    runtime,
    permissions,
    secrets,
    tools,
    compatibility,
    files,
  };
  validateManifestBase(base);
  if (manifest.signatureAlgorithm !== LOCAL_MCP_SIGNATURE_ALGORITHM) {
    fail("invalid_package", "signatureAlgorithm is unsupported");
  }
  if (typeof manifest.packageDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(manifest.packageDigest)) {
    fail("invalid_package", "packageDigest is invalid");
  }
  if (typeof manifest.manifestDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(manifest.manifestDigest)) {
    fail("invalid_package", "manifestDigest is invalid");
  }
  if (typeof manifest.signature !== "string" || !/^base64:[A-Za-z0-9+/]{86}==$/.test(manifest.signature)) {
    fail("signature_invalid", "signature is invalid");
  }
  if (Buffer.byteLength(canonicalJson(manifest), "utf8") > MAX_MANIFEST_BYTES) {
    fail("invalid_package", "manifest exceeds the size limit");
  }
  return {
    schemaVersion: LOCAL_MCP_PACKAGE_SCHEMA_VERSION,
    packageId: manifest.packageId,
    releaseId: manifest.releaseId,
    packageVersion: manifest.packageVersion,
    publisher: manifest.publisher,
    createdAt: manifest.createdAt,
    description: manifest.description,
    signingKeyId: manifest.signingKeyId,
    signatureAlgorithm: manifest.signatureAlgorithm,
    runtime,
    permissions,
    secrets,
    tools,
    compatibility,
    files,
    packageDigest: manifest.packageDigest,
    manifestDigest: manifest.manifestDigest,
    signature: manifest.signature,
  };
}

export function verifySignedPackage(publicKey, input, limits = {}) {
  try {
    assertExactFields(input, PACKAGE_FIELDS, "package");
    if (input.schemaVersion !== LOCAL_MCP_PACKAGE_SCHEMA_VERSION) {
      fail("invalid_package", "package schemaVersion is unsupported");
    }
    const manifest = validateManifestShape(input.manifest);
    if (!input.files || typeof input.files !== "object" || Array.isArray(input.files)) {
      fail("invalid_package", "package files must be an object");
    }
    const descriptorPaths = manifest.files.map((file) => file.path);
    const inputPaths = Object.keys(input.files);
    if (inputPaths.length !== descriptorPaths.length
        || inputPaths.some((filePath, index) => filePath !== descriptorPaths[index])) {
      fail("invalid_package", "package files do not match the signed file table");
    }
    const files = new Map();
    for (const descriptor of manifest.files) {
      const bytes = decodeBase64File(input.files[descriptor.path], descriptor.path);
      if (bytes.length !== descriptor.bytes || sha256Digest(bytes) !== descriptor.hash) {
        fail("package_tampered", "package file hash or size does not match the manifest");
      }
      files.set(descriptor.path, bytes);
    }
    if (packageDigestFor(manifest.files) !== manifest.packageDigest) {
      fail("package_tampered", "package digest does not match the manifest");
    }
    const { signature, manifestDigest, packageDigest, ...baseWithAlgorithm } = manifest;
    const base = { ...baseWithAlgorithm };
    const expectedManifestDigest = sha256Digest(
      Buffer.from(canonicalJson({ ...base, packageDigest }), "utf8"),
    );
    if (expectedManifestDigest !== manifestDigest) {
      fail("package_tampered", "manifest digest does not match");
    }
    const signatureBytes = Buffer.from(signature.slice("base64:".length), "base64");
    let valid = false;
    try {
      valid = crypto.verify(
        null,
        Buffer.from(canonicalJson({ ...base, packageDigest, manifestDigest }), "utf8"),
        publicKey,
        signatureBytes,
      );
    } catch {
      valid = false;
    }
    if (!valid) fail("signature_invalid", "package signature is invalid");
    return {
      schemaVersion: LOCAL_MCP_PACKAGE_SCHEMA_VERSION,
      manifest,
      files,
    };
  } catch (error) {
    if (error instanceof LocalMcpError) throw error;
    throw new LocalMcpError("invalid_package", "package could not be verified");
  }
}
