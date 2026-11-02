import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import { FileAuditSink } from "./audit.js";
import { LocalMcpError } from "./errors.js";
import { LocalMcpHealthStore } from "./health.js";
import {
  DEFAULT_MAX_PACKAGE_BYTES,
  DEFAULT_MAX_PACKAGE_FILES,
  LOCAL_MCP_RISKS,
  buildSignedPackage,
  canonicalJson,
  publicKeyFingerprint,
  sha256Hex,
  validateManifestShape,
  verifySignedPackage,
} from "./package.js";
import { buildSandboxCommand } from "./sandbox.js";
import { JsonRpcProcessSession } from "./session.js";

export const DEFAULT_MAX_PROCESS_MS = 10_000;
export const DEFAULT_MAX_MESSAGE_BYTES = 1024 * 1024;
export const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
export const DEFAULT_LOCK_STALE_MS = 15 * 60 * 1000;

const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const SAFE_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$/;
const MINIMAL_ENV_NAMES = ["SystemRoot", "WINDIR"];

function fail(code, message) {
  throw new LocalMcpError(code, message);
}

function riskRank(risk) {
  const index = LOCAL_MCP_RISKS.indexOf(risk);
  if (index < 0) fail("invalid_config", "risk level is invalid");
  return index;
}

function parseSemver(value) {
  const match = SEMVER.exec(value);
  if (!match) fail("invalid_config", "client version is invalid");
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function compareVersions(left, right) {
  const a = parseSemver(left);
  const b = parseSemver(right);
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return 0;
}

function normalizeStringArray(value, label, { allowEmpty = true } = {}) {
  if (!Array.isArray(value)
      || (!allowEmpty && value.length === 0)
      || value.some((item) => typeof item !== "string" || !item)
      || new Set(value).size !== value.length) {
    fail("invalid_config", `${label} is invalid`);
  }
  return [...value];
}

function normalizeKeys(publicKeys, keyFingerprints) {
  const entries = publicKeys instanceof Map
    ? [...publicKeys.entries()]
    : publicKeys && typeof publicKeys === "object" && !Array.isArray(publicKeys)
      ? Object.entries(publicKeys)
      : null;
  if (!entries || entries.length === 0) fail("invalid_config", "publicKeys must not be empty");
  const fingerprints = keyFingerprints instanceof Map
    ? new Map(keyFingerprints)
    : keyFingerprints && typeof keyFingerprints === "object" && !Array.isArray(keyFingerprints)
      ? new Map(Object.entries(keyFingerprints))
      : new Map();
  const keys = new Map();
  for (const [keyId, input] of entries) {
    if (typeof keyId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(keyId)) {
      fail("invalid_config", "signing key id is invalid");
    }
    let key;
    try {
      if (input?.type === "private") throw new Error("private key");
      if (typeof input === "string" || Buffer.isBuffer(input)) {
        const text = Buffer.isBuffer(input) ? input.toString("utf8") : input;
        if (text.includes("PRIVATE KEY")) throw new Error("private key");
        key = crypto.createPublicKey(text);
      } else {
        key = crypto.createPublicKey(input);
      }
    } catch {
      fail("invalid_config", "public key could not be loaded");
    }
    if (key.asymmetricKeyType !== "ed25519") fail("invalid_config", "public key must be Ed25519");
    const fingerprint = publicKeyFingerprint(key);
    if (fingerprints.has(keyId) && fingerprints.get(keyId) !== fingerprint) {
      fail("invalid_config", "public key fingerprint does not match");
    }
    keys.set(keyId, { key, fingerprint });
  }
  return keys;
}

function normalizeEnvironment(environment) {
  if (environment === undefined) {
    const minimal = {};
    for (const name of MINIMAL_ENV_NAMES) {
      if (process.env[name]) minimal[name] = process.env[name];
    }
    return minimal;
  }
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) {
    fail("invalid_config", "environment must be an object");
  }
  const output = {};
  for (const [name, value] of Object.entries(environment)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)
        || typeof value !== "string"
        || value.includes("\0")
        || value.length > 16 * 1024) {
      fail("invalid_config", "environment contains an invalid variable");
    }
    output[name] = value;
  }
  return output;
}

function normalizeInterpreterAliases(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("invalid_config", "interpreterAliases must be an object");
  }
  const aliases = new Map();
  for (const [alias, command] of Object.entries(value)) {
    if (!/^[a-z][a-z0-9-]{0,31}$/.test(alias)
        || typeof command !== "string"
        || !path.isAbsolute(command)
        || command.includes("\0")) {
      fail("invalid_config", "interpreter alias is invalid");
    }
    aliases.set(alias, path.resolve(command));
  }
  if (aliases.size === 0) fail("invalid_config", "interpreterAliases must not be empty");
  return aliases;
}

function hostAllowed(host, allowlist) {
  return allowlist.some((entry) => {
    if (entry.startsWith("*.")) {
      const suffix = entry.slice(1);
      return host.endsWith(suffix) && host.length > suffix.length;
    }
    return host === entry;
  });
}

function manifestHostCovered(host, allowlist) {
  if (host.startsWith("*.")) return allowlist.includes(host);
  return hostAllowed(host, allowlist);
}

function normalizeNow(now) {
  return () => {
    const value = now();
    const milliseconds = value instanceof Date ? value.getTime() : Number(value);
    if (!Number.isFinite(milliseconds)) fail("invalid_config", "now returned an invalid value");
    return milliseconds;
  };
}

async function lstatOrNull(target) {
  try {
    return await fs.lstat(target);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function assertNoSymlinkPath(root, target) {
  const relative = path.relative(root, target);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    fail("path_traversal", "managed path escapes the root");
  }
  let current = root;
  for (const segment of relative.split(path.sep)) {
    current = path.join(current, segment);
    const stat = await lstatOrNull(current);
    if (!stat) return;
    if (stat.isSymbolicLink()) fail("path_symlink", "managed path contains a symbolic link");
  }
}

async function ensureDirectory(root, target) {
  await assertNoSymlinkPath(root, target);
  const parent = path.dirname(target);
  if (parent !== root) await ensureDirectory(root, parent);
  const stat = await lstatOrNull(target);
  if (!stat) {
    await fs.mkdir(target, { mode: 0o700 });
  } else if (stat.isSymbolicLink()) {
    fail("path_symlink", "managed directory is a symbolic link");
  } else if (!stat.isDirectory()) {
    fail("invalid_state", "managed directory is not a directory");
  }
  await assertNoSymlinkPath(root, target);
}

async function ensureRoot(rootDir) {
  const stat = await lstatOrNull(rootDir);
  if (!stat) {
    await fs.mkdir(rootDir, { recursive: true, mode: 0o700 });
  }
  const created = await lstatOrNull(rootDir);
  if (!created || created.isSymbolicLink() || !created.isDirectory()) {
    fail("invalid_config", "rootDir must be a real directory");
  }
  for (const name of ["packages", "staging", "locks", "state"]) {
    await ensureDirectory(rootDir, path.join(rootDir, name));
  }
}

async function writeFileSynced(file, data) {
  const handle = await fs.open(file, "wx", 0o600);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function safePackageSegment(value, label) {
  if (typeof value !== "string" || !SAFE_SEGMENT.test(value)) {
    fail("path_traversal", `${label} is not a safe path segment`);
  }
  return value;
}

function validateToolArguments(args, maxBytes) {
  let canonical;
  try {
    canonical = canonicalJson(args);
  } catch {
    fail("tool_denied", "tool arguments must be canonical JSON");
  }
  if (Buffer.byteLength(canonical, "utf8") > maxBytes) {
    fail("protocol_too_large", "tool arguments exceed the size limit");
  }
  return JSON.parse(canonical);
}

function sanitizeResult(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("protocol_invalid", "tool result must be an object");
  }
  return value;
}

export class LocalMcpHost {
  constructor({
    rootDir,
    publicKeys,
    keyFingerprints,
    allowedPublishers,
    allowedTools,
    deniedTools = [],
    maxRisk = "low",
    allowedCapabilities = [],
    allowedNetworkHosts = [],
    allowedSecretPrefixes = [],
    interpreterAliases,
    workspaceDir = null,
    tempDir = null,
    environment,
    secretBroker = null,
    approvalVerifier = null,
    approvalAtOrAbove = "high",
    auditSink = null,
    healthStore = null,
    healthReporter = null,
    sandboxAdapter = null,
    clientVersion,
    platform = process.platform,
    architecture = process.arch,
    deviceId = "",
    maxPackageBytes = DEFAULT_MAX_PACKAGE_BYTES,
    maxPackageFiles = DEFAULT_MAX_PACKAGE_FILES,
    maxProcessMs = DEFAULT_MAX_PROCESS_MS,
    maxMessageBytes = DEFAULT_MAX_MESSAGE_BYTES,
    maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
    lockStaleMs = DEFAULT_LOCK_STALE_MS,
    now = () => Date.now(),
  } = {}) {
    if (typeof rootDir !== "string" || !path.isAbsolute(rootDir)) {
      fail("invalid_config", "rootDir must be absolute");
    }
    if (typeof clientVersion !== "string" || !SEMVER.test(clientVersion)) {
      fail("invalid_config", "clientVersion is invalid");
    }
    if (!LOCAL_MCP_RISKS.includes(maxRisk)
        || !LOCAL_MCP_RISKS.includes(approvalAtOrAbove)) {
      fail("invalid_config", "risk policy is invalid");
    }
    if (!Number.isSafeInteger(maxPackageBytes) || maxPackageBytes < 1 || maxPackageBytes > 100 * 1024 * 1024) {
      fail("invalid_config", "maxPackageBytes is invalid");
    }
    if (!Number.isSafeInteger(maxPackageFiles) || maxPackageFiles < 1 || maxPackageFiles > 1024) {
      fail("invalid_config", "maxPackageFiles is invalid");
    }
    for (const [value, label, lower, upper] of [
      [maxProcessMs, "maxProcessMs", 100, 120_000],
      [maxMessageBytes, "maxMessageBytes", 1024, 16 * 1024 * 1024],
      [maxResponseBytes, "maxResponseBytes", 1024, 16 * 1024 * 1024],
      [lockStaleMs, "lockStaleMs", 1_000, 24 * 60 * 60 * 1000],
    ]) {
      if (!Number.isSafeInteger(value) || value < lower || value > upper) {
        fail("invalid_config", `${label} is invalid`);
      }
    }
    if (workspaceDir !== null && (typeof workspaceDir !== "string" || !path.isAbsolute(workspaceDir))) {
      fail("invalid_config", "workspaceDir must be absolute");
    }
    if (tempDir !== null && (typeof tempDir !== "string" || !path.isAbsolute(tempDir))) {
      fail("invalid_config", "tempDir must be absolute");
    }
    if (secretBroker !== null && typeof secretBroker.resolve !== "function") {
      fail("invalid_config", "secretBroker must provide resolve()");
    }
    if (approvalVerifier !== null && typeof approvalVerifier !== "function") {
      fail("invalid_config", "approvalVerifier must be a function");
    }
    if (auditSink !== null && typeof auditSink.write !== "function") {
      fail("invalid_config", "auditSink must provide write()");
    }
    if (healthReporter !== null && typeof healthReporter !== "function") {
      fail("invalid_config", "healthReporter must be a function");
    }
    if (sandboxAdapter !== null && typeof sandboxAdapter?.wrap !== "function") {
      fail("invalid_config", "sandboxAdapter must provide wrap()");
    }
    this.rootDir = path.resolve(rootDir);
    this.keys = normalizeKeys(publicKeys, keyFingerprints);
    this.allowedPublishers = normalizeStringArray(allowedPublishers, "allowedPublishers", { allowEmpty: false });
    this.allowedTools = normalizeStringArray(allowedTools, "allowedTools", { allowEmpty: false });
    this.deniedTools = normalizeStringArray(deniedTools, "deniedTools");
    this.maxRisk = maxRisk;
    this.allowedCapabilities = normalizeStringArray(allowedCapabilities, "allowedCapabilities");
    this.allowedNetworkHosts = normalizeStringArray(allowedNetworkHosts, "allowedNetworkHosts")
      .map((host) => host.toLowerCase());
    this.allowedSecretPrefixes = normalizeStringArray(
      allowedSecretPrefixes,
      "allowedSecretPrefixes",
    );
    this.interpreterAliases = normalizeInterpreterAliases(interpreterAliases);
    this.workspaceDir = workspaceDir ? path.resolve(workspaceDir) : null;
    this.tempDir = tempDir ? path.resolve(tempDir) : null;
    this.environment = normalizeEnvironment(environment);
    this.secretBroker = secretBroker;
    this.approvalVerifier = approvalVerifier;
    this.approvalAtOrAbove = approvalAtOrAbove;
    this.healthReporter = healthReporter;
    this.sandboxAdapter = sandboxAdapter;
    this.clientVersion = clientVersion;
    this.platform = platform;
    this.architecture = architecture;
    this.deviceId = deviceId;
    this.maxPackageBytes = maxPackageBytes;
    this.maxPackageFiles = maxPackageFiles;
    this.maxProcessMs = maxProcessMs;
    this.maxMessageBytes = maxMessageBytes;
    this.maxResponseBytes = maxResponseBytes;
    this.lockStaleMs = lockStaleMs;
    this.now = normalizeNow(now);
    this.auditSink = auditSink ?? new FileAuditSink(this.rootDir);
    this.healthStore = healthStore ?? new LocalMcpHealthStore(
      path.join(this.rootDir, "state"),
      { now: this.now },
    );
  }

  packageKey(manifest) {
    const trusted = this.keys.get(manifest.signingKeyId);
    if (!trusted) fail("key_unknown", "package signing key is not pinned");
    return trusted;
  }

  assertPolicy(manifest) {
    if (!this.allowedPublishers.includes(manifest.publisher)) {
      fail("publisher_denied", "package publisher is not allowed");
    }
    if (compareVersions(this.clientVersion, manifest.compatibility.minClientVersion) < 0) {
      fail("client_version_incompatible", "client version is too old for this package");
    }
    if (!manifest.compatibility.platforms.includes(this.platform)
        || !manifest.compatibility.architectures.includes(this.architecture)) {
      fail("platform_incompatible", "package does not support this platform");
    }
    if (manifest.permissions.capabilities.some((item) => !this.allowedCapabilities.includes(item))) {
      fail("policy_denied", "package requests a capability not granted by enterprise policy");
    }
    if (manifest.permissions.networkHosts.some(
      (host) => !manifestHostCovered(host.toLowerCase(), this.allowedNetworkHosts),
    )) {
      fail("policy_denied", "package requests a network host not granted by enterprise policy");
    }
    if (!this.allowedSecretPrefixes.length && manifest.secrets.length) {
      fail("policy_denied", "package requests secrets while secret access is disabled");
    }
    if (manifest.secrets.some(
      (secret) => !this.allowedSecretPrefixes.some((prefix) => secret.reference.startsWith(prefix)),
    )) {
      fail("policy_denied", "package requests a secret outside the allowed scope");
    }
  }

  async verifyPackage(input) {
    let wrapper;
    try {
      wrapper = typeof input === "string" || Buffer.isBuffer(input)
        ? JSON.parse(Buffer.isBuffer(input) ? input.toString("utf8") : input)
        : input;
    } catch {
      fail("invalid_package", "package is not valid JSON");
    }
    const keyId = wrapper?.manifest?.signingKeyId;
    const trusted = typeof keyId === "string" ? this.keys.get(keyId) : null;
    if (!trusted) fail("key_unknown", "package signing key is not pinned");
    const verified = verifySignedPackage(trusted.key, wrapper, {
      maxBytes: this.maxPackageBytes,
      maxFiles: this.maxPackageFiles,
    });
    this.assertPolicy(verified.manifest);
    return verified;
  }

  targetDirectory(packageId, releaseId) {
    safePackageSegment(packageId, "packageId");
    safePackageSegment(releaseId, "releaseId");
    return path.join(this.rootDir, "packages", packageId, releaseId);
  }

  async loadInstalled(packageId, releaseId) {
    await ensureRoot(this.rootDir);
    const target = this.targetDirectory(packageId, releaseId);
    await assertNoSymlinkPath(this.rootDir, target);
    const stat = await lstatOrNull(target);
    if (!stat || !stat.isDirectory() || stat.isSymbolicLink()) {
      fail("package_not_installed", "local MCP package is not installed");
    }
    const metadataPath = path.join(target, "metadata.json");
    const metadataStat = await lstatOrNull(metadataPath);
    if (!metadataStat || !metadataStat.isFile() || metadataStat.isSymbolicLink()
        || metadataStat.size > 512 * 1024) {
      fail("package_tampered", "installed package metadata is invalid");
    }
    let manifest;
    try {
      manifest = validateManifestShape(
        JSON.parse(await fs.readFile(metadataPath, "utf8")),
        { maxBytes: this.maxPackageBytes, maxFiles: this.maxPackageFiles },
      );
    } catch (error) {
      if (error instanceof LocalMcpError) throw error;
      fail("package_tampered", "installed package metadata is invalid");
    }
    if (manifest.packageId !== packageId || manifest.releaseId !== releaseId) {
      fail("package_tampered", "installed package identity does not match its path");
    }
    const trusted = this.packageKey(manifest);
    this.assertPolicy(manifest);
    const files = {};
    for (const descriptor of manifest.files) {
      const file = path.join(target, ...descriptor.path.split("/"));
      await assertNoSymlinkPath(this.rootDir, file);
      const fileStat = await lstatOrNull(file);
      if (!fileStat || !fileStat.isFile() || fileStat.isSymbolicLink()) {
        fail("package_tampered", "installed package file is missing");
      }
      const content = await fs.readFile(file);
      if (content.length !== descriptor.bytes) {
        fail("package_tampered", "installed package file size changed");
      }
      files[descriptor.path] = `base64:${content.toString("base64")}`;
    }
    const verified = verifySignedPackage(trusted.key, {
      schemaVersion: 1,
      manifest,
      files,
    }, {
      maxBytes: this.maxPackageBytes,
      maxFiles: this.maxPackageFiles,
    });
    return {
      ...verified,
      directory: target,
    };
  }

  async acquireInstallLock(packageId, releaseId) {
    await ensureRoot(this.rootDir);
    const lockFile = path.join(
      this.rootDir,
      "locks",
      `${sha256Hex(`${packageId}\0${releaseId}`).slice(0, 40)}.lock`,
    );
    try {
      const handle = await fs.open(lockFile, "wx", 0o600);
      await handle.writeFile(String(this.now()));
      await handle.close();
    } catch (error) {
      if (error.code !== "EEXIST") fail("install_failed", "install lock could not be created");
      const stat = await lstatOrNull(lockFile);
      if (stat && this.now() - stat.mtimeMs > this.lockStaleMs) {
        await fs.rm(lockFile, { force: true });
        return this.acquireInstallLock(packageId, releaseId);
      }
      fail("install_locked", "another install is in progress");
    }
    return async () => {
      await fs.rm(lockFile, { force: true });
    };
  }

  async audit(event) {
    try {
      await this.auditSink.write({ at: new Date(this.now()).toISOString(), ...event });
    } catch {
      fail("audit_unavailable", "audit event could not be recorded");
    }
  }

  async install(input) {
    const verified = await this.verifyPackage(input);
    const { manifest, files } = verified;
    await ensureRoot(this.rootDir);
    const target = this.targetDirectory(manifest.packageId, manifest.releaseId);
    const releaseLock = await this.acquireInstallLock(manifest.packageId, manifest.releaseId);
    try {
      const existing = await lstatOrNull(target);
      if (existing) {
        if (existing.isSymbolicLink() || !existing.isDirectory()) {
          fail("package_conflict", "installed package path is not a safe directory");
        }
        const installed = await this.loadInstalled(manifest.packageId, manifest.releaseId);
        if (installed.manifest.packageDigest !== manifest.packageDigest) {
          fail("package_conflict", "a different immutable release already exists");
        }
        return {
          status: "already_installed",
          packageId: manifest.packageId,
          releaseId: manifest.releaseId,
          packageDigest: manifest.packageDigest,
        };
      }
      await this.audit({
        event: "local_mcp.install_started",
        packageId: manifest.packageId,
        releaseId: manifest.releaseId,
        packageDigest: manifest.packageDigest,
        publisher: manifest.publisher,
        signingKeyId: manifest.signingKeyId,
      });
      const staging = path.join(this.rootDir, "staging", crypto.randomUUID());
      await fs.mkdir(staging, { mode: 0o700 });
      try {
        for (const descriptor of manifest.files) {
          const output = path.join(staging, ...descriptor.path.split("/"));
          await fs.mkdir(path.dirname(output), { recursive: true, mode: 0o700 });
          await writeFileSynced(output, files.get(descriptor.path));
        }
        await writeFileSynced(
          path.join(staging, "metadata.json"),
          `${JSON.stringify(manifest)}\n`,
        );
        const parent = path.dirname(target);
        await ensureDirectory(this.rootDir, parent);
        await fs.rename(staging, target);
      } catch (error) {
        await fs.rm(staging, { recursive: true, force: true });
        if (error instanceof LocalMcpError) throw error;
        fail("install_failed", "package could not be installed atomically");
      }
      await this.loadInstalled(manifest.packageId, manifest.releaseId);
      await this.audit({
        event: "local_mcp.install_completed",
        packageId: manifest.packageId,
        releaseId: manifest.releaseId,
        packageDigest: manifest.packageDigest,
        publisher: manifest.publisher,
        signingKeyId: manifest.signingKeyId,
      });
      await this.healthStore.recordInstalled(manifest);
      await this.reportHealth();
      return {
        status: "installed",
        packageId: manifest.packageId,
        releaseId: manifest.releaseId,
        packageDigest: manifest.packageDigest,
      };
    } finally {
      await releaseLock();
    }
  }

  async listTools(packageId, releaseId) {
    const installed = await this.loadInstalled(packageId, releaseId);
    return installed.manifest.tools
      .filter((tool) => this.toolAllowed(tool))
      .map((tool) => ({
        name: tool.name,
        description: tool.description,
        risk: tool.risk,
        capabilities: [...tool.capabilities],
      }));
  }

  toolAllowed(tool) {
    if (this.deniedTools.includes(tool.name)) return false;
    if (!this.allowedTools.includes("*") && !this.allowedTools.includes(tool.name)) return false;
    if (riskRank(tool.risk) > riskRank(this.maxRisk)) return false;
    return tool.capabilities.every((capability) => this.allowedCapabilities.includes(capability));
  }

  async resolveSecrets(manifest, toolName, signal) {
    if (!manifest.secrets.length) return {};
    if (!this.secretBroker) fail("secret_unavailable", "secret broker is not configured");
    const environment = {};
    for (const secret of manifest.secrets) {
      let lease;
      try {
        lease = await this.secretBroker.resolve({
          reference: secret.reference,
          packageId: manifest.packageId,
          releaseId: manifest.releaseId,
          toolName,
          deviceId: this.deviceId,
        }, signal);
      } catch (error) {
        if (secret.required) {
          if (error instanceof LocalMcpError) throw error;
          fail("secret_unavailable", "required secret is unavailable");
        }
        continue;
      }
      if (!lease
          || typeof lease.value !== "string"
          || !lease.value
          || typeof lease.leaseId !== "string"
          || typeof lease.expiresAt !== "string"
          || Date.parse(lease.expiresAt) <= this.now()) {
        if (secret.required) fail("secret_expired", "required secret lease is invalid or expired");
        continue;
      }
      if (Object.hasOwn(this.environment, secret.name)) {
        fail("invalid_config", "secret name collides with the restricted environment");
      }
      environment[secret.name] = lease.value;
    }
    return environment;
  }

  async safeHealth(operation) {
    try {
      await operation();
      return true;
    } catch {
      return false;
    }
  }

  async reportHealth() {
    if (!this.healthReporter) return;
    try {
      const report = await this.healthStore.report();
      await this.healthReporter(report);
    } catch {
      // Reporting is best effort; the local health state remains authoritative.
    }
  }

  async denyTool(manifest, toolName, error) {
    const code = error instanceof LocalMcpError ? error.code : "tool_denied";
    await this.safeHealth(() => this.healthStore.recordTool(
      manifest.packageId,
      manifest.releaseId,
      toolName,
      { status: "denied", errorCode: code },
    ));
    await this.audit({
      event: "local_mcp.tool_denied",
      packageId: manifest.packageId,
      releaseId: manifest.releaseId,
      toolName,
      errorCode: code,
    });
    await this.reportHealth();
    throw error;
  }

  async verifyToolApproval(tool, approval, manifest) {
    if (riskRank(tool.risk) < riskRank(this.approvalAtOrAbove)) return;
    if (!approval || typeof approval !== "object" || Array.isArray(approval)) {
      fail("approval_required", "this tool requires an enterprise approval");
    }
    if (!this.approvalVerifier) {
      fail("approval_required", "approval verifier is not configured");
    }
    let valid = false;
    try {
      valid = await this.approvalVerifier({
        packageId: manifest.packageId,
        releaseId: manifest.releaseId,
        packageDigest: manifest.packageDigest,
        toolName: tool.name,
        risk: tool.risk,
        approval,
        deviceId: this.deviceId,
      });
    } catch {
      valid = false;
    }
    if (!valid) fail("approval_invalid", "enterprise approval is invalid");
  }

  async callTool(packageId, releaseId, toolName, args, options = {}) {
    const installed = await this.loadInstalled(packageId, releaseId);
    const { manifest } = installed;
    const tool = manifest.tools.find((item) => item.name === toolName);
    if (!tool) {
      await this.denyTool(manifest, toolName, new LocalMcpError(
        "tool_not_found",
        "tool is not declared by the signed package",
      ));
    }
    if (!this.toolAllowed(tool)) {
      await this.denyTool(manifest, toolName, new LocalMcpError(
        "tool_denied",
        "tool is denied by enterprise policy",
      ));
    }
    try {
      await this.verifyToolApproval(tool, options.approval, manifest);
    } catch (error) {
      await this.denyTool(manifest, toolName, error);
    }
    const normalizedArgs = validateToolArguments(args, this.maxMessageBytes);
    const interpreter = this.interpreterAliases.get(manifest.runtime.interpreter);
    if (!interpreter) {
      await this.denyTool(manifest, toolName, new LocalMcpError(
        "runtime_not_supported",
        "package interpreter is not configured",
      ));
    }

    const startedAt = this.now();
    await this.audit({
      event: "local_mcp.tool_started",
      packageId: manifest.packageId,
      releaseId: manifest.releaseId,
      toolName,
      risk: tool.risk,
      capabilities: [...tool.capabilities],
    });
    const healthStarted = await this.safeHealth(() => this.healthStore.recordTool(
      manifest.packageId,
      manifest.releaseId,
      toolName,
      { status: "started" },
    ));
    if (!healthStarted) {
      await this.audit({
        event: "local_mcp.tool_failed",
        packageId: manifest.packageId,
        releaseId: manifest.releaseId,
        toolName,
        errorCode: "health_write_failed",
      });
      fail("health_write_failed", "health state could not be recorded before execution");
    }
    const runtimeStarted = await this.safeHealth(() => this.healthStore.recordRuntime(
      manifest.packageId,
      manifest.releaseId,
      { runtimeStatus: "starting", health: "degraded" },
    ));
    if (!runtimeStarted) {
      await this.audit({
        event: "local_mcp.tool_failed",
        packageId: manifest.packageId,
        releaseId: manifest.releaseId,
        toolName,
        errorCode: "health_write_failed",
      });
      fail("health_write_failed", "health state could not be recorded before execution");
    }

    let session;
    let secretEnvironment = {};
    try {
      secretEnvironment = await this.resolveSecrets(manifest, toolName, options.signal);
      const sandbox = buildSandboxCommand({
        manifest,
        packageDir: installed.directory,
        interpreter,
        workspaceDir: this.workspaceDir,
        tempDir: this.tempDir,
        environment: {
          ...this.environment,
          ...secretEnvironment,
        },
        sandboxAdapter: this.sandboxAdapter,
      });
      session = new JsonRpcProcessSession({
        command: sandbox.command,
        args: sandbox.args,
        cwd: sandbox.cwd,
        env: sandbox.env,
        maxMessageBytes: this.maxMessageBytes,
        maxResponseBytes: this.maxResponseBytes,
      });
      await session.start();
      await session.request("initialize", {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: {
          name: "magpie-enterprise-local-mcp",
          version: this.clientVersion,
        },
      }, this.maxProcessMs);
      session.notify("notifications/initialized", {});
      const catalog = await session.request("tools/list", {}, this.maxProcessMs);
      if (!catalog || typeof catalog !== "object" || !Array.isArray(catalog.tools)) {
        fail("protocol_invalid", "tools/list result is invalid");
      }
      const names = catalog.tools
        .map((entry) => entry?.name)
        .filter((name) => typeof name === "string")
        .sort();
      const expected = manifest.tools.map((entry) => entry.name).sort();
      if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
        fail("protocol_invalid", "served tools do not match the signed package");
      }
      const result = sanitizeResult(await session.request("tools/call", {
        name: toolName,
        arguments: normalizedArgs,
      }, this.maxProcessMs));
      const failed = result.isError === true;
      const durationMs = Math.max(0, this.now() - startedAt);
      await this.safeHealth(() => this.healthStore.recordTool(
        manifest.packageId,
        manifest.releaseId,
        toolName,
        {
          status: failed ? "failed" : "succeeded",
          errorCode: failed ? "tool_failed" : null,
          durationMs,
          responseBytes: Buffer.byteLength(JSON.stringify(result), "utf8"),
        },
      ));
      await this.safeHealth(() => this.healthStore.recordRuntime(
        manifest.packageId,
        manifest.releaseId,
        { runtimeStatus: "stopped", health: failed ? "degraded" : "healthy" },
      ));
      await this.audit({
        event: "local_mcp.tool_finished",
        packageId: manifest.packageId,
        releaseId: manifest.releaseId,
        toolName,
        status: failed ? "tool_error" : "succeeded",
        durationMs,
      });
      await this.reportHealth();
      return {
        status: failed ? "tool_error" : "succeeded",
        result,
      };
    } catch (error) {
      const local = error instanceof LocalMcpError
        ? error
        : new LocalMcpError("process_failed", "local MCP tool call failed");
      await this.safeHealth(() => this.healthStore.recordTool(
        manifest.packageId,
        manifest.releaseId,
        toolName,
        {
          status: "failed",
          errorCode: local.code,
          durationMs: Math.max(0, this.now() - startedAt),
        },
      ));
      await this.safeHealth(() => this.healthStore.recordRuntime(
        manifest.packageId,
        manifest.releaseId,
        {
          runtimeStatus: local.code === "process_timeout" ? "timeout" : "failed",
          health: "unhealthy",
          errorCode: local.code,
        },
      ));
      try {
        await this.audit({
          event: "local_mcp.tool_failed",
          packageId: manifest.packageId,
          releaseId: manifest.releaseId,
          toolName,
          errorCode: local.code,
        });
      } catch {
        await this.reportHealth();
        throw new LocalMcpError("audit_unavailable", "tool failed and audit could not be recorded");
      }
      await this.reportHealth();
      throw local;
    } finally {
      await session?.close();
    }
  }

  async health() {
    await ensureRoot(this.rootDir);
    return this.healthStore.report();
  }
}

export { buildSignedPackage };
