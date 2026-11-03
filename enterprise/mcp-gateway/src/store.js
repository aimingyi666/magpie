import fs from "node:fs/promises";
import path from "node:path";

export const STORE_SCHEMA_VERSION = 1;
export const SERVER_STATUSES = Object.freeze(["active", "disabled"]);
export const CLIENT_STATUSES = Object.freeze(["active", "revoked"]);
export const TOOL_ACCESS = Object.freeze(["allow", "deny"]);
export const RISK_LEVELS = Object.freeze(["low", "medium", "high", "critical"]);

const STORE_FIELDS = new Set(["version", "servers", "clients", "idempotency"]);
const STORE_FIELDS_WITH_PERMS = new Set(["version", "servers", "clients", "idempotency", "mcpPermissions"]);
const SERVER_FIELDS = new Set([
  "id",
  "namespace",
  "name",
  "description",
  "endpoint",
  "secretRef",
  "assignments",
  "status",
  "toolPolicies",
  "createdAt",
  "updatedAt",
  "createdBy",
  "updatedBy",
]);
const TOOL_POLICY_FIELDS = new Set(["tool", "access", "risk", "visible"]);
const CLIENT_FIELDS = new Set([
  "id",
  "name",
  "subjectId",
  "orgIds",
  "deviceIds",
  "serverScopes",
  "tokenDigest",
  "status",
  "expiresAt",
  "createdAt",
  "createdBy",
  "revokedAt",
  "revokedBy",
]);
const IDEMPOTENCY_FIELDS = new Set([
  "fingerprint",
  "method",
  "path",
  "statusCode",
  "responseBody",
  "operationId",
  "createdAt",
]);
const SERVER_STATUS_SET = new Set(SERVER_STATUSES);
const CLIENT_STATUS_SET = new Set(CLIENT_STATUSES);
const TOOL_ACCESS_SET = new Set(TOOL_ACCESS);
const RISK_LEVEL_SET = new Set(RISK_LEVELS);
const SECRET_VALUE_PATTERNS = Object.freeze([
  /-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/,
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,
  /\bsk-[A-Za-z0-9_-]{20,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b/i,
]);

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactFields(value, fields) {
  return plainObject(value)
    && Object.keys(value).length === fields.size
    && Object.keys(value).every((key) => fields.has(key));
}

function safeText(value, maximum = 500, allowEmpty = false) {
  return typeof value === "string"
    && value.length <= maximum
    && (allowEmpty || value.length > 0)
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function timestamp(value) {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function stableId(value, prefix) {
  return typeof value === "string"
    && new RegExp(`^${prefix}[a-z0-9]{16,64}$`).test(value);
}

function uniqueTextArray(value, maximum, validate) {
  return Array.isArray(value)
    && value.length <= maximum
    && value.every(validate)
    && new Set(value).size === value.length;
}

function assignment(value) {
  return value === "*"
    || (typeof value === "string"
      && /^(?:user|org|device):[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(value));
}

function identityId(value) {
  return typeof value === "string"
    && /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(value);
}

function selector(value) {
  return value === "*" || stableId(value, "srv_");
}

function environmentName(value) {
  return value === "" || /^[A-Z][A-Z0-9_]{2,127}$/.test(value);
}

function endpoint(value) {
  if (!safeText(value, 2048)) return false;
  try {
    const parsed = new URL(value);
    return ["http:", "https:"].includes(parsed.protocol)
      && !parsed.username
      && !parsed.password
      && !parsed.hash;
  } catch {
    return false;
  }
}

function validateToolPolicy(policy) {
  return exactFields(policy, TOOL_POLICY_FIELDS)
    && safeText(policy.tool, 128)
    && !policy.tool.includes("__")
    && TOOL_ACCESS_SET.has(policy.access)
    && RISK_LEVEL_SET.has(policy.risk)
    && typeof policy.visible === "boolean"
    && (policy.access === "deny" ? policy.visible === false : true);
}

function validateServer(serverId, server, namespaces) {
  if (!exactFields(server, SERVER_FIELDS)
      || server.id !== serverId
      || !stableId(serverId, "srv_")) {
    throw new Error("MCP registry contains an invalid server record");
  }
  if (!/^[a-z][a-z0-9-]{1,31}$/.test(server.namespace)
      || namespaces.has(server.namespace)
      || !safeText(server.name, 200)
      || !safeText(server.description, 2000, true)
      || !endpoint(server.endpoint)
      || !environmentName(server.secretRef)
      || !uniqueTextArray(server.assignments, 100, assignment)
      || !SERVER_STATUS_SET.has(server.status)
      || !Array.isArray(server.toolPolicies)
      || server.toolPolicies.length > 500
      || !server.toolPolicies.every(validateToolPolicy)
      || new Set(server.toolPolicies.map((policy) => policy.tool)).size !== server.toolPolicies.length
      || !timestamp(server.createdAt)
      || !timestamp(server.updatedAt)
      || Date.parse(server.updatedAt) < Date.parse(server.createdAt)
      || !safeText(server.createdBy, 128)
      || !safeText(server.updatedBy, 128)) {
    throw new Error(`MCP registry server ${serverId} is invalid`);
  }
  namespaces.add(server.namespace);
}

function validateClient(clientId, client) {
  if (!exactFields(client, CLIENT_FIELDS)
      || client.id !== clientId
      || !stableId(clientId, "cli_")) {
    throw new Error("MCP registry contains an invalid client record");
  }
  const revoked = client.status === "revoked";
  if (!safeText(client.name, 200)
      || !identityId(client.subjectId)
      || !uniqueTextArray(client.orgIds, 100, identityId)
      || !uniqueTextArray(client.deviceIds, 100, identityId)
      || !uniqueTextArray(client.serverScopes, 1000, selector)
      || !/^[a-f0-9]{64}$/.test(client.tokenDigest)
      || !CLIENT_STATUS_SET.has(client.status)
      || !timestamp(client.expiresAt)
      || !timestamp(client.createdAt)
      || !safeText(client.createdBy, 128)
      || (revoked
        ? !timestamp(client.revokedAt) || !safeText(client.revokedBy, 128)
        : client.revokedAt !== "" || client.revokedBy !== "")) {
    throw new Error(`MCP registry client ${clientId} is invalid`);
  }
}

function validateIdempotency(key, record) {
  if (!/^[a-f0-9]{64}$/.test(key)
      || !exactFields(record, IDEMPOTENCY_FIELDS)
      || !/^[a-f0-9]{64}$/.test(record.fingerprint)
      || !["POST", "PUT"].includes(record.method)
      || !safeText(record.path, 1024)
      || !Number.isInteger(record.statusCode)
      || record.statusCode < 200
      || record.statusCode > 299
      || !plainObject(record.responseBody)
      || !safeText(record.operationId, 128)
      || !timestamp(record.createdAt)) {
    throw new Error("MCP registry contains an invalid idempotency record");
  }
}

function assertNoCredentialValues(data) {
  const serialized = JSON.stringify(data);
  for (const pattern of SECRET_VALUE_PATTERNS) {
    if (pattern.test(serialized)) {
      throw new Error("MCP registry must not contain credential values");
    }
  }
}

export function emptyStore() {
  return {
    version: STORE_SCHEMA_VERSION,
    servers: {},
    clients: {},
    idempotency: {},
  };
}

export function validateStore(data) {
  const fields = "mcpPermissions" in data ? STORE_FIELDS_WITH_PERMS : STORE_FIELDS;
  if (!exactFields(data, fields)) {
    throw new Error("MCP registry with permissions must include only schema fields plus mcpPermissions");
  }
  if (data.version !== STORE_SCHEMA_VERSION) {
    throw new Error(`MCP registry schema ${data.version} is unsupported`);
  }
  if (!plainObject(data.servers)
      || !plainObject(data.clients)
      || !plainObject(data.idempotency)) {
    throw new Error("MCP registry collection types are invalid");
  }
  if ("mcpPermissions" in data && !plainObject(data.mcpPermissions)) {
    throw new Error("MCP registry mcpPermissions must be an object");
  }
  const namespaces = new Set();
  for (const [serverId, server] of Object.entries(data.servers)) {
    validateServer(serverId, server, namespaces);
  }
  for (const [clientId, client] of Object.entries(data.clients)) {
    validateClient(clientId, client);
    for (const scope of client.serverScopes) {
      if (scope !== "*" && !data.servers[scope]) {
        throw new Error(`MCP registry client ${clientId} references a missing server scope`);
      }
    }
  }
  for (const [key, record] of Object.entries(data.idempotency)) {
    validateIdempotency(key, record);
  }
  assertNoCredentialValues(data);
  return data;
}

export async function writeAtomicJson(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`;
  const handle = await fs.open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(temporary, file);
}

export class McpRegistryStore {
  constructor(file) {
    this.file = file;
    this.data = emptyStore();
    this.queue = Promise.resolve();
  }

  async load() {
    try {
      this.data = validateStore(JSON.parse(await fs.readFile(this.file, "utf8")));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await writeAtomicJson(this.file, this.data);
    }
    return this.data;
  }

  async read(fn) {
    await this.queue;
    return fn(this.data);
  }

  mutate(fn) {
    const run = this.queue.then(async () => {
      const draft = structuredClone(this.data);
      const result = await fn(draft);
      validateStore(draft);
      await writeAtomicJson(this.file, draft);
      this.data = draft;
      return result;
    });
    this.queue = run.catch(() => {});
    return run;
  }
}
