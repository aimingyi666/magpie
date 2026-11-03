/**
 * M10 - MCP Resource Library: Role-Based Permissions
 *
 * Access-control rules for MCP servers: deny-by-default, allow rules matching
 * role + org unit.
 */

import fs from "node:fs/promises";
import path from "node:path";

export const PERMISSION_FIELDS = new Set([
  "id",
  "mcpServerId",
  "allowedRoles",
  "allowedOrgUnits",
  "deniedRoles",
  "deniedOrgUnits",
  "description",
  "createdAt",
  "createdBy",
]);

const ID_PATTERN = /^mcp_perm_[a-z0-9]{16,64}$/;

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

function identityId(value) {
  return typeof value === "string"
    && /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(value);
}

function uniqueTextArray(value, maximum, validate) {
  return Array.isArray(value)
    && value.length <= maximum
    && value.every(validate)
    && new Set(value).size === value.length;
}

export function emptyPermissions() {
  return {};
}

function validatePermission(permissionId, permission) {
  if (!exactFields(permission, PERMISSION_FIELDS)
      || permission.id !== permissionId
      || !ID_PATTERN.test(permissionId)) {
    throw new Error("MCP permission " + permissionId + " is invalid");
  }
  if (!safeText(permission.mcpServerId, 200)
      || !uniqueTextArray(permission.allowedRoles, 100, identityId)
      || !uniqueTextArray(permission.allowedOrgUnits, 100, identityId)
      || !uniqueTextArray(permission.deniedRoles, 100, identityId)
      || !uniqueTextArray(permission.deniedOrgUnits, 100, identityId)
      || !safeText(permission.description, 2000, true)
      || !safeText(permission.createdBy, 128)
      || typeof permission.createdAt !== "string"
      || !Date.parse(permission.createdAt)) {
    throw new Error("MCP permission " + permissionId + " contains invalid fields");
  }
  return permission;
}

function validatePermissions(data) {
  if (!plainObject(data)) {
    throw new Error("MCP permissions must be an object");
  }
  for (const [permissionId, permission] of Object.entries(data)) {
    validatePermission(permissionId, permission);
  }
  return data;
}

export async function writeAtomicJson(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = file + "." + process.pid + "." + Date.now() + "." + Math.random().toString(16).slice(2) + ".tmp";
  const handle = await fs.open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(JSON.stringify(value, null, 2) + "\n", "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(temporary, file);
}

export class McpPermissionStore {
  constructor(file) {
    this.file = file;
    this.data = {};
    this.queue = Promise.resolve();
  }

  async load() {
    try {
      this.data = validatePermissions(JSON.parse(await fs.readFile(this.file, "utf8")));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await writeAtomicJson(this.file, this.data);
    }
    return this.data;
  }

  async mutate(fn) {
    const run = this.queue.then(async () => {
      const draft = structuredClone(this.data);
      const result = await fn(draft);
      validatePermissions(draft);
      await writeAtomicJson(this.file, draft);
      this.data = draft;
      return result;
    });
    this.queue = run.catch(() => {});
    return run;
  }

  async list() {
    await this.queue;
    return Object.values(this.data);
  }

  async get(permissionId) {
    await this.queue;
    return this.data[permissionId] ?? null;
  }

  async create(permissionId, input, actor = "admin-service") {
    const now = new Date().toISOString();
    const permission = {
      id: permissionId,
      mcpServerId: input.mcpServerId,
      allowedRoles: input.allowedRoles ?? [],
      allowedOrgUnits: input.allowedOrgUnits ?? [],
      deniedRoles: input.deniedRoles ?? [],
      deniedOrgUnits: input.deniedOrgUnits ?? [],
      description: input.description ?? "",
      createdAt: input.createdAt ?? now,
      createdBy: input.createdBy ?? actor,
    };
    validatePermission(permissionId, permission);
    return await this.mutate((permissions) => {
      if (permissionId in permissions) {
        throw new McpPermissionError("Permission already exists", { statusCode: 409 });
      }
      permissions[permissionId] = permission;
      return permission;
    });
  }

  async update(permissionId, patch) {
    await this.queue;
    const existing = this.data[permissionId];
    if (!existing) {
      throw new McpPermissionError("Permission not found", { statusCode: 404 });
    }
    const merged = { ...existing, ...patch, id: permissionId };
    validatePermission(permissionId, merged);
    return await this.mutate((permissions) => {
      permissions[permissionId] = merged;
      return merged;
    });
  }

  async delete(permissionId) {
    await this.queue;
    const existing = this.data[permissionId];
    if (!existing) {
      throw new McpPermissionError("Permission not found", { statusCode: 404 });
    }
    return await this.mutate((permissions) => {
      delete permissions[permissionId];
      return existing;
    });
  }
}

export class McpPermissionError extends Error {
  constructor(message = "MCP permission error", options = {}) {
    super(message);
    this.name = "McpPermissionError";
    this.statusCode = Number.isInteger(options.statusCode) ? options.statusCode : 400;
    this.code = typeof options.code === "string" && options.code
      ? options.code
      : "mcp_permission_error";
  }
}

export class McpPermissionChecker {
  constructor(permissionStore) {
    this.permissionStore = permissionStore;
  }

  async canAccess({ mcpServerId, roles, orgUnits }) {
    const permissions = await this.permissionStore.list();

    const denies = permissions.filter((perm) => perm.mcpServerId === mcpServerId)
      .some((perm) => {
        if (perm.deniedRoles.some((r) => roles.includes(r))) return true;
        if (perm.deniedOrgUnits.some((o) => orgUnits.includes(o))) return true;
        return false;
      });
    if (denies) return { allowed: false, reason: "denied" };

    const allows = permissions.filter((perm) => perm.mcpServerId === mcpServerId)
      .some((perm) => {
        const roleMatch = perm.allowedRoles.length === 0
          || perm.allowedRoles.some((r) => roles.includes(r));
        const orgMatch = perm.allowedOrgUnits.length === 0
          || perm.allowedOrgUnits.some((o) => orgUnits.includes(o));
        return roleMatch && orgMatch;
      });
    if (allows) return { allowed: true };

    return { allowed: false, reason: "no_rule" };
  }


}
