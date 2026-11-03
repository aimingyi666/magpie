/**
 * M10 - MCP Resource Library: Role-Based Permissions
 *
 * Access-control rules for MCP servers: deny-by-default, allow rules matching
 * role + org unit.
 */

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

export const ROLE_SCOPE_FIELDS = new Set([
  "allowedRoles",
  "allowedOrgUnits",
  "deniedRoles",
  "deniedOrgUnits",
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

function validatePermission(permissionId, permission) {
  if (!exactFields(permission, PERMISSION_FIELDS)
      || permission.id !== permissionId
      || !ID_PATTERN.test(permissionId)) {
    throw new Error(`MCP permission ${permissionId} is invalid`);
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
    throw new Error(`MCP permission ${permissionId} contains invalid fields`);
  }
  return permission;
}

export function emptyPermissions() {
  return {};
}

export class McpPermissionStore {
  constructor(store) {
    this.store = store;
  }

  get storeKey() {
    return "mcpPermissions";
  }

  async read(fn) {
    await this.store.read((data) => {
      if (!(this.storeKey in data)) {
        data[this.storeKey] = {};
      }
      return fn(data[this.storeKey]);
    });
  }

  async mutate(fn) {
    const result = await this.store.mutate((data) => {
      if (!(this.storeKey in data)) {
        data[this.storeKey] = {};
      }
      const draft = data[this.storeKey];
      const outcome = fn(draft);
      return outcome;
    });
    return result;
  }

  async list() {
    return await this.read((permissions) => {
      return Object.values(permissions);
    });
  }

  async get(permissionId) {
    return await this.read((permissions) => {
      return permissions[permissionId] ?? null;
    });
  }

  async create(permissionId, permission) {
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
    const existing = await this.get(permissionId);
    if (!existing) {
      throw new McpPermissionError("Permission not found", { statusCode: 404 });
    }
    const merged = { ...existing, ...patch };
    validatePermission(permissionId, merged);
    return await this.mutate((permissions) => {
      permissions[permissionId] = merged;
      return merged;
    });
  }

  async delete(permissionId) {
    const existing = await this.get(permissionId);
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

    // Step 1: explicit deny wins.
    const denies = permissions.filter((perm) => perm.mcpServerId === mcpServerId)
      .some((perm) => {
        if (perm.deniedRoles.some((r) => roles.includes(r))) return true;
        if (perm.deniedOrgUnits.some((o) => orgUnits.includes(o))) return true;
        return false;
      });
    if (denies) return { allowed: false, reason: "denied" };

    // Step 2: allow rules matching role + org unit.
    const allows = permissions.filter((perm) => perm.mcpServerId === mcpServerId)
      .some((perm) => {
        const roleMatch = perm.allowedRoles.length === 0
          || perm.allowedRoles.some((r) => roles.includes(r));
        const orgMatch = perm.allowedOrgUnits.length === 0
          || perm.allowedOrgUnits.some((o) => orgUnits.includes(o));
        return roleMatch && orgMatch;
      });
    if (allows) return { allowed: true };

    // Step 3: deny by default.
    return { allowed: false, reason: "no_rule" };
  }
}