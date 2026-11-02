import { sha256 } from "./security.js";

export const ROLES = Object.freeze({
  employee: [],
  department_admin: [
    "users.read",
    "devices.read",
    "credentials.read",
    "quota.read",
    "quota.write",
    "models.read",
    "models.write",
    "mcp.read",
    "resources.read",
    "usage.read",
    "approvals.read",
    "notifications.read",
  ],
  enterprise_admin: [
    "users.read",
    "users.invite",
    "users.disable",
    "devices.read",
    "devices.revoke",
    "credentials.read",
    "credentials.rotate",
    "quota.read",
    "quota.write",
    "models.read",
    "models.write",
    "mcp.read",
    "mcp.write",
    "resources.read",
    "resources.write",
    "usage.read",
    "usage.export",
    "audit.read",
    "audit.export",
    "operations.reconcile",
    "alerts.read",
    "alerts.respond",
    "roles.read",
    "system.read",
    "approvals.read",
    "approvals.decide",
    "approvals.configure",
    "approvals.revoke",
    "notifications.read",
    "notifications.replay",
    "notifications.channels.read",
    "notifications.channels.write",
    "notifications.channels.test",
  ],
  auditor: [
    "users.read",
    "devices.read",
    "usage.read",
    "audit.read",
    "alerts.read",
    "approvals.read",
    "notifications.read",
    "notifications.channels.read",
  ],
  security_admin: [
    "devices.read",
    "devices.revoke",
    "credentials.read",
    "credentials.rotate",
    "users.disable",
    "alerts.read",
    "alerts.respond",
    "approvals.read",
    "approvals.decide",
    "breakglass.review",
    "notifications.channels.read",
  ],
  ops_admin: [
    "devices.read",
    "devices.revoke",
    "system.read",
    "approvals.read",
  ],
  super_admin: [
    "users.read",
    "users.invite",
    "users.disable",
    "devices.read",
    "devices.revoke",
    "credentials.read",
    "credentials.rotate",
    "quota.read",
    "quota.write",
    "models.read",
    "models.write",
    "mcp.read",
    "mcp.write",
    "resources.read",
    "resources.write",
    "usage.read",
    "usage.export",
    "audit.read",
    "audit.export",
    "operations.reconcile",
    "alerts.read",
    "alerts.respond",
    "roles.read",
    "system.read",
    "approvals.read",
    "approvals.decide",
    "approvals.configure",
    "approvals.revoke",
    "breakglass.request",
    "breakglass.review",
    "notifications.read",
    "notifications.replay",
    "notifications.channels.read",
    "notifications.channels.write",
    "notifications.channels.test",
  ],
});

export const HIGH_RISK_PERMISSIONS = Object.freeze([
  "audit.content.read",
  "audit.export",
  "usage.export",
  "roles.write",
  "system.write",
]);

export function adminSubjectId(issuer, subject) {
  return `adm_${sha256(`${issuer}|${subject}`).slice(0, 24)}`;
}

function validDate(value) {
  const time = Date.parse(value || "");
  return Number.isFinite(time) ? time : null;
}

export function activeRoleBindings(data, subjectId, now = Date.now()) {
  return Object.values(data.roleBindings).filter((binding) => {
    if (!binding || binding.subjectType !== "admin" || binding.subjectId !== subjectId) return false;
    if (!ROLES[binding.role]) return false;
    const from = validDate(binding.validFrom);
    const to = validDate(binding.validTo);
    if (from == null || to == null || to <= now || from > now) return false;
    if (binding.scopeOrgUnitId !== "*") {
      const org = data.orgUnits[binding.scopeOrgUnitId];
      if (!org || org.status !== "active") return false;
    }
    return true;
  });
}

function permissionsForBinding(binding) {
  const permissions = new Set(ROLES[binding.role] || []);
  for (const permission of binding.extraPermissions || []) {
    if (typeof permission === "string" && permission) permissions.add(permission);
  }
  return permissions;
}

function descendants(data, org) {
  const prefix = `${org.path}/`;
  return Object.values(data.orgUnits)
    .filter((candidate) => candidate.status === "active"
      && (candidate.id === org.id || String(candidate.path || "").startsWith(prefix)))
    .map((candidate) => candidate.id);
}

export function scopeAllows(data, binding, targetOrgUnitId) {
  if (!targetOrgUnitId) return true;
  if (binding.scopeOrgUnitId === "*") return true;
  const scope = data.orgUnits[binding.scopeOrgUnitId];
  if (!scope || scope.status !== "active") return false;
  return descendants(data, scope).includes(targetOrgUnitId);
}

export function authorize(data, subjectId, permission, targetOrgUnitId = "", now = Date.now()) {
  const bindings = activeRoleBindings(data, subjectId, now);
  if (bindings.length === 0) {
    return { allowed: false, reason: "forbidden_role", bindings: [] };
  }
  let hasPermission = false;
  for (const binding of bindings) {
    if (!permissionsForBinding(binding).has(permission)) continue;
    hasPermission = true;
    if (scopeAllows(data, binding, targetOrgUnitId)) {
      return { allowed: true, reason: "", bindings };
    }
  }
  return {
    allowed: false,
    reason: hasPermission ? "forbidden_scope" : "forbidden_role",
    bindings,
  };
}

export function effectiveAccess(data, subjectId, now = Date.now()) {
  const bindings = activeRoleBindings(data, subjectId, now);
  const roles = [...new Set(bindings.map((binding) => binding.role))];
  const permissions = new Set();
  const scopeOrgUnitIds = new Set();
  for (const binding of bindings) {
    for (const permission of permissionsForBinding(binding)) permissions.add(permission);
    if (binding.scopeOrgUnitId === "*") {
      scopeOrgUnitIds.add("*");
      for (const org of Object.values(data.orgUnits)) {
        if (org.status === "active") scopeOrgUnitIds.add(org.id);
      }
    } else {
      const scope = data.orgUnits[binding.scopeOrgUnitId];
      if (scope && scope.status === "active") {
        for (const id of descendants(data, scope)) scopeOrgUnitIds.add(id);
      }
    }
  }
  return {
    roles,
    permissions: [...permissions].sort(),
    scopeOrgUnitIds: [...scopeOrgUnitIds].sort(),
    bindings,
  };
}

export function visibleOrgUnits(data, access) {
  const all = access.scopeOrgUnitIds.includes("*");
  return Object.values(data.orgUnits)
    .filter((org) => org.status === "active" && (all || access.scopeOrgUnitIds.includes(org.id)))
    .sort((left, right) => String(left.path).localeCompare(String(right.path)))
    .map((org) => ({
      id: org.id,
      parentId: org.parentId || "",
      name: org.name,
      path: org.path,
      status: org.status,
    }));
}
