// Who a gateway caller key belongs to.
//
// The gateway knows a caller key, never a person: a content stream needs a
// user, a department and a device, so the control plane resolves them from
// the credential the key was issued as. A key that is unknown, or whose
// credential or user is no longer active, resolves to nothing (or to a
// state that says why) and the capture is dropped — failing closed, never
// guessing a person from a key's name.

const ACTIVE = "active";

function text(value) {
  return typeof value === "string" ? value : "";
}

// activeOrgUnit mirrors the scope rule the rest of the management service
// uses: a user's department counts only while that unit is active.
function activeOrgUnit(userOrgUnits, orgUnits, userId) {
  const orgUnitId = text(userOrgUnits?.[userId]);
  if (!orgUnitId) return "";
  const org = orgUnits?.[orgUnitId];
  return org?.status === ACTIVE ? orgUnitId : "";
}

// resolveContentIdentity answers { state, userId, deviceId, departmentId }
// for a caller key, or null when no credential was issued as that key.
// Nothing secret is returned: no key value, email, token hash or key name.
export function resolveContentIdentity({
  callerKeyId,
  credentials = [],
  users = [],
  userOrgUnits = {},
  orgUnits = {},
} = {}) {
  const key = text(callerKeyId).trim();
  if (!key) return null;
  const credential = credentials.find((entry) => text(entry?.id) === key);
  if (!credential) return null;
  const userId = text(credential.userId);
  const deviceId = text(credential.deviceId);
  if (!userId) return null;
  if (text(credential.status) !== ACTIVE) {
    return { state: "credential_inactive", userId, deviceId, departmentId: "" };
  }
  const user = users.find((entry) => text(entry?.id) === userId);
  if (!user) return { state: "user_unknown", userId, deviceId, departmentId: "" };
  if (text(user.status) !== ACTIVE) {
    return { state: "user_inactive", userId, deviceId, departmentId: "" };
  }
  return {
    state: ACTIVE,
    userId,
    deviceId,
    departmentId: activeOrgUnit(userOrgUnits, orgUnits, userId),
  };
}
