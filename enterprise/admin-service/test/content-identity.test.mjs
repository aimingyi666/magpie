import assert from "node:assert/strict";
import test from "node:test";

import { resolveContentIdentity } from "../src/content-identity.js";

const users = [
  { id: "usr_active", status: "active", email: "a@example.com" },
  { id: "usr_disabled", status: "disabled", email: "d@example.com" },
];
const credentials = [
  { id: "k_active", userId: "usr_active", deviceId: "dev_1", status: "active" },
  { id: "k_revoked", userId: "usr_active", deviceId: "dev_2", status: "revoked" },
  { id: "k_disabled", userId: "usr_disabled", deviceId: "dev_3", status: "active" },
];
const orgUnits = {
  org_eng: { id: "org_eng", status: "active" },
  org_old: { id: "org_old", status: "disabled" },
};
const base = { credentials, users, orgUnits };

test("an active key resolves to its person, device and department", () => {
  const identity = resolveContentIdentity({
    ...base,
    callerKeyId: "k_active",
    userOrgUnits: { usr_active: "org_eng" },
  });
  assert.deepEqual(identity, {
    state: "active",
    userId: "usr_active",
    deviceId: "dev_1",
    departmentId: "org_eng",
  });
});

test("a user mapped to no active unit resolves with no department", () => {
  assert.equal(resolveContentIdentity({
    ...base, callerKeyId: "k_active", userOrgUnits: {},
  }).departmentId, "");
  assert.equal(resolveContentIdentity({
    ...base, callerKeyId: "k_active", userOrgUnits: { usr_active: "org_old" },
  }).departmentId, "");
});

test("a revoked key, a disabled user and an unknown key each fail closed", () => {
  assert.equal(resolveContentIdentity({ ...base, callerKeyId: "k_revoked" }).state,
    "credential_inactive");
  assert.equal(resolveContentIdentity({ ...base, callerKeyId: "k_disabled" }).state,
    "user_inactive");
  assert.equal(resolveContentIdentity({ ...base, callerKeyId: "k_missing" }), null);
  assert.equal(resolveContentIdentity({ ...base, callerKeyId: "" }), null);
});

test("the answer carries no secret, email or key name", () => {
  const identity = resolveContentIdentity({
    ...base,
    callerKeyId: "k_active",
    userOrgUnits: { usr_active: "org_eng" },
  });
  const serialized = JSON.stringify(identity);
  assert.doesNotMatch(serialized, /example\.com/);
  assert.doesNotMatch(serialized, /k_active/);
  assert.doesNotMatch(serialized, /token|hash|email/i);
});
