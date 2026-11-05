import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ContentGrantError,
  ContentGrantManager,
} from "../src/content-grant.js";

const SECRET = ["content", "grant", "test", "secret", "0123456789"].join("-");
const CONTENT_REF = `ct_${"a".repeat(43)}`;
const OTHER_CONTENT_REF = `ct_${"b".repeat(43)}`;

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-content-grant-"));
}

function grantPath(root) {
  return path.join(root, "audit-content", "content-grants.json");
}

function expected(overrides = {}) {
  return {
    contentRef: CONTENT_REF,
    adminId: "admin_audit_001",
    organizationId: "org_example",
    sessionId: "session_admin_001",
    ...overrides,
  };
}

function issueContext(overrides = {}) {
  return {
    contentRef: CONTENT_REF,
    adminId: "admin_audit_001",
    organizationId: "org_example",
    sessionId: "session_admin_001",
    purpose: "security_investigation",
    reason: "security case 42",
    approvalId: "apr_security_0042",
    ttlSeconds: 30,
    ...overrides,
  };
}

async function openManager(root, options = {}) {
  const manager = new ContentGrantManager({
    filePath: grantPath(root),
    secret: SECRET,
    defaultTtlSeconds: 60,
    maxTtlSeconds: 300,
    now: options.now || (() => Date.parse("2026-11-02T08:00:00.000Z")),
    ...options,
  });
  await manager.load();
  return manager;
}

function grantError(statusCode, code) {
  return (error) => error instanceof ContentGrantError
    && error.statusCode === statusCode
    && error.code === code;
}

test("grants are bound, consumed once and cannot be replayed after restart", async () => {
  const root = tempDirectory();
  const now = () => Date.parse("2026-11-02T08:00:00.000Z");
  const manager = await openManager(root, { now });
  const issued = await manager.issue(issueContext());

  assert.match(issued.grant, /^mcg1_/);
  assert.equal(issued.issuedAt, "2026-11-02T08:00:00.000Z");
  assert.equal(issued.expiresAt, "2026-11-02T08:00:30.000Z");
  const consumed = await manager.consume(issued.grant, expected());
  assert.equal(consumed.grantId, issued.grantId);
  assert.equal(consumed.approvalId, "apr_security_0042");
  assert.equal(consumed.reason, "security case 42");
  await assert.rejects(
    manager.consume(issued.grant, expected()),
    grantError(409, "content_grant_reused"),
  );
  await manager.close();

  const persisted = fs.readFileSync(grantPath(root), "utf8");
  assert.equal(persisted.includes(SECRET), false);
  assert.equal(persisted.includes(issued.grant), false);
  assert.equal(persisted.includes("admin_audit_001"), false);
  assert.equal(persisted.includes("security case 42"), false);

  const restarted = await openManager(root, { now });
  await assert.rejects(
    restarted.consume(issued.grant, expected()),
    grantError(409, "content_grant_reused"),
  );
  await restarted.close();
});

test("grant signature, target, administrator, organization and session are bound", async () => {
  const manager = await openManager(tempDirectory());
  const issued = await manager.issue(issueContext());
  const tampered = `${issued.grant.slice(0, -1)}${issued.grant.endsWith("A") ? "B" : "A"}`;

  await assert.rejects(
    manager.consume(tampered, expected()),
    grantError(401, "content_grant_invalid"),
  );
  for (const mismatch of [
    expected({ contentRef: OTHER_CONTENT_REF }),
    expected({ adminId: "admin_audit_002" }),
    expected({ organizationId: "org_other" }),
    expected({ sessionId: "session_admin_002" }),
  ]) {
    await assert.rejects(
      manager.consume(issued.grant, mismatch),
      grantError(403, "content_grant_scope_mismatch"),
    );
  }

  const consumed = await manager.consume(issued.grant, expected());
  assert.equal(consumed.contentRef, CONTENT_REF);
  await manager.close();
});

test("grant expiry and TTL bounds fail closed", async () => {
  let now = Date.parse("2026-11-02T08:00:00.000Z");
  const manager = await openManager(tempDirectory(), { now: () => now });

  await assert.rejects(
    manager.issue(issueContext({ ttlSeconds: 14 })),
    grantError(400, "content_grant_ttl_invalid"),
  );
  await assert.rejects(
    manager.issue(issueContext({ ttlSeconds: 301 })),
    grantError(400, "content_grant_ttl_invalid"),
  );
  await assert.rejects(
    manager.issue(issueContext({ reason: "short" })),
    grantError(400, "content_grant_reason_required"),
  );
  await assert.rejects(
    manager.issue(issueContext({ purpose: "curiosity" })),
    grantError(400, "content_grant_purpose_invalid"),
  );

  const issued = await manager.issue(issueContext({ ttlSeconds: 15 }));
  now += 15_000;
  await assert.rejects(
    manager.consume(issued.grant, expected()),
    grantError(401, "content_grant_expired"),
  );
  await manager.close();
});

test("concurrent grant consumption has exactly one winner", async () => {
  const manager = await openManager(tempDirectory());
  const issued = await manager.issue(issueContext());
  const results = await Promise.allSettled([
    manager.consume(issued.grant, expected()),
    manager.consume(issued.grant, expected()),
  ]);

  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  const rejected = results.find((result) => result.status === "rejected");
  assert.equal(rejected.reason.statusCode, 409);
  assert.equal(rejected.reason.code, "content_grant_reused");
  await manager.close();
});

test("grant ledger corruption and unsafe configuration fail startup", async () => {
  assert.throws(
    () => new ContentGrantManager({
      filePath: grantPath(tempDirectory()),
      secret: "too-short",
    }),
    /secret must be at least 32 characters/,
  );

  const root = tempDirectory();
  fs.mkdirSync(path.dirname(grantPath(root)), { recursive: true });
  fs.writeFileSync(grantPath(root), "{not-json", { mode: 0o600 });
  await assert.rejects(
    openManager(root),
    grantError(500, "content_grant_store_corrupt"),
  );
});
