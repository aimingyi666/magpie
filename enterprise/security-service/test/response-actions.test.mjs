import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createSecurityServer } from "../src/service.js";

const INGEST_TOKEN = ["security", "response", "ingest", "fixture"].join("-");
const READ_TOKEN = ["security", "response", "read", "fixture"].join("-");
const CONTROL_TOKEN = ["security", "response", "control", "fixture"].join("-");
const IP_HASH = `sha256:${"a".repeat(64)}`;
const UNTRUSTED_IP_HASH = `sha256:${"b".repeat(64)}`;
const FIXED_NOW = Date.parse("2026-11-03T01:05:00.000Z");

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-security-response-"));
}

function config(root, overrides = {}) {
  return {
    bind: "127.0.0.1",
    port: 0,
    ingestToken: INGEST_TOKEN,
    readToken: READ_TOKEN,
    controlToken: CONTROL_TOKEN,
    storePath: path.join(root, "security-store.json"),
    maxBodyBytes: 16 * 1024,
    maxEvents: 1000,
    maxFindings: 2000,
    maxResponseActions: 2000,
    maxStoreBytes: 4 * 1024 * 1024,
    rateLimitPerMinute: 10_000,
    policy: {
      suppressionWindowSeconds: 300,
      usageTokenMultiplier: 5,
      usageCostMultiplier: 5,
      usageMinimumTokens: 100_000,
      usageMinimumCost: 10,
      budgetWarningRatio: 0.9,
      budgetCriticalRatio: 1,
      trustedRegions: ["cn-beijing"],
      trustedSourceIpHashes: [IP_HASH],
      ...(overrides.policy || {}),
    },
    ...overrides,
  };
}

async function start(root, overrides = {}, options = {}) {
  const app = await createSecurityServer(config(root, overrides), {
    logger: () => {},
    ...options,
  });
  await new Promise((resolve, reject) => {
    app.server.once("error", reject);
    app.server.listen(0, "127.0.0.1", resolve);
  });
  return {
    ...app,
    base: `http://127.0.0.1:${app.server.address().port}`,
  };
}

async function request(base, route, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.token !== null) {
    headers.authorization = `Bearer ${options.token ?? READ_TOKEN}`;
  }
  let body;
  if (options.body !== undefined) {
    headers["content-type"] = options.contentType || "application/json";
    body = typeof options.body === "string" ? options.body : JSON.stringify(options.body);
  }
  return fetch(`${base}${route}`, {
    method: options.method || (body === undefined ? "GET" : "POST"),
    headers,
    body,
  });
}

async function controlRequest(base, route, options = {}) {
  const headers = {
    "x-magpie-organization": options.organizationId ?? "org_test",
    ...(options.key ? { "idempotency-key": options.key } : {}),
    ...(options.headers || {}),
  };
  return request(base, route, {
    ...options,
    token: options.token === undefined ? CONTROL_TOKEN : options.token,
    headers,
  });
}

async function responseJson(response) {
  return JSON.parse(await response.text());
}

function timestamp(milliseconds) {
  return new Date(milliseconds).toISOString();
}

function detectionEvent(ruleId, overrides = {}) {
  const suffix = crypto.randomUUID();
  const base = {
    schemaVersion: 1,
    eventId: `devt_response_${suffix}`,
    occurredAt: "2026-11-03T01:00:00.000Z",
    organizationId: "org_test",
    subject: { type: "user", id: "usr_alice" },
    requestId: `req_response_${suffix}`,
    sessionId: `ses_response_${suffix}`,
    ...overrides,
  };
  if (ruleId === "sec.content.sensitive") {
    base.content = { sensitiveCategories: ["email"], matchCount: 1 };
  } else if (ruleId === "sec.device.noncompliant") {
    base.subject = { type: "device", id: "dev_alice_laptop" };
    base.device = {
      complianceState: "noncompliant",
      reasonCodes: ["disk_encryption_disabled"],
    };
  } else if (ruleId === "sec.source.untrusted_ip") {
    base.source = { region: "us-west", ipHash: UNTRUSTED_IP_HASH };
  }
  return base;
}

async function seedFinding(app, ruleId, overrides = {}) {
  const event = detectionEvent(ruleId, overrides);
  const ingest = await request(app.base, "/api/v1/detection-events", {
    token: INGEST_TOKEN,
    body: event,
  });
  assert.equal(ingest.status, 202);
  const findings = await responseJson(await request(
    app.base,
    `/api/v1/findings?ruleId=${encodeURIComponent(ruleId)}`
      + `&organizationId=${encodeURIComponent(event.organizationId)}`,
  ));
  assert.equal(findings.findings.length, 1);
  return findings.findings[0];
}

function actionRequest(finding, overrides = {}) {
  const target = finding.ruleId === "sec.source.untrusted_ip"
    ? { type: "ip_hash", id: finding.evidence.ipHash }
    : { type: finding.subject.type, id: finding.subject.id };
  return {
    actionType: "rate_limit",
    source: { type: "finding", id: finding.findingId },
    organizationId: "org_test",
    target,
    reason: "Contain a verified security finding",
    requestedBySubjectId: "usr_requester",
    durationSeconds: 3600,
    ...overrides,
  };
}

function approvalBody(now, overrides = {}) {
  return {
    actorSubjectId: "usr_approver",
    reason: "Approve containment after review",
    authorization: {
      mode: "approval",
      reference: "apr_response_0001",
      actorSubjectId: "usr_approver",
      incidentId: "",
      stepUpReference: "stepup_response_0001",
      approvedAt: timestamp(now),
      expiresAt: timestamp(now + 600_000),
      ...(overrides.authorization || {}),
    },
    ...overrides,
  };
}

function actorBody(prefix, overrides = {}) {
  return {
    actorSubjectId: "usr_responder",
    reason: `${prefix} the containment action`,
    ...overrides,
  };
}

function uniqueKey(prefix) {
  return `${prefix}-${crypto.randomUUID()}`;
}

async function createAction(app, finding, body = actionRequest(finding), key = uniqueKey("create")) {
  const response = await controlRequest(app.base, "/api/v1/response-actions", {
    method: "POST",
    key,
    body,
  });
  return { response, body: await responseJson(response), key };
}

test("response action completes an auditable simulated lifecycle and replays its original state", async () => {
  const root = tempDirectory();
  let now = FIXED_NOW;
  const app = await start(root, {}, { now: () => now });
  try {
    const finding = await seedFinding(app, "sec.content.sensitive");
    const requestBody = actionRequest(finding);
    const created = await createAction(app, finding, requestBody);
    assert.equal(created.response.status, 201);
    assert.equal(created.body.action.status, "requested");
    assert.equal(created.body.action.enforcement, "none");
    assert.equal(created.body.enforcement, "none");
    assert.equal(created.body.replayed, false);
    assert.equal(created.body.action.revision, 1);

    const actionId = created.body.action.actionId;
    assert.match(actionId, /^sra_[a-f0-9]{24}$/);
    assert.equal("idempotencyKeyHash" in created.body.action, false);
    assert.equal("requestDigest" in created.body.action, false);

    now += 1_000;
    const approved = await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/approve`,
      { key: uniqueKey("approve"), body: approvalBody(now) },
    );
    const approvedBody = await responseJson(approved);
    assert.equal(approved.status, 200);
    assert.equal(approvedBody.action.status, "approved");
    assert.equal(approvedBody.action.revision, 2);

    now += 1_000;
    const activated = await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/activate`,
      { key: uniqueKey("activate"), body: actorBody("Activate") },
    );
    const activatedBody = await responseJson(activated);
    assert.equal(activated.status, 200);
    assert.equal(activatedBody.action.status, "active");
    assert.equal(activatedBody.enforcement, "simulated");
    assert.equal(activatedBody.action.execution.activation.policyApplied, true);
    assert.equal(activatedBody.action.execution.activation.gatewayApplied, false);
    assert.equal(activatedBody.action.execution.activation.adapter, "simulation");
    assert.equal(
      activatedBody.action.execution.activation.resultCode,
      "policy_applied_without_gateway_enforcement",
    );

    now += 1_000;
    const reverted = await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/revert`,
      { key: uniqueKey("revert"), body: actorBody("Revert") },
    );
    const revertedBody = await responseJson(reverted);
    assert.equal(reverted.status, 200);
    assert.equal(revertedBody.action.status, "reverted");
    assert.equal(revertedBody.enforcement, "simulated");
    assert.equal(revertedBody.action.execution.reversion.gatewayApplied, false);
    assert.equal(
      revertedBody.action.execution.reversion.resultCode,
      "policy_reverted_without_gateway_enforcement",
    );

    const audits = await responseJson(await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/audit`,
    ));
    assert.equal(audits.audits.length, 4);
    assert.deepEqual(
      audits.audits.map((audit) => audit.event),
      ["requested", "approved", "activated", "reverted"],
    );
    assert.equal(audits.audits[0].previousHash, "0".repeat(64));
    for (let index = 1; index < audits.audits.length; index += 1) {
      assert.equal(audits.audits[index].previousHash, audits.audits[index - 1].hash);
    }
    assert.equal(JSON.stringify(audits).includes(created.key), false);

    const replay = await controlRequest(app.base, "/api/v1/response-actions", {
      method: "POST",
      key: created.key,
      body: requestBody,
    });
    const replayBody = await responseJson(replay);
    assert.equal(replay.status, 200);
    assert.equal(replayBody.replayed, true);
    assert.equal(replayBody.action.actionId, actionId);
    assert.equal(replayBody.action.status, "requested");
    assert.equal(replayBody.action.revision, 1);
    assert.equal(replayBody.action.authorization, null);
    assert.equal(replayBody.action.execution.activation, null);

    const stored = fs.readFileSync(path.join(root, "security-store.json"), "utf8");
    assert.equal(stored.includes(created.key), false);
    assert.equal(stored.includes(finding.evidence.ipHash || "not-present"), false);
  } finally {
    await app.close();
  }
});

test("self approval, stale authorization and organization mismatches fail closed", async () => {
  const root = tempDirectory();
  let now = FIXED_NOW;
  const app = await start(root, {}, { now: () => now });
  try {
    const finding = await seedFinding(app, "sec.content.sensitive");
    const created = await createAction(app, finding);
    const actionId = created.body.action.actionId;

    now += 1_000;
    const selfApproval = approvalBody(now, {
      actorSubjectId: "usr_requester",
      authorization: {
        mode: "approval",
        reference: "apr_response_self",
        actorSubjectId: "usr_requester",
        incidentId: "",
        stepUpReference: "stepup_response_self",
        approvedAt: timestamp(now),
        expiresAt: timestamp(now + 600_000),
      },
    });
    const selfResponse = await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/approve`,
      { key: uniqueKey("approve-self"), body: selfApproval },
    );
    assert.equal(selfResponse.status, 409);
    assert.equal(
      (await responseJson(selfResponse)).error.code,
      "response_action_self_approval",
    );

    const beforeRequest = approvalBody(now, {
      authorization: {
        mode: "approval",
        reference: "apr_response_before",
        actorSubjectId: "usr_approver",
        incidentId: "",
        stepUpReference: "stepup_response_before",
        approvedAt: timestamp(FIXED_NOW - 1_000),
        expiresAt: timestamp(now + 600_000),
      },
    });
    const beforeResponse = await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/approve`,
      { key: uniqueKey("approve-before"), body: beforeRequest },
    );
    assert.equal(beforeResponse.status, 409);
    assert.equal(
      (await responseJson(beforeResponse)).error.code,
      "response_authorization_before_request",
    );

    const organizationMismatch = actionRequest(finding, { organizationId: "org_other" });
    const mismatchedCreate = await controlRequest(app.base, "/api/v1/response-actions", {
      method: "POST",
      key: uniqueKey("create-org-mismatch"),
      body: organizationMismatch,
    });
    assert.equal(mismatchedCreate.status, 403);
    assert.equal(
      (await responseJson(mismatchedCreate)).error.code,
      "organization_mismatch",
    );

    const crossOrganization = await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}`,
      { organizationId: "org_other" },
    );
    assert.equal(crossOrganization.status, 404);
  } finally {
    await app.close();
  }
});

test("source and target binding reject missing, mismatched and unverifiable targets", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const finding = await seedFinding(app, "sec.content.sensitive");

    const missingSource = actionRequest(finding, {
      source: { type: "finding", id: `sdf_${"0".repeat(24)}` },
    });
    const missing = await controlRequest(app.base, "/api/v1/response-actions", {
      method: "POST",
      key: uniqueKey("create-missing-source"),
      body: missingSource,
    });
    assert.equal(missing.status, 400);
    assert.equal(
      (await responseJson(missing)).error.code,
      "response_action_source_invalid",
    );

    const mismatchedTarget = actionRequest(finding, {
      target: { type: "user", id: "usr_other" },
    });
    const mismatch = await controlRequest(app.base, "/api/v1/response-actions", {
      method: "POST",
      key: uniqueKey("create-target-mismatch"),
      body: mismatchedTarget,
    });
    assert.equal(mismatch.status, 400);
    assert.equal(
      (await responseJson(mismatch)).error.code,
      "response_action_target_mismatch",
    );

    const gatewayKey = actionRequest(finding, {
      actionType: "revoke_key",
      target: { type: "gateway_key", id: "gwk_customer_key" },
    });
    const gateway = await controlRequest(app.base, "/api/v1/response-actions", {
      method: "POST",
      key: uniqueKey("create-gateway-key"),
      body: gatewayKey,
    });
    assert.equal(gateway.status, 400);
    assert.equal(
      (await responseJson(gateway)).error.code,
      "response_action_target_unverifiable",
    );

    const otherOrganizationFinding = await seedFinding(
      app,
      "sec.content.sensitive",
      { organizationId: "org_other" },
    );
    const crossOrganizationSource = actionRequest(otherOrganizationFinding);
    const crossSource = await controlRequest(app.base, "/api/v1/response-actions", {
      method: "POST",
      key: uniqueKey("create-cross-source"),
      body: crossOrganizationSource,
    });
    assert.equal(crossSource.status, 400);
    assert.equal(
      (await responseJson(crossSource)).error.code,
      "response_action_source_invalid",
    );
  } finally {
    await app.close();
  }
});

test("ip_hash targets bind to source-ip evidence and device targets bind to findings", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const ipFinding = await seedFinding(app, "sec.source.untrusted_ip");
    const ipCreated = await createAction(
      app,
      ipFinding,
      actionRequest(ipFinding, { actionType: "block" }),
    );
    assert.equal(ipCreated.response.status, 201);
    assert.deepEqual(ipCreated.body.action.target, {
      type: "ip_hash",
      id: UNTRUSTED_IP_HASH,
    });

    const deviceFinding = await seedFinding(app, "sec.device.noncompliant");
    const deviceCreated = await createAction(
      app,
      deviceFinding,
      actionRequest(deviceFinding, { actionType: "lock_device" }),
    );
    assert.equal(deviceCreated.response.status, 201);
    assert.deepEqual(deviceCreated.body.action.target, {
      type: "device",
      id: "dev_alice_laptop",
    });
  } finally {
    await app.close();
  }
});

test("idempotency conflicts and original result replay are scoped by organization", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const finding = await seedFinding(app, "sec.content.sensitive");
    const key = uniqueKey("idempotency");
    const body = actionRequest(finding);
    const first = await controlRequest(app.base, "/api/v1/response-actions", {
      method: "POST",
      key,
      body,
    });
    assert.equal(first.status, 201);
    const firstBody = await responseJson(first);

    const replay = await controlRequest(app.base, "/api/v1/response-actions", {
      method: "POST",
      key,
      body,
    });
    const replayBody = await responseJson(replay);
    assert.equal(replay.status, 200);
    assert.equal(replayBody.replayed, true);
    assert.deepEqual(replayBody.action, firstBody.action);

    const conflict = await controlRequest(app.base, "/api/v1/response-actions", {
      method: "POST",
      key,
      body: { ...body, reason: "A different containment request" },
    });
    assert.equal(conflict.status, 409);
    assert.equal(
      (await responseJson(conflict)).error.code,
      "response_idempotency_conflict",
    );
  } finally {
    await app.close();
  }
});

test("activation failure is recorded as failed without claiming enforcement", async () => {
  const root = tempDirectory();
  let now = FIXED_NOW;
  const app = await start(root, {}, {
    now: () => now,
    responseExecutor: {
      activate() {
        throw Object.assign(new Error("adapter unavailable"), {
          code: "gateway_adapter_unavailable",
        });
      },
      revert() {
        return {
          policyApplied: true,
          gatewayApplied: false,
          adapter: "simulation",
          resultCode: "policy_reverted_without_gateway_enforcement",
          evidenceRef: "",
        };
      },
    },
  });
  try {
    const finding = await seedFinding(app, "sec.content.sensitive");
    const created = await createAction(app, finding);
    const actionId = created.body.action.actionId;

    now += 1_000;
    assert.equal((await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/approve`,
      { key: uniqueKey("approve"), body: approvalBody(now) },
    )).status, 200);

    now += 1_000;
    const activation = await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/activate`,
      { key: uniqueKey("activate"), body: actorBody("Activate") },
    );
    const activationBody = await responseJson(activation);
    assert.equal(activation.status, 200);
    assert.equal(activationBody.action.status, "failed");
    assert.equal(activationBody.enforcement, "none");
    assert.equal(activationBody.action.execution.activation.state, "failed");
    assert.equal(activationBody.action.execution.activation.policyApplied, false);
    assert.equal(activationBody.action.execution.activation.gatewayApplied, false);
    assert.equal(
      activationBody.action.execution.activation.resultCode,
      "gateway_adapter_unavailable",
    );

    const audits = await responseJson(await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/audit`,
    ));
    assert.deepEqual(
      audits.audits.map((audit) => audit.event),
      ["requested", "approved", "activation_failed"],
    );
  } finally {
    await app.close();
  }
});

test("revert failure leaves the action active and records revert_failed", async () => {
  const root = tempDirectory();
  let now = FIXED_NOW;
  const app = await start(root, {}, {
    now: () => now,
    responseExecutor: {
      activate() {
        return {
          policyApplied: true,
          gatewayApplied: false,
          adapter: "simulation",
          resultCode: "policy_applied_without_gateway_enforcement",
          evidenceRef: "",
        };
      },
      revert() {
        throw new Error("revert adapter unavailable");
      },
    },
  });
  try {
    const finding = await seedFinding(app, "sec.content.sensitive");
    const created = await createAction(app, finding);
    const actionId = created.body.action.actionId;

    now += 1_000;
    assert.equal((await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/approve`,
      { key: uniqueKey("approve"), body: approvalBody(now) },
    )).status, 200);
    now += 1_000;
    assert.equal((await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/activate`,
      { key: uniqueKey("activate"), body: actorBody("Activate") },
    )).status, 200);
    now += 1_000;

    const revert = await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/revert`,
      { key: uniqueKey("revert"), body: actorBody("Revert") },
    );
    const revertBody = await responseJson(revert);
    assert.equal(revert.status, 200);
    assert.equal(revertBody.action.status, "active");
    assert.equal(revertBody.action.execution.reversion, null);
    assert.equal(revertBody.enforcement, "simulated");

    const audits = await responseJson(await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/audit`,
    ));
    assert.equal(audits.audits.at(-1).event, "revert_failed");
    assert.equal(audits.audits.at(-1).status, "active");
  } finally {
    await app.close();
  }
});

test("authorization and pending action expiry are enforced by the clock", async () => {
  const root = tempDirectory();
  let now = FIXED_NOW;
  const app = await start(root, {}, { now: () => now });
  try {
    const finding = await seedFinding(app, "sec.content.sensitive");
    const created = await createAction(
      app,
      finding,
      actionRequest(finding, { durationSeconds: 60 }),
    );
    const actionId = created.body.action.actionId;

    now += 61_000;
    const approval = approvalBody(now);
    const expiredAction = await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/approve`,
      { key: uniqueKey("approve-expired-action"), body: approval },
    );
    assert.equal(expiredAction.status, 409);
    assert.equal(
      (await responseJson(expiredAction)).error.code,
      "response_action_expired",
    );

    const expiredAuthorization = approvalBody(now, {
      authorization: {
        mode: "approval",
        reference: "apr_response_expired_authorization",
        actorSubjectId: "usr_approver",
        incidentId: "",
        stepUpReference: "stepup_response_expired",
        approvedAt: timestamp(now - 1_000),
        expiresAt: timestamp(now),
      },
    });
    const expiredAuth = await controlRequest(
      app.base,
      `/api/v1/response-actions/${actionId}/approve`,
      { key: uniqueKey("approve-expired-authorization"), body: expiredAuthorization },
    );
    assert.equal(expiredAuth.status, 409);
    assert.equal(
      (await responseJson(expiredAuth)).error.code,
      "response_authorization_expired",
    );

    const expirable = await createAction(
      app,
      finding,
      actionRequest(finding, { durationSeconds: 60 }),
      uniqueKey("create-expirable"),
    );
    const expirableId = expirable.body.action.actionId;
    now += 61_000;
    const expired = await controlRequest(
      app.base,
      `/api/v1/response-actions/${expirableId}/expire`,
      { key: uniqueKey("expire"), body: actorBody("Expire") },
    );
    const expiredBody = await responseJson(expired);
    assert.equal(expired.status, 200);
    assert.equal(expiredBody.action.status, "expired");
    assert.equal(expiredBody.enforcement, "none");
  } finally {
    await app.close();
  }
});

test("control, read and ingest tokens are isolated for response actions", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const finding = await seedFinding(app, "sec.content.sensitive");
    const body = actionRequest(finding);
    for (const token of [READ_TOKEN, INGEST_TOKEN]) {
      const response = await controlRequest(app.base, "/api/v1/response-actions", {
        method: "POST",
        key: uniqueKey("wrong-token"),
        body,
        token,
      });
      assert.equal(response.status, 401);
      assert.equal((await responseJson(response)).error.code, "unauthorized");
    }

    const readWithControl = await request(app.base, "/api/v1/findings", {
      token: CONTROL_TOKEN,
    });
    assert.equal(readWithControl.status, 401);

    const missingOrganization = await controlRequest(
      app.base,
      "/api/v1/response-actions",
      {
        method: "POST",
        key: uniqueKey("missing-org"),
        body,
        organizationId: "",
      },
    );
    assert.equal(missingOrganization.status, 400);
    assert.equal(
      (await responseJson(missingOrganization)).error.code,
      "invalid_organization",
    );

    const missingKey = await controlRequest(app.base, "/api/v1/response-actions", {
      method: "POST",
      body,
    });
    assert.equal(missingKey.status, 400);
    assert.equal(
      (await responseJson(missingKey)).error.code,
      "invalid_idempotency_key",
    );
  } finally {
    await app.close();
  }
});

test("response actions and audit chains survive restart", async () => {
  const root = tempDirectory();
  let now = FIXED_NOW;
  const first = await start(root, {}, { now: () => now });
  let actionId;
  try {
    const finding = await seedFinding(first, "sec.content.sensitive");
    const created = await createAction(first, finding);
    actionId = created.body.action.actionId;
    now += 1_000;
    assert.equal((await controlRequest(
      first.base,
      `/api/v1/response-actions/${actionId}/approve`,
      { key: uniqueKey("approve"), body: approvalBody(now) },
    )).status, 200);
  } finally {
    await first.close();
  }

  const second = await start(root, {}, { now: () => now });
  try {
    const action = await responseJson(await controlRequest(
      second.base,
      `/api/v1/response-actions/${actionId}`,
    ));
    assert.equal(action.action.status, "approved");
    const audits = await responseJson(await controlRequest(
      second.base,
      `/api/v1/response-actions/${actionId}/audit`,
    ));
    assert.equal(audits.audits.length, 2);
    const stats = await responseJson(await request(second.base, "/api/v1/stats"));
    assert.equal(stats.responseActionCount, 1);
    assert.equal(stats.responseAuditCount, 2);
    assert.equal(stats.responseIdempotencyCount, 2);
  } finally {
    await second.close();
  }
});

test("tampered audit chains fail closed on restart", async () => {
  const root = tempDirectory();
  const first = await start(root);
  let actionId;
  try {
    const finding = await seedFinding(first, "sec.content.sensitive");
    actionId = (await createAction(first, finding)).body.action.actionId;
  } finally {
    await first.close();
  }

  const storePath = path.join(root, "security-store.json");
  const state = JSON.parse(fs.readFileSync(storePath, "utf8"));
  state.responseAudits[actionId][0].reason = "Tampered containment reason";
  fs.writeFileSync(storePath, JSON.stringify(state));

  await assert.rejects(
    createSecurityServer(config(root), { logger: () => {} }),
    (error) => error.code === "security_store_invalid",
  );
});

test("v1 stores migrate to v2 response collections on startup", async () => {
  const root = tempDirectory();
  const storePath = path.join(root, "security-store.json");
  fs.writeFileSync(storePath, JSON.stringify({
    version: 1,
    events: {},
    findings: {},
    aggregates: {},
    suppressions: {},
    stats: {
      acceptedEvents: 0,
      duplicateEvents: 0,
      findings: 0,
      suppressedFindings: 0,
    },
  }));

  const app = await start(root);
  try {
    const migrated = JSON.parse(fs.readFileSync(storePath, "utf8"));
    assert.equal(migrated.version, 2);
    assert.deepEqual(migrated.responseActions, {});
    assert.deepEqual(migrated.responseAudits, {});
    assert.deepEqual(migrated.responseIdempotency, {});
    const stats = await responseJson(await request(app.base, "/api/v1/stats"));
    assert.equal(stats.responseActionCount, 0);
  } finally {
    await app.close();
  }
});

test("list filtering is organization-scoped and does not expose idempotency material", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const finding = await seedFinding(app, "sec.content.sensitive");
    const created = await createAction(app, finding);
    const actionId = created.body.action.actionId;

    const listed = await responseJson(await controlRequest(
      app.base,
      "/api/v1/response-actions?status=requested&actionType=rate_limit&targetType=user",
    ));
    assert.equal(listed.actions.length, 1);
    assert.equal(listed.actions[0].actionId, actionId);
    assert.equal(JSON.stringify(listed).includes(created.key), false);

    const otherOrganization = await responseJson(await controlRequest(
      app.base,
      "/api/v1/response-actions",
      { organizationId: "org_other" },
    ));
    assert.deepEqual(otherOrganization.actions, []);

    const invalidFilter = await controlRequest(
      app.base,
      "/api/v1/response-actions?status=unknown",
    );
    assert.equal(invalidFilter.status, 400);
  } finally {
    await app.close();
  }
});
