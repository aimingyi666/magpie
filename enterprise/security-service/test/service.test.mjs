import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { loadConfig } from "../src/config.js";
import { createSecurityServer } from "../src/service.js";

const INGEST_TOKEN = ["security", "ingest", "token", "fixture", "material"].join("-");
const READ_TOKEN = ["security", "read", "token", "fixture", "material"].join("-");
const CONTROL_TOKEN = ["security", "control", "token", "fixture", "material"].join("-");
const IP_HASH = `sha256:${"a".repeat(64)}`;
const OTHER_IP_HASH = `sha256:${"b".repeat(64)}`;
const FIXED_NOW = Date.parse("2026-11-03T01:05:00.000Z");

function tempDirectory() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "magpie-security-service-"));
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

function detectionEvent(overrides = {}) {
  return {
    schemaVersion: 1,
    eventId: "devt_service_event_0001",
    occurredAt: "2026-11-03T01:00:00.000Z",
    organizationId: "org_test",
    subject: { type: "user", id: "usr_alice" },
    requestId: "req_service_request_0001",
    sessionId: "ses_service_session_0001",
    ...overrides,
  };
}

function allRulesEvent(overrides = {}) {
  return detectionEvent({
    connection: { route: "direct_provider", managedAgent: false },
    content: { sensitiveCategories: ["api_key", "email"], matchCount: 2 },
    device: {
      complianceState: "noncompliant",
      reasonCodes: ["disk_encryption_disabled"],
    },
    authorization: {
      decision: "denied",
      dimension: "model",
      policyId: "pol_model_default",
    },
    source: { region: "us-west", ipHash: OTHER_IP_HASH },
    usage: {
      totalTokens: 1_000_000,
      baselineTokens: 1_000,
      cost: 100,
      baselineCost: 1,
      budgetLimit: 100,
      budgetUsed: 150,
    },
    ...overrides,
  });
}

function compliantEvent(overrides = {}) {
  return detectionEvent({
    eventId: "devt_service_event_compliant_0001",
    connection: { route: "enterprise_gateway", managedAgent: true },
    device: { complianceState: "compliant" },
    authorization: {
      decision: "allowed",
      dimension: "model",
      policyId: "pol_model_default",
    },
    source: { region: "cn-beijing", ipHash: IP_HASH },
    usage: {
      totalTokens: 1_000,
      baselineTokens: 1_000,
      cost: 1,
      baselineCost: 1,
      budgetLimit: 100,
      budgetUsed: 1,
    },
    ...overrides,
  });
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

async function responseJson(response) {
  return JSON.parse(await response.text());
}

test("all eight detection rules fire for a fully violating event", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const response = await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: allRulesEvent(),
    });
    const body = await responseJson(response);
    assert.equal(response.status, 202);
    assert.equal(body.accepted, true);
    assert.equal(body.duplicate, false);
    assert.equal(body.findingIds.length, 8);

    const findingsResponse = await request(app.base, "/api/v1/findings?limit=20");
    const findingsBody = await responseJson(findingsResponse);
    assert.equal(findingsResponse.status, 200);
    assert.equal(findingsBody.findings.length, 8);
    assert.deepEqual(
      findingsBody.findings.map((finding) => finding.ruleId).sort(),
      [
        "sec.authorization.scope_violation",
        "sec.client.direct_bypass",
        "sec.content.sensitive",
        "sec.device.noncompliant",
        "sec.source.untrusted_ip",
        "sec.source.untrusted_region",
        "sec.usage.anomaly",
        "sec.usage.budget_threshold",
      ],
    );
    for (const finding of findingsBody.findings) {
      assert.match(finding.findingId, /^sdf_[a-f0-9]{24}$/);
      assert.match(finding.dedupeKey, /^sdk_[a-f0-9]{24}$/);
      assert.match(finding.aggregateId, /^sag_[a-f0-9]{24}$/);
      assert.equal(finding.suppressed, false);
    }
  } finally {
    await app.close();
  }
});

test("compliant traffic does not create findings", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const response = await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: compliantEvent(),
    });
    const body = await responseJson(response);
    assert.equal(response.status, 202);
    assert.deepEqual(body.findingIds, []);
    const stats = await responseJson(await request(app.base, "/api/v1/stats"));
    assert.equal(stats.eventCount, 1);
    assert.equal(stats.findingCount, 0);
  } finally {
    await app.close();
  }
});

test("finding ids and dedupe keys are deterministic across stores", async () => {
  const first = await start(tempDirectory());
  const second = await start(tempDirectory());
  try {
    for (const app of [first, second]) {
      const response = await request(app.base, "/api/v1/detection-events", {
        token: INGEST_TOKEN,
        body: allRulesEvent({ usage: { totalTokens: 1_000_000, baselineTokens: 1_000 } }),
      });
      assert.equal(response.status, 202);
    }
    const firstBody = await responseJson(await request(first.base, "/api/v1/findings?limit=20"));
    const secondBody = await responseJson(await request(second.base, "/api/v1/findings?limit=20"));
    assert.deepEqual(
      firstBody.findings.map(({ findingId, dedupeKey, aggregateId }) => ({
        findingId,
        dedupeKey,
        aggregateId,
      })),
      secondBody.findings.map(({ findingId, dedupeKey, aggregateId }) => ({
        findingId,
        dedupeKey,
        aggregateId,
      })),
    );
  } finally {
    await first.close();
    await second.close();
  }
});

test("suppression marks repeated findings but preserves raw events and aggregates", async () => {
  const root = tempDirectory();
  let now = FIXED_NOW;
  const app = await start(root, {}, { now: () => now });
  try {
    const firstEvent = detectionEvent({
      eventId: "devt_suppression_event_0001",
      occurredAt: "2026-11-03T01:00:00.000Z",
      content: { sensitiveCategories: ["email"], matchCount: 1 },
    });
    const secondEvent = detectionEvent({
      eventId: "devt_suppression_event_0002",
      occurredAt: "2026-11-03T01:01:00.000Z",
      content: { sensitiveCategories: ["email"], matchCount: 2 },
    });
    assert.equal((await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: firstEvent,
    })).status, 202);
    now += 60_000;
    assert.equal((await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: secondEvent,
    })).status, 202);

    const findings = await responseJson(
      await request(app.base, "/api/v1/findings?ruleId=sec.content.sensitive"),
    );
    assert.equal(findings.findings.length, 2);
    assert.equal(findings.findings[0].suppressed, true);
    assert.equal(findings.findings[1].suppressed, false);
    assert.equal(findings.findings[0].dedupeKey, findings.findings[1].dedupeKey);

    const aggregates = await responseJson(
      await request(app.base, "/api/v1/aggregates?ruleId=sec.content.sensitive"),
    );
    assert.equal(aggregates.aggregates.length, 1);
    assert.equal(aggregates.aggregates[0].count, 2);

    const suppressions = await responseJson(
      await request(app.base, "/api/v1/suppressions?activeOnly=true"),
    );
    assert.equal(suppressions.suppressions.length, 1);
    assert.equal(suppressions.suppressions[0].count, 2);

    const stats = await responseJson(await request(app.base, "/api/v1/stats"));
    assert.equal(stats.eventCount, 2);
    assert.equal(stats.findingCount, 2);
    assert.equal(stats.suppressedFindings ?? stats.stats.suppressedFindings, 1);
  } finally {
    await app.close();
  }
});

test("zero suppression window stores every finding without suppressions", async () => {
  const root = tempDirectory();
  let now = FIXED_NOW;
  const app = await start(root, { policy: { suppressionWindowSeconds: 0 } }, {
    now: () => now,
  });
  try {
    for (const [index, eventId] of [
      "devt_no_suppression_0001",
      "devt_no_suppression_0002",
    ].entries()) {
      const response = await request(app.base, "/api/v1/detection-events", {
        token: INGEST_TOKEN,
        body: detectionEvent({
          eventId,
          occurredAt: `2026-11-03T01:0${index}:00.000Z`,
          content: { sensitiveCategories: ["email"] },
        }),
      });
      assert.equal(response.status, 202);
      now += 1_000;
    }
    const findings = await responseJson(
      await request(app.base, "/api/v1/findings?ruleId=sec.content.sensitive"),
    );
    assert.equal(findings.findings.every((finding) => finding.suppressed === false), true);
    const suppressions = await responseJson(await request(app.base, "/api/v1/suppressions"));
    assert.equal(suppressions.suppressions.length, 0);
  } finally {
    await app.close();
  }
});

test("event replay is idempotent and different content conflicts", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const event = allRulesEvent({ usage: { totalTokens: 1_000_000, baselineTokens: 1_000 } });
    const first = await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: event,
    });
    assert.equal(first.status, 202);
    const replay = await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: event,
    });
    const replayBody = await responseJson(replay);
    assert.equal(replay.status, 200);
    assert.equal(replayBody.duplicate, true);
    assert.deepEqual(replayBody.findingIds, []);

    const conflict = await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: allRulesEvent({
        usage: { totalTokens: 2_000_000, baselineTokens: 1_000 },
      }),
    });
    const conflictBody = await responseJson(conflict);
    assert.equal(conflict.status, 409);
    assert.equal(conflictBody.error.code, "detection_event_conflict");

    const stats = await responseJson(await request(app.base, "/api/v1/stats"));
    assert.equal(stats.eventCount, 1);
    assert.equal(stats.stats.duplicateEvents, 1);
    assert.equal(stats.findingCount, 7);
  } finally {
    await app.close();
  }
});

test("the store reloads findings and raw evidence after restart", async () => {
  const root = tempDirectory();
  const first = await start(root);
  const eventId = "devt_restart_event_0001";
  try {
    const response = await request(first.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: detectionEvent({
        eventId,
        content: { sensitiveCategories: ["email"] },
      }),
    });
    assert.equal(response.status, 202);
  } finally {
    await first.close();
  }

  const second = await start(root);
  try {
    const findings = await responseJson(
      await request(second.base, "/api/v1/findings?ruleId=sec.content.sensitive"),
    );
    assert.equal(findings.findings.length, 1);
    assert.equal(findings.findings[0].eventId, eventId);
    const stats = await responseJson(await request(second.base, "/api/v1/stats"));
    assert.equal(stats.eventCount, 1);
    assert.equal(stats.findingCount, 1);
  } finally {
    await second.close();
  }
});

test("a corrupt store fails closed before the server starts", async () => {
  const root = tempDirectory();
  fs.writeFileSync(path.join(root, "security-store.json"), '{"version":1,"events":{}}');
  await assert.rejects(
    createSecurityServer(config(root), { logger: () => {} }),
    (error) => error.code === "security_store_invalid",
  );
});

test("ingest and read tokens are isolated", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const readWithIngest = await request(app.base, "/api/v1/findings", {
      token: INGEST_TOKEN,
    });
    assert.equal(readWithIngest.status, 401);
    assert.equal((await responseJson(readWithIngest)).error.code, "unauthorized");

    const writeWithRead = await request(app.base, "/api/v1/detection-events", {
      token: READ_TOKEN,
      body: compliantEvent(),
    });
    assert.equal(writeWithRead.status, 401);
    assert.equal((await responseJson(writeWithRead)).error.code, "unauthorized");

    const health = await request(app.base, "/healthz", { token: null });
    assert.equal(health.status, 200);
    assert.equal((await responseJson(health)).service, "security-service");
  } finally {
    await app.close();
  }
});

test("HTTP validation uses stable error codes and request ids", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const wrongType = await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      contentType: "text/plain",
      body: "{}",
    });
    const wrongTypeBody = await responseJson(wrongType);
    assert.equal(wrongType.status, 415);
    assert.equal(wrongTypeBody.error.code, "unsupported_media_type");
    assert.match(wrongTypeBody.requestId, /^req_/);
    assert.equal(wrongType.headers.get("x-request-id"), wrongTypeBody.requestId);

    const badJson = await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: "{",
    });
    assert.equal(badJson.status, 400);
    assert.equal((await responseJson(badJson)).error.code, "invalid_json");

    const unknownField = await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: detectionEvent({ prompt: "must never be accepted" }),
    });
    assert.equal(unknownField.status, 400);
    assert.equal((await responseJson(unknownField)).error.code, "invalid_detection_event");

    const invalidQuery = await request(app.base, "/api/v1/findings?severity=low");
    assert.equal(invalidQuery.status, 400);
    assert.equal((await responseJson(invalidQuery)).error.code, "invalid_query");

    const unknownRoute = await request(app.base, "/api/v1/detection-events/raw");
    assert.equal(unknownRoute.status, 404);
    assert.equal((await responseJson(unknownRoute)).error.code, "not_found");
  } finally {
    await app.close();
  }
});

test("secret-bearing and oversized events are rejected without persistence", async () => {
  const root = tempDirectory();
  const app = await start(root, { maxBodyBytes: 1024 });
  try {
    const secret = `sk-${"z".repeat(32)}`;
    const secretResponse = await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: detectionEvent({ subject: { type: "user", id: secret } }),
    });
    assert.equal(secretResponse.status, 400);
    assert.equal((await responseJson(secretResponse)).error.code, "detection_secret_detected");

    const oversized = await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: detectionEvent({ requestId: `req_${"x".repeat(2000)}` }),
    });
    assert.equal(oversized.status, 413);
    assert.equal((await responseJson(oversized)).error.code, "request_too_large");

    const stats = await responseJson(await request(app.base, "/api/v1/stats"));
    assert.equal(stats.eventCount, 0);
    assert.equal(stats.findingCount, 0);
  } finally {
    await app.close();
  }
});

test("rules and stats responses do not expose configured secrets", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    for (const route of ["/api/v1/rules", "/api/v1/stats", "/healthz"]) {
      const text = await (await request(app.base, route, {
        token: route === "/healthz" ? null : READ_TOKEN,
      })).text();
      assert.equal(text.includes(INGEST_TOKEN), false);
      assert.equal(text.includes(READ_TOKEN), false);
    }
  } finally {
    await app.close();
  }
});

test("configuration fails closed for missing, short or shared tokens", () => {
  assert.throws(() => loadConfig({}), /SECURITY_INGEST_TOKEN is required/);
  assert.throws(
    () => loadConfig({
      SECURITY_INGEST_TOKEN: "short",
      SECURITY_READ_TOKEN: READ_TOKEN,
      SECURITY_CONTROL_TOKEN: CONTROL_TOKEN,
    }),
    /SECURITY_INGEST_TOKEN must be at least 32 characters/,
  );
  assert.throws(
    () => loadConfig({
      SECURITY_INGEST_TOKEN: INGEST_TOKEN,
      SECURITY_READ_TOKEN: INGEST_TOKEN,
      SECURITY_CONTROL_TOKEN: CONTROL_TOKEN,
    }),
    /must differ/,
  );
  assert.throws(
    () => loadConfig({
      SECURITY_INGEST_TOKEN: INGEST_TOKEN,
      SECURITY_READ_TOKEN: READ_TOKEN,
    }),
    /SECURITY_CONTROL_TOKEN is required/,
  );
  assert.throws(
    () => loadConfig({
      SECURITY_INGEST_TOKEN: INGEST_TOKEN,
      SECURITY_READ_TOKEN: READ_TOKEN,
      SECURITY_CONTROL_TOKEN: "short",
    }),
    /SECURITY_CONTROL_TOKEN must be at least 32 characters/,
  );
  assert.throws(
    () => loadConfig({
      SECURITY_INGEST_TOKEN: INGEST_TOKEN,
      SECURITY_READ_TOKEN: READ_TOKEN,
      SECURITY_CONTROL_TOKEN: READ_TOKEN,
    }),
    /must differ/,
  );
  const configValue = loadConfig({
    SECURITY_INGEST_TOKEN: INGEST_TOKEN,
    SECURITY_READ_TOKEN: READ_TOKEN,
    SECURITY_CONTROL_TOKEN: CONTROL_TOKEN,
    SECURITY_SUPPRESSION_SECONDS: "0",
    SECURITY_TRUSTED_SOURCE_IP_HASHES: `${IP_HASH},${OTHER_IP_HASH}`,
  });
  assert.equal(configValue.policy.suppressionWindowSeconds, 0);
  assert.equal(configValue.policy.trustedSourceIpHashes.length, 2);
  assert.equal(configValue.controlToken, CONTROL_TOKEN);
  assert.equal(configValue.maxResponseActions, 200_000);
  assert.match(configValue.storePath, /security-store\.json$/);
});

test("duplicate idempotency does not create a second finding id", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    const event = detectionEvent({
      eventId: "devt_duplicate_finding_0001",
      content: { sensitiveCategories: ["email"] },
    });
    const first = await responseJson(await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: event,
    }));
    const second = await responseJson(await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: event,
    }));
    assert.equal(first.findingIds.length, 1);
    assert.deepEqual(second.findingIds, []);
    const findings = await responseJson(await request(app.base, "/api/v1/findings"));
    assert.equal(findings.findings.length, 1);
  } finally {
    await app.close();
  }
});

test("a usage anomaly is measured against the subject's own history", async () => {
  const root = tempDirectory();
  const app = await start(root);
  try {
    for (let i = 0; i < 5; i += 1) {
      const normal = detectionEvent({
        eventId: `devt_baseline_event_${String(i).padStart(4, "0")}`,
        requestId: `req_baseline_request_${i}`,
        sessionId: `ses_baseline_session_${i}`,
        usage: { totalTokens: 2_000 },
      });
      const response = await request(app.base, "/api/v1/detection-events", {
        token: INGEST_TOKEN,
        body: normal,
      });
      assert.equal(response.status, 202);
    }

    const spikeResponse = await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: detectionEvent({
        eventId: "devt_baseline_event_spike",
        requestId: "req_baseline_spike",
        sessionId: "ses_baseline_spike",
        usage: { totalTokens: 1_000_000 },
      }),
    });
    assert.equal(spikeResponse.status, 202);

    const findingsResponse = await request(app.base, "/api/v1/findings?limit=50");
    const findingsBody = await responseJson(findingsResponse);
    const anomalies = findingsBody.findings.filter(
      (finding) => finding.ruleId === "sec.usage.anomaly",
    );
    assert.equal(anomalies.length, 1);
    assert.equal(anomalies[0].evidence.baselineTokens, 2_000);
    assert.equal(anomalies[0].evidence.totalTokens, 1_000_000);
  } finally {
    await app.close();
  }
});

test("an event dated in the future is refused before it can wedge the store", async () => {
  const root = tempDirectory();
  const app = await start(root, {}, { now: () => FIXED_NOW });
  try {
    const response = await request(app.base, "/api/v1/detection-events", {
      token: INGEST_TOKEN,
      body: detectionEvent({
        occurredAt: new Date(FIXED_NOW + 5 * 60 * 1000).toISOString(),
        usage: { totalTokens: 10 },
      }),
    });
    const body = await responseJson(response);
    assert.equal(response.status, 400, JSON.stringify(body));
    assert.equal(body.error.code, "event_in_future", JSON.stringify(body));
  } finally {
    await app.close();
  }
});
