import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  NotificationRuleRouter,
  createNotificationRule,
  processNotificationEscalations,
  publicNotificationRule,
  routeNotification,
  selectNotificationRule,
  validateNotificationRuleStore,
} from "../src/notification-rules.js";
import { NotificationOutbox } from "../src/notification-outbox.js";

const CHANNEL_A = `nch_${"a".repeat(24)}`;
const CHANNEL_B = `nch_${"b".repeat(24)}`;
const CHANNEL_ESC = `nch_${"c".repeat(24)}`;

function channel(channelId, eventTypes = ["approval.requested", "operation.failed"]) {
  return {
    channelId,
    enabled: true,
    type: "webhook",
    provider: "generic",
    eventTypes,
  };
}

function data(channels = [channel(CHANNEL_A), channel(CHANNEL_B), channel(CHANNEL_ESC)]) {
  return {
    notificationDeliveries: {},
    notificationRules: {},
    notificationRuleRequests: {},
    notificationSuppressions: {},
    notificationAggregates: {},
    notificationEscalations: {},
    notificationChannels: Object.fromEntries(channels.map((item) => [item.channelId, item])),
  };
}

function rule(overrides = {}) {
  return createNotificationRule({
    name: "Approval routing",
    enabled: true,
    priority: 100,
    eventTypes: ["approval.requested"],
    severities: [],
    channelId: CHANNEL_A,
    suppressionWindowSeconds: 0,
    aggregation: { enabled: false },
    escalation: { enabled: false },
    ...overrides,
  }, {
    now: "2026-11-02T00:00:00.000Z",
    actorSubjectId: "adm_test",
  });
}

function event(overrides = {}) {
  return {
    eventId: `evt_rule_${crypto.randomUUID()}`,
    eventType: "approval.requested",
    severity: "warning",
    occurredAt: "2026-11-02T00:00:00.000Z",
    organizationId: "env_test",
    actorSubjectId: "usr_requester",
    actorEmail: "requester@corp.example",
    targetType: "user",
    targetId: "usr_alice",
    targetOrgUnitId: "org_platform",
    operationId: "op_test",
    requestId: "req_test",
    errorCode: "",
    summary: "Approval needs review",
    ...overrides,
  };
}

test("NOTIFY-01d selects the highest-priority rule with exact organization scope", () => {
  const state = data();
  const global = rule({ priority: 10, channelId: CHANNEL_B });
  const scoped = rule({
    priority: 20,
    targetOrgUnitId: "org_platform",
    channelId: CHANNEL_A,
  });
  state.notificationRules[global.ruleId] = global;
  state.notificationRules[scoped.ruleId] = scoped;

  assert.equal(selectNotificationRule(state, event())?.ruleId, scoped.ruleId);
  assert.equal(selectNotificationRule(
    state,
    event({ targetOrgUnitId: "org_sales" }),
  )?.ruleId, global.ruleId);
  assert.deepEqual(publicNotificationRule(scoped).eventTypes, ["approval.requested"]);
});

test("NOTIFY-01d suppression deduplicates matching events inside the configured window", () => {
  const state = data();
  const configured = rule({ suppressionWindowSeconds: 300 });
  state.notificationRules[configured.ruleId] = configured;
  const first = routeNotification(state, event(), {
    channels: Object.values(state.notificationChannels),
    now: new Date("2026-11-02T00:00:00.000Z"),
  });
  const second = routeNotification(state, event(), {
    channels: Object.values(state.notificationChannels),
    now: new Date("2026-11-02T00:01:00.000Z"),
  });

  assert.equal(first.insertedCount, 1);
  assert.equal(second.insertedCount, 0);
  assert.equal(second.suppressed, true);
  const suppression = Object.values(state.notificationSuppressions)[0];
  assert.equal(suppression.count, 2);
  assert.equal(suppression.eventIds.length, 2);
});

test("NOTIFY-01d critical and security events cannot be suppressed or aggregated", () => {
  for (const protectedEvent of [
    event({ severity: "critical" }),
    event({
      eventType: "security.break_glass_used",
      severity: "warning",
      summary: "Emergency access was used",
    }),
  ]) {
    const state = data([
      channel(CHANNEL_A, [protectedEvent.eventType]),
      channel(CHANNEL_B, [protectedEvent.eventType]),
      channel(CHANNEL_ESC, [protectedEvent.eventType]),
    ]);
    const configured = rule({
      eventTypes: [protectedEvent.eventType],
      suppressionWindowSeconds: 300,
      aggregation: { enabled: true, windowSeconds: 300 },
    });
    state.notificationRules[configured.ruleId] = configured;
    const first = routeNotification(state, protectedEvent, {
      channels: Object.values(state.notificationChannels),
    });
    const second = routeNotification(state, {
      ...protectedEvent,
      eventId: `evt_rule_${crypto.randomUUID()}`,
    }, {
      channels: Object.values(state.notificationChannels),
    });

    assert.equal(first.protected, true);
    assert.equal(second.protected, true);
    assert.equal(first.insertedCount, 1);
    assert.equal(second.insertedCount, 1);
    assert.equal(Object.keys(state.notificationSuppressions).length, 0);
    assert.equal(Object.keys(state.notificationAggregates).length, 0);
  }
});

test("NOTIFY-01d aggregation is atomic and ignores repeated event IDs", () => {
  const state = data();
  const configured = rule({
    aggregation: {
      enabled: true,
      windowSeconds: 300,
      dimensions: ["eventType", "targetOrgUnitId", "targetId"],
    },
  });
  state.notificationRules[configured.ruleId] = configured;
  const firstEvent = event();
  const secondEvent = event();
  const first = routeNotification(state, firstEvent, {
    channels: Object.values(state.notificationChannels),
    now: new Date("2026-11-02T00:00:00.000Z"),
  });
  const second = routeNotification(state, secondEvent, {
    channels: Object.values(state.notificationChannels),
    now: new Date("2026-11-02T00:01:00.000Z"),
  });
  const duplicate = routeNotification(state, secondEvent, {
    channels: Object.values(state.notificationChannels),
    now: new Date("2026-11-02T00:02:00.000Z"),
  });

  const aggregate = state.notificationAggregates[first.aggregateId];
  assert.equal(first.aggregateId, second.aggregateId);
  assert.equal(aggregate.count, 2);
  assert.equal(duplicate.insertedCount, 0);
  assert.equal(aggregate.count, 2);
  assert.equal(Object.keys(state.notificationAggregates).length, 1);
});

test("NOTIFY-01d escalates once per aggregate by threshold or elapsed time", () => {
  const state = data();
  const configured = rule({
    aggregation: { enabled: true, windowSeconds: 600 },
    escalation: {
      enabled: true,
      thresholdCount: 2,
      delaySeconds: 0,
      channelId: CHANNEL_ESC,
    },
  });
  state.notificationRules[configured.ruleId] = configured;
  routeNotification(state, event(), {
    channels: Object.values(state.notificationChannels),
    now: new Date("2026-11-02T00:00:00.000Z"),
  });
  routeNotification(state, event(), {
    channels: Object.values(state.notificationChannels),
    now: new Date("2026-11-02T00:01:00.000Z"),
  });
  routeNotification(state, event(), {
    channels: Object.values(state.notificationChannels),
    now: new Date("2026-11-02T00:02:00.000Z"),
  });

  const escalations = Object.values(state.notificationEscalations);
  assert.equal(escalations.length, 1);
  assert.equal(escalations[0].trigger, "threshold");
  assert.equal(escalations[0].status, "sent");

  const delayed = data();
  const delayedRule = rule({
    aggregation: { enabled: true, windowSeconds: 600 },
    escalation: {
      enabled: true,
      thresholdCount: 0,
      delaySeconds: 120,
      channelId: CHANNEL_ESC,
    },
  });
  delayed.notificationRules[delayedRule.ruleId] = delayedRule;
  routeNotification(delayed, event(), {
    channels: Object.values(delayed.notificationChannels),
    now: new Date("2026-11-02T00:00:00.000Z"),
  });
  const result = processNotificationEscalations(delayed, {
    channels: Object.values(delayed.notificationChannels),
    now: new Date("2026-11-02T00:02:01.000Z"),
  });
  assert.deepEqual(result, { sent: 1, failed: 0 });
});

test("NOTIFY-01d unavailable rule channels fall back to the original fanout", () => {
  const state = data([channel(CHANNEL_B), channel(CHANNEL_ESC)]);
  const configured = rule({ channelId: CHANNEL_A });
  state.notificationRules[configured.ruleId] = configured;
  const router = new NotificationRuleRouter();
  const outbox = new NotificationOutbox({}, {
    router,
    channelProvider: () => Object.values(state.notificationChannels),
  });
  const result = outbox.enqueue(state, event());

  assert.equal(result.insertedCount, 2);
  assert.deepEqual(
    result.deliveries.map((delivery) => delivery.channelId).sort(),
    [CHANNEL_B, CHANNEL_ESC].sort(),
  );
});

test("NOTIFY-01d rejects secret material and validates persisted references", () => {
  assert.throws(() => rule({
    aggregation: {
      enabled: true,
      token: "plaintext-secret",
    },
  }), /secret reference/);

  const state = data();
  const configured = rule();
  state.notificationRules[configured.ruleId] = configured;
  validateNotificationRuleStore(state);
  state.notificationRules[configured.ruleId].channelId = "not-a-channel";
  assert.throws(() => validateNotificationRuleStore(state), /invalid rule metadata/);
});
