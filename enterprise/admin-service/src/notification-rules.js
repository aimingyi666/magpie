import crypto from "node:crypto";
import { assertNoSecretMaterial, channelMatchesEvent } from "./notification-channels.js";
import {
  NOTIFICATION_EVENT_TYPES,
  NOTIFICATION_SEVERITIES,
  enqueueNotification,
  normalizeNotificationEvent,
  stableErrorCode,
} from "./notification-outbox.js";

const RULE_ID_PATTERN = /^nrul_[a-f0-9]{24}$/;
const AGGREGATE_ID_PATTERN = /^nag_[a-f0-9]{24}$/;
const ESCALATION_ID_PATTERN = /^nes_[a-f0-9]{24}$/;
const SUPPRESSION_ID_PATTERN = /^nsp_[a-f0-9]{24}$/;
const CHANNEL_ID_PATTERN = /^nch_[a-f0-9]{24}$/;
const EVENT_TYPES = new Set(NOTIFICATION_EVENT_TYPES);
const SEVERITIES = new Set(NOTIFICATION_SEVERITIES);
const AGGREGATE_DIMENSIONS = Object.freeze([
  "eventType",
  "severity",
  "targetType",
  "targetId",
  "targetOrgUnitId",
  "organizationId",
  "operationId",
]);
const DIMENSIONS = new Set(AGGREGATE_DIMENSIONS);
const MAX_EVENT_IDS = 50;
const MAX_NAME_LENGTH = 100;
const MAX_ORG_UNIT_LENGTH = 128;

function safeText(value, maxLength = 320) {
  return String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, maxLength);
}

function plainObject(value, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value;
}

function iso(value) {
  const date = value instanceof Date ? value : new Date(value || Date.now());
  return date.toISOString();
}

function digestId(prefix, value) {
  return `${prefix}_${crypto.createHash("sha256").update(value).digest("hex").slice(0, 24)}`;
}

function normalizeStringList(value, allowed, name, options = {}) {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new Error(`${name} must be an array`);
  const result = [...new Set(value.map((item) => safeText(item, 80)).filter(Boolean))].sort();
  if (options.required && result.length === 0) {
    throw new Error(`${name} must be a non-empty array`);
  }
  if (allowed && result.some((item) => !allowed.has(item))) {
    throw new Error(`${name} contains an unsupported value`);
  }
  return result;
}

function normalizeRuleConfig(value) {
  const input = plainObject(value, "notification rule");
  assertNoSecretMaterial(input);
  const name = safeText(input.name, MAX_NAME_LENGTH);
  if (!name) throw new Error("name is required");
  const enabled = input.enabled === undefined ? true : Boolean(input.enabled);
  const priority = Number(input.priority ?? 100);
  if (!Number.isSafeInteger(priority) || priority < 0 || priority > 1000) {
    throw new Error("priority must be an integer from 0 to 1000");
  }
  const channelId = safeText(input.channelId, 80);
  if (!CHANNEL_ID_PATTERN.test(channelId)) {
    throw new Error("channelId is invalid");
  }
  const targetOrgUnitId = safeText(input.targetOrgUnitId, MAX_ORG_UNIT_LENGTH);
  const suppressionWindowSeconds = Number(input.suppressionWindowSeconds || 0);
  if (!Number.isSafeInteger(suppressionWindowSeconds)
      || suppressionWindowSeconds < 0
      || suppressionWindowSeconds > 30 * 24 * 60 * 60) {
    throw new Error("suppressionWindowSeconds must be an integer from 0 to 2592000");
  }
  const aggregation = plainObject(input.aggregation || {}, "aggregation");
  const aggregationEnabled = Boolean(aggregation.enabled);
  const windowSeconds = Number(aggregation.windowSeconds || 300);
  if (!Number.isSafeInteger(windowSeconds) || windowSeconds < 60 || windowSeconds > 7 * 24 * 60 * 60) {
    throw new Error("aggregation.windowSeconds must be an integer from 60 to 604800");
  }
  const dimensions = normalizeStringList(
    aggregation.dimensions == null
      ? ["eventType", "targetType", "targetId", "targetOrgUnitId"]
      : aggregation.dimensions,
    DIMENSIONS,
    "aggregation.dimensions",
    { required: true },
  );
  const escalation = plainObject(input.escalation || {}, "escalation");
  const escalationEnabled = Boolean(escalation.enabled);
  const thresholdCount = Number(escalation.thresholdCount || 0);
  const delaySeconds = Number(escalation.delaySeconds || 0);
  const escalationChannelId = safeText(escalation.channelId, 80);
  if (!Number.isSafeInteger(thresholdCount)
      || thresholdCount < 0
      || thresholdCount > 1000000) {
    throw new Error("escalation.thresholdCount must be an integer from 0 to 1000000");
  }
  if (!Number.isSafeInteger(delaySeconds) || delaySeconds < 0 || delaySeconds > 30 * 24 * 60 * 60) {
    throw new Error("escalation.delaySeconds must be an integer from 0 to 2592000");
  }
  if (escalationEnabled) {
    if (thresholdCount < 1 && delaySeconds < 1) {
      throw new Error("enabled escalation requires thresholdCount or delaySeconds");
    }
    if (!CHANNEL_ID_PATTERN.test(escalationChannelId)) {
      throw new Error("escalation.channelId is invalid");
    }
  } else if (escalationChannelId && !CHANNEL_ID_PATTERN.test(escalationChannelId)) {
    throw new Error("escalation.channelId is invalid");
  }
  return {
    name,
    enabled,
    priority,
    eventTypes: normalizeStringList(input.eventTypes, EVENT_TYPES, "eventTypes"),
    severities: normalizeStringList(input.severities, SEVERITIES, "severities"),
    targetOrgUnitId,
    channelId,
    suppressionWindowSeconds,
    aggregation: {
      enabled: aggregationEnabled,
      dimensions,
      windowSeconds,
    },
    escalation: {
      enabled: escalationEnabled,
      thresholdCount,
      delaySeconds,
      channelId: escalationChannelId,
    },
  };
}

export function createNotificationRule(input, options = {}) {
  const normalized = normalizeRuleConfig(input);
  const now = iso(options.now);
  const ruleId = digestId(
    "nrul",
    `${now}\u0000${crypto.randomUUID()}\u0000${normalized.name}`,
  );
  return {
    ruleId,
    ...normalized,
    createdAt: now,
    updatedAt: now,
    createdBy: safeText(options.actorSubjectId, 100),
    updatedBy: safeText(options.actorSubjectId, 100),
  };
}

export function updateNotificationRule(existing, patch, options = {}) {
  plainObject(existing, "stored notification rule");
  plainObject(patch, "notification rule update");
  assertNoSecretMaterial(patch);
  const merged = {};
  for (const key of [
    "name",
    "enabled",
    "priority",
    "eventTypes",
    "severities",
    "targetOrgUnitId",
    "channelId",
    "suppressionWindowSeconds",
  ]) {
    merged[key] = patch[key] === undefined ? existing[key] : patch[key];
  }
  merged.aggregation = patch.aggregation === undefined
    ? existing.aggregation
    : { ...existing.aggregation, ...plainObject(patch.aggregation, "aggregation") };
  merged.escalation = patch.escalation === undefined
    ? existing.escalation
    : { ...existing.escalation, ...plainObject(patch.escalation, "escalation") };
  const normalized = normalizeRuleConfig(merged);
  return {
    ...existing,
    ...normalized,
    updatedAt: iso(options.now),
    updatedBy: safeText(options.actorSubjectId, 100),
  };
}

export function publicNotificationRule(rule) {
  return {
    ruleId: String(rule?.ruleId || ""),
    name: String(rule?.name || ""),
    enabled: Boolean(rule?.enabled),
    priority: Number.isSafeInteger(rule?.priority) ? rule.priority : 0,
    eventTypes: Array.isArray(rule?.eventTypes) ? rule.eventTypes.map(String) : [],
    severities: Array.isArray(rule?.severities) ? rule.severities.map(String) : [],
    targetOrgUnitId: String(rule?.targetOrgUnitId || ""),
    channelId: String(rule?.channelId || ""),
    suppressionWindowSeconds: Number.isSafeInteger(rule?.suppressionWindowSeconds)
      ? rule.suppressionWindowSeconds
      : 0,
    aggregation: {
      enabled: Boolean(rule?.aggregation?.enabled),
      dimensions: Array.isArray(rule?.aggregation?.dimensions)
        ? rule.aggregation.dimensions.map(String)
        : [],
      windowSeconds: Number.isSafeInteger(rule?.aggregation?.windowSeconds)
        ? rule.aggregation.windowSeconds
        : 0,
    },
    escalation: {
      enabled: Boolean(rule?.escalation?.enabled),
      thresholdCount: Number.isSafeInteger(rule?.escalation?.thresholdCount)
        ? rule.escalation.thresholdCount
        : 0,
      delaySeconds: Number.isSafeInteger(rule?.escalation?.delaySeconds)
        ? rule.escalation.delaySeconds
        : 0,
      channelId: String(rule?.escalation?.channelId || ""),
    },
    createdAt: String(rule?.createdAt || ""),
    updatedAt: String(rule?.updatedAt || ""),
    createdBy: String(rule?.createdBy || ""),
    updatedBy: String(rule?.updatedBy || ""),
  };
}

export function publicNotificationAggregate(aggregate) {
  return {
    aggregateId: String(aggregate?.aggregateId || ""),
    ruleId: String(aggregate?.ruleId || ""),
    key: String(aggregate?.key || ""),
    dimensions: aggregate?.dimensions && typeof aggregate.dimensions === "object"
      ? { ...aggregate.dimensions }
      : {},
    eventType: String(aggregate?.eventType || ""),
    severity: String(aggregate?.severity || ""),
    targetType: String(aggregate?.targetType || ""),
    targetId: String(aggregate?.targetId || ""),
    targetOrgUnitId: String(aggregate?.targetOrgUnitId || ""),
    count: Number.isSafeInteger(aggregate?.count) ? aggregate.count : 0,
    firstEventAt: String(aggregate?.firstEventAt || ""),
    lastEventAt: String(aggregate?.lastEventAt || ""),
    windowEndsAt: String(aggregate?.windowEndsAt || ""),
    status: String(aggregate?.status || ""),
    escalationStatus: String(aggregate?.escalationStatus || ""),
    escalatedAt: String(aggregate?.escalatedAt || ""),
    escalationErrorCode: String(aggregate?.escalationErrorCode || ""),
    createdAt: String(aggregate?.createdAt || ""),
    updatedAt: String(aggregate?.updatedAt || ""),
  };
}

export function publicNotificationSuppression(suppression) {
  return {
    suppressionId: String(suppression?.suppressionId || ""),
    ruleId: String(suppression?.ruleId || ""),
    targetOrgUnitId: String(suppression?.targetOrgUnitId || ""),
    key: String(suppression?.key || ""),
    count: Number.isSafeInteger(suppression?.count) ? suppression.count : 0,
    firstEventAt: String(suppression?.firstEventAt || ""),
    lastEventAt: String(suppression?.lastEventAt || ""),
    windowEndsAt: String(suppression?.windowEndsAt || ""),
    createdAt: String(suppression?.createdAt || ""),
    updatedAt: String(suppression?.updatedAt || ""),
  };
}

export function publicNotificationEscalation(escalation) {
  return {
    escalationId: String(escalation?.escalationId || ""),
    aggregateId: String(escalation?.aggregateId || ""),
    ruleId: String(escalation?.ruleId || ""),
    channelId: String(escalation?.channelId || ""),
    trigger: String(escalation?.trigger || ""),
    status: String(escalation?.status || ""),
    count: Number.isSafeInteger(escalation?.count) ? escalation.count : 0,
    delaySeconds: Number.isSafeInteger(escalation?.delaySeconds)
      ? escalation.delaySeconds
      : 0,
    eventId: String(escalation?.eventId || ""),
    deliveryId: String(escalation?.deliveryId || ""),
    errorCode: String(escalation?.errorCode || ""),
    targetOrgUnitId: String(escalation?.targetOrgUnitId || ""),
    createdAt: String(escalation?.createdAt || ""),
    updatedAt: String(escalation?.updatedAt || ""),
  };
}

function ruleMatches(rule, event) {
  if (!rule?.enabled) return false;
  if (rule.targetOrgUnitId && rule.targetOrgUnitId !== event.targetOrgUnitId) return false;
  if (Array.isArray(rule.eventTypes)
      && rule.eventTypes.length > 0
      && !rule.eventTypes.includes(event.eventType)) {
    return false;
  }
  if (Array.isArray(rule.severities)
      && rule.severities.length > 0
      && !rule.severities.includes(event.severity)) {
    return false;
  }
  return true;
}

export function selectNotificationRule(data, event) {
  return Object.values(data.notificationRules || {})
    .filter((rule) => ruleMatches(rule, event))
    .sort((left, right) => {
      const byPriority = Number(right.priority || 0) - Number(left.priority || 0);
      if (byPriority !== 0) return byPriority;
      const byCreated = String(left.createdAt || "").localeCompare(String(right.createdAt || ""));
      if (byCreated !== 0) return byCreated;
      return String(left.ruleId || "").localeCompare(String(right.ruleId || ""));
    })[0] || null;
}

function protectedEvent(event) {
  return event.severity === "critical" || event.eventType.startsWith("security.");
}

function channelForTarget(channels, channelId, event) {
  return (Array.isArray(channels) ? channels : [])
    .find((channel) => channel.channelId === channelId
      && channelMatchesEvent(channel, event.eventType)) || null;
}

function appendEventId(record, eventId) {
  record.eventIds ||= [];
  if (record.eventIds.includes(eventId)) return false;
  record.eventIds.push(eventId);
  if (record.eventIds.length > MAX_EVENT_IDS) {
    record.eventIds.splice(0, record.eventIds.length - MAX_EVENT_IDS);
  }
  return true;
}

function routeResult(deliveryResult, extra = {}) {
  const deliveries = deliveryResult?.deliveries || (
    deliveryResult?.delivery ? [deliveryResult.delivery] : []
  );
  return {
    deliveries,
    insertedCount: Number(deliveryResult?.insertedCount)
      || (deliveryResult?.inserted ? 1 : 0),
    inserted: Boolean(deliveryResult?.inserted),
    ...extra,
  };
}

function matchingChannel(channels, rule, event) {
  return channelForTarget(channels, rule.channelId, event);
}

function dimensionValues(rule, event) {
  const values = {};
  for (const dimension of rule.aggregation.dimensions) {
    values[dimension] = String(event[dimension] || "");
  }
  return values;
}

function aggregateKey(rule, values) {
  return rule.aggregation.dimensions
    .map((dimension) => `${dimension}=${encodeURIComponent(values[dimension] || "")}`)
    .join("&");
}

function suppressionKey(event) {
  return [
    `eventType=${encodeURIComponent(event.eventType)}`,
    `targetType=${encodeURIComponent(event.targetType)}`,
    `targetId=${encodeURIComponent(event.targetId)}`,
    `targetOrgUnitId=${encodeURIComponent(event.targetOrgUnitId)}`,
  ].join("&");
}

function activeAggregate(data, rule, key, now) {
  const nowMs = now.getTime();
  return Object.values(data.notificationAggregates || {})
    .find((aggregate) => aggregate.ruleId === rule.ruleId
      && aggregate.key === key
      && aggregate.status === "open"
      && Date.parse(aggregate.windowEndsAt) >= nowMs) || null;
}

function activeSuppression(data, rule, key, now) {
  const nowMs = now.getTime();
  return Object.values(data.notificationSuppressions || {})
    .find((suppression) => suppression.ruleId === rule.ruleId
      && suppression.key === key
      && Date.parse(suppression.windowEndsAt) >= nowMs) || null;
}

function createSuppression(data, rule, event, key, now) {
  const suppressionId = digestId(
    "nsp",
    `${rule.ruleId}\u0000${event.targetOrgUnitId}\u0000${key}\u0000${now.toISOString()}`,
  );
  const suppression = {
    suppressionId,
    ruleId: rule.ruleId,
    targetOrgUnitId: event.targetOrgUnitId,
    key,
    count: 1,
    eventIds: [event.eventId],
    firstEventAt: now.toISOString(),
    lastEventAt: now.toISOString(),
    windowEndsAt: new Date(
      now.getTime() + rule.suppressionWindowSeconds * 1000,
    ).toISOString(),
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };
  data.notificationSuppressions[suppressionId] = suppression;
  return suppression;
}

function createAggregate(data, rule, event, key, values, now) {
  const aggregateId = digestId(
    "nag",
    `${rule.ruleId}\u0000${key}\u0000${now.toISOString()}`,
  );
  const aggregate = {
    aggregateId,
    ruleId: rule.ruleId,
    key,
    dimensions: values,
    eventType: event.eventType,
    severity: event.severity,
    targetType: event.targetType,
    targetId: event.targetId,
    targetOrgUnitId: event.targetOrgUnitId,
    organizationId: event.organizationId,
    operationId: event.operationId,
    count: 1,
    eventIds: [event.eventId],
    firstEventAt: now.toISOString(),
    lastEventAt: now.toISOString(),
    windowEndsAt: new Date(
      now.getTime() + rule.aggregation.windowSeconds * 1000,
    ).toISOString(),
    status: "open",
    escalationStatus: rule.escalation.enabled ? "pending" : "not_configured",
    escalatedAt: "",
    escalationDeliveryId: "",
    escalationErrorCode: "",
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };
  data.notificationAggregates[aggregateId] = aggregate;
  return aggregate;
}

function escalationRecord(data, aggregate, rule, trigger, now) {
  const existing = Object.values(data.notificationEscalations || {})
    .find((item) => item.aggregateId === aggregate.aggregateId);
  if (existing) return { escalation: existing, inserted: false };
  const escalationId = digestId(
    "nes",
    `${rule.ruleId}\u0000${aggregate.aggregateId}\u0000${trigger}`,
  );
  const escalation = {
    escalationId,
    aggregateId: aggregate.aggregateId,
    ruleId: rule.ruleId,
    channelId: rule.escalation.channelId,
    trigger,
    status: "pending",
    count: aggregate.count,
    delaySeconds: rule.escalation.delaySeconds,
    eventId: "",
    deliveryId: "",
    errorCode: "",
    targetOrgUnitId: aggregate.targetOrgUnitId,
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };
  data.notificationEscalations[escalationId] = escalation;
  return { escalation, inserted: true };
}

function tryEscalate(data, aggregate, rule, channels, trigger, now, options = {}) {
  if (!rule?.escalation?.enabled || !aggregate) return null;
  const reservation = escalationRecord(data, aggregate, rule, trigger, now);
  if (!reservation.inserted) {
    aggregate.escalationStatus = reservation.escalation.status;
    aggregate.escalatedAt = reservation.escalation.updatedAt;
    aggregate.escalationErrorCode = reservation.escalation.errorCode;
    aggregate.escalationDeliveryId = reservation.escalation.deliveryId;
    return reservation.escalation;
  }
  const escalation = reservation.escalation;
  const channel = channelForTarget(channels, rule.escalation.channelId, {
    eventType: aggregate.eventType,
  });
  if (!channel) {
    escalation.status = "failed";
    escalation.errorCode = "escalation_channel_unavailable";
    escalation.updatedAt = now.toISOString();
    aggregate.escalationStatus = "failed";
    aggregate.escalationErrorCode = escalation.errorCode;
    aggregate.updatedAt = now.toISOString();
    return escalation;
  }
  const eventId = `evt_notification_escalation_${aggregate.aggregateId.slice(4)}`;
  try {
    const result = enqueueNotification(data, {
      eventId,
      eventType: aggregate.eventType,
      severity: "critical",
      occurredAt: now.toISOString(),
      organizationId: aggregate.organizationId,
      actorSubjectId: "system_notification_escalation",
      actorEmail: "",
      targetType: aggregate.targetType,
      targetId: aggregate.targetId,
      targetOrgUnitId: aggregate.targetOrgUnitId,
      operationId: aggregate.operationId,
      requestId: "",
      errorCode: "",
      summary: `Notification escalation for rule ${rule.ruleId}`
        + ` (${aggregate.count} matching events)`,
    }, {
      channelId: channel.channelId,
      maxAttempts: options.maxAttempts,
    });
    escalation.status = "sent";
    escalation.eventId = eventId;
    escalation.deliveryId = result.delivery.deliveryId;
    escalation.updatedAt = now.toISOString();
    aggregate.escalationStatus = "sent";
    aggregate.escalatedAt = escalation.updatedAt;
    aggregate.escalationDeliveryId = escalation.deliveryId;
    aggregate.escalationErrorCode = "";
    aggregate.updatedAt = now.toISOString();
  } catch (error) {
    escalation.status = "failed";
    escalation.errorCode = stableErrorCode(error);
    escalation.updatedAt = now.toISOString();
    aggregate.escalationStatus = "failed";
    aggregate.escalationErrorCode = escalation.errorCode;
    aggregate.updatedAt = now.toISOString();
  }
  return escalation;
}

function thresholdReached(rule, aggregate) {
  return Boolean(rule?.escalation?.enabled)
    && rule.escalation.thresholdCount > 0
    && aggregate.count >= rule.escalation.thresholdCount;
}

function delayedEscalationDue(rule, aggregate, now) {
  return Boolean(rule?.escalation?.enabled)
    && rule.escalation.delaySeconds > 0
    && now.getTime() >= Date.parse(aggregate.firstEventAt)
      + rule.escalation.delaySeconds * 1000;
}

function aggregateAfterDelivery(data, rule, event, key, values, now, delivered) {
  if (!delivered?.inserted) return null;
  const aggregate = createAggregate(data, rule, event, key, values, now);
  return aggregate;
}

export function routeNotification(data, input, options = {}) {
  const event = normalizeNotificationEvent(input);
  const rule = selectNotificationRule(data, event);
  if (!rule) return undefined;
  const channels = Array.isArray(options.channels) ? options.channels : [];
  const targetChannel = matchingChannel(channels, rule, event);
  if (!targetChannel) return undefined;
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const deliveryOptions = {
    channelId: targetChannel.channelId,
    maxAttempts: options.maxAttempts,
  };
  if (protectedEvent(event)) {
    return routeResult(enqueueNotification(data, event, deliveryOptions), {
      ruleId: rule.ruleId,
      protected: true,
      suppressed: false,
      aggregated: false,
      fallback: false,
    });
  }

  if (rule.aggregation.enabled) {
    const values = dimensionValues(rule, event);
    const key = aggregateKey(rule, values);
    const existing = activeAggregate(data, rule, key, now);
    if (existing) {
      if (existing.eventIds.includes(event.eventId)) {
        return routeResult({ deliveries: [], insertedCount: 0, inserted: false }, {
          ruleId: rule.ruleId,
          aggregateId: existing.aggregateId,
          suppressed: false,
          aggregated: true,
          fallback: false,
        });
      }
      const delivery = enqueueNotification(data, event, deliveryOptions);
      if (!delivery.inserted) {
        return routeResult(delivery, {
          ruleId: rule.ruleId,
          aggregateId: existing.aggregateId,
          suppressed: false,
          aggregated: true,
          fallback: false,
        });
      }
      appendEventId(existing, event.eventId);
      existing.count += 1;
      existing.lastEventAt = now.toISOString();
      existing.updatedAt = now.toISOString();
      if (thresholdReached(rule, existing)) {
        tryEscalate(data, existing, rule, channels, "threshold", now, options);
      }
      return routeResult(delivery, {
        ruleId: rule.ruleId,
        aggregateId: existing.aggregateId,
        suppressed: false,
        aggregated: true,
        fallback: false,
      });
    }
    const delivery = enqueueNotification(data, event, deliveryOptions);
    const aggregate = aggregateAfterDelivery(data, rule, event, key, values, now, delivery);
    if (aggregate && thresholdReached(rule, aggregate)) {
      tryEscalate(data, aggregate, rule, channels, "threshold", now, options);
    }
    return routeResult(delivery, {
      ruleId: rule.ruleId,
      aggregateId: aggregate?.aggregateId || "",
      suppressed: false,
      aggregated: Boolean(aggregate),
      fallback: false,
    });
  }

  if (rule.suppressionWindowSeconds > 0) {
    const key = suppressionKey(event);
    const existing = activeSuppression(data, rule, key, now);
    if (existing) {
      if (!appendEventId(existing, event.eventId)) {
        return routeResult({ deliveries: [], insertedCount: 0, inserted: false }, {
          ruleId: rule.ruleId,
          suppressionId: existing.suppressionId,
          suppressed: true,
          aggregated: false,
          fallback: false,
        });
      }
      existing.count += 1;
      existing.lastEventAt = now.toISOString();
      existing.updatedAt = now.toISOString();
      return routeResult({ deliveries: [], insertedCount: 0, inserted: false }, {
        ruleId: rule.ruleId,
        suppressionId: existing.suppressionId,
        suppressed: true,
        aggregated: false,
        fallback: false,
      });
    }
    const delivery = enqueueNotification(data, event, deliveryOptions);
    if (delivery.inserted) createSuppression(data, rule, event, key, now);
    return routeResult(delivery, {
      ruleId: rule.ruleId,
      suppressed: false,
      aggregated: false,
      fallback: false,
    });
  }

  return routeResult(enqueueNotification(data, event, deliveryOptions), {
    ruleId: rule.ruleId,
    suppressed: false,
    aggregated: false,
    fallback: false,
  });
}

export function processNotificationEscalations(data, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const channels = Array.isArray(options.channels) ? options.channels : [];
  let sent = 0;
  let failed = 0;
  for (const aggregate of Object.values(data.notificationAggregates || {})) {
    const rule = data.notificationRules?.[aggregate.ruleId];
    if (!rule?.escalation?.enabled) continue;
    const existing = Object.values(data.notificationEscalations || {})
      .some((escalation) => escalation.aggregateId === aggregate.aggregateId);
    if (existing) continue;
    if (Date.parse(aggregate.windowEndsAt) < now.getTime() && aggregate.status === "open") {
      aggregate.status = "closed";
      aggregate.updatedAt = now.toISOString();
    }
    let trigger = "";
    if (thresholdReached(rule, aggregate)) trigger = "threshold";
    else if (delayedEscalationDue(rule, aggregate, now)) trigger = "time";
    if (!trigger) continue;
    const escalation = tryEscalate(
      data,
      aggregate,
      rule,
      channels,
      trigger,
      now,
      options,
    );
    if (escalation?.status === "sent") sent += 1;
    else if (escalation?.status === "failed") failed += 1;
  }
  return { sent, failed };
}

export class NotificationRuleRouter {
  constructor(options = {}) {
    this.now = options.now || (() => new Date());
    this.maxAttempts = options.maxAttempts;
  }

  route(data, input, options = {}) {
    return routeNotification(data, input, {
      ...options,
      now: this.now(),
      maxAttempts: options.maxAttempts || this.maxAttempts,
    });
  }

  processDue(data, options = {}) {
    return processNotificationEscalations(data, {
      ...options,
      now: this.now(),
      maxAttempts: options.maxAttempts || this.maxAttempts,
    });
  }
}

export class NotificationEscalationScheduler {
  constructor(store, outbox, options = {}) {
    this.store = store;
    this.outbox = outbox;
    this.intervalMs = options.intervalMs || 30 * 1000;
    this.onError = options.onError || (() => {});
    this.timer = null;
    this.active = null;
    this.stopped = false;
    this.lastError = "";
  }

  async runOnce() {
    if (this.stopped) return { sent: 0, failed: 0 };
    try {
      return await this.outbox.processDueEscalations();
    } catch (error) {
      this.lastError = String(error?.message || error);
      this.onError(error);
      throw error;
    }
  }

  start() {
    if (this.timer || this.stopped) return;
    const tick = () => {
      if (this.active) return;
      this.active = this.runOnce()
        .catch(() => {})
        .finally(() => {
          this.active = null;
        });
    };
    this.timer = setInterval(tick, this.intervalMs);
    this.timer.unref?.();
    tick();
  }

  async stop() {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    if (this.active) await this.active;
  }
}

function validateTimestamp(value, name, allowEmpty = false) {
  if (!value && allowEmpty) return;
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw new Error(`admin store ${name} timestamp is invalid`);
  }
}

export function validateNotificationRuleStore(data) {
  for (const [ruleId, rule] of Object.entries(data.notificationRules || {})) {
    if (!RULE_ID_PATTERN.test(ruleId)
        || !rule
        || typeof rule !== "object"
        || Array.isArray(rule)
        || rule.ruleId !== ruleId) {
      throw new Error("admin store notificationRules contains an invalid rule");
    }
    assertNoSecretMaterial(rule, `notificationRules.${ruleId}`);
    let normalized;
    try {
      normalized = normalizeRuleConfig(rule);
    } catch {
      throw new Error("admin store notificationRules contains invalid rule metadata");
    }
    for (const key of ["name", "createdAt", "updatedAt", "createdBy", "updatedBy"]) {
      if (typeof rule[key] !== "string") {
        throw new Error(`admin store notification rule ${key} is invalid`);
      }
    }
    validateTimestamp(rule.createdAt, "notification rule createdAt", true);
    validateTimestamp(rule.updatedAt, "notification rule updatedAt", true);
    if (JSON.stringify(normalized) !== JSON.stringify(normalizeRuleConfig({
      ...rule,
      ...normalized,
    }))) {
      throw new Error("admin store notification rule normalization is unstable");
    }
  }
  for (const [keyHash, request] of Object.entries(data.notificationRuleRequests || {})) {
    if (!/^[a-f0-9]{64}$/.test(keyHash)
        || !request
        || typeof request !== "object"
        || Array.isArray(request)
        || request.idempotencyKeyHash !== keyHash
        || !/^[a-f0-9]{64}$/.test(String(request.requestFingerprint || ""))
        || !["create", "update"].includes(request.action)
        || request.status !== "succeeded"
        || !data.notificationRules[request.ruleId]) {
      throw new Error("admin store notificationRuleRequests contains an invalid request");
    }
    assertNoSecretMaterial(request, `notificationRuleRequests.${keyHash}`);
    validateTimestamp(request.createdAt, "notification rule request createdAt");
    validateTimestamp(request.updatedAt, "notification rule request updatedAt");
  }
  for (const [suppressionId, suppression] of Object.entries(data.notificationSuppressions || {})) {
    if (!SUPPRESSION_ID_PATTERN.test(suppressionId)
        || !suppression
        || typeof suppression !== "object"
        || Array.isArray(suppression)
        || suppression.suppressionId !== suppressionId
        || !data.notificationRules[suppression.ruleId]
        || !Number.isSafeInteger(suppression.count)
        || suppression.count < 1
        || !Array.isArray(suppression.eventIds)
        || suppression.eventIds.length === 0
        || suppression.eventIds.length > MAX_EVENT_IDS
        || suppression.eventIds.some((eventId) => typeof eventId !== "string" || !eventId)) {
      throw new Error("admin store notificationSuppressions contains an invalid suppression");
    }
    assertNoSecretMaterial(suppression, `notificationSuppressions.${suppressionId}`);
    for (const key of ["ruleId", "targetOrgUnitId", "key", "firstEventAt", "lastEventAt", "windowEndsAt", "createdAt", "updatedAt"]) {
      if (typeof suppression[key] !== "string") {
        throw new Error(`admin store notification suppression ${key} is invalid`);
      }
    }
    for (const key of ["firstEventAt", "lastEventAt", "windowEndsAt", "createdAt", "updatedAt"]) {
      validateTimestamp(suppression[key], `notification suppression ${key}`);
    }
    if (Date.parse(suppression.windowEndsAt) <= Date.parse(suppression.firstEventAt)) {
      throw new Error("admin store notification suppression window is invalid");
    }
  }
  for (const [aggregateId, aggregate] of Object.entries(data.notificationAggregates || {})) {
    if (!AGGREGATE_ID_PATTERN.test(aggregateId)
        || !aggregate
        || typeof aggregate !== "object"
        || Array.isArray(aggregate)
        || aggregate.aggregateId !== aggregateId
        || !data.notificationRules[aggregate.ruleId]
        || !Number.isSafeInteger(aggregate.count)
        || aggregate.count < 1
        || !Array.isArray(aggregate.eventIds)
        || aggregate.eventIds.length === 0
        || aggregate.eventIds.length > MAX_EVENT_IDS
        || !["open", "closed"].includes(aggregate.status)
        || !["pending", "sent", "failed", "not_configured"].includes(aggregate.escalationStatus)) {
      throw new Error("admin store notificationAggregates contains an invalid aggregate");
    }
    assertNoSecretMaterial(aggregate, `notificationAggregates.${aggregateId}`);
    if (!aggregate.dimensions
        || typeof aggregate.dimensions !== "object"
        || Array.isArray(aggregate.dimensions)) {
      throw new Error("admin store notification aggregate dimensions are invalid");
    }
    for (const key of [
      "key",
      "eventType",
      "severity",
      "targetType",
      "targetId",
      "targetOrgUnitId",
      "organizationId",
      "operationId",
      "firstEventAt",
      "lastEventAt",
      "windowEndsAt",
      "escalatedAt",
      "escalationDeliveryId",
      "escalationErrorCode",
      "createdAt",
      "updatedAt",
    ]) {
      if (typeof aggregate[key] !== "string") {
        throw new Error(`admin store notification aggregate ${key} is invalid`);
      }
    }
    for (const key of ["firstEventAt", "lastEventAt", "windowEndsAt", "createdAt", "updatedAt"]) {
      validateTimestamp(aggregate[key], `notification aggregate ${key}`);
    }
    if (aggregate.escalatedAt) {
      validateTimestamp(aggregate.escalatedAt, "notification aggregate escalatedAt");
    }
  }
  for (const [escalationId, escalation] of Object.entries(data.notificationEscalations || {})) {
    if (!ESCALATION_ID_PATTERN.test(escalationId)
        || !escalation
        || typeof escalation !== "object"
        || Array.isArray(escalation)
        || escalation.escalationId !== escalationId
        || !data.notificationRules[escalation.ruleId]
        || !data.notificationAggregates[escalation.aggregateId]
        || !["threshold", "time"].includes(escalation.trigger)
        || !["pending", "sent", "failed"].includes(escalation.status)
        || !Number.isSafeInteger(escalation.count)
        || escalation.count < 1) {
      throw new Error("admin store notificationEscalations contains an invalid escalation");
    }
    assertNoSecretMaterial(escalation, `notificationEscalations.${escalationId}`);
    for (const key of [
      "ruleId",
      "channelId",
      "eventId",
      "deliveryId",
      "errorCode",
      "targetOrgUnitId",
      "createdAt",
      "updatedAt",
    ]) {
      if (typeof escalation[key] !== "string") {
        throw new Error(`admin store notification escalation ${key} is invalid`);
      }
    }
    validateTimestamp(escalation.createdAt, "notification escalation createdAt");
    validateTimestamp(escalation.updatedAt, "notification escalation updatedAt");
    if (escalation.status === "sent" && (!escalation.eventId || !escalation.deliveryId)) {
      throw new Error("admin store sent notification escalation is missing delivery metadata");
    }
  }
}

export { AGGREGATE_DIMENSIONS };
