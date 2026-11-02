import crypto from "node:crypto";
import {
  channelMatchesEvent,
  deliveryIdForChannel,
} from "./notification-channels.js";
import {
  NOTIFICATION_EVENT_TYPES,
  NOTIFICATION_RETRY_DELAYS_MS,
  NOTIFICATION_SEVERITIES,
  NOTIFICATION_STATUSES,
  publicNotificationDelivery,
} from "./notification-schema.js";
import { SIEM_CRITICAL_VISIBILITY_TARGET_MS } from "./notification-siem.js";

export {
  NOTIFICATION_EVENT_TYPES,
  NOTIFICATION_RETRY_DELAYS_MS,
  NOTIFICATION_SEVERITIES,
  NOTIFICATION_STATUSES,
  publicNotificationDelivery,
} from "./notification-schema.js";

const DELIVERY_STATUSES = new Set(NOTIFICATION_STATUSES);
const EVENT_TYPES = new Set(NOTIFICATION_EVENT_TYPES);
const SEVERITIES = new Set(NOTIFICATION_SEVERITIES);
const MAX_SUMMARY_LENGTH = 240;
const MAX_FIELD_LENGTH = 320;
const STABLE_ERROR_CODES = new Set([
  "transport_timeout",
  "transport_unavailable",
  "transport_rate_limited",
  "transport_server_error",
  "transport_rejected",
  "transport_invalid_response",
  "transport_error",
  "transport_invalid_url",
  "transport_url_rejected",
  "transport_host_not_allowed",
  "transport_private_address",
  "transport_redirect_rejected",
  "transport_response_too_large",
  "transport_payload_too_large",
  "transport_secret_unavailable",
  "transport_endpoint_unavailable",
  "transport_channel_unavailable",
  "transport_recipient_domain_rejected",
  "delivery_payload_invalid",
  "lease_lost",
  "lease_expired",
  "lease_expired_max_attempts",
]);

function iso(now) {
  const value = now instanceof Date ? now : new Date(now);
  if (!Number.isFinite(value.getTime())) return new Date().toISOString();
  return value.toISOString();
}

function safeText(value, maxLength = MAX_FIELD_LENGTH) {
  return String(value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, maxLength);
}

function safeDate(value, fallback) {
  return Number.isFinite(Date.parse(value || "")) ? String(value) : fallback;
}

function requireSafeEventInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("notification event must be an object");
  }
  const eventId = safeText(input.eventId, 200);
  if (!/^evt_[A-Za-z0-9_.:-]{4,195}$/.test(eventId)) {
    throw new Error("notification eventId is invalid");
  }
  const eventType = safeText(input.eventType, 80);
  if (!EVENT_TYPES.has(eventType)) {
    throw new Error("notification eventType is not allowlisted");
  }
  const severity = safeText(input.severity, 20);
  if (!SEVERITIES.has(severity)) {
    throw new Error("notification severity is invalid");
  }
  const summary = safeText(input.summary, MAX_SUMMARY_LENGTH);
  if (!summary) throw new Error("notification summary is required");
  return {
    eventId,
    schemaVersion: 1,
    eventType,
    severity,
    occurredAt: safeDate(input.occurredAt, new Date().toISOString()),
    organizationId: safeText(input.organizationId),
    actorSubjectId: safeText(input.actorSubjectId),
    actorEmail: safeText(input.actorEmail),
    targetType: safeText(input.targetType, 80),
    targetId: safeText(input.targetId),
    targetOrgUnitId: safeText(input.targetOrgUnitId),
    operationId: safeText(input.operationId),
    requestId: safeText(input.requestId),
    errorCode: safeText(input.errorCode, 80),
    summary,
    dataClassification: "L0",
  };
}

function stableErrorCode(error) {
  const candidate = safeText(error?.code, 80);
  if (STABLE_ERROR_CODES.has(candidate)) return candidate;
  const name = safeText(error?.name, 80);
  if (name === "AbortError" || candidate === "ETIMEDOUT" || candidate === "UND_ERR_CONNECT_TIMEOUT") {
    return "transport_timeout";
  }
  if (candidate === "ECONNREFUSED"
      || candidate === "ENOTFOUND"
      || candidate === "EAI_AGAIN"
      || candidate === "ENETUNREACH") {
    return "transport_unavailable";
  }
  const statusCode = Number(error?.statusCode || error?.status);
  if (statusCode === 408 || statusCode === 504) return "transport_timeout";
  if (statusCode === 429) return "transport_rate_limited";
  if (statusCode >= 500) return "transport_server_error";
  if (statusCode >= 400) return "transport_rejected";
  if (error?.code || error?.name) return "transport_error";
  return "transport_error";
}

function retryDelayMs(attemptCount) {
  const index = Math.max(0, Math.min(
    Number(attemptCount) - 1,
    NOTIFICATION_RETRY_DELAYS_MS.length - 1,
  ));
  return NOTIFICATION_RETRY_DELAYS_MS[index];
}

function clearLease(delivery) {
  delivery.leaseOwner = "";
  delivery.leaseExpiresAt = "";
}

export function notificationTransportEvent(delivery) {
  return publicNotificationDelivery(delivery);
}

export function enqueueNotification(data, input, options = {}) {
  if (!data.notificationDeliveries || typeof data.notificationDeliveries !== "object") {
    throw new Error("notification outbox storage is unavailable");
  }
  const event = requireSafeEventInput(input);
  const channelId = safeText(options.channelId, 80);
  if (channelId && !/^nch_[a-f0-9]{24}$/.test(channelId)) {
    throw new Error("notification channelId is invalid");
  }
  const existing = Object.values(data.notificationDeliveries)
    .find((delivery) => delivery.eventId === event.eventId
      && String(delivery.channelId || "") === channelId);
  if (existing) return { delivery: existing, inserted: false };

  const deliveryId = deliveryIdForChannel(event.eventId, channelId);
  if (data.notificationDeliveries[deliveryId]) {
    throw new Error("notification delivery ID collision");
  }
  const now = event.occurredAt;
  const maxAttempts = Number.isSafeInteger(options.maxAttempts) && options.maxAttempts > 0
    ? options.maxAttempts
    : 6;
  const delivery = {
    deliveryId,
    channelId,
    ...event,
    status: "pending",
    attemptCount: 0,
    maxAttempts,
    nextAttemptAt: now,
    leaseOwner: "",
    leaseExpiresAt: "",
    lastErrorCode: "",
    createdAt: now,
    updatedAt: now,
    deliveredAt: "",
    replayCount: 0,
    lastReplayAt: "",
  };
  data.notificationDeliveries[deliveryId] = delivery;
  return { delivery, inserted: true };
}

export function enqueueNotificationFanout(data, input, channels, options = {}) {
  const matching = (Array.isArray(channels) ? channels : [])
    .filter((channel) => channelMatchesEvent(channel, String(input?.eventType || "")));
  const deliveries = [];
  let insertedCount = 0;
  for (const channel of matching) {
    const result = enqueueNotification(data, input, {
      ...options,
      channelId: channel.channelId,
    });
    deliveries.push(result.delivery);
    if (result.inserted) insertedCount += 1;
  }
  return {
    deliveries,
    insertedCount,
    inserted: insertedCount > 0,
  };
}

function enqueueWithChannels(data, input, options = {}) {
  if (Array.isArray(options.channels)) {
    const { channels, ...channelOptions } = options;
    return enqueueNotificationFanout(data, input, channels, channelOptions);
  }
  return enqueueNotification(data, input, options);
}

export function enqueueApprovalNotification(data, action, approval, options = {}) {
  if (!approval || ![
    "approval.requested",
    "approval.step_progressed",
    "approval.approved",
    "approval.rejected",
    "approval.expired",
    "approval.withdrawn",
    "approval.revoked",
    "approval.transferred",
    "approval.reserved",
    "approval.consumed",
    "approval.recovered_reserved",
  ].includes(action)) {
    return null;
  }
  const severity = ["H", "C"].includes(String(approval.riskLevel || ""))
    ? "critical"
    : "warning";
  const actorSubjectId = action === "approval.requested"
    ? approval.requesterSubjectId
    : options.actorSubjectId || (
      action === "approval.consumed"
        ? "system_operation"
        : action === "approval.expired"
          ? "system_expiry"
          : ""
    );
  const eventKey = String(options.eventKey || "")
    .replace(/[^A-Za-z0-9_-]/g, "")
    .slice(0, 72);
  return enqueueWithChannels(data, {
    eventId: `evt_${action.replaceAll(".", "_")}_${approval.id}${eventKey ? `_${eventKey}` : ""}`,
    eventType: action,
    severity,
    occurredAt: options.occurredAt || approval.updatedAt || new Date().toISOString(),
    organizationId: options.organizationId || approval.environmentId,
    actorSubjectId,
    actorEmail: action === "approval.requested"
      ? approval.requesterEmail
      : options.actorEmail || "",
    targetType: approval.targetType,
    targetId: approval.targetId,
    targetOrgUnitId: approval.targetOrgUnitId,
    operationId: options.operationId || approval.operationId,
    requestId: options.requestId || "",
    errorCode: options.errorCode || "",
    summary: `Approval ${approval.id} ${action.split(".")[1].replaceAll("_", " ")}`
      + ` for ${approval.action}`,
  }, {
    maxAttempts: options.maxAttempts,
    channels: options.channels,
  });
}

export function enqueueOperationNotification(data, operation, options = {}) {
  const state = String(options.state || operation?.responseBody?.result?.state || "");
  let eventType = "";
  if (options.kind === "audit_failed") {
    eventType = "operation.audit_failed";
  } else if (state === "partial_success") {
    eventType = "operation.partial_success";
  } else if (operation?.status === "failed" || options.kind === "failed") {
    eventType = "operation.failed";
  }
  if (!eventType) return null;
  const eventId = `evt_${eventType.replaceAll(".", "_")}_${operation.id}`;
  return enqueueWithChannels(data, {
    eventId,
    eventType,
    severity: eventType === "operation.failed" ? "critical" : "warning",
    occurredAt: options.occurredAt || operation.updatedAt || new Date().toISOString(),
    organizationId: options.organizationId || operation.environmentId || "",
    actorSubjectId: operation.actorSubjectId,
    actorEmail: operation.actorEmail,
    targetType: operation.targetType,
    targetId: operation.targetId,
    targetOrgUnitId: operation.targetOrgUnitId,
    operationId: operation.id,
    requestId: operation.requestId,
    errorCode: operation.errorCode || options.errorCode || "",
    summary: `Operation ${operation.id} ${eventType.split(".")[1].replaceAll("_", " ")}`
      + (operation.errorCode ? ` (${operation.errorCode})` : ""),
  }, {
    maxAttempts: options.maxAttempts,
    channels: options.channels,
  });
}

export function recoverExpiredNotificationLeases(data, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const nowMs = now.getTime();
  let recovered = 0;
  for (const delivery of Object.values(data.notificationDeliveries || {})) {
    if (!["leased", "delivering"].includes(delivery.status)) continue;
    const leaseExpiresAt = Date.parse(delivery.leaseExpiresAt || "");
    if (Number.isFinite(leaseExpiresAt) && leaseExpiresAt > nowMs) continue;
    clearLease(delivery);
    delivery.updatedAt = now.toISOString();
    if (delivery.attemptCount >= delivery.maxAttempts) {
      delivery.status = "dead_letter";
      delivery.nextAttemptAt = "";
      delivery.lastErrorCode = "lease_expired_max_attempts";
    } else {
      delivery.status = "retry_wait";
      delivery.nextAttemptAt = now.toISOString();
      delivery.lastErrorCode = "lease_expired";
    }
    recovered += 1;
  }
  return recovered;
}

export function claimNotificationDelivery(data, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const nowMs = now.getTime();
  const leaseMs = Number.isSafeInteger(options.leaseMs) && options.leaseMs > 0
    ? options.leaseMs
    : 60 * 1000;
  const candidates = Object.values(data.notificationDeliveries || {})
    .filter((delivery) => ["pending", "retry_wait"].includes(delivery.status))
    .filter((delivery) => {
      const next = Date.parse(delivery.nextAttemptAt || "");
      return !Number.isFinite(next) || next <= nowMs;
    })
    .sort((left, right) => {
      const severityOrder = { critical: 0, warning: 1, info: 2 };
      const bySeverity = (severityOrder[left.severity] ?? 3)
        - (severityOrder[right.severity] ?? 3);
      if (bySeverity !== 0) return bySeverity;
      const byDate = String(left.nextAttemptAt || "").localeCompare(String(right.nextAttemptAt || ""));
      if (byDate !== 0) return byDate;
      return String(left.createdAt || "").localeCompare(String(right.createdAt || ""));
    });
  const delivery = candidates[0];
  if (!delivery) return null;
  if (delivery.attemptCount >= delivery.maxAttempts) {
    delivery.status = "dead_letter";
    delivery.nextAttemptAt = "";
    delivery.updatedAt = now.toISOString();
    delivery.lastErrorCode = "lease_expired_max_attempts";
    return null;
  }
  delivery.status = "leased";
  delivery.attemptCount += 1;
  delivery.leaseOwner = safeText(options.ownerId);
  delivery.leaseExpiresAt = new Date(nowMs + leaseMs).toISOString();
  delivery.nextAttemptAt = "";
  delivery.updatedAt = now.toISOString();
  return delivery;
}

export function markNotificationDelivering(data, deliveryId, ownerId, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const leaseMs = Number.isSafeInteger(options.leaseMs) && options.leaseMs > 0
    ? options.leaseMs
    : 60 * 1000;
  const delivery = data.notificationDeliveries?.[deliveryId];
  if (!delivery
      || delivery.status !== "leased"
      || delivery.leaseOwner !== ownerId
      || Date.parse(delivery.leaseExpiresAt || "") <= now.getTime()) {
    return false;
  }
  delivery.status = "delivering";
  delivery.leaseExpiresAt = new Date(now.getTime() + leaseMs).toISOString();
  delivery.updatedAt = now.toISOString();
  return true;
}

export function completeNotificationDelivery(data, deliveryId, ownerId, options = {}) {
  const delivery = data.notificationDeliveries?.[deliveryId];
  if (!delivery
      || !["leased", "delivering"].includes(delivery.status)
      || delivery.leaseOwner !== ownerId) {
    return false;
  }
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  delivery.status = "delivered";
  delivery.nextAttemptAt = "";
  delivery.lastErrorCode = "";
  delivery.deliveredAt = now.toISOString();
  delivery.updatedAt = now.toISOString();
  clearLease(delivery);
  return true;
}

export function failNotificationDelivery(data, deliveryId, ownerId, error, options = {}) {
  const delivery = data.notificationDeliveries?.[deliveryId];
  if (!delivery
      || !["leased", "delivering"].includes(delivery.status)
      || delivery.leaseOwner !== ownerId) {
    return false;
  }
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  delivery.lastErrorCode = stableErrorCode(error);
  delivery.updatedAt = now.toISOString();
  clearLease(delivery);
  if (delivery.attemptCount >= delivery.maxAttempts) {
    delivery.status = "dead_letter";
    delivery.nextAttemptAt = "";
  } else {
    delivery.status = "retry_wait";
    delivery.nextAttemptAt = new Date(now.getTime() + retryDelayMs(delivery.attemptCount)).toISOString();
  }
  return true;
}

export class NotificationDispatcher {
  constructor(store, options = {}) {
    this.store = store;
    this.transport = options.transport;
    this.ownerId = options.ownerId || `ntw_${process.pid}_${crypto.randomUUID()}`;
    this.leaseMs = options.leaseMs || 60 * 1000;
    this.pollIntervalMs = options.pollIntervalMs || 30 * 1000;
    if (this.pollIntervalMs > SIEM_CRITICAL_VISIBILITY_TARGET_MS) {
      throw new Error("notification dispatcher polling must not exceed the 5-minute SIEM target");
    }
    this.batchSize = options.batchSize || 20;
    this.now = options.now || (() => new Date());
    this.timer = null;
    this.active = null;
    this.stopped = false;
  }

  async recoverExpired() {
    return this.store.mutate((data) => (
      recoverExpiredNotificationLeases(data, { now: this.now() })
    ));
  }

  async dispatchOnce() {
    if (!this.transport || this.stopped) return { claimed: 0, delivered: 0, failed: 0 };
    if (this.active) return this.active;
    this.active = this.runOnce().finally(() => {
      this.active = null;
    });
    return this.active;
  }

  async runOnce() {
    await this.recoverExpired();
    const result = { claimed: 0, delivered: 0, failed: 0 };
    for (let index = 0; index < this.batchSize; index += 1) {
      const claimed = await this.store.mutate((data) => {
        const delivery = claimNotificationDelivery(data, {
          now: this.now(),
          ownerId: this.ownerId,
          leaseMs: this.leaseMs,
        });
        return delivery ? structuredClone(delivery) : null;
      });
      if (!claimed) break;
      result.claimed += 1;
      const delivering = await this.store.mutate((data) => markNotificationDelivering(
        data,
        claimed.deliveryId,
        this.ownerId,
        { now: this.now(), leaseMs: this.leaseMs },
      ));
      if (!delivering) continue;
      try {
        const response = await this.transport(notificationTransportEvent(claimed));
        if (response && typeof response === "object"
            && (response.ok === false || Number(response.statusCode) >= 400)) {
          throw Object.assign(new Error("transport rejected the notification"), {
            statusCode: Number(response.statusCode) || 0,
          });
        }
        const completed = await this.store.mutate((data) => completeNotificationDelivery(
          data,
          claimed.deliveryId,
          this.ownerId,
          { now: this.now() },
        ));
        if (completed) result.delivered += 1;
        else result.failed += 1;
      } catch (error) {
        const failed = await this.store.mutate((data) => failNotificationDelivery(
          data,
          claimed.deliveryId,
          this.ownerId,
          error,
          { now: this.now() },
        ));
        if (failed) result.failed += 1;
      }
    }
    return result;
  }

  start() {
    if (!this.transport || this.timer || this.stopped) return;
    this.timer = setInterval(() => {
      this.dispatchOnce().catch(() => {});
    }, this.pollIntervalMs);
    this.timer.unref?.();
    this.dispatchOnce().catch(() => {});
  }

  async stop() {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    if (this.active) await this.active;
  }
}

export class NotificationOutbox {
  constructor(store, options = {}) {
    this.store = store;
    this.maxAttempts = options.maxAttempts || 6;
    this.now = options.now || (() => new Date());
    this.channelProvider = options.channelProvider || null;
  }

  enqueue(data, input) {
    return enqueueNotification(data, input, {
      maxAttempts: this.maxAttempts,
      channels: this.channelProvider ? this.channelProvider(data) : undefined,
    });
  }

  enqueueApproval(data, action, approval, options = {}) {
    return enqueueApprovalNotification(data, action, approval, {
      ...options,
      maxAttempts: this.maxAttempts,
      channels: this.channelProvider ? this.channelProvider(data) : undefined,
    });
  }

  enqueueOperation(data, operation, options = {}) {
    return enqueueOperationNotification(data, operation, {
      ...options,
      maxAttempts: this.maxAttempts,
      channels: this.channelProvider ? this.channelProvider(data) : undefined,
    });
  }

  async recoverExpired() {
    return this.store.mutate((data) => (
      recoverExpiredNotificationLeases(data, { now: this.now() })
    ));
  }
}

export { stableErrorCode };
