export const NOTIFICATION_EVENT_TYPES = Object.freeze([
  "approval.requested",
  "approval.approved",
  "approval.rejected",
  "approval.expired",
  "approval.consumed",
  "operation.failed",
  "operation.partial_success",
  "operation.audit_failed",
  "security.access_denied",
  "security.auth_failed",
  "security.break_glass_used",
  "security.anomaly_detected",
]);

export const NOTIFICATION_STATUSES = Object.freeze([
  "pending",
  "leased",
  "delivering",
  "delivered",
  "retry_wait",
  "dead_letter",
]);

export const NOTIFICATION_SEVERITIES = Object.freeze(["info", "warning", "critical"]);

export const NOTIFICATION_RETRY_DELAYS_MS = Object.freeze([
  60 * 1000,
  5 * 60 * 1000,
  15 * 60 * 1000,
  60 * 60 * 1000,
  6 * 60 * 60 * 1000,
]);

export function publicNotificationDelivery(delivery) {
  return {
    deliveryId: String(delivery?.deliveryId || ""),
    eventId: String(delivery?.eventId || ""),
    channelId: String(delivery?.channelId || ""),
    eventType: String(delivery?.eventType || ""),
    severity: String(delivery?.severity || ""),
    occurredAt: String(delivery?.occurredAt || ""),
    organizationId: String(delivery?.organizationId || ""),
    targetType: String(delivery?.targetType || ""),
    targetId: String(delivery?.targetId || ""),
    targetOrgUnitId: String(delivery?.targetOrgUnitId || ""),
    operationId: String(delivery?.operationId || ""),
    requestId: String(delivery?.requestId || ""),
    errorCode: String(delivery?.errorCode || ""),
    status: String(delivery?.status || ""),
    attemptCount: Number.isSafeInteger(delivery?.attemptCount) ? delivery.attemptCount : 0,
    nextAttemptAt: String(delivery?.nextAttemptAt || ""),
    leaseExpiresAt: String(delivery?.leaseExpiresAt || ""),
    lastErrorCode: String(delivery?.lastErrorCode || ""),
    summary: String(delivery?.summary || ""),
    createdAt: String(delivery?.createdAt || ""),
    updatedAt: String(delivery?.updatedAt || ""),
    deliveredAt: String(delivery?.deliveredAt || ""),
  };
}
