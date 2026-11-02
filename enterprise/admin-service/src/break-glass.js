import {
  approvalBindingDigest,
  approvalPayloadDigest,
  normalizedApprovalPayload,
} from "./approval.js";

export const BREAK_GLASS_GRANT_TTL_MS = 15 * 60 * 1000;
export const BREAK_GLASS_REVIEW_DUE_MS = 24 * 60 * 60 * 1000;
export const BREAK_GLASS_POLICY_VERSION = "APR-01e-v1";

export const BREAK_GLASS_STATUSES = Object.freeze([
  "active",
  "expired",
  "consumed",
  "review_overdue",
  "reviewed",
]);

export const BREAK_GLASS_REVIEW_CONCLUSIONS = Object.freeze([
  "justified",
  "not_justified",
]);

function timestamp(value) {
  const parsed = Date.parse(String(value || ""));
  return Number.isFinite(parsed) ? parsed : null;
}

export function breakGlassExpectedBinding(input) {
  const payloadDigest = approvalPayloadDigest(input.action, input.payload);
  const bindingDigest = approvalBindingDigest({
    environmentId: input.environmentId,
    policyVersion: input.policyVersion,
    requesterSubjectId: input.requesterSubjectId,
    action: input.action,
    targetType: input.targetType,
    targetId: input.targetId,
    targetOrgUnitId: input.targetOrgUnitId,
    riskLevel: input.riskLevel,
    reason: input.reason,
    payloadDigest,
  });
  return {
    environmentId: String(input.environmentId || ""),
    policyVersion: String(input.policyVersion || ""),
    requesterSubjectId: String(input.requesterSubjectId || ""),
    action: String(input.action || ""),
    targetType: String(input.targetType || ""),
    targetId: String(input.targetId || ""),
    targetOrgUnitId: String(input.targetOrgUnitId || ""),
    riskLevel: String(input.riskLevel || ""),
    reason: String(input.reason || ""),
    payload: normalizedApprovalPayload(input.action, input.payload),
    payloadDigest,
    bindingDigest,
  };
}

export function breakGlassConsumptionFailure(grant, expected, now = Date.now()) {
  if (!grant) return "break_glass_invalid";
  if (grant.environmentId !== expected.environmentId
      || grant.policyVersion !== expected.policyVersion
      || grant.requesterSubjectId !== expected.requesterSubjectId
      || grant.action !== expected.action
      || grant.targetType !== expected.targetType
      || grant.targetId !== expected.targetId
      || grant.targetOrgUnitId !== expected.targetOrgUnitId
      || grant.riskLevel !== expected.riskLevel
      || grant.reason !== expected.reason) {
    return "break_glass_target_mismatch";
  }
  if (grant.payloadDigest !== expected.payloadDigest
      || grant.bindingDigest !== expected.bindingDigest) {
    return "break_glass_payload_mismatch";
  }
  if (grant.consumedAt) return "break_glass_consumed";
  const expiresAt = timestamp(grant.expiresAt);
  if (expiresAt == null || expiresAt <= now) return "break_glass_expired";
  return "";
}

export function breakGlassReviewDueAt(consumedAt) {
  const parsed = timestamp(consumedAt);
  return parsed == null ? "" : new Date(parsed + BREAK_GLASS_REVIEW_DUE_MS).toISOString();
}

export function projectedBreakGlassStatus(grant, review = null, now = Date.now()) {
  if (review?.conclusion) return "reviewed";
  const consumedAt = timestamp(grant?.consumedAt);
  if (consumedAt != null) {
    const dueAt = timestamp(grant?.reviewDueAt);
    // An invalid due timestamp must not silently turn a used grant into a clean state.
    if (dueAt == null || now >= dueAt) return "review_overdue";
    return "consumed";
  }
  const expiresAt = timestamp(grant?.expiresAt);
  if (expiresAt == null || now >= expiresAt) return "expired";
  return "active";
}

export function publicBreakGlassGrant(grant, review = null, now = Date.now()) {
  const status = projectedBreakGlassStatus(grant, review, now);
  return {
    breakGlassId: String(grant?.id || ""),
    status,
    requesterSubjectId: String(grant?.requesterSubjectId || ""),
    requesterEmail: String(grant?.requesterEmail || ""),
    action: String(grant?.action || ""),
    targetType: String(grant?.targetType || ""),
    targetId: String(grant?.targetId || ""),
    targetOrgUnitId: String(grant?.targetOrgUnitId || ""),
    riskLevel: String(grant?.riskLevel || ""),
    payloadDigest: String(grant?.payloadDigest || ""),
    bindingDigest: String(grant?.bindingDigest || ""),
    environmentId: String(grant?.environmentId || ""),
    policyVersion: String(grant?.policyVersion || ""),
    incidentId: String(grant?.incidentId || ""),
    reason: String(grant?.reason || ""),
    createdAt: String(grant?.createdAt || ""),
    updatedAt: String(grant?.updatedAt || ""),
    expiresAt: String(grant?.expiresAt || ""),
    consumedAt: String(grant?.consumedAt || ""),
    consumedBySubjectId: String(grant?.consumedBySubjectId || ""),
    operationId: String(grant?.operationId || ""),
    reviewDueAt: String(grant?.reviewDueAt || ""),
    reviewOverdueAt: String(grant?.reviewOverdueAt || ""),
    reviewedAt: String(grant?.reviewedAt || ""),
    notificationEventIds: {
      used: String(grant?.notificationEventIds?.used || ""),
      reviewDue: String(grant?.notificationEventIds?.reviewDue || ""),
      reviewOverdue: String(grant?.notificationEventIds?.reviewOverdue || ""),
      reviewed: String(grant?.notificationEventIds?.reviewed || ""),
    },
    review: review
      ? {
        reviewId: String(review.id || ""),
        conclusion: String(review.conclusion || ""),
        reviewerSubjectId: String(review.reviewerSubjectId || ""),
        reviewerEmail: String(review.reviewerEmail || ""),
        reason: String(review.reason || ""),
        reviewedAt: String(review.reviewedAt || ""),
        notificationEventId: String(review.notificationEventId || ""),
      }
      : null,
  };
}

export function enqueueBreakGlassReviewReminders(data, outbox, options = {}) {
  const now = Number.isFinite(Number(options.now)) ? Number(options.now) : Date.now();
  const result = { due: 0, overdue: 0 };
  for (const grant of Object.values(data.breakGlassGrants || {})) {
    const review = Object.values(data.breakGlassReviews || {})
      .find((candidate) => candidate.grantId === grant.id);
    if (review || !grant.consumedAt) continue;
    const dueAt = timestamp(grant.reviewDueAt);
    if (dueAt == null) {
      throw new Error(`Break-glass grant ${grant.id} has an invalid review due time`);
    }
    grant.notificationEventIds ||= {};
    const reminderAt = dueAt - 60 * 60 * 1000;
    if (now >= reminderAt
        && now < dueAt
        && !grant.notificationEventIds.reviewDue) {
      const occurredAt = new Date(now).toISOString();
      outbox.enqueueBreakGlass(data, "review_due", grant, { occurredAt });
      grant.updatedAt = occurredAt;
      result.due += 1;
    }
    if (now >= dueAt && !grant.notificationEventIds.reviewOverdue) {
      outbox.enqueueBreakGlass(data, "review_overdue", grant, {
        occurredAt: new Date(now).toISOString(),
      });
      grant.reviewOverdueAt = new Date(now).toISOString();
      grant.updatedAt = grant.reviewOverdueAt;
      grant.stateHistory.push({
        status: "review_overdue",
        at: grant.reviewOverdueAt,
        actorSubjectId: "system_scheduler",
        reason: "post-incident review overdue",
      });
      result.overdue += 1;
    }
  }
  return result;
}

export class BreakGlassReviewScheduler {
  constructor(store, outbox, options = {}) {
    this.store = store;
    this.outbox = outbox;
    this.now = options.now || (() => Date.now());
    this.intervalMs = options.intervalMs || 60 * 1000;
    this.onError = options.onError || (() => {});
    this.timer = null;
    this.active = null;
    this.stopped = false;
    this.lastError = "";
  }

  async runOnce() {
    if (this.stopped) return { due: 0, overdue: 0 };
    try {
      return await this.store.mutate((data) => enqueueBreakGlassReviewReminders(
        data,
        this.outbox,
        { now: this.now() },
      ));
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
