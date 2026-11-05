import crypto from "node:crypto";

import {
  ContentStoreError,
  contentSessionHash,
} from "./content-store.js";
import { canonicalJson, sha256Text } from "./events.js";

const HOLD_ID_PATTERN = /^hld_[A-Za-z0-9_-]{43}$/;
const CONTENT_REF_PATTERN = /^ct_[A-Za-z0-9_-]{43}$/;
const STREAM_ID_PATTERN = /^str_[A-Za-z0-9_-]{43}$/;
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const AUTHORIZATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@_-]{7,127}$/;
const IDEMPOTENCY_KEY_PATTERN = /^[\u0021-\u007e]{1,128}$/;
const CREATE_FIELDS = new Set([
  "scope",
  "reason",
  "approvalId",
  "custodianId",
  "startsAt",
  "expiresAt",
]);
const RELEASE_FIELDS = new Set(["reason", "approvalId"]);
const SCOPE_FIELDS = new Set([
  "contentRef",
  "streamId",
  "userId",
  "departmentId",
  "deviceId",
  "agentId",
]);
const MAX_HOLD_MS = 3650 * 24 * 60 * 60 * 1000;

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function invalid(message) {
  throw new ContentStoreError(
    400,
    "invalid_content_governance_request",
    message,
  );
}

function validText(value, minimum, maximum) {
  return typeof value === "string"
    && value.length >= minimum
    && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function timestamp(value, name) {
  if (typeof value !== "string") invalid(`${name} must be an ISO timestamp`);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    invalid(`${name} must be a canonical UTC timestamp`);
  }
  return value;
}

function validateScope(value) {
  if (!plainObject(value)
      || Object.keys(value).length === 0
      || Object.keys(value).some((key) => !SCOPE_FIELDS.has(key))) {
    throw new ContentStoreError(
      400,
      "content_legal_hold_scope_required",
      "A valid legal hold scope is required",
    );
  }
  if (value.contentRef !== undefined && !CONTENT_REF_PATTERN.test(value.contentRef)) {
    invalid("scope.contentRef is invalid");
  }
  if (value.streamId !== undefined && !STREAM_ID_PATTERN.test(value.streamId)) {
    invalid("scope.streamId is invalid");
  }
  for (const field of ["userId", "departmentId", "deviceId", "agentId"]) {
    if (value[field] !== undefined && !SAFE_ID_PATTERN.test(value[field])) {
      invalid(`scope.${field} is invalid`);
    }
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, item]),
  );
}

function validateCreate(value) {
  if (!plainObject(value)
      || Object.keys(value).some((key) => !CREATE_FIELDS.has(key))) {
    invalid("The legal hold request contains an unknown field");
  }
  const scope = validateScope(value.scope);
  if (!validText(value.reason, 8, 1024)) {
    invalid("reason must be from 8 to 1024 characters");
  }
  if (!AUTHORIZATION_ID_PATTERN.test(value.approvalId || "")) {
    throw new ContentStoreError(
      400,
      "content_legal_hold_approval_required",
      "A valid approvalId is required",
    );
  }
  if (!SAFE_ID_PATTERN.test(value.custodianId || "")) {
    invalid("custodianId is invalid");
  }
  const startsAt = value.startsAt === undefined
    ? null
    : timestamp(value.startsAt, "startsAt");
  const expiresAt = timestamp(value.expiresAt, "expiresAt");
  return {
    scope,
    reason: value.reason,
    approvalId: value.approvalId,
    custodianId: value.custodianId,
    startsAt,
    expiresAt,
  };
}

function validateRelease(value) {
  if (!plainObject(value)
      || Object.keys(value).some((key) => !RELEASE_FIELDS.has(key))) {
    invalid("The legal hold release contains an unknown field");
  }
  if (!validText(value.reason, 8, 1024)) {
    invalid("release reason must be from 8 to 1024 characters");
  }
  if (!AUTHORIZATION_ID_PATTERN.test(value.approvalId || "")) {
    invalid("release approvalId must be valid");
  }
  return { reason: value.reason, approvalId: value.approvalId };
}

function idempotencyHash(key) {
  return sha256Text(`legal_hold_create\u0000${key}`);
}

function publicHold(hold, nowMs) {
  return {
    holdId: hold.holdId,
    scope: structuredClone(hold.scope),
    reason: hold.reason,
    approvalId: hold.approvalId,
    custodianId: hold.custodianId,
    startsAt: hold.startsAt,
    expiresAt: hold.expiresAt,
    createdAt: hold.createdAt,
    createdBy: hold.createdBy,
    organizationId: hold.organizationId,
    status: hold.status,
    effectiveStatus: effectiveStatus(hold, nowMs),
    ...(hold.releasedAt ? { releasedAt: hold.releasedAt } : {}),
    ...(hold.releasedBy ? { releasedBy: hold.releasedBy } : {}),
    ...(hold.releaseReason ? { releaseReason: hold.releaseReason } : {}),
    ...(hold.releaseApprovalId
      ? { releaseApprovalId: hold.releaseApprovalId }
      : {}),
  };
}

function effectiveStatus(hold, nowMs) {
  if (hold.status === "released") return "released";
  if (nowMs < new Date(hold.startsAt).getTime()) return "scheduled";
  if (nowMs >= new Date(hold.expiresAt).getTime()) return "expired";
  return "active";
}

function scopeMatches(scope, candidate) {
  return Object.entries(scope)
    .every(([key, value]) => candidate[key] === value);
}

export class ContentLegalHoldManager {
  constructor(store, options = {}) {
    if (!store) throw new Error("ContentLegalHoldManager store is required");
    if (!validText(options.sessionSecret, 32, 4096)) {
      throw new Error("ContentLegalHoldManager sessionSecret is invalid");
    }
    if (!SAFE_ID_PATTERN.test(options.organizationId || "")) {
      throw new Error("ContentLegalHoldManager organizationId is invalid");
    }
    this.store = store;
    this.sessionSecret = options.sessionSecret;
    this.organizationId = options.organizationId;
    this.now = options.now || Date.now;
  }

  nowMs() {
    const value = this.now();
    return value instanceof Date ? value.getTime() : Number(value);
  }

  sessionHash(administrator) {
    return contentSessionHash(
      this.sessionSecret,
      administrator.adminId,
      administrator.organizationId,
      administrator.sessionId,
    );
  }

  activeFor(candidate) {
    this.store.assertLoaded();
    const nowMs = this.nowMs();
    return Object.values(this.store.index.legalHolds).some((hold) =>
      effectiveStatus(hold, nowMs) === "active"
      && scopeMatches(hold.scope, candidate));
  }

  async create(administrator, request, idempotencyKey) {
    if (!IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey || "")) {
      invalid("A valid Idempotency-Key is required");
    }
    const validated = validateCreate(request);
    const now = new Date(this.nowMs()).toISOString();
    const startsAt = validated.startsAt || now;
    const startsMs = new Date(startsAt).getTime();
    const expiresMs = new Date(validated.expiresAt).getTime();
    if (!Number.isFinite(startsMs)
        || !Number.isFinite(expiresMs)
        || expiresMs <= startsMs
        || expiresMs - startsMs > MAX_HOLD_MS) {
      invalid("expiresAt must be later than startsAt and at most 3650 days");
    }
    const normalized = {
      scope: validated.scope,
      reason: validated.reason,
      approvalId: validated.approvalId,
      custodianId: validated.custodianId,
      startsAt,
      expiresAt: validated.expiresAt,
    };
    const sessionHash = this.sessionHash(administrator);
    const fingerprint = sha256Text(canonicalJson({
      operation: "legal_hold_create",
      adminId: administrator.adminId,
      organizationId: administrator.organizationId,
      sessionHash,
      request: normalized,
    }));
    const keyHash = idempotencyHash(idempotencyKey);
    return this.store.withMutation(async () => {
      const previous = this.store.index.governanceIdempotency[keyHash];
      if (previous) {
        if (previous.operation !== "legal_hold_create"
            || previous.fingerprint !== fingerprint) {
          throw new ContentStoreError(
            409,
            "content_legal_hold_idempotency_conflict",
            "The idempotency key conflicts with an existing legal hold request",
          );
        }
        const hold = this.store.index.legalHolds[previous.resultId];
        if (!hold) {
          throw new ContentStoreError(
            500,
            "content_store_corrupt",
            "The legal hold idempotency index points to a missing hold",
          );
        }
        return {
          duplicate: true,
          hold: publicHold(hold, this.nowMs()),
        };
      }
      const holdId = `hld_${crypto.randomBytes(32).toString("base64url")}`;
      const hold = {
        holdId,
        ...normalized,
        createdAt: now,
        createdBy: administrator.adminId,
        organizationId: administrator.organizationId,
        sessionHash,
        status: "active",
      };
      const record = {
        operation: "legal_hold_create",
        fingerprint,
        resultId: holdId,
      };
      this.store.index.legalHolds[holdId] = hold;
      this.store.index.governanceIdempotency[keyHash] = record;
      try {
        await this.store.persist();
      } catch (error) {
        delete this.store.index.legalHolds[holdId];
        delete this.store.index.governanceIdempotency[keyHash];
        throw error;
      }
      return {
        duplicate: false,
        hold: publicHold(hold, this.nowMs()),
      };
    });
  }

  async release(administrator, holdId, request) {
    if (!HOLD_ID_PATTERN.test(holdId || "")) {
      invalid("holdId is invalid");
    }
    const validated = validateRelease(request);
    return this.store.withMutation(async () => {
      const hold = this.store.index.legalHolds[holdId];
      if (!hold) {
        throw new ContentStoreError(
          404,
          "content_legal_hold_not_found",
          "Content legal hold not found",
        );
      }
      if (hold.organizationId !== administrator.organizationId) {
        throw new ContentStoreError(
          403,
          "content_admin_scope_mismatch",
          "The administrator organization scope is invalid",
        );
      }
      if (hold.status === "released") {
        throw new ContentStoreError(
          409,
          "content_legal_hold_released",
          "Content legal hold is already released",
        );
      }
      const previous = structuredClone(hold);
      Object.assign(hold, {
        status: "released",
        releasedAt: new Date(this.nowMs()).toISOString(),
        releasedBy: administrator.adminId,
        releaseReason: validated.reason,
        releaseApprovalId: validated.approvalId,
      });
      try {
        await this.store.persist();
      } catch (error) {
        this.store.index.legalHolds[holdId] = previous;
        throw error;
      }
      return { hold: publicHold(hold, this.nowMs()) };
    });
  }

  async list(options = {}) {
    this.store.assertLoaded();
    const limit = options.limit ?? 100;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) {
      invalid("limit must be from 1 to 500");
    }
    const nowMs = this.nowMs();
    return Object.values(this.store.index.legalHolds)
      .filter((hold) => !options.organizationId
        || hold.organizationId === options.organizationId)
      .filter((hold) => !options.contentRef
        || hold.scope.contentRef === options.contentRef)
      .filter((hold) => !options.effectiveStatus
        || effectiveStatus(hold, nowMs) === options.effectiveStatus)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt)
        || right.holdId.localeCompare(left.holdId))
      .slice(0, limit)
      .map((hold) => publicHold(hold, nowMs));
  }
}
