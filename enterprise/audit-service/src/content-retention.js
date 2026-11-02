import { ContentStoreError } from "./content-store.js";
import { sha256Text } from "./events.js";

const RUN_FIELDS = new Set(["dryRun", "limit"]);
const SAFE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/;
const SOURCE_HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function invalid(message) {
  throw new ContentStoreError(400, "invalid_content_governance_request", message);
}

function validateRunRequest(value) {
  if (!plainObject(value)
      || Object.keys(value).some((key) => !RUN_FIELDS.has(key))) {
    invalid("The retention request contains an unknown field");
  }
  if (value.dryRun !== undefined && typeof value.dryRun !== "boolean") {
    invalid("dryRun must be a boolean");
  }
  if (value.limit !== undefined
      && (!Number.isSafeInteger(value.limit)
        || value.limit < 1
        || value.limit > 500)) {
    invalid("limit must be from 1 to 500");
  }
  return {
    dryRun: value.dryRun === true,
    limit: value.limit ?? 100,
  };
}

function candidateFor(stream) {
  const request = stream.request || {};
  return {
    contentRef: stream.contentRef,
    streamId: stream.streamId,
    userId: request.userId,
    departmentId: request.departmentId,
    deviceId: request.deviceId,
    agentId: request.agentId,
  };
}

function isDue(value, nowMs) {
  const expiresMs = new Date(value).getTime();
  return Number.isFinite(expiresMs) && nowMs >= expiresMs;
}

export class ContentRetentionManager {
  constructor(store, options = {}) {
    if (!store) throw new Error("ContentRetentionManager store is required");
    if (!options.deletion) throw new Error("ContentRetentionManager deletion is required");
    if (!options.legalHolds) throw new Error("ContentRetentionManager legalHolds is required");
    if (!SAFE_ID_PATTERN.test(options.organizationId || "")) {
      throw new Error("ContentRetentionManager organizationId is invalid");
    }
    this.store = store;
    this.deletion = options.deletion;
    this.legalHolds = options.legalHolds;
    this.exports = options.exports || null;
    this.organizationId = options.organizationId;
    this.intervalMs = options.intervalMs ?? 60 * 60 * 1000;
    this.now = options.now || Date.now;
    this.logger = options.logger || (() => {});
    this.timer = null;
    this.running = null;
    this.autoSourceHash = `sha256:${sha256Text("magpie-system-retention-v1")}`;
  }

  nowMs() {
    const value = this.now();
    return value instanceof Date ? value.getTime() : Number(value);
  }

  candidates(nowMs, limit) {
    const content = [];
    const metadata = [];
    for (const object of Object.values(this.store.index.objects)) {
      if (!isDue(object.contentRetentionExpiresAt, nowMs)) continue;
      const stream = this.store.index.streams[object.streamId];
      if (!stream) continue;
      content.push({
        kind: "content",
        dueAt: object.contentRetentionExpiresAt,
        contentRef: object.contentRef,
        stream,
        candidate: candidateFor({
          ...stream,
          contentRef: object.contentRef,
        }),
      });
    }
    for (const stream of Object.values(this.store.index.streams)) {
      if (stream.metadataRedactedAt
          || !isDue(stream.metadataRetentionExpiresAt, nowMs)) {
        continue;
      }
      metadata.push({
        kind: "metadata",
        dueAt: stream.metadataRetentionExpiresAt,
        stream,
        candidate: candidateFor(stream),
      });
    }
    return [...content, ...metadata]
      .sort((left, right) => left.dueAt.localeCompare(right.dueAt)
        || left.kind.localeCompare(right.kind)
        || (left.contentRef || left.stream.streamId)
          .localeCompare(right.contentRef || right.stream.streamId))
      .slice(0, limit);
  }

  async run(request = {}, auditContext = {}) {
    this.store.assertLoaded();
    const { dryRun, limit } = validateRunRequest(request);
    if (!SOURCE_HASH_PATTERN.test(auditContext.sourceHash || "")) {
      throw new ContentStoreError(
        500,
        "invalid_content_governance_request",
        "The retention audit context is invalid",
      );
    }
    const requestId = auditContext.requestId || "req_system_retention";
    const nowMs = this.nowMs();
    const now = new Date(nowMs).toISOString();
    const selected = this.candidates(nowMs, limit);
    const summary = {
      dryRun,
      scanned: selected.length,
      contentDeleted: 0,
      metadataRedacted: 0,
      skippedLegalHold: 0,
      exportsExpired: 0,
      errors: 0,
    };

    for (const item of selected) {
      if (this.legalHolds.activeFor(item.candidate)) {
        summary.skippedLegalHold += 1;
        continue;
      }
      if (dryRun) {
        if (item.kind === "content") summary.contentDeleted += 1;
        else summary.metadataRedacted += 1;
        continue;
      }
      try {
        if (item.kind === "content") {
          const result = await this.deletion.deleteExpired(item.contentRef, {
            organizationId: this.organizationId,
            requestId,
            sourceHash: auditContext.sourceHash,
          });
          if (!result.duplicate) summary.contentDeleted += 1;
        } else {
          const result = await this.store.redactStreamMetadata(
            item.stream.streamId,
            now,
            (stream) => {
              if (this.legalHolds.activeFor(candidateFor(stream))) {
                throw new ContentStoreError(
                  409,
                  "content_legal_hold_active",
                  "An active legal hold prevents metadata redaction",
                );
              }
            },
          );
          if (result.redacted) summary.metadataRedacted += 1;
        }
      } catch (error) {
        if (error instanceof ContentStoreError
            && error.code === "content_legal_hold_active") {
          summary.skippedLegalHold += 1;
          continue;
        }
        if (error instanceof ContentStoreError
            && error.code === "content_object_not_found") {
          continue;
        }
        summary.errors += 1;
        this.logger({
          event: "content_retention_error",
          kind: item.kind,
          code: error instanceof ContentStoreError ? error.code : "internal_error",
        });
      }
    }

    if (this.exports) {
      if (dryRun) {
        summary.exportsExpired = Object.values(this.store.index.exports)
          .filter((record) => record.status !== "expired"
            && nowMs >= new Date(record.expiresAt).getTime())
          .length;
      } else {
        const result = await this.exports.cleanupExpired();
        summary.exportsExpired = result.cleaned;
      }
    }

    if (summary.errors > 0) {
      throw new ContentStoreError(
        503,
        "content_store_unavailable",
        "Content retention did not complete",
        true,
      );
    }
    return summary;
  }

  start() {
    if (this.timer) return;
    this.timer = setInterval(() => {
      void this.sweepSafely();
    }, this.intervalMs);
    this.timer.unref?.();
  }

  async sweepSafely() {
    if (this.running) return this.running;
    this.running = this.run({}, {
      requestId: "req_system_retention",
      sourceHash: this.autoSourceHash,
    }).then((summary) => {
      if (summary.contentDeleted > 0
          || summary.metadataRedacted > 0
          || summary.exportsExpired > 0) {
        this.logger({
          event: "content_retention_sweep",
          ...summary,
        });
      }
      return summary;
    }).catch((error) => {
      this.logger({
        event: "content_retention_sweep_failed",
        code: error instanceof ContentStoreError ? error.code : "internal_error",
      });
    }).finally(() => {
      this.running = null;
    });
    return this.running;
  }

  async close() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    if (this.running) await this.running;
  }
}
