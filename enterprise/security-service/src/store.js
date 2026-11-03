import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import {
  canonicalJson,
  hasSecretMaterial,
  plainObject,
  sha256Text,
  validateDetectionEvent,
} from "./events.js";

export const SECURITY_STORE_SCHEMA_VERSION = 1;
const FINDING_ID_PATTERN = /^sdf_[a-f0-9]{24}$/;
const AGGREGATE_ID_PATTERN = /^sag_[a-f0-9]{24}$/;
const DEDUPE_KEY_PATTERN = /^sdk_[a-f0-9]{24}$/;
const RULE_ID_PATTERN = /^sec\.[a-z0-9._-]+$/;
const SUBJECT_TYPE_PATTERN = /^(?:user|device|agent|service)$/;
const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const STATE_FIELDS = new Set([
  "version",
  "events",
  "findings",
  "aggregates",
  "suppressions",
  "stats",
]);
const EVENT_RECORD_FIELDS = new Set(["event", "fingerprint", "receivedAt"]);
const FINDING_RECORD_FIELDS = new Set(["finding", "fingerprint", "storedAt"]);
const AGGREGATE_FIELDS = new Set([
  "aggregateId",
  "ruleId",
  "ruleVersion",
  "organizationId",
  "subjectType",
  "subjectId",
  "count",
  "firstDetectedAt",
  "lastDetectedAt",
  "lastFindingId",
]);
const SUPPRESSION_FIELDS = new Set([
  "dedupeKey",
  "ruleId",
  "organizationId",
  "subjectType",
  "subjectId",
  "count",
  "firstDetectedAt",
  "lastDetectedAt",
  "lastFindingId",
  "suppressedUntil",
]);
const STATS_FIELDS = new Set([
  "acceptedEvents",
  "duplicateEvents",
  "findings",
  "suppressedFindings",
]);
const FINDING_FIELDS = new Set([
  "findingId",
  "eventId",
  "ruleId",
  "ruleVersion",
  "ruleKind",
  "severity",
  "organizationId",
  "subject",
  "requestId",
  "sessionId",
  "detectedAt",
  "evaluatedAt",
  "evidence",
  "dedupeKey",
  "aggregateId",
  "suppressed",
  "suppressionUntil",
]);
const SUBJECT_FIELDS = new Set(["type", "id", "orgUnitId"]);
const EVIDENCE_FIELDS = new Map([
  ["sec.client.direct_bypass", new Set(["route", "managedAgent"])],
  ["sec.content.sensitive", new Set(["sensitiveCategories", "matchCount"])],
  ["sec.device.noncompliant", new Set(["complianceState", "reasonCodes"])],
  ["sec.authorization.scope_violation", new Set(["decision", "dimension", "policyId"])],
  ["sec.source.untrusted_ip", new Set(["ipHash", "trustedAddressCount"])],
  ["sec.source.untrusted_region", new Set(["region", "trustedRegionCount"])],
  ["sec.usage.anomaly", new Set([
    "totalTokens",
    "baselineTokens",
    "tokenMultiplier",
    "tokenThreshold",
    "minimumTokens",
    "cost",
    "baselineCost",
    "costMultiplier",
    "costThreshold",
    "minimumCost",
    "triggeredBy",
  ])],
  ["sec.usage.budget_threshold", new Set([
    "budgetLimit",
    "budgetUsed",
    "ratio",
    "warningRatio",
    "criticalRatio",
  ])],
]);
const SUBJECT_TYPES = new Set(["user", "device", "agent", "service"]);
const CONNECTION_ROUTES = new Set(["direct_provider", "enterprise_gateway", "unknown"]);
const AUTHORIZATION_DIMENSIONS = new Set([
  "gateway",
  "mcp",
  "model",
  "organization",
  "provider",
  "scope",
  "tool",
]);
const SENSITIVE_CATEGORIES = new Set([
  "api_key",
  "bank_card",
  "bearer_token",
  "cloud_access_key",
  "credential",
  "email",
  "national_id",
  "other_sensitive",
  "password",
  "phone",
  "private_key",
]);

export class SecurityStoreError extends Error {
  constructor(code, message, statusCode = 500, retryable = false) {
    super(message);
    this.name = "SecurityStoreError";
    this.code = code;
    this.statusCode = statusCode;
    this.retryable = retryable;
  }
}

function timestamp(value) {
  return typeof value === "string"
    && TIMESTAMP_PATTERN.test(value)
    && Number.isFinite(Date.parse(value))
    && new Date(value).toISOString() === value;
}

function safeIdentifier(value) {
  return typeof value === "string"
    && /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/.test(value);
}

function safeCode(value, maximum = 64) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximum
    && /^[a-z][a-z0-9._-]*$/.test(value);
}

function safeCodeList(value) {
  return Array.isArray(value)
    && value.length > 0
    && value.length <= 32
    && value.every((item) => safeCode(item))
    && new Set(value).size === value.length;
}

function finiteNumber(value, minimum = 0) {
  return typeof value === "number"
    && Number.isFinite(value)
    && value >= minimum;
}

function emptyStore() {
  return {
    version: SECURITY_STORE_SCHEMA_VERSION,
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
  };
}

function assertRecord(value, allowedFields, name) {
  if (!plainObject(value)
      || Object.keys(value).some((key) => !allowedFields.has(key))) {
    throw new SecurityStoreError("security_store_invalid", `${name} is invalid`);
  }
}

function verifyFingerprint(value, fingerprint, name) {
  if (typeof fingerprint !== "string"
      || !/^[a-f0-9]{64}$/.test(fingerprint)
      || sha256Text(canonicalJson(value)) !== fingerprint) {
    throw new SecurityStoreError("security_store_invalid", `${name} fingerprint is invalid`);
  }
}

export function validateFindingValue(finding) {
  if (!plainObject(finding)
      || Object.keys(finding).some((key) => !FINDING_FIELDS.has(key))
      || !FINDING_ID_PATTERN.test(finding.findingId || "")
      || !/^devt_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(finding.eventId || "")
      || typeof finding.ruleId !== "string"
      || !RULE_ID_PATTERN.test(finding.ruleId)
      || !Number.isSafeInteger(finding.ruleVersion)
      || finding.ruleVersion < 1
      || !safeCode(finding.ruleKind)
      || !["warning", "high", "critical"].includes(finding.severity)
      || !safeIdentifier(finding.organizationId)
      || !plainObject(finding.subject)
      || Object.keys(finding.subject).some((key) => !SUBJECT_FIELDS.has(key))
      || !SUBJECT_TYPES.has(finding.subject.type)
      || !safeIdentifier(finding.subject.id)
      || (finding.subject.orgUnitId !== undefined
        && !safeIdentifier(finding.subject.orgUnitId))
      || typeof finding.requestId !== "string"
      || (finding.requestId !== ""
        && !/^req_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(finding.requestId))
      || typeof finding.sessionId !== "string"
      || (finding.sessionId !== ""
        && !/^ses_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(finding.sessionId))
      || !timestamp(finding.detectedAt)
      || !timestamp(finding.evaluatedAt)
      || !plainObject(finding.evidence)
      || !DEDUPE_KEY_PATTERN.test(finding.dedupeKey || "")
      || !AGGREGATE_ID_PATTERN.test(finding.aggregateId || "")
      || typeof finding.suppressed !== "boolean"
      || (finding.suppressionUntil !== "" && !timestamp(finding.suppressionUntil))
      || hasSecretMaterial(finding)) {
    return false;
  }

  const allowedEvidence = EVIDENCE_FIELDS.get(finding.ruleId);
  if (!allowedEvidence
      || Object.keys(finding.evidence).length === 0
      || Object.keys(finding.evidence).some((key) => !allowedEvidence.has(key))) {
    return false;
  }
  return validateEvidence(finding);
}

function validateEvidence(finding) {
  const evidence = finding.evidence;
  if (finding.ruleId === "sec.client.direct_bypass") {
    return CONNECTION_ROUTES.has(evidence.route)
      && typeof evidence.managedAgent === "boolean";
  }
  if (finding.ruleId === "sec.content.sensitive") {
    return Array.isArray(evidence.sensitiveCategories)
      && evidence.sensitiveCategories.length > 0
      && evidence.sensitiveCategories.every((category) => SENSITIVE_CATEGORIES.has(category))
      && Number.isSafeInteger(evidence.matchCount)
      && evidence.matchCount > 0;
  }
  if (finding.ruleId === "sec.device.noncompliant") {
    return evidence.complianceState === "noncompliant"
      && safeCodeList(evidence.reasonCodes);
  }
  if (finding.ruleId === "sec.authorization.scope_violation") {
    return evidence.decision === "denied"
      && AUTHORIZATION_DIMENSIONS.has(evidence.dimension)
      && (evidence.policyId === "" || safeCode(evidence.policyId, 128));
  }
  if (finding.ruleId === "sec.source.untrusted_ip") {
    return /^sha256:[a-f0-9]{64}$/.test(evidence.ipHash || "")
      && Number.isSafeInteger(evidence.trustedAddressCount)
      && evidence.trustedAddressCount > 0;
  }
  if (finding.ruleId === "sec.source.untrusted_region") {
    return safeCode(evidence.region)
      && Number.isSafeInteger(evidence.trustedRegionCount)
      && evidence.trustedRegionCount > 0;
  }
  if (finding.ruleId === "sec.usage.anomaly") {
    const tokenTriggered = evidence.triggeredBy?.includes("tokens");
    const costTriggered = evidence.triggeredBy?.includes("cost");
    return Array.isArray(evidence.triggeredBy)
      && evidence.triggeredBy.length > 0
      && evidence.triggeredBy.every((item) => item === "tokens" || item === "cost")
      && new Set(evidence.triggeredBy).size === evidence.triggeredBy.length
      && (!tokenTriggered || (
        Number.isSafeInteger(evidence.totalTokens)
        && Number.isSafeInteger(evidence.baselineTokens)
        && evidence.baselineTokens > 0
        && finiteNumber(evidence.tokenMultiplier, 1.01)
        && finiteNumber(evidence.tokenThreshold, 1.01)
        && Number.isSafeInteger(evidence.minimumTokens)
      ))
      && (!costTriggered || (
        finiteNumber(evidence.cost)
        && finiteNumber(evidence.baselineCost)
        && evidence.baselineCost > 0
        && finiteNumber(evidence.costMultiplier, 1.01)
        && finiteNumber(evidence.costThreshold, 1.01)
        && finiteNumber(evidence.minimumCost, 0.01)
      ));
  }
  if (finding.ruleId === "sec.usage.budget_threshold") {
    return finiteNumber(evidence.budgetLimit, Number.MIN_VALUE)
      && finiteNumber(evidence.budgetUsed)
      && finiteNumber(evidence.ratio)
      && finiteNumber(evidence.warningRatio, 0.01)
      && finiteNumber(evidence.criticalRatio, evidence.warningRatio)
      && evidence.criticalRatio >= evidence.warningRatio
      && evidence.ratio >= evidence.warningRatio;
  }
  return false;
}

function validateStats(stats) {
  if (!plainObject(stats)
      || Object.keys(stats).some((key) => !STATS_FIELDS.has(key))
      || Object.values(stats).some((value) => !Number.isSafeInteger(value) || value < 0)) {
    throw new SecurityStoreError("security_store_invalid", "security store stats are invalid");
  }
}

function validateAggregate(aggregateId, aggregate) {
  assertRecord(aggregate, AGGREGATE_FIELDS, `aggregate ${aggregateId}`);
  if (!AGGREGATE_ID_PATTERN.test(aggregateId)
      || aggregate.aggregateId !== aggregateId
      || !RULE_ID_PATTERN.test(aggregate.ruleId || "")
      || !Number.isSafeInteger(aggregate.ruleVersion)
      || aggregate.ruleVersion < 1
      || !safeIdentifier(aggregate.organizationId)
      || !SUBJECT_TYPE_PATTERN.test(aggregate.subjectType || "")
      || !safeIdentifier(aggregate.subjectId)
      || !Number.isSafeInteger(aggregate.count)
      || aggregate.count < 1
      || !timestamp(aggregate.firstDetectedAt)
      || !timestamp(aggregate.lastDetectedAt)
      || aggregate.firstDetectedAt > aggregate.lastDetectedAt
      || !FINDING_ID_PATTERN.test(aggregate.lastFindingId || "")) {
    throw new SecurityStoreError("security_store_invalid", `aggregate ${aggregateId} is invalid`);
  }
}

function validateSuppression(dedupeKey, suppression) {
  assertRecord(suppression, SUPPRESSION_FIELDS, `suppression ${dedupeKey}`);
  if (!DEDUPE_KEY_PATTERN.test(dedupeKey)
      || suppression.dedupeKey !== dedupeKey
      || !RULE_ID_PATTERN.test(suppression.ruleId || "")
      || !safeIdentifier(suppression.organizationId)
      || !SUBJECT_TYPE_PATTERN.test(suppression.subjectType || "")
      || !safeIdentifier(suppression.subjectId)
      || !Number.isSafeInteger(suppression.count)
      || suppression.count < 1
      || !timestamp(suppression.firstDetectedAt)
      || !timestamp(suppression.lastDetectedAt)
      || suppression.firstDetectedAt > suppression.lastDetectedAt
      || !FINDING_ID_PATTERN.test(suppression.lastFindingId || "")
      || !timestamp(suppression.suppressedUntil)) {
    throw new SecurityStoreError(
      "security_store_invalid",
      `suppression ${dedupeKey} is invalid`,
    );
  }
}

function validateLoadedState(data, limits) {
  if (!plainObject(data)) {
    throw new SecurityStoreError("security_store_invalid", "security store must be an object");
  }
  if (data.version !== SECURITY_STORE_SCHEMA_VERSION) {
    throw new SecurityStoreError(
      "security_store_invalid",
      `security store schema ${data.version} is unsupported`,
    );
  }
  if (Object.keys(data).some((key) => !STATE_FIELDS.has(key))) {
    throw new SecurityStoreError("security_store_invalid", "security store has unknown fields");
  }
  for (const key of ["events", "findings", "aggregates", "suppressions", "stats"]) {
    if (!plainObject(data[key])) {
      throw new SecurityStoreError("security_store_invalid", `security store ${key} is invalid`);
    }
  }
  if (Object.keys(data.events).length > limits.maxEvents) {
    throw new SecurityStoreError(
      "security_store_invalid",
      "security store exceeds the configured event limit",
    );
  }
  if (Object.keys(data.findings).length > limits.maxFindings) {
    throw new SecurityStoreError(
      "security_store_invalid",
      "security store exceeds the configured finding limit",
    );
  }
  validateStats(data.stats);

  for (const [eventId, record] of Object.entries(data.events)) {
    assertRecord(record, EVENT_RECORD_FIELDS, `event ${eventId}`);
    let event;
    try {
      event = validateDetectionEvent(record.event);
    } catch {
      throw new SecurityStoreError(
        "security_store_invalid",
        `event ${eventId} contains an invalid detection event`,
      );
    }
    if (event.eventId !== eventId || !timestamp(record.receivedAt)) {
      throw new SecurityStoreError("security_store_invalid", `event ${eventId} is invalid`);
    }
    verifyFingerprint(event, record.fingerprint, `event ${eventId}`);
  }

  for (const [findingId, record] of Object.entries(data.findings)) {
    assertRecord(record, FINDING_RECORD_FIELDS, `finding ${findingId}`);
    if (!validateFindingValue(record.finding)
        || record.finding.findingId !== findingId
        || !timestamp(record.storedAt)) {
      throw new SecurityStoreError("security_store_invalid", `finding ${findingId} is invalid`);
    }
    verifyFingerprint(record.finding, record.fingerprint, `finding ${findingId}`);
    if (!data.events[record.finding.eventId]) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `finding ${findingId} does not reference a stored event`,
      );
    }
  }

  for (const [aggregateId, aggregate] of Object.entries(data.aggregates)) {
    validateAggregate(aggregateId, aggregate);
    if (!data.findings[aggregate.lastFindingId]) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `aggregate ${aggregateId} references a missing finding`,
      );
    }
  }

  for (const [dedupeKey, suppression] of Object.entries(data.suppressions)) {
    validateSuppression(dedupeKey, suppression);
    if (!data.findings[suppression.lastFindingId]) {
      throw new SecurityStoreError(
        "security_store_invalid",
        `suppression ${dedupeKey} references a missing finding`,
      );
    }
  }
  return data;
}

function matchesFinding(finding, filters) {
  if (filters.ruleId && finding.ruleId !== filters.ruleId) return false;
  if (filters.severity && finding.severity !== filters.severity) return false;
  if (filters.organizationId && finding.organizationId !== filters.organizationId) return false;
  if (filters.subjectId && finding.subject.id !== filters.subjectId) return false;
  if (filters.since && finding.detectedAt < filters.since) return false;
  return true;
}

export class SecurityStore {
  constructor(storePath, limits = {}) {
    this.path = path.resolve(String(storePath));
    this.maxEvents = limits.maxEvents ?? 1_000_000;
    this.maxFindings = limits.maxFindings ?? 2_000_000;
    this.maxStoreBytes = limits.maxStoreBytes ?? 536_870_912;
    this.now = typeof limits.now === "function" ? limits.now : Date.now;
    this.state = emptyStore();
    this.queue = Promise.resolve();
    this.initialized = false;
  }

  async init() {
    if (this.initialized) return this;
    await fs.mkdir(path.dirname(this.path), { recursive: true });
    let text;
    try {
      const stat = await fs.stat(this.path);
      if (stat.size > this.maxStoreBytes) {
        throw new SecurityStoreError(
          "security_store_invalid",
          "security store exceeds the configured file-size limit",
        );
      }
      text = await fs.readFile(this.path, "utf8");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      this.initialized = true;
      return this;
    }
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new SecurityStoreError("security_store_invalid", "security store is not valid JSON");
    }
    this.state = validateLoadedState(parsed, this);
    this.initialized = true;
    return this;
  }

  #enqueue(operation) {
    if (!this.initialized) {
      return Promise.reject(new SecurityStoreError(
        "security_store_not_ready",
        "security store is not initialized",
        503,
        true,
      ));
    }
    const run = this.queue.then(operation, operation);
    this.queue = run.catch(() => {});
    return run;
  }

  async #persist(state) {
    const temporary = `${this.path}.${process.pid}.${crypto.randomUUID()}.tmp`;
    let handle;
    try {
      handle = await fs.open(temporary, "wx", 0o600);
      await handle.writeFile(JSON.stringify(state));
      await handle.sync();
      await handle.close();
      handle = null;
      await fs.rename(temporary, this.path);
    } catch (error) {
      if (handle) await handle.close().catch(() => {});
      await fs.unlink(temporary).catch(() => {});
      throw new SecurityStoreError(
        "security_store_write_failed",
        "The security store could not be persisted",
        503,
        true,
      );
    }
  }

  ingest(event, options = {}) {
    return this.#enqueue(async () => {
      const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
      if (!Number.isFinite(now.getTime())) {
        throw new SecurityStoreError("invalid_evaluation_time", "Evaluation time is invalid", 400);
      }
      const receivedAt = now.toISOString();
      const eventFingerprint = sha256Text(canonicalJson(event));
      const existing = this.state.events[event.eventId];
      if (existing) {
        if (existing.fingerprint !== eventFingerprint) {
          throw new SecurityStoreError(
            "detection_event_conflict",
            "The eventId is already stored with different content",
            409,
          );
        }
        const nextDuplicateState = {
          ...this.state,
          stats: {
            ...this.state.stats,
            duplicateEvents: this.state.stats.duplicateEvents + 1,
          },
        };
        await this.#persist(nextDuplicateState);
        this.state = nextDuplicateState;
        return {
          duplicate: true,
          findings: [],
          aggregateIds: [],
        };
      }
      if (Object.keys(this.state.events).length >= this.maxEvents) {
        throw new SecurityStoreError(
          "security_event_capacity_exceeded",
          "The configured detection event capacity has been reached",
          507,
        );
      }

      const evaluated = options.evaluate(event, { now });
      if (!Array.isArray(evaluated)) throw new Error("rule evaluator must return an array");
      if (Object.keys(this.state.findings).length + evaluated.length > this.maxFindings) {
        throw new SecurityStoreError(
          "security_finding_capacity_exceeded",
          "The configured detection finding capacity has been reached",
          507,
        );
      }

      const next = {
        ...this.state,
        events: { ...this.state.events },
        findings: { ...this.state.findings },
        aggregates: { ...this.state.aggregates },
        suppressions: { ...this.state.suppressions },
        stats: { ...this.state.stats },
      };
      next.events[event.eventId] = {
        event,
        fingerprint: eventFingerprint,
        receivedAt,
      };
      next.stats.acceptedEvents += 1;

      const storedFindings = [];
      const aggregateIds = [];
      const windowSeconds = options.suppressionWindowSeconds ?? 300;
      const windowMs = windowSeconds * 1000;
      for (const rawFinding of evaluated) {
        if (!validateFindingValue(rawFinding)) {
          throw new Error("rule evaluator returned an invalid finding");
        }
        const priorSuppression = next.suppressions[rawFinding.dedupeKey];
        const suppressed = Boolean(
          windowMs > 0
          && priorSuppression
          && Date.parse(priorSuppression.suppressedUntil) > now.getTime(),
        );
        const suppressionUntil = suppressed
          ? priorSuppression.suppressedUntil
          : new Date(now.getTime() + windowMs).toISOString();
        const finding = {
          ...rawFinding,
          suppressed,
          suppressionUntil: windowMs > 0 ? suppressionUntil : "",
        };
        const fingerprint = sha256Text(canonicalJson(finding));
        next.findings[finding.findingId] = {
          finding,
          fingerprint,
          storedAt: receivedAt,
        };
        next.stats.findings += 1;
        if (suppressed) next.stats.suppressedFindings += 1;
        storedFindings.push(finding);
        aggregateIds.push(finding.aggregateId);

        const aggregate = next.aggregates[finding.aggregateId] || {
          aggregateId: finding.aggregateId,
          ruleId: finding.ruleId,
          ruleVersion: finding.ruleVersion,
          organizationId: finding.organizationId,
          subjectType: finding.subject.type,
          subjectId: finding.subject.id,
          count: 0,
          firstDetectedAt: finding.detectedAt,
          lastDetectedAt: finding.detectedAt,
          lastFindingId: finding.findingId,
        };
        next.aggregates[finding.aggregateId] = {
          ...aggregate,
          count: aggregate.count + 1,
          firstDetectedAt: aggregate.firstDetectedAt < finding.detectedAt
            ? aggregate.firstDetectedAt
            : finding.detectedAt,
          lastDetectedAt: aggregate.lastDetectedAt > finding.detectedAt
            ? aggregate.lastDetectedAt
            : finding.detectedAt,
          lastFindingId: finding.findingId,
        };

        if (windowMs > 0) {
          const prior = next.suppressions[finding.dedupeKey];
          next.suppressions[finding.dedupeKey] = {
            dedupeKey: finding.dedupeKey,
            ruleId: finding.ruleId,
            organizationId: finding.organizationId,
            subjectType: finding.subject.type,
            subjectId: finding.subject.id,
            count: (prior?.count || 0) + 1,
            firstDetectedAt: prior?.firstDetectedAt || finding.detectedAt,
            lastDetectedAt: prior?.lastDetectedAt
              && prior.lastDetectedAt > finding.detectedAt
              ? prior.lastDetectedAt
              : finding.detectedAt,
            lastFindingId: finding.findingId,
            suppressedUntil: suppressed
              ? suppressionUntil
              : new Date(now.getTime() + windowMs).toISOString(),
          };
        }
      }

      await this.#persist(next);
      this.state = next;
      return {
        duplicate: false,
        findings: structuredClone(storedFindings),
        aggregateIds: [...new Set(aggregateIds)],
      };
    });
  }

  read(operation) {
    return this.#enqueue(async () => operation(structuredClone(this.state)));
  }

  stats() {
    return this.read((state) => {
      const now = this.now();
      return {
        eventCount: Object.keys(state.events).length,
        findingCount: Object.keys(state.findings).length,
        aggregateCount: Object.keys(state.aggregates).length,
        suppressionCount: Object.keys(state.suppressions).length,
        activeSuppressionCount: Object.values(state.suppressions)
          .filter((item) => Date.parse(item.suppressedUntil) > now).length,
        stats: { ...state.stats },
        limits: {
          maxEvents: this.maxEvents,
          maxFindings: this.maxFindings,
        },
      };
    });
  }

  listFindings(filters = {}) {
    const limit = Math.min(Math.max(Number(filters.limit) || 100, 1), 500);
    return this.read((state) => Object.values(state.findings)
      .map((record) => record.finding)
      .filter((finding) => matchesFinding(finding, filters))
      .sort((left, right) => {
        const byTime = right.detectedAt.localeCompare(left.detectedAt);
        return byTime || left.findingId.localeCompare(right.findingId);
      })
      .slice(0, limit));
  }

  listAggregates(filters = {}) {
    const limit = Math.min(Math.max(Number(filters.limit) || 100, 1), 500);
    return this.read((state) => Object.values(state.aggregates)
      .filter((aggregate) => (
        (!filters.ruleId || aggregate.ruleId === filters.ruleId)
        && (!filters.organizationId || aggregate.organizationId === filters.organizationId)
        && (!filters.subjectId || aggregate.subjectId === filters.subjectId)
      ))
      .sort((left, right) => right.lastDetectedAt.localeCompare(left.lastDetectedAt))
      .slice(0, limit));
  }

  listSuppressions(filters = {}) {
    const limit = Math.min(Math.max(Number(filters.limit) || 100, 1), 500);
    const now = this.now();
    return this.read((state) => Object.values(state.suppressions)
      .filter((suppression) => (
        (!filters.ruleId || suppression.ruleId === filters.ruleId)
        && (!filters.organizationId || suppression.organizationId === filters.organizationId)
        && (!filters.subjectId || suppression.subjectId === filters.subjectId)
        && (!filters.activeOnly || Date.parse(suppression.suppressedUntil) > now)
      ))
      .sort((left, right) => right.lastDetectedAt.localeCompare(left.lastDetectedAt))
      .slice(0, limit));
  }
}
