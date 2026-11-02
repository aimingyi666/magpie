import fs from "node:fs/promises";
import path from "node:path";

import {
  AUDIT_EVENT_SCHEMA_VERSION,
  canonicalJson,
  plainObject,
  sha256Text,
  validateAuditEvent,
  validateTimestamp,
} from "./events.js";

export const AUDIT_STORE_SCHEMA_VERSION = 1;
const STATE_FIELDS = new Set(["version", "events", "sessions", "idempotency", "queue", "stats"]);
const STAT_FIELDS = new Set(["accepted", "duplicates", "committed", "queueRejected"]);
const IDEMPOTENCY_FIELDS = new Set(["fingerprint", "eventId", "acceptedAt", "status"]);
const QUEUE_FIELDS = new Set(["event", "fingerprint", "acceptedAt"]);
const SESSION_FIELDS = new Set([
  "sessionId",
  "firstOccurredAt",
  "lastOccurredAt",
  "eventCount",
  "requestIds",
  "userIds",
  "departmentIds",
  "deviceIds",
  "agentIds",
  "modelIds",
  "toolNames",
  "truncated",
]);

function emptyStats() {
  return {
    accepted: 0,
    duplicates: 0,
    committed: 0,
    queueRejected: 0,
  };
}

function emptyStore() {
  return {
    version: AUDIT_STORE_SCHEMA_VERSION,
    events: {},
    sessions: {},
    idempotency: {},
    queue: {},
    stats: emptyStats(),
  };
}

function validString(value, maximum = 512) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validStringArray(value, maximumEntries = 1000, maximumLength = 256) {
  return Array.isArray(value)
    && value.length <= maximumEntries
    && value.every((item) => validString(item, maximumLength))
    && new Set(value).size === value.length;
}

function validateStats(stats) {
  if (!plainObject(stats)
      || Object.keys(stats).some((key) => !STAT_FIELDS.has(key))
      || Object.values(stats).some((value) => !Number.isSafeInteger(value) || value < 0)) {
    throw new Error("audit store stats are invalid");
  }
}

function validateSession(sessionId, session) {
  if (!plainObject(session)
      || Object.keys(session).some((key) => !SESSION_FIELDS.has(key))
      || session.sessionId !== sessionId
      || !/^ses_[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(sessionId)
      || !validateTimestamp(session.firstOccurredAt, "firstOccurredAt")
      || !validateTimestamp(session.lastOccurredAt, "lastOccurredAt")
      || session.firstOccurredAt > session.lastOccurredAt
      || !Number.isSafeInteger(session.eventCount)
      || session.eventCount < 1
      || !validStringArray(session.requestIds)
      || !validStringArray(session.userIds)
      || !validStringArray(session.departmentIds)
      || !validStringArray(session.deviceIds)
      || !validStringArray(session.agentIds)
      || !validStringArray(session.modelIds)
      || !validStringArray(session.toolNames)
      || typeof session.truncated !== "boolean") {
    throw new Error(`audit store session ${sessionId} is invalid`);
  }
}

function validateIdempotency(idempotencyKey, record, events, queue) {
  if (!/^[a-f0-9]{64}$/.test(idempotencyKey)
      || !plainObject(record)
      || Object.keys(record).some((key) => !IDEMPOTENCY_FIELDS.has(key))
      || !/^[a-f0-9]{64}$/.test(record.fingerprint)
      || !validString(record.eventId, 135)
      || !validateTimestamp(record.acceptedAt, "acceptedAt")
      || !["queued", "committed"].includes(record.status)) {
    throw new Error("audit store idempotency record is invalid");
  }
  if (record.status === "queued") {
    const queued = queue[record.eventId];
    if (!queued || queued.fingerprint !== record.fingerprint) {
      throw new Error("audit store idempotency record does not match its queued event");
    }
  }
  if (record.status === "committed") {
    const event = events[record.eventId];
    if (!event || sha256Text(canonicalJson(event)) !== record.fingerprint) {
      throw new Error("audit store idempotency record does not match its committed event");
    }
  }
}

function validateQueueRecord(eventId, record) {
  if (!plainObject(record)
      || Object.keys(record).some((key) => !QUEUE_FIELDS.has(key))
      || !/^[a-f0-9]{64}$/.test(record.fingerprint)
      || !validateTimestamp(record.acceptedAt, "acceptedAt")) {
    throw new Error(`audit store queue record ${eventId} is invalid`);
  }
  let event;
  try {
    event = validateAuditEvent(record.event);
  } catch {
    throw new Error(`audit store queue record ${eventId} contains an invalid event`);
  }
  if (event.eventId !== eventId || canonicalJson(event) !== canonicalJson(record.event)) {
    throw new Error(`audit store queue record ${eventId} does not match its event`);
  }
  if (sha256Text(canonicalJson(event)) !== record.fingerprint) {
    throw new Error(`audit store queue record ${eventId} has an invalid fingerprint`);
  }
}

function migrateLoaded(data, limits) {
  if (!plainObject(data)) throw new Error("audit store must be a JSON object");
  if (!Number.isInteger(data.version) || data.version > AUDIT_STORE_SCHEMA_VERSION) {
    throw new Error(`audit store schema ${data.version} is unsupported`);
  }
  if (Object.keys(data).some((key) => !STATE_FIELDS.has(key))) {
    throw new Error("audit store contains unknown fields");
  }
  const base = emptyStore();
  for (const key of Object.keys(base)) {
    if (data[key] == null) data[key] = base[key];
  }
  if (!plainObject(data.events)
      || !plainObject(data.sessions)
      || !plainObject(data.idempotency)
      || !plainObject(data.queue)
      || !plainObject(data.stats)) {
    throw new Error("audit store collection types are invalid");
  }
  if (Object.keys(data.events).length > limits.maxEvents) {
    throw new Error("audit store exceeds the configured event limit");
  }
  if (Object.keys(data.sessions).length > limits.maxSessions) {
    throw new Error("audit store exceeds the configured session limit");
  }
  if (Object.keys(data.queue).length > limits.maxQueueEvents) {
    throw new Error("audit store exceeds the configured queue limit");
  }
  validateStats(data.stats);
  for (const [eventId, event] of Object.entries(data.events)) {
    let normalized;
    try {
      normalized = validateAuditEvent(event);
    } catch {
      throw new Error(`audit store event ${eventId} is invalid`);
    }
    if (normalized.eventId !== eventId || canonicalJson(normalized) !== canonicalJson(event)) {
      throw new Error(`audit store event ${eventId} does not match its key`);
    }
  }
  for (const [eventId, record] of Object.entries(data.queue)) {
    validateQueueRecord(eventId, record);
  }
  for (const eventId of Object.keys(data.events)) {
    if (data.queue[eventId]) {
      throw new Error(`audit store event ${eventId} is both queued and committed`);
    }
  }
  for (const [sessionId, session] of Object.entries(data.sessions)) {
    validateSession(sessionId, session);
  }
  const expectedSessions = {};
  for (const event of Object.values(data.events)) {
    updateSession(expectedSessions, event, limits);
  }
  if (canonicalJson(data.sessions) !== canonicalJson(expectedSessions)) {
    throw new Error("audit store sessions do not match the committed events");
  }
  const idempotencyByEvent = new Map();
  for (const [key, record] of Object.entries(data.idempotency)) {
    validateIdempotency(key, record, data.events, data.queue);
    if (idempotencyByEvent.has(record.eventId)) {
      throw new Error(`audit store event ${record.eventId} has multiple idempotency records`);
    }
    idempotencyByEvent.set(record.eventId, record);
  }
  for (const eventId of [...Object.keys(data.events), ...Object.keys(data.queue)]) {
    const proof = idempotencyByEvent.get(eventId);
    if (!proof) {
      throw new Error(`audit store event ${eventId} has no idempotency record`);
    }
    if (proof.status !== (data.queue[eventId] ? "queued" : "committed")) {
      throw new Error(`audit store event ${eventId} has an invalid idempotency status`);
    }
  }
  if (JSON.stringify(data).includes("-----BEGIN PRIVATE KEY-----")
      || JSON.stringify(data).includes("-----BEGIN OPENSSH PRIVATE KEY-----")) {
    throw new Error("audit store must not contain a private key");
  }
  data.version = AUDIT_STORE_SCHEMA_VERSION;
  data.stats = { ...emptyStats(), ...data.stats };
  return data;
}

async function writeAtomic(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`;
  const handle = await fs.open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(temporary, file);
}

function addUnique(target, value, maximum = 1000) {
  if (!value) return false;
  if (target.includes(value)) return false;
  if (target.length >= maximum) return true;
  target.push(value);
  return false;
}

function updateSession(sessions, event, limits) {
  let session = sessions[event.sessionId];
  if (!session) {
    if (Object.keys(sessions).length >= limits.maxSessions) {
      throw new Error("audit session limit reached");
    }
    session = {
      sessionId: event.sessionId,
      firstOccurredAt: event.occurredAt,
      lastOccurredAt: event.occurredAt,
      eventCount: 0,
      requestIds: [],
      userIds: [],
      departmentIds: [],
      deviceIds: [],
      agentIds: [],
      modelIds: [],
      toolNames: [],
      truncated: false,
    };
    sessions[event.sessionId] = session;
  }
  session.eventCount += 1;
  if (event.occurredAt < session.firstOccurredAt) session.firstOccurredAt = event.occurredAt;
  if (event.occurredAt > session.lastOccurredAt) session.lastOccurredAt = event.occurredAt;
  session.truncated = addUnique(session.requestIds, event.requestId) || session.truncated;
  session.truncated = addUnique(session.userIds, event.userId) || session.truncated;
  session.truncated = addUnique(session.departmentIds, event.departmentId) || session.truncated;
  session.truncated = addUnique(session.deviceIds, event.deviceId) || session.truncated;
  session.truncated = addUnique(session.agentIds, event.agentId) || session.truncated;
  session.truncated = addUnique(session.modelIds, event.modelId) || session.truncated;
  session.truncated = addUnique(session.toolNames, event.toolName) || session.truncated;
}

export class AuditStore {
  constructor(file, options = {}) {
    this.file = file;
    this.limits = {
      maxEvents: options.maxEvents ?? 1_000_000,
      maxQueueEvents: options.maxQueueEvents ?? 100_000,
      maxSessions: options.maxSessions ?? 100_000,
    };
    this.writer = options.writer || writeAtomic;
    this.data = emptyStore();
    this.queue = Promise.resolve();
  }

  async load() {
    try {
      this.data = migrateLoaded(JSON.parse(await fs.readFile(this.file, "utf8")), this.limits);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await this.writer(this.file, this.data);
    }
    return this.data;
  }

  async read(fn) {
    await this.queue;
    return fn(this.data);
  }

  mutate(fn) {
    const run = this.queue.then(async () => {
      const draft = structuredClone(this.data);
      const result = await fn(draft);
      migrateLoaded(draft, this.limits);
      await this.writer(this.file, draft);
      this.data = draft;
      return result;
    });
    this.queue = run.catch(() => {});
    return run;
  }

  async enqueue(event, idempotencyKey) {
    const key = sha256Text(idempotencyKey);
    const fingerprint = sha256Text(canonicalJson(event));
    return this.mutate((draft) => {
      const existing = draft.idempotency[key];
      if (existing) {
        if (existing.fingerprint !== fingerprint || existing.eventId !== event.eventId) {
          return { conflict: true, reason: "idempotency" };
        }
        draft.stats.duplicates += 1;
        return {
          duplicate: true,
          eventId: event.eventId,
          status: existing.status,
          acceptedAt: existing.acceptedAt,
        };
      }
      if (draft.events[event.eventId] || draft.queue[event.eventId]) {
        return { conflict: true, reason: "event_id" };
      }
      if (Object.keys(draft.queue).length >= this.limits.maxQueueEvents) {
        draft.stats.queueRejected += 1;
        return { queueFull: true };
      }
      const acceptedAt = new Date().toISOString();
      draft.queue[event.eventId] = {
        event,
        fingerprint,
        acceptedAt,
      };
      draft.idempotency[key] = {
        fingerprint,
        eventId: event.eventId,
        acceptedAt,
        status: "queued",
      };
      draft.stats.accepted += 1;
      return {
        duplicate: false,
        eventId: event.eventId,
        status: "queued",
        acceptedAt,
      };
    });
  }

  async commitQueued(batchSize) {
    const hasQueued = await this.read((data) => Object.keys(data.queue).length > 0);
    if (!hasQueued) return { committed: 0, queued: 0 };
    return this.mutate((draft) => {
      const candidates = Object.values(draft.queue)
        .sort((left, right) => {
          const byTime = left.acceptedAt.localeCompare(right.acceptedAt);
          return byTime || left.event.eventId.localeCompare(right.event.eventId);
        })
        .slice(0, batchSize);
      if (candidates.length === 0) return { committed: 0, queued: 0 };
      if (Object.keys(draft.events).length + candidates.length > this.limits.maxEvents) {
        throw new Error("audit event limit reached");
      }
      const idempotencyByEvent = new Map(
        Object.values(draft.idempotency)
          .filter((item) => item.status === "queued")
          .map((item) => [item.eventId, item]),
      );
      for (const record of candidates) {
        const event = record.event;
        draft.events[event.eventId] = event;
        updateSession(draft.sessions, event, this.limits);
        delete draft.queue[event.eventId];
        const idempotency = idempotencyByEvent.get(event.eventId);
        if (!idempotency) throw new Error(`audit queue event ${event.eventId} has no idempotency proof`);
        idempotency.status = "committed";
        draft.stats.committed += 1;
      }
      return {
        committed: candidates.length,
        queued: Object.keys(draft.queue).length,
      };
    });
  }
}

export { AUDIT_EVENT_SCHEMA_VERSION };
