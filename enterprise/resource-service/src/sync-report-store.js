import fs from "node:fs/promises";
import path from "node:path";

export const SYNC_REPORT_STORE_SCHEMA_VERSION = 1;
const REPORT_STATUSES = new Set(["synced", "up_to_date", "failed", "offline", "drift", "busy"]);
const DRIFT_STATES = new Set([
  "missing",
  "version_mismatch",
  "not_in_desired_state",
  "content_invalid",
  "metadata_mismatch",
  "path_symlink",
]);
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const REVISION = /^sha256:[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function timestamp(value) {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function emptyStore() {
  return { version: SYNC_REPORT_STORE_SCHEMA_VERSION, reports: {} };
}

function validateReport(deviceId, report) {
  if (!SAFE_ID.test(deviceId)
      || !plainObject(report)
      || report.deviceId !== deviceId
      || !SAFE_ID.test(report.userId)
      || !REVISION.test(report.revision)
      || !REPORT_STATUSES.has(report.status)
      || typeof report.clientVersion !== "string"
      || report.clientVersion.length < 1
      || report.clientVersion.length > 64
      || !Array.isArray(report.installed)
      || report.installed.length > 500
      || !Array.isArray(report.drift)
      || report.drift.length > 500
      || !timestamp(report.reportedAt)
      || !timestamp(report.receivedAt)) {
    throw new Error(`sync report ${deviceId} is invalid`);
  }
  for (const item of report.installed) {
    if (!plainObject(item)
        || !SAFE_ID.test(item.resourceId)
        || !SAFE_ID.test(item.releaseId)
        || !DIGEST.test(item.manifestDigest)) {
      throw new Error(`sync report ${deviceId} contains invalid installed evidence`);
    }
  }
  for (const item of report.drift) {
    if (!plainObject(item)
        || !SAFE_ID.test(item.resourceId)
        || !DRIFT_STATES.has(item.state)
        || typeof item.expectedReleaseId !== "string"
        || !SAFE_ID.test(item.expectedReleaseId)
        || typeof item.actualReleaseId !== "string"
        || (item.actualReleaseId && !SAFE_ID.test(item.actualReleaseId))) {
      throw new Error(`sync report ${deviceId} contains invalid drift evidence`);
    }
  }
}

function migrateLoaded(data) {
  if (!plainObject(data)
      || data.version !== SYNC_REPORT_STORE_SCHEMA_VERSION
      || !plainObject(data.reports)
      || Object.keys(data).some((key) => !["version", "reports"].includes(key))) {
    throw new Error("sync report store schema is invalid or unsupported");
  }
  for (const [deviceId, report] of Object.entries(data.reports)) {
    validateReport(deviceId, report);
  }
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

export class SyncReportStore {
  constructor(file) {
    this.file = file;
    this.data = emptyStore();
    this.queue = Promise.resolve();
  }

  async load() {
    try {
      this.data = migrateLoaded(JSON.parse(await fs.readFile(this.file, "utf8")));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await writeAtomic(this.file, this.data);
    }
    return this.data;
  }

  async read(fn) {
    await this.queue;
    return fn(this.data);
  }

  record(report) {
    const run = this.queue.then(async () => {
      const draft = structuredClone(this.data);
      if (!draft.reports[report.deviceId] && Object.keys(draft.reports).length >= 10000) {
        throw new Error("sync report device limit reached");
      }
      draft.reports[report.deviceId] = structuredClone(report);
      migrateLoaded(draft);
      await writeAtomic(this.file, draft);
      this.data = draft;
      return structuredClone(report);
    });
    this.queue = run.catch(() => {});
    return run;
  }
}
