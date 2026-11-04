import fs from "node:fs/promises";

export class UsageReadError extends Error {
  constructor(message = "The usage source is unavailable") {
    super(message);
    this.statusCode = 503;
    this.code = "storage_unavailable";
  }
}

function count(value) {
  if (value == null || value === "") return 0;
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) {
    throw new UsageReadError("The usage source contains an invalid counter");
  }
  return number;
}

function text(value, maxLength = 512) {
  return String(value || "").slice(0, maxLength);
}

function normalizeRecord(value, maxFields) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new UsageReadError("The usage source contains a malformed record");
  }
  if (Object.keys(value).length > maxFields) {
    throw new UsageReadError("The usage source contains a record with too many fields");
  }
  const time = Date.parse(String(value.t || ""));
  if (!Number.isFinite(time)) {
    throw new UsageReadError("The usage source contains a record without a valid time");
  }
  const costValue = value.cost == null || value.cost === "" ? null : Number(value.cost);
  if (costValue != null && (!Number.isFinite(costValue) || costValue < 0)) {
    throw new UsageReadError("The usage source contains an invalid cost");
  }
  return {
    time,
    agent: text(value.agent, 160),
    provider: text(value.provider, 160),
    callerKeyId: text(value.callerKeyId || value.key, 240),
    callerKeyName: text(value.callerKeyName, 240),
    model: text(value.req) || text(value.model, 240),
    status: count(value.status),
    inputTokens: count(value.in),
    outputTokens: count(value.out),
    cacheReadTokens: count(value.cache_read),
    cacheWriteTokens: count(value.cache_write),
    costUsd: costValue,
    rejected: value.rejected === true,
    handedOn: value.handed_on === true,
  };
}

export async function readUsageFile(config, window) {
  if (!config.path) throw new UsageReadError("ADMIN_USAGE_PATH is not configured");

  let stat;
  try {
    stat = await fs.stat(config.path);
  } catch (error) {
    throw new UsageReadError(
      error.code === "ENOENT"
        ? "The usage source does not exist"
        : "The usage source cannot be read",
    );
  }
  if (!stat.isFile()) throw new UsageReadError("The usage source is not a regular file");
  if (stat.size > config.maxBytes) {
    throw new UsageReadError("The usage source exceeds the configured size limit");
  }

  let bytes;
  try {
    bytes = await fs.readFile(config.path);
  } catch {
    throw new UsageReadError("The usage source cannot be read");
  }
  if (bytes.length > 0 && bytes[bytes.length - 1] !== 0x0a) {
    throw new UsageReadError("The usage source ends with an incomplete record");
  }

  let source;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new UsageReadError("The usage source is not valid UTF-8");
  }

  const lines = source.split("\n");
  if (lines.at(-1) === "") lines.pop();
  if (lines.length > config.maxRecords) {
    throw new UsageReadError("The usage source exceeds the configured record limit");
  }

  const records = [];
  for (const rawLine of lines) {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (!line) throw new UsageReadError("The usage source contains an empty record");
    if (Buffer.byteLength(line, "utf8") > config.maxLineBytes) {
      throw new UsageReadError("The usage source contains an oversized record");
    }
    let value;
    try {
      value = JSON.parse(line);
    } catch {
      throw new UsageReadError("The usage source contains malformed JSON");
    }
    const record = normalizeRecord(value, config.maxFields);
    if (window && (record.time < window.fromMs || record.time >= window.toMs)) continue;
    records.push(record);
  }

  return {
    records,
    bytes: bytes.length,
    lines: lines.length,
  };
}
