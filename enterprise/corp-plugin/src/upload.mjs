// What this machine tells the corporation: how much was spent, in what,
// and how many secrets were kept off the wire.
//
// The sources are magpie's own ledgers, read and never written:
//   <config>/usage.jsonl            one line per call, metadata only
//   <config>/masking/<day>.jsonl    the values masking swapped, by kind
//
// Neither holds a prompt or a reply, so nothing here parses an agent's
// transcript. What leaves is a whitelist: a field this file doesn't name
// is not sent, however the ledger grows.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const MAX_ROWS = 500;

export function ledgerPath(configDir) {
  return configDir ? path.join(configDir, "usage.jsonl") : "";
}

export function maskingDir(configDir) {
  return configDir ? path.join(configDir, "masking") : "";
}

function readLines(file, visit) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return;
  }
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      visit(JSON.parse(line));
    } catch {
      // a line half written by a crash is skipped, not fatal
    }
  }
}

function num(value) {
  return Number.isFinite(value) ? Math.max(0, Math.trunc(value)) : 0;
}

// toUsageRow is one ledger record as the server gets it: who, what, how
// much, how long, and whether it worked. Never the host, the account's
// email, a key's name or an error's text.
export function toUsageRow(record) {
  if (!record || typeof record !== "object") return null;
  const at = String(record.t || "");
  if (!at) return null;
  const row = {
    at,
    agent: String(record.agent || "").slice(0, 64),
    provider: String(record.provider || "").slice(0, 64),
    model: String(record.model || "").slice(0, 128),
    kind: String(record.operation || "chat").slice(0, 40),
    sessionId: String(record.session || "").slice(0, 128),
    input: num(record.in),
    output: num(record.out),
    cacheRead: num(record.cache_read),
    cacheWrite: num(record.cache_write),
    ms: num(record.ms),
    status: num(record.status),
    error: String(record.err_type || "").slice(0, 64),
  };
  row.rowId = rowID(row);
  return row;
}

// rowID is stable for a ledger line, so a resend after a crash is the same
// row to the server and counts once.
export function rowID(row) {
  const body = [row.at, row.agent, row.provider, row.model, row.sessionId, row.input, row.output, row.status, row.ms].join("|");
  return `sha256:${crypto.createHash("sha256").update(body).digest("hex").slice(0, 32)}`;
}

// toMaskingRow is one masking record, which magpie already keeps without
// the value: a placeholder, its kind, its first character and its length.
export function toMaskingRow(record) {
  if (!record || typeof record !== "object") return null;
  const at = String(record.t || "");
  const values = Array.isArray(record.values) ? record.values : [];
  return {
    at,
    agent: String(record.agent || "").slice(0, 64),
    provider: String(record.provider || "").slice(0, 64),
    model: String(record.model || "").slice(0, 128),
    sessionId: String(record.session || "").slice(0, 128),
    what: String(record.what || "").slice(0, 40),
    blocked: record.blocked === true,
    count: num(record.n),
    kinds: values.map((value) => String(value?.k || "").slice(0, 40)).filter(Boolean),
    placeholders: values.map((value) => String(value?.p || "").slice(0, 80)).filter(Boolean),
    lengths: values.map((value) => num(value?.l)),
  };
}

// readUsageRows answers the rows of the ledger after since, oldest first.
export function readUsageRows(configDir, since = "", limit = MAX_ROWS) {
  const file = ledgerPath(configDir);
  if (!file) return [];
  const out = [];
  readLines(file, (record) => {
    const row = toUsageRow(record);
    if (!row) return;
    if (since && row.at <= since) return;
    out.push(row);
  });
  out.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
  return out.slice(0, limit);
}

// readMaskingRows answers the masking records after since, oldest day's
// file first.
export function readMaskingRows(configDir, since = "", limit = MAX_ROWS) {
  const dir = maskingDir(configDir);
  if (!dir) return [];
  let names;
  try {
    names = fs.readdirSync(dir).filter((n) => n.endsWith(".jsonl")).sort();
  } catch {
    return [];
  }
  const out = [];
  for (const name of names) {
    readLines(path.join(dir, name), (record) => {
      const row = toMaskingRow(record);
      if (!row?.at) return;
      if (since && row.at <= since) return;
      out.push(row);
    });
    if (out.length >= limit) break;
  }
  out.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
  return out.slice(0, limit);
}

// sessionsOf folds usage rows into the conversations they were part of:
// turns, models and tokens, no content.
export function sessionsOf(rows) {
  const byID = new Map();
  for (const row of rows) {
    if (!row.sessionId) continue;
    let session = byID.get(row.sessionId);
    if (!session) {
      session = {
        sessionId: row.sessionId,
        agent: row.agent,
        startedAt: row.at,
        endedAt: row.at,
        turns: 0,
        models: [],
        input: 0,
        output: 0,
        errors: 0,
      };
      byID.set(row.sessionId, session);
    }
    session.turns += 1;
    if (row.at < session.startedAt) session.startedAt = row.at;
    if (row.at > session.endedAt) session.endedAt = row.at;
    if (row.model && !session.models.includes(row.model)) session.models.push(row.model);
    session.input += row.input;
    session.output += row.output;
    if (row.status >= 400) session.errors += 1;
  }
  return [...byID.values()];
}

export function batchID(from, to, hashes) {
  return `b_${crypto.createHash("sha256").update(`${from}|${to}|${hashes.sort().join(",")}`).digest("hex").slice(0, 24)}`;
}

// upload runs one channel once and answers what happened. The cursor
// advances only on an accepted batch: a rejected row is the server's final
// word on it, so a batch the server parsed moves on too.
export async function uploadChannel({ client, store, config, channel, rows, bodyKey, encoder }) {
  if (!rows.length) return { sent: 0, accepted: 0, duplicates: 0, rejected: 0 };
  const from = store.state().cursors[channel] || "";
  const to = rows[rows.length - 1].at;
  const body = {
    schemaVersion: 1,
    batchId: batchID(from, to, rows.map((row) => row.rowId || row.at)),
    [bodyKey]: encoder(rows),
    cursor: { from, to },
  };
  // a session summary rides along with the usage batch it was folded from
  if (channel === "usage" && config.upload.sessions) body.sessions = sessionsOf(rows);

  const { payload } = await client.request("/api/v1/telemetry/" + (channel === "usage" ? "usage" : channel), {
    method: "POST",
    body,
  });
  const accepted = Number(payload?.accepted) || 0;
  const duplicates = Number(payload?.duplicates) || 0;
  const rejected = Array.isArray(payload?.rejected) ? payload.rejected : [];
  const next = String(payload?.nextCursor || to);
  store.update((state) => {
    state.cursors[channel] = next;
    state.lastUploadAt[channel] = new Date().toISOString();
    return state;
  });
  return { sent: rows.length, accepted, duplicates, rejected: rejected.length };
}

// uploadAll runs the channels the server asked for.
export async function uploadAll({ client, store, config, channels }) {
  const out = {};
  const state = store.state();
  if ((channels || config.upload).usage) {
    out.usage = await uploadChannel({
      client,
      store,
      config,
      channel: "usage",
      rows: readUsageRows(config.configDir, state.cursors.usage, MAX_ROWS),
      bodyKey: "rows",
      encoder: (rows) => rows,
    });
  }
  const maskingOn = (channels || config.upload).masking;
  if (maskingOn) {
    out.masking = await uploadChannel({
      client,
      store,
      config,
      channel: "masking",
      rows: readMaskingRows(config.configDir, state.cursors.masking, MAX_ROWS),
      bodyKey: "hits",
      encoder: (rows) => rows,
    });
  }
  return out;
}
