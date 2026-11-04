import crypto from "node:crypto";
import http from "node:http";
import path from "node:path";
import fs from "node:fs/promises";

import { loadConfig } from "./config.js";

const SERVER_VERSION = "0.1.0";
const API_PREFIX = "/api/v1/portal";
const PORTAL_TEMPLATE = await fs.readFile(new URL("./portal-template.html", import.meta.url), "utf8");

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function portalPage(data) {
  const usage = Object.values(data.usage || {});
  const tickets = Object.values(data.tickets || {});
  const latest = usage
    .map((entry) => String(entry.date || ""))
    .filter((date) => /^\d{4}-\d{2}-\d{2}$/.test(date))
    .sort()
    .at(-1);
  const sampleDate = latest || new Date().toISOString().slice(0, 10);
  const monthUsage = usage.filter((entry) => entry.subjectId === "usr_alice" && String(entry.date || "").startsWith(sampleDate.slice(0, 7)));
  const totals = monthUsage.reduce((sum, entry) => {
    sum.tokens += Number(entry.tokens || 0);
    sum.cost += Number(entry.cost || 0);
    sum.requests += Number(entry.requests || 0);
    return sum;
  }, { tokens: 0, cost: 0, requests: 0 });
  const aliceTickets = tickets.filter((ticket) => ticket.subjectId === "usr_alice");
  const openCount = aliceTickets.filter((ticket) => ticket.status === "open" || ticket.status === "in_progress").length;
  const quota = 2_000_000;
  const remaining = Math.max(0, quota - totals.tokens);
  const recentRows = monthUsage.length
    ? monthUsage.map((entry) => `<tr><td>${escapeHtml(entry.date)}</td><td class="num">${escapeHtml(Number(entry.requests || 0).toLocaleString("zh-CN"))}</td><td class="num">${escapeHtml(Number(entry.tokens || 0).toLocaleString("zh-CN"))}</td><td class="num">$${escapeHtml(Number(entry.cost || 0).toFixed(4))}</td></tr>`).join("")
    : `<tr><td colspan="4"><div class="empty">本月还没有调用记录。</div></td></tr>`;
  const ticketRows = aliceTickets.length
    ? aliceTickets.map((ticket) => `<tr><td><span class="cell-main" title="${escapeHtml(ticket.title)}">${escapeHtml(ticket.title)}</span><span class="cell-sub mono">${escapeHtml(ticket.id)}</span></td><td>${ticket.priority === "high" ? '<span class="pill bad">紧急</span>' : '<span class="pill neutral">普通</span>'}</td><td class="num"><button class="row-action" data-goto="tickets" type="button">查看</button></td></tr>`).join("")
    : `<tr><td colspan="3"><div class="empty">没有待处理申请。</div></td></tr>`;
  return PORTAL_TEMPLATE
    .replaceAll("{{sampleDate}}", escapeHtml(sampleDate))
    .replaceAll("{{openCount}}", escapeHtml(openCount))
    .replaceAll("{{requests}}", escapeHtml(totals.requests.toLocaleString("zh-CN")))
    .replaceAll("{{tokens}}", escapeHtml(totals.tokens.toLocaleString("zh-CN")))
    .replaceAll("{{cost}}", escapeHtml(totals.cost.toFixed(4)))
    .replaceAll("{{remainingPercent}}", escapeHtml(`${Math.round(remaining / quota * 100)}%`))
    .replaceAll("{{remaining}}", escapeHtml(remaining.toLocaleString("zh-CN")))
    .replaceAll("{{quota}}", escapeHtml(quota.toLocaleString("zh-CN")))
    .replaceAll("{{trendSvg}}", usageTrend(usage.filter((entry) => entry.subjectId === "usr_alice"), sampleDate))
    .replaceAll("{{recentRows}}", recentRows)
    .replaceAll("{{homeTickets}}", ticketRows);
}

function usageTrend(entries, sampleDate) {
  const end = new Date(`${sampleDate}T00:00:00Z`);
  const days = Array.from({ length: 7 }, (_, index) => {
    const date = new Date(end);
    date.setUTCDate(end.getUTCDate() - (6 - index));
    return date.toISOString().slice(0, 10);
  });
  const values = days.map((day) => entries
    .filter((entry) => entry.date === day)
    .reduce((sum, entry) => sum + Number(entry.requests || 0), 0));
  const max = Math.max(1, ...values);
  const width = 640;
  const height = 210;
  const pad = 28;
  const step = (width - pad * 2) / 6;
  const points = values.map((value, index) => [
    pad + step * index,
    height - 34 - (value / max) * (height - 68),
  ]);
  const marks = points.map((point, index) => `<text x="${point[0]}" y="${height - 12}" fill="#687173" font-size="11" text-anchor="middle">${days[index].slice(5)}</text><circle cx="${point[0]}" cy="${point[1]}" r="3.5" fill="#1b6c80"></circle>`).join("");
  return `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="近七日请求趋势"><line x1="${pad}" y1="${height - 34}" x2="${width - pad}" y2="${height - 34}" stroke="#e5eaeb"></line><polyline points="${points.map((point) => point.join(",")).join(" ")}" fill="none" stroke="#1b6c80" stroke-width="2"></polyline>${marks}</svg>`;
}

class FixedWindowRateLimiter {
  constructor(limit, windowMs = 60000) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.buckets = new Map();
  }
  consume(key) {
    const now = Date.now();
    let bucket = this.buckets.get(key);
    if (!bucket || now - bucket.startedAt >= this.windowMs) {
      bucket = { startedAt: now, count: 0 };
      this.buckets.set(key, bucket);
    }
    bucket.count += 1;
    if (this.buckets.size > 10000) {
      for (const [bucketKey, value] of this.buckets) {
        if (now - value.startedAt >= this.windowMs) this.buckets.delete(bucketKey);
      }
    }
    return bucket.count <= this.limit;
  }
}

function requestId() {
  return crypto.randomUUID();
}

function sendJson(res, statusCode, body, extraHeaders = {}) {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(payload.length),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    connection: "close",
    ...extraHeaders,
  });
  res.end(payload);
}

function apiErrorBody(error) {
  return {
    error: {
      code: error.code,
      message: error.message,
      retryable: Boolean(error.retryable),
    },
  };
}

export class ApiError extends Error {
  constructor(statusCode, code, message, retryable = false) {
    super(message);
    this.name = "ApiError";
    this.statusCode = statusCode;
    this.code = code;
    this.retryable = retryable;
  }
}

async function readBody(req, maximum) {
  const contentType = String(req.headers["content-type"] || "").toLowerCase();
  if (!contentType.startsWith("application/json")) {
    throw new ApiError(415, "unsupported_media_type", "Content-Type must be application/json");
  }
  const declared = Number(req.headers["content-length"] || 0);
  if (Number.isFinite(declared) && declared > maximum) {
    req.resume();
    throw new ApiError(413, "body_too_large", "The request body is too large");
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maximum) {
      req.resume();
      throw new ApiError(413, "body_too_large", "The request body is too large");
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new ApiError(400, "invalid_json", "The request body is not valid JSON");
  }
}

function actorId(req) {
  const actor = String(req.headers["x-magpie-subject"] || "");
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(actor)) {
    throw new ApiError(400, "invalid_actor", "X-Magpie-Subject is required and invalid");
  }
  return actor;
}

function plainObject(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function safeText(value, maximum = 500, allowEmpty = false) {
  return typeof value === "string"
    && value.length <= maximum
    && (allowEmpty || value.length > 0)
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function stableId(value, prefix) {
  return typeof value === "string"
    && new RegExp(`^${prefix}[a-z0-9]{16,64}$`).test(value);
}

export class JsonStore {
  constructor(file) {
    this.file = file;
    this.data = {};
    this.queue = Promise.resolve();
  }
  async load() {
    try {
      this.data = JSON.parse(await fs.readFile(this.file, "utf8"));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await this.write(this.data);
    }
    return this.data;
  }
  async read(fn) {
    await this.queue;
    return fn(this.data);
  }
  async write(value) {
    await fs.mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const temporary = `${this.file}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`;
    const handle = await fs.open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.rename(temporary, this.file);
    this.data = value;
  }
  async mutate(fn) {
    const run = this.queue.then(async () => {
      const draft = structuredClone(this.data);
      const result = await fn(draft);
      await this.write(draft);
      return result;
    });
    this.queue = run.catch(() => {});
    return run;
  }
}

export async function createEmployeePortalServer(config, {
  store = new JsonStore(config.storePath),
  usageStore = new JsonStore(config.usageStorePath),
  ticketStore = new JsonStore(config.ticketStorePath),
  logger = () => {},
} = {}) {
  await store.load();
  await usageStore.load();
  await ticketStore.load();

  const rateLimiter = new FixedWindowRateLimiter(config.rateLimitPerMinute);

  async function withActor(req, res, operation) {
    let subject;
    try {
      subject = actorId(req);
    } catch (error) {
      const safe = error instanceof ApiError ? error : new ApiError(400, "invalid_actor", "X-Magpie-Subject is required");
      return sendJson(res, safe.statusCode, apiErrorBody(safe));
    }
    const limitKey = `${req.socket.remoteAddress}:${subject}`;
    if (!rateLimiter.consume(limitKey)) {
      const limited = new ApiError(429, "rate_limited", "Too many requests", true);
      return sendJson(res, limited.statusCode, apiErrorBody(limited));
    }
    try {
      return await operation(subject);
    } catch (error) {
      const safe = error instanceof ApiError ? error : new ApiError(500, "internal_error", "The request failed");
      if (!res.headersSent) return sendJson(res, safe.statusCode, apiErrorBody(safe));
      throw error;
    }
  }

  async function handleConfig(req, res, subject) {
    if (req.method !== "GET") {
      throw new ApiError(405, "method_not_allowed", "Use GET");
    }
    let models = [];
    let mcpServers = [];
    if (config.modelCatalogUrl) {
      try {
        const resp = await fetch(new URL("/api/v1/admin/model-catalog", config.modelCatalogUrl));
        if (resp.ok) {
          const body = await resp.json();
          models = Array.isArray(body.models) ? body.models : [];
        }
      } catch { models = []; }
    }
    if (config.adminServiceUrl && config.adminServiceToken) {
      try {
        const resp = await fetch(new URL("/api/v1/admin/mcp/servers", config.adminServiceUrl), {
          headers: { authorization: `Bearer ${config.adminServiceToken}` },
        });
        if (resp.ok) {
          const body = await resp.json();
          mcpServers = Array.isArray(body.servers) ? body.servers : [];
        }
      } catch { mcpServers = []; }
    }
    return sendJson(res, 200, {
      subjectId: subject,
      models,
      mcpServers,
      providerOptions: [
        { id: "builtin", label: "Built-in provider" },
        { id: "plugin", label: "Plugin provider" },
      ],
    });
  }

  async function handleConfigApply(req, res, subject) {
    if (req.method !== "POST") {
      throw new ApiError(405, "method_not_allowed", "Use POST");
    }
    const body = await readBody(req, config.maxBodyBytes || 256 * 1024);
    if (!body || !plainObject(body)) {
      throw new ApiError(400, "invalid_request", "Request body is required");
    }
    if (!stableId(body.providerId || "", "prov_") && body.providerId !== "builtin" && body.providerId !== "plugin") {
      throw new ApiError(400, "invalid_request", "providerId is invalid");
    }
    if (!safeText(body.model, 128)) {
      throw new ApiError(400, "invalid_request", "model is required");
    }
    const configDoc = {
      version: "1.0",
      subjectId: subject,
      provider: body.providerId || "builtin",
      model: body.model,
      mcpServers: Array.isArray(body.mcpServers) ? body.mcpServers : [],
      env: plainObject(body.env) ? body.env : {},
      createdAt: new Date().toISOString(),
    };
    await store.mutate((data) => {
      data[`agent_config_${subject}`] = configDoc;
    });
    return sendJson(res, 201, {
      ok: true,
      config: configDoc,
      message: "Agent configuration applied. Restart your local agent to pick it up.",
    });
  }

  async function handleUsagePersonal(req, res, subject) {
    if (req.method !== "GET") {
      throw new ApiError(405, "method_not_allowed", "Use GET");
    }
    const url = new URL(req.url, "http://localhost");
    const period = url.searchParams.get("period") || "month";
    if (!["day", "month", "all"].includes(period)) {
      throw new ApiError(400, "invalid_request", "period must be day, month, or all");
    }
    const usage = await usageStore.read((data) => {
      const entries = Object.values(data.usage || {});
      const now = new Date();
      const filtered = entries.filter((e) => e.subjectId === subject);
      if (period === "day") {
        const today = now.toISOString().slice(0, 10);
        return filtered.filter((e) => e.date === today);
      }
      if (period === "month") {
        const month = now.toISOString().slice(0, 7);
        return filtered.filter((e) => e.date.startsWith(month));
      }
      return filtered;
    });
    const totals = usage.reduce((acc, e) => {
      acc.tokens += Number(e.tokens || 0);
      acc.cost += Number(e.cost || 0);
      acc.requests += Number(e.requests || 0);
      return acc;
    }, { tokens: 0, cost: 0, requests: 0 });
    totals.cost = Number(totals.cost.toFixed(6));
    return sendJson(res, 200, {
      subjectId: subject,
      period,
      entries: usage,
      totals,
    });
  }

  async function handleTicketsList(req, res, subject) {
    if (req.method !== "GET") {
      throw new ApiError(405, "method_not_allowed", "Use GET");
    }
    const tickets = await ticketStore.read((data) => {
      return Object.values(data.tickets || {})
        .filter((t) => t.subjectId === subject)
        .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
    });
    return sendJson(res, 200, { tickets });
  }

  async function handleTicketCreate(req, res, subject) {
    if (req.method !== "POST") {
      throw new ApiError(405, "method_not_allowed", "Use POST");
    }
    const body = await readBody(req, config.maxBodyBytes || 256 * 1024);
    if (!body || !plainObject(body)) {
      throw new ApiError(400, "invalid_request", "Request body is required");
    }
    if (!safeText(body.title, 200)) {
      throw new ApiError(400, "invalid_request", "title is required");
    }
    if (!safeText(body.description, 5000, true)) {
      throw new ApiError(400, "invalid_request", "description is too long");
    }
    const ticket = {
      id: `tk_${crypto.randomUUID().replaceAll("-", "")}`,
      subjectId: subject,
      title: body.title,
      description: body.description || "",
      status: "open",
      priority: body.priority === "high" ? "high" : "normal",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await ticketStore.mutate((data) => {
      data.tickets = data.tickets || {};
      data.tickets[ticket.id] = ticket;
    });
    return sendJson(res, 201, { ticket });
  }

  async function handleTicketGet(req, res, subject, ticketId) {
    if (req.method !== "GET") {
      throw new ApiError(405, "method_not_allowed", "Use GET");
    }
    const ticket = await ticketStore.read((data) => data.tickets?.[ticketId]);
    if (!ticket) {
      throw new ApiError(404, "not_found", "Ticket not found");
    }
    if (ticket.subjectId !== subject) {
      throw new ApiError(403, "forbidden", "You can only view your own tickets");
    }
    return sendJson(res, 200, { ticket });
  }

  const server = http.createServer(async (req, res) => {
    const context = { requestId: requestId(), remoteAddress: String(req.socket.remoteAddress || "unknown") };
    try {
      const url = new URL(req.url || "/", "http://localhost");
      if (url.pathname === "/healthz") {
        if (req.method !== "GET") throw new ApiError(405, "method_not_allowed", "Use GET");
        return sendJson(res, 200, { service: "employee-portal", version: SERVER_VERSION });
      }
      if ((url.pathname === "/" || url.pathname === "/portal") && req.method === "GET") {
        const [usageData, ticketData] = await Promise.all([
          usageStore.read((data) => data),
          ticketStore.read((data) => data),
        ]);
        const html = Buffer.from(portalPage({ ...usageData, ...ticketData }), "utf8");
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "content-length": String(html.length),
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
        });
        res.end(html);
        return;
      }

      if (url.pathname.startsWith(`${API_PREFIX}/config`)) {
        if (url.pathname === `${API_PREFIX}/config/apply`) {
          return withActor(req, res, (subject) => handleConfigApply(req, res, subject));
        }
        if (url.pathname === `${API_PREFIX}/config`) {
          return withActor(req, res, (subject) => handleConfig(req, res, subject));
        }
        throw new ApiError(404, "not_found", "The route was not found");
      }
      if (url.pathname === `${API_PREFIX}/usage/personal`) {
        return withActor(req, res, (subject) => handleUsagePersonal(req, res, subject));
      }
      if (url.pathname === `${API_PREFIX}/tickets`) {
        if (req.method === "GET") {
          return withActor(req, res, (subject) => handleTicketsList(req, res, subject));
        }
        if (req.method === "POST") {
          return withActor(req, res, (subject) => handleTicketCreate(req, res, subject));
        }
        throw new ApiError(405, "method_not_allowed", "Use GET or POST");
      }
      const ticketMatch = /^\/api\/v1\/portal\/tickets\/([A-Za-z0-9_-]+)$/.exec(url.pathname);
      if (ticketMatch) {
        return withActor(req, res, (subject) => handleTicketGet(req, res, subject, ticketMatch[1]));
      }
      throw new ApiError(404, "not_found", "The route was not found");
    } catch (error) {
      const safe = error instanceof ApiError ? error : new ApiError(500, "internal_error", "The request failed");
      if (!(error instanceof ApiError)) {
        logger({ requestId: context.requestId, code: safe.code, errorName: error?.name || "Error" });
      }
      if (!res.headersSent) sendJson(res, safe.statusCode, apiErrorBody(safe));
      else res.destroy();
    }
  });

  return { server, store, usageStore, ticketStore };
}
