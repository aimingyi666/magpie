// magpie-corp-server: an internal control plane for the magpie corp plugin.
//
// It is small on purpose: it does what the protocol in
// devtools/corp-plugin-protocol.md says and nothing else, so it can be read
// as the reference the real service is built from.
//
// The one thing worth looking at twice: a device's token IS a gateway key.
// On enroll, this server asks the gateway's admin API to make a caller key
// for that person, and hands the key's value to the device. From then on
// the gateway checks every model request itself; this server never sees
// model traffic.
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import os from "node:os";

import { createKeySet, verifyIdToken, TokenError } from "./oidc.mjs";

// ---- settings -------------------------------------------------------------

const HERE = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const STATE_FILE = process.env.CORP_STATE_FILE || path.join(HERE, "state.json");

function env(name, fallback = "") {
  return String(process.env[name] || fallback).trim();
}

const CONFIG = {
  port: Number(env("CORP_PORT", "3600")) || 3600,
  // where the gateway's admin API is, and the token it takes
  gatewayAdminUrl: env("CORP_GATEWAY_ADMIN_URL", "http://127.0.0.1:3501"),
  gatewayAdminToken: env("CORP_GATEWAY_ADMIN_TOKEN", ""),
  // what a device is handed; the gateway itself, never a vendor
  gatewayPublicUrl: env("CORP_GATEWAY_PUBLIC_URL", "http://127.0.0.1:3499/v1"),
  publicUrl: env("CORP_PUBLIC_URL", `http://127.0.0.1:${env("CORP_PORT", "3600")}`),
  corporateName: env("CORP_NAME", "示例公司"),

  oidc: {
    issuer: env("CORP_OIDC_ISSUER", "https://sso.example.com"),
    authorizationEndpoint: env("CORP_OIDC_AUTHORIZE", "https://sso.example.com/oauth2/authorize"),
    clientId: env("CORP_OIDC_CLIENT_ID", "magpie-corp"),
    clientSecret: env("CORP_OIDC_CLIENT_SECRET", ""),
    scopes: ["openid", "profile", "email"],
    // how far two clocks may disagree before a token is called expired
    clockToleranceSeconds: Number(env("CORP_OIDC_CLOCK_TOLERANCE_SECONDS", "60")) || 60,
  },
  // A directory of demos signs a device in without an identity provider,
  // so the client can be watched end to end on a laptop. Never on in
  // production: it is refused the moment a secret is configured.
  allowDemoSignIn: env("CORP_ALLOW_DEMO_SIGNIN", "false") === "true",

  // each person's key: the models they may use and what it may spend
  plan: {
    models: env("CORP_PLAN_MODELS", "*").split(",").map((m) => m.trim()).filter(Boolean),
    limit: env("CORP_PLAN_LIMIT", "") ? JSON.parse(env("CORP_PLAN_LIMIT")) : null,
  },
  deviceTokenDays: Number(env("CORP_DEVICE_TOKEN_DAYS", "90")) || 90,
};

// ---- storage --------------------------------------------------------------

function emptyState() {
  return { version: 1, devices: {}, users: {}, bundleRevision: "rev_1", bundles: {}, usage: [], masking: [] };
}

function loadState() {
  try {
    const value = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) return emptyState();
    return { ...emptyState(), ...value };
  } catch {
    return emptyState();
  }
}

const state = loadState();

function saveState() {
  const body = `${JSON.stringify(state, null, 2)}\n`;
  const temporary = `${STATE_FILE}.${process.pid}.tmp`;
  fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
  fs.writeFileSync(temporary, body, { mode: 0o600 });
  fs.renameSync(temporary, STATE_FILE);
}

// ---- the gateway's admin API ----------------------------------------------

class GatewayError extends Error {
  constructor(code, message, status = 0) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

async function gatewayAdmin(method, pathname, body) {
  if (!CONFIG.gatewayAdminToken) {
    throw new GatewayError("gateway_not_configured", "CORP_GATEWAY_ADMIN_TOKEN is not set");
  }
  let response;
  try {
    response = await fetch(new URL(pathname, CONFIG.gatewayAdminUrl), {
      method,
      headers: {
        authorization: `Bearer ${CONFIG.gatewayAdminToken}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(15000),
    });
  } catch (error) {
    throw new GatewayError("gateway_unreachable", `the gateway's admin API is unreachable: ${error?.message || error}`);
  }
  const text = await response.text();
  let payload = null;
  if (text.trim()) {
    try {
      payload = JSON.parse(text);
    } catch {
      throw new GatewayError("gateway_bad_response", `the gateway answered something unreadable (${response.status})`, response.status);
    }
  }
  if (!response.ok) {
    const code = payload?.error?.code || `gateway_http_${response.status}`;
    throw new GatewayError(code, payload?.error?.message || `the gateway answered ${response.status}`, response.status);
  }
  return payload;
}

// issueDeviceKey makes this person's gateway key. The key's value comes
// back once, here, and is kept only as its SHA-256: a restart can still
// find and revoke a key by the hash it stored, but cannot print the key
// again. A device that joins twice gets a fresh key, and the one before
// is revoked, so no key outlives the device it was made for.
async function issueDeviceKey({ deviceId, email, name }) {
  const created = await gatewayAdmin("POST", "/v1/magpie/admin/gateway/keys", {
    name: keyNameFor(email, deviceId),
    ...(CONFIG.plan.models.includes("*") ? {} : { models: CONFIG.plan.models, modelsSet: true }),
    ...(CONFIG.plan.limit ? { limit: CONFIG.plan.limit, limitSet: true } : {}),
  });
  const secret = String(created?.secret || "");
  const keyID = String(created?.key?.id || "");
  if (!secret || !keyID) {
    throw new GatewayError("gateway_no_key", "the gateway made a key without a value");
  }
  return { keyID, secret, digest: sha256(secret), name: keyNameFor(email, deviceId) };
}

// revokeDeviceKey takes a key out of the gateway. The gateway has no DELETE
// for one: a PATCH with remove:true takes it away (internal/gateway/admin.go,
// adminGatewayKeyPatch's Remove), and it needs the key's current revision,
// which is read first.
async function revokeDeviceKey(keyID) {
  if (!keyID) return;
  try {
    const listed = await gatewayAdmin("GET", "/v1/magpie/admin/gateway/keys");
    const key = (Array.isArray(listed?.keys) ? listed.keys : []).find((k) => k.id === keyID);
    if (!key) return; // already gone: what was wanted
    await gatewayAdmin("PATCH", `/v1/magpie/admin/gateway/keys/${encodeURIComponent(keyID)}`, {
      expectedRevision: String(key.revision || ""),
      remove: true,
    });
    console.log(`corp: revoked gateway key ${keyID}`);
  } catch (error) {
    // a key already gone is what was wanted; anything else is logged and
    // the device is still marked revoked here, so it can't be refreshed
    console.error("corp: revoking gateway key", keyID, "failed:", error?.message || error);
  }
}

function keyNameFor(email, deviceId) {
  return `corp:${email}:${String(deviceId).slice(-6)}`;
}

// ---- the bundle the corporation hands out ---------------------------------

function currentBundle() {
  return state.bundles[state.bundleRevision] || {
    schemaVersion: 1,
    revision: state.bundleRevision,
    providers: [
      {
        id: "corp",
        name: "企业网关",
        mode: "gateway",
        baseUrl: CONFIG.gatewayPublicUrl,
        npm: "@ai-sdk/openai-compatible",
        models: ["deepseek-v4-pro", "deepseek-flash"],
        defaultModel: "deepseek-v4-pro",
        enabled: true,
      },
    ],
    instructions: [],
    mcp: [],
    skills: [],
  };
}

// ---- identity -------------------------------------------------------------

function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

// exchangeCode trades an OIDC authorization code for the person's claims.
// In the demo mode there is no identity provider: the "code" is a demo
// address, and this is refused unless CORP_ALLOW_DEMO_SIGNIN=true and no
// client secret is set.
async function exchangeCode(code, redirectUri, nonce) {
  if (!CONFIG.oidc.clientSecret) {
    if (!CONFIG.allowDemoSignIn) {
      throw new HttpError(501, "oidc_not_configured", "the identity provider is not set up: CORP_OIDC_CLIENT_SECRET is missing");
    }
    const email = String(code || "").replace(/^demo:/, "");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      throw new HttpError(400, "demo_code_invalid", "a demo sign-in is demo:someone@example.com");
    }
    return { subject: `demo:${email}`, email, name: email.split("@")[0], groups: ["engineering"] };
  }
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: CONFIG.oidc.clientId,
    client_secret: CONFIG.oidc.clientSecret,
  });
  let response;
  try {
    response = await fetch(new URL("/oauth2/token", CONFIG.oidc.issuer), {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body,
      signal: AbortSignal.timeout(15000),
    });
  } catch (error) {
    throw new HttpError(502, "idp_unreachable", `the identity provider is unreachable: ${error?.message || error}`);
  }
  const said = await response.json().catch(() => ({}));
  if (!response.ok || typeof said.id_token !== "string") {
    throw new HttpError(401, "sign_in_failed", said?.error_description || "the identity provider refused the code");
  }

  // The id_token is proved before any of it is believed: its signature
  // against the provider's published key, and the claims that say it is
  // this provider's, for this service, for this sign-in, and current.
  let claims;
  try {
    claims = await verifyIdToken(said.id_token, {
      issuer: CONFIG.oidc.issuer,
      audience: CONFIG.oidc.clientId,
      nonce: nonce === undefined ? undefined : String(nonce),
      clockToleranceSeconds: CONFIG.oidc.clockToleranceSeconds,
    }, { keySet: keySetFor(CONFIG.oidc.issuer) });
  } catch (error) {
    if (error instanceof TokenError) {
      console.error("corp: id_token refused:", error.code, error.message);
      throw new HttpError(401, error.code, error.message);
    }
    throw error;
  }
  if (!claims?.sub || !claims?.email) {
    throw new HttpError(401, "sign_in_incomplete", "the identity provider's token carries no subject or email");
  }
  return {
    subject: String(claims.sub),
    email: String(claims.email),
    name: String(claims.name || claims.email),
    groups: Array.isArray(claims.groups) ? claims.groups.map(String) : [],
  };
}

// keySetFor keeps one provider's keys for this process's life: a sign-in
// must not fetch them every time, and they change rarely.
const keySets = new Map();
function keySetFor(issuer) {
  let set = keySets.get(issuer);
  if (!set) {
    set = createKeySet({ issuer });
    keySets.set(issuer, set);
  }
  return set;
}

// ---- HTTP -----------------------------------------------------------------

class HttpError extends Error {
  constructor(status, code, message, extra) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

const MAX_BODY = 4 << 20;

async function readJson(req) {
  const declared = Number(req.headers["content-length"] || 0);
  if (Number.isFinite(declared) && declared > MAX_BODY) {
    throw new HttpError(413, "payload_too_large", "the request body is too large");
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY) throw new HttpError(413, "payload_too_large", "the request body is too large");
    chunks.push(chunk);
  }
  if (!total) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "bad_json", "the request body is not JSON");
  }
}

function send(res, status, body, headers = {}) {
  const payload = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": String(payload.length),
    "cache-control": "no-store",
    ...headers,
  });
  res.end(payload);
}

function deviceFor(req) {
  const header = String(req.headers.authorization || "");
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) throw new HttpError(401, "missing_device_token", "a device token is required");
  const digest = sha256(token);
  for (const device of Object.values(state.devices)) {
    if (device.tokenDigest === digest) {
      if (device.state !== "active") throw new HttpError(403, "device_disabled", "this device has been revoked");
      if (device.expiresAt && Date.parse(device.expiresAt) < Date.now()) {
        throw new HttpError(401, "device_token_expired", "this device's token has expired");
      }
      return device;
    }
  }
  throw new HttpError(401, "invalid_device_token", "the device token is not known here");
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", CONFIG.publicUrl);
  try {
    await route(req, res, url);
  } catch (error) {
    const status = error instanceof HttpError ? error.status
      : error instanceof GatewayError ? (error.status || 502)
        : 500;
    const code = error?.code || "internal_error";
    if (status >= 500) console.error("corp:", req.method, url.pathname, "->", code, error?.message || error);
    send(res, status, {
      error: {
        code,
        message: String(error?.message || error),
        retryable: status >= 500,
        ...(error?.extra || {}),
      },
    });
  }
});

async function route(req, res, url) {
  const p = url.pathname;

  // ---- what the client discovers about this server --------------------
  if (req.method === "GET" && p === "/api/v1/corp/config") {
    return send(res, 200, {
      schemaVersion: 1,
      corporate: CONFIG.corporateName,
      oidc: {
        issuer: CONFIG.oidc.issuer,
        authorizationEndpoint: CONFIG.oidc.authorizationEndpoint,
        clientId: CONFIG.oidc.clientId,
        scopes: CONFIG.oidc.scopes,
      },
      gateway: { baseUrl: CONFIG.gatewayPublicUrl },
      upload: { usage: true, masking: true, sessions: true, minSeconds: 60 },
      limits: { maxBatchRows: 500, maxBatchBytes: 1 << 20 },
      demoSignIn: CONFIG.allowDemoSignIn && !CONFIG.oidc.clientSecret,
    });
  }

  // ---- a device signs in ----------------------------------------------
  if (req.method === "POST" && p === "/api/v1/device/enroll") {
    const body = await readJson(req);
    const code = String(body.code || "");
    const redirectUri = String(body.redirectUri || "");
    if (!code) throw new HttpError(400, "missing_code", "an authorization code is required");

    const ident = await exchangeCode(code, redirectUri);

    // one person may have several devices; each gets its own key
    const userId = `usr_${sha256(ident.subject).slice(0, 20)}`;
    const deviceId = `dev_${crypto.randomBytes(9).toString("hex")}`;
    const previous = Object.values(state.devices).filter((d) => d.userId === userId && d.state === "active");
    for (const device of previous) await revokeDeviceKey(device.gatewayKeyID);

    const key = await issueDeviceKey({ deviceId, email: ident.email, name: ident.name });
    const token = key.secret;
    const expiresAt = new Date(Date.now() + CONFIG.deviceTokenDays * 86400 * 1000).toISOString();

    // The device before this one, of the same person, is replaced: it
    // keeps no token of its own (its key was revoked just now), so a
    // request with the old token is an unknown token, not a revoked
    // device. Only a device an administrator disabled answers "disabled".
    for (const device of previous) {
      device.state = "replaced";
      device.tokenDigest = "";
    }

    state.users[userId] = {
      id: userId, subject: ident.subject, email: ident.email, name: ident.name,
      groups: ident.groups, lastSeenAt: new Date().toISOString(),
    };
    state.devices[deviceId] = {
      id: deviceId, userId, name: String(body.device?.name || "").slice(0, 120),
      platform: String(body.device?.platform || "").slice(0, 32),
      state: "active", gatewayKeyID: key.keyID, gatewayKeyDigest: key.digest,
      tokenDigest: sha256(token), createdAt: new Date().toISOString(), expiresAt,
    };
    saveState();
    console.log(`corp: ${ident.email} enrolled (${deviceId}), gateway key ${key.keyID}`);

    return send(res, 200, {
      schemaVersion: 1,
      deviceId,
      deviceToken: token,
      expiresAt,
      user: { id: userId, email: ident.email, name: ident.name, department: ident.groups[0] || "" },
      gateway: { baseUrl: CONFIG.gatewayPublicUrl },
      bundleRevision: state.bundleRevision,
    });
  }

  // ---- the bundle -----------------------------------------------------
  if (req.method === "GET" && p === "/api/v1/client/bundle") {
    deviceFor(req);
    const asked = url.searchParams.get("revision") || String(req.headers["if-none-match"] || "").replace(/^W\/|"/g, "");
    const bundle = currentBundle();
    if (asked && asked === bundle.revision) {
      res.writeHead(304, { "cache-control": "no-store", etag: `"${bundle.revision}"` });
      return res.end();
    }
    return send(res, 200, bundle, { etag: `"${bundle.revision}"` });
  }

  // ---- usage and masking back from a device ---------------------------
  if (req.method === "POST" && p === "/api/v1/telemetry/usage") {
    const device = deviceFor(req);
    const body = await readJson(req);
    const rows = Array.isArray(body.rows) ? body.rows : [];
    const seen = new Set(state.usage.map((r) => `${device.id}|${r.rowId}`));
    let accepted = 0;
    let duplicates = 0;
    for (const row of rows) {
      const rowId = String(row?.rowId || sha256(JSON.stringify(row)));
      if (seen.has(`${device.id}|${rowId}`)) {
        duplicates += 1;
        continue;
      }
      state.usage.push({ ...sanitizeUsage(row), rowId, deviceId: device.id, userId: device.userId, at: String(row.at || "") });
      seen.add(`${device.id}|${rowId}`);
      accepted += 1;
    }
    saveState();
    console.log(`corp: usage from ${device.id}: ${accepted} accepted, ${duplicates} duplicates`);
    return send(res, 200, {
      schemaVersion: 1, accepted, duplicates, rejected: [],
      nextCursor: body.cursor?.to || new Date().toISOString(),
    });
  }

  if (req.method === "POST" && p === "/api/v1/telemetry/masking") {
    const device = deviceFor(req);
    const body = await readJson(req);
    const hits = Array.isArray(body.hits) ? body.hits : [];
    for (const hit of hits) {
      state.masking.push({ ...sanitizeMasking(hit), deviceId: device.id, userId: device.userId });
    }
    saveState();
    console.log(`corp: masking from ${device.id}: ${hits.length} hits`);
    return send(res, 200, {
      schemaVersion: 1, accepted: hits.length, duplicates: 0, rejected: [],
      nextCursor: body.cursor?.to || new Date().toISOString(),
    });
  }

  // ---- admin ----------------------------------------------------------
  if (req.method === "GET" && p === "/__admin/summary") {
    const usage = state.usage;
    return send(res, 200, {
      devices: Object.values(state.devices).map((d) => ({
        id: d.id, email: state.users[d.userId]?.email, state: d.state,
        gatewayKeyID: d.gatewayKeyID, expiresAt: d.expiresAt,
      })),
      usage: {
        rows: usage.length,
        byModel: usage.reduce((out, r) => {
          const k = r.model || "?";
          out[k] = out[k] || { calls: 0, input: 0, output: 0 };
          out[k].calls += 1;
          out[k].input += r.input || 0;
          out[k].output += r.output || 0;
          return out;
        }, {}),
      },
      masking: { hits: state.masking.length, kinds: [...new Set(state.masking.flatMap((h) => h.kinds || []))] },
      bundleRevision: state.bundleRevision,
    });
  }

  throw new HttpError(404, "not_found", "no such path");
}

// The server keeps only the fields the protocol names: a client that sends
// more, or a ledger that grows a field, can't widen what is stored.
function sanitizeUsage(row) {
  const num = (v) => (Number.isFinite(v) ? Math.max(0, Math.trunc(v)) : 0);
  return {
    agent: String(row?.agent || "").slice(0, 64),
    provider: String(row?.provider || "").slice(0, 64),
    model: String(row?.model || "").slice(0, 128),
    kind: String(row?.kind || "").slice(0, 40),
    sessionId: String(row?.sessionId || "").slice(0, 128),
    input: num(row?.input), output: num(row?.output),
    cacheRead: num(row?.cacheRead), cacheWrite: num(row?.cacheWrite),
    ms: num(row?.ms), status: num(row?.status),
    error: String(row?.error || "").slice(0, 64),
  };
}

function sanitizeMasking(hit) {
  const arr = (v) => (Array.isArray(v) ? v.map((x) => String(x).slice(0, 80)).slice(0, 32) : []);
  return {
    at: String(hit?.at || ""), agent: String(hit?.agent || "").slice(0, 64),
    provider: String(hit?.provider || "").slice(0, 64), model: String(hit?.model || "").slice(0, 128),
    what: String(hit?.what || "").slice(0, 40), blocked: hit?.blocked === true,
    count: Number.isSafeInteger(hit?.count) ? hit.count : 0,
    kinds: arr(hit?.kinds), placeholders: arr(hit?.placeholders),
    lengths: Array.isArray(hit?.lengths) ? hit.lengths.slice(0, 32).map((n) => (Number.isFinite(n) ? Math.trunc(n) : 0)) : [],
  };
}

// startServer listens and answers a small handle, so a test can run this
// file's server on a port of its own with no gateway behind it.
export function startServer({ port = CONFIG.port, config = CONFIG } = {}) {
  const listening = new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server.address().port));
  });
  return { server, listening, config };
}

// Run as a program (not imported by a test): listen and say what it runs
// with.
const runDirectly = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
if (runDirectly) {
  server.listen(CONFIG.port, "127.0.0.1", () => {
    console.log(`corp server on ${CONFIG.publicUrl}`);
    console.log(`  gateway      ${CONFIG.gatewayPublicUrl}`);
    console.log(`  gateway admin ${CONFIG.gatewayAdminUrl} ${CONFIG.gatewayAdminToken ? "(token set)" : "(NO TOKEN)"}`);
    console.log(`  demo sign-in ${CONFIG.allowDemoSignIn && !CONFIG.oidc.clientSecret ? "ON (no identity provider)" : "off"}`);
  });
}
