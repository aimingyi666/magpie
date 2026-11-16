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
  // Who may open the corporate plugin's administrator view. The groups are
  // the ones the identity provider puts in the id_token; the addresses are
  // for a directory that has no groups yet.
  adminGroups: env("CORP_ADMIN_GROUPS", "corp-admins,magpie-admins,admins")
    .split(",").map((group) => group.trim().toLowerCase()).filter(Boolean),
  adminEmails: env("CORP_ADMIN_EMAILS", "")
    .split(",").map((email) => email.trim().toLowerCase()).filter(Boolean),
  // A demo directory has no groups and no real identity provider; this
  // makes every demo account an administrator so the view can be watched.
  demoAdmin: env("CORP_DEMO_ADMIN", "false") === "true",
  // A write to an /__admin route needs this token when it is set. The
  // summary stays open on loopback, as it always was.
  adminToken: env("CORP_ADMIN_TOKEN", ""),

  // The Cursor bridge, for the people this policy names. A device whose
  // user is named gets the plugin in its bundle; the plugin installs it
  // and connects it to `model` (a magpie id, or a bare model of the corp
  // provider). Empty `users` and `groups` means nobody; "*" means all.
  cursorBridge: {
    enabled: env("CORP_CURSOR_BRIDGE", "off").toLowerCase() === "on",
    users: env("CORP_CURSOR_BRIDGE_USERS", "")
      .split(",").map((value) => value.trim().toLowerCase()).filter(Boolean),
    groups: env("CORP_CURSOR_BRIDGE_GROUPS", "")
      .split(",").map((value) => value.trim().toLowerCase()).filter(Boolean),
    model: env("CORP_CURSOR_BRIDGE_MODEL", ""),
  },

  // each person's key: the models they may use and what it may spend
  plan: {
    models: env("CORP_PLAN_MODELS", "*").split(",").map((m) => m.trim()).filter(Boolean),
    limit: env("CORP_PLAN_LIMIT", "") ? JSON.parse(env("CORP_PLAN_LIMIT")) : null,
  },
  deviceTokenDays: Number(env("CORP_DEVICE_TOKEN_DAYS", "90")) || 90,
};

// ---- storage --------------------------------------------------------------

function emptyState() {
  return {
    version: 1, devices: {}, users: {}, bundleRevision: "rev_1", bundles: {},
    sharing: { mode: "", updatedAt: "", providers: [], installed: [], catalog: [] },
    pluginPolicy: null,
    usage: [], masking: [],
    workbuddy: { shares: {}, imported: {} },
  };
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

// ---- who is an administrator ---------------------------------------------
//
// The identity provider's groups are the usual answer; an explicit address
// list is for a directory that has none yet. A demo directory has neither,
// so CORP_DEMO_ADMIN makes every demo account an administrator and the
// view can be watched on a laptop.

function roleOf(user) {
  if (!user) return "member";
  const groups = Array.isArray(user.groups) ? user.groups.map((group) => String(group).toLowerCase()) : [];
  if (groups.some((group) => CONFIG.adminGroups.includes(group))) return "admin";
  const email = String(user.email || "").toLowerCase();
  if (email && CONFIG.adminEmails.includes(email)) return "admin";
  if (CONFIG.demoAdmin && String(user.subject || "").startsWith("demo:")) return "admin";
  return "member";
}

// ---- sharing the native magpie's providers -------------------------------
//
// Two ways an administrator shares what the magpie on their computer holds:
//
//   native  the providers and their keys are written into the corporate
//           gateway's own provider list, so the gateway calls the vendors.
//           The keys are sent once and are not kept in this server's state.
//   remote  the gateway already is a magpie with providers of its own; this
//           server only publishes its model list (a Remote magpie).
//   off     publish no enterprise provider at all.

const SHARING_MODES = new Set(["native", "remote", "off"]);

function clean(value, max = 200) {
  return String(value ?? "").trim().slice(0, max);
}

function modelList(value) {
  const list = Array.isArray(value) ? value : [];
  return [...new Set(list.map((model) => clean(model, 200)).filter(Boolean))].slice(0, 500);
}

function maskKey(secret) {
  const value = String(secret || "");
  if (!value) return "";
  if (value.length <= 8) return "…";
  return `…${value.slice(-6)}`;
}

function publicSharing() {
  const sharing = state.sharing || {};
  const sources = (Array.isArray(sharing.providers) ? sharing.providers : []).map((provider) => ({
    id: clean(provider.id, 64),
    name: clean(provider.name, 120) || clean(provider.id, 64),
    models: Array.isArray(provider.models) ? provider.models : [],
    modelCount: Array.isArray(provider.models) ? provider.models.length : 0,
    keyCount: Number(provider.keyCount) || 0,
    keyMasked: clean(provider.keyMasked, 40),
    gatewayProviderId: clean(provider.gatewayProviderId, 64),
    available: provider.available !== false,
  }));
  for (const source of importedSources(sharing)) {
    sources.push({
      id: source.id,
      name: source.name,
      models: source.models,
      modelCount: source.models.length,
      keyCount: 0,
      keyMasked: "",
      gatewayProviderId: source.provider,
      available: true,
    });
  }
  return {
    mode: clean(sharing.mode, 16),
    updatedAt: clean(sharing.updatedAt, 40),
    catalog: sharedCatalog(sharing),
    sources,
  };
}

function catalogOf(providers) {
  const out = [];
  for (const provider of Array.isArray(providers) ? providers : []) {
    for (const model of Array.isArray(provider.models) ? provider.models : []) {
      if (model && !out.includes(model)) out.push(model);
    }
  }
  return out;
}

async function gatewayProviders() {
  const listed = await gatewayAdmin("GET", "/v1/magpie/admin/providers");
  return Array.isArray(listed?.providers) ? listed.providers : [];
}

// installNativeProviders writes each shared provider into the gateway. A
// failure part way takes back what this call already made: a share that
// only half landed would bill or expose the wrong vendor.
async function installNativeProviders(providers) {
  const installed = [];
  try {
    for (const provider of providers) {
      const name = clean(provider.name, 120) || clean(provider.id, 64);
      const models = modelList(provider.models);
      const keys = [...new Set([provider.key, ...(Array.isArray(provider.keys) ? provider.keys : [])]
        .map((key) => clean(key, 4096)).filter(Boolean))];
      if (!keys.length) throw new GatewayError("invalid_sharing", `供应商 ${name} 没有 API Key`);
      if (!models.length) throw new GatewayError("invalid_sharing", `供应商 ${name} 没有选择模型`);
      const body = {
        name,
        models,
        modelsSet: true,
        key: keys[0],
      };
      if (keys.length > 1) body.addKeys = keys.slice(1);
      if (clean(provider.preset, 64)) body.preset = clean(provider.preset, 64);
      for (const field of ["chat", "responses", "anthropic", "gemini"]) {
        if (clean(provider[field], 2048)) body[field] = clean(provider[field], 2048);
      }
      if (clean(provider.baseAPI, 32)) body.baseAPI = clean(provider.baseAPI, 32);
      let made;
      try {
        made = await gatewayAdmin("POST", "/v1/magpie/admin/providers", body);
      } catch (error) {
        // A preset the gateway does not know is not a reason to refuse a
        // share that already carries the endpoints: the fields are enough.
        if (!body.preset || error?.code !== "invalid_preset") throw error;
        const { preset, ...withoutPreset } = body;
        made = await gatewayAdmin("POST", "/v1/magpie/admin/providers", withoutPreset);
      }
      const gatewayProviderId = clean(made?.provider?.id, 64);
      if (!gatewayProviderId) {
        throw new GatewayError("gateway_no_provider", `网关创建了供应商 ${name} 但没有返回 id`);
      }
      installed.push({
        id: clean(provider.id, 64) || gatewayProviderId,
        name,
        gatewayProviderId,
        models,
        keyCount: keys.length,
        keyMasked: maskKey(keys[0]),
      });
    }
    return installed;
  } catch (error) {
    await removeGatewayProviders(installed.map((provider) => provider.gatewayProviderId));
    throw error;
  }
}

// removeGatewayProviders takes back only the ids this server wrote. A
// provider an administrator added to the gateway by hand is never touched.
async function removeGatewayProviders(ids) {
  const wanted = new Set((Array.isArray(ids) ? ids : []).map((id) => clean(id, 64)).filter(Boolean));
  if (!wanted.size) return [];
  let listed;
  try {
    listed = await gatewayProviders();
  } catch (error) {
    console.error("corp: reading gateway providers to remove a share failed:", error?.message || error);
    return [...wanted];
  }
  const byId = new Map(listed.map((provider) => [provider.id, provider]));
  const failed = [];
  for (const id of wanted) {
    const provider = byId.get(id);
    if (!provider) continue;
    try {
      await gatewayAdmin("DELETE", `/v1/magpie/admin/providers/${encodeURIComponent(id)}`, {
        expectedRevision: String(provider.revision || ""),
      });
    } catch (error) {
      console.error("corp: removing gateway provider", id, "failed:", error?.message || error);
      failed.push(id);
    }
  }
  return failed;
}

async function remoteCatalog(models) {
  const asked = modelList(models);
  if (asked.length) return asked;
  try {
    const providers = await gatewayProviders();
    const out = [];
    for (const provider of providers) {
      if (provider.off) continue;
      for (const model of Array.isArray(provider.models) ? provider.models : []) {
        if (model && !out.includes(model)) out.push(model);
      }
    }
    return out.slice(0, 500);
  } catch (error) {
    console.error("corp: reading the gateway's providers for a Remote magpie share failed:", error?.message || error);
    return modelList(CONFIG.plan.models.filter((model) => model !== "*"));
  }
}

// ---- an employee's own WorkBuddy account ---------------------------------
//
// A person signs in to WorkBuddy in their own browser; the gateway's
// WorkBuddy plugin runs the sign-in and keeps the account there. This
// server drives the flow and records what came of it: it starts the
// sign-in, hands the person the vendor's page, and once the sign-in is
// done reads the models the gateway now serves and adds them to what the
// corporation hands out. A person who is already signed in in their own
// magpie has that sign-in imported instead (see importWorkbuddySignIn):
// it passes through once, to the gateway, and is written nowhere here.

const WORKBUDDY_PROVIDERS = new Map([
  ["workbuddy", "WorkBuddy（国内版）"],
  ["workbuddy-ai", "WorkBuddy（国际版）"],
]);

const SHARE_PREFIX = "/api/v1/share/workbuddy/";

function workbuddyState() {
  if (!state.workbuddy || typeof state.workbuddy !== "object") state.workbuddy = { shares: {}, imported: {} };
  if (!state.workbuddy.shares || typeof state.workbuddy.shares !== "object") state.workbuddy.shares = {};
  if (!state.workbuddy.imported || typeof state.workbuddy.imported !== "object") state.workbuddy.imported = {};
  return state.workbuddy;
}

// shareStateOf is the gateway's sign-in state as the employee's page names
// it: installing and waiting are both "the page is open, scan when ready".
function shareStateOf(value) {
  if (value === "done" || value === "failed" || value === "canceled") return value;
  return "waiting";
}

function sharingServes(sharing = state.sharing) {
  const mode = clean(sharing?.mode, 16);
  return mode === "native" || mode === "remote";
}

// selectedModels is what an administrator ticked of one imported provider.
// Nothing an employee shares reaches anyone else until they do: the
// account is in the gateway either way, but the models are the
// corporation's call.
function selectedModels(item) {
  const all = Array.isArray(item?.models) ? item.models : [];
  const picked = Array.isArray(item?.selected) ? item.selected : [];
  return all.filter((model) => picked.includes(model));
}

// sameModels says two lists name the same models, whatever their order: a
// tick that only reorders them changes nothing a device would see.
function sameModels(one, two) {
  const a = [...(Array.isArray(one) ? one : [])].sort();
  const b = [...(Array.isArray(two) ? two : [])].sort();
  return a.length === b.length && a.every((model, index) => model === b[index]);
}

// importedModels is every model the administrator handed out of the
// accounts employees shared.
function importedModels() {
  const out = [];
  for (const item of Object.values(workbuddyState().imported)) {
    for (const model of selectedModels(item)) {
      if (model && !out.includes(model)) out.push(model);
    }
  }
  return out;
}

// importedSources is those models in the shape a share's sources take, so
// an administrator and a device see where a model came from.
function importedSources(sharing = state.sharing) {
  if (!sharingServes(sharing)) return [];
  const out = [];
  for (const item of Object.values(workbuddyState().imported)) {
    const models = selectedModels(item);
    if (!models.length) continue;
    out.push({
      provider: clean(item.provider, 64),
      id: clean(item.provider, 64),
      name: `${clean(item.name, 120) || clean(item.provider, 64)}（员工共享）`,
      models,
    });
  }
  return out;
}

// sharedCatalog is the models the corporation hands out: what the
// administrator shared, plus what they ticked of what employees' own
// accounts brought in. With sharing off they stay recorded in the
// administrator's view and are not handed to anyone.
function sharedCatalog(sharing = state.sharing) {
  const base = Array.isArray(sharing?.catalog) && sharing.catalog.length
    ? sharing.catalog
    : catalogOf(sharing?.providers);
  const out = [];
  for (const model of base) if (model && !out.includes(model)) out.push(model);
  if (sharingServes(sharing)) {
    for (const model of importedModels()) if (!out.includes(model)) out.push(model);
  }
  return out;
}

function publicShare(share) {
  const provider = clean(share?.provider, 40);
  return {
    id: clean(share?.id, 64),
    provider,
    providerName: WORKBUDDY_PROVIDERS.get(provider) || provider,
    state: shareStateOf(share?.state),
    url: clean(share?.url, 2000),
    account: clean(share?.account, 200),
    models: Array.isArray(share?.models) ? share.models.slice(0, 500) : [],
    error: clean(share?.error, 300),
    createdAt: clean(share?.createdAt, 40),
    updatedAt: clean(share?.updatedAt, 40),
    completedAt: clean(share?.completedAt, 40),
  };
}

// shareFailure is a gateway answer as an employee can act on it: "the
// plugin isn't loaded" rather than the admin API's own wording.
function shareFailure(error) {
  if (!(error instanceof GatewayError)) return error;
  if (error.code === "gateway_not_configured") {
    return new HttpError(503, "workbuddy_unavailable", "企业网关还没有配置管理接口，请联系管理员");
  }
  if (error.status === 400) {
    return new HttpError(409, "workbuddy_unavailable", "企业网关还没有安装或加载 WorkBuddy 插件，请联系管理员");
  }
  if (error.code === "gateway_unreachable") {
    return new HttpError(502, "workbuddy_unreachable", "企业网关暂时连不上，请稍后再试");
  }
  return error;
}

// pruneShares drops what nobody will look at again: finished shares older
// than a month, and all but the newest 500.
function pruneShares() {
  const store = workbuddyState();
  const cut = Date.now() - 30 * 86400 * 1000;
  for (const share of Object.values(store.shares)) {
    const finished = share.state === "done" || share.state === "canceled" || share.state === "failed";
    if (finished && Date.parse(share.updatedAt || share.createdAt || "") < cut) delete store.shares[share.id];
  }
  const left = Object.values(store.shares).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  for (const share of left.slice(500)) delete store.shares[share.id];
}

async function startWorkbuddyShare(device, user, provider) {
  let started;
  try {
    // Concurrent: another person's sign-in to the same provider keeps
    // waiting instead of being canceled, so two employees can scan at once.
    started = await gatewayAdmin("POST", "/v1/magpie/admin/plugin-signin", {
      provider, method: 0, concurrent: true,
    });
  } catch (error) {
    throw shareFailure(error);
  }
  const signInId = clean(started?.id, 120);
  if (!signInId) throw new GatewayError("gateway_no_signin", "the gateway started no sign-in");
  const now = new Date().toISOString();
  const share = {
    id: `shr_${crypto.randomBytes(12).toString("hex")}`,
    signInId,
    provider,
    deviceId: device.id,
    userId: user.id,
    state: shareStateOf(started?.state),
    url: clean(started?.url, 2000),
    account: "",
    models: [],
    error: clean(started?.error, 300),
    createdAt: now,
    updatedAt: now,
    completedAt: "",
  };
  pruneShares();
  workbuddyState().shares[share.id] = share;
  saveState();
  console.log(`corp: ${user.email} started sharing ${provider} (${share.id})`);
  return { share, instructions: clean(started?.instructions, 2000) };
}

// importWorkbuddySignIn puts a sign-in the employee's own magpie already
// holds into the gateway's provider, then records the models it serves.
// The sign-in is written to the gateway and dropped here: it is in no
// field of the state, no answer and no log. The employee's own magpie
// forgets its copy after this answer (the plugin does it), so two hosts
// never renew one token.
async function importWorkbuddySignIn(device, user, provider, auth) {
  let imported;
  try {
    imported = await gatewayAdmin("POST", "/v1/magpie/admin/plugin-import", { provider, auth });
  } catch (error) {
    throw shareFailure(error);
  }
  const key = clean(imported?.account, 200);
  if (!key) throw new GatewayError("gateway_no_account", "the gateway imported no account");
  const now = new Date().toISOString();
  const share = {
    id: `shr_${crypto.randomBytes(12).toString("hex")}`,
    signInId: "",
    provider,
    deviceId: device.id,
    userId: user.id,
    state: "done",
    url: "",
    account: clean(auth.accountId || auth.metadata?.email || auth.email, 200) || key,
    models: [],
    error: "",
    createdAt: now,
    updatedAt: now,
    completedAt: now,
  };
  pruneShares();
  workbuddyState().shares[share.id] = share;
  try {
    await importWorkbuddyAccount(share);
  } catch (error) {
    // the account is in the gateway either way; the models are asked again
    // by the next share, and the administrator can tick them then
    share.error = `账号已导入企业网关，但读取模型失败：${error?.message || error}`;
  }
  share.updatedAt = new Date().toISOString();
  saveState();
  console.log(`corp: ${user.email} imported ${provider} account ${key} from ${device.id} (${share.id})`);
  return share;
}

// importWorkbuddyAccount reads the models the gateway now serves for the
// provider and records them. The vendor's own list is asked again (the
// provider's models action), because a freshly signed-in account brings
// models the gateway has not saved picks for yet.
async function importWorkbuddyAccount(share) {
  const label = WORKBUDDY_PROVIDERS.get(share.provider) || share.provider;
  let listed;
  try {
    listed = await gatewayAdmin("POST", "/v1/magpie/admin/provider/models", { id: share.provider });
  } catch (error) {
    throw shareFailure(error);
  }
  const provider = listed?.provider;
  if (!provider) {
    throw new GatewayError("provider_missing", `企业网关里还没有 ${label}：请管理员先安装并加载 WorkBuddy 插件`);
  }
  const models = [];
  for (const model of Array.isArray(provider.models) ? provider.models : []) {
    const id = clean(model?.id, 200);
    // a model its owner unticked is not one the corporation should serve
    if (id && model.on !== false && !models.includes(id)) models.push(id);
  }

  const store = workbuddyState();
  const now = new Date().toISOString();
  const existing = store.imported[share.provider] || {};
  const accounts = Array.isArray(existing.accounts) ? existing.accounts.slice() : [];
  // what the administrator had already handed out of this provider: a
  // model the account no longer lists drops out with it
  const before = selectedModels(existing);
  const account = clean(share.account, 200);
  const at = account
    ? accounts.findIndex((item) => clean(item.account, 200).toLowerCase() === account.toLowerCase())
    : -1;
  const entry = {
    account,
    email: clean(state.users[share.userId]?.email, 200),
    deviceId: share.deviceId,
    userId: share.userId,
    at: now,
  };
  if (at >= 0) accounts[at] = { ...accounts[at], ...entry };
  else accounts.unshift(entry);
  store.imported[share.provider] = {
    provider: share.provider,
    name: clean(provider.name, 120) || label,
    models,
    selected: before.filter((model) => models.includes(model)),
    accounts: accounts.slice(0, 100),
    at: now,
  };
  share.models = models;
  if (!models.length) share.error = `账号已导入，但 ${label} 还没有列出模型；可以稍后重新共享一次`;
  // A model the account stopped listing must stop reaching devices; new
  // ones wait for the administrator, who ticks what to hand out.
  if (sharingServes() && !sameModels(selectedModels(store.imported[share.provider]), before)) {
    bumpRevision();
  }
  return models;
}

// adminWorkbuddy is what an administrator's page sees of the accounts
// employees shared: every model the gateway listed, what is handed out
// now, and who shared it. The accounts' names and emails stay here; no
// token is part of this.
function adminWorkbuddy(sharing = state.sharing) {
  return {
    serving: sharingServes(sharing),
    sources: Object.values(workbuddyState().imported).map((item) => ({
      provider: clean(item.provider, 64),
      name: clean(item.name, 120) || clean(item.provider, 64),
      models: Array.isArray(item.models) ? item.models.slice(0, 500) : [],
      selected: selectedModels(item),
      accounts: (Array.isArray(item.accounts) ? item.accounts : []).slice(0, 100).map((account) => ({
        account: clean(account.account, 200),
        email: clean(account.email, 200),
        at: clean(account.at, 40),
      })),
      at: clean(item.at, 40),
      selectedAt: clean(item.selectedAt, 40),
    })),
  };
}

// selectWorkbuddyModels is the administrator tick: which of an imported
// provider's models the corporation hands out. A change publishes a new
// bundle revision, so every device's next sync picks it up.
function selectWorkbuddyModels(provider, models) {
  const store = workbuddyState();
  const item = store.imported[provider];
  if (!item) throw new HttpError(404, "not_found", "no employee has shared that provider");
  const all = Array.isArray(item.models) ? item.models : [];
  const picked = [];
  for (const model of Array.isArray(models) ? models : []) {
    const id = clean(model, 200);
    if (!id) continue;
    if (!all.includes(id)) {
      throw new HttpError(422, "unknown_model", `${id} is not one of this provider's models`);
    }
    if (!picked.includes(id)) picked.push(id);
  }
  const before = selectedModels(item);
  item.selected = picked;
  item.selectedAt = new Date().toISOString();
  if (sharingServes() && !sameModels(before, picked)) bumpRevision();
  saveState();
  return adminWorkbuddy();
}

async function refreshWorkbuddyShare(share) {
  if (share.state === "done" || share.state === "canceled") return { share, instructions: "" };
  const before = JSON.stringify([share.state, share.url, share.account, share.error, share.models]);
  let st = null;
  try {
    st = await gatewayAdmin("GET", `/v1/magpie/admin/signin/${encodeURIComponent(share.signInId)}`);
  } catch (error) {
    if (!(error instanceof GatewayError && error.status === 404)) throw shareFailure(error);
    share.state = "failed";
    share.error = "这次登录在网关上已经失效，请重新发起共享";
  }
  let instructions = "";
  if (st) {
    instructions = clean(st.instructions, 2000);
    if (clean(st.url, 2000)) share.url = clean(st.url, 2000);
    const next = shareStateOf(st.state);
    if (next === "failed" || next === "canceled") {
      share.state = next;
      share.error = clean(st.error, 300) || (next === "canceled" ? "已取消" : "登录失败，请重试");
      share.url = "";
    } else if (next === "done") {
      // the account is in the gateway; what remains is recording it here
      share.state = "waiting";
      share.account = clean(st.user, 200) || share.account;
      share.error = "";
      try {
        await importWorkbuddyAccount(share);
        share.state = "done";
        share.url = "";
        share.completedAt = new Date().toISOString();
        console.log(`corp: ${share.provider} account ${share.account} imported (${share.id})`);
      } catch (error) {
        share.error = `WorkBuddy 账号已登录，但导入供应商失败：${error?.message || error}`;
      }
    } else {
      share.state = "waiting";
      share.error = clean(st.error, 300);
    }
  }
  const after = JSON.stringify([share.state, share.url, share.account, share.error, share.models]);
  if (after !== before) {
    share.updatedAt = new Date().toISOString();
    saveState();
  }
  return { share, instructions };
}

async function cancelWorkbuddyShare(share) {
  if (share.state === "done" || share.state === "canceled") return share;
  try {
    await gatewayAdmin("POST", `/v1/magpie/admin/signin/${encodeURIComponent(share.signInId)}/cancel`);
  } catch (error) {
    // a sign-in the gateway no longer holds is as canceled as it gets
    if (!(error instanceof GatewayError && error.status === 404)) throw shareFailure(error);
  }
  share.state = "canceled";
  share.error = "";
  share.url = "";
  share.updatedAt = new Date().toISOString();
  saveState();
  return share;
}

function shareFor(device, id) {
  const share = workbuddyState().shares[id];
  // another person's share is not this device's to read: 404, not 403,
  // so an id that isn't yours tells you nothing about it
  if (!share || share.deviceId !== device.id) throw new HttpError(404, "not_found", "no such share");
  return share;
}

function sharesOfDevice(deviceId, limit = 10) {
  return Object.values(workbuddyState().shares)
    .filter((share) => share.deviceId === deviceId)
    .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
    .slice(0, limit)
    .map(publicShare);
}

// ---- the bundle the corporation hands out ---------------------------------

function buildBundle(sharing = state.sharing) {
  const mode = clean(sharing?.mode, 16);
  if (mode === "native" || mode === "remote") {
    const catalog = sharedCatalog(sharing);
    return {
      schemaVersion: 1,
      revision: state.bundleRevision,
      providers: [{
        id: "corp",
        name: mode === "remote" ? "企业网关 · Remote magpie" : "企业网关",
        mode: "gateway",
        baseUrl: CONFIG.gatewayPublicUrl,
        npm: "@ai-sdk/openai-compatible",
        models: catalog,
        defaultModel: catalog[0] || "",
        enabled: true,
      }],
      sharing: {
        mode,
        updatedAt: clean(sharing.updatedAt, 40),
        sources: [
          ...(Array.isArray(sharing.providers) ? sharing.providers : []).map((provider) => ({
            id: clean(provider.id, 64),
            name: clean(provider.name, 120) || clean(provider.id, 64),
            models: Array.isArray(provider.models) ? provider.models : [],
          })),
          ...importedSources(sharing).map((source) => ({
            id: source.id,
            name: source.name,
            models: source.models,
          })),
        ],
      },
      instructions: [],
      mcp: [],
      skills: [],
    };
  }
  if (mode === "off") {
    return {
      schemaVersion: 1,
      revision: state.bundleRevision,
      providers: [],
      sharing: { mode, updatedAt: clean(sharing?.updatedAt, 40), sources: [] },
      instructions: [],
      mcp: [],
      skills: [],
    };
  }
  return {
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

function currentBundle() {
  return state.bundles[state.bundleRevision] || buildBundle();
}

// ---- plugins the corporation requires -------------------------------------
//
// A policy names the people, or identity-provider groups, whose devices
// get a plugin. The bundle carries only the plugins this device's user is
// named for; the client installs them and connects their agent.

function policyList(value) {
  const list = Array.isArray(value) ? value : [];
  return [...new Set(list.map((item) => String(item || "").trim().toLowerCase()).filter(Boolean))];
}

function normalizeBridgePolicy(value) {
  const policy = value && typeof value === "object" ? value : {};
  return {
    enabled: policy.enabled === true,
    users: policyList(policy.users),
    groups: policyList(policy.groups),
    model: String(policy.model || "").trim(),
  };
}

function cursorBridgePolicy() {
  if (state.pluginPolicy?.cursorBridge) return normalizeBridgePolicy(state.pluginPolicy.cursorBridge);
  return normalizeBridgePolicy(CONFIG.cursorBridge);
}

// cursorBridgeFor is the bundle's plugin entry for one person, or null
// when the policy doesn't name them. `model` is a magpie model id; a bare
// model is taken as the corp provider's.
export function cursorBridgeFor(user, policy = CONFIG.cursorBridge, bundle = buildBundle()) {
  const checked = normalizeBridgePolicy(policy);
  if (!checked.enabled) return null;

  const email = String(user?.email || "").trim().toLowerCase();
  const groups = Array.isArray(user?.groups)
    ? user.groups.map((group) => String(group || "").trim().toLowerCase()).filter(Boolean)
    : [];
  const everyone = checked.users.includes("*");
  const named = everyone || checked.users.includes(email) || checked.groups.some((group) => groups.includes(group));
  if (!named) return null;

  const providers = (Array.isArray(bundle?.providers) ? bundle.providers : [])
    .filter((provider) => provider && provider.enabled !== false && provider.id);
  const corp = providers.find((provider) => provider.id === "corp") || providers[0];
  if (!corp) return null;

  const chosen = checked.model
    ? (checked.model.includes("/") ? checked.model : `${corp.id}/${checked.model}`)
    : `${corp.id}/${corp.defaultModel || (Array.isArray(corp.models) ? corp.models[0] : "") || ""}`;
  if (!chosen || chosen.endsWith("/")) return null;

  return {
    id: "cursor-bridge",
    name: "Cursor · Magpie Bridge",
    model: chosen,
    enabled: true,
    required: true,
  };
}

// bundleForDevice is what one device is handed: the corporation's bundle,
// plus the plugins its user is named for. The shared bundle stays the
// same for everyone and is what revisions are cut from; the plugin list
// is computed per device from the policy in force.
function bundleForDevice(device) {
  const bundle = currentBundle();
  const user = state.users[device?.userId] || {};
  const plugin = cursorBridgeFor(user, cursorBridgePolicy(), bundle);
  return { ...bundle, plugins: plugin ? [plugin] : [] };
}

// bridgeAssignments is the people a policy names right now: the addresses
// listed, and the people the identity provider puts in a named group. It
// answers who actually gets the plugin, not who was asked for, so an
// administrator can see a typo in a group name.
function bridgeAssignments(policy) {
  const checked = normalizeBridgePolicy(policy);
  if (!checked.enabled) return [];
  const everyone = checked.users.includes("*");
  return Object.values(state.users)
    .filter((user) => {
      const email = String(user?.email || "").trim().toLowerCase();
      if (everyone || checked.users.includes(email)) return true;
      const groups = Array.isArray(user?.groups)
        ? user.groups.map((group) => String(group || "").trim().toLowerCase()).filter(Boolean)
        : [];
      return checked.groups.some((group) => groups.includes(group));
    })
    .map((user) => ({
      email: String(user.email || ""),
      name: String(user.name || ""),
      groups: Array.isArray(user.groups) ? user.groups : [],
      devices: Object.values(state.devices).filter((device) => device.userId === user.id).length,
    }))
    .sort((a, b) => a.email.localeCompare(b.email));
}

const BRIDGE_LIST_MAX = 500;
const BRIDGE_ENTRY_MAX = 200;
const BRIDGE_MODEL = /^[A-Za-z0-9][A-Za-z0-9._:@-]*(?:\/[A-Za-z0-9][A-Za-z0-9._:@-]*){0,3}$/;

// bridgePolicyFrom is the write side of the policy. A policy that names
// something this server can't store is refused whole, rather than kept
// partly, so no device is handed a rule nobody asked for.
function bridgePolicyFrom(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new HttpError(422, "invalid_plugin_policy", "a plugin policy is a JSON object");
  }
  const has = (name) => Object.prototype.hasOwnProperty.call(body, name);
  if (has("enabled") && typeof body.enabled !== "boolean") {
    throw new HttpError(422, "invalid_plugin_policy", "enabled is true or false");
  }
  const list = (name) => {
    if (!has(name)) return [];
    if (!Array.isArray(body[name])) {
      throw new HttpError(422, "invalid_plugin_policy", `${name} is a list of addresses or groups`);
    }
    if (body[name].length > BRIDGE_LIST_MAX) {
      throw new HttpError(422, "invalid_plugin_policy", `${name} names at most ${BRIDGE_LIST_MAX} entries`);
    }
    const out = [];
    for (const value of body[name]) {
      if (typeof value !== "string") {
        throw new HttpError(422, "invalid_plugin_policy", `${name} holds strings only`);
      }
      const entry = value.trim().toLowerCase();
      if (entry.length > BRIDGE_ENTRY_MAX) {
        throw new HttpError(422, "invalid_plugin_policy", `${name} has an entry longer than ${BRIDGE_ENTRY_MAX} characters`);
      }
      if (entry && !out.includes(entry)) out.push(entry);
    }
    return out;
  };
  const model = has("model") ? String(body.model ?? "").trim() : "";
  if (model && !BRIDGE_MODEL.test(model)) {
    throw new HttpError(422, "invalid_plugin_policy", "model is a magpie model id, like corp/deepseek-v4-pro");
  }
  return {
    enabled: body.enabled === true,
    users: list("users"),
    groups: list("groups"),
    model,
  };
}

function adminWriteAllowed(req) {
  if (!CONFIG.adminToken) return true;
  const header = String(req.headers.authorization || "");
  return header === `Bearer ${CONFIG.adminToken}`;
}

// bumpRevision is how any change to what a device is handed reaches it:
// a new revision, kept whole, so a device that asks with the old one is
// answered exactly what it last applied. A plugin policy changes what
// some devices are handed, so it publishes a revision too — without one,
// a withdrawal would be answered 304 and never reach the device.
function bumpRevision() {
  const seq = Number(String(state.bundleRevision || "").replace(/^rev_/, "")) || 1;
  state.bundleRevision = `rev_${seq + 1}`;
  state.bundles = state.bundles || {};
  state.bundles[state.bundleRevision] = buildBundle(state.sharing);
  const revisions = Object.keys(state.bundles);
  for (const revision of revisions.slice(0, Math.max(0, revisions.length - 8))) delete state.bundles[revision];
  return state.bundleRevision;
}

// publishSharing is how a change of what the corporation shares reaches
// devices.
function publishSharing(sharing) {
  state.sharing = { ...sharing, updatedAt: new Date().toISOString() };
  bumpRevision();
  saveState();
  return publicSharing();
}

// enabledResources lists what the bundle now hands out, in the shape the
// admin summary shows. An item the corporation disabled does not appear,
// matching what a device would actually apply.
function enabledResources() {
  const bundle = currentBundle();
  const named = (value) => String(value || "").trim();
  return {
    instructions: (bundle.instructions || []).filter((item) => item && item.enabled !== false)
      .map((item) => named(item.title) || named(item.id) || "shared"),
    mcp: (bundle.mcp || []).filter((item) => item && item.enabled !== false && named(item.name))
      .map((item) => named(item.name)),
    skills: (bundle.skills || []).filter((item) => item && item.enabled !== false && named(item.name))
      .map((item) => named(item.name)),
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
async function exchangeCode(code, redirectUri, { nonce, codeVerifier } = {}) {
  if (!CONFIG.oidc.clientSecret) {
    if (!CONFIG.allowDemoSignIn) {
      throw new HttpError(501, "oidc_not_configured", "the identity provider is not set up: CORP_OIDC_CLIENT_SECRET is missing");
    }
    // `demo-admin:` asks for the demo directory's administrator. The prefix
    // is read only here, and this branch is refused the moment an identity
    // provider is configured, so a real deployment can never grant it.
    const raw = String(code || "");
    const wantsAdmin = raw.startsWith("demo-admin:");
    const email = raw.replace(/^demo-admin:|^demo:/, "");
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      throw new HttpError(400, "demo_code_invalid", "a demo sign-in is demo:someone@example.com");
    }
    const groups = ["engineering"];
    if (wantsAdmin) groups.push(String(CONFIG.adminGroups[0] || "corp-admins"));
    // The subject stays `demo:<email>` either way: asking for the
    // administrator view is the same demo person with more rights, not a
    // second account, so a later plain sign-in cannot leave two of them.
    return {
      subject: `demo:${email}`,
      email,
      name: email.split("@")[0],
      groups,
    };
  }
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: CONFIG.oidc.clientId,
    client_secret: CONFIG.oidc.clientSecret,
  });
  if (codeVerifier) body.set("code_verifier", String(codeVerifier));
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
      nonce: nonce == null || nonce === "" ? undefined : String(nonce),
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

// adminDevice is the one gate the administrator routes go through: a
// device token that is active, and a person the identity provider (or the
// explicit list) calls an administrator. A member's token is refused with
// 403, never quietly treated as an empty administrator.
function adminDevice(req) {
  const device = deviceFor(req);
  const user = state.users[device.userId];
  if (!user) throw new HttpError(401, "not_enrolled", "this device has no user");
  if (roleOf(user) !== "admin") {
    throw new HttpError(403, "forbidden_admin", "this account is not an enterprise administrator");
  }
  return { device, user };
}

// projectKey is a gateway key as an administrator's page may see it: its
// name, mask, what it may use and spend. Its value, and the vendor account
// emails beside it, never leave the gateway.
function projectKey(key) {
  if (!key) return null;
  return {
    id: String(key.id || ""),
    name: String(key.name || ""),
    state: String(key.state || ""),
    masked: String(key.masked || ""),
    models: Array.isArray(key.models) ? key.models : [],
    readOnly: key.readOnly === true,
    limit: key.limit && typeof key.limit === "object" ? key.limit : null,
    moreLimits: Array.isArray(key.moreLimits) ? key.moreLimits : [],
    expiresAt: key.expiresAt || "",
    revision: String(key.revision || ""),
  };
}

const LIMIT_PERIODS = new Set(["day", "week", "month", "hours", "days"]);

// sanitizeLimit keeps only the fields access.Limit names, and only when
// the period is one the gateway knows. Everyone is better served by a
// refused edit than by a limit silently written as "no limit".
function sanitizeLimit(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new HttpError(422, "invalid_limit", "a limit is an object, or null for none");
  }
  const period = String(value.period || "").trim();
  if (!LIMIT_PERIODS.has(period)) {
    throw new HttpError(422, "invalid_limit", "limit.period is one of day, week, month, hours, days");
  }
  const integer = (raw, max) => {
    const number = Number(raw);
    if (!Number.isFinite(number) || number < 0 || number > max) return 0;
    return Math.trunc(number);
  };
  const out = { period };
  if (period === "days") out.days = integer(value.days, 366) || 1;
  if (period === "hours") out.hours = integer(value.hours, 24 * 366) || 1;
  const tokens = integer(value.tokens, Number.MAX_SAFE_INTEGER);
  const cost = Number(value.cost);
  if (tokens) out.tokens = tokens;
  if (Number.isFinite(cost) && cost > 0) out.cost = cost;
  if (value.cacheReads === true) out.cacheReads = true;
  if (!out.tokens && !out.cost && !out.cacheReads) {
    throw new HttpError(422, "invalid_limit", "a limit needs tokens, cost or cacheReads");
  }
  return out;
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

    const ident = await exchangeCode(code, redirectUri, {
      nonce: body.nonce,
      codeVerifier: body.codeVerifier,
    });

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
      user: {
        id: userId, email: ident.email, name: ident.name,
        department: ident.groups[0] || "", groups: ident.groups, role: roleOf(state.users[userId]),
      },
      gateway: { baseUrl: CONFIG.gatewayPublicUrl },
      bundleRevision: state.bundleRevision,
    });
  }

  // ---- a device refreshes its gateway key -----------------------------
  if (req.method === "POST" && p === "/api/v1/device/refresh") {
    const body = await readJson(req);
    // Prefer the Authorization header; the body field is accepted for the
    // protocol's documented shape and for clients that only send that.
    const header = String(req.headers.authorization || "");
    const fromHeader = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
    const token = fromHeader || String(body.deviceToken || "");
    if (!token) throw new HttpError(401, "missing_device_token", "a device token is required");
    // Look the device up without refusing an expired token: refresh is how
    // an expired-but-known device gets a new key. A disabled one stays out.
    const digest = sha256(token);
    const device = Object.values(state.devices).find((d) => d.tokenDigest === digest);
    if (!device) throw new HttpError(401, "invalid_device_token", "the device token is not known here");
    if (device.state !== "active") throw new HttpError(403, "device_disabled", "this device has been revoked");
    const user = state.users[device.userId];
    if (!user) throw new HttpError(401, "not_enrolled", "this device has no user");

    await revokeDeviceKey(device.gatewayKeyID);
    const key = await issueDeviceKey({ deviceId: device.id, email: user.email, name: user.name });
    const nextToken = key.secret;
    const expiresAt = new Date(Date.now() + CONFIG.deviceTokenDays * 86400 * 1000).toISOString();
    device.gatewayKeyID = key.keyID;
    device.gatewayKeyDigest = key.digest;
    device.tokenDigest = sha256(nextToken);
    device.expiresAt = expiresAt;
    user.lastSeenAt = new Date().toISOString();
    saveState();
    console.log(`corp: ${user.email} refreshed (${device.id}), gateway key ${key.keyID}`);

    return send(res, 200, {
      schemaVersion: 1,
      deviceId: device.id,
      deviceToken: nextToken,
      expiresAt,
      user: {
        id: user.id, email: user.email, name: user.name,
        department: user.groups?.[0] || "", groups: user.groups || [], role: roleOf(user),
      },
      gateway: { baseUrl: CONFIG.gatewayPublicUrl },
      bundleRevision: state.bundleRevision,
    });
  }

  // ---- the bundle -----------------------------------------------------
  if (req.method === "GET" && p === "/api/v1/device/me") {
    const device = deviceFor(req);
    const user = state.users[device.userId] || {};
    return send(res, 200, {
      schemaVersion: 1,
      device: {
        id: device.id,
        name: device.name || "",
        platform: device.platform || "",
        state: device.state,
        createdAt: device.createdAt || "",
        expiresAt: device.expiresAt || "",
        gatewayKeyID: device.gatewayKeyID || "",
      },
      user: {
        id: user.id || "",
        email: user.email || "",
        name: user.name || "",
        department: user.groups?.[0] || "",
        groups: user.groups || [],
        role: roleOf(user),
      },
      gateway: { baseUrl: CONFIG.gatewayPublicUrl },
      sharing: publicSharing(),
      workbuddy: { shares: sharesOfDevice(device.id) },
      bundleRevision: state.bundleRevision,
    });
  }

  if (req.method === "GET" && p === "/api/v1/client/bundle") {
    const device = deviceFor(req);
    const asked = url.searchParams.get("revision") || String(req.headers["if-none-match"] || "").replace(/^W\/|"/g, "");
    const bundle = bundleForDevice(device);
    // Every change to what a device is handed — sharing or a plugin
    // policy — publishes a revision, so the device's own revision is a
    // complete answer to "is this still what I should have?".
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

  // ---- an employee shares their own WorkBuddy account ------------------
  //
  // The employee's local service opens the vendor's sign-in in their own
  // browser, the page polls the share, and the account lands in the
  // gateway's WorkBuddy plugin. The answer carries the vendor's URL and the
  // outcome, never a token: this server never holds one.
  if (req.method === "POST" && p === "/api/v1/share/workbuddy/start") {
    const device = deviceFor(req);
    const user = state.users[device.userId];
    if (!user) throw new HttpError(401, "not_enrolled", "this device has no user");
    const body = await readJson(req);
    const provider = clean(body.provider, 40).toLowerCase() || "workbuddy";
    if (!WORKBUDDY_PROVIDERS.has(provider)) {
      throw new HttpError(422, "invalid_provider", "provider is workbuddy or workbuddy-ai");
    }
    const { share, instructions } = await startWorkbuddyShare(device, user, provider);
    return send(res, 200, { schemaVersion: 1, share: publicShare(share), instructions });
  }

  // A sign-in already made on the employee's own magpie, imported rather
  // than scanned again. The body carries it once, on its way to the
  // gateway; what this server keeps is the account's name.
  if (req.method === "POST" && p === "/api/v1/share/workbuddy/import") {
    const device = deviceFor(req);
    const user = state.users[device.userId];
    if (!user) throw new HttpError(401, "not_enrolled", "this device has no user");
    const body = await readJson(req);
    const provider = clean(body.provider, 40).toLowerCase() || "workbuddy";
    if (!WORKBUDDY_PROVIDERS.has(provider)) {
      throw new HttpError(422, "invalid_provider", "provider is workbuddy or workbuddy-ai");
    }
    const auth = body.auth;
    if (!auth || typeof auth !== "object" || Array.isArray(auth) || auth.type !== "oauth") {
      throw new HttpError(422, "invalid_auth", "auth must be an OAuth sign-in");
    }
    const share = await importWorkbuddySignIn(device, user, provider, auth);
    return send(res, 200, { schemaVersion: 1, share: publicShare(share) });
  }

  if (p.startsWith(SHARE_PREFIX)) {
    const rest = p.slice(SHARE_PREFIX.length);
    const cancel = req.method === "POST" && rest.endsWith("/cancel");
    let id = "";
    try {
      id = decodeURIComponent(cancel ? rest.slice(0, -"/cancel".length) : rest);
    } catch {
      throw new HttpError(404, "not_found", "no such share");
    }
    if (!/^shr_[0-9a-f]{8,64}$/.test(id)) throw new HttpError(404, "not_found", "no such share");
    if (!cancel && req.method !== "GET") {
      throw new HttpError(405, "method_not_allowed", "read a share, or POST its /cancel");
    }
    const device = deviceFor(req);
    const share = shareFor(device, id);
    if (cancel) {
      return send(res, 200, { schemaVersion: 1, share: publicShare(await cancelWorkbuddyShare(share)) });
    }
    const { share: current, instructions } = await refreshWorkbuddyShare(share);
    return send(res, 200, { schemaVersion: 1, share: publicShare(current), instructions });
  }

  // ---- admin ----------------------------------------------------------
  // The WorkBuddy accounts employees shared land in the gateway; what of
  // them the corporation hands out is the administrator's tick.
  if (p === "/api/v1/admin/workbuddy") {
    adminDevice(req);
    if (req.method === "GET") {
      return send(res, 200, { schemaVersion: 1, ...adminWorkbuddy() });
    }
    if (req.method === "PUT") {
      const body = await readJson(req);
      const provider = clean(body.provider, 40).toLowerCase();
      if (!WORKBUDDY_PROVIDERS.has(provider)) {
        throw new HttpError(422, "invalid_provider", "provider is workbuddy or workbuddy-ai");
      }
      return send(res, 200, { schemaVersion: 1, ...selectWorkbuddyModels(provider, body.models) });
    }
    throw new HttpError(405, "method_not_allowed", "read the shared accounts, or PUT the models to hand out");
  }

  if (req.method === "GET" && p === "/api/v1/admin/sharing") {
    adminDevice(req);
    return send(res, 200, {
      sharing: publicSharing(),
      catalog: Array.isArray(state.sharing?.catalog) ? state.sharing.catalog : [],
      gateway: {
        baseUrl: CONFIG.gatewayPublicUrl,
        adminConfigured: Boolean(CONFIG.gatewayAdminToken),
      },
      bundleRevision: state.bundleRevision,
    });
  }

  if (req.method === "PUT" && p === "/api/v1/admin/sharing") {
    adminDevice(req);
    const body = await readJson(req);
    const mode = String(body.mode || "").trim();
    if (!SHARING_MODES.has(mode)) {
      throw new HttpError(422, "invalid_mode", "mode is native, remote or off");
    }

    // Whatever this server wrote before goes first, whichever mode comes
    // next: a provider left behind would keep vendor keys in a gateway the
    // corporation no longer shares through.
    const previous = Array.isArray(state.sharing?.installed) ? state.sharing.installed : [];
    if (previous.length) {
      const failed = await removeGatewayProviders(previous);
      if (failed.length) {
        throw new GatewayError("gateway_not_cleaned", `网关里上一次分享的供应商没有删干净：${failed.join("、")}`);
      }
    }

    if (mode === "native") {
      const providers = Array.isArray(body.providers) ? body.providers : [];
      if (!providers.length) {
        throw new HttpError(422, "no_providers", "至少选择一个要分享的供应商");
      }
      const installed = await installNativeProviders(providers);
      const sharing = publishSharing({
        mode,
        providers: installed,
        installed: installed.map((provider) => provider.gatewayProviderId),
        catalog: catalogOf(installed),
      });
      console.log(`corp: sharing ${installed.length} native provider(s) through the gateway`);
      return send(res, 200, {
        sharing,
        catalog: sharing.catalog,
        bundleRevision: state.bundleRevision,
      });
    }

    if (mode === "remote") {
      const catalog = await remoteCatalog(body.models);
      const sharing = publishSharing({
        mode,
        providers: [{
          id: "corp",
          name: "企业网关 · Remote magpie",
          models: catalog,
          keyCount: 0,
          keyMasked: "",
          available: true,
        }],
        installed: [],
        catalog,
      });
      console.log(`corp: sharing the gateway as a Remote magpie, ${catalog.length} model(s)`);
      return send(res, 200, {
        sharing,
        catalog: sharing.catalog,
        bundleRevision: state.bundleRevision,
      });
    }

    const sharing = publishSharing({ mode: "off", providers: [], installed: [], catalog: [] });
    console.log("corp: sharing turned off");
    return send(res, 200, { sharing, catalog: [], bundleRevision: state.bundleRevision });
  }

  if (req.method === "GET" && p === "/api/v1/admin/people") {
    adminDevice(req);
    let keys = null;
    let gatewayError = "";
    try {
      const listed = await gatewayAdmin("GET", "/v1/magpie/admin/gateway/keys");
      keys = Array.isArray(listed?.keys) ? listed.keys : [];
    } catch (error) {
      if (!(error instanceof GatewayError)) throw error;
      gatewayError = error.message;
    }
    const byId = new Map((keys || []).map((key) => [key.id, key]));
    const people = Object.values(state.users)
      .map((user) => ({
        id: user.id,
        email: user.email,
        name: user.name,
        groups: user.groups || [],
        role: roleOf(user),
        lastSeenAt: user.lastSeenAt || "",
        devices: Object.values(state.devices)
          .filter((device) => device.userId === user.id)
          .map((device) => ({
            id: device.id,
            name: device.name || "",
            platform: device.platform || "",
            state: device.state,
            createdAt: device.createdAt || "",
            expiresAt: device.expiresAt || "",
            key: projectKey(device.gatewayKeyID ? byId.get(device.gatewayKeyID) : null),
          })),
      }))
      .sort((a, b) => String(a.email).localeCompare(String(b.email)));
    return send(res, 200, {
      people,
      catalog: Array.isArray(state.sharing?.catalog) ? state.sharing.catalog : [],
      sharing: publicSharing(),
      gateway: {
        baseUrl: CONFIG.gatewayPublicUrl,
        adminConfigured: Boolean(CONFIG.gatewayAdminToken),
        keysReadable: Boolean(keys),
        error: gatewayError,
      },
    });
  }

  if (req.method === "PATCH" && p.startsWith("/api/v1/admin/people/")) {
    adminDevice(req);
    const deviceId = decodeURIComponent(p.slice("/api/v1/admin/people/".length));
    const device = state.devices[deviceId];
    if (!device) throw new HttpError(404, "not_found", "no such device");
    if (!device.gatewayKeyID) throw new HttpError(409, "no_gateway_key", "this device has no gateway key");
    const body = await readJson(req);

    const listed = await gatewayAdmin("GET", "/v1/magpie/admin/gateway/keys");
    const key = (Array.isArray(listed?.keys) ? listed.keys : []).find((item) => item.id === device.gatewayKeyID);
    if (!key) throw new HttpError(404, "gateway_key_missing", "the gateway no longer has this device's key");

    const patch = { expectedRevision: String(key.revision || "") };
    const has = (name) => Object.prototype.hasOwnProperty.call(body, name);
    if (has("name")) patch.name = String(body.name || "").slice(0, 120);
    if (has("models")) {
      patch.models = modelList(body.models);
      patch.modelsSet = true;
    }
    if (has("readOnly")) patch.readOnly = body.readOnly === true;
    if (has("off")) patch.off = body.off === true;
    if (has("limit")) {
      patch.limit = sanitizeLimit(body.limit);
      patch.limitSet = true;
    }
    if (Object.keys(patch).length === 1) {
      throw new HttpError(422, "nothing_to_change", "the request names nothing to change");
    }
    const updated = await gatewayAdmin(
      "PATCH",
      `/v1/magpie/admin/gateway/keys/${encodeURIComponent(key.id)}`,
      patch,
    );
    const next = updated?.key
      || (Array.isArray(updated?.keys) ? updated.keys.find((item) => item.id === key.id) : null)
      || { ...key, ...patch };
    console.log(`corp: administrator changed gateway key ${key.id} (${deviceId})`);
    return send(res, 200, { key: projectKey(next), deviceId });
  }

  // ---- admin: the plugins devices are told to install -----------------
  if (req.method === "GET" && p === "/__admin/plugins") {
    const policy = cursorBridgePolicy();
    return send(res, 200, {
      cursorBridge: policy,
      everyone: policy.users.includes("*"),
      assigned: bridgeAssignments(policy),
      catalog: Array.isArray(state.sharing?.catalog) ? state.sharing.catalog : [],
      bundleRevision: state.bundleRevision,
    });
  }

  if (req.method === "POST" && p === "/__admin/plugins/cursor-bridge") {
    if (!adminWriteAllowed(req)) {
      throw new HttpError(403, "admin_token_required", "this write needs the administrator token");
    }
    const policy = bridgePolicyFrom(await readJson(req));
    const before = cursorBridgePolicy();
    state.pluginPolicy = { ...(state.pluginPolicy || {}), cursorBridge: policy };
    // A policy that names different people, or another model, changes what
    // devices are handed even though the providers did not change.
    const changed = JSON.stringify(before) !== JSON.stringify(policy);
    if (changed) bumpRevision();
    saveState();
    const assigned = bridgeAssignments(policy);
    console.log(`corp: cursor bridge ${policy.enabled ? "on" : "off"}, ${assigned.length} person(s) named`);
    return send(res, 200, {
      cursorBridge: policy,
      everyone: policy.users.includes("*"),
      assigned,
      catalog: Array.isArray(state.sharing?.catalog) ? state.sharing.catalog : [],
      bundleRevision: state.bundleRevision,
    });
  }

  if (req.method === "GET" && p === "/__admin/summary") {
    const usage = state.usage;
    const resources = enabledResources();
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
      sharing: publicSharing(),
      plugins: {
        cursorBridge: cursorBridgePolicy(),
        assigned: bridgeAssignments(cursorBridgePolicy()).map((person) => person.email),
      },
      workbuddy: {
        served: sharingServes(),
        shares: Object.values(workbuddyState().shares)
          .sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)))
          .slice(0, 100)
          .map((share) => ({
            id: share.id,
            provider: share.provider,
            email: clean(state.users[share.userId]?.email, 200),
            deviceId: share.deviceId,
            account: clean(share.account, 200),
            state: shareStateOf(share.state),
            error: clean(share.error, 300),
            createdAt: share.createdAt,
            completedAt: share.completedAt,
          })),
        imported: Object.values(workbuddyState().imported).map((item) => ({
          provider: item.provider,
          name: item.name,
          models: Array.isArray(item.models) ? item.models.length : 0,
          selected: selectedModels(item).length,
          accounts: (Array.isArray(item.accounts) ? item.accounts : [])
            .map((account) => clean(account.email, 200) || clean(account.account, 200)),
          at: item.at,
        })),
      },
      resources: {
        instructions: resources.instructions,
        mcp: resources.mcp,
        skills: resources.skills,
      },
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
