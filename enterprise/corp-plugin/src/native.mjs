// The native magpie on this computer, as an administrator's page may see
// it: the providers and gateway keys magpie already holds, without their
// secrets. The page chooses what to share; this module reads the files and
// hands the values only to the local service, which sends them on.
//
// magpie's plugin host sets MAGPIE_CONFIG_DIR to the folder the running
// magpie reads. A standalone service (a test, or a page opened outside the
// host) falls back to the installed folder.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const MAX_MODELS = 500;
const MAX_PROVIDERS = 200;
const WORKBUDDY_PROVIDERS = new Set(["workbuddy", "workbuddy-ai"]);

export function magpieConfigDir(config = {}, env = process.env) {
  const explicit = String(config.configDir || env.MAGPIE_CONFIG_DIR || "").trim();
  if (explicit) return path.resolve(explicit);
  if (process.platform === "win32") {
    const home = env.USERPROFILE || os.homedir();
    return path.join(home, ".config", "magpie");
  }
  const base = String(env.XDG_CONFIG_HOME || "").trim() || path.join(os.homedir(), ".config");
  return path.join(path.resolve(base), "magpie");
}

function readJson(file, { array = false } = {}) {
  try {
    const value = JSON.parse(fs.readFileSync(file, "utf8"));
    if (array) return Array.isArray(value) ? value : null;
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    return value;
  } catch {
    return null;
  }
}

export function maskSecret(secret) {
  const value = String(secret || "");
  if (!value) return "";
  if (value.length <= 8) return "…";
  return `…${value.slice(-6)}`;
}

// localWorkbuddyAccounts are the WorkBuddy accounts this computer's magpie
// already has signed in, named by their own labels. plugin-auth.json keeps
// their tokens beside those labels; this reads past them and returns none.
// A page that imports one has the tokens read by localWorkbuddySignIn, on
// this computer, and sent to the corporate gateway alone.
export function localWorkbuddyAccounts(config = {}, env = process.env) {
  const dir = magpieConfigDir(config, env);
  const auth = readJson(path.join(dir, "plugin-auth.json"));
  const out = [];
  for (const [key, value] of Object.entries(auth || {})) {
    if (!value || typeof value !== "object" || value.type !== "oauth") continue;
    const provider = clean(key, 160).split("#")[0];
    if (!WORKBUDDY_PROVIDERS.has(provider)) continue;
    const account = clean(value.accountId || value.metadata?.email || value.email, 120);
    if (out.some((item) => item.provider === provider && item.account === account)) continue;
    out.push({ provider, account });
  }
  return out
    .sort((a, b) => a.provider.localeCompare(b.provider) || a.account.localeCompare(b.account))
    .slice(0, 20);
}

// localWorkbuddySignIn is the sign-in behind one account this computer's
// magpie has, tokens and all, for the one route that moves it to the
// corporate gateway. The page never sees this: service.mjs sends it to the
// server, which writes it into the gateway, and drops it. The key it came
// from is answered so the service can sign the account out here once the
// gateway has it — two hosts renewing one token would break each other.
export function localWorkbuddySignIn(provider, account, config = {}, env = process.env) {
  const id = clean(provider, 40).toLowerCase();
  if (!WORKBUDDY_PROVIDERS.has(id)) return null;
  const want = clean(account, 120).toLowerCase();
  const dir = magpieConfigDir(config, env);
  const auth = readJson(path.join(dir, "plugin-auth.json"));
  for (const [key, value] of Object.entries(auth || {})) {
    if (!value || typeof value !== "object" || value.type !== "oauth") continue;
    if (clean(key, 160).split("#")[0] !== id) continue;
    const who = clean(value.accountId || value.metadata?.email || value.email, 120);
    if (want && who.toLowerCase() !== want) continue;
    return { key, provider: id, account: who, auth: value };
  }
  return null;
}

function clean(value, max = 200) {
  return String(value ?? "").trim().slice(0, max);
}

function modelsOf(provider) {
  const listed = Array.isArray(provider?.models) ? provider.models : [];
  return [...new Set(listed.map((model) => clean(model, 200)).filter(Boolean))].slice(0, MAX_MODELS);
}

// providerKeys are every value this provider can be sent with: its first
// key and the accounts saved beside it. A subscription's access token is
// not one of these, and a provider with none can't be shared.
function providerKeys(provider) {
  const out = [];
  if (typeof provider?.key === "string" && provider.key.trim()) out.push(provider.key.trim());
  for (const account of Array.isArray(provider?.keys) ? provider.keys : []) {
    if (account && typeof account.key === "string" && account.key.trim()) out.push(account.key.trim());
  }
  return [...new Set(out)];
}

function endpointsOf(provider) {
  return {
    chat: clean(provider?.chat, 2048),
    responses: clean(provider?.responses, 2048),
    anthropic: clean(provider?.anthropic, 2048),
    gemini: clean(provider?.gemini, 2048),
    baseAPI: clean(provider?.baseAPI, 32),
  };
}

// nativeProviders is what the native magpie would share: a provider with
// an explicit model list and at least one key. A provider left to "the
// vendor's whole list" has no stable ids for a gateway bundle yet, so it
// is shown with why it can't be shared rather than guessed at.
export function nativeProviders(config = {}, env = process.env) {
  const dir = magpieConfigDir(config, env);
  const file = readJson(path.join(dir, "providers.json"));
  const list = Array.isArray(file?.providers) ? file.providers.slice(0, MAX_PROVIDERS) : [];
  return list
    .filter((provider) => provider && typeof provider === "object" && clean(provider.id, 64))
    .map((provider) => {
      const id = clean(provider.id, 64);
      const name = clean(provider.name, 120) || id;
      const models = modelsOf(provider);
      const keys = providerKeys(provider);
      const subscription = Boolean(provider.account);
      let reason = "";
      if (subscription && !keys.length) reason = "订阅账号没有可分享的 API Key";
      else if (!keys.length) reason = "没有可分享的 API Key";
      else if (!models.length) reason = "还没有选择要分享的模型";
      return {
        id,
        name,
        preset: clean(provider.preset, 64),
        host: clean(provider.chat || provider.responses || provider.anthropic || provider.gemini, 300),
        models,
        modelCount: models.length,
        keyCount: keys.length,
        maskedKeys: keys.map(maskSecret),
        subscription,
        shareable: Boolean(keys.length && models.length),
        reason,
      };
    });
}

// shareNativeProviders takes the page's selection and makes the payload
// the corporate server hands to the gateway. The values never reach the
// page: the local service sends this itself.
export function shareNativeProviders(ids, config = {}, env = process.env) {
  const wanted = new Set((Array.isArray(ids) ? ids : []).map((id) => clean(id, 64)).filter(Boolean));
  const dir = magpieConfigDir(config, env);
  const file = readJson(path.join(dir, "providers.json"));
  const list = Array.isArray(file?.providers) ? file.providers : [];
  const providers = [];
  const skipped = [];

  for (const provider of list) {
    if (!provider || typeof provider !== "object") continue;
    const id = clean(provider.id, 64);
    if (!wanted.has(id)) continue;
    const models = modelsOf(provider);
    const keys = providerKeys(provider);
    if (!models.length) {
      skipped.push({ id, name: clean(provider.name, 120) || id, reason: "没有选择模型" });
      continue;
    }
    if (!keys.length) {
      skipped.push({ id, name: clean(provider.name, 120) || id, reason: "没有 API Key" });
      continue;
    }
    const endpoints = endpointsOf(provider);
    providers.push({
      id,
      name: clean(provider.name, 120) || id,
      preset: clean(provider.preset, 64),
      ...endpoints,
      models,
      key: keys[0],
      keys: keys.slice(1),
    });
  }

  for (const id of wanted) {
    if (!providers.some((provider) => provider.id === id) && !skipped.some((item) => item.id === id)) {
      skipped.push({ id, name: id, reason: "原生 magpie 里没有这个供应商" });
    }
  }
  return { providers, skipped, configDir: dir };
}

function usable(key, now = Date.now()) {
  if (!key || key.off) return false;
  if (!key.expires) return true;
  const at = Date.parse(key.expires);
  return !Number.isFinite(at) || at > now;
}

// nativeKeys is the native magpie's gateway keys as a page may see them:
// a name, a mask, whether it may read only, and what it may use. A key's
// value stays in this process.
export function nativeKeys(config = {}, env = process.env) {
  const dir = magpieConfigDir(config, env);
  const list = readJson(path.join(dir, "caller-keys.json"), { array: true }) || [];
  return list
    .filter((key) => key && typeof key === "object" && clean(key.id, 64))
    .map((key) => ({
      id: clean(key.id, 64),
      name: clean(key.name, 120) || clean(key.id, 64),
      masked: maskSecret(key.secret),
      readOnly: key.readOnly === true,
      off: key.off === true,
      usable: usable(key) && key.readOnly !== true,
      models: Array.isArray(key.models) ? key.models.map((model) => clean(model, 200)).filter(Boolean) : [],
      limit: key.limit && typeof key.limit === "object" ? key.limit : null,
    }));
}

export function nativeKeySecret(id, config = {}, env = process.env) {
  const dir = magpieConfigDir(config, env);
  const list = readJson(path.join(dir, "caller-keys.json"), { array: true }) || [];
  const key = list.find((item) => item && clean(item.id, 64) === clean(id, 64));
  if (!key || !usable(key)) return "";
  return String(key.secret || "");
}

// localGatewayAddress is where this computer's magpie answers: the host
// the plugin host was told, or the default port when it wasn't.
export function localGatewayAddress(env = process.env) {
  const raw = clean(env.MAGPIE_ADDR, 300) || "127.0.0.1:3425";
  const withScheme = /^[a-z][\w+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  try {
    const url = new URL(withScheme);
    if (url.hostname === "0.0.0.0" || url.hostname === "::") url.hostname = "127.0.0.1";
    if (!url.port) url.port = "3425";
    return url.origin;
  } catch {
    return "http://127.0.0.1:3425";
  }
}

// modelsAt asks this computer's magpie what it lists, with the key the
// administrator chose. It answers model ids already prefixed by their
// provider, which is what a Remote magpie provider's list holds.
export async function modelsAt(base, key, { timeoutMs = 8000 } = {}) {
  const origin = String(base || "").replace(/\/+$/, "");
  if (!origin) return [];
  const response = await fetch(new URL("/v1/models", `${origin}/`), {
    headers: { authorization: `Bearer ${key}`, accept: "application/json" },
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) {
    throw new Error(`this computer's magpie answered ${response.status} for its model list`);
  }
  const payload = await response.json().catch(() => ({}));
  const rows = Array.isArray(payload?.data) ? payload.data : [];
  return [...new Set(rows.map((row) => clean(row?.id, 200)).filter(Boolean))].slice(0, MAX_MODELS);
}
