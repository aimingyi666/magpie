// What the corporation hands out as a provider, read from the bundle the
// last sync kept.
//
// Two views of the same thing: `config` names the provider and its base at
// host load (magpie's config hook), and `models` answers each listing, so
// a model the corporation adds shows without restarting magpie.
//
// The provider always points at the corporate gateway, which holds the
// vendors' keys: `mode: "direct"` is the one case a vendor key would land
// on this computer, and the server has to say so explicitly.
import fs from "node:fs";
import path from "node:path";

const PROVIDER_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const DEFAULT_NPM = "@ai-sdk/openai-compatible";

export function readBundle(dir) {
  try {
    const value = JSON.parse(fs.readFileSync(path.join(dir, "bundle.json"), "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    return value;
  } catch {
    return null;
  }
}

export function enabledProviders(bundle) {
  const list = Array.isArray(bundle?.providers) ? bundle.providers : [];
  return list
    .filter((provider) => provider && typeof provider.id === "string" && PROVIDER_ID.test(provider.id))
    .filter((provider) => provider.enabled !== false);
}

// modelsOf is one provider's models as magpie's list: a map of model id to
// what little a listing needs, each carrying its own base so the list is
// usable even when the config hook ran before the first sync.
function modelsOf(provider, config) {
  const out = {};
  const ids = Array.isArray(provider.models) ? provider.models : [];
  for (const raw of ids) {
    const id = String(raw || "").trim();
    if (!id) continue;
    out[id] = {
      name: id,
      provider: {
        npm: provider.npm || DEFAULT_NPM,
        api: provider.mode === "direct" && provider.baseUrl
          ? String(provider.baseUrl)
          : String(provider.baseUrl || config.baseUrl || ""),
      },
    };
  }
  return out;
}

export function providerConfig(cfg, { provider, dir, config, store }) {
  const bundle = readBundle(dir);
  if (!bundle) return;
  cfg.provider = cfg.provider || {};
  const current = enabledProviders(bundle);
  const ids = new Set(current.map((entry) => entry.id));
  // A provider the corporation withdrew is taken away. Only ids this
  // plugin wrote before are considered: a provider the reader added by
  // hand is never touched, whatever the server says.
  const applied = Array.isArray(store?.state?.().appliedProviders) ? store.state().appliedProviders : [];
  for (const id of applied) {
    if (!ids.has(id) && cfg.provider[id]) delete cfg.provider[id];
  }
  for (const entry of current) {
    const base = entry.mode === "direct" && entry.baseUrl ? entry.baseUrl : entry.baseUrl || config.baseUrl;
    cfg.provider[entry.id] = {
      name: entry.name || entry.id,
      npm: entry.npm || DEFAULT_NPM,
      options: base ? { baseURL: String(base) } : {},
      models: modelsOf(entry, config),
    };
  }
  if (store && applied.join(",") !== [...ids].join(",")) {
    store.update((state) => {
      state.appliedProviders = [...ids];
      return state;
    });
  }
}

export async function providerModels({ provider, dir, config }) {
  const bundle = readBundle(dir);
  if (!bundle) return {};
  const entry = enabledProviders(bundle).find((p) => p.id === provider);
  if (!entry) return {};
  return modelsOf(entry, config);
}

// defaultModel is the model a new agent should get: the bundle's pick when
// it names one this provider serves, else the first it lists.
export function defaultModel(bundle, provider) {
  const entry = enabledProviders(bundle).find((p) => p.id === provider);
  if (!entry) return "";
  const ids = (Array.isArray(entry.models) ? entry.models : []).map(String);
  const chosen = String(entry.defaultModel || "");
  const bare = chosen.includes("/") ? chosen.split("/").slice(1).join("/") : chosen;
  if (bare && ids.includes(bare)) return `${entry.id}/${bare}`;
  return ids.length ? `${entry.id}/${ids[0]}` : "";
}
