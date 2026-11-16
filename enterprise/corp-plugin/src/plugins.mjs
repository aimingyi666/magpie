// The plugins a corporation makes part of joining it.
//
// A bundle may name a plugin for this device, and this file installs it,
// turns it on, and connects its agent to one of the corporation's models.
// Only the plugins below can be named: a bundle chooses among them, it
// never supplies a package to install, so a compromised bundle cannot run
// code of its choosing.
//
// The Cursor bridge is the one that matters here: its agent points Cursor
// at this machine's magpie gateway, and the corp provider on that gateway
// sends the requests on to the corporation's gateway.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { runMagpie } from "./resources.mjs";

const PLUGIN_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:@-]*(?:\/[A-Za-z0-9][A-Za-z0-9._:@-]*){0,3}$/;

// The plugins a bundle may name. The spec and the agent are this file's,
// never the server's.
const KNOWN = Object.freeze({
  "cursor-bridge": Object.freeze({
    id: "cursor-bridge",
    name: "Cursor · Magpie Bridge",
    package: "magpie-agent-cursor-bridge",
    spec: "github:932633145/magpie-agent-cursor-bridge",
    agent: "cursor-bridge",
    // where magpie writes the agent's connection, as its agent.js says
    config: [".config", "magpie-cursor-bridge", "connection.json"],
  }),
});

function readJson(file) {
  try {
    const value = JSON.parse(fs.readFileSync(file, "utf8"));
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

// installedPlugins is magpie's own list, read rather than asked of the
// CLI: the list is what `plugin add`, `plugin on` and `plugin off` write.
function installedPlugins(configDir) {
  const value = readJson(path.join(configDir, "plugins.json"));
  return (Array.isArray(value?.plugins) ? value.plugins : [])
    .filter((entry) => entry && typeof entry === "object")
    .map((entry) => ({ spec: String(entry.spec || "").trim(), off: entry.off === true }))
    .filter((entry) => entry.spec);
}

// samePlugin matches what plugins.json keeps for a known plugin: the
// exact spec, an npm package at any version, a GitHub spec pinned to a
// ref, or the package's own name.
function samePlugin(spec, known) {
  if (spec === known.spec || spec === known.package) return true;
  if (spec.startsWith(`${known.package}@`)) return true;
  if (!spec.startsWith("github:")) return false;
  const base = spec.slice("github:".length).replace(/#.*$/, "").replace(/\.git$/, "");
  return base === known.spec.slice("github:".length) || base.endsWith(`/${known.package}`);
}

function modelFor(value, provider, bundle) {
  const chosen = String(value || "").trim();
  if (chosen) return chosen.includes("/") ? chosen : `${provider}/${chosen}`;
  const providers = (Array.isArray(bundle?.providers) ? bundle.providers : [])
    .filter((entry) => entry && entry.enabled !== false && entry.id);
  const first = providers.find((entry) => entry.id === provider) || providers[0];
  if (!first) return "";
  const fallback = String(first.defaultModel || (Array.isArray(first.models) ? first.models[0] : "") || "").trim();
  return fallback ? `${first.id}/${fallback}` : "";
}

// wantedPlugins is what the bundle asks this device for, in the shape the
// rest of this file works with. An entry the bundle didn't name, or named
// but turned off, is not wanted.
export function wantedPlugins(bundle, { provider = "corp" } = {}) {
  const errors = [];
  const wanted = [];
  const named = Array.isArray(bundle?.plugins) ? bundle.plugins : [];
  for (const item of named) {
    if (!item || item.enabled === false) continue;
    const id = String(item.id || "").trim();
    const known = KNOWN[id];
    if (!PLUGIN_ID.test(id) || !known) {
      errors.push({ code: "unknown_plugin", message: `${id || "(no id)"}: this client has no such plugin` });
      continue;
    }
    const model = modelFor(item.model, provider, bundle);
    if (!MODEL.test(model)) {
      errors.push({ code: "plugin_model_invalid", message: `${id}: the bundle names no usable model` });
      continue;
    }
    wanted.push({ ...known, model, required: item.required !== false });
  }
  return { wanted, errors };
}

function connectedAt(file, model = null) {
  const value = readJson(file);
  if (!value || value.enabled !== true) return false;
  return model === null || value.model === model;
}

function agentFile(known, home) {
  return path.join(home, ...known.config);
}

// applyPlugins installs, turns on and connects what the bundle wants, and
// disconnects an agent the bundle no longer wants. It answers the ids now
// applied, so the next sync knows what to take back.
//
// Nothing is removed: a plugin the corporation no longer wants is left
// installed and turned off by disconnecting its agent, restoring the
// editor's own settings, but the user keeps what they installed.
export async function applyPlugins(bundle, {
  magpieBin,
  configDir,
  provider = "corp",
  applied = [],
  run = runMagpie,
  home = os.homedir(),
  log = () => {},
} = {}) {
  const { wanted, errors } = wantedPlugins(bundle, { provider });
  const previous = Array.isArray(applied) ? applied.map(String) : [];
  if (!wanted.length && !previous.length) return { applied: [], errors };
  if (!configDir) {
    return {
      applied: [],
      errors: [{ code: "config_dir_unknown", message: "magpie didn't say where its files are (MAGPIE_CONFIG_DIR)" }],
    };
  }

  const call = (args, timeoutMs = 60_000) => run(magpieBin, args, { configDir, timeoutMs });
  const installed = installedPlugins(configDir);
  const next = [];

  for (const plugin of wanted) {
    // A plugin that was applied before stays "applied" when this pass
    // fails partway: its connection may still be in place, and the next
    // pass — or a withdrawn policy — must know to look at it.
    const keep = () => {
      if (previous.includes(plugin.id) && !next.includes(plugin.id)) next.push(plugin.id);
    };
    const entry = installed.find((item) => samePlugin(item.spec, plugin));
    if (!entry) {
      const added = await call(["plugin", "add", plugin.spec], 10 * 60_000);
      if (!added.ok) {
        errors.push({ code: "plugin_add_failed", message: `${plugin.id}: ${added.message}` });
        keep();
        continue;
      }
      log(`${plugin.id} installed`);
    } else if (entry.off) {
      const on = await call(["plugin", "on", entry.spec], 60_000);
      if (!on.ok) {
        errors.push({ code: "plugin_enable_failed", message: `${plugin.id}: ${on.message}` });
        keep();
        continue;
      }
      log(`${plugin.id} turned on`);
    }

    if (!connectedAt(agentFile(plugin, home), plugin.model)) {
      const connected = await call([plugin.agent, plugin.model], 2 * 60_000);
      if (!connected.ok) {
        errors.push({ code: "plugin_connect_failed", message: `${plugin.id}: ${connected.message}` });
        keep();
        continue;
      }
      log(`${plugin.id} connected to ${plugin.model}`);
    }
    next.push(plugin.id);
  }

  // an agent the corporation withdrew is disconnected, so the editor goes
  // back to its own settings rather than quietly keeping the gateway
  for (const id of previous) {
    if (wanted.some((plugin) => plugin.id === id)) continue;
    const known = KNOWN[id];
    if (!known) continue;
    if (!connectedAt(agentFile(known, home))) continue;
    const off = await call([known.agent, "default"], 2 * 60_000);
    if (!off.ok) {
      errors.push({ code: "plugin_disconnect_failed", message: `${id}: ${off.message}` });
    } else {
      log(`${id} disconnected`);
    }
  }

  return { applied: next, errors };
}

export { KNOWN as knownPlugins };
