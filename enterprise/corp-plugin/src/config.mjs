// Where the corporate client keeps its state, and what it runs with.
//
// The directory is the same one the enterprise join script uses, so a
// machine that joined before keeps its files: %LOCALAPPDATA%\MagpieCorp on
// Windows, ~/.local/state/magpie-corp elsewhere. It can be moved with
// MAGPIE_CORP_DIR.
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

export const MIN_SECRET = 16;

export function stateDirectory(env = process.env) {
  const chosen = String(env.MAGPIE_CORP_DIR || "").trim();
  if (chosen) return path.resolve(chosen);
  if (process.platform === "win32") {
    const base = env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local");
    return path.join(base, "MagpieCorp");
  }
  return path.join(os.homedir(), ".local", "state", "magpie-corp");
}

function trimRight(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

// safeBase accepts a server address only when it is https, or plain http
// on loopback: a device token must never travel in clear over a network.
export function safeBase(raw) {
  const value = trimRight(raw);
  if (!value) return "";
  let url;
  try {
    url = new URL(value);
  } catch {
    return "";
  }
  if (url.protocol === "https:") return value;
  const host = url.hostname;
  const loopback = host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "[::1]";
  if (url.protocol === "http:" && loopback) return value;
  return "";
}

export function loadCorpConfig(dir, options = {}, env = process.env) {
  let file = {};
  try {
    file = JSON.parse(fs.readFileSync(path.join(dir, "corp.json"), "utf8"));
  } catch {
    file = {};
  }
  if (!file || typeof file !== "object" || Array.isArray(file)) file = {};

  const baseUrl = safeBase(
    env.MAGPIE_CORP_URL || options.baseUrl || file.baseUrl || "",
  );
  const providerId = String(
    options.provider || file.provider || "corp",
  ).trim() || "corp";

  return {
    dir,
    baseUrl,
    providerId,
    // The OIDC parameters the server discovers. Kept from the last
    // /api/v1/corp/config so a server that is down at start still lets
    // the page show what it knows.
    oidc: file.oidc && typeof file.oidc === "object" ? file.oidc : null,
    servicePort: Number(options.port) || 3488,
    upload: {
      usage: file.upload?.usage !== false,
      masking: file.upload?.masking !== false,
      sessions: file.upload?.sessions !== false,
      minSeconds: Number(file.upload?.minSeconds) || 60,
    },
    // Where magpie's own files are: the ledger and the masking records
    // are read from here, never written.
    configDir: String(env.MAGPIE_CONFIG_DIR || "").trim(),
    magpieBin: String(env.MAGPIE_BIN || "magpie").trim(),
  };
}

// saveCorpConfig writes what discovery and the page learned, keeping the
// file to the owner: it carries the OIDC parameters, no secret.
export function saveCorpConfig(dir, value) {
  const file = path.join(dir, "corp.json");
  const body = {
    baseUrl: safeBase(value.baseUrl),
    provider: String(value.provider || "corp"),
    oidc: value.oidc && typeof value.oidc === "object" ? value.oidc : null,
    upload: value.upload,
  };
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(body, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, file);
  return body;
}
