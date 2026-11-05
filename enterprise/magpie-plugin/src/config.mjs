import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const DEFAULT_SERVICE_PORT = 3477;
export const DEFAULT_MAX_RESOURCE_BYTES = 4 * 1024 * 1024;

const SYNC_CONFIG_FILE = "enterprise-sync.json";
const RESOURCE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

// adminBaseUrlValue is the one shape an administrator's console address
// may take: https, or plain http on this machine. Anything else is refused
// rather than saved, because a desktop token would be sent there.
export function adminBaseUrlValue(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return { error: "empty" };
  let url;
  try {
    url = new URL(raw);
  } catch {
    return { error: "url" };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return { error: "scheme" };
  if (url.protocol === "http:"
      && !["127.0.0.1", "localhost", "[::1]", "::1"].includes(url.hostname.toLowerCase())) {
    return { error: "loopback" };
  }
  if (url.username || url.password || url.search || url.hash) return { error: "parts" };
  return { value: url.toString().replace(/\/+$/, "") };
}

// setSyncAdminBaseUrl writes adminBaseUrl into enterprise-sync.json,
// keeping everything else the file carries. It answers the value saved,
// and never writes a file it could not read: overwriting the pinned
// signing keys would break the device's next sync.
export function setSyncAdminBaseUrl(dir, value) {
  const checked = adminBaseUrlValue(value);
  if (checked.error) return checked;
  const file = path.join(dir, SYNC_CONFIG_FILE);
  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    return { error: error?.code === "ENOENT" ? "missing" : "invalid" };
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) return { error: "invalid" };
  data.adminBaseUrl = checked.value;
  const temp = `${file}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(temp, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temp, file);
  } catch {
    fs.rmSync(temp, { force: true });
    return { error: "write" };
  }
  return { value: checked.value };
}

// stateDirectory is where join-enterprise.ps1 keeps this device's credential:
// %LOCALAPPDATA%\MagpieEnterprise on Windows, ~/.local/state/magpie-enterprise
// elsewhere.
export function stateDirectory(env = process.env) {
  const given = env.MAGPIE_ENTERPRISE_STATE_DIR;
  if (typeof given === "string" && given.trim()) return path.resolve(given.trim());
  if (process.platform === "win32" && env.LOCALAPPDATA) {
    return path.join(env.LOCALAPPDATA, "MagpieEnterprise");
  }
  return path.join(os.homedir(), ".local", "state", "magpie-enterprise");
}

// readCredential finds the device joined by join-enterprise.ps1. A file
// that can't be read or parsed is "unknown", never "not joined": the page
// says which, and does not offer Sync now on a guess.
export function readCredential(dir = stateDirectory()) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") return { state: "missing", dir };
    return { state: "unreadable", dir, code: error?.code || "unreadable" };
  }

  const files = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith("-device.json"))
    .map((entry) => {
      const file = path.join(dir, entry.name);
      try {
        return { file, at: fs.statSync(file).mtimeMs };
      } catch {
        return { file, at: 0 };
      }
    })
    .sort((left, right) => right.at - left.at);
  if (files.length === 0) return { state: "missing", dir };

  const file = files[0].file;
  let raw;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch (error) {
    return { state: "unreadable", dir, file, code: error?.code || "unreadable" };
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    return { state: "invalid", dir, file, reason: "json" };
  }
  if (!data || typeof data !== "object"
      || typeof data.authUrl !== "string" || !data.authUrl.trim()
      || typeof data.deviceToken !== "string" || !data.deviceToken) {
    return { state: "invalid", dir, file, reason: "fields" };
  }
  return { state: "ok", dir, file, data };
}

// readSyncConfig reads what the device pins for resource sync: the
// resource-service address and the Ed25519 public keys it trusts. The
// client never learns these from the service, so a compromised or
// misdirected service can't sign its own resources.
export function readSyncConfig(dir = stateDirectory()) {
  const file = path.join(dir, SYNC_CONFIG_FILE);
  let raw;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch (error) {
    return {
      state: error?.code === "ENOENT" ? "missing" : "unreadable",
      dir,
      file,
      code: error?.code || "unreadable",
    };
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    return { state: "invalid", dir, file, reason: "json" };
  }
  if (!data || typeof data !== "object") return { state: "invalid", dir, file, reason: "object" };

  const resourceBaseUrl = typeof data.resourceBaseUrl === "string" ? data.resourceBaseUrl.trim() : "";
  if (!resourceBaseUrl) return { state: "invalid", dir, file, reason: "resourceBaseUrl" };
  try {
    const parsed = new URL(resourceBaseUrl);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") throw new Error("scheme");
  } catch {
    return { state: "invalid", dir, file, reason: "resourceBaseUrl" };
  }

  const declared = data.signingKeys && typeof data.signingKeys === "object" && !Array.isArray(data.signingKeys)
    ? data.signingKeys
    : {};
  const publicKeys = {};
  const keyFingerprints = {};
  for (const [keyId, value] of Object.entries(declared)) {
    if (typeof value === "string" && value.trim()) {
      publicKeys[keyId] = value;
      continue;
    }
    if (value && typeof value === "object"
        && typeof value.publicKeyPem === "string" && value.publicKeyPem.trim()) {
      publicKeys[keyId] = value.publicKeyPem;
      if (typeof value.fingerprint === "string" && value.fingerprint.trim()) {
        keyFingerprints[keyId] = value.fingerprint.trim();
      }
    }
  }
  if (Object.keys(publicKeys).length === 0) {
    return { state: "invalid", dir, file, reason: "signingKeys" };
  }

  // displayNames lets an enterprise show a resource under the name people
  // know it by. desired-state carries only ids and the signed manifest, so
  // without an override the page has nothing but the content's heading.
  const displayNames = {};
  if (data.displayNames && typeof data.displayNames === "object" && !Array.isArray(data.displayNames)) {
    for (const [id, value] of Object.entries(data.displayNames)) {
      if (RESOURCE_ID.test(id) && typeof value === "string" && value.trim()) {
        displayNames[id] = value.trim().slice(0, 120);
      }
    }
  }

  return {
    state: "ok",
    dir,
    file,
    resourceBaseUrl,
    adminBaseUrl: typeof data.adminBaseUrl === "string" && data.adminBaseUrl.trim()
      ? data.adminBaseUrl.trim()
      : "",
    publicKeys,
    keyFingerprints,
    rootDir: typeof data.rootDir === "string" && data.rootDir.trim()
      ? path.resolve(dir, data.rootDir.trim())
      : path.join(dir, "resources"),
    clientSyncModule: typeof data.clientSyncModule === "string" ? data.clientSyncModule.trim() : "",
    clientVersion: typeof data.clientVersion === "string" ? data.clientVersion.trim() : "",
    displayNames,
    maxResourceBytes: Number.isSafeInteger(data.maxResourceBytes) && data.maxResourceBytes > 0
      ? data.maxResourceBytes
      : DEFAULT_MAX_RESOURCE_BYTES,
  };
}
