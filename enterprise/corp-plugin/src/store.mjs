// The files this plugin keeps: the device credential, the bundle the
// server hands out, and the cursors its uploads have reached.
//
// One store, one file each, written whole (temp file, sync, rename) so a
// crash leaves the old file rather than half a new one. The credential
// file is 0600: it is the device's gateway key.
import fs from "node:fs";
import path from "node:path";

const FILES = Object.freeze({
  device: "device.json",
  bundle: "bundle.json",
  state: "state.json",
});

function readJson(file) {
  try {
    const raw = fs.readFileSync(file, "utf8");
    const value = JSON.parse(raw);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    return value;
  } catch {
    return null;
  }
}

function writeJson(file, value, mode) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  const fd = fs.openSync(temporary, "w", mode);
  try {
    fs.writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(temporary, file);
}

// emptyState is what a machine that never synced has: no cursors, no
// revision, nothing said.
function emptyState() {
  return {
    version: 1,
    revision: "",
    lastSyncAt: "",
    lastSyncError: "",
    cursors: { usage: "", masking: "", sessions: "" },
    lastUploadAt: {},
    providerAppliedAt: "",
    appliedProviders: [],
  };
}

export function createStore(dir) {
  const at = (name) => path.join(dir, FILES[name]);

  return {
    dir,

    device() {
      const value = readJson(at("device"));
      if (!value || typeof value.deviceToken !== "string" || !value.deviceToken) return null;
      return value;
    },
    saveDevice(device, mode = 0o600) {
      writeJson(at("device"), device, mode);
    },

    bundle() {
      return readJson(at("bundle"));
    },
    saveBundle(bundle) {
      writeJson(at("bundle"), bundle, 0o600);
    },

    state() {
      const value = readJson(at("state")) || {};
      return { ...emptyState(), ...value, cursors: { ...emptyState().cursors, ...(value.cursors || {}) } };
    },
    saveState(value) {
      writeJson(at("state"), value, 0o600);
    },
    update(fn) {
      const next = fn(this.state());
      this.saveState(next);
      return next;
    },
  };
}

// deviceUsable says whether a device record can still be used at now, with
// skewSeconds of room. A record with no expiry is usable: the server
// decides, and a 401 sends the user back to sign-in.
export function deviceUsable(device, now = Date.now(), skewSeconds = 300) {
  if (!device || !device.deviceToken) return false;
  if (!device.expiresAt) return true;
  const at = Date.parse(device.expiresAt);
  if (!Number.isFinite(at)) return true;
  return at - skewSeconds * 1000 > now;
}
