import fs from "node:fs";
import path from "node:path";

// A resource id the sync engine would accept. Anything else is left out
// rather than shown as a resource.
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MAX_TITLE = 120;

function recordOf(value) {
  if (!value || typeof value !== "object") return null;
  if (typeof value.resourceId !== "string" || !SAFE_ID.test(value.resourceId)) return null;
  const releaseId = typeof value.releaseId === "string" && SAFE_ID.test(value.releaseId)
    ? value.releaseId
    : "";
  return {
    resourceId: value.resourceId,
    releaseId,
    resourceVersion: typeof value.resourceVersion === "string" ? value.resourceVersion : "",
    kind: typeof value.kind === "string" ? value.kind : "",
    deliveryMode: value.deliveryMode === "forced" ? "forced" : "recommended",
    hash: typeof value.hash === "string" ? value.hash : "",
    manifestDigest: typeof value.manifestDigest === "string" ? value.manifestDigest : "",
    signingKeyId: typeof value.signingKeyId === "string" ? value.signingKeyId : "",
    installedAt: typeof value.installedAt === "string" ? value.installedAt : "",
  };
}

// resourceTitle finds what to call a resource: the release's own metadata
// when the control plane sends a title, else the first heading of its
// content. The desired state carries only ids, so without this the page
// had nothing but res_… to show.
function resourceTitle(rootDir, record) {
  if (!rootDir || !record?.releaseId) return "";
  const release = path.join(rootDir, "releases", record.resourceId, record.releaseId);
  try {
    const meta = JSON.parse(fs.readFileSync(path.join(release, "metadata.json"), "utf8"));
    const named = [meta?.title, meta?.displayName, meta?.name]
      .find((value) => typeof value === "string" && value.trim());
    if (named) return clipTitle(named);
  } catch {
    // no metadata, or not JSON: the content may still have a heading
  }
  try {
    const heading = /^#\s+(.+)$/m.exec(readHead(path.join(release, "content")));
    if (heading) return clipTitle(heading[1]);
  } catch {
    // removed after the state was written, or unreadable
  }
  return "";
}

// readHead reads only the start of a resource's content: a title is in its
// first lines, and a resource may be megabytes.
function readHead(file) {
  const fd = fs.openSync(file, "r");
  try {
    const buf = Buffer.alloc(4096);
    const read = fs.readSync(fd, buf, 0, buf.length, 0);
    return buf.toString("utf8", 0, read);
  } finally {
    fs.closeSync(fd);
  }
}

function clipTitle(value) {
  const line = String(value).replace(/\s+/g, " ").trim();
  return line.length > MAX_TITLE ? `${line.slice(0, MAX_TITLE - 1)}…` : line;
}

// readSyncState reads the engine's state.json. A missing file is "never"
// (the device has not synced); a file that can't be read or parsed is
// "unknown", and the page says so instead of showing an empty device.
// No absolute path is returned: it is not the page's to know.
export function readSyncState(rootDir) {
  const file = path.join(rootDir, "state.json");
  let raw;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") return { state: "never" };
    return { state: "unreadable", code: error?.code || "unreadable" };
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    return { state: "invalid", reason: "json" };
  }
  if (!data || data.schemaVersion !== 1) return { state: "invalid", reason: "schema" };

  const active = Array.isArray(data.resources) ? data.resources.map(recordOf).filter(Boolean) : [];
  const desired = data.desired && Array.isArray(data.desired.resources)
    ? data.desired.resources.map(recordOf).filter(Boolean)
    : [];
  const disabledRecommended = Array.isArray(data.disabledRecommended)
    ? data.disabledRecommended.filter((id) => typeof id === "string" && SAFE_ID.test(id))
    : [];

  return {
    state: "ok",
    dir: rootDir,
    revision: typeof data.revision === "string" ? data.revision : null,
    desiredRevision: data.desired && typeof data.desired.revision === "string" ? data.desired.revision : null,
    lastSuccessfulSyncAt: typeof data.lastSuccessfulSyncAt === "string" ? data.lastSuccessfulSyncAt : null,
    lastAttemptAt: typeof data.lastAttemptAt === "string" ? data.lastAttemptAt : null,
    lastError: data.lastError && typeof data.lastError === "object"
      ? {
        code: typeof data.lastError.code === "string" ? data.lastError.code : "unknown",
        at: typeof data.lastError.at === "string" ? data.lastError.at : null,
      }
      : null,
    active,
    desired,
    disabledRecommended,
  };
}

// resourceRows is what the page shows: the desired resources first, each
// with whether the active version is the desired one, then installed
// resources the control plane no longer assigns.
export function resourceRows(state, displayNames = {}) {
  if (state.state !== "ok") return [];
  const activeById = new Map(state.active.map((record) => [record.resourceId, record]));
  const seen = new Set();
  const rows = [];
  for (const wanted of state.desired) {
    seen.add(wanted.resourceId);
    const installed = activeById.get(wanted.resourceId);
    let status = "missing";
    if (installed) {
      status = installed.releaseId === wanted.releaseId && installed.hash === wanted.hash
        ? "installed"
        : "drift";
    }
    if (state.disabledRecommended.includes(wanted.resourceId)) status = "disabled";
    rows.push({
      ...wanted,
      title: displayNames[wanted.resourceId] || resourceTitle(state.dir, installed || wanted),
      installedReleaseId: installed?.releaseId || "",
      installedVersion: installed?.resourceVersion || "",
      installedAt: installed?.installedAt || "",
      status,
    });
  }
  for (const installed of state.active) {
    if (seen.has(installed.resourceId)) continue;
    rows.push({
      ...installed,
      title: displayNames[installed.resourceId] || resourceTitle(state.dir, installed),
      installedReleaseId: installed.releaseId,
      installedVersion: installed.resourceVersion,
      status: "orphaned",
    });
  }
  return rows;
}
