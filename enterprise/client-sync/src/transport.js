import { ClientSyncError } from "./errors.js";

export const DEFAULT_SYNC_TIMEOUT_MS = 15_000;
export const DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

const CREDENTIAL_SKEW_MS = 30_000;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
const REVISION_PATTERN = /^sha256:[a-f0-9]{64}$/;
const CREDENTIAL_PATTERN = /^mss1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const SYNC_REPORT_STATUSES = new Set([
  "synced",
  "up_to_date",
  "failed",
  "offline",
  "drift",
  "busy",
]);
const DRIFT_STATES = new Set([
  "missing",
  "version_mismatch",
  "not_in_desired_state",
  "content_invalid",
  "metadata_mismatch",
  "path_symlink",
]);

function assertBaseUrl(value, name) {
  if (typeof value !== "string" || !value.trim()) {
    throw new ClientSyncError("invalid_config", `${name} is required`);
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new ClientSyncError("invalid_config", `${name} is invalid`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new ClientSyncError("invalid_config", `${name} must use https`);
  }
  if (url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname)) {
    throw new ClientSyncError("invalid_config", `${name} must use https`);
  }
  if (url.username || url.password) {
    throw new ClientSyncError("invalid_config", `${name} must not carry credentials`);
  }
  if (url.search || url.hash) {
    throw new ClientSyncError("invalid_config", `${name} must not carry a query or fragment`);
  }
  return url;
}

function joinUrl(base, pathname) {
  const url = new URL(base.toString());
  url.pathname = `${url.pathname.replace(/\/+$/, "")}${pathname}`;
  return url.toString();
}

async function readLimited(response, maxBytes) {
  const declared = Number(response.headers.get("content-length") || "");
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new ClientSyncError("response_too_large", "response is too large");
  }
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new ClientSyncError("response_too_large", "response is too large");
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, total);
}

function parseJson(buffer) {
  try {
    return JSON.parse(buffer.toString("utf8"));
  } catch {
    throw new ClientSyncError("invalid_response", "response is not valid JSON");
  }
}

function errorCodeOf(body) {
  const code = body?.error?.code;
  return typeof code === "string" ? code : "";
}

function withTimeout(signal, timeoutMs) {
  const controller = new AbortController();
  const abort = () => controller.abort(signal?.reason);
  if (signal?.aborted) abort();
  else signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref?.();
  return {
    signal: controller.signal,
    release() {
      clearTimeout(timer);
      signal?.removeEventListener?.("abort", abort);
    },
  };
}

function normalizeStatus(status) {
  if (typeof status !== "string") return "failed";
  if (status === "in_sync") return "up_to_date";
  if (status === "last_sync_failed") return "failed";
  return SYNC_REPORT_STATUSES.has(status) ? status : "failed";
}

function normalizeInstalled(records) {
  if (!Array.isArray(records)) return [];
  return records
    .filter((record) => record
      && typeof record.resourceId === "string"
      && typeof record.releaseId === "string"
      && typeof record.manifestDigest === "string"
      && REVISION_PATTERN.test(record.manifestDigest))
    .map((record) => ({
      resourceId: record.resourceId,
      releaseId: record.releaseId,
      manifestDigest: record.manifestDigest,
    }));
}

function normalizeDrift(entries) {
  if (!Array.isArray(entries)) return [];
  return entries
    .filter((entry) => entry
      && typeof entry.resourceId === "string"
      && DRIFT_STATES.has(entry.state))
    .map((entry) => ({
      resourceId: entry.resourceId,
      state: entry.state,
      expectedReleaseId: typeof entry.expectedReleaseId === "string" ? entry.expectedReleaseId : "",
      actualReleaseId: typeof entry.actualReleaseId === "string" ? entry.actualReleaseId : "",
    }));
}

/**
 * Builds the transport that connects the local sync engine to the enterprise
 * control plane: auth-service mints the short-lived sync credential, and
 * resource-service serves the desired state and accepts the device report.
 *
 * The device token is only ever sent to auth-service, and the sync credential
 * is only ever sent to resource-service. Neither value is logged, persisted or
 * put into an error message.
 */
export function createEnterpriseSyncTransport({
  authBaseUrl,
  resourceBaseUrl,
  deviceToken,
  clientVersion,
  fetch: fetchImpl = globalThis.fetch,
  timeoutMs = DEFAULT_SYNC_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES,
  now = () => Date.now(),
} = {}) {
  const authBase = assertBaseUrl(authBaseUrl, "authBaseUrl");
  const resourceBase = assertBaseUrl(resourceBaseUrl, "resourceBaseUrl");
  if (typeof deviceToken !== "string" || !deviceToken.trim()) {
    throw new ClientSyncError("invalid_config", "deviceToken is required");
  }
  if (typeof clientVersion !== "string" || !clientVersion.trim()) {
    throw new ClientSyncError("invalid_config", "clientVersion is required");
  }
  if (typeof fetchImpl !== "function") {
    throw new ClientSyncError("invalid_config", "fetch must be a function");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120000) {
    throw new ClientSyncError("invalid_config", "timeoutMs must be 1000-120000");
  }
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1024) {
    throw new ClientSyncError("invalid_config", "maxResponseBytes must be at least 1024");
  }

  let credential = null;
  let snapshot = null;

  async function send({ url, method, headers, body, signal }) {
    const timeout = withTimeout(signal, timeoutMs);
    try {
      const response = await fetchImpl(url, {
        method,
        headers,
        body,
        signal: timeout.signal,
        redirect: "error",
      });
      const payload = await readLimited(response, maxResponseBytes);
      return { status: response.status, headers: response.headers, body: payload };
    } catch (error) {
      if (error instanceof ClientSyncError) throw error;
      if (signal?.aborted) {
        throw new ClientSyncError("sync_aborted", "client sync was aborted");
      }
      throw new ClientSyncError("desired_state_unavailable", "the control plane is unreachable");
    } finally {
      timeout.release();
    }
  }

  async function mintCredential(signal) {
    const response = await send({
      url: joinUrl(authBase, "/api/v1/devices/sync-credential"),
      method: "POST",
      headers: { authorization: `Bearer ${deviceToken}` },
      signal,
    });
    if (response.status !== 200) {
      throw new ClientSyncError(
        "sync_credential_unavailable",
        "the sync credential could not be issued",
      );
    }
    const body = parseJson(response.body);
    if (body?.schemaVersion !== 1
        || typeof body.credential !== "string"
        || !CREDENTIAL_PATTERN.test(body.credential)
        || !Number.isFinite(Date.parse(body.expiresAt))) {
      throw new ClientSyncError("sync_credential_unavailable", "the sync credential could not be issued");
    }
    credential = {
      value: body.credential,
      expiresAtMs: Date.parse(body.expiresAt),
    };
    return credential;
  }

  async function ensureCredential(signal) {
    const current = Number(now());
    if (credential && credential.expiresAtMs - CREDENTIAL_SKEW_MS > current) {
      return credential;
    }
    return mintCredential(signal);
  }

  function decodeSnapshot(body) {
    const parsed = parseJson(body);
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.resources)) {
      throw new ClientSyncError("invalid_response", "the desired state is malformed");
    }
    const resources = parsed.resources.map((resource) => {
      if (!resource || typeof resource !== "object"
          || !resource.manifest || typeof resource.manifest !== "object"
          || typeof resource.contentBase64 !== "string") {
        throw new ClientSyncError("invalid_response", "the desired state is malformed");
      }
      const content = Buffer.from(resource.contentBase64, "base64");
      if (content.toString("base64").replace(/=+$/, "") !== resource.contentBase64.replace(/=+$/, "")) {
        throw new ClientSyncError("invalid_response", "the desired state is malformed");
      }
      return { manifest: resource.manifest, content };
    });
    return {
      schemaVersion: parsed.schemaVersion,
      revision: parsed.revision,
      generatedAt: parsed.generatedAt,
      resources,
    };
  }

  async function requestDesiredState(signal, retry, revision) {
    const current = await ensureCredential(signal);
    const headers = { authorization: `Bearer ${current.value}` };
    if (typeof revision === "string"
        && snapshot
        && snapshot.revision === revision) {
      headers["if-none-match"] = `"${revision}"`;
    }
    const response = await send({
      url: joinUrl(resourceBase, "/api/v1/client/sync/desired-state"),
      method: "GET",
      headers,
      signal,
    });
    if (response.status === 304) {
      if (!snapshot || snapshot.revision !== revision) {
        throw new ClientSyncError("desired_state_unavailable", "the control plane reported no change");
      }
      return snapshot;
    }
    if (response.status === 401) {
      const code = errorCodeOf(parseJson(response.body));
      if (retry
          && (code === "invalid_sync_token" || code === "sync_token_expired")) {
        credential = null;
        return requestDesiredState(signal, false, revision);
      }
      throw new ClientSyncError("desired_state_unavailable", "the sync credential was rejected");
    }
    if (response.status !== 200) {
      throw new ClientSyncError("desired_state_unavailable", "the control plane rejected the request");
    }
    const decoded = decodeSnapshot(response.body);
    snapshot = decoded;
    return decoded;
  }

  async function fetchDesiredState({ revision, signal } = {}) {
    return requestDesiredState(signal, true, revision);
  }

  async function postReport(body, retry) {
    const current = await ensureCredential();
    const response = await send({
      url: joinUrl(resourceBase, "/api/v1/client/sync/report"),
      method: "POST",
      headers: {
        authorization: `Bearer ${current.value}`,
        "content-type": "application/json",
      },
      body: Buffer.from(JSON.stringify(body), "utf8"),
    });
    if (response.status === 401) {
      const code = errorCodeOf(parseJson(response.body));
      if (retry
          && (code === "invalid_sync_token" || code === "sync_token_expired")) {
        credential = null;
        return postReport(body, false);
      }
      throw new ClientSyncError("sync_report_rejected", "the sync credential was rejected");
    }
    if (response.status !== 202 && response.status !== 200) {
      throw new ClientSyncError("sync_report_rejected", "the control plane rejected the report");
    }
    return { skipped: false, accepted: true, revision: body.revision };
  }

  async function reportResult(result) {
    const state = result?.state;
    const revision = result?.revision || state?.revision;
    if (typeof revision !== "string" || !REVISION_PATTERN.test(revision)) {
      return { skipped: true, reason: "no_revision" };
    }
    const body = {
      schemaVersion: 1,
      revision,
      clientVersion,
      status: normalizeStatus(result?.status),
      installed: normalizeInstalled(state?.resources),
      drift: normalizeDrift(result?.drift),
      reportedAt: new Date(now()).toISOString(),
    };
    return postReport(body, true);
  }

  return { fetchDesiredState, reportResult };
}
