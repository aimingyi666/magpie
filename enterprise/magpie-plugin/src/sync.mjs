import path from "node:path";
import { pathToFileURL } from "node:url";

let running = null;

export function syncInProgress() {
  return running !== null;
}

// syncNow runs one sync at a time. A second click while the first is still
// going answers "busy" instead of racing the state file.
export function syncNow({ config, credential }) {
  if (running) return Promise.resolve({ status: "busy", error: { code: "sync_busy" } });
  running = runSync({ config, credential }).finally(() => {
    running = null;
  });
  return running;
}

async function runSync({ config, credential }) {
  const clientSync = await loadClientSync(config.clientSyncModule, config.dir);
  const clientVersion = clientSyncVersion(config.clientVersion || credential.clientVersion || "0.0.0");
  const transport = clientSync.createEnterpriseSyncTransport({
    authBaseUrl: credential.authUrl,
    resourceBaseUrl: config.resourceBaseUrl,
    deviceToken: credential.deviceToken,
    clientVersion,
  });
  const engine = new clientSync.ClientSyncEngine({
    rootDir: config.rootDir,
    publicKeys: config.publicKeys,
    keyFingerprints: config.keyFingerprints,
    clientVersion,
    maxResourceBytes: config.maxResourceBytes,
    fetchDesiredState: transport.fetchDesiredState,
    ...(config.agents && Object.keys(config.agents).length
      ? { agents: config.agents }
      : {}),
  });

  const result = await engine.syncOnce();
  let report;
  try {
    report = await transport.reportResult(result);
  } catch (error) {
    // The device did sync; only the report failed. Say which, so the page
    // doesn't call a good sync failed.
    report = { skipped: true, reason: "report_failed", code: error?.code || "report_failed" };
  }
  return {
    status: result.status,
    revision: result.revision || null,
    error: result.error || null,
    installed: result.installed || [],
    unchanged: result.unchanged || [],
    skipped: result.skipped || [],
    drift: result.drift || [],
    applied: result.applied || [],
    applyErrors: result.applyErrors || [],
    report,
    at: new Date().toISOString(),
  };
}

// join-enterprise.ps1 writes a display version such as "enterprise-1.0.0".
// The sync core compares semantic versions, so keep the x.y.z part.
function clientSyncVersion(value) {
  const match = /(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)/.exec(String(value));
  return match ? match[1] : String(value);
}

// loadClientSync finds the sync core beside this plugin (the repo's
// enterprise/client-sync), or where enterprise-sync.json says it is.
async function loadClientSync(explicit, baseDir) {
  const candidates = [];
  if (explicit) {
    candidates.push(explicit.includes("://") ? explicit : path.resolve(baseDir || process.cwd(), explicit));
  }
  candidates.push(new URL("../../client-sync/src/index.js", import.meta.url).href);

  let last;
  for (const candidate of candidates) {
    try {
      const url = candidate.includes("://") ? candidate : pathToFileURL(path.resolve(candidate)).href;
      return await import(url);
    } catch (error) {
      last = error;
    }
  }
  const error = new Error(
    "the enterprise client sync package was not found; set clientSyncModule in enterprise-sync.json",
  );
  error.code = "client_sync_module_missing";
  error.cause = last;
  throw error;
}
