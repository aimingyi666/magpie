// One pass of everything the corporation sends down: the bundle, then the
// resources it carries, then the usage this machine owes back.
//
// A pass never applies an older revision: the server going back in time is
// a server that lost its data, not a reason to give an employee a set of
// models the corporation withdrew.
import { createClient } from "./client.mjs";
import { readBundle } from "./providers.mjs";
import { applyResources } from "./resources.mjs";
import { uploadAll } from "./upload.mjs";

export function clientFor({ config, store }) {
  const device = store.device();
  return createClient({
    baseUrl: config.baseUrl,
    getToken: () => store.device()?.deviceToken || "",
    timeoutMs: 20000,
  });
}

// syncBundle runs one pass and answers a summary the page shows.
export async function syncBundle({ config, store, run = undefined, now = () => new Date() }) {
  const startedAt = now().toISOString();
  const summary = {
    startedAt,
    revision: "",
    providers: 0,
    resources: { instructions: 0, mcp: 0, skills: 0 },
    upload: {},
    errors: [],
  };
  const state = store.state();
  const previous = state.revision;
  const client = clientFor({ config, store });

  let payload = null;
  try {
    const query = previous ? `?revision=${encodeURIComponent(previous)}` : "";
    const response = await client.request(`/api/v1/client/bundle${query}`);
    if (response.status === 304) {
      summary.revision = previous;
      payload = null;
    } else {
      payload = response.payload;
    }
  } catch (error) {
    summary.errors.push({ code: error?.code || "bundle_failed", message: String(error?.message || error) });
    store.update((next) => {
      next.lastSyncError = summary.errors[0].message;
      return next;
    });
    return summary;
  }

  if (payload) {
    const revision = String(payload.revision || "");
    const bundle = {
      revision,
      providers: Array.isArray(payload.providers) ? payload.providers : [],
      instructions: Array.isArray(payload.instructions) ? payload.instructions : [],
      mcp: Array.isArray(payload.mcp) ? payload.mcp : [],
      skills: Array.isArray(payload.skills) ? payload.skills : [],
      keptAt: startedAt,
    };
    if (previous && revision && revision < previous) {
      // a revision that sorts below the one already applied is a rollback
      summary.errors.push({ code: "revision_rollback", message: `The server offered ${revision}, older than ${previous}; kept the newer one` });
    } else {
      store.saveBundle(bundle);
      summary.revision = revision;
      summary.providers = bundle.providers.length;
      const applied = await applyResources(bundle, {
        configDir: config.configDir,
        magpieBin: config.magpieBin,
        dir: store.dir,
        applied: state.applied || {},
        ...(run ? { run } : {}),
      });
      summary.resources = {
        instructions: applied.applied.instructions.length,
        mcp: applied.applied.mcp.length,
        skills: applied.applied.skills.length,
      };
      summary.errors.push(...(applied.errors || []));
      store.update((next) => {
        next.revision = revision || next.revision;
        next.applied = applied.applied;
        next.lastSyncAt = startedAt;
        next.lastSyncError = summary.errors.length ? summary.errors[0].message : "";
        return next;
      });
    }
  } else {
    summary.revision = previous;
    summary.providers = (readBundle(store.dir)?.providers || []).length;
  }

  try {
    summary.upload = await uploadAll({ client, store, config, channels: config.upload });
  } catch (error) {
    summary.errors.push({ code: error?.code || "upload_failed", message: String(error?.message || error) });
  }

  summary.finishedAt = now().toISOString();
  return summary;
}
