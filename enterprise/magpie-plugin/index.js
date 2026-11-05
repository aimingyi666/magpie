// The plugin host's part of the enterprise page. The page itself is a
// sandboxed frame that magpie serves with connect-src 'none', so it opens
// this loopback service instead of calling it: page/index.html hands its
// frame to the service, and the service draws the page (docs/subsystems/
// plugin-runtime.md, P4).
//
// The service is where the device credential, the pinned signing keys and
// the client sync engine live. None of them reaches the page.
import { DEFAULT_SERVICE_PORT } from "./src/config.mjs";
import { startService } from "./src/service.mjs";

let started;

export default async function enterprise(_input, options = {}) {
  const chosen = Number(options?.port);
  const port = Number.isInteger(chosen) && chosen > 0 && chosen < 65536
    ? chosen
    : DEFAULT_SERVICE_PORT;
  if (!started) {
    // The administrator's management console address comes from the
    // environment or from what joining the enterprise pinned; the plugin
    // never guesses one.
    const adminUrl = String(
      process.env.MAGPIE_ENTERPRISE_ADMIN_URL
        || options?.adminUrl
        || "",
    ).trim();
    started = startService({ port, adminUrl: adminUrl || undefined }).catch((error) => {
      started = undefined;
      throw error;
    });
  }
  await started;
}
