import { loadConfig } from "./config.js";
import { createEnterpriseAdminServer } from "./service.js";

async function main() {
  const config = loadConfig();
  const {
    server,
    modelCatalog,
    notificationDispatcher,
  } = await createEnterpriseAdminServer(config);
  server.listen(config.port, config.bind, () => {
    console.log(`Magpie Enterprise admin listening on ${config.bind}:${config.port}`);
    console.log(`Management OIDC redirect URI: ${config.oidc.redirectUri}`);
    console.log(`Model catalog loaded: ${JSON.stringify(modelCatalog.status)}`);
  });

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`received ${signal}; shutting down`);
    const forced = setTimeout(() => process.exit(1), 10000);
    forced.unref();
    try {
      await notificationDispatcher?.stop();
      await new Promise((resolve) => server.close(resolve));
      clearTimeout(forced);
      process.exit(0);
    } catch {
      process.exit(1);
    }
  };
  process.on("SIGINT", () => {
    void shutdown("SIGINT");
  });
  process.on("SIGTERM", () => {
    void shutdown("SIGTERM");
  });
}

main().catch((error) => {
  console.error(`startup failed: ${error.message}`);
  process.exit(1);
});
