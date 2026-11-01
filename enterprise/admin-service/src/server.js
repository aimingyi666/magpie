import { loadConfig } from "./config.js";
import { createEnterpriseAdminServer } from "./service.js";

async function main() {
  const config = loadConfig();
  const { server, modelCatalog } = await createEnterpriseAdminServer(config);
  server.listen(config.port, config.bind, () => {
    console.log(`Magpie Enterprise admin listening on ${config.bind}:${config.port}`);
    console.log(`Management OIDC redirect URI: ${config.oidc.redirectUri}`);
    console.log(`Model catalog loaded: ${JSON.stringify(modelCatalog.status)}`);
  });

  const shutdown = (signal) => {
    console.log(`received ${signal}; shutting down`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000).unref();
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

main().catch((error) => {
  console.error(`startup failed: ${error.message}`);
  process.exit(1);
});
