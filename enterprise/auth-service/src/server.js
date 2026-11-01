import { loadConfig } from "./config.js";
import { createEnterpriseAuthServer } from "./service.js";

async function main() {
  const config = loadConfig();
  const { server } = await createEnterpriseAuthServer(config);
  server.listen(config.port, config.bind, () => {
    console.log(`Magpie Enterprise auth listening on ${config.bind}:${config.port}`);
    console.log(`OIDC redirect URI: ${config.oidc.redirectUri}`);
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
