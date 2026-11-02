import { loadConfig } from "./config.js";
import { createResourceServer } from "./service.js";

async function main() {
  const config = loadConfig();
  const { server } = await createResourceServer(config, {
    logger: ({ requestId, code, errorName }) => {
      console.error(`request ${requestId} failed: ${code} (${errorName})`);
    },
  });
  server.listen(config.port, config.bind, () => {
    console.log(`Magpie Enterprise resource service listening on ${config.bind}:${config.port}`);
    console.log(`Resource signing key id: ${config.signingKeyId}`);
  });

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`received ${signal}; shutting down`);
    const forced = setTimeout(() => process.exit(1), 10_000);
    forced.unref();
    try {
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
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
