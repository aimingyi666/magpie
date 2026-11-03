import http from "node:http";
import { loadPortalConfig } from "./config.js";
import { createService } from "./service.js";

const config = loadPortalConfig();
const { handleRequest } = createService(config);

const server = http.createServer(handleRequest);

server.listen(config.port, () => {
  console.log("Employee portal running on port " + config.port);
});

server.on("error", (err) => {
  console.error("Server error:", err);
  process.exit(1);
});
