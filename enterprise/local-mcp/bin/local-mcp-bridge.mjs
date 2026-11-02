#!/usr/bin/env node

import { bridgeFromEnvironment, runBridgeStdio } from "../src/bridge.js";

try {
  const bridge = bridgeFromEnvironment(process.env);
  process.stdout.on("error", (error) => {
    if (error.code === "EPIPE") process.exit(0);
    throw error;
  });
  await runBridgeStdio({ bridge });
} catch (error) {
  const code = typeof error?.code === "string"
    ? error.code.replace(/[^a-z0-9_]/g, "_").slice(0, 64)
    : "bridge_start_failed";
  process.stderr.write(`local MCP bridge failed: ${code}\n`);
  process.exitCode = 1;
}
