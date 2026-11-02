import fs from "node:fs/promises";
import path from "node:path";

import { LocalMcpError } from "./errors.js";

export class FileAuditSink {
  constructor(rootDir) {
    if (typeof rootDir !== "string" || !path.isAbsolute(rootDir)) {
      throw new LocalMcpError("invalid_config", "audit rootDir must be absolute");
    }
    this.file = path.join(rootDir, "audit.jsonl");
  }

  async write(event) {
    if (!event || typeof event !== "object" || Array.isArray(event)) {
      throw new LocalMcpError("audit_unavailable", "audit event must be an object");
    }
    const line = `${JSON.stringify(event)}\n`;
    let handle;
    try {
      await fs.mkdir(path.dirname(this.file), { recursive: true, mode: 0o700 });
      handle = await fs.open(this.file, "a", 0o600);
      await handle.writeFile(line, "utf8");
      await handle.sync();
    } catch {
      throw new LocalMcpError("audit_unavailable", "audit event could not be persisted");
    } finally {
      await handle?.close().catch(() => {});
    }
  }
}
