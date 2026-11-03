/**
 * Employee Portal - JSON Store (atomic writes)
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";

export class JsonStore {
  constructor(storePath) {
    this.storePath = storePath;
  }

  async read() {
    try {
      const data = await fs.readFile(this.storePath, "utf8");
      return JSON.parse(data);
    } catch {
      return { version: 1, agents: [], tickets: [], usageLog: [], models: [], mcpServers: [] };
    }
  }

  async write(data) {
    const tmpPath = this.storePath + ".tmp." + process.pid;
    try {
      await fs.writeFile(tmpPath, JSON.stringify(data, null, 2), "utf8");
      await fs.rename(tmpPath, this.storePath);
    } catch (err) {
      try {
        await fs.unlink(tmpPath);
      } catch {
        // ignore cleanup failure
      }
      throw err;
    }
  }

  async mutate(fn) {
    const data = await this.read();
    const result = fn(data);
    await this.write(data);
    return result;
  }
}

export function generateId(prefix = "id") {
  const rand = crypto.randomUUID().replace(/-/g, "").slice(0, 12);
  return `${prefix}_${rand}`;
}
