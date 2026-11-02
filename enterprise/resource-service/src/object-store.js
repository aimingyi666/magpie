import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

function normalizeHash(value) {
  const hash = String(value || "").replace(/^sha256:/, "");
  if (!/^[a-f0-9]{64}$/.test(hash)) throw new Error("object hash must be SHA-256 hex");
  return hash;
}

async function writeFileSynced(file, data) {
  const handle = await fs.open(file, "wx", 0o600);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export class FileObjectStore {
  constructor(root) {
    this.root = path.resolve(root);
  }

  async load() {
    await fs.mkdir(this.root, { recursive: true, mode: 0o700 });
  }

  pathFor(hash) {
    const normalized = normalizeHash(hash);
    return path.join(this.root, normalized.slice(0, 2), normalized);
  }

  async put(content) {
    if (!Buffer.isBuffer(content) || content.length === 0) {
      throw new Error("object content must be a non-empty Buffer");
    }
    const hash = crypto.createHash("sha256").update(content).digest("hex");
    const target = this.pathFor(hash);
    const directory = path.dirname(target);
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });

    try {
      const existing = await fs.readFile(target);
      if (crypto.createHash("sha256").update(existing).digest("hex") !== hash) {
        throw new Error("object store content hash mismatch");
      }
      return { hash, bytes: content.length, created: false };
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }

    const temporary = path.join(directory, `.${hash}.${process.pid}.${crypto.randomUUID()}.tmp`);
    await writeFileSynced(temporary, content);
    try {
      await fs.link(temporary, target);
      return { hash, bytes: content.length, created: true };
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
      const existing = await fs.readFile(target);
      if (crypto.createHash("sha256").update(existing).digest("hex") !== hash) {
        throw new Error("object store content hash mismatch");
      }
      return { hash, bytes: content.length, created: false };
    } finally {
      await fs.rm(temporary, { force: true });
    }
  }

  async get(hash) {
    return fs.readFile(this.pathFor(hash));
  }

  async has(hash) {
    try {
      await fs.access(this.pathFor(hash));
      return true;
    } catch (error) {
      if (error.code === "ENOENT") return false;
      throw error;
    }
  }
}
