import { spawn } from "node:child_process";

import { LocalMcpError } from "./errors.js";

const DEFAULT_MAX_STDERR_BYTES = 64 * 1024;

export class JsonRpcProcessSession {
  constructor({
    command,
    args,
    cwd,
    env,
    maxMessageBytes,
    maxResponseBytes,
    maxStderrBytes = DEFAULT_MAX_STDERR_BYTES,
  }) {
    this.command = command;
    this.args = args;
    this.cwd = cwd;
    this.env = env;
    this.maxMessageBytes = maxMessageBytes;
    this.maxResponseBytes = maxResponseBytes;
    this.maxStderrBytes = maxStderrBytes;
    this.nextId = 1;
    this.pending = new Map();
    this.stdoutBytes = 0;
    this.stderrBytes = 0;
    this.lineBuffer = "";
    this.closed = false;
    this.child = null;
    this.exit = new Promise((resolve) => {
      this.resolveExit = resolve;
    });
  }

  async start() {
    if (this.child) return;
    try {
      this.child = spawn(this.command, this.args, {
        cwd: this.cwd,
        env: this.env,
        shell: false,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      throw new LocalMcpError("process_failed", "local MCP process could not be started");
    }
    await new Promise((resolve, reject) => {
      this.child.once("spawn", resolve);
      this.child.once("error", () => reject(new LocalMcpError(
        "process_failed",
        "local MCP process could not be started",
      )));
    });
    this.child.stdout.on("data", (chunk) => this.onStdout(chunk));
    this.child.stderr.on("data", (chunk) => {
      this.stderrBytes += chunk.length;
      if (this.stderrBytes > this.maxStderrBytes) this.fail("protocol_too_large");
    });
    this.child.once("close", (code, signal) => this.onClose(code, signal));
  }

  onStdout(chunk) {
    this.stdoutBytes += chunk.length;
    if (this.stdoutBytes > this.maxResponseBytes) {
      this.fail("protocol_too_large");
      return;
    }
    this.lineBuffer += chunk.toString("utf8");
    if (Buffer.byteLength(this.lineBuffer, "utf8") > this.maxMessageBytes) {
      this.fail("protocol_too_large");
      return;
    }
    let newline = this.lineBuffer.indexOf("\n");
    while (newline >= 0) {
      const line = this.lineBuffer.slice(0, newline);
      this.lineBuffer = this.lineBuffer.slice(newline + 1);
      if (line.trim()) this.onLine(line);
      newline = this.lineBuffer.indexOf("\n");
    }
  }

  onLine(line) {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      this.fail("protocol_invalid");
      return;
    }
    if (!message || message.jsonrpc !== "2.0" || typeof message !== "object") {
      this.fail("protocol_invalid");
      return;
    }
    if (message.id === undefined || message.id === null) return;
    const pending = this.pending.get(message.id);
    if (!pending) return;
    this.pending.delete(message.id);
    clearTimeout(pending.timer);
    if (message.error) {
      pending.reject(new LocalMcpError("tool_failed", "local MCP returned a JSON-RPC error"));
      return;
    }
    pending.resolve(message.result);
  }

  onClose(code, signal) {
    if (this.closed) return;
    this.closed = true;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new LocalMcpError("process_failed", "local MCP process exited"));
    }
    this.pending.clear();
    this.resolveExit({ code, signal });
  }

  fail(code) {
    if (this.closed) return;
    this.closed = true;
    this.child?.kill();
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new LocalMcpError(code, "local MCP protocol failed"));
    }
    this.pending.clear();
  }

  send(message) {
    if (this.closed || !this.child?.stdin?.writable) {
      throw new LocalMcpError("process_failed", "local MCP process is not writable");
    }
    const line = `${JSON.stringify(message)}\n`;
    if (Buffer.byteLength(line, "utf8") > this.maxMessageBytes) {
      throw new LocalMcpError("protocol_too_large", "local MCP request is too large");
    }
    this.child.stdin.write(line);
  }

  request(method, params, timeoutMs) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new LocalMcpError("process_timeout", "local MCP request timed out"));
        this.fail("process_timeout");
      }, timeoutMs);
      timer.unref?.();
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.send({ jsonrpc: "2.0", id, method, params });
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error);
      }
    });
  }

  notify(method, params) {
    this.send({ jsonrpc: "2.0", method, params });
  }

  async close() {
    if (!this.child) return;
    if (!this.closed) {
      this.closed = true;
      this.child.stdin.end();
      this.child.kill();
    }
    await Promise.race([
      this.exit,
      new Promise((resolve) => setTimeout(resolve, 500)),
    ]);
  }
}
