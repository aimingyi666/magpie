import { spawn } from "node:child_process";

const MAX_OUTPUT_BYTES = 64 << 10;
const KILL_GRACE_MS = 1500;

export class GatewayControlError extends Error {
  constructor(code, message, retryable = false) {
    super(message);
    this.name = "GatewayControlError";
    this.code = code;
    this.retryable = retryable;
  }
}

function childEnvironment(config) {
  const env = {
    HOME: config.configHome,
    USERPROFILE: config.configHome,
    XDG_CONFIG_HOME: config.configHome,
    TZ: process.env.TZ || "UTC",
    LANG: process.env.LANG || "C.UTF-8",
  };
  if (process.env.LC_ALL) env.LC_ALL = process.env.LC_ALL;
  for (const name of ["PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"]) {
    if (process.env[name]) env[name] = process.env[name];
  }
  return env;
}

function terminate(child) {
  try {
    if (!child.kill("SIGKILL")) child.kill();
  } catch {
    try {
      child.kill();
    } catch {
      // The close event decides the final result.
    }
  }
}

export function createMagpieRunner(config, options = {}) {
  const spawnImpl = options.spawn || spawn;

  function run(args, input = null) {
    return new Promise((resolve, reject) => {
      const startedAt = Date.now();
      let child;
      try {
        child = spawnImpl(config.magpiePath, args, {
          shell: false,
          cwd: config.configHome,
          env: childEnvironment(config),
          stdio: ["pipe", "pipe", "pipe"],
          windowsHide: true,
        });
      } catch {
        reject(new GatewayControlError("gateway_command_failed", "Magpie could not be started", true));
        return;
      }

      const stdout = [];
      const stderr = [];
      let outputBytes = 0;
      let stoppedFor = "";
      let spawnError = null;
      let finished = false;
      let graceTimer = null;
      let timeoutTimer = null;

      const stop = (reason) => {
        if (stoppedFor) return;
        stoppedFor = reason;
        terminate(child);
      };

      const finish = (exitCode, signal) => {
        if (finished) return;
        finished = true;
        clearTimeout(timeoutTimer);
        clearTimeout(graceTimer);
        const elapsedMs = Date.now() - startedAt;
        if (spawnError) {
          reject(new GatewayControlError("gateway_command_failed", "Magpie could not be started", true));
          return;
        }
        if (stoppedFor === "timeout") {
          reject(new GatewayControlError("gateway_timeout", "The gateway command timed out", true));
          return;
        }
        if (stoppedFor === "output") {
          reject(new GatewayControlError("gateway_output_too_large", "The gateway command output is too large", false));
          return;
        }
        resolve({
          exitCode,
          signal,
          stdout: Buffer.concat(stdout).toString("utf8"),
          stderr: Buffer.concat(stderr).toString("utf8"),
          elapsedMs,
        });
      };

      child.once("error", (error) => {
        spawnError = error;
        if (!child.pid) finish(null, null);
      });
      child.once("close", (exitCode, signal) => {
        clearTimeout(graceTimer);
        finish(exitCode, signal);
      });

      const collect = (target) => (chunk) => {
        outputBytes += chunk.length;
        if (outputBytes > (config.maxOutputBytes || MAX_OUTPUT_BYTES)) {
          stop("output");
          return;
        }
        target.push(chunk);
      };
      child.stdout.on("data", collect(stdout));
      child.stderr.on("data", collect(stderr));
      child.stdin.on("error", () => {
        // A command that exits early may close stdin first.
      });

      timeoutTimer = setTimeout(() => {
        stop("timeout");
        graceTimer = setTimeout(() => {
          if (!finished) finish(null, "SIGKILL");
        }, KILL_GRACE_MS);
      }, config.timeoutMs);

      if (input == null) child.stdin.end();
      else child.stdin.end(input);
    });
  }

  return Object.freeze({
    describe(id) {
      return run(["gateway-key", "describe", id, "--json"]);
    },
    apply(id, body) {
      return run(["gateway-key", "policy", "apply", id, "--json"], body);
    },
  });
}

export { MAX_OUTPUT_BYTES };
