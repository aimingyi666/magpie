import path from "node:path";

import { LocalMcpError } from "./errors.js";

const UNSAFE_INTERPRETERS = new Set(["bash", "cmd", "cmd.exe", "powershell.exe", "pwsh.exe", "sh"]);
const EXTERNALLY_ENFORCED_CAPABILITIES = new Set([
  "network.connect",
  "clipboard.read",
  "clipboard.write",
  "desktop.control",
]);

function normalizeDirectory(value, label) {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || !path.isAbsolute(value)) {
    throw new LocalMcpError("invalid_config", `${label} must be absolute`);
  }
  return path.resolve(value);
}

export function buildSandboxCommand({
  manifest,
  packageDir,
  interpreter,
  workspaceDir = null,
  tempDir = null,
  environment,
  sandboxAdapter = null,
}) {
  if (typeof interpreter !== "string" || !path.isAbsolute(interpreter)) {
    throw new LocalMcpError("invalid_config", "interpreter must be an absolute path");
  }
  if (UNSAFE_INTERPRETERS.has(path.basename(interpreter).toLowerCase())) {
    throw new LocalMcpError("sandbox_unavailable", "shell interpreters are not allowed");
  }
  const workspace = normalizeDirectory(workspaceDir, "workspaceDir");
  const temporary = normalizeDirectory(tempDir, "tempDir");
  const capabilities = manifest.permissions.capabilities;
  const entrypoint = path.join(packageDir, ...manifest.runtime.entrypoint.split("/"));
  const relative = path.relative(packageDir, entrypoint);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new LocalMcpError("path_traversal", "entrypoint escapes the package directory");
  }

  const external = capabilities.filter((capability) => EXTERNALLY_ENFORCED_CAPABILITIES.has(capability));
  if (external.length && typeof sandboxAdapter?.wrap !== "function") {
    throw new LocalMcpError(
      "sandbox_unavailable",
      "an OS sandbox adapter is required for network, clipboard or desktop access",
    );
  }
  const needsWritableDirectory = capabilities.some((item) => item === "fs.write" || item === "fs.delete");
  if (needsWritableDirectory && !workspace && !temporary) {
    throw new LocalMcpError("sandbox_unavailable", "write capability has no writable scope");
  }

  const args = ["--permission", `--allow-fs-read=${packageDir}`];
  if (capabilities.includes("fs.read")) {
    if (workspace) args.push(`--allow-fs-read=${workspace}`);
    if (temporary) args.push(`--allow-fs-read=${temporary}`);
  }
  const writable = [];
  if (capabilities.some((item) => item === "fs.write" || item === "fs.delete")) {
    if (workspace) writable.push(workspace);
    if (temporary) writable.push(temporary);
  }
  for (const directory of new Set(writable)) args.push(`--allow-fs-write=${directory}`);
  if (capabilities.includes("network.connect")) args.push("--allow-net");
  if (capabilities.includes("process.spawn")) args.push("--allow-child-process");
  if (capabilities.includes("worker.start")) args.push("--allow-worker");
  if (capabilities.includes("native.addon")) args.push("--allow-addons");
  if (capabilities.includes("native.ffi")) args.push("--allow-ffi");
  args.push(entrypoint, ...manifest.runtime.args);

  const env = {
    ...environment,
    MAGPIE_LOCAL_MCP_PACKAGE_ID: manifest.packageId,
    MAGPIE_LOCAL_MCP_RELEASE_ID: manifest.releaseId,
    MAGPIE_LOCAL_MCP_CAPABILITIES: capabilities.join(","),
    MAGPIE_LOCAL_MCP_NETWORK_HOSTS: manifest.permissions.networkHosts.join(","),
  };
  if (temporary) {
    env.TEMP = temporary;
    env.TMP = temporary;
  }

  const profile = {
    packageId: manifest.packageId,
    releaseId: manifest.releaseId,
    capabilities: [...capabilities],
    networkHosts: [...manifest.permissions.networkHosts],
    packageDir,
    workspaceDir: workspace,
    tempDir: temporary,
  };
  let command = interpreter;
  let commandArgs = args;
  let commandEnv = env;
  if (sandboxAdapter) {
    let wrapped;
    try {
      wrapped = sandboxAdapter.wrap({
        command,
        args: commandArgs,
        cwd: packageDir,
        env: commandEnv,
        profile,
      });
    } catch {
      throw new LocalMcpError("sandbox_unavailable", "sandbox adapter failed");
    }
    if (!wrapped
        || typeof wrapped.command !== "string"
        || !path.isAbsolute(wrapped.command)
        || !Array.isArray(wrapped.args)
        || wrapped.args.some((arg) => typeof arg !== "string")
        || !wrapped.env
        || typeof wrapped.env !== "object"
        || Array.isArray(wrapped.env)) {
      throw new LocalMcpError("sandbox_unavailable", "sandbox adapter returned an invalid command");
    }
    command = wrapped.command;
    commandArgs = wrapped.args;
    commandEnv = wrapped.env;
  }
  return {
    command,
    args: commandArgs,
    cwd: packageDir,
    env: commandEnv,
    profile,
    mode: sandboxAdapter ? "external-adapter+node-permission" : "node-permission",
  };
}
