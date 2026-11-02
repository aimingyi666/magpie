# Local MCP runtime

`@magpie-enterprise/local-mcp` is the client-side runtime for M3-D controlled
local MCP packages. It verifies an Ed25519-signed immutable package before any
code runs, applies enterprise publisher/capability/network/secret/tool policy,
launches the package with Node's permission model, and records append-only
metadata audits and bounded health counters.

The package now includes the client-facing integration core:

- `LocalMcpHelper` connects a signed client-sync resource to the local MCP
  runtime without accepting a package id from the caller.
- `createLocalMcpServer()` exposes the helper only on loopback with a Bearer
  token, a bounded JSON API, stable error codes, and a single-helper lock.
- `LocalMcpBridge` and the `magpie-local-mcp-bridge` executable expose a
  bounded newline-delimited JSON-RPC MCP server over stdio.
- `applyCodexAgentConfig()` manages only Magpie's marked block in Codex's
  `config.toml`, preserves other user configuration, and references the helper
  token by environment-variable name rather than writing its value.
- `setupLocalMcpClient()` orchestrates sync, reconcile, resource/tool
  selection, the loopback helper, Codex config readback, and controlled launch
  environment injection as one fail-closed setup operation.

This is still a runtime and helper core, not a complete employee product. The
installer, Windows service/MDM packaging, code signing, upgrade/rollback flow,
admin-console integration, real Codex client acceptance, browser E2E,
production secret broker, production token rotation/recovery, and real external
OS sandbox remain unfinished.

## Security boundary

- The manifest and every file are bound by SHA-256 digests and an Ed25519
  signature. A package with an unknown key, unsupported shape, unsafe path,
  hash mismatch, or different immutable release is rejected.
- Install writes files into staging, fsyncs them, verifies the installed copy,
  and atomically renames the release directory. Concurrent installs use a lock.
- Child processes start with `shell: false`, a restricted environment, and
  Node permission flags derived from signed capabilities.
- Network, clipboard, desktop, and native access require explicit enterprise
  grants and an external OS sandbox adapter where Node cannot enforce the
  boundary alone.
- Secret references are resolved at tool-call time through an HTTPS broker.
  Secret values are not persisted in the manifest, audit, health state, or
  result summary.
- Tool calls are denied unless the publisher, tool, risk level, and every
  capability pass enterprise policy. High-risk calls can require a verifier
  approval bound to the package digest and tool.
- Audit persistence is fail-closed. Health write failure prevents execution
  from starting or is surfaced as a failed call.

## Example

```js
import {
  LocalMcpHost,
  buildSignedPackage,
  publicKeyFingerprint,
} from "@magpie-enterprise/local-mcp";

const host = new LocalMcpHost({
  rootDir: "C:\\ProgramData\\Magpie\\local-mcp",
  publicKeys: { "enterprise-local-mcp-v1": publicKeyPem },
  keyFingerprints: {
    "enterprise-local-mcp-v1": publicKeyFingerprint(publicKey),
  },
  allowedPublishers: ["enterprise-platform"],
  allowedTools: ["search"],
  maxRisk: "low",
  allowedCapabilities: ["fs.read"],
  allowedNetworkHosts: [],
  interpreterAliases: { node: process.execPath },
  clientVersion: "1.0.0",
  platform: process.platform,
  architecture: process.arch,
});

await host.install(signedPackage);
const tools = await host.listTools("local-search", "2026.11.1");
const result = await host.callTool(
  "local-search",
  "2026.11.1",
  "search",
  { query: "policy" },
);
```

Package publishers use `buildSignedPackage(fields, files, privateKey)`.
`verifySignedPackage(publicKey, input)` is available for preflight checks.

## Client sync and local helper

The helper uses `ClientSyncEngine.readActiveResource()` as its only source of
active MCP package bytes. The engine re-reads state, rejects unsafe paths and
symlinks, verifies the Ed25519 manifest signature and content digest, and
checks that the on-disk manifest still matches the active state record.

During sync, pass the helper validator into the engine so only `mcp` resources
are installed into the local runtime:

```js
import { ClientSyncEngine } from "@magpie-enterprise/client-sync";
import { LocalMcpHelper } from "@magpie-enterprise/local-mcp";

let helper;
const syncEngine = new ClientSyncEngine({
  // ...the normal client-sync options...
  validateInstalled: (resource) => helper.validateClientResource(resource),
});
helper = new LocalMcpHelper({ clientSync: syncEngine, host });

await helper.synchronize();
const status = await helper.snapshot();
```

The helper never trusts a caller-supplied `packageId`, `releaseId`, path, or
secret. It resolves those identities from the verified active resource and
fails closed when the resource is inactive, drifted, not `kind: "mcp"`,
missing, tampered with, or not installed in the local runtime. `snapshot()`
returns only bounded identities, versions, health counters, and stable error
codes; it does not return resource bodies, secrets, private keys, or absolute
paths.

The local HTTP server accepts only `127.0.0.1` or `::1`, checks the peer
address again on every request, and binds its lock file under the configured
local MCP root. `/healthz` is public. The remaining routes require
`Authorization: Bearer <opaque helper token>`:

```text
GET  /api/v1/local-mcp/status
GET  /api/v1/local-mcp/resources/:resourceId/tools
POST /api/v1/local-mcp/resources/:resourceId/tools/:toolName/call
```

The call body is `{ "args": { ... }, "approval": { ... } }`; `approval` is
optional and must be an object. Unknown fields are rejected. The default body
limit is 256 KiB (configurable from 1 to 1024 KiB), responses use
`cache-control: no-store` and `x-content-type-options: nosniff`, and no CORS
permission is granted. A second helper using the same lock fails with
`helper_locked` (HTTP 409); `close()` is idempotent.

## Agent stdio bridge and Codex config

`magpie-local-mcp-bridge` speaks newline-delimited JSON-RPC over stdio and
supports only `initialize`, `tools/list`, and `tools/call`. Its helper URL must
be an HTTP loopback origin, and all three values below are required:

```text
MAGPIE_LOCAL_MCP_HELPER_URL=http://127.0.0.1:<port>
MAGPIE_LOCAL_MCP_HELPER_TOKEN=<opaque token>
MAGPIE_LOCAL_MCP_RESOURCE_ID=<signed MCP resource id>
```

The bridge never accepts a caller-supplied package path or release id. It
applies request, response, timeout, tool-name, and error-code bounds, and it
does not follow redirects or connect to non-loopback helpers.

Codex can be configured without editing unrelated entries:

```js
import {
  applyCodexAgentConfig,
  codexConfigPath,
} from "@magpie-enterprise/local-mcp";

const result = await applyCodexAgentConfig({
  configPath: codexConfigPath(),
  nodePath: process.execPath,
  bridgePath: "C:\\Program Files\\Magpie\\local-mcp-bridge.mjs",
  helperUrl: "http://127.0.0.1:3426",
  resourceId: "res_local_echo",
  tokenEnvName: "MAGPIE_LOCAL_MCP_HELPER_TOKEN",
});
```

The function supports `CODEX_HOME`, writes a marked `[mcp_servers.*]` block,
preserves BOM/CRLF and unrelated configuration, is idempotent, and uses an
atomic replacement. If a user changes the managed block outside Magpie, the
default result is `agent_config_drift`; pass `force: true` to replace it
explicitly. It refuses to overwrite an unmanaged server with the same name.

## One-click client setup orchestration

`setupLocalMcpClient()` is the client-side technical flow behind a future
"one-click configure agent" action. It performs the following sequence and
fails closed at every step:

```text
helper.synchronize()
  -> helper.reconcile()
  -> helper.snapshot() and resource selection
  -> helper.listTools()
  -> start the loopback helper server
  -> authenticated helper probe
  -> write the managed Codex MCP block
  -> inspect the managed block
  -> pass the launch environment to a controlled launcher
```

```js
import { setupLocalMcpClient } from "@magpie-enterprise/local-mcp";

const setup = await setupLocalMcpClient({
  helper,
  configPath: codexConfigPath(),
  nodePath: process.execPath,
  bridgePath: "C:\\Program Files\\Magpie\\local-mcp-bridge.mjs",
  rootDir: "C:\\ProgramData\\Magpie\\local-mcp",
  resourceId: "res_local_echo",
  injectLaunchEnvironment: async ({ environment }) => {
    // A controlled launcher must receive this environment and confirm readiness.
    return startCodexWithEnvironment(environment);
  },
});
```

`injectLaunchEnvironment` is mandatory. Without it, setup stops with
`token_injection_required` instead of creating a configuration that cannot
start. When no token is supplied, setup generates 32 random bytes as a
base64url token in memory. The token is never written to `config.toml` or the
public setup result; it is only passed in the frozen environment patch:

```text
MAGPIE_LOCAL_MCP_HELPER_TOKEN
MAGPIE_LOCAL_MCP_HELPER_URL
MAGPIE_LOCAL_MCP_RESOURCE_ID
```

The config still uses `env_vars` to reference the token variable. The launcher
must inject it into the Codex child process. The successful result exposes
bounded identities and control handles only:

```text
serverName, resourceId, helperUrl, tokenEnvName, toolCount,
sync, launch, close(), uninstall()
```

If more than one MCP resource is active, `resourceId` is required. Failures
close the helper server, release its lock, and remove the managed config block
written by this setup attempt. Stable failure codes include
`client_setup_sync_failed`, `client_setup_reconcile_failed`,
`client_setup_resource_required`, `client_setup_resource_not_found`,
`client_setup_resource_blocked`, `client_setup_tools_invalid`,
`client_setup_no_tools`, `client_setup_server_failed`,
`client_setup_readback_failed`, `client_setup_injection_failed`, and
`token_injection_required`.

## Tests

```powershell
& 'D:\Environment\node-v26.12.1\node.exe' --test .\enterprise\local-mcp\test\*.test.mjs
```

Current result: **60 passed, 0 failed** (21 runtime, 7 helper integration,
9 HTTP server, 5 bridge, 7 Codex config, 10 client setup, and 1
real-subprocess end-to-end test). They use isolated temporary roots, in-memory
test helpers, random loopback ports, and local child processes only. They do
not read production audit, health, usage, session, agent, secret, or real
`~/.codex/config.toml` files.

The end-to-end test runs
`setupLocalMcpClient + ClientSyncEngine + LocalMcpHost + helper HTTP server +
stdio bridge` in a real child process and covers managed config readback,
process-only environment injection, initialize, tools/list, tools/call, and
audit output. It does not prove that a real Codex client reads the generated
config, a real employee install, Windows service/MDM deployment, or a
production OS boundary.

## Not yet production-ready

- Local helper installer, Windows service/MDM packaging, code signing,
  upgrade/rollback, real Codex client acceptance, and administrator visibility.
- A production launcher contract, Windows ACL/DPAPI integration, token
  rotation/recovery, and crash-safe token persistence outside an
  operator-managed environment.
- Real OIDC, approval service, Secret Broker, KMS/HSM, and enterprise IdP.
- Windows ACL enforcement and a signed, recoverable installer.
- A proven external OS sandbox for network, clipboard, desktop, native, and
  broad filesystem controls.
- Docker/VM isolation, browser E2E, shared-volume concurrency, HA, and
  production acceptance.
