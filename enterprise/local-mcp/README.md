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

This is still a runtime and helper core, not a complete employee product. The
installer, Windows service/MDM packaging, code signing, upgrade/rollback flow,
admin-console integration, browser E2E, production secret broker, and real
external OS sandbox remain unfinished.

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

## Tests

```powershell
& 'D:\Environment\node-v26.12.1\node.exe' --test .\enterprise\local-mcp\test\*.test.mjs
```

Current result: **37 passed, 0 failed** (21 runtime, 7 helper integration, and
9 HTTP server tests). They use isolated temporary roots, in-memory test
helpers, and local child processes only. They do not read production audit,
health, usage, session, agent, or secret files.

The tests prove the individual contracts with mock client-sync and runtime
adapters. They do not prove a full
`ClientSyncEngine + LocalMcpHost + HTTP server` end-to-end flow, a real
employee install, or a production OS boundary.

## Not yet production-ready

- Local helper installer, Windows service/MDM packaging, code signing,
  upgrade/rollback, target-agent configuration, and administrator visibility.
- Real OIDC, approval service, Secret Broker, KMS/HSM, and enterprise IdP.
- Windows ACL enforcement and a signed, recoverable installer.
- A proven external OS sandbox for network, clipboard, desktop, native, and
  broad filesystem controls.
- Docker/VM isolation, browser E2E, shared-volume concurrency, HA, and
  production acceptance.
