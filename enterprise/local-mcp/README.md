# Local MCP runtime

`@magpie-enterprise/local-mcp` is the client-side runtime for M3-D controlled
local MCP packages. It verifies an Ed25519-signed immutable package before any
code runs, applies enterprise publisher/capability/network/secret/tool policy,
launches the package with Node's permission model, and records append-only
metadata audits and bounded health counters.

This package is a runtime core. It is not yet connected to the employee helper,
admin console, browser flow, Windows service/MDM, or a production secret broker.

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

## Tests

```powershell
& 'D:\Environment\node-v26.12.1\node.exe' --test .\enterprise\local-mcp\test\*.test.mjs
```

Tests use isolated temporary roots and local child processes only. They do not
read production audit, health, usage, session, agent, or secret files.

## Not yet production-ready

- Local helper/agent configuration integration and administrator visibility.
- Real OIDC, approval service, Secret Broker, KMS/HSM, and enterprise IdP.
- Windows ACL/MDM enforcement, code signing, installer rollback, and upgrades.
- A proven external OS sandbox for network, clipboard, desktop, native, and
  broad filesystem controls.
- Docker/VM isolation, browser E2E, shared-volume concurrency, HA, and
  production acceptance.
