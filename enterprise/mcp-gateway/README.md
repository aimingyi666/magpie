# Magpie Enterprise remote MCP gateway

Status: **M3-B core implemented and covered by 14 unit/Mock integration tests.
M3-C resource-sync core now lives in `enterprise/client-sync`; M3-D and
production acceptance are not implemented.**

This service is the enterprise control point for remote MCP servers. It gives
Magpie clients one stable MCP endpoint while keeping upstream credentials,
server assignment and tool policy off employee devices.

## What is implemented

- A metadata-only remote MCP registry with owner, namespace, endpoint,
  secret-reference name, assignments, tool policy, state and health.
- Admin APIs for server registration/read/update/check and client
  issuance/list/revocation.
- `POST /mcp/enterprise`, a tools-only Streamable HTTP JSON-RPC endpoint for
  `initialize`, `notifications/initialized`, `ping`, `tools/list`,
  `tools/call` and `notifications/cancelled`.
- Server-side enforcement of user, organization, device and server scopes.
- Tool namespacing as `<server-namespace>__<upstream-tool>`, tool-level
  allow/deny, risk and visibility filtering.
- Short-lived HMAC approval tokens for high/critical tools, bound to approval,
  client, server, tool, time and nonce. Missing approval configuration fails
  closed.
- HTTPS-only upstreams by default, host allowlisting, DNS resolution checks,
  validated-address pinning, redirect rejection, timeouts, response-size
  limits, rate limits and per-server circuit breakers.
- Atomic JSON registry persistence, SHA-256 client-token digests, environment
  secret references and metadata-only audit records.

## Not implemented

- Admin console, employee portal, productized client synchronization and real
  OIDC-to-registry assignment. The M3-C resource-sync engine is implemented
  separately, but no device credential API, local helper flow or admin drift
  view connects it to this gateway. M3-D remains unimplemented.
- Real admin-service approval query/one-time consumption. The M3-B approval
  token is an independently signed gate, not proof that an admin approval was
  queried from APR-01.
- Local MCP packages, signed sandboxes, secret brokers, KMS/HSM and mTLS.
- Multi-replica/shared storage. Approval replay nonces are held in memory and
  rate limiters are per process.
- A real MCP server, enterprise IdP, browser E2E, Docker/Compose runtime
  startup or production acceptance.

## Run locally

Use Node.js 22 or newer. The service has no runtime package dependencies.

```powershell
$env:MCP_SERVICE_TOKEN = "<at-least-32-random-characters>"
$env:MCP_STORE_PATH = "$PWD/data/mcp-registry.json"
$env:MCP_AUDIT_PATH = "$PWD/data/mcp-audit.jsonl"
$env:MCP_UPSTREAM_ALLOWED_HOSTS = "mcp.search.corp.example"
$env:MCP_APPROVAL_HMAC_SECRET = "<at-least-32-random-characters>"
node enterprise/mcp-gateway/src/server.js
```

The service listens on `0.0.0.0:3448` by default. Bind it to an internal
interface and put TLS/reverse-proxy termination in front of it for any
non-loopback deployment.

Run tests:

```powershell
node --test enterprise/mcp-gateway/test/mcp-gateway.test.mjs
```

## Compose profile

The profile is internal-only and publishes no host port:

```bash
cd enterprise
docker compose --profile mcp-gateway up -d mcp-gateway
```

Set the M3-B values in `enterprise/.env`. The container runs read-only, drops
all Linux capabilities, enables `no-new-privileges`, and stores state only in
the `mcp-data` volume.

This repository has not executed the Compose profile on a Docker host. Static
review is not runtime acceptance.

## Admin API

Every admin request requires:

```http
Authorization: Bearer <MCP_SERVICE_TOKEN>
X-Magpie-Actor: <control-plane service identity>
```

Writes additionally require `Idempotency-Key`, `operationId` and `reason`.
Updates require `expectedUpdatedAt`.

| Method | Path |
| --- | --- |
| `POST` | `/api/v1/admin/mcp/servers` |
| `GET` | `/api/v1/admin/mcp/servers` |
| `GET` | `/api/v1/admin/mcp/servers/{serverId}` |
| `PUT` | `/api/v1/admin/mcp/servers/{serverId}` |
| `POST` | `/api/v1/admin/mcp/servers/{serverId}/check` |
| `POST` | `/api/v1/admin/mcp/clients` |
| `GET` | `/api/v1/admin/mcp/clients` |
| `POST` | `/api/v1/admin/mcp/clients/{clientId}/revoke` |
| `GET` | `/api/v1/admin/mcp/audit-logs` |

Register a server with an environment-variable reference, never a credential
value:

```json
{
  "namespace": "search",
  "name": "Corporate search",
  "description": "Approved search tools",
  "endpoint": "https://mcp.search.corp.example/mcp",
  "secretRef": "MCP_SEARCH_UPSTREAM_TOKEN",
  "assignments": ["org:engineering"],
  "status": "active",
  "toolPolicies": [
    { "tool": "lookup", "access": "allow", "risk": "low", "visible": true },
    { "tool": "delete_record", "access": "deny", "risk": "critical", "visible": false }
  ],
  "operationId": "op-mcp-search-001",
  "reason": "Register the approved engineering search MCP"
}
```

Issue a scoped client credential only for an already authenticated subject.
The token is returned once:

```json
{
  "name": "alice-laptop",
  "subjectId": "oidc-subject-alice",
  "orgIds": ["engineering"],
  "deviceIds": ["device-alice-laptop"],
  "serverScopes": ["srv_0123456789abcdef"],
  "ttlDays": 30,
  "operationId": "op-mcp-client-alice-001",
  "reason": "Provision Alice's managed MCP client"
}
```

## Client endpoint

Configure the local Magpie/agent with:

```text
URL:    https://mcp.ai.corp.example/mcp/enterprise
Header: Authorization: Bearer <scoped client credential>
```

The upstream endpoint and credential are never returned to the client. The
client only sees assigned servers and visible, allowed tools.

## Environment

| Variable | Required | Default / behavior |
| --- | --- | --- |
| `MCP_SERVICE_TOKEN` | yes | At least 32 characters; admin bearer token |
| `MCP_APPROVAL_HMAC_SECRET` | no | If empty, high/critical calls fail closed |
| `MCP_BIND` / `MCP_PORT` | no | `0.0.0.0` / `3448` |
| `MCP_PUBLIC_URL` | no | Informational public service URL |
| `MCP_STORE_PATH` | no | `./data/mcp-registry.json` |
| `MCP_AUDIT_PATH` | no | `./data/mcp-audit.jsonl` |
| `MCP_UPSTREAM_ALLOWED_HOSTS` | yes for registration | Comma-separated exact or `*.` hosts; empty denies all |
| `MCP_ALLOWED_ORIGINS` | no | Comma-separated browser origins; absent origins are allowed |
| `MCP_ALLOW_HTTP_UPSTREAMS` | no | `false`; HTTP requires an explicit lab override |
| `MCP_ALLOW_PRIVATE_UPSTREAMS` | no | `false`; private targets require an explicit override |
| `MCP_UPSTREAM_CA_PATH` | no | PEM CA bundle for internal TLS servers |
| `MCP_UPSTREAM_TIMEOUT_MS` | no | `10000` |
| `MCP_UPSTREAM_MAX_RESPONSE_BYTES` | no | `1048576` |
| `MCP_MAX_BODY_BYTES` | no | `262144` |
| `MCP_RATE_LIMIT_PER_MINUTE` | no | `600` |
| `MCP_AUTH_RATE_LIMIT_PER_MINUTE` | no | `60` |
| `MCP_CATALOG_TTL_MS` | no | `60000` |
| `MCP_HEALTH_INTERVAL_MS` | no | `30000` |
| `MCP_HEALTH_TIMEOUT_MS` | no | `5000` |
| `MCP_BREAKER_FAILURE_THRESHOLD` | no | `3` |
| `MCP_BREAKER_COOLDOWN_MS` | no | `30000` |
| `MCP_CLIENT_TOKEN_TTL_DAYS` | no | `30` |
| `MCP_APPROVAL_MAX_TTL_SECONDS` | no | `900` |

Additional integer bounds are enforced by `src/config.js`.

## Failure and audit semantics

The registry and audit log are separate files. A write is committed to the
registry before its result audit entry is appended. If the audit append fails,
the API returns an error even though the registry mutation may already be
durable.

- Server create/update: inspect the registry before retrying; the same create
  can report a namespace conflict because the first write committed.
- Client issuance: a failed audit append can consume an issued client record
  without delivering its one-time token because plaintext token material is
  never stored. Treat the client id as orphaned, revoke it, and issue a new
  client. Do not assume the same idempotency key can recover the token.
- Revocation: inspect current state before retrying.

This is an M3-B limitation. Production needs one transactional/shared store for
registry, audit and idempotency, or a durable audit intent/compensation state
machine. Audit storage must also be append-only/immutable and independently
monitored.

## Security boundaries

This service is not a complete MCP security boundary by itself:

- Terminate TLS at a trusted internal reverse proxy and restrict the listener
  to the management/client network.
- Inject upstream credentials from a secret manager. Never put them in the
  registry, Compose file, API payload, audit log or source control.
- Keep the service token and approval HMAC key in different secret scopes from
  caller credentials, admin sessions and OIDC secrets.
- Run one replica until replay nonces, rate limits, registry, audit and
  idempotency move to a shared transactional store.
- Treat tool arguments and results as untrusted. M3-B does not provide
  content inspection, prompt-injection defense, data-loss prevention or
  conversation audit.
- Review every upstream server and tool policy. `tools/list` filtering is not
  a substitute for network egress control.

See [DESIGN.md](DESIGN.md) for the frozen boundary and tests.
