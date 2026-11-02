# M3-B remote MCP gateway: frozen boundary

Status: M3-B core implemented and covered by 14 unit/Mock integration tests.
M3-C/M3-D and production acceptance remain unimplemented. This document
defines the frozen M3-B contract; the README records operating instructions and
the concrete failure boundaries.

## 1. Scope

M3-B adds one internal enterprise service with two surfaces:

| Surface | Caller | Trust boundary |
| --- | --- | --- |
| Admin registry API | Trusted control-plane services | Bearer service token plus an audit actor header |
| Employee/agent MCP endpoint | Local Magpie or a managed agent | Scoped opaque client credential |

The service owns:

- the remote MCP registry: owner, namespace, endpoint, assignments, tool policy,
  active/disabled state and health projection;
- the stable enterprise MCP endpoint `/mcp/enterprise`;
- server-side upstream credentials resolved only from environment secret
  references;
- tool-level allow/deny, risk classification, visibility filtering and
  server-side call enforcement;
- health checks, request timeouts, body/response limits, rate limits,
  per-server circuit breakers and failure isolation;
- metadata-only audit records.

It does not own local MCP packages, client-side installation, resource
distribution, conversation content, approval workflow storage or the admin UI.
Those remain M3-C/M3-D, M2-E and M4 work.

## 2. Data boundary

Registry records contain no credential values. A remote server stores only an
environment variable name such as `MCP_UPSTREAM_SEARCH_TOKEN`. The process
resolves that value at request time and sends it only to the upstream MCP
server. Client-facing responses never include upstream headers, endpoint
credentials or the secret reference value.

Client records store a SHA-256 token digest, never the bearer value. The token is
returned once when the credential is issued. Records carry subject, organization
and device identifiers so registry assignments can be evaluated server-side.

Assignments use explicit selectors:

```text
*
user:<subjectId>
org:<orgUnitId>
device:<deviceId>
```

A client sees a server only when its subject, organization set or device set
matches an active server assignment. Hidden servers and tools are absent from
`tools/list` and `tools/call` treats them as unknown.

## 3. Admin contract

All admin routes use `/api/v1/admin/mcp/` and require:

```http
Authorization: Bearer <MCP_SERVICE_TOKEN>
X-Magpie-Actor: <control-plane service identity>
```

Writes also require `Idempotency-Key`, `operationId` and `reason`. Server
updates require `expectedUpdatedAt`.

Routes:

| Method | Path | Behavior |
| --- | --- | --- |
| `POST` | `/servers` | Register a remote MCP server |
| `GET` | `/servers` | List registry records with health |
| `GET` | `/servers/{id}` | Read one record |
| `PUT` | `/servers/{id}` | Replace policy/assignment fields with optimistic concurrency |
| `POST` | `/servers/{id}/check` | Run an isolated health check |
| `POST` | `/clients` | Issue a scoped opaque client credential once |
| `GET` | `/clients` | List client records without token material |
| `POST` | `/clients/{id}/revoke` | Revoke a client credential |
| `GET` | `/audit-logs` | Read metadata-only audit records |

## 4. MCP data-plane contract

The data plane is Streamable HTTP JSON-RPC at:

```text
POST /mcp/enterprise
Authorization: Bearer <scoped client credential>
Content-Type: application/json
```

Supported methods:

- `initialize`
- `notifications/initialized`
- `ping`
- `tools/list`
- `tools/call`
- `notifications/cancelled`

The gateway is tools-only. It rejects resources, prompts, batching and unknown
methods. Tools are namespaced as `<server-namespace>__<upstream-tool>`.

High/critical tools require a short-lived HMAC approval token in
`X-Magpie-Approval-Token`. The signed payload binds approval id, client id,
server id, upstream tool name, issue time, expiry and nonce. When no approval
key is configured, high/critical calls fail closed. Approval nonce replay
protection is in memory in M3-B; a durable shared store is required before
multi-replica production use.

## 5. Network and SSRF contract

Only `https:` upstream URLs are accepted by default. HTTP is an explicit test
configuration. URLs must have no username, password, fragment or unsafe header.

Every outbound request:

1. matches an exact or `*.` host allowlist entry;
2. resolves DNS for the current request;
3. fails if any resolved address is loopback, private, link-local, multicast,
   documentation-only, unspecified or cloud metadata space;
4. pins the validated address into the connection lookup;
5. refuses redirects rather than following them;
6. enforces timeout and response-size limits.

TLS verification stays enabled. A private CA file may be configured globally.

## 6. Failure model

Each server has independent health, catalog cache and circuit-breaker state. A
failing server cannot hide healthy servers from `tools/list`, and an open
circuit rejects only that server's calls.

Registry load fails closed on malformed JSON, unknown fields, invalid state,
plaintext token fields, invalid assignments or a client record without a token
digest. Audit load fails closed on a malformed line.

Registry mutation and audit append are separate durable writes. A result audit
failure can therefore return an error after a server/client mutation has
already committed. For client issuance, plaintext token material is never
stored, so that failure can leave an orphaned client record whose token cannot
be recovered. Operators must inspect the current state, revoke an orphaned
client and issue a replacement. Production requires a shared transactional
store for registry, audit and idempotency, or a durable audit-intent and
compensation state machine. This is a production blocker, not a retryable
client-issue guarantee.

## 7. Acceptance tests

The implementation is accepted as an M3-B core only when tests prove:

- employee/MCP/tool authorization is enforced server-side;
- unauthorized MCPs and tools are invisible and uncallable;
- allow/deny and risk policy cannot be bypassed by naming a hidden tool;
- upstream credentials never appear in client/admin projections or audit;
- private, loopback, link-local, metadata and unsafe redirect targets are
  rejected;
- health timeout, unhealthy server and open circuit isolate one server;
- request body, upstream response, timeout and rate-limit boundaries hold;
- malformed registry/audit state fails closed;
- high-risk approval binding, expiry and replay protection fail closed;
- a healthy server remains callable when a different server fails.

## 8. File ownership

```text
enterprise/mcp-gateway/**
enterprise/docker-compose.yml          M3-B profile only
enterprise/.env.example                M3-B settings only
enterprise/README.md                   M3-B status section only
devtools/enterprise-*                  M3-B evidence/status rows only
```

M3-B does not edit the upstream gateway router or client synchronization files.
