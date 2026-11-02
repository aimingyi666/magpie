# Magpie 企业审计事件与内容管道（M4-A + M4-B + M4-C 核心）

`audit-service` 当前包含三个核心：

- M4-A：接收、校验、排队并持久化 L0/L1 元数据事件，按请求和会话建立索引，并提供受
  服务令牌保护的查询接口。
- M4-B：默认关闭的 L2 脱敏正文分片管道，包含跨分片统一脱敏和 AES-256-GCM 加密对象存储。
- M4-C：受管理令牌保护的正文流元数据检索、HMAC 签名 cursor、一次性正文读取 grant、
  管理员/组织/会话绑定和持久访问审计。

这个切片**不是完整的 M4**，也不是生产可用的内容审计系统。当前没有接入真实网关、
管理台或员工页面；没有 L3、附件、二进制正文、留存/删除证明、法律保留或 WORM。
M4-C 本轮只实现后端的组织配置边界、管理员会话头和一次性授权；仍未接入
admin-service 的管理员 OIDC/RBAC/step-up、管理台 UI、浏览器 E2E 或生产验收。

## 当前边界

已实现：

- schema v1 的 `request`、`response`、`tool_call`、`policy_decision` 事件；
- L0 请求/响应元数据和 L1 工具调用/策略决策元数据；
- 强制 `eventId`、`requestId`、`sessionId`，会话和请求可串联；
- 严格字段 allowlist，不接收 Prompt、回复、附件、正文或未知字段；
- 私钥、云访问密钥、常见厂商 token、Bearer token 和 JWT 的秘密扫描；
- 规范毫秒 UTC 时间戳、Bearer 服务令牌和 `Idempotency-Key`；
- 持久 JSON 队列、批量提交、重启恢复、幂等重放和冲突检测；
- 会话索引、游标分页、筛选、统计、队列深度和健康状态；
- 原子写入、串行变更、优雅 drain 和客户端有界重试。
- M4-B 默认关闭，只接受 `text/plain` 的 L2 正文，拒绝 L3、附件和二进制；
- 最多 1 MiB 正文的分片提交、顺序/累计字节校验、幂等重放、乱序/冲突/容量/TTL 拒绝；
- 全部分片拼接完成后统一脱敏，覆盖私钥、密码赋值、Bearer/JWT、云/厂商 token、
  URL 凭据、邮箱、手机号、身份证和通过 Luhn 校验的银行卡；
- AES-256-GCM 加密正文对象，对象与索引分目录存储；
- 受管理令牌保护的正文流元数据检索，支持员工、部门、设备、Agent、模型、MCP、工具、
  内容类型、状态和时间筛选；
- HMAC 签名 cursor 绑定筛选条件和排序版本，拒绝篡改、筛选变化和排序版本变化；
- 正文读取必须使用一次性 `X-Audit-Content-Grant`；grant 绑定管理员、组织、会话、目标、
  用途、理由、审批 ID 和 TTL，消费账本持久化且重启后不可重放；
- 成功、缺失、篡改和失败读取均尝试写入访问审计；访问审计持久化失败时返回 `503`，
  不返回正文；
- 未完成流在重启时标记中断，已完成对象可恢复读取。

未实现：

- 真实 Magpie 网关、admin-service、管理台和员工页面的审计流接入；
- admin-service 的管理员 OIDC、RBAC、step-up、管理员会话编排和导出审批；
- L3、附件/二进制正文、管理台 UI 和真实网关正文采集；
- 正文留存、删除、删除证明、法律保留、WORM、加密导出和备份恢复演练；
- PostgreSQL/ClickHouse、多副本、HA、负载测试和生产容量验证；
- Compose 实机构建、真实共享卷、真实 IdP、浏览器 E2E 和生产验收。

## 启动

需要 Node.js 22 或更高版本。

```powershell
$env:AUDIT_SERVICE_TOKEN = "replace-with-a-separate-long-random-audit-service-token"
$env:AUDIT_BIND = "127.0.0.1"
$env:AUDIT_PORT = "3449"
$env:AUDIT_STORE_PATH = ".\data\audit-store.json"
$env:AUDIT_CONTENT_ENABLED = "false"
$env:AUDIT_CONTENT_ADMIN_ENABLED = "false"
node src/server.js
```

也可以从仓库根目录使用 Compose 的 `audit` profile：

```powershell
docker compose --profile audit up -d audit
```

该服务默认只在 Compose 内部网络暴露 `3449`，不发布宿主机端口。`AUDIT_SERVICE_TOKEN`
必须与网关控制、auth、admin、resource、MCP 和其他服务令牌不同。M4-A 事件查询仍使用
服务令牌；M4-C 内容管理在启用后使用独立 `AUDIT_CONTENT_ADMIN_TOKEN`，ingest 和管理
令牌严格隔离。两者都不能替代 admin-service 的生产 OIDC/RBAC 授权。

M4-B 默认关闭。启用时必须另设 32 字节 `AUDIT_CONTENT_ENCRYPTION_KEY`（base64 或 64 位
hex）。M4-C 内容管理也默认关闭；启用时还必须另设相互独立的
`AUDIT_CONTENT_ADMIN_TOKEN`、`AUDIT_CONTENT_GRANT_SECRET`、
`AUDIT_CONTENT_CURSOR_SECRET` 和可信的 `AUDIT_CONTENT_ORGANIZATION_ID`。
旧 `AUDIT_CONTENT_READ_TOKEN` 已退役；设置它会导致服务启动失败，不能作为正文读取旁路。
所有秘密都不得与 `AUDIT_SERVICE_TOKEN` 或其他服务令牌复用。

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `AUDIT_BIND` | `0.0.0.0` | 监听地址 |
| `AUDIT_PORT` | `3449` | 监听端口，范围 1-65535 |
| `AUDIT_SERVICE_TOKEN` | 必填 | 32-512 个可打印字符的 Bearer 服务令牌 |
| `AUDIT_STORE_PATH` | `./data/audit-store.json` | 持久 JSON 文件 |
| `AUDIT_MAX_BODY_BYTES` | `32768` | 单事件请求体上限，最大 128 KiB |
| `AUDIT_MAX_EVENTS` | `1000000` | 已提交事件上限 |
| `AUDIT_MAX_QUEUE_EVENTS` | `100000` | 待提交队列上限 |
| `AUDIT_MAX_SESSIONS` | `100000` | 会话索引上限 |
| `AUDIT_FLUSH_INTERVAL_MS` | `1000` | 后台 drain 间隔 |
| `AUDIT_BATCH_SIZE` | `200` | 每次提交的最大事件数 |
| `AUDIT_RATE_LIMIT_PER_MINUTE` | `6000` | 单来源每分钟请求上限 |
| `AUDIT_CONTENT_ENABLED` | `false` | 是否启用 M4-B 内容审计核心 |
| `AUDIT_CONTENT_ENCRYPTION_KEY` | 启用时必填 | AES-256-GCM 密钥，32 字节 base64 或 64 位 hex |
| `AUDIT_CONTENT_ADMIN_ENABLED` | `false` | 是否启用 M4-C 内容元数据检索和 one-time grant |
| `AUDIT_CONTENT_ADMIN_TOKEN` | 启用时必填 | 内容管理 Bearer 令牌，必须独立于 ingest |
| `AUDIT_CONTENT_ORGANIZATION_ID` | 启用时必填 | 内容管理请求允许的可信组织范围 |
| `AUDIT_CONTENT_GRANT_SECRET` | 启用时必填 | 一次性 grant 的 HMAC 密钥 |
| `AUDIT_CONTENT_CURSOR_SECRET` | 启用时必填 | 内容检索 cursor 的 HMAC 密钥 |
| `AUDIT_CONTENT_GRANT_TTL_SECONDS` | `120` | grant 默认 TTL，允许 15-300 秒 |
| `AUDIT_CONTENT_STORE_DIR` | `./data/audit-content` | 正文对象和索引目录 |
| `AUDIT_CONTENT_MAX_BODY_BYTES` | `393216` | 内容 API 单请求上限，最大 64 MiB |
| `AUDIT_CONTENT_MAX_CHUNK_BYTES` | `262144` | 单分片上限，最大 4 MiB 且不得超过流上限 |
| `AUDIT_CONTENT_MAX_STREAM_BYTES` | `1048576` | 单正文流上限，最大 32 MiB |
| `AUDIT_CONTENT_MAX_BUFFER_BYTES` | `67108864` | 所有活动流的总缓冲上限 |
| `AUDIT_CONTENT_MAX_ACTIVE_STREAMS` | `256` | 同时活动的正文流上限 |
| `AUDIT_CONTENT_STREAM_TTL_MS` | `900000` | 未完成流 TTL，范围 10 秒到 24 小时 |

队列或索引达到配置上限时，服务返回稳定错误，不会静默丢弃事件。

## API

除 `/healthz` 外，所有路由都要求：

```text
Authorization: Bearer <AUDIT_SERVICE_TOKEN>
```

```text
GET  /healthz
POST /api/v1/internal/audit/events
GET  /api/v1/admin/audit/events
GET  /api/v1/admin/audit/sessions
GET  /api/v1/admin/audit/sessions/{sessionId}
GET  /api/v1/admin/audit/stats
POST /api/v1/internal/audit/content/streams
POST /api/v1/internal/audit/content/streams/{streamId}/chunks
GET  /api/v1/admin/audit/content/streams
POST /api/v1/admin/audit/content/{contentRef}/grants
GET  /api/v1/admin/audit/content/{contentRef}
```

内容管理路由在启用后要求：

```text
Authorization: Bearer <AUDIT_CONTENT_ADMIN_TOKEN>
X-Audit-Admin-Id: <受信任管理网关注入的管理员 ID>
X-Audit-Organization-Id: <必须等于 AUDIT_CONTENT_ORGANIZATION_ID>
X-Audit-Admin-Session: <不透明管理员会话标识>
```

这些头不能来自员工终端或浏览器查询参数；生产集成必须由 admin-service 完成 OIDC、RBAC、
step-up 和组织范围校验后转发。

创建正文 grant 的请求体：

```json
{
  "purpose": "security_investigation",
  "reason": "security case 42",
  "approvalId": "apr_...",
  "ttlSeconds": 120
}
```

读取正文时额外要求同一管理员、组织和会话头，以及一次性 grant：

```text
X-Audit-Content-Grant: <one-time grant>
```

grant 过期、身份或目标不匹配、已消费或重启后重放均失败关闭。成功、缺失、篡改和失败的
正文读取都会尝试写入访问审计。响应带
`X-Audit-Watermark: MAGPIE-AUDIT-CONTENT ...`，`cache-control: no-store`。
内容流 ID 和内容引用是随机的，不含员工、时间或组织信息。

事件写入还要求 `Content-Type: application/json` 和 1-128 个可打印 ASCII 字符的
`Idempotency-Key`。新事件返回 `202`；同键同体重放返回 `200` 且
`duplicate: true`；同键异体返回 `409 idempotency_conflict`；同一 `eventId` 对应不同
内容返回 `409 event_id_conflict`。

事件查询支持 `requestId`、`sessionId`、`userId`、`departmentId`、`deviceId`、
`modelId`、`toolName`、`status`、`from`、`to`、`limit` 和 `cursor`。

## 事件 schema

必填字段：

```json
{
  "schemaVersion": 1,
  "eventId": "evt_01J00000000000000000000000",
  "requestId": "req_01J00000000000000000000000",
  "sessionId": "ses_01J00000000000000000000000",
  "eventKind": "request",
  "auditLevel": "L0",
  "occurredAt": "2026-11-01T08:00:00.000Z",
  "userId": "usr_123",
  "departmentId": "org_engineering",
  "deviceId": "dev_456",
  "agentId": "codex",
  "clientVersion": "1.0.0",
  "requestKind": "chat",
  "status": "started"
}
```

可选字段：

```text
modelId, providerId, mcpServerId, toolName, parameterCategories,
errorCode, inputTokens, outputTokens, cost, latencyMs, sourceIpHash,
policyHits
```

- `eventKind`：`request`、`response`、`tool_call`、`policy_decision`
- `auditLevel`：`L0`、`L1`
- `requestKind`：`chat`、`responses`、`messages`、`mcp`
- `status`：`started`、`success`、`blocked`、`error`
- `response` 不能是 `started`；`tool_call` 和 `policy_decision` 必须是终止状态
- `tool_call` 必须是 L1 MCP 事件，并带 `toolName` 和 `parameterCategories`
- `policy_decision` 必须至少带一个 `policyHits`
- L0 事件不能包含 `toolName` 或 `parameterCategories`

L1 工具调用示例：

```json
{
  "schemaVersion": 1,
  "eventId": "evt_01J00000000000000000000001",
  "requestId": "req_01J00000000000000000000000",
  "sessionId": "ses_01J00000000000000000000000",
  "eventKind": "tool_call",
  "auditLevel": "L1",
  "occurredAt": "2026-11-01T08:00:01.000Z",
  "userId": "usr_123",
  "departmentId": "org_engineering",
  "deviceId": "dev_456",
  "agentId": "codex",
  "clientVersion": "1.0.0",
  "requestKind": "mcp",
  "status": "success",
  "mcpServerId": "mcp_search",
  "toolName": "search.read",
  "parameterCategories": ["query"],
  "policyHits": ["tool.allowed"],
  "latencyMs": 120
}
```

这两个示例只描述契约，不代表真实网关已经发送这些事件。

## 内容审计 schema

内容流只接受 L2 `text/plain`，不接收 L3、附件、二进制、未知字段或超出上限的正文。
所有分片必须按连续序号提交，并受累计字节上限约束；同一幂等键同体重放，异体返回冲突。最后一片完成后，服务先
拼接完整正文，再统一脱敏，避免跨分片秘密漏检。加密对象写入后，索引只保留摘要、脱敏
统计和访问证据，不保留明文正文。

内容元数据检索支持：

```text
userId, departmentId, deviceId, agentId, modelId, mcpServerId,
toolName, contentKind, status, from, to, limit, cursor
```

排序固定为 `createdAt DESC, streamId DESC`；cursor 绑定全部筛选条件和排序版本。
列表响应永不包含正文、加密对象路径或密钥。

## 队列、恢复和健康

写入先原子进入队列，后台按 `AUDIT_BATCH_SIZE` 提交到已提交索引。进程收到
`SIGTERM`/`SIGINT` 时先停止接受新工作，再 drain 队列；重启加载时会校验事件、队列、
幂等索引和会话索引的一致性。

`GET /healthz` 无需令牌：

- `ready`：队列为空且没有连续提交失败；
- `degraded`：仍有排队事件或最近提交失败。

`GET /api/v1/admin/audit/stats` 返回队列深度、最早排队时间、已提交数量、会话数量、
累计统计和最近失败摘要。当前没有 Prometheus/OTel 指标导出，也没有积压告警。

## 测试

```powershell
node --test test/*.test.mjs
```

当前专项测试为 **47 passed, 0 failed**，覆盖 M4-A 事件管道、M4-B 内容分片/加密/脱敏，
以及 M4-C 检索、签名 cursor、一次性 grant、并发消费和访问审计失败关闭。测试使用临时
目录、端口 `0`、Mock fetch 和隔离存储，不读取真实 `usage.jsonl`、管理员会话或生产数据。
