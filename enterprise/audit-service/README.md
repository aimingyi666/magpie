# Magpie 企业审计事件管道（M4-A）

`audit-service` 是 M4-A 的独立审计事件管道核心。它接收、校验、排队并持久化
L0/L1 元数据事件，按请求和会话建立索引，并提供受服务令牌保护的查询接口。

这个切片**不是完整的 M4**，也不是生产可用的内容审计系统。当前没有接入真实网关、
管理台或员工页面，没有 L2/L3 正文采集、检索、留存、删除证明或管理员 OIDC/RBAC。

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

未实现：

- 真实 Magpie 网关、admin-service、管理台和员工页面的审计流接入；
- 管理员 OIDC、RBAC、组织范围、管理员会话、访问审计和导出审批；
- L2/L3 正文、流式拼接、正文脱敏、对象存储、正文索引和查看授权；
- 留存策略、法律保留、删除证明、WORM 和备份恢复演练；
- PostgreSQL/ClickHouse、多副本、HA、负载测试和生产容量验证；
- Compose 实机构建、真实共享卷、真实 IdP、浏览器 E2E 和生产验收。

## 启动

需要 Node.js 22 或更高版本。

```powershell
$env:AUDIT_SERVICE_TOKEN = "replace-with-an-independent-32-character-token"
$env:AUDIT_BIND = "127.0.0.1"
$env:AUDIT_PORT = "3449"
$env:AUDIT_STORE_PATH = ".\data\audit-store.json"
node src/server.js
```

也可以从仓库根目录使用 Compose 的 `audit` profile：

```powershell
docker compose --profile audit up -d audit
```

该服务默认只在 Compose 内部网络暴露 `3449`，不发布宿主机端口。`AUDIT_SERVICE_TOKEN`
必须与网关控制、auth、admin、resource、MCP 和其他服务令牌不同。当前 ingest 和管理查询
共用这一个 Bearer 服务令牌；这不是生产管理员授权模型，必须在 M4-C 前替换。

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
```

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

测试使用临时目录、端口 `0`、Mock fetch 和隔离存储，不读取真实 `usage.jsonl`、
管理员会话或生产数据。
