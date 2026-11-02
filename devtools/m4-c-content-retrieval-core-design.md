# M4-C 内容检索与一次性正文授权核心设计

本文冻结 M4-C 核心的边界、契约和验收条件。它不表示 M4-D 的留存删除、法律保留、
WORM、导出，也不表示真实网关、管理台、管理员 OIDC/RBAC 或生产验收已经完成。

## 1. 目标

M4-C 在 M4-A 元数据管道和 M4-B L2 脱敏正文对象之上提供：

1. 受管理令牌保护的内容流元数据检索，不返回正文。
2. 按员工、部门、时间、模型、工具、内容类型和状态筛选。
3. 防篡改、绑定筛选条件的分页 cursor。
4. 短期、一次性、绑定管理员/组织/目标/理由/审批/会话的正文读取 grant。
5. 成功和失败读取的持久访问审计；审计写入失败时不返回正文。

## 2. 身份与默认关闭

两套身份严格隔离：

- ingest：`Authorization: Bearer <AUDIT_SERVICE_TOKEN>`，只能创建内容流和提交分片。
- 内容管理：`Authorization: Bearer <AUDIT_CONTENT_ADMIN_TOKEN>`，只能查询元数据、
  创建 grant 和凭 grant 读取正文。

内容管理默认关闭。`AUDIT_CONTENT_ADMIN_ENABLED=false` 时所有内容管理路由返回
`503 content_admin_disabled`。启用时要求：

```text
AUDIT_CONTENT_ENABLED=true
AUDIT_CONTENT_ADMIN_ENABLED=true
AUDIT_CONTENT_ADMIN_TOKEN=<>=32 chars>
AUDIT_CONTENT_ORGANIZATION_ID=<trusted organization id>
AUDIT_CONTENT_GRANT_SECRET=<>=32 chars>
AUDIT_CONTENT_CURSOR_SECRET=<>=32 chars>
AUDIT_CONTENT_GRANT_TTL_SECONDS=120
```

上述秘密彼此不得复用，也不得与 `AUDIT_SERVICE_TOKEN` 或任何其他服务令牌复用。
旧 `AUDIT_CONTENT_READ_TOKEN` 已退役，不能再作为正文读取旁路。

管理请求还必须携带由受信任管理网关写入并验证过的上下文：

```text
X-Audit-Admin-Id: <admin id>
X-Audit-Organization-Id: <organization id, must equal configured scope>
X-Audit-Admin-Session: <opaque session identifier>
```

这些头不能来自终端员工或浏览器查询参数。生产集成必须由 admin-service 的 OIDC、
RBAC、step-up 和组织范围校验后转发；本轮只实现并验证核心边界。

## 3. 元数据检索

```text
GET /api/v1/admin/audit/content/streams
```

允许筛选：

```text
userId, departmentId, deviceId, agentId, modelId, mcpServerId,
toolName, contentKind, status, from, to, limit, cursor
```

- `limit` 默认 50，最小 1，最大 200。
- 时间筛选针对内容流 `createdAt`，边界为闭区间。
- 工具筛选只匹配内容流自身的 `toolName`。缺失时不命中，不从 M4-A 事件跨请求推断。
- 组织范围不接受查询参数自报，只来自管理令牌验证后的可信头和配置边界。
- 排序固定为 `createdAt DESC, streamId DESC`。
- 响应只使用 `publicContentStream()`，绝不包含正文、加密对象路径或密钥。

响应：

```json
{
  "schemaVersion": 1,
  "ok": true,
  "streams": [],
  "nextCursor": null
}
```

## 4. 签名 cursor

cursor 为：

```text
base64url(canonical-payload).HMAC-SHA256(cursor-secret, base64url-payload)
```

payload 绑定：

- cursor 版本；
- 全部有效筛选条件；
- 固定排序版本；
- 最后一条的 `createdAt` 和 `streamId`。

以下情况失败关闭为 `400 invalid_cursor`：

- 格式错误、签名错误或字段未知；
- 筛选条件与签发时不同；
- 排序版本不同；
- 分页位置字段不合法。

不允许使用可伪造的裸 base64 JSON。

## 5. 一次性正文 grant

创建：

```text
POST /api/v1/admin/audit/content/{contentRef}/grants
Content-Type: application/json

{
  "purpose": "security_investigation",
  "reason": "security case 42",
  "approvalId": "apr_...",
  "ttlSeconds": 120
}
```

创建前必须确认目标对象存在。grant 由 HMAC-SHA256 签名并绑定：

- `contentRef`；
- 管理员 `adminId`；
- 组织 `organizationId`；
- `purpose`、`reason`、`approvalId`；
- 管理员会话摘要；
- 签发时间和过期时间。

TTL 默认 120 秒，允许 15-300 秒。服务端配置决定硬上限，请求不能放大。

读取：

```text
GET /api/v1/admin/audit/content/{contentRef}
X-Audit-Content-Grant: <one-time grant>
```

读取还必须带同一管理员、组织和会话头。grant 目标、身份、组织、会话任一不符均失败，
错误为 `401/403`。过期失败，已消费失败为 `409 content_grant_reused`。

一次性消费账本持久化在内容存储目录的独立文件
`content-grants.json` 中，使用临时文件、`fsync` 和原子 rename。成功写入消费记录后才
读取正文，因此进程重启后不能重放。该核心是单进程/共享单写卷语义，不宣称多副本分布式锁。

## 6. 访问审计

每次已通过 grant 校验的正文读取，无论对象存在、完整性、解密或成功结果如何，都必须
写入访问审计。记录包括：

```text
accessId, accessedAt, reason, authorizationId, approvalId,
grantId, adminId, organizationId, purpose, requestId,
sourceHash, outcome, errorCode
```

`authorizationId` 保留为 `approvalId` 的兼容访问证据。旧 M4-B 访问记录仍可加载。

消费账本或访问审计持久化失败时，响应为 `503`，不得返回正文。未通过 grant 的请求不
产生正文访问记录；生产应在上层管理网关记录认证失败安全事件。

## 7. 明确不做

- M4-D 留存删除、删除证明、法律保留、WORM、加密导出；
- 真实 admin-service OIDC/RBAC/step-up 编排、管理 UI 和浏览器 E2E；
- 真实 Magpie 网关正文采集；
- PostgreSQL/ClickHouse、多副本分布式一次性和 HA；
- Docker/Compose 实机、真实 IdP/MFA、负载、备份恢复和生产验收。

## 8. 验收

必须通过：

- 所有筛选维度、稳定排序、分页和空结果；
- cursor 篡改、筛选变化、排序版本变化拒绝；
- ingest 令牌不能查询元数据或读正文，管理令牌不能 ingest；
- 组织范围、管理员、会话、目标任一不符拒绝；
- grant 过期、重放、重启后重放拒绝；
- 列表响应永不含正文；
- 缺失对象、完整性失败和成功读取均写访问审计；
- 审计持久化失败不返回正文；
- 旧 M4-B 索引/访问记录可加载；
- 秘密不进入响应、日志或持久文件。
