# M4-D 留存、法律保留、删除证明与加密导出核心设计

本文冻结 M4-D 后端核心的边界、契约和验收条件。它不表示 M4 已完成，也不表示企业生产
可用；真实网关正文采集、admin-service 管理员 OIDC/RBAC/step-up 编排、管理台 UI、
浏览器 E2E、WORM、KMS/HSM、对象存储版本控制、PostgreSQL/ClickHouse、HA、多副本一致性、
Docker/Compose 实机、真实 IdP/MFA、备份恢复和生产验收仍不在本切片内。

## 1. 目标

M4-D 在 M4-A 元数据管道、M4-B L2 加密正文对象和 M4-C 检索/一次性读取授权之上提供：

1. 正文与元数据分别配置留存期，并记录明确的到期时间。
2. 到期正文的自动或显式清扫；清扫不删除不可逆删除证明。
3. 带审批、理由、范围、责任人和到期时间的法律保留。
4. 法律保留优先于普通留存删除和元数据脱敏。
5. 原子删除索引引用、正文对象和删除证明，支持重启后的失败关闭与清理恢复。
6. 独立于普通访问审计上限的删除证明查询和 HMAC 完整性验证。
7. 加密导出、一次性下载凭证、首次消费、短期过期、水印和稳定导出审计编号。

## 2. 身份、权限和默认关闭

沿用 M4-C 的 ingest 与内容管理令牌隔离，并新增治理权限：

- ingest：`AUDIT_SERVICE_TOKEN`。
- 普通内容管理：`AUDIT_CONTENT_ADMIN_TOKEN`，可检索元数据、创建读取 grant、读取正文。
- 治理管理：`AUDIT_CONTENT_GOVERNANCE_TOKEN`，仅用于留存清扫、法律保留、删除证明和导出。
- 普通管理令牌不能执行治理操作，治理令牌也不能检索或读取普通正文。

治理默认关闭。启用时要求：

```text
AUDIT_CONTENT_ENABLED=true
AUDIT_CONTENT_ADMIN_ENABLED=true
AUDIT_CONTENT_GOVERNANCE_ENABLED=true
AUDIT_CONTENT_ORGANIZATION_ID=<trusted organization id>
AUDIT_CONTENT_ADMIN_TOKEN=<>=32 chars>
AUDIT_CONTENT_GOVERNANCE_TOKEN=<>=32 chars>
AUDIT_CONTENT_GRANT_SECRET=<>=32 chars>
AUDIT_CONTENT_CURSOR_SECRET=<>=32 chars>
AUDIT_CONTENT_PROOF_SECRET=<>=32 chars>
```

加密导出另需：

```text
AUDIT_CONTENT_EXPORT_ENABLED=true
AUDIT_CONTENT_EXPORT_SECRET=<>=32 chars>
AUDIT_CONTENT_EXPORT_KEY=<exactly 32 bytes, base64 or 64 hex chars>
AUDIT_CONTENT_EXPORT_TTL_SECONDS=120
```

所有秘密必须互不相同，也不得与任何其他服务令牌复用。治理请求仍必须携带 M4-C 的管理员
上下文：

```text
X-Audit-Admin-Id
X-Audit-Organization-Id
X-Audit-Admin-Session
```

这些头只能由受信任管理网关写入。M4-D 核心验证这些边界，但不代替 admin-service 的
OIDC、RBAC、MFA/step-up 和审批编排。

## 3. 留存语义

内容流请求的 `collection.retentionDays` 保持向后兼容，表示正文留存天数。新增可选的
`collection.metadataRetentionDays`，表示元数据留存天数：

- 取值范围均为 1-3650 天；
- `metadataRetentionDays` 省略时等于 `retentionDays`；
- `metadataRetentionDays` 不得小于 `retentionDays`；
- 到期时间从对象最终提交时间 `finalizedAt` 起计算；
- 元数据到期不早于正文到期，避免出现正文仍在但检索关系已丢失。

到期比较使用规范 UTC 毫秒时间，边界为 `now >= expiresAt`。

### 3.1 正文清扫

正文到期且没有活动法律保留时：

1. 从可读对象索引移除该对象；
2. 状态改为 `deleted`，记录 `deletedAt` 和 `deletionId`；
3. 保留不可逆摘要 `plaintextSha256`、字节数、内容引用和删除证明；
4. 删除加密对象文件；
5. 后续 grant 创建、正文读取和导出都不再看到该正文。

正文删除后，元数据仍按 `metadataRetentionExpiresAt` 保留，直到被脱敏。

### 3.2 元数据脱敏

元数据到期且没有活动法律保留时，清除员工、部门、设备、Agent、模型、MCP、工具、请求/
会话关联和采集授权 ID，只保留无法还原正文的随机流引用、内容引用、内容类型、状态、
留存时间和删除证明。脱敏后记录 `metadataRedactedAt`，统计中的
`metadataRedacted` 增加。

法律保留同时阻止正文删除和元数据脱敏。

## 4. 法律保留

创建：

```text
POST /api/v1/admin/audit/content/legal-holds
Idempotency-Key: <1-128 printable ASCII>
```

```json
{
  "scope": {
    "contentRef": "ct_...",
    "streamId": "str_...",
    "userId": "usr_alice",
    "departmentId": "dept_engineering"
  },
  "reason": "litigation hold case 2026-42",
  "approvalId": "apr_legal_hold_2026_42",
  "custodianId": "legal_custodian_01",
  "startsAt": "2026-11-02T00:00:00.000Z",
  "expiresAt": "2026-12-02T00:00:00.000Z"
}
```

`scope` 至少包含一个字段；同时包含多个字段时为 AND 匹配。`startsAt` 省略时取当前
时间。`expiresAt` 必须晚于 `startsAt`，最长 3650 天。保留记录包含随机 `holdId`、
创建人、组织、创建时间、状态和所有审批字段。

释放：

```text
POST /api/v1/admin/audit/content/legal-holds/{holdId}/release
```

```json
{
  "reason": "legal case closed",
  "approvalId": "apr_release_hold_2026_42"
}
```

释放后状态为 `released`，保留释放时间、释放人、理由和审批 ID，不物理删除保留记录。
到期但未显式释放的保留不再阻止删除，但在记录中仍保持创建时状态；查询响应提供
`effectiveStatus` 为 `active`、`scheduled`、`expired` 或 `released`。

## 5. 删除与证明

### 5.1 自动清扫

```text
POST /api/v1/admin/audit/content/retention/run
```

```json
{
  "dryRun": false,
  "limit": 100
}
```

`limit` 为 1-500。自动后台清扫使用固定操作人 `system_retention`、理由
`retention_policy_expired` 和审批 ID `system_retention_policy`。后台间隔由
`AUDIT_CONTENT_RETENTION_SWEEP_INTERVAL_MS` 配置，允许 10 秒到 24 小时。

### 5.2 显式删除

```text
DELETE /api/v1/admin/audit/content/{contentRef}
Idempotency-Key: <1-128 printable ASCII>
```

```json
{
  "reason": "data subject deletion request",
  "approvalId": "apr_delete_2026_42",
  "force": false
}
```

未到期且 `force=false` 返回 `409 content_object_not_expired`。有活动法律保留返回
`409 content_legal_hold_active`。`force=true` 仍不能绕过法律保留。

### 5.3 原子性和恢复

删除在内容存储串行变更队列中执行：

1. 校验对象、留存到期、法律保留和证明字段；
2. 将加密对象原子改名为删除 staging 文件；
3. 移除对象索引、更新流状态、写入删除证明并原子持久化索引；
4. 删除 staging 文件；
5. 持久化失败时恢复 staging 文件并回滚内存索引。

启动恢复规则：

- 索引仍引用对象但正式文件缺失、存在对应 staging 文件时，恢复 staging 文件；
- 索引已无对象但存在 staging 文件时，删除该孤儿文件；
- 对象正式文件和 staging 文件都不存在时保持索引引用，任何读取失败关闭并写失败访问审计。

该核心是单进程/共享单写卷语义，不宣称对象存储版本控制、WORM、多副本一致性或不可恢复
介质擦除。

### 5.4 删除证明字段

```text
deletionId, contentRef, streamId, deletedAt,
plaintextSha256, objectBytes, retentionExpiresAt,
actorType, actorId, organizationId, sessionHash,
requestId, sourceHash, reason, approvalId,
policyVersion, proofMac
```

`proofMac` 为 `AUDIT_CONTENT_PROOF_SECRET` 对除自身外全部字段的 HMAC-SHA256。证明
独立存放在索引的 `deletionProofs` 对象中，不受普通访问审计每目标 10,000 条上限影响。
证明不包含正文、加密路径、导入密钥、导出密钥、下载 token 或明文密钥。

查询和验证：

```text
GET  /api/v1/admin/audit/content/deletions
GET  /api/v1/admin/audit/content/deletions/{deletionId}
POST /api/v1/admin/audit/content/deletions/{deletionId}/verify
```

列表支持 `contentRef`、`from`、`to`、`limit`。验证只返回 `valid`、证明摘要和原因，
重建 MAC 失败返回 `valid:false`。

## 6. 加密导出

### 6.1 创建

```text
POST /api/v1/admin/audit/content/exports
Idempotency-Key: <1-128 printable ASCII>
```

```json
{
  "scope": {
    "contentRefs": ["ct_...", "ct_..."],
    "userId": "usr_alice",
    "departmentId": "dept_engineering",
    "from": "2026-11-01T00:00:00.000Z",
    "to": "2026-11-02T00:00:00.000Z"
  },
  "purpose": "compliance_review",
  "reason": "regulator request 2026-42",
  "approvalId": "apr_export_2026_42",
  "ttlSeconds": 120
}
```

`contentRefs` 与筛选字段可以同时使用，最终为 AND 匹配。单次最多 100 个对象。只导出
当前仍可读的 L2 脱敏正文；缺失或完整性失败时整个导出失败，不生成下载 token。
每个被读取对象的成功或失败仍写普通访问审计。

导出包明文结构为 `magpie-content-export-v1` JSON，包含导出 ID、生成时间、组织、水印、
稳定审计编号、筛选摘要和每个对象的脱敏正文与元数据。导出文件使用独立
`AUDIT_CONTENT_EXPORT_KEY` 以 AES-256-GCM 加密：

```text
magic "MAGPIE-EXPORT-1" || 12-byte nonce || 16-byte tag || ciphertext
AAD = "MAGPIE-EXPORT-1:<exportId>"
```

响应只返回 `exportId`、一次性 token、过期时间、对象数、审计编号和水印，不返回正文、
密钥或文件路径。幂等重放可重建同一导出 token；不创建第二份文件。

下载响应返回 `.mge` 加密包本身，而不是服务端解密后的 JSON。服务端在响应前完成
AES-GCM 完整性和包结构校验，但不得通过 HTTP 返回导出密钥；解密密钥只能由受控的
离线保管/解密流程使用。下载响应头、管理列表和索引不得包含正文、导出密钥、一次性
token 或绝对路径。

### 6.2 下载

```text
GET /api/v1/admin/audit/content/exports/{exportId}/download
X-Audit-Export-Token: <one-time token>
```

token 绑定 `exportId`、管理员、组织、管理员会话摘要、筛选摘要、审计编号、签发和过期
时间，TTL 为 15-300 秒。下载必须同时带相同管理员、组织和会话头。

首次下载成功后 token 立即消费并持久化。重复下载返回
`409 content_export_token_reused`，过期返回 `410 content_export_expired`，身份或目标
不符返回 `401/403`。下载响应：

```text
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="magpie-export-<exportId>.mge"
Cache-Control: no-store
X-Audit-Watermark: MAGPIE-AUDIT-EXPORT <exportId> <timestamp>
```

消费记录或导出审计持久化失败时返回 `503`，不返回文件字节。

### 6.3 导出清理

导出到期后由留存清扫标记为 `expired` 并删除加密导出文件。已消费导出按同一到期时间
清理。导出审计记录保留在索引中，至少包含创建、下载、拒绝原因和清理事件。

## 7. API

```text
POST   /api/v1/admin/audit/content/retention/run
DELETE /api/v1/admin/audit/content/{contentRef}
GET    /api/v1/admin/audit/content/deletions
GET    /api/v1/admin/audit/content/deletions/{deletionId}
POST   /api/v1/admin/audit/content/deletions/{deletionId}/verify
POST   /api/v1/admin/audit/content/legal-holds
GET    /api/v1/admin/audit/content/legal-holds
POST   /api/v1/admin/audit/content/legal-holds/{holdId}/release
POST   /api/v1/admin/audit/content/exports
GET    /api/v1/admin/audit/content/exports
GET    /api/v1/admin/audit/content/exports/{exportId}/download
```

所有治理路由要求治理 Bearer 令牌和管理员上下文。`GET .../deletions`、
`GET .../legal-holds` 和 `GET .../exports` 只返回公开投影，不返回正文、路径、密钥、
token 或内部摘要。

## 8. 错误码

```text
503 content_governance_disabled
401 content_governance_unauthorized
400 invalid_content_governance_request
400 content_legal_hold_scope_required
400 content_legal_hold_approval_required
409 content_legal_hold_idempotency_conflict
404 content_legal_hold_not_found
409 content_legal_hold_released
409 content_legal_hold_active
404 content_object_not_found
409 content_object_not_expired
409 content_deletion_idempotency_conflict
404 content_deletion_not_found
400 invalid_content_export
413 content_export_scope_too_large
409 content_export_not_available
409 content_export_token_reused
410 content_export_expired
401 content_export_token_required
401 content_export_token_invalid
503 content_store_unavailable
```

## 9. JSON 索引 schema v2

`ContentStore` 索引版本从 1 升至 2，新增：

```text
legalHolds, deletionProofs, exports, governanceIdempotency
```

对象和内容流新增正文/元数据到期时间、删除状态和元数据脱敏时间；统计新增正文删除数、
元数据脱敏数和导出发起数。加载 v1 索引时执行一次性兼容迁移：

- 以已有 `finalizedAt + retentionDays` 补齐正文和元数据到期时间；
- 初始化空治理集合和新统计；
- 迁移后原子写回 v2。

损坏、未知字段、非法状态、重复 ID、时间格式错误或证明 MAC 格式错误均失败关闭为
`content_store_corrupt`。不支持从 v2 无审计地降级回 v1；回滚到旧版本前必须使用同版本
备份或在隔离环境执行明确的数据降级演练。

## 10. 验收

必须覆盖：

- 未到期正文仍可读，到期正文删除后不可读；
- 正文和元数据留存分别计算，元数据不得短于正文；
- 活动法律保留阻止删除和脱敏，释放或到期后恢复可删除；
- 显式删除的到期、force、保留和幂等边界；
- 删除证明可查询、可验证、独立于普通访问上限且不含秘密；
- 删除索引、文件、staging 恢复和重启后一致性；
- 持久化失败时不返回成功，并保持可重试或失败关闭；
- 导出仅生成一次、首次下载消费、重复/过期/身份/目标校验；
- 导出审计失败不返回文件；
- 导出文件加密，索引、证明、日志和响应不含正文、token、密钥或路径；
- 旧 M4-C v1 索引可迁移并读取；
- 八套企业回归全量通过。
