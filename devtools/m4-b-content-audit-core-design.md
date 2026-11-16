# M4-B 内容采集与脱敏对象存储核心设计冻结

> 历史说明：旧静态正文读取令牌已被 M4-C 一次性 grant 取代，本文仅作历史记录。

状态：实现前冻结版 v1，2026-11-02  
分支：`codex/m4-b-content-audit-core`  
依赖：`codex/m4-a-audit-event-pipeline`

本文只冻结 **M4-B 核心**。它不表示 M4-C 的正文检索与二次授权、也不表示 M4-D 的
留存/删除证明/法律保留/加密导出已经完成。实现和验收时不得用本文替代
`enterprise-acceptance-checklist.md` 中的真实环境证据。

## 1. 不可破坏的兼容性边界

1. M4-A 的 schema v1 事件契约保持原样：`request`、`response`、`tool_call`、
   `policy_decision` 仍只接受 L0/L1 元数据，不接收正文、附件或未知字段。
2. 内容采集使用独立的 URL、独立的请求 schema 和独立存储，不放宽 M4-A 的
   `validateAuditEvent()`。
3. 内容采集默认关闭。`AUDIT_CONTENT_ENABLED=false` 时内容 API 失败关闭，
   不存在“默认顺手采集正文”的路径。
4. M4-B 只启用 L2 经脱敏正文。L3 原始正文不实现、不可配置、请求直接拒绝。
5. 附件、图片和二进制不进入正文对象存储；它们只能以元数据、媒体类型和
   SHA-256 摘要出现在上层元数据事件中。
6. 正文读取必须使用与 ingest 不同的 Bearer 令牌；未配置读取令牌时读取失败关闭。
7. 正文对象以 AES-256-GCM 加密落盘；索引与对象分目录保存；`contentRef` 使用
   32 字节 CSPRNG 随机值，不能从 `requestId`、`sessionId` 或时间推导。
8. 脱敏发生在正文对象写入前。测试必须在所有持久文件中搜索测试秘密，确认
   秘密没有以明文落盘。
9. 流式拼接默认有总字节、分片数、并发流、流空闲时间上限；断流、乱序、冲突
   分片、超限和重启都失败关闭，不产生半截正文对象。
10. 索引接口不返回正文。读取正文必须记录访问审计，包括内容引用、理由、
    authorization ID、访问时间、来源哈希和结果。

## 2. 冻结 API

所有内容 API 继续要求 `Authorization: Bearer <AUDIT_SERVICE_TOKEN>`；正文读取
还要求独立的 `X-Audit-Content-Token`。

### 2.1 创建流

```text
POST /api/v1/internal/audit/content/streams
Idempotency-Key: <printable-ascii>
Content-Type: application/json
```

请求：

```json
{
  "schemaVersion": 1,
  "requestId": "req_...",
  "sessionId": "ses_...",
  "userId": "usr_123",
  "departmentId": "org_engineering",
  "deviceId": "dev_456",
  "agentId": "codex",
  "modelId": "provider/model",
  "contentKind": "prompt",
  "mediaType": "text/plain",
  "auditLevel": "L2",
  "collection": {
    "purpose": "security_investigation",
    "authorizationId": "apr_...",
    "confirmed": true,
    "retentionDays": 7
  }
}
```

响应返回随机 `streamId`、`nextSequence=0` 和流状态。`collection.confirmed` 必须为
`true`；`retentionDays` 只记录到对象元数据，M4-B **不执行**到期删除。真实审批状态
查询属于后续集成缺口，不能把这里的 `authorizationId` 当作已批准的证明。

### 2.2 提交分片

```text
POST /api/v1/internal/audit/content/streams/{streamId}/chunks
Idempotency-Key: <printable-ascii>
Content-Type: application/json
```

```json
{
  "schemaVersion": 1,
  "sequence": 0,
  "text": "redact me before this reaches the object store",
  "final": false
}
```

- `sequence` 必须从 0 连续递增。
- 同序号同内容重放返回 `200 duplicate:true`；同序号不同内容返回
  `409 content_chunk_conflict`。
- 乱序返回 `409 content_sequence_out_of_order`。
- 超过 `AUDIT_CONTENT_MAX_STREAM_BYTES` 返回 `413 content_stream_too_large`。
- `final:true` 触发拼接、脱敏、加密和对象写入；成功后返回不能再修改的
  `contentRef`、脱敏规则版本、命中类别计数和明文 SHA-256。
- 任何失败都不产生可读取正文对象。

### 2.3 查询流元数据

```text
GET /api/v1/admin/audit/content/streams/{streamId}
```

只返回状态、序号、字节数、内容引用、脱敏摘要和错误码，不返回正文。

### 2.4 读取 L2 正文

```text
GET /api/v1/admin/audit/content/{contentRef}
Authorization: Bearer <AUDIT_SERVICE_TOKEN>
X-Audit-Content-Token: <AUDIT_CONTENT_READ_TOKEN>
X-Audit-Content-Reason: <short reason>
X-Audit-Content-Authorization: <approval/authorization id>
```

读取成功返回明文和 `x-audit-watermark` 响应头。该接口只是 M4-B 核心读取边界，
不是 M4-C 的检索、二次授权、RBAC 或管理台 UI。

## 3. 存储边界

新增独立目录，默认 `AUDIT_CONTENT_STORE_DIR=./data/audit-content`：

```text
audit-content/
  index.json                  # 流、对象元数据、访问记录，600
  objects/
    <contentRef>.bin          # MAGPIE-CONTENT-1 + nonce + tag + ciphertext
```

索引只保存对象元数据、明文 SHA-256、大小、媒体类型、脱敏摘要和访问记录；
对象文件只保存密文。二者不能合并为一个文件，也不能通过普通 M4-A 事件查询返回
对象路径。

## 4. 文件所有权与并行任务图

先串行冻结本文件和 `content-schema.js`。之后四条写入线互不重叠：

| 任务 | 主要写入者 | 独占文件 | 合并顺序 |
| --- | --- | --- | --- |
| A 契约与脱敏 | 后端 A | `src/content-schema.js`、`src/redaction.js`、对应单测 | 1 |
| B 加密对象存储 | 后端 B | `src/content-store.js`、对应单测 | 2 |
| C 流式拼接与 API | 主线程/集成 | `src/content-streams.js`、`src/content-service.js`、`src/service.js`、`src/config.js` | 3 |
| D 文档与部署 | SRE/文档 | `README.md`、`enterprise/docker-compose.yml`、`enterprise/.env.example`、企业状态文档 | 4 |

约束：

- 一个文件只能有一个主要写入者。
- `src/service.js`、`src/config.js` 是路由热点，只由集成者修改。
- 所有测试使用临时目录、端口 `0` 和进程内密钥，不接触真实 `usage.jsonl`、
  管理员会话或生产卷。
- 后端 A/B 的模块不得直接读取环境变量；配置只由 `config.js` 注入。
- 合并前由主线程统一运行 `node --check`、audit-service 测试、九套企业回归、
  `git diff --check` 和持久文件秘密扫描。

## 5. 验收矩阵

| 用例 | 断言 |
| --- | --- |
| 默认关闭 | 未开启内容采集时创建流返回稳定错误，不产生目录或对象 |
| L2 显式采集 | 完整分片拼接后返回随机 `contentRef` 和脱敏计数 |
| 流式完整性 | 多分片正文拼接顺序正确，跨分片秘密被脱敏 |
| 重复/乱序/冲突 | 重复幂等，乱序和同序号异内容拒绝，均不落正文 |
| 超限/断流 | 超字节或重启中的 collecting 流失败关闭，无半截对象 |
| 脱敏 | API Key、Bearer/JWT、私钥、密码赋值、邮箱、手机号、身份证、银行卡均被替换 |
| 落盘保密 | `index.json` 和对象文件均不含测试秘密明文 |
| 引用不可猜 | `contentRef` 为高熵随机值，不能由请求标识推导 |
| 加密完整性 | 对象可正确解密；篡改 nonce/tag/ciphertext 或索引 hash 后读取失败 |
| 独立读取权限 | 缺读取令牌、理由或 authorization ID 拒绝，且不返回对象地址 |
| 访问审计 | 成功和失败读取都有访问记录，记录不含正文 |
| 重启恢复 | 已完成对象可恢复读取；未完成 collecting 流标记中断且不产生对象 |

## 6. 本轮明确不做

- M4-C 的跨员工/部门/时间/模型/工具正文检索、审批消费、水印渲染和管理台 UI。
- M4-D 的留存到期删除、删除证明、法律保留、WORM、加密导出和访问审批。
- L3、附件正文、二进制内容、对象存储 S3/MinIO、KMS/HSM、PostgreSQL/HA。
- 真实网关采集接入、真实 OIDC/RBAC、组织范围、浏览器 E2E、Docker/Compose 实机
  和生产验收。
