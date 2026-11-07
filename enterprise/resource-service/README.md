# Magpie Enterprise resource service

状态：**M3-A 核心后端与 M3-C 客户端同步控制面已实现，通过 15 项单元/Mock 集成测试；
尚未接入 admin-service 审批、管理台资源/漂移页和企业生产验收。**

这个服务提供企业资源目录、不可变版本、内容寻址对象存储和 Ed25519 签名
manifest。它不是员工门户，也不是公网 API；生产环境应只允许可信控制面服务通过
内部网络访问。

## 1. 当前范围

支持的资源类型：

```text
mcp
skill
instructions
subagent
template
redact
hook
```

支持的交付模式：

```text
forced
recommended
```

已实现：

- 资源元数据、分配范围、最低客户端版本和交付模式。
- 每个版本内容不可变；对象按 SHA-256 内容寻址，重复内容只存一份。
- canonical JSON、manifest digest 和 Ed25519 签名。
- 发布、历史版本回滚、乐观并发控制和完整资源审计链。
- `Idempotency-Key` 重放、同键异体冲突和 actor 绑定。
- JSON 单实例原子存储、临时文件加 `fsync` 和原子 rename。
- 明文秘密、私钥、自定义密钥字段和超大请求失败关闭。
- Bearer 服务令牌、固定窗口限流和请求 ID。
- M3-C 同步控制面：设备用短期同步凭证换取 desired state，客户端回报安装/漂移状态，
  管理员用服务令牌读取每台设备的最新报告。

当前不包含：

- 真实审批状态查询和一次性消费。`approvalId` 目前只是必填证据，资源服务不会自行
  把它当作已批准事实。
- 员工端安装。本服务只提供 desired state 和报告入口；真正写本机 Agent 文件的是
  本机 Magpie/helper，即 `enterprise/client-sync`。
- 灰度发布、自动回滚和资源分配管理页面。
- 远程 MCP 代理、工具级 allow/deny 和健康检查。
- S3/MinIO、KMS/HSM、多副本共享存储或分布式锁。
- 员工资源视图和公网 TLS 终止。

## 2. 信任边界

```text
管理员浏览器
      |
      |  管理会话 + CSRF
      v
admin-service（后续接入）
      |
      |  Bearer service token + X-Magpie-Actor
      v
resource-service :3447（仅内部网络）
      ^
      |
      |  短期同步凭证 mss1.<claims>.<hmac>
      |
本机 Magpie / enterprise helper
```

`X-Magpie-Actor` 是审计归属字段，不是身份认证。资源服务信任持有
`RESOURCE_SERVICE_TOKEN` 的调用方；因此只有 admin-service 或其他受控服务可以持有
该令牌。不要把令牌放进浏览器、员工客户端、URL、日志或 Git。

客户端路由 `/api/v1/client/sync/*` 只接受短期同步凭证；管理路由
`/api/v1/admin/*` 只接受 `RESOURCE_SERVICE_TOKEN`。两者不能互用：同步凭证不是
管理令牌，管理令牌也不接受同步请求。

同步凭证由 auth-service 签发：设备用 opaque device token 调用
`POST /api/v1/devices/sync-credential`，得到一个 60-900 秒、单用途的
`mss1.<claims>.<hmac>` 凭证。凭证绑定 `userId`、`deviceId`、OIDC `groups`
派生的 `organizationIds`、签发/过期时间和随机 `nonce`，并由
`SYNC_TOKEN_SECRET` 与 `RESOURCE_SYNC_TOKEN_SECRET` 共用的同一个 HMAC 密钥签名。
凭证不得写入日志、审计、状态文件或错误响应。

服务本身使用 HTTP。生产环境应放在受控 Compose/Kubernetes 网络、mTLS 网格或
只接受内部流量的反向代理之后。

## 3. 启动

Node.js 要求 `>=22`。服务没有第三方运行时依赖。

生成全新的 Ed25519 密钥：

```bash
node enterprise/resource-service/scripts/generate-signing-key.mjs \
  enterprise/secrets/resource-signing-key.pem
```

脚本拒绝覆盖已有文件，并输出公钥路径和 SPKI SHA-256 指纹。私钥应保持
`0400`/`0600` 权限；Linux 容器内如果由 Compose secret 挂载为 `0444`，
镜像入口脚本会先复制到 `/tmp` 的 tmpfs，再以 `0600` 交给 Node 进程。

设置环境变量：

```bash
export RESOURCE_SERVICE_TOKEN='<at-least-32-random-characters>'
export RESOURCE_SYNC_TOKEN_SECRET='<same-value-as-auth-SYNC_TOKEN_SECRET>'
export RESOURCE_SIGNING_PRIVATE_KEY_PATH="$PWD/enterprise/secrets/resource-signing-key.pem"
export RESOURCE_SIGNING_KEY_ID='resource-2026-11-v1'
export RESOURCE_STORE_PATH="$PWD/enterprise/data/resource-store.json"
export RESOURCE_CONTENT_PATH="$PWD/enterprise/data/objects"
export RESOURCE_SYNC_REPORT_PATH="$PWD/enterprise/data/sync-reports.json"
```

启动：

```bash
node enterprise/resource-service/src/server.js
```

健康检查不需要令牌：

```bash
curl -fsS http://127.0.0.1:3447/healthz
```

其他接口都要求：

```http
Authorization: Bearer <RESOURCE_SERVICE_TOKEN>
```

## 4. API

管理路由使用 `/api/v1/admin/` 前缀，仅表示由控制面调用，不代表浏览器管理员
会话可以直接访问。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/healthz` | 健康检查 |
| `POST` | `/api/v1/admin/resources` | 创建资源 |
| `GET` | `/api/v1/admin/resources` | 列出资源 |
| `GET` | `/api/v1/admin/resources/{id}` | 资源详情和历史版本 |
| `POST` | `/api/v1/admin/resources/{id}/releases` | 创建不可变候选版本 |
| `GET` | `/api/v1/admin/resources/{id}/releases` | 列出版本 |
| `GET` | `/api/v1/admin/resources/{id}/releases/{releaseId}/manifest` | 获取并在线验签 |
| `GET` | `/api/v1/admin/resources/{id}/releases/{releaseId}/content` | 下载内容 |
| `POST` | `/api/v1/admin/resources/{id}/publish` | 发布候选版本 |
| `POST` | `/api/v1/admin/resources/{id}/rollback` | 恢复历史已发布版本 |
| `GET` | `/api/v1/admin/signing-key` | 获取公钥指纹和公钥 |
| `GET` | `/api/v1/admin/audit-logs` | 查询资源审计 |
| `GET` | `/api/v1/admin/resources/{id}/audit-logs` | 查询单个资源审计 |

所有写请求必须带唯一的 `Idempotency-Key`、`X-Magpie-Actor`、`operationId` 和
`reason`。创建版本、发布和回滚还必须带 `expectedUpdatedAt`，用于乐观并发控制。

客户端同步路由使用 `/api/v1/client/sync/` 前缀，认证方式是短期同步凭证，不是管理
服务令牌：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/api/v1/client/sync/desired-state` | 取当前设备的完整 desired state 快照 |
| `POST` | `/api/v1/client/sync/report` | 回报本设备的安装与漂移状态 |
| `GET` | `/api/v1/admin/sync-reports` | 列出全部设备的最新报告 |
| `GET` | `/api/v1/admin/sync-reports/{deviceId}` | 读取单台设备的最新报告 |

`GET /api/v1/client/sync/desired-state` 的行为：

- 只返回 `status=published`、有当前发布版本，且 `assignments` 与凭证
  `organizationIds` 有交集的资源。
- 逐个校验当前版本的签名、manifest digest 和内容哈希，任一不一致即整体失败。
- 返回稳定 `revision`，格式为 `sha256:<64 hex>`，由快照内容计算。
- 支持 `If-None-Match`；匹配时返回 `304` 且不返回正文。
- 受 `RESOURCE_MAX_SNAPSHOT_RESOURCES` 和 `RESOURCE_MAX_SNAPSHOT_BYTES` 限制，
  超限返回 `409` 而不是截断的快照。

`POST /api/v1/client/sync/report` 的行为：

- 身份完全来自同步凭证。客户端不能通过请求体冒充其他用户或设备。
- 只接受资源 ID、release ID、digest、状态和漂移状态；资源正文、Secret、token
  和自由文本字段一律拒绝。
- 每台设备只保留最新一份报告，最多 10000 台设备。

```http
POST /api/v1/client/sync/report
Authorization: Bearer <mss1...>
Content-Type: application/json

{
  "schemaVersion": 1,
  "revision": "sha256:<64 hex>",
  "clientVersion": "1.4.0",
  "status": "synced",
  "installed": [
    {
      "resourceId": "res_<id>",
      "releaseId": "rel_<id>",
      "manifestDigest": "sha256:<64 hex>"
    }
  ],
  "drift": [],
  "reportedAt": "2026-11-02T00:00:00.000Z"
}
```

创建资源示例：

```http
POST /api/v1/admin/resources
Authorization: Bearer <token>
Idempotency-Key: 0d8f0f88-59eb-4ea1-a6ee-2e7f9f979d67
X-Magpie-Actor: admin_platform
Content-Type: application/json

{
  "kind": "instructions",
  "name": "Engineering baseline",
  "description": "Shared engineering instructions",
  "publisher": "enterprise-platform",
  "deliveryMode": "forced",
  "assignments": ["org_engineering"],
  "compatibility": { "minClientVersion": "0.2.0" },
  "operationId": "op_create_engineering_baseline",
  "reason": "Create the engineering baseline resource"
}
```

创建候选版本：

```http
POST /api/v1/admin/resources/{id}/releases
Authorization: Bearer <token>
Idempotency-Key: <unique-key>
X-Magpie-Actor: admin_platform
Content-Type: application/json

{
  "resourceVersion": "2026.11.1",
  "mediaType": "text/markdown",
  "contentBase64": "<base64>",
  "operationId": "op_release_2026_11_1",
  "reason": "Create an immutable candidate",
  "expectedUpdatedAt": "<resource.updatedAt>"
}
```

发布候选版本：

```http
POST /api/v1/admin/resources/{id}/publish
Authorization: Bearer <token>
Idempotency-Key: <unique-key>
X-Magpie-Actor: admin_platform
Content-Type: application/json

{
  "releaseId": "rel_<id>",
  "approvalId": "apr_<approved-request-id>",
  "operationId": "op_publish_2026_11_1",
  "reason": "Publish the approved release",
  "expectedUpdatedAt": "<resource.updatedAt>"
}
```

回滚使用同一结构，路径改为 `/rollback`，目标必须是曾经发布过的历史版本。

## 5. Manifest 与验签

manifest 固定包含：

```text
schemaVersion
resourceId
releaseId
resourceVersion
kind
hash
contentBytes
mediaType
publisher
createdAt
assignments
deliveryMode
compatibility
previousReleaseId
signingKeyId
signatureAlgorithm
manifestDigest
signature
```

客户端必须：

1. 从可信控制面取得固定 `signingKeyId` 和公钥。
2. 校验 manifest 字段集合、schema、key id 和 Ed25519 签名。
3. 校验内容长度和 `sha256` 内容哈希。
4. 拒绝未知字段、签名变化、内容变化或版本回退。

不能只根据 HTTP `200`、文件名或对象存储中的内容判定发布可信。

## 6. 存储与并发

默认路径：

```text
RESOURCE_STORE_PATH=./data/resource-store.json
RESOURCE_CONTENT_PATH=./data/objects
```

资源元数据和审计在同一个 JSON store 中原子提交。内容按哈希分目录保存，并拒绝
覆盖为不同内容。

当前限制：

- 只支持单个服务实例。多个副本不能共享当前 JSON store。
- 没有 S3/MinIO、数据库事务、分布式锁和对象生命周期策略。
- 损坏、未知 schema 或未知字段会阻止启动，不会带着不完整状态继续服务。

## 7. 主要错误码

| HTTP | 错误码 | 含义 |
| --- | --- | --- |
| `400` | `approval_required` | 发布/回滚缺少审批证据 |
| `400` | `content_secret_detected` | 内容或元数据含明文秘密 |
| `400` | `invalid_request` | 字段缺失、未知字段或类型错误 |
| `400` | `invalid_sync_report` | 同步报告字段、类型或取值不合法 |
| `401` | `unauthorized` | 服务令牌缺失或错误 |
| `401` | `missing_sync_credential` | 客户端路由缺少同步凭证 |
| `401` | `invalid_sync_token` | 同步凭证签名、claims 或 audience 不合法 |
| `401` | `sync_token_expired` | 同步凭证已过期 |
| `404` | `resource_not_found` / `release_not_found` | 目标不存在 |
| `404` | `sync_report_not_found` | 该设备还没有上报 |
| `409` | `idempotency_conflict` | 同一幂等键用于不同请求或 actor |
| `409` | `stale_resource` | `expectedUpdatedAt` 已过期 |
| `409` | `resource_version_exists` | 版本号重复 |
| `409` | `release_stale` / `release_not_candidate` | 版本状态不允许发布 |
| `409` | `release_integrity_failed` | 对象内容或 manifest 校验失败 |
| `409` | `sync_snapshot_limit_reached` | 分配资源数超过快照上限 |
| `409` | `sync_snapshot_too_large` | 快照字节数超过上限 |
| `409` | `sync_report_limit_reached` | 设备报告数超过上限 |
| `413` | `request_too_large` / `content_too_large` | 超过配置上限 |
| `429` | `rate_limited` | 超过固定窗口限流 |

错误响应包含 `requestId`，但不会返回内部路径、私钥、令牌或调用栈。

## 8. 配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `RESOURCE_SERVICE_TOKEN` | 无，必填 | 至少 32 字符 |
| `RESOURCE_SYNC_TOKEN_SECRET` | 无，必填 | 至少 32 字符；必须与 auth-service 的 `SYNC_TOKEN_SECRET` 相同，且不得等于 `RESOURCE_SERVICE_TOKEN` |
| `RESOURCE_SYNC_TOKEN_AUDIENCE` | `magpie-enterprise-resource` | 同步凭证的 audience，必须与 auth-service 相同 |
| `RESOURCE_SYNC_REPORT_PATH` | `./data/sync-reports.json` | 每设备最新同步报告的存储路径 |
| `RESOURCE_SIGNING_PRIVATE_KEY_PATH` | 无，必填 | Ed25519 PKCS#8/OpenSSH 私钥 |
| `RESOURCE_SIGNING_KEY_ID` | 无，必填 | 稳定公钥标识 |
| `RESOURCE_BIND` | `0.0.0.0` | 容器内监听地址 |
| `RESOURCE_PORT` | `3447` | 监听端口 |
| `RESOURCE_STORE_PATH` | `./data/resource-store.json` | JSON store |
| `RESOURCE_CONTENT_PATH` | `./data/objects` | 内容对象目录 |
| `RESOURCE_MAX_CONTENT_BYTES` | `1048576` | 单资源内容上限，最大 16 MiB |
| `RESOURCE_MAX_RESOURCES` | `1000` | 资源总数上限 |
| `RESOURCE_MAX_RELEASES_PER_RESOURCE` | `200` | 单资源版本上限 |
| `RESOURCE_MAX_SNAPSHOT_BYTES` | `8388608` | 单次 desired state 快照字节上限 |
| `RESOURCE_MAX_SNAPSHOT_RESOURCES` | `200` | 单次快照的资源数上限 |
| `RESOURCE_MAX_SYNC_REPORT_BYTES` | `262144` | 单次同步报告请求体上限 |
| `RESOURCE_RATE_LIMIT_PER_MINUTE` | `600` | 每客户端每分钟请求数 |

## 9. Compose 部署

在 `enterprise/` 下准备：

```text
secrets/resource-signing-key.pem
.env
```

`enterprise/docker-compose.yml` 的 `resource` profile：

- 只暴露容器内部 `3447`，不发布主机端口。
- 使用独立 `resource-data` 和 `resource-content` 卷。
- 根文件系统只读，`/tmp` 使用 tmpfs。
- 删除全部 Linux capabilities，设置 `no-new-privileges`。
- 以 UID/GID `10001` 运行。
- 签名私钥通过 Compose secret 只读挂载，入口脚本复制到 tmpfs 后立即切换到 `0600`。

启动：

```bash
cd enterprise
docker compose --profile resource up -d resource
```

当前机器未安装 Docker CLI，因此本仓库尚未提供 Compose 实机构建、启动、健康检查和
Linux 文件权限验收证据。

## 10. 测试

```bash
node --test enterprise/resource-service/test/resource-service.test.mjs \
        enterprise/resource-service/test/sync-control-plane.test.mjs
```

当前结果：

```text
15 passed, 0 failed
```

覆盖 Bearer 鉴权、发布与验签、内容和 manifest 篡改、不可变版本、幂等与 actor
冲突、乐观并发、并发发布、回滚审计、审批字段缺失、秘密扫描、请求上限、损坏存储和
签名 helper；以及同步控制面：客户端路由与管理路由的令牌互斥、只返回已发布且已分配
资源、身份取自凭证、快照与报告上限失败关闭、报告内容不含 token 和资源正文。
