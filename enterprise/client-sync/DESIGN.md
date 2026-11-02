# Magpie Enterprise client sync design

状态：**M3-C-1 客户端同步控制面，24 项单元/Mock 测试通过。同步引擎、短期同步凭证、
desired-state、设备上报、管理员 JSON 查询 API 和客户端 HTTP 传输适配器已实现；管理台
资源/漂移页、本地 helper 产品入口、Windows ACL、MDM、目标 Agent 文件映射和企业生产
环境验收仍未完成；M3-D 运行时核心已在 `enterprise/local-mcp` 实现，但 helper 集成和
生产验收未完成，M4-M6 仍未实现。**

## 1. 目标与信任边界

客户端同步解决的是：受信控制面决定某台员工设备应使用哪些企业资源；本机
Magpie/helper 拉取这些资源，验证企业签名，原子安装，并把期望版本、实际版本、
离线状态和漂移报告给本机 UI/控制面。

```text
浏览器
  |  不能直接写本机 Agent 文件
  v
本机 Magpie / enterprise helper
  |  设备令牌 -> auth-service；短期同步凭证 -> resource-service
  v
受信控制面 desired-state adapter
  |
  |  返回签名 manifest + 内容字节
  v
ClientSyncEngine
```

本包实现同步引擎和客户端传输适配器。传输适配器只把设备令牌发给 auth-service，把
`mss1` 短期同步凭证发给 resource-service；它不持有 `RESOURCE_SERVICE_TOKEN`，也不调用
仅供管理控制面使用的 `/api/v1/admin/*` API。不能把管理服务令牌放进浏览器或员工机。

## 2. Desired state 契约

`fetchDesiredState(context)` 由传输层注入，必须返回：

```js
{
  schemaVersion: 1,
  revision: "desired-state-revision",
  generatedAt: "2026-11-02T00:00:00.000Z",
  resources: [
    {
      manifest: { /* resource-service signed manifest */ },
      content: Buffer.from("...")
    }
  ]
}
```

约束：

- `revision` 是控制面生成的不可变摘要或版本，不是用户可编辑名称。
- 每个 `content` 必须是 `Buffer` 或 `Uint8Array`；HTTP JSON 适配器负责从受大小限制的
  base64 字段解码，不能把任意大响应整体复制到状态文件。
- 每个 `manifest` 必须符合 `resource-service/src/manifest.js` 的固定字段集合。
- `resourceId`、`releaseId` 必须只含安全路径字符；`..`、路径分隔符、控制字符失败关闭。
- `compatibility.minClientVersion` 必须不高于当前客户端版本。
- `fetchDesiredState` 的 `context` 包含 `revision`、`clientVersion` 和 `AbortSignal`，
  传输层可据此做条件请求和取消。

## 2.1 已接入的控制面

```text
auth-service
  POST /api/v1/devices/sync-credential
    Authorization: Bearer <opaque device token>

resource-service
  GET  /api/v1/client/sync/desired-state
  POST /api/v1/client/sync/report

resource-service admin JSON
  GET  /api/v1/admin/sync-reports
  GET  /api/v1/admin/sync-reports/{deviceId}
```

同步凭证使用 `mss1.<claims>.<hmac>` 格式，绑定 `userId`、`deviceId`、OIDC `groups`
派生的 `organizationIds`、签发/过期时间和随机 `nonce`。auth-service 与 resource-service
必须配置相同的 HMAC 密钥，但该密钥必须与 `RESOURCE_SERVICE_TOKEN` 不同。

`createEnterpriseSyncTransport()` 负责凭证缓存、到期前重签、条件请求、401 单次重签、
超时、响应体上限和错误归并。资源服务只返回与凭证组织范围匹配的已发布资源；报告只
保留资源 ID、release ID、digest、状态和漂移证据，不接收正文、Secret、token 或自由文本。

desired state 是完整快照。成功同步后，不在快照中的资源不再处于 active 状态；旧版本
目录仍保留用于回滚和缓存。管理员明确把 desired release 回退到旧 ID 时，客户端接受该
受信快照；它不是由资源 URL、文件名或单个 HTTP 200 自行决定的“版本回退”。

## 3. 密钥固定

构造时必须提供至少一个 `signingKeyId -> public key`，并建议同时固定 SPKI SHA-256
指纹：

```js
{
  publicKeys: {
    "resource-2026-11-v1": "-----BEGIN PUBLIC KEY-----\n..."
  },
  keyFingerprints: {
    "resource-2026-11-v1": "sha256:<SPKI SHA-256>"
  }
}
```

私钥、`PRIVATE KEY` PEM 和非 Ed25519 公钥会在构造时拒绝。manifest 的
`signingKeyId` 必须命中已固定 key；未知 key 不得退回“尝试所有 key”。

## 4. 安装布局

`rootDir` 必须是绝对路径。所有路径都拒绝符号链接。

```text
rootDir/
  releases/
    <resourceId>/
      <releaseId>/
        content
        metadata.json
  staging/
    <random>/
  state.json
  sync.lock
```

- 内容和 manifest 先写入同卷 `staging/`，fsync 后完整复验，再 rename 到 release 目录。
- `metadata.json` 保存签名 manifest，不保存私钥、设备凭证或正文副本。
- 内容和元数据文件权限为 `0600`，目录为 `0700`；Windows 上由 ACL 承担同等保护。
- 相同 `resourceId + releaseId` 已存在但 manifest 或内容不同，返回 `cache_conflict`，
  不覆盖未知缓存。
- 已存在的可信缓存可以复用；损坏或未知 schema 的缓存失败关闭。

## 5. 状态 schema

`state.json` 使用固定 schema v1：

```js
{
  schemaVersion: 1,
  revision: "last successful desired-state revision or null",
  lastSuccessfulSyncAt: "ISO-8601 or null",
  lastAttemptAt: "ISO-8601",
  lastError: { code: "stable_code", at: "ISO-8601" } | null,
  desired: {
    revision: "last observed desired-state revision",
    resources: [
      {
        resourceId,
        releaseId,
        resourceVersion,
        kind,
        deliveryMode,
        hash,
        manifestDigest,
        signingKeyId
      }
    ]
  } | null,
  resources: [
    {
      resourceId,
      releaseId,
      resourceVersion,
      kind,
      deliveryMode,
      hash,
      manifestDigest,
      signingKeyId,
      installedAt,
      directory
    }
  ],
  disabledRecommended: ["resourceId"]
}
```

状态只保存标识、摘要、版本和稳定错误码。不得保存资源内容、Secret、token、设备
凭据、私钥、完整上游响应或自由文本错误。

状态写入流程是“临时文件 + fsync + rename”。同步失败时会更新 `desired` 和
`lastError` 以显示漂移，但 active `resources` 仍指向最后一次完整验证并激活的版本。

## 6. 事务与失败语义

一次 `syncOnce()` 的顺序：

1. 取得进程锁，清理未激活的 staging。
2. 读取并严格校验旧状态。
3. 拉取 desired state。
4. 校验所有 manifest、固定 key、签名、内容长度和 SHA-256。
5. 将所有新资源写入 staging 并复验；可运行按资源类型的额外 `validateInstalled`。
6. 全部准备成功后，逐个 rename 到不可变 release 目录。
7. 原子提交新的 `state.json`；提交前 active 状态不变。

因此：

- 新版本失败时仍使用上一已验证版本。
- 首次安装失败不会破坏其他 active 资源。
- 状态提交失败时旧 `state.json` 仍指向旧版本；新文件目录可在下次同步时复用。
- 网络不可用时返回 `offline`，保留最后已验签版本，并记录
  `desired_state_unavailable`。
- 签名、哈希、缓存、路径和安装校验错误返回 `failed`，不得当作普通离线。
- 并发同步返回 `busy/sync_locked`，不得并行改状态。

默认同步间隔 60 秒，构造时强制在 1 秒到 300 秒之间。企业可设置 60-120 秒；
不能配置成超过 5 分钟。

## 7. 强制、推荐与漂移

- `forced`：员工不能关闭。即使内部状态误写过 disabled，下一次同步也会清除该标记并
  安装 forced 版本。
- `recommended`：可在已安装后通过 `setRecommendedEnabled(id, false)` 禁用。禁用期间
  保留最后 active 版本，但跳过新版本；重新启用后的下一轮同步安装期望版本。
- `inspect()` 重新读取 active release 的 manifest 和内容，验证签名/哈希，并比较
  active 与 last observed desired 的 release。
- 漂移状态包括 `missing`、`version_mismatch`、`not_in_desired_state`、
  `content_invalid`、`metadata_mismatch` 和 `path_symlink`。

## 8. 稳定错误码

| code | 含义 |
| --- | --- |
| `invalid_config` | 根目录、公钥、版本、周期或注入函数配置错误 |
| `invalid_state` | 状态 schema、字段或时间戳不可信 |
| `path_traversal` | 资源/release 标识不能安全用于路径 |
| `path_symlink` | 托管目录、状态或 release 路径出现符号链接 |
| `state_write_failed` | 状态无法原子提交 |
| `desired_state_unavailable` | 传输层不可用或超时；最后版本仍 active |
| `desired_state_invalid` | desired state 字段、重复资源或 revision 非法 |
| `manifest_invalid` | manifest schema、digest、签名或固定 key 校验失败 |
| `manifest_key_unknown` | manifest 使用未固定 key |
| `content_invalid` | 内容长度或 SHA-256 不匹配 |
| `client_version_incompatible` | 客户端低于资源最低版本 |
| `content_too_large` | 单资源超过客户端大小上限 |
| `cache_conflict` | release 缓存损坏或同 ID 对应不同签名内容 |
| `install_validation_failed` | 安装后类型校验拒绝资源 |
| `install_failed` | 本地 staging/rename 失败 |
| `sync_locked` | 另一个同步进程持有锁 |
| `forced_resource` | 试图关闭强制资源 |
| `resource_not_installed` | 试图关闭未安装的推荐资源 |
| `sync_aborted` | 调用方取消同步 |

## 9. 不在此包内的能力

- 员工端 OIDC/设备令牌换取短期同步凭证的 API。
- HTTP 下载、证书固定、代理、重试和条件请求；这些属于传输适配器。
- Skills/Subagents 的目标 Agent 文件映射与一键配置。
- MCP 本地进程启动、沙箱、Secret Reference 和健康检查；这些属于 M3-D。
- 管理台设备版本/漂移列表和灰度发布；控制面 desired-state 与设备上报 API 已实现，
  但目前只有管理员 JSON 查询 API，没有对应管理 UI。
- 删除策略、磁盘配额、内容压缩、增量 patch 和多副本共享状态。

浏览器仍只能发起“请求本机 helper 同步”的受控动作；真正写本机 Agent 文件和
企业资源目录的必须是有设备身份、可审计、可升级的本机进程。

## 10. 验证

当前专项测试使用临时目录、内存 desired-state 适配器和临时 Ed25519 key，不访问网络，
不读取真实 `~/.codex`、`~/.claude`、`~/.config/magpie` 或真实资源目录。

```powershell
& 'D:\Environment\node-v26.12.1\node.exe' --test enterprise/client-sync/test/*.test.mjs
```

当前结果：**16 passed, 0 failed**。这证明签名 desired-state、原子安装、失败保留旧版本、
离线缓存、强制/推荐策略、漂移检测、路径/符号链接防护、并发锁和状态秘密隔离，不等于
员工端 API、管理台、浏览器 E2E、Windows 文件 ACL、MDM、目标 Agent 文件映射、真实企业
IdP 或生产部署已经验收。
