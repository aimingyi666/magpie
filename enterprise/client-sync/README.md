# Magpie Enterprise client sync

状态：**M3-C-1 客户端同步控制面已接入。同步引擎、短期同步凭证、desired-state、
设备上报、管理员 JSON 查询 API、客户端 HTTP 传输适配器和已验证 active 资源读取接口
已实现，并通过 26 项单元/Mock 测试；本地 MCP helper/HTTP server 集成核心已在
`enterprise/local-mcp` 实现，并通过 50 项专项测试（含 helper HTTP、stdio bridge 和
真实子进程 E2E）。管理台资源/漂移页、本地 helper 安装器/Windows 服务、Windows ACL、
MDM、真实 Codex 客户端配置验收和生产验收仍未完成；M4-M6 仍未实现。**

这个包提供本机 Magpie/helper 所需的企业资源同步核心：

- 拉取一份完整 desired state。
- 固定 Ed25519 公钥和 SPKI 指纹。
- 校验 manifest schema、digest、签名、内容长度和 SHA-256。
- 先 staging、后原子激活；新版本失败保留上一版本。
- 强制/推荐资源策略、离线缓存、漂移检测和稳定错误码。
- 进程锁、路径穿越/符号链接拒绝、`0600` 状态和秘密不落状态。
- `createEnterpriseSyncTransport()`：设备令牌只发给 auth-service，换取短期 `mss1`
  同步凭证；desired-state 和报告只发给 resource-service。

它不是浏览器 SDK。浏览器不能直接写本机 `~/.codex`、`~/.claude` 或
`~/.config/magpie`；本机文件必须由带设备身份的 Magpie/helper 安装。

## 最小用法

```js
import fs from "node:fs";
import { ClientSyncEngine } from "@magpie-enterprise/client-sync";

const engine = new ClientSyncEngine({
  rootDir: "C:\\ProgramData\\Magpie\\EnterpriseResources",
  clientVersion: "1.4.0",
  publicKeys: JSON.parse(fs.readFileSync("trusted-resource-key.json", "utf8")).keys,
  keyFingerprints: JSON.parse(fs.readFileSync("trusted-resource-key.json", "utf8")).fingerprints,
  fetchDesiredState: async ({ revision, clientVersion, signal }) => {
    // 传输层必须使用员工设备身份/短期同步凭证，不得使用管理服务令牌。
    // 返回 { schemaVersion, revision, generatedAt, resources: [{ manifest, content }] }。
  },
});

const result = await engine.syncOnce();
const status = await engine.inspect();
```

需要周期运行且不超过 5 分钟时：

```js
const controller = new AbortController();
await engine.run({
  signal: controller.signal,
  onResult(result) {
    // 只上传稳定 code、版本、摘要和漂移；不要上传内容或 Secret。
  },
});
```

推荐项启停：

```js
await engine.setRecommendedEnabled("res_optional_skill", false);
await engine.setRecommendedEnabled("res_optional_skill", true);
```

强制项调用会抛出 `ClientSyncError("forced_resource")`。

## 读取 active 资源

`readActiveResource(resourceId)` 只读取最后一次成功激活且仍与 state 记录一致的资源。
它不会扫描 release 目录、接受调用方提供的路径，或回退到未激活版本。

```js
const active = await engine.readActiveResource("res_local_mcp_echo");
// active.manifest: 已重新校验的签名 manifest
// active.content:  Buffer 内容
// active.record:   与 manifest 对应的 active state 记录
```

读取时会重新验证 manifest schema、Ed25519 签名、内容长度和 SHA-256，拒绝路径穿越、
符号链接、缺失文件、超大文件和 state/manifest 不一致。该接口供本机 helper 使用：
`LocalMcpHelper` 只接受 `kind === "mcp"` 的 active 资源，并从验证后的 manifest 解析
`packageId`/`releaseId`，不信任调用方传入的包身份。

## 传输适配器和控制面

当前仓库已经提供员工设备可用的控制面链路：

```text
本机 helper
  -> POST auth-service /api/v1/devices/sync-credential
  -> GET resource-service /api/v1/client/sync/desired-state
  -> POST resource-service /api/v1/client/sync/report
```

`createEnterpriseSyncTransport()` 可直接注入 `ClientSyncEngine`。它会在凭证到期前重新签发，
对 `304` 使用本地缓存，并只在收到 `invalid_sync_token` 或 `sync_token_expired` 时重试一次。
管理员目前可以通过
`GET /api/v1/admin/sync-reports[/{deviceId}]` 读取最新设备报告；对应的管理台页面尚未实现。

传输实现仍必须遵守以下边界：

- 必须使用 HTTPS 和内网/公网受控入口。
- 必须携带设备或用户短期身份，不接受匿名下载。
- 必须按用户、部门、设备范围只返回已分配资源。
- 必须设置响应、单资源和总资源大小上限及超时。
- 必须返回签名 manifest 和原始内容字节。
- 不得在 URL、日志、状态或报告中放 token、设备令牌或 Secret。

不能把 `RESOURCE_SERVICE_TOKEN` 或 `/api/v1/admin/*` 管理令牌放进员工机。

## 测试

```powershell
& 'D:\Environment\node-v26.12.1\node.exe' --test enterprise/client-sync/test/*.test.mjs
```

当前结果：**26 passed, 0 failed**。其中同步引擎核心 18 项、HTTP 传输适配器 8 项。

测试覆盖有效安装、manifest/内容篡改、失败回滚、离线、强制/推荐与推荐转强制、
漂移、路径穿越、未知 key、符号链接、坏缓存、release 冲突、并发锁、Secret 不落状态、
最低版本、超大 manifest、状态写入失败报告一致性、重复资源、active 资源重新验签和
同步周期上限。测试只使用
临时目录和内存/Fetch Mock，不访问真实用户目录或网络。传输测试覆盖凭证签发、401 重签、
304 缓存、超时、响应体上限、报告字段白名单和错误保持。

详细契约、状态 schema、事务和未实现边界见 [DESIGN.md](DESIGN.md)。
