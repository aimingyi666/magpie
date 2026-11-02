# Magpie Enterprise client sync

状态：**M3-C 客户端同步核心已实现并通过 16 项单元/Mock 测试；尚未接入员工端
OIDC/设备短期同步凭证 API、管理台资源/漂移页、浏览器/helper 产品入口、Windows ACL、
MDM、目标 Agent 文件映射和企业生产验收。M3-D 与 M4-M6 仍未实现。**

这个包提供本机 Magpie/helper 所需的企业资源同步核心：

- 拉取一份完整 desired state。
- 固定 Ed25519 公钥和 SPKI 指纹。
- 校验 manifest schema、digest、签名、内容长度和 SHA-256。
- 先 staging、后原子激活；新版本失败保留上一版本。
- 强制/推荐资源策略、离线缓存、漂移检测和稳定错误码。
- 进程锁、路径穿越/符号链接拒绝、`0600` 状态和秘密不落状态。

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

## 传输适配器要求

当前仓库还没有员工设备可用的资源同步 API，因此包只冻结了适配器契约：

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

当前结果：**16 passed, 0 failed**。

测试覆盖有效安装、manifest/内容篡改、失败回滚、离线、强制/推荐与推荐转强制、
漂移、路径穿越、未知 key、符号链接、坏缓存、release 冲突、并发锁、Secret 不落状态、
最低版本、超大 manifest、状态写入失败报告一致性、重复资源和同步周期上限。测试只使用
临时目录和内存适配器，不访问真实用户目录或网络。

详细契约、状态 schema、事务和未实现边界见 [DESIGN.md](DESIGN.md)。
