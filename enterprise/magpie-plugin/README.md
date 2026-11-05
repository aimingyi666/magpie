# Magpie Enterprise 企业页

这个插件在 Magpie 侧边栏增加「企业」页，包含「员工」和「管理员」两个视图。
员工电脑和管理员电脑仍然使用同一份 Magpie，**不需要安装单独的企业定制版
客户端**。插件里的本地回环服务负责状态、同步和管理员会话，页面本身不直接
持有企业令牌或供应商 Key。

## 员工视图

- 查看设备是否已加入企业，以及设备名、网关、凭据到期时间。
- 查看最近一次资源同步、最后成功时间、错误码和资源列表。
- 查看每个资源的强制/推荐策略，以及已安装、已变更、缺失、已关闭、已不再分配状态。
- 点击「立即同步」，在本机执行一次已有的 `enterprise/client-sync` 同步。

资源名称优先取已安装 release 的 `metadata.json`（`title`、`displayName`、`name`），
没有时取正文第一个一级标题，再没有才显示资源 ID；ID 仍保留在名称下方用于排障。

## 管理员视图

管理员视图不嵌入 `admin-service` 的网页，而是调用插件本地服务，再由本地服务
访问远程管理服务。首期覆盖：

- 运行总览：网关状态、供应商/路由组/Gateway Key 数量、近期请求。
- 供应商：卡片式列表，新增、编辑、删除；预设、API Key、自定义 Base URL、模型列表和启停。
  卡片下列出每个 Key 的名称、掩码、协议、权重、计划、首要/启停/休息状态；可新增多个
  Key、启用/停用、设为首要、轮换和删除。
- 路由：路由组增删改，成员顺序、规则、权重、亲和性和 fallback；每个成员显示实时
  在线/停用/休息状态。
- 网关：网关地址与模型目录、Gateway Key 列表、新增、轮换、删除、额度、模型白名单和启停，
  以及按管理员组织范围过滤的员工设备（只读）。
- 用量与请求详情：按 `usage.jsonl` / usage ledger 查询历史；实时 trace 只用于当前请求详情。

管理员点击「登录」后：

1. 本机服务生成 `state`、PKCE verifier/challenge 和 nonce。
2. 系统浏览器打开 `admin-service` 现有的管理 OIDC/MFA 流程。
3. `admin-service` 回调本机回环地址，只交回一次性 ticket。
4. 本机服务用 ticket + PKCE verifier 换取短期桌面管理员 token。

管理 Cookie、OIDC secret、桌面 token、网关管理 token 和供应商 Key 都不进入页面。
桌面 token 最长 8 小时、空闲 30 分钟失效，退出即撤销。原生页未迁移的用户、组织、
设备、审批、审计等治理页仍从「打开网页管理台」进入；新标签页打开，不使用 iframe。

供应商 Key 只存在企业网关。员工机、本机服务和浏览器只转发或展示掩码，不保存
供应商 Key。网关写操作要求 `expectedRevision`（或 `If-Match`），供应商/路由/Gateway
Key 的删除、轮换和额度/白名单变更还需要 `admin-service` 的审批；原生页会提示
`approvalId` 需求，审批中心仍在网页管理台。

资源发布、回滚、审批中心、用户与组织、设备管理、审计导出仍归 `admin-service` /
`resource-service` 的网页管理台。加入企业仍由
`enterprise/scripts/join-enterprise.ps1` 完成。

## 安装

从仓库目录安装（Magpie 会把该路径作为插件目录，不复制它）：

```powershell
magpie plugin add .\enterprise\magpie-plugin
```

也可以在 Magpie 的 Plugins 页面从文件夹添加。插件默认在
`127.0.0.1:3477` 启动本地服务，可在插件设置里用 `port` 选项改端口。
改端口时，必须把同一个端口加入 `admin-service` 的
`ADMIN_DESKTOP_CALLBACK_PORTS`，否则浏览器登录回调会被拒绝。

安装后打开侧边栏的「企业」页。页面本身只负责导航；真正的状态与同步界面由
插件宿主启动的本地服务提供。

## 配置

`enterprise-sync.json` 和企业设备凭据放在同一个状态目录：

- Windows：`%LOCALAPPDATA%\MagpieEnterprise`
- 其他系统：`~/.local/state/magpie-enterprise`

凭据由 `join-enterprise.ps1` 写入，文件名形如
`<providerId>-device.json`。不要手工把设备令牌或私钥放进插件目录。

`enterprise-sync.json` 示例：

```json
{
  "resourceBaseUrl": "https://resource.ai.corp.example",
  "rootDir": "./resources",
  "clientVersion": "enterprise-1.0.0",
  "displayNames": {
    "res_ade68d3335e1464182f2fb769f6906e1": "研发知识库 MCP"
  },
  "signingKeys": {
    "resource-2026-11": {
      "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "fingerprint": "sha256:..."
    }
  }
}
```

字段说明：

- `resourceBaseUrl`：员工设备访问的 resource-service 地址。
- `signingKeys`：设备固定信任的 Ed25519 公钥，不能从服务端临时学习。
- `rootDir`：资源落盘目录，相对路径以状态目录为基准，默认 `resources`。
- `clientVersion`：同步时上报的客户端版本；缺省用设备凭据里的版本。
- `maxResourceBytes`：单资源上限，默认 4 MiB。
- `displayNames`：可选的 `resourceId` → 显示名覆盖。优先级高于 release 的
  `metadata.json` 和正文标题。当前 desired-state 协议只带资源 ID 和签名 manifest，
  不带管理端的资源名称，所以企业可用加入脚本/MDM 下发这个映射；后续可改为在签名
  manifest 里携带 `title`。
- `clientSyncModule`：同步核心的路径。相对路径以状态目录为基准。通常不需要设置：
  从仓库安装时插件会使用相邻的 `enterprise/client-sync`。

管理员模式还需要管理服务地址，按以下顺序查找，取第一个安全地址：

- 环境变量 `MAGPIE_ENTERPRISE_ADMIN_URL`；
- `enterprise-sync.json` 的 `adminBaseUrl`；
- 已加入设备凭据里的 `adminUrl`。

只接受 `https://`，或本机回环的 `http://127.0.0.1` / `http://localhost`。
不会猜测地址，避免把管理员 token 发给错误主机。

未配置时，管理员页会直接显示地址输入框；保存后写入 `enterprise-sync.json` 的
`adminBaseUrl`，本机服务立即生效，不需要重启 Magpie。

如果只把插件文件夹复制到员工机，请把 `client-sync` 一起放到部署目录，
并在 `enterprise-sync.json` 中用绝对路径设置 `clientSyncModule`。

## 行为

页面打开时读取一次状态，之后每 10 秒刷新。点击「立即同步」会调用
`ClientSyncEngine.syncOnce()`，并在完成后重新读取 `state.json`。

- 未加入企业：显示加入提示，同步按钮不可用。
- 未配置 `enterprise-sync.json`：显示配置提示，同步按钮不可用。
- 控制面不可达：保留最后验签版本，页面显示离线错误。
- 同一进程重复点击：第二次返回 `sync_busy`，不会并发改状态。
- 同步成功但结果上报失败：资源仍算已同步，页面单独提示上报失败。

这一版没有后台定时资源同步；加入脚本安装的计划任务只刷新短期网关 Key。
需要定时资源同步时，由后续的本地 helper/服务承载。

## 安全边界

- 服务只监听 `127.0.0.1`，并校验 `Host` 属于本机回环名称。
- 页面从本地服务取得本次运行的访问令牌；`/v1/status` 和 `/v1/sync` 都要求该令牌。
- 管理员接口同样要求页面令牌；本地服务只调用固定的管理 API 路径，页面不能构造任意上游 URL。
- 管理员登录回调只接受回环地址和配置允许的端口，一次性 ticket 由 PKCE 换取。
- `Origin` 只接受插件沙箱页面的 `null`、同一回环端口的页面，或没有 `Origin`
  的导航/同源请求；其他站点来源拒绝。
- 页面上的状态不包含设备令牌、私钥、供应商 Key、网关管理 token、桌面 token 或绝对路径。
- 在 `magpie web` 中通过 Magpie 的插件服务代理访问，不把 `127.0.0.1`
  误当成服务器。

## 测试

```powershell
node --check enterprise\magpie-plugin\page\ui.js
node --test enterprise\magpie-plugin\test\*.test.mjs
node --test enterprise\client-sync\test\*.test.mjs
```

插件测试只使用临时目录和本机回环服务；同步并发测试使用本地 fake 模块，
管理员测试用本地 mock 管理服务验证 PKCE、失败关闭和路由白名单，不会访问真实控制面。
