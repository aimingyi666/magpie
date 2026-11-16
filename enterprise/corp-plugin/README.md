# Magpie Corp Plugin

企业内部客户端插件：员工用飞书 OIDC 登录一次，插件把企业网关变成 magpie 的一个 provider，
把公司规定的指令 / MCP / 技能写进资源库，并把用量、脱敏统计回传服务端。

服务端由你自己实现，接口契约见 [`../../devtools/corp-plugin-protocol.md`](../../devtools/corp-plugin-protocol.md)。

## 它做什么

| 职责 | 机制 | 落到哪里 |
| --- | --- | --- |
| 发起认证 | 插件 `auth` 钩子 + 系统浏览器 OIDC PKCE + 本机回环回调 | `device.json`（0600），同时作为网关 API Key 交给 magpie |
| 下拉供应商 | 插件 `config` / `provider.models` 钩子 | magpie 的 provider 列表，不动 `providers.json`；插件关掉即消失 |
| 下拉资源库 | `magpie library` CLI + 写 `library/skills/` | 每个 Agent 自己的配置文件 |
| 安装企业指定插件 | bundle 的 `plugins` → `magpie plugin add/on` + `magpie <agent> <model>` | magpie 的插件目录与 agent 自己的配置 |
| 上传用量 | 读 `{configDir}/usage.jsonl` | 只读，游标推进在 `state.json` |
| 上传脱敏统计 | 读 `{configDir}/masking/*.jsonl` | 只读；magpie 本来就只记占位符、类型、长度 |
| 上传会话 | 由用量行按 `session` 聚合 | 只有轮数、模型、token，没有正文 |

**不读 Agent 的对话记录。** 会话信息全部来自 magpie 自己的用量账本，所以插件不需要解析
Claude Code / Codex 的 transcript。

## 安装

```powershell
magpie plugin add .\enterprise\corp-plugin
```

然后在插件设置里填服务端地址（或设置环境变量 `MAGPIE_CORP_URL`）：

```powershell
$env:MAGPIE_CORP_URL = "https://ai.corp.example"
```

**建议 MDM 同时设置 `MAGPIE_BIN` 指向 magpie.exe**：资源库落地要用 CLI，插件默认只在
`PATH` 里找 `magpie`，找不到时只有资源库那一项会失败（认证、供应商、上传都不受影响）。

### MDM / 软件中心一键接入

员工机上的目标是：**装好后只点 Sign in**，不跑 PowerShell、不手填地址。

```powershell
# 由 Intune / 软件中心 / 开机脚本以当前用户执行
.\enterprise\scripts\install-corp-plugin.ps1 `
  -CorpUrl "https://control.corp.example" `
  -Magpie "C:\Program Files\Magpie\magpie.exe" `
  -PluginPath "C:\Program Files\Magpie\plugins\corp-plugin"
```

脚本会：

1. 设置用户环境变量 `MAGPIE_CORP_URL`、`MAGPIE_BIN`（加 `-MachineEnv` 则写机器级）
2. 写入 `%LOCALAPPDATA%\MagpieCorp\corp.json`
3. 执行 `magpie plugin add` 并写入插件 options

**不会**替员工完成 OIDC 登录，也**不会**立刻改供应商/资源库；登录并 Sync 后才落地。

推荐分发内容：

| 内容 | 放哪 |
| --- | --- |
| magpie.exe | 固定路径，例如 `C:\Program Files\Magpie\` |
| `enterprise/corp-plugin/` | 同上 `plugins\corp-plugin\` |
| `install-corp-plugin.ps1` | 软件中心静默安装命令 |

验收：员工打开 magpie → 侧边栏「企业」已有服务端地址 → Sign in → Sync now 后看到 Providers / Instructions / MCP / Skills。

## 使用流程

1. 打开侧边栏「企业」页 → **Sign in**（或在 Providers 里给 `corp` 点登录）。
2. 浏览器完成飞书登录，回调到 `127.0.0.1:3488/oidc/callback`。
3. 服务端返回设备令牌，magpie 把它作为 `corp` 这个 provider 的 Key 保存。
4. 页面点 **Sync now**，拉下供应商和资源库，回传用量。

之后每 5 分钟自动同步一次；网络不通时继续用上一次的 bundle。

## 企业指定安装的插件

服务端可以在 bundle 里给**部分人**下发 `plugins`（见协议 3.3）。目前客户端只认一个：

| id | 包 | 作用 |
| --- | --- | --- |
| `cursor-bridge` | `magpie-agent-cursor-bridge` | 把 Cursor 接到本机 magpie 网关，再经 `corp` provider 走企业网关 |

同步时插件会：

1. 读 `{configDir}/plugins.json`，没装就 `magpie plugin add`，装但关了就跑 `magpie plugin on`；
2. 读 `~/.config/magpie-cursor-bridge/connection.json`，模型不一致就 `magpie cursor-bridge <model>`；
3. 企业撤回策略后执行 `magpie cursor-bridge default` 让 Cursor 回到自己的设置，**不卸载**插件。

安全边界：`spec` 写死在插件里，服务端只能从白名单里选 `id`，**不能**指定要安装的包，
所以被篡改的 bundle 不能在员工机上执行任意代码。页面上的「推荐安装的插件」显示企业要求的
插件与是否已落地（`state.json` 的 `appliedPlugins`）。

## 页面：登录、概览、个人信息、管理员

插件页是四个独立地址，共用同一个回环服务：

- `/login` — **登录页**。本机还没有可用设备时，其他页面都会跳到这里。填写企业服务端地址、
  「使用企业账号登录」（在系统浏览器打开飞书 / 企业 SSO）和演示登录（成员 / 管理员）都在这一页；登录发起后
 页面每 2 秒问一次状态，拿到可用设备就自动回到 `/`。已登录时访问会跳回概览，只有
  `/login?renew=1` 留在登录页做续期。
- `/` — **概览**。账号摘要（链接到个人信息）、企业网关、同步、供应商、分享来源、
  共享 WorkBuddy，以及推荐安装的插件和企业资源。操作有「立即同步」「重新登录」。
- `/me` — **个人信息**。当前账号的姓名、邮箱、部门、角色与分组；设备 ID、登录时间与状态；
  凭据的到期与续期时间；企业网关地址与模型数；同步与上传状态；企业资源；本人共享的
  WorkBuddy 账号。页面不显示凭据本身。
- `/admin` — **管理员视图**（下一节）。

所有页面都拿不到设备令牌，请求经本机服务转发。

页面跟随 magpie 的外观：插件 frame 打开时把窗口的浅色 / 深色写在 `?theme=` 上，页面记住它，
之后在 `/`、`/me`、`/admin` 之间切换也保持一致；直接用浏览器打开、没有这个参数时，按系统的
浅色 / 深色显示。样式取自 magpie 自己的色板与行列表（`internal/gui/assets/app.css`），插件页
看起来与 magpie 的供应商列表是同一套界面。

「概览」页还有一张「共享 WorkBuddy」卡片：选国内版或国际版后，本机服务请企业服务端向网关
发起一次 WorkBuddy 扫码登录，再由本机服务交给本机默认浏览器打开插件的登录页
（腾讯/WorkBuddy 页面上自己显示二维码）。magpie 给插件页的沙箱 frame 不能自己开新标签，
所以窗口打不开时页面会直接给出可点击选中的登录页地址。页面每 2 秒问一次状态，登录完成后
显示「已导入企业供应商：\<账号\>」和导入的模型，并自动同步一次；模型要等管理员在管理员页
勾选下发后才会进企业目录。页面只拿到登录页 URL 与状态：token 由企业网关的插件持有，本机
服务与页面都不接触。

卡片还会读本机 magpie 的 `plugin-auth.json`，把已经登录的 WorkBuddy 账号列出来
（例如「138\*\*\*\*1234」），每个账号旁有「导入」：点它会把这份登录直接交给企业网关，
不必再扫一次。确认框写明导入后本机 magpie 会退出这个账号（随时可以重新登录）；网关
收下之后本机服务才退出，失败则本机登录保持不动。账号名会随 `GET /v1/status` 出现，
token 只在本机服务发往企业网关的那一次请求里，页面拿不到。

**管理员**视图在服务端确认登录人是管理员后才读取本机 magpie：

- **本机 magpie 供应商**：读 `{MAGPIE_CONFIG_DIR}/providers.json`，列出名称、模型数、
  Key 数与掩码后的 Key。勾选后「分享选中」会把供应商端点、模型和 Key 交给企业服务端；
  服务端再把它们写进企业网关。Key 只在本机服务与企业网关之间传递，**不会出现在页面 HTML
  或 JSON 里**。
- **以 Remote magpie 分享**：企业网关本身就是一台 magpie 时，不搬运供应商 Key，只发布
  网关的模型列表。可手填逗号分隔的模型，留空则从网关读取。
- **停止分享**：清空企业下发的供应商；已经写进网关的、由本插件发起的供应商会被删除。
- **领取密钥的人员**：列出每个员工、设备与网关 caller key。管理员可以给每条 Key 设置
  模型白名单（逗号分隔，留空 = 全部）、只读、停用，以及按天 / 周 / 月 / 滚动小时 / 滚动天
  的 Token 或费用额度。保存时服务端带上网关返回的 `revision`，冲突会失败而不是覆盖。
- **本机 magpie 网关密钥**：只读预览本机 `caller-keys.json` 的名称、掩码、模型和额度，
  便于核对。
- **员工共享的 WorkBuddy**：列出员工扫码后导入企业网关的账号，勾选要下发给全公司的模型，
  「下发选中」后发布新 revision。没勾选的不进企业目录；分享模式为 `off` 时只保存勾选，
  等开启分享后生效。

管理员身份由服务端判定：IdP 的 `groups` 命中 `CORP_ADMIN_GROUPS`（默认
`corp-admins,magpie-admins,admins`），或邮箱在 `CORP_ADMIN_EMAILS` 里；演示登录时可用
`CORP_DEMO_ADMIN=true`。普通成员的设备令牌访问管理员接口会被拒绝（403
`forbidden_admin`）。

管理员视图读取的是**运行插件这台机器**的 magpie 配置。把插件装在员工机上，员工看不到
别人的供应商；把插件装在管理员机上，管理员才能分享本机供应商。

## 配置

`%LOCALAPPDATA%\MagpieCorp`（Windows）或 `~/.local/state/magpie-corp`（其它系统），
可用 `MAGPIE_CORP_DIR` 改：

```text
corp.json      服务端地址、OIDC 参数、上传开关（页面配置后自动写入）
device.json    设备令牌，0600，绝不进插件目录
state.json     bundle revision、上传游标、已应用的插件、上次错误
bundle.json    服务端下发的供应商、资源与插件快照
```

插件选项：

| 选项 | 默认 | 说明 |
| --- | --- | --- |
| `port` | 3488 | 本机服务端口，改端口要同时改回调地址 |
| `baseUrl` | 空 | 服务端地址；也可用 `MAGPIE_CORP_URL` |
| `provider` | `corp` | provider id，改了等于换一个 provider |

## 安全边界

- 服务只监听 `127.0.0.1`，校验 `Host`；`/v1/*` 要求本次运行随机生成的页面令牌。
- 页面拿不到设备令牌，也拿不到 `MAGPIE_BIN`、绝对路径或任何凭据。
- WorkBuddy 扫码共享只经过登录页 URL 与状态：服务端不保存 token，页面也拿不到 token；
  员工只能读自己设备发起的共享，别人的 share id 在本机服务与企业服务端都是 404。
- 「导入本机账号」是唯一的例外：本机服务读 `plugin-auth.json` 里的那一条登录，只发往
  企业网关的 `plugin-import`，页面与状态接口都看不到 token；网关收下后本机退出该账号，
  避免同一个 token 在两处续期。
- 管理员视图的供应商 Key 由本机服务直接发往企业服务端，页面只能看到掩码；服务端把它们
  写进网关后不写进自己的状态文件。
- 上传字段是白名单：模型、token、耗时、状态码、session id、脱敏占位符。
  **永不发送**提示词、回复、Cookie、Authorization、真实 Key、厂商账号邮箱、原始 IP。
- 服务端地址只接受 `https://` 或回环 `http://`；不跟随重定向。
- 服务端 revision 比本地旧时拒绝应用，避免被降级到不安全的旧资源。

## 测试

```powershell
node --check enterprise\corp-plugin\index.js
node --test enterprise\corp-plugin\test\core.test.mjs
node --test enterprise\corp-plugin\test\service.test.mjs
node --test enterprise\corp-plugin\test\plugins.test.mjs
```

测试只使用临时目录和本机回环服务，不访问任何网络。直接 `node --test test/*.test.mjs`
在受限环境里可能因 `spawn EPERM` 失败，用上面的逐文件命令。

## 已知边界

- 首次登录后要**重启 magpie** 或重新开关插件，`corp` 才会带上模型列表：`config` 钩子只在
  插件宿主加载时跑一次，第一次同步时还没有 bundle。之后新增模型不需要重启
  （`provider.models` 每次列模型都会问）。
- 资源库落地依赖 `magpie` 可执行文件；找不到时页面会显示 `config_dir_unknown` /
  `magpie_unavailable`，其它三项照常工作。
- 没有后台服务/计划任务：同步由插件宿主进程驱动，magpie 退出就停。
