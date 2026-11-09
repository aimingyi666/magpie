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

## 使用流程

1. 打开侧边栏「企业」页 → **Sign in**（或在 Providers 里给 `corp` 点登录）。
2. 浏览器完成飞书登录，回调到 `127.0.0.1:3488/oidc/callback`。
3. 服务端返回设备令牌，magpie 把它作为 `corp` 这个 provider 的 Key 保存。
4. 页面点 **Sync now**，拉下供应商和资源库，回传用量。

之后每 5 分钟自动同步一次；网络不通时继续用上一次的 bundle。

## 配置

`%LOCALAPPDATA%\MagpieCorp`（Windows）或 `~/.local/state/magpie-corp`（其它系统），
可用 `MAGPIE_CORP_DIR` 改：

```text
corp.json      服务端地址、OIDC 参数、上传开关（页面配置后自动写入）
device.json    设备令牌，0600，绝不进插件目录
state.json     bundle revision、上传游标、上次错误
bundle.json    服务端下发的供应商与资源快照
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
- 上传字段是白名单：模型、token、耗时、状态码、session id、脱敏占位符。
  **永不发送**提示词、回复、Cookie、Authorization、真实 Key、厂商账号邮箱、原始 IP。
- 服务端地址只接受 `https://` 或回环 `http://`；不跟随重定向。
- 服务端 revision 比本地旧时拒绝应用，避免被降级到不安全的旧资源。

## 测试

```powershell
node --check enterprise\corp-plugin\index.js
node --test enterprise\corp-plugin\test\core.test.mjs
node --test enterprise\corp-plugin\test\service.test.mjs
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
