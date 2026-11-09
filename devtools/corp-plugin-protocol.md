# Magpie 企业客户端插件协议（v1 草案）

状态：方案草案 v0.1，服务端 API 契约待与服务端实现联调确认

日期：2026-11-08

本文定义 **magpie 插件（客户端）** 与 **自建服务端** 之间的契约。插件负责四件事：
发起认证、下拉企业供应商、下拉资源库（固定指令 / MCP / 技能）、上传统计数据。
服务端由你实现，本文第 3 节就是它必须提供的接口。

前置条件（已具备，不再讨论）：MDM/软件中心可分发 magpie；飞书 OIDC 已接入内部 OIDC 平台。

## 1. 角色与边界

```text
员工电脑                                     你的服务端
┌───────────────────────────────┐            ┌──────────────────────┐
│ Agent ──→ magpie 本地网关      │            │ 认证/设备服务         │
│             └─→ 企业网关 ──────┼───────────→│ （OIDC 校验、发设备令牌）│
│                                │            │                      │
│ magpie 企业插件                │            │ 供应商/资源目录       │
│  ├─ 浏览器 OIDC 登录           │            │ 用量/会话/脱敏汇总     │
│  ├─ 写 provider 配置           │←───────────┤                      │
│  └─ 采集 usage/脱敏记录 ───────┼───────────→│                      │
└───────────────────────────────┘            └──────────────────────┘
```

三条硬边界：

1. **厂商 Key 不出服务端。** 插件下发的 provider 一律指向企业网关，模型请求由网关转发；
   `mode: "direct"`（直连 + 下发厂商 Key）仅在你明确接受"Key 落在员工机"时使用。
2. **插件不读 Agent 对话正文。** 会话信息只取自 magpie 自己的用量账本（已有 session id、
   agent、模型、token），不解析 Claude Code / Codex 的 transcript。需要正文审计时另立项目。
3. **页面不持有凭据。** 插件的沙箱页面通过本机回环服务拿状态；设备令牌只在本机服务和
   magpie 进程之间流动。

## 2. 认证：登录一次，拿到三样东西

插件用标准 OIDC Authorization Code + PKCE，走系统浏览器，回调打到插件自己的回环端口
（不依赖 `join-enterprise.ps1`，员工不需要 PowerShell）。

```text
插件                                 浏览器                 内部 OIDC(飞书)      你的服务端
 │── 生成 state+PKCE ──────────────────→ │                      │                    │
 │── 打开 authorize URL ───────────────→ │── 登录/MFA ─────────→│                    │
 │←────────── code (loopback) ──────────│                      │                    │
 │── POST /api/v1/device/enroll {idToken} ──────────────────────────────────────────→ │
 │←── {deviceId, deviceToken, expiresAt, gateway, bundleRevision} ───────────────────│
```

要点：

- **插件不直接换 token。** 插件把 OIDC 的 `code` + `codeVerifier` 交给你的服务端，由服务端
  向 IdP 换取 `id_token` 并校验（签名、`iss`、`aud`、`nonce`、`email` 域），再把
  `deviceToken` 发给它。这样 IdP 的 `client_secret` 永远不进员工电脑。
- **`deviceToken` 同时是网关 API Key。** 插件把它写进 provider 的 `apiKey`，企业网关校验它、
  映射到用户和额度。这样插件不需要第二套密钥轮换逻辑。
- 有效期建议 90 天，刷新用 `POST /api/v1/device/refresh`（见 3.2）。失效时插件把 provider
  标记为需要重新登录，不静默失败。

## 3. 服务端 API 契约

约定：

- 全部 `https://`，基址 `CORP_BASE_URL`；JSON；UTF-8；请求/响应都带 `schemaVersion: 1`。
- 认证：`Authorization: Bearer <deviceToken>`（除 3.1 外全部要求）。
- 错误信封统一：

```json
{ "error": { "code": "device_token_expired", "message": "…", "retryable": true } }
```

稳定错误码：`invalid_device_token`、`device_token_expired`、`device_disabled`、
`not_enrolled`、`rate_limited`、`payload_too_large`、`schema_unsupported`、
`service_unavailable`。插件只对 `retryable: true` 退避重试。

### 3.1 `GET /api/v1/corp/config`（无认证）

插件首次配置时读取，用于自动发现、减少手工填参数。

```json
{
  "schemaVersion": 1,
  "oidc": {
    "issuer": "https://sso.corp.example",
    "authorizationEndpoint": "https://sso.corp.example/oauth2/authorize",
    "clientId": "magpie-corp",
    "scopes": ["openid", "profile", "email"],
    "acrValues": "urn:mace:incommon:iap:silver"
  },
  "gateway": { "baseUrl": "https://ai.corp.example/v1" },
  "upload": { "usage": true, "masking": true, "sessions": true },
  "limits": { "maxBatchRows": 500, "maxBatchBytes": 1048576, "minUploadSeconds": 60 }
}
```

### 3.2 `POST /api/v1/device/enroll` 与 `/refresh`

**`deviceToken` 就是网关 Key，不是你自己造的令牌。** 服务端在 enroll 里必须：

```text
收 code → 向 IdP 换 id_token → 校验 → 在网关建一条 caller key（限定该人的模型与额度）
       → 把这条 key 的值作为 deviceToken 返回
```

做法有两种，选一种：

| 做法 | 接口 | 说明 |
| --- | --- | --- |
| 管理 API（推荐） | `POST /v1/magpie/admin/gateway/keys` | 需 `MAGPIE_ADMIN_TOKEN`，响应里的 `secret` 只返回一次 |
| 签发接口 | `POST /v1/magpie/keys` | 用 issuer Key 签发短期 Key，自带幂等（`enterpriseIssuanceId`），适合频繁续期 |

这样模型请求在网关侧就完成了鉴权与计量，**你的服务端不碰模型流量**，也不需要维护第二套令牌体系。
设备重复 enroll 时应撤销旧 Key——否则一份凭据可以无限复制到多台机器。

参考实现见 [`../enterprise/corp-server`](../enterprise/corp-server)，`issueDeviceKey()` 与
`revokeDeviceKey()` 就是这一段。

```jsonc
// enroll 请求
{
  "schemaVersion": 1,
  "code": "…",              // OIDC authorization code
  "codeVerifier": "…",      // PKCE
  "redirectUri": "http://127.0.0.1:3488/oidc/callback",
  "device": {
    "name": "AIMINGYI-PC",
    "platform": "windows",
    "clientVersion": "corp-plugin-1.0.0",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n…"  // 可选，设备指纹用
  }
}

// enroll / refresh 响应
{
  "schemaVersion": 1,
  "deviceId": "dev_…",
  "deviceToken": "…",          // 同时是网关 Key
  "expiresAt": "2027-02-06T00:00:00Z",
  "refreshAfter": "2026-12-01T00:00:00Z",
  "user": { "id": "usr_…", "email": "a@corp.example", "name": "…", "department": "研发中心" },
  "gateway": { "baseUrl": "https://ai.corp.example/v1", "models": ["corp/kimi-k2.5", "corp/glm-5.3"] },
  "bundleRevision": "rev_20261108_1",
  "policy": { "dailyTokens": 2000000, "monthlyCostUsd": 40 }
}

// refresh 请求：{"schemaVersion":1,"deviceToken":"…"}
```

### 3.3 `GET /api/v1/client/bundle?revision=<上次的>`

一次拿全：供应商、资源库、策略。`If-None-Match` 也接受，未变更返回 `304`。

```jsonc
{
  "schemaVersion": 1,
  "revision": "rev_20261108_1",
  "providers": [
    {
      "id": "corp",
      "name": "企业网关",
      "mode": "gateway",                 // gateway | direct
      "baseUrl": "https://ai.corp.example/v1",
      "npm": "@ai-sdk/openai-compatible",
      "models": ["kimi-k2.5", "glm-5.3"],
      "defaultModel": "corp/kimi-k2.5",
      "enabled": true
    }
  ],
  "instructions": [
    { "id": "ins_corp", "name": "公司规范", "content": "…markdown…", "agents": ["*"] }
  ],
  "mcp": [
    {
      "id": "mcp_kb", "name": "corp-kb", "transport": "http",
      "url": "https://mcp.corp.example/kb",
      "headers": {}, "agents": ["*"], "enabled": true
    }
  ],
  "skills": [
    {
      "id": "skill_report", "name": "corp-report", "version": "1.2.0",
      "files": [{ "path": "SKILL.md", "content": "…" }],
      "agents": ["*"], "enabled": true
    }
  ]
}
```

`agents` 用 magpie 的 agent id（`claude`、`codex`、`opencode`…），`["*"]` 表示全部。

### 3.4 上传（三条通道，独立开关、独立游标）

```jsonc
// POST /api/v1/telemetry/usage
{
  "schemaVersion": 1,
  "batchId": "uuid",                    // 幂等键：重发同一 batchId 必须不重复计费
  "deviceId": "dev_…",
  "cursor": { "from": "2026-11-08T00:00:00Z", "to": "2026-11-08T01:00:00Z" },
  "rows": [
    {
      "rowId": "sha256:…",              // 账本行的稳定哈希，服务端去重
      "at": "2026-11-08T00:31:12Z",
      "agent": "claude",
      "provider": "corp",
      "model": "kimi-k2.5",
      "kind": "chat",
      "sessionId": "s_…",               // 可空
      "input": 1200, "output": 340, "cacheRead": 800, "cacheWrite": 0,
      "cost": 0.0021,
      "status": 200, "ms": 1830,
      "error": ""                       // 只放错误码，不放正文
    }
  ]
}

// POST /api/v1/telemetry/sessions —— 可选；默认随 usage 批次一起发，见下
{ "schemaVersion":1, "batchId":"uuid",
  "sessions":[{ "sessionId":"s_…","agent":"claude","startedAt":"…","endedAt":"…",
                "turns":12,"models":["kimi-k2.5"],"input":12000,"output":3000 }] }

// POST /api/v1/telemetry/masking —— 只放"遮了几处、什么类型"，不放原值
{ "schemaVersion":1, "batchId":"uuid",
  "hits":[{ "at":"…","agent":"claude","provider":"corp","kind":"API_KEY",
            "placeholder":"{{API_KEY_k3v9x2mq}}","length":51,"head":"sk-abc" }] }
```

统一响应：

```json
{ "schemaVersion": 1, "accepted": 480, "duplicates": 20,
  "rejected": [{ "rowId": "sha256:…", "code": "unknown_model" }],
  "nextCursor": "2026-11-08T01:00:00Z" }
```

幂等与游标规则：

- 客户端只在**收到 2xx 后**推进游标；`rejected` 的行也推进（服务端已判定终态），
  否则会永远重发。`duplicates` 同样推进。
- `batchId` 由客户端按 `from|to|rowsHash` 派生，重试时不变。
- 服务端 `409 schema_unsupported` → 客户端停止上传并提示升级，不降级猜测。
- **会话随用量批次一起发**：`POST /api/v1/telemetry/usage` 的 body 还带一个
  `sessions` 数组（由该批 `rows` 按 `sessionId` 聚合而成：轮数、模型、token、错误数），
  服务端没有 session id 时直接忽略。单独的 `/telemetry/sessions` 是留给"只补会话、
  不重发用量"的场合，客户端 v1 不发。

## 4. 客户端本地状态

目录（与现有企业插件一致的做法）：

- Windows：`%LOCALAPPDATA%\MagpieCorp`
- macOS/Linux：`~/.local/state/magpie-corp`

```text
corp.json          # 服务端地址、OIDC 参数、开关（0600）
device.json        # deviceId/deviceToken/expiresAt（0600）
state.json         # bundle revision、上次同步、游标、错误
bundle/            # 服务端下发的资源缓存（按 revision 落盘，失败保留旧版本）
```

`device.json` 绝不进插件目录；插件目录只放代码。

## 5. 四件事在本机怎么落地

| 职责 | 机制 | 说明 |
| --- | --- | --- |
| 认证 | 插件 `auth` 钩子（`type: "api"`）+ 回环 PKCE | magpie 把 `deviceToken` 当普通 API Key 保存，签名/续期都由服务端负责 |
| 供应商 | 插件 `config` 钩子写 `config.provider.<id>` | 不动 `providers.json`，插件关掉配置自动消失；网关 `KeepFresh` 不需要重启 |
| 资源库 | 写 `{configDir}/library/`，再 `magpie library sync` | 指令 → `magpie library instructions set -`；MCP → `magpie library mcp add`；技能 → 写 `library/skills/<name>/` 后同步 |
| 上传 | 只读 `{configDir}/usage.jsonl` 与 `{configDir}/masking/*.jsonl` | 两者都是 magpie 自己的元数据账本，不含提示词正文 |

资源库落地需要 `magpie` 可执行文件：插件按 `MAGPIE_BIN` → `PATH` 里的 `magpie` 顺序查找。
**MDM 分发时请显式设置 `MAGPIE_BIN`**，这是唯一需要额外约定的一项。

## 6. 失败与降级

| 情况 | 行为 |
| --- | --- |
| 服务端不可达 | 继续用上一次的 bundle；供应商配置不变；上传退避重试（60s → 30min 封顶） |
| 令牌过期 | provider 标记 `needs_sign_in`，页面提示重新登录；不静默改用旧 Key |
| bundle revision 回退 | 拒绝应用，保留本地较新版本并上报冲突，避免被降级到不安全的旧资源 |
| 资源应用失败 | 保留旧版本，页面显示错误码；上传不受影响 |
| 上传被拒（schema） | 停止该通道，提示升级插件，不降级重试 |

## 7. 安全边界

- 插件服务只监听 `127.0.0.1`，校验 `Host`，要求本次运行随机生成的页面令牌。
- 页面拿不到 `deviceToken`、`MAGPIE_BIN` 路径、资源正文以外的任何凭据。
- 上传内容白名单：**模型、token 数、费用、耗时、状态码、session id、脱敏占位符**。
  永不发送：提示词、回复、Cookie、Authorization、真实 Key、原始 IP。
- 服务端地址只接受 `https://`，或显式允许的 `http://127.0.0.1`；不跟随重定向。

## 8. 实施顺序

1. **W1**：`GET /corp/config`、`POST /device/enroll`、`GET /client/bundle`（只有 providers）
   → 插件跑通"登录 + 下拉供应商"，这是最小可用闭环。
2. **W2**：`/telemetry/usage` + 客户端游标 → 后台能看到用量。
3. **W3**：资源库三条通道（指令 / MCP / 技能）+ 页面状态。
4. **W4**：`/telemetry/masking`、会话汇总、失败演练。

每一步都能独立上线，前一步不做完不影响后一步的联调。
