# Magpie Enterprise Auth

独立的企业身份与设备服务，负责：

- OIDC Authorization Code + PKCE 登录。
- 把浏览器登录结果转换为一次性加入码。
- 注册设备并绑定设备公钥。
- 通过 Magpie issuer API 签发短期网关 Key。
- 设备心跳、Key 刷新、设备/用户停用和撤销队列。
- 保存不含 Key 明文的凭证元数据，供管理服务做用户/设备/凭证治理。
- 提供仅限服务间调用的内部写接口，支持停用/启用用户、吊销设备和轮换当前凭证。
- 保存用户级模型与额度策略，提供首次初始化、乐观锁、失败关闭和逐凭证回读确认。

这个服务不修改 Magpie 上游核心，员工机上的 Magpie 仍然负责 Provider 写入和 Agent 一键配置。

## 前置条件

1. 一个支持 OIDC 的企业 IdP，并登记回调地址：
   `AUTH_PUBLIC_URL/oauth/callback`。
2. 一个已启动的 Magpie 企业网关。
3. 在网关创建专用 issuer Key，并开启签发权限：

```powershell
magpie gateway-key add enterprise-auth
# 使用输出的 Key，在网关执行：
magpie gateway-key issuer <issuer-id> on
```

4. 为认证服务生成互相独立的高熵值：

```text
AUTH_COOKIE_SECRET
AUTH_ADMIN_TOKEN
AUTH_INTERNAL_ADMIN_TOKEN
MAGPIE_ISSUER_KEY
```

不要把 `MAGPIE_ISSUER_KEY` 当成员工 Key，也不要把它放进 Git、日志或员工电脑。
`AUTH_INTERNAL_ADMIN_TOKEN` 只供 `admin-service` 在内网调用内部读写接口，必须不同于
`AUTH_ADMIN_TOKEN`，不能进入浏览器、日志、前端构建产物或员工电脑。

## 配置

从 [`../.env.example`](../.env.example) 复制模板，至少设置：

```dotenv
AUTH_PUBLIC_URL=https://auth.ai.corp.example
AUTH_SECURE_COOKIE=true
AUTH_COOKIE_SECRET=<独立随机值>
AUTH_ADMIN_TOKEN=<独立随机值>
AUTH_INTERNAL_ADMIN_TOKEN=<独立随机值；与 admin-service 共享>

OIDC_ISSUER=https://<idp>/.well-known/openid-configuration 的 issuer
OIDC_CLIENT_ID=magpie-enterprise
OIDC_CLIENT_SECRET=<IdP 客户端密钥>
OIDC_REDIRECT_URI=https://auth.ai.corp.example/oauth/callback
OIDC_ALLOWED_EMAIL_DOMAINS=corp.example

MAGPIE_GATEWAY_URL=http://gateway:3425
MAGPIE_GATEWAY_PUBLIC_URL=https://ai.corp.example
MAGPIE_ISSUER_KEY=<网关 issuer Key>
MAGPIE_KEY_TTL=8h
MAGPIE_KEY_MODELS=deepseek/deepseek-chat
```

`MAGPIE_GATEWAY_URL` 是认证服务访问 Magpie 的内部地址；
`MAGPIE_GATEWAY_PUBLIC_URL` 是员工机收到的网关地址。两者不能混用。

## 启动

单独运行：

```powershell
$env:AUTH_COOKIE_SECRET = "..."
$env:AUTH_ADMIN_TOKEN = "..."
$env:AUTH_INTERNAL_ADMIN_TOKEN = "..."
$env:MAGPIE_ISSUER_KEY = "..."
$env:OIDC_ISSUER = "https://idp.example"
$env:OIDC_CLIENT_ID = "magpie-enterprise"
$env:OIDC_CLIENT_SECRET = "..."
$env:MAGPIE_GATEWAY_URL = "http://127.0.0.1:3425"
$env:MAGPIE_GATEWAY_PUBLIC_URL = "https://ai.corp.example"
node src/server.js
```

Compose：

```bash
cd enterprise
docker compose --profile auth up -d
docker compose ps
curl http://127.0.0.1:${AUTH_HOST_PORT:-3444}/healthz
```

## 员工加入流程

员工电脑需要先安装/运行 Magpie，然后执行：

```powershell
.\join-enterprise.ps1 `
  -AuthUrl https://auth.ai.corp.example `
  -Magpie magpie `
  -Agent claude `
  -AgentModel deepseek/deepseek-chat
```

脚本会：

1. 生成本机 RSA 设备密钥。
2. 启动 loopback callback，打开企业 OIDC 登录。
3. 用一次性加入码和 PKCE 换取设备令牌和短期网关 Key。
4. 在本地 Magpie 写入企业 Provider。
5. 可选择地调用 Magpie 原生 Agent 一键配置。
6. 在 Windows 默认注册每 30 分钟刷新一次的当前用户计划任务。

短期 Key 不打印；设备凭据写到当前用户 ACL 保护的本地文件。

## 当前 API

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/healthz` | 存活和基础计数 |
| GET | `/api/v1/internal/admin/status` | 管理服务专用；独立服务令牌，返回最小计数 |
| GET | `/api/v1/internal/admin/users` | 管理服务专用；用户元数据 |
| GET | `/api/v1/internal/admin/devices` | 管理服务专用；设备元数据 |
| GET | `/api/v1/internal/admin/credentials` | 管理服务专用；凭证元数据，不含 Key/hash |
| POST | `/api/v1/internal/admin/users/{id}/disable` | 管理服务专用；停用用户并撤销设备、会话和凭证 |
| POST | `/api/v1/internal/admin/users/{id}/enable` | 管理服务专用；恢复用户状态，不恢复旧设备或旧凭证 |
| POST | `/api/v1/internal/admin/devices/{id}/revoke` | 管理服务专用；吊销指定设备和该设备当前凭证 |
| POST | `/api/v1/internal/admin/credentials/{id}/rotate` | 管理服务专用；按设备串行轮换当前凭证 |
| PUT | `/api/v1/internal/admin/users/{id}/policy/quota` | 管理服务专用；设置 0-5 个额度窗口，要求 `expectedVersion`/`If-Match` |
| PATCH | `/api/v1/internal/admin/users/{id}/policy/models` | 管理服务专用；设置稳定模型白名单，要求 `expectedVersion`/`If-Match` |
| POST | `/api/v1/internal/admin/users/{id}/policy/confirm-credential` | 管理服务专用；提交 gateway-control 的独立回读并确认单张凭证已同步 |
| GET | `/login` | 发起 OIDC 登录 |
| GET | `/oauth/callback` | IdP 回调 |
| POST | `/api/v1/join/exchange` | 换取设备令牌和短期 Key |
| POST | `/api/v1/devices/heartbeat` | 设备心跳 |
| POST | `/api/v1/devices/refresh` | 刷新短期 Key |
| POST | `/api/v1/devices/revoke` | 吊销本设备 |
| GET | `/api/v1/me` | 当前网页会话 |
| POST | `/api/v1/logout` | 注销网页会话 |
| GET | `/api/v1/admin/users` | 最小管理接口 |
| GET | `/api/v1/admin/devices` | 最小管理接口 |
| POST | `/api/v1/admin/users/{id}/{disable\|enable}` | 停用/启用员工 |

上表的 `/api/v1/admin/*` 是 M1 最小接口，不是完整管理后台。M2-C1 已通过
`AUTH_INTERNAL_ADMIN_TOKEN` 提供内部写接口，M2-C2 已在 `admin-service` 提供四个对应的
受控对外写接口（管理会话、CSRF、RBAC、组织范围和必填理由已接入）。auth-service 的内部
接口仍只供 `admin-service` 在内网调用，不能直接暴露给浏览器，也不能把最小 admin token
接口当成生产管理后台。M2-C3 的幂等、`operationId` 和 intent/result 管理审计已在
`admin-service` 实现；auth-service 内部接口本身不承担管理会话、RBAC、幂等或管理审计，
这些能力统一由 `admin-service` 的 C2/C3 入口提供。C4-01 的网关机器协议已在 Magpie
工作分支实现并通过本地测试；C4-02 `gateway-control` 已实现并通过 15 项 Mock/故障测试，
但 Docker/真实共享卷、admin-service 接入和 mTLS 尚未验收。C4-03a 正式只读模型目录已在
`admin-service` 实现，并通过管理服务 31/31 测试，但 auth-service 尚未接入。C4-03b
已实现 auth-service 内的用户级策略状态机、M1 `unknown` 迁移、首次分步设置、版本冲突、
失败关闭和回读确认接口；C4-03c 的自动 apply、issuance journal 和同步后交付仍未实现。
C4-03d/C4-04、M2-C5 和 M2-D 仍未实现。完整契约见
[`../../devtools/enterprise-feature-spec.md`](../../devtools/enterprise-feature-spec.md) 第 12.8.1 节。

## M2-C4 策略状态（C4-03b 已实现核心状态机，C4-03c/C4-03d/C4-04 未实现）

auth-service 中的用户级 `gatewayPolicy` 是策略意图的唯一事实来源，不是
`caller-keys.json`：

```text
version
models[]
limits[]                 # 0-5 个窗口；空数组表示明确无额度上限
quotaStatus              # known|unknown|pending
modelStatus              # known|unknown|pending
updatedAt
confirmedAt
operationId
```

每张企业凭证还必须保存安全元数据：

```text
policyVersion
policySyncState          # pending|synced|failed
lastPolicyErrorCode
lastPolicySyncedAt
```

当前已经满足：

- 新用户默认策略为 `unknown`；旧 M1 用户和凭证迁移时也只得到 `unknown`，不会根据全局
  默认值反推历史额度或模型范围。
- quota 和 models 可以任意顺序首次设置；缺任意一项时 join、refresh 和 rotate 在调用
  `magpie.issue()` 前返回 `409 policy_setup_required`。
- 新签发、refresh 和 rotate 在调用 issuer 前检查 `known`；不满足时失败关闭，不签发
  Gateway Key。
- 设置策略使用单调递增的 `version`、`expectedVersion`/`If-Match` 和 `operationId`；
  stale version 返回 `409 policy_version_conflict`。
- `confirm-credential` 只接受固定字段白名单的 gateway-control 回读，要求 schema v1、
  安全 request ID、有效时间和 `policyRevision`，并逐项比较模型与额度内容是否与当前策略
  完全一致；不泄露 Key、token、Cookie 或服务令牌。
- 任一活跃凭证与当前策略版本不一致时，策略保持 `pending`，不得把管理写成功当作网关已
  生效。

仍待 C4-03c 完成：

- auth-service 尚未自动调用 `gateway-control`。当前 `confirm-credential` 是受控的服务间
  确认入口，不能替代真实的 apply/readback 编排。
- `known` 才允许正常签发；`pending` 时 join、refresh、rotate 返回
  `409 policy_sync_in_progress`。
- 当前实现可以安全支持“有模型、`limits=[]`（明确无额度窗口）且没有存量活跃凭证”的
  首次签发；非空额度窗口必须先经过 C4-03c 的 apply/readback 才能交付，因此现在会被
  `policy_sync_in_progress` 拒绝。
- 尚无 issuance journal、崩溃恢复、同步完成前禁止交付和孤儿 Key 对账。
- auth-service 不能直接读写 `caller-keys.json`。C4 通过独立 `gateway-control` 服务调用
  `magpie gateway-key describe <id> --json` 和原子
  `magpie gateway-key policy apply <id> --json`；服务间使用独立服务令牌或 mTLS，
  不复用 `AUTH_INTERNAL_ADMIN_TOKEN`、管理员 Cookie、issuer Key 或设备令牌。
- 适配器写入后必须再独立 `describe` 回读。全部活跃凭证回读一致才能提升为 `known`；
  部分失败返回 `partial_success` 并保持 `pending`，不能返回虚假成功。

C4-03 的具体门禁：

- **C4-03a（已完成管理服务部分）**：模型目录由只读 `ADMIN_MODEL_CATALOG_PATH` 提供，
  admin-service 已加载并安全投影；auth-service 尚未接入。接入后 auth-service 不接收
  group 表达式给网关，必须先按目录展开为稳定模型 ID。坏目录、未知引用或超 2 MiB 失败关闭。
- **C4-03b（已实现核心状态机与内部接口）**：旧 M1 凭证只迁移为 `quotaStatus=unknown`、
  `modelStatus=unknown`、
  `policyVersion=0`、`initializationSource=m1_unknown`，不得反推全局默认值。quota/models
  可任意顺序首次设置；缺项返回 `policy_setup_required`，两项完整且逐凭证回读后才 `known`。
- **C4-03c（未实现）**：join/refresh/rotate 的顺序固定为确认 `known` -> issuance journal -> 签发
  Key -> apply -> 独立 describe -> 原子持久化 -> 交付。同步完成前不能把 Key 返回客户端；
  任一步失败撤销新 Key，撤销失败保留 `pendingRevocations`，重启扫描不得留下孤儿 Key。
- **C4-03d（未实现）**：员工页和运营页消费上述真实状态；`unknown` 不显示 0/无限，`pending` 和
  `partial_success` 显示待同步凭证，`dependency_invoked` 禁止自动重试。员工网页不能直接
  修改设备上的 Agent 文件。

为接入 C4-03c，当前配置草案冻结新增：

```text
GATEWAY_CONTROL_URL
GATEWAY_CONTROL_TOKEN
GATEWAY_CONTROL_TIMEOUT_MS
```

当前 auth-service 已有用户级 `gatewayPolicy`、内部额度/模型写接口、M1 迁移和回读确认；
但仍没有 `gateway-control` 客户端调用、issuance journal、同步后交付、崩溃恢复扫描和
孤儿 Key 证明。启动只 drain 撤销队列，没有策略恢复。C4-01 的 `describe --json` 与原子
`policy apply --json` 已在 Magpie 工作分支实现；auth-service 到适配器的自动编排和真实
E2E 尚未实现。详细 schema、状态机和错误码见
[`../../devtools/enterprise-feature-spec.md`](../../devtools/enterprise-feature-spec.md) 第
12.8.1.1 至 12.8.1.6 节。

## 安全边界

- OIDC 使用 Authorization Code + PKCE，并校验 `iss`、`aud`、`exp`、`nonce` 和 JWT 签名。
- 设备令牌和网关 Key 在存储中只保留 SHA-256 哈希。
- 刷新采用“先签发新 Key，再原子更新设备，再把旧 Key 放入撤销队列”。
- 新 Key 未成功持久化时会立即撤销，避免留下孤儿 Key。
- 同一设备的刷新请求按 `device.id` 串行化；进入临界区后会重新读取并复核设备、用户、令牌
  和当前 Key 状态，避免并发请求产生多个活跃 Key。
- 如果员工或设备在刷新签发过程中被停用，持久化前复核会阻止提交，并立即撤销刚签发的新 Key。
- `AUTH_ADMIN_TOKEN` 只是 M1 最小管理接口，不是生产级 RBAC；M2 必须换成管理会话、角色、组织范围和操作审计。
- `AUTH_INTERNAL_ADMIN_TOKEN` 只用于服务间调用；内部读写接口不返回设备令牌、Gateway Key、
  token hash、公钥正文或 issuer Key，也不能复用浏览器 Cookie。轮换成功只返回新凭证 ID 和
  `awaiting_device_refresh`，新 Key 明文只通过设备刷新流程交付给目标设备。
- 凭证集合记录 Key ID、设备/用户、状态、签发/到期/撤销时间、模型范围以及公钥 SHA-256；
  Gateway Key 明文从未落库。
- 当前存储是单进程 JSON，适合试点，不适合多副本或大规模并发。
- 当前不采集对话正文；内容审计在 M4 设计。

## 测试

```powershell
& 'D:\Environment\node-v26.12.1\node.exe' `
  --test test/auth-service.test.mjs
```

测试使用临时目录和 Mock IdP/Mock Magpie，不会触碰真实网关数据。

当前结果：`18 passed, 0 failed`。覆盖 OIDC/JWT、PKCE、加入、心跳、刷新撤销、停用、
过期令牌、持久化回滚、同设备并发刷新、“刷新签发过程中停用员工”的交错场景、内部读写
接口的缺失令牌/错误令牌/正确服务令牌、停用后设备和凭证失效、启用不恢复旧凭据、设备吊销
隔离目标、凭证轮换旧 Key 撤销和持久化失败清理孤儿 Key、同设备并发轮换与刷新，以及旧
M1 store 的兼容加载。策略测试还覆盖 quota/models 两种首次设置顺序、缺项和
`magpie.issue()` 零调用、stale/`If-Match` 冲突、非对象 JSON、模型与额度边界、M1 迁移
幂等、`unknown/pending` 失败关闭及回读内容/字段/时间/版本校验。

真实 Magpie issuer 端到端测试（需要 Magpie 可执行文件）：

```powershell
& 'D:\Environment\PowerShell-7.6.6-win-x64\pwsh.exe' `
  -NoLogo -NoProfile -NonInteractive `
  -File test\auth-e2e.ps1 `
  -Magpie C:\path\to\magpie.exe `
  -Node D:\Environment\node-v26.12.1\node.exe
```

该脚本覆盖 issuer Key、OIDC 加入、员工调用、用量归属、刷新、停用和 auth 重启。访问网关时
必须使用非回环地址，否则 Magpie 会把回环请求当作免鉴权请求，无法验证旧 Key 是否被拒绝。
本地真实链路已全部通过；真实企业 IdP、Compose 健康检查和 Windows 计划任务仍未验收。
