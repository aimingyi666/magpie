# 企业层（与核心仓库协同）

这个目录放企业部署需要的全部东西：网关部署、员工开通、客户端加入、验收测试。
企业业务逻辑主要位于独立服务；为提供机器可读的策略能力，C4-01 在
`internal/access/` 和 `internal/gateway/` 增加了 schema v1 的 Gateway Key
`describe`/`policy apply` 实现。这些核心改动必须继续遵守上游兼容性、测试和分支规则，
不能把整个企业层描述成“完全不改核心”。

## 目标形态

```text
员工电脑                                     企业内网
Agent → magpie(客户端，本地网关) ──→ magpie(服务端网关) ──→ 真实模型
        一键配置 Agent、本地转发            IP 白名单 + 网关密钥 + 用量统计
```

- 员工机上的 magpie 继续负责“一键配置 Agent”，但它只连内网网关。
- 企业网关（`magpie serve` 或 Docker）持有真实模型 Key，统一做访问控制、额度和用量统计。
- 客户端和服务端是同一份 magpie 二进制、不同的数据目录和配置，不需要改代码。

当前可用范围是 M0、M1、M2-A/M2-B、M2-C1/C2/C3 和 M2-C4-01/C4-02/C4-03a/C4-03b 核心，
以及 C4-03c 的管理 API、签发 journal、自动 apply/独立回读、同步后交付和启动补偿：
手工/OIDC 加入、短期 Key、设备注册与吊销、管理身份与只读治理、四个受控管理写 API、
管理额度/模型 API、持久化幂等、管理审计、schema v1 的网关策略机器回读/原子写入、
受控 `gateway-control` 适配器、正式只读模型目录，以及 auth-service 的用户级策略状态机。
`gateway-control` 已通过 15 项 Mock/故障测试；auth-service 已通过 21 项测试；
admin-service 已通过 34 项测试（27 项管理服务集成测试 + 7 项目录专项测试）。
`GET /api/v1/admin/models` 使用正式目录，由 admin-service 将 group/provider 选择器展开为
稳定模型 ID 后再交给 auth-service。C4-03d 仅部分实现：管理页已展示策略版本和凭证同步
状态，但没有写按钮、完整员工门户、operation/audit 查询或人工对账。Docker/Compose
实机构建、启动和健康检查，真实共享卷、真实企业 IdP、浏览器、反向代理、Windows
计划任务和 mTLS 尚未验收；C4-04 真实 Magpie 限额/模型拒绝/多凭证行为 E2E、M2-C5、
M2-D 和 M3-M6 仍未实现。当前不是生产就绪版本。

## M2-C4 目标边界（C4-01/C4-02/C4-03a/C4-03b/C4-03c 核心已实现，C4-03d 部分实现，C4-04 未实现）

用户级额度与模型授权不能由管理服务直接改写 `caller-keys.json`，也不能把页面写入或人类
可读 CLI 输出当成真实生效。C4 的固定链路是：

```text
admin-service
  -> auth-service（用户级 gatewayPolicy、版本、operation、issuance journal）
  -> gateway-control（独立服务令牌或 mTLS）
  -> magpie gateway-key describe/policy apply（固定 argv，无 shell）
  -> 专用 XDG_CONFIG_HOME + caller-keys.json
  -> 独立 describe 回读
  -> 原子持久化凭证
  -> 交付 Key
```

企业 Magpie fork 的当前工作分支已提供两个 schema v1 的机器契约，并通过 Go 单测、CLI 回归
和隔离真实二进制冒烟测试：

```text
magpie gateway-key describe <id> --json
magpie gateway-key policy apply <id> --json
```

`describe` 只读，输出安全 Key 状态、模型 patterns、0-5 个额度窗口、账户范围摘要和
`policyRevision`，不得输出 Gateway Key、masked key、token hash、账户 ID、设备令牌或
Secret。`policy apply` 从 stdin 接收 JSON，在**同一次文件锁**内校验
`expectedPolicyRevision`、校验模型/额度并原子替换，冲突时不写文件；默认 64 KiB 输入输出
上限。写入后还必须独立执行一次 `describe`，只有回读一致且真实请求行为符合策略，才能把
`gatewayPolicy` 标为 `known`；真实请求是否按限额和模型白名单拒绝仍由 C4-04 验收。

`gateway-control` 已实现在 [`gateway-control/`](gateway-control/)：只允许 describe/apply/
健康检查，使用专用非 root 账号、固定 `GATEWAY_CONTROL_CONFIG_HOME`、默认 10 秒子进程
超时和 64 KiB 请求/输出上限，不映射公网端口、不访问 Docker socket、不读取 issuer Key、
OIDC Secret、设备令牌或管理员会话。它使用独立 Bearer 服务令牌，不复用管理员 Cookie
或其他内部令牌；**当前不是 mTLS**，mTLS/SPIFFE 仍属于生产加固项。Dockerfile 和 Compose
`gateway-control` profile 已存在，但当前机器没有 Docker CLI，尚未实际构建、启动或做健康
检查。适配器必须调用上述两个机器命令，不能解析人类可读 CLI 文本，也不能直接读写
`caller-keys.json`。admin-service 已接入 auth-service，auth-service 已自动调用
`gateway-control`，并只在 apply、独立回读和原子持久化全部成功后才向客户端交付 Key。

管理 API 为：

```text
PUT   /api/v1/admin/users/{id}/policy/quota     # quota.write
PATCH /api/v1/admin/users/{id}/policy/models    # models.write
```

接口必须带 `expectedVersion`（或一致的 `If-Match`）、规范化额度/模型 payload 指纹、
`Idempotency-Key`、intent/result 审计和稳定状态机。`limits=[]` 表示明确无额度上限；
`models=[]`、裸 `*`、显示名和未知模型必须拒绝。部分凭证失败时返回
`partial_success` 并保持 `pending`；全部失败或超时返回 `502 dependency_unavailable`；
result 审计失败返回 `503 audit_unavailable`，operation 停留在 `dependency_invoked`。

C4-03a/C4-03b/C4-03c 核心已实现，C4-03d 部分实现，C4-04 仍未实现：

- C4-03a 已实现只读 `ADMIN_MODEL_CATALOG_PATH`：schema v1、2 MiB 上限、严格 JSON、重复
  key/未知字段/尾随内容拒绝、稳定模型 ID、显式 Provider 通配符、非嵌套 group 展开和
  SHA-256 digest 固定；坏目录导致管理服务启动失败。`ADMIN_MODELS` 只用于无正式目录时的
  兼容显示，不是权限事实来源。admin-service 负责把选择器展开为稳定模型 ID；
  auth-service 只接收展开后的 ID，不加载模型目录，也不接收 group 表达式。
- C4-03b 已在 auth-service 实现版本化 `gatewayPolicy`：旧 M1 只能迁移为 `unknown`，
  quota/models 可任意顺序首次设置，但缺项必须返回 `policy_setup_required`；两项完整且逐
  凭证回读后才进入 `known`。
- C4-03c 已实现签发 journal、幂等签发、自动 apply、独立回读、原子持久化和同步后交付。
  签发失败会补偿撤销新 Key；启动时扫描非 `committed` journal，对可确认的孤儿 Key 执行
  幂等撤销，撤销结果不确定时保留 `unknown` 供后续重试。核心已通过 Mock/故障测试，
  但尚未完成真实 Magpie 行为 E2E 和生产验收。
- C4-03d 只有 `succeeded + known + synced + 回读一致` 才允许按“已生效”呈现；
  `unknown`、`pending`、`partial_success` 和 `dependency_invoked` 不能显示为成功。
  当前管理页已展示凭证同步状态、最后同步时间和错误码，但尚无调额/模型写按钮、完整员工
  门户、operation/audit 查询和人工对账。员工网页仍不能直接修改本机 Agent 文件。
`pending` 时 join、refresh 和 rotate 必须失败关闭，不能扩散未确认策略。

详细字段、状态和验收见
[`../devtools/enterprise-feature-spec.md`](../devtools/enterprise-feature-spec.md) 第
12.8.1.5 节和
[`../devtools/enterprise-deployment.md`](../devtools/enterprise-deployment.md) 第 10 节。

## M2-E 设计边界（未实现）

审批、step-up、break-glass 和通知投递目前只有设计，没有代码或生产验收证据。当前实现中的
`approvalId` 只是冻结的请求字段，服务端还不能证明审批存在、签名有效、属于当前组织/动作/
payload、尚未过期/撤销，也不能证明只消费一次。因此任何高风险写接口都不能把“请求带
`approvalId`”当作审批通过。

M2-E 的统一边界是：

```text
APR-01a/b/c
  -> NOTIFY-01a/b/c
  -> M2-D
  -> APR-01d/e + NOTIFY-01d
```

- `APR-01a`：风险分级、规范化 payload、绑定摘要、审批状态机、自审批拒绝、一次性消费和
  `operationId` 审计串联。
- `APR-01b`：外部审批适配器；真实 OA/飞书/ServiceNow/Jira 回调必须验签并防重放。
- `APR-01c`：独立管理 OIDC Client 的 step-up/MFA/ACR、短有效期和会话/IP/角色绑定。
- `APR-01d`：M2-D 之后提供内置审批箱、串并行步骤、转交/撤回和双人复核。
- `APR-01e`：15 分钟 break-glass、强制高风险告警和 24 小时事后复核。
- `NOTIFY-01a`：与业务状态和审计同事务/同文件锁提交的 transactional outbox、租约、
  幂等、指数退避、重启恢复、死信和人工重放。
- `NOTIFY-01b`：邮件、企业 IM、HMAC Webhook 和工单；Webhook 只允许 HTTPS + 允许列表，
  防 SSRF、重定向和 DNS rebinding。
- `NOTIFY-01c`：OTel/Syslog/HTTP SIEM 投递，固定 schema，不发送 Prompt/回复正文、工具
  完整参数、Key、token 或 Cookie。
- `NOTIFY-01d`：通知渠道、规则、投递、抑制、聚合、死信和重试运营页。

当前仓库没有审批表/API、step-up 中间件、outbox、dispatcher、邮件/IM/Webhook/SIEM/工单
适配器，也没有对应管理页面。业务请求不能同步调用外部通知渠道；渠道故障不能回滚已成功的
业务事务，也不能在页面上伪造“已通知”或“已审批”。在 M2-E1/M2-E2 和对应验收完成前，
整体仍只能表述为“可演示 + 可受控技术试点”。

## 快速开始

### 1. 服务端

Docker（推荐）：

```bash
cd enterprise
cp .env.example .env       # 改 MAGPIE_ALLOW_IPS 为公司网段
docker compose up -d
```

或者直接用二进制：

```powershell
$env:MAGPIE_ADDR = "0.0.0.0:3425"
$env:MAGPIE_ALLOW_IPS = "10.0.0.0/8,192.168.0.0/16"
magpie serve
```

首次部署时在服务端配置真实 Provider（Key 只留在服务端）：

```powershell
magpie provider add deepseek sk-...          # 或 provider add <name> url=... key=... models=...
```

给员工开通网关密钥（在本目录）：

```powershell
.\scripts\provision-user.ps1 -Magpie magpie -Name alice -Models "deepseek/deepseek-chat"
```

脚本会打印一次给 alice 的密钥。给每个员工单独开一个，离职用 `magpie gateway-key remove <id>` 或
`gateway-key rotate <id>` 即可。

### 2. 客户端（M0：手工 Key）

在员工电脑上（本目录随仓库一起分发，或单独拷过去）：

```powershell
.\scripts\join-client.ps1 -Magpie magpie `
  -GatewayUrl http://gateway.corp.example:3425 `
  -Key <alice 的密钥> `
  -Models "deepseek/deepseek-chat" `
  -Agent claude -AgentModel deepseek/deepseek-chat
```

`join-client.ps1` 会把企业网关加成本地 magpie 的 Provider；`-Agent`/`-AgentModel` 是可选的一键配置。
之后员工本地的 Agent 仍然指向 `127.0.0.1:3425`，由本地 magpie 转发到企业网关。

### 3. OIDC 加入（M1：推荐试点）

先按 [`auth-service/README.md`](auth-service/README.md) 配好企业 IdP、issuer Key 和
`docker compose --profile auth`，然后在员工电脑运行：

```powershell
.\scripts\join-enterprise.ps1 `
  -AuthUrl https://auth.ai.corp.example `
  -Magpie magpie `
  -Agent claude `
  -AgentModel deepseek/deepseek-chat
```

脚本会启动浏览器 OIDC 登录，注册本机设备，自动写入企业 Provider，并安装当前 Windows
用户级的 30 分钟刷新计划任务。短期 Key 不会打印。

注意：浏览器不能直接写本机 Agent 文件。员工必须已经安装/运行本地 Magpie；网页负责身份
授权和展示，本地 Magpie 负责实际配置 Agent。

### 4. 管理面（M2-A + M2-B + M2-C1 + M2-C2：身份底座、只读治理与受控写接口）

管理面使用独立 OIDC Client、独立 Cookie、独立端口和独立数据卷：

```bash
docker compose --profile admin up -d
curl http://127.0.0.1:3445/healthz
```

在 `.env` 中配置 `ADMIN_OIDC_*`、`ADMIN_SESSION_SECRET`、`ADMIN_ALLOWED_IPS` 和
`AUTH_INTERNAL_ADMIN_TOKEN`。管理员打开 `https://admin.ai.corp.example/admin/`，使用企业
账号 + MFA 登录。`ADMIN_BOOTSTRAP_SUBJECTS`/`ADMIN_BOOTSTRAP_EMAILS` 只用于创建有到期时间的
首个 `super_admin`；正式角色绑定建立后应移除。

当前管理面能认证管理员、执行 CSRF/IP/会话保护、计算角色和组织范围，并提供最小管理页、
`/api/v1/admin/me`、组织单元、用户、部门、设备、凭证、模型和用量只读视图。模型视图已改为
正式只读目录的安全投影。用量通过只读挂载 `/magpie-readonly/magpie/usage.jsonl` 汇总，
按用户组织范围过滤；不返回对话正文。
M2-C2 已在管理服务提供四个受控写接口：停用/启用用户、吊销设备、轮换当前凭证。接口要求
管理会话、CSRF、RBAC、组织范围和非空 `reason`；M2-C3 已接入 `Idempotency-Key` 持久化/
重放/冲突、`operationId`、intent/result 管理审计和审计失败阻断，因此 API 层面的敏感操作
已有可追溯性。C4-03c 已提供额度/模型管理 API、自动同步、同步后交付和失败状态持久化；
管理页可查看策略版本、凭证同步状态、最后同步时间和错误码。管理台写按钮、operation/audit
查询、失败对账、完整筛选/导出和看板仍属于 C4-03d、M2-C5/D，尚未实现。详见
[`admin-service/README.md`](admin-service/README.md)。

## 5. 当前员工与管理员流程（只列已实现）

### 5.1 员工流程

1. 员工电脑先安装或运行本地 Magpie，并准备要接入的 Agent（例如 Claude Code、Codex 或
   OpenCode）。
2. 员工运行 `join-enterprise.ps1`。脚本在浏览器中发起企业 OIDC 登录，注册本机设备，取得
   短期网关 Key，把企业 Provider 写入本地 Magpie，并可选调用 Magpie 原生 Agent 一键配置。
3. 脚本在当前 Windows 用户下安装刷新计划任务；设备随后通过短期 Key 访问企业网关，真实
   厂商 Key 只保留在网关。
4. 当前员工网页能完成 OIDC 身份建立，并通过 `/api/v1/me` 返回本人身份和本人的设备元数据。
   完整员工门户、本人额度/模型范围、凭证恢复提示和操作历史属于 M2-D，尚未实现。
5. **网页不能直接修改员工电脑上的 Agent 文件。** 必须由本地 Magpie/加入脚本执行 Provider
   写入和 Agent 一键配置；只打开浏览器、不安装本地 Magpie，不能设置本机 Agent。

### 5.2 管理员流程

1. 管理员打开独立的管理入口，使用独立 OIDC Client 和企业账号登录，完成 MFA/ACR。
2. 管理服务按管理员角色和组织范围返回组织单元、用户、部门、设备、凭证、模型和用量只读
   视图；跨组织范围请求被服务端拒绝。管理员可通过受控 API 设置额度和模型授权，链路会
   自动 apply、独立回读，并在同步完成后才把新 Key 交付设备。
3. 当前用量是网关 `usage.jsonl` 的元数据汇总，可按授权范围查看请求元数据和用量统计；
   模型列表来自只读正式目录；admin-service 在写入前把选择器展开为稳定模型 ID，
   auth-service 以这些 ID 作为用户级授权事实。
   管理员目前**不能查看员工对话正文**；正文审计属于 M4，尚未实现。
4. M2-C1/C2 已提供四个受控写 API：停用/启用用户、吊销设备、轮换当前凭证。API 要求管理
   会话、CSRF、RBAC、组织范围和非空理由；M2-C3 已接入幂等、`operationId` 和
   intent/result 管理审计。当前管理页还没有这些写操作的按钮，只能由受控 API 客户端调用。
5. 管理员当前可以**通过受控 API 调整员工额度或模型授权**，但管理页还没有对应写按钮。
   写操作要求 `expectedVersion`/`If-Match`、`Idempotency-Key`、组织范围和理由，并产生
   `operationId` 与 intent/result 审计。同步完成后凭证状态才显示 `synced`；部分失败返回
   `partial_success` 并保持待对账。管理员**不能查询 operation/audit 日志或执行人工对账**，
   因为 C5 尚未实现。真实 Magpie 限额/模型拒绝 E2E 与 Docker/共享卷验收也未完成。
6. 管理员当前**不能下发 MCP 服务器、企业 Skills/Instructions 或中央资源库**。MCP 治理和
   企业资源库属于 M3，尚未实现；现有管理面只能展示只读元数据、四个受控写 API，以及
   通过 API 调用的额度/模型策略写入。
7. 管理员不能直接读取或改写员工本机 Agent 配置。后续中央策略也必须通过本地 Magpie/helper
   的受控同步接口落地，浏览器不能获得任意本机文件写权限。

### 5.3 当前结论

员工不是“只通过网页就能设置本地 Agent”。已实现的闭环是“网页 OIDC 授权 + 本地 Magpie
落配置”；管理员也不是“完整企业控制台”，当前具备身份底座、只读治理、四个受控写 API
和额度/模型策略 API，但缺少管理台写按钮、查询对账、真实行为 E2E 和生产验收。
在 C4-03d/C4-04、C5/D、M3/M4 和生产验收完成前，整体只能描述为“可演示、可受控技术
试点”。

## 6. 验收

```powershell
.\scripts\verify.ps1 -Magpie magpie -GatewayUrl http://gateway.corp.example:3425 -Key <密钥> -Model deepseek/deepseek-chat
```

脚本会检查 `/v1/models` 和一次真实的 chat 请求，打印 PASS/FAIL。请从员工电脑运行；
magpie 对网关本机的回环请求始终放行，在服务端本机运行只能验证路由，不能验证密钥是否有效。

## 7. 端到端自测（不需要真实模型）

`test/e2e.ps1` 会在本机起三个进程：mock 上游、服务端 magpie、客户端 magpie，
然后验证“客户端 → 服务端 → 上游”的完整链路和按密钥归属的用量记录。

准备一个 magpie 可执行文件（官方 CLI 构建或 `make cli` 的产物），运行：

```powershell
.\test\e2e.ps1 -Magpie C:\path\to\magpie.exe -Node C:\path\to\node.exe
```

它只使用临时目录，不会碰你正在用的 magpie 数据。它会验证
`provision-user.ps1`、`join-client.ps1`、`verify.ps1`，以及“客户端 → 服务端 → 上游”链路和
`usage.jsonl` 中按员工密钥归属的记录。失败时保留临时目录和日志；成功时可用 `-Keep` 保留。

M1 真实 issuer 链路另行运行：

```powershell
.\test\auth-e2e.ps1 -Magpie C:\path\to\magpie.exe -Node C:\path\to\node.exe
```

它覆盖真实 issuer Key、OIDC 加入、短期 Key、员工调用、用量归属、刷新撤销、停用吊销、
auth-service 重启和凭据脱敏。脚本通过本机非回环 IPv4 访问网关，隔离临时用户目录，
并已通过本地验收；真实企业 IdP、Docker 和 Windows 计划任务仍未验证。

## 8. 安全边界（当前版本）

- `MAGPIE_ALLOW_IPS`：只允许公司 VPN/内网网段；本机回环永远放行。
- 每员工一个网关密钥：可在服务端设模型白名单、token/成本额度、只读权限和过期时间。
- 用量：服务端 `usage.jsonl` 记录 `callerKeyName`，可按人/模型/时间对账；可开 OTLP 导出。
- 审计内容：magpie 默认只记元数据，不记对话正文；正文审计是下一步的独立插件/服务。
- OIDC：`enterprise/auth-service` 已实现登录、设备注册、短期 Key 刷新、停用吊销和自动
  策略同步；本地真实 issuer 链路已通过，真实企业 IdP、Docker 和计划任务仍需完整验收。
- 当前 auth 的 `AUTH_ADMIN_TOKEN` 仍是 M1 最小接口凭据，不应继续扩展成生产管理后台。
- `enterprise/admin-service` 已实现 M2-A 的管理 OIDC、MFA/ACR、已验证邮箱、会话、CSRF、
  IP 限制、RBAC、组织范围、独立服务令牌和最小管理页；已通过 Mock 单元/集成测试。
- M2-B 已实现用户、部门、设备、凭证、模型和用量只读 API，服务端组织范围过滤、只读
  `usage.jsonl` 读取、用户-部门显式映射和管理页摘要；Mock 集成测试通过。
- Auth 服务的 M2-C1 内部写接口和 admin-service 的 M2-C2 四个对外写接口已实现并通过 Mock
  测试；管理会话、CSRF、RBAC、组织范围和非空理由已接入，响应已做字段白名单脱敏。
  M2-C3 已把 `Idempotency-Key` 接入持久化预留、同键重放、同键异体 `409`、执行中 `409`、
  `operationId` 和 intent/result 管理审计；intent 审计失败不调用依赖，result 审计失败不
  返回成功。C4-01 已提供机器回读/原子写入，C4-02 已提供经 15 项 Mock/故障测试的受控
  适配器和独立 Bearer 服务令牌；C4-03a 已提供正式只读模型目录和摘要固定，并由
  admin-service 在写入前展开选择器；C4-03b 已提供 auth-service 的策略核心和内部接口；
  C4-03c 已把调度、apply、独立回读、同步后交付、失败补偿和启动恢复串成实现。真实
  Magpie 请求行为验证属于 C4-04；操作查询、审计查询和人工对账属于 M2-C5；
  管理台写按钮、完整筛选/分页、导出和看板属于 M2-D，均尚未实现。真实 IdP、Compose、
  浏览器、反向代理、真实共享卷和真实用量卷也尚未验收。当前不是 mTLS。

## 9. 目录

```text
enterprise/
  README.md                 本文件
  docker-compose.yml        服务端网关
  .env.example              部署参数
  auth-service/              OIDC、设备注册、短期 Key 服务
  admin-service/             管理 OIDC、会话、RBAC、组织范围、只读治理和管理页
  gateway-control/           C4-02 受控 Key describe/policy apply 适配器
  scripts/
    provision-user.ps1      服务端：开通/配置员工密钥
    join-client.ps1         客户端：加入企业网关
    join-enterprise.ps1     客户端：OIDC 加入
    refresh-client.ps1      客户端：刷新短期 Key
    verify.ps1              验收：模型列表 + chat 请求
  test/
    mock-upstream.mjs       测试用 OpenAI 兼容上游
    mock-oidc.mjs           测试用 OIDC 授权码、Token 和 JWKS
    e2e.ps1                 客户端/服务端分离的端到端验证
    auth-e2e.ps1            M1 issuer/OIDC/刷新/吊销端到端验证
```

当前真实实现状态见 `devtools/enterprise-implementation-status.md`。完整管理层方案见
`devtools/enterprise-plan-summary.md`；后续路线见 `devtools/enterprise-master-plan.md` 和
`devtools/enterprise-roadmap.md`：C4-03d/C4-04 的页面与真实请求 E2E、
操作/审计查询、管理台写按钮、
中央 MCP/资源库、内容审计、可观测性和高可用。生产验收按
`devtools/enterprise-acceptance-checklist.md` 逐项留证；当前只能作为受控技术试点，不能把
Mock 测试、只读治理或网页登录描述为“企业生产版已完成”。
完整需求 ID、交付包、M2-C 执行门禁和每项完成定义见
`devtools/enterprise-feature-spec.md` 第 25 节。
项目职责、GitHub 分支保护、环境晋级、发布证据、成本容量、培训和试点退出规则见
`devtools/enterprise-operating-model.md`。
企业功能优先放独立服务和插件，核心只保留必要 hook。
