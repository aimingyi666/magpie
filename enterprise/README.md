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
以及 C4-03c 的管理 API、签发 journal、自动 apply/独立回读、同步后交付和启动补偿，
外加 C4-03d 的管理页额度/模型写表单、停用/吊销/轮换基础操作、员工只读状态门户、
M2-C5 的查询/对账和 M2-D 的基础运营页与 CSV 导出、
M2-E1/APR-01a 的服务端审批、APR-01b 的 HMAC 外部审批回调适配器、APR-01c 的独立
OIDC step-up、APR-01d 的审批箱/串并行步骤/quorum/转交/撤回、APR-01e 的 break-glass
15 分钟单次授权/24 小时复核，以及 NOTIFY-01a/01b/01c
的通知 outbox、渠道管理和 SIEM transport，以及 M3-A 的资源目录与签名服务核心：
手工/OIDC 加入、短期 Key、设备注册与吊销、管理身份与只读治理、四个受控管理写 API、
管理额度/模型 API、持久化幂等、管理审计、审批申请/决策/撤销、审批一次性消费、
schema v1 的网关策略机器回读/原子写入、受控 `gateway-control` 适配器、正式只读模型目录，
以及 auth-service 的用户级策略状态机；M3-A 已提供资源目录、不可变版本、内容寻址对象
存储、Ed25519 签名 manifest、发布/回滚和资源审计；M3-B 已提供远程 MCP 注册、企业统一
MCP 端点、工具级 allow/deny、健康检查、上游凭据隔离和元数据审计核心；M3-C-1 已提供
设备短期同步凭证、desired-state、设备上报、管理员 JSON 查询和客户端 HTTP 传输，
`enterprise/client-sync` 包也提供签名 desired-state、原子安装、失败保留旧版本、离线缓存、
强制/推荐策略和漂移检测核心；M3-C-2 已把资源目录和设备同步报告以只读、按组织范围过滤的
方式接入管理页，并把依赖失败稳定映射为 `503 resource_service_unavailable`。`gateway-control`
已通过 38 项 Mock/故障测试；
auth-service 已通过 26 项测试；admin-service 已通过 133 项测试（96 项管理服务集成测试 +
5 项内容治理客户端专项 + 5 项内容治理存储专项 + 7 项目录专项 + 7 项通知渠道专项 +
7 项通知规则专项 + 6 项 SIEM 专项）；resource-service
已通过 16 项单元/Mock 集成测试（12 核心 + 4 控制面，含 `hook` 资源类型）；mcp-gateway 已通过 17 项
单元/Mock 集成测试；client-sync 已通过 26 项单元/Mock 集成测试（18 核心 + 8 传输）；
local-mcp 已通过 60 项隔离测试（21 运行时 + 7 helper + 9 HTTP server + 5 stdio bridge
+ 7 Codex 配置映射 + 10 一键配置编排 + 1 真实子进程 E2E）；audit-service 已通过 67 项
隔离测试（20 项 L0/L1 事件管道 + 27 项内容审计、检索与一次性授权核心 + 20 项留存、
法律保留、删除证明和加密导出核心）；security-service 已通过 44 项隔离测试（固定事件
allowlist、秘密扫描、八条稳定检测规则、确定性 finding/聚合、抑制标记、幂等重放和
原子持久化，M5-B 覆盖响应动作状态机、审批、幂等、撤销和 hash-chain 审计）；
magpie-plugin 已通过 37 项隔离测试（员工页、管理员页、资源页、用量汇总、审计元数据页、
主题跟随、PKCE 与页面检查）；网关元数据投递核心另有 12 项 Go 测试通过（导出器 8、
插件生命周期 3、身份/来源地址映射 1）；当前十套合计 464 项通过、0 失败。
NOTIFY-01a 的 transactional outbox、NOTIFY-01b 的渠道管理 API/统一 HTTPS 渠道适配器和
NOTIFY-01c 的 SIEM transport 已实现并通过 Mock/故障测试；支持 `email`/`im`/`webhook`/
`ticketing`/`siem`、HMAC Webhook、host allowlist、DNS 固定解析、私网/重定向防护，以及
`http-collector`/`otlp-http`/`syslog-tls`。默认禁用渠道，未启用渠道或没有 transport 时
不创建 dispatcher。
`GET /api/v1/admin/models` 使用正式目录，由 admin-service 将 group/provider 选择器展开为
稳定模型 ID 后再交给 auth-service。C4-03d 部分实现：管理页已展示策略版本、完整证据链和
凭证同步状态，并提供额度/模型写表单；员工页可查看本人额度、模型、凭证、设备和同步状态。
管理页已有停用/吊销/轮换基础操作、审批、operation/audit 查询、人工对账和 CSV 导出入口；
浏览器 E2E、失败恢复入口和完整运营体验仍未完成。Docker/Compose 实机构建、
启动和健康检查，真实共享卷、真实企业 IdP、浏览器、反向代理、Windows 计划任务和 mTLS
尚未验收；C4-04 完整管理到真实 Magpie 策略流 E2E 已通过，覆盖双设备独立 Key、真实
限额/模型拒绝、多凭证部分失败、refresh/rotate 继承、故障后 pending、Journal/孤儿 Key
撤销和恢复同步；M2-C5 与 M2-D 核心已实现，基础管理页面已接入；APR-01a、APR-01b、
APR-01c、NOTIFY-01a、NOTIFY-01b 和 NOTIFY-01c 后端已实现，但真实渠道环境未验收。APR-01b
当前是 HMAC 回调适配器，真实飞书/OA/ServiceNow/Jira 适配和故障演练未验证；NOTIFY-01b
是厂商 HTTPS 网关契约，不是原生 SMTP/Graph/飞书/Teams/Slack/ServiceNow/Jira SDK，真实
证书、租户配置和投递未验收；NOTIFY-01c 的真实 SIEM/Collector/Syslog/生产证书未验收。
NOTIFY-01d 的规则/抑制、聚合、升级、受审计重放和通知运营页已实现并通过 Mock/集成测试；
M3-A、M3-B、M3-C-1 与 M3-C-2 核心/控制面/只读管理可见性已实现；M3-D 受控本地 MCP
运行时、`LocalMcpHelper`、回环 HTTP server、stdio bridge、Codex 配置映射和
`setupLocalMcpClient()` 一键配置编排核心已实现，但安装器/Windows 服务、生产 launcher/
token 轮换、管理台员工产品流、真实外部沙箱和生产验收尚未完成。M4-A 审计事件管道核心、
M4-B 内容审计核心、M4-C 内容检索/一次性授权后端核心和 M4-D 留存/法律保留/删除证明/
加密导出后端核心已实现；M4-E 已把管理员内容检索、一次性正文读取、留存/删除、法律保留和
双层加密导出接入 admin-service、管理台、审批、step-up、幂等、operation 和审计链路，
但默认关闭且真实网关正文采集、浏览器 E2E 和生产验收未完成；M5-A 检测规则引擎和网关
元数据投递核心已实现，规则服务 17 项隔离测试及网关侧 12 项 Go 测试通过，提供八条规则、
确定性 finding/聚合、原始事件保留、抑制标记和默认关闭的元数据导出器；导出器只发送网关
Key 身份、Agent、Token 用量和 HMAC 源地址，不发送 Prompt、回复、Cookie、Authorization、
网关密钥或原始 IP，但管理台安全运营页面、自动响应、OTel/Prometheus/Grafana、生产 SIEM、
值班手册、HA、Docker/Compose、真实反向代理来源地址和运行中端到端投递仍未实现或未验证；
M5-B 响应动作状态机与受控模拟执行核心已实现，但真实网关阻断/吊销、真实厂商工单、管理 UI 和生产验收未完成；M5-C 和 M6 仍未实现；M2-D 核心已实现，生产验收未完成。
M3-A/M3-B 尚未接入 admin-service 真实审批和可写管理台，
M3-C-1/M3-C-2 已接入只读同步报告/资源目录页面，但尚未接入资源发布/回滚 UI、审批联动和本地
helper 产品流，MCP 审批 nonce 仍是
单进程内存状态，审计与注册表也不是同一事务；Compose 也未实机验收。当前不是生产就绪版本。

## M2-C4 目标边界（C4-01/C4-02/C4-03a/C4-03b/C4-03c 核心已实现，C4-03d 部分实现，C4-04 完整策略流 E2E 已通过）

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
`gatewayPolicy` 标为 `known`；C4-04 已在隔离真实 Magpie 链路中验证限额和模型白名单拒绝，
真实 Docker/共享卷和生产环境仍待验收。

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

C4-03a/C4-03b/C4-03c 核心已实现，C4-03d 部分实现，C4-04 完整管理链路 E2E 已通过：

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
- C4-03d 只有完整证据链（`succeeded + known + synced + operation 匹配 + 无需对账`）
  才允许按“已生效”呈现；`unknown`、`pending`、`partial_success` 和
  `dependency_invoked` 不能显示为成功。管理页已提供额度/模型写表单和失败证据，员工页已
  提供本人状态只读门户；M2-C5/M2-D 已提供 operation/audit 基础查询、人工对账和 CSV
  导出页面，但浏览器 E2E、失败恢复入口和完整运营体验仍未完成。员工网页仍不能直接修改
  本机 Agent 文件。
`pending` 时 join、refresh 和 rotate 必须失败关闭，不能扩散未确认策略。

详细字段、状态和验收见
[`../devtools/enterprise-feature-spec.md`](../devtools/enterprise-feature-spec.md) 第
12.8.1.5 节和
[`../devtools/enterprise-deployment.md`](../devtools/enterprise-deployment.md) 第 10 节。

## M2-E 当前边界（APR-01a/b/c 与 NOTIFY-01a/b 核心已实现，其余未实现）

APR-01a 已经提供服务端审批：申请、读取、决策、撤销四个 API，24 小时有效期，L/M/H/C
风险，规范化 payload/binding SHA-256，审批状态机，禁止自审批，组织范围校验和一次性消费。
除低风险 `user.enable` 外，现有受支持管理写操作必须消费一个有效的已批准审批；过期、撤销、
跨动作、跨目标、改 payload 或改策略版本都会失败关闭。审批申请、决策、撤销、消费和启动恢复
均写系统审计。

APR-01b 已实现 HMAC-SHA256 外部审批回调适配器：原始 body 验签、300 秒时间窗、nonce
防重放、issuer/audience、eventId 幂等、职责分离、审批状态迁移和系统审计。回调只改变
审批状态，不能直接执行管理动作；业务写入仍需原绑定校验和一次性原子消费。当前只有
协议/Mock 能力，真实飞书/OA/ServiceNow/Jira 的字段映射、证书、网络、租户配置和故障
演练尚未验证。

APR-01c 已实现独立管理 OIDC step-up、MFA/ACR、`auth_time` 新鲜度、会话/IP/User-Agent/
角色范围绑定和 H/C 风险门禁，并通过 Mock IdP 集成测试。NOTIFY-01a 已实现 transactional
outbox、租约、幂等、退避、死信、重启恢复、deliveries 查询和受审计人工重放；NOTIFY-01b
已实现渠道管理 API、渠道测试和统一 HTTPS 渠道适配器；NOTIFY-01c 的 SIEM transport、固定
L0 schema 和 dead-letters API 也已实现。APR-01d 已交付：内置审批箱、串行/并行步骤、
显式 `stepId`、quorum、转交和申请人撤回已接入管理页。APR-01e 的 15 分钟单次
break-glass、强制 step-up、24 小时事后复核、RBAC、告警事件、审计、API 和管理页已完成
Mock/集成核心。NOTIFY-01d 的规则/抑制、聚合、升级、受审计重放和通知运营页也已完成
Mock/集成核心。仍未验收的是真实 OA/厂商连接器、真实 IdP/MFA、SIEM/告警、浏览器 E2E、
真实生产复核演练和生产值班闭环。不能把 Mock/API
证据描述成生产审批或通知闭环。

```text
Break-glass Mock/integration core is implemented. Real IdP/MFA, SIEM/alerting,
OA/ticketing, browser E2E, and production post-incident review rehearsal remain unaccepted.
```

M2-E 的统一边界是：

```text
APR-01a/b/c
  -> NOTIFY-01a/b/c
  -> M2-D
  -> APR-01d [done] -> APR-01e [core done] + NOTIFY-01d [core done]
```

- `APR-01a`：风险分级、规范化 payload、绑定摘要、审批状态机、自审批拒绝、一次性消费和
  `operationId` 审计串联。
- `APR-01b`：外部审批适配器；HMAC/Mock 协议已实现，真实 OA/飞书/ServiceNow/Jira
  连接器和生产回调验收未完成。
- `APR-01c`：独立管理 OIDC Client 的 step-up/MFA/ACR、短有效期和会话/IP/角色绑定；
  代码和 Mock IdP 集成测试已完成，真实 IdP/MFA/反向代理和生产验收未完成。
- `APR-01d`：内置审批箱、串并行步骤、显式 `stepId`、quorum、转交、撤回和审批页已交付；
  浏览器 E2E、真实 OA 和生产审批演练未完成。
- `APR-01e`：15 分钟单次 break-glass、强制关键 step-up、绑定动作/目标/payload、24 小时
  事后复核、单独高风险告警事件和管理页/API 已完成 Mock/集成核心；真实 IdP/MFA、
  SIEM/告警、OA/工单和浏览器 E2E 未验收。
- `NOTIFY-01a`：与业务状态和审计同事务/同文件锁提交的 transactional outbox、租约、
  幂等、指数退避、重启恢复、死信和人工重放已实现并通过 Mock/故障测试。
- `NOTIFY-01b`：渠道管理 API、渠道测试、邮件/企业 IM/HMAC Webhook/工单统一 HTTPS 网关
  适配器；Webhook 只允许 HTTPS:443 + 允许列表，防 SSRF、重定向和 DNS rebinding。不是
  原生厂商 SDK，真实网关、证书和租户配置未验收。
- `NOTIFY-01c`：`http-collector`/`otlp-http`/`syslog-tls` SIEM transport、固定 L0 schema、
  HTTPS:443/TLS:6514、allowlist、固定 DNS、SSRF 防护和 dead-letters API 已实现；默认
  32 KiB 上限、critical 优先和 5 分钟轮询上限。真实 SIEM/Collector/Syslog 和生产证书
  未验收。
- `NOTIFY-01d`：通知渠道、规则、投递、抑制、聚合、阈值/延迟升级、死信和受审计重放运营页。

当前仓库已有 APR-01b 的 HMAC 外部审批回调适配器、APR-01c 的 step-up 门禁、APR-01d 的
内置审批箱与多步骤审批、NOTIFY-01a 的 outbox/租约/重试/死信/人工重放核心、NOTIFY-01b
的渠道 API/统一 HTTPS transport、NOTIFY-01c 的 SIEM transport，以及 NOTIFY-01d 的规则、
抑制、聚合、升级和通知运营页面；没有真实 OA 连接器、原生厂商 SDK 或真实 SIEM 接入。默认禁用渠道，
未启用渠道或没有 transport 时不创建 dispatcher，不会伪造“已投递”。业务请求不能同步调用
外部通知渠道；渠道故障不能回滚已成功的业务事务。APR-01a/b/c 和 NOTIFY-01a/b/c 不证明真实
OA、真实 IdP step-up、真实 break-glass 告警/工单、真实厂商网关、真实 SIEM 接入或生产通知
闭环已完成。Break-glass Mock/integration core is implemented. Real IdP/MFA, SIEM/alerting,
OA/ticketing, browser E2E, and production post-incident review rehearsal remain unaccepted.

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
`AUTH_INTERNAL_ADMIN_TOKEN`。高风险动作还需要独立 step-up Client：
`ADMIN_STEP_UP_OIDC_CLIENT_ID`、`ADMIN_STEP_UP_OIDC_CLIENT_SECRET` 和
`ADMIN_STEP_UP_REDIRECT_URI`；可选设置 `ADMIN_STEP_UP_ALLOWED_ACR_VALUES` 和三个 TTL。
管理员打开 `https://admin.ai.corp.example/admin/`，使用企业账号 + MFA 登录。
`ADMIN_BOOTSTRAP_SUBJECTS`/`ADMIN_BOOTSTRAP_EMAILS` 只用于创建有到期时间的首个
`super_admin`；正式角色绑定建立后应移除。bootstrap 只会写自己创建的绑定：只要该管理员
已有一条非 bootstrap 的正式角色绑定，bootstrap 就不再写入或续期，因此移除配置即刻生效，
过期的正式绑定也不会被悄悄续上。首次创建和过期续期都会写入
`bootstrap.binding.created` / `bootstrap.binding.refreshed` 系统审计。

当前管理面能认证管理员、执行 CSRF/IP/会话保护、计算角色和组织范围，并提供最小管理页、
`/api/v1/admin/me`、组织单元、用户、部门、设备、凭证、模型和用量只读视图。模型视图已改为
正式只读目录的安全投影。用量通过只读挂载 `/magpie-readonly/magpie/usage.jsonl` 汇总，
按用户组织范围过滤；不返回对话正文。
M2-C2 已在管理服务提供四个受控写接口：停用/启用用户、吊销设备、轮换当前凭证。接口要求
管理会话、CSRF、RBAC、组织范围和非空 `reason`；M2-C3 已接入 `Idempotency-Key` 持久化/
重放/冲突、`operationId`、intent/result 管理审计和审计失败阻断，因此 API 层面的敏感操作
已有可追溯性。C4-03c 已提供额度/模型管理 API、自动同步、同步后交付和失败状态持久化；
管理页可查看策略版本、凭证同步状态、最后同步时间和错误码，并可提交额度/模型策略，已有
停用/吊销/轮换基础操作、审批箱、串并行多步骤审批、operation/audit 查询、人工对账和 CSV
导出入口；员工页
可查看本人额度、模型、凭证、设备和同步状态。M2-C5 和 M2-D 基础页面已接入，APR-01a
已提供审批 API 和一次性消费，APR-01c 已提供 H/C 风险 step-up 门禁和重新认证入口；
完整审批/运营体验、失败恢复入口、费用趋势看板、Excel/异步导出和生产验收仍未完成。详见
[`admin-service/README.md`](admin-service/README.md)。

### 4.1 资源目录服务（M3-A：核心后端）

`resource-service` 是企业资源目录与签名 manifest 的内部服务，支持 `mcp`、`skill`、
`instructions`、`subagent` 和 `template`，并提供不可变版本、SHA-256 内容寻址对象存储、
Ed25519 签名、发布/回滚、幂等写和资源审计链：

```bash
docker compose --profile resource up -d resource
```

该 profile 不发布主机端口，只接受持有 `RESOURCE_SERVICE_TOKEN` 的受信控制面服务调用。
签名私钥通过 Compose secret 挂载，不能写入 `.env` 或仓库。接口、密钥生成、存储限制和
安全边界见 [`resource-service/README.md`](resource-service/README.md)。

当前边界：`approvalId` 只是必填证据，尚未查询或消费 admin-service 审批；没有资源发布/回滚
UI、灰度发布、S3/MinIO、KMS/HSM 或多副本。M3-C-1 已提供设备同步凭证、desired-state、
设备上报和管理员 JSON 查询，独立客户端核心也支持强制/推荐、漂移检测和失败保留旧版本；
M3-C-2 已把资源目录和同步报告以只读方式接入管理页，并按管理员组织范围过滤。仍缺少资源
发布/回滚 UI、审批联动、本地 helper、目标 Agent 文件映射、Windows ACL、MDM、真实 IdP、
浏览器 E2E、Docker/Compose 实机验收、灰度/自动回滚和生产验收。

### 4.2 远程 MCP 网关（M3-B：核心后端）

`mcp-gateway` 是 M3-B 的远程 MCP 治理核心，提供管理面和员工/Agent 数据面：

```bash
docker compose --profile mcp-gateway up -d mcp-gateway
```

员工/Agent 只配置企业 MCP 地址 `https://mcp.ai.corp.example/mcp/enterprise` 和一次性签发的
scoped client credential；上游 MCP 地址、上游凭据、服务器分配和工具策略不会下发到员工机。
管理面支持注册/更新/健康检查远程 MCP、签发/吊销客户端凭据和查询元数据审计。工具名按
`<server-namespace>__<tool>` 暴露，服务端强制执行 user/org/device/server scope 以及工具级
allow/deny、可见性和风险策略；high/critical 工具还要求短期 HMAC 审批 token。

安全边界：默认只允许 HTTPS 和 allowlist 主机，强制校验 DNS 解析并固定已验证地址，拒绝
私网/回环/链路本地/云元数据地址和重定向，并限制请求体、上游响应、超时、速率和熔断。
客户端 token 只存 SHA-256，上游凭据只保存环境变量名，审计不记录参数或正文。

当前严格边界：M3-B 只是核心后端，尚未接入 admin-service 真实审批查询/一次性消费、管理台、
OIDC 组织分配或员工客户端同步；M3-C-1 已有独立同步控制面和客户端核心，M3-D 受控本地 MCP
运行时及 helper/server 核心已实现于 `enterprise/local-mcp`，但尚未接入安装器/Windows 服务、
管理台员工产品流和生产验收。审批 nonce 和限流器只在单进程内存中，
不能多副本。注册表和审计是分开的持久化写入，审计落盘失败可能发生在状态提交之后；client
签发场景会留下无法取回明文 token 的孤立 client，必须吊销后重新签发。生产部署需要共享事务
存储或审计 intent/补偿状态机、不可篡改审计、KMS/HSM、mTLS、真实 MCP/IdP 和浏览器 E2E。
当前机器没有 Docker CLI，Compose 只做静态审查，未实机构建或健康检查。详细契约见
[`mcp-gateway/README.md`](mcp-gateway/README.md)。

### 4.3 客户端资源同步（M3-C-1：控制面与核心包）

`client-sync` 是本地 Magpie 插件/helper 使用的签名资源同步核心，本身不直接暴露给网页；
员工端插件通过回环服务调用它。它固定 Ed25519 公钥、`signingKeyId` 和 SPKI SHA-256 指纹，校验 desired-state
manifest、资源内容、长度和 SHA-256，在 staging 中 fsync 并复验后以 rename 原子激活；新版本
验签或安装失败时保留上一验签版本，离线时继续使用最后验签版本。

核心同时实现 forced/recommended 策略、最低客户端版本、`inspect()` 漂移检测、进程锁、
状态文件 `0600` 原子写入和脱敏报告，并拒绝路径穿越、符号链接、坏缓存、重复资源/版本/
hash、未知签名 key 和超大 manifest。`readActiveResource()` 只返回仍与 active state
一致且重新通过签名/长度/SHA-256 校验的资源，供 local MCP helper 消费。专项当前
26 项测试通过（18 核心 + 8 传输）：

```bash
node --test enterprise/client-sync/test/*.test.mjs
```

当前严格边界：已有员工设备短期同步凭证、desired-state、设备上报和管理员 JSON 查询；
M3-C-2 已提供管理页的只读资源目录和同步报告/漂移可见性；员工端已有 Magpie 插件页展示
状态并执行立即同步。但仍没有资源发布/回滚 UI、发布/回滚审批联动、独立 helper 安装器、
浏览器 E2E、Windows ACL、MDM、目标 Agent 文件映射或灰度发布；因此员工网页仍不能直接
修改本机 Agent 文件，M3-C-1/M3-C-2 不能据此宣称产品级同步完成。

### 4.4 只读管理可见性（M3-C-2：admin-service）

`admin-service` 新增四条只读接口：

- `GET /api/v1/admin/resources` 和 `GET /api/v1/admin/resources/{resourceId}`，要求
  `resources.read`；仅当资源分配到 `"*"` 或管理员组织范围时才可见，响应只含白名单元数据。
- `GET /api/v1/admin/resource-sync/reports` 和
  `GET /api/v1/admin/resource-sync/reports/{deviceId}`，要求 `devices.read`；设备必须存在、
  属于可见用户，且报告 `userId` 与设备映射一致，否则不显示。

配置为 `ADMIN_RESOURCE_SERVICE_URL` / `ADMIN_RESOURCE_SERVICE_TOKEN`（必须成对，令牌至少
32 字符），并可用 `ADMIN_RESOURCE_SERVICE_TIMEOUT_MS`（默认 5000）和
`ADMIN_RESOURCE_SERVICE_MAX_RESPONSE_BYTES`（默认 4194304）收紧边界。客户端只发 GET、
不跟随重定向；未配置、超时、坏 JSON、超大响应、5xx 或重定向统一返回
`503 resource_service_unavailable`，不会显示为空列表。资源内容、签名私钥、服务令牌和
上游 actor 字段不会进入响应或页面。

管理页已提供“Resources and client sync”只读面板。仍未实现：资源发布/回滚 UI、发布/回滚
审批联动、灰度/自动回滚、M3-B MCP 管理台、真实 IdP、浏览器 E2E、Docker/Compose 实机验收、
Windows ACL/MDM 和生产验收。

### 4.5 受控本地 MCP（M3-D：运行时核心）

`enterprise/local-mcp/` 已实现 M3-D 的客户端运行时核心：Ed25519 签名包、canonical manifest、
SHA-256 文件摘要和公钥指纹；staging/fsync/复验/原子 rename 安装与并发锁；Node permission
model、`shell: false`、受限环境及发布者/工具/风险/文件/网络/秘密/解释器策略；高风险工具
审批绑定包 digest 和工具名；HTTPS Secret Broker 短期租约；JSON-RPC 超时、响应上限和工具
目录一致性检查；fail-closed 审计及有界健康计数。

本切片新增 `LocalMcpHelper` 和 `createLocalMcpServer()`：helper 通过
`ClientSyncEngine.readActiveResource()` 读取 active `kind: "mcp"` 资源，重新验签后从
manifest 解析包身份，不接受调用方提交的 `packageId`/路径；在同步阶段可作为
`validateInstalled` 回调安装签名 MCP 包。HTTP server 只允许 `127.0.0.1`/`::1`，`/healthz`
公开，其余路由要求至少 16 字节 Bearer token；提供 status、tools 和 call 三个固定接口，
默认 256 KiB body 上限、固定 JSON 字段、稳定错误码、文件锁、无 CORS 和 `no-store`。
snapshot 不返回正文、Secret、私钥或绝对路径。M3-D-2 还新增了
`magpie-local-mcp-bridge`：它只连接 HTTP 回环 helper，通过 stdio 暴露固定的
`initialize`/`tools/list`/`tools/call`，限制请求、响应和超时；Codex
`config.toml` 映射只维护 Magpie 标记块，支持 `CODEX_HOME`、保留用户其他配置、
BOM/CRLF、幂等原子写入和漂移拒绝，并只引用 token 环境变量名。

M3-D-3 新增 `setupLocalMcpClient()` 一键配置编排：按顺序完成同步、reconcile、快照选包、
工具发现、回环 helper 启动与探测、Codex 受管配置写入/严格回读和受控启动器环境注入。
调用方必须提供 `injectLaunchEnvironment`；缺失时返回 `token_injection_required` 并失败
关闭。未提供 token 时只在进程内生成 32 字节随机 token，token 仅进入冻结的启动环境补丁，
不写入 `config.toml`，成功结果也不返回 token。多资源要求显式 `resourceId`；任一阶段失败
会移除本次受管块、关闭 server 并释放 helper lock。网页不能直接修改员工电脑，必须由设备
上的本地 helper/受控 launcher 执行。本包当前通过 60 项隔离测试（21 运行时 + 7 helper +
9 HTTP server + 5 stdio bridge + 7 Codex 配置映射 + 10 一键配置编排 + 1 真实子进程 E2E）。

严格边界：真实子进程 E2E 已覆盖经过 `setupLocalMcpClient()` 的
`ClientSyncEngine + LocalMcpHost + helper HTTP server + stdio bridge` 的
initialize/list/call、受控环境注入和审计，但这不等于真实 Codex 客户端已读取生成的配置。
安装器/Windows 服务/MDM、代码签名、升级回滚、生产 launcher、Windows ACL/DPAPI、
token 轮换/恢复和管理台员工产品流仍未实现；
真实 OIDC、审批服务、Secret Broker、KMS/HSM、Windows ACL 和已证明的外部 OS 沙箱仍需
验收。Docker/VM 隔离、共享卷并发、浏览器 E2E、HA 和生产验收也未完成，因此不能把 M3-D
运行时核心写成产品化或生产可用。

### 4.6 员工端 Magpie 插件页（状态 + 立即同步：已实现）

`enterprise/magpie-plugin/` 在员工已有的 Magpie 侧边栏增加「企业」页。员工仍然安装同一份
Magpie，**不需要单独的企业定制版客户端**。这一刀只覆盖员工端：

- 读取 `join-enterprise.ps1` 写入的设备凭据，显示已加入/未加入、设备名、网关和凭据到期时间。
- 读取 `client-sync` 的 `state.json`，显示最近同步、最后成功时间、错误码和资源列表。
- 显示资源的强制/推荐策略，以及已安装、已变更、缺失、已关闭、已不再分配状态。
- 资源名称优先取 `enterprise-sync.json` 的 `displayNames`，其次取 release 的
  `metadata.json` 或正文首个一级标题；资源 ID 作为次要信息保留。desired-state
  协议本身只带 ID，管理端名称暂不下发。
- 「立即同步」通过插件宿主的回环服务调用现有 `ClientSyncEngine.syncOnce()`，并上报结果。

安装方式：

```powershell
magpie plugin add .\enterprise\magpie-plugin
```

插件默认在 `127.0.0.1:3477` 启动本地服务，端口可在插件设置中用 `port` 选项修改。页面不接触
设备令牌、私钥或绝对路径；本地服务只监听回环地址，并要求每次运行随机生成的页面令牌。

边界：这一版不做供应商接入、资源发布/回滚、后台定时资源同步或独立安装器；这些仍分别属于
普通 Provider 配置、`admin-service`/`resource-service` 和后续本地 helper/服务。插件页测试
覆盖凭据/配置/状态文件异常、资源状态推导、Host/Origin/页面令牌、未加入/未配置和并发同步，
当前 30 项通过（含管理员模式的 PKCE、失败关闭、路由白名单与页面/翻译检查）。

### 4.7 原生管理员模式（客户端插件 + 网页管理台并存）

`enterprise/magpie-plugin/` 现在还提供「管理员」视图，和员工视图共用同一个插件与本地回环
服务。它不是把 `/admin/` iframe 进 Magpie：原生页只调用本机服务，本机服务再访问
`admin-service`。网页管理台 `/admin/`、Cookie、CSRF 和 OIDC 路由保持不变，继续承载用户与
组织、设备、凭证、审批、资源同步、审计和导出。

首期原生页覆盖运行总览、供应商、路由、网关、用量与请求详情。管理员可以在自己电脑的
Magpie 打开，也可以直接在管理服务器上的 Magpie 打开；两种位置都走同一条回环服务路径。

登录过程：

1. 本机服务生成 `state`、PKCE 和 nonce。
2. 系统浏览器完成现有管理 OIDC/MFA。
3. `admin-service` 回调本机回环地址，只返回一次性 desktop ticket。
4. 本机服务用 ticket + PKCE verifier 换取短期桌面管理员 token。

页面从不持有 OIDC secret、管理 Cookie、桌面 token、网关管理 token 或供应商 Key。桌面
token 最长 8 小时、空闲 30 分钟失效，可手动退出；首期不做长期 refresh token。

企业网关新增独立的管理 API：

- 监听容器内专用地址，例如 `MAGPIE_ADMIN_ADDR=0.0.0.0:3450`；
- 只接受 `MAGPIE_ADMIN_TOKEN`，普通 Gateway Key、员工设备令牌、只读 Key 和浏览器 Cookie
  一律拒绝；
- 管理端口只在 Compose 网络内，**不发布宿主机端口**；
- `admin-service` 用 `ADMIN_GATEWAY_ADMIN_URL` 和 `ADMIN_GATEWAY_ADMIN_TOKEN` 访问它，
  不跟随重定向、限制响应大小、超时和异常都失败关闭；
- 供应商、路由、Gateway Key、遥测请求均有字段白名单；供应商 Key/Secret、AccessKey、
  token hash、私钥和内部路径不回传；
- 写操作要求 revision/`If-Match`，写后重新读取确认；失败的写不会报成成功。

风险级别：

- 供应商、路由、Gateway Key 的普通查看为 `L`；
- 新增/编辑模型与路由为 `M`，需要 step-up；
- 删除供应商、轮换/清除 Key、修改 Gateway Key 额度或白名单为 `H`，需要审批 + step-up。

原生页首期不实现审批中心；遇到 `approval_required` 时，管理员转到网页管理台完成审批。
这一版同样不修改网关监听地址/端口、不做局域网共享、重启或进程接管，也不支持在服务器侧
登录 Cursor、WorkBuddy、Codex 等订阅 OAuth；首期供应商只支持 API Key、自定义 Provider
和预设 Provider。

## 5. 当前员工与管理员流程（只列已实现）

### 5.1 员工流程

1. 员工电脑先安装或运行本地 Magpie，并准备要接入的 Agent（例如 Claude Code、Codex 或
   OpenCode）。
2. 员工运行 `join-enterprise.ps1`。脚本在浏览器中发起企业 OIDC 登录，注册本机设备，取得
   短期网关 Key，把企业 Provider 写入本地 Magpie，并可选调用 Magpie 原生 Agent 一键配置。
3. 脚本在当前 Windows 用户下安装刷新计划任务；设备随后通过短期 Key 访问企业网关，真实
   厂商 Key 只保留在网关。
4. 员工网页已完成 OIDC 身份建立，并展示本人身份、额度、模型、凭证、设备、策略同步状态和
   恢复提示；`/api/v1/me` 也只返回当前登录员工的同类数据。页面不返回 Gateway Key、设备令牌
   或 token hash。操作历史和完整资源视图仍属于后续阶段。
5. 员工桌面 Magpie 可安装 `enterprise/magpie-plugin`。侧边栏「企业」页只读展示设备、最近
   同步和资源状态，并提供「立即同步」；它复用同一份 Magpie，不是单独的企业定制客户端。
6. **网页不能直接修改员工电脑上的 Agent 文件。** 必须由本地 Magpie/加入脚本执行 Provider
   写入和 Agent 一键配置；只打开浏览器、不安装本地 Magpie，不能设置本机 Agent。

### 5.2 管理员流程

1. 管理员打开独立的管理入口，使用独立 OIDC Client 和企业账号登录，完成 MFA/ACR。
2. 管理服务按管理员角色和组织范围返回组织单元、用户、部门、设备、凭证、模型和用量只读
   视图；跨组织范围请求被服务端拒绝。管理员可通过受控 API 或管理页设置额度和模型授权，
   链路会自动 apply、独立回读，并在同步完成后才把新 Key 交付设备。
3. 当前用量是网关 `usage.jsonl` 的元数据汇总，可按授权范围查看请求元数据和用量统计；
   模型列表来自只读正式目录；admin-service 在写入前把选择器展开为稳定模型 ID，
   auth-service 以这些 ID 作为用户级授权事实。
  管理员可以在默认关闭、显式 RBAC、全局组织范围、审批和 fresh step-up 约束下，
  通过管理台检索脱敏正文流元数据并一次性读取脱敏正文；留存清扫、删除/脱敏、HMAC
  删除证明、法律保留和双层加密导出也已接入审批、幂等、operation 和审计链路。
  break-glass 不得用于内容治理。当前仍未接入真实 Magpie 网关正文采集，也没有生产浏览器
  E2E、WORM/KMS/HA、备份恢复演练和正式生产验收。
4. M2-C1/C2 已提供四个受控写 API：停用/启用用户、吊销设备、轮换当前凭证。API 要求管理
   会话、CSRF、RBAC、组织范围和非空理由；M2-C3 已接入幂等、`operationId` 和
   intent/result 管理审计。管理页已提供对应基础操作入口，真实环境仍需浏览器 E2E 验收。
5. 管理员可以在管理页填写理由和 `expectedVersion` 后提交额度/模型策略；页面自动携带
   CSRF 与 `Idempotency-Key`，并区分 `pending_sync`、`partial_success`、`unknown`。
   写操作要求组织范围和版本，并产生
   `operationId` 与 intent/result 审计。同步完成后凭证状态才显示 `synced`；部分失败返回
   `partial_success` 并保持待对账。M2-C5 已提供 operation/audit 基础查询、人工对账和
   CSV 导出页面。C4-04 已证明隔离真实 Magpie 的限额/模型拒绝、部分失败和
   refresh/rotate 继承；Docker/共享卷、真实企业 IdP、反向代理和浏览器 E2E 仍未验收。
6. 高风险写操作在 APR-01a 中必须先通过审批 API 获得有效审批，并在写入时一次性消费；
   申请人不能审批自己的请求。APR-01b 可由受信任外部系统通过 HMAC 回调批准/拒绝，但回调
   只改变审批状态，不直接执行管理动作。APR-01c 要求 H/C 风险审批创建、决策和写入通过
   新鲜独立 step-up；未配置时失败关闭。审批箱已支持串行/并行步骤、quorum、显式 `stepId`、
   转交和申请人撤回。APR-01e 已提供 15 分钟单次紧急授权、24 小时复核、关键 step-up、
   RBAC、告警事件、审计和管理页/API；真实 OA 连接器、SIEM/告警、通知投递和浏览器 E2E
   仍未验收。
7. 管理员当前可以通过管理页**只读查看**资源目录和员工设备同步报告，但**还不能通过管理台
   发布/回滚资源、下发 MCP 服务器、企业 Skills/Instructions 或中央资源库**。
   M3-A 已提供内部资源目录、不可变版本、签名 manifest、发布/回滚和审计核心，M3-B 已提供
   远程 MCP 注册、统一企业 MCP 端点、工具级策略、健康检查、上游凭据隔离和元数据审计核心；
   M3-C-1 已提供设备同步凭证、desired-state、设备上报、管理员 JSON 查询和客户端同步核心，
   包括强制/推荐、原子安装和漂移检测；M3-C-2 已接入只读资源/漂移页。但资源发布/回滚 UI、
   审批联动和本地 helper 安装器/产品流仍未实现；受控本地 MCP 属于 M3-D，运行时、
   helper、回环 HTTP server、stdio bridge 和 Codex 配置映射核心已实现，但尚未接入安装器、
   Windows 服务、真实 Codex 客户端和管理台员工产品流。
8. 管理员不能直接读取或改写员工本机 Agent 配置。后续中央策略也必须通过本地 Magpie/helper
   的受控同步接口落地，浏览器不能获得任意本机文件写权限。

### 5.3 当前结论

员工不是“只通过网页就能设置本地 Agent”。已实现的闭环是“网页 OIDC 授权 + 本地 Magpie
落配置”；员工网页可以只读查看本人策略、凭证、设备和同步状态。员工桌面的 Magpie 插件页
还能查看资源同步状态并执行「立即同步」，但仍不是独立企业客户端，也不负责供应商接入。
管理员也不是“完整企业
控制台”，当前具备身份底座、只读治理、四个受控写 API 与基础页面、额度/模型策略写表单、
完整证据链状态、C5 查询/对账、M2-D CSV 导出、APR-01a 基础审批、APR-01b HMAC 回调
适配器和 APR-01c step-up 门禁；C4-04 的真实管理链路 E2E 已通过，但仍缺少完整审批/运营
体验、失败恢复入口、真实 OA 连接器、生产 break-glass 告警/复核、通知、Docker/共享卷、
真实企业 IdP、浏览器和生产验收；M3-C-2 已提供只读资源/同步可见性，M3-B/M3-C-1 仍未接入
可写管理台、真实审批联动和员工产品流。M5-A 已提供固定事件 allowlist、八条检测规则、
确定性 finding/聚合、抑制标记、只接收哈希源 IP 的规则核心，以及默认关闭的网关元数据
导出器；导出器在每次路由尝试后发送已认证 Key、Agent、Token 用量和 HMAC peer 地址，但
不信任转发头且不会发送正文或凭据。管理台安全运营页面、告警/阻断/吊销/设备锁定/工单、
生产 SIEM、可观测性、Docker/Compose、真实反向代理来源地址、运行中端到端、值班演练和
生产验收尚未完成；M5-B 当前只做受控模拟执行，不能视为真实阻断能力已交付；M5-C 不能视为已交付。
在 M2-D 生产验收、M2-E 剩余项、M3/M4 和生产验收完成前，整体只能描述为“可演示、可受控
技术试点”。

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
- M3-B 远程 MCP 核心已实现：默认 HTTPS、host allowlist、DNS/地址校验、拒绝私网与重定向、
  工具级授权、短期审批 token、上游凭据隔离、健康检查和元数据审计。审批 nonce 仅单进程内存，
  注册表/审计分离且存在提交后审计失败窗口，因此当前只能单副本受控试点，不能声明生产就绪。
- OIDC：`enterprise/auth-service` 已实现登录、设备注册、短期 Key 刷新、停用吊销和自动
  策略同步；本地真实 issuer 链路已通过，真实企业 IdP、Docker 和计划任务仍需完整验收。
- 当前 auth 的 `AUTH_ADMIN_TOKEN` 仍是 M1 最小接口凭据，不应继续扩展成生产管理后台。
- `enterprise/admin-service` 已实现 M2-A 的管理 OIDC、MFA/ACR、已验证邮箱、会话、CSRF、
  IP 限制、RBAC、组织范围、独立服务令牌、最小管理页和 APR-01c step-up；已通过 Mock
  单元/集成测试。
- M2-B 已实现用户、部门、设备、凭证、模型和用量只读 API，服务端组织范围过滤、只读
  `usage.jsonl` 读取、用户-部门显式映射和管理页摘要；Mock 集成测试通过。
- Auth 服务的 M2-C1 内部写接口和 admin-service 的 M2-C2 四个对外写接口已实现并通过 Mock
  测试；管理会话、CSRF、RBAC、组织范围和非空理由已接入，响应已做字段白名单脱敏。
  M2-C3 已把 `Idempotency-Key` 接入持久化预留、同键重放、同键异体 `409`、执行中 `409`、
  `operationId` 和 intent/result 管理审计；intent 审计失败不调用依赖，result 审计失败不
  返回成功。C4-01 已提供机器回读/原子写入，C4-02 已提供经 15 项 Mock/故障测试的受控
  适配器和独立 Bearer 服务令牌；C4-03a 已提供正式只读模型目录和摘要固定，并由
   admin-service 在写入前展开选择器；C4-03b 已提供 auth-service 的策略核心和内部接口；
   C4-03c 已把调度、apply、独立回读、同步后交付、失败补偿和启动恢复串成实现。C4-03d
   已补管理页额度/模型写表单、完整证据链状态和员工只读状态门户。C4-04 已通过隔离真实
   Magpie 的完整管理链路 E2E；M2-C5/M2-D 已接入 operation/audit 基础查询、人工对账、
   停用/吊销/轮换、基础审批和 CSV 导出页面；APR-01a 已提供审批 API、绑定校验、职责分离
    和一次性消费。审批箱、串并行步骤、quorum、转交和撤回已实现；真实外部 OA、
    break-glass 告警/工单和浏览器 E2E 未验收。APR-01e 的 15 分钟单次授权、24 小时复核、
    RBAC、step-up、API、管理页和审计已完成 Mock/集成核心；NOTIFY-01a/01b 的 outbox、渠道 API 和统一 HTTPS
  transport 已实现，但 SIEM、规则/抑制、运营页、真实厂商连接器、证书/租户配置和生产
   投递未验收。APR-01c step-up 已实现代码和 Mock IdP 集成测试，但真实 IdP/MFA/反向代理和
   生产验收未完成。基础筛选、分页和 CSV 导出已实现，费用趋势看板、Excel、异步/对象存储
   导出和完整运营体验仍未实现。真实 IdP、Compose、浏览器、反向代理、真实共享卷和真实
   用量卷也尚未验收。当前不是 mTLS。

## 9. 目录

```text
enterprise/
  README.md                 本文件
  docker-compose.yml        服务端网关
  .env.example              部署参数
  auth-service/              OIDC、设备注册、短期 Key 服务
  admin-service/             管理 OIDC、会话、RBAC、组织范围、只读治理和管理页
  gateway-control/           C4-02 受控 Key describe/policy apply 适配器
  resource-service/          M3-A 资源目录、不可变版本和签名 manifest
  mcp-gateway/               M3-B 远程 MCP 注册、策略代理和健康检查
  audit-service/             M4-A + M4-B + M4-C + M4-D 审计事件、内容与治理核心
                             M4-E 由 admin-service/管理台编排
  security-service/          M5-A 检测规则/ingest 与 M5-B 响应动作状态机/模拟执行核心
  client-sync/               M3-C-1 签名资源同步核心和 HTTP 传输
  local-mcp/                 M3-D 受控本地 MCP 运行时核心
  magpie-plugin/             客户端插件页：员工状态/同步/资源 + 管理员视图与主题跟随
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
    c4-enterprise-policy-e2e.ps1  C4-04 管理到真实 Magpie 策略流 E2E
```

当前真实实现状态见 `devtools/enterprise-implementation-status.md`。完整管理层方案见
`devtools/enterprise-plan-summary.md`；后续路线见 `devtools/enterprise-master-plan.md` 和
`devtools/enterprise-roadmap.md`：C4-03d 的页面 E2E、C4-04 部署复核、
操作/审计查询、剩余管理写表单、
中央 MCP/资源库、内容审计、可观测性和高可用。生产验收按
`devtools/enterprise-acceptance-checklist.md` 逐项留证；当前只能作为受控技术试点，不能把
Mock 测试、只读治理或网页登录描述为“企业生产版已完成”。
完整需求 ID、交付包、M2-C 执行门禁和每项完成定义见
`devtools/enterprise-feature-spec.md` 第 25 节。
项目职责、GitHub 分支保护、环境晋级、发布证据、成本容量、培训和试点退出规则见
`devtools/enterprise-operating-model.md`。
企业功能优先放独立服务和插件，核心只保留必要 hook。
