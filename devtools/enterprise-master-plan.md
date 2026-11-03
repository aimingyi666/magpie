# Magpie 企业版完整功能方案与实施总纲

状态：完整实施方案 v3.36（完整需求追踪矩阵见 `enterprise-feature-spec.md` 第 25 节；能力闭环
矩阵和阶段证据表见同文档第 0.6、0.7 节；M0 已完成，
M1 本地真实链路已验收，M2-A/M2-B/M2-C1/M2-C2/M2-C3 已实现并通过 Mock 测试；
M2-C4-01 网关机器协议已实现，并通过 Go 单测、gateway-key CLI 回归和隔离真实二进制冒烟；
C4-02 `gateway-control` 已实现并通过 15 项 Mock/故障测试；C4-03a 正式只读模型目录已实现，
并通过 7 项目录专项、86 项管理服务集成、5 项内容治理客户端专项、5 项内容治理存储专项、
7 项通知渠道专项、7 项通知规则专项和 6 项 SIEM 专项测试，管理服务合计 123 项通过；C4-03b 已在
auth-service 实现用户级策略核心状态机、M1 `unknown` 迁移、分步首次设置、版本冲突、
失败关闭和回读确认接口，auth-service 当前 26 项测试通过；C4-03c 的管理端额度/模型 API、
幂等签发、issuance journal、自动 apply/readback、同步后交付、失败补偿和启动恢复核心
已实现，并通过 Mock/故障测试；C4-03d 已补管理页额度/模型写表单和员工只读状态门户，
页面 E2E 和失败恢复入口仍未完成；M2-C5 的 operation/audit 查询和四种人工对账
动作已经实现，并通过 Mock/故障测试；C4-04 完整管理到真实 Magpie 策略流 E2E 已实现并通过，
覆盖多凭证、refresh/rotate 继承和故障恢复；M2-D 核心已实现，Mock/集成测试通过；生产验收尚未完成；M3-A 的资源目录、不可变版本、哈希、Ed25519 签名、发布/回滚和资源审计核心已实现并通过 11 项测试，M3-B 的远程 MCP 注册、企业统一端点、工具级授权、健康检查、上游凭据隔离和元数据审计核心已实现并通过 14 项测试，M3-C-1 的同步凭证、desired-state、设备上报、管理员 JSON 查询和客户端 HTTP 传输适配器已实现，M3-C-2 的只读资源/同步管理 API 和管理页面板已实现并通过 5 项新增管理测试，resource-service 通过 15 项测试（11 核心 + 4 控制面），client-sync 通过 26 项测试（18 核心 + 8 传输），admin-service 通过 123 项测试、local-mcp 通过 60 项测试、audit-service 通过 67 项测试（20 事件管道 + 14 内容审计核心 + 13 检索/一次性授权核心 + 20 留存/法律保留/删除证明/加密导出核心），security-service 通过 30 项测试，企业九套回归合计 376 项通过；M3-D 运行时、本地 helper、回环 HTTP server、stdio bridge、受管 Codex `config.toml` 映射和 `setupLocalMcpClient()` 一键配置编排核心已实现签名包、原子安装、权限/能力策略、高风险审批、Secret Broker、JSON-RPC、审计、健康计数、受控环境注入和经过编排入口的真实子进程 E2E，但管理台员工产品流、安装器/Windows 服务、真实 Codex 客户端、生产 launcher/token 轮换和生产验收未完成，M4-A 审计事件管道核心、M4-B 内容审计核心、M4-C 检索/一次性授权核心、M4-D 留存/法律保留/删除证明/加密导出核心和 M4-E 管理侧内容治理已实现，M5-A 检测规则引擎和网关元数据投递核心已实现并通过 17 项规则测试及 12 项 Go 投递测试，M5-B 响应动作状态机与模拟执行核心已实现，但真实执行、管理 UI 和生产验收未完成，M5-C 与 M6 仍未实现；M2-E 的 APR-01a
服务端审批、绑定校验、职责分离、组织范围、一次性消费和启动恢复已实现并通过 Mock/故障
测试，APR-01b 的 HMAC/Mock 外部审批回调适配器也已实现并通过测试；APR-01c 的独立 OIDC
step-up 已实现并通过 Mock IdP 集成测试，NOTIFY-01a 的 transactional outbox、租约、幂等、
退避、死信、重启恢复、deliveries 查询和受审计人工重放已实现并通过 Mock/故障测试；
NOTIFY-01b 的 email/im/webhook/ticketing 渠道管理、渠道测试和统一 HTTPS 网关适配器已实现
并通过 Mock/故障测试；NOTIFY-01c 的 SIEM transport、固定 L0 schema 和 dead-letters API
已实现并通过 6 项专项测试，但真实 SIEM/Collector/Syslog/生产证书尚未验收；NOTIFY-01d 的
规则、抑制、聚合、阈值/延迟升级、dead-letter 受审计重放和运营页已实现并通过 Mock/集成
测试；APR-01d 审批箱、多步骤审批和 APR-01e break-glass 核心已实现；
Docker/Compose、真实 IdP/OA、公司代理和生产验收未完成）

日期：2026-11-03

适用对象：产品、研发、IT 运维、安全、合规、审计

目标仓库：`aimingyi666/magpie`（`yetone/magpie` 的 fork）

## 0. 文档定位

本文件是企业建设的总入口，回答四个问题：

1. 企业版最终要做成什么，员工和管理员分别怎么用。
2. 功能按什么顺序实现，每个阶段的退出条件是什么。
3. 哪些能力复用 Magpie，哪些必须独立建设，如何避免破坏上游同步。
4. 当前什么是真正可用的，什么只是设计，什么必须等生产验收。

详细设计与事实记录仍以以下文档为准：

- [`enterprise-plan-summary.md`](enterprise-plan-summary.md)：面向管理层的一页式完整方案，汇总架构边界、角色流程、E1-E12、R0-R4、唯一实施顺序、当前真实完成度和不能承诺项。
- [`enterprise-feature-spec.md`](enterprise-feature-spec.md)：完整产品、架构、数据模型、API、权限、审计和验收设计；第 0.6、0.7 节分别给出 E1-E12 能力闭环和阶段交付证据，第 25 节是逐项需求追踪矩阵。
- [`enterprise-roadmap.md`](enterprise-roadmap.md)：简版路线图，必须与本文件的里程碑顺序一致。
- [`enterprise-acceptance-checklist.md`](enterprise-acceptance-checklist.md)：从技术试点到生产上线的逐项证据和签字表。
- [`enterprise-implementation-status.md`](enterprise-implementation-status.md)：代码、测试和未验证项的唯一事实记录。
- [`enterprise-deployment.md`](enterprise-deployment.md)：fork 同步、分支保护、部署、MDM 和发布操作。
- [`enterprise-operating-model.md`](enterprise-operating-model.md)：项目 RACI、协作节奏、GitHub 规则、环境晋级、发布证据、成本容量、培训和试点退出。
- [`../enterprise/README.md`](../enterprise/README.md)：当前可运行环境的操作入口。

冲突处理规则：实现状态以 `enterprise-implementation-status.md` 为准；功能边界以
`enterprise-feature-spec.md` 为准；阶段顺序以本文件为准。

### 0.1 一页看懂企业版

**产品定义：** Magpie 企业版不是把个人版 Magpie 改成一个多租户 SaaS，而是“企业可治理的
本地 AI 客户端 + 企业模型/MCP 网关 + 管理控制面”。员工继续使用本地 Agent 和本地 Magpie；
企业只把身份、模型出口、MCP 出口、额度、资源分发和审计集中起来。

```text
员工浏览器 ── OIDC/设备授权 ──┐
                              ├─> 企业控制面
本地 Agent -> 本地 Magpie -> 企业模型/MCP 网关 -> 上游模型/MCP
                              │
                              ├─ auth-service：员工身份、设备、短期凭证
                              ├─ admin-service：管理员、RBAC、额度、模型和操作审计
                              ├─ approval-service：step-up、审批、一次性消费和 break-glass
                              ├─ notification dispatcher：outbox、邮件/IM/Webhook/SIEM/工单
                              ├─ resource：MCP、资源库；audit（M4-A/M4-B/M4-C/M4-D 核心）：L0/L1 事件、L2 内容、检索授权与治理；admin M4-E：审批/step-up 编排、管理台与双层导出
                              └─ IdP/SCIM、Secret Manager、监控、备份
```

**员工最终体验：**

1. 通过公司 OIDC + MFA 登录企业页面。
2. 本地 Magpie/helper 注册设备，拿到短期网关凭证。
3. 本地 Magpie 自动写入企业 Provider，并调用原有的一键配置能力配置 Claude Code、Codex、
   OpenCode 等 Agent。
4. 员工只访问企业模型和企业 MCP；工资条、真实厂商 Key、上游 MCP 凭据都不进入员工机。
5. 员工页面展示本人设备、模型、额度、资源、同步状态和可恢复错误。

**管理员最终体验：**

1. 使用独立管理 OIDC + MFA/ACR 登录管理控制台。
2. 在角色和组织子树范围内查看用户、设备、凭证、模型、额度、用量、MCP、资源和告警。
3. 停用员工、吊销设备、轮换凭证、调额和模型授权均需理由、幂等键和 intent/result 审计；
   高风险动作还要按风险等级完成 step-up 和/或外部审批。
4. 审计员默认只读元数据；正文、导出、角色和留存权限必须单独授予。
5. 任何依赖失败都显示稳定错误或待同步状态，不能把“接口返回成功”当成“网关已经生效”。

**首期生产闭环：** 企业 OIDC 登录 -> 设备注册 -> 短期凭证 -> 本地一键配置 -> 只访问授权
模型/MCP -> 按人/部门看用量 -> 敏感操作可审计 -> 离职/设备丢失可吊销。

**当前事实：** 已完成 M0，以及 M1、M2-A、M2-B、M2-C1、M2-C2、M2-C3 的代码和 Mock/本地
验证；C4-01 有底层机器协议和本地测试，C4-02 有受控适配器和 Mock/故障测试。C4-03a 正式
只读模型目录已实现，管理服务当前 123/123 通过；C4-03b 的用户级策略核心已在 auth-service
实现并通过 26 项测试；C4-03c 的管理端额度/模型 API、新 Key 自动同步后交付、失败补偿和
启动恢复核心已实现并通过 Mock/故障测试，C4-03d 已补管理页额度/模型写表单和员工只读状态门户；
M2-C5 已实现 operation 详情、脱敏审计分页和四种人工对账动作，M2-D 已接入基础审批、操作、
用量/审计查询、对账和 CSV 导出页面，并通过 Mock/集成测试；生产验收尚未完成。
APR-01a 已实现管理写操作的审批请求、风险分级、payload/target 绑定、职责分离、一次性
消费、并发拒绝和启动失败关闭；APR-01b 已实现 HMAC/Mock 外部审批回调适配器；APR-01c
已实现独立 OIDC step-up，均通过 Mock/故障测试和 Mock IdP 集成测试。
C4-04 的完整管理到真实 Magpie 策略流 E2E 已通过，验证模型拒绝、Token 限额、冲突不落盘、
双设备部分失败、refresh/rotate 策略继承、故障后 pending、Journal/孤儿 Key 撤销、恢复同步、
旧 Key `401` 和秘密扫描；C5/M2-D 已完成基础页面接入，但生产验收尚未完成。M3-A 资源目录核心已实现并通过 11 项测试，M3-B 远程 MCP 治理核心已实现并通过 14 项测试，M3-C-1 同步凭证、desired-state、设备上报、管理员 JSON 查询和客户端 HTTP 传输适配器已实现，M3-C-2 只读资源/同步管理 API 和管理页面板已实现并通过 5 项新增管理测试，resource-service 通过 15 项测试（11 核心 + 4 控制面），client-sync 通过 26 项测试（18 核心 + 8 传输），admin-service 通过 123 项测试、local-mcp 通过 60 项测试、audit-service 通过 67 项测试（20 事件管道 + 14 内容审计核心 + 13 检索/一次性授权核心 + 20 留存/法律保留/删除证明/加密导出核心），security-service 通过 30 项测试，企业九套回归合计 376 项通过；M3-D 运行时、本地 helper、回环 HTTP server、stdio bridge、Codex 配置映射和 `setupLocalMcpClient()` 一键配置编排核心已实现，并通过经过编排入口的真实子进程 E2E，但管理台员工产品流、安装器/Windows 服务、真实 Codex 客户端、生产 launcher/token 轮换和生产验收未完成，M4-A 审计事件管道核心、M4-B 内容审计核心、M4-C 检索/一次性授权核心、M4-D 留存/法律保留/删除证明/加密导出核心和 M4-E 管理侧内容治理已实现，M5-A 检测规则引擎和网关元数据投递核心已实现并通过 17 项规则测试及 12 项 Go 投递测试，M5-B 响应动作状态机与模拟执行核心已实现，但真实网关阻断/吊销、真实工单、管理 UI 和生产验收未完成，M5-C OTel/Prometheus/Grafana/生产 SIEM/演练和 M6 仍未实现。M3-C-1/M3-C-2 已接入员工端同步凭证和同步报告 API 及管理页只读资源/漂移视图，但资源发布/回滚 UI、审批联动、本地 helper 安装器/产品入口、目标 Agent 文件映射、Windows ACL、MDM、真实 IdP、浏览器 E2E、Docker/Compose 实机、灰度/自动回滚和生产验收仍未完成。
APR-01d 的审批箱、串并行步骤、quorum、转交和撤回已实现；APR-01e 的 break-glass
15 分钟单次授权、24 小时复核、提醒、通知、审计、API 和管理页已完成 Mock/集成核心；
NOTIFY-01d 的规则、抑制、聚合、升级、dead-letter 受审计重放和运营页已完成 Mock/集成核心；
NOTIFY-01a/01b/01c 已有 outbox、统一 HTTPS 渠道适配器和 SIEM transport，但没有真实厂商
连接器，真实 SIEM/Collector/Syslog/生产证书也未验收；APR-01b 只有
HMAC/Mock 适配器，没有真实 OA 连接器。APR-01c 的 step-up
代码和 Mock IdP 测试已完成，但真实企业 IdP/MFA/OA、Docker Compose、
Windows 计划任务、反向代理、共享卷、真实 OA/IdP/MFA 审批联调和生产浏览器流程、M3-B 远程 MCP
生产验收、客户端资源同步、真实网关正文采集、安全运营和 HA 仍未完成。M3-A/M3-B 只有核心后端；
M3-C-1/M3-C-2 已实现同步控制面、
客户端 HTTP 传输和管理页只读资源/漂移视图，但尚未接入 admin-service 真实审批、资源发布/
回滚 UI、本地 helper 安装器和员工产品流。当前结论只能是“可演示 + 可受控技术试点”，
不能称为“企业生产版已完成”。

### 0.2 完整功能地图

企业功能按 12 个能力域交付。每个能力域都必须同时定义员工体验、管理员入口、服务端权限、
数据事实来源、失败/回滚和验收证据，不能只交一个页面。

| 能力域 | 必须交付 | 优先级 | 阶段 | 当前状态 |
| --- | --- | --- | --- | --- |
| E1 身份与组织 | OIDC+PKCE、MFA/ACR、稳定用户 ID、部门/用户组、角色有效期、SCIM/离职同步 | P0 | M1/M2/M3 | 员工/管理 OIDC 和基础角色已实现；SCIM、完整组织同步未实现 |
| E2 设备与凭证 | 设备注册、心跳、短期 Key、刷新、轮换、吊销、并发保护、合规状态 | P0 | M1/M2 | 本地真实 issuer 链路已通过；真实终端、MDM 和计划任务待验收 |
| E3 员工门户 | 本人身份、设备、Agent、模型、额度、资源、同步和错误；本地 helper 边界 | P0 | M1/M2-D/M3-C | 本人身份、设备、凭证、模型、额度、同步、恢复提示和个人用量/审计结果的只读门户已实现；M3-C-1 已提供设备短期同步凭证和 desired-state/report API；中央资源/漂移视图、本地 helper 安装器/产品入口、目标 Agent 文件映射和网页直接修改本机 Agent 仍未实现 |
| E4 管理控制台 | 独立管理登录、RBAC、组织范围、只读治理、敏感写操作、审批/step-up、操作/审计查询、看板 | P0 | M2-A..E | A/B/C1/C2/C3 已实现；C4-01 已通过本地测试，C4-02 已通过 15 项 Mock/故障测试但待 Docker/真实卷验收；C4-03a 已实现并通过管理服务 123/123，待真实部署验收；C4-03b/C4-03c 核心已通过 auth 26 项测试和管理 API 编排测试；C4-03d/M2-D 已实现基础写操作、审批、operation、用量/审计查询、人工对账和 CSV 导出页面，页面 E2E、失败恢复入口和浏览器 E2E 未完成；M2-C5 的 operation/audit 查询和人工对账后端已通过 Mock/故障测试；APR-01a 的审批、绑定、职责分离和一次性消费、APR-01b 的 HMAC/Mock 回调适配器、APR-01c 的独立 step-up、APR-01d 的审批箱/串并行/quorum/转交/撤回、APR-01e 的 break-glass 15 分钟单次授权和 24 小时复核、NOTIFY-01a 的 outbox 核心、NOTIFY-01b 的渠道管理/HTTPS 适配器、NOTIFY-01c 的 SIEM transport/dead-letters API 和 NOTIFY-01d 的规则/抑制/聚合/升级/运营页已通过 Mock/故障或集成测试；M3-C-2 已提供只读资源/同步面板；M4-E 已接入内容检索、审批/step-up、留存/删除/法律保留和双层加密导出；C4-04 完整管理到真实 Magpie 策略流 E2E 已通过；真实 OA/厂商连接器、真实 SIEM 接收端、真实 IdP/MFA/反向代理、break-glass 告警/工单和生产验收未完成 |
| E5 模型网关 | 模型目录、白名单、路由、回退、额度、限流、价格、稳定模型 ID | P0 | M0/M2-C/M2-D | 基础网关和额度能力已有；部门和真实网关管理闭环待完成 |
| E6 用量与成本 | 人/部门/设备/Agent/模型/Key 的 Token、费用、错误、趋势、导出、预算告警 | P0/P1 | M2-B/D/M5 | 元数据汇总、时间序列、筛选和授权 CSV 导出已有；费用趋势看板、Excel/异步/对象存储导出和预算告警未实现 |
| E7 MCP 治理 | 中央目录、远程 MCP 代理、本地 MCP、工具级 allow/deny、健康检查、限流和熔断 | P1 | M3/M5 | M3-A 可登记 `mcp` 资源类型和签名版本；M3-B 已提供远程 MCP 注册、企业统一端点、工具级权限、健康检查、限流和每服务器熔断核心；管理台、admin-service 真实审批联动、OIDC 组织分配、客户端产品接入尚未完成；M3-D helper/server、stdio bridge、Codex 配置映射和 `setupLocalMcpClient()` 一键配置编排核心已实现，但管理台员工产品流、安装器/Windows 服务、真实 Codex 客户端、生产 launcher/token 轮换和生产验收未实现 |
| E8 企业资源库 | Skills、Instructions、Subagents、模板、不可变版本、签名、审批、同步、漂移和回滚 | P1 | M3 | M3-A 核心后端已实现并通过 11 项测试；M3-C-1 已提供短期同步凭证、desired-state、设备上报和管理员 JSON 查询，resource 15 项、client-sync 26 项测试通过；M3-C-2 已提供管理页只读资源目录和同步报告/漂移可见性；真实审批、资源发布/回滚 UI、发布/回滚审批联动、本地 helper 安装器/产品流、目标 Agent 文件映射和产品级自动回滚未实现 |
| E9 客户端策略 | 企业 Provider/网关锁定、最低版本、强制/推荐资源、离线策略和防绕过 | P1 | M3/M5 | 网络和 Key 基础已有；客户端强制未实现 |
| E10 审计与通知 | L0-L3 分级、脱敏、留存、访问审计；transactional outbox、邮件/IM/Webhook/SIEM/工单和死信 | P0/P1/P2 | M2-E/M4/M5 | 当前有 L0 元数据、M4-A 审计事件管道核心（L0/L1 allowlist 元数据、幂等队列和查询；真实网关正文采集未接入）、M4-B 内容审计后端核心（默认关闭，L2 `text/plain` 流式拼接/脱敏/AES-256-GCM 对象存储）、M4-C 内容检索与一次性授权核心（筛选、签名 cursor、短期一次性 grant、成功/失败访问审计）、M4-D 留存/法律保留/删除证明/加密导出核心、M4-E 管理侧内容治理（OIDC/RBAC/step-up、审批、CSRF、幂等、operation/审计、管理台和双层 AES-256-GCM 导出）、APR-01a 审批系统审计、NOTIFY-01a outbox、NOTIFY-01b 渠道管理/统一 HTTPS 网关适配器、NOTIFY-01c SIEM transport/固定 L0 schema/dead-letters API，以及 NOTIFY-01d 规则/抑制/聚合/升级/受审计重放和运营页；真实网关正文采集、真实厂商连接、真实 SIEM 接收端、WORM/KMS、值班闭环和生产验收未实现/未验收 |
| E11 安全运营 | 异常用量、异地、越权、直连、敏感数据规则、告警、阻断、吊销、审批和 SIEM | P1 | M2-E/M5 | APR-01a 已提供管理写审批与职责分离，APR-01b 已提供 HMAC/Mock 外部回调适配器，APR-01c 已提供独立 step-up，APR-01e 已提供 break-glass 核心，NOTIFY-01c 已提供 SIEM transport；M5-A 检测规则引擎和网关元数据投递核心已实现并通过 17 项规则测试及 12 项 Go 投递测试；M5-B 响应动作状态机与受控模拟执行核心已通过 13 项测试；真实 OA、真实 IdP/MFA、管理 UI、告警/真实阻断自动响应、真实 SIEM 接收端、Docker/Compose、反向代理来源地址、运行中端到端和 break-glass 生产演练未验收 |
| E12 交付与上游治理 | Compose/MDM/内网更新、备份、灰度、回滚、HA、KMS/mTLS、SBOM 和每小时检查上游并创建同步 PR | P0/P2 | 全阶段 | Compose 模板、同步机制和隔离测试已有；自动 PR、生产验收、HA 和供应链未完成 |

审批与通知是横切控制能力，分别归入管理控制台（E4）、审计（E10）和安全运营（E11），
不再单列第 13 个能力域。所有高风险写操作、资源发布、正文访问和安全响应必须复用同一套
`APR-01`/`NOTIFY-01`，不得各模块自行实现。

### 0.3 每个阶段的硬性交付规则

每个功能从设计到上线必须同时具备以下六类证据，缺一项只能标记为“部分验证”：

1. **功能证据：** 员工或管理员可以从正式入口完成操作，不依赖手工改文件或隐藏接口。
2. **权限证据：** 服务端校验会话、RBAC、组织子树和资源范围，跨范围请求被稳定拒绝。
3. **审计证据：** 敏感操作有 intent/result、操作者、目标、理由、前后摘要和 `operationId`。
4. **失败证据：** 依赖超时、审计不可写、部分失败、重复提交和并发冲突都有稳定状态，不伪造成功。
5. **秘密证据：** 响应、日志、审计、镜像和员工机中不出现 Gateway Key、token hash、设备令牌、
   OIDC Secret、issuer Key 或服务令牌。
6. **环境证据：** 真实 IdP、反向代理、Docker、Windows/MDM、真实网关和备份恢复按阶段验收。

### 0.4 完整交付包

| 交付包 | 包含阶段 | 适用对象 | 可以承诺的结论 |
| --- | --- | --- | --- |
| R0 演示包 | M0 + Mock | 产品/研发 | 只做演示，不接真实员工 |
| R1 受控试点包 | M0-M2-B + 真实内网验收 | 5-50 人单部门 | 可做受控技术试点，必须有退出通道 |
| R2 生产候选包 | M0-M2-D + APR-01/NOTIFY-01 基线 | 50-200 人单企业 | 可做正式小范围试用，不得称全公司生产完成 |
| R3 企业生产包 | M3-M5 | 50-500 人 | 可全员推广的单企业生产版 |
| R4 规模化包 | M6 | 500+ 人或强合规 | 多副本、高可用、多地域和强供应链 |

“方案完整”表示范围、顺序、接口、数据、验收和回滚已经定义，不表示 R0-R4 已一次做完。

## 1. 管理层结论

企业版采用三条清晰边界：

```text
员工本地 Magpie / Agent
  -> 企业模型与 MCP 数据面
  -> 企业身份、管理、策略、资源和审计控制面
```

建设原则：

- **不重写 Magpie 模型路由核心。** 复用现有 Provider、路由、额度、Agent 一键配置和
  元数据用量能力。
- **控制面独立部署。** OIDC、管理台、策略、资源库、审计和报表放在 `enterprise/` 独立服务。
- **服务端是最终安全边界。** 页面隐藏按钮不算权限控制；所有读取、写入和模型调用都在服务端
  校验身份、权限和组织范围。
- **浏览器不等于本地权限。** 员工网页可以登录、授权和展示状态，但不能直接修改员工电脑上的
  Agent 文件；一键配置由已安装的本地 Magpie/helper 执行。
- **默认最小审计。** 默认只记录 L0 元数据；对话正文属于 L2/L3，必须单独授权、二次确认并
  记录管理员访问审计。

生产上线的核心闭环：

```text
企业 OIDC 登录
  -> 设备注册和短期凭证
  -> 本地 Magpie 一键配置 Agent
  -> 只能访问企业模型/企业 MCP
  -> 管理员按人/部门/设备/Agent/模型看用量和错误
  -> 敏感操作有 RBAC、组织范围和审计
  -> 离职或设备丢失可立即吊销
```

在真实 IdP、反向代理、Docker、Windows 计划任务和权限演练全部有证据前，只能称为试点，
不能称为“企业生产版已完成”。

## 2. 角色与使用边界

| 角色 | 使用入口 | 默认范围 | 核心能力 |
| --- | --- | --- | --- |
| 员工 | 本地 Magpie + 企业员工页 | 本人 | 登录、注册设备、一键配置 Agent、查看本人模型/资源/用量 |
| 部门管理员 | 管理控制台 | 指定组织单元及子树 | 查看本部门用户、设备、凭证、用量；在授权范围内管理策略 |
| 企业管理员 | 管理控制台 | 全企业 | 组织、模型、MCP、资源、客户端策略和全局报表 |
| 安全管理员 | 管理控制台 | 全域或指定范围 | 规则、告警、阻断、吊销和事件处置 |
| 审计员 | 管理控制台 | 授权部门/时间 | 只读查询元数据和经批准的审计正文，不能修改配置 |
| 运维管理员 | 运维入口 | 基础设施 | 健康检查、备份、升级和应急吊销，默认不看业务正文 |
| 超级管理员 | 管理控制台 | 全企业 | 角色和紧急操作；不能单独删除审计证据或关闭留存 |

强制规则：

- 员工不能查看其他员工、部门汇总、厂商 Key、服务令牌或其他设备数据。
- 部门管理员不能通过 URL、请求体或批量接口跨出组织子树。
- 审计员只读；即使有 `audit.read`，也不自动拥有 `audit.content.read`。
- 查看正文、导出、批量吊销、修改留存和授予高权限必须二次确认、填写理由并写审计。
- 角色撤销和组织调动必须在下一个管理请求生效，不能等待重新登录。

## 3. 端到端使用流程

### 3.1 员工首次加入

1. 员工电脑安装签名版 Magpie 客户端。
2. 员工打开企业加入页，选择“加入组织”。
3. 浏览器跳转企业 IdP，完成 MFA/条件访问。
4. 员工页生成一次性加入码或短时授权结果。
5. 本地 Magpie/helper 使用加入码注册设备并取得短期网关凭证。
6. 本地 Magpie 写入企业 Provider，并调用现有一键配置能力设置 Claude Code、Codex、
   OpenCode 或其他 Agent。
7. 客户端显示网关、模型、策略版本和同步状态。

预期结果：新员工在 5 分钟内可用，不手工复制厂商 Key 或长期网关 Key。

### 3.2 员工日常使用

1. Agent 请求本地 Magpie。
2. 本地 Magpie 使用短期凭证转发到企业网关。
3. 企业网关验证设备、用户、模型、额度、IP 和策略。
4. 网关调用授权模型或远程 MCP，并把元数据写入用量/审计事件。
5. 本地 Magpie 自动续期短期凭证；失败时给出可恢复错误，不自动绕过企业网关。

员工页面展示：

- 企业身份、当前设备、客户端版本和合规状态。
- 可用 Agent、已绑定模型、网关连通性和最近同步时间。
- 已分配的 MCP、Skills、Instructions、Subagents 和模板。
- 本人 Token、费用、额度周期、错误和策略提示。
- 强制资源、推荐资源和同步失败原因。

### 3.3 管理员日常运维

1. 管理员使用独立 OIDC Client 和 MFA 登录管理控制台。
2. 控制台按角色、组织范围和时间范围查询数据。
3. 管理员查看总览、员工、设备、凭证、模型、MCP、资源、用量、告警、审批和操作审计。
4. 写操作先校验权限、目标范围、版本和高风险审批/step-up，再写审计意图，执行后写结果。
5. 邮件、IM、Webhook、SIEM 和工单统一由 outbox 异步投递；管理员可查看重试、死信和抑制状态。
6. auth-service、审批服务、网关、通知 dispatcher 或策略服务不可用时显示稳定错误，不伪造成功状态。

### 3.4 员工离职或设备丢失

1. IdP/SCIM 停用用户，或管理员手动停用。
2. 禁止新的加入、刷新和心跳。
3. 当前短期 Key 进入撤销队列并尽快失效。
4. 已有管理会话、设备令牌和资源访问权限同步失效。
5. 全过程记录操作者、原因、请求 ID 和结果。

## 4. 完整功能目录

| 编号 | 能力域 | 功能 | 优先级 | 当前状态 |
| --- | --- | --- | --- | --- |
| E1 | 身份与组织 | OIDC + PKCE、MFA/ACR、用户、部门、用户组、SCIM | P0 | M1/M2-A 部分实现，SCIM 未实现 |
| E2 | 设备与凭证 | 设备注册、心跳、短期 Key、刷新、吊销、合规状态 | P0 | M1 已实现，真实终端验收待完成 |
| E3 | 员工门户 | 本人身份、设备、Agent、模型、额度、资源和错误；本地 helper 边界 | P0 | 基础员工页、加入脚本、本人额度/模型/凭证/设备只读状态和用量/审计结果已有；中央资源视图、网页直接修改本机 Agent 和完整恢复体验未实现 |
| E4 | 管理控制台 | 独立管理登录、RBAC、组织范围、只读治理、写操作、审批/step-up、查询和看板 | P0 | M2-A/M2-B/M2-C1/M2-C2/M2-C3 已实现；C4-03c 额度/模型 API 和同步后交付核心已实现；C4-03d 部分实现；C4-04 完整管理到真实 Magpie 策略流 E2E 已通过；M2-C5 操作/审计查询与人工对账后端已实现并通过 Mock/故障测试；M2-D 已接入基础写操作、审批、break-glass、operation、用量/审计查询、对账和 CSV 导出页面；APR-01a/b/c/d/e 核心已实现并通过 Mock 测试；浏览器 E2E、失败恢复入口、完整运营看板和 break-glass 生产验收未完成 |
| E5 | 模型网关 | 模型目录、白名单、路由、回退、额度、限流和价格 | P0 | M0 基础已有，部门级治理待实现 |
| E6 | 用量与成本 | 人/部门/设备/Agent/模型/API Key 的 Token、费用、错误和趋势 | P0 | 元数据文件、只读汇总、时间序列、筛选和授权 CSV 导出已有；费用趋势看板、Excel/异步/对象存储导出和预算告警未实现 |
| E7 | MCP 治理 | 中央目录、远程 MCP、本地 MCP、工具级权限、健康检查、限流和熔断 | P1 | M3-B 远程 MCP 治理核心已实现并通过 14 项测试；管理台、真实审批、OIDC 组织分配、员工端同步接入、M3-D helper/server/一键配置编排核心已实现，但管理台员工产品流、安装器/Windows 服务、共享事务存储和生产验收未实现 |
| E8 | 企业资源库 | Skills、Instructions、Subagents、模板、签名、版本、同步和回滚 | P1 | M3-A 已有资源目录、不可变版本、内容哈希、Ed25519 签名、发布/回滚和审计；M3-C-1 已有短期同步凭证、desired-state、设备上报和管理员 JSON 查询，M3-C 客户端已有签名同步、原子安装、离线缓存、强制/推荐策略和漂移检测核心；M3-C-2 已有只读资源/同步管理 API 和管理页面板；真实审批、资源发布/回滚 UI、发布/回滚审批联动、本地 helper 安装器/产品流、目标 Agent 文件映射和产品级自动回滚未实现 |
| E9 | 客户端策略 | 企业网关锁定、Provider 锁定、最低版本、强制资源和防绕过 | P1 | 部分网络/Key 能力已有，客户端强制未实现 |
| E10 | 审计与通知 | L0-L3 分级、脱敏、检索、留存、导出、正文访问；outbox、邮件/IM/Webhook/SIEM/工单 | P0/P1/P2 | 已有 L0 元数据、M4-A 审计事件管道核心（L0/L1 allowlist 元数据、幂等队列和查询；真实网关正文采集未接入）、M4-B 内容审计后端核心（默认关闭，L2 `text/plain` 流式拼接/脱敏/AES-256-GCM 对象存储）、M4-C 内容检索与一次性授权核心（多维筛选、签名 cursor、一次性 grant、访问审计失败关闭）、M4-D 留存/法律保留/删除证明/加密导出核心、M4-E 管理台与 OIDC/RBAC/step-up 编排（审批、幂等、operation/审计和双层加密下载；仅全局范围 `*`，break-glass 禁止）、NOTIFY-01a outbox、NOTIFY-01b 渠道 API/统一 HTTPS adapters、NOTIFY-01c SIEM transport/固定 L0 schema/dead-letters API，以及 NOTIFY-01d 规则/抑制/聚合/升级/受审计重放和运营页；L3、真实网关正文采集、WORM/KMS、真实厂商连接、真实 SIEM 接收端、生产值班和生产验收未实现/未验收 |
| E11 | 安全运营 | 异常用量、敏感数据、越权、直连、告警、阻断和 SIEM | P1 | M5-A 检测规则引擎核心已通过 17 项测试，网关元数据投递核心另有 12 项 Go 测试通过，提供八条规则、确定性 finding/聚合、原始事件保留、抑制标记和默认关闭的元数据导出器；M5-B 响应动作状态机与受控模拟执行核心已通过 13 项测试，覆盖五类动作、审批/职责分离、组织隔离、幂等、撤销和逐动作 hash-chain 审计；管理 UI、真实网关阻断/吊销、真实工单、生产 SIEM、值班处置闭环、Docker/Compose 和运行中端到端未实现 |
| E12 | 交付与上游治理 | Compose、MDM、更新源、备份、HA、KMS、mTLS、多地域和上游同步 | 全阶段 | Compose 模板和更新机制已有，生产验收未完成 |

### 4.1 管理员能看到的员工信息

管理员可见范围由“权限 + 组织 + 资源 + 时间”共同决定，默认包括：

- 身份：姓名、企业邮箱、稳定用户 ID、部门、角色、状态、最后登录。
- 设备：设备名、平台、客户端版本、最后心跳、合规状态、当前 Key 到期时间。
- 凭证：Key ID、状态、模型范围、额度、过期和吊销记录；不返回 Key 明文或哈希。
- 模型：可用模型、路由、价格版本、额度和最近错误。
- 用量：请求数、成功率、Token、缓存、费用、Agent、模型、Provider、时间段。
- 资源：已分配的 MCP、Skills、Instructions、Subagents、版本、同步状态和漂移。
- 安全：异常用量、异地、IP、越权、敏感规则命中和处置状态。
- 审批：风险等级、申请人、审批人、动作、目标、payload 摘要、有效期、状态和消费记录。
- 通知：渠道、事件类型、重试次数、死信、抑制、外部工单 ID 和最近投递错误。
- 管理审计：谁在什么范围、何时、对谁、做了什么、结果和理由。

对话正文单独受控：

- 默认 L0 不包含提示词、回复、附件正文和完整工具参数。
- L1 可包含请求摘要、工具名、参数类别和结果状态。
- L2 只对经过批准的脱敏正文开放，需要 `audit.content.read`。
- L3 原始正文默认禁止，只用于法定调查、双人审批和短保留。
- 每次查看、下载或导出正文都写管理员审计，不能由普通管理员删除。

### 4.2 MCP 与企业资源库

管理员可以集中配置和调控：

- MCP Server 的名称、类型、地址/包坐标、版本、签名、负责人和健康状态。
- 适用部门、用户组、员工、Agent 和项目。
- 工具级 allow/deny、读写属性、风险等级、限流和审批。
- 远程 MCP 的上游凭据只在网关侧；员工机只拿到企业 MCP 地址。
- 本地 MCP 只对受控用户组开放，必须签名、最小权限运行并上报健康状态。
- Skills、Instructions、Subagents 和模板按不可变版本发布，生成签名 manifest。
- 资源可设为强制或推荐；强制资源由客户端锁定，推荐资源允许员工启停。
- 客户端离线使用最后一个已验证版本；升级失败回退上一版本。
- 控制台能看到每个员工/设备的期望版本、实际版本、同步错误和漂移。

### 4.3 方案边界与优先级

本方案的完整范围不是“把 Magpie 改造成一个大而全的 SaaS”，而是形成企业可治理的 AI 客户端
与网关平台。优先级和明确边界如下：

| 优先级 | 范围 | 目标 | 不做什么 |
| --- | --- | --- | --- |
| P0 生产闭环 | OIDC、设备、短期 Key、管理身份、组织范围、只读治理、敏感写操作、管理审计、真实模型网关 | 员工能安全用，管理员能管，离职能吊销 | 不做纯网页改本机 Agent；不保存厂商 Key 到员工机 |
| P1 企业运营 | 中央 MCP/资源库、客户端策略、用量看板、成本预警、L0/L1 审计、告警 | 资源可分发，使用可运营，风险可发现 | 不默认采集 L3 原始正文；不依赖页面隐藏做安全 |
| P2 合规增强 | L2 脱敏正文、导出审批、法律保留、SIEM、安全阻断、双人复核 | 经批准的审计和调查闭环 | 不把“能看正文”作为普通管理员默认权限 |
| P3 规模化 | PostgreSQL/ClickHouse、多副本、Redis、KMS/mTLS、多地域、HA/DR | 500+ 人、稳定性和供应链 | 不在 50 人试点前上 K8s/多地域 |

明确非目标：

- 浏览器不能直接修改员工电脑上的 Agent 文件；必须由已安装的本地 Magpie/helper 执行。
- 管理台可受控查看脱敏正文，但系统默认 L0、默认不采集，正文治理必须显式启用、获得审批并完成 fresh step-up；M4-A 提供 L0/L1 元数据管道核心，M4-B 提供 L2 脱敏正文后端核心，M4-C 提供检索、签名 cursor 和一次性正文 grant，M4-D 提供留存、法律保留、删除证明和加密导出后端核心，M4-E 提供管理台、OIDC/RBAC/step-up、审批、幂等、operation/审计和独立 AES-256-GCM 双层导出；内容治理仅允许全局组织范围 `*`，break-glass 禁止。真实网关正文采集、水印、WORM/KMS、备份恢复和生产验收仍未完成。
- 当前已有 M3-A 内部资源目录核心、M3-B 远程 MCP 治理核心、M3-C-1 同步控制面/客户端同步
  核心和 M3-C-2 只读资源/漂移可见性；设备短期同步凭证、desired-state 和报告 API 已接入，
  但资源发布/回滚 UI、真实审批联动、OIDC 组织分配和本地 helper 安装器/员工产品流尚未完成；
  M3-D 已有 helper/server、stdio bridge、Codex 配置映射和 `setupLocalMcpClient()` 一键配置编排核心，但尚未接安装器、Windows 服务、生产 launcher/token 轮换，且真实 Codex 客户端仍未验收。
- 当前不是生产级高可用；JSON 单实例存储不能宣称多副本一致。
- 企业控制面不替代 IdP、MDM、网络出口、终端 EDR 和法务/合规制度。

## 5. 系统边界与事实来源

| 数据/能力 | 唯一事实来源 | 不得做什么 |
| --- | --- | --- |
| 员工身份、设备、员工短期 Key | `enterprise-auth` | 管理台不能自行复制用户身份或保存设备令牌明文 |
| 角色、组织范围、管理会话、管理审计 | `enterprise-admin` | auth-service 不承载复杂管理后台 |
| 用户与部门映射 | 管理服务的受控组织映射 | 不能只按邮箱域名或姓名猜部门 |
| 模型请求、路由、额度执行 | Magpie Gateway | 管理台不直接代理模型流量 |
| 用量 | 网关 `usage.jsonl`，后续可替换为事件存储 | 不能把不完整文件当成完整报表 |
| MCP/资源发布 | `enterprise-resource` + 对象存储 | 客户端不能执行未签名强制资源 |
| 对话正文 | 独立 `enterprise-audit` | 网关、管理台和日志不能各自保存一份明文 |
| 审批状态与 step-up 断言 | `approval-service` | 业务服务不能信任浏览器提交的 `approvalId`，也不能各自维护审批状态 |
| 通知事件与投递 | notification outbox + dispatcher | 业务请求不能同步发通知，页面不能直接改投递结果 |
| 厂商 Key、issuer Key、服务令牌 | Secret Manager/Vault/KMS | 浏览器、日志、仓库和员工机不能接触 |

内部调用链：

```text
管理员浏览器
  -> admin-service（OIDC + CSRF + RBAC）
      -> auth-service 内部接口（独立服务令牌或 mTLS）
      -> gateway 管理接口/CLI（最小权限）
      -> approval-service（审批校验与一次性消费）
      -> usage/audit 查询接口
      -> notification dispatcher（只经 outbox 异步投递）
```

浏览器永远不能获得 `AUTH_ADMIN_TOKEN`、`AUTH_INTERNAL_ADMIN_TOKEN`、issuer Key、设备令牌、
Gateway Key 或 OIDC Client Secret。

## 6. 唯一实施顺序

### M0：企业网关基线（已完成）

交付：客户端/服务端分离、员工网关 Key、额度、模型白名单、IP 白名单、元数据用量、
Agent 一键配置和可重复 E2E。

退出条件：员工经本地 Magpie -> 企业网关 -> Mock 上游成功；用量可按员工 Key 归属。

### M1：身份、设备与短期凭证（本地链路已完成，生产验收中）

交付：OIDC + PKCE、加入码、设备注册/心跳/刷新/吊销、短期 Key、离职停用和刷新并发保护。

退出条件：真实企业 IdP、Compose、Windows 计划任务、真实反向代理全部通过。

### M2-A：管理身份底座（已实现，Mock 测试通过）

交付：独立管理 OIDC、MFA/ACR、已验证邮箱、管理会话、CSRF、IP 限制、RBAC、组织范围、
内部服务令牌和最小管理页。

退出条件：真实管理 IdP、浏览器、反向代理和至少四类管理员角色演练通过。

### M2-B：只读治理（已实现，Mock 测试通过，生产验收中）

交付：

- 用户、部门、设备、凭证、模型和用量的只读 API。
- 用户与部门的受控映射，不按邮箱猜部门。
- 服务端组织范围过滤和管理页只读列表。
- 部门接口复用 `org_units`，不建立第二套组织数据。

退出条件：企业管理员可读全域；部门管理员只能读本部门子树；跨部门为 `403
forbidden_scope`；响应不含任何 Key、哈希、Cookie 或服务令牌。上述条件已由 Mock 集成测试
覆盖；真实 `usage.jsonl` 数据卷、真实 IdP、浏览器和反向代理尚未验收。

实现证据：管理服务 `82 passed, 0 failed`（62 项管理集成 + 7 项目录专项 + 7 项通知渠道专项 + 6 项 SIEM 专项），auth-service
`25 passed, 0 failed`；覆盖全域/
部门范围、用户详情跨范围拒绝、凭证元数据、用量按人和部门归属、时间序列、损坏和超限文件
拒绝，以及依赖故障。

### M2-C：敏感写操作与管理审计（C1/C2/C3、C4-01/C4-02/C4-03a/C4-03b/C4-03c 核心已完成，C4-03d 部分完成，C4-04 完整策略流已通过，C5 后端已完成）

交付：停用/启用、设备吊销、凭证轮换、额度修改、模型授权、幂等、版本冲突检查和管理审计。

工作包与当前状态：

- **M2-C1（已完成，Mock 测试通过）**：auth-service 内部写接口，停用/启用用户、吊销设备、
  轮换凭证；停用用户时撤销其
  所有设备 Key，吊销设备时撤销当前 Gateway Key，轮换按设备串行化并清理孤儿 Key。
  接口只接受 `AUTH_INTERNAL_ADMIN_TOKEN`，启用不恢复旧设备/旧凭证，轮换响应不含新 Key
  明文，轮换持久化失败会立即撤销新 Key。
- **M2-C2（已完成，Mock 测试通过）**：admin-service 的四个受控写接口：停用/启用用户、
  吊销设备和轮换当前凭证。接口要求管理会话、CSRF、RBAC、组织子树和必填 `reason`；
  `Idempotency-Key` 的持久化、重放和冲突保护由随后的 M2-C3 接入；响应使用字段白名单，
  不返回 Gateway Key、设备令牌、token hash、公钥或服务令牌。
- **M2-C3（已完成，Mock 测试通过）**：`Idempotency-Key` 持久化、同键同请求重放、同键异体
  `409 idempotency_conflict`、执行中 `409 operation_in_progress`、`operationId` 和 intent/result
  管理审计；intent 失败不调用依赖，result 失败不返回成功，审计只追加且不返回任何秘密。
- **M2-C4-01（已实现，本地测试通过）**：schema v1 的 `gateway-key describe <id> --json` 和
  原子 `gateway-key policy apply <id> --json`；64 KiB 输入输出、稳定错误码、无秘密输出、
  `expectedPolicyRevision` 冲突不写文件、文件锁内原子替换和独立回读。
- **M2-C4-02（已实现，Mock/故障测试通过）**：独立 `enterprise/gateway-control/` 适配器；
  只允许 describe、policy apply 和健康检查，固定 argv、`shell: false`、独立服务令牌、
  Key ID 白名单、64 KiB 请求/输出上限、默认 10 秒超时、写后独立回读和稳定错误码；
  Dockerfile 与 Compose profile 已提供，但尚未实机构建和运行。
- **M2-C4-03a（已实现，待真实部署验收）**：管理服务只读正式模型目录；严格 JSON、schema v1、
  2 MiB 上限、稳定模型 ID、显式 Provider 通配符、group 展开、SHA-256 digest 和安全投影；
  坏目录失败关闭。当前管理服务合计 123/123（86 项管理集成 + 5 项内容治理客户端专项 + 5 项内容治理存储专项 + 7 项目录专项 + 7 项通知渠道专项 + 7 项通知规则专项 + 6 项 SIEM 专项）。
- **M2-C4-03b（已实现 auth-service 核心，26 项测试通过）**：版本化用户级
  `gatewayPolicy`、旧 M1 显式迁移为 `unknown`、quota/models 分步首次设置、缺项失败关闭、
  `expectedVersion`/`If-Match`、凭证回读确认，以及 join/refresh/rotate 在签发前门禁。
- **M2-C4-03c（核心已实现，Mock/故障测试通过）**：管理端额度/模型 API 自动编排、
  issuance journal、apply/readback、同步后交付、失败补偿和启动恢复。真实共享卷、
  真实 Magpie、真实 IdP 和真实故障注入仍待验收。
- **M2-C4-03d（部分实现）**：管理页已提供额度/模型策略写表单、CSRF/幂等键/版本/理由提交，
  展示策略版本、逐凭证同步状态、最后同步时间和错误码；员工页已提供本人额度、模型、凭证、
  设备、同步和恢复提示的只读视图。M2-D 已接入基础操作、审批、查询、对账和导出页面；
  浏览器页面端到端测试、失败设备恢复入口和剩余运营体验仍未完成。
- **M2-C4-04（完整管理到真实 Magpie 策略流已通过）**：`c4-enterprise-policy-e2e.ps1`
  已证明首次 join `409 policy_setup_required`、管理 OIDC/CSRF、quota/models 分步设置、
  双设备独立 Key、模型拒绝、Token 限额、精确 `partial_success`、refresh/rotate 策略继承、
  故障后 `unknown/pending_sync`、Journal/孤儿 Key 撤销、恢复同步、usage 归属和秘密扫描。
  `c4-gateway-policy-e2e.ps1` 继续覆盖单 Key 底层行为。
- **M2-C5（后端已实现，Mock/故障测试通过）**：operation 详情、脱敏审计分页、签名 cursor、
  显式重试/回滚和人工确认；对账生成子 operation，原 operation 和审计不可改写。真实审计
  存储、生产查询入口和运维演练仍待验收。

接口基线：

```text
POST /api/v1/admin/users/{id}/disable
POST /api/v1/admin/users/{id}/enable
POST /api/v1/admin/devices/{id}/revoke
POST /api/v1/admin/credentials/{id}/rotate
PUT  /api/v1/admin/users/{id}/quota
PATCH /api/v1/admin/users/{id}/models
GET  /api/v1/admin/audit-logs
GET  /api/v1/admin/operations/{operationId}
```

退出条件：每个敏感操作有 `intent` 和 `result` 审计；审计写入失败时操作失败且依赖调用为 0；
同幂等键重复请求只产生一个有效结果；跨部门写返回 `403 forbidden_scope`；真实网关验证停用、
吊销、轮换、调额和模型授权生效；响应、日志和审计无任何 Key/token/Secret。

当前完成 C1、C2、C3、C4-01、C4-02、C4-03a、C4-03b、C4-03c 的核心链路、C5 后端和 M2-D 基础页面。C4-03c 已把
管理端额度/模型 API、auth-service 幂等签发与 journal、gateway-control apply/独立回读、
原子提交和同步后交付串通，并通过 Mock/故障测试；C4-03d 已补管理页额度/模型写表单和
员工只读状态门户；C4-04 完整管理到真实 Magpie 策略流 E2E 已通过。真实共享卷、真实 IdP、
浏览器 E2E、完整运营查询/对账体验、失败恢复入口和生产环境验收仍未完成。不能把这些切片当作
M2-C 或生产管理台完成。

#### M2-C4：真实网关额度与模型授权（C4-01/C4-02/C4-03a/C4-03b/C4-03c 核心已实现，C4-03d 部分实现，C4-04 完整策略流已通过）

冻结交付物：

1. auth-service 用户级 `gatewayPolicy`：版本、稳定模型 ID、0-5 个额度窗口、
   `known/unknown/pending` 状态、`updatedAt`、`confirmedAt` 和最近 operationId。
2. 每张企业凭证的 `policyVersion`、`policySyncState`、`lastPolicyErrorCode` 和
   `lastPolicySyncedAt`；不得保存 Gateway Key 或 token hash。
3. `PUT /api/v1/admin/users/{id}/quota`：`quota.write`、管理会话、CSRF、组织范围、
   理由、审批、`expectedVersion`/`If-Match`、持久化幂等和 intent/result 审计。
4. `PATCH /api/v1/admin/users/{id}/models`：`models.write`、稳定模型 ID、显式通配符、
   未知模型拒绝、空数组拒绝和同一套版本/幂等/审计语义。
5. 请求指纹必须包含规范化业务 payload；同键不同额度或模型必须返回
   `409 idempotency_conflict`。
6. C4-01 已交付 `gateway-key describe <id> --json` 和
   `gateway-key policy apply <id> --json` 机器契约：只接受 schema v1、无秘密输出、
   64 KiB 输入输出上限、`expectedPolicyRevision` 乐观锁，并在一次文件锁内原子替换模型和
   0-5 个额度窗口。当前实现和本地测试覆盖 schema、64 KiB、冲突、原子替换和回读；10 秒
   调用超时属于 C4-02 适配器，不在 C4-01 的实现范围内。禁止解析人类可读 `limit/models`
   文本作为生产回读依据。
7. C4-02 的 `gateway-control` 受控适配器已实现并通过 Mock/故障测试；管理服务仍禁止直接
   读写 `caller-keys.json`。适配器只执行 describe/apply/健康检查白名单、使用专用服务账号、
   独立服务令牌、超时/输出上限、写入后独立回读和稳定错误映射；Docker/Compose 和真实共享
   卷尚未验收。
8. **C4-03a 正式模型目录（已实现，待真实部署验收）**：admin-service 只读
   `ADMIN_MODEL_CATALOG_PATH`，schema v1、稳定模型 ID、显式 `providerWildcards`、group
   展开、SHA-256 digest 和 2 MiB 上限；坏 JSON、未知字段、重复项、空目录、未知引用均
   失败关闭。`GET /api/v1/admin/models` 已使用正式目录，`ADMIN_MODELS` 只保留兼容显示。
   admin-service 负责展开选择器，auth-service 接收稳定模型 ID，gateway-control 不接收
   group 表达式；C4-04 已验证完整多凭证策略流，真实部署仍待验收。
9. **C4-03b 用户级策略核心（已实现，26 项 auth 测试通过）**：旧 M1 只迁移为
   `quotaStatus=unknown`、`modelStatus=unknown`，不得反推历史额度或模型。quota 与 models
   可任意顺序首次提交，但不得伪造缺失项；缺项返回 `policy_setup_required`。已实现版本
   冲突、回读确认和 join/refresh/rotate 前置失败关闭；管理端自动编排由 C4-03c 补齐。
10. **C4-03c 签发同步后交付（核心已实现，Mock/故障测试通过）**：顺序固定为确认策略 `known` -> issuance journal ->
    签发 Key -> `gateway-control` 应用完整策略 -> 独立 describe 回读 -> 原子持久化 -> 才交付
    客户端。同步完成前不得返回 Key；任一步失败撤销新 Key，撤销失败保留 pending revocation
    和告警。崩溃恢复必须证明没有孤儿 Key，rotate 只能在新 Key 提交后撤销旧 Key。
11. **C4-03d 页面与运营状态（部分实现）**：管理页已展示策略和同步状态，但完整语义仍在实现中。只有 `operation.state=succeeded`、
    `quotaStatus=known`、`modelStatus=known`、全部活跃凭证 `policySyncState=synced` 且
    `requiresReconciliation=false` 时才显示“已生效”。`unknown`、`pending`、
    `partial_success`、`dependency_invoked` 必须显示真实证据和恢复入口，禁止自动重试。
12. 逐凭证串行更新和回读。全部成功才进入 `known`；部分失败返回 `partial_success`
    且保持 `pending`，列出失败 credentialId/deviceId/errorCode。
13. 网关全失败或超时返回 `502 dependency_unavailable`；result 审计失败返回
    `503 audit_unavailable` 且 operation 保持 `dependency_invoked`。
14. 不自动回滚。重试目标策略或回滚上一确认版本必须通过 C5 生成新的子 operation。

必须覆盖的测试：

- 跨部门写拒绝且依赖调用为 0。
- 审计员、只读角色和错误权限键拒绝。
- CSRF、空理由、坏审批 ID、非法额度、重复窗口、超过 5 个窗口拒绝。
- 显示名、空模型数组、裸 `*`、未知模型和隐式扩大 Provider 拒绝。
- `describe --json` 的 schema v1、字段类型、`policyRevision`、64 KiB 上限和失败 JSON 稳定；
  未知 schema、重复字段、尾随 JSON、NaN/Inf 和秘密字段被拒绝。
- `policy apply --json` 在一次文件锁内替换模型和多窗口额度；旧 revision 冲突且不写文件；
  不改变 Key、账户、停用状态、到期时间和已记录用量。
- 缺版本、旧版本和 `If-Match` 不一致分别返回稳定错误。
- 同键同请求只调用一次；同键不同 payload 返回 `409`；执行中返回 `409`。
- 网关超时、退出码异常、回读不一致、全量失败和部分失败不伪造成功。
- 新签发、refresh、rotate 继承当前策略；`pending` 时失败关闭。
- 旧 M1 凭证迁移为 `unknown`，不伪造额度或模型列表。
- 响应、存储、日志和审计无 Key、token hash、设备令牌、Cookie 或 Secret。

真实 Magpie E2E 已在隔离端口、临时 `XDG_CONFIG_HOME` 和临时用户目录中证明：双设备
独立 Key、模型和额度真实生效、零额度/低额度真实限流、`partial_success`、refresh/rotate
策略继承、gateway-control 故障后的 pending、Journal/孤儿 Key 撤销和恢复同步，且不接触
真实用户目录或 `127.0.0.1:3425`。

退出条件：上述测试全部通过，并有真实 Magpie 回读证据；只要页面值变化但真实请求限制
未变化，C4 即判定失败。

#### M2-C5：操作查询、审计查询与对账（后端和基础页面已实现，Mock/故障测试通过）

实现状态：admin-service 已提供 operation 详情、脱敏审计分页和四种人工对账动作；
auth-service 已提供原子 models+limits 对账接口；M2-D 已接入基础 operation/audit 查询、
人工对账和导出页面。权限、组织范围、签名 cursor、脱敏、幂等/冲突、旧快照、依赖/审计失败、
父子 operation 和原审计不可改写均有测试。真实审计存储、生产身份/代理链路、完整运营
查询/对账体验和人工运维演练仍未验收。

冻结交付物：

1. `GET /api/v1/admin/operations/{operationId}`：按原动作权限和组织范围读取真实状态、
   依赖调用时间、错误码、失败凭证、策略版本、重试和对账状态。
2. `GET /api/v1/admin/audit-logs`：支持 operationId、操作者、动作、目标、结果、时间、
   游标分页和最大条数限制；只返回安全元数据。
3. `POST /api/v1/admin/operations/{operationId}/reconcile`：要求
   `operations.reconcile`、CSRF、理由、审批编号和幂等键；动作固定为
   `retry_desired`、`rollback_previous`、`confirm_applied`、`confirm_not_applied`。
4. 对账动作生成子 operation 并追加审计，不修改原始 intent/result。
5. `dependency_invoked`、`partial_success` 和可重试失败必须显示为待处理，不能静默转成
   成功。

退出条件：可从 operationId 串起操作者、目标、前后摘要、依赖结果、失败项、对账动作和
最终状态；查询响应按组织范围授权且不含秘密；人工确认必须带外部证据引用。

#### M2-D：管理写 UI、看板与导出

冻结交付物：

1. 管理页接入停用、启用、吊销、轮换、额度和模型写操作；展示目标、范围、理由、审批、
   当前版本、变更前后摘要、operationId 和真实同步状态。
2. 只有 `succeeded` 显示“已生效”；`partial_success`/`pending`/`failed` 显示失败项和
   对账入口。
3. 旧凭证额度显示“未知”，不得显示 0、无限或默认值。
4. 用量/费用看板按人、部门、Agent、模型和时间筛选；损坏 `usage.jsonl` 不生成部分报表。
5. CSV/Excel 导出使用独立权限、理由、审批、一次性链接和审计。
6. 管理员操作历史从 C5 查询，不从浏览器本地状态或 `usage.jsonl` 推测。
7. 员工本人页只显示本人额度、模型范围、凭证状态和恢复提示；网页不直接修改本机 Agent。

M2-D 启动条件：C4 的真实 Magpie E2E 已通过，C5 的查询/对账 API 和 Mock/故障测试已通过，
页面可以按冻结契约接入；真实审计存储和生产查询入口仍需在 M2-D 上线前验收。M2-D 不得通过
隐藏按钮、前端乐观更新或默认值来弥补 C4/C5 的状态缺口。

当前实现状态：**M2-D 核心已实现，Mock/集成测试通过；生产验收尚未完成。** 已接入基础写操作、
审批、operation、用量/审计查询、人工对账和授权 CSV 导出；尚未实现 Excel、异步大批量导出
或对象存储导出，真实审计存储、浏览器 E2E、负载/并发和运维演练仍需验收。

#### M2-C4/C5/D 分支与证据规则

```text
feat/m2-c4-gateway-policy
feat/m2-c5-operations-audit
feat/m2-d-admin-operations
```

三个分支分别从最新 `origin/main` 创建，PR 前合入 `upstream/main`，不得串联成一个大 PR。
每个 PR 必须包含代码、测试、文档、回滚说明、实际命令、原始输出路径、未验证项和秘密扫描
结果。C4 未通过前不开始 C5；C5 后端与 Mock 对账闭环未通过前，不开始 D 的查询/对账页面。

### M2-E：审批、重新认证与通知投递（APR-01a-e 与 NOTIFY-01a-d 核心已实现）

交付：统一 `APR-01` 和 `NOTIFY-01`，供管理写操作、资源发布、正文访问和安全响应复用。

- `APR-01a`：已实现风险等级、规范化 payload、审批绑定、状态机、职责分离、组织范围、
  一次性消费、并发/重启失败关闭和审批系统审计。
- `APR-01b`：HMAC/Mock 外部审批回调适配器已实现原始 body 验签、时间窗、nonce 防重放、
  issuer/audience、eventId 幂等和系统审计；真实 OA/飞书/ServiceNow/Jira 连接器待建。
- `APR-01c`：step-up；独立管理 OIDC Client、MFA/ACR、authTime、短有效期和会话/IP/角色绑定。
- `APR-01d`：内置审批箱、串并行步骤、转交/撤回和双人复核。
- `APR-01e`：break-glass；15 分钟单次授权、24 小时事后复核、提醒、通知、审计、API 和管理页
  已完成 Mock/集成核心；真实高风险告警/工单和生产复核演练待验收。
- `NOTIFY-01a`：transactional outbox、租约、幂等、指数退避、死信、重启恢复和人工重放已实现，
  并通过 Mock/故障测试；默认禁用渠道，未启用渠道或没有 transport 时不创建 dispatcher。
- `NOTIFY-01b`：email/im/webhook/ticketing 渠道管理、渠道测试和统一 HTTPS 网关适配器已实现；
  含 SSRF、重定向和 DNS rebinding 防护。邮件/IM/工单是网关契约，不是原生厂商 SDK，真实
  飞书/Teams/Slack/ServiceNow/Jira 连接和生产投递未验收。
- `NOTIFY-01c`：SIEM（OTel/Syslog/HTTP）、稳定事件 schema 和 dead-letters API 已实现；
  critical 优先和 5 分钟轮询上限已通过 Mock/故障测试，真实 SIEM/Collector/Syslog、
  生产证书和值班看板未验收。
- `NOTIFY-01d`：渠道、规则、投递、抑制、聚合、阈值/延迟升级、死信和受审计重放运营页已完成
  Mock/集成核心；真实厂商渠道、真实 IdP/MFA、浏览器 E2E 和生产值班闭环待验收。

固定顺序：

```text
ENV-01
  -> C4-02 [done] -> C4-03a [done] -> C4-03b [core done] -> C4-03c [core done] -> C4-03d [partial] -> C4-04 [done]
  -> C5 [backend done]
  -> APR-01a [done] -> APR-01b [adapter done] -> APR-01c [done]
  -> NOTIFY-01a [done] / 01b [done] -> NOTIFY-01c [transport done]
  -> M2-D
  -> APR-01d [done] -> APR-01e [core done] + NOTIFY-01d [core done]
  -> M3/M4/M5
```

退出条件：缺失、伪造、过期、撤销、跨组织、跨动作、payload 改变、自审批和重复/并发消费的
审批全部失败关闭；APR-01a 已覆盖缺失、伪造、过期、撤销、跨组织、跨动作、payload 变化、
自审批和重复/并发消费；APR-01b 已覆盖 HMAC/Mock 验签、时间窗、nonce 防重放、issuer/
audience 和 eventId 幂等；未完成 step-up 的高风险操作依赖调用为 0；业务成功和 outbox 同事务提交；
渠道故障、重启、重试和死信不丢事件、不伪造业务结果；Webhook SSRF、SIEM 脱敏和人工重放
均有证据。R2 生产候选必须包含 `APR-01a/b/c` 与 `NOTIFY-01a/b/c` 的验收记录。

### M3：中央 MCP 与企业资源库

- M3-A（核心已实现）：资源目录、不可变版本、哈希、Ed25519 签名、内容寻址对象存储、
  发布/历史回滚、乐观并发、幂等和资源审计。
- M3-B（核心已实现）：远程 MCP 注册、企业统一端点、工具级权限、健康检查、凭据隔离和
  元数据审计；管理台、真实审批联动、OIDC 组织分配、客户端同步、共享事务存储和生产验收
  未完成。
- M3-C-1（控制面与核心已实现）：设备短期同步凭证、desired-state、设备上报、管理员 JSON
  查询、HTTP 传输、签名 desired-state、原子安装、失败保留旧版本、离线缓存、强制/推荐资源、
  漂移检测、路径/符号链接防护、并发锁和状态秘密隔离；M3-C-2 已提供管理页只读资源/漂移
  可见性。资源发布/回滚 UI、发布/回滚审批联动、本地 helper 安装器/产品入口、目标 Agent 文件映射、
  Windows ACL、MDM、真实 IdP、浏览器 E2E、Docker/Compose 实机、灰度/自动回滚和生产验收未完成。
- M3-D（运行时、helper、回环 HTTP server、stdio bridge、Codex 配置映射和一键配置编排核心已实现）：
  受控本地 MCP 签名包、最小权限、策略审批、Secret Broker、JSON-RPC、审计、健康上报、
  `setupLocalMcpClient()` 同步/选包/启动/写入/回读/受控环境注入和经过编排入口的真实子进程
  E2E；管理台员工产品流、安装器/Windows 服务、真实 Codex 客户端、生产 launcher/token
  轮换、外部 OS 沙箱和生产验收未完成。

退出条件：管理员发布后指定员工在 5 分钟内可见；未授权员工不可见、不可调用；强制资源不能
被关闭；升级失败回退上一版本。当前 M3-C-2 只提供只读可见性，M3-A/M3-B 尚未接入
admin-service 真实审批和可写管理台，因此不满足 M3 整体退出条件。

### M4：会话与工具审计

- M4-A：请求/回复/tool_call/policy_decision 事件、请求 ID、会话索引、幂等和异步重试。
  管道核心已实现并通过 20 项测试；真实网关/UI、管理员 OIDC/RBAC、组织范围、积压告警和生产验收未完成。
- M4-B：流式拼接、脱敏、分片和对象存储。
  后端核心已实现并通过 14 项测试（audit-service 合计 47 项）；默认关闭，只接受
  L2 `text/plain`，拒绝 L3/附件/二进制/未知字段；支持分片顺序/偏移/幂等/冲突/乱序/
  TTL/容量、重启中断恢复、统一脱敏、AES-256-GCM 对象存储和访问审计。
  真实网关正文采集、管理员 OIDC/RBAC/组织范围、管理台检索/查看、显式授权/二次确认、
  水印、留存删除、删除证明、法律保留、WORM、加密导出、Docker/Compose、真实 IdP、
  浏览器 E2E 和生产验收未完成。
- M4-C：按员工/部门/时间/模型/工具检索和正文一次性授权。
  后端核心已实现并通过 13 项测试：固定排序、筛选绑定签名 cursor、管理员/组织/会话/
  目标/用途/理由/审批绑定、15-300 秒 TTL、持久化一次性消费、成功/失败访问审计和
  审计失败关闭。管理员 OIDC/RBAC/step-up 编排、管理 UI、浏览器 E2E、真实网关和
  生产验收未完成。
- M4-D：留存、删除证明、法律保留、加密导出和访问审计。
  后端核心已实现并通过 20 项测试（audit-service 合计 67 项）；正文/元数据留存独立计算，
  后台/显式 `dryRun` 清扫，活动法律保留阻止删除和脱敏，幂等删除/脱敏、staging 恢复、
  HMAC 删除证明、AES-256-GCM `.mge` 导出、一次性下载 token、过期/孤儿清理和治理令牌
  分离已覆盖。管理 UI、真实网关采集、admin-service 审批/step-up 编排、WORM/KMS、
  PostgreSQL/HA、Docker/Compose 实机、真实 IdP/MFA、备份恢复和生产验收未完成。
- M4-E：管理员内容治理已接入管理台、OIDC/RBAC/step-up、审批、CSRF、幂等、operation/审计、
  一次性正文读取、留存/删除/法律保留和双层 AES-256-GCM 导出；默认关闭，仅允许全局组织
  范围 `*`，break-glass 禁止。真实网关采集、WORM/KMS、HA、备份恢复、浏览器 E2E 和正式验收
  未完成。

退出条件：L0 完整可检索；正文只在授权场景可见；敏感字段落盘前被处理；删除和留存可验证。
M4-A/M4-B/M4-C/M4-D/M4-E 核心已实现，但不等于 M4 整体完成；管理台可在显式启用、授权、
审批和 fresh step-up 下查看脱敏正文并执行留存、删除、法律保留和导出，但默认 L0、默认不采集，
真实网关正文采集、L3、水印、WORM/KMS、HA、备份恢复和生产验收仍未完成。

### M5：安全运营与可观测性

- M5-A：敏感数据、异常用量、预算阈值、异地、越权、直连和设备不合规规则。
  规则引擎核心已实现并通过 17 项测试，网关元数据投递核心另有 12 项 Go 测试通过；
  管理 UI、Docker/Compose、反向代理来源地址、运行中端到端和生产规则验收未完成。
- M5-B：告警、限流、阻断、吊销、设备锁定和工单联动。状态机、审批门禁、幂等、撤销、失败状态和逐动作 hash-chain 审计核心已实现；当前只做受控模拟执行（`gatewayApplied: false`），真实网关执行、真实工单、管理 UI 和生产验收未完成。
- M5-C：OTel、Prometheus/Grafana、SIEM、值班手册和故障演练。未实现；现有
  NOTIFY-01c SIEM transport 不等于生产可观测性或值班闭环。

退出条件：典型违规和故障 5 分钟内可见；严重事件可一键处置并留下完整证据。

### M6：规模化、高可用与供应链

- M6-A：PostgreSQL/ClickHouse、迁移、备份和恢复。
- M6-B：网关/控制面多副本、Redis 限流和灰度。
- M6-C：Vault/KMS、mTLS、SBOM、镜像签名、扫描和多地域。

退出条件：容量压测、单节点故障、RPO 15 分钟、RTO 2 小时和回滚演练全部通过。

## 7. 阶段工作量与预期效果

以下为规划假设，不是当前承诺；真实工期取决于 IdP、网络、合规和 UI 范围。

| 阶段 | 参考工期 | 主要角色 | 预期效果 |
| --- | --- | --- | --- |
| M0 | 已完成 | 平台研发、运维 | 5-10 人可经企业网关使用并按 Key 计量 |
| M1 生产验收 | 1-2 周 | 身份、平台、IT | 员工 OIDC 加入，5 分钟可用，短期 Key 自动续期 |
| M2-A 生产验收 | 1 周 | 平台、IT、安全 | 管理员可安全登录，角色和组织范围生效 |
| M2-B | 1-2 周 | 后端、前端 | 管理员看得到人、设备、凭证、模型和用量，范围不越权 |
| M2-C1 | 已完成，Mock 测试通过 | 后端、安全 | Auth 内部停用/吊销/轮换完成；管理台仍需通过后续管理 API/UI 接入 |
| M2-C2 管理写 API | 已完成，Mock 测试通过 | 后端、安全 | 停用/启用、吊销、轮换可由管理 API 执行；已接入 C3 幂等和审计 |
| M2-C3 幂等与管理审计 | 已完成，Mock 测试通过 | 后端、安全 | 写操作可幂等重放、冲突被拒绝、可用 `operationId` 追溯 intent/result |
| M2-C4-01 网关机器协议 | 已完成，本地测试通过 | 后端、安全 | 提供 schema v1 的策略回读和原子写入，后续适配器可稳定调用 |
| M2-C4-02 `gateway-control` | 已完成，Mock/故障测试通过 | 后端、安全 | 管理服务可经最小特权适配器受控回读/写入网关策略；真实管理 API 接入和 Compose 待验收 |
| C4-03d 剩余/M2-D + C5 真实验收 | 1-2 周 | 后端、前端、安全 | M2-D 核心页面和 CSV 导出已通过 Mock/集成测试；继续完成真实共享卷/审计存储、浏览器 E2E、失败恢复入口、负载/并发和生产验收 |
| M2-E 剩余审批与通知投递 | 1.5-2.5 周 | 后端、安全、IT | APR-01a 审批和一次性消费、APR-01b HMAC/Mock 回调适配器、APR-01c 独立 step-up、APR-01d 审批箱/多步骤审批、APR-01e break-glass 核心已实现；剩余真实 OA/IdP/MFA/反向代理验收、break-glass 告警/工单与生产复核演练，以及通知投递 |
| M2-D | 核心已实现，生产验收未完成 | 前端、数据、安全 | 部门成本和异常使用可查询、可对账、可导出；真实环境和浏览器验收待完成 |
| M3 | 4-6 周 | 平台、前端、安全 | 中央 MCP/资源库可控分发、版本化、可回滚 |
| M4 | 4-6 周（M4-A/M4-B/M4-C/M4-D 后端核心和 M4-E 管理侧治理已实现，M4 整体未完成） | 网关、后端、安全 | M4-A 管道核心通过 20 项测试，M4-B 内容审计核心通过 14 项测试，M4-C 检索/一次性授权核心通过 13 项测试，M4-D 留存/保留/证明/导出核心通过 20 项测试，M4-E 管理台、审批/step-up、operation/审计和双层加密导出通过 10 项管理专项测试；还需真实网关采集、水印、WORM/KMS、HA、备份恢复和生产验收，方可宣称经授权的会话/工具审计可检索、可留存、可删除、可导出 |
| M5 | 3-4 周（M5-A 规则与网关投递核心、M5-B 响应动作状态机与模拟执行核心已实现，M5 整体未完成） | 安全、SRE | M5-A 八条检测规则、确定性 finding/聚合、抑制标记和网关元数据导出器已通过 17 项规则测试及 12 项 Go 投递测试；M5-B 五类响应动作、审批/职责分离、组织隔离、幂等、撤销、失败状态和逐动作 hash-chain 审计已通过 13 项测试，但当前 `gatewayApplied: false`；仍需管理 UI、运行中端到端与反向代理验收、真实网关阻断/吊销、真实工单、OTel/Prometheus/Grafana、生产 SIEM、值班手册和演练，方可实现典型事件 5 分钟可见与闭环处置 |
| M6 | 4-8 周或按需 | SRE、平台 | 多副本、共享存储、密钥托管、RPO/RTO 达标 |

建议最小团队：

- 1 名架构/技术负责人，负责边界、评审和上游兼容。
- 2 名后端/平台研发，负责 auth、admin、gateway 集成和策略。
- 1 名前端研发，负责员工页和管理控制台。
- 1 名 SRE/IT，负责 IdP、反向代理、Docker、MDM、备份和监控。
- 安全/合规和审计各指定一名固定评审人。

### 7.1 实施关键路径

不能并行堆所有功能。关键路径固定如下：

```text
现有 M1/M2-A/M2-B/M2-C1/C2/C3
  -> 真实环境验收（IdP、代理、Docker、Windows、用量卷）
  -> M2-C4 真实网关调额/模型授权
  -> M2-C5 操作/审计查询与失败对账 [backend done]
  -> APR-01a [done] -> APR-01b [adapter done] -> APR-01c step-up 与真实 OA
  -> NOTIFY-01a/b/c [done/transport done] outbox、渠道与 SIEM
  -> M2-D 完整管理运营 UI、用量/费用看板和授权导出
  -> APR-01d [done] -> APR-01e [core done] + NOTIFY-01d [core done]
  -> break-glass 生产告警/工单/复核、真实渠道与通知值班验收
  -> M2 生产候选验收（必须含审批和通知证据）
  -> M3 中央 MCP/资源库/客户端策略
  -> M4 会话与工具审计
  -> M5 安全运营和可观测性
  -> M6 高可用、共享存储、KMS/mTLS 和规模化
```

当前开发排序必须是：

1. **先验收已有链路。** 不在真实 IdP、代理、Docker、Windows 和真实 `usage.jsonl` 未验证时，
   继续堆管理页面或正文审计。
2. **先做 C4 再做 C5。** 调额/模型授权必须先证明真实 Magpie 网关生效，才允许提供操作查询和
   “已生效”状态；否则查询只能显示“待同步/未知”。
3. **先做 C5 再做 D。** `dependency_invoked`、审计失败和部分成功必须有对账入口，页面才有
   资格展示写操作历史。
4. **先做审批/通知再做高风险页面。** 管理页写操作和资源发布前必须有服务端审批、step-up、
   一次性消费和 outbox；页面不能只传一个 `approvalId` 就当作已批准。
5. **先锁出口再做资源。** M3 的 MCP/资源下发必须同时有 Provider/网关锁定、签名和回滚，
   不能只做一个资源列表。
6. **先控制可见再做正文。** 员工能使用什么模型和 MCP 尚未锁住前，不开展正文采集。

## 8. 数据与 API 底线

### 8.1 稳定标识

- 用户主键使用 IdP `issuer + subject` 派生 ID，不按邮箱合并。
- 模型权限使用稳定模型 ID，不使用显示名。
- Gateway Key ID 可展示，Key 明文、token hash、设备令牌和 issuer Key 永不返回。
- 组织单元使用不可变 ID 和 `path` 表达子树，禁止环路。

### 8.2 M2-B 只读接口

```text
GET /api/v1/admin/users
GET /api/v1/admin/users/{id}
GET /api/v1/admin/departments
GET /api/v1/admin/devices
GET /api/v1/admin/credentials
GET /api/v1/admin/models
GET /api/v1/admin/usage/summary
GET /api/v1/admin/usage/timeseries
```

统一错误码至少包括：

```text
unauthenticated
forbidden_role
forbidden_scope
csrf_invalid
target_not_found
dependency_unavailable
storage_unavailable
```

服务端顺序固定为：认证 -> 权限 -> 组织范围 -> 目标存在性 -> 查询 -> 脱敏输出。

### 8.3 用量读取

当前企业网关容器使用 `XDG_CONFIG_HOME=/config`，用量文件为：

```text
/config/magpie/usage.jsonl
```

管理服务只能只读挂载网关数据卷，例如：

```yaml
volumes:
  - magpie-data:/magpie-readonly:ro
```

并设置 `ADMIN_USAGE_PATH=/magpie-readonly/magpie/usage.jsonl`。读取器必须限制单行长度和字段
数量；损坏、缺失或不完整时返回稳定依赖错误，不能把部分数据伪装成完整报表。

## 9. 安全与合规门槛

上线前至少完成：

- 真实 IdP 的登录、MFA、ACR、JWKS、回调、Claim、停用和会话过期。
- 管理域名 HTTPS、可信反向代理、Cookie 域、公司 CA 和 IP 允许列表。
- 厂商 Key 只在网关或 Secret Manager；仓库、镜像、日志和员工机不含明文。
- 员工机只保存受 ACL 保护的设备凭据和短期 Key。
- 管理审计与业务审计分离；查看/导出正文有独立权限、理由和审批。
- 默认 L0；L2/L3 必须通过员工告知、安全评审和数据保护影响评估。
- 网关、控制面和审计面的备份、恢复、灰度、回滚和值班责任明确。
- 至少一次跨部门越权、泄露 Key、离职吊销和设备丢失演练。

## 10. 测试与验收策略

每阶段必须同时具备：

- 单元测试：权限、范围、签名、脱敏、解析和状态机。
- 集成测试：真实服务间认证、超时、重试、幂等和依赖故障。
- E2E：员工加入、Agent 配置、模型调用、用量归属、刷新、停用和重启。
- 安全测试：未登录、越权、CSRF、跨部门、秘密泄露和损坏数据。
- 运维测试：Compose/健康检查、备份、恢复、升级和回滚。

每阶段交付必须记录：

1. 实际修改了哪些文件。
2. 实际运行了哪些命令。
3. 测试结果是否为 `X passed, 0 failed` 或明确的 E2E PASS。
4. 哪些环境未验证，例如真实 IdP、Docker、浏览器、代理或公司网络。
5. 是否可试点、适用人数和回退方式。

“代码写了”“接口设计好了”“Mock 通过”都不能替代生产验收。

## 11. Fork 兼容与发布纪律

- `main` 只用于同步上游和合入已验收企业提交，禁止直接开发。
- 每个功能从最新 `main` 开 `feat/*`，小步提交，定期合并 `upstream/main`。
- 企业能力优先放 `enterprise/*` 独立服务；其次插件/中间件；只有无法避免时才加最小核心
  hook。
- 核心 hook 默认关闭，有开关、超时、降级和独立测试，不改变个人用户默认行为。
- 企业发布只从验证过的 `release/e*` 分支或 tag 构建，不直接从开发分支发布。
- 上游同步失败时，企业发布停在最后一个已验证版本，不阻塞上游同步。
- 每次上游变更后跑 M0/M1/M2 关键回归、权限、脱敏、迁移和构建测试。

### 11.1 分支与合并规则

这些规则是强制项，不是建议：

| 规则 | 要求 |
| --- | --- |
| `main` | 只接收上游同步和已验收企业 PR；禁止直接开发、直接提交和直接推送 |
| 功能分支 | `feat/<issue或模块>-<短描述>`，例如 `feat/m2-c4-gateway-policy` |
| 修复分支 | `fix/<模块>-<短描述>`；安全修复使用 `security/<编号>-<短描述>` |
| 发布分支 | `release/ent-YYYY.MM.DD-N` 或不可变 tag `ent-vYYYY.MM.DD-N` |
| 分支起点 | 必须从最新 `origin/main` 创建；不得从另一个未验收功能分支“搭车” |
| 上游同步 | 开发者每天或至少每次提 PR 前将 `upstream/main` 合入功能分支并解决冲突；自动化只创建同步 PR，不直推受保护 `main` |
| PR 大小 | 一个 PR 只解决一个能力或一个明确缺陷；包含代码、测试、文档和回滚说明 |
| PR 门禁 | 至少 1-2 人 Review；语法/单测/集成/E2E/秘密扫描全部通过 |
| 核心改动 | 修改上游跟踪文件必须有 ADR、开关、默认关闭、降级路径和额外回归 |
| 合并方式 | 功能分支通过 PR 合入；禁止强制推送 `main`；不自动删除失败分支 |
| 发布 | 只从已验收 commit/tag 构建；发布记录必须关联 PR、测试证据和回滚点 |

推荐每个 PR 固定包含：

```text
1. 变更目的与影响范围
2. 是否修改上游跟踪文件；如果修改，为什么不能放在 enterprise/ 或插件
3. API、数据迁移和兼容性说明
4. 权限、组织范围、审计和秘密处理
5. 失败、重试、回滚和灰度策略
6. 实际执行的测试命令与结果
7. 尚未验证的真实环境项
```

上游同步目标态固定为：每小时创建 `sync/upstream-<时间戳>` -> 合并 `upstream/main` -> 运行
Go/Node/前端/安全扫描和关键 E2E -> 自动创建 PR -> 必需检查通过后合入受保护 `main`。同步
PR 失败或冲突时不覆盖、不 reset、不跳过门禁，保留同步分支并告警。

自动同步上游失败时，处理顺序是：保留 `main` 最后一个已验证状态 -> 在单独同步分支解决冲突
-> 全量回归 -> PR 合入。不能为了“保持实时”直接覆盖企业代码，也不能让同步失败阻塞紧急安全
修复；两条线通过分支和 release 点隔离。

## 12. 当前立即执行清单

| 顺序 | 任务 | 当前状态 | 完成证据 |
| --- | --- | --- | --- |
| 1 | Docker Compose `auth`/`admin` 构建、健康检查、持久化和重启 | 未执行，当前机器无 Docker CLI | 干净环境 Compose 日志和验收记录 |
| 2 | Windows 用户会话计划任务刷新、锁、网络恢复和 ACL | 未执行 | 至少一次真实自动刷新和不含 Key 的日志 |
| 3 | 真实员工/管理 IdP 登录、MFA/ACR、Claim 和停用 | 未执行 | 两个独立 OIDC Client 的 E2E 记录 |
| 4 | HTTPS 反向代理、Cookie、公司 CA 和内部服务令牌隔离 | 未执行 | 浏览器 E2E 和网络抓包/日志检查 |
| 5 | 四类管理员角色与跨部门拒绝演练 | 部分 Mock 通过 | 真实账号逐项验收表 |
| 6 | M2-B 只读治理 | 已实现，Mock 测试通过 | 只读 API、范围过滤、用量读取；管理 `123/123`、auth `26/26`；真实数据卷待验收 |
| 7 | M2-C1 Auth 内部写接口 | 已实现，Mock 测试通过 | 仅服务间令牌；停用/启用、设备吊销、当前凭证轮换 |
| 8 | M2-C2 管理写 API | 已实现，Mock 测试通过 | 管理会话、CSRF、RBAC、组织范围、理由和响应脱敏；真实环境待验收 |
| 9 | M2-C3 幂等、管理审计和 `operationId` | 已实现，Mock 测试通过 | 审计失败拒绝、同键重放/冲突、失败重放和 `operationId` 追溯证据；管理 `123/123` |
| 10 | M2-C4-01 网关机器协议 | C4-01 已实现，本地测试通过 | schema v1、64 KiB、冲突、原子替换、独立回读和秘密扫描 |
| 11 | C4-02 `gateway-control` 受控适配器 | 已实现，Mock/故障测试通过 | 固定 argv、服务令牌、脱敏、超时、输出上限、写后回读和故障 `pending`；Docker/Compose 与真实卷待验收 |
| 12a | C4-03a 正式只读模型目录 | 已实现，待真实部署验收 | schema v1、严格 JSON、2 MiB、稳定 ID、Provider 通配符、group、digest、安全投影和坏目录失败关闭；管理 `123/123`；管理写接口已接入目录选择器并展开为稳定模型 ID |
| 12 | C4-03c 管理 API、签发同步与交付 | 核心已实现，Mock/故障测试通过 | 管理端额度/模型 API、自动 apply/readback、issuance journal、同步后交付、失败补偿和启动恢复；真实环境待验收 |
| 12b | C4-04 完整管理到真实 Magpie 策略流 E2E | 已实现并通过 | 管理 OIDC/CSRF、quota/models 分步设置、双设备 Key、模型拒绝/限额、部分失败、refresh/rotate 继承、故障后 pending、Journal/孤儿 Key 撤销、恢复同步、usage 归属和秘密扫描 |
| 12c | C4-03d 剩余 + M2-D 页面 | M2-D 核心已实现；生产验收未完成 | 管理页已有基础写操作、审批、operation、用量/审计查询、人工对账和 CSV 导出；员工只读状态门户已有；浏览器 E2E、失败恢复入口、完整运营体验和生产验收未完成 |
| 13 | APR-01 审批与 step-up | APR-01a/b/c/d/e 核心已实现 | APR-01a 已覆盖风险矩阵、payload/目标绑定、自审批拒绝、一次性消费、操作串联和启动恢复；APR-01b 已覆盖 HMAC/Mock 验签、时间窗、nonce 防重放、issuer/audience、eventId 幂等和系统审计；APR-01c 已覆盖独立 OIDC Client、PKCE、`prompt=login`、`max_age`、`auth_time`、ACR/MFA、会话/IP/UA/角色范围绑定和失败关闭；APR-01d 已覆盖审批箱、串行/并行步骤、quorum、转交、撤回和外部回调 `stepId`；APR-01e 已覆盖 15 分钟单次授权、24 小时复核、提醒、通知、审计、API 和管理页；真实 OA、真实 IdP/MFA/反向代理、break-glass 告警/工单和生产复核验收未完成 |
| 14 | NOTIFY-01 outbox 与多渠道投递 | NOTIFY-01a/01b/01c/01d 已实现并通过 Mock/集成测试 | outbox 原子提交、租约、幂等、退避、死信、重启恢复、deliveries 查询和人工重放，渠道管理、渠道测试、邮件/IM/Webhook/工单 HTTPS 网关适配器、SSRF 防护，SIEM transport/固定 L0 schema/dead-letters API，以及规则/抑制/聚合/阈值与延迟升级/运营页有 Mock/故障或集成证据；真实厂商连接、真实 SIEM 接收端和生产投递未验收 |
| 15 | M2-D 看板和导出 | 核心已实现，Mock/集成测试通过；生产验收未完成 | 按人/部门/模型筛选、基础写操作、审批、operation、用量/审计查询、人工对账和授权 CSV 导出；Excel、异步/对象存储导出、浏览器 E2E、负载和完整运营看板未完成 |

## 13. 上线决策

以下任一条件成立时不得全量上线：

- 真实 IdP、真实网关 issuer 或真实 Windows 客户端链路未验收。
- 部门管理员存在跨部门读取或写入路径。
- 管理写操作不能证明“谁做了什么、结果是什么”。
- 对话正文治理虽已接入受控授权、脱敏、留存、删除和访问审计，但真实网关采集、水印、
  WORM/KMS、备份恢复或生产浏览器 E2E 尚未验收。
- 员工可以绕过企业网关直连厂商或未授权 MCP。
- Docker、安装包、更新源未从干净环境构建。
- 备份恢复、灰度或回滚未演练。
- 上游同步后关键回归失败。

企业版的正式完成标准不是“功能列表全勾选”，而是员工能安全使用、管理员能证明治理、
安全能审计处置、运维能恢复回滚，并且上游仍可持续同步。

## 14. 完整需求基线与交付包

`enterprise-feature-spec.md` 第 25 节已经把企业功能拆成可追踪的需求 ID、交付包、端到端
场景和完成定义。实施时按以下优先级使用，不得跳级宣称完成：

| 交付包 | 对应阶段 | 适用规模 | 不允许宣称的内容 |
| --- | --- | --- | --- |
| R0 演示包 | M0 + Mock | 研发/产品 | 不能接真实员工，不能称试点 |
| R1 受控试点包 | M0-M2-B + 真实环境验收 | 5-50 人单部门 | 不能称生产候选 |
| R2 生产候选包 | M0-M2-D | 50-200 人单企业 | 不能称全公司生产完成 |
| R3 企业生产包 | M3-M5 | 50-500 人 | 不能称高可用/多地域完成 |
| R4 规模化包 | M6 | 500+ 人或强合规 | 不能跳过前三包直接交付 |

每个交付包必须同时具备：功能、权限、审计、失败/回滚、真实环境证据和实现状态记录。只有
代码、接口或 Mock 测试而没有真实环境验收，统一降级为“部分验证”。

## 15. 业务验收指标

以下指标是生产候选的门槛，不是“有页面就算完成”：

| 维度 | 指标 | 通过标准 |
| --- | --- | --- |
| 开通效率 | 新员工从登录到 Agent 可用 | P95 ≤ 5 分钟；失败有自助恢复提示 |
| 凭证安全 | 员工机和前端可见凭证 | 不含厂商 Key、issuer Key、设备令牌明文或服务令牌 |
| 吊销时效 | 停用用户/吊销设备后的阻断 | 新刷新和心跳立即失败；当前 Key 在网关撤销周期内失效 |
| 权限正确性 | 跨部门读写 | 服务端拒绝率 100%；依赖调用为 0；有回归测试 |
| 敏感操作审计 | 停用、启用、吊销、轮换、调额、模型授权 | 100% 有 intent/result、理由、目标、操作者、结果和 `operationId` |
| 高风险审批 | 审批、step-up、自审批、payload 变化、重复消费 | 未满足审批/ACR 时依赖调用为 0；同一 operation 最多消费一次；审批可串联审计 |
| 通知可靠性 | outbox、邮件/IM/Webhook/SIEM/工单 | 业务提交不依赖渠道；重启不丢事件；重试、死信、人工重放和去重有证据 |
| 失败真实性 | 依赖/审计/存储失败 | 不返回伪造成功；可查询、可对账、可补偿 |
| 用量归属 | 人/部门/设备/Agent/模型/Key | 100% 请求可解释归属；未知归属单独标记，不猜测 |
| 资源同步 | 强制 MCP/Skills/Instructions | P95 ≤ 5 分钟可见；失败回退上一验签版本 |
| 审计隐私 | L0/L1/L2/L3 | 默认 L0；正文访问、导出和删除有独立权限和证据 |
| 运维恢复 | 备份、RPO、RTO、回滚 | 生产候选完成恢复演练；规模化目标 RPO 15 分钟、RTO 2 小时 |
| 上游同步 | 上游变更被发现、验证并合入企业 `main` 的延迟 | 正常 ≤ 1 小时发现并创建同步 PR；合并延迟取决于 CI 和审查；冲突有告警且不覆盖企业提交 |
| 可用性 | 网关/控制面 | 试点 99.0%；生产目标 99.9%，按规模完成 HA |

## 16. 风险登记与应对

| 风险 | 影响 | 预防 | 发生时 |
| --- | --- | --- | --- |
| 上游频繁修改同一点 | 自动合并冲突、企业功能回归 | 企业代码隔离、小 PR、每日合入上游、核心 hook 开关 | 在同步分支解决；发布停在最后已验证 tag |
| 员工绕过企业网关直连厂商 | 数据出口、额度和审计失效 | 网络出口、MDM/EDR、Provider 锁定、短期凭证 | 阻断出口、吊销设备和凭证、安全事件复盘 |
| 部门管理员越权 | 跨部门数据泄露或误操作 | 服务端组织范围、逐对象校验、负向测试 | 拒绝请求、记录审计、临时停权并复核绑定 |
| 管理员可以静默看正文 | 合规和员工信任风险 | 默认 L0、独立 `audit.content.read`、二次审批和访问审计 | 关闭能力、保全证据、按事件流程调查 |
| Gateway/issuer/服务令牌泄露 | 非授权模型调用或伪造签发 | Secret Manager、最小权限、轮换、日志脱敏 | 立即轮换、吊销、检查用量和审计链 |
| result 审计失败但依赖已执行 | 页面与真实状态不一致 | 先 intent 后执行、result 失败不返回成功、C5 对账 | operation 保持 `dependency_invoked`，人工补偿并记录 |
| 幂等键或版本冲突处理错误 | 重复扣额、重复轮换或覆盖配置 | 持久化指纹、同键异体 409、`If-Match`/版本号 | 冻结相关写接口，回放审计并修复状态 |
| `usage.jsonl` 损坏或轮转不完整 | 报表和成本错误 | 只读挂载、大小/行/记录限制、损坏 fail closed | 返回 `storage_unavailable`，从备份/归档恢复 |
| MCP/资源供应链攻击 | 员工机执行恶意工具或资源 | 不可变版本、哈希/签名、审批、沙箱和最小权限 | 停止分发、回滚版本、吊销签名和调查影响面 |
| 过早追求全功能 | 安全债务累积、无法上线 | 按 R0-R4 和 M0-M6 顺序，阶段退出条件 | 砍范围回到当前交付包，不以演示替代验收 |

## 17. 项目治理与职责

| 角色 | 负责 | 必须签字/参与的节点 |
| --- | --- | --- |
| 产品负责人 | 范围、员工体验、验收优先级 | R1/R2 范围冻结，M2-D/M3/M4 验收 |
| 架构/技术负责人 | 服务边界、上游兼容、核心 hook 评审 | 每个核心改动 ADR、M2/M3/M6 设计评审 |
| 平台/后端 | auth、admin、gateway 适配、数据模型和测试 | 每个 API/状态机/迁移 PR |
| 前端 | 员工门户、管理控制台、错误和空状态 | M2-D、M3 资源与看板验收 |
| IT/身份团队 | IdP、SCIM、反向代理、MDM、Windows 刷新 | M1/M2 真实环境验收、E2E 演练 |
| SRE/运维 | Compose/HA、监控、备份、恢复、发布回滚 | M5/M6 和每次生产发布 |
| 安全管理员 | 威胁模型、规则、告警、阻断和响应 | M3-M5 安全评审、事件演练 |
| 审计/合规 | 留存、正文访问、导出、员工告知和 DPA | M4 上线前、季度演练和最终签字 |

没有明确责任人和证据路径的功能，不得进入下一阶段。多人并行开发时，每个分支必须指定
负责人、目标阶段、依赖和回滚点。

## 18. 开发前必须确认的决策

以下决策未确认前可以继续做隔离原型，但不能把它们当作生产默认值：

1. 员工 IdP 和管理 IdP 是否使用不同 Client、不同 ACR/条件访问和不同会话策略。
2. SCIM 是否作为人员和组织事实来源，以及离职事件的 SLA 和重试策略。
3. 企业网关是否统一承载模型和 MCP，还是模型与 MCP 分域部署。
4. 哪些模型必须走企业网关、哪些允许本地模型，以及模型稳定 ID 和价格版本由谁维护。
5. 额度按 token、费用、请求数还是组合计算；周期、共享范围和超额动作是什么。
6. 管理审计、用量和正文的保留期、备份位置、跨境限制和法定保留流程。
7. MCP 是否允许本地运行；如果允许，签名、沙箱、网络和 Secret Reference 的边界是什么。
8. 客户端最低版本、更新源、MDM 卸载/回滚和离线宽限期。
9. 生产规模、可用性目标、RPO/RTO、预算和是否在首期建设 HA。
10. 谁有权触发紧急吊销、谁批准正文查看/导出、谁对最终生产发布签字。

## 19. 最终完成定义

企业功能方案只有以下四句话同时成立才算真正落地：

1. **员工能用：** 企业账号登录后 5 分钟内完成本地 Agent 接入，只能访问授权模型/MCP，
   失败时有明确恢复路径。
2. **管理员能管：** 用户、组织、设备、凭证、额度、模型、MCP、资源和客户端版本都在权限与
   组织范围内管理，敏感操作可追溯。
3. **安全能证明：** 身份、权限、审计、脱敏、留存、告警、吊销、备份和回滚都有可重复证据，
   不依赖页面隐藏或口头承诺。
4. **上游能持续同步：** 企业改动保持隔离，上游更新后关键回归通过，企业发布可独立灰度、
   回滚和停服。

任何一项无法证明，都应停留在对应交付包，不得对外宣称“企业生产版已完成”。
