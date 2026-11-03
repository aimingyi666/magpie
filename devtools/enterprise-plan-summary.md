# Magpie 企业版完整方案（管理层总览）

状态：方案评审与实施基线 v3.35（与功能方案、实施总纲和运营手册同步）

日期：2026-11-03

适用范围：基于 `aimingyi666/magpie`（`yetone/magpie` 的 fork）建设企业内部 AI 客户端、
模型/MCP 网关和管理控制面。

本文是面向管理层、产品、IT、安全和运维的总览，不替代详细设计。事实状态以
[`enterprise-implementation-status.md`](enterprise-implementation-status.md) 为准；功能、
API、数据模型和验收设计见 [`enterprise-feature-spec.md`](enterprise-feature-spec.md)；
项目职责、GitHub 规则和试点退出见
[`enterprise-operating-model.md`](enterprise-operating-model.md)；部署操作见
[`enterprise-deployment.md`](enterprise-deployment.md)；生产证据见
[`enterprise-acceptance-checklist.md`](enterprise-acceptance-checklist.md)。

## 1. 管理层结论

企业版不是“把 Magpie 改成纯 SaaS”，也不是“只建一个管理网页”。它由三部分组成：

```text
员工本地 Agent
  -> 本地 Magpie（一键配置、本地网关、凭证刷新）
  -> 企业模型/MCP 网关（数据面）
  -> 企业控制面（OIDC、管理、策略、资源、审计）
```

三条不可混淆的边界：

1. **员工电脑上必须安装本地 Magpie 或受控 helper。** 浏览器不能直接修改员工电脑上的
   Agent 配置文件。网页负责 OIDC 登录、授权、状态展示和下载加入信息；本地 Magpie/helper
   负责把企业 Provider、网关地址、短期凭证和受控资源写入本机 Agent。
2. **数据面和控制面分开。** 模型/MCP 请求走企业网关；身份、管理、策略、资源发布和审计
   走独立控制面。管理服务不能直接读写网关的 `caller-keys.json`。
3. **服务端才是安全边界。** 页面隐藏按钮、前端状态或“管理员看起来有权限”都不算权限控制。
   所有读写、模型授权、额度、MCP 工具和企业资源必须在服务端校验身份、角色、组织范围和
   资源范围。

当前结论：已有可运行的技术切片和本地/Mock 测试，但整体只能描述为
**“可演示、可受控技术试点”**，不能描述为“企业生产版已完成”。

## 2. 目标闭环

首期真正要交付的不是“功能最多”，而是下面这条链路可证明、可撤销、可回滚：

```text
员工用企业 OIDC/MFA 登录
  -> 注册受控设备
  -> 获得短期企业凭证
  -> 本地 Magpie 一键配置 Agent
  -> Agent 只访问企业模型和企业 MCP
  -> 管理员按人/部门/设备/Agent/模型查看用量和错误
  -> 高风险操作有权限、理由、审批或 step-up、审计和真实生效证据
  -> 离职、设备丢失或撤销后无法继续刷新和调用
```

## 3. 员工使用流程

### 3.1 首次使用

1. IT 通过 MDM 或软件中心安装本地 Magpie。
2. 员工打开本地 Magpie，选择“企业登录”。
3. 浏览器跳转企业 OIDC，完成 MFA/ACR 和条件访问。
4. 本地 Magpie 生成设备密钥，注册设备并获取短期凭证。
5. 本地 Magpie 自动配置支持的 Agent：Provider 指向企业网关，模型范围使用企业授权结果。
6. 员工在本地 Magpie 查看本人设备、凭证、模型范围、额度和恢复提示。
7. 本地 Magpie 自动刷新短期凭证；刷新失败时保留可解释错误，不把旧凭证当成功。

### 3.2 网页和本地的职责

| 能力 | 企业网页 | 本地 Magpie/helper |
| --- | --- | --- |
| OIDC/MFA 登录 | 可以 | 发起或接收登录结果 |
| 展示授权、额度、设备状态 | 可以 | 展示本机状态 |
| 下载加入命令/配置包 | 可以 | 校验并执行 |
| 修改本机 Agent 文件 | **不可以直接修改** | 负责落盘、备份和回滚 |
| 刷新短期凭证 | 不接触长期秘密 | 在设备上安全刷新 |
| 查看他人数据 | 不可以 | 不可以 |

### 3.3 日常与异常

- 凭证过期：本地自动刷新，失败时提示重新登录或联系管理员。
- 设备丢失：管理员吊销设备，刷新、心跳和当前 Key 按撤销策略失效。
- 离职：停用用户后撤销设备、会话和当前凭证；启用用户不恢复旧设备或旧凭证。
- 模型被移除：真实请求应被企业网关拒绝，页面不能只显示“已变更”而没有网关证据。
- 上游故障：返回稳定错误码和 `requestId`，不要求员工发送 Key、Token 或正文。

## 4. 管理员、审计员、安全与运维流程

### 4.1 管理员

1. 使用独立管理 OIDC Client 登录，强制 MFA/ACR 和已验证邮箱。
2. 服务端按“权限 + 组织子树 + 资源范围 + 时间”判断，不按页面菜单判断。
3. 管理用户、部门、设备、凭证、模型、额度、策略、MCP、资源、用量和审计。
4. 高风险操作要求理由、幂等键、版本检查、审计，以及审批或 step-up。
5. 只有完整证据链“成功 + 策略已知 + 已同步 + 独立回读一致”才显示“已生效”。
6. `pending`、`partial_success`、`dependency_invoked` 必须显示真实状态和恢复入口，
   禁止自动重试结果不确定的操作。

建议角色：

| 角色 | 主要权限 |
| --- | --- |
| 部门管理员 | 本部门及子树只读；受控用户/设备/凭证操作 |
| 企业管理员 | 全企业用户、设备、凭证、模型、额度和策略 |
| 审计员 | 默认只读审计元数据；正文和导出需要额外权限 |
| 安全管理员 | 规则、告警、阻断、吊销和 break-glass 复核 |
| 运维管理员 | 部署、健康、容量、备份、恢复和发布 |
| 超级管理员 | 仅用于平台治理，不默认拥有正文查看权 |

### 4.2 审计员

- 默认只看 L0 元数据：身份、时间、模型、Token、费用、错误、`requestId`、
  `operationId` 和脱敏目标。
- 对话正文属于 L2/L3，必须单独授权、二次确认、填写目的并记录访问审计。
- 审计记录只追加，不修改历史证据；导出有独立权限、审批、一次性链接和审计。

### 4.3 安全管理员

- 发现异常用量、异地/IP 变化、越权、直连、禁用模型或敏感数据命中后，执行限流、阻断、
  吊销、设备锁定或工单。
- 自动响应也必须有理由、权限和审计；紧急操作不能绕过证据保全。
- SIEM、Webhook、邮件、IM 和工单通过 transactional outbox 异步投递，不能阻塞业务请求。

### 4.4 运维管理员

- 负责 Compose/MDM、内网更新源、健康检查、指标、备份、恢复、灰度、回滚和值班。
- 生产发布必须从已验收发布点构建，不从上游最新 commit 直接发布。
- 真实 IdP、反向代理、共享卷、Windows 计划任务、公司 CA 和灾备演练是上线门槛。

## 5. 十二个功能域（E1-E12）

| 能力域 | 必须交付 | 阶段 | 当前真实状态 |
| --- | --- | --- | --- |
| E1 身份与组织 | OIDC+PKCE、MFA/ACR、稳定用户 ID、部门/用户组、SCIM/离职同步 | M1/M2/M3 | 员工/管理 OIDC 和基础角色已实现；SCIM、完整组织同步未实现 |
| E2 设备与凭证 | 设备注册、心跳、短期 Key、刷新、轮换、吊销、并发保护和合规状态 | M1/M2 | 本地真实 issuer 链路已通过；真实终端、MDM 和计划任务待验收 |
| E3 员工门户 | 本人身份、设备、Agent、模型、额度、资源和错误；本地 helper 边界 | M1/M2-D/M3-C | 基础员工页、加入脚本、本人额度/模型/凭证/设备只读状态和用量/审计结果已实现；M3-C-1 已提供设备短期同步凭证和 desired-state/report API，但资源/漂移视图、本地 helper 安装器/产品入口、目标 Agent 文件映射、网页直接修改本机 Agent 和完整恢复体验未实现 |
| E4 管理控制台 | 独立管理登录、RBAC、组织范围、只读治理、敏感写操作、审批/step-up、查询和看板 | M2-A..E | 管理身份、只读治理、四个受控写 API、幂等/审计、额度/模型同步后交付、C5 查询/对账、APR-01a 审批、APR-01b HMAC/Mock 回调适配器、APR-01c 独立 step-up、APR-01d 审批箱/多步骤审批和 APR-01e break-glass 核心已实现；M2-D 已接入基础写操作、审批、break-glass、operation、用量/审计查询、对账和 CSV 导出；完整运营看板、失败恢复入口、浏览器 E2E、真实 OA/IdP/MFA/反向代理和 break-glass 生产验收未完成 |
| E5 模型网关 | 模型目录、白名单、路由、回退、额度、限流、价格和稳定模型 ID | M0/M2-C/M2-D | 基础网关和额度已有；正式目录、用户级策略和真实管理闭环待贯通 |
| E6 用量与成本 | 人/部门/设备/Agent/模型/Key 的 Token、费用、错误、趋势、导出和预算告警 | M2-B/D/M5 | 元数据汇总、时间序列、筛选和授权 CSV 导出已有；费用趋势看板、Excel/异步/对象存储导出和预算告警未实现 |
| E7 MCP 治理 | 中央目录、远程/本地 MCP、工具级 allow/deny、健康检查、限流和熔断 | M3/M5 | M3-A 可登记 `mcp` 资源类型和签名版本；M3-B 已提供远程 MCP 注册、企业统一端点、工具级 allow/deny、健康检查、限流和每服务器熔断核心；管理台、真实审批联动、OIDC 组织分配、员工端同步接入、M3-D helper/server、stdio bridge、Codex 配置映射和 `setupLocalMcpClient()` 一键配置编排核心已实现，但管理台员工产品流、安装器/Windows 服务、真实 Codex 客户端、生产 launcher/token 轮换和生产验收未实现 |
| E8 企业资源库 | Skills、Instructions、Subagents、模板、不可变版本、签名、审批、同步、漂移和回滚 | M3 | M3-A 核心后端已实现并通过 11 项测试；M3-C-1 已提供短期同步凭证、desired-state、设备上报和管理员 JSON 查询，resource 15 项、client-sync 26 项测试通过，覆盖签名 desired-state、原子安装、失败保留旧版本、离线缓存、强制/推荐和漂移；M3-C-2 已提供管理页只读资源目录和同步报告/漂移可见性，admin-service 新增 5 项测试；真实审批、资源发布/回滚 UI、发布/回滚审批联动、本地 helper 安装器/产品流、目标 Agent 文件映射和产品级自动回滚未实现 |
| E9 客户端策略 | 企业 Provider/网关锁定、最低版本、强制/推荐资源、离线策略和防绕过 | M3/M5 | 网络和 Key 基础已有；M3-C 已实现 forced/recommended 资源策略、最低版本、签名校验、离线缓存和防路径/符号链接核心；设备身份和短期同步凭证 API 已接入，但管理台策略、MDM/EDR 联动和完整防绕过未实现 |
| E10 审计与通知 | L0-L3 分级、脱敏、留存、访问审计；outbox、邮件/IM/Webhook/SIEM/工单和死信 | M2-E/M4/M5 | M4-A/M4-B/M4-C/M4-D 后端核心和 M4-E 管理侧内容治理已实现；NOTIFY-01a outbox、NOTIFY-01b 渠道管理/统一 HTTPS 网关适配器、NOTIFY-01c SIEM transport/固定 L0 schema/dead-letters API 和 NOTIFY-01d 规则/抑制/聚合/升级/运营页已实现；真实网关正文采集、真实厂商连接、真实 SIEM 接收端、WORM/KMS/HA、生产值班闭环和生产验收未实现/未验收 |
| E11 安全运营 | 异常用量、异地、越权、直连、敏感数据规则、告警、阻断、吊销、审批和 SIEM | M2-E/M5 | APR-01a 审批与职责分离、APR-01b HMAC/Mock 回调适配器、APR-01c 独立 step-up、APR-01e break-glass 核心和 NOTIFY-01c SIEM transport 已实现；M5-A 规则引擎与网关元数据投递核心已实现，规则服务 17 项测试和网关侧 12 项 Go 测试通过；真实 OA/IdP/MFA、管理 UI、告警/阻断自动响应、真实 SIEM 接收端、Docker/Compose、反向代理来源地址、运行中端到端和 break-glass 生产演练未验收 |
| E12 交付与上游治理 | Compose/MDM/内网更新、备份、灰度、回滚、HA、KMS/mTLS、SBOM 和上游同步 | 全阶段 | Compose 模板、同步机制和隔离测试已有；生产验收、HA 和供应链未完成 |

审批与通知是横切能力，分别归入 E4、E10 和 E11；不得各模块自行实现一套“看起来审批过”
的逻辑。

## 6. 交付分级（R0-R4）

| 交付包 | 包含阶段 | 适用对象 | 可以承诺的结论 |
| --- | --- | --- | --- |
| R0 演示包 | M0 + Mock | 产品/研发 | 只做演示，不接真实员工 |
| R1 受控试点包 | M0-M2-B + 真实内网验收 | 5-50 人单部门 | 可做受控技术试点，必须有退出通道 |
| R2 生产候选包 | M0-M2-D + APR-01/NOTIFY-01 基线 | 50-200 人单企业 | 可做正式小范围试用，不得称全公司生产完成 |
| R3 企业生产包 | M3-M5 | 50-500 人 | 可全员推广的单企业生产版 |
| R4 规模化包 | M6 | 500+ 人或强合规 | 多副本、高可用、多地域和强供应链 |

“方案完整”表示范围、顺序、接口、数据、验收和回滚已经定义，不表示 R0-R4 已一次做完。

## 7. 唯一实施顺序

```text
真实环境验收
-> C4-03c
-> C4-03d
-> C4-04
-> C5
-> APR-01a/b/c
-> NOTIFY-01a [done] / 01b [done] / 01c [transport done]
-> M2-D
-> M3
-> M4
-> M5
-> M6
```

完整阶段顺序：

```text
M0 -> M1 -> M2-A/B/C1/C2/C3
-> C4-01/C4-02/C4-03a/C4-03b
-> C4-03c -> C4-03d -> C4-04
-> C5 -> APR-01a/b/c -> NOTIFY-01a/b/c -> M2-D
-> M3 -> M4 -> M5 -> M6
```

每个阶段的预期结果：

| 阶段 | 完成后能得到什么 | 验收时应看到 |
| --- | --- | --- |
| 真实环境验收 | 现有切片脱离 Mock 后仍可运行 | 真实 IdP、Docker、Windows 计划任务、反向代理、共享卷和离职/吊销演练有证据 |
| C4-03c | 管理端额度/模型授权自动落到网关并可追踪 | 授权、apply、独立回读、issuance journal、同步后交付和失败补偿形成一条链路 |
| C4-03d | 管理员和员工看到真实生效状态 | 页面区分 `pending`、部分成功、失败设备、恢复入口和对账入口 |
| C4-04 | 策略不仅“写成功”，而且真实拦截请求 | 超限、禁用模型、刷新/轮换继承和部分失败均由真实 Magpie E2E 证明 |
| C5 | 操作可查、审计可查、账可对 | operations/audit-logs 可查询，人工对账能发现并解释差异 |
| APR-01/NOTIFY-01 | 高风险动作可控，状态变化可靠送达 | 审批绑定 payload/版本/范围，真实 OA 验签和防重放有效，step-up/break-glass 生效，outbox 可恢复且渠道故障不影响业务提交 |
| M2-D | 管理员有正式操作台 | 写操作、看板、报表、授权导出和员工状态页均有服务端权限与审计 |
| M3 | 全公司资源可控分发 | 管理员登记 MCP/工具、Skills/Instructions/Subagents 和模板，客户端同步、漂移、回滚和撤销可证明 |
| M4 | 对话与工具使用可审计 | 默认只看 L0；L2/L3 正文按独立授权、目的、水印、访问审计和留存策略开放 |
| M5 | 安全事件能发现、阻断和闭环 | 规则告警、限流、阻断、吊销、工单、SIEM 和值班处置可用 |
| M6 | 能承载多团队和大规模使用 | 多副本、共享存储、KMS/mTLS、备份恢复、故障切换、压测和多地域演练通过 |

顺序理由：

1. 先证明真实 IdP、Docker、Windows、代理和共享卷，否则后续只是 Mock 叠加。
2. C4-03c 的自动同步后交付和 C4-04 的真实请求行为已有证据，下一步补齐 C4-03d 页面状态、
   恢复入口和部署验收。
3. 先有操作/审计查询和人工对账（C5），再开放完整管理 UI 和大范围写操作。
4. 高风险页面必须建立在审批、step-up 和通知 outbox 之上。
5. 先控制“能用什么”（M3），再处理“记录什么正文”（M4）。
6. 先证明安全运营闭环（M5），再扩大 HA 和多地域暴露面（M6）。

## 8. 当前真实完成度

| 工作包 | 状态 | 已证明 | 尚未证明 |
| --- | --- | --- | --- |
| M0 企业网关基线 | 已实现 | 客户端 -> 企业网关 -> Mock 上游、按人归属、额度/白名单、E2E | 真实公司网络和大规模容量 |
| M1 OIDC/设备/短期 Key | 已实现本地真实链路 | join、调用、用量、刷新撤销、停用吊销和重启恢复 | 真实企业 IdP、Docker、Windows 计划任务和离职同步 |
| M2-A 管理身份 | 已实现，Mock 测试 | 独立管理 OIDC、MFA/ACR、会话、CSRF、IP、RBAC 和组织范围 | 真实管理 IdP、代理、浏览器和角色演练 |
| M2-B 只读治理 | 已实现，Mock 测试 | 用户/部门/设备/凭证/模型/用量只读 API 和范围过滤 | 真实 `usage.jsonl` 数据卷、浏览器和生产验收 |
| M2-C1 | 已实现，Mock 测试 | 内部停用/启用、设备吊销、凭证轮换 | 真实服务和真实网关验收 |
| M2-C2 | 已实现，Mock 测试 | 四个管理写 API、CSRF、组织范围、理由、脱敏和基础管理页面 | 浏览器 E2E、失败恢复入口和真实环境验收 |
| M2-C3 | 已实现，Mock 测试 | 持久化幂等、`operationId`、intent/result 审计和审计失败阻断 | 真实审计存储、生产查询/对账验收和人工运维演练 |
| C4-01 | 已实现，本地测试通过 | schema v1、原子 `policy apply`、版本冲突、无秘密输出、文件锁和真实二进制冒烟 | 管理链路 |
| C4-02 | 已实现，15 项 Mock/故障测试通过 | 固定路由/argv、服务令牌、超时、输出上限、独立回读和 `pending` | Docker、真实共享卷、mTLS |
| C4-03a | 已实现，当前管理服务 109/109 测试通过 | 正式只读模型目录、严格 JSON、稳定 ID、group、digest 和失败关闭 | 真实 Compose、只读挂载、digest 重启 |
| C4-03b | 核心已实现，26/26 auth 测试通过 | 用户级 `gatewayPolicy`、M1 `unknown`、分步初始化、版本冲突、失败关闭和回读确认 | 真实部署和真实请求 E2E |
| C4-03c | 核心已实现，Mock/故障测试通过 | 管理额度/模型 API、幂等签发、issuance journal、apply/readback、同步后交付、失败补偿和启动恢复 | 真实 Magpie/共享卷故障注入、真实 IdP 和生产验收 |
| C4-03d | 部分实现 | 管理页有额度/模型写表单、完整证据链和失败证据；员工页有本人额度/模型/凭证/设备只读门户；M2-D 已接入基础 operation/audit 查询、人工对账、审批、导出和停用/吊销/轮换页面 | 浏览器 E2E、失败恢复入口、完整运营体验和生产验收 |
| C4-04 | 完整管理链路 E2E 已通过 | 隔离真实 Magpie 的管理 OIDC/CSRF、分步策略、双设备 Key、限额/模型拒绝、`partial_success`、refresh/rotate 继承、故障后 pending、Journal/孤儿 Key 撤销、恢复同步、usage 归属和秘密扫描 | Docker/共享卷、真实企业 IdP、反向代理、浏览器自动化和生产验收 |
| M2-C5 | 后端和基础页面已实现，Mock/故障测试通过 | operation 详情、脱敏审计分页、签名 cursor 和四种人工对账 API | 真实审计存储和生产运维演练 |
| M2-E | APR-01a-e 核心与 NOTIFY-01a-d 已实现 | 服务端审批、绑定、职责分离、一次性消费、HMAC/Mock 外部审批回调、独立 OIDC step-up、审批箱/串并行/quorum/转交/撤回、break-glass 15 分钟单次授权/24 小时复核/提醒，以及事务性 outbox、租约、退避、死信、重启恢复、人工重放、渠道管理、渠道测试、统一 HTTPS 邮件/IM/Webhook/工单网关适配器、SIEM transport、dead-letters API、规则/抑制/聚合/升级和运营页已实现 | 真实 OA/IdP/MFA、break-glass 告警/工单和生产复核、真实 SIEM/Collector/Syslog/生产证书、真实厂商连接、生产值班闭环和生产投递 |
| M2-D | 核心已实现，Mock/集成测试通过；生产验收尚未完成 | 基础写操作、审批、operation、用量/审计筛选、人工对账、CSV 导出和操作历史已实现 | 浏览器 E2E、失败恢复入口、真实数据/负载、完整运营看板和异步/对象存储导出 |
| M3 | M3-A/M3-B/M3-C-1/M3-C-2 核心、控制面与只读管理可见性已实现；M3-D helper/server、stdio bridge、Codex 配置映射和一键配置编排核心已实现 | resource-service 15 项、mcp-gateway 14 项、client-sync 26 项、admin-service 新增 5 项、local-mcp 60 项测试通过；企业七套回归合计 265 项 | M3-A 已有资源目录、不可变版本、内容寻址、签名、发布/回滚和审计；M3-B 已有远程 MCP 注册、企业统一端点、工具级授权、健康检查、凭据隔离和审计；M3-C-1 已有设备短期同步凭证、desired-state、设备上报、管理员 JSON 查询和 HTTP 传输，叠加签名 desired-state、原子安装、失败保留旧版本、离线缓存、强制/推荐、漂移、路径/符号链接防护、并发锁和状态秘密隔离；M3-C-2 已有按组织范围过滤的只读资源/同步 API、严格字段投影和只读管理页面板；M3-D 已有 helper HTTP、stdio bridge、受管 Codex `config.toml` 映射、`setupLocalMcpClient()` 同步/选包/启动/写入/回读/受控环境注入和经过编排入口的真实子进程 E2E。资源发布/回滚 UI、admin-service 真实审批联动、OIDC 组织分配、本地 helper 安装器/员工产品流、真实 Codex 客户端、生产 launcher/token 轮换验收尚未完成；M3-D 管理台员工产品流、安装器/Windows 服务和生产验收未实现 |
| M4 | M4-A/M4-B/M4-C/M4-D 后端核心和 M4-E 管理侧治理已实现，M4 整体未完成 | audit-service 67 项测试覆盖 L0/L1 allowlist、默认关闭的 L2 脱敏流式存储、内容检索、签名 cursor、一次性正文授权、留存、法律保留、删除证明和加密导出；admin-service 已验证管理 OIDC/RBAC/step-up、审批、幂等、operation/审计和双层加密下载 | 真实网关正文采集、浏览器 E2E、WORM/KMS、HA、备份恢复和生产验收 |
| M5 | M5-A 规则引擎与网关元数据投递核心已实现，M5-B/M5-C 未实现 | security-service 17 项规则测试和网关侧 12 项 Go 测试通过；已有八条稳定规则、确定性 finding/聚合、抑制标记、默认关闭的元数据导出器、HMAC 源地址和有界异步重试 | 管理 UI、自动响应、生产 SIEM、值班处置、Docker/Compose、真实反向代理来源地址、运行中端到端、HA 和生产验收 |
| M6 | 未实现 | 只有规模化设计 | PostgreSQL/ClickHouse、多副本、Redis、KMS、mTLS、多地域和灾备 |

当前已执行并通过的本地测试：

- `enterprise/auth-service`：`26 passed, 0 failed`
- `enterprise/admin-service`：`123 passed, 0 failed`（86 项管理集成 + 7 项目录专项 + 5 项内容治理客户端 + 5 项内容治理存储 + 7 项通知渠道专项 + 7 项通知规则专项 + 6 项 SIEM 专项）
- `enterprise/gateway-control`：`15 passed, 0 failed`
- `enterprise/resource-service`：`15 passed, 0 failed`（11 核心 + 4 控制面）
- `enterprise/mcp-gateway`：`14 passed, 0 failed`
- `enterprise/client-sync`：`26 passed, 0 failed`（18 核心 + 8 传输）
- `enterprise/local-mcp`：`60 passed, 0 failed`（21 运行时 + 7 helper + 9 HTTP server + 5 bridge + 7 Codex 配置 + 10 client setup + 1 真实子进程 E2E）
- `enterprise/audit-service`：`67 passed, 0 failed`（20 项 L0/L1 事件管道 + 27 项内容审计/检索/授权 + 20 项留存/法律保留/删除证明/加密导出）
- `enterprise/security-service`：`17 passed, 0 failed`
- 九套 Node/Mock 回归合计：`363 passed, 0 failed`
- M5-A 网关元数据投递：12 项 Go 测试通过（导出器 8、插件生命周期 3、身份/来源地址映射 1）
- `enterprise/test/c4-enterprise-policy-e2e.ps1`：18 阶段完整管理到真实 Magpie 策略流 E2E 通过

以上九套 Node/Mock 测试合计 `363 passed, 0 failed`。这些结果不等于真实 IdP、Docker、共享卷、
Windows、反向代理、真实 Codex 客户端或生产部署验收。C4-04 只使用
隔离真实 Magpie、临时配置目录和 Mock 上游，不能替代生产环境。

## 9. 当前管理员能看到和不能看到什么

当前可以：

- 通过管理 API/最小管理页查看本人身份、组织范围和只读治理摘要。
- 查看用户、部门、设备、凭证元数据、正式模型目录和 L0 用量元数据。
- 通过管理页和受控 API 执行停用/启用、设备吊销、当前凭证轮换和额度/模型策略写入；这些
  操作已接入审批、operation、用量/审计查询、人工对账和 CSV 导出。

当前不可以：

- 默认不能查看员工对话正文、Prompt、回复、附件正文或完整工具参数；M4-E 已实现经审批、
  fresh step-up、理由、组织范围、一次性授权和访问审计的受控正文读取与加密导出，但只允许
  全局组织范围 `*`，禁止 break-glass，且真实网关正文采集、浏览器 E2E 和生产验收仍未完成。
- 管理页已有受控额度/模型写表单、停用/吊销/轮换、审批、operation/audit 查询、人工对账
  和 CSV 导出入口，C4-04 已证明隔离真实链路生效；但浏览器 E2E、失败恢复入口、真实共享卷、
  真实企业 IdP、生产反向代理和生产验收仍未完成，不能宣称生产自助管理完成。
- 基础管理页面已支持 operations/audit-logs 查询、人工对账和 CSV 导出；仍缺浏览器 E2E、
  失败恢复入口、完整运营体验和生产验收，不能据此宣称生产自助管理完成。
- 不能通过管理台配置远程 MCP、工具权限、客户端强制策略或发布/回滚资源；M3-A 资源目录、
  M3-B 远程 MCP、M3-C-1 同步控制面和 M3-C-2 只读资源/漂移可见性已实现，设备短期同步
  凭证和 desired-state/report API 已接入；但真实审批、资源发布/回滚 UI、发布/回滚审批联动、
  OIDC 组织分配和本地 helper 产品流仍未完成；M3-D 运行时、helper、回环 HTTP server、
  stdio bridge 和 Codex 配置映射核心已实现，但管理台员工产品流、安装器/Windows 服务、
  真实 Codex 客户端和生产验收尚未完成。
- 不能宣称真实 OA、真实 IdP/MFA、反向代理、break-glass、真实厂商 Webhook/SIEM/工单或完整审批
  运营已可用；APR-01a 服务端审批、APR-01b HMAC/Mock 回调适配器、APR-01c 独立 step-up、
  NOTIFY-01a outbox、NOTIFY-01b 渠道管理/统一 HTTPS 网关适配器、NOTIFY-01c SIEM transport
  和 NOTIFY-01d 规则/抑制/聚合/升级/运营页已实现，APR-01d 审批箱和多步骤审批、
  APR-01e break-glass 核心也已实现，但真实 OA/IdP/MFA、break-glass 告警/工单和生产复核、
  真实厂商连接、真实 SIEM 接收端和生产值班闭环尚未完成。
- 不能宣称高可用、多副本、KMS、mTLS 或多地域已完成；M6 尚未实现。

## 10. MCP 与企业资源库（M3-A/M3-B/M3-C-1/M3-C-2 核心、控制面与只读管理可见性已实现，M3-D helper/server、stdio bridge、Codex 配置映射和一键配置编排核心已实现）

M3 要解决的是“全公司能用什么”，不是只在员工电脑上手工装插件。

当前事实：M3-A 的 `enterprise/resource-service/` 已提供内部资源目录、不可变版本、
SHA-256 内容寻址、canonical JSON、Ed25519 签名、发布/历史回滚、乐观并发、幂等和资源审计，
并通过 11 项单元/Mock 集成测试。M3-B 的 `enterprise/mcp-gateway/` 已提供远程 MCP 注册、
企业统一端点、工具级授权、健康检查、上游凭据隔离和元数据审计，并通过 14 项单元/Mock
集成测试。M3-C-1 已在 auth-service 提供设备短期同步凭证，在 resource-service 提供
desired-state、设备上报和管理员 JSON 查询，并在 `enterprise/client-sync/` 提供 HTTP 传输、
固定 Ed25519 公钥/SPKI 指纹、manifest 和内容校验、staging/原子激活、失败保留上一验签版本、
离线缓存、forced/recommended、漂移检测、路径/符号链接拒绝、并发锁和 `0600` 状态秘密隔离；
resource-service 15 项（11 核心 + 4 控制面）和 client-sync 26 项（18 核心 + 8 传输）测试通过。
M3-C-2 已在 admin-service 提供只读资源目录和同步报告/漂移 API，按管理员组织范围过滤并只
投影白名单字段；依赖故障统一返回 `503 resource_service_unavailable`，管理页提供只读面板。
`approvalId` 目前只是资源服务的必填证据，不会自行当作真实已批准事实；M3-B 的审批 token
也未查询/消费 admin-service 真实审批。资源发布/回滚 UI、发布/回滚审批联动、OIDC 组织分配、
本地 helper 安装器/产品入口、目标 Agent 文件映射、Windows ACL、MDM、真实 IdP、浏览器 E2E、
Docker/Compose 实机验收、灰度/自动回滚和生产验收仍未实现；M3-D 受控本地 MCP 运行时、
helper、回环 HTTP server、stdio bridge、Codex 配置映射和 `setupLocalMcpClient()` 一键配置
编排已实现并通过 60 项测试（含经过编排入口的真实子进程 E2E）。编排要求受控启动器提供
`injectLaunchEnvironment`，缺失时失败关闭；token 不写入配置或成功结果，失败会清理受管
块、server 和 lock。但管理台员工产品流、安装器/Windows 服务、真实 Codex 客户端、
生产 launcher/Windows ACL/DPAPI/token 轮换、外部 OS 沙箱和生产验收仍未完成。
M3-B 的审批 nonce 仅单进程内存，注册表/审计/幂等不是同一事务，存在提交后审计失败窗口。

### 10.1 中央 MCP 目录

- 管理员登记远程 MCP、受控本地 MCP、工具、风险等级、数据分级和适用范围。
- 工具级 allow/deny，未授权 MCP/工具不可见、不可调用。
- MCP 上游凭据只保存在网关或 Secret Manager，不进入员工机。
- 支持健康检查、超时、限流、熔断、审计和故障隔离。

### 10.2 企业资源库

- 统一发布 Skills、Instructions、Subagents、模板和企业知识资源。
- 使用不可变版本、哈希/签名、审批、灰度、强制/推荐策略和兼容版本范围。
- 客户端同步后上报期望/实际版本，管理员看到漂移、安装失败和回滚状态。
- 坏资源自动回退上一版本；强制资源不可由员工关闭。
- 客户端只从企业签名源同步，不从任意公网地址拉取未审批资源。

当前已有资源目录、远程 MCP 治理、客户端同步核心、设备同步凭证/desired-state/report API，
以及管理页只读资源/漂移可见性；但没有资源发布/回滚 UI、发布/回滚审批联动、目标 Agent
文件映射或本地 helper 安装器/产品入口。不能把核心包或现有单机插件、模型 Provider 配置描述成
已经上线的企业 MCP/资源治理。

## 11. 会话与工具审计（M4 核心已实现，生产验收未完成）

当前状态：M4-A/M4-B/M4-C/M4-D 后端核心和 M4-E 管理侧治理已实现，audit-service 67 项、
admin-service 内容治理 10 项测试通过；系统仍默认 L0，真实网关正文采集、WORM/KMS、HA、
备份恢复和生产验收尚未完成，M4 整体不得描述为已上线。

审计分级：

| 等级 | 内容 | 默认 |
| --- | --- | --- |
| L0 | 身份、时间、模型、Token、费用、错误、调用结果和 `requestId` | 开启 |
| L1 | 工具名、参数类别、结果状态和资源标识 | 按需 |
| L2 | 脱敏后的 Prompt/回复摘要或正文 | 默认关闭，独立授权 |
| L3 | 原始正文 | 默认关闭，法定调查、双人审批、短保留 |

必须实现：

- 流式回复拼接完整，断流和重试可恢复，不产生重复正文。
- 正文访问有独立权限、目的、二次确认、水印、访问审计和短时授权。
- 留存、法律保留、删除和导出可证明，删除不能只改页面状态。
- 日志、审计、SIEM 和通知不含 Gateway Key、token hash、Cookie、OIDC/服务 token、
  Prompt/回复正文或完整工具参数。
- 审计员默认只看元数据；正文查看、导出和留存修改不能由一人静默完成。

## 12. 审批、step-up、break-glass 与通知（M2-E，APR-01a-e 与 NOTIFY-01a-d 核心已实现）

### 12.1 审批

- 服务端按动作、目标、批量大小、数据分级和组织范围计算 L/M/H/C 风险。
- 审批绑定组织、动作、目标、资源范围、风险、规范化 payload SHA-256、策略版本和有效期。
- HMAC/Mock 外部审批回调适配器已实现验签，并校验 issuer、audience、时间窗、nonce、
  重放缓存和 eventId 幂等；真实飞书/OA/ServiceNow/Jira 连接器未验证。
- 申请人不能审批自己的请求；审批一次性消费，并发和重启后只能产生一个业务结果。
- 审批后修改额度、模型、目标、批量成员或资源版本，旧审批立即失效。

### 12.2 step-up 与 break-glass

- APR-01c 已完成代码与 Mock IdP 集成测试：高风险动作使用独立管理 OIDC Client、PKCE、
  `prompt=login`、MFA/ACR、`max_age` 和新鲜 `auth_time`。
- step-up 绑定会话、用户、客户端 IP、User-Agent 和角色/权限/组织范围摘要；默认 10 分钟，
  关键动作 5 分钟；未配置 step-up 时失败关闭。
- break-glass 只用于紧急场景，15 分钟自动过期，5 分钟内产生高风险告警/工单，
  24 小时内完成事后复核并保全证据。

### 12.3 通知与安全运营投递

- NOTIFY-01a 已实现业务状态、审计和 outbox 事件在同一事务或受控文件锁提交；通过
  Mock/故障测试验证租约、退避、死信、重启恢复和人工重放。
- 业务响应不等待邮件、IM、Webhook、SIEM 或工单；渠道故障不改变已提交业务结果。
- NOTIFY-01b 已实现 `email`/`im`/`webhook`/`ticketing` 渠道管理、渠道测试和统一 HTTPS
  网关适配器；仅允许 HTTPS:443、host allowlist、固定 DNS 解析、私网/回环/链路本地/云
  元数据地址拒绝、307/308 最多 3 跳逐跳复验，并限制超时和响应大小。Webhook 使用时间戳、
  nonce 和 HMAC-SHA256；Secret 只保存环境变量名 `secretRef`。邮件/IM/工单不是原生 SMTP、
  Graph、飞书、Teams、ServiceNow 或 Jira SDK，真实厂商连接和生产投递未验收。
- NOTIFY-01c 的 SIEM transport、固定 L0 schema 和 dead-letters API 已实现并通过 6 项专项
  测试；真实 SIEM/Collector/Syslog/生产证书未验收。NOTIFY-01d 的规则、抑制、聚合、
  阈值/延迟升级、dead-letter 受审计重放和运营页已实现，并通过 7 项通知规则专项及管理
  回归；真实厂商渠道、生产值班闭环和浏览器 E2E 未验收。正常启动没有启用渠道或 transport
  时不创建 dispatcher，业务请求不等待外部渠道。
- Webhook 仅 HTTPS 和允许列表，HMAC 时间戳/nonce，防 SSRF、私网探测、DNS rebinding。
- SIEM transport 使用固定 L0 schema，critical 优先且 dispatcher 轮询不超过 5 分钟；
  事件不含正文和秘密。真实接收端可见时间和生产证书仍未验收。

当前 `approvalId` 必须经服务端审批状态、绑定、有效性和一次性消费校验，不能只凭字段值
当作已批准。APR-01c 已有独立 step-up 代码和 Mock IdP 测试；NOTIFY-01b 已有受控 HTTPS
出站适配器，APR-01d 审批箱、串并行步骤、quorum、转交和撤回已实现；当前仍没有真实
OA/IdP/MFA、break-glass、真实厂商连接或生产通知闭环验收。

## 13. 安全运营、规模化与高可用（M5/M6）

### 13.1 M5 安全运营

- 异常用量、异地/IP、越权、直连、禁用模型和敏感数据规则。
- 告警、限流、阻断、吊销、设备锁定、工单和值班处置闭环。
- OTel/SIEM 元数据投递，严重事件 5 分钟内可见可处置。
- 所有自动响应有理由、权限、审批和审计，可撤销。

### 13.2 M6 规模化

- 网关无状态化、多副本、负载均衡和共享存储。
- 密钥、用量、审计从本地 JSON 迁移到 PostgreSQL，必要时使用 ClickHouse 和 Redis。
- Vault/KMS 托管密钥，客户端到网关 mTLS/设备证书，镜像签名和 SBOM。
- 明确 RPO/RTO，完成备份恢复、故障切换、压测、回滚和多地域演练。
- 500+ 人或强合规场景才进入 R4，不得跳过 R1-R3。

## 14. 分支、PR 与上游同步规则

### 14.1 分支模型

- `main`：只接收已验证提交；不直接开发企业功能，不做手工大冲突合并。
- 每个功能从最新 `main` 开独立分支，一个 PR 只解决一个切片。
- 推荐命名：
  - `feat/m2-c4-gateway-policy`
  - `feat/m2-c4-gateway-policy-e2e`
  - `feat/m2-c5-operations-audit`
  - `feat/apr-01-approval-step-up`
  - `feat/apr-01b-external-approval`
  - `feat/apr-01c-step-up`
  - `feat/notify-01-outbox-delivery`
  - `feat/m2-d-admin-operations`
  - `feat/m3-central-mcp-resources`
  - `feat/m4-conversation-audit`
  - `fix/<security-or-regression>`
- PR 前必须合入最新 `upstream/main`；冲突在功能分支解决。
- 企业代码优先放 `enterprise/`、插件和最小核心 hook；修改上游跟踪文件必须有 ADR、
  开关、默认关闭、降级路径和额外回归。

### 14.2 每小时的 upstream 同步

当前仓库的 `.github/workflows/sync-upstream.yml` 会每小时抓取并合并
`yetone/magpie/main` 后直接推送 `main`；`devtools/new-feature`、`update-feature` 和
`finish-feature` 也已提供分支创建、上游合并和收尾脚本。它们适合个人开发或紧急维护，
但 `finish-feature` 当前的“直接合并并推送 main”不能作为企业多人和受保护分支的最终流程。

企业目标态应启用受保护 `main`，并让同步走自动 PR：

1. 每小时创建临时分支 `sync/upstream-<timestamp>`。
2. 合并 `upstream/main`。
3. 运行 Go/Node/前端/安全扫描和关键 E2E。
4. 通过后创建 PR 合入 `main`。
5. 冲突、测试失败或需要人工判断时保留分支并告警，不自动覆盖企业提交。

禁止：

- 为“保持实时”强制覆盖企业提交。
- 让同步失败阻塞紧急安全修复。
- 把上游最新 commit 直接部署给员工。
- 在 `main` 上手工解决大冲突。

### 14.3 发布规则

- 企业发布使用独立 tag，例如 `enterprise-v1.4.0`，不从上游最新 commit 直接发布。
- 发布前固定依赖、生成 SBOM/哈希、构建镜像、做秘密扫描和回归。
- 灰度发布，保留上一已验证发布点和回滚脚本。
- 紧急安全修复走独立分支和独立发布点，不等待上游同步。

“实时更新”只表示上游代码和冲突能被及时发现并进入验证队列，不表示把上游最新 commit
自动部署给员工。员工只接收通过企业验收、签名、灰度和可回滚的发布点。

## 15. 验收与上线门槛

每个切片必须同时有：

1. 功能证据：正式入口可完成，不依赖手工改文件或隐藏接口。
2. 权限证据：会话、RBAC、组织范围、资源范围和 CSRF 服务端校验。
3. 审计证据：intent/result、操作者、目标、理由、前后摘要和 `operationId`。
4. 失败证据：超时、审计不可写、部分失败、重复提交和并发冲突不伪造成功。
5. 秘密证据：响应、日志、审计、镜像和员工机无 Key/token/Secret。
6. 环境证据：真实 IdP、反向代理、Docker、Windows/MDM、共享卷、浏览器和备份恢复。

进入生产候选前必须完成：

- 真实企业员工 IdP 和管理 IdP 的 OIDC、MFA/ACR、Claim、停用和会话过期。
- Windows 用户会话计划任务刷新、文件 ACL、锁冲突、断网恢复和重启。
- Docker Compose、真实共享卷、健康检查、只读挂载、日志脱敏和故障恢复。
- 真实 `usage.jsonl` 归属、轮转、损坏检测和管理容器不可写。
- 至少一次离职、设备丢失、跨部门越权和 Key 泄露演练。
- C4-04 的真实 Magpie 请求行为已通过隔离管理链路；C4-03c/C4-03d 的生产部署、页面 E2E
  和真实环境复核通过。
- C5 操作/审计查询与人工对账通过。
- APR-01a/b/c 与 NOTIFY-01a/b/c/d 的本地/Mock 证据通过；真实 OA 回调、step-up、真实厂商
  HTTPS 网关、通知投递、真实 SIEM 接收端、生产值班和浏览器 E2E 仍须按生产清单验收。

任一条件缺失，结论只能是“受控试点”或“生产候选”，不能是“企业生产版完成”。

## 16. 明确不能承诺的内容

- 不能承诺员工只打开网页、不安装任何本地程序就能自动配置本机 Agent。
- 不能承诺管理员可以无审批查看员工对话正文；默认只有 L0 元数据，M4-E 的受控正文读取
  必须经过审批、fresh step-up、理由、一次性授权和访问审计，且真实网关采集与生产验收未完成。
- 不能承诺当前已可通过管理台发布/回滚公司资源或上线中央 MCP；核心和只读资源/同步可见性
  已实现，但资源发布/回滚 UI、审批联动、员工端本地 helper、Agent 文件映射和生产验收未完成。
- 不能承诺当前已有完整、经过生产验收的对话正文/工具审计；M4-A 至 M4-E 核心已实现，
  但真实网关正文采集、WORM/KMS、HA、备份恢复和生产验收仍属于未完成范围。
- 不能承诺当前有真实 OA/IdP/MFA、反向代理、break-glass 生产告警/工单、Webhook/SIEM/工单、
  真实 SIEM 接收端或完整通知运营页；属于 M2-E/M5。当前已有 APR-01a 审批后端、APR-01b
  HMAC/Mock 回调适配器、APR-01c 独立 step-up 和 APR-01e break-glass 核心，但均不等于
  真实企业环境验收。
- 不能承诺当前是高可用、多副本、多地域；属于 M6。
- 不能把 123/26/15/15/14/26/60/67/17（九套合计 363）项本地/Mock 测试等同于真实 IdP、Docker、Windows、代理、
  真实 SIEM、真实审批和
  生产验收。

## 17. 建议的管理决策

1. 先批准“真实环境验收”窗口，不继续堆新页面。
2. 将 C4-03c 真实环境验收、C4-03d 剩余恢复入口、C4-04 部署复核、C5 和 M2-D 浏览器 E2E
   作为下一组连续交付门禁。
3. 继续完成 APR-01e 生产告警/工单与 24 小时复核验收；APR-01d、APR-01e 和 NOTIFY-01d
   核心已实现，NOTIFY-01c transport 已完成，但真实厂商渠道和真实 SIEM 接收端仍需按验收
   清单验证。
4. M3 单独立项，明确 MCP 目录、工具权限、资源签名和同步回滚负责人。
5. 在数据分级和安全/法务批准前，不启用 L2/L3 正文采集。
6. 以 R1 受控试点启动，5-50 人单部门，保留退出、回滚和停止推广条件。
