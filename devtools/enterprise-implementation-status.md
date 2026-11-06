# Magpie 企业版实现状态

状态日期：2026-11-03
定位：这是“代码和测试真实发生了什么”的记录，不是未来方案。产品设计见
[`enterprise-feature-spec.md`](enterprise-feature-spec.md)，实施顺序见
[`enterprise-master-plan.md`](enterprise-master-plan.md) 和
[`enterprise-roadmap.md`](enterprise-roadmap.md)。

2026-11-06 合并 `main`（382 个提交）后新增**原生管理员模式与客户端企业页**：企业网关
增加独立管理监听器 `MAGPIE_ADMIN_ADDR`/`MAGPIE_ADMIN_TOKEN`，以及供应商、路由组、
Gateway Key、遥测管理 API（写操作带 revision 校验、写前写后审计，秘密不投影）；
admin-service 增加网关管理代理、桌面 PKCE 登录（一次性 ticket 换 8 小时、空闲 30 分钟的
短期 token），沿用既有 RBAC/step-up/审批/组织范围；`enterprise/magpie-plugin` 提供员工与
管理员两个客户端视图，覆盖总览、供应商、路由、网关、资源（含发布记录）和用量，页面跟随
窗口主题实时切换。用量页新增企业范围汇总、按用户明细和按天请求柱状图；资源目录新增
`hook` 类型（只登记元数据，不执行）；管理员标签补充 `aria-selected`；新增**审计页**，
按用户/Agent/模型/状态查询已采集内容流并查看流详情，**只显示元数据、不读取正文**。合并后
十套企业 Node 回归 `471 passed, 0 failed`（auth 26、admin 140、gateway-control 38、
resource 16、mcp-gateway 17、client-sync 26、local-mcp 60、audit-service 67、
security-service 44、magpie-plugin 37）；真实 IdP、Compose/反向代理、浏览器 E2E 与
生产验收仍未完成。

正文采集链已接通：网关侧新增 `internal/auditcontent` 观察器（`usage.Observer`，默认关闭，
有界队列满即丢弃，不阻塞模型请求；请求带 Key 才采集，模型无 provider 前缀则跳过，超长按
UTF-8 边界截断）。发送前按 API 格式提取对话文本：Anthropic Messages、OpenAI Responses、
Chat Completions、Gemini 的 system/instructions/messages/contents，以及四种 SSE 流的
文本增量；工具定义、工具参数、图片、思考块和其他字段不采，无法识别的格式不发送。
经 `MAGPIE_AUDIT_CONTENT_URL` 发到 admin-service；admin-service 新增
`POST /api/v1/internal/content/capture`（独立令牌，常量时间比较），用
`content-identity.js` 把 `callerKeyId` 解析为用户/设备/部门（未知或已停用失败关闭），
再以 `content-ingest-client.js` 按常驻授权（purpose、authorizationId、retentionDays）
写入 audit-service 的 streams/chunks。测试：admin 新增 7 项（含错误令牌 401、未知 Key 404、
已吊销 409 且不写入；另有 1 项对真实 audit-service 的端到端测试，断言流最终为
`finalized`、`request.userId` 已解析、明文不出现在索引中），Go 共 24 项（观察器 7 +
文本提取 17）。**尚未**在 Compose 实机运行；生产启用前需提供真实的常驻授权 ID 与审计
服务令牌。

2026-11-03 方案基线更新到 v3.36。当前 `codex/m5-b-response-actions` 分支新增
**M5-B 响应动作状态机与受控模拟执行核心**：新增限流、阻断、吊销 Key、锁定设备和开票五类动作，`requested/approved/active/reverted/expired/failed` 状态机，创建、审批、激活、撤销、过期、列表、详情和逐动作审计 API；强制独立 `SECURITY_CONTROL_TOKEN`、`Idempotency-Key`、组织头、职责分离、授权/动作有效期、source/target 绑定和 fail-closed 校验；每动作使用独立 hash-chain 审计，支持幂等重放、冲突拒绝、组织隔离和重启恢复。执行器明确为 `simulation`，返回 `policyApplied: true`、`gatewayApplied: false` 和 `policy_applied_without_gateway_enforcement`，不声称真实网关阻断；`gateway_key` 因无法验证而 fail closed。security-service 30 项测试通过，九套企业 Node/Mock 回归合计 376 项通过。真实网关阻断/吊销、真实厂商工单、安全运营管理 UI、OTel/Prometheus/Grafana、生产 SIEM、完整 OIDC 角色授权和生产验收仍未完成。此前 `codex/m5-a-gateway-detection-ingest` 分支在
**M5-A 检测规则引擎核心**之上补齐**网关元数据检测事件投递核心**：Magpie 网关通过
`usage.Observer` 在每次路由尝试后发送严格 schema v1 事件，只包含网关 Key 身份、Agent、
Token 用量和 HMAC 哈希后的连接来源地址；不发送 Prompt、回复、Cookie、Authorization、
网关 Key 明文或原始 IP。导出器默认关闭，启用后使用有界异步队列，队列满时丢弃而不阻塞
模型请求；支持 429/5xx 有限重试、`Retry-After`、同事件体/同 `eventId` 重试、禁止重定向、
响应大小限制和关闭时有界 drain。配置错误只使 `securitydetect` 插件失败，不影响模型流量。
新增 Go 测试 12 项通过：内部导出器 8 项、插件生命周期 3 项、真实网关身份/来源地址映射
1 项；security-service 17 项 Node 测试继续通过。Docker/Compose、真实反向代理来源地址、
真实 IdP、真实 SIEM、HA 和生产验收仍未验证。M5-A 切片仍只是检测与投递核心；M5-B 已在本轮补齐状态机和受控模拟执行，但
真实网关阻断/吊销、真实厂商工单、管理 UI 和生产验收未完成，M5-C OTel/Prometheus/Grafana/SIEM/值班手册未完成。此前
`codex/m4-e-admin-content-governance` 分支新增
**M4-E 管理员内容治理**：admin-service 编排 audit-service 的内容流元数据检索、审批 +
fresh step-up + 一次性正文读取、留存清扫、删除/脱敏、HMAC 删除证明、法律保留和加密导出；
audit-service 生成 `.mge` 后，admin-service 使用独立 AES-256-GCM 密钥再加密为 `.mge.enc`。
管理台已接入检索、正文读取、留存、删除证明、法律保留和导出表单；内容治理只允许全局组织
范围 `*`，并明确禁止 break-glass。M4-E 仍默认关闭，真实网关正文采集、WORM/KMS/HA、
备份恢复和生产验收未完成。此前 **M4-D 留存、法律保留、删除证明与加密导出核心**已实现：
正文和元数据留存期独立计算，元数据不得先于正文到期；支持后台和显式 `dryRun` 清扫、
活动法律保留阻止删除/脱敏、幂等显式删除和元数据脱敏、删除 staging 恢复、HMAC 删除证明
列表/详情/验证、AES-256-GCM 加密 `.mge` 导出、一次性短期下载 token、导出审计和过期/
孤儿清理。此前 **M4-C 内容检索与一次性正文授权核心**已实现：签名 cursor 筛选、一次性正文
grant、管理员/组织/会话绑定和访问审计失败关闭。此前 **M4-B 内容审计核心**已实现：开启后
只接受 L2 `text/plain` 脱敏正文，拒绝 L3、附件、二进制和未知字段；实现分片顺序/偏移校验、
幂等重放、冲突/乱序/TTL/容量限制、重启中断恢复，完成后统一脱敏私钥、密码、Bearer/JWT、
云/厂商 token、URL 凭据、邮箱、手机号、身份证
和 Luhn 银行卡；正文对象使用 AES-256-GCM 加密并与索引分目录。健康状态、优雅关闭和
Compose 配置已接入。此前 **M4-A 审计事件管道核心** 已实现：`enterprise/audit-service` 接收
`request`、`response`、
`tool_call` 和 `policy_decision` 四类 schema v1 事件，只接受严格 allowlist 的 L0/L1
元数据，不接收 Prompt、回复、附件、正文或未知字段；提供秘密扫描、规范 UTC 毫秒时间、
Bearer 服务令牌、`Idempotency-Key`、持久 JSON 队列、批量提交、重启恢复、幂等重放/冲突、
会话/请求索引、筛选游标、统计和优雅 drain。Compose 新增内部 `audit` profile，不发布
宿主机端口，并使用独立 `audit-data` 卷。此前 **M3-D-3** 已新增
`setupLocalMcpClient()` 一键配置编排核心：串行执行
`synchronize -> reconcile -> snapshot -> listTools -> 回环 helper 启动与探测 -> Codex 受管配置写入与回读 -> 受控启动器环境注入`；
缺少受控注入器时返回 `token_injection_required`，不伪造启动成功；未提供 token 时仅在进程内
生成 32 字节随机 token，公开结果和 `config.toml` 均不含 token 明文；任一阶段失败会移除本次
写入的受管块、关闭 server 并释放 helper 锁。真实子进程 E2E 已改为经过该编排入口，覆盖
配置回读、环境注入、initialize/list/call 和审计。产品安装器、Windows 服务/MDM、真实
Codex 客户端验收、生产启动器与 token 轮换、管理台员工产品流、真实外部沙箱和生产验收仍未完成。
此前 **M3-C-1** 已提供设备短期同步
凭证、desired-state、设备上报、管理员 JSON 查询和客户端 HTTP 传输适配器。此前
`feat/notify-01d-notification-ops` 分支实现了 **APR-01e break-glass** 的 15 分钟单次紧急授权、
24 小时事后复核、复核提醒、通知事件、RBAC、关键 step-up、审计、API 和管理页，同时保留
**APR-01d 审批箱**的审批视图、串行/并行步骤、quorum、显式 `stepId`、转交和申请人撤回；
在既有 **M2-C5** operation 详情、脱敏审计分页和
四种人工对账动作，**M2-E1/APR-01a** 的服务端审批、绑定摘要、职责分离、一次性消费和
审批系统审计，**APR-01b** 的 HMAC 外部审批回调适配器，以及 **APR-01c** 的独立 OIDC
step-up；对账生成子 operation，不修改原 intent/result。APR-01c 覆盖独立 OIDC Client、
`prompt=login`、`max_age`、`auth_time`、ACR/MFA、会话/IP/User-Agent/角色范围摘要绑定，
未配置 step-up 时高风险操作返回 `503 step_up_unavailable` 并失败关闭。**NOTIFY-01a**
新增 transactional outbox、稳定 `eventId`/`deliveryId` 幂等、租约、指数退避、死信、重启
恢复、deliveries 查询和受审计人工重放。**NOTIFY-01b** 新增
`email`/`im`/`webhook`/`ticketing` 渠道管理 API、渠道测试、按 `eventId + channelId`
fanout 去重，以及统一 HTTPS 渠道适配器：仅允许 HTTPS:443、host allowlist、固定 DNS
解析并拒绝私网/回环/链路本地/云元数据地址，只接受 307/308 且最多 3 跳，每跳重新校验，
并限制超时和响应大小；Webhook 使用时间戳、nonce 和 HMAC-SHA256，Secret 只保存
`secretRef` 环境变量名。本轮 **NOTIFY-01c** 新增 `siem` 渠道及 `http-collector`/
`otlp-http`/`syslog-tls` transport、固定 L0 schema、4 个安全事件类型和 dead-letters API。
本轮 **M2-D** 新增管理写操作基础页面、审批申请/决策/撤销页面、operation/audit 查询、
人工对账、用量/审计 CSV 授权导出和操作历史。导出要求已批准或已消费审批、fresh step-up、
CSRF、RBAC、组织范围、理由、`approvalId` 和 `Idempotency-Key`，使用一次性 Bearer token、
绑定同一管理员会话 Cookie，首次下载即消费并记录 `export.downloaded` 系统审计。
break-glass 绑定环境、策略版本、申请人、动作、目标、组织、风险、理由、payload 摘要和
binding 摘要；授权只能原子消费一次，审批与 break-glass 禁止同时使用，复核人不能是申请人。
使用后立即写入 `security.break_glass_used` 通知/审计，并在复核到期前一小时和逾期时产生
`security.break_glass_review_due`/`security.break_glass_review_overdue`。本轮 **NOTIFY-01d**
新增通知规则、抑制、聚合、阈值/延迟升级、dead-letter 受审计重放，以及管理页的渠道、规则、
投递、死信、聚合、抑制和升级运营视图；规则和渠道写操作继续要求管理会话、CSRF、RBAC、
step-up、理由和幂等。admin-service 当前通过 **123 passed, 0 failed**（86 项管理服务
集成测试 + 5 项内容治理客户端专项 + 5 项内容治理存储专项 + 7 项目录专项 + 7 项通知渠道
专项 + 7 项通知规则专项 + 6 项 SIEM 专项），
auth-service 通过 **26 passed, 0 failed**，gateway-control 通过 **15 passed, 0 failed**，
resource-service 通过 **15 passed, 0 failed**，mcp-gateway 通过 **14 passed, 0 failed**。
client-sync 通过 **26 passed, 0 failed**，M3-D local-mcp 通过 **60 passed, 0 failed**，
audit-service 通过 **67 passed, 0 failed**（20 项事件管道 + 27 项内容审计、检索与一次性
授权核心 + 20 项留存、法律保留、删除证明与加密导出核心），security-service 通过
**30 passed, 0 failed**（17 项 M5-A + 13 项 M5-B）。此前 **M3-C-2** 在既有 104 项管理测试上新增 5 项管理服务测试
（未新增测试文件）；当前九套企业回归合计 **376 passed, 0 failed**。
**C4-01** 网关机器协议已通过 Go 单测、CLI 回归和隔离真实二进制
冒烟；**C4-02** `gateway-control` 受控适配器已通过 15 项 Mock/故障测试；**C4-03a**
正式只读模型目录、**C4-03b/C4-03c** 用户级策略、幂等签发、issuance journal、自动
apply/独立回读、失败补偿、启动恢复和同步后交付均已实现，并通过 Mock/故障测试。
**C4-03d** 部分实现：管理页已有额度/模型写表单和完整证据链状态，员工页已有本人额度、模型、
凭证、设备、同步和恢复提示的只读门户；M2-D 已补基础停用/吊销/轮换页面、审批、
operation/audit 查询、对账和 CSV 导出；浏览器 E2E、失败恢复入口和完整运营体验仍未完成。
**C4-04 完整管理到真实 Magpie 策略流 E2E** 已实现并通过：隔离真实 Magpie 在随机
端口和临时 `XDG_CONFIG_HOME` 中验证了模型白名单 `403`、Token 限额 `429`、旧 Key 撤销、
轮换后策略保持、冲突不落盘、秘密扫描、多凭证部分失败、refresh/rotate 策略继承、故障后
`unknown/pending_sync`、Journal/孤儿 Key 撤销和恢复同步；完整链路覆盖
`admin-service -> auth-service -> gateway-control -> Magpie -> Mock 上游`。Docker/Compose、
真实共享卷、真实企业 IdP、反向代理、浏览器自动化 E2E 和生产验收仍未完成。APR-01b 已
实现 HMAC/Mock 回调协议，但真实 OA/飞书/ServiceNow/Jira 连接器未验证；APR-01c 的
step-up 已完成代码和 Mock IdP 集成测试，APR-01d 的审批箱、串并行步骤、quorum、转交和
撤回已实现，APR-01e 的 break-glass Mock/集成核心已完成；
NOTIFY-01a 的 outbox 核心、NOTIFY-01b 的渠道管理/统一 HTTPS 网关适配器、NOTIFY-01c 的
SIEM transport，以及 NOTIFY-01d 的规则、抑制、聚合、升级、dead-letter 受审计幂等重放和
完整通知运营页面均已实现并通过 Mock/集成测试；邮件、IM、工单当前是 HTTPS 网关契约，不是
原生 SMTP、Graph、飞书、Teams、ServiceNow 或 Jira SDK。真实 SIEM/Collector/Syslog、
生产证书、真实厂商连接和生产值班闭环未验收。
Break-glass Mock/integration core is implemented. Real IdP/MFA, SIEM/alerting,
OA/ticketing, browser E2E, and production post-incident review rehearsal remain unaccepted.
渠道关闭、没有启用渠道或缺少 transport 时不创建 dispatcher，也不会伪造
“已投递”；
**M2-D 核心已实现，Mock/集成测试通过；生产验收尚未完成。** M3-A 的资源目录、不可变版本、
SHA-256 内容寻址、Ed25519 签名、发布/历史回滚、乐观并发、幂等和资源审计核心已实现，
并通过 11 项测试；M3-B 的远程 MCP 注册、企业统一端点、工具级授权、健康检查、上游凭据
隔离和元数据审计核心已实现，并通过 14 项测试；M3-C-1 的同步凭证、desired-state、
设备上报、管理员 JSON 查询、客户端 HTTP 传输适配器和 `readActiveResource()` 已实现，
resource-service 通过 15 项测试（11 项核心 + 4 项控制面），client-sync 通过 26 项测试
（18 项核心 + 8 项传输）。
M3-C 原有签名 desired-state、原子安装、失败保留旧版本、离线缓存、强制/推荐策略、漂移检测、
路径/符号链接防护、并发锁和状态秘密隔离核心仍保持通过；M3-D 受控本地 MCP 运行时、
helper、回环 HTTP server、stdio bridge、Codex 配置映射和一键配置编排核心已实现并通过
60 项隔离单元/Mock 测试，但安装器/Windows 服务/MDM、真实 Codex 客户端、生产启动器与
token 轮换、管理台员工流、真实外部沙箱和生产验收尚未完成。M4-A 审计事件管道核心、
M4-B 内容审计核心、M4-C 检索/一次性授权后端核心、M4-D 留存/法律保留/删除证明/加密导出
后端核心和 M4-E 管理侧治理编排已实现；M5-A 检测规则引擎核心和网关元数据投递核心
已实现，规则引擎 17 项测试和网关侧 12 项 Go 测试通过；M5-B 响应动作状态机与受控模拟执行核心已实现并通过 13 项专项测试，但真实网关执行、真实工单、管理 UI 和生产验收未完成，M5-C 和 M6 仍未实现。
M4-B/M4-C/D/E 默认关闭；
管理台在显式启用后可经 OIDC/RBAC、审批和 fresh step-up 检索、一次性读取脱敏正文、执行
留存/删除并生成双层加密导出，但 break-glass 禁止用于这些动作，且只允许全局组织范围 `*`。
M3-A/M3-B 尚未接入 admin-service 真实审批和可写管理台，M3-B 的 OIDC 组织分配也未实现；
M3-C-1/M3-C-2 已接入员工端短期同步凭证、desired-state/report API，以及管理页只读资源目录
和同步报告/漂移可见性；但资源发布/回滚 UI、发布/回滚审批联动、本地 helper 产品入口、
目标 Agent 文件映射、Windows ACL、MDM、真实 IdP、浏览器 E2E、Docker/Compose 实机验收、
灰度/自动回滚和生产验收尚未完成。M3-B 的审批
nonce 仅单进程内存，注册表和审计不是同一事务，Compose 也尚未实机验收。当前已有默认关闭、
需显式授权的脱敏正文治理链路，但没有真实 Magpie 网关正文采集，也没有生产浏览器 E2E、
WORM/KMS 或正式合规验收。本状态只描述仓库中已经存在并有测试证据的能力。

## 1. 一句话结论

当前完成的是一个**可试点的 M0 企业网关基线**、一个**已完成本地真实链路验收的 M1
身份/设备服务**、一个 **M2-A 管理身份底座**、一个 **M2-B 只读治理切片**、
**M2-C2/C3 管理写接口、幂等与管理审计切片**、**M2-C4 的网关策略控制核心链路**，
以及 **APR-01/APR-01b/APR-01c 和 NOTIFY-01a/01b 的审批、step-up、outbox 与渠道适配器
切片**，并新增 **M3-A 的签名资源目录后端核心**。
真实 Magpie
issuer、Mock OIDC、设备注册、短期 Key 签发、员工调用、用量归属、刷新撤销、停用吊销和
auth-service 重启均已通过端到端测试；管理服务已通过独立 OIDC、MFA/ACR、会话、CSRF、
RBAC、组织范围、用户/部门/设备/凭证/模型/用量只读接口、只读数据卷和依赖故障测试。
M2-C1 已完成 auth-service 内部停用/启用、设备吊销和凭证轮换的内部写接口；M2-C2 已完成
四个 admin-service 对外写接口、管理会话/CSRF/RBAC/组织范围/理由校验和响应脱敏。完整幂等、
`operationId` 和 intent/result 管理审计由 M2-C3 补齐，并已通过成功/失败重放、同键异体、
并发执行中、intent 审计失败和 result 审计失败测试。当前工作分支的 C4-01 已提供
schema v1 的 `gateway-key describe <id> --json` 和原子
`gateway-key policy apply <id> --json`；它只证明网关 Key 的机器回读与原子写入，
`gateway-control` 已完成受控适配器、服务令牌隔离、固定 argv、超时/大小限制和独立
回读，并通过 15 项 Mock/故障测试；C4-03a 已完成管理服务的正式只读模型目录、摘要固定、
严格 JSON 校验和 group 展开；C4-03b/C4-03c 已完成用户级策略核心、M1 `unknown` 迁移、
首次分步设置、版本冲突、失败关闭、幂等签发、issuance journal、自动 apply/readback、
失败补偿、启动恢复和同步后交付。C4-03d 已补管理页额度/模型写表单和员工只读状态门户；
M2-C5 已补 operation/audit 查询和人工对账后端；M2-E1/APR-01a 已补审批 API、L/M/H/C
风险、payload/binding SHA-256、非自审批、过期/撤销校验和原子一次性消费。完整管理到真实
Magpie 策略流 E2E 已经通过。APR-01b 的 HMAC/Mock 外部回调协议和 APR-01c 的独立 OIDC
step-up 已实现；NOTIFY-01b 已提供渠道管理和经过 SSRF/秘密扫描的 HTTPS 渠道适配器，
NOTIFY-01c 已提供固定 L0 schema 的 SIEM transport 和 dead-letters API。审批箱和基础
多步骤管理 UI 已实现，但真实 OA 连接器、真实 IdP/MFA、break-glass、真实 SIEM 接入、通知运营页、
真实厂商连接器、失败恢复入口、停用/吊销/轮换
页面、完整管理写 UI 和真实身份管理链路仍未实现/未验收。
M1/M2-A/M2-B/M2-C1/M2-C2/M2-C3/C4-02/C4-03c 尚未完成真实企业
IdP、Docker Compose、浏览器/反向代理、真实 `usage.jsonl` 数据卷和 Windows 计划任务的
完整验收，因此不能标记为“企业生产版已完成”。

### 1.1 当前员工与管理员实际能做什么

| 使用者 | 当前真实可用 | 当前不可用/不能承诺 |
| --- | --- | --- |
| 员工 | 浏览器 OIDC 登录、本人额度/模型/凭证/设备/同步状态只读门户、Mock/本地真实 issuer 加入、设备注册、短期 Key、通过本地 Magpie 调用企业网关、自动刷新脚本、停用后失效 | 不能只靠网页修改本机 Agent；真实企业 IdP、公司反向代理、Windows 计划任务实机、MDM 安装未验收 |
| 管理员 | 独立管理 OIDC + MFA/ACR、会话/CSRF/IP、RBAC、组织范围，用户/部门/设备/凭证/模型/用量只读视图，正式只读模型目录，四个受控管理写 API，以及额度/模型策略写表单；策略写入会经 auth-service 自动 apply/readback，同步完成前不交付 Key，并返回 `known/pending/partial_success/unknown`；写操作已有幂等重放/冲突、`operationId`、intent/result 审计、operation/audit 查询和受控人工对账；基础停用/吊销/轮换、审批箱、串并行步骤、quorum、转交/撤回、break-glass、用量/审计筛选及 CSV 授权导出已接入；APR-01a 已提供审批申请/决策/撤销 API、审批权限、组织范围校验和一次性消费，APR-01b 已提供 HMAC 外部审批回调适配器，APR-01c 已提供独立 step-up 和 H/C 写操作门禁，APR-01e 已提供 15 分钟单次紧急授权和 24 小时复核 | 真实 OA 连接器、真实管理 IdP/MFA、真实 SIEM/告警、真实工单 ID 回读、break-glass 生产演练和浏览器 E2E 未验收；失败目标恢复入口、完整运营体验和看板未完成；真实 Magpie/共享卷/IdP 未验收；不能管理 MCP/资源库 |
| 管理员能看到的员工信息 | 姓名/邮箱/稳定 ID/部门/状态、设备/版本/心跳、凭证元数据、模型、Token/费用/错误/时间；显式启用且获批时可检索内容元数据、一次性读取脱敏正文、执行留存/删除/法律保留和双层加密导出 | 系统默认 L0，不采集正文；真实网关正文采集、L3、水印、WORM/KMS、生产浏览器 E2E 和合规验收未完成；内容治理只允许全局组织范围 `*`，break-glass 禁止 |
| 安全/审计人员 | 只读用量和授权元数据，角色撤销在下一请求生效；可经授权查询 SIEM 死信元数据；内容治理动作受独立 RBAC、审批、step-up 和审计约束 | 没有默认正文查看、独立导出审批演练、告警阻断、真实 SIEM 检索或生产二次授权演练 |
| 全公司配置 | 管理服务从只读 `ADMIN_MODEL_CATALOG_PATH` 加载正式目录并把 group/provider 选择器展开为稳定模型 ID；auth-service 保存和同步用户级策略，gateway-control 执行原子 apply/独立回读；网关提供模型白名单、额度和 IP 白名单 | 当前没有中央 MCP 服务器、资源库、Skills/Instructions/Subagents 下发；M3 才实现；真实共享卷和企业环境未验收 |

因此，当前只能把员工流程描述为“已安装本地 Magpie 的受控技术试点”，不能描述为“纯网页、
零安装、生产可用的企业客户端”。

## 2. 阶段状态

| 阶段 | 状态 | 可用范围 |
| --- | --- | --- |
| M0 企业网关 | 已完成并通过隔离 E2E | 5-10 人试点、内网访问、按员工 Key 计量 |
| M1 身份与设备 | 已实现，本地真实链路验收通过 | 本地 Mock、并发刷新、“签发中停用”和真实 issuer E2E；生产条件待验收 |
| M2-A 管理身份 | 已实现并通过 Mock 测试 | 管理员登录、会话、CSRF、RBAC、组织范围和健康检查 |
| M2-B 只读治理 | 已实现并通过 Mock 测试 | 用户、部门、设备、凭证、模型、用量只读 API 和服务端范围过滤 |
| M2-C1 Auth 内部写接口 | 已实现并通过 Mock 测试 | 仅服务间令牌；停用/启用、设备吊销、当前凭证轮换；未暴露管理台 |
| M2-C2 管理写 API | 已实现并通过 Mock 测试 | 管理会话/CSRF/RBAC、组织范围、理由、四个停用/启用/吊销/轮换接口和响应脱敏 |
| M2-C3 幂等与管理审计 | 已实现并通过 Mock 测试 | 持久化幂等、同键重放/冲突、执行中保护、`operationId`、intent/result 审计和审计失败阻断 |
| M2-C4-01 网关机器协议 | 已实现并通过本地测试 | schema v1 的 `describe --json`、原子 `policy apply --json`、版本冲突和无秘密输出 |
| M2-C4-02 受控适配器 | 已实现并通过 Mock/故障测试 | `gateway-control` 的固定路由、独立服务令牌、固定 argv、超时、64 KiB 上限、独立回读和 `pending` |
| M2-C4-03a 正式模型目录 | 已实现并通过本地测试 | 只读模型目录、稳定模型 ID、显式 Provider 通配符、group 展开、摘要固定和失败关闭 |
| M2-C4-03b 用户级策略核心 | 已实现，26 项 auth 测试通过 | 旧 M1 `unknown`、quota/models 分步提交、缺项失败关闭、版本冲突、逐凭证回读确认 |
| M2-C4-03c 管理 API 与同步后交付 | 核心已实现，Mock/故障测试通过 | 管理端额度/模型 API、幂等签发、issuance journal、自动 apply/回读、同步后交付、失败补偿和启动恢复；真实环境验收待完成 |
| M2-C4-03d 页面与运营状态 | 部分实现 | 管理页有额度/模型写表单和完整证据链状态；员工页有本人额度、模型、凭证、设备、同步和恢复提示只读视图；M2-D 已补基础写操作、审批、查询、对账和导出页面，但页面 E2E、恢复入口和完整运营体验未完成 |
| M2-C4-04 真实 Magpie 行为 E2E | 完整管理到真实策略流已通过 | 管理 OIDC/CSRF、quota/models 分步设置、双设备 Key、真实模型拒绝和 Token 限额、`partial_success`、refresh/rotate 策略继承、故障后 `unknown/pending_sync`、Journal/孤儿 Key 撤销、恢复同步、usage 归属和秘密扫描均已验证 |
| M2-C5 操作/审计查询与对账 | 后端已实现并通过 Mock/故障测试；M2-D 已接入基础页面 | operation 详情、脱敏审计分页、签名 cursor、组织范围过滤和四种人工对账动作；原 operation/审计不可改写；真实审计存储、完整运营体验和生产运维演练待验收 |
| M2-E1 APR-01a/d/e 审批、审批箱与 break-glass | 已实现核心并通过 Mock/故障测试 | 24 小时有效期、L/M/H/C 风险、规范化 payload/binding SHA-256、申请/批准/拒绝/过期/撤销/撤回/转交/预留/消费状态机、禁止自审批、一次性消费、启动恢复失败关闭和系统审计；审批箱支持串行/并行步骤、显式 `stepId`、quorum 和组织范围筛选；APR-01c 的独立 step-up 已完成代码和 Mock IdP 集成测试；APR-01e 支持 15 分钟单次授权、24 小时复核、复核提醒和独立复核人；真实 OA 连接器、真实 IdP/MFA、真实 SIEM/告警、真实工单、break-glass 生产演练和浏览器 E2E 未验收 |
| APR-01b 外部审批回调适配器 | 已实现 HMAC/Mock 协议并通过测试 | 原始 body HMAC-SHA256、时间窗、nonce 防重放、issuer/audience、eventId 幂等、职责分离、审批状态迁移和系统审计；回调不直接执行管理动作；真实飞书/OA/ServiceNow/Jira 连接器和生产回调演练未验证 |
| APR-01c 独立 OIDC step-up | 已实现并通过 Mock IdP 集成测试 | 独立 OIDC Client/secret/redirect/scopes；`prompt=login`、`max_age`、essential `auth_time`；ACR/MFA、IdP `sub`/email、会话/IP/User-Agent/角色权限/组织范围摘要绑定；H/C 风险写操作和审批门禁；未配置失败关闭；logout/会话过期清理断言；真实 IdP、MFA、反向代理、浏览器和生产验收未完成 |
| APR-01e break-glass | 已实现 Mock/集成核心并通过测试 | `APR-01e-v1` 策略；15 分钟有效、单次原子消费、24 小时事后复核；`active/expired/consumed/review_overdue/reviewed` 状态；`super_admin` 可申请/复核，`security_admin` 仅复核；绑定环境、策略版本、申请人、动作、目标、组织、风险、理由、payload 和 binding 摘要；复核人不能为申请人；使用、复核到期、逾期和复核完成均产生通知与审计；真实 IdP/MFA、SIEM/告警、OA/工单、外部工单 ID 回读、浏览器 E2E 和生产事后复核演练未验收 |
| NOTIFY-01a transactional outbox | 已实现并通过 Mock/故障测试 | 8 种 L0 事件、字段白名单、稳定 `eventId`/`deliveryId`、原子提交、租约、指数退避、死信、重启恢复、deliveries 查询和受审计人工重放 |
| NOTIFY-01b 渠道管理 | 已实现并通过 Mock/故障测试 | `email`/`im`/`webhook`/`ticketing` 渠道 API、RBAC/CSRF/step-up/理由/幂等/审计、渠道测试、按 `eventId + channelId` 去重、HMAC Webhook 和统一 HTTPS 网关适配器；邮件/IM/工单不是原生厂商 SDK；真实厂商连接和生产投递未验收 |
| NOTIFY-01c SIEM transport | 已实现并通过 6 项专项及管理回归 | `http-collector`/`otlp-http`/`syslog-tls`；固定 L0 schema；HTTPS:443/TLS:6514；host allowlist、固定 DNS、私网/回环/链路本地/云元数据拒绝；HTTP/OTLP 可选 Bearer `secretRef`，Syslog 禁止 `secretRef`；默认 32 KiB 上限；critical 优先；5 分钟轮询上限；dead-letters API；新增 4 个安全事件类型；真实 SIEM/Collector/Syslog/生产证书未验收 |
| NOTIFY-01d 通知规则与运营 | 已实现并通过 Mock/集成测试 | 通知规则 CRUD、按事件/严重级别/目标/组织选择渠道；抑制窗口、聚合维度与窗口、阈值和延迟升级、单条升级失败隔离；`aggregates`/`suppressions`/`escalations` 运营查询；dead-letter 受审计幂等重放；管理页提供渠道、规则、投递、死信、聚合、抑制和升级视图；规则/渠道写操作要求会话、CSRF、RBAC、H 级 step-up、理由和 `Idempotency-Key`；真实邮件/IM/Webhook/工单/SIEM 厂商、生产证书和值班闭环未验收 |
| M2-D 管理运营 | 核心已实现，Mock/集成测试通过；生产验收尚未完成 | 基础管理写页面、审批页面、operation/audit 查询、人工对账、CSV 导出和操作历史已实现；浏览器 E2E、失败恢复入口、完整看板和异步/对象存储导出未完成 |
| M3-A 资源目录与签名 | 核心后端已实现，11 项测试通过 | `mcp`/`skill`/`instructions`/`subagent`/`template` 目录、`forced`/`recommended`、不可变版本、SHA-256 内容寻址、canonical JSON、manifest digest、Ed25519 签名、发布/历史回滚、乐观并发、幂等、资源审计和损坏存储失败关闭；M3-C-2 已提供管理页只读资源目录；真实审批、发布/回滚 UI、员工端同步接入和生产验收未完成 |
| M3-B 远程 MCP 治理 | 核心后端已实现，14 项测试通过 | 元数据注册表、企业统一 `/mcp/enterprise` 端点、远程 MCP 代理、user/org/device/server scope、工具级 allow/deny/风险/可见性、short-lived HMAC 审批门禁、健康检查、固定 DNS、HTTPS/host allowlist、拒绝私网/重定向、超时、响应/请求限制、速率和单服务器熔断；管理台、admin-service 真实审批查询/一次性消费、OIDC 组织分配和员工端同步接入未完成 |
| M3-B 生产阻断项 | 未验收 | 审批 nonce 和限流器仅单进程内存；注册表、审计和幂等不是同一事务，审计失败可能发生在状态提交之后；客户端签发审计失败会留下无法取回明文 token 的孤立记录；未做多副本、共享事务存储、KMS/HSM、mTLS、真实 MCP/IdP、浏览器 E2E、Docker/Compose 实机和生产验收 |
| M3-C 客户端同步 | 控制面与核心已实现；resource 15 项、client-sync 26 项测试通过 | 设备短期同步凭证、OIDC `groups` 组织范围、desired-state、设备上报、管理员 JSON 查询、HTTP 传输凭证缓存/重签、条件请求、超时和响应上限；固定 Ed25519 公钥/SPKI 指纹、manifest/内容/长度/SHA-256 校验、staging/fsync/复验/rename 原子激活、失败保留上一验签版本、离线缓存、forced/recommended、漂移检测、路径穿越和符号链接拒绝、并发锁、`0600` 状态、秘密隔离和 `readActiveResource()` active 资源重新验签；M3-C-2 已提供管理页只读资源/漂移可见性；资源发布/回滚 UI、发布/回滚审批联动、本地 helper 安装器/产品入口、浏览器 E2E、Windows ACL、MDM、目标 Agent 文件映射、灰度/自动回滚和生产验收未完成 |
| M3-C-2 只读管理可见性 | 已实现，admin-service 新增 5 项测试并通过；该阶段企业全量 203 项通过 | `GET /api/v1/admin/resources`、`/resources/{id}`（`resources.read`）、`/resource-sync/reports`、`/resource-sync/reports/{deviceId}`（`devices.read`）；`ADMIN_RESOURCE_SERVICE_URL`/`TOKEN` 成对校验、独立 Bearer、GET-only、不跟随重定向、5 秒超时、4 MiB 响应上限；资源按 `"*"`/组织范围可见，报告要求设备存在且 `userId` 与设备映射一致；严格字段白名单；依赖故障统一 `503 resource_service_unavailable`；管理页只读面板无内联脚本；资源发布/回滚 UI、审批联动、真实 IdP、浏览器 E2E、Docker/Compose 实机、灰度/自动回滚和生产验收未完成 |
| M3-D-1 本地 MCP helper/server 核心 | 阶段已实现；后续 M3-D-3 已补齐 stdio bridge、Codex 配置映射、一键配置编排和真实子进程 E2E，当前 local-mcp 60 项测试通过；完整 M3-D 产品集成和生产验收尚未完成 | 既有签名包/原子安装/权限能力/Secret Broker/JSON-RPC/审计/健康核心；新增 `LocalMcpHelper.validateClientResource()`、`reconcile()`、`synchronize()`、`snapshot()`、`listTools()`、`callTool()`；仅使用 client-sync active 资源并重新验签，拒绝 inactive/drift/non-MCP/tampered；回环绑定、peer 复核、Bearer、固定 status/tools/call 路由、256 KiB 默认 body 上限、固定字段、稳定错误码、single-helper 锁、幂等 close、无 CORS、`no-store` 和脱敏 snapshot。该阶段测试使用 Mock client-sync/runtime/helper；后续 M3-D-2/M3-D-3 已补 `ClientSyncEngine + LocalMcpHost + helper HTTP server + stdio bridge` 真实子进程 E2E 和受控启动注入；安装器/Windows 服务/MDM/代码签名/升级回滚、真实 Codex 客户端、生产启动器与 token 轮换、管理台员工流、真实 OIDC/审批/Secret Broker/KMS、Windows ACL、外部 OS 沙箱、Docker/VM、浏览器 E2E、共享卷、HA 和生产验收未完成 |
| M3-D-2 Agent stdio bridge / Codex 配置映射核心 | 已实现，local-mcp 50 项测试通过，含真实子进程 E2E；产品集成和生产验收尚未完成 | 新增 `LocalMcpBridge`、`LoopbackHelperClient`、`runBridgeStdio()` 和 `magpie-local-mcp-bridge` CLI；只接受 `127.0.0.1`/`::1` HTTP helper，token 仅从环境变量读取，固定 initialize/tools/list/tools/call、请求/响应大小上限、超时和稳定错误码。新增 Codex `config.toml` 受管块映射：支持 `CODEX_HOME`、保留用户其他 MCP 配置、幂等原子替换、BOM/CRLF 保留、默认拒绝漂移、显式 `force` 更新，仅写 token 环境变量名。新增 E2E 覆盖 `ClientSyncEngine + LocalMcpHost + helper HTTP server + stdio bridge` 的 initialize/list/call 和审计。真实 Codex 客户端读取 `config.toml`、安装器/Windows 服务/MDM/代码签名/升级回滚、密钥安全注入/轮换、真实 OIDC/审批/Secret Broker/KMS、Windows ACL、外部 OS 沙箱、Docker/VM、浏览器 E2E、共享卷、HA 和生产验收未完成 |
| M3-D-3 一键配置编排核心 | 已实现，local-mcp 60 项测试通过，含经过编排入口的真实子进程 E2E；产品安装器和生产验收尚未完成 | 新增 `setupLocalMcpClient()`、`LOCAL_MCP_CLIENT_SETUP_SCHEMA_VERSION=1` 和 `DEFAULT_CLIENT_SETUP_TOKEN_BYTES=32`；串行编排同步、reconcile、快照选包、工具发现、回环 server/probe、Codex 受管配置写入/回读和受控启动器环境注入；强制 `injectLaunchEnvironment`，缺失返回 `token_injection_required`；自动生成的 token 只在冻结环境补丁中，成功对象和配置不含 token；多资源必须显式 `resourceId`；失败清理受管块、server 和 lock；`inspectCodexAgentConfig()` 严格回读受管 node/bridge/URL/resource/token 变量/超时，畸形配置返回 `agent_config_malformed`。真实 Codex 客户端读取配置、生产 launcher/Windows ACL/DPAPI、token 轮换与恢复、安装器/Windows 服务/MDM、管理台员工产品流、真实 OIDC/审批/Secret Broker/KMS、外部 OS 沙箱、Docker/VM、浏览器 E2E、共享卷、HA 和生产验收未完成 |
| M4 会话内容审计 | M4-A/M4-B/M4-C/M4-D 后端核心和 M4-E 管理侧治理已实现；M4 整体未完成 | `audit-service` 可接收、排队、持久化和查询 L0/L1 元数据；M4-B 可接收 L2 `text/plain` 分片、统一脱敏和 AES-256-GCM 存储；M4-C 可按组织配置边界检索内容元数据，并要求绑定管理员、组织、会话、目标、理由、审批和 TTL 的一次性 grant 读取正文，成功/失败读取均写访问审计；M4-D 支持正文/元数据留存、法律保留、幂等删除/脱敏、HMAC 删除证明、加密 `.mge` 导出、一次性下载和治理审计；M4-E 已接入管理台、管理 OIDC/RBAC/step-up、审批、CSRF、幂等、operation/审计和独立 AES-256-GCM 二次加密下载。系统仍默认 L0；真实网关采集、WORM/KMS、HA、备份恢复和生产验收未完成 |
| M5 安全运营 | M5-A 规则引擎与网关元数据投递核心、M5-B 响应动作状态机与模拟执行核心已实现；M5-C 未实现 | 八条检测规则、确定性 finding/聚合、抑制标记和内部 ingest/read API；网关 `usage.Observer` 每次路由尝试投递严格 schema v1 元数据，不发送 Prompt、回复、Cookie、Authorization 或原始 IP；M5-B 提供五类动作、审批/职责分离、组织隔离、幂等/冲突、source/target 绑定、有效期、撤销、失败状态和逐动作 hash-chain 审计，当前只做受控模拟执行且 `gatewayApplied: false`；真实网关阻断/吊销、真实工单、管理 UI、生产 SIEM、指标看板和值班闭环未完成 |
| M6 高可用/规模化 | 未实现 | 当前单实例、JSON 存储 |

### 2.1 C4/C5/D/E1 的实现边界

以下能力已经存在：C4-01 提供 schema v1 的机器回读和原子策略写入，复用
`internal/access` 的文件锁、原子替换、模型校验和额度校验；Go 测试覆盖 schema、无秘密
输出、回读、冲突、未知字段、NaN/Inf、超限和文件锁内原子替换。C4-02 提供
`enterprise/gateway-control/` 受控适配器，只允许 Key 描述、策略应用和健康检查，使用
`shell: false` 的固定 argv、独立 Bearer 服务令牌、默认 10 秒超时、64 KiB 请求/输出
上限、Key ID 白名单和写入后的独立 `describe` 回读；15 项 Mock/故障测试已通过。
C4-03a 由 admin-service 从只读 `ADMIN_MODEL_CATALOG_PATH` 加载 schema v1 目录，校验
2 MiB 上限、重复 key、未知字段、稳定模型 ID、显式 Provider 通配符和 group 引用，并可用
SHA-256 digest 固定文件；无效目录会使管理服务启动失败。`GET /api/v1/admin/models` 返回
安全目录投影，`ADMIN_MODELS` 仅保留无目录时的兼容显示。admin-service 在写入前把
group/provider 选择器展开为稳定模型 ID；auth-service 和 gateway-control 不加载目录。

C4-03b/C4-03c 的当前真实链路是：

```text
admin-service
  -> auth-service
  -> gateway-control
  -> Magpie describe/apply/readback
  -> credential commit
  -> key delivery
```

- auth-service 提供版本化用户级 `gatewayPolicy`、旧 M1 `unknown` 迁移、quota/models 任意
  顺序首次设置、`policy_setup_required`、版本冲突和逐凭证回读确认。
- 管理端通过 `PUT /api/v1/admin/users/{id}/policy/quota` 和
  `PATCH /api/v1/admin/users/{id}/policy/models` 受控调额/授权；管理端展开模型选择器，
  auth-service 只接收稳定模型 ID。
- auth-service 使用 `enterpriseIssuanceId` 做幂等签发，并维护
  `preparing/issued/syncing/synced/committed/failed/unknown` issuance journal。
- 只有 apply 成功、独立 describe 回读一致且凭证状态原子提交后才交付 Key；失败会撤销
  不确定的孤儿 Key，无法确认的补偿保留 `unknown`，启动时扫描非 `committed` journal。
- 部分凭证失败返回 `partial_success` 和 `requiresReconciliation=true`，策略保持
  `pending`；全部失败/超时返回 `502 dependency_unavailable`，不伪造成功。
- 管理操作持久化 `operationId`、payload 绑定幂等、白名单前后摘要和 intent/result 审计。
- M2-C5 提供 `GET /api/v1/admin/operations/{operationId}`、
  `GET /api/v1/admin/audit-logs` 和 `POST /api/v1/admin/operations/{operationId}/reconcile`；
  operation 查询按原动作权限和目标组织范围授权，审计查询使用绑定会话与查询条件的签名
  cursor，只返回脱敏元数据。
- 人工对账要求 `operations.reconcile`、CSRF、`reason`、`approvalId`、`Idempotency-Key`
  和 `evidenceRef`，动作固定为 `retry_desired`、`rollback_previous`、`confirm_applied`、
  `confirm_not_applied`；每次对账创建子 operation，父 operation 的原结果和审计不可改写。
- APR-01a 提供 `POST /api/v1/admin/approvals`、`GET /api/v1/admin/approvals/{id}`、
  `POST /api/v1/admin/approvals/{id}/decisions` 和
  `POST /api/v1/admin/approvals/{id}/revoke`。审批绑定环境、申请人、组织范围、动作、
  目标、风险、理由、规范化 payload 摘要和策略版本，有效期 24 小时。
- 除低风险 `user.enable` 外，现有受支持管理动作必须消费一个已批准且未过期的审批；
  申请人不能审批自己的请求。审批在业务写入前原子预留，成功后标记为 `consumed`；
  并发复用返回 `409 approval_consumed`，启动时遗留 `reserved` 状态失败关闭为 `consumed`。
- 审批申请、决策和撤销都要求管理会话、CSRF、理由和对应权限，并写系统审计。审批存储使用
  `approvalRequests`、`approvalDecisions`、`approvalConsumptions`、
  `approvalCallbackEvents` 和 `approvalCallbackNonces` 五个集合；APR-01b 使用独立
  HMAC 回调端点，验签和 nonce 校验通过后只改变审批状态，不直接执行管理动作。
  APR-01c 使用独立 step-up OIDC Client，要求 `prompt=login`、`max_age`、新鲜
  `auth_time` 和允许的 ACR；断言绑定管理会话哈希、管理员 subject、客户端 IP、
  User-Agent 哈希及角色/权限/组织范围摘要。H/C 风险写入、审批创建和审批决策必须通过
  step-up；未配置 step-up 时失败关闭。NOTIFY-01a 已新增与审批/operation 业务审计同一次
  原子存储提交的 outbox，8 种 L0 事件、稳定 `eventId`/`deliveryId`、租约、1/5/15/60/360
  分钟退避、最大尝试、死信、重启租约恢复、安全 deliveries 查询和受审计人工重放均已通过
  Mock/故障测试。NOTIFY-01b 新增渠道管理 API、测试记录、按 `eventId + channelId`
  fanout 去重和统一 HTTPS 网关适配器；只允许 HTTPS:443、host allowlist、固定 DNS
  解析，拒绝私网/回环/链路本地/云元数据地址，只接受 307/308 最多 3 跳且每跳重新校验。
  Webhook 使用 `X-Magpie-Timestamp`、`X-Magpie-Nonce`、`X-Magpie-Signature`，签名为
  `v1 = HMAC-SHA256(secret, timestamp.nonce.rawJsonBody)`。审批申请/决策基础页面已存在；真实 OA 连接器、
  真实 IdP/MFA、完整审批箱、break-glass、真实 SIEM 接入、rules/suppress、通知运营页面和真实厂商连接
  尚未实现/未验收。
- auth-service 的 policy reconcile 内部接口在同一版本事务中原子更新 models 和 limits，版本
  只增加一次，并为每张活跃凭证各调用一次 gateway-control；旧快照不完整时拒绝回滚。

仍未完成或未验收：

- Dockerfile/Compose 静态配置已完成，但 Docker 构建、Compose 启动、健康检查和真实共享卷
  尚未实机验收。
- 服务间当前使用独立 Bearer 令牌，不是 mTLS；mTLS/SPIFFE/工作负载身份仍是生产加固项。
- C4-03d 已实现管理页额度/模型写表单和员工只读状态门户；M2-D 已补基础停用/吊销/轮换
  页面、审批、查询、对账和导出，但仍缺页面 E2E、失败设备恢复入口和完整运营体验。
- C4-04 的完整管理到真实 Magpie 策略流 E2E 已通过，证明真实模型拒绝、Token 限额、
  冲突不写、rotate 策略保持、双设备部分失败、refresh/rotate 策略继承、故障后 pending、
  Journal/孤儿 Key 撤销和恢复同步；Docker/共享卷、企业 IdP、反向代理、公司 CA 和浏览器
  自动化 E2E 仍无验收证据。
- 旧凭证在没有独立网关回读前仍只能是 `unknown`，不能因为管理端存在策略 API 就标为
  `known`。

因此当前可描述为“管理 API 到同步后交付的 Mock/故障链路已实现，可受控技术试点”，不能
描述为“企业生产调额与模型授权闭环已完成”。

## 3. 已实现的代码

### M0 企业网关基线

- `enterprise/docker-compose.yml`：企业网关 Compose 模板。
- `enterprise/.env.example`：网关和认证服务环境变量模板；只含占位符，不含真实密钥。
- `enterprise/scripts/provision-user.ps1`：创建/调整员工网关 Key、模型白名单、额度和只读属性。
- `enterprise/scripts/join-client.ps1`：把企业网关 Provider 写入本地 Magpie，可调用 Agent 一键配置。
- `enterprise/scripts/verify.ps1`：检查模型列表和一次 chat 请求。
- `enterprise/test/e2e.ps1`：验证客户端 → 企业网关 → Mock 上游 → 按员工 Key 归属用量。

### M1 OIDC、设备和短期凭证

- `enterprise/auth-service/src/oidc.js`：OIDC discovery、授权码 + PKCE、JWKS 缓存和 `id_token` 校验。
- `enterprise/auth-service/src/security.js`：JWT 签名验证、PKCE、Cookie 签名和常量时间比较。
- `enterprise/auth-service/src/service.js`：登录、加入码、设备注册/心跳/刷新/吊销、最小管理
  接口；按设备串行化刷新，并在持久化前复核设备、用户、令牌和审计状态，避免并发刷新产生
  孤儿 Key。
- `enterprise/auth-service/src/magpie.js`：调用 Magpie issuer API 签发和撤销短期 Key。
- `enterprise/auth-service/src/store.js`：原子写入 JSON 存储；设备令牌和网关 Key 只保存哈希。
- `enterprise/scripts/join-enterprise.ps1`：生成设备 RSA 密钥和 PKCE，完成浏览器加入并把凭据保存到当前用户 ACL 保护的文件。
- `enterprise/scripts/refresh-client.ps1`：使用设备令牌轮换短期 Key，更新本地 Provider；有文件锁和脱敏刷新日志。
- `enterprise/test/auth-e2e.ps1`：真实 Magpie issuer、Mock OIDC、Mock 上游和 auth-service 的 M1 端到端验收脚本。
- `enterprise/test/mock-oidc.mjs`：E2E 使用的本地 OIDC 授权码、Token 和 JWKS 模拟器。

### M2-A 管理身份底座

- `enterprise/admin-service/src/oidc.js`：独立管理端 OIDC、PKCE、JWKS 校验、MFA/ACR 和
  已验证邮箱检查。
- `enterprise/admin-service/src/session.js`：管理会话、绝对/空闲超时、IP 和 User-Agent
  绑定、CSRF。
- `enterprise/admin-service/src/rbac.js`：角色权限表、有效期、组织子树范围和每次请求重新
  计算权限。
- `enterprise/admin-service/src/service.js`：管理登录、最小管理页面、`/admin/me`、组织范围、
  健康检查和稳定错误码。
- `enterprise/admin-service/src/auth-client.js`：使用独立服务令牌调用 auth-service 内部状态
  接口，不转发浏览器 Cookie。
- `enterprise/admin-service/src/store.js`：组织、角色、会话和管理审计的原子 JSON 存储。
- `enterprise/auth-service/src/service.js`：新增 `/api/v1/internal/admin/status`，只返回
  用户、设备和待撤销计数，要求 `AUTH_INTERNAL_ADMIN_TOKEN`。
- `enterprise/docker-compose.yml`、`.env.example`：新增 `admin` profile、独立端口、独立卷和
  管理端配置模板。

### M2-B 只读治理

- `enterprise/auth-service/src/store.js`：新增 `credentials` 元数据集合；旧 M1 store 可自动
  补齐，不保存 Gateway Key 明文。
- `enterprise/auth-service/src/service.js`：设备吊销、用户停用和刷新时同步凭证状态；新增
  `/api/v1/internal/admin/status|users|devices|credentials`，只接受独立内部服务令牌。
- `enterprise/admin-service/src/auth-client.js`：统一调用 auth-service 内部只读接口，依赖
  故障返回 `502 dependency_unavailable`。
- `enterprise/admin-service/src/store.js`：新增 `userOrgUnits` 受控用户-组织映射；未映射用户
  只对全域管理员可见，不按邮箱猜部门。
- `enterprise/admin-service/src/usage-reader.js`：只读解析 `usage.jsonl`；缺失、不可读、损坏、
  尾部半行、非 UTF-8、超行/超字段/超记录/超大小均返回 `503 storage_unavailable`。
- `enterprise/admin-service/src/service.js`：新增用户、部门、设备、凭证、模型、用量汇总和
  时间序列只读 API；服务端按组织子树过滤；管理页展示只读摘要。
- `enterprise/docker-compose.yml`：admin-service 只读挂载网关数据卷并配置
  `ADMIN_USAGE_PATH=/magpie-readonly/magpie/usage.jsonl`；不能写网关数据卷。

### M2-C1 Auth 内部写接口

- `enterprise/auth-service/src/service.js`：新增四个内部写接口，只接受
  `AUTH_INTERNAL_ADMIN_TOKEN`：
  - `POST /api/v1/internal/admin/users/{id}/disable`
  - `POST /api/v1/internal/admin/users/{id}/enable`
  - `POST /api/v1/internal/admin/devices/{id}/revoke`
  - `POST /api/v1/internal/admin/credentials/{id}/rotate`
- `disable` 将用户和全部设备置为不可用，删除网页/管理会话，撤销全部 active 凭证，并把当前
  Gateway Key 加入撤销队列。`enable` 只恢复用户状态，不自动恢复旧设备、旧凭证或旧会话，
  响应明确返回 `requiresDeviceJoin: true`。
- 设备吊销按设备串行化，只影响目标设备及其 active 凭证；凭证轮换先读取设备 ID，再进入
  设备锁并重新校验用户、设备、凭证和“是否为设备当前 Key”，最后签发新 Key、撤销旧凭证。
- 轮换响应不返回新 Gateway Key 明文，只返回新凭证 ID 和
  `status: awaiting_device_refresh`；新 Key 只通过目标设备的后续刷新流程交付。持久化失败时
  立即撤销新 Key，避免留下活跃孤儿。
- C1 本身不包含：admin-service 对外写 API、管理会话/CSRF/RBAC 映射、幂等键、理由、组织
  范围写校验和 intent/result 管理审计。这些能力随后由 M2-C2/C3 接入；额度/模型策略写入
  已由 C4-03c/C4-03d 部分接入，操作/审计查询和对账后端由 M2-C5 接入，完整管理台写操作
  仍属于 M2-D。

### M2-C2 管理写接口与权限映射

- `enterprise/admin-service/src/auth-client.js`：抽取通用 `request()`，新增 `post()` 和四个
  内部写调用。
- `enterprise/admin-service/src/service.js`：新增四个管理写路由：
  - `POST /api/v1/admin/users/{id}/disable`
  - `POST /api/v1/admin/users/{id}/enable`
  - `POST /api/v1/admin/devices/{id}/revoke`
  - `POST /api/v1/admin/credentials/{id}/rotate`
- 检查顺序固定为：管理会话 -> CSRF -> JSON -> 必填 `reason` -> 可选 `Idempotency-Key`
  格式 -> RBAC -> 目标存在及组织子树 -> 调用 auth-service。
- 目标所属用户从 auth-service 读取后校验组织范围；跨部门写返回 `403 forbidden_scope`，
  且在目标/范围检查失败时不调用依赖写接口。
- 写响应使用字段白名单；不返回 Gateway Key、设备令牌、token hash、公钥或服务令牌。
  auth-service 故障稳定映射为 `502 dependency_unavailable`。
- C2 提供管理会话、CSRF、RBAC、组织子树、理由、目标预检和响应脱敏；幂等键持久化、重放、
  冲突、`operationId` 和 intent/result 审计由随后的 M2-C3 接入。

### M2-C3 幂等、操作状态与管理审计

- `enterprise/admin-service/src/store.js`：新增 `adminOperations` 和 `adminIdempotency`
  集合；旧 store 会自动补齐集合，已有数据仍可加载。
- `enterprise/admin-service/src/service.js`：四个管理写接口统一进入
  `performWrite()`，按以下顺序执行：
  1. 管理会话和 CSRF。
  2. JSON、`reason`、`approvalId` 和可选 `Idempotency-Key` 校验。
  3. RBAC、目标存在性、目标组织范围和请求指纹计算。
  4. 原子预留幂等键、创建 `operationId`、写 `intent` 审计。
  5. 调用 auth-service。
  6. 写 `result` 审计并提交 operation 的最终状态。
  7. 返回安全成功结果或稳定错误。
- 幂等键只保存 `SHA-256(actorSubjectId + "\0" + key)`，不保存原键；请求指纹覆盖动作、
  目标类型、目标 ID、理由和审批 ID；C4 额度/模型接口进一步把规范化 payload 和
  `expectedVersion` 纳入指纹。
- 同键同请求重放原响应、原 `operationId` 和原 `requestId`；同键异体返回
  `409 idempotency_conflict`；同键操作仍在执行返回 `409 operation_in_progress`。
- 失败操作会保存原失败并稳定重放，不会自动重试依赖。
- intent 审计写入失败返回 `503 audit_unavailable`，依赖调用次数为 0。
- result 审计写入失败返回 `503 audit_unavailable`，不返回成功；operation 保留在
  `dependency_invoked`，由 C5 的 operation 查询、失败对账和人工补偿流程处理。
- operation 和审计只保存安全业务快照，不保存 Gateway Key、设备令牌、Cookie、token hash、
  OIDC Secret、服务令牌或对话正文。

### M2-C4-02 受控网关适配器

- `enterprise/gateway-control/src/service.js`：只实现 `GET /api/v1/gateway-keys/{id}`、
  `POST /api/v1/gateway-keys/{id}/policy` 和 `GET /healthz`；写路由要求 JSON，Key ID
  只接受 `^[A-Za-z0-9_-]{1,64}$`。
- `enterprise/gateway-control/src/runner.js`：使用固定 argv、`shell: false`、固定工作目录和
  最小环境变量调用 C4-01 的 `describe`/`policy apply`；请求体和子进程输出上限均为
  64 KiB，默认 10 秒超时，超时后终止子进程。
- `enterprise/gateway-control/src/config.js`：验证 Magpie 与配置目录的绝对路径，要求
  `GATEWAY_CONTROL_TOKEN` 至少 32 字符，并拒绝复用已知 Secret。
- `enterprise/gateway-control/src/server.js`：只监听受控地址，使用 timing-safe 比较验证
  独立 Bearer 服务令牌；日志不含请求体、CLI 输出、Key、token hash 或服务令牌。
- 写入后独立执行一次 `describe`，仅当模型、额度窗口和 `policyRevision` 一致时返回
  `200 applied`；超时、输出损坏或回读不一致返回 `502` 和 `state: pending`，不伪造成功。
- `enterprise/gateway-control/Dockerfile`、`enterprise/docker-compose.yml` 的
  `gateway-control` profile、`.env.example` 和 README 已新增；Compose 不发布宿主机端口，
  只使用内部网络和 `magpie-data:/config`，并配置只读根文件系统、`cap_drop: ALL`、
  `no-new-privileges` 和非 root UID/GID。
- 当前适配器已由 admin-service -> auth-service 的 C4-03c 链路自动调用；auth-service
  在 apply/独立回读成功后才提交凭证并交付 Key，部分成功、失败补偿和启动恢复已有
  Mock/故障测试。真实共享卷、真实 Magpie 行为 E2E 和人工对账仍未验收。

### M2-C4-03b 用户级策略核心

- `enterprise/auth-service/src/service.js`：用户级 `gatewayPolicy` 包含单调递增
  `version`、`models`、0-5 个 `limits` 窗口、`quotaStatus/modelStatus`、
  `operationId`、`updatedAt` 和 `confirmedAt`；旧 M1 数据只迁移为 `unknown`，不反推
  历史额度或模型范围。
- quota 和 models 可以由 `PUT .../policy/quota` 与 `PATCH .../policy/models` 任意顺序
  首次设置；缺少任意一项时返回 `409 policy_setup_required`，不伪造空额度或默认模型。
- 写接口支持 `expectedVersion`/`If-Match`、`operationId` 和版本冲突；join、refresh、
  rotate 在调用 `magpie.issue()` 前检查完整策略，`unknown/pending` 时失败关闭。
- `POST .../policy/confirm-credential` 只接受固定字段白名单的 gateway-control 回读，
  校验 schema v1、时间、`policyRevision`、模型和 0-5 个额度窗口的完整一致性；响应和
  存储不返回 Gateway Key、设备令牌、token hash、OIDC Secret 或服务令牌。
- C4-03b 的策略核心已与 C4-03c 的自动编排接通；真实 Magpie 行为 E2E、Docker/共享卷、
  企业 IdP 和人工对账仍未验收，因此不能称企业生产闭环已完成。

### M2-C4-03c 管理 API、同步与交付

- `enterprise/admin-service/src/service.js`：新增额度/模型管理写 API，要求
  `quota.write`/`models.write`、CSRF、RBAC、组织范围、`reason`、`expectedVersion`
  或一致的 `If-Match`，并在调用 auth-service 前展开模型目录选择器。
- `enterprise/admin-service/src/auth-client.js`：支持受控 JSON `PUT/PATCH` 和
  `If-Match` 透传；auth-service 返回的同步状态、错误码和 reconciliation 标记按白名单透出。
- `enterprise/admin-service/src/service.js`：额度/模型 payload 和 `expectedVersion` 纳入
  幂等指纹；同键异 payload 返回 `409 idempotency_conflict`，策略版本冲突保持
  `409 policy_version_conflict`。
- `enterprise/auth-service/src/gateway-control.js`：以独立服务令牌调用固定
  `gateway-control` 路由，校验 schema v1、稳定模型 ID、额度窗口、readback
  `policyRevision` 和超时/大小限制。
- `enterprise/auth-service/src/service.js`：serve 决策在调用 `magpie.issue()` 前检查完整
  `gatewayPolicy`；签发使用 `enterpriseIssuanceId` 幂等，journal 状态为
  `preparing/issued/syncing/synced/committed/failed/unknown`，非 `committed` 状态在启动时
  扫描并撤销可确认的孤儿 Key。
- 交付顺序固定为：journal preparing -> 幂等 issue -> apply -> 独立 describe readback ->
  原子凭证提交 -> 返回 Key。同步完成前不交付 Key；撤销不确定时保留 `unknown`，不伪造
  补偿成功。
- 部分凭证失败返回 HTTP 200、`state=partial_success`、
  `requiresReconciliation=true`，策略保持 `pending`；全部失败或适配器不可用返回
  `502 dependency_unavailable`。
- 管理页新增策略版本、凭证同步状态、最后同步时间和稳定错误码展示，并提供额度/模型策略
  写表单；员工页提供本人额度和模型等只读状态。这是 C4-03d 的部分实现，不包含失败恢复
  和完整运营体验；基础停用/吊销/轮换、查询、对账和导出页面已由 M2-D 接入。

### M2-E1 APR-01a 服务端审批

- `enterprise/admin-service/src/approval.js`：集中定义 `APR-01a-v1` 策略版本、L/M/H/C
  风险、审批状态、规范化 payload、payload SHA-256、binding SHA-256、审批过期判断和消费
  前校验。
- `enterprise/admin-service/src/service.js`：新增四个审批 API，并把受支持的高风险/关键
  管理写操作接入审批消费。申请、决策和撤销要求管理会话、CSRF、必填理由和对应权限；
  决策和撤销还会按申请人的组织范围校验目标审批。
- `enterprise/admin-service/src/rbac.js`：新增 `approvals.read`、`approvals.decide` 和
  `approvals.revoke`，分别授予需要只读、审批和撤销能力的角色。
- `enterprise/admin-service/src/store.js`：新增 `approvalRequests`、`approvalDecisions`
  和 `approvalConsumptions`；旧 store 自动补齐空集合，损坏引用或非法状态拒绝加载。
- 审批固定 24 小时有效。除低风险 `user.enable` 外，当前受支持的 `credential.rotate`、
  `user.policy.quota`、`user.disable`、`device.revoke`、`user.policy.models` 和
  `operation.reconcile` 都需要审批。
- 审批绑定 `environmentId`、策略版本、申请人、动作、目标类型/ID、目标组织、风险、理由和
  payload 摘要；修改审批后的目标、额度、模型、对账证据或策略版本会失败关闭。
- 申请人不能审批自己的请求；审批必须在业务依赖调用前原子预留，成功写入后一次性消费。
  同一审批被并发复用返回 `409 approval_consumed`，幂等重放发生在审批消费检查之前。
- 启动恢复把遗留 `reserved` 审批保守地标记为 `consumed`，防止进程重启后重复授权；审批
  申请、决策、撤销、消费和恢复均写系统审计。
- APR-01b 已实现 HMAC/Mock 外部审批回调协议并通过测试；APR-01c 的独立 OIDC step-up
  已完成代码和 Mock IdP 集成测试；APR-01d 已实现审批箱、串并行步骤、quorum、转交、撤回
  和基础管理 UI；APR-01e 已实现 break-glass Mock/集成核心。尚未验收：真实
  飞书/OA/ServiceNow/Jira 连接器、真实 IdP/MFA、浏览器审批 E2E、真实告警/工单和
  生产事后复核演练。

### M2-E1 APR-01e break-glass

- `enterprise/admin-service/src/break-glass.js`：固定 `APR-01e-v1` 策略、15 分钟授权有效期、
  24 小时复核期限、五种投影状态和复核调度器；状态由授权时间和复核记录推导，不依赖可漂移
  的静态标记。
- 授权绑定 `environmentId`、策略版本、申请人、动作、目标类型/ID、目标组织、风险、理由、
  payload 摘要和 binding 摘要；任一字段变化均返回 `break_glass_target_mismatch` 或
  `break_glass_payload_mismatch`，且审批与 break-glass 不能同时用于同一业务操作。
- `super_admin` 可申请和复核，`security_admin` 仅可复核，`ops_admin` 无权限；申请与复核
  都要求管理会话、CSRF、必填理由、对应 RBAC、组织范围、新鲜的 critical step-up 和
  `Idempotency-Key`。
- 消费前在存储锁内校验状态和绑定并原子写入 `consumedAt`、`operationId` 和
  `reviewDueAt`；并发消费只有一个成功，重复使用返回稳定错误，业务依赖失败后也保留已使用
  事实、通知和审计证据。
- 使用后产生 `security.break_glass_used`；复核到期前一小时产生
  `security.break_glass_review_due`，逾期产生 `security.break_glass_review_overdue`，
  完成复核产生 `security.break_glass_reviewed`。申请人不能复核自己的授权，复核记录不可改写。
- API 为 `POST/GET /api/v1/admin/break-glass`、`GET /api/v1/admin/break-glass/{id}` 和
  `POST /api/v1/admin/break-glass/{id}/review`；管理页支持申请、状态筛选、详情、复核和
  operation/导出入口。
- Break-glass Mock/integration core is implemented. Real IdP/MFA, SIEM/alerting,
  OA/ticketing, browser E2E, and production post-incident review rehearsal remain unaccepted.

### APR-01c 独立 OIDC step-up

- `config.js` 增加独立 step-up OIDC Client、Secret、redirect URI、scopes、允许的 ACR
  值和 TTL；未配置时高风险操作失败关闭。
- `/admin/oauth/step-up/start` 发起独立授权码 + PKCE 流程，强制 `prompt=login` 和
  `max_age`；callback 校验 state、nonce、`auth_time` 新鲜度、`acr`/MFA、IdP `sub` 和
  email 一致性。
- `stepUpAssertions` 不保存 access token、refresh token、cookie 或 client secret；断言
  绑定管理会话哈希、管理员 subject、客户端 IP、User-Agent 哈希及角色/权限/组织范围摘要。
- H/C 风险写入、审批创建和审批决策强制 step-up；TTL 默认 600 秒，关键动作默认 300 秒。
  logout 和会话过期会清理对应断言。
- `/api/v1/admin/me` 返回 `stepUp.state`、`startUrl` 和有效期信息；管理页显示近期认证
  状态，并在 `step_up_*` 错误时提供重新认证入口。
- 修复了状态读取 bug：`requireStepUp()`、`stepUpState()` 和 `mePayload()` 现接收完整
  `current` 对象，避免成功认证后仍错误显示 `"state":"required"`。
- 真实企业 IdP、真实 MFA/条件访问、反向代理、浏览器流程和生产验收仍未执行。

## 4. 已通过的测试

### 4.1 Auth 服务和 Mock 集成

```powershell
& 'D:\Environment\node-v26.12.1\node.exe' `
  --test enterprise\auth-service\test\auth-service.test.mjs
```

结果：`25 passed, 0 failed`。覆盖：

- OIDC discovery、JWT/JWKS 验签、PKCE、加入码换取。
- 无效设备公钥被拒绝。
- 设备心跳、短期 Key 刷新和旧 Key 撤销。
- 持久化失败时新 Key 被撤销，避免孤儿 Key。
- 设备令牌过期、用户停用、设备令牌和网关 Key 被拒绝。
- 存储中不出现明文网关 Key、设备令牌或 issuer Key。
- 浏览器登录会话和 `/api/v1/me`。
- 同一设备 5 个并发刷新请求最终只有一个活跃 Key；其余新 Key 立即撤销。
- 刷新签发过程中停用员工：刷新返回 `403`，刚签发的新 Key 被立即撤销，存储中没有活跃员工
  设备 Key。
- 内部管理状态接口：无令牌和错误令牌返回 `401`，独立服务令牌返回最小计数，不能复用
  `AUTH_ADMIN_TOKEN`。
- 凭证元数据跟随签发、刷新、设备吊销和用户停用变化；响应不含 Gateway Key、设备令牌、
  token hash 或公钥正文。
- 旧 M1 store 没有 `credentials` 集合时仍可加载，且不会伪造历史凭证。
- 四个内部写接口缺少令牌、错误令牌或复用 `AUTH_ADMIN_TOKEN` 时均返回 `401`。
- 内部停用后用户、设备、凭证和会话状态正确，心跳和刷新返回 `403`；启用后旧设备仍不可用，
  员工必须重新加入。
- 设备吊销只影响目标设备；凭证轮换成功会撤销旧 Key、让设备指向新 Key，响应不含新 Key
  明文；目标不存在、凭证非 active 或不是当前 Key 时返回稳定错误。
- 轮换持久化失败会立即撤销新 Key；同设备并发 rotate 与 refresh 最终只有一个 active Key。
- 内部写接口响应和持久化数据不包含 Gateway Key、设备令牌、token hash、公钥正文或服务令牌。
- 旧 M1 用户和凭证迁移后只得到 `quotaStatus/modelStatus=unknown`，重复迁移幂等。
- quota/models 任意顺序首次设置均不伪造缺失项；缺项时 join、refresh、rotate 在调用
  `magpie.issue()` 前返回 `policy_setup_required`。
- 策略 `expectedVersion`/`If-Match`、版本冲突、非法 JSON、模型边界和 0-5 个额度窗口
  校验通过。
- 凭证回读确认严格比较 schema、时间、策略版本、模型和额度；响应、存储和错误详情不泄露
  Gateway Key、设备令牌、token hash、OIDC Secret 或服务令牌。
- 正常签发链路会先写 issuance journal，使用 `enterpriseIssuanceId` 调用幂等签发，再执行
  gateway-control apply/独立回读，最后在同一存储事务中提交凭证和 journal；刷新和轮换
  均走同一交付门禁。
- 现有回归还覆盖策略更新后的凭证同步结果、pending/unknown 失败关闭、轮换提交失败后的
  孤儿 Key 撤销和策略版本冲突。
- C5 策略对账测试覆盖 models+limits 原子更新、version 恰好增加一次、每张活跃凭证各
  apply 一次、stale version 冲突、并发对账只成功一次，以及响应和持久化状态不泄露秘密。

### 4.2 管理服务 M2-A/M2-B/M2-C2/M2-C3/M2-C5/M2-E1/APR-01b/01c/01e/NOTIFY-01a/01b/01d/C4-03c/M3-C-2

```powershell
$node = 'D:\Environment\node-v26.12.1\node.exe'
Get-ChildItem enterprise\admin-service\src\*.js | ForEach-Object {
  & $node --check $_.FullName
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
& $node --test enterprise\admin-service\test\*.test.mjs
```

结果：`123 passed, 0 failed`（86 项管理服务集成测试 + 5 项内容治理客户端专项测试 + 5 项内容治理存储专项测试 + 7 项目录专项测试 + 7 项通知渠道专项测试 + 7 项通知规则专项测试 + 6 项 SIEM 专项测试）。覆盖：

- 未登录拒绝、管理 OIDC 登录、MFA 拒绝和 `email_verified` 拒绝。
- 配置 ACR 时向 IdP 发送 `acr_values` 和 essential 的 `acr` claim 请求。
- CSRF 缺失拒绝；角色撤销后下一次请求立即返回 `forbidden_role`。
- 部门管理员可读本部门子树，读取兄弟部门返回 `forbidden_scope`。
- 绝对过期、空闲过期和过期时清除管理 Cookie。
- IP 允许列表配置错误时 fail closed，不在名单内返回 `ip_not_allowed`。
- auth-service 不可用返回 `502 dependency_unavailable`，日志不含服务令牌、OIDC Secret 或 Cookie。
- 管理存储不出现 OIDC Secret、服务令牌、CSRF 明文或会话 Cookie；损坏 JSON 拒绝加载。
- 全域管理员读取用户、部门、设备、凭证、模型和用量；部门管理员只能读取本组织子树。
- 部门管理员读取本部门用户详情返回 `200`，读取兄弟部门返回 `403 forbidden_scope`，不存在
  用户返回 `404 target_not_found`。
- 用量按 `callerKeyId -> credential -> user -> 组织` 归属；跨部门用量不计入，响应只含
  metadata，不含对话正文、Gateway Key、设备令牌或 token hash。
- 用量汇总和 `groupBy=user|department|model|agent`、`bucket=hour|day` 的时间序列；
  文件缺失、坏 JSON、尾部半行、超行、超字段和超记录均不会返回部分报表。
- 审计员只有允许的只读元数据能力，不能调用管理写接口。
- 全域管理员调用四个 M2-C2 管理写接口成功，响应只含动作、目标 ID 和白名单业务字段。
- 部门管理员只能写本组织子树；写兄弟部门返回 `403 forbidden_scope`，且 auth-service
  写调用次数为 0。
- 写接口缺少 CSRF、`reason`、合法 `Idempotency-Key` 或 JSON 时失败关闭；目标不存在返回
  `404 target_not_found`，依赖故障返回 `502 dependency_unavailable`，均不伪造成功。
- 同键同请求只执行一次；成功和失败结果均可稳定重放原响应、`operationId` 和
  `requestId`；同键异体返回 `409 idempotency_conflict`，并发执行中返回
  `409 operation_in_progress`，均不再次调用依赖。
- intent 审计写入失败返回 `503 audit_unavailable`，auth-service 调用次数为 0；result 审计
  写入失败也不返回成功，operation 保留 `dependency_invoked` 且没有伪造的 result 审计。
- 成功、失败、冲突和审计故障响应与管理存储均不包含 Gateway Key、设备令牌、token hash、
  公钥、Cookie、服务令牌或 OIDC Secret。
- C4-03a 使用严格 JSON 解析拒绝重复 key、尾随内容和未知字段，执行 2 MiB 上限、
  schema v1、稳定模型 ID、显式 Provider 通配符、group 展开和 SHA-256 digest 校验；
  `/api/v1/admin/models` 只返回模型 ID、通配符和 group 的安全投影，不返回目录路径。
- 管理服务在坏目录、坏 digest、坏 UTF-8、未知引用、空目录和超限文件时启动失败；
  成功启动会写入 `model_catalog.load` 系统审计，并只在 health/models 响应中暴露安全状态。
- C4-03c 额度/模型管理 API 要求 `quota.write`/`models.write`、CSRF、RBAC、组织范围、
  `reason` 和 `expectedVersion`；管理端展开 group/provider 选择器后只向 auth-service 发送
  稳定模型 ID。
- 同键同 payload 重放原响应；同键异 payload 返回 `409 idempotency_conflict`；策略版本
  落后返回 `409 policy_version_conflict`，并由管理服务写入 result 审计。
- 管理服务会透出凭证同步状态、`partial_success`、`requiresReconciliation` 和稳定错误码，
  不把 `pending/unknown` 显示为已生效。
- M2-C5 覆盖 operation 详情的原动作权限、组织范围、目标不存在和只读角色拒绝；审计查询
  的过滤、默认/最大条数、稳定分页、cursor 会话/查询绑定、损坏 cursor 拒绝和脱敏。
- 四种对账动作均覆盖审批、CSRF、证据、幂等键、依赖故障、intent/result 审计失败、父子
  operation、原 operation/审计不可改写、旧策略快照完整性和幂等重放/冲突。
- APR-01a 覆盖风险等级和规范化摘要稳定性；审批申请/读取/决策/撤销的 CSRF、权限、
  组织范围、自审批拒绝和稳定错误码。
- 审批与动作、目标、理由、payload、策略版本和环境绑定；跨动作、跨目标、修改额度/模型、
  修改理由或策略版本均失败关闭。
- APR-01c 覆盖独立 OIDC Client/PKCE、`prompt=login`、`max_age`、新鲜 `auth_time`、
  ACR/MFA、IdP `sub`/email、会话/IP/User-Agent/角色权限/组织范围绑定、H/C 写操作和
  审批门禁、未配置失败关闭、logout/会话过期清理，以及成功认证后
  `/api/v1/admin/me` 不再误报 `"state":"required"`。
- 过期和撤销审批不能授权写操作；并发操作只有一个可消费审批，其他请求返回
  `409 approval_consumed`；启动恢复把遗留 `reserved` 审批失败关闭为 `consumed`。
- 审批状态迁移、决策和消费记录不包含 Gateway Key、设备令牌、Cookie、token hash、
  OIDC Secret 或服务令牌。
- APR-01b 覆盖回调配置成组校验、原始 body HMAC-SHA256 验签、300 秒时间窗、issuer/
  audience、nonce 重放、eventId 幂等、错误签名/媒体类型/缺失头、职责分离、过期/撤销/
  已消费失败关闭、旧 store 集合迁移，以及 secret 不落响应和存储。
- APR-01e 覆盖申请/列表/详情/复核的 CSRF、critical step-up、角色和组织范围；环境、
  策略版本、动作、目标、理由、payload 或 binding 不匹配时失败关闭；15 分钟过期、并发
  单次消费、业务失败后仍通知/审计、自复核拒绝、幂等重放、复核到期/逾期提醒、复核不可变
  和损坏持久化数据拒绝加载。
- NOTIFY-01a 覆盖 8 种 L0 事件、字段白名单、稳定 `eventId`/`deliveryId` 幂等、审批/
  operation 审计与 outbox 同一次原子存储提交、租约、并发串行、指数退避、死信、重启
  恢复、deliveries 查询、组织范围、CSRF、权限、理由、幂等键和受审计死信重放。
- NOTIFY-01b 覆盖渠道 RBAC/CSRF/step-up/理由/幂等/审计、渠道测试和重放、`eventId +
  channelId` fanout 去重、Secret 投影、邮件收件人数/域名限制，以及有/无渠道时的启动行为。
- NOTIFY-01b 出站覆盖 HTTPS:443、host allowlist、DNS 固定解析、私网/回环/链路本地/云
  元数据拒绝、仅 307/308 最多 3 跳且逐跳复验、响应体/超时限制和 Webhook HMAC 签名。
- 管理存储和 deliveries 响应不包含外部 transport 响应、Prompt、Gateway Key、token
  hash、Cookie、OIDC/服务 token 或完整工具参数；渠道关闭、没有启用渠道或没有 transport
  时不创建 dispatcher，也不会把 pending 事件伪装为 delivered。渠道测试只记录测试结果，
  不生成或伪造真实 delivery。

### 4.3 语法检查

- `enterprise/auth-service/src/*.js` 均通过 `node --check`。
- `enterprise/admin-service/src/*.js` 均通过 `node --check`。
- `join-enterprise.ps1`、`refresh-client.ps1`、`join-client.ps1` 通过 PowerShell AST 解析。

### 4.4 M0 真实 Magpie E2E

```powershell
& 'D:\Environment\PowerShell-7.6.6-win-x64\pwsh.exe' `
  -NoLogo -NoProfile -NonInteractive `
  -File enterprise\test\e2e.ps1 `
  -Magpie 'C:\Users\AiMingYi\Desktop\magpie-enterprise-demo\server\magpie.exe' `
  -Node 'D:\Environment\node-v26.12.1\node.exe' `
  -MockPort 3631 -ServerPort 3632 -ClientPort 3633
```

结果：

- 客户端 Magpie → 企业 Magpie → Mock 上游成功。
- 员工 Key 可用于模型列表和 chat。
- `usage.jsonl` 按 `callerKeyId/callerKeyName` 归属到员工。
- 未触碰用户正在使用的 `127.0.0.1:3425` 数据。

### 4.5 M1 真实 Magpie issuer E2E（本地链路全部通过）

`enterprise/test/auth-e2e.ps1` 已加入，用于验证真实 Magpie 的 issuer Key、OIDC 加入、
短期 Key 签发、员工 chat、用量归属、刷新、旧 Key 撤销、停用员工和 auth-service 重启。

结果：`PASS`。覆盖：

- 真实 Magpie 创建 issuer Key 并开启 issuer 权限。
- Mock OIDC → `enterprise-auth` 加入成功。
- 真实 Magpie issuer API 签发员工 Key。
- 员工 Key 调用真实网关并到达 Mock 上游。
- `usage.jsonl` 正确归属到员工 Key。
- 刷新后旧 Key 立即返回 `401`，新 Key 返回 `200`。
- 停用员工后当前 Key、设备刷新和设备心跳全部失效。
- auth-service 重启后设备状态保留，撤销队列为空。
- 持久化文件中不含员工 Key、设备令牌、issuer Key 或 OIDC Secret 的明文。

测试已改用本机非回环 IPv4 访问网关，避免 Magpie 对回环请求免鉴权；同时隔离
`HOME/USERPROFILE/APPDATA/LOCALAPPDATA/XDG_CONFIG_HOME`，不会写入真实用户目录。真实
Magpie 使用临时数据目录启动，不触碰正在使用的 `127.0.0.1:3425`。

### 4.6 C4-01 机器协议（已通过本地测试）

当前分支 `feat/m2-c4-gateway-policy` 已增加：

```text
magpie gateway-key describe <id> --json
magpie gateway-key policy apply <id> --json
```

验证命令：

```powershell
& 'C:\Users\AiMingYi\AppData\Local\Temp\go-toolchain-20261101111126\go\bin\go.exe' `
  vet ./internal/access ./internal/cli
& 'C:\Users\AiMingYi\AppData\Local\Temp\go-toolchain-20261101111126\go\bin\go.exe' `
  test -count=1 -timeout=90s ./internal/access
& 'C:\Users\AiMingYi\AppData\Local\Temp\go-toolchain-20261101111126\go\bin\go.exe' `
  test -count=1 -timeout=120s ./internal/cli -run '^TestGatewayKey'
& 'C:\Users\AiMingYi\AppData\Local\Temp\go-toolchain-20261101111126\go\bin\go.exe' `
  build ./...
```

结果：全部通过。隔离 `XDG_CONFIG_HOME` 的真实构建二进制冒烟测试还验证了
`describe`、`policy apply` 和回读均为 `schemaVersion=1`；模型 2 项和月额度
500 万 tokens 正确回读；`policyRevision` 更新后独立回读一致；旧 revision 返回
`gateway_policy_conflict` 且 `retryable=false`；输出未发现 Secret 或 masked key。

这不等同于 C4 完成：C4-02/C4-03c 的自动测试覆盖受控适配器、管理编排和 Mock/故障边界；
4.8 的 C4-04 已通过隔离真实 Magpie E2E，覆盖完整管理链路、多凭证部分成功、
refresh/rotate 策略继承、真实限流和模型拒绝。真实共享卷文件锁、Docker/Compose、
真实企业 IdP 和生产部署仍需继续验收。完整 CLI 包中的无关网络测试
`TestLibrarySkillRmGone` 曾超时，因此不能宣称整个 `internal/cli` 包全绿。

### 4.7 C4-02 `gateway-control` 受控适配器（已通过 Mock/故障测试）

验证命令：

```powershell
& 'D:\Environment\node-v26.12.1\node.exe' `
  --check enterprise\gateway-control\src\service.js
& 'D:\Environment\node-v26.12.1\node.exe' `
  --check enterprise\gateway-control\test\gateway-control.test.mjs
& 'D:\Environment\node-v26.12.1\node.exe' `
  --test enterprise\gateway-control\test\gateway-control.test.mjs
```

结果：语法检查通过，`15 passed, 0 failed`。覆盖：

- 缺失、错误和复用已知 Secret 的服务令牌均被拒绝；健康检查不访问 Key 存储。
- Key ID 白名单拒绝路径、空格、分号和其他 shell 字符；请求体和输出上限生效。
- 请求只以原始 JSON 传给固定 argv，子进程使用 `shell: false`，不能注入额外参数。
- schema、模型、额度窗口、版本冲突和存储错误映射为稳定错误码。
- 写入后执行独立 `describe` 回读；回读不一致、超时或结果不确定返回保守的 `pending`。
- 子进程超时会被终止；响应、日志和错误输出不包含 Gateway Key、masked key、token hash、
  账户 ID、设备令牌或 Secret。
- 配置拒绝复用管理员、issuer、OIDC 或 auth 内部令牌；Dockerfile/Compose 静态约束已写入
  文档。

以上测试使用 Mock 子进程和服务边界；C4-03c 已通过 auth-service 的 Mock
gateway-control 接入，但不等于 Docker 镜像/Compose、真实共享卷文件锁、真实 Magpie
请求行为或企业生产验收通过。

### 4.8 C4-04 完整管理到真实 Magpie 策略流 E2E（已通过）

`enterprise/test/c4-enterprise-policy-e2e.ps1` 已通过 18 个阶段的企业链路测试，覆盖：

- 首次 join 返回 `409 policy_setup_required`，管理员完成 OIDC、CSRF、quota/models
  分步设置后，双设备获得独立 Gateway Key。
- 模型白名单真实返回 `403` 且请求不达上游；Token 月限额真实返回 `429`，包含
  `Retry-After`、`X-Magpie-Limit-Reset` 和 `X-Should-Retry: false`。
- 单 Key 禁用产生精确 `partial_success`；恢复后两个凭证重新 `synced`；refresh 轮换后
  旧 Key `401`、新 Key `200`，并继承当前策略。
- `gateway-control` 故障时保留 `unknown/pending_sync`，故障期间 refresh 失败且不能产生
  孤儿 Key；Journal 记录和孤儿 Key 撤销路径通过，恢复后重新同步。
- usage 归属、凭证列表、健康检查、管理 API/store/usage/日志和 22 个非凭证文本文件
  秘密扫描通过。

提交 `9bb0f94dc` 还提供 `enterprise/test/c4-gateway-policy-e2e.ps1` 单 Key 底层切片，并对
`enterprise/test/mock-upstream.mjs` 增加请求计数。脚本使用随机端口、临时 portable
Magpie、隔离 `XDG_CONFIG_HOME` 和独立 Mock 上游，不接触真实用户目录或
`127.0.0.1:3425`。

实际执行结果：全部 `PASS`。覆盖：

- 策略允许模型时真实 chat 返回 `200`，Mock 上游只收到 1 次请求。
- 模型白名单拒绝返回 `403 permission_error`，请求未到达上游。
- `month/tokens=1` 在已有 5 token 用量后稳定返回 `429`，带 `Retry-After`、
  `X-Magpie-Limit-Reset` 和 `X-Should-Retry: false`，请求未到达上游。
- 旧 `policyRevision` 返回 `gateway_policy_conflict`，策略保持不变。
- `gateway-key rotate` 保留策略；旧 Key 返回 `401`，新 Key 的 `/v1/models` 返回 `200`；
  清除额度后新 Key chat 返回 `200`。
- `describe/apply` 机器输出、日志和 `usage.jsonl` 不包含旧/新 Key 明文；
  `caller-keys.json` 按设计只保留当前 Key 明文，并具备 Windows ACL 允许读取规则。
- 不带 `-Keep` 的清理路径通过。

边界：C4-04 已证明管理 API 到真实 Magpie 的多凭证、策略继承和故障恢复链路，但仍不等同
生产验收。尚未覆盖共享卷文件锁、Docker Compose、mTLS、真实企业 IdP、反向代理、浏览器
自动化、Windows 计划任务、真实审计存储、生产人工对账、MCP/资源库、正文审计和 HA；
C4-03c 真实共享卷验收、C4-03d 页面 E2E、C5 生产验收和 M2-D 生产验收仍不能标记为完成。

## 5. 未验证事项

以下事项不能写成“已完成”：

1. 真实企业 IdP（Entra/Okta/Keycloak 等）的登录、JWKS、回调地址、Claim 映射和 MFA。
2. 管理端真实 IdP 的 `amr`/`acr`、条件访问、`email_verified` 和回调契约。
3. Docker CLI 不在当前 PATH，Compose 配置和镜像构建/健康检查未实际运行。
4. 管理域名、反向代理、真实 Cookie 域、公司 CA 和浏览器 End-to-End 未验证。
5. Windows 计划任务刷新未实机验证；需要验证锁、用户登录状态、网络恢复和失败重试。
6. SCIM/IdP 离职 Webhook 未接入；当前只有管理接口停用。
7. C4-01/C4-02/C4-03a/C4-03b/C4-03c 均已实现并完成本地/Mock/故障测试；C4-02/C4-03c
   的 Docker/Compose 构建、启动、健康检查、真实共享卷文件锁、服务令牌轮换和公司反向代理
   未验收。C4-03d 已实现管理页额度/模型写表单和员工只读状态门户；M2-D 已接入基础
   写操作、审批、查询、对账和 CSV 导出页面，但页面 E2E、失败设备恢复入口和完整运营体验
   仍未完成。C4-04 的
   完整管理到真实 Magpie 策略流已通过，包括多凭证部分失败、refresh/rotate 继承和故障恢复；
   真实 IdP、反向代理、浏览器自动化和生产审计存储仍未验收。
8. 多实例、共享存储、限流分布式化和高可用未实现。
9. APR-01a 已完成审批 API、状态机、绑定校验、职责分离、一次性消费和系统审计的
   Mock/故障测试；APR-01b 的 HMAC 回调适配器已覆盖原始 body 验签、时间窗、nonce
   防重放、issuer/audience、eventId 幂等、职责分离和系统审计。APR-01c 的独立 OIDC
   step-up 已完成代码和 Mock IdP 集成测试；基础审批页面已实现，APR-01d 的完整串并行
  审批箱、quorum、转交和撤回已实现并通过 Mock/集成测试；APR-01e 的 15 分钟单次授权、
  24 小时复核、提醒、通知、审计和管理页已完成 Mock/集成核心。真实管理 IdP/MFA、真实
  OA 连接器、SIEM/告警、工单 ID 回读、浏览器 E2E 和生产事后复核演练未验收。
   NOTIFY-01a 已实现 outbox、租约恢复、重试、死信、deliveries 查询和死信人工重放；
   NOTIFY-01b 已实现渠道管理、渠道测试和统一 HTTPS 邮件/IM/Webhook/工单网关适配器，
   但没有真实厂商连接和生产投递验收。`operation.audit_failed` 目前只有 schema，尚无可靠
   触发点；查询没有 cursor，`count` 仅表示当前页数量；NOTIFY-01c 的 SIEM transport 和
   dead-letters API 已实现，但真实接收端未验收；NOTIFY-01d 的渠道规则、抑制、聚合、升级、
   受审计重放和运营页面已实现并通过 Mock/集成测试，真实厂商和生产值班仍未验收。渠道关闭、
   没有启用渠道或缺少 transport 时不创建 dispatcher。

## 6. M1 验收门槛

本地验收门槛已经全部满足：

- 在临时数据目录启动真实 Magpie，创建专用 issuer Key 并开启 issuer。
- 启动 Mock OIDC + `enterprise-auth`，完整跑 join → Key 签发 → 员工 chat。
- 刷新后旧 Key 立即返回 `401`，新 Key 可用。
- 停用员工后设备令牌、刷新接口和当前网关 Key 全部失效。
- 重启认证服务后设备和待撤销队列仍正确。
- 同一设备并发刷新和“刷新签发中停用”回归通过。

生产验收还要全部满足以下条件：

- 用 Compose `--profile auth` 构建并拉起，healthcheck 通过。
- 用 Compose `--profile admin` 拉起，管理 OIDC 回调、Cookie、IP 限制、auth 内部接口和
  只读 `usage.jsonl` 挂载通过。
- 在真实 Windows 用户会话验证计划任务至少自动刷新一次，日志不含 Key。
- 真实员工 IdP 和管理 IdP 测试通过后再做 5-10 人试点。

## 7. 当前安全边界

- 员工机不持有模型厂商 Key；厂商 Key 只在企业网关。
- M1 网关 Key 是短期凭据，设备令牌保存在受 ACL 保护的文件中。
- 认证存储不保存明文网关 Key 和设备令牌，只保存哈希。
- auth-service 的 `AUTH_ADMIN_TOKEN` 仍是最小 M1 管理接口；生产管理必须走
  `admin-service` 的管理 OIDC、RBAC 和组织范围，不能把裸 token 暴露给浏览器。
- `admin-service` 已实现 M2-A 身份底座、M2-B 只读视图、M2-C2 的停用/启用、吊销、轮换
  四个受控管理写接口，以及 M2-C3 的幂等、operation 和 intent/result 管理审计；auth-service
  已实现额度/模型策略 API 到 gateway-control apply/独立回读、同步后交付、失败补偿和启动
  恢复的 C4-03c 核心链路。真实 Magpie/共享卷/IdP 验收和 C4-03d 剩余页面能力未完成。
- M2-C1 的 auth-service 内部写接口只有 `AUTH_INTERNAL_ADMIN_TOKEN` 能调用；M2-C2 的
  admin-service 管理写 API 已接入管理会话、CSRF、RBAC、组织范围和 M2-C3 的幂等/
  intent-result 审计。result 审计失败时 operation 会停在 `dependency_invoked`，必须由 C5
  查询和人工对账处理。浏览器不能直接调用 auth-service 内部接口。
- 内容审计已有默认关闭的管理侧治理链路：显式启用后可经审批和 fresh step-up 一次性读取
  脱敏正文，并执行留存、删除、法律保留和双层加密导出；系统默认 L0，真实网关正文采集、
  L3、水印、WORM/KMS、生产浏览器 E2E、备份恢复和合规签字仍未完成。
- 浏览器不能直接改本地 Agent 文件；必须由安装好的本地 Magpie/helper 执行。

## 8. 下一步

1. 在 Docker 可用的机器上验证 Compose、健康检查和重启恢复。
2. 在真实 Windows 用户会话验证计划任务刷新。
3. 用真实企业 IdP 完成登录、MFA、Claim 映射和停用测试。
4. 验证管理 `--profile admin`、管理 OIDC 回调、MFA/ACR、IP 限制和反向代理 Cookie。
5. 用真实网关生成的 `usage.jsonl` 验证只读挂载、归属、部门过滤、损坏/轮转和大文件行为。
6. M2-C3 已完成 Mock 验证：幂等重放/冲突、`operationId`、intent/result 审计和审计失败阻断
   均已覆盖；下一步把同一流程接入真实存储和真实管理请求链路。
7. C4-02 受控适配器已通过 15 项 Mock/故障测试；C4-03b/C4-03c 的 auth-service 核心链路
   已通过 26 项 auth 回归、123 项 admin 测试、15 项 gateway-control 测试、15 项
   resource-service 测试、14 项 mcp-gateway 测试、26 项 client-sync 测试、60 项 local-mcp
   测试、67 项 audit-service 测试和 30 项 security-service 测试，共 376 项。M3-D-3
   的真实子进程 E2E 已覆盖一键配置编排、client-sync、local MCP
   host、helper HTTP、Codex 配置回读、受控环境注入和 stdio bridge；真实 Codex 客户端、
   安装器和生产部署仍未验收。下一步在
   Docker 可用环境验证镜像、Compose、
   健康检查和真实共享卷故障恢复；C4-04 完整管理到真实 Magpie 策略流 E2E 已通过。
8. M2-C5 的 `audit-logs`、`operations/{id}`、人工对账和补偿后端已通过 Mock/故障测试；
   M2-D 已接入基础写操作、审批、operation/audit 查询、人工对账、CSV 导出和操作历史；
   下一步在真实审计存储和运维流程中验收，并补齐浏览器 E2E、失败恢复入口、完整看板和
   异步/对象存储导出。
9. M5-A 规则引擎已有 17 项隔离测试，网关元数据投递核心已有 12 项 Go 测试；下一步在
   真实网关、反向代理和运行中的 security-service 上验证端到端投递及来源地址语义，再接
   管理 UI 和通知/审批响应链路；M5-B 还需接入真实网关执行器、真实工单和管理 UI，再完成 M5-C 监控/SIEM/值班闭环。
10. APR-01a 已实现服务端审批和一次性消费，APR-01b 已实现 HMAC/Mock 外部审批回调适配器，
   APR-01c 已实现独立 OIDC step-up 和 H/C 门禁并通过 Mock IdP 测试，APR-01d 已实现
  审批箱、串并行步骤、quorum、转交和撤回，APR-01e 已实现 break-glass Mock/集成核心；
  下一步完成真实 IdP/MFA/反向代理和浏览器 E2E 验收，接入真实 OA、SIEM/告警和工单，
  完成 5 分钟告警/工单 SLA 与 24 小时生产事后复核演练；NOTIFY-01d 的规则、抑制、聚合、
  升级和运营页已完成 Mock/集成核心，NOTIFY-01c 的真实 SIEM 接入仍需验收。
11. NOTIFY-01a 已完成与审批/operation 业务审计同一次原子存储提交的 outbox、租约恢复、
    重试、死信和人工重放；NOTIFY-01b 已接入经过 SSRF/秘密扫描的邮件、企业 IM、
    Webhook 和工单 HTTPS 网关适配器，并完成渠道管理/测试 API；NOTIFY-01c 已完成
    http-collector/otlp-http/syslog-tls、固定 L0 schema 和 dead-letters API；NOTIFY-01d
    已完成规则、抑制、聚合、升级、受审计重放和运营页面。下一步用真实测试域验证厂商网关和
    SIEM 接收端。没有真实厂商
    连接和测试域验收时不得宣称生产通知闭环。
12. 每个阶段完成后更新第 9 节，记录实际分支、commit、命令、结果、未覆盖项和秘密扫描；
   没有原始证据时继续保持“未实现/未验收”。

## 9. 阶段交付记录

每次推进阶段都更新本表。`测试结果`只记录实际运行过的命令和结果，不把设计或代码存在当成
通过。

| 阶段 | 分支/目录 | 本阶段实现 | 测试命令 | 结果 | 未覆盖项 |
| --- | --- | --- | --- | --- | --- |
| M0 企业网关基线 | `feat/enterprise-plan` / `enterprise/` | 企业网关 Compose、员工 Key 开通、客户端加入、验收脚本、Mock 上游 E2E | `enterprise/test/e2e.ps1` | 真实 Magpie 客户端 → 企业网关 → Mock 上游通过；用量按员工 Key 归属 | 正式 TLS、公司 OTLP/SIEM、MDM 分发 |
| M1 身份与设备 | `feat/enterprise-plan` / `enterprise/auth-service/` | OIDC+PKCE、加入码、设备注册/心跳/刷新/吊销、短期 Key、管理停用接口、并发刷新串行化、凭证元数据 | `node --test enterprise/auth-service/test/auth-service.test.mjs` | 当前回归 `25 passed, 0 failed` | 真实企业 IdP、Docker、Windows 计划任务 |
| M1 真实链路 | `feat/enterprise-plan` / `enterprise/test/auth-e2e.ps1` | 真实 issuer Key、Mock OIDC、真实网关、Mock 上游、刷新、停用、重启和脱敏检查 | `enterprise/test/auth-e2e.ps1 -Magpie ... -Node ...` | 全部 PASS | 真实 IdP、Compose 健康检查、计划任务实机 |
| M2-A 管理身份底座 | `feat/enterprise-plan` / `enterprise/admin-service/` | 独立管理 OIDC、MFA/ACR、已验证邮箱、会话/CSRF/IP、RBAC、组织范围、服务间独立令牌、最小页面、Compose `admin` profile | `node --check`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs`；`node --test enterprise/auth-service/test/auth-service.test.mjs` | 该阶段回归 `61 passed, 0 failed`；auth `25 passed, 0 failed` | 真实 IdP、Docker/浏览器/反向代理；C4-03d 剩余能力、C5 和 M2-D 的生产验收未完成 |
| M2-B 只读治理 | `feat/enterprise-plan` / `enterprise/auth-service/`、`enterprise/admin-service/` | 用户/部门/设备/凭证/模型/用量只读 API、凭证元数据、用户组织映射、服务端子树过滤、只读 usage 读取和管理页摘要 | `node --check`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs`；`node --test enterprise/auth-service/test/auth-service.test.mjs` | 该阶段回归 `61 passed, 0 failed`；auth `25 passed, 0 failed` | 真实 `usage.jsonl` 数据卷、真实 IdP、Docker/浏览器/代理、C4-03d 剩余能力、C5 生产验收、D |
| M2-C1 Auth 内部写接口 | `feat/enterprise-plan` / `enterprise/auth-service/` | 内部停用/启用、设备吊销、当前凭证轮换；停用撤销设备/会话/凭证，启用不恢复旧凭据，轮换按设备串行化并清理孤儿 Key | `node --check`；`node --test enterprise/auth-service/test/auth-service.test.mjs` | 当前回归 `25 passed, 0 failed` | admin-service 对外写 API、RBAC/CSRF/幂等/理由/审计、真实 IdP 和真实网关验收 |
| M2-C2 管理写接口 | `feat/enterprise-plan` / `enterprise/admin-service/` | 四个管理写 API；会话/CSRF/RBAC/组织子树/理由校验；目标预检和响应白名单；依赖故障映射 | `node --check`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs` | 该阶段回归 `61 passed, 0 failed`（C2 新增 3 组测试） | 停用/吊销/轮换页面按钮、真实 IdP/代理/网关验收 |
| M2-C3 幂等与管理审计 | `feat/enterprise-plan` / `enterprise/admin-service/` | `adminOperations`/`adminIdempotency` 集合；键哈希和请求指纹；同键重放/冲突/执行中；intent/result 审计；审计失败阻断；operationId 返回和失败重放 | `node --check`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs` | 该阶段回归 `61 passed, 0 failed`（含 7 项目录测试；C3 新增 5 组测试） | 页面 E2E、真实 IdP/代理/网关验收；查询与对账由 C5 提供 |
| C4-01 网关机器协议 | `feat/m2-c4-gateway-policy` 工作区 | `describe --json`、原子 `policy apply --json`、schema v1、64 KiB 输入输出上限、`expectedPolicyRevision`、稳定错误码、无秘密输出 | `go vet ./internal/access ./internal/cli`；`go test -count=1 -timeout=90s ./internal/access`；`go test -count=1 -timeout=120s ./internal/cli -run '^TestGatewayKey'`；`go build ./...`；隔离 `XDG_CONFIG_HOME` 真实二进制冒烟 | 全部通过；schema/模型/额度/冲突/回读/脱敏冒烟通过 | 尚未合入 `main`；无管理 API、真实请求行为 E2E 或生产环境证据 |
| C4-02 受控网关适配器 | `feat/m2-c4-gateway-control` 工作区 / `enterprise/gateway-control/` | 固定路由、独立 Bearer 服务令牌、固定 argv/`shell: false`、Key ID 白名单、10 秒超时、64 KiB 上限、独立回读、`pending` 保守状态、Dockerfile 和 Compose profile | `node --check enterprise/gateway-control/src/service.js`；`node --check enterprise/gateway-control/test/gateway-control.test.mjs`；`node --test enterprise/gateway-control/test/gateway-control.test.mjs` | `15 passed, 0 failed`；Mock/故障测试通过 | Docker/Compose、真实共享卷、真实 Magpie、mTLS 和生产环境未验收 |
| C4-03a 正式只读模型目录 | `feat/m2-c4-gateway-policy` 工作区 / `enterprise/admin-service/` | 只读 `ADMIN_MODEL_CATALOG_PATH`、严格 JSON、schema v1、稳定模型 ID、显式 Provider 通配符、group 展开、2 MiB 上限、SHA-256 digest、安全状态摘要、启动审计和 `GET /api/v1/admin/models` 正式目录 | `Get-ChildItem enterprise/admin-service/src/*.js \| ForEach-Object { node --check $_.FullName }`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs` | 该阶段回归 `61 passed, 0 failed`（7 项目录专项 + 54 项管理集成） | auth-service 不加载目录，只接收稳定 ID；真实 Docker/共享卷、真实 IdP、浏览器、反向代理和生产环境未验收 |
| C4-03b 用户级策略核心 | `feat/m2-c4-gateway-policy` 工作区 / `enterprise/auth-service/` | 版本化 `gatewayPolicy`、0-5 额度窗口、稳定模型、M1 `unknown` 迁移、quota/models 分步设置、缺项失败关闭、`expectedVersion`/`If-Match`、join/refresh/rotate 前置门禁和凭证回读确认 | `node --check enterprise/auth-service/src/service.js`；`node --check enterprise/auth-service/test/auth-service.test.mjs`；`node --test enterprise/auth-service/test/auth-service.test.mjs` | `25 passed, 0 failed` | 真实 E2E、页面剩余能力和生产验收未完成 |
| C4-03c 管理 API 与同步后交付 | `feat/m2-c4-gateway-policy` 工作区 / `enterprise/admin-service/`、`enterprise/auth-service/` | 额度/模型 API、模型选择器展开、payload 幂等、issuance journal、`enterpriseIssuanceId` 幂等签发、apply/readback、同步后交付、失败补偿、启动恢复和 `partial_success` | `node --check`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs`；`node --test enterprise/auth-service/test/auth-service.test.mjs` | 该阶段回归 admin `61 passed, 0 failed`；auth `25 passed, 0 failed` | Docker/共享卷、真实 Magpie、真实 IdP、mTLS、生产对账和生产验收未完成 |
| C4-04 完整管理到真实 Magpie 策略流 E2E | `feat/m2-c4-gateway-policy-e2e` / `enterprise/test/c4-enterprise-policy-e2e.ps1` | 管理 OIDC/CSRF、quota/models 分步设置、双设备独立 Key、真实模型拒绝和 Token 限额、部分失败、refresh/rotate 继承、故障后 pending、Journal/孤儿 Key 撤销、恢复同步、usage 归属和秘密扫描 | `enterprise/test/c4-enterprise-policy-e2e.ps1 -Magpie <magpie.exe> -Node <node.exe>` | 全部 `PASS`；18 个阶段覆盖真实管理到网关链路 | Docker/共享卷、真实企业 IdP、反向代理、浏览器自动化、C5 和 M2-D 的生产验收未覆盖 |
| C4-03d | `feat/m2-d-admin-operations` | C4-03d 已实现管理页额度/模型写表单和员工只读状态门户；M2-D 已补基础停用/吊销/轮换、审批、operation/audit 查询、人工对账和 CSV 导出页面；页面 E2E、失败恢复入口和完整运营体验未完成 | 页面/API 静态路径及管理服务集成测试覆盖 | C4-03d 部分实现；M2-D 核心已实现 | C4-03d 剩余项、浏览器 E2E 和生产验收 |
| M2-C5 操作/审计查询与对账 | `feat/m2-c5-operations-audit` / `enterprise/admin-service/`、`enterprise/auth-service/` | operation 详情、脱敏审计分页、签名 cursor、四种人工对账动作、父子 operation、原子 models+limits 更新和逐活跃凭证 apply；M2-D 已接入基础查询/对账页面 | `node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs`；`node --test enterprise/auth-service/test/auth-service.test.mjs` | 该阶段回归 admin `61 passed, 0 failed`；auth `25 passed, 0 failed`；C5 Mock/故障测试通过 | 真实审计存储、生产 IdP/代理、浏览器 E2E 和生产运维演练未验收 |
| M2-E1 APR-01a 服务端审批 | `feat/m2-e-approval-step-up` / `enterprise/admin-service/` | 四个审批 API、24 小时有效期、L/M/H/C、规范化 payload/binding SHA-256、审批状态机、自审批拒绝、组织范围、一次性消费、启动恢复失败关闭和审批系统审计 | `node --check`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs` | 该阶段回归 admin `61 passed, 0 failed`；审批 Mock/故障测试通过 | 审批管理 UI、真实 IdP/MFA、审批箱和 break-glass 未实现/未验收；后续 NOTIFY-01a 已补 outbox 核心，渠道仍未实现 |
| APR-01b 外部审批回调适配器 | `feat/apr-01b-external-approval` / `enterprise/admin-service/` | HMAC-SHA256 原始 body 验签、300 秒时间窗、nonce 防重放、issuer/audience、eventId 幂等、职责分离、审批状态迁移和系统审计；回调不直接执行管理动作 | `node --check`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs`；变异测试：临时关闭 HMAC 比较后目标测试失败为 `200 !== 401` | 该阶段回归 admin `61 passed, 0 failed`；HMAC/Mock 回调测试通过 | 真实飞书/OA/ServiceNow/Jira 连接器、生产回调演练、审批管理 UI、真实 IdP/MFA、审批箱和 break-glass 未实现/未验收；后续 NOTIFY-01a 已补 outbox 核心，渠道仍未实现 |
| APR-01c 独立 OIDC step-up | `feat/apr-01c-step-up` / `enterprise/admin-service/` | 独立 OIDC Client、PKCE、`prompt=login`、`max_age`、`auth_time`、ACR/MFA、IdP `sub`/email、会话/IP/User-Agent/角色权限/组织范围绑定、H/C 门禁、未配置失败关闭、logout/会话过期清理和管理页重新认证入口 | `Get-ChildItem src\*.js \| ForEach-Object { node --check $_.FullName }`；`node --test test\admin-service.test.mjs test\model-catalog.test.mjs` | 该阶段回归 admin `61 passed, 0 failed` | 真实 IdP、真实 MFA/条件访问、反向代理、浏览器流程和 CI 生产验收未执行 |
| NOTIFY-01a transactional outbox | `feat/notify-01a-outbox` / `enterprise/admin-service/` | 8 种 L0 审批/operation 事件；字段白名单与 `schemaVersion=1`；稳定 `eventId`/`deliveryId` 幂等；pending/leased/delivering/delivered/retry_wait/dead_letter；1/5/15/60/360 分钟退避；租约、并发串行、重启恢复；deliveries 查询和死信人工重放；审批审计/结果审计与 outbox 同一次 JSON 存储原子提交；SIGTERM 先停 dispatcher | `Get-ChildItem src\*.js \| ForEach-Object { node --check $_.FullName }`；`node --test test\admin-service.test.mjs test\model-catalog.test.mjs`；`node --test enterprise\auth-service\test\auth-service.test.mjs`；`node --test enterprise\gateway-control\test\gateway-control.test.mjs` | admin `67 passed, 0 failed`；auth `25 passed, 0 failed`；gateway-control `15 passed, 0 failed`；合计 `107 passed, 0 failed` | 没有邮件/IM/Webhook/SIEM/工单 transport，正常启动不创建 dispatcher；没有 channels/rules/suppress/test-channel API 或运营 UI；`operation.audit_failed` 无触发点；查询无 cursor；真实渠道、生产存储和通知闭环未验收 |
| NOTIFY-01c SIEM transport | `feat/notify-01c-siem` / `enterprise/admin-service/` | `siem` 渠道及 `http-collector`/`otlp-http`/`syslog-tls`；固定 L0 schema；HTTPS:443/TLS:6514；host allowlist、固定 DNS、私网/回环/链路本地/云元数据拒绝；HTTP/OTLP 可选 Bearer `secretRef`，Syslog 禁止 `secretRef`；默认 32 KiB 上限（可配 1-64 KiB）；critical 优先；dispatcher 轮询不超过 5 分钟；dead-letters API；新增 `security.access_denied`/`auth_failed`/`break_glass_used`/`anomaly_detected` | `node --check` 全部管理服务 JS；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs enterprise/admin-service/test/notification-channels.test.mjs enterprise/admin-service/test/notification-siem.test.mjs` | admin `82 passed, 0 failed`（62 项管理集成 + 7 项目录 + 7 项通知渠道 + 6 项 SIEM）；auth `25 passed, 0 failed`；gateway-control `15 passed, 0 failed`；合计 `122 passed, 0 failed` | 真实 SIEM/Collector/Syslog/生产证书未验收；rules/suppress、聚合、升级和完整运营 UI 未实现 |
| M2-D 管理运营 | `feat/m2-d-admin-operations` / `enterprise/admin-service/` | 基础管理写页面、审批申请/决策/撤销、operation/audit 查询、人工对账、用量/审计 CSV 授权导出、一次性下载 token 和操作历史；导出要求审批、fresh step-up、CSRF、RBAC、组织范围、理由和幂等 | `node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs enterprise/admin-service/test/notification-channels.test.mjs enterprise/admin-service/test/notification-siem.test.mjs` | 当时阶段记录为 admin `86 passed, 0 failed`；后续 APR-01d 提升到 `90 passed, 0 failed`，APR-01e 再提升到 `95 passed, 0 failed` | 浏览器 E2E、失败恢复入口、真实数据/负载、完整运营看板、Excel、对象存储、异步大批量导出、分布式锁和生产验收未完成 |
| APR-01d 审批箱与多步骤审批 | `feat/m2-e2-approval-inbox` / `enterprise/admin-service/` | 审批箱视图、串行/并行步骤、显式 `stepId`、quorum、转交、申请人撤回、外部回调 `stepId`、步骤摘要和管理页操作 | `node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs enterprise/admin-service/test/notification-channels.test.mjs enterprise/admin-service/test/notification-siem.test.mjs` | 该阶段 admin `90 passed, 0 failed`（75 项管理集成 + 7 项目录 + 7 项通知渠道 + 6 项 SIEM）；auth `25 passed, 0 failed`；gateway-control `15 passed, 0 failed`；合计 `130 passed, 0 failed` | 该阶段真实 OA/IdP/MFA、浏览器 E2E、审批通知和生产验收未完成；后续 APR-01e 已补 break-glass 核心 |
| APR-01e break-glass | `feat/apr-01e-break-glass` / `enterprise/admin-service/` | 15 分钟单次授权、24 小时复核、`active/expired/consumed/review_overdue/reviewed` 状态、申请/复核 RBAC、critical step-up、环境/策略版本/申请人/动作/目标/组织/风险/理由/payload/binding 绑定、原子消费、复核提醒、四类通知事件、审计、API 和管理页 | `node --test enterprise/admin-service/test/*.test.mjs`；auth 与 gateway-control 全回归 | admin `95 passed, 0 failed`（75 项管理集成 + 7 项目录 + 7 项通知渠道 + 6 项 SIEM）；auth `25 passed, 0 failed`；gateway-control `15 passed, 0 failed`；合计 `135 passed, 0 failed` | 真实 IdP/MFA、SIEM/告警、OA/工单、外部工单 ID 回读、浏览器 E2E、5 分钟告警/工单 SLA 和 24 小时生产事后复核演练未验收 |
| NOTIFY-01d 通知规则与运营 | `feat/notify-01d-notification-ops` / `enterprise/admin-service/` | 通知规则 CRUD、事件/严重级别/目标/组织匹配、抑制窗口、聚合维度和窗口、阈值/延迟升级、失败隔离、aggregates/suppressions/escalations 查询、dead-letter 受审计幂等重放，以及渠道/规则/投递/死信/聚合/抑制/升级管理页；规则和渠道写操作要求会话、CSRF、RBAC、H 级 step-up、理由和 `Idempotency-Key`，规则更新支持 `expectedUpdatedAt` | `node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs enterprise/admin-service/test/notification-channels.test.mjs enterprise/admin-service/test/notification-rules.test.mjs enterprise/admin-service/test/notification-siem.test.mjs`；auth 与 gateway-control 全回归 | admin `104 passed, 0 failed`（77 项管理集成 + 7 项目录 + 7 项通知渠道 + 7 项通知规则 + 6 项 SIEM）；auth `25 passed, 0 failed`；gateway-control `15 passed, 0 failed`；合计 `144 passed, 0 failed` | 真实邮件/IM/Webhook/工单/SIEM 厂商、真实 IdP/MFA、生产证书与域名、浏览器 E2E、生产高可用/负载、留存和灾备未验收 |
| M3-A 资源目录与签名 | `feat/m3-a-resource-catalog` / `enterprise/resource-service/` | 五类资源目录、强制/推荐交付模式、不可变版本、SHA-256 内容寻址、canonical JSON、manifest digest、Ed25519 签名、发布/历史回滚、乐观并发、`Idempotency-Key` 与 actor 绑定、JSON 原子存储、Bearer 服务令牌、限流、请求 ID、秘密/私钥/未知字段失败关闭和资源审计 | `node --test enterprise/resource-service/test/resource-service.test.mjs`；admin、auth、gateway-control 全回归 | resource `11 passed, 0 failed`；admin `104 passed, 0 failed`；auth `25 passed, 0 failed`；gateway-control `15 passed, 0 failed`；该阶段合计 `155 passed, 0 failed` | 真实审批状态查询/一次性消费、admin-service 编排与管理台、客户端同步、S3/MinIO、KMS/HSM、多副本、Docker/Compose 实机和生产验收未完成；远程 MCP 由后续 M3-B 核心单独提供 |
| M3-B 远程 MCP 治理 | `feat/m3-b-remote-mcp` / `enterprise/mcp-gateway/` | 元数据注册表、管理员注册/更新/健康检查、客户端凭据签发/吊销、企业统一 tools-only Streamable HTTP JSON-RPC 端点、user/org/device/server scope、工具命名空间与 allow/deny/风险/可见性、short-lived HMAC 审批门禁、HTTPS/host allowlist、固定 DNS、私网/回环/元数据地址和重定向拒绝、请求/响应/超时/速率限制、每服务器熔断、SHA-256 客户端 token 摘要、环境 Secret Reference 和元数据审计 | `node --test enterprise/mcp-gateway/test/mcp-gateway.test.mjs`；admin、auth、gateway-control、resource 全回归 | mcp-gateway `14 passed, 0 failed`；admin `104 passed, 0 failed`；auth `25 passed, 0 failed`；gateway-control `15 passed, 0 failed`；resource `11 passed, 0 failed`；该阶段合计 `169 passed, 0 failed` | 审批 nonce/限流器仅单进程；注册表、审计和幂等非同一事务；审计失败窗口可能留下不可恢复 token 的孤立 client；admin-service 真实审批查询/一次性消费、管理台、OIDC 组织分配、员工端同步接入、M3-D、共享事务存储、KMS/HSM、mTLS、真实 MCP/IdP、浏览器 E2E、Docker/Compose 实机和生产验收未完成 |
| M3-C 客户端资源同步核心 | `codex/m3-c-client-sync` / `enterprise/client-sync/` | 固定 Ed25519 公钥、`signingKeyId` 和 SPKI SHA-256 指纹；desired-state manifest/内容/长度/SHA-256 校验；staging、fsync、复验、rename 原子激活；失败保留上一验签版本；离线继续使用；forced/recommended；inspect 漂移；路径穿越、符号链接、坏缓存、重复资源/版本/hash、未知 key、低版本客户端和超大 manifest 拒绝；进程锁；状态 `0600` 原子写入；报告不含内容、token、Secret 或私钥；同步周期 1-300 秒 | `node --test enterprise/client-sync/test/*.test.mjs`；企业全量 Node/Mock 回归 | 该阶段 client-sync `16 passed, 0 failed`；admin `104 passed, 0 failed`；auth `25 passed, 0 failed`；gateway-control `15 passed, 0 failed`；resource `11 passed, 0 failed`；mcp-gateway `14 passed, 0 failed`；合计 `185 passed, 0 failed` | 该阶段尚未接入员工端同步凭证 API、管理台资源/漂移页、本地 helper 产品入口、目标 Agent 文件映射和设备端上报；后续 M3-C-1 已补齐控制面 API |
| M3-C-1 同步控制面 | `codex/m3-c-sync-control-plane` / `enterprise/auth-service/`、`enterprise/resource-service/`、`enterprise/client-sync/` | 设备身份换取 60-900 秒 `mss1` HMAC 同步凭证，绑定 user/device/组织范围和 audience；OIDC `groups` 去重和校验；按组织范围生成 desired-state；设备只上报元数据证据；管理端 JSON 查询；报告按设备保留最新一份并原子 `0600` 写入；`createEnterpriseSyncTransport()` 支持凭证缓存/重签、ETag 条件请求、超时、响应大小上限和报告投影 | `node --test enterprise/auth-service/test/auth-service.test.mjs`；`node --test enterprise/resource-service/test/*.test.mjs`；`node --test enterprise/client-sync/test/*.test.mjs`；企业全量 Node/Mock 回归 | auth `26 passed, 0 failed`；admin `104 passed, 0 failed`；gateway-control `15 passed, 0 failed`；resource `15 passed, 0 failed`（11 核心 + 4 控制面）；mcp-gateway `14 passed, 0 failed`；client-sync `24 passed, 0 failed`（16 核心 + 8 传输）；合计 `198 passed, 0 failed` | 管理台资源/漂移页、本地 helper 产品入口、目标 Agent 文件映射、Windows ACL、MDM、真实 IdP、浏览器 E2E、Docker/Compose 实机验收、灰度发布、自动回滚和企业生产验收未完成；管理端只有 JSON API，没有同步报告 UI |
| M3-C-2 只读管理可见性 | `codex/m3-c2-admin-sync-visibility` / `enterprise/admin-service/` | 四条只读资源/同步 API；独立 Bearer 服务令牌、GET-only、禁止重定向、5 秒超时、4 MiB 响应上限；严格字段白名单；资源按 `"*"`/组织范围过滤并裁剪范围外 assignments；同步报告要求设备存在、可见且 `userId` 与设备一致；依赖故障统一 `503 resource_service_unavailable`；管理页只读面板 | `node --test enterprise/admin-service/test/*.test.mjs`；企业全量 Node/Mock 回归 | admin `109 passed, 0 failed`（82 集成 + 7 目录 + 7 渠道 + 7 规则 + 6 SIEM）；企业合计 `203 passed, 0 failed` | 资源发布/回滚 UI、发布/回滚审批联动、M3-B MCP 管理台、本地 helper 产品入口、目标 Agent 文件映射、Windows ACL/MDM、真实 IdP、浏览器 E2E、Docker/Compose 实机、灰度/自动回滚和生产验收未完成 |
| M3-D-1 受控本地 MCP helper/server 核心（阶段证据） | `codex/m3-d-local-mcp` / `enterprise/local-mcp/`、`enterprise/client-sync/` | 既有 Ed25519 签名包、canonical manifest、原子安装、权限能力策略、Secret Broker、JSON-RPC、审计和健康核心；新增 `ClientSyncEngine.readActiveResource()`；`LocalMcpHelper` 只消费 active `kind: "mcp"` 资源，重新验签并从 manifest 解析包身份，支持同步期安装、reconcile/synchronize/snapshot/listTools/callTool；回环 HTTP server 仅允许 `127.0.0.1`/`::1`，复核 peer，`/healthz` 公开、其余 Bearer，固定 status/tools/call 路由，默认 256 KiB body 上限、字段/URL/token 上限、稳定错误码、文件锁、无 CORS 和 `no-store`，snapshot 脱敏 | `node --test enterprise/client-sync/test/*.test.mjs`；`node --test enterprise/local-mcp/test/*.test.mjs`；既有企业 Node/Mock 回归 | 该阶段 client-sync `26 passed, 0 failed`（18 核心 + 8 传输）；local-mcp `37 passed, 0 failed`（21 运行时 + 7 helper + 9 server）；七套合计 `242 passed, 0 failed`；后续 M3-D-2 将 local-mcp 提升到 50 项、企业合计 255 项 | 该阶段为接口级 Mock/单元测试；后续 M3-D-2 已补 `ClientSyncEngine + LocalMcpHost + helper HTTP server + stdio bridge` 真实子进程 E2E。本地 helper 安装器/Windows 服务/MDM/代码签名/升级回滚、真实 Codex 客户端、管理台员工流、真实 OIDC/审批服务/Secret Broker/KMS、Windows ACL、已证明的外部 OS 沙箱、Docker/VM、浏览器 E2E、共享卷并发、HA 和生产验收未完成；不得宣称完整 M3-D、产品化或生产可用 |
| M3-D-2 Agent stdio bridge / Codex 配置映射核心 | `codex/m3-d-local-mcp-agent-bridge` / `enterprise/local-mcp/` | 新增回环 helper stdio bridge、JSON-RPC initialize/tools/list/tools/call、环境变量 token、请求/响应上限、超时和稳定错误码；Codex `config.toml` 受管注释块映射、`CODEX_HOME`、保留用户其他 MCP 配置、幂等原子写入、BOM/CRLF 保留、漂移默认拒绝、显式 `force` 更新，只引用 token 环境变量名；受管标记必须独占整行，异常配置失败关闭；新增真实子进程 E2E | `node --test enterprise/local-mcp/test/e2e.test.mjs`；`node --test enterprise/local-mcp/test/*.test.mjs`；`node --test enterprise/client-sync/test/*.test.mjs`；七套企业回归 | local-mcp `50 passed, 0 failed`（21 运行时 + 7 helper + 9 server + 5 bridge + 7 Codex 配置 + 1 真实子进程 E2E）；client-sync `26 passed, 0 failed`；七套合计 `255 passed, 0 failed` | 技术 E2E 已覆盖 `ClientSyncEngine + LocalMcpHost + helper HTTP server + stdio bridge`，但不等于真实 Codex 客户端读取配置；Windows 安装器/服务/MDM/代码签名、密钥安全注入/轮换、真实 OIDC/审批/Secret Broker/KMS、Windows ACL、外部 OS 沙箱、Docker/VM、浏览器 E2E、共享卷、HA 和生产验收未完成 |
| M3-D-3 一键配置编排核心 | `codex/m3-d-local-mcp-agent-bridge` / `enterprise/local-mcp/` | 新增 `setupLocalMcpClient()`：synchronize、reconcile、snapshot 选包、listTools、回环 server/probe、Codex 受管配置写入/严格回读和受控启动器环境注入；强制注入器，缺省 token 只在进程内生成并以 base64url 传入冻结环境补丁；成功对象不含 token；多资源要求 `resourceId`；失败阶段化稳定错误码和自动清理；E2E 改为经过编排入口 | `node --test enterprise/local-mcp/test/*.test.mjs`；`node --test enterprise/client-sync/test/*.test.mjs`；七套企业回归 | local-mcp `60 passed, 0 failed`（21 运行时 + 7 helper + 9 server + 5 bridge + 7 Codex 配置 + 10 client setup + 1 真实子进程 E2E）；client-sync `26 passed, 0 failed`；七套合计 `265 passed, 0 failed` | 技术链路不等于真实 Codex 客户端读取配置；生产 launcher、Windows ACL/DPAPI、token 轮换/恢复、安装器/Windows 服务/MDM、真实 OIDC/审批/Secret Broker/KMS、外部 OS 沙箱、Docker/VM、浏览器 E2E、共享卷、HA 和生产验收未完成 |
| M4-A 审计事件管道核心 | `codex/m4-a-audit-event-pipeline` / `enterprise/audit-service/` | 新增 schema v1 的 `request`/`response`/`tool_call`/`policy_decision`；只接收 allowlist 的 L0/L1 元数据；Bearer 服务令牌、`Idempotency-Key`、秘密扫描、规范 UTC 毫秒时间；持久 JSON 队列、批量提交、幂等重放/冲突、重启恢复、优雅 drain、会话/请求索引、筛选游标和统计；Compose `audit` profile 内部暴露且独立 `audit-data` 卷 | `node --test enterprise/audit-service/test/*.test.mjs`；八套企业回归 | audit-service `20 passed, 0 failed`；八套合计 `285 passed, 0 failed` | 仅管道核心；真实网关/UI 未接入，管理员 OIDC/RBAC/组织范围未实现，ingest 与查询共用服务令牌；L2/L3 正文、流式拼接、对象存储、留存/删除证明、WORM、Prometheus/积压告警、PostgreSQL/HA、Docker/Compose 实机、真实 IdP、浏览器 E2E 和生产验收未完成 |
| M4-B 内容审计核心（历史阶段） | `codex/m4-b-content-audit-core` / `enterprise/audit-service/` | 内部流式内容 API；默认关闭，只接受 L2 `text/plain` 脱敏正文，拒绝 L3/附件/二进制/未知字段；分片顺序/偏移校验、幂等重放、冲突/乱序/TTL/容量限制、重启中断恢复；完成后统一脱敏私钥、密码、Bearer/JWT、云/厂商 token、URL 凭据、邮箱、手机号、身份证和 Luhn 银行卡；AES-256-GCM 加密正文对象与索引分目录；当时的静态读取令牌已被后续 M4-C 一次性 grant 取代；健康状态和优雅关闭接入 | `node --test enterprise/audit-service/test/*.test.mjs`；八套企业回归 | 该阶段 audit-service `34 passed, 0 failed`（20 事件管道 + 14 内容审计核心）；八套合计 `299 passed, 0 failed` | 该阶段仅有后端核心且默认关闭；真实网关正文采集、管理台检索/查看、留存删除、删除证明、法律保留、WORM、加密导出、Docker/Compose 实机、真实 IdP、浏览器 E2E 和生产验收未完成 |
| M4-C 内容检索与一次性正文授权核心 | `codex/m4-c-content-retrieval-core` / `enterprise/audit-service/` | 新增受管理令牌保护的元数据检索，支持员工/部门/设备/Agent/模型/MCP/工具/内容类型/状态/时间筛选；`createdAt DESC, streamId DESC` 固定排序；HMAC cursor 绑定筛选条件和排序版本；一次性正文 grant 绑定管理员/组织/会话/目标/用途/理由/审批/TTL，消费账本持久化且重启后不可重放；成功/缺失/篡改/失败读取均尝试写访问审计，审计失败不返回正文；ingest 与内容管理令牌隔离，内容管理默认关闭并校验可信管理员头和配置组织范围；旧静态正文读取令牌失败关闭 | `Get-ChildItem enterprise/audit-service/src/*.js \| ForEach-Object { node --check $_.FullName }`；audit-service 专项；八套企业全量 Node/Mock 回归 | audit-service `47 passed, 0 failed`（20 事件管道 + 27 内容审计/检索/授权核心）；八套合计 `312 passed, 0 failed` | 仅后端核心且默认关闭；真实 Magpie 网关正文采集、admin-service 管理员 OIDC/RBAC/step-up/组织隔离编排、管理台检索/查看 UI、浏览器 E2E、留存删除、删除证明、法律保留、WORM、加密导出、PostgreSQL/ClickHouse、HA、多副本一致性、Docker/Compose 实机、真实 IdP/MFA、备份恢复和生产验收未完成；不等于完整 M4 或生产可用 |
| M4-D 留存、法律保留、删除证明与加密导出核心 | `codex/m4-d-retention-export-core` / `enterprise/audit-service/` | 正文和元数据留存独立计算，元数据不得先到期；后台和显式 `dryRun` 清扫、上限控制、活动法律保留阻止删除/脱敏；幂等删除/脱敏、删除 staging 恢复、索引 v1→v2 兼容迁移；HMAC 删除证明列表/详情/验证；AES-256-GCM `.mge` 导出、一次性短期下载 token、导出审计、过期/孤儿清理；内容管理/治理令牌分离，治理和导出默认关闭 | `node --test enterprise/audit-service/test/content-retention.test.mjs enterprise/audit-service/test/content-export.test.mjs enterprise/audit-service/test/content-governance.test.mjs`；audit-service 专项；八套企业全量 Node/Mock 回归 | audit-service `67 passed, 0 failed`（20 事件管道 + 47 内容审计/检索/治理核心）；八套合计 `332 passed, 0 failed`；M4-D 新增 20 项 | 仅后端核心且默认关闭；真实 Magpie 网关正文采集、admin-service 的 OIDC/RBAC/step-up/审批编排、管理台治理 UI、浏览器 E2E、WORM、KMS/HSM、对象存储版本控制、PostgreSQL/ClickHouse、HA、多副本一致性、Docker/Compose 实机、真实 IdP/MFA、备份恢复和生产验收未完成；不等于完整 M4 或生产可用 |
| M4-E 管理员内容治理 | `codex/m4-e-admin-content-governance` / `enterprise/admin-service/`、`enterprise/audit-service/` | admin-service 新增内容流检索/详情、一次正文读取、留存 dry-run/执行、删除/脱敏、HMAC 删除证明列表/详情/验证、法律保留创建/查询/释放和加密导出编排；正文读取要求审批、fresh step-up、理由和一次性下载/读取语义；所有写操作接入管理 OIDC、RBAC、组织范围、CSRF、幂等、operation 和 intent/result 审计；内容治理只允许全局组织范围 `*`，break-glass 禁止；audit-service `.mge` 再由 admin-service 独立 AES-256-GCM 密钥加密为 `.mge.enc`；管理台新增检索、读取、留存、删除证明、法律保留和导出表单，下载 token 不持久化 | `node --test enterprise/admin-service/test/*.test.mjs`；`node --test enterprise/audit-service/test/*.test.mjs`；`git diff --check` | admin `123 passed, 0 failed`（86 管理集成 + 5 内容治理客户端 + 5 内容治理存储 + 7 目录 + 7 通知渠道 + 7 通知规则 + 6 SIEM）；audit-service `67 passed, 0 failed`；八套合计 `346 passed, 0 failed`；M4-E 新增 10 项 | 默认关闭，必须成组配置五项内容治理环境变量；真实 Docker/Compose、企业 OIDC/MFA、TLS/反向代理、真实 Magpie 网关正文采集、浏览器 E2E、WORM/KMS/HA、备份恢复和正式合规验收未完成；内容治理只允许全局组织范围 `*`，且不能使用 break-glass；不等于完整 M4 或生产可用 |
| M5-A 检测规则引擎与网关元数据投递核心 | `codex/m5-a-detection-rules-core` + `codex/m5-a-gateway-detection-ingest` / `enterprise/security-service/`、`internal/securitydetect/`、`plugins/securitydetect/` | 严格检测事件 allowlist，拒绝 Prompt、回复、附件、正文、Cookie、凭据和未知字段；来源 IP 仅接受 `sha256:<64 lowercase hex>`；敏感数据、异常 Token/费用、预算阈值、直连、授权范围越权、设备不合规、来源 IP 和来源区域八条稳定规则；确定性 finding、去重键和聚合 ID；原始事件保留，抑制只标记 finding；原子 JSON 存储、幂等重放/同 ID 冲突、秘密扫描、独立 ingest/read token、请求 ID、限流和优雅关闭；Compose `security` profile 内部暴露且独立 `security-data` 卷；网关 `usage.Observer` 按每次路由尝试投递元数据，使用已认证网关 Key 身份、真实连接 peer、HMAC-SHA256 源地址、异步有界队列和 429/5xx 有限重试，不信任转发头，配置失败只影响插件 | `node --test enterprise/security-service/test/*.test.mjs`；`go test -tags nogui ./internal/securitydetect ./plugins/securitydetect`；`go test -tags nogui ./internal/pluginrt`；`go test -tags nogui ./internal/gateway -run "TestObserver|TestObserved|TestCapture|TestWatch"`；九套企业全量 Node/Mock 回归；`git diff --check` | security-service `17 passed, 0 failed`；网关投递新增 12 项 Go 测试通过（导出器 8、插件生命周期 3、网关身份/来源地址映射 1）；九套合计 `363 passed, 0 failed` | 仅规则引擎与网关投递核心；没有安全运营管理 UI、告警/限流/阻断/吊销/设备锁定/工单自动响应、OTel/Prometheus/Grafana、生产 SIEM、值班手册/演练、HA 和生产验收；Docker/Compose、真实反向代理来源地址、运行中 Go 导出器到 security-service 的端到端投递未验证；不等于完整 M5 或生产可用 |
| M5-B 响应动作状态机与受控模拟执行核心 | `codex/m5-b-response-actions` / `enterprise/security-service/`、`enterprise/docker-compose.yml`、`enterprise/.env.example` | 新增 `rate_limit`、`block`、`revoke_key`、`lock_device`、`open_ticket` 五类动作；`requested/approved/active/reverted/expired/failed` 状态机；创建、审批、激活、撤销、过期、列表、详情和逐动作审计 API；强制独立 `SECURITY_CONTROL_TOKEN`、`Idempotency-Key`、组织头、职责分离、授权/动作有效期、source/target 绑定和 fail-closed 校验；每动作独立 hash-chain 审计，支持幂等重放、冲突拒绝、组织隔离和重启恢复；v1→v2 存储迁移；执行器明确为 `simulation`，返回 `policyApplied: true`、`gatewayApplied: false` 和 `policy_applied_without_gateway_enforcement`，不声称真实网关阻断；`gateway_key` 因无法验证而 fail closed | `node --test enterprise/security-service/test/*.test.mjs`；九套企业全量 Node/Mock 回归；`git diff --check` | security-service `30 passed, 0 failed`（17 项 M5-A + 13 项 M5-B）；九套合计 `376 passed, 0 failed` | 当前只做受控模拟执行；真实网关阻断/吊销、真实厂商工单、安全运营管理 UI、OTel/Prometheus/Grafana、生产 SIEM、完整 OIDC 角色授权、Docker/Compose 实机、HA 和生产验收未完成；不等于完整 M5 或生产可用 |
