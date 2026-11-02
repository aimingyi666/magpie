# Magpie 企业版完整功能方案

状态：完整方案评审版 v3.24（完整需求基线见第 25 节，执行版工作分解见第 26 节；M0 已落地；
M1 已完成本地真实链路验收；M2-A 管理身份底座、M2-B 只读治理、M2-C1 Auth 内部写接口、
M2-C2 管理写 API 和 M2-C3 幂等/管理审计状态机已实现并通过 Mock 集成测试；M2-C4-01
网关机器协议已实现，并通过 Go 单测、CLI 回归和隔离真实二进制冒烟测试；C4-02
`gateway-control` 受控适配器已实现，并通过 15 项 Mock/故障测试；C4-03a 正式只读模型
目录已实现，并通过 7 项目录专项、82 项管理服务集成、7 项通知渠道专项、7 项通知规则专项
和 6 项 SIEM 专项测试，管理服务总计 109 项通过；
C4-03b 已在 auth-service 实现用户级策略核心状态机、M1 `unknown` 迁移、分步初始化、
版本冲突、失败关闭和回读确认接口，auth-service 当前 26 项测试通过；C4-03c 的管理端
额度/模型 API、幂等签发、issuance journal、自动 apply/readback、同步后交付、失败补偿和
启动恢复核心已实现，并通过 Mock/故障测试；C4-03d 已实现管理页额度/模型写表单、完整
证据链状态、员工只读状态门户、审批/operation 页面、用量/审计查询和 CSV 授权导出，
基础停用/吊销/轮换页面也已接入，但失败目标恢复入口和浏览器 E2E 未完成；M2-C5 已实现 operation
查询、脱敏审计分页和四种人工对账动作，并通过 Mock/故障测试；C4-04 的完整管理
到真实 Magpie 策略流 E2E 已实现并通过，覆盖真实模型拒绝、
Token 限额、冲突不落盘、旧 Key 撤销和秘密扫描，以及双设备独立 Key、`partial_success`、
refresh/rotate 策略继承、故障后 `unknown/pending_sync`、Journal/孤儿 Key 撤销和恢复同步；
M2-D 核心已实现，Mock/集成测试通过；生产验收尚未完成。M2-D 当前使用受限 JSON 存储，
没有对象存储、异步大批量导出、Excel 导出或分布式锁。M3-A 的资源目录、不可变版本、
SHA-256 内容寻址、Ed25519 签名、发布/历史回滚和资源审计核心已实现并通过 11 项测试；
M3-B 的远程 MCP 注册、企业统一端点、工具级授权、健康检查、上游凭据隔离和元数据审计
核心已实现并通过 14 项测试；M3-C-1 的同步凭证、desired-state、设备上报、管理员 JSON
查询 API 和客户端 HTTP 传输适配器已实现，叠加原有签名同步、原子安装、失败保留旧版本、
离线缓存、强制/推荐策略、漂移检测、路径/符号链接防护、并发锁和状态秘密隔离核心，
client-sync 当前 24 项测试通过，M3-D 与 M4-M6 尚未实现。M3-C-2 已把资源目录和设备同步
报告以只读、按组织范围过滤的方式接入管理页，并只投影白名单字段；依赖故障统一返回
`503 resource_service_unavailable`。M3-A/M3-B 尚未接入 admin-service 真实审批和可写管理台，
M3-B 的 OIDC 组织分配也未实现；M3-C-1/M3-C-2 已接入员工端短期同步凭证和
desired-state/report API 及管理页只读资源/漂移视图，但资源发布/回滚 UI、发布/回滚审批联动、
本地 helper 产品入口、目标 Agent 文件映射、Windows ACL、MDM、真实 IdP、浏览器 E2E、
Docker/Compose 实机验收、灰度/自动回滚和生产验收仍未完成；
M3-B 的审批 nonce 仅单进程内存，
注册表与审计不是同一事务，且 Docker/Compose 尚未实机验收。M2-E 的 APR-01a
服务端审批、绑定校验、职责分离、
一次性消费和启动恢复已实现并通过 Mock/故障测试；APR-01b 的 HMAC 外部审批回调适配器
已实现并通过 Mock/故障测试，但真实飞书/OA/ServiceNow/Jira 连接器未验证；APR-01c 的
独立 OIDC step-up 已实现并通过 Mock IdP 集成测试；APR-01d 的审批箱、串行/并行步骤、
显式 `stepId`、quorum、转交、撤回和基础管理页已交付；APR-01e 的 15 分钟单次
break-glass、强制关键 step-up、24 小时事后复核、RBAC、告警事件、审计、API 和管理页已完成
Mock/集成核心；真实 OA、真实 IdP/MFA、SIEM/告警、浏览器 E2E 和生产事后复核演练仍未验收；
NOTIFY-01a 的 transactional outbox、租约、幂等、退避、死信、重启恢复、
deliveries 查询和人工重放已实现并通过 Mock/故障测试；NOTIFY-01b 的渠道管理 API 和统一
HTTPS 渠道适配器已实现并通过 Mock/故障测试；NOTIFY-01c 的 SIEM transport 已实现并通过
6 项专项测试，支持 `http-collector`/`otlp-http`/`syslog-tls`、固定 L0 schema 和 dead-letters
API；NOTIFY-01d 的规则/抑制、聚合、阈值/延迟升级、受审计重放和通知运营页已实现并通过
7 项专项及管理回归测试，但真实 SIEM/Collector/Syslog、生产证书和真实厂商渠道未验收；
Docker/Compose、
真实企业 IdP、公司反向代理和生产环境仍需完整验收。C4-03a/C4-03b/C4-03c/C4-03d
四项实现契约分别是正式模型目录、首次策略初始化、新 Key 同步后交付和页面与对账状态语义；
其中 C4-03a/C4-03b/C4-03c 核心已实现，C4-03d 部分实现，C5 后端和基础页面已实现，
M2-D 核心已实现并待真实环境验收。

日期：2026-11-02
适用范围：基于 `yetone/magpie` fork 的企业内部二次开发
目标读者：产品、研发、IT、安全、运维、审计

关联文档：

- [`enterprise-master-plan.md`](enterprise-master-plan.md)：面向评审和实施的总纲，统一角色流程、功能目录、里程碑顺序和上线门槛。
- [`enterprise-roadmap.md`](enterprise-roadmap.md)：按阶段和优先级拆分的路线图。
- [`enterprise-deployment.md`](enterprise-deployment.md)：fork 同步、发布和部署操作。
- [`enterprise-operating-model.md`](enterprise-operating-model.md)：项目 RACI、协作节奏、GitHub 规则、环境晋级、发布证据、成本容量、培训和试点退出。
- [`enterprise-acceptance-checklist.md`](enterprise-acceptance-checklist.md)：从试点到生产的逐项验收证据清单。
- [`enterprise-implementation-status.md`](enterprise-implementation-status.md)：已实现、已测试和未验证能力的真实状态。
- [`../enterprise/README.md`](../enterprise/README.md)：当前可运行的 M0/M1/M2 企业层操作入口，并记录 C4-01/C4-02 的机器协议与受控适配器边界。

### 版本记录

| 版本 | 日期 | 变更 |
| --- | --- | --- |
| v3.24 | 2026-11-02 | 记录 M3-C-2 只读管理可见性交付：admin-service 新增 `GET /api/v1/admin/resources`、`GET /api/v1/admin/resources/{resourceId}`（`resources.read`），以及 `GET /api/v1/admin/resource-sync/reports`、`GET /api/v1/admin/resource-sync/reports/{deviceId}`（`devices.read`）；配置 `ADMIN_RESOURCE_SERVICE_URL`/`ADMIN_RESOURCE_SERVICE_TOKEN`（成对、令牌至少 32 字符）、`ADMIN_RESOURCE_SERVICE_TIMEOUT_MS` 和 `ADMIN_RESOURCE_SERVICE_MAX_RESPONSE_BYTES`；客户端只发 GET、禁止重定向、默认 5 秒超时和 4 MiB 响应上限；资源按 `"*"`/管理员组织范围过滤并只投影范围内 assignments，同步报告要求设备存在、属于可见用户且 `userId` 与设备映射一致；资源内容、签名私钥、服务令牌和上游 actor 字段不返回；未配置、超时、坏 JSON、超大响应、5xx 和重定向统一 `503 resource_service_unavailable`；管理页新增无内联脚本的只读资源/同步面板。admin 109 项（82 集成 + 7 目录 + 7 渠道 + 7 规则 + 6 SIEM）、auth 26 项、gateway-control 15 项、resource 15 项、mcp-gateway 14 项、client-sync 24 项，总计 203 项通过。资源发布/回滚 UI、发布/回滚审批联动、M3-B MCP 管理台、本地 helper 产品入口、目标 Agent 文件映射、Windows ACL/MDM、真实 IdP、浏览器 E2E、Docker/Compose 实机、灰度/自动回滚和生产验收仍未完成。 |
| v3.23 | 2026-11-02 | 记录 M3-C-1 同步控制面交付：auth-service 新增 `POST /api/v1/devices/sync-credential`，从设备身份签发 60-900 秒的 `mss1` HMAC 同步凭证，并绑定 OIDC `groups` 派生的组织范围；resource-service 新增按组织范围返回的 `GET /api/v1/client/sync/desired-state`、只接收元数据证据的 `POST /api/v1/client/sync/report`，以及管理员 `GET /api/v1/admin/sync-reports[/{deviceId}]` JSON 查询；报告按设备保留最新一份，原子写入、`0600` 并限制设备数；client-sync 新增 `createEnterpriseSyncTransport()`，覆盖凭证缓存/重签、条件请求、超时、响应上限和报告投影。auth 26 项、admin 104 项、gateway-control 15 项、resource 15 项、mcp-gateway 14 项、client-sync 24 项，总计 198 项通过；resource 15 = 11 项核心 + 4 项控制面，client-sync 24 = 16 项核心 + 8 项传输。管理台资源/漂移页、本地 helper 产品入口、目标 Agent 文件映射、Windows ACL、MDM、真实 IdP、浏览器 E2E、Docker/Compose 实机验收、灰度发布和自动回滚仍未完成；管理端目前只有 JSON API，没有同步报告 UI。 |
| v3.22 | 2026-11-02 | 记录 M3-C 客户端资源同步核心交付：固定 Ed25519 公钥、`signingKeyId` 和 SPKI SHA-256 指纹；desired-state manifest/内容/长度/SHA-256 校验；staging、fsync、复验、rename 原子激活；失败保留上一验签版本；离线缓存；forced/recommended；漂移检测；路径穿越、符号链接、坏缓存、重复资源/版本/hash、未知 key、低版本客户端和超大 manifest 拒绝；进程锁；状态 `0600` 原子写入；报告不含内容、token、Secret 或私钥；同步周期 1-300 秒。client-sync 16 项、admin 104 项、auth 25 项、gateway-control 15 项、resource 11 项、mcp-gateway 14 项，总计 185 项通过。员工端同步凭证 API、管理台资源/漂移页、本地 helper 产品入口、浏览器 E2E、Windows ACL、MDM、目标 Agent 文件映射、灰度发布、设备端上报和生产验收仍未完成；M3-D 与 M4-M6 未实现。 |
| v3.21 | 2026-11-02 | 记录 M3-B 远程 MCP 治理核心交付：元数据注册表、管理员注册/更新/健康检查、客户端凭据签发/吊销、tools-only Streamable HTTP JSON-RPC 企业端点、user/org/device/server scope、工具级 allow/deny/风险/可见性、short-lived HMAC 审批门禁、HTTPS/host allowlist、固定 DNS、私网/元数据地址与重定向拒绝、请求/响应/超时/速率限制、每服务器熔断、SHA-256 客户端 token 摘要、环境 Secret Reference 和元数据审计。mcp-gateway 14 项、admin 104 项、auth 25 项、gateway-control 15 项、resource 11 项，总计 169 项通过。审批 nonce/限流器仍仅单进程；注册表、审计和幂等非同一事务，审计失败窗口可能留下不可恢复 token 的孤立 client；admin-service 真实审批查询/一次性消费、管理台、OIDC 组织分配、客户端同步、M3-C/D、共享事务存储、KMS/HSM、mTLS、真实 MCP/IdP、浏览器 E2E、Docker/Compose 实机和生产验收仍未完成。 |
| v3.20 | 2026-11-02 | 记录 M3-A 资源目录与签名服务核心交付：五类资源目录、`forced`/`recommended` 交付模式、不可变版本、SHA-256 内容寻址、canonical JSON、manifest digest、Ed25519 签名、发布/历史回滚、乐观并发、`Idempotency-Key` 与 actor 绑定、JSON 原子存储、Bearer 服务令牌、限流、请求 ID、明文秘密/私钥/未知字段失败关闭和资源审计。resource-service 11 项、admin 104 项、auth 25 项、gateway-control 15 项，总计 155 项通过。`approvalId` 目前只是必填证据，尚未接入真实审批状态查询/一次性消费；远程 MCP、客户端同步、管理台、S3/MinIO、KMS/HSM、多副本、Docker/Compose 实机和生产验收仍未完成。 |
| v3.19 | 2026-11-02 | 记录 NOTIFY-01d 通知规则与运营交付：通知规则 CRUD、事件/严重级别/目标/组织匹配、抑制窗口、聚合维度与窗口、阈值/延迟升级、单条升级失败隔离、`aggregates`/`suppressions`/`escalations` 查询、dead-letter 受审计幂等重放，以及渠道/规则/投递/死信/聚合/抑制/升级运营页；规则和渠道写操作要求管理会话、CSRF、RBAC、H 级 step-up、理由和 `Idempotency-Key`，规则更新支持 `expectedUpdatedAt`。admin 104 项、auth 25 项、gateway-control 15 项，总计 144 项通过。真实 IdP/MFA、真实 SIEM、真实邮件/IM/Webhook/工单厂商、生产证书与域名、浏览器 E2E、生产高可用/负载、留存和灾备未验收。 |
| v3.18 | 2026-11-02 | 记录 APR-01e break-glass Mock/集成核心交付：15 分钟单次紧急授权、24 小时事后复核、`active/expired/consumed/review_overdue/reviewed` 状态、申请/复核 RBAC、关键 step-up、环境/策略版本/申请人/动作/目标/组织/风险/理由/payload/绑定摘要、原子消费、复核提醒、通知事件、审计、API 和管理页；禁止审批与 break-glass 同时使用。admin 95 项、auth 25 项、gateway-control 15 项，总计 135 项通过。真实 IdP/MFA、SIEM/告警、OA/工单、浏览器 E2E 和生产事后复核演练仍未验收。 |
| v3.17 | 2026-11-02 | 记录 APR-01d 审批箱与多步骤审批交付：`GET /api/v1/admin/approvals/inbox`、申请人撤回、步骤转交、串行/并行步骤、显式 `stepId`、每步 `requiredApprovers/quorum`、步骤摘要、外部回调 `stepId` 要求和自动加载；管理页可查看活动步骤并执行撤回/转交。新增串行审批箱、并行 quorum、转交/撤回和外部回调 `stepId` 测试。admin 90 项、auth 25 项、gateway-control 15 项，总计 130 项通过。APR-01d 仅为 Mock/集成核心，APR-01e break-glass、真实 OA/IdP/MFA、浏览器 E2E 和生产验收仍未完成。 |
| v3.16 | 2026-11-02 | 记录 M2-D 核心交付：用量/审计查询与 cursor 分页、operation 列表/详情和受控人工对账、停用/吊销/轮换与审批基础页面、用量/审计 CSV 授权导出；首次创建要求已批准且未消费审批、fresh step-up、CSRF、RBAC、组织范围、理由、`approvalId` 和 `Idempotency-Key`，同键幂等重放可返回原导出，使用一次性 Bearer token、绑定同一管理员会话 Cookie、拒绝 query-string token，首次下载后消费并记录 `export.downloaded` 系统审计；CSV 使用 UTF-8 BOM/CRLF、公式注入防护和记录/字节上限，不导出对话正文、Key ID、Cookie、OIDC/service secret 或 token hash。admin 86 项、auth 25 项、gateway-control 15 项，总计 126 项通过。M2-D 核心已实现，Mock/集成测试通过；生产验收尚未完成。仍缺失败目标恢复入口、浏览器 E2E、真实 IdP/MFA/OA/SIEM、共享卷/Docker、生产负载测试、分布式锁、留存/删除策略，以及费用趋势看板、对象存储和异步大批量导出；Excel 导出未实现。M3-M6 仍未实现。 |
| v3.15 | 2026-11-02 | 记录 NOTIFY-01c SIEM transport 交付：新增 `siem` 渠道及 `http-collector`/`otlp-http`/`syslog-tls` 三种 provider、固定 L0 schema、HTTPS:443/TLS:6514、host allowlist、固定 DNS、私网/回环/链路本地/云元数据拒绝、HTTP/OTLP 可选 Bearer `secretRef`、Syslog 禁止 `secretRef`、默认 32 KiB 事件上限、critical 优先、5 分钟轮询上限和 dead-letters API；新增 4 个安全事件类型。admin 82 项、auth 25 项、gateway-control 15 项，总计 122 项通过。真实 SIEM/Collector/Syslog/生产证书未验收；rules/suppress API、聚合、升级、NOTIFY-01d/完整运营 UI 和 M5 闭环未实现。邮件/IM/工单仍是 HTTPS 网关契约。 |
| v3.14 | 2026-11-02 | 记录 NOTIFY-01b 渠道交付：`email`/`im`/`webhook`/`ticketing` 渠道管理 API、渠道测试、按 `eventId + channelId` 去重 fanout、RBAC/CSRF/step-up/幂等/审计，以及统一 HTTPS 网关适配器；仅允许 HTTPS:443、host allowlist、固定 DNS 解析、拒绝私网/回环/链路本地/云元数据地址、仅 307/308 最多 3 跳重定向、超时和响应大小限制；Webhook 使用时间戳、nonce 和 HMAC-SHA256；Secret 只保存环境变量名 `secretRef`。邮件/IM/工单是 HTTPS 网关契约，不是原生 SMTP、Graph、飞书、Teams、ServiceNow 或 Jira SDK。admin 75 项、auth 25 项、gateway-control 15 项，总计 115 项通过。SIEM、rules/suppress API、通知运营页、真实厂商连接和生产验收未完成。 |
| v3.13 | 2026-11-02 | 记录 NOTIFY-01a transactional outbox：8 种 L0 审批/operation 事件、字段白名单、稳定 `eventId`/`deliveryId` 幂等、租约、并发串行、1/5/15/60/360 分钟退避、死信、重启恢复、deliveries 查询和受审计人工重放；审批/结果审计与 outbox 同一次原子存储提交。admin 67 项、auth 25 项、gateway-control 15 项，总计 107 项通过。尚无渠道 transport、channels/rules/suppress API 或运营页；`operation.audit_failed` 无触发点；查询无 cursor，`count` 为当前页数量；正常启动无 transport 时不创建 dispatcher；真实渠道和生产验收未完成。 |
| v3.12 | 2026-11-02 | 记录 APR-01c 独立 OIDC step-up：独立 Client、授权码 + PKCE、`prompt=login`、`max_age`、essential `auth_time`、ACR/MFA、会话/IP/UA/角色范围摘要绑定，以及 H/C 写操作和审批门禁；未配置时失败关闭。admin 61 项、auth 25 项、gateway-control 15 项，总计 101 项通过。真实 IdP、MFA、反向代理、浏览器流程和生产验收仍未完成；APR-01d/e 审批箱/break-glass 和 NOTIFY-01 仍未实现。 |
| v3.11 | 2026-11-02 | 记录 APR-01b HMAC 外部审批回调适配器：原始 body HMAC-SHA256、时间窗、nonce 防重放、issuer/audience、eventId 幂等、职责分离、审批状态和系统审计；admin 53 项、auth 25 项、gateway-control 15 项，总计 93 项通过。真实飞书/OA/ServiceNow/Jira 适配、审批 UI、step-up/MFA/ACR、审批箱、break-glass 和通知 outbox/渠道仍未实现或未验收。 |
| v3.10 | 2026-11-02 | 记录 APR-01a 服务端审批交付：风险分级、规范化 payload 与绑定摘要、审批状态机、职责分离、组织范围、一次性消费、并发/重启失败关闭、审批 API 和系统审计；admin 49 项、auth 25 项、gateway-control 15 项，总计 89 项通过。外部 OA 回调、step-up、审批箱、break-glass、通知 outbox/渠道和审批管理 UI 仍未实现或未验收。 |
| v3.9 | 2026-11-02 | 记录 M2-C5 后端交付：operation 详情、脱敏审计分页、签名 cursor、四种人工对账动作、父子 operation、原子 models+limits 更新；admin 44 项、auth 25 项测试通过。管理台查询/对账页面、真实审计存储、生产 IdP/代理和人工运维演练仍未验收。 |
| v3.8 | 2026-11-02 | 记录 C4-04 完整管理到真实 Magpie 策略流 E2E 通过：双设备独立 Key、多凭证部分失败、refresh/rotate 继承、故障后 pending、Journal/孤儿 Key 撤销、恢复同步、真实限额/模型拒绝、usage 归属和秘密扫描；明确当时 Docker、真实 IdP、共享卷、浏览器 E2E、C5 页面/D 和生产验收仍未完成。 |
| v3.7 | 2026-11-02 | 记录 C4-03d 部分交付：管理页额度/模型写表单、完整证据链状态和员工只读状态门户；当时统一 auth 23 项、admin 35 项测试口径，明确页面 E2E、恢复入口、C5 查询对账和生产验收仍未完成。 |
| v3.6 | 2026-11-02 | 记录 C4-03c 核心实现和 C4-03d 部分实现；当时统一 auth 21 项、admin 34 项和 gateway-control 15 项测试口径；明确真实环境、真实 Magpie E2E、完整员工门户和 C5 对账仍未验收。 |
| v3.5 | 2026-11-01 | 统一 E1-E12 功能域编号；补齐能力闭环矩阵和阶段交付证据表；统一 C4 核心已实现与管理链路未实现的状态口径；修正上游同步目标态为自动 PR，禁止机器人或人工直推受保护 `main`。 |
| v3.4 | 2026-11-01 | 冻结 C4-03a/C4-03b/C4-03c/C4-03d 正式模型目录、首次策略初始化、同步后交付和页面状态契约。 |

本版本是方案和验收基线更新，不代表本轮重新执行了代码测试；实际完成度仍以
[`enterprise-implementation-status.md`](enterprise-implementation-status.md) 记录的原始证据为准。

## 0. 方案结论

这套方案把 Magpie 企业版拆成“客户端 + 控制面 + 数据面”三部分，而不是把企业功能全部塞进
Magpie 单机 Web UI：

```text
员工本地 Magpie/Agent
  -> 企业模型/MCP 网关（数据面）
  -> 企业控制面（身份、管理、策略、资源、审计）
```

首期不追求一次做完所有能力。正确的顺序是：

1. 用 M0 完成企业网关、员工身份归属、额度和最小闭环。
2. 用 M1 完成 OIDC、设备注册和短期凭证，消灭长期员工 Key。
3. 用 M2 建立管理会话、组织范围、RBAC、管理操作审计和用量看板。
4. 用 M3 建立中央 MCP、Skills、Instructions、Subagents 和模板的资源库。
5. 用 M4 做经授权的会话与工具审计；默认仍然只记录元数据。
6. 用 M5 做告警、阻断、SIEM 和值班闭环。
7. 用 M6 做 PostgreSQL、HA、KMS、mTLS 和多地域。

### 0.1 首期上线的最小可用闭环

首期不是“功能越多越好”，而是下面这条链路可证明、可回滚：

```text
员工用企业 OIDC 登录
  -> 注册受控设备和短期凭证
  -> 本地 Magpie 自动配置 Agent
  -> 只能访问企业模型和企业 MCP
  -> 管理员按人/部门/设备/Agent/模型查看用量
  -> 敏感操作有权限检查和管理员审计
  -> 离职或设备丢失可立即吊销
```

达到这个闭环后，员工才算真正“能用”，管理员才算真正“能管”。在此之前，只能称为试点
环境，不能对外宣称企业生产版已经完成。

### 0.2 方案完整性检查

| 领域 | 方案是否覆盖 | 当前真实状态 |
| --- | --- | --- |
| 员工身份、设备、短期凭证 | 是，见第 5、6.1、12 节 | M1 本地真实链路已验收，真实 IdP 待验收 |
| 管理登录、RBAC、组织范围 | 是，见第 4、18、12.1 节 | M2-A/M2-B 已实现认证、会话、CSRF、角色、组织范围和只读治理；M2-C1 内部写接口、M2-C2 四个管理写 API 和 M2-C3 幂等/intent-result 管理审计已实现；C4-01 底层机器协议、C4-02 受控适配器、C4-03b/C4-03c 策略核心与额度/模型 API 已实现；C4-03d 已部分交付管理页额度/模型写表单和员工只读状态门户；M2-C5 的 operation/audit 查询和人工对账后端已实现并通过 Mock/故障测试；M2-D 已交付审批、operation、查询、CSV 导出和基础停用/吊销/轮换页面；失败恢复、浏览器 E2E、完整运营体验和生产验收未完成 |
| 员工/管理员页面与操作流程 | 是，见第 5、6.2、6.3、12.1 节 | 已有 M1 员工页、M2-A 管理页、M2-B 只读摘要、C4-03d 额度/模型写表单和员工只读状态门户，以及 M2-D 的审批/operation、用量/审计查询、导出和基础停用/吊销/轮换页面；完整运营看板、浏览器 E2E、失败恢复入口和生产验收未完成 |
| 模型网关、额度、白名单 | 是，见第 6.4、6.8、12.8.1 节 | M0 已有手工网关能力；C4-01 的 schema v1 机器回读和原子策略写入已实现并通过本地测试；C4-02 的受控适配器已实现并通过 15 项 Mock/故障测试；C4-03a 的正式只读模型目录、C4-03b 的用户级策略核心和 C4-03c 的管理/签发/同步/交付核心已实现；C4-03d 仅部分实现；C4-04 完整管理到真实 Magpie 策略流 E2E 已通过，但 Docker/真实共享卷、真实 IdP 和生产验收仍未完成 |
| MCP 目录、远程/本地 MCP、工具权限 | 是，见第 5.4、6.5 节 | M3-B 远程 MCP 治理核心已实现并通过 14 项测试；M3-C-1 已提供短期同步凭证、desired-state、设备上报和管理员 JSON 查询 API，client-sync 24 项测试通过；本地 MCP/M3-D、管理台、admin-service 真实审批联动、OIDC 真实 IdP 验收和生产环境验收未实现 |
| 中央资源库、版本、签名、同步、漂移 | 是，见第 5.5、6.6 节 | M3-A 资源目录、版本、签名和审计核心已实现；M3-C-1 已实现签名 desired-state、原子安装/失败保留旧版本、离线缓存、强制/推荐、漂移检测、设备上报和管理员 JSON 查询，但资源发布/回滚 UI、审批联动、本地 helper 产品入口、目标 Agent 文件映射、Windows ACL 和产品级自动回滚未实现 |
| 客户端策略与防绕过 | 是，见第 6.7、9 节 | 只有现有网关和 IP 白名单，完整强制未实现 |
| 会话/工具审计、脱敏、留存 | 是，见第 5.6、6.9、19 节 | 未实现；当前只有元数据用量 |
| 审批、二次认证、职责分离 | 是，见第 5.11、6.12、8.2、9 节 | APR-01a 的服务端审批、绑定校验、职责分离、组织范围、一次性消费和启动恢复已实现并通过 Mock/故障测试；APR-01b 的 HMAC 外部审批回调适配器已实现并通过 Mock/故障测试，但真实 OA 连接器未验证；APR-01c 独立 OIDC step-up 已实现并通过 Mock IdP 集成测试；APR-01d 审批箱、串行/并行步骤、quorum、转交/撤回和基础管理 UI 已实现；APR-01e break-glass 的 15 分钟单次授权、24 小时复核、提醒、通知、审计、API 和管理页已完成 Mock/集成核心；真实 OA、SIEM/告警、工单、浏览器 E2E、真实 IdP/MFA、反向代理和生产验收未完成 |
| 通知、告警路由、Webhook/SIEM/工单 | 是，见第 6.10、6.12、20 节 | NOTIFY-01a 的 outbox、租约、幂等、退避、死信、重启恢复、deliveries 查询和人工重放已实现；NOTIFY-01b 的渠道管理 API 与统一 HTTPS 渠道适配器已实现并通过 Mock/故障测试，覆盖邮件网关、企业 IM、HMAC Webhook 和工单网关；NOTIFY-01c 的 `http-collector`/`otlp-http`/`syslog-tls` SIEM transport、固定 L0 schema 和 dead-letters API 已实现并通过 6 项专项测试；NOTIFY-01d 的规则/抑制、聚合、阈值/延迟升级、受审计重放和通知运营页已实现并通过 7 项专项及管理回归测试。真实 SIEM/Collector/Syslog、生产证书、真实厂商连接和生产值班闭环未验收；不得在业务请求中同步发通知 |
| 部署、备份、灰度、回滚 | 是，见第 10、20、21 节 | Compose 模板已有，Docker/计划任务待实机验收 |
| 上游同步与 fork 兼容 | 是，见第 14、17 节 | 分支工具可用，但当前 `sync-upstream.yml` 仍是合并后直推 `main`；企业目标态必须改为“同步分支 -> 合并 upstream -> CI -> 自动 PR -> 受保护 main 合并”，并完成规则与回归验收 |
| 项目职责、协作、分支保护、环境晋级、成本容量和培训 | 是，见 [`enterprise-operating-model.md`](enterprise-operating-model.md) | 完整运营规则已定义；GitHub 规则、预算和人员任命需企业实际落地 |
| 测试与上线门槛 | 是，见第 13、22、23、25 节 | 已记录 M0/M1/M2-A/M2-B/M2-C1/M2-C2/M2-C3 实测结果；C4-01 有本地单测、CLI 回归和隔离二进制冒烟证据；C4-02 有 15 项 Mock/故障测试证据；C4-03a 有 7 项目录专项和 82 项管理服务集成测试证据；C4-03b/C4-03c 有 26 项 auth-service 测试；M3-A 有 11 项资源目录/签名/存储/幂等/审计测试证据；M3-B 有 14 项注册表、scope、工具授权、审批、SSRF、健康/熔断、边界和审计测试证据；M3-C-1 有 4 项同步凭证/desired-state/report 控制面测试和 8 项客户端传输测试，叠加 16 项同步引擎核心测试；M2-C5、M2-D、APR-01a、APR-01b、APR-01c、APR-01d、APR-01e、NOTIFY-01a、NOTIFY-01b、NOTIFY-01c 和 NOTIFY-01d 有 operation/audit/reconcile/export/approval/callback/step-up/inbox/break-glass/outbox/channel/SIEM/rules/aggregation/escalation 的 Mock/故障测试证据；C4-04 完整管理到真实 Magpie 策略流 E2E 已通过。当前总计 admin 109/109、auth 26/26、gateway-control 15/15、resource 15/15、mcp-gateway 14/14、client-sync 24/24，共 203/203。resource 15 = 11 核心 + 4 控制面，client-sync 24 = 16 核心 + 8 传输。浏览器 E2E、真实企业 IdP/OA、break-glass 的 5 分钟告警/工单 SLA 和 24 小时生产复核演练、恢复入口、Docker/共享卷、真实审批、资源发布/回滚 UI、审批联动、本地 helper 和 Agent 文件映射、真实厂商通知连接器、真实 SIEM/Collector/Syslog/证书、M2-C5/M2-D 生产验收、M3-B/M3-C 生产验收和 M3-D/M4-M6 尚无完整生产环境验收证据 |

### 0.3 本文档不替代的事实

- “已设计”不等于“已实现”。
- “代码已写完”不等于“已通过真实 IdP、Docker、Windows 和公司网络验收”。
- “员工能在网页看到状态”不等于“网页能直接修改员工电脑上的 Agent 文件”。
- “管理员有权限”不等于“管理员默认可以查看员工对话正文”；正文必须单独授权、二次确认
  并记录管理员审计。

### 0.4 企业上线判定

企业版本必须按证据分级，禁止把“能演示”写成“可生产”：

| 判定 | 必须满足 | 允许的结论 |
| --- | --- | --- |
| 可演示 | Mock IdP、Mock 上游、隔离目录和只读演示数据通过 | 只允许研发/产品演示，不接真实员工 |
| 可试点 | M0/M1/M2-A/M2-B 在真实内网、真实 IdP、真实 Magpie issuer 和受控员工机通过；有备份、吊销和回滚手册 | 允许 5-50 人试点，必须限定部门和保留退出通道 |
| 可生产 | M2-C 写操作与管理审计、审批/step-up、通知投递审计、真实反向代理/浏览器、Windows 计划任务、真实用量卷、备份恢复、权限演练和滚动回滚全部有证据；按规模完成 M6 的 HA/DR | 才允许全员推广和对外称为企业生产版 |

当前仓库的实际判定是：**可演示 + 可做受控技术试点，不是生产完成**。生产验收必须逐项引用
[`enterprise-acceptance-checklist.md`](enterprise-acceptance-checklist.md) 的证据编号。

### 0.5 企业级统一能力模型

下表把分散在各章的方案收敛成十二个能力域，并与第 25 节使用同一套 E1-E12 编号。它描述
“企业生产版必须同时具备什么”，不表示
这些能力已经完成；当前状态仍以
[`enterprise-implementation-status.md`](enterprise-implementation-status.md) 为准。

| 能力域 | 必须实现的能力 | 主要交付阶段 | 当前状态 |
| --- | --- | --- | --- |
| E1 身份与组织 | 员工/管理 OIDC、MFA/ACR、稳定 subject、组织树、角色有效期、SCIM/离职同步 | M1/M2-A/M3 | 员工/管理 OIDC、基础角色和组织范围已实现；真实企业 IdP、MFA/ACR 验收、SCIM 和完整组织同步未完成 |
| E2 设备与凭证 | 设备注册、心跳、短期 Key、刷新、轮换、吊销、并发保护、设备合规状态 | M1/M2-C/M3 | 本地真实 issuer 链路和并发刷新已验收；真实 Windows 计划任务、MDM、设备合规和全域吊销未验收 |
| E3 员工门户 | 本人身份、设备、Agent、模型、额度、资源、同步错误；网页与本地 helper 边界 | M1/M2-D/M3 | 基础员工页、加入脚本和一键配置能力已有；本人额度/模型/凭证/设备只读状态页已实现，个人用量/审计结果可在 M2-D 页面查看；M3-C-1 已提供设备短期同步凭证、desired-state 和报告 API，但资源/漂移页、本地 helper 产品入口、目标 Agent 文件映射、中央 MCP 和网页直接修改本机 Agent 仍未实现 |
| E4 管理控制台 | 独立管理登录、RBAC、组织范围、只读治理、敏感写操作、审批/step-up、操作与审计查询、看板 | M2-A..E | M2-A/B/C1/C2/C3、C4-01/02/03a/03b、C4-03c 核心、M2-C5 后端、APR-01a 服务端审批、APR-01b HMAC 回调适配器、APR-01c 独立 step-up、APR-01d 审批箱/多步骤核心和 APR-01e break-glass 核心已有；C4-03d 部分实现；C4-04 完整管理到真实 Magpie 策略流 E2E 已通过；M2-D 已交付审批/break-glass、operation、用量/审计查询、CSV 导出和基础停用/吊销/轮换页面；浏览器 E2E、失败恢复入口、完整运营体验、C5/M2-D 生产验收、真实 IdP/MFA/反向代理、真实 OA/SIEM/告警/工单和 break-glass 生产演练未完成 |
| E5 模型网关 | 正式模型目录、稳定模型 ID、Provider 隔离、用户级额度、限流、路由、回退和策略回读 | M0/M2-C4 | 手工网关、C4-01 机器协议、C4-02 受控适配器、C4-03a 目录和 C4-03b 策略核心已有；管理员自助调额/模型授权到真实网关生效未完成 |
| E6 用量与成本 | 人/部门/设备/Agent/模型/Key 的 Token、费用、错误、趋势、预算、导出和告警 | M2-B/M2-D/M5 | `usage.jsonl` 元数据归属、只读汇总、筛选/分页、费用趋势和 CSV 授权导出核心已有；预算告警、生产用量卷、对象存储和异步大批量导出未验收 |
| E7 MCP 治理 | 中央目录、远程 MCP 代理、本地 MCP、工具级 allow/deny、健康检查、限流和熔断 | M3/M5 | M3-A 可登记 `mcp` 资源类型和签名版本；M3-B 已提供远程 MCP 注册、企业统一端点、工具级 allow/deny、健康检查、限流和每服务器熔断核心；管理台、admin-service 真实审批联动、OIDC 组织分配、员工端同步接入、本地 MCP/M3-D 和生产验收未实现 |
| E8 企业资源库 | Skills、Instructions、Subagents、模板、不可变版本、签名、审批、同步、漂移和回滚 | M3 | M3-A 核心后端已实现并通过 11 项测试；M3-C-1 已提供同步凭证、desired-state、设备上报和管理员 JSON 查询，叠加签名同步、原子安装、失败保留旧版本、离线缓存、强制/推荐策略和漂移核心，client-sync 24 项测试通过；管理台资源/漂移页、本地 helper、目标 Agent 文件映射、真实审批和产品级自动回滚未实现 |
| E9 客户端策略 | 企业 Provider/网关锁定、最低版本、强制/推荐资源、离线策略和防绕过 | M3/M5 | 现有网关、IP 和 Key 约束可用；M3-C-1 已实现 forced/recommended、最低版本、签名校验、离线缓存和漂移检测，但管理台策略、Windows ACL、MDM/EDR 联动、目标 Agent 文件映射和完整防绕过未实现 |
| E10 审计与通知 | L0-L3 分级、脱敏、留存、访问审计；transactional outbox、邮件/IM/Webhook/SIEM/工单和死信 | M2-E/M4/M5 | 当前有 L0 元数据、审批系统审计、NOTIFY-01a outbox 核心、NOTIFY-01b 渠道管理/统一 HTTPS 网关适配器、NOTIFY-01c SIEM transport/固定 L0 schema/dead-letters API，以及 NOTIFY-01d 规则/抑制/聚合/升级/受审计重放和运营页；真实 SIEM/Collector/Syslog/证书、真实厂商连接、正文审计、生产值班闭环和生产验收未实现/未验收 |
| E11 安全运营 | 异常用量、异地、越权、直连、敏感数据规则、告警、阻断、吊销、SIEM 和 break-glass | M2-E/M5 | APR-01a 已为管理写操作提供审批和职责分离，APR-01b 已提供 HMAC 外部审批回调适配器，APR-01c 已提供独立 step-up，APR-01e 已提供 break-glass 核心及使用/复核到期/逾期/完成通知，NOTIFY-01c 已提供 SIEM transport；真实 OA 连接器、真实 IdP/MFA、M5 检测响应、告警/阻断、真实 SIEM 接收端、5 分钟告警/工单 SLA 和 break-glass 生产演练未验收 |
| E12 交付与上游治理 | Compose/MDM/内网更新、备份、灰度、回滚、HA、KMS/mTLS、SBOM、自动 PR 上游同步和发布证据 | 全阶段/M6 | 模板、本地测试和分支工具已有；当前同步 workflow 仍直推 `main`，真实环境、CI 门禁、HA 和供应链未验收 |

实现时必须遵守一条贯穿所有能力域的规则：**控制面接受期望值不等于数据面已经生效**。
模型、额度、MCP、资源和客户端策略都必须有独立的“应用 -> 回读 -> 持久化 -> 展示”证据链。

### 0.6 能力闭环矩阵

本矩阵用于评审每个能力域是否真正闭环。任何一行缺少入口、服务端权限、事实来源、失败补偿
或验收证据，都只能标记为“部分验证”或“已设计”，不能因为页面存在就判定完成。

共同规则：

- 员工浏览器只负责登录、授权、展示和发起受控流程；浏览器不能直接修改员工电脑上的 Agent 文件。
- 本机 Agent 配置只能由已安装的本地 Magpie/helper 在设备上执行，并受设备身份、签名配置和版本策略约束。
- 管理员默认只能查看 L0 元数据；对话正文、导出和删除必须独立授予权限、二次确认并记录访问审计。
- 服务端 RBAC、组织范围、资源范围和依赖调用才是安全边界，前端隐藏按钮不构成权限控制。
- M3-A 已提供内部资源目录、不可变版本和签名 manifest 核心；M3-B 已提供远程 MCP 治理
  核心；M3-C-1 已提供设备短期同步凭证、desired-state、设备上报、管理员 JSON 查询、
  客户端签名同步和 HTTP 传输，但资源发布/回滚 UI、审批联动、本地 helper 产品入口、目标 Agent
  文件映射、Windows ACL 和 MDM 尚未接入；受控本地 MCP 属于 M3-D，当前尚未实现。

| 能力域 | 员工流程 | 管理员入口 | 服务端权限与事实来源 | 主要 API/执行面 | 失败与补偿 | 审计与脱敏 | 部署验收 | 阶段 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| E1 身份与组织 | 公司 OIDC + MFA 登录，获得稳定员工身份；离职后无法再加入或刷新 | 用户、部门、用户组、角色和 SCIM 同步管理 | `enterprise-auth` / `enterprise-admin`；IdP Claim 和受控组织映射是事实源 | OIDC/PKCE、角色绑定、SCIM/Webhook、停用接口 | Claim 冲突、IdP 不可用、离职晚到和重复同步均失败关闭并可重放 | 登录、角色变更和停用审计；不记录密码、OIDC Secret 或完整令牌 | 真实员工/管理 IdP、MFA/ACR、停用和会话过期 E2E | M1/M2-A/M3 |
| E2 设备与凭证 | 本地 helper 注册设备，取得短期凭证并自动刷新/轮换 | 查看设备与凭证状态，吊销设备或轮换当前凭证 | `enterprise-auth`；设备绑定、Key 哈希和撤销队列是事实源 | join、heartbeat、refresh、rotate、internal revoke | 并发刷新串行化；失败无孤儿 Key；撤销失败进入 `pendingRevocations` 并告警 | 只记录安全 Key ID、设备 ID、操作者和结果；不记录 Key 明文、token hash 或设备令牌 | Windows 计划任务、ACL、断网恢复、MDM 和真实重启恢复 | M1/M2-C |
| E3 员工门户 | 网页查看本人身份、设备、模型、额度、同步状态和恢复提示；本机 helper 执行 Agent 配置 | 查看用户接入状态、失败设备和客户端版本 | `enterprise-auth` + 设备范围 API；网页永远不能写入本机文件 | 个人状态 API、本地 join/config helper、一键配置 Agent | 网页失败可重试；helper 失败显示设备侧错误；不回传其他员工数据 | 个人状态访问审计；响应无 Key、Cookie、设备令牌或他人数据 | 真实浏览器 + 本地 Magpie + 至少一种真实 Agent 5 分钟接入 | M1/M2-D |
| E4 管理控制台 | 无员工入口；员工只能看到本人操作结果 | 独立管理登录、组织范围、只读治理、敏感写、审批/step-up、操作与审计查询和报表 | `enterprise-admin`；管理会话、RBAC、组织子树和 intent/result 审计是事实源 | C5 查询/对账后端、C4-03d 剩余页面、M2-E、M2-D | 幂等冲突、依赖超时、部分成功和审计失败均不得伪造成功；支持对账和子 operation | intent/result、操作者、目标、理由、前后摘要和 `operationId`；默认无正文 | 真实管理 IdP、反向代理、角色演练、浏览器 E2E、失败恢复入口、完整运营体验和生产审计存储 | M2-A..E |
| E5 模型网关 | Agent -> 本地 Magpie -> 企业网关 -> 授权模型；员工不持有厂商 Key | 发布模型目录、配额、模型授权、路由和回退 | Magpie Gateway；模型目录、策略版本和独立回读结果是事实源 | `gateway-key describe/policy apply`、`gateway-control`、C4 管理 API | `unknown` 不伪造历史值；`pending/partial_success` 保留失败凭证；apply/readback 失败不交付 Key | 记录模型、额度版本、安全 Key ID 和策略结果；不记录上游密钥 | 完整管理到真实 Magpie 策略流 E2E 已通过；Docker/真实共享卷、真实 IdP 和浏览器 E2E 待验收 | M0/M2-C4 |
| E6 用量与成本 | 查看本人 Token、费用、额度周期和错误摘要 | 按人/部门/设备/Agent/模型/Key 筛选、导出和预算告警 | 网关 `usage.jsonl`；后续事件存储是事实源 | 只读用量 API、异步导出、告警规则 | 损坏/超限数据不得生成部分报表；导出失败可重试且不伪造结果 | 默认只含 L0 元数据；导出需独立权限、水印和访问审计 | 真实用量卷、轮转、大文件、损坏恢复和成本对账 | M2-B/M2-D/M5 |
| E7 MCP 治理 | 只看到已分配 MCP 和工具，使用企业地址而非上游凭据 | 登记、审批、分配、健康检查、工具 allow/deny 和回滚 | `enterprise-resource` + MCP Gateway；目录和签名 manifest 是事实源 | MCP 目录、远程代理、工具策略、健康检查 | 未授权工具拒绝；上游故障熔断；发布失败回退上一签名版本 | 工具名、参数类别、结果状态和策略命中；默认不记录完整参数或正文 | 真实 MCP、工具越权、凭据不下发和故障隔离 E2E | M3/M5 |
| E8 企业资源库 | 获取强制/推荐 Skills、Instructions、Subagents 和模板，查看期望/实际版本 | 发布、审批、灰度、分配、漂移和回滚 | `enterprise-resource` + 对象存储；不可变 manifest、签名和版本是事实源 | manifest、签名包、内容分发、同步和漂移上报 | 未签名/哈希不符拒绝；坏版本回滚；离线使用最后已验证版本 | 发布者、审批、版本、范围、同步结果；资源包不含明文 Secret | 签名校验、篡改拒绝、灰度和 5 分钟同步证据 | M3 |
| E9 客户端策略 | Agent 使用企业 Provider/网关；强制项不可关闭，离线遵循最后签名策略 | 发布最低版本、Provider 锁定、强制/推荐资源和离线策略 | 本地 Magpie 策略执行 + 网络出口 + 服务端凭证共同构成边界 | 签名策略包、MDM/EDR 状态、客户端心跳和版本上报 | 策略过期降级；不合规阻断；回滚恢复上一配置；不靠隐藏按钮 | 策略版本、设备状态、漂移和响应动作审计；不含本机秘密 | Windows/macOS 实机、MDM、断网、直连检测和回滚演练 | M3/M5 |
| E10 审计与通知 | 员工可被告知采集范围；本人元数据查询受企业政策约束 | 审计员按范围查询 L0/L1；正文 L2/L3 需独立授权；通知运营查看投递和死信 | `enterprise-audit` + outbox/dispatcher；不可篡改事件和 outbox 是事实源 | 审计查询、正文访问审批、outbox、邮件/IM/Webhook/SIEM/工单 | 正文采集失败不影响请求的策略可配置；通知独立重试；死信可重放；不阻塞业务提交 | 元数据/摘要/正文/附件分权；访问、导出、删除和投递均审计，事件白名单脱敏 | 留存/删除演练、outbox 重启恢复、渠道故障和 SIEM 5 分钟可见 | M2-E/M4/M5 |
| E11 安全运营 | 异常行为收到阻断或恢复提示，不暴露检测规则和敏感证据 | 安全管理员查看告警、阻断、吊销、工单和 break-glass 记录 | 安全运营服务 + SIEM；检测事件和响应 operation 是事实源 | 规则、告警、响应动作、工单和 break-glass | 误报可抑制但不丢原始事件；响应可撤销；break-glass 到期失效并事后复核 | 检测证据、操作者和响应结果审计；事件不含 Prompt/回复正文和秘密 | 典型规则复现、5 分钟告警、阻断吊销和 24 小时复核演练 | M2-E/M5 |
| E12 交付与上游治理 | 员工只接收签名、灰度、可回滚的企业版本，不直接跟随上游最新 commit | 发布管理员查看同步 PR、CI、发布证据、灰度和回滚点 | 受保护 `main` + CI + 制品库；已验证 tag/commit 是发布事实源 | 同步分支、自动 PR、构建、签名、MDM/内网更新源、备份恢复 | 冲突或 CI 失败停在上一已验证发布点；不回滚已撤销秘密；保留同步分支和证据 | 发布审批、制品哈希、SBOM、同步点和回滚操作审计 | 真实 IdP/Docker/代理/Windows、备份恢复、HA 和供应链验收 | 全阶段/M6 |

### 0.7 阶段交付证据表

下表说明每个阶段“交付什么、证明什么、还缺什么、如何回滚”。表中的“已有证据”是此前记录的
仓库验证结果，不是本轮重新测试；生产验收仍必须按
[`enterprise-acceptance-checklist.md`](enterprise-acceptance-checklist.md) 留存原始输出。

| 阶段 | 依赖 | 交付物 | 预期效果 | 已有/所需测试证据 | 未覆盖项 | 回滚点 |
| --- | --- | --- | --- | --- | --- | --- |
| M0 企业网关基线 | Magpie 现有网关能力 | 企业网关、每员工 Key、模型/额度/IP 策略、用量归属、加入与巡检脚本 | 5-10 人可经企业网关调用并按员工归属用量 | 已有真实 Magpie -> 企业网关 -> Mock 上游、模型调用和用量归属证据 | 公司 TLS、正式 OTLP/SIEM、MDM 分发 | 回到上一网关镜像、配置和旧 Key；不删除撤销记录 |
| M1 身份与设备 | M0、企业 IdP 测试租户 | OIDC/PKCE、设备注册、短期 Key、刷新、轮换、吊销、Windows 刷新脚本 | 员工 5 分钟加入，长期员工 Key 被短期凭证替代 | 已有 Mock/单元 26/26、真实 issuer 签发/调用/刷新/停用/重启 E2E | 真实企业 IdP、MFA/ACR、Docker、Windows 计划任务、SCIM | 保留旧 Key 迁移窗口；回退 auth 镜像和配置，但不得恢复已泄露 Key |
| M2-A/M2-B 管理身份与只读治理 | M1、独立管理 OIDC Client | 管理登录、会话、CSRF、IP、RBAC、组织范围、只读用户/设备/凭证/模型/用量 | 管理员按组织子树查看，跨部门读取被拒绝 | 已有管理 Mock 回归覆盖会话、范围、脱敏、损坏和超限用量 | 真实管理 IdP、浏览器、代理、真实用量卷 | 回退管理服务，保留只读数据副本；撤销新增管理会话和角色 |
| M2-C1/C2/C3 敏感写与管理审计 | M2-A/B、独立内部服务令牌 | 停用/启用、吊销、轮换；管理写 API；幂等、`operationId`、intent/result 审计 | 管理员可安全执行已有四个写操作且失败不伪造成功 | 已有管理 109/109、auth 26/26 中的内部写、权限、审批、幂等、审计失败和脱敏证据 | 真实 IdP/代理/网关、浏览器 E2E、失败恢复入口和生产验收 | 回退服务并停止写入口；保留 operation 和审计证据用于对账 |
| C4-01/C4-02/C4-03a/C4-03b 策略底座 | M2-C、模型目录、共享卷设计 | schema v1 机器协议、受控适配器、正式目录、用户级策略核心 | 管理端具备可回读、可原子写入、可版本化的策略基础 | 已有 C4-01 Go/CLI/隔离二进制证据、C4-02 15 项 Mock/故障测试、C4-03a 管理 109/109、C4-03b auth 26/26 | Docker/真实共享卷、只读挂载、digest 重启、auth-service 接入、管理端编排 | 保留上一镜像与目录版本；撤销未确认策略，不恢复已撤销凭证 |
| C4-03c 管理 API、签发同步与交付 | C4-02/C4-03a/C4-03b、C3 | `PUT quota`、`PATCH models`、issuance journal、apply、独立回读、原子持久化、同步后交付、孤儿补偿 | 管理员调额/模型授权可落到真实 Magpie 网关，未同步成功不交付新 Key | 已有管理 109/109、auth 26/26 和 gateway-control 15/15 的 Mock/故障证据，覆盖 payload 绑定幂等、部分成功、失败补偿和启动恢复；C4-04 已用隔离真实 Magpie 覆盖 apply/readback、多凭证部分失败和故障恢复 | 真实 Docker/共享卷、真实企业 IdP、生产反向代理和真实生产故障演练未验收 | journal 恢复到 `issued`/`compensating`；撤销未提交 Key；保留 `pendingRevocations` |
| C4-03d 页面与运营状态 | C4-03c | 管理页/员工页同步状态、失败设备、首次设置、待对账入口 | 管理员和员工看到真实 `unknown/pending/partial_success/dependency_invoked/succeeded` | 管理页已有额度/模型写表单、完整证据链状态和失败证据；员工页已有本人额度/模型/凭证/设备只读门户；M2-D 已接入 operation/audit 查询、人工对账、CSV 导出和基础停用/吊销/轮换页面 | 失败目标恢复入口、浏览器 E2E、完整运营体验和真实审计存储验收未完成 | 回退前端静态资源；保留后端状态和 operation，不篡改审计 |
| C4-04 真实网关行为 E2E | C4-03a-d | 隔离真实 Magpie 的额度、模型拒绝、多凭证、refresh/rotate、部分失败和故障注入 | 证明不是只改页面，真实请求确实被限额和拒绝 | 已有 `admin-service -> auth-service -> gateway-control -> Magpie -> Mock 上游` 18 阶段 E2E：首次 join 409、管理 OIDC/CSRF、分步策略设置、双设备 Key、真实限额/模型拒绝、`partial_success`、refresh/rotate 继承、故障后 pending、Journal/孤儿 Key 撤销、恢复同步、usage 归属和秘密扫描 | Docker/共享卷、真实企业 IdP、反向代理、浏览器自动化、M2-D/C5 生产验收未完成 | 终止隔离进程、删除临时目录；不触碰生产配置和真实 Key |
| C5 操作、审计查询与对账 | C4-03c/C4-03d/C4-04 | `operations/{id}`、`audit-logs`、过滤分页、人工确认/重试/补偿子 operation | 管理员可追溯失败、部分成功和依赖结果，完成人工对账 | 已有 operation/audit/reconcile Mock/故障测试和 M2-D 基础页面：权限、组织范围、签名 cursor、脱敏、幂等/冲突、旧快照、依赖/审计失败、父子 operation 和原审计不可改写 | 真实审计存储、浏览器 E2E 和生产运维演练未验收 | 保留原 operation 和审计，新增补偿 operation；不覆盖历史结果 |
| M2-E 审批、step-up 与通知投递 | C3/C5、真实管理 IdP、外部 OA/IM/SIEM | APR-01a-e、NOTIFY-01a-d、外部审批验签、一次性消费、break-glass、outbox 和死信 | 高风险操作有审批和 ACR，通知异步可靠且可运营 | 已有 APR-01a 审批风险/绑定/职责分离/一次性消费/启动恢复、APR-01b HMAC 回调验签/防重放/幂等、APR-01c 独立 step-up/ACR/auth_time/绑定/失败关闭、APR-01d 审批箱/串并行/quorum/转交/撤回、APR-01e 15 分钟单次授权/24 小时复核/提醒/通知、NOTIFY-01a outbox/租约/退避/死信/重启恢复、NOTIFY-01b 渠道管理/HTTPS 适配器/SSRF 防护、NOTIFY-01c SIEM transport/固定 L0 schema/dead-letters API，以及 NOTIFY-01d 规则/抑制/聚合/阈值与延迟升级/受审计重放/运营页的 Mock/故障证据；仍需真实 OA 连接器、真实 IdP/MFA、真实厂商渠道、真实 SIEM/Collector/Syslog/证书、5 分钟告警/工单 SLA 和 24 小时生产复核演练作为生产验收证据 | APR-01b 仅有 HMAC/Mock 适配器，真实 OA/飞书/ServiceNow/Jira 未接入；APR-01e 仅有 Mock/集成核心，真实告警/工单和外部工单 ID 回读未验收；NOTIFY-01d 已实现核心和运营页，真实 SIEM 接入、NOTIFY-01b 的真实厂商连接、浏览器审批流程和生产值班闭环未验收 | 关闭对应审批/通知功能；保留待消费审批、break-glass、outbox 和死信供人工处置 |
| M2-D 管理体验与员工门户 | C2-C5、M2-E、真实数据卷 | 管理写 UI、用量/成本看板、授权导出、操作历史和员工状态页 | 管理员可日常运营，员工可自助恢复，不暴露秘密 | 已有 109 项管理测试覆盖筛选/分页、operation、人工对账、审批箱/多步骤、break-glass、通知规则/聚合/抑制/升级、用量/审计查询、CSV 导出权限/审批/step-up/一次性下载/幂等/公式注入防护；页面 E2E、真实浏览器和导出生产验收未完成 | C4-03d 已部分交付额度/模型写表单和员工只读状态页；M2-D 核心已实现，浏览器 E2E、失败恢复入口、完整运营体验和大规模异步导出未验收 | 回退前端资源；保留导出审计和 operation，不丢弃已生成证据 |
| M3-M6 资源、审计、安全与规模化 | R2 生产候选全部通过 | 中央 MCP、资源库、客户端策略、L0-L3 审计、安全运营、PostgreSQL/HA/KMS/mTLS | 50-500+ 人可治理、可审计、可扩展和可恢复 | M3-A 已有 11 项、M3-B 已有 14 项、M3-C-1 相关 resource 已有 15 项、client-sync 已有 24 项单元/Mock 集成测试，M3-C-2 已有 5 项管理服务测试；M3-B 仍有单进程 nonce、注册表/审计事务和真实部署缺口；M3-C-2 只完成只读资源/漂移可见性，资源发布/回滚 UI、审批联动、本地 helper、目标 Agent 文件映射、Windows ACL、MDM、真实 IdP、浏览器 E2E 和 Docker/Compose 实机验收仍未完成；L0-L3 审计、安全运营、HA 和合规签字仍无证据 | M3-A/M3-B 尚未接入真实审批和可写管理台，M3-C-2 仍未接入发布/回滚和本地 helper 产品流；M3-D 与 M4-M6 未实现，不得引用本表作为上线证明 | 按阶段独立回退；资源回滚到已发布签名版本，MCP 注册表/审计/幂等迁移必须有逆向脚本和隔离恢复演练 |

## 1. 目标与边界

### 1.1 建设目标

把 Magpie 从“个人本地 AI 工具”升级为企业可治理的 AI 客户端与网关平台，同时保持与上游持续同步：

- 员工用一个客户端即可接入 Claude Code、Codex、OpenCode、VS Code 等本地 Agent。
- 企业的真实模型密钥、MCP 凭据和敏感配置不落到员工电脑。
- 管理员统一管理员工、部门、设备、模型、额度、MCP、资源库和客户端策略。
- 安全与审计人员可以按权限查看员工使用情况，必要时查看经脱敏的对话内容和工具调用。
- 所有企业功能优先做独立服务、插件和最小核心 hook，减少与上游代码的冲突。

### 1.2 核心原则

1. **身份先于权限**：额度、审计、资源分发都必须绑定到真实员工、部门和设备。
2. **默认最小可见**：默认只记录请求元数据；对话正文由企业策略显式开启。
3. **企业策略不可绕过**：模型出口、MCP 出口和资源版本由客户端托管配置加网络策略共同保证。
4. **中心管理、本地执行**：控制面负责配置和策略，员工电脑本地 Magpie 负责写入 Agent 配置。
5. **上游可持续合并**：企业代码放到独立目录或独立仓库，核心只接受少量、稳定、带开关的 hook。
6. **先满足 50-200 人**：不做过早分布式复杂化，超过规模阈值再升级存储和 HA。

### 1.3 非目标

- 不重写 Magpie 的模型路由和 Agent 适配核心。
- 不把企业控制面塞进 Magpie 单机 Web UI，避免多租户改造污染上游代码。
- 不默认保存所有员工原始对话；正文审计必须受企业策略、权限和留存规则约束。
- 不依赖“员工看不到按钮”作为安全边界；真正的边界是身份、签名配置、网络策略和服务端鉴权。

## 2. 当前基础与缺口

### 2.1 当前已具备

| 能力 | 当前状态 |
| --- | --- |
| 客户端与网关双角色 | 已可用，同一二进制、不同配置 |
| 每员工网关密钥 | 已可用，支持额度、模型白名单、只读、过期 |
| 请求归属 | `usage.jsonl` 可按 `callerKeyId/callerKeyName` 归属 |
| 用量查看 | 管理页面和 CLI 可按员工、Agent、模型、供应商查看 Token/费用 |
| Agent 一键接入 | 已可用，员工本地 Web 可配置 Agent |
| 企业 Provider 隔离 | 已可用，员工只看到企业分配的 Provider |
| IP 白名单 | 已可用，支持 CIDR |
| 隐私脱敏 | 已可用，可配置规则 |
| 客户端/服务端演示 | 已完成，支持员工、管理员、只读账号的端到端验证 |

### 2.2 当前缺口

| 企业需求 | 当前缺口 |
| --- | --- |
| OIDC/SSO、设备注册和短期凭证 | M1 已有本地实现；真实 IdP、容器和 Windows 计划任务尚待验收；SCIM 和完整组织架构未实现 |
| 管理后台多角色 RBAC | M2-A/M2-B 已有管理 OIDC、会话、CSRF、角色、组织范围和只读治理；M2-C1 已有 Auth 内部写接口；M2-C2 已有四个管理写 API、组织范围写校验和理由校验；M2-C3 已实现幂等重放、`operationId` 和 intent/result 管理审计；C4-03c/C4-03d 已部分交付调额/模型授权 API 和写表单；M2-C5 已提供查询/对账后端；完整运营查询/对账体验、失败恢复入口和运营看板未实现 |
| 员工、部门、设备总览 | M2-B 已提供用户、部门、设备、凭证、模型和用量只读视图及范围过滤；完整筛选、分页、导出和看板未实现 |
| 对话正文和工具调用审计 | 未实现；当前只有请求元数据 |
| 中央 MCP 目录和下发 | 未实现；当前 MCP 是每台电脑的本地 Library |
| 中央资源库 | 未实现；当前可手工用 Git/备份同步 |
| 策略强制和防绕过 | 未完整实现 |
| 高可用、共享存储、指标告警 | 未完整实现 |
| 离职自动吊销和密钥短命化 | 短期密钥和停用吊销已在 M1 服务中实现；SCIM 自动触发和全域吊销尚未验收 |

### 2.3 实现状态（必须和方案分开看）

截至 2026-11-02，仓库中的真实状态如下。不要把“方案已设计”误读为“功能已上线”。

| 阶段 | 代码状态 | 已通过的验证 | 尚未验证或未实现 |
| --- | --- | --- | --- |
| M0 企业网关基线 | 已落地在 `enterprise/`，未改上游跟踪文件 | 真实 Magpie 二进制的客户端 → 企业网关 → Mock 上游、模型调用、按员工 Key 归属用量 | 公司正式 TLS 入口、正式 OTLP/SIEM、MDM 分发 |
| M1 OIDC 与设备身份 | `enterprise/auth-service/`、加入/刷新脚本和真实 issuer E2E 脚本已实现；同设备刷新已串行化；M3-C-1 增加设备短期同步凭证和 OIDC `groups` 组织范围映射 | Node 单元/Mock 集成测试（26/26）、并发刷新和“签发中停用”回归、PowerShell 语法检查、M0 真实 Magpie 链路；真实 issuer E2E 的签发/调用/用量/刷新撤销/停用/重启全部通过 | 真实企业 IdP/groups claim、Docker 构建、Windows 计划任务实机刷新、SCIM |
| M2-A 管理身份底座 | `enterprise/admin-service/` 已实现独立管理 OIDC、MFA/ACR、会话、CSRF、IP 限制、RBAC、组织范围、内部服务令牌和最小管理页 | Node 语法检查、管理服务 Mock 集成测试（当前回归 109/109，包含 M2-B/M2-C2/M2-C3/M2-C5/M2-D、APR-01a/b/c/d、NOTIFY-01a/b/c/d、C4-03a 目录和 C4-03d 页面测试）、auth 服务 Mock 集成测试（26/26） | 真实 IdP、Docker/浏览器/反向代理、正式角色/组织初始化流程 |
| M2-B 只读治理 | 用户、部门、设备、凭证、模型和用量只读 API；显式用户-组织映射；只读 `usage.jsonl`；服务端子树过滤和管理页摘要 | 当前管理 `109/109`、auth `26/26`；覆盖跨部门 `403`、用户 `404`、凭证脱敏、用量归属、时间序列和损坏/超限存储 | 真实用量卷、真实 IdP、Docker/浏览器/代理、轮转和大文件验收 |
| M2-C1 Auth 内部写接口 | 停用/启用用户、设备吊销、当前凭证轮换；只接受独立内部服务令牌 | Auth Mock `26/26`：鉴权、目标校验、设备串行化、启用不恢复旧凭据、轮换失败无孤儿 Key、响应不返回秘密，并覆盖同步凭证签发边界 | C1 本身不接入管理会话/RBAC/CSRF/理由；对应管理入口由 C2 提供并由 Mock 覆盖；完整幂等/审计由 C2/C3 提供；真实 IdP、网关、浏览器 E2E 和生产验收未完成 |
| M2-C2 管理写 API | 四个管理写 API；管理会话/CSRF/RBAC/组织子树/理由校验；目标预检和响应白名单 | 管理 `109/109`；覆盖全域写、子树/兄弟部门、CSRF/理由/幂等键格式/坏 JSON/目标不存在/依赖故障和脱敏 | 真实 IdP/代理/网关、浏览器 E2E、失败恢复入口和生产验收 |
| M2-C3 幂等、操作状态与管理审计 | 持久化 `Idempotency-Key` 指纹、同键同请求重放、同键异体 `409`、执行中 `409`、`operationId`、intent/result 审计、审计失败阻断 | 管理 `109/109`；覆盖成功/失败重放、同键异体、并发执行中、intent 失败依赖调用为 0、result 审计失败不返回成功、operation 状态和审计脱敏 | 真实 IdP/代理/真实网关未验收；查询/对账接口由 C5 提供，页面已由 M2-D 接入 |
| M2-C4-01 网关机器协议 | 当前工作分支已实现 `describe --json` 和原子 `policy apply --json` | Go 单测、CLI 回归和隔离真实二进制冒烟；覆盖 schema v1、64 KiB 输入输出、冲突和回读 | `gateway-control` 调用超时、用户级策略和管理 API 不在此切片 |
| M2-C4-02 受控适配器 | `enterprise/gateway-control/` 已实现，固定调用 describe/apply、独立回读、服务令牌、64 KiB 和 10 秒超时 | Node 语法检查与 `15 passed, 0 failed`；覆盖鉴权、脱敏、注入式 ID、超时/存储故障 pending、确定性失败、子进程退出和输出超限；C4-04 已验证真实适配器调用链 | Docker/Compose、共享卷文件锁、真实企业 IdP 和独立适配器部署未验收 |
| M2-C4-03a 正式模型目录 | 只读 `ADMIN_MODEL_CATALOG_PATH`、严格 JSON、schema v1、稳定模型 ID、显式 Provider 通配符、group 展开、2 MiB 上限、SHA-256 digest 和安全状态摘要 | 管理 `109/109`（82 项管理服务集成 + 7 项目录专项 + 7 项通知渠道专项 + 7 项通知规则专项 + 6 项 SIEM 专项）；`GET /api/v1/admin/models` 已使用正式目录，admin-service 把选择器展开为稳定模型 ID | 真实 Docker/共享卷、真实 IdP、浏览器和反向代理未验收 |
| M2-C4-03b 用户级策略核心 | auth-service 的版本化 `gatewayPolicy`、0-5 个额度窗口、旧 M1 `unknown` 迁移、quota/models 分步首次设置、版本冲突、失败关闭和凭证回读确认 | auth-service `26/26`；C4-04 管理链路验证首次设置、双设备回读、refresh/rotate 继承和失败关闭 | 真实部署验收未完成 |
| M2-C4-03c 管理 API、签发同步与交付 | 管理端额度/模型 API、issuance journal、自动 apply/readback、同步后交付、失败补偿和启动恢复 | 核心已实现；管理 109/109、auth 26/26、gateway-control 15/15 Mock/故障测试通过；C4-04 已通过隔离真实 Magpie 的 apply/readback、多凭证部分失败和故障恢复 | 真实 Docker/共享卷、真实企业 IdP、生产反向代理和生产故障演练 |
| M2-C4-04 完整策略流 E2E | 管理 OIDC/CSRF、quota/models 分步设置、双设备独立 Key、真实模型拒绝/限额、部分失败、refresh/rotate 继承、故障后 pending、Journal/孤儿 Key 撤销、恢复同步和 usage 归属 | 18 阶段 E2E 全部通过；真实 `admin-service -> auth-service -> gateway-control -> Magpie -> Mock 上游` 链路、秘密扫描通过 | Docker/共享卷、真实企业 IdP、反向代理、浏览器自动化、C5/M2-D 的浏览器 E2E 和生产验收 |
| M2-C4-03d 页面与运营状态 | 管理页/员工页同步状态、失败恢复入口和对账入口 | C4-03d 部分实现：管理页额度/模型写表单、完整证据链状态和员工只读状态门户已通过 Node 页面/API 测试；M2-D 已接入 operation/audit 查询和人工对账基础页面 | 浏览器 E2E、失败目标恢复入口和完整运营体验 |
| M2-C5 操作/审计查询与对账 | operation 详情、脱敏审计分页、签名 cursor 和四种人工对账动作 | 后端已实现并通过 Mock/故障测试；覆盖权限、组织范围、过滤分页、消费绑定、脱敏、幂等/冲突、旧快照、依赖/审计失败、父子 operation 和原审计不可改写；M2-D 已接入基础查询/对账页面 | 真实审计存储、生产 IdP/代理、完整运营查询/对账体验和人工运维演练未验收 |
| M2-D 看板与运营 | 用量/审计查询与 cursor 分页、operation 列表/详情、受控人工对账、审批箱/串并行多步骤、用量/审计 CSV 授权导出、员工只读状态页和通知运营页 | 管理 `109/109`；覆盖 RBAC/组织范围、审批绑定、审批箱、serial/parallel、quorum、转交/撤回、fresh step-up、CSRF、理由、幂等、一次性 Bearer token、会话 Cookie 绑定、query-string token 拒绝、下载后消费/过期、CSV BOM/CRLF、公式注入防护、字段/记录/字节上限、L0 脱敏和通知规则/抑制/聚合/升级/死信运营契约 | 失败目标恢复入口、完整运营体验、对象存储、异步大批量导出、Excel、分布式锁、浏览器 E2E、真实 IdP/OA/SIEM、生产负载和留存/删除策略 |
| M3 中央 MCP/资源库 | M3-A 资源目录/签名、M3-B 远程 MCP、M3-C-1 同步控制面和 M3-C-2 只读管理可见性已实现 | resource `15/15`（11 核心 + 4 控制面）、mcp-gateway `14/14`、client-sync `24/24`（16 核心 + 8 传输）、admin 新增 5 项 M3-C-2 测试；资源发布/回滚 UI、审批联动、M3-B MCP 管理台、本地 helper、Agent 文件映射、真实 IdP、浏览器 E2E 和 Docker/Compose 实机待完成 | 本地 MCP/M3-D、可写管理 UI、生产验收、灰度/自动回滚 |
| M4 会话审计 | 方案；当前只有元数据用量 | M0 用法归属 | 正文采集、流式拼接、脱敏、检索、留存 |
| M5 安全运营 | 方案 | 无 | 告警、阻断、SIEM、值班闭环 |
| M6 规模化 | 方案 | 无 | PostgreSQL/HA、KMS、mTLS、容量压测 |

## 3. 总体架构

```text
                          ┌──────────────────────────────┐
                          │ 企业 IdP / OIDC / SCIM       │
                          └──────────────┬───────────────┘
                                         │ 登录、组织、离职
┌────────────────────────────┐  HTTPS   ┌▼─────────────────────────────┐
│ 员工电脑                    │ ────────▶│ 企业控制面                    │
│                            │          │ Auth / Admin / Policy         │
│ Agent                      │          │ Resource / Device             │
│   │                        │          └──────┬───────────────┬───────┘
│   ▼                        │                 │               │
│ 本地 Magpie Client         │          ┌──────▼──────┐  ┌─────▼────────┐
│ 本地网关 / 配置 Agent      │          │ PostgreSQL  │  │ 对象存储      │
│ 资源缓存 / 设备心跳        │          │ 控制面数据   │  │ 资源/审计正文 │
│   │                        │          └─────────────┘  └──────────────┘
│   │ 短期凭证               │
└───┼────────────────────────┘
    │
    ▼
┌────────────────────────────┐
│ 企业 AI 数据面              │
│ Model Gateway / MCP Gateway │
│ 鉴权、策略、脱敏、审计       │
└──────┬───────────┬─────────┘
       │           │
       ▼           ▼
  模型供应商     企业 MCP Server
```

### 3.1 组件职责

| 组件 | 职责 |
| --- | --- |
| `enterprise-auth` | OIDC 登录、设备注册、短期网关凭证签发、续期、吊销 |
| `enterprise-admin` | 管理员控制台、员工/部门/设备/策略/资源/审计管理 |
| `enterprise-policy` | 组织策略、模型白名单、MCP 权限、资源分配、客户端锁定 |
| `enterprise-resource` | MCP、Skills、Instructions、Subagents、模板的中央目录和版本 |
| Magpie Enterprise Gateway | 模型与 MCP 的统一数据面，负责鉴权、额度、路由和审计 hook |
| `enterprise-audit` | 元数据和内容审计、脱敏、留存、检索、导出、访问审计 |
| 员工本地 Magpie | Agent 一键配置、本地网关、资源缓存、策略执行、设备心跳 |
| PostgreSQL | 用户、组织、设备、角色、策略、资源版本、密钥元数据 |
| 对象存储 | 大型资源包、附件、可选审计正文、导出文件 |
| Redis（可选） | 会话、短时缓存、分布式限流 |
| OTel / SIEM | 指标、日志、告警、安全事件 |

## 4. 角色与权限

### 4.1 角色

| 角色 | 范围 | 主要能力 |
| --- | --- | --- |
| 员工 | 本人 | 配置本机 Agent、使用授权模型/MCP、看本人用量 |
| 部门管理员 | 指定部门 | 管理部门成员、额度、模型、资源和部门报表 |
| 企业管理员 | 全企业 | 管理全域策略、用户、模型、资源和客户端版本 |
| 审计员 | 指定范围只读 | 查询、导出受权范围内的请求和会话审计 |
| 安全管理员 | 全企业安全策略 | 规则、阻断、告警、密钥吊销、设备合规 |
| 运维管理员 | 基础设施 | 网关、存储、监控、备份和升级，不默认查看正文 |
| 超级管理员 | 全企业 | 角色授权和紧急操作，不默认拥有正文查看权 |

### 4.2 权限原则

- 权限由“角色 + 组织范围 + 资源范围 + 时间范围”共同决定。
- 查看对话正文必须单独授权，不随普通管理员权限自动获得。
- 查看正文、导出、删除、修改留存策略等敏感动作必须写管理员审计日志。
- 超级管理员不能单独关闭自己的审计记录。
- 只读审计员不能修改额度、密钥、资源或策略。
- 管理 API 与服务 API 使用不同认证受众和不同密钥。

## 5. 关键业务流程

### 5.1 员工首次加入

1. IT 通过 MDM 安装企业 Magpie Client。
2. 客户端生成设备标识和密钥对，向控制面注册设备。
3. 员工通过浏览器进入企业 OIDC 登录。
4. 控制面校验用户、部门、设备合规和授权策略。
5. 服务端签发 1-8 小时短期网关凭证和资源同步凭证。
6. 客户端拉取组织配置：企业网关地址、模型目录、MCP 目录、强制资源、更新策略。
7. 客户端写入本地 Provider；员工在本地页面选择 Agent 和模型。
8. 客户端完成自检，状态上报控制面，员工开始使用。

### 5.2 员工日常使用

1. 员工打开本地 Magpie。
2. 客户端自动续期短期凭证并获取最新策略版本。
3. 员工在 `Agents` 页面选择 Agent、模型并开启接入。
4. Agent 请求发给本地 Magpie。
5. 本地 Magpie 附带设备身份和短期凭证转发到企业网关。
6. 企业网关执行身份、IP、设备、模型、额度、内容策略检查。
7. 请求转发到允许的模型或企业 MCP。
8. 网关记录元数据；若策略要求，再记录经脱敏的会话内容。
9. 员工只能看到本人的授权资源、用量和本地接入状态。

### 5.3 管理员发布模型或路由

1. 管理员创建模型目录和路由规则。
2. 选择适用部门、员工组和客户端策略。
3. 先发布到测试组，观察成功率、成本和安全告警。
4. 审批后全量发布，客户端在下次同步时刷新模型目录。
5. 管理员可按版本回滚，客户端保留上一版本直到新版本验证通过。

### 5.4 管理员发布 MCP

远程 MCP：

1. 管理员登记 MCP Server 的地址、认证方式、工具清单和允许范围。
2. 网关代理 MCP 请求并执行 OIDC/服务凭证鉴权。
3. 客户端只拿到网关注册的 MCP 地址，不直接持有上游 MCP 凭据。
4. 管理员按部门、角色、Agent 和工具授权。

本地 MCP：

1. 管理员将经过签名和测试的 MCP 包放入企业资源库。
2. 客户端按操作系统拉取包并校验签名和哈希。
3. 必需项自动安装，推荐项由员工启停，禁止项不展示。
4. 启动命令、环境变量、网络权限和文件权限由策略下发。
5. 客户端上报安装版本、运行状态和健康检查结果。

### 5.5 管理员发布 Skills、Instructions 和 Subagents

1. 上传或从 Git 仓库导入资源。
2. 资源进入草稿、测试、审批、发布、归档生命周期。
3. 发布时生成签名清单和版本号。
4. 客户端按角色同步，并把资源写成对应 Agent 的格式。
5. 客户端报告成功、失败、冲突和漂移。
6. 资源更新失败时保留上一个可用版本。

### 5.6 审计人员查看会话

1. 审计员按员工、部门、时间、Agent、模型、会话 ID 或关键词检索。
2. 系统先返回元数据列表。
3. 查看正文前执行权限检查、目的确认和二次确认。
4. 服务端返回经脱敏的正文和工具调用，不返回原始秘密。
5. 本次查看写入管理员审计日志。
6. 导出需要单独权限，并生成水印、审计编号和过期下载链接。

### 5.7 员工离职或设备丢失

1. IdP/SCIM 发出离职或停用事件。
2. 控制面立即停用用户、设备和刷新令牌。
3. 网关短期凭证在最大有效期内失效。
4. 管理员可立即吊销全部现存网关凭证。
5. 已缓存资源在下次联网时被清理或锁定。
6. 审计记录按留存策略保留，但普通管理员不能继续访问。

### 5.8 网页、本地 Magpie 与 Agent 的边界

这是产品设计中最容易被误解的一点：**网页不能直接修改员工电脑上的 Agent 配置文件**。

浏览器的安全沙箱不允许网页任意读取或写入本机文件，也不允许网页无提示地修改
`~/.claude`、`~/.codex`、VS Code 配置或其他本地 Agent 配置。因此不能把“纯网页登录”
宣传成“纯网页完成本地 Agent 配置”。

正确的能力分层是：

| 层次 | 能做什么 | 不能做什么 |
| --- | --- | --- |
| 企业网页 | OIDC 登录、查看授权、设备状态、用量、资源说明、管理员审批 | 直接改本机 Agent 文件；直接持有厂商 Key |
| 本地 Magpie | 接收网页签发的一次性加入码、写入 Provider、调用原生一键配置 Agent、刷新短期 Key | 代替 IdP 做身份认证；绕过企业网关 |
| 企业控制面 | 身份、策略、设备、额度、资源版本、吊销 | 依赖“员工看不到按钮”阻止绕过 |
| 企业网关/网络 | 校验短期凭证、模型/MCP 白名单、IP、额度、审计和阻断 | 依赖员工机上的静态长期密钥 |

因此推荐两种上线方式：

1. **标准方式（推荐）**：企业通过 MDM 安装 Magpie，员工从企业网页登录后运行
   `join-enterprise.ps1`；脚本启动 loopback 回调，领取一次性加入码，注册设备，并把短期
   Key 写入本地 Magpie。员工随后在本地 Magpie 页面一键配置 Agent。
2. **纯网页方式**：网页只负责身份登录、授权说明、下载安装包、复制加入命令或发起受控的
   深链。真正的 Provider/Agent 修改仍由本地 Magpie 或企业安装器完成。

如果未来要做“浏览器点击即完成本机配置”，必须额外提供一个经签名的本地 helper/URI
scheme，并由操作系统、MDM 和浏览器权限共同约束；不应通过降低浏览器安全策略实现。

### 5.9 管理员的日常闭环

管理员不是只看一个仪表盘，而是完成以下闭环：

1. **人员**：从 IdP/SCIM 同步或手工邀请员工，分配部门、角色和资源范围。
2. **设备**：查看注册设备、客户端版本、合规状态、最后心跳和资源漂移。
3. **凭证**：查看短期凭证的持有人、设备、模型范围、额度和到期时间；离职、挂失或异常时吊销。
4. **模型**：发布模型目录、路由、回退和部门白名单；先灰度测试组，再全量。
5. **MCP/资源**：登记、审批、签名、分配、灰度、回滚，并查看员工端安装结果。
6. **用量**：按人、部门、Agent、模型、项目和 MCP 工具核对 Token 与成本。
7. **审计**：默认看元数据；查看正文必须二次授权并留下管理员审计记录。
8. **安全事件**：接收告警，执行限流、阻断、吊销和工单闭环。
9. **高风险操作**：按风险等级完成理由、重新认证、审批或双人复核；审批绑定具体动作、
   目标和 payload，执行前重新校验并一次性消费。

### 5.10 员工首次使用的最短路径

目标体验是 5 分钟内完成，而不是要求员工理解 Provider、Base URL 或 Key：

```text
IT/MDM 安装企业 Magpie
  -> 员工打开企业入口，完成 OIDC
  -> 本地 Magpie 领取一次性加入码并注册设备
  -> 自动写入企业 Gateway Provider
  -> 员工在本地页面选择 Agent 和模型
  -> 自检通过，开始使用
```

这条路依赖一个已安装的本地 Magpie。若企业只允许网页、不安装任何本地组件，则只能做到
“登录、查看和下载”，不能安全地完成本地 Agent 一键配置；这是浏览器安全模型的硬边界。

### 5.11 高风险操作、二次认证与审批

审批不是“表单里传一个 `approvalId`”，而是一条可验证、可消费、可审计的控制链：

```text
管理员发起动作
  -> 服务端计算动作/目标/规范化 payload 指纹
  -> 按风险要求 step-up（MFA/ACR）和/或企业审批
  -> 审批人确认同一组织、同一动作、同一目标、同一 payload
  -> 写 intent 审计并原子预留审批
  -> 执行依赖
  -> 写 result 审计并关闭 operation
  -> 审批标记 consumed，不能再次使用
```

强制规则：

- 审批记录必须在服务端创建或从受信外部审批系统同步，不能信任浏览器提交的任意字符串。
- 申请人不能审批自己的请求；高风险管理动作至少需要一人申请、另一人批准。
- payload、目标、动作、组织范围或风险等级任一变化，原审批立即失效。
- 审批有明确过期时间、单次使用和撤销状态；消费必须原子化，重复使用返回稳定错误。
- 高风险操作默认“审批 + 理由 + 幂等键 + `operationId`”；关键操作还必须完成 step-up。
- 紧急 break-glass 必须短时有效、标红、单独告警，并在规定时限内完成事后复核。
- 外部审批服务不可用时高风险操作失败关闭；只有显式 break-glass 流程可以例外。

## 6. 功能清单

### 6.1 身份、组织与设备

#### 6.1 功能

- OIDC Authorization Code + PKCE 登录。
- 支持 Azure AD/Entra、Okta、Keycloak、企业微信/钉钉身份代理或自建 IdP。
- SCIM 或 IdP Webhook 同步人员、部门、组、入离职状态。
- 用户、部门、用户组、岗位和项目组管理。
- 设备注册、设备证书、客户端版本、操作系统、最后在线时间。
- 设备合规状态：是否安装企业客户端、是否启用磁盘加密、是否安装 EDR、是否越狱/Root。
- 账号与设备解绑、挂失、远程吊销。
- 短期网关凭证：建议 1-8 小时，支持自动续期和立即吊销。

#### 管理字段

| 对象 | 主要字段 |
| --- | --- |
| 用户 | 企业 ID、姓名、邮箱、部门、角色、状态、最后登录 |
| 部门 | 名称、上级部门、管理员、模型/MCP 策略 |
| 用户组 | 动态规则或手工成员、资源范围 |
| 设备 | 设备 ID、公钥、系统、版本、合规状态、最后心跳 |
| 凭证 | 所属用户/设备、模型范围、额度、过期时间、吊销状态 |

### 6.2 员工本地门户

#### 页面

- `首页`：连接状态、企业身份、设备状态、策略更新时间、快捷连接 Agent。
- `Agents`：检测本地 Agent、模型选择、连接/断开、重启提示。
- `我的资源`：已分配 MCP、Skills、Instructions、Subagents 和模板。
- `模型`：企业授权模型、能力和额度说明。
- `用量`：本人调用量、Token、费用、剩余额度。
- `设备与安全`：设备状态、最近登录、吊销提示、客户端版本。
- `帮助`：企业支持入口、隐私说明、常见问题和重新同步。

#### 约束

- 员工只能看到本人范围内的资源和用量。
- 强制资源有锁定标识，不能删除或关闭。
- 推荐资源可以启停，但不能改变其来源和版本。
- 禁止资源不显示，也不能通过本地页面添加。
- 员工不能看到供应商真实密钥、其他员工数据和全公司报表。
- 生产版应通过托管配置锁住企业 Gateway 和企业资源来源。

### 6.3 管理员控制台

#### 信息架构

| 页面 | 内容 |
| --- | --- |
| `总览` | 在线员工、请求量、错误率、费用、超额、未合规设备、告警 |
| `员工与组织` | 用户、部门、用户组、角色、入离职、设备绑定 |
| `设备` | 客户端版本、在线状态、合规状态、资源版本、最后活动 |
| `网关与凭证` | 员工凭证、额度、模型白名单、只读、吊销、轮换 |
| `模型与路由` | Provider、模型目录、路由组、回退、成本策略 |
| `MCP` | MCP 目录、远程/本地类型、工具权限、健康检查、分配 |
| `资源库` | Skills、Instructions、Subagents、模板、版本、审批、回滚 |
| `策略` | 模型/MCP/工具白名单、强制资源、客户端限制、网络策略 |
| `用量与成本` | 人、部门、Agent、模型、MCP、项目和时间维度报表 |
| `会话审计` | 元数据、正文、工具调用、检索、导出、留存和合法保留 |
| `安全告警` | 敏感信息、异常用量、异地、越权、直连和高风险工具 |
| `审计日志` | 谁查看了谁、谁导出了什么、谁修改了策略 |
| `系统设置` | IdP、SIEM、邮件、Webhook、留存、品牌和版本 |

#### 核心交互

- 所有列表支持按部门、用户、时间、Agent、模型、状态和策略筛选。
- 批量操作支持分配资源、调整额度、吊销凭证和调整策略。
- 高风险操作要求影响预览、二次确认和操作理由。
- 删除操作优先软删除，并保留审计和恢复窗口。
- 报表支持 CSV/Excel 导出；大报表走异步任务和一次性下载链接。
- 所有配置修改需要记录 before/after、操作人和请求 ID。

### 6.4 企业模型网关

#### 6.4 功能

- 每员工/每设备凭证，支持模型、额度和有效期限制。
- 部门、员工、Agent、模型和时间维度的配额。
- API 入口同时支持 OpenAI Chat Completions、Responses 和 Anthropic Messages。
- Provider 密钥只在服务端密钥库或 KMS 中。
- 模型白名单、路由、故障回退、灰度模型和禁用模型。
- 请求体大小、并发、速率、超时和输出长度限制。
- 按请求记录使用元数据，不默认记录正文。
- 对敏感字段进行脱敏、阻断或告警。
- 统一请求 ID、会话 ID、Agent、设备、部门和项目标签。

#### 配额对象

| 维度 | 示例 |
| --- | --- |
| 员工 | 每日 100k Tokens / 5 美元 |
| 部门 | 每月 20M Tokens / 1000 美元 |
| 模型 | 某高价模型每日上限 |
| Agent | Claude Code 与 Codex 分别限流 |
| MCP 工具 | 某搜索工具每员工每小时 100 次 |

### 6.5 MCP 管理

#### MCP 目录

管理员可以登记：

- 名称、说明、图标、负责人、适用部门和资源组。
- 类型：Streamable HTTP、SSE、stdio、本地包。
- 地址或包坐标、版本、哈希和签名。
- 认证方式：平台短期凭证、OAuth、mTLS、服务账号。
- 工具清单、每个工具的读写属性、风险等级和权限。
- 网络出口、文件访问、允许的命令和参数限制。
- 健康检查、超时、重试和熔断策略。
- 允许使用的 Agent、部门和员工组。

#### 远程 MCP

优先推荐远程 MCP，因为：

- 凭据不进入员工电脑。
- 工具调用可以统一鉴权、限流和审计。
- 更新只需发布服务端。
- 可按员工和部门做工具级权限。

网关暴露统一地址，例如：

```text
https://ai-gateway.corp.example/mcp/{server-id}
```

网关在内部使用员工或服务身份换取 MCP 凭证，外部客户端看不到上游凭据。

#### 本地 MCP

本地 MCP 只用于必须访问本机文件、桌面或内网环境的能力：

- 资源包必须签名，并带 SHA-256 和发布者信息。
- 客户端按策略安装，不能执行未签名包。
- 进程以最低权限运行，限制工作目录、文件系统、网络和环境变量。
- 敏感环境变量通过短期 Secret 注入，不放进资源包。
- 客户端上报版本、进程状态、健康检查、异常退出和工具调用摘要。
- 本地 MCP 的风险高于远程 MCP，默认只对受控用户组开放。

#### MCP 工具权限

- 工具级 allow/deny，不把整个 MCP Server 一刀切。
- 文件类工具区分只读、写入、执行和删除。
- 外部网络工具按域名白名单和请求大小限制。
- 高风险工具需要二次确认、审批或只允许在指定项目使用。
- 每次调用记录员工、设备、Agent、MCP、工具、状态、耗时、参数摘要和返回字节数。
- 默认不记录完整参数和完整返回值；可按策略开启脱敏后的正文审计。

### 6.6 企业资源库

#### 资源类型

- Instructions / 提示词基线。
- Skills / 技能包及其文件。
- Subagents / 子代理定义。
- MCP Server 定义。
- 项目模板、代码规范、常用命令和安全规则。
- Agent 配置模板和企业 Provider 预设。

#### 资源范围

- 全公司。
- 部门。
- 用户组。
- 项目组。
- 指定员工。
- 指定设备或设备组。

#### 生命周期

```text
草稿 -> 测试 -> 审批 -> 发布 -> 灰度 -> 全量 -> 归档
                              \-> 回滚
```

#### 版本与同步

- 每个资源版本不可变，发布生成签名 manifest。
- 客户端显示当前版本、期望版本、同步状态和错误。
- 客户端离线时使用最后一个已验证版本。
- 新版本同步失败自动回退到上一可用版本。
- 管理员可以查看每个员工/设备的安装版本和漂移情况。
- 强制资源由客户端策略锁定；推荐资源允许员工启停。
- 冲突时保留员工原有配置，并给出可操作的错误，不静默覆盖。

#### 秘密管理

- 资源包不包含真实密钥。
- 在资源定义中使用 Secret Reference。
- 客户端向控制面换取短期 Secret；能在网关侧代理的能力不向客户端下发凭据。
- 管理员只能看到 Secret 元数据，不能查看明文。
- Secret 轮换不要求重新发布资源版本。

#### 6.6.1 中央 MCP 与资源发布的控制面/数据面分离

管理员可以集中调控全公司 MCP，但必须把“目录和授权”与“工具实际调用”分开：

```text
管理台/资源库
  -> 创建 MCP 草稿、工具清单、风险等级、适用范围
  -> 审批并生成不可变 release manifest
  -> 控制面向客户端发布期望版本

员工本地 Magpie
  -> 拉取 manifest，校验签名、哈希、版本和适用范围
  -> 只把允许的 MCP 名称、地址和工具暴露给 Agent
  -> 上报期望版本、实际版本、健康状态和漂移

企业 MCP Gateway（远程 MCP）
  -> 验证员工、设备、Agent、MCP、工具和额度
  -> 使用服务端持有的上游凭据调用 MCP Server
  -> 记录 L0 元数据、工具结果状态和策略命中
```

远程 MCP 的上游凭据、OAuth refresh token 和私钥只保存在 Secret Manager 或 MCP Gateway，
不进入资源包、客户端配置、管理页面、日志和审计。管理员只能选择或引用 Secret，不能读取
明文。本地 MCP 默认只对受控用户组开放，必须经过发布者签名、哈希校验和隔离测试。

#### 6.6.2 发布、灰度和回滚协议

每次发布使用不可变 manifest，至少包含：

```json
{
  "schemaVersion": 1,
  "resourceId": "res_...",
  "releaseId": "rel_...",
  "version": "2026.11.1",
  "kind": "mcp|skill|instructions|subagent|template",
  "hash": "sha256:...",
  "signature": "base64:...",
  "publisher": "enterprise-platform",
  "compatibility": {"minClientVersion": "..."},
  "assignments": ["org_unit_id", "group_id", "user_id"],
  "rollout": {"strategy": "canary", "percent": 5, "stopOnErrorRate": 0.02},
  "previousReleaseId": "rel_..."
}
```

发布顺序固定为：草稿 -> 自动校验 -> 隔离测试 -> 审批 -> 灰度 -> 全量 -> 归档。灰度必须能
按部门、用户组、员工或设备比例控制；客户端拉取后先校验签名和哈希，再安装到临时目录，
自检通过才切换“当前版本”。新版本失败、策略不兼容或客户端版本过低时回退到
`previousReleaseId`，同时上报告警和管理审计。管理员看到的是期望版本与实际版本，不允许
只在控制台改一个“已发布”字段而没有客户端证据。

发布、回滚、修改适用范围和强制/推荐属性都必须写管理审计 intent/result。资源删除采用归档，
不能删除已被引用的不可变版本；合法删除必须有保留期、影响预览和审批。

### 6.7 客户端策略与防绕过

#### 必须实现的客户端策略

- 企业 Gateway 地址不可删除。
- 企业 Provider 不可编辑密钥。
- 禁止添加非企业 Provider。
- 禁止直接连接模型厂商或未授权 MCP 地址。
- 强制 MCP、Skills、Instructions 不可关闭。
- 只允许安装签名客户端和签名资源。
- 客户端版本低于最低版本时禁止使用模型。
- 策略版本过期或设备不合规时降级为只读或拒绝请求。

#### 真正的防绕过

客户端 UI 锁定只是第一层，生产必须同时使用：

- 企业 DNS 和防火墙只允许访问企业网关。
- 终端 EDR/MDM 检查企业客户端是否运行。
- 网关只接受企业设备证书或短期设备凭证。
- 模型厂商的出口密钥只在网关侧持有。
- 对员工电脑禁止保存厂商长期 Key。
- 发现未经过网关的敏感目标流量时告警或阻断。

### 6.8 用量、成本与报表

#### 记录维度

- 企业用户、部门、用户组、项目。
- 设备和客户端版本。
- Agent、模型、Provider、路由组。
- 请求类型、状态、错误码、延迟。
- 输入、输出、缓存、推理 Token。
- 成本、币种、价格版本。
- MCP Server、Tool 和调用结果。

#### 报表

- 实时今日看板。
- 日/周/月用量趋势。
- 部门成本排行和预算消耗。
- 员工异常用量。
- 模型和 Agent 使用分布。
- 失败率、超时和供应商可用性。
- 定时 CSV/Excel/PDF 报表和邮件摘要。

### 6.9 会话与工具调用审计

#### 审计等级

| 等级 | 内容 | 适用 |
| --- | --- | --- |
| L0 元数据 | 人、时间、Agent、模型、状态、Token、费用、IP、设备 | 默认 |
| L1 摘要 | 请求摘要、工具名、参数类别、结果状态 | 安全运营 |
| L2 脱敏正文 | 经规则脱敏的提示词、回复、工具参数和结果 | 经批准的合规场景 |
| L3 原始正文 | 未脱敏内容 | 原则上不启用；仅法定调查并严格审批 |

#### 采集原则

- 在网关统一采集，不依赖员工本地客户端主动上传。
- 流式回复需要完整拼接后才能形成可检索记录。
- 二进制、图片、附件默认只记录元数据和哈希，正文另行授权。
- 敏感字段先脱敏再落盘。
- 审计服务和网关数据面隔离，网关只异步发送事件。
- 采集失败不能阻断正常请求，除非企业明确启用“无审计即拒绝”模式。

#### 检索

- 员工、部门、设备、Agent、模型。
- 时间范围、会话 ID、请求 ID。
- 工具名、错误码、策略命中。
- 关键词和语义检索需单独授权。
- 审计员只能搜索授权部门，跨部门需要临时授权。

#### 留存

- 按数据类型和企业策略配置保留期。
- 支持删除请求、法律保留和导出。
- 正文删除后保留不可逆哈希和元数据。
- 审计日志与正文分开存储和分权。
- 对象存储启用服务端加密和版本控制，必要时使用 WORM。

#### 6.9.1 审计事件最小 schema

L0/L1 事件必须可在不读取正文的情况下完成归属、成本、错误和安全分析：

```json
{
  "schemaVersion": 1,
  "eventId": "evt_...",
  "requestId": "req_...",
  "sessionId": "ses_...",
  "occurredAt": "2026-11-01T08:00:00Z",
  "userId": "usr_...",
  "departmentId": "org_...",
  "deviceId": "dev_...",
  "agentId": "codex",
  "clientVersion": "1.0.0",
  "modelId": "deepseek/deepseek-chat",
  "providerId": "provider_...",
  "mcpServerId": "mcp_...",
  "toolName": "search.read",
  "requestKind": "chat|responses|messages|mcp",
  "status": "success|blocked|error",
  "errorCode": "quota_exceeded",
  "inputTokens": 120,
  "outputTokens": 80,
  "cost": 0.01,
  "latencyMs": 840,
  "sourceIpHash": "...",
  "policyHits": ["secret.detected"],
  "contentRef": "optional://audit/content/..."
}
```

`contentRef` 只指向单独的加密正文对象；没有授权时只返回元数据，不返回对象地址或可猜测路径。
正文对象包含 `contentLevel`（L2/L3）、脱敏规则版本、hash、保留期和 access policy 版本。
事件管道必须幂等，重复投递不重复计费；失败可重试，队列积压和丢事件必须告警。

#### 6.9.2 对话查看与管理员访问

“管理员能看到员工对话”必须区分以下三种能力，不能合并宣传：

1. **元数据查看**：默认可用，展示请求次数、模型、Token、费用、状态、时间、设备和策略命中，
   不展示提示词或回复。
2. **受控摘要**：需要 `audit.read` 和策略允许，展示工具名、参数类别、结果状态，不展示正文。
3. **正文查看**：需要独立的 `audit.content.read`、二次确认、目的说明和可选审批；每次查看、
   下载和导出都产生一条不可删除的管理员访问审计。

审计员默认只能看 1/2；L2 正文必须单独授权；L3 原始正文默认禁用，只能在法定调查、双人
审批和短保留窗口内启用。管理员不能在普通搜索列表里看到正文片段；正文页面必须显示水印、
访问编号和自动过期时间。

### 6.10 安全检测与告警

#### 规则

- 员工短时间调用量或费用突增。
- 异地、异常 IP、多个设备并发。
- 使用禁用模型、禁用 MCP 或禁用工具。
- 多次越权、密钥错误、设备不合规。
- 检测到 API Key、密码、身份证、银行卡、私钥或代码仓库令牌。
- 大批量导出、异常文件访问、危险命令执行。
- 直连模型厂商或非企业 MCP 的尝试。
- 管理员大量查看或导出审计正文。

#### 响应

- 通知、限流、阻断、吊销凭证、锁定设备、要求重新认证。
- 告警发送到邮件、企业 IM、Webhook、SIEM 或工单系统。
- 每个告警包含请求 ID、员工、部门、设备、规则、策略和处置建议。
- 支持抑制、聚合和升级，避免告警风暴。
- 所有外部发送统一通过第 6.12.6 节的 outbox 和通知投递服务完成，不能在检测或业务请求
  中同步发送；投递失败、重试和死信必须可查询。

### 6.11 MDM、安装与更新

- Windows MSI/MSIX/EXE、macOS PKG、Linux deb/rpm。
- 由 Intune、Jamf、PDQ、域策略或公司软件中心统一安装。
- 安装后自动注册设备并进入“加入组织”流程。
- 客户端版本、最低版本和灰度通道由控制面管理。
- 更新包签名，更新源固定为企业地址。
- 没有网络时保留离线模式，策略过期后按企业规则降级。
- 提供卸载保护、配置恢复和用户数据清理流程。

### 6.12 审批、重新认证与通知投递

本节定义贯穿管理控制面、审计、资源发布和安全运营的统一审批与通知能力。**APR-01a**
的服务端审批、绑定校验、职责分离、组织范围、一次性消费和启动恢复已实现，并通过
Mock/故障测试；**APR-01b 的 HMAC-SHA256 外部审批回调适配器**也已实现并通过 Mock/
故障测试，包含时间窗、nonce 防重放、issuer/audience、eventId 幂等和系统审计。
**APR-01c 的独立 OIDC step-up 已实现并通过 Mock IdP 集成测试**，**NOTIFY-01a 的
transactional outbox、租约、幂等、退避、死信、重启恢复、deliveries 查询和人工重放已实现
并通过 Mock/故障测试**，**NOTIFY-01b 的渠道管理 API、渠道测试和统一 HTTPS 渠道适配器
已实现并通过 Mock/故障测试**，**NOTIFY-01c 的 SIEM transport、固定 L0 schema 和
dead-letters API 已实现并通过 6 项专项测试**。**APR-01d 的审批箱、串行/并行步骤、
显式 `stepId`、quorum、转交和撤回已交付；APR-01e 的 break-glass 15 分钟单次授权、
24 小时事后复核、提醒、通知、审计、API 和管理页已完成 Mock/集成核心；NOTIFY-01d 的
规则 CRUD、抑制窗口、聚合、阈值/延迟升级、dead-letter 受审计幂等重放和完整通知运营页
已完成 Mock/集成核心**。
邮件、IM 和工单当前是统一 HTTPS 网关契约，不是原生 SMTP、Graph、飞书、Teams、
ServiceNow 或 Jira SDK；真实厂商连接、真实 OA/管理 IdP、MFA/ACR、反向代理、浏览器审批
流程、真实 SIEM/Collector/Syslog/证书和生产验收均未完成，因此不能把本次交付描述为企业
审批/通知闭环或生产就绪。

#### 6.12.1 适用动作与风险等级

| 风险等级 | 典型动作 | 最低控制 |
| --- | --- | --- |
| L | 单人停用、吊销单个设备、查看本人数据 | 管理会话、RBAC、组织范围、理由、审计 |
| M | 单人调额/模型授权、轮换凭证、批量停用 2-20 人 | 理由、幂等、审计；按企业策略要求 step-up |
| H | 批量吊销 >20 人、修改角色、发布 MCP/Skills/Instructions、导出用量 | 审批 + 理由 + 幂等；默认要求 step-up |
| C | 查看/导出 L2/L3 正文、授予超级管理员、修改留存/法律保留、break-glass 吊销 | 双人审批或独立安全审批 + step-up + 短时有效 + 事后复核 |

风险等级必须由服务端策略根据动作、目标、批量大小、数据分级和组织范围计算。客户端可以
显示风险提示，但不能自行降低或覆盖服务端判定。

#### 6.12.2 审批模式

审批适配器支持三种模式，按企业现状启用：

1. **`external`（首期推荐）**：对接飞书审批、企业 OA、ServiceNow、Jira 或自建审批。
   magpie 只保存审批引用、申请人、审批人、状态、有效期和绑定摘要；审批通过回调必须是
   受信服务间调用或验签 Webhook，不能由浏览器直接伪造。
2. **`builtin`（后续）**：管理控制台内置审批箱和多步审批。适合没有统一 OA 的企业，但
   必须实现申请人/审批人职责分离、并行/串行步骤、拒绝、撤回、过期和转交。
3. **`step_up`（可与前两者组合）**：要求当前管理会话重新完成 OIDC MFA/ACR，服务端记录
   `authTime`、`acr`、`amr` 和验证时间。step-up 只证明“当前操作者仍是本人”，不能替代
   审批；审批也不能替代 step-up。

外部审批结果只更新 `approval_requests`，不能直接执行目标业务动作。真正执行前，管理服务
必须重新读取审批、比较绑定摘要、检查过期和撤销状态，再以原子操作消费。

#### 6.12.3 审批绑定与防重放

每个审批至少绑定以下字段：

```text
approvalId
organizationId
requesterSubjectId
action
targetType
targetId
resourceScope
riskLevel
normalizedPayloadSha256
policyVersion
requiredSteps
expiresAt
externalReference
nonce
```

要求：

- 规范化完成后计算 SHA-256；JSON 使用固定键序、固定数字/时间格式并拒绝重复键，不接受
  “薄雾式”等价 payload 绕过。
- 审批记录保存申请人、审批人、组织范围和角色快照；审批人必须处于有效状态且拥有匹配权限。
- 外部回调验证 issuer、audience、签名、时间戳、nonce 和重放缓存；默认允许时钟偏差不超过
  5 分钟。
- `approvalId` 不能跨环境、跨组织或跨动作复用；测试环境的审批不能在生产企业使用。
- 审批通过后只允许原 `operationId` 使用一次。依赖超时后的安全重试仍属于同一 operation，
  不重复消费；修改 payload 或创建新 operation 必须重新审批。
- 审批消费、operation 状态和 intent 审计至少要在同一持久化事务/文件锁中保持一致；生产
  数据库使用唯一约束和事务，JSON 试点使用锁、原子替换和启动恢复扫描。

审批域状态机：

```text
requested -> pending_approval -> approved / rejected / expired / revoked
approved -> reserved -> consumed
pending_approval/approved -> expired
approved/reserved -> revoked（尚未 consumed 时）
consumed -> execution_succeeded / execution_failed
```

同一 `operationId` 只允许一个消费成功；重复消费返回 `409 approval_consumed`。审批被撤销后
不得继续执行；已经执行的业务动作不能通过“撤销审批”回滚，必须走新的补偿 operation。

#### 6.12.4 重新认证（step-up）

- 管理登录和 step-up 使用独立 OIDC Client、PKCE、MFA/ACR 与 `max_age`；服务端只保存
  验证结果和时间，不保存 IdP access/refresh token。
- 默认 step-up 有效期 10 分钟；关键操作建议 5 分钟。过期后返回
  `403 step_up_expired`，不能复用旧断言。
- step-up 与会话绑定，并同时校验用户、设备/浏览器绑定、IP 策略、角色和组织范围。
- 真实 IdP 不支持 `acr`/`amr` 时，只能采用企业批准的安全替代流程；不得把普通重新登录
  自动标成满足 ACR。
- 审批人与申请人都必须完成自身所需的 step-up；申请人的 MFA 不能替审批人认证。

#### 6.12.5 审批数据模型和 API

核心表：

| 表 | 关键字段 | 说明 |
| --- | --- | --- |
| `approval_requests` | id、org、requester、action、target、payloadHash、risk、state、expiresAt、operationId、version | 审批主记录；不保存秘密或完整正文 |
| `approval_steps` | approvalId、stepOrder、requiredRole、scope、state、requiredApprovers | 串行/并行审批步骤 |
| `approval_decisions` | approvalId、step、approverId、decision、reason、decidedAt、signatureRef | 审批决定和理由 |
| `step_up_assertions` | sessionId、subjectId、acr、amr、authTime、verifiedAt、expiresAt | 只保存验证摘要，不保存 IdP token |
| `approval_consumptions` | approvalId、operationId、consumedAt、payloadHash、resultState | 一次性消费和重放保护 |

服务接口：

```text
POST /api/v1/admin/approvals
GET  /api/v1/admin/approvals/{approvalId}
POST /api/v1/admin/approvals/{approvalId}/decisions
POST /api/v1/admin/approvals/{approvalId}/revoke
POST /api/v1/internal/approvals/validate
POST /api/v1/internal/approvals/{approvalId}/consume
```

`validate` 只回答审批是否匹配当前动作和 payload，不产生副作用；`consume` 才是原子消费。
内部接口仅允许 admin-service、audit-service、resource-service 等受信服务使用 mTLS 或
带 `aud`/最小 scope 的短期 service JWT。浏览器不能调用内部接口。

#### 6.12.6 通知与事件投递

所有告警和业务通知采用 **transactional outbox**：

```text
业务服务：业务状态 + 审计 + outbox 事件（同一事务/文件锁）
  -> notification dispatcher（内网、无公网入口）
  -> 邮件 / 企业 IM / Webhook / SIEM / 工单
```

业务请求不能等待邮件或 Webhook；发送失败也不能伪造业务失败或成功。通知采用至少一次投递，
消费端必须按 `eventId` 去重。投递状态至少包括：

```text
pending -> leased -> delivering -> delivered
                         -> retry_wait -> dead_letter
pending/retry_wait -> suppressed
```

默认重试采用指数退避（例如 1 分钟、5 分钟、15 分钟、1 小时、6 小时），超过策略上限进入
死信并产生内部告警；人工可以在授权、理由和审计下重试或关闭。通知聚合和抑制不能丢弃原始
安全事件，只影响外部发送和值班打扰。

通知渠道：

- 邮件：企业 SMTP/Graph/邮件网关，限制收件人域和附件。
- 企业 IM：飞书、Teams、Slack 等机器人 Webhook；凭据放 Secret Manager。
- 通用 Webhook：仅 HTTPS、固定允许列表、TLS 校验、请求体上限、超时和 HMAC 签名。
- SIEM：Syslog/OTel/HTTP Collector，优先发送稳定 schema 的事件元数据。
- 工单：ServiceNow、Jira、飞书审批/工单等；保存外部工单 ID，不把 token 写进事件。

Webhook 必须防 SSRF：默认禁止回环、链路本地、云元数据地址和未批准私网段；每次重定向都
重新校验；DNS 解析与连接必须防 rebinding。通用 Webhook 带
`X-Magpie-Timestamp`、`X-Magpie-Nonce`、`X-Magpie-Signature`，接收方按时间窗和 nonce
防重放。

#### 6.12.7 通知事件契约

事件至少包含：

```json
{
  "eventId": "evt_...",
  "schemaVersion": 1,
  "eventType": "operation.partial_success",
  "severity": "high",
  "occurredAt": "2026-11-01T00:00:00Z",
  "organizationId": "org_...",
  "actor": {"subjectId": "usr_..."},
  "target": {"type": "credential", "id": "cred_..."},
  "operationId": "op_...",
  "requestId": "req_...",
  "errorCode": "dependency_unavailable",
  "summary": "Policy sync partially failed; 2 of 5 credentials pending",
  "dataClassification": "metadata"
}
```

强制禁止：Gateway Key、masked key、token hash、设备令牌、Cookie、OIDC/服务 token、issuer
Key、上游 MCP Secret、完整 Prompt/回复正文、完整工具参数和未脱敏导出数据。通知正文只能
使用服务端模板和安全摘要；URL 只能是短时、一次性、带审计的查看链接，不能把 bearer token
放进 URL。

首批事件类型：

```text
approval.requested
approval.approved
approval.rejected
approval.expired
approval.consumed
operation.failed
operation.partial_success
operation.audit_failed
security.rule_hit
security.break_glass_used
credential.revoked
gateway.dependency_down
policy.sync_drift
audit.content_accessed
audit.export_created
```

#### 6.12.8 通知配置和查询 API

```text
GET  /api/v1/admin/notifications/channels
POST /api/v1/admin/notifications/channels
PATCH /api/v1/admin/notifications/channels/{id}
POST /api/v1/admin/notifications/channels/{id}/test
GET  /api/v1/admin/notifications/rules
POST /api/v1/admin/notifications/rules
GET  /api/v1/admin/notifications/deliveries
POST /api/v1/admin/notifications/deliveries/{id}/retry
POST /api/v1/admin/notifications/deliveries/{id}/suppress
POST /api/v1/internal/notifications/dispatch
```

渠道写操作要求 `notifications.channels.write`，渠道测试要求
`notifications.channels.test`，均要求管理会话、CSRF、理由、`Idempotency-Key`、近期
step-up（按 H 风险处理）和审计；读取要求 `notifications.channels.read`。渠道 Secret 只能
通过部署环境注入，API 只接收环境变量名 `secretRef`，拒绝 token/password/secret 明文。
测试通道使用固定的 L0 测试事件，不生成或伪造真实 delivery。投递查询只返回事件类型、
严重度、目标渠道、尝试次数、稳定错误码和安全摘要，不返回渠道 Secret、完整响应体或消息
正文。NOTIFY-01c 已提供 dead-letters API 和 critical 优先；NOTIFY-01d 已实现规则/抑制、
聚合、升级、dead-letter 重放和运营页。真实厂商投递、生产证书和生产值班闭环仍未验收。

#### 6.12.9 失败语义与稳定错误码

审批/step-up 失败默认失败关闭。新增稳定错误码：

```text
approval_required
approval_invalid
approval_expired
approval_revoked
approval_consumed
approval_target_mismatch
approval_payload_mismatch
approval_separation_required
approval_unavailable
step_up_required
step_up_expired
step_up_binding_mismatch
notification_channel_invalid
notification_delivery_failed
notification_dead_letter
```

业务通知失败通常不撤销已成功完成的业务动作，但必须写 result 审计、更新投递队列并产生
降级告警；安全事件的 SIEM/工单投递失败要进入死信和值班看板。若某项合规要求“告警成功
后才能提交关键变更”，则该动作必须在审批策略中显式声明为强一致，并在通知失败时保持
`pending`，不能自行判定成功。

#### 6.12.10 实施顺序与依赖

审批和通知跨多个阶段，但不能一开始就做成多功能平台。推荐切片：

| 工作包 | 内容 | 前置 | 退出条件 |
| --- | --- | --- | --- |
| APR-01a 审批契约 | 风险矩阵、规范化 payload、绑定摘要、状态机、稳定错误码 | C3、C5 契约冻结 | 伪造/过期/改 payload/重复消费均被拒绝 |
| APR-01b 外部审批 | `external` 适配器、验签回调、审批查询和一次性消费 | APR-01a、真实 OA | 真实 OA 审批通过后才能执行；回调重放无效 |
| APR-01c step-up | ACR/amr、authTime、短会话和绑定校验 | M2-A、真实管理 IdP | MFA 未完成/过期时高风险动作失败关闭 |
| APR-01d 内置审批 | 审批箱、串行/并行步骤、职责分离和转交 | APR-01a、M2-D 页面 | 申请人不能自批；双人审批可证明 |
| APR-01e break-glass | 短时紧急审批、强制告警、事后复核 | APR-01b/c | 紧急使用 15 分钟内过期，24 小时内完成复核证据 |
| NOTIFY-01a outbox | outbox 表、租约、幂等、重试、死信和恢复扫描 | C3、C5 | 业务成功不依赖外部渠道；重复事件可不重复发送 |
| NOTIFY-01b 渠道 | 邮件、企业 IM、Webhook、工单 | NOTIFY-01a、Secret Manager | 渠道测试、超时、重试、死信和秘密扫描通过 |
| NOTIFY-01c SIEM transport | OTel/Syslog/HTTP 投递、固定事件 schema 和 dead-letters API | NOTIFY-01a、稳定事件 schema/Collector 测试环境 | Mock/故障测试与秘密扫描通过；真实 SIEM/Collector/Syslog/生产证书未验收；M5 规则复用该投递层 |
| NOTIFY-01d 运营 UI | 渠道、规则、投递、死信、重试和抑制 | NOTIFY-01b/c、M2-D | 管理员可定位失败并留审计 |

固定顺序：

```text
ENV-01
  -> C4-02 [done] -> C4-03a [done] -> C4-03b [core done] -> C4-03c -> C4-03d -> C4-04
  -> C5
  -> APR-01a -> APR-01b -> APR-01c
  -> NOTIFY-01a -> NOTIFY-01b [adapter done] -> NOTIFY-01c [transport done]
  -> M2-D（审批、投递状态和 operation/audit 查询接入页面）
  -> APR-01d / NOTIFY-01d
  -> M3/M4/M5 使用同一审批和通知服务
```

C4/C5 开发早期可以采用冻结的审批字段和外部审批引用，但任何高风险操作在 R2 生产候选前
必须接入 APR-01；M3 资源发布、M4 正文查看/导出和 M5 告警处置不得各自再实现一套审批或
通知逻辑。

#### 6.12.11 验收要求

- 缺失、伪造、过期、撤销、跨组织、跨动作、payload 改变和重复消费的审批全部拒绝。
- 申请人不能自审批；审批人无权限或未完成自身 step-up 时拒绝。
- 审批期间目标版本变化时，旧审批不自动适配新版本，必须重新审批。
- 审批通过后回调重放、并发消费和故障恢复不会产生第二个业务结果。
- step-up 过期、会话绑定变化、ACR 不足和 IdP 不可用时高风险操作失败关闭。
- break-glass 短时有效、产生最高级别告警，并在规定时限内生成事后复核任务。
- 通知 outbox 在业务成功、渠道故障和进程重启后都不丢事件；重试、死信、人工重放可追踪。
- Webhook 通过 SSRF、重定向、DNS rebinding、签名/nonce 和超时测试；SIEM 投递通过秘密扫描。
- 审批、operation、审计和通知可按 `operationId` 串联；通知日志、投递记录和外部工单不含秘密。

## 7. 数据模型

以下为建议的核心表，不要求第一阶段全部实现。

| 表 | 用途 |
| --- | --- |
| `org_units` | 部门、项目组、层级 |
| `users` | 企业用户、状态、外部 IdP ID |
| `user_groups` | 用户组和成员关系 |
| `roles` | 角色和权限集合 |
| `role_bindings` | 用户/组与角色、组织范围绑定 |
| `devices` | 设备、公钥、系统、版本、合规状态 |
| `gateway_credentials` | 短期凭证、范围、过期、吊销 |
| `providers` | 上游 Provider 和模型来源 |
| `model_catalog` | 企业模型、能力、价格、状态 |
| `routing_policies` | 路由、回退和模型限制 |
| `quota_policies` | 人/部门/模型/Agent 额度 |
| `mcp_servers` | MCP 元数据、类型、地址、健康检查 |
| `mcp_tools` | 工具、风险、权限、限流 |
| `resources` | 资源主记录和当前发布版本 |
| `resource_versions` | 不可变版本、签名、哈希、发布者 |
| `resource_assignments` | 资源与部门/组/员工/设备的关系 |
| `client_policies` | 客户端锁定、最低版本、更新通道 |
| `device_resource_state` | 设备安装版本、同步状态、漂移 |
| `sessions` | 会话索引，不直接存正文 |
| `requests` | 请求元数据和归属 |
| `messages` | 可选的消息正文密文和脱敏版本 |
| `tool_calls` | MCP/工具调用元数据和可选正文 |
| `usage_events` | Token、费用和配额事件 |
| `security_events` | 规则命中、阻断和告警 |
| `admin_audit_logs` | 管理员操作和正文访问审计 |
| `approval_requests` | 审批主记录、动作/目标/payload 绑定、风险、有效期和状态 |
| `approval_steps` | 串行/并行审批步骤、所需角色和组织范围 |
| `approval_decisions` | 审批人、决定、理由、时间、签名引用和非秘密备注 |
| `step_up_assertions` | 重新认证的 acr/amr/authTime、会话绑定和过期时间 |
| `approval_consumptions` | 审批与 operation 的一次性消费映射和重放保护 |
| `outbox_events` | 与业务状态同事务写入、等待异步投递的事件 |
| `notification_channels` | 邮件、企业 IM、Webhook、SIEM、工单的配置和安全引用 |
| `notification_rules` | 事件类型、严重度、范围、聚合、抑制和升级规则 |
| `notification_deliveries` | 渠道投递、尝试次数、结果、重试、死信和人工操作 |
| `retention_policies` | 留存、删除和法律保留 |
| `secrets_metadata` | 密钥引用、版本、轮换状态，不存明文 |

## 8. API 设计原则

### 控制面

```text
GET    /api/v1/me
GET    /api/v1/me/devices
POST   /api/v1/devices/register
POST   /api/v1/devices/heartbeat
GET    /api/v1/me/policy
GET    /api/v1/me/resources
POST   /api/v1/me/resources/{id}/ack

GET    /api/v1/admin/users
GET    /api/v1/admin/departments
GET    /api/v1/admin/devices
GET    /api/v1/admin/usage
GET    /api/v1/admin/audit/sessions
GET    /api/v1/admin/audit/sessions/{id}
POST   /api/v1/admin/approvals
GET    /api/v1/admin/approvals/{approvalId}
POST   /api/v1/admin/approvals/{approvalId}/decisions
POST   /api/v1/admin/approvals/{approvalId}/revoke
GET    /api/v1/admin/notifications/channels
POST   /api/v1/admin/notifications/channels
POST   /api/v1/admin/notifications/channels/{id}/test
GET    /api/v1/admin/notifications/rules
POST   /api/v1/admin/notifications/rules
GET    /api/v1/admin/notifications/deliveries
POST   /api/v1/admin/notifications/deliveries/{id}/retry
POST   /api/v1/admin/notifications/deliveries/{id}/suppress
POST   /api/v1/admin/resources
POST   /api/v1/admin/resources/{id}/publish
POST   /api/v1/admin/mcp/{id}/healthcheck
```

当前 M1 已实现的认证服务接口（不是完整控制面 API）：

```text
GET    /login                        OIDC Authorization Code + PKCE 入口
GET    /oauth/callback               IdP 回调
POST   /api/v1/join/exchange         用一次性加入码注册设备并领取短期 Key
POST   /api/v1/devices/heartbeat     设备心跳
POST   /api/v1/devices/refresh       轮换短期 Key，旧 Key 进入撤销队列
POST   /api/v1/devices/revoke        吊销本设备
GET    /api/v1/me                    当前网页会话及其设备
POST   /api/v1/logout                注销会话
GET    /healthz                      存活与基础计数
GET    /api/v1/admin/users           M1 最小管理接口（Bearer admin token）
GET    /api/v1/admin/devices         M1 最小管理接口
POST   /api/v1/admin/users/{id}/(disable|enable)
POST   /api/v1/internal/approvals/validate
POST   /api/v1/internal/approvals/{approvalId}/consume
POST   /api/v1/internal/notifications/dispatch
```

后续控制面接口应只通过独立管理服务提供，并由 RBAC、组织范围、操作审计和 CSRF/会话保护
共同约束；不要把 `AUTH_ADMIN_TOKEN` 当成完整管理员认证体系。

### 数据面

```text
POST /v1/chat/completions
POST /v1/responses
POST /v1/messages
GET  /v1/models
POST /mcp/{server-id}
```

### 请求头

```text
Authorization: Bearer <short-lived-token>
X-Magpie-Device-Id: <device-id>
X-Magpie-Client-Version: <version>
X-Magpie-Agent: <agent-id>
X-Magpie-Session-Id: <session-id>
X-Magpie-Request-Id: <request-id>
```

### API 约束

- 控制面与数据面使用不同域名、不同认证受众和不同证书。
- 所有写操作支持幂等键和请求 ID。
- 分页、筛选、排序统一格式。
- 错误响应包含稳定错误码、用户可读消息和请求 ID，不包含密钥或内部栈。
- 资源和服务端配置使用版本号和乐观锁，防止并发覆盖。

#### 8.1 统一响应契约

成功响应至少包含：

```json
{
  "ok": true,
  "requestId": "req_...",
  "operationId": "op_...",
  "data": {}
}
```

失败响应至少包含：

```json
{
  "ok": false,
  "requestId": "req_...",
  "operationId": "op_...",
  "code": "forbidden_scope",
  "message": "The target is outside the administrator scope",
  "retryable": false
}
```

不得在 `message`、`details`、日志或审计中返回 Cookie、Authorization、Gateway Key、设备令牌、
token hash、OIDC Secret、issuer Key、SAML/OIDC token、数据库连接串或上游堆栈。稳定错误码
至少包括：

```text
not_signed_in
session_expired
session_idle
session_binding_mismatch
mfa_required
email_not_verified
csrf_invalid
forbidden_role
forbidden_scope
target_not_found
idempotency_conflict
operation_in_progress
precondition_failed
invalid_request
dependency_unavailable
storage_unavailable
audit_unavailable
approval_required
approval_invalid
approval_expired
approval_revoked
approval_consumed
approval_target_mismatch
approval_payload_mismatch
approval_separation_required
approval_unavailable
step_up_required
step_up_expired
step_up_binding_mismatch
notification_channel_invalid
notification_delivery_failed
notification_dead_letter
rate_limited
```

认证、权限、组织范围、目标存在性和状态前置条件必须按固定顺序校验：认证 -> CSRF ->
权限 -> 组织范围 -> 目标存在性 -> 状态/版本 -> 依赖服务 -> 脱敏输出。不能先查目标再判范围，
否则会泄露目标是否存在。

#### 8.2 敏感写操作协议

所有会改变员工可用性、凭证、额度、授权、资源或安全策略的接口，统一使用以下请求头：

```text
Idempotency-Key: <客户端生成的 128-bit 以上随机值>
X-CSRF-Token: <管理会话对应的 CSRF token>
X-Request-Id: <调用链请求 ID，可由服务端生成>
If-Match: <目标版本号或 ETag，可选但推荐>
```

请求体必须包含：

```json
{
  "reason": "ticket INC-1234: device reported stolen",
  "approvalId": "optional-approval-id",
  "expectedVersion": 7
}
```

`reason` 为 8-500 字符；批量操作必须逐目标返回结果，不能用一个总成功掩盖部分失败。审批编号
只在企业启用审批流后强制；高风险操作还要求 `step_up_required` 时完成重新认证。服务端必须
按第 6.12.3 节重新校验审批的动作、目标、组织范围、payload 指纹、审批人、有效期、撤销状态
和一次性消费状态，不能只检查 `approvalId` 非空。审批消费失败时不得调用依赖。

写操作状态机：

```text
received -> idempotency_checked -> intent_audited -> dependency_invoked
        -> result_audited -> succeeded
        -> failed / partial_success / dependency_failed / audit_failed
```

不可违反的规则：

1. 先校验身份、CSRF、权限、范围、目标和版本，再写 `intent` 审计。
2. `intent` 审计写入失败时，绝不调用 auth-service、gateway 或资源服务。
3. 依赖服务成功或失败后都写 `result` 审计；结果写失败时返回
   `audit_unavailable`，不能把它当普通成功。
4. 同一操作重复提交只允许产生一个业务结果；重复请求返回原结果或当前处理中状态。
5. 审计只追加，不提供普通管理员的更新、删除或覆盖接口。

#### 8.3 幂等与并发

幂等唯一键使用：

```text
actorSubjectId + idempotencyKey
```

幂等记录至少保存 `operationId`、动作、目标、请求体摘要、状态、结果摘要、创建/完成时间和
保留期。相同幂等键但目标、动作或请求体摘要不同，返回 `409 idempotency_conflict`。相同请求
仍在执行时返回 `409 operation_in_progress` 或原 `operationId` 的进度，不重复调用依赖服务。

涉及用户、设备、凭证、额度、模型授权和资源的写操作同时检查：

- 目标当前状态是否允许该动作，例如已停用用户不能重复停用。
- `If-Match` / `expectedVersion` 是否与当前版本一致。
- 同一设备凭证轮换是否已有进行中的操作。
- 批量操作是否超过设定上限，且每个对象独立幂等。

幂等记录、业务状态和审计结果必须能区分配置为同一原子事务，至少在 JSON 试点期通过文件锁、
临时文件原子替换和启动恢复扫描保证“不会同时出现半写状态”。生产数据库阶段使用唯一索引和
事务。

#### 8.4 版本、迁移与兼容

- API 使用 `/api/v1`；破坏性变更必须升主版本并提供迁移窗口。
- 配置、资源 manifest、审计事件和客户端策略都必须有 `schemaVersion`。
- 企业 Provider ID、网关 URL、模型稳定 ID、角色键和错误码是长期契约；改名必须提供别名
  和迁移脚本。
- JSON 数据升级前自动备份；无法识别的字段必须保留，不能静默丢弃后覆盖。
- 企业服务与客户端允许 N/N-1 兼容一个发布周期；密钥轮换必须有新旧并存窗口。
- 任何数据库/JSON 迁移必须提供备份、校验、前滚和回滚步骤，不能把“重新部署”当成数据回滚。

## 9. 安全与合规

### 身份与访问

- OIDC + PKCE，禁止在客户端保存 IdP 密码。
- 短期凭证优先，设备绑定和证书可选。
- 管理后台强制 MFA，支持条件访问和 IP 限制。
- 最小权限、职责分离和临时授权。
- 离职、设备挂失和异常行为自动吊销。

### 数据安全

- TLS 1.2+，内部服务 mTLS。
- 数据库字段级加密，正文和附件使用对象存储加密。
- 密钥放 Vault/KMS，不进数据库明文、不入 Git、不进日志。
- 脱敏在落盘前执行。
- 日志和错误信息不输出完整 Prompt、响应、Token 和 Secret。
- 备份加密、恢复演练和删除验证。

### 合规

- 明确员工告知、使用目的和监控范围。
- 遵循最小必要、最小留存和访问可追溯原则。
- 支持数据主体查询、删除和导出流程。
- 正文审计、导出、角色提升、批量吊销和资源发布需要审批、step-up 和审计记录；审批必须
  绑定具体动作、目标和 payload，并一次性消费。
- 邮件、IM、Webhook、SIEM 和工单投递不包含秘密或完整正文；投递失败、重试和死信可查询。
- 按企业适用法规、行业监管和内部制度做最终合规评审。

### 9.1 服务间认证与信任边界

浏览器只能访问管理服务的公开入口，不能直接访问 auth-service、网关管理接口或数据库：

```text
公网/办公网
  └─ WAF/TLS -> admin-service / auth-service 公开路由
内网服务网
  ├─ admin-service -> auth-service 内部 API
  ├─ admin-service -> gateway 管理 API
  └─ gateway/audit -> 事件队列或内部 API
```

生产要求：

- 服务间优先使用 mTLS；不能使用 mTLS 时使用短期、带 `aud` 和最小 scope 的 service JWT。
- 内部 API 只绑定内网地址，不经过公网反向代理；网络策略默认拒绝其他访问。
- 服务身份有独立密钥和轮换周期；服务 JWT 短命、不可重放，并记录调用方和请求 ID。
- 管理服务调用 auth-service 时只携带完成当前动作所需的最小字段，不把浏览器 Cookie 透传。
- 网关管理 API 使用独立服务凭据，不允许管理服务直接读取/写入 `caller-keys.json`。
- `AUTH_ADMIN_TOKEN` 只能作为一次性引导或应急凭据；首次创建管理员绑定后立即轮换/停用，
  且永远不能出现在浏览器、前端源码、日志或普通员工电脑上。
- 内部调用失败、超时和重试要可观测；写操作通过幂等键避免重复执行。

### 9.2 IdP/SCIM 同步契约

企业 IdP 是人员、组和离职状态的事实来源；控制面保存本地映射和审计记录：

- 支持 SCIM 2.0 Users/Groups 的创建、更新、停用和增量同步；不支持 SCIM 时提供签名
  Webhook 或受控同步任务。
- 以 `issuer + subject` 或 IdP 外部 ID 作为稳定主键，不以姓名或可变邮箱做主键。
- 组到组织单元/角色只建立显式映射；未知组不自动授予管理员权限。
- 离职/停用事件优先级最高：立即停用本地用户、设备、管理会话和刷新权限，并排队撤销
  Gateway Key；不能等待下一次全量同步。
- 同步失败保留上一次成功状态并告警，不能把“读不到组”解释成“用户不属于任何组”而放宽权限。
- 删除用户时保留审计和必要的法定记录，但撤销所有可访问资源；默认采用停用而非物理删除。
- 每次同步记录来源、批次、对象数、成功/失败数、耗时和错误摘要；日志不包含完整 IdP Token。
- SCIM 凭据单独保管、可轮换、仅允许受信网络；同步接口必须幂等并支持重放安全。

## 10. 部署方案

### 10.1 当前 M1 可运行拓扑（先跑通闭环）

当前仓库已经提供 `enterprise/docker-compose.yml` 的 M0 网关和可选 `auth` profile：

```bash
cd enterprise
cp .env.example .env
docker compose up -d                         # 企业网关
docker compose --profile auth up -d          # 网关 + OIDC/设备服务
```

逻辑链路：

```text
员工浏览器
  └─ OIDC ──> enterprise-auth ──> 企业 IdP
                    │
                    └─ 调用 Magpie issuer API 签发短期 Key
员工电脑 Magpie ──> 企业 Magpie Gateway ──> 模型 Provider / MCP
                    │
                    └─ usage.jsonl、额度、模型白名单、IP 白名单
```

部署前必须完成：

- 在 Magpie 网关创建专用 issuer Key，并执行 `magpie gateway-key issuer <id> on`。
- 为企业 IdP 配置回调地址 `AUTH_PUBLIC_URL/oauth/callback`，并登记 `OIDC_CLIENT_ID`。
- 为 `AUTH_COOKIE_SECRET`、`AUTH_ADMIN_TOKEN`、`MAGPIE_ISSUER_KEY` 使用三个独立的高熵值。
- 网关只暴露给公司网段；Auth 服务通过 TLS 反向代理对外，Cookie 开启 `Secure`。
- 先在隔离的演示环境、Mock IdP 和 Mock 上游上跑通，再接入正式 IdP。

当前服务使用 JSON 持久化和单实例限流，适合 5-50 人试点；`AUTH_ADMIN_TOKEN` 仅用于
M1 最小管理接口，不是生产级管理后台。不要在没有 PostgreSQL、备份、审计和管理台之前
直接扩大到全公司。

### 10.2 小规模试点（5-50 人）

单台内网服务器或两台高可用前置代理：

```text
Nginx/Traefik
  ├─ enterprise-admin
  ├─ enterprise-auth
  ├─ magpie gateway
  └─ enterprise-audit
PostgreSQL + MinIO
```

- Docker Compose 部署。
- 单实例 Magpie Gateway。
- PostgreSQL 保存控制面数据，JSONL 可保留短期兼容。
- MinIO 保存资源和可选审计正文。
- 每日备份，保留 7-30 天。
- 适合试点和功能验证，不承诺 99.9%。

### 10.3 中等规模（50-500 人）

- 网关至少 2 副本，控制面 2 副本。
- PostgreSQL 主备或托管数据库。
- Redis 做会话和分布式限流。
- MinIO/S3 高可用。
- OTel Collector + Prometheus/Grafana + Loki/ELK/SIEM。
- 统一入口 WAF/TLS，一对多网关路由。
- 蓝绿或滚动升级，数据库迁移可回滚。

### 10.4 大规模（500+ 人或多地域）

- Kubernetes 部署，按数据面和审计面独立扩缩容。
- ClickHouse 或专用事件存储做高吞吐审计。
- 多地域数据面，中心控制面或分区控制面。
- Vault/KMS、HSM、mTLS、零信任网关。
- 审计 WORM 存储、跨地域备份和灾难恢复。
- 按部门或租户做资源隔离和配额隔离。

### 10.5 M2 管理服务部署契约

管理服务可以复用现有 Compose，但必须使用独立端口、独立 OIDC Client、独立 Cookie 和
独立数据目录。建议环境变量如下，值只放在企业 Secret Manager 或部署系统，不写入仓库：

```text
ADMIN_PUBLIC_URL=https://admin.ai.corp.example
ADMIN_BIND=0.0.0.0
ADMIN_PORT=3445
ADMIN_STORE_PATH=/data/admin-store.json
ADMIN_SESSION_SECRET=<独立随机值>
ADMIN_OIDC_ISSUER=https://<idp>
ADMIN_OIDC_CLIENT_ID=magpie-enterprise-admin
ADMIN_OIDC_CLIENT_SECRET=<IdP 客户端密钥>
ADMIN_OIDC_REDIRECT_URI=https://admin.ai.corp.example/admin/oauth/callback
ADMIN_ALLOWED_IPS=10.0.0.0/8,192.168.0.0/16
ADMIN_REQUIRE_VERIFIED_EMAIL=true
ADMIN_ALLOWED_ACR_VALUES=<按 IdP 约定填写，可留空>
ADMIN_AUTH_SERVICE_URL=https://auth.internal:3444
ADMIN_AUTH_SERVICE_TOKEN=<与 AUTH_INTERNAL_ADMIN_TOKEN 相同>
ADMIN_AUTH_SERVICE_TIMEOUT_MS=5000
ADMIN_SESSION_TTL_HOURS=8
ADMIN_IDLE_TIMEOUT_MINUTES=30
ADMIN_RATE_LIMIT_PER_MINUTE=120
```

部署规则：

- `AUTH_INTERNAL_ADMIN_TOKEN` 由 auth-service 与 admin-service 共享，必须是独立于
  `AUTH_ADMIN_TOKEN`、员工设备令牌、Gateway Key 和 issuer Key 的高熵值；只允许在内网服务
  之间传递，不进入浏览器。
- `auth-service` 的员工公开路由和管理服务公开路由分开；auth-service 的最小 admin token 接口
  不对公网暴露。
- 管理服务只通过反向代理暴露 HTTPS，上游连接使用内部 DNS 和固定服务身份。
- 管理服务和 auth-service 的 OIDC Client 分开，避免员工 Token 被管理端接受。
- 日志中不打印 Cookie、Authorization、请求体全文、OIDC Token 或 Secret。
- 管理 JSON/数据库和审计存储分开备份；恢复后先验证角色、组织范围和吊销状态。
- 试点阶段可以单实例；扩大到多个实例前，必须先把会话、角色、额度和审计迁移到共享存储，
  否则不同副本会看到不同权限和状态。

## 11. 非功能要求

| 项目 | 试点 | 生产目标 |
| --- | --- | --- |
| 网关可用性 | 99.0% | 99.9% |
| 控制面可用性 | 99.0% | 99.9% |
| 登录/签发延迟 | < 3 秒 | P95 < 1 秒 |
| 请求额外延迟 | < 100 ms | P95 < 50 ms |
| 元数据落库 | 异步，允许秒级延迟 | 99% < 5 秒 |
| 审计正文异步写入 | 可重试 | 99% < 30 秒 |
| 审批校验/消费 | P95 < 1 秒 | P95 < 500 ms；外部审批超时失败关闭 |
| step-up 验证 | P95 < 3 秒 | P95 < 2 秒；关键操作默认 5-10 分钟有效 |
| 通知 outbox 投递 | 允许分钟级重试 | 99% < 1 分钟进入渠道；死信可见并告警 |
| 配置同步 | 5 分钟 | 1-5 分钟可调 |
| 备份恢复 | 24 小时 | RPO 15 分钟，RTO 2 小时 |
| 版本回滚 | 手工 | < 10 分钟 |

## 12. 实施路线图

### M0：企业网关基线（已完成）

交付：

- 客户端/服务端分离。
- 员工网关密钥、额度、模型白名单、只读。
- IP 白名单和元数据用量。
- 本地 Agent 一键配置。
- 隔离的演示环境和端到端测试。

验收：

- 员工经本地 Magpie -> 企业网关 -> Mock 上游成功。
- 管理员按员工密钥看到用量。
- 只读账号不能调用模型。
- 重启后数据和配置仍有效。

### M1：身份与设备（2-4 周；代码完成，本地真实链路已验收，生产验收中）

交付：

- `enterprise-auth`。
- OIDC + PKCE。
- 设备注册和心跳。
- 1-8 小时短期网关凭证。
- `enterprise-join` 客户端加入流程。
- 离职/停用立即吊销。

验收：

- 新员工用公司账号登录后 5 分钟内可用。
- 员工不再手工复制长期网关 Key。
- 停用用户后新请求在 5 分钟内被拒绝。

已通过的本地验收：

- Mock OIDC 与真实 Magpie issuer 完成加入、短期 Key 签发和员工 chat。
- 刷新后旧 Key 立即返回 `401`，新 Key 返回 `200`。
- 停用员工后当前 Key、设备刷新和设备心跳全部失效。
- 同设备 5 个并发刷新只有一个活跃 Key；“刷新签发中停用”会撤销刚签发的 Key。
- auth-service 重启后设备状态保留，待撤销队列归零，持久化文件不含明文凭据。

尚未完成的生产验收：

- 真实企业 IdP 的登录、MFA、JWKS、回调地址和 Claim 映射。
- Compose 镜像构建、健康检查和重启恢复。
- Windows 用户会话中的计划任务自动刷新、网络恢复和失败重试。

### M2：管理控制台与 RBAC（3-4 周）

交付：

- 独立的 `enterprise/admin-service`，不要把生产管理逻辑继续堆在 auth-service。
- 用户、部门、设备、角色、凭证、额度、模型白名单页面。
- 部门管理员、审计员、安全管理员视图。
- 管理操作审计。
- 高风险操作的审批、step-up、职责分离和一次性审批消费。
- 审批状态、通知投递、重试和死信的管理入口。
- 用量和费用看板。

验收：

- IT 可以自助开通、停用、调额和轮换凭证。
- 部门管理员只能看本部门。
- 审计员不能修改配置。
- 每次敏感操作都能追溯。
- 缺失、伪造、过期、改 payload 或重复使用的审批不能执行；申请人不能自审批。

#### 12.1 M2 服务边界

建议新增：

```text
enterprise/admin-service/
  src/config.js          管理服务配置和启动校验
  src/oidc.js            管理端 OIDC，不保存 IdP 密码
  src/session.js         管理会话、CSRF、绝对/空闲超时
  src/rbac.js            角色、权限、组织范围判定
  src/service.js         HTTP API 和业务编排
  src/auth-client.js     调用 auth-service 的内部接口
  src/gateway-client.js  调用网关管理 API/CLI，不直接改 caller-keys.json
  src/usage-reader.js    读取 usage.jsonl 或后续查询 API
  src/audit.js           管理操作审计
  src/store.js           试点期原子 JSON 存储；生产切 PostgreSQL
  test/                  权限、范围、CSRF、审计和故障测试
```

管理服务是**控制面**，不替代 Magpie 数据面：

| 服务 | 负责 | 不负责 |
| --- | --- | --- |
| `enterprise-auth` | 员工 OIDC、加入、设备、短期网关凭证 | 管理员页面、部门额度、管理报表 |
| `enterprise-admin` | 管理登录、RBAC、组织范围、管理操作、看板 | 直接代理模型请求、保存厂商 Key 明文 |
| Magpie Gateway | 请求鉴权、模型/MCP 路由、额度执行、元数据 | 管理会话、复杂审批流 |
| `enterprise-audit` | 会话索引、正文、检索、留存、导出 | 修改模型或资源权限 |

管理服务调用 auth-service 和网关时必须使用独立的服务身份，不能把浏览器 Cookie、
`AUTH_ADMIN_TOKEN` 或 issuer Key 转交给前端。内部调用链建议为：

```text
管理员浏览器
  -> admin-service（OIDC 管理会话 + CSRF）
      -> auth-service 内部接口（mTLS 或短期 service JWT）
      -> gateway 管理接口/CLI（最小服务权限）
      -> usage/audit 查询接口
```

#### 12.2 管理登录与账户安全

管理端使用与员工端不同的 OIDC Client、回调和 Cookie 名称，避免员工会话获得管理权限：

```text
员工登录：/login                 -> 员工加入/设备授权
管理登录：/admin/login           -> 管理控制台
管理回调：/admin/oauth/callback  -> 只接受管理端 OIDC Client
```

要求：

- OIDC Authorization Code + PKCE；校验 `iss`、`aud`、`exp`、`nonce`、签名和时间偏差。
- 管理登录必须满足企业 MFA/条件访问；从 IdP 的 `amr`/`acr` 或用户组判断，不只看邮箱。
- 管理会话使用 `HttpOnly`、`Secure`、`SameSite=Lax` 或 `Strict` Cookie；绝对值不超过 8 小时，
  空闲超时建议 30 分钟。
- 会话绑定用户、IdP 主体、创建时间、最后活动、来源 IP 和 User-Agent 摘要；高风险操作重新
  验证 MFA。
- 所有修改请求使用 CSRF token；不能只依赖 `SameSite`。
- 管理端单独限流、IP 允许列表和登录失败告警；反向代理必须可信，不能无条件相信
  `X-Forwarded-For`。
- 退出、停用、角色撤销和会话过期都必须使已有管理会话失效。

#### 12.3 RBAC、组织范围与职责分离

权限判断必须由四元组组成：

```text
允许(角色, 权限, 组织范围, 资源范围/时间范围)
```

建议权限键：

```text
users.read             users.invite            users.disable
devices.read           devices.revoke          credentials.read
credentials.rotate     quota.read              quota.write
models.read            models.write            mcp.read
mcp.write              resources.read          resources.write
usage.read             audit.read              audit.content.read
audit.export           alerts.read             alerts.respond
roles.read             roles.write             system.read
system.write
```

角色不要只做成页面开关，要由服务端统一判断：

| 角色 | 默认范围 | 默认权限 | 明确限制 |
| --- | --- | --- | --- |
| `employee` | 本人 | 本人设备、授予的模型/MCP、本人用量 | 不能看他人或部门汇总 |
| `department_admin` | 指定组织单元及子单元（可配置） | 本部门用户、设备、额度、模型/MCP 分配、部门报表 | 不能跨部门授权，不能改全局 IdP |
| `enterprise_admin` | 全企业 | 全域用户、组织、额度、模型、资源、客户端策略 | 默认不能看正文，不能单独修改留存 |
| `auditor` | 授权组织/时间 | 元数据、摘要、按授权看正文、导出（若单独授予） | 只读，不能改额度/凭证/策略 |
| `security_admin` | 全企业或指定范围 | 安全规则、告警、限流、阻断、吊销 | 不默认管理组织或查看业务正文 |
| `ops_admin` | 基础设施 | 健康检查、备份、升级、应急吊销 | 默认看不到员工正文和业务数据 |
| `super_admin` | 全企业 | 角色授权、紧急操作 | 不能单独关闭审计或删除审计证据 |

服务端必须遵守：

- 先校验“是否有权限”，再校验“目标是否在组织范围”，不能只在前端隐藏按钮。
- 列表查询在数据库/存储层按组织范围过滤，不能把所有数据取回后再在页面过滤。
- 部门管理员不能通过修改 URL 中的 `userId`、`departmentId` 或请求体中的 scope 越权。
- 批量操作逐对象校验；部分成功要返回逐项结果，并记录每个对象的审计。
- 角色绑定有有效期和授予人；临时授权到期自动失效。
- 高风险权限（`audit.content.read`、`audit.export`、`roles.write`、`system.write`）需要单独
  绑定，不能随“管理员”自动获得。
- 业务权限和正文访问权分离；审计员也不能因为“能查日志”而默认能查看原始正文。

#### 12.4 M2 API 切片

第一批只实现能支撑试点闭环的接口，不建议一开始做完所有 CRUD：

```text
GET  /api/v1/admin/me
GET  /api/v1/admin/users
GET  /api/v1/admin/users/{id}
POST /api/v1/admin/users/{id}/disable
POST /api/v1/admin/users/{id}/enable
GET  /api/v1/admin/departments
GET  /api/v1/admin/devices
POST /api/v1/admin/devices/{id}/revoke
GET  /api/v1/admin/credentials
POST /api/v1/admin/credentials/{id}/rotate
PUT  /api/v1/admin/users/{id}/quota
GET  /api/v1/admin/models
PATCH /api/v1/admin/users/{id}/models
GET  /api/v1/admin/usage/summary
GET  /api/v1/admin/usage/timeseries
GET  /api/v1/admin/audit-logs
GET  /api/v1/admin/operations/{operationId}
GET  /api/v1/admin/roles
GET  /api/v1/admin/health
```

第二批再增加 MCP、资源和正文审计接口：

```text
GET/POST /api/v1/admin/mcp
POST     /api/v1/admin/mcp/{id}/healthcheck
GET/POST /api/v1/admin/resources
POST     /api/v1/admin/resources/{id}/publish
POST     /api/v1/admin/resources/{id}/rollback
GET      /api/v1/admin/audit/sessions
GET      /api/v1/admin/audit/sessions/{id}
POST     /api/v1/admin/audit/sessions/{id}/reveal
POST     /api/v1/admin/audit/export
```

所有写接口要求：

- `Idempotency-Key` 或等价的请求 ID，防止重复停用、重复扣额度和重复轮换。
- `If-Match`/版本号校验，防止两个管理员互相覆盖。
- 统一错误码；例如 `forbidden_scope`、`forbidden_role`、`csrf_invalid`、`step_up_required`、
  `target_not_found`、`dependency_unavailable`。
- 成功和失败都返回 `requestId`，并写入管理审计。
- 涉及 auth-service 的调用失败时返回稳定的 `502 dependency_unavailable`，不能假装成功或把
  上游堆栈返回给浏览器。

#### 12.5 M2 数据模型增量

在认证服务已有的 `users`、`devices` 基础上，管理服务先管理以下数据。认证服务继续作为
员工身份、设备和员工 Key 的事实来源；管理服务保存组织范围、角色、额度和操作审计：

| 表/集合 | 关键字段 | 约束 |
| --- | --- | --- |
| `org_units` | `id`、`parent_id`、`name`、`path`、`external_id`、`status` | `path` 唯一；禁止环路；停用部门不能新增授权 |
| `role_bindings` | `subject_type`、`subject_id`、`role`、`scope_org_unit_id`、`valid_from`、`valid_to`、`created_by` | 同一主体/角色/范围不可重复；必须有到期日 |
| `quota_policies` | `scope_type`、`scope_id`、`period`、`tokens`、`cost`、`models`、`agents` | 只能由有 `quota.write` 的角色修改；变更留 before/after |
| `model_entitlements` | `scope_type`、`scope_id`、`model_id`、`status` | 以模型目录的稳定 ID 为准，不用显示名做权限键 |
| `admin_sessions` | `id_hash`、`subject`、`created_at`、`last_seen_at`、`expires_at`、`ip`、`ua_hash`、`revoked_at` | 只保存 session hash；角色变更后重新计算权限 |
| `admin_audit_logs` | `id`、`actor`、`role_snapshot`、`scope_snapshot`、`action`、`target`、`result`、`request_id`、`ip`、`reason`、`before/after` | 追加写；普通管理员不可删除；敏感字段脱敏 |
| `idp_groups` | `external_id`、`name`、`org_unit_id`、`mapping_state` | 只同步映射，不把 IdP 密码或 Token 落库 |

关键一致性规则：

- 用户停用必须同时阻断设备刷新、设备心跳、管理会话和新加入；已签发 Key 进入撤销队列。
- 角色撤销或组织调动必须在下一个管理请求生效，不能依赖浏览器重新登录。
- 额度修改先写审计和版本，再调用数据面；数据面失败时记录“待重试”状态，不能显示已生效。
- 管理服务和 auth-service 使用同一个稳定用户主键（建议 `issuer + subject` 的派生 ID），
  不能只按邮箱合并，避免同名、改名和重复账号。
- JSON 阶段所有写入使用原子替换、文件锁和备份；解析失败按“未知”处理，不能当成空数据。

#### 12.6 管理员页面与员工页面

**管理员页面首批视图：**

| 页面 | 必须看到 | 主要操作 |
| --- | --- | --- |
| 总览 | 在线员工、设备合规、请求/错误、Token/费用、告警 | 进入详情、导出当前视图 |
| 员工与组织 | 姓名、邮箱、部门、角色、状态、最后登录、设备 | 邀请/停用/启用、部门调动、角色绑定 |
| 设备 | 设备名、用户、平台、客户端版本、心跳、Key 到期 | 吊销、查看合规和最近活动 |
| 凭证与额度 | 持有人、设备、模型范围、Token/费用额度、到期 | 轮换、调额、只读、模型授权 |
| 模型 | 企业模型目录、Provider、价格、适用部门 | 灰度发布、黑白名单、回滚 |
| 用量 | 人/部门/Agent/模型/时间段、成功率和费用 | 筛选、导出、设置预警 |
| 安全告警 | 规则、对象、严重度、状态、责任人 | 确认、抑制、阻断、吊销 |
| 操作审计 | 操作者、角色、范围、动作、目标、结果、时间 | 查询和导出（需单独权限） |

**员工页面首批视图：**

| 页面 | 必须看到 | 主要操作 |
| --- | --- | --- |
| 首页 | 企业身份、设备状态、网关连通性、策略版本 | 重新同步、重新登录 |
| Agents | 本机已安装 Agent、可用模型、连接状态 | 一键连接/断开、重启提示 |
| 我的资源 | 已分配的 MCP、Skills、Instructions、模板 | 启停推荐项；强制项只读 |
| 用量 | 本人 Token、费用、剩余额度、周期 | 查看明细和预算说明 |
| 设备与安全 | 当前设备、最后活动、客户端版本、吊销提示 | 挂失/联系管理员 |
| 帮助 | 隐私说明、支持入口、错误码解释 | 下载日志（自动脱敏） |

员工页面**不能**：

- 直接写入 `~/.claude`、`~/.codex`、VS Code 或其他 Agent 文件；只能调用本地 Magpie/helper。
- 显示厂商真实 Key、issuer Key、设备令牌、OIDC Secret 或其他员工数据。
- 让员工通过隐藏按钮绕过企业网关；真正的边界在网络、服务端鉴权和短期凭证。

#### 12.7 管理操作审计规则

每条管理审计至少记录：

```text
requestId, timestamp, actorSubject, actorEmail,
role, scopeOrgUnitIds, action, targetType, targetId,
beforeSummary, afterSummary, result, errorCode,
sourceIp, userAgentHash, reason, approvalId
```

规则：

- 敏感写操作采用 **先写审计意图，再执行，再写结果**；审计写入失败时默认拒绝该操作。
- `before/after` 只保存业务字段和脱敏摘要，不保存密码、Token、Secret 或完整正文。
- 查看正文、导出、跨部门授权、批量吊销、修改留存和角色变更必须填写理由。
- 审计日志只追加，不允许普通管理员删除或修改；保留期由独立安全策略管理。
- 审计员可以读审计，但不能修改配置；安全管理员可以阻断，但不能静默删除证据。
- 所有失败也要记录，尤其是越权、CSRF 失败和依赖不可用。

#### 12.8 M2 实施切片与验收

建议按以下可独立评审的切片推进：

| 切片 | 内容 | 当前状态 | 通过后才能进入 |
| --- | --- | --- | --- |
| M2-A 身份底座 | 管理 OIDC、会话、CSRF、服务间认证、`/admin/me`、组织/角色存储 | 已实现；当前管理回归 109/109、auth 26/26 | 角色撤销立即生效 |
| M2-B 只读治理 | 用户、部门、设备、凭证、模型、用量只读接口和范围过滤 | 已实现，Mock 测试通过；生产环境待验收 | 部门管理员不能跨部门读取 |
| M2-C1 Auth 内部写接口 | 停用/启用、设备吊销、当前凭证轮换；仅服务间令牌 | 已实现，Auth Mock 测试通过 | 目标校验、设备串行化和失败回滚通过；不暴露管理台 |
| M2-C2 管理写 API 与权限映射 | 四个管理写 API、管理权限/范围/CSRF/理由、目标预检和响应脱敏 | 已实现，Mock 测试通过；管理页已接入额度/模型策略写表单和基础停用/吊销/轮换页面 | 跨部门写拒绝；依赖故障不伪造成功 |
| M2-C3 幂等、操作状态与审计 | 持久化幂等键、同键重放/冲突、`operationId`、intent/result 审计和审计失败阻断 | 已实现，Mock 测试通过 | 每个敏感写操作可追溯；审计失败时依赖调用为 0 |
| M2-C4-01 网关机器协议 | schema v1 的 `gateway-key describe <id> --json` 和原子 `policy apply <id> --json` | 已实现，Go 单测、CLI 回归和隔离真实二进制冒烟通过 | 后续适配器只能调用机器协议，不得解析人类文本或直接改 `caller-keys.json` |
| M2-C4-02 受控网关适配器 | `enterprise/gateway-control/` 的 describe/apply/健康检查、固定 argv、独立 Bearer 令牌、超时、输出上限、独立回读和 `pending` | 已实现；Node Mock/故障测试 `15 passed, 0 failed`；C4-04 真实管理链路已验证 | Docker/Compose、真实共享卷和 mTLS 待验收 |
| M2-C4-03a 正式模型目录 | 只读模型目录、稳定模型 ID、显式 Provider 通配符、group 展开、目录摘要和失败关闭 | 已实现；82 项管理服务集成、7 项目录专项、7 项通知渠道专项、7 项通知规则专项和 6 项 SIEM 专项测试通过，合计 109/109 | admin-service 展开稳定模型 ID；部署后坏目录必须启动失败，日志不泄漏路径 |
| M2-C4-03b 用户级策略核心 | 旧 M1 `unknown` 迁移、版本化用户级 `gatewayPolicy`、quota/models 分步首次设置、缺项失败关闭、版本冲突和凭证回读确认 | 已实现 auth-service 核心和内部接口；26 项 auth 测试通过；C4-04 验证管理端到真实网关的完整编排 | 真实部署验收 |
| M2-C4-03c 管理 API、签发同步与交付 | 管理端额度/模型 API、issuance journal、自动 apply/readback、同步后交付、失败补偿和启动恢复 | 核心已实现；管理 109/109、auth 26/26、gateway-control 15/15 Mock/故障测试通过；真实环境待验收 | 调额/模型授权在真实网关生效；失败可补偿且不交付未同步 Key |
| M2-C4-04 完整管理到真实 Magpie 策略流 E2E | 首次 join、管理 OIDC/CSRF、分步策略、双设备 Key、真实限额/模型拒绝、部分失败、refresh/rotate 继承、故障恢复、usage 归属和秘密扫描 | 18 阶段 E2E 全部通过 | Docker/共享卷、真实企业 IdP、反向代理和浏览器自动化验收 |
| M2-C4-03d 页面与运营 | 页面状态、失败恢复入口和查询/对账入口 | C4-03d 部分实现：管理页写表单/证据链和员工只读状态门户已通过页面/API 静态路径测试；M2-D 已接入基础 operation/audit 查询、人工对账和导出页面 | 浏览器 E2E、失败恢复入口和完整运营体验 |
| M2-C5 操作、审计查询与对账 | operation 详情、脱敏审计分页、过滤/游标和四种人工对账动作 | 后端已实现；权限、组织范围、脱敏、分页、幂等/冲突、旧快照、依赖/审计失败、父子 operation 和原审计不可改写均通过 Mock/故障测试；M2-D 已接入基础操作/审计查询页面 | 真实审计存储、完整运营查询/对账体验和失败对账补偿演练 |
| APR-01a/01b/01c/01d 审批、外部回调与 step-up | 风险分级、规范化 payload 与绑定摘要、审批状态机、职责分离、组织范围、一次性消费、并发拒绝、启动恢复、系统审计、HMAC 外部回调适配器、独立 OIDC step-up，以及审批箱/串并行/quorum/转交/撤回 | APR-01a/01b/01c/01d 均已实现并通过当前管理 `109/109` 回归；APR-01d 覆盖审批箱状态过滤、活动步骤、并行 quorum、转交/撤回和外部回调 `stepId` | 真实 OA/IdP/MFA/反向代理/浏览器流程和生产回调演练未验收；基础审批页面已由 M2-D 接入 |
| APR-01e break-glass | 15 分钟单次紧急授权、24 小时事后复核、申请/复核 RBAC、critical step-up、环境/策略/申请人/动作/目标/组织/风险/理由/payload/binding 绑定、原子消费、复核提醒、通知、审计、API 和管理页 | Mock/集成核心已实现并通过 admin `109/109` 回归；`super_admin` 可申请/复核，`security_admin` 仅复核；审批和 break-glass 不能同时使用 | 真实 IdP/MFA、SIEM/告警、OA/工单、外部工单 ID 回读、浏览器 E2E、5 分钟告警/工单 SLA 和 24 小时生产事后复核演练未验收 |
| NOTIFY-01a transactional outbox | 8 种 L0 事件、稳定 `eventId`/`deliveryId`、原子提交、租约、退避、死信、重启恢复、deliveries 查询和人工重放 | 已实现并通过 Mock/故障测试 | 真实生产存储、通知运营 UI 和完整通知闭环未验收 |
| NOTIFY-01b 渠道管理 | `email`/`im`/`webhook`/`ticketing` 渠道 API、RBAC/CSRF/step-up/理由/幂等/审计、按 `eventId + channelId` fanout、渠道测试、HMAC Webhook 和统一 HTTPS 网关适配器 | 已实现并通过 7 项专项及管理回归；仅允许 HTTPS:443、host allowlist、DNS 固定解析、拒绝私网/回环/链路本地/云元数据、仅 307/308 最多 3 跳、超时和响应大小限制；Secret 只保存 `secretRef` | 不是原生 SMTP/Graph/飞书/Teams/ServiceNow/Jira SDK；真实厂商连接、证书/租户配置、真实 SIEM 接入和生产投递未验收 |
| NOTIFY-01c SIEM transport | `http-collector`/`otlp-http`/`syslog-tls`、固定 L0 schema、dead-letters API、HTTPS:443/TLS:6514、allowlist、固定 DNS、SSRF 防护、Bearer `secretRef`（Syslog 禁止）、32 KiB 默认上限、critical 优先和 5 分钟轮询上限 | 已实现并通过 6 项专项及管理回归 | 真实 SIEM/Collector/Syslog/生产证书未验收；真实值班接入和 5 分钟可见性 SLA 未验收 |
| NOTIFY-01d 规则与运营 | 通知规则 CRUD、事件/严重级别/目标/组织匹配、抑制窗口、聚合维度与窗口、阈值/延迟升级、单条升级失败隔离、aggregates/suppressions/escalations 查询、dead-letter 受审计幂等重放，以及渠道/规则/投递/死信/聚合/抑制/升级运营页 | 已实现并通过 7 项通知规则专项及管理回归；写操作要求管理会话、CSRF、RBAC、H 级 step-up、理由和 `Idempotency-Key`，规则更新支持 `expectedUpdatedAt` | 真实邮件/IM/Webhook/工单厂商、真实 SIEM、生产值班、浏览器 E2E 和生产验收未完成 |
| M2-D 看板与运营 | 管理 UI 写操作、用量/审计查询与 cursor 分页、授权导出、operation/对账、审批以及通知规则、抑制、聚合、升级、投递和死信入口 | 核心已实现并通过 Mock/集成测试；通知运营页已接入 | 失败目标恢复入口、完整运营体验、浏览器 E2E、真实数据/负载、对象存储、异步大批量导出和生产验收 |

M2 测试至少覆盖：

1. 部门管理员读取本部门成功，读取兄弟部门返回 `403`。
2. 审计员可读审计但所有写请求返回 `403`。
3. 安全管理员可阻断/吊销，但不能修改角色绑定。
4. 未登录、会话过期、CSRF 错误和 IP 不在允许范围时返回稳定错误。
5. 修改额度、停用员工、轮换凭证和查看正文均写入审计。
6. 审计存储不可写时，敏感写操作失败，不出现“操作成功但无审计”。
7. auth-service 超时或不可用时，管理服务返回 `502 dependency_unavailable`，不伪造成功。
8. 角色撤销后，已有管理会话下一次请求即失去对应权限。
9. 并发的重复停用/调额请求只产生一个有效结果，另外请求幂等返回。
10. 错误响应、日志和审计中不出现 Cookie、Gateway Key、设备令牌、issuer Key 或 OIDC Secret。

M2 的完成标准不是“页面有了”，而是：

- 至少有一个企业管理员、一个部门管理员、一个审计员和一个安全管理员完成端到端演练。
- 管理员能证明“谁在什么范围做了什么、结果是什么”。
- 所有跨部门访问都有服务端拒绝测试证据。
- 管理台重新部署、auth-service 重启和管理会话过期后，权限仍按事实来源计算。

M2-B 已由 Mock 集成测试证明：全域管理员可读全域；部门管理员只能读本组织子树；读取兄弟
部门为 `403 forbidden_scope`；不存在用户为 `404 target_not_found`；凭证和用量响应不含
Gateway Key、设备令牌、token hash 或对话正文。真实 IdP、真实 `usage.jsonl` 数据卷、
Docker、浏览器和反向代理仍未验收，因此不能把 M2-B 标成生产完成。

M2-C2 已由 Mock 集成测试证明：全域管理员可调用四个管理写接口；部门管理员只能写本组织
子树；兄弟部门返回 `403 forbidden_scope` 且依赖调用为 0；CSRF、理由、幂等键格式、坏 JSON、
目标不存在和依赖故障均失败关闭；写响应、管理存储和故障响应不含 Key/token/Secret。
`Idempotency-Key` 在 M2-C3 已完成持久化、重放、冲突和执行中保护；每个写操作都生成
`operationId`，并写入 intent/result 两条管理审计。M2-C5 已提供 operation/audit 查询和
人工对账后端；管理页已有额度/模型策略写表单、基础停用/吊销/轮换页面和 operation/audit/
对账页面，但失败恢复入口、完整运营体验和真实环境验收仍未完成，因此不能把 C3/C5 标成
完整管理台或生产完成。

#### 12.8.1 M2-C 完整实现契约（C1/C2/C3、C4-01/C4-02/C4-03a/C4-03b/C4-03c 核心已完成，C4-03d 部分实现，C4-04 完整策略流已通过，C5 后端已完成）

M2-C 是第一个会真正改变员工使用状态的阶段，必须先冻结接口、权限、幂等和审计语义，不能边
写边改。建议实现以下接口：

| 方法 | 路径 | 权限 | 依赖 | 说明 |
| --- | --- | --- | --- | --- |
| `POST` | `/api/v1/admin/users/{id}/disable` | `users.disable` | auth-service | 停用用户，撤销设备刷新与新加入 |
| `POST` | `/api/v1/admin/users/{id}/enable` | `users.disable` | auth-service | 启用用户，不自动恢复旧 Key |
| `POST` | `/api/v1/admin/devices/{id}/revoke` | `devices.revoke` | auth-service | 吊销设备并撤销当前 Gateway Key |
| `POST` | `/api/v1/admin/credentials/{id}/rotate` | `credentials.rotate` | auth-service / gateway | 轮换当前有效凭证，旧 Key 失效 |
| `PUT` | `/api/v1/admin/users/{id}/quota` | `quota.write` | gateway 管理接口 | 设置该用户 Gateway Key 的 token/成本上限与周期 |
| `PATCH` | `/api/v1/admin/users/{id}/models` | `models.write` | gateway 管理接口 | 替换该用户允许的稳定模型 ID 列表 |
| `GET` | `/api/v1/admin/audit-logs` | `audit.read` | admin store | 查询管理操作审计，不返回秘密和正文 |
| `GET` | `/api/v1/admin/operations/{operationId}` | 对应动作权限 | admin store | 查询幂等操作状态、结果和错误码 |
| `POST` | `/api/v1/admin/operations/{operationId}/reconcile` | `operations.reconcile` | auth-service / gateway | 受控重试、回滚或人工确认，生成子 operation |

当前已有 M2-C1 的四个 Auth 内部接口：`/api/v1/internal/admin/users/{id}/disable`、
`enable`、`/api/v1/internal/admin/devices/{id}/revoke` 和
`/api/v1/internal/admin/credentials/{id}/rotate`。它们只接受
`AUTH_INTERNAL_ADMIN_TOKEN`，不经过管理会话、RBAC、CSRF、幂等、理由或管理审计。上表中的
前四个 `/api/v1/admin/*` 对外接口已由 M2-C2 实现，并接入管理会话、CSRF、RBAC、组织范围
和必填 `reason`；M2-C3 已为这四个接口接入幂等操作状态和 intent/result 管理审计。
`PUT quota` 和 `PATCH models` 已由 M2-C4 实现；`GET audit-logs`、
`GET operations/{operationId}` 和 `POST operations/{operationId}/reconcile` 已由 M2-C5
实现，并通过 Mock/故障测试。C5 的基础查询/对账页面已由 M2-D 接入；真实审计存储、
失败恢复入口、完整运营体验和生产运维演练仍待验收。

**M2-C3 已实现且 C4/C5 必须复用的写入门禁。**

- 所有 C4/C5 写操作都必须先经过管理会话、CSRF、RBAC、目标组织范围、目标存在性、非空
  `reason` 和可选 `approvalId` 校验。
- `Idempotency-Key` 是可选请求头；不提供时每次请求都是新的 `operationId`。管理 UI、自动化
  脚本和批量任务必须始终提供该头。
- 服务端只持久化 `SHA-256(actorSubjectId + "\0" + Idempotency-Key)`，不保存原始键。同一
  管理员在不同请求中复用相同原文会命中同一条记录；不同管理员之间不会互相碰撞。
- C1-C3 的请求指纹覆盖动作、目标类型、目标 ID、理由和审批 ID。C4 必须在实现时扩展指纹，
  把规范化后的额度或模型请求体一起纳入；否则同一幂等键可以用不同额度命中旧结果，属于安全
  缺陷。规范化至少包含 `expectedVersion`、`limits` 或 `models` 的全部业务字段。
- 同键同指纹返回原响应、原 `operationId` 和原 `requestId`，不会再次调用 auth-service 或
  网关；同键不同指纹返回 `409 idempotency_conflict`；同一操作仍在执行时返回
  `409 operation_in_progress`。
- 操作状态至少包括 `received`、`dependency_invoked`、`succeeded`、`partial_success` 和
  `failed`。失败和部分成功结果都会持久化，同键重放返回原结果，不自动重试依赖。
- 所有操作先原子预留幂等键和 operation，再写 `intent` 审计。intent 写入失败时返回
  `503 audit_unavailable`，auth-service、网关 CLI/API 的调用次数必须为 0。
- 依赖结果写入 `result` 审计后才返回成功。result 审计提交失败时返回
  `503 audit_unavailable`，即使网关已经完成变更也不得向调用方返回成功；operation 保持在
  `dependency_invoked`，由 C5 的操作查询、人工对账和补偿流程处理。
- 成功、失败、部分成功、冲突和执行中响应都只包含安全错误码、原请求 ID、operation ID 和
  白名单业务摘要；不包含 Gateway Key、设备令牌、Cookie、token hash、OIDC Secret、issuer
  Key 或服务令牌。

#### 12.8.1.1 C4 用户级 `gatewayPolicy`

C4 的唯一事实来源是 auth-service 中的用户级 `gatewayPolicy`。管理服务只能提交经过校验的
期望值和读取安全摘要，不能直接写 `caller-keys.json`，也不能把“控制面写入了期望值”当成
“真实网关已生效”。

```text
gatewayPolicy:
  version: integer                  # 用户级单调递增版本
  models: string[]                  # 稳定模型 ID；空数组不代表“允许全部”
  limits: Limit[]                   # 0-5 个窗口；空数组代表无额度上限
  quotaStatus: known|unknown|pending
  modelStatus: known|unknown|pending
  updatedAt: RFC3339
  confirmedAt?: RFC3339             # 仅在网关逐凭证确认后写入
  operationId?: string              # 最近一次策略变更

Limit:
  period: day|week|month|days|hours
  days?: integer                    # period=days 时 1..3650
  hours?: integer                   # period=hours 时 1..8760
  tokens: integer >= 0              # 0 表示该指标不限额
  cost: number >= 0                 # 美元；最多 4 位小数；0 表示该指标不限额
  cacheReads: boolean
```

状态语义固定如下：

| 状态 | 含义 | 新签发/刷新/轮换 |
| --- | --- | --- |
| `known` | 控制面期望值和全部活跃凭证已由网关确认 | 允许，并继承当前 `version` |
| `pending` | 已提交变更，但仍有凭证未确认或需要人工对账 | 失败关闭，返回 `409 policy_sync_in_progress` |
| `unknown` | 旧凭证迁移或无法证明历史额度 | 不允许凭猜测签发；首次显式设置后才能变为 `known` |

每张由企业策略管理的凭证另存安全元数据：

```text
policyVersion: integer
policySyncState: pending|synced|failed
lastPolicyErrorCode?: string
lastPolicySyncedAt?: RFC3339
```

凭证记录和响应不得保存或返回 Gateway Key、token hash、设备令牌、Cookie 或服务令牌。

#### 12.8.1.2 C4 额度修改接口

```http
PUT /api/v1/admin/users/{id}/quota
Permission: quota.write
Headers: Cookie, X-CSRF-Token, Idempotency-Key, If-Match
```

请求体：

```json
{
  "reason": "项目组 11 月额度调整",
  "approvalId": "APR-2026-00123",
  "expectedVersion": 7,
  "limits": [
    {
      "period": "month",
      "tokens": 5000000,
      "cost": 200,
      "cacheReads": false
    }
  ]
}
```

校验规则：

- `limits` 为 0-5 项；空数组表示明确移除额度上限，不得与“未知额度”混淆。
- 每个窗口至少要有一个大于 0 的 `tokens` 或 `cost`；负数和 NaN/Inf 一律拒绝。
- `period=days` 时只允许 1-3650 的 `days`；`period=hours` 时只允许 1-8760 的 `hours`；
  其他周期不能携带无关的 `days`/`hours`。
- 同一个 `period + days + hours` 只能出现一次；重复窗口返回 `400 invalid_quota`。
- `cost` 最多 4 位小数；超过 4 位小数直接返回 `400 invalid_quota`，不得静默四舍五入。
  `tokens` 必须是安全整数。
- `expectedVersion` 必须等于目标用户当前 `gatewayPolicy.version`；缺失返回
  `400 version_required`，落后返回 `409 policy_version_conflict`。
- `If-Match` 与 `expectedVersion` 同时存在时必须一致，防止浏览器或代理重放旧版本。

成功或部分成功响应：

```json
{
  "operationId": "op_01J...",
  "requestId": "req_01J...",
  "state": "succeeded",
  "policy": {
    "version": 8,
    "quotaStatus": "known",
    "modelStatus": "known",
    "limits": [
      {
        "period": "month",
        "tokens": 5000000,
        "cost": 200,
        "cacheReads": false
      }
    ]
  },
  "credentials": {
    "total": 3,
    "succeeded": 3,
    "failed": 0,
    "failedItems": []
  },
  "requiresReconciliation": false
}
```

部分成功仍返回 HTTP `200`，但 `state` 必须为 `partial_success`，
`requiresReconciliation=true`，并列出安全失败项：

```json
{
  "state": "partial_success",
  "credentials": {
    "total": 3,
    "succeeded": 2,
    "failed": 1,
    "failedItems": [
      {
        "credentialId": "cred_<opaque>",
        "deviceId": "dev_01J...",
        "errorCode": "gateway_timeout"
      }
    ]
  },
  "requiresReconciliation": true
}
```

网关完全不可用返回 `502 dependency_unavailable`，审计不可写返回
`503 audit_unavailable`；两者都必须带原 `operationId` 和 `requestId`，且不得把用户状态、
额度或模型范围显示为已成功。

#### 12.8.1.3 C4 模型授权接口

```http
PATCH /api/v1/admin/users/{id}/models
Permission: models.write
Headers: Cookie, X-CSRF-Token, Idempotency-Key, If-Match
```

请求体：

```json
{
  "reason": "研发一组允许使用企业批准的模型",
  "approvalId": "APR-2026-00124",
  "expectedVersion": 8,
  "models": [
    "openai/gpt-5.2",
    "anthropic/claude-sonnet-5",
    "company-model/*",
    "group/engineering-approved"
  ]
}
```

校验规则：

- 只接受稳定模型 ID、`<provider>/*` 或 `group/<name>`；不接受显示名、空字符串、裸 `*`
  或可由客户端猜测的别名。
- `models` 至少 1 项；去重后保持稳定顺序。需要禁止全部模型时，应停用用户或吊销设备，
  不能把空数组解释成“全部允许”。
- 普通模型 ID、Provider 通配符和 group 必须存在于当前企业模型目录；未知项返回
  `400 unknown_model`，并在任何依赖调用前拒绝。
- 不得把模型列表自动扩展为同 Provider 的其他模型；必须显式写 `provider/*` 才允许通配。
- 响应沿用额度接口的 `operationId`、`state`、`credentials` 和
  `requiresReconciliation` 结构，只把策略摘要换为模型列表。

#### 12.8.1.4 新旧凭证继承与迁移

- 新签发、刷新和轮换都必须读取用户级 `gatewayPolicy`，不能继续无条件使用
  `config.magpie.models`、`config.magpie.tokens` 和 `config.magpie.cost`。
- 当前策略为 `known` 时，新凭证继承同一 `version`，签发成功后标记 `synced`。
- 当前策略为 `pending` 时拒绝新签发、刷新和轮换，返回 `409 policy_sync_in_progress`，
  避免在真实状态未确认时继续扩散不一致策略。
- 当前策略为 `unknown` 时，不得伪造历史额度或模型范围；管理页显示“未知”，管理员必须
  显式提交一次新策略并经网关确认后才进入 `known`。
- 旧 M1 存储迁移只能迁移已有 Key ID、状态和到期时间；不能根据当前默认配置反推历史额度。
- `publicCredential()` 只返回额度/模型的安全摘要和版本，不返回 Key、token hash 或设备令牌。
- join、refresh、rotate 已有的设备串行化、原子持久化和失败撤销新 Key 保护不得削弱。

#### 12.8.1.5 真实网关适配器边界

当前真实 Magpie 只提供面向人的 CLI，例如：

```text
magpie gateway-key limit <id> ...
magpie gateway-key models <id> ...
magpie gateway-key limit <id>
magpie gateway-key models <id>
```

后两条命令输出 tabwriter 文本或自然语言，不是稳定协议。文本中的列顺序、空格、空额度
措辞和 Provider 同名账户处理都可能变化，因此 C4 **禁止把解析这些输出作为生产回读依据**。
`internal/gui/caller_keys.go` 的 `/api/caller-keys` 也不直接采用：它面向本机 GUI，
不是独立的服务管理协议，直接调用会扩大信任边界并绑定 GUI 生命周期。

##### 12.8.1.5.1 C4-01 机器协议 v1（已实现）

Magpie 企业 fork 已增加两个最小、白名单、机器可读的 CLI 动作。它们复用
`internal/access` 的文件锁、原子写和 `CleanModels`/`Limit.Valid`，不直接暴露
`caller-keys.json`，也不改变个人用户默认 CLI 行为：

```text
magpie gateway-key describe <id> --json
magpie gateway-key policy apply <id> --json
```

`describe` 只读；`policy apply` 从 stdin 读取一个 JSON 对象，并在**同一次文件锁**内完成
“读取当前策略 -> 校验版本 -> 校验模型/额度 -> 一次性写入 -> 回读”。禁止由
`gateway-control` 用 `limit off`、多次 `limit add`、`models all` 再拼接出目标状态，因为
那会暴露中间状态，并且无法证明多窗口额度是原子替换。

`describe --json` 成功输出固定为：

```json
{
  "schemaVersion": 1,
  "ok": true,
  "observedAt": "2026-11-01T08:00:00Z",
  "key": {
    "id": "abc123def456",
    "name": "employee-device",
    "state": "enabled",
    "readOnly": false,
    "expiresAt": null
  },
  "models": {
    "mode": "restricted",
    "patterns": ["openai/gpt-5.2", "anthropic/*"]
  },
  "limits": [
    {
      "period": "month",
      "tokens": 5000000,
      "cost": 200,
      "cacheReads": false,
      "cycleStartedAt": null
    }
  ],
  "accounts": {
    "restricted": false,
    "count": 0,
    "digest": null
  },
  "policyRevision": "sha256:8f1c..."
}
```

字段语义：

- `schemaVersion` 只接受主版本 `1`；未知主版本返回 `gateway_schema_unsupported`，不能猜测。
- `key.state` 只能是 `enabled`、`disabled` 或 `expired`。`expiresAt` 无到期时明确为 `null`。
- `models.mode` 只能是 `all`、`restricted` 或 `accounts_only`；`patterns` 是原始配置，
  不是经过账户推导后的 `HeldModels`。C4 只允许写入 `restricted` 且至少一个 pattern。
- `limits` 按原顺序输出 0-5 项；不输出“已使用量”。`cycleStartedAt` 只用于解释真实窗口，
  不属于调用方可设置的期望策略。
- `accounts.restricted/count/digest` 只用于发现账户范围变化或漂移，不返回账户 ID 或密钥。
  账户摘要变化时，C4 必须重新核验实际模型权限，不能静默视为 `known`。
- `policyRevision` 由 `key.state + key.readOnly + models.mode + models.patterns +
  limits(period/days/hours/tokens/cost/cacheReads) + accounts.digest` 的规范化 JSON
  计算 SHA-256。不得包含时间、Key 密码、token hash、账户 ID 或 CLI 文本。
- 输出上限默认 64 KiB；超过上限、尾随多个 JSON 对象、未知字段类型、重复字段、NaN/Inf
  或不满足上述约束时返回 `gateway_output_invalid`。
- stdout 只能有一个 JSON 对象和一个换行，stderr 不得输出秘密。失败也使用固定 JSON：

```json
{
  "schemaVersion": 1,
  "ok": false,
  "error": {
    "code": "gateway_key_not_found",
    "message": "The gateway key does not exist",
    "retryable": false
  }
}
```

稳定错误码至少包括：

```text
gateway_key_not_found
gateway_policy_conflict
gateway_schema_unsupported
gateway_output_invalid
gateway_output_too_large
gateway_storage_unavailable
gateway_command_failed
gateway_timeout
```

`policy apply` 的 stdin 契约固定为：

```json
{
  "schemaVersion": 1,
  "expectedPolicyRevision": "sha256:8f1c...",
  "models": ["openai/gpt-5.2", "anthropic/*"],
  "limits": [
    {
      "period": "month",
      "tokens": 5000000,
      "cost": 200,
      "cacheReads": false
    }
  ]
}
```

`policy apply` 规则：

1. `<id>` 必须先按稳定 ID 校验；用户可控值只能作为 argv 的一个独立参数，绝不拼入 shell。
2. stdin 最大 64 KiB；拒绝未知 `schemaVersion`、未知字段、裸 `*`、空模型列表、超过
   5 个额度窗口、重复窗口、负数、NaN/Inf 和超范围周期。
3. 当前 `policyRevision` 必须等于 `expectedPolicyRevision`，否则返回
   `gateway_policy_conflict` 且不写文件。该检查防止适配器读到旧状态后覆盖其他管理员的变更。
4. 同一窗口保留原 `cycleStartedAt`；新增窗口从本次写入开始计时；删除窗口直接移除。
5. 只修改 `models` 和额度字段，不得改变 Key 密码、账户、`readOnly`、issuer、到期时间、
   停用状态或已记录用量。
6. 写入使用现有文件锁和原子替换；返回与 `describe` 相同的安全 JSON。失败时不得返回部分
   成功，除非错误明确是存储层在原子替换前失败。
7. 任何输出都不得包含 Gateway Key、masked key、token hash、账户 ID、设备令牌或 Secret。

这两个命令是 C4-01 的**已交付能力**，也是 C4-02/C4-03c/C4-03d/C4-04 的强制依赖。当前已有 Go
单测、CLI 回归和隔离真实二进制冒烟证据，覆盖 schema v1、64 KiB 输入输出上限、稳定错误码、
无秘密输出、`expectedPolicyRevision` 冲突不写文件、文件锁内原子替换和独立回读。C4-02
已经固定调用这两个命令，并通过 15 项 Mock/故障测试；它不等于用户级策略或真实请求行为
已经完成。C4-03a 正式目录、C4-03b auth-service 策略核心和 C4-03c 管理链路核心已实现；
C4-03d 已实现管理页额度/模型写表单、完整证据链状态和员工只读状态门户，但页面 E2E、
恢复入口和查询对账仍未完成；C4-04 完整管理到真实 Magpie 策略流 E2E 已通过，包括多凭证、
refresh/rotate 继承、故障恢复和秘密扫描；Docker/共享卷和真实企业 IdP 仍未验收。后续阶段不得改用人类可读 CLI 文本冒充生产回读。若为了
兼容旧版本临时保留文本解析，必须固定 Magpie commit/tag、写格式契约测试、限制输出长度，
并继续把策略标为 `unknown`，不得进入生产。

##### 12.8.1.5.2 `gateway-control` 服务

C4 固定采用以下服务边界：

1. **管理服务禁止直接读写 `caller-keys.json`。** admin-service 只挂载网关数据卷的只读视图。
2. 新增独立的 `gateway-control` 适配器/sidecar，由它接收 auth-service 的服务间请求；
   只允许 `describe`、`policy apply` 和健康检查，不提供任意命令执行。
3. `gateway-control` 使用专用低权限服务账号，只挂载网关配置数据卷的必要子目录；不得读取
   issuer Key、OIDC Secret、设备令牌或管理员会话数据。
4. 生产环境由该账号使用受控的 `XDG_CONFIG_HOME` 执行白名单命令，并依赖 Magpie 已有的
   文件锁和原子写。测试必须使用临时 `XDG_CONFIG_HOME`、临时端口和临时数据目录，不得
   接触真实用户目录或正在使用的 `127.0.0.1:3425`。
5. 适配器以 argv 数组调用，不经过 shell 字符串拼接；用户可控值只能是已校验的 Key ID、
   稳定模型 ID、整数额度和枚举周期。
6. 默认超时 10 秒，单次输出上限 64 KiB，并发按 Key 串行；超时后必须终止子进程，不能只
   停止等待。日志只记录动作、Key ID、策略版本、耗时和错误码，不记录完整 CLI 输出、
   token、账户 ID 或 Secret。
7. 每次 `policy apply` 后必须再独立执行一次 `describe` 并比较目标 model/limit 字段和
   `policyRevision`。无法可信回读时只能标记 `pending`，不能标记 `known`。
8. `gateway-control` 只在内网服务网络暴露，不映射公网端口；auth-service 与它之间使用独立
   服务令牌或 mTLS，不能复用管理员 Cookie、`AUTH_ADMIN_TOKEN` 或
   `AUTH_INTERNAL_ADMIN_TOKEN`。

如果试点阶段暂时由 auth-service 直接启动受控 CLI，仍必须满足专用系统账号、隔离配置目录、
白名单参数、超时、日志脱敏和回读校验；该临时方式不能跳过 C4 的部分成功和对账语义。

#### 12.8.1.6 C4 执行顺序、部分成功与补偿

额度或模型变更按以下顺序执行：

1. admin-service 完成会话、CSRF、RBAC、组织范围、目标、版本、理由和请求体校验。
2. 写 `intent` 审计并预留持久化幂等键和 operation。
3. auth-service 将用户级策略写为目标版本并标记 `pending`，返回需要更新的活跃凭证集合。
4. `gateway-control` 按凭证串行执行额度或模型变更；v1 不做无界并发，以保证错误可定位。
5. 每个凭证变更后回读校验，记录 `synced` 或 `failed` 与稳定错误码。
6. 全部凭证 `synced` 且无活跃凭证遗漏时，把策略提升为 `known` 并写 `result` 审计。
7. 部分凭证失败时保留 `pending`，operation 记为 `partial_success`，列出失败凭证/设备 ID。
8. 全部失败或依赖超时时保留 `pending`，operation 记为 `failed`，返回
   `502 dependency_unavailable`；result 审计失败则保持 `dependency_invoked`。
9. 默认不自动回滚，因为自动回滚会制造第二次部分状态。管理员必须通过 C5 选择重试目标
   策略，或用上一已确认版本执行显式回滚。

回滚语义：

- 回滚是一次新的、可审计的 C4 操作，必须使用新的 `Idempotency-Key` 和新
  `operationId`，并引用原 operation。
- 回滚把上一已确认 `gatewayPolicy` 应用到当前活跃凭证；部分失败同样返回
  `partial_success`。
- 旧凭证状态为 `unknown` 时没有可信的“上一版本”，不得声称已回滚；只能重新设置明确策略
  或停用用户。
- 回滚、人工确认和重试都不得删除凭证、恢复旧 Key 或绕过用户停用状态。

#### 12.8.1.7 C5 操作查询、审计查询和对账（后端已实现）

C5 提供以下只读查询和受控对账入口：

```text
GET  /api/v1/admin/operations/{operationId}
GET  /api/v1/admin/audit-logs
POST /api/v1/admin/operations/{operationId}/reconcile
```

查询参数固定至少支持：

```text
operationId, actorSubjectId, action, targetType, targetId,
result, from, to, cursor, limit
```

`limit` 默认 50、最大 200；分页使用不可猜测的游标，不返回数据库偏移。查询结果只包含
授权组织范围，审计员默认只能读审计元数据，不能读员工对话正文。响应中的
`beforeSummary/afterSummary` 只包含安全业务摘要，不包含 Key、token hash、Cookie、
设备令牌或服务令牌。

操作查询至少返回：

```text
operationId, requestId, action, targetType, targetId,
state, errorCode, retryable, requiresReconciliation,
actorSubjectId, role, scopeOrgUnitIds,
createdAt, updatedAt, dependencyInvokedAt,
policyVersion, credentialSummary, failedItems,
reconciliationState, parentOperationId
```

`reconciliationState` 只能是 `not_required`、`pending`、`confirmed_applied`、
`confirmed_not_applied` 或 `compensated`。`dependency_invoked`、`partial_success` 和
`failed + retryable=true` 必须在页面上显示为需要处理，不能静默转成成功。

对账接口只接受已认证的管理员、`operations.reconcile` 权限、CSRF、理由、幂等键和审批编号。
动作固定为：

- `retry_desired`：把当前期望策略重试到失败凭证，生成新的子 operation。
- `rollback_previous`：应用上一已确认策略，生成新的子 operation。
- `confirm_applied`：依据外部网关证据人工确认已生效，必须填写 `evidenceRef`。
- `confirm_not_applied`：依据外部证据确认未生效并保留告警；不得自动删除审计。

对账动作不能修改原始 intent/result 审计，只能追加新的审计记录和 operation 关系。

#### 12.8.1.8 M2-D 管理页面与报表

M2-D 只消费 C2-C5 已经验证的 API，不得在浏览器中重新计算权限、额度、模型授权或最终状态。

- 管理员写操作页面必须展示目标、组织范围、理由、审批编号、当前版本、变更前后摘要、
  `operationId` 和真实同步状态。
- 按钮提交后只能显示“处理中”；收到 `succeeded` 后才能显示“已生效”，收到
  `partial_success` 或 `pending` 时必须展示失败凭证/设备和“待对账”。
- 旧凭证额度显示“未知”，不能显示 0、无限或默认额度；未知值必须有解释和首次设置入口。
- 用量/费用看板支持按人、部门、Agent、模型和时间筛选；损坏或不完整 `usage.jsonl` 时
  不生成部分报表。
- CSV/Excel 导出使用独立权限、理由、审批和一次性下载链接；导出动作写管理员审计。
- 管理员操作历史从 C5 读取，不能从浏览器本地状态或只读用量文件推测写操作结果。
- 员工页可以显示本人额度、模型范围、凭证状态和恢复提示；网页仍不能直接修改本机 Agent
  文件，必须由已安装的本地 Magpie/helper 执行。

#### 12.8.1.9 审计 before/after 安全摘要

每条 C4/C5 审计至少包含：

```text
id, operationId, requestId, timestamp, phase,
actorSubject, actorEmail, role, scopeOrgUnitIds,
action, targetType, targetId, beforeSummary, afterSummary,
result, errorCode, sourceIp, userAgentHash,
reason, approvalId
```

`phase` 只允许 `intent` 或 `result`。当前实现使用 `roles` 保存角色快照，并另存
`actorSubjectId`。C4/C5 的摘要固定为：

- 额度：`gatewayPolicy.version`、窗口数量、每个窗口的周期/`tokens`/`cost`/
  `cacheReads`、`quotaStatus`、受影响凭证总数和成功/失败数。
- 模型：`gatewayPolicy.version`、稳定模型 ID 列表、`modelStatus`、受影响凭证总数和
  成功/失败数。
- 凭证：只记录 `credentialId`、`deviceId`、`policyVersion`、同步状态和错误码。
- 对账：原 operation ID、子 operation ID、动作、`evidenceRef`、确认人和审批编号。

不得写入 Gateway Key、设备令牌、token hash、Cookie、OIDC Token、服务令牌、密码或对话
正文。审计只追加，不提供普通管理员的修改或删除接口。审计存储失败时：
intent 失败不执行依赖；result 失败不返回成功，operation 保持 `dependency_invoked`。

#### 12.8.1.10 正式模型目录配置（C4-03a，已实现，待真实部署验收）

`ADMIN_MODELS` 只是逗号分隔的显示字符串，不能表达稳定模型 ID、Provider 通配符和 group 的
区别，也不能作为权限事实来源。C4-03a 已由 admin-service 实现只读配置：

```text
ADMIN_MODEL_CATALOG_PATH=/etc/magpie-enterprise/model-catalog.json
```

该文件由部署系统只读挂载，admin-service 不得通过 API 修改它；auth-service 和
gateway-control 当前尚未接入该目录，但同样不得新增目录写入接口。推荐 schema：

```json
{
  "schemaVersion": 1,
  "models": [
    {
      "id": "openai/gpt-5.2",
      "provider": "openai",
      "displayName": "GPT-5.2"
    },
    {
      "id": "anthropic/claude-sonnet-5",
      "provider": "anthropic",
      "displayName": "Claude Sonnet 5"
    }
  ],
  "providerWildcards": [
    "company-model"
  ],
  "groups": {
    "engineering-approved": [
      "openai/gpt-5.2",
      "anthropic/claude-sonnet-5"
    ]
  }
}
```

当前实现按以下规则失败关闭：

- `schemaVersion` 只接受 `1`；文件不可读、非 UTF-8、JSON 损坏、尾随内容、超过 64 层嵌套、
  空 `models`、重复稳定模型 ID、重复 JSON key、重复 group 名或未知字段均拒绝启动。
- `models[].id` 是唯一权限键，必须是规范化的 `<provider>/<model>`；`displayName` 只供页面
  展示，不能出现在管理 API 的 `models[]` 中，也不能作为授权匹配键。
- `providerWildcards` 必须逐项显式列出，不能从已有模型自动推导；每项只允许 Provider 名，
  不得包含 `/`、`*` 或 group。只有列出的 Provider 才允许使用 `<provider>/*`。
- group 名只允许 `[a-z0-9][a-z0-9._-]{0,63}`；group 只能引用已存在的稳定模型 ID，不能
  嵌套 group、引用通配符或隐式扩大 Provider 权限。
- `group/<name>` 只用于控制面的可读授权表达式。auth-service 在调用网关前必须把 group
  展开为去重后的稳定模型 ID；`gateway-control` 和 Magpie 不接收 group 表达式。
- 不接受裸 `*`、空模型、显示名、未知模型 ID、未知 group 或从普通模型自动推导出的
  `<provider>/*`。
- 文件大小上限由实现冻结为 2 MiB；超过上限、尾随内容或不可解析内容均失败关闭。
- `ADMIN_MODEL_CATALOG_DIGEST` 可选固定文件字节的 SHA-256；配置后必须与 `sha256:<64 hex>`
  完全一致，否则以 `model_catalog_digest_mismatch` 拒绝启动。
- 启动时记录 `catalogVersion`、`catalogDigest`、`loadedAt`、模型/group/Provider 通配符数量，
  写入管理状态摘要和启动管理审计。不得在 API、页面或日志暴露内部文件绝对路径。
- 当前没有在线 reload 或目录写入 API。目录变化必须重算 digest、更新 `.env` 并重启
  admin-service 后生效；启动失败时进程直接退出，不继续提供管理 API。
- `GET /api/v1/admin/models` 返回不含 `displayName` 的安全投影、展开后的 group 和目录摘要；
  未配置文件时才退回 `ADMIN_MODELS` 兼容显示，且明确标记
  `authorizationReady=false`、`catalogVersion=0`。

当前完成边界：

- 82 项管理服务集成、7 项目录专项、7 项通知渠道专项、7 项通知规则专项和 6 项 SIEM 专项测试通过，管理服务合计 109 项通过。
- admin-service 加载目录并把 group/provider 选择器展开为稳定模型 ID；auth-service 把
  稳定模型 ID 写入用户级 `gatewayPolicy`，gateway-control 不接收 group 表达式。
- C4-03a 的本地测试证明目录加载、校验和安全投影；C4-03c 的 Mock/故障测试证明管理 API
  到 auth-service、gateway-control、apply/readback 和凭证提交的编排。C4-04 的 18 阶段
  真实管理链路 E2E 已证明首次设置、双设备签发、模型拒绝、Token 限额、多凭证部分失败、
  refresh/rotate 继承、故障后的 pending 和恢复同步；真实共享卷和部署验收仍未完成。

模型目录错误至少使用以下稳定错误码：

```text
model_catalog_unavailable
model_catalog_invalid
model_catalog_too_large
model_catalog_schema_unsupported
model_catalog_digest_mismatch
unknown_model
unknown_model_group
provider_wildcard_not_allowed
```

#### 12.8.1.11 首次策略初始化与 `unknown` 迁移（C4-03b，核心已实现）

实现状态：auth-service 已实现版本化用户级 `gatewayPolicy`、0-5 个额度窗口、稳定模型
列表、旧 M1 `unknown` 迁移、quota/models 任意顺序首次设置、缺项
`policy_setup_required`、`expectedVersion`/`If-Match`、版本冲突、凭证回读确认，以及
join/refresh/rotate 在 `magpie.issue()` 前失败关闭。`enterprise/auth-service` 当前
`25 passed, 0 failed`。C4-03b 本身只证明策略状态机、首次初始化、版本冲突和回读确认；
管理端编排、issuance journal、自动 apply/readback、同步后交付和崩溃恢复由后续 C4-03c
核心补齐，并已通过 Mock/故障测试，但真实环境仍未验收。

旧 M1 凭证只知道 Key ID、设备、状态和到期时间，无法证明历史额度与模型范围。迁移必须显式写入：

```text
quotaStatus = unknown
modelStatus = unknown
policyVersion = 0
initializationSource = m1_unknown
```

不得根据当前 `MAGPIE_KEY_MODELS`、`MAGPIE_KEY_TOKENS`、`MAGPIE_KEY_COST`、当前全局配置或
其他用户策略反推旧值。迁移重复执行必须幂等，不能覆盖已进入 `known` 或 `pending` 的策略。
存储迁移必须带 schema/迁移版本标记，并在启动摘要中报告 `unknownPolicyUsers` 数量，但不得
输出用户敏感信息。

首次设置规则：

- `PATCH models` 和 `PUT quota` 可以任意顺序首次提交，不要求同一个请求同时携带。
- 第一项只持久化该部分的明确期望值，并把对应状态设为 `pending`；另一部分保持 `unknown`，
  不得伪造为空数组、默认额度、全局默认模型或“无限”。
- 只有 `models` 与 `limits` 都已被管理员显式设置，且 `models` 已通过模型目录校验、`limits`
  已通过 C4 校验后，才组成完整策略并允许调用 `gateway-control`。
- 每张活跃凭证都必须独立回读并匹配完整的 `models + limits`；全部一致后，
  `quotaStatus` 和 `modelStatus` 才同时变为 `known`，并写入 `confirmedAt`。
- 任一状态不是 `known` 时，join、refresh、rotate 和新增设备都失败关闭。
- 当只缺一项时，策略相关依赖操作返回：

```json
{
  "error": {
    "code": "policy_setup_required",
    "missing": ["quota"]
  }
}
```

`missing` 只允许恰好包含 `["quota"]` 或 `["models"]`。两项都缺返回两项都缺的稳定错误，
不得只返回其中一项。管理员首次提交单一部分的响应必须保留 `operationId`、当前
`policy.version`、`quotaStatus`、`modelStatus` 和 `missing`，页面不得显示“已生效”。

- `unknown` 页面显示“历史额度未知”或“历史模型范围未知”，并给出首次设置入口；
  不得显示 `0`、无限、默认额度或当前全局模型列表。
- 首次设置期间不产生“部分回滚”；只允许继续补齐缺失部分、显式取消未完成设置，或停用用户/
  吊销设备。取消设置必须留下审计，并把策略恢复到可解释状态，不能伪装成已确认策略。

#### 12.8.1.12 新 Key 签发、同步、回读与交付（C4-03c，核心已实现，真实环境待验收）

当前实现：auth-service 已按下列顺序接入 `enterpriseIssuanceId` 幂等签发、issuance journal、
`gateway-control` apply、独立 describe 回读、原子提交、失败补偿和启动恢复；管理端提供
`PUT /api/v1/admin/users/{id}/policy/quota` 和
`PATCH /api/v1/admin/users/{id}/policy/models`，并把规范化业务 payload 和
`expectedVersion` 纳入幂等指纹。该链路已通过 Mock/故障测试和 C4-04 的 18 阶段真实管理链路
E2E，后者覆盖真实 Magpie apply/readback、多凭证部分失败、refresh/rotate 继承和
`gateway-control` 故障恢复；真实共享卷、真实 IdP、Docker/Compose、反向代理和生产故障
演练仍属于部署验收。

现有 `internal/access` 的新 Key 签发只能直接携带一个生命周期额度，不能原子表达 C4 的完整
多窗口策略。因此新 Key 的正式顺序固定为：

1. 在 `serializeByDevice()` 设备锁内读取用户策略，确认 `quotaStatus=known` 且
   `modelStatus=known`；否则失败关闭，不签发。
2. 生成不可猜测的 `enterpriseIssuanceId`，先持久化不含秘密的签发 journal，记录
   `operationId`、userId、deviceId、issuanceId、开始时间、预期 `policyVersion` 和状态。
3. 使用当前策略模型签发新 Key。签发 API 必须支持 `enterpriseIssuanceId` 幂等绑定或等价
   的按 issuanceId 查找；没有这个能力就无法证明崩溃后没有孤儿 Key，C4-03c 门禁不通过。
4. 立即用新 Key 的安全 ID 更新 journal，状态进入 `issued`。journal、Key ID 和凭证元数据
   不得包含 Key 明文、token hash 以外的敏感材料。
5. 调用 `gateway-control` 对新 Key 应用完整 `models + limits`，不能只应用签发时的单窗口
   额度。
6. `gateway-control` 独立执行 `describe` 回读；只有模型、全部额度窗口、Key 状态和
   `policyRevision` 与目标策略一致才进入 `synced`。
7. 通过一次原子 `store.mutate()` 持久化凭证、设备引用、策略版本和 `synced` 摘要。
8. 持久化成功后才把 Key、设备令牌或其他客户端凭据返回给调用方。**同步完成前不能把 Key
   交给员工。**
9. 成功后把 journal 标记为 `committed`，写 operation/result 审计；旧 Key 保持当前状态，
   不因新 Key 签发失败被误撤销。

失败和恢复语义：

- 策略应用超时、网关不可达、回读不一致或持久化失败：立即撤销新 Key，不交付客户端；
  journal 进入 `compensating`，撤销成功后进入 `revoked`。
- 撤销失败：保留 `pendingRevocations` 和 journal，告警并返回失败；不得返回成功或删除证据。
- 进程在签发前、`issued`、`syncing`、`synced`、持久化前或撤销中崩溃：启动扫描 journal 和
  `pendingRevocations`，先通过 issuanceId 查询/幂等接口确认真实 Key，再完成提交或撤销。
- 不能留下孤儿 Key。若服务无法关联 Key ID、无法查询 issuanceId 或无法证明补偿完成，
  C4-03c 只能标记为失败，不得用“通常会撤销”代替证据。
- 同一设备的签发、apply 和交付保持串行；不同设备是否并发仍受 v1 单 Key 串行约束。
- 任何响应、日志、journal、审计或错误详情都不得包含 Gateway Key 明文、完整设备令牌、
  Cookie、issuer Key 或服务令牌。

该顺序同时适用于 join、refresh、rotate 和新增设备。`rotate` 只有在新 Key 完成同步、持久化并
可交付后才撤销旧 Key；失败时保留旧 Key 的真实状态，不制造第二次部分故障。

#### 12.8.1.13 页面与运营状态语义（C4-03d，部分实现）

当前实现：管理页已提供额度/模型写表单并携带 CSRF、幂等键、理由和 `expectedVersion`；
展示策略版本、逐凭证 `policySyncState`、最后同步时间和错误码，并保留 `unknown`、
`pending`、`partial_success` 和 `requiresReconciliation` 的保守显示。员工页已展示本人额度、
模型、凭证、设备和同步状态。仍缺页面 E2E、失败设备恢复入口，以及 operation/audit 查询与
人工对账页面。

页面必须分别展示 `operation.state`、`gatewayPolicy` 的 `quotaStatus/modelStatus` 和逐凭证
`policySyncState`，不能用其中任何一个字段替代其余两个。只有以下条件全部成立，才允许显示
“已生效”：

```text
operation.state = succeeded
quotaStatus = known
modelStatus = known
所有活跃凭证 policySyncState = synced
最近一次独立回读一致且 requiresReconciliation = false
```

| 状态 | 页面必须显示 | 页面禁止显示 | 运营动作 |
| --- | --- | --- | --- |
| `unknown` | “历史额度未知”/“历史模型范围未知”、首次设置入口 | `0`、无限、全局默认值、伪造的模型列表 | 补齐 quota 与 models，或停用用户/吊销设备 |
| `pending` | 待同步凭证数、失败设备数、最近回读时间、待对账入口 | “已生效”、按期望值展示真实额度 | 查看失败项并进入 C5 对账；不自动重复 apply |
| `partial_success` | 成功/失败数量、失败 credentialId/deviceId、稳定 errorCode | 只显示总数或隐藏失败目标 | 策略保持 `pending`，`requiresReconciliation=true`，逐凭证人工对账/显式重试 |
| `dependency_invoked` | “网关已调用但结果未确认”、operationId、调用时间 | “失败且未执行”、自动重试按钮 | 禁止自动重试；只能人工检查网关证据后确认已应用/未应用或发起新的显式子操作 |

`dependency_invoked` 不是“确定失败”，也不是“已成功”。任何自动重试都可能重复写入策略，
因此默认禁止；重试必须生成新的子 operation 并引用原 operation。

员工页只能展示本人的身份、设备、策略版本、额度/模型摘要、同步状态、失败设备和恢复提示。
员工页不能读取他人数据，也不能直接修改员工电脑上的 Agent 文件；浏览器只负责展示和发起
受控流程，最终的 Provider/Agent 配置仍由已安装的本地 Magpie/helper 在设备上执行。

管理页面不得从期望值、缓存、前端状态或人类可读 CLI 文本推断最终状态。查询与对账页面
接入前，`dependency_invoked`、`partial_success` 和未完成首次设置只能显示为待处理；管理员
可通过已实现的 C5 后端 API 查询证据并发起受控人工对账，不能伪造页面查询能力或成功状态。

#### 12.8.1.14 C4/C5/D 测试矩阵与退出条件

自动化测试至少覆盖：

| 类别 | 用例 | 通过标准 |
| --- | --- | --- |
| 权限 | 无 `quota.write`/`models.write` 角色调用 | `403 forbidden_role`，依赖调用为 0 |
| 范围 | 部门管理员修改兄弟部门或全公司用户 | `403 forbidden_scope`，依赖调用为 0 |
| CSRF/理由 | 缺 CSRF、空理由、非法审批 ID | 稳定 `4xx`，无策略和网关副作用 |
| 额度校验 | 负数、NaN/Inf、坏周期、重复窗口、超过 5 个窗口 | `400 invalid_quota`，无依赖调用 |
| 模型校验 | 显示名、空数组、裸 `*`、未知模型、隐式扩大 Provider | `400`，无依赖调用 |
| 模型目录 | 文件不可读、坏 JSON、未知字段、空目录、重复 ID/group、未知 group 引用、超 2 MiB | 启动失败关闭；不调用网关；错误和日志不泄漏内部路径 |
| 版本 | 缺 `expectedVersion`、旧版本、`If-Match` 不一致 | `400` 或 `409 policy_version_conflict` |
| 幂等 | 同键同请求、同键不同额度/模型、执行中 | 只执行一次；异体 `409 idempotency_conflict`；执行中 `409` |
| 审计故障 | intent 失败、result 失败 | intent 失败依赖调用 0；result 失败不返回成功且保留 `dependency_invoked` |
| 网关故障 | 超时、退出码异常、回读不一致、全量失败 | 返回 `502` 或 `pending`，不伪造 `known` |
| 部分成功 | 3 张凭证中 1 张失败 | `partial_success`，列出失败项，策略保持 `pending` |
| 继承 | 新签发、refresh、rotate | 继承当前策略版本；`pending` 时失败关闭 |
| 迁移 | 旧 M1 凭证、重复执行迁移 | 状态为 `unknown`，不伪造额度或模型范围；已确认策略不被覆盖 |
| 首次初始化 | 先 quota、先 models、缺项 join/refresh/rotate | 第一部分只进入 `pending`；缺项返回 `policy_setup_required`；依赖调用为 0 |
| 新 Key 顺序 | apply、回读、持久化任一步失败；进程在任一阶段崩溃 | 撤销未提交 Key；不交付；无孤儿；旧 Key 保持原状态 |
| 交付门禁 | 回读未完成或策略非 `known` | 客户端拿不到新 Key/设备令牌；operation 和审计可解释 |
| 脱敏 | 响应、存储、日志、审计、错误详情 | 不含 Key、token hash、设备令牌、Cookie 或 Secret |
| 查询 | 按 operationId、操作者、目标、动作、结果、时间过滤 | 只返回授权范围和安全字段；分页稳定 |
| 对账 | 重试、回滚、确认已生效/未生效 | 新 operation 可追溯，原审计不被修改 |
| 页面 | `unknown`/`pending`/`partial_success`/`dependency_invoked`/`succeeded` | 只有完整证据链成立才显示“已生效”；其余显示真实状态、计数和恢复入口 |

真实 Magpie E2E 至少覆盖：

1. 在隔离端口和临时 `XDG_CONFIG_HOME` 中启动真实 Magpie 网关。
2. 为用户创建两张以上活跃凭证，修改额度后验证每张旧 Key 的真实限制变化。
3. 设置零额度或低额度，验证请求确实被限流，而不是只改变管理页显示值。
4. 修改模型列表后验证旧 Key 只能访问授权模型，未授权模型被真实拒绝。
5. 执行 refresh/rotate，验证新凭证继续继承 `gatewayPolicy`，不会回退到全局默认。
6. 制造一张凭证更新失败，验证返回 `partial_success`、策略保持 `pending`，C5 后端可查询并经
   人工对账重试。
7. 验证全过程不访问真实用户目录、不修改真实配置、不接触 `127.0.0.1:3425`。
8. 在签发、策略 apply、独立回读、持久化和撤销的每个可注入故障点终止进程，重启后不得出现
   无法关联、无法撤销或可被客户端使用的孤儿 Key。
9. 让旧 M1 存储只迁移为 `unknown`，分别先设置 quota 和先设置 models，证明缺项时签发依赖为 0，
   两项完成并逐凭证回读后才允许 join/refresh/rotate。

C4/C5/D 退出条件：

- 8 个 M2-C 管理接口、C5 查询/对账接口和 D 页面全部有权限、范围、CSRF、幂等、理由、
  审计和失败测试。
- 至少一次真实 IdP + 真实 Magpie 网关的停用、吊销、轮换、调额和模型授权演练通过。
- 任意敏感操作都可用 `operationId` 串起操作者、目标、前后状态、依赖结果、错误码和
  是否已对账。
- 响应、日志、审计、错误详情和存储中不存在 Gateway Key、设备令牌、token hash、Cookie、
  OIDC Secret、issuer Key 或服务令牌。
- 审计不可写、依赖超时、部分失败、版本冲突和重复提交都有稳定、可恢复的结果。

以上是 M2-C/D 整体退出清单，不是 C4/C5/D 已完成证明。C3 当前实际覆盖的是前四个写接口
的管理会话/CSRF/RBAC、组织子树、必填理由、持久化幂等、`operationId`、intent/result
审计、审计失败阻断和响应/存储脱敏。C4-01 覆盖底层机器协议；C4-02 覆盖受控适配器并通过
Mock/故障测试，但尚未完成 Docker/真实共享卷验收。C4-03a 已实现正式只读目录并通过
109 项管理服务测试，真实部署未验收；C4-03b/C4-03c 已在 auth-service 和管理服务接通
策略核心、自动 apply/readback、同步后交付、失败补偿和启动恢复，并通过 Mock/故障测试。
C4-03d 已实现管理页额度/模型写表单、完整证据链状态和员工只读状态门户；C4-04 完整管理到
真实 Magpie 策略流 E2E 已通过。M2-C5 的查询/审计/对账后端已通过 Mock/故障测试，
M2-D 已接入基础查询/对账、停用/吊销/轮换和导出页面；浏览器 E2E、失败恢复入口、完整
运营体验、真实审计存储、真实共享卷、真实企业 IdP 和 M2-D 生产验收仍未完成。

### M2-E：审批、重新认证与通知投递（APR-01a-e 与 NOTIFY-01a-d 核心已实现）

交付：

- `APR-01a`：已实现风险分级、规范化 payload、绑定摘要、审批状态机、职责分离、组织范围、
  一次性消费、并发/重启失败关闭和审批系统审计。
- `APR-01b`：已实现 HMAC-SHA256 外部审批回调适配器、时间窗、nonce 防重放、
  issuer/audience、eventId 幂等、审批状态迁移和系统审计；真实 OA 连接器未验证。
- `APR-01d`：内置审批箱、串行/并行步骤、quorum、转交和撤回已实现；浏览器流程仍待验收。
- `APR-01e`：break-glass 的 15 分钟单次授权、24 小时复核、提醒、通知、审计、API 和管理页
  已完成 Mock/集成核心；真实 IdP/MFA、SIEM/告警、OA/工单、浏览器流程和生产复核演练仍待验收。
  `APR-01c` 的独立 step-up 已完成代码和 Mock IdP 集成测试，真实 IdP/MFA/反向代理/浏览器
  流程仍待验收。
- `NOTIFY-01a`：已实现 transactional outbox、稳定事件/投递幂等、租约、重试、死信、
  重启恢复、deliveries 查询和受审计人工重放；渠道关闭或未配置 transport 时不创建
  dispatcher，也不伪造“已投递”。
- `NOTIFY-01b`：已实现 `email`/`im`/`webhook`/`ticketing` 渠道管理 API、渠道测试和统一
  HTTPS 渠道适配器；邮件/IM/工单只是网关契约，不是厂商原生 SDK。按事件类型 fanout，
  以 `eventId + channelId` 去重。真实飞书/Teams/Slack/ServiceNow/Jira 连接和生产验收未完成。
- `NOTIFY-01c`：SIEM transport、`http-collector`/`otlp-http`/`syslog-tls` provider、固定
  L0 schema、HTTPS:443/TLS:6514、allowlist、固定 DNS、SSRF 防护、默认 32 KiB 事件上限、
  critical 优先、5 分钟轮询上限、dead-letters API 和 4 个安全事件类型已实现，并通过
  6 项专项及管理回归；真实 SIEM/Collector/Syslog/生产证书未验收。
- `NOTIFY-01d`：通知规则 CRUD、抑制窗口、聚合、阈值/延迟升级、dead-letter 受审计幂等
  重放、运营查询和完整通知运营页已实现并通过 Mock/集成测试；真实渠道、SIEM、生产值班和
  浏览器 E2E 未验收。
- `admin-service` 接入审批校验/消费、step-up 断言和通知投递状态。
- `audit-service`、`resource-service`、`security-service` 只调用统一审批/通知能力，不各自
  新建一套审批表或同步发送逻辑。

固定顺序：

```text
ENV-01
  -> C4-02 [done] -> C4-03a [done] -> C4-03b [core done] -> C4-03c -> C4-03d -> C4-04
  -> C5
  -> APR-01a [done] -> APR-01b [adapter done] -> APR-01c [done]
  -> NOTIFY-01a/b/c
  -> M2-D
  -> APR-01d [done] -> APR-01e [core done] + NOTIFY-01d
  -> M3/M4/M5
```

C5 开发曾使用冻结的 `approvalId` 和外部审批引用；现在管理写操作已强制校验 APR-01a 审批，
APR-01b 已提供 HMAC 外部回调适配器，APR-01c 已提供独立 step-up，但 R2 生产候选前仍必须
完成真实 OA 连接器、真实 IdP/MFA/反向代理/浏览器验收和通知链路。M3 发布、M4 正文查看/
导出、M5 告警处置必须复用这些工作包。

验收：

- APR-01a 已覆盖缺失、伪造、过期、撤销、跨组织、跨动作、payload 变化、自审批和重复/
  并发消费的失败关闭；admin-service 的 Mock/故障测试已通过。
- 真实 OA 连接器、生产回调演练、真实 IdP/MFA/反向代理/浏览器流程和 break-glass 生产
  验收尚未完成；break-glass Mock/集成核心、审批箱串并行流程、quorum、转交和撤回已实现
  并通过 Mock/故障测试；审批人
  自身 step-up 门禁已完成代码和 Mock IdP 集成测试。
- 审批期间目标版本变化时旧审批失效，不自动套用到新版本。
- 业务成功与 outbox 同事务写入；渠道故障、进程重启和重试不会产生伪造业务结果或丢失事件。
- Webhook SSRF 防护、HMAC/nonce、SIEM 脱敏和死信人工重放均通过测试。
- 审批、operation、管理审计和通知投递可按 `operationId` 串联，响应、日志和外部渠道无秘密。

独立分支：

```text
feat/m2-e-approval-step-up
feat/m2-e-notification-outbox
```

### M3：中央资源库与 MCP（4-6 周）

交付：

- MCP 目录。
- 远程 MCP 网关。
- 资源包、版本、签名、审批、分配和回滚。
- 员工本地资源同步和漂移检测。
- 策略锁定和强制资源。

验收：

- 管理员发布一个 MCP 后，指定员工在 5 分钟内可见。
- 未授权员工不可见、不可调用。
- 强制资源不能被员工关闭。
- 资源升级失败自动保留上一版本。

### M4：会话与工具审计（4-6 周）

交付：

- 请求元数据和会话索引。
- 流式响应完整采集。
- L0-L3 审计等级。
- 脱敏、关键词检索、留存、导出。
- 管理员查看审计日志和二次确认。

验收：

- 管理员能按员工、时间、Agent、模型和工具检索。
- 未授权管理员不能查看正文。
- 敏感字段不会以明文落盘。
- 删除和留存策略实际可验证。

### M5：安全策略与运营（3-4 周）

交付：

- 敏感数据、异常用量、异地、越权、直连检测。
- 告警、限流、阻断和吊销联动。
- SIEM/OTel 接入。
- 运维看板、健康检查和值班手册。

验收：

- 典型违规场景 5 分钟内可见。
- 严重风险可一键吊销和阻断。
- 告警有明确责任人和处置记录。

### M6：规模化与高可用（按需）

交付：

- PostgreSQL/ClickHouse 迁移。
- 网关多副本和负载均衡。
- Redis 限流和缓存。
- Vault/KMS、mTLS、SBOM、签名发布。
- 多地域和灾备。

验收：

- 通过容量压测和故障演练。
- 单节点故障不影响请求。
- 备份恢复达到 RPO/RTO 目标。

### 12.9 M3-M6 工作包与完成定义

| 阶段 | 工作包 | 关键产物 | 完成定义 |
| --- | --- | --- | --- |
| M3 | M3-A 目录与签名（核心已实现） | `resource-service`、manifest schema、内容寻址对象存储、签名校验 | 资源可创建不可变版本并校验哈希/签名；11 项测试已覆盖，真实审批、管理台、员工端同步接入和生产验收未完成 |
| M3 | M3-B 远程 MCP（核心已实现） | MCP 注册、企业统一端点、工具级权限、健康检查 | 14 项测试已覆盖未授权 MCP/工具不可见/不可调用、scope、审批门禁、SSRF、凭据隔离、健康/熔断和审计边界；管理台、admin-service 真实审批联动、OIDC 组织分配、员工端同步接入、共享事务存储、多副本和生产验收未完成 |
| M3 | M3-C-1/M3-C-2 同步控制面与只读管理可见性（已实现） | 短期同步凭证、desired-state、设备上报、管理员 JSON 查询、签名同步、原子安装、失败保留旧版本、离线缓存、强制/推荐、漂移、秘密隔离，以及按组织范围过滤的只读资源/同步报告 API 和管理页面板 | client-sync 24 项测试覆盖 16 项同步引擎核心和 8 项 HTTP 传输；resource 15 项测试覆盖 11 项核心和 4 项控制面；admin-service 新增 5 项 M3-C-2 测试并通过，企业全量 203 项；资源发布/回滚 UI、审批联动、本地 helper、Windows ACL、MDM、Agent 文件映射、浏览器 E2E、Docker/Compose 实机、5 分钟端到端可见和生产验收未完成 |
| M3 | M3-D 本地 MCP（未实现） | 签名包、运行权限、Secret Reference、健康检查 | 未签名包不能运行；本地访问范围可证明 |
| M4 | M4-A 事件管道 | 请求/回复事件 schema、请求 ID、幂等、异步投递 | 元数据可按会话和请求串联；写入可重试 |
| M4 | M4-B 内容采集 | 流式拼接、脱敏、分片、对象存储、索引 | 流式回复完整；敏感字段落盘前被处理 |
| M4 | M4-C 检索与权限 | 员工/部门/时间/模型/工具筛选、正文二次授权 | 审计员只看到授权范围，查看正文有记录 |
| M4 | M4-D 留存与导出 | 留存策略、删除证明、加密导出、过期链 | 删除和法定保留均有可验证证据 |
| M5 | M5-A 规则引擎 | 敏感数据、异常用量、越权、直连检测规则 | 规则命中可在测试环境稳定复现 |
| M5 | M5-B 响应动作 | 告警、限流、阻断、吊销、设备锁定、工单 | 严重事件处置可追踪到人和时间 |
| M5 | M5-C 可观测性 | OTel/Prometheus/Grafana、SIEM、值班手册 | 典型故障和违规 5 分钟内可见 |
| M6 | M6-A 数据层 | PostgreSQL/ClickHouse、迁移、备份、恢复演练 | 迁移可回滚，RPO/RTO 达标 |
| M6 | M6-B 数据面 | 多副本、负载均衡、Redis 限流、灰度 | 单节点故障不影响请求 |
| M6 | M6-C 密钥与供应链 | Vault/KMS、mTLS、SBOM、签名发布、扫描 | 密钥不落明文，构建产物可验证 |

M3-M6 的共同完成定义：

- 有一个真实或高保真集成测试，覆盖正常、拒绝、超时和降级。
- 管理端可以查看状态、错误和版本，不需要登录服务器读日志。
- 变更前有备份和迁移脚本，变更后能回到上一已验证版本。
- 相关领域文档更新，记录接口、状态、失败行为、兼容性、测试命令和未验证项。
- 没有越过 `main` 自动同步链路；企业发布仍在独立 release 流程完成。

## 13. 测试与验收矩阵

| 场景 | 验收点 |
| --- | --- |
| 新员工加入 | OIDC 登录、设备注册、短期凭证、Agent 连接成功 |
| 离职 | 用户停用、凭证吊销、设备无法继续调用 |
| 并发刷新 | 同设备最终只有一个活跃 Key，其余新 Key 均被撤销 |
| 签发中停用 | 停用与刷新交错时，刷新失败且刚签发的 Key 立即撤销 |
| 模型越权 | 白名单外模型返回稳定错误并告警 |
| MCP 越权 | 未分配 MCP/工具不可见、不可调用 |
| 强制资源 | 员工无法关闭或删除，重启后仍恢复 |
| 资源版本回滚 | 新版本失败后自动回到上一版本 |
| 额度耗尽 | 超额被限流，管理员收到告警 |
| 对话审计 | 元数据准确；正文仅在授权和策略允许时采集 |
| 审计权限 | 审计员只能查看授权范围，查看动作被记录 |
| 敏感数据 | 落盘前脱敏，日志和导出不含明文 Secret |
| 审批绑定 | 缺失、伪造、过期、撤销、跨组织、改 payload 和重复消费均失败关闭 |
| 职责分离 | 申请人不能自审批；审批人和申请人都满足各自 step-up 与权限 |
| 审批恢复 | 回调重放、并发消费、进程重启和目标版本变化不会产生第二个业务结果 |
| 通知投递 | outbox 不丢事件；重试、聚合、抑制和死信可查询，外部渠道不含秘密 |
| 设备丢失 | 吊销凭证并阻止新请求 |
| 网关故障 | 多副本接管，错误可观测 |
| 上游故障 | 回退策略生效，员工收到可理解提示 |
| 上游同步 | 企业构建和功能测试通过，冲突可回滚 |

## 14. 与上游兼容的开发方式

### 14.1 代码布局建议

```text
enterprise/
  auth-service/
  admin-service/
  approval-service/
  notification-service/
  audit-service/
  policy-service/
  resource-service/
  deploy/
  scripts/
  test/

plugins/
  enterprise-audit/
  enterprise-policy/

internal/
  enterprisehooks/       # 尽可能小且稳定的 hook
```

### 14.2 变更原则

- 优先独立服务，补齐能力不依赖改上游核心。
- 能用 `gwmw` 中间件完成的审计和拒绝逻辑，不直接写进路由核心。
- 核心 hook 必须默认关闭、带测试、可降级，不影响个人用户。
- 企业 UI 独立部署，不直接大改上游单机 Web UI。
- 每个企业功能使用独立 `feat/*` 分支和 PR。
- 上游同步失败时，企业发布必须停在最后一个已验证版本。
- 每次上游升级后执行端到端、权限、脱敏和审计回归。

### 14.3 保留现有基线

- 保留现有员工一键配置 Agent 能力。
- 保留当前企业网关密钥和元数据用量作为兜底。
- 保留 `MAGPIE_ALLOW_IPS`、模型白名单、额度和只读能力。
- 现有脚本和演示环境作为 M1/M2 的回归测试基础。

## 15. 风险与处理

| 风险 | 影响 | 处理 |
| --- | --- | --- |
| 企业改造污染上游 | 无法持续合并 | 独立服务、插件和最小 hook |
| 全量正文审计 | 隐私和合规风险 | 分级、脱敏、授权、留存和访问审计 |
| 本地 MCP 过权 | 可读写本机文件或执行命令 | 签名、沙箱、工具级权限和审批 |
| 员工绕过客户端 | 直连厂商或未授权 MCP | 网络出口、设备合规、服务端短期凭证 |
| 静态长期密钥 | 泄露后长期可用 | 迁移到 OIDC + 短命凭证 |
| 单实例存储 | 故障和扩展受限 | 50-100 人后迁移 PostgreSQL/HA |
| 审计数据膨胀 | 存储和检索成本高 | 元数据与正文分层、冷热存储、保留策略 |
| 供应商模型变化 | 路由和成本波动 | 模型目录版本、价格版本、回退和告警 |
| 资源包供应链风险 | 恶意 Skills/MCP | 签名、SBOM、扫描、隔离测试和发布审批 |

## 16. 首期推荐交付顺序

如果以最快形成企业可用闭环为目标，建议按下面顺序：

1. OIDC 登录和设备注册。
2. 管理控制台中的用户、部门、设备、凭证和额度。
3. 中央 MCP 目录和远程 MCP。
4. 中央资源库、强制策略和客户端同步。
5. 元数据审计和权限分域。
6. 经政策批准的内容审计。
7. 统一审批、step-up、通知 outbox、SIEM 和值班闭环。
8. HA 和规模化。

首期上线的最低闭环是：

```text
员工 OIDC 登录
  -> 自动获得短期凭证
  -> 本地 Magpie 自动配置 Agent
  -> 只能访问企业模型和企业 MCP
  -> 管理员看到人/部门/Agent/模型/额度/异常
  -> 离职可立即吊销
```

在这个闭环稳定后，再逐步开放正文审计、复杂资源编排和跨地域部署。

## 17. Fork 工程治理与兼容性

### 17.1 代码边界

企业能力按以下顺序选择实现位置：

| 优先级 | 位置 | 适用能力 | 上游同步风险 |
| --- | --- | --- | --- |
| 1 | 独立服务 `enterprise/*-service` | OIDC、管理台、策略、资源库、审计 | 无 |
| 2 | Magpie 插件/中间件 | 请求改写、脱敏、拒绝、事件投递 | 低 |
| 3 | 独立部署脚本和 Compose | 密钥、设备、发布、巡检 | 无 |
| 4 | 最小核心 hook | 只有插件无法获得的稳定事件点 | 必须评审 |

核心 hook 必须满足：

- 默认关闭，不影响个人用户和非企业部署。
- 有独立开关、超时、失败降级和关闭路径。
- 有单元测试和上游升级回归。
- 不把新的长期状态写入上游核心数据文件。
- 不改变原有 API、配置格式和 CLI 的默认语义。

### 17.2 分支规则

`main` 只承担两件事：同步上游、发布已经验证的企业提交。任何功能都必须从最新 `main`
开分支，避免把半成品直接带进同步链路。

推荐分支命名：

```text
feat/enterprise-auth
feat/enterprise-admin-rbac
feat/enterprise-mcp-catalog
feat/enterprise-resource-sync
feat/enterprise-audit
fix/enterprise-key-refresh-race
release/e1.4.2
```

现有 `devtools/new-feature.ps1`、`update-feature.ps1`、`finish-feature.ps1` 可以继续使用：

```text
从最新 main 开分支 -> 小步提交 -> 定期把 origin/main 和 upstream/main 合入功能分支
-> 在功能分支解决冲突 -> CI 和 E2E 通过 -> PR/评审 -> 合并 main
```

团队必须开启以下 GitHub 规则：

- `main` 禁止直接推送，至少要求 PR 和 1 次评审；核心 hook 变更要求 2 次评审。
- CI 必须包含语法、Go/Node 单测、M0 E2E、M1 auth 测试和构建。
- 自动同步 workflow 使用单独的 machine token，只允许同步上游，不允许发布企业产物。
- 企业发布只从通过验证的 `release/e*` 分支或 tag 构建，不从开发分支直接发。
- 分支保护不能只依赖客户端 hook；GitHub 服务端规则才是最终约束。

### 17.3 冲突处理

功能分支每天都应执行一次：

```powershell
devtools\update-feature.cmd
```

冲突处理顺序：

1. 先判断是否是同一文件的上游语义变化；优先保留上游行为，再把企业逻辑放进独立 hook/服务。
2. 配置字段新增必须向后兼容；旧字段保留至少一个发布周期并给出迁移日志。
3. 数据库/JSON 状态升级必须可回滚；先备份，再运行迁移，再启动新版本。
4. 冲突解决后重新跑 M0 链路、M1 auth、模型白名单、额度和吊销回归。
5. 合并到 `main` 后观察上游下一次同步是否仍能自动完成；不能自动完成就回退企业提交，不阻塞上游。

### 17.4 发布兼容契约

- 企业服务 API 使用 `/api/v1`，破坏性变更升版本并保留过渡期。
- 企业配置以 `version` 字段标记；客户端遇到不认识的字段必须忽略，不得静默删除。
- 企业 Provider ID、网关 URL 和模型 ID 是稳定契约；改名需要迁移脚本。
- 企业插件 manifest、资源包和 MCP 包必须有 `schemaVersion`、哈希和签名。
- 任何密钥轮换都允许“新旧并存窗口”，不能要求所有员工同时重启客户端。
- 发布产物必须能回退到上一企业版本；回退不重置用户数据和审计索引。

## 18. 权限矩阵与敏感操作

### 18.1 角色权限

| 能力 | 员工 | 部门管理员 | 企业管理员 | 安全管理员 | 审计员 | 运维管理员 |
| --- | --- | --- | --- | --- | --- | --- |
| 配置本人 Agent | 允许 | 允许 | 允许 | 允许 | 允许 | 允许 |
| 查看本人用量 | 允许 | 允许 | 允许 | 允许 | 允许 | 不默认 |
| 查看本部门汇总 | 禁止 | 允许 | 允许 | 允许 | 按授权 | 不默认 |
| 修改部门额度/模型 | 禁止 | 允许 | 允许 | 可建议/阻断 | 禁止 | 禁止 |
| 查看全公司汇总 | 禁止 | 禁止 | 允许 | 按授权 | 按授权 | 不默认 |
| 查看对话正文 | 禁止 | 默认禁止 | 默认禁止 | 单独授权 | 单独授权 | 禁止 |
| 吊销设备/Key | 仅本人设备 | 本部门 | 全公司 | 全公司 | 禁止 | 可执行应急 |
| 修改安全规则 | 禁止 | 禁止 | 可建议 | 允许 | 禁止 | 禁止 |
| 修改 IdP/系统配置 | 禁止 | 禁止 | 双人审批 | 可审计 | 禁止 | 允许 |
| 导出审计数据 | 禁止 | 禁止 | 审批后 | 审批后 | 按范围 | 禁止 |

#### 18.1.1 数据可见范围

| 数据 | 员工 | 部门管理员 | 企业管理员 | 安全管理员 | 审计员 | 运维管理员 |
| --- | --- | --- | --- | --- | --- | --- |
| 本人身份、设备、用量 | 允许 | 允许 | 允许 | 允许 | 允许 | 不默认 |
| 本部门用户列表 | 禁止 | 允许 | 允许 | 按授权 | 按授权 | 禁止 |
| 兄弟部门数据 | 禁止 | 禁止 | 允许 | 按授权 | 禁止 | 禁止 |
| 全公司成本和模型分布 | 禁止 | 禁止 | 允许 | 按授权 | 按授权 | 禁止 |
| Gateway Key 明文 | 禁止 | 禁止 | 禁止 | 禁止 | 禁止 | 禁止 |
| Gateway Key ID/状态/到期 | 仅本人 | 本部门 | 全域 | 按授权 | 按授权只读 | 排障最小字段 |
| IP、User-Agent、设备指纹 | 仅本人摘要 | 本部门摘要 | 全域摘要 | 全域 | 按授权 | 排障最小字段 |
| L0 请求元数据 | 本人 | 本部门 | 全域 | 全域 | 按授权 | 禁止 |
| L1 工具/策略摘要 | 本人摘要 | 按授权 | 按授权 | 全域 | 按授权 | 禁止 |
| L2 脱敏正文 | 本人可申请 | 默认禁止 | 默认禁止 | 单独授权 | 单独授权 | 禁止 |
| L3 原始正文 | 禁止 | 禁止 | 禁止 | 双人审批 | 双人审批 | 禁止 |
| 管理审计日志 | 禁止 | 本部门操作 | 全域只读 | 安全相关只读 | 授权范围内只读 | 运维事件摘要 |
| 备份、密钥和基础设施配置 | 禁止 | 禁止 | 双人审批 | 只读安全配置 | 禁止 | 允许运维但不含秘密 |

`ops_admin` 可以执行应急吊销、恢复和升级，但不能通过运维接口读取业务正文、复制数据库、
导出审计或修改角色。任何“紧急权限”必须有到期时间、理由和事后复核。

#### 18.1.2 职责分离

以下权限不能由同一自然人在无第二人审批的情况下同时使用：

- `roles.write` + `audit.content.read`。
- `audit.content.read` + 删除/缩短留存。
- `system.write` + `audit.export`。
- `credentials.rotate` + 修改上游 Provider 真实密钥。

高风险授权必须有有效期和授予人。超级管理员不是“全能账号”，不能单独删除审计、关闭审计、
查看 L3 正文或修改自己的角色绑定。

### 18.2 敏感操作

以下动作必须二次确认、填写理由、生成请求 ID，并写入管理员审计日志：

- 查看、下载或导出正文。
- 批量停用员工、吊销设备或轮换上游 Provider Key。
- 修改模型/MCP 白名单、额度、留存期和审计规则。
- 发布或回滚强制资源、客户端最低版本和安全策略。
- 扩大角色范围、跨部门授权和临时访问。

管理员审计日志至少记录操作者、角色、组织范围、目标对象、动作、时间、来源 IP、请求 ID、
修改前后摘要和结果；日志本身不能被普通管理员删除。

## 19. 数据生命周期与审计边界

### 19.1 分级记录

| 级别 | 默认 | 数据 | 用途 |
| --- | --- | --- | --- |
| L0 元数据 | 开启 | 人、设备、Agent、模型、Token、费用、状态、IP、请求 ID | 成本、容量、安全和基本审计 |
| L1 摘要 | 按需 | 请求摘要、工具名、参数类别、结果状态、策略命中 | 安全运营和异常调查 |
| L2 脱敏正文 | 显式授权 | 脱敏后的提示词、回复、工具参数/结果 | 经批准的合规调查 |
| L3 原始正文 | 默认禁止 | 未脱敏内容 | 仅法定调查、双人审批、短保留 |

### 19.2 留存与删除

- 元数据、摘要、正文、附件分别设置留存期，不能用一个“全量永久保存”开关。
- 正文采用对象存储加密、版本控制和最小权限访问；索引与正文分权。
- 删除请求先删除可读正文，再保留不可逆哈希和删除证明。
- 法律保留优先于普通删除，但必须有审批、范围和到期时间。
- 导出文件使用一次性下载链接、水印、审计编号和自动过期。
- 每季度验证一次备份恢复、删除流程和访问审计，保留演练证据。

### 19.3 员工告知

企业上线前应明确告知：采集哪些数据、为什么采集、谁能查看、保留多久、如何申请查询或删除。
默认策略应是 L0；不得把“技术上可以打开 L3”当成“默认开启全量对话监控”。

## 20. 部署与运维 Runbook

### 20.1 上线前检查

- DNS、TLS 证书、反向代理、WAF 和内网防火墙已完成。
- IdP 回调地址、Client ID/Secret、Claim 映射和允许邮箱域已验证。
- `AUTH_COOKIE_SECRET`、`AUTH_ADMIN_TOKEN`、`MAGPIE_ISSUER_KEY` 三值独立且放在密钥管理系统中。
- 企业网关只允许公司网段；员工机网络策略只放行企业网关、更新源和必要 IdP。
- 企业 Provider Key 只存在网关侧，仓库、镜像、日志和员工机均不含真实 Key。
- 已创建测试员工、测试设备、测试模型和测试 MCP，不拿真实员工做首次验证。
- 已备份认证存储、网关数据、数据库和审计配置。

### 20.2 启动与健康检查

```text
反向代理 / TLS
  -> Magpie Gateway /healthcheck 或对应健康接口
  -> Auth /healthz
  -> 管理服务 /healthz
  -> 审计服务 /healthz
```

发布后 10 分钟内检查：登录成功率、Key 签发延迟、模型 5xx、额度异常、撤销队列积压、
设备心跳、审计落库和错误日志。任何一项失败都停止扩大灰度。

### 20.3 备份与恢复

- 认证 JSON/数据库每天备份，Key 元数据和设备状态必须一起备份。
- 网关配置、Provider 密钥引用、模型目录和策略版本一起备份。
- 审计正文和索引分开备份，恢复后验证权限和留存策略仍生效。
- 试点目标 RPO 24 小时；生产目标 RPO 15 分钟、RTO 2 小时。
- 每季度做一次“恢复到一个隔离环境”的演练，不能只在原环境做备份成功检查。

### 20.4 故障与应急

| 故障 | 第一动作 | 降级 |
| --- | --- | --- |
| IdP 不可用 | 检查 discovery/JWKS、网络和回调 | 已缓存短期 Key 继续到过期；禁止新登录 |
| Auth 不可用 | 检查存储、issuer Key、撤销队列 | 网关继续校验现有 Key；禁止刷新和新加入 |
| 网关不可用 | 检查副本、上游 Provider、证书 | 客户端显示明确错误；不自动绕过企业网关 |
| 怀疑 Key 泄露 | 停用设备/员工，吊销 Key | 强制重新登录和新设备注册 |
| 审计写入失败 | 保留本地事件缓冲，告警 | 默认继续请求；合规要求时可切换“无审计即拒绝” |
| 上游模型故障 | 查看错误率，触发路由回退 | 只允许备用企业 Provider |

### 20.5 运维指标

- 登录成功率、OIDC 回调错误、JWKS 刷新失败。
- Key 签发成功率、刷新延迟、撤销队列长度和最长积压时间。
- 网关请求成功率、P50/P95/P99 延迟、上游错误率。
- 每员工/部门/模型/Agent 的 Token、成本和额度耗尽率。
- 设备在线率、最低版本不达标率、资源同步失败率。
- 敏感规则命中、阻断、告警确认和平均处置时间。
- 审计正文写入延迟、留存删除任务、备份恢复成功率。

### 20.6 推荐技术路线

不追求第一版就上最重的组件，按规模演进：

| 能力 | 试点（5-50 人） | 规模化后 |
| --- | --- | --- |
| 认证服务 | 现有 Node 22 服务 + JSON 原子存储 | PostgreSQL + 多副本 + 分布式限流 |
| 管理后台 | 独立 React/TypeScript 管理站 + 独立 API | 同左，接组织范围和审批流 |
| 模型数据面 | 现有 Magpie Gateway | 多副本 + 负载均衡 + Redis 限流 |
| 资源库 | S3/MinIO + 签名 manifest | 对象存储版本控制 + 发布流水线 |
| 元数据/用量 | `usage.jsonl` + OTel Collector | PostgreSQL/ClickHouse + 专用事件管道 |
| 正文审计 | 独立审计服务 + 对象存储 | 分区事件存储、WORM、冷热分层 |
| 密钥 | 环境变量/公司 Secret Manager | Vault/KMS/HSM + 自动轮换 |
| 观测 | OTel + Prometheus/Grafana | 多地域 Collector + SIEM + 告警平台 |

原则是复用 Magpie 已有的模型路由、Agent 适配和网关能力，不在企业版重写一个模型网关；
企业层只补身份、治理、资源、审计和运营能力。

## 21. 迁移、灰度与回滚

### 21.1 从 M0 静态 Key 迁移

1. 保留 M0 网关、员工 Key、额度、模型白名单和 usage，作为回退路径。
2. 在测试组启用 M1 OIDC，给员工同时保留旧 Key 到迁移窗口结束。
3. 员工通过 `join-enterprise.ps1` 加入，客户端使用新短期 Key；旧 Key 记录迁移状态。
4. 管理员按设备确认新 Key 可用、用量归属正确、刷新成功，再撤销旧 Key。
5. 迁移完成后关闭新增长期 Key；保留应急管理员签发流程。

### 21.2 灰度规则

- 先内部 IT/研发 5 人，再一个部门 20-50 人，再全公司。
- 每批至少观察一个完整工作日和一个额度周期。
- 模型、MCP、资源包和客户端版本分别灰度，不能同时全量变更。
- 每批必须有明确成功指标和停止条件；失败只回滚该批，不影响已稳定用户。

### 21.3 回滚规则

- Auth 回滚：保留旧存储备份和 issuer Key，不回滚已经撤销的泄露 Key。
- 网关回滚：切回上一已验证镜像/配置，保留用量和撤销记录。
- 客户端回滚：内网更新源指向上一版本，MDM 重新下发。
- 资源回滚：使用不可变版本和签名 manifest，恢复到上一发布版本。
- 数据迁移回滚：先有备份和逆向脚本；不能把“重新部署”当成数据回滚。

## 22. 最终验收与项目治理

### 22.1 首期上线必须全部通过

| 类别 | 必须通过 |
| --- | --- |
| 身份 | 真实 IdP 登录、MFA、停用用户无法再加入或刷新 |
| 凭证 | 短期 Key 签发、调用、刷新、旧 Key 失效、撤销队列可恢复 |
| 客户端 | 员工 5 分钟内完成加入；浏览器边界说明与本地配置流程一致 |
| 模型 | 白名单外模型被拒绝；额度耗尽有稳定错误；Provider Key 不出网关 |
| MCP | 未授权 MCP/工具不可见、不可调用；远程 MCP 不泄露上游凭据 |
| 资源 | 强制资源不可关闭；失败回滚；漂移可见 |
| 审计 | L0 可按人/部门/Agent/模型/时间检索；正文权限和访问日志可验证 |
| 安全 | IP、设备、异常用量和敏感数据规则可告警/阻断 |
| 运维 | 备份、恢复、健康检查、灰度、回滚和值班责任人均已验证 |
| 上游 | 合并上游后企业构建和全部关键回归通过，失败可自动停在上一发布点 |

### 22.2 责任分工（RACI）

| 工作 | 产品 | 平台研发 | IT 运维 | 安全/合规 | 审计 | IdP 团队 |
| --- | --- | --- | --- | --- | --- | --- |
| 需求和优先级 | A | R | C | C | C | I |
| 企业网关与认证 | C | A/R | C | C | I | C |
| IdP/SCIM 集成 | C | R | C | C | I | A |
| 策略和审计 | A | R | I | A | C | I |
| 发布和回滚 | I | R | A | C | I | I |
| 事件响应 | I | C | R | A | C | C |

`A`=最终负责，`R`=执行，`C`=咨询，`I`=知会。超级管理员不应单独拥有“查看正文 + 删除审计 +
修改留存”三项能力。

### 22.3 上线决策

以下任一条件成立时不得全量上线：

- 真实 IdP 或真实 Magpie 签发链路未验收。
- 撤销队列、停用用户或设备丢失流程不可证明。
- 正文审计权限、留存和删除没有得到安全/合规批准。
- Docker/安装包/更新源没有从干净环境构建验证。
- 企业网关可以被员工通过非企业出口直连绕过。
- 上游同步后的关键回归失败。

## 23. 当前最优先的实施顺序

当前不应继续堆功能，而应按下面的顺序验收已有 C4-03c 核心和 C4-04 真实链路，再推进
C4-03d 剩余页面和 M2-D；C5 后端已实现，进入真实审计存储和生产运维验收。
M2-C1 的 Auth 内部写接口、M2-C2 的四个管理写 API 和 M2-C3 的幂等/intent-result 管理审计
已完成；C4-01 的机器协议和 C4-02 的 `gateway-control` 也已实现，分别通过本地和 Mock/
故障测试。C2 还没有接入管理页，C4-02 还没有 Docker/真实共享卷验收；C4-03c 的额度/模型
API、同步后交付和失败补偿已有 Mock/故障证据；C4-04 完整管理到真实 Magpie 策略流 E2E
已通过，覆盖多凭证、refresh/rotate 继承和故障恢复，但真实共享卷、真实企业 IdP、反向代理
和浏览器自动化仍未验收；C5 后端已提供查询、审计分页与人工对账，但页面接入、真实审计存储
和生产运维演练仍未验收：

1. 在 Docker 可用环境验证 `--profile auth` 和 `--profile admin`：镜像构建、依赖启动顺序、
   healthcheck、重启恢复、持久化卷和日志脱敏。当前开发机没有 Docker CLI，这一步尚未执行。
2. 在真实 Windows 用户会话验证计划任务刷新、锁、网络恢复、凭据文件 ACL 和失败重试。
3. 用真实企业 IdP 分别验收员工端和管理端：登录、MFA/ACR、回调、Claim 映射、
   `email_verified`、条件访问、停用和会话过期。
4. 通过 HTTPS 反向代理验收管理域名、Cookie 域、公司 CA、IP 允许列表，以及
   `AUTH_INTERNAL_ADMIN_TOKEN` 不经过公网。
5. 用至少一个企业管理员、一个部门管理员、一个审计员和一个安全管理员演练 M2-A/M2-B 的
   角色、组织范围和只读视图，确认角色撤销在下一请求生效，跨部门读取被拒绝。
6. 用真实网关写入的 `usage.jsonl` 验证只读数据卷、刷新归属、轮转/归档、损坏恢复和限制
   参数；确认管理容器不能写入网关卷。
7. M2-C3 已完成并通过 Mock：四个管理写 API 已具备 `Idempotency-Key` 持久化/重放/冲突、
   `operationId` 和 intent/result 审计；intent 失败不调用依赖，result 失败不返回成功。
   C4-02 已完成代码和 Mock/故障测试，下一步在 Docker 可用环境验证镜像、Compose、健康检查、
真实共享卷和故障恢复。C4-03a 已完成正式只读目录、坏目录失败关闭和 109 项管理服务测试，
   但还要在真实 Compose 中验证只读挂载和 digest 重启。C4-03b 和 C4-03c 核心已完成，
   下一步验证真实共享卷和部署环境中的 apply/readback、同步后交付和失败补偿。C4-03d 的
   管理页额度/模型写表单和员工只读状态门户已实现，M2-D 已接入基础 operation/audit 查询、
   对账、导出和停用/吊销/轮换页面；下一步补齐浏览器 E2E、失败恢复入口和完整运营体验；
   C4-04 完整管理到真实 Magpie 策略流 E2E 已通过，包括
   多凭证、refresh/rotate 继承和故障恢复；M2-C5 已提供操作/审计查询与失败对账后端，最后用
   M2-D 补齐报表、导出和运营入口。

M2-A/M2-B/M2-C1/M2-C2/M2-C3 已经完成独立管理 OIDC、会话、CSRF、RBAC、组织范围、内部服务
令牌、只读治理、四个管理写 API 和幂等/管理审计，但这不等于完整管理台已经上线。第一条原则仍然不变：**不要用 `AUTH_ADMIN_TOKEN` 扩展
生产管理后台**，也不要把 Mock 测试结果当成真实 IdP、浏览器和反向代理验收。

## 24. 方案默认选择与上线前确认项

以下默认选择用于避免开发过程中反复改方向；企业上线前由产品、IT、安全和合规共同确认：

| 主题 | 默认选择 | 上线前必须确认 |
| --- | --- | --- |
| IdP | OIDC Authorization Code + PKCE；SCIM 作为人员同步增强 | 真实 IdP 的 MFA、Claim、组映射和离职事件 |
| 管理端 | 独立 `admin-service` + 独立 OIDC Client | 管理域名、IP 范围、会话时长和审批人 |
| 数据存储 | 试点 JSON；50-100 人以上迁 PostgreSQL | 备份、恢复、RPO/RTO 和数据驻留 |
| 数据面 | 复用 Magpie Gateway，不自研模型路由核心 | 模型供应商、出口网段、额度和价格版本 |
| MCP | 远程 MCP 优先，本地 MCP 只给受控用户组 | 工具风险、网络出口、签名和沙箱方案 |
| 资源库 | Git/对象存储保存不可变版本，发布走签名 manifest | 谁来审批、如何回滚、是否允许员工自定义 |
| 审计 | 默认 L0 元数据；L2 正文显式授权 | 员工告知、留存期、查看审批和法定保留 |
| 客户端 | 本地 Magpie 执行 Agent 配置；网页只做身份和展示 | MDM、安装包签名、更新源和最低版本 |
| 部署 | 5-50 人 Compose，50-500 人 HA，500+ 人按需 K8s | 公司网络、WAF、证书、值班和容量预算 |
| 发布 | `main` 自动跟随上游，企业版本单独构建和灰度 | 谁有权发版、回滚窗口和变更审批 |

如果上述任一项没有负责人或验收证据，只能继续试点，不能把企业版标记为“生产可用”。

## 25. 企业版完整需求追踪矩阵

本节把“企业功能方案”固化为可执行的需求基线。它回答的不是“最终想做什么”，而是每个能力
由哪个阶段交付、什么条件下算完成、到哪里找证据。实现状态仍以
[`enterprise-implementation-status.md`](enterprise-implementation-status.md) 为唯一事实来源；
本节的状态列只是摘要，不能替代测试记录。

### 25.1 交付包与判定口径

| 交付包 | 覆盖阶段 | 目标人群 | 必须包含 | 允许的使用结论 |
| --- | --- | --- | --- | --- |
| R0 演示包 | M0、Mock 链路 | 产品/研发 | 网关、员工 Key、模型调用、用量归属、Mock IdP/上游 | 只能演示，不接真实员工 |
| R1 受控试点包 | M0-M2-B + 真实环境验收 | 5-50 人单部门 | OIDC、设备、短期 Key、管理登录、RBAC、组织范围、只读治理、备份/吊销手册 | 可做受控技术试点 |
| R2 生产候选包 | M0-M2-D | 50-200 人单企业 | R1 + 敏感写操作、管理审计、额度/模型授权、看板、导出、真实 IdP/代理/Windows 验收 | 可做正式小范围试用 |
| R3 企业生产包 | M3-M5 | 50-500 人 | R2 + 中央 MCP、资源库、客户端策略、L0/L1 审计、告警/SIEM、灰度回滚 | 可全员推广的单企业生产版 |
| R4 规模化包 | M6 | 500+ 人或强合规 | PostgreSQL/ClickHouse、多副本、KMS/mTLS、HA/DR、供应链安全、多地域 | 大规模或高可用生产 |

“方案完整”不表示一次做完 R0-R4。每个交付包都必须独立可验收、可回滚、可停止；R2 通过后
才能把企业版称为“生产候选”，R3 全部通过后才能称为“企业生产版”。

### 25.2 功能需求基线

状态口径：

- `已验证`：有当前仓库内可重复运行的测试，且测试记录在实现状态文档中。
- `部分验证`：核心代码存在，但真实 IdP、Docker、浏览器、代理、Windows 或真实数据卷未验收。
- `已设计`：只有接口、数据模型或验收设计，不能声称可用。
- `未开始`：没有实现，也没有可执行验收证据。

#### 25.2.1 身份、组织与设备（E1/E2）

| ID | 优先级 | 能力 | 阶段 | 完成标准 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| E1.1 | P0 | 员工 OIDC + PKCE 登录 | M1 | 真实 IdP 完成登录、MFA、JWKS、回调、Claim 映射；禁止密码落客户端 | 部分验证 |
| E1.2 | P0 | 独立管理 OIDC + MFA/ACR | M2-A | 管理端独立 Client、回调、Cookie；真实 IdP 拒绝未满足 MFA 的登录 | 部分验证 |
| E1.3 | P0 | 用户、部门、用户组和组织树 | M2-B/M3 | 稳定 ID、不可变组织路径、无环路；服务端按子树过滤 | 部分验证 |
| E1.4 | P0 | 角色绑定、有效期和职责分离 | M2-A/M2-C | 角色撤销在下一请求生效；高风险权限单独绑定；有授予人和到期时间 | 部分验证 |
| E1.5 | P1 | SCIM 2.0/Webhook 人员同步 | M2-C/M3 | 创建、更新、停用、增量同步幂等；离职优先于全量同步 | 未开始 |
| E2.1 | P0 | 设备注册、公钥和用户绑定 | M1 | 重复加入、错误公钥、跨用户绑定均被拒绝 | 已验证 |
| E2.2 | P0 | 设备心跳、客户端版本、在线状态 | M1 | 停用后心跳返回 `403`；管理员看到最后心跳和版本 | 部分验证 |
| E2.3 | P0 | 短期 Gateway Key 签发与续期 | M1 | Key 只保存哈希；旧 Key 在刷新后失效；失败无孤儿 Key | 已验证 |
| E2.4 | P0 | 设备/用户吊销和立即阻断 | M1/M2-C | 停用用户、吊销设备后刷新、心跳和当前 Key 均失效 | 部分验证 |
| E2.5 | P1 | 设备合规、证书和 MDM 状态 | M3/M5 | 磁盘加密、EDR、版本和合规状态可查询；不合规按策略降级 | 未开始 |
| E2.6 | P1 | 离线恢复、重启恢复和撤销队列 | M1/M2-C | 服务重启后状态保留；撤销队列可重放且不丢事件 | 已验证（本地） |

#### 25.2.2 员工本地 Magpie、网页与 Agent（E3）

| ID | 优先级 | 能力 | 阶段 | 完成标准 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| E3.1 | P0 | 员工登录、身份、设备和策略状态页 | M1/M2-D | 员工只看到本人摘要；网页不返回 Key、设备令牌或他人数据 | 部分验证 |
| E3.2 | P0 | 本地 Magpie 一键配置 Agent | M0/M1 | 至少完成 Claude Code、Codex、OpenCode 中一种真实客户端验收 | 部分验证 |
| E3.3 | P0 | 企业 Provider 和模型选择 | M0/M2-D | 员工不能编辑厂商 Key；未授权模型不可见且调用被拒绝 | 部分验证 |
| E3.4 | P0 | 本人用量、额度和错误状态 | M2-D | 本人 Token、费用、周期和错误可查；不显示全公司汇总 | 未开始 |
| E3.5 | P0 | 网页与本地执行的权限边界 | M1 | 网页只做登录、授权和展示；本机文件由本地 Magpie/helper 修改 | 已验证（脚本边界） |
| E3.6 | P1 | 资源、MCP、Skills、Instructions 视图 | M3 | 强制项只读、推荐项可启停；显示期望/实际版本和漂移 | 未开始 |
| E3.7 | P1 | 客户端企业预置、MDM 和更新通道 | M3/M5 | 内网更新源、签名包、最低版本和回滚通道通过实机验收 | 未开始 |

#### 25.2.3 管理控制台、RBAC 与敏感操作（E4）

| ID | 优先级 | 能力 | 阶段 | 完成标准 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| E4.1 | P0 | 管理登录、会话、CSRF、IP 限制 | M2-A | 过期、绑定不匹配、CSRF 错误和 IP 不在范围返回稳定错误 | 已验证（Mock） |
| E4.2 | P0 | 用户、部门、设备、凭证、模型、用量只读视图 | M2-B | 全域管理员可读全域；部门管理员只读本子树；响应无秘密 | 已验证（Mock） |
| E4.3 | P0 | 停用/启用员工 | M2-C1/C2/C3 | 需要权限、范围、CSRF、幂等键和理由；先写 intent 再调用依赖 | 内部接口、管理 API、幂等和管理审计已验证（Mock） |
| E4.4 | P0 | 吊销设备和轮换凭证 | M2-C1/C2/C3 | 旧 Key 失效、刷新失败、无活跃孤儿 Key；全过程可追溯 | 内部接口、管理 API、幂等和管理审计已验证（Mock） |
| E4.5 | P0 | 额度修改和模型授权 | M2-C4 | 真实 Magpie 生效，页面显示待同步/已生效，不伪造成功 | 底层机器协议、受控适配器、正式目录、auth-service 策略核心和管理 API/自动 apply/readback/同步后交付核心已实现；C4-04 完整管理到真实 Magpie 策略流 E2E 已通过，覆盖双设备、限流、模型拒绝、部分失败、refresh/rotate 继承和故障恢复；C4-03d 剩余页面和真实部署验收未完成 |
| E4.6 | P0 | 幂等、版本冲突和操作查询 | M2-C3/C5 | 同键同请求只执行一次；同键不同请求体返回 `409`；可按操作 ID 查询 | 幂等和执行中保护已验证（Mock）；C5 操作查询、审计分页和人工对账后端已通过 Mock/故障测试；页面接入待 M2-D |
| E4.7 | P0 | 管理审计 intent/result | M2-C3 | 审计失败时依赖调用次数为 0；result 失败不返回成功；审计只追加且不含秘密 | 已验证（Mock）；真实审计存储待验收 |
| E4.8 | P0 | 看板、筛选、分页和运营入口 | M2-D | 按人/部门/Agent/模型/时间出报表；大报表可异步下载 | 未开始 |
| E4.9 | P1 | 审批、二次认证和职责分离 | M2-E/M5 | 高风险操作有审批或 step-up；正文/导出/角色修改不能单人不留痕完成 | APR-01a 已实现管理写审批、职责分离和一次性消费；APR-01c 已实现 H/C 写操作和审批决策所需的新鲜独立 step-up；正文/导出/角色修改等高风险审批及真实 IdP/MFA 验收仍未完成（见 A1-A8） |

#### 25.2.4 企业模型网关与用量成本（E5/E6）

| ID | 优先级 | 能力 | 阶段 | 完成标准 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| E5.1 | P0 | OpenAI/Responses/Anthropic 兼容数据面 | M0 | 员工经本地 Magpie 到企业网关到上游成功；网关持有厂商 Key | 已验证（Mock 上游） |
| E5.2 | P0 | 模型白名单、路由、回退和禁用 | M0/M2-C | 白名单外模型拒绝；路由失败按策略回退；模型使用稳定 ID | 部分验证 |
| E5.3 | P0 | 人/部门/Agent/模型/时间维度额度 | M0/M2-C | 超额限流；管理员修改额度后真实网关生效 | M0 手工额度能力、C4-01 机器协议、C4-02 受控适配器和 C4-03b 用户级策略核心已具备；管理端自助修改、自动同步和真实网关行为 E2E 未完成 |
| E5.4 | P0 | IP/设备/用户/服务端鉴权 | M0/M1 | 非公司网段、停用用户、吊销设备和非法 Key 均被拒绝 | 部分验证 |
| E5.5 | P1 | 请求大小、并发、速率、超时和输出限制 | M0/M5 | 超限稳定返回；不同租户/部门互不影响 | 部分设计 |
| E5.6 | P1 | 模型价格、预算和成本告警 | M2-D/M5 | 价格版本可追溯；预算超额产生告警并可阻断 | 部分设计 |
| E6.1 | P0 | `usage.jsonl` 元数据归属和查询 | M0/M2-B | `callerKeyId -> credential -> user -> 组织` 归属正确 | 部分验证 |
| E6.2 | P0 | 人/部门/Agent/模型/API Key 报表 | M2-D | 支持筛选、分页、时间和导出；损坏数据不生成部分报表 | 部分验证 |
| E6.3 | P1 | OTel/SIEM 指标和异常用量 | M5 | 指标可查询、告警可配置、敏感字段不外泄 | 未开始 |

#### 25.2.5 中央 MCP 治理（E7）

| ID | 优先级 | 能力 | 阶段 | 完成标准 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| E7.1 | P1 | MCP 目录、负责人、类型和健康状态 | M3 | 管理员可登记和查询远程/本地 MCP；未授权用户不可见 | 已设计 |
| E7.2 | P1 | 远程 MCP 网关代理 | M3 | 客户端只拿企业地址；上游 OAuth/Key 只在网关；工具调用可审计 | 已设计 |
| E7.3 | P1 | 工具级 allow/deny 和风险等级 | M3 | 未授权工具不可调用；读写/执行工具分级；高风险操作需审批 | 已设计 |
| E7.4 | P1 | 本地 MCP 签名、沙箱和 Secret Reference | M3 | 未签名包不能运行；文件/网络/命令范围受限；密钥不下发 | 已设计 |
| E7.5 | P1 | 健康检查、限流、熔断和告警 | M3/M5 | MCP 故障不影响其他资源；管理员看到状态和错误 | 已设计 |
| E7.6 | P1 | MCP 发布、灰度、回滚和漂移 | M3 | 指定员工 5 分钟内可见；失败回退上一版本；期望/实际版本可见 | 已设计 |

#### 25.2.6 企业资源库与客户端策略（E8/E9）

| ID | 优先级 | 能力 | 阶段 | 完成标准 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| E8.1 | P1 | Skills、Instructions、Subagents、模板目录 | M3 | 版本不可变、可分配、可查询、可归档 | 已设计 |
| E8.2 | P1 | manifest、哈希、签名和审批 | M3 | 客户端拒绝未签名/哈希不符内容；每次发布有发布者和审批记录 | 已设计 |
| E8.3 | P1 | 部门/组/用户/设备范围 | M3 | 跨范围不可见；分配和撤回均写审计 | 已设计 |
| E8.4 | P1 | 同步、离线缓存、漂移和回滚 | M3 | 客户端离线可用；新版本失败回退；管理台看到同步错误 | 已设计 |
| E8.5 | P1 | Secret Reference 和轮换 | M3 | 资源包无明文秘密；轮换不重新发布资源；管理员只见元数据 | 已设计 |
| E9.1 | P1 | 企业 Gateway/Provider 锁定 | M3 | 企业地址不可删除、非企业 Provider 不可添加、策略过期可降级 | 已设计 |
| E9.2 | P1 | 强制资源锁定和离线策略 | M3 | 强制资源不可关闭；离线使用最后一个已验签版本 | 已设计 |
| E9.3 | P1 | 防绕过组合控制 | M3/M5 | 网络出口、MDM/EDR、设备凭证和网关鉴权共同生效，不能只靠隐藏按钮 | 已设计 |
| E9.4 | P1 | 企业配置优先级和冲突处理 | M3 | 企业强制 > 企业推荐 > 员工自定义；冲突不静默覆盖 | 已设计 |

#### 25.2.7 会话、工具调用、内容审计与通知（E10）

| ID | 优先级 | 能力 | 阶段 | 完成标准 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| E10.1 | P0 | L0 请求元数据 | M0/M4 | 人/部门/设备/Agent/模型/状态/Token/费用/延迟/IP 可检索 | 部分验证 |
| E10.2 | P1 | L1 摘要和工具调用 | M4 | 工具名、参数类别、结果状态和策略命中可检索，不含正文 | 未开始 |
| E10.3 | P2 | L2 脱敏正文 | M4 | 显式授权、二次确认、目的、水印、访问审计和留存全部生效 | 未开始 |
| E10.4 | P2 | L3 原始正文 | M4 | 默认关闭；双人审批、短保留、法定调查和不可删除访问审计 | 未开始 |
| E10.5 | P1 | 流式拼接、幂等和异步投递 | M4 | 断流/重试可恢复；重复事件不重复计费；积压可告警 | 未开始 |
| E10.6 | P1 | 检索、导出、留存和删除证明 | M4 | 按范围检索；加密导出；删除后可验证；法律保留优先 | 未开始 |
| E10.7 | P1 | 审计访问与正文分离 | M4 | 元数据、摘要、正文、附件分权；管理员访问不能被普通管理员删除 | 未开始 |
| E10.8 | P0 | 通知 outbox 与多渠道投递 | M2-E/M5 | 业务提交不等待渠道；outbox 可恢复，邮件/IM/Webhook/SIEM/工单可重试、死信、人工重放且不含秘密 | NOTIFY-01a 的 outbox、租约、重试、死信、deliveries 查询和人工重放已实现；NOTIFY-01b 的 email/im/webhook/ticketing 渠道管理、渠道测试和统一 HTTPS 网关适配器已实现并通过 Mock/故障测试；NOTIFY-01c 的 SIEM transport、固定 L0 schema 和 dead-letters API 已实现并通过 6 项专项测试；NOTIFY-01d 的规则、抑制、聚合、升级、受审计重放和运营页已实现并通过 7 项专项测试；真实 SIEM、真实厂商连接、生产值班和生产验收未完成（见 N1-N8） |

#### 25.2.8 安全运营与合规（E11）

| ID | 优先级 | 能力 | 阶段 | 完成标准 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| E11.1 | P1 | 异常用量、异地、越权、直连检测 | M5 | 典型规则可稳定复现，误报可抑制/聚合 | 已设计 |
| E11.2 | P1 | 限流、阻断、吊销和设备锁定 | M5 | 一键响应有审批/理由/审计；响应动作可撤销 | 已设计 |
| E11.3 | P1 | 敏感数据检测和落盘前脱敏 | M4/M5 | Key、密码、身份证、银行卡、私钥等不进入日志/正文存储 | 部分设计 |
| E11.4 | P1 | 安全事件证据链 | M5 | 事件、请求、管理员访问和响应动作可串联，不可静默删除 | 已设计 |
| E11.5 | P2 | 法规/行业合规评审 | 上线前 | 员工告知、数据保护影响评估、留存和跨境策略有签字 | 未开始 |

#### 25.2.9 交付、部署、规模化与上游治理（E12）

| ID | 优先级 | 能力 | 阶段 | 完成标准 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| E12.1 | P0 | Compose/健康检查/持久化 | M1/M2 | 干净环境拉起 auth/admin/gateway，重启后状态恢复 | 未执行（无 Docker CLI） |
| E12.2 | P0 | HTTPS、反向代理、Cookie 和公司 CA | M2 | 浏览器 E2E 通过；内部令牌不经过公网 | 未执行 |
| E12.3 | P0 | 备份、恢复、灰度和回滚 | M2/M6 | 隔离环境恢复成功；RPO/RTO 有记录；发布可回退 | 未执行 |
| E12.4 | P1 | OTel、Prometheus/Grafana、日志和告警 | M5 | 登录、签发、请求、撤销、同步和审计延迟可见 | 未开始 |
| E12.5 | P1 | PostgreSQL/ClickHouse 和迁移工具 | M6 | 迁移可验证、可回滚；数据一致性和容量达标 | 未开始 |
| E12.6 | P1 | 多副本、Redis 限流和 HA | M6 | 单节点故障不影响请求；共享会话和权限一致 | 未开始 |
| E12.7 | P2 | Vault/KMS、mTLS、SBOM、镜像签名 | M6 | 密钥不落明文；制品可验证；渗透和供应链扫描通过 | 未开始 |
| E12.8 | P0 | `main` 只同步上游与已验收企业提交 | 全阶段 | 服务端分支保护开启；禁止直接开发/推送 main；同步只能提 PR | 文档已定义，GitHub 规则待确认 |
| E12.9 | P0 | 每功能独立分支、小 PR 和定期同步 | 全阶段 | 每个功能从最新 main 开分支；冲突在功能分支解决；不直接推送 main | 工具已具备 |
| E12.10 | P0 | 企业代码隔离 | 全阶段 | 优先 `enterprise/*`、插件、最小 hook；默认不影响个人用户 | M0-M2-B 满足 |
| E12.11 | P0 | 上游同步后回归门禁 | 全阶段 | Go/Node 单测、M0 E2E、M1/M2 测试和构建全部通过 | 本地部分通过，CI 待配置 |
| E12.12 | P0 | 独立企业发布/回滚 | 全阶段 | 只从已验收 tag/release 构建；上一版本可恢复数据和配置 | 未演练 |

#### 25.2.10 M2-C4/C5/D 交付基线（C4/C5/D）

本表是 C4/C5/D 的需求追踪入口。状态按独立切片记录，只有
[`enterprise-implementation-status.md`](enterprise-implementation-status.md) 记录了实际测试命令和
结果时才允许标为已实现。

| ID | 优先级 | 能力 | 阶段 | 完成标准 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| C4.1 | P0 | 用户级 `gatewayPolicy` | M2-C4 | 模型、0-5 个额度窗口、版本和 `known/unknown/pending` 状态持久化；新签发、refresh、rotate 继承 | auth-service 核心已实现，26/26 测试通过；管理端自动编排已接通 |
| C4.2 | P0 | 额度修改 API | M2-C4 | `PUT /users/{id}/quota` 具备会话、CSRF、RBAC、范围、理由、版本、幂等和 intent/result 审计 | 已实现，管理 109/109 覆盖；管理页写表单已接入，真实环境待验收 |
| C4.3 | P0 | 模型授权 API | M2-C4 | `PATCH /users/{id}/models` 只接受稳定模型 ID；未知、空数组和隐式扩大范围被拒绝 | 已实现，管理 109/109 覆盖；管理页写表单已接入，真实环境待验收 |
| C4-01 | P0 | 网关机器协议 | M2-C4-01 | schema v1 的 `describe --json` 和原子 `policy apply --json`；64 KiB、稳定错误、无秘密、冲突不写、独立回读 | 已实现；Go 单测、CLI 回归和隔离真实二进制冒烟通过 |
| C4-02 | P0 | 受控网关适配器 | M2-C4-02 | 管理服务不读写 `caller-keys.json`；专用 `gateway-control` 只执行白名单命令、10 秒超时、回读确认并映射稳定错误 | 已实现；15 项 Mock/故障测试通过；Docker/真实共享卷、admin-service 接入和 mTLS 待验收 |
| C4-03a | P0 | 正式模型目录 | M2-C4-03a | 只读 `ADMIN_MODEL_CATALOG_PATH`、稳定模型 ID、显式 Provider 通配符、group 展开、目录版本/摘要；坏目录失败关闭 | 已实现；82 项管理服务集成和 7 项目录专项等合计 109 项管理测试通过；真实 Compose/digest 验收待完成 |
| C4-03b | P0 | 首次策略初始化与 `unknown` 迁移 | M2-C4-03b | 旧 M1 显式 `unknown`；`quota`/`models` 可分别先提交但不得伪造另一项；两项完整并逐凭证回读后才 `known` | auth-service 核心已实现，26/26 测试通过；管理端编排已接通，真实部署待验收 |
| C4-03c | P0 | 管理 API、新 Key 同步后交付 | M2-C4-03c | 管理 API 门禁、签发 journal/幂等关联、apply、独立回读、原子持久化、成功后交付；任一步失败撤销，崩溃恢复不留下孤儿 Key | 核心已实现，Mock/故障测试通过；真实环境待验收 |
| C4-03d | P0 | 页面与运营状态语义 | M2-C4-03d | `unknown/pending/partial_success/dependency_invoked` 显示可解释；只有完整证据链才可显示“已生效” | 部分实现；管理页写表单/证据链和员工只读状态门户已有，基础查询/对账和停用/吊销/轮换页面已接入；浏览器 E2E、失败恢复入口、完整运营体验和生产验收未完成 |
| C4-04 | P0 | 真实 Magpie 请求行为 E2E | M2-C4-04 | 真实限额、模型拒绝、多凭证、refresh/rotate 继承、故障注入和回读一致；不接触真实用户目录或 `127.0.0.1:3425` | 完整管理到真实 Magpie 策略流 E2E 已通过：首次 join `409`、管理 OIDC/CSRF、quota/models 分步设置、双设备独立 Key、模型拒绝/限额、`partial_success`、refresh/rotate 继承、故障后 pending、Journal/孤儿 Key 撤销、恢复同步、usage 归属和秘密扫描 |
| C4-05 | P0 | 部分成功和旧凭证迁移 | M2-C4 | 逐凭证返回成功/失败；部分失败为 `partial_success` 且策略保持 `pending` | C4-04 已验证双设备部分失败、精确失败凭证和恢复后重新 `synced`；旧 M1 凭证迁移、更多故障组合和生产部署验收仍未完成 |
| C4-06 | P0 | 用户级策略端到端组合门禁 | M2-C4 | C4.1-C4.3 与 C4-01-C4-05 全部通过，并具备真实环境、失败补偿、秘密扫描和回滚证据 | 组合门禁未通过；C4-03a/C4-03b/C4-03c 核心和 C4-04 真实管理链路已有证据，C4-03d 页面、C4-05 完整迁移、真实共享卷/IdP 和生产回滚仍待验收 |
| C5.1 | P0 | 操作查询 | M2-C5 | `GET /operations/{operationId}` 返回真实状态、依赖调用时间、失败项、重试/对账状态和安全摘要 | 后端和 M2-D 基础页面已实现并通过 Mock/故障测试；浏览器 E2E 和生产验收待完成 |
| C5.2 | P0 | 管理审计查询 | M2-C5 | `GET /audit-logs` 支持 operationId、操作者、目标、动作、结果、时间过滤；按组织范围授权并脱敏 | 后端和 M2-D 基础页面已实现并通过 Mock/故障测试；真实审计存储和浏览器 E2E 待验收 |
| C5.3 | P0 | 人工对账与补偿 | M2-C5 | 支持重试目标策略、回滚上一确认版本和凭证据确认；每次动作生成子 operation 并追加审计 | 后端和 M2-D 基础页面已实现并通过 Mock/故障测试；生产运维演练待完成 |
| D1 | P0 | 管理写操作 UI | M2-D | 额度、模型、停用、吊销、轮换均展示理由、审批、版本、operationId 和真实同步状态 | 部分实现：额度/模型写表单、审批、operation 和人工对账页面已有；停用、吊销、轮换页面未实现 |
| D2 | P0 | 用量/费用看板 | M2-D | 按人、部门、Agent、模型和时间筛选；损坏用量不生成部分报表 | 已实现筛选、分页、趋势和受控导出核心并通过 Mock/集成测试；真实用量卷、浏览器 E2E、对象存储和异步大批量导出未验收 |
| D3 | P0 | 授权导出与操作历史 | M2-D | 导出有独立权限、审批、一次性链接和审计；操作历史从 C5 读取 | 已实现 CSV 用量/审计导出、独立权限、审批、fresh step-up、一次性 token、会话 Cookie 绑定、幂等和下载审计；Excel、对象存储、异步大导出和分布式锁未实现 |
| D4 | P0 | 员工本人状态页 | M2-D | 显示本人额度、模型范围、凭证状态和恢复提示；不返回他人数据或秘密 | 部分实现：本人额度、模型、凭证、设备和同步状态只读门户已有；完整恢复操作和真实浏览器 E2E 未完成 |

编号规则：`C4.x` 表示管理员可见的管理 API 或策略对象；`C4-xx` 表示可独立测试和交付的技术
切片；`C4-06` 是组合门禁，不是新的业务能力。PR、测试记录和发布证据必须同时写清所属管理
API、技术切片和组合门禁，禁止用 `C4.2a` 一类重复语义的编号。

#### 25.2.11 M2-E 审批与通知投递基线（APR-01/NOTIFY-01）

本表是 M2-E 的需求追踪入口。审批采用 `external` 优先、`step_up` 组合、`builtin` 后续补齐的
路线；通知统一走 transactional outbox，不允许业务请求同步等待邮件、IM、Webhook、SIEM 或
工单。`APR-01a` 的服务端审批、绑定、职责分离、一次性消费和系统审计已实现并通过 Mock/
故障测试；`APR-01b` 的 HMAC 外部审批回调适配器、时间窗、nonce 防重放、issuer/audience、
eventId 幂等和系统审计也已实现并通过 Mock/故障测试；`APR-01c` 的独立 OIDC step-up
已实现并通过 Mock IdP 集成测试。`NOTIFY-01a` 的 transactional outbox、租约、重试、
死信、重启恢复、deliveries 查询和受审计人工重放已实现并通过 Mock/故障测试；
`NOTIFY-01b` 的渠道管理 API、渠道测试和统一 HTTPS 邮件/IM/Webhook/工单网关适配器已实现
并通过 Mock/故障测试，但不等于真实厂商连接。`NOTIFY-01c` 的 SIEM transport、固定 L0
schema、dead-letters API 和 critical 优先已实现并通过 6 项专项测试；真实
SIEM/Collector/Syslog/生产证书未验收。审批箱、串并行、quorum、转交和撤回已实现，
break-glass 的 15 分钟单次授权、24 小时复核、提醒、通知、审计、API 和管理页已完成
Mock/集成核心；`NOTIFY-01d` 的规则、抑制、聚合、升级、受审计重放和完整运营 UI 已完成
Mock/集成核心；
真实 OA、真实 IdP/MFA、反向代理、
浏览器审批流程、真实厂商渠道和生产回调演练均未验收。

| ID | 优先级 | 能力 | 工作包 | 完成标准 | 当前状态 |
| --- | --- | --- | --- | --- | --- |
| A1 | P0 | 风险分级与审批绑定 | APR-01a | 服务端按动作、目标、批量大小、数据分级和组织范围计算 L/M/H/C；审批绑定组织、动作、目标、资源范围、风险、规范化 payload SHA-256、策略版本和有效期 | APR-01a 已实现并通过 Mock/故障测试；真实 OA 未接入 |
| A2 | P0 | 审批状态机 | APR-01a | 覆盖 requested、pending_approval、approved、rejected、expired、revoked、reserved、consumed 和执行结果；非法迁移与跨状态重放稳定拒绝 | APR-01a 已实现并通过 Mock/故障测试；审批管理 UI 未实现 |
| A3 | P0 | 外部审批适配器 | APR-01b | 飞书/OA/ServiceNow/Jira 等回调必须验签、校验 issuer/audience/时间窗/nonce 和重放缓存；外部批准不能直接执行业务动作 | HMAC-SHA256/Mock 适配器已实现并通过测试：原始 body 验签、300 秒时间窗、nonce 防重放、issuer/audience、eventId 幂等、职责分离和系统审计；真实飞书/OA/ServiceNow/Jira 连接器与生产回调演练未实现/未验收 |
| A4 | P0 | step-up 重新认证 | APR-01c | 独立管理 OIDC Client、PKCE、MFA/ACR、`max_age`；绑定会话、用户、浏览器/IP 策略和角色范围；默认 10 分钟、关键操作 5 分钟有效 | 已实现并通过 Mock IdP 集成测试：独立 Client/secret/redirect/scopes、`prompt=login`、`max_age`、essential `auth_time`、ACR/MFA、IdP `sub`/email、会话/IP/UA/角色范围摘要绑定、H/C 门禁、logout/过期清理和未配置失败关闭；真实 IdP/MFA/反向代理/浏览器流程未验收 |
| A5 | P0 | 职责分离与自审批拒绝 | APR-01a/APR-01d | 申请人不能审批自己的请求；审批人状态、权限、组织范围和自身 step-up 均有效；需要的串行/并行步骤全部满足 | APR-01a 已实现自审批拒绝、审批权限和组织范围校验；APR-01c 已强制审批决策使用审批人的新鲜独立 step-up；APR-01d 已实现串行/并行步骤、活动步骤权限和 quorum，并通过 Mock/故障测试 |
| A6 | P0 | 一次性消费与防重放 | APR-01a | `approval_consumptions` 以 approvalId/operationId/payloadHash 唯一约束原子消费；并发、重复请求和重启恢复只产生一个业务结果 | APR-01a 已实现原子预留、一次性消费、并发拒绝和 reserved 启动恢复，并通过 Mock/故障测试 |
| A7 | P0 | break-glass 紧急流程 | APR-01e | 短时有效、单独高风险告警、禁止静默使用；固定时限内完成任务单和事后复核；到期自动失效并保全证据 | Mock/集成核心已实现：15 分钟有效、单次原子消费、24 小时复核、提醒、四类通知、审计、API 和管理页；真实 IdP/MFA、SIEM/告警、OA/工单、外部工单 ID 回读、浏览器 E2E、5 分钟告警/工单 SLA 和 24 小时生产复核演练未验收 |
| A8 | P0 | 审批、operation 与审计串联 | APR-01a/b/c | 审批、intent/result、operation、通知和外部工单可按 `operationId` 串联；拒绝、过期、撤销、消费和补偿均可追溯且不含秘密 | APR-01a 已实现审批、operation 和管理系统审计串联；NOTIFY-01a 已将审批/operation 事件写入同一原子提交的 outbox；NOTIFY-01b 已提供通用 HTTPS 工单网关契约；原生厂商工单集成、真实投递和外部工单 ID 回读未验收 |
| N1 | P0 | transactional outbox | NOTIFY-01a | 业务状态、审计和 outbox 事件在同一事务/文件锁提交；业务响应不等待外部渠道；至少一次投递并以 `eventId` 去重 | NOTIFY-01a 已实现并通过 Mock/故障测试：审批/结果审计与 outbox 同一次 JSON Store mutation 提交，稳定 `eventId`/`deliveryId` 幂等；NOTIFY-01b 在渠道启用且有 transport 时启动 dispatcher，默认禁用渠道，不会伪造投递 |
| N2 | P0 | 租约、重试、死信与恢复 | NOTIFY-01a | pending/leased/delivering/delivered/retry_wait/dead_letter 状态可查询；指数退避、租约超时回收、进程重启恢复和人工重放均可用 | NOTIFY-01a 已实现并通过 Mock/故障测试：状态机、1/5/15/60/360 分钟退避、租约超时回收、重启恢复、死信和受审计人工重放可用；deliveries 查询无 cursor，尚无真实渠道验收 |
| N3 | P0 | 邮件与企业 IM | NOTIFY-01b | SMTP/Graph/邮件网关和飞书/Teams/Slack 机器人可配置、可测试；限制收件人域、附件、超时和消息大小；凭据只在 Secret Manager | 已实现统一 HTTPS 邮件/IM 网关适配器、渠道管理/测试和域名/大小限制；不是原生 SMTP、Graph、飞书、Teams 或 Slack SDK，真实厂商连接与测试域未验收 |
| N4 | P0 | 通用 Webhook | NOTIFY-01b | 仅 HTTPS 和允许列表；HMAC 时间戳/nonce 签名；限制响应体、超时和重定向；防 SSRF、私网探测和 DNS rebinding | 已实现并通过 Mock/故障测试：仅 HTTPS:443、host allowlist、固定 DNS 解析、拒绝私网/回环/链路本地/云元数据、仅 307/308 最多 3 跳且每跳复验、超时和响应体上限；真实接收端未验收 |
| N5 | P0 | SIEM 投递 | NOTIFY-01c | Syslog/OTel/HTTP Collector 使用稳定 schema；严重安全事件 5 分钟内可见；正文和秘密不进入事件；死信进入值班看板 | SIEM transport 已实现并通过 6 项专项及管理回归：`http-collector`/`otlp-http`/`syslog-tls`、固定 L0 schema、HTTPS:443/TLS:6514、allowlist、固定 DNS、SSRF 防护、HTTP/OTLP 可选 Bearer `secretRef`、Syslog 禁止 `secretRef`、默认 32 KiB 事件上限、critical 优先、5 分钟轮询上限和 dead-letters API；真实 SIEM/Collector/Syslog/生产证书和完整值班看板未验收 |
| N6 | P0 | 工单联动 | NOTIFY-01b | ServiceNow/Jira/飞书工单可创建和关联事件，保存外部工单 ID；失败重试、死信和人工补单不伪造成功 | 已实现统一 HTTPS 工单网关适配器、渠道管理和可验证投递/重试契约；不是 ServiceNow/Jira/飞书原生 SDK，真实租户、字段映射、外部工单 ID 和生产补单演练未验收 |
| N7 | P0 | 抑制、聚合与证据保全 | NOTIFY-01a/d | 可按规则聚合并抑制外部打扰，但不丢弃原始安全事件；抑制原因、范围、到期和恢复均写审计 | NOTIFY-01d 已实现规则匹配、抑制窗口、聚合维度/窗口、阈值/延迟升级、aggregates/suppressions/escalations 查询和审计；原始事件保持在 outbox/delivery 证据中，不因抑制而删除；生产值班策略仍需真实验收 |
| N8 | P0 | 通知脱敏与运营查询 | NOTIFY-01b/c/d | 事件使用固定 schema 和字段白名单；不包含 Gateway Key、token hash、Cookie、OIDC/服务 token、Prompt/回复正文和完整工具参数；投递、重试、抑制和死信可审计查询 | NOTIFY-01a 的 deliveries 查询、字段白名单、存储脱敏和死信重放，NOTIFY-01b 的渠道 Secret 引用和出站请求脱敏，NOTIFY-01c 的 SIEM 固定 L0 schema 和 dead-letters API，以及 NOTIFY-01d 的规则/抑制/聚合/升级查询与运营页已通过 Mock/集成测试；真实厂商、SIEM、浏览器 E2E 和生产值班未验收 |

### 25.3 端到端验收场景

每个场景都必须有执行日期、环境、执行人、命令/操作、原始证据、结果和复核人。只有 UI 截图
不算通过；涉及权限和秘密的场景必须同时检查服务端响应、日志和存储。

| 场景 | 必测步骤 | 通过标准 | 对应需求 |
| --- | --- | --- | --- |
| S1 新员工加入 | OIDC 登录 -> 设备注册 -> 短期 Key -> 本地 Magpie -> Agent | 5 分钟内完成；员工机无厂商 Key；用量归属正确 | E1.1/E2.1/E2.3/E3.2 |
| S2 日常调用 | Agent -> 本地 Magpie -> 企业网关 -> 允许模型 | 成功、限额、白名单、错误码和用量均可解释 | E5.1/E5.2/E5.4/E6.1 |
| S3 自动刷新 | 计划任务刷新、断网、重启、锁冲突 | 新 Key 可用、旧 Key 失效、失败可恢复且日志无秘密 | E2.3/E2.6 |
| S4 离职/挂失 | 管理员停用用户或吊销设备 | 心跳、刷新、当前 Key 全部失效；intent/result 审计完整 | E2.4/E4.3/E4.4/E4.7 |
| S5 跨部门越权 | 修改 URL、请求体、批量目标、分页参数 | 全部返回 `403 forbidden_scope`；不调用依赖 | E4.2/E4.3/E4.4 |
| S6 幂等与审计故障 | 重复请求、同键异体、审计存储不可写 | 只执行一次；同键异体 `409`；审计失败依赖调用为 0 | E4.6/E4.7 |
| S7 额度/模型授权 | 管理员调额、改模型；多凭证更新、部分失败、refresh/rotate 继承、真实网关验证 | 新额度/模型真实生效；旧凭证不伪造额度；部分失败返回 `partial_success` 且可对账；失败不显示已生效 | E5.2/E5.3/E4.5/C4.1-C4.3/C4-01-C4-06 |
| S8 MCP 越权 | 未分配 MCP/工具直接调用、伪造地址 | 不可见、不可调用；只返回稳定拒绝响应 | E7.1/E7.2/E7.3 |
| S9 资源回滚 | 发布坏资源、签名错误、客户端版本过低 | 回退上一版本；上报漂移；强制资源不可关闭 | E8.2/E8.4 |
| S10 审计权限 | 审计员查元数据、申请正文、导出 | 默认只读元数据；正文需独立权限、理由和访问审计 | E10.1-E10.7 |
| S11 安全告警 | 异常用量、敏感数据、异地、直连、越权 | 5 分钟内告警；响应动作可追踪、可撤销 | E11.1-E11.4 |
| S12 部署恢复 | 干净 Compose、重启、备份恢复、回滚 | healthcheck 通过；状态恢复；RPO/RTO 达标 | E12.1-E12.3 |
| S13 上游同步 | 同步 upstream -> 冲突处理 -> 全回归 -> 企业发布 | 企业构建通过；失败停在上一已验证发布点 | E12.9/E12.11/E12.12 |
| S14 审批与 step-up | 高风险动作发起 -> 风险判定 -> step-up -> 外部审批 -> 预留/消费 -> 执行 -> 审计；再覆盖伪造、过期、撤销、自审批、改 payload、并发消费和 break-glass | 未满足审批或 ACR 时依赖调用为 0；同一 operation 只执行一次；自审批和改 payload 被拒绝；break-glass 强制告警并在 24 小时内完成复核 | A1-A8/E4.9/E11.2 |
| S15 通知 outbox 与安全运营投递 | 业务提交 -> outbox -> 邮件/IM/Webhook/SIEM/工单；注入渠道 5xx、超时、重启、重定向和 DNS 变化，再执行死信重放与抑制 | 业务成功不依赖渠道；事件至少一次且可去重；重启不丢事件；重试/死信/人工重放可追踪；Webhook 防 SSRF；SIEM 无正文和秘密 | N1-N8/E10.8/E12.4 |

### 25.4 M2-C 的执行门禁

M2-C 是当前从“可看”进入“可管”的关键阶段。为避免一次性改太多，必须按以下顺序执行；
前一项未通过，不进入下一项。C1 只代表 Auth 内部安全切片完成，不代表管理台已经能写：

| 顺序 | 工作包 | 范围 | 当前状态 | 退出条件 |
| --- | --- | --- | --- | --- |
| C1 | auth-service 内部写接口 | 停用/启用、设备吊销、凭证轮换 | 已完成并通过 Mock 测试；管理页面未接入 | 独立服务令牌、目标校验、撤销队列和失败回滚测试通过；管理入口由 C2 提供 |
| C2 | admin-service 写接口与权限映射 | 四个对外写 API、组织范围、角色权限、理由和响应脱敏 | 已完成并通过 Mock 测试；管理页未接入 | 跨部门写拒绝；审计员/安全管理员职责边界正确；真实环境待验收 |
| C3 | 幂等、操作状态和审计状态机 | `Idempotency-Key` 持久化/重放/冲突、intent/result、operationId | 已完成并通过 Mock 测试 | 审计失败时依赖调用为 0；重复请求只产生一个业务结果 |
| C4-01 | 网关机器协议 | schema v1 的 `describe --json` 和原子 `policy apply --json` | 已实现并通过本地测试 | 64 KiB、稳定错误、冲突不写、无秘密和独立回读通过 |
| C4-02 | `gateway-control` 适配器 | 固定路由、白名单 argv、服务令牌、超时、输出限制和回读 | 已实现并通过 15 项 Mock/故障测试；Docker/真实共享卷待验收 | 真实共享卷、文件锁、健康检查和故障恢复通过 |
| C4-03a | 正式模型目录与策略校验 | 只读模型目录、稳定 ID、Provider 通配符、group 展开、目录摘要和失败关闭 | 已实现；管理服务 109/109 通过；真实部署待完成 | 坏目录、未知字段、重复 ID/group 和未知引用全部失败关闭；日志不泄漏路径；真实只读挂载、digest 和重启生效通过 |
| C4-03b | 策略模型、首次初始化与迁移 | `gatewayPolicy`、旧 M1 `unknown`、quota/models 分步提交和缺项错误 | auth-service 核心已实现，26/26 测试通过 | 不伪造另一部分；`policy_setup_required` 正确；两项完整并回读后才 `known`；管理端编排已接通，真实部署待验收 |
| C4-03c | 管理 API、签发同步与交付 | `PUT quota`、`PATCH models`、版本/幂等/审计、签发 journal、apply、回读、持久化、交付和无孤儿补偿 | 核心已实现，Mock/故障测试通过 | 管理 API 门禁、同步完成前不交付、失败补偿和启动恢复已有测试；真实环境待验收 |
| C4-03d | 页面与运营状态 | 管理页和员工页消费 C4-03b/c 的真实状态，展示失败设备和恢复入口 | 部分实现 | 管理页额度/模型写表单、完整证据链和员工只读状态门户已有；只有完整证据链显示“已生效”，`dependency_invoked` 不自动重试 |
| C4-04 | 真实网关行为 E2E | 真实 Magpie 限额、模型拒绝、策略继承、多凭证、部分失败和故障注入 | 完整管理链路 18 阶段 E2E 已通过；Docker/共享卷、真实 IdP、反向代理和浏览器 E2E 待验收 | 隔离真实 Magpie 的请求行为与回读一致，不接触真实目录或 `127.0.0.1:3425` |
| C5 | 操作与审计查询 | `audit-logs`、`operations/{id}`、人工对账 | 后端和 M2-D 基础页面已实现并通过 Mock/故障测试；浏览器 E2E 和生产验收待完成 | 可按操作者、目标、动作、结果和时间过滤；响应脱敏；对账生成子 operation |
| D | 管理写操作、看板与授权导出 | 管理 UI、报表、导出和操作历史 | 核心已实现，Mock/集成测试通过；生产验收尚未完成 | 额度/模型、审批、operation、对账、查询和 CSV 导出已有；停用/吊销/轮换、异步大导出、浏览器 E2E 和真实环境待完成；只展示 C2-C5 的真实状态 |

C1/C2/C3 的完成边界：

- 四个 `/api/v1/internal/admin/*` 写接口存在并只接受 `AUTH_INTERNAL_ADMIN_TOKEN`。
- 停用用户会撤销设备、会话和当前凭证；启用用户不恢复旧设备、旧凭证或旧会话。
- 设备吊销只影响目标设备；凭证轮换按设备串行化，持久化失败时撤销新 Key。
- 内部响应和持久化状态不返回 Gateway Key、设备令牌、token hash、公钥正文或服务令牌。
- C1 没有管理会话、RBAC、组织范围写校验、CSRF、`Idempotency-Key`、理由或 intent/result
  管理审计；管理侧入口由 C2/C3 提供，C1 本身不能从管理台操作。
- C2 的四个管理写接口已接入管理会话、CSRF、RBAC、组织范围、理由和响应白名单。
- C3 已实现可选幂等键的持久化重放/冲突/执行中保护、`operationId`、intent/result 审计和
  审计失败阻断；成功和失败结果都可稳定重放，C5 后端已提供查询与人工对账，页面入口仍待 M2-D。

M2-C 的整体完成定义：

- 八条冻结接口全部存在，且每一条都有权限、范围、CSRF、幂等、理由和审计测试。
- 至少一次真实 IdP + 真实 Magpie 网关的停用、吊销、轮换、调额和模型授权演练通过。
- 任意敏感操作都可用 `operationId` 串起操作者、目标、前后状态、依赖结果和错误。
- 响应、日志、审计、错误详情和存储中不出现 Gateway Key、设备令牌、token hash、Cookie、
  OIDC Secret、issuer Key 或服务令牌。
- 审计不可写、依赖超时、部分失败和重复提交都有稳定、可恢复的结果。

M2-C 通过后，M2-D 只负责“看板和运营体验”，不能反过来弥补权限或审计缺口。

C4/C5/D 必须使用独立分支、独立 PR，不许把三个切片堆在一个分支里“顺带完成”：

```text
feat/m2-c4-gateway-policy
feat/m2-c5-operations-audit
feat/m2-d-admin-operations
```

每个分支都必须从最新 `origin/main` 创建，PR 前合入 `upstream/main`，并带上本文第
12.8.1.14 节的测试证据。C4 未在隔离真实 Magpie 环境证明额度/模型真实生效前，不得开始
C5；D 必须建立在 C5 后端已通过 `dependency_invoked`、部分失败和对账闭环 Mock/故障测试，
且查询/对账端到端页面验证通过的基础上。

M2-C4/C5/D 的证据包必须包含：

```text
分支、commit、环境、执行日期、执行人
实际命令和原始输出路径
测试覆盖矩阵（通过/失败/跳过）
真实 Magpie 临时 XDG_CONFIG_HOME、端口和进程清理记录
响应/存储/日志/审计的秘密扫描结果
失败注入与人工对账记录
未验证项和发布结论
```

### 25.5 每项需求的完成定义

一个需求从“已设计”进入“已验证”，必须同时满足：

1. 代码或配置已合入企业功能分支，未直接改 `main`。
2. 接口、数据状态、错误码、失败行为和兼容性已写入文档。
3. 有自动化测试或可重复 E2E；真实依赖未覆盖时必须明确标注。
4. 权限、组织范围、秘密脱敏、依赖故障和回滚路径至少各有一条测试。
5. 在实现状态文档中记录实际命令、结果、测试环境、未覆盖项和可用级别。
6. 上游同步后仍通过关键回归；不能因为合并上游而静默改变企业语义。

以下任一情况只能算“部分验证”，不能算完成：

- 只有页面，没有服务端权限和审计。
- 只有 Mock，没有真实 IdP、网关、Docker、浏览器或 Windows 验收。
- 只有接口存在，没有组织范围、幂等和失败路径。
- 只在管理端改了显示值，没有验证真实 Magpie 生效。
- 能演示正文查看，但没有授权、脱敏、留存和访问审计。

### 25.6 上线后的运营闭环

企业版上线后必须形成以下固定节奏：

| 周期 | 动作 | 输出 |
| --- | --- | --- |
| 每日 | 检查登录、签发、网关 5xx、额度、撤销队列、审计积压和备份 | 值班记录；异常升级 |
| 每周 | 检查新增用户/设备、未合规终端、异常费用和策略漂移 | 周报；整改项 |
| 每月 | 复核角色绑定、临时权限、MCP/资源版本和模型价格 | 权限与成本评审 |
| 每季度 | 备份恢复、离职吊销、设备丢失、跨部门越权、上游同步和回滚演练 | 演练证据；整改闭环 |
| 每半年 | 安全评审、渗透测试、供应链扫描、留存与员工告知复核 | 合规/安全结论 |

运营闭环的负责人必须是具体角色，不能写成“团队负责”。没有负责人、告警接收人和回滚
决定人，企业版仍然只是技术演示。

### 25.7 最终完成判定

企业功能方案只有在以下四句话同时成立时才算真正落地：

1. **员工能用**：企业账号登录，5 分钟内完成本地 Agent 接入，只能使用授权模型/MCP，故障
   时有明确恢复路径。
2. **管理员能管**：用户、组织、设备、凭证、额度、模型、MCP、资源和客户端版本都能在权限
   与组织范围内管理，敏感操作可追溯。
3. **安全能证明**：身份、权限、审计、脱敏、留存、告警、吊销和回滚都有可重复证据，不能
   依赖页面隐藏或口头承诺。
4. **上游能持续同步**：企业改动保持隔离，上游更新后关键回归通过，企业发布可独立回滚。

任何一项无法证明，都应停留在相应交付包，不得对外宣称“企业生产版已完成”。

## 26. 执行版工作分解与发布计划

本节把第 25 节需求转成研发可以直接排期的工作包。工作包编号用于 PR、测试记录、发布说明和
验收证据关联；一个 PR 可以拆成多个小提交，但不能把多个互不相关的工作包塞进同一个 PR。

### 26.1 工作包

| 工作包 | 优先级 | 依赖 | 交付物 | 完成证据 |
| --- | --- | --- | --- | --- |
| ENV-01 真实环境基线 | P0 | M1/M2 现有代码 | IdP、TLS 代理、Docker、Windows 计划任务、真实用量卷 | 逐步 E2E、日志脱敏、重启恢复和公司 CA 记录 |
| C4-01 网关机器协议 | P0 | C3 | schema v1 `describe --json`、原子 `policy apply --json`、64 KiB、冲突和独立回读 | 已实现；Go 单测、CLI 回归、隔离真实二进制冒烟和秘密扫描通过 |
| C4-02 `gateway-control` 适配器 | P0 | C4-01、C3 | 最小权限服务、白名单 argv、10 秒超时、输出上限、故障映射和回读确认 | 已实现并通过 15 项 Node Mock/故障测试；Docker/真实共享卷验收待完成；不直接解析 `caller-keys.json`，不接受任意命令 |
| C4-03a 正式模型目录 | P0 | C4-02、C3 | 只读目录 schema、稳定模型 ID、显式 Provider 通配符、group 展开、2 MiB 限制、目录摘要 | 已实现并通过管理服务 109/109；坏文件/未知字段/重复项/未知引用失败关闭；真实 Compose/digest 验收待完成 |
| C4-03b 策略模型与首次初始化 | P0 | C4-03a、C3 | `gatewayPolicy`、旧 M1 `unknown` 迁移、quota/models 分步提交、缺项错误和版本规则 | auth-service 核心已实现，26/26 测试通过；不伪造另一部分，两项完整并逐凭证回读后才 `known`，迁移幂等；管理端编排已接通，真实部署待验收 |
| C4-03c 管理 API、签发同步与交付 | P0 | C4-03a/b、C4-02、C3 | `PUT quota`、`PATCH models`、payload 指纹、签发 journal/幂等关联、apply、独立回读、持久化和补偿 | 同步前不交付；任一步失败撤销；崩溃恢复不产生孤儿 Key；管理 API 全门禁通过 |
| C4-03d 页面与运营状态 | P0 | C4-03b/c | 管理页/员工页状态、失败凭证和设备、首次设置、对账入口 | 只有 `succeeded + known + synced + 回读一致` 显示“已生效”；`dependency_invoked` 禁止自动重试 |
| C4-04 真实网关行为 E2E | P0 | C4-03a-d | 旧 Key 迁移、多凭证同步、真实限流、refresh/rotate 继承、部分成功和故障注入 | 18 阶段隔离真实管理链路已证明双设备 Key、限额、模型拒绝、`partial_success`、refresh/rotate 继承、故障后 pending、Journal/孤儿 Key 撤销、恢复同步和秘密扫描；Docker/共享卷和生产环境待验收；不接触真实用户目录或 `127.0.0.1:3425` |
| C5-01 操作查询 | P0 | C3/C4 | `GET /operations/{operationId}`、过滤、分页、权限和组织范围 | 已实现并通过 Mock/故障测试；`received`/`dependency_invoked`/`succeeded`/`failed` 可追溯 |
| C5-02 管理审计查询 | P0 | C3 | `GET /audit-logs`、时间/操作者/目标/动作/结果过滤、脱敏 | 已实现并通过 Mock/故障测试；审计员只读；跨范围拒绝；不返回秘密和正文 |
| C5-03 失败对账与补偿 | P0 | C5-01/C5-02 | 待同步、部分成功、人工确认、重试/补偿状态 | 后端已实现并通过 Mock/故障测试；result 审计失败和依赖超时支持受控人工闭环 |
| APR-01a 审批契约与消费 | P0 | C3/C5 | 风险矩阵、规范化 payload、审批表/状态机、稳定错误码、自审批拒绝、预留和一次性消费 | 伪造/过期/撤销/跨组织/跨动作/改 payload/重复或并发消费全部拒绝；审批可串联 operation |
| APR-01b 外部审批 | P0 | APR-01a、真实 OA | `external` 适配器、验签回调、审批查询、nonce/重放缓存和外部工单引用 | 真实 OA 批准后才允许执行；回调重放、错误 audience 和错误签名无效 |
| APR-01c step-up | P0 | M2-A、真实管理 IdP | 独立 OIDC Client、ACR/amr/authTime、短会话、浏览器/IP/角色绑定 | MFA 未完成、ACR 不足、过期或绑定变化时高风险动作失败关闭 |
| APR-01d 内置审批运营 | P1 | APR-01a/c、M2-D | 审批箱、串并行步骤、转交/撤回、双人复核和审批状态页 | 申请人不能自批；串并行和双人审批可证明；撤回/转交/过期不产生业务执行 |
| APR-01e break-glass 紧急流程 | P0 | APR-01a/b/c、NOTIFY-01a | 短时紧急审批、独立高风险告警、到期自动失效和 24 小时事后复核 | break-glass 15 分钟过期；异常使用 5 分钟内告警；24 小时内留复核和关闭证据 |
| NOTIFY-01a outbox 与投递引擎 | P0 | C3/C5 | outbox、租约、幂等、指数退避、死信、重启恢复扫描和人工重放 | 渠道故障不影响业务提交；重复投递可按 eventId 去重；重启不丢事件 |
| NOTIFY-01b 邮件/IM/Webhook/工单 | P0 | NOTIFY-01a、Secret Manager | 渠道配置、测试、邮件域限制、企业 IM、HMAC Webhook、工单适配和 Secret 引用 | 超时、重试、死信、SSRF/重定向/DNS rebinding 和秘密扫描通过 |
| NOTIFY-01c SIEM 与安全运营投递 | P0 | NOTIFY-01a、M5 | OTel/Syslog/HTTP Collector、稳定事件 schema、严重级别和值班看板 | 严重事件 5 分钟内可见；死信可重放；事件不含正文、Prompt/回复和秘密 |
| NOTIFY-01d 通知运营页 | P1 | NOTIFY-01b/c、M2-D | 渠道、规则、投递、死信、重试、抑制和聚合管理入口 | 管理员可定位失败并在权限、理由和审计下重放或关闭；页面不显示渠道 Secret |
| D-01 管理台写操作 | P0 | C4/C5 | 停用、启用、吊销、轮换、调额、模型授权表单和状态 | 二次确认、理由、幂等键、待同步/失败/成功状态正确 |
| D-02 用量与成本看板 | P0 | M2-B/C5 | 总览、人/部门/Agent/模型/时间筛选、CSV 导出和告警入口 | 大报表异步下载；导出单独授权并写审计 |
| ORG-01 SCIM/离职同步 | P0/P1 | M1/M2 | SCIM 用户、组织、停用、增量同步和重试 | 离职优先、幂等、失败可重放；停用触发吊销 |
| M3-01 资源服务与签名 | P1 | ENV-01 | 资源目录、manifest、哈希、签名、对象存储、不可变版本 | 篡改内容被拒绝；发布/回滚有审批和审计 |
| M3-02 MCP 目录与远程代理 | P1 | M3-01 | MCP 注册、工具 allow/deny、企业地址、健康检查、限流 | 未授权工具不可调用；上游凭据只在网关 |
| M3-03 客户端同步与策略 | P1 | M3-01/02 | 短期同步凭证、desired-state、设备上报、强制/推荐资源、离线缓存、漂移上报、Provider 锁定和回滚 | 凭证来源固定且按设备/组织授权；5 分钟内同步；坏版本回退；员工不能关闭强制项；管理 UI、本地 helper 和目标 Agent 文件映射完成 |
| M4-01 审计事件管道 | P1 | M3、网关插件 | L0/L1 事件、请求 ID、异步重试、会话索引 | 元数据和工具调用可串联；积压可告警 |
| M4-02 L2/L3 内容审计 | P2 | M4-01、合规批准 | 流式拼接、脱敏、分片、检索、留存、删除证明和访问审计 | 正文默认不可见；查看/导出有审批、水印和证据 |
| M5-01 检测与响应 | P1 | M4、OTel | 异常用量/异地/越权/直连/敏感规则、告警、阻断和工单 | 典型事件 5 分钟可见；响应动作可追踪、可撤销 |
| M6-01 数据层与 HA | P2 | 容量目标 | PostgreSQL/ClickHouse、迁移、备份、多副本、Redis 限流 | 迁移可回滚；故障切换、RPO/RTO 演练通过 |
| M6-02 供应链与密钥 | P2 | 安全评审 | Vault/KMS、mTLS、SBOM、镜像/产物签名、依赖扫描 | 密钥不落明文；制品可验签；渗透测试通过 |

### 26.2 推荐发布节奏

| 发布点 | 内容 | 入口条件 | 退出条件 |
| --- | --- | --- | --- |
| `ent-pilot-1` | M0 + M1 + M2-A/B + 真实内网验收 | 5-50 人单部门、退出通道、备份可用 | 员工加入、调用、刷新、停用、只读治理演练通过 |
| `ent-pilot-2` | M2-C4/C5 + APR-01a/b/c + NOTIFY-01a/b/c + D-01 管理页写操作 | C3 审计状态机、真实网关适配、真实 OA/管理 IdP 和 Secret Manager 可用 | 调额/模型授权真实生效；高风险动作审批和 step-up 有效；通知可投递、重试、死信和人工重放 |
| `ent-prod-candidate` | M2-D 完整看板/导出/操作历史 + APR-01e 生产验收 + NOTIFY-01d + SCIM | 真实 IdP、代理、Windows、真实用量卷、权限演练；审批、step-up、break-glass 和通知证据齐备 | 生产候选验收清单全部有证据；不得缺少审批伪造/过期/改 payload、自审批、step-up、break-glass 告警/复核、outbox 重启和死信演练 |
| `ent-prod-1` | M3 资源库/MCP + 客户端策略 | 资源签名、回滚、网络出口和 MDM 完成 | 50-500 人可运营，资源可灰度/回滚 |
| `ent-prod-2` | M4/M5 审计与安全运营 | 合规、留存、告警和值班批准 | L0/L1 完整，L2/L3 受控，SIEM 闭环 |
| `ent-scale-1` | M6 HA/规模化 | 容量、RPO/RTO 和预算批准 | 压测、故障、恢复和回滚全部通过 |

### 26.3 每次发布必须附带的证据包

```text
release tag / commit
upstream merge point
修改的 PR 列表
数据库/配置迁移说明
Go/Node 语法、单测、集成和 E2E 结果
真实 IdP、代理、Docker、Windows、真实网关验证项
权限/跨部门/CSRF/幂等/审计失败测试
审批伪造/过期/撤销/改 payload/自审批/并发消费/step-up 测试
outbox 重启恢复、渠道重试、死信、人工重放、Webhook SSRF 和 SIEM 秘密扫描
正式模型目录加载失败、未知字段、重复 ID/group、未知引用和摘要证据
旧 M1 策略迁移为 `unknown`、quota/models 分步首次初始化和缺项失败证据
新 Key 签发 journal、同步前不可交付、各阶段崩溃恢复和无孤儿 Key 证据
`unknown/pending/partial_success/dependency_invoked` 页面与人工对账证据
秘密扫描、镜像/产物哈希和 SBOM（适用时）
备份点、灰度范围、回滚步骤和负责人
未验证项及禁止宣称的结论
```

发布证据包缺失时，版本只能进入内部演示或受控试点，不能进入生产候选。上游同步点必须能在
发布记录中追溯到具体 commit/tag，不能只写“最新 main”。
