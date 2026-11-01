# 企业级功能路线图（在现有 fork 上增量实现）

目标：在不破坏“每小时检查上游并通过受控 PR 同步”的前提下，把 magpie 从“个人工具”升级为“企业可治理的 AI 网关”。
原则：**能配置解决的先配置，能插件解决的先插件，核心代码少改**。

完整的产品、架构、数据模型、MCP/资源库、审计、部署和验收方案见
[`enterprise-feature-spec.md`](enterprise-feature-spec.md)。本文件保留为简版路线图。
面向评审的统一实施基线、角色流程、功能目录和上线门槛见
[`enterprise-master-plan.md`](enterprise-master-plan.md)。本文件的里程碑编号必须与总纲一致。
项目职责、GitHub 规则、环境晋级、发布证据、成本容量、培训和试点退出见
[`enterprise-operating-model.md`](enterprise-operating-model.md)。
逐项生产验收证据和签字表见
[`enterprise-acceptance-checklist.md`](enterprise-acceptance-checklist.md)。

当前进度（2026-11-01，完整实施方案 v3.5）：M0 的客户端/服务端分离已经落地在 `enterprise/`，包括部署模板、
员工密钥开通、客户端加入、验收脚本和可重复的端到端测试；没有修改任何上游跟踪文件。
M1 的 `enterprise-auth`、OIDC+PKCE、设备注册、短期 Key 刷新、同设备并发刷新串行化和
加入脚本已经实现，并通过 Node 单元/Mock 集成测试（18/18）。真实 Magpie issuer E2E 已全部
通过：签发、调用、用量归属、刷新撤销、停用吊销和重启恢复均已验证。
M2-A 管理身份底座、M2-B 只读治理、M2-C2 管理写接口和 M2-C3 幂等/管理审计已实现：`enterprise/admin-service` 提供独立管理 OIDC、
MFA/ACR、已验证邮箱、管理会话、CSRF、IP 限制、RBAC、组织范围、内部服务令牌、最小管理页，
以及用户、部门、设备、凭证、模型和用量只读 API；用量从只读挂载的 `usage.jsonl` 汇总并按
组织子树过滤。M2-C2 已提供停用/启用用户、吊销设备和轮换当前凭证四个受控写 API，
接入管理会话、CSRF、RBAC、组织子树、必填理由和响应脱敏；M2-C3 已接入持久化
`Idempotency-Key`、同键重放/冲突、执行中保护、`operationId` 和 intent/result 管理审计。
管理端测试为 31/31（24 项管理集成 + 7 项目录专项），auth-service 为 18/18。M2-C1 的 auth-service
内部写接口也已实现并通过 Mock 测试。C4-01 的 schema v1 机器协议已经实现并通过 Go 单测、
gateway-key CLI 回归和隔离真实二进制冒烟：`gateway-key describe <id> --json` 可安全回读，
`gateway-key policy apply <id> --json` 可在文件锁内原子替换模型和额度。C4-02
`gateway-control` 受控适配器已实现，并通过 15 项 Mock/故障测试：固定路由、独立服务
令牌、固定 argv、Key ID 白名单、10 秒超时、64 KiB 上限、独立回读和 `pending` 状态均已
验证。C4-03a 正式只读模型目录已实现，管理服务 `GET /api/v1/admin/models` 已使用该目录；
C4-03b 用户级 `gatewayPolicy` 核心已实现，覆盖旧 M1 `unknown` 迁移、quota/models 分步初始化、
版本冲突、失败关闭和回读确认接口，并通过 18 项测试；这仍不等于管理端已完成调额/模型授权。
C4-03c 管理 API 与同步后交付、C4-03d 页面与运营状态仍未实现。C4-04 真实
Magpie 行为 E2E、C5（操作/审计查询与对账）和 M2-D（管理台写按钮、完整看板和报表）
仍未实现。真实企业 IdP、
Docker Compose、真实共享卷、真实用量数据卷、
反向代理/浏览器、公司 CA 和 Windows 计划任务仍需完整验收。
M2-E 的审批、step-up、通知 outbox、Webhook/SIEM/工单已完成设计，但 `APR-01`/`NOTIFY-01`
尚未实现，不能把现有 `approvalId` 当作已校验审批，也不能在业务请求中同步发送通知。
逐项真实状态见 [`enterprise-implementation-status.md`](enterprise-implementation-status.md)。
完整需求 ID、交付包、端到端场景和每项完成定义见
[`enterprise-feature-spec.md`](enterprise-feature-spec.md) 第 25 节。

---

## 一、现状盘点：已有能力 vs 企业缺口

| 能力 | 现状 | 结论 |
| --- | --- | --- |
| 客户端 + 服务端双角色 | 原生支持（本地网关 / Docker 网关） | 可直接用 |
| 网关密钥（每人一 key） | `magpie gateway-key add/limit/models/access/rotate/remove` | 可直接用 |
| 短命密钥 / 子密钥 | `gateway-key issue --ttl` + `issuer`，1 分钟到 30 天 | OIDC 的基础 |
| IP 白名单 | `MAGPIE_ALLOW_IPS`（CIDR，先于密钥校验） | 可直接用 |
| 用量统计 | 逐条 `usage.jsonl`，可 OTLP 导出元数据 | 可直接用 |
| 隐私脱敏 | Settings → Privacy（redact/masking） | 可直接用 |
| 一键配置 Agent | 原生，覆盖数十种 Agent | 客户端卖点 |
| 内网更新源 | `MAGPIE_UPDATE_FEED` + SHA-256 校验 | 可直接用 |
| 请求中间件 | `gwmw` + `plugins/middleware`（可改写/拒绝） | 内容审计的挂点 |
| **OIDC / SSO** | M1 本地实现（OIDC+PKCE、设备注册、短期 Key）；真实 IdP 未验收 | 完成验收后可用 |
| **对话内容审计** | 默认不落内容，usage 只有元数据 | **要建** |
| **管理后台 / RBAC** | M2-A/M2-B 已实现管理身份和只读治理；M2-C1 内部写接口、M2-C2 管理写 API 和 M2-C3 幂等/管理审计已实现；C4-01 网关机器协议和 C4-02 受控适配器已实现本地/Mock 测试；C4-03a 正式只读目录和 C4-03b 用户级策略核心已实现 | C4-03c/C4-03d/C4-04、M2-C5/D 待建；C4-02 和 C4-03a 待真实部署验收；auth-service 尚未接入目录，管理端也尚未编排用户级策略 |
| **审批 / step-up / 职责分离** | 第 5.11、6.12、25.2.11 节已设计风险矩阵、绑定摘要、状态机、外部审批、一次性消费和 break-glass；无实现 | **要建 APR-01a-e** |
| **通知 / Webhook / SIEM / 工单** | 第 6.12、25.2.11 节已设计 transactional outbox、重试、死信、抑制和投递 schema；无实现 | **要建 NOTIFY-01a-d** |
| **指标 / 健康检查** | auth/admin 已有 `/healthz`；网关指标、告警和值班闭环未建 | 逐步补齐 |
| **高可用 / 共享存储** | JSON 文件、单实例 | 按规模再建 |
| **设备级 mTLS / 证书** | 无 | 按合规再建 |

## 二、能力工作包（按能力分组，不单独定义里程碑编号）

### P0-1 企业网关基线（已完成，1-2 周）

- 内容：Docker 部署企业网关（`MAGPIE_ADDR=0.0.0.0`、`MAGPIE_ALLOW_IPS=公司网段`、TLS 终止）；每名员工一个网关密钥；默认额度（token/成本/周期）；usage 走 OTLP；`MAGPIE_UPDATE_FEED` 指向内网；新增 `enterprise/` 下的开通/轮换/巡检脚本。
- 已验收：客户端 magpie → 企业网关 → mock 上游；`usage.jsonl` 按 `callerKeyId/callerKeyName`
  归属到员工；短命密钥和已有用户改额度可用；测试不触碰真实 magpie 数据。
- 仍需配套：在公司入口做 TLS 终止、把 `MAGPIE_UPDATE_FEED` 指向内网、接入 OTLP/SIEM。
- 预期效果：试点 5-10 人即可用；外联只剩内网网关；IP、身份、额度、用量四件事当天可管。
- 工作量：小（S），不写核心代码。

### P0-2 OIDC 单点登录 → 自动发短命密钥（已实现，待完整验收）

- 内容：新增独立服务 `enterprise-auth`（Go/Node 均可）：
  - 标准 OIDC 授权码 + PKCE 登录，校验 `id_token`；
  - 在服务端用密钥库保存一把专用签发密钥（`gateway-key issuer <id> on`），登录成功后调用
    `POST /v1/magpie/keys`，为员工签发 1-8 小时、限定模型和额度的子密钥；
  - 已实现 `POST /api/v1/devices/refresh`（续期）、`POST /api/v1/devices/revoke`（吊销）；
    接 IdP 的 SCIM/Webhook 仍待实现，当前通过最小管理接口停用；
  - 新增独立客户端工具 `enterprise-join`（PowerShell/Go 均可）：打开浏览器 OIDC，拿到密钥后
    调用现有 `join-client.ps1` 的同样步骤写入本地 Provider。**不要求改 magpie 核心**。
- 已落地：`enterprise/auth-service`、`join-enterprise.ps1`、`refresh-client.ps1`；设备私钥、
  设备令牌和网关 Key 不进入日志；刷新失败会撤销未持久化的新 Key。
- 已测试：OIDC/JWT 验签、PKCE、加入码换取、设备心跳、刷新、停用吊销、过期令牌、
  公钥格式校验、持久化失败回滚、同设备并发刷新、“刷新签发中停用”、内部管理状态接口、
  真实 issuer join → 调用 → 用量 → 刷新撤销 → 停用 → 重启；auth-service 当前 `18/18` 通过。
- 待验收：真实企业 IdP、Docker 镜像/健康检查、Windows 计划任务实机刷新、
  SCIM/离职自动同步。
- 预期效果：员工用公司账号一键登录，不再手工贴 key；密钥短命，离职 <1 小时失效；IT 不用逐台发密钥。
- 工作量：中（M）。

### P0-3 管理控制台 + RBAC（M2-A/B/C1/C2/C3、C4-01/C4-02/C4-03a、C4-03b 核心已实现，C4-03c/C4-03d/C4-04/C5/D 待做）

- 已落地 M2-A 管理身份底座：
  - 独立 `enterprise/admin-service`，不继续扩展裸 `AUTH_ADMIN_TOKEN`；
  - 管理端 OIDC、MFA/ACR、已验证邮箱、会话、CSRF、IP 限制和重新认证边界；
  - 角色：部门管理员、企业管理员、审计员、安全管理员、运维管理员和超级管理员；
    权限按“权限 + 组织范围 + 资源范围 + 时间”判断；
  - `/admin/me`、组织范围读取、最小管理页、内部服务状态和稳定错误码；
  - auth-service 与 admin-service 使用独立的 `AUTH_INTERNAL_ADMIN_TOKEN`，浏览器不能接触。
- 已测试：管理服务 `31/31`（24 项管理集成 + 7 项目录专项），覆盖登录、MFA、已验证邮箱、ACR、CSRF、会话
  过期、IP fail-closed、角色撤销、部门子树、兄弟部门拒绝、用户/设备/凭证/模型/用量只读
  接口、用量归属、依赖故障、损坏用量和凭据不落盘；M2-C2 覆盖四个写接口、写组织范围、
  必填理由、坏 JSON 和响应/存储脱敏；M2-C3 覆盖同键重放/冲突、执行中保护、失败重放、
  intent/result 审计和审计失败阻断；auth-service 当前 `18/18`。
- 已实现 M2-B：用户、部门、设备、凭证、模型和用量只读 API、服务端范围过滤、显式用户-
  部门映射、只读 `usage.jsonl` 读取和管理页摘要。
- 已实现 M2-C1：auth-service 内部停用/启用、设备吊销、当前凭证轮换；只有独立服务令牌，
  不经过管理会话、RBAC、CSRF、幂等或管理审计。
- 已实现 M2-C2：admin-service 四个对外写 API、管理员权限映射、组织范围写校验、CSRF 和
  必填理由；响应使用字段白名单。
- 已实现 M2-C3：持久化幂等键、同键重放/冲突、执行中保护、`operationId`、intent/result
  管理审计和审计失败阻断；成功、失败和审计故障路径均已用 Mock 覆盖。
- 已完成 C4-01：schema v1 的 `gateway-key describe <id> --json` 与原子
  `gateway-key policy apply <id> --json` 已实现。覆盖安全策略回读、64 KiB 输入输出限制、
  `expectedPolicyRevision` 乐观锁、稳定 JSON 错误码、无 Key/账户/Secret 输出和文件锁内
  原子替换；已通过 Go 单测、gateway-key CLI 回归和隔离真实二进制冒烟。C4-01 不是管理
  API，也不证明真实请求已按策略生效。
- 已完成 C4-02：`enterprise/gateway-control/` 已实现固定 describe/apply/健康检查路由、
  独立 Bearer 服务令牌、固定 argv、`shell: false`、Key ID 白名单、默认 10 秒超时、
  64 KiB 请求/输出上限、专用配置目录和写入后的独立回读；不确定结果返回 `pending`，
  不伪造成功。Dockerfile、Compose profile 和安全配置已新增，Node 语法检查及
  `15 passed, 0 failed` 的 Mock/故障测试通过。它不是管理 API，admin-service 尚未接入；
  Docker/Compose、真实共享卷和 mTLS 尚未验收。
- C4-03a 已实现：admin-service 只读 `ADMIN_MODEL_CATALOG_PATH`；严格 JSON、稳定模型 ID、
  显式 `providerWildcards`、group 展开、2 MiB 上限、SHA-256 digest 和安全状态摘要。
  `ADMIN_MODELS` 仅在未配置正式目录时兼容显示，不是权限事实来源。当前 31/31 通过，
  但 auth-service 尚未接入，真实 Compose/只读挂载/digest 重启仍待验收。
- C4-03b 核心已实现：auth-service 已有版本化用户级 `gatewayPolicy`、旧 M1 `unknown` 迁移、
  quota/models 任意顺序首次提交、`policy_setup_required`、版本冲突、失败关闭和逐凭证回读确认；
  当前 18/18 测试通过。它还不是管理台功能，admin-service 尚未自动编排该策略，也没有真实
  Compose/共享卷/真实 IdP 验收。
- 待实现 C4-03c：额度修改、模型授权、规范化 payload 指纹、issuance journal、apply、
  独立回读、原子持久化和同步后才交付。管理服务禁止直接读写 `caller-keys.json`；由专用
  `gateway-control` 调用 C4-01 的两个机器命令。新签发、刷新、轮换必须继承用户策略，
  `unknown`/`pending` 时失败关闭；任一步失败撤销新 Key，崩溃恢复不得留下孤儿 Key。
- 待实现 C4-03d：管理页和员工页分别展示策略状态、逐凭证同步状态、失败设备和对账入口；
  只有 `succeeded + known + synced + 回读一致` 才显示“已生效”，`dependency_invoked`
  禁止自动重试。员工网页仍不能直接修改本机 Agent 文件。
- 待实现 C4-04：真实 Magpie 行为 E2E，必须证明多张旧 Key 的额度/模型范围真实变化、零额度
  真实限流、refresh/rotate 继承策略、部分失败不伪造成功，并隔离临时目录和端口。
- 待实现 M2-C5：`GET /operations/{operationId}`、`GET /audit-logs` 和
  `POST /operations/{operationId}/reconcile`；支持按操作者、目标、动作、结果和时间过滤，
  对 `dependency_invoked`、部分失败执行显式重试、回滚或凭证据人工确认。
- 待实现 M2-D：管理写操作 UI、用量/费用看板、授权导出、管理员操作历史和员工本人状态页。
  页面只能展示 C2-C5 的真实状态，不能把 `partial_success`/`pending` 显示为“已生效”。
- 分支与顺序：C4-01/C4-02/C4-03a 已完成，C4-03b 核心已完成；当前
  `feat/m2-c4-gateway-policy` 下一步直接做 C4-03c，不要重做 C4-03a/C4-03b。之后依次为
  `feat/m2-c4-gateway-policy-e2e`（C4-04） ->
  `feat/m2-c5-operations-audit` ->
  `feat/apr-01-approval-step-up` -> `feat/notify-01-outbox-delivery` ->
  `feat/m2-d-admin-operations` -> `feat/m2-e-approval-notify-ops`。每个分支从最新
  `origin/main` 创建，PR 前合入 `upstream/main`；不得把多个切片放在同一分支或同一大 PR。
- 验收门槛：C4-01 的本地协议测试和 C4-02 的 Mock/故障测试已完成；C4-02 还须在
  Docker/真实共享卷上证明健康检查、文件锁和故障恢复；C4-03a 的坏目录失败关闭、digest 和
  不泄漏路径已有专项测试，还须在真实 Compose 证明只读挂载与重启生效；C4-03b 的本地测试
  已证明旧凭证 `unknown`、分步首次设置和缺项零依赖，还须完成管理链路和真实部署验收；C4-03c 必须
  证明管理 API 权限、版本冲突、payload 指纹、同步前不交付、崩溃无孤儿和失败关闭；
  C4-03d 必须证明各状态页面语义；C4-04 必须在隔离端口和临时 `XDG_CONFIG_HOME` 中证明旧活跃
  Key 的额度和模型真实变化、零额度真实限流、refresh/rotate 后策略保持；C5 必须证明失败
  可查询可对账；D 必须证明不同状态在页面上显示正确。
- 实现边界：控制台作为独立管理服务运行在网关主机旁；创建/轮换顶层员工密钥时调用
  `magpie gateway-key` CLI，不直接改 `caller-keys.json`。等规模上来再接共享存储。
- 设计细节：服务边界、RBAC 权限键、组织范围过滤、管理操作审计、API 切片、页面和
  测试矩阵见 [`enterprise-feature-spec.md`](enterprise-feature-spec.md) 第 12.1-12.8 节。
- 预期效果：M2-A/M2-B 可验证管理员身份、权限和只读治理，M2-C1/C2/C3 已具备内部和管理 API
  敏感操作、幂等和审计能力；M2-C4/C5/D 完成后，IT 才能从管理台自助管理上百人，预算按
  部门可见、可预警，额度/模型真实生效，部分失败可对账补偿。
- 工作量：M2-A/B/C1/C2/C3 和 C4-01/C4-02/C4-03a 已完成；C4-03b 核心已完成；C4-03c/C4-03d/C4-04、M2-C5/D 合计仍需中等
  偏大工作量。

### P0-4 审批、重新认证与通知投递（M2-E，已设计未实现，2-3 周）

- 目标：高风险管理动作不能只凭一个管理员会话直接执行；业务成功、审计和安全事件不能
  依赖邮件、IM、Webhook、SIEM 或工单同步可用。
- `APR-01a` 审批契约：服务端计算 L/M/H/C 风险，规范化动作、目标、组织范围、资源范围、
  批量大小和 payload SHA-256；审批状态机、职责分离、一次性消费、稳定错误码和
  `operationId` 串联统一实现。
- `APR-01b` 外部审批：飞书/OA/ServiceNow/Jira 适配器必须验签，并校验 issuer、audience、
  时间窗、nonce 和重放缓存；外部回调只能改变审批状态，不能直接执行管理动作。
- `APR-01c` step-up：使用独立管理 OIDC Client、PKCE、MFA/ACR 和 `max_age`；重新认证
  绑定会话、用户、浏览器/IP 策略和角色范围，默认 10 分钟、关键动作 5 分钟有效。
- `APR-01d` 内置审批：在 M2-D 页面提供审批箱、串并行步骤、转交/撤回和双人复核；申请人
  永远不能审批自己的请求，审批人角色撤销、超出组织范围或自身 step-up 失效时立即拒绝。
- `APR-01e` break-glass：只用于外部审批和正常 step-up 不可用的紧急场景；15 分钟自动过期，
  强制产生高风险告警和工单，24 小时内完成事后复核；不得静默使用或转让给他人。
- `NOTIFY-01a` outbox：业务状态、intent/result 审计和待投递事件在同一事务或受控文件锁内
  提交；至少一次投递、`eventId` 幂等、租约、指数退避、死信、重启恢复和人工重放统一实现。
- `NOTIFY-01b` 渠道：邮件、企业 IM、HMAC Webhook 和工单；邮件限制收件人域，Webhook 仅
  HTTPS + 允许列表，限制超时/响应体/重定向并防 SSRF、私网探测和 DNS rebinding。
- `NOTIFY-01c` SIEM：通过 OTel、Syslog 或 HTTP Collector 发送固定 schema；严重事件
  5 分钟内可见，只发白名单元数据，不发送 Prompt/回复正文、工具完整参数、Key、token
  或 Cookie。
- `NOTIFY-01d` 运营页：在 M2-D 页面提供渠道测试、投递状态、规则、抑制、聚合、死信和
  受审计的人工重放；页面不显示渠道 Secret，重放不能伪造业务成功。
- 固定顺序遵循总纲：C5 -> `APR-01a/b/c` -> `NOTIFY-01a/b/c` -> M2-D ->
  `APR-01d/e + NOTIFY-01d` -> M3/M4/M5。审批和通知先于高风险页面，是为了避免页面先上线、
  后端仍信任可伪造的 `approvalId`，或在请求线程里同步等待外部渠道。
- 验收门槛：缺失/伪造/过期/撤销/跨组织/跨动作/改 payload/自审批/重复消费全部失败关闭；
  并发消费只产生一个业务结果；step-up 不满足时依赖调用为 0；outbox 在进程重启和渠道故障后
  不丢事件；死信可人工重放；Webhook SSRF、SIEM 脱敏和全链路秘密扫描有原始证据。
- 当前边界：该工作包只有设计，没有审批表、审批 API、step-up 中间件、outbox、dispatcher、
  渠道适配器或运营页；现有 `approvalId` 只是预留字段，不能证明审批真实、有效或已消费。

### P1-1 审计与内容合规（对应 M4，4-6 周）

- 内容：
  - 审计事件：每次请求记录 人、时间、来源 IP、Agent、模型、token、费用、成败、策略命中；
  - 内容采集：基于 `gwmw` 中间件插件，采集（脱敏后的）请求/回复，流式内容先做 PoC 验证完整性；
  - 策略引擎：敏感词/密钥/身份证/代码库路径规则，支持放行、告警、阻断（中间件 Reject）；
  - 留存与导出：按天分片、保留期、哈希链防篡改，导出 Syslog / HTTP / OTLP 到 SIEM。
- 实现边界：审计插件放在企业自己的插件仓库，通过 `plugins/middleware` 的 gateway hook 运行；
  内容采集/策略引擎是独立服务，插件只做同步判定和异步投递，避免把合规逻辑塞进核心。
- 预期效果：能回答"谁在什么时候问了什么、花了多少、是否违规"；通过安全/合规评审；敏感数据外发可拦截。
- 工作量：大（L）。

### P1-2 可观测性（对应 M5-C，1-2 周）

- 内容：先用现有 OTLP 导出接 OpenTelemetry Collector，再由 collector 提供 Prometheus 指标；
  独立巡检服务补 `/healthz`、`/readyz` 和额度告警；Grafana 面板与告警规则。
- 实现边界：若后续确实需要进程内 `/metrics`，再作为最小核心 hook 单独评审，不影响当前阶段。
- 预期效果：故障 5 分钟内定位；容量和成本可预测。
- 工作量：小（S）。

### P1-3 客户端企业预置（对应 M3-C/M5，2-3 周）

- 内容：组织配置包（JSON 或 `magpie://join?...`）：网关地址、Provider 模板、模型目录、策略版本；客户端"加入组织"后自动完成 Provider + Agent 一键配置；MDM 静默安装 + 版本锁定 + 更新源。
- 预期效果：新员工 5 分钟内可用，零手工配置；版本统一、可回滚。
- 工作量：中（M）。

### P2-1 高可用与共享存储（对应 M6-A/B，4-8 周，>100 人再做）

- 内容：密钥/用量/审计从本地 JSON 迁到 Postgres（保留 SQLite 单机模式）；网关无状态化，多副本 + 负载均衡；迁移工具、备份恢复、灰度升级。
- 预期效果：可用性从单实例 99.5% 提升到 99.9%；支持横向扩容。
- 工作量：大（L）。

### P2-2 安全加固（对应 M5/M6-C，按合规要求，2-4 周）

- 内容：客户端到网关 mTLS/设备证书；密钥托管接 Vault/KMS；审计日志加密与保留策略；构建产物签名 + SBOM；渗透测试。
- 预期效果：满足等保/ISO 27001/SOC 2 的证据要求。
- 工作量：中（M）。

## 三、实施顺序与里程碑

本节是简版顺序表；完整工作包、退出条件和上线门槛以
[`enterprise-master-plan.md`](enterprise-master-plan.md) 第 6、7、12 节为准。

| 阶段 | 参考周 | 交付 | 退出条件 |
| --- | --- | --- | --- |
| M0 企业网关基线 | 已完成 | 网关、员工 Key、IP 白名单、额度、元数据和 E2E | 5-10 人试点，请求可按人追溯 |
| M1 身份与设备 | 已实现，生产验收中 | OIDC + PKCE、设备、短期 Key、刷新和吊销 | 真实 IdP、Compose、计划任务和离职流程通过 |
| M2-A 管理身份 | 已实现，生产验收中 | 管理 OIDC、MFA/ACR、会话、CSRF、RBAC 和组织范围 | 真实管理 IdP、代理、浏览器和角色演练通过 |
| M2-B 只读治理 | 已实现，Mock 测试通过 | 用户、部门、设备、凭证、模型、用量只读 API 和范围过滤 | 企业管理员可读全域；部门管理员不能跨部门读取 |
| M2-C1 Auth 内部写接口 | 已完成，Mock 测试通过 | 仅服务间调用的停用/启用、设备吊销和当前凭证轮换 | 接口鉴权、目标校验、设备串行化、撤销队列和失败回滚测试通过；管理台不可直接操作 |
| M2-C2 管理写 API | 已完成，Mock 测试通过 | 管理会话/RBAC/CSRF、组织范围、理由、四个停用/吊销/轮换接口和响应脱敏 | 跨部门写拒绝；依赖故障不伪造成功；真实环境待验收 |
| M2-C3 幂等与管理审计 | 已完成，Mock 测试通过 | 持久化幂等、`operationId`、intent/result 审计和审计失败阻断 | 审计失败时依赖调用为 0；敏感操作可追溯 |
| M2-C4-01 网关机器协议 | 已完成，本地测试通过 | `describe --json`、原子 `policy apply --json`、版本冲突、无秘密输出 | Go 单测、CLI 回归和隔离真实二进制冒烟通过 |
| M2-C4-02 受控网关适配器 | 已完成，Mock/故障测试通过 | 固定路由、独立服务令牌、固定 argv、超时/64 KiB 上限、独立回读和 `pending` | Node `15/15`；Docker/Compose、真实共享卷和 mTLS 待验收 |
| C4-03a 正式只读模型目录 | 已完成，待部署验收 | 严格 JSON、schema v1、稳定模型 ID、Provider 通配符、group、2 MiB、digest 和安全投影；管理 `31/31` | 真实只读挂载、digest 重启和失败关闭通过；auth-service 接入属于后续 C4-03c 管理链路 |
| C4-03b 用户级策略核心 | 已完成本地测试 | 版本化 `gatewayPolicy`、旧 M1 `unknown`、分步初始化、版本冲突、失败关闭和回读确认 | auth-service `18/18`；管理链路与真实部署待验收 |
| C4-03c/C4-03d/C4-04 用户级策略贯通与真实 E2E | 1-2 周 | 额度/模型管理 API、同步后交付、页面状态、策略继承、部分成功和真实 Magpie 请求行为 E2E | 管理 API 失败关闭；真实额度/模型生效，可按 credential 对账 |
| M2-C5 操作/审计查询与对账 | 与 C4 同阶段或紧随其后 | operations/audit-logs/reconcile、失败查询、子 operation 和人工补偿 | 可按操作 ID、操作者、目标、时间和结果查询；失败可对账 |
| M2-E1 审批、step-up 与通知后端 | 1.5-2 周 | APR-01a/b/c、NOTIFY-01a/b/c；审批绑定/消费、外部审批、step-up、outbox、渠道和 SIEM | 高风险动作失败关闭；业务提交不等外部渠道；重启、重试、死信和人工重放可验证 |
| M2-D 看板与运营 | 1-2 周 | 总览、筛选、用量/费用趋势、导出和告警入口 | 可稳定输出人/部门/模型报表 |
| M2-E2 内置审批与通知运营页 | 0.5-1 周 | APR-01d/e、NOTIFY-01d；审批箱、break-glass、渠道/死信/重试/抑制页面 | 双人审批可证明；break-glass 15 分钟过期并 24 小时内复核；死信可受审计重放 |
| M3 中央 MCP/资源库 | 4-6 周 | 目录、远程/本地 MCP、签名资源、同步、漂移和回滚 | 授权后 5 分钟可见；未授权不可见/不可调用；失败可回滚 |
| M4 会话与工具审计 | 4-6 周 | 事件管道、流式拼接、脱敏、检索、留存和导出 | L0 完整；正文按授权可见；删除和留存可验证 |
| M5 安全运营与可观测性 | 3-4 周 | 规则、告警、阻断、吊销、OTel、SIEM 和值班闭环 | 典型违规/故障 5 分钟可见并可处置 |
| M6 规模化与高可用 | 4-8 周或按需 | PostgreSQL/ClickHouse、多副本、Redis、KMS、mTLS 和多地域 | 压测、故障、RPO/RTO 和回滚演练通过 |

顺序理由：**身份（M1）先于治理（M2）**，因为所有额度、资源和审计都必须绑定到真实人和设备；
**只读（M2-B）先于写操作（M2-C）**，先证明组织范围正确，再开放会改变状态的接口；
**写操作先做内部安全切片（M2-C1）再做管理入口（M2-C2）**，随后由 M2-C3 补齐持久化幂等、
`operationId` 和 intent/result 管理审计；C4/C5 只负责真实网关调额/模型授权和查询对账，
不能再把审计状态机留到 C4/C5，也不能把尚未审计的接口称为生产闭环；
**审批/step-up/通知后端先于高风险页面（M2-E1 -> M2-D）**，因为额度、模型、正文查看和
资源发布会扩大权限或数据暴露面；内置审批箱、break-glass 和通知运营页随后在 M2-E2 补齐，
避免先用页面制造一个“看起来有审批、实际可伪造”的假闭环；
**资源/MCP（M3）先于正文审计（M4）**，先控制员工能用什么，再处理可以记录什么；
**安全运营（M5）先于规模化（M6）**，先证明能发现和处置风险，再扩大暴露面。

## 四、预期效果（验收指标）

- 开通效率：新员工从"手工配置 30 分钟"降到"登录即用 ≤5 分钟"。
- 安全：密钥 100% 短命（≤8 小时），离职失效 ≤1 小时；员工机不持有任何厂商 Key。
- 审计：100% 请求可按 人/部门/Agent/模型/IP/时间 检索；敏感数据规则命中可告警或阻断。
- 成本：按部门/人/模型出用量与费用报表，超额自动告警。
- 运维：版本统一推送，回滚 ≤10 分钟；单实例可用性 99.5%，HA 后 99.9%。

## 五、工程原则（保护 fork 同步）

- 企业功能优先做成**独立服务 + 插件**（`gwmw` 中间件、独立 auth/admin 服务），核心仓库只加必要 hook；这样每次同步上游 PR 时冲突面最小。
- 每个功能一个 `feat/*` 分支、小 PR、带测试；核心改动必须有过期/降级路径，默认不影响个人用户。
- 数据存储先用现有 JSON，明确超过 50-100 人再上 Postgres，避免过早复杂化。
- 发布走自己的流水线与内网更新源，不依赖上游 `release.yml`。

## 六、不建议现在做

- 不自己重写模型网关/路由核心，能用 LiteLLM/现有 Provider 解决的就复用。
- 不在 100 人以内上 Kubernetes/多副本，单实例 + 备份足够。
- 不默认全量记录对话内容：先脱敏、分级、按策略采集，避免合规反噬。
- 不为每个 Agent 单独做企业适配，优先复用现有一键配置机制 + 组织配置包。
