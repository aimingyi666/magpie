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

当前进度（2026-11-02，完整实施方案 v3.27）：M0 的客户端/服务端分离已经落地在 `enterprise/`，包括部署模板、
员工密钥开通、客户端加入、验收脚本和可重复的端到端测试；没有修改任何上游跟踪文件。
M1 的 `enterprise-auth`、OIDC+PKCE、设备注册、短期 Key 刷新、同设备并发刷新串行化和
加入脚本已经实现，并通过 Node 单元/Mock 集成测试（26/26）。真实 Magpie issuer E2E 已全部
通过：签发、调用、用量归属、刷新撤销、停用吊销和重启恢复均已验证。
M2-A 管理身份底座、M2-B 只读治理、M2-C2 管理写接口和 M2-C3 幂等/管理审计已实现：`enterprise/admin-service` 提供独立管理 OIDC、
MFA/ACR、已验证邮箱、管理会话、CSRF、IP 限制、RBAC、组织范围、内部服务令牌、最小管理页，
以及用户、部门、设备、凭证、模型和用量只读 API；用量从只读挂载的 `usage.jsonl` 汇总并按
组织子树过滤。M2-C2 已提供停用/启用用户、吊销设备和轮换当前凭证四个受控写 API，
接入管理会话、CSRF、RBAC、组织子树、必填理由和响应脱敏；M2-C3 已接入持久化
`Idempotency-Key`、同键重放/冲突、执行中保护、`operationId` 和 intent/result 管理审计。
管理端测试为 109/109（82 项管理集成 + 7 项目录专项 + 7 项通知渠道专项 + 7 项通知规则专项 + 6 项 SIEM 专项），auth-service 为 26/26，gateway-control 为 15/15，resource-service 为 15/15，mcp-gateway 为 14/14，client-sync 为 26/26、local-mcp 为 50/50；合计 255/255。M2-C1 的 auth-service
内部写接口也已实现并通过 Mock 测试。C4-01 的 schema v1 机器协议已经实现并通过 Go 单测、
gateway-key CLI 回归和隔离真实二进制冒烟：`gateway-key describe <id> --json` 可安全回读，
`gateway-key policy apply <id> --json` 可在文件锁内原子替换模型和额度。C4-02
`gateway-control` 受控适配器已实现，并通过 15 项 Mock/故障测试：固定路由、独立服务
令牌、固定 argv、Key ID 白名单、10 秒超时、64 KiB 上限、独立回读和 `pending` 状态均已
验证。C4-03a 正式只读模型目录已实现，管理服务 `GET /api/v1/admin/models` 已使用该目录；
C4-03b 用户级 `gatewayPolicy` 核心已实现，覆盖旧 M1 `unknown` 迁移、quota/models 分步初始化、
版本冲突、失败关闭和回读确认接口，并通过 25 项测试；这仍不等于真实管理链路已通过生产验收。
C4-03c 的管理 API、幂等签发、issuance journal、apply/独立回读、同步后交付、失败补偿和
启动恢复核心已实现并通过 Mock/故障测试；C4-03d 部分实现：管理页已有额度/模型写表单、
停用/吊销/轮换操作、审批、operation、用量/审计查询、人工对账和 CSV 导出，员工页已有
本人额度/模型/凭证/设备只读门户；失败恢复入口和浏览器 E2E 未完成。C4-04 完整管理到真实 Magpie 策略流 E2E
已实现并通过，验证管理 OIDC/CSRF、quota/models 分步设置、双设备独立 Key、模型拒绝、
Token 限额、冲突不落盘、`partial_success`、refresh/rotate 策略继承、故障后
`unknown/pending_sync`、Journal/孤儿 Key 撤销、恢复同步、usage 归属和秘密扫描。C5
（操作/审计查询与对账）后端已实现并通过 Mock/故障测试，基础页面已接入，但生产验收未完成；
M2-D 核心已实现，Mock/集成测试通过；生产验收尚未完成。真实企业 IdP、
Docker Compose、真实共享卷、真实用量数据卷、
反向代理/浏览器、公司 CA 和 Windows 计划任务仍需完整验收。
M2-E 的审批、step-up、通知 outbox、Webhook/SIEM/工单已完成设计；`APR-01a` 的服务端审批、
绑定、职责分离、一次性消费和系统审计已实现，`APR-01b` 的 HMAC/Mock 外部审批回调适配器
也已实现并通过测试；`APR-01c` 的独立 OIDC step-up、PKCE、`prompt=login`、`max_age`、
`auth_time`、ACR/MFA、会话/IP/User-Agent/角色范围绑定和 H/C 风险门禁已完成代码与 Mock IdP
集成测试。`NOTIFY-01a` 的 transactional outbox、租约、幂等、退避、死信、重启恢复、
deliveries 查询和受审计人工重放已实现并通过 Mock/故障测试；`NOTIFY-01b` 的
`email`/`im`/`webhook`/`ticketing` 渠道管理、渠道测试和统一 HTTPS 网关适配器也已实现并
通过 Mock/故障测试，但邮件/IM/工单不是原生厂商 SDK。`NOTIFY-01c` 的 SIEM transport、
固定 L0 schema 和 dead-letters API 已实现并通过 6 项专项测试，真实 SIEM/Collector/
Syslog/生产证书未验收；`NOTIFY-01d` 的规则、抑制、聚合、升级和运营页已实现并通过
Mock/集成测试，真实厂商渠道和生产值班闭环未验收。
真实 OA/飞书/ServiceNow/Jira 连接器、真实管理 IdP/MFA/反向代理、
APR-01d 审批箱核心已实现并通过 Mock/集成测试，break-glass（`APR-01e`）Mock/集成核心
也已实现并通过测试；真实审批演练和生产复核尚未验收，
不能把现有 `approvalId` 当作未经服务端校验的审批。
M3-A 的资源目录、不可变版本、SHA-256 内容寻址、canonical JSON、manifest digest、
Ed25519 签名、发布/历史回滚、乐观并发、幂等和资源审计核心已实现，并通过 11 项
resource-service 测试；M3-B 远程 MCP 注册、企业统一端点、工具级授权、健康检查、凭据
隔离和元数据审计核心已实现，并通过 14 项 mcp-gateway 测试；M3-C-1 同步凭证、desired-state、
设备上报和管理员 JSON 查询 API 已实现，客户端 HTTP 传输适配器已接入，并通过 8 项专项测试。
叠加原有签名同步、原子安装、失败保留旧版本、离线缓存、强制/推荐策略、漂移检测、
路径/符号链接防护、并发锁和状态秘密隔离核心，client-sync 当前 26 项测试通过；
resource-service 15 项测试通过（11 项核心 + 4 项控制面）。M3-D 受控本地 MCP 运行时、helper、回环 HTTP server、stdio bridge 和 Codex 配置映射核心已实现并通过 50 项测试（含真实子进程 E2E）；真实 Codex 客户端、管理台员工产品流、安装器/Windows 服务和生产验收尚未完成。M3-C-2 已把资源目录和
设备同步报告以只读、按组织范围过滤的方式接入管理页，
并只投影白名单字段，依赖故障统一 `503 resource_service_unavailable`。M3-A/M3-B 尚未接入
admin-service 真实审批和可写管理台，M3-B 的 OIDC 组织分配也未实现；M3-C-1/M3-C-2
已有控制面 API 和只读管理页，但资源发布/回滚 UI、审批联动、本地 helper 安装器/产品入口、
目标 Agent 文件映射、Windows ACL、MDM、真实 IdP、浏览器 E2E、Docker/Compose 实机验收、
灰度/自动回滚和生产验收未完成；
M3-B 审批 nonce 仅单进程内存，注册表/审计不是同一事务。
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
| **管理后台 / RBAC** | M2-A/M2-B 已实现管理身份和只读治理；M2-C1 内部写接口、M2-C2 管理写 API 和 M2-C3 幂等/管理审计已实现；C4-01 网关机器协议和 C4-02 受控适配器已实现本地/Mock 测试；C4-03a 正式只读目录、C4-03b 用户级策略核心和 C4-03c 管理 API/签发同步/交付核心已实现；C4-04 完整管理到真实 Magpie 策略流 E2E 已通过；M2-C5 operation/audit 查询和人工对账后端已实现；M2-D 已接入基础写操作、审批、查询、对账和 CSV 导出页面 | C4-02/C4-03a/C4-03c/C5/C4-03d 和 M2-D 待真实部署、真实共享卷、浏览器和生产验收 |
| **审批 / step-up / 职责分离** | APR-01a 已实现审批存储/API、风险分级、绑定摘要、职责分离、一次性消费和启动恢复；APR-01b 已实现 HMAC/Mock 外部审批回调适配器；APR-01c 已实现独立 OIDC step-up 和 H/C 门禁；APR-01d 已实现审批箱、串并行步骤、quorum、转交和撤回；APR-01e 已实现 15 分钟单次 break-glass 和 24 小时复核，均通过 Mock/故障测试 | **继续真实审批、break-glass 告警/工单和生产复核验收** |
| **通知 / Webhook / SIEM / 工单** | NOTIFY-01a outbox/租约/死信/重放、NOTIFY-01b 渠道管理/HTTPS 适配器、NOTIFY-01c SIEM transport/固定 L0 schema/dead-letters API 和 NOTIFY-01d 规则/抑制/聚合/升级/运营页已实现并通过 Mock/故障或集成测试；HTTPS:443/TLS:6514、allowlist、DNS 固定解析、私网/元数据拒绝和逐跳重定向校验；无启用渠道或 transport 时不创建 dispatcher | **继续真实厂商连接、真实 SIEM 接收端和生产投递验收** |
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
   真实 issuer join → 调用 → 用量 → 刷新撤销 → 停用 → 重启；auth-service 当前 `26/26` 通过。
- 待验收：真实企业 IdP、Docker 镜像/健康检查、Windows 计划任务实机刷新、
  SCIM/离职自动同步。
- 预期效果：员工用公司账号一键登录，不再手工贴 key；密钥短命，离职 <1 小时失效；IT 不用逐台发密钥。
- 工作量：中（M）。

### P0-3 管理控制台 + RBAC（M2-A/B/C1/C2/C3、C4-01/C4-02/C4-03a/C4-03b/C4-03c 核心已实现，C4-03d 部分实现，C4-04 完整策略流 E2E 已通过，C5 和 M2-D 核心已实现待生产验收）

- 已落地 M2-A 管理身份底座：
  - 独立 `enterprise/admin-service`，不继续扩展裸 `AUTH_ADMIN_TOKEN`；
  - 管理端 OIDC、MFA/ACR、已验证邮箱、会话、CSRF、IP 限制和重新认证边界；
  - 角色：部门管理员、企业管理员、审计员、安全管理员、运维管理员和超级管理员；
    权限按“权限 + 组织范围 + 资源范围 + 时间”判断；
  - `/admin/me`、组织范围读取、最小管理页、内部服务状态和稳定错误码；
  - auth-service 与 admin-service 使用独立的 `AUTH_INTERNAL_ADMIN_TOKEN`，浏览器不能接触。
- 已测试：管理服务 `109/109`（82 项管理集成 + 7 项目录专项 + 7 项通知渠道专项 + 7 项通知规则专项 + 6 项 SIEM 专项），覆盖登录、MFA、已验证邮箱、ACR、CSRF、会话
  过期、IP fail-closed、角色撤销、部门子树、兄弟部门拒绝、用户/设备/凭证/模型/用量只读
  接口、用量归属、依赖故障、损坏用量和凭据不落盘；M2-C2 覆盖四个写接口、写组织范围、
  必填理由、坏 JSON 和响应/存储脱敏；M2-C3 覆盖同键重放/冲突、执行中保护、失败重放、
  intent/result 审计和审计失败阻断；auth-service 当前 `26/26`。
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
  `15 passed, 0 failed` 的 Mock/故障测试通过。它不是管理 API，admin-service 经 auth-service
  间接调用，尚未直接接入；
  Docker/Compose、真实共享卷和 mTLS 尚未验收。
- C4-03a 已实现：admin-service 只读 `ADMIN_MODEL_CATALOG_PATH`；严格 JSON、稳定模型 ID、
  显式 `providerWildcards`、group 展开、2 MiB 上限、SHA-256 digest 和安全状态摘要。
  `ADMIN_MODELS` 仅在未配置正式目录时兼容显示，不是权限事实来源。当前 109/109 通过；
  auth-service 不加载目录，只接收展开后的稳定模型 ID，真实 Compose/只读挂载/digest 重启仍待验收。
- C4-03b 核心已实现：auth-service 已有版本化用户级 `gatewayPolicy`、旧 M1 `unknown` 迁移、
  quota/models 任意顺序首次提交、`policy_setup_required`、版本冲突、失败关闭和逐凭证回读确认；
  当前 26/26 测试通过。C4-03c 已由 admin-service 调用 auth-service 编排额度/模型策略，
  但真实 Compose/共享卷/真实 IdP 尚未验收。
- C4-03c 核心已实现：额度修改、模型授权、规范化 payload 指纹、issuance journal、apply、
  独立回读、原子持久化和同步后才交付。管理服务禁止直接读写 `caller-keys.json`；由专用
  `gateway-control` 调用 C4-01 的两个机器命令。新签发、刷新、轮换继承用户策略，
  `unknown`/`pending` 时失败关闭；任一步失败撤销新 Key，启动恢复处理可确认的孤儿 Key。
- C4-03d 部分实现：管理页已有额度/模型写表单、停用/吊销/轮换操作、审批、operation、
  用量/审计查询、人工对账和 CSV 导出，并可展示策略状态、逐凭证同步状态、最后同步时间和
  错误码；员工页已有本人额度、模型、凭证、设备和同步状态只读门户；失败设备恢复入口和
  浏览器 E2E 尚未完成；
  只有 `succeeded + known + synced + 回读一致` 才显示“已生效”，`dependency_invoked`
  禁止自动重试。员工网页仍不能直接修改本机 Agent 文件。
- C4-04 完整管理到真实 Magpie 策略流 E2E 已实现并通过：
  `enterprise/test/c4-enterprise-policy-e2e.ps1` 在随机端口、临时 Magpie 和隔离
  `XDG_CONFIG_HOME` 中覆盖管理 OIDC/CSRF、quota/models 分步设置、双设备独立 Key、
  模型白名单 `403`、Token 限额 `429`、精确 `partial_success`、refresh/rotate 策略继承、
  故障后 `unknown/pending_sync`、Journal/孤儿 Key 撤销、恢复同步、usage 归属和秘密扫描。
  `c4-gateway-policy-e2e.ps1` 继续作为单 Key 底层回归。
- M2-C5 后端和基础页面已实现：`GET /operations/{operationId}`、`GET /audit-logs` 和
  `POST /operations/{operationId}/reconcile`；支持按操作者、目标、动作、结果和时间过滤，
  对 `dependency_invoked`、部分失败执行显式重试、回滚或凭证据人工确认。真实审计存储和
  生产运维演练仍待验收。
- M2-D 核心已实现：基础管理写操作、审批、operation/审计查询、用量筛选/趋势、授权 CSV
  导出和管理员操作历史已接入；Excel、异步/对象存储导出、完整运营看板和失败恢复体验未实现。
  页面只展示 C2-C5 的真实状态，不能把 `partial_success`/`pending` 显示为“已生效”。
- 分支与顺序：C4-01/C4-02/C4-03a 已完成，C4-03b/C4-03c 核心已完成，C4-03d 部分完成；
  当前 `feat/m2-c4-gateway-policy-e2e` 已完成 C4-04 完整策略流切片，不要重做
  C4-03a/C4-03b/C4-03c。之后依次为
  `feat/m2-c4-gateway-policy-e2e` 收尾 ->
  `feat/m2-c5-operations-audit` ->
  `feat/apr-01-approval-step-up` -> `feat/notify-01-outbox-delivery` ->
  `feat/m2-d-admin-operations` -> `feat/m2-e-approval-notify-ops`。每个分支从最新
  `origin/main` 创建，PR 前合入 `upstream/main`；不得把多个切片放在同一分支或同一大 PR。
- 验收门槛：C4-01 的本地协议测试和 C4-02 的 Mock/故障测试已完成；C4-02 还须在
  Docker/真实共享卷上证明健康检查、文件锁和故障恢复；C4-03a 的坏目录失败关闭、digest 和
  不泄漏路径已有专项测试，还须在真实 Compose 证明只读挂载与重启生效；C4-03b/C4-03c 的本地测试
  已证明旧凭证 `unknown`、分步首次设置、缺项零依赖、同步后交付和失败补偿，还须完成真实部署验收；C4-03c 必须
  证明管理 API 权限、版本冲突、payload 指纹、同步前不交付、崩溃无孤儿和失败关闭；
  C4-03d 必须证明各状态页面语义；C4-04 已证明隔离端口、临时 `XDG_CONFIG_HOME`、
  模型拒绝、零额度限流、冲突、多凭证部分失败、refresh/issue 继承、故障注入和恢复同步；
  C5 必须证明失败可查询可对账；D 必须证明不同状态在页面上显示正确。
- 实现边界：控制台作为独立管理服务运行在网关主机旁；创建/轮换顶层员工密钥时调用
  `magpie gateway-key` CLI，不直接改 `caller-keys.json`。等规模上来再接共享存储。
- 设计细节：服务边界、RBAC 权限键、组织范围过滤、管理操作审计、API 切片、页面和
  测试矩阵见 [`enterprise-feature-spec.md`](enterprise-feature-spec.md) 第 12.1-12.8 节。
- 预期效果：M2-A/M2-B 可验证管理员身份、权限和只读治理，M2-C1/C2/C3 已具备内部和管理 API
  敏感操作、幂等和审计能力；M2-C4/C5/D 完成后，IT 才能从管理台自助管理上百人，预算按
  部门可见、可预警，额度/模型真实生效，部分失败可对账补偿。
- 工作量：M2-A/B/C1/C2/C3 和 C4-01/C4-02/C4-03a 已完成；C4-03b/C4-03c 核心已完成，C4-03d 部分完成；C4-04 完整策略流已完成；C4-03c 真实验收、C4-03d 剩余项、M2-C5/D 合计仍需中等
  偏大工作量。

### P0-4 审批、重新认证与通知投递（M2-E，APR-01a-e 与 NOTIFY-01a-d 核心已实现，2-3 周）

- 目标：高风险管理动作不能只凭一个管理员会话直接执行；业务成功、审计和安全事件不能
  依赖邮件、IM、Webhook、SIEM 或工单同步可用。
- `APR-01a` 审批契约：服务端计算 L/M/H/C 风险，规范化动作、目标、组织范围、资源范围、
  批量大小和 payload SHA-256；审批状态机、职责分离、一次性消费、稳定错误码和
  `operationId` 串联统一实现。
- `APR-01b` 外部审批：HMAC-SHA256/Mock 回调适配器已实现，覆盖原始 body 验签、issuer、
  audience、时间窗、nonce、eventId 幂等和系统审计；真实飞书/OA/ServiceNow/Jira 连接器
  尚未验证。外部回调只能改变审批状态，不能直接执行管理动作。
- `APR-01c` step-up：已完成代码与 Mock IdP 集成测试。使用独立管理 OIDC Client、PKCE、
  `prompt=login`、`max_age`、`auth_time`、ACR/MFA 和允许的 ACR 值；重新认证绑定会话、
  用户、客户端 IP、User-Agent 和角色/权限/组织范围摘要，H/C 风险写入及审批门禁强制
  step-up，未配置时失败关闭；默认 10 分钟、关键动作 5 分钟有效。
- `APR-01d` 内置审批：审批箱、串并行步骤、quorum、转交/撤回和双人复核核心已实现并通过
  Mock/集成测试；申请人永远不能审批自己的请求，审批人角色撤销、超出组织范围或自身
  step-up 失效时立即拒绝。真实 OA/IdP/MFA 和浏览器审批 E2E 尚未验收。
- `APR-01e` break-glass：只用于外部审批和正常 step-up 不可用的紧急场景；15 分钟自动过期、
  单次原子消费和 24 小时事后复核已完成 Mock/集成核心，使用、复核到期、逾期和完成均产生
  通知与审计；真实高风险告警/工单、外部工单 ID 回读和生产复核演练未验收。不得静默使用或转让给他人。
- `NOTIFY-01a` outbox：已实现业务状态、intent/result 审计和待投递事件在同一事务或受控
  文件锁内提交；至少一次投递、`eventId` 幂等、租约、指数退避、死信、重启恢复和人工重放
  已通过 Mock/故障测试。默认禁用渠道，未启用渠道或没有 transport 时不创建 dispatcher。
- `NOTIFY-01b` 渠道：已实现 email/im/webhook/ticketing 渠道管理、渠道测试和统一 HTTPS
  网关适配器；邮件限制收件人域，Webhook 仅 HTTPS + 允许列表，限制超时/响应体/重定向并防
  SSRF、私网探测和 DNS rebinding。邮件/IM/工单不是原生 SMTP、Graph、飞书、Teams、
  ServiceNow 或 Jira SDK，真实厂商连接和生产投递未验收。
- `NOTIFY-01c` SIEM：通过 OTel、Syslog 或 HTTP Collector 发送固定 L0 schema 的 transport
  已实现并通过 6 项专项测试；HTTPS:443/TLS:6514、host allowlist、固定 DNS、SSRF 防护、
  32 KiB 默认上限、critical 优先和 5 分钟轮询上限已有 Mock/故障证据；只发白名单元数据，
  不发送 Prompt/回复正文、工具完整参数、Key、token 或 Cookie。真实 SIEM/Collector/
  Syslog 和生产证书未验收。
- `NOTIFY-01d` 规则与运营页：在 M2-D 页面提供渠道测试、投递状态、规则、抑制、聚合、
  阈值/延迟升级、死信和受审计的人工重放；规则和渠道写操作要求管理会话、CSRF、RBAC、
  step-up、理由和幂等，页面不显示渠道 Secret，重放不能伪造业务成功。该阶段已完成
  Mock/集成核心，真实厂商渠道、生产值班闭环和浏览器 E2E 待验收。
- 固定顺序遵循总纲：C5 -> `APR-01a` [done] -> `APR-01b` [adapter done] ->
  `APR-01c` [Mock done] -> `NOTIFY-01a` [done] / `01b` [done] -> `NOTIFY-01c` [transport done] -> M2-D ->
  `APR-01d` [done] -> `APR-01e [core done] + NOTIFY-01d [core done]` -> M3/M4/M5。审批和通知先于高风险页面，是为了避免页面先上线、
  后端仍信任可伪造的 `approvalId`，或在请求线程里同步等待外部渠道。
- 验收门槛：缺失/伪造/过期/撤销/跨组织/跨动作/改 payload/自审批/重复消费全部失败关闭；
  并发消费只产生一个业务结果；step-up 不满足时依赖调用为 0；outbox 在进程重启和渠道故障后
  不丢事件；死信可人工重放；Webhook SSRF、SIEM 脱敏和全链路秘密扫描有原始证据。
- 当前边界：APR-01a 已实现审批存储/API、绑定校验、职责分离、一次性消费和启动恢复；
  APR-01b 已实现 HMAC/Mock 外部回调适配器；APR-01c 已实现独立 OIDC step-up、新鲜度/ACR
  校验和 H/C 门禁；NOTIFY-01a 已实现 outbox、租约、退避、死信、重启恢复、deliveries
  查询和人工重放，均通过 Mock/故障或集成测试。APR-01d 已实现审批箱、串并行步骤、quorum、
  转交和撤回；APR-01e 已实现 break-glass 15 分钟单次授权和 24 小时复核核心；NOTIFY-01d
  已实现规则、抑制、聚合、升级和运营页。真实 OA 连接器、真实 IdP/MFA、break-glass
  告警/工单和生产复核、真实 SIEM/Collector/Syslog/生产证书、真实厂商渠道和生产值班闭环
  仍未验收。

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

### P1-3 客户端企业预置（对应 M3-C-1/M5，2-3 周）

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
| C4-03a 正式只读模型目录 | 已完成，待部署验收 | 严格 JSON、schema v1、稳定模型 ID、Provider 通配符、group、2 MiB、digest 和安全投影；管理 `109/109` | 真实只读挂载、digest 重启和失败关闭通过；admin-service 已把选择器展开为稳定模型 ID |
| C4-03b 用户级策略核心 | 已完成本地测试 | 版本化 `gatewayPolicy`、旧 M1 `unknown`、分步初始化、版本冲突、失败关闭和回读确认 | auth-service `26/26`；真实部署待验收 |
| C4-03c 管理 API、签发同步与交付 | 核心已实现，Mock/故障测试通过 | 额度/模型 API、幂等签发、issuance journal、apply/readback、同步后交付、失败补偿和启动恢复 | 真实共享卷/Magpie/IdP 验收待完成 |
| C4-04 完整管理到真实 Magpie 策略流 E2E | 已完成 | 管理 OIDC/CSRF、quota/models 分步设置、双设备独立 Key、真实模型拒绝/限额、部分失败、refresh/rotate 继承、故障后 pending、Journal/孤儿 Key 撤销、恢复同步、usage 归属和秘密扫描 | 完整链路 `PASS`；不接触真实用户目录或 `127.0.0.1:3425` |
| C4-03d 页面与剩余运营能力 | 1-2 周 | C4-03d 部分实现；基础审批、operation、查询/对账和导出页面已接入，剩余失败恢复入口和浏览器 E2E | 管理 API 失败关闭；页面只显示真实状态；失败可经 C5 对账 |
| M2-C5 操作/审计查询与对账 | 后端和基础页面已实现，Mock/故障测试通过 | operations/audit-logs/reconcile API、失败查询、子 operation 和人工补偿 | 可按操作 ID、操作者、目标、时间和结果查询；真实审计存储和生产演练未验收 |
| M2-E1 审批、step-up 与通知后端 | APR-01a-e 核心与 NOTIFY-01a-d 核心已实现；剩余真实环境验收 | 真实 OA、IdP/MFA、厂商渠道、SIEM 和 break-glass 生产验收 | APR-01a 高风险动作失败关闭、APR-01b HMAC/Mock 回调验签和防重放、APR-01c 独立 step-up 与 H/C 门禁、APR-01d 审批箱/串并行/quorum/转交/撤回、APR-01e 15 分钟单次授权/24 小时复核/提醒、NOTIFY-01a 原子 outbox/租约/死信/重放、NOTIFY-01b 渠道管理和 HTTPS/SSRF 防护、NOTIFY-01c SIEM transport/固定 L0 schema/dead-letters API、NOTIFY-01d 规则/抑制/聚合/升级/重放和运营页已通过 Mock/故障或集成测试；真实 OA/IdP/MFA、break-glass 告警/工单和生产复核、真实 SIEM 接收端、真实厂商连接和生产通知闭环待验收 |
| M2-D 看板与运营 | 核心已实现，生产验收未完成 | 总览、筛选、用量/费用趋势、授权 CSV 导出和操作历史 | 可稳定输出人/部门/模型报表；真实数据、浏览器 E2E、负载和异步/对象存储导出待验收 |
| M2-E2 内置审批与通知运营页 | 核心已实现，真实环境验收未完成 | 渠道/规则/投递/死信/聚合/抑制/升级页面已完成；补充真实审批、真实渠道、浏览器 E2E、break-glass 生产告警/工单与 24 小时复核演练 | 双人审批可证明；break-glass 15 分钟过期并 24 小时内复核；死信可受审计幂等重放 |
| M3-A 资源目录与签名 | 核心已实现，11/11 测试通过 | 五类资源目录、不可变版本、SHA-256 内容寻址、Ed25519 签名、发布/历史回滚、幂等和资源审计 | 内容与签名可验证；坏存储失败关闭；真实审批、管理台和客户端尚未接入 |
| M3-B 远程 MCP 治理 | 核心后端已实现，14/14 测试通过 | 注册表、企业统一端点、工具级权限、健康检查、凭据隔离和审计 | 未授权 MCP/工具不可见/不可调用；SSRF、凭据泄露、健康和审计边界通过单元/Mock 测试；管理台、真实审批联动、OIDC 组织分配、客户端同步、共享事务存储和生产验收未完成 |
| M3-C-1 客户端同步 | 控制面与核心已实现，client-sync 26/26、resource 15/15；产品页和本机落盘待完成 | 短期同步凭证、desired-state、设备上报、管理员 JSON 查询、HTTP 传输、签名 desired-state、原子安装、失败保留旧版本、离线缓存、强制/推荐策略、漂移、路径/符号链接防护、并发锁和状态秘密隔离 | 控制面 API 和 Mock/单元证据可验证；资源发布/回滚 UI、管理台员工产品流、本地 helper 安装器、目标 Agent 文件映射、Windows ACL、MDM、真实 IdP、浏览器 E2E、Docker/Compose 实机、5 分钟可见和生产验收未完成 |
| M3-C-2 只读管理可见性 | 已实现，admin-service 新增 5 项测试；企业全量 242 项通过 | 只读资源/同步 API、组织范围过滤、严格字段投影、独立服务令牌、GET-only/禁止重定向/超时/响应上限、`503 resource_service_unavailable` 和只读管理页面板 | Mock/集成测试可验证；发布/回滚 UI、审批联动、M3-B MCP 管理台、浏览器 E2E、真实 IdP、Docker/Compose 实机、灰度/自动回滚和生产验收未完成 |
| M3-D 受控本地 MCP | 运行时、helper、回环 HTTP server、stdio bridge 和 Codex 配置映射核心已实现，50/50 测试通过（含真实子进程 E2E）；产品集成与生产验收未完成 | 签名包、最小权限、策略审批、Secret Broker、JSON-RPC、审计、健康上报、Agent stdio bridge 和受管 Codex 配置 | 单元/Mock 测试覆盖未签名包拒绝、篡改/路径/版本冲突、原子安装、危险能力需外部 OS 沙箱适配及审计失败关闭；真实子进程 E2E 覆盖同步、helper HTTP、bridge 和审计；安装器/管理台员工产品流、真实 Codex 客户端、Windows/MDM、外部沙箱和生产验收未完成 |
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
