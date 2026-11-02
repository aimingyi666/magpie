# Magpie Enterprise Admin Service

独立的企业管理控制面。当前版本完成 **M2-A 管理身份底座**、**M2-B 只读治理**、
**M2-C2 管理写接口与权限映射**、**M2-C3 幂等与 intent/result 管理审计**和
**M2-C5 操作/审计查询与对账**、**M2-E1/APR-01a 服务端审批**，以及
**APR-01b HMAC 外部审批回调适配器**、**APR-01c 独立 OIDC step-up**、
**NOTIFY-01a transactional outbox** 和 **NOTIFY-01b 渠道管理/统一 HTTPS transport**：
管理 OIDC、
会话、CSRF、RBAC、组织范围、用户/部门/设备/凭证/模型/用量只读视图、只读 `usage.jsonl`
汇总，以及停用/启用用户、吊销设备和轮换当前凭证四个受控写接口。Auth 服务的
**M2-C1 内部写接口**继续只供服务间调用。

管理写接口已接入管理会话、CSRF、RBAC、组织子树、必填 `reason`、原子幂等预留、
`operationId` 和先写 intent 后调用依赖的审计门禁。成功和失败写操作都会写 result 管理审计；
审计不可用时失败关闭，不返回成功。C4-01 的网关机器协议已实现并通过本地测试；C4-02
`gateway-control` 受控适配器已实现并通过 15 项 Mock/故障测试，现已由 auth-service 自动
调用；Docker/真实共享卷验收仍未完成。C4-03a 的正式只读模型目录已实现：管理服务从只读
文件加载 schema v1 目录、校验摘要，并在写入前把 group/provider 选择器展开为稳定模型 ID；
当前总计 82 项管理测试通过（62 项管理服务集成测试 + 7 项目录专项 + 7 项通知渠道专项 + 6 项 SIEM 专项）。
auth-service 的
C4-03b/C4-03c 用户级策略核心、自动 apply/readback、issuance journal、失败补偿和同步后
交付已实现并通过 25 项测试。C4-03d 部分实现：管理页已提供额度/模型策略写表单，自动携带
CSRF、`Idempotency-Key`、理由和 `expectedVersion`，并只在完整证据链成立时显示“已生效”；
员工页已提供本人额度、模型、凭证、设备和同步状态只读门户。C5 已提供 operation 查询、
脱敏审计分页和四种人工对账动作，对账生成子 operation 且不改写原 intent/result。
页面 E2E、失败恢复入口和完整运营页面仍属于 D。C4-04 完整管理到真实 Magpie
策略流 E2E 已通过，覆盖双设备独立 Key、真实限额/模型拒绝、多凭证部分失败、refresh/rotate
继承、故障后 pending、Journal/孤儿 Key 撤销和恢复同步；Docker/共享卷、真实企业 IdP、
反向代理和浏览器 E2E 仍未验收。当前是“可演示 + 受控技术试点”，不是完整管理台或企业
生产完成，也仍没有对话正文审计。

APR-01b 已提供带 HMAC-SHA256、时间窗、nonce 防重放、issuer/audience、事件幂等和职责
分离的 **Mock 外部审批回调适配器**。真实飞书/OA/ServiceNow/Jira 的字段映射、网络、
证书、租户配置和故障演练尚未验证，不能把该适配器描述成已完成真实 OA 集成。

APR-01c 已提供独立 OIDC Client 的 step-up：`prompt=login`、`max_age`、essential
`auth_time`、MFA/ACR、`sub`/邮箱一致性校验，以及会话、管理员、IP、User-Agent 和
角色/权限/组织范围摘要绑定。H/C 风险写入、审批创建和审批决策必须通过新鲜 step-up；
普通 TTL 默认 10 分钟，关键动作 TTL 默认 5 分钟，`auth_time` 默认最多 2 分钟。
未配置 step-up 时高风险动作返回 `503 step_up_unavailable`，不会降级放行。

完整设计见
[`../../devtools/enterprise-feature-spec.md`](../../devtools/enterprise-feature-spec.md)
第 12.1-12.9 节；M2-C 的接口、幂等和审计状态机见第 12.8.1 节。真实实现状态见
[`../../devtools/enterprise-implementation-status.md`](../../devtools/enterprise-implementation-status.md)。
生产验收证据见
[`../../devtools/enterprise-acceptance-checklist.md`](../../devtools/enterprise-acceptance-checklist.md)。

## 当前能力

- 独立管理 OIDC Authorization Code + PKCE，不复用员工 OIDC Client。
- 管理登录要求 MFA；支持通过 `amr`/`acr` 判断，也支持向 IdP 请求指定 `acr_values`。
- 默认要求 `email_verified=true`，可在确认 IdP 契约后显式关闭。
- 高风险操作使用独立管理 OIDC Client 做 step-up，强制 `prompt=login`、`max_age` 和
  essential `auth_time`；普通/关键动作分别使用独立 TTL。
- step-up assertion 绑定当前会话、管理员 `sub`、IP、User-Agent 和角色/权限/组织范围摘要；
  身份、权限、网络或浏览器变化后要求重新认证。
- `HttpOnly` 管理会话 Cookie、独立 CSRF Cookie、绝对/空闲超时、IP 和 User-Agent 绑定。
- 管理 IP 允许列表，配置错误时 fail closed。
- 每次请求重新计算角色和组织范围，角色撤销在下一次请求立即生效。
- 服务间调用使用独立 `AUTH_INTERNAL_ADMIN_TOKEN`，不接受浏览器 Cookie 或员工 admin token。
- 原子 JSON 存储，损坏文件不会被当成空存储。
- 最小管理页面 `/admin/`、`/api/v1/admin/me`、组织范围和健康检查。
- 管理页和写表单会显示近期认证状态；`step_up_*` 错误提供重新认证入口。
- 用户、部门、设备、凭证、模型和用量的只读 API；服务端按组织子树过滤。
- 用户与部门使用显式 `userOrgUnits` 映射，不按邮箱或姓名猜部门。
- 用量只读挂载企业网关数据卷，按 `callerKeyId -> credential -> user -> 组织` 归属；不返回
  对话正文或任何 Key/token 材料。
- 四个受控管理写接口：停用/启用用户、吊销设备、轮换当前凭证。每次写操作校验会话、CSRF、
  权限、目标组织子树和 `reason`；auth-service 故障稳定映射为 `502 dependency_unavailable`。
- 两个额度/模型策略写接口：`PUT .../policy/quota` 和 `PATCH .../policy/models`。管理服务
  校验 `expectedVersion`、组织范围、理由和幂等键，展开模型目录选择器后调用 auth-service；
  同步未完成的状态不会被当成成功。
- 写响应使用字段白名单，不返回 Gateway Key、设备令牌、token hash、公钥或服务令牌。
- 每个管理写操作获得独立 `operationId`，并持久化操作状态、请求指纹、白名单前后摘要以及
  intent/result 两条管理审计。
- 可选 `Idempotency-Key` 按管理员主体隔离并以 SHA-256 保存，不保存原值。同键同请求复用
  原响应和原 `operationId`；同键异体返回 `409 idempotency_conflict`；执行中重放返回
  `409 operation_in_progress`。
- intent 审计失败时返回 `503 audit_unavailable`，不调用 auth-service；result 审计失败时
  不返回成功，操作停留在 `dependency_invoked`，需要后续运维核对，不能自动重试依赖。
- `GET /api/v1/admin/operations/{operationId}` 按原动作权限和组织范围返回真实状态、依赖
  调用时间、失败凭证、策略版本和对账状态。
- `GET /api/v1/admin/audit-logs` 支持 operationId、操作者、动作、目标、结果和时间过滤；
  默认 50 条、最大 200 条，使用绑定管理员会话和查询条件的签名 cursor，响应只含脱敏元数据。
- `POST /api/v1/admin/operations/{operationId}/reconcile` 要求 `operations.reconcile`、
  CSRF、`reason`、`approvalId`、`Idempotency-Key` 和人工确认所需的 `evidenceRef`；
  动作固定为 `retry_desired`、`rollback_previous`、`confirm_applied`、
  `confirm_not_applied`。每次对账创建子 operation 并追加 intent/result 审计，父 operation
  的状态、响应和原审计保持不变。
- `POST /api/v1/admin/approvals`、`GET /api/v1/admin/approvals/{id}`、
  `POST /api/v1/admin/approvals/{id}/decisions` 和
  `POST /api/v1/admin/approvals/{id}/revoke` 提供审批申请、查询、批准/拒绝和撤销。
  申请、决策、撤销要求管理会话、CSRF、必填理由和对应权限；决策/撤销还会校验目标组织范围。
- APR-01a 使用 24 小时有效期和 L/M/H/C 风险。审批绑定环境、申请人、组织、动作、目标、
  理由、规范化 payload SHA-256、binding SHA-256 和策略版本；禁止自审批。
- 除低风险 `user.enable` 外，现有受支持管理写操作都要消费有效审批。审批在业务依赖调用前
  原子预留，成功后一次性消费；并发复用返回 `409 approval_consumed`，进程启动时遗留
  `reserved` 状态按失败关闭处理为 `consumed`。
- APR-01b 提供 `POST /api/v1/integrations/approvals/callback`：校验
  `X-Magpie-Timestamp`、`X-Magpie-Nonce`、`X-Magpie-Signature`、issuer、audience 和
  schema v1；同一 `eventId` 幂等，nonce 在有效期内置为已用，重复 nonce 返回
  `409 approval_callback_replay`。回调只更新审批状态和决策/系统审计，不直接调用
  auth-service 或执行管理动作；原绑定校验和一次性消费仍在业务写入前执行。

## M2-C4 目标边界（C4-01/C4-02/C4-03a/C4-03b/C4-03c 核心已实现，C4-03d 部分实现，C4-04 完整策略流 E2E 已通过）

除四个停用/吊销/轮换写接口外，C4-03c 已新增：

```http
PUT   /api/v1/admin/users/{id}/policy/quota
PATCH /api/v1/admin/users/{id}/policy/models
```

额度接口需要 `quota.write`，模型接口需要 `models.write`；两者都必须经过管理会话、CSRF、
RBAC、目标组织范围、非空 `reason`、可选 `approvalId`、`expectedVersion`（或一致的
`If-Match`）、持久化 `Idempotency-Key` 和 intent/result 审计。`Idempotency-Key` 的请求
指纹必须包含规范化后的完整额度或模型 payload；只改额度值或模型列表但复用同一键，必须返回
`409 idempotency_conflict`。

策略状态和真实生效规则：

- `limits=[]` 表示明确移除额度上限，不能解释成“未知”；`models=[]`、裸 `*`、显示名、
  未知模型和隐式扩大 Provider 必须拒绝。
- `expectedVersion` 必填，落后返回 `409 policy_version_conflict`；`If-Match` 与
  `expectedVersion` 同时存在时必须一致。
- 依赖变更后只有所有活跃凭证都被网关回读确认，`gatewayPolicy` 才能进入 `known`。
- 部分凭证失败返回 HTTP 200、`state=partial_success`、
  `requiresReconciliation=true`，策略保持 `pending`，并列安全
  `credentialId/deviceId/errorCode`。
- 全部失败或适配器超时返回 `502 dependency_unavailable`；result 审计失败返回
  `503 audit_unavailable`，operation 保持 `dependency_invoked`。
- 默认不自动回滚。人工重试、回滚上一确认版本或确认结果必须由 C5 创建新的子 operation。
- `pending` 时 auth-service 的 join、refresh 和 rotate 必须失败关闭；`unknown` 时不得
  伪造历史策略。

admin-service 不能直接读写网关的 `caller-keys.json`，也不能获得配置目录写权限。C4 的固定
链路是 admin-service -> auth-service -> 独立 `gateway-control` -> 白名单 Magpie CLI ->
独立回读。C4-02 的 `gateway-control` 已实现，使用专用非 root 账号、固定
`GATEWAY_CONTROL_CONFIG_HOME`、独立 Bearer 服务令牌、10 秒超时、64 KiB 输出上限，且不
映射公网端口、不访问 Docker socket、不读取 issuer Key/OIDC Secret/设备令牌/管理员会话。
当前 Bearer 服务令牌不是 mTLS；mTLS/SPIFFE/工作负载身份是生产加固项。

真实 Magpie 工作分支已经提供 schema v1 的
`magpie gateway-key describe <id> --json` 与原子
`magpie gateway-key policy apply <id> --json`，并通过 Go 单测、CLI 回归和隔离真实二进制
冒烟测试。C4-02 的 `gateway-control` 已固定调用这两个命令，禁止解析人类可读 `limit/models`
文本或用多次 CLI 命令拼接目标状态冒充生产回读；真实 Docker/共享卷验收仍未完成。
C4-03a 由 admin-service 加载正式目录并把 group/provider 选择器展开为稳定模型 ID；
auth-service 和 gateway-control 只接收稳定模型 ID，不加载目录。C4-03b/C4-03c 的策略核心、
自动 apply/readback、issuance journal、失败补偿和同步后交付已在 auth-service 接通；
C4-03d 已补管理页额度/模型写表单、完整证据链状态和员工只读状态门户；C5 已实现 operation
查询、脱敏审计分页和人工对账。页面 E2E、运营页面和失败恢复入口仍属于 D。C4-04 的完整
管理到真实 Magpie 策略流 E2E 已通过，
但 Docker/共享卷、真实企业 IdP、反向代理、浏览器和生产部署仍未验收。
完整契约见
[`../../devtools/enterprise-feature-spec.md`](../../devtools/enterprise-feature-spec.md) 第
12.8.1.5 节和
[`../../devtools/enterprise-master-plan.md`](../../devtools/enterprise-master-plan.md) 的
M2-C4 工作包。

## 角色

| 角色 | 当前用途 |
| --- | --- |
| `employee` | 无管理权限 |
| `department_admin` | 指定组织单元及子单元内的只读视图、用户/设备/凭证受控写操作、`quota.write`/`models.write` 策略写入和审批申请/读取；仍需真实 IdP、代理和网关验收 |
| `enterprise_admin` | 全企业治理，但不默认获得正文审计权限 |
| `auditor` | 只读审计和用量 |
| `security_admin` | 设备、凭据、告警和人员停用 |
| `ops_admin` | 健康、设备和运维处置 |
| `super_admin` | 全域治理和高风险权限 |

角色绑定包含 `scopeOrgUnitId`、`validFrom` 和 `validTo`。部门范围会包含其子部门；服务端先
判断权限，再判断目标组织范围。

## 部署前提

1. 企业 IdP 为企业管理后台单独登记回调：

   ```text
   ADMIN_PUBLIC_URL/admin/oauth/callback
   ```

2. 使用独立的管理 OIDC Client，不要复用员工登录 Client。
3. 在 IdP 启用 MFA/条件访问；若 IdP 支持约定的认证上下文，设置
   `ADMIN_ALLOWED_ACR_VALUES`。
4. 为 step-up 再登记一个独立 Client 和回调：

   ```text
   ADMIN_PUBLIC_URL/admin/oauth/step-up/callback
   ```

   配置 `ADMIN_STEP_UP_OIDC_CLIENT_ID`、`ADMIN_STEP_UP_OIDC_CLIENT_SECRET` 和
   `ADMIN_STEP_UP_REDIRECT_URI`。这些值必须成组配置；step-up Client ID 和回调也不能与
   普通管理登录相同。若 IdP 支持约定的认证上下文，另行设置
   `ADMIN_STEP_UP_ALLOWED_ACR_VALUES`。
5. 生成互相独立的高熵值：

   ```text
   ADMIN_SESSION_SECRET
   ADMIN_OIDC_CLIENT_SECRET
   ADMIN_STEP_UP_OIDC_CLIENT_SECRET
   AUTH_INTERNAL_ADMIN_TOKEN
   ```

   step-up TTL 可通过 `ADMIN_STEP_UP_TTL_SECONDS`（默认 600 秒）、
   `ADMIN_STEP_UP_CRITICAL_TTL_SECONDS`（默认 300 秒）和
   `ADMIN_STEP_UP_AUTH_TIME_MAX_AGE_SECONDS`（默认 120 秒）收紧；关键 TTL 不得大于普通 TTL。

`AUTH_INTERNAL_ADMIN_TOKEN` 由 auth-service 和 admin-service 共用，只在 Compose/内网中传递。
它必须不同于 `AUTH_ADMIN_TOKEN`、员工设备令牌、Gateway Key 和 issuer Key，且不能进入浏览器。

## Compose 启动

从 `enterprise/` 目录：

```bash
cp .env.example .env
docker compose --profile admin up -d
docker compose ps
curl http://127.0.0.1:3445/healthz
```

`--profile admin` 会同时启动网关、auth-service 和 admin-service。管理服务的默认容器端口是
`3445`，数据保存在独立卷 `admin-data`，不会和员工设备数据混用。

M2-B 还会把网关卷以只读方式挂载到管理容器：

```yaml
volumes:
  - admin-data:/data
  - magpie-data:/magpie-readonly:ro
environment:
  ADMIN_USAGE_PATH: /magpie-readonly/magpie/usage.jsonl
  ADMIN_MODEL_CATALOG_PATH: /etc/magpie-enterprise/model-catalog.json
```

`ADMIN_MODEL_CATALOG_PATH` 是 C4-03a 已实现的只读模型目录入口，Compose 要求
`enterprise/model-catalog.json` 存在并以只读方式挂载。目录必须是严格 JSON、schema v1、
2 MiB 以内，稳定模型 ID、`providerWildcards` 和 group 均显式声明；坏文件、重复 JSON key、
未知字段、尾随内容、重复项和未知引用均导致启动失败，API/日志不泄漏内部路径。
`ADMIN_MODEL_CATALOG_DIGEST` 可选固定文件 SHA-256；修改目录后必须重算摘要并重启服务。
`ADMIN_MODELS` 只在未配置正式目录时保留兼容显示，不能作为稳定模型 ID、Provider 通配符
或 group 的权限事实来源。当前由 admin-service 加载目录并展开选择器；auth-service 只接收
展开后的稳定模型 ID，不加载模型目录。
`ADMIN_USAGE_MAX_BYTES`、
`ADMIN_USAGE_MAX_LINE_BYTES`、`ADMIN_USAGE_MAX_RECORDS`、`ADMIN_USAGE_MAX_FIELDS` 和
`ADMIN_USAGE_MAX_RANGE_DAYS` 限制单次查询资源。管理容器不能写 `magpie-data`。

生产部署至少要做到：

- 管理域名只经过 HTTPS 反向代理，不复用员工认证域名。
- `ADMIN_ALLOWED_IPS` 只允许办公网、VPN 或专用管理网。
- auth-service 的内部状态接口不经过公网反向代理。
- 管理 Cookie 使用 `Secure`、`HttpOnly` 和 `SameSite=Lax`。
- 管理 JSON 与 auth JSON 分开备份，并验证恢复后的角色和吊销状态。

## 首次管理员

有两种引导方式，生产优先使用稳定的 IdP `sub`：

```dotenv
ADMIN_BOOTSTRAP_SUBJECTS=<idp-subject-id>
# 或者仅在受控试点使用：
ADMIN_BOOTSTRAP_EMAILS=platform-admin@corp.example
ADMIN_BOOTSTRAP_VALID_HOURS=24
```

首次成功登录会创建一条有到期时间的 `super_admin` 角色绑定。验证管理员能登录后，应尽快写入
正式角色绑定并移除 bootstrap 配置。bootstrap 不是长期授权机制。

## 数据

默认存储为 `ADMIN_STORE_PATH` 指向的 JSON 文件，包含：

```text
orgUnits
userOrgUnits
roleBindings
adminSessions
adminAuditLogs
adminOperations
adminIdempotency
approvalRequests
approvalDecisions
approvalConsumptions
approvalCallbackEvents
approvalCallbackNonces
stepUpAssertions
```

当前还没有角色/组织写 API，因此试点初始化时可以由受控运维流程写入 `orgUnits`、
`userOrgUnits` 和 `roleBindings`。停止服务后备份并修改文件，再启动服务；不要在服务运行时
手工覆盖。后续会通过带权限、完整幂等和管理审计的 API 替代手工维护。

存储中只保存会话 Hash、CSRF Hash、User-Agent Hash 和角色数据，不保存浏览器 Cookie、
OIDC Client Secret、服务令牌或 Gateway Key。

凭证和用量不复制到管理存储：

- 凭证元数据从 auth-service 内部读接口读取；M2-C2 已通过白名单字段把四个受控写操作暴露
  给管理 API，但不转发内部服务令牌或任何秘密。
- 用量从网关卷中的 `usage.jsonl` 读取，管理服务只做 metadata 汇总，不写该卷。
- 读取失败、损坏、尾部半行或超过配置上限时返回 `503 storage_unavailable`，不会把部分数据
  伪装成完整报表。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/healthz` | 未认证存活和存储计数 |
| `GET` | `/admin/login` | 开始管理 OIDC 登录 |
| `GET` | `/admin/oauth/callback` | 管理 OIDC 回调 |
| `GET` | `/admin/oauth/step-up/start` | 为当前管理会话开始独立 OIDC step-up；只允许站内 `/admin/` 返回路径 |
| `GET` | `/admin/oauth/step-up/callback` | step-up 回调；校验 state、PKCE、`auth_time`、MFA/ACR 和原管理员身份 |
| `GET` | `/admin/` | 最小管理页面 |
| `GET` | `/api/v1/admin/me` | 当前身份、角色、权限、范围、CSRF token 和 step-up 状态 |
| `POST` | `/api/v1/admin/logout` | 注销会话；表单请求会跳回登录页 |
| `GET` | `/api/v1/admin/org-units` | 当前管理员可见组织 |
| `GET` | `/api/v1/admin/org-units/{id}` | 单个组织，服务端校验范围 |
| `GET` | `/api/v1/admin/departments` | 部门只读视图，复用组织单元数据 |
| `GET` | `/api/v1/admin/users` | 当前管理员可见员工 |
| `GET` | `/api/v1/admin/users/{id}` | 单个员工；跨范围返回 `403` |
| `GET` | `/api/v1/admin/devices` | 当前范围内设备元数据 |
| `GET` | `/api/v1/admin/credentials` | 当前范围内凭证元数据；不含 Key/hash |
| `GET` | `/api/v1/admin/models` | 返回正式只读模型目录的安全投影和 `catalog` 摘要；未配置目录时才退回 `ADMIN_MODELS` 兼容显示 |
| `GET` | `/api/v1/admin/usage/summary` | Token、费用、成功率及人/部门/模型/Agent 汇总 |
| `GET` | `/api/v1/admin/usage/timeseries` | `bucket=hour\|day`、`groupBy=user\|department\|model\|agent\|all` 的趋势 |
| `GET` | `/api/v1/admin/health` | 管理服务读取 auth-service 最小状态 |
| `POST` | `/api/v1/admin/users/{id}/disable` | 停用员工；要求 CSRF、`users.disable`、组织范围和 `reason` |
| `POST` | `/api/v1/admin/users/{id}/enable` | 启用员工；不恢复旧设备或旧凭证 |
| `POST` | `/api/v1/admin/devices/{id}/revoke` | 吊销设备和当前凭证 |
| `POST` | `/api/v1/admin/credentials/{id}/rotate` | 轮换当前凭证，新 Key 等待目标设备刷新 |
| `PUT` | `/api/v1/admin/users/{id}/policy/quota` | 调额；要求 `quota.write`、`expectedVersion` 和幂等校验 |
| `PATCH` | `/api/v1/admin/users/{id}/policy/models` | 模型授权；要求 `models.write`、`expectedVersion` 和幂等校验 |
| `POST` | `/api/v1/admin/approvals` | 申请审批；要求被审批动作的原权限、CSRF、`reason` 和动作绑定字段 |
| `GET` | `/api/v1/admin/approvals/{id}` | 读取审批状态和决策；要求 `approvals.read` 和目标组织范围 |
| `POST` | `/api/v1/admin/approvals/{id}/decisions` | 批准/拒绝；要求 `approvals.decide`、CSRF 和 `reason`，禁止自审批 |
| `POST` | `/api/v1/admin/approvals/{id}/revoke` | 撤销审批；要求 `approvals.revoke`、CSRF 和 `reason` |
| `POST` | `/api/v1/integrations/approvals/callback` | 外部审批 HMAC 回调；不使用管理会话/CSRF，只改变审批状态 |
| `GET` | `/api/v1/admin/notifications/deliveries` | 查询 outbox 投递；要求 `notifications.read`，只返回脱敏状态；当前无 cursor，`count` 为当前页数量 |
| `POST` | `/api/v1/admin/notifications/deliveries/{ntd_id}/retry` | 重放死信；要求 `notifications.replay`、CSRF、理由和 `Idempotency-Key`，并写系统审计 |

稳定错误码包括 `not_signed_in`、`session_expired`、`session_idle`、`session_binding_mismatch`、
`forbidden_role`、`forbidden_scope`、`csrf_invalid`、`mfa_required`、`email_not_verified` 和
`target_not_found`，以及 `dependency_unavailable`、`storage_unavailable`、
`invalid_time_range`、`invalid_json`、`invalid_reason`、`invalid_idempotency_key`、
`idempotency_conflict`、`operation_in_progress`、`audit_unavailable`、`approval_required`、
`approval_invalid`、`approval_expired`、`approval_revoked`、`approval_consumed`、
`approval_target_mismatch`、`approval_payload_mismatch` 和
`approval_separation_required`。APR-01b 另有 `approval_callback_unavailable`、
`approval_callback_invalid`、`approval_callback_timestamp_invalid`、
`approval_callback_signature_invalid`、`approval_callback_issuer_invalid`、
`approval_callback_audience_invalid`、`approval_callback_replay`、
`approval_callback_conflict` 和 `approval_callback_scope`。APR-01c 另有
`step_up_required`、`step_up_expired`、`step_up_binding_mismatch`、
`step_up_unavailable` 和 `step_up_invalid`。

外部回调契约：

```text
签名输入 = <timestamp>.<nonce>.<raw-body>
签名头   = X-Magpie-Signature: sha256=<64 位小写 hex>
必要配置 = ADMIN_APPROVAL_CALLBACK_SECRET / ISSUER / AUDIENCE
默认窗口 = timestamp 300 秒；nonce 记录至少保留 600 秒
```

secret 至少 32 字符；secret、issuer、audience 必须成组配置，否则服务启动失败。
回调事件只保存 eventId、事件摘要、审批/决策关联、issuer、audience 和 nonce 摘要，不保存
原始请求体或 secret。事件重放返回原审批投影；同一 eventId 携带不同 raw body 返回
`409 approval_callback_conflict`。

NOTIFY-01a 的 outbox 配置：

```text
ADMIN_NOTIFICATION_OUTBOX_POLL_SECONDS=30
ADMIN_NOTIFICATION_OUTBOX_LEASE_SECONDS=60
ADMIN_NOTIFICATION_OUTBOX_MAX_ATTEMPTS=6
ADMIN_NOTIFICATION_OUTBOX_BATCH_SIZE=20
```

NOTIFY-01b 的渠道配置：

```text
ADMIN_NOTIFICATION_CHANNELS_ENABLED=false
ADMIN_NOTIFICATION_OUTBOUND_ALLOWLIST=
ADMIN_NOTIFICATION_EMAIL_RECIPIENT_DOMAINS=
ADMIN_NOTIFICATION_HTTP_TIMEOUT_MS=5000
ADMIN_NOTIFICATION_HTTP_MAX_RESPONSE_BYTES=65536
ADMIN_NOTIFICATION_HTTP_MAX_REDIRECTS=3
```

可用渠道类型为 `email`、`im`、`webhook` 和 `ticketing`。渠道只保存 `secretRef` 环境变量
名，不保存 Secret；Webhook 要求 `secretRef`，发送
`X-Magpie-Timestamp`、`X-Magpie-Nonce` 和
`X-Magpie-Signature: v1=HMAC-SHA256(secret, timestamp.nonce.rawJsonBody)`。出站必须是
HTTPS:443、命中 host allowlist，并在每次请求和 307/308 重定向时重新解析并固定公网地址；
拒绝私网、回环、链路本地、云元数据和不允许的端口。

渠道 API：

```text
GET   /api/v1/admin/notifications/channels
POST  /api/v1/admin/notifications/channels
PATCH /api/v1/admin/notifications/channels/{channelId}
POST  /api/v1/admin/notifications/channels/{channelId}/test
GET   /api/v1/admin/notifications/dead-letters
```

读操作要求 `notifications.channels.read`；创建/更新要求 `.write`，测试要求 `.test`。所有写
操作还要求管理会话、CSRF、非空理由、`Idempotency-Key`、审计和 H 风险 step-up。渠道测试
只写 `notificationChannelTests` 结果，不创建伪造的业务 delivery。默认禁用渠道；未启用渠道
或没有 transport 时不会创建 dispatcher，也不会把事件标成 `delivered`。邮件/IM/工单使用
厂商 HTTPS 网关契约，不是原生 SMTP/Graph/飞书/Teams/ServiceNow/Jira SDK。`siem` 渠道支持
`http-collector`/`otlp-http`/`syslog-tls`，使用固定 L0 schema；真实 SIEM/Collector/
Syslog/生产证书、rules/suppress API、完整通知运营页和真实厂商网关验收仍未完成。

四个写接口的成功响应包含 `requestId`、`operationId`、动作名、目标 ID 和白名单业务摘要。
请求可携带 `Idempotency-Key`（去空白后最长 128 个字符且不得含控制字符）。服务端只持久化
`SHA-256(actorSubjectId + "\0" + key)`，不保存原值。请求指纹覆盖
`action/targetType/targetId/reason/approvalId`；额度/模型写接口还把规范化后的业务 payload
和 `expectedVersion` 纳入指纹：

- 同键同请求且原操作成功：返回原成功响应、原 `operationId` 和原 `requestId`，不再次调用
  auth-service。
- 同键同请求且原操作失败：重放原稳定错误、原状态码和原 `operationId`，不自动重试依赖。
- 同键异体：返回 `409 idempotency_conflict`。
- 原操作仍在执行：返回 `409 operation_in_progress`。
- 未提供幂等键：仍创建 operation 和两条管理审计，但不提供跨请求重放。

额度/模型写接口的请求指纹已包含规范化后的完整 payload 和 `expectedVersion`；同键不同额度
或模型返回 `409 idempotency_conflict`。`src/auth-client.js` 已支持 JSON `PUT/PATCH` body
和 `If-Match` 透传，管理端会把 auth-service 返回的 `known`、`pending`、
`partial_success` 和 `unknown` 原样呈现，不能把未确认状态显示为“已生效”。

管理写操作的 intent 审计和幂等预留位于同一原子存储事务中；intent 审计写入失败时，不会
调用 auth-service。依赖调用完成后必须成功写入 result 审计和最终操作状态，否则返回
`503 audit_unavailable`，operation 保持 `dependency_invoked`。审计记录不包含 Gateway Key、
设备令牌、Cookie、token hash 或服务令牌。

## 测试

```powershell
$node = 'D:\Environment\node-v26.12.1\node.exe'
Get-ChildItem src\*.js | ForEach-Object {
  & $node --check $_.FullName
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
& $node --test test\admin-service.test.mjs test\model-catalog.test.mjs test\notification-channels.test.mjs test\notification-siem.test.mjs
```

2026-11-02 的实际结果：`82 passed, 0 failed`（62 项管理服务集成测试 + 7 项目录专项测试 +
7 项通知渠道专项测试 + 6 项 SIEM 专项测试）。
使用 Mock IdP、Mock auth-service 和临时
`usage.jsonl`，覆盖登录、MFA、已验证邮箱、ACR 请求、CSRF、角色撤销、部门子树、兄弟部门
拒绝、用户详情跨范围拒绝、会话过期、IP fail-closed、依赖不可用、凭证元数据、用量归属、
时间和分组参数、损坏/超限用量拒绝、凭据不落盘和损坏存储拒绝加载。M2-C2 覆盖四个管理写
接口、管理会话/CSRF/RBAC、组织范围写校验、必填理由、幂等键格式、坏 JSON、目标不存在、
依赖故障和写响应/存储脱敏。M2-C3 新增覆盖成功/失败重放、同键异体、并发执行中、intent
审计失败时依赖调用为 0、result 审计失败不返回成功，以及 operation 停留在
`dependency_invoked`。C4-03a 目录专项测试覆盖只读加载、严格 JSON/重复 key/未知字段/
尾随内容拒绝、2 MiB 上限、schema 版本、稳定模型 ID、显式 Provider 通配符、group 展开、
digest 不匹配和失败关闭。C4-03c 集成测试覆盖额度/模型 API、模型选择器展开、
`expectedVersion` 冲突、payload 绑定幂等、同步状态透传、`partial_success` 和依赖故障。
C4-03d 页面测试覆盖 CSRF meta、静态脚本、只读角色无写表单、完整证据链才显示 verified，
以及页面不泄漏 Gateway Key 或 token hash。M2-C5 覆盖 operation 详情权限/组织范围、审计
过滤和 cursor 绑定、脱敏、四种对账动作、父/子 operation 关系、原审计不可改写、旧快照
失败关闭、依赖/审计失败和幂等重放。APR-01a 覆盖风险与摘要稳定性、审批申请/决策/撤销的
CSRF/权限/组织范围/自审批拒绝、动作/目标/理由/payload/策略版本绑定、过期/撤销、一次性
消费、并发复用和启动恢复失败关闭。APR-01b 覆盖回调配置成组校验、HMAC 原始 body 验签、
时间窗、issuer/audience、nonce 重放、
eventId 幂等、错误签名/媒体类型/缺失头、审批状态和职责分离、过期/撤销/已消费失败关闭、
旧 store 集合迁移和 secret 不落响应/存储。APR-01c 覆盖无 step-up 时 H 风险失败关闭且
依赖调用为 0、成功 step-up、H/C 独立 TTL、角色/范围/IP/User-Agent 绑定变化、IdP
`sub`/邮箱变化、缺失/过期/未来 `auth_time`、缺失 MFA/ACR、`prompt=login`/`max_age`/
essential `auth_time`/ACR 请求、未配置时失败关闭、站外返回路径拒绝、配置一致性和 secret
不落响应/存储。NOTIFY-01a 新增覆盖 8 种 L0 事件、字段白名单、稳定 `eventId`/`deliveryId`
幂等、租约恢复、并发串行、1/5/15/60/360 分钟退避、死信、deliveries 脱敏查询、受审计
人工重放、审批/结果审计与 outbox 原子提交、渠道 RBAC/CSRF/step-up/理由/幂等/审计、
渠道投影与收件人限制、Webhook HMAC、HTTPS/allowlist/DNS 固定解析、SSRF 和重定向拒绝、
fanout 去重、渠道测试记录，以及有/无 transport 时的启动行为。管理服务当前为
`82 passed, 0 failed`，
auth-service 为 `25 passed, 0 failed`，gateway-control 为 `15 passed, 0 failed`，合计
`122 passed, 0 failed`。

尚未验证：

- 真实 Entra/Okta/Keycloak 的 Claim、MFA、ACR、普通/step-up Client 回调地址和条件访问。
- Docker Compose 构建和健康检查；当前机器没有 Docker CLI。
- 浏览器、反向代理、真实 Cookie 域和公司 CA 的端到端演练。
- C4-03a 的真实部署验收，以及真实共享卷上的用户级模型授权链路。
- C4-03c 的 Docker/真实共享卷和生产部署验收；C4-04 已完成隔离真实 Magpie 的完整管理链路、
  回读和故障恢复 E2E，但真实共享卷、真实 IdP、反向代理和浏览器仍未验收。C4-03d 仍有
  页面 E2E、停用/吊销/轮换页面和失败恢复入口待 D 完成；C5 的查询与对账目前只有
  Mock/故障测试证据，尚未接入完整管理页面。
- APR-01c 的代码和 Mock IdP 集成测试已完成；APR-01d/e 及真实管理 IdP step-up/MFA/ACR、
  真实飞书/OA/ServiceNow/Jira 适配器及生产回调演练、串并行审批箱、转交、break-glass、
  审批通知仍未实现/未验收。
- NOTIFY-01a/01b/01c 默认不启用渠道；未启用渠道或没有 transport 时正常启动不创建 dispatcher。
  `operation.audit_failed` 只有 schema、暂无可靠触发点；deliveries 查询无 cursor。
  邮件/IM/工单是统一 HTTPS 网关契约，不是原生厂商 SDK；真实网关、证书、租户配置和投递
  未验收。SIEM transport 已实现并通过 6 项专项测试，但真实 SIEM/Collector/Syslog/
  生产证书、rules/suppress API、聚合、升级和完整通知运营页面未实现/未验收。
- 四个 M2-C2 写接口在真实 IdP、反向代理、真实 auth-service 和真实网关上的端到端演练。

## 当前限制

- 单实例 JSON 存储，不适合多副本；超过 50-100 人或需要 HA 时迁移 PostgreSQL。
- 每个管理请求会更新 `lastSeenAt`，小规模试点可接受，规模化需要共享存储和写合并。
- result 审计失败时 operation 会停在 `dependency_invoked`；C5 已提供查询、审计分页和受控
  对账，但自动补偿、告警队列和真实运维演练仍未实现/验收。
- 审批已有服务端 API、一次性消费、HMAC 外部回调适配器和 APR-01c step-up；NOTIFY-01a/01b/01c
  已有 outbox、渠道 API、统一 HTTPS/SIEM transport 与死信重放，但没有审批管理 UI、真实 OA
  连接器、审批箱、break-glass、真实 SIEM 接入、通知运营页或真实厂商网关验收；审批、step-up、
  渠道和 outbox 状态存储仍是
  单实例 JSON，尚未做多实例并发和真实 OA/IdP 验收。
- 角色/组织目前没有管理 API，尚未接入 SCIM 或 IdP Group 映射。
- 用量读取当前基于单个 `usage.jsonl` 文件；轮转、归档、超大文件和事件存储查询尚未验收。
- CSV 导出、费用趋势图、完整管理写按钮和运营看板属于 M2-D；C5 已提供审计过滤/分页和
  管理员操作查询 API，尚未接入完整页面。
- IPv6 允许列表当前只支持精确 `/128`。
- 没有任何对话正文；完整内容审计属于 M4，必须单独授权和审计。
- M2-C2/C3 的管理 API 已接入会话、CSRF、RBAC、组织范围、理由、幂等和 intent/result
  管理审计；C4-03c 已完成额度/模型 API 到 auth-service、gateway-control、apply/readback
  和同步后交付的 Mock/故障链路，C4-04 已通过完整管理到真实 Magpie 策略流 E2E。
  Docker/真实共享卷、真实企业 IdP、反向代理、C4-03d 剩余页面、C5 生产验收和 D 仍未
  完成，不能把 Mock 测试或隔离 E2E 通过描述成生产管理闭环。
