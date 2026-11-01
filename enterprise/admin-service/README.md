# Magpie Enterprise Admin Service

独立的企业管理控制面。当前版本完成 **M2-A 管理身份底座**、**M2-B 只读治理**、
**M2-C2 管理写接口与权限映射**和 **M2-C3 幂等与 intent/result 管理审计**：管理 OIDC、
会话、CSRF、RBAC、组织范围、用户/部门/设备/凭证/模型/用量只读视图、只读 `usage.jsonl`
汇总，以及停用/启用用户、吊销设备和轮换当前凭证四个受控写接口。Auth 服务的
**M2-C1 内部写接口**继续只供服务间调用。

管理写接口已接入管理会话、CSRF、RBAC、组织子树、必填 `reason`、原子幂等预留、
`operationId` 和先写 intent 后调用依赖的审计门禁。成功和失败写操作都会写 result 管理审计；
审计不可用时失败关闭，不返回成功。C4-01 的网关机器协议已实现并通过本地测试；C4-02
`gateway-control` 受控适配器已实现并通过 15 项 Mock/故障测试，但尚未接入 admin-service，
也尚未完成 Docker/真实共享卷验收。C4-03a 的正式只读模型目录已实现：管理服务从只读文件
加载 schema v1 目录、校验摘要并让 `GET /api/v1/admin/models` 返回安全目录投影；当前总计
31 项管理测试通过。auth-service 的 C4-03b 用户级策略核心也已实现并通过 18 项测试，但它
尚未自动接入该目录，admin-service 也尚未编排 apply/readback 与同步后交付；调额/模型授权
管理链路和操作/审计查询仍未实现，后者属于 C5。管理页面仍没有写操作按钮，因此当前是
“可演示 + 受控技术试点”，不是完整管理台或企业生产完成。当前仍没有对话正文审计。

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
- `HttpOnly` 管理会话 Cookie、独立 CSRF Cookie、绝对/空闲超时、IP 和 User-Agent 绑定。
- 管理 IP 允许列表，配置错误时 fail closed。
- 每次请求重新计算角色和组织范围，角色撤销在下一次请求立即生效。
- 服务间调用使用独立 `AUTH_INTERNAL_ADMIN_TOKEN`，不接受浏览器 Cookie 或员工 admin token。
- 原子 JSON 存储，损坏文件不会被当成空存储。
- 最小管理页面 `/admin/`、`/api/v1/admin/me`、组织范围和健康检查。
- 用户、部门、设备、凭证、模型和用量的只读 API；服务端按组织子树过滤。
- 用户与部门使用显式 `userOrgUnits` 映射，不按邮箱或姓名猜部门。
- 用量只读挂载企业网关数据卷，按 `callerKeyId -> credential -> user -> 组织` 归属；不返回
  对话正文或任何 Key/token 材料。
- 四个受控管理写接口：停用/启用用户、吊销设备、轮换当前凭证。每次写操作校验会话、CSRF、
  权限、目标组织子树和 `reason`；auth-service 故障稳定映射为 `502 dependency_unavailable`。
- 写响应使用字段白名单，不返回 Gateway Key、设备令牌、token hash、公钥或服务令牌。
- 每个管理写操作获得独立 `operationId`，并持久化操作状态、请求指纹、白名单前后摘要以及
  intent/result 两条管理审计。
- 可选 `Idempotency-Key` 按管理员主体隔离并以 SHA-256 保存，不保存原值。同键同请求复用
  原响应和原 `operationId`；同键异体返回 `409 idempotency_conflict`；执行中重放返回
  `409 operation_in_progress`。
- intent 审计失败时返回 `503 audit_unavailable`，不调用 auth-service；result 审计失败时
  不返回成功，操作停留在 `dependency_invoked`，需要后续运维核对，不能自动重试依赖。

## M2-C4 目标边界（C4-01/C4-02/C4-03a/C4-03b 核心已实现，C4-03c/C4-03d/C4-04 未实现）

当前四个管理写接口只覆盖停用/启用、设备吊销和凭证轮换。它们不包含额度修改或模型授权，
也不能单独构成完整企业治理闭环。C4 必须新增：

```http
PUT   /api/v1/admin/users/{id}/quota
PATCH /api/v1/admin/users/{id}/models
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
C4-03a 只读正式模型目录已实现，但 auth-service 尚未接入；C4-03b 的策略核心和内部接口
已在 auth-service 实现，但 admin-service 尚未自动编排；C4-03c/C4-03d/C4-04 和真实请求
E2E 仍未实现。
完整契约见
[`../../devtools/enterprise-feature-spec.md`](../../devtools/enterprise-feature-spec.md) 第
12.8.1.5 节和
[`../../devtools/enterprise-master-plan.md`](../../devtools/enterprise-master-plan.md) 的
M2-C4 工作包。

## 角色

| 角色 | 当前用途 |
| --- | --- |
| `employee` | 无管理权限 |
| `department_admin` | 指定组织单元及子单元内的只读视图及用户/设备/凭证受控写操作；额度写入仍待 C4-03c/C4-03d/C4-04 |
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
4. 生成互相独立的高熵值：

   ```text
   ADMIN_SESSION_SECRET
   ADMIN_OIDC_CLIENT_SECRET
   AUTH_INTERNAL_ADMIN_TOKEN
   ```

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
或 group 的权限事实来源。当前只有 admin-service 加载目录，auth-service 尚未接入。
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
| `GET` | `/admin/` | 最小管理页面 |
| `GET` | `/api/v1/admin/me` | 当前身份、角色、权限、范围和 CSRF token |
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

稳定错误码包括 `not_signed_in`、`session_expired`、`session_idle`、`session_binding_mismatch`、
`forbidden_role`、`forbidden_scope`、`csrf_invalid`、`mfa_required`、`email_not_verified` 和
`target_not_found`，以及 `dependency_unavailable`、`storage_unavailable`、
`invalid_time_range`、`invalid_json`、`invalid_reason`、`invalid_idempotency_key`、
`idempotency_conflict`、`operation_in_progress`、`audit_unavailable`。

四个写接口的成功响应包含 `requestId`、`operationId`、动作名、目标 ID 和白名单业务摘要。
请求可携带 `Idempotency-Key`（去空白后最长 128 个字符且不得含控制字符）。服务端只持久化
`SHA-256(actorSubjectId + "\0" + key)`，不保存原值。请求指纹覆盖
`action/targetType/targetId/reason/approvalId`：

- 同键同请求且原操作成功：返回原成功响应、原 `operationId` 和原 `requestId`，不再次调用
  auth-service。
- 同键同请求且原操作失败：重放原稳定错误、原状态码和原 `operationId`，不自动重试依赖。
- 同键异体：返回 `409 idempotency_conflict`。
- 原操作仍在执行：返回 `409 operation_in_progress`。
- 未提供幂等键：仍创建 operation 和两条管理审计，但不提供跨请求重放。

C4-03c 实现时必须扩展该指纹，把规范化后的额度或模型业务 payload 和 `expectedVersion`
一起纳入；同键不同额度或模型必须返回 `409 idempotency_conflict`。现有
`src/auth-client.js` 只支持 GET/POST，尚无 JSON `PUT/PATCH` body 和 `If-Match` 透传，
因此不能直接把它当作 C4-03c 已完成。页面只有在 C5 查询可用且真实证据链完整时，才能展示
最终状态；`partial_success`、`pending` 和 `dependency_invoked` 不得显示为“已生效”。

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
& $node --test test\admin-service.test.mjs test\model-catalog.test.mjs
```

2026-11-01 的实际结果：`31 passed, 0 failed`（24 项管理服务集成测试 + 7 项目录专项测试）。
使用 Mock IdP、Mock auth-service 和临时
`usage.jsonl`，覆盖登录、MFA、已验证邮箱、ACR 请求、CSRF、角色撤销、部门子树、兄弟部门
拒绝、用户详情跨范围拒绝、会话过期、IP fail-closed、依赖不可用、凭证元数据、用量归属、
时间和分组参数、损坏/超限用量拒绝、凭据不落盘和损坏存储拒绝加载。M2-C2 覆盖四个管理写
接口、管理会话/CSRF/RBAC、组织范围写校验、必填理由、幂等键格式、坏 JSON、目标不存在、
依赖故障和写响应/存储脱敏。M2-C3 新增覆盖成功/失败重放、同键异体、并发执行中、intent
审计失败时依赖调用为 0、result 审计失败不返回成功，以及 operation 停留在
`dependency_invoked`。C4-03a 目录专项测试覆盖只读加载、严格 JSON/重复 key/未知字段/
尾随内容拒绝、2 MiB 上限、schema 版本、稳定模型 ID、显式 Provider 通配符、group 展开、
digest 不匹配和失败关闭。Auth 服务当前为 `18 passed, 0 failed`。

尚未验证：

- 真实 Entra/Okta/Keycloak 的 Claim、MFA、ACR、回调地址和条件访问。
- Docker Compose 构建和健康检查；当前机器没有 Docker CLI。
- 浏览器、反向代理、真实 Cookie 域和公司 CA 的端到端演练。
- C4-03a 的真实部署验收，以及 auth-service 自动接入正式目录后的用户级模型授权链路。
- C4-02 的 Docker/真实共享卷验收、C4-03c/C4-03d/C4-04 和 M2-C5/D 的调额、模型授权、
  操作/审计查询、管理台写按钮、完整筛选/分页、导出和看板。
- 四个 M2-C2 写接口在真实 IdP、反向代理、真实 auth-service 和真实网关上的端到端演练。

## 当前限制

- 单实例 JSON 存储，不适合多副本；超过 50-100 人或需要 HA 时迁移 PostgreSQL。
- 每个管理请求会更新 `lastSeenAt`，小规模试点可接受，规模化需要共享存储和写合并。
- result 审计失败时 operation 会停在 `dependency_invoked`；当前没有自动补偿或人工核对
  队列，C5 需要提供查询、告警和受控恢复流程。
- 角色/组织目前没有管理 API，尚未接入 SCIM 或 IdP Group 映射。
- 用量读取当前基于单个 `usage.jsonl` 文件；轮转、归档、超大文件和事件存储查询尚未验收。
- 列表筛选、分页、CSV 导出、费用趋势图、管理员操作历史和写按钮属于 M2-C5/M2-D。
- IPv6 允许列表当前只支持精确 `/128`。
- 没有任何对话正文；完整内容审计属于 M4，必须单独授权和审计。
- M2-C2/C3 的管理 API 已接入会话、CSRF、RBAC、组织范围、理由、幂等和 intent/result
  管理审计；C4-01 只完成底层机器协议，C4-02 只完成受控适配器的 Mock/故障测试，C4-03a
  只完成管理服务的正式只读目录；C4-03b 只在 auth-service 完成策略核心，尚未由管理端自动
  编排同步。管理 API、Docker/真实共享卷、C4-03c/C4-03d/C4-04、C5/D 和生产环境验收仍未
  完成，不能把 API 测试通过描述成生产管理闭环完成。
