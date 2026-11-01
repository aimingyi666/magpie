# Magpie 企业版实现状态

状态日期：2026-11-02
定位：这是“代码和测试真实发生了什么”的记录，不是未来方案。产品设计见
[`enterprise-feature-spec.md`](enterprise-feature-spec.md)，实施顺序见
[`enterprise-master-plan.md`](enterprise-master-plan.md) 和
[`enterprise-roadmap.md`](enterprise-roadmap.md)。

2026-11-02 方案基线更新到 v3.6。M2-C1 的 auth-service 内部写接口、M2-C2 的四个管理写
接口和 M2-C3 的幂等/管理审计状态机已实现并通过 Mock 测试。当前工作分支还实现了
M2-C4 的 **C4-01** 网关机器协议，并通过 Go 单测、CLI 回归和隔离真实二进制冒烟测试；
**C4-02** `gateway-control` 受控适配器已实现并通过 15 项 Mock/故障测试；**C4-03a**
正式只读模型目录已实现，admin-service 当前通过 **34 passed, 0 failed**（27 项管理服务
集成测试 + 7 项目录专项测试）。`GET /api/v1/admin/models` 使用正式目录，`ADMIN_MODELS`
只保留兼容显示；auth-service 和 gateway-control 只接收稳定模型 ID，不加载目录。
**C4-03b/C4-03c** 已在 auth-service 实现用户级 `gatewayPolicy`、幂等签发、
issuance journal、自动 apply/独立回读、失败补偿、启动恢复和同步后交付，auth-service
当前 **21 passed, 0 failed**。**C4-03d** 只完成管理页同步状态展示，写按钮、员工门户、
operation/audit 查询和人工对账仍未实现；C4-04 真实 Magpie 行为 E2E，以及 M2-C5、
M2-D 和 M3-M6 仍未实现。本状态只描述仓库中已经存在并有测试证据的能力。

## 1. 一句话结论

当前完成的是一个**可试点的 M0 企业网关基线**、一个**已完成本地真实链路验收的 M1
身份/设备服务**、一个 **M2-A 管理身份底座**、一个 **M2-B 只读治理切片**、
**M2-C2/C3 管理写接口、幂等与管理审计切片**，以及 **M2-C4 的网关策略控制核心链路**。
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
失败补偿、启动恢复和同步后交付。真实 Magpie 请求行为 E2E、操作/审计查询、人工对账和
管理台写按钮仍未实现。M1/M2-A/M2-B/M2-C1/M2-C2/M2-C3/C4-02/C4-03c 尚未完成真实企业
IdP、Docker Compose、浏览器/反向代理、真实 `usage.jsonl` 数据卷和 Windows 计划任务的
完整验收，因此不能标记为“企业生产版已完成”。

### 1.1 当前员工与管理员实际能做什么

| 使用者 | 当前真实可用 | 当前不可用/不能承诺 |
| --- | --- | --- |
| 员工 | 浏览器 OIDC 登录、Mock/本地真实 issuer 加入、设备注册、短期 Key、通过本地 Magpie 调用企业网关、自动刷新脚本、停用后失效 | 不能只靠网页修改本机 Agent；真实企业 IdP、公司反向代理、Windows 计划任务实机、MDM 安装未验收 |
| 管理员 | 独立管理 OIDC + MFA/ACR、会话/CSRF/IP、RBAC、组织范围，用户/部门/设备/凭证/模型/用量只读视图，正式只读模型目录，四个受控管理写 API，以及额度/模型策略写 API；策略写入会经 auth-service 自动 apply/readback，同步完成前不交付 Key，并返回 `known/pending/partial_success/unknown`；写操作已有幂等重放/冲突、`operationId` 和 intent/result 审计 | 管理页尚无写按钮；operation/audit 查询、人工对账、完整员工门户、筛选/导出未实现；真实 Magpie/共享卷/IdP 未验收；不能管理 MCP/资源库 |
| 管理员能看到的员工信息 | 姓名/邮箱/稳定 ID/部门/状态、设备/版本/心跳、凭证元数据、模型、Token/费用/错误/时间 | 不能看对话正文；当前只有 L0 用量元数据；L1/L2/L3 属于 M4 |
| 安全/审计人员 | 只读用量和授权元数据，角色撤销在下一请求生效 | 没有正文查看、导出审批、告警阻断、SIEM、二次授权 |
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
| M2-C4-03b 用户级策略核心 | 已实现，21 项 auth 测试通过 | 旧 M1 `unknown`、quota/models 分步提交、缺项失败关闭、版本冲突、逐凭证回读确认 |
| M2-C4-03c 管理 API 与同步后交付 | 核心已实现，Mock/故障测试通过 | 管理端额度/模型 API、幂等签发、issuance journal、自动 apply/回读、同步后交付、失败补偿和启动恢复；真实环境验收待完成 |
| M2-C4-03d 页面与运营状态 | 部分实现 | 管理页可看策略版本、同步状态、最后同步时间和错误码；无写按钮、完整员工页、operation/audit 查询和人工对账 |
| M2-C4-04 真实 Magpie 行为 E2E | 未实现 | 真实限额、模型拒绝、策略继承、多凭证、部分失败和故障注入 |
| M2-C5 操作/审计查询与对账 | 已冻结契约，未实现 | 无代码、无测试；`dependency_invoked` 仍只能人工查存储 |
| M2-D 看板与运营 | 已冻结契约，未实现 | 无管理写 UI、报表、导出和员工状态页 |
| M3 中央 MCP/资源库 | 未实现 | 只有产品/架构设计 |
| M4 会话内容审计 | 未实现 | 目前只有请求元数据和用量 |
| M5 安全运营 | 未实现 | 无 SIEM 告警、阻断和值班闭环 |
| M6 高可用/规模化 | 未实现 | 当前单实例、JSON 存储 |

### 2.1 C4/C5/D 的实现边界

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

仍未完成或未验收：

- Dockerfile/Compose 静态配置已完成，但 Docker 构建、Compose 启动、健康检查和真实共享卷
  尚未实机验收。
- 服务间当前使用独立 Bearer 令牌，不是 mTLS；mTLS/SPIFFE/工作负载身份仍是生产加固项。
- C4-03d 只完成管理页同步状态展示；没有写按钮、完整员工门户、operation/audit 查询和人工
  对账，C5/M2-D 仍负责这些能力。
- 没有真实 Magpie 限额/模型拒绝行为 E2E、策略继承、多凭证真实故障注入或企业 IdP、反向
  代理、公司 CA 的验收证据，属于 C4-04 和生产验收。
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
  范围写校验和 intent/result 管理审计。这些能力随后由 M2-C2/C3 接入；调额、模型授权、
  操作查询和管理台写按钮仍分别属于 M2-C4/C5 和 M2-D。

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
  `dependency_invoked`，供 C5 的操作查询、失败对账和人工补偿流程使用。
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
- 管理页新增策略版本、凭证同步状态、最后同步时间和稳定错误码展示；这是 C4-03d 的
  部分实现，不包含写按钮、operation/audit 查询、人工对账或员工门户。

## 4. 已通过的测试

### 4.1 Auth 服务和 Mock 集成

```powershell
& 'D:\Environment\node-v26.12.1\node.exe' `
  --test enterprise\auth-service\test\auth-service.test.mjs
```

结果：`21 passed, 0 failed`。覆盖：

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

### 4.2 管理服务 M2-A/M2-B/M2-C2/M2-C3/C4-03c

```powershell
$node = 'D:\Environment\node-v26.12.1\node.exe'
Get-ChildItem enterprise\admin-service\src\*.js | ForEach-Object {
  & $node --check $_.FullName
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
& $node --test enterprise\admin-service\test\admin-service.test.mjs enterprise\admin-service\test\model-catalog.test.mjs
```

结果：`34 passed, 0 failed`（7 项目录专项测试 + 27 项管理服务集成测试）。覆盖：

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

这不等同于 C4 完成：C4-02/C4-03c 只完成了受控适配器、管理编排和 Mock/故障测试；真实
请求限流/拒绝、共享卷、部分成功和策略继承仍需在 C4-04 与生产验收中验证。完整 CLI 包中的无关网络测试
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

## 5. 未验证事项

以下事项不能写成“已完成”：

1. 真实企业 IdP（Entra/Okta/Keycloak 等）的登录、JWKS、回调地址、Claim 映射和 MFA。
2. 管理端真实 IdP 的 `amr`/`acr`、条件访问、`email_verified` 和回调契约。
3. Docker CLI 不在当前 PATH，Compose 配置和镜像构建/健康检查未实际运行。
4. 管理域名、反向代理、真实 Cookie 域、公司 CA 和浏览器 End-to-End 未验证。
5. Windows 计划任务刷新未实机验证；需要验证锁、用户登录状态、网络恢复和失败重试。
6. SCIM/IdP 离职 Webhook 未接入；当前只有管理接口停用。
7. C4-01/C4-02/C4-03a/C4-03b/C4-03c 均已实现并完成本地/Mock/故障测试；C4-02/C4-03c
   的 Docker/Compose 构建、启动、健康检查、真实共享卷文件锁、服务令牌轮换、真实 Magpie
   apply/readback 和公司反向代理未验收。C4-03d 只完成管理页同步状态展示，写按钮、完整
   员工门户、operation/audit 查询和人工对账未实现；C4-04 的真实限额/模型拒绝、策略继承、
   多凭证故障注入仍未完成。已有管理写接口及其 C3 幂等/审计尚未在真实 IdP、反向代理、
   真实 auth-service 和真实网关上做端到端验收。
8. 多实例、共享存储、限流分布式化和高可用未实现。

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
- 内容审计尚未实现，不能宣称已经可以查看员工完整对话。
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
   已通过 21 项 auth 回归和 34 项 admin 测试。下一步在 Docker 可用环境验证镜像、Compose、
   健康检查、真实共享卷和故障恢复，并在隔离真实 Magpie 环境完成 C4-04 行为 E2E、
   多凭证故障和策略继承验证。
8. 按 `feat/m2-c5-operations-audit` 实现 `audit-logs`、`operations/{id}`、失败对账和补偿；
   再按 `feat/m2-d-admin-operations` 补齐管理写 UI、看板、导出和员工本人状态页。
9. 每个阶段完成后更新第 9 节，记录实际分支、commit、命令、结果、未覆盖项和秘密扫描；
   没有原始证据时继续保持“未实现/未验收”。

## 9. 阶段交付记录

每次推进阶段都更新本表。`测试结果`只记录实际运行过的命令和结果，不把设计或代码存在当成
通过。

| 阶段 | 分支/目录 | 本阶段实现 | 测试命令 | 结果 | 未覆盖项 |
| --- | --- | --- | --- | --- | --- |
| M0 企业网关基线 | `feat/enterprise-plan` / `enterprise/` | 企业网关 Compose、员工 Key 开通、客户端加入、验收脚本、Mock 上游 E2E | `enterprise/test/e2e.ps1` | 真实 Magpie 客户端 → 企业网关 → Mock 上游通过；用量按员工 Key 归属 | 正式 TLS、公司 OTLP/SIEM、MDM 分发 |
| M1 身份与设备 | `feat/enterprise-plan` / `enterprise/auth-service/` | OIDC+PKCE、加入码、设备注册/心跳/刷新/吊销、短期 Key、管理停用接口、并发刷新串行化、凭证元数据 | `node --test enterprise/auth-service/test/auth-service.test.mjs` | 当前回归 `21 passed, 0 failed` | 真实企业 IdP、Docker、Windows 计划任务 |
| M1 真实链路 | `feat/enterprise-plan` / `enterprise/test/auth-e2e.ps1` | 真实 issuer Key、Mock OIDC、真实网关、Mock 上游、刷新、停用、重启和脱敏检查 | `enterprise/test/auth-e2e.ps1 -Magpie ... -Node ...` | 全部 PASS | 真实 IdP、Compose 健康检查、计划任务实机 |
| M2-A 管理身份底座 | `feat/enterprise-plan` / `enterprise/admin-service/` | 独立管理 OIDC、MFA/ACR、已验证邮箱、会话/CSRF/IP、RBAC、组织范围、服务间独立令牌、最小页面、Compose `admin` profile | `node --check`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs`；`node --test enterprise/auth-service/test/auth-service.test.mjs` | 当前回归 `34 passed, 0 failed`；auth `21 passed, 0 failed` | 真实 IdP、Docker/浏览器/反向代理；C4-03d 剩余能力、C4-04、C5 和 D 未实现或未验收 |
| M2-B 只读治理 | `feat/enterprise-plan` / `enterprise/auth-service/`、`enterprise/admin-service/` | 用户/部门/设备/凭证/模型/用量只读 API、凭证元数据、用户组织映射、服务端子树过滤、只读 usage 读取和管理页摘要 | `node --check`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs`；`node --test enterprise/auth-service/test/auth-service.test.mjs` | 当前回归 `34 passed, 0 failed`；auth `21 passed, 0 failed` | 真实 `usage.jsonl` 数据卷、真实 IdP、Docker/浏览器/代理、C4-03d 剩余能力、C4-04、C5/D |
| M2-C1 Auth 内部写接口 | `feat/enterprise-plan` / `enterprise/auth-service/` | 内部停用/启用、设备吊销、当前凭证轮换；停用撤销设备/会话/凭证，启用不恢复旧凭据，轮换按设备串行化并清理孤儿 Key | `node --check`；`node --test enterprise/auth-service/test/auth-service.test.mjs` | 当前回归 `21 passed, 0 failed` | admin-service 对外写 API、RBAC/CSRF/幂等/理由/审计、真实 IdP 和真实网关验收 |
| M2-C2 管理写接口 | `feat/enterprise-plan` / `enterprise/admin-service/` | 四个管理写 API；会话/CSRF/RBAC/组织子树/理由校验；目标预检和响应白名单；依赖故障映射 | `node --check`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs` | 当前回归 `34 passed, 0 failed`（C2 新增 3 组测试） | 管理页按钮、真实 IdP/代理/网关验收 |
| M2-C3 幂等与管理审计 | `feat/enterprise-plan` / `enterprise/admin-service/` | `adminOperations`/`adminIdempotency` 集合；键哈希和请求指纹；同键重放/冲突/执行中；intent/result 审计；审计失败阻断；operationId 返回和失败重放 | `node --check`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs` | `34 passed, 0 failed`（含 7 项目录测试；C3 新增 5 组测试） | 操作/审计查询、失败对账、管理页按钮、真实 IdP/代理/网关验收 |
| C4-01 网关机器协议 | `feat/m2-c4-gateway-policy` 工作区 | `describe --json`、原子 `policy apply --json`、schema v1、64 KiB 输入输出上限、`expectedPolicyRevision`、稳定错误码、无秘密输出 | `go vet ./internal/access ./internal/cli`；`go test -count=1 -timeout=90s ./internal/access`；`go test -count=1 -timeout=120s ./internal/cli -run '^TestGatewayKey'`；`go build ./...`；隔离 `XDG_CONFIG_HOME` 真实二进制冒烟 | 全部通过；schema/模型/额度/冲突/回读/脱敏冒烟通过 | 尚未合入 `main`；无管理 API、真实请求行为 E2E 或生产环境证据 |
| C4-02 受控网关适配器 | `feat/m2-c4-gateway-control` 工作区 / `enterprise/gateway-control/` | 固定路由、独立 Bearer 服务令牌、固定 argv/`shell: false`、Key ID 白名单、10 秒超时、64 KiB 上限、独立回读、`pending` 保守状态、Dockerfile 和 Compose profile | `node --check enterprise/gateway-control/src/service.js`；`node --check enterprise/gateway-control/test/gateway-control.test.mjs`；`node --test enterprise/gateway-control/test/gateway-control.test.mjs` | `15 passed, 0 failed`；Mock/故障测试通过 | Docker/Compose、真实共享卷、真实 Magpie、mTLS 和生产环境未验收 |
| C4-03a 正式只读模型目录 | `feat/m2-c4-gateway-policy` 工作区 / `enterprise/admin-service/` | 只读 `ADMIN_MODEL_CATALOG_PATH`、严格 JSON、schema v1、稳定模型 ID、显式 Provider 通配符、group 展开、2 MiB 上限、SHA-256 digest、安全状态摘要、启动审计和 `GET /api/v1/admin/models` 正式目录 | `Get-ChildItem enterprise/admin-service/src/*.js \| ForEach-Object { node --check $_.FullName }`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs` | `34 passed, 0 failed`（7 项目录专项 + 27 项管理集成） | auth-service 不加载目录，只接收稳定 ID；真实 Docker/共享卷、真实 IdP、浏览器、反向代理和生产环境未验收 |
| C4-03b 用户级策略核心 | `feat/m2-c4-gateway-policy` 工作区 / `enterprise/auth-service/` | 版本化 `gatewayPolicy`、0-5 额度窗口、稳定模型、M1 `unknown` 迁移、quota/models 分步设置、缺项失败关闭、`expectedVersion`/`If-Match`、join/refresh/rotate 前置门禁和凭证回读确认 | `node --check enterprise/auth-service/src/service.js`；`node --check enterprise/auth-service/test/auth-service.test.mjs`；`node --test enterprise/auth-service/test/auth-service.test.mjs` | `21 passed, 0 failed` | 真实 E2E、页面剩余能力和生产验收未完成 |
| C4-03c 管理 API 与同步后交付 | `feat/m2-c4-gateway-policy` 工作区 / `enterprise/admin-service/`、`enterprise/auth-service/` | 额度/模型 API、模型选择器展开、payload 幂等、issuance journal、`enterpriseIssuanceId` 幂等签发、apply/readback、同步后交付、失败补偿、启动恢复和 `partial_success` | `node --check`；`node --test enterprise/admin-service/test/admin-service.test.mjs enterprise/admin-service/test/model-catalog.test.mjs`；`node --test enterprise/auth-service/test/auth-service.test.mjs` | admin `34 passed, 0 failed`；auth `21 passed, 0 failed` | Docker/共享卷、真实 Magpie、真实 IdP、mTLS、人工对账和生产验收未完成 |
| C4-03d/C4-04 + C5/D | 计划 `feat/m2-c4-gateway-policy-e2e` / `feat/m2-c5-operations-audit` / `feat/m2-d-admin-operations` | C4-03d 只完成管理页同步状态展示；写按钮、员工门户、operation/audit 查询、人工对账、策略继承和真实 Magpie 行为 E2E 未实现 | 未执行 | 部分实现；剩余项未测试 | C4-03d 剩余项、C4-04 + C5/D 全部 |
| M2-C5 操作/审计查询与对账 | 计划 `feat/m2-c5-operations-audit` | 仅有完整设计；尚无查询、对账和子 operation 代码 | 未执行 | 未测试、不可用 | 所有 C5 项 |
| M2-D 管理运营 | 计划 `feat/m2-d-admin-operations` | 仅有完整设计；尚无写 UI、看板、导出和员工状态页 | 未执行 | 未测试、不可用 | 所有 M2-D 项 |
