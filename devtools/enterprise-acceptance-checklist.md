# Magpie 企业版验收清单

状态：生产验收基线 v1.8（与完整方案 v3.13 对应）

日期：2026-11-02

本文只记录“什么条件下可以从小范围试点进入生产”，不把设计、Mock 或单次演示当作验收证据。
真实现状见 [`enterprise-implementation-status.md`](enterprise-implementation-status.md)，完整方案见
[`enterprise-feature-spec.md`](enterprise-feature-spec.md)；需求 ID、交付包和端到端场景以该文件
第 25 节为准，本清单负责逐项留证和签字。

## 1. 判定规则

| 级别 | 判定 | 允许范围 |
| --- | --- | --- |
| D0 可演示 | 隔离环境、Mock IdP、Mock 上游 | 研发/产品演示 |
| D1 技术试点 | M0/M1/M2-A/M2-B 在真实内网通过，至少一名员工和一名管理员完成闭环 | 受控部门、5-50 人 |
| D2 生产候选 | M2-C 写操作与管理审计、M2-E1 审批/step-up/通知后端、真实 IdP/OA/代理/浏览器/Windows、备份恢复、权限演练全部通过 | 单部门或小规模正式试用 |
| D3 生产 | D2 + M2-E2 内置审批/break-glass/通知运营页、容量、HA/DR、安全事件、供应链、发布回滚和值班责任全部有证据 | 全员生产 |

每个验收项必须有：执行日期、环境、执行人、命令/操作步骤、原始证据路径、结果、失败项和
复核人。没有这些字段的“已通过”不计数。

## 2. 代码与上游兼容

| 编号 | 验收项 | 通过标准 | 当前状态 |
| --- | --- | --- | --- |
| G-01 | `main` 只同步上游和已验收提交 | 分支保护开启；功能从最新 `main` 开分支 | 文档已定义，GitHub 配置需人工确认 |
| G-02 | 上游自动同步 | GitHub Actions 每小时执行；冲突有告警且不覆盖企业提交 | 需在 GitHub 网页确认 |
| G-03 | 企业代码隔离 | 企业能力在 `enterprise/`、插件或最小 hook；默认不影响个人用户 | M0-M2-C3 已满足 |
| G-04 | 回归门禁 | 语法、Go/Node 单测、M0 E2E、M1/M2 测试和构建全部通过 | 本地部分通过；CI 需配置 |
| G-05 | 可回滚发布 | 从已验收 tag/release 构建，上一版本可恢复数据和配置 | 尚未做真实发布演练 |

## 3. 员工加入与日常使用

| 编号 | 验收项 | 通过标准 | 当前状态 |
| --- | --- | --- | --- |
| E-01 | 安装与身份 | MDM 安装签名客户端；员工用企业 OIDC + MFA 登录 | 本地 Mock/真实 issuer 已通；真实 IdP/MDM 未验收 |
| E-02 | 设备注册 | 生成设备密钥、注册设备、绑定用户、保存凭据 ACL | 本地已通过 |
| E-03 | 短期凭证 | 签发 1-8 小时 Gateway Key；员工机无厂商 Key | 本地真实 issuer E2E 已通过 |
| E-04 | Agent 一键配置 | 本地 Magpie 写入企业 Provider 并配置至少 Claude Code/Codex/OpenCode 中一种 | 脚本已实现，真实客户端待验收 |
| E-05 | 首次可用时间 | 新员工从登录到成功调用 ≤5 分钟 | 需真实计时记录 |
| E-06 | 自动刷新 | Windows 当前用户计划任务自动刷新；锁冲突、断网、重启可恢复 | 未实机验收 |
| E-07 | 员工边界 | 网页只做登录/展示/加入码；不能直接写本机 Agent 文件 | 设计和脚本边界正确 |
| E-08 | 日常调用 | Agent -> 本地 Magpie -> 企业网关 -> 模型成功；模型白名单生效 | M0 隔离 E2E 已通过 |
| E-09 | 离职/挂失 | 停用用户或吊销设备后心跳、刷新、当前 Key 全部失效 | Auth 内部接口 Mock 和本地 E2E 已通过；四个管理写 API 的 Mock 已通过；管理页停用/吊销/轮换页面和真实环境未验收 |

## 4. 管理身份与权限

| 编号 | 验收项 | 通过标准 | 当前状态 |
| --- | --- | --- | --- |
| A-01 | 管理 OIDC | 独立 Client、PKCE、MFA/ACR、`email_verified`、回调域名正确 | Mock 已通；真实 IdP 未验收 |
| A-02 | 管理会话 | HttpOnly/Secure Cookie、绝对/空闲超时、IP/UA 绑定、CSRF | Mock 已通；代理/浏览器未验收 |
| A-03 | RBAC | 员工、部门、企业、安全、审计、运维、超级管理员权限符合矩阵 | 服务端角色已实现；真实账号演练未做 |
| A-04 | 组织范围 | 部门管理员只能读/写本子树；跨部门返回 `403 forbidden_scope` | 读写范围 Mock 已通过；跨部门写入不会调用依赖；真实环境未验收 |
| A-05 | 角色变更即时性 | 撤销角色后下一次请求立即失去权限 | Mock 已通过 |
| A-06 | 管理审计 | 每个敏感操作有 intent/result、理由、目标、前后摘要和结果 | M2-C3 Mock 已覆盖四个写接口的 intent/result、operationId 和脱敏；真实审计存储待验收 |
| A-07 | 审计失败阻断 | 审计不可写时拒绝写操作，依赖服务调用次数为 0 | M2-C3 Mock 已覆盖 intent 失败依赖调用为 0、result 失败不返回成功；真实存储待验收 |
| A-08 | 职责分离 | 正文查看、审计导出、角色修改和留存修改不能由一人静默完成 | 设计已定义，待实现 |

## 5. M2-C 写操作（C1/C2/C3 已验证，C4-01/C4-02 已实现本地/Mock 测试，C4-03a 已实现待部署验收，C4-03b/C4-03c 核心已实现，C4-03d 部分实现，C4-04 完整策略流 E2E 已通过，C5 后端已实现并通过 Mock/故障测试）

| 编号 | 验收项 | 通过标准 | 当前状态 |
| --- | --- | --- | --- |
| W-01 | 停用/启用员工 | 权限、范围、幂等、理由、CSRF、审计和依赖失败正确 | Auth 内部接口、管理 API、权限/CSRF/范围/理由、幂等和 intent/result 审计 Mock 已通过；真实环境待验收 |
| W-02 | 吊销设备 | 当前 Key 失效、刷新拒绝、设备和凭证状态正确 | Auth 内部接口、管理 API、权限/CSRF/范围/理由、幂等和 intent/result 审计 Mock 已通过；真实环境待验收 |
| W-03 | 轮换凭证 | 旧 Key 失效、新 Key 可用、失败无孤儿 Key | Auth 内部接口、管理 API、权限/CSRF/范围/理由、幂等和 intent/result 审计 Mock 已通过；真实环境待验收 |
| W-04a | 正式模型目录（C4-03a） | 只读 `ADMIN_MODEL_CATALOG_PATH`；`schemaVersion=1`、稳定模型 ID、显式 Provider 通配符、group 只引用已知模型、2 MiB 上限、目录摘要和稳定错误码 | 已实现；7 项专项和 54 项管理集成测试通过；真实 Docker/只读挂载/digest 重启未验收；auth-service 不加载目录，只接收稳定模型 ID |
| W-04b | 首次策略初始化与 `unknown` 迁移（C4-03b） | 旧 M1 只迁移为 `quotaStatus/modelStatus=unknown`；quota/models 可任意顺序首次提交但不得伪造缺项；缺项返回 `policy_setup_required`；两项完整并逐凭证回读后才 `known` | auth-service 核心已实现，`25/25` 测试通过；管理端已编排额度/模型写入；C4-04 已验证首次设置、真实请求限额/模型拒绝和 refresh/rotate 继承；真实 Compose/共享卷和真实 IdP 尚未验收 |
| W-04c | 管理 API 与同步后交付（C4-03c） | `PUT quota`/`PATCH models` 具备会话、CSRF、RBAC、范围、理由、版本、payload 指纹和 intent/result 审计；issuance journal -> 签发 -> apply -> 独立回读 -> 原子持久化 -> 才交付；同步前客户端拿不到 Key；任一步失败撤销且启动恢复处理可确认的孤儿 Key | 核心已实现并通过 Mock/故障测试；C4-04 已用隔离真实 Magpie 覆盖 apply/readback、多凭证部分失败和恢复；真实共享卷、真实 IdP 和生产验收未完成 |
| W-04d | 页面与运营状态（C4-03d） | `unknown/pending/partial_success/dependency_invoked` 显示真实状态、计数、失败凭证和恢复入口；只有 `succeeded + known + synced + 回读一致` 显示“已生效”；禁止自动重试不确定操作 | 部分实现；管理页已有额度/模型写表单、完整证据链和失败证据，员工页已有本人额度/模型/凭证/设备只读门户；页面 E2E、恢复入口和查询/对账 UI 未完成 |
| W-04e | 机器可读控制契约与受控适配器 | `gateway-key describe/policy apply --json` 只接受 schema v1，原子写入、稳定错误码、64 KiB 限制和无秘密输出；`gateway-control` 只允许白名单路由/argv、独立服务令牌、10 秒超时、64 KiB 上限、写入后独立回读；不确定结果为 `pending` | C4-01 已通过 Go 单测、CLI 回归和隔离真实二进制冒烟；C4-02 已通过 `15/15` Mock/故障测试；C4-04 完整 E2E 已通过真实 `admin-service -> auth-service -> gateway-control -> Magpie` apply/readback、多凭证、故障恢复、模型拒绝、限额和 rotate。Docker/Compose、真实共享卷和真实企业 IdP 仍未验收 |
| W-05 | 模型授权 | 只接受稳定模型 ID；空数组、显示名、裸 `*`、未知模型和隐式扩大范围被拒绝；旧 Key 实际被拒 | 管理 API、目录展开、策略同步和 Mock 拒绝路径已实现；C4-04 完整 E2E 已证明白名单外模型返回 `403` 且请求未到上游，rotate 后旧 Key 返回 `401`，新 Key 继承策略并可用 |
| W-06 | 幂等冲突 | 同请求只执行一次；同键不同请求体返回 `409 idempotency_conflict`；执行中返回 `409 operation_in_progress` | M2-C3 Mock 已覆盖成功/失败重放、同键异体和并发执行中；真实环境待验收 |
| W-07 | 依赖故障 | auth/gateway 不可用返回 `502 dependency_unavailable`，不伪造成功 | Auth C1 内部失败回滚和管理面写依赖故障 Mock 已通过；真实网关未验收 |
| W-08 | 操作查询 | `GET /api/v1/admin/operations/{operationId}` 返回真实状态、依赖时间、失败项和对账状态 | 已实现并通过权限、组织范围、目标不存在和脱敏 Mock/故障测试；真实审计存储和生产查询入口待验收 |
| W-09 | 审计查询 | `GET /api/v1/admin/audit-logs` 支持授权范围内的过滤/游标分页，只返回脱敏元数据 | 已实现并通过过滤、稳定分页、签名 cursor、会话绑定、脱敏和坏 cursor 拒绝测试；真实审计存储和生产代理待验收 |
| W-10 | 人工对账 | 重试、回滚、确认已生效/未生效生成子 operation，原审计不可修改 | 已实现四种动作并通过审批/CSRF/证据/幂等、旧快照、依赖和审计故障、父子关系及原审计不可改写测试；真实运维演练待验收 |
| W-11 | 部分成功 | 多凭证中部分失败返回 `partial_success`，列出 credentialId/deviceId/errorCode，策略保持 `pending` | C4-03c 核心 Mock/故障测试与 C4-04 真实双设备 E2E 均覆盖；禁用单个 Key 后返回精确 `partial_success`，恢复后两凭证重新 `synced` |
| W-12 | 幂等指纹 | 额度/模型 payload 纳入指纹；同键不同额度或模型不能重放旧结果 | 管理 API 测试已覆盖；真实存储和多实例行为待验收 |
| W-13 | 策略继承 | 新签发、refresh、rotate 继承当前策略；`pending` 时失败关闭且无新偏差凭证 | auth-service Mock 已覆盖；C4-04 真实管理链路已证明首次双设备签发、refresh 轮换、rotate、旧 Key `401`、新 Key `200` 和策略继承 |
| W-14 | 管理写 UI | 只有完整证据链显示“已生效”；`partial_success`/`pending`/`unknown` 显示真实状态 | C4-03d 部分实现：额度/模型策略写表单和员工只读状态门户已通过 HTML/API/静态脚本测试；停用/吊销/轮换页面、页面 E2E、恢复入口和查询/对账 UI 未实现 |
| W-15 | 报表与导出 | 人/部门/Agent/模型筛选、费用趋势、授权导出和操作历史符合权限与审计 | M2-D 未实现 |

### 5.1 C4/C5/D 验收证据字段

W-04 至 W-15 的每条记录至少保留：

```text
执行日期、环境、执行人、分支、commit
请求方法、路径、角色、组织范围、expectedVersion、Idempotency-Key 摘要
HTTP 状态、稳定 errorCode、operationId、requestId
beforeSummary、afterSummary
受影响 credentialId/deviceId 列表（不得含 Key/token hash）
真实 Magpie 回读结果和一次实际允许/拒绝请求
schemaVersion、policyRevision、describe 回读 JSON 的安全摘要
临时 XDG_CONFIG_HOME、端口、进程和清理结果
审计 intent/result 原文路径
响应、存储、日志、审计的秘密扫描结果
失败注入、对账动作、子 operationId 和最终状态
gateway-control requestId、固定 argv、服务令牌隔离、超时和 64 KiB 限制证据
写入后独立 describe 回读摘要；不确定结果必须为 pending，不得标为 applied
Docker/Compose 构建、启动、健康检查和真实共享卷验证状态
未验证项与复核人
```

C4-01 已完成本地单元、CLI 回归和隔离真实二进制冒烟；C4-02 已完成 Node 语法检查和
15 项 Mock/故障测试。C4-03a 已完成 7 项目录专项和 60 项管理服务集成测试，管理服务合计
67/67 通过；真实 Compose、只读挂载和 digest 重启仍未验收。C4-03b/C4-03c/C5 核心已通过
25 项 auth-service 测试；C4-03d 已部分实现管理页额度/模型写表单和员工只读状态门户；
C4-04 完整管理到真实 Magpie 策略流 E2E 已通过，包括多凭证、refresh/rotate 继承和故障恢复。
APR-01a 已实现审批后端、绑定校验、职责分离、一次性消费和系统审计；APR-01b 已实现
HMAC/Mock 外部审批回调适配器；APR-01c 已实现独立 OIDC step-up、PKCE、`prompt=login`、
`max_age`、`auth_time`、ACR/MFA、会话/IP/User-Agent/角色范围绑定和 H/C 门禁，并通过
Mock IdP 集成测试。NOTIFY-01a 已实现 outbox 原子提交、租约恢复、重试、死信、deliveries
查询和受审计人工重放，并通过 Mock/故障测试；NOTIFY-01b/c/d 的邮件/IM/Webhook/SIEM/
工单、渠道规则和运营页未实现。页面 E2E、恢复入口、真实共享卷、真实企业 IdP/MFA、
反向代理、C5 生产验收、真实 OA 连接器、审批 UI、审批箱、break-glass、真实通知渠道以及
D 仍未完成/验收。
后续应至少运行：

W-04a-d 还必须逐项保留以下证据：

- 模型目录：坏文件、坏 JSON、重复 JSON key、未知字段、尾随内容、重复稳定 ID/group、
  空目录、未知 group 引用和超过 2 MiB 全部启动失败；digest 固定和格式校验正确；
  API/日志/审计不含内部绝对路径；真实 Compose 只读挂载和修改后重启生效通过。
- 首次初始化：旧 M1 迁移后只能得到 `unknown`；分别先提交 quota 和先提交 models，
  缺项时 join/refresh/rotate 的依赖调用均为 0，错误为 `policy_setup_required`；
  两项完整且逐凭证回读一致后才进入 `known`。
- 同步后交付：策略 apply、独立回读、持久化任一步失败时客户端拿不到新 Key；在每个阶段
  注入进程终止并重启，能按 issuanceId 证明提交或撤销，最终无孤儿 Key。
- 页面状态：`unknown` 不显示 0/无限/默认值；`pending` 和 `partial_success` 显示失败凭证
  且不显示“已生效”；`dependency_invoked` 明确“网关已调用但结果未确认”，禁止自动重试。

```powershell
go vet ./internal/access ./internal/cli
go test -count=1 -timeout=90s ./internal/access
go test -count=1 -timeout=120s ./internal/cli -run '^TestGatewayKey'
go build ./...
node --check enterprise/gateway-control/src/service.js
node --test enterprise/gateway-control/test/gateway-control.test.mjs
node --test enterprise/admin-service/test/admin-service.test.mjs
node --test enterprise/auth-service/test/auth-service.test.mjs
.\enterprise\test\c4-gateway-policy-e2e.ps1 -Magpie <magpie.exe> -Node <node.exe>
.\enterprise\test\c4-enterprise-policy-e2e.ps1 -Magpie <magpie.exe> -Node <node.exe>
```

`c4-gateway-policy-e2e.ps1` 已由提交 `9bb0f94dc` 加入并实际执行，全部 `PASS`。它使用随机
端口、临时 portable Magpie、隔离 `XDG_CONFIG_HOME` 和独立 Mock 上游，证明模型白名单
`403`、Token 限额 `429`、冲突不写、rotate 保持策略、旧 Key `401`、新 Key 可用，以及
`describe/apply`、日志和 `usage.jsonl` 的秘密扫描通过。`c4-enterprise-policy-e2e.ps1`
进一步在真实管理链路中验证首次 join `409 policy_setup_required`、管理 OIDC/CSRF、
quota/models 分步设置、双设备独立 Key、单 Key `partial_success`、refresh/rotate 策略继承、
`gateway-control` 故障后的 `unknown/pending_sync`、Journal/孤儿 Key 撤销、恢复同步、
usage 归属、health 和 22 个非凭证文本文件秘密扫描。W-04e 的 C4-01 证据仍覆盖 schema
v1、64 KiB 输入输出上限、稳定错误码、无秘密输出、`expectedPolicyRevision` 冲突不写文件、
文件锁内原子替换和独立回读；C4-02 证据覆盖固定路由/argv、服务令牌隔离、10 秒超时、
64 KiB 上限和独立回读，但仍属于 Mock/故障测试。W-04e/W-05/W-11/W-13 可记录该完整真实
链路证据；Docker/共享卷、真实企业 IdP、反向代理、浏览器自动化、C5 生产验收、D 和生产
环境仍未验收。C5 查询/对账和 D 的脚本、页面测试同样必须以实际文件与原始输出为准，不能
只在清单中勾选。

完整 `go test ./internal/cli` 还包含会访问网络的上游测试，当前曾因 `TestLibrarySkillRmGone`
超时；因此 C4-01 的 CLI 证据只采用 `-run '^TestGatewayKey'` 的定向回归，不能把定向回归写成
“整个 CLI 包全绿”。

## 6. 只读治理与报表

| 编号 | 验收项 | 通过标准 | 当前状态 |
| --- | --- | --- | --- |
| R-01 | 用户/部门/设备/凭证 | 管理员按范围看到元数据；不返回 Key/hash/token | 管理服务 67/67 已覆盖 |
| R-02 | 用量归属 | `callerKeyId -> credential -> user -> 组织` 正确 | Mock 已覆盖；真实 usage 卷未验收 |
| R-03 | 时间序列 | `groupBy=user/department/model/agent`，`bucket=hour/day` | Mock 已覆盖 |
| R-04 | 数据损坏 | 缺失、尾半行、坏 JSON、超行/超字段/超记录返回稳定存储错误 | Mock 已覆盖 |
| R-05 | 真实数据卷 | 轮转、归档、刷新、只读挂载和管理容器不可写 | 未验收 |
| R-06 | 报表导出 | CSV/Excel 受单独权限和审计；大报表异步一次性下载 | M2-D 未实现 |

## 7. 审批、二次认证与通知投递

本节对应 `APR-01` 和 `NOTIFY-01`。APR-01a 的服务端审批、风险分级、绑定摘要、职责分离、
一次性消费和系统审计已实现；APR-01b 的 HMAC/Mock 外部审批回调适配器已实现；APR-01c
的独立 OIDC step-up 已实现并通过 Mock IdP 集成测试。NOTIFY-01a 的 transactional outbox、
租约、幂等、退避、死信、重启恢复、deliveries 查询和受审计人工重放已实现并通过 Mock/故障
测试；NOTIFY-01b/c/d 的邮件/IM/Webhook/SIEM/工单、规则和运营页尚未实现。真实 OA/IdP/
MFA/反向代理、内置审批箱、break-glass 和真实通知渠道尚未验收。Mock、页面截图或存在
`approvalId` 字段本身都不算生产验收通过；审批生产验收
至少使用真实管理 IdP 和真实 OA 回调，通知至少使用真实邮件/IM 测试域、
受控 Webhook、SIEM 测试索引和工单测试项目。每条记录保留脱敏后的 `approvalId`、
`operationId`、`eventId`、时间、角色、状态迁移、依赖调用次数、原始响应路径、投递尝试、
错误码、重放结果和复核人，不得保存或展示 Key、token、Cookie、Prompt/回复正文和完整工具参数。

### 7.1 审批与二次认证

| 编号 | 验收项 | 通过标准 | 当前状态 |
| --- | --- | --- | --- |
| AP-01 | 风险分级与审批绑定 | 服务端按动作、目标、批量大小、数据分级和组织范围计算 L/M/H/C；审批绑定组织、动作、目标、资源范围、风险、规范化 payload SHA-256、策略版本和有效期 | APR-01a Mock 范围已实现：L/M/H/C 映射、24 小时有效期、组织/动作/目标/理由/payload/策略版本绑定；真实 IdP/OA 验收待完成 |
| AP-02 | 伪造与缺失审批 | 缺失、未知、伪造、跨环境或不属于当前组织的 `approvalId` 一律 `403 approval_invalid`，高风险业务依赖调用为 0 | APR-01a Mock 范围已实现：缺失、未知、跨环境和绑定不匹配失败关闭；真实 IdP/OA 验收待完成 |
| AP-03 | 过期与撤销 | 审批过期、审批人撤回、管理员撤销或角色/组织范围变化后立即失效；每次失败有稳定错误码和审计 | APR-01a Mock 范围已实现过期、撤销和消费失败关闭；角色/组织范围变化后的真实 IdP 联动待验收 |
| AP-04 | payload 与目标绑定 | 审批后修改动作、目标 ID、批量成员、额度、模型、资源版本或组织范围，旧审批全部失效 | APR-01a Mock 范围已实现动作、目标、组织、理由、payload 和策略版本变更失效；批量成员和真实资源版本待后续工作包 |
| AP-05 | 职责分离与自审批 | 申请人不能审批自己的请求；需要 N 人/串并行步骤时，少一步、重复一人或不合格审批人均失败关闭 | APR-01a Mock 范围已实现自审批拒绝；N 人/串并行步骤、转交和双人复核未实现 |
| AP-06 | 外部审批回调 | 飞书/OA/ServiceNow/Jira 回调验签、issuer、audience、时间窗、nonce 和重放缓存均有效；重放、错误签名和错误租户不改变审批状态 | APR-01b HMAC/Mock 适配器已实现并通过原始 body 验签、300 秒时间窗、nonce 防重放、issuer/audience、eventId 幂等、职责分离和系统审计测试；真实飞书/OA/ServiceNow/Jira 连接器与生产回调演练未实现/验收 |
| AP-07 | step-up 二次认证 | 独立管理 OIDC Client、PKCE、MFA/ACR 和 `max_age` 生效；未完成 MFA、ACR 不足、authTime 过期、会话/IP/角色绑定变化时高风险动作失败关闭 | 代码和 Mock IdP 集成测试已完成：独立 Client/PKCE、`prompt=login`、`max_age`、essential `auth_time`、ACR/MFA、IdP `sub`/email，以及会话/IP/User-Agent/角色权限/组织范围绑定；未配置时 `503 step_up_unavailable` 失败关闭。真实企业 IdP、MFA/条件访问、反向代理和浏览器流程未验收 |
| AP-08 | 一次性消费与并发 | 同一审批被重复请求、并发执行、进程重启后重试时只产生一个业务结果；`approval_consumptions` 唯一约束和审计证据一致 | APR-01a Mock 范围已实现原子预留、一次性消费、并发返回 `409 approval_consumed` 和启动恢复失败关闭；真实多实例/存储验收待完成 |
| AP-09 | break-glass | 仅授权角色可发起，15 分钟自动过期，不能静默使用；5 分钟内产生高风险告警/工单，24 小时内完成事后复核并保全证据 | 未实现 |
| AP-10 | operation 与审计串联 | 审批、intent/result、operation、通知和外部工单可按 `operationId` 串联；拒绝、过期、撤销、消费和补偿均可追溯且不含秘密 | APR-01a Mock 范围已实现审批、operation 和系统审计串联；通知、外部工单和真实审计存储待验收 |
| AP-11 | 内置审批运营 | 审批箱支持串并行步骤、转交、撤回、过期和双人复核；非法状态迁移被拒绝，所有操作有审计 | 未实现 |
| AP-12 | 依赖失败语义 | OA、IdP、审批存储、审计或 operation 存储不可用时失败关闭，返回稳定错误且不执行业务动作；不得降级为“默认批准” | APR-01a Mock 范围已实现审批/审计存储失败关闭和稳定错误码；真实 OA/IdP 依赖失败待验收 |

### 7.2 通知、Webhook、SIEM 与工单

| 编号 | 验收项 | 通过标准 | 当前状态 |
| --- | --- | --- | --- |
| NT-01 | outbox 原子提交 | 业务状态、审计和 outbox 事件在同一事务或受控文件锁提交；任一提交失败时不出现“业务成功但事件永久丢失” | 01a 核心已实现并有集成测试；生产存储未验收 |
| NT-02 | 请求解耦 | 业务响应不等待 SMTP、IM、Webhook、SIEM 或工单；渠道超时不改变已提交业务结果 | 01a 设计满足；无真实渠道可验收 |
| NT-03 | 重启恢复 | 在 pending/leased/delivering/retry_wait 各状态强制重启 dispatcher，事件恢复且不丢失；租约超时可回收 | 01a 核心已实现并有重启式存储测试；生产部署未验收 |
| NT-04 | 重试与幂等 | 超时、5xx、限流和网络错误按指数退避重试；同一 `eventId` 重复投递可被接收端去重，不产生重复工单或重复告警 | 01a 重试/幂等核心已实现；无真实接收端验收 |
| NT-05 | 死信与人工重放 | 永久失败进入 dead_letter 并可查询；有权限管理员在理由和审计下重放，重放生成新 attempt，不修改原始证据 | 01a 已实现，无运营 UI 和真实渠道验收 |
| NT-06 | 邮件与企业 IM | SMTP/Graph/邮件网关和飞书/Teams/Slack 机器人可配置、可测试；收件人域、附件、超时和消息大小限制生效，Secret 不落页面或日志 | 未实现 |
| NT-07 | 通用 Webhook | 仅 HTTPS + 允许列表；HMAC 时间戳/nonce 签名可由接收端验证；超时、响应体上限和重试符合契约 | 未实现 |
| NT-08 | Webhook 防 SSRF | 拒绝私网、回环、链路本地、云元数据和不允许的端口；重定向逐跳重新校验；DNS rebinding 和 TOCTOU 测试不能访问内网 | 未实现 |
| NT-09 | SIEM 投递 | OTel/Syslog/HTTP Collector 使用固定 schema；严重安全事件 5 分钟内进入测试索引，字段、严重级别和 `eventId` 可核对 | 未实现 |
| NT-10 | 工单联动 | ServiceNow/Jira/飞书工单可创建并保存外部工单 ID；创建失败重试、死信和人工补单，不伪造“已建单” | 未实现 |
| NT-11 | 抑制、聚合与证据 | 规则可聚合并抑制重复外部打扰，但原始安全事件不丢弃；抑制范围、原因、到期和恢复均可见审计 | 未实现 |
| NT-12 | 脱敏与运营查询 | 响应、存储、日志、审计、outbox、Webhook 和 SIEM 全链路扫描不含 Gateway Key、token hash、Cookie、OIDC/服务 token、Prompt/回复正文和完整工具参数；失败、重试、抑制和死信可授权查询 | 01a 的 deliveries 查询、存储脱敏和死信重放已覆盖；Webhook/SIEM、抑制和完整运营页未实现 |

每条审批/通知验收还必须保留以下串联证据：

```text
approvalId / operationId / eventId（脱敏摘要）
风险等级、申请人、审批人、组织范围、动作、目标、payloadHash
状态迁移、step-up ACR/authTime、一次性消费结果
业务依赖调用次数、before/after 摘要、最终业务状态
outbox 状态、attempt、渠道、HTTP/协议结果、死信和人工重放
外部审批/工单 ID、Webhook 签名验证结果、SIEM 查询时间窗
响应、存储、日志、审计、outbox、Webhook、SIEM 秘密扫描结果
未验证项、执行人、复核人和原始证据路径
```

## 8. 中央 MCP 与资源库

| 编号 | 验收项 | 通过标准 | 当前状态 |
| --- | --- | --- | --- |
| M-01 | MCP 目录 | 管理员登记远程/本地 MCP、工具、风险和适用范围 | 未实现 |
| M-02 | 工具权限 | 未授权 MCP/工具不可见、不可调用；工具级 allow/deny 生效 | 未实现 |
| M-03 | 上游凭据隔离 | MCP 凭据只在网关/Secret Manager，不进入员工机 | 未实现 |
| M-04 | 资源发布 | 不可变版本、哈希、签名、审批和灰度 | 未实现 |
| M-05 | 客户端同步 | 5 分钟内可见；校验签名；上报期望/实际版本 | 未实现 |
| M-06 | 强制与回滚 | 强制资源不可关闭；失败自动回退上一版本 | 未实现 |
| M-07 | 漂移与健康 | 管理员看到设备安装版本、同步错误和漂移 | 未实现 |

## 9. 内容审计

| 编号 | 验收项 | 通过标准 | 当前状态 |
| --- | --- | --- | --- |
| C-01 | 默认 L0 | 不采集 Prompt/回复/附件正文；只记元数据 | 当前只做到这一层 |
| C-02 | L1 摘要 | 工具名、参数类别和结果状态可检索 | 未实现 |
| C-03 | L2 脱敏正文 | 显式授权、二次确认、目的、水印和访问审计 | 未实现 |
| C-04 | L3 原始正文 | 默认关闭；法定调查双人审批、短保留 | 未实现 |
| C-05 | 流式完整性 | 流式回复拼接完整，断流/重试可恢复 | 未实现 |
| C-06 | 留存与删除 | 分级留存、法律保留、删除证明可验证 | 未实现 |
| C-07 | 访问控制 | 审计员默认只看元数据；正文和导出分别授权 | 未实现 |

## 10. 安全运营与可观测性

| 编号 | 验收项 | 通过标准 | 当前状态 |
| --- | --- | --- | --- |
| S-01 | 规则检测 | 异常用量、异地/IP、越权、敏感数据、禁用模型可告警 | 未实现 |
| S-02 | 自动响应 | 支持限流、阻断、吊销、设备锁定和工单 | 未实现 |
| S-03 | 告警闭环 | 严重事件 5 分钟内可见，有负责人和处置记录 | 未实现 |
| S-04 | 指标 | 登录/签发/请求/撤销/同步/审计延迟和错误率可见 | 未实现 |
| S-05 | SIEM/OTel | 元数据可送 OTel/SIEM，且不泄露正文和秘密 | 未实现 |

## 11. 部署、备份与高可用

| 编号 | 验收项 | 通过标准 | 当前状态 |
| --- | --- | --- | --- |
| O-01 | Compose | 干净环境 `--profile admin` 和 `--profile gateway-control` 分别构建、启动、健康检查、重启恢复；验证 gateway-control 不发布宿主机端口且只能使用内部网络 | 当前机器无 Docker CLI；C4-02 Dockerfile/Compose 仅静态编写，未构建、启动或健康检查 |
| O-02 | HTTPS/代理 | 管理域名、Cookie、公司 CA、WAF、可信代理头正确 | 未验收 |
| O-03 | 密钥管理 | Gateway/issuer/session/OIDC/internal token 全部独立且不进仓库 | 文档已定义，需 Secret Manager 验收 |
| O-04 | 备份恢复 | admin/auth/gateway/audit 数据分别备份并隔离恢复 | 未验收 |
| O-05 | 灰度回滚 | 客户端、模型、资源和策略可独立灰度/回滚 | 未验收 |
| O-06 | 容量 | 目标人数、并发、P95 延迟和存储增长压测通过 | 未做 |
| O-07 | HA/DR | 多副本、共享存储、RPO 15 分钟、RTO 2 小时演练通过 | 未实现 |
| O-08 | 供应链 | 镜像签名、SBOM、依赖扫描和发布签名 | 未实现 |

## 12. 必做演练

上线前至少完成以下演练，并保留时间、参与人、操作记录和结果：

1. 员工加入失败：IdP 回调错误、网络中断、重复加入码、设备密钥不匹配。
2. 设备丢失：管理员在 5 分钟内吊销设备，旧 Key 和刷新接口均失效。
3. 员工离职：IdP 停用后禁止新加入、心跳和刷新，当前 Key 尽快失效。
4. 跨部门越权：部门管理员修改 URL、请求体和批量目标均被服务端拒绝。
5. 审计故障：审计存储不可写时敏感写操作全部失败，依赖调用为 0。
6. 依赖故障：auth/gateway 超时，管理台显示稳定错误，不伪造成功。
7. 密钥泄露：撤销 Key、轮换 issuer、检查日志和审计无秘密。
8. 资源回滚：强制 MCP/Skill 升级失败自动回退上一版本。
9. 备份恢复：在隔离环境恢复 admin/auth/gateway 数据并验证权限、吊销和审计。
10. 上游同步：合并最新上游后跑全部关键回归，失败可停在上一企业发布点。
11. 审批攻击：伪造、过期、撤销、跨组织、跨动作和修改 payload 的审批全部拒绝，业务依赖
    调用为 0；同一审批并发消费只产生一个业务结果。
12. 二次认证失效：MFA 未完成、ACR 不足、authTime 过期、会话/IP/角色绑定变化时高风险
    动作全部失败关闭。
13. 外部审批重放：使用错误签名、错误 audience、过期时间窗和重复 nonce 回调，审批状态
    不变，原始业务不执行。
14. 通知故障恢复：制造渠道超时、5xx、限流和 dispatcher 崩溃，验证 outbox 重启恢复、
    指数退避、死信和人工重放，业务结果不被改写。
15. Webhook 边界：测试私网地址、重定向、云元数据端点、DNS rebinding 和超时，均不能
    访问内网或泄漏 Secret。
16. break-glass 事后复核：使用紧急流程后验证 15 分钟过期、5 分钟内告警/工单和 24 小时
    内复核证据；未复核时保持高风险状态并禁止静默关闭。

## 13. 上线签字

| 角色 | 签字人 | 结论 | 日期 |
| --- | --- | --- | --- |
| 产品负责人 |  | 范围与体验是否达标 |  |
| 平台研发 |  | 代码、接口、测试是否达标 |  |
| IT 运维 |  | IdP、MDM、代理、备份、值班是否达标 |  |
| 安全/合规 |  | 权限、审计、留存、数据出口是否达标 |  |
| 审计负责人 |  | 访问审计和证据链是否达标 |  |

缺少任一签字，只能继续保持试点，不得宣称生产上线。
