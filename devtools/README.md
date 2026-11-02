# 二开规则（Fork 开发规范）

本仓库是 yetone/magpie 的 fork。当前 GitHub Actions「同步上游」会每小时抓取上游并直接推送
`main`；这只是现状，不是企业目标态。企业版必须改为“同步分支 -> 合并 `upstream/main` ->
CI -> 自动创建 PR -> 通过受保护 `main` 合并”。所以 `main` 不是普通开发分支，不能直接改。

当前 `devtools/new-feature`、`update-feature` 和 `finish-feature` 脚本保留了单人维护时的
快捷流程，其中 `finish-feature` 会直接合并并推送 `main`。企业多人协作或启用 `main`
分支保护后，必须改为“推送 `feat/*` 分支 -> 创建 PR -> 通过必需检查 -> 合并”。任何
自动化都不得绕过保护；只有经批准的真人紧急维护可按 break-glass 流程使用管理员 bypass，
并保留安全记录和事后复核。上游每小时同步也应从直接推送改为自动 PR，并在合并前运行完整
回归，避免未经验证的上游提交进入员工可部署发布点。

企业功能的产品方案、实施状态和部署说明：

- [`enterprise-plan-summary.md`](enterprise-plan-summary.md)：管理层可读的完整企业方案、角色流程、功能域、交付分级、唯一实施顺序和当前真实完成度。
- [`enterprise-master-plan.md`](enterprise-master-plan.md)：企业版总纲、唯一里程碑顺序、角色流程、功能目录和上线门槛。
- [`enterprise-feature-spec.md`](enterprise-feature-spec.md)：完整企业功能方案、架构、权限、MCP/资源库、审计、验收和 fork 兼容规则；第 5.11、6.12、25.2.11 节定义审批、step-up、break-glass、通知 outbox、Webhook/SIEM/工单，第 25 节提供逐项需求追踪矩阵、交付包和完成定义。
- [`enterprise-roadmap.md`](enterprise-roadmap.md)：按阶段拆分的实施顺序和优先级。
- [`enterprise-acceptance-checklist.md`](enterprise-acceptance-checklist.md)：从技术试点到生产上线的验收证据和签字表。
- [`enterprise-implementation-status.md`](enterprise-implementation-status.md)：当前已实现、已测试和未验证能力。
- [`enterprise-deployment.md`](enterprise-deployment.md)：团队部署、上游同步、分支保护、MDM 和发布流程。
- [`enterprise-operating-model.md`](enterprise-operating-model.md)：项目 RACI、协作节奏、GitHub 规则、环境晋级、发布证据、成本容量、培训和试点退出。

## 企业版当前实施基线

截至 2026-11-02，M0、M1、M2-A、M2-B、M2-C1、M2-C2 和 M2-C3 已有实现和测试证据。
当前工作分支还实现了 **C4-01** 的 `gateway-key describe --json` 和原子
`gateway-key policy apply --json` 机器协议，并通过 Go 单测、CLI 回归和隔离真实二进制的
冒烟测试。**C4-02** `gateway-control` 受控适配器也已实现，并通过 `15/15` Mock/故障
测试：只允许 describe/apply/健康检查、独立 Bearer 服务令牌、固定 argv、10 秒超时、
64 KiB 上限、写入后独立回读和 `pending` 保守状态。C4-02 的 Docker/Compose 尚未实机
验收，admin-service 经 auth-service 间接调用，尚未直接接入。**C4-03a** 正式只读模型目录已实现，并通过 7 项目录专项；
当前管理服务 `104/104`（77 项管理服务集成、7 项目录专项、7 项通知渠道专项、7 项通知规则专项、6 项 SIEM 专项）；
`GET /api/v1/admin/models` 已使用正式目录，`ADMIN_MODELS` 仅保留兼容显示。C4-03a 仍待真实
Compose/只读挂载/digest 验收；
auth-service 不加载目录，只接收展开后的稳定模型 ID。**C4-03b** 的用户级策略核心已实现：版本化 `gatewayPolicy`、
旧 M1 `unknown` 迁移、quota/models 分步首次设置、缺项失败关闭、版本冲突和逐凭证回读确认
均通过 auth-service `26/26`。C4-03c 的额度/模型管理 API、幂等签发、issuance journal、
apply/独立回读、同步后交付、失败补偿和启动恢复核心已实现并通过 Mock/故障测试；
C4-03d 部分实现：管理页已有额度/模型写表单和完整证据链状态，员工页已有本人额度/模型/
凭证/设备只读门户；M2-D 已补基础停用/吊销/轮换、审批、operation/audit 查询、人工对账
和 CSV 导出页面，但仍缺浏览器 E2E、失败恢复入口和完整运营体验。C4-04 完整管理到真实
Magpie 策略流 E2E 已通过，覆盖双设备独立 Key、真实限额/模型拒绝、多凭证部分失败、
refresh/rotate 继承、故障后 pending、Journal/孤儿 Key 撤销和恢复同步。M2-D 核心已实现，
Mock/集成测试通过；生产验收尚未完成。M3-A 的资源目录、不可变版本、内容哈希、Ed25519
签名、发布/回滚、幂等和资源审计核心已实现，并通过 11 项测试；M3-B 的远程 MCP 注册、
企业统一端点、工具级授权、健康检查、上游凭据隔离和元数据审计核心已实现，并通过 14 项
测试；M3-C-1 的设备短期同步凭证、desired-state、设备上报、管理员 JSON 查询和客户端 HTTP
传输适配器已实现，resource-service 15 项（11 核心 + 4 控制面）、client-sync 24 项
（16 核心 + 8 传输）测试通过；M3-D 与 M4-M6 仍未实现。M3-A/M3-B 尚未接入 admin-service
真实审批、管理台和 OIDC 组织分配；M3-C-1 已接入员工端同步 API，但管理台资源/漂移页、
本地 helper、目标 Agent 文件映射、Windows ACL、MDM、真实 IdP、浏览器 E2E 和
Docker/Compose 实机验收未完成。M3-B 的审批 nonce 仅单进程内存、注册表与审计不是同一事务，
且 Compose 尚未实机验收。当前本地/Mock 回归为 admin 104 项、auth 26 项、gateway-control
15 项、resource 15 项、mcp-gateway 14 项、client-sync 24 项，合计 198 项通过。
C4-01/C4-02/C4-03a/C4-03b/C4-03c 尚未合入 `main`，且真实环境验收未完成，不能据此
宣称管理员已经可以在生产自助调额或授予模型。
`APR-01a/b` 的服务端审批、职责分离、一次性消费和 HMAC/Mock 外部审批回调，
以及 `APR-01c` 的独立 step-up 已实现并通过 Mock/故障测试；`APR-01c` 覆盖独立 OIDC
Client、`prompt=login`、`max_age`、`auth_time`、ACR/MFA、会话/IP/UA/角色范围绑定，
未配置时高风险操作失败关闭。`NOTIFY-01a` 的 transactional outbox、租约、幂等、退避、
死信、重启恢复、deliveries 查询和受审计人工重放已实现并通过 Mock/故障测试；`NOTIFY-01b`
的渠道管理 API 和统一 HTTPS 渠道适配器已实现并通过专项/故障测试，支持 `email`/`im`/
`webhook`/`ticketing`、HMAC Webhook、host allowlist、DNS 固定解析和私网/重定向防护。
邮件/IM/工单是厂商 HTTPS 网关契约，不是原生 SMTP/Graph/飞书/Teams/ServiceNow/Jira SDK；
`NOTIFY-01c` 的 SIEM transport、固定 L0 schema 和 dead-letters API 已实现；真实 SIEM
接收端未验收。`NOTIFY-01d` 的渠道规则/抑制、聚合、升级和运营页已实现并通过 Mock/集成
测试。默认禁用渠道，未启用渠道或没有
transport 时不会创建 dispatcher，也不会伪造“已投递”。`APR-01d` 的审批箱已实现并通过
Mock/集成测试，`APR-01e` 的 break-glass、真实 OA/IdP 连接器、真实厂商网关和生产投递
仍未实现或验收。业务请求不得同步等待外部通知
渠道，管理页也不能在真实 IdP、MFA、反向代理和生产验收完成前宣称生产可用。

企业功能必须按下面的顺序推进，不能跳步：

```text
真实环境验收
  -> C4-01：机器可读 describe/原子 policy apply
  -> C4-02：gateway-control 受控适配器（已完成本地 Mock/故障测试；待 Docker/真实卷验收）
  -> C4-03a：只读正式模型目录、稳定模型 ID、Provider 通配符和 group 展开（已完成本地测试；待真实部署验收）
  -> C4-03b：用户级 gatewayPolicy、旧 M1 unknown、首次初始化和逐凭证 known（核心已完成）
  -> C4-03c：额度/模型管理 API、issuance journal、同步后交付和无孤儿补偿（核心已完成；待真实环境验收）
  -> C4-03d：页面/运营真实状态、失败凭证和对账入口（部分完成）
  -> C4-04：完整管理到真实 Magpie 策略流 E2E（已完成；待 Docker/共享卷和真实 IdP 验收）
  -> C5：operations/audit-logs/reconcile（后端和基础页面已完成）
  -> APR-01a/b/c：审批绑定/一次性消费、外部审批、step-up（代码和 Mock 测试已完成）
  -> NOTIFY-01a/b [core done] / 01c：outbox、渠道 API/HTTPS transport、SIEM
  -> M2-D：管理台写操作、基础页面和授权导出（核心已完成；生产验收待完成）
  -> APR-01d [done]：内置审批箱、多步骤审批
  -> APR-01e + NOTIFY-01d [core done]：break-glass、通知运营页
  -> M3-A [core done]：资源目录、不可变版本、哈希、Ed25519 签名、发布/回滚和资源审计
  -> M3-B [core done]：远程 MCP 注册、企业端点、工具级授权、健康检查和凭据隔离
  -> M3-C-1 [control plane + core done]：同步凭证、desired-state、报告 API、HTTP 传输与同步核心
  -> M3-D：受控本地 MCP
  -> M4-M6
```

C4-01 已按以下机器协议边界实现；后续适配器和管理 API 必须继续遵守这些约束，禁止用人类
可读的 `limit/models` 文本解析冒充生产回读：

1. 复用 `internal/access` 的文件锁、原子写、`CleanModels` 和 `Limit.Valid`。
2. `describe` 只读，固定输出 `schemaVersion: 1`、安全 Key 状态、模型 patterns、0-5 个额度窗口、
   `policyRevision` 和账户范围摘要；不得输出 Key、masked key、token hash、账户 ID 或 Secret。
3. `policy apply` 从 stdin 接收一份 schema v1 JSON，在同一文件锁内校验、原子替换模型和额度，
   再回读；使用 `expectedPolicyRevision` 乐观锁，冲突不写文件。
4. `gateway-control` 只允许 describe/apply/健康检查，使用固定 argv 数组、独立服务令牌或 mTLS、
   10 秒超时、64 KiB 上限和专用配置目录；写入后必须再独立执行一次 describe。
5. 只有独立回读一致且真实请求行为符合目标策略，才能把策略标为 `known`；否则保持
   `pending`。C4-04 已在隔离真实链路中验证这一点，但 Docker/共享卷和真实企业 IdP 仍需验收。

详细 schema、状态机、接口和验收字段见
[`enterprise-feature-spec.md`](enterprise-feature-spec.md) 第 12.8.1.5 节和
[`enterprise-master-plan.md`](enterprise-master-plan.md) 的 M2-C4 工作包。

## 三条铁律

1. **main 归同步管**：不要直接改 main、不要直接推 main。
2. **新功能必开分支**：功能一律在 `feat/功能名` 分支上开发，可以同时开多个互不干扰。
3. **从最新 main 出发**：用本目录的工具开分支，保证起点与上游最新一致。

当前企业阶段的推荐分支顺序：

```text
feat/m2-c4-gateway-control（已完成，待合入/合入后）
  -> feat/m2-c4-gateway-policy
  -> feat/m2-c4-gateway-policy-e2e
  -> feat/m2-c5-operations-audit
  -> feat/apr-01b-external-approval
  -> feat/apr-01c-step-up（当前）
  -> feat/notify-01-outbox-delivery
  -> feat/m2-d-admin-operations
  -> feat/m2-e-approval-notify-ops
```

用户级策略/额度、真实 E2E 和对账页面仍必须分别使用独立功能分支和独立 PR，
在前一切片合入 `main` 后再创建依赖分支；审批、step-up、outbox 和各通知渠道也不能作为
页面附属功能塞进 M2-D。不得把机器协议、适配器、额度 API、模型 API、审批、通知和页面
堆成一个无法审查的大 PR。

## 一个功能的完整流程

```text
devtools\new-feature.cmd 功能名     # 1. 从最新代码创建 feat/功能名 分支
（在此分支上开发、提交……）
devtools\update-feature.cmd         # 2.（可选）功能做到一半想同步最新上游
devtools\finish-feature.cmd         # 3. 功能完成：合并回 main 并推送
```

### 新建功能

`devtools\new-feature.cmd 我的功能`

- 自动做三件事：拉取 origin + upstream；把本地 main 更新到与上游一致；从 main 创建 `feat/我的功能`。
- 功能名会自动转成小写字母数字和连字符。
- 手头有未提交的改动时，脚本会拒绝执行（先提交或 `git stash`）。

### 中途同步（防止冲突）

`devtools\update-feature.cmd`

- 把 origin/main 和 upstream/main 的最新代码合并进当前功能分支。
- 万一有冲突（上游也改了同样的文件），会在这里暴露——全程不碰 main，在功能分支里解决最安全。
- 建议：功能超过一天、或上游变化频繁时，每天跑一次。

### 功能收尾

`devtools\finish-feature.cmd`

- 这是单人维护快捷路径：把功能分支推到 GitHub 备份；切回 main 并同步；合并功能；推送 main。
- 企业默认不使用该直推路径。启用受保护 `main` 后，功能分支只推送并创建 PR；只有经批准的
  真人紧急维护才能按 break-glass、安全记录和事后复核流程使用管理员 bypass。机器人和同步
  工作流永远不得 bypass。手动 `git push origin main` 仍会被本地钩子拦下。

## 防护钩子（pre-push）

仓库已配置 `core.hooksPath = devtools/hooks`，规则由钩子强制执行：

- 直接 `git push origin main` → 被拦下，提示改用上面的脚本。
- 推送 `feat/*` 等其它分支 → 正常放行。
- 确需绕过本地钩子（例如经批准的紧急维护）：`MAGPIE_MAIN_OK=1 git push origin main`，
  或 `git push --no-verify`。这只绕过本地钩子，不会绕过 GitHub 分支保护或必需检查；请慎用。

## 为什么这样能避免和 main 冲突

- 每个功能都基于「最新的 main」独立开分支，互相独立，也能并行开发。
- main 只做两件事：接收通过 PR 的企业功能，以及接收通过 CI 的上游同步 PR；不能直接推送。
- 真冲突只可能发生在「你改的代码恰好也是上游最近改的代码」。此时 `update-feature` 会在你的功能分支里提前把它暴露出来，那是最可控的解决时机。

## 给 Codex / AI 助手的提示

- 本项目是 fork：**永远不要**把改动直接提交到 main 或推送 main。
- 新功能先运行 `devtools\new-feature.cmd 名字`；企业默认收尾是推送分支并创建 PR，
  `finish-feature` 只用于单人维护快捷路径。
- main 是受保护的集成与上游同步分支；遇到冲突先在功能分支运行
  `devtools\update-feature.cmd`，同步冲突则在 `sync/upstream-*` 分支解决。
- 所有 PowerShell 命令必须用 `D:\Environment\PowerShell-7.6.6-win-x64\pwsh.exe` 执行（见根目录 AGENTS.md）。
