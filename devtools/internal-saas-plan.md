# 内部 SaaS 化方案（员工自助接入）

状态：方案草案 v0.1，待确认后进入实施排期

日期：2026-11-08

适用范围：把现有 `enterprise/` 技术切片从"IT 逐个开 Key"改造成"员工自助接入"的内部平台。
本文只覆盖企业内部人员使用形态，不覆盖对外多租户商业 SaaS、计费和多地域。

关联文档：[`enterprise-plan-summary.md`](enterprise-plan-summary.md)、
[`enterprise-feature-spec.md`](enterprise-feature-spec.md)、
[`enterprise-implementation-status.md`](enterprise-implementation-status.md)。

## 1. 结论先行

**不需要做多租户。** 内部人员使用是单一信任域，做 `tenantId` 贯穿
`auth-service` / `admin-service` / 网关的改造成本约 6–8 周，且每一处漏判都是跨部门数据串号，
而内部场景下这个隔离收益为零。

真正让现在这套跑不起来的只有三件事：

1. 新员工第一次 OIDC 登录后**拿不到 Key**（`policy_setup_required`），必须管理员手工设额度+模型；
2. 部门归属靠管理员手工维护，IdP 的 `groups` 已经拿到了却没用；
3. 员工接入必须开 PowerShell 跑 `join-enterprise.ps1`，普通员工做不到。

把这三点打通，就是"内部 SaaS"的完整体验。多租户、计费、按量账单全部延后。

## 2. 现状证据

| 事实 | 位置 |
| --- | --- |
| 首次 OIDC 登录会自动建用户，但策略是 `unknown` | `enterprise/auth-service/src/service.js:1634-1661` |
| 策略不完整就拒绝签发 Key，返回 `409 policy_setup_required` | `enterprise/auth-service/src/service.js:207-223` |
| `unknown` 策略的构造点 | `enterprise/auth-service/src/policy.js:16-26` |
| IdP 的 `groups` 已随登录写入用户，但没有下游消费 | `enterprise/auth-service/src/service.js:1647,1657` |
| 组织单元与用户归属是手工维护的 JSON | `enterprise/admin-service/src/store.js:176-177` |
| 员工接入口是 PowerShell 脚本 | `enterprise/scripts/join-enterprise.ps1` |
| 网关 Key 无租户字段，`caller-keys.json` 单文件单锁 | `internal/access/access.go:111`、`:197` |
| 核心 Go 侧没有"企业登录"入口，只有 Key 签发 API | `internal/gateway/issue_keys.go` |

## 3. 三个必做改造

### P0-1 默认策略模板（解锁自助开通）

问题：`policyGateError` 要求 `quota` 和 `models` 两项都齐全，新用户两项都是 `null`，
所以永远卡在 `409`。

改法：

- 新增策略模板存储（`enterprise/auth-service/src/policy-templates.js`）：
  `{ id, name, models[], limits[], matchGroups[], matchEmailDomains[], priority }`。
- 首次登录建用户时，在同一个 `store.mutate` 内按 `identity.groups` 匹配模板，
  直接materialize 一份**完整**策略，`quotaStatus`/`modelStatus` 初始化为 `pending`。
- 之后完全复用现有链路：`gateway-control` apply → 独立回读 → `known` → 交付 Key。
  这条链路已有测试覆盖（C4-03c/C4-04），不需要改。
- 兜底：无任何模板匹配时，用 `DEFAULT_POLICY_FALLBACK`（建议：只读模型 + 小额度），
  而不是让用户卡住；管理员的例外授权在其后覆盖。
- 策略来源写入 `initializationSource: "template:<id>"`，让管理员能看出"这条是模板给的还是人给的"。

验收：新建一个测试账号首次登录，不点任何管理页面，60 秒内 `/api/v1/me` 显示可用 Key，
`policyKnown=true`。

风险：模板一旦写错会把额度发给所有人。所以模板变更必须走
`admin-service` 的受控写接口 + 审计，不能直接改 JSON 文件。

### P0-2 IdP 组 → 部门 → 模板映射

问题：管理员现在要手工维护 `userOrgUnits`，几百人规模不可行。

改法：

- `admin-service` 增加 `groupMappings: { idpGroup, orgUnitId, policyTemplateId, priority }`。
- 登录时（或在 auth 的登录回调里）把 `identity.groups` 映射成 `userOrgUnits` 与 `policyTemplate`，
  写回 admin store；只在映射结果与当前值不同时才写，避免每次登录都产生审计噪音。
- 管理员只维护"组 → 部门"这一层，人员归属随 IdP 自动流动；入职离职由 IdP 决定。
- 映射变更必须产生管理审计，并记录受影响用户数。

验收：在 IdP 侧把测试账号加入 `ai-platform` 组，重新登录，管理页自动出现该部门归属和对应额度。

### P0-3 客户端一键登录（去掉 PowerShell 门槛）

问题：`join-enterprise.ps1` 需要员工本机有 PowerShell 执行策略、知道仓库路径、会传参数。

改法：

- 短期（1 周，不动核心 Go）：把脚本包成一条命令
  `magpie enterprise join --url https://auth.ai.corp.example`，
  内部复用现有 `join-enterprise.ps1` 逻辑（设备密钥、PKCE、loopback 回调、Provider 写入）。
  员工文档只写这一行。
- 中期（2–3 周，改核心 Go，独立 `feat/` 分支）：在 magpie 客户端加"企业登录"入口，
  走同一条 OIDC + 设备注册 + Provider 写入流程；复用 `internal/oidc`。
- 两条都保留：命令行给技术员工，GUI 给非技术员工。

验收：在干净机器上只跑一条命令，Agent 配置被写入且能真实调用。

## 4. 优先级 P1（试点前需要）

### P1-1 部门用量与成本摊分

- 数据源已有：网关 `usage.jsonl` + admin-service 的用量汇总。
- 增加按部门/月的汇总视图与 CSV 导出，复用现有导出框架。
- 不做计费系统：内部用"部门 token 池 + 月度报表"足够。

### P1-2 员工门户引导页

- `enterprise/employee-portal` 已有，补首登引导：显示本人额度、模型、一键复制的接入命令、
  客户端下载链接、常见问题。
- 明确保留现有边界：网页不读写员工本机 Agent 文件，落盘由本地 magpie/helper 完成。

## 5. 明确不做

- 不在 `internal/access` 里加 `tenant` 字段，不在一个网关进程里跑多租户。
- 不做自助注册 + 信用卡计费；内部账号由 IdP 决定。
- 不卖第三方订阅账号共享（`AGENTS.md` 里已把这类内置订阅全部迁出，SaaS 化会放大厂商条款风险）。
- 不默认采集对话正文。

## 6. 成本与容量

单网关 + 单一 `caller-keys.json` 意味着：

- 网关是单点，需要至少主备 + 定期备份 `caller-keys.json` 与 auth/admin store。
- 额度是共享池，必须靠 P0-1 的默认模板兜住"没人设额度"的情况，否则一个月就可能烧穿预算。
- 500 人以内单实例足够；超过后按部门拆多个网关实例（届时再谈多租户）。

## 7. 里程碑

| 周 | 交付 | 是否动核心 Go |
| --- | --- | --- |
| W1 | P0-1 策略模板 + P0-2 组映射（auth/admin，纯 JS）+ 对应测试 | 否 |
| W2 | P0-3 命令行封装 + 员工接入文档 + 20 人试点 | 否 |
| W3 | P1-1 部门报表 + P1-2 门户引导 + 试点复盘 | 否 |
| W4+ | P0-3 GUI 一键登录 | 是，独立 `feat/` 分支 |

W1–W3 全部在 `enterprise/` 内，不碰上游同步的核心代码，风险最低。

## 8. 待确认

1. 默认额度取什么值？（建议：每人每月 token 上限，按部门池子分配，先给一个偏低的值）
2. 新员工默认模型范围？（建议：默认只开中低成本的 2–3 个模型，高成本模型按组申请）
3. IdP 是否已经有稳定的部门组？没有的话 P0-2 要先做组规划。
4. 员工电脑上是否已有 MDM/软件中心可分发 magpie？这决定 P0-3 走命令行还是安装包。
