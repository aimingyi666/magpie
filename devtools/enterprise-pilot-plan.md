# Magpie 企业版试点计划（8 周）

状态：执行版 v1，2026-11-06
目标：**两个月内让 5–10 名真实员工试用**，正文审计是合规硬要求，必须同期交付。
依据：[`enterprise-implementation-status.md`](enterprise-implementation-status.md)（事实）、
[`enterprise-master-plan.md`](enterprise-master-plan.md)（退出条件）、
[`enterprise-acceptance-checklist.md`](enterprise-acceptance-checklist.md)（证据要求）。

本计划只覆盖试点范围。生产加固、HA、真实 SIEM/OA 连接器不在其中，见第 6 节。

## 1. 成功标准

试用结束时要能当众演示、也能当场撤销：

1. 员工用**企业现有 OIDC** 登录 → 注册设备 → 拿到短期 Key → 本地 Agent 可用，全程 ≤ 5 分钟，员工不接触厂商 Key。
2. 离职或丢设备后 ≤ 1 小时无法刷新、无法调用。
3. 管理员能看到**按人/部门/设备/模型/路由组**的用量与请求路由，而不是只有总量。
4. 企业资源（统一指令、MCP、技能、子代理）能下发到员工机器并真实写入 Agent；能回滚；员工能看到当前版本。
5. 企业设置的供应商在员工客户端**置顶且不可删改**，界面与客户端自建供应商一致。
6. 正文审计：管理员凭授权可查指定员工的对话正文；每次查看有访问记录；到期能删除并留下删除证据。
7. 脱敏规则可按企业定制，**但基线规则不可关闭**。

以上 7 条任何一条做不到，试点就只算「技术演示」，不能对外称「可试用」。

## 2. 已定决策

| 决策 | 结论 | 影响 |
| --- | --- | --- |
| 交付目标 | 5–10 人受控试点，两个月 | 功能广度让位于「端到端可证明」 |
| 正文审计 | 合规硬要求，进关键路径 | M4-A/M4-B 从「以后」提前到 W1 |
| Key 粒度 | **每设备一把**（保留现状） | 丢设备只撤一把；按人统计需经凭证表聚合 |
| 设备身份强度 | 增加**设备私钥签名**（W1） | 设备令牌或 Key 被复制到别的机器也换不到新 Key |
| 网关策略事实源 | **原生管理 API**（`MAGPIE_ADMIN_ADDR`） | `gateway-control` 降为过渡，验收后删除；不再新增经 CLI 的写路径 |
| IP 控制 | 网关级 allowlist（办公网/VPN），不做 per-key IP | 反向代理下 per-key IP 不可靠 |
| 首批 Agent | **Claude Code + Codex**（OpenCode 第二期） | 决定资源落盘器的工作量 |
| 分支基线 | 先合并再开发 | 当前分支落后 `main` 382 个提交、7 个冲突，不合并则计划时间不可信 |

## 2.1 前端形态：全部在客户端内，服务端只出 JSON

页面不写成独立网站，也不在 admin-service 里渲染 HTML 字符串：

- **用户端和管理端的展示页都在 `enterprise/magpie-plugin` 里**，由客户端加载，作为插件页面运行；不新增服务端渲染页面。
- **admin-service 只提供 `/api/v1/...` JSON 和管理 OIDC 回调**，不承担界面。
- **对上游 `main` 的改动只有插件页面挂载点**（`internal/plugin/page.go`、`internal/gui/pluginpage.go`），是加分枝、不改原有行为；其余企业代码都在 `enterprise/`。
- **登录走浏览器 OIDC 回调**：插件本机服务生成 PKCE，系统浏览器完成企业 OIDC/MFA，回调只带回一次性 ticket，服务端换短期桌面 token；页面从不接触 OIDC secret、管理 Cookie、桌面 token 或供应商 Key。
- **样式跟随窗口，不另立一套**：页面由插件本机服务绘制（与窗口不同源），所以 `index.html` 把窗口的 `--magpie-*` 令牌随跳转交给服务，服务生成 `theme.css`，`ui.css` 只读这些令牌；页面再通过 `theme-bridge.js` 向父窗口 hello，接收 `theme` 事件，切换明暗/字体时**实时重绘**，不用重开页面。
- 网页管理台 `admin-service` 的 `/admin/` 暂时保留，只作为**审批消费的兜底入口**；等审批中心进了客户端就可以下线。

## 3. 前置条件：企业 OIDC

企业已有 OIDC 服务，这是最大的时间优势：不需要自建 IdP，也不用再等 Mock。W0 用两天把它打通。

### 3.1 需要 IdP 管理员提供的参数

| 用途 | Client | 回调地址 | 需要的 Claim |
| --- | --- | --- | --- |
| 员工登录 | `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | `{AUTH_PUBLIC_URL}/oauth/callback` | `sub`、`email`、`email_verified`、`name`、`groups` |
| 管理登录 | `ADMIN_OIDC_CLIENT_ID` / `ADMIN_OIDC_CLIENT_SECRET` | `{ADMIN_PUBLIC_URL}/admin/oauth/callback` | 同上，另加 `acr`、`amr` |
| 高风险二次认证 | `ADMIN_STEP_UP_OIDC_CLIENT_ID` / `_SECRET` | `{ADMIN_PUBLIC_URL}/admin/oauth/step-up/callback` | `auth_time`、`acr`、`amr` |
| 本地加入 | 员工 Client 的 loopback 回调 | `http://127.0.0.1:{port}/callback` | — |
| 桌面管理插件 | 管理 Client 的 loopback 回调 | `http://127.0.0.1:{port}/admin-callback` | — |

配置项见 [`enterprise-deployment.md`](enterprise-deployment.md) 的 `ADMIN_OIDC_*` 与
`auth-service/src/config.js` 的 `OIDC_*`。名称可改：`OIDC_EMAIL_CLAIM`、`OIDC_NAME_CLAIM`、
`OIDC_GROUPS_CLAIM`，但语义必须与上面一致。

### 3.2 必须先验证的三件事

1. **`groups` 到底返回什么。** 组织范围、资源下发、审计授权全挂在它上面。要确认：是组名还是组 ID、有没有数量上限（Entra 超过约 200 个会改走分离接口）、嵌套组是否展开。
2. **`email_verified` 是否总是 true。** `ADMIN_REQUIRE_VERIFIED_EMAIL=true` 时它缺失就会拒绝登录。
3. **`acr`/`amr` 在 MFA 后是什么值。** 决定 `ADMIN_ALLOWED_ACR_VALUES` 和 step-up 门禁能否成立。

兜底：如果 IdP 给不出 `groups`，组织范围改为「管理端手工映射 + 后续 SCIM」，这在计划里要多留 3 天。

### 3.3 OIDC 打通任务（W0，2 天）

- 用真实 IdP 跑通 discovery、JWKS、授权码 + PKCE、刷新、logout。
- 管理端单独跑通 MFA/ACR 和 step-up。
- 记录实际下发到 `/api/v1/me` 的 claim 投影，确认没有多余字段外泄。
- 结果写进 `enterprise-acceptance-checklist.md` 第 4 节，附 IdP 名称、Client ID 后四位和时间。

## 4. 八周排期

三条主线并行；A 是合规关键路径，任何延期先保 A。

| 周 | A 正文审计（关键路径） | B 资源下发 | C 供应商 / 路由 / 用量 | D 身份与设备 |
| --- | --- | --- | --- | --- |
| W0 | 合并分支、CI 跑绿；冻结 M4-B 契约 | 确认首批 Agent 与落盘格式 | 修 `/api/v1/client/enterprise/providers` 404 | 真实 OIDC 打通 |
| W1 | 网关采集 prompt/response（L2，默认关） | `hook` 类型建模；资源落盘器设计 | 企业供应商置顶（核心 + GUI） | 设备私钥签名 |
| W2 | 采集接入 audit-service，按人归属 | Claude Code 落盘：指令/技能/子代理 | 路由可见页面（按 callerKey 聚合） | 签名上线 + 迁移策略 |
| W3 | 管理员查看页 + 授权核验 | Codex 落盘：指令/技能/MCP | 用量分析页（趋势/成本/异常） | 真实 IdP 回归 |
| W4 | 访问审计 + 留存到期删除 | 漂移检测 + 回滚 + 员工可见 | 模型组企业锁定 | 停用/丢设备演练 |
| W5 | 脱敏规则企业定制（基线 + 叠加） | Hook 下发（签名 + 审批） | 供应商凭据服务端托管 | — |
| W6 | 规则预览/试跑/版本化 | 管理台发布/回滚页 | 全成员用量报表导出 | — |
| W7 | 合规演练：谁能看、看了记什么、怎么删 | 全链路回归 | 浏览器 E2E | 反向代理 + HTTPS |
| W8 | 试点上线、值班、问题清单 | 同左 | 同左 | 同左 |

### 4.1 各阶段退出条件

- **W0**：`main` 上九套企业测试全绿；`enterprise` CI job 在 `main` 上真的跑过；工作区无未归属改动。
- **W1–W2**：一段真实员工请求的 prompt/response 能在 audit-service 落库，管理员凭授权读回，落盘文件中搜不到测试秘密。
- **W3–W4**：能按人/时间检索；每次读取都有访问记录；到期对象被删除且删除记录可查。
- **W5–W6**：企业自定义规则生效，基线规则关不掉；试跑能对同一段文本给出前后对照。
- **W7**：真实 IdP + 反向代理 + 浏览器全流程通过；停用一个账号，1 小时内全部失效。
- **W8**：5–10 名员工连续使用 5 个工作日，无 P1 故障。

## 5. 工作分解

### A. 正文审计（合规关键路径）

现状：`enterprise/audit-service` 有 M4-A 元数据管道和 M4-B 内容核心，**默认关闭、无生产者、无消费者、授权 ID 未核验**。

1. **采集（W1–W2）**：网关在请求/响应结束时把 L2 文本推给 audit-service。只采 prompt 与回复正文；工具调用的参数和结果**第一期只记元数据**（名称、耗时、是否失败），不进正文对象。理由：工具参数里出现密钥和源码的概率最高，且体积不可控。
2. **查看（W3–W4）**：管理台按人/时间/会话检索，点开需提交 `authorizationId` 与理由；服务端向审批系统核验该授权真实存在、未过期、范围匹配，核验失败拒绝。
3. **留存（W4）**：按组织配置保留天数；到期任务删除对象与索引，写删除记录（对象 ID、时间、原因、操作者）。删除证明第一期只做「可查的删除记录」，不做 WORM。
4. **脱敏定制（W5–W6）**：基线规则版本锁定、不可禁用；企业规则只能**追加**替换或屏蔽模式，不能删除基线类别。规则改动需版本化、试跑、审计，并禁止把「邮箱/手机号」这类基线类别整体关掉。
   - 已实现（2026-11-06）：新增 `redact` 资源类型，client-sync 把它合并写成
     `<magpie 配置目录>/managed-redact.json`（原子写、移除即清空）；magpie 的
     `internal/masking` 每个请求读取，策略带 `requireBaseline` 时强制打开 secrets
     与个人数据、忽略用户的分类开关；网关的插件刷新也监听该文件，策略到达后无需重启。
     未做：按规则命中统计、试跑/预览、规则版本历史。
   - 企业规则可**按组织/部门启用**，按优先级依次执行，冲突时更严格的规则先生效；
   - 每条规则记录命中次数，管理端能看到「哪条规则在真实流量里起作用」；
   - 规则只影响新写入的正文，不回溯改写已存对象（回溯属于二期）。

**开放决策（W1 前必须回答）**：留存几天、谁能看（安全管理员常驻 vs 每次审批）、是否包含工具参数。建议：30 天、`security_admin` + 每次理由 + 抽样复核、工具参数不进正文。

### B. 资源下发

现状（2026-11-06）：`instructions` 写进 `CLAUDE.md`/`AGENTS.md` 的受管块；`skill` 写
`.claude/skills/<name>/SKILL.md`，`subagent` 写 `.claude/agents/<name>.md`，`mcp` 合并进
`.mcp.json`，三者都带归属标记、同名冲突拒绝、资源移除时收回；`redact` 策略写入
`<magpie 配置目录>/managed-redact.json`，由 magpie 每个请求读取（基线类别不可关）。
Codex 接收 `instructions`/`skill`/`mcp`/`hook`；`hook` 写入 Claude 的 `settings.json` 和
Codex 的 `hooks.json`，写过的条目记在同步目录里，员工改过的条目不会被删。Codex 没有已知的
用户级子代理文件，`subagent` 对它报 `unsupported`。管理台已可在客户端插件里发布/回滚（发布要求一个绑定版本的一次性审批）。

1. **建模（W1）**：新增 `hook`；明确每类资源的落盘位置与格式：

   | 资源 | Claude Code | Codex |
   | --- | --- | --- |
   | 统一指令 | `CLAUDE.md`（受管块） | `AGENTS.md`（受管块） |
   | 技能 | `.claude/skills/<name>/` | 按 Codex 当前支持的技能目录 |
   | 子代理 | `.claude/agents/<name>.md` | 暂不支持，第一期只做 Claude Code |
   | MCP 服务器 | `.mcp.json`（项目）或 `~/.claude.json`（用户） | `config.toml`（受管块） |
   | Hook | `settings.json` 的 `hooks` | `config.toml` 对应段 |

   落盘前必须先探测 Agent 版本与现有配置，未知格式一律失败关闭，不猜。
2. **落盘器（W2–W4）**：受管块写入、备份、冲突检测（用户改过的文件不覆盖）、漂移检测、一键回滚。所有写入走临时文件 + 原子替换。
3. **Hook（W5）**：可执行代码按最高风险处理：签名验证、管理员审批、员工端可见「将执行什么」、可一键停用。第一期不做静默下发。
4. **管理台（W6）**：发布、回滚、按组织/部门定向、员工端查看当前版本。

**注意**：资源落盘是「改员工电脑上的文件」，与 `docs/subsystems` 里本地写入的既有约束一致，必须可回滚、可解释。

### C. 供应商、路由、用量

1. **企业供应商（W1–W2）**
   - ~~修 `enterprise/magpie-plugin` 调用的 `/api/v1/client/enterprise/providers`：admin-service 目前没有这个路由，面板会 404。~~ 已实现（2026-11-06）：`GET /api/v1/client/enterprise/providers` 用设备令牌向 auth-service 解析用户/设备/凭证，再取网关供应商的安全投影，并按凭证的模型白名单过滤模型；插件面板位置已提到供应商列表之前。auth-service 新增管理服务专用的 `POST /api/v1/internal/admin/devices/resolve`。
   - **界面复用客户端现有的供应商设置页**，不另造一套：同一个列表、同一套表单，只在企业项上加锁定标记。
   - 核心新增 `managedBy: "enterprise"`：置顶排序、GUI 禁止删除/改地址/改凭据、员工可看不可改。
   - **员工自建供应商保留**，但永远排在企业供应商之后，且不能被拖到企业项上面。
   - 是否允许员工自建由组织策略开关控制（见第 9 节开放决策 5）。
   - 供应商凭据只存在服务端，客户端只拿到可用模型与状态。
2. **路由可见（W2）**：遥测已记录 `callerKeyId/Name`；页面按人聚合，展示走了哪个账号、哪个模型、是否失败。
   - **网关只认 Key，不认人。** 人/部门由 admin-service 用凭证表关联；页面上标明「归属来自凭证映射」，映射缺失时显示「未归属」，不按邮箱猜。
   - 已实现（2026-11-06）：`/api/v1/admin/gateway/requests` 的每一行带 `user/userId`；
     网关新增 `/v1/magpie/admin/telemetry/active`（在飞请求 + callerKey），admin-service
     代理为 `/api/v1/admin/gateway/active` 并补人，会话字段不进入企业视图。
3. **用量分析（W3）**：复用 `usage-reader`，补四类视图：
   - 全成员：按人、部门、设备、Agent、模型、路由组聚合（设备/路由组维度已实现，
     `groupBy=device|group`，过滤与 CSV 同步支持）；
   - 成本：按模型单价折算费用，按部门对比；
   - 异常：用量突增、失败率异常、深夜调用；
   - 导出：授权后的 CSV（沿用现有审批 + step-up 链路）。
4. **模型组（W4）**：原生路由组加「企业锁定」。
   - 企业定义的组在客户端以 `group/<name>` 出现，选择和本地路由组完全一样；
   - 成员、优先级、故障转移由管理端维护，员工只能选、不能改；
   - 企业组的模型范围必须落在模型目录内，引用不存在的模型时发布失败。

### D. 身份与设备

1. **设备私钥签名（W1）**：注册时公钥已保存（`auth-service/src/service.js:1744`），但目前只存不用。刷新与换 Key 时要求设备私钥对「方法 + 路径 + 时间戳 + nonce」签名；服务端验签、校验时间窗、nonce 防重放。
2. **存量设备**：试点尚未开始，按**直接强制**处理，不留兼容分支；若已有设备在用，改为双轨 + 到期强制重新加入。
3. **真实 IdP 回归（W3）**：登录、刷新、停用、换设备各跑一遍。

## 6. 明确不做（试点期）

- M5 安全运营：真实 SIEM、告警阻断、值班闭环。
- M6 高可用：PostgreSQL、多副本、Redis、KMS/HSM、mTLS。
- 真实 OA/飞书/ServiceNow/Jira 连接器；真实邮件/IM 网关。
- break-glass 生产演练、加密导出、WORM、法律保留。
- OpenCode 及其他 Agent 的资源落盘（第二期）。
- per-key IP 绑定。

## 7. 风险登记

| 风险 | 影响 | 应对 |
| --- | --- | --- |
| IdP 的 `groups` 不符合预期 | 组织范围全链路返工 | W0 先验证；不行就改手工映射 + SCIM，预留 3 天 |
| 反向代理下 Cookie/回调用错域名 | 登录与 step-up 失败 | W7 前用真实域名和公司 CA 演练 |
| Agent 文件格式随版本变化 | 落盘器失效 | 受管块 + 版本探测 + 失败保留旧版；只承诺首批两个 Agent |
| Hook 被滥用 | 员工机器执行任意代码 | 签名 + 审批 + 可见 + 可停用；第一期不静默下发 |
| 正文审计的法务口径未定 | 上线即违规 | W1 前由业务/法务确认留存、可见范围、告知方式 |
| 分支长期不合 main | 合并成本指数上升 | W0 必做，之后每周同步一次 |
| 两个会话同 checkout 改文件 | 提交串味 | 一个分支一个会话；提交前 `git status` 核对归属 |

## 8. 记录规则

- 每个提交写清「改了什么、跑了什么、没试什么」，不写模板占位符。
- 测试必须在**将要推送的那个提交**上跑；真实环境证据写进
  [`enterprise-acceptance-checklist.md`](enterprise-acceptance-checklist.md)，写明 IdP、域名、时间。
- 「Mock 通过」不等于「验收通过」，文档里继续分开写。

## 9. 开放决策

| # | 问题 | 建议 | 需谁定 |
| --- | --- | --- | --- |
| 1 | 正文留存天数、可见范围、是否含工具参数 | 30 天；`security_admin` + 理由 + 抽样复核；工具参数不进正文 | 业务 + 法务 |
| 2 | 已有设备是否需要兼容 | 试点未开始则直接强制签名 | 项目负责人 |
| 3 | Hook 是否进第一期 | 进，但只做签名 + 审批 + 可停用 | 安全 |
| 4 | 员工告知方式（登录页/入职流程） | 登录时明示并留痕 | 法务 + HR |
| 5 | 是否允许员工自建供应商 | 允许，但永远排在企业项之后 | 业务 |
| 6 | 企业资源标记「强制」时，与员工本地同名资源冲突怎么办 | 企业覆盖并提示，保留本地副本可回滚 | 业务 + 安全 |
| 7 | 脱敏规则是否允许按部门不同 | 允许追加，但基线类别所有部门一致 | 法务 |

## 10. 分支冲突分析（2026-11-06）

处理顺序、确认门禁和每周检查见
[`enterprise-drift-plan.md`](enterprise-drift-plan.md)。

以 `codex/m4-b-content-audit-core`（HEAD `c7010e496`）为基准做 `git merge-tree` 预演：

| 目标分支 | 落后/领先 | 冲突文件 | 说明 |
| --- | --- | --- | --- |
| `main` | 落后 382，领先 6 | 13 个：5 份 `devtools/enterprise-*.md`、`enterprise/README.md`、`enterprise/admin-service/README.md`、`enterprise/.env.example`、`enterprise/admin-service/src/{approval,config,service}.js`、`admin-service.test.mjs`、`enterprise/docker-compose.yml` | 本分支从 main 的 M9–M11 之前分出，两边都改了 admin-service 和文档 |
| `codex/enterprise-console-ui` | 在 main 之上多 4 个提交 | 同上 13 个 | 服务端渲染的控制台线：`admin-template.html`、`employee-portal/portal-template.html`、`charts.js`、本地化与可访问性 |
| `feat/enterprise-full`、`feat/enterprise-m9-m11-complete`、`codex/m8-admin-console` | — | 12–13 个，同上 | 同一批 admin-service 与文档 |

不冲突的部分：

- `enterprise/magpie-plugin/**`（页面、服务、测试）是本分支新增，main 和 console-ui 都没有；两边合并都是纯新增。
- `internal/gui/*` 不是本分支的改动（来自 main 的漂移），`internal/gui/assets/index.html` 可自动合并，但合并后要跑一次 `plugin-page.test.cjs`。

需要决策的重复：

1. `codex/enterprise-console-ui` 正在做**服务端渲染的 HTML 控制台/员工门户**，与本计划「页面在客户端插件里」的方向相反；两套都留会长期双 UI。
2. 该分支的本地化、可访问性、`charts.js` 等成果可以移植到插件页面，但不要保留它的 HTML 页面宿主。
3. 该分支已在 `C:/Users/AiMingYi/.codex/worktrees/m4b-store/magpie` 检出，属于另一个会话；不要在那个工作区里操作。

建议的合并顺序：

1. 先把 `main` 合进本分支，只解决那 13 个文件；解决时以本分支的「原生管理 API + 插件 UI」为准，文档取两边并集。
2. `enterprise/magpie-plugin` 整包提交，连同 `theme.css`/`theme-bridge.js` 一起，避免页面与主题分离。
3. console-ui 分支的 UI 宿主（admin-template/portal-template）标记为「停止演进」，只挑本地化和可访问性代码。

## 11. 变更记录

| 日期 | 变更 |
| --- | --- |
| 2026-11-06 | 初版：按「5–10 人试点 + 正文审计硬要求 + 企业已有 OIDC」重排 |
| 2026-11-06 | v1.1：补齐供应商自建与置顶、Agent 落盘位置、路由归属口径、用量四类视图、脱敏组织范围与优先级、企业资源冲突策略 |
| 2026-11-06 | v1.2：前端形态定为客户端插件页面；admin-service 只出 JSON 和 OIDC 回调；网页管理台仅留作审批兜底；资源库页已作为第一个客户端页面落地 |
| 2026-11-06 | v1.3：资源页支持查看发布记录；页面主题改为随窗口实时更新；补充分支冲突分析与合并顺序 |
| 2026-11-06 | v1.4：P0 企业供应商链路落地：客户端供应商路由、设备令牌解析、按凭证模型过滤、面板置顶、`managedBy` 标记；请求行补 `user/userId` 归属。剩余缺口（核心侧企业锁定、员工自建策略开关、真实联调）未动 |
| 2026-11-06 | v1.5：P1–P3 落地：skill/subagent/mcp 落盘与移除收回；在飞请求接口与按人归属；用量设备/路由组维度与 CSV；`redact` 资源下发 + 基线锁定。仍未做：hook 落盘、Codex 非指令类型、规则命中统计/试跑、异常检测、管理台发布回滚 UI、真实环境验收 |
| 2026-11-07 | v1.6：补全资源下发与运营闭环：hook 写入 Claude `settings.json` / Codex `hooks.json`（条目日志、员工改动不覆盖）；Codex 也接收 skill/mcp；用量异常检测改为按主体历史自动算基线；管理台可在客户端插件内创建→加版本→发布/回滚（发布需一次性审批），插件每 5 分钟自动同步；已用真实 resource-service + admin-service 跑通发布到落盘。仍未做：Codex 子代理（无已知格式）、规则命中统计/试跑、真实设备验收 |
