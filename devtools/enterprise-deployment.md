# 企业团队部署指南（Fork 二开 + 内网落地）

完整角色流程、功能目录、里程碑顺序和上线门槛见
[`enterprise-master-plan.md`](enterprise-master-plan.md)；本文侧重部署和发布操作。

本仓库是 `yetone/magpie` 的 fork（MIT 协议，允许企业内部使用与二开，保留版权声明即可）。
这份指南面向"企业/团队多人使用"的场景：既要持续吸收上游更新，又要保证版本可控、密钥不外泄、能安全分发、能审计。

一句话思路：**上游持续跟、版本自己发、模型密钥留在内部网关、更新走内网源、分发走 MDM、代码走 PR**。

完整能力、数据模型、M2 管理服务/RBAC、MCP/资源库、审计和验收标准见
[`enterprise-feature-spec.md`](enterprise-feature-spec.md)；当前代码和测试状态见
[`enterprise-implementation-status.md`](enterprise-implementation-status.md)；生产上线逐项证据
见 [`enterprise-acceptance-checklist.md`](enterprise-acceptance-checklist.md)。本文只负责落地
操作，不把设计方案描述成已实现。

**当前状态：** M0、M1、M2-A/B/C1/C2/C3 已有代码和测试；C4-01 的
`gateway-key describe --json` 与原子 `gateway-key policy apply --json` 机器协议已实现，
并通过 Go 单测、gateway-key CLI 回归和隔离真实二进制冒烟。C4-02
`enterprise/gateway-control/` 受控适配器也已实现，并通过 15 项 Mock/故障测试。C4-03a
正式只读模型目录已实现，并通过 7 项目录专项测试；当前管理服务 109 项测试通过（82 项管理
服务集成、7 项目录专项、7 项通知渠道专项、7 项通知规则专项、6 项 SIEM 专项），`GET /api/v1/admin/models` 已使用正式目录，
`ADMIN_MODELS` 仅保留
无正式目录时的兼容显示。C4-03b 用户级 `gatewayPolicy` 核心已在 auth-service 实现，
覆盖旧 M1 `unknown` 迁移、分步初始化、版本冲突、失败关闭和回读确认，当前 26 项测试通过；
C4-03c 的管理 API、幂等签发、issuance journal、自动 apply/readback、同步后交付、失败补偿
和启动恢复核心已实现，并通过 Mock/故障测试；C4-03d 部分实现：管理页已有额度/模型写
表单、停用/吊销/轮换基础操作、审批、operation/audit 查询、人工对账和 CSV 导出入口，
员工页已有本人额度、模型、凭证和设备只读门户；浏览器 E2E、失败恢复入口和完整运营体验
仍未完成。C4-04 完整管理到真实 Magpie 策略流
E2E 已通过，覆盖管理 OIDC/CSRF、quota/models 分步设置、双设备独立 Key、真实限额/模型
拒绝、多凭证部分失败、refresh/rotate 继承、故障后 pending、Journal/孤儿 Key 撤销和恢复
同步；M2-C5 的查询/对账与 M2-D 核心已实现，基础页面已接入，生产验收尚未完成。admin-service
负责展开正式目录选择器，auth-service 接收
稳定模型 ID；APR-01a 审批后端、APR-01b HMAC/Mock 外部审批回调适配器、APR-01c 独立 OIDC
step-up、APR-01d 审批箱/多步骤审批和 APR-01e break-glass 核心已实现并通过测试；NOTIFY-01a 的 transactional outbox、租约、幂等、退避、死信、
重启恢复、deliveries 查询和受审计人工重放也已通过 Mock/故障测试；NOTIFY-01b 的渠道管理
API 与统一 HTTPS 渠道适配器已实现，覆盖 `email`/`im`/`webhook`/`ticketing`、HMAC Webhook、
host allowlist、DNS 固定解析和私网/重定向防护。默认不启用渠道；未启用渠道或没有 transport
时不创建 dispatcher。邮件、IM 和工单依赖厂商 HTTPS 网关契约，不是原生厂商 SDK；真实网关、
证书/租户配置和真实投递未验证。NOTIFY-01c 的 `http-collector`/`otlp-http`/`syslog-tls`
SIEM transport、固定 L0 schema 和 dead-letters API 已实现并通过 6 项专项测试；真实
SIEM/Collector/Syslog/生产证书未验收。NOTIFY-01d 的规则/抑制、聚合、升级、受审计重放和
运营页已实现并通过 Mock/集成测试。真实 OA
连接器、真实 IdP/MFA/反向代理、浏览器流程、break-glass 告警/工单与 24 小时生产复核也未验证。
M3-A 的 `enterprise/resource-service/` 已实现资源目录、不可变版本、SHA-256 内容寻址、
Ed25519 签名、发布/历史回滚、幂等和资源审计，并通过 11 项核心测试；M3-B 远程 MCP 治理
核心已通过 14 项测试；M3-C-1 已实现设备短期同步凭证、desired-state、设备上报、管理员
JSON 查询和客户端 HTTP 传输适配器，resource-service 15 项（11 核心 + 4 控制面）、
client-sync 24 项（16 核心 + 8 传输）测试通过；M3-C-2 已实现 admin-service 只读资源/
同步报告 API 和管理页面板，admin-service 109 项、local-mcp 21 项通过；既有企业回归 203 项，合计 224 项。
M3-A/M3-B 只有核心服务 API；M3-C-1/M3-C-2 已有控制面 API 和只读管理页，但尚未接入
admin-service 真实审批、资源发布/回滚 UI、发布/回滚审批联动、OIDC 组织分配和本地 helper
产品入口；
M3-B 的审批 nonce/限流器仅单进程，注册表/审计/幂等不是同一事务，存在提交后审计失败窗口。
M3-D 运行时核心已实现并通过 21 项测试，但本地 helper/管理台集成、外部 OS 沙箱和生产验收仍未完成；S3/MinIO、KMS/HSM、多副本和 Docker/Compose 实机仍未验收。
Docker/Compose、真实共享卷、真实企业 IdP、公司
反向代理和生产环境均未验收。
第 10 节描述的是 C4-01/C4-02/C4-03a/C4-04 的已实现边界和待验收项；当前不能把受控适配器、
真实 E2E 或只读目录当成生产部署完成。

---

## 1. 合规与安全基础（先想清楚的事）

- **MIT 许可**：企业内部使用、二次开发、再分发都合法。条件是保留原版权声明。
- **数据出口**：magpie 本质是本地网关，把 Agent 的请求转发给你配置的模型服务。**Prompt 会发到模型服务那一端**。部署前必须明确：
  - 只能用内网/允许名单里的模型入口（见第 2 节，推荐方案）；
  - 涉密文件的路径提示词、代码片段会进入模型上下文，需要和法务/安全团队确认哪些数据允许出域。
- **隐私 masking**：Settings → Privacy 里有隐私过滤（默认关闭）。按团队需要开启，作为第一道防线，但不能替代内网网关。
- **插件外联**：上游把部分订阅迁到了社区插件（`magpie-community/plugins`）。企业若有强管控要求，限制员工装插件、只允许白名单插件。

## 2. 内部模型网关（推荐核心，先做这个）

magpie 只是"客户端/网关壳"，模型请求最终发给 Provider。企业最省心的做法是**自建一个 OpenAI 兼容的模型入口**，让 magpie 只连内网：

```text
员工电脑 magpie ──→ 内网模型网关（LiteLLM / vLLM / Ollama / 公司中转）──→ 真实大模型
                         ↑
              只有网关持有真实 API Key
```

做法：

1. 在企业内部挑一台机器（或云上私有网段）部署 LiteLLM：它统一转发到 OpenAI / Anthropic / 自建模型，对外只暴露一个 OpenAI 兼容地址，例如 `http://model-gateway.internal:8000/v1`。
2. 员工的 magpie 里只配这个内网地址 + **低权限的临时 token**，不配任何真实厂商 Key。
3. 真实 API Key 只存在网关的密钥管理（或公司密钥服务）里，随网关按部门做限额和审计。

这样做到：密钥不落到每台员工机、请求可统一审计、用量可控。

当前 fork 的企业层已经把这条链路具体化为 `enterprise/docker-compose.yml`、员工 Key
开通脚本和隔离 E2E；M1 另外提供 `enterprise/auth-service` 做 OIDC 登录、设备注册和短期
Key 签发；M2-A/M2-B 提供独立的 `enterprise/admin-service` 管理身份、组织范围和只读治理；
M2-C1 提供 Auth 服务间停用/启用、设备吊销和凭证轮换内部接口；M2-C2 提供受控的管理写 API。
完整状态见
[`enterprise-implementation-status.md`](enterprise-implementation-status.md)。

## 3. 版本与发布策略（上游照跟，发布自己做）

现状：

- `main` 当前仍由 `sync-upstream.yml` 每小时合并并直接推送上游；这不是启用分支保护后的企业目标态。企业版必须改为“创建同步分支 -> 合并 `upstream/main` -> CI -> 自动创建 PR -> 通过受保护 `main` 合并”。
- 上游的 `release.yml` 依赖上游私有仓库和签名密钥，**fork 里无法原样出官方安装包**。所以正式发布要在自己这侧做。

建议流程（关键：发布和开发分开）：

1. **日常开发**：功能在 `feat/*` 分支开发，通过 PR 合并回受保护 `main`（见第 5 节）。同步任务每小时检查上游并创建自动 PR，只有必需检查通过后才合入。
2. **发版**：选一个 main 上稳定、测试通过的点，手动打 release 分支（如 `release/v1.4.2`）或直接打 tag `v1.4.2`。
3. **自己构建发布物**：在自己仓库的 Actions 里跑 `make build` / `make cli`，产物传到内部制品库（GitHub Releases、公司 Artifactory、S3/MinIO 均可）。
4. **灰度**：先发 5-10 人试用组，确认一周无问题，再推送全员。

## 4. 内网更新源（关键抓手，magpie 原生支持）

magpie 的自更新源可通过环境变量 `MAGPIE_UPDATE_FEED` 指到**你自己的地址**（`internal/update/update.go`），自带 SHA-256 校验。这样员工机由你统一推送版本，不会偷偷升到上游新版本：

1. 在内部静态文件服务（或 GitHub Releases 上你自己发的产物）放：

   ```json
   {
     "Version": "1.4.2",
     "Notes": "公司内部版：新增内网网关预设",
     "URL": "https://update.internal.example/magpie/1.4.2/",
     "Assets": {
       "magpie-windows.zip": {
         "URL": "https://update.internal.example/magpie/1.4.2/magpie-windows.zip",
         "Size": 48219904,
         "SHA256": "要填构建产物的真实哈希"
       }
     }
   }
   ```

2. 打包/下发时给员工机设置环境变量 `MAGPIE_UPDATE_FEED=https://update.internal.example/magpie/feed.json`（可以写进 MDM 的安装脚本或公司包预置）。
3. 注意：裸二进制按 SHA-256 自校验没问题；但 **macOS 若未做公司内代码签名，官方自更新机制会失败**。两个选择：走公司开发者证书签名后发布；或干脆禁用自更新、版本全由 MDM 下推（小团队更省事）。

## 5. 团队代码流程（多人协作，锁住 main）

个人二开靠 `devtools` 的三个脚本，团队要再上一层：**main 只有自动同步和 PR 能进**。

GitHub 仓库设置里开分支保护（Settings → Branches → main）：

- 要求 PR（pull request）才能合并；
- 要求至少 1-2 人 Review；
- 要求 CI 通过（`test.yml` 已在仓库里，直接启用）；
- 禁止机器人和人工直推 `main`，也不要给同步任务配置 bypass。同步任务只创建 `sync/upstream-<时间戳>` 分支和 PR，由必需检查和受保护分支规则决定能否合并。

日常协作流程：

```text
组员A：new-feature.cmd A功能  → 开发 → 提交 → push feat/A功能 → 提 PR 等 Review → 合并回 main
组员B：new-feature.cmd B功能  → 并行开发，互不干扰
同步任务：每小时创建 sync/upstream-<时间戳> → 合并 upstream/main → CI → 自动 PR
main：必需检查通过后合并同步 PR；冲突时在同步分支解决并告警，不覆盖企业提交
```

`devtools` 里的 `new-feature` / `update-feature` 仍可用于创建分支和同步上游；
`finish-feature` 只是单人维护的直推快捷路径，不能作为企业默认。企业必须以 PR、必需检查和
受保护 `main` 为唯一常规合入方式；只有经批准的真人紧急维护可按 break-glass 使用管理员
bypass，并保留安全记录和事后复核。机器人、CI 和同步工作流永远不得 bypass。

## 6. 安全分发（MDM 装包 + 预置配置）

用公司 MDM（Intune / Jamf / 鹿班 / PDQ 等）统一装、统一更：

1. **装包**：把企业构建产物做成公司安装包（Windows MSI/Inno Setup 封装、macOS pkg、Linux deb/rpm）。
2. **预置配置**：安装脚本里写进用户级配置——默认只指向内部网关的 Provider、设好 `MAGPIE_UPDATE_FEED`、关闭敏感 Provider、开启隐私 masking。**不预置任何真实模型密钥**（密钥只在网关侧）。
3. **网络策略**：员工机只允许访问：内网模型网关、内网更新源、公司代理。默认拒绝直连外网模型厂商（如确有需要，走公司代理白名单并记录）。
4. **新员工/离职**：账号鉴权统一接公司 SSO（或至少每次登录走网关 token），离职即吊销该 token。

注意：企业网页不能直接读写员工电脑上的 Agent 配置文件。标准流程是“MDM 安装本地
Magpie → 员工通过网页完成 OIDC → 本地 `join-enterprise.ps1` 写入 Provider 并调用原生
一键配置 Agent”。网页可以负责身份、授权、设备状态和资源展示，但不能把浏览器当成
本地文件配置器。

## 7. 运维与监控（共享环境 + 日志审计）

- **共享/CI 环境**：仓库自带 `Dockerfile`（Debian 12 slim、nonroot、数据全在 `/config` 卷）。可以在内网用 Docker / Web UI 跑一个共享实例，供 CI 或远程小环境用，示例：

  ```yaml
  services:
    magpie:
      image: registry.internal/magpie:e1.4.2
      ports: ["127.0.0.1:8080:8080"]
      volumes:
        - magpie-data:/config
        - magpie-home:/config/home
  volumes:
    magpie-data:
    magpie-home:
  ```

- **日志与审计**：收集网关侧的请求日志（谁、何时、调了哪个模型、多少 token）；本机日志在 Windows `%LOCALAPPDATA%\magpie\logs`。规定日志保留期和脱敏规则。
- **用量监控**：在网关层（LiteLLM 等自带用量统计）做 token/费用看板，按部门限额。
- **备份与回滚**：`/config` 卷定期备份；出问题时把内网更新源 feed 指回上一版本即可全量回滚，不用逐台机器操作。
- **上游跟踪节奏**：main 每小时自动跟上游；你可以在更新源里晚几天再发新版本——先看上游 release 说明，再决定要不要跟进，灰度通过再全员。

## 8. 分阶段落地清单

| 阶段 | 内容 | 完成标志 |
| --- | --- | --- |
| 1. 试点 | 内网模型网关 + 5-10 人试用组，手动发版 | 大家每天都用，无阻断问题 |
| 2. 锁版本 | 内网更新源 + 固定版本号 + 灰度发布流程 | 员工机版本可统一控制 |
| 3. 铺开 | MDM 装包、分支保护、日志审计 | 全团队接入，密钥都在网关卡 |
| 4. 身份闭环 | 真实 IdP + 真实 Magpie issuer + 设备注册 + 短期 Key 刷新 | 离职/挂失可立即吊销，员工无需手工复制 Key |
| 5. 管理身份 | M2-A/M2-B：独立 admin-service + 管理 OIDC + MFA/ACR + 会话/CSRF + RBAC + 组织范围 + 只读治理 | Mock 测试通过；真实 IdP、反向代理、角色演练和真实用量卷通过 |
| 6. 管理写接口 | M2-C1/C2：Auth 内部与管理侧停用/启用、设备吊销、当前凭证轮换 | C1/C2 的鉴权、目标校验、范围、CSRF、理由和失败回滚已通过 Mock；真实环境待验收 |
| 7. 网关机器协议 | C4-01：`gateway-key describe --json` 和原子 `policy apply --json` | schema v1、无秘密输出、冲突不写入和隔离真实二进制冒烟通过 |
| 8. 管理闭环（核心实现，待生产验收） | C4-02 `gateway-control`、C4-03a 正式只读模型目录、C4-03b 用户级策略核心、C4-03c 管理 API/签发同步/交付和 C4-04 完整管理链路 E2E 已实现；C4-03d 已补管理页额度/模型写表单、停用/吊销/轮换基础操作和员工只读状态门户；M2-C5 的 operation/audit 查询、人工对账和 M2-D 基础运营页、CSV 导出已接入 | 管理员能受控自助操作，跨部门访问被拒绝，敏感操作可追溯；浏览器 E2E、失败恢复体验、真实负载和生产验收完成（目标状态） |
| 9. 持续 | 按周跟进上游 release，定期做回归和安全检查 | 长期稳定运行 |

上表第 8 行是目标状态，不是当前完成状态。C4-02 已有受控适配器和 Docker/Compose 文件，
并通过 Mock/故障测试，但尚未在真实 Docker、共享卷和真实 Magpie 上验收。C4-03a 已提供
正式只读目录和固定摘要，并由 admin-service 展开稳定模型 ID；C4-03b/C4-03c 已在
admin-service、auth-service 和 gateway-control 之间接通策略核心、apply/readback、
同步后交付、失败补偿和启动恢复。C4-04 已通过隔离真实 Magpie 的完整管理链路 E2E，
但真实共享卷、真实企业 IdP、反向代理、浏览器和生产环境仍未验收；C4-03d 仍缺浏览器
E2E 与失败恢复入口，C5 和 M2-D 的基础查询、对账、写操作和 CSV 导出页面已接入，生产
验收尚未完成。
因此不得把管理台描述成“生产自助管理员工额度/模型已完成”，也不得把隔离 E2E 通过等同于
生产部署验收。C4-04 证明真实 Magpie 会按策略限额和拒绝模型，但不证明 Docker/Compose、
共享卷、真实 IdP 或生产反向代理可用。

## 9. M2-A/M2-B/M2-C1/M2-C2/M2-C3 管理面部署与验收

当前 `enterprise/admin-service` 已实现管理身份底座、只读治理、四个受控管理写 API，以及
额度/模型策略写 API：最小
管理页、组织范围、用户、部门、设备、凭证、模型、用量汇总和时间序列；用量从网关卷只读
挂载。停用/启用、设备吊销和当前凭证轮换的 Auth 内部接口（M2-C1）与管理侧接口（M2-C2）
均已实现并通过 Mock 测试；管理侧已接入管理会话、CSRF、RBAC、组织子树和必填理由，
响应使用字段白名单。M2-C3 已为四个写接口接入 `Idempotency-Key` 持久化/重放/冲突、
`operationId`、intent/result 管理审计和审计失败阻断；C4-03c 已把调额/模型授权接到
auth-service、gateway-control、apply/readback 和同步后交付，并覆盖 payload 绑定幂等和
失败补偿。C4-03d 已补管理页额度/模型写表单、停用/吊销/轮换基础操作和员工只读状态门户，
M2-C5/M2-D 已补审批、operation/audit 基础筛选查询、人工对账和 CSV 导出页面；浏览器 E2E、
失败恢复入口、费用趋势看板、Excel/异步大批量导出和完整运营体验仍未完成。C4-01 的机器协议和 C4-02 的受控适配器已实现并通过本地/Mock 测试；C4-04 已通过
隔离真实 Magpie 的完整管理链路 E2E，但真实共享卷、Docker/Compose、真实企业 IdP、
公司反向代理和生产环境仍未验收。
不要把 Mock 测试当成生产管理台验收，也不要把“能看元数据”说成“能看对话正文”。

### 9.1 启动

在 `enterprise/` 目录准备 `.env`：

```bash
cp .env.example .env
docker compose --profile admin up -d
docker compose ps
curl http://127.0.0.1:3445/healthz
```

`--profile admin` 会同时启动网关、auth-service 和 admin-service。Compose 要求
`enterprise/model-catalog.json` 存在并以只读方式挂载；缺少该文件时管理服务按失败关闭处理。
首次试点先从示例复制并固定 digest：

```powershell
Copy-Item enterprise\model-catalog.example.json enterprise\model-catalog.json
& 'D:\Environment\PowerShell-7.6.6-win-x64\pwsh.exe' `
  -NoLogo -NoProfile -NonInteractive `
  -Command 'Get-FileHash enterprise\model-catalog.json -Algorithm SHA256'
```

把输出中的哈希写入 `enterprise/.env`：

```dotenv
ADMIN_MODEL_CATALOG_DIGEST=sha256:<实际哈希>
```

目录文件只读挂载到 `/etc/magpie-enterprise/model-catalog.json`。修改目录后必须重算 digest、
更新 `.env` 并重启管理服务；实现没有在线 reload 接口。至少配置：

- `ADMIN_PUBLIC_URL`、`ADMIN_OIDC_*` 和独立的管理 OIDC Client；
- `ADMIN_SESSION_SECRET`，不能与 `AUTH_COOKIE_SECRET` 复用；
- `ADMIN_ALLOWED_IPS`，试点默认只允许办公网/VPN；
- `AUTH_INTERNAL_ADMIN_TOKEN`，由 auth-service 和 admin-service 共享，且不同于
  `AUTH_ADMIN_TOKEN`；
- `ADMIN_REQUIRE_VERIFIED_EMAIL=true`；确认 IdP 契约后才考虑关闭；
- `ADMIN_ALLOWED_ACR_VALUES`（可选）用于固定 IdP 的 MFA/条件访问认证上下文；
- 外部审批回调启用时，`ADMIN_APPROVAL_CALLBACK_SECRET`、`ADMIN_APPROVAL_CALLBACK_ISSUER`
  和 `ADMIN_APPROVAL_CALLBACK_AUDIENCE` 必须成组配置；secret 至少 32 字符，并只通过
  Secret Manager 或受控环境变量注入。`ADMIN_APPROVAL_CALLBACK_MAX_SKEW_SECONDS` 默认
  300 秒，`ADMIN_APPROVAL_CALLBACK_NONCE_TTL_SECONDS` 默认 600 秒；
- `ADMIN_MODEL_CATALOG_DIGEST`，固定正式目录字节；只读目录文件使用 schema v1、严格 JSON、
  2 MiB 上限、稳定模型 ID、显式 `providerWildcards` 和非嵌套 group，重复 key、未知字段、
  尾随内容、重复模型/group、未知引用或 digest 不匹配都会阻止管理服务启动；
- `ADMIN_MODELS` 只用于没有正式目录时的兼容显示，不是稳定模型 ID、Provider 通配符或 group
  的权限事实来源；
- `ADMIN_USAGE_PATH=/magpie-readonly/magpie/usage.jsonl`，以及
  `ADMIN_USAGE_MAX_BYTES`、`ADMIN_USAGE_MAX_LINE_BYTES`、`ADMIN_USAGE_MAX_RECORDS`、
  `ADMIN_USAGE_MAX_FIELDS`、`ADMIN_USAGE_MAX_RANGE_DAYS`；
- 受限 CSV 导出使用 `ADMIN_EXPORT_TTL_SECONDS`（默认 900 秒）、
  `ADMIN_EXPORT_MAX_BYTES`（默认 5 MiB）和 `ADMIN_EXPORT_MAX_RECORDS`（默认 100000）
  限制下载窗口、单文件大小和行数。导出要求有效审批、fresh step-up、CSRF、组织范围和理由，
  下载 token 只通过响应体返回，必须同时使用同一管理员会话 Cookie；禁止把 token 放进查询串。

`GET /api/v1/admin/models` 已读取正式目录并返回安全投影与 `catalog` 摘要。目录解析只由
admin-service 负责；auth-service 接收管理端展开后的稳定模型 ID，gateway-control 不解析
目录。因此“管理员能看到正式目录”仍不等于“员工凭证已经按该目录授权”，真实生效必须看
策略同步状态和独立回读结果。

`gateway-control` 是独立 profile，不会随 `--profile admin` 自动进入管理链路。启动它可验证
适配器自身健康检查：

```bash
docker compose --profile gateway-control up -d
docker compose exec gateway-control node -e \
  "fetch('http://127.0.0.1:3446/healthz').then(r=>r.text()).then(console.log)"
```

当前 auth-service 已接入该适配器执行策略 apply 和独立回读；适配器或容器启动成功本身仍不
代表额度修改或模型范围授权已经生效，必须检查 issuance journal 和同步状态。

### 9.1.1 M3-A 资源目录服务

`resource` 是独立 profile，不会随 `--profile admin` 启动。它只暴露内部端口 `3447`，
不发布宿主机端口，使用独立 `resource-data` 和 `resource-content` 卷；签名私钥通过
Compose secret 挂载，入口脚本复制到 tmpfs 后设置为 `0600`。先在 `enterprise/` 下生成
密钥并配置 `.env`：

```bash
node resource-service/scripts/generate-signing-key.mjs \
  secrets/resource-signing-key.pem
```

`RESOURCE_SERVICE_TOKEN` 必须是独立的长随机值，只提供给受信控制面服务，不得进入浏览器、
员工客户端、URL、日志或 Git。`RESOURCE_SIGNING_KEY_ID` 必须稳定；轮换公钥时要保留旧公钥
的验签窗口。关键变量见 `enterprise/.env.example`：

```text
RESOURCE_SIGNING_KEY_FILE=./secrets/resource-signing-key.pem
RESOURCE_SIGNING_KEY_ID=resource-2026-11-v1
RESOURCE_SERVICE_TOKEN=<separate-long-random-token>
RESOURCE_STORE_PATH=/data/resource-store.json
RESOURCE_CONTENT_PATH=/content/objects
```

启动并检查容器内健康状态：

```bash
docker compose --profile resource up -d resource
docker compose exec resource node -e \
  "fetch('http://127.0.0.1:3447/healthz').then(r=>r.text()).then(console.log)"
```

当前机器未安装 Docker CLI，因此上述 Compose 构建、启动、健康检查、卷权限和 secret 复制
都还没有实机证据。该 profile 成功启动也只说明目录服务可用，不代表真实审批、管理台、
员工端同步接入、S3/MinIO、KMS/HSM、多副本或生产验收完成。

### 9.1.2 M3-C-1 同步控制面与客户端同步核心

`enterprise/client-sync/` 是安装在员工设备上的 Node 核心包，不是新增的常驻服务，也没有
Compose profile。M3-C-1 新增 `createEnterpriseSyncTransport()`，从 auth-service 的设备身份
换取短期同步凭证，并向 resource-service 拉取 desired-state、提交元数据同步报告；传输层
支持凭证缓存/重签、ETag 条件请求、超时、响应大小上限和报告投影。同步核心仍负责签名
desired-state 的验签、原子激活、离线缓存、策略和漂移行为。浏览器不能直接写
`~/.codex`、`~/.claude` 或 `~/.config/magpie`，也不能使用 `RESOURCE_SERVICE_TOKEN`。

```powershell
Set-Location enterprise/client-sync
& 'D:\Environment\node-v26.12.1\node.exe' --test test/*.test.mjs
```

当前 client-sync 24 项测试通过（16 核心 + 8 传输），resource-service 15 项测试通过
（11 核心 + 4 控制面）。M3-C-2 已把资源目录和同步报告以只读方式接入管理页：
admin-service 使用 `ADMIN_RESOURCE_SERVICE_URL` 和独立 `ADMIN_RESOURCE_SERVICE_TOKEN`
调用 resource-service，只发 GET、不跟随重定向，默认 5 秒超时和 4 MiB 响应上限；
资源与报告按管理员组织范围过滤，依赖故障返回 `503 resource_service_unavailable`。
资源发布/回滚 UI、发布/回滚审批联动、本地 helper 产品入口、目标 Agent 文件映射、
Windows ACL、MDM、浏览器 E2E、真实企业 IdP、Docker/Compose 实机和灰度/自动回滚均未验收。

Compose 必须把网关数据卷只读挂载到管理容器：

```yaml
volumes:
  - admin-data:/data
  - magpie-data:/magpie-readonly:ro
```

管理服务只读 `usage.jsonl`，不能写网关数据卷；文件缺失、损坏、尾部半行或超过限制时返回
`503 storage_unavailable`，不会输出部分报表。

### 9.1.3 M3-D 受控本地 MCP 运行时核心

`enterprise/local-mcp/` 是员工设备侧的 Node 运行时核心，不是 Compose 服务。它先验证
Ed25519 签名包、canonical manifest、文件 SHA-256 和公钥指纹，再以 staging/fsync/复验/
原子 rename 安装；运行时套用 Node permission model、受限环境和企业能力策略，高风险工具
调用需要绑定包 digest 与工具名的审批，Secret 通过 HTTPS Broker 在调用时短期解析。

tests:

```powershell
& 'D:\Environment\node-v26.12.1\node.exe' --test enterprise\local-mcp\test\*.test.mjs
```

当前 local-mcp 21 项测试通过，既有企业回归 203 项，合计 224 项。测试只使用精确文件路径、
临时目录和隔离子进程，不读取真实 usage、管理员会话、Agent 配置或生产 Secret。

生产阻断项：尚未接入本地 helper/Agent 配置和管理台；真实 OIDC、审批服务、Secret Broker、
KMS/HSM、Windows ACL/MDM、代码签名、安装升级/回滚和已证明的外部 OS 沙箱未验收；
Docker/VM、共享卷并发、浏览器 E2E、HA 和生产验收未完成。

### 9.2 管理员流程

1. 管理员打开 `https://admin.ai.corp.example/admin/`。
2. 经独立 OIDC Client 登录，完成 MFA/ACR。
3. 首次登录按受控 bootstrap 创建有到期时间的 `super_admin`，随后写入正式角色绑定并移除
   bootstrap 配置。
4. `/api/v1/admin/me` 返回当前角色、权限、组织范围和 CSRF token。
5. `GET /api/v1/admin/org-units`、`departments`、`users`、`devices`、`credentials`、
   `models`、`usage/summary` 和 `usage/timeseries` 只返回服务端计算后可读的数据；跨范围
   用户详情返回 `forbidden_scope`。
6. 会话绝对过期、空闲过期、IP/User-Agent 绑定变化或角色撤销后，下一次请求被拒绝；过期
   会话会清除管理 Cookie。
7. 四个 M2-C2 写接口要求 CSRF、对应 RBAC 权限、目标组织子树和必填 `reason`；跨范围写入
   返回 `forbidden_scope` 且不调用 auth-service。M2-C3 为这些接口提供可选但应强制使用的
   `Idempotency-Key`、`operationId`、同键重放/冲突和执行中保护，以及 intent/result 审计。
   当前管理页已提供停用/启用、设备吊销和当前凭证轮换的基础操作入口，仍须在真实 IdP、
   反向代理和网关环境完成浏览器 E2E 与故障恢复演练。
8. 当 result 审计失败时，调用方会收到 `503 audit_unavailable`，operation 保留在
   `dependency_invoked`。C5 已提供 operation 查询、脱敏审计分页和人工对账 API，管理页
   已接入基础查询、对账和 CSV 导出入口；必须通过这些受控流程确认依赖是否已生效，不能
   重复假装成功，也不能在未核对前重试写操作。

### 9.3 生产验收清单

以下 C4/C5 条目是后续生产候选的验收条件。C4-01 只完成了机器协议和本地测试；C4-02 已完成
受控适配器和 15 项 Mock/故障测试，但 Docker/Compose、真实共享卷和健康检查尚未实机验证；
C4-03b/C4-03c 核心已有 26 项 auth 测试，管理端已接入额度/模型 API 并覆盖同步后交付和
失败补偿；C4-04 完整管理到真实 Magpie 策略流 E2E 已通过，C4-03d、C5 和 M2-D 的基础
页面已接入，但浏览器 E2E、失败恢复入口、Docker/共享卷、真实 IdP 和生产环境验收尚未完成，
不能填写为“通过”。C4-03a 已有本地专项测试，但仍需完成真实 Docker、只读挂载和 digest
变更重启验收。在真实部署、完整运营入口和生产负载验收齐备前，试点范围仍应限制在受控管理员。

- 管理端真实 IdP 的 `amr`/`acr`、`email_verified`、回调地址和条件访问全部验证。
- 反向代理终止 HTTPS，管理 Cookie 使用 `Secure`、`HttpOnly`、`SameSite=Lax`。
- auth-service 内部状态接口不经过公网，`AUTH_INTERNAL_ADMIN_TOKEN` 不出现在浏览器、
  日志或前端构建产物中。
- M2-C1 的四个内部写接口只允许服务间调用；如果直接暴露到公网，视为验收失败。
- 逐一验证 M2-C2 四个管理写接口和管理页基础按钮的会话、CSRF、RBAC、组织范围、理由和
   依赖故障映射；在浏览器 E2E 和故障恢复演练完成前，不得把页面可操作描述成“生产自助闭环”。
- 验证 M2-C3 的同键重放、同键异体 `409`、执行中 `409`、失败重放、intent 失败依赖调用为 0、
  result 审计失败不返回成功，以及 operation/audit 记录不含秘密。
- 验证 C4-02 `gateway-control` 的独立 Bearer 服务令牌、固定 Key ID 白名单、64 KiB 请求/输出
  上限、10 秒超时、子进程终止、写入后独立 `describe` 回读和 `pending` 保守状态；未在
  Docker/真实共享卷运行前不得勾选通过。
- 用一个企业管理员、一个部门管理员、一个审计员和一个安全管理员演练角色和范围。
- 用真实网关生成 `usage.jsonl`，验证只读挂载、按用户/部门归属、时间窗口、分组、文件轮转、
  损坏和超限行为；确认管理容器不能写 `magpie-data`。
- 停止 auth-service 后，管理读接口和四个管理写接口返回 `502 dependency_unavailable`，
  不得伪造健康状态或写入成功。
- 备份并恢复 `admin-data`，验证角色、组织范围和会话失效语义。

当前机器没有 Docker CLI，以上 Compose、真实浏览器、反向代理和公司 CA 尚未实际验收。

### 9.4 生产验收与上线签字

在进入全员生产前，必须按
[`enterprise-acceptance-checklist.md`](enterprise-acceptance-checklist.md) 逐项记录证据。至少要覆盖：

- 真实员工 IdP 和管理 IdP 的 OIDC、MFA/ACR、回调、Claim、停用和会话过期。
- 反向代理、公司 CA、Cookie、IP 允许列表和内部服务令牌隔离。
- Windows 用户会话计划任务刷新、文件 ACL、锁冲突、断网恢复和重启。
- 真实 `usage.jsonl` 的只读挂载、归属、时间窗口、轮转、损坏和超限。
- M2-C1/C2/C3 的停用、吊销、轮换、幂等、operationId 和 intent/result 管理审计已由 Mock
  覆盖；还要在真实 auth-service 和真实网关上验证撤销队列、当前 Key 失效、设备重新加入、
  管理会话/CSRF/范围/理由，以及审计失败后的对账链路。
- C4-03a 的正式目录在真实 Compose 中完成只读挂载、digest、坏目录失败关闭和重启生效验收。
- C4-04 已通过隔离真实 Magpie 的管理链路，仍须完成真实共享卷/Docker 部署复核；C4-03d/C5
   的基础写操作、审批、operation/audit 查询、人工对账和 CSV 导出页面已接入，但浏览器 E2E、
   失败恢复入口、完整运营体验和生产环境证据尚未验收。本地 Mock/故障测试不能替代这些部署验收。
- M3-A 已通过 11 项 resource-service 核心单元/Mock 集成测试；M3-B 已通过 14 项 mcp-gateway
  单元/Mock 集成测试；M3-C-1 已通过 resource-service 15 项（11 核心 + 4 控制面）和
  client-sync 24 项（16 核心 + 8 传输）单元/Mock 集成测试；M3-C-2 已通过 admin-service
  109 项测试中的 5 项新增用例（企业全量 203 项）。仍须在真实
  Compose 中验证镜像构建、secret 文件权限、
  `resource-data`/`resource-content`/`mcp-data` 卷、健康检查、重启恢复、签名密钥轮换和
  MCP 单副本限制，并接入 admin-service 真实审批、可写管理台和 OIDC 组织分配后再做
  发布/回滚与 MCP 故障演练。M3-C-2 仍须完成资源发布/回滚 UI、审批联动、浏览器 E2E、
  Docker/Compose 实机、灰度/自动回滚和生产验收；M3-C-1 仍须完成本地 helper、目标 Agent
  文件映射、Windows ACL、MDM、真实 IdP、浏览器 E2E、Docker/Compose 实机和生产验收；
  M3-D 受控本地 MCP 运行时核心已实现并通过 21 项测试，但本地 helper/管理台集成、外部 OS 沙箱和生产验收未完成。
- 备份恢复、灰度、回滚、至少一次跨部门越权和设备丢失演练。

上述任何一项没有证据，发布结论只能是“受控试点”，不能写“企业生产已完成”。

## 10. M2-C4 `gateway-control` 部署契约（C4-02 已实现，待实机验收）

本节固定 C4 的部署边界，避免管理服务直接读写 `caller-keys.json`，或把“页面显示成功”
误当成“真实网关已生效”。C4-02 的 `enterprise/gateway-control/`、Dockerfile、Compose
`gateway-control` profile、环境变量和 `/healthz` 已完成，并通过 Node Mock/故障测试。
当前已有 C4-03a 正式只读模型目录、C4-03b 的 auth-service 用户级策略核心，以及 C4-03c
的管理端额度/模型 API、自动 apply/readback、同步后交付、失败补偿、管理页写表单和员工
只读状态门户；C4-03d、C5 和 M2-D 已接入停用/吊销/轮换基础操作、审批、operation/audit
查询、人工对账和 CSV 导出入口，但仍缺浏览器 E2E、失败恢复入口和完整运营体验。C4-04
完整管理到真实 Magpie 策略流 E2E 已通过，但 Docker/Compose、
真实共享卷、公司反向代理和生产环境尚未实机验收。

### 10.1 信任边界

```text
浏览器员工/管理员
        |
        v
admin-service ──(只读 usage.jsonl)──> gateway data volume
        |
        | 管理会话、CSRF、RBAC、组织范围、理由、审批、幂等
        v
auth-service ──(独立 Bearer 服务令牌)──> gateway-control
                                             |
                                             | 白名单 argv，无 shell
                                             v
                          magpie gateway-key limit/models
                                             |
                                             v
                          专用 XDG_CONFIG_HOME + caller-keys.json
                                             |
                                             v
                                   回读校验结果
```

- admin-service 仍只读挂载网关数据卷，不能写 `caller-keys.json`，也不能获得网关配置目录
  的写权限。
- auth-service 持有用户级 `gatewayPolicy`、版本和 operation 状态；它不能把服务令牌、
  Gateway Key、Cookie 或管理员会话传给适配器。
- `gateway-control` 是唯一允许修改网关 Key 额度和模型范围的受控组件。它不提供任意命令、
  路径或 shell 参数执行。
- 网关 runtime、auth-service 和 `gateway-control` 不共用管理员 Cookie、OIDC Secret 或
  issuer Key。每种信任关系使用独立凭据。
- 当前 C4-02 使用独立 `GATEWAY_CONTROL_TOKEN` Bearer 服务令牌，不是 mTLS；mTLS/SPIFFE/
  工作负载身份仍是生产加固项。
- 任何参与方都不能以“写入成功”作为生效证明；只有回读结果和实际请求行为都符合目标策略
  才能进入 `known`。

### 10.2 专用服务账号与配置目录

1. 为 `gateway-control` 创建专用非 root 服务账号，例如 UID/GID 固定的
   `magpie-control`，不授予交互式登录、宿主机目录、Docker socket 或 sudo 权限。当前镜像
   使用非 root UID/GID `65532`。
2. 生产 `XDG_CONFIG_HOME` 必须是一个固定、绝对、白名单的目录；适配器启动时只接受配置中
   预置的路径，不能从 HTTP 请求、Key ID 或模型名拼接路径。
3. 目录只允许该服务账号和运维备份账号访问；`caller-keys.json` 及其锁文件只授予必需的
   写权限。管理员容器只保留 `usage.jsonl` 的只读挂载。当前 Compose 为适配器挂载完整
   `magpie-data:/config`，实机验收后应收窄为实际配置子目录或专用卷。
4. 适配器进程应使用只读根文件系统、临时 `/tmp`、`no-new-privileges`、移除全部 Linux
   capabilities，不运行在 host network，也不把 Docker API 暴露给它。
5. 测试和验收必须使用临时 `XDG_CONFIG_HOME`、临时 HOME、隔离端口和临时数据目录，禁止
   接触真实用户目录、真实企业配置或正在使用的 `127.0.0.1:3425`。
6. 如果采用“auth-service 临时直接调用 CLI”的试点方案，必须同样通过专用系统账号、
   白名单参数、超时、输出上限、日志脱敏和回读校验；不能因此绕过 C4 的部分成功和对账
   语义。

### 10.3 Compose 与网络目标

C4-02 已新增独立 profile/服务。当前 `enterprise/docker-compose.yml` 的核心配置如下：

```yaml
services:
  gateway-control:
    profiles: ["gateway-control"]
    build:
      context: ..
      dockerfile: enterprise/gateway-control/Dockerfile
    restart: unless-stopped
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    tmpfs: ["/tmp:rw,noexec,nosuid,size=16m"]
    expose: ["3446"]
    volumes:
      - magpie-data:/config
    environment:
      GATEWAY_CONTROL_TOKEN: ${GATEWAY_CONTROL_TOKEN:-}
      GATEWAY_CONTROL_MAGPIE: /usr/local/bin/magpie
      GATEWAY_CONTROL_CONFIG_HOME: /config
      GATEWAY_CONTROL_BIND: 0.0.0.0
      GATEWAY_CONTROL_PORT: 3446
      GATEWAY_CONTROL_TIMEOUT_MS: ${GATEWAY_CONTROL_TIMEOUT_MS:-10000}
```

部署要求：

- `gateway-control` 不配置宿主机 `ports`，不映射公网，不加入面向员工的入口网络。
- admin-service 只通过 auth-service 的受控接口间接发起 C4 请求；浏览器永远不能访问
  `gateway-control`。
- 当前服务间使用独立、可轮换的 `GATEWAY_CONTROL_TOKEN` Bearer 令牌，不是 mTLS；
  生产应优先升级 mTLS/SPIFFE/工作负载身份。该令牌不得复用 `AUTH_ADMIN_TOKEN`、
  `AUTH_INTERNAL_ADMIN_TOKEN`、管理员 Cookie 或 `MAGPIE_ISSUER_KEY`。
- 适配器只接受来自 auth-service 固定服务身份/网段的请求，使用请求 ID、时间戳、幂等键、
  请求体大小限制和稳定错误码；拒绝浏览器 Cookie、OIDC access token 和任意用户提供的
  命令参数。
- 出口默认拒绝；若未来需要访问网关内部 HTTP 接口，只允许固定服务地址，不能访问公网。
- 当前 Compose 使用默认服务网络，未设置 `internal: true`；生产部署前必须增加网络分段、
  NetworkPolicy/防火墙和只允许 auth-service 来源的访问控制。`.env` 令牌只适合受控试点，
  生产应改用 Secret Manager 或 Secret 文件挂载。

### 10.4 白名单调用与回读

当前公开的 `gateway-key limit <id>` 和 `gateway-key models <id>` 是面向人的文本输出，
不是管理协议。C4-01 已在企业 Magpie fork 中提供以下机器协议，C4-02 已固定复用：

```text
magpie gateway-key describe <id> --json
magpie gateway-key policy apply <id> --json
```

`describe` 只读并返回 `schemaVersion=1` 的安全策略摘要；`policy apply` 从 stdin 接收
目标模型、0-5 个额度窗口和 `expectedPolicyRevision`，在一次文件锁内原子替换并回读。
完整 schema、`policyRevision`、错误码和状态语义见
[`enterprise-feature-spec.md`](enterprise-feature-spec.md) 第 12.8.1.5 节。

`gateway-control` 只允许以下 argv 形态，不接受请求中携带的二进制路径、配置文件路径或额外
参数：

```text
<固定 magpie 路径> gateway-key describe <校验后的 key id> --json
<固定 magpie 路径> gateway-key policy apply <校验后的 key id> --json
```

执行要求：

- 使用 `execve`/等价 argv 数组，不经 shell、不做变量展开，不把 stdin 内容拼进命令行。
- `policy apply` 的 stdin 最大 64 KiB；`describe` 输出最大 64 KiB；默认 10 秒超时并杀死
  整个子进程组。超过限制一律失败关闭。
- 只接受 `schemaVersion=1`。未知主版本、重复字段、尾随 JSON、NaN/Inf、未知 Key、版本
  冲突、存储错误和回读不一致都映射为稳定错误码。
- 每次写入后必须重新执行 `describe`，比较目标模型、额度字段与 `policyRevision`；写命令
  自己返回的摘要不能代替独立回读。
- 同一 Key 和跨 Key 的写入在 v1 中串行执行；C4-04 通过真实 E2E 证明稳定性后才允许扩大
  并发。
- 日志只记录 `operationId`、`credentialId`、动作、目标策略版本、开始/结束时间、错误码和
  回读一致/不一致。不得记录完整 JSON、Gateway Key、masked key、token hash、账户 ID、
  issuer Key 或服务令牌。

不允许：

- 直接读取或修改 `caller-keys.json` 来完成变更；
- 解析 `gateway-key limit/models` 的人类可读文本作为生产成功证据；
- 用多条 `limit off`/`limit add` 模拟一次策略变更；
- 使用 shell 拼接命令、环境变量展开或把模型名当命令行选项；
- 记录完整 CLI 输出、Gateway Key、token hash、issuer Key 或服务令牌；
- 没有独立回读就声称 `known`、`synced` 或“已生效”。

回读不一致、超时、schema 不支持或输出损坏时一律保持 `pending`，交给 C5 对账。C4-02
Mock/故障测试已覆盖这些映射；真实 Docker/共享卷故障恢复仍需 C4-02 实机验收。

### 10.5 C4 故障、补偿和上线门禁

| 场景 | 必须的结果 |
| --- | --- |
| 多张活跃凭证中部分失败 | HTTP `200`，`state=partial_success`，`requiresReconciliation=true`，策略保持 `pending`，只返回安全的 `credentialId/deviceId/errorCode` |
| 全部凭证失败、适配器不可达或超时 | `502 dependency_unavailable`，不修改用户可见成功状态，保留原 `operationId` |
| 回读不一致或 CLI 输出不可解析 | 不进入 `known`，保持 `pending`，生成待对账状态 |
| result 审计不可写 | `503 audit_unavailable`，operation 保持 `dependency_invoked`，不得返回成功 |
| 管理员要求回滚 | 只能通过 C5 创建新的子 operation；默认不自动回滚，不恢复旧 Key，不绕过停用状态 |
| 旧 M1 凭证 | 额度和模型状态为 `unknown`，不得反推历史值或显示为 0/无限/默认值 |

上线门禁：

- C4-02 未完成 Docker/真实共享卷验收前，C4-03c/C4-03d 不得接触真实员工凭证。
- C4-03a 虽已有坏目录失败关闭测试，但真实部署尚未验收；只能作为管理端只读目录和稳定模型
  ID 展开来源，不得把 `ADMIN_MODELS` 或管理端返回值扩展成真实员工授权事实来源。
- C4-03b/C4-03c 虽已在本地证明旧 M1 `unknown`、分步首次初始化、回读确认、同步后交付和
  失败补偿，但真实共享卷、真实 Magpie 和真实 IdP 尚未验收；在完整链路通过前，不得让生产
  join/refresh/rotate 消费策略。
- C4-03c 未在真实环境证明 apply、独立回读、持久化完成前不交付 Key，以及崩溃后无孤儿 Key 前，
  不得向员工签发企业凭证。
- C4-04 已通过隔离真实 Magpie E2E；C4-03d、C5 和 M2-D 的基础页面与导出入口已实现，但
  浏览器 E2E、恢复入口、完整运营体验和生产验收未通过前不得宣布生产完成。
- 真实 E2E 已证明双设备独立 Key 的额度/模型实际变化、真实限流和模型拒绝、回读一致、
  refresh/rotate 继承策略、`pending` 时失败关闭、部分失败和恢复同步；管理容器不能写网关卷
  仍须在真实 Docker/共享卷部署中验收。
- 任何“页面值已变但实际请求未被限制/未被拒绝”的结果都视为 C4 失败。
- C4-01 机器协议和 C4-02 `gateway-control` 已实现；C4-02 通过 15 项 Mock/故障测试，
  但 Docker/Compose、真实共享卷、健康检查和故障恢复尚未实机验收。C4-03a 正式只读目录
  已通过 7 项目录专项；管理服务当前 109 项通过（含 7 项通知渠道、7 项通知规则和 6 项 SIEM 专项），
  但仍待真实部署验收。
  C4-03b/C4-03c 已接通本地 Mock/故障链路，C4-04 完整管理链路 E2E 已通过；C4-03d、C5
  和 M2-D 核心已实现，基础查询、对账和导出页面已接入，但浏览器 E2E、失败恢复入口和
  生产验收未完成，不得把本节或隔离 E2E 当作完整生产部署闭环。

---

注：本文件只描述方案和示例，不修改仓库上游文件。分支保护、MDM、内部模型网关等需要在 GitHub 网页或公司系统里实际操作。
