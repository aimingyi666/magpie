# 企业版漂移处理与确认方案

状态：执行版 v1，2026-11-06
适用范围：`enterprise/`、插件页面、相关文档与分支。上游 `main` 的发布节奏不在此列。

## 1. 什么是漂移

| 类型 | 判定 |
| --- | --- |
| 分支漂移 | 本地分支既不是 `main` 的祖先，也没有作为唯一集成分支被登记 |
| 工作区漂移 | 未提交的文件没有明确归属，或同一 checkout 有两个会话在写 |
| 环境漂移 | 存在无人认领的 worktree、游离 HEAD、临时文件 |
| 架构漂移 | 同一能力有两套实现（服务端 HTML 控制台 / 客户端插件页面） |
| 文档漂移 | `enterprise-implementation-status.md` 与代码、测试证据不一致 |

## 2. 台账（2026-11-06）

### 2.1 分支

- 本地分支 **42** 个，远程 **42** 个。
- **40 个已并入 `main`**（分支 tip 是 `main` 的祖先），属历史遗留，可清理。
- 只有 **2 个**未并入：

| 分支 | 领先 main | 落后 main | 定位 |
| --- | --- | --- | --- |
| `codex/m4-b-content-audit-core`（当前） | 6 | 382 | 企业原生管理模式、M4-B、插件页面 |
| `codex/enterprise-console-ui` | 3 | 0 | 服务端渲染控制台/员工门户（本地化、可访问性、charts） |

### 2.2 工作区

当前 16 项未提交：11 个修改 + 5 个未跟踪（`providers-panel.*`、`theme-bridge.js`、本计划、`envtest.txt`）。
`envtest.txt` 内容为 `hello-env-inherited`，是测试留下的临时文件。

### 2.3 环境

3 个 worktree：

- `C:/Users/AiMingYi/Desktop/magpie` → 当前分支；
- `C:/Users/AiMingYi/.codex/worktrees/m4b-store/magpie` → `codex/enterprise-console-ui`，属另一个会话；
- `C:/Users/AiMingYi/.codex/worktrees/m4b-redaction/magpie` → 游离 HEAD `055220684`，无人认领。

### 2.4 架构与文档

- 两套界面：console-ui 的 `admin-template.html` / `portal-template.html`，与插件 `page/ui.html`。
- 状态文档有多处按旧分支写的“已完成/未实现”，与当前代码不一致。

## 3. 唯一事实源

| 对象 | 唯一来源 |
| --- | --- |
| 上游代码 | `origin/main` |
| 企业集成分支 | `codex/m4-b-content-audit-core`（试点结束前不改名，避免又开一条线） |
| 界面 | `enterprise/magpie-plugin` 客户端插件页面；服务端只出 JSON |
| 事实状态 | `enterprise-implementation-status.md` |
| 计划 | `enterprise-pilot-plan.md` |
| 分支清理 | 只有 `main` 的祖先可以删除 |

**console-ui 的处理**：冻结，不再演进；只把它的本地化文案、可访问性和 `charts.js` 移植进插件页面，页面宿主（两个 template）删除或归档。

## 4. 处理顺序

### D0 归属确认（今天）

- 确认 `internal/gui/{pluginpage.go}`、`internal/plugin/page.go`、`internal/gui/assets/index.html`、`providers-panel.*` 是谁的改动。
- 认领的会话负责提交；无人认领的进第 4.1 节的切片。
- 删除 `envtest.txt`。

### D1 工作区切片提交

| 切片 | 文件 | 提交信息 |
| --- | --- | --- |
| 1 插件页面 | `enterprise/magpie-plugin/page/*`、`src/service.mjs`、`test/*`、`package.json` | `feat(enterprise): draw the enterprise page in the client` |
| 2 页面挂载点 | `internal/plugin/page.go`、`internal/gui/pluginpage.go`、`internal/gui/assets/index.html` | `feat(gui): host a plugin's page in the window` |
| 3 测试补钉 | `internal/access/patch_test.go` | `test(access): cover patch-key's one-write contract` |
| 4 文档 | `devtools/enterprise-*.md` | `docs(enterprise): record the pilot plan and drift rules` |

每个切片单独跑对应测试，body 写清“改了什么、跑了什么、没试什么”。

### D2 合并 main

```bash
git switch codex/m4-b-content-audit-core
git fetch origin
git merge --no-ff origin/main
```

冲突处理口径：

- `admin-service/src/{approval,config,service}.js`：以 `main` 的 M9–M11 为基础，保留本分支的 bootstrap 修复与原生管理代理；
- `docker-compose.yml`、`.env.example`、两份 README：取并集；
- `devtools/enterprise-*.md`：以本分支的试点计划和状态表为准，补进 main 的新增章节；
- 合并后重跑九套企业回归与 `go test ./internal/gui/...`。

### D3 console-ui 冻结

- 在该分支的会话里停止 UI 开发；
- 把 `admin-app.js` 的本地化词表、`charts.js`、可访问性属性移植到插件页面（单独提交）；
- 两个 `*-template.html` 删除；`employee-portal` 保留为服务端 API，不保留页面。

### D4 清理已合并分支

确认 D1–D3 完成后：

```bash
git branch --merged main | grep -v '^\*' | xargs -n1 git branch -d
```

只删本地；远程分支保留，防止误删他人工作。40 个分支之外若有人认领，先移出清单。

### D5 文档对齐

- 状态文档按“代码 + 测试证据”重写阶段表，删除按旧分支写的“已实现”；
- `enterprise-pilot-plan.md` 的排期与本次合并后的实际状态对齐；
- 两处同时改，避免又出现“文档说做了、代码没做”。

## 5. 确认门禁

每次声称“漂移处理完成”，逐条给出结果：

| 门禁 | 检查 | 通过标准 |
| --- | --- | --- |
| G0 工作区 | `git status --porcelain` | 空 |
| G1 分支 | 未并入 main 的分支 | 只剩集成分支与 console-ui（冻结中） |
| G2 合并 | `git merge-tree --write-tree HEAD main` | 无 `CONFLICT` |
| G3 企业回归 | 九套 `node --test` + `go test ./internal/gateway ./internal/access` | 全绿，记录条数 |
| G4 插件页 | `node --test enterprise/magpie-plugin/test/*.test.mjs` | 全绿 |
| G5 格式 | `gofmt -l`、`git diff --check` | 无输出 |
| G6 环境 | `git worktree list` | ≤2 个，且每个有归属 |
| G7 文档 | 状态表抽查 3 项 | 与代码一致 |

`devtools/check-drift.ps1` 自动检查 G0、G1、G2、G6；其余人工记录。

## 6. 每周检查

每周第一个工作日运行：

```powershell
pwsh -File devtools/check-drift.ps1
```

输出贴进本文件第 7 节，注明日期、HEAD、结果。任何一条不过，当周不新增功能，先还债。

## 7. 检查记录

| 日期 | HEAD | G0 | G1 | G2 | G6 | 备注 |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-11-06 | `c7010e496` | 否（16 项） | 否（2 个未并入） | 否（13 个冲突） | 否（3 个 worktree） | 首次记录 |
| 2026-11-06 | `7365d22a7` | 否（3 项，均为其他会话新建） | 否（console-ui 未冻结） | ✅ 无冲突 | 否（3 个 worktree） | 合并 main 完成；十套企业回归 460 项通过 |

## 8. 需要拍板

1. `codex/enterprise-console-ui` 是否冻结（推荐：是）。
2. 是否本周执行 D2 合并 `main`（推荐：是，先切片提交再合）。
3. 是否删除 40 个已并入 `main` 的本地分支（推荐：是，远程保留）。
4. `envtest.txt` 是否直接删除（推荐：是）。
5. 游离 worktree `m4b-redaction` 由谁认领；无人认领则移除。
