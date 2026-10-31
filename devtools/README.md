# 二开规则（Fork 开发规范）

本仓库是 yetone/magpie 的 fork：`main` 会被 GitHub Actions「同步上游」每小时自动合并上游代码。所以 `main` 不是普通开发分支，不能直接在上面改代码。

## 三条铁律

1. **main 归同步管**：不要直接改 main、不要直接推 main。
2. **新功能必开分支**：功能一律在 `feat/功能名` 分支上开发，可以同时开多个互不干扰。
3. **从最新 main 出发**：用本目录的工具开分支，保证起点与上游最新一致。

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

- 自动做四件事：先把功能分支推到 GitHub 备份；切回 main 并同步；合并功能；推送 main。
- 只有这个脚本能推送 main（内部走白名单）。手动 `git push origin main` 会被钩子拦下。

## 防护钩子（pre-push）

仓库已配置 `core.hooksPath = devtools/hooks`，规则由钩子强制执行：

- 直接 `git push origin main` → 被拦下，提示改用上面的脚本。
- 推送 `feat/*` 等其它分支 → 正常放行。
- 确需绕过（例如紧急修复）：`MAGPIE_MAIN_OK=1 git push origin main`，或 `git push --no-verify`。请慎用。

## 为什么这样能避免和 main 冲突

- 每个功能都基于「最新的 main」独立开分支，互相独立，也能并行开发。
- main 只做一件事：自动吸收上游。你的功能合入 main 后，上游的新提交会作为合并提交继续自动合入。
- 真冲突只可能发生在「你改的代码恰好也是上游最近改的代码」。此时 `update-feature` 会在你的功能分支里提前把它暴露出来，那是最可控的解决时机。

## 给 Codex / AI 助手的提示

- 本项目是 fork：**永远不要**把改动直接提交到 main 或推送 main。
- 新功能先运行 `devtools\new-feature.cmd 名字`，收尾运行 `devtools\finish-feature.cmd`。
- main 是自动同步分支；遇到冲突先 `devtools\update-feature.cmd`。
- 所有 PowerShell 命令必须用 `D:\Environment\PowerShell-7.6.6-win-x64\pwsh.exe` 执行（见根目录 AGENTS.md）。
