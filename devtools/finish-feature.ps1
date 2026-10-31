# 功能收尾：推送功能分支 → 合并进 main → 推送 main（唯一合法的 main 直推路径）
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$branch = git branch --show-current
if ($branch -eq 'main') {
    Write-Host '当前已在 main。finish-feature 请在功能分支上运行。' -ForegroundColor Yellow
    exit 1
}
if ($branch -notlike 'feat/*') {
    Write-Host "当前分支 [$branch] 不是 feat/ 功能分支。" -ForegroundColor Yellow
    exit 1
}

$dirty = git status --porcelain
if ($dirty) {
    Write-Host '功能分支还有未提交的改动，请先提交：' -ForegroundColor Yellow
    $dirty
    exit 1
}

# 1. 先把功能分支推到 GitHub 备份，避免合并失败丢工作
git push -u origin $branch
if ($LASTEXITCODE -ne 0) { Write-Host '推送功能分支失败。' -ForegroundColor Red; exit 1 }

# 2. 回 main，并先与远端对齐
git fetch origin main
if ($LASTEXITCODE -ne 0) { Write-Host '拉取 origin 失败（网络/代理问题？）' -ForegroundColor Red; exit 1 }
git switch main
if ($LASTEXITCODE -ne 0) { exit 1 }
git merge --ff-only origin/main
if ($LASTEXITCODE -ne 0) {
    Write-Host '本地 main 与远端不一致（可能有没推送的本地提交），请先处理。' -ForegroundColor Red
    git switch $branch
    exit 1
}

# 3. 合并功能分支
git merge --no-edit $branch
if ($LASTEXITCODE -ne 0) {
    Write-Host "合并 [$branch] 到 main 冲突。请先运行 devtools\update-feature.cmd，把 main 合并进功能分支解决冲突后再来。" -ForegroundColor Red
    git switch $branch
    exit 1
}

# 4. 推送 main（钩子只放行带白名单环境变量的推送）
$env:MAGPIE_MAIN_OK = '1'
git push origin main
$pushCode = $LASTEXITCODE
Remove-Item Env:MAGPIE_MAIN_OK -ErrorAction SilentlyContinue
if ($pushCode -ne 0) { Write-Host '推送 main 失败。' -ForegroundColor Red; exit 1 }

Write-Host ''
Write-Host "✔ [$branch] 已合并进 main 并推送到 GitHub。" -ForegroundColor Green
Write-Host '   功能分支已保留备份（本地 + 远程）。确认稳定后可自行删除：'
Write-Host "   git branch -d $branch; git push origin --delete $branch"
