# 把 origin/main 与 upstream/main 的最新代码合并进当前功能分支
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$branch = git branch --show-current
if ($branch -eq 'main') {
    Write-Host '当前就在 main 上。main 由定时同步管理，不要在 main 上做这个操作。' -ForegroundColor Yellow
    exit 0
}
if ($branch -notlike 'feat/*') {
    Write-Host "当前分支 [$branch] 不是 feat/ 功能分支，update-feature 只在功能分支使用。" -ForegroundColor Yellow
    exit 1
}

$dirty = git status --porcelain
if ($dirty) {
    Write-Host '请先提交或 git stash 当前改动：' -ForegroundColor Yellow
    $dirty
    exit 1
}

Write-Host '拉取并合并最新代码到当前功能分支...' -ForegroundColor Cyan
git fetch origin main
if ($LASTEXITCODE -ne 0) { Write-Host '拉取 origin 失败（网络/代理问题？）' -ForegroundColor Red; exit 1 }
git fetch upstream main
if ($LASTEXITCODE -ne 0) { Write-Host '拉取 upstream 失败（网络/代理问题？）' -ForegroundColor Red; exit 1 }

git merge --no-edit origin/main
if ($LASTEXITCODE -ne 0) {
    Write-Host 'origin/main 与当前分支冲突——请在此功能分支内解决冲突后再继续（比在 main 上解决安全）。' -ForegroundColor Red
    exit 1
}
git merge --no-edit upstream/main
if ($LASTEXITCODE -ne 0) {
    Write-Host 'upstream/main 与当前分支冲突——同上，请在功能分支内解决。' -ForegroundColor Red
    exit 1
}

Write-Host "✔ $branch 已同步到最新，可以继续开发。" -ForegroundColor Green
