# 新建功能分支：从最新 main 创建 feat/<功能名>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Name
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$feature = ($Name.ToLower() -replace '[^a-z0-9_-]', '-').TrimStart('-').TrimEnd('-')
if ($feature -eq '') {
    Write-Host '功能名无效，例如: devtools\new-feature.cmd 我的功能' -ForegroundColor Red
    exit 1
}
$branch = "feat/$feature"

if (git branch --list $branch) {
    Write-Host "分支已存在: $branch，换个名字或切换过去继续开发。" -ForegroundColor Yellow
    exit 1
}

$dirty = git status --porcelain
if ($dirty) {
    Write-Host '当前有未提交的改动，请先提交或 git stash，否则会被带进新分支：' -ForegroundColor Yellow
    $dirty
    exit 1
}

Write-Host '拉取最新代码（origin + upstream）...' -ForegroundColor Cyan
git fetch origin
if ($LASTEXITCODE -ne 0) { Write-Host '拉取 origin 失败（网络/代理问题？）' -ForegroundColor Red; exit 1 }
git fetch upstream
if ($LASTEXITCODE -ne 0) { Write-Host '拉取 upstream 失败（网络/代理问题？）' -ForegroundColor Red; exit 1 }

git switch main
if ($LASTEXITCODE -ne 0) { exit 1 }

git merge --ff-only origin/main
if ($LASTEXITCODE -ne 0) {
    Write-Host '本地 main 与远端不一致（可能有没推送的本地提交），请先处理或运行 devtools\finish-feature.cmd。' -ForegroundColor Red
    exit 1
}

git merge --no-edit upstream/main
if ($LASTEXITCODE -ne 0) {
    Write-Host 'main 合并上游冲突。可稍等定时同步处理，或先手工解决 main 的冲突。' -ForegroundColor Red
    exit 1
}

git switch -c $branch
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host ''
Write-Host "✔ 新功能分支已创建：$branch" -ForegroundColor Green
Write-Host '   开发完成后运行: devtools\finish-feature.cmd'
Write-Host '   中途同步上游:   devtools\update-feature.cmd'
