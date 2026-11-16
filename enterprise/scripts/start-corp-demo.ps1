<#
.SYNOPSIS
Start a local Magpie Corp demo that the native magpie corp-plugin can join.

.DESCRIPTION
Starts an isolated enterprise gateway (magpie serve) and corp-server in demo
mode, seeds a sample resource bundle, and points this user's MagpieCorp
config at the local control plane. Your everyday magpie stays the client;
this script does not replace its install.

After it prints PASS:
1. Open your normal magpie → sidebar「企业」→ Sign in
2. For a second identity, Sign in again with another demo email
3. Admin data is at http://127.0.0.1:<corpPort>/__admin/summary

.EXAMPLE
.\enterprise\scripts\start-corp-demo.ps1
#>
[CmdletBinding()]
param(
    [string]$Magpie = $(if (Test-Path "$env:TEMP\magpie-corp-test.exe") { "$env:TEMP\magpie-corp-test.exe" } else { "magpie" }),
    [string]$Node = "node",
    [int]$CorpPort = 3600,
    [string]$WorkRoot,
    # Optional: the gateway's WorkBuddy plugin, so the demo has an account to
    # share. A local checkout/package directory, or a package magpie can add.
    # Also read from $env:CORP_WORKBUDDY_PLUGIN.
    [string]$WorkbuddyPlugin = $env:CORP_WORKBUDDY_PLUGIN
)

$ErrorActionPreference = "Stop"

if (-not $WorkRoot) {
    $WorkRoot = Join-Path $env:TEMP "magpie-corp-demo"
}
$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
$gatewayHome = Join-Path $WorkRoot "gateway-home"
$corpState = Join-Path $WorkRoot "corp-state.json"
$pidFile = Join-Path $WorkRoot "demo.pids.json"
$tokenFile = Join-Path $WorkRoot "admin-token.txt"
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
$corpServer = Join-Path $repoRoot "enterprise\corp-server\src\server.mjs"
$runServer = Join-Path $repoRoot "enterprise\test\corp-e2e-run-server.mjs"

if (-not (Test-Path -LiteralPath $corpServer)) {
    throw "corp-server not found: $corpServer"
}

function Resolve-Bin {
    param([string]$Candidate)
    if ([System.IO.Path]::IsPathRooted($Candidate) -and (Test-Path -LiteralPath $Candidate)) {
        return (Resolve-Path -LiteralPath $Candidate).Path
    }
    $cmd = Get-Command $Candidate -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { return $cmd.Source }
    throw "command not found: $Candidate"
}

function New-AdminToken {
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return ([Convert]::ToBase64String($bytes) -replace '[+/=]', 'x')
}

function Wait-HttpOk {
    param([string]$Url, [int]$Seconds = 20)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
            if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) { return $true }
        } catch {
            Start-Sleep -Milliseconds 300
        }
    }
    return $false
}

function Get-ListenPorts {
    param([int]$ProcessId)
    Get-NetTCPConnection -OwningProcess $ProcessId -State Listen -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty LocalPort -Unique
}

$magpiePath = Resolve-Bin $Magpie
$nodePath = Resolve-Bin $Node
New-Item -ItemType Directory -Path $gatewayHome -Force | Out-Null

if (Test-Path -LiteralPath $pidFile) {
    try {
        $old = Get-Content -Raw -LiteralPath $pidFile | ConvertFrom-Json
        foreach ($id in @($old.gatewayPid, $old.corpPid)) {
            if ($id) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }
        }
    } catch {}
}

$adminToken = New-AdminToken
Set-Content -LiteralPath $tokenFile -Value $adminToken -Encoding ascii

$seed = [ordered]@{
    version = 1
    devices = @{}
    users = @{}
    bundleRevision = "rev_demo_1"
    bundles = [ordered]@{
        rev_demo_1 = [ordered]@{
            schemaVersion = 1
            revision = "rev_demo_1"
            providers = @(
                [ordered]@{
                    id = "corp"
                    name = "企业网关"
                    mode = "gateway"
                    baseUrl = "http://127.0.0.1:3499/v1"
                    npm = "@ai-sdk/openai-compatible"
                    models = @("deepseek-v4-pro", "deepseek-flash")
                    defaultModel = "deepseek-v4-pro"
                    enabled = $true
                }
            )
            instructions = @(
                [ordered]@{
                    id = "ins_corp"
                    title = "公司规范"
                    content = "# 公司 AI 使用规范`n`n- 不上传客户隐私`n- 优先使用企业网关模型`n"
                    agents = @("*")
                    enabled = $true
                }
            )
            mcp = @(
                [ordered]@{
                    name = "corp-kb"
                    transport = "http"
                    url = "https://mcp.corp.example/kb"
                    agents = @("*")
                    enabled = $true
                }
            )
            skills = @(
                [ordered]@{
                    name = "corp-report"
                    agents = @("*")
                    enabled = $true
                    files = @(
                        [ordered]@{ path = "SKILL.md"; content = "# 企业周报`n`n按模板汇总本周进展。`n" }
                    )
                }
            )
        }
    }
    usage = @()
    masking = @()
}
Set-Content -LiteralPath $corpState -Value (($seed | ConvertTo-Json -Depth 10) + "`n") -Encoding utf8

Write-Host "starting isolated enterprise gateway..."
$oldEnv = @{}
$gatewayEnv = @{
    MAGPIE_HOME = $gatewayHome
    MAGPIE_CONFIG_DIR = (Join-Path $gatewayHome "magpie")
    MAGPIE_STATE_DIR = $gatewayHome
    MAGPIE_ADDR = "127.0.0.1:0"
    MAGPIE_ADMIN_ADDR = "127.0.0.1:0"
    MAGPIE_ADMIN_TOKEN = $adminToken
}
foreach ($k in $gatewayEnv.Keys) {
    $oldEnv[$k] = [System.Environment]::GetEnvironmentVariable($k, "Process")
    Set-Item -Path "Env:$k" -Value $gatewayEnv[$k]
}
try {
    if ($WorkbuddyPlugin) {
        # The isolated gateway starts with an empty MAGPIE_HOME, so it has no
        # WorkBuddy plugin unless one is installed here. Installing before
        # serve starts means the plugin host loads it on the first run.
        $pluginSpec = if (Test-Path -LiteralPath $WorkbuddyPlugin) {
            (Resolve-Path -LiteralPath $WorkbuddyPlugin).Path
        } else {
            $WorkbuddyPlugin
        }
        Write-Host "installing the WorkBuddy plugin into the demo gateway..."
        & $magpiePath plugin add $pluginSpec | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "WorkBuddy plugin install failed; the share button will answer workbuddy_unavailable"
        }
    }
    $gatewayProc = Start-Process -FilePath $magpiePath -ArgumentList @("serve") -WorkingDirectory $WorkRoot -WindowStyle Hidden -PassThru
} finally {
    foreach ($k in $oldEnv.Keys) {
        if ($null -eq $oldEnv[$k] -or $oldEnv[$k] -eq "") {
            Remove-Item -Path "Env:$k" -ErrorAction SilentlyContinue
        } else {
            Set-Item -Path "Env:$k" -Value $oldEnv[$k]
        }
    }
}

Start-Sleep -Seconds 2
if ($gatewayProc.HasExited) {
    throw "enterprise gateway exited early (pid $($gatewayProc.Id))"
}

$ports = @()
for ($i = 0; $i -lt 40 -and $ports.Count -lt 2; $i++) {
    Start-Sleep -Milliseconds 250
    $ports = @(Get-ListenPorts -ProcessId $gatewayProc.Id)
}
if ($ports.Count -lt 2) {
    throw "enterprise gateway did not open listen ports"
}

$adminPort = $null
$gatewayPort = $null
foreach ($p in $ports) {
    try {
        $h = Invoke-WebRequest -Uri "http://127.0.0.1:$p/healthz" -UseBasicParsing -TimeoutSec 2
        if ($h.Content -match "magpie-admin") { $adminPort = $p; continue }
    } catch {}
    try {
        $m = Invoke-WebRequest -Uri "http://127.0.0.1:$p/v1/models" -UseBasicParsing -TimeoutSec 2
        if ($m.StatusCode -eq 200) { $gatewayPort = $p }
    } catch {}
}
if (-not $adminPort -or -not $gatewayPort) {
    throw "could not detect gateway/admin ports from $($ports -join ',')"
}

$gatewayPublic = "http://127.0.0.1:$gatewayPort/v1"
$gatewayAdmin = "http://127.0.0.1:$adminPort"

$seedObj = Get-Content -Raw -LiteralPath $corpState | ConvertFrom-Json
$seedObj.bundles.rev_demo_1.providers[0].baseUrl = $gatewayPublic
Set-Content -LiteralPath $corpState -Value (($seedObj | ConvertTo-Json -Depth 12) + "`n") -Encoding utf8

Write-Host "starting corp-server on $CorpPort..."
$corpEnv = @{
    CORP_PORT = "$CorpPort"
    CORP_STATE_FILE = $corpState
    CORP_GATEWAY_ADMIN_URL = $gatewayAdmin
    CORP_GATEWAY_ADMIN_TOKEN = $adminToken
    CORP_GATEWAY_PUBLIC_URL = $gatewayPublic
    CORP_PUBLIC_URL = "http://127.0.0.1:$CorpPort"
    CORP_ALLOW_DEMO_SIGNIN = "true"
    CORP_NAME = "演示公司"
}
foreach ($k in $corpEnv.Keys) { Set-Item -Path "Env:$k" -Value $corpEnv[$k] }
$corpProc = Start-Process -FilePath $nodePath -ArgumentList @($runServer) -WorkingDirectory $repoRoot -WindowStyle Hidden -PassThru

if (-not (Wait-HttpOk -Url "http://127.0.0.1:$CorpPort/api/v1/corp/config" -Seconds 20)) {
    throw "corp-server did not become ready on $CorpPort"
}

$corpDir = if ($env:MAGPIE_CORP_DIR) { $env:MAGPIE_CORP_DIR } else { Join-Path $env:LOCALAPPDATA "MagpieCorp" }
New-Item -ItemType Directory -Path $corpDir -Force | Out-Null
$corpJson = Join-Path $corpDir "corp.json"
$clientCfg = [ordered]@{
    baseUrl = "http://127.0.0.1:$CorpPort"
    provider = "corp"
    oidc = $null
    upload = [ordered]@{ usage = $true; masking = $true; sessions = $true; minSeconds = 60 }
}
Set-Content -LiteralPath $corpJson -Value (($clientCfg | ConvertTo-Json -Depth 5) + "`n") -Encoding utf8
[System.Environment]::SetEnvironmentVariable("MAGPIE_CORP_URL", "http://127.0.0.1:$CorpPort", "User")
[System.Environment]::SetEnvironmentVariable("MAGPIE_BIN", $magpiePath, "User")
$env:MAGPIE_CORP_URL = "http://127.0.0.1:$CorpPort"
$env:MAGPIE_BIN = $magpiePath

$pluginSpec = Join-Path $repoRoot "enterprise\corp-plugin"
try {
    $options = (@{ baseUrl = "http://127.0.0.1:$CorpPort"; provider = "corp" } | ConvertTo-Json -Compress)
    & magpie plugin options $pluginSpec $options 2>$null | Out-Null
} catch {}

@{ gatewayPid = $gatewayProc.Id; corpPid = $corpProc.Id; adminPort = $adminPort; gatewayPort = $gatewayPort; corpPort = $CorpPort } |
    ConvertTo-Json | Set-Content -LiteralPath $pidFile -Encoding utf8

Write-Host ""
Write-Host "PASS  local corp demo is up"
Write-Host "  gateway     $gatewayPublic"
Write-Host "  admin API   $gatewayAdmin"
Write-Host "  corp-server http://127.0.0.1:$CorpPort"
Write-Host "  admin view  http://127.0.0.1:$CorpPort/__admin/summary"
Write-Host "  client cfg  $corpJson"
Write-Host ""
Write-Host "员工登录（原生 magpie）"
Write-Host "  1. 打开你正在用的 magpie（侧边栏应有「企业」）"
Write-Host "  2. 点 Sign in"
Write-Host "  3. demo 授权码: demo:alice@corp.example"
Write-Host "     第二个账号: demo:bob@corp.example"
Write-Host "  4. 回 magpie 点 Sync now"
Write-Host ""
Write-Host "管理员查看数据"
Write-Host "  浏览器打开: http://127.0.0.1:$CorpPort/__admin/summary"
Write-Host "  可见 devices / usage / masking / resources / workbuddy"
Write-Host ""
if ($WorkbuddyPlugin) {
    Write-Host "共享 WorkBuddy"
    Write-Host "  概览页 → 共享 WorkBuddy → 国内版/国际版 → 扫码登录"
    Write-Host "  账号导入后 /__admin/summary 的 workbuddy.imported 会列出模型"
} else {
    Write-Host "共享 WorkBuddy 需要网关装 WorkBuddy 插件："
    Write-Host "  重跑本脚本时加 -WorkbuddyPlugin <插件目录|包名>，或设 CORP_WORKBUDDY_PLUGIN"
}
Write-Host ""
Write-Host "停止: Stop-Process -Id $($gatewayProc.Id),$($corpProc.Id)"
