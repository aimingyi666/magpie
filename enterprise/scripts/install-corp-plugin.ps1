<#
.SYNOPSIS
Install the Magpie corp plugin for an employee machine (MDM / software center).

.DESCRIPTION
Quietly installs enterprise/corp-plugin into the current user's magpie,
writes the corporate server address, and sets MAGPIE_CORP_URL / MAGPIE_BIN
so the employee only needs to open magpie and click Sign in.

This does not sign the employee in, does not overwrite hand-added providers,
and does not sync the resource library until Sign in + Sync.

.EXAMPLE
.\install-corp-plugin.ps1 -CorpUrl https://control.corp.example

.EXAMPLE
.\install-corp-plugin.ps1 `
  -CorpUrl https://control.corp.example `
  -Magpie "C:\Program Files\Magpie\magpie.exe" `
  -PluginPath "C:\Program Files\Magpie\plugins\corp-plugin"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CorpUrl,
    [string]$Magpie = "magpie",
    [string]$PluginPath,
    [string]$Provider = "corp",
    [string]$PluginName = "magpie-corp-plugin",
    [switch]$MachineEnv,
    [switch]$SkipPluginAdd,
    [switch]$SkipOptions
)

$ErrorActionPreference = "Stop"

function Resolve-MagpiePath {
    param([Parameter(Mandatory = $true)][string]$Candidate)

    if ([System.IO.Path]::IsPathRooted($Candidate) -and (Test-Path -LiteralPath $Candidate)) {
        return (Resolve-Path -LiteralPath $Candidate).Path
    }

    $command = Get-Command $Candidate -ErrorAction SilentlyContinue
    if ($command -and $command.Source) {
        return $command.Source
    }

    throw "magpie not found: $Candidate (set -Magpie or MAGPIE_BIN)"
}

function Assert-HttpsOrLoopback {
    param([Parameter(Mandatory = $true)][string]$Url)

    $trimmed = $Url.Trim().TrimEnd("/")
    try {
        $uri = [uri]$trimmed
    } catch {
        throw "CorpUrl is not a URL: $Url"
    }

    $loopback = @("127.0.0.1", "localhost", "::1") -contains $uri.Host
    if ($uri.Scheme -eq "https") {
        return $trimmed
    }
    if ($uri.Scheme -eq "http" -and $loopback) {
        return $trimmed
    }
    throw "CorpUrl must be https:// (or http:// on loopback): $Url"
}

function Set-EnvPersistent {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value,
        [switch]$Machine
    )

    $target = if ($Machine) {
        [System.EnvironmentVariableTarget]::Machine
    } else {
        [System.EnvironmentVariableTarget]::User
    }
    [System.Environment]::SetEnvironmentVariable($Name, $Value, $target)
    Set-Item -Path "Env:$Name" -Value $Value
}

function Write-CorpConfig {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$ProviderId
    )

    $dir = if ($env:MAGPIE_CORP_DIR) {
        $env:MAGPIE_CORP_DIR
    } elseif ($IsWindows -or $env:OS -match "Windows") {
        Join-Path $env:LOCALAPPDATA "MagpieCorp"
    } else {
        Join-Path $HOME ".local/state/magpie-corp"
    }

    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $file = Join-Path $dir "corp.json"
    $body = [ordered]@{
        baseUrl  = $BaseUrl
        provider = $ProviderId
        oidc     = $null
        upload   = [ordered]@{
            usage     = $true
            masking   = $true
            sessions  = $true
            minSeconds = 60
        }
    }
    $json = ($body | ConvertTo-Json -Depth 5) + "`n"
    $temporary = "$file.$([guid]::NewGuid().ToString('N')).tmp"
    [System.IO.File]::WriteAllText($temporary, $json, [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $file -Force
    return $file
}

if (-not $PluginPath) {
    $PluginPath = Join-Path $PSScriptRoot "..\corp-plugin"
}
$PluginPath = [System.IO.Path]::GetFullPath($PluginPath)
if (-not (Test-Path -LiteralPath (Join-Path $PluginPath "package.json"))) {
    throw "plugin package not found at $PluginPath"
}

$corpUrl = Assert-HttpsOrLoopback -Url $CorpUrl
$magpiePath = Resolve-MagpiePath -Candidate $Magpie

Write-Host "magpie: $magpiePath"
Write-Host "plugin: $PluginPath"
Write-Host "server: $corpUrl"

Set-EnvPersistent -Name "MAGPIE_BIN" -Value $magpiePath -Machine:$MachineEnv
Set-EnvPersistent -Name "MAGPIE_CORP_URL" -Value $corpUrl -Machine:$MachineEnv

$configFile = Write-CorpConfig -BaseUrl $corpUrl -ProviderId $Provider
Write-Host "wrote $configFile"

if (-not $SkipPluginAdd) {
    Write-Host "installing plugin..."
    & $magpiePath plugin add $PluginPath
    if ($LASTEXITCODE -ne 0) {
        throw "magpie plugin add failed with exit $LASTEXITCODE"
    }
}

if (-not $SkipOptions) {
    $options = @{ baseUrl = $corpUrl; provider = $Provider } | ConvertTo-Json -Compress
    Write-Host "setting plugin options..."
    & $magpiePath plugin options $PluginName $options
    if ($LASTEXITCODE -ne 0) {
        Write-Host "WARNING: could not set plugin options for $PluginName (exit $LASTEXITCODE)"
        Write-Host "MAGPIE_CORP_URL and corp.json are already set; Sign in will still work."
    }
}

Write-Host ""
Write-Host "PASS  corp plugin is ready on this machine"
Write-Host "Next: open magpie → sidebar「企业」→ Sign in → Sync now"
Write-Host "The employee does not need PowerShell after this."
