<#
.SYNOPSIS
Join this computer's magpie to an enterprise gateway.

.DESCRIPTION
Adds (or updates) an OpenAI-compatible provider that points at the enterprise
gateway, using the employee's own gateway key. Agents keep pointing at the
local magpie, so magpie's one-click agent configuration still works.

The key is passed to the local magpie only; it is never printed. Use -KeyFile
instead of -Key from enterprise-join.ps1 or an MDM script so the key does not
appear in a process command line.

.EXAMPLE
.\join-client.ps1 -Magpie magpie -GatewayUrl http://gateway.corp.example:3425 -Key <key> -Models "deepseek/deepseek-chat"

.EXAMPLE
.\join-client.ps1 -Magpie magpie -GatewayUrl https://ai.corp.example -Key <key> -Agent claude -AgentModel deepseek/deepseek-chat

.EXAMPLE
.\join-client.ps1 -Magpie magpie -GatewayUrl https://ai.corp.example -KeyFile C:\secure\gateway-key.txt
#>
[CmdletBinding(DefaultParameterSetName = "Key")]
param(
    [string]$Magpie = "magpie",
    [Parameter(Mandatory = $true)][string]$GatewayUrl,
    [Parameter(Mandatory = $true, ParameterSetName = "Key")][string]$Key,
    [Parameter(Mandatory = $true, ParameterSetName = "KeyFile")][string]$KeyFile,
    [string]$ProviderName = "Enterprise Gateway",
    [string]$ProviderId,
    [string]$Models,
    [string]$Agent,
    [string]$AgentModel,
    [switch]$SkipTest
)

$ErrorActionPreference = "Stop"

function Format-MagpieArguments {
    param([string[]]$Arguments)
    $safe = foreach ($argument in $Arguments) {
        if ([string]$argument -match "^key=") { "key=***" } else { [string]$argument }
    }
    return $safe -join " "
}

function Invoke-Magpie {
    param([string[]]$Arguments)
    $output = & $Magpie @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("magpie " + (Format-MagpieArguments $Arguments) + " failed:`n" + ($output -join "`n"))
    }
    return ,$output
}

if ($PSCmdlet.ParameterSetName -eq "KeyFile") {
    $resolvedKeyFile = (Resolve-Path -LiteralPath $KeyFile -ErrorAction Stop).Path
    $Key = (Get-Content -LiteralPath $resolvedKeyFile -Raw).Trim()
    if (-not $Key) {
        throw "the key file is empty"
    }
}

$url = $GatewayUrl.Trim().TrimEnd("/")
if ($url -notmatch "/v1$") {
    $url += "/v1"
}

if (-not $ProviderId) {
    $ProviderId = ($ProviderName.ToLowerInvariant() -replace "[^a-z0-9]+", "-").Trim("-")
    if (-not $ProviderId) { $ProviderId = "enterprise-gateway" }
}

$kv = @("url=$url", "key=$Key")
if ($Models) {
    $kv += "models=" + (($Models -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ",")
}

if ($Agent -xor $AgentModel) {
    throw "-Agent and -AgentModel must be given together"
}

$exists = $false
& $Magpie provider $ProviderId *> $null
if ($LASTEXITCODE -eq 0) { $exists = $true }

if ($exists) {
    Invoke-Magpie (@("provider", "set", $ProviderId) + $kv) | Out-Null
    Write-Host "updated provider $ProviderId -> $url"
} else {
    $out = Invoke-Magpie (@("provider", "add", $ProviderName, "id=$ProviderId") + $kv)
    foreach ($line in $out) {
        if ([string]$line -match "\(([^()]+)\)\s*$") {
            $ProviderId = $Matches[1]
        }
    }
    Write-Host "added provider $ProviderId -> $url"
}

if (-not $SkipTest) {
    $testOut = Invoke-Magpie @("provider", "test", $ProviderId)
    foreach ($line in $testOut) { Write-Host ([string]$line) }
}

if ($Agent -and $AgentModel) {
    $model = $AgentModel
    if ($model -notmatch "/") {
        $model = "$ProviderId/$model"
    }
    Invoke-Magpie @($Agent, $model) | Out-Null
    Write-Host "configured agent '$Agent' -> $model"
}

Write-Host "done: agents reach the enterprise gateway through this computer's magpie"
