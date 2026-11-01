<#
.SYNOPSIS
Create or reconfigure one employee's gateway key on the enterprise gateway.

.DESCRIPTION
Runs on the gateway host (or inside the gateway container). Prints the new
key once; magpie keeps only its hash, so save it before closing the terminal.

Use -Ttl to issue a short-lived key instead of a permanent one. Use -Id to
change the models or budget of an existing key without creating another.

.EXAMPLE
.\provision-user.ps1 -Magpie magpie -Name alice -Models "deepseek/deepseek-chat" -Period day -Tokens 200000 -Cost 10

.EXAMPLE
.\provision-user.ps1 -Magpie magpie -Name ci -Ttl 8h -Models "deepseek/*"

.EXAMPLE
docker compose exec gateway magpie gateway-key add alice
#>
[CmdletBinding()]
param(
    [string]$Magpie = "magpie",
    [Parameter(Mandatory = $true)][string]$Name,
    [string]$Key,
    [string]$Id,
    [string]$Models,
    [ValidateSet("day", "week", "month", "")][string]$Period = "",
    [long]$Tokens = 0,
    [double]$Cost = 0,
    [switch]$ReadOnly,
    [string]$Ttl,
    [string]$IssuerId,
    [switch]$Json
)

$ErrorActionPreference = "Stop"

function Invoke-Magpie {
    param([string[]]$Arguments)
    $output = & $Magpie @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("magpie " + ($Arguments -join " ") + " failed:`n" + ($output -join "`n"))
    }
    return ,$output
}

function Get-KeyId {
    param([string]$KeyName)
    $lines = Invoke-Magpie @("gateway-key", "list")
    $pattern = '^(\S+)\s+' + [regex]::Escape($KeyName) + '(\s|$)'
    foreach ($line in $lines) {
        if ([string]$line -match $pattern) {
            return $Matches[1]
        }
    }
    throw "gateway key '$KeyName' was created but not found in 'gateway-key list'"
}

$secret = $null
$targetId = $Id
$expires = $null

if ($Ttl) {
    if ($targetId) {
        throw "-Ttl creates a new key; do not combine it with -Id"
    }
    $issueArgs = @("gateway-key", "issue", "--ttl", $Ttl, "--name", $Name)
    if ($IssuerId) { $issueArgs += @("--from", $IssuerId) }
    if ($Models) { $issueArgs += @("--models", $Models) }
    if ($Tokens -gt 0) { $issueArgs += @("--tokens", "$Tokens") }
    if ($Cost -gt 0) { $issueArgs += @("--cost", "$Cost") }
    if ($ReadOnly) { $issueArgs += "--read-only" }
    $issueArgs += "--json"

    $out = Invoke-Magpie $issueArgs
    $issued = ($out -join "`n") | ConvertFrom-Json
    $secret = [string]$issued.key
    $targetId = [string]$issued.id
    $expires = [string]$issued.expires
} elseif (-not $targetId) {
    $addArgs = @("gateway-key", "add", $Name)
    if ($Key) { $addArgs += @("--key", $Key) }
    if ($ReadOnly) { $addArgs += "--read-only" }
    $out = Invoke-Magpie $addArgs
    $secret = ([string]($out | Select-Object -Last 1)).Trim()
    if (-not $secret) {
        throw "magpie did not print the new key"
    }
    $targetId = Get-KeyId -KeyName $Name
}

if ($Models -and -not $Ttl) {
    $modelArgs = @("gateway-key", "models", $targetId) + @($Models -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    Invoke-Magpie $modelArgs | Out-Null
}

if ($Period) {
    $limitArgs = @("gateway-key", "limit", $targetId, $Period)
    if ($Tokens -gt 0) { $limitArgs += @("--tokens", "$Tokens") }
    if ($Cost -gt 0) { $limitArgs += @("--cost", "$Cost") }
    Invoke-Magpie $limitArgs | Out-Null
}

if ($Json) {
    [pscustomobject]@{
        id       = $targetId
        name     = $Name
        key      = $secret
        expires  = $expires
        models   = $Models
        period   = $Period
        tokens   = $Tokens
        cost     = $Cost
        readOnly = [bool]$ReadOnly
    } | ConvertTo-Json -Depth 3
} elseif ($secret) {
    Write-Output $secret
} else {
    Write-Output "gateway key $targetId updated"
}
