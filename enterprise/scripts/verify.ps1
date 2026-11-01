<#
.SYNOPSIS
Check that an enterprise gateway accepts this key and serves a model.

.DESCRIPTION
Run this from an employee computer. magpie always lets its own loopback
through without a gateway key, so a run on the gateway host proves routing
but not that the key itself works.

.EXAMPLE
.\verify.ps1 -Magpie magpie -GatewayUrl http://gateway.corp.example:3425 -Key <key>

.EXAMPLE
.\verify.ps1 -GatewayUrl https://ai.corp.example -Key <key> -Model deepseek/deepseek-chat
#>
[CmdletBinding()]
param(
    [string]$Magpie = "magpie",
    [Parameter(Mandatory = $true)][string]$GatewayUrl,
    [Parameter(Mandatory = $true)][string]$Key,
    [string]$Model,
    [switch]$Json
)

$ErrorActionPreference = "Stop"
$results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Check, [bool]$Pass, [string]$Detail = "")
    $results.Add([pscustomobject]@{ check = $Check; pass = $Pass; detail = $Detail })
}

$base = $GatewayUrl.Trim().TrimEnd("/")
if ($base -match "/v1$") {
    $base = $base.Substring(0, $base.Length - 3)
}
$headers = @{ Authorization = "Bearer $Key" }

try {
    $models = Invoke-WebRequest -Uri "$base/v1/models" -Headers $headers -SkipHttpErrorCheck -TimeoutSec 20
    Add-Result "models" ($models.StatusCode -eq 200) "HTTP $($models.StatusCode)"
} catch {
    Add-Result "models" $false $_.Exception.Message
}

if ($Model) {
    $requestModel = ($Model -split "/")[-1]
    $body = @{
        model    = $requestModel
        messages = @(@{ role = "user"; content = "ping" })
    } | ConvertTo-Json -Depth 6
    try {
        $chat = Invoke-WebRequest -Uri "$base/v1/chat/completions" -Method Post -Headers $headers `
            -ContentType "application/json" -Body $body -SkipHttpErrorCheck -TimeoutSec 60
        $detail = "HTTP $($chat.StatusCode)"
        $pass = $chat.StatusCode -eq 200
        if ($pass) {
            $parsed = $chat.Content | ConvertFrom-Json
            $detail += " · " + [string]$parsed.choices[0].message.content
        }
        Add-Result "chat $requestModel" $pass $detail
    } catch {
        Add-Result "chat $requestModel" $false $_.Exception.Message
    }
}

if ($Json) {
    $results | ConvertTo-Json -Depth 4
} else {
    foreach ($r in $results) {
        $mark = if ($r.pass) { "PASS" } else { "FAIL" }
        Write-Output ("{0}  {1}  {2}" -f $mark, $r.check, $r.detail)
    }
}

if ($results | Where-Object { -not $_.pass }) {
    exit 1
}
