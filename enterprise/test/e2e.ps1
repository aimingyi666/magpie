<#
.SYNOPSIS
Verify client/server separation without touching the local magpie data.

.DESCRIPTION
Starts a mock OpenAI-compatible upstream, an enterprise magpie gateway and a
client magpie in a temporary folder. The test then sends one chat request
through client -> enterprise gateway -> mock upstream and checks that the
server records usage against the employee's gateway key.

Use -Keep to keep the temporary folder and logs for inspection.

.EXAMPLE
.\e2e.ps1 -Magpie C:\path\to\magpie.exe -Node C:\path\to\node.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Magpie,
    [string]$Node = "node",
    [int]$MockPort = 3499,
    [int]$ServerPort = 3426,
    [int]$ClientPort = 3427,
    [string]$WorkDir,
    [switch]$Keep
)

$ErrorActionPreference = "Stop"

function Invoke-Magpie {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $output = & $Exe @Arguments 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw ("magpie " + ($Arguments -join " ") + " failed with exit code $code`n" + ($output -join "`n"))
    }
    return ,$output
}

function Wait-Tcp {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutSec = 20,
        [object]$Job
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Job -and $Job.State -ne "Running") {
            $details = Receive-Job -Job $Job -Keep -ErrorAction SilentlyContinue
            throw "job stopped before port $Port opened`n" + ($details -join "`n")
        }

        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync("127.0.0.1", $Port)
            if ($task.Wait(500) -and $client.Connected) {
                return
            }
        } catch {
            # The listener is not ready yet.
        } finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds 200
    }
    throw "127.0.0.1:$Port did not open within $TimeoutSec seconds"
}

function Wait-Healthy {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][object]$Job,
        [int]$TimeoutSec = 30
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    $last = ""
    $oldAddr = $env:MAGPIE_ADDR
    try {
        $env:MAGPIE_ADDR = "127.0.0.1:$Port"
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($Job.State -ne "Running") {
                $details = Receive-Job -Job $Job -Keep -ErrorAction SilentlyContinue
                throw "magpie on port $Port stopped before becoming healthy`n" + ($details -join "`n")
            }
            $out = & $Exe healthcheck 2>&1
            if ($LASTEXITCODE -eq 0) {
                return
            }
            $last = $out -join "`n"
            Start-Sleep -Milliseconds 300
        }
    } finally {
        $env:MAGPIE_ADDR = $oldAddr
    }
    throw "magpie on port $Port did not become healthy: $last"
}

function Show-JobLogs {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Jobs)
    foreach ($entry in $Jobs.GetEnumerator()) {
        $lines = Receive-Job -Job $entry.Value -Keep -ErrorAction SilentlyContinue
        if ($lines) {
            Write-Host "--- $($entry.Key) ---"
            $lines | Select-Object -Last 25 | ForEach-Object { Write-Host ([string]$_) }
        }
    }
}

$magpiePath = (Resolve-Path -LiteralPath $Magpie).Path
$nodeCommand = Get-Command $Node -ErrorAction SilentlyContinue
if (-not $nodeCommand) {
    throw "node executable not found: $Node"
}
$nodePath = $nodeCommand.Source
$mockScript = Join-Path $PSScriptRoot "mock-upstream.mjs"
$provisionScript = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts\provision-user.ps1"
$joinScript = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts\join-client.ps1"
$verifyScript = Join-Path (Split-Path $PSScriptRoot -Parent) "scripts\verify.ps1"

foreach ($path in @($magpiePath, $mockScript, $provisionScript, $joinScript, $verifyScript)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "required file not found: $path"
    }
}

$base = if ($WorkDir) {
    [System.IO.Path]::GetFullPath($WorkDir)
} else {
    [System.IO.Path]::GetTempPath()
}
New-Item -ItemType Directory -Path $base -Force | Out-Null
$root = Join-Path $base ("magpie-enterprise-e2e-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$serverDir = Join-Path $root "server"
$clientDir = Join-Path $root "client"
New-Item -ItemType Directory -Path (Join-Path $serverDir "data"), (Join-Path $clientDir "data") -Force | Out-Null
$serverExe = Join-Path $serverDir "magpie.exe"
$clientExe = Join-Path $clientDir "magpie.exe"
Copy-Item -LiteralPath $magpiePath -Destination $serverExe
Copy-Item -LiteralPath $magpiePath -Destination $clientExe

$gatewayKey = "e2e-" + [guid]::NewGuid().ToString("N")
$gatewayKeyFile = Join-Path $root "gateway-key.tmp"
Set-Content -LiteralPath $gatewayKeyFile -Value $gatewayKey -NoNewline
$model = "mock-model"
$jobs = [ordered]@{}
$succeeded = $false

try {
    Write-Host "work folder: $root"

    $jobs.mock = Start-Job -ScriptBlock {
        param($NodeExe, $Script, $Port)
        $env:PORT = "$Port"
        & $NodeExe $Script 2>&1
    } -ArgumentList $nodePath, $mockScript, $MockPort
    Wait-Tcp -Port $MockPort -Job $jobs.mock

    Invoke-Magpie -Exe $serverExe -Arguments @(
        "provider", "add", "mock",
        "url=http://127.0.0.1:$MockPort/v1",
        "key=test",
        "models=$model"
    ) | Out-Null

    $provisionOut = & $provisionScript `
        -Magpie $serverExe `
        -Name alice `
        -Key $gatewayKey `
        -Models "mock/$model" `
        -Period day `
        -Tokens 100000 `
        -Cost 5 `
        -Json
    if ($LASTEXITCODE -ne 0) {
        throw "provision-user.ps1 failed with exit code $LASTEXITCODE"
    }
    $provisioned = ($provisionOut -join "`n") | ConvertFrom-Json
    if (-not $provisioned.id -or $provisioned.name -ne "alice") {
        throw "provision-user.ps1 returned an unexpected result: $($provisionOut -join ' ')"
    }

    $jobs.server = Start-Job -ScriptBlock {
        param($Exe, $Port)
        $env:MAGPIE_ADDR = "0.0.0.0:$Port"
        $env:MAGPIE_ALLOW_IPS = "127.0.0.1/32"
        & $Exe serve 2>&1
    } -ArgumentList $serverExe, $ServerPort
    Wait-Tcp -Port $ServerPort -Job $jobs.server
    Wait-Healthy -Exe $serverExe -Port $ServerPort -Job $jobs.server

    & $joinScript `
        -Magpie $clientExe `
        -GatewayUrl "http://127.0.0.1:$ServerPort" `
        -KeyFile $gatewayKeyFile `
        -Models $model `
        -ProviderName "Enterprise Gateway" `
        -ProviderId "enterprise-gateway" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "join-client.ps1 failed with exit code $LASTEXITCODE"
    }

    $jobs.client = Start-Job -ScriptBlock {
        param($Exe, $Port)
        $env:MAGPIE_ADDR = "127.0.0.1:$Port"
        & $Exe serve 2>&1
    } -ArgumentList $clientExe, $ClientPort
    Wait-Tcp -Port $ClientPort -Job $jobs.client
    Wait-Healthy -Exe $clientExe -Port $ClientPort -Job $jobs.client

    $headers = @{ Authorization = "Bearer $gatewayKey" }
    $body = @{
        model    = "enterprise-gateway/$model"
        messages = @(@{ role = "user"; content = "ping" })
    } | ConvertTo-Json -Depth 6
    $chat = Invoke-WebRequest `
        -Uri "http://127.0.0.1:$ClientPort/v1/chat/completions" `
        -Method Post `
        -Headers $headers `
        -ContentType "application/json" `
        -Body $body `
        -SkipHttpErrorCheck `
        -TimeoutSec 30
    if ($chat.StatusCode -ne 200) {
        throw "client chat failed: HTTP $($chat.StatusCode) $($chat.Content)"
    }
    $reply = $chat.Content | ConvertFrom-Json
    if ($reply.choices[0].message.content -ne "mock-upstream-ok") {
        throw "unexpected upstream reply: $($chat.Content)"
    }
    Write-Host "PASS  client -> enterprise gateway -> mock upstream"

    $verifyOut = & $verifyScript `
        -GatewayUrl "http://127.0.0.1:$ServerPort" `
        -Key $gatewayKey `
        -Model $model `
        -Json
    if ($LASTEXITCODE -ne 0) {
        throw "verify.ps1 failed with exit code $LASTEXITCODE`n" + ($verifyOut -join "`n")
    }
    $verify = ($verifyOut -join "`n") | ConvertFrom-Json
    if ($verify | Where-Object { -not $_.pass }) {
        throw "verify.ps1 reported a failed check: $($verifyOut -join ' ')"
    }
    Write-Host "PASS  models and chat accepted with the employee key"

    $usagePath = Join-Path $serverDir "data\usage.jsonl"
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    $usageLine = $null
    while ([DateTime]::UtcNow -lt $deadline -and -not $usageLine) {
        if (Test-Path -LiteralPath $usagePath) {
            $usageLine = Get-Content -LiteralPath $usagePath |
                Where-Object { $_ -match '"callerKeyName":"alice"' } |
                Select-Object -Last 1
        }
        if (-not $usageLine) {
            Start-Sleep -Milliseconds 200
        }
    }
    if (-not $usageLine) {
        throw "usage.jsonl has no entry attributed to alice"
    }
    $usage = $usageLine | ConvertFrom-Json
    if ($usage.callerKeyId -ne $provisioned.id -or $usage.status -ne 200) {
        throw "unexpected usage attribution: $usageLine"
    }
    Write-Host "PASS  usage attributed to $($usage.callerKeyName) / $($usage.callerKeyId)"

    $succeeded = $true
    Write-Host "PASS  enterprise client/server separation"
} catch {
    Write-Host "FAIL  $($_.Exception.Message)"
    Show-JobLogs -Jobs $jobs
    throw
} finally {
    foreach ($job in $jobs.Values) {
        try {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        } catch {
            # Best-effort cleanup after a failed test.
        }
    }

    if ($succeeded -and -not $Keep) {
        $resolvedRoot = [System.IO.Path]::GetFullPath($root)
        $resolvedTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if ($resolvedRoot.StartsWith($resolvedTemp, [System.StringComparison]::OrdinalIgnoreCase) -and
            (Split-Path $resolvedRoot -Leaf) -like "magpie-enterprise-e2e-*") {
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        }
    } else {
        Write-Host "logs and portable data kept in: $root"
    }
}
