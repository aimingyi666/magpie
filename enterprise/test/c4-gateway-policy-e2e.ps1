<#
.SYNOPSIS
Verify gateway policy machine writes against real Magpie request behavior.

.DESCRIPTION
Starts an isolated portable Magpie gateway and a mock OpenAI-compatible
upstream. The test applies policies through the real CLI, then proves that
model and token limits are enforced before the upstream, stale revisions do
not write, key rotation preserves the policy, the old key is revoked and the
new key works. It also scans machine output, logs and usage for plaintext
gateway keys.

Use -Keep to keep the temporary folder and logs for inspection.

.EXAMPLE
.\c4-gateway-policy-e2e.ps1 -Magpie C:\path\to\magpie.exe -Node C:\path\to\node.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Magpie,
    [string]$Node = "node",
    [ValidateRange(0, 65535)][int]$UpstreamPort = 0,
    [ValidateRange(0, 65535)][int]$GatewayPort = 0,
    [string]$WorkDir,
    [switch]$Keep
)

$ErrorActionPreference = "Stop"

function Get-FreeTcpPort {
    param([int[]]$Avoid = @())
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        $listener = [System.Net.Sockets.TcpListener]::new(
            [System.Net.IPAddress]::Loopback,
            0
        )
        $listener.Start()
        try {
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        } finally {
            $listener.Stop()
        }
        if ($port -ne 3425 -and -not ($Avoid -contains $port)) {
            return $port
        }
    }
    throw "could not allocate a temporary TCP port"
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

function Wait-MagpieHealthy {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][object]$Job,
        [int]$TimeoutSec = 30
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    $oldAddr = $env:MAGPIE_ADDR
    $last = ""
    try {
        $env:MAGPIE_ADDR = "127.0.0.1:$Port"
        while ([DateTime]::UtcNow -lt $deadline) {
            if ($Job.State -ne "Running") {
                $details = Receive-Job -Job $Job -Keep -ErrorAction SilentlyContinue
                throw "magpie on port $Port stopped before becoming healthy`n" + ($details -join "`n")
            }
            $probe = Invoke-MagpieProcess -Exe $Exe -Arguments @("healthcheck")
            if ($probe.ExitCode -eq 0) {
                return
            }
            $last = $probe.Text
            Start-Sleep -Milliseconds 300
        }
    } finally {
        $env:MAGPIE_ADDR = $oldAddr
    }
    throw "magpie on port $Port did not become healthy: $last"
}

function Invoke-MagpieProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [AllowNull()][string]$InputText = $null
    )
    $output = if ($null -ne $InputText) {
        $InputText | & $Exe @Arguments 2>&1
    } else {
        & $Exe @Arguments 2>&1
    }
    $code = $LASTEXITCODE
    $lines = @($output)
    return [pscustomobject]@{
        ExitCode = [int]$code
        Lines    = $lines
        Text     = ($lines -join "`n")
    }
}

function Assert-ExitCode {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][object]$Result,
        [int]$Expected = 0
    )
    if ($Result.ExitCode -ne $Expected) {
        throw "$Label exited $($Result.ExitCode), expected ${Expected}: $($Result.Text)"
    }
}

function Assert-Status {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][object]$Response,
        [Parameter(Mandatory = $true)][int]$Expected
    )
    $actual = [int]$Response.StatusCode
    if ($actual -ne $Expected) {
        throw "$Label returned HTTP $actual, expected ${Expected}: $($Response.Content)"
    }
}

function Get-HeaderValue {
    param(
        [Parameter(Mandatory = $true)][object]$Response,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $value = $Response.Headers[$Name]
    if ($null -eq $value) {
        return ""
    }
    return (@($value) -join ", ")
}

function Get-LocalIPv4 {
    $addresses = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
        Where-Object {
            $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
            -not [System.Net.IPAddress]::IsLoopback($_) -and
            -not $_.ToString().StartsWith("169.254.", [System.StringComparison]::Ordinal)
        }
    $address = $addresses | Select-Object -First 1
    if (-not $address) {
        throw "no non-loopback IPv4 address is available for authenticated gateway tests"
    }
    return $address.ToString()
}

function New-RandomUrlToken {
    param([int]$Bytes = 32)
    $buffer = [byte[]]::new($Bytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    return [Convert]::ToBase64String($buffer).
        TrimEnd("=").
        Replace("+", "-").
        Replace("/", "_")
}

function Show-JobLogs {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Jobs)
    foreach ($entry in $Jobs.GetEnumerator()) {
        $lines = Receive-Job -Job $entry.Value -Keep -ErrorAction SilentlyContinue
        if ($lines) {
            Write-Host "--- $($entry.Key) ---"
            $lines | Select-Object -Last 40 | ForEach-Object { Write-Host ([string]$_) }
        }
    }
}

function Get-MockStats {
    $stats = Invoke-RestMethod `
        -Uri "http://127.0.0.1:$UpstreamPort/__stats" `
        -TimeoutSec 10
    return [pscustomobject]@{
        ChatRequests = [int]$stats.chatRequests
        ByModel      = $stats.chatRequestsByModel
    }
}

function Send-Chat {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$Model
    )
    $headers = @{ Authorization = "Bearer $Key" }
    $body = @{
        model    = $Model
        messages = @(@{ role = "user"; content = "policy e2e" })
    } | ConvertTo-Json -Depth 6 -Compress
    return Invoke-WebRequest `
        -Uri "$gatewayBase/v1/chat/completions" `
        -Method Post `
        -Headers $headers `
        -ContentType "application/json" `
        -Body $body `
        -SkipHttpErrorCheck `
        -TimeoutSec 30
}

function Get-Policy {
    param([Parameter(Mandatory = $true)][string]$KeyId)
    $result = Invoke-MagpieProcess `
        -Exe $serverExe `
        -Arguments @("gateway-key", "describe", $KeyId, "--json")
    Assert-ExitCode -Label "gateway-key describe" -Result $result
    [void]$machineOutputs.Add($result.Text)
    try {
        $policy = $result.Text | ConvertFrom-Json
    } catch {
        throw "gateway-key describe returned invalid JSON: $($result.Text)"
    }
    if ($policy.ok -ne $true -or [int]$policy.schemaVersion -ne 1) {
        throw "gateway-key describe returned an unexpected policy: $($result.Text)"
    }
    return $policy
}

function Invoke-PolicyApply {
    param(
        [Parameter(Mandatory = $true)][string]$KeyId,
        [Parameter(Mandatory = $true)][string]$ExpectedRevision,
        [Parameter(Mandatory = $true)][string[]]$Models,
        [object[]]$Limits = @()
    )
    $payload = [ordered]@{
        schemaVersion          = 1
        expectedPolicyRevision = $ExpectedRevision
        models                 = @($Models)
        limits                 = @($Limits)
    } | ConvertTo-Json -Depth 10 -Compress
    return Invoke-MagpieProcess `
        -Exe $serverExe `
        -Arguments @("gateway-key", "policy", "apply", $KeyId, "--json") `
        -InputText $payload
}

function Read-PolicyApplyResult {
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)][string]$Label
    )
    Assert-ExitCode -Label $Label -Result $Result
    [void]$machineOutputs.Add($Result.Text)
    try {
        $policy = $Result.Text | ConvertFrom-Json
    } catch {
        throw "$Label returned invalid JSON: $($Result.Text)"
    }
    if ($policy.ok -ne $true -or [int]$policy.schemaVersion -ne 1) {
        throw "$Label returned an unexpected policy: $($Result.Text)"
    }
    return $policy
}

function Get-PolicyFingerprint {
    param([Parameter(Mandatory = $true)][object]$Policy)
    $limits = @($Policy.limits | ForEach-Object {
        [ordered]@{
            period = [string]$_.period
            days   = [int]$_.days
            hours  = [int]$_.hours
            tokens = [int64]$_.tokens
            cost   = [double]$_.cost
        }
    })
    return ([ordered]@{
        policyRevision = [string]$Policy.policyRevision
        models         = @($Policy.models.patterns | ForEach-Object { [string]$_ })
        limits         = $limits
    } | ConvertTo-Json -Depth 10 -Compress)
}

function Assert-PolicyMatches {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Actual,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if ((Get-PolicyFingerprint -Policy $Expected) -cne
        (Get-PolicyFingerprint -Policy $Actual)) {
        throw "$Label did not match: expected $($Expected | ConvertTo-Json -Depth 10 -Compress), got $($Actual | ConvertTo-Json -Depth 10 -Compress)"
    }
}

function Assert-NoSecret {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string[]]$Secrets
    )
    foreach ($secret in $Secrets) {
        if ($secret -and $Text.Contains($secret)) {
            throw "$Label contains a plaintext gateway key"
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
foreach ($path in @($magpiePath, $mockScript)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "required file not found: $path"
    }
}

if ($UpstreamPort -eq 0) {
    $UpstreamPort = Get-FreeTcpPort
}
if ($GatewayPort -eq 0) {
    $GatewayPort = Get-FreeTcpPort -Avoid @($UpstreamPort)
}
if ($UpstreamPort -eq $GatewayPort) {
    throw "UpstreamPort and GatewayPort must differ"
}

$base = if ($WorkDir) {
    [System.IO.Path]::GetFullPath($WorkDir)
} else {
    [System.IO.Path]::GetTempPath()
}
New-Item -ItemType Directory -Path $base -Force | Out-Null
$root = Join-Path $base ("magpie-enterprise-policy-e2e-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$serverDir = Join-Path $root "server"
$dataDir = Join-Path $serverDir "data"
$sandboxHome = Join-Path $root "home"
New-Item -ItemType Directory -Path $dataDir, $sandboxHome -Force | Out-Null
$serverExe = Join-Path $serverDir "magpie.exe"
Copy-Item -LiteralPath $magpiePath -Destination $serverExe
Set-Content -LiteralPath (Join-Path $serverDir ".portable") -Value "policy e2e" -NoNewline

$gatewayHost = Get-LocalIPv4
$gatewayBase = "http://${gatewayHost}:$GatewayPort"
$gatewayKey = "e2e-" + (New-RandomUrlToken -Bytes 32)
$rotatedKey = ""
$keyId = ""
$jobs = [ordered]@{}
$succeeded = $false
$machineOutputs = [System.Collections.Generic.List[string]]::new()
$envNames = @(
    "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
    "MAGPIE_ADDR"
)
$savedEnv = @{}
foreach ($name in $envNames) {
    $savedEnv[$name] = [System.Environment]::GetEnvironmentVariable($name, "Process")
}

try {
    $env:HOME = $sandboxHome
    $env:USERPROFILE = $sandboxHome
    $env:APPDATA = Join-Path $sandboxHome "AppData\Roaming"
    $env:LOCALAPPDATA = Join-Path $sandboxHome "AppData\Local"
    $env:XDG_CONFIG_HOME = Join-Path $sandboxHome ".config"
    $env:XDG_DATA_HOME = Join-Path $sandboxHome ".local\share"
    $env:XDG_CACHE_HOME = Join-Path $sandboxHome ".cache"
    $env:XDG_STATE_HOME = Join-Path $sandboxHome ".local\state"
    $env:MAGPIE_ADDR = "127.0.0.1:$GatewayPort"

    Write-Host "work folder: $root"
    Write-Host "gateway address: $gatewayBase"

    $jobs.upstream = Start-Job -ScriptBlock {
        param($NodeExe, $Script, $Port)
        $env:PORT = "$Port"
        & $NodeExe $Script 2>&1
    } -ArgumentList $nodePath, $mockScript, $UpstreamPort
    Wait-Tcp -Port $UpstreamPort -Job $jobs.upstream
    $mockStats = Get-MockStats
    if ($mockStats.ChatRequests -ne 0) {
        throw "mock upstream did not start with an empty request count"
    }

    $provider = Invoke-MagpieProcess -Exe $serverExe -Arguments @(
        "provider", "add", "mock",
        "url=http://127.0.0.1:$UpstreamPort/v1",
        "key=test",
        "models=mock-model,mock-second"
    )
    Assert-ExitCode -Label "provider add" -Result $provider

    $add = Invoke-MagpieProcess `
        -Exe $serverExe `
        -Arguments @("gateway-key", "add", "alice", "--key", "-") `
        -InputText $gatewayKey
    Assert-ExitCode -Label "gateway-key add" -Result $add
    $keyRows = Invoke-MagpieProcess -Exe $serverExe -Arguments @("gateway-key", "list")
    Assert-ExitCode -Label "gateway-key list" -Result $keyRows
    $keyRow = $keyRows.Lines |
        Where-Object { $_ -match "^\s*\S+\s+alice\s+" } |
        Select-Object -First 1
    if (-not $keyRow) {
        throw "the created key did not appear in gateway-key list"
    }
    $keyId = [regex]::Match([string]$keyRow, "^\s*(\S+)").Groups[1].Value
    if (-not $keyId) {
        throw "could not parse the created key id"
    }

    $jobs.gateway = Start-Job -ScriptBlock {
        param($Exe, $Port)
        $env:MAGPIE_ADDR = "0.0.0.0:$Port"
        & $Exe serve 2>&1
    } -ArgumentList $serverExe, $GatewayPort
    Wait-Tcp -Port $GatewayPort -Job $jobs.gateway
    Wait-MagpieHealthy -Exe $serverExe -Port $GatewayPort -Job $jobs.gateway
    Write-Host "PASS  isolated real Magpie gateway is healthy"

    $initial = Get-Policy -KeyId $keyId
    $allowBoth = Invoke-PolicyApply `
        -KeyId $keyId `
        -ExpectedRevision $initial.policyRevision `
        -Models @("mock/mock-model", "mock/mock-second") `
        -Limits @()
    $allowBothPolicy = Read-PolicyApplyResult -Result $allowBoth -Label "initial policy apply"
    $allowBothReadback = Get-Policy -KeyId $keyId
    Assert-PolicyMatches -Expected $allowBothPolicy -Actual $allowBothReadback -Label "initial policy readback"

    $beforeAllowed = Get-MockStats
    $allowed = Send-Chat -Key $gatewayKey -Model "mock/mock-model"
    Assert-Status -Label "allowed chat" -Response $allowed -Expected 200
    if (($allowed.Content | ConvertFrom-Json).choices[0].message.content -ne "mock-upstream-ok") {
        throw "allowed chat returned an unexpected upstream reply"
    }
    $afterAllowed = Get-MockStats
    if ($afterAllowed.ChatRequests -ne $beforeAllowed.ChatRequests + 1) {
        throw "allowed chat did not reach the mock upstream exactly once"
    }
    Write-Host "PASS  policy-allowed chat reached the upstream"

    $restrict = Invoke-PolicyApply `
        -KeyId $keyId `
        -ExpectedRevision $allowBothReadback.policyRevision `
        -Models @("mock/mock-model") `
        -Limits @()
    $restrictedPolicy = Read-PolicyApplyResult -Result $restrict -Label "model policy apply"
    $restrictedReadback = Get-Policy -KeyId $keyId
    Assert-PolicyMatches -Expected $restrictedPolicy -Actual $restrictedReadback -Label "model policy readback"
    $modelPolicyRevision = [string]$restrictedReadback.policyRevision

    $beforeDenied = Get-MockStats
    $denied = Send-Chat -Key $gatewayKey -Model "mock/mock-second"
    Assert-Status -Label "model-denied chat" -Response $denied -Expected 403
    $deniedError = ($denied.Content | ConvertFrom-Json).error
    if ($deniedError.type -ne "permission_error" -or
        -not ([string]$deniedError.message).Contains("may not use mock/mock-second") -or
        -not ([string]$deniedError.message).Contains("mock/mock-model")) {
        throw "model-denied chat returned the wrong error: $($denied.Content)"
    }
    $afterDenied = Get-MockStats
    if ($afterDenied.ChatRequests -ne $beforeDenied.ChatRequests) {
        throw "the model-denied request reached the upstream"
    }
    Write-Host "PASS  model policy rejected before the upstream"

    $lowLimit = @([ordered]@{
        period = "month"
        tokens = 1
    })
    $limited = Invoke-PolicyApply `
        -KeyId $keyId `
        -ExpectedRevision $restrictedReadback.policyRevision `
        -Models @("mock/mock-model") `
        -Limits $lowLimit
    $limitedPolicy = Read-PolicyApplyResult -Result $limited -Label "limit policy apply"
    if (@($limitedPolicy.limits).Count -ne 1 -or [int64]$limitedPolicy.limits[0].tokens -ne 1) {
        throw "limit policy apply did not return the expected token cap"
    }
    $limitedReadback = Get-Policy -KeyId $keyId
    Assert-PolicyMatches -Expected $limitedPolicy -Actual $limitedReadback -Label "limit policy readback"

    $beforeLimit = Get-MockStats
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $limitResponse = $null
    $lastLimit = ""
    while ([DateTime]::UtcNow -lt $deadline) {
        $candidate = Send-Chat -Key $gatewayKey -Model "mock/mock-model"
        $lastLimit = "HTTP $($candidate.StatusCode) $($candidate.Content)"
        if ([int]$candidate.StatusCode -eq 429) {
            $limitResponse = $candidate
            break
        }
        if ([int]$candidate.StatusCode -eq 503 -and
            $candidate.Content.Contains("gateway_key_limit_off")) {
            Start-Sleep -Milliseconds 300
            continue
        }
        throw "limited chat did not produce a stable refusal: $lastLimit"
    }
    if (-not $limitResponse) {
        throw "limited chat did not return HTTP 429: $lastLimit"
    }
    $afterLimit = Get-MockStats
    if ($afterLimit.ChatRequests -ne $beforeLimit.ChatRequests) {
        throw "the token-limited request reached the upstream"
    }
    if (-not (Get-HeaderValue -Response $limitResponse -Name "Retry-After")) {
        throw "HTTP 429 did not include Retry-After"
    }
    if (-not (Get-HeaderValue -Response $limitResponse -Name "X-Magpie-Limit-Reset")) {
        throw "HTTP 429 did not include X-Magpie-Limit-Reset"
    }
    if ((Get-HeaderValue -Response $limitResponse -Name "X-Should-Retry") -ne "false") {
        throw "HTTP 429 did not include X-Should-Retry: false"
    }
    Write-Host "PASS  token policy rejected before the upstream with stable retry headers"

    $beforeConflict = Get-MockStats
    $conflict = Invoke-PolicyApply `
        -KeyId $keyId `
        -ExpectedRevision $modelPolicyRevision `
        -Models @("mock/mock-second") `
        -Limits @()
    if ($conflict.ExitCode -eq 0) {
        throw "a stale policy revision was accepted"
    }
    [void]$machineOutputs.Add($conflict.Text)
    $conflictJson = $conflict.Lines |
        Where-Object { ([string]$_).TrimStart().StartsWith("{") } |
        Select-Object -First 1
    if (-not $conflictJson) {
        throw "stale policy apply returned no JSON error: $($conflict.Text)"
    }
    $conflictBody = $conflictJson | ConvertFrom-Json
    if ($conflictBody.ok -ne $false -or
        $conflictBody.error.code -ne "gateway_policy_conflict") {
        throw "stale policy apply returned the wrong machine error: $($conflict.Text)"
    }
    $afterConflictPolicy = Get-Policy -KeyId $keyId
    Assert-PolicyMatches -Expected $limitedReadback -Actual $afterConflictPolicy -Label "conflict readback"
    $afterConflict = Get-MockStats
    if ($afterConflict.ChatRequests -ne $beforeConflict.ChatRequests) {
        throw "the conflicting policy request reached the upstream"
    }
    Write-Host "PASS  stale policy revision was rejected without changing the policy"

    $beforeRotate = Get-Policy -KeyId $keyId
    $rotate = Invoke-MagpieProcess -Exe $serverExe -Arguments @("gateway-key", "rotate", $keyId)
    Assert-ExitCode -Label "gateway-key rotate" -Result $rotate
    $rotatedKey = $rotate.Text.Trim()
    if (-not $rotatedKey -or $rotatedKey -eq $gatewayKey) {
        throw "gateway-key rotate did not return a new key"
    }
    $afterRotate = Get-Policy -KeyId $keyId
    Assert-PolicyMatches -Expected $beforeRotate -Actual $afterRotate -Label "rotation policy readback"

    $oldModels = Invoke-WebRequest `
        -Uri "$gatewayBase/v1/models" `
        -Headers @{ Authorization = "Bearer $gatewayKey" } `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "old key after rotation" -Response $oldModels -Expected 401
    $newModels = Invoke-WebRequest `
        -Uri "$gatewayBase/v1/models" `
        -Headers @{ Authorization = "Bearer $rotatedKey" } `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "new key after rotation" -Response $newModels -Expected 200
    if (-not $newModels.Content.Contains("mock/mock-model")) {
        throw "the rotated key did not list its policy-allowed model"
    }
    Write-Host "PASS  rotation preserved policy, revoked the old key and enabled the new key"

    $clearLimit = Invoke-PolicyApply `
        -KeyId $keyId `
        -ExpectedRevision $afterRotate.policyRevision `
        -Models @("mock/mock-model") `
        -Limits @()
    $clearedPolicy = Read-PolicyApplyResult -Result $clearLimit -Label "clear limit policy apply"
    if (@($clearedPolicy.limits).Count -ne 0) {
        throw "clearing the limit still returned a limit"
    }
    $beforeRotatedChat = Get-MockStats
    $rotatedChat = Send-Chat -Key $rotatedKey -Model "mock/mock-model"
    Assert-Status -Label "rotated key chat" -Response $rotatedChat -Expected 200
    $afterRotatedChat = Get-MockStats
    if ($afterRotatedChat.ChatRequests -ne $beforeRotatedChat.ChatRequests + 1) {
        throw "the rotated key did not reach the upstream exactly once"
    }
    Write-Host "PASS  rotated key accepted after the policy limit was cleared"

    foreach ($text in $machineOutputs) {
        Assert-NoSecret `
            -Text $text `
            -Label "describe/apply machine output" `
            -Secrets @($gatewayKey, $rotatedKey)
    }
    foreach ($entry in $jobs.GetEnumerator()) {
        $logText = (Receive-Job -Job $entry.Value -Keep -ErrorAction SilentlyContinue) -join "`n"
        Assert-NoSecret `
            -Text $logText `
            -Label "$($entry.Key) log" `
            -Secrets @($gatewayKey, $rotatedKey)
    }

    $usagePath = Join-Path $dataDir "usage.jsonl"
    if (-not (Test-Path -LiteralPath $usagePath -PathType Leaf)) {
        throw "usage.jsonl was not written"
    }
    $usageText = Get-Content -LiteralPath $usagePath -Raw
    Assert-NoSecret -Text $usageText -Label "usage.jsonl" -Secrets @($gatewayKey, $rotatedKey)
    $attributed = Get-Content -LiteralPath $usagePath |
        Where-Object { $_ -match [regex]::Escape($keyId) } |
        Where-Object { $_ -match '"status":200' } |
        Select-Object -First 1
    if (-not $attributed) {
        throw "usage.jsonl has no successful request attributed to the test key"
    }

    $storePath = Join-Path $dataDir "caller-keys.json"
    if (-not (Test-Path -LiteralPath $storePath -PathType Leaf)) {
        throw "caller-keys.json was not written"
    }
    $storeText = Get-Content -LiteralPath $storePath -Raw
    if (-not $storeText.Contains($rotatedKey)) {
        throw "caller-keys.json does not contain the current gateway key"
    }
    if ($storeText.Contains($gatewayKey)) {
        throw "caller-keys.json still contains the rotated-out gateway key"
    }
    if ($IsWindows) {
        $acl = Get-Acl -LiteralPath $storePath
        $readable = @($acl.Access | Where-Object {
            $_.AccessControlType -eq "Allow" -and
            (($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) -ne 0)
        }).Count -gt 0
        if (-not $readable) {
            throw "caller-keys.json has no allowing file-system read rule"
        }
    }

    $scannedFiles = 0
    foreach ($file in Get-ChildItem -LiteralPath $serverDir -Recurse -File -Force) {
        if ($file.FullName -eq $storePath -or
            $file.Extension -ieq ".exe" -or
            $file.Length -gt 10MB) {
            continue
        }
        try {
            $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
        } catch {
            continue
        }
        Assert-NoSecret -Text $text -Label $file.FullName -Secrets @($gatewayKey, $rotatedKey)
        $scannedFiles++
    }
    Write-Host "PASS  machine output, logs and usage are secret-free; store holds only the current key"
    Write-Host "PASS  scanned $scannedFiles non-store text files under the portable data folder"

    $succeeded = $true
    Write-Host "PASS  C4 real gateway policy end-to-end"
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
    foreach ($name in $envNames) {
        [System.Environment]::SetEnvironmentVariable($name, $savedEnv[$name], "Process")
    }

    if ($succeeded -and -not $Keep) {
        $resolvedRoot = [System.IO.Path]::GetFullPath($root)
        $resolvedTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if ($resolvedRoot.StartsWith($resolvedTemp, [System.StringComparison]::OrdinalIgnoreCase) -and
            (Split-Path $resolvedRoot -Leaf) -like "magpie-enterprise-policy-e2e-*") {
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        }
    } else {
        Write-Host "logs and portable data kept in: $root"
    }
}
