<#
.SYNOPSIS
Verify the real Magpie issuer API and the enterprise-auth M1 flow.

.DESCRIPTION
Starts a temporary portable Magpie gateway, a mock OpenAI-compatible
upstream, a mock OIDC provider, and enterprise/auth-service. It then exercises
OIDC join, a real /v1/magpie/keys issue, an employee model call, usage
attribution, refresh, immediate old-key revocation, employee disable, and
auth-service restart. It never touches the user's running Magpie data.

.EXAMPLE
.\auth-e2e.ps1 -Magpie C:\path\to\magpie.exe -Node C:\path\to\node.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Magpie,
    [string]$Node = "node",
    [int]$OidcPort = 3731,
    [int]$UpstreamPort = 3732,
    [int]$GatewayPort = 3733,
    [int]$AuthPort = 3734,
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

function Wait-TcpClosed {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutSec = 15
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    while ([DateTime]::UtcNow -lt $deadline) {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync("127.0.0.1", $Port)
            if (-not ($task.Wait(300) -and $client.Connected)) {
                return
            }
        } catch {
            return
        } finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds 200
    }
    throw "127.0.0.1:$Port did not close within $TimeoutSec seconds"
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
        throw "no non-loopback IPv4 address is available for the gateway revocation test"
    }
    return $address.ToString()
}

function Wait-MagpieHealthy {
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

function Wait-AuthHealthy {
    param(
        [Parameter(Mandatory = $true)][object]$Job,
        [int]$TimeoutSec = 30
    )
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    $last = ""
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Job.State -ne "Running") {
            $details = Receive-Job -Job $Job -Keep -ErrorAction SilentlyContinue
            throw "enterprise-auth stopped before becoming healthy`n" + ($details -join "`n")
        }
        try {
            $response = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$AuthPort/healthz" `
                -SkipHttpErrorCheck `
                -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                return ($response.Content | ConvertFrom-Json)
            }
            $last = "HTTP $($response.StatusCode)"
        } catch {
            $last = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 300
    }
    throw "enterprise-auth did not become healthy: $last"
}

function Show-JobLogs {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Jobs)
    foreach ($entry in $Jobs.GetEnumerator()) {
        $lines = Receive-Job -Job $entry.Value -Keep -ErrorAction SilentlyContinue
        if ($lines) {
            Write-Host "--- $($entry.Key) ---"
            $lines | Select-Object -Last 30 | ForEach-Object { Write-Host ([string]$_) }
        }
    }
}

function New-RandomUrlToken {
    param([int]$Bytes = 32)
    $buffer = [byte[]]::new($Bytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    return [Convert]::ToBase64String($buffer).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function New-PkceChallenge {
    param([string]$Verifier)
    $digest = [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes($Verifier)
    )
    return [Convert]::ToBase64String($digest).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Resolve-HttpLocation {
    param(
        [Parameter(Mandatory = $true)][string]$Current,
        [Parameter(Mandatory = $true)][uri]$Location
    )
    if ($Location.IsAbsoluteUri) {
        return $Location.AbsoluteUri
    }
    return ([uri]::new([uri]$Current, $Location.OriginalString)).AbsoluteUri
}

function Get-Redirect {
    param(
        [Parameter(Mandatory = $true)][System.Net.Http.HttpClient]$Client,
        [Parameter(Mandatory = $true)][string]$Url
    )
    $response = $Client.GetAsync($Url).GetAwaiter().GetResult()
    try {
        $location = $response.Headers.Location
        return [pscustomobject]@{
            Status   = [int]$response.StatusCode
            Location = if ($location) { Resolve-HttpLocation -Current $Url -Location $location } else { "" }
        }
    } finally {
        $response.Dispose()
    }
}

function Get-OidcJoinCode {
    param(
        [Parameter(Mandatory = $true)][string]$AuthBase,
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][string]$Verifier
    )
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.CookieContainer = [System.Net.CookieContainer]::new()
    $client = [System.Net.Http.HttpClient]::new($handler)
    try {
        $returnTo = "http://127.0.0.1:45678/callback"
        $login = "$AuthBase/login" +
            "?return_to=$([uri]::EscapeDataString($returnTo))" +
            "&state=$([uri]::EscapeDataString($State))" +
            "&code_challenge=$([uri]::EscapeDataString((New-PkceChallenge -Verifier $Verifier)))"
        $started = Get-Redirect -Client $client -Url $login
        if ($started.Status -ne 302 -or -not $started.Location) {
            throw "enterprise-auth /login returned HTTP $($started.Status)"
        }
        $authorize = Get-Redirect -Client $client -Url $started.Location
        if ($authorize.Status -ne 302 -or -not $authorize.Location) {
            throw "mock OIDC /authorize returned HTTP $($authorize.Status)"
        }
        $callback = Get-Redirect -Client $client -Url $authorize.Location
        if ($callback.Status -ne 302 -or -not $callback.Location) {
            throw "enterprise-auth /oauth/callback returned HTTP $($callback.Status)"
        }
        $query = [System.Web.HttpUtility]::ParseQueryString(([uri]$callback.Location).Query)
        if ($query["state"] -cne $State) {
            throw "OIDC callback state does not match"
        }
        if (-not $query["code"]) {
            throw "OIDC callback has no join code"
        }
        return $query["code"]
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

function Start-AuthJob {
    param(
        [Parameter(Mandatory = $true)][string]$NodeExe,
        [Parameter(Mandatory = $true)][string]$AuthDir,
        [Parameter(Mandatory = $true)][hashtable]$Environment
    )
    return Start-Job -ScriptBlock {
        param($NodePath, $WorkingDirectory, $Values)
        Set-Location -LiteralPath $WorkingDirectory
        foreach ($entry in $Values.GetEnumerator()) {
            Set-Item -Path ("Env:" + $entry.Key) -Value ([string]$entry.Value)
        }
        & $NodePath src/server.js 2>&1
    } -ArgumentList $NodeExe, $AuthDir, $Environment
}

function Assert-Status {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][object]$Response,
        [Parameter(Mandatory = $true)][int]$Expected
    )
    if ($Response.StatusCode -ne $Expected) {
        throw "$Label returned HTTP $($Response.StatusCode), expected ${Expected}: $($Response.Content)"
    }
}

$magpiePath = (Resolve-Path -LiteralPath $Magpie).Path
$nodeCommand = Get-Command $Node -ErrorAction SilentlyContinue
if (-not $nodeCommand) {
    throw "node executable not found: $Node"
}
$nodePath = $nodeCommand.Source
$oidcScript = Join-Path $PSScriptRoot "mock-oidc.mjs"
$upstreamScript = Join-Path $PSScriptRoot "mock-upstream.mjs"
$authDir = Join-Path (Split-Path $PSScriptRoot -Parent) "auth-service"
$authServer = Join-Path $authDir "src\server.js"

foreach ($path in @($magpiePath, $oidcScript, $upstreamScript, $authServer)) {
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
$root = Join-Path $base ("magpie-enterprise-auth-e2e-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$serverDir = Join-Path $root "server"
$serverData = Join-Path $serverDir "data"
$sandboxHome = Join-Path $root "home"
$authData = Join-Path $root "auth"
New-Item -ItemType Directory -Path $serverData, $authData, $sandboxHome -Force | Out-Null
$serverExe = Join-Path $serverDir "magpie.exe"
Copy-Item -LiteralPath $magpiePath -Destination $serverExe

$issuerKey = "issuer-" + (New-RandomUrlToken -Bytes 36)
$adminToken = "admin-" + (New-RandomUrlToken -Bytes 36)
$cookieSecret = "cookie-" + (New-RandomUrlToken -Bytes 36)
$oidcClientId = "magpie-enterprise-e2e"
$oidcClientSecret = "oidc-" + (New-RandomUrlToken -Bytes 36)
$employeeEmail = "alice@corp.example"
$gatewayBase = "http://127.0.0.1:$GatewayPort"
$gatewayHost = Get-LocalIPv4
$remoteGatewayBase = "http://${gatewayHost}:$GatewayPort"
$authBase = "http://127.0.0.1:$AuthPort"
$oidcBase = "http://127.0.0.1:$OidcPort"
$jobs = [ordered]@{}
$authJob = $null
$succeeded = $false

$authEnvironment = @{
    AUTH_BIND = "127.0.0.1"
    AUTH_PORT = "$AuthPort"
    AUTH_PUBLIC_URL = $authBase
    AUTH_STORE_PATH = (Join-Path $authData "auth-store.json")
    AUTH_COOKIE_SECRET = $cookieSecret
    AUTH_ADMIN_TOKEN = $adminToken
    AUTH_SECURE_COOKIE = "false"
    AUTH_RATE_LIMIT_PER_MINUTE = "1000"
    OIDC_ISSUER = $oidcBase
    OIDC_CLIENT_ID = $oidcClientId
    OIDC_CLIENT_SECRET = $oidcClientSecret
    OIDC_REDIRECT_URI = "$authBase/oauth/callback"
    OIDC_ALLOWED_EMAIL_DOMAINS = "corp.example"
    MAGPIE_GATEWAY_URL = $gatewayBase
    MAGPIE_GATEWAY_PUBLIC_URL = $remoteGatewayBase
    MAGPIE_ISSUER_KEY = $issuerKey
    MAGPIE_KEY_TTL = "1h"
    MAGPIE_KEY_MODELS = "mock/mock-model"
    AUTH_DEVICE_TOKEN_TTL_DAYS = "30"
}

try {
    Write-Host "work folder: $root"

    $jobs.upstream = Start-Job -ScriptBlock {
        param($NodeExe, $Script, $Port)
        $env:PORT = "$Port"
        & $NodeExe $Script 2>&1
    } -ArgumentList $nodePath, $upstreamScript, $UpstreamPort
    Wait-Tcp -Port $UpstreamPort -Job $jobs.upstream

    $jobs.oidc = Start-Job -ScriptBlock {
        param($NodeExe, $Script, $Port, $ClientId, $ClientSecret, $Email)
        $env:PORT = "$Port"
        $env:CLIENT_ID = $ClientId
        $env:CLIENT_SECRET = $ClientSecret
        $env:EMPLOYEE_EMAIL = $Email
        & $NodeExe $Script 2>&1
    } -ArgumentList $nodePath, $oidcScript, $OidcPort, $oidcClientId, $oidcClientSecret, $employeeEmail
    Wait-Tcp -Port $OidcPort -Job $jobs.oidc

    Invoke-Magpie -Exe $serverExe -Arguments @(
        "provider", "add", "mock",
        "url=http://127.0.0.1:$UpstreamPort/v1",
        "key=test",
        "models=mock-model"
    ) | Out-Null

    $issuerKey | & $serverExe gateway-key add enterprise-auth --key - *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "could not create the enterprise-auth issuer key"
    }
    $keyRows = Invoke-Magpie -Exe $serverExe -Arguments @("gateway-key", "list")
    $issuerRow = $keyRows |
        Where-Object { $_ -match "^\s*\S+\s+enterprise-auth\s+" } |
        Select-Object -First 1
    if (-not $issuerRow) {
        throw "issuer key did not appear in gateway-key list"
    }
    $issuerId = [regex]::Match([string]$issuerRow, "^\s*(\S+)").Groups[1].Value
    if (-not $issuerId) {
        throw "could not parse the issuer key id"
    }
    Invoke-Magpie -Exe $serverExe -Arguments @("gateway-key", "issuer", $issuerId, "on") | Out-Null
    Write-Host "PASS  real Magpie issuer key created"

    $jobs.gateway = Start-Job -ScriptBlock {
        param($Exe, $Port, $HomePath)
        $env:MAGPIE_ADDR = "0.0.0.0:$Port"
        $env:HOME = $HomePath
        $env:USERPROFILE = $HomePath
        $env:APPDATA = Join-Path $HomePath "AppData\Roaming"
        $env:LOCALAPPDATA = Join-Path $HomePath "AppData\Local"
        $env:XDG_CONFIG_HOME = Join-Path $HomePath ".config"
        & $Exe serve 2>&1
    } -ArgumentList $serverExe, $GatewayPort, $sandboxHome
    Wait-Tcp -Port $GatewayPort -Job $jobs.gateway
    Wait-MagpieHealthy -Exe $serverExe -Port $GatewayPort -Job $jobs.gateway

    $authJob = Start-AuthJob -NodeExe $nodePath -AuthDir $authDir -Environment $authEnvironment
    $jobs.auth = $authJob
    Wait-Tcp -Port $AuthPort -Job $authJob
    Wait-AuthHealthy -Job $authJob | Out-Null

    $state = New-RandomUrlToken -Bytes 24
    $verifier = New-RandomUrlToken -Bytes 48
    $joinCode = Get-OidcJoinCode -AuthBase $authBase -State $state -Verifier $verifier
    $exchangeBody = @{
        code = $joinCode
        codeVerifier = $verifier
        device = @{
            name = "E2E Employee PC"
            platform = "windows"
            clientVersion = "enterprise-e2e"
        }
    } | ConvertTo-Json -Depth 6
    $exchange = Invoke-WebRequest `
        -Uri "$authBase/api/v1/join/exchange" `
        -Method Post `
        -ContentType "application/json" `
        -Body $exchangeBody `
        -SkipHttpErrorCheck `
        -TimeoutSec 30
    Assert-Status -Label "join/exchange" -Response $exchange -Expected 201
    $joined = $exchange.Content | ConvertFrom-Json
    if ($joined.user.email -ne $employeeEmail) {
        throw "join returned the wrong employee: $($joined.user.email)"
    }
    if (-not $joined.gateway.key -or -not $joined.gateway.keyId -or -not $joined.deviceToken) {
        throw "join returned an incomplete credential"
    }
    Write-Host "PASS  OIDC join issued a device credential"

    $headers = @{ Authorization = "Bearer $($joined.gateway.key)" }
    $models = Invoke-WebRequest `
        -Uri "$remoteGatewayBase/v1/models" `
        -Headers $headers `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "employee /v1/models" -Response $models -Expected 200

    $chatBody = @{
        model = "mock-model"
        messages = @(@{ role = "user"; content = "ping" })
    } | ConvertTo-Json -Depth 6
    $chat = Invoke-WebRequest `
        -Uri "$remoteGatewayBase/v1/chat/completions" `
        -Method Post `
        -Headers $headers `
        -ContentType "application/json" `
        -Body $chatBody `
        -SkipHttpErrorCheck `
        -TimeoutSec 30
    Assert-Status -Label "employee chat" -Response $chat -Expected 200
    $reply = $chat.Content | ConvertFrom-Json
    if ($reply.choices[0].message.content -ne "mock-upstream-ok") {
        throw "unexpected upstream reply: $($chat.Content)"
    }
    Write-Host "PASS  issued key reached the real gateway and mock upstream"

    $usagePath = Join-Path $serverData "usage.jsonl"
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    $usageLine = $null
    while ([DateTime]::UtcNow -lt $deadline -and -not $usageLine) {
        if (Test-Path -LiteralPath $usagePath) {
            $usageLine = Get-Content -LiteralPath $usagePath |
                Where-Object { $_ -match [regex]::Escape([string]$joined.gateway.keyId) } |
                Select-Object -Last 1
        }
        if (-not $usageLine) {
            Start-Sleep -Milliseconds 200
        }
    }
    if (-not $usageLine) {
        throw "usage.jsonl has no entry for the issued gateway key"
    }
    $usage = $usageLine | ConvertFrom-Json
    if ($usage.callerKeyId -ne $joined.gateway.keyId -or $usage.status -ne 200) {
        throw "unexpected usage attribution: $usageLine"
    }
    Write-Host "PASS  usage attributed to $($usage.callerKeyName)"

    $refresh = Invoke-WebRequest `
        -Uri "$authBase/api/v1/devices/refresh" `
        -Method Post `
        -Headers @{ Authorization = "Bearer $($joined.deviceToken)" } `
        -SkipHttpErrorCheck `
        -TimeoutSec 30
    Assert-Status -Label "device refresh" -Response $refresh -Expected 200
    $refreshed = $refresh.Content | ConvertFrom-Json
    if (-not $refreshed.gateway.key -or $refreshed.gateway.keyId -eq $joined.gateway.keyId) {
        throw "refresh did not rotate the gateway key"
    }

    $oldKey = Invoke-WebRequest `
        -Uri "$remoteGatewayBase/v1/models" `
        -Headers $headers `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "revoked old key" -Response $oldKey -Expected 401
    $newHeaders = @{ Authorization = "Bearer $($refreshed.gateway.key)" }
    $newKey = Invoke-WebRequest `
        -Uri "$remoteGatewayBase/v1/models" `
        -Headers $newHeaders `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "refreshed key" -Response $newKey -Expected 200
    Write-Host "PASS  refresh revoked the old key immediately and the new key works"

    $adminHeaders = @{ Authorization = "Bearer $adminToken" }
    $usersResponse = Invoke-WebRequest `
        -Uri "$authBase/api/v1/admin/users" `
        -Headers $adminHeaders `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "admin users" -Response $usersResponse -Expected 200
    $user = ($usersResponse.Content | ConvertFrom-Json).users[0]
    $disable = Invoke-WebRequest `
        -Uri "$authBase/api/v1/admin/users/$($user.id)/disable" `
        -Method Post `
        -Headers $adminHeaders `
        -SkipHttpErrorCheck `
        -TimeoutSec 30
    Assert-Status -Label "disable employee" -Response $disable -Expected 200

    $disabledKey = Invoke-WebRequest `
        -Uri "$remoteGatewayBase/v1/models" `
        -Headers $newHeaders `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "disabled employee key" -Response $disabledKey -Expected 401
    $deniedRefresh = Invoke-WebRequest `
        -Uri "$authBase/api/v1/devices/refresh" `
        -Method Post `
        -Headers @{ Authorization = "Bearer $($joined.deviceToken)" } `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "disabled device refresh" -Response $deniedRefresh -Expected 403
    $deniedHeartbeat = Invoke-WebRequest `
        -Uri "$authBase/api/v1/devices/heartbeat" `
        -Method Post `
        -Headers @{
            Authorization = "Bearer $($joined.deviceToken)"
            "Content-Type" = "application/json"
        } `
        -Body "{}" `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "disabled device heartbeat" -Response $deniedHeartbeat -Expected 403
    Write-Host "PASS  employee disable revoked the current key and device token access"

    Stop-Job -Job $authJob
    Wait-Job -Job $authJob -Timeout 10 | Out-Null
    Remove-Job -Job $authJob -Force
    Wait-TcpClosed -Port $AuthPort
    $jobs.Remove("auth")
    $authJob = Start-AuthJob -NodeExe $nodePath -AuthDir $authDir -Environment $authEnvironment
    $jobs.auth = $authJob
    Wait-Tcp -Port $AuthPort -Job $authJob
    $health = Wait-AuthHealthy -Job $authJob
    if ([int]$health.pendingRevocations -ne 0) {
        throw "restart left $($health.pendingRevocations) pending revocations"
    }
    $afterRestart = Invoke-WebRequest `
        -Uri "$authBase/api/v1/devices/refresh" `
        -Method Post `
        -Headers @{ Authorization = "Bearer $($joined.deviceToken)" } `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "refresh after restart" -Response $afterRestart -Expected 403
    Write-Host "PASS  auth restart kept device state and an empty revocation queue"

    $storePath = $authEnvironment.AUTH_STORE_PATH
    $storeText = Get-Content -LiteralPath $storePath -Raw
    foreach ($secret in @($joined.gateway.key, $joined.deviceToken, $issuerKey, $oidcClientSecret)) {
        if ($storeText.Contains($secret)) {
            throw "auth store contains a plaintext credential"
        }
    }
    Write-Host "PASS  auth store holds hashes and identifiers, not plaintext keys"

    $succeeded = $true
    Write-Host "PASS  M1 real Magpie issuer end-to-end"
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
            (Split-Path $resolvedRoot -Leaf) -like "magpie-enterprise-auth-e2e-*") {
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        }
    } else {
        Write-Host "logs and portable data kept in: $root"
    }
}
