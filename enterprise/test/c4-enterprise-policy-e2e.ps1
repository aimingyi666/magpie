<#
.SYNOPSIS
Verify the enterprise policy path from the management UI API to real Magpie.

.DESCRIPTION
Starts isolated instances of the mock upstream, employee OIDC, management
OIDC, real Magpie, gateway-control, auth-service and admin-service. The test
then exercises first-login policy setup, employee joins, policy writes,
model denial, token limits, partial credential failure, refresh/rotation,
gateway-control outage, reconciliation, usage attribution and secret
non-disclosure.

All services share one isolated Magpie config directory. No Docker, shared
production volume, external identity provider or browser is used.

.EXAMPLE
.\c4-enterprise-policy-e2e.ps1 -Magpie C:\path\to\magpie.exe -Node C:\path\to\node.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Magpie,
    [string]$Node = "node",
    [string]$WorkDir,
    [switch]$Keep
)

$ErrorActionPreference = "Stop"

function Get-FreeTcpPort {
    param([int[]]$Avoid = @())

    for ($attempt = 0; $attempt -lt 30; $attempt++) {
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
        [int]$TimeoutSec = 30,
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
        [int]$TimeoutSec = 20
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

function Wait-HttpHealthy {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][object]$Job,
        [string]$Label = $Url,
        [int]$TimeoutSec = 30
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    $last = ""
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($Job.State -ne "Running") {
            $details = Receive-Job -Job $Job -Keep -ErrorAction SilentlyContinue
            throw "$Label stopped before becoming healthy`n" + ($details -join "`n")
        }
        try {
            $response = Invoke-WebRequest `
                -Uri $Url `
                -SkipHttpErrorCheck `
                -TimeoutSec 5
            if ([int]$response.StatusCode -eq 200) {
                return
            }
            $last = "HTTP $($response.StatusCode)"
        } catch {
            $last = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 250
    }
    throw "$Label did not become healthy: $last"
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
                throw "magpie stopped before becoming healthy`n" + ($details -join "`n")
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
    throw "magpie did not become healthy: $last"
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

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw $Message
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

function ConvertFrom-JsonOrThrow {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$Label
    )

    try {
        return $Text | ConvertFrom-Json
    } catch {
        throw "$Label returned invalid JSON: $Text"
    }
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
        throw "no non-loopback IPv4 address is available for the gateway test"
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
        Assert-True ($started.Status -eq 302 -and [bool]$started.Location) `
            "employee auth /login returned HTTP $($started.Status)"
        $authorize = Get-Redirect -Client $client -Url $started.Location
        Assert-True ($authorize.Status -eq 302 -and [bool]$authorize.Location) `
            "employee OIDC /authorize returned HTTP $($authorize.Status)"
        $callback = Get-Redirect -Client $client -Url $authorize.Location
        Assert-True ($callback.Status -eq 302 -and [bool]$callback.Location) `
            "employee auth /oauth/callback returned HTTP $($callback.Status)"
        $query = [System.Web.HttpUtility]::ParseQueryString(([uri]$callback.Location).Query)
        Assert-True ($query["state"] -ceq $State) "employee OIDC callback state did not match"
        Assert-True ([bool]$query["code"]) "employee OIDC callback has no join code"
        return $query["code"]
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

function New-JoinCredential {
    param(
        [Parameter(Mandatory = $true)][string]$AuthBase,
        [Parameter(Mandatory = $true)][string]$DeviceName,
        [int]$ExpectedStatus = 201
    )

    $state = New-RandomUrlToken -Bytes 24
    $verifier = New-RandomUrlToken -Bytes 48
    $joinCode = Get-OidcJoinCode -AuthBase $AuthBase -State $state -Verifier $verifier
    $body = @{
        code = $joinCode
        codeVerifier = $verifier
        device = @{
            name = $DeviceName
            platform = "windows"
            clientVersion = "enterprise-c4-e2e"
        }
    } | ConvertTo-Json -Depth 6 -Compress
    $response = Invoke-WebRequest `
        -Uri "$AuthBase/api/v1/join/exchange" `
        -Method Post `
        -ContentType "application/json" `
        -Body $body `
        -SkipHttpErrorCheck `
        -TimeoutSec 30
    Assert-Status -Label "join/exchange ($DeviceName)" -Response $response -Expected $ExpectedStatus
    return [pscustomobject]@{
        Response = $response
        Body     = if ($response.Content) { $response.Content | ConvertFrom-Json } else { $null }
    }
}

function Start-NodeJob {
    param(
        [Parameter(Mandatory = $true)][string]$NodeExe,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][hashtable]$Environment
    )

    return Start-Job -ScriptBlock {
        param($NodePath, $Directory, $Script, $Values)
        Set-Location -LiteralPath $Directory
        foreach ($entry in $Values.GetEnumerator()) {
            Set-Item -Path ("Env:" + $entry.Key) -Value ([string]$entry.Value)
        }
        & $NodePath $Script 2>&1
    } -ArgumentList $NodeExe, $WorkingDirectory, $ScriptPath, $Environment
}

function Start-MagpieJob {
    param(
        [Parameter(Mandatory = $true)][string]$Exe,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][string]$WebKey,
        [Parameter(Mandatory = $true)][string]$SharedConfig
    )

    return Start-Job -ScriptBlock {
        param($Executable, $GatewayPort, $PagePort, $PageKey, $ConfigHome)
        $env:MAGPIE_ADDR = "0.0.0.0:$GatewayPort"
        $env:MAGPIE_WEB_KEY = $PageKey
        $env:XDG_CONFIG_HOME = $ConfigHome
        & $Executable serve "--web=127.0.0.1:$PagePort" 2>&1
    } -ArgumentList $Exe, $Port, $WebPort, $WebKey, $SharedConfig
}

function Show-JobLogs {
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Jobs)

    foreach ($entry in $Jobs.GetEnumerator()) {
        $lines = Receive-Job -Job $entry.Value -Keep -ErrorAction SilentlyContinue
        if ($lines) {
            Write-Host "--- $($entry.Key) ---"
            $lines | Select-Object -Last 50 | ForEach-Object { Write-Host ([string]$_) }
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
        [Parameter(Mandatory = $true)][string]$Base,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][string]$Model
    )

    $headers = @{ Authorization = "Bearer $Key" }
    $body = @{
        model    = $Model
        messages = @(@{ role = "user"; content = "enterprise policy e2e" })
    } | ConvertTo-Json -Depth 6 -Compress
    return Invoke-WebRequest `
        -Uri "$Base/v1/chat/completions" `
        -Method Post `
        -Headers $headers `
        -ContentType "application/json" `
        -Body $body `
        -SkipHttpErrorCheck `
        -TimeoutSec 30
}

function Set-GatewayKeyState {
    param(
        [Parameter(Mandatory = $true)][string]$KeyId,
        [Parameter(Mandatory = $true)][ValidateSet("off-key", "on-key")][string]$Action
    )

    if ($null -eq $script:webSession) {
        $script:webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
        $signIn = Invoke-WebRequest `
            -Uri "$WebBase/?k=$([uri]::EscapeDataString($WebKey))" `
            -WebSession $script:webSession `
            -MaximumRedirection 1 `
            -SkipHttpErrorCheck `
            -TimeoutSec 20
        Assert-True ([int]$signIn.StatusCode -eq 200) `
            "magpie web sign-in returned HTTP $($signIn.StatusCode)"
    }
    $body = @{ key = $KeyId } | ConvertTo-Json -Compress
    $response = Invoke-WebRequest `
        -Uri "$WebBase/api/caller-keys/$Action" `
        -Method Post `
        -WebSession $script:webSession `
        -Headers @{ Origin = $WebBase } `
        -ContentType "application/json" `
        -Body $body `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "caller-keys/$Action" -Response $response -Expected 200
    [void]$safeOutputs.Add([string]$response.Content)
}

function Invoke-AdminHttp {
    param(
        [Parameter(Mandatory = $true)][object]$Session,
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][string]$Body = $null,
        [hashtable]$Headers = @{}
    )

    $request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::new($Method),
        "$AdminBase$Path"
    )
    try {
        if ($null -ne $Body) {
            $request.Content = [System.Net.Http.StringContent]::new(
                $Body,
                [System.Text.Encoding]::UTF8,
                "application/json"
            )
        }
        foreach ($entry in $Headers.GetEnumerator()) {
            [void]$request.Headers.TryAddWithoutValidation([string]$entry.Key, [string]$entry.Value)
        }
        $response = $Session.Client.SendAsync($request).GetAwaiter().GetResult()
        try {
            $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            $contentType = $response.Content.Headers.ContentType
            $isJson = $contentType -and
                $contentType.MediaType -and
                $contentType.MediaType.Contains("json", [System.StringComparison]::OrdinalIgnoreCase)
            return [pscustomobject]@{
                StatusCode = [int]$response.StatusCode
                Content    = $text
                Headers    = $response.Headers
                Json       = if ($text -and $isJson) {
                    ConvertFrom-JsonOrThrow -Text $text -Label "admin $Method $Path"
                } else {
                    $null
                }
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        $request.Dispose()
    }
}

function New-AdminSession {
    param(
        [Parameter(Mandatory = $true)][string]$Base,
        [Parameter(Mandatory = $true)][string]$Email
    )

    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.CookieContainer = [System.Net.CookieContainer]::new()
    $client = [System.Net.Http.HttpClient]::new($handler)
    try {
        $started = Get-Redirect -Client $client -Url "$Base/admin/login"
        Assert-True ($started.Status -eq 302 -and [bool]$started.Location) `
            "admin /login returned HTTP $($started.Status)"
        $authorize = Get-Redirect -Client $client -Url $started.Location
        Assert-True ($authorize.Status -eq 302 -and [bool]$authorize.Location) `
            "management OIDC /authorize returned HTTP $($authorize.Status)"
        $callback = Get-Redirect -Client $client -Url $authorize.Location
        Assert-True ($callback.Status -eq 302 -and $callback.Location -like "*/admin/") `
            "admin /oauth/callback returned HTTP $($callback.Status) to $($callback.Location)"

        $session = [pscustomobject]@{
            Client = $client
            Handler = $handler
            Email = $Email
            CsrfToken = ""
        }
        $me = Invoke-AdminHttp -Session $session -Method "GET" -Path "/api/v1/admin/me"
        Assert-True ($me.StatusCode -eq 200) "admin /me returned HTTP $($me.StatusCode): $($me.Content)"
        [void]$safeOutputs.Add([string]$me.Content)
        Assert-True ($me.Json.user.email -eq $Email) "admin login returned the wrong email: $($me.Json.user.email)"
        Assert-True (@($me.Json.roles) -contains "super_admin") "bootstrap admin did not receive super_admin"
        Assert-True ([bool]$me.Json.csrfToken) "admin /me did not return a CSRF token"
        $session.CsrfToken = [string]$me.Json.csrfToken
        return $session
    } catch {
        $client.Dispose()
        $handler.Dispose()
        throw
    }
}

function Invoke-AdminRead {
    param(
        [Parameter(Mandatory = $true)][object]$Session,
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$ExpectedStatus = 200
    )

    $response = Invoke-AdminHttp -Session $Session -Method "GET" -Path $Path
    [void]$safeOutputs.Add([string]$response.Content)
    Assert-True ($response.StatusCode -eq $ExpectedStatus) `
        "admin GET $Path returned HTTP $($response.StatusCode): $($response.Content)"
    return $response.Json
}

function Invoke-AdminPolicyWrite {
    param(
        [Parameter(Mandatory = $true)][object]$Session,
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Payload,
        [Parameter(Mandatory = $true)][string]$IdempotencyKey
    )

    $body = $Payload | ConvertTo-Json -Depth 12 -Compress
    $headers = @{
        Origin = $AdminBase
        "x-csrf-token" = $Session.CsrfToken
        "Idempotency-Key" = $IdempotencyKey
    }
    $response = Invoke-AdminHttp `
        -Session $Session `
        -Method $Method `
        -Path $Path `
        -Body $body `
        -Headers $headers
    [void]$safeOutputs.Add([string]$response.Content)
    Assert-True ($response.StatusCode -eq 200) `
        "admin $Method $Path returned HTTP $($response.StatusCode): $($response.Content)"
    Assert-True ($response.Json.ok -eq $true) "admin policy write did not return ok=true"
    Assert-True ([bool]$response.Json.operationId) "admin policy write returned no operationId"
    Assert-True ([bool]$response.Json.result.operationId) "admin policy write returned no result operationId"
    return $response.Json
}

function Assert-Credentials {
    param(
        [Parameter(Mandatory = $true)][object]$Summary,
        [int]$Total,
        [int]$Succeeded,
        [int]$Failed,
        [int]$Unknown,
        [int]$FailedItems
    )

    Assert-True ([int]$Summary.total -eq $Total) "credential total was $($Summary.total), expected $Total"
    Assert-True ([int]$Summary.succeeded -eq $Succeeded) `
        "credential succeeded was $($Summary.succeeded), expected $Succeeded"
    Assert-True ([int]$Summary.failed -eq $Failed) "credential failed was $($Summary.failed), expected $Failed"
    Assert-True ([int]$Summary.unknown -eq $Unknown) "credential unknown was $($Summary.unknown), expected $Unknown"
    Assert-True (@($Summary.failedItems).Count -eq $FailedItems) `
        "credential failedItems count was $(@($Summary.failedItems).Count), expected $FailedItems"
}

function Assert-NoSecret {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string[]]$Secrets
    )

    foreach ($secret in $Secrets) {
        if ($secret -and $Text.Contains($secret, [System.StringComparison]::Ordinal)) {
            throw "$Label contains a plaintext protected value"
        }
    }
}

$magpiePath = (Resolve-Path -LiteralPath $Magpie).Path
$nodeCommand = Get-Command $Node -ErrorAction SilentlyContinue
if (-not $nodeCommand) {
    throw "node executable not found: $Node"
}
$nodePath = $nodeCommand.Source
$testDir = $PSScriptRoot
$repoRoot = Split-Path $testDir -Parent | Split-Path -Parent
$oidcScript = Join-Path $testDir "mock-oidc.mjs"
$upstreamScript = Join-Path $testDir "mock-upstream.mjs"
$gatewayDir = Join-Path $repoRoot "enterprise/gateway-control"
$authDir = Join-Path $repoRoot "enterprise/auth-service"
$adminDir = Join-Path $repoRoot "enterprise/admin-service"

foreach ($path in @(
    $magpiePath,
    $oidcScript,
    $upstreamScript,
    (Join-Path $gatewayDir "src/server.js"),
    (Join-Path $authDir "src/server.js"),
    (Join-Path $adminDir "src/server.js")
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "required file not found: $path"
    }
}

$usedPorts = @()
$UpstreamPort = Get-FreeTcpPort -Avoid $usedPorts
$usedPorts += $UpstreamPort
$EmployeeOidcPort = Get-FreeTcpPort -Avoid $usedPorts
$usedPorts += $EmployeeOidcPort
$AdminOidcPort = Get-FreeTcpPort -Avoid $usedPorts
$usedPorts += $AdminOidcPort
$GatewayPort = Get-FreeTcpPort -Avoid $usedPorts
$usedPorts += $GatewayPort
$WebPort = Get-FreeTcpPort -Avoid $usedPorts
$usedPorts += $WebPort
$GatewayControlPort = Get-FreeTcpPort -Avoid $usedPorts
$usedPorts += $GatewayControlPort
$AuthPort = Get-FreeTcpPort -Avoid $usedPorts
$usedPorts += $AuthPort
$AdminPort = Get-FreeTcpPort -Avoid $usedPorts

$base = if ($WorkDir) {
    [System.IO.Path]::GetFullPath($WorkDir)
} else {
    [System.IO.Path]::GetTempPath()
}
New-Item -ItemType Directory -Path $base -Force | Out-Null
$root = Join-Path $base ("magpie-enterprise-c4-e2e-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$serverDir = Join-Path $root "server"
$sandboxHome = Join-Path $root "home"
$sharedConfig = Join-Path $root "shared-config"
$serviceData = Join-Path $root "service-data"
New-Item -ItemType Directory -Path $serverDir, $sandboxHome, $sharedConfig, $serviceData -Force | Out-Null
$serverExe = Join-Path $serverDir "magpie.exe"
Copy-Item -LiteralPath $magpiePath -Destination $serverExe

$catalogPath = Join-Path $root "model-catalog.json"
$usagePath = Join-Path $sharedConfig "magpie/usage.jsonl"
New-Item -ItemType Directory -Path (Split-Path $usagePath -Parent) -Force | Out-Null
New-Item -ItemType File -Path $usagePath -Force | Out-Null
$catalog = [ordered]@{
    schemaVersion = 1
    models = @(
        [ordered]@{
            id = "mock/mock-model"
            provider = "mock"
            displayName = "Mock Model"
        },
        [ordered]@{
            id = "mock/mock-second"
            provider = "mock"
            displayName = "Mock Second"
        }
    )
    groups = [ordered]@{
        approved = @("mock/mock-model", "mock/mock-second")
    }
}
$catalog | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $catalogPath -Encoding utf8NoBOM

$employeeOidcClientId = "magpie-employee-e2e"
$adminOidcClientId = "magpie-admin-e2e"
$employeeOidcSecret = "eoidc-" + (New-RandomUrlToken -Bytes 40)
$adminOidcSecret = "aoidc-" + (New-RandomUrlToken -Bytes 40)
$issuerKey = "issuer-" + (New-RandomUrlToken -Bytes 40)
$authAdminToken = "authadmin-" + (New-RandomUrlToken -Bytes 40)
$internalAdminToken = "internal-" + (New-RandomUrlToken -Bytes 40)
$authCookieSecret = "authcookie-" + (New-RandomUrlToken -Bytes 40)
$gatewayControlToken = "control-" + (New-RandomUrlToken -Bytes 40)
$adminSessionSecret = "adminsession-" + (New-RandomUrlToken -Bytes 40)
$WebKey = "web-" + (New-RandomUrlToken -Bytes 40)
$employeeEmail = "alice@corp.example"
$adminEmail = "admin@corp.example"

$gatewayHost = Get-LocalIPv4
$gatewayBase = "http://127.0.0.1:$GatewayPort"
$remoteGatewayBase = "http://${gatewayHost}:$GatewayPort"
$WebBase = "http://127.0.0.1:$WebPort"
$employeeOidcBase = "http://127.0.0.1:$EmployeeOidcPort"
$adminOidcBase = "http://127.0.0.1:$AdminOidcPort"
$gatewayControlBase = "http://127.0.0.1:$GatewayControlPort"
$authBase = "http://127.0.0.1:$AuthPort"
$AdminBase = "http://127.0.0.1:$AdminPort"

$authStorePath = Join-Path $serviceData "auth-store.json"
$adminStorePath = Join-Path $serviceData "admin-store.json"
$callerKeysPath = Join-Path $sharedConfig "magpie/caller-keys.json"

$jobs = [ordered]@{}
$adminSession = $null
$script:webSession = $null
$succeeded = $false
$safeOutputs = [System.Collections.Generic.List[string]]::new()
$envNames = @(
    "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
    "MAGPIE_ADDR"
)
$savedEnv = @{}
foreach ($name in $envNames) {
    $savedEnv[$name] = [System.Environment]::GetEnvironmentVariable($name, "Process")
}

$gatewayControlEnvironment = @{
    GATEWAY_CONTROL_BIND = "127.0.0.1"
    GATEWAY_CONTROL_PORT = "$GatewayControlPort"
    GATEWAY_CONTROL_TOKEN = $gatewayControlToken
    GATEWAY_CONTROL_MAGPIE = $serverExe
    GATEWAY_CONTROL_CONFIG_HOME = $sharedConfig
    GATEWAY_CONTROL_TIMEOUT_MS = "10000"
}
$authEnvironment = @{
    AUTH_BIND = "127.0.0.1"
    AUTH_PORT = "$AuthPort"
    AUTH_PUBLIC_URL = $authBase
    AUTH_STORE_PATH = $authStorePath
    AUTH_COOKIE_SECRET = $authCookieSecret
    AUTH_ADMIN_TOKEN = $authAdminToken
    AUTH_INTERNAL_ADMIN_TOKEN = $internalAdminToken
    AUTH_SECURE_COOKIE = "false"
    AUTH_RATE_LIMIT_PER_MINUTE = "1000"
    AUTH_DEVICE_TOKEN_TTL_DAYS = "30"
    OIDC_ISSUER = $employeeOidcBase
    OIDC_CLIENT_ID = $employeeOidcClientId
    OIDC_CLIENT_SECRET = $employeeOidcSecret
    OIDC_REDIRECT_URI = "$authBase/oauth/callback"
    OIDC_ALLOWED_EMAIL_DOMAINS = "corp.example"
    MAGPIE_GATEWAY_URL = $gatewayBase
    MAGPIE_GATEWAY_PUBLIC_URL = $remoteGatewayBase
    MAGPIE_ISSUER_KEY = $issuerKey
    MAGPIE_KEY_TTL = "1h"
    MAGPIE_KEY_MODELS = "mock/mock-model,mock/mock-second"
    GATEWAY_CONTROL_URL = $gatewayControlBase
    GATEWAY_CONTROL_TOKEN = $gatewayControlToken
    GATEWAY_CONTROL_TIMEOUT_MS = "10000"
    XDG_CONFIG_HOME = $sharedConfig
}
$adminEnvironment = @{
    ADMIN_BIND = "127.0.0.1"
    ADMIN_PORT = "$AdminPort"
    ADMIN_PUBLIC_URL = $AdminBase
    ADMIN_STORE_PATH = $adminStorePath
    ADMIN_SESSION_SECRET = $adminSessionSecret
    ADMIN_SECURE_COOKIE = "false"
    ADMIN_RATE_LIMIT_PER_MINUTE = "1000"
    ADMIN_ALLOWED_IPS = "127.0.0.1/32,::1/128"
    ADMIN_OIDC_ISSUER = $adminOidcBase
    ADMIN_OIDC_CLIENT_ID = $adminOidcClientId
    ADMIN_OIDC_CLIENT_SECRET = $adminOidcSecret
    ADMIN_OIDC_REDIRECT_URI = "$AdminBase/admin/oauth/callback"
    ADMIN_ALLOWED_EMAIL_DOMAINS = "corp.example"
    ADMIN_BOOTSTRAP_EMAILS = $adminEmail
    ADMIN_REQUIRE_MFA = "false"
    ADMIN_REQUIRE_VERIFIED_EMAIL = "false"
    ADMIN_AUTH_SERVICE_URL = $authBase
    ADMIN_AUTH_SERVICE_TOKEN = $internalAdminToken
    ADMIN_MODEL_CATALOG_PATH = $catalogPath
    ADMIN_USAGE_PATH = $usagePath
    XDG_CONFIG_HOME = $sharedConfig
}

try {
    $env:HOME = $sandboxHome
    $env:USERPROFILE = $sandboxHome
    $env:APPDATA = Join-Path $sandboxHome "AppData/Roaming"
    $env:LOCALAPPDATA = Join-Path $sandboxHome "AppData/Local"
    $env:XDG_CONFIG_HOME = $sharedConfig
    $env:XDG_DATA_HOME = Join-Path $sandboxHome ".local/share"
    $env:XDG_CACHE_HOME = Join-Path $sandboxHome ".cache"
    $env:XDG_STATE_HOME = Join-Path $sandboxHome ".local/state"
    $env:MAGPIE_ADDR = "127.0.0.1:$GatewayPort"

    Write-Host "work folder: $root"
    Write-Host "gateway address: $remoteGatewayBase"
    Write-Host "admin console: $AdminBase/admin/"

    $jobs.upstream = Start-NodeJob `
        -NodeExe $nodePath `
        -WorkingDirectory $testDir `
        -ScriptPath $upstreamScript `
        -Environment @{ PORT = "$UpstreamPort" }
    Wait-Tcp -Port $UpstreamPort -Job $jobs.upstream
    if ((Get-MockStats).ChatRequests -ne 0) {
        throw "mock upstream did not start with an empty request count"
    }

    $jobs.employeeOidc = Start-NodeJob `
        -NodeExe $nodePath `
        -WorkingDirectory $testDir `
        -ScriptPath $oidcScript `
        -Environment @{
            PORT = "$EmployeeOidcPort"
            CLIENT_ID = $employeeOidcClientId
            CLIENT_SECRET = $employeeOidcSecret
            EMPLOYEE_SUB = "employee-alice"
            EMPLOYEE_EMAIL = $employeeEmail
            EMPLOYEE_NAME = "Alice Zhang"
        }
    Wait-Tcp -Port $EmployeeOidcPort -Job $jobs.employeeOidc

    $jobs.adminOidc = Start-NodeJob `
        -NodeExe $nodePath `
        -WorkingDirectory $testDir `
        -ScriptPath $oidcScript `
        -Environment @{
            PORT = "$AdminOidcPort"
            CLIENT_ID = $adminOidcClientId
            CLIENT_SECRET = $adminOidcSecret
            EMPLOYEE_SUB = "admin-alice"
            EMPLOYEE_EMAIL = $adminEmail
            EMPLOYEE_NAME = "Admin Alice"
        }
    Wait-Tcp -Port $AdminOidcPort -Job $jobs.adminOidc

    $provider = Invoke-MagpieProcess -Exe $serverExe -Arguments @(
        "provider", "add", "mock",
        "url=http://127.0.0.1:$UpstreamPort/v1",
        "key=test",
        "models=mock-model,mock-second"
    )
    Assert-ExitCode -Label "provider add" -Result $provider

    $issuerAdd = Invoke-MagpieProcess `
        -Exe $serverExe `
        -Arguments @("gateway-key", "add", "enterprise-issuer", "--key", "-") `
        -InputText $issuerKey
    Assert-ExitCode -Label "issuer key add" -Result $issuerAdd
    $issuerRows = Invoke-MagpieProcess -Exe $serverExe -Arguments @("gateway-key", "list")
    Assert-ExitCode -Label "gateway-key list" -Result $issuerRows
    $issuerRow = $issuerRows.Lines |
        Where-Object { $_ -match "^\s*\S+\s+enterprise-issuer\s+" } |
        Select-Object -First 1
    if (-not $issuerRow) {
        throw "issuer key did not appear in gateway-key list"
    }
    $issuerId = [regex]::Match([string]$issuerRow, "^\s*(\S+)").Groups[1].Value
    if (-not $issuerId) {
        throw "could not parse the issuer key id"
    }
    $issuerOn = Invoke-MagpieProcess `
        -Exe $serverExe `
        -Arguments @("gateway-key", "issuer", $issuerId, "on")
    Assert-ExitCode -Label "issuer key enable" -Result $issuerOn

    $jobs.gateway = Start-MagpieJob `
        -Exe $serverExe `
        -Port $GatewayPort `
        -WebPort $WebPort `
        -WebKey $WebKey `
        -SharedConfig $sharedConfig
    Wait-Tcp -Port $GatewayPort -Job $jobs.gateway
    Wait-Tcp -Port $WebPort -Job $jobs.gateway
    Wait-MagpieHealthy -Exe $serverExe -Port $GatewayPort -Job $jobs.gateway

    $jobs.gatewayControl = Start-NodeJob `
        -NodeExe $nodePath `
        -WorkingDirectory $gatewayDir `
        -ScriptPath (Join-Path $gatewayDir "src/server.js") `
        -Environment $gatewayControlEnvironment
    Wait-Tcp -Port $GatewayControlPort -Job $jobs.gatewayControl
    Wait-HttpHealthy `
        -Url "$gatewayControlBase/healthz" `
        -Job $jobs.gatewayControl `
        -Label "gateway-control"

    $jobs.auth = Start-NodeJob `
        -NodeExe $nodePath `
        -WorkingDirectory $authDir `
        -ScriptPath (Join-Path $authDir "src/server.js") `
        -Environment $authEnvironment
    Wait-Tcp -Port $AuthPort -Job $jobs.auth
    Wait-HttpHealthy -Url "$authBase/healthz" -Job $jobs.auth -Label "auth-service"

    $jobs.admin = Start-NodeJob `
        -NodeExe $nodePath `
        -WorkingDirectory $adminDir `
        -ScriptPath (Join-Path $adminDir "src/server.js") `
        -Environment $adminEnvironment
    Wait-Tcp -Port $AdminPort -Job $jobs.admin
    Write-Host "PASS  isolated real Magpie and enterprise services are running"

    $blocked = New-JoinCredential `
        -AuthBase $authBase `
        -DeviceName "Policy Missing PC" `
        -ExpectedStatus 409
    if ($blocked.Body.error.code -ne "policy_setup_required") {
        throw "first join returned the wrong policy gate: $($blocked.Response.Content)"
    }
    if (@($blocked.Body.error.missing) -notcontains "quota" -or
        @($blocked.Body.error.missing) -notcontains "models") {
        throw "first join did not report both missing policy parts: $($blocked.Response.Content)"
    }
    [void]$safeOutputs.Add([string]$blocked.Response.Content)
    Write-Host "PASS  unknown policy blocked credential issuance"

    $adminSession = New-AdminSession -Base $AdminBase -Email $adminEmail
    $users = Invoke-AdminRead -Session $adminSession -Path "/api/v1/admin/users"
    $alice = @($users.users | Where-Object { $_.email -eq $employeeEmail }) | Select-Object -First 1
    if (-not $alice) {
        throw "management users did not include the OIDC employee"
    }
    Assert-True ([int]$alice.policy.version -eq 0) "new employee policy version was not 0"
    Assert-True ($alice.policy.quotaStatus -eq "unknown") "new employee quota status was not unknown"
    Assert-True ($alice.policy.modelStatus -eq "unknown") "new employee model status was not unknown"
    $userId = [string]$alice.id

    $quotaWrite = Invoke-AdminPolicyWrite `
        -Session $adminSession `
        -Method "PUT" `
        -Path "/api/v1/admin/users/$userId/policy/quota" `
        -Payload @{
            reason = "Initialize the employee monthly allowance"
            expectedVersion = 0
            limits = @()
        } `
        -IdempotencyKey "c4-quota-initial-$userId"
    Assert-True ([int]$quotaWrite.result.policy.version -eq 1) "initial quota write did not advance version to 1"
    Assert-True (@($quotaWrite.result.policy.missing) -contains "models") `
        "initial quota write did not report the missing model policy"

    $modelsWrite = Invoke-AdminPolicyWrite `
        -Session $adminSession `
        -Method "PATCH" `
        -Path "/api/v1/admin/users/$userId/policy/models" `
        -Payload @{
            reason = "Grant the approved gateway models"
            expectedVersion = 1
            models = @("mock/mock-model", "mock/mock-second")
        } `
        -IdempotencyKey "c4-models-initial-$userId"
    Assert-True ($modelsWrite.result.state -eq "succeeded") `
        "initial model policy did not succeed: $($modelsWrite.result.state)"
    Assert-True ([int]$modelsWrite.result.policy.version -eq 2) "initial model write did not advance version to 2"
    Assert-True ($modelsWrite.result.policy.quotaStatus -eq "known") "quota status was not known after setup"
    Assert-True ($modelsWrite.result.policy.modelStatus -eq "known") "model status was not known after setup"
    Assert-True (-not [bool]$modelsWrite.result.requiresReconciliation) `
        "successful initial policy still required reconciliation"
    Write-Host "PASS  administrator initialized quota and models before issuance"

    $firstJoin = New-JoinCredential -AuthBase $authBase -DeviceName "Alice Workstation"
    $secondJoin = New-JoinCredential -AuthBase $authBase -DeviceName "Alice Laptop"
    $first = $firstJoin.Body
    $second = $secondJoin.Body
    foreach ($joined in @($first, $second)) {
        Assert-True ([int]$joined.policyVersion -eq 2) "join did not use policy version 2"
        Assert-True ($joined.gateway.url -eq $remoteGatewayBase) "join returned the wrong gateway URL"
        Assert-True ([bool]$joined.deviceToken) "join returned no device token"
        Assert-True ([bool]$joined.gateway.key) "join returned no gateway key"
        Assert-True ([bool]$joined.gateway.keyId) "join returned no gateway key id"
        Assert-True (@($joined.gateway.models).Count -eq 2) "join returned the wrong model set"
    }
    if ($first.gateway.keyId -eq $second.gateway.keyId) {
        throw "two devices received the same gateway key"
    }
    Write-Host "PASS  two OIDC joins received independently synchronized credentials"

    $beforeAllowed = Get-MockStats
    $allowed = Send-Chat -Base $remoteGatewayBase -Key $first.gateway.key -Model "mock/mock-model"
    Assert-Status -Label "policy-allowed employee chat" -Response $allowed -Expected 200
    if (($allowed.Content | ConvertFrom-Json).choices[0].message.content -ne "mock-upstream-ok") {
        throw "policy-allowed employee chat returned an unexpected upstream reply"
    }
    $afterAllowed = Get-MockStats
    Assert-True ($afterAllowed.ChatRequests -eq $beforeAllowed.ChatRequests + 1) `
        "allowed employee chat did not reach the upstream exactly once"

    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    $usageLine = $null
    while ([DateTime]::UtcNow -lt $deadline -and -not $usageLine) {
        if (Test-Path -LiteralPath $usagePath) {
            $usageLine = Get-Content -LiteralPath $usagePath |
                Where-Object { $_ -match [regex]::Escape([string]$first.gateway.keyId) } |
                Select-Object -Last 1
        }
        if (-not $usageLine) {
            Start-Sleep -Milliseconds 200
        }
    }
    if (-not $usageLine) {
        throw "usage.jsonl did not attribute the successful employee request"
    }
    Write-Host "PASS  policy-allowed chat reached the upstream and was attributed"

    $restrictModels = Invoke-AdminPolicyWrite `
        -Session $adminSession `
        -Method "PATCH" `
        -Path "/api/v1/admin/users/$userId/policy/models" `
        -Payload @{
            reason = "Remove the second model from the employee"
            expectedVersion = 2
            models = @("mock/mock-model")
        } `
        -IdempotencyKey "c4-models-deny-$userId"
    Assert-True ($restrictModels.result.state -eq "succeeded") `
        "model restriction did not synchronize both credentials"
    Assert-Credentials -Summary $restrictModels.result.credentials `
        -Total 2 -Succeeded 2 -Failed 0 -Unknown 0 -FailedItems 0

    $beforeDenied = Get-MockStats
    $denied = Send-Chat -Base $remoteGatewayBase -Key $first.gateway.key -Model "mock/mock-second"
    Assert-Status -Label "model-denied employee chat" -Response $denied -Expected 403
    $afterDenied = Get-MockStats
    Assert-True ($afterDenied.ChatRequests -eq $beforeDenied.ChatRequests) `
        "the model-denied request reached the upstream"
    Write-Host "PASS  management model policy rejected before the upstream"

    $policyVersion = [int]$restrictModels.result.policy.version
    $limitWrite = Invoke-AdminPolicyWrite `
        -Session $adminSession `
        -Method "PUT" `
        -Path "/api/v1/admin/users/$userId/policy/quota" `
        -Payload @{
            reason = "Apply a one-token monthly cap for enforcement testing"
            expectedVersion = $policyVersion
            limits = @(@{ period = "month"; tokens = 1 })
        } `
        -IdempotencyKey "c4-quota-limit-$userId"
    Assert-True ($limitWrite.result.state -eq "succeeded") `
        "token policy did not synchronize both credentials"
    Assert-True ([int64]$limitWrite.result.policy.limits[0].tokens -eq 1) `
        "token policy did not return the expected cap"

    $beforeLimit = Get-MockStats
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $limitResponse = $null
    $lastLimit = ""
    while ([DateTime]::UtcNow -lt $deadline) {
        $candidate = Send-Chat -Base $remoteGatewayBase -Key $first.gateway.key -Model "mock/mock-model"
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
        throw "token-limited employee chat did not produce a stable refusal: $lastLimit"
    }
    if (-not $limitResponse) {
        throw "token-limited employee chat did not return HTTP 429: $lastLimit"
    }
    $afterLimit = Get-MockStats
    Assert-True ($afterLimit.ChatRequests -eq $beforeLimit.ChatRequests) `
        "the token-limited request reached the upstream"
    Assert-True ([bool](Get-HeaderValue -Response $limitResponse -Name "Retry-After")) `
        "HTTP 429 did not include Retry-After"
    Assert-True ([bool](Get-HeaderValue -Response $limitResponse -Name "X-Magpie-Limit-Reset")) `
        "HTTP 429 did not include X-Magpie-Limit-Reset"
    Assert-True ((Get-HeaderValue -Response $limitResponse -Name "X-Should-Retry") -eq "false") `
        "HTTP 429 did not include X-Should-Retry: false"
    Write-Host "PASS  management quota policy produced a stable 429 before the upstream"

    Set-GatewayKeyState -KeyId $second.gateway.keyId -Action "off-key"
    $policyVersion = [int]$limitWrite.result.policy.version
    $partial = Invoke-AdminPolicyWrite `
        -Session $adminSession `
        -Method "PATCH" `
        -Path "/api/v1/admin/users/$userId/policy/models" `
        -Payload @{
            reason = "Exercise a partial credential synchronization failure"
            expectedVersion = $policyVersion
            models = @("mock/mock-model", "mock/mock-second")
        } `
        -IdempotencyKey "c4-partial-$userId"
    Assert-True ($partial.result.state -eq "partial_success") `
        "disabled credential did not produce partial_success: $($partial.result.state)"
    Assert-True ([bool]$partial.result.requiresReconciliation) `
        "partial credential synchronization did not require reconciliation"
    Assert-Credentials -Summary $partial.result.credentials `
        -Total 2 -Succeeded 1 -Failed 1 -Unknown 0 -FailedItems 1
    $failedCredential = @($partial.result.credentials.failedItems)[0]
    Assert-True ($failedCredential.credentialId -eq $second.gateway.keyId) `
        "partial failure named the wrong credential: $($failedCredential.credentialId)"
    Assert-True ($failedCredential.deviceId -eq $second.device.id) `
        "partial failure named the wrong device: $($failedCredential.deviceId)"
    Assert-True ($failedCredential.errorCode -eq "gateway_key_not_enabled") `
        "partial failure returned the wrong stable error code: $($failedCredential.errorCode)"
    Write-Host "PASS  disabled credential produced exact partial_success evidence"

    Set-GatewayKeyState -KeyId $second.gateway.keyId -Action "on-key"
    $policyVersion = [int]$partial.result.policy.version
    $recovered = Invoke-AdminPolicyWrite `
        -Session $adminSession `
        -Method "PATCH" `
        -Path "/api/v1/admin/users/$userId/policy/models" `
        -Payload @{
            reason = "Reconcile both enabled credentials"
            expectedVersion = $policyVersion
            models = @("mock/mock-model", "mock/mock-second")
        } `
        -IdempotencyKey "c4-reconcile-$userId"
    Assert-True ($recovered.result.state -eq "succeeded") `
        "re-enabled credential did not reconcile to succeeded"
    Assert-Credentials -Summary $recovered.result.credentials `
        -Total 2 -Succeeded 2 -Failed 0 -Unknown 0 -FailedItems 0
    Assert-True ($recovered.result.policy.quotaStatus -eq "known") `
        "reconciled policy quota status was not known"
    Assert-True ($recovered.result.policy.modelStatus -eq "known") `
        "reconciled policy model status was not known"
    Write-Host "PASS  re-enabled credential reconciled to known/synced state"

    $policyVersion = [int]$recovered.result.policy.version
    $clearQuota = Invoke-AdminPolicyWrite `
        -Session $adminSession `
        -Method "PUT" `
        -Path "/api/v1/admin/users/$userId/policy/quota" `
        -Payload @{
            reason = "Clear the test quota before rotation"
            expectedVersion = $policyVersion
            limits = @()
        } `
        -IdempotencyKey "c4-quota-clear-$userId"
    Assert-True ($clearQuota.result.state -eq "succeeded") `
        "clearing quota did not synchronize both credentials"

    $oldFirstKeyId = [string]$first.gateway.keyId
    $oldFirstKey = [string]$first.gateway.key
    $refresh = Invoke-WebRequest `
        -Uri "$authBase/api/v1/devices/refresh" `
        -Method Post `
        -Headers @{ Authorization = "Bearer $($first.deviceToken)" } `
        -SkipHttpErrorCheck `
        -TimeoutSec 30
    Assert-Status -Label "device refresh" -Response $refresh -Expected 200
    $refreshed = $refresh.Content | ConvertFrom-Json
    Assert-True ([bool]$refreshed.gateway.key) "refresh returned no gateway key"
    Assert-True ($refreshed.gateway.keyId -ne $oldFirstKeyId) "refresh did not rotate the key"
    $oldModels = Invoke-WebRequest `
        -Uri "$remoteGatewayBase/v1/models" `
        -Headers @{ Authorization = "Bearer $oldFirstKey" } `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "refresh-revoked old key" -Response $oldModels -Expected 401
    $newModels = Invoke-WebRequest `
        -Uri "$remoteGatewayBase/v1/models" `
        -Headers @{ Authorization = "Bearer $($refreshed.gateway.key)" } `
        -SkipHttpErrorCheck `
        -TimeoutSec 20
    Assert-Status -Label "refreshed key" -Response $newModels -Expected 200
    Write-Host "PASS  refresh rotated the key and preserved the synchronized policy"

    Stop-Job -Job $jobs.gatewayControl
    Wait-Job -Job $jobs.gatewayControl -Timeout 10 | Out-Null
    Remove-Job -Job $jobs.gatewayControl -Force
    Wait-TcpClosed -Port $GatewayControlPort
    $jobs.Remove("gatewayControl")

    $policyVersion = [int]$clearQuota.result.policy.version
    $unknown = Invoke-AdminPolicyWrite `
        -Session $adminSession `
        -Method "PATCH" `
        -Path "/api/v1/admin/users/$userId/policy/models" `
        -Payload @{
            reason = "Record a policy while gateway-control is unavailable"
            expectedVersion = $policyVersion
            models = @("mock/mock-model")
        } `
        -IdempotencyKey "c4-outage-$userId"
    Assert-True ($unknown.result.state -in @("unknown", "pending_sync")) `
        "gateway-control outage returned an authoritative state: $($unknown.result.state)"
    Assert-True ([bool]$unknown.result.requiresReconciliation) `
        "gateway-control outage did not require reconciliation"
    $unknownCredentials = [int]$unknown.result.credentials.unknown + [int]$unknown.result.credentials.pending
    Assert-True ($unknownCredentials -eq 2) `
        "gateway-control outage did not leave both credentials unresolved: $($unknown.result.credentials | ConvertTo-Json -Compress)"
    Write-Host "PASS  gateway-control outage left the policy unresolved and reconcilable"

    $failedRefresh = Invoke-WebRequest `
        -Uri "$authBase/api/v1/devices/refresh" `
        -Method Post `
        -Headers @{ Authorization = "Bearer $($first.deviceToken)" } `
        -SkipHttpErrorCheck `
        -TimeoutSec 30
    Assert-True ([int]$failedRefresh.StatusCode -ne 200) `
        "refresh unexpectedly succeeded while gateway-control was down"
    [void]$safeOutputs.Add([string]$failedRefresh.Content)

    Start-Sleep -Milliseconds 300
    $authStoreText = Get-Content -LiteralPath $authStorePath -Raw
    $authStore = $authStoreText | ConvertFrom-Json
    $refreshJournal = @($authStore.issuanceJournal) |
        Where-Object {
            $_.purpose -eq "refresh" -and
            $_.deviceId -eq $first.device.id -and
            $_.state -ne "committed"
        } |
        Select-Object -Last 1
    if (-not $refreshJournal) {
        throw "failed refresh did not leave an issuance journal entry"
    }
    Assert-True ($refreshJournal.revocationResult -eq "revoked") `
        "failed refresh did not compensate the newly issued key"
    Assert-True ([bool]$refreshJournal.keyId) "failed refresh journal has no orphan key id"
    $callerKeysText = Get-Content -LiteralPath $callerKeysPath -Raw
    Assert-True (-not $callerKeysText.Contains([string]$refreshJournal.keyId, [System.StringComparison]::Ordinal)) `
        "failed refresh left its orphan key in caller-keys.json"
    $firstDevice = $authStore.devices.PSObject.Properties[$first.device.id].Value
    Assert-True ($firstDevice.gatewayKeyId -eq $refreshed.gateway.keyId) `
        "failed refresh replaced the device's last known good key"
    Write-Host "PASS  failed refresh revoked the new key and kept the device on its last good key"

    $jobs.gatewayControl = Start-NodeJob `
        -NodeExe $nodePath `
        -WorkingDirectory $gatewayDir `
        -ScriptPath (Join-Path $gatewayDir "src/server.js") `
        -Environment $gatewayControlEnvironment
    Wait-Tcp -Port $GatewayControlPort -Job $jobs.gatewayControl
    Wait-HttpHealthy `
        -Url "$gatewayControlBase/healthz" `
        -Job $jobs.gatewayControl `
        -Label "gateway-control"

    $policyVersion = [int]$unknown.result.policy.version
    $restored = Invoke-AdminPolicyWrite `
        -Session $adminSession `
        -Method "PATCH" `
        -Path "/api/v1/admin/users/$userId/policy/models" `
        -Payload @{
            reason = "Reconcile after gateway-control recovery"
            expectedVersion = $policyVersion
            models = @("mock/mock-model", "mock/mock-second")
        } `
        -IdempotencyKey "c4-restore-$userId"
    Assert-True ($restored.result.state -eq "succeeded") `
        "gateway-control recovery did not restore succeeded state"
    Assert-Credentials -Summary $restored.result.credentials `
        -Total 2 -Succeeded 2 -Failed 0 -Unknown 0 -FailedItems 0
    Assert-True ($restored.result.policy.quotaStatus -eq "known") `
        "post-recovery quota status was not known"
    Assert-True ($restored.result.policy.modelStatus -eq "known") `
        "post-recovery model status was not known"
    Write-Host "PASS  gateway-control recovery reconciled both credentials"

    $usageSummary = Invoke-AdminRead -Session $adminSession -Path "/api/v1/admin/usage/summary"
    Assert-True ([int]$usageSummary.totals.requests -ge 1) "usage summary had no requests"
    Assert-True ([int]$usageSummary.totals.successfulRequests -ge 1) `
        "usage summary had no successful requests"
    $userUsage = @($usageSummary.dimensions.user | Where-Object { $_.userId -eq $userId }) |
        Select-Object -First 1
    if (-not $userUsage) {
        throw "usage summary did not attribute requests to the employee"
    }
    Assert-True ([int]$userUsage.requests -ge 1) "employee usage dimension had no requests"
    Write-Host "PASS  management usage summary attributed successful requests to the employee"

    $credentials = Invoke-AdminRead -Session $adminSession -Path "/api/v1/admin/credentials"
    $currentFirst = @($credentials.credentials | Where-Object {
        $_.id -eq $refreshed.gateway.keyId
    }) | Select-Object -First 1
    if (-not $currentFirst) {
        throw "management credentials did not include the refreshed key"
    }
    Assert-True ($currentFirst.policySyncState -eq "synced") `
        "refreshed credential was not synced after recovery"
    Assert-True ($currentFirst.lastPolicyErrorCode -eq "") `
        "refreshed credential retained a policy error after recovery"

    $health = Invoke-AdminRead -Session $adminSession -Path "/api/v1/admin/health"
    Assert-True ($health.ok -eq $true) "management health was not ok"
    Assert-True ($health.auth.service -eq "auth") "management health did not reach auth-service"
    Assert-True ($health.modelCatalog.authorizationReady -eq $true) `
        "management model catalog was not authorization-ready"

    $adminPageResponse = Invoke-AdminHttp -Session $adminSession -Method "GET" -Path "/admin/"
    Assert-True ($adminPageResponse.StatusCode -eq 200) `
        "admin page returned HTTP $($adminPageResponse.StatusCode)"
    [void]$safeOutputs.Add([string]$adminPageResponse.Content)
    foreach ($label in @("Usage overview", "Users", "Devices", "Models", "Credentials")) {
        Assert-True ($adminPageResponse.Content.Contains($label, [System.StringComparison]::Ordinal)) `
            "admin page did not contain $label"
    }
    Write-Host "PASS  authenticated management page renders the operational views"

    $protectedSecrets = @(
        [string]$first.gateway.key,
        [string]$refreshed.gateway.key,
        [string]$second.gateway.key,
        [string]$first.deviceToken,
        [string]$second.deviceToken,
        [string]$issuerKey,
        [string]$authAdminToken,
        [string]$internalAdminToken,
        [string]$authCookieSecret,
        [string]$gatewayControlToken,
        [string]$adminSessionSecret,
        [string]$WebKey,
        [string]$employeeOidcSecret,
        [string]$adminOidcSecret
    )

    foreach ($text in $safeOutputs) {
        Assert-NoSecret -Text $text -Label "management/API output" -Secrets $protectedSecrets
    }
    foreach ($entry in $jobs.GetEnumerator()) {
        $logText = (Receive-Job -Job $entry.Value -Keep -ErrorAction SilentlyContinue) -join "`n"
        if ($entry.Key -eq "gateway") {
            # `serve --web` intentionally prints its one-time page link to the
            # local operator at startup. Do not treat that bootstrap line as a
            # downstream disclosure, while still checking every other secret.
            $logText = $logText.Replace($WebKey, "<startup web key>")
        }
        Assert-NoSecret -Text $logText -Label "$($entry.Key) log" -Secrets $protectedSecrets
    }
    Assert-NoSecret -Text $authStoreText -Label "auth store" -Secrets $protectedSecrets
    $adminStoreText = Get-Content -LiteralPath $adminStorePath -Raw
    Assert-NoSecret -Text $adminStoreText -Label "admin store" -Secrets $protectedSecrets
    $usageText = Get-Content -LiteralPath $usagePath -Raw
    Assert-NoSecret -Text $usageText -Label "usage.jsonl" -Secrets $protectedSecrets

    Assert-True ($callerKeysText.Contains($refreshed.gateway.key, [System.StringComparison]::Ordinal)) `
        "caller-keys.json does not contain the current refreshed employee key"
    Assert-True ($callerKeysText.Contains($second.gateway.key, [System.StringComparison]::Ordinal)) `
        "caller-keys.json does not contain the second employee key"
    Assert-True (-not $callerKeysText.Contains($oldFirstKey, [System.StringComparison]::Ordinal)) `
        "caller-keys.json still contains the rotated-out employee key"
    foreach ($deviceToken in @($first.deviceToken, $second.deviceToken)) {
        Assert-True (-not $callerKeysText.Contains([string]$deviceToken, [System.StringComparison]::Ordinal)) `
            "caller-keys.json contains a plaintext device token"
        Assert-True (-not $authStoreText.Contains([string]$deviceToken, [System.StringComparison]::Ordinal)) `
            "auth store contains a plaintext device token"
    }
    Assert-True (-not $authStoreText.Contains([string]$first.gateway.key, [System.StringComparison]::Ordinal)) `
        "auth store contains a plaintext employee gateway key"
    Assert-True (-not $authStoreText.Contains([string]$issuerKey, [System.StringComparison]::Ordinal)) `
        "auth store contains the plaintext issuer key"
    Write-Host "PASS  protected values stayed out of management output, stores, usage and logs"
    Write-Host "PASS  caller-keys.json holds only the expected active credentials"

    $scanned = 0
    foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File -Force) {
        if ($file.FullName -eq $callerKeysPath -or
            $file.Extension -ieq ".exe" -or
            $file.Length -gt 10MB) {
            continue
        }
        try {
            $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
        } catch {
            continue
        }
        Assert-NoSecret -Text $text -Label $file.FullName -Secrets $protectedSecrets
        $scanned++
    }
    Write-Host "PASS  scanned $scanned non-credential files for protected values"

    $succeeded = $true
    Write-Host "PASS  C4-04 enterprise management-to-real-gateway end-to-end"
} catch {
    Write-Host "FAIL  $($_.Exception.Message)"
    Show-JobLogs -Jobs $jobs
    throw
} finally {
    if ($adminSession) {
        try {
            $adminSession.Client.Dispose()
            $adminSession.Handler.Dispose()
        } catch {
            # Best-effort client cleanup.
        }
    }
    foreach ($job in $jobs.Values) {
        try {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        } catch {
            # Best-effort process cleanup after a failed test.
        }
    }
    foreach ($name in $envNames) {
        [System.Environment]::SetEnvironmentVariable($name, $savedEnv[$name], "Process")
    }

    if ($succeeded -and -not $Keep) {
        $resolvedRoot = [System.IO.Path]::GetFullPath($root)
        $resolvedTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if ($resolvedRoot.StartsWith($resolvedTemp, [System.StringComparison]::OrdinalIgnoreCase) -and
            (Split-Path $resolvedRoot -Leaf) -like "magpie-enterprise-c4-e2e-*") {
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        }
    } else {
        Write-Host "logs and isolated state kept in: $root"
    }
}
