<#
.SYNOPSIS
Join this computer to a Magpie Enterprise OIDC tenant.

.DESCRIPTION
Starts a loopback OIDC login, exchanges the one-time join code with the
enterprise auth service, registers this device, and configures the local
magpie provider. The device token is stored only in a current-user protected
file; the short-lived gateway key is written directly into magpie and is never
printed.

On Windows, a per-user scheduled task refreshes the short-lived gateway key
every 30 minutes. Use -SkipRefreshTask to disable that task.

.EXAMPLE
.\join-enterprise.ps1 -AuthUrl https://auth.ai.corp.example -Magpie magpie

.EXAMPLE
.\join-enterprise.ps1 -AuthUrl https://auth.ai.corp.example -Magpie magpie -Agent claude
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AuthUrl,
    [string]$Magpie = "magpie",
    [string]$ProviderName = "Enterprise Gateway",
    [string]$ProviderId,
    [string]$Models,
    [string]$Agent,
    [string]$AgentModel,
    [string]$DeviceName = $env:COMPUTERNAME,
    [string]$Platform = "windows",
    [string]$ClientVersion = "enterprise-1.0.0",
    [string]$StateDir,
    [int]$LoginTimeoutSeconds = 300,
    [switch]$NoBrowser,
    [switch]$SkipProviderTest,
    [switch]$SkipRefreshTask
)

$ErrorActionPreference = "Stop"

function New-RandomUrlToken {
    param([int]$Bytes = 32)
    $buffer = [byte[]]::new($Bytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($buffer)
    return [Convert]::ToBase64String($buffer).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function New-PkceChallenge {
    param([string]$Verifier)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Verifier)
    $digest = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return [Convert]::ToBase64String($digest).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Protect-PrivateFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ($IsWindows) {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $acl = [System.Security.AccessControl.FileSecurity]::new()
        $acl.SetOwner($identity.User)
        $acl.SetAccessRuleProtection($true, $false)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity.User,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl
    } else {
        & chmod 600 -- $Path
        if ($LASTEXITCODE -ne 0) {
            throw "could not restrict permissions on $Path"
        }
    }
}

function Write-PrivateText {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Value
    )
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    [System.IO.File]::WriteAllText($temporary, $Value, [System.Text.UTF8Encoding]::new($false))
    Protect-PrivateFile -Path $temporary
    Move-Item -LiteralPath $temporary -Destination $Path -Force
    Protect-PrivateFile -Path $Path
}

function Wait-LoopbackCallback {
    param(
        [Parameter(Mandatory = $true)][System.Net.Sockets.TcpListener]$Listener,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $accept = $Listener.AcceptTcpClientAsync()
    if (-not $accept.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
        throw "timed out waiting for the browser to finish OIDC login"
    }
    $client = $accept.Result
    try {
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $reader = [System.IO.StreamReader]::new(
            $stream,
            [System.Text.UTF8Encoding]::new($false),
            $false,
            1024,
            $true
        )
        $requestLine = $reader.ReadLine()
        if (-not $requestLine) {
            throw "browser sent an empty callback request"
        }
        do {
            $header = $reader.ReadLine()
        } while ($header)

        $parts = $requestLine -split " "
        if ($parts.Count -lt 2 -or $parts[0] -ne "GET") {
            throw "browser callback was not a GET request"
        }
        $html = "<!doctype html><title>Magpie Enterprise</title><p>Login complete. You can close this tab.</p>"
        $body = [System.Text.Encoding]::UTF8.GetBytes($html)
        $headers = "HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nCache-Control: no-store`r`nConnection: close`r`nContent-Length: $($body.Length)`r`n`r`n"
        $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($headers)
        $stream.Write($headerBytes, 0, $headerBytes.Length)
        $stream.Write($body, 0, $body.Length)
        $stream.Flush()
        return $parts[1]
    } finally {
        $client.Dispose()
    }
}

function Register-RefreshTask {
    param(
        [Parameter(Mandatory = $true)][string]$CredentialFile,
        [Parameter(Mandatory = $true)][string]$RefreshScript,
        [Parameter(Mandatory = $true)][string]$MagpieCommand,
        [Parameter(Mandatory = $true)][string]$TaskSuffix
    )

    if (-not $IsWindows) {
        Write-Host "Automatic refresh is not installed on this OS. Run this periodically:"
        Write-Host "  pwsh -NoProfile -File `"$RefreshScript`" -CredentialFile `"$CredentialFile`" -Magpie `"$MagpieCommand`""
        return $false
    }

    try {
        $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
        $safeSuffix = $TaskSuffix -replace "[^A-Za-z0-9_.-]+", "-"
        $taskName = "MagpieEnterpriseRefresh-$safeSuffix"
        $arguments = "-NoLogo -NoProfile -NonInteractive -File `"$RefreshScript`" -CredentialFile `"$CredentialFile`" -Magpie `"$MagpieCommand`""
        $action = New-ScheduledTaskAction -Execute $pwsh -Argument $arguments
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
            -RepetitionInterval (New-TimeSpan -Minutes 30)
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
            -MultipleInstances IgnoreNew `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
        $principal = New-ScheduledTaskPrincipal `
            -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
            -LogonType Interactive `
            -RunLevel Limited
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Settings $settings -Principal $principal -Force | Out-Null
        Write-Host "automatic refresh installed as scheduled task $taskName"
        return $true
    } catch {
        Write-Host "WARNING  automatic refresh task was not installed: $($_.Exception.Message)"
        Write-Host "Run this periodically:"
        Write-Host "  pwsh -NoProfile -File `"$RefreshScript`" -CredentialFile `"$CredentialFile`" -Magpie `"$MagpieCommand`""
        return $false
    }
}

if (-not $DeviceName) {
    $DeviceName = if ($IsWindows) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
}
if (-not $Platform) {
    $Platform = if ($IsWindows) { "windows" } elseif ($IsMacOS) { "macos" } else { "linux" }
}
if (-not $StateDir) {
    if ($IsWindows -and $env:LOCALAPPDATA) {
        $StateDir = Join-Path $env:LOCALAPPDATA "MagpieEnterprise"
    } else {
        $StateDir = Join-Path $HOME ".local/state/magpie-enterprise"
    }
}

if ($Agent -xor $AgentModel) {
    throw "-Agent and -AgentModel must be given together"
}

$authBase = $AuthUrl.Trim().TrimEnd("/")
$StateDir = [System.IO.Path]::GetFullPath($StateDir)
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

if (-not $ProviderId) {
    $ProviderId = ($ProviderName.ToLowerInvariant() -replace "[^a-z0-9]+", "-").Trim("-")
    if (-not $ProviderId) { $ProviderId = "enterprise-gateway" }
}

$devicePrivateKeyFile = Join-Path $StateDir "$ProviderId-device-key.pem"
$credentialFile = Join-Path $StateDir "$ProviderId-device.json"
$refreshScript = Join-Path $PSScriptRoot "refresh-client.ps1"
$joinScript = Join-Path $PSScriptRoot "join-client.ps1"

$rsa = [System.Security.Cryptography.RSA]::Create(3072)
try {
    $publicKeyPem = $rsa.ExportSubjectPublicKeyInfoPem()
    $privateKeyPem = $rsa.ExportPkcs8PrivateKeyPem()
} finally {
    $rsa.Dispose()
}
Write-PrivateText -Path $devicePrivateKeyFile -Value ($privateKeyPem.TrimEnd() + "`n")

$verifier = New-RandomUrlToken -Bytes 48
$challenge = New-PkceChallenge -Verifier $verifier
$clientState = New-RandomUrlToken -Bytes 24
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
try {
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $returnTo = "http://127.0.0.1:$port/callback"
    $loginUrl = "$authBase/login?return_to=$([uri]::EscapeDataString($returnTo))&state=$([uri]::EscapeDataString($clientState))&code_challenge=$([uri]::EscapeDataString($challenge))"
    Write-Host "opening company sign-in..."
    Write-Host $loginUrl
    if (-not $NoBrowser) {
        Start-Process $loginUrl | Out-Null
    }

    $callbackTarget = Wait-LoopbackCallback -Listener $listener -TimeoutSeconds $LoginTimeoutSeconds
} finally {
    $listener.Stop()
}

$callback = [uri]::new("http://127.0.0.1:$port", $callbackTarget)
if ($callback.AbsolutePath -ne "/callback") {
    throw "unexpected OIDC callback path"
}
$query = [System.Web.HttpUtility]::ParseQueryString($callback.Query)
if ($query["error"]) {
    throw "company sign-in failed: $($query['error'])"
}
if ($query["state"] -cne $clientState) {
    throw "OIDC callback state does not match"
}
$joinCode = $query["code"]
if (-not $joinCode) {
    throw "OIDC callback did not contain a join code"
}

$exchangeBody = @{
    code         = $joinCode
    codeVerifier = $verifier
    device       = @{
        name          = $DeviceName
        platform      = $Platform
        clientVersion = $ClientVersion
        publicKey     = $publicKeyPem
    }
} | ConvertTo-Json -Depth 6

$exchange = Invoke-WebRequest `
    -Uri "$authBase/api/v1/join/exchange" `
    -Method Post `
    -ContentType "application/json" `
    -Body $exchangeBody `
    -SkipHttpErrorCheck `
    -TimeoutSec 30
if ($exchange.StatusCode -ne 201) {
    $detail = if ($exchange.Content) {
        try {
            $errorBody = $exchange.Content | ConvertFrom-Json
            "$($errorBody.error.code): $($errorBody.error.message)"
        } catch {
            "HTTP $($exchange.StatusCode)"
        }
    } else {
        "HTTP $($exchange.StatusCode)"
    }
    throw "device registration failed: $detail"
}
$joined = $exchange.Content | ConvertFrom-Json

$credential = [ordered]@{
    version             = 1
    authUrl             = $authBase
    userId              = [string]$joined.user.id
    email               = [string]$joined.user.email
    deviceId            = [string]$joined.device.id
    deviceName          = $DeviceName
    platform            = $Platform
    clientVersion       = $ClientVersion
    deviceToken         = [string]$joined.deviceToken
    tokenExpiresAt      = [string]$joined.device.tokenExpiresAt
    privateKeyFile      = $devicePrivateKeyFile
    providerId          = $ProviderId
    providerName        = $ProviderName
    gatewayUrl          = [string]$joined.gateway.url
    gatewayKeyId        = [string]$joined.gateway.keyId
    gatewayKeyExpiresAt = [string]$joined.gateway.expiresAt
    models              = @($joined.gateway.models)
    createdAt           = [DateTime]::UtcNow.ToString("o")
    lastRefreshAt       = [DateTime]::UtcNow.ToString("o")
}
Write-PrivateText -Path $credentialFile -Value (($credential | ConvertTo-Json -Depth 6) + "`n")

$keyFile = Join-Path $StateDir "$ProviderId-gateway-key.tmp"
try {
    Write-PrivateText -Path $keyFile -Value (([string]$joined.gateway.key).Trim() + "`n")
    $modelsValue = if ($Models) { $Models } else { (@($joined.gateway.models) -join ",") }
    $joinArgs = @{
        Magpie       = $Magpie
        GatewayUrl   = [string]$joined.gateway.url
        KeyFile     = $keyFile
        ProviderName = $ProviderName
        ProviderId   = $ProviderId
        Models       = $modelsValue
    }
    if ($Agent) {
        $joinArgs.Agent = $Agent
        $joinArgs.AgentModel = $AgentModel
    }
    if ($SkipProviderTest) {
        $joinArgs.SkipTest = $true
    }
    & $joinScript @joinArgs
} finally {
    if (Test-Path -LiteralPath $keyFile) {
        Remove-Item -LiteralPath $keyFile -Force
    }
}

if (-not $SkipRefreshTask) {
    Register-RefreshTask `
        -CredentialFile $credentialFile `
        -RefreshScript $refreshScript `
        -MagpieCommand $Magpie `
        -TaskSuffix $ProviderId | Out-Null
}

Write-Host "joined as $($joined.user.email) with device $($joined.device.id)"
Write-Host "device credentials: $credentialFile"
Write-Host "short-lived gateway key expires: $($joined.gateway.expiresAt)"
