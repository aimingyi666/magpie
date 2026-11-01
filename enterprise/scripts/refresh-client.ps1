<#
.SYNOPSIS
Refresh this device's short-lived Magpie Enterprise gateway key.

.DESCRIPTION
Uses the protected device token created by join-enterprise.ps1 to request a
new short-lived gateway key and updates the configured local magpie provider.
The gateway key is never printed.

.EXAMPLE
.\refresh-client.ps1 -CredentialFile "$env:LOCALAPPDATA\MagpieEnterprise\enterprise-gateway-device.json"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CredentialFile,
    [string]$Magpie = "magpie",
    [switch]$SkipProviderTest
)

$ErrorActionPreference = "Stop"

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

function Write-RefreshLog {
    param([string]$Status, [string]$Detail = "")
    $logFile = "$CredentialFile.log"
    $line = "{0} {1} {2}`n" -f [DateTime]::UtcNow.ToString("o"), $Status, $Detail
    [System.IO.File]::AppendAllText($logFile, $line, [System.Text.UTF8Encoding]::new($false))
    if ($IsWindows) {
        try { Protect-PrivateFile -Path $logFile } catch { }
    } else {
        try { & chmod 600 -- $logFile } catch { }
    }
}

$resolvedCredential = (Resolve-Path -LiteralPath $CredentialFile -ErrorAction Stop).Path
$credential = Get-Content -LiteralPath $resolvedCredential -Raw | ConvertFrom-Json
if (-not $credential.deviceToken -or -not $credential.authUrl) {
    throw "credential file is missing deviceToken or authUrl"
}

$authBase = ([string]$credential.authUrl).TrimEnd("/")
$lock = $null
try {
    try {
        $lock = [System.IO.File]::Open(
            "$resolvedCredential.lock",
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
    } catch {
        Write-RefreshLog "SKIP" "another refresh is already running"
        exit 0
    }

    $response = Invoke-WebRequest `
        -Uri "$authBase/api/v1/devices/refresh" `
        -Method Post `
        -Headers @{ Authorization = "Bearer $($credential.deviceToken)" } `
        -SkipHttpErrorCheck `
        -TimeoutSec 30
    if ($response.StatusCode -ne 200) {
        $detail = "HTTP $($response.StatusCode)"
        try {
            $errorBody = $response.Content | ConvertFrom-Json
            $detail = "$($errorBody.error.code): $($errorBody.error.message)"
        } catch {
        }
        $credential | Add-Member -NotePropertyName lastRefreshError -NotePropertyValue $detail -Force
        Write-PrivateText -Path $resolvedCredential -Value (($credential | ConvertTo-Json -Depth 8) + "`n")
        Write-RefreshLog "FAIL" $detail
        if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403) {
            Write-Host "device credential is no longer valid; run join-enterprise.ps1 again"
        }
        throw "gateway key refresh failed: $detail"
    }

    $refreshed = $response.Content | ConvertFrom-Json
    if (-not $refreshed.gateway.key -or -not $refreshed.gateway.url) {
        throw "auth service returned an incomplete gateway credential"
    }
    $expectedGateway = ([string]$credential.gatewayUrl).TrimEnd("/")
    $actualGateway = ([string]$refreshed.gateway.url).TrimEnd("/")
    if ($expectedGateway -and $actualGateway -ne $expectedGateway) {
        throw "auth service returned a different gateway URL; rejecting the refresh"
    }

    $keyFile = "$resolvedCredential.gateway-key.tmp"
    try {
        Write-PrivateText -Path $keyFile -Value (([string]$refreshed.gateway.key).Trim() + "`n")
        $joinArgs = @{
            Magpie       = $Magpie
            GatewayUrl   = $actualGateway
            KeyFile     = $keyFile
            ProviderName = [string]$credential.providerName
            ProviderId   = [string]$credential.providerId
        }
        if ($credential.models) {
            $joinArgs.Models = (@($credential.models) -join ",")
        }
        if ($SkipProviderTest) {
            $joinArgs.SkipTest = $true
        }
        & (Join-Path $PSScriptRoot "join-client.ps1") @joinArgs | Out-Null
    } finally {
        if (Test-Path -LiteralPath $keyFile) {
            Remove-Item -LiteralPath $keyFile -Force
        }
    }

    $credential.gatewayKeyId = [string]$refreshed.gateway.keyId
    $credential.gatewayKeyExpiresAt = [string]$refreshed.gateway.expiresAt
    $credential.lastRefreshAt = [DateTime]::UtcNow.ToString("o")
    $credential | Add-Member -NotePropertyName lastRefreshError -NotePropertyValue $null -Force
    $credential | Add-Member -NotePropertyName pendingRevocations `
        -NotePropertyValue ([int]$refreshed.pendingRevocations) -Force
    Write-PrivateText -Path $resolvedCredential -Value (($credential | ConvertTo-Json -Depth 8) + "`n")
    Write-RefreshLog "OK" "gateway key expires $($refreshed.gateway.expiresAt)"
    Write-Host "gateway key refreshed; expires $($refreshed.gateway.expiresAt)"
} finally {
    if ($lock) {
        $lock.Dispose()
    }
}
