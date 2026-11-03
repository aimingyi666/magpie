<#
.SYNOPSIS
One-click deployment of Magpie Enterprise with Docker Compose.

.DESCRIPTION
Pre-flight checks Docker, Node.js, .env presence; starts all enterprise
services with Docker Compose, waits for health checks, and prints a
deployment summary. Does not mutate source control.

Use the M11 profile names in docker-compose.yml to start subsets:
  deploy.ps1 -Profiles "admin,employee-portal,nginx"

.EXAMPLE
pwsh ./deploy.ps1 -Profiles "admin,employee-portal,nginx"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ProjectName = "magpie-enterprise",

    [Parameter(Mandatory = $false)]
    [string]$ComposeFile = "enterprise/docker-compose.yml",

    [Parameter(Mandatory = $false)]
    [string[]]$Profiles = @("admin","employee-portal","nginx"),

    [Parameter(Mandatory = $false)]
    [string]$EnvFile = ".env",

    [switch]$SkipHealthcheck,

    [int]$HealthcheckTimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"
$PSVersionTable.PSVersion | Select-Object Major

function Write-Header { param($t) Write-Host "`n=== $t ===" }

Write-Header "Pre-flight checks"

# 1. Docker availability
try {
    docker --version | Out-Null
    Write-Host "Docker CLI found"
} catch {
    Write-Error "Docker CLI not found. Install Docker Desktop / Docker Engine."
}
try {
    docker compose version | Out-Null
    Write-Host "Docker Compose found"
} catch {
    Write-Error "Docker Compose plugin not found."
}

# 2. Compose file exists
if (!(Test-Path $ComposeFile)) {
    Write-Error "Compose file not found: $ComposeFile"
}
Write-Host "Compose file: $ComposeFile"

# 3. Env file
if (!(Test-Path $EnvFile)) {
    Write-Warning ".env file not found at $EnvFile - copy .env.example first"
}
else {
    Write-Host "Env file: $EnvFile"
}

# 4. Build profile argument
$profileArgs = @()
foreach ($p in $Profiles) {
    $profileArgs += @("--profile", $p)
}

Write-Header "Starting services"
$composeArgs = @("-p", $ProjectName, "-f", $ComposeFile) + $profileArgs + @("up", "-d")
& docker compose @composeArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "docker compose up failed with exit code $LASTEXITCODE"
}

if (-not $SkipHealthcheck) {
    Write-Header "Waiting for health checks (timeout ${HealthcheckTimeoutSeconds}s)"
    $start = Get-Date
    $deadline = $start.AddSeconds($HealthcheckTimeoutSeconds)
    $services = $Profiles
    do {
        Start-Sleep -Seconds 5
        $allHealthy = $true
        foreach ($svc in $services) {
            $status = & docker compose -p $ProjectName -f $ComposeFile ps --filter "name=$svc" --format json | ConvertFrom-Json
            if ($status.Status -ne "healthy") {
                $allHealthy = $false
            }
        }
    } while (-not $allHealthy -and (Get-Date) -lt $deadline)

    if (-not $allHealthy) {
        Write-Warning "Not all services became healthy in time. Check `docker compose logs`."
    } else {
        Write-Host "All services healthy"
    }
}

Write-Header "Deployment summary"
& docker compose -p $ProjectName -f $ComposeFile ps
Write-Host "`nDone. Employee portal: http://127.0.0.1:3007`nAdmin console: http://127.0.0.1:3445"
