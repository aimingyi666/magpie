<#
.SYNOPSIS
Monitor Magpie Enterprise service health.

.DESCRIPTION
Polls each configured service healthcheck endpoint and prints a concise
status table. Flags any unhealthy service as an alert.

.EXAMPLE
.\monitor.ps1 -IntervalSeconds 30
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][string]$ComposeFile = "enterprise/docker-compose.yml",
    [Parameter(Mandatory = $false)][string]$ProjectName = "magpie-enterprise",
    [Parameter(Mandatory = $false)][int]$IntervalSeconds = 30,
    [switch]$Once
)

$ErrorActionPreference = "Stop"

$services = @(
    @{ Name = "auth";         Port = 3444; Path = "/healthz" },
    @{ Name = "admin";        Port = 3445; Path = "/healthz" },
    @{ Name = "gateway-control"; Port = 3446; Path = "/healthz" },
    @{ Name = "resource";     Port = 3447; Path = "/healthz" },
    @{ Name = "mcp-gateway";  Port = 3448; Path = "/healthz" },
    @{ Name = "audit";        Port = 3449; Path = "/healthz" },
    @{ Name = "security";     Port = 3450; Path = "/healthz" },
    @{ Name = "employee-portal"; Port = 3007; Path = "/healthz" },
    @{ Name = "nginx";        Port = 80;   Path = "/" },
    @{ Name = "prometheus";   Port = 9090; Path = "/-/healthy" },
    @{ Name = "grafana";      Port = 3008; Path = "/" },
)

function Check-Service {
    param($s)
    try {
        $start = [Diagnostics.Stopwatch]::StartNew()
        $resp = Invoke-RestMethod -Uri "http://127.0.0.1:$($s.Port)$($s.Path)" -TimeoutSec 5 -ErrorAction Stop
        $start.Stop()
        return @{ Name = $s.Name; Status = "healthy"; Ms = $start.ElapsedMilliseconds; Error = $null }
    } catch {
        return @{ Name = $s.Name; Status = "unhealthy"; Ms = 0; Error = $_.Exception.Message }
    }
}

function Show-Table {
    param($results)
    Clear-Host
    Write-Host "=== Magpie Enterprise Monitor ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) ==="
    Write-Host ("{0,-20} {1,-12} {2,-10} {3}" -f "SERVICE", "STATUS", "LATENCY(ms)", "ERROR")
    Write-Host ("-" * 70)
    $unhealthy = 0
    foreach ($r in $results) {
        Write-Host ("{0,-20} {1,-12} {2,-10} {3}" -f $r.Name, $r.Status, $r.Ms, $r.Error)
        if ($r.Status -eq "unhealthy") { $unhealthy++ }
    }
    Write-Host ("-" * 70)
    if ($unhealthy -gt 0) {
        Write-Host "ALERT: $unhealthy service(s) unhealthy" -ForegroundColor Red
    } else {
        Write-Host "All services healthy" -ForegroundColor Green
    }
}

do {
    $results = $services | ForEach-Object { Check-Service $_ }
    Show-Table $results
    if ($Once) { break }
    Start-Sleep -Seconds $IntervalSeconds
} while ($true)
