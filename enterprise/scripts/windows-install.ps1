<#
.SYNOPSIS
Install Magpie Enterprise Node services as Windows services via NSSM.

.DESCRIPTION
Wraps each enterprise Node service (admin, auth, gateway-control,
gateway-control, mcp-gateway, audit, security, employee-portal) as a
Windows service using NSSM. Supports install / uninstall / start / stop /
status.

Requires NSSM (nssm.exe) on PATH or at -NssmPath.

.EXAMPLE
.\windows-install.ps1 -Action install -Service admin
.\windows-install.ps1 -Action status -Service employee-portal
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet("install","uninstall","start","stop","status")]
    [string]$Action,

    [Parameter(Mandatory = $true)][ValidateSet("admin","auth","gateway-control","resource","mcp-gateway","audit","security","employee-portal","all")]
    [string]$Service = "all",

    [Parameter(Mandatory = $false)][string]$NssmPath = "nssm",
    [Parameter(Mandatory = $false)][string]$NodeExe = "node",
    [Parameter(Mandatory = $false)][string]$WorkRoot = "enterprise",
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

$services = @{
    admin            = @{ script = "admin-service/src/server.js";       port = 3445 }
    auth             = @{ script = "auth-service/src/server.js";        port = 3444 }
    "gateway-control" = @{ script = "gateway-control/src/server.js";    port = 3446 }
    resource         = @{ script = "resource-service/src/server.js";    port = 3447 }
    "mcp-gateway"    = @{ script = "mcp-gateway/src/server.js";         port = 3448 }
    audit            = @{ script = "audit-service/src/server.js";       port = 3449 }
    security         = @{ script = "security-service/src/server.js";    port = 3450 }
    "employee-portal"= @{ script = "employee-portal/src/server.js";     port = 3007 }
}

function Get-TargetServices {
    param($name)
    if ($name -eq "all") { return $services.Keys }
    return @($name)
}

function Invoke-Nssm {
    param($svc, $args)
    $cmd = "& $NssmPath $args `"$svc`""
    if ($Verbose) { Write-Host $cmd }
    Invoke-Expression $cmd
}

function Get-ServiceCmd {
    param($svcName)
    $cfg = $services[$svcName]
    $scriptPath = Join-Path $WorkRoot $cfg.script
    return @(
        $NodeExe,
        $scriptPath
    )
}

$targets = Get-TargetServices $Service

switch ($Action) {
    "install" {
        foreach ($t in $targets) {
            $cfg = $services[$t]
            $svcName = "magpie-$t"
            Write-Host "Installing $svcName ..."
            $cmd = Get-ServiceCmd $t
            $argStr = ($cmd | ForEach-Object { if ($_ -match " ") { "`"$_`" " } else { "$_ " } }) -join ""
            Invoke-Nssm $svcName "install $argStr"
            Invoke-Nssm $svcName "set Start SERVICE_AUTO_START"
            Invoke-Nssm $svcName "set Description Magpie Enterprise $t service"
        }
        Write-Host "Install complete."
    }
    "uninstall" {
        foreach ($t in $targets) {
            $svcName = "magpie-$t"
            Write-Host "Uninstalling $svcName ..."
            Invoke-Nssm $svcName "stop"
            Invoke-Nssm $svcName "remove"
        }
        Write-Host "Uninstall complete."
    }
    "start" {
        foreach ($t in $targets) {
            $svcName = "magpie-$t"
            Write-Host "Starting $svcName ..."
            Invoke-Nssm $svcName "start"
        }
        Write-Host "Start complete."
    }
    "stop" {
        foreach ($t in $targets) {
            $svcName = "magpie-$t"
            Write-Host "Stopping $svcName ..."
            Invoke-Nssm $svcName "stop"
        }
        Write-Host "Stop complete."
    }
    "status" {
        foreach ($t in $targets) {
            $svcName = "magpie-$t"
            Write-Host "`n--- $svcName ---"
            Invoke-Nssm $svcName "status"
        }
    }
}
