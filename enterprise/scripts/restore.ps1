<#
.SYNOPSIS
Restore Magpie Enterprise data (Postgres + Redis) from a backup.

.DESCRIPTION
Lists available backups, restores Postgres via psql and Redis by replacing
dump.rdb, then restarts dependent services.

.EXAMPLE
.\restore.ps1 -BackupFile "enterprise/backups/magpie-backup-20261101-020000.postgres.sql"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][string]$BackupDir = "enterprise/backups",
    [Parameter(Mandatory = $false)][string]$BackupFile,
    [Parameter(Mandatory = $false)][string]$PostgresContainer = "magpie-enterprise-postgres",
    [Parameter(Mandatory = $false)][string]$PostgresUser = "magpie",
    [Parameter(Mandatory = $false)][string]$PostgresDb = "magpie_enterprise",
    [Parameter(Mandatory = $false)][string]$RedisContainer = "magpie-enterprise-redis",
    [switch]$RestartServices
)

$ErrorActionPreference = "Stop"

if (!(Test-Path $BackupDir)) {
    Write-Error "Backup directory not found: $BackupDir"
}

# Resolve backup file
if (-not $BackupFile) {
    $files = Get-ChildItem -Path $BackupDir -File | Sort-Object LastWriteTime -Descending
    if ($files.Count -eq 0) {
        Write-Error "No backup files found in $BackupDir"
    }
    Write-Host "Available backups:"
    $files | ForEach-Object { Write-Host "  $($_.Name)  ($($_.LastWriteTime))" }
    Write-Host "`nSpecify -BackupFile <name> to restore one."
    exit
}

$pgFile = Join-Path $BackupDir $BackupFile
if (!(Test-Path $pgFile)) {
    Write-Error "Backup file not found: $pgFile"
}

Write-Host "=== Magpie Enterprise Restore ==="
Write-Host "Backup file: $pgFile"

# --- Restore Postgres ---
Write-Host "`n[1/2] Restoring Postgres database '$PostgresDb' ..."
& docker exec -i $PostgresContainer psql -U $PostgresUser -d $PostgresDb < $pgFile
if ($LASTEXITCODE -ne 0) {
    Write-Error "psql restore failed"
}
Write-Host "Postgres restore complete."

# --- Restore Redis ---
$redisRdb = [System.IO.Path]::ChangeExtension($pgFile, ".redis.rdb")
if (Test-Path $redisRdb) {
    Write-Host "`n[2/2] Restoring Redis dump ..."
    & docker cp $redisRdb "$RedisContainer:/data/dump.rdb"
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Redis restore copy failed"
    }
    & docker restart $RedisContainer | Out-Null
    Write-Host "Redis restored and container restarted."
}

# --- Restart dependent services ---
if ($RestartServices) {
    Write-Host "`nRestarting dependent services ..."
    & docker compose -f enterprise/docker-compose.yml -p magpie-enterprise restart admin employee-portal auth | Out-Null
    Write-Host "Services restarted."
}

Write-Host "`nRestore complete."
