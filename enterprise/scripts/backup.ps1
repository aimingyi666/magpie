<#
.SYNOPSIS
Backup Magpie Enterprise data (Postgres + Redis).

.DESCRIPTION
Creates a timestamped backup of Postgres via pg_dump and Redis via
BGREWRITEAFILE/SAVE, stores them under ./backups/, and prunes backups older
than 7 days.

.EXAMPLE
.\backup.ps1 -Tag pre-upgrade
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)][string]$BackupDir = "enterprise/backups",
    [Parameter(Mandatory = $false)][string]$Tag = "",
    [Parameter(Mandatory = $false)][string]$PostgresContainer = "magpie-enterprise-postgres",
    [Parameter(Mandatory = $false)][string]$PostgresUser = "magpie",
    [Parameter(Mandatory = $false)][string]$PostgresDb = "magpie_enterprise",
    [Parameter(Mandatory = $false)][string]$RedisContainer = "magpie-enterprise-redis",
    [int]$RetainDays = 7
)

$ErrorActionPreference = "Stop"

if (!(Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$suffix = if ($Tag) { "-$Tag" } else { "" }
$baseName = "magpie-backup-$timestamp$suffix"

Write-Host "=== Magpie Enterprise Backup ==="
Write-Host "Target dir: $BackupDir"
Write-Host "Base name:  $baseName"

# --- Postgres backup ---
Write-Host "`n[1/2] Dumping Postgres database '$PostgresDb' ..."
$pgDumpFile = Join-Path $BackupDir "$baseName.postgres.sql"
& docker exec $PostgresContainer pg_dump -U $PostgresUser -d $PostgresDb > $pgDumpFile
if ($LASTEXITCODE -ne 0) {
    Write-Error "pg_dump failed"
}
Write-Host "Postgres dump written: $pgDumpFile"

# --- Redis backup ---
Write-Host "`n[2/2] Triggering Redis SAVE ..."
$rdbFile = Join-Path $BackupDir "$baseName.redis.rdb"
& docker exec $RedisContainer redis-cli SAVE > $null
& docker cp "$RedisContainer:/data/dump.rdb" $rdbFile
if ($LASTEXITCODE -ne 0) {
    Write-Error "Redis backup failed"
}
Write-Host "Redis dump written: $rdbFile"

# --- Prune old backups ---
Write-Host "`nPruning backups older than $RetainDays days ..."
$cutoff = (Get-Date).AddDays(-$RetainDays)
Get-ChildItem -Path $BackupDir -File |
    Where-Object { $_.LastWriteTime -lt $cutoff } |
    Remove-Item -Force

Write-Host "`nBackup complete."
Get-ChildItem -Path $BackupDir | Sort-Object LastWriteTime | Format-Table Name, Length, LastWriteTime
