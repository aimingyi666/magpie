#!/usr/bin/env pwsh
# Reports the drift gates of devtools/enterprise-drift-plan.md: the working
# tree, branches not merged into main, what a merge into main would conflict
# on, and the worktrees open on this machine.
#
#   pwsh -File devtools/check-drift.ps1
#
# Exit 0 when G0, G1, G2 and G6 hold; 1 when any fails. G3-G5, G7 are run by
# hand: they need the suites and a reading of the status document.

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo

$failed = $false

function Section([string]$name) {
  Write-Host ""
  Write-Host "== $name =="
}

function Fail([string]$why) {
  Write-Host "!! $why"
  $script:failed = $true
}

# G0: nothing uncommitted, so every change has an owner and a commit.
Section "G0 working tree"
$status = @(git status --porcelain)
if ($status.Count -eq 0) {
  Write-Host "clean"
} else {
  $status | ForEach-Object { Write-Host $_ }
  Fail "$($status.Count) uncommitted entries"
}

# G1: only the integration branch and a frozen branch may be unmerged.
Section "G1 branches not merged into main"
$divergent = @()
foreach ($branch in @(git for-each-ref --format="%(refname:short)" refs/heads)) {
  git merge-base --is-ancestor $branch main 2>$null
  if ($LASTEXITCODE -ne 0) { $divergent += $branch }
}
if ($divergent.Count -eq 0) {
  Write-Host "none"
} else {
  $divergent | ForEach-Object { Write-Host $_ }
  if ($divergent.Count -gt 2) { Fail "$($divergent.Count) branches are unmerged; expected at most 2" }
}

# G2: a merge into main would write without conflicts.
Section "G2 merge into main"
$tree = @(git merge-tree --write-tree --name-only HEAD main 2>&1)
if ($LASTEXITCODE -eq 0) {
  Write-Host "no conflicts"
} else {
  $conflicts = @($tree | Where-Object { $_ -like "CONFLICT*" })
  $conflicts | ForEach-Object { Write-Host $_ }
  Fail "$($conflicts.Count) conflicts"
}

# G6: one checkout per session, and no one left behind.
Section "G6 worktrees"
$worktrees = @(git worktree list)
$worktrees | ForEach-Object { Write-Host $_ }
if ($worktrees.Count -gt 2) { Fail "$($worktrees.Count) worktrees; expected at most 2" }

Pop-Location
Write-Host ""
if ($failed) {
  Write-Host "drift: gates failed"
  exit 1
}
Write-Host "drift: G0, G1, G2 and G6 hold"
exit 0
