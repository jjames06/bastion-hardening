#Requires -Version 5.1
<#
.SYNOPSIS
  Regenerate src\MANIFEST.sha256 for Bastion plain-text modules.

.DESCRIPTION
  Hashes every *.ps1 under src\ (and other non-manifest files you choose to include).
  Format:  <SHA256>  <relative-path>
  Developers: run after editing any src\*.ps1. pack-release may call this before packing.

.EXAMPLE
  pwsh -File tools/New-BastionSourceManifest.ps1
#>
[CmdletBinding()]
param(
  [string]$SrcDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
if (-not $SrcDir) {
  $SrcDir = Join-Path $RepoRoot "src"
}
if (-not (Test-Path -LiteralPath $SrcDir -PathType Container)) {
  throw "src directory not found: $SrcDir"
}

$manifestPath = Join-Path $SrcDir "MANIFEST.sha256"
$files = Get-ChildItem -LiteralPath $SrcDir -File |
  Where-Object {
    $_.Name -ne "MANIFEST.sha256" -and
    $_.Name -notlike "_*" -and
    $_.Extension -in @(".ps1", ".txt", ".md")
  } |
  Sort-Object Name

if ($files.Count -lt 1) {
  throw "No source files to hash under $SrcDir"
}

$lines = New-Object System.Collections.Generic.List[string]
[void]$lines.Add("# Bastion source integrity manifest (SHA256)")
[void]$lines.Add("# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$lines.Add("# Regenerate: pwsh -File tools/New-BastionSourceManifest.ps1")
[void]$lines.Add("# Format: hash  relativepath (paths relative to src\)")
[void]$lines.Add("")

foreach ($f in $files) {
  $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToUpperInvariant()
  # Relative to src\ for portable verify
  [void]$lines.Add(("{0}  {1}" -f $hash, $f.Name))
}

$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllLines($manifestPath, $lines, $utf8NoBom)
Write-Host "Wrote $manifestPath ($($files.Count) files)"
foreach ($f in $files) {
  Write-Host ("  {0}" -f $f.Name)
}
