#Requires -Version 5.1
<#
.SYNOPSIS
  Build the official Bastion release zip so Extract creates one folder.

.DESCRIPTION
  Layout inside the zip:

    bastion-hardening-v15.8/
      Bastion-Hardening.bat
      Bastion-Hardening.ps1
      ...
      docs/

  Windows Explorer "Extract All" then yields a single folder with everything
  together (not loose files at the extract root).

.PARAMETER Version
  Version label without leading v (e.g. 15.8). Default: read from env or 15.8.

.PARAMETER OutputDir
  Where to write the zip. Default: repo root \dist

.EXAMPLE
  pwsh -File tools/pack-release.ps1 -Version 15.8
#>
[CmdletBinding()]
param(
  [string]$Version = $(if ($env:BASTION_RELEASE_VERSION) { $env:BASTION_RELEASE_VERSION } else { "15.8.2" }),
  [string]$OutputDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
if (-not $OutputDir) {
  $OutputDir = Join-Path $RepoRoot "dist"
}

$Version = $Version.Trim().TrimStart("v", "V")
if ($Version -notmatch '^\d+(\.\d+)*([A-Za-z0-9._-]+)?$') {
  throw "Invalid Version '$Version' (expected like 15.7)."
}

$FolderName = "bastion-hardening-v$Version"
$ZipName = "$FolderName.zip"
$StageRoot = Join-Path $env:TEMP ("bastion-pack-" + [guid]::NewGuid().ToString("n"))
$StageDir = Join-Path $StageRoot $FolderName

function Copy-Required {
  param([string]$RelativePath)
  $src = Join-Path $RepoRoot $RelativePath
  if (-not (Test-Path -LiteralPath $src)) {
    throw "Missing required path: $RelativePath"
  }
  $dest = Join-Path $StageDir $RelativePath
  $destParent = Split-Path -Parent $dest
  if (-not (Test-Path -LiteralPath $destParent)) {
    New-Item -ItemType Directory -Path $destParent -Force | Out-Null
  }
  if (Test-Path -LiteralPath $src -PathType Container) {
    Copy-Item -LiteralPath $src -Destination $dest -Recurse -Force
  }
  else {
    Copy-Item -LiteralPath $src -Destination $dest -Force
  }
}

try {
  New-Item -ItemType Directory -Path $StageDir -Force | Out-Null

  # Runtime + legal + docs (handbook ships under docs/)
  $paths = @(
    "Bastion-Hardening.bat",
    "Bastion-Hardening.ps1",
    "Bastion-Banner.utf8.txt",
    "LICENSE",
    "NOTICE",
    "README.md",
    "SECURITY.md",
    "docs"
  )

  foreach ($p in $paths) {
    Copy-Required $p
  }

  # Do not ship packaging tools or git metadata inside the product zip
  $drop = @(
    (Join-Path $StageDir "docs\images"), # optional screenshots for README only; keep if present
    (Join-Path $StageDir ".git")
  )
  # Keep docs\images if they exist (README may reference them); no-op if missing.

  if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
  }

  $zipPath = Join-Path $OutputDir $ZipName
  if (Test-Path -LiteralPath $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
  }

  # Compress the folder so the zip root is bastion-hardening-vX.Y/
  Compress-Archive -Path $StageDir -DestinationPath $zipPath -CompressionLevel Optimal

  # Sanity: zip should contain FolderName/Bastion-Hardening.bat (not flat root)
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
  try {
    $norm = @($zip.Entries | ForEach-Object { ($_.FullName -replace '\\', '/').TrimStart('/') })
    $bat = "$FolderName/Bastion-Hardening.bat"
    $ps1 = "$FolderName/Bastion-Hardening.ps1"
    if ($norm -notcontains $bat) {
      $sample = ($norm | Select-Object -First 8) -join ', '
      throw "Zip sanity failed: expected entry $bat. Sample: $sample"
    }
    if ($norm -notcontains $ps1) {
      throw "Zip sanity failed: expected entry $ps1"
    }
    if ($norm -contains "Bastion-Hardening.bat") {
      throw "Zip sanity failed: flat root layout detected (Bastion-Hardening.bat at zip root)."
    }
  }
  finally {
    $zip.Dispose()
  }

  $item = Get-Item -LiteralPath $zipPath
  Write-Host "OK: $($item.FullName) ($([math]::Round($item.Length / 1KB, 1)) KB)"
  Write-Host "Extract yields folder: $FolderName\"
  Write-Host "Upload this file as the GitHub Release asset (name must match bastion-hardening-v*.zip)."
}
finally {
  if (Test-Path -LiteralPath $StageRoot) {
    Remove-Item -LiteralPath $StageRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}
