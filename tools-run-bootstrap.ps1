#Requires -Version 5.1
<#
.SYNOPSIS
  Elevated launch helper for Bastion-Hardening.bat.
  Unblocks Mark-of-the-Web, sets Process Bypass, runs Bastion-Hardening.ps1.

.DESCRIPTION
  PURPOSE
    After Bastion-Hardening.bat confirms High Integrity elevation, this script
    prepares the process and invokes the real PowerShell bootstrap.

  WHAT IT DOES
    1) Resolves product Root (folder with Bastion-Hardening.ps1 + src\).
    2) Sets ExecutionPolicy Bypass for this process only (not machine-wide).
    3) Recursively Unblock-File under Root (clears Zone.Identifier MOTW from
       Windows "downloaded from the Internet" zip extracts).
    4) Invokes Bastion-Hardening.ps1 (optional -BastionSmokeLoadOnly).
    5) Exits with the bootstrap's LASTEXITCODE.

  ROLE
    Kept as a .ps1 so cmd.exe never has to parse nested parentheses or
    PowerShell syntax inside the .bat (avoids cmd parse failures).

  DO NOT
    - Run as a substitute for reading modular source (this is a launcher only).
    - Encrypt or obfuscate (GPLv3; pack-release ships this plain next to the bat).
    - Skip the bat's elevation check; this helper assumes already elevated.

  SECURITY NOTES
    - Modular src\ is plain text (not encrypted). MANIFEST.sha256 = integrity.
    - DPAPI is only for DNS/RDP undo data after Apply (inside Bastion.Config.ps1).
    - Unblock-File only clears MOTW; it does not disable Defender or signature checks.
    - Process Bypass does not change user/machine ExecutionPolicy permanently.

.PARAMETER Root
  Product root directory. Defaults to this script's folder ($PSScriptRoot).

.PARAMETER BastionSmokeLoadOnly
  Forwarded to Bastion-Hardening.ps1 for packaging smoke tests.

.NOTES
  Ship next to Bastion-Hardening.bat (pack-release includes this file).
#>
param(
    [string]$Root = "",
    [switch]$BastionSmokeLoadOnly
)

$ErrorActionPreference = "Stop"

try {
    # Resolve product root: folder that must contain Bastion-Hardening.ps1 and src\.
    if ([string]::IsNullOrWhiteSpace($Root)) {
        $Root = $PSScriptRoot
    }
    if ([string]::IsNullOrWhiteSpace($Root)) {
        $Root = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    $Root = (Resolve-Path -LiteralPath $Root).Path

    # Process-scoped only so Restricted machines can still launch via the bat.
    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    } catch {}

    # Clear Mark-of-the-Web on extracted release files (zip from browser often blocks scripts).
    Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue |
        Unblock-File -ErrorAction SilentlyContinue

    $ps1 = Join-Path $Root "Bastion-Hardening.ps1"
    if (-not (Test-Path -LiteralPath $ps1)) {
        Write-Host ("Missing bootstrap: {0}" -f $ps1) -ForegroundColor Red
        exit 1
    }

    # Hand off to the real bootstrap (modules + menus, or smoke load only).
    if ($BastionSmokeLoadOnly) {
        & $ps1 -BastionSmokeLoadOnly
    } else {
        & $ps1
    }
    exit [int]$LASTEXITCODE
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
