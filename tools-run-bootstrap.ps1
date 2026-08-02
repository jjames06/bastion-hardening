#Requires -Version 5.1
<#
.SYNOPSIS
  Elevated launch helper for Bastion-Hardening.bat.
  Unblocks Mark-of-the-Web, sets Process Bypass, runs Bastion-Hardening.ps1.
  Kept as a .ps1 so cmd.exe never has to parse nested parentheses or PowerShell syntax.
.NOTES
  Ship next to Bastion-Hardening.bat (pack-release includes this file).
  Modular src\ is plain text (not encrypted). DPAPI is only for undo data after Apply.
#>
param(
    [string]$Root = "",
    [switch]$BastionSmokeLoadOnly
)

$ErrorActionPreference = "Stop"

try {
    if ([string]::IsNullOrWhiteSpace($Root)) {
        $Root = $PSScriptRoot
    }
    if ([string]::IsNullOrWhiteSpace($Root)) {
        $Root = Split-Path -Parent $MyInvocation.MyCommand.Path
    }
    $Root = (Resolve-Path -LiteralPath $Root).Path

    try {
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    } catch {}

    Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue |
        Unblock-File -ErrorAction SilentlyContinue

    $ps1 = Join-Path $Root "Bastion-Hardening.ps1"
    if (-not (Test-Path -LiteralPath $ps1)) {
        Write-Host ("Missing bootstrap: {0}" -f $ps1) -ForegroundColor Red
        exit 1
    }

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
