#Requires -Version 5.1
<#
.SYNOPSIS
  Elevate Bastion-Hardening.bat via UAC and wait (used only by the .bat).

.DESCRIPTION
  PURPOSE
    Thin helper so Bastion-Hardening.bat can re-launch itself elevated without
    embedding nested PowerShell parentheses inside parenthesized cmd blocks
    (those break cmd parsing with ". was unexpected at this time.").

  ROLE
    Called only when the bat detects the process is NOT High Integrity
    (missing SID S-1-16-12288). Starts the same .bat with -Verb RunAs and
    waits so the parent bat can surface the elevated child's exit code.

  DO NOT
    - Run standalone as a hardening tool (it only elevates a bat path).
    - Encrypt this file; it ships plain text in the release zip.
    - Treat this as integrity verification (that is MANIFEST.sha256 in src\).

  SECURITY NOTES
    - UAC consent is explicit (RunAs). User must approve the prompt.
    - Modular Bastion source remains plain text (GPLv3).
    - DPAPI is only for undo data after Apply, never for this helper.

.PARAMETER BatPath
  Full path to Bastion-Hardening.bat (or any bat to elevate). Mandatory.

.NOTES
  Packaged in the release zip next to Bastion-Hardening.bat.
  Exit codes: child process exit code, or 1 if missing path / Start-Process failed.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$BatPath
)

$ErrorActionPreference = "Stop"

# Fail closed if the bat was moved or the caller passed a bad path.
if (-not (Test-Path -LiteralPath $BatPath)) {
    Write-Host ("Missing bat: {0}" -f $BatPath) -ForegroundColor Red
    exit 1
}

try {
    # RunAs triggers UAC. -Wait keeps this process alive until the elevated bat exits
    # so the non-elevated parent bat can exit /b with the same ERRORLEVEL.
    $p = Start-Process -FilePath $BatPath -Verb RunAs -Wait -PassThru
    if ($null -eq $p) { exit 1 }
    exit [int]$p.ExitCode
} catch {
    # User cancelled UAC or Start-Process failed (policy, path, etc.).
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
