#Requires -Version 5.1
<#
.SYNOPSIS
  Relaunch Bastion-Hardening.bat elevated (UAC) and wait for exit.

.DESCRIPTION
  Invoked by Bastion-Hardening.bat when the current console is not elevated.
  Lives next to the bat (product root) so the bat can use -File instead of a
  nested PowerShell one-liner. Nested parentheses in cmd one-liners caused
  ". was unexpected at this time." and flash-exit 255 on re-UAC.

.PARAMETER BatPath
  Full path to Bastion-Hardening.bat (passed as %~f0 from the launcher).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BatPath
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($BatPath) -or -not (Test-Path -LiteralPath $BatPath)) {
    Write-Host ""
    Write-Host "  ERROR: Bastion bat not found for elevation:" -ForegroundColor Red
    Write-Host ("  {0}" -f $BatPath) -ForegroundColor Red
    Write-Host ""
    exit 1
}

try {
    $p = Start-Process -FilePath $BatPath -Verb RunAs -Wait -PassThru
    if ($null -eq $p) {
        exit 1
    }
    exit [int]$p.ExitCode
}
catch {
    Write-Host ""
    Write-Host ("  Elevation failed: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Write-Host "  Right-click Bastion-Hardening.bat and choose Run as administrator." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
