#Requires -Version 5.1
<#
.SYNOPSIS
  Elevate Bastion-Hardening.bat via UAC and wait (used only by the .bat).
  Kept as a .ps1 so cmd.exe never has to parse nested parentheses.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$BatPath
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $BatPath)) {
    Write-Host ("Missing bat: {0}" -f $BatPath) -ForegroundColor Red
    exit 1
}

try {
    $p = Start-Process -FilePath $BatPath -Verb RunAs -Wait -PassThru
    if ($null -eq $p) { exit 1 }
    exit [int]$p.ExitCode
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
