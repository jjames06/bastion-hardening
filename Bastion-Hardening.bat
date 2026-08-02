@echo off
setlocal EnableExtensions
title Bastion Hardening Framework
cd /d "%~dp0"

if not exist "%~dp0Bastion-Hardening.ps1" (
    echo.
    echo  ERROR: Bastion-Hardening.ps1 was not found next to this batch file.
    echo  Keep Bastion-Hardening.bat and Bastion-Hardening.ps1 in the same folder.
    echo.
    pause
    exit /b 1
)

if not exist "%~dp0src\Bastion.Core.ps1" (
    echo.
    echo  ERROR: Modular sources missing (src\Bastion.Core.ps1).
    echo  Keep the src\ folder next to Bastion-Hardening.ps1 (official release layout).
    echo  Do not run a lone .ps1 without the src modules.
    echo.
    pause
    exit /b 1
)

if not exist "%~dp0src\MANIFEST.sha256" (
    echo.
    echo  ERROR: src\MANIFEST.sha256 was not found.
    echo  Integrity manifest is required. Re-download the official release zip.
    echo.
    pause
    exit /b 1
)

rem ---------------------------------------------------------------------------
rem Self-elevate THIS batch file so Bastion runs in the elevated console.
rem (A separate Start-Process powershell child was easy to miss if it flash-closed.)
rem ---------------------------------------------------------------------------
net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo  Bastion Hardening Framework
    echo  Administrator rights required. Requesting UAC elevation...
    echo.
    echo  If a UAC prompt appears, click Yes.
    echo  The elevated window keeps errors visible (pause on failure).
    echo.
    rem Relaunch this .bat elevated and wait. Parent stays open only to report UAC decline.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $p = Start-Process -FilePath \"%~f0\" -Verb RunAs -Wait -PassThru; if ($null -eq $p) { exit 1 }; exit $p.ExitCode } catch { Write-Host $_.Exception.Message; exit 1 }"
    set "ERR=%ERRORLEVEL%"
    if not "%ERR%"=="0" (
        echo.
        echo  Elevation failed or Bastion exited with code %ERR%.
        echo  - If you clicked No on UAC: right-click Bastion-Hardening.bat - Run as administrator.
        echo  - If UAC was approved: read the error in the elevated window (it should have paused).
        echo  - Expected layout: Bastion-Hardening.ps1 next to src\Bastion.*.ps1 and src\MANIFEST.sha256
        echo.
        pause
        exit /b %ERR%
    )
    exit /b 0
)

echo.
echo  Bastion Hardening Framework
echo  Elevated console ready. Starting PowerShell...
echo.
echo  Transparency (also in README and docs\):
echo  - First run creates a writable data directory and seeds menu defaults.
echo  - Session logs and config live there; path is shown on the main menu.
echo  - Apply history (Bastion-LastApply.json) is written only after a real Apply.
echo  - Encrypted Client Hello (ECH) is never enabled unless you opt in under Strict.
echo  - Dry Run / Apply detect live Windows state; they do not fake prior hardening.
echo  - Source is plain-text under src\ (GPLv3); startup verifies SHA256 MANIFEST.
echo  - License: GNU GPLv3 (LICENSE + NOTICE). Free software; modified distributions must stay GPLv3 with source.
echo.

rem Run in THIS elevated window so menus/errors never vanish into a child process.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Bastion-Hardening.ps1"
set "ERR=%ERRORLEVEL%"

if not "%ERR%"=="0" (
    echo.
    echo  Bastion exited with code %ERR%.
    echo  - Expected layout: Bastion-Hardening.ps1 next to src\Bastion.*.ps1 and src\MANIFEST.sha256
    echo  - Re-download the official release zip if modules or MANIFEST are missing/corrupt.
    echo.
    pause
    exit /b %ERR%
)

endlocal
exit /b 0
