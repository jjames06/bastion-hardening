@echo off
setlocal
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

echo.
echo  Bastion Hardening Framework
echo  Launching elevated PowerShell (UAC)...
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
echo  Waiting for the elevated Bastion window to finish...
echo  (If UAC appears, approve it. Errors stay visible in that window.)
echo.

rem -Wait so this parent bat does not flash-close after UAC accept.
rem ArgumentList as an array keeps paths with spaces intact.
rem Bootstrap Wait-BastionBootstrapKey also pauses on fatals inside the elevated process.
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { $p = Start-Process -FilePath powershell.exe -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','%~dp0Bastion-Hardening.ps1'); if ($null -eq $p) { exit 1 }; exit $p.ExitCode } catch { Write-Host $_.Exception.Message; exit 1 }"
set "ERR=%ERRORLEVEL%"

if not "%ERR%"=="0" (
    echo.
    echo  Bastion elevated process failed or UAC was declined (exit %ERR%).
    echo  - If you clicked No on UAC: right-click Bastion-Hardening.bat - Run as administrator.
    echo  - If UAC was approved: read the error in the elevated window (it should have paused).
    echo  - Expected layout: Bastion-Hardening.ps1 next to src\Bastion.*.ps1 and src\MANIFEST.sha256
    echo.
    pause
    exit /b %ERR%
)

endlocal
