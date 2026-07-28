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

echo.
echo  Bastion Hardening Framework
echo  Launching elevated PowerShell...
echo.
echo  Transparency (also in README and docs\):
echo  - First run creates a writable data directory and seeds menu defaults.
echo  - Session logs and config live there; path is shown on the main menu.
echo  - Apply history (Bastion-LastApply.json) is written only after a real Apply.
echo  - Encrypted Client Hello (ECH) is never enabled unless you opt in under Strict.
echo  - Dry Run / Apply detect live Windows state; they do not fake prior hardening.
echo  - License: GNU GPLv3 (LICENSE + NOTICE). Free software; modified distributions must stay GPLv3 with source.
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%~dp0Bastion-Hardening.ps1\"'"
set "ERR=%ERRORLEVEL%"
if not "%ERR%"=="0" (
    echo.
    echo  Launch failed or UAC was declined (exit %ERR%).
    echo  Right-click Bastion-Hardening.bat and choose Run as administrator.
    echo.
    pause
    exit /b %ERR%
)

endlocal
