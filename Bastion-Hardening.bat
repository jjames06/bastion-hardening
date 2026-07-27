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
echo  On first run, Bastion creates a writable data directory and seeds defaults.
echo  Dry Run / Apply detect live Windows state; Apply history is only written after Apply.
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
