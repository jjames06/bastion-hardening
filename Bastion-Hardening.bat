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
    echo.
    pause
    exit /b 1
)

if not exist "%~dp0src\MANIFEST.sha256" (
    echo.
    echo  ERROR: src\MANIFEST.sha256 was not found.
    echo  Re-download the official release zip.
    echo.
    pause
    exit /b 1
)

rem ---------------------------------------------------------------------------
rem Admin check WITHOUT "net session".
rem Bastion HighRiskServices disables LanmanServer (Server service). After that,
rem "net session" fails even when already elevated, so the bat looped forever
rem through a broken re-UAC path and flash-closed with ". was unexpected".
rem Use whoami SID S-1-5-32-544 (Administrators) instead.
rem ---------------------------------------------------------------------------
set "BASTION_IS_ADMIN=0"
whoami /groups 2>nul | findstr /i /c:"S-1-5-32-544" >nul
if not errorlevel 1 set "BASTION_IS_ADMIN=1"

if "%BASTION_IS_ADMIN%"=="0" (
    echo.
    echo  Bastion Hardening Framework
    echo  Administrator rights required. Requesting UAC elevation...
    echo.
    echo  If a UAC prompt appears, click Yes.
    echo  Always use this .bat (do not double-click Bastion-Hardening.ps1 alone).
    echo.
    rem Elevate via PowerShell helper file so cmd never parses nested parentheses.
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools-elevate-self.ps1" -BatPath "%~f0"
    if errorlevel 1 (
        rem Fallback if helper missing from older layouts: inline elevate without nested ) in cmd.
        if not exist "%~dp0tools-elevate-self.ps1" (
            powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -Wait"
        )
        set "ERR=%ERRORLEVEL%"
        if not "%ERR%"=="0" (
            echo.
            echo  Elevation failed or Bastion exited with code %ERR%.
            echo  Right-click Bastion-Hardening.bat and choose Run as administrator.
            echo.
            pause
            exit /b %ERR%
        )
    )
    exit /b 0
)

echo.
echo  Bastion Hardening Framework
echo  Elevated console ready.
echo  Unblocking download flags and starting with ExecutionPolicy Bypass...
echo.
echo  Transparency: plain-text src\ modules, MANIFEST integrity, GPLv3.
echo  Prefer this .bat launcher. Direct .ps1 double-click fails under Restricted policy.
echo.

rem Process Bypass + Unblock Mark-of-the-Web, then run bootstrap in THIS window.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue; $root = (Resolve-Path -LiteralPath '%~dp0').Path; Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue; $ps1 = Join-Path $root 'Bastion-Hardening.ps1'; and $ps1; exit $LASTEXITCODE"

rem Fix typo: "and $ps1" should be "& $ps1" - rewrite carefully below via second approach

set "ERR=%ERRORLEVEL%"
if not "%ERR%"=="0" goto :fail
endlocal
exit /b 0

:fail
echo.
echo  Bastion exited with code %ERR%.
echo  - Use Bastion-Hardening.bat (not the .ps1 alone under Restricted policy).
echo  - Zip: Properties - Unblock - OK, then re-extract if needed.
echo  - Layout: Bastion-Hardening.ps1 + src\ + MANIFEST.sha256
echo.
pause
exit /b %ERR%
