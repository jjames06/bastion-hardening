@echo off
setlocal EnableExtensions
title Bastion Hardening Framework
cd /d "%~dp0"

if not exist "%~dp0Bastion-Hardening.ps1" goto :err_missing_ps1
if not exist "%~dp0src\Bastion.Core.ps1" goto :err_missing_src
if not exist "%~dp0src\MANIFEST.sha256" goto :err_missing_manifest

rem ---------------------------------------------------------------------------
rem Elevation check WITHOUT "net session".
rem Bastion HighRiskServices can disable LanmanServer (Server service). After that,
rem "net session" fails even when already elevated -> infinite re-UAC + flash-close.
rem
rem Use High Mandatory Level SID S-1-16-12288 (true elevated / high integrity token).
rem Do NOT use Administrators group S-1-5-32-544 alone: non-elevated UAC tokens still
rem list that SID as "deny only", which would skip UAC and fail later in PowerShell.
rem
rem Also avoid parenthesized if-blocks with echo lines containing "(" or ")" - cmd
rem treats those as block delimiters and fails with ". was unexpected at this time."
rem Prefer goto labels + helper .ps1 files so cmd never parses nested PowerShell.
rem ---------------------------------------------------------------------------
set "BASTION_IS_ADMIN=0"
whoami /groups 2>nul | findstr /i /c:"S-1-16-12288" >nul
if not errorlevel 1 set "BASTION_IS_ADMIN=1"

if "%BASTION_IS_ADMIN%"=="1" goto :run_elevated

echo.
echo  Bastion Hardening Framework
echo  Administrator rights required. Requesting UAC elevation...
echo.
echo  If a UAC prompt appears, click Yes.
echo  Always use this .bat - do not double-click Bastion-Hardening.ps1 alone.
echo.

if exist "%~dp0tools-elevate-self.ps1" goto :elevate_helper
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -Wait"
goto :elevate_done

:elevate_helper
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools-elevate-self.ps1" -BatPath "%~f0"

:elevate_done
set "ERR=%ERRORLEVEL%"
if "%ERR%"=="0" exit /b 0
echo.
echo  Elevation failed or Bastion exited with code %ERR%.
echo  Right-click Bastion-Hardening.bat and choose Run as administrator.
echo  Do not double-click Bastion-Hardening.ps1 under Restricted policy.
echo.
pause
exit /b %ERR%

:run_elevated
echo.
echo  Bastion Hardening Framework
echo  Elevated console ready.
echo  Unblocking download flags and starting with ExecutionPolicy Bypass...
echo.
echo  Transparency: plain-text src modules, MANIFEST integrity, GPLv3.
echo  Prefer this .bat. Direct .ps1 double-click fails when scripts are disabled.
echo  Encryption note: only DNS/RDP undo data uses DPAPI; modular source is never encrypted.
echo.

if exist "%~dp0tools-run-bootstrap.ps1" goto :run_via_helper
rem Fallback if helper missing: still avoid nested parentheses in this .bat
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Bastion-Hardening.ps1"
goto :after_run

:run_via_helper
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools-run-bootstrap.ps1"

:after_run
set "ERR=%ERRORLEVEL%"
if "%ERR%"=="0" goto :success
echo.
echo  Bastion exited with code %ERR%.
echo  - Always use Bastion-Hardening.bat, not the .ps1 alone.
echo  - Zip: Properties - Unblock - OK, then re-extract if needed.
echo  - Layout: Bastion-Hardening.ps1 + src + MANIFEST.sha256 + tools helpers
echo.
pause
exit /b %ERR%

:success
endlocal
exit /b 0

:err_missing_ps1
echo.
echo  ERROR: Bastion-Hardening.ps1 was not found next to this batch file.
echo  Keep Bastion-Hardening.bat and Bastion-Hardening.ps1 in the same folder.
echo.
pause
exit /b 1

:err_missing_src
echo.
echo  ERROR: Modular sources missing - expected src\Bastion.Core.ps1.
echo  Keep the src folder next to Bastion-Hardening.ps1 [official release layout].
echo.
pause
exit /b 1

:err_missing_manifest
echo.
echo  ERROR: src\MANIFEST.sha256 was not found.
echo  Re-download the official release zip.
echo.
pause
exit /b 1
