@echo off
REM unveil - launcher.
REM
REM Why this file exists: on a default Windows install, double-clicking unveil.ps1
REM does nothing useful. ExecutionPolicy commonly blocks unsigned local scripts,
REM so the user double-clicks, sees nothing happen, and blames the tool. This
REM wrapper keeps the double-click path working on a stock machine.
REM
REM It bypasses ExecutionPolicy ONLY for its own child process, via -ExecutionPolicy
REM Bypass on the command line. That setting is process-scoped and dies with it: the
REM machine's policy is never modified. Doing this quietly to someone else's machine
REM would be the wrong example, so run.cmd changes nothing persistent. If you would
REM rather decide for yourself, use Set-ExecutionPolicy -Scope Process and run
REM unveil.ps1 yourself.

setlocal EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "PS1=%SCRIPT_DIR%unveil.ps1"

if not exist "%PS1%" (
    echo [XX] unveil.ps1 not found next to this launcher.
    echo     Expected: %PS1%
    echo.
    pause
    exit /b 1
)

echo ==== unveil ==========================================
echo.

REM Prefer pwsh (PowerShell 7, cross-platform) when present, else Windows PowerShell.
set "PSEXE="
where pwsh.exe >nul 2>&1 && set "PSEXE=pwsh.exe"
if not defined PSEXE (
    where powershell.exe >nul 2>&1 && set "PSEXE=powershell.exe"
)

if not defined PSEXE (
    echo [XX] No PowerShell found on PATH.
    echo     Install PowerShell 7 ^(https://aka.ms/powershell^) or enable
    echo     Windows PowerShell 5.1, then run unveil.ps1 directly.
    echo.
    pause
    exit /b 1
)

REM -NoProfile: do not pollute the run with the user's profile.
REM -ExecutionPolicy Bypass: process-scoped, applies to this child only, changes
REM     nothing on the machine. It is what lets an unsigned local script run at all.
REM -File: runs the file, and forwards any arguments the user passed through.
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*

set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo [ok] done.
) else (
    echo [XX] unveil exited with code %RC%.
    echo     See the logs under %%LOCALAPPDATA%%\unveil\work\logs
)

REM Keep the window open so results can be read and the launcher can be re-run.
if not defined UNVEIL_NO_PAUSE pause
exit /b %RC%