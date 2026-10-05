<#
.SYNOPSIS
    Rebuilds unveil-single.cmd - the one file you hand to a friend.

.DESCRIPTION
    Bundles unveil.ps1 into a single self-extracting .cmd. The friend double-clicks
    one file; it unpacks itself into %TEMP%, runs, and cleans up. No PowerShell
    script next to it, no zip, no install, no warnings.

    Why a .cmd and not a .exe: an unsigned .exe trips SmartScreen on a stranger's
    machine and gets flagged by heuristic AV. A .cmd does neither. Building an .exe
    would also need a compiler (csc or dotnet), neither of which is present here.

.PARAMETER OutFile
    Where to write the bundle. Defaults to unveil-single.cmd beside this script.

.EXAMPLE
    .\build.ps1
    Produces unveil-single.cmd next to unveil.ps1.
#>
[CmdletBinding()]
param(
    [string] $OutFile = (Join-Path $PSScriptRoot 'unveil-single.cmd')
)

$ErrorActionPreference = 'Stop'

$source = Join-Path $PSScriptRoot 'unveil.ps1'
if (-not (Test-Path $source)) { throw "unveil.ps1 not found next to this script" }

# Plain alphanumeric token: no %, no :, no #, so nothing in it can be misread or
# interpolated by cmd. It appears twice by design - once in the header, once as the
# separator - and the extractor uses LastIndexOf to skip the header copy.
$Marker = 'UNVEIL_PAYLOAD_BEGIN_9F3A2C7E'

$payload = [IO.File]::ReadAllText($source, [Text.Encoding]::UTF8)
if ($payload.Contains($Marker)) { throw 'the marker also appears inside unveil.ps1' }

# Header is ASCII-only. It does extraction and execution as two separate steps:
# -File forwards %* natively, so switches like -Target and -SkipDownload arrive as
# real parameters. Doing both from one -Command block required re-splitting the
# arguments in PowerShell, and array splatting passes positionally - which silently
# turned "-Target" into the value of the first parameter instead of its name.
$header = @'
@echo off
REM unveil - single file build. Double-click to run; no arguments needed.
REM Self-extracting: the PowerShell pipeline is appended below the marker.

setlocal

set "UNVEIL_SELF=%~f0"
set "UNVEIL_MARKER=UNVEIL_PAYLOAD_BEGIN_9F3A2C7E"

set "PSEXE="
where pwsh.exe >nul 2>&1 && set "PSEXE=pwsh.exe"
if not defined PSEXE where powershell.exe >nul 2>&1 && set "PSEXE=powershell.exe"

if not defined PSEXE (
    echo [XX] No PowerShell found on PATH.
    echo     Install PowerShell 7 ^(https://aka.ms/powershell^) or enable
    echo     Windows PowerShell 5.1, then run unveil.ps1 directly.
    if not defined UNVEIL_NO_PAUSE pause
    exit /b 1
)

set "UNVEIL_TMP=%TEMP%\unveil-%RANDOM%%RANDOM%"

REM Step 1 - unpack the payload that lives below the marker in this same file.
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $c=[IO.File]::ReadAllText($env:UNVEIL_SELF,[Text.Encoding]::UTF8); $m=$env:UNVEIL_MARKER; $i=$c.LastIndexOf($m); if($i -lt 0){Write-Host '[XX] payload marker missing' -ForegroundColor Red; exit 2}; $p=$c.Substring($i+$m.Length).TrimStart([char]10,[char]13,[char]32); $d=$env:UNVEIL_TMP; New-Item -ItemType Directory -Path $d -Force | Out-Null; [IO.File]::WriteAllText((Join-Path $d 'unveil.ps1'),$p,(New-Object Text.UTF8Encoding $false))"

if errorlevel 1 (
    if not defined UNVEIL_NO_PAUSE pause
    exit /b 2
)

echo ==== unveil ==========================================
echo     unpacked to %UNVEIL_TMP%
echo.

REM Step 2 - run it. -File hands %* to PowerShell's own parser.
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%UNVEIL_TMP%\unveil.ps1" %*
set "RC=%ERRORLEVEL%"

REM Step 3 - clean up the temporary copy.
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -Command "Remove-Item -LiteralPath $env:UNVEIL_TMP -Recurse -Force -ErrorAction SilentlyContinue"

echo.
if "%RC%"=="0" (
    echo [ok] done.
) else (
    echo [XX] unveil exited with code %RC%.
    echo     Logs: %%LOCALAPPDATA%%\unveil\work\logs
)

if not defined UNVEIL_NO_PAUSE pause
endlocal & exit /b %RC%

'@

# CRLF throughout: cmd is happiest with it, and PowerShell parses it either way.
$bundle = ($header -replace "`r`n", "`n").Replace("`n", "`r`n") +
          $Marker + "`r`n" +
          ($payload -replace "`r`n", "`n").Replace("`n", "`r`n")

[IO.File]::WriteAllText($OutFile, $bundle, (New-Object Text.UTF8Encoding $false))

# Verify the artifact rather than trusting the write.
$written = [IO.File]::ReadAllText($OutFile, [Text.Encoding]::UTF8)
$count = ([regex]::Matches($written, [regex]::Escape($Marker))).Count
if ($count -ne 2) { throw "marker appears $count times, expected 2 (header + separator)" }
if ($written.LastIndexOf($Marker) -le $written.IndexOf($Marker)) {
    throw 'separator must come after the header copy, or extraction unpacks the header'
}

$head = $written.Substring(0, $written.LastIndexOf($Marker))
if ($head -match '[^\x00-\x7F]') { throw 'header is not ASCII-only; cmd may misparse it' }

$extracted = $written.Substring($written.LastIndexOf($Marker) + $Marker.Length)
# Compare with line endings normalized: the payload is deliberately rewritten to CRLF
# for cmd, while unveil.ps1 on disk is LF-only, so a raw compare would always differ.
$norm = { param($s) (($s -replace "`r`n", "`n").TrimStart("`n")) }
if ((& $norm $extracted) -ne (& $norm $payload)) {
    throw 'payload does not survive the round-trip'
}

$kb = [math]::Round((Get-Item $OutFile).Length / 1KB, 1)
Write-Host "built $OutFile  ($kb KB, payload $($payload.Length) chars, marker x$count)" -ForegroundColor Green
Write-Host 'hand over that one file.' -ForegroundColor DarkGray