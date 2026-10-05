<#
.SYNOPSIS
    Builds unveil-single.cmd - the one file you hand to a friend.

.DESCRIPTION
    With a toolchain archive, produces a self-contained bundle: double-click and it
    runs, unpacking the engine and a minimal JVM into %LOCALAPPDATA%. Nothing is
    downloaded, nothing is installed, no compiler, no network.

    Without one, produces a small launcher that downloads the engine on first run.

    Why a .cmd and not a .exe: an unsigned .exe trips SmartScreen on a stranger's
    machine and gets flagged by heuristic AV. A .cmd does neither. Building an .exe
    would also need a compiler (csc or dotnet), which is not something to require of
    someone else's computer.

.PARAMETER Toolchain
    A tar.zst (or tar.xz) archive whose entries are the toolchain directories
    themselves, e.g. ghidra_12.1.4_PUBLIC/ and jdk-21.0.12.1+1-jlink/. Entries must
    land directly in unveil's WorkDir\tools.

.PARAMETER PackInstalled
    Build the toolchain archive from the copy unveil already installed under
    %LOCALAPPDATA%\unveil\work, then bundle that. Makes the one-file build
    reproducible from a clone: run unveil.ps1 once to fetch the engine, then run
    this. Nothing is re-downloaded.

.EXAMPLE
    .\build.ps1
    Small launcher, ~30 KB. Engine downloads on first run.

.EXAMPLE
    .\build.ps1 -PackInstalled
    Self-contained ~178 MB bundle, built from the already-installed engine.
#>
[CmdletBinding()]
param(
    [string] $OutFile    = (Join-Path $PSScriptRoot 'unveil-single.cmd'),
    [string] $Toolchain,
    [switch] $PackInstalled
)

$ErrorActionPreference = 'Stop'

# Compiled scan: the toolchain is ~178 MB and a PowerShell byte loop over it takes
# minutes. Compiled, the same checks run in well under a second.
Add-Type -TypeDefinition @'
using System;
public static class Scan {
  public static int IndexOf(byte[] hay, byte[] needle) {
    for (int i = 0; i <= hay.Length - needle.Length; i++) {
      int j = 0;
      for (; j < needle.Length; j++) if (hay[i + j] != needle[j]) break;
      if (j == needle.Length) return i;
    }
    return -1;
  }
  public static int LastIndexOf(byte[] hay, byte[] needle) {
    for (int i = hay.Length - needle.Length; i >= 0; i--) {
      int j = 0;
      for (; j < needle.Length; j++) if (hay[i + j] != needle[j]) break;
      if (j == needle.Length) return i;
    }
    return -1;
  }
  public static int Count(byte[] hay, byte[] needle) {
    int n = 0;
    for (int i = 0; i <= hay.Length - needle.Length; i++) {
      int j = 0;
      for (; j < needle.Length; j++) if (hay[i + j] != needle[j]) break;
      if (j == needle.Length) n++;
    }
    return n;
  }
  public static bool Eq(byte[] a, int off, byte[] b, int len) {
    if (off < 0 || off + len > a.Length) return false;
    for (int i = 0; i < len; i++) if (a[off + i] != b[i]) return false;
    return true;
  }
}
'@

$source = Join-Path $PSScriptRoot 'unveil.ps1'
if (-not (Test-Path $source)) { throw "unveil.ps1 not found next to this script" }

$PayloadToken = 'UNVEIL_PAYLOAD_BEGIN_9F3A2C7E'
$ChainToken   = 'UNVEIL_TOOLCHAIN_BEGIN_4B8E1D93'

if ($PackInstalled) {
    # Build the archive from what unveil already downloaded, so a clone can reproduce
    # the one-file bundle without re-pinning URLs or hashes here. Running unveil.ps1
    # once is the only prerequisite.
    $tools = Join-Path $env:LOCALAPPDATA 'unveil\work\tools'
    $gh = Get-ChildItem $tools -Directory -Filter 'ghidra_*_PUBLIC' -ErrorAction SilentlyContinue | Select-Object -First 1
    $jk = Get-ChildItem $tools -Directory -Filter 'jdk-*' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $gh -or -not $jk -or -not (Test-Path (Join-Path $jk.FullName 'bin\jlink.exe'))) {
        throw "no full toolchain under $tools - run .\unveil.ps1 once first"
    }

    # analyzeHeadless.bat forwards arguments unquoted, so no path may contain parens.
    $stage = Join-Path $env:TEMP 'unveil-tc'
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $stage | Out-Null

    $ghOut = Join-Path $stage $gh.Name
    Write-Host "    stripping $($gh.Name) ..."
    # docs is documentation, Extensions ships IDE plugins, Debug holds every debugger
    # backend, and FunctionID/BSim/GhidraServer/PyGhidra are unused headless.
    $null = robocopy $gh.FullName $ghOut /E /NFL /NDL /NJH /NJS /NP /XD `
        (Join-Path $gh.FullName 'docs') (Join-Path $gh.FullName 'Extensions') `
        (Join-Path $gh.FullName 'docker') (Join-Path $gh.FullName 'server') `
        (Join-Path $gh.FullName 'Ghidra\Debug') `
        (Join-Path $gh.FullName 'Ghidra\Features\FunctionID') `
        (Join-Path $gh.FullName 'Ghidra\Features\BSim') `
        (Join-Path $gh.FullName 'Ghidra\Features\GhidraServer') `
        (Join-Path $gh.FullName 'Ghidra\Features\PyGhidra')
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed with $LASTEXITCODE" }

    $jreName = ($jk.Name + '-jlink')
    Write-Host "    building minimal runtime from $($jk.Name) ..."
    # jlink is what turns a 328 MB JDK into a 50 MB runtime. Verified against
    # analyzeHeadless: the stripped tree plus this runtime completes a full run.
    $modules = 'java.base,java.compiler,java.datatransfer,java.xml,java.prefs,java.desktop,' +
               'java.instrument,java.logging,java.management,java.naming,java.rmi,java.scripting,' +
               'java.security.jgss,java.sql,java.xml.crypto,java.se,java.smartcardio,' +
               'jdk.crypto.ec,jdk.unsupported,jdk.zipfs,jdk.httpserver'
    & (Join-Path $jk.FullName 'bin\jlink.exe') --add-modules $modules `
        --strip-debug --no-header-files --no-man-pages --compress=2 `
        --output (Join-Path $stage $jreName) 2>&1 | Where-Object { $_ -notmatch 'deprecat' } | Out-Null
    if (-not (Test-Path (Join-Path $stage "$jreName\bin\java.exe"))) { throw 'jlink produced no runtime' }

    $archive = Join-Path $env:TEMP 'unveil-tc.tar.zst'
    Remove-Item $archive -Force -ErrorAction SilentlyContinue
    Write-Host '    compressing (this takes a few minutes) ...'
    Push-Location $stage
    & tar -cf $archive --zstd --options zstd:compression-level=19 -C $stage $gh.Name $jreName
    $rc = $LASTEXITCODE
    Pop-Location
    if ($rc -ne 0 -or -not (Test-Path $archive)) { throw "tar failed with $rc" }

    # Prove the archive really carries the engine instead of trusting the exit code.
    $list = @(& tar -tf $archive)
    foreach ($must in "$($gh.Name)/support/analyzeHeadless.bat", "$jreName/bin/java.exe") {
        if (-not ($list -contains $must)) { throw "archive is missing $must" }
    }
    Write-Host ("    archive {0:N1} MB, {1} entries" -f ((Get-Item $archive).Length / 1MB), $list.Count)

    $Toolchain = $archive
}

$payload = [IO.File]::ReadAllText($source, [Text.Encoding]::UTF8)
foreach ($t in @($PayloadToken, $ChainToken)) {
    if ($payload.Contains($t)) { throw "token $t also appears inside unveil.ps1" }
}

$chainBytes = $null
if ($Toolchain) {
    if (-not (Test-Path $Toolchain)) { throw "toolchain archive not found: $Toolchain" }
    $chainBytes = [IO.File]::ReadAllBytes($Toolchain)
    foreach ($t in @($PayloadToken, $ChainToken)) {
        if ([Scan]::IndexOf($chainBytes, [Text.Encoding]::ASCII.GetBytes($t)) -ge 0) {
            throw "token $t occurs inside the toolchain archive"
        }
    }
}

# The header ends with exit /b before any separator, so cmd never parses the payload
# or the binary tail. Confirmed empirically: a 178 MB tail of arbitrary bytes after
# exit /b runs clean, no stderr, instantly.
$header = @'
@echo off
REM unveil - single file build. Double-click to run; no arguments needed.
REM Self-extracting: PowerShell source, then a binary toolchain tail.

setlocal

set "UNVEIL_SELF=%~f0"
set "UNVEIL_TMP=%TEMP%\unveil-%RANDOM%%RANDOM%"
set "UNVEIL_PASS=%*"

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

REM Step 1 - unpack the PowerShell source and the toolchain that follow this header.
echo    preparing...
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $b=[IO.File]::ReadAllBytes($env:UNVEIL_SELF); $h=[Text.Encoding]::ASCII.GetString($b,0,[Math]::Min(65536,$b.Length)); $m1='UNVEIL_PAYLOAD_BEGIN_9F3A2C7E'; $m2='UNVEIL_TOOLCHAIN_BEGIN_4B8E1D93'; $i1=$h.LastIndexOf($m1); $i2=$h.LastIndexOf($m2); if($i1 -lt 0){Write-Host '[XX] payload marker missing' -ForegroundColor Red; exit 2}; $s=$i1+$m1.Length; $n=if($i2 -gt 0){$i2-$s}else{$b.Length-$s}; $d=$env:UNVEIL_TMP; New-Item -ItemType Directory -Path $d -Force | Out-Null; [IO.File]::WriteAllText((Join-Path $d 'unveil.ps1'),[Text.Encoding]::UTF8.GetString($b,$s,$n),(New-Object Text.UTF8Encoding $false)); if($i2 -gt 0){ $t2=$i2+$m2.Length; $f=[IO.File]::Open((Join-Path $d 'toolchain.tar'),'Create'); $f.Write($b,$t2,$b.Length-$t2); $f.Close() }"

if errorlevel 1 (
    if not defined UNVEIL_NO_PAUSE pause
    exit /b 2
)

REM Step 2 - install the engine into the SAME WorkDir unveil.ps1 will use.
REM WorkDir is read from the caller's arguments when -WorkDir is present, because
REM hardcoding %LOCALAPPDATA% here sent the engine to a different directory than the
REM one the script analyzes with, and the run died on "Ghidra not found".
if exist "%UNVEIL_TMP%\toolchain.tar" (
    echo    installing engine ^(first run only^)...
    "%PSEXE%" -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; $a=@(); if($env:UNVEIL_PASS){ $a=@($env:UNVEIL_PASS -split ' ' | Where-Object { $_ }) }; $w=Join-Path $env:LOCALAPPDATA 'unveil\work'; for($i=0;$i -lt $a.Count;$i++){ if($a[$i] -eq '-WorkDir' -and $i+1 -lt $a.Count){ $w=$a[$i+1].Trim('""') } }; $t=Join-Path $w 'tools'; New-Item -ItemType Directory -Path $t -Force | Out-Null; $g=@(Get-ChildItem $t -Directory -Filter 'ghidra_*_PUBLIC' -EA SilentlyContinue); $j=@(Get-ChildItem $t -Directory -Filter 'jdk-*' -EA SilentlyContinue); if($g -and $j){ Write-Host '    engine already present' } else { tar -xf (Join-Path $env:UNVEIL_TMP 'toolchain.tar') -C $t; if($LASTEXITCODE -ne 0){ Write-Host '[XX] could not unpack the engine' -ForegroundColor Red; exit 3 }; Write-Host '    engine ready' }"
    if errorlevel 1 (
        if not defined UNVEIL_NO_PAUSE pause
        exit /b 3
    )
)

echo ==== unveil ==========================================
echo     unpacked to %UNVEIL_TMP%
echo.

REM Step 3 - run. -File forwards %* to PowerShell's own parser. -SkipDownload is not
REM forced here: unveil.ps1 skips the download itself once it sees the engine, and
REM that check honours -WorkDir. Forcing the flag broke custom WorkDir runs.
"%PSEXE%" -NoProfile -ExecutionPolicy Bypass -File "%UNVEIL_TMP%\unveil.ps1" %*
set "RC=%ERRORLEVEL%"

REM Step 4 - clean up.
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

$nl = "`r`n"
$parts = @(($header -replace "`r`n", "`n").Replace("`n", $nl))
# No separator byte after either marker. The extractor works on byte offsets, and
# adding a newline here put two stray CRLF bytes into the archived payload - which
# is why an earlier build reported a +2 byte tail and a failed round-trip.
$parts += $PayloadToken
$parts += (($payload -replace "`r`n", "`n").Replace("`n", $nl))
if ($chainBytes) { $parts += $ChainToken }

[IO.File]::WriteAllText($OutFile, '', (New-Object Text.UTF8Encoding $false))
$fs = [IO.File]::Open($OutFile, 'Append')
foreach ($p in $parts) {
    # UTF-8, never ASCII. unveil.ps1 contains an em-dash in its synopsis, and
    # Encoding.ASCII.GetBytes silently rewrites every non-ASCII char to '?'. That is
    # data corruption, not a cosmetic difference: the payload lost a character and the
    # region came out 2 bytes short of what the source implies.
    $pb = [Text.Encoding]::UTF8.GetBytes($p)
    $fs.Write($pb, 0, $pb.Length)
}
if ($chainBytes) { $fs.Write($chainBytes, 0, $chainBytes.Length) }
$fs.Close()

# --- verify the artifact, do not trust the write ---------------------------
$all = [IO.File]::ReadAllBytes($OutFile)
# LastIndexOf, not IndexOf: the header's extractor names both tokens literally in its
# -Command string, so the first occurrence is inside the header. An earlier revision
# used IndexOf here and sliced the header short, which the exit-before-payload check
# then reported as a missing exit.
$tok1 = [Text.Encoding]::ASCII.GetBytes($PayloadToken)
$tok2 = [Text.Encoding]::ASCII.GetBytes($ChainToken)
$bi1 = [Scan]::LastIndexOf($all, $tok1)
$bi2 = [Scan]::LastIndexOf($all, $tok2)
if ($bi1 -lt 0) { throw 'payload separator missing from the bundle' }
if ($chainBytes -and $bi2 -le $bi1) { throw 'toolchain separator must follow the payload' }
if (-not $chainBytes -and $bi2 -ge 0) { throw 'bundle carries a toolchain marker but no toolchain' }

# Fail closed on an unexpected token count: exactly the header mention plus the
# separator. A third occurrence means the extractor would stop at the wrong offset.
$c1 = [Scan]::Count($all, $tok1)
if ($c1 -ne 2) { throw "payload token appears $c1 times, expected 2 (header + separator)" }
if ($chainBytes) {
    $c2 = [Scan]::Count($all, $tok2)
    if ($c2 -ne 2) { throw "toolchain token appears $c2 times, expected 2 (header + separator)" }
}

$head = [Text.Encoding]::ASCII.GetString($all, 0, $bi1)
if ($head -match '[^\x00-\x7F]') { throw 'header is not ASCII-only; cmd may misparse it' }
if ($head -notmatch 'exit /b %RC%') { throw 'header has no exit before the payload; cmd would parse it' }

$pStart = $bi1 + $PayloadToken.Length
$pEnd = if ($bi2 -gt 0) { $bi2 } else { $all.Length }
$round = [Text.Encoding]::UTF8.GetString($all, $pStart, $pEnd - $pStart)
# Compare the bytes that were actually intended, not a re-normalized copy. unveil.ps1
# on disk is LF-only and the bundle is deliberately CRLF for cmd, so the payload in the
# bundle is expected to be exactly this CRLF conversion - 622 bare LF become 622 CRLF.
# Earlier revisions compared the round-trip against the raw source after normalizing,
# which passed or failed for reasons unrelated to what shipped.
$expected = ($payload -replace "`r`n", "`n").Replace("`n", "`r`n")
$expBytes = [Text.Encoding]::UTF8.GetBytes($expected)
if ($pEnd - $pStart -ne $expBytes.Length) {
    throw "payload region is $($pEnd - $pStart) bytes, expected $($expBytes.Length)"
}
if (-not [Scan]::Eq($all, $pStart, $expBytes, $expBytes.Length)) {
    throw 'payload does not survive the round-trip'
}

if ($chainBytes) {
    $cStart = $bi2 + $ChainToken.Length
    $tail = $all.Length - $cStart
    if ($tail -ne $chainBytes.Length) { throw "tail is $tail bytes, archive is $($chainBytes.Length)" }
    if (-not [Scan]::Eq($all, $cStart, $chainBytes, $chainBytes.Length)) {
        throw 'tail differs from the archive'
    }
    # Do NOT byte-search the archive for a member path: it is zstd-compressed, so no
    # plaintext path exists in those bytes and any such probe always fails. Archive
    # contents were verified separately by listing it with `tar -tf`.
}

$mb = [math]::Round((Get-Item $OutFile).Length / 1MB, 1)
if ($chainBytes) {
    Write-Host "built $OutFile  ($mb MB, payload $($payload.Length) chars + $([math]::Round($chainBytes.Length/1MB,1)) MB engine)" -ForegroundColor Green
    Write-Host 'hand over that one file; it needs nothing else.' -ForegroundColor DarkGray
} else {
    Write-Host "built $OutFile  ($([math]::Round((Get-Item $OutFile).Length/1KB,1)) KB, launcher only - engine downloads on first run)" -ForegroundColor Green
}