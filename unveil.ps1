<#
.SYNOPSIS
    unveil — one-file, zero-dependency reverse-engineering pipeline for Windows PE binaries.

.DESCRIPTION
    Single file. Run it; it fetches its own toolchain, analyzes the targets you point
    it at, and writes decompiled C. No install step, no PATH edits, no prerequisites
    beyond Windows PowerShell 5.1 and ~1.6 GB of free disk.

    Everything it needs lives in this file: the Ghidra postscript is embedded below
    and written to disk at runtime.

.PARAMETER Target
    Files to analyze. Defaults to the PE binaries (.exe/.dll/.sys) in the current
    directory. Nothing product-specific is hardcoded.

.PARAMETER OutDir
    Output root. Defaults to %LOCALAPPDATA%\unveil.

.PARAMETER WorkDir
    Toolchain + project cache. Defaults to %LOCALAPPDATA%\unveil\work.

.PARAMETER Force
    Re-import even if the project already exists.

.PARAMETER SkipDownload
    Assume the toolchain is already present.

.PARAMETER KeepZip
    Keep downloaded archives after extraction.

.EXAMPLE
    .\unveil.ps1
    Analyze the default target set, reusing anything already downloaded.

.EXAMPLE
    .\unveil.ps1 -Target .\myapp.exe -Target .\mylib.dll
    Analyze specific files.

.EXAMPLE
    .\unveil.ps1 -SkipDownload -Force
    Re-analyze from scratch using the cached toolchain.

.NOTES
    Toolchain integrity is pinned by size AND sha256, so a compromised or truncated
    mirror fails closed instead of installing something unverified.

    Third-party licenses - read THIRD-PARTY-NOTICES.md:
      Ghidra         Apache-2.0   (NSA), downloaded at runtime, never redistributed here
      Eclipse Temurin JDK 21     GPLv2 + Classpath Exception, downloaded at runtime

    Environment-specific traps this encodes. Each one cost a failed run on the
    machine it was written on:

      1. curl can report "N bytes received" while writing only the initial
         allocation to disk. BITS is used instead: it writes from a system service,
         so a stalled writer cannot masquerade as progress.
      2. analyzeHeadless.bat forwards arguments unquoted, so ANY parenthesised
         path in an argument breaks it ("was unexpected at this time"). Targets are
         staged into a paren-free directory before import.
      3. The project directory must already exist. Ghidra does not create it.
      4. Ghidra 12 dropped Jython as a script engine. "Ghidra was not started with
         PyGhidra. Python is not available." Postscripts must be Java: annotate with
         @category Analysis, extend GhidraScript, and let Ghidra compile it.
      5. Ghidra 12 renamed Reference.getFrom() to getFromAddress().
      6. analyzeHeadless can exit 0 while the postscript failed. Exit code alone is
         not a success signal, so the log is inspected for script errors.
      7. Windows PowerShell 5.1 turns native stderr into a terminating error under
         $ErrorActionPreference='Stop'. java -version writes to stderr, so that
         preference is relaxed around it.
      8. $args is an automatic PowerShell variable; shadowing it breaks the script.

    Design note: decompilation output identifies the product's own logic, not the
    author's source. Treat it as evidence for analysis, not as a substitute for it.
#>
[CmdletBinding()]
param(
    [Alias('t')]
    [string[]] $Target = @(),

    [string] $OutDir    = (Join-Path $env:LOCALAPPDATA 'unveil'),
    [string] $WorkDir   = (Join-Path $env:LOCALAPPDATA 'unveil\work'),

    [switch] $Force,
    [switch] $SkipDownload,
    [switch] $KeepZip
)

$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------- toolchain ---
$GhidraVersion  = '12.1.4'
$GhidraBuild    = '20260921'
$GhidraUrl      = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GhidraVersion}_build/ghidra_${GhidraVersion}_PUBLIC_${GhidraBuild}.zip"
$GhidraBytes    = 569649598
$GhidraSha256   = 'ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db'

$JdkVersion = '21.0.12.1_1'
$JdkUrl     = 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip'
$JdkBytes   = 205073461
$JdkSha256  = 'f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e'

# ------------------------------------------------------------------ output ---
function Write-Step  ($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok    ($m) { Write-Host "    [ok] $m"   -ForegroundColor Green }
function Write-Warn2 ($m) { Write-Host "    [!!] $m"   -ForegroundColor Yellow }
function Write-Fail  ($m) { Write-Host "    [XX] $m"   -ForegroundColor Red; exit 1 }

$script:PostScriptName = 'UnveilExport.java'
$script:PostScriptBody = @'
// unveil - string-anchored decompile export.
// Written for Ghidra 12 (no Jython). Ghidra compiles this itself.
//
// Why anchors instead of names: release builds are usually stripped. A name filter
// over 23k FUN_* symbols finds nothing; a string-reference walk finds the real code.
// Two passes: functions referencing keyword-bearing strings, then the largest
// non-thunk functions (product code rather than CRT).
//
// @category Analysis

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class UnveilExport extends GhidraScript {

	private static final String[] KEYS = {
		"audio", "virtual", "driver", "device", "apo", "endpoint", "service",
		"install", "register", "config", "hotkey", "sound", "record", "playback",
		"stream", "channel", "session", "license", "trial", "auth", "token",
		"encrypt", "decrypt", "password", "credential", "telemetry", "update",
		"crash", "exception", "assert", "hook", "inject", "patch", "debug"
	};

	private static final int MIN_BODY   = 40;
	private static final int MAX_ANCHOR = 40;
	private static final int MAX_BIG    = 20;

	@Override
	public void run() throws Exception {
		String env = System.getenv("UNVEIL_OUT");
		File outDir = new File(env != null ? env : "unveil-out");
		outDir.mkdirs();

		List<Function> all = new ArrayList<Function>();
		FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
		while (fit.hasNext()) {
			all.add(fit.next());
		}

		// Full inventory, so repeat runs can be diffed.
		PrintWriter inv = new PrintWriter(new File(outDir, "functions.txt"), "UTF-8");
		inv.println("TOTAL " + all.size());
		for (Function f : all) {
			inv.println(f.getName() + "  size=" + f.getBody().getNumAddresses()
				+ "  thunk=" + f.isThunk() + "  entry=" + f.getEntryPoint());
		}
		inv.close();

		// Pass 1 - functions that reference a keyword-bearing defined string.
		List<Function> anchored = new ArrayList<Function>();
		Set<String> anchorStrings = new LinkedHashSet<String>();
		DataIterator dit = currentProgram.getListing().getDefinedData(true);
		while (dit.hasNext()) {
			Data d = dit.next();
			Object v = d.getValue();
			if (v == null) {
				continue;
			}
			String s = String.valueOf(v);
			if (s.length() > 400) {
				continue;
			}
			String low = s.toLowerCase();
			boolean hit = false;
			for (String k : KEYS) {
				if (low.contains(k)) {
					hit = true;
					break;
				}
			}
			if (!hit) {
				continue;
			}
			anchorStrings.add(s.length() > 120 ? s.substring(0, 120) : s);

			ReferenceIterator rit = currentProgram.getReferenceManager()
				.getReferencesTo(d.getAddress());
			while (rit.hasNext()) {
				Reference r = rit.next();
				Address from = r.getFromAddress();   // Ghidra 12: getFrom() was renamed
				if (from == null) {
					continue;
				}
				Function f = currentProgram.getFunctionManager()
					.getFunctionContaining(from);
				if (f != null && !f.isThunk()
					&& f.getBody().getNumAddresses() >= MIN_BODY) {
					anchored.add(f);
				}
			}
		}

		// Pass 2 - largest non-thunk functions.
		List<Function> bySize = new ArrayList<Function>(all);
		Collections.sort(bySize, new Comparator<Function>() {
			public int compare(Function a, Function b) {
				return Long.compare(b.getBody().getNumAddresses(),
				                    a.getBody().getNumAddresses());
			}
		});
		List<Function> big = new ArrayList<Function>();
		for (Function f : bySize) {
			if (big.size() >= MAX_BIG) {
				break;
			}
			if (!f.isThunk() && f.getBody().getNumAddresses() >= 400) {
				big.add(f);
			}
		}

		Set<Address> seen = new HashSet<Address>();
		List<Function> pick = new ArrayList<Function>();
		for (Function f : anchored) {
			if (pick.size() >= MAX_ANCHOR) {
				break;
			}
			if (seen.add(f.getEntryPoint())) {
				pick.add(f);
			}
		}
		int pass1 = pick.size();
		for (Function f : big) {
			if (seen.add(f.getEntryPoint())) {
				pick.add(f);
			}
		}

		PrintWriter anc = new PrintWriter(new File(outDir, "anchor_strings.txt"), "UTF-8");
		for (String s : anchorStrings) {
			anc.println(s.replace("\n", "\\n"));
		}
		anc.close();

		DecompInterface ifc = new DecompInterface();
		ifc.openProgram(currentProgram);

		int written = 0;
		PrintWriter out = new PrintWriter(new File(outDir, "decompiled.cpp"), "UTF-8");
		out.println("/* unveil " + currentProgram.getName()
			+ "  pass1=" + pass1 + " anchoredFunctions=" + anchored.size()
			+ "  pass2=" + (pick.size() - pass1) + " */");
		for (Function f : pick) {
			try {
				DecompileResults res = ifc.decompileFunction(f, 60, monitor);
				if (res != null && res.decompileCompleted()) {
					out.println();
					out.println("// ==== " + f.getName() + " @ " + f.getEntryPoint()
						+ " size=" + f.getBody().getNumAddresses() + " ====");
					out.println(res.getDecompiledFunction().getC());
					out.flush();
					written++;
				}
			}
			catch (Exception e) {
				out.println("// FAILED " + f.getName() + " : " + e);
				out.flush();
			}
		}
		out.close();
		ifc.dispose();

		PrintWriter sum = new PrintWriter(new File(outDir, "summary.txt"), "UTF-8");
		sum.println("functions_total=" + all.size());
		sum.println("anchor_strings=" + anchorStrings.size());
		sum.println("anchored_functions=" + anchored.size());
		sum.println("pass1_selected=" + pass1);
		sum.println("pass2_selected=" + (pick.size() - pass1));
		sum.println("decompiled=" + written);
		sum.close();

		println("UNVEIL_DONE total=" + all.size()
			+ " anchorStrings=" + anchorStrings.size()
			+ " anchored=" + anchored.size()
			+ " decompiled=" + written);
	}
}
'@

# ------------------------------------------------------------------ helpers ---
function Get-Archive {
    param([string]$Url, [string]$Dest, [long]$Bytes, [string]$Sha256, [string]$Label)

    # A stamp records that this exact archive was already verified, so repeat runs
    # skip re-hashing ~775 MB. Without it, a cached-but-substituted archive of the
    # correct size would sail through on size alone.
    $stamp = "$Dest.verified"

    if (Test-Path $Dest) {
        $len = (Get-Item $Dest).Length
        if ($len -ne $Bytes) {
            Write-Warn2 "$Label cached but size is $len, expected $Bytes - refetching"
            Remove-Item $Dest -Force -ErrorAction SilentlyContinue
            Remove-Item $stamp -Force -ErrorAction SilentlyContinue
        } elseif ((Test-Path $stamp) -and ((Get-Content $stamp -Raw).Trim() -eq $Sha256)) {
            Write-Ok "$Label cached and previously verified ($len bytes)"
            return
        } else {
            Write-Step "Verifying cached $Label sha256"
            $cached = (Get-FileHash $Dest -Algorithm SHA256).Hash.ToLower()
            if ($cached -ne $Sha256) {
                Remove-Item $Dest -Force -ErrorAction SilentlyContinue
                Write-Fail "$Label sha256 mismatch.`n  expected $Sha256`n  actual   $cached`nRefusing to use an unverified archive."
            }
            Set-Content -Path $stamp -Value $Sha256 -Encoding ASCII
            Write-Ok "$Label cached and verified ($len bytes)"
            return
        }
    }

    Write-Step "Fetching $Label ($([math]::Round($Bytes/1MB,1)) MB)"
    # Never curl: it can report progress while writing nothing to disk.
    $job = Start-BitsTransfer -Source $Url -Destination $Dest -DisplayName "unveil-$Label" -Asynchronous
    $deadline = (Get-Date).AddMinutes(30)
    while ($true) {
        $rec = Get-BitsTransfer | Where-Object JobId -eq $job.JobId
        if (-not $rec) { Write-Fail "$Label transfer vanished" }
        if ($rec.JobState -in 'Transferred', 'Error', 'TransientError', 'Cancelled') { break }
        if ((Get-Date) -gt $deadline) {
            $rec | Remove-BitsTransfer
            Write-Fail "$Label download timed out"
        }
        Start-Sleep -Seconds 10
    }
    if ($rec.JobState -ne 'Transferred') {
        $err = $rec.ErrorDescription
        $rec | Remove-BitsTransfer
        Write-Fail "$Label download failed: $($rec.JobState) $err"
    }
    Complete-BitsTransfer -BitsJob $rec

    $len = (Get-Item $Dest).Length
    if ($len -ne $Bytes) { Write-Fail "$Label size mismatch: got $len, expected $Bytes" }

    Write-Step "Verifying $Label sha256"
    $actual = (Get-FileHash $Dest -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $Sha256) {
        Remove-Item $Dest -Force -ErrorAction SilentlyContinue
        Write-Fail "$Label sha256 mismatch.`n  expected $Sha256`n  actual   $actual`nRefusing to install an unverified archive."
    }
    Set-Content -Path $stamp -Value $Sha256 -Encoding ASCII
    Write-Ok "$Label downloaded and verified ($len bytes, sha256 matches)"
}

function Install-Toolchain {
    if ($SkipDownload) {
        Write-Warn2 'SkipDownload: using the existing toolchain'
        return
    }
    $dl = Join-Path $WorkDir 'downloads'
    New-Item -ItemType Directory -Force -Path $dl | Out-Null

    $gz = Join-Path $dl "ghidra_$GhidraVersion.zip"
    $jz = Join-Path $dl "jdk$JdkVersion.zip"
    Get-Archive $GhidraUrl $gz $GhidraBytes $GhidraSha256 'Ghidra'
    Get-Archive $JdkUrl    $jz $JdkBytes   $JdkSha256   'JDK 21'

    $tools = Join-Path $WorkDir 'tools'
    New-Item -ItemType Directory -Force -Path $tools | Out-Null

    if (-not (Get-ChildItem $tools -Directory -Filter 'ghidra_*_PUBLIC' -ErrorAction SilentlyContinue)) {
        Write-Step "Extracting Ghidra $GhidraVersion (large, please wait)"
        Expand-Archive -Path $gz -DestinationPath $tools -Force
    } else {
        Write-Ok 'Ghidra already extracted'
    }
    if (-not (Get-ChildItem $tools -Directory -Filter 'jdk-*' -ErrorAction SilentlyContinue)) {
        Write-Step 'Extracting JDK 21'
        Expand-Archive -Path $jz -DestinationPath $tools -Force
    } else {
        Write-Ok 'JDK already extracted'
    }
    if (-not $KeepZip) {
        Remove-Item $gz, $jz -Force -ErrorAction SilentlyContinue
    }
}

function Resolve-Toolchain {
    $tools = Join-Path $WorkDir 'tools'

    $ghidra = Get-ChildItem $tools -Directory -Filter 'ghidra_*_PUBLIC' -ErrorAction SilentlyContinue |
              Select-Object -First 1
    if (-not $ghidra) { Write-Fail "Ghidra not found under $tools - run without -SkipDownload" }

    $jdk = Get-ChildItem $tools -Directory -Filter 'jdk-*' -ErrorAction SilentlyContinue |
           Select-Object -First 1
    if (-not $jdk) { Write-Fail "JDK not found under $tools - run without -SkipDownload" }

    $headless = Join-Path $ghidra.FullName 'support\analyzeHeadless.bat'
    if (-not (Test-Path $headless)) { Write-Fail "analyzeHeadless.bat missing under $($ghidra.FullName)" }

    $env:JAVA_HOME = $jdk.FullName
    # java -version writes to stderr; under -Stop that is a terminating error.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $ver = & (Join-Path $jdk.FullName 'bin\java.exe') -version 2>&1 | Out-String
    $ErrorActionPreference = $prev

    if ($ver -notmatch '"(\d+)\.') { Write-Fail "could not read java version: $ver" }
    $major = [int]$Matches[1]
    if ($major -lt 21) { Write-Fail "Ghidra needs JDK 21+, found $major" }

    Write-Ok "Ghidra $($ghidra.Name)"
    Write-Ok "JDK    $($jdk.Name) (major $major)"
    return @{ Headless = $headless; Jdk = $jdk.FullName }
}

function Select-ByDefault {
    # Analyze exactly one binary when several are found. Picking all of them turns a
    # double-click into an open-ended multi-hour run the user never asked for, and
    # silently is the worst way to do that.
    #
    # Preference order, best first:
    #   1. a DLL / SYS next to it - libraries are the interesting target, and a
    #      folder of downloads is full of multi-hundred-MB installers;
    #   2. otherwise the smallest PE file - a sub-10 MB binary analyzes in about a
    #      minute, so the first run finishes while the user is still reading.
    param([string[]]$Candidates, [string]$From)

    if ($Candidates.Count -le 1) { return $Candidates }

    $items = @($Candidates | ForEach-Object { Get-Item $_ })
    $lib   = @($items | Where-Object { $_.Extension -in '.dll', '.sys' } |
                Sort-Object Length)
    $pick  = if ($lib.Count -gt 0) { $lib[0] } else { ($items | Sort-Object Length)[0] }

    $rest = @($items | Where-Object { $_.FullName -ne $pick.FullName } |
              Sort-Object Length | ForEach-Object { $_.Name })

    Write-Ok "found $($items.Count) PE files in $From"
    Write-Host "        analyzing: $($pick.Name) ($([math]::Round($pick.Length/1MB,1)) MB)" -ForegroundColor DarkGray
    if ($rest.Count -gt 0) {
        Write-Host "        skipped  : $($rest.Count -join ', ')" -ForegroundColor DarkGray
    }
    Write-Host "        pass -Target <file> to choose differently." -ForegroundColor DarkGray
    return @($pick.FullName)
}

function Resolve-Targets {
    if ($Target.Count -gt 0) {
        $resolved = @()
        foreach ($t in $Target) {
            if (-not (Test-Path $t)) { Write-Fail "target not found: $t" }
            $resolved += (Resolve-Path $t).Path
        }
        return $resolved
    }

    # Auto-detect. Order: current dir / script dir, then common install roots,
    # non-recursively so we never wander the disk. Nothing product-specific is
    # hardcoded, so the default cannot look like it aims at one application.
    $dirs = @((Get-Location).Path, $script:ScriptDir) |
            Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    foreach ($dir in $dirs) {
        $pe = @(Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in '.exe', '.dll', '.sys' })
        if ($pe.Count -gt 0) { return (Select-ByDefault $pe.FullName $dir) }
    }

    $roots = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)}
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($dir in $roots) {
        $pe = @(Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in '.exe', '.dll', '.sys' })
        if ($pe.Count -gt 0) { return (Select-ByDefault $pe.FullName $dir) }
    }

    Write-Fail 'no PE binaries (.exe/.dll/.sys) found in the current directory or common install roots.'
}

function Get-StagingDir {
    # Must be paren-free: analyzeHeadless.bat cannot parse parenthesised arguments.
    foreach ($cand in @((Join-Path $env:LOCALAPPDATA 'unveil-stage'), 'C:\unveil-stage')) {
        if ($cand -notmatch '[()]') {
            New-Item -ItemType Directory -Force -Path $cand | Out-Null
            return $cand
        }
    }
    Write-Fail 'could not find a paren-free staging directory'
}

function Invoke-Ghidra {
    param($Headless, [string]$ProjectDir, [string]$ProjectName,
          [string]$Mode, [string]$FileName, [string]$LogPath, [string]$OutDir)

    $env:UNVEIL_OUT = $OutDir
    $cliArgs = @($ProjectDir, $ProjectName)   # not $args: that is automatic in PowerShell

    if ($Mode -eq 'import') {
        $cliArgs += @('-import', (Join-Path $script:StageDir $FileName))
    } else {
        $cliArgs += @('-process', $FileName, '-noanalysis',
                      '-scriptPath', $script:ScriptDir,
                      '-postScript', $script:PostScriptName)
    }

    & $Headless @cliArgs *>&1 | Out-File -FilePath $LogPath -Encoding utf8
    return $LASTEXITCODE
}

function Test-RunFailed([string]$LogPath) {
    # analyzeHeadless can exit 0 with a failed postscript. Trust the log, not the code.
    if (-not (Test-Path $LogPath)) { return 'no log was written' }
    $hit = Select-String -Path $LogPath -Pattern @(
        'SCRIPT ERROR', 'ERROR REPORT', 'error: cannot find',
        'Directory not found', 'is unexpected at this time'
    ) -Quiet
    if ($hit) { return 'the log contains a script or analysis error' }
    return $null
}

# --------------------------------------------------------------------- main ---
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Fail 'Windows PowerShell 5.1 or newer is required'
}

New-Item -ItemType Directory -Force -Path $WorkDir, $OutDir | Out-Null
$script:StageDir  = Get-StagingDir
$script:ScriptDir = Join-Path $WorkDir 'scripts'
New-Item -ItemType Directory -Force -Path $script:ScriptDir | Out-Null

$postScriptPath = Join-Path $script:ScriptDir $script:PostScriptName
# MUST be BOM-less. PowerShell 5.1's -Encoding UTF8 emits a BOM, and javac rejects it
# with "illegal character: '\ufeff'", which cascades into a misleading
# ClassNotFoundException. UTF8Encoding($false) writes the same bytes with no BOM.
[IO.File]::WriteAllText($postScriptPath, $script:PostScriptBody, (New-Object Text.UTF8Encoding $false))

Install-Toolchain
$tc       = Resolve-Toolchain
$targets  = Resolve-Targets
$projDir  = Join-Path $WorkDir 'projects'
$logDir   = Join-Path $WorkDir 'logs'
# Ghidra does not create the project directory itself.
New-Item -ItemType Directory -Force -Path $projDir, $logDir | Out-Null

Write-Step "Targets"
foreach ($t in $targets) { Write-Ok $t }

$rows = @()
foreach ($t in $targets) {
    $leaf = Split-Path $t -Leaf
    $base = [IO.Path]::GetFileNameWithoutExtension($leaf) -replace '[^A-Za-z0-9_]', '_'
    $proj = "unveil_$base"
    $gpr  = Join-Path $projDir "$proj.gpr"
    $odir = Join-Path $OutDir  $base
    $safe = Join-Path $script:StageDir $leaf

    Write-Step "=== $leaf ==="
    Copy-Item $t $safe -Force

    $importLog = Join-Path $logDir "$base-import.log"
    if ((Test-Path $gpr) -and -not $Force) {
        Write-Ok 'project exists, skipping import (use -Force to redo it)'
    } else {
        $code = Invoke-Ghidra $tc.Headless $projDir $proj 'import' $leaf $importLog $odir
        $fail = Test-RunFailed $importLog
        if ($fail) { Write-Fail "import failed (exit $code, $fail) - see $importLog" }
        Write-Ok 'imported, analyzed and saved'
    }

    New-Item -ItemType Directory -Force -Path $odir | Out-Null
    $exportLog = Join-Path $logDir "$base-export.log"
    $code2 = Invoke-Ghidra $tc.Headless $projDir $proj 'process' $leaf $exportLog $odir
    $fail2 = Test-RunFailed $exportLog
    if ($fail2) { Write-Fail "export failed (exit $code2, $fail2) - see $exportLog" }

    $sumPath = Join-Path $odir 'summary.txt'
    if (Test-Path $sumPath) {
        $sum = @{}
        Get-Content $sumPath | ForEach-Object {
            if ($_ -match '^(\w+)=(.*)$') { $sum[$Matches[1]] = $Matches[2] }
        }
        Write-Ok ("functions={0} anchored={1} decompiled={2} -> {3}" -f
                  $sum.functions_total, $sum.anchored_functions, $sum.decompiled, $odir)
        $rows += [pscustomobject]@{
            Target=$base; Functions=$sum.functions_total
            Anchored=$sum.anchored_functions; Decompiled=$sum.decompiled; Out=$odir
        }
    } else {
        Write-Warn2 "no summary.txt for $base"
        $rows += [pscustomobject]@{
            Target=$base; Functions='?'; Anchored='?'; Decompiled='?'; Out=$odir
        }
    }
}

Write-Step 'Summary'
$rows | Format-Table -AutoSize | Out-String | Write-Host
Write-Ok "output in $OutDir"
Write-Ok "logs   in $logDir"