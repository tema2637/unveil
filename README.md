# unveil

One-file reverse-engineering pipeline for Windows PE binaries. Run it; it fetches its own
toolchain, analyzes the binary, and writes decompiled C.

No install step. No PATH edits. Windows PowerShell 5.1 and ~1.6 GB of free disk are the
only prerequisites.

## Just run it

Download the repo (or the zip), put the folder anywhere, and **double-click `run.cmd`**.

That's the whole thing. No arguments, no configuration. `run.cmd` picks up the binary for
you, downloads the toolchain on first run, and prints where the output landed.

If your machine blocks unsigned local scripts, `run.cmd` already handles it — see
*Execution policy* below.

From a terminal:

```powershell
.\run.cmd                              # the double-click path
.\unveil.ps1 -Target .\app.exe         # pick a specific binary
```

## What it does

1. Downloads and unpacks Ghidra and a JDK, pinning both by **size and sha256**.
2. Stages the target into a paren-free directory (see *Why those workarounds* below).
3. Imports it into a persistent Ghidra project and runs the analysis.
4. Exports decompiled C, a full function inventory, the anchor strings, and a summary.

Re-running is cheap: the project is reused and only the export re-runs, via
`-process -noanalysis`. Nothing is re-downloaded.

## How it picks a target

You don't have to say. With no `-Target`, it looks, in order, at the current directory,
the script's own directory, then `Downloads`, `Desktop`, `Program Files`,
`Program Files (x86)`.

If it finds several PE files it analyzes **exactly one** — the first `.dll`/`.sys` it
found, otherwise the smallest file. It then tells you which file it picked and which it
skipped, because silently picking 13 binaries turns a double-click into an open-ended
run. To analyze more than one, pass `-Target` more than once.

## Usage

```powershell
.\unveil.ps1                                  # auto-detect
.\unveil.ps1 -Target .\app.exe -Target .\lib.dll
.\unveil.ps1 -SkipDownload                    # toolchain already present
.\unveil.ps1 -Force                           # re-import from scratch
.\unveil.ps1 -OutDir D:\out -WorkDir D:\cache
.\unveil.ps1 -KeepZip                         # keep downloaded archives
```

Output per target:

| File | Contents |
|---|---|
| `decompiled.cpp` | decompiled C for anchored + largest functions |
| `functions.txt` | full function inventory (name, size, thunk, entry) |
| `anchor_strings.txt` | strings that anchored the selection |
| `summary.txt` | counters: functions, anchored, decompiled |

## Execution policy

Windows often blocks unsigned local scripts, which is why `run.cmd` exists: double-clicking
`unveil.ps1` directly usually does nothing visible.

`run.cmd` launches the child PowerShell with `-ExecutionPolicy Bypass`, which applies to
**that one process only** and changes nothing on the machine. It deliberately does not
touch the machine's policy, because quietly disabling a security setting is not something a
tool should do to someone else's computer.

If you would rather not bypass anything, run the script yourself:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\unveil.ps1
```

Set `UNVEIL_NO_PAUSE=1` to stop `run.cmd` from waiting for a keypress at the end.

## Why it selects functions by string, not by name

Release builds are usually stripped. On the binary this was written against, 23 815
functions carried only **208** real names — the rest were `FUN_*`. A name filter found
three hits, all of them CRT noise.

The string-anchored walk found 906 keyword strings, referenced from 1 509 functions.
Two passes:

- **pass 1** — functions that reference a keyword-bearing defined string
- **pass 2** — the largest non-thunk functions, which is product code rather than CRT

That trade-off is deliberate: coverage over a stripped binary is better than precision
over a named one. The knob is `KEYS` in the embedded postscript.

## Why those workarounds

Each of these is a real environment trap that cost a failed run. They are encoded so you
do not rediscover them:

1. **curl can lie.** It reports "N bytes received" while writing only the initial
   allocation to disk. `unveil` uses BITS, which writes from a system service — a stalled
   writer cannot masquerade as progress there.
2. **Parenthesised paths break `.bat` argument parsing.** `analyzeHeadless.bat` forwards
   arguments unquoted, so `C:\Program Files (x86)\...` yields *"was unexpected at this
   time"* and an immediate exit. Targets are staged into a paren-free directory.
3. **The project directory must already exist.** Ghidra does not create it, despite what
   the name suggests.
4. **Ghidra 12 dropped Jython.** A `.py` postscript dies with *"Ghidra was not started
   with PyGhidra. Python is not available"* — while the analysis itself still reports
   success, which is what makes it nasty. Postscripts must be Java: `@category Analysis`,
   extend `GhidraScript`, and Ghidra compiles it in-process.
5. **`Reference.getFrom()` became `getFromAddress()`** in Ghidra 12.
6. **Exit code 0 does not mean the postscript ran.** `unveil` inspects the log for script
   errors instead of trusting `$LASTEXITCODE`. This is what silently hid failure #4.
7. **PowerShell 5.1 turns native stderr into a terminating error** under
   `$ErrorActionPreference='Stop'`. `java -version` writes to stderr, so that preference is
   relaxed around it.
8. **`$args` is an automatic PowerShell variable.** Shadowing it breaks the script.

## Integrity

Downloads are pinned by size *and* sha256. A truncated or substituted mirror fails closed
rather than installing unverified code. Hashes are in `unveil.ps1` near the top; update
them when you bump versions.

## Scope

`unveil` recovers the product's own logic from a shipped binary. It is evidence for
analysis, not a reconstruction of anyone's source, and not a substitute for reading it.
You are responsible for holding any rights required to analyze a given binary.

## Third-party

Read [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). In short: this project's own code
is MIT, Ghidra is Apache-2.0, and the JDK is GPLv2 with the Classpath Exception. None of
the third-party components are vendored into this repository — they are fetched at runtime
and installed under their own licenses.

MIT licensed. See [LICENSE](LICENSE).