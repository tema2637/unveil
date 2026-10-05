# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-05

### Added

- `run.cmd`: double-click launcher. Windows commonly blocks unsigned local scripts, so
  double-clicking `unveil.ps1` usually did nothing visible. The launcher forwards to a child
  PowerShell with `-ExecutionPolicy Bypass`, scoped to that process only; it does not
  change machine policy. Set `UNVEIL_NO_PAUSE=1` to skip the final keypress.
- Target auto-detection, so no arguments are needed. Searches the current directory, the
  script directory, then `Downloads`, `Desktop`, `Program Files` and `Program Files (x86)`,
  non-recursively.
- `Select-ByDefault`: when several PE files are found, exactly one is analyzed — the first
  `.dll`/`.sys`, otherwise the smallest file. The chosen and skipped files are printed.
  Analyzing everything would turn a double-click into an open-ended run, and doing so
  silently is the worst option. More than one target is still available via `-Target`.

### Fixed

- CI triggered on `main` while the default branch is `master`, so the first push produced
  zero runs: the workflow registered as active and never executed. Both branch names are
  now listed.

## [0.1.0] - 2026-10-05

Initial release.

### Added

- Single-file pipeline (`unveil.ps1`). Downloads and unpacks Ghidra 12.1.4 and Temurin
  JDK 21.0.12.1+1, imports each target into a persistent Ghidra project, and exports
  decompiled C. No install step and no PATH edits.
- Embedded Ghidra postscript (`UnveilExport.java`), written as Java because Ghidra 12
  dropped Jython. Written to disk at runtime, so the repository stays one file.
- Two-pass function selection: functions referencing keyword-bearing strings, then the
  largest non-thunk functions. Chosen because release binaries are stripped and a name
  filter over 23 815 `FUN_*` symbols found 3 useless hits.
- Per-target output: `decompiled.cpp`, `functions.txt`, `anchor_strings.txt`, `summary.txt`.
- Idempotent reruns: existing projects are reused and only the export re-runs, via
  `-process -noanalysis`.
- Toolchain integrity pinned by size **and** sha256, with a `.verified` stamp so repeat
  runs skip re-hashing ~775 MB while still refusing an unverified archive.
- `THIRD-PARTY-NOTICES.md` recording Ghidra's Apache-2.0 and the JDK's GPLv2 + Classpath
  Exception, with what each permits in practice.

### Known limitations

- Selection is a slice, not an audit: 59 of 23 815 functions on the reference binary.
  Raise `KEYS` or the pass limits in the embedded postscript to widen it.
- Decompiled output is evidence about a shipped binary, not the author's source.
- Only x86/x64 Windows PE binaries. Native Windows x86 and x64 are handled; other
  architectures are not specifically covered.
- Analysis time scales with binary size; a 12 MB binary takes several minutes per pass.

## [Unreleased]

[0.2.0]: https://github.com/tema2637/unveil/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tema2637/unveil/releases/tag/v0.1.0