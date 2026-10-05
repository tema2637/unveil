# Third-party notices

`unveil` itself is MIT licensed. It does **not** vendor or redistribute any third-party
component. Both third-party tools are downloaded at runtime and installed under their own
licenses into your own cache directory.

This file exists because the licensing facts determine what you may and may not do when
you redistribute, rebrand, or publish output derived from this tool. Read it before you do
any of those things.

---

## Ghidra

- **Project:** https://github.com/NationalSecurityAgency/ghidra
- **Version pinned by `unveil`:** 12.1.4 PUBLIC (build 20260921)
- **License:** Apache License 2.0
- **Copyright:** National Security Agency

Apache-2.0 is permissive. You may use, modify, and redistribute it, including commercially,
provided that you:

- include the Apache-2.0 license text and any `NOTICE` file shipped with the distribution;
- state significant changes you made;
- do not imply NSA endorsement or sponsorship;
- preserve patent and trademark notices.

### What this means in practice

- **Redistributing Ghidra itself is permitted.** Ship the upstream zip, unmodified, with
  its `LICENSE` intact.
- **Do not rename Ghidra and present it as your product.** Apache-2.0 does not let you
  rebrand someone else's work. "unveil" is this project's name; "Ghidra" remains Ghidra.
- **Bundling Ghidra into a larger installer** is permitted, provided the Apache-2.0 terms
  above are met and Ghidra is not presented as your own creation.
- **Patent grant.** Apache-2.0 §3 includes an express patent grant from contributors. This
  is a benefit of the license, not a separate grant from NSA.

Verified against `LICENSE` inside the shipped distribution, not from memory.

---

## Eclipse Temurin JDK 21

- **Project:** https://adoptium.net / https://github.com/adoptium/temurin21-binaries
- **Version pinned by `unveil`:** Temurin 21.0.12.1+1 (LTS), Windows x64
- **License:** GPLv2 **with the Classpath Exception**
- **Copyright:** Eclipse Adoptium and the OpenJDK contributors

### What this means in practice

- **Running it is fine.** The Classpath Exception exists precisely so that linking against
  these class libraries does not force your work under the GPL.
- **The GPL does not reach your script.** `unveil.ps1` and the embedded postscript are your
  own code. Invoking a JDK is not distributing it.
- **Do not vendor the JDK into your own repository** without preserving its license files
  and the Classpath Exception text. `unveil` avoids this entirely by downloading at runtime.
- **Do not modify the JDK and ship the result.** The Classpath Exception covers linking, not
  redistribution of a modified runtime.

Verified against `legal/java.base/LICENSE` and `legal/java.base/ASSEMBLY_EXCEPTION` inside
the shipped distribution.

---

## How `unveil` complies

1. Downloads are pinned by **size and sha256** and fail closed on mismatch, so a substituted
   mirror cannot be installed silently.
2. Version and hash constants live at the top of `unveil.ps1` and are updated together.
3. Neither third-party archive is committed to this repository.
4. Neither third-party archive is redistributed by this project.
5. Attribution is stated here rather than buried, and the pinned upstream URLs are recorded
   so a reader can verify the exact artifact obtained.

---

## Decompiled output

`unveil` writes decompiled C derived from third-party binaries you supply. That output is
evidence produced by running a third-party decompiler (Ghidra) against a third-party program.
It contains no Ghidra or JDK source code, and it is not covered by their licenses. What you
may do with it depends on the license of the **binary you analyzed**, not of this tool —
check that program's terms before redistributing analysis of it.

---

## Summary

| Component | License | Redistribute? | Rebrand? |
|---|---|---|---|
| `unveil` (this project) | MIT | yes | yours |
| Ghidra | Apache-2.0 | yes, keep LICENSE + NOTICE | no |
| Temurin JDK 21 | GPLv2 + Classpath Exception | yes, keep its license files | n/a |

If you are unsure whether a planned packaging satisfies these terms, read the upstream
license texts rather than trusting a summary — including this one.