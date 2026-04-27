# x86_64 KPM Patch Hygiene

The WSA x86_64 KPM work should stay reviewable as a sequence of small, testable changes. Keep the port split by ownership boundary instead of mixing loader logic, Android userspace, WSA packaging and release notes in one patch.

## Suggested Patch Series

1. Android x86_64 `ksud kpm` command path.
2. x86_64 `ET_REL` loader and RELA relocation parser.
3. x86_64 hook backend and `text_poke_bp` install/restore.
4. Generated executable memory allocator and `RW+NX` to `ROX` transitions.
5. Hook owner tracking, unload gate and callback accounting.
6. Userspace `doctor`, `audit`, version and capability handshake.
7. SDK examples and runtime self-test modules.
8. ELF fuzz smoke and CI preflight.
9. WSA integration, release manifest and compatibility matrix.
10. Security policy, issue template and recovery documentation.

## Rebase Rules

1. Keep `kernel/kpm/kpm_loader_x86_64.c` as the main x86_64 loader surface. Shared ABI constants belong in `kernel/kpm/kpm_loader_x86_64.h`.
2. Keep Android command behavior in `userspace/ksud/src/android/kpm.rs`; do not hide kernel return codes in Manager-only code.
3. Keep formal ABI text in `docs/KPM_X86_64_ABI.md`. README files should summarize and link to the ABI instead of duplicating every relocation or feature bit.
4. Keep WSA-only packaging and release provenance in `Ognisty321/WSA-Linux-Kernel`; do not require generic ReSukiSU builds to know about a specific WSA package.
5. Keep new compatibility symbols additive. If an ABI change breaks an existing sample KPM, bump the ABI version and update the compatibility docs in the same patch.
6. Keep negative behavior explicit. Unsupported syscall hooks, reserved hook targets and malformed ELF input should fail with specific errors, not silent success.

## Required Checks Before Syncing Into WSA

```sh
bash scripts/kpm-x86-preflight.sh
```

For a WSA runtime candidate, also run:

```sh
RUN_WSA=1 ADB="/mnt/d/Programy/Path Tools/adb.exe" ADB_TARGET=127.0.0.1:58526 \
  bash scripts/kpm-x86-preflight.sh
```

If the Manager APK or release `ksud` changes, run:

```sh
scripts/check-manager-kpm-x86.sh /path/to/ReSukiSU-Manager.apk
scripts/check-manager-kpm-x86.sh /path/to/ksud
```

## Review Focus

Reviewers should look first at:

1. Bounds checks around ELF headers, sections, string tables, symbols and RELA records.
2. Integer overflow and sign extension in relocation math.
3. Whether hook targets are real kernel text and not reserved patching infrastructure.
4. Whether replacement functions are in allowed executable text.
5. Whether every executable allocation has a checked permission transition.
6. Whether unload refuses to free a module that still owns hooks or active callbacks.
7. Whether userspace exposes the original kernel error clearly enough for support.
