# Security Policy

## Scope

This policy covers the WSA x86_64 ReSukiSU fork, especially:

1. The x86_64 KPM ELF loader.
2. RELA relocation handling.
3. Inline hook, function pointer hook and hotpatch backends.
4. The Android x86_64 `ksud kpm` command path.
5. Manager integration that depends on the fork-specific `libksud.so`.

Issues in upstream Linux, KernelSU, SukiSU, ReSukiSU or SUSFS that are not specific to this WSA x86_64 fork should be reported to those projects.

## Reporting a Vulnerability

Please do not open a public issue for a suspected security bug. Use a private advisory on the repository that contains the affected code:

1. ReSukiSU fork: <https://github.com/Ognisty321/ReSukiSU/security/advisories/new>
2. WSA kernel fork: <https://github.com/Ognisty321/WSA-Linux-Kernel/security/advisories/new>

Include:

1. Minimal `.kpm` sample or reproduction steps.
2. Output of `ksud kpm doctor --json`.
3. Output of `adb shell uname -a`.
4. Relevant `dmesg` lines.
5. Kernel config or release tag.
6. Whether Windows Memory Integrity was on or off.

## In Scope

1. Memory corruption, use after free, out of bounds or double free in the KPM loader and hook backend.
2. Parser bugs reachable from a crafted `.kpm` file.
3. Incorrect relocation handling that can redirect execution unexpectedly.
4. Hook restore failures that leave kernel text or function pointers in an inconsistent state.
5. Userspace command bugs that report success after kernel-side failure.

## Out Of Scope

1. Bugs that require an attacker to already have arbitrary kernel write access.
2. Phone-vendor Android driver bugs not present in WSA.
3. Upstream issues that are not introduced by this fork.
4. Reports based only on unsupported ARM64 `.kpm` binaries failing to load on x86_64.

## Hardening Expectations

Security-sensitive changes should keep these properties intact:

1. Failed loads must leave no partially registered KPM module.
2. Failed hotpatch commits must roll back earlier writes when rollback is possible.
3. Failed unload must keep the module resident instead of freeing executable memory while hooks may still point at it.
4. `/data/adb/kpm` must be a real directory, not a symlink, and should use mode `700`.
5. Diagnostics should expose concrete error codes rather than converting failures into success.
