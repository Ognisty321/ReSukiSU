# Security Policy

## Scope

This policy covers the WSA x86_64 ReSukiSU fork, especially:

1. The x86_64 KPM ELF loader.
2. RELA relocation handling.
3. Inline hook, function pointer hook and hotpatch backends.
4. The Android x86_64 `ksud kpm` command path.
5. Manager integration that depends on the fork-specific `libksud.so`.

Issues in upstream Linux, KernelSU, SukiSU, ReSukiSU or SUSFS that are not specific to this WSA x86_64 fork should be reported to those projects.

## Supported Versions

Security fixes are targeted at the current `main` branch and the latest WSA x86_64 KPM release consumed by `Ognisty321/WSA-Linux-Kernel`. Older local test builds are not supported unless the issue is reproducible on current `main`.

## Threat Model

The KPM loader accepts `.kpm` objects from privileged `ksud kpm` callers and from the boot-time `/data/adb/kpm` autoload directory. A malicious or corrupted `.kpm` can already execute with kernel privileges if it loads successfully, so the main security boundary is loader and parser correctness before successful registration: malformed ELF input, relocation bounds, hook restore correctness, executable memory permissions and userspace reporting fidelity.

The `/data/adb/kpm` directory must be a real directory with mode `700`. A `/data/adb/kpm.disabled` marker disables boot-time autoload after a failed autoload attempt or manual recovery action.

## Reporting a Vulnerability

Please do not open a public issue for a suspected security bug. Use a private advisory on the repository that contains the affected code:

1. ReSukiSU fork: <https://github.com/Ognisty321/ReSukiSU/security/advisories/new>
2. WSA kernel fork: <https://github.com/Ognisty321/WSA-Linux-Kernel/security/advisories/new>

Include:

1. Minimal `.kpm` sample or reproduction steps.
2. Output of `ksud kpm doctor --json`.
3. Output of `ksud kpm audit --json` after the attempted load.
4. Output of `adb shell uname -a`.
5. Relevant `dmesg` lines.
6. Kernel config, WSA kernel release tag, kernel SHA256 and ReSukiSU submodule commit.
7. WSA package version, Windows build and whether Windows Memory Integrity was on or off.

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
5. `/data/adb/kpm.disabled` must suppress boot-time autoload until removed.
6. Diagnostics should expose concrete error codes rather than converting failures into success.
