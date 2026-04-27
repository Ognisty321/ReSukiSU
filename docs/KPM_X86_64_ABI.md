# KPM x86_64 ABI

This document defines the stable ABI contract for x86_64 KPM modules loaded by the WSA ReSukiSU runtime.

The single source of truth for the loader identity is [`kernel/kpm/kpm_loader_x86_64.h`](../kernel/kpm/kpm_loader_x86_64.h):

| Field | Value |
| --- | --- |
| Loader name | `ReSukiSU-x86_64-KPM-loader` |
| Loader version | `ReSukiSU-x86_64-KPM-loader/0.20` |
| ABI version | `1` |

## Module Format

An x86_64 KPM is a little endian `ELFCLASS64` `ET_REL` object with `e_machine == EM_X86_64`. ARM64 `.kpm` binaries, KernelPatch `kpimg` payloads and `ET_DYN` objects are not part of this ABI.

Required sections:

1. `.kpm.info`
2. `.kpm.init`
3. `.kpm.exit`
4. `.symtab`
5. `.strtab`

Optional sections:

1. `.kpm.ctl0`
2. `.kpm.ctl1`
3. Allocatable text, rodata, data and bss style sections accepted by the loader layout pass.

The `.kpm.info` section is a NUL-separated metadata string table. It must be NUL-terminated and must contain at least:

```text
name=<module-name>
version=<module-version>
```

Recognized optional keys are `license`, `author` and `description`. Unknown keys are ignored by the loader.

## Entrypoints

Entrypoint sections contain function pointer slots. After relocation, each non-empty slot must point into the loaded module text range.

```c
typedef long (*kpm_init_t)(const char *args, const char *event, void __user *reserved);
typedef long (*kpm_exit_t)(void __user *reserved);
typedef long (*kpm_ctl0_t)(const char *args, char __user *out_msg, int outlen);
typedef long (*kpm_ctl1_t)(void *a1, void *a2, void *a3);
```

Lifecycle:

1. Load calls `init(args, "load-file", reserved)`.
2. Control calls `.kpm.ctl0` when present.
3. Unload calls `.kpm.exit`.
4. If `exit` returns an error, the loader keeps the module resident and reports the error to userspace.

Return values follow Linux kernel convention: `0` for success, negative `-errno` for failure. Positive init or exit return values are treated as invalid.

## Relocations

Only RELA relocation sections are supported. REL relocation sections are rejected.

Supported relocation types:

| Relocation | Notes |
| --- | --- |
| `R_X86_64_64` | Absolute 64-bit value |
| `R_X86_64_32` | Absolute 32-bit value with bounds check |
| `R_X86_64_32S` | Absolute signed 32-bit value with bounds check |
| `R_X86_64_PC32` | PC-relative 32-bit value with overflow check |
| `R_X86_64_PLT32` | Treated as PC-relative 32-bit call target |
| `R_X86_64_PC64` | PC-relative 64-bit value |
| `R_X86_64_GOTPCREL` | Loader-created GOT slot |
| `R_X86_64_GOTPCRELX` | Loader-created GOT slot |
| `R_X86_64_REX_GOTPCRELX` | Loader-created GOT slot |

Unsupported relocation types fail the load with `-ENOEXEC`.

## Build Contract

Recommended clang flags:

```text
-mcmodel=kernel -mno-red-zone -mno-sse -mno-mmx -mno-avx -fno-jump-tables -fcf-protection=none -mretpoline-external-thunk -fno-pic -fno-plt -fno-common
```

KPM modules must not rely on userspace ABI features such as the red zone, SSE argument passing, PIC/PLT stubs or compiler-generated CFI/IBT landing pads.

For a source-level ARM64 to x86_64 checklist, see [KPM_X86_64_PORTING.md](KPM_X86_64_PORTING.md).

## Feature Bits

The loader exports these read-only symbols to KPM modules:

1. `kpm_loader_version`
2. `kpm_loader_abi_version`
3. `kpm_abi_version`
4. `kpm_loader_feature_bits`
5. `kpm_feature_bits`

Feature bit assignments:

| Bit | Constant | Meaning |
| --- | --- | --- |
| 0 | `SUKISU_KPM_X86_64_FEATURE_ET_REL` | x86_64 `ET_REL` modules |
| 1 | `SUKISU_KPM_X86_64_FEATURE_RELA` | RELA relocation handling |
| 2 | `SUKISU_KPM_X86_64_FEATURE_GOTPCREL` | Loader-created GOT slots |
| 3 | `SUKISU_KPM_X86_64_FEATURE_INLINE_HOOK` | Inline hook API |
| 4 | `SUKISU_KPM_X86_64_FEATURE_FP_HOOK` | Function pointer hook API |
| 5 | `SUKISU_KPM_X86_64_FEATURE_HOTPATCH` | Hotpatch API with rollback on commit failure |
| 6 | `SUKISU_KPM_X86_64_FEATURE_ROX_ALLOC` | Generated executable memory transitions to ROX |
| 7 | `SUKISU_KPM_X86_64_FEATURE_RCU_EXEC_FREE` | RCU task synchronization before executable memory free |
| 8 | `SUKISU_KPM_X86_64_FEATURE_TEXT_POKE_BP` | `text_poke_bp` inline hook install/restore path |
| 9 | `SUKISU_KPM_X86_64_FEATURE_HOOK_TARGET_GUARDS` | ftrace/kprobes/alternatives/jump-label/static-call guards |
| 10 | `SUKISU_KPM_X86_64_FEATURE_AUDIT` | Kernel/userspace audit reporting |
| 11 | `SUKISU_KPM_X86_64_FEATURE_UNLOAD_GATE` | Unload is refused while owned hooks or callbacks remain active |

## Userspace Capability Handshake

The compatibility command `KSU_KPM_VERSION` remains a string-only response for older Manager builds.

New tooling should use `KSU_KPM_CAPS`, which fills `struct ksu_kpm_caps`:

```c
struct ksu_kpm_caps {
    __u32 abi_version;
    __u32 reserved;
    __u64 feature_bits;
    char loader_version[64];
};
```

`ksud kpm doctor --json` reads this command and reports `loader_abi_version` and `loader_feature_bits`. If the kernel is older and does not support `KSU_KPM_CAPS`, `doctor` still falls back to the legacy version command and prints a `loader_caps_error` field.

## Hooking Rules

The inline hook backend copies and relocates the original x86_64 prologue with the kernel instruction decoder. It accepts simple prologues and rejects unsafe cases instead of guessing.

Rejected or guarded targets include:

1. Invalid non-kernel addresses.
2. Existing KPM inline hooks on the same function.
3. Text owned by ftrace, kprobes, alternatives, jump labels or static calls.
4. Prologues containing unsupported control flow such as relative calls, direct jumps, conditional jumps, `ret` or `int3`.
5. RIP-relative displacement rewrites that overflow.
6. Patch attempts from IRQ or atomic context.

Inline hook install return codes:

| Code | Meaning |
| ---: | --- |
| `0` | Hook installed. |
| `4095` | Bad hook target address. |
| `4094` | Hook already installed on this target. |
| `4093` | Hook metadata allocation failed. |
| `4092` | Prologue relocation or instruction copy is unsupported. |
| `4091` | Trampoline or wrapper allocation failed. |
| `4090` | Wrapper chain has no free slot. |
| `4089` | Target text is reserved by ftrace, kprobes, alternatives, jump labels or static calls. |
| `4088` | Text patch backend failed. |
| `4087` | Memory permission transition failed. |
| `4086` | Replacement function is outside allowed executable text. |

## Userspace Diagnostics

`ksud kpm version` returns the compatibility string expected by Manager:

```text
ReSukiSU-x86_64-KPM-loader/0.20
```

Structured diagnostics are available through:

```sh
ksud kpm version --json
ksud kpm list --json
ksud kpm doctor
ksud kpm doctor --json
ksud kpm audit
ksud kpm audit --json
```

`doctor` reports loader reachability, loaded module count, safe mode state, autoload disable state and `/data/adb/kpm` hardening status.

`audit` reports loader feature metadata, loaded modules, source paths, SHA256 hashes for readable module files, active hook/callback counters and active hook records. The loader tags hooks installed from a module's `init`, `control` or `exit` context and refuses unload if `.kpm.exit` returns success but owned hooks or callback chain items are still present.

## SDK And Examples

The x86_64 sample SDK is in [`examples/kpm-x86_64`](../examples/kpm-x86_64).

It builds:

1. `hello_kpm_x86_64`
2. `control_kpm`
3. `inline_hook`
4. `fp_hook`
5. `hotpatch`
6. `failure_cases`

Use:

```sh
scripts/build-kpm-x86_64.sh
```

The generated `.kpm` files are `ET_REL` objects with `.kpm.info`, `.kpm.init` and `.kpm.exit` sections.

## Fuzz Smoke

The userspace ELF metadata smoke fuzzer lives in [`tools/kpm-x86-fuzz`](../tools/kpm-x86-fuzz).

Run:

```sh
scripts/fuzz-kpm-x86-smoke.sh
```

When libFuzzer and sanitizer runtimes are installed, the script uses `-fsanitize=fuzzer,address,undefined`. If the local clang package lacks those runtimes, it falls back to a standalone corpus smoke run so CI and developer machines still exercise malformed ELF input parsing. The smoke corpus includes static malformed seeds, the built x86_64 example KPM objects and deterministic mutations of ELF header and section table fields.

## Preflight

For a local preflight that runs the ABI check, shell syntax checks, example build, ELF section verification, fuzz smoke, Rust host checks and local Android x86_64 checks when an NDK config is present:

```sh
scripts/kpm-x86-preflight.sh
```

Set `RUN_WSA=1` to include the live WSA runtime self-test. Set `RUN_RUST=0` for a lightweight CI pass that only needs the KPM C/tooling checks.

## Runtime Self-Test

After pushing the built examples to WSA, `scripts/kpm-x86-runtime-selftest.sh` exercises:

1. `inline_hook` load/unload for the `text_poke_bp` and trampoline ROX path.
2. `fp_hook` load/control/unload for function pointer patching.
3. `failure_cases` unload refusal followed by control-assisted cleanup.
4. A short `control_kpm` control/unload race.
5. A dmesg scan for `BUG`, `WARNING`, `Oops`, sanitizer, `DEBUG_WX`, lockdep and use-after-free markers.

The self-test unloads known sample modules and removes their `.kpm` files from `/data/adb/kpm` on exit so test artifacts do not become boot-time autoload modules.
