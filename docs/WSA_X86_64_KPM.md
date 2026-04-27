# WSA x86_64 ReSukiSU KPM Runtime

This document describes the ReSukiSU KPM runtime that powers the WSA x86_64 kernel port. The kernel build itself lives at [Ognisty321/WSA-Linux-Kernel](https://github.com/Ognisty321/WSA-Linux-Kernel); this repository is consumed there as the `KernelSU` submodule.

## Why a Port Was Needed

The public KPM ecosystem grew on top of KernelPatch, which is built around AArch64 specifics (fixed length 4 byte instructions, branch helpers, `mrs sp_el0`, AArch64 ELF and `R_AARCH64_*` relocations, ARM64 syscall numbers, `Image` parsing in `kptools`). WSA runs an x86_64 Linux kernel, so a normal ReSukiSU build with `CONFIG_KPM=y` exposes the API surface but does not provide a real x86_64 backend behind it.

## Scope

Implemented:

1. Android x86_64 `ksud kpm` command path.
2. x86_64 `ET_REL` KPM ELF loader with header / section / string / relocation / entry point bounds checks.
3. x86_64 RELA relocation handling for `R_X86_64_64`, `R_X86_64_PC32`, `R_X86_64_PLT32`, `R_X86_64_32`, `R_X86_64_32S`, `R_X86_64_GOTPCREL`, `R_X86_64_GOTPCRELX`, `R_X86_64_REX_GOTPCRELX`.
4. KernelPatch style compatibility symbols: `kpver`, `kver`, `kp_malloc`, `kp_free`, `compat_copy_to_user`, `symbol_lookup_name`, `hotpatch`, `hook`, `hook_wrap`, `fp_hook`, `fp_hook_wrap`.
5. x86_64 inline hook backend that uses the kernel `insn` decoder for length and RIP relative fixup.
6. `text_poke_bp()` based install and restore for normal `JMP rel32` hooks under `text_mutex`.
7. `RW+NX` to `ROX` page transitions for trampolines and wrapper stubs.
8. `synchronize_rcu_tasks_rude()` plus `synchronize_rcu_tasks()` before generated executable buffers are freed.
9. Refusal of unsafe or conflicting hook targets owned by ftrace, kprobes, alternatives, jump labels or static calls.
10. Refusal of patching from IRQ or atomic context.
11. Userspace capability handshake through `KSU_KPM_CAPS`.
12. Buildable x86_64 KPM SDK examples and ELF fuzz smoke CI.
13. `ksud kpm audit` reporting with module source paths, SHA256 hashes where userspace can read the module file, hook counters and unload gate state.

Not implemented in this release:

1. Direct syscall hook install. Wrappers exist for compatibility but install calls return `EOPNOTSUPP`.
2. ARM64 branch helper APIs (`branch_from_to`, `branch_relative`, `branch_absolute`, `ret_absolute`).
3. ARM64 `kpimg` style boot time patching of the kernel image.

## Main Files

1. [`kernel/kpm/kpm_loader_x86_64.c`](../kernel/kpm/kpm_loader_x86_64.c)
2. [`kernel/kpm/kpm_loader_x86_64.h`](../kernel/kpm/kpm_loader_x86_64.h)
3. [`kernel/kpm/kpm.c`](../kernel/kpm/kpm.c)
4. [`kernel/Kbuild`](../kernel/Kbuild)
5. [`kernel/hook/x86_64/patch_memory.c`](../kernel/hook/x86_64/patch_memory.c)
6. [`kernel/supercall/dispatch.c`](../kernel/supercall/dispatch.c)
7. [`userspace/ksud/src/android/cli.rs`](../userspace/ksud/src/android/cli.rs)
8. [`docs/KPM_X86_64_ABI.md`](KPM_X86_64_ABI.md)
9. [`examples/kpm-x86_64`](../examples/kpm-x86_64)
10. [`tools/kpm-x86-fuzz`](../tools/kpm-x86-fuzz)

## Loader ABI

The formal ABI contract is defined in [KPM_X86_64_ABI.md](KPM_X86_64_ABI.md). This section is a short operational summary.

Current loader marker: `ReSukiSU-x86_64-KPM-loader/0.20`.

KPM modules are x86_64 `ET_REL` ELF objects with these sections:

1. `.kpm.info` text metadata: name, version, license, author, description.
2. `.kpm.init` initialization entry (`KPM_INIT`).
3. `.kpm.exit` cleanup entry (`KPM_EXIT`).
4. `.kpm.ctl0` optional first control entry (`KPM_CTL0`).
5. `.kpm.ctl1` optional second control entry (`KPM_CTL1`).

Lifecycle:

```text
load   -> kpm_init(args, "load", reserved)
ctl    -> kpm_ctl0(ctl_args, out_msg, outlen)
ctl    -> kpm_ctl1(a1, a2, a3)
unload -> kpm_exit(reserved)
```

The loader exports `kpm_loader_abi_version`, `kpm_abi_version`, `kpm_loader_feature_bits` and `kpm_feature_bits` as compatibility symbols so modules can check the runtime contract before using optional APIs. Userspace can read the same contract through `KSU_KPM_CAPS`, which is used by `ksud kpm doctor --json`.

## Hook Backend

Normal in range inline hook:

1. The patcher acquires `text_mutex`.
2. `text_poke_bp()` installs a 5 byte `JMP rel32` to a per hook trampoline. The breakpoint emulation step uses the new jump itself.
3. The trampoline contains the relocated original prologue, copied with the kernel `insn` decoder, with RIP relative operands rewritten and overflowing displacements rejected with `-ERANGE`.
4. The trampoline pages start `RW+NX`, are populated, then transition to `ROX`.

Restore:

1. The patcher acquires `text_mutex`.
2. `text_poke_bp()` writes the original prologue bytes back. The breakpoint emulation step uses the previous jump bytes so any in flight CPU continues into the trampoline rather than into a half restored prologue.
3. `synchronize_rcu_tasks_rude()` and `synchronize_rcu_tasks()` are called before the trampoline pages are freed, so no task can still be running inside them.

Far jump fallback: when the trampoline cannot be reached with a 5 byte `JMP rel32`, the install path falls back to a 14 byte absolute jump emitted by the existing ReSukiSU x86_64 text writer.

Address validation:

1. Inline hook targets must pass `kernel_text_address()`. A pointer that merely looks like a high-half kernel address is not enough.
2. Replacement functions must be normal kernel text or text owned by the currently executing KPM module. Generated wrapper stubs are accepted only through the internal `hook_wrap` path.
3. Function pointer hooks still validate the pointer slot as a writable kernel address, but their replacement target must satisfy the executable-address rule above.

## Safety Semantics

1. `hotpatch(addrs, values, cnt)` now uses a prepare / commit / rollback model. The loader snapshots all original 32 bit values before patching. If any commit step fails, previously written values are restored and rollback failures are logged with the failing address.
2. `unload` marks a module as unloading before calling `.kpm.exit`. While that flag is set, `control` returns `-EBUSY` and duplicate loads are refused because the module remains in the registry.
3. If `.kpm.exit` returns an error, the module stays loaded instead of freeing executable memory that may still be referenced by hooks or callbacks.
4. Hooks installed from a KPM `init`, `control` or `exit` context are tagged to that module. Unload is refused after `.kpm.exit` if owned inline hooks, function pointer hooks, wrapper chain items or active callbacks remain.
5. Module ownership context is tracked per task and as a stack, so overlapping callbacks from different tasks cannot overwrite each other's current owner.

## KPM Build Flags

For out of tree x86_64 KPM modules:

```text
-mcmodel=kernel -mno-red-zone -mno-sse -mno-mmx -mno-avx -fno-jump-tables -fcf-protection=none -mretpoline-external-thunk -fno-pic -fno-plt -fno-common
```

Rationale:

1. `-mcmodel=kernel` keeps the kernel `[-2 GB, 0)` code model.
2. `-mno-red-zone`, `-mno-sse`, `-mno-mmx`, `-mno-avx` match the kernel ABI.
3. `-fno-jump-tables` keeps prologues hookable.
4. `-fcf-protection=none` avoids generating `endbr64` from the user toolchain in places the loader does not expect.
5. `-mretpoline-external-thunk` routes indirect calls through the kernel retpoline thunks.
6. `-fno-pic -fno-plt -fno-common` keep the object file structure that the loader expects.

## Diagnostics

The Android x86_64 `ksud kpm` path propagates kernel loader errors as command failures. For automation and Manager integration:

```sh
ksud kpm version --json
ksud kpm list --json
ksud kpm doctor
ksud kpm doctor --json
ksud kpm audit --json
```

`doctor` reports loader reachability, loaded module count, safe mode state and the `/data/adb/kpm` directory mode. The expected mode is `700`; the boot-time loader path creates or repairs that directory and rejects symlinks.
`audit` reports the loader's hook accounting plus module source paths and SHA256 hashes for readable `.kpm` files.

## SDK Examples

Buildable examples live in `examples/kpm-x86_64`:

```sh
scripts/build-kpm-x86_64.sh
```

The examples cover hello, control, inline hook, function pointer hook, hotpatch and failure cases. They are compiled as `ET_REL` objects and keep the `.kpm.*` sections in the format required by the loader.

For runtime validation against a booted WSA instance:

```sh
scripts/kpm-x86-runtime-selftest.sh
```

The self-test covers the `text_poke_bp` inline hook path, ROX trampoline transition, function pointer hook path, unload refusal/recovery and a short control/unload race, then scans dmesg for crash, sanitizer, `DEBUG_WX`, lockdep and use-after-free markers.
It also removes the sample `.kpm` files from `/data/adb/kpm` during cleanup so they do not autoload on the next WSA boot.

For the local all-in-one check used before syncing this submodule into the WSA kernel tree:

```sh
scripts/kpm-x86-preflight.sh
```

The preflight runs the ABI/version guard, shell syntax checks, example build, ELF section validation, fuzz smoke and `ksud` Rust checks. Set `RUN_WSA=1` to append the live runtime self-test.

## Validation Done

The release build was stress tested with capability KPMs covering:

1. Basic KPM ABI (`load`, `info`, `control`, `unload`).
2. Hotpatch and function pointer hook capability checks.
3. Inline hook install, trampoline call and restore checks.
4. `hook_wrap` and `fp_hook_wrap` checks for argument counts up to 12.
5. x86_64 instruction relocation cases including RIP relative MOV / LEA, ENDBR64, 10 byte `movabs`, refusal of `call rel32` and short branches in the prologue.
6. Malformed `.kpm.info` rejection.
7. Unsupported syscall hook rejection.
8. `500` loops across `5` capability modules, for `2500` total load / control / unload cycles.
9. Final `kpm num = 0`.
10. Kernel log clean for `BUG`, `WARNING`, `Oops`, general protection faults, invalid opcode reports and use after free reports.

## Open Validation

The stock WSA configuration does not enable `KASAN`, `KCSAN`, `DEBUG_WX`, `IBT`, `CFI` or `FineIBT`. The WSA kernel tree carries optional validation overlays in `configs/wsa/fragments/` for debug, sanitizer and experimental IBT/CFI probe builds. Validation rows that need these configs are tracked here for future debug kernel runs:

1. CFI / IBT / FineIBT compliance.
2. `endbr64` preservation under IBT (hook at `func+4`).
3. `text_poke_bp` atomicity under multi CPU stress.
4. `KASAN_VMALLOC`, `KCSAN`, `KFENCE`, `DEBUG_WX`, `PROVE_LOCKING`, `DEBUG_LIST`, `DEBUG_KMEMLEAK` 24 hour stress soak.
5. Longer AFL++ / libFuzzer runs beyond the smoke harness.
6. ftrace / kprobes / livepatch coexistence.

## Compatibility

1. ARM64 `.kpm` binaries cannot load on this x86_64 kernel.
2. Source level KPMs port cleanly when they avoid ARM64 inline asm, ARM64 syscall numbers, ARM64 system registers and ARM64 branch helpers.
3. WSA does not have most vendor specific Android drivers, so KPMs that target a specific phone vendor cannot work on WSA regardless of architecture.
