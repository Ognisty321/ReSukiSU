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

## Loader ABI

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

The stock WSA configuration does not enable `KASAN`, `KCSAN`, `DEBUG_WX`, `IBT`, `CFI` or `FineIBT`. Validation rows that need these configs are tracked here for future debug kernel runs:

1. CFI / IBT / FineIBT compliance.
2. `endbr64` preservation under IBT (hook at `func+4`).
3. `text_poke_bp` atomicity under multi CPU stress.
4. `KASAN_VMALLOC`, `KCSAN`, `KFENCE`, `DEBUG_WX`, `PROVE_LOCKING`, `DEBUG_LIST`, `DEBUG_KMEMLEAK` 24 hour stress soak.
5. AFL++ / libFuzzer harness for the ELF parser.
6. ftrace / kprobes / livepatch coexistence.

## Compatibility

1. ARM64 `.kpm` binaries cannot load on this x86_64 kernel.
2. Source level KPMs port cleanly when they avoid ARM64 inline asm, ARM64 syscall numbers, ARM64 system registers and ARM64 branch helpers.
3. WSA does not have most vendor specific Android drivers, so KPMs that target a specific phone vendor cannot work on WSA regardless of architecture.
