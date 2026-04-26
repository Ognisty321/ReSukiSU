# WSA x86_64 KPM Runtime

Author and maintainer: Ognisty321

This document describes the ReSukiSU side of the WSA x86_64 KPM runtime.

## Purpose

The upstream KPM ecosystem is mostly ARM64. WSA runs an x86_64 kernel, so ARM64 `kpimg` and ARM64 `.kpm` binaries are not usable directly.

This branch adds an x86_64 direct KPM loader and compatibility layer inside ReSukiSU for the WSA kernel tree.

## Main Files

1. `kernel/kpm/kpm_loader_x86_64.c`
2. `kernel/kpm/kpm_loader_x86_64.h`
3. `kernel/kpm/kpm.c`
4. `kernel/Kbuild`
5. `kernel/hook/x86_64/patch_memory.c`
6. `kernel/supercall/dispatch.c`
7. `userspace/ksud/src/android/cli.rs`

## Loader ABI

The loader accepts x86_64 `ET_REL` KPM objects with these sections:

1. `.kpm.info`
2. `.kpm.init`
3. `.kpm.exit`
4. `.kpm.ctl0`
5. `.kpm.ctl1`

The loader validates ELF headers, section bounds, string bounds, relocation section sizes and entrypoint locations before invoking module code.

## Hook Backend

The normal inline hook path uses a 5 byte `JMP rel32` when the replacement target is in range.

Install uses `text_poke_bp()` under `text_mutex`.

Restore also uses `text_poke_bp()`. During the INT3 patching window, the emulated instruction is the old jump to the trampoline, while the bytes being written are the original prologue bytes.

Generated trampolines and wrapper stubs are allocated from the module area, emitted while `RW+NX`, then moved to `ROX`. Before freeing executable buffers, the code waits for Tasks RCU grace periods through `synchronize_rcu_tasks_rude()` and `synchronize_rcu_tasks()`.

The rare far jump fallback still uses the existing ReSukiSU x86_64 text writer. Direct syscall hook wrappers are intentionally unsupported on this WSA build and return `EOPNOTSUPP`.

## Compatibility Surface

Implemented compatibility symbols include:

1. `kpver`
2. `kver`
3. `kp_malloc`
4. `kp_free`
5. `compat_copy_to_user`
6. `symbol_lookup_name`
7. `hotpatch`
8. `hook`
9. `hook_wrap`
10. `fp_hook`
11. `fp_hook_wrap`

ARM64 branch helper symbols remain unsupported on x86_64.

## Tested Result

Tested on WSA Linux `5.15.104-windows-subsystem-for-android-20230927` build `#20`.

Expected version:

```text
ReSukiSU-x86_64-KPM-loader/0.20
```

Validated capability modules:

1. Basic KPM load, info, control and unload.
2. Hotpatch and function pointer hook.
3. Inline hook and trampoline restore.
4. `hook_wrap` and `fp_hook_wrap`.
5. x86_64 instruction relocation checks.
6. Malformed `.kpm.info` rejection.
7. Syscall hook unsupported path.

Stress result:

```text
500 loops x 5 modules = 2500 load/control/unload cycles
final kpm num = 0
```

Kernel log check after the run was clean for kernel `BUG`, `WARNING`, `Oops`, general protection faults, invalid opcode reports and use after free reports.

## Porting Existing KPMs

ARM64 `.kpm` binaries do not load on x86_64.

KPMs with source code can be ported if they avoid ARM64 assembly, ARM64 syscall numbers, ARM64 system registers and ARM64 branch helpers.

Recommended x86_64 module flags:

```text
-mcmodel=kernel -mno-red-zone -mno-sse -mno-mmx -mno-avx -fno-jump-tables -fcf-protection=none -mretpoline-external-thunk -fno-pic -fno-plt -fno-common
```
