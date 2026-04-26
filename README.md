# ReSukiSU (WSA x86_64 fork)

<img align='right' src='docs/ReSukiSU_blue.svg' width='220px' alt="ReSukiSU Icon">

This is a fork of [`ReSukiSU/ReSukiSU`](https://github.com/ReSukiSU/ReSukiSU) that adds an **x86_64 KPM runtime** on top of ReSukiSU and SUSFS so the result can be used inside the [WSA x86_64 kernel](https://github.com/Ognisty321/WSA-Linux-Kernel).

ReSukiSU itself is based on [`SukiSU-Ultra/SukiSU-Ultra`](https://github.com/SukiSU-Ultra/SukiSU-Ultra) which is based on [`tiann/KernelSU`](https://github.com/tiann/KernelSU). All upstream attribution and license terms are preserved.

[![Latest release](https://img.shields.io/github/v/release/Ognisty321/WSA-Linux-Kernel?label=Kernel%20release&logo=github)](https://github.com/Ognisty321/WSA-Linux-Kernel/releases/latest)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-orange.svg?logo=gnu)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

## What This Fork Adds

The public ReSukiSU and SukiSU KPM flow expects ARM64 KernelPatch payloads. WSA runs an x86_64 kernel, so a normal ReSukiSU build with `CONFIG_KPM=y` exposes the API surface but does not provide a real x86_64 backend behind it. This fork adds:

1. Android x86_64 `ksud kpm` command path so ReSukiSU Manager can drive the loader.
2. x86_64 `ET_REL` KPM ELF loader with bounds checks on header, sections, strings, relocations and entry points.
3. x86_64 RELA relocation handling for `R_X86_64_64`, `R_X86_64_PC32`, `R_X86_64_PLT32`, `R_X86_64_32`, `R_X86_64_32S`, `R_X86_64_GOTPCREL`, `R_X86_64_GOTPCRELX`, `R_X86_64_REX_GOTPCRELX`.
4. KernelPatch style compatibility surface: `kpver`, `kver`, `kp_malloc`, `kp_free`, `compat_copy_to_user`, `symbol_lookup_name`, `hotpatch`, `hook`, `hook_wrap`, `fp_hook`, `fp_hook_wrap`.
5. x86_64 inline hook backend with kernel `insn` decoder for length and RIP relative fixup.
6. `text_poke_bp()` based install and restore for normal `JMP rel32` hooks under `text_mutex`.
7. `RW+NX` to `ROX` page transitions for trampolines and wrapper stubs.
8. `synchronize_rcu_tasks_rude()` plus `synchronize_rcu_tasks()` before generated executable buffers are freed.
9. Refusal of unsafe or conflicting hook targets owned by ftrace, kprobes, alternatives, jump labels or static calls.

Detailed write up: [docs/WSA_X86_64_KPM.md](docs/WSA_X86_64_KPM.md).

## Where Does the Kernel Build Live?

This repository is meant to be consumed as a `KernelSU` submodule of the WSA kernel fork. Users who want a working WSA setup should go to:

> [Ognisty321/WSA-Linux-Kernel](https://github.com/Ognisty321/WSA-Linux-Kernel)

That repository ships the tested release binary and the install guide.

## Tested Version

| Field | Value |
| --- | --- |
| KPM loader | `ReSukiSU-x86_64-KPM-loader/0.20` |
| WSA kernel build | `#20` |
| Stress result | `500 loops x 5 modules = 2500 load/control/unload cycles` |
| Final module count | `kpm num = 0` |

## Main Implementation Files

1. [`kernel/kpm/kpm_loader_x86_64.c`](kernel/kpm/kpm_loader_x86_64.c) main x86_64 KPM loader.
2. [`kernel/kpm/kpm_loader_x86_64.h`](kernel/kpm/kpm_loader_x86_64.h) loader internal API.
3. [`kernel/kpm/kpm.c`](kernel/kpm/kpm.c) loader integration with the supercall path.
4. [`kernel/hook/x86_64/patch_memory.c`](kernel/hook/x86_64/patch_memory.c) x86_64 text patching backend.
5. [`userspace/ksud/src/android/cli.rs`](userspace/ksud/src/android/cli.rs) Android x86_64 `ksud kpm` command path.

## Compatibility

1. ARM64 `.kpm` binaries cannot load on this x86_64 loader.
2. KPMs with C source can be ported by rebuilding for x86_64 with the flags documented in [docs/WSA_X86_64_KPM.md](docs/WSA_X86_64_KPM.md#kpm-build-flags).
3. Direct syscall hook install is intentionally not exposed and returns `EOPNOTSUPP`.

## Upstream

Upstream ReSukiSU continues to be maintained at [`ReSukiSU/ReSukiSU`](https://github.com/ReSukiSU/ReSukiSU). Issues that are not specific to the WSA x86_64 KPM port should be reported upstream first.

## License

GPL-2.0. Upstream KernelSU, SukiSU and ReSukiSU notices are kept under their original files. See [LICENSE](LICENSE).
