# ReSukiSU WSA x86_64 Runtime

Author and maintainer: Ognisty321

This branch contains the ReSukiSU side of the WSA x86_64 kernel port.

## Purpose

ReSukiSU can be built into the WSA x86_64 kernel. For a complete WSA build, this branch also carries the x86_64 KPM runtime because upstream KPM support depends on ARM64 KernelPatch assumptions.

WSA needs x86_64 ELF loading, x86_64 relocations, x86_64 text patching and an Android x86_64 `ksud kpm` userspace path. This branch adds those parts.

## Main Documentation

1. `docs/WSA_X86_64_KPM.md`

## Main Implementation

1. `kernel/kpm/kpm_loader_x86_64.c`
2. `kernel/kpm/kpm_loader_x86_64.h`
3. `kernel/kpm/kpm.c`
4. `kernel/hook/x86_64/patch_memory.c`
5. `userspace/ksud/src/android/cli.rs`

## Tested Version

1. KPM version: `ReSukiSU-x86_64-KPM-loader/0.20`
2. WSA kernel build: `#20`
3. Stress result: `2500` load, control and unload cycles
4. Final module count: `kpm num = 0`

## Compatibility

ARM64 `.kpm` binaries are not compatible with x86_64. Existing modules need an x86_64 rebuild or a source level port.
