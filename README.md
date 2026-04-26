# ReSukiSU WSA x86_64 KPM Branch

Author and maintainer: Ognisty321

This branch contains the ReSukiSU side of the WSA x86_64 KPM runtime.

Main documentation:

1. `docs/WSA_X86_64_KPM.md`

Main implementation:

1. `kernel/kpm/kpm_loader_x86_64.c`
2. `kernel/kpm/kpm_loader_x86_64.h`

Tested version:

1. KPM version `ReSukiSU-x86_64-KPM-loader/0.20`
2. WSA kernel build `#20`
3. Final stress result `2500` load, control and unload cycles, final `kpm num = 0`

ARM64 `.kpm` binaries are not compatible with x86_64. Existing modules need an x86_64 rebuild or a source level port.
