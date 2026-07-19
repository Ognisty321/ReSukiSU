# ReSukiSU for WSA x86_64

<img align="right" src="docs/ReSukiSU_blue.svg" width="200" alt="ReSukiSU logo">

ReSukiSU fork that brings a working KPM runtime to the x86_64 kernel used by Windows Subsystem for Android.

[![Latest kernel release](https://img.shields.io/github/v/release/Ognisty321/WSA-Linux-Kernel?label=kernel%20release&logo=github)](https://github.com/Ognisty321/WSA-Linux-Kernel/releases/latest)
[![License: GPL v2](https://img.shields.io/badge/license-GPL--2.0-orange.svg?logo=gnu)](LICENSE)

This repository contains the ReSukiSU, Manager and KPM implementation. If you only want to install a ready-to-use WSA kernel, start with [WSA-Linux-Kernel](https://github.com/Ognisty321/WSA-Linux-Kernel).

## Start Here

| I want to... | Go to |
| --- | --- |
| Install the WSA kernel | [WSA-Linux-Kernel releases](https://github.com/Ognisty321/WSA-Linux-Kernel/releases/latest) |
| Understand the x86_64 KPM port | [Technical overview](docs/WSA_X86_64_KPM.md) |
| Port a KPM module from ARM64 | [Module porting guide](docs/KPM_X86_64_PORTING.md) |
| Build or package the Manager | [Manager x86_64 guide](docs/MANAGER_X86_64.md) |
| Check the module contract | [KPM x86_64 ABI](docs/KPM_X86_64_ABI.md) |
| Prepare changes for upstream | [Patch and rebase guide](docs/UPSTREAMING_X86_64.md) |

## Why This Fork Exists

Upstream ReSukiSU and SukiSU KPM support was designed around ARM64 KernelPatch payloads. WSA uses an x86_64 kernel, so enabling `CONFIG_KPM` alone exposes the interface without providing a usable backend.

This fork fills that gap with:

- an x86_64 ELF loader and relocation support for KPM modules;
- an Android x86_64 `ksud kpm` command path used by ReSukiSU Manager;
- x86_64 inline hooks, function pointer hooks and native syscall wrappers;
- guarded text patching, executable-memory permission transitions and safe trampoline cleanup;
- validation that rejects malformed modules and unsafe or conflicting hook targets;
- `doctor` and `audit` diagnostics for capability and module-state checks.

The detailed implementation and safety model live in [docs/WSA_X86_64_KPM.md](docs/WSA_X86_64_KPM.md).

## Compatibility

- The target is the WSA 5.15 x86_64 kernel. This repository is consumed as the `KernelSU` submodule of [WSA-Linux-Kernel](https://github.com/Ognisty321/WSA-Linux-Kernel).
- ARM64 `.kpm` binaries cannot run on x86_64. Modules with source code can often be rebuilt by following the [porting checklist](docs/KPM_X86_64_PORTING.md).
- Native x86_64 syscall wrappers are supported. Compat syscall wrapping remains unsupported and fails with `EOPNOTSUPP`.
- The Manager package must include an x86_64 `libksud.so` with the `kpm` command path. The packaging guide includes a preflight check.

The current source marker is `ReSukiSU-x86_64-KPM-loader/0.22`. Run `ksud kpm version` on the target system to identify the exact loader included in an installed kernel. The current ABI and supported features are documented in [docs/KPM_X86_64_ABI.md](docs/KPM_X86_64_ABI.md).

## Repository Guide

| Path | Purpose |
| --- | --- |
| `kernel/kpm/` | KPM loader, lifecycle and ABI integration |
| `kernel/hook/x86_64/` | x86_64 patching and hook backend |
| `userspace/ksud/` | Android userspace and `ksud kpm` commands |
| `manager/` | ReSukiSU Manager application |
| `examples/kpm-x86_64/` | Minimal x86_64 KPM examples |
| `scripts/check-kpm-x86-abi.sh` | Local ABI and documentation preflight |

## Validation

The x86_64 path is covered by loader, relocation, hook, malformed-input and repeated load/control/unload tests. Release-specific versions, artifacts and runtime results are kept with the [WSA kernel releases](https://github.com/Ognisty321/WSA-Linux-Kernel/releases) instead of being duplicated here.

## Upstream and License

This fork is based on [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU), which builds on [SukiSU Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra) and [KernelSU](https://github.com/tiann/KernelSU). Issues unrelated to the WSA x86_64 port should be reproduced against upstream before being reported here.

The project is licensed under GPL-2.0. Upstream notices remain in their original files. See [LICENSE](LICENSE).
