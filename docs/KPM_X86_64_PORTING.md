# Porting KPM Modules to WSA x86_64

This checklist is for KPM modules that have source code and were originally written for ARM64 KernelPatch style environments. Prebuilt ARM64 `.kpm` files cannot be converted in place.

## Quick Decision Tree

1. If the module is only an ARM64 `.kpm` binary, it cannot run on WSA x86_64.
2. If the module patches `Image`, uses `kpimg` boot-time patching or depends on AArch64 instruction helpers, it needs a source-level rewrite.
3. If the module targets a phone vendor driver that WSA does not ship, it will not work on WSA even after an architecture port.
4. If the module is mostly C and hooks normal kernel functions, it is a candidate for x86_64 rebuild and validation.

## Build Target

Build as a little endian x86_64 `ET_REL` object with `e_machine == EM_X86_64`. Keep the standard `.kpm.*` sections:

1. `.kpm.info`
2. `.kpm.init`
3. `.kpm.exit`
4. Optional `.kpm.ctl0`
5. Optional `.kpm.ctl1`

Recommended clang flags:

```text
-mcmodel=kernel -mno-red-zone -mno-sse -mno-mmx -mno-avx -fno-jump-tables -fcf-protection=none -mretpoline-external-thunk -fno-pic -fno-plt -fno-common
```

Start from `examples/kpm-x86_64/include/kpm_x86_64.h` and keep the module freestanding. Do not include Android userspace headers in the KPM object.

## Source Changes

Replace ARM64-specific code before the first WSA test:

1. Remove AArch64 inline assembly such as `mrs sp_el0`, `tcr_el1`, `br`, `blr` and `ret` stubs.
2. Replace fixed 4 byte instruction assumptions with x86_64 instruction-length aware logic, or use the loader `hook` API and let it decode the prologue.
3. Remove `R_AARCH64_*` relocation assumptions. The x86_64 loader accepts the relocation set documented in `KPM_X86_64_ABI.md`.
4. Replace ARM64 syscall numbers and direct syscall-table hook logic. Direct syscall hook install returns `EOPNOTSUPP` on this runtime.
5. Re-check all struct offsets against the WSA `5.15.104` kernel source, not against a phone kernel.
6. Avoid device-specific symbols unless the WSA kernel exports or resolves them.

## Runtime Feature Checks

Modules can require the x86_64 ABI and optional features before installing hooks:

```c
extern const unsigned int kpm_abi_version;
extern const unsigned long kpm_feature_bits;

#define KPM_X86_64_FEATURE_INLINE_HOOK (1UL << 3)

static long require_x86_64_runtime(void)
{
	if (kpm_abi_version < 1)
		return -95;
	if (!(kpm_feature_bits & KPM_X86_64_FEATURE_INLINE_HOOK))
		return -95;
	return 0;
}
```

Use `-EOPNOTSUPP` style failures for optional capability gaps so `ksud kpm load` reports a clear command failure.

## Hooking Checklist

Before calling `hook()`:

1. Resolve the target symbol on the WSA kernel you are actually running.
2. Prefer normal C functions in core kernel text.
3. Avoid syscall table entries, ftrace-owned call sites, kprobes, alternatives, jump labels, static calls, `.entry.text` and `.noinstr.text`.
4. Keep replacement functions in module text or normal kernel text.
5. Always keep and use the backup trampoline returned by `hook()`.
6. Unhook in `.kpm.exit` before returning success.

If unload fails, run:

```sh
adb shell su -c "ksud kpm audit --json"
```

Look for active hook or callback counters owned by the module.

## Test Flow

Build the examples and inspect their ELF shape:

```sh
scripts/build-kpm-x86_64.sh clean all
make -C examples/kpm-x86_64 inspect
scripts/check-kpm-module-x86.sh examples/kpm-x86_64/out/*.kpm
```

Run the same checker before adding a third-party module to a WSA compatibility row:

```sh
scripts/check-kpm-module-x86.sh /path/to/your_module.kpm
```

On WSA:

```sh
adb shell su -c "ksud kpm doctor --json"
adb push your_module.kpm /data/local/tmp/your_module.kpm
adb shell su -c "mkdir -p /data/adb/kpm && chmod 700 /data/adb/kpm"
adb shell su -c "cp /data/local/tmp/your_module.kpm /data/adb/kpm/your_module.kpm"
adb shell su -c "ksud kpm load /data/adb/kpm/your_module.kpm"
adb shell su -c "ksud kpm info your_module"
adb shell su -c "ksud kpm audit --json"
adb shell su -c "ksud kpm unload your_module"
```

Then scan the fresh `dmesg` slice for `kpm:`, `BUG`, `WARNING`, `Oops`, `KASAN`, `KCSAN`, `KFENCE`, `DEBUG_WX`, `W+X`, `lockdep` and use-after-free markers.

## Common Failures

| Symptom | Likely cause |
| --- | --- |
| `Exec format error` | Not an x86_64 `ET_REL` KPM or unsupported relocation. |
| `4095` | Inline hook target is not valid kernel text. |
| `4089` | Target text is reserved by ftrace, kprobes, alternatives, jump labels or static calls. |
| `4088` | Kernel text patch backend refused or failed the write. |
| `4087` | Executable memory permission transition failed. |
| `4086` | Replacement function is outside allowed executable text. |
| Unload returns busy or fails | The module still owns hooks, wrapper chain items or active callbacks. |
| `scripts/check-kpm-module-x86.sh` rejects the file | The file is not an x86_64 `ET_REL` KPM, is missing required `.kpm.*` sections, uses REL instead of RELA relocation sections or carries a relocation outside the loader ABI. |
