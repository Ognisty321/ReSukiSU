# KPM x86_64 Examples

These examples build small x86_64 `ET_REL` KPM objects for the WSA ReSukiSU loader.

Build:

```bash
make -C examples/kpm-x86_64
```

Inspect:

```bash
make -C examples/kpm-x86_64 inspect
scripts/check-kpm-module-x86.sh examples/kpm-x86_64/out/*.kpm
```

The generated files are written to `examples/kpm-x86_64/out/*.kpm`.

Expected runtime flow on WSA:

```bash
ksud kpm doctor --json
ksud kpm load /data/adb/kpm/hello_kpm_x86_64.kpm
ksud kpm info hello_kpm_x86_64
ksud kpm audit --json
ksud kpm unload hello_kpm_x86_64
```

The examples intentionally avoid libc and Android headers. The SDK header only emits the `.kpm.info`, `.kpm.init`, `.kpm.exit`, `.kpm.ctl0` and `.kpm.ctl1` sections expected by the loader.

Included samples:

1. `hello_kpm_x86_64` - minimal load/unload module.
2. `control_kpm` - `.kpm.ctl0` return value handling.
3. `control_owner` - hook ownership tagging from a `.kpm.ctl0` callback.
4. `inline_hook` - `hook` / `unhook` against a resolved kernel symbol.
5. `fp_hook` - `fp_hook` / `fp_unhook` against a module-local function pointer.
6. `hotpatch` - no-op transactional hotpatch call.
7. `failure_cases` - unload refusal and control-assisted cleanup path.
