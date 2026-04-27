# ReSukiSU Manager x86_64 KPM Compatibility

WSA x86_64 needs a Manager build whose embedded `libksud.so` includes the Android x86_64 `ksud kpm` command path. The kernel loader can be correct while Manager still shows `Unsupported` if the APK was updated to a stock library that lacks that path.

## Required Package Shape

For WSA x86_64 releases, record and verify:

1. The Manager APK version and SHA256.
2. An APK entry at `lib/x86_64/libksud.so`.
3. `libksud.so` is `ELF64` and `Machine: Advanced Micro Devices X86-64`.
4. The library contains the x86_64 KPM command strings used by `ksud kpm doctor`, `ksud kpm audit` and boot-time autoload diagnostics.
5. Runtime commands work against the installed kernel:

```sh
adb shell su -c "ksud kpm version"
adb shell su -c "ksud kpm doctor --json"
adb shell su -c "ksud kpm audit --json"
```

The expected version string is the kernel loader marker, for example:

```text
ReSukiSU-x86_64-KPM-loader/0.20
```

## Local Packaging Check

Use the packaging guard on the APK, an extracted library or a release `ksud` binary:

```sh
scripts/check-manager-kpm-x86.sh /path/to/ReSukiSU-Manager.apk
scripts/check-manager-kpm-x86.sh /path/to/libksud.so
scripts/check-manager-kpm-x86.sh /path/to/ksud
```

The script checks the x86_64 ELF header and scans for KPM userspace tokens. It is a packaging guard, not a substitute for the runtime `ksud kpm` commands above.

## Release Notes Checklist

For every WSA x86_64 release, include:

1. Kernel release tag and kernel SHA256.
2. ReSukiSU submodule commit.
3. Manager APK version and SHA256.
4. `scripts/check-manager-kpm-x86.sh` result for the APK.
5. Output of `ksud kpm version`.
6. Output of `ksud kpm doctor --json`.
7. Output of `ksud kpm audit --json` after a load/control/unload smoke test.

## Update Recovery

If Manager is updated and the KPM badge changes to `Unsupported`:

1. Check `adb shell su -c "ksud kpm version"`.
2. If the command works, the kernel side is still healthy and the Manager APK likely changed `libksud.so`.
3. Reinstall the last known-good Manager APK or install a Manager build that includes `lib/x86_64/libksud.so` with the KPM command path.
4. Re-run `ksud kpm doctor --json` and confirm `kernel_arch` is `x86_64`.
