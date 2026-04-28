#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

header="kernel/kpm/kpm_loader_x86_64.h"
loader_name="$(sed -n 's/^#define SUKISU_KPM_LOADER_NAME "\(.*\)"/\1/p' "$header")"
loader_semver="$(sed -n 's/^#define SUKISU_KPM_LOADER_SEMVER "\(.*\)"/\1/p' "$header")"
abi_version="$(sed -n 's/^#define SUKISU_KPM_X86_64_ABI_VERSION \([0-9][0-9]*\)$/\1/p' "$header")"

if [[ -z "$loader_name" || -z "$loader_semver" || -z "$abi_version" ]]; then
  echo "missing KPM x86_64 loader version or ABI constants in $header" >&2
  exit 1
fi

loader_version="${loader_name}/${loader_semver}"

for file in README.md docs/WSA_X86_64_KPM.md docs/KPM_X86_64_ABI.md; do
  if ! grep -Fq "$loader_version" "$file"; then
    echo "$file does not mention $loader_version" >&2
    exit 1
  fi
done

if ! grep -Fq "ABI version | \`$abi_version\`" docs/KPM_X86_64_ABI.md; then
  echo "docs/KPM_X86_64_ABI.md does not match ABI version $abi_version" >&2
  exit 1
fi

for token in KSU_KPM_CAPS ksu_kpm_caps KSU_KPM_AUDIT; do
  if ! grep -Fq "$token" uapi/supercall.h; then
    echo "uapi/supercall.h does not expose $token" >&2
    exit 1
  fi
done

for token in SUKISU_KPM_X86_64_FEATURE_AUDIT SUKISU_KPM_X86_64_FEATURE_UNLOAD_GATE SUKISU_KPM_X86_64_FEATURE_SYSCALL_WRAP; do
  if ! grep -Fq "$token" "$header"; then
    echo "$header does not expose $token" >&2
    exit 1
  fi
done

if ! grep -Fq "ksud kpm audit --json" docs/KPM_X86_64_ABI.md; then
  echo "docs/KPM_X86_64_ABI.md does not document kpm audit" >&2
  exit 1
fi

if ! grep -Fq "hook_syscalln" docs/KPM_X86_64_ABI.md; then
  echo "docs/KPM_X86_64_ABI.md does not document syscall wrapping" >&2
  exit 1
fi

search_paths=(
  README.md
  SECURITY.md
  docs
  examples
  scripts
  tools
  kernel/kpm
  uapi
  userspace/ksud/src/android
  manager/app/src/main/java
)
existing_paths=()
for path in "${search_paths[@]}"; do
  [[ -e "$path" ]] && existing_paths+=("$path")
done

stale_pattern='ReSukiSU-x86_64-KPM-loader/0\.2($|[^0-9])'
if command -v rg >/dev/null 2>&1 && rg --version >/dev/null 2>&1; then
  stale_matches() { rg -n "$stale_pattern" "${existing_paths[@]}"; }
else
  stale_matches() { grep -RInE "$stale_pattern" "${existing_paths[@]}"; }
fi

if stale_matches; then
  echo "found stale KPM loader version marker" >&2
  exit 1
fi

echo "KPM x86_64 ABI metadata ok: $loader_version ABI $abi_version"
