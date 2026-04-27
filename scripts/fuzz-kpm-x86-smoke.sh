#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${CC:-clang}"
RUNS="${RUNS:-256}"
OUT="${OUT:-${TMPDIR:-/tmp}/kpm_elf_fuzz}"
CORPUS="${CORPUS:-$ROOT/tools/kpm-x86-fuzz/corpus}"
FUZZER_LOG="$(mktemp "${TMPDIR:-/tmp}/kpm_elf_fuzz_link.XXXXXX")"
trap 'rm -f "$FUZZER_LOG"' EXIT

if "$CC" \
    -std=c11 \
    -Wall -Wextra -Werror \
    -O1 -g \
    -fsanitize=fuzzer,address,undefined \
    "$ROOT/tools/kpm-x86-fuzz/kpm_elf_fuzz.c" \
    -o "$OUT" >"$FUZZER_LOG" 2>&1; then
  "$OUT" "$CORPUS" -runs="$RUNS" -max_len=65536 -detect_leaks=0
  exit 0
fi

if ! grep -Eq 'libclang_rt\.(fuzzer|asan)|unsupported option.*fsanitize=fuzzer' "$FUZZER_LOG"; then
  cat "$FUZZER_LOG" >&2
fi
echo "libFuzzer runtime unavailable, running standalone corpus smoke"
"$CC" \
  -std=c11 \
  -Wall -Wextra -Werror \
  -O2 \
  -DKPM_FUZZ_STANDALONE \
  "$ROOT/tools/kpm-x86-fuzz/kpm_elf_fuzz.c" \
  -o "$OUT"

mapfile -t corpus_files < <(find "$CORPUS" -type f | sort)
if ((${#corpus_files[@]} == 0)); then
  echo "empty corpus: $CORPUS" >&2
  exit 1
fi
"$OUT" "${corpus_files[@]}"
