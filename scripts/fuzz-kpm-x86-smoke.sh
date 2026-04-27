#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${CC:-clang}"
RUNS="${RUNS:-256}"
OUT="${OUT:-${TMPDIR:-/tmp}/kpm_elf_fuzz}"
CORPUS="${CORPUS:-$ROOT/tools/kpm-x86-fuzz/corpus}"
BUILD_EXAMPLES="${BUILD_EXAMPLES:-1}"
EXAMPLE_OUT="${EXAMPLE_OUT:-$ROOT/examples/kpm-x86_64/out}"
FUZZER_LOG="$(mktemp "${TMPDIR:-/tmp}/kpm_elf_fuzz_link.XXXXXX")"
WORK_CORPUS="$(mktemp -d "${TMPDIR:-/tmp}/kpm_elf_seed_corpus.XXXXXX")"
trap 'rm -f "$FUZZER_LOG"; rm -rf "$WORK_CORPUS"' EXIT

copy_seed() {
	local src="$1"
	local dst="$WORK_CORPUS/$(basename "$src")"

	cp "$src" "$dst"
	printf '%s\n' "$dst"
}

mutate_byte() {
	local src="$1"
	local name="$2"
	local offset="$3"
	local value="$4"
	local dst="$WORK_CORPUS/$name"

	cp "$src" "$dst"
	printf '%b' "$value" | dd of="$dst" bs=1 seek="$offset" conv=notrunc status=none
}

truncate_seed() {
	local src="$1"
	local name="$2"
	local bytes="$3"

	dd if="$src" of="$WORK_CORPUS/$name" bs=1 count="$bytes" status=none
}

prepare_corpus() {
	local seed
	local first_seed=""

	if compgen -G "$CORPUS/*" >/dev/null; then
		cp "$CORPUS"/* "$WORK_CORPUS"/
	fi

	if [ "$BUILD_EXAMPLES" = "1" ]; then
		"$ROOT/scripts/build-kpm-x86_64.sh" >/dev/null
	fi

	if compgen -G "$EXAMPLE_OUT/*.kpm" >/dev/null; then
		for seed in "$EXAMPLE_OUT"/*.kpm; do
			seed="$(copy_seed "$seed")"
			[ -n "$first_seed" ] || first_seed="$seed"
		done
	fi

	if [ -n "$first_seed" ]; then
		truncate_seed "$first_seed" trunc-ehdr.kpm 32
		truncate_seed "$first_seed" trunc-shdr.kpm 160
		mutate_byte "$first_seed" bad-class.kpm 4 '\x01'
		mutate_byte "$first_seed" bad-type.kpm 16 '\x03'
		mutate_byte "$first_seed" bad-machine.kpm 18 '\xb7'
		mutate_byte "$first_seed" bad-shentsize.kpm 58 '\x20'
		mutate_byte "$first_seed" bad-shnum.kpm 60 '\xff'
		mutate_byte "$first_seed" bad-shstrndx.kpm 62 '\xff'
	fi
}

prepare_corpus

if "$CC" \
    -std=c11 \
    -Wall -Wextra -Werror \
    -O1 -g \
    -fsanitize=fuzzer,address,undefined \
    "$ROOT/tools/kpm-x86-fuzz/kpm_elf_fuzz.c" \
    -o "$OUT" >"$FUZZER_LOG" 2>&1; then
  "$OUT" "$WORK_CORPUS" -runs="$RUNS" -max_len=65536 -detect_leaks=0
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

mapfile -t corpus_files < <(find "$WORK_CORPUS" -type f | sort)
if ((${#corpus_files[@]} == 0)); then
  echo "empty corpus: $WORK_CORPUS" >&2
  exit 1
fi
"$OUT" "${corpus_files[@]}"
