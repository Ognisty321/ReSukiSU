#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${CC:-clang}"
RUNS="${RUNS:-256}"
OUT="${OUT:-${TMPDIR:-/tmp}/kpm_elf_fuzz}"
CORPUS="${CORPUS:-$ROOT/tools/kpm-x86-fuzz/corpus}"
BUILD_EXAMPLES="${BUILD_EXAMPLES:-1}"
FUZZER_LOG="$(mktemp "${TMPDIR:-/tmp}/kpm_elf_fuzz_link.XXXXXX")"
WORK_CORPUS="$(mktemp -d "${TMPDIR:-/tmp}/kpm_elf_seed_corpus.XXXXXX")"
WORK_BASE="$WORK_CORPUS/base"
WORK_VALID="$WORK_CORPUS/valid"
WORK_INVALID="$WORK_CORPUS/invalid"
EXAMPLE_OUT="${EXAMPLE_OUT:-$WORK_CORPUS/example-build}"
VALIDATOR="${OUT}.validate"
mkdir -p "$WORK_BASE" "$WORK_VALID" "$WORK_INVALID"
trap 'rm -f "$FUZZER_LOG" "$VALIDATOR"; rm -rf "$WORK_CORPUS"' EXIT

copy_seed() {
	local src="$1"
	local dst

	dst="$WORK_VALID/$(basename "$src")"
	cp "$src" "$dst"
	printf '%s\n' "$dst"
}

mutate_byte() {
	local src="$1"
	local name="$2"
	local offset="$3"
	local value="$4"
	local dst="$WORK_INVALID/$name"

	cp "$src" "$dst"
	printf '%b' "$value" | dd of="$dst" bs=1 seek="$offset" conv=notrunc status=none
}

truncate_seed() {
	local src="$1"
	local name="$2"
	local bytes="$3"

	dd if="$src" of="$WORK_INVALID/$name" bs=1 count="$bytes" status=none
}

read_le() {
	local file="$1"
	local offset="$2"
	local bytes="$3"

	od -An -tu"$bytes" -N"$bytes" -j"$offset" "$file" | tr -d '[:space:]'
}

section_index() {
	local file="$1"
	local section="$2"

	readelf -SW "$file" | awk -v wanted="$section" '
		match($0, /\[[[:space:]]*[0-9]+\]/) {
			idx = substr($0, RSTART + 1, RLENGTH - 2)
			gsub(/[[:space:]]/, "", idx)
			rest = substr($0, RSTART + RLENGTH)
			split(rest, fields)
			if (fields[1] == wanted) {
				print idx
				exit
			}
		}
	'
}

section_header_offset() {
	local file="$1"
	local section="$2"
	local shoff index

	shoff="$(read_le "$file" 40 8)"
	index="$(section_index "$file" "$section")"
	[ -n "$index" ] || return 1
	printf '%s\n' "$((shoff + index * 64))"
}

mutate_section_bytes() {
	local src="$1"
	local name="$2"
	local section="$3"
	local relative_offset="$4"
	local value="$5"
	local dst="$WORK_INVALID/$name"
	local shdr

	shdr="$(section_header_offset "$src" "$section")"
	cp "$src" "$dst"
	printf '%b' "$value" | dd of="$dst" bs=1 seek="$((shdr + relative_offset))" conv=notrunc status=none
}

mutate_section_last_byte() {
	local src="$1"
	local name="$2"
	local section="$3"
	local dst="$WORK_INVALID/$name"
	local shdr offset bytes

	shdr="$(section_header_offset "$src" "$section")"
	offset="$(read_le "$src" "$((shdr + 24))" 8)"
	bytes="$(read_le "$src" "$((shdr + 32))" 8)"
	[ "$bytes" -gt 0 ]
	cp "$src" "$dst"
	printf '\x41' | dd of="$dst" bs=1 seek="$((offset + bytes - 1))" conv=notrunc status=none
}

mutate_shstr_last_byte() {
	local src="$1"
	local name="$2"
	local dst="$WORK_INVALID/$name"
	local shoff index shdr offset bytes

	shoff="$(read_le "$src" 40 8)"
	index="$(read_le "$src" 62 2)"
	shdr="$((shoff + index * 64))"
	offset="$(read_le "$src" "$((shdr + 24))" 8)"
	bytes="$(read_le "$src" "$((shdr + 32))" 8)"
	[ "$bytes" -gt 0 ]
	cp "$src" "$dst"
	printf '\x41' | dd of="$dst" bs=1 seek="$((offset + bytes - 1))" conv=notrunc status=none
}

prepare_corpus() {
	local seed
	local first_seed=""

	if compgen -G "$CORPUS/*" >/dev/null; then
		cp "$CORPUS"/* "$WORK_BASE"/
	fi

	if [ "$BUILD_EXAMPLES" = "1" ]; then
		make -C "$ROOT/examples/kpm-x86_64" OUT="$EXAMPLE_OUT" all >/dev/null
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
		mutate_section_bytes "$first_seed" bad-align.kpm .text 48 '\x03\x00\x00\x00\x00\x00\x00\x00'
		mutate_section_bytes "$first_seed" wx-text.kpm .text 8 '\x07\x00\x00\x00\x00\x00\x00\x00'
		mutate_section_bytes "$first_seed" oversized-nobits-type.kpm .text 4 '\x08\x00\x00\x00'
		mutate_section_bytes "$WORK_INVALID/oversized-nobits-type.kpm" oversized-nobits.kpm .text 32 \
			'\x00\x00\x00\x03\x00\x00\x00\x00'
		mutate_shstr_last_byte "$first_seed" unterminated-shstr.kpm
		mutate_section_last_byte "$first_seed" unterminated-symstr.kpm .strtab
		mutate_section_bytes "$first_seed" bad-rela-link.kpm .rela.kpm.init 40 '\x00\x00\x00\x00'
	fi
}

prepare_corpus

"$CC" \
  -std=c11 \
  -Wall -Wextra -Werror \
  -O2 \
  -DKPM_FUZZ_STANDALONE \
  "$ROOT/tools/kpm-x86-fuzz/kpm_elf_fuzz.c" \
  -o "$VALIDATOR"

mapfile -t valid_files < <(find "$WORK_VALID" -type f | sort)
mapfile -t invalid_files < <(find "$WORK_INVALID" -type f | sort)
if ((${#valid_files[@]} == 0 || ${#invalid_files[@]} == 0)); then
  echo "missing deterministic ELF validation corpus" >&2
  exit 1
fi
"$VALIDATOR" --expect-valid "${valid_files[@]}"
"$VALIDATOR" --expect-invalid "${invalid_files[@]}"

if "$CC" \
    -std=c11 \
    -Wall -Wextra -Werror \
    -O1 -g \
    -fsanitize=fuzzer,address,undefined \
    "$ROOT/tools/kpm-x86-fuzz/kpm_elf_fuzz.c" \
    -o "$OUT" >"$FUZZER_LOG" 2>&1; then
  "$OUT" "$WORK_BASE" "$WORK_VALID" "$WORK_INVALID" -runs="$RUNS" -max_len=65536 -detect_leaks=0
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
