#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
	printf 'usage: %s module.kpm [...]\n' "$0" >&2
	exit 2
fi

if ! command -v readelf >/dev/null 2>&1; then
	echo "readelf is required" >&2
	exit 2
fi

if ! command -v sha256sum >/dev/null 2>&1; then
	echo "sha256sum is required" >&2
	exit 2
fi

allowed_relocation() {
	case "$1" in
	R_X86_64_NONE | \
		R_X86_64_64 | \
		R_X86_64_32 | \
		R_X86_64_32S | \
		R_X86_64_PC32 | \
		R_X86_64_PLT32 | \
		R_X86_64_PC64 | \
		R_X86_64_GOTPCREL | \
		R_X86_64_GOTPCRELX | \
		R_X86_64_REX_GOTPCRELX)
		return 0
		;;
	*)
		return 1
		;;
	esac
}

has_section() {
	local file="$1"
	local section="$2"

	readelf -WS "$file" | awk -v section="$section" '
		{
			for (i = 1; i <= NF; i++) {
				if ($i == section) {
					found = 1
				}
			}
		}
		END {
			exit found ? 0 : 1
		}
	'
}

has_rel_sections() {
	local file="$1"

	readelf -WS "$file" | awk '
		{
			for (i = 1; i <= NF; i++) {
				if ($i == "REL") {
					found = 1
				}
			}
		}
		END {
			exit found ? 0 : 1
		}
	'
}

check_one() {
	local file="$1"
	local class data machine type sha relocs reloc failed
	local -a unsupported

	failed=0
	unsupported=()

	if [ ! -f "$file" ]; then
		printf '%s: not found\n' "$file" >&2
		return 1
	fi

	if ! readelf -h "$file" >/dev/null 2>&1; then
		printf '%s: not an ELF file\n' "$file" >&2
		return 1
	fi

	class="$(readelf -h "$file" | awk -F: '/Class:/ { gsub(/^[ \t]+/, "", $2); print $2; exit }')"
	data="$(readelf -h "$file" | awk -F: '/Data:/ { gsub(/^[ \t]+/, "", $2); print $2; exit }')"
	type="$(readelf -h "$file" | awk -F: '/Type:/ { gsub(/^[ \t]+/, "", $2); print $2; exit }')"
	machine="$(readelf -h "$file" | awk -F: '/Machine:/ { gsub(/^[ \t]+/, "", $2); print $2; exit }')"

	if [ "$class" != "ELF64" ]; then
		printf '%s: expected ELF64, got %s\n' "$file" "$class" >&2
		failed=1
	fi

	case "$data" in
	*"little endian"*) ;;
	*)
		printf '%s: expected little endian data, got %s\n' "$file" "$data" >&2
		failed=1
		;;
	esac

	case "$type" in
	REL*) ;;
	*)
		printf '%s: expected ET_REL, got %s\n' "$file" "$type" >&2
		failed=1
		;;
	esac

	case "$machine" in
	*"X86-64"* | *"x86-64"* | *"Advanced Micro Devices"*) ;;
	*)
		printf '%s: expected x86_64 machine, got %s\n' "$file" "$machine" >&2
		failed=1
		;;
	esac

	for section in .kpm.info .kpm.init .kpm.exit; do
		if ! has_section "$file" "$section"; then
			printf '%s: missing required section %s\n' "$file" "$section" >&2
			failed=1
		fi
	done

	if has_rel_sections "$file"; then
		printf '%s: uses REL relocation sections, expected RELA on x86_64\n' "$file" >&2
		failed=1
	fi

	while IFS= read -r reloc; do
		[ -n "$reloc" ] || continue
		if ! allowed_relocation "$reloc"; then
			unsupported+=("$reloc")
		fi
	done < <(readelf -Wr "$file" | awk '$3 ~ /^R_/ { print $3 }' | sort -u)

	if [ "${#unsupported[@]}" -gt 0 ]; then
		printf '%s: unsupported relocation(s): %s\n' "$file" "${unsupported[*]}" >&2
		failed=1
	fi

	if [ "$failed" -ne 0 ]; then
		return 1
	fi

	sha="$(sha256sum "$file" | awk '{ print $1 }')"
	relocs="$(readelf -Wr "$file" | awk '$3 ~ /^R_/ { print $3 }' | sort -u | paste -sd, -)"
	if [ -z "$relocs" ]; then
		relocs="none"
	fi
	printf '%s: ok sha256=%s relocations=%s\n' "$file" "$sha" "$relocs"
}

failed=0
for file in "$@"; do
	if ! check_one "$file"; then
		failed=1
	fi
done

exit "$failed"
