#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat >&2 <<'USAGE'
Usage: scripts/check-manager-kpm-x86.sh <manager.apk|libksud.so|ksud>

Checks that a ReSukiSU Manager APK, extracted libksud.so or release ksud
binary carries an x86_64 Android KPM command path. This is a packaging guard
for WSA x86_64 builds.
USAGE
}

if [ "$#" -ne 1 ]; then
	usage
	exit 2
fi

INPUT="$1"
TMP=""
STRINGS_TMP=""

cleanup() {
	if [ -n "$TMP" ]; then
		rm -f "$TMP"
	fi
	if [ -n "$STRINGS_TMP" ]; then
		rm -f "$STRINGS_TMP"
	fi
}
trap cleanup EXIT

need_tool() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required tool: $1" >&2
		exit 2
	fi
}

extract_lib() {
	local input="$1"

	case "$input" in
		*.apk|*.zip)
			need_tool unzip
			if ! unzip -l "$input" 'lib/x86_64/libksud.so' >/dev/null 2>&1; then
				echo "missing lib/x86_64/libksud.so in $input" >&2
				exit 1
			fi
			TMP="$(mktemp "${TMPDIR:-/tmp}/libksud-x86_64.XXXXXX.so")"
			unzip -p "$input" 'lib/x86_64/libksud.so' >"$TMP"
			printf '%s\n' "$TMP"
			;;
		*)
			printf '%s\n' "$input"
			;;
	esac
}

if [ ! -f "$INPUT" ]; then
	echo "file not found: $INPUT" >&2
	exit 2
fi

need_tool readelf
need_tool strings

LIB="$(extract_lib "$INPUT")"

class="$(readelf -h "$LIB" | awk '/Class:/ {print $2}')"
machine="$(readelf -h "$LIB" | sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p')"

if [ "$class" != "ELF64" ]; then
	echo "libksud is not ELF64: $class" >&2
	exit 1
fi

case "$machine" in
	*X86-64*|*x86-64*)
		;;
	*)
		echo "libksud is not x86_64: $machine" >&2
		exit 1
		;;
esac

missing=0
STRINGS_TMP="$(mktemp "${TMPDIR:-/tmp}/libksud-strings.XXXXXX")"
strings "$LIB" >"$STRINGS_TMP"

for token in \
	"KPM module manager" \
	"Load a KPM module" \
	"Print KPM Loader version" \
	"Failed to get kpm audit" \
	"Print boot-time KPM autoload status" \
	"Load all .kpm files from the autoload directory now" \
	"/data/adb/kpm"; do
	if ! grep -Fq "$token" "$STRINGS_TMP"; then
		echo "missing KPM userspace token in libksud.so: $token" >&2
		missing=1
	fi
done

if [ "$missing" -ne 0 ]; then
	exit 1
fi

printf 'manager x86_64 KPM userspace path ok: %s\n' "$INPUT"
