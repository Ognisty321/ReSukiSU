#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_RUST="${RUN_RUST:-1}"
RUN_ANDROID="${RUN_ANDROID:-auto}"
RUN_WSA="${RUN_WSA:-0}"
RUN_DIFF_CHECK="${RUN_DIFF_CHECK:-1}"

log() {
	printf '[kpm-x86-preflight] %s\n' "$*"
}

run() {
	log "+ $*"
	"$@"
}

verify_examples() {
	local f sec type

	for f in "$ROOT"/examples/kpm-x86_64/out/*.kpm; do
		if [ ! -f "$f" ]; then
			echo "missing built KPM examples in $ROOT/examples/kpm-x86_64/out" >&2
			exit 1
		fi

		type="$(readelf -h "$f" | awk '/Type:/ {print $2}')"
		if [ "$type" != "REL" ]; then
			echo "$f is not ET_REL: $type" >&2
			exit 1
		fi

		for sec in .kpm.info .kpm.init .kpm.exit; do
			if ! readelf -S "$f" | grep -q "$sec"; then
				echo "$f is missing $sec" >&2
				exit 1
			fi
		done
	done
}

run bash -n \
	"$ROOT/scripts/check-kpm-x86-abi.sh" \
	"$ROOT/scripts/check-manager-kpm-x86.sh" \
	"$ROOT/scripts/build-kpm-x86_64.sh" \
	"$ROOT/scripts/fuzz-kpm-x86-smoke.sh" \
	"$ROOT/scripts/kpm-x86-runtime-selftest.sh" \
	"$0"

run bash "$ROOT/scripts/check-kpm-x86-abi.sh"
if [ -f "$ROOT/userspace/ksud/target/x86_64-linux-android/release/ksud" ]; then
	run bash "$ROOT/scripts/check-manager-kpm-x86.sh" \
		"$ROOT/userspace/ksud/target/x86_64-linux-android/release/ksud"
else
	log "skipping Manager x86_64 packaging guard; no release ksud found"
fi
run bash "$ROOT/scripts/build-kpm-x86_64.sh" clean all
verify_examples
run bash "$ROOT/scripts/fuzz-kpm-x86-smoke.sh"

if [ "$RUN_RUST" = "1" ]; then
	log "checking ksud host Rust build"
	(
		cd "$ROOT/userspace/ksud"
		run cargo fmt --all -- --check
		run cargo check --manifest-path Cargo.toml
		run cargo clippy --all-targets -- -D warnings

		if [ "$RUN_ANDROID" = "1" ] ||
			{ [ "$RUN_ANDROID" = "auto" ] && [ -f .cargo/config.toml ] &&
				grep -q 'x86_64-linux-android' .cargo/config.toml; }; then
			log "checking ksud Android x86_64 target"
			run cargo check --target x86_64-linux-android
			run cargo clippy --target x86_64-linux-android -- -D warnings
		else
			log "skipping Android x86_64 cargo check; set RUN_ANDROID=1 to require it"
		fi
	)
else
	log "skipping Rust checks; set RUN_RUST=1 to enable"
fi

if [ "$RUN_DIFF_CHECK" = "1" ] && git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	run git -C "$ROOT" diff --check
fi

if [ "$RUN_WSA" = "1" ]; then
	run bash "$ROOT/scripts/kpm-x86-runtime-selftest.sh"
else
	log "skipping live WSA runtime self-test; set RUN_WSA=1 to enable"
fi

log "pass"
