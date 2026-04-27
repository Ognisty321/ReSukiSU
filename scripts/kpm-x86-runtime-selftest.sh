#!/usr/bin/env bash
set -euo pipefail

ADB="${ADB:-adb}"
ADB_TARGET="${ADB_TARGET:-127.0.0.1:58526}"
REMOTE_DIR="${REMOTE_DIR:-/data/adb/kpm}"
KSUD="${KSUD:-/data/adb/ksud}"
LOCAL_OUT="${LOCAL_OUT:-examples/kpm-x86_64/out}"
CONTROL_LOOPS="${CONTROL_LOOPS:-50}"
DMESG_SCAN="${DMESG_SCAN:-1}"

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_FILES=()

log() {
	printf '[kpm-x86-selftest] %s\n' "$*"
}

cleanup_all() {
	if [ "${#TMP_FILES[@]}" -gt 0 ]; then
		rm -f "${TMP_FILES[@]}"
	fi
	if declare -f cleanup_known_modules >/dev/null; then
		cleanup_known_modules
	fi
}

adb_shell() {
	"$ADB" shell "$@"
}

adb_su() {
	adb_shell "su -M -c \"$*\""
}

push_kpm() {
	local name="$1"
	local local_file="$ROOT/$LOCAL_OUT/$name.kpm"
	local tmp_file="/data/local/tmp/$name.kpm"

	if [ ! -f "$local_file" ]; then
		log "building example corpus"
		"$ROOT/scripts/build-kpm-x86_64.sh"
	fi

	adb_su "mkdir -p '$REMOTE_DIR' && chmod 700 '$REMOTE_DIR'"
	"$ADB" push "$local_file" "$tmp_file" >/dev/null
	adb_su "cp '$tmp_file' '$REMOTE_DIR/$name.kpm' && chmod 600 '$REMOTE_DIR/$name.kpm'"
}

cleanup_known_modules() {
	local name

	for name in control_owner control_kpm hotpatch fp_hook inline_hook failure_cases hello_kpm_x86_64; do
		if [ "$name" = "control_owner" ]; then
			adb_su "$KSUD kpm control '$name' cleanup" >/dev/null 2>&1 || true
		fi
		if [ "$name" = "failure_cases" ]; then
			adb_su "$KSUD kpm control '$name' allow-exit" >/dev/null 2>&1 || true
		fi
		adb_su "$KSUD kpm unload '$name'" >/dev/null 2>&1 || true
		adb_su "rm -f '$REMOTE_DIR/$name.kpm'" >/dev/null 2>&1 || true
	done
}

load_unload() {
	local name="$1"
	local path="$REMOTE_DIR/$name.kpm"

	log "load $name"
	adb_su "$KSUD kpm load '$path'"
	log "audit $name"
	adb_su "$KSUD kpm audit --json"
	log "unload $name"
	adb_su "$KSUD kpm unload '$name'"
}

log "connecting to $ADB_TARGET"
"$ADB" connect "$ADB_TARGET" >/dev/null || true
"$ADB" wait-for-device

log "doctor"
adb_su "$KSUD kpm doctor --json"
cleanup_known_modules
trap cleanup_all EXIT
DMESG_START_LINE="$(adb_su "dmesg | wc -l" | tr -dc '0-9')"

push_kpm inline_hook
load_unload inline_hook

push_kpm fp_hook
load_unload fp_hook

push_kpm hotpatch
load_unload hotpatch

push_kpm failure_cases
log "load failure_cases"
adb_su "$KSUD kpm load '$REMOTE_DIR/failure_cases.kpm'"
log "expect failure_cases unload refusal"
if adb_su "$KSUD kpm unload failure_cases" >/dev/null 2>&1; then
	log "failure_cases unload unexpectedly succeeded"
	exit 1
fi
adb_su "$KSUD kpm info failure_cases" >/dev/null
log "allow failure_cases unload"
adb_su "$KSUD kpm control failure_cases allow-exit"
adb_su "$KSUD kpm unload failure_cases"

push_kpm control_owner
log "load control_owner"
adb_su "$KSUD kpm load '$REMOTE_DIR/control_owner.kpm'"
log "install control-owned fp hook"
adb_su "$KSUD kpm control control_owner install"
log "expect control_owner unload refusal while hook is owned"
if adb_su "$KSUD kpm unload control_owner" >/dev/null 2>&1; then
	log "control_owner unload unexpectedly succeeded with an owned hook"
	exit 1
fi
adb_su "$KSUD kpm info control_owner" >/dev/null
log "cleanup control-owned fp hook"
adb_su "$KSUD kpm control control_owner cleanup"
adb_su "$KSUD kpm unload control_owner"

push_kpm control_kpm
log "load control_kpm for unload race"
adb_su "$KSUD kpm load '$REMOTE_DIR/control_kpm.kpm'"
log "control/unload race"
for _ in $(seq 1 "$CONTROL_LOOPS"); do
	adb_su "$KSUD kpm control control_kpm ping" >/dev/null 2>&1 &
done
adb_su "$KSUD kpm unload control_kpm" || true
wait || true
if adb_su "$KSUD kpm info control_kpm" >/dev/null 2>&1; then
	adb_su "$KSUD kpm unload control_kpm"
fi

log "final audit"
adb_su "$KSUD kpm audit --json"
final_num="$(adb_su "$KSUD kpm num" | tr -dc '0-9')"
printf '%s\n' "$final_num"
if [ "$final_num" != "0" ]; then
	log "expected zero loaded KPM modules, got $final_num"
	exit 1
fi

if [ "$DMESG_SCAN" = "1" ]; then
	log "dmesg scan for text_poke/ROX/WX/race failures"
	tmp="$(mktemp)"
	TMP_FILES+=("$tmp")
	adb_su "dmesg" | tail -n +"$((DMESG_START_LINE + 1))" >"$tmp"
	if grep -Eai 'BUG:|WARNING:|Oops|general protection fault|invalid opcode|KASAN|KCSAN|KFENCE|DEBUG_WX|W\+X|W\^X|writable.*executable|text_poke.*(fail|warn|bug|oops|invalid|error)|lockdep|use-after-free' "$tmp"; then
		log "kernel log contains a failure marker"
		exit 1
	fi
fi

log "pass"
