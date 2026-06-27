#!/bin/sh
# shellcheck shell=sh
#
# run-scenario.sh - drive one odhcp6c integration scenario end-to-end.
#
# Usage:
#   run-scenario.sh [options] <scenario-name>
#   run-scenario.sh --list
#
# Options:
#   --odhcp6c <path>     odhcp6c binary under test (default: autodetect / $ODHCP6C_BIN)
#   --privsep <on|off>   when "off", prepend --no-privsep to scenario args; when "on",
#                        leave scenario args unchanged (default: ${HARNESS_PRIVSEP:-on})
#   --trace <mode>       none | strace | seccomp-log   (default: none)
#   --outdir <dir>       keep artifacts here (default: a fresh mktemp dir)
#   --keep               do not delete the work dir on exit
#   --timeout <seconds>  per-wait timeout (default: 30)
#   --list               list available scenarios and exit
#   -h, --help           show this help
#
# A scenario lives in scenarios/<name>/ and provides scenario.sh defining the
# shell functions below (each optional except scenario_drive):
#
#   scenario_backend     echo the backend + args, e.g. "scapy ra --prefix ..."
#                        (empty / unset => no server backend, RA-injection only)
#   scenario_setup       run AFTER the backend is up but BEFORE odhcp6c starts.
#                        Use for prerequisites the binary needs at startup (e.g.
#                        a ubusd instance a WITH_UBUS build connects to during
#                        init). Default: no-op.
#   scenario_odhcp6c     echo the odhcp6c argument list, ending in the interface
#                        (default: "<iface>"). Do NOT pin the privsep mode here;
#                        the --privsep axis controls it (see below).
#   scenario_drive       perform the lifecycle (waits, signals, injections) and
#                        leave captured records in $HARNESS_CAPTURE
#   scenario_assert      run assertions (default: assert against expect.txt)
#   scenario_teardown    tear down anything scenario_setup started (e.g. ubusd).
#                        Runs on every exit path (idempotent). Default: no-op.
#
# Exit status: 0 if the scenario completed and all assertions passed, non-zero
# otherwise. The driver never hangs: every wait is bounded by --timeout.

set -u

SELF="$(cd "$(dirname "$0")" && pwd)"
LIB="$SELF/lib"

# shellcheck disable=SC1091
. "$LIB/common.sh"
# shellcheck disable=SC1091
. "$LIB/assert.sh"
# shellcheck disable=SC1091
. "$LIB/trace.sh"

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

ODHCP6C_ARG=""
TRACE_MODE="none"
PRIVSEP="${HARNESS_PRIVSEP:-on}"
KEEP=0
SCENARIO=""

while [ $# -gt 0 ]; do
	case "$1" in
	--odhcp6c) ODHCP6C_ARG="$2"; shift 2 ;;
	--privsep) PRIVSEP="$2"; shift 2 ;;
	--privsep=*) PRIVSEP="${1#--privsep=}"; shift ;;
	--trace) TRACE_MODE="$2"; shift 2 ;;
	--trace=*) TRACE_MODE="${1#--trace=}"; shift ;;
	--outdir) HARNESS_OUTDIR="$2"; shift 2 ;;
	--keep) KEEP=1; shift ;;
	--timeout) HARNESS_TIMEOUT="$2"; shift 2 ;;
	--list)
		for d in "$SELF"/scenarios/*/; do
			[ -f "$d/scenario.sh" ] && basename "$d"
		done
		exit 0
		;;
	-h|--help) usage; exit 0 ;;
	-*) fatal "unknown option: $1" ;;
	*) SCENARIO="$1"; shift ;;
	esac
done

[ -n "$SCENARIO" ] || { usage; exit 1; }

# Normalise the privsep selection. "on" keeps the production default (privsep
# enabled); "off" forces --no-privsep. Accept a few friendly synonyms so the
# value can come straight from a CI env var.
case "$PRIVSEP" in
	on|yes|1|enabled|true)   PRIVSEP=on ;;
	off|no|0|disabled|false) PRIVSEP=off ;;
	*) fatal "invalid --privsep value: '$PRIVSEP' (expected on|off)" ;;
esac

SCN_DIR="$SELF/scenarios/$SCENARIO"
[ -f "$SCN_DIR/scenario.sh" ] || fatal "no such scenario: $SCENARIO ($SCN_DIR/scenario.sh missing)"

# Resolve paths and binary up front so we fail fast on misconfiguration.
harness_require_paths "$LIB" "$ODHCP6C_ARG"

# ---- default scenario hooks (overridable by scenario.sh) ----
scenario_backend()  { :; }
scenario_setup()    { :; }
scenario_teardown() { :; }
# Default to just the interface so the --privsep axis (below) is free to select
# the mode. Pinning --no-privsep here would defeat the both-modes CI matrix.
scenario_odhcp6c()  { echo "$HARNESS_VETH_CLIENT"; }
scenario_assert() {
	if [ -f "$SCN_DIR/expect.txt" ]; then
		harness_assert_expect "$SCN_DIR/expect.txt"
	else
		warn "scenario has no expect.txt and no scenario_assert(); nothing asserted"
	fi
}
scenario_drive() { fatal "scenario $SCENARIO does not define scenario_drive()"; }

# Source the scenario (may override the hooks above and read $SCN_DIR).
# shellcheck disable=SC1090
. "$SCN_DIR/scenario.sh"

# ---- run ----
trap 'scenario_teardown; harness_cleanup' EXIT INT TERM

harness_workdir_init
harness_set_trace "$TRACE_MODE" "$HARNESS_WORKDIR/trace"
harness_net_up

# Start the server/RA backend if the scenario declares one.
_backend_spec="$(scenario_backend)"
if [ -n "$_backend_spec" ]; then
	# shellcheck disable=SC2086
	harness_backend_start $_backend_spec
fi

# Scenario-specific prerequisites that must exist BEFORE odhcp6c starts (e.g. a
# ubusd a WITH_UBUS build connects to during init). Runs after the backend so it
# can depend on the network fabric being up.
scenario_setup

# Start odhcp6c with the scenario's arguments. When privsep is disabled, prepend
# --no-privsep so the same scenarios exercise the single-process path too. (If a
# scenario already passes --no-privsep itself, odhcp6c tolerates the duplicate.)
_odhcp6c_args="$(scenario_odhcp6c)"
[ "$PRIVSEP" = off ] && _odhcp6c_args="--no-privsep $_odhcp6c_args"
log "privsep: $PRIVSEP"
# shellcheck disable=SC2046,SC2086
harness_odhcp6c_start $_odhcp6c_args

# Drive the lifecycle.
RC=0
scenario_drive || RC=$?

# Stop odhcp6c so release-on-stop paths run before we assert.
harness_odhcp6c_stop
harness_backend_stop

# Post-process any syscall trace.
harness_trace_finalize || true

# Assert.
scenario_assert
harness_assert_summary || RC=1

# Persist a copy of the captured records + logs next to the scenario when an
# outdir was requested; otherwise leave them in the temp workdir.
log "artifacts in: $HARNESS_WORKDIR"
[ "$RC" -eq 0 ] && info "SCENARIO PASSED: $SCENARIO" || warn "SCENARIO FAILED: $SCENARIO (rc=$RC)"

# Clean the network fabric now; keep files unless --keep was given.
scenario_teardown
harness_cleanup
trap - EXIT INT TERM
if [ "$KEEP" = 0 ] && [ -z "${HARNESS_OUTDIR:-}" ]; then
	rm -rf "$HARNESS_WORKDIR"
fi

exit "$RC"
