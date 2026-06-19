#!/bin/sh
# shellcheck shell=sh
#
# common.sh - shared helpers for the odhcp6c integration harness.
#
# Provides:
#   * logging + bounded waiting helpers
#   * hermetic network setup (two netns joined by a veth pair)
#   * odhcp6c lifecycle management (start / signal / stop) with trace hooks
#   * server-backend launch/teardown
#
# Everything is POSIX sh so it runs under Alpine's BusyBox ash as well as bash.
#
# This file is sourced; it never runs anything on its own.

# ---------------------------------------------------------------------------
# Configuration (overridable by the environment / run-scenario.sh)
# ---------------------------------------------------------------------------

: "${HARNESS_NS_CLIENT:=odhcp6c-ns}"   # netns running the binary under test
: "${HARNESS_NS_SERVER:=server-ns}"    # netns running the server/RA backend
: "${HARNESS_VETH_CLIENT:=veth0}"      # client-side veth (odhcp6c binds this)
: "${HARNESS_VETH_SERVER:=veth1}"      # server-side veth (backend binds this)
: "${HARNESS_TIMEOUT:=30}"             # default bound on any single wait (s)

# Filled in by harness_require_paths().
HARNESS_ODHCP6C=""
HARNESS_STUB=""
HARNESS_LIB_DIR=""
HARNESS_ROOT=""

# Runtime state (set by helpers below).
HARNESS_WORKDIR=""
HARNESS_CAPTURE=""
HARNESS_ODHCP6C_PID=""
HARNESS_BACKEND_PID=""
HARNESS_TRACE_MODE="none"
HARNESS_TRACE_DIR=""

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log()   { printf '[harness] %s\n' "$*" >&2; }
info()  { printf '[harness] %s\n' "$*" >&2; }
warn()  { printf '[harness][warn] %s\n' "$*" >&2; }
fatal() { printf '[harness][FATAL] %s\n' "$*" >&2; exit 1; }

# Run a command in the client netns (the binary-under-test side).
ns_client() { ip netns exec "$HARNESS_NS_CLIENT" "$@"; }
# Run a command in the server netns (the backend side).
ns_server() { ip netns exec "$HARNESS_NS_SERVER" "$@"; }

# Are we root? netns/veth manipulation requires CAP_NET_ADMIN.
harness_have_priv() {
	[ "$(id -u)" = "0" ]
}

# Wrapper so the harness works both as root and via sudo on a dev box.
SUDO=""
harness_pick_sudo() {
	if harness_have_priv; then
		SUDO=""
	elif command -v sudo >/dev/null 2>&1; then
		SUDO="sudo"
	else
		fatal "need root (or sudo) for network-namespace setup"
	fi
}

# ---------------------------------------------------------------------------
# Bounded waiting (determinism: never sleep blindly, always cap with a timeout)
# ---------------------------------------------------------------------------

# wait_for <timeout_s> <description> <shell-condition...>
# Polls the condition every 0.25s until it succeeds or the timeout elapses.
wait_for() {
	_wf_timeout="$1"; shift
	_wf_desc="$1"; shift
	_wf_deadline=$(( $(date +%s) + _wf_timeout ))
	while :; do
		if "$@"; then
			return 0
		fi
		if [ "$(date +%s)" -ge "$_wf_deadline" ]; then
			warn "timed out after ${_wf_timeout}s waiting for: ${_wf_desc}"
			return 1
		fi
		sleep 0.25
	done
}

# Convenience: wait until a record with the given ACTION has been captured.
wait_for_action() {
	_wfa_action="$1"
	_wfa_timeout="${2:-$HARNESS_TIMEOUT}"
	wait_for "$_wfa_timeout" "status action '$_wfa_action'" \
		harness_has_action "$_wfa_action"
}

harness_has_action() {
	[ -n "$HARNESS_CAPTURE" ] || return 1
	grep -lq "^ACTION=$1\$" "$HARNESS_CAPTURE"/rec.* 2>/dev/null
}

# Wait until a log line matching the extended regex appears. An optional third
# argument requires at least that many matching lines (default 1) -- useful to
# wait for a line that recurs (e.g. a second "(re)starting transaction").
wait_for_log() {
	_wfl_re="$1"
	_wfl_timeout="${2:-$HARNESS_TIMEOUT}"
	_wfl_count="${3:-1}"
	wait_for "$_wfl_timeout" "log line /$_wfl_re/ x$_wfl_count" \
		_wait_for_log_count "$_wfl_re" "$_wfl_count"
}

_wait_for_log_count() {
	_c=$(grep -Ec "$1" "$HARNESS_WORKDIR/odhcp6c.log" 2>/dev/null || echo 0)
	[ "${_c:-0}" -ge "$2" ]
}

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

# harness_require_paths <lib_dir> <odhcp6c_binary>
harness_require_paths() {
	HARNESS_LIB_DIR="$1"
	HARNESS_ROOT="$(cd "$HARNESS_LIB_DIR/.." && pwd)"
	HARNESS_STUB="$HARNESS_ROOT/stub-script.sh"

	HARNESS_ODHCP6C="${2:-${ODHCP6C_BIN:-}}"
	if [ -z "$HARNESS_ODHCP6C" ]; then
		# Try common build locations relative to the repo root.
		for c in \
			"$HARNESS_ROOT/../../build/odhcp6c" \
			"$HARNESS_ROOT/../../build/odhcp6c-without-ubus/odhcp6c" \
			"$(command -v odhcp6c 2>/dev/null)"; do
			if [ -n "$c" ] && [ -x "$c" ]; then
				HARNESS_ODHCP6C="$c"
				break
			fi
		done
	fi
	[ -n "$HARNESS_ODHCP6C" ] && [ -x "$HARNESS_ODHCP6C" ] || \
		fatal "odhcp6c binary not found (set ODHCP6C_BIN or pass --odhcp6c)"
	[ -x "$HARNESS_STUB" ] || fatal "stub script not executable: $HARNESS_STUB"
	log "odhcp6c: $HARNESS_ODHCP6C"
}

# ---------------------------------------------------------------------------
# Network fabric: two netns + a veth pair, link-local addressing only.
# ---------------------------------------------------------------------------

harness_net_up() {
	harness_pick_sudo
	harness_net_down >/dev/null 2>&1 || true

	$SUDO ip netns add "$HARNESS_NS_CLIENT" || fatal "cannot create client netns"
	$SUDO ip netns add "$HARNESS_NS_SERVER" || fatal "cannot create server netns"

	$SUDO ip link add "$HARNESS_VETH_CLIENT" netns "$HARNESS_NS_CLIENT" \
		type veth peer name "$HARNESS_VETH_SERVER" netns "$HARNESS_NS_SERVER" \
		|| fatal "cannot create veth pair"

	for pair in "$HARNESS_NS_CLIENT $HARNESS_VETH_CLIENT" \
	            "$HARNESS_NS_SERVER $HARNESS_VETH_SERVER"; do
		# shellcheck disable=SC2086
		set -- $pair
		_ns="$1"; _if="$2"
		$SUDO ip netns exec "$_ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 2>/dev/null || true
		$SUDO ip netns exec "$_ns" sysctl -qw "net.ipv6.conf.$_if.disable_ipv6=0" 2>/dev/null || true
		# Disable DAD so the link-local address is usable immediately and
		# deterministically (no random DAD delay in CI).
		$SUDO ip netns exec "$_ns" sysctl -qw "net.ipv6.conf.$_if.accept_dad=0" 2>/dev/null || true
		$SUDO ip netns exec "$_ns" ip link set lo up
		$SUDO ip netns exec "$_ns" ip link set "$_if" up
	done

	# Wait until both ends have a usable (non-tentative) link-local address.
	wait_for "$HARNESS_TIMEOUT" "client link-local address" \
		_harness_has_lla "$HARNESS_NS_CLIENT" "$HARNESS_VETH_CLIENT" \
		|| fatal "client veth never got a link-local address"
	wait_for "$HARNESS_TIMEOUT" "server link-local address" \
		_harness_has_lla "$HARNESS_NS_SERVER" "$HARNESS_VETH_SERVER" \
		|| fatal "server veth never got a link-local address"

	log "network up: $HARNESS_NS_CLIENT/$HARNESS_VETH_CLIENT <-> $HARNESS_NS_SERVER/$HARNESS_VETH_SERVER"
}

_harness_has_lla() {
	$SUDO ip netns exec "$1" ip -6 addr show dev "$2" scope link 2>/dev/null \
		| grep -q "inet6 fe80::" || return 1
	# Reject tentative addresses (would fail sends).
	! $SUDO ip netns exec "$1" ip -6 addr show dev "$2" scope link 2>/dev/null \
		| grep -q "tentative"
}

# Link-local address of a given side, e.g. harness_lla client / harness_lla server.
harness_lla() {
	case "$1" in
	client) _ns="$HARNESS_NS_CLIENT"; _if="$HARNESS_VETH_CLIENT" ;;
	server) _ns="$HARNESS_NS_SERVER"; _if="$HARNESS_VETH_SERVER" ;;
	*) fatal "harness_lla: side must be client|server" ;;
	esac
	$SUDO ip netns exec "$_ns" ip -6 addr show dev "$_if" scope link 2>/dev/null \
		| awk '/inet6/ {print $2}' | cut -d/ -f1 | head -1
}

harness_net_down() {
	[ -n "$SUDO" ] || harness_pick_sudo
	$SUDO ip netns del "$HARNESS_NS_CLIENT" 2>/dev/null || true
	$SUDO ip netns del "$HARNESS_NS_SERVER" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Work directory + capture directory
# ---------------------------------------------------------------------------

harness_workdir_init() {
	HARNESS_WORKDIR="${HARNESS_OUTDIR:-$(mktemp -d /tmp/odhcp6c-harness.XXXXXX)}"
	mkdir -p "$HARNESS_WORKDIR"
	HARNESS_CAPTURE="$HARNESS_WORKDIR/capture"
	mkdir -p "$HARNESS_CAPTURE"
	# The privsep worker may exec the stub as an unprivileged user, so the
	# capture dir must be world-writable.
	chmod 0777 "$HARNESS_CAPTURE"
	: > "$HARNESS_WORKDIR/odhcp6c.log"
	log "workdir: $HARNESS_WORKDIR"
}

# ---------------------------------------------------------------------------
# Server/RA backend management (delegated to lib/backend_*.sh)
# ---------------------------------------------------------------------------

# harness_backend_start <backend> [args...]
harness_backend_start() {
	_be="$1"; shift
	_be_lib="$HARNESS_LIB_DIR/backend_${_be}.sh"
	[ -f "$_be_lib" ] || fatal "unknown backend: $_be (no $_be_lib)"
	# shellcheck disable=SC1090
	. "$_be_lib"
	backend_start "$@"
}

harness_backend_stop() {
	if command -v backend_stop >/dev/null 2>&1; then
		backend_stop || true
	fi
	if [ -n "$HARNESS_BACKEND_PID" ]; then
		kill "$HARNESS_BACKEND_PID" 2>/dev/null || true
		HARNESS_BACKEND_PID=""
	fi
}

# ---------------------------------------------------------------------------
# odhcp6c lifecycle
# ---------------------------------------------------------------------------

# harness_set_trace <none|strace|seccomp-log> [trace_dir]
harness_set_trace() {
	HARNESS_TRACE_MODE="$1"
	HARNESS_TRACE_DIR="${2:-$HARNESS_WORKDIR/trace}"
	[ "$HARNESS_TRACE_MODE" = "none" ] || mkdir -p "$HARNESS_TRACE_DIR"
}

# harness_odhcp6c_start <odhcp6c-args...>
# Always appends the interface name (caller passes only options) -- callers pass
# the full argument list including the interface as the final argument.
harness_odhcp6c_start() {
	_cmd="$HARNESS_ODHCP6C"
	_pre=""

	case "$HARNESS_TRACE_MODE" in
	strace)
		# Follow forks (-f) so BOTH privsep processes (monitor + worker) are
		# traced; -ff writes one file per pid; -qq quiets attach/exit noise.
		_pre="strace -f -ff -qq -e trace=%network,%desc,%memory,%signal,%process -o $HARNESS_TRACE_DIR/trace"
		;;
	seccomp-log)
		# Snapshot dmesg position so we can scrape only new SECCOMP records.
		if command -v dmesg >/dev/null 2>&1; then
			$SUDO dmesg 2>/dev/null | wc -l > "$HARNESS_TRACE_DIR/dmesg.mark" || \
				echo 0 > "$HARNESS_TRACE_DIR/dmesg.mark"
		else
			echo 0 > "$HARNESS_TRACE_DIR/dmesg.mark"
		fi
		;;
	none) : ;;
	*) fatal "unknown trace mode: $HARNESS_TRACE_MODE" ;;
	esac

	# Environment the stub script reads.
	ODHCP6C_HARNESS_CAPTURE="$HARNESS_CAPTURE" \
	ODHCP6C_HARNESS_LOG="$HARNESS_WORKDIR/records.log" \
	$SUDO env \
		ODHCP6C_HARNESS_CAPTURE="$HARNESS_CAPTURE" \
		ODHCP6C_HARNESS_LOG="$HARNESS_WORKDIR/records.log" \
		ip netns exec "$HARNESS_NS_CLIENT" \
		$_pre "$_cmd" -s "$HARNESS_STUB" -e "$@" \
		> "$HARNESS_WORKDIR/odhcp6c.stdout" \
		2> "$HARNESS_WORKDIR/odhcp6c.log" &
	HARNESS_ODHCP6C_PID=$!
	log "odhcp6c started (pid $HARNESS_ODHCP6C_PID, trace=$HARNESS_TRACE_MODE)"
}

# Send a signal to the odhcp6c process group (covers monitor + worker).
harness_odhcp6c_signal() {
	_sig="$1"
	[ -n "$HARNESS_ODHCP6C_PID" ] || return 0
	# We started via sudo/ip-netns, so signal the whole subtree by name within
	# the client netns is fragile; instead signal the launched pid and let the
	# monitor forward to the worker (odhcp6c does this for SIGTERM).
	$SUDO kill "-$_sig" "$HARNESS_ODHCP6C_PID" 2>/dev/null || true
}

harness_odhcp6c_running() {
	[ -n "$HARNESS_ODHCP6C_PID" ] || return 1
	kill -0 "$HARNESS_ODHCP6C_PID" 2>/dev/null
}

# Stop odhcp6c gracefully (SIGTERM), then hard-kill if needed.
harness_odhcp6c_stop() {
	[ -n "$HARNESS_ODHCP6C_PID" ] || return 0
	harness_odhcp6c_signal TERM
	# Give it a bounded grace period to run the release + stopped script.
	_deadline=$(( $(date +%s) + 5 ))
	while harness_odhcp6c_running; do
		[ "$(date +%s)" -ge "$_deadline" ] && break
		sleep 0.2
	done
	harness_odhcp6c_running && harness_odhcp6c_signal KILL
	wait "$HARNESS_ODHCP6C_PID" 2>/dev/null || true
	HARNESS_ODHCP6C_PID=""
}

# ---------------------------------------------------------------------------
# Teardown (idempotent; safe to call from a trap)
# ---------------------------------------------------------------------------

harness_cleanup() {
	harness_odhcp6c_stop
	harness_backend_stop
	harness_net_down
}

# ---------------------------------------------------------------------------
# One-shot crafted-packet injection (for edge-case sub-phases inside a drive).
# ---------------------------------------------------------------------------

# harness_inject <scapy-subcommand-and-args...>
# Runs the scapy server in one-shot mode in the server netns and waits for it to
# finish. Use a finite --count so it returns. Example:
#   harness_inject ra --count 3 --hoplimit 1 --prefix 2001:db8:dead::
harness_inject() {
	_srv="$HARNESS_ROOT/servers/scapy_server.py"
	[ -f "$_srv" ] || fatal "scapy server not found: $_srv"
	$SUDO ip netns exec "$HARNESS_NS_SERVER" \
		"${PYTHON:-python3}" "$_srv" --iface "$HARNESS_VETH_SERVER" "$@" \
		>> "$HARNESS_WORKDIR/inject.log" 2>&1
}
