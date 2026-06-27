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
HARNESS_ODHCP6C_EXIT=""   # propagated odhcp6c exit status (set by stop helpers)

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
	grep -q "^ACTION=$1\$" "$HARNESS_CAPTURE"/rec.* 2>/dev/null
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
		# Trace EVERY syscall (no -e trace= class filter): the seccomp
		# reconciliation must see the worker's complete syscall set, including
		# ones outside the network/desc/memory/signal/process classes (e.g.
		# futex, getrandom, the clock_* family, getuid/getpid). A class filter
		# here creates a blind spot -- a syscall the worker really issues but
		# strace never records -- which makes the reconciliation falsely report
		# the allow-list as complete while seccomp kills the worker at runtime.
		_pre="strace -f -ff -qq -o $HARNESS_TRACE_DIR/trace"
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

	# Environment the stub script reads, plus optional pass-throughs. The
	# seccomp diagnostic toggle (ODHCP6C_SECCOMP_DIAG) is forwarded explicitly
	# so it reaches the worker even when the harness runs via `sudo` (which
	# scrubs the ambient environment): with it set, a blocked syscall traps and
	# is logged instead of silently killing the worker. Empty by default => the
	# worker keeps its fail-closed SCMP_ACT_KILL_PROCESS behaviour.
	ODHCP6C_HARNESS_CAPTURE="$HARNESS_CAPTURE" \
	ODHCP6C_HARNESS_LOG="$HARNESS_WORKDIR/records.log" \
	$SUDO env \
		ODHCP6C_HARNESS_CAPTURE="$HARNESS_CAPTURE" \
		ODHCP6C_HARNESS_LOG="$HARNESS_WORKDIR/records.log" \
		ODHCP6C_SECCOMP_DIAG="${ODHCP6C_SECCOMP_DIAG:-}" \
		ip netns exec "$HARNESS_NS_CLIENT" \
		$_pre "$_cmd" -s "$HARNESS_STUB" -e "$@" \
		> "$HARNESS_WORKDIR/odhcp6c.stdout" \
		2> "$HARNESS_WORKDIR/odhcp6c.log" &
	HARNESS_ODHCP6C_PID=$!
	log "odhcp6c started (pid $HARNESS_ODHCP6C_PID, trace=$HARNESS_TRACE_MODE)"
}

# List the odhcp6c PIDs running inside the client netns. In privsep mode this is
# the monitor (privileged parent) and the worker (unprivileged child); otherwise
# it is the single process. Prints one PID per line.
harness_odhcp6c_pids() {
	# Enumerate the odhcp6c monitor AND worker without needing CAP_SYS_PTRACE.
	# The privsep worker calls PR_SET_DUMPABLE(0) and drops to an unprivileged
	# uid, which makes `ip netns pids` (it stats /proc/<pid>/ns/net, gated by
	# the ptrace access check) unable to see it from a root-but-no-SYS_PTRACE
	# container -- it would only ever return the monitor. Reading comm and the
	# monitor's children needs no ptrace, so seed from the netns members ip CAN
	# see (the monitor) and add its odhcp6c children (the worker). One PID per
	# line, de-duplicated so a ptrace-capable host that lists both still works.
	_pids=""
	for _pid in $($SUDO ip netns pids "$HARNESS_NS_CLIENT" 2>/dev/null); do
		_comm=$($SUDO cat "/proc/$_pid/comm" 2>/dev/null || true)
		# The privsep monitor/worker relabel comm via prctl(PR_SET_NAME)
		# to odhcp6c-monitor / odhcp6c-worker; a non-privsep build keeps
		# plain "odhcp6c". Accept all three.
		case "$_comm" in
		odhcp6c|odhcp6c-monitor|odhcp6c-worker) ;;
		*) continue ;;
		esac
		_pids="$_pids $_pid"
		for _kid in $($SUDO cat "/proc/$_pid/task/$_pid/children" 2>/dev/null); do
			_kcomm=$($SUDO cat "/proc/$_kid/comm" 2>/dev/null || true)
			case "$_kcomm" in
			odhcp6c|odhcp6c-monitor|odhcp6c-worker) _pids="$_pids $_kid" ;;
			esac
		done
	done
	for _p in $_pids; do printf '%s\n' "$_p"; done | sort -un
}

# Print the parent PID of a process. Reads /proc/<pid>/status so a comm containing
# spaces or parentheses cannot confuse field splitting.
_harness_ppid() {
	# shellcheck disable=SC2016  # $2 is an awk field, not a shell variable
	$SUDO awk '/^PPid:/ { print $2 }' "/proc/$1/status" 2>/dev/null
}

# Resolve the PID of a privsep role: "monitor" (the privileged parent that owns
# signal forwarding/translation -- src/script_monitor.c monitor_sighandle) or "worker"
# (the unprivileged child running the DHCPv6 state machine). The worker is the
# odhcp6c process whose parent is itself an odhcp6c process; the monitor is the
# one whose parent is not. In single-process (non-privsep) mode both roles
# collapse to the one PID. Prints the resolved PID, or nothing if none is found.
harness_odhcp6c_role_pid() {
	_role="$1"
	_pids=$(harness_odhcp6c_pids)
	[ -n "$_pids" ] || return 0

	_monitor=""
	_worker=""
	for _p in $_pids; do
		_pp=$(_harness_ppid "$_p")
		_parent_is_odhcp6c=0
		for _q in $_pids; do
			[ "$_pp" = "$_q" ] && { _parent_is_odhcp6c=1; break; }
		done
		if [ "$_parent_is_odhcp6c" = 1 ]; then
			_worker="$_p"
		else
			_monitor="$_p"
		fi
	done

	# Single-process mode (or an unresolved race): collapse the roles.
	[ -n "$_worker" ]  || _worker="$_monitor"
	[ -n "$_monitor" ] || _monitor="$_worker"

	case "$_role" in
	monitor) printf '%s\n' "$_monitor" ;;
	worker)  printf '%s\n' "$_worker" ;;
	*) fatal "harness_odhcp6c_role_pid: role must be monitor|worker" ;;
	esac
}

# True when the monitor and worker are distinct processes, i.e. privsep is
# actually active. Lets a scenario prove it isolated the monitor path rather than
# silently degrading to single-process signalling.
harness_odhcp6c_privsep_active() {
	_m=$(harness_odhcp6c_role_pid monitor)
	_w=$(harness_odhcp6c_role_pid worker)
	[ -n "$_m" ] && [ -n "$_w" ] && [ "$_m" != "$_w" ]
}

# [privsep-debug] Dump enough state to separate the single-process causes:
# (A) privsep not compiled in, (B) compiled in but not euid 0 at runtime, or
# (C) forked but the detector missed the worker. Remove once confirmed.
harness_dump_privsep_state() {
	info "[privsep-debug] netns=$HARNESS_NS_CLIENT odhcp6c processes:"
	_any=0
	for _p in $(harness_odhcp6c_pids); do
		_any=1
		_ppid=$(_harness_ppid "$_p")
		# shellcheck disable=SC2016  # $2..$5 are awk fields, not shell vars
		_uids=$($SUDO awk '/^Uid:/ { print $2" "$3" "$4" "$5 }' "/proc/$_p/status" 2>/dev/null)
		info "[privsep-debug]   pid=$_p ppid=$_ppid uid(r e s fs)=$_uids"
	done
	[ "$_any" = 1 ] || info "[privsep-debug]   (no odhcp6c pids in netns)"
	info "[privsep-debug] resolved monitor=$(harness_odhcp6c_role_pid monitor) worker=$(harness_odhcp6c_role_pid worker)"
	_olog="$HARNESS_WORKDIR/odhcp6c.log"
	_pat='privsep|single-process|socketpair|not running as root|drop privile|seccomp'
	if [ -f "$_olog" ] && grep -niE "$_pat" "$_olog" >/dev/null 2>&1; then
		info "[privsep-debug] odhcp6c.log privsep lines:"
		grep -niE "$_pat" "$_olog" 2>/dev/null | while IFS= read -r _ln; do
			info "[privsep-debug]   $_ln"
		done
	else
		info "[privsep-debug] odhcp6c.log: no privsep-related lines"
	fi
}

# Send a signal to odhcp6c (monitor + worker). Used by the generic lifecycle and
# by scenarios that do not care which process reacts.
harness_odhcp6c_signal() {
	_sig="$1"
	[ -n "$HARNESS_ODHCP6C_PID" ] || return 0
	# In privsep mode SIGUSR1/SIGUSR2 are handled by the worker while the monitor
	# can ignore them, so signal all odhcp6c PIDs inside the client netns.
	_sent=0
	for _pid in $(harness_odhcp6c_pids); do
		$SUDO kill "-$_sig" "$_pid" 2>/dev/null || true
		_sent=1
	done

	# Fallback for early startup/teardown windows where the netns PID scan is empty.
	[ "$_sent" -eq 1 ] || $SUDO kill "-$_sig" "$HARNESS_ODHCP6C_PID" 2>/dev/null || true
}

# Send a signal to ONLY one privsep role (monitor|worker). Real init systems
# signal the launcher (monitor) PID, so targeting the monitor in privsep mode
# exercises the monitor's signal forwarding/translation path in isolation --
# something the broadcast harness_odhcp6c_signal cannot do because it also hits
# the worker directly.
harness_odhcp6c_signal_role() {
	_role="$1"; _sig="$2"
	_target=$(harness_odhcp6c_role_pid "$_role")
	if [ -z "$_target" ]; then
		warn "no $_role PID resolved; cannot send SIG$_sig"
		return 1
	fi
	# Report the real delivery result so callers can detect a failed signal
	# (PID already exited, EPERM, ...) instead of a swallowed `|| true`.
	if $SUDO kill "-$_sig" "$_target" 2>/dev/null; then
		log "sent SIG$_sig to $_role (pid $_target)"
		return 0
	fi
	warn "failed to send SIG$_sig to $_role (pid $_target)"
	return 1
}

harness_odhcp6c_running() {
	[ -n "$HARNESS_ODHCP6C_PID" ] || return 1
	kill -0 "$HARNESS_ODHCP6C_PID" 2>/dev/null
}

# Wait (bounded) for the whole odhcp6c process tree to leave the client netns,
# then reap the launcher and record its propagated exit status in
# HARNESS_ODHCP6C_EXIT. The launcher PID can linger as a zombie until we wait(),
# so termination is detected by polling the netns for live odhcp6c processes
# rather than kill -0 on the (possibly zombie) launcher.
_harness_odhcp6c_reap() {
	_deadline=$(( $(date +%s) + ${1:-8} ))
	while [ -n "$(harness_odhcp6c_pids)" ]; do
		[ "$(date +%s)" -ge "$_deadline" ] && break
		sleep 0.2
	done
	if [ -n "$(harness_odhcp6c_pids)" ]; then
		warn "odhcp6c still alive after grace period; hard-killing"
		harness_odhcp6c_signal KILL
	fi
	wait "$HARNESS_ODHCP6C_PID" 2>/dev/null
	HARNESS_ODHCP6C_EXIT=$?
	HARNESS_ODHCP6C_PID=""
}

# Gracefully stop odhcp6c by signalling ONLY the privsep monitor (SIGTERM to the
# monitor PID), then reap and capture the propagated exit status. In privsep mode
# this drives the monitor's TERM->worker-SIGTERM translation and proves the
# monitor faithfully reports the worker's exit status (the SIGCHLD/worker-pid race
# fix). Clears HARNESS_ODHCP6C_PID so the subsequent generic stop is a no-op and
# does not clobber HARNESS_ODHCP6C_EXIT.
harness_odhcp6c_stop_monitor() {
	[ -n "$HARNESS_ODHCP6C_PID" ] || return 0
	harness_odhcp6c_signal_role monitor TERM \
		|| warn "monitor-only SIGTERM delivery failed; relying on reap fallback"
	_harness_odhcp6c_reap 8
	log "monitor stop: odhcp6c exit status $HARNESS_ODHCP6C_EXIT"
}

# Abnormally kill ONLY the privsep worker (default SIGKILL, uncatchable) to
# simulate a worker crash, then reap the launcher and capture the propagated
# exit status in HARNESS_ODHCP6C_EXIT. This is the failure-path counterpart to
# harness_odhcp6c_stop_monitor: in privsep mode the monitor must SURVIVE the
# worker's death, observe it, clean up, and exit non-zero (the monitor loop
# returns 1 for a worker that did not exit normally -- src/script_monitor.c
# script_monitor_loop), WITHOUT the worker having had a chance to send a
# graceful RELEASE. In single-process (non-privsep) mode the role resolver
# targets the sole process, so this kills it directly (wait reports 128+signal).
# Clears HARNESS_ODHCP6C_PID so run-scenario.sh's later stop is a no-op and does
# not clobber HARNESS_ODHCP6C_EXIT.
harness_odhcp6c_kill_worker() {
	[ -n "$HARNESS_ODHCP6C_PID" ] || return 0
	_sig="${1:-KILL}"
	harness_odhcp6c_signal_role worker "$_sig" \
		|| warn "worker SIG$_sig delivery failed; relying on reap fallback"
	_harness_odhcp6c_reap 8
	log "worker abnormal-kill (SIG$_sig): odhcp6c exit status $HARNESS_ODHCP6C_EXIT"
}

# Stop odhcp6c gracefully (SIGTERM to the whole tree), then hard-kill if needed.
# Captures the propagated exit status in HARNESS_ODHCP6C_EXIT.
harness_odhcp6c_stop() {
	[ -n "$HARNESS_ODHCP6C_PID" ] || return 0
	harness_odhcp6c_signal TERM
	_harness_odhcp6c_reap 5
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
