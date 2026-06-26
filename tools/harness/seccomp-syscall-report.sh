#!/usr/bin/env bash
#
# seccomp-syscall-report.sh - reconcile the worker seccomp allow-list against
# syscalls actually observed in strace traces.
#
# Given the checked-in worker allow-list (src/seccomp.c) and one or more harness
# trace directories captured with `run-scenario.sh --trace=strace --outdir`,
# this isolates the unprivileged privsep WORKER process in each trace and
# reports, over the union of all supplied traces:
#
#   * every syscall the worker issued,
#   * syscalls the worker used that are NOT in seccomp_allow[] -- i.e. the gap
#     that the real fail-closed filter (SCMP_ACT_KILL_PROCESS) would kill on,
#   * ioctl request commands the worker used that are NOT permitted by the
#     seccomp_ioctl_allow[] argument filter.
#
# It is purely diagnostic: it modifies nothing and exits 0 even when a gap is
# found (the gap is printed for a human / CI to act on). Pass --strict as the
# first argument to exit non-zero when a gap is found.
#
# The worker is identified structurally rather than by name: in privilege-
# separated mode it is the process that does DHCPv6 socket I/O (socket +
# recvmsg/recvfrom) but never forks or execs -- all process creation lives in
# the monitor, and the script children exec `sh`. That heuristic uniquely
# picks the confined worker out of the monitor + script-child traces.
#
# Usage:
#   seccomp-syscall-report.sh [--strict] <seccomp.c> <trace-dir>...
#
# Each <trace-dir> contains a trace/ subdir with syscalls.<pid>.txt and raw
# trace.<pid> files (a run-scenario.sh --trace=strace --outdir target).

set -eu

STRICT=0
if [ "${1:-}" = "--strict" ]; then
	STRICT=1
	shift
fi

if [ "$#" -lt 2 ]; then
	echo "usage: seccomp-syscall-report.sh [--strict] <seccomp.c> <trace-dir>..." >&2
	exit 2
fi

SECCOMP_SRC="$1"
shift

if [ ! -f "$SECCOMP_SRC" ]; then
	echo "error: seccomp source not found: $SECCOMP_SRC" >&2
	exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# --- 1. allow-list, extracted from the source of truth ----------------------
grep -oE 'SCMP_SYS\([a-z0-9_]+\)' "$SECCOMP_SRC" \
	| sed -E 's/SCMP_SYS\(([a-z0-9_]+)\)/\1/' \
	| sort -u > "$tmp/allow.syscalls"

# ioctl request tokens from inside the seccomp_ioctl_allow[] initializer only
# (so comments elsewhere in the file do not widen the permitted set).
awk '
	/seccomp_ioctl_allow\[\]/ { inblk = 1 }
	inblk { print }
	inblk && /};/             { inblk = 0 }
' "$SECCOMP_SRC" | grep -oE 'SIOC[A-Z0-9_]+' | sort -u > "$tmp/allow.ioctls"

# --- 2. isolate the worker in each trace and collect its syscalls -----------
is_worker() {  # $1 = path to syscalls.<pid>.txt
	grep -qxE 'recvmsg|recvfrom' "$1" \
		&& grep -qx socket "$1" \
		&& ! grep -qxE 'execve|fork|vfork|clone|wait4' "$1"
}

: > "$tmp/worker.syscalls"
: > "$tmp/worker.ioctls"
: > "$tmp/worker.pids"

for root in "$@"; do
	[ -e "$root" ] || continue
	while IFS= read -r f; do
		is_worker "$f" || continue
		pid="${f##*/syscalls.}"
		pid="${pid%.txt}"
		echo "$(dirname "$f")|$pid" >> "$tmp/worker.pids"
		cat "$f" >> "$tmp/worker.syscalls"
		# Pull decoded ioctl request commands from the raw trace for this pid:
		#   ioctl(7, SIOCGIFINDEX, 0x...) = 0   ->  SIOCGIFINDEX
		# A numeric command (0x8933) means strace could not decode it.
		raw="$(dirname "$f")/trace.$pid"
		if [ -f "$raw" ]; then
			grep -hoE 'ioctl\([0-9]+, [A-Za-z0-9_]+' "$raw" 2>/dev/null \
				| sed -E 's/.*, //' >> "$tmp/worker.ioctls" || true
		fi
	done <<EOF
$(find "$root" -type f -name 'syscalls.*.txt' ! -name 'syscalls.union.txt' 2>/dev/null)
EOF
done

sort -u "$tmp/worker.syscalls" > "$tmp/worker.syscalls.u"
sort -u "$tmp/worker.ioctls"  > "$tmp/worker.ioctls.u"
comm -23 "$tmp/worker.syscalls.u" "$tmp/allow.syscalls" > "$tmp/missing.syscalls"
comm -23 "$tmp/worker.ioctls.u"  "$tmp/allow.ioctls"   > "$tmp/missing.ioctls"

# --- 3. report --------------------------------------------------------------
nworker_pid=$(wc -l < "$tmp/worker.pids" | tr -d ' ')
nsys=$(wc -l < "$tmp/worker.syscalls.u" | tr -d ' ')

echo "== worker seccomp syscall reconciliation =="
echo "allow-list source : $SECCOMP_SRC"
echo "trace roots       : $*"
echo "worker processes  : $nworker_pid identified"
echo

if [ "$nworker_pid" -eq 0 ]; then
	echo "WARNING: no privsep worker process was identified in the supplied"
	echo "traces (need socket + recvmsg/recvfrom and no fork/execve). Was the"
	echo "scenario run with privsep enabled and --trace=strace?"
	exit 0
fi

echo "worker syscalls observed ($nsys):"
sed 's/^/  - /' "$tmp/worker.syscalls.u"
echo

if [ -s "$tmp/missing.syscalls" ]; then
	echo "!! MISSING from seccomp_allow[] -- the worker WOULD BE KILLED on these:"
	sed 's/^/  - /' "$tmp/missing.syscalls"
else
	echo "OK: every observed worker syscall is covered by seccomp_allow[]."
fi
echo

if [ -s "$tmp/worker.ioctls.u" ]; then
	echo "worker ioctl request commands observed:"
	sed 's/^/  - /' "$tmp/worker.ioctls.u"
	echo
	if [ -s "$tmp/missing.ioctls" ]; then
		echo "!! ioctl commands NOT permitted by seccomp_ioctl_allow[]"
		echo "   (a 0x.. entry means strace could not decode it -- verify by hand):"
		sed 's/^/  - /' "$tmp/missing.ioctls"
		echo
	else
		echo "OK: every observed worker ioctl command is permitted by"
		echo "    seccomp_ioctl_allow[]."
		echo
	fi
fi

gap=0
[ -s "$tmp/missing.syscalls" ] && gap=1
[ -s "$tmp/missing.ioctls" ]   && gap=1

if [ "$gap" -eq 1 ]; then
	echo "result: GAP found (see lines marked '!!')."
	[ "$STRICT" -eq 1 ] && exit 1
else
	echo "result: allow-list fully covers the observed worker behaviour."
fi
exit 0
