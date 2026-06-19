#!/bin/sh
# shellcheck shell=sh
#
# trace.sh - syscall capture post-processing for the harness trace modes.
#
# Two modes are supported (selected via run-scenario.sh --trace=...):
#
#   strace       odhcp6c is wrapped with `strace -f -ff` so BOTH privilege-
#                separation processes (monitor + worker) are followed, one trace
#                file per pid. harness_trace_finalize() turns each trace file
#                into a sorted-unique list of syscall names and also emits a
#                combined union list.
#
#   seccomp-log  odhcp6c is built with the seccomp filter default action set to
#                SCMP_ACT_LOG, so disallowed syscalls are logged (not killed) to
#                the kernel ring buffer / audit. harness_trace_finalize() scrapes
#                the new SECCOMP records, maps the syscall numbers to names, and
#                emits the observed set.
#
# All modes produce machine-readable artifacts under <trace_dir>/:
#   syscalls.<pid>.txt   per-process sorted-unique syscall names (strace)
#   syscalls.union.txt   union across all processes (strace)
#   syscalls.seccomp.txt observed syscalls (seccomp-log)
#
# These artifacts are what the N-2 seccomp reconciliation job diffs against the
# checked-in allow-list.

# Extract sorted-unique syscall names from a single strace output file.
_strace_syscalls() {
	# strace lines look like:  "name(args) = ret"  or  "[pid 123] name(..."
	# Also handle resumed/unfinished lines and signal lines (--- SIG... ---).
	sed -E \
		-e 's/^\[pid[[:space:]]+[0-9]+\][[:space:]]*//' \
		-e 's/^[0-9]+[[:space:]]+//' \
		"$1" 2>/dev/null \
	| grep -E '^[a-zA-Z_][a-zA-Z0-9_]*\(' \
	| sed -E 's/^([a-zA-Z_][a-zA-Z0-9_]*)\(.*/\1/' \
	| sort -u
}

# Map a syscall number to a name using `ausyscall` if available, else a small
# built-in table for the syscalls odhcp6c is expected to use. Architecture
# matters; ausyscall handles that. Falls back to "syscall_<n>".
_syscall_name() {
	_num="$1"; _arch="${2:-}"
	if command -v ausyscall >/dev/null 2>&1; then
		if [ -n "$_arch" ]; then
			ausyscall "$_arch" "$_num" 2>/dev/null && return 0
		fi
		ausyscall "$_num" 2>/dev/null && return 0
	fi
	printf 'syscall_%s\n' "$_num"
}

# harness_trace_finalize  (uses HARNESS_TRACE_MODE / HARNESS_TRACE_DIR)
harness_trace_finalize() {
	[ "$HARNESS_TRACE_MODE" = "none" ] && return 0
	mkdir -p "$HARNESS_TRACE_DIR"

	case "$HARNESS_TRACE_MODE" in
	strace)
		_union="$HARNESS_TRACE_DIR/syscalls.union.txt"
		: > "$HARNESS_TRACE_DIR/.union.tmp"
		_found=0
		for f in "$HARNESS_TRACE_DIR"/trace.*; do
			[ -e "$f" ] || continue
			_found=1
			_pid="${f##*.}"
			_out="$HARNESS_TRACE_DIR/syscalls.$_pid.txt"
			_strace_syscalls "$f" > "$_out"
			cat "$_out" >> "$HARNESS_TRACE_DIR/.union.tmp"
			log "trace: $(wc -l < "$_out") syscalls for pid $_pid"
		done
		if [ "$_found" = 0 ]; then
			warn "strace produced no trace files (was strace available?)"
			return 1
		fi
		sort -u "$HARNESS_TRACE_DIR/.union.tmp" > "$_union"
		rm -f "$HARNESS_TRACE_DIR/.union.tmp"
		log "trace: union of $(wc -l < "$_union") syscalls -> $_union"
		;;
	seccomp-log)
		_out="$HARNESS_TRACE_DIR/syscalls.seccomp.txt"
		_mark=0
		[ -f "$HARNESS_TRACE_DIR/dmesg.mark" ] && _mark="$(cat "$HARNESS_TRACE_DIR/dmesg.mark")"
		if ! command -v dmesg >/dev/null 2>&1; then
			warn "dmesg unavailable; cannot scrape seccomp log"
			return 1
		fi
		# Collect SECCOMP audit lines emitted since the mark, extract syscall=NN.
		$SUDO dmesg 2>/dev/null | tail -n "+$((_mark + 1))" \
			| grep -i "seccomp" \
			| grep -oE 'syscall=[0-9]+' \
			| cut -d= -f2 | sort -un \
			| while read -r n; do _syscall_name "$n"; done \
			| sort -u > "$_out"
		if [ ! -s "$_out" ]; then
			warn "no SECCOMP records scraped (build with SCMP_ACT_LOG and ensure dmesg access)"
		else
			log "trace: $(wc -l < "$_out") seccomp syscalls -> $_out"
		fi
		;;
	esac
}
