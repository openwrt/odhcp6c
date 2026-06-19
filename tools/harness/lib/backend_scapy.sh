#!/bin/sh
# shellcheck shell=sh
#
# backend_scapy.sh - launch the crafted-packet (scapy) server/RA backend.
#
# Exposes backend_start() and backend_stop(), called by common.sh's
# harness_backend_start/stop. The scenario passes the scapy subcommand and flags
# (everything after the backend name) straight through, e.g.:
#
#   harness_backend_start scapy ra --prefix 2001:db8:1:: --mtu 1480 \
#       --rdnss 2001:db8:1::53
#
# The server runs in the server netns and binds the server-side veth.

: "${PYTHON:=python3}"

backend_start() {
	_srv="$HARNESS_ROOT/servers/scapy_server.py"
	[ -f "$_srv" ] || fatal "scapy server not found: $_srv"

	$SUDO ip netns exec "$HARNESS_NS_SERVER" \
		"$PYTHON" "$_srv" --iface "$HARNESS_VETH_SERVER" "$@" \
		> "$HARNESS_WORKDIR/backend.log" 2>&1 &
	HARNESS_BACKEND_PID=$!
	log "scapy backend started (pid $HARNESS_BACKEND_PID): $*"

	# Wait until the server reports it is ready before driving odhcp6c.
	wait_for "$HARNESS_TIMEOUT" "scapy backend ready" \
		grep -q "^\[scapy\] ready" "$HARNESS_WORKDIR/backend.log" \
		|| warn "scapy backend did not report ready (continuing)"
}

backend_stop() {
	[ -n "$HARNESS_BACKEND_PID" ] || return 0
	$SUDO kill "$HARNESS_BACKEND_PID" 2>/dev/null || true
	wait "$HARNESS_BACKEND_PID" 2>/dev/null || true
	HARNESS_BACKEND_PID=""
}
