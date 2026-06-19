# ra-options-edge: exercise the RA option handlers with boundary and malformed
# inputs (H-1 / H-2 / N-4) and confirm odhcp6c stays alive and rejects bad input.
#
# Phase 1 (continuous backend): a well-formed RA carrying a minimum-MTU option
# (1280), a PIO, RDNSS and a route-information option drives a normal
# ra-updated with known values.
#
# Phase 2 (one-shot injections): deliberately malformed RAs that must be parsed
# defensively and dropped WITHOUT crashing or leaking state:
#   * ND_OPT_ROUTE_INFORMATION with len == 0           (H-1)
#   * ND_OPT_RECURSIVE_DNS with an odd/short length     (H-2)
#   * hop-limit != 255 carrying a distinctive prefix    (must be dropped)
#   * non-link-local source carrying a distinctive prefix (must be dropped)
#
# Assertions: the good values are present; the distinctive "dead"/"beef"
# prefixes from the dropped RAs never appear; and odhcp6c survived every
# malformed packet.

scenario_backend() {
	echo "scapy ra --respond-rs --interval 1 \
--prefix 2001:db8:1:: --prefix-len 64 \
--mtu 1280 \
--rdnss 2001:db8:1::53 \
--route-info 2001:db8:2:: --route-info-plen 48"
}

scenario_odhcp6c() {
	echo "-l7 $HARNESS_VETH_CLIENT"
}

scenario_drive() {
	wait_for_action ra-updated "$HARNESS_TIMEOUT" \
		|| { warn "never reached ra-updated"; return 1; }

	# Phase 2: malformed / must-be-dropped RAs.
	harness_inject ra --count 3 --interval 0.3 --raw-route-info-len0 \
		--prefix 2001:db8:1:: || true
	_ensure_alive "after route-info len==0" || return 1

	harness_inject ra --count 3 --interval 0.3 --raw-rdnss-odd \
		--prefix 2001:db8:1:: || true
	_ensure_alive "after odd RDNSS length" || return 1

	# hop-limit != 255 must be dropped (carry a distinctive prefix to detect leak)
	harness_inject ra --count 3 --interval 0.3 --hoplimit 1 \
		--prefix 2001:db8:dead:: || true
	_ensure_alive "after bad hop-limit" || return 1

	# non-link-local source must be dropped
	harness_inject ra --count 3 --interval 0.3 --source 2001:db8:bad::1 \
		--prefix 2001:db8:beef:: || true
	_ensure_alive "after non-link-local source" || return 1

	# Allow a final good RA to land so the asserted record is fresh.
	sleep 2
}

_ensure_alive() {
	if harness_odhcp6c_running; then
		assert_pass "odhcp6c survived malformed RA: $1"
		return 0
	fi
	assert_fail "odhcp6c crashed on malformed RA: $1"
	return 1
}
