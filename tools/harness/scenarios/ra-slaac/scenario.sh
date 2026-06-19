# ra-slaac: SLAAC-only RA path.
#
# A scapy RA backend advertises a PIO (autonomous), MTU, RDNSS and a
# route-information option, and answers Router Solicitations. odhcp6c is run
# without -S so it accepts SLAAC configuration. We assert that the RA option
# handlers populate RA_ADDRESSES / RA_ROUTES / RA_DNS / RA_MTU and friends.
#
# This path is receive-driven (odhcp6c acts on unsolicited RAs), so it exercises
# ra.c end-to-end even on hosts that restrict the client's own egress.

scenario_backend() {
	echo "scapy ra --respond-rs --interval 1 \
--prefix 2001:db8:1:: --prefix-len 64 \
--mtu 1492 \
--rdnss 2001:db8:1::53 --rdnss 2001:db8:1::54 \
--dnssl slaac.example.test \
--route-info 2001:db8:2:: --route-info-plen 48 \
--reachable 30000 --retransmit 1000"
}

scenario_odhcp6c() {
	# Default privsep (production default), accept SLAAC (no -S), verbose log.
	echo "-l7 $HARNESS_VETH_CLIENT"
}

scenario_drive() {
	wait_for_action ra-updated "$HARNESS_TIMEOUT" \
		|| { warn "never reached ra-updated"; return 1; }
	# Let a couple more RAs land so lifetimes/route formatting are stable.
	wait_for 5 "second ra-updated" _ra_slaac_two_updates || true
}

# Helper: at least two ra-updated records captured.
_ra_slaac_two_updates() {
	[ "$(grep -l '^ACTION=ra-updated$' "$HARNESS_CAPTURE"/rec.* 2>/dev/null | wc -l)" -ge 2 ]
}
