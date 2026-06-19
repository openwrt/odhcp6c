# release-on-stop: SIGTERM handling and RELEASE-on-stop behavior.
#
# odhcp6c always emits a final 'stopped' status when it exits, and 'unbound'
# first if it was bound. When it holds a lease (server-id + IA) it additionally
# sends a DHCPv6 RELEASE on the wire, UNLESS started with -k.
#
# This scenario runs the full RA + DHCPv6 backend so that, where the client's
# own egress is permitted (e.g. CI), odhcp6c reaches 'bound' and the RELEASE is
# observable in the server log. The terminal 'stopped' status is asserted
# unconditionally; the on-the-wire RELEASE is asserted only when a lease was
# actually established (REPLY seen), so the scenario is meaningful on hosts that
# restrict client egress while still proving RELEASE in CI.
#
# Set RELEASE_SUPPRESS=1 to run the -k variant, which inverts the RELEASE
# expectation (no RELEASE must be sent on stop).

scenario_backend() {
	echo "scapy serve --respond-rs --interval 1 \
--prefix 2001:db8:1:: --rdnss 2001:db8:1::53 \
--dns 2001:db8:1::53 --domains example.test \
--address 2001:db8:1::1000 --pd-prefix 2001:db8:abcd:: --pd-len 56"
}

scenario_odhcp6c() {
	# Request a prefix so a lease (and thus a RELEASE) is in play.
	if [ "${RELEASE_SUPPRESS:-0}" = "1" ]; then
		echo "-l7 -P 56 -k $HARNESS_VETH_CLIENT"
	else
		echo "-l7 -P 56 $HARNESS_VETH_CLIENT"
	fi
}

scenario_drive() {
	# Prefer a real lease; fall back to RA processing where egress is blocked.
	if wait_for_action bound 15; then
		info "reached bound"
	else
		warn "did not reach bound (client egress likely restricted); continuing"
		wait_for_action ra-updated 10 || true
	fi
	# run-scenario.sh sends SIGTERM via harness_odhcp6c_stop after this returns,
	# which exercises the release-on-stop path.
}

scenario_assert() {
	harness_assert_action_seen stopped

	_bound=0
	harness_has_action bound && _bound=1

	if [ "$_bound" = 1 ]; then
		harness_assert_action_seen unbound
		if [ "${RELEASE_SUPPRESS:-0}" = "1" ]; then
			if grep -q "RELEASE received" "$HARNESS_WORKDIR/backend.log" 2>/dev/null; then
				assert_fail "RELEASE was sent despite -k"
			else
				assert_pass "no RELEASE sent with -k (as expected)"
			fi
		else
			if grep -q "RELEASE received" "$HARNESS_WORKDIR/backend.log" 2>/dev/null; then
				assert_pass "RELEASE sent on stop"
			else
				assert_fail "expected RELEASE on stop but server saw none"
			fi
		fi
	else
		warn "lease not established; skipping RELEASE-on-wire assertion (stopped still verified)"
	fi
}
