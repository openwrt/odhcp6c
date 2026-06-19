# renew-rebind: bound -> renew -> rebind -> reset, forcing DHCPv6 socket
# re-creation.
#
# Flow:
#   1. Reach 'bound' with a short T1/T2 so renew/rebind happen quickly.
#   2. Trigger an explicit renew with SIGUSR1 and assert an 'updated' record.
#   3. Stop the server. With no answer odhcp6c walks RENEW -> REBIND and finally
#      DHCPV6_RESET, which closes and re-creates the DHCPv6 socket and re-enters
#      DHCPV6_INIT ("(re)starting transaction" logged a second time).
#
# The second "(re)starting transaction" line is the observable proof that the
# DHCPV6_RESET path ran and the socket was re-created.
#
# Requires client egress (see stateful-basic note); green in the CI container.

scenario_backend() {
	echo "scapy serve --respond-rs --interval 1 --t1 2 --t2 4 \
--prefix 2001:db8:1:: \
--address 2001:db8:1::1000 --pd-prefix 2001:db8:abcd:: --pd-len 56 \
--dns 2001:db8:1::53 --domains example.test"
}

scenario_odhcp6c() {
	echo "-l7 -P 56 $HARNESS_VETH_CLIENT"
}

scenario_drive() {
	wait_for_action bound "${HARNESS_TIMEOUT:-30}" \
		|| fatal "odhcp6c did not reach 'bound'"

	# Explicit renew.
	harness_odhcp6c_signal USR1
	wait_for_action updated 10 || warn "no 'updated' after SIGUSR1 renew"

	# Kill the server to force renew->rebind->reset and socket re-creation.
	harness_backend_stop
	wait_for_log "\(re\)starting transaction" "${HARNESS_TIMEOUT:-30}" 2 \
		|| fatal "DHCPV6_RESET / socket re-creation not observed"
}

scenario_assert() {
	harness_assert_action_seen bound
	harness_assert_action_seen updated

	# Socket re-creation: the "(re)starting transaction" line must appear at
	# least twice (initial transaction + post-reset re-init).
	_n=$(grep -c "(re)starting transaction" "$HARNESS_WORKDIR/odhcp6c.log" 2>/dev/null || echo 0)
	if [ "${_n:-0}" -ge 2 ]; then
		assert_pass "DHCPv6 socket re-created after reset (saw $_n transaction (re)starts)"
	else
		assert_fail "expected >=2 transaction (re)starts (socket re-create), saw ${_n:-0}"
	fi
}
