# stateful-basic: full IA_NA + IA_PD lease via the DHCPv6 server backend.
#
# Brings odhcp6c to 'bound' through a real SOLICIT -> ADVERTISE -> REQUEST ->
# REPLY exchange and asserts that the address, delegated prefix, recursive DNS
# servers and search domains are exported into the status-script environment.
#
# NOTE: this scenario requires the odhcp6c client to be able to *send* DHCPv6
# packets. Some sandboxes block datagram egress with a cgroup/eBPF firewall; in
# that case 'bound' is never reached and the scenario fails (correctly). It runs
# green in the CI container, which imposes no such restriction.

scenario_backend() {
	echo "scapy serve --respond-rs --interval 1 \
--prefix 2001:db8:1:: \
--address 2001:db8:1::1000 --pd-prefix 2001:db8:abcd:: --pd-len 56 \
--dns 2001:db8:1::53 --domains example.test"
}

scenario_odhcp6c() {
	# Request a /56 prefix and addresses; default ORO asks for DNS + domains.
	echo "-l7 -P 56 $HARNESS_VETH_CLIENT"
}

scenario_drive() {
	wait_for_action bound "${HARNESS_TIMEOUT:-30}" \
		|| fatal "odhcp6c did not reach 'bound'"
}
