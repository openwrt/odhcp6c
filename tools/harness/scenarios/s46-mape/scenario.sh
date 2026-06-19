# s46-mape (optional): MAP-E softwire (RFC 7598) option formatting.
#
# The server includes an OPTION_S46_CONT_MAPE container (one FMR rule + BR) in
# its REPLY. odhcp6c parses it and exports a MAPE=... line to the status script.
# Asserts the formatted MAPE environment value.
#
# Optional + requires client egress (see stateful-basic note); green in CI.

scenario_backend() {
	echo "scapy serve --respond-rs --interval 1 --mape \
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
}
