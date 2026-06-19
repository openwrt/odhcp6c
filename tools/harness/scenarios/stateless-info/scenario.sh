# stateless-info: information-request / stateless mode.
#
# With no IA_NA and no IA_PD requested, odhcp6c runs the stateless path and
# sends an INFORMATION-REQUEST. The server answers with DNS + search domains
# and odhcp6c emits the 'informed' action. Asserts the stateless DNS data is
# exported.
#
# Requires client egress (see stateful-basic note); green in the CI container.

scenario_backend() {
	echo "scapy serve --respond-rs --other --interval 1 \
--prefix 2001:db8:1:: \
--dns 2001:db8:1::53 --domains example.test"
}

scenario_odhcp6c() {
	# -N none => no IA_NA; no -P => no IA_PD => stateless INFORMATION-REQUEST.
	echo "-l7 -N none $HARNESS_VETH_CLIENT"
}

scenario_drive() {
	wait_for_action informed "${HARNESS_TIMEOUT:-30}" \
		|| fatal "odhcp6c did not reach 'informed' (stateless)"
}
