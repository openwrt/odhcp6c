# malformed-dhcpv6: DHCPv6 reply-parser robustness (negative path).
#
# The DHCPv6 counterpart to ra-options-edge: the server appends a deliberately
# malformed trailer to its ADVERTISE/REPLY (via scapy_server.py
# --reply-raw-trailer) and odhcp6c must parse defensively -- it must NOT crash
# and must NOT bind on the bogus option.
#
# Trailer 0003ffff = an option header with code 0x0003 (IA_NA) declaring length
# 0xffff but carrying no body, so the declared length exceeds the datagram.
# odhcp6c's TLV walker must reject it rather than read out of bounds.
#
# Requires scapy_server.py --reply-raw-trailer.

scenario_backend() {
	echo "scapy serve --respond-rs --address 2001:db8:1::1000 \
		--pd-prefix 2001:db8:abcd:: --pd-len 56 --reply-raw-trailer 0003ffff"
}

scenario_odhcp6c() { echo "$HARNESS_VETH_CLIENT"; }

scenario_drive() {
	# odhcp6c should keep running and NOT reach bound. Wait briefly for liveness
	# via a recurring log line, then stop and assert.
	wait_for_log 'starting transaction|SOLICIT|RArecv|odhcp6c' 10 1 || true
	sleep 3
}

scenario_assert() {
	harness_assert_no_action bound
	harness_assert_no_action informed
	harness_assert_one '*' ADDRESSES empty
	harness_assert_one '*' PREFIXES  empty
}
