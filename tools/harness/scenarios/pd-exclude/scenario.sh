# pd-exclude: RFC 6603 Prefix Exclude option encode/decode regression guard.
#
# Regression test for the upstream fix "odhcp6c: fix handling of RFC6603 Prefix
# Exclude Option" (commit 07d324ee, PR openwrt/odhcp6c#151). Before that fix the
# DHCPV6_OPT_PD_EXCLUDE sub-option was mishandled on decode: short encodings
# (a single subnet-ID octet, sub-data length 2) were dropped entirely by a
# "slen > 2" guard, and multi-octet subnet IDs were byte-swapped, so the
# excluded prefix exported to the status script was missing or wrong.
#
# The scapy DHCPv6 server returns one IA_PD with two IA_PREFIX options, each
# carrying a nested RFC 6603 PD_EXCLUDE:
#
#   * 2001:db8:1234::/48  exclude 2001:db8:1234:5600::/56  (1 subnet-ID octet;
#     sub-data length 2 -> silently dropped by the pre-fix "slen > 2" guard)
#   * 2001:db8:abcd::/48  exclude 2001:db8:abcd:1234::/63  (2 subnet-ID octets;
#     byte-swapped to ...:3412::/63 by the pre-fix decode loop)
#
# odhcp6c parses these in dhcpv6_parse_ia() and exports them via entry_to_env()
# as ",excluded=<prefix>/<len>" appended to the matching PREFIXES entry (see
# src/script.c). We assert both excluded prefixes appear, correctly decoded, in
# the 'bound' record -- so this scenario FAILS on the pre-#151 code and PASSES
# on the fixed code.
#
# Like stateful-basic this needs the odhcp6c client to be able to *send* DHCPv6
# packets; it is green in the CI container (no egress restriction) and may not
# reach 'bound' in sandboxes that block client datagram egress.

scenario_backend() {
	echo "scapy serve --respond-rs --interval 1 \
--address 2001:db8:1::1000 \
--dns 2001:db8:1::53 --domains example.test \
--pd-exclude 2001:db8:1234::/48,2001:db8:1234:5600::/56 \
--pd-exclude 2001:db8:abcd::/48,2001:db8:abcd:1234::/63"
}

scenario_odhcp6c() {
	# Request prefix delegation so the IA_PD (and its PD_EXCLUDE) is in play.
	echo "-l7 -P 48 $HARNESS_VETH_CLIENT"
}

scenario_drive() {
	wait_for_action bound "${HARNESS_TIMEOUT:-30}" \
		|| fatal "odhcp6c did not reach 'bound'"
}

scenario_assert() {
	# Positive checks: both excluded prefixes present and correctly decoded.
	harness_assert_expect "$SCN_DIR/expect.txt"

	# Explicit guard against the pre-fix decoder, which byte-swapped the 2-octet
	# subnet ID (2001:db8:abcd:1234::/63 would appear as 2001:db8:abcd:3412::/63).
	harness_assert_one bound PREFIXES not_contains 2001:db8:abcd:3412:

	# The fix also added a PD_EXCLUDE info log line per excluded prefix.
	harness_assert_log "PD_EXCLUDE 2001:db8:1234:5600::/56" "PD_EXCLUDE log (/56)"
	harness_assert_log "PD_EXCLUDE 2001:db8:abcd:1234::/63" "PD_EXCLUDE log (/63)"
}
