# prefix-renumber: SLAAC prefix renumbering / lifetime-0 withdrawal.
#
# A scapy RA backend advertises a SLAAC PIO (2001:db8:1::/64) so odhcp6c forms a
# RA_ADDRESSES entry. We then inject the SAME prefix with valid-lifetime 0, which
# per RFC 4862 withdraws the address: entry_to_env still emits invalid prefix/RA
# entries (see src/script_worker.c entry_to_env), but the configured address must be
# gone from the FINAL ra-updated record.
#
# This needs harness_assert_last (lib/assert.sh): a plain not_contains would
# wrongly fail on the first record, which legitimately still carries the prefix.

scenario_backend() {
	echo "scapy ra --respond-rs --prefix 2001:db8:1:: --prefix-len 64 --prefix-valid 300 --prefix-preferred 120"
}

scenario_odhcp6c() { echo "$HARNESS_VETH_CLIENT"; }

scenario_drive() {
	wait_for_action ra-updated 30
	# Re-advertise the SAME prefix with valid-lifetime 0 -> withdrawal.
	harness_inject ra --prefix 2001:db8:1:: --prefix-len 64 --prefix-valid 0 --prefix-preferred 0 --count 1
	wait_for_action ra-updated 30
}

scenario_assert() {
	# Learned at some point...
	harness_assert_one  ra-updated RA_ADDRESSES contains 2001:db8:1:
	# ...and absent from the FINAL record after the lifetime-0 re-advertisement.
	harness_assert_last ra-updated RA_ADDRESSES not_contains 2001:db8:1:
}
