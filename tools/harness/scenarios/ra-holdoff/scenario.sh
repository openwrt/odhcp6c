# ra-holdoff: RA update suppression via the -m holdoff interval.
#
# odhcp6c_update_entry() suppresses an entry refresh when both the valid and the
# preferred lifetime grow by LESS than the holdoff interval (src/odhcp6c.c
# odhcp6c_update_entry). With -m 120 a tiny +5s bump must be suppressed, while a
# large drop to 60/40 must apply.
#
# Honest limitation: the stub records RA_ADDRESSES as a space-separated address
# list WITHOUT per-address lifetimes, so the harness cannot directly observe
# "valid went 300->60 but not ->305". This proves the weaker-but-useful property
# that holdoff did not block a legitimate large update and did not drop the
# entry. Strengthening needs a record-count helper or lifetimes in the record;
# do NOT rely on the sleep as the gate.

scenario_backend() {
	echo "scapy ra --respond-rs --prefix 2001:db8:1:: --prefix-len 64 --prefix-valid 300 --prefix-preferred 200"
}

scenario_odhcp6c() { echo "-m 120 $HARNESS_VETH_CLIENT"; }

scenario_drive() {
	wait_for_action ra-updated 30
	# Tiny change WITHIN the 120s holdoff window -> should be suppressed.
	harness_inject ra --prefix 2001:db8:1:: --prefix-len 64 --prefix-valid 305 --prefix-preferred 205 --count 1
	sleep 3   # bounded; we are asserting a non-event, so we cannot wait_for one
	# Large change BEYOND the window -> must apply.
	harness_inject ra --prefix 2001:db8:1:: --prefix-len 64 --prefix-valid 60 --prefix-preferred 40 --count 1
	wait_for_action ra-updated 30
}

scenario_assert() {
	# Provable signal: the address was learned and is still present after the
	# large update applied. (See caveat: full suppression-counting needs more.)
	harness_assert_one  ra-updated RA_ADDRESSES contains 2001:db8:1:
	harness_assert_last ra-updated RA_ADDRESSES contains 2001:db8:1:
}
