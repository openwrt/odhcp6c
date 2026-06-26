# info-options: DHCPv6 DNS server + search domain list formatting.
#
# The server returns multiple RDNSS addresses and multiple search domains in its
# REPLY. odhcp6c formats them into the space-separated RDNSS / DOMAINS env values
# (src/script_worker.c ipv6_to_env / fqdn_to_env). We assert each value is present and
# sanitized.
#
# Note: the backend's --dns/--domains use argparse action="append" with NON-empty
# defaults (2001:db8:1::53 / example.test), so the user values are appended to
# the defaults rather than replacing them. We therefore assert presence
# (contains), not exact equality. NTP is intentionally not asserted: the backend
# emits an NTP option with an empty suboption list, so NTP_IP/NTP_FQDN stay
# empty.

scenario_backend() {
	echo "scapy serve --respond-rs \
		--dns 2001:db8:1::53 --dns 2001:db8:1::54 \
		--domains example.test --domains corp.example.test \
		--address 2001:db8:1::1000 --pd-prefix 2001:db8:abcd:: --pd-len 56"
}

scenario_odhcp6c() { echo "$HARNESS_VETH_CLIENT"; }

scenario_drive() { wait_for_action bound 30; }
