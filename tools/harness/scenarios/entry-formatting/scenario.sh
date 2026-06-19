# entry-formatting: exact entry_to_env field layout (incl. the class= suffix).
#
# entry_to_env (src/script.c) formats:
#   ADDRESS:  <addr>/128,<preferred>,<valid>,<t1>,<t2>
#   PREFIX:   <pfx>/<len>,<preferred>,<valid>,<t1>,<t2>[,class=%08x][,excluded=...]
#   ROUTE:    <pfx>/<len>,[router],<valid>,<priority>
#
# class= appears only when ntohl(iaid) != 1. We request the PD with a non-1 IAID
# via the ':' form of -P (src/odhcp6c.c case 'P':
# prefix.iaid = htonl(strtoul(&iaid_begin[1], NULL, 16))); the scapy server
# echoes the client's IA_PD IAID, so entry_to_env emits ",class=2a2a2a2a".
#
# excluded= is NOT covered here -- it needs OPTION_PD_EXCLUDE emission from the
# backend (see entry-formatting-exclude / the --pd-exclude follow-up).

scenario_backend() {
	echo "scapy serve --respond-rs \
		--address 2001:db8:1::1000 \
		--pd-prefix 2001:db8:abcd:: --pd-len 56 \
		--t1 100 --t2 200 --preferred 300 --valid 600"
}

scenario_odhcp6c() {
	# Request the PD with IAID 0x2a2a2a2a (hex via the ':' form) so class= appears.
	echo "-P 56:2a2a2a2a $HARNESS_VETH_CLIENT"
}

scenario_drive() { wait_for_action bound 30; }
