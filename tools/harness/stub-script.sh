#!/bin/sh
#
# odhcp6c integration-harness status script (the assertion surface).
#
# odhcp6c invokes this script via its -s option on every state transition. The
# script is deliberately inert with respect to the system (it touches no real
# interface configuration); its only job is to faithfully record *what odhcp6c
# asked it to do* so the harness can assert on it afterwards.
#
# For each invocation it writes one structured record to a per-invocation file
# under $ODHCP6C_HARNESS_CAPTURE (a directory the harness creates). The record
# is a block of KEY=VALUE lines:
#
#   ACTION=<bound|informed|updated|...>   (from argv[2])
#   IFACE=<interface>                     (from argv[1])
#   <every odhcp6c-exported environment variable, verbatim>
#
# The values are written exactly as odhcp6c exported them. This is the primary
# observable of the whole harness: it validates parsing, formatting, and -- for
# the captive-portal/H-3 case -- that values derived from attacker-controlled
# network input were sanitized before being placed in the environment.
#
# The capture directory must be writable by the (possibly unprivileged, e.g.
# "nobody") process that execs the script under privilege separation, so the
# harness creates it mode 0777.

set -u

iface="${1:-}"
action="${2:-}"

# Where to drop the record. Fall back to a temp dir so the script never fails
# hard if invoked outside the harness (e.g. for manual inspection).
capture="${ODHCP6C_HARNESS_CAPTURE:-/tmp/odhcp6c-harness-capture}"
mkdir -p "$capture" 2>/dev/null || true

# A unique, sortable filename: zero-padded sequence is not available portably,
# so use a high-resolution timestamp plus the pid. The harness sorts records by
# filename to reconstruct invocation order.
stamp="$(date +%s%N 2>/dev/null || date +%s)"
rec="$capture/rec.$stamp.$$"

# The odhcp6c-exported variables we care about. We capture the full environment
# but tag the odhcp6c-specific names so assertions are easy to write and records
# stay readable. The list mirrors script.c (*_to_env) and ra.c.
odhcp6c_vars="ACTION IFACE \
PREFIXES ADDRESSES SERVER RDNSS DOMAINS SNTP_IP NTP_IP NTP_FQDN \
SIP_IP SIP_DOMAIN AFTR MAPE MAPT LW4O6 \
CAPTIVE_PORTAL_URI \
RA_ADDRESSES RA_ROUTES RA_DNS RA_DOMAINS \
RA_HOPLIMIT RA_MTU RA_REACHABLE RA_RETRANSMIT \
PASSTHRU"

{
	printf 'ACTION=%s\n' "$action"
	printf 'IFACE=%s\n'  "$iface"

	# Emit the known odhcp6c variables (even when empty) in a stable order so
	# fixtures are deterministic. Skip ACTION/IFACE which we already printed.
	for v in $odhcp6c_vars; do
		case "$v" in
		ACTION|IFACE) continue ;;
		esac
		eval "val=\${$v-__UNSET__}"
		[ "$val" = "__UNSET__" ] && val=""
		printf '%s=%s\n' "$v" "$val"
	done

	# Also emit any OPTION_<n> passthru variables (bin_to_env) which have
	# dynamic names and cannot be enumerated above.
	env | grep '^OPTION_[0-9]' | sort
} > "$rec" 2>/dev/null

# Optionally append to a single combined log for human debugging.
if [ -n "${ODHCP6C_HARNESS_LOG:-}" ]; then
	{
		echo "=== $action ($iface) @ $stamp ==="
		cat "$rec"
		echo
	} >> "$ODHCP6C_HARNESS_LOG" 2>/dev/null || true
fi

exit 0
