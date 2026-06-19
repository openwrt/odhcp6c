# captive-portal: prove H-3 captive-portal URI sanitization.
#
# A scapy RA backend advertises an ND_OPT_CAPTIVE_PORTAL option whose URI is
# laced with shell metacharacters and control bytes. odhcp6c parses it in
# ra.c and exports CAPTIVE_PORTAL_URI via string_to_env(), which routes the
# value through script_sanitize_env(). We assert the value reaching the status
# script is sanitized: every dangerous byte replaced with '_', while the benign
# parts of the URI survive.
#
# This is the regression guard for H-3: reverting the sanitization makes the
# CAPTIVE_PORTAL_URI record contain `, $, ", ' or control bytes and the
# 'sanitized' assertion fails.
#
# The malicious URI is built with printf so it contains REAL control bytes (a
# tab and a BEL) in addition to the shell metacharacters. It is passed as a
# single, properly-quoted argument to the one-shot injector so the harness shell
# never interprets the metacharacters itself.

scenario_backend() { :; }   # no continuous backend; we inject crafted RAs

scenario_odhcp6c() {
	echo "-l7 $HARNESS_VETH_CLIENT"
}

scenario_drive() {
	# Build a URI with backtick, $(), &, quotes and real control bytes.
	# Single-quoted printf format keeps the metacharacters literal; \t and \a
	# expand to real control bytes.
	_uri="$(printf 'https://cp.example.test/login?token=`id`;$(reboot)&x="a"\ty\a')"

	# Inject several captive-portal RAs so odhcp6c reliably processes one.
	harness_inject ra --count 6 --interval 0.5 \
		--prefix 2001:db8:1:: --captive-portal "$_uri" \
		|| { warn "injection failed"; return 1; }

	wait_for_action ra-updated "$HARNESS_TIMEOUT" \
		|| { warn "never reached ra-updated"; return 1; }
	# Make sure a record actually carried a non-empty CAPTIVE_PORTAL_URI.
	wait_for 5 "captive-portal URI captured" _cp_uri_present || return 1
}

_cp_uri_present() {
	grep -h '^CAPTIVE_PORTAL_URI=' "$HARNESS_CAPTURE"/rec.* 2>/dev/null \
		| grep -q 'CAPTIVE_PORTAL_URI=..*'
}
