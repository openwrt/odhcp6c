# privsep-user: exercise the runtime-configurable privsep drop user (--privsep-user).
#
# The privsep scenarios otherwise rely on the compile-time ODHCP6C_USER default
# ("nobody"). This scenario instead passes --privsep-user explicitly so the
# option parsing and plumbing into drop_privileges() are actually covered: the
# worker must resolve the named user and report the uid/gid it dropped to.
#
# When privsep is genuinely active (the CI 'privsep on' axis built with
# libcap-ng and run as root), assert the worker logged its uid/gid drop. On the
# '--privsep off' axis (or where privsep silently degrades to a single process)
# there is no drop, so the assertion is skipped -- the scenario stays meaningful
# on both axes of the CI matrix, mirroring privsep-signals.
#
# Requires client egress (like stateful-basic / release-on-stop); green in CI.

scenario_backend() {
	echo "scapy serve --respond-rs --interval 1 \
--prefix 2001:db8:1:: \
--address 2001:db8:1::1000 --pd-prefix 2001:db8:abcd:: --pd-len 56 \
--dns 2001:db8:1::53 --domains example.test"
}

scenario_odhcp6c() {
	# Explicitly select the unprivileged user (matches the built-in default so
	# it resolves in every harness image) and request a prefix so a lease is in
	# play. The --privsep axis (run-scenario.sh) still controls on/off.
	echo "--privsep-user nobody -l7 -P 56 $HARNESS_VETH_CLIENT"
}

scenario_drive() {
	wait_for_action bound "${HARNESS_TIMEOUT:-30}" \
		|| fatal "odhcp6c did not reach 'bound'"

	if harness_odhcp6c_privsep_active; then
		info "privsep active: asserting worker dropped to the requested user"
		harness_assert_log \
			'privsep: worker running as uid=[0-9]+ gid=[0-9]+' \
			"worker reports uid/gid after --privsep-user drop"
	else
		info "single-process mode (no privilege drop); asserting --privsep-user warning"
		harness_assert_log \
			"privsep: --privsep-user 'nobody' ignored because privilege separation is disabled" \
			"--privsep-user warns when privsep is disabled"
	fi

	harness_assert_summary
}
