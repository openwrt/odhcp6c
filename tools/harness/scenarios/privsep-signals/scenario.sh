# privsep-signals: exercise the privilege-separation signal paths in isolation.
#
# The other signal-driven scenarios (renew-rebind, release-on-stop) use the
# broadcast helper harness_odhcp6c_signal, which sends the signal to BOTH the
# privsep monitor and the worker. That hides the monitor entirely: the worker
# reacts even if the monitor's forwarding/translation (src/script.c
# monitor_sighandle) is broken. This scenario instead signals ONLY the monitor --
# exactly how a real init system signals odhcp6c (it targets the launcher PID) --
# so the monitor path is actually under test:
#
#   1. SIGUSR1 to the monitor only -> the monitor must forward it to the worker,
#      which renews and emits an 'updated' record. With long T1/T2 no spontaneous
#      renew can occur, so 'updated' proves the forward happened.
#   2. SIGTERM to the monitor only -> the monitor must translate it into a graceful
#      worker SIGTERM (RELEASE + unbound + stopped) and must report the worker's
#      exit status as its own process exit code (0 on a clean stop). This guards
#      the SIGCHLD/worker-pid race fix.
#
# In non-privsep (--privsep off) runs there is a single process and the role
# resolver targets it directly, so the same assertions still hold -- the scenario
# is meaningful on both axes of the CI matrix.
#
# Requires client egress (like stateful-basic / release-on-stop); green in CI.

scenario_backend() {
	# Default T1/T2 (300/500) are long relative to the test window, so the ONLY
	# renew during the run is the one triggered by our forwarded SIGUSR1 -- no
	# spontaneous T1 renew can race in and produce a misleading 'updated'.
	echo "scapy serve --respond-rs --interval 1 \
--prefix 2001:db8:1:: \
--address 2001:db8:1::1000 --pd-prefix 2001:db8:abcd:: --pd-len 56 \
--dns 2001:db8:1::53 --domains example.test"
}

scenario_odhcp6c() {
	# Request a prefix so a lease (hence a RELEASE on stop) is in play.
	echo "-l7 -P 56 $HARNESS_VETH_CLIENT"
}

HARNESS_SAW_PRIVSEP=0

scenario_drive() {
	wait_for_action bound "${HARNESS_TIMEOUT:-30}" \
		|| fatal "odhcp6c did not reach 'bound'"

	# Record whether privsep is genuinely active (distinct monitor/worker) so the
	# assertions can prove the monitor path was really isolated, not silently
	# degraded to single-process signalling.
	if harness_odhcp6c_privsep_active; then
		HARNESS_SAW_PRIVSEP=1
		info "privsep active: monitor=$(harness_odhcp6c_role_pid monitor) worker=$(harness_odhcp6c_role_pid worker)"
	else
		info "single-process mode (no distinct monitor/worker)"
	fi

	# (1) Forwarding: SIGUSR1 to the MONITOR ONLY must reach the worker.
	harness_odhcp6c_signal_role monitor USR1 \
		|| fatal "could not signal monitor with SIGUSR1"
	wait_for_action updated 15 \
		|| fatal "no 'updated' after monitor-only SIGUSR1 (forwarding broken?)"

	# (2) Termination + exit status: SIGTERM to the MONITOR ONLY must produce a
	# graceful release and propagate the worker's exit status (0). This stops
	# odhcp6c and captures HARNESS_ODHCP6C_EXIT; it clears HARNESS_ODHCP6C_PID so
	# run-scenario.sh's later harness_odhcp6c_stop is a no-op.
	harness_odhcp6c_stop_monitor
}

scenario_assert() {
	# Forwarding path.
	harness_assert_action_seen bound
	harness_assert_action_seen updated

	# Graceful termination via the monitor's TERM->worker translation.
	harness_assert_action_seen unbound
	harness_assert_action_seen stopped

	# On-the-wire proof the worker actually released (not just exited).
	if grep -q "RELEASE received" "$HARNESS_WORKDIR/backend.log" 2>/dev/null; then
		assert_pass "RELEASE sent after monitor-only SIGTERM"
	else
		assert_fail "expected RELEASE after monitor SIGTERM but server saw none"
	fi

	# Exit-status propagation (SIGCHLD/worker-pid race fix): the monitor's process
	# exit code must equal the worker's clean exit status (0).
	if [ "${HARNESS_ODHCP6C_EXIT:-x}" = "0" ]; then
		assert_pass "monitor propagated worker exit status 0"
	else
		assert_fail "monitor exit status was '${HARNESS_ODHCP6C_EXIT:-unset}', expected 0"
	fi

	# When privsep is on, prove the monitor path was genuinely isolated (we really
	# signalled a distinct monitor process, not a collapsed single process).
	if [ "${PRIVSEP:-}" = "on" ]; then
		if [ "$HARNESS_SAW_PRIVSEP" = "1" ]; then
			assert_pass "monitor path isolated (distinct monitor/worker observed)"
		else
			assert_fail "privsep on but no distinct monitor/worker seen during drive"
		fi
	fi
}
