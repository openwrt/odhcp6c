# abnormal-exit: the failure-path counterpart to privsep-signals.
#
# privsep-signals proves the GRACEFUL path: SIGTERM to the monitor -> worker
# releases -> monitor propagates the worker's clean exit status 0. This scenario
# proves the ABNORMAL path, which the graceful test cannot reach: the worker is
# killed with an uncatchable SIGKILL (simulating a crash / OOM-kill), so it has
# no chance to release or shut down cleanly. We then assert that the privsep
# monitor:
#
#   1. SURVIVES the worker's death (the harness killed the worker, NOT the
#      launcher/monitor) -- proven by the monitor reaping the worker and exiting
#      on its own rather than the launcher dying from the signal.
#   2. Reports a NON-ZERO exit status. src/script.c script_monitor_loop()
#      defaults status_code to 1 and only overwrites it with WEXITSTATUS when the
#      worker exited normally; a signal-killed worker is not WIFEXITED, so the
#      monitor returns 1. In privsep mode we assert exactly 1 -- if the harness
#      had instead killed the launcher we would see 128+SIGKILL=137, so '== 1'
#      is what distinguishes "monitor survived and translated the death" from
#      "monitor itself was killed".
#   3. Did NOT emit a graceful terminal sequence: no RELEASE on the wire and no
#      'stopped'/'unbound' records, because SIGKILL cannot be caught.
#
# Why this matters: the whole point of the monitor's exit-status handling (the
# SIGCHLD/worker-pid race fix) is to faithfully report worker outcomes to the
# init system. privsep-signals only ever exercises the success value (0); a
# regression that mis-reported a crashed worker as success (e.g. defaulting
# status_code to 0, or losing the WIFEXITED guard) would pass privsep-signals
# but fail here. An init system relies on this non-zero status to decide whether
# to respawn odhcp6c.
#
# In non-privsep (--privsep off) runs there is a single process; killing the
# "worker" kills it directly and the launcher's wait() reports the signal death
# as a non-zero status, so the core assertions (non-zero exit, no graceful
# RELEASE/stopped) still hold and the scenario stays meaningful on both axes.
#
# Requires client egress (like stateful-basic / privsep-signals); green in CI.

scenario_backend() {
	# Long default T1/T2 (300/500): we kill the worker shortly after 'bound', well
	# before any spontaneous renew, so the run is a clean steady-state lease when
	# the crash is injected.
	echo "scapy serve --respond-rs --interval 1 \
--prefix 2001:db8:1:: \
--address 2001:db8:1::1000 --pd-prefix 2001:db8:abcd:: --pd-len 56 \
--dns 2001:db8:1::53 --domains example.test"
}

scenario_odhcp6c() {
	# Request a prefix so a real lease is held when the worker is killed.
	echo "-l7 -P 56 $HARNESS_VETH_CLIENT"
}

HARNESS_SAW_PRIVSEP=0

scenario_drive() {
	wait_for_action bound "${HARNESS_TIMEOUT:-30}" \
		|| fatal "odhcp6c did not reach 'bound'"

	# Record whether privsep is genuinely active (distinct monitor/worker) so the
	# assertions can prove the monitor really survived a DISTINCT worker's death
	# rather than the single process simply being killed.
	if harness_odhcp6c_privsep_active; then
		HARNESS_SAW_PRIVSEP=1
		info "privsep active: monitor=$(harness_odhcp6c_role_pid monitor) worker=$(harness_odhcp6c_role_pid worker)"
	else
		info "single-process mode (no distinct monitor/worker)"
	fi

	# Abnormally terminate the worker with an uncatchable SIGKILL: no graceful
	# RELEASE/shutdown is possible. This reaps the launcher and captures the
	# propagated exit status in HARNESS_ODHCP6C_EXIT; it clears HARNESS_ODHCP6C_PID
	# so run-scenario.sh's later harness_odhcp6c_stop is a no-op.
	harness_odhcp6c_kill_worker KILL
}

scenario_assert() {
	# A lease was actually established before the crash.
	harness_assert_action_seen bound

	# SIGKILL is uncatchable: the worker could not run its graceful shutdown, so
	# neither the terminal 'stopped' nor 'unbound' records may appear. Their
	# absence is what makes this an *abnormal* exit rather than a graceful stop.
	harness_assert_no_action stopped
	harness_assert_no_action unbound

	# On-the-wire proof the worker did NOT release: a graceful stop sends a DHCPv6
	# RELEASE; an abnormal kill must not.
	if grep -q "RELEASE received" "$HARNESS_WORKDIR/backend.log" 2>/dev/null; then
		assert_fail "worker was SIGKILLed but server saw a RELEASE (graceful path taken?)"
	else
		assert_pass "no RELEASE after worker SIGKILL (abnormal exit, not graceful)"
	fi

	# The monitor must report the abnormal death as a FAILURE, never success.
	if [ "${HARNESS_ODHCP6C_EXIT:-x}" = "0" ]; then
		assert_fail "odhcp6c exit status was 0 after a worker SIGKILL; a crashed worker must propagate non-zero"
	else
		assert_pass "non-zero exit after worker SIGKILL (status='${HARNESS_ODHCP6C_EXIT:-unset}')"
	fi

	# When privsep is on, prove the monitor SURVIVED the worker's death and
	# translated it into its own clean status 1 (script_monitor_loop's default for
	# a not-WIFEXITED worker). 137 (128+SIGKILL) would instead mean the launcher
	# itself was killed -- i.e. the monitor did not survive to propagate. '== 1'
	# pins down the survive-and-propagate behavior.
	if [ "${PRIVSEP:-}" = "on" ]; then
		if [ "$HARNESS_SAW_PRIVSEP" = "1" ]; then
			assert_pass "monitor path isolated (distinct monitor/worker observed)"
			if [ "${HARNESS_ODHCP6C_EXIT:-x}" = "1" ]; then
				assert_pass "monitor survived worker SIGKILL and propagated status 1"
			else
				assert_fail "expected monitor to propagate status 1 for a signal-killed worker but got '${HARNESS_ODHCP6C_EXIT:-unset}' (137 => the launcher itself was killed, not the worker)"
			fi
		else
			# Single-process under --privsep on almost always means the binary was
			# built without libcap-ng: privsep_should_enable() is gated on
			# WITH_LIBCAP_NG and compiles out otherwise. Rebuild with -DLIBCAP_NG=ON
			# (see tools/harness/Dockerfile*).
			assert_fail "privsep on but odhcp6c ran single-process; binary likely built without libcap-ng (build with -DLIBCAP_NG=ON)"
		fi
	fi
}
