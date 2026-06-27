# ubus-reconnect: exercise the ubus code path under privsep + seccomp, including
# a broker disconnect/reconnect cycle.
#
# Why this scenario exists
# ------------------------
# The privsep refactor splits odhcp6c into a privileged monitor and an
# unprivileged, seccomp-confined worker. All ubus work lives in the worker:
# ubus_init() connects + registers the object as root, BEFORE drop_privileges()
# and seccomp_apply(); every *runtime* ubus syscall (the method dispatch, the
# renew/release SIGUSR raises, and crucially the reconnect path's socket()+
# connect()) then runs AFTER the seccomp filter is installed. The default harness
# images build WITHOUT ubus, so that reconciliation was never actually executed.
# This scenario closes that gap on a -DUBUS=ON image.
#
# What it proves
# --------------
#   1. Connected: the worker registers "odhcp6c.<iface>" and serves `ubus call
#      ... renew`, which raises SIGUSR1 -> a renew -> an 'updated' record. That
#      one call exercises recvmsg/sendmsg/writev + raise(->tgkill) under seccomp.
#   2. Disconnect: killing ubusd makes the worker run ubus_disconnect_cb ->
#      ubus_reconnect(), i.e. socket()+connect() AFTER seccomp. If those weren't
#      allow-listed the worker would be killed (fail-closed) -- so the worker
#      logging "Cannot reconnect to ubus" and STAYING ALIVE is the proof the
#      reconnect syscalls are permitted. A direct SIGUSR1 to the worker then
#      yields a second 'updated', proving the DHCPv6 state machine is unharmed by
#      the ubus loss.
#   3. Reconnect: ubusd is brought back. This is best-effort only -- there is a
#      known, separately-tracked deferred bug (the worker's poll loop keeps the
#      stale ubus fd after a reconnect, and a disconnect that destroys the ctx is
#      never retried), so this scenario deliberately does NOT assert the object
#      re-registers. It only asserts the worker survives the whole cycle.
#   4. Seccomp: with ODHCP6C_SECCOMP_DIAG=1 a blocked syscall is trapped and
#      logged as "seccomp-diag: blocked syscall=<n>" instead of killing the
#      worker. The scenario asserts NO such line appears across the entire ubus
#      lifecycle -- the empirical seccomp reconciliation.
#
# Self-gating: ubus is an optional build. If the binary under test was built
# without ubus, or ubusd/ubus are not installed, the scenario SKIPS cleanly (it
# passes with a note) so it is safe to run anywhere. A binary that HAS ubus but
# no ubusd is a broken image (the binary would NULL-deref at startup), so that
# combination is a hard error rather than a skip.

# shellcheck disable=SC1090,SC1091
. "$HARNESS_LIB_DIR/ubus.sh"

HARNESS_UBUS_SKIP=0

scenario_backend() {
	# Long default T1/T2 (300/500) relative to the run window, so the only renews
	# are the ones we trigger -- no spontaneous T1 renew can race in a misleading
	# 'updated'. Mirrors privsep-signals' backend.
	echo "scapy serve --respond-rs --interval 1 \
--prefix 2001:db8:1:: \
--address 2001:db8:1::1000 --pd-prefix 2001:db8:abcd:: --pd-len 56 \
--dns 2001:db8:1::53 --domains example.test"
}

scenario_odhcp6c() {
	# Request a prefix so a real lease (hence renewable state) is in play.
	echo "-l7 -P 56 $HARNESS_VETH_CLIENT"
}

scenario_setup() {
	if ! harness_odhcp6c_has_ubus; then
		HARNESS_UBUS_SKIP=1
		warn "odhcp6c built without ubus; skipping ubus-reconnect scenario"
		return 0
	fi
	# The broker itself is started by the harness (harness_ubus_autostart) before
	# odhcp6c, exactly as ubusd is already running on OpenWrt. This scenario only
	# drives that broker through a disconnect/reconnect cycle in scenario_drive.
}

scenario_teardown() {
	# The harness owns the broker lifecycle (it stops ubusd itself); only the
	# subscriber this scenario spawned needs cleaning up here.
	harness_ubus_subscribe_stop
}

# Number of captured 'updated' records so far (each renew that reaches the script
# produces exactly one). Used to wait for a *new* update rather than re-observing
# an earlier one.
_ubus_updated_count() {
	grep -l '^ACTION=updated$' "$HARNESS_CAPTURE"/rec.* 2>/dev/null | wc -l | tr -d ' '
}

_ubus_updated_at_least() {
	[ "$(_ubus_updated_count)" -ge "$1" ]
}

scenario_drive() {
	[ "$HARNESS_UBUS_SKIP" = 1 ] && return 0

	wait_for_action bound "${HARNESS_TIMEOUT:-30}" \
		|| fatal "odhcp6c did not reach 'bound'"

	if harness_odhcp6c_privsep_active; then
		info "privsep active: monitor=$(harness_odhcp6c_role_pid monitor) worker=$(harness_odhcp6c_role_pid worker)"
	else
		info "single-process mode (no distinct monitor/worker)"
	fi

	# (1) Connected: object visible + a method round-trip that renews.
	harness_ubus_wait_object 10 \
		|| fatal "odhcp6c object $(harness_ubus_object_name) never appeared on the bus"
	harness_ubus_subscribe_bg
	harness_ubus call "$(harness_ubus_object_name)" renew \
		|| fatal "ubus call renew failed while connected"
	wait_for 15 "first 'updated' from ubus renew" _ubus_updated_at_least 1 \
		|| fatal "no 'updated' after ubus call renew (method dispatch broken under seccomp?)"

	# (2) Disconnect: kill the broker and leave it down. The worker must run the
	# reconnect path (socket()+connect() under seccomp), fail gracefully, and
	# survive. Stop the subscriber first so it does not race the broker death.
	harness_ubus_subscribe_stop
	harness_ubusd_stop
	wait_for_log "Cannot reconnect to ubus" 15 \
		|| fatal "worker did not run/return from the ubus reconnect path after broker death (seccomp kill?)"
	harness_odhcp6c_running \
		|| fatal "worker did not survive ubus broker death"

	# Worker still drives DHCPv6 after losing ubus: a direct SIGUSR1 renews again.
	harness_odhcp6c_signal_role worker USR1 \
		|| fatal "could not signal worker with SIGUSR1 after ubus loss"
	wait_for 15 "second 'updated' after post-disconnect SIGUSR1" _ubus_updated_at_least 2 \
		|| fatal "worker did not renew after ubus loss (state machine harmed?)"

	# (3) Reconnect: bring the broker back. Best-effort only -- see the header note
	# on the deferred stale-fd bug; we do NOT assert re-registration. A best-effort
	# renew call may legitimately not be serviced.
	harness_ubusd_restart
	if harness_ubus_wait_object 5; then
		info "object re-registered after broker restart"
		harness_ubus call "$(harness_ubus_object_name)" renew >/dev/null 2>&1 || true
	else
		info "object not re-registered after broker restart (known deferred reconnect bug; not asserted)"
	fi

	# Stop odhcp6c gracefully so the release-on-stop path runs before asserting.
	harness_odhcp6c_stop_monitor
}

scenario_assert() {
	if [ "$HARNESS_UBUS_SKIP" = 1 ]; then
		assert_pass "ubus-reconnect skipped (no ubus in this build/image)"
		return 0
	fi

	# Connected + post-disconnect renews both reached the script.
	harness_assert_action_seen bound
	if [ "$(_ubus_updated_count)" -ge 2 ]; then
		assert_pass "two 'updated' records (ubus renew + post-disconnect SIGUSR1)"
	else
		assert_fail "expected >=2 'updated' records, saw $(_ubus_updated_count)"
	fi

	# The worker ran the reconnect path and survived the broker death.
	harness_assert_log "Cannot reconnect to ubus" "worker ran ubus reconnect path after broker death"

	# Seccomp reconciliation: the worker filter must cover every ubus syscall. With
	# ODHCP6C_SECCOMP_DIAG=1 a missing syscall traps and logs the line below; its
	# absence across the full ubus lifecycle is the empirical proof of coverage.
	if grep -Eq 'seccomp-diag: blocked syscall=' "$HARNESS_WORKDIR/odhcp6c.log"; then
		_blk=$(grep -E 'seccomp-diag: blocked syscall=' "$HARNESS_WORKDIR/odhcp6c.log" | sort -u | tr '\n' ' ')
		assert_fail "seccomp blocked ubus syscall(s): $_blk"
	else
		assert_pass "no ubus syscall blocked by seccomp"
	fi

	# When the diagnostic was requested, prove it actually reached the worker (so
	# the assertion above is meaningful and not vacuously green on a build where
	# the env var was dropped). Only checked if seccomp is compiled in.
	if [ "${ODHCP6C_SECCOMP_DIAG:-}" = "1" ] \
		&& grep -q "seccomp: worker syscall filter active" "$HARNESS_WORKDIR/odhcp6c.log"; then
		harness_assert_log "DIAGNOSTIC trap mode" "ODHCP6C_SECCOMP_DIAG reached the worker"
	fi
}
