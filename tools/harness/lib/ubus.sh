# shellcheck shell=sh
#
# ubus.sh - harness helpers for driving a ubusd instance and the ubus CLI
# alongside odhcp6c, so the ubus-reconnect scenario can exercise the ubus code
# path under privsep + seccomp.
#
# Why this lives apart from common.sh: ubus is an optional build of odhcp6c
# (-DUBUS=ON). The harness images build it in by default, but it can be built out
# with --build-arg UBUS=OFF. Only the ubus-reconnect scenario sources this file,
# and it self-gates on the helpers below so it is a clean no-op (skip) wherever
# ubusd / a ubus-enabled binary are absent.
#
# Transport note: ubus uses a filesystem UNIX socket (default
# /var/run/ubus/ubus.sock), not the network, so ubusd runs on the host while
# odhcp6c runs inside the client netns -- the mount namespace (hence the socket
# path) is shared, so they still reach each other. ubusd is therefore NOT started
# with `ip netns exec`.

# Compiled-in default socket path used by both ubusd and libubus' ubus_connect(NULL).
: "${HARNESS_UBUS_SOCKET:=/var/run/ubus/ubus.sock}"

HARNESS_UBUSD_PID=""
HARNESS_UBUS_SUB_PID=""
HARNESS_UBUS_ACL_DIR=""

# True when both ubusd (the broker) and the ubus CLI are on PATH. Without these
# the scenario cannot run and must skip.
harness_ubus_tooling_present() {
	command -v ubusd >/dev/null 2>&1 && command -v ubus >/dev/null 2>&1
}

# True when the odhcp6c under test was built WITH_UBUS. Detect by the linked
# libubus DT_NEEDED entry (authoritative), falling back to a string marker that
# only the ubus translation unit emits. A no-ubus binary fails both, so the
# scenario skips instead of starting a binary that never registers an object.
harness_odhcp6c_has_ubus() {
	[ -n "${HARNESS_ODHCP6C:-}" ] || return 1
	if command -v readelf >/dev/null 2>&1; then
		readelf -d "$HARNESS_ODHCP6C" 2>/dev/null | grep -q 'NEEDED.*libubus' && return 0
	fi
	if command -v strings >/dev/null 2>&1; then
		strings "$HARNESS_ODHCP6C" 2>/dev/null | grep -q 'Disconnecting from ubus' && return 0
	fi
	return 1
}

# Ensure a baseline ubus broker for the binary under test, called once by
# run-scenario.sh before odhcp6c starts. A WITH_UBUS odhcp6c calls ubus_connect()
# during init and cannot run without a listening broker -- ubus_init() returns
# NULL and the caller then dereferences the NULL context -- so EVERY scenario
# needs a ubusd when the binary has ubus, exactly as ubusd is always running on
# OpenWrt. On a no-ubus build (UBUS=OFF) this is a clean no-op so the non-ubus
# scenarios still run. The ubus-reconnect scenario drives this same broker through
# its disconnect/reconnect cycle; all other scenarios just register their object
# against it. Idempotent (harness_ubusd_start returns early if already running).
harness_ubus_autostart() {
	harness_odhcp6c_has_ubus || return 0
	harness_ubus_tooling_present \
		|| fatal "odhcp6c built WITH ubus but ubusd/ubus not installed in image"
	harness_ubusd_start
}

# The object name odhcp6c registers: "odhcp6c.<interface>" (src/ubus.c ubus_init).
harness_ubus_object_name() {
	printf 'odhcp6c.%s\n' "$HARNESS_VETH_CLIENT"
}

# Thin wrapper so every ubus CLI call targets the harness socket explicitly and
# runs with the same privilege as ubusd (root). Returns the CLI's own status.
harness_ubus() {
	$SUDO ubus -s "$HARNESS_UBUS_SOCKET" "$@"
}

# ubusd refuses object registration ("publish") from a non-root client unless an
# ACL grants it (ubusd_obj.c -> ubusd_acl_check(UBUS_ACL_PUBLISH); a root client,
# uid 0, bypasses the check). odhcp6c's initial ubus_init() registers as root,
# BEFORE drop_privileges(), so it slips through -- but the privsep worker
# reconnects as 'nobody' AFTER the drop, and ubusd then silently denies the
# re-publish (libubus ignores the add_object error), so the object never reappears
# on the bus after a broker restart. A real OpenWrt deployment grants this via an
# /usr/share/acl.d file; mirror that here with a throwaway ACL dir handed to ubusd
# via -A. ubusd requires each *.json to be owned root:root and to be neither
# group/other-writable nor other-executable, so it is written 0644 as root.
harness_ubus_acl_prepare() {
	HARNESS_UBUS_ACL_DIR="${HARNESS_WORKDIR:-/tmp}/ubus-acl.d"
	$SUDO mkdir -p "$HARNESS_UBUS_ACL_DIR" \
		|| fatal "ubus acl: cannot create $HARNESS_UBUS_ACL_DIR"
	printf '%s\n' \
		'{' \
		'	"user": "nobody",' \
		'	"publish": [ "odhcp6c.*" ]' \
		'}' \
		| $SUDO tee "$HARNESS_UBUS_ACL_DIR/odhcp6c.json" >/dev/null \
		|| fatal "ubus acl: cannot write odhcp6c.json"
	$SUDO chown 0:0 "$HARNESS_UBUS_ACL_DIR/odhcp6c.json" 2>/dev/null || true
	$SUDO chmod 0644 "$HARNESS_UBUS_ACL_DIR/odhcp6c.json" \
		|| fatal "ubus acl: cannot chmod odhcp6c.json"
}

# Start ubusd on the default socket and wait for it to listen. ubusd hardcodes
# creating the socket's parent dir and needs root for it, so this runs under
# $SUDO; the harness already runs as root in CI. Records the PID for stop/restart.
harness_ubusd_start() {
	[ -z "$HARNESS_UBUSD_PID" ] || return 0

	_sockdir=$(dirname "$HARNESS_UBUS_SOCKET")
	$SUDO mkdir -p "$_sockdir" || fatal "ubusd: cannot create $_sockdir"
	# A stale socket from a crashed prior run makes ubusd fail to bind.
	$SUDO rm -f "$HARNESS_UBUS_SOCKET" 2>/dev/null || true

	# Authorize the unprivileged worker to (re-)register its object post-drop.
	harness_ubus_acl_prepare

	$SUDO ubusd -A "$HARNESS_UBUS_ACL_DIR" -s "$HARNESS_UBUS_SOCKET" \
		> "$HARNESS_WORKDIR/ubusd.log" 2>&1 &
	HARNESS_UBUSD_PID=$!

	if ! wait_for 10 "ubusd socket $HARNESS_UBUS_SOCKET" \
		harness_ubusd_socket_present; then
		harness_ubusd_stop
		fatal "ubusd did not create $HARNESS_UBUS_SOCKET"
	fi
	log "ubusd up (pid $HARNESS_UBUSD_PID) on $HARNESS_UBUS_SOCKET"
}

harness_ubusd_socket_present() {
	$SUDO test -S "$HARNESS_UBUS_SOCKET"
}

# Stop ubusd if running. Idempotent: safe from scenario_teardown and a trap.
harness_ubusd_stop() {
	[ -n "$HARNESS_UBUSD_PID" ] || return 0
	$SUDO kill "$HARNESS_UBUSD_PID" 2>/dev/null || true
	wait "$HARNESS_UBUSD_PID" 2>/dev/null || true
	$SUDO rm -f "$HARNESS_UBUS_SOCKET" 2>/dev/null || true
	log "ubusd stopped (pid $HARNESS_UBUSD_PID)"
	HARNESS_UBUSD_PID=""
}

# Restart ubusd to model the broker coming back after an outage.
harness_ubusd_restart() {
	harness_ubusd_stop
	harness_ubusd_start
}

# Wait (bounded) until odhcp6c's object is visible on the bus.
harness_ubus_wait_object() {
	_obj=$(harness_ubus_object_name)
	wait_for "${1:-10}" "ubus object $_obj" harness_ubus_object_present "$_obj"
}

harness_ubus_object_present() {
	harness_ubus list 2>/dev/null | grep -qx "$1"
}

# Subscribe to the object's notifications in the background, appending to a log
# the scenario can inspect. Best-effort: notifications are not load-bearing for
# the seccomp reconciliation, so failure here is non-fatal.
harness_ubus_subscribe_bg() {
	_obj=$(harness_ubus_object_name)
	$SUDO ubus -s "$HARNESS_UBUS_SOCKET" subscribe "$_obj" \
		> "$HARNESS_WORKDIR/ubus-notify.log" 2>&1 &
	HARNESS_UBUS_SUB_PID=$!
}

harness_ubus_subscribe_stop() {
	[ -n "$HARNESS_UBUS_SUB_PID" ] || return 0
	$SUDO kill "$HARNESS_UBUS_SUB_PID" 2>/dev/null || true
	wait "$HARNESS_UBUS_SUB_PID" 2>/dev/null || true
	HARNESS_UBUS_SUB_PID=""
}
