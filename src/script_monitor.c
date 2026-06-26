/**
 * Copyright (C) 2012-2014 Steven Barth <steven@midlink.org>
 * Copyright (C) 2017-2018 Hans Dedecker <dedeckeh@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

/*
 * Privileged (root) monitor: the trusted compute base of the privilege-
 * separation design. It never trusts the unprivileged worker. It owns the
 * script path and argv; for every request datagram it re-validates the magic,
 * the padding, every length field, the exact datagram size, the action against
 * a hard-coded allow-list, and re-sanitizes every "NAME=value" entry before
 * exec. It consults NO client state and contains NO env-building code from the
 * presentation layer — that separation is the point, so a reviewer can audit
 * this file in isolation.
 */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "odhcp6c.h"
#include "script.h"
#include "script_internal.h"

/*
 * The exact set of actions odhcp6c emits today (from the notify_state_change()
 * call sites). The monitor only ever runs the script with one of these; any
 * other action from the worker is rejected.
 */
static const char *const script_actions[] = {
	"started", "bound", "informed", "ra-updated",
	"updated", "rebound", "unbound", "stopped",
};

static bool script_action_allowed(const char *act, size_t len)
{
	if (len == 0 || len > SCRIPT_ACTION_MAX)
		return false;

	for (size_t i = 0; i < sizeof(script_actions) / sizeof(script_actions[0]); i++) {
		if (strlen(script_actions[i]) == len &&
				!memcmp(script_actions[i], act, len))
			return true;
	}

	return false;
}

static void monitor_sighandle(int signal)
{
	if (monitor_worker_pid <= 0)
		return;

	switch (signal) {
	case SIGUSR1:
	case SIGUSR2:
		/*
		 * Reconfiguration signals (renew/rebind) are handled by the
		 * worker, which owns the DHCPv6 state machine. Forward them so
		 * that callers (e.g. init scripts) signalling the launcher PID
		 * reach the worker in privsep mode.
		 */
		kill(monitor_worker_pid, signal);
		break;
	default:
		/*
		 * Ask the worker to begin its graceful DHCPV6_EXIT/RELEASE
		 * path. The worker's final notifications arrive over the
		 * channel and the monitor exits once the channel reaches EOF.
		 */
		kill(monitor_worker_pid, SIGTERM);
		break;
	}
}

/*
 * In-child env step for the monitor: putenv() each already-re-validated
 * NAME=value entry from the request. No client state is consulted, so the
 * delay is unused here.
 */
struct monitor_env_ctx { char *const *envp; size_t envc; };

static void monitor_run_script_child(int delay, void *ctx)
{
	(void)delay;

	const struct monitor_env_ctx *e = ctx;

	for (size_t i = 0; i < e->envc; i++)
		putenv(e->envp[i]);
}

/*
 * Run the status script for an already validated request. Reuses the shared
 * script_spawn() bookkeeping (kill/replace a still-running script, delay
 * adjustment, action/resume handling, SIGCHLD discipline) but runs as the
 * privileged monitor with a fixed script path/argv and a caller-supplied,
 * re-sanitized environment. No client state is consulted here.
 */
static void monitor_run_script(const char *act, int delay, bool resume,
		char *const *envp, size_t envc)
{
	struct monitor_env_ctx ctx = { .envp = envp, .envc = envc };

	script_spawn(act, delay, resume, monitor_run_script_child, &ctx);
}

/*
 * Validate one request datagram from the worker and, if everything checks out,
 * run the script. The monitor must not trust the worker: every length field is
 * bounded, the datagram size must match the declared layout exactly, the action
 * must be on the allow-list, and each environment entry is re-validated and
 * re-sanitized (name charset + value sanitizer) before use. Any failure rejects
 * the whole request without executing anything.
 */
static void monitor_handle_request(uint8_t *buf, size_t len)
{
	struct script_req req;

	if (len < sizeof(req)) {
		error("monitor: rejecting short request (%zu bytes)", len);
		return;
	}

	memcpy(&req, buf, sizeof(req));

	if (req.magic != SCRIPT_REQ_MAGIC) {
		error("monitor: rejecting request with bad magic");
		return;
	}

	if (req.pad[0] || req.pad[1] || req.pad[2]) {
		error("monitor: rejecting request with non-zero padding");
		return;
	}

	/* resume is a boolean in the IPC contract; reject anything but 0/1. */
	if (req.resume > 1) {
		error("monitor: rejecting request with invalid resume value");
		return;
	}

	if (req.action_len > SCRIPT_ACTION_MAX ||
			req.env_count > SCRIPT_ENV_MAX_COUNT ||
			req.env_total > SCRIPT_ENV_MAX_TOTAL) {
		error("monitor: rejecting request exceeding hard caps");
		return;
	}

	/* The datagram size must match the declared layout exactly. */
	if (len != sizeof(req) + req.action_len + req.env_total) {
		error("monitor: rejecting request with inconsistent size");
		return;
	}

	char action_buf[SCRIPT_ACTION_MAX + 1];
	memcpy(action_buf, buf + sizeof(req), req.action_len);
	action_buf[req.action_len] = '\0';

	if (!script_action_allowed(action_buf, req.action_len)) {
		error("monitor: rejecting unknown action");
		return;
	}

	/* Parse and re-validate the environment entries. */
	char **envp = NULL;
	size_t envc = 0;
	bool ok = true;

	if (req.env_count > 0) {
		envp = calloc(req.env_count, sizeof(*envp));
		if (!envp) {
			error("monitor: out of memory handling request");
			return;
		}
	}

	uint8_t *env = buf + sizeof(req) + req.action_len;
	uint8_t *eend = env + req.env_total;
	uint8_t *p = env;

	for (size_t i = 0; i < req.env_count; i++) {
		uint8_t *nul = memchr(p, '\0', (size_t)(eend - p));

		if (!nul) {
			error("monitor: rejecting request with unterminated env entry");
			ok = false;
			break;
		}

		char *entry = (char *)p;

		/* Re-apply the H-3 sanitizer; reject on invalid NAME. */
		if (!script_sanitize_env(entry)) {
			error("monitor: rejecting request with invalid env entry");
			ok = false;
			break;
		}

		envp[envc++] = entry;
		p = nul + 1;
	}

	/* Every declared byte must be consumed by exactly env_count entries. */
	if (ok && (envc != req.env_count || p != eend)) {
		error("monitor: rejecting request with trailing env bytes");
		ok = false;
	}

	if (ok) {
		int delay = req.delay;

		if (delay < 0)
			delay = 0;
		else if (delay > SCRIPT_DELAY_MAX)
			delay = SCRIPT_DELAY_MAX;

		monitor_run_script(action_buf, delay, req.resume != 0,
				envp, envc);
	}

	free(envp);
}

int script_monitor_loop(int fd, const char *script, const char *ifname,
		pid_t worker_pid)
{
	static uint8_t buf[sizeof(struct script_req) + SCRIPT_ACTION_MAX +
			SCRIPT_ENV_MAX_TOTAL];

	/* The monitor owns the script path and argv; they never come from the
	 * worker. script_init() already populated them, but assert it here. */
	script_child.argv[0] = (char *)script;
	script_child.argv[1] = (char *)ifname;
	monitor_worker_pid = worker_pid;

	/*
	 * The caller blocked SIGCHLD across the fork so a fast-exiting worker
	 * could not be reaped before monitor_worker_pid was set above. It is
	 * now safe to deliver any pending SIGCHLD.
	 */
	sigset_t chld_mask;

	sigemptyset(&chld_mask);
	sigaddset(&chld_mask, SIGCHLD);
	sigprocmask(SIG_UNBLOCK, &chld_mask, NULL);

	/*
	 * Forward termination and reconfiguration signals to the worker; the
	 * worker owns the DHCPv6 state machine and the SIGUSR1/SIGUSR2 handlers
	 * (renew/rebind), so init scripts signalling the launcher PID still
	 * reach it in privsep mode.
	 */
	signal(SIGTERM, monitor_sighandle);
	signal(SIGINT, monitor_sighandle);
	signal(SIGHUP, monitor_sighandle);
	signal(SIGUSR1, monitor_sighandle);
	signal(SIGUSR2, monitor_sighandle);
	signal(SIGIO, SIG_IGN);
	/* SIGCHLD is reaped by script_sighandle(), installed in script_init(). */

	for (;;) {
		ssize_t n = recv(fd, buf, sizeof(buf), 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;

			error("monitor: recv failed: %s", strerror(errno));
			break;
		}

		if (n == 0)
			break;	/* worker closed the channel */

		monitor_handle_request(buf, (size_t)n);
	}

	/*
	 * Worker is gone: stop any running script and reap remaining children.
	 * The SIGCHLD handler (script_sighandle) performs the actual reaping; it
	 * clears 'running' for script children and records the worker's exit
	 * status in monitor_worker_status/monitor_worker_reaped.
	 *
	 * The in-flight child is normally the final 'stopped' notification
	 * script: the worker emits 'unbound' then 'stopped' and immediately
	 * closes the channel, so the monitor can reach here while that last
	 * script is still starting up. Wait for it to finish on its own first
	 * -- killing it outright would drop the terminal notification (observed
	 * as a lost 'stopped' under fast-exiting libc/timing, e.g. musl). Only
	 * if it overruns the drain budget do we escalate to SIGTERM, then
	 * SIGKILL, so a script that ignores signals still cannot wedge daemon
	 * shutdown. Every wait stays bounded, mirroring script_drain_running().
	 */
	for (int waited = 0; script_child.running > 0 &&
			waited < SCRIPT_DRAIN_TIMEOUT_MS; waited += 10)
		script_sleep_ms(10);

	pid_t script_pid = script_child.running;
	if (script_pid > 0) {
		kill(script_pid, SIGTERM);

		for (int waited = 0; script_child.running > 0 &&
				waited < SCRIPT_DRAIN_TIMEOUT_MS; waited += 10)
			script_sleep_ms(10);
	}

	script_pid = script_child.running;
	if (script_pid > 0) {
		kill(script_pid, SIGKILL);

		for (int waited = 0; script_child.running > 0 &&
				waited < SCRIPT_DRAIN_TIMEOUT_MS; waited += 10)
			script_sleep_ms(10);
	}

	/* Bounded wait for the worker to exit so we can return its status. */
	for (int waited = 0; !monitor_worker_reaped &&
			waited < SCRIPT_DRAIN_TIMEOUT_MS; waited += 10)
		script_sleep_ms(10);

	/*
	 * Default to a non-zero status: if the worker is never observed exiting
	 * (it hung past the bounded wait, or neither the WNOHANG sweep nor the
	 * SIGCHLD handler captured it), reporting failure is safer than a false
	 * success. The real status overwrites this once the worker is reaped.
	 */
	int status_code = 1;
	int st;
	pid_t w;

	/* Sweep up any children the SIGCHLD handler has not yet collected. */
	while ((w = waitpid(-1, &st, WNOHANG)) > 0) {
		if (w == worker_pid)
			status_code = WIFEXITED(st) ? WEXITSTATUS(st) : 1;
		else if (w == script_child.running)
			script_child.running = 0;
	}

	/* If the SIGCHLD handler already reaped the worker, use the status it
	 * captured rather than the result of the loop above (which would have
	 * missed it). */
	if (monitor_worker_reaped)
		status_code = WIFEXITED(monitor_worker_status) ?
				WEXITSTATUS(monitor_worker_status) : 1;

	close(fd);

	return status_code;
}
