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
 * Shared core of the status-script machinery. It holds the small amount of
 * state and the few primitives used by BOTH the unprivileged worker
 * (script_worker.c) and the privileged monitor (script_monitor.c): the single
 * place that forks a script child, the SIGCHLD reaping discipline, the env
 * sanitizer, and process init. Keeping these here lets the worker and monitor
 * be audited independently without duplicating the subtle fork/signal logic.
 */

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "odhcp6c.h"
#include "script.h"
#include "script_internal.h"

/* The single shared launch-bookkeeping instance (see script_internal.h). */
struct script_child script_child = {
	.running = 0,
	.started_delay = 0,
	.action = "",
	.argv = { NULL, NULL, NULL, NULL },
};

/*
 * Pid of the worker, used by the monitor to forward termination signals.
 * Because the SIGCHLD handler reaps every child (to avoid leaking zombies of
 * replaced script children), it can reap the worker before the monitor's final
 * waitpid() loop runs. To avoid losing the worker's exit status it is captured
 * here when the handler reaps it, and the monitor loop falls back to this value.
 */
volatile pid_t monitor_worker_pid = 0;
volatile int monitor_worker_status = 0;
volatile sig_atomic_t monitor_worker_reaped = 0;

void script_child_init(void)
{
	/*
	 * argv[2] aliases action[]: the action is latched in place by
	 * script_spawn() and is therefore already wired into the child's argv
	 * by the time execv() runs. Establish (and document) that alias here;
	 * nothing else may rebuild argv[2].
	 */
	script_child.argv[2] = script_child.action;
	script_child.argv[3] = NULL;
}

static void script_sighandle(int signal)
{
	if (signal == SIGCHLD) {
		pid_t child;
		int status;

		while ((child = waitpid(-1, &status, WNOHANG)) > 0) {
			if (monitor_worker_pid > 0 && child == monitor_worker_pid) {
				/* Preserve the worker's status for the monitor
				 * loop instead of discarding it here. */
				monitor_worker_status = status;
				monitor_worker_reaped = 1;
			} else if (script_child.running == child)
				script_child.running = 0;
		}
	}
}

/*
 * Sleep for the full requested interval. nanosleep() can return early with
 * EINTR when a signal is delivered; retry with the remaining time so callers
 * that poll on a wall-clock budget do not advance their counters without
 * actually waiting (which would shorten the drain timeout).
 */
void script_sleep_ms(long ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000L * 1000 };

	while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
		;
}

/*
 * Block SIGCHLD so the handler cannot run (and reap a just-forked script
 * child) between fork() and the bookkeeping that records the child's pid in
 * script_child.running. Without this a fast-exiting child can be reaped before
 * 'running' is set, leaving a stale pid that is never cleared. The previous
 * mask is returned via *omask so the caller can restore it.
 */
static void script_block_sigchld(sigset_t *omask)
{
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, omask);
}

/*
 * Wait (bounded) for the in-flight script child to exit so its status
 * notification is delivered before the next script starts. The SIGCHLD handler
 * reaps the child and clears script_child.running. This is used when a previous
 * script has already moved past its scheduled delay and begun executing:
 * cancelling it would silently drop a notification (e.g. the terminal "unbound"
 * -> "stopped" sequence on shutdown). A misbehaving script must not wedge the
 * caller, so fall back to SIGTERM after the timeout.
 */
static void script_drain_running(void)
{
	for (int waited = 0; script_child.running > 0 &&
			waited < SCRIPT_DRAIN_TIMEOUT_MS; waited += 10)
		script_sleep_ms(10);

	/*
	 * Snapshot 'running' before signalling. The SIGCHLD handler can clear
	 * it to 0 between the test and the kill(); passing 0 to kill() would
	 * signal the entire process group instead of just the script child.
	 */
	pid_t pid = script_child.running;
	if (pid > 0)
		kill(pid, SIGTERM);
}

int script_init(const char *path, const char *ifname)
{
	script_child_init();
	script_child.argv[0] = (char*)path;
	script_child.argv[1] = (char*)ifname;
	signal(SIGCHLD, script_sighandle);

	return 0;
}

/*
 * The single place that forks a script child. Both the single-process worker
 * (script_call) and the privileged monitor (monitor_run_script) delegate here
 * so the subtle fork/signal bookkeeping lives in exactly one spot and the two
 * paths can never drift.
 *
 * The shared bookkeeping is:
 *   - supersede-or-drain a still-running script: if the previous child is still
 *     in its pre-exec delay window a newer state supersedes it (SIGTERM + delay
 *     inheritance = state batching); an already-executing one is drained so its
 *     notification (e.g. the terminal unbound -> stopped sequence) is not lost;
 *   - latch the action into the shared action[] buffer (resume/replace rules);
 *   - block SIGCHLD across fork() so the handler cannot reap the child before
 *     'running' is recorded, and snapshot it in the parent;
 *   - in the child, reset SIGTERM, sleep out the delay, then run the
 *     caller-supplied env step before execv.
 *
 * The only real difference between the two callers is what the child does to
 * prepare its environment immediately before execv; that is supplied via
 * child_setup(delay, ctx) so the rest stays identical.
 */
void script_spawn(const char *act, int delay, bool resume,
		void (*child_setup)(int delay, void *ctx), void *ctx)
{
	time_t now = odhcp6c_get_milli_time() / 1000;
	bool running_script = false;

	pid_t prev = script_child.running;
	if (prev > 0) {
		time_t diff = now - script_child.started;

		if (diff < script_child.started_delay) {
			/* Still in its pre-exec delay window: a newer state
			 * supersedes it, so cancel and replace it (state
			 * batching). */
			kill(prev, SIGTERM);

			if (diff > delay)
				delay -= diff;
			else
				delay = 0;

			running_script = true;
		} else {
			/* Already executing: let it finish so its notification
			 * is not lost (e.g. the terminal unbound -> stopped
			 * sequence) before starting the next one. */
			script_drain_running();
		}
	}

	if (resume || !running_script || !script_child.action[0]) {
		strncpy(script_child.action, act, sizeof(script_child.action) - 1);
		script_child.action[sizeof(script_child.action) - 1] = '\0';
	}

	sigset_t omask;
	script_block_sigchld(&omask);

	pid_t pid = fork();

	if (pid < 0) {
		error("Failed to fork script handler: %s", strerror(errno));
		/*
		 * Leave 'running' unchanged: a previous script child may still be
		 * in-flight (script_drain_running() can return after SIGTERM while
		 * the child is still exiting). Clearing it would drop that child
		 * from tracking and let the next request start an overlapping
		 * script without draining it first.
		 */
		sigprocmask(SIG_SETMASK, &omask, NULL);
		return;
	}

	if (pid > 0) {
		script_child.running = pid;
		script_child.started = now;
		script_child.started_delay = delay;

		if (!resume)
			script_child.action[0] = 0;

		sigprocmask(SIG_SETMASK, &omask, NULL);
	} else if (pid == 0) {
		sigprocmask(SIG_SETMASK, &omask, NULL);
		signal(SIGTERM, SIG_DFL);
		if (delay > 0)
			sleep(delay);

		child_setup(delay, ctx);

		execv(script_child.argv[0], script_child.argv);
		_exit(128);
	}
}

/*
 * Prepare an already-assembled "NAME=value" buffer that originates from
 * untrusted network input before it is exported to the environment of the
 * (root) status script.
 *
 * The variable NAME (the bytes before the first '=') is validated, not
 * rewritten. It is only accepted if it is a non-empty run of the portable
 * environment-variable charset ([A-Za-z_][A-Za-z0-9_]*). Silently rewriting an
 * invalid name could map a value onto an unexpected variable, so a missing or
 * invalid name causes the whole entry to be rejected: the function returns
 * false and the caller must not putenv() it. Rejecting a single entry (rather
 * than aborting the process) avoids handing an attacker a denial-of-service
 * trigger. The names used in this file are compile-time constants, so this is
 * defense in depth against future call sites.
 *
 * The value (the bytes after the first '=') is sanitized in place. DHCPv6
 * replies and ICMPv6 Router Advertisements are attacker-controlled, so option
 * payloads may contain newlines or other non-printable bytes. Any byte that is
 * not printable ASCII, or that could trigger shell quoting/expansion, is
 * replaced with '_'. This cannot remove embedded NUL bytes (they already
 * terminate the C string) and does not by itself guarantee shell-safety: the
 * consuming script must still quote variables.
 *
 * Returns true if the entry is safe to export, false if it must be discarded.
 */
bool script_sanitize_env(char *env)
{
	char *p = strchr(env, '=');

	/* A well-formed entry must have a non-empty NAME before the '='. */
	if (p == NULL || p == env)
		return false;

	/* Validate the NAME without modifying it. */
	for (char *n = env; n < p; n++) {
		unsigned char c = (unsigned char)*n;

		if (c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
			continue;
		/* Digits are allowed, but not as the first character. */
		if (n != env && c >= '0' && c <= '9')
			continue;

		return false;
	}

	/* Sanitize the value portion in place. */
	for (p++; *p; p++) {
		unsigned char c = (unsigned char)*p;

		/* Reject non-printable and non-ASCII bytes */
		if (c < 0x20 || c > 0x7e) {
			*p = '_';
			continue;
		}

		/* Reject shell-significant characters */
		switch (c) {
		case '`': case '$': case '\\': case '"': case '\'':
			*p = '_';
			break;
		default:
			/* Replace whitespace other than a single regular space */
			if (c != ' ' && isspace(c))
				*p = '_';
			break;
		}
	}

	return true;
}
