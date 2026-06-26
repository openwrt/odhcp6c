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

#ifndef ODHCP6C_SCRIPT_INTERNAL_H
#define ODHCP6C_SCRIPT_INTERNAL_H

#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

/*
 * Internal surface shared between the script translation units. It exists only
 * so the file can be split along the privilege-separation trust boundary
 * (presentation worker vs. root monitor vs. the small shared core) while
 * promoting the absolute minimum number of symbols out of file scope. Nothing
 * here is part of the public IPC contract in script.h.
 *
 *   - script_common.c  shared core: the single fork()ing helper, the child
 *                      bookkeeping, the SIGCHLD handler and the env sanitizer.
 *   - script_worker.c  unprivileged, network-facing env presentation + request
 *                      side.
 *   - script_monitor.c the privileged (root) TCB that re-validates and runs the
 *                      status script.
 */

/*
 * Upper bound (milliseconds) for draining a still-executing script child before
 * launching the next one, so a misbehaving script cannot wedge the caller.
 */
#define SCRIPT_DRAIN_TIMEOUT_MS 5000

/*
 * The launch bookkeeping for the at-most-one script child alive per process.
 * Previously these were scattered file-scope globals; bundling them makes
 * ownership unambiguous once the file is split across the trust boundary.
 *
 * argv[2] aliases action[]: the child's argv is {path, ifname, action, NULL}
 * and the action is latched in place in action[] so it is already wired into
 * argv before execv(). script_child_init() establishes that alias; nothing may
 * break it. running is volatile because the SIGCHLD handler clears it
 * asynchronously when the child is reaped.
 */
struct script_child {
	volatile pid_t running;
	time_t  started;
	int     started_delay;
	char    action[16];
	char   *argv[4];	/* argv[0]=path, argv[1]=ifname, argv[2]=action, argv[3]=NULL */
};

/* The single shared instance (one script child at a time per process). */
extern struct script_child script_child;

/* Wire argv[2] -> action[] (and argv[3]=NULL); call once before any spawn. */
void script_child_init(void);

/*
 * Worker pid, used by the monitor to forward termination signals. Because the
 * SIGCHLD handler reaps every child (to avoid leaking zombies of replaced
 * script children) it can reap the worker before the monitor's final waitpid()
 * loop runs, so the handler captures the worker's exit status here for the
 * monitor loop to fall back on.
 */
extern volatile pid_t monitor_worker_pid;
extern volatile int monitor_worker_status;
extern volatile sig_atomic_t monitor_worker_reaped;

/*
 * The single place that forks a script child. Both the worker (script_call) and
 * the monitor (monitor_run_script) delegate here so the subtle fork/signal
 * bookkeeping lives in exactly one spot. child_setup(delay, ctx) supplies the
 * only per-caller difference: the in-child env preparation just before execv.
 */
void script_spawn(const char *act, int delay, bool resume,
		void (*child_setup)(int delay, void *ctx), void *ctx);

/* Sleep for the full requested interval, retrying across EINTR. */
void script_sleep_ms(long ms);

/*
 * Validate/sanitize an already-assembled "NAME=value" buffer originating from
 * untrusted network input before it is exported to the (root) script's
 * environment. Returns true if the entry is safe to export, false if it must be
 * discarded. Used by the worker while building env and re-applied by the
 * monitor on every received entry.
 */
bool script_sanitize_env(char *env);

#endif /* ODHCP6C_SCRIPT_INTERNAL_H */
