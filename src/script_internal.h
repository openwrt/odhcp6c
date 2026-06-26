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
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "script.h"

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

/*
 * Pure, side-effect-free codec for the worker<->monitor request datagram
 * (script_codec.c). These functions touch no sockets, no globals, do not fork
 * and never exec; they operate purely on caller buffers so the privileged
 * parser can be unit-tested and fuzzed in isolation. The wire format is the one
 * documented in script.h.
 */

/*
 * Reason codes returned by script_req_decode(). 0 means accept; every reject is
 * a distinct negative value so callers can log exactly why a datagram was
 * dropped. Map to text with script_req_strerror().
 */
enum script_req_reason {
	SCRIPT_REQ_OK = 0,
	SCRIPT_REQ_ERR_SHORT = -1,		/* datagram smaller than the header */
	SCRIPT_REQ_ERR_MAGIC = -2,		/* bad magic sentinel */
	SCRIPT_REQ_ERR_PADDING = -3,		/* non-zero reserved padding */
	SCRIPT_REQ_ERR_RESUME = -4,		/* resume flag not 0/1 */
	SCRIPT_REQ_ERR_CAPS = -5,		/* a length field exceeds its hard cap */
	SCRIPT_REQ_ERR_SIZE = -6,		/* datagram size != declared layout */
	SCRIPT_REQ_ERR_ACTION = -7,		/* action not on the allow-list */
	SCRIPT_REQ_ERR_ENV_UNTERMINATED = -8,	/* env entry missing its NUL */
	SCRIPT_REQ_ERR_ENV_INVALID = -9,	/* env entry rejected by sanitizer */
	SCRIPT_REQ_ERR_ENV_TRAILING = -10,	/* declared bytes not fully consumed */
	SCRIPT_REQ_ERR_ENV_CAP = -11,		/* env_count exceeds caller array */
};

/* Human-readable text for a script_req_decode() reason code. */
const char *script_req_strerror(int reason);

/*
 * Serialize a request into out[0..outcap). Returns the number of bytes written,
 * or -1 if out is NULL, the message would not fit, or the inputs exceed the
 * SCRIPT_ENV_* hard caps (the same caps the decoder enforces). Reads are bounded
 * (strnlen), so a non-NUL-terminated entry is rejected rather than over-read.
 * Produces byte-for-byte the same datagram the worker has always sent for
 * already-capped input; performs no I/O.
 */
ssize_t script_req_encode(uint8_t *out, size_t outcap,
		const char *action, int delay, bool resume,
		char *const *env, size_t envc);

/*
 * Validate one request datagram and, on success, fill the caller's buffers:
 *   - out_hdr     the parsed (and bounds-checked) header;
 *   - action      the NUL-terminated action string (<= SCRIPT_ACTION_MAX);
 *   - env_out     up to env_cap pointers to the re-sanitized "NAME=value"
 *                 entries (which point into buf);
 *   - env_count_out  number of env entries written.
 * Returns SCRIPT_REQ_OK (0) on accept or a negative script_req_reason on reject;
 * never forks or execs. buf is mutable because each env entry is re-sanitized in
 * place (the same defense-in-depth gate the monitor has always applied); the
 * caller owns buf and must keep it alive while the env_out pointers are used.
 */
int script_req_decode(uint8_t *buf, size_t len,
		struct script_req *out_hdr, char action[SCRIPT_ACTION_MAX + 1],
		char **env_out, size_t env_cap, size_t *env_count_out);

#endif /* ODHCP6C_SCRIPT_INTERNAL_H */
