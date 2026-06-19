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

#ifndef ODHCP6C_SCRIPT_H
#define ODHCP6C_SCRIPT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * Privilege-separation IPC contract between the unprivileged worker and the
 * privileged monitor.
 *
 * The worker performs all attacker-facing parsing and then asks the monitor to
 * run the status script for a given action with an already-formatted set of
 * environment strings. The monitor never trusts the worker: it owns the script
 * path and argv, matches the action against a hard-coded allow-list, and
 * re-validates/re-sanitizes every environment entry before exec.
 *
 * One request is one SOCK_SEQPACKET datagram laid out as:
 *
 *     struct script_req header
 *     action bytes            (header.action_len bytes, no trailing NUL)
 *     env_count NUL-terminated "NAME=value" strings, totaling env_total bytes
 */

/* Fixed sentinel ("o6ip"); any other value rejects the whole request. */
#define SCRIPT_REQ_MAGIC 0x6f366970u

/* Hard caps the monitor enforces on every request. */
#define SCRIPT_ACTION_MAX 16		/* max action length (excl. NUL) */
#define SCRIPT_ENV_MAX_COUNT 256	/* max number of env entries */
#define SCRIPT_ENV_MAX_TOTAL 65536	/* max total env bytes (incl. NULs) */
#define SCRIPT_ENV_ENTRY_MAX 4096	/* max length of one "NAME=value" (incl. NUL) */
#define SCRIPT_DELAY_MAX 600		/* delay clamp upper bound, seconds */

struct script_req {
	uint32_t magic;		/* SCRIPT_REQ_MAGIC */
	uint32_t action_len;	/* <= SCRIPT_ACTION_MAX */
	int32_t  delay;		/* clamped to [0, SCRIPT_DELAY_MAX] */
	uint8_t  resume;	/* forced to 0/1 */
	uint8_t  pad[3];	/* explicit padding, must be zero */
	uint32_t env_count;	/* <= SCRIPT_ENV_MAX_COUNT */
	uint32_t env_total;	/* <= SCRIPT_ENV_MAX_TOTAL */
};

/*
 * Worker side: register the socketpair end on which script requests are sent
 * to the monitor. A value >= 0 switches script_call() from fork+exec to
 * serialize+send. Passing -1 restores the in-process (single root) behavior.
 */
void script_set_channel(int fd);

/*
 * Monitor side: receive, validate and execute script requests from the worker
 * over fd until the worker closes the channel (EOF) or exits. The script path
 * and ifname are fixed here and never read from a request. worker_pid is the
 * pid of the worker, used for SIGTERM forwarding and final reaping. Returns the
 * process exit status to propagate.
 */
int script_monitor_loop(int fd, const char *script, const char *ifname,
		pid_t worker_pid);

#endif /* ODHCP6C_SCRIPT_H */
