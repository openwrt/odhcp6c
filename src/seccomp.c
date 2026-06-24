/**
 * Copyright (C) 2024 odhcp6c contributors
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

#include "odhcp6c_seccomp.h"

#ifdef WITH_SECCOMP

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <seccomp.h>

#include "odhcp6c.h"

/*
 * Default action for any syscall not explicitly allowed below. Prefer a hard
 * stop of the whole process (kernel >= 4.14, libseccomp >= 2.4). Fall back to
 * killing just the offending thread on toolchains that predate the macro; for
 * a single-threaded worker that is equivalent in practice.
 */
#ifdef SCMP_ACT_KILL_PROCESS
#define ODHCP6C_SECCOMP_DEFAULT SCMP_ACT_KILL_PROCESS
#else
#define ODHCP6C_SECCOMP_DEFAULT SCMP_ACT_KILL
#endif

/*
 * Allow-list for the network-facing worker. Derived from the syscalls the
 * worker exercises across the full DHCPv6 lifecycle (solicit -> bound -> renew
 * -> rebind -> reset/re-init -> release), RA processing and repeated script
 * requests to the monitor. The list intentionally omits execve, fork, clone
 * and vfork: with privilege separation the monitor performs all process
 * creation, so a parser compromise in the worker cannot spawn a shell.
 *
 * Both glibc and musl variants are listed (e.g. ppoll/poll, the *_time64
 * variants used on 32-bit, and socketcall for socket multiplexing on some
 * 32-bit architectures). Names unknown on the build arch are skipped when the
 * rules are added, so listing extra variants is harmless.
 *
 * The list must be reconciled empirically per target libc/arch; see the N-2
 * design notes. libseccomp resolves these names to the correct numbers for the
 * build architecture.
 */
static const int seccomp_allow[] = {
	/* event loop + I/O on already-open fds */
	SCMP_SYS(ppoll), SCMP_SYS(poll),
	SCMP_SYS(recvmsg), SCMP_SYS(recvfrom),
	SCMP_SYS(sendmsg), SCMP_SYS(sendto),
	SCMP_SYS(read), SCMP_SYS(write),
	SCMP_SYS(close),
	/* DHCPv6 socket re-creation on DHCPV6_RESET (worker retains
	 * CAP_NET_RAW + CAP_NET_BIND_SERVICE). ioctl is broad but used only
	 * for SIOCGIFFLAGS/SIOCGIFINDEX/SIOCGIFHWADDR during socket setup and
	 * EUI-64 generation; left as a plain allow for a first cut rather than
	 * an argument filter. socketcall covers 32-bit socket multiplexing. */
	SCMP_SYS(socket), SCMP_SYS(setsockopt), SCMP_SYS(getsockopt),
	SCMP_SYS(bind), SCMP_SYS(connect), SCMP_SYS(getsockname),
	SCMP_SYS(socketcall),
	SCMP_SYS(ioctl),
	SCMP_SYS(fcntl), SCMP_SYS(fcntl64),
	/* time + randomness + alarms */
	SCMP_SYS(clock_gettime), SCMP_SYS(clock_gettime64),
	SCMP_SYS(gettimeofday), SCMP_SYS(time),
	SCMP_SYS(nanosleep), SCMP_SYS(clock_nanosleep),
	SCMP_SYS(clock_nanosleep_time64),
	SCMP_SYS(getrandom),
	SCMP_SYS(setitimer), SCMP_SYS(alarm),
	/* signals */
	SCMP_SYS(rt_sigreturn), SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(rt_sigaction), SCMP_SYS(sigreturn),
	SCMP_SYS(restart_syscall),
	/* self-signaling: raise(3) in the ubus renew/reconfigure/release
	 * handlers resolve to tgkill (glibc) or tkill (musl); gettid
	 * backs the tid lookup on some libc versions. */
	SCMP_SYS(tgkill), SCMP_SYS(tkill), SCMP_SYS(gettid),
	/* memory + housekeeping (madvise is used by some libc allocators) */
	SCMP_SYS(getpid),
	SCMP_SYS(brk), SCMP_SYS(mmap), SCMP_SYS(mmap2),
	SCMP_SYS(munmap), SCMP_SYS(mremap), SCMP_SYS(madvise),
	/* state files the worker still reads (e.g. odhcp6c_addr_in_scope
	 * reads /proc/net/if_inet6) */
	SCMP_SYS(openat), SCMP_SYS(open),
	SCMP_SYS(lseek), SCMP_SYS(_llseek),
	SCMP_SYS(fstat), SCMP_SYS(fstat64), SCMP_SYS(newfstatat),
	/* clean shutdown */
	SCMP_SYS(exit), SCMP_SYS(exit_group),
};

void seccomp_apply(void)
{
	scmp_filter_ctx ctx = seccomp_init(ODHCP6C_SECCOMP_DEFAULT);
	if (!ctx) {
		critical("seccomp: seccomp_init failed");
		exit(EXIT_FAILURE);
	}

	for (size_t i = 0; i < ARRAY_SIZE(seccomp_allow); ++i) {
		int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, seccomp_allow[i], 0);
		if (rc == -EDOM) {
			/* Syscall is not defined for the build architecture
			 * (e.g. a 32-bit-only variant such as socketcall or
			 * fcntl64 on a 64-bit target); skip it rather than
			 * aborting. */
			debug("seccomp: skipping syscall index %zu not available on this architecture",
					i);
			continue;
		}
		if (rc != 0) {
			critical("seccomp: could not add rule for syscall index %zu: %s", i,
					strerror(-rc));
			seccomp_release(ctx);
			exit(EXIT_FAILURE);
		}
	}

	int rc = seccomp_load(ctx);
	if (rc != 0) {
		seccomp_release(ctx);
#ifdef WITH_SECCOMP_FAIL_OPEN
		warn("seccomp: seccomp_load failed, continuing unconfined: %s",
				strerror(-rc));
		return;
#else
		critical("seccomp: seccomp_load failed: %s", strerror(-rc));
		exit(EXIT_FAILURE);
#endif
	}

	seccomp_release(ctx);
	notice("seccomp: worker syscall filter active");
}

#else /* !WITH_SECCOMP */

void seccomp_apply(void)
{
	/* no-op: seccomp confinement disabled at build time */
}

#endif /* WITH_SECCOMP */
