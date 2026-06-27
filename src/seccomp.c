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
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <seccomp.h>

#include "odhcp6c.h"

/*
 * Diagnostic mode (opt-in via the ODHCP6C_SECCOMP_DIAG environment variable):
 * instead of killing the worker on the first disallowed syscall, install the
 * filter with SCMP_ACT_TRAP as the default action and a SIGSYS handler that
 * records the blocked syscall number to stderr, then lets the syscall return
 * -ENOSYS so the worker keeps running and every gap in one lifecycle is
 * enumerated (not just the first). This turns the otherwise-silent SIGSYS kill
 * into actionable output in the worker log -- no dmesg/audit access required,
 * which matters inside CI containers. Production builds never set the env var
 * and keep the fail-closed SCMP_ACT_KILL_PROCESS default.
 */
static int seccomp_diag_enabled(void)
{
	const char *v = getenv("ODHCP6C_SECCOMP_DIAG");
	return v && v[0] && strcmp(v, "0") != 0;
}

/* async-signal-safe: write a decimal integer to fd */
static void seccomp_diag_write_int(int fd, long v)
{
	char buf[24];
	size_t i = sizeof(buf);
	int neg = v < 0;
	unsigned long u = neg ? (unsigned long)(-v) : (unsigned long)v;
	if (u == 0)
		buf[--i] = '0';
	while (u) {
		buf[--i] = (char)('0' + (u % 10));
		u /= 10;
	}
	if (neg)
		buf[--i] = '-';
	while (write(fd, buf + i, sizeof(buf) - i) < 0 && errno == EINTR)
		;
}

static void seccomp_diag_sigsys(int sig, siginfo_t *si, void *uc)
{
	(void)sig;
	(void)uc;
	/* Log each distinct syscall number once to avoid flooding the log if a
	 * blocked syscall is retried in a loop. 512 covers all syscall numbers
	 * on the architectures odhcp6c targets. */
	static volatile sig_atomic_t seen[512];
	int nr = si->si_syscall;
	static const char pfx[] = "seccomp-diag: blocked syscall=";
	static const char nl = '\n';
	if (nr >= 0 && nr < (int)(sizeof(seen) / sizeof(seen[0]))) {
		if (seen[nr])
			return;
		seen[nr] = 1;
	}
	while (write(STDERR_FILENO, pfx, sizeof(pfx) - 1) < 0 && errno == EINTR)
		;
	seccomp_diag_write_int(STDERR_FILENO, nr);
	while (write(STDERR_FILENO, &nl, 1) < 0 && errno == EINTR)
		;
}

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
	/* event loop + I/O on already-open fds. writev backs buffered stdio
	 * flushes on musl (__stdio_write), observed in the worker's log path. */
	SCMP_SYS(ppoll), SCMP_SYS(poll),
	/* y2038 time64 / pselect forms of the event loop, used on 32-bit
	 * arches (ARM/MIPS OpenWrt targets). Same semantics as ppoll/poll. */
	SCMP_SYS(ppoll_time64), SCMP_SYS(pselect6), SCMP_SYS(pselect6_time64),
	/* libubox uloop's epoll-backed fd management on the ubus (re)connect
	 * path. libubus initialises uloop during ubus_connect(), which runs as
	 * root before the worker drops privileges, so the epoll instance itself
	 * (epoll_create) and the initial waker-pipe registration happen
	 * pre-seccomp. Only epoll_ctl recurs post-drop, when libubus re-arms the
	 * uloop fd set while reconnecting after the broker restarts; odhcp6c
	 * drives its own poll() loop rather than uloop_run(), so epoll_wait is
	 * never reached. Confirmed as the sole gap via ODHCP6C_SECCOMP_DIAG in
	 * the ubus-reconnect harness scenario (syscall 233 on x86-64). */
	SCMP_SYS(epoll_ctl),
	SCMP_SYS(recvmsg), SCMP_SYS(recvfrom),
	SCMP_SYS(sendmsg), SCMP_SYS(sendto),
	SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(writev),
	/* positional I/O on already-open fds (no exposure beyond read/write) */
	SCMP_SYS(pread64), SCMP_SYS(pwrite64),
	SCMP_SYS(close),
	/* DHCPv6 socket re-creation on DHCPV6_RESET (worker retains
	 * CAP_NET_RAW + CAP_NET_BIND_SERVICE). socketcall covers 32-bit
	 * socket multiplexing. ioctl is not allowed here: it is restricted to
	 * a fixed set of SIOCGIF* requests via an argument filter added
	 * separately below (see seccomp_ioctl_allow). */
	SCMP_SYS(socket), SCMP_SYS(setsockopt), SCMP_SYS(getsockopt),
	SCMP_SYS(bind), SCMP_SYS(connect), SCMP_SYS(getsockname),
	SCMP_SYS(socketcall),
	SCMP_SYS(fcntl), SCMP_SYS(fcntl64),
	/* time + randomness + alarms */
	SCMP_SYS(clock_gettime), SCMP_SYS(clock_gettime64),
	SCMP_SYS(gettimeofday), SCMP_SYS(time),
	SCMP_SYS(clock_getres), SCMP_SYS(clock_getres_time64),
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
	/* libc synchronization + scheduling housekeeping. futex backs libc
	 * mutex/stdio/malloc locking (process-local fast-userspace lock; only
	 * traps under contention). rseq is registered by glibc's thread setup.
	 * All are process-local and cannot reach other tasks. */
	SCMP_SYS(futex), SCMP_SYS(futex_time64),
	SCMP_SYS(sched_yield), SCMP_SYS(rseq),
	/* libc internals: uname is not called directly by odhcp6c but both
	 * musl and glibc issue it lazily on the worker's post-seccomp path
	 * (kernel-version probe). Confirmed as the sole allow-list gap on both
	 * libcs via the SIGSYS trap diagnostic; read-only and harmless. */
	SCMP_SYS(uname),
	/* memory + housekeeping (madvise is used by some libc allocators) */
	SCMP_SYS(getpid),
	SCMP_SYS(brk), SCMP_SYS(mmap), SCMP_SYS(mmap2),
	SCMP_SYS(munmap), SCMP_SYS(mremap), SCMP_SYS(madvise),
	/* state files the worker still reads (e.g. odhcp6c_addr_in_scope
	 * reads /proc/net/if_inet6) */
	SCMP_SYS(openat), SCMP_SYS(open),
	SCMP_SYS(lseek), SCMP_SYS(_llseek),
	SCMP_SYS(fstat), SCMP_SYS(fstat64), SCMP_SYS(newfstatat),
	/* statx is glibc's stat() backend on >=2.33; getdents64 backs
	 * readdir(3). Same read-only exposure as the stat/open calls above. */
	SCMP_SYS(statx), SCMP_SYS(getdents64),
	/* clean shutdown */
	SCMP_SYS(exit), SCMP_SYS(exit_group),
};

/*
 * The worker issues ioctl(2) only with a small, fixed set of SIOCGIF* requests:
 *   - SIOCGIFFLAGS : point-to-point detection during RA socket setup (ra.c)
 *   - SIOCGIFINDEX : interface index lookup for the DHCPv6/RA sockets,
 *                    including DHCPV6_RESET socket re-creation (dhcpv6.c, ra.c)
 *   - SIOCGIFHWADDR: client DUID and EUI-64 hardware-address fetch
 *                    (dhcpv6.c, ra.c)
 *   - SIOCGIFCONF  : DUID fallback scan for a usable hardware address when the
 *                    request interface has none (dhcpv6.c)
 * Restrict ioctl to exactly these request numbers via an argument filter
 * (arg1 == request) instead of a blanket allow, so a parser compromise in the
 * worker cannot reach arbitrary driver/terminal ioctls. The request numbers
 * are stable kernel UAPI values, identical across glibc and musl.
 */
static const unsigned long seccomp_ioctl_allow[] = {
	SIOCGIFFLAGS,
	SIOCGIFINDEX,
	SIOCGIFHWADDR,
	SIOCGIFCONF,
};

void seccomp_apply(void)
{
	int diag = seccomp_diag_enabled();
	uint32_t default_action = ODHCP6C_SECCOMP_DEFAULT;

	if (diag) {
		/* Trap (don't kill) so a SIGSYS handler can log every blocked
		 * syscall to stderr; the syscall then returns -ENOSYS and the
		 * worker keeps running to surface further gaps. */
		struct sigaction sa = {0};
		sa.sa_sigaction = seccomp_diag_sigsys;
		sa.sa_flags = SA_SIGINFO | SA_NODEFER;
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGSYS, &sa, NULL) == 0) {
			default_action = SCMP_ACT_TRAP;
			notice("seccomp: DIAGNOSTIC mode (SCMP_ACT_TRAP) -- blocked "
					"syscalls are logged, not fatal; do NOT use in production");
		} else {
			warn("seccomp: diagnostic SIGSYS handler install failed: %s",
					strerror(errno));
			diag = 0;
		}
	}

	scmp_filter_ctx ctx = seccomp_init(default_action);
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

	/*
	 * Narrow ioctl to the fixed SIOCGIF* request set (see seccomp_ioctl_allow):
	 * allow ioctl only when arg1 (the request) matches one of the permitted
	 * commands; every other ioctl falls through to the default kill action.
	 */
	for (size_t i = 0; i < ARRAY_SIZE(seccomp_ioctl_allow); ++i) {
		int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 1,
				SCMP_A1(SCMP_CMP_EQ, seccomp_ioctl_allow[i]));
		if (rc == -EDOM) {
			/* ioctl not defined for the build architecture; skip
			 * rather than aborting (mirrors the allow-list loop). */
			debug("seccomp: skipping ioctl request filter index %zu not available on this architecture",
					i);
			continue;
		}
		if (rc != 0) {
			critical("seccomp: could not add ioctl rule index %zu: %s", i,
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
	notice("seccomp: worker syscall filter active%s",
			diag ? " (DIAGNOSTIC trap mode)" : "");
}

#else /* !WITH_SECCOMP */

void seccomp_apply(void)
{
	/* no-op: seccomp confinement disabled at build time */
}

#endif /* WITH_SECCOMP */
