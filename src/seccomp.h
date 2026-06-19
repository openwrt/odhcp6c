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

#ifndef _SECCOMP_H_
#define _SECCOMP_H_

/*
 * Confine the privsep worker with a seccomp-BPF syscall allow-list. Must be
 * called as the LAST initialization step of the worker: after all sockets/fds
 * are open and after drop_privileges() (which sets PR_SET_NO_NEW_PRIVS), but
 * before the first recvmsg() of attacker-controlled data.
 *
 * When built without WITH_SECCOMP this is a no-op. With WITH_SECCOMP it fails
 * closed (calls exit() on error) unless WITH_SECCOMP_FAIL_OPEN is defined, in
 * which case a load failure logs a warning and execution continues unconfined.
 */
void seccomp_apply(void);

#endif /* _SECCOMP_H_ */
