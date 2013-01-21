/**
 * Copyright (C) 2012 Steven Barth <steven@midlink.org>
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

#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>

#include "odhcp6c.h"


static int sock = -1;
static unsigned seq = 0;


// Init rtnetlink socket
int init_rtnetlink(void)
{
	sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	struct sockaddr_nl rtnl_kernel = { .nl_family = AF_NETLINK };
	if (connect(sock, (struct sockaddr*)&rtnl_kernel, sizeof(rtnl_kernel)))
		return -1;

	return 0;
}


// CRUD addresses to interface
int set_rtnetlink_addr(int ifindex, const struct in6_addr *addr,
		uint32_t pref, uint32_t valid)
{
	int flags = NLM_F_REQUEST | NLM_F_ACK;
	int cmd = RTM_DELADDR;

	if (valid) {
		flags |= NLM_F_CREATE | NLM_F_REPLACE;
		cmd = RTM_NEWADDR;
	}

	struct {
		struct nlmsghdr nhm;
		struct ifaddrmsg ifa;
		struct rtattr rta_addr;
		struct in6_addr addr;
		struct rtattr rta_local;
		struct in6_addr local;
		struct rtattr rta_info;
		struct ifa_cacheinfo info;
	} req = {
		{sizeof(req), cmd, flags, ++seq, 0},
		{AF_INET6, 128, 0, RT_SCOPE_UNIVERSE, ifindex},
		{sizeof(req.rta_addr) + sizeof(req.addr), IFA_ADDRESS},
		*addr,
		{sizeof(req.rta_local) + sizeof(req.local), IFA_LOCAL},
		*addr,
		{sizeof(req.rta_info) + sizeof(req.info), IFA_CACHEINFO},
		{pref, valid, 0, 0}
	};
	send(sock, &req, sizeof(req), 0);

	struct {
		struct nlmsghdr nhm;
		struct nlmsgerr err;
	} reply;
	recv(sock, &reply, sizeof(reply), 0);

	char buf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, addr, buf, sizeof(buf));
	syslog(LOG_WARNING, "%s address %s/128 for iface %i: %s",
			(valid) ? "assigning" : "removing", buf,
			ifindex, strerror(-reply.err.error));

	if (reply.err.error < 0 || valid == 0)
		return reply.err.error;

	// Check for duplicate addresses
	struct timespec ts = {1, 0};
	nanosleep(&ts, NULL);

	req.nhm.nlmsg_type = RTM_GETADDR;
	req.nhm.nlmsg_seq = ++seq;
	req.nhm.nlmsg_flags = NLM_F_REQUEST;
	send(sock, &req, sizeof(req), 0);

	struct {
		struct nlmsghdr nhm;
		struct ifaddrmsg ifa;
		uint8_t buf[1024];
	} dad_reply;
	recv(sock, &dad_reply, sizeof(dad_reply), 0);

	if (dad_reply.nhm.nlmsg_type != RTM_NEWADDR ||
			(dad_reply.ifa.ifa_flags & IFA_F_DADFAILED)) {
		syslog(LOG_WARNING, "Removing duplicate address %s", buf);
		set_rtnetlink_addr(ifindex, addr, 0, 0);
		return -EADDRNOTAVAIL;
	}
	return 0;
}
