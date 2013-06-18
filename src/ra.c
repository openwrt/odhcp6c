/**
 * Copyright (C) 2012-2013 Steven Barth <steven@midlink.org>
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

#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <linux/rtnetlink.h>


#include "odhcp6c.h"
#include "ra.h"


static int sock = -1, rtnl_sock = -1;
static unsigned if_index = 0;
static char if_name[IF_NAMESIZE] = {0};
static volatile int rs_attempt = 0;
static struct in6_addr lladdr = IN6ADDR_ANY_INIT;

static void ra_send_rs(int signal __attribute__((unused)));

int ra_init(const char *ifname, const struct in6_addr *ifid)
{
	sock = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if_index = if_nametoindex(ifname);
	strncpy(if_name, ifname, sizeof(if_name) - 1);
	lladdr = *ifid;

	// Filter ICMPv6 package types
	struct icmp6_filter filt;
	ICMP6_FILTER_SETBLOCKALL(&filt);
	ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filt);
	setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt));

	// Bind to all-nodes
	struct ipv6_mreq an = {ALL_IPV6_NODES, if_index};
	setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &an, sizeof(an));

	// Let the kernel compute our checksums
	int val = 2;
	setsockopt(sock, IPPROTO_RAW, IPV6_CHECKSUM, &val, sizeof(val));

	// This is required by RFC 4861
	val = 255;
	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val));

	// Bind to one device
	setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));

	// Add async-mode
	const pid_t ourpid = getpid();
	fcntl(sock, F_SETOWN, ourpid);
	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_ASYNC);

	if (IN6_IS_ADDR_UNSPECIFIED(&lladdr)) {
		// Autodetect interface-id if not specified
		FILE *fp = fopen("/proc/net/if_inet6", "r");
		if (fp) {
			char addrbuf[33], ifbuf[16];
			while (fscanf(fp, "%32s %*x %*x %*x %*x %15s", addrbuf, ifbuf) == 2) {
				if (!strcmp(ifbuf, if_name)) {
					script_unhexlify((uint8_t*)&lladdr, sizeof(lladdr), addrbuf);
					break;
				}
			}
			fclose(fp);
		}
	}

	// Open rtnetlink socket
	rtnl_sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	struct sockaddr_nl rtnl_kernel = { .nl_family = AF_NETLINK };
	if (connect(rtnl_sock, (struct sockaddr*)&rtnl_kernel, sizeof(rtnl_kernel)))
		return -1;
	uint32_t group = RTNLGRP_IPV6_IFADDR;
	setsockopt(rtnl_sock, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group));

	// Add async-mode
	fcntl(rtnl_sock, F_SETOWN, ourpid);
	fcntl(rtnl_sock, F_SETFL, fcntl(rtnl_sock, F_GETFL) | O_ASYNC);

	// Send RS
	signal(SIGALRM, ra_send_rs);
	ra_send_rs(SIGALRM);

	return 0;
}


static void ra_send_rs(int signal __attribute__((unused)))
{
	const struct icmp6_hdr rs = {ND_ROUTER_SOLICIT, 0, 0, {{0}}};
	const struct sockaddr_in6 dest = {AF_INET6, 0, 0, ALL_IPV6_ROUTERS, if_index};
	sendto(sock, &rs, sizeof(rs), MSG_DONTWAIT, (struct sockaddr*)&dest, sizeof(dest));

	if (++rs_attempt <= 3)
		alarm(4);
}


static int16_t pref_to_priority(uint8_t flags)
{
	flags = (flags >> 3) & 0x03;
	return (flags == 0x0) ? 1024 : (flags == 0x1) ? 512 :
			(flags == 0x3) ? 2048 : -1;
}


static void update_proc(const char *sect, const char *opt, uint32_t value)
{
	char buf[64];
	snprintf(buf, sizeof(buf), "/proc/sys/net/ipv6/%s/%s/%s", sect, if_name, opt);

	int fd = open(buf, O_WRONLY);
	write(fd, buf, snprintf(buf, sizeof(buf), "%u", value));
	close(fd);
}


static bool ra_deduplicate(const struct in6_addr *any, uint8_t length)
{
	struct odhcp6c_entry entry = {IN6ADDR_ANY_INIT, length, 0, *any, 0, 0};
	struct odhcp6c_entry *x = odhcp6c_find_entry(STATE_RA_PREFIX, &entry);
	if (x && IN6_ARE_ADDR_EQUAL(&x->target, any)) {
		odhcp6c_random(&x->target.s6_addr32[2], 2 * sizeof(uint32_t));
	} else if (odhcp6c_find_entry(STATE_IA_NA, &entry)) {
		dhcpv6_request(DHCPV6_MSG_DECLINE);
		raise(SIGUSR2);
	}

	return !!x;
}


bool ra_rtnl_process(void)
{
	bool found = false;
	uint32_t elapsed = odhcp6c_elapsed();
	uint8_t buf[8192];
	while (true) {
		ssize_t len = recv(rtnl_sock, buf, sizeof(buf), MSG_DONTWAIT);
		if (len < 0)
			break;

		if (elapsed > 10)
			continue;

		for (struct nlmsghdr *nh = (struct nlmsghdr*)buf; NLMSG_OK(nh, (size_t)len);
					nh = NLMSG_NEXT(nh, len)) {
			struct ifaddrmsg *ifa = NLMSG_DATA(nh);
			struct in6_addr *addr = NULL;
			if (NLMSG_PAYLOAD(nh, 0) < sizeof(*ifa) || ifa->ifa_index != if_index ||
					(nh->nlmsg_type == RTM_NEWADDR && !(ifa->ifa_flags & IFA_F_DADFAILED)) ||
					(nh->nlmsg_type == RTM_DELADDR && !(ifa->ifa_flags & IFA_F_TENTATIVE)) ||
					(nh->nlmsg_type != RTM_NEWADDR && nh->nlmsg_type != RTM_DELADDR))
				continue;

			ssize_t alen = NLMSG_PAYLOAD(nh, sizeof(*ifa));
			for (struct rtattr *rta = (struct rtattr*)&ifa[1]; RTA_OK(rta, alen);
					rta = RTA_NEXT(rta, alen))
				if (rta->rta_type == IFA_ADDRESS && RTA_PAYLOAD(rta) >= sizeof(*addr))
					addr = RTA_DATA(rta);

			if (addr) {
				char ipbuf[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, addr, ipbuf, sizeof(ipbuf));
				syslog(LOG_WARNING, "duplicate address detected: %s (code: %u:%x)",
						ipbuf, (unsigned)nh->nlmsg_type, (unsigned)ifa->ifa_flags);
				found |= ra_deduplicate(addr, ifa->ifa_prefixlen);
			}
		}
	}
	return found;
}


bool ra_process(void)
{
	bool found = false;
	uint8_t buf[1500];
	struct nd_router_advert *adv = (struct nd_router_advert*)buf;
	struct odhcp6c_entry entry = {IN6ADDR_ANY_INIT, 0, 0, IN6ADDR_ANY_INIT, 0, 0};
	const struct in6_addr any = IN6ADDR_ANY_INIT;

	while (true) {
		struct sockaddr_in6 from;
		socklen_t from_len = sizeof(from);
		ssize_t len = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT, &from, &from_len);
		if (len < 0)
			break;
		else if (len < (ssize_t)sizeof(*adv))
			continue;

		// Stop sending solicits
		if (rs_attempt > 0) {
			alarm(0);
			rs_attempt = 0;
		}

		if (!found) {
			odhcp6c_expire();
			found = true;
		}
		uint32_t router_valid = ntohs(adv->nd_ra_router_lifetime);

		// Parse default route
		entry.target = any;
		entry.length = 0;
		entry.router = from.sin6_addr;
		entry.priority = pref_to_priority(adv->nd_ra_flags_reserved);
		if (entry.priority < 0)
			entry.priority = pref_to_priority(0);
		entry.valid = router_valid;
		entry.preferred = entry.valid;
		odhcp6c_update_entry(STATE_RA_ROUTE, &entry);

		// Parse ND parameters
		if (ntohl(adv->nd_ra_reachable) <= 3600000)
			update_proc("neigh", "base_reachable_time_ms", ntohl(adv->nd_ra_reachable));

		if (ntohl(adv->nd_ra_retransmit) <= 60000)
			update_proc("neigh", "retrans_time_ms", ntohl(adv->nd_ra_retransmit));


		// Evaluate options
		struct icmpv6_opt *opt;
		icmpv6_for_each_option(opt, &adv[1], &buf[len]) {
			if (opt->type == ND_OPT_MTU) {
				uint32_t *mtu = (uint32_t*)&opt->data[2];
				if (ntohl(*mtu) >= 1280 && ntohl(*mtu) <= 65535)
					update_proc("conf", "mtu", ntohl(*mtu));
			} else if (opt->type == ND_OPT_ROUTE_INFORMATION && opt->len <= 3) {
				entry.router = from.sin6_addr;
				entry.target = any;
				entry.priority = pref_to_priority(opt->data[1]);
				entry.length = opt->data[0];
				uint32_t *valid = (uint32_t*)&opt->data[2];
				entry.valid = ntohl(*valid);
				memcpy(&entry.target, &opt->data[6], (opt->len - 1) * 8);

				if (entry.length > 128 || IN6_IS_ADDR_LINKLOCAL(&entry.target)
						|| IN6_IS_ADDR_LOOPBACK(&entry.target)
						|| IN6_IS_ADDR_MULTICAST(&entry.target))
					continue;

				if (entry.priority > 0)
					odhcp6c_update_entry(STATE_RA_ROUTE, &entry);
			} else if (opt->type == ND_OPT_PREFIX_INFORMATION && opt->len == 4) {
				struct nd_opt_prefix_info *pinfo = (struct nd_opt_prefix_info*)opt;
				entry.router = any;
				entry.target = pinfo->nd_opt_pi_prefix;
				entry.priority = 256;
				entry.length = pinfo->nd_opt_pi_prefix_len;
				entry.valid = ntohl(pinfo->nd_opt_pi_valid_time);
				entry.preferred = ntohl(pinfo->nd_opt_pi_preferred_time);

				if (entry.length > 128 || IN6_IS_ADDR_LINKLOCAL(&entry.target)
						|| IN6_IS_ADDR_LOOPBACK(&entry.target)
						|| IN6_IS_ADDR_MULTICAST(&entry.target)
						|| entry.valid < entry.preferred)
					continue;

				if (pinfo->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK)
					odhcp6c_update_entry_safe(STATE_RA_ROUTE, &entry, 7200);

				if (!(pinfo->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) ||
						pinfo->nd_opt_pi_prefix_len != 64)
					continue;

				entry.target.s6_addr32[2] = lladdr.s6_addr32[2];
				entry.target.s6_addr32[3] = lladdr.s6_addr32[3];

				odhcp6c_update_entry_safe(STATE_RA_PREFIX, &entry, 7200);
			} else if (opt->type == ND_OPT_RECURSIVE_DNS && opt->len > 2) {
				entry.router = from.sin6_addr;
				entry.priority = 0;
				entry.length = 128;
				uint32_t *valid = (uint32_t*)&opt->data[2];
				entry.valid = ntohl(*valid);
				entry.preferred = 0;

				for (ssize_t i = 0; i < (opt->len - 1) / 2; ++i) {
					memcpy(&entry.target, &opt->data[6 + i * sizeof(entry.target)],
							sizeof(entry.target));
					odhcp6c_update_entry(STATE_RA_DNS, &entry);
				}
			}
		}

		size_t ra_dns_len;
		struct odhcp6c_entry *entry = odhcp6c_get_state(STATE_RA_DNS, &ra_dns_len);
		for (size_t i = 0; i < ra_dns_len / sizeof(*entry); ++i)
			if (IN6_ARE_ADDR_EQUAL(&entry[i].router, &from.sin6_addr) &&
					entry[i].valid > router_valid)
				entry[i].valid = router_valid;
	}

	if (found)
		odhcp6c_expire();

	return found;
}
