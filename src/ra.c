#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <linux/rtnetlink.h>


#include "odhcp6c.h"
#include "ra.h"


static int sock = -1, rtnl_sock = -1;
static unsigned if_index = 0;
static char if_name[IF_NAMESIZE] = {0};
static volatile int rs_attempt = 1;
static struct in6_addr lladdr = IN6ADDR_ANY_INIT;

static void ra_send_rs(int signal __attribute__((unused)));

int ra_init(const char *ifname)
{
	sock = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if_index = if_nametoindex(ifname);
	strncpy(if_name, ifname, sizeof(if_name) - 1);

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

	// Get LL-addr
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

	if (++rs_attempt < 3)
		alarm(4);
}


static int16_t pref_to_priority(uint8_t flags)
{
	flags = (flags >> 3) & 0x03;
	return (flags == 0x00) ? 1024 : (flags == 0x01) ? 512 :
			(flags == 0x11) ? 2048 : -1;
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
	if (x) {
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
	uint8_t buf[8192];
	while (true) {
		ssize_t len = recv(rtnl_sock, buf, sizeof(buf), MSG_DONTWAIT);
		if (len < 0)
			break;

		for (struct nlmsghdr *nh = (struct nlmsghdr*)buf; NLMSG_OK(nh, len);
					nh = NLMSG_NEXT(nh, len)) {
			struct ifaddrmsg *ifa = NLMSG_DATA(nh);
			struct in6_addr *addr = NULL;
			if (nh->nlmsg_type != RTM_NEWADDR || NLMSG_PAYLOAD(nh, 0) < sizeof(*ifa) ||
					!(ifa->ifa_flags & IFA_F_DADFAILED) ||
					ifa->ifa_index != if_index)
				continue;

			ssize_t alen = NLMSG_PAYLOAD(nh, sizeof(*ifa));
			for (struct rtattr *rta = (struct rtattr*)&ifa[1]; RTA_OK(rta, alen);
					rta = RTA_NEXT(rta, alen))
				if (rta->rta_type == IFA_LOCAL && RTA_PAYLOAD(rta) >= sizeof(*addr))
					addr = RTA_DATA(rta);

			if (addr)
				found |= ra_deduplicate(addr, ifa->ifa_prefixlen);
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
	odhcp6c_expire();

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

		found = true;

		// Parse default route
		entry.router = from.sin6_addr;
		entry.priority = pref_to_priority(adv->nd_ra_flags_reserved);
		if (entry.priority < 0)
			entry.priority = pref_to_priority(0);
		entry.valid = ntohs(adv->nd_ra_router_lifetime);
		entry.preferred = entry.valid;
		odhcp6c_update_entry(STATE_RA_ROUTE, &entry);

		// Parse ND parameters
		if (adv->nd_ra_reachable)
			update_proc("neigh", "base_reachable_time_ms", ntohl(adv->nd_ra_reachable));

		if (adv->nd_ra_retransmit)
			update_proc("neigh", "retrans_time_ms", ntohl(adv->nd_ra_retransmit));

		// Evaluate options
		struct icmpv6_opt *opt;
		icmpv6_for_each_option(opt, &adv[1], &buf[len]) {
			if (opt->type == ND_OPT_MTU) {
				update_proc("conf", "mtu", ntohl(*((uint32_t*)&opt->data[2])));
			} else if (opt->type == ND_OPT_ROUTE_INFORMATION && opt->len <= 3) {
				entry.router = from.sin6_addr;
				entry.target = any;
				entry.priority = pref_to_priority(opt->data[1]);
				entry.length = opt->data[0];
				entry.valid = ntohl(*((uint32_t*)&opt->data[2]));
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
				entry.priority = 0;
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
			}

		}
	}
	return found;
}
