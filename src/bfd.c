#include <syslog.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <sys/socket.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <linux/rtnetlink.h>
#include <linux/filter.h>

#include <fcntl.h>
#include <unistd.h>

#include "odhcp6c.h"

static int sock = -1, rtnl = -1;
static int if_index = -1;
static int bfd_failed = 0, bfd_limit = 0, bfd_interval = 0;
static bool bfd_armed = false;


static void bfd_send(int signal)
{
	struct {
		struct ip6_hdr ip6;
		struct icmp6_hdr icmp6;
	} ping;
	memset(&ping, 0, sizeof(ping));

	ping.ip6.ip6_vfc = 6 << 4;
	ping.ip6.ip6_plen = htons(8);
	ping.ip6.ip6_nxt = IPPROTO_ICMPV6;
	ping.ip6.ip6_hlim = 255;

	ping.icmp6.icmp6_type = ICMP6_ECHO_REQUEST;
	ping.icmp6.icmp6_data32[0] = htonl(0xbfd0bfd);

	size_t pdlen, rtlen;
	struct odhcp6c_entry *pd = odhcp6c_get_state(STATE_IA_PD, &pdlen), *cpd = NULL;
	struct odhcp6c_entry *rt = odhcp6c_get_state(STATE_RA_ROUTE, &rtlen), *crt = NULL;
	bool crt_found = false;

	// Detect PD-Prefix
	for (size_t i = 0; i < pdlen / sizeof(*pd); ++i)
		if (!cpd || ((cpd->target.s6_addr[0] & 7) == 0xfc) > ((pd[i].target.s6_addr[0] & 7) == 0xfc)
				|| cpd->preferred < pd[i].preferred)
			cpd = &pd[i];

	// Detect default router
	for (size_t i = 0; i < rtlen / sizeof(*rt); ++i)
		if (IN6_IS_ADDR_UNSPECIFIED(&rt[i].target) && (!crt || crt->priority > rt[i].priority))
			crt = &rt[i];

	struct sockaddr_ll dest = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IPV6),
		.sll_ifindex = if_index,
		.sll_halen = ETH_ALEN,
	};

	if (crt) {
		struct {
			struct nlmsghdr hdr;
			struct ndmsg ndm;
		} req = {
			.hdr = {sizeof(req), RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP, 1, 0},
			.ndm = {.ndm_family = AF_INET6, .ndm_ifindex = if_index}
		};
		send(rtnl, &req, sizeof(req), 0);

		uint8_t buf[8192];
		struct nlmsghdr *nhm;
		do {
			ssize_t read = recv(rtnl, buf, sizeof(buf), 0);
			nhm = (struct nlmsghdr*)buf;
			if (read < 0 || !NLMSG_OK(nhm, (size_t)read))
				continue;

			for (; read > 0 && NLMSG_OK(nhm, (size_t)read); nhm = NLMSG_NEXT(nhm, read)) {
				ssize_t attrlen = NLMSG_PAYLOAD(nhm, sizeof(struct ndmsg));
				if (nhm->nlmsg_type != RTM_NEWNEIGH || attrlen <= 0) {
					nhm = NULL;
					break;
				}

				// Already have our MAC
				if (crt_found)
					continue;

				struct ndmsg *ndm = NLMSG_DATA(nhm);
				for (struct rtattr *rta = (struct rtattr*)&ndm[1];
						attrlen > 0 && RTA_OK(rta, (size_t)attrlen);
						rta = RTA_NEXT(rta, attrlen)) {
					if (rta->rta_type == NDA_DST) {
						crt_found = IN6_ARE_ADDR_EQUAL(RTA_DATA(rta), &crt->router);
					} else if (rta->rta_type == NDA_LLADDR) {
						memcpy(dest.sll_addr, RTA_DATA(rta), ETH_ALEN);
					}
				}
			}
		} while (nhm);
	}

	if (!crt_found || !cpd)
		return;

	ping.ip6.ip6_src = cpd->target;
	ping.ip6.ip6_dst = cpd->target;

	if (bfd_armed) {
		if (bfd_failed++ > bfd_limit) {
			raise(SIGUSR2);
			return;
		}
	}

/*
	uint16_t sum = cksum(&ping.ip6.ip6_src, sizeof(ping.ip6.ip6_src), 0);
	sum = cksum(&ping.ip6.ip6_dst, sizeof(ping.ip6.ip6_dst), ~sum);
	sum = cksum(&ping.ip6.ip6_plen, sizeof(ping.ip6.ip6_plen), ~sum);

	uint8_t next[4] = {0, 0, 0, ping.ip6.ip6_nxt};
	sum = cksum(next, sizeof(next), ~sum);

	ping.icmp6.icmp6_cksum = cksum(&ping.icmp6, sizeof(ping.icmp6), ~sum);
*/

	struct sock_filter bpf[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct ip6_hdr, ip6_plen)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(8 << 16 | IPPROTO_ICMPV6 << 8 | 254), 0, 13),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct ip6_hdr, ip6_dst)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ping.ip6.ip6_dst.s6_addr32[0], 0, 11),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct ip6_hdr, ip6_dst) + 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ping.ip6.ip6_dst.s6_addr32[1], 0, 9),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct ip6_hdr, ip6_dst) + 8),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ping.ip6.ip6_dst.s6_addr32[2], 0, 7),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct ip6_hdr, ip6_dst) + 12),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ping.ip6.ip6_dst.s6_addr32[3], 0, 5),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, sizeof(struct ip6_hdr) +
				offsetof(struct icmp6_hdr, icmp6_type)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(ICMP6_ECHO_REQUEST << 24), 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, sizeof(struct ip6_hdr) +
				offsetof(struct icmp6_hdr, icmp6_data32)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ping.icmp6.icmp6_data32[0], 0, 1),
		BPF_STMT(BPF_RET | BPF_K, 0xffffffff),
		BPF_STMT(BPF_RET | BPF_K, 0),
	};
	struct sock_fprog bpf_prog = {sizeof(bpf) / sizeof(*bpf), bpf};

	setsockopt(sock, SOL_SOCKET, SO_DETACH_FILTER, &bpf_prog, sizeof(bpf_prog));
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog, sizeof(bpf_prog))) {
		close(sock);
		return;
	}


	if (!signal) {
		bind(sock, (struct sockaddr*)&dest, sizeof(dest));
		uint8_t dummy[8];
		while (recv(sock, dummy, sizeof(dummy), MSG_DONTWAIT | MSG_TRUNC) > 0);
	}
	sendto(sock, &ping, sizeof(ping), MSG_DONTWAIT,
			(struct sockaddr*)&dest, sizeof(dest));
	alarm(bfd_interval);
}


void bfd_receive(void)
{
	uint8_t dummy[8];
	while (recv(sock, dummy, sizeof(dummy), MSG_DONTWAIT | MSG_TRUNC) > 0) {
		bfd_failed = 0;
		bfd_armed = true;
	}
}


int bfd_start(int ifindex, int limit, int interval)
{
	if_index = ifindex;
	bfd_armed = false;
	bfd_failed = 0;
	bfd_limit = limit;
	bfd_interval = interval;

	if (limit < 1 || interval < 1)
		return 0;

	rtnl = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_ROUTE);
	struct sockaddr_nl rtnl_kernel = { .nl_family = AF_NETLINK };
	connect(rtnl, (const struct sockaddr*)&rtnl_kernel, sizeof(rtnl_kernel));

	sock = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IPV6));
	bfd_send(0);

	fcntl(sock, F_SETOWN, getpid());
	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_ASYNC);

	signal(SIGALRM, bfd_send);
	return 0;
}


void bfd_stop(void)
{
	alarm(0);
	close(sock);
	close(rtnl);
}

/*

uint16_t cksum(const uint16_t *addr, size_t count, uint16_t start)
{
	uint32_t sum = start;

	while (count > 1) {
		sum += *addr++;
		count -= 2;
	}

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

*/
