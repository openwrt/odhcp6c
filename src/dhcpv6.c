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
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <resolv.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <net/if.h>
#include <net/ethernet.h>

#include "odhcp6c.h"


#define ALL_DHCPV6_RELAYS {{{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02}}}
#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547
#define DHCPV6_DUID_LLADDR 3
#define DHCPV6_REQ_DELAY 1


static bool dhcpv6_response_is_valid(const void *buf, ssize_t len,
		const uint8_t transaction[3], enum dhcpv6_msg type);

static time_t dhcpv6_parse_ia(void *opt, void *end);

static reply_handler dhcpv6_handle_reply;
static reply_handler dhcpv6_handle_advert;
static reply_handler dhcpv6_handle_rebind_reply;
static reply_handler dhcpv6_handle_reconfigure;
static int dhcpv6_commit_advert(uint32_t elapsed);



// RFC 3315 - 5.5 Timeout and Delay values
static struct dhcpv6_retx dhcpv6_retx[_DHCPV6_MSG_MAX] = {
	[DHCPV6_MSG_UNKNOWN] = {false, 1, 120, "<POLL>",
			dhcpv6_handle_reconfigure, NULL},
	[DHCPV6_MSG_SOLICIT] = {true, 1, 120, "SOLICIT",
			dhcpv6_handle_advert, dhcpv6_commit_advert},
	[DHCPV6_MSG_REQUEST] = {true, 30, 10, "REQUEST",
			dhcpv6_handle_reply, NULL},
	[DHCPV6_MSG_RENEW] = {false, 10, 600, "RENEW",
			dhcpv6_handle_reply, NULL},
	[DHCPV6_MSG_REBIND] = {false, 10, 600, "REBIND",
			dhcpv6_handle_rebind_reply, NULL},
	[DHCPV6_MSG_RELEASE] = {false, 1, 600, "RELEASE", NULL, NULL},
	[DHCPV6_MSG_DECLINE] = {false, 1, 3, "DECLINE", NULL, NULL},
	[DHCPV6_MSG_INFO_REQ] = {true, 1, 120, "INFOREQ",
			dhcpv6_handle_reply, NULL},
};


// Sockets
static int sock = -1;
static int urandom_fd = -1;
static int ifindex = -1;
static time_t t1 = 0, t2 = 0, t3 = 0;

// IA states
static int request_prefix = -1;
static enum odhcp6c_ia_mode na_mode = IA_MODE_NONE;
static bool accept_reconfig = false;



int init_dhcpv6(const char *ifname, int request_pd)
{
	request_prefix = request_pd;
	urandom_fd = open("/dev/urandom", O_CLOEXEC | O_RDONLY);
	if (urandom_fd < 0)
		return -1;

	sock = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);

	// Detect interface
	struct ifreq ifr;
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(sock, SIOCGIFINDEX, &ifr))
		return -1;
	ifindex = ifr.ifr_ifindex;

	// Create client DUID
	size_t client_id_len;
	odhcp6c_get_state(STATE_CLIENT_ID, &client_id_len);
	if (client_id_len == 0) {
		ioctl(sock, SIOCGIFHWADDR, &ifr);
		uint8_t duid[14] = {0, DHCPV6_OPT_CLIENTID, 0, 10, 0,
				DHCPV6_DUID_LLADDR, 0, 1};
		memcpy(&duid[8], ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
		odhcp6c_add_state(STATE_CLIENT_ID, duid, sizeof(duid));
	}

	// Create ORO
	uint16_t oro[] = {htons(DHCPV6_OPT_DNS_SERVERS),
			htons(DHCPV6_OPT_DNS_DOMAIN)};
	odhcp6c_add_state(STATE_ORO, oro, sizeof(oro));


	// Configure IPv6-options
	int val = 1;
	setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));

	struct sockaddr_in6 client_addr = { .sin6_family = AF_INET6,
		.sin6_port = htons(DHCPV6_CLIENT_PORT), .sin6_flowinfo = 0 };
	if (bind(sock, (struct sockaddr*)&client_addr, sizeof(client_addr)))
		return -1;

	return 0;
}


void dhcpv6_set_ia_na_mode(enum odhcp6c_ia_mode mode)
{
	na_mode = mode;
}


void dhcpv6_remove_addrs(void)
{
	size_t ia_na_len;
	uint8_t *odata, *ia_na = odhcp6c_get_state(STATE_IA_NA, &ia_na_len);
	uint16_t otype, olen;
	dhcpv6_for_each_option(ia_na, ia_na + ia_na_len, otype, olen, odata) {
		struct dhcpv6_ia_addr *addr = (void*)&odata[-4];
		set_rtnetlink_addr(ifindex, &addr->addr, 0, 0);
	}
}


static void dhcpv6_send(enum dhcpv6_msg type, uint8_t trid[3], uint32_t ecs)
{
	// Build FQDN
	char fqdn_buf[256];
	gethostname(fqdn_buf, sizeof(fqdn_buf));
	struct {
		uint16_t type;
		uint16_t len;
		uint8_t flags;
		uint8_t data[256];
	} fqdn;
	size_t fqdn_len = 5 + dn_comp(fqdn_buf, fqdn.data,
			sizeof(fqdn.data), NULL, NULL);
	fqdn.type = htons(DHCPV6_OPT_FQDN);
	fqdn.len = htons(fqdn_len - 4);
	fqdn.flags = 0;


	// Build Client ID
	size_t cl_id_len;
	void *cl_id = odhcp6c_get_state(STATE_CLIENT_ID, &cl_id_len);

	// Get Server ID
	size_t srv_id_len;
	void *srv_id = odhcp6c_get_state(STATE_SERVER_ID, &srv_id_len);

	// Build IA_PDs
	size_t ia_pd_len;
	void *ia_pd = odhcp6c_get_state(STATE_IA_PD, &ia_pd_len);
	struct dhcpv6_ia_hdr hdr_ia_pd = {
		htons(DHCPV6_OPT_IA_PD),
		htons(sizeof(hdr_ia_pd) - 4 + ia_pd_len),
		1, 0, 0
	};

	struct dhcpv6_ia_prefix pref = {
		.type = htons(DHCPV6_OPT_IA_PREFIX),
		.len = htons(25), .prefix = request_prefix
	};

	if (ia_pd_len == 0 && request_prefix > 0 &&
			(type == DHCPV6_MSG_SOLICIT ||
			type == DHCPV6_MSG_REQUEST)) {
		ia_pd = &pref;
		ia_pd_len = sizeof(pref);
	}

	// Build IA_NAs
	size_t ia_na_len;
	void *ia_na = odhcp6c_get_state(STATE_IA_NA, &ia_na_len);
	struct dhcpv6_ia_hdr hdr_ia_na = {
		htons(DHCPV6_OPT_IA_NA),
		htons(sizeof(hdr_ia_na) - 4 + ia_na_len),
		1, 0, 0
	};

	// Reconfigure Accept
	struct {
		uint16_t type;
		uint16_t length;
	} reconf_accept = {htons(DHCPV6_OPT_RECONF_ACCEPT), 0};

	// Request Information Refresh
	uint16_t oro_refresh = htons(DHCPV6_OPT_INFO_REFRESH);

	// Prepare Header
	size_t oro_len;
	void *oro = odhcp6c_get_state(STATE_ORO, &oro_len);
	struct {
		uint8_t type;
		uint8_t trid[3];
		uint16_t elapsed_type;
		uint16_t elapsed_len;
		uint16_t elapsed_value;
		uint16_t oro_type;
		uint16_t oro_len;
	} hdr = {
		type, {trid[0], trid[1], trid[2]},
		htons(DHCPV6_OPT_ELAPSED), htons(2),
			htons((ecs > 0xffff) ? 0xffff : ecs),
		htons(DHCPV6_OPT_ORO), htons(oro_len),
	};

	struct iovec iov[] = {
		{&hdr, sizeof(hdr)},
		{oro, oro_len},
		{&oro_refresh, 0},
		{cl_id, cl_id_len},
		{srv_id, srv_id_len},
		{&reconf_accept, 0},
		{&fqdn, fqdn_len},
		{&hdr_ia_na, sizeof(hdr_ia_na)},
		{ia_na, ia_na_len},
		{&hdr_ia_pd, sizeof(hdr_ia_pd)},
		{ia_pd, ia_pd_len},
	};

	size_t cnt = ARRAY_SIZE(iov);
	if (type == DHCPV6_MSG_INFO_REQ) {
		cnt = 5;
		iov[2].iov_len = sizeof(oro_refresh);
		hdr.oro_len = htons(oro_len + sizeof(oro_refresh));
	} else if (!request_prefix) {
		cnt = 9;
	}

	// Disable IAs if not used
	if (type == DHCPV6_MSG_SOLICIT) {
		iov[5].iov_len = sizeof(reconf_accept);
	} else if (type != DHCPV6_MSG_REQUEST) {
		if (ia_na_len == 0)
			iov[7].iov_len = 0;
		if (ia_pd_len == 0)
			iov[9].iov_len = 0;
	}

	if (na_mode == IA_MODE_NONE)
		iov[7].iov_len = 0;

	struct sockaddr_in6 srv = {AF_INET6, htons(DHCPV6_SERVER_PORT),
		0, ALL_DHCPV6_RELAYS, ifindex};
	struct msghdr msg = {&srv, sizeof(srv), iov, cnt, NULL, 0, 0};

	sendmsg(sock, &msg, 0);
}


static int64_t dhcpv6_rand_delay(int64_t time)
{
	int random;
	read(urandom_fd, &random, sizeof(random));
	return (time * (random % 1000)) / 10000;
}


int dhcpv6_request(enum dhcpv6_msg type)
{
	uint8_t buf[1536];
	uint32_t timeout = UINT32_MAX;
	struct dhcpv6_retx *retx = &dhcpv6_retx[type];

	if (retx->delay) {
		struct timespec ts = {0, 0};
		ts.tv_nsec = dhcpv6_rand_delay(10 * DHCPV6_REQ_DELAY);
		nanosleep(&ts, NULL);
	}

	if (type == DHCPV6_MSG_RELEASE || type == DHCPV6_MSG_DECLINE)
		timeout = 3;
	else if (type == DHCPV6_MSG_UNKNOWN)
		timeout = t1;
	else if (type == DHCPV6_MSG_RENEW)
		timeout = t2 - t1;
	else if (type == DHCPV6_MSG_REBIND)
		timeout = t3 - t2;

	if (timeout == 0)
		return -1;

	syslog(LOG_NOTICE, "Sending %s (timeout %us)", retx->name, timeout);

	uint64_t start = odhcp6c_get_milli_time(), round_start = start, elapsed;

	// Generate transaction ID
	uint8_t trid[3];
	read(urandom_fd, trid, sizeof(trid));
	ssize_t len = -1;
	int64_t rto = 0;

	do {
		rto = (rto == 0) ? (retx->init_timeo * 1000 +
				dhcpv6_rand_delay(retx->init_timeo * 1000)) :
				(2 * rto + dhcpv6_rand_delay(rto));

		if (rto >= retx->max_timeo * 1000)
			rto = retx->max_timeo * 1000 +
				dhcpv6_rand_delay(retx->max_timeo * 1000);

		// Calculate end for this round and elapsed time
		uint64_t round_end = round_start + rto;
		elapsed = round_start - start;

		// Don't wait too long
		if (round_end - start > timeout * 1000)
			round_end = timeout * 1000 + start;

		// Built and send package
		if (type != DHCPV6_MSG_UNKNOWN)
			dhcpv6_send(type, trid, elapsed / 10);

		// Receive rounds
		for (; len < 0 && round_start < round_end;
				round_start = odhcp6c_get_milli_time()) {
			// Check for pending signal
			if (odhcp6c_signal_is_pending())
				return -1;

			// Set timeout for receiving
			uint64_t t = round_end - round_start;
			struct timeval timeout = {t / 1000, (t % 1000) * 1000};
			setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
					&timeout, sizeof(timeout));

			// Receive cycle
			len = recv(sock, buf, sizeof(buf), 0);

			if (!dhcpv6_response_is_valid(buf, len, trid, type))
				len = -1;

			if (len > 0) {
				uint8_t *opt = &buf[4];
				uint8_t *opt_end = opt + len - 4;

				round_start = odhcp6c_get_milli_time();
				elapsed = round_start - start;
				syslog(LOG_NOTICE, "Got a valid reply after "
						"%ums", (unsigned)elapsed);

				if (retx->handler_reply)
					len = retx->handler_reply(type,
						opt, opt_end, elapsed / 1000);
			}
		}

		// Allow
		if (retx->handler_finish)
			len = retx->handler_finish(elapsed / 1000);
	} while (len < 0 && elapsed / 1000 < timeout);

	return len;
}


static bool dhcpv6_response_is_valid(const void *buf, ssize_t len,
		const uint8_t transaction[3], enum dhcpv6_msg type)
{
	const struct dhcpv6_header *rep = buf;
	if (len < (ssize_t)sizeof(*rep) || memcmp(rep->tr_id,
			transaction, sizeof(rep->tr_id)))
		return false; // Invalid reply

	if (type == DHCPV6_MSG_SOLICIT) {
		if (rep->msg_type != DHCPV6_MSG_ADVERT &&
				rep->msg_type != DHCPV6_MSG_REPLY)
			return false;
	} else if (type == DHCPV6_MSG_UNKNOWN) {
		if (!accept_reconfig || rep->msg_type != DHCPV6_MSG_RECONF)
			return false;
	} else if (rep->msg_type != DHCPV6_MSG_REPLY) {
		return false;
	}

	uint8_t *end = ((uint8_t*)buf) + len, *odata;
	uint16_t otype, olen;
	bool clientid_ok = false, serverid_ok = false;

	size_t client_id_len, server_id_len;
	void *client_id = odhcp6c_get_state(STATE_CLIENT_ID, &client_id_len);
	void *server_id = odhcp6c_get_state(STATE_SERVER_ID, &server_id_len);

	dhcpv6_for_each_option(&rep[1], end, otype, olen, odata)
		if (otype == DHCPV6_OPT_CLIENTID)
			clientid_ok = (olen + 4U == client_id_len) && !memcmp(
					&odata[-4], client_id, client_id_len);
		else if (otype == DHCPV6_OPT_SERVERID)
			serverid_ok = (olen + 4U == server_id_len) && !memcmp(
					&odata[-4], server_id, server_id_len);

	return clientid_ok && (serverid_ok || server_id_len == 0);
}


int dhcpv6_poll_reconfigure(void)
{
	int ret = dhcpv6_request(DHCPV6_MSG_UNKNOWN);
	if (ret != -1)
		ret = dhcpv6_request(ret);

	return ret;
}


static int dhcpv6_handle_reconfigure(_unused enum dhcpv6_msg orig,
		const void *opt, const void *end, uint32_t elapsed)
{
	// TODO: should verify the reconfigure message
	uint16_t otype, olen;
	uint8_t *odata, msg = DHCPV6_MSG_RENEW;
	dhcpv6_for_each_option(opt, end, otype, olen, odata)
		if (otype == DHCPV6_OPT_RECONF_MESSAGE && olen == 1 && (
				odata[0] == DHCPV6_MSG_RENEW ||
				odata[0] == DHCPV6_MSG_INFO_REQ))
			msg = odata[0];

	t1 -= elapsed;
	t2 -= elapsed;
	t3 -= elapsed;

	if (t1 < 0)
		t1 = 0;

	if (t2 < 0)
		t2 = 0;

	if (t3 < 0)
		t3 = 0;

	dhcpv6_handle_reply(DHCPV6_MSG_UNKNOWN, NULL, NULL, elapsed);
	return msg;
}


// Collect all advertised servers
static int dhcpv6_handle_advert(_unused enum dhcpv6_msg orig,
		const void *opt, const void *end, _unused uint32_t elapsed)
{
	uint16_t olen, otype;
	uint8_t *odata;
	struct dhcpv6_server_cand cand = {false, false, 0, 0, {0}};

	dhcpv6_for_each_option(opt, end, otype, olen, odata) {
		if (otype == DHCPV6_OPT_SERVERID && olen <= 130) {
			memcpy(cand.duid, odata, olen);
			cand.duid_len = olen;
		} else if (otype == DHCPV6_OPT_STATUS && olen >= 2 && !odata[0]
				&& odata[1] == DHCPV6_NoAddrsAvail) {
			if (na_mode == IA_MODE_FORCE) {
				return -1;
			} else {
				cand.has_noaddravail = true;
				cand.preference -= 1000;
			}
		} else if (otype == DHCPV6_OPT_STATUS && olen >= 2 && !odata[0]
				&& odata[1] == DHCPV6_NoPrefixAvail) {
			cand.preference -= 2000;
		} else if (otype == DHCPV6_OPT_PREF && olen >= 1 &&
				cand.preference >= 0) {
			cand.preference = odata[1];
		} else if (otype == DHCPV6_OPT_RECONF_ACCEPT) {
			cand.wants_reconfigure = true;
		} else if (otype == DHCPV6_OPT_IA_PD && request_prefix) {
			struct dhcpv6_ia_hdr *h = (void*)odata;
			uint8_t *oend = odata + olen, *d;
			dhcpv6_for_each_option(&h[1], oend, otype, olen, d) {
				if (otype == DHCPV6_OPT_IA_PREFIX)
					cand.preference += 2000;
				else if (otype == DHCPV6_OPT_STATUS &&
						olen >= 2 && d[0] == 0 &&
						d[1] == DHCPV6_NoPrefixAvail)
					cand.preference -= 2000;
			}
		}
	}

	if (cand.duid_len > 0)
		odhcp6c_add_state(STATE_SERVER_CAND, &cand, sizeof(cand));

	return -1;
}


static int dhcpv6_commit_advert(_unused uint32_t elapsed)
{
	size_t cand_len;
	struct dhcpv6_server_cand *c = NULL, *cand =
			odhcp6c_get_state(STATE_SERVER_CAND, &cand_len);

	bool retry = false;
	for (size_t i = 0; i < cand_len / sizeof(*c); ++i) {
		if (cand[i].has_noaddravail)
			retry = true; // We want to try again

		if (!c || c->preference < cand[i].preference)
			c = &cand[i];
	}

	if (retry && na_mode == IA_MODE_TRY) {
		// We give it a second try without the IA_NA
		na_mode = IA_MODE_NONE;
		return dhcpv6_request(DHCPV6_MSG_SOLICIT);
	}

	if (c) {
		uint16_t hdr[2] = {htons(DHCPV6_OPT_SERVERID),
				htons(c->duid_len)};
		odhcp6c_add_state(STATE_SERVER_ID, hdr, sizeof(hdr));
		odhcp6c_add_state(STATE_SERVER_ID, c->duid, c->duid_len);
		accept_reconfig = c->wants_reconfigure;
	}

	odhcp6c_clear_state(STATE_SERVER_CAND);

	if (!c)
		return -1;
	else if (request_prefix || na_mode != IA_MODE_NONE)
		return DHCPV6_STATEFUL;
	else
		return DHCPV6_STATELESS;
}


static int dhcpv6_handle_rebind_reply(enum dhcpv6_msg orig,
		const void *opt, const void *end, uint32_t elapsed)
{
	dhcpv6_handle_advert(orig, opt, end, elapsed);
	if (dhcpv6_commit_advert(elapsed) < 0)
		return -1;

	return dhcpv6_handle_reply(orig, opt, end, elapsed);
}


static int dhcpv6_handle_reply(_unused enum dhcpv6_msg orig,
		const void *opt, const void *end, uint32_t elapsed)
{
	uint16_t otype, olen;
	uint8_t *odata;
	bool have_update = false;

	t1 = t2 = t3 = 86400;

	size_t ia_na_len, dns_len, search_len;
	uint8_t *ia_na = odhcp6c_get_state(STATE_IA_NA, &ia_na_len);
	uint8_t *ia_end;
	odhcp6c_get_state(STATE_DNS, &dns_len);
	odhcp6c_get_state(STATE_SEARCH, &search_len);

	// Decrease valid and preferred lifetime of prefixes
	size_t ia_pd_len;
	uint8_t *ia_pd = odhcp6c_get_state(STATE_IA_PD, &ia_pd_len);
	dhcpv6_for_each_option(ia_pd, ia_pd + ia_pd_len, otype, olen, odata) {
		struct dhcpv6_ia_prefix *p = (void*)&odata[-4];
		uint32_t valid = ntohl(p->valid);
		p->valid = (valid < elapsed) ? 0 : htonl(valid - elapsed);

		uint32_t pref = ntohl(p->preferred);
		p->preferred = (pref < elapsed) ? 0 : htonl(pref - elapsed);
	}

	// Decrease valid and preferred lifetime of addresses
	dhcpv6_for_each_option(ia_na, ia_na + ia_na_len, otype, olen, odata) {
		struct dhcpv6_ia_addr *p = (void*)&odata[-4];
		uint32_t valid = ntohl(p->valid);
		p->valid = (valid < elapsed) ? 0 : htonl(valid - elapsed);

		uint32_t pref = ntohl(p->preferred);
		p->preferred = (pref < elapsed) ? 0 : htonl(pref - elapsed);
	}

	// Parse and find all matching IAs
	dhcpv6_for_each_option(opt, end, otype, olen, odata) {
		if ((otype == DHCPV6_OPT_IA_PD || otype == DHCPV6_OPT_IA_NA)
				&& olen > sizeof(struct dhcpv6_ia_hdr)) {
			struct dhcpv6_ia_hdr *ia_hdr = (void*)(&odata[-4]);
			time_t l_t1 = ntohl(ia_hdr->t1);
			time_t l_t2 = ntohl(ia_hdr->t2);

			// Test ID and T1-T2 validity
			if (ia_hdr->iaid != 1 || l_t2 < l_t1)
				continue;

			uint16_t stype, slen;
			uint8_t *sdata;
			// Test status and bail if error
			dhcpv6_for_each_option(&ia_hdr[1], odata + olen,
					stype, slen, sdata)
				if (stype == DHCPV6_OPT_STATUS && slen >= 2 &&
						(sdata[0] || sdata[1]))
					continue;

			// Update times
			if (l_t1 > 0 && t1 > l_t1)
				t1 = l_t1;

			if (l_t2 > 0 && t2 > l_t2)
				t2 = l_t2;

			// Always report update in case we have IA_PDs so that
			// the state-script is called with updated times
			if (otype == DHCPV6_OPT_IA_PD && request_prefix)
				have_update = true;

			time_t n = dhcpv6_parse_ia(&ia_hdr[1], odata + olen);

			if (n < t1)
				t1 = n;

			if (n < t2)
				t2 = n;

			if (n < t3)
				t3 = n;

		} else if (otype == DHCPV6_OPT_DNS_SERVERS) {
			odhcp6c_add_state(STATE_DNS, odata, olen);
		} else if (otype == DHCPV6_OPT_DNS_DOMAIN) {
			odhcp6c_add_state(STATE_SEARCH, odata, olen);
		} else if (otype == DHCPV6_OPT_INFO_REFRESH && olen >= 4) {
			uint32_t refresh = ntohl(*((uint32_t*)odata));
			if (refresh < (uint32_t)t1)
				t1 = refresh;
		} else if (otype != DHCPV6_OPT_CLIENTID &&
				otype != DHCPV6_OPT_SERVERID) {
			odhcp6c_add_state(STATE_CUSTOM_OPTS,
					&odata[-4], olen + 4);
		}
	}

	if (opt) {
		have_update |= odhcp6c_commit_state(STATE_DNS, dns_len);
		have_update |= odhcp6c_commit_state(STATE_SEARCH, search_len);
		size_t new_ia_pd_len, new_ia_na_len;
		odhcp6c_get_state(STATE_IA_PD, &new_ia_pd_len);
		odhcp6c_get_state(STATE_IA_NA, &new_ia_na_len);
		have_update |= (new_ia_pd_len != ia_pd_len) ||
				(new_ia_na_len != ia_na_len);
	}

	// Delete prefixes with 0 valid-time
	ia_pd = odhcp6c_get_state(STATE_IA_PD, &ia_pd_len);
	ia_end = ia_pd + ia_pd_len;
	dhcpv6_for_each_option(ia_pd, ia_end, otype, olen, odata) {
		struct dhcpv6_ia_prefix *p = (void*)&odata[-4];
		while (!p->valid) {
			ia_end = ia_pd + odhcp6c_remove_state(STATE_IA_PD,
					(uint8_t*)p - ia_pd, olen + 4);
			have_update = true;
		}
	}


	// Delete addresses with 0 valid-time
	ia_na = odhcp6c_get_state(STATE_IA_NA, &ia_na_len);
	ia_end = ia_na + ia_na_len;
	dhcpv6_for_each_option(ia_na, ia_end, otype, olen, odata) {
		struct dhcpv6_ia_addr *p = (void*)&odata[-4];
		while (!p->valid) {
			ia_end = ia_na + odhcp6c_remove_state(STATE_IA_NA,
					(uint8_t*)p - ia_na, olen + 4);
			have_update = true;
		}
	}

	return have_update;
}


static time_t dhcpv6_parse_ia(void *opt, void *end)
{
	uint32_t timeout = UINT32_MAX; // Minimum timeout
	uint16_t otype, olen, stype, slen;
	uint8_t *odata, *sdata;

	// Update address IA
	dhcpv6_for_each_option(opt, end, otype, olen, odata) {
		if (otype == DHCPV6_OPT_IA_PREFIX) {
			struct dhcpv6_ia_prefix *prefix = (void*)&odata[-4];
			if (olen + 4U < sizeof(*prefix))
				continue;

			olen = sizeof(*prefix); // Normalize length
			uint32_t valid = ntohl(prefix->valid);
			uint32_t pref = ntohl(prefix->preferred);

			if (pref > valid)
				continue;

			// Search matching IA
			struct dhcpv6_ia_prefix *local = NULL;
			size_t pd_len;
			uint8_t *pd = odhcp6c_get_state(STATE_IA_PD, &pd_len);
			dhcpv6_for_each_option(pd, pd + pd_len,
					stype, slen, sdata)
				if (!memcmp(sdata + 8, odata + 8,
						sizeof(local->addr) + 1))
					local = (void*)&sdata[-4];

			if (local) { // Already know that IA
				local->preferred = prefix->preferred;
				local->valid = prefix->valid;
			} else { // New IA
				odhcp6c_add_state(STATE_IA_PD, prefix, olen);
			}

			if (timeout > valid)
				timeout = valid;

			if (prefix->valid == 0) // We probably lost that prefix
				odhcp6c_add_state(STATE_IA_PD_LOST,
						prefix, olen);
		} else if (otype == DHCPV6_OPT_IA_ADDR) {
			struct dhcpv6_ia_addr *addr = (void*)&odata[-4];
			if (olen + 4U < sizeof(*addr))
				continue;

			olen = sizeof(*addr); // Normalize length
			uint32_t pref = ntohl(addr->preferred);
			uint32_t valid = ntohl(addr->valid);

			if (pref > valid)
				continue;

			// Search matching IA
			struct dhcpv6_ia_addr *local = NULL;
			size_t na_len;
			uint8_t *na = odhcp6c_get_state(STATE_IA_NA, &na_len);
			dhcpv6_for_each_option(na, na + na_len,
					stype, slen, sdata)
				if (!memcmp(sdata, odata, sizeof(local->addr)))
					local = (void*)&sdata[-4];


			if (local) { // Already know that IA
				local->preferred = addr->preferred;
				local->valid = addr->valid;
			} else { // New IA
				odhcp6c_add_state(STATE_IA_NA, addr, olen);
			}


			if (timeout > valid)
				timeout = valid;

			if (set_rtnetlink_addr(ifindex, &addr->addr,
					pref, valid) == -EADDRNOTAVAIL) {
				dhcpv6_request(DHCPV6_MSG_DECLINE);
				raise(SIGUSR2);
			}
		}
	}

	return timeout;
}
