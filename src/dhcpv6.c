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

#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
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
#include "md5.h"


#define ALL_DHCPV6_RELAYS {{{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,\
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02}}}
#define DHCPV6_CLIENT_PORT 546
#define DHCPV6_SERVER_PORT 547
#define DHCPV6_DUID_LLADDR 3
#define DHCPV6_REQ_DELAY 1


static bool dhcpv6_response_is_valid(const void *buf, ssize_t len,
		const uint8_t transaction[3], enum dhcpv6_msg type);

static uint32_t dhcpv6_parse_ia(void *opt, void *end);

static reply_handler dhcpv6_handle_reply;
static reply_handler dhcpv6_handle_advert;
static reply_handler dhcpv6_handle_rebind_reply;
static reply_handler dhcpv6_handle_reconfigure;
static int dhcpv6_commit_advert(void);



// RFC 3315 - 5.5 Timeout and Delay values
static struct dhcpv6_retx dhcpv6_retx[_DHCPV6_MSG_MAX] = {
	[DHCPV6_MSG_UNKNOWN] = {false, 1, 120, "<POLL>",
			dhcpv6_handle_reconfigure, NULL},
	[DHCPV6_MSG_SOLICIT] = {true, 1, 3600, "SOLICIT",
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
static int ifindex = -1;
static int64_t t1 = 0, t2 = 0, t3 = 0;

// IA states
static int request_prefix = -1;
static enum odhcp6c_ia_mode na_mode = IA_MODE_NONE, pd_mode = IA_MODE_NONE;
static bool accept_reconfig = false;

// Reconfigure key
static uint8_t reconf_key[16];



int init_dhcpv6(const char *ifname, int request_pd)
{
	request_prefix = request_pd;

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

		uint8_t zero[ETHER_ADDR_LEN] = {0, 0, 0, 0, 0, 0};
		struct ifreq ifs[100], *ifp, *ifend;
		struct ifconf ifc;
		ifc.ifc_req = ifs;
		ifc.ifc_len = sizeof(ifs);

		if (!memcmp(&duid[8], zero, ETHER_ADDR_LEN) &&
				ioctl(sock, SIOCGIFCONF, &ifc) >= 0) {
			// If our interface doesn't have an address...
			ifend = ifs + (ifc.ifc_len / sizeof(struct ifreq));
			for (ifp = ifc.ifc_req; ifp < ifend &&
					!memcmp(&duid[8], zero, 6); ifp++) {
				memcpy(ifr.ifr_name, ifp->ifr_name,
						sizeof(ifr.ifr_name));
				ioctl(sock, SIOCGIFHWADDR, &ifr);
				memcpy(&duid[8], ifr.ifr_hwaddr.sa_data,
						ETHER_ADDR_LEN);
			}
		}

		odhcp6c_add_state(STATE_CLIENT_ID, duid, sizeof(duid));
	}

	// Create ORO
	uint16_t oro[] = {
			htons(DHCPV6_OPT_SIP_SERVER_D),
			htons(DHCPV6_OPT_SIP_SERVER_A),
			htons(DHCPV6_OPT_DNS_SERVERS),
			htons(DHCPV6_OPT_DNS_DOMAIN),
			htons(DHCPV6_OPT_NTP_SERVER),
			htons(DHCPV6_OPT_SIP_SERVER_A),
			htons(DHCPV6_OPT_AFTR_NAME),
			htons(DHCPV6_OPT_PD_EXCLUDE),
#ifdef EXT_PREFIX_CLASS
			htons(DHCPV6_OPT_PREFIX_CLASS),
#endif
	};
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


void dhcpv6_set_ia_mode(enum odhcp6c_ia_mode na, enum odhcp6c_ia_mode pd)
{
	na_mode = na;
	pd_mode = pd;
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
	size_t ia_pd_entries, ia_pd_len = 0;
	struct odhcp6c_entry *e = odhcp6c_get_state(STATE_IA_PD, &ia_pd_entries);
	ia_pd_entries /= sizeof(*e);
	struct dhcpv6_ia_hdr hdr_ia_pd = {
		htons(DHCPV6_OPT_IA_PD),
		htons(sizeof(hdr_ia_pd) - 4),
		1, 0, 0
	};


	uint8_t *ia_pd = alloca(ia_pd_entries * (sizeof(struct dhcpv6_ia_prefix) + 10));
	for (size_t i = 0; i < ia_pd_entries; ++i) {
		uint8_t ex_len = 0;
		if (e[i].priority > 0)
			ex_len = ((e[i].priority - e[i].length - 1) / 8) + 6;

		struct dhcpv6_ia_prefix p = {
			.type = htons(DHCPV6_OPT_IA_PREFIX),
			.len = htons(sizeof(p) - 4U + ex_len),
			.prefix = e[i].length,
			.addr = e[i].target
		};

		memcpy(ia_pd + ia_pd_len, &p, sizeof(p));
		ia_pd_len += sizeof(p);

		if (ex_len) {
			ia_pd[ia_pd_len++] = 0;
			ia_pd[ia_pd_len++] = DHCPV6_OPT_PD_EXCLUDE;
			ia_pd[ia_pd_len++] = 0;
			ia_pd[ia_pd_len++] = ex_len - 4;
			ia_pd[ia_pd_len++] = e[i].priority;

			uint32_t excl = ntohl(e[i].router.s6_addr32[1]);
			excl >>= (64 - e[i].priority);
			excl <<= 8 - ((e[i].priority - e[i].length) % 8);

			for (size_t i = ex_len - 5; i > 0; --i, excl >>= 8)
				ia_pd[ia_pd_len + i] = excl & 0xff;
			ia_pd_len += ex_len - 5;
		}
	}

	struct dhcpv6_ia_prefix pref = {
		.type = htons(DHCPV6_OPT_IA_PREFIX),
		.len = htons(25), .prefix = request_prefix
	};
	if (request_prefix > 0 && ia_pd_len == 0 && type == DHCPV6_MSG_SOLICIT) {
		ia_pd = (uint8_t*)&pref;
		ia_pd_len = sizeof(pref);
	}
	hdr_ia_pd.len = htons(ntohs(hdr_ia_pd.len) + ia_pd_len);

	// Build IA_NAs
	size_t ia_na_entries, ia_na_len = 0;
	void *ia_na = NULL;
	e = odhcp6c_get_state(STATE_IA_NA, &ia_na_entries);
	ia_na_entries /= sizeof(*e);

	struct dhcpv6_ia_hdr hdr_ia_na = {
		htons(DHCPV6_OPT_IA_NA),
		htons(sizeof(hdr_ia_na) - 4),
		1, 0, 0
	};

	struct dhcpv6_ia_addr pa[ia_na_entries];
	for (size_t i = 0; i < ia_na_entries; ++i) {
		pa[i].type = htons(DHCPV6_OPT_IA_ADDR);
		pa[i].len = htons(sizeof(pa[i]) - 4U);
		pa[i].addr = e[i].target;
		pa[i].preferred = 0;
		pa[i].valid = 0;
	}

	ia_na = pa;
	ia_na_len = sizeof(pa);
	hdr_ia_na.len = htons(ntohs(hdr_ia_na.len) + ia_na_len);

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
		{&reconf_accept, sizeof(reconf_accept)},
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
	if (type != DHCPV6_MSG_SOLICIT) {
		iov[5].iov_len = 0;
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
	odhcp6c_random(&random, sizeof(random));
	return (time * ((int64_t)random % 1000LL)) / 10000LL;
}


int dhcpv6_request(enum dhcpv6_msg type)
{
	uint8_t buf[1536];
	uint64_t timeout = UINT32_MAX;
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
		timeout = (t2 > t1) ? t2 - t1 : 0;
	else if (type == DHCPV6_MSG_REBIND)
		timeout = (t3 > t2) ? t3 - t2 : 0;

	if (timeout == 0)
		return -1;

	syslog(LOG_NOTICE, "Sending %s (timeout %us)", retx->name, (unsigned)timeout);

	uint64_t start = odhcp6c_get_milli_time(), round_start = start, elapsed;

	// Generate transaction ID
	uint8_t trid[3] = {0, 0, 0};
	if (type != DHCPV6_MSG_UNKNOWN)
		odhcp6c_random(trid, sizeof(trid));
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
			if (odhcp6c_signal_process())
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
					len = retx->handler_reply(
							type, opt, opt_end);

				if (len > 0 && round_end - round_start > 1000)
					round_end = 1000 + round_start;
			}
		}

		// Allow
		if (retx->handler_finish)
			len = retx->handler_finish();
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
	bool clientid_ok = false, serverid_ok = false, rcauth_ok = false;

	size_t client_id_len, server_id_len;
	void *client_id = odhcp6c_get_state(STATE_CLIENT_ID, &client_id_len);
	void *server_id = odhcp6c_get_state(STATE_SERVER_ID, &server_id_len);

	dhcpv6_for_each_option(&rep[1], end, otype, olen, odata) {
		if (otype == DHCPV6_OPT_CLIENTID) {
			clientid_ok = (olen + 4U == client_id_len) && !memcmp(
					&odata[-4], client_id, client_id_len);
		} else if (otype == DHCPV6_OPT_SERVERID) {
			serverid_ok = (olen + 4U == server_id_len) && !memcmp(
					&odata[-4], server_id, server_id_len);
		} else if (otype == DHCPV6_OPT_AUTH && olen == -4 +
				sizeof(struct dhcpv6_auth_reconfigure)) {
			struct dhcpv6_auth_reconfigure *r = (void*)&odata[-4];
			if (r->protocol != 3 || r->algorithm != 1 || r->reconf_type != 2)
				continue;

			md5_state_t md5;
			uint8_t serverhash[16], secretbytes[16], hash[16];
			memcpy(serverhash, r->key, sizeof(serverhash));
			memset(r->key, 0, sizeof(r->key));
			memcpy(secretbytes, reconf_key, sizeof(secretbytes));

			for (size_t i = 0; i < sizeof(secretbytes); ++i)
				secretbytes[i] ^= 0x36;

			md5_init(&md5);
			md5_append(&md5, secretbytes, sizeof(secretbytes));
			md5_append(&md5, buf, len);
			md5_finish(&md5, hash);

			for (size_t i = 0; i < sizeof(secretbytes); ++i) {
				secretbytes[i] ^= 0x36;
				secretbytes[i] ^= 0x5c;
			}

			md5_init(&md5);
			md5_append(&md5, secretbytes, sizeof(secretbytes));
			md5_append(&md5, hash, 16);
			md5_finish(&md5, hash);

			rcauth_ok = !memcmp(hash, serverhash, sizeof(hash));
		}
	}

	if (rep->msg_type == DHCPV6_MSG_RECONF && !rcauth_ok)
		return false;

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
		const void *opt, const void *end)
{
	// TODO: should verify the reconfigure message
	uint16_t otype, olen;
	uint8_t *odata, msg = DHCPV6_MSG_RENEW;
	dhcpv6_for_each_option(opt, end, otype, olen, odata)
		if (otype == DHCPV6_OPT_RECONF_MESSAGE && olen == 1 && (
				odata[0] == DHCPV6_MSG_RENEW ||
				odata[0] == DHCPV6_MSG_INFO_REQ))
			msg = odata[0];

	dhcpv6_handle_reply(DHCPV6_MSG_UNKNOWN, NULL, NULL);
	return msg;
}


// Collect all advertised servers
static int dhcpv6_handle_advert(enum dhcpv6_msg orig,
		const void *opt, const void *end)
{
	uint16_t olen, otype;
	uint8_t *odata;
	struct dhcpv6_server_cand cand = {false, false, 0, 0, {0}, NULL, NULL, 0, 0};
	bool have_na = false, have_pd = false;

	dhcpv6_for_each_option(opt, end, otype, olen, odata) {
		if (orig == DHCPV6_MSG_SOLICIT &&
				(otype == DHCPV6_OPT_IA_PD || otype == DHCPV6_OPT_IA_NA) &&
				olen > sizeof(struct dhcpv6_ia_hdr)) {
			struct dhcpv6_ia_hdr *ia_hdr = (void*)(&odata[-4]);
			dhcpv6_parse_ia(&ia_hdr[1], odata + olen);
		}

		if (otype == DHCPV6_OPT_SERVERID && olen <= 130) {
			memcpy(cand.duid, odata, olen);
			cand.duid_len = olen;
		} else if (otype == DHCPV6_OPT_STATUS && olen >= 2 && !odata[0]
				&& odata[1] == DHCPV6_NoPrefixAvail) {
			cand.preference -= 2000;
		} else if (otype == DHCPV6_OPT_PREF && olen >= 1 &&
				cand.preference >= 0) {
			cand.preference = odata[0];
		} else if (otype == DHCPV6_OPT_RECONF_ACCEPT) {
			cand.wants_reconfigure = true;
		} else if (otype == DHCPV6_OPT_IA_PD && request_prefix) {
			struct dhcpv6_ia_hdr *h = (struct dhcpv6_ia_hdr*)&odata[-4];
			uint8_t *oend = odata + olen, *d;
			dhcpv6_for_each_option(&h[1], oend, otype, olen, d)
				if (otype == DHCPV6_OPT_IA_PREFIX)
					have_pd = true;
		} else if (otype == DHCPV6_OPT_IA_NA) {
			struct dhcpv6_ia_hdr *h = (struct dhcpv6_ia_hdr*)&odata[-4];
			uint8_t *oend = odata + olen, *d;
			dhcpv6_for_each_option(&h[1], oend, otype, olen, d)
				if (otype == DHCPV6_OPT_IA_ADDR)
					have_na = true;
		}
	}

	if ((!have_na && na_mode == IA_MODE_FORCE) ||
			(!have_pd && pd_mode == IA_MODE_FORCE))
		return -1;

	if (na_mode != IA_MODE_NONE && !have_na) {
		cand.has_noaddravail = true;
		cand.preference -= 1000;
	}

	if (pd_mode != IA_MODE_NONE) {
		if (have_pd)
			cand.preference += 2000;
		else
			cand.preference -= 2000;
	}

	if (cand.duid_len > 0) {
		cand.ia_na = odhcp6c_move_state(STATE_IA_NA, &cand.ia_na_len);
		cand.ia_pd = odhcp6c_move_state(STATE_IA_PD, &cand.ia_pd_len);
		odhcp6c_add_state(STATE_SERVER_CAND, &cand, sizeof(cand));
	}

	if (orig == DHCPV6_MSG_SOLICIT) {
		odhcp6c_clear_state(STATE_IA_NA);
		odhcp6c_clear_state(STATE_IA_PD);
	}

	return -1;
}


static int dhcpv6_commit_advert(void)
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
		odhcp6c_add_state(STATE_IA_NA, c->ia_na, c->ia_na_len);
		odhcp6c_add_state(STATE_IA_PD, c->ia_pd, c->ia_pd_len);
	}

	for (size_t i = 0; i < cand_len / sizeof(*c); ++i) {
		free(cand[i].ia_na);
		free(cand[i].ia_pd);
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
		const void *opt, const void *end)
{
	dhcpv6_handle_advert(orig, opt, end);
	if (dhcpv6_commit_advert() < 0) {
		dhcpv6_handle_reply(DHCPV6_MSG_UNKNOWN, NULL, NULL);
		return -1;
	}

	return dhcpv6_handle_reply(orig, opt, end);
}


static int dhcpv6_handle_reply(enum dhcpv6_msg orig,
		const void *opt, const void *end)
{
	uint8_t *odata;
	uint16_t otype, olen;

	odhcp6c_expire();

	if (orig == DHCPV6_MSG_UNKNOWN) {
		static time_t last_update = 0;
		time_t now = odhcp6c_get_milli_time() / 1000;

		uint32_t elapsed = (last_update > 0) ? now - last_update : 0;
		last_update = now;

		t1 -= elapsed;
		t2 -= elapsed;
		t3 -= elapsed;

		if (t1 < 0)
			t1 = 0;

		if (t2 < 0)
			t2 = 0;

		if (t3 < 0)
			t3 = 0;
	} else {
		t1 = t2 = t3 = UINT32_MAX;
	}

	if (orig == DHCPV6_MSG_REQUEST) {
		// Delete NA and PD we have in the state from the Advert
		odhcp6c_clear_state(STATE_IA_NA);
		odhcp6c_clear_state(STATE_IA_PD);
	}

	if (opt) {
		odhcp6c_clear_state(STATE_DNS);
		odhcp6c_clear_state(STATE_SEARCH);
		odhcp6c_clear_state(STATE_SNTP_IP);
		odhcp6c_clear_state(STATE_SNTP_FQDN);
		odhcp6c_clear_state(STATE_SIP_IP);
		odhcp6c_clear_state(STATE_SIP_FQDN);
		odhcp6c_clear_state(STATE_AFTR_NAME);
	}

	// Parse and find all matching IAs
	dhcpv6_for_each_option(opt, end, otype, olen, odata) {
		if ((otype == DHCPV6_OPT_IA_PD || otype == DHCPV6_OPT_IA_NA)
				&& olen > sizeof(struct dhcpv6_ia_hdr)) {
			struct dhcpv6_ia_hdr *ia_hdr = (void*)(&odata[-4]);
			uint32_t l_t1 = ntohl(ia_hdr->t1);
			uint32_t l_t2 = ntohl(ia_hdr->t2);

			// Test ID and T1-T2 validity
			if (ia_hdr->iaid != 1 || l_t2 < l_t1)
				continue;

			int error = 0;
			uint16_t stype, slen;
			uint8_t *sdata;
			// Test status and bail if error
			dhcpv6_for_each_option(&ia_hdr[1], odata + olen,
					stype, slen, sdata)
				if (stype == DHCPV6_OPT_STATUS && slen >= 2)
					error = ((int)sdata[0]) << 8 | ((int)sdata[1]);

			if (error) {
				syslog(LOG_WARNING, "Server returned IAID status %i!", error);
				if (error != 2)
					raise(SIGUSR2);
				break;
			}

			uint32_t n = dhcpv6_parse_ia(&ia_hdr[1], odata + olen);

			if (!l_t1)
				l_t1 = 300;

			if (!l_t2)
				l_t2 = 600;

			if (n < t3)
				t3 = n;

			// Update times
			if (l_t1 > 0 && t1 > l_t1)
				t1 = l_t1;

			if (l_t2 > 0 && t2 > l_t2)
				t2 = l_t2;

		} else if (otype == DHCPV6_OPT_DNS_SERVERS) {
			if (olen % 16 == 0)
				odhcp6c_add_state(STATE_DNS, odata, olen);
		} else if (otype == DHCPV6_OPT_DNS_DOMAIN) {
			odhcp6c_add_state(STATE_SEARCH, odata, olen);
		} else if (otype == DHCPV6_OPT_NTP_SERVER) {
			uint16_t stype, slen;
			uint8_t *sdata;
			// Test status and bail if error
			dhcpv6_for_each_option(odata, odata + olen,
					stype, slen, sdata) {
				if (slen == 16 && (stype == NTP_MC_ADDR ||
						stype == NTP_SRV_ADDR))
					odhcp6c_add_state(STATE_SNTP_IP,
							sdata, slen);
				else if (slen > 0 && stype == NTP_SRV_FQDN)
					odhcp6c_add_state(STATE_SNTP_FQDN,
							sdata, slen);
			}
		} else if (otype == DHCPV6_OPT_SIP_SERVER_A) {
			if (olen == 16)
				odhcp6c_add_state(STATE_SIP_IP, odata, olen);
		} else if (otype == DHCPV6_OPT_SIP_SERVER_D) {
			odhcp6c_add_state(STATE_SIP_FQDN, odata, olen);
		} else if (otype == DHCPV6_OPT_INFO_REFRESH && olen >= 4) {
			uint32_t refresh = ntohl(*((uint32_t*)odata));
			if (refresh < (uint32_t)t1)
				t1 = refresh;
		} else if (otype == DHCPV6_OPT_AUTH && olen == -4 +
				sizeof(struct dhcpv6_auth_reconfigure)) {
			struct dhcpv6_auth_reconfigure *r = (void*)&odata[-4];
			if (r->protocol == 3 && r->algorithm == 1 &&
					r->reconf_type == 1)
				memcpy(reconf_key, r->key, sizeof(r->key));
		} else if (otype == DHCPV6_OPT_AFTR_NAME && olen > 3) {
			size_t cur_len;
			odhcp6c_get_state(STATE_AFTR_NAME, &cur_len);
			if (cur_len == 0)
				odhcp6c_add_state(STATE_AFTR_NAME, odata, olen);
		} else if (otype != DHCPV6_OPT_CLIENTID &&
				otype != DHCPV6_OPT_SERVERID) {
			odhcp6c_add_state(STATE_CUSTOM_OPTS,
					&odata[-4], olen + 4);
		}
	}

	if (t1 == UINT32_MAX)
		t1 = 300;

	if (t2 == UINT32_MAX)
		t2 = 600;

	if (t3 == UINT32_MAX)
		t3 = 3600;

	return true;
}


static uint32_t dhcpv6_parse_ia(void *opt, void *end)
{
	uint32_t timeout = UINT32_MAX; // Minimum timeout
	uint16_t otype, olen;
	uint8_t *odata;

	// Update address IA
	dhcpv6_for_each_option(opt, end, otype, olen, odata) {
		struct odhcp6c_entry entry = {IN6ADDR_ANY_INIT, 0, 0,
				IN6ADDR_ANY_INIT, 0, 0, 0};

		if (otype == DHCPV6_OPT_IA_PREFIX) {
			struct dhcpv6_ia_prefix *prefix = (void*)&odata[-4];
			if (olen + 4U < sizeof(*prefix))
				continue;

			entry.valid = ntohl(prefix->valid);
			entry.preferred = ntohl(prefix->preferred);

			if (entry.preferred > entry.valid)
				continue;

			entry.length = prefix->prefix;
			entry.target = prefix->addr;
			uint16_t stype, slen;
			uint8_t *sdata;

#ifdef EXT_PREFIX_CLASS
                        // Find prefix class, if any
			dhcpv6_for_each_option(&prefix[1], odata + olen,
					stype, slen, sdata)
				if (stype == DHCPV6_OPT_PREFIX_CLASS && slen == 2)
					entry.class = sdata[0] << 8 | sdata[1];
#endif

			// Parse PD-exclude
			bool ok = true;
			dhcpv6_for_each_option(odata + sizeof(*prefix) - 4U,
					odata + olen, stype, slen, sdata) {
				if (stype != DHCPV6_OPT_PD_EXCLUDE || slen < 2)
					continue;

				uint8_t elen = sdata[0];
				if (elen > 64)
					elen = 64;

				if (elen <= 32 || elen <= entry.length) {
					ok = false;
					continue;
				}


				uint8_t bytes = ((elen - entry.length - 1) / 8) + 1;
				if (slen <= bytes) {
					ok = false;
					continue;
				}

				uint32_t exclude = 0;
				do {
					exclude = exclude << 8 | sdata[bytes];
				} while (--bytes);

				exclude >>= 8 - ((elen - entry.length) % 8);
				exclude <<= 64 - elen;

				// Abusing router & priority fields for exclusion
				entry.router = entry.target;
				entry.router.s6_addr32[1] |= htonl(exclude);
				entry.priority = elen;
			}

			if (ok)
				odhcp6c_update_entry(STATE_IA_PD, &entry);

			entry.priority = 0;
			memset(&entry.router, 0, sizeof(entry.router));
		} else if (otype == DHCPV6_OPT_IA_ADDR) {
			struct dhcpv6_ia_addr *addr = (void*)&odata[-4];
			if (olen + 4U < sizeof(*addr))
				continue;

			entry.preferred = ntohl(addr->preferred);
			entry.valid = ntohl(addr->valid);

			if (entry.preferred > entry.valid)
				continue;

			entry.length = 128;
			entry.target = addr->addr;

#ifdef EXT_PREFIX_CLASS
			uint16_t stype, slen;
			uint8_t *sdata;
			// Find prefix class, if any
			dhcpv6_for_each_option(&addr[1], odata + olen,
					stype, slen, sdata)
				if (stype == DHCPV6_OPT_PREFIX_CLASS && slen == 2)
					entry.class = sdata[0] << 8 | sdata[1];
#endif

			odhcp6c_update_entry(STATE_IA_NA, &entry);
		}
		if (entry.valid > 0 && timeout > entry.valid)
			timeout = entry.valid;
	}

	return timeout;
}
