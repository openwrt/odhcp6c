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
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#define _unused __attribute__((unused))
#define _packed __attribute__((packed))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#define ND_OPT_RECURSIVE_DNS 25
#define ND_OPT_DNSSL 31

enum dhcvp6_opt {
	DHCPV6_OPT_CLIENTID = 1,
	DHCPV6_OPT_SERVERID = 2,
	DHCPV6_OPT_IA_NA = 3,
	DHCPV6_OPT_IA_ADDR = 5,
	DHCPV6_OPT_ORO = 6,
	DHCPV6_OPT_PREF = 7,
	DHCPV6_OPT_ELAPSED = 8,
	DHCPV6_OPT_RELAY_MSG = 9,
	DHCPV6_OPT_AUTH = 11,
	DHCPV6_OPT_STATUS = 13,
	DHCPV6_OPT_RAPID_COMMIT = 14,
	DHCPV6_OPT_RECONF_MESSAGE = 19,
	DHCPV6_OPT_RECONF_ACCEPT = 20,
	DHCPV6_OPT_DNS_SERVERS = 23,
	DHCPV6_OPT_DNS_DOMAIN = 24,
	DHCPV6_OPT_IA_PD = 25,
	DHCPV6_OPT_IA_PREFIX = 26,
	DHCPV6_OPT_INFO_REFRESH = 32,
	DHCPV6_OPT_FQDN = 39,
	DHCPV6_OPT_NTP_SERVER = 56,
	DHCPV6_OPT_SIP_SERVER_D = 21,
	DHCPV6_OPT_SIP_SERVER_A = 22,
};

enum dhcpv6_opt_npt {
	NTP_SRV_ADDR = 1,
	NTP_MC_ADDR = 2,
	NTP_SRV_FQDN = 3
};

enum dhcpv6_msg {
	DHCPV6_MSG_UNKNOWN = 0,
	DHCPV6_MSG_SOLICIT = 1,
	DHCPV6_MSG_ADVERT = 2,
	DHCPV6_MSG_REQUEST = 3,
	DHCPV6_MSG_RENEW = 5,
	DHCPV6_MSG_REBIND = 6,
	DHCPV6_MSG_REPLY = 7,
	DHCPV6_MSG_RELEASE = 8,
	DHCPV6_MSG_DECLINE = 9,
	DHCPV6_MSG_RECONF = 10,
	DHCPV6_MSG_INFO_REQ = 11,
	_DHCPV6_MSG_MAX
};

enum dhcpv6_status {
	DHCPV6_NoAddrsAvail = 2,
	DHCPV6_NoPrefixAvail = 6,
};

typedef int(reply_handler)(enum dhcpv6_msg orig,
		const void *opt, const void *end);

// retransmission strategy
struct dhcpv6_retx {
	bool delay;
	uint8_t init_timeo;
	uint16_t max_timeo;
	char name[8];
	reply_handler *handler_reply;
	int(*handler_finish)(void);
};


// DHCPv6 Protocol Headers
struct dhcpv6_header {
	uint8_t msg_type;
	uint8_t tr_id[3];
} __attribute__((packed));

struct dhcpv6_ia_hdr {
	uint16_t type;
	uint16_t len;
	uint32_t iaid;
	uint32_t t1;
	uint32_t t2;
} _packed;

struct dhcpv6_ia_addr {
	uint16_t type;
	uint16_t len;
	struct in6_addr addr;
	uint32_t preferred;
	uint32_t valid;
} _packed;

struct dhcpv6_ia_prefix {
	uint16_t type;
	uint16_t len;
	uint32_t preferred;
	uint32_t valid;
	uint8_t prefix;
	struct in6_addr addr;
} _packed;

struct dhcpv6_duid {
	uint16_t type;
	uint16_t len;
	uint16_t duid_type;
	uint8_t data[128];
} _packed;


extern bool log_quiet;
#define dhcpv6_syslog(level, ...) \
	if (!log_quiet) {                \
		syslog(level, __VA_ARGS__);   \
	}


#define dhcpv6_for_each_option(start, end, otype, olen, odata)\
	for (uint8_t *_o = (uint8_t*)(start); _o + 4 <= (uint8_t*)(end) &&\
		((otype) = _o[0] << 8 | _o[1]) && ((odata) = (void*)&_o[4]) &&\
		((olen) = _o[2] << 8 | _o[3]) + (odata) <= (uint8_t*)(end); \
		_o += 4 + (_o[2] << 8 | _o[3]))


struct dhcpv6_server_cand {
	bool has_noaddravail;
	bool wants_reconfigure;
	int16_t preference;
	uint8_t duid_len;
	uint8_t duid[130];
};


enum odhcp6c_state {
	STATE_CLIENT_ID,
	STATE_SERVER_ID,
	STATE_SERVER_CAND,
	STATE_ORO,
	STATE_DNS,
	STATE_SEARCH,
	STATE_IA_NA,
	STATE_IA_PD,
	STATE_CUSTOM_OPTS,
	STATE_SNTP_IP,
	STATE_SNTP_FQDN,
	STATE_SIP_IP,
	STATE_SIP_FQDN,
	STATE_RA_ROUTE,
	STATE_RA_PREFIX,
	STATE_RA_DNS,
	_STATE_MAX
};


struct icmp6_opt {
	uint8_t type;
	uint8_t len;
	uint8_t data[6];
};


enum dhcpv6_mode {
	DHCPV6_UNKNOWN,
	DHCPV6_STATELESS,
	DHCPV6_STATEFUL
};


enum odhcp6c_ia_mode {
	IA_MODE_NONE,
	IA_MODE_TRY,
	IA_MODE_FORCE,
};


struct odhcp6c_entry {
	struct in6_addr router;
	uint16_t length;
	int16_t priority;
	struct in6_addr target;
	uint32_t valid;
	uint32_t preferred;
};


int init_dhcpv6(const char *ifname, int request_pd);
void dhcpv6_set_ia_na_mode(enum odhcp6c_ia_mode mode);
int dhcpv6_request(enum dhcpv6_msg type);
int dhcpv6_poll_reconfigure(void);

int init_rtnetlink(void);
int set_rtnetlink_addr(int ifindex, const struct in6_addr *addr,
		uint32_t pref, uint32_t valid);

int script_init(const char *path, const char *ifname);
ssize_t script_unhexlify(uint8_t *dst, size_t len, const char *src);
void script_call(const char *status);

bool odhcp6c_signal_process(void);
uint64_t odhcp6c_get_milli_time(void);
void odhcp6c_random(void *buf, size_t len);

// State manipulation
void odhcp6c_clear_state(enum odhcp6c_state state);
void odhcp6c_add_state(enum odhcp6c_state state, const void *data, size_t len);
size_t odhcp6c_remove_state(enum odhcp6c_state state, size_t offset, size_t len);
void* odhcp6c_get_state(enum odhcp6c_state state, size_t *len);

// Entry manipulation
struct odhcp6c_entry* odhcp6c_find_entry(enum odhcp6c_state state, const struct odhcp6c_entry *new);
void odhcp6c_update_entry(enum odhcp6c_state state, struct odhcp6c_entry *new);
void odhcp6c_update_entry_safe(enum odhcp6c_state state, struct odhcp6c_entry *new, uint32_t safe);

void odhcp6c_expire(void);
