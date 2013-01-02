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

#include <stdio.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "odhcp6c.h"

static const char hexdigits[] = "0123456789abcdef";
static const int8_t hexvals[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -1, -1, -2, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};



static char *argv[4] = {NULL, NULL, NULL, NULL};


int script_init(const char *path, const char *ifname)
{
	argv[0] = (char*)path;
	argv[1] = (char*)ifname;
	return 0;
}


ssize_t script_unhexlify(uint8_t *dst, size_t len, const char *src)
{
	size_t c;
	for (c = 0; c < len && src[0] && src[1]; ++c) {
		int8_t x = (int8_t)*src++;
		int8_t y = (int8_t)*src++;
		if (x < 0 || (x = hexvals[x]) < 0
				|| y < 0 || (y = hexvals[y]) < 0)
			return -1;
		dst[c] = x << 4 | y;
		while (((int8_t)*src) < 0 ||
				(*src && hexvals[(uint8_t)*src] < 0))
			src++;
	}

	return c;
}


void script_hexlify(char *dst, const uint8_t *src, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		*dst++ = hexdigits[src[i] >> 4];
		*dst++ = hexdigits[src[i] & 0x0f];
	}
	*dst = 0;
}


static void ipv6_to_env(const char *name,
		const struct in6_addr *addr, size_t cnt)
{
	size_t buf_len = strlen(name);
	char *buf = realloc(NULL, cnt * INET6_ADDRSTRLEN + buf_len + 2);
	memcpy(buf, name, buf_len);
	buf[buf_len++] = '=';
	for (size_t i = 0; i < cnt; ++i) {
		inet_ntop(AF_INET6, &addr[i], &buf[buf_len], INET6_ADDRSTRLEN);
		buf_len += strlen(&buf[buf_len]);
		buf[buf_len++] = ' ';
	}
	buf[buf_len - 1] = '\0';
	putenv(buf);
}


static void fqdn_to_env(const char *name, const uint8_t *fqdn, size_t len)
{
	size_t buf_len = strlen(name);
	const uint8_t *fqdn_end = fqdn + len;
	char *buf = realloc(NULL, len + buf_len + 2);
	memcpy(buf, name, buf_len);
	buf[buf_len++] = '=';
	int l = 1;
	while (l > 0 && fqdn < fqdn_end) {
		l = dn_expand(fqdn, &fqdn[len], fqdn, &buf[buf_len], len);
		fqdn += l;
		buf_len += strlen(&buf[buf_len]);
		buf[buf_len++] = ' ';
	}
	buf[buf_len - 1] = '\0';
	putenv(buf);
}


static void bin_to_env(uint8_t *opts, size_t len)
{
	uint8_t *oend = opts + len, *odata;
	uint16_t otype, olen;
	dhcpv6_for_each_option(opts, oend, otype, olen, odata) {
		char *buf = realloc(NULL, 14 + (olen * 2));
		size_t buf_len = 0;

		snprintf(buf, 14, "OPTION_%hu=", otype);
		buf_len += strlen(buf);

		script_hexlify(&buf[buf_len], odata, olen);
		putenv(buf);
	}
}


static void prefix_to_env(const char *name, const uint8_t *fqdn, size_t len)
{
	size_t buf_len = strlen(name);
	struct dhcpv6_ia_prefix *p = NULL;
	char *buf = realloc(NULL, buf_len + 2 +
			(len / sizeof(*p)) * (INET6_ADDRSTRLEN + 32));
	memcpy(buf, name, buf_len);
	buf[buf_len++] = '=';

	uint16_t otype, olen;
	uint8_t *odata;
	dhcpv6_for_each_option(fqdn, &fqdn[len], otype, olen, odata) {
		if (otype != DHCPV6_OPT_IA_PREFIX || olen + 4U < sizeof(*p))
			continue;

		p = (struct dhcpv6_ia_prefix*)&odata[-4];
		inet_ntop(AF_INET6, &p->addr, &buf[buf_len], INET6_ADDRSTRLEN);
		buf_len += strlen(&buf[buf_len]);
		buf_len += snprintf(&buf[buf_len], 32, "/%hhu,%u,%u ",
				p->prefix, ntohl(p->preferred),
				ntohl(p->valid));
	}
	buf[buf_len - 1] = '\0';
	putenv(buf);
}


void script_call(const char *status)
{
	syslog(LOG_WARNING, "State for %s changed to %s", argv[1], status);
	size_t dns_len, search_len, custom_len, sntp_ip_len, sntp_dns_len;
	size_t sip_ip_len, sip_fqdn_len;

	struct in6_addr *dns = odhcp6c_get_state(STATE_DNS, &dns_len);
	uint8_t *search = odhcp6c_get_state(STATE_SEARCH, &search_len);
	uint8_t *custom = odhcp6c_get_state(STATE_CUSTOM_OPTS, &custom_len);
	struct in6_addr *sntp = odhcp6c_get_state(STATE_SNTP_IP, &sntp_ip_len);
	uint8_t *sntp_dns = odhcp6c_get_state(STATE_SNTP_FQDN, &sntp_dns_len);
	struct in6_addr *sip = odhcp6c_get_state(STATE_SIP_IP, &sip_ip_len);
	uint8_t *sip_fqdn = odhcp6c_get_state(STATE_SIP_FQDN, &sip_fqdn_len);

	size_t prefix_len, lost_pd_len;
	uint8_t *prefix = odhcp6c_get_state(STATE_IA_PD, &prefix_len);
	uint8_t *lost_pd = odhcp6c_get_state(STATE_IA_PD_LOST, &lost_pd_len);

	// Don't set environment before forking, because env is leaky.
	if (fork() == 0) {
		ipv6_to_env("RDNSS", dns, dns_len / sizeof(*dns));
		ipv6_to_env("SNTP_IP", sntp, sntp_ip_len / sizeof(*sntp));
		ipv6_to_env("SIP_IP", sip, sip_ip_len / sizeof(*sip));
		fqdn_to_env("DOMAINS", search, search_len);
		fqdn_to_env("SNTP_FQDN", sntp_dns, sntp_dns_len);
		fqdn_to_env("SIP_DOMAIN", sip_fqdn, sip_fqdn_len);
		bin_to_env(custom, custom_len);
		prefix_to_env("PREFIXES", prefix, prefix_len);
		prefix_to_env("PREFIXES_LOST", lost_pd, lost_pd_len);

		argv[2] = (char*)status;
		execv(argv[0], argv);
		_exit(128);
	}

	// Delete lost prefixes and user opts
	odhcp6c_clear_state(STATE_IA_PD_LOST);
	odhcp6c_clear_state(STATE_CUSTOM_OPTS);
}
