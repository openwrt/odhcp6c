/**
 * Copyright (C) 2012-2014 Steven Barth <steven@midlink.org>
 * Copyright (C) 2017-2018 Hans Dedecker <dedeckeh@gmail.com>
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

/*
 * Unprivileged worker / presentation side of the status-script machinery. This
 * is the network-facing code: it turns the parsed (attacker-influenced) DHCPv6
 * and RA client state into "NAME=value" environment strings. In the single
 * process model it forks the script itself (via the shared script_spawn());
 * under privilege separation it instead serializes the environment and ships it
 * to the root monitor, which re-validates everything before exec. Nothing here
 * runs as root in privsep mode and nothing here is part of the trusted compute
 * base.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "odhcp6c.h"
#include "script.h"
#include "script_internal.h"

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

/*
 * Worker-side IPC channel. When >= 0, script_call() serializes the request and
 * sends it to the monitor instead of forking and exec'ing the script itself.
 */
static int script_channel = -1;

/*
 * Environment collector. The *_to_env() helpers build fully-formed
 * "NAME=value" strings and always hand them to script_env_collect(); none of
 * them call putenv() or sanitize directly. A single explicit emit step (see
 * script_call_child / script_send_request) then consumes the collected list,
 * sanitizes every entry exactly once, and chooses the sink: putenv() into the
 * forked script child (single process) or serialization to the monitor
 * (privsep). Making the data flow visible at one site -- rather than hidden
 * behind a mode flag read deep inside the collector -- is the point of this
 * design.
 */
struct env_collector {
	char  **list;
	size_t  cnt, cap;
};

static struct env_collector env = {
	.list = NULL,
	.cnt = 0,
	.cap = 0,
};

void script_set_channel(int fd)
{
	script_channel = fd;
}

/*
 * Take ownership of a heap-allocated "NAME=value" string and append it to the
 * collector. Builders always route here; the sink (putenv vs. wire) and the
 * mandatory sanitization are decided later by the single emit step, not here.
 * No caps are applied at collection time: the single-process emit path is
 * uncapped (as it has always been), while the privsep path enforces the
 * monitor's hard caps when it serializes (see script_env_apply_caps()).
 */
static void script_env_collect(char *buf)
{
	if (!buf)
		return;

	if (env.cnt == env.cap) {
		size_t ncap = env.cap ? env.cap * 2 : 32;
		char **n = realloc(env.list, ncap * sizeof(*env.list));

		if (!n) {
			free(buf);
			return;
		}

		env.list = n;
		env.cap = ncap;
	}

	env.list[env.cnt++] = buf;
}

static void script_env_collect_reset(void)
{
	for (size_t i = 0; i < env.cnt; i++)
		free(env.list[i]);

	env.cnt = 0;
}

/*
 * The single, centralized sanitization step (Item 5). Every collected entry --
 * regardless of which builder produced it or whether its charset was thought
 * "safe" -- passes through script_sanitize_env() exactly once here. The value
 * is sanitized in place; an entry whose NAME is invalid is rejected (freed and
 * dropped from the list), which never aborts the process. Because
 * script_sanitize_env() is idempotent on already-safe input, known-safe entries
 * are emitted unchanged. The monitor independently re-sanitizes on the
 * privileged side; that defense-in-depth gate is intentional and kept.
 */
static void script_env_sanitize(void)
{
	size_t out = 0;

	for (size_t i = 0; i < env.cnt; i++) {
		char *buf = env.list[i];

		if (script_sanitize_env(buf))
			env.list[out++] = buf;
		else
			free(buf);
	}

	env.cnt = out;
}

/*
 * Single-process sink: export every (already sanitized) collected entry into
 * the forked script child's environment, then forget them. putenv() does not
 * copy, so ownership of each string transfers to environ and the strings must
 * not be freed here; only the pointer array is released. This path is uncapped,
 * exactly as the historical direct-putenv() path was -- the monitor's hard caps
 * apply solely to what crosses the privsep wire.
 */
static void script_env_emit_putenv(void)
{
	for (size_t i = 0; i < env.cnt; i++)
		putenv(env.list[i]);

	free(env.list);
	env.list = NULL;
	env.cnt = 0;
	env.cap = 0;
}

/*
 * Privsep sink helper: drop (in place) any collected entry that would push the
 * serialized request past the monitor's hard caps, so env.list holds exactly
 * what script_send_request() will put on the wire. The per-entry skip with
 * running totals matches the historical collect-time enforcement: an oversized
 * entry is dropped individually while smaller later entries still fit.
 */
static void script_env_apply_caps(void)
{
	size_t out = 0;
	size_t total = 0;

	for (size_t i = 0; i < env.cnt; i++) {
		char *buf = env.list[i];
		size_t len = strlen(buf) + 1;

		if (len > SCRIPT_ENV_ENTRY_MAX ||
				out >= SCRIPT_ENV_MAX_COUNT ||
				total + len > SCRIPT_ENV_MAX_TOTAL) {
			free(buf);
			continue;
		}

		total += len;
		env.list[out++] = buf;
	}

	env.cnt = out;
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

void script_hexlify(char *dst, const uint8_t *src, size_t len)
{
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
	char *buf = malloc(cnt * INET6_ADDRSTRLEN + buf_len + 2);

	if (!buf)
		return;

	memcpy(buf, name, buf_len);
	buf[buf_len++] = '=';

	for (size_t i = 0; i < cnt; ++i) {
		inet_ntop(AF_INET6, &addr[i], &buf[buf_len], INET6_ADDRSTRLEN);
		buf_len += strlen(&buf[buf_len]);
		buf[buf_len++] = ' ';
	}

	if (buf[buf_len - 1] == ' ')
		buf_len--;

	buf[buf_len] = '\0';
	script_env_collect(buf);
}

static void fqdn_to_env(const char *name, const uint8_t *fqdn, size_t len)
{
	size_t buf_len = strlen(name);
	size_t buf_size = len + buf_len + 2;
	const uint8_t *fqdn_end = fqdn + len;
	char *buf = malloc(buf_size);

	if (!buf)
		return;

	memcpy(buf, name, buf_len);
	buf[buf_len++] = '=';

	while (fqdn < fqdn_end) {
		int l = dn_expand(fqdn, fqdn_end, fqdn, &buf[buf_len], buf_size - buf_len);
		if (l <= 0)
			break;
		fqdn += l;
		buf_len += strlen(&buf[buf_len]);
		buf[buf_len++] = ' ';
	}

	if (buf[buf_len - 1] == ' ')
		buf_len--;

	buf[buf_len] = '\0';
	script_env_collect(buf);
}

static void string_to_env(const char *name, const uint8_t *string, size_t len)
{
	size_t name_len = strlen(name);
	char *buf = malloc(name_len + 1 + len + 1);

	if (!buf)
		return;

	memcpy(buf, name, name_len);
	buf[name_len] = '=';
	memcpy(&buf[name_len + 1], string, len);
	buf[name_len + 1 + len] = '\0';
	script_env_collect(buf);
}

static void bin_to_env(uint8_t *opts, size_t len)
{
	uint8_t *oend = opts + len, *odata;
	uint16_t otype, olen;

	dhcpv6_for_each_option(opts, oend, otype, olen, odata) {
		char *buf = malloc(14 + (olen * 2));
		size_t buf_len = 0;

		if (!buf)
			continue;

		snprintf(buf, 14, "OPTION_%hu=", otype);
		buf_len += strlen(buf);

		script_hexlify(&buf[buf_len], odata, olen);
		script_env_collect(buf);
	}
}

enum entry_type {
	ENTRY_ADDRESS,
	ENTRY_HOST,
	ENTRY_ROUTE,
	ENTRY_PREFIX
};

static void entry_to_env(const char *name, const void *data, size_t len, enum entry_type type)
{
	const uint8_t *start = data;
	char addr[INET6_ADDRSTRLEN];
	char *str = NULL;
	size_t strsize = 0;

	FILE *fp = open_memstream(&str, &strsize);
	if (!fp)
		return;

	fputs(name, fp);
	fputc('=', fp);

	for (const struct odhcp6c_entry *e = (const struct odhcp6c_entry *)start;
			(const uint8_t *)e < start + len &&
			(const uint8_t *)odhcp6c_next_entry(e) <= start + len;
			e = odhcp6c_next_entry(e)) {
		/*
		 * The only invalid entries allowed to be passed to the script are prefix and RA
		 * entries. This will allow immediate removal of the old ipv6-prefix-assignment
		 * that might otherwise be kept for up to 2 hours (see L-13 requirement of RFC 7084).
		 * Similarly, a RA with router lifetime set to 0 indicates that the advertising
		 * router "is not a default router and SHOULD NOT appear on the default router list"
		 * (see RFC 4861, section 4.2).
		 */
		if (!e->valid && type != ENTRY_PREFIX && type != ENTRY_ROUTE)
			continue;

		inet_ntop(AF_INET6, &e->target, addr, sizeof(addr));
		fputs(addr, fp);

		if (type != ENTRY_HOST) {
			fprintf(fp, "/%"PRIu16, e->length);

			if (type == ENTRY_ROUTE) {
				fputc(',', fp);

				if (!IN6_IS_ADDR_UNSPECIFIED(&e->router)) {
					inet_ntop(AF_INET6, &e->router, addr, sizeof(addr));
					fputs(addr, fp);
				}

				fprintf(fp, ",%u,%u", e->valid, e->priority);
			} else {
				fprintf(fp, ",%u,%u,%u,%u", e->preferred, e->valid, e->t1, e->t2);
			}

			if (type == ENTRY_PREFIX && ntohl(e->iaid) != 1)
				fprintf(fp, ",class=%08x", ntohl(e->iaid));

			if (type == ENTRY_PREFIX && e->exclusion_length) {
				fputs(",excluded=", fp);
				/* .router is dual-used: for prefixes it contains the excluded prefix */
				inet_ntop(AF_INET6, &e->router, addr, sizeof(addr));
				fprintf(fp, "%s/%u", addr, e->exclusion_length);
			}
		}

		fputc(' ', fp);
	}

	if (fclose(fp)) {
		free(str);
		return;
	}

	if (strsize > 0 && str[strsize - 1] == ' ')
		str[strsize - 1] = '\0';

	script_env_collect(str);
}

static void search_to_env(const char *name, const uint8_t *start, size_t len)
{
	size_t buf_len = strlen(name);
	char *buf = malloc(buf_len + 2 + len);
	char *c;

	if (!buf)
		return;

	c = mempcpy(buf, name, buf_len);
	*c++ = '=';

	for (struct odhcp6c_entry *e = (struct odhcp6c_entry*)start;
				(uint8_t*)e < &start[len] &&
				(uint8_t*)odhcp6c_next_entry(e) <= &start[len];
				e = odhcp6c_next_entry(e)) {
		if (!e->valid)
			continue;
		c = mempcpy(c, e->auxtarget, e->auxlen);
		*c++ = ' ';
	}

	if (c[-1] == ' ')
		c--;

	*c = '\0';
	script_env_collect(buf);
}

static void int_to_env(const char *name, int value)
{
	size_t len = 13 + strlen(name);
	char *buf = malloc(len);

	if (!buf)
		return;

	snprintf(buf, len, "%s=%d", name, value);
	script_env_collect(buf);
}

static void s46_to_env_portparams(const uint8_t *data, size_t len, FILE *fp)
{
	uint8_t *odata;
	uint16_t otype, olen;

	dhcpv6_for_each_option(data, &data[len], otype, olen, odata) {
		if (otype == DHCPV6_OPT_S46_PORTPARAMS &&
				olen == sizeof(struct dhcpv6_s46_portparams)) {
			struct dhcpv6_s46_portparams *params = (void*)odata;
			fprintf(fp, "offset=%d,psidlen=%d,psid=%d,",
					params->offset, params->psid_len, ntohs(params->psid));
		}
	}
}

static void s46_to_env(enum odhcp6c_state state, const uint8_t *data, size_t len)
{
	const char *name = (state == STATE_S46_MAPE) ? "MAPE" :
			(state == STATE_S46_MAPT) ? "MAPT" : "LW4O6";

	if (len == 0)
		return;

	char *str;
	size_t strsize;

	FILE *fp = open_memstream(&str, &strsize);
	fputs(name, fp);
	fputc('=', fp);

	const char *type = (state == STATE_S46_MAPE) ? "map-e" :
			(state == STATE_S46_MAPT) ? "map-t" : "lw4o6";

	uint8_t *odata;
	uint16_t otype, olen;

	dhcpv6_for_each_option(data, &data[len], otype, olen, odata) {
		struct dhcpv6_s46_rule *rule = (struct dhcpv6_s46_rule*)odata;
		struct dhcpv6_s46_v4v6bind *bind = (struct dhcpv6_s46_v4v6bind*)odata;

		if (state != STATE_S46_LW && otype == DHCPV6_OPT_S46_RULE &&
				olen >= sizeof(struct dhcpv6_s46_rule)) {
			char buf4[INET_ADDRSTRLEN];
			char buf6[INET6_ADDRSTRLEN];
			struct in6_addr in6 = IN6ADDR_ANY_INIT;

			size_t prefix6len = rule->prefix6_len;
			prefix6len = (prefix6len % 8 == 0) ? prefix6len / 8 : prefix6len / 8 + 1;

			if (prefix6len > sizeof(in6) ||
			    olen < sizeof(struct dhcpv6_s46_rule) + prefix6len)
				continue;

			memcpy(&in6, rule->ipv6_prefix, prefix6len);

			inet_ntop(AF_INET, &rule->ipv4_prefix, buf4, sizeof(buf4));
			inet_ntop(AF_INET6, &in6, buf6, sizeof(buf6));

			if (rule->flags & 1)
				fputs("fmr,", fp);

			fprintf(fp, "type=%s,ealen=%d,prefix4len=%d,prefix6len=%d,ipv4prefix=%s,ipv6prefix=%s,",
					type, rule->ea_len, rule->prefix4_len, rule->prefix6_len, buf4, buf6);

			s46_to_env_portparams(&rule->ipv6_prefix[prefix6len],
					olen - sizeof(*rule) - prefix6len, fp);

			dhcpv6_for_each_option(data, &data[len], otype, olen, odata) {
				if (state != STATE_S46_MAPT && otype == DHCPV6_OPT_S46_BR &&
						olen == sizeof(struct in6_addr)) {
					inet_ntop(AF_INET6, odata, buf6, sizeof(buf6));
					fprintf(fp, "br=%s,", buf6);
				} else if (state == STATE_S46_MAPT && otype == DHCPV6_OPT_S46_DMR &&
						olen >= sizeof(struct dhcpv6_s46_dmr)) {
					struct dhcpv6_s46_dmr *dmr = (struct dhcpv6_s46_dmr*)odata;
					memset(&in6, 0, sizeof(in6));
					size_t prefix6len = dmr->dmr_prefix6_len;
					prefix6len = (prefix6len % 8 == 0) ? prefix6len / 8 : prefix6len / 8 + 1;

					if (prefix6len > sizeof(in6) ||
					    olen < sizeof(struct dhcpv6_s46_dmr) + prefix6len)
						continue;

					memcpy(&in6, dmr->dmr_ipv6_prefix, prefix6len);
					inet_ntop(AF_INET6, &in6, buf6, sizeof(buf6));
					fprintf(fp, "dmr=%s/%d,", buf6, dmr->dmr_prefix6_len);
				}
			}

			fputc(' ', fp);
		} else if (state == STATE_S46_LW && otype == DHCPV6_OPT_S46_V4V6BIND &&
				olen >= sizeof(struct dhcpv6_s46_v4v6bind)) {
			char buf4[INET_ADDRSTRLEN];
			char buf6[INET6_ADDRSTRLEN];
			struct in6_addr in6 = IN6ADDR_ANY_INIT;

			size_t prefix6len = bind->bindprefix6_len;
			prefix6len = (prefix6len % 8 == 0) ? prefix6len / 8 : prefix6len / 8 + 1;

			if (prefix6len > sizeof(in6) ||
			    olen < sizeof(struct dhcpv6_s46_v4v6bind) + prefix6len)
				continue;

			memcpy(&in6, bind->bind_ipv6_prefix, prefix6len);

			inet_ntop(AF_INET, &bind->ipv4_address, buf4, sizeof(buf4));
			inet_ntop(AF_INET6, &in6, buf6, sizeof(buf6));

			fprintf(fp, "type=%s,prefix4len=32,prefix6len=%d,ipv4prefix=%s,ipv6prefix=%s,",
					type, bind->bindprefix6_len, buf4, buf6);

			s46_to_env_portparams(&bind->bind_ipv6_prefix[prefix6len],
					olen - sizeof(*bind) - prefix6len, fp);

			dhcpv6_for_each_option(data, &data[len], otype, olen, odata) {
				if (otype == DHCPV6_OPT_S46_BR && olen == sizeof(struct in6_addr)) {
					inet_ntop(AF_INET6, odata, buf6, sizeof(buf6));
					fprintf(fp, "br=%s,", buf6);
				}
			}

			fputc(' ', fp);
		}
	}

	fclose(fp);
	script_env_collect(str);
}

/*
 * Build the full set of "NAME=value" environment strings from the current
 * client state into the collector. Builders never putenv() or sanitize: a
 * single emit step (script_call_child for the forked child, or
 * script_send_request for privsep) consumes the collector, sanitizes every
 * entry once, and dispatches it to the chosen sink.
 */
static void script_build_env(void)
{
	size_t dns_len, search_len, custom_len, sntp_ip_len, ntp_ip_len, ntp_dns_len;
	size_t sip_ip_len, sip_fqdn_len, aftr_name_len, addr_len;
	size_t s46_mapt_len, s46_mape_len, s46_lw_len, passthru_len;
	size_t capt_port_ra_len, capt_port_dhcpv6_len;

	struct in6_addr *addr = odhcp6c_get_state(STATE_SERVER_ADDR, &addr_len);
	struct in6_addr *dns = odhcp6c_get_state(STATE_DNS, &dns_len);
	uint8_t *search = odhcp6c_get_state(STATE_SEARCH, &search_len);
	uint8_t *custom = odhcp6c_get_state(STATE_CUSTOM_OPTS, &custom_len);
	struct in6_addr *sntp = odhcp6c_get_state(STATE_SNTP_IP, &sntp_ip_len);
	struct in6_addr *ntp = odhcp6c_get_state(STATE_NTP_IP, &ntp_ip_len);
	uint8_t *ntp_dns = odhcp6c_get_state(STATE_NTP_FQDN, &ntp_dns_len);
	struct in6_addr *sip = odhcp6c_get_state(STATE_SIP_IP, &sip_ip_len);
	uint8_t *sip_fqdn = odhcp6c_get_state(STATE_SIP_FQDN, &sip_fqdn_len);
	uint8_t *aftr_name = odhcp6c_get_state(STATE_AFTR_NAME, &aftr_name_len);
	uint8_t *s46_mapt = odhcp6c_get_state(STATE_S46_MAPT, &s46_mapt_len);
	uint8_t *s46_mape = odhcp6c_get_state(STATE_S46_MAPE, &s46_mape_len);
	uint8_t *s46_lw = odhcp6c_get_state(STATE_S46_LW, &s46_lw_len);
	uint8_t *capt_port_ra = odhcp6c_get_state(STATE_CAPT_PORT_RA, &capt_port_ra_len);
	uint8_t *capt_port_dhcpv6 = odhcp6c_get_state(STATE_CAPT_PORT_DHCPV6, &capt_port_dhcpv6_len);
	uint8_t *passthru = odhcp6c_get_state(STATE_PASSTHRU, &passthru_len);

	size_t prefix_len, address_len, ra_pref_len,
		ra_route_len, ra_dns_len, ra_search_len;
	uint8_t *prefix = odhcp6c_get_state(STATE_IA_PD, &prefix_len);
	uint8_t *address = odhcp6c_get_state(STATE_IA_NA, &address_len);
	uint8_t *ra_pref = odhcp6c_get_state(STATE_RA_PREFIX, &ra_pref_len);
	uint8_t *ra_route = odhcp6c_get_state(STATE_RA_ROUTE, &ra_route_len);
	uint8_t *ra_dns = odhcp6c_get_state(STATE_RA_DNS, &ra_dns_len);
	uint8_t *ra_search = odhcp6c_get_state(STATE_RA_SEARCH, &ra_search_len);

	/* RFC8910 §3 */
	if (capt_port_ra_len > 0 && capt_port_dhcpv6_len > 0) {
		if (capt_port_ra_len != capt_port_dhcpv6_len ||
			memcmp(capt_port_dhcpv6, capt_port_ra, capt_port_dhcpv6_len))
			error(
				"%s received via different vectors differ: preferring URI from DHCPv6",
				CAPT_PORT_URI_STR);
	}

	ipv6_to_env("SERVER", addr, addr_len / sizeof(*addr));
	ipv6_to_env("RDNSS", dns, dns_len / sizeof(*dns));
	ipv6_to_env("SNTP_IP", sntp, sntp_ip_len / sizeof(*sntp));
	ipv6_to_env("NTP_IP", ntp, ntp_ip_len / sizeof(*ntp));
	fqdn_to_env("NTP_FQDN", ntp_dns, ntp_dns_len);
	ipv6_to_env("SIP_IP", sip, sip_ip_len / sizeof(*sip));
	fqdn_to_env("DOMAINS", search, search_len);
	fqdn_to_env("SIP_DOMAIN", sip_fqdn, sip_fqdn_len);
	fqdn_to_env("AFTR", aftr_name, aftr_name_len);
	s46_to_env(STATE_S46_MAPE, s46_mape, s46_mape_len);
	s46_to_env(STATE_S46_MAPT, s46_mapt, s46_mapt_len);
	s46_to_env(STATE_S46_LW, s46_lw, s46_lw_len);
	if (capt_port_dhcpv6_len > 0)
		string_to_env(CAPT_PORT_URI_STR, capt_port_dhcpv6, capt_port_dhcpv6_len);
	else if (capt_port_ra_len > 0)
		string_to_env(CAPT_PORT_URI_STR, capt_port_ra, capt_port_ra_len);
	bin_to_env(custom, custom_len);

	if (odhcp6c_is_bound()) {
		entry_to_env("PREFIXES", prefix, prefix_len, ENTRY_PREFIX);
		entry_to_env("ADDRESSES", address, address_len, ENTRY_ADDRESS);
	}

	entry_to_env("RA_ADDRESSES", ra_pref, ra_pref_len, ENTRY_ADDRESS);
	entry_to_env("RA_ROUTES", ra_route, ra_route_len, ENTRY_ROUTE);
	entry_to_env("RA_DNS", ra_dns, ra_dns_len, ENTRY_HOST);
	search_to_env("RA_DOMAINS", ra_search, ra_search_len);

	int_to_env("RA_HOPLIMIT", ra_get_hoplimit());
	int_to_env("RA_MTU", ra_get_mtu());
	int_to_env("RA_REACHABLE", ra_get_reachable());
	int_to_env("RA_RETRANSMIT", ra_get_retransmit());

	char *buf = malloc(10 + passthru_len * 2);
	if (buf) {
		strncpy(buf, "PASSTHRU=", 10);
		script_hexlify(&buf[9], passthru, passthru_len);
		script_env_collect(buf);
	}
}

/*
 * Worker side of privilege separation: serialize the collected environment plus
 * the requested action/delay/resume into a single SOCK_SEQPACKET datagram and
 * send it to the monitor. The monitor re-validates everything before exec, so
 * this side only needs to produce a well-formed, bounded message.
 */
static void script_send_request(const char *status, int delay, bool resume)
{
	script_env_collect_reset();

	/*
	 * Build the environment from the current DHCPv6 state now, before the
	 * monitor applies any delay. Unlike the non-privsep path, a delayed run
	 * does not re-run odhcp6c_expire() after the delay, so lifetime fields
	 * (preferred/valid/t1/t2 in PREFIXES/ADDRESSES/RA_*) may read up to
	 * 'delay' seconds (at most SCRIPT_DELAY_MAX) stale. This is intentional:
	 * re-applying expiry here would require either parsing env semantics in
	 * the trusted monitor or mutating authoritative worker state before the
	 * delay actually elapsed. The skew is small and bounded, and the next
	 * state notification corrects it.
	 */
	script_build_env();

	/*
	 * Single emit step: sanitize every entry once, then drop anything that
	 * would exceed the monitor's hard caps. env.list now holds exactly the
	 * entries that will be serialized.
	 */
	script_env_sanitize();
	script_env_apply_caps();

	size_t action_len = strlen(status);
	if (action_len > SCRIPT_ACTION_MAX)
		action_len = SCRIPT_ACTION_MAX;

	size_t env_total = 0;
	size_t env_count = env.cnt;
	for (size_t i = 0; i < env_count; i++)
		env_total += strlen(env.list[i]) + 1;

	struct script_req req = {
		.magic = SCRIPT_REQ_MAGIC,
		.action_len = action_len,
		.delay = delay,
		.resume = resume ? 1 : 0,
		.env_count = env_count,
		.env_total = env_total,
	};

	size_t msg_len = sizeof(req) + action_len + env_total;
	uint8_t *msg = malloc(msg_len);
	if (msg) {
		uint8_t *p = msg;

		memcpy(p, &req, sizeof(req));
		p += sizeof(req);
		memcpy(p, status, action_len);
		p += action_len;

		for (size_t i = 0; i < env_count; i++) {
			size_t l = strlen(env.list[i]) + 1;

			memcpy(p, env.list[i], l);
			p += l;
		}

		if (send(script_channel, msg, msg_len, MSG_NOSIGNAL | MSG_EOR) < 0)
			error("Failed to send script request to monitor: %s",
					strerror(errno));

		free(msg);
	} else {
		error("Failed to allocate %zu bytes for script request", msg_len);
	}

	script_env_collect_reset();
}

/*
 * Worker-side in-child env step: if a delay was actually waited out, expire
 * stale client state first, then build the environment from live client state.
 * odhcp6c_expire() must run only here (the worker), never in the monitor. The
 * collected entries are sanitized once and exported via putenv() before execv.
 */
static void script_call_child(int delay, void *ctx)
{
	(void)ctx;

	if (delay > 0)
		odhcp6c_expire(false);

	script_build_env();
	script_env_sanitize();
	script_env_emit_putenv();
}

void script_call(const char *status, int delay, bool resume)
{
	if (!script_child.argv[0])
		return;

	if (script_channel >= 0) {
		script_send_request(status, delay, resume);
		return;
	}

	script_spawn(status, delay, resume, script_call_child, NULL);
}
