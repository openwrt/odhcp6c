/****************************************************************************
**
** SPDX-License-Identifier: BSD-2-Clause-Patent
**
** SPDX-FileCopyrightText: Copyright (c) 2024 SoftAtHome
**
** Redistribution and use in source and binary forms, with or
** without modification, are permitted provided that the following
** conditions are met:
**
** 1. Redistributions of source code must retain the above copyright
** notice, this list of conditions and the following disclaimer.
**
** 2. Redistributions in binary form must reproduce the above
** copyright notice, this list of conditions and the following
** disclaimer in the documentation and/or other materials provided
** with the distribution.
**
** Subject to the terms and conditions of this license, each
** copyright holder and contributor hereby grants to those receiving
** rights under this license a perpetual, worldwide, non-exclusive,
** no-charge, royalty-free, irrevocable (except for failure to
** satisfy the conditions of this license) patent license to make,
** have made, use, offer to sell, sell, import, and otherwise
** transfer this software, where such license applies only to those
** patent claims, already acquired or hereafter acquired, licensable
** by such copyright holder or contributor that are necessarily
** infringed by:
**
** (a) their Contribution(s) (the licensed copyrights of copyright
** holders and non-copyrightable additions of contributors, in
** source or binary form) alone; or
**
** (b) combination of their Contribution(s) with the work of
** authorship to which such Contribution(s) was added by such
** copyright holder or contributor, if, at the time the Contribution
** is added, such addition causes such combination to be necessarily
** infringed. The patent license shall not apply to any other
** combinations which include the Contribution.
**
** Except as expressly stated above, no rights or licenses from any
** copyright holder or contributor is granted under this license,
** whether expressly, by implication, estoppel or otherwise.
**
** DISCLAIMER
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
** CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
** INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
** MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
** CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
** USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
** AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
** ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
** POSSIBILITY OF SUCH DAMAGE.
**
****************************************************************************/
#include "odhcp6c.h"

#include <string.h>
#include <resolv.h>
#include <limits.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <syslog.h>

#include "config.h"

#define ARRAY_SEP " ,\t"

static struct config_dhcp config_dhcp;

struct config_dhcp *config_dhcp_get(void) {
	return &config_dhcp;
}

void config_dhcp_reset(void) {
	config_dhcp.release = true;
	config_dhcp.dscp = 0;
	config_dhcp.sk_prio = 0;
	config_dhcp.stateful_only_mode = false;
	config_dhcp.ia_na_mode = IA_MODE_TRY;
	config_dhcp.ia_pd_mode = IA_MODE_NONE;
	config_dhcp.client_options = DHCPV6_CLIENT_FQDN | DHCPV6_ACCEPT_RECONFIGURE;
	config_dhcp.allow_slaac_only = -1;
	config_dhcp.oro_user_cnt = 0;
	memset(config_dhcp.message_rtx, 0, sizeof(config_dhcp.message_rtx));
	config_dhcp.message_rtx[CONFIG_DHCP_SOLICIT].delay_max = DHCPV6_MAX_DELAY;
	config_dhcp.message_rtx[CONFIG_DHCP_SOLICIT].timeout_init = DHCPV6_SOL_INIT_RT;
	config_dhcp.message_rtx[CONFIG_DHCP_SOLICIT].timeout_max = DHCPV6_SOL_MAX_RT;
	config_dhcp.message_rtx[CONFIG_DHCP_REQUEST].timeout_init = DHCPV6_REQ_INIT_RT;
	config_dhcp.message_rtx[CONFIG_DHCP_REQUEST].timeout_max = DHCPV6_REQ_MAX_RT;
	config_dhcp.message_rtx[CONFIG_DHCP_REQUEST].rc_max = DHCPV6_REQ_MAX_RC;
	config_dhcp.message_rtx[CONFIG_DHCP_RENEW].timeout_init = DHCPV6_REN_INIT_RT;
	config_dhcp.message_rtx[CONFIG_DHCP_RENEW].timeout_max = DHCPV6_REN_MAX_RT;
	config_dhcp.message_rtx[CONFIG_DHCP_REBIND].timeout_init = DHCPV6_REB_INIT_RT;
	config_dhcp.message_rtx[CONFIG_DHCP_REBIND].timeout_max = DHCPV6_REB_MAX_RT;
	config_dhcp.message_rtx[CONFIG_DHCP_INFO_REQ].delay_max = DHCPV6_MAX_DELAY;
	config_dhcp.message_rtx[CONFIG_DHCP_INFO_REQ].timeout_init = DHCPV6_INF_INIT_RT;
	config_dhcp.message_rtx[CONFIG_DHCP_INFO_REQ].timeout_max = DHCPV6_INF_MAX_RT;
	config_dhcp.message_rtx[CONFIG_DHCP_RELEASE].timeout_init = DHCPV6_REL_INIT_RT;
	config_dhcp.message_rtx[CONFIG_DHCP_RELEASE].rc_max = DHCPV6_REL_MAX_RC;
	config_dhcp.message_rtx[CONFIG_DHCP_DECLINE].timeout_init = DHCPV6_DEC_INIT_RT;
	config_dhcp.message_rtx[CONFIG_DHCP_DECLINE].rc_max = DHCPV6_DEC_MAX_RC;
	config_dhcp.irt_default = DHCPV6_IRT_DEFAULT;
	config_dhcp.irt_min = DHCPV6_IRT_MIN;
	config_dhcp.rand_factor = DHCPV6_RAND_FACTOR;
}

void config_set_release(bool enable) {
	config_dhcp.release = enable;
}

bool config_set_dscp(unsigned int value) {
	if(value > 63) {
		syslog(LOG_ERR, "Invalid DSCP value");
		return false;
	}
	config_dhcp.dscp = value;
	return true;
}

bool config_set_sk_priority(unsigned int priority) {
	if(priority > 6) {
		syslog(LOG_ERR, "Invalid SK priority value");
		return false;
	}
	config_dhcp.sk_prio = priority;
	return true;
}

void config_set_client_options(enum dhcpv6_config option, bool enable) {
	if(enable) {
		config_dhcp.client_options |= option;
	} else {
		config_dhcp.client_options &= ~option;
	}
}

bool config_set_request_addresses(char* mode) {
	if (!strcmp(mode, "force")) {
		config_dhcp.ia_na_mode = IA_MODE_FORCE;
		config_dhcp.allow_slaac_only = -1;
	} else if (!strcmp(mode, "none"))
		config_dhcp.ia_na_mode = IA_MODE_NONE;
	else if (!strcmp(mode, "try"))
		config_dhcp.ia_na_mode = IA_MODE_TRY;
	else {
		syslog(LOG_ERR, "Invalid Request Adresses mode");
		return false;
	}

	return true;
}

bool config_set_request_prefix(unsigned int length, unsigned int id) {
	struct odhcp6c_request_prefix prefix = {0};

	odhcp6c_clear_state(STATE_IA_PD_INIT);

	if (config_dhcp.ia_pd_mode != IA_MODE_FORCE)
		config_dhcp.ia_pd_mode = length > 128 ? IA_MODE_NONE : IA_MODE_TRY;

	if(length <= 128) {
		if (config_dhcp.allow_slaac_only >= 0 && config_dhcp.allow_slaac_only < 10)
			config_dhcp.allow_slaac_only = 10;

		prefix.length = length;
		prefix.iaid = htonl(id);

		if (odhcp6c_add_state(STATE_IA_PD_INIT, &prefix, sizeof(prefix))) {
			syslog(LOG_ERR, "Failed to set request IPv6-Prefix");
			return false;
		}
	}

	return true;
}

void config_set_force_prefix(bool enable) {
	if(enable) {
		config_dhcp.allow_slaac_only = -1;
		config_dhcp.ia_pd_mode = IA_MODE_FORCE;
	}
	else {
		config_dhcp.ia_pd_mode = IA_MODE_NONE;
	}
}

void config_set_stateful_only(bool enable) {
	config_dhcp.stateful_only_mode = enable;
}

void config_set_allow_slaac_only(int value) {
	config_dhcp.allow_slaac_only = value;
}

void config_clear_requested_options(void) {
	config_dhcp.oro_user_cnt = 0;
}

bool config_add_requested_options(unsigned int option) {
	if(option > UINT16_MAX) {
		syslog(LOG_ERR, "Invalid requested option");
		return false;
	}

	option = htons(option);
	if (odhcp6c_insert_state(STATE_ORO, 0, &option, 2)) {
		syslog(LOG_ERR, "Failed to set requested option");
		return false;
	}
	config_dhcp.oro_user_cnt++;
	return true;
}

void config_clear_send_options(void) {
	odhcp6c_clear_state(STATE_OPTS);
}

bool config_add_send_options(char* option) {
	return (config_parse_opt(option) == 0);
}

bool config_set_rtx_delay_max(enum config_dhcp_msg msg, unsigned int value)
{
	if(msg >= CONFIG_DHCP_MAX || value > UINT8_MAX) {
		syslog(LOG_ERR, "Invalid retransmission Maximum Delay value");
		return false;
	}
	config_dhcp.message_rtx[msg].delay_max = value;
	return true;
}

bool config_set_rtx_timeout_init(enum config_dhcp_msg msg, unsigned int value)
{
	if(msg >= CONFIG_DHCP_MAX || value > UINT8_MAX || value == 0) {
		syslog(LOG_ERR, "Invalid retransmission Initial Timeout value");
		return false;
	}
	config_dhcp.message_rtx[msg].timeout_init = value;
	return true;
}

bool config_set_rtx_timeout_max(enum config_dhcp_msg msg, unsigned int value)
{
	if(msg >= CONFIG_DHCP_MAX || value > UINT16_MAX) {
		syslog(LOG_ERR, "Invalid retransmission Maximum Timeout value");
		return false;
	}
	config_dhcp.message_rtx[msg].timeout_max = value;
	return true;
}

bool config_set_rtx_rc_max(enum config_dhcp_msg msg, unsigned int value)
{
	if(msg >= CONFIG_DHCP_MAX || value > UINT8_MAX) {
		syslog(LOG_ERR, "Invalid retransmission Retry Attempt value");
		return false;
	}
	config_dhcp.message_rtx[msg].rc_max = value;
	return true;
}

bool config_set_irt_default(unsigned int value)
{
	if(value == 0) {
		syslog(LOG_ERR, "Invalid Default Information Refresh Time value");
		return false;
	}
	config_dhcp.irt_default = value;
	return true;
}

bool config_set_irt_min(unsigned int value)
{
	if(value == 0) {
		syslog(LOG_ERR, "Invalid Minimum Information Refresh Time value");
		return false;
	}
	config_dhcp.irt_min = value;
	return true;
}

bool config_set_rand_factor(unsigned int value)
{
	if(value > 999 || value < 10) {
		syslog(LOG_ERR, "Invalid Random Factor value");
		return false;
	}
	config_dhcp.rand_factor = value;
	return true;
}

static int config_parse_opt_u8(const char *src, uint8_t **dst)
{
	int len = strlen(src);

	*dst = realloc(*dst, len/2);
	if (!*dst)
		return -1;

	return script_unhexlify(*dst, len, src);
}

static int config_parse_opt_string(const char *src, uint8_t **dst, const bool array)
{
	int o_len = 0;
	char *sep = strpbrk(src, ARRAY_SEP);

	if (sep && !array)
		return -1;

	do {
		if (sep) {
			*sep = 0;
			sep++;
		}

		int len = strlen(src);

		*dst = realloc(*dst, o_len + len);
		if (!*dst)
			return -1;

		memcpy(&((*dst)[o_len]), src, len);

		o_len += len;
		src = sep;

		if (sep)
			sep = strpbrk(src, ARRAY_SEP);
	} while (src);

	return o_len;
}

static int config_parse_opt_dns_string(const char *src, uint8_t **dst, const bool array)
{
	int o_len = 0;
	char *sep = strpbrk(src, ARRAY_SEP);

	if (sep && !array)
		return -1;

	do {
		uint8_t tmp[256];

		if (sep) {
			*sep = 0;
			sep++;
		}

		int len = dn_comp(src, tmp, sizeof(tmp), NULL, NULL);
		if (len < 0)
			return -1;

		*dst = realloc(*dst, o_len + len);
		if (!*dst)
			return -1;

		memcpy(&((*dst)[o_len]), tmp, len);

		o_len += len;
		src = sep;

		if (sep)
			sep = strpbrk(src, ARRAY_SEP);
	} while (src);

	return o_len;
}

static int config_parse_opt_ip6(const char *src, uint8_t **dst, const bool array)
{
	int o_len = 0;
	char *sep = strpbrk(src, ARRAY_SEP);

	if (sep && !array)
		return -1;

	do {
		int len = sizeof(struct in6_addr);

		if (sep) {
			*sep = 0;
			sep++;
		}

		*dst = realloc(*dst, o_len + len);
		if (!*dst)
			return -1;

		if (inet_pton(AF_INET6, src, &((*dst)[o_len])) < 1)
			return -1;

		o_len += len;
		src = sep;

		if (sep)
			sep = strpbrk(src, ARRAY_SEP);
	} while (src);

	return o_len;
}

static int config_parse_opt_user_class(const char *src, uint8_t **dst, const bool array)
{
	int o_len = 0;
	char *sep = strpbrk(src, ARRAY_SEP);

	if (sep && !array)
		return -1;

	do {
		if (sep) {
			*sep = 0;
			sep++;
		}
		uint16_t str_len = strlen(src);

		*dst = realloc(*dst, o_len + str_len + 2);
		if (!*dst)
			return -1;

		struct user_class {
			uint16_t len;
			uint8_t data[];
		} *e = (struct user_class *)&((*dst)[o_len]);

		e->len = ntohs(str_len);
		memcpy(e->data, src, str_len);

		o_len += str_len + 2;
		src = sep;

		if (sep)
			sep = strpbrk(src, ARRAY_SEP);
	} while (src);

	return o_len;
}

static uint8_t *config_state_find_opt(const uint16_t code)
{
	size_t opts_len;
	uint8_t *odata, *opts = odhcp6c_get_state(STATE_OPTS, &opts_len);
	uint16_t otype, olen;

	dhcpv6_for_each_option(opts, &opts[opts_len], otype, olen, odata) {
		if (otype == code)
			return &odata[-4];
	}

	return NULL;
}

int config_add_opt(const uint16_t code, const uint8_t *data, const uint16_t len)
{
	struct {
		uint16_t code;
		uint16_t len;
	} opt_hdr = { htons(code), htons(len) };

	if (config_state_find_opt(code))
		return -1;

	if (odhcp6c_add_state(STATE_OPTS, &opt_hdr, sizeof(opt_hdr)) ||
			odhcp6c_add_state(STATE_OPTS, data, len)) {
		syslog(LOG_ERR, "Failed to add option %hu", code);
		return 1;
	}

	return 0;
}

int config_parse_opt_data(const char *data, uint8_t **dst, const unsigned int type,
		const bool array)
{
	int ret = 0;

	switch (type) {
	case OPT_U8:
		ret = config_parse_opt_u8(data, dst);
		break;

	case OPT_STR:
		ret = config_parse_opt_string(data, dst, array);
		break;

	case OPT_DNS_STR:
		ret = config_parse_opt_dns_string(data, dst, array);
		break;

	case OPT_IP6:
		ret = config_parse_opt_ip6(data, dst, array);
		break;

	case OPT_USER_CLASS:
		ret = config_parse_opt_user_class(data, dst, array);
		break;

	default:
		ret = -1;
		break;
	}

	return ret;
}

int config_parse_opt(const char *opt)
{
	uint32_t optn;
	char *data;
	uint8_t *payload = NULL;
	int payload_len;
	unsigned int type = OPT_U8;
	bool array = false;
	struct odhcp6c_opt *dopt = NULL;
	int ret = -1;

	data = strpbrk(opt, ":");
	if (!data)
		return -1;

	*data = '\0';
	data++;

	if (strlen(opt) == 0 || strlen(data) == 0)
		return -1;

	dopt = odhcp6c_find_opt_by_name(opt);
	if (!dopt) {
		char *e;
		optn = strtoul(opt, &e, 0);
		if (*e || e == opt || optn > USHRT_MAX)
			return -1;

		dopt = odhcp6c_find_opt(optn);
	} else
		optn = dopt->code;

	/* Check if the type for the content is well-known */
	if (dopt) {
		/* Refuse internal options */
		if (dopt->flags & OPT_INTERNAL)
			return -1;

		type = dopt->flags & OPT_MASK_SIZE;
		array = ((dopt->flags & OPT_ARRAY) == OPT_ARRAY) ? true : false;
	} else if (data[0] == '"' || data[0] == '\'') {
		char *end = strrchr(data + 1, data[0]);

		if (end && (end == (data + strlen(data) - 1))) {
			/* Raw option is specified as a string */
			type = OPT_STR;
			data++;
			*end = '\0';
		}

	}

	payload_len = config_parse_opt_data(data, &payload, type, array);
	if (payload_len > 0)
		ret = config_add_opt(optn, payload, payload_len);

	free(payload);

	return ret;
}

void config_apply_dhcp_rtx(struct dhcpv6_retx* dhcpv6_retx)
{
	dhcpv6_retx[DHCPV6_MSG_SOLICIT].max_delay = config_dhcp.message_rtx[CONFIG_DHCP_SOLICIT].delay_max;
	dhcpv6_retx[DHCPV6_MSG_SOLICIT].init_timeo = config_dhcp.message_rtx[CONFIG_DHCP_SOLICIT].timeout_init;
	dhcpv6_retx[DHCPV6_MSG_SOLICIT].max_timeo = config_dhcp.message_rtx[CONFIG_DHCP_SOLICIT].timeout_max;
	dhcpv6_retx[DHCPV6_MSG_REQUEST].init_timeo = config_dhcp.message_rtx[CONFIG_DHCP_REQUEST].timeout_init;
	dhcpv6_retx[DHCPV6_MSG_REQUEST].max_timeo = config_dhcp.message_rtx[CONFIG_DHCP_REQUEST].timeout_max;
	dhcpv6_retx[DHCPV6_MSG_REQUEST].max_rc = config_dhcp.message_rtx[CONFIG_DHCP_REQUEST].rc_max;
	dhcpv6_retx[DHCPV6_MSG_RENEW].init_timeo = config_dhcp.message_rtx[CONFIG_DHCP_RENEW].timeout_init;
	dhcpv6_retx[DHCPV6_MSG_RENEW].max_timeo = config_dhcp.message_rtx[CONFIG_DHCP_RENEW].timeout_max;
	dhcpv6_retx[DHCPV6_MSG_REBIND].init_timeo = config_dhcp.message_rtx[CONFIG_DHCP_REBIND].timeout_init;
	dhcpv6_retx[DHCPV6_MSG_REBIND].max_timeo = config_dhcp.message_rtx[CONFIG_DHCP_REBIND].timeout_max;
	dhcpv6_retx[DHCPV6_MSG_INFO_REQ].max_delay = config_dhcp.message_rtx[CONFIG_DHCP_INFO_REQ].delay_max;
	dhcpv6_retx[DHCPV6_MSG_INFO_REQ].init_timeo = config_dhcp.message_rtx[CONFIG_DHCP_INFO_REQ].timeout_init;
	dhcpv6_retx[DHCPV6_MSG_INFO_REQ].max_timeo = config_dhcp.message_rtx[CONFIG_DHCP_INFO_REQ].timeout_max;
	dhcpv6_retx[DHCPV6_MSG_RELEASE].init_timeo = config_dhcp.message_rtx[CONFIG_DHCP_RELEASE].timeout_init;
	dhcpv6_retx[DHCPV6_MSG_RELEASE].max_rc = config_dhcp.message_rtx[CONFIG_DHCP_RELEASE].rc_max;
	dhcpv6_retx[DHCPV6_MSG_DECLINE].init_timeo = config_dhcp.message_rtx[CONFIG_DHCP_DECLINE].timeout_init;
	dhcpv6_retx[DHCPV6_MSG_DECLINE].max_rc = config_dhcp.message_rtx[CONFIG_DHCP_DECLINE].rc_max;
}