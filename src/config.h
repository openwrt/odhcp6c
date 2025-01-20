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

#ifndef _CONFIG_H__
#define _CONFIG_H__

struct config_dhcp_rtx {
	uint8_t delay_max;
	uint8_t timeout_init;
	uint16_t timeout_max;
	uint8_t rc_max;
};

enum config_dhcp_msg {
	CONFIG_DHCP_SOLICIT,
	CONFIG_DHCP_REQUEST,
	CONFIG_DHCP_RENEW,
	CONFIG_DHCP_REBIND,
	CONFIG_DHCP_RELEASE,
	CONFIG_DHCP_DECLINE,
	CONFIG_DHCP_INFO_REQ,
	CONFIG_DHCP_MAX
};

struct config_dhcp {
	bool release;
	int dscp;
	int sk_prio;
	bool stateful_only_mode;
	enum odhcp6c_ia_mode ia_na_mode;
	enum odhcp6c_ia_mode ia_pd_mode;
	unsigned int client_options;
	int allow_slaac_only;
	unsigned int oro_user_cnt;
	struct config_dhcp_rtx message_rtx[CONFIG_DHCP_MAX];
	uint32_t irt_default;
	uint32_t irt_min;
	uint16_t rand_factor;
};

struct config_dhcp *config_dhcp_get(void);
void config_dhcp_reset(void);
void config_set_release(bool enable);
bool config_set_dscp(unsigned int value) ;
bool config_set_sk_priority(unsigned int priority);
void config_set_client_options(enum dhcpv6_config option, bool enable);
bool config_set_request_addresses(char *mode);
bool config_set_request_prefix(unsigned int length, unsigned int id);
void config_set_force_prefix(bool enable);
void config_set_stateful_only(bool enable);
void config_set_allow_slaac_only(int value);
void config_clear_requested_options(void) ;
bool config_add_requested_options(unsigned int option);
void config_clear_send_options(void);
bool config_add_send_options(char *option);
bool config_set_rtx_delay_max(enum config_dhcp_msg msg, unsigned int value);
bool config_set_rtx_timeout_init(enum config_dhcp_msg msg, unsigned int value);
bool config_set_rtx_timeout_max(enum config_dhcp_msg msg, unsigned int value);
bool config_set_rtx_rc_max(enum config_dhcp_msg msg, unsigned int value);
bool config_set_irt_default(unsigned int value);
bool config_set_irt_min(unsigned int value);
bool config_set_rand_factor(unsigned int value);

int config_add_opt(const uint16_t code, const uint8_t *data, const uint16_t len);
int config_parse_opt_data(const char *data, uint8_t **dst, const unsigned int type, const bool array);
int config_parse_opt(const char *opt);

void config_apply_dhcp_rtx(struct dhcpv6_retx* dhcpv6_retx);

#endif
