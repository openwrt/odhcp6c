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

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if_addr.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <poll.h>
#include <resolv.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "odhcp6c.h"
#include "ra.h"
#include "ubus.h"

#define DHCPV6_FD_INDEX 0
#define UBUS_FD_INDEX 1

#ifndef IN6_IS_ADDR_UNIQUELOCAL
#define IN6_IS_ADDR_UNIQUELOCAL(a) \
	((((__const uint32_t *) (a))[0] & htonl (0xfe000000)) \
	 == htonl (0xfc000000))
#endif

static void sighandler(int signal);
static int usage(void);

static uint8_t *state_data[_STATE_MAX] = {NULL};
static size_t state_len[_STATE_MAX] = {0};

static volatile bool signal_io = false;
static volatile bool signal_usr1 = false;
static volatile bool signal_usr2 = false;
static volatile bool signal_term = false;

static int urandom_fd = -1;
static bool bound = false, ra = false;
static time_t last_update = 0;
static char *ifname = NULL;
struct config_dhcp *config_dhcp = NULL;

static unsigned int script_sync_delay = 10;
static unsigned int script_accu_delay = 1;

static struct odhcp6c_opt opts[] = {
	{ .code = DHCPV6_OPT_CLIENTID, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_SERVERID, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_IA_NA, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str= NULL },
	{ .code = DHCPV6_OPT_IA_TA, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_IA_ADDR, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_ORO, .flags = OPT_INTERNAL, .str = NULL },
	{ .code = DHCPV6_OPT_PREF, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_ELAPSED, .flags = OPT_INTERNAL, .str = NULL },
	{ .code = DHCPV6_OPT_RELAY_MSG, .flags = OPT_INTERNAL, .str = NULL },
	{ .code = DHCPV6_OPT_AUTH, .flags = OPT_U8 | OPT_NO_PASSTHRU, .str = "authentication" },
	{ .code = DHCPV6_OPT_UNICAST, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_STATUS, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_RAPID_COMMIT, .flags = OPT_INTERNAL, .str = NULL },
	{ .code = DHCPV6_OPT_USER_CLASS, .flags = OPT_USER_CLASS | OPT_ARRAY, .str = "userclass" },
	{ .code = DHCPV6_OPT_VENDOR_CLASS, .flags = OPT_U8, .str = "vendorclass" },
	{ .code = DHCPV6_OPT_INTERFACE_ID, .flags = OPT_INTERNAL, .str = NULL },
	{ .code = DHCPV6_OPT_RECONF_MESSAGE, .flags = OPT_INTERNAL, .str = NULL },
	{ .code = DHCPV6_OPT_RECONF_ACCEPT, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_SIP_SERVER_D, .flags = OPT_DNS_STR | OPT_ORO, .str = "sipserver_d" },
	{ .code = DHCPV6_OPT_SIP_SERVER_A, .flags = OPT_IP6 | OPT_ARRAY | OPT_ORO, .str = "sipserver_a" },
	{ .code = DHCPV6_OPT_DNS_SERVERS, .flags = OPT_IP6 | OPT_ARRAY | OPT_ORO, .str = "dns" },
	{ .code = DHCPV6_OPT_DNS_DOMAIN, .flags = OPT_DNS_STR | OPT_ORO, .str = "search" },
	{ .code = DHCPV6_OPT_IA_PD, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_IA_PREFIX, .flags = OPT_INTERNAL, .str = NULL },
	{ .code = DHCPV6_OPT_SNTP_SERVERS, .flags = OPT_IP6 | OPT_ARRAY | OPT_ORO, .str = "sntpservers" },
	{ .code = DHCPV6_OPT_INFO_REFRESH, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU | OPT_ORO | OPT_ORO_STATELESS, .str = NULL },
	{ .code = DHCPV6_OPT_REMOTE_ID, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_SUBSCRIBER_ID, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_FQDN, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU | OPT_ORO, .str = NULL },
	{ .code = DHCPV6_OPT_ERO, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_LQ_QUERY, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_CLIENT_DATA, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_CLT_TIME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_LQ_RELAY_DATA, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_LQ_CLIENT_LINK, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_RELAY_ID, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_NTP_SERVER, .flags = OPT_U8 | OPT_ORO, .str = "ntpserver" },
	{ .code = DHCPV6_OPT_CLIENT_ARCH_TYPE, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_AFTR_NAME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU | OPT_ORO, .str = NULL },
	{ .code = DHCPV6_OPT_RSOO, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_PD_EXCLUDE, .flags = OPT_INTERNAL | OPT_ORO | OPT_ORO_STATEFUL, .str = NULL },
	{ .code = DHCPV6_OPT_VSS, .flags = OPT_U8, .str = "vss" },
	{ .code = DHCPV6_OPT_LINK_LAYER_ADDRESS, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_LINK_ADDRESS, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_RADIUS, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_SOL_MAX_RT, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU | OPT_ORO | OPT_ORO_SOLICIT, .str = NULL },
	{ .code = DHCPV6_OPT_INF_MAX_RT, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU | OPT_ORO | OPT_ORO_STATELESS, .str = NULL },
	{ .code = DHCPV6_OPT_DHCPV4_MSG, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_S46_RULE, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_S46_BR, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_S46_DMR, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_S46_V4V6BIND, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_S46_PORTPARAMS, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_S46_CONT_MAPE, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU | OPT_ORO, .str = NULL },
	{ .code = DHCPV6_OPT_S46_CONT_MAPT, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU | OPT_ORO, .str = NULL },
	{ .code = DHCPV6_OPT_S46_CONT_LW, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU | OPT_ORO, .str = NULL },
	{ .code = DHCPV6_OPT_LQ_BASE_TIME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_LQ_START_TIME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_LQ_END_TIME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_ANI_ATT, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_ANI_NETWORK_NAME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_ANI_AP_NAME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_ANI_AP_BSSID, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_ANI_OPERATOR_ID, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_ANI_OPERATOR_REALM, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_MUD_URL_V6, .flags = OPT_STR | OPT_NO_PASSTHRU, .str = "mud_url_v6" },
	{ .code = DHCPV6_OPT_F_BINDING_STATUS, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_CONNECT_FLAGS, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_DNS_REMOVAL_INFO, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_DNS_HOST_NAME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_DNS_ZONE_NAME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_DNS_FLAGS, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_EXPIRATION_TIME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_MAX_UNACKED_BNDUPD, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_MCLT, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_PARTNER_LIFETIME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_PARTNER_LIFETIME_SENT, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_PARTNER_DOWN_TIME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_PARTNER_RAW_CLT_TIME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_PROTOCOL_VERSION, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_KEEPALIVE_TIME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_RECONFIGURE_DATA, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_RELATIONSHIP_NAME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_SERVER_FLAGS, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_SERVER_STATE, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_START_TIME_OF_STATE, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_F_STATE_EXPIRATION_TIME, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = DHCPV6_OPT_RELAY_PORT, .flags = OPT_INTERNAL | OPT_NO_PASSTHRU, .str = NULL },
	{ .code = 0, .flags = 0, .str = NULL },
};

int main(_o_unused int argc, char* const argv[])
{
	static struct in6_addr ifid = IN6ADDR_ANY_INIT;
	// Allocate resources
	const char *pidfile = NULL;
	const char *script = "/lib/netifd/dhcpv6.script";
	ssize_t l;
	uint8_t buf[134], *o_data;
	char *optpos;
	uint16_t opttype;
	struct odhcp6c_opt *opt;
	int ia_pd_iaid_index = 0;
	int verbosity = 0;
	bool help = false, daemonize = false;
	int logopt = LOG_PID;
	int c;
	int res = -1;
	unsigned int ra_options = RA_RDNSS_DEFAULT_LIFETIME;
	unsigned int ra_holdoff_interval = RA_MIN_ADV_INTERVAL;
	bool terminate = false;
	config_dhcp = config_dhcp_get();
	config_dhcp_reset();

	while ((c = getopt(argc, argv, "S::DN:V:P:FB:c:i:r:Ru:Ux:s:EkK:t:C:m:Lhedp:fav")) != -1) {
		switch (c) {
		case 'S':
			config_set_allow_slaac_only((optarg) ? atoi(optarg) : -1);
			break;

		case 'D':
			config_set_stateful_only(true);
			break;

		case 'N':
			if (!config_set_request_addresses(optarg))
				help = true;
			break;

		case 'V':
			opt = odhcp6c_find_opt(DHCPV6_OPT_VENDOR_CLASS);
			if (!opt) {
				syslog(LOG_ERR, "Failed to set vendor-class option");
				return 1;
			}

			o_data = NULL;
			res = config_parse_opt_data(optarg, &o_data, opt->flags & OPT_MASK_SIZE,
						(opt->flags & OPT_ARRAY) == OPT_ARRAY);
			if (res > 0) {
				res = config_add_opt(opt->code, o_data, res);
				if (res) {
					if (res > 0)
						return 1;

					help = true;
				}
			} else {
				help = true;
			}

			free(o_data);
			break;

		case 'P':
			if (config_dhcp->ia_pd_mode == IA_MODE_NONE)
				config_dhcp->ia_pd_mode = IA_MODE_TRY;

			if (config_dhcp->allow_slaac_only >= 0 && config_dhcp->allow_slaac_only < 10)
				config_dhcp->allow_slaac_only = 10;

			struct odhcp6c_request_prefix prefix = { 0 };

			optpos = strchr(optarg, '/');
			if (optpos) {
				strncpy((char *)buf, optarg, optpos - optarg);
				buf[optpos - optarg] = '\0';
				if (inet_pton(AF_INET6, (char *)buf, &prefix.addr) <= 0) {
					syslog(LOG_ERR, "invalid argument: '%s'", optarg);
					return 1;
				}
				optpos++;
			} else {
				optpos = optarg;
			}

			char *iaid_begin;
			int iaid_len = 0;
			prefix.length = strtoul(optpos, &iaid_begin, 10);

			if (*iaid_begin != '\0' && *iaid_begin != ',' && *iaid_begin != ':') {
				syslog(LOG_ERR, "invalid argument: '%s'", optarg);
				return 1;
			}

			if (*iaid_begin == ',' && (iaid_len = strlen(iaid_begin)) > 1)
				memcpy(&prefix.iaid, iaid_begin + 1, iaid_len > 4 ? 4 : iaid_len);
			else if (*iaid_begin == ':')
				prefix.iaid = htonl((uint32_t)strtoul(&iaid_begin[1], NULL, 16));
			else
				prefix.iaid = htonl(++ia_pd_iaid_index);

			if (odhcp6c_add_state(STATE_IA_PD_INIT, &prefix, sizeof(prefix))) {
				syslog(LOG_ERR, "Failed to set request IPv6-Prefix");
				return 1;
			}
			break;

		case 'F':
			config_set_force_prefix(true);
			break;

		case 'c':
			l = script_unhexlify(&buf[4], sizeof(buf) - DHCPV6_OPT_HDR_SIZE, optarg);
			if (l > 0) {
				buf[0] = 0;
				buf[1] = DHCPV6_OPT_CLIENTID;
				buf[2] = 0;
				buf[3] = l;
				if (odhcp6c_add_state(STATE_CLIENT_ID, buf, l + 4)) {
					syslog(LOG_ERR, "Failed to override client-ID");
					return 1;
				}
			} else {
				help = true;
			}
			break;

		case 'i':
			if (inet_pton(AF_INET6, optarg, &ifid) != 1)
				help = true;
			break;

		case 'r':
			optpos = optarg;
			while (optpos[0]) {
				opttype = htons(strtoul(optarg, &optpos, 10));
				if (optpos == optarg)
					break;
				else if (optpos[0])
					optarg = &optpos[1];

				if (odhcp6c_add_state(STATE_ORO, &opttype, 2)) {
					syslog(LOG_ERR, "Failed to add requested option");
					return 1;
				}
			}
			break;

		case 'R':
			config_set_client_options(DHCPV6_STRICT_OPTIONS, true);
			break;

		case 'u':
			opt = odhcp6c_find_opt(DHCPV6_OPT_USER_CLASS);
			if (!opt) {
				syslog(LOG_ERR, "Failed to set user-class option");
				return 1;
			}

			o_data = NULL;
			res = config_parse_opt_data(optarg, &o_data, opt->flags & OPT_MASK_SIZE,
						(opt->flags & OPT_ARRAY) == OPT_ARRAY);
			if (res > 0) {
				res = config_add_opt(opt->code, o_data, res);
				if (res) {
					if (res > 0)
						return 1;

					help = true;
				}
			} else {
				help = true;
			}

			free(o_data);
			break;

		case 'U':
			config_set_client_options(DHCPV6_IGNORE_OPT_UNICAST, true);
			break;

		case 's':
			if (script)
				script = optarg;
			break;

		case 'E':
#ifndef WITH_UBUS
			syslog(LOG_ERR, "Failed to use ubus event: ENABLE_UBUS compilation flag missing");
			return 1;
#endif /* WITH_UBUS */
			script = NULL;
			break;

		case 'k':
			config_set_release(false);
			break;

		case 'K':
			config_set_sk_priority(atoi(optarg));
			break;

		case 't':
			config_set_rtx_timeout_max(CONFIG_DHCP_SOLICIT, atoi(optarg));
			break;

		case 'C':
			config_set_dscp(atoi(optarg));
			break;

		case 'm':
			ra_holdoff_interval = atoi(optarg);
			break;

		case 'L':
			ra_options &= ~RA_RDNSS_DEFAULT_LIFETIME;
			break;

		case 'e':
			logopt |= LOG_PERROR;
			break;

		case 'd':
			daemonize = true;
			break;

		case 'p':
			pidfile = optarg;
			break;

		case 'f':
			config_set_client_options(DHCPV6_CLIENT_FQDN, false);
			break;

		case 'a':
			config_set_client_options(DHCPV6_ACCEPT_RECONFIGURE, false);
			break;

		case 'v':
			++verbosity;
			break;

		case 'x':
			res = config_parse_opt(optarg);
			if (res) {
				if (res > 0)
					return res;

				help = true;
			}
			break;

		default:
			help = true;
			break;
		}
	}

	if (config_dhcp->allow_slaac_only > 0)
		script_sync_delay = config_dhcp->allow_slaac_only;

	openlog("odhcp6c", logopt, LOG_DAEMON);
	if (!verbosity)
		setlogmask(LOG_UPTO(LOG_WARNING));

	ifname = argv[optind];

	if (help || !ifname)
		return usage();

	signal(SIGIO, sighandler);
	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);

	if (daemonize) {
		openlog("odhcp6c", LOG_PID, LOG_DAEMON); // Disable LOG_PERROR
		if (daemon(0, 0)) {
			syslog(LOG_ERR, "Failed to daemonize: %s",
					strerror(errno));
			return 3;
		}

		if (!pidfile) {
			snprintf((char*)buf, sizeof(buf), "/var/run/odhcp6c.%s.pid", ifname);
			pidfile = (char*)buf;
		}

		FILE *fp = fopen(pidfile, "w");
		if (fp) {
			fprintf(fp, "%i\n", getpid());
			fclose(fp);
		}
	}

	if ((urandom_fd = open("/dev/urandom", O_CLOEXEC | O_RDONLY)) < 0 ||
			ra_init(ifname, &ifid, ra_options, ra_holdoff_interval) ||
			script_init(script, ifname)) {
		syslog(LOG_ERR, "failed to initialize: %s", strerror(errno));
		return 4;
	}

	struct pollfd fds[2] = {0};
	int nfds = 0;

	int mode = DHCPV6_UNKNOWN;
	enum dhcpv6_msg msg_type = DHCPV6_MSG_UNKNOWN;

	fds[DHCPV6_FD_INDEX].fd = -1;
	fds[DHCPV6_FD_INDEX].events = POLLIN;
	nfds++;

#ifdef WITH_UBUS
	char *err = ubus_init(ifname);
	if (err) {
		syslog(LOG_ERR, "ubus error: %s", err);
		return 1;
	}

	struct ubus_context *ubus = ubus_get_ctx();
	int ubus_socket = ubus->sock.fd;
	if (ubus_socket < 0) {
		syslog(LOG_ERR, "Invalid ubus file descriptor");
		return 1;
	}
	fds[UBUS_FD_INDEX].fd = ubus_socket;
	fds[UBUS_FD_INDEX].events = POLLIN;
	nfds++;
#endif /* WITH_UBUS */

	notify_state_change("started", 0, false);

	while (!terminate) { // Main logic
		int poll_res;
		bool signalled = odhcp6c_signal_process();

		switch (dhcpv6_get_state()) {
		case DHCPV6_INIT:
			odhcp6c_clear_state(STATE_SERVER_ID);
			odhcp6c_clear_state(STATE_SERVER_ADDR);
			odhcp6c_clear_state(STATE_IA_NA);
			odhcp6c_clear_state(STATE_IA_PD);
			odhcp6c_clear_state(STATE_SNTP_IP);
			odhcp6c_clear_state(STATE_NTP_IP);
			odhcp6c_clear_state(STATE_NTP_FQDN);
			odhcp6c_clear_state(STATE_SIP_IP);
			odhcp6c_clear_state(STATE_SIP_FQDN);
			bound = false;

			size_t oro_len = 0;
			odhcp6c_get_state(STATE_ORO, &oro_len);
			config_dhcp->oro_user_cnt = oro_len / sizeof(uint16_t);

			if (init_dhcpv6(ifname)) {
				syslog(LOG_ERR, "failed to initialize: %s", strerror(errno));
				return 1;
			}

			fds[DHCPV6_FD_INDEX].fd = dhcpv6_get_socket();

			syslog(LOG_NOTICE, "(re)starting transaction on %s", ifname);

			signal_usr1 = signal_usr2 = false;

			dhcpv6_set_state(DHCPV6_SOLICIT);
			break;

		case DHCPV6_SOLICIT:
			mode = dhcpv6_get_ia_mode();
			if (mode == DHCPV6_STATELESS) {
				dhcpv6_set_state(DHCPV6_REQUEST);
				break;
			}

			msg_type = DHCPV6_MSG_SOLICIT;
			dhcpv6_send_request(msg_type);
			break;

		case DHCPV6_ADVERT:
			if (res > 0) {
				mode = DHCPV6_STATEFUL;
				dhcpv6_set_state(DHCPV6_REQUEST);
			} else {
				mode = DHCPV6_UNKNOWN;
				dhcpv6_set_state(DHCPV6_RESET);
			}
			break;

		case DHCPV6_REQUEST:
			msg_type = (mode == DHCPV6_STATELESS) ? DHCPV6_MSG_INFO_REQ : DHCPV6_MSG_REQUEST;
			dhcpv6_send_request(msg_type);
			break;

		case DHCPV6_REPLY:
			if ((res > 0) && mode != DHCPV6_UNKNOWN) {
				dhcpv6_set_state(DHCPV6_BOUND);
				break;
			}

			if ((res < 0) && signalled) {
				mode = DHCPV6_UNKNOWN;
				dhcpv6_set_state(DHCPV6_RESET);
				break;
			}

			mode = dhcpv6_promote_server_cand();
			dhcpv6_set_state(mode > DHCPV6_UNKNOWN ? DHCPV6_REQUEST : DHCPV6_RESET);
			break;

		case DHCPV6_BOUND:
			if (!bound) {
				bound = true;
				if (mode == DHCPV6_STATELESS) {
					syslog(LOG_NOTICE, "entering stateless-mode on %s", ifname);
					signal_usr1 = false;
					notify_state_change("informed", script_sync_delay, true);
				} else {
					notify_state_change("bound", script_sync_delay, true);
					syslog(LOG_NOTICE, "entering stateful-mode on %s", ifname);
				}
			}

			msg_type = DHCPV6_MSG_UNKNOWN;
			dhcpv6_send_request(msg_type);
			break;

		case DHCPV6_BOUND_REPLY:
			if (res == DHCPV6_MSG_RENEW || res == DHCPV6_MSG_REBIND ||
				res == DHCPV6_MSG_INFO_REQ) {
				msg_type = res;
				dhcpv6_set_state(DHCPV6_RECONF);
			} else {
				dhcpv6_set_state(DHCPV6_RECONF_REPLY);
			}
			break;

		case DHCPV6_RECONF:
			dhcpv6_send_request(msg_type);
			break;

		case DHCPV6_RECONF_REPLY:
			if (res > 0) {
				dhcpv6_set_state(DHCPV6_BOUND);
				if (mode == DHCPV6_STATEFUL)
					notify_state_change("updated", 0, false);
			} else {
				dhcpv6_set_state(mode == DHCPV6_STATELESS ? DHCPV6_INFO : DHCPV6_RENEW);
			}
			break;

		case DHCPV6_RENEW:
			msg_type = DHCPV6_MSG_RENEW;
			dhcpv6_send_request(msg_type);
			break;

		case DHCPV6_RENEW_REPLY:
			if (res > 0 ) {
				notify_state_change("updated", 0, false);
				dhcpv6_set_state(DHCPV6_BOUND);
			} else {
				dhcpv6_set_state(DHCPV6_REBIND);
			}
			break;

		case DHCPV6_REBIND:
			odhcp6c_clear_state(STATE_SERVER_ID); // Remove binding
			odhcp6c_clear_state(STATE_SERVER_ADDR);

			size_t ia_pd_len_r, ia_na_len_r;
			odhcp6c_get_state(STATE_IA_PD, &ia_pd_len_r);
			odhcp6c_get_state(STATE_IA_NA, &ia_na_len_r);

			// If we have IAs, try rebind otherwise restart
			if (ia_pd_len_r == 0 && ia_na_len_r == 0) {
				dhcpv6_set_state(DHCPV6_RESET);
				break;
			}

			msg_type = DHCPV6_MSG_REBIND;
			dhcpv6_send_request(msg_type);
			break;

		case DHCPV6_REBIND_REPLY:
			if (res < 0) {
				dhcpv6_set_state(DHCPV6_RESET);
			} else {
				notify_state_change("rebound", 0, true);
				dhcpv6_set_state(DHCPV6_BOUND);
			}
			break;

		case DHCPV6_INFO:
			msg_type = DHCPV6_MSG_INFO_REQ;
			dhcpv6_send_request(msg_type);
			break;

		case DHCPV6_INFO_REPLY:
			dhcpv6_set_state(res < 0 ? DHCPV6_RESET : DHCPV6_BOUND);
			break;

		case DHCPV6_SOLICIT_PROCESSING:
		case DHCPV6_REQUEST_PROCESSING:
			res = dhcpv6_state_processing(msg_type);
			break;

		case DHCPV6_BOUND_PROCESSING:
		case DHCPV6_RECONF_PROCESSING:
		case DHCPV6_REBIND_PROCESSING:
			res = dhcpv6_state_processing(msg_type);

			if (signal_usr1)
				dhcpv6_set_state(mode == DHCPV6_STATELESS ? DHCPV6_INFO : DHCPV6_RENEW);
			break;

		case DHCPV6_RENEW_PROCESSING:
		case DHCPV6_INFO_PROCESSING:
			res = dhcpv6_state_processing(msg_type);

			if (signal_usr1)
				signal_usr1 = false;	// Acknowledged
			break;

		case DHCPV6_EXIT:
			odhcp6c_expire(false);

			size_t ia_pd_len, ia_na_len, server_id_len;
			odhcp6c_get_state(STATE_IA_PD, &ia_pd_len);
			odhcp6c_get_state(STATE_IA_NA, &ia_na_len);
			odhcp6c_get_state(STATE_SERVER_ID, &server_id_len);

			// Add all prefixes to lost prefixes
			if (bound) {
				bound = false;
				notify_state_change("unbound", 0, true);
			}

			if (server_id_len > 0 && (ia_pd_len > 0 || ia_na_len > 0) && (!signal_term || config_dhcp->release))
				dhcpv6_send_request(DHCPV6_MSG_RELEASE);

			odhcp6c_clear_state(STATE_IA_NA);
			odhcp6c_clear_state(STATE_IA_PD);

			if (signal_term) {
				terminate = true;
			} else {
				signal_usr2 = false;
				dhcpv6_set_state(DHCPV6_RESET);
			}
			break;

		case DHCPV6_RESET:
			odhcp6c_clear_state(STATE_CLIENT_ID);

			if (bound) {
				bound = false;
				notify_state_change("unbound", 0, true);
			}

			size_t oro_user_len, oro_total_len;
			odhcp6c_get_state(STATE_ORO, &oro_total_len);
			oro_user_len = config_dhcp->oro_user_cnt * sizeof(uint16_t);
			odhcp6c_remove_state(STATE_ORO, oro_user_len, oro_total_len - oro_user_len);

			close(dhcpv6_get_socket());
			fds[DHCPV6_FD_INDEX].fd = -1;

			dhcpv6_set_state(DHCPV6_INIT);
			break;

		default:
			break;
		}

		if (signal_usr2 || signal_term)
			dhcpv6_set_state(DHCPV6_EXIT);

		poll_res = poll(fds, nfds, dhcpv6_get_state_timeout());
		dhcpv6_reset_state_timeout();
		if (poll_res == -1 && (errno == EINTR || errno == EAGAIN)) {
			continue;
		}

		if (fds[0].revents & POLLIN)
			dhcpv6_receive_response(msg_type);

#ifdef WITH_UBUS
		if (fds[1].revents & POLLIN)
			ubus_handle_event(ubus);
#endif /* WITH_UBUS */
	}

	notify_state_change("stopped", 0, true);

#ifdef WITH_UBUS
	ubus_destroy(ubus);
#endif /* WITH_UBUS */

	return 0;
}

static int usage(void)
{
	const char buf[] =
	"Usage: odhcp6c [options] <interface>\n"
	"\nFeature options:\n"
	"	-S <time>	Wait at least <time> sec for a DHCP-server (0)\n"
	"	-D		Discard advertisements without any address or prefix proposed\n"
	"	-N <mode>	Mode for requesting addresses [try|force|none]\n"
	"	-P <[pfx/]len>	Request IPv6-Prefix (0 = auto)\n"
	"	-F		Force IPv6-Prefix\n"
	"	-V <class>	Set vendor-class option (base-16 encoded)\n"
	"	-u <user-class> Set user-class option string\n"
	"	-x <opt>:<val>	Add option opt (with value val) in sent packets (cumulative)\n"
	"			Examples of IPv6 address, string and base-16 encoded options:\n"
	"			-x dns:2001:2001::1,2001:2001::2 - option 23\n"
	"			-x 15:office - option 15 (userclass)\n"
	"			-x 0x1f4:ABBA - option 500\n"
	"			-x 202:'\"file\"' - option 202\n"
	"	-c <clientid>	Override client-ID (base-16 encoded 16-bit type + value)\n"
	"	-i <iface-id>	Use a custom interface identifier for RA handling\n"
	"	-r <options>	Options to be requested (comma-separated)\n"
	"	-R		Do not request any options except those specified with -r\n"
	"	-s <script>	Status update script (/lib/netifd/dhcpv6.script)\n"
	"	-E		Only use UBUS event and disable status update script\n"
	"	-a		Don't send Accept Reconfigure option\n"
	"	-f		Don't send Client FQDN option\n"
	"	-k		Don't send a RELEASE when stopping\n"
	"	-K <sk-prio>	Set packet kernel priority (0)\n"
	"	-C <dscp>	Set packet DSCP value (0)\n"
	"	-t <seconds>	Maximum timeout for DHCPv6-SOLICIT (120)\n"
	"	-m <seconds>	Minimum time between accepting RA updates (3)\n"
	"	-L		Ignore default lifetime for RDNSS records\n"
	"	-U		Ignore Server Unicast option\n"
	"\nInvocation options:\n"
	"	-p <pidfile>	Set pidfile (/var/run/odhcp6c.pid)\n"
	"	-d		Daemonize\n"
	"	-e		Write logmessages to stderr\n"
	"	-v		Increase logging verbosity\n"
	"	-h		Show this help\n\n";
	fputs(buf, stderr);

	return 1;
}

// Don't want to pull-in librt and libpthread just for a monotonic clock...
uint64_t odhcp6c_get_milli_time(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);

	return ((uint64_t)t.tv_sec) * 1000 + ((uint64_t)t.tv_nsec) / 1000000;
}

static uint8_t* odhcp6c_resize_state(enum odhcp6c_state state, ssize_t len)
{
	if (len == 0)
		return state_data[state] + state_len[state];
	else if (state_len[state] + len > 1024)
		return NULL;

	uint8_t *n = realloc(state_data[state], state_len[state] + len);

	if (n || state_len[state] + len == 0) {
		state_data[state] = n;
		n += state_len[state];
		state_len[state] += len;
	}

	return n;
}

static bool odhcp6c_server_advertised()
{
	size_t len;
	uint8_t *start = odhcp6c_get_state(STATE_RA_ROUTE, &len);

	for (struct odhcp6c_entry *c = (struct odhcp6c_entry*)start;
			(uint8_t*)c < &start[len] &&
			(uint8_t*)odhcp6c_next_entry(c) <= &start[len];
			c = odhcp6c_next_entry(c)) {
		// Only default route entries have flags
		if (c->length != 0 || IN6_IS_ADDR_UNSPECIFIED(&c->router))
			continue;

		if (c->ra_flags & (ND_RA_FLAG_MANAGED | ND_RA_FLAG_OTHER))
			return true;
	}

	return false;
}

bool odhcp6c_signal_process(void)
{
	while (signal_io) {
		signal_io = false;

		size_t old_ra_prefix_size = state_len[STATE_RA_PREFIX];
		bool ra_updated = ra_process();

		if (ra_link_up()) {
			signal_usr2 = true;
			ra = false;
		} else if (old_ra_prefix_size != state_len[STATE_RA_PREFIX] &&
				odhcp6c_server_advertised()) {
			// Restart DHCPv6 transaction when router advertisement flags
			// show presence of a DHCPv6 server and new prefixes were
			// added to STATE_RA_PREFIX state
			signal_usr2 = true;
		}

		if (ra_updated && (bound || config_dhcp->allow_slaac_only >= 0)) {
			notify_state_change("ra-updated", (!ra && !bound) ?
					script_sync_delay : script_accu_delay, false);
			ra = true;
		}
	}

	return signal_usr1 || signal_usr2 || signal_term;
}

void odhcp6c_clear_state(enum odhcp6c_state state)
{
	state_len[state] = 0;
}

int odhcp6c_add_state(enum odhcp6c_state state, const void *data, size_t len)
{
	uint8_t *n = odhcp6c_resize_state(state, len);

	if (!n)
		return -1;

	memcpy(n, data, len);

	return 0;
}

int odhcp6c_insert_state(enum odhcp6c_state state, size_t offset, const void *data, size_t len)
{
	ssize_t len_after = state_len[state] - offset;
	if (len_after < 0)
		return -1;

	uint8_t *n = odhcp6c_resize_state(state, len);

	if (n) {
		uint8_t *sdata = state_data[state];

		memmove(sdata + offset + len, sdata + offset, len_after);
		memcpy(sdata + offset, data, len);
	}

	return 0;
}

size_t odhcp6c_remove_state(enum odhcp6c_state state, size_t offset, size_t len)
{
	uint8_t *data = state_data[state];
	ssize_t len_after = state_len[state] - (offset + len);

	if (len_after < 0)
		return state_len[state];

	memmove(data + offset, data + offset + len, len_after);

	return state_len[state] -= len;
}

void* odhcp6c_move_state(enum odhcp6c_state state, size_t *len)
{
	*len = state_len[state];
	void *data = state_data[state];

	state_len[state] = 0;
	state_data[state] = NULL;

	return data;
}

void* odhcp6c_get_state(enum odhcp6c_state state, size_t *len)
{
	*len = state_len[state];

	return state_data[state];
}

static struct odhcp6c_entry* odhcp6c_find_entry(enum odhcp6c_state state, const struct odhcp6c_entry *new)
{
	size_t len, cmplen = offsetof(struct odhcp6c_entry, target) + ((new->length + 7) / 8);
	uint8_t *start = odhcp6c_get_state(state, &len);

	for (struct odhcp6c_entry *c = (struct odhcp6c_entry*)start;
			(uint8_t*)c < &start[len] &&
			(uint8_t*)odhcp6c_next_entry(c) <= &start[len];
			c = odhcp6c_next_entry(c)) {
		if (!memcmp(c, new, cmplen) && !memcmp(c->auxtarget, new->auxtarget, new->auxlen))
			return c;
	}

	return NULL;
}

bool odhcp6c_update_entry(enum odhcp6c_state state, struct odhcp6c_entry *new,
		unsigned int holdoff_interval)
{
	struct odhcp6c_entry *x = odhcp6c_find_entry(state, new);

	if (x) {
		if (holdoff_interval && new->valid >= x->valid &&
				new->valid != UINT32_MAX &&
				new->valid - x->valid < holdoff_interval &&
				new->preferred >= x->preferred &&
				new->preferred != UINT32_MAX &&
				new->preferred - x->preferred < holdoff_interval)
			return false;

		x->valid = new->valid;
		x->ra_flags = new->ra_flags;
		x->priority = new->priority;
		x->preferred = new->preferred;
		x->t1 = new->t1;
		x->t2 = new->t2;
		x->iaid = new->iaid;
	} else if (odhcp6c_add_state(state, new, odhcp6c_entry_size(new))) {
		return false;
	}

	return true;
}

static void odhcp6c_expire_list(enum odhcp6c_state state, uint32_t elapsed, bool remove_expired)
{
	size_t len;
	uint8_t *start = odhcp6c_get_state(state, &len);

	for (struct odhcp6c_entry *c = (struct odhcp6c_entry*)start;
			(uint8_t*)c < &start[len] &&
			(uint8_t*)odhcp6c_next_entry(c) <= &start[len];
			) {
		if (c->t1 < elapsed)
			c->t1 = 0;
		else if (c->t1 != UINT32_MAX)
			c->t1 -= elapsed;

		if (c->t2 < elapsed)
			c->t2 = 0;
		else if (c->t2 != UINT32_MAX)
			c->t2 -= elapsed;

		if (c->preferred < elapsed)
			c->preferred = 0;
		else if (c->preferred != UINT32_MAX)
			c->preferred -= elapsed;

		if (c->valid < elapsed)
			c->valid = 0;
		else if (c->valid != UINT32_MAX)
			c->valid -= elapsed;

		if (!c->valid && remove_expired) {
			odhcp6c_remove_state(state, ((uint8_t*)c) - start, odhcp6c_entry_size(c));
			start = odhcp6c_get_state(state, &len);
		} else {
			c = odhcp6c_next_entry(c);
		}
	}
}

void odhcp6c_expire(bool expire_ia_pd)
{
	time_t now = odhcp6c_get_milli_time() / 1000;
	uint32_t elapsed = (last_update > 0) ? now - last_update : 0;

	last_update = now;

	odhcp6c_expire_list(STATE_RA_PREFIX, elapsed, true);
	odhcp6c_expire_list(STATE_RA_ROUTE, elapsed, true);
	odhcp6c_expire_list(STATE_RA_DNS, elapsed, true);
	odhcp6c_expire_list(STATE_RA_SEARCH, elapsed, true);
	odhcp6c_expire_list(STATE_IA_NA, elapsed, true);
	odhcp6c_expire_list(STATE_IA_PD, elapsed, expire_ia_pd);
}

uint32_t odhcp6c_elapsed(void)
{
	return odhcp6c_get_milli_time() / 1000 - last_update;
}

int odhcp6c_random(void *buf, size_t len)
{
	return read(urandom_fd, buf, len);
}

bool odhcp6c_is_bound(void)
{
	return bound;
}

bool odhcp6c_addr_in_scope(const struct in6_addr *addr)
{
	FILE *fd = fopen("/proc/net/if_inet6", "r");
	int len;
	bool ret = false;
	char buf[256];

	if (fd == NULL)
		return false;

	while (fgets(buf, sizeof(buf), fd)) {
		struct in6_addr inet6_addr;
		uint32_t flags, dummy;
		unsigned int i;
		char name[IF_NAMESIZE], addr_buf[33];

		len = strlen(buf);

		if ((len <= 0) || buf[len - 1] != '\n')
			break;

		buf[--len] = '\0';

		if (sscanf(buf, "%s %x %x %x %x %s",
				addr_buf, &dummy, &dummy, &dummy, &flags, name) != 6)
			break;

		if (strcmp(name, ifname) ||
			(flags & (IFA_F_DADFAILED | IFA_F_TENTATIVE | IFA_F_DEPRECATED)))
			continue;

		for (i = 0; i < strlen(addr_buf); i++) {
			if (!isxdigit(addr_buf[i]) || isupper(addr_buf[i]))
				break;
		}

		memset(&inet6_addr, 0, sizeof(inet6_addr));
		for (i = 0; i < (strlen(addr_buf) / 2); i++) {
			unsigned char byte;
			static const char hex[] = "0123456789abcdef";
			byte = ((index(hex, addr_buf[i * 2]) - hex) << 4) |
				(index(hex, addr_buf[i * 2 + 1]) - hex);
			inet6_addr.s6_addr[i] = byte;
		}

		if ((IN6_IS_ADDR_LINKLOCAL(&inet6_addr) == IN6_IS_ADDR_LINKLOCAL(addr)) &&
			(IN6_IS_ADDR_UNIQUELOCAL(&inet6_addr) == IN6_IS_ADDR_UNIQUELOCAL(addr))) {
			ret = true;
			break;
		}
	}

	fclose(fd);
	return ret;
}

static void sighandler(int signal)
{
	if (signal == SIGUSR1)
		signal_usr1 = true;
	else if (signal == SIGUSR2)
		signal_usr2 = true;
	else if (signal == SIGIO)
		signal_io = true;
	else
		signal_term = true;
}

void notify_state_change(const char *status, int delay, bool resume)
{
	script_call(status, delay, resume);

#ifdef WITH_UBUS
	ubus_dhcp_event(status);
#endif /* WITH_UBUS */
}

struct odhcp6c_opt *odhcp6c_find_opt(const uint16_t code)
{
	struct odhcp6c_opt *opt = opts;

	while (opt->code) {
		if (opt->code == code)
			return opt;

		opt++;
	}

	return NULL;
}

struct odhcp6c_opt *odhcp6c_find_opt_by_name(const char *name)
{
	struct odhcp6c_opt *opt = opts;

	if (!name || !strlen(name))
		return NULL;

	while (opt->code && (!opt->str || strcmp(opt->str, name)))
		opt++;

	return (opt->code > 0 ? opt : NULL);
}
