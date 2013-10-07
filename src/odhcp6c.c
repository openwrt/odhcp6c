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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>

#include <net/if.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <arpa/inet.h>

#include "odhcp6c.h"
#include "ra.h"


static void sighandler(int signal);
static int usage(void);


static uint8_t *state_data[_STATE_MAX] = {NULL};
static size_t state_len[_STATE_MAX] = {0};

static volatile int do_signal = 0;
static int urandom_fd = -1, allow_slaac_only = 0;
static bool bound = false, release = true;
static time_t last_update = 0;


int main(_unused int argc, char* const argv[])
{
	// Allocate ressources
	const char *pidfile = NULL;
	const char *script = "/usr/sbin/odhcp6c-update";
	ssize_t l;
	uint8_t buf[134];
	char *optpos;
	uint16_t opttype;
	enum odhcp6c_ia_mode ia_na_mode = IA_MODE_TRY;
	enum odhcp6c_ia_mode ia_pd_mode = IA_MODE_TRY;
	static struct in6_addr ifid = IN6ADDR_ANY_INIT;

	bool help = false, daemonize = false;
	int logopt = LOG_PID;
	int c, request_pd = 0;
	while ((c = getopt(argc, argv, "S::N:P:Fc:i:r:s:khedp:")) != -1) {
		switch (c) {
		case 'S':
			allow_slaac_only = (optarg) ? atoi(optarg) : -1;
			break;

		case 'N':
			if (!strcmp(optarg, "force")) {
				ia_na_mode = IA_MODE_FORCE;
				allow_slaac_only = -1;
			} else if (!strcmp(optarg, "none")) {
				ia_na_mode = IA_MODE_NONE;
			} else if (!strcmp(optarg, "try")) {
				ia_na_mode = IA_MODE_TRY;
			} else{
				help = true;
			}
			break;

		case 'P':
			if (allow_slaac_only >= 0 && allow_slaac_only < 10)
				allow_slaac_only = 10;

			request_pd = strtoul(optarg, NULL, 10);
			if (request_pd == 0)
				request_pd = -1;

			ia_pd_mode = IA_MODE_TRY;
			break;

		case 'F':
			allow_slaac_only = -1;
			ia_pd_mode = IA_MODE_FORCE;
			break;

		case 'c':
			l = script_unhexlify(&buf[4], sizeof(buf) - 4, optarg);
			if (l > 0) {
				buf[0] = 0;
				buf[1] = DHCPV6_OPT_CLIENTID;
				buf[2] = 0;
				buf[3] = l;
				odhcp6c_add_state(STATE_CLIENT_ID, buf, l + 4);
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
				odhcp6c_add_state(STATE_ORO, &opttype, 2);
			}
			break;

		case 's':
			script = optarg;
			break;

		case 'k':
			release = false;
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

		default:
			help = true;
			break;
		}
	}

	openlog("odhcp6c", logopt, LOG_DAEMON);
	const char *ifname = argv[optind];

	if (help || !ifname)
		return usage();

	signal(SIGIO, sighandler);
	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGCHLD, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);

	if ((urandom_fd = open("/dev/urandom", O_CLOEXEC | O_RDONLY)) < 0 ||
			init_dhcpv6(ifname, request_pd) || ra_init(ifname, &ifid) ||
			script_init(script, ifname)) {
		syslog(LOG_ERR, "failed to initialize: %s", strerror(errno));
		return 3;
	}

	if (daemonize) {
		openlog("odhcp6c", LOG_PID, LOG_DAEMON); // Disable LOG_PERROR
		if (daemon(0, 0)) {
			syslog(LOG_ERR, "Failed to daemonize: %s",
					strerror(errno));
			return 4;
		}

		char pidbuf[128];
		if (!pidfile) {
			snprintf(pidbuf, sizeof(pidbuf),
					"/var/run/odhcp6c.%s.pid", ifname);
			pidfile = pidbuf;
		}

		int fd = open(pidfile, O_WRONLY | O_CREAT);
		if (fd >= 0) {
			char buf[8];
			int len = snprintf(buf, sizeof(buf), "%i\n", getpid());
			write(fd, buf, len);
			close(fd);
		}
	}

	script_call("started");

	while (do_signal != SIGTERM) { // Main logic
		odhcp6c_clear_state(STATE_SERVER_ID);
		odhcp6c_clear_state(STATE_IA_NA);
		odhcp6c_clear_state(STATE_IA_PD);
		odhcp6c_clear_state(STATE_SNTP_IP);
		odhcp6c_clear_state(STATE_SNTP_FQDN);
		odhcp6c_clear_state(STATE_SIP_IP);
		odhcp6c_clear_state(STATE_SIP_FQDN);
		dhcpv6_set_ia_mode(ia_na_mode, ia_pd_mode);
		bound = false;

		// Server candidates need deep-delete
		size_t cand_len;
		struct dhcpv6_server_cand *cand = odhcp6c_get_state(STATE_SERVER_CAND, &cand_len);
		for (size_t i = 0; i < cand_len / sizeof(*cand); ++i) {
			free(cand[i].ia_na);
			free(cand[i].ia_pd);
		}
		odhcp6c_clear_state(STATE_SERVER_CAND);

		syslog(LOG_NOTICE, "(re)starting transaction on %s", ifname);

		do_signal = 0;
		int res = dhcpv6_request(DHCPV6_MSG_SOLICIT);
		odhcp6c_signal_process();

		if (res < 0) {
			continue; // Might happen if we got a signal
		} else if (res == DHCPV6_STATELESS) { // Stateless mode
			while (do_signal == 0 || do_signal == SIGUSR1) {
				do_signal = 0;

				res = dhcpv6_request(DHCPV6_MSG_INFO_REQ);
				odhcp6c_signal_process();
				if (do_signal == SIGUSR1)
					continue;
				else if (res < 0)
					break;
				else if (res > 0)
					script_call("informed");

				bound = true;
				syslog(LOG_NOTICE, "entering stateless-mode on %s", ifname);

				if (dhcpv6_poll_reconfigure() > 0)
					script_call("informed");
			}

			continue;
		}

		// Stateful mode
		if (dhcpv6_request(DHCPV6_MSG_REQUEST) < 0)
			continue;

		odhcp6c_signal_process();
		script_call("bound");
		bound = true;
		syslog(LOG_NOTICE, "entering stateful-mode on %s", ifname);

		while (do_signal == 0 || do_signal == SIGUSR1) {
			// Renew Cycle
			// Wait for T1 to expire or until we get a reconfigure
			int res = dhcpv6_poll_reconfigure();
			odhcp6c_signal_process();
			if (res >= 0) {
				if (res > 0)
					script_call("updated");

				continue;
			}

			// Handle signal, if necessary
			if (do_signal == SIGUSR1)
				do_signal = 0; // Acknowledged
			else if (do_signal > 0)
				break; // Other signal type

			size_t ia_pd_len, ia_na_len, ia_pd_new, ia_na_new;
			odhcp6c_get_state(STATE_IA_PD, &ia_pd_len);
			odhcp6c_get_state(STATE_IA_NA, &ia_na_len);

			// If we have any IAs, send renew, otherwise request
			int r;
			if (ia_pd_len == 0 && ia_na_len == 0)
				r = dhcpv6_request(DHCPV6_MSG_REQUEST);
			else
				r = dhcpv6_request(DHCPV6_MSG_RENEW);
			odhcp6c_signal_process();
			if (r > 0) // Publish updates
				script_call("updated");
			if (r >= 0)
				continue; // Renew was successful

			odhcp6c_clear_state(STATE_SERVER_ID); // Remove binding

			// If we have IAs, try rebind otherwise restart
			res = dhcpv6_request(DHCPV6_MSG_REBIND);
			odhcp6c_signal_process();

			odhcp6c_get_state(STATE_IA_PD, &ia_pd_new);
			odhcp6c_get_state(STATE_IA_NA, &ia_na_new);
			if (res < 0 || (ia_pd_new == 0 && ia_pd_len) ||
					(ia_na_new == 0 && ia_na_len))
				break; // We lost all our IAs, restart
			else if (res > 0)
				script_call("rebound");
		}


		size_t ia_pd_len, ia_na_len, server_id_len;
		odhcp6c_get_state(STATE_IA_PD, &ia_pd_len);
		odhcp6c_get_state(STATE_IA_NA, &ia_na_len);
		odhcp6c_get_state(STATE_SERVER_ID, &server_id_len);

		// Add all prefixes to lost prefixes
		bound = false;
		script_call("unbound");

		if (server_id_len > 0 && (ia_pd_len > 0 || ia_na_len > 0) && release)
			dhcpv6_request(DHCPV6_MSG_RELEASE);

		odhcp6c_clear_state(STATE_IA_NA);
		odhcp6c_clear_state(STATE_IA_PD);
	}

	script_call("stopped");
	return 0;
}


static int usage(void)
{
	const char buf[] =
	"Usage: odhcp6c [options] <interface>\n"
	"\nFeature options:\n"
	"	-S <time>	Wait at least <time> sec for a DHCP-server (0)\n"
	"	-N <mode>	Mode for requesting addresses [try|force|none]\n"
	"	-P <length>	Request IPv6-Prefix (0 = auto)\n"
	"	-F		Force IPv6-Prefix\n"
	"	-c <clientid>	Override client-ID (base-16 encoded)\n"
	"	-i <iface-id>	Use a custom interface identifier for RA handling\n"
	"	-r <options>	Options to be requested (comma-separated)\n"
	"	-s <script>	Status update script (/usr/sbin/odhcp6c-update)\n"
	"	-k		Don't send a RELEASE when stopping\n"
	"\nInvocation options:\n"
	"	-p <pidfile>	Set pidfile (/var/run/6relayd.pid)\n"
	"	-d		Daemonize\n"
	"	-e		Write logmessages to stderr\n"
	//"	-v		Increase logging verbosity\n"
	"	-h		Show this help\n\n";
	write(STDERR_FILENO, buf, sizeof(buf));
	return 1;
}


// Don't want to pull-in librt and libpthread just for a monotonic clock...
uint64_t odhcp6c_get_milli_time(void)
{
	struct timespec t = {0, 0};
	syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000 + t.tv_nsec / 1000000;
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


bool odhcp6c_signal_process(void)
{
	if (do_signal == SIGIO) {
		do_signal = 0;
		bool ra_updated = ra_process();

		if (ra_updated && (bound || allow_slaac_only == 0))
			script_call("ra-updated"); // Immediate process urgent events
		else if (ra_updated && !bound && allow_slaac_only > 0)
			script_delay_call("ra-updated", allow_slaac_only);
	}

	return do_signal != 0;
}


void odhcp6c_clear_state(enum odhcp6c_state state)
{
	state_len[state] = 0;
}


void odhcp6c_add_state(enum odhcp6c_state state, const void *data, size_t len)
{
	uint8_t *n = odhcp6c_resize_state(state, len);
	if (n)
		memcpy(n, data, len);
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


struct odhcp6c_entry* odhcp6c_find_entry(enum odhcp6c_state state, const struct odhcp6c_entry *new)
{
	size_t len, cmplen = offsetof(struct odhcp6c_entry, target) + new->length / 8;
	struct odhcp6c_entry *start = odhcp6c_get_state(state, &len);
	struct odhcp6c_entry *x = NULL;

	for (struct odhcp6c_entry *c = start; !x && c < &start[len/sizeof(*c)]; ++c)
		if (!memcmp(c, new, cmplen))
			return c;

	return NULL;
}


void odhcp6c_update_entry_safe(enum odhcp6c_state state, struct odhcp6c_entry *new, uint32_t safe)
{
	size_t len;
	struct odhcp6c_entry *x = odhcp6c_find_entry(state, new);
	struct odhcp6c_entry *start = odhcp6c_get_state(state, &len);

	if (x && x->valid > new->valid && new->valid < safe)
		new->valid = safe;

	if (new->valid > 0) {
		if (x) {
			x->valid = new->valid;
			x->preferred = new->preferred;
			x->class = new->class;
		} else {
			odhcp6c_add_state(state, new, sizeof(*new));
		}
	} else if (x) {
		odhcp6c_remove_state(state, (x - start) * sizeof(*x), sizeof(*x));
	}
}


void odhcp6c_update_entry(enum odhcp6c_state state, struct odhcp6c_entry *new)
{
	odhcp6c_update_entry_safe(state, new, 0);
}


static void odhcp6c_expire_list(enum odhcp6c_state state, uint32_t elapsed)
{
	size_t len;
	struct odhcp6c_entry *start = odhcp6c_get_state(state, &len);
	for (struct odhcp6c_entry *c = start; c < &start[len / sizeof(*c)]; ++c) {
		if (c->preferred < elapsed)
			c->preferred = 0;
		else if (c->preferred != UINT32_MAX)
			c->preferred -= elapsed;

		if (c->valid < elapsed)
			c->valid = 0;
		else if (c->valid != UINT32_MAX)
			c->valid -= elapsed;

		if (!c->valid)
			odhcp6c_remove_state(state, (c - start) * sizeof(*c), sizeof(*c));
	}
}


void odhcp6c_expire(void)
{
	time_t now = odhcp6c_get_milli_time() / 1000;
	uint32_t elapsed = (last_update > 0) ? now - last_update : 0;
	last_update = now;

	odhcp6c_expire_list(STATE_RA_PREFIX, elapsed);
	odhcp6c_expire_list(STATE_RA_ROUTE, elapsed);
	odhcp6c_expire_list(STATE_RA_DNS, elapsed);
	odhcp6c_expire_list(STATE_IA_NA, elapsed);
	odhcp6c_expire_list(STATE_IA_PD, elapsed);
}


uint32_t odhcp6c_elapsed(void)
{
	return odhcp6c_get_milli_time() / 1000 - last_update;
}


void odhcp6c_random(void *buf, size_t len)
{
	read(urandom_fd, buf, len);
}


static void sighandler(int signal)
{
	if (signal == SIGCHLD)
		while (waitpid(-1, NULL, WNOHANG) > 0);
	else if (signal == SIGUSR1)
		do_signal = SIGUSR1;
	else if (signal == SIGUSR2)
		do_signal = SIGUSR2;
	else if (signal == SIGIO)
		do_signal = SIGIO;
	else
		do_signal = SIGTERM;
}
