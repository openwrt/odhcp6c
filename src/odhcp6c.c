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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>

#include <net/if.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include "odhcp6c.h"


static void sighandler(int signal);
static int usage(void);


static uint8_t *state_data[_STATE_MAX] = {NULL};
static size_t state_len[_STATE_MAX] = {0};

static volatile int do_signal = 0;


int main(_unused int argc, char* const argv[])
{
	openlog("odhcp6c", LOG_PERROR | LOG_PID, LOG_DAEMON);

	// Allocate ressources
	const char *pidfile = NULL;
	const char *script = "/usr/sbin/odhcp6c-update";
	ssize_t l;
	uint8_t buf[134];
	char *optpos;
	uint16_t opttype;
	enum odhcp6c_ia_mode ia_na_mode = IA_MODE_TRY;

	bool help = false, daemonize = false;
	int c, request_pd = 0, timeout = 0;
	while ((c = getopt(argc, argv, "N:P:c:r:s:t:hdp:")) != -1) {
		switch (c) {
		case 'N':
			if (!strcmp(optarg, "force"))
				ia_na_mode = IA_MODE_FORCE;
			else if (!strcmp(optarg, "none"))
				ia_na_mode = IA_MODE_NONE;
			else if (!strcmp(optarg, "try"))
				ia_na_mode = IA_MODE_TRY;
			else
				help = true;
			break;

		case 'P':
			request_pd = strtoul(optarg, NULL, 10);
			if (request_pd == 0)
				request_pd = -1;
			break;

		case 'c':
			l = script_unhexlify(&buf[4], sizeof(buf) - 4, optarg);
			if (l > 0) {
				buf[0] = 0;
				buf[1] = DHCPV6_OPT_CLIENTID;
				buf[2] = 0;
				buf[4] = l;
				odhcp6c_add_state(STATE_CLIENT_ID, buf, l + 4);
			} else {
				help = true;
			}
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

		case 't':
			timeout = strtoul(optarg, NULL, 10);
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

	const char *ifname = argv[optind];

	if (help || !ifname)
		return usage();

	if (init_dhcpv6(ifname, request_pd) || init_rtnetlink() ||
			script_init(script, ifname)) {
		syslog(LOG_ERR, "failed to initialize: %s", strerror(errno));
		return 3;
	}

	signal(SIGHUP, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGALRM, sighandler);
	signal(SIGCHLD, sighandler);
	signal(SIGTERM, sighandler);
	signal(SIGUSR1, sighandler);
	signal(SIGUSR2, sighandler);

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
		odhcp6c_clear_state(STATE_SERVER_CAND);
		odhcp6c_clear_state(STATE_IA_PD);
		odhcp6c_clear_state(STATE_SNTP_IP);
		odhcp6c_clear_state(STATE_SNTP_FQDN);
		odhcp6c_clear_state(STATE_SIP_IP);
		odhcp6c_clear_state(STATE_SIP_FQDN);
		dhcpv6_set_ia_na_mode(ia_na_mode);

		alarm(timeout);
		do_signal = 0;
		int res = dhcpv6_request(DHCPV6_MSG_SOLICIT);

		if (res < 0) {
			continue; // Might happen if we got a signal
		} else if (res == DHCPV6_STATELESS) { // Stateless mode
			while (do_signal == 0 || do_signal == SIGUSR1) {
				do_signal = 0;

				res = dhcpv6_request(DHCPV6_MSG_INFO_REQ);
				if (do_signal == SIGUSR1)
					continue;
				else if (res < 0)
					break;
				else if (res > 0)
					script_call("informed");

				alarm(0);
				if (dhcpv6_poll_reconfigure() > 0)
					script_call("informed");
			}

			if (do_signal == SIGALRM)
				script_call("timeout");

			continue;
		}

		// Stateful mode
		if (dhcpv6_request(DHCPV6_MSG_REQUEST) < 0)
			continue;

		script_call("bound");
		alarm(0);

		while (do_signal == 0 || do_signal == SIGUSR1) {
			// Renew Cycle
			// Wait for T1 to expire or until we get a reconfigure
			int res = dhcpv6_poll_reconfigure();
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
			if (r > 0) // Publish updates
				script_call("updated");
			if (r >= 0)
				continue; // Renew was successful

			odhcp6c_clear_state(STATE_SERVER_ID); // Remove binding

			// If we have IAs, try rebind otherwise restart
			res = dhcpv6_request(DHCPV6_MSG_REBIND);

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
		odhcp6c_clear_state(STATE_IA_PD);

		if (do_signal == SIGALRM)
			script_call("timeout");
		else
			script_call("unbound");

		// Remove assigned addresses
		if (ia_na_len > 0)
			dhcpv6_remove_addrs();

		if (server_id_len > 0 && (ia_pd_len > 0 || ia_na_len > 0))
			dhcpv6_request(DHCPV6_MSG_RELEASE);
	}

	script_call("stopped");
	return 0;
}


static int usage(void)
{
	const char buf[] =
	"Usage: odhcp6c [options] <interface>\n"
	"\nFeature options:\n"
	"	-N <mode>	Mode for requesting addresses [try|force|none]\n"
	"	-P <length>	Request IPv6-Prefix (0 = auto)\n"
	"	-c <clientid>	Override client-ID (base-16 encoded)\n"
	"	-r <options>	Options to be requested (comma-separated)\n"
	"	-s <script>	Status update script (/usr/sbin/odhcp6c-update)\n"
	"	-t <timeout>	Request timeout after which the script is called\n"
	"\nInvocation options:\n"
	"	-p <pidfile>	Set pidfile (/var/run/6relayd.pid)\n"
	"	-d		Daemonize\n"
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

	uint8_t *n = realloc(state_data[state], state_len[state] + len);
	if (n || state_len[state] + len == 0) {
		state_data[state] = n;
		n += state_len[state];
		state_len[state] += len;
	}
	return n;
}


bool odhcp6c_signal_is_pending(void)
{
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


bool odhcp6c_commit_state(enum odhcp6c_state state, size_t old_len)
{
	size_t new_len = state_len[state] - old_len;
	uint8_t *old_data = state_data[state], *new_data = old_data + old_len;
	bool upd = new_len != old_len || memcmp(old_data, new_data, new_len);

	memmove(old_data, new_data, new_len);
	odhcp6c_resize_state(state, -old_len);

	return upd;
}


void* odhcp6c_get_state(enum odhcp6c_state state, size_t *len)
{
	*len = state_len[state];
	return state_data[state];
}


static void sighandler(int signal)
{
	if (signal == SIGCHLD)
		while (waitpid(-1, NULL, WNOHANG) > 0);
	else if (signal == SIGUSR1)
		do_signal = SIGUSR1;
	else if (signal == SIGUSR2)
		do_signal = SIGUSR2;
	else if (signal == SIGALRM)
		do_signal = SIGALRM;
	else
		do_signal = SIGTERM;
}
