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
 * Pure codec and validation layer for the privilege-separation IPC request
 * datagram (see the wire-format documentation in script.h). Everything here is
 * side-effect free: no sockets, no fork/exec, no mutable globals, no client
 * state. The worker calls script_req_encode() to serialize a request; the
 * privileged monitor calls script_req_decode() to validate and re-sanitize one
 * before it ever runs the script. Keeping these as pure functions makes the
 * root-side parser unit-testable and fuzzable in isolation (see tools/fuzz).
 *
 * The action allow-list and the per-entry environment sanitizer live here too:
 * both are part of "is this datagram acceptable?", so co-locating them keeps the
 * decision in one auditable place that the fuzz target exercises directly.
 */

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "odhcp6c.h"
#include "script.h"
#include "script_internal.h"

/*
 * The exact set of actions odhcp6c emits today (from the notify_state_change()
 * call sites). The monitor only ever runs the script with one of these; any
 * other action from the worker is rejected.
 */
static const char *const script_actions[] = {
	"started", "bound", "informed", "ra-updated",
	"updated", "rebound", "unbound", "stopped",
};

static bool script_action_allowed(const char *act, size_t len)
{
	if (len == 0 || len > SCRIPT_ACTION_MAX)
		return false;

	for (size_t i = 0; i < sizeof(script_actions) / sizeof(script_actions[0]); i++) {
		if (strlen(script_actions[i]) == len &&
				!memcmp(script_actions[i], act, len))
			return true;
	}

	return false;
}

/*
 * Prepare an already-assembled "NAME=value" buffer that originates from
 * untrusted network input before it is exported to the environment of the
 * (root) status script.
 *
 * The variable NAME (the bytes before the first '=') is validated, not
 * rewritten. It is only accepted if it is a non-empty run of the portable
 * environment-variable charset ([A-Za-z_][A-Za-z0-9_]*). Silently rewriting an
 * invalid name could map a value onto an unexpected variable, so a missing or
 * invalid name causes the whole entry to be rejected: the function returns
 * false and the caller must not putenv() it. Rejecting a single entry (rather
 * than aborting the process) avoids handing an attacker a denial-of-service
 * trigger. The names used in this file are compile-time constants, so this is
 * defense in depth against future call sites.
 *
 * The value (the bytes after the first '=') is sanitized in place. DHCPv6
 * replies and ICMPv6 Router Advertisements are attacker-controlled, so option
 * payloads may contain newlines or other non-printable bytes. Any byte that is
 * not printable ASCII, or that could trigger shell quoting/expansion, is
 * replaced with '_'. This cannot remove embedded NUL bytes (they already
 * terminate the C string) and does not by itself guarantee shell-safety: the
 * consuming script must still quote variables.
 *
 * Returns true if the entry is safe to export, false if it must be discarded.
 */
bool script_sanitize_env(char *env)
{
	char *p = strchr(env, '=');

	/* A well-formed entry must have a non-empty NAME before the '='. */
	if (p == NULL || p == env)
		return false;

	/* Validate the NAME without modifying it. */
	for (char *n = env; n < p; n++) {
		unsigned char c = (unsigned char)*n;

		if (c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
			continue;
		/* Digits are allowed, but not as the first character. */
		if (n != env && c >= '0' && c <= '9')
			continue;

		return false;
	}

	/* Sanitize the value portion in place. */
	for (p++; *p; p++) {
		unsigned char c = (unsigned char)*p;

		/* Reject non-printable and non-ASCII bytes */
		if (c < 0x20 || c > 0x7e) {
			*p = '_';
			continue;
		}

		/* Reject shell-significant characters */
		switch (c) {
		case '`': case '$': case '\\': case '"': case '\'':
			*p = '_';
			break;
		default:
			/* Replace whitespace other than a single regular space */
			if (c != ' ' && isspace(c))
				*p = '_';
			break;
		}
	}

	return true;
}

const char *script_req_strerror(int reason)
{
	switch (reason) {
	case SCRIPT_REQ_OK:			return "ok";
	case SCRIPT_REQ_ERR_SHORT:		return "datagram shorter than header";
	case SCRIPT_REQ_ERR_MAGIC:		return "bad magic";
	case SCRIPT_REQ_ERR_PADDING:		return "non-zero padding";
	case SCRIPT_REQ_ERR_RESUME:		return "invalid resume value";
	case SCRIPT_REQ_ERR_CAPS:		return "length field exceeds hard cap";
	case SCRIPT_REQ_ERR_SIZE:		return "size inconsistent with declared layout";
	case SCRIPT_REQ_ERR_ACTION:		return "unknown action";
	case SCRIPT_REQ_ERR_ENV_UNTERMINATED:	return "unterminated env entry";
	case SCRIPT_REQ_ERR_ENV_INVALID:	return "invalid env entry";
	case SCRIPT_REQ_ERR_ENV_TRAILING:	return "trailing env bytes";
	case SCRIPT_REQ_ERR_ENV_CAP:		return "too many env entries for buffer";
	default:				return "unknown reason";
	}
}

ssize_t script_req_encode(uint8_t *out, size_t outcap,
		const char *action, int delay, bool resume,
		char *const *env, size_t envc)
{
	size_t action_len = strlen(action);

	if (action_len > SCRIPT_ACTION_MAX)
		action_len = SCRIPT_ACTION_MAX;

	size_t env_total = 0;
	for (size_t i = 0; i < envc; i++)
		env_total += strlen(env[i]) + 1;

	size_t msg_len = sizeof(struct script_req) + action_len + env_total;

	if (!out || msg_len > outcap)
		return -1;

	struct script_req req = {
		.magic = SCRIPT_REQ_MAGIC,
		.action_len = action_len,
		.delay = delay,
		.resume = resume ? 1 : 0,
		.env_count = envc,
		.env_total = env_total,
	};

	uint8_t *p = out;

	memcpy(p, &req, sizeof(req));
	p += sizeof(req);
	memcpy(p, action, action_len);
	p += action_len;

	for (size_t i = 0; i < envc; i++) {
		size_t l = strlen(env[i]) + 1;

		memcpy(p, env[i], l);
		p += l;
	}

	return (ssize_t)msg_len;
}

int script_req_decode(uint8_t *buf, size_t len,
		struct script_req *out_hdr, char action[SCRIPT_ACTION_MAX + 1],
		char **env_out, size_t env_cap, size_t *env_count_out)
{
	struct script_req req;

	*env_count_out = 0;

	if (len < sizeof(req))
		return SCRIPT_REQ_ERR_SHORT;

	memcpy(&req, buf, sizeof(req));

	if (req.magic != SCRIPT_REQ_MAGIC)
		return SCRIPT_REQ_ERR_MAGIC;

	if (req.pad[0] || req.pad[1] || req.pad[2])
		return SCRIPT_REQ_ERR_PADDING;

	/* resume is a boolean in the IPC contract; reject anything but 0/1. */
	if (req.resume > 1)
		return SCRIPT_REQ_ERR_RESUME;

	if (req.action_len > SCRIPT_ACTION_MAX ||
			req.env_count > SCRIPT_ENV_MAX_COUNT ||
			req.env_total > SCRIPT_ENV_MAX_TOTAL)
		return SCRIPT_REQ_ERR_CAPS;

	/* The datagram size must match the declared layout exactly. */
	if (len != sizeof(req) + req.action_len + req.env_total)
		return SCRIPT_REQ_ERR_SIZE;

	if (req.env_count > env_cap)
		return SCRIPT_REQ_ERR_ENV_CAP;

	char action_buf[SCRIPT_ACTION_MAX + 1];
	memcpy(action_buf, buf + sizeof(req), req.action_len);
	action_buf[req.action_len] = '\0';

	if (!script_action_allowed(action_buf, req.action_len))
		return SCRIPT_REQ_ERR_ACTION;

	uint8_t *env = buf + sizeof(req) + req.action_len;
	uint8_t *eend = env + req.env_total;
	uint8_t *p = env;
	size_t envc = 0;

	for (size_t i = 0; i < req.env_count; i++) {
		uint8_t *nul = memchr(p, '\0', (size_t)(eend - p));

		if (!nul)
			return SCRIPT_REQ_ERR_ENV_UNTERMINATED;

		char *entry = (char *)p;

		/* Re-apply the sanitizer; reject on invalid NAME. */
		if (!script_sanitize_env(entry))
			return SCRIPT_REQ_ERR_ENV_INVALID;

		env_out[envc++] = entry;
		p = nul + 1;
	}

	/* Every declared byte must be consumed by exactly env_count entries. */
	if (envc != req.env_count || p != eend)
		return SCRIPT_REQ_ERR_ENV_TRAILING;

	*out_hdr = req;
	*env_count_out = envc;
	memcpy(action, action_buf, req.action_len + 1);

	return SCRIPT_REQ_OK;
}
