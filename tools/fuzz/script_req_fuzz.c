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
 * libFuzzer harness for the privileged-side request parser, script_req_decode().
 * The monitor runs as root and parses datagrams produced by the unprivileged,
 * network-facing worker, so this parser must never crash, over-read or accept a
 * malformed datagram. The codec is pure (no sockets/fork/exec/globals), so the
 * fuzzer links only src/script_codec.c plus this file -- nothing from the daemon.
 *
 * Build & run (see tools/fuzz/README.md):
 *   CC=clang cmake -S . -B build-fuzz -DFUZZING=ON
 *   cmake --build build-fuzz --target script_req_fuzz
 *   ./build-fuzz/script_req_fuzz tools/fuzz/corpus
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "script.h"
#include "script_internal.h"

/*
 * The codec is pure: script_req_decode() only validates and returns a reason
 * code, it does not log (the monitor wrapper logs the reason). So the fuzz
 * target needs no logging sink and links against nothing from the daemon -- it
 * is just src/script_codec.c plus this harness.
 */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/*
	 * script_req_decode() re-sanitizes each env entry in place, so it needs
	 * a writable buffer. libFuzzer's input is conceptually const, so copy it.
	 */
	uint8_t *buf = malloc(size ? size : 1);

	if (!buf)
		return 0;

	memcpy(buf, data, size);

	struct script_req hdr;
	char action[SCRIPT_ACTION_MAX + 1];
	char *env[SCRIPT_ENV_MAX_COUNT];
	size_t n = 0;

	(void)script_req_decode(buf, size, &hdr, action, env,
			SCRIPT_ENV_MAX_COUNT, &n);

	free(buf);
	return 0;
}
