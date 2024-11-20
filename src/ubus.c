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


#include <sys/types.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <stdio.h>
#include <syslog.h>
#include <inttypes.h>
#include <libubus.h>
#include <libubox/blobmsg.h>

#include "ubus.h"

struct ubus_context *ubus = NULL;
static char ubus_name[24];

static int ubus_handle_get_state(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method, struct blob_attr *msg);

static struct ubus_object_type odhcp6c_object_type = {
	.name = "odhcp6c"
};

static struct ubus_object odhcp6c_object = {
	.name = NULL,
	.type = &odhcp6c_object_type,
	.methods = odhcp6c_object_methods,
	.n_methods = ARRAY_SIZE(odhcp6c_object_methods),
};

static void ubus_disconnect_cb(struct ubus_context *ubus)
{
	int ret;

	ret = ubus_reconnect(ubus, NULL);
	if (ret) {
		syslog(LOG_ERR, "Cannot reconnect to ubus: %s", ubus_strerror(ret));
		ubus_destroy(ubus);
	}
}

char *ubus_init(const char* interface) 
{
	int ret = 0;

 	if (!(ubus = ubus_connect(NULL)))
		return NULL;

	snprintf(ubus_name, 24, "odhcp6c.%s", interface);
	odhcp6c_object.name = ubus_name;
	
	ret = ubus_add_object(ubus, &odhcp6c_object);
	if (ret) {
		ubus_destroy(ubus);
		return (char *)ubus_strerror(ret);
	}

	ubus->connection_lost = ubus_disconnect_cb;
	return NULL;
}

struct ubus_context *ubus_get_ctx(void)
{
	return ubus;
}

void ubus_destroy(struct ubus_context *ubus)
{
	syslog(LOG_NOTICE, "Disconnecting from ubus");
	
	if (ubus != NULL)
		ubus_free(ubus);
	ubus = NULL;

	/* Forces re-initialization when we're reusing the same definitions later on. */
	odhcp6c_object.id = 0;
	odhcp6c_object.id = 0;
}
