/* $Id$ */
/* Copyright 2003-2004 Edward Rudd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "ap_provider.h"

#include "mod_ftpd.h"

module AP_MODULE_DECLARE_DATA ftpd_fail_module;

static ftpd_chroot_status_t ftpd_fail_map_chroot(const request_rec *r,
					const char **chroot,
					const char **initroot)
{
	return FTPD_CHROOT_FAIL;
}

/* Module initialization structures */

static const ftpd_provider ftpd_fail_provider =
{
	ftpd_fail_map_chroot,		/* map_chroot */
	NULL
};

static void register_hooks(apr_pool_t *p)
{
	ap_register_provider(p, FTPD_PROVIDER_GROUP, "fail", "0",
		&ftpd_fail_provider);
}

module AP_MODULE_DECLARE_DATA ftpd_fail_module = {
	STANDARD20_MODULE_STUFF,
    NULL,                          /* create per-directory config structure */
    NULL,                          /* merge per-directory config structures */
    NULL,  						   /* create per-server config structure */
    NULL,                          /* merge per-server config structures */
    NULL,                  		   /* command apr_table_t */
    register_hooks                 /* register hooks */
};
