/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2002 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */


#include "httpd.h"
#include "http_config.h"
#include "apr_strings.h"
#include "http_log.h"
#include "ap_provider.h"

#include "mod_ftpd.h"

/* per server configuration */
typedef struct {
	const char *chroot_path;
} ftpd_default_server_conf;

module AP_MODULE_DECLARE_DATA ftpd_default_module;

/* Apache config process */
static void *ftpd_default_create_server_config(apr_pool_t *p, server_rec *s)
{
	ftpd_default_server_conf *pConfig = apr_pcalloc(p, sizeof(ftpd_default_server_conf));
	return pConfig;
}

static const char * ftpd_default_cmd_chrootpath(cmd_parms *cmd, void *config,
									 const char *arg)
{
	ftpd_default_server_conf *conf = ap_get_module_config(cmd->server->module_config,
									&ftpd_default_module);
	conf->chroot_path = apr_pstrdup(cmd->pool, arg);

	return NULL;
}

static ftpd_chroot_status_t ftpd_default_map_chroot(const request_rec *r,
										const char **chroot,
										const char **initroot)
{
	ftpd_default_server_conf *pConfig = ap_get_module_config(r->server->module_config,
										&ftpd_default_module);
	*chroot = apr_pstrdup(r->pool, pConfig->chroot_path);

	return FTPD_CHROOT_USER_FOUND;
}

/* Module initialization structures */
static const ftpd_hooks_chroot ftpd_hooks_chroot_default =
{
	ftpd_default_map_chroot		/* map_chroot */
};

static const ftpd_provider ftpd_default_provider =
{
	&ftpd_hooks_chroot_default,		/* chroot */
	NULL		/* listing */
};

static const command_rec ftpd_default_cmds[] = {
	AP_INIT_TAKE1("FTPChrootPath", ftpd_default_cmd_chrootpath, NULL, RSRC_CONF,
                 "Path to Database to use chroot mapping."),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
	ap_register_provider(p, FTPD_PROVIDER_GROUP, "default", "0",
		&ftpd_default_provider);
}

module AP_MODULE_DECLARE_DATA ftpd_default_module = {
	STANDARD20_MODULE_STUFF,
    NULL,                          /* create per-directory config structure */
    NULL,                          /* merge per-directory config structures */
    ftpd_default_create_server_config,  /* create per-server config structure */
    NULL,                          /* merge per-server config structures */
    ftpd_default_cmds,                  /* command apr_table_t */
    register_hooks                 /* register hooks */
};
