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


/* $Header: /home/cvs/httpd-ftp/providers/default/mod_ftpd_default.c,v 1.4 2004/03/05 04:09:06 urkle Exp $ */
#include "httpd.h"
#include "http_config.h"
#include "apr_strings.h"
#include "apr_global_mutex.h"
#include "apr_shm.h"
#include "http_log.h"
#include "ap_provider.h"

#include "mod_ftpd.h"

typedef struct {
	int counter;
} ftpd_default_counter_rec;

/* per server configuration */
typedef struct {
	const char *chroot_path;
	int maxlogins;
	int server_offset;
} ftpd_default_server_conf;

static apr_shm_t *ftpd_counter_shm;
static ftpd_default_counter_rec *ftpd_counter;
static char *ftpd_global_mutex_file;
static apr_global_mutex_t *ftpd_global_mutex;
static int server_count;

#define MOD_FTPD_DEFAULT_SHMEM_CACHE "/tmp/mod_ftpd_default"

module AP_MODULE_DECLARE_DATA ftpd_default_module;

/* Apache config process */
static void *ftpd_default_create_server_config(apr_pool_t *p, server_rec *s)
{
	ftpd_default_server_conf *pConfig = apr_pcalloc(p, sizeof(ftpd_default_server_conf));
	pConfig->maxlogins = 20;
	return pConfig;
}

static apr_status_t ftpd_cleanup_shm(void *data)
{
	if (ftpd_counter_shm) {
		apr_shm_destroy(ftpd_counter_shm);
		ftpd_counter_shm = NULL;
	}
	return APR_SUCCESS;
}

static apr_status_t ftpd_cleanup_locks(void *data)
{
	apr_status_t rv = APR_SUCCESS;
	if (ftpd_global_mutex) {
		rv = apr_global_mutex_destroy(ftpd_global_mutex);
	}
	return rv;
}

static int ftpd_default_post_conf(apr_pool_t *p, apr_pool_t *log, apr_pool_t *temp,
								server_rec *s)
{
	apr_status_t rv;
	/*int server_count = 0;*/
	server_rec *cur_s;
	void *data = NULL;
	const char *userdata_key = "ftpd_default_post_config";

	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (data == NULL) {
		apr_pool_userdata_set((const void *)1, userdata_key,
			apr_pool_cleanup_null, s->process->pool);
		return OK;
	}
	if (!ftpd_global_mutex_file)
		ftpd_global_mutex_file = "mod_ftpd_default.tmp.lock";

	rv = apr_global_mutex_create(&ftpd_global_mutex, ftpd_global_mutex_file,
			APR_LOCK_DEFAULT, p);
	if (rv != APR_SUCCESS) {
		ap_log_perror(APLOG_MARK, APLOG_EMERG, 0, log,
			"[mod_ftpd_default.c] - Failed creating global lock mutex! apr_global_mutex_create returned: (%d)", rv);
		return rv;
	}
	apr_pool_cleanup_register(p, NULL, ftpd_cleanup_locks, apr_pool_cleanup_null);
	for (cur_s = s; cur_s; cur_s = cur_s->next) {
		ftpd_default_server_conf *pConfig = ap_get_module_config(
						cur_s->module_config, &ftpd_default_module);
		pConfig->server_offset = server_count;
		server_count++;
	}

	/*rv = apr_shm_create(&ftpd_counter_shm, sizeof(ftpd_default_counter_rec)*server_count,
			MOD_FTPD_DEFAULT_SHMEM_CACHE, p);
	if (rv == APR_EEXIST) {
		ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, log,
			"[mod_ftpd_default.c] - shm already exists: reconnecting: %d", rv);
		rv = apr_shm_attach(&ftpd_counter_shm, MOD_FTPD_DEFAULT_SHMEM_CACHE, p);
		if (rv == APR_SUCCESS) {
			rv = apr_shm_destroy(ftpd_counter_shm);
			ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, log,
				"[mod_ftpd_default.c] - shm connected: destroed: %d", rv);
		}
		rv = apr_shm_create(&ftpd_counter_shm, sizeof(ftpd_default_counter_rec)*server_count,
			MOD_FTPD_DEFAULT_SHMEM_CACHE, p);
	}
	if (rv != APR_SUCCESS) {
		return rv;
	}
	ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, log,
		"[mod_ftpd_default.c] - shm created: %d", rv);
	apr_pool_cleanup_register(p, NULL, ftpd_cleanup_shm, apr_pool_cleanup_null);*/
	return OK;
}

static void ftpd_default_init_child(apr_pool_t *pchild, server_rec *s)
{
	apr_status_t rv;
	rv = apr_global_mutex_child_init(&ftpd_global_mutex,
			ftpd_global_mutex_file, pchild);
	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			"Error attaching to global mutex: %d", rv);
		return;
	}
	rv = apr_shm_create(&ftpd_counter_shm, sizeof(ftpd_default_counter_rec)*server_count,
			MOD_FTPD_DEFAULT_SHMEM_CACHE, pchild);
	if (rv == APR_EEXIST) {
		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
			"shm already exists: reconnecting: %d", rv);
		rv = apr_shm_attach(&ftpd_counter_shm, MOD_FTPD_DEFAULT_SHMEM_CACHE, pchild);
	}
	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			"Error attaching to shared memory: %d", rv);
		return;
	}
	apr_pool_cleanup_register(pchild, NULL, ftpd_cleanup_shm, apr_pool_cleanup_null);
	ftpd_counter = apr_shm_baseaddr_get(ftpd_counter_shm);
}

static const char * ftpd_default_cmd_chrootpath(cmd_parms *cmd, void *config,
									 const char *arg)
{
	ftpd_default_server_conf *conf = ap_get_module_config(cmd->server->module_config,
									&ftpd_default_module);
	conf->chroot_path = apr_pstrdup(cmd->pool, arg);

	return NULL;
}

static const char * ftpd_default_cmd_maxlogins(cmd_parms *cmd, void *config,
									const char *arg)
{
	ftpd_default_server_conf *conf = ap_get_module_config(cmd->server->module_config,
									&ftpd_default_module);
    const char *err = ap_check_cmd_context(cmd,NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) {
		return err;
	}

	conf->maxlogins = apr_atoi64(arg);
	if (conf->maxlogins < 1) {
		return apr_psprintf(cmd->pool, "%s must be greater than 0",cmd->cmd->name);
	}

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

static ftpd_limit_status_t ftpd_default_limit_check(const request_rec *r, 
											ftpd_limit_check_t check_type)
{
	ftpd_default_server_conf *pConfig = ap_get_module_config(r->server->module_config,
										&ftpd_default_module);
	apr_global_mutex_lock(ftpd_global_mutex);
	switch (check_type) {
	case FTPD_LIMIT_CHECK:
		if (ftpd_counter[pConfig->server_offset].counter >= pConfig->maxlogins)
			return FTPD_LIMIT_TOOMANY;
		break;
	case FTPD_LIMIT_CHECKIN:
		ftpd_counter[pConfig->server_offset].counter++;
		break;
	case FTPD_LIMIT_CHECKOUT:
		ftpd_counter[pConfig->server_offset].counter--;
		break;
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		"Login count: %d", ftpd_counter[pConfig->server_offset].counter);
	apr_global_mutex_unlock(ftpd_global_mutex);
	return check_type==FTPD_LIMIT_CHECK?FTPD_LIMIT_ALLOW:FTPD_LIMIT_DEFAULT;
}

/* Module initialization structures */

static const ftpd_provider ftpd_default_provider =
{
	ftpd_default_map_chroot,	/* map_chroot */
	ftpd_default_limit_check	/* limit_checkin */
};

static const command_rec ftpd_default_cmds[] = {
	AP_INIT_TAKE1("FtpDefaultChroot", ftpd_default_cmd_chrootpath, NULL, RSRC_CONF,
                 "Path to set the chroot to."),
	AP_INIT_TAKE1("FtpDefaultMaxLogins", ftpd_default_cmd_maxlogins, NULL, RSRC_CONF,
				"Maximum number of logins to the FTP server. The Default is 20."),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
	ap_hook_post_config(ftpd_default_post_conf, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init(ftpd_default_init_child, NULL, NULL, APR_HOOK_MIDDLE);
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
