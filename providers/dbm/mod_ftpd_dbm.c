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
#include "apr_strings.h"
#include "apr_dbm.h"
#include "http_log.h"
#include "ap_provider.h"

#include "mod_ftpd.h"

/* per server configuration */
typedef struct {
	const char *chrootdb_path;
	const char *dbtype;
} ftpd_dbm_server_conf;

module AP_MODULE_DECLARE_DATA ftpd_dbm_module;

/* Apache config process */
static void *ftpd_dbm_create_server_config(apr_pool_t *p, server_rec *s)
{
	ftpd_dbm_server_conf *pConfig = apr_pcalloc(p, sizeof(ftpd_dbm_server_conf));
	pConfig->dbtype = "default";
	return pConfig;
}

static const char * ftpd_dbm_cmd_dbmpath(cmd_parms *cmd, void *config,
									 const char *arg)
{
	ftpd_dbm_server_conf *conf = ap_get_module_config(cmd->server->module_config,
									&ftpd_dbm_module);
	conf->chrootdb_path = ap_server_root_relative(cmd->pool, arg);

	if (!conf->chrootdb_path) {
		return apr_pstrcat(cmd->pool, "Invalid FTPChrootDBM: ", arg, NULL);
	}

	return NULL;
}

static const char * ftpd_dbm_cmd_dbmtype(cmd_parms *cmd, void *config,
									 const char *arg)
{
	ftpd_dbm_server_conf *conf = ap_get_module_config(cmd->server->module_config,
									&ftpd_dbm_module);
	conf->dbtype = apr_pstrdup(cmd->pool, arg);
	if (apr_strnatcmp(conf->dbtype, "default") &&
			apr_strnatcmp(conf->dbtype, "DB") &&
			apr_strnatcmp(conf->dbtype, "GDBM") &&
			apr_strnatcmp(conf->dbtype, "SDBM") &&
			apr_strnatcmp(conf->dbtype, "NDBM")) {
		return apr_pstrcat(cmd->pool, "Invalid FTPChrootDBMType: ", arg, NULL);
	}
	return NULL;
}

static ftpd_chroot_status_t ftpd_dbm_map_chroot(const request_rec *r,
										const char **chroot,
										const char **initroot)
{
	apr_status_t res;
	apr_dbm_t *file;
	ftpd_chroot_status_t ret = FTPD_CHROOT_USER_NOT_FOUND;
	apr_datum_t key,val = { 0 };
	char *value, *tok, *tok_ses;
	ftpd_user_rec *ur  __attribute__ ((unused))= ftpd_get_user_rec(r);
	ftpd_dbm_server_conf *pConfig = ap_get_module_config(r->server->module_config,
										&ftpd_dbm_module);

	if ((res = apr_dbm_open_ex(&file, pConfig->dbtype, pConfig->chrootdb_path,
								APR_DBM_READONLY, APR_OS_DEFAULT, r->pool))
								!= APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r,
			"Error opening DBM file: %s",pConfig->chrootdb_path);
		ret = FTPD_CHROOT_FAIL;
	} else {
		if (file != NULL) {
			/* search the DB */
			key.dptr = r->user;
			key.dsize = strlen(key.dptr);

			if (apr_dbm_exists(file, key)) {
				if (apr_dbm_fetch(file, key, &val) == APR_SUCCESS) {
					value = apr_pstrndup(r->pool, val.dptr, val.dsize);
					tok = apr_strtok(value, ":", &tok_ses);
					if (tok != NULL) {
						*chroot = apr_pstrdup(r->pool, tok);
						tok = apr_strtok(NULL, ":", &tok_ses);
						if (tok != NULL) {
							*initroot = apr_pstrdup(r->pool, tok);
						}
						ret = FTPD_CHROOT_USER_FOUND;
					} else {
						ret = FTPD_CHROOT_FAIL;
					}
				}
			}

			apr_dbm_close(file);
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"File open failed: %s",pConfig->chrootdb_path);
			ret = FTPD_CHROOT_FAIL;
		}
	}
	return ret;
}

/* Module initialization structures */

static const ftpd_provider ftpd_dbm_provider =
{
	ftpd_dbm_map_chroot,		/* map_chroot */
	NULL
};

static const command_rec ftpd_dbm_cmds[] = {
	AP_INIT_TAKE1("FtpDBMFile", ftpd_dbm_cmd_dbmpath, NULL, RSRC_CONF,
                 "Path to Database to use chroot mapping."),
	AP_INIT_TAKE1("FtpDBMType", ftpd_dbm_cmd_dbmtype, NULL, RSRC_CONF,
                 "What type of DBM file to open. default, DB,GDBM,NDBM, SDBM."),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
	ap_register_provider(p, FTPD_PROVIDER_GROUP, "dbm","0",
		&ftpd_dbm_provider);
}

module AP_MODULE_DECLARE_DATA ftpd_dbm_module = {
	STANDARD20_MODULE_STUFF,
    NULL,                          /* create per-directory config structure */
    NULL,                          /* merge per-directory config structures */
    ftpd_dbm_create_server_config,  /* create per-server config structure */
    NULL,                          /* merge per-server config structures */
    ftpd_dbm_cmds,                  /* command apr_table_t */
    register_hooks                 /* register hooks */
};
