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
#include "apr_dbm.h"
#include "http_log.h"
#include "ap_provider.h"

#include "mod_ftp.h"

/* per server configuration */
typedef struct {
	const char *chrootdb_path;
	const char *dbtype;
} ftp_dbm_server_conf;

module AP_MODULE_DECLARE_DATA ftp_dbm_module;

/* Apache config process */
static void *ftp_dbm_create_server_config(apr_pool_t *p, server_rec *s)
{
	ftp_dbm_server_conf *pConfig = apr_pcalloc(p, sizeof(ftp_dbm_server_conf));
	pConfig->dbtype = "default";
	return pConfig;
}

static const char * ftp_dbm_cmd_dbmpath(cmd_parms *cmd, void *config,
									 const char *arg)
{
	ftp_dbm_server_conf *conf = ap_get_module_config(cmd->server->module_config,
									&ftp_dbm_module);
	conf->chrootdb_path = ap_server_root_relative(cmd->pool, arg);

	if (!conf->chrootdb_path) {
		return apr_pstrcat(cmd->pool, "Invalid FTPChrootDBM: ", arg, NULL);
	}

	return NULL;
}

static const char * ftp_dbm_cmd_dbmtype(cmd_parms *cmd, void *config,
									 const char *arg)
{
	ftp_dbm_server_conf *conf = ap_get_module_config(cmd->server->module_config,
									&ftp_dbm_module);
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

static ftp_chroot_status_t ftp_dbm_map_chroot(const request_rec *r,
										const char **chroot,
										const char **initroot)
{
	apr_status_t res;
	apr_dbm_t *file;
	ftp_chroot_status_t ret = FTP_CHROOT_USER_NOT_FOUND;
	apr_datum_t key,val = { 0 };
	char *value, *tok, *tok_ses;
	ftp_user_rec *ur  __attribute__ ((unused))= ftp_get_user_rec(r);
	ftp_dbm_server_conf *pConfig = ap_get_module_config(r->server->module_config,
										&ftp_dbm_module);

	if ((res = apr_dbm_open_ex(&file, pConfig->dbtype, pConfig->chrootdb_path,
								APR_DBM_READONLY, APR_OS_DEFAULT, r->pool))
								!= APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r,
			"Error opening DBM file: %s",pConfig->chrootdb_path);
		ret = FTP_CHROOT_FAIL;
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
						ret = FTP_CHROOT_USER_FOUND;
					} else {
						ret = FTP_CHROOT_FAIL;
					}
				}
			}

			apr_dbm_close(file);
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"File open failed: %s",pConfig->chrootdb_path);
			ret = FTP_CHROOT_FAIL;
		}
	}
	return ret;
}

/* Module initialization structures */
static const ftp_hooks_chroot ftp_hooks_chroot_dbm =
{
	ftp_dbm_map_chroot		/* map_chroot */
};

static const ftp_provider ftp_dbm_provider =
{
	"DBM",		/* name */
	&ftp_hooks_chroot_dbm,		/* chroot */
	NULL		/* listing */
};

static const command_rec ftp_dbm_cmds[] = {
	AP_INIT_TAKE1("FTPChrootDBM", ftp_dbm_cmd_dbmpath, NULL, RSRC_CONF,
                 "Path to Database to use chroot mapping."),
	AP_INIT_TAKE1("FTPChrootDBMType", ftp_dbm_cmd_dbmtype, NULL, RSRC_CONF,
                 "What type of DBM file to open. default, DB,GDBM,NDBM, SDBM."),
    { NULL }
};

static void register_hooks(apr_pool_t *p)
{
	ap_register_provider(p, FTP_PROVIDER_GROUP, ftp_dbm_provider.name, "0",
		&ftp_dbm_provider);
}

module AP_MODULE_DECLARE_DATA ftp_dbm_module = {
	STANDARD20_MODULE_STUFF,
    NULL,                          /* create per-directory config structure */
    NULL,                          /* merge per-directory config structures */
    ftp_dbm_create_server_config,  /* create per-server config structure */
    NULL,                          /* merge per-server config structures */
    ftp_dbm_cmds,                  /* command apr_table_t */
    register_hooks                 /* register hooks */
};
