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


/* $Header: /home/cvs/httpd-ftp/ftp_core.c,v 1.20 2004/01/08 04:42:48 urkle Exp $ */
/* An FTP Protocol Module for Apache
 * RFC 959 - Primary FTP definition
 * RFC 1123 - Updated refinement of FTP
 * RFC 1579 - Recommendation of using PASV for clients
 * RFC 1639 - LPRT and LPSV commands (not used much)
 * RFC 2228 - AUTH security support
 * RFC 2389 - FEAT command for features supported by server
 * RFC 2428 - EPRT,EPSV IPV4,IPV6 support
 * RFC 2640 - Internationalization support
 * draft-ietf-ftpext-mlst-16,txt(on www.ietf.org) MDTM, SIZE, and MLST
 * http://www.wu-ftpd.org/rfc/
 * http://war.jgaa.com/ftp/?cmd=rfc
 * http://cr.yp.to/ftp.html
 */
#define CORE_PRIVATE
#include "httpd.h"
#include "http_protocol.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_request.h"
#include "http_log.h"
#include "ap_config.h"
#include "ap_mmn.h"
#include "apr_lib.h"
#include "apr_buckets.h"
#include "apr_strings.h"
#include "util_filter.h"
#include "scoreboard.h"
#include "ap_provider.h"

#include "ftp.h"

int ftpd_methods[FTPD_M_LAST];
/* Creates the main request record for the connection */
static request_rec *ftpd_create_request(ftpd_user_rec *ur)
{
    apr_pool_t *p;
    request_rec *r;

    apr_pool_create(&p, ur->p);

    r                  = apr_pcalloc(p, sizeof(*r));
    r->pool            = p;
    r->connection      = ur->c;
    r->server          = ur->c->base_server;

    ur->c->keepalive    = 0;
 
    r->user            = NULL;
    r->ap_auth_type    = NULL;
 
	r->hostname = apr_pstrdup(r->pool,ur->c->local_ip);

    r->allowed_methods = ap_make_method_list(p, 2);
 
    r->headers_in      = apr_table_make(r->pool, 1);
    r->subprocess_env  = apr_table_make(r->pool, 1);
    r->headers_out     = apr_table_make(r->pool, 1);
    r->err_headers_out = apr_table_make(r->pool, 1);
    r->notes           = apr_table_make(r->pool, 5);
 
    r->request_config  = ap_create_request_config(r->pool);

	ap_run_create_request(r);

    r->per_dir_config  = r->server->lookup_defaults;
 
    r->sent_bodyct     = 0;                      /* bytect isn't for body */
 
    r->output_filters  = ur->c->output_filters;
    r->input_filters   = ur->c->input_filters;

    r->status = HTTP_OK;                         /* Until further notice. */

    ap_set_module_config(r->request_config, &ftpd_module, ur);

    return r;
}

static void *ftpd_create_server_config(apr_pool_t *p, server_rec *s)
{
    ftpd_svr_config_rec *pConfig = apr_pcalloc(p, sizeof *pConfig);

    pConfig->bEnabled = 0;
	pConfig->nMinPort = 1024;
	pConfig->nMaxPort = 65535;
	pConfig->bRealPerms = 0;
	pConfig->bAllowPort = 1;
	pConfig->bAnnounce = 1;
	pConfig->sFakeGroup = "ftp";
	pConfig->sFakeUser = "ftp";
    return pConfig;
}

static int process_ftpd_connection(conn_rec *c)
{
    server_rec *s = c->base_server;
	request_rec *r;
	ftpd_user_rec *ur;
	apr_pool_t *p;
	apr_bucket_brigade *bb;
    ftpd_svr_config_rec *pConfig = ap_get_module_config(c->base_server->module_config,
                                               &ftpd_module);

    if (!pConfig->bEnabled) {
        return DECLINED;
    }

	ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);
	/* TODO: Create ASCII Filter for command output and TYPE A retreival to replace *hack* function */
/*	ap_add_output_filter("FTPD_COMMAND_OUTPUT",NULL,NULL,c);*/
	apr_pool_create(&p, c->pool);
    ur = apr_pcalloc(p, sizeof(*ur));
    ur->p = p;
	apr_pool_create(&ur->data.p, ur->p);
    ur->c = c;
	ur->s = s;
    ur->state = FTPD_STATE_AUTH;
	ur->data.type = FTPD_PIPE_NONE;

    bb = apr_brigade_create(ur->p, c->bucket_alloc);

    r = ftpd_create_request(ur);

	/*TODO: Flow control greeting here CODE 421 then close connection*/
    ap_fprintf(c->output_filters, bb, 
               FTP_C_GREET" %s FTP server ready ("PACKAGE_NAME"/"PACKAGE_VERSION")\r\n",
			   ap_get_server_name(r));
    ap_fflush(c->output_filters, bb);

    process_ftpd_connection_internal(r, bb);

    return OK;
}

static int ftpd_init_handler(apr_pool_t *p, apr_pool_t *log, apr_pool_t *ptemp,
					server_rec *s)
{
	ftpd_svr_config_rec *pConfig = ap_get_module_config(s->module_config,
					&ftpd_module);
	/* Register FTP methods */

	/* RETR is GET
	 * STOR is PUT
	 * Delete is DELETE
	 * Make directry is MKCOL
	 * Rename is MOVE
	 */

	/* Login (CD to root directory) and the CD command */
	ftpd_methods[FTPD_M_CHDIR] = ap_method_register(p, "CHDIR");
	/* LIST, NLST, SIZE, MDTM, STAT (filename) */
	ftpd_methods[FTPD_M_LIST] = ap_method_register(p, "LIST");
	/* STOU, Separate from STOR for uploads */
/*	ftpd_methods[FTPD_M_STOU] = ap_method_register(p, "STOU");*/
	/* APPE, Append uploads, and STOR w/ REST */
	ftpd_methods[FTPD_M_APPEND] = ap_method_register(p, "APPEND");
	/* Remove directory */
	ftpd_methods[FTPD_M_XRMD] = ap_method_register(p, "XRMD");

	/* Add version string to Apache headers */
	if (pConfig->bAnnounce) {
		ap_add_version_component(p, PACKAGE_NAME"/"PACKAGE_VERSION);
	}
	return OK;
}

static int translate_chroot(request_rec *r)
{
	char *name = r->uri;
	int is_absolute;
	char *filename;
	apr_status_t res;
	apr_finfo_t statbuf;
	ftpd_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
								&ftpd_module);
	ftpd_user_rec *ur = ftpd_get_user_rec(r);

    if (!pConfig->bEnabled) {
        return DECLINED;
    }

	if (!ur->chroot) {
		return DECLINED;
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		"input URI is %s -> %s", name, ur->chroot);
	is_absolute = ap_os_is_path_absolute(r->pool, ur->chroot);
	if (is_absolute) {
		filename = apr_pstrcat(r->pool, ur->chroot, NULL);
	} else {
		filename = apr_pstrcat(r->pool, ap_document_root(r),"/", ur->chroot, NULL);
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		"filename set to %s",filename);
	/* TODO: Side affect.. stating the dir causes missing chroot to fall back to Docuementroot */
	if ((res = apr_stat(&statbuf, filename, APR_FINFO_MIN, r->pool))
			== APR_SUCCESS || res == APR_INCOMPLETE) {
		r->filename = apr_pstrcat(r->pool, filename, name, NULL);
		//r->finfo = statbuf;
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"r->filename set to %s",r->filename);
		return OK;
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r,
			"Stat Error");
	}
	return DECLINED;
}

FTPD_DECLARE(void) ftpd_register_handler(char *key, ftpd_handler *func, int states,
							const char *help_text, void *data, apr_pool_t *p)
{
	char *dupkey = apr_pstrdup(p, key);
    ftpd_handler_st *hand = apr_palloc(p, sizeof(*hand));

    hand->func = func;
    hand->states = states;
	hand->help_text = help_text;
	hand->data = data;
    ap_str_tolower(dupkey);

    apr_hash_set(ftpd_hash, dupkey, APR_HASH_KEY_STRING, hand);
}


FTPD_DECLARE(void) ap_ftpd_str_toupper(char *str)
{
	while (*str) {
		*str = apr_toupper(*str);
		++str;
	}
}


FTPD_DECLARE(ftpd_user_rec) *ftpd_get_user_rec(const request_rec *r)
{
	return ap_get_module_config(r->request_config, &ftpd_module);
}

/* Include Server ap_set_*_slot functions */
/* Set Module name for functions */
#define MODULE_NAME ftpd_module
#include "server_config.h"

static const char *ftpd_set_chroot_order(cmd_parms *cmd,
                                    		 void *struct_ptr,
                                     		 const char *arg)
{
	const char *provider_name;
	ftpd_provider_list *newp;
	ftpd_svr_config_rec *pConfig = ap_get_module_config(cmd->server->module_config,
								&ftpd_module);

	const char *err = ap_check_cmd_context(cmd,NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) {
		return err;
	}

	if (strcasecmp(arg, "none") == 0) {
		/* disable all providers */
		pConfig->providers = NULL;
		return NULL;
	} else {
		provider_name = apr_pstrdup(cmd->pool, arg);
	}
	newp = apr_pcalloc(cmd->pool, sizeof(ftpd_provider_list));
	newp->name = provider_name;
	newp->provider = ap_lookup_provider(FTPD_PROVIDER_GROUP, newp->name, "0");
	if (newp->provider == NULL) {
		return apr_psprintf(cmd->pool, "Chroot Provider '%s' not loaded", newp->name);
	}
	/* add to the list */
	if (!pConfig->providers) {
		pConfig->providers = newp;
	} else {
		ftpd_provider_list *last = pConfig->providers;
		while (last->next) {
			last = last->next;
		}
		last->next = newp;
	}
    return NULL;
}

static void register_hooks(apr_pool_t *p)
{
	static const char * const aszPre[] = { "mod_alias.c", NULL };
	static const char * const aszSucc[]= { "mod_vhost_alias.c", NULL };
	ftpd_hash = apr_hash_make(p);

    ap_hook_process_connection(process_ftpd_connection,NULL,NULL,
			       APR_HOOK_MIDDLE);
/* For registering ftp methods */
	ap_hook_post_config(ftpd_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
/* Translate hook for Chroot supporting */
	ap_hook_translate_name(translate_chroot, aszPre, aszSucc, APR_HOOK_MIDDLE);
	
/* Register input/output filters */
/*    ap_register_output_filter("FTPD_COMMAND_OUTPUT", ftpd_command_output_filter,
							  NULL, AP_FTYPE_CONNECTION);
*/
/* Everthing below here is registeriny FTP commands handlers */
/* Authentication Commands */
    ftpd_register_handler("USER", HANDLER_FUNC(user), FTPD_STATE_AUTH | FTPD_STATE_USER_ACK,
		"<sp> username", NULL, p);  
    ftpd_register_handler("PASS", HANDLER_FUNC(passwd), FTPD_STATE_USER_ACK | FTPD_FLAG_HIDE_ARGS,
		"<sp> password", NULL, p);
	/* TODO: implement Secure AUTH */
	ftpd_register_handler("AUTH", NULL, FTPD_FLAG_NOT_IMPLEMENTED | FTPD_FLAG_HIDE_ARGS, NULL, NULL, p);

/* General Commands */
	ftpd_register_handler("QUIT", HANDLER_FUNC(quit), FTPD_ALL_STATES,
		"(Quits the FTP Session)", NULL, p);
	ftpd_register_handler("HELP", HANDLER_FUNC(help), FTPD_STATE_TRANSACTION,
		"[ <sp> <command> ]", NULL, p);
	ftpd_register_handler("NOOP", HANDLER_FUNC(NOOP), FTPD_STATE_TRANSACTION,
		"", NULL, p);
	ftpd_register_handler("SYST", HANDLER_FUNC(syst), FTPD_STATE_TRANSACTION,
		"(Get Type of Operating System)", NULL, p);
	ftpd_register_handler("FEAT", HANDLER_FUNC(help), FTPD_STATE_TRANSACTION,
		"(list feature extensions)", (void *)1, p);
	ftpd_register_handler("CLNT", HANDLER_FUNC(clnt), FTPD_STATE_TRANSACTION,
		"<sp> Client User Agent", NULL, p);
	ftpd_register_handler("OPTS", NULL, FTPD_FLAG_NOT_IMPLEMENTED,
		"<sp> command <sp> options", NULL, p);

/* Directory Commands */
	ftpd_register_handler("CWD", HANDLER_FUNC(cd), FTPD_STATE_TRANSACTION,
		"[ <sp> directory-name ]", NULL, p);
	ftpd_register_handler("XCWD", HANDLER_FUNC(cd), FTPD_STATE_TRANSACTION,
		"[ <sp> directory-name ]", NULL, p);
	ftpd_register_handler("CDUP", HANDLER_FUNC(cd), FTPD_STATE_TRANSACTION,
		"(Change to Parent Directory)", (void *)1, p);
	ftpd_register_handler("PWD", HANDLER_FUNC(pwd), FTPD_STATE_TRANSACTION,
		"(Returns Current Directory)", NULL, p);
	ftpd_register_handler("XPWD", HANDLER_FUNC(pwd), FTPD_STATE_TRANSACTION,
		"(Returns Current Directory)", NULL, p);
	ftpd_register_handler("MKD", HANDLER_FUNC(mkdir), FTPD_STATE_TRANSACTION | FTPD_FLAG_LOG_COMMAND,
		"<sp> directory-name", NULL, p);
	ftpd_register_handler("XMKD", HANDLER_FUNC(mkdir), FTPD_STATE_TRANSACTION | FTPD_FLAG_LOG_COMMAND,
		"<sp> directory-name", NULL, p);
	ftpd_register_handler("RMD", HANDLER_FUNC(rmdir), FTPD_STATE_TRANSACTION | FTPD_FLAG_LOG_COMMAND,
		"<sp> directory-name", NULL, p);
	ftpd_register_handler("XRMD", HANDLER_FUNC(rmdir), FTPD_STATE_TRANSACTION | FTPD_FLAG_LOG_COMMAND,
		"<sp> directory-name", NULL, p);
	ftpd_register_handler("SIZE", HANDLER_FUNC(size), FTPD_STATE_TRANSACTION | FTPD_FLAG_FEATURE,
		"<sp> path-name", NULL, p);
	ftpd_register_handler("MDTM", HANDLER_FUNC(mdtm), FTPD_STATE_TRANSACTION | FTPD_FLAG_FEATURE,
		"<sp> path-name", NULL, p);

/* Transfer mode settings */
	ftpd_register_handler("PASV", HANDLER_FUNC(pasv), FTPD_STATE_TRANSACTION | FTPD_FLAG_EPSV_LOCK,
		"(Set Server into Passive Mode)", NULL, p);
	/* Unfortunatly needed by some old clients */
	ftpd_register_handler("PORT", HANDLER_FUNC(port), FTPD_STATE_TRANSACTION | FTPD_FLAG_EPSV_LOCK,
		"<sp> h1, h2, h3, h4, p1, p2", NULL, p);
	ftpd_register_handler("TYPE", HANDLER_FUNC(type), FTPD_STATE_TRANSACTION,
		"<sp> [ A | E | I | L ]", NULL, p);
	ftpd_register_handler("SITE", NULL, FTPD_FLAG_NOT_IMPLEMENTED, NULL, NULL, p);

/* Directory Listing */
	ftpd_register_handler("LIST", HANDLER_FUNC(list), FTPD_STATE_TRANS_DATA | FTPD_FLAG_LOG_COMMAND,
		"[ <sp> path-name ]", NULL, p);
	ftpd_register_handler("NLST", HANDLER_FUNC(list), FTPD_STATE_TRANS_DATA | FTPD_FLAG_LOG_COMMAND,
		"[ <sp> path-name ]", (void *)1, p);

/* File Rename */
	ftpd_register_handler("RNFR", HANDLER_FUNC(rename), FTPD_STATE_TRANSACTION,
		"<sp> path-name", NULL, p);
	ftpd_register_handler("RNTO", HANDLER_FUNC(rename), FTPD_STATE_RENAME | FTPD_FLAG_LOG_COMMAND,
		"<sp> path-name", (void *)1, p);

/* File Transfer */
	ftpd_register_handler("RETR", HANDLER_FUNC(retr), FTPD_STATE_TRANS_DATA | FTPD_FLAG_LOG_COMMAND,
		"<sp> file-name", NULL, p);
	ftpd_register_handler("STOR", HANDLER_FUNC(stor), FTPD_STATE_TRANS_DATA | FTPD_FLAG_LOG_COMMAND,
		"<sp> file-name", NULL, p);
	ftpd_register_handler("APPE", HANDLER_FUNC(stor), FTPD_STATE_TRANS_DATA | FTPD_FLAG_LOG_COMMAND,
		"<sp> file-name", (void *)1, p);
	ftpd_register_handler("DELE", HANDLER_FUNC(delete), FTPD_STATE_TRANSACTION | FTPD_FLAG_LOG_COMMAND,
		"<sp> file-name", NULL, p);
	ftpd_register_handler("REST", HANDLER_FUNC(restart), FTPD_STATE_TRANSACTION,
		"<sp> offset", NULL, p);
	/* TODO: implement stou (suggested name upload) */
	ftpd_register_handler("STOU", NULL, FTPD_FLAG_NOT_IMPLEMENTED, NULL, NULL, p);

/* Abort/Status Pipelining */
	/* TODO: implement stat */
	ftpd_register_handler("STAT", NULL, FTPD_FLAG_NOT_IMPLEMENTED, 
		"[ <sp> path-name ]", NULL, p);
	/* TODO: Do we need to support ABOR? */
	ftpd_register_handler("ABOR", NULL, FTPD_FLAG_NOT_IMPLEMENTED, NULL, NULL, p);

/* Extended Commands for IPv6 support */
	ftpd_register_handler("EPRT", HANDLER_FUNC(port), FTPD_STATE_TRANSACTION | FTPD_FLAG_EPSV_LOCK,
		"<sp> |af|addr|port|", (void *)1, p);
	ftpd_register_handler("EPSV", HANDLER_FUNC(pasv), FTPD_STATE_TRANSACTION,
		"[ <sp> af|ALL]", (void *)1, p);
/*  LONG passive and port */
	ftpd_register_handler("LPRT", NULL, FTPD_FLAG_NOT_IMPLEMENTED, NULL, NULL, p);
	ftpd_register_handler("LPSV", NULL, FTPD_FLAG_NOT_IMPLEMENTED, NULL, NULL, p);
/* no documentation for this command can be found */
	ftpd_register_handler("SPSV", NULL, FTPD_FLAG_NOT_IMPLEMENTED, NULL, NULL, p);

/* unknown */
	ftpd_register_handler("PROT", NULL, FTPD_FLAG_NOT_IMPLEMENTED, NULL, NULL, p);
	ftpd_register_handler("PBSZ", NULL, FTPD_FLAG_NOT_IMPLEMENTED, NULL, NULL, p);

/* Antiquated commands */
	ftpd_register_handler("STRU", HANDLER_FUNC(NOOP), FTPD_STATE_TRANSACTION,
		"(Specify File Structure) - (Depricated)", "F", p);
	ftpd_register_handler("MODE", HANDLER_FUNC(NOOP), FTPD_STATE_TRANSACTION,
		"(Specify Transfer Mode) - (Depricated)", "S", p);
	ftpd_register_handler("ALLO", NULL, FTPD_FLAG_NOT_IMPLEMENTED, 
		"(Pre-Allocate storage) (Depricated)", NULL, p);
	ftpd_register_handler("SMNT", NULL, FTPD_FLAG_NOT_IMPLEMENTED, 
		"(Structured Mount) - (Depricated)", NULL, p);
	ftpd_register_handler("ACCT", NULL, FTPD_FLAG_NOT_IMPLEMENTED, 
		"(Depricated)", NULL, p);
	ftpd_register_handler("REIN", NULL, FTPD_FLAG_NOT_IMPLEMENTED, 
		"(Reinitialize Server State) - (Depricated)", NULL, p);
}

static const command_rec ftpd_cmds[] = {
    AP_INIT_FLAG("FTPProtocol", ap_set_server_flag_slot, 
				(void *)APR_OFFSETOF(ftpd_svr_config_rec, bEnabled), RSRC_CONF,
                 "Whether this server is serving the FTP protocol. Default: Off"),

	AP_INIT_FLAG("FTPShowRealPermissions", ap_set_server_flag_slot,
				(void *)APR_OFFSETOF(ftpd_svr_config_rec, bRealPerms), RSRC_CONF,
                 "Show Real Permissions of files. Default: Off"),

	AP_INIT_TAKE1("FTPFakeGroup", ap_set_server_string_slot,
				(void *)APR_OFFSETOF(ftpd_svr_config_rec, sFakeGroup), RSRC_CONF,
				"The fake group name to display in directory listings. Default: ftp"),

	AP_INIT_TAKE1("FTPFakeUser", ap_set_server_string_slot,
				(void *)APR_OFFSETOF(ftpd_svr_config_rec, sFakeUser), RSRC_CONF,
				"The fake user name to display in directory listings. Default: ftp"),

	AP_INIT_FLAG("FTPAllowActive", ap_set_server_flag_slot,
				(void *)APR_OFFSETOF(ftpd_svr_config_rec, bAllowPort), RSRC_CONF,
                 "Allow active(PORT) connections on this server. Default: On"),

	AP_INIT_FLAG("FTPAllowFXP", ap_set_server_flag_slot,
				(void *)APR_OFFSETOF(ftpd_svr_config_rec, bAllowFXP), RSRC_CONF,
				"Allow FXP transfers (ie. transfer data to a different server/client). Default: Off"),

	AP_INIT_TAKE1("FTPPasvMinPort", ap_set_server_int_slot, 
				(void *)APR_OFFSETOF(ftpd_svr_config_rec, nMinPort), RSRC_CONF,
				"Minimum PASV port to use for Data connections. Default: 1024"),

	AP_INIT_TAKE1("FTPPasvMaxPort", ap_set_server_int_slot, 
				(void *)APR_OFFSETOF(ftpd_svr_config_rec, nMaxPort), RSRC_CONF,
				"Maximum PASV port to use for Data connections. Default: 65535"),

	AP_INIT_ITERATE("FTPChroot", ftpd_set_chroot_order,
				NULL, RSRC_CONF,
				"List of Chroot prviders to query for chrooting the loging in user. Default: none"),

	AP_INIT_FLAG("FTPServerAnnounce", ap_set_server_flag_slot,
				(void *)APR_OFFSETOF(ftpd_svr_config_rec, bAnnounce), RSRC_CONF,
				"Whether to announce this module in the server header. Default: On"),

	{ NULL }
};


module AP_MODULE_DECLARE_DATA ftpd_module = {
	STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    ftpd_create_server_config,  /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    ftpd_cmds,                  /* command apr_table_t */
    register_hooks              /* register hooks */
};
