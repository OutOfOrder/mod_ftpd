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

#include "ftp.h"


static request_rec *ftp_create_request(ftp_user_rec *ur)
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
 
    r->allowed_methods = ap_make_method_list(p, 2);
 
    r->headers_in      = apr_table_make(r->pool, 1);
    r->subprocess_env  = NULL;
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

    ap_set_module_config(r->request_config, &ftp_module, ur);

    return r;
}

static void *create_ftp_server_config(apr_pool_t *p, server_rec *s)
{
    ftp_config_rec *pConfig = apr_pcalloc(p, sizeof *pConfig);

    pConfig->bEnabled = 0;
	/* Should just use DocumentRoot */
	pConfig->sFtpRoot = DOCUMENT_LOCATION;  /* Probably a BAD default */
	pConfig->pasv_minport = 1024;
	pConfig->pasv_maxport = 65535;
    return pConfig;
}

static const char *set_ftp_protocol(cmd_parms *cmd, void *dummy, int arg)
{
    ftp_config_rec *pConfig = ap_get_module_config(cmd->server->module_config,
                                               &ftp_module);
    const char *err = ap_check_cmd_context(cmd,NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) {
		return err;
	}

	pConfig->bEnabled = arg;
    return NULL;
}

static const char *set_ftp_docroot(cmd_parms *cmd, void *dummy, char *arg)
{
    ftp_config_rec *pConfig = ap_get_module_config(cmd->server->module_config,
                                               &ftp_module);
    const char *err = ap_check_cmd_context(cmd,NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) {
		return err;
	}
	if (apr_filepath_merge((char**)&pConfig->sFtpRoot,NULL,arg, 
			APR_FILEPATH_TRUENAME, cmd->pool) != APR_SUCCESS
		|| !ap_is_directory(cmd->pool, arg)) {
		return "FTPDocumentRoot must be a directory";
	}
    return NULL;
}
/*static const char *set_ftp_portrange(cmd_parms *cmd, void *dummy, char *arg)
{
}*/

static int process_ftp_connection(conn_rec *c)
{
    //server_rec *s = c->base_server;
	request_rec *r;
	ftp_user_rec *ur;
	apr_pool_t *p;
	apr_bucket_brigade *bb;
    ftp_config_rec *pConfig = ap_get_module_config(c->base_server->module_config,
                                               &ftp_module);

    if (!pConfig->bEnabled) {
        return DECLINED;
    }

	ap_update_child_status(c->sbh, SERVER_BUSY_READ, NULL);
	//OutPut Filter? ap_add_output_filter("FTP_OUTPUT",NULL,NULL,c);
	apr_pool_create(&p, c->pool);
    ur = apr_palloc(p, sizeof(*ur));
    ur->p = p;
	//apr_pool_create(&ur->datap, ur->p);
    ur->c = c;
    ur->state = FTP_AUTH;
	ur->passive_socket = NULL;
    bb = apr_brigade_create(ur->p, c->bucket_alloc);

    r = ftp_create_request(ur);

	/*TODO: Flow control greeting here CODE 421 then close connection*/
    ap_fprintf(c->output_filters, bb, 
               "220 %s FTP server ready (Comments to: %s)\r\n",
               ap_get_server_name(r), r->server->server_admin);
    ap_fflush(c->output_filters, bb);

    process_ftp_connection_internal(r, bb);

    return OK;
}


void ap_ftp_register_handler(char *key, ap_ftp_handler *func, int states,
							const char *help_text, void *data, apr_pool_t *p)
{
	char *dupkey = apr_pstrdup(p, key);
    ftp_handler_st *hand = apr_palloc(p, sizeof(*hand));

    hand->func = func;
    hand->states = states;
	hand->help_text = help_text;
	hand->data = data;
    ap_str_tolower(dupkey);

    apr_hash_set(ap_ftp_hash, dupkey, APR_HASH_KEY_STRING, hand);
}

void ap_ftp_str_toupper(char *str)
{
	while (*str) {
		*str = apr_toupper(*str);
		++str;
	}
}

static void register_hooks(apr_pool_t *p)
{
	ap_ftp_hash = apr_hash_make(p);

    ap_hook_process_connection(process_ftp_connection,NULL,NULL,
			       APR_HOOK_MIDDLE);

/* Authentication Commands */
    ap_ftp_register_handler("USER", ap_ftp_handle_user, FTP_AUTH | FTP_USER_ACK,
		"<sp> username", NULL, p);  
    ap_ftp_register_handler("PASS", ap_ftp_handle_passwd, FTP_USER_ACK,
		"<sp> password", NULL, p);
	ap_ftp_register_handler("AUTH", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("ACCT", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);

/* General Commands */
	ap_ftp_register_handler("QUIT", ap_ftp_handle_quit, FTP_ALL_STATES,
		"(Quits the FTP Session)", NULL, p);
	ap_ftp_register_handler("HELP", ap_ftp_handle_help, FTP_TRANSACTION,
		"[ <sp> <command> ]", NULL, p);
	ap_ftp_register_handler("NOOP", ap_ftp_handle_NOOP, FTP_TRANSACTION,
		"", NULL, p);
	ap_ftp_register_handler("SYST", ap_ftp_handle_syst, FTP_TRANSACTION,
		"(Get Type of Operating System)", NULL, p);

/* Directory Commands */
	ap_ftp_register_handler("CWD", ap_ftp_handle_cd, FTP_TRANSACTION,
		"[ <sp> directory-name ]", NULL, p);
	ap_ftp_register_handler("XCWD", ap_ftp_handle_cd, FTP_TRANSACTION,
		"[ <sp> directory-name ]", NULL, p);
	ap_ftp_register_handler("CDUP", ap_ftp_handle_cd, FTP_TRANSACTION,
		"(Change to Parent Directory)", (void *)1, p);
	ap_ftp_register_handler("PWD", ap_ftp_handle_pwd, FTP_TRANSACTION,
		"(Returns Current Directory)", NULL, p);
	ap_ftp_register_handler("XPWD", ap_ftp_handle_pwd, FTP_TRANSACTION,
		"(Returns Current Directory)", NULL, p);
	ap_ftp_register_handler("MKD", NULL, FTP_NOT_IMPLEMENTED,
		"<sp> directory-name", NULL, p);
	ap_ftp_register_handler("RMD", NULL, FTP_NOT_IMPLEMENTED,
		"<sp> directory-name", NULL, p);
	ap_ftp_register_handler("SIZE", NULL, FTP_NOT_IMPLEMENTED,
		"<sp> path-name", NULL, p);

/* Transfer mode settings */
	ap_ftp_register_handler("STRU", ap_ftp_handle_NOOP, FTP_TRANSACTION,
		"(Specify File Structure)", NULL, p);
	ap_ftp_register_handler("MODE", ap_ftp_handle_NOOP, FTP_TRANSACTION,
		"(Specify Transfer Mode)", NULL, p);
	ap_ftp_register_handler("PASV", ap_ftp_handle_pasv, FTP_TRANSACTION, 
		"(Set Server into Passive Mode)", NULL, p);
	ap_ftp_register_handler("TYPE", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("SITE", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);

/* Directory Listing */
	ap_ftp_register_handler("LIST", ap_ftp_handle_list, FTP_TRANS_PASV, 
		"[ <sp> path-name ]", NULL, p);
	ap_ftp_register_handler("NLST", ap_ftp_handle_list, FTP_TRANS_PASV,
		"[ <sp> path-name ]", (void *)1, p);
/* File Rename */
	ap_ftp_register_handler("RNFR", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("RNTO", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
/* File Transfer */
	ap_ftp_register_handler("RETR", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("STOR", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("APPE", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("DELE", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("REST", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("STOU", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);

/* Abort/Status Pipelining */
	ap_ftp_register_handler("STAT", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("ABOR", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);

/* Extended Commands */
	ap_ftp_register_handler("EPRT", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("EPSV", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("LPRT", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("LPSV", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);

/* unknown */
	ap_ftp_register_handler("PROT", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("PBSZ", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);

/* Never support this one.. Connection goes server to client */
	ap_ftp_register_handler("PORT", NULL, FTP_NOT_IMPLEMENTED, 
		"<sp> h1, h2, h3, h4, p1, p2", NULL, p);

	/* Assign output filters? */
}

static const command_rec ftp_cmds[] = {
    AP_INIT_FLAG("FTPProtocol", set_ftp_protocol, NULL, RSRC_CONF,
                 "Whether this server is serving the FTP0 protocol"),
	AP_INIT_TAKE1("FTPDocumentRoot", set_ftp_docroot, NULL, RSRC_CONF,
				 "Root of this FTP server\nDefault: The Server DocumentRoot"),
	AP_INIT_TAKE1("FTPPasvMinPort", ap_set_int_slot, 
				(void *)APR_OFFSETOF(ftp_config_rec, pasv_minport), RSRC_CONF,
				"Minimum PASV port to use for Data connections\nDefault: 1024"),
	AP_INIT_TAKE1("FTPPasvMinPort", ap_set_int_slot, 
				(void *)APR_OFFSETOF(ftp_config_rec, pasv_minport), RSRC_CONF,
				"Minimum PASV port to use for Data connections\nDefault: 65535"),
    { NULL }
};


module AP_MODULE_DECLARE_DATA ftp_module = {
	STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    create_ftp_server_config,  /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    ftp_cmds,                  /* command apr_table_t */
    register_hooks              /* register hooks */
};
