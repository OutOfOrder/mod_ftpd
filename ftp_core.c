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


/* An FTP Protocol Module for Apache
 * RFC 959 - Primary FTP definition
 * RFC 1123 - Updated refinement of FTP
 * RFC 1579 - Recommendation of using PASV for clients
 * RFC 1639 - LPRT and LPSV commands (not used much)
 * RFC 2228 - AUTH security support
 * RFC 2389 - FEAT command for features supported by server
 * RFC 2428 - EPRT,EPSV IPV4,IPV6 support
 * RFC 2640 - Internationalization support
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

#include "ftp.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
	pConfig->nMinPort = 1024;
	pConfig->nMaxPort = 65535;
	pConfig->bRealPerms = 0;
	pConfig->bAllowPort = 1;
    return pConfig;
}

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
	ap_add_output_filter("FTP_COMMAND_OUTPUT",NULL,NULL,c);
	apr_pool_create(&p, c->pool);
    ur = apr_palloc(p, sizeof(*ur));
    ur->p = p;
	apr_pool_create(&ur->data.p, ur->p);
    ur->c = c;
    ur->state = FTP_AUTH;
	ur->data.type = FTP_PIPE_NONE;

	ur->binaryflag = 0;	/* Default is ASCII */

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

static apr_status_t ftp_command_output_filter(ap_filter_t * f, 
                                           apr_bucket_brigade * bb)
{
    apr_bucket *e;
    apr_status_t rv;
    const char *buf;
    const char *pos;
 
    APR_BRIGADE_FOREACH(e, bb) {
        apr_size_t len = e->length;

        if (e->length != 0) {
            rv = apr_bucket_read(e, &buf, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            /* We search the data for a LF, if we find one, we split the
             * bucket so that the LF is the first character in the new
             * bucket.  We then create a new bucket with a CR and insert
             * it before the LF bucket.
             */
            pos = memchr(buf, APR_ASCII_LF, len);
            while (pos) {
                apr_bucket *b = NULL;
                if ((pos > buf) && (*(pos - 1) != APR_ASCII_CR)) {
                    /* XXX: won't detect a bare LF at the beginning
                     * of any bucket not created by this function */
                    apr_bucket_split(e, pos - buf);
                    b = apr_bucket_immortal_create("\r", 1, f->c->bucket_alloc);
                    APR_BUCKET_INSERT_AFTER(e, b);
                    e = APR_BUCKET_NEXT(e);  /* Skip the inserted bucket */
                    break;
                }
                else if (pos - buf + 1 < len) {
                    /* there is at least one more char left in the bucket */
                    if (*(pos + 1) == '.') {
                        apr_bucket_split(e, pos - buf + 1);
                        b = apr_bucket_immortal_create(".", 1,
                                                       f->c->bucket_alloc);
                        APR_BUCKET_INSERT_AFTER(e, b);
                        e = APR_BUCKET_NEXT(e);  /* Skip the inserted bucket */
                        break;
                    }
                    pos = memchr(pos+1, APR_ASCII_LF, len-(pos-buf+1));
                }
                else {
                    /* done with this bucket */
                    break;
                }
            }
        }
    }
    return ap_pass_brigade(f->next, bb);
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

/* Include Server ap_set_*_slot functions */
/* Set Module name for functions */
#define MODULE_NAME ftp_module
#include "server_config.h"

static void register_hooks(apr_pool_t *p)
{
	ap_ftp_hash = apr_hash_make(p);

    ap_hook_process_connection(process_ftp_connection,NULL,NULL,
			       APR_HOOK_MIDDLE);
/* Register input/output filters */
    ap_register_output_filter("FTP_COMMAND_OUTPUT", ftp_command_output_filter, NULL,
                              AP_FTYPE_CONNECTION);

/* Authentication Commands */
    ap_ftp_register_handler("USER", ap_ftp_handle_user, FTP_AUTH | FTP_USER_ACK,
		"<sp> username", NULL, p);  
    ap_ftp_register_handler("PASS", ap_ftp_handle_passwd, FTP_USER_ACK,
		"<sp> password", NULL, p);
	/* TODO: implement Secure AUTH */
	ap_ftp_register_handler("AUTH", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);

/* General Commands */
	ap_ftp_register_handler("QUIT", ap_ftp_handle_quit, FTP_ALL_STATES,
		"(Quits the FTP Session)", NULL, p);
	ap_ftp_register_handler("HELP", ap_ftp_handle_help, FTP_TRANSACTION,
		"[ <sp> <command> ]", NULL, p);
	ap_ftp_register_handler("NOOP", ap_ftp_handle_NOOP, FTP_TRANSACTION,
		"", NULL, p);
	ap_ftp_register_handler("SYST", ap_ftp_handle_syst, FTP_TRANSACTION,
		"(Get Type of Operating System)", NULL, p);
	ap_ftp_register_handler("FEAT", ap_ftp_handle_help, FTP_TRANSACTION,
		"(list feature extensions)", (void *)1, p);
	/* TODO: Store CLNT in UserAgent for logging? */
	ap_ftp_register_handler("CLNT", ap_ftp_handle_NOOP, FTP_TRANSACTION,
		"<sp> Client User Agent", NULL, p);
	ap_ftp_register_handler("OPTS", NULL, FTP_NOT_IMPLEMENTED,
		"<sp> command <sp> options", NULL, p);

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
	/* TODO: implement mkdir */
	ap_ftp_register_handler("MKD", NULL, FTP_NOT_IMPLEMENTED,
		"<sp> directory-name", NULL, p);
	ap_ftp_register_handler("XMKD", NULL, FTP_NOT_IMPLEMENTED,
		"<sp> directory-name", NULL, p);
	/* TODO: implement rmdir */
	ap_ftp_register_handler("RMD", NULL, FTP_NOT_IMPLEMENTED,
		"<sp> directory-name", NULL, p);
	ap_ftp_register_handler("XRMD", NULL, FTP_NOT_IMPLEMENTED,
		"<sp> directory-name", NULL, p);
	/* TODO: Check for ASCII transfer mode and return failure for SIZE*/
	ap_ftp_register_handler("SIZE", ap_ftp_handle_size, FTP_TRANSACTION | FTP_FEATURE,
		"<sp> path-name", NULL, p);
	ap_ftp_register_handler("MDTM", ap_ftp_handle_mdtm, FTP_TRANSACTION | FTP_FEATURE,
		"<sp> path-name", NULL, p);

/* Transfer mode settings */
	/* TODO: Support IPV6 PASV hack? */
	ap_ftp_register_handler("PASV", ap_ftp_handle_pasv, FTP_TRANSACTION, 
		"(Set Server into Passive Mode)", NULL, p);
	/* Unfortunatly needed by some old clients */
	ap_ftp_register_handler("PORT", ap_ftp_handle_port, FTP_TRANSACTION, 
		"<sp> h1, h2, h3, h4, p1, p2", NULL, p);
	ap_ftp_register_handler("TYPE", ap_ftp_handle_type, FTP_TRANSACTION, 
		"<sp> [ A | E | I | L ]", NULL, p);
	ap_ftp_register_handler("SITE", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);

/* Directory Listing */
	/* TODO: support listing of a file with LIST */
	ap_ftp_register_handler("LIST", ap_ftp_handle_list, FTP_TRANS_DATA, 
		"[ <sp> path-name ]", NULL, p);
	ap_ftp_register_handler("NLST", ap_ftp_handle_list, FTP_TRANS_DATA,
		"[ <sp> path-name ]", (void *)1, p);

/* File Rename */
	/* TODO: Implement renaming of files */
	ap_ftp_register_handler("RNFR", NULL, FTP_NOT_IMPLEMENTED,
		"<sp> path-name", NULL, p);
	ap_ftp_register_handler("RNTO", NULL, FTP_NOT_IMPLEMENTED,
		"<sp> path-name", NULL, p);

/* File Transfer */
	ap_ftp_register_handler("RETR", ap_ftp_handle_retr, FTP_TRANS_DATA, 
		"<sp> file-name", NULL, p);
	/* TODO: implement store, and append */
	ap_ftp_register_handler("STOR", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("APPE", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("DELE", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	/* TODO: implement restore */
	ap_ftp_register_handler("REST", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	/* TODO: implement stou (suggested name upload */
	ap_ftp_register_handler("STOU", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);

/* Abort/Status Pipelining */
	/* TODO: implement stat */
	ap_ftp_register_handler("STAT", NULL, FTP_NOT_IMPLEMENTED, 
		"[ <sp> path-name ]", NULL, p);
	/* TODO: Do we need to support ABOR? */
	ap_ftp_register_handler("ABOR", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);

/* Extended Commands for IPv6 support */
	/* TODO: implement EPRT, and EPSV, RFCed IPV6 support */
	ap_ftp_register_handler("EPRT", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("EPSV", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
/*  LONG passive and port */
	ap_ftp_register_handler("LPRT", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("LPSV", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);

/* unknown */
	ap_ftp_register_handler("PROT", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);
	ap_ftp_register_handler("PBSZ", NULL, FTP_NOT_IMPLEMENTED, NULL, NULL, p);

/* Antiquated commands */
	ap_ftp_register_handler("STRU", ap_ftp_handle_NOOP, FTP_TRANSACTION,
		"(Specify File Structure) - (Depricated)", "F", p);
	ap_ftp_register_handler("MODE", ap_ftp_handle_NOOP, FTP_TRANSACTION,
		"(Specify Transfer Mode) - (Depricated)", "S", p);
	ap_ftp_register_handler("ALLO", NULL, FTP_NOT_IMPLEMENTED, 
		"(Pre-Allocate storage) (Depricated)", NULL, p);
	ap_ftp_register_handler("SMNT", NULL, FTP_NOT_IMPLEMENTED, 
		"(Structured Mount) - (Depricated)", NULL, p);
	ap_ftp_register_handler("ACCT", NULL, FTP_NOT_IMPLEMENTED, 
		"(Depricated)", NULL, p);
	ap_ftp_register_handler("REIN", NULL, FTP_NOT_IMPLEMENTED, 
		"(Reinitialize Server State) - (Depricated)", NULL, p);
}

static const command_rec ftp_cmds[] = {
    AP_INIT_FLAG("FTPProtocol", ap_set_server_flag_slot, 
				(void *)APR_OFFSETOF(ftp_config_rec, bEnabled), RSRC_CONF,
                 "Whether this server is serving the FTP0 protocol. Default: Off"),

	AP_INIT_FLAG("FTPShowRealPermissions", ap_set_server_flag_slot,
				(void *)APR_OFFSETOF(ftp_config_rec, bRealPerms), RSRC_CONF,
                 "Show Real Permissions on files. Default: Off"),

	AP_INIT_FLAG("FTPAllowActive", ap_set_server_flag_slot,
				(void *)APR_OFFSETOF(ftp_config_rec, bAllowPort), RSRC_CONF,
                 "Allow active(PORT) connections on this server. Default: On"),

	AP_INIT_TAKE1("FTPPasvMinPort", ap_set_server_int_slot, 
				(void *)APR_OFFSETOF(ftp_config_rec, nMinPort), RSRC_CONF,
				"Minimum PASV port to use for Data connections. Default: 1024"),

	AP_INIT_TAKE1("FTPPasvMaxPort", ap_set_server_int_slot, 
				(void *)APR_OFFSETOF(ftp_config_rec, nMaxPort), RSRC_CONF,
				"Maximum PASV port to use for Data connections. Default: 65535"),

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
