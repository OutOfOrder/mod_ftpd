#include "ap_config.h"
#include "ap_mmn.h"
#include "httpd.h"
#include "http_config.h"
#include "http_connection.h"

#include "apr_buckets.h"
#include "util_filter.h"

#include "ftp.h"

static void *create_ftp_server_config(apr_pool_t *p, server_rec *s)
{
    ftp_config_rec *pConfig = apr_pcalloc(p, sizeof *pConfig);

    pConfig->bEnabled = 0;

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

static int process_ftp_connection(conn_rec *c)
{
    server_rec *s = c->base_server;
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
	//OutPut Filter?
	apr_pool_create(&p, c->pool);
    ur = apr_palloc(p, sizeof(*ur));
    ur->ctx = apr_palloc(p, sizeof(*ur->ctx));
    ur->p = p;
    ur->c = c;
    ur->state = POP_AUTH;
    ur->high_access = 0;  /* We always start at 0. */
    bb = apr_brigade_create(ur->p, c->bucket_alloc);

    r = ftp_create_request(ur);

    ap_fprintf(c->output_filters, bb, 
               "+OK %s POP3 server ready (Comments to: %s)\r\n",
               ap_get_server_name(r), r->server->server_admin);
    ap_fflush(c->output_filters, bb);

    process_pop_connection_internal(r, bb);

    return OK;
}


void ap_ftp_register_handler(char *key, ap_ftp_handler *func, int states,
                             apr_pool_t *p)
{
	char *dupkey = (char *)apr_pstrdup(p, key);
    ftp_handler_st *hand = apr_palloc(p, sizeof(*hand));

    hand->func = func;
    hand->states = states;
    ap_str_tolower(dupkey);

    apr_hash_set(ap_ftp_hash, dupkey, APR_HASH_KEY_STRING, hand);
}


static void register_hooks(apr_pool_t *p)
{
	ap_ftp_hash = apr_hash_make(p);

    ap_hook_process_connection(process_ftp_connection,NULL,NULL,
			       APR_HOOK_MIDDLE);
}

static const command_rec ftp_cmds[] = {
    AP_INIT_FLAG("FTPProtocol", set_ftp_protocol, NULL, RSRC_CONF,
                 "Whether this server is serving the FTP0 protocol"),
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
