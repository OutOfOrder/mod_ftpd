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

/*
 *  Written by Paul Querna <chip force-elite.com>
 *   Based on mod_authn_dbi -> http://mod-auth.sourceforge.net
 */


#include "httpd.h"
#include "http_config.h"
#include "apr_strings.h"
#include "apr_reslist.h"
#include "apr_hash.h"

#include "http_log.h"
#include "ap_provider.h"

#include "mod_ftpd.h"

#include <dbi/dbi.h>

#define MOD_FTPD_DBI_VERSION "0.1"

#define DFLT_DBI_NAME "AuthDB"
#define DFLT_DBI_HOST "localhost"
#define DFLT_DBI_DRIVER "mysql"
#define DFLT_DBI_USER "root"
#define DFLT_DBI_PASS ""        /* setting this to NULL triggers a bug in libdbi which causes a segfault. mysql docs
                                 * say this must be set to NULL in order to login without a password. fortunately,
                                 * setting "" works as well. the bug is reported to the libdbi maintainers. we will
                                 * change this back when the bug is fixed.
                                 *
                                 */
#define DFLT_DBI_TABLE "Users"
#define DFLT_USERNAME_FIELD "Username"
#define DFLT_CHROOT_FIELD "chroot"
#define DFLT_CHROOT_QUERY NULL
#define DFLT_ACTIVE_FIELD NULL
#define DFLT_CONN_MIN (1)
#define DFLT_CONN_SOFT (5)
#define DFLT_CONN_MAX (25)
#define DFLT_CONN_TTL (600)
#define DFLT_OPTIONS (0)

#ifndef DBI_HARD_MAX_CONNS
#define DBI_HARD_MAX_CONNS (255)
#endif

/* do NOT set this to the empty string ""! */
#define DBI_EMPTY_CHROOT "::"

enum
{
    CONF_DBI_DRIVER,
    CONF_DBI_DRIVER_DIR,
    CONF_DBI_HOST,
    CONF_DBI_USERNAME,
    CONF_DBI_PASSWORD,
    CONF_DBI_NAME,
    CONF_DBI_TABLE,
    CONF_DBI_USERNAME_FIELD,
    CONF_DBI_CHROOT_FIELD,
    CONF_DBI_CHROOT_QUERY,
    CONF_DBI_IS_ACTIVE_FIELD,
    CONF_DBI_CONN_MIN,
    CONF_DBI_CONN_SOFTMAX,
    CONF_DBI_CONN_HARDMAX,
    CONF_DBI_CONN_TTL,
    CONF_DBI_OPTIONS
};

typedef struct ftpd_dbi_dconfig
{
    const char *id;
} ftpd_dbi_dconfig;

typedef struct ftpd_dbi_gconfig
{
    const char *driverdir;
} ftpd_dbi_gconfig;

/* This might be a little clumsy but should do for now. */

static ftpd_dbi_gconfig dbi_global_config = { NULL };
static apr_hash_t *ftpd_dbi_config_hash;
static int dbi_conn_count = 0;

typedef struct ftpd_dbi_config_rec_struct
{
    const char *dbi_name;
    const char *dbi_user;
    const char *dbi_pass;
    const char *dbi_driver;
    const char *dbi_host;
    const char *dbi_table;
    const char *username_field;
    const char *chroot_field;
    const char *chroot_query;
    const char *isactive_field;
    int conn_min;
    int conn_soft;
    int conn_max;
    int conn_ttl;
    apr_uint32_t options;
} ftpd_dbi_config_rec;

module AP_MODULE_DECLARE_DATA ftpd_dbi_module;

typedef struct ftpd_dbi_config_struct
{
    const char name;
    apr_reslist_t *pool;
    ftpd_dbi_config_rec rec;
} ftpd_dbi_config;

typedef struct ftpd_dbi_rest_struct
{
    dbi_conn *conn;
} ftpd_dbi_rest;

typedef const char *conn_id;


static apr_status_t safe_dbi_new_conn(void **resource, void *params,
                                      apr_pool_t * r)
{
    apr_status_t rv = APR_SUCCESS;
    ftpd_dbi_config_rec *conf = params;
    int err_num = 0;
    const char *err_str;
    const char *host = conf->dbi_host;
    const char *driver = conf->dbi_driver;
    const char *name = conf->dbi_name;
    const char *user = conf->dbi_user;
    const char *pwd = conf->dbi_pass;
    ftpd_dbi_rest *myres;

    dbi_conn_count++;

    if (DBI_HARD_MAX_CONNS > dbi_conn_count) {

        ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "[mod_ftpd_dbi.c] Creating New DBI Server Connection");

        myres = apr_palloc(r, sizeof(*myres));

        myres->conn = dbi_conn_new(driver);
        if (myres->conn == NULL) {
            ap_log_perror(APLOG_MARK, APLOG_EMERG, 0, r,
                          "[mod_ftpd_dbi.c] DBI Connection Failed. dbi_conn_new returned NULL.");
            rv = !APR_SUCCESS;
            /*
             * modules/ssl/ssl_engine_log.c:103
             *  said this was okay. so i do it.
             */
            exit(1);
        }
        else {
            dbi_conn_set_option(myres->conn, "host", (char *)host);
            dbi_conn_set_option(myres->conn, "username", (char *)user);
            dbi_conn_set_option(myres->conn, "password", (char *)pwd);
            dbi_conn_set_option(myres->conn, "dbname", (char *)name);
            if (dbi_conn_connect(myres->conn) != 0) {
                err_num = dbi_conn_error(myres->conn, (const char **)&err_str);
                /* Connetion Failed */
                ap_log_perror(APLOG_MARK, APLOG_ERR, 0, r,
                              "[mod_ftpd_dbi.c] DBI Connection to %s://%s@%s/%s Failed. Error: (%d) %s",
                              driver, user, host, name, err_num, err_str);
                rv = !APR_SUCCESS;
            }
            else {
                ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "[mod_ftpd_dbi.c] Connection was created sucessfully");
            }
        }
        *resource = myres;
    }
    else {
        /* Error -- we have too many TOTAL DBI Connections. Maybe a Evil User trying to hurt our system? */
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, r,
                      "[mod_ftpd_dbi.c] DBI Connection Failed. Hard Max Limit of %d Connections has been reached",
                      DBI_HARD_MAX_CONNS);
        /* we didn't create a new connection! */
        dbi_conn_count--;
        rv = !APR_SUCCESS;
    }
    return rv;
}


static apr_status_t safe_dbi_kill_conn(void *resource, void *params,
                                       apr_pool_t * pool)
{
/*    dbi_config_rec *conf = params; */
    ftpd_dbi_rest *res = resource;
    ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, pool,
                  "[mod_ftpd_dbi.c] Disconnecting from Server");
    dbi_conn_close(res->conn);

    dbi_conn_count--;

    return APR_SUCCESS;
}

static ftpd_dbi_config *create_new_conf(conn_id conn_id, apr_pool_t * p)
{
    ftpd_dbi_config *conf;
    conf = (ftpd_dbi_config *) apr_pcalloc(p, sizeof(ftpd_dbi_config));
    if (conf == NULL) {
        return NULL;
    }
    conf->rec.dbi_name = DFLT_DBI_NAME;
    conf->rec.dbi_driver = DFLT_DBI_DRIVER;
    conf->rec.dbi_host = DFLT_DBI_HOST;
    conf->rec.dbi_user = DFLT_DBI_USER;
    conf->rec.dbi_pass = DFLT_DBI_PASS;
    conf->rec.dbi_table = DFLT_DBI_TABLE;
    conf->rec.username_field = DFLT_USERNAME_FIELD;
    conf->rec.chroot_field = DFLT_CHROOT_FIELD;
    conf->rec.chroot_query = DFLT_CHROOT_QUERY;
    conf->rec.isactive_field = DFLT_ACTIVE_FIELD;
    conf->rec.conn_min = DFLT_CONN_MIN;
    conf->rec.conn_soft = DFLT_CONN_SOFT;
    conf->rec.conn_max = DFLT_CONN_MAX;
    conf->rec.conn_ttl = DFLT_CONN_TTL;
    conf->rec.options = DFLT_OPTIONS;
    apr_hash_set(ftpd_dbi_config_hash, conn_id, APR_HASH_KEY_STRING, conf);
    ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, p,
                  "[mod_ftpd_dbi.c] Creating Config for %s", conn_id);
    return conf;
}

static apr_status_t get_or_create_dbi_conf(const char *conn_id,
                                           apr_pool_t * p,
                                           ftpd_dbi_config ** confname)
{
    ftpd_dbi_config *temp;
    unsigned int c;

    /* some sanity checks on conn_id..limits are liberal and are more or less random */
    if (strlen(conn_id) > 255) {
        return !APR_SUCCESS;
    }
    for (c = 0; c < strlen(conn_id); c++) {
        if (conn_id[c] < ' ') {
            return !APR_SUCCESS;
        }
    }
    temp = apr_hash_get(ftpd_dbi_config_hash, conn_id, APR_HASH_KEY_STRING);
    if (temp == NULL) {
        /* no such server yet... */
        temp = create_new_conf(conn_id, p);
    }
    *confname = temp;
    return APR_SUCCESS;
}

#define QUERYSTRING_MAGIC_CHAR '&'
#define QUERYSTRING_LEFT_DELIM_CHAR '{'
#define QUERYSTRING_RIGHT_DELIM_CHAR '}'

#define EMPTY_VAR ""            /* do NOT set this to NULL! */

/* with a little help from ap_resolve_env() ;) */
static const char *populate_querystring(const request_rec * r,
                                 const char *querystring,
                                 ftpd_dbi_config * conf,
                                 ftpd_dbi_dconfig * dconf,
                                 ftpd_dbi_rest * dbi_res, const char *user)
{

    char tmp[MAX_STRING_LEN];   /* 8 KByte should be enough for everyone :) */
    const char *s, *e;
    char *p;
    int written = 0;
    tmp[0] = '\0';

    if (!(s = ap_strchr_c(querystring, QUERYSTRING_MAGIC_CHAR)))
        return querystring;

    do {
        written += (s - querystring);
        if (written >= MAX_STRING_LEN) {
            ap_log_perror(APLOG_MARK, APLOG_ERR, 0, r->pool,
                          "[mod_ftpd_dbi.c] Populated string would exceed %d bytes",
                          MAX_STRING_LEN);
            return NULL;
        }
        strncat(tmp, querystring, s - querystring);

        if ((s[1] == QUERYSTRING_LEFT_DELIM_CHAR)
            && (e = ap_strchr_c(s, QUERYSTRING_RIGHT_DELIM_CHAR))) {
            const char *e2 = e;
            char *var;
            p = NULL;
            querystring = e + 1;
            e = NULL;
            var = apr_pstrndup(r->pool, s + 2, e2 - (s + 2));

            if (!strcasecmp(var, "GivenUsername")) {
                e = (user ? user : EMPTY_VAR);
            }
            else if (!strcasecmp(var, "RequestHostname")) {
                e = (r->hostname ? r->hostname : EMPTY_VAR);
            }
            else if (!strcasecmp(var, "Name")) {
                e = (conf->rec.dbi_name ? conf->rec.dbi_name : EMPTY_VAR);
            }
            else if (!strcasecmp(var, "ConfigHostname")) {
                e = (r->server->server_hostname ? r->server->
                     server_hostname : EMPTY_VAR);
            }
            /* Everything but the variable values representing fieldnames and tables gets
             * escaped according to the selected driver */

            if (e != NULL) {
                p = strdup(e);
                dbi_driver_quote_string(dbi_conn_get_driver(dbi_res->conn),
                                        &p);
            }
            if (!strcasecmp(var, "UsernameField")) {
                e = (conf->rec.username_field ? conf->rec.
                     username_field : EMPTY_VAR);
            }
            else if (!strcasecmp(var, "ChrootField")) {
                e = (conf->rec.chroot_field ? conf->rec.
                     chroot_field : EMPTY_VAR);
            }
            else if (!strcasecmp(var, "IsActiveField")) {
                e = (conf->rec.isactive_field ? conf->rec.
                     isactive_field : EMPTY_VAR);
            }
            else if (!strcasecmp(var, "Table")) {
                e = (conf->rec.dbi_table ? conf->rec.dbi_table : EMPTY_VAR);
            }

            if (e == NULL) {
                ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, r->pool,
                              "[mod_ftpd_dbi.c] Unknown variable: %s", var);
                return NULL;
            }
            if (p == NULL) {
                p = strdup(e);
            }
            written += strlen(p);
            if (written >= MAX_STRING_LEN) {
                ap_log_perror(APLOG_MARK, APLOG_ERR, 0, r->pool,
                              "[mod_ftpd_dbi.c] Populated string would exceed %d bytes",
                              MAX_STRING_LEN);
                free(p);
                return NULL;
            }
            strcat(tmp, p);
            free(p);

        }
        else {
            ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, r->pool,
                          "[mod_ftpd_dbi.c] Invalid querystring");
            return NULL;

        };

    } while ((s = ap_strchr_c(querystring, QUERYSTRING_MAGIC_CHAR)));
    strcat(tmp, querystring);
    written += strlen(querystring);
    ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, r->pool,
                  "[mod_ftpd_dbi.c] Populated result: \"%s\" / %d chars written",
                  apr_pstrdup(r->pool, tmp), written);

    return apr_pstrdup(r->pool, tmp);
}


static conn_id encap_conn_id(cmd_parms * cmd, const char *conn_id)
{
    /* this will be used to allow configuration in htaccess */
    return conn_id;
}

static const char *set_dbi_switch_conf(cmd_parms * cmd, void *config,
                                       const char *conn_id, const char *value)
{
    apr_ssize_t pos = (apr_ssize_t) cmd->info;
    ftpd_dbi_config *temp;
    if ((get_or_create_dbi_conf
         (encap_conn_id(cmd, conn_id), cmd->pool, &temp)) == APR_SUCCESS) {

        /* Overwriting an existing value technically is a memory leak, since the pconf pool is only
         * destroyed at the termination of the whole apache process. Otoh, when processing htaccess,
         * we get handed the request-pool instead which is freed afterwards, so we should be fine. */
        switch (pos) {
        case CONF_DBI_DRIVER:
            temp->rec.dbi_driver = value;
            break;
        case CONF_DBI_HOST:
            temp->rec.dbi_host = value;
            break;
        case CONF_DBI_USERNAME:
            temp->rec.dbi_user = value;
            break;
        case CONF_DBI_PASSWORD:
            temp->rec.dbi_pass = value;
            break;
        case CONF_DBI_NAME:
            temp->rec.dbi_name = value;
            break;
        case CONF_DBI_TABLE:
            temp->rec.dbi_table = value;
            break;
        case CONF_DBI_USERNAME_FIELD:
            temp->rec.username_field = value;
            break;
        case CONF_DBI_CHROOT_FIELD:
            temp->rec.chroot_field = value;
            break;
        case CONF_DBI_CHROOT_QUERY:
            temp->rec.chroot_query = value;
            break;
        case CONF_DBI_IS_ACTIVE_FIELD:
            temp->rec.isactive_field = value;
            break;
        case CONF_DBI_CONN_MIN:
            temp->rec.conn_min = atoi(value);
            break;
        case CONF_DBI_CONN_SOFTMAX:
            temp->rec.conn_soft = atoi(value);
            break;
        case CONF_DBI_CONN_HARDMAX:
            temp->rec.conn_max = atoi(value);
            break;
        case CONF_DBI_CONN_TTL:
            temp->rec.conn_ttl = atoi(value);
            break;
        default:
            // unknown config directive?
            break;
        }
    }
    return NULL;
}

static const char *set_dbi_driverdir(cmd_parms * cmd, void *config,
                                     const char *field)
{
    if (dbi_global_config.driverdir != NULL) {
        ap_log_perror(APLOG_MARK, APLOG_WARNING, 0, cmd->pool,
                      "[mod_ftpd_dbi.c] Overwriting previous FtpDbiDriver value with new value %s",
                      dbi_global_config.driverdir);
    }
    dbi_global_config.driverdir = field;
    return NULL;
}

static const char *set_ddbi_conn(cmd_parms * cmd, void *config,
                                 const char *field)
{
    ftpd_dbi_config *conf;

    /* we dont use get_or_create_dbi_conf here because we just look, and don't touch */
    if ((conf =
         apr_hash_get(ftpd_dbi_config_hash, field, APR_HASH_KEY_STRING))) {
        ((ftpd_dbi_dconfig *) config)->id = field;
    }
    else {
        ap_log_perror(APLOG_MARK, APLOG_ERR, 0, cmd->pool,
                      "[mod_ftpd_dbi.c] Unknown configuration %s", field);
    }
    return NULL;
}

static const command_rec ftpd_dbi_cmds[] = {

    /* global config items */

    AP_INIT_TAKE2("FtpDbiDriver", set_dbi_switch_conf,
                  (void *) CONF_DBI_DRIVER, RSRC_CONF,
                  "The DBI Driver"),
    AP_INIT_TAKE1("FtpDbiDriverDir", set_dbi_driverdir,
                  (void *) CONF_DBI_DRIVER_DIR, RSRC_CONF,
                  "The directory containing the DBI drivers"),
    AP_INIT_TAKE2("FtpDbiHost", set_dbi_switch_conf, (void *) CONF_DBI_HOST,
                  RSRC_CONF,
                  "The host for the database connection"),
    AP_INIT_TAKE2("FtpDbiUsername", set_dbi_switch_conf,
                  (void *) CONF_DBI_USERNAME, RSRC_CONF,
                  "The username for the database connection"),
    AP_INIT_TAKE2("FtpDbiPassword", set_dbi_switch_conf,
                  (void *) CONF_DBI_PASSWORD, RSRC_CONF,
                  "The password for the database connection"),
    AP_INIT_TAKE2("FtpDbiName", set_dbi_switch_conf, (void *) CONF_DBI_NAME,
                  RSRC_CONF,
                  "The name of the database containing the tables"),
    AP_INIT_TAKE2("FtpDbiTable", set_dbi_switch_conf,
                  (void *) CONF_DBI_TABLE, RSRC_CONF,
                  "The name of the table containing the usernames and password hashes"),
    AP_INIT_TAKE2("FtpDbiUsernameField", set_dbi_switch_conf,
                  (void *) CONF_DBI_USERNAME_FIELD, RSRC_CONF,
                  "The table field that contains the username"),
    AP_INIT_TAKE2("FtpDbiChrootField", set_dbi_switch_conf,
                  (void *) CONF_DBI_CHROOT_FIELD,
                  RSRC_CONF,
                  "The table field that contains the password"),
    AP_INIT_TAKE2("FtpDbiChrootQuery", set_dbi_switch_conf,
                  (void *) CONF_DBI_CHROOT_QUERY,
                  RSRC_CONF,
                  "The SQL query to pick the password field from"),
    AP_INIT_TAKE2("FtpDbiIsActiveField", set_dbi_switch_conf,
                  (void *) CONF_DBI_IS_ACTIVE_FIELD,
                  RSRC_CONF,
                  "The table field that contains the username"),
    AP_INIT_TAKE2("FtpDbiConnMin", set_dbi_switch_conf,
                  (void *) CONF_DBI_CONN_MIN, RSRC_CONF,
                  "The Minimum Number of Database Connections"),
    AP_INIT_TAKE2("FtpDbiConnSoftMax", set_dbi_switch_conf,
                  (void *) CONF_DBI_CONN_SOFTMAX, RSRC_CONF,
                  "The Soft Maximum Number of Database Connections"),
    AP_INIT_TAKE2("FtpDbiConnHardMax", set_dbi_switch_conf,
                  (void *) CONF_DBI_CONN_HARDMAX, RSRC_CONF,
                  "The Hard Maximum Number of Database Connections"),
    AP_INIT_TAKE2("FtpDbiConnTTL", set_dbi_switch_conf,
                  (void *) CONF_DBI_CONN_TTL, RSRC_CONF,
                  "The Database Pool Time To Live for Each Connection."),

    /* per auth section */
    AP_INIT_TAKE1("FtpDbiServerConfig", set_ddbi_conn, NULL, OR_AUTHCFG,
                  "The name of the configuration to use for this section"),
    {NULL}
};


static void *create_ftpd_dbi_dir_config(apr_pool_t * p, char *d)
{
    ftpd_dbi_dconfig *conf;
    if (d == NULL) {
        return NULL;
    }
    conf = (ftpd_dbi_dconfig *) apr_pcalloc(p, sizeof(ftpd_dbi_dconfig));
    if (conf) {
        conf->id = NULL;
    }
    return conf;
}

static void *create_ftpd_dbi_config(apr_pool_t * p, server_rec * s)
{
    /* TODO: fix this.... this is very bad... */
    return NULL;
}

static apr_status_t safe_dbi_rel_server(apr_reslist_t * ftpd_dbi_pool,
                                        ftpd_dbi_rest * server,
                                        const request_rec * r)
{
    apr_status_t rv;
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "[mod_ftpd_dbi.c] Returning Server Connection to DBI Pool");
    rv = apr_reslist_release(ftpd_dbi_pool, (void **) server);
    return rv;
}
static int safe_dbi_query(ftpd_dbi_rest * mydbi_res, dbi_result * res,
                          const request_rec * r, const char *query)
{
    int err_num = 0;
    const char *err_str;
    int error = 1;

    *res = (dbi_result) dbi_conn_query(mydbi_res->conn, query);

    /* logging complete sql queries is bad. I personaly
     * uncomment this for some debuging... but even
     * APLOG_DEBUG isn't good for this.
     */
    /* ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
     *                   "[mod_ftpd_dbi.c] SQL Query: %s", query);
     */


    if (res == NULL) {
        err_num = dbi_conn_error(mydbi_res->conn, (const char **)&err_str);
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                      "[mod_ftpd_dbi.c] SQL Query Failed.  DBI said: (%d) %s",
                      err_num, err_str);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "[mod_ftpd_dbi.c] Query Result is good.");
        error = 0;
    }
    return error;
}

static ftpd_chroot_status_t ftpd_dbi_map_chroot(const request_rec *r,
                                          const char **ret_chroot,
                                          const char **ret_initroot)
{
    ftpd_chroot_status_t ARV = FTPD_CHROOT_USER_NOT_FOUND;
    ftpd_dbi_config *conf;
    const char *query;
    const char *chroot;
    ftpd_dbi_rest *dbi_res;
    dbi_result result;
    ftpd_dbi_dconfig *dconf = ap_get_module_config(r->per_dir_config,
                                                  &ftpd_dbi_module);


    conf = apr_hash_get(ftpd_dbi_config_hash, dconf->id, APR_HASH_KEY_STRING);
    if (conf == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "[mod_ftpd_dbi.c] - Server Config for \"%s\" was not found",
                      dconf->id);
        return FTPD_CHROOT_FAIL;
    }

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "[mod_ftpd_dbi.c] Attempting to Acquire DBI Connection");
    apr_reslist_acquire(conf->pool, (void **) &dbi_res);

    /* make the query to get the user's password */
    if (conf->rec.isactive_field) {
        if (conf->rec.chroot_query == NULL) {
            query =
                "SELECT &{ChrootField} FROM &{Table} WHERE &{UsernameField}=&{GivenUsername} AND &{IsActiveField}!=0 LIMIT 0,1";
        }
        else {
            query = conf->rec.chroot_query;
        }
    }
    else {
        if (conf->rec.chroot_query == NULL) {
            query =
                "SELECT &{ChrootField} FROM &{Table} WHERE &{UsernameField}=&{GivenUsername} LIMIT 0,1";
        }
        else {
            query = conf->rec.chroot_query;
        }
    }
    /* perform the query */

    if ((query =
         populate_querystring(r, query, conf, dconf, dbi_res, r->user))
        && safe_dbi_query(dbi_res, &result, r, query) == 0) {
        /* store the query result */
        if (dbi_result_next_row(result)
            && dbi_result_get_numrows(result) == 1) {

            chroot =
                dbi_result_get_string_copy(result, conf->rec.chroot_field);
            if ((chroot == NULL) || (strcmp(chroot, "ERROR") == 0)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "[mod_ftpd_dbi.c] - libdbi returned an error when retrieving the chroot.");
                ARV = FTPD_CHROOT_FAIL;
            }
            else {
                // XXXX: Do more checks of the chroot here!
                *ret_chroot = apr_pstrdup(r->pool, chroot);
                ARV = FTPD_CHROOT_USER_FOUND;
            }
        }
        else {
            if (dbi_result_get_numrows(result) == 0) {
                ARV = FTPD_CHROOT_USER_NOT_FOUND;
            }
            else {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "[mod_ftpd_dbi.c] %lu row(s) was not returned by dbi_result_get_numrows(result)",
                              (unsigned long) dbi_result_get_numrows(result));
                ARV = FTPD_CHROOT_FAIL;
            }
        }
        dbi_result_free(result);
    }
    else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                      "[mod_ftpd_dbi.c] Query Failed!");
        ARV = FTPD_CHROOT_FAIL;
    }

    safe_dbi_rel_server(conf->pool, dbi_res, r);
    return ARV;
}

/* Module initialization structures */

static const ftpd_provider ftpd_dbi_provider = {
    ftpd_dbi_map_chroot,      /* map_chroot */
	NULL
};


static apr_status_t init_ftpd_dbi_config(apr_pool_t * pconf,
                                        apr_pool_t * plog, apr_pool_t * ptemp)
{
    apr_status_t rv = APR_SUCCESS;
    /* create our globalish config var */
    ftpd_dbi_config_hash = apr_hash_make(pconf);
    return rv;
}

static apr_status_t kill_dbi(void *p)
{
    apr_status_t rv = APR_SUCCESS;
    apr_hash_index_t *idx;
    char *key;
    ftpd_dbi_config *val;
    apr_ssize_t len;

    for (idx = apr_hash_first((apr_pool_t *) p, ftpd_dbi_config_hash); idx;
         idx = apr_hash_next(idx)) {
        apr_hash_this(idx, (void *) &key, &len, (void *) &val);
        apr_reslist_destroy(val->pool);
    }
    dbi_shutdown();

    return rv;
}

static apr_status_t init_ftpd_dbi(apr_pool_t * p, apr_pool_t * plog,
                                 apr_pool_t * ptemp, server_rec * s)
{
    apr_status_t rv = APR_SUCCESS;
    int rval;
    dbi_driver dbi_driver;
    void *data;
    apr_hash_index_t *idx;
    char *key;
    ftpd_dbi_config *val;
    apr_ssize_t len;
    const char *userdata_key = "mod_ftpd_dbi_init";
/*    dbi_config *conf = ap_get_module_config(s->module_config,
 *                                                    &ftpd_dbi_module); */

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);

    ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, plog,
                              "[mod_ftpd_dbi.c] init.");

    if (!data) {
        apr_pool_userdata_set((const void *) 1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);
        return OK;
    }
    ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, p,
                  "[mod_ftpd_dbi.c] Running DBI init Code");

    if ((rval = dbi_initialize(dbi_global_config.driverdir)) > 0) {
        if (dbi_global_config.driverdir == NULL) {
            ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, plog,
                          "[mod_ftpd_dbi.c] Initialization of libdbi found %d drivers in default driver directory",
                          rval);
        }
        else {
            ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, plog,
                          "[mod_ftpd_dbi.c] Initialization of libdbi found %d drivers in directory %s",
                          rval, dbi_global_config.driverdir);
        }
        if (s->loglevel >= APLOG_DEBUG) {
            dbi_driver = NULL;
            while ((dbi_driver = dbi_driver_list(dbi_driver)) != NULL) {
                ap_log_perror(APLOG_MARK, APLOG_DEBUG, 0, plog,
                              "[mod_ftpd_dbi.c] Driver '%s' was loaded.",
                              dbi_driver_get_name(dbi_driver));
            }
        }
    }
    else {                      /* An error was returned or libdbi found 0 drivers */
        if (dbi_global_config.driverdir == NULL) {
            ap_log_perror(APLOG_MARK, APLOG_EMERG, 0, plog,
                          "[mod_ftpd_dbi.c] - Initlialization of libdbi with default driver directory failed");
        }
        else {
            ap_log_perror(APLOG_MARK, APLOG_EMERG, 0, plog,
                          "[mod_ftpd_dbi.c] - Initlialization of libdbi with FtpDbiDriverDir %s failed",
                          dbi_global_config.driverdir);
        }
        return !APR_SUCCESS;
    }

    /* loop the hashed config stuff... */
    for (idx = apr_hash_first(p, ftpd_dbi_config_hash); idx;
         idx = apr_hash_next(idx)) {
        apr_hash_this(idx, (void *) &key, &len, (void *) &val);
        apr_reslist_create(&val->pool, val->rec.conn_min,       /* hard minimum */
                           val->rec.conn_soft,  /* soft maximum */
                           val->rec.conn_max,   /* hard maximum */
                           val->rec.conn_ttl,   /* Time to live -- dbi server might override/disconnect! */
                           safe_dbi_new_conn,   /* Make a New Connection */
                           safe_dbi_kill_conn,  /* Kill Old Connection */
                           (void *) &val->rec, p);
        apr_hash_set(ftpd_dbi_config_hash, key, APR_HASH_KEY_STRING, val);
    }
    apr_pool_cleanup_register(p, p, kill_dbi, apr_pool_cleanup_null);

    ap_add_version_component(p, "mod_ftpd_dbi/" MOD_FTPD_DBI_VERSION);

    return rv;
}



static void register_hooks(apr_pool_t * p)
{
    ap_hook_pre_config(init_ftpd_dbi_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(init_ftpd_dbi, NULL, NULL, APR_HOOK_MIDDLE);
    ap_register_provider(p, FTPD_PROVIDER_GROUP, "dbi", "0",
		&ftpd_dbi_provider);
}

module AP_MODULE_DECLARE_DATA ftpd_dbi_module = {
    STANDARD20_MODULE_STUFF,
    create_ftpd_dbi_dir_config,  /* create per-directory config structure */
    NULL,                       /* merge per-directory config structures */
    create_ftpd_dbi_config,      /* create per-server config structure */
    NULL,                       /* merge per-server config structures */
    ftpd_dbi_cmds,               /* command apr_table_t */
    register_hooks              /* register hooks */
};
