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
#define CORE_PRIVATE
#include "httpd.h"
#include "http_protocol.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_core.h"
#include "http_request.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_md5.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_buckets.h"
#include "apr_network_io.h"
#include "util_filter.h"
#include "util_time.h"
#include "scoreboard.h"

#include "ftp.h"

extern int ftpd_methods[FTPD_M_LAST];

/* close a data connection */
static int ftpd_data_socket_close(ftpd_user_rec *ur)
{
	switch (ur->data.type) {
	case FTPD_PIPE_OPEN:
		apr_socket_close(ur->data.pipe);
		break;
	case FTPD_PIPE_PASV:
		apr_socket_close(ur->data.pasv);
		break;
	default:
		break;
	}
	apr_pool_clear(ur->data.p);
	ur->data.type = FTPD_PIPE_NONE;
	ur->state = FTPD_STATE_TRANS_NODATA;
	return OK;
}

/* open a data connection */
static int ftpd_data_socket_connect(ftpd_user_rec *ur, ftpd_svr_config_rec *pConfig)
{
	apr_status_t res=-1;

	switch (ur->data.type) {
	case FTPD_PIPE_PASV:
		res = apr_socket_accept(&ur->data.pipe, ur->data.pasv, ur->data.p);
		apr_socket_close(ur->data.pasv);
		if (!pConfig->bAllowFXP) {
			apr_sockaddr_t *data;
			char *ip_data;
			apr_socket_addr_get(&data, APR_REMOTE, ur->data.pipe);
			apr_sockaddr_ip_get(&ip_data,data);
			if (!apr_sockaddr_equal(data, ur->c->remote_addr)) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, ur->s,
					"Data connection from foreign host: %s", ip_data);
				apr_socket_close(ur->data.pipe);
				apr_pool_clear(ur->data.p);
				return APR_ECONNREFUSED;
			}
		}
		ur->data.type = FTPD_PIPE_OPEN;
		ur->state = FTPD_STATE_TRANS_NODATA;
		break;
	case FTPD_PIPE_PORT:
		apr_socket_create(&ur->data.pipe, ur->data.port->family,
			SOCK_STREAM, APR_PROTO_TCP, ur->data.p);
		res = apr_socket_connect(ur->data.pipe, ur->data.port);
		ur->data.type = FTPD_PIPE_OPEN;
		ur->state = FTPD_STATE_TRANS_NODATA;
		break;
	default:
		break;
	}
	return res;
}


static ftpd_chroot_status_t ftpd_call_chroot(ftpd_svr_config_rec *pConfig, request_rec *r,
					const char **chroot, const char **initroot)
{
	ftpd_provider_list *current_provider;
	for (current_provider = pConfig->chroots;
			current_provider;
			current_provider = current_provider->next)
	{
		ftpd_chroot_status_t chroot_ret;
		const ftpd_provider *provider;
		provider = current_provider->provider;

		if (! provider->map_chroot) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"Provider '%s' does not provider chroot mapping.",
				current_provider->name);
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
				"Chroot provider %s", current_provider->name);
			chroot_ret = provider->map_chroot(r, chroot, initroot);
			if (chroot_ret == FTPD_CHROOT_USER_FOUND) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
					"Chroot set to %s", *chroot);
				return FTPD_CHROOT_USER_FOUND;
			} else if (chroot_ret == FTPD_CHROOT_FAIL) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"User denied access to server");
				ap_rprintf(r, FTP_C_NOLOGIN" Login not allowed\r\n");
				ap_rflush(r);
				return FTPD_CHROOT_FAIL;
			} else { /* FTPD_CHROOT_USER_NOT_FOUND*/
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
					"User not found in chroot provider. Continuing");
			}
		}
	}
	return FTPD_CHROOT_USER_NOT_FOUND;
}

static ftpd_limit_status_t ftpd_call_limit(ftpd_svr_config_rec *pConfig,
										request_rec *r, ftpd_limit_check_t check_type)
{
	ftpd_provider_list *current_provider;
	for (current_provider = pConfig->limits;
			current_provider;
			current_provider = current_provider->next)
	{
		ftpd_limit_status_t limit_ret;
		const ftpd_provider *provider;
		provider = current_provider->provider;

		if (! provider->limit_check) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"Provider '%s' does not provider limit support.",
				current_provider->name);
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
				"Limit provider %s", current_provider->name);
			limit_ret = provider->limit_check(r,check_type);
			if (limit_ret == FTPD_LIMIT_TOOMANY) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"Too many users logged in.");
				return FTPD_LIMIT_TOOMANY;
			} else if (limit_ret == FTPD_LIMIT_ALLOW) {
				/* This one says we can login, lets check the next */
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
					"Limit ALLOW, Contining.");
			} else { /* FTPD_LIMIT_DEFAULT */
				/* this is only hit during checkin/checkout */
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
					"Check%s called: %s", 
					check_type==FTPD_LIMIT_CHECKIN?"in":"out",
					current_provider->name);
			}
		}
	}
	return check_type==FTPD_LIMIT_CHECK?FTPD_LIMIT_ALLOW:FTPD_LIMIT_DEFAULT;
}

static apr_status_t ftpd_limit_checkout(void *r)
{
	ftpd_svr_config_rec *pConfig = ap_get_module_config(((request_rec *)r)->server->module_config,
					&ftpd_module);
	ftpd_call_limit(pConfig, r, FTPD_LIMIT_CHECKOUT);
	return APR_SUCCESS;
}

/* Creates a sub request record for handlers */
static request_rec *ftpd_create_subrequest(request_rec *r, ftpd_user_rec *ur)
{
	apr_pool_t *rrp;
	request_rec *rnew;
	apr_pool_create(&rrp, r->pool);

	rnew = apr_pcalloc(rrp, sizeof(request_rec));
	rnew->pool = rrp;

	rnew->hostname 		= r->hostname;
	rnew->request_time 	= r->request_time;
	rnew->connection 	= r->connection;
	rnew->server		= r->server;

	rnew->user			= r->user;
	rnew->ap_auth_type	= r->ap_auth_type;

	rnew->request_config = ap_create_request_config(rnew->pool);

	rnew->per_dir_config = r->server->lookup_defaults;

	rnew->htaccess = r->htaccess;
	rnew->allowed_methods = ap_make_method_list(rnew->pool, 2);

	ap_copy_method_list(rnew->allowed_methods, r->allowed_methods);

	ap_set_sub_req_protocol(rnew, r);

	rnew->assbackwards = 0;
	rnew->protocol = "FTP";
	ap_run_create_request(rnew);

/* TODO: Play with filters in create subreq??? */
	rnew->output_filters = r->connection->output_filters;
	rnew->input_filters = r->connection->input_filters;
	
	ap_set_module_config(rnew->request_config, &ftpd_module, ur);
	return rnew;
}

#define ftpd_check_acl(r) ap_process_request_internal(r)
/*#define ftpd_check_acl(r) ftpd_check_acl_ex(NULL,r,0)*/

static int ftpd_check_acl_ex(const char *newpath, request_rec *r, int skipauth) 
{
	apr_status_t res;
	if (newpath) {
		r->uri = apr_pstrdup(r->pool, newpath);
	} // else assume uri has already been updated

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		"Checking Method: %s (%d)", r->method, r->method_number);

	if ((res = ap_location_walk(r)) != OK) {
		return res;
	}
	if ((res = ap_run_translate_name(r)) != OK) {
		return res;
	}
	if ((res = ap_run_map_to_storage(r)) != OK) {
		return res;
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		"URI %s -> %s", r->uri, r->filename);
	if ((res = ap_location_walk(r)) != OK) {
		return res;
	}	
	if ((res = ap_run_access_checker(r)) != OK) {
		return res;
	}
	/* User authentication checks */
	if (!skipauth) {
		if ((res = ap_run_check_user_id(r)) != OK) {
			return res;
		}
		if ((res = ap_run_auth_checker(r)) != OK) {
			return res;
		}
	}
	return APR_SUCCESS;
}


typedef enum {ASCII_TO_LF, ASCII_TO_CRLF} ascii_direction;
static char *ftpd_ascii_convert(char *buf, apr_size_t *len, ascii_direction way, apr_pool_t *p)
{
	char *itr = buf;
	char *buf2;
	char temp[FTPD_IO_BUFFER_MAX*2];
	apr_size_t len_itr = 0;

	memset(temp, 0, FTPD_IO_BUFFER_MAX * 2);
	while ((itr - buf) < *len) {
		switch (way) {
		case ASCII_TO_CRLF:
			if (*itr == APR_ASCII_LF) {
				temp[len_itr++] = APR_ASCII_CR;
			}
			temp[len_itr++] = *itr;
			break;
		case ASCII_TO_LF:
			if (*itr != APR_ASCII_CR) {
				temp[len_itr++] = *itr;
			}
			break;
		}
		itr++;
	}
	*len = len_itr;
	buf2 = apr_palloc(p, *len);
	memcpy(buf2, temp, *len);
	return buf2;
}

int process_ftpd_connection_internal(request_rec *r, apr_bucket_brigade *bb)
{
	char cmdbuff[FTPD_STRING_LENGTH];
    char *buffer;	/* a pointer to cmdbuff */
	char *command;
    int invalid_cmd = 0;
    apr_size_t len;
    ftpd_handler_st *handle_func;
	apr_status_t res;
	request_rec *handler_r;
	apr_pool_t *p;
	apr_time_t request_time;
    ftpd_user_rec *ur = ftpd_get_user_rec(r);

	apr_pool_create(&p, r->pool);

	r->the_request = "IDLE";
	ap_update_child_status(r->connection->sbh, SERVER_BUSY_KEEPALIVE, r);
    while (1) {
		buffer = cmdbuff;   /* reset buffer pointer */
		apr_pool_clear(p);
        if ((invalid_cmd > MAX_INVALID_CMD) ||
            ap_rgetline(&buffer, FTPD_STRING_LENGTH, &len, r, 0, bb) != APR_SUCCESS)
        {
            break;
        }
		request_time = apr_time_now();
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
				"C:(%d)%s",len, buffer);
		/* This command moves the pointer of buffer to the end of the extracted string */
        command = ap_getword_white_nc(p, &buffer);
        ap_str_tolower(command);
        handle_func = apr_hash_get(ftpd_hash, command, APR_HASH_KEY_STRING);

        if (!handle_func) {
            ap_rprintf(r, FTP_C_BADCMD" '%s': command not understood.\r\n", command);
            ap_rflush(r);
            invalid_cmd++;
            continue;
        }
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"handler state: %X, epsv mode: %d", handle_func->states, ur->epsv_lock);
        if (!(handle_func->states & ur->state)
				|| ((handle_func->states & FTPD_FLAG_EPSV_LOCK) && ur->epsv_lock) ) {
			if ((ur->state == FTPD_STATE_AUTH)||(ur->state == FTPD_STATE_USER_ACK)) {
				ur->state = FTPD_STATE_AUTH;
				ap_rprintf(r, FTP_C_LOGINERR" '%s' Please login with USER and PASS.\r\n", command);
			} else if ((handle_func->states & FTPD_FLAG_EPSV_LOCK) &&  ur->epsv_lock) {
				ap_rprintf(r, FTP_C_BADSENDCONN" EPSV ALL mode in effect command %s disabled.\r\n", command);
			} else if (handle_func->states & FTPD_STATE_RENAME) {
				ap_rprintf(r, FTP_C_NEEDRNFR" '%s' RNTO requires RNFR first.\r\n", command);
			} else if (handle_func->states & FTPD_STATE_TRANS_DATA) {
				ap_rprintf(r, FTP_C_BADSENDCONN" '%s' Please Specify PASV, PORT, EPRT, EPSV first.\r\n", command);
			} else if (handle_func->states & FTPD_FLAG_NOT_IMPLEMENTED) {
				ap_rprintf(r, FTP_C_CMDNOTIMPL" '%s' Command not implemented on this server.\r\n", command);
			} else {
            	ap_rprintf(r, "500 '%s': command not allowed in this state\r\n", command);
			}
            ap_rflush(r);
            //invalid_cmd++;
            continue;
        }
		handler_r = ftpd_create_subrequest(r,ur);
		handler_r->request_time = request_time;
		ap_ftpd_str_toupper(command);
	
		if (handle_func->states & FTPD_FLAG_HIDE_ARGS) {
			handler_r->the_request = apr_pstrdup(handler_r->pool, command);
		} else {
			handler_r->the_request = apr_psprintf(handler_r->pool, "%s %s", command, buffer);
		}

		ap_update_child_status(r->connection->sbh, SERVER_BUSY_WRITE, handler_r);

       	res = handle_func->func(handler_r, buffer, handle_func->data);

		if (res == FTPD_HANDLER_PERMDENY) {
				handler_r->status = HTTP_FORBIDDEN;
		} else if ((res == FTPD_HANDLER_USER_NOT_ALLOWED) || (res == FTPD_HANDLER_USER_UNKNOWN)) {
				handler_r->status = HTTP_UNAUTHORIZED;
		} else if (res == FTPD_HANDLER_SERVERERROR) {
				handler_r->status = HTTP_INTERNAL_SERVER_ERROR;
		} else if (res == FTPD_HANDLER_FILENOTFOUND) {
				handler_r->status = HTTP_NOT_FOUND; /* 404'ed */
		}
		if (handle_func->states & FTPD_FLAG_LOG_COMMAND) {
			/* Make sure URI is URI escaped */
			if (handler_r->uri) {
				handler_r->uri = ap_escape_uri(handler_r->pool, handler_r->uri);
			} else {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"URI is empty!!");
			}
			ap_run_log_transaction(handler_r);			
		}

		ap_increment_counts(r->connection->sbh, handler_r);
		ap_update_child_status(r->connection->sbh, SERVER_BUSY_KEEPALIVE, r);

		if (res == FTPD_HANDLER_UPDATE_AUTH) {
			/* Assign to master request_rec for all subreqs */
			r->user = apr_pstrdup(r->pool, ur->user);
		    apr_table_set(r->headers_in, "Authorization", ur->auth_string);
			r->ap_auth_type = apr_pstrdup(r->pool, handler_r->ap_auth_type);
		} else if (res == FTPD_HANDLER_UPDATE_AGENT) {
			apr_table_set(r->headers_in, "User-Agent", ur->useragent);
		} else if (res == FTPD_HANDLER_QUIT) {
            break;
        }
		apr_pool_destroy(handler_r->pool);
    }
	if (ur->state & FTPD_STATE_TRANSACTION) {
		
	}
    return FTPD_HANDLER_OK;
}

HANDLER_DECLARE(quit)
{
    ftpd_user_rec *ur = ftpd_get_user_rec(r);

    if (ur->state & FTPD_STATE_TRANSACTION) {
		/* TODO: Add logoff statistics */
        ap_rprintf(r, FTP_C_GOODBYE"-FTP Statistics go here.\r\n");
    }
	ap_rprintf(r, FTP_C_GOODBYE" Goodbye.\r\n");

    ap_rflush(r);
    ur->state = FTPD_STATE_AUTH;
    return FTPD_HANDLER_QUIT;
}

HANDLER_DECLARE(user)
{
	char *user;
    ftpd_user_rec *ur = ftpd_get_user_rec(r);

    user = ap_getword_white_nc(r->pool, &buffer);
    if (!strcmp(user, "")) {
        ap_rprintf(r, FTP_C_LOGINERR" Please login with USER and PASS.\r\n");
        ap_rflush(r);
        return FTPD_HANDLER_USER_NOT_ALLOWED;
    }
    ur->user = apr_pstrdup(ur->p, user);

    ap_rprintf(r, FTP_C_GIVEPWORD" Password required for %s.\r\n", ur->user);
    ap_rflush(r);    
	ur->state = FTPD_STATE_USER_ACK;
	return FTPD_HANDLER_OK;
}

HANDLER_DECLARE(passwd)
{
	char *passwd;
	apr_status_t res;
	ftpd_chroot_status_t chroot_ret;
	ftpd_limit_status_t limit_ret;
	const char *chroot = NULL,*initroot = NULL;
	ftpd_user_rec *ur = ftpd_get_user_rec(r);
	ftpd_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftpd_module);

	/* Get chroot mapping */
	
	r->user = apr_pstrdup(r->pool, ur->user);
	chroot_ret = ftpd_call_chroot(pConfig,r,&chroot,&initroot);
	if (chroot_ret == FTPD_CHROOT_FAIL)
		return FTPD_HANDLER_QUIT;

    passwd = apr_psprintf(r->pool, "%s:%s", ur->user,
                          ap_getword_white_nc(r->pool, &buffer));
    ur->auth_string = apr_psprintf(ur->p, "Basic %s",
                                   ap_pbase64encode(r->pool, passwd)); 
    apr_table_set(r->headers_in, "Authorization", ur->auth_string);

	if (chroot) {
		ur->chroot = apr_pstrdup(ur->p, chroot);
	} else {
		ur->chroot = NULL;
	}

	/* TODO: check to make sure this directory actually exists and fall back to chroot dir */
	if (initroot) {
		if (initroot[0]=='/') {
			ur->current_directory = apr_pstrdup(ur->p, initroot);
		} else {
			ur->current_directory = apr_pstrcat(ur->p, "/", initroot, NULL);
		}
	} else {
		ur->current_directory = apr_pstrdup(ur->p,"/");		
	}
/* CHDIR as we are changing into the root directory on login 
 * Probably not a good way to prevent logins but it works 
 */
	r->method = apr_pstrdup(r->pool, "CHDIR");
	r->method_number = ftpd_methods[FTPD_M_CHDIR];

	if ((res = ftpd_check_acl_ex(ur->current_directory, r, 1))!=OK) {
		ap_rprintf(r, FTP_C_NOLOGIN" Login not allowed\r\n");
		ap_rflush(r);
		/* Bail out immediatly if this occurs? */
		return FTPD_HANDLER_QUIT;
	}
	
    if ((res = ap_run_check_user_id(r)) != OK) {
        ap_rprintf(r, FTP_C_LOGINERR" Login incorrect\r\n");
        ap_rflush(r);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
               "Unauthorized user '%s' tried to log in:", ur->user);
        ur->state = FTPD_STATE_AUTH;
        return FTPD_HANDLER_USER_NOT_ALLOWED;
    }
	if ((res = ap_run_auth_checker(r)) != OK) {
		ap_rprintf(r, FTP_C_LOGINERR" Login denied\r\n");
		ap_rflush(r);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
               "Unauthorized user '%s' tried to log in:", ur->user);
		return FTPD_HANDLER_USER_UNKNOWN;
	}
	/* check to see if there is space in limits */
	limit_ret = ftpd_call_limit(pConfig, r, FTPD_LIMIT_CHECK);
	if (limit_ret == FTPD_LIMIT_TOOMANY) {
		ap_rprintf(r, FTP_C_NOLOGIN"-There are too many users logged in currently.\r\n");
		ap_rprintf(r, FTP_C_NOLOGIN" Please try agaom later.\r\n");
		ap_rflush(r);
		/* Too many users logged in */
		return FTPD_HANDLER_QUIT;
	}
	/* register login with limit provider */
	limit_ret = ftpd_call_limit(pConfig, r, FTPD_LIMIT_CHECKIN);
	/* register a checkout with session pool */
	apr_pool_cleanup_register(ur->p, (void *)r, ftpd_limit_checkout, apr_pool_cleanup_null);
	/* Report succsessful login */
    ap_rprintf(r, FTP_C_LOGINOK" User %s logged in.\r\n", ur->user);
    ap_rflush(r);
	ur->state = FTPD_STATE_TRANS_NODATA;
	return FTPD_HANDLER_UPDATE_AUTH;
}

HANDLER_DECLARE(pwd)
{
    ftpd_user_rec *ur = ftpd_get_user_rec(r);

	ap_rprintf(r, FTP_C_PWDOK" \"%s\" is current directory.\r\n",ur->current_directory);

    ap_rflush(r);
    return FTPD_HANDLER_OK;
}


HANDLER_DECLARE(cd)
{
	char *patharg;  /* incoming directory change */
	//char *newpath;	/* temp space for merged local path */
    ftpd_user_rec *ur = ftpd_get_user_rec(r);

	if ((int)data==1) {
		patharg = "..";
	} else {
    	patharg = buffer;
	}
	if (apr_filepath_merge(&r->uri,ur->current_directory,patharg, 
			APR_FILEPATH_TRUENAME, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid path.\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	}
	r->method = apr_pstrdup(r->pool, "CHDIR");
	r->method_number = ftpd_methods[FTPD_M_CHDIR];

	if (ftpd_check_acl(r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" Permission Denied.\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_PERMDENY;
	}

	if (!ap_is_directory(r->pool, r->filename)) {
		ap_rprintf(r, FTP_C_FILEFAIL" '%s': No such file or directory.\r\n",patharg);
    	ap_rflush(r);
	    return FTPD_HANDLER_FILENOTFOUND;
	} else {
		ur->current_directory = apr_pstrdup(ur->p,r->uri);
		ap_rprintf(r, FTP_C_CWDOK" CWD command successful.\r\n");
    	ap_rflush(r);
	    return FTPD_HANDLER_OK;
	}
}

HANDLER_DECLARE(help)
{
	char *command;
	int column;
	apr_hash_index_t* hash_itr;
	ftpd_handler_st *handle_func;
	int rv = FTPD_HANDLER_OK;

	command = ap_getword_white_nc(r->pool, &buffer);
	if (command[0]=='\0') {
		if (!(int)data) { /* HELP */
			ap_rprintf(r, FTP_C_HELPOK"-The following commands are implemented.\r\n");
		} else { /* FEAT */
			ap_rprintf(r, FTP_C_FEATOK"-FEAT\r\n");
		}
		column = 0;
		for (hash_itr = apr_hash_first(r->pool, ftpd_hash); hash_itr;
				hash_itr = apr_hash_next(hash_itr)) {
			apr_hash_this(hash_itr, (const void **)&command, NULL,(void **)&handle_func);
			command = apr_pstrdup(r->pool,command);
			ap_ftpd_str_toupper(command);
			if (!(int)data) { /* HELP */
				column++;
				ap_rprintf(r,"   %c%-4s",
					(handle_func->states & FTPD_FLAG_NOT_IMPLEMENTED)?'*':' ',
					command);
				if ((column % 7)==0) {
					ap_rputs("\r\n",r);
				}
			} else { /* FEAT */
				if (handle_func->states & FTPD_FLAG_FEATURE) {
					ap_rprintf(r,"    %-4s\r\n",command);
				}
			}
		}
		if (!(int)data) { /* HELP */
			if ((column % 7)!=0) {
				ap_rputs("\r\n",r);
			}
			ap_rprintf(r, FTP_C_HELPOK"-Use \"HELP command\" to get help for a specific command\r\n");
			ap_rprintf(r, FTP_C_HELPOK"-Command not implemented have a '*' next to them.\r\n");
			ap_rprintf(r, FTP_C_HELPOK" Send Comments %s.\r\n",r->server->server_admin);
		} else { /* FEAT */
			ap_rprintf(r, FTP_C_FEATOK" END\r\n");
		}
	} else {
		ap_str_tolower(command);
		handle_func = apr_hash_get(ftpd_hash, command, APR_HASH_KEY_STRING);
		/* Str to Upper */
		ap_ftpd_str_toupper(command);
		if (!handle_func) {
			ap_rprintf(r, FTP_C_BADHELP" Unknown command %s\r\n",command);
			rv = FTPD_HANDLER_SERVERERROR;
		} else {
			if (handle_func->states & FTPD_FLAG_NOT_IMPLEMENTED) {
				if (handle_func->help_text) {
					ap_rprintf(r, FTP_C_HELPOK"-Syntax: %s %s\r\n",command,handle_func->help_text);
				}
				ap_rprintf(r, FTP_C_HELPOK" This command is not implemented on this server.\r\n");
			} else {
				if (!handle_func->help_text) {
					ap_rprintf(r, FTP_C_HELPOK" Syntax: %s No Help Available.\r\n",command);
				} else {
					ap_rprintf(r, FTP_C_HELPOK" Syntax: %s %s\r\n",command,handle_func->help_text);
				}
			}
		}
	}
	ap_rflush(r);
	return rv;
}

HANDLER_DECLARE(syst)
{
	ap_rputs(FTP_C_SYSTOK" UNIX Type: L8\r\n",r);
	ap_rflush(r);
	return FTPD_HANDLER_OK;
}

HANDLER_DECLARE(NOOP)
{
	int rv = FTPD_HANDLER_OK;
	if (!data) {
		ap_rputs(FTP_C_NOOPOK" Command completed successfully.\r\n",r);
	} else {
		char *arg = ap_getword_white_nc(r->pool, &buffer);
		ap_str_tolower(arg);
		if (!apr_strnatcmp(arg, data)) {
			ap_rputs(FTP_C_NOOPOK" Command completed successfully.\r\n",r);
		} else {
			ap_rputs(FTP_C_INVALIDARG" Invalid argument.\r\n",r);
			rv = FTPD_HANDLER_SERVERERROR;
		}
	}
	ap_rflush(r);
	return rv;
}
HANDLER_DECLARE(clnt)
{
	ftpd_user_rec *ur = ftpd_get_user_rec(r);

	ur->useragent = apr_pstrdup(ur->p, buffer);
	ap_rputs(FTP_C_CLNTOK" Command completed successfully.\r\n",r);
	ap_rflush(r);
	return FTPD_HANDLER_UPDATE_AGENT;
}

HANDLER_DECLARE(pasv)
{
	apr_sockaddr_t *listen_addr, *local_addr = r->connection->local_addr;
	apr_port_t port;
	char *ipaddr;
	int family;
	apr_status_t res;
	ftpd_user_rec *ur = ftpd_get_user_rec(r);
	ftpd_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftpd_module);
	int bind_retries = 10;

/* Close old socket if already connected */
	ftpd_data_socket_close(ur);

	apr_sockaddr_ip_get(&ipaddr, local_addr);

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		"Ipaddr info. %s", ipaddr);
	/* Argument parsing */
	if (data) { /* EPSV command */
		family = apr_atoi64(buffer);
		if (apr_strnatcasecmp(buffer,"ALL")==0) {
			ur->epsv_lock = 1;
		} else if ( (family==1 && local_addr->family!=1)
				|| (family==2 && local_addr->family!=2)) {
			ap_rprintf(r, FTP_C_INVALID_PROTO" not same protocol as connection, use (%d)\r\n",
					local_addr->family);
			ap_rflush(r);
			return FTPD_HANDLER_SERVERERROR;
		} else if (family!=0) {
			ap_rprintf(r, FTP_C_INVALID_PROTO" Unsupported Protocol, use (1,2)\r\n");
			ap_rflush(r);
			return FTPD_HANDLER_SERVERERROR;
		}
	}
	family = local_addr->family;
/* Assign IP */
	if ((res = apr_sockaddr_info_get(&listen_addr, ipaddr, family, 0,
				0, ur->data.p)) != APR_SUCCESS) {
		ap_rprintf(r,FTP_C_PASVFAIL" Unable to assign socket addresss\r\n");
	}
	if ((res = apr_socket_create(&ur->data.pasv, family,
			SOCK_STREAM, APR_PROTO_TCP, ur->data.p)) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_PASVFAIL" Unable to create Socket\r\n");
	}
/* Bind to server IP and Port */
	while (--bind_retries) {
		apr_generate_random_bytes((unsigned char *)&port,2);
		port = ( (pConfig->nMaxPort - pConfig->nMinPort) * port) / 65535;
		port += pConfig->nMinPort;
		apr_sockaddr_info_get(&listen_addr,ipaddr, family, port, 0, ur->data.p);
		//apr_sockaddr_port_set(listen_addr,port);
		if ((res = apr_socket_bind(ur->data.pasv, listen_addr))==APR_SUCCESS) {
			break;
		}
	}
	if (!bind_retries) {
		ap_rprintf(r, FTP_C_PASVFAIL" Error Binding to address\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	}
	
/* open the socket in listen mode and allow 1 queued connection */
	apr_socket_listen(ur->data.pasv, 1);

	if (!data) { /* regular port command */
		if (family == APR_INET) { /* IPv4 */
			char *temp;
		/* Change .'s to ,'s */
			temp = ipaddr = apr_pstrdup(ur->data.p, r->connection->local_ip);
			while (*temp) {
				if (*temp=='.')
					*temp=',';
				++temp;
			}
			ap_rprintf(r,FTP_C_PASVOK" Entering Passive Mode (%s,%d,%d)\r\n",
				ipaddr, port >> 8, port & 255);
		} else {
			ap_rprintf(r,FTP_C_PASVOK" =127,555,555,555,%d,%d\r\n",
				port >> 8, port & 255);
		}
	} else { /* Eprt command */
		ap_rprintf(r, FTP_C_EPASVOK" Entering Extended Passive Mode (|||%d|)\r\n",
			port);
	}
	ap_rflush(r);
	ur->data.type = FTPD_PIPE_PASV;
	ur->state = FTPD_STATE_TRANS_DATA;
	return FTPD_HANDLER_OK;
}

HANDLER_DECLARE(port)
{
	int ip1,ip2,ip3,ip4,p1,p2;
	char *strfamily, *ipaddr, *strport;
	char tok_sep[2], *tok_sess;
	int family;
	apr_port_t port;
	ftpd_user_rec *ur = ftpd_get_user_rec(r);
	ftpd_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftpd_module);

	if (!pConfig->bAllowPort) {
		ap_rprintf(r, FTP_C_CMDDISABLED" PORT command not allowed on this server\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	}
/* Close old socket if already connected */
	ftpd_data_socket_close(ur);

	if (!data) { /* regular port cmmand */
		sscanf(buffer, "%d,%d,%d,%d,%d,%d",
			&ip1,&ip2,&ip3,&ip4,
			&p1,&p2);
		family = APR_INET;
		ipaddr = apr_psprintf(r->pool, "%d.%d.%d.%d",ip1,ip2,ip3,ip4);
		port = (p1<<8)+p2;
	} else { /* Extended port */
		tok_sep[0] = *buffer; /* first character is separator */
		tok_sep[1] = '\0';
		if ((strfamily = apr_strtok(buffer, tok_sep, &tok_sess))==NULL) {
			ap_rprintf(r, FTP_C_INVALIDARG" Invalid Argument\r\n");
			ap_rflush(r);
			return FTPD_HANDLER_SERVERERROR;
		}
		if ((ipaddr = apr_strtok(NULL, tok_sep, &tok_sess))==NULL) {
			ap_rprintf(r, FTP_C_INVALIDARG" Invalid Argument\r\n");
			ap_rflush(r);
			return FTPD_HANDLER_SERVERERROR;
		}
		if ((strport = apr_strtok(NULL, tok_sep, &tok_sess))==NULL) {
			ap_rprintf(r, FTP_C_INVALIDARG" Invalid Argument\r\n");
			ap_rflush(r);
			return FTPD_HANDLER_SERVERERROR;
		}
		port = apr_atoi64(strport);
		family = apr_atoi64(strfamily);
		if (family == 1) {
			family = APR_INET;
#if APR_HAVE_IPV6
		} else if (family == 2) {
			family = APR_INET6;
#endif
		} else {
			ap_rprintf(r, FTP_C_INVALID_PROTO" Unsupported Protocol, use (1,2)\r\n");
			ap_rflush(r);
			return FTPD_HANDLER_SERVERERROR;
		}
	}
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		"IP connect to client: %d - %s:%d", family, ipaddr, port);
	apr_sockaddr_info_get(&ur->data.port,ipaddr, family, port,
				0, ur->data.p);
	if (!pConfig->bAllowFXP) {
		char *ip_data;
		apr_sockaddr_ip_get(&ip_data,ur->data.port);
		if (!apr_sockaddr_equal(ur->data.port, r->connection->remote_addr)) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"Data connection from foreign host: %s", ip_data);
			ap_rprintf(r, FTP_C_CMDDISABLED" Port to foreign host not allowed %s\r\n",ip_data);
			ap_rflush(r);
			return FTPD_HANDLER_SERVERERROR;
		}
	}
	ap_rprintf(r, FTP_C_PORTOK" Command Successful\r\n");
	ap_rflush(r);
	ur->data.type = FTPD_PIPE_PORT;
	ur->state = FTPD_STATE_TRANS_DATA;
	return FTPD_HANDLER_OK;
}

HANDLER_DECLARE(list)
{
	apr_size_t retsize;
	apr_status_t res;
	apr_dir_t *dir;
	apr_finfo_t entry;
	apr_int32_t flags;
	char *listline;
	apr_time_exp_t time;
	apr_time_t nowtime;
 	char *user, *group;
	char strtime[16], strperms[11];

    ftpd_user_rec *ur = ftpd_get_user_rec(r);
	ftpd_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftpd_module);


	/* Skip past all list arguments */
	if (*buffer != '\0') {
		if (*buffer == '-') {
			while (*buffer != ' ' && *buffer != '\0')
				buffer++;
			while (*buffer == ' ')
				buffer++;
		}
	}
	apr_filepath_merge(&r->uri, ur->current_directory, buffer,
		APR_FILEPATH_TRUENAME, r->pool);

	/* Set Method */
	r->method = apr_pstrdup(r->pool,"LIST");
	r->method_number = ftpd_methods[FTPD_M_LIST];
	r->the_request = apr_psprintf(r->pool, "LIST %s", r->uri);
	ap_update_child_status(r->connection->sbh, SERVER_BUSY_WRITE, r);

	ap_rputs(FTP_C_DATACONN" Opening ASCII mode data connection for file list.\r\n", r);
	if ((res = ftpd_data_socket_connect(ur,pConfig)) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_BADSENDCONN" Error accepting connection\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	}

	if (ftpd_check_acl(r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" Permission Denied.\r\n");
		ap_rflush(r);
		ftpd_data_socket_close(ur);
		return FTPD_HANDLER_PERMDENY;
	}
	/* TODO: support listing of a file with LIST */
	if (!ap_is_directory(r->pool, r->filename)) {
		ap_rprintf(r, FTP_C_FILEFAIL" Not a directory\r\n");
		ap_rflush(r);
		ftpd_data_socket_close(ur);
		return FTPD_HANDLER_SERVERERROR;
	}

	if (apr_dir_open(&dir, r->filename, r->pool)!=APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Error opening directory\r\n");
		ap_rflush(r);
		ftpd_data_socket_close(ur);
		return FTPD_HANDLER_SERVERERROR;
	}
	if ((int)data==1) {  /* NLST */
		flags = APR_FINFO_NAME | APR_FINFO_TYPE;
	} else { /* LIST */
		flags = APR_FINFO_NAME | APR_FINFO_TYPE | APR_FINFO_SIZE
			| APR_FINFO_OWNER | APR_FINFO_PROT | APR_FINFO_MTIME;
	}
	r->sent_bodyct = 1;
	r->bytes_sent = 0;
	nowtime = apr_time_now();
	while (1) {
		res = apr_dir_read(&entry,flags,dir);
		if (res!=APR_SUCCESS && res!=APR_INCOMPLETE) {
			break;
		}
		if (!apr_strnatcmp(entry.name,".") || !apr_strnatcmp(entry.name,"..")) {
			continue;
		}
		if ((int)data==1) { /* NLST */
			if (entry.filetype != APR_DIR) {
				if (*buffer!='\0') {
					listline = apr_psprintf(r->pool,"%s\r\n", ap_make_full_path(r->pool,buffer, entry.name));
				} else {
					listline = apr_psprintf(r->pool, "%s\r\n", entry.name);
				}
			} else {
				continue;
			}
		} else { /* LIST */
			apr_time_exp_lt(&time,entry.mtime);
			if ( (nowtime - entry.mtime) > apr_time_from_sec(60 * 60 * 24 * 182) ) {
				apr_strftime(strtime, &retsize, 16, "%b %d  %Y", &time);
			} else {
				apr_strftime(strtime, &retsize, 16, "%b %d %H:%M", &time);
			}
			if (pConfig->bRealPerms) {
				apr_uid_name_get(&user,entry.user,r->pool);
				apr_gid_name_get(&group,entry.group,r->pool);
				apr_cpystrn(strperms,"----------",11);
				if (entry.filetype == APR_DIR)
					strperms[0]='d';
				if (entry.filetype == APR_LNK)
					strperms[0]='l';
				if (entry.protection & APR_UREAD)
					strperms[1]='r';
				if (entry.protection & APR_UWRITE)
					strperms[2]='w';
				if (entry.protection & APR_UEXECUTE)
					strperms[3]='x';
				if (entry.protection & APR_GREAD)
					strperms[4]='r';
				if (entry.protection & APR_GWRITE)
					strperms[5]='w';
				if (entry.protection & APR_GEXECUTE)
					strperms[6]='x';
				if (entry.protection & APR_WREAD)
					strperms[7]='r';
				if (entry.protection & APR_WWRITE)
					strperms[8]='w';
				if (entry.protection & APR_WEXECUTE)
					strperms[9]='x';
			} else {
				user = pConfig->sFakeUser;
				group = pConfig->sFakeGroup;
				if (entry.filetype == APR_DIR) {
					apr_cpystrn(strperms,"drwxr-xr-x",11);
				/* TODO: config: resolve symlinks */
				} else if (entry.filetype == APR_LNK) {
					apr_cpystrn(strperms,"lrwxr-xr-x",11);					
				} else {
					apr_cpystrn(strperms,"-rw-r--r--",11);
				}
			}
			/* TODO: Retrieve symlink destination */
			/*if (entry.filetype == APR_LNK) {
				apr_snprintf(linkdest, 64, " -> %s", "to some strange file");
			} else {
				linkdest[0]='\0';
			}*/

			listline = apr_psprintf(r->pool, "%s   1 %-8s %-8s %8"APR_OFF_T_FMT" %s %s\r\n",
				strperms, user, group,
				entry.size, strtime, entry.name);
		}
		retsize = strlen(listline);
		r->bytes_sent += retsize;
		apr_socket_send(ur->data.pipe, listline, &retsize);
	}
	apr_dir_close(dir);
	ap_rputs(FTP_C_TRANSFEROK" Transfer complete.\r\n",r);
	ap_rflush(r);
	ftpd_data_socket_close(ur);
	return FTPD_HANDLER_OK;
}

HANDLER_DECLARE(type)
{
	char *arg;
    ftpd_user_rec *ur = ftpd_get_user_rec(r);
	int rv = FTPD_HANDLER_OK;

	arg = apr_pstrdup(r->pool, buffer);
	ap_str_tolower(arg);
	if (!apr_strnatcmp(arg, "l8") ||
			!apr_strnatcmp(arg, "l 8") ||
			!apr_strnatcmp(arg, "i")) {
		ap_rprintf(r, FTP_C_TYPEOK" Set Binary mode.\r\n");
		ur->binaryflag = 1;
	} else if (!apr_strnatcmp(arg, "a") ||
			!apr_strnatcmp(arg, "a n")) {
		ap_rprintf(r, FTP_C_TYPEOK" Set ASCII mode.\r\n");
		ur->binaryflag = 0;
	} else {
		ap_rprintf(r, FTP_C_INVALIDARG" Invalid Argument.\r\n");
		rv = FTPD_HANDLER_SERVERERROR;
	}
	ap_rflush(r);
	return rv;
}

HANDLER_DECLARE(retr)
{
	apr_size_t buffsize;
	char buff[FTPD_IO_BUFFER_MAX];
	char *sendbuff;
	int iodone;
	apr_file_t *fp;
	apr_finfo_t finfo;
	apr_status_t res;

	ftpd_user_rec *ur = ftpd_get_user_rec(r);
	ftpd_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftpd_module);

	apr_filepath_merge(&r->uri, ur->current_directory, buffer,
			APR_FILEPATH_TRUENAME, r->pool);
	/* Set Method */
	r->method = apr_pstrdup(r->pool, "GET");
	r->method_number = M_GET;
	r->the_request = apr_psprintf(r->pool, "RETR %s", r->uri);
	ap_update_child_status(r->connection->sbh, SERVER_BUSY_WRITE, r);

	if (ftpd_check_acl(r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" Permission Denied.\r\n");
		ap_rflush(r);
		ftpd_data_socket_close(ur);
		return FTPD_HANDLER_PERMDENY;
	}

	if (apr_file_open(&fp, r->filename, APR_READ,
			APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" %s: file does not exist\r\n", buffer);
		ap_rflush(r);
		ftpd_data_socket_close(ur);
		return FTPD_HANDLER_FILENOTFOUND;
	}
	apr_file_info_get(&finfo, APR_FINFO_TYPE | APR_FINFO_SIZE, fp);
	if (finfo.filetype == APR_DIR) {
		ap_rprintf(r, FTP_C_FILEFAIL" %s: not a plain file\r\n", buffer);
		ap_rflush(r);
		apr_file_close(fp);
		ftpd_data_socket_close(ur);
		return FTPD_HANDLER_SERVERERROR;
	}
	ap_rprintf(r, FTP_C_DATACONN" Opening data connection\r\n");
	ap_rflush(r);
	if (ftpd_data_socket_connect(ur,pConfig) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_BADSENDCONN" Error accepting connection\r\n");
		ap_rflush(r);
		apr_file_close(fp);
		return FTPD_HANDLER_SERVERERROR;
	}
/* Check Restart */
	if (ur->restart_position) {
		apr_off_t offset = ur->restart_position;
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
			"Restore to %d", ur->restart_position);
		if (apr_file_seek(fp, APR_SET, &offset)!=APR_SUCCESS) {
			ap_rprintf(r, FTP_C_FILEFAIL" Unable to set file postition\r\n");
			ap_rflush(r);
			apr_file_close(fp);
			ftpd_data_socket_close(ur);
			return FTPD_HANDLER_SERVERERROR;
		}
		ur->restart_position = 0;
	}
/* Start sending the file */
	iodone = 0;
	r->sent_bodyct = 1;
	r->bytes_sent = 0;
	while (!iodone) {
		buffsize = FTPD_IO_BUFFER_MAX;
		res = apr_file_read(fp, buff, &buffsize);
				/* did we receive anything? */
		if (res == APR_SUCCESS) {
			if (!ur->binaryflag) {
				sendbuff = ftpd_ascii_convert(buff, &buffsize, ASCII_TO_CRLF, r->pool);
			} else {
				sendbuff = buff;
			}
			/* Update bytes sent */
			r->bytes_sent += buffsize;
			res = apr_socket_send(ur->data.pipe, sendbuff, &buffsize);
			if (res != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r,
					"Failed to send data to client");
			}
		} else if (res != APR_EOF) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, res, r,
				"Error reading from file");
		} else {
			iodone = 1;
		}
	}
/* Close verything up */
	ap_rprintf(r, FTP_C_TRANSFEROK" Transfer complete\r\n");
	ap_rflush(r);
	ftpd_data_socket_close(ur);
	apr_file_close(fp);
	return FTPD_HANDLER_OK;
}

HANDLER_DECLARE(size)
{
	apr_finfo_t finfo;
    ftpd_user_rec *ur = ftpd_get_user_rec(r);

	if (apr_filepath_merge(&r->uri, ur->current_directory, buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	}
	/* Set Method */
	r->method = apr_pstrdup(r->pool,"LIST");
	r->method_number = ftpd_methods[FTPD_M_LIST];

	if (ftpd_check_acl(r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" Permission Denied.\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_PERMDENY;
	}
	if (!ur->binaryflag) {
		ap_rprintf(r, FTP_C_FILEFAIL" Could not get file size.\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	}
	if (apr_stat(&finfo, r->filename, APR_FINFO_SIZE | APR_FINFO_TYPE, r->pool)!=APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Error stating file\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_FILENOTFOUND;
	}
	if (finfo.filetype == APR_DIR) {
		ap_rprintf(r, FTP_C_FILEFAIL" %s: not a plain file\r\n", buffer);
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	} else {
		ap_rprintf(r, FTP_C_SIZEOK" %"APR_OFF_T_FMT"\r\n",finfo.size);
		ap_rflush(r);
		return FTPD_HANDLER_OK;
	}
}
HANDLER_DECLARE(mdtm)
{
	apr_finfo_t finfo;
	ftpd_user_rec *ur = ftpd_get_user_rec(r);

	if (apr_filepath_merge(&r->uri,ur->current_directory,buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	}
	/* Set Method */
	r->method = apr_pstrdup(r->pool,"LIST");
	r->method_number = ftpd_methods[FTPD_M_LIST];

	if (ftpd_check_acl(r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" Permission Denied.\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_PERMDENY;
	}

	if (apr_stat(&finfo, r->filename, APR_FINFO_MTIME | APR_FINFO_TYPE, r->pool)!=APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Error stating file\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_FILENOTFOUND;
	}
	if (finfo.filetype == APR_DIR) {
		ap_rprintf(r, FTP_C_FILEFAIL" %s: not a plain file\r\n", buffer);
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	} else {
		char strtime[32];
		apr_size_t retsize;
		apr_time_exp_t time;
		apr_time_exp_gmt(&time,finfo.mtime);
		apr_strftime(strtime, &retsize, 32, "%Y%m%d%H%M%S", &time);
		ap_rprintf(r, FTP_C_MDTMOK" %s\r\n",strtime);
		ap_rflush(r);
		return FTPD_HANDLER_OK;
	}
}

HANDLER_DECLARE(stor)
{
	apr_file_t *fp;
	apr_status_t res;
	int flags;
	int iodone;
	apr_size_t buffsize;
    char buff[FTPD_IO_BUFFER_MAX];
	char *sendbuff;
	ftpd_user_rec *ur = ftpd_get_user_rec(r);
	ftpd_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftpd_module);
/* TODO: find out why the correct per dir config doesn't get imported */
	ftpd_dir_config_rec *dConfig = ap_get_module_config(r->per_dir_config,
					&ftpd_module);

	if (strlen(buffer)==0) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid filename.\r\n");
		ap_rflush(r);
		ftpd_data_socket_close(ur);
		return FTPD_HANDLER_SERVERERROR;
	}
	if (apr_filepath_merge(&r->uri,ur->current_directory,buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		ftpd_data_socket_close(ur);
		return FTPD_HANDLER_SERVERERROR;
	}

	if (ur->restart_position || ((int)data==1)) {
/* APPEnd, if the APPE command or REST before STOR is used */
		flags = APR_WRITE | APR_CREATE | APR_APPEND;
		/* Set Method */
		r->method = apr_pstrdup(r->pool,"APPEND");
		r->method_number = ftpd_methods[FTPD_M_APPEND];
		r->the_request = apr_psprintf(r->pool, "APPEND %s", r->uri);
	} else {
/* STORe, error out if the file already exists */
		if (dConfig->bAllowOverwrite) {
			flags = APR_WRITE | APR_CREATE | APR_TRUNCATE;
		} else {
			flags = APR_WRITE | APR_CREATE | APR_EXCL;
		}
		/* Set Method */
		r->method = apr_pstrdup(r->pool,"PUT");
		r->method_number = M_PUT;
		r->the_request = apr_psprintf(r->pool, "PUT %s", r->uri);
	}
	ap_update_child_status(r->connection->sbh, SERVER_BUSY_WRITE, r);

	if (ftpd_check_acl(r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" Permission Denied.\r\n");
		ap_rflush(r);
		ftpd_data_socket_close(ur);
		return FTPD_HANDLER_PERMDENY;
	}

	if ((res = apr_file_open(&fp, r->filename, flags,
			APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r,
					"Unable to write file to disk: %s.", r->filename);
		ap_rprintf(r, FTP_C_FILEFAIL" %s: unable to open file for writing\r\n",buffer);
		ap_rflush(r);
		ftpd_data_socket_close(ur);
		return FTPD_HANDLER_SERVERERROR;
	}
	ap_rprintf(r, FTP_C_DATACONN" Opening data connection\r\n");
	ap_rflush(r);
	if (ftpd_data_socket_connect(ur,pConfig) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_BADSENDCONN" Error accepting connection\r\n");
		ap_rflush(r);
		apr_file_close(fp);
		return FTPD_HANDLER_SERVERERROR;
	}
/* Check Restart */
	if (ur->restart_position) {
		apr_off_t offset = ur->restart_position;
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, 
			"Restore to %d", ur->restart_position);
		if (!ur->binaryflag) {
			ap_rprintf(r, FTP_C_FILEFAIL" Cannot restore a ASCII transfer\r\n");
			ap_rflush(r);
			apr_file_close(fp);
			ftpd_data_socket_close(ur);
			return FTPD_HANDLER_SERVERERROR;
		}
		if (apr_file_seek(fp, APR_SET, &offset)!=APR_SUCCESS) {
			ap_rprintf(r, FTP_C_FILEFAIL" Unable to set file postition\r\n");
			ap_rflush(r);
			apr_file_close(fp);
			ftpd_data_socket_close(ur);
			return FTPD_HANDLER_SERVERERROR;
		}
		ur->restart_position = 0;
	}
/* Start receiving the file */
	iodone = 0;
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
		"Begginging File transfer");
	r->sent_bodyct = 1;
	r->bytes_sent = 0;
	while (!iodone) {
		buffsize = FTPD_IO_BUFFER_MAX;
		res = apr_socket_recv(ur->data.pipe, buff, &buffsize);
		/* did we receive anything? */
		if (buffsize > 0) {
			if (res == APR_EOF) { // end of file
				iodone = 1;
			}
			if (!ur->binaryflag) {
				sendbuff = ftpd_ascii_convert(buff, &buffsize, ASCII_TO_LF, r->pool);
			} else {
				sendbuff = buff;
			}
			r->bytes_sent += buffsize;
			res = apr_file_write(fp, sendbuff, &buffsize);
			if (res != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r,
					"Failed to write data to disk?");
			}
		} else {
			/* we didn't receive anything. end of file?? */
			if (res != APR_EOF) {
				ap_log_rerror(APLOG_MARK, APLOG_WARNING, res, r,
					"0 bytes read without EOF?");
			}
			iodone = 1;
		}
	}
/* Close verything up */
	ap_rprintf(r, FTP_C_TRANSFEROK" Transfer complete\r\n");
	ap_rflush(r);
	ftpd_data_socket_close(ur);
	apr_file_close(fp);

	return FTPD_HANDLER_OK;	
}

HANDLER_DECLARE(rename)
{
	apr_finfo_t finfo;
	ftpd_user_rec *ur = ftpd_get_user_rec(r);
	int rv = FTPD_HANDLER_OK;

	/* Whole filename is in buffer */
	if (apr_filepath_merge(&r->uri,ur->current_directory, buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	}
	/* Set Method */
	r->method = apr_pstrdup(r->pool,"MOVE");
	r->method_number = M_MOVE;

	if (ftpd_check_acl(r)!=OK) {
		ap_rprintf(r, FTP_C_RENAMEFAIL" %s: Permission Denied.\r\n", buffer);
		ap_rflush(r);
		return FTPD_HANDLER_PERMDENY;
	}
	if (!data) {
		/* Check if file exists. */
		if (apr_stat(&finfo, r->filename, APR_FINFO_TYPE, r->pool) == APR_SUCCESS) {
			/* Store the requested filename into session */
			ur->rename_file = apr_pstrdup(ur->p,r->filename);
			ur->state = FTPD_STATE_RENAME;
			ap_rprintf(r, FTP_C_RNFROK" File exists, ready for destination name.\r\n");
		} else {
			ap_rprintf(r, FTP_C_RENAMEFAIL" File does not exists.\r\n");
			rv = FTPD_HANDLER_FILENOTFOUND;
		}
	} else {
		ur->state = FTPD_STATE_TRANS_NODATA;
		if (apr_stat(&finfo, r->filename, APR_FINFO_TYPE, r->pool) == APR_SUCCESS) {
			/* warning file exists cancel rename */
			ap_rprintf(r, FTP_C_RENAMEFAIL" File already exists.\r\n");
			rv = FTPD_HANDLER_SERVERERROR;
		} else {
			/* destination filename sent, rename */
			if (apr_file_rename(ur->rename_file, r->filename, r->pool) == APR_SUCCESS) {
				ap_rprintf(r, FTP_C_RENAMEOK" File renamed.\r\n");
			} else {
				ap_rprintf(r, FTP_C_RENAMEFAIL" File rename failed.\r\n");
				rv = FTPD_HANDLER_SERVERERROR;
			}
		}
	}
	ap_rflush(r);
	return rv;
}

HANDLER_DECLARE(delete)
{
	apr_finfo_t finfo;
	ftpd_user_rec *ur = ftpd_get_user_rec(r);
	int rv = FTPD_HANDLER_OK;

	/* Whole filename is in buffer */
	if (apr_filepath_merge(&r->uri,ur->current_directory, buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	}
	/* Set Method */
	r->method = apr_pstrdup(r->pool,"DELETE");
	r->method_number = M_DELETE;

	if (ftpd_check_acl(r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" %s: Permission Denied.\r\n", buffer);
		ap_rflush(r);
		return FTPD_HANDLER_PERMDENY;
	}

	if (apr_stat(&finfo, r->filename, APR_FINFO_TYPE, r->pool)==APR_SUCCESS) {
		if (finfo.filetype == APR_DIR) {
			ap_rprintf(r, FTP_C_FILEFAIL" %s: is a directory.\r\n", buffer);
			rv = FTPD_HANDLER_SERVERERROR;
		} else {
			if (apr_file_remove(r->filename, r->pool)==APR_SUCCESS) {
				ap_rprintf(r, FTP_C_DELEOK" %s: File deleted.\r\n", buffer);
			} else {
				ap_rprintf(r, FTP_C_FILEFAIL" %s: Could not delete file.\r\n", buffer);
				rv = FTPD_HANDLER_SERVERERROR;
			}
		}
	} else {
		ap_rprintf(r, FTP_C_FILEFAIL" %s: File not found.\r\n", buffer);
		rv = FTPD_HANDLER_FILENOTFOUND;
	}
	ap_rflush(r);
	return rv;
}

HANDLER_DECLARE(mkdir)
{
	apr_status_t res;
	ftpd_user_rec *ur = ftpd_get_user_rec(r);
	int rv = FTPD_HANDLER_OK;

	/* Whole filename is in buffer */
	if (apr_filepath_merge(&r->uri,ur->current_directory, buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	}
	/* Set Method */
	r->method = apr_pstrdup(r->pool,"MKCOL");
	r->method_number = M_MKCOL;

	if (ftpd_check_acl(r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" %s: Permission Denied.\r\n", buffer);
		ap_rflush(r);
		return FTPD_HANDLER_PERMDENY;
	}

	res = apr_dir_make(r->filename, APR_OS_DEFAULT, r->pool);
	if (res != APR_SUCCESS) {
		if (!APR_STATUS_IS_EEXIST(res)) {
			ap_rprintf(r, FTP_C_FILEFAIL" %s: Could not create directory.\r\n", buffer);
			rv = FTPD_HANDLER_SERVERERROR;
		} else {
			ap_rprintf(r, FTP_C_FILEFAIL" %s: Directory of file already exists.\r\n", buffer);
			rv = FTPD_HANDLER_SERVERERROR;
		}
	} else {
		ap_rprintf(r, FTP_C_MKDIROK" %s: Directory created.\r\n", buffer);
	}
	ap_rflush(r);
	return rv;
}

HANDLER_DECLARE(rmdir)
{
	apr_status_t res;
	ftpd_user_rec *ur = ftpd_get_user_rec(r);
	int rv = FTPD_HANDLER_OK;

	/* Whole filename is in buffer */
	if (apr_filepath_merge(&r->uri,ur->current_directory, buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		return FTPD_HANDLER_SERVERERROR;
	}
	/* Set Method */
	r->method = apr_pstrdup(r->pool,"XRMD");
	r->method_number = ftpd_methods[FTPD_M_XRMD];

	if (ftpd_check_acl(r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" %s: Permission Denied.\r\n", buffer);
		ap_rflush(r);
		return FTPD_HANDLER_PERMDENY;
	}

	res = apr_dir_remove(r->filename, r->pool);
	if (res != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" %s: Could not delete directory.\r\n", buffer);
		rv = FTPD_HANDLER_SERVERERROR;
	} else {
		ap_rprintf(r, FTP_C_MKDIROK" %s: Directory deleted.\r\n", buffer);
	}
	ap_rflush(r);
	return rv;
}

HANDLER_DECLARE(restart)
{
	ftpd_user_rec *ur = ftpd_get_user_rec(r);
	int rv = FTPD_HANDLER_OK;

	ur->restart_position = apr_atoi64(buffer);
	if (ur->restart_position >= 0) {
		ap_rprintf(r, FTP_C_RESTOK" Restarting at %d. Send RETR or STOR.\r\n", ur->restart_position);
	} else {
		ap_rprintf(r, FTP_C_INVALIDARG" Invalid restart postition.\r\n");
		rv = FTPD_HANDLER_SERVERERROR;
	}
	ap_rflush(r);
	return rv;
}
