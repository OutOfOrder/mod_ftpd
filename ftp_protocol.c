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

/* $Header: /home/cvs/httpd-ftp/ftp_protocol.c,v 1.29 2003/12/22 06:12:13 urkle Exp $ */
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

extern int ftp_methods[FTP_M_LAST];

static int ftp_data_socket_close(ftp_user_rec *ur)
{
	switch (ur->data.type) {
	case FTP_PIPE_OPEN:
		apr_socket_close(ur->data.pipe);
		break;
	case FTP_PIPE_PASV:
		apr_socket_close(ur->data.pasv);
		break;
	default:
		break;
	}
	apr_pool_clear(ur->data.p);
	ur->data.type = FTP_PIPE_NONE;
	ur->state = FTP_TRANS_NODATA;
	return OK;
}

static int ftp_data_socket_connect(ftp_user_rec *ur, ftp_svr_config_rec *pConfig)
{
	apr_status_t res=-1;

	switch (ur->data.type) {
	case FTP_PIPE_PASV:
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
		ur->data.type = FTP_PIPE_OPEN;
		ur->state = FTP_TRANS_NODATA;
		break;
	case FTP_PIPE_PORT:
		apr_socket_create(&ur->data.pipe, ur->data.port->family,
			SOCK_STREAM, APR_PROTO_TCP, ur->data.p);
		res = apr_socket_connect(ur->data.pipe, ur->data.port);
		ur->data.type = FTP_PIPE_OPEN;
		ur->state = FTP_TRANS_NODATA;
		break;
	default:
		break;
	}
	return res;
}

/* Creates a sub request record for handlers */
static request_rec *ftp_create_subrequest(request_rec *r, ftp_user_rec *ur)
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

	rnew->request_config = ap_create_request_config(rnew->pool);

	rnew->per_dir_config = r->server->lookup_defaults;

	rnew->htaccess = r->htaccess;
	rnew->allowed_methods = ap_make_method_list(rnew->pool, 2);

	ap_copy_method_list(rnew->allowed_methods, r->allowed_methods);

	ap_set_sub_req_protocol(rnew, r);
	rnew->assbackwards = 0;

	ap_run_create_request(rnew);

/* TODO: Play with filters in create subreq??? */
	rnew->output_filters = r->connection->output_filters;
	rnew->input_filters = r->connection->input_filters;
	
	ap_set_module_config(rnew->request_config, &ftp_module, ur);
	return rnew;
}

#define ftp_check_acl(a,b) ftp_check_acl_ex(a,b,0)

static int ftp_check_acl_ex(const char *newpath, request_rec *r, int skipauth) 
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
static char *ftp_ascii_convert(char *buf, apr_size_t *len, ascii_direction way, apr_pool_t *p)
{
	char *itr = buf;
	char *buf2;
	char temp[FTP_IO_BUFFER_MAX*2];
	apr_size_t len_itr = 0;

	memset(temp, 0, FTP_IO_BUFFER_MAX * 2);
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

int process_ftp_connection_internal(request_rec *r, apr_bucket_brigade *bb)
{
    char *buffer = apr_palloc(r->pool, FTP_STRING_LENGTH);
    char *command,*arg;
    int invalid_cmd = 0;
    apr_size_t len;
    ftp_handler_st *handle_func;
	apr_status_t res;
	request_rec *handler_r;
    ftp_user_rec *ur = ftp_get_user_rec(r);

	r->the_request = apr_pstrdup(r->pool, "IDLE");
	ap_update_child_status(r->connection->sbh, SERVER_BUSY_KEEPALIVE, r);
    while (1) {
        if ((invalid_cmd > MAX_INVALID_CMD) ||
            ap_rgetline(&buffer, FTP_STRING_LENGTH, &len, r, 0, bb) != APR_SUCCESS)
        {
            break;
        }
		r->request_time = apr_time_now();
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
				"C: %s",buffer);
        command = ap_getword_white_nc(r->pool, &buffer);
        ap_str_tolower(command);
        handle_func = apr_hash_get(ap_ftp_hash, command, APR_HASH_KEY_STRING);

        if (!handle_func) {
			arg = ap_getword_white_nc(r->pool, &buffer);
            ap_rprintf(r, FTP_C_BADCMD" '%s %s': command not understood.\r\n", command, arg);
            ap_rflush(r);
            invalid_cmd++;
            continue;
        }
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
			"handler state: %X, epsv mode: %d", handle_func->states, ur->epsv_lock);
        if (!(handle_func->states & ur->state)
				|| ((handle_func->states & FTP_EPSV_LOCK) && ur->epsv_lock) ) {
			if ((ur->state == FTP_AUTH)||(ur->state == FTP_USER_ACK)) {
				ur->state = FTP_AUTH;
				ap_rprintf(r, FTP_C_LOGINERR" '%s' Please login with USER and PASS.\r\n", command);
			} else if ((handle_func->states & FTP_EPSV_LOCK) &&  ur->epsv_lock) {
				ap_rprintf(r, FTP_C_BADSENDCONN" EPSV ALL mode in effect command %s disabled.\r\n", command);
			} else if (handle_func->states & FTP_TRANS_RENAME) {
				ap_rprintf(r, FTP_C_NEEDRNFR" '%s' RNTO requires RNFR first.\r\n", command);
			} else if (handle_func->states & FTP_TRANS_DATA) {
				ap_rprintf(r, FTP_C_BADSENDCONN" '%s' Please Specify PASV, PORT, EPRT, EPSV first.\r\n", command);
			} else if (handle_func->states & FTP_NOT_IMPLEMENTED) {
				ap_rprintf(r, FTP_C_CMDNOTIMPL" '%s' Command not implemented on this server.\r\n", command);
			} else {
            	ap_rprintf(r, "500 '%s': command not allowed in this state\r\n", command);
			}
            ap_rflush(r);
            invalid_cmd++;
            continue;
        }
		handler_r = ftp_create_subrequest(r,ur);

		ap_ftp_str_toupper(command);
	
		if (handle_func->states & FTP_HIDE_ARGS) {
			handler_r->the_request = apr_pstrdup(handler_r->pool, command);
		} else {
			handler_r->the_request = apr_psprintf(handler_r->pool, "%s %s", command, buffer);
		}

		ap_update_child_status(r->connection->sbh, SERVER_BUSY_WRITE, handler_r);

       	res = handle_func->func(handler_r, buffer, handle_func->data);

		if (handle_func->states & FTP_LOG_COMMAND) {
			ap_run_log_transaction(handler_r);			
		}

		ap_increment_counts(r->connection->sbh, handler_r);
		ap_update_child_status(r->connection->sbh, SERVER_BUSY_KEEPALIVE, r);

		apr_pool_destroy(handler_r->pool);
		if (res == FTP_UPDATE_AUTH) {
			/* Assign to master request_rec for all subreqs */
			r->user = apr_pstrdup(r->pool, ur->user);
		    apr_table_set(r->headers_in, "Authorization", ur->auth_string);
		} else if (res == FTP_UPDATE_AGENT) {
			apr_table_set(r->headers_in, "User-Agent", ur->useragent);
		} else if (res == FTP_QUIT) {
            break;
        }
    }
    return OK;
}

HANDLER_DECLARE(quit)
{
    ftp_user_rec *ur = ftp_get_user_rec(r);

    if (ur->state & FTP_TRANSACTION) {
        ap_rprintf(r, FTP_C_GOODBYE"-FTP Statistics go here.\r\n");
    }
	ap_rprintf(r, FTP_C_GOODBYE" Goodbye.\r\n");

    ap_rflush(r);
    ur->state = FTP_AUTH;
    return FTP_QUIT;
}

HANDLER_DECLARE(user)
{
	char *user;
    ftp_user_rec *ur = ftp_get_user_rec(r);

    user = ap_getword_white_nc(r->pool, &buffer);
    if (!strcmp(user, "")) {
        ap_rprintf(r, FTP_C_LOGINERR" Please login with USER and PASS.\r\n");
        ap_rflush(r);
        return FTP_USER_NOT_ALLOWED;
    }
    ur->user = apr_pstrdup(ur->p, user);

    ap_rprintf(r, FTP_C_GIVEPWORD" Password required for %s.\r\n", ur->user);
    ap_rflush(r);    
	ur->state = FTP_USER_ACK;
	return OK;
}

HANDLER_DECLARE(passwd)
{
	char *passwd;
	ftp_provider_list *current_provider;
	apr_status_t res;
	const char *chroot = NULL,*initroot = NULL;
	ftp_chroot_status_t chroot_ret;
	ftp_user_rec *ur = ftp_get_user_rec(r);
	ftp_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftp_module);

    passwd = apr_psprintf(r->pool, "%s:%s", ur->user,
                          ap_getword_white_nc(r->pool, &buffer));
    ur->auth_string = apr_psprintf(r->pool, "Basic %s",
                                   ap_pbase64encode(r->pool, passwd)); 
	r->user = apr_pstrdup(r->pool, ur->user);
    apr_table_set(r->headers_in, "Authorization", ur->auth_string);

	/* Get chroot mapping */
	current_provider = pConfig->providers;
	while (current_provider) {
		const ftp_provider *provider;
		provider = current_provider->provider;

		if (! provider->chroot) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"Provider '%s' does not provider chroot mapping.",
				current_provider->name);
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
				"Check provider %s", current_provider->name);
			chroot_ret = provider->chroot->map_chroot(r, &chroot, &initroot);
			if (chroot_ret == FTP_CHROOT_USER_FOUND) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
					"Chroot set to %s", chroot);
				break; /* We got one fall out */
			} else if (chroot_ret == FTP_CHROOT_FAIL) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"User denied access to server");
				ap_rprintf(r, FTP_C_NOLOGIN" Login not allowed\r\n");
				ap_rflush(r);
				/* Bail out immediatly if this occurs */
				return FTP_QUIT;
			} else { /* FTP_CHROOT_USER_NOT_FOUND*/
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
					"User not found in chroot provider. Continuing");
			}
		}
		current_provider = current_provider->next;
	}

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
	r->method_number = ftp_methods[FTP_M_CHDIR];

	if ((res = ftp_check_acl_ex(ur->current_directory, r, 1))!=OK) {
		ap_rprintf(r, FTP_C_NOLOGIN" Login not allowed\r\n");
		ap_rflush(r);
		/* Bail out immediatly if this occurs? */
		return FTP_QUIT;
	}
	
    if ((res = ap_run_check_user_id(r)) != OK) {
        ap_rprintf(r, FTP_C_LOGINERR" Login incorrect\r\n");
        ap_rflush(r);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
               "Unauthorized user '%s' tried to log in:", ur->user);
        ur->state = FTP_AUTH;
        return FTP_USER_NOT_ALLOWED;
    }
	if ((res = ap_run_auth_checker(r)) != OK) {
		ap_rprintf(r, FTP_C_LOGINERR" Login denied\r\n");
		ap_rflush(r);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
               "Unauthorized user '%s' tried to log in:", ur->user);
		return FTP_USER_UNKNOWN;
	}

	/* Report succsessful login */
    ap_rprintf(r, FTP_C_LOGINOK" User %s logged in.\r\n", ur->user);
    ap_rflush(r);
	ur->state = FTP_TRANS_NODATA;
	return FTP_UPDATE_AUTH;
}

HANDLER_DECLARE(pwd)
{
    ftp_user_rec *ur = ftp_get_user_rec(r);

	ap_rprintf(r, FTP_C_PWDOK" \"%s\" is current directory.\r\n",ur->current_directory);

    ap_rflush(r);
    return OK;
}


HANDLER_DECLARE(cd)
{
	char *patharg;  /* incoming directory change */
	char *newpath;	/* temp space for merged local path */
    ftp_user_rec *ur = ftp_get_user_rec(r);

	if ((int)data==1) {
		patharg = "..";
	} else {
    	patharg = ap_getword_white_nc(r->pool, &buffer);
	}
	if (apr_filepath_merge(&newpath,ur->current_directory,patharg, 
			APR_FILEPATH_TRUENAME, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid path.\r\n");
		ap_rflush(r);
		return OK;
	}
	r->method = apr_pstrdup(r->pool, "CHDIR");
	r->method_number = ftp_methods[FTP_M_CHDIR];

	if (ftp_check_acl(newpath, r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" Permission Denied.\r\n");
		ap_rflush(r);
		return OK;
	}

	if (!ap_is_directory(r->pool, r->filename)) {
		ap_rprintf(r, FTP_C_FILEFAIL" '%s': No such file or directory.\r\n",patharg);
	} else {
		ur->current_directory = apr_pstrdup(ur->p,newpath);
		ap_rprintf(r, FTP_C_CWDOK" CWD command successful.\r\n");
	}
    ap_rflush(r);
    return OK;
}

HANDLER_DECLARE(help)
{
	char *command;
	int column;
	apr_hash_index_t* hash_itr;
	ftp_handler_st *handle_func;

	command = ap_getword_white_nc(r->pool, &buffer);
	if (command[0]=='\0') {
		if (!(int)data) { /* HELP */
			ap_rprintf(r, FTP_C_HELPOK"-The following commands are implemented.\r\n");
		} else { /* FEAT */
			ap_rprintf(r, FTP_C_FEATOK"-FEAT\r\n");
		}
		column = 0;
		for (hash_itr = apr_hash_first(r->pool, ap_ftp_hash); hash_itr;
				hash_itr = apr_hash_next(hash_itr)) {
			apr_hash_this(hash_itr, (const void **)&command, NULL,(void **)&handle_func);
			command = apr_pstrdup(r->pool,command);
			ap_ftp_str_toupper(command);
			if (!(int)data) { /* HELP */
				column++;
				ap_rprintf(r,"   %c%-4s",
					(handle_func->states & FTP_NOT_IMPLEMENTED)?'*':' ',
					command);
				if ((column % 7)==0) {
					ap_rputs("\r\n",r);
				}
			} else { /* FEAT */
				if (handle_func->states & FTP_FEATURE) {
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
		handle_func = apr_hash_get(ap_ftp_hash, command, APR_HASH_KEY_STRING);
		/* Str to Upper */
		ap_ftp_str_toupper(command);
		if (!handle_func) {
			ap_rprintf(r, FTP_C_BADHELP" Unknown command %s\r\n",command);
		} else {
			if (handle_func->states & FTP_NOT_IMPLEMENTED) {
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
	return OK;
}

HANDLER_DECLARE(syst)
{
	ap_rputs(FTP_C_SYSTOK" UNIX Type: L8\r\n",r);
	ap_rflush(r);
	return OK;
}

HANDLER_DECLARE(NOOP)
{
	if (!data) {
		ap_rputs(FTP_C_NOOPOK" Command completed successfully.\r\n",r);
	} else {
		char *arg = ap_getword_white_nc(r->pool, &buffer);
		ap_str_tolower(arg);
		if (!apr_strnatcmp(arg, data)) {
			ap_rputs(FTP_C_NOOPOK" Command completed successfully.\r\n",r);
		} else {
			ap_rputs(FTP_C_INVALIDARG" Invalid argument.\r\n",r);
		}
	}
	ap_rflush(r);
	return OK;
}
HANDLER_DECLARE(clnt)
{
	ftp_user_rec *ur = ftp_get_user_rec(r);

	ur->useragent = apr_pstrdup(ur->p, buffer);
	ap_rputs(FTP_C_CLNTOK" Command completed successfully.\r\n",r);
	ap_rflush(r);
	return FTP_UPDATE_AGENT;
}

HANDLER_DECLARE(pasv)
{
	apr_sockaddr_t *listen_addr, *local_addr = r->connection->local_addr;
	apr_port_t port;
	char *ipaddr;
	int family;
	apr_status_t res;
	ftp_user_rec *ur = ftp_get_user_rec(r);
	ftp_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftp_module);
	int bind_retries = 10;

/* Close old socket if already connected */
	ftp_data_socket_close(ur);

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
			return OK;
		} else if (family!=0) {
			ap_rprintf(r, FTP_C_INVALID_PROTO" Unsupported Protocol, use (1,2)\r\n");
			ap_rflush(r);
			return OK;
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
		apr_sockaddr_port_set(listen_addr,port);
		if ((res = apr_socket_bind(ur->data.pasv, listen_addr))==APR_SUCCESS) {
			break;
		}
	}
	if (!bind_retries) {
		ap_rprintf(r, FTP_C_PASVFAIL" Error Binding to address\r\n");
		ap_rflush(r);
		return OK;
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
	ur->data.type = FTP_PIPE_PASV;
	ur->state = FTP_TRANS_DATA;
	return OK;
}

HANDLER_DECLARE(port)
{
	int ip1,ip2,ip3,ip4,p1,p2;
	char *strfamily, *ipaddr, *strport;
	char tok_sep[2], *tok_sess;
	int family;
	apr_port_t port;
	ftp_user_rec *ur = ftp_get_user_rec(r);
	ftp_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftp_module);

	if (!pConfig->bAllowPort) {
		ap_rprintf(r, FTP_C_CMDDISABLED" PORT command not allowed on this server\r\n");
		ap_rflush(r);
		return OK;
	}
/* Close old socket if already connected */
	ftp_data_socket_close(ur);

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
			return OK;
		}
		if ((ipaddr = apr_strtok(NULL, tok_sep, &tok_sess))==NULL) {
			ap_rprintf(r, FTP_C_INVALIDARG" Invalid Argument\r\n");
			ap_rflush(r);
			return OK;
		}
		if ((strport = apr_strtok(NULL, tok_sep, &tok_sess))==NULL) {
			ap_rprintf(r, FTP_C_INVALIDARG" Invalid Argument\r\n");
			ap_rflush(r);
			return OK;
		}
		port = apr_atoi64(strport);
		family = apr_atoi64(strfamily);
		if (family == 1) {
			family = APR_INET;
		} else if (family == 2) {
			family = APR_INET6;
		} else {
			ap_rprintf(r, FTP_C_INVALID_PROTO" Unsupported Protocol, use (1,2)\r\n");
			ap_rflush(r);
			return OK;
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
			return OK;
		}
	}
	ap_rprintf(r, FTP_C_PORTOK" Command Successful\r\n");
	ap_rflush(r);
	ur->data.type = FTP_PIPE_PORT;
	ur->state = FTP_TRANS_DATA;
	return OK;
}

HANDLER_DECLARE(list)
{
	apr_status_t res;
	apr_dir_t *dir;
	apr_finfo_t entry;
	apr_int32_t flags;
	char buff[128];
	apr_time_exp_t time;
	apr_time_t nowtime;
 	char *user, *group;
	char strtime[16], strperms[11];

    ftp_user_rec *ur = ftp_get_user_rec(r);
	ftp_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftp_module);

	ap_rputs(FTP_C_DATACONN" Opening ASCII mode data connection for file list.\r\n", r);
	if ((res = ftp_data_socket_connect(ur,pConfig)) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_BADSENDCONN" Error accepting connection\r\n");
		ap_rflush(r);
		return OK;
	}

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
	r->method_number = ftp_methods[FTP_M_LIST];
	r->the_request = apr_psprintf(r->pool, "LIST %s", r->uri);
	ap_update_child_status(r->connection->sbh, SERVER_BUSY_WRITE, r);

	if (ftp_check_acl(NULL, r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" Permission Denied.\r\n");
		ap_rflush(r);
		ftp_data_socket_close(ur);
		return OK;
	}

	if (!ap_is_directory(r->pool, r->filename)) {
		ap_rprintf(r, FTP_C_FILEFAIL" Not a directory\r\n");
		ap_rflush(r);
		ftp_data_socket_close(ur);
		return OK;
	}

	if (apr_dir_open(&dir, r->filename, r->pool)!=APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Error opening directory\r\n");
		ap_rflush(r);
		ftp_data_socket_close(ur);
		return OK;
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
					apr_snprintf(buff, 128, "%s\r\n", ap_make_full_path(r->pool,buffer, entry.name));
				} else {
					apr_snprintf(buff, 128, "%s\r\n", entry.name);
				}
			} else {
				continue;
			}
		} else { /* LIST */
			apr_time_exp_lt(&time,entry.mtime);
			if ( (nowtime - entry.mtime) > apr_time_from_sec(60 * 60 * 24 * 182) ) {
				apr_strftime(strtime, &res, 16, "%b %d  %Y", &time);
			} else {
				apr_strftime(strtime, &res, 16, "%b %d %H:%M", &time);
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

			apr_snprintf(buff, 128, "%s   1 %-8s %-8s %8"APR_OFF_T_FMT" %s %s\r\n",
				strperms, user, group,
				entry.size, strtime, entry.name);
		}
		res = strlen(buff);
		r->bytes_sent += res;
		apr_socket_send(ur->data.pipe, buff, &res);
	}
	apr_dir_close(dir);
	ap_rputs(FTP_C_TRANSFEROK" Transfer complete.\r\n",r);
	ap_rflush(r);
	ftp_data_socket_close(ur);
	return OK;
}

HANDLER_DECLARE(type)
{
	char *arg;
    ftp_user_rec *ur = ftp_get_user_rec(r);

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
	}
	ap_rflush(r);
	return OK;
}

HANDLER_DECLARE(retr)
{
	apr_size_t buffsize;
	char buff[FTP_IO_BUFFER_MAX];
	char *sendbuff;
	int iodone;
	apr_file_t *fp;
	apr_finfo_t finfo;
	apr_status_t res;

	ftp_user_rec *ur = ftp_get_user_rec(r);
	ftp_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftp_module);

	apr_filepath_merge(&r->uri, ur->current_directory, buffer,
			APR_FILEPATH_TRUENAME, r->pool);
	/* Set Method */
	r->method = apr_pstrdup(r->pool, "GET");
	r->method_number = M_GET;
	r->the_request = apr_psprintf(r->pool, "RETR %s", r->uri);
	ap_update_child_status(r->connection->sbh, SERVER_BUSY_WRITE, r);

	if (ftp_check_acl(NULL, r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" Permission Denied.\r\n");
		ap_rflush(r);
		ftp_data_socket_close(ur);
		return OK;
	}

	if (apr_file_open(&fp, r->filename, APR_READ,
			APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" %s: file does not exist\r\n", buffer);
		ap_rflush(r);
		ftp_data_socket_close(ur);
		return OK;
	}
	apr_file_info_get(&finfo, APR_FINFO_TYPE | APR_FINFO_SIZE, fp);
	if (finfo.filetype == APR_DIR) {
		ap_rprintf(r, FTP_C_FILEFAIL" %s: not a plain file\r\n", buffer);
		ap_rflush(r);
		apr_file_close(fp);
		ftp_data_socket_close(ur);
		return OK;
	}
	ap_rprintf(r, FTP_C_DATACONN" Opening data connection\r\n");
	ap_rflush(r);
	if (ftp_data_socket_connect(ur,pConfig) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_BADSENDCONN" Error accepting connection\r\n");
		ap_rflush(r);
		apr_file_close(fp);
		return OK;
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
			ftp_data_socket_close(ur);
			return OK;
		}
		ur->restart_position = 0;
	}
/* Start sending the file */
	iodone = 0;
	r->sent_bodyct = 1;
	r->bytes_sent = 0;
	while (!iodone) {
		buffsize = FTP_IO_BUFFER_MAX;
		res = apr_file_read(fp, buff, &buffsize);
				/* did we receive anything? */
		if (res == APR_SUCCESS) {
			if (!ur->binaryflag) {
				sendbuff = ftp_ascii_convert(buff, &buffsize, ASCII_TO_CRLF, r->pool);
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
	ftp_data_socket_close(ur);
	apr_file_close(fp);
	return OK;
}

HANDLER_DECLARE(size)
{
	apr_finfo_t finfo;
    ftp_user_rec *ur = ftp_get_user_rec(r);

	if (apr_filepath_merge(&r->uri, ur->current_directory, buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		return OK;
	}
	/* Set Method */
	r->method = apr_pstrdup(r->pool,"LIST");
	r->method_number = ftp_methods[FTP_M_LIST];

	if (ftp_check_acl(NULL, r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" Permission Denied.\r\n");
		ap_rflush(r);
		return OK;
	}
	if (!ur->binaryflag) {
		ap_rprintf(r, FTP_C_FILEFAIL" Could not get file size.\r\n");
		ap_rflush(r);
		return OK;		
	}
	if (apr_stat(&finfo, r->filename, APR_FINFO_SIZE | APR_FINFO_TYPE, r->pool)!=APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Error stating file\r\n");
		ap_rflush(r);
		return OK;
	}
	if (finfo.filetype == APR_DIR) {
		ap_rprintf(r, FTP_C_FILEFAIL" %s: not a plain file\r\n", buffer);
	} else {
		ap_rprintf(r, FTP_C_SIZEOK" %"APR_OFF_T_FMT"\r\n",finfo.size);
	}
	ap_rflush(r);
	return OK;
}
HANDLER_DECLARE(mdtm)
{
	apr_finfo_t finfo;
    ftp_user_rec *ur = ftp_get_user_rec(r);

	if (apr_filepath_merge(&r->uri,ur->current_directory,buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		return OK;
	}
	/* Set Method */
	r->method = apr_pstrdup(r->pool,"LIST");
	r->method_number = ftp_methods[FTP_M_LIST];

	if (ftp_check_acl(NULL, r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" Permission Denied.\r\n");
		ap_rflush(r);
		return OK;
	}

	if (apr_stat(&finfo, r->filename, APR_FINFO_MTIME | APR_FINFO_TYPE, r->pool)!=APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Error stating file\r\n");
		ap_rflush(r);
		return OK;
	}
	if (finfo.filetype == APR_DIR) {
		ap_rprintf(r, FTP_C_FILEFAIL" %s: not a plain file\r\n", buffer);
	} else {
		char strtime[32];
		int res;
		apr_time_exp_t time;
		apr_time_exp_gmt(&time,finfo.mtime);
		apr_strftime(strtime, &res, 32, "%Y%m%d%H%M%S", &time);
		ap_rprintf(r, FTP_C_MDTMOK" %s\r\n",strtime);
	}
	ap_rflush(r);
	return OK;
}

HANDLER_DECLARE(stor)
{
	apr_file_t *fp;
	apr_status_t res;
	int flags;
	int iodone;
	apr_size_t buffsize;
    char buff[FTP_IO_BUFFER_MAX];
	char *sendbuff;
	ftp_user_rec *ur = ftp_get_user_rec(r);
	ftp_svr_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftp_module);

	if (strlen(buffer)==0) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid filename.\r\n");
		ap_rflush(r);
		ftp_data_socket_close(ur);
		return OK;
	}
	if (apr_filepath_merge(&r->uri,ur->current_directory,buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		ftp_data_socket_close(ur);
		return OK;
	}

	if (ur->restart_position || ((int)data==1)) {
/* APPEnd, if the APPE command or REST before STOR is used */
		flags = APR_WRITE | APR_CREATE | APR_APPEND;
		/* Set Method */
		r->method = apr_pstrdup(r->pool,"APPEND");
		r->method_number = ftp_methods[FTP_M_APPEND];
		r->the_request = apr_psprintf(r->pool, "APPEND %s", r->uri);
	} else {
/* STORe, error out if the file already exists */
		flags = APR_WRITE | APR_CREATE | APR_EXCL;
		/* Set Method */
		r->method = apr_pstrdup(r->pool,"PUT");
		r->method_number = M_PUT;
		r->the_request = apr_psprintf(r->pool, "PUT %s", r->uri);
	}
	ap_update_child_status(r->connection->sbh, SERVER_BUSY_WRITE, r);

	if (ftp_check_acl(NULL, r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" Permission Denied.\r\n");
		ap_rflush(r);
		ftp_data_socket_close(ur);
		return OK;
	}

	if ((res = apr_file_open(&fp, r->filename, flags,
			APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, res, r,
					"Unable to write file to disk: %s.", r->filename);
		ap_rprintf(r, FTP_C_FILEFAIL" %s: unable to open file for writing\r\n",buffer);
		ap_rflush(r);
		ftp_data_socket_close(ur);
		return OK;
	}
	ap_rprintf(r, FTP_C_DATACONN" Opening data connection\r\n");
	ap_rflush(r);
	if (ftp_data_socket_connect(ur,pConfig) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_BADSENDCONN" Error accepting connection\r\n");
		ap_rflush(r);
		apr_file_close(fp);
		return OK;
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
			ftp_data_socket_close(ur);
		}
		if (apr_file_seek(fp, APR_SET, &offset)!=APR_SUCCESS) {
			ap_rprintf(r, FTP_C_FILEFAIL" Unable to set file postition\r\n");
			ap_rflush(r);
			apr_file_close(fp);
			ftp_data_socket_close(ur);
			return OK;
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
		buffsize = FTP_IO_BUFFER_MAX;
		res = apr_socket_recv(ur->data.pipe, buff, &buffsize);
		/* did we receive anything? */
		if (buffsize > 0) {
			if (res == APR_EOF) { // end of file
				iodone = 1;
			}
			if (!ur->binaryflag) {
				sendbuff = ftp_ascii_convert(buff, &buffsize, ASCII_TO_LF, r->pool);
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
	ftp_data_socket_close(ur);
	apr_file_close(fp);

	return OK;	
}

HANDLER_DECLARE(rename)
{
	apr_finfo_t finfo;
	ftp_user_rec *ur = ftp_get_user_rec(r);

	/* Whole filename is in buffer */
	if (apr_filepath_merge(&r->uri,ur->current_directory, buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		return OK;
	}
	/* Set Method */
	r->method = apr_pstrdup(r->pool,"MOVE");
	r->method_number = M_MOVE;

	if (ftp_check_acl(NULL, r)!=OK) {
		ap_rprintf(r, FTP_C_RENAMEFAIL" %s: Permission Denied.\r\n", buffer);
		ap_rflush(r);
		return OK;
	}
	if (!data) {
		/* Check if file exists. */
		if (apr_stat(&finfo, r->filename, APR_FINFO_TYPE, r->pool) == APR_SUCCESS) {
			/* Store the requested filename into session */
			ur->rename_file = apr_pstrdup(ur->p,r->filename);
			ur->state = FTP_TRANS_RENAME;
			ap_rprintf(r, FTP_C_RNFROK" File exists, ready for destination name.\r\n");
		} else {
			ap_rprintf(r, FTP_C_RENAMEFAIL" File does not exists.\r\n");
		}
	} else {
		ur->state = FTP_TRANS_NODATA;
		if (apr_stat(&finfo, r->filename, APR_FINFO_TYPE, r->pool) == APR_SUCCESS) {
			/* warning file exists cancel rename */
			ap_rprintf(r, FTP_C_RENAMEFAIL" File already exists.\r\n");
		} else {
			/* destination filename sent, rename */
			if (apr_file_rename(ur->rename_file, r->filename, r->pool) == APR_SUCCESS) {
				ap_rprintf(r, FTP_C_RENAMEOK" File renamed.\r\n");
			} else {
				ap_rprintf(r, FTP_C_RENAMEFAIL" File rename failed.\r\n");
			}
		}
	}
	ap_rflush(r);
	return OK;
}

HANDLER_DECLARE(delete)
{
	apr_finfo_t finfo;
	ftp_user_rec *ur = ftp_get_user_rec(r);

	/* Whole filename is in buffer */
	if (apr_filepath_merge(&r->uri,ur->current_directory, buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		return OK;
	}
	/* Set Method */
	r->method = apr_pstrdup(r->pool,"DELETE");
	r->method_number = M_DELETE;

	if (ftp_check_acl(NULL, r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" %s: Permission Denied.\r\n", buffer);
		ap_rflush(r);
		return OK;
	}

	if (apr_stat(&finfo, r->filename, APR_FINFO_TYPE, r->pool)==APR_SUCCESS) {
		if (finfo.filetype == APR_DIR) {
			ap_rprintf(r, FTP_C_FILEFAIL" %s: is a directory.\r\n", buffer);
		} else {
			if (apr_file_remove(r->filename, r->pool)==APR_SUCCESS) {
				ap_rprintf(r, FTP_C_DELEOK" %s: File deleted.\r\n", buffer);
			} else {
				ap_rprintf(r, FTP_C_FILEFAIL" %s: Could not delete file.\r\n", buffer);
			}
		}
	} else {
		ap_rprintf(r, FTP_C_FILEFAIL" %s: File not found.\r\n", buffer);
	}
	ap_rflush(r);
	return OK;
}

HANDLER_DECLARE(mkdir)
{
	apr_status_t res;
	ftp_user_rec *ur = ftp_get_user_rec(r);

	/* Whole filename is in buffer */
	if (apr_filepath_merge(&r->uri,ur->current_directory, buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		return OK;
	}
	/* Set Method */
	r->method = apr_pstrdup(r->pool,"MKCOL");
	r->method_number = M_MKCOL;

	if (ftp_check_acl(NULL, r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" %s: Permission Denied.\r\n", buffer);
		ap_rflush(r);
		return OK;
	}

	res = apr_dir_make(r->filename, APR_OS_DEFAULT, r->pool);
	if (res != APR_SUCCESS) {
		if (!APR_STATUS_IS_EEXIST(res)) {
			ap_rprintf(r, FTP_C_FILEFAIL" %s: Could not create directory.\r\n", buffer);		
		} else {
			ap_rprintf(r, FTP_C_FILEFAIL" %s: Directory of file already exists.\r\n", buffer);		
		}
	} else {
		ap_rprintf(r, FTP_C_MKDIROK" %s: Directory created.\r\n", buffer);
	}
	ap_rflush(r);
	return OK;
}

HANDLER_DECLARE(rmdir)
{
	apr_status_t res;
	ftp_user_rec *ur = ftp_get_user_rec(r);

	/* Whole filename is in buffer */
	if (apr_filepath_merge(&r->uri,ur->current_directory, buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" Invalid file name.\r\n");
		ap_rflush(r);
		return OK;
	}
	/* Set Method */
	r->method = apr_pstrdup(r->pool,"XRMD");
	r->method_number = ftp_methods[FTP_M_XRMD];

	if (ftp_check_acl(NULL, r)!=OK) {
		ap_rprintf(r, FTP_C_PERMDENY" %s: Permission Denied.\r\n", buffer);
		ap_rflush(r);
		return OK;
	}

	res = apr_dir_remove(r->filename, r->pool);
	if (res != APR_SUCCESS) {
		ap_rprintf(r, FTP_C_FILEFAIL" %s: Could not delete directory.\r\n", buffer);		
	} else {
		ap_rprintf(r, FTP_C_MKDIROK" %s: Directory deleted.\r\n", buffer);
	}
	ap_rflush(r);
	return OK;
}
HANDLER_DECLARE(restart)
{
	ftp_user_rec *ur = ftp_get_user_rec(r);

	ur->restart_position = apr_atoi64(buffer);
	if (ur->restart_position >= 0) {
		ap_rprintf(r, FTP_C_RESTOK" Restarting at %d. Send RETR or STOR.\r\n", ur->restart_position);
	} else {
		ap_rprintf(r, FTP_C_INVALIDARG" Invalid restart postition.\r\n");
	}
	ap_rflush(r);
	return OK;
}
