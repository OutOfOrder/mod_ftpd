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
	ur->data.type = FTP_PIPE_NONE;
	ur->state = FTP_TRANS_NODATA;
	return OK;
}

static int ftp_data_socket_connect(ftp_user_rec *ur,request_rec *r)
{
	apr_status_t res;
	switch (ur->data.type) {
	case FTP_PIPE_PASV:
		res = apr_socket_accept(&ur->data.pipe, ur->data.pasv, ur->data.p);
		apr_socket_close(ur->data.pasv);
		ur->data.type = FTP_PIPE_OPEN;
		ur->state = FTP_TRANS_NODATA;
		break;
	case FTP_PIPE_PORT:
		apr_socket_create_ex(&ur->data.pipe, ur->data.port->family,
			SOCK_STREAM, APR_PROTO_TCP, ur->data.p);
		apr_socket_timeout_set(ur->data.pipe, apr_time_from_sec(300));
		res = apr_socket_connect(ur->data.pipe, ur->data.port);
		ur->data.type = FTP_PIPE_OPEN;
		ur->state = FTP_TRANS_NODATA;
		break;
	default:
	}
	return res;
}

int process_ftp_connection_internal(request_rec *r, apr_bucket_brigade *bb)
{
    char *buffer = apr_palloc(r->pool, FTP_STRING_LENGTH);
    char *command,*arg;
    int invalid_cmd = 0;
    apr_size_t len;
    ftp_handler_st *handle_func;
    ftp_user_rec *ur = ap_get_module_config(r->request_config,
					&ftp_module);

    r->uri = apr_pstrdup(r->pool, "ftp:");

    ap_run_map_to_storage(r);

    while (1) {
        int res;
        if ((invalid_cmd > MAX_INVALID_CMD) ||
            ap_rgetline(&buffer, FTP_STRING_LENGTH, &len, r, 0, bb) != APR_SUCCESS)
        {
            break;
        }
		ap_log_rerror(APLOG_MARK, APLOG_NOTICE|APLOG_NOERRNO, 0, r,
				"C: %s",buffer);
        command = ap_getword_white_nc(r->pool, &buffer);
        ap_str_tolower(command);
        handle_func = apr_hash_get(ap_ftp_hash, command, APR_HASH_KEY_STRING);

        if (!handle_func) {
			arg = ap_getword_white_nc(r->pool, &buffer);
            ap_rprintf(r, "500 '%s %s': command not understood\r\n", command, arg);
            ap_rflush(r);
            invalid_cmd++;
            continue;
        }
        if (!(handle_func->states & ur->state)) {
			if ((ur->state == FTP_AUTH)||(ur->state == FTP_USER_ACK)) {
				ur->state = FTP_AUTH;
				ap_rprintf(r, "530 '%s' Please login with USER and PASS.\r\n",command);
			} else if (handle_func->states & FTP_TRANS_DATA) {
				ap_rprintf(r, "425 '%s' Please Specify PASV  or PORT first.\r\n",command);
			} else if (handle_func->states & FTP_NOT_IMPLEMENTED) {
				ap_rprintf(r, "502 '%s' Command not implemented on this server.\r\n",command);
			} else {
            	ap_rprintf(r, "500 '%s': command not allowed in this state\r\n", command);
			}
            ap_rflush(r);
            invalid_cmd++;
            continue;
        }
        res = handle_func->func(r, buffer, handle_func->data);
        if (res == FTP_QUIT) {
            break;
        }
    }
    return OK;
}

int ap_ftp_handle_quit(request_rec *r, char *buffer, void *data)
{
    ftp_user_rec *ur = ap_get_module_config(r->request_config,
					&ftp_module);

    if (ur->state & FTP_TRANSACTION) {
        ap_rprintf(r, "221-FTP Statistics go here\r\n");
    }
	ap_rprintf(r, "221 Goodbye.\r\n");

    ap_rflush(r);
    ur->state = FTP_AUTH;
    return FTP_QUIT;
}

int ap_ftp_handle_user(request_rec *r, char *buffer, void *data)
{
	char *user;
    ftp_user_rec *ur = ap_get_module_config(r->request_config,
					&ftp_module);

    user = ap_getword_white_nc(r->pool, &buffer);
    if (!strcmp(user, "")) {
        ap_rprintf(r, "530 Please login with USER and PASS.\r\n");
        ap_rflush(r);
        return FTP_USER_NOT_ALLOWED;
    }
    r->user = ur->user = apr_pstrdup(ur->p, user); 

    ap_rprintf(r, "331 Password required for %s\r\n", r->user);
    ap_rflush(r);    
	ur->state = FTP_USER_ACK;
	return OK;
}

int ap_ftp_handle_passwd(request_rec *r, char *buffer, void *data)
{
	char *passwd;
	int res;
	ftp_user_rec *ur = ap_get_module_config(r->request_config,
					&ftp_module);
	/*ftp_config_rec *pConfig = ap_get_module_config(r->server->module_config,
								&ftp_module);*/

    passwd = apr_psprintf(r->pool, "%s:%s", ur->user,
                          ap_getword_white_nc(r->pool, &buffer));
    ur->auth_string = apr_psprintf(r->connection->pool, "Basic %s",
                                   ap_pbase64encode(r->pool, passwd)); 

    apr_table_set(r->headers_in, "Authorization", ur->auth_string);

 	r->uri = apr_pstrdup(r->pool, "/");

	ap_run_translate_name(r);
    ap_run_map_to_storage(r);

    if ((res = ap_run_check_user_id(r)) != OK) {
        ap_rprintf(r,
               "530 Login incorrect.%d \r\n", res);
        ap_rflush(r);
        ap_log_rerror(APLOG_MARK, APLOG_ERR|APLOG_NOERRNO, 0, r,
                      "Unauthorized user tried to log in");
        ur->state = FTP_AUTH;
        return FTP_USER_NOT_ALLOWED;
    }

    ap_rprintf(r, "230 User %s logged in.\r\n", ur->user);
    ap_rflush(r);
	ur->current_directory = apr_pstrdup(ur->p,"/");
	ur->state = FTP_TRANS_NODATA;
	return OK;
}

int ap_ftp_handle_pwd(request_rec *r, char *buffer, void *data)
{
    ftp_user_rec *ur = ap_get_module_config(r->request_config,
					&ftp_module);

	ap_rprintf(r, "257 \"%s\" is current directory.\r\n",ur->current_directory);

    ap_rflush(r);
    return OK;
}

int ap_ftp_handle_cd(request_rec *r, char *buffer, void *data)
{
	char *patharg;  /* incoming directory change */
	char *newpath;	/* temp space for merged local path */
    ftp_user_rec *ur = ap_get_module_config(r->request_config,
					&ftp_module);
//	ftp_config_rec *pConfig = ap_get_module_config(r->server->module_config,
//					&ftp_module);

	if ((int)data==1) {
		patharg = "..";
	} else {
    	patharg = ap_getword_white_nc(r->pool, &buffer);
	}
	if (apr_filepath_merge((char**)&newpath,ur->current_directory,patharg, 
			APR_FILEPATH_TRUENAME, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, "550 invalid root path\r\n");
	}
	//translate from local to real filename
	r->uri	= apr_pstrdup(r->pool,newpath);
	ap_run_translate_name(r);
	ap_run_map_to_storage(r);

	if (!ap_is_directory(r->pool, r->filename)) {
		ap_rprintf(r, "550 '%s': No such file or directory.\r\n",patharg);
	} else {
		ur->current_directory = apr_pstrdup(ur->p,newpath);
		ap_rprintf(r, "250 CWD command successful.\r\n");
	}
    ap_rflush(r);
    return OK;
}

int ap_ftp_handle_help(request_rec *r, char *buffer, void *data)
{
	char *command;
//	char *temp;
	int column;
	apr_hash_index_t* hash_itr;
	ftp_handler_st *handle_func;

	command = ap_getword_white_nc(r->pool, &buffer);
	if (command[0]=='\0') {
		if (!(int)data) { /* HELP */
			ap_rprintf(r, "214-The following commands are implemented.\r\n");
		} else { /* FEAT */
			ap_rprintf(r, "211-FEAT\r\n");
		}
		column = 0;
		for (hash_itr = apr_hash_first(r->pool,ap_ftp_hash); hash_itr;
				hash_itr = apr_hash_next(hash_itr)) {
			apr_hash_this(hash_itr, (const void **)&command, NULL,(void **)&handle_func);
			command = apr_pstrdup(r->pool,command);
			ap_ftp_str_toupper(command);
			if (!(int)data) { /* HELP */
				column++;
				ap_rprintf(r,"   %-4s%c",command, 
					(handle_func->states & FTP_NOT_IMPLEMENTED)?'*':' ');
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
			ap_rprintf(r, "214-Use \"HELP command\" to get help for a specific command\r\n");
			ap_rprintf(r, "214-Command not implemented have a '*' next to them.\r\n");
			ap_rprintf(r, "214 Send Comments %s.\r\n",r->server->server_admin);
		} else { /* FEAT */
			ap_rprintf(r, "211 END\r\n");
		}
	} else {
		ap_str_tolower(command);
		handle_func = apr_hash_get(ap_ftp_hash, command, APR_HASH_KEY_STRING);
		/* Str to Upper */
		ap_ftp_str_toupper(command);
		if (!handle_func) {
			ap_rprintf(r, "502 Unknown command %s\r\n",command);
		} else {
			if (handle_func->states & FTP_NOT_IMPLEMENTED) {
				if (handle_func->help_text) {
					ap_rprintf(r, "214-Syntax: %s %s\r\n",command,handle_func->help_text);
				}
				ap_rprintf(r, "214 This command is not implemented on this server.\r\n");
			} else {
				if (!handle_func->help_text) {
					ap_rprintf(r, "214 Syntax: %s No Help Available.\r\n",command);
				} else {
					ap_rprintf(r, "214 Syntax: %s %s\r\n",command,handle_func->help_text);
				}
			}
		}
	}
	ap_rflush(r);
	return OK;
}

int ap_ftp_handle_syst(request_rec *r, char *buffer, void *data)
{
	ap_rputs("215 UNIX Type: L8\r\n",r);
	ap_rflush(r);
	return OK;
}

int ap_ftp_handle_NOOP(request_rec *r, char *buffer, void *data)
{
	if (!data) {
		ap_rputs("200 Command completed successfully.\r\n",r);
	} else {
		char *arg = ap_getword_white_nc(r->pool, &buffer);
		ap_str_tolower(arg);
		if (!apr_strnatcmp(arg, data)) {
			ap_rputs("200 Command completed successfully.\r\n",r);
		} else {
			ap_rputs("504 Invalid argument.\r\n",r);
		}
	}
	ap_rflush(r);
	return OK;
}

int ap_ftp_handle_pasv(request_rec *r, char *buffer, void *data)
{
	apr_sockaddr_t *listen_addr;
	apr_port_t port;
	apr_status_t res;
	ftp_user_rec *ur = ap_get_module_config(r->request_config,
					&ftp_module);
	ftp_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftp_module);
	int bind_retries = 10;
	char *ipaddr,*temp;

/* Close old socket if already connected */
	ftp_data_socket_close(ur);
/* Clear Data connection Pool */
	apr_pool_clear(ur->data.p);
/* Assign IP */
	if ((res = apr_sockaddr_info_get(&listen_addr,r->connection->local_ip, APR_INET, 1024,
				0, ur->data.p)) != APR_SUCCESS) {
		ap_rprintf(r,"451 Unable to assign socket addresss\r\n");
	}
	if ((res = apr_socket_create_ex(&ur->data.pasv, listen_addr->family,
			SOCK_STREAM, APR_PROTO_TCP, ur->data.p)) != APR_SUCCESS) {
		ap_rprintf(r, "451 Unable to create Socket\r\n");
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
	if (!bind_retries)
		ap_rputs("451 Error Binding to address\r\n", r);
	
/* open the socket in listen mode and allow 1 queued connection */
	apr_socket_listen(ur->data.pasv, 1);

/* Change .'s to ,'s */
	temp = ipaddr = apr_pstrdup(ur->data.p, r->connection->local_ip);
	while (*temp) {
		if (*temp=='.')
			*temp=',';
		++temp;
	}
	ap_rprintf(r,"227 Entering Passive Mode (%s,%d,%d)\r\n",
		ipaddr, port >> 8, port & 255);
	ap_rflush(r);
	ur->data.type = FTP_PIPE_PASV;
	ur->state = FTP_TRANS_DATA;
	return OK;
}

int ap_ftp_handle_port(request_rec *r, char *buffer, void *data)
{
	int ip1,ip2,ip3,ip4,p1,p2;
	char *ipaddr;
	ftp_user_rec *ur = ap_get_module_config(r->request_config,
					&ftp_module);
	ftp_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftp_module);

	if (!pConfig->bAllowPort) {
		ap_rprintf(r, "502  PORT command not allowed on this server\r\n");
		ap_rflush(r);
		return OK;
	}
	sscanf(buffer, "%d,%d,%d,%d,%d,%d",
		&ip1,&ip2,&ip3,&ip4,
		&p1,&p2);
	ipaddr = apr_psprintf(r->pool, "%d.%d.%d.%d",ip1,ip2,ip3,ip4);
	apr_sockaddr_info_get(&ur->data.port,ipaddr, APR_INET, (p1<<8)+p2,
				0, ur->data.p);
	ap_rprintf(r, "200 Command Successful\r\n");
	ap_rflush(r);
	ur->data.type = FTP_PIPE_PORT;
	ur->state = FTP_TRANS_DATA;
	return OK;
}

int ap_ftp_handle_list(request_rec *r, char *buffer, void *data)
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

    ftp_user_rec *ur = ap_get_module_config(r->request_config,
					&ftp_module);
	ftp_config_rec *pConfig = ap_get_module_config(r->server->module_config,
					&ftp_module);

	ap_rputs("150 Opening ASCII mode data connection for file list.\r\n", r);
	if ((res = ftp_data_socket_connect(ur,r)) != APR_SUCCESS) {
		ap_rprintf(r, "425 Error accepting connection\r\n");
		ap_rflush(r);
		return OK;
	}
	apr_socket_timeout_set(ur->data.pipe,apr_time_from_sec(300));

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

	ap_run_translate_name(r);
	ap_run_map_to_storage(r);

	if (!ap_is_directory(r->pool, r->filename)) {
		ap_rprintf(r, "451 Not a directory\r\n");
		ap_rflush(r);
		ftp_data_socket_close(ur);
		return OK;
	}

	if (apr_dir_open(&dir, r->filename, ur->data.p)!=APR_SUCCESS) {
		ap_rprintf(r, "451 Permission Denied\r\n");
		ap_rflush(r);
		ftp_data_socket_close(ur);
		return OK;
	}
	if ((int)data==1) {  /* NLST */
		flags = APR_FINFO_NAME | APR_FINFO_TYPE;
	} else { /* LIST */
		flags = APR_FINFO_NAME | APR_FINFO_TYPE | APR_FINFO_SIZE
			| APR_FINFO_OWNER | APR_FINFO_PROT | APR_FINFO_MTIME
			| APR_FINFO_TYPE;
	}
	nowtime = apr_time_now();
	while (apr_dir_read(&entry,flags,dir)==APR_SUCCESS) {
		if ((int)data==1) { /* NLST */
			if (entry.filetype != APR_DIR) {
				/* TODO: Check for too many slashes in arg buffer */
				if (*buffer!='\0') {
					apr_snprintf(buff, 128, "%s/%s\r\n", buffer, entry.name);
				} else {
					apr_snprintf(buff, 128, "%s\r\n", entry.name);
				}
			}
		} else { /* LIST */
			if (!strcmp(entry.name,".") || !strcmp(entry.name,"..")) {
				continue;
			}
			apr_time_exp_lt(&time,entry.mtime);
			if ( (nowtime - entry.mtime) > apr_time_from_sec(60 * 60 * 24 * 182) ) {
				apr_strftime(strtime, &res, 16, "%b %d  %Y", &time);
			} else {
				apr_strftime(strtime, &res, 16, "%b %d %H:%M", &time);
			}

			apr_gid_name_get(&group,entry.group,ur->data.p);
			apr_uid_name_get(&user,entry.user,ur->data.p);
			if (pConfig->bRealPerms) {
				apr_cpystrn(strperms,"----------",11);
				if (entry.filetype == APR_DIR)
					strperms[0]='d';
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
				if (entry.filetype == APR_DIR) {
					apr_cpystrn(strperms,"drwxr-xr-x",11);
				} else {
					apr_cpystrn(strperms,"-rw-r--r--",11);
				}
			}
			apr_snprintf(buff, 128, "%s   1 %-8s %-8s %8"APR_OFF_T_FMT" %s %s\r\n",
				strperms, user, group,
				entry.size, strtime, entry.name);
		}
		res  = strlen(buff);
		apr_socket_send(ur->data.pipe, buff, &res);
	}
	apr_dir_close(dir);
	ap_rputs("226 Transfer complete.\r\n",r);
	ap_rflush(r);
	ftp_data_socket_close(ur);
	return OK;
}

int ap_ftp_handle_type(request_rec *r, char *buffer, void *data)
{
	char *arg = apr_pstrdup(r->pool, buffer);
    ftp_user_rec *ur = ap_get_module_config(r->request_config,
				&ftp_module);

	ap_str_tolower(arg);
	if (!apr_strnatcmp(arg, "l8") ||
			!apr_strnatcmp(arg, "l 8") ||
			!apr_strnatcmp(arg, "i")) {
		ap_rprintf(r, "200 Set Binary mode.\r\n");
		ur->binaryflag = 1;
	} else if (!apr_strnatcmp(arg, "a") ||
			!apr_strnatcmp(arg, "a n")) {
		ap_rprintf(r, "200 Set ASCII mode.\r\n");
		ur->binaryflag = 0;
	} else {
		ap_rprintf(r, "5 Invalid Argument.\r\n");
	}
	ap_rflush(r);
	return OK;
}

int ap_ftp_handle_retr(request_rec *r, char *buffer, void *data)
{
	char *filename = ap_getword_white_nc(r->pool,&buffer); 
	apr_off_t off;
	apr_size_t size;
	apr_file_t *fp;
	apr_finfo_t finfo;

	ftp_user_rec *ur = ap_get_module_config(r->request_config,
					&ftp_module);

	apr_filepath_merge(&r->uri, ur->current_directory, filename,
			APR_FILEPATH_TRUENAME, r->pool);

	ap_run_translate_name(r);
	ap_run_map_to_storage(r);
	/* TODO: hand a subrequest to Apache to retrieve file */
	if (apr_file_open(&fp, r->filename, APR_READ | APR_SENDFILE_ENABLED,
			APR_OS_DEFAULT, ur->data.p) != APR_SUCCESS) {
		ap_rprintf(r, "451 %s: file does not exist\r\n",filename);
		ap_rflush(r);
		ftp_data_socket_close(ur);
		return OK;
	}
	apr_file_info_get(&finfo, APR_FINFO_TYPE | APR_FINFO_SIZE, fp);
	if (finfo.filetype == APR_DIR) {
		ap_rprintf(r, "550 %s: not a plain file\r\n",filename);
		ap_rflush(r);
		apr_file_close(fp);
		ftp_data_socket_close(ur);
		return OK;
	}
	ap_rprintf(r, "150 Opening data connection\r\n");
	ap_rflush(r);
	if (ftp_data_socket_connect(ur,r) != APR_SUCCESS) {
		ap_rprintf(r, "425 Error accepting connection\r\n");
		ap_rflush(r);
		apr_file_close(fp);
		return OK;
	}
	apr_socket_timeout_set(ur->data.pipe,apr_time_from_sec(300));
/* Start sending the file */
	size  = finfo.size;
	off = 0;
	apr_socket_sendfile(ur->data.pipe, fp, NULL, &off, &size, 0);
/* Close verything up */
	ap_rprintf(r, "226 Transfer complete\r\n");
	ap_rflush(r);
	ftp_data_socket_close(ur);
	apr_file_close(fp);
	return OK;
}
int ap_ftp_handle_size(request_rec *r, char *buffer, void *data)
{
	apr_finfo_t finfo;

    ftp_user_rec *ur = ap_get_module_config(r->request_config,
				&ftp_module);

	if (apr_filepath_merge(&r->uri,ur->current_directory,buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, "550 invalid file name\r\n");
		ap_rflush(r);
		return OK;
	}

	ap_run_translate_name(r);
	ap_run_map_to_storage(r);

	if (apr_stat(&finfo, r->filename, APR_FINFO_SIZE | APR_FINFO_TYPE, ur->data.p)!=APR_SUCCESS) {
		ap_rprintf(r, "550 Error stating file\r\n");
		ap_rflush(r);
		return OK;
	}
	if (finfo.filetype == APR_DIR) {
		ap_rprintf(r, "550 %s: not a plain file\r\n", buffer);
	} else {
		ap_rprintf(r, "213 %"APR_OFF_T_FMT"\r\n",finfo.size);
	}
	ap_rflush(r);
	return OK;
}
int ap_ftp_handle_mdtm(request_rec *r, char *buffer, void *data)
{
	apr_finfo_t finfo;
    ftp_user_rec *ur = ap_get_module_config(r->request_config,
				&ftp_module);

	if (apr_filepath_merge(&r->uri,ur->current_directory,buffer,
			APR_FILEPATH_TRUENAME|APR_FILEPATH_NOTRELATIVE, r->pool) != APR_SUCCESS) {
		ap_rprintf(r, "550 invalid file name\r\n");
		ap_rflush(r);
		return OK;
	}

	ap_run_translate_name(r);
	ap_run_map_to_storage(r);

	if (apr_stat(&finfo, r->filename, APR_FINFO_MTIME | APR_FINFO_TYPE, ur->data.p)!=APR_SUCCESS) {
		ap_rprintf(r, "550 Error stating file\r\n");
		ap_rflush(r);
		return OK;
	}
	if (finfo.filetype == APR_DIR) {
		ap_rprintf(r, "550 %s: not a plain file\r\n", buffer);
	} else {
		char strtime[32];
		int res;
		apr_time_exp_t time;
		apr_time_exp_gmt(&time,finfo.mtime);
		apr_strftime(strtime, &res, 32, "%Y%m%d%H%M%S", &time);
		ap_rprintf(r, "213 %s\r\n",strtime);
	}
	ap_rflush(r);
	return OK;
}
