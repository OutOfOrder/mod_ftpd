/* $Id: ftp.h,v 1.24 2004/03/10 02:29:05 urkle Exp $ */
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
#ifndef FTP_H
#define FTP_H

#include "apr.h"
#include "apr_md5.h"
#include "apr_hash.h"
#include "apr_version.h"
#include "httpd.h"
#include "util_filter.h"

#if APR_MAJOR_VERSION < 1
/* With 1.0 apr_socket_create uses the apr_socket_create_ex prototype.. 
 * And apr_socket_create_ex is no more.
 * So lets remap apr_socket_create to apr_socket_create_ex
 */
#define apr_socket_create apr_socket_create_ex
#endif

#ifdef HAVE_CONFIG_H
/* Undefine these to prevent conflicts between Apache ap_config_auto.h and 
 * my config.h. Only really needed for Apache < 2.0.48, but it can't hurt.
 */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include "config.h"
#endif

#include "mod_ftpd.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_INVALID_CMD 10

module AP_MODULE_DECLARE_DATA ftpd_module;

typedef struct {
	int bEnabled; /* Is FTP Enabled? */
	//char* sFtpRoot; /* The FTP document root */
	int nMinPort; /* Minimum PASV port to use */
	int nMaxPort; /* Maximum PASV port to use */
	int bRealPerms; /* Show real permissionts in file listing */
	int bAllowPort; /* Whether to allow the PORT command */
	ftpd_provider_list *chroots; /* Order of chroot querying */
	ftpd_provider_list *limits;  /* Order of limit querying */
	int bAnnounce; /* Annount in the server header */
	int bAllowFXP; /* Allow pasv and port connections from/to machines other than the client */
	char *sFakeGroup; /* The fake group name to display for listings */
	char *sFakeUser; /* The fake user name to display for listings */
} ftpd_svr_config_rec;

typedef struct {
	int bAllowOverwrite;	/* Can a STOR overwrite an existing file. */
} ftpd_dir_config_rec;

apr_hash_t *ftpd_hash;

#define FTPD_STRING_LENGTH 255
#define FTPD_IO_BUFFER_MAX 262144 /*524288 1048576 */

int process_ftpd_connection_internal(request_rec *r, apr_bucket_brigade *bb);

typedef struct ftpd_handler_st {
	ftpd_handler *func;
	int states;
	const char *help_text;
	void *data;
} ftpd_handler_st;

HANDLER_DECLARE(quit);
HANDLER_DECLARE(user);
HANDLER_DECLARE(passwd);
HANDLER_DECLARE(pwd);
HANDLER_DECLARE(cd);
HANDLER_DECLARE(help);
HANDLER_DECLARE(syst);
HANDLER_DECLARE(NOOP);
HANDLER_DECLARE(clnt);
HANDLER_DECLARE(pasv);
HANDLER_DECLARE(port);
HANDLER_DECLARE(list);
HANDLER_DECLARE(type);
HANDLER_DECLARE(retr);
HANDLER_DECLARE(size);
HANDLER_DECLARE(mdtm);
HANDLER_DECLARE(stor);
HANDLER_DECLARE(rename);
HANDLER_DECLARE(delete);
HANDLER_DECLARE(mkdir);
HANDLER_DECLARE(rmdir);
HANDLER_DECLARE(restart);

#ifdef __cplusplus
}
#endif

#endif /*FTP_H*/
