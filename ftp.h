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

/* $Header: /home/cvs/httpd-ftp/ftp.h,v 1.20 2003/12/22 06:12:12 urkle Exp $ */
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

#include "mod_ftp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_INVALID_CMD 10

module AP_MODULE_DECLARE_DATA ftp_module;

typedef struct {
    int bEnabled; /* Is FTP Enabled? */
	//char* sFtpRoot; /* The FTP document root */
	int nMinPort; /* Minimum PASV port to use */
	int nMaxPort; /* Maximum PASV port to use */
	int bRealPerms; /* Show real permissionts in file listing */
	int bAllowPort; /* Whether to allow the PORT command */
	ftp_provider_list *providers; /* Order of chroot querying */
	int bAnnounce; /* Annount in the server header */
	int bAllowFXP; /* Allow pasv and port connections from/to machines other than the client */
	char *sFakeGroup; /* The fake group name to display for listings */
	char *sFakeUser; /* The fake user name to display for listings */
} ftp_svr_config_rec;

typedef struct {
} ftp_dir_config_rec;

apr_hash_t *ap_ftp_hash;

#define FTP_STRING_LENGTH 255
#define FTP_IO_BUFFER_MAX 262144 /*524288 1048576 */

int process_ftp_connection_internal(request_rec *r, apr_bucket_brigade *bb);

typedef struct ftp_handler_st {
	ap_ftp_handler *func;
	int states;
	const char *help_text;
	void *data;
} ftp_handler_st;

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
