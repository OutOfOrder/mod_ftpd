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

/* $Header: /home/cvs/httpd-ftp/Attic/mod_ftp.h,v 1.11 2003/12/22 06:12:13 urkle Exp $ */
#ifndef _MOD_FTP_H_
#define _MOD_FTP_H_

#include "apr_hooks.h"
#include "httpd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Current version of the Plugin interface */

#define FTP_PLUGIN_VERSION 20031215

/* Create a set of FTP_DECLARE(type), FTP_DECLARE_NONSTD(type) and 
 * FTP_DECLARE_DATA with appropriate export and import tags for the platform
 */
#if !defined(WIN32)
#define FTP_DECLARE(type)            type
#define FTP_DECLARE_NONSTD(type)     type
#define FTP_DECLARE_DATA
#elif defined(FTP_DECLARE_STATIC)
#define FTP_DECLARE(type)            type __stdcall
#define FTP_DECLARE_NONSTD(type)     type
#define FTP_DECLARE_DATA
#elif defined(FTP_DECLARE_EXPORT)
#define FTP_DECLARE(type)            __declspec(dllexport) type __stdcall
#define FTP_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define FTP_DECLARE_DATA             __declspec(dllexport)
#else
#define FTP_DECLARE(type)            __declspec(dllimport) type __stdcall
#define FTP_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define FTP_DECLARE_DATA             __declspec(dllimport)
#endif

/* mod_ftp published internal strcutures */

/* FTP handlers registration */
#define HANDLER_PROTOTYPE request_rec *r, char *buffer, void *data

#define HANDLER_FUNC(name)  ftp_handler_##name
#define HANDLER_DECLARE(name) FTP_DECLARE(int) HANDLER_FUNC(name) (HANDLER_PROTOTYPE)

typedef int ap_ftp_handler(HANDLER_PROTOTYPE);

FTP_DECLARE(void) ftp_register_handler(char *key, ap_ftp_handler *func, int states,
							const char *help_text, void *data, apr_pool_t *p);
FTP_DECLARE(void) ap_ftp_str_toupper(char *str);

/* FTP Return codes: Shamelessly borrowed from vsftp/ftpcodes.h */
#define FTP_C_DATACONN		"150"

#define FTP_C_CLNTOK		"200"
#define FTP_C_NOOPOK		"200"
#define FTP_C_TYPEOK		"200"
#define FTP_C_PORTOK		"200"
#define FTP_C_UMASKOK		"200"
#define FTP_C_CHMODOK		"200"
#define FTP_C_FEATOK		"211"
#define FTP_C_SIZEOK		"213"
#define FTP_C_MDTMOK		"213"
#define FTP_C_HELPOK		"214"
#define FTP_C_SYSTOK		"215"
#define FTP_C_GREET			"220"
#define FTP_C_GOODBYE		"221"
#define FTP_C_ABOR_NOCONN	"225"
#define FTP_C_TRANSFEROK	"226"
#define FTP_C_ABOROK		"226"
#define FTP_C_PASVOK		"227"
#define FTP_C_EPASVOK		"229"
#define FTP_C_LOGINOK		"230"
#define FTP_C_CWDOK			"250"
#define FTP_C_RMDIROK		"250"
#define FTP_C_DELEOK		"250"
#define FTP_C_RENAMEOK		"250"
#define FTP_C_PWDOK			"257"
#define FTP_C_MKDIROK		"257"

#define FTP_C_GIVEPWORD		"331"
#define FTP_C_RESTOK		"350"
#define FTP_C_RNFROK		"350"

#define FTP_C_IDLE_TIMEOUT	"421"
#define FTP_C_DATA_TIMEOUT	"421"
#define FTP_C_NOLOGIN		"421"
#define FTP_C_BADSENDCONN	"425"
#define FTP_C_BADSENDNET	"426"
#define FTP_C_BADSENDFILE	"451"
#define FTP_C_PASVFAIL		"451"

#define FTP_C_BADCMD		"500"
#define FTP_C_CMDNOTIMPL	"502"
#define FTP_C_CMDDISABLED	"502"
#define FTP_C_BADHELP		"502"
#define FTP_C_NEEDUSER		"503"
#define FTP_C_NEEDRNFR		"503"
#define FTP_C_INVALIDARG	"504"
#define FTP_C_INVALID_PROTO	"522"
#define FTP_C_LOGINERR		"530"
#define FTP_C_FILEFAIL		"550"
#define FTP_C_PERMDENY		"550"
#define FTP_C_UPLOADFAIL	"553"
#define FTP_C_RENAMEFAIL	"553"

/* FTP methods */
enum {
	FTP_M_CHDIR = 0,
	FTP_M_LIST,
/*	FTP_M_STOU,*/
	FTP_M_APPEND,
	FTP_M_XRMD,
	FTP_M_LAST
};

/* Handler return codes */
#define FTP_QUIT                1
#define FTP_USER_UNKNOWN        2
#define FTP_USER_NOT_ALLOWED    3
#define FTP_UPDATE_AUTH			4
#define FTP_UPDATE_AGENT		5

/* Current Data Pipe state */
typedef enum {
	FTP_PIPE_NONE,
	FTP_PIPE_PASV,
	FTP_PIPE_PORT,
	FTP_PIPE_OPEN
} ftp_pipe_state;

/* connection state */
typedef enum {
	FTP_AUTH 			= 0x001, /* The initial connection state */
	FTP_USER_ACK 		= 0x002, /* a username has been provided, password expected */
	FTP_TRANS_NODATA 	= 0x004, /* standard transaction state */
	FTP_TRANS_DATA 		= 0x008, /* a pasv or port or variant has been provided for file transfer */
	FTP_TRANS_RENAME	= 0x010, /* a from name has been provided, a to name is expected */
	FTP_EPSV_LOCK		= 0x020, /* Flag: which commands are locked in epsv all state */
	FTP_NOT_IMPLEMENTED = 0x040, /* Flag: an unimplimented command */
	FTP_FEATURE 		= 0x080, /* Flag: a Feature listed in FEAT */
	FTP_HIDE_ARGS		= 0x100, /* Flag: hide arguments in logging */
	FTP_LOG_COMMAND		= 0x200  /* Flag: log this command in the access log */
} ftp_state;

/* All States connection states */
#define FTP_ALL_STATES FTP_AUTH | FTP_USER_ACK | FTP_TRANS_NODATA \
	| FTP_TRANS_DATA | FTP_TRANS_RENAME
/* All command Flags */
#define FTP_ALL_FLAGS FTP_EPSV_LOCK | FTP_NOT_IMPLEMENTED | FTP_FEATURE \
	| FTP_HIDE_ARGS | FTP_LOG_COMMAND
/* Transaction state is both DATA and NODATA */
#define FTP_TRANSACTION (FTP_TRANS_NODATA | FTP_TRANS_DATA)

typedef struct ftp_datacon_rec {
	apr_pool_t *p;
	ftp_pipe_state type;
	union {
		apr_socket_t *pasv;
		apr_sockaddr_t *port;
	};
	apr_socket_t *pipe;
} ftp_datacon_rec;

typedef struct ftp_user_rec {
    apr_pool_t *p;

	conn_rec *c;
	server_rec *s;

    char *user;
    char *passwd;
    char *auth_string;

	const char *chroot;
	char *current_directory;
	char *useragent;

	int binaryflag;
	int restart_position;
	char *rename_file;

	ftp_datacon_rec	data;

    ftp_state state;
	int epsv_lock;

} ftp_user_rec;

/* Gets a pointer to the internal session state structure */

FTP_DECLARE(ftp_user_rec) *ftp_get_user_rec(const request_rec *r);

/*
 * HOOK Stuctures
 *
 * Forward Declared HOOKS
 *
 */

typedef struct ftp_hooks_chroot ftp_hooks_chroot;
typedef struct ftp_hooks_listing ftp_hooks_listing;

/*
 * FTP Plugins
 *
 */

/*
 * ftp_provider
 *
 * This structure defines all of the hooks that an FTP plugin can provide.
 *
 */
#define FTP_PROVIDER_GROUP "ftp"

typedef struct {
	const ftp_hooks_chroot *chroot;
	const ftp_hooks_listing *listing;
} ftp_provider;

typedef struct ftp_provider_list ftp_provider_list;

struct ftp_provider_list {
	const char *name;
	const ftp_provider *provider;
	ftp_provider_list *next;
};

/* chroot hooks */
typedef enum {
	FTP_CHROOT_USER_FOUND = 0,	/* User is found and chroot has been set */
	FTP_CHROOT_USER_NOT_FOUND,	/* User not found pass to next provider */
	FTP_CHROOT_FAIL				/* Fail the login */
} ftp_chroot_status_t;

struct ftp_hooks_chroot {
	/* only one hook really needed right? */
	/* Get the chroot directory for the specified user */
	ftp_chroot_status_t (*map_chroot)(
		const request_rec *r,
		const char **chroot,
		const char **initroot
	);
};

/* chroot hooks */
struct ftp_hooks_listing {
	/* only one hook really needed right? */
	/* Get the listing */
	char * (*get_entry)(
		const char *name
	);
};

#ifdef __cplusplus
}
#endif

#endif /*_MOD_FTP_H_*/
