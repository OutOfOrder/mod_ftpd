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

/* $Header: /home/cvs/httpd-ftp/mod_ftpd.h,v 1.1 2004/01/08 04:42:49 urkle Exp $ */
#ifndef _MOD_FTPD_H_
#define _MOD_FTPD_H_

#include "apr_hooks.h"
#include "httpd.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Current version of the Plugin interface */

#define FTPD_PLUGIN_VERSION 20031215

/* Create a set of FTPD_DECLARE(type), FTPD_DECLARE_NONSTD(type) and 
 * FTPD_DECLARE_DATA with appropriate export and import tags for the platform
 */
#if !defined(WIN32)
#define FTPD_DECLARE(type)            type
#define FTPD_DECLARE_NONSTD(type)     type
#define FTPD_DECLARE_DATA
#elif defined(FTPD_DECLARE_STATIC)
#define FTPD_DECLARE(type)            type __stdcall
#define FTPD_DECLARE_NONSTD(type)     type
#define FTPD_DECLARE_DATA
#elif defined(FTPD_DECLARE_EXPORT)
#define FTPD_DECLARE(type)            __declspec(dllexport) type __stdcall
#define FTPD_DECLARE_NONSTD(type)     __declspec(dllexport) type
#define FTPD_DECLARE_DATA             __declspec(dllexport)
#else
#define FTPD_DECLARE(type)            __declspec(dllimport) type __stdcall
#define FTPD_DECLARE_NONSTD(type)     __declspec(dllimport) type
#define FTPD_DECLARE_DATA             __declspec(dllimport)
#endif

/* mod_ftp published internal strcutures */

/* FTP handlers registration */
#define HANDLER_PROTOTYPE request_rec *r, char *buffer, void *data

#define HANDLER_FUNC(name)  ftpd_handler_##name
#define HANDLER_DECLARE(name) FTPD_DECLARE(int) HANDLER_FUNC(name) (HANDLER_PROTOTYPE)

typedef int ftpd_handler(HANDLER_PROTOTYPE);

FTPD_DECLARE(void) ftpd_register_handler(char *key, ftpd_handler *func, int states,
							const char *help_text, void *data, apr_pool_t *p);
FTPD_DECLARE(void) ap_ftpd_str_toupper(char *str);

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
	FTPD_M_CHDIR = 0,
	FTPD_M_LIST,
/*	FTPD_M_STOU,*/
	FTPD_M_APPEND,
	FTPD_M_XRMD,
	FTPD_M_LAST
};

/* Handler return codes */
enum {
	FTPD_HANDLER_OK = 0,				/* Everthings OK */
	FTPD_HANDLER_QUIT,				/* Terminate the connection */
	FTPD_HANDLER_PERMDENY,			/* Permision was denied */
	FTPD_HANDLER_FILENOTFOUND,		/* File does not exist */
	FTPD_HANDLER_SERVERERROR,		/* Other server error */
	FTPD_HANDLER_USER_UNKNOWN,		/* User is unknown */
	FTPD_HANDLER_USER_NOT_ALLOWED,	/* User not allowed to login */
	FTPD_HANDLER_UPDATE_AUTH,		/* Update the global auth credentials */
	FTPD_HANDLER_UPDATE_AGENT,		/* Update the global UserAgent */
	FTPD_HANDLER_LAST
};

/* Current Data Pipe state */
typedef enum {
	FTPD_PIPE_NONE = 0,
	FTPD_PIPE_PASV,
	FTPD_PIPE_PORT,
	FTPD_PIPE_OPEN,
	FTPD_PIPE_LAST
} ftpd_pipe_state;

/* connection state and handler flags */
typedef enum {
	FTPD_STATE_AUTH 				= 0x001, /* The initial connection state */
	FTPD_STATE_USER_ACK 			= 0x002, /* a username has been provided, password expected */
	FTPD_STATE_TRANS_NODATA 		= 0x004, /* standard transaction state */
	FTPD_STATE_TRANS_DATA 		= 0x008, /* a pasv or port or variant has been provided for file transfer */
	FTPD_STATE_RENAME			= 0x010, /* a from name has been provided, a to name is expected */
	FTPD_FLAG_EPSV_LOCK			= 0x020, /* Flag: which commands are locked in epsv all state */
	FTPD_FLAG_NOT_IMPLEMENTED 	= 0x040, /* Flag: an unimplimented command */
	FTPD_FLAG_FEATURE 			= 0x080, /* Flag: a Feature listed in FEAT */
	FTPD_FLAG_HIDE_ARGS			= 0x100, /* Flag: hide arguments in logging */
	FTPD_FLAG_LOG_COMMAND		= 0x200  /* Flag: log this command in the access log */
} ftpd_state;

/* All States connection states */
#define FTPD_ALL_STATES FTPD_STATE_AUTH | FTPD_STATE_USER_ACK | FTPD_STATE_TRANS_NODATA \
	| FTPD_STATE_TRANS_DATA | FTPD_STATE_RENAME
/* All command Flags */
#define FTPD_ALL_FLAGS FTPD_FLAG_EPSV_LOCK | FTPD_FLAG_NOT_IMPLEMENTED | FTPD_FLAG_FEATURE \
	| FTPD_FLAG_HIDE_ARGS | FTPD_FLAG_LOG_COMMAND
/* Transaction state is both DATA and NODATA */
#define FTPD_STATE_TRANSACTION (FTPD_STATE_TRANS_NODATA | FTPD_STATE_TRANS_DATA)

typedef struct ftpd_datacon_rec {
	apr_pool_t *p;
	ftpd_pipe_state type;
	union {
		apr_socket_t *pasv;
		apr_sockaddr_t *port;
	};
	apr_socket_t *pipe;
} ftpd_datacon_rec;

typedef struct ftpd_user_rec {
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

	ftpd_datacon_rec	data;

    ftpd_state state;
	int epsv_lock;

} ftpd_user_rec;

/* Gets a pointer to the internal session state structure */

FTPD_DECLARE(ftpd_user_rec) *ftpd_get_user_rec(const request_rec *r);

/*
 * HOOK Stuctures
 *
 * Forward Declared HOOKS
 *
 */

typedef struct ftpd_hooks_chroot ftpd_hooks_chroot;
typedef struct ftpd_hooks_listing ftpd_hooks_listing;

/*
 * FTP Plugins
 *
 */

/*
 * ftpd_provider
 *
 * This structure defines all of the hooks that an FTP plugin can provide.
 *
 */
#define FTPD_PROVIDER_GROUP "ftpd"

typedef struct {
	const ftpd_hooks_chroot *chroot;
	const ftpd_hooks_listing *listing;
} ftpd_provider;

typedef struct ftpd_provider_list ftpd_provider_list;

struct ftpd_provider_list {
	const char *name;
	const ftpd_provider *provider;
	ftpd_provider_list *next;
};

/* chroot hooks */
typedef enum {
	FTPD_CHROOT_USER_FOUND = 0,	/* User is found and chroot has been set */
	FTPD_CHROOT_USER_NOT_FOUND,	/* User not found pass to next provider */
	FTPD_CHROOT_FAIL				/* Fail the login */
} ftpd_chroot_status_t;

struct ftpd_hooks_chroot {
	/* only one hook really needed right? */
	/* Get the chroot directory for the specified user */
	ftpd_chroot_status_t (*map_chroot)(
		const request_rec *r,
		const char **chroot,
		const char **initroot
	);
};

/* chroot hooks */
struct ftpd_hooks_listing {
	/* only one hook really needed right? */
	/* Get the listing */
	char * (*get_entry)(
		const char *name
	);
};

#ifdef __cplusplus
}
#endif

#endif /*_MOD_FTPD_H_*/
