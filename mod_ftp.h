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

/* Handler return codes */
#define FTP_QUIT                1
#define FTP_USER_UNKNOWN        2
#define FTP_USER_NOT_ALLOWED    3
#define FTP_UPDATE_AUTH			4

/* Current Data Pipe state */
typedef enum {
	FTP_PIPE_NONE,
	FTP_PIPE_PASV,
	FTP_PIPE_PORT,
	FTP_PIPE_OPEN
} ftp_pipe_state;

/* connection state */
typedef enum {
	FTP_AUTH 			= 0x001,
	FTP_USER_ACK 		= 0x002,
	FTP_TRANS_NODATA 	= 0x004,
	FTP_TRANS_DATA 		= 0x008,
	FTP_TRANS_RENAME	= 0x010,
	FTP_EPSV_LOCK		= 0x020,
	FTP_NOT_IMPLEMENTED = 0x040,
	FTP_FEATURE 		= 0x080,
	FTP_HIDE_ARGS		= 0x100
} ftp_state;

/* All States does not contain FTP_NOT_IMPLEMENTED */
#define FTP_ALL_STATES FTP_AUTH | FTP_USER_ACK | FTP_TRANS_NODATA \
	| FTP_TRANS_DATA | FTP_TRANS_RENAME
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

	int binaryflag;
	int restart_position;
	char *rename_file;

	ftp_datacon_rec	data;

    ftp_state state;
	int epsv_lock;

} ftp_user_rec;

/* Gets a pointer to the internal session state structure */

ftp_user_rec *ftp_get_user_rec(const request_rec *r);

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
	const char *name;
	const ftp_hooks_chroot *chroot;
	const ftp_hooks_listing *listing;
} ftp_provider;

/*FTP_DECLARE(void) ftp_register_provider(apr_pool_t *p,
										const ftp_provider *hooks);

const ftp_provider *ftp_lookup_provider(const char *name);*/

/* chroot hooks */
typedef enum {
	FTP_CHROOT_USER_FOUND = 0,	/* User is found and chroot has been set */
	FTP_CHROOT_USER_NOT_FOUND,	/* User not found pass to next provider */
	FTP_CHROOT_FAIL
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
