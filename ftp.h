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

#ifndef FTP_H
#define FTP_H

#include "apr.h"
#include "apr_md5.h"
#include "apr_hash.h"
#include "httpd.h"
#include "util_filter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_INVALID_CMD 10

module AP_MODULE_DECLARE_DATA ftp_module;

typedef struct {
    int bEnabled; /* Is FTP Enabled? */
	char* sFtpRoot; /* The FTP document root */
	int nMinPort; /* Minimum PASV port to use */
	int nMaxPort; /* Maximum PASV port to use */
	int bRealPerms; /* Show real permissionts in file listing */
	int bAllowPort; /* Whether to allow the PORT command */
} ftp_config_rec;

apr_hash_t *ap_ftp_hash;

typedef int ap_ftp_handler(request_rec *r, char *a, void *d);

typedef struct ftp_handler_st {
	ap_ftp_handler *func;
	int states;
	const char *help_text;
	void *data;
} ftp_handler_st;

#define FTP_STRING_LENGTH 255

/* Handler return codes */
#define FTP_QUIT                1
#define FTP_USER_UNKNOWN        2
#define FTP_USER_NOT_ALLOWED    3

/* FTP Return codes: Shamelessly borrowed from vsftp/ftpcodes.h */
#define FTP_C_DATACONN		"150"

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
#define FTP_C_LOGINERR		"530"
#define FTP_C_FILEFAIL		"550"
#define FTP_C_PERMDENY		"550"
#define FTP_C_UPLOADFAIL	"553"

/* Current Data Pipe state */
typedef enum { FTP_PIPE_NONE, FTP_PIPE_PASV, FTP_PIPE_PORT, FTP_PIPE_OPEN} ftp_pipe_state;

/* connection state */
typedef enum {FTP_AUTH = 1, FTP_USER_ACK = 2, FTP_TRANS_NODATA = 4, FTP_TRANS_DATA = 8, FTP_NOT_IMPLEMENTED = 16, FTP_FEATURE = 32} ftp_state;
/* All States does not contain FTP_NOT_IMPLEMENTED */
#define FTP_ALL_STATES FTP_AUTH | FTP_USER_ACK | FTP_TRANS_NODATA | FTP_TRANS_DATA
/* Transaction state is both DATA and NODATA */
#define FTP_TRANSACTION (FTP_TRANS_NODATA | FTP_TRANS_DATA)

/* FTP methods */
enum {
	FTP_M_RETR = 0,
	FTP_M_LAST
};

typedef struct ftp_user_rec {
    apr_pool_t *p;
    conn_rec *c;
    request_rec *r;

    char *user;
    char *passwd;
    char *auth_string;

	char *current_directory;
	int binaryflag;
	struct {
		ftp_pipe_state type;
		apr_pool_t *p;
		union {
			apr_socket_t *pasv;
			apr_sockaddr_t *port;
		};
		apr_socket_t *pipe;
	} data;

    ftp_state state;

/*    apr_file_t *fp;
    apr_mmap_t *mm;*/
    /* we only compute one ctx at a time, but it is a lot easier to
     * keep this in the user_rec struct, because we won't have to 
     * re-allocate space for it every time we need one.
     */
/*    apr_md5_ctx_t *ctx;*/
} ftp_user_rec;

int process_ftp_connection_internal(request_rec *r, apr_bucket_brigade *bb);

void ap_ftp_register_handler(char *key, ap_ftp_handler *func, int states,
							const char *help_text, void *data, apr_pool_t *p);
void ap_ftp_str_toupper(char *str);

int ap_ftp_handle_quit(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_user(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_passwd(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_pwd(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_cd(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_help(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_syst(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_NOOP(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_pasv(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_port(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_list(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_type(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_retr(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_size(request_rec *r, char *buffer, void *data);
int ap_ftp_handle_mdtm(request_rec *r, char *buffer, void *data);

#ifdef __cplusplus
}
#endif

#endif /*FTP_H*/
