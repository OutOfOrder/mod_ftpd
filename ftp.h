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
    int bEnabled;
} ftp_config_rec;

apr_hash_t *ap_ftp_hash;

typedef int ap_ftp_handler(request_rec *r, char *a);

typedef struct ftp_handler_st {
	ap_ftp_handler *func;
	int states;
} ftp_handler_st;

#define FTP_STRING_LENGTH 255


typedef enum {FTP_AUTH = 1, USER_ACK = 2, FTP_TRANSACTION = 4, UPDATE = 8} ftp_state;
#define FTP_ALL_STATES FTP_AUTH | USER_ACK | FTP_TRANSACTION | UPDATE

typedef struct ftp_user_rec {
    apr_pool_t *p;

    conn_rec *c;
    request_rec *r;

    char *user;
    char *passwd;
    char *auth_string;

    ftp_state state;

    apr_file_t *fp;
    apr_mmap_t *mm;
    int high_access;
    /* we only compute one ctx at a time, but it is a lot easier to
     * keep this in the user_rec struct, because we won't have to 
     * re-allocate space for it every time we need one.
     */
    apr_md5_ctx_t *ctx;
} ftp_user_rec;

void ap_ftp_register_handler(char *key, ap_ftp_handler *func, int states,
                             apr_pool_t *p);

#ifdef __cplusplus
}
#endif

#endif /*FTP_H*/
