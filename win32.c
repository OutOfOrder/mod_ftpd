/**
 * Taken from httpd-2.0.49/server/protocol.c 
 * This function is exported on unix, but not on win32
 */

/*
 * A couple of other functions which initialize some of the fields of
 * a request structure, as appropriate for adjuncts of one kind or another
 * to a request in progress.  Best here, rather than elsewhere, since
 * *someone* has to set the protocol-specific fields...
 */
#include "httpd.h"

void ap_set_sub_req_protocol(request_rec *rnew, const request_rec *r)
{
    rnew->the_request     = r->the_request;  /* Keep original request-line */

    rnew->assbackwards    = 1;   /* Don't send headers from this. */
    rnew->no_local_copy   = 1;   /* Don't try to send HTTP_NOT_MODIFIED for a
                                  * fragment. */
    rnew->method          = "GET";
    rnew->method_number   = M_GET;
    rnew->protocol        = "INCLUDED";

    rnew->status          = HTTP_OK;

    rnew->headers_in      = r->headers_in;
    rnew->subprocess_env  = apr_table_copy(rnew->pool, r->subprocess_env);
    rnew->headers_out     = apr_table_make(rnew->pool, 5);
    rnew->err_headers_out = apr_table_make(rnew->pool, 5);
    rnew->notes           = apr_table_make(rnew->pool, 5);

    rnew->expecting_100   = r->expecting_100;
    rnew->read_length     = r->read_length;
    rnew->read_body       = REQUEST_NO_BODY;

    rnew->main = (request_rec *) r;
}
