/* $Header: /home/cvs/httpd-ftp/server_config.h,v 1.2 2003/12/22 06:12:13 urkle Exp $ */
#include "http_config.h"


static const char *ap_set_server_string_slot(cmd_parms *cmd,
                                    		 void *struct_ptr,
                                     		 const char *arg) __attribute__ ((unused));
static const char *ap_set_server_flag_slot(cmd_parms *cmd, 
										   void *struct_ptr, 
										   int arg) __attribute__ ((unused));
static const char *ap_set_server_int_slot(cmd_parms *cmd,
										  void *struct_ptr,
										  const char *arg) __attribute__ ((unused));
static const char *ap_set_server_string_slot_lower(cmd_parms *cmd,
                                                   void *struct_ptr,
                                                   const char *arg_) __attribute__ ((unused));
static const char *ap_set_server_file_slot(cmd_parms *cmd, void *struct_ptr,
                                                 const char *arg) __attribute__ ((unused));
/* implementation */

static const char *ap_set_server_flag_slot(cmd_parms *cmd, 
										   void *struct_ptr, 
										   int arg)
{
	int offset = (int)(long)cmd->info;
	void *ptr = ap_get_module_config(cmd->server->module_config,
			&MODULE_NAME);

    const char *err = ap_check_cmd_context(cmd,NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) {
		return err;
	}

	*(int *)((char *)ptr + offset) = arg ? 1 : 0;

    return NULL;
}

static const char *ap_set_server_int_slot(cmd_parms *cmd,
										  void *struct_ptr,
										  const char *arg)
{
	char *endptr;
	char *error_str = NULL;
	int offset = (int)(long)cmd->info;
	void *ptr = ap_get_module_config(cmd->server->module_config,
			&MODULE_NAME);

    const char *err = ap_check_cmd_context(cmd,NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) {
		return err;
	}

	*(int *)(ptr + offset) = strtol(arg, &endptr, 10);

	if ((*arg == '\0') || (*endptr != '\0')) {
		error_str = apr_psprintf(cmd->pool,
				"Invalid value for the directive %s, exptected integer",
				cmd->directive->directive);
	}

    return error_str;
}

static const char *ap_set_server_string_slot(cmd_parms *cmd,
                                     		 void *struct_ptr,
                                     		 const char *arg)
{
	int offset = (int)(long)cmd->info;
	void *ptr = ap_get_module_config(cmd->server->module_config,
			&MODULE_NAME);

	const char *err = ap_check_cmd_context(cmd,NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) {
		return err;
	}

    *(const char **)((char *)ptr + offset) = arg;
    
    return NULL;
}

static const char *ap_set_server_string_slot_lower(cmd_parms *cmd,
                                                   void *struct_ptr,
                                                   const char *arg_)
{
    char *arg = apr_pstrdup(cmd->pool,arg_);
	int offset = (int)(long)cmd->info;
	void *ptr = ap_get_module_config(cmd->server->module_config,
			&MODULE_NAME);

	const char *err = ap_check_cmd_context(cmd,NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) {
		return err;
	}

    ap_str_tolower(arg);
    *(char **)((char *)ptr + offset) = arg;
    
    return NULL;
}

static const char *ap_set_server_file_slot(cmd_parms *cmd, void *struct_ptr,
                                                 const char *arg)
{
    /* Prepend server_root to relative arg.
     * This allows most args to be independent of server_root,
     * so the server can be moved or mirrored with less pain.
     */
    const char *path;
	int offset = (int)(long)cmd->info;
	void *ptr = ap_get_module_config(cmd->server->module_config,
			&MODULE_NAME);

	const char *err = ap_check_cmd_context(cmd,NOT_IN_DIR_LOC_FILE|NOT_IN_LIMIT);
	if (err) {
		return err;
	}

    path = ap_server_root_relative(cmd->pool, arg);
                            
    if (!path) {
        return apr_pstrcat(cmd->pool, "Invalid file path ",
                           arg, NULL);
    }
    
    *(const char **) ((char*)ptr + offset) = path;

    return NULL;
}
