## This is the shared library to be built
lib_LTLIBRARIES = libhttpd_ftp.la
CFLAGS = -Wall -Werror
## Define the source file for the module
libhttpd_ftp_la_SOURCES = ftp_module.c ftp_protocol.c

## Define that an include directory is required.
INCLUDES = -I@apache_dir@/include 

noinst_HEADERS = ftp.h

install-exec-local:
	@apache_dir@/bin/apxs -a -i -n ftp libhttpd_ftp.la

install-libLTLIBRARIES:
