dnl Required initializer
AC_INIT(mod_ftpd, 0.12.2)
AC_PREREQ(2.53)
AC_CONFIG_HEADERS(config.h)

AC_CONFIG_SRCDIR(ftp_core.c)

dnl Add a test for a compiler.
AC_PROG_CC

APACHE_VERSION=2.0.44
CHECK_PATH_APACHE($APACHE_VERSION,
   		:,
   		AC_MSG_ERROR([*** Apache version $APACHE_VERSION not found!])
  		)

AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])

dnl configure providers

MOD_FTPD_INCLUDE_PROVIDERS(providers)

dnl Write config.status and the Makefile

AC_OUTPUT(Makefile
    docs/Makefile
    docs/rfc/Makefile)
