dnl Required initializer
AC_INIT(mod_ftp, 0.2)
AC_PREREQ(2.53)
AC_CONFIG_HEADERS(config.h)

AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])
AC_CONFIG_SRCDIR(ftp_core.c)

dnl Add a test for a compiler.
AC_PROG_CC

APACHE_VERSION=2.0.48
CHECK_PATH_APACHE($APACHE_VERSION,
   		:,
   		AC_MSG_ERROR([*** Apache version $APACHE_VERSION not found!])
  		)

# Write config.status and the Makefile
AC_OUTPUT(Makefile)
