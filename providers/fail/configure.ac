dnl Required initializer
AC_INIT(mod_ftpd_fail, 0.1)
AC_PREREQ(2.53)
AC_CONFIG_HEADERS(config.h)

AC_CONFIG_SRCDIR(mod_ftpd_fail.c)

dnl Add a test for a compiler.
AC_PROG_CC

APACHE_VERSION=2.0.44
CHECK_PATH_APACHE($APACHE_VERSION,
   		:,
   		AC_MSG_ERROR([*** Apache version $APACHE_VERSION not found!])
  		)

AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])
# Write config.status and the Makefile
AC_OUTPUT(Makefile)
