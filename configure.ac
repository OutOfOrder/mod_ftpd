dnl Required initializer
AC_INIT(mod_ftp, 0.11.0)
AC_PREREQ(2.53)
AC_CONFIG_HEADERS(config.h)

AC_CONFIG_SRCDIR(ftp_core.c)

dnl Add a test for a compiler.
AC_PROG_CC

AC_ARG_ENABLE(dbm_provider, [AC_HELP_STRING([--disable-dbm-provider],[Do not compile the dbm provider])],
		, enable_dbm_provider=yes)
AC_ARG_ENABLE(default_provider, [AC_HELP_STRING([--disable-default-provider],[Do not compile the default provider])],
		, enable_default_provider=yes)
AC_ARG_ENABLE(fail_provider, [AC_HELP_STRING([--disable-fail-provider],[Do not compile the fail provider])],,
		, enable_fail_provider=yes)
AC_ARG_ENABLE(dbi_provider, [AC_HELP_STRING([--enable-dbi-provider],[Compile the dbi provider])],
		enable_dbi_provider=yes, )

APACHE_VERSION=2.0.44
CHECK_PATH_APACHE($APACHE_VERSION,
   		:,
   		AC_MSG_ERROR([*** Apache version $APACHE_VERSION not found!])
  		)

AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])

dnl configure providers

if test "$enable_dbm_provider" = yes; then
	AC_CONFIG_SUBDIRS(providers/dbm)
fi

if test "$enable_default_provider" = yes; then
	AC_CONFIG_SUBDIRS(providers/default)
fi

if test "$enable_fail_provider" = yes; then
	AC_CONFIG_SUBDIRS(providers/fail)
fi

if test "$enable_dbi_provider" = yes; then
	AC_CONFIG_SUBDIRS(providers/dbi)
fi

dnl Write config.status and the Makefile

AC_OUTPUT(Makefile)
