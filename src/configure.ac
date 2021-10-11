AC_INIT([packetbl], [0.10])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

AC_PROG_CC
AC_PROG_INSTALL

AC_CANONICAL_BUILD
case "${build_os}" in
	linux-*)
		;;
	*)
		AC_MSG_ERROR(This program can only be compiled under Linux)
		;;
esac

AC_CHECK_HEADERS(ctype.h errno.h getopt.h netdb.h netinet/in.h netinet/tcp.h regex.h stdarg.h stdint.h stdio.h stdlib.h string.h string.h syslog.h sys/stat.h sys/types.h time.h unistd.h unistd.h)

ACX_PTHREAD
PKG_CHECK_MODULES([NFQUEUE], [libnetfilter_queue])
PKG_CHECK_MODULES([DOTCONF], [dotconf])
PKG_CHECK_MODULES([LDNS], [libldns])

AC_ARG_WITH(cache,
	AC_HELP_STRING([--with-cache], [If enabled, a caching mechanism is used.]),
	[ac_cv_use_cache=yes], [ac_cv_use_cache=no])

AC_MSG_CHECKING(whether caching is enabled)
if test "$ac_cv_use_cache" == "yes" ; then
	AC_MSG_RESULT(yes)
	AC_DEFINE([USE_CACHE], 1, [Enable if you want to use a caching mechanism.])
else
	AC_MSG_RESULT(no)
fi

AC_OUTPUT
