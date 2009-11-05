#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(traff, 0.7)
AM_INIT_AUTOMAKE(@PACKAGE_NAME@, @PACKAGE_VERSION@)
AC_CONFIG_SRCDIR([config.h.in])
AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

AC_ARG_ENABLE([mysql],
            [AS_HELP_STRING([--with-mysql],
              [Support MYSQL database dumping @<:@default=check@:>@])],
            [],
            [with_mysql=no])
          
          LIBMYSQL=
          AS_IF([test "x$with_mysql" != xno],
            [AC_CHECK_LIB([mysqlclient], [mysql_real_connect],,
              [if test "x$with_mysql" != xcheck; then
                 AC_MSG_FAILURE(
                   [--with-mysql was given, but test for mysqlclient failed])
               fi
              ])])

AC_ARG_ENABLE([postgresql],
            [AS_HELP_STRING([--with-postgresql],
              [Support PostgreSQL database dumping])],
            [],
            [with_PostgreSQL=no])
          
          LIBPQ=
          AS_IF([test "x$with_PostgreSQL" != xno],
            [AC_CHECK_LIB([pq], [PQsetdbLogin],,
              [if test "x$with_postgresql" != xcheck; then
                 AC_MSG_FAILURE(
                   [--with-postgresql was given, but test for libpq failed])
               fi
              ])])

# Checks for libraries.
AC_CHECK_LIB([pcap], [main],,AC_MSG_FAILURE([pcap libaries not installed.]))
AC_CHECK_LIB([pthread], [main],,AC_MSG_FAILURE([pcap libaries not installed.]))

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h limits.h netinet/in.h stdlib.h string.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([bzero memset mkfifo strcasecmp strerror strpbrk strspn])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
