# ===========================================================================
#       https://www.gnu.org/software/autoconf-archive/ax_lib_mysql.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_LIB_MYSQL([MINIMUM-VERSION])
#
# DESCRIPTION
#
#   This macro provides tests of availability of MySQL client library of
#   particular version or newer.
#
#   AX_LIB_MYSQL macro takes only one argument which is optional. If there
#   is no required version passed, then macro does not run version test.
#
#   This is a short and adapted version of the original macro.
#
# LICENSE
#
#   Copyright (c) 2008 Mateusz Loskot <mateusz@loskot.net>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 13

AC_DEFUN([AX_LIB_MYSQL],
[
  if test "$MYSQL_CONFIG" != "no"; then
    MYSQL_VERSION=`$MYSQL_CONFIG --version`
    found_mysql="yes"
  else
    found_mysql="no"
  fi

  dnl
  dnl Check if required version of MySQL is available
  dnl

  mysql_version_req=ifelse([$1], [], [], [$1])

  if test "$found_mysql" = "yes" -a -n "$mysql_version_req"; then
    AC_MSG_CHECKING([if MySQL version is >= $mysql_version_req])

    dnl Decompose required version string of MySQL
    dnl and calculate its number representation
    mysql_version_req_major=`expr $mysql_version_req : '\([[0-9]]*\)'`
    mysql_version_req_minor=`expr $mysql_version_req : '[[0-9]]*\.\([[0-9]]*\)'`
    mysql_version_req_micro=`expr $mysql_version_req : '[[0-9]]*\.[[0-9]]*\.\([[0-9]]*\)'`
    if test "x$mysql_version_req_micro" = "x"; then
      mysql_version_req_micro="0"
    fi

    mysql_version_req_number=`expr $mysql_version_req_major \* 1000000 \
	\+ $mysql_version_req_minor \* 1000 \
	\+ $mysql_version_req_micro`

    dnl Decompose version string of installed MySQL
    dnl and calculate its number representation
    mysql_version_major=`expr $MYSQL_VERSION : '\([[0-9]]*\)'`
    mysql_version_minor=`expr $MYSQL_VERSION : '[[0-9]]*\.\([[0-9]]*\)'`
    mysql_version_micro=`expr $MYSQL_VERSION : '[[0-9]]*\.[[0-9]]*\.\([[0-9]]*\)'`
    if test "x$mysql_version_micro" = "x"; then
      mysql_version_micro="0"
    fi

    mysql_version_number=`expr $mysql_version_major \* 1000000 \
	\+ $mysql_version_minor \* 1000 \
	\+ $mysql_version_micro`

    mysql_version_check=`expr $mysql_version_number \>\= $mysql_version_req_number`

    if test "$mysql_version_check" = "1"; then
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  fi

  AC_SUBST([MYSQL_VERSION])
])
