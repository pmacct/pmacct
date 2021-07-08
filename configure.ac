dnl Process this file with autoconf to produce a configure script.
dnl configuration file for pmacct 

m4_include([VERSION]) #Force reconf on VERSION change
AC_INIT([pmacct], m4_esyscmd_s(cat VERSION), [paolo@pmacct.net])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_MACRO_DIR([m4])
LT_INIT
AC_PREFIX_DEFAULT([/usr/local])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)])

PMACCT_VERSION=`cat $srcdir/VERSION`
AC_SUBST(PMACCT_VERSION)

COMPILE_ARGS="${ac_configure_args}"

dnl Checks for programs.
AC_PROG_CC

dnl pkg-config stuff
PKG_CONFIG_PATH=${PKG_CONFIG_PATH}:/usr/local/lib/pkgconfig
export PKG_CONFIG_PATH
PKG_PROG_PKG_CONFIG

AC_CANONICAL_HOST

AC_MSG_CHECKING(OS)
AC_MSG_RESULT($host_os)

AC_MSG_CHECKING(hardware)
AC_MSG_RESULT($host_cpu)

dnl initial checks; tweakings to CFLAGS and LDFLAGS
dnl see final checks for tweakings to LIBS
if test "x$ac_cv_prog_gcc" = xyes ; then
  CFLAGS="-O2 ${CFLAGS}"
fi

AC_CHECK_FUNCS([strlcpy])

dnl: shared object handling
AC_MSG_CHECKING([whether to disable linking against shared objects])
AC_ARG_ENABLE(so,
        [  --disable-so                     Disable linking against shared objects (default: no)],
	[ 
        if test x$enableval = x"yes" ; then
          AC_MSG_RESULT(no)
          AC_CHECK_FUNC(dlopen, [ USING_DLOPEN="yes" ], [])
          AC_CHECK_LIB(dl, dlopen,
                [ USING_DLOPEN="yes"
                  LIBS="${LIBS} -ldl" ],
                  [])
          if test x"$USING_DLOPEN" != x"yes"; then
                AC_MSG_ERROR(Unable to find dlopen(). Try with --disable-so)
          fi
        else
          AC_MSG_RESULT(yes)
	  if test "x$ac_cv_prog_gcc" = xyes ; then
		LDFLAGS="-static ${LDFLAGS}"
	  fi
        fi
        ],
	[
        AC_MSG_RESULT(no)
        AC_CHECK_FUNC(dlopen, [ USING_DLOPEN="yes" ], [])
        AC_CHECK_LIB(dl, dlopen,
                [ USING_DLOPEN="yes"
                  LIBS="${LIBS} -ldl" ],
                  [])
        if test x"$USING_DLOPEN" != x"yes"; then
                AC_MSG_ERROR(Unable to find dlopen(). Try with --disable-so)
        fi
	]
)
dnl finish: shared object handling

dnl os specific flags
case "$host_os" in
  Sun*)
    AC_DEFINE(SOLARIS, 1)
    LIBS="-lresolv -lsocket -lnsl ${LIBS}"
    ;;
  *BSD)
    AC_DEFINE(BSD, 1)
    ;;
  linux*)
    AC_DEFINE(LINUX, 1)
    ;;
esac

AC_CHECK_PROG(MAKE, gmake, gmake)
if test x"$MAKE" = x""; then
  AC_CHECK_PROG(MAKE, make, make)
fi
AC_SUBST(MAKE)
AC_PROG_MAKE_SET

dnl
dnl some systems have __progname ; if this is the case and we play around argv
dnl we need to enable a minor hack to make things work nicely.
dnl
AC_MSG_CHECKING(for __progname)
AC_TRY_LINK([ extern char *__progname; ], 
[ __progname = "test"; ],
[AC_MSG_RESULT(yes); AC_DEFINE(PROGNAME, 1)], [AC_MSG_RESULT(no)])

dnl
dnl Check for architecture endianess: big | little 
dnl
dnl XXX: switch to manually define this feature 
ac_cv_endianess="unknown"
if test x"$ac_cv_endianess" = x"unknown"; then
  AC_MSG_CHECKING(endianess)
  AC_TRY_RUN([
  #include <stdlib.h>

  int main () {
    union {
      long l;
      char c[sizeof (long)];
    } u;

    u.l = 1;

    exit (u.c[sizeof (long) - 1] == 1);
  }
  ], ac_cv_endianess="little", ac_cv_endianess="big", ac_cv_endianess="little")
  AC_MSG_RESULT($ac_cv_endianess)
fi

if test x"$ac_cv_endianess" = x"big"; then
  AC_DEFINE(IM_BIG_ENDIAN, 1)
fi
if test x"$ac_cv_endianess" = x"little"; then
  AC_DEFINE(IM_LITTLE_ENDIAN, 1)
fi

dnl
dnl Check for unaligned memory access; based entirely over
dnl AC_LBL_UNALIGNED_ACCESS
dnl
dnl XXX: switch to manually define this feature;
ac_cv_unaligned="unknown"
case "$host_cpu" in
  alpha*|arm*|hp*|mips*|sh*|sparc*|ia64|nv1)
    ac_cv_unaligned="fail"
    AC_MSG_CHECKING(unaligned accesses)
    AC_MSG_RESULT($ac_cv_unaligned)
    ;;
esac

if test x"$ac_cv_unaligned" = x"unknown"; then
  AC_MSG_CHECKING(unaligned accesses)
  cat > conftest.c << EOF
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>

    unsigned char a[[5]] = { 1, 2, 3, 4, 5 };
    int main () {
    	unsigned int i;
        pid_t pid;
        int status;
        /* avoid "core dumped" message */
        pid = fork();
        if (pid <  0) exit(2);
        if (pid > 0) {
        	/* parent */
                pid = waitpid(pid, &status, 0);
                if (pid < 0) exit(3);
                exit(!WIFEXITED(status));
        }
        /* child */
        i = *(unsigned int *)&a[[1]];
        printf("%d\n", i);
        exit(0);
    }
EOF
  ${CC-cc} -o conftest $CFLAGS $CPPFLAGS $LDFLAGS \
	conftest.c $LIBS >/dev/null 2>&1
  if test ! -x conftest ; then
    ac_cv_unaligned="fail"
  else
    ./conftest >conftest.out
    if test ! -s conftest.out ; then ac_cv_unaligned="fail"
    else ac_cv_unaligned="ok"
    fi
  fi
  rm -f conftest* core core.conftest
  AC_MSG_RESULT($ac_cv_unaligned)
fi

if test x"$ac_cv_unaligned" = x"fail"; then
  AC_DEFINE(NEED_ALIGN, 1)
fi

AC_MSG_CHECKING([whether to enable L2 features])
AC_ARG_ENABLE(l2,
        [  --enable-l2                      Enable Layer-2 features and support (default: yes)],
	[
        	if test x$enableval = x"yes" ; then
        		AC_MSG_RESULT(yes)
	  		AC_DEFINE(HAVE_L2, 1) 
        	else
			AC_MSG_RESULT(no)
        	fi
	],
	[
        	AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_L2, 1) 
		COMPILE_ARGS="${COMPILE_ARGS} '--enable-l2'"
	]
)

AC_CHECK_FUNCS(inet_pton)
if test x"$ac_cv_func_inet_pton" = x"no"; then
	AC_MSG_ERROR(ERROR: missing inet_pton())
fi

AC_CHECK_FUNCS(inet_ntop)
if test x"$ac_cv_func_inet_ntop" = x"no"; then
	AC_MSG_ERROR(ERROR: missing inet_ntop())
fi

AC_ARG_WITH(pcap-includes,
  [  --with-pcap-includes=DIR         Search the specified directory for header files],
  [
	AC_LINEARIZE_PATH($withval, withval=$absdir)
	INCLUDES="${INCLUDES} -I$withval"
	PCAPINCLS=$withval
	PCAPINCLUDESFOUND=1
  ])

if test x"$PCAPINCLS" != x""; then
  AC_MSG_CHECKING(your own pcap includes)
  if test -r $PCAPINCLS/pcap.h; then 
    AC_MSG_RESULT(ok)
    AC_DEFINE(HAVE_PCAP_H, 1)
    PCAPINCLUDESFOUND=1
  else
    AC_MSG_RESULT(no)
    AC_MSG_ERROR(ERROR: missing pcap.h in $PCAPINCLS) 
  fi
fi

AC_CHECK_PROG([PCAP_CONFIG], [pcap-config], [pcap-config], [no])

if test x"$PCAPINCLUDESFOUND" = x""; then
  if test ${PCAP_CONFIG} = "pcap-config"; then
    AC_MSG_CHECKING([using pcap-config for pcap.h])
    PCAP_CONFIG_INCLUDES=`${PCAP_CONFIG} --cflags`
    INCLUDES="${INCLUDES} ${PCAP_CONFIG_INCLUDES}"
    AC_DEFINE(HAVE_PCAP_PCAP_H, 1)
    AC_MSG_RESULT([${PCAP_CONFIG_INCLUDES}])
    PCAPINCLUDESFOUND=1
  fi
fi

if test x"$PCAPINCLUDESFOUND" = x""; then
  AC_MSG_CHECKING([default locations for pcap.h])
  if test -r /usr/include/pcap.h; then
    AC_MSG_RESULT([found in /usr/include])
    PCAPINCLUDESFOUND=1
    AC_DEFINE(HAVE_PCAP_H, 1)
  elif test -r /usr/include/pcap/pcap.h; then
    AC_MSG_RESULT([found in /usr/include])
    PCAPINCLUDESFOUND=1
    AC_DEFINE(HAVE_PCAP_PCAP_H, 1)
  elif test -r /usr/local/include/pcap.h; then
    AC_MSG_RESULT([found in /usr/local/include])
    INCLUDES="${INCLUDES} -I/usr/local/include"
    PCAPINCLUDESFOUND=1
    AC_DEFINE(HAVE_PCAP_H, 1) 
  elif test -r /usr/local/include/pcap/pcap.h; then
    AC_MSG_RESULT([found in /usr/local/include])
    INCLUDES="${INCLUDES} -I/usr/local/include"
    PCAPINCLUDESFOUND=1
    AC_DEFINE(HAVE_PCAP_PCAP_H, 1)
  fi
  if test x"$PCAPINCLUDESFOUND" = x""; then
    AC_MSG_RESULT([not found])
    AC_MSG_ERROR(ERROR: missing pcap.h)
  fi
fi

AC_ARG_WITH(pcap-libs,
  [  --with-pcap-libs=DIR             Search the specified directory for pcap library],
  [	
	AC_LINEARIZE_PATH($withval, withval=$absdir)
	LIBS="${LIBS} -L$withval"
	PCAPLIB=$withval
	PCAPLIBFOUND=1
  ])

if test x"$PCAPLIB" != x""; then
  AC_MSG_CHECKING(your own pcap libraries)
  if test -r $PCAPLIB/libpcap.a -o -r $PCAPLIB/libpcap.so; then
    AC_MSG_RESULT(ok)
    PCAP_LIB_FOUND=1
    AC_MSG_CHECKING(for PF_RING library)
    if test -r $PCAPLIB/libpfring.a -o -r $PCAPLIB/libpfring.so; then
      LIBS="${LIBS} -lpfring -lpcap"
      AC_MSG_RESULT(yes)
      PFRING_LIB_FOUND=1
      AC_DEFINE(PFRING_LIB_FOUND, 1)
    else
      AC_MSG_RESULT(no)
    fi
  else
    AC_MSG_RESULT(no)
    AC_MSG_ERROR(ERROR: unable to find pcap library in $PCAPLIB)
  fi
fi

if test x"$PCAPLIBFOUND" = x""; then
  AC_MSG_CHECKING([default locations for libpcap])
  if test -r /usr/local/lib/libpcap.a -o -r /usr/local/lib/libpcap.so; then
    LIBS="${LIBS} -L/usr/local/lib"
    AC_MSG_RESULT([found in /usr/local/lib])
    PCAPLIBFOUND=1
    AC_MSG_CHECKING(for PF_RING library)
    if test -r /usr/local/lib/libpfring.a -o -r /usr/local/lib/libpfring.so; then
      LIBS="${LIBS} -lpfring -lpcap"
      AC_MSG_RESULT(yes)
      PFRING_LIB_FOUND=1
      AC_DEFINE(PFRING_LIB_FOUND, 1)
    else
      AC_MSG_RESULT(no)
    fi
  else
    AC_MSG_RESULT(no)
  fi
fi

if test x"$PCAPLIBFOUND" = x""; then
  if test ${PCAP_CONFIG} = "pcap-config"; then
    AC_MSG_CHECKING([using pcap-config for libpcap])
    PCAP_CONFIG_LIBS=`${PCAP_CONFIG} --libs`
    INCLUDES="${INCLUDES} ${PCAP_CONFIG_LIBS}"
    AC_MSG_RESULT([${PCAP_CONFIG_LIBS}])
    PCAPLIBFOUND=1
  fi
fi

dnl Checks for libraries.

dnl libpcap is checked only if PF_RING is not found
if test x"$PFRING_LIB_FOUND" = x""; then
  AC_CHECK_LIB([pcap], [pcap_dispatch], [], [AC_MSG_ERROR([
    ERROR: missing pcap library. Refer to: http://www.tcpdump.org/
  ])])

  AC_CHECK_LIB([pcap], [pcap_set_protocol], [ AC_DEFINE(PCAP_SET_PROTOCOL, 1) ], [])
else
  AC_CHECK_LIB([numa], [numa_bind], [], [AC_MSG_ERROR([
    ERROR: missing libnuma. Requirement for building PF_RING.
  ])])

  #AC_CHECK_LIB([rt], [clock_gettime], [], [AC_MSG_ERROR([
  #  ERROR: missing librt devel. Requirement for building PF_RING.
  #])])

  LIBS="${LIBS} -lrt -lnuma"
fi

AC_CHECK_LIB([pcap], [pcap_setdirection], [ AC_DEFINE(PCAP_SET_DIRECTION, 1) ], [])

dnl start: mysql handling
AC_MSG_CHECKING(whether to enable MySQL support)
AC_ARG_ENABLE(mysql,
  [  --enable-mysql                   Enable MySQL support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)

    dnl no pkg-config support for MySQL
    AC_CHECK_PROG([MYSQL_CONFIG], [mysql_config], [mysql_config], [no])
    if test "x${MYSQL_CONFIG}" = "xno"; then
      AC_MSG_ERROR([ERROR: missing mysql_config program])
    fi

    MYSQL_CFLAGS=`$MYSQL_CONFIG --cflags`
    MYSQL_LIBS=`$MYSQL_CONFIG --libs`

    dnl version check not enforced with a AC_MSG_ERROR for now
    AX_LIB_MYSQL(5.6.3)

    AC_SUBST(MYSQL_CFLAGS)
    AC_SUBST(MYSQL_LIBS)

    PLUGINS="${PLUGINS} mysql"
    USING_SQL="yes"
    USING_MYSQL="yes"
    PMACCT_CFLAGS="$PMACCT_CFLAGS $MYSQL_CFLAGS"
    AC_DEFINE(WITH_MYSQL, 1)
    _save_LIBS="$LIBS"
    LIBS="$LIBS $MYSQL_LIBS"
    AC_CHECK_LIB([mysqlclient], [mysql_query])
    LIBS="$_save_LIBS"
    _save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $MYSQL_CFLAGS"
    AC_CHECK_HEADERS([mysql.h mysql/mysql.h])
    CFLAGS="$_save_CFLAGS"

    AC_CHECK_LIB([numa], [numa_bind], [], [AC_MSG_ERROR([
      ERROR: missing libnuma. Requirement for building MySQL.
    ])])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: mysql handling

dnl start: pgsql handling
AC_MSG_CHECKING(whether to enable PostgreSQL support)
AC_ARG_ENABLE(pgsql,
  [  --enable-pgsql                   Enable PostgreSQL support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([PGSQL], [libpq >= 8.4], [
      PLUGINS="${PLUGINS} pgsql"
      USING_SQL="yes"
      USING_PGSQL="yes"
      PMACCT_CFLAGS="$PMACCT_CFLAGS $PGSQL_CFLAGS"
      AC_DEFINE(WITH_PGSQL, 1)
      _save_LIBS="$LIBS"
      LIBS="$LIBS $PGSQL_LIBS"
      AC_CHECK_LIB([pq], [PQexec])
      AC_CHECK_FUNCS([PQlibVersion])
      LIBS="$_save_LIBS"
      _save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $PGSQL_CFLAGS"
      AC_CHECK_HEADER([libpq-fe.h])
      CFLAGS="$_save_CFLAGS"
    ], [
      AC_MSG_ERROR([Missing PQ library. Refer to: http://www.postgresql.org/download/])
    ])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: pgsql handling

dnl start: mongodb handling
AC_MSG_CHECKING(whether to enable MongoDB support)
AC_ARG_ENABLE(mongodb,
  [  --enable-mongodb                 Enable MongoDB support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([MONGODB], [libmongoc],, [
	AC_MSG_CHECKING([default locations for libmongoc])
	if test -r /usr/lib/libmongoc.a -o -r /usr/lib/libmongoc.so; then
		MONGODB_LIBS="-L/usr/lib -lmongoc"
		AC_MSG_RESULT([found in /usr/lib])
	elif test -r /usr/lib64/libmongoc.a -o -r /usr/lib64/libmongoc.so; then
		MONGODB_LIBS="-L/usr/lib64 -lmongoc"
		AC_MSG_RESULT([found in /usr/lib64])
	elif test -r /usr/local/lib/libmongoc.a -o -r /usr/local/lib/libmongoc.so; then
		MONGODB_LIBS="-L/usr/local/lib -lmongoc"
		AC_MSG_RESULT([found in /usr/local/lib])
	else
		AC_MSG_RESULT([not found])
                _save_LIBS="$LIBS"
                LIBS="$LIBS $MONGODB_LIBS"
		AC_CHECK_LIB([mongoc], [mongo_connect], [], [AC_MSG_ERROR([
			ERROR: missing MongoDB library (0.8 version). Refer to: https://github.com/mongodb/mongo-c-driver-legacy
		])])
                LIBS="$_save_LIBS"
	fi

	AC_MSG_CHECKING([default locations for mongo.h])
	if test -r /usr/include/mongo.h; then
		MONGODB_CFLAGS="-I/usr/include"
		AC_MSG_RESULT([found in /usr/include])
	elif test -r /usr/local/include/mongo.h; then
		MONGODB_CFLAGS="-I/usr/local/include"
		AC_MSG_RESULT([found in /usr/local/include])
	else
		AC_MSG_RESULT([not found])
                _save_CFLAGS="$CFLAGS"
                CFLAGS="$CFLAGS $MONGODB_CFLAGS"
		AC_CHECK_HEADER([mongo.h], [], [AC_MSG_ERROR(ERROR: missing MongoDB headers)])
                CFLAGS="$_save_CFLAGS"
	fi
    ])
    PLUGINS="${PLUGINS} mongodb"
    USING_MONGODB="yes"
    PMACCT_CFLAGS="$PMACCT_CFLAGS $MONGODB_CFLAGS"
    AC_DEFINE(WITH_MONGODB, 1)
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: mongodb handling

dnl start: sqlite3 handling
AC_MSG_CHECKING(whether to enable SQLite3 support)
AC_ARG_ENABLE(sqlite3,
  [  --enable-sqlite3                 Enable SQLite3 support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    dnl reasonably old libsqlite3 already support pkg-config
    PKG_CHECK_MODULES([SQLITE3], [sqlite3 >= 3.7.13], [
      PLUGINS="${PLUGINS} sqlite3"
      USING_SQL="yes"
      USING_SQLITE3="yes"
      PMACCT_CFLAGS="$PMACCT_CFLAGS $SQLITE3_CFLAGS"
      AC_DEFINE(WITH_SQLITE3, 1)
      _save_LIBS="$LIBS"
      LIBS="$LIBS $SQLITE3_LIBS"
      AC_CHECK_LIB([sqlite3], [sqlite3_exec])
      LIBS="$_save_LIBS"
      _save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $SQLITE3_CFLAGS"
      AC_CHECK_HEADER([sqlite3.h])
      CFLAGS="$_save_CFLAGS"
    ])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: sqlite3 handling

dnl start: RabbitMQ/AMQP handling
AC_MSG_CHECKING(whether to enable RabbitMQ/AMQP support)
AC_ARG_ENABLE(rabbitmq,
  [  --enable-rabbitmq                Enable RabbitMQ/AMQP support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    dnl reasonably old librabbitmq already support pkg-config
    PKG_CHECK_MODULES([RABBITMQ], [librabbitmq >= 0.8.0], [
      PLUGINS="${PLUGINS} rabbitmq"
      USING_RABBITMQ="yes"
      PMACCT_CFLAGS="$PMACCT_CFLAGS $RABBITMQ_CFLAGS"
      AC_DEFINE(WITH_RABBITMQ, 1)
      _save_LIBS="$LIBS"
      LIBS="$LIBS $RABBITMQ_LIBS"
      AC_CHECK_LIB([rabbitmq], [amqp_basic_publish])
      LIBS="$_save_LIBS"
      _save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $RABBITMQ_CFLAGS"
      AC_CHECK_HEADER([amqp.h])
      CFLAGS="$_save_CFLAGS"
    ], [
      AC_MSG_ERROR([Missing RabbitMQ C API. Refer to: https://github.com/alanxz/rabbitmq-c/])
    ])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: RabbitMQ/AMQP handling

dnl start: ZeroMQ handling
AC_MSG_CHECKING(whether to enable ZeroMQ support)
AC_ARG_ENABLE(zmq,
  [  --enable-zmq                     Enable ZeroMQ support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([ZMQ], [libzmq >= 4.2.0], [
      SUPPORTS="${SUPPORTS} zmq"
      USING_ZMQ="yes"
      PMACCT_CFLAGS="$PMACCT_CFLAGS $ZMQ_CFLAGS"
      AC_DEFINE(WITH_ZMQ, 1)
      _save_LIBS="$LIBS"
      LIBS="$LIBS $ZMQ_LIBS"
      AC_CHECK_LIB([zmq], [zmq_send])
      LIBS="$_save_LIBS"
      _save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $ZMQ_CFLAGS"
      AC_CHECK_HEADER([zmq.h])
      CFLAGS="$_save_CFLAGS"
    ], [
      AC_MSG_ERROR([Missing ZeroMQ. Refer to: http://zeromq.org/intro:get-the-software])
    ])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: ZeroMQ handling

dnl start: Kafka handling
AC_MSG_CHECKING(whether to enable Kafka support)
AC_ARG_ENABLE(kafka,
  [  --enable-kafka                   Enable Kafka support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([KAFKA], [rdkafka >= 0.9.2], [
      PLUGINS="${PLUGINS} kafka"
      USING_KAFKA="yes"
      PMACCT_CFLAGS="$PMACCT_CFLAGS $KAFKA_CFLAGS"
      AC_DEFINE(WITH_KAFKA, 1)
      _save_LIBS="$LIBS"
      LIBS="$LIBS $KAFKA_LIBS"
      AC_CHECK_LIB([rdkafka], [rd_kafka_produce])
      LIBS="$_save_LIBS"
      _save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $KAFKA_CFLAGS"
      AC_CHECK_HEADER([librdkafka/rdkafka.h])
      CFLAGS="$_save_CFLAGS"
    ], [
      AC_MSG_ERROR([Missing librdkafka. Refer to: https://github.com/edenhill/librdkafka/])
    ])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: Kafka handling

dnl start: Redis handling
AC_MSG_CHECKING(whether to enable Redis support)
AC_ARG_ENABLE(redis,
  [  --enable-redis                   Enable Redis support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([REDIS], [hiredis >= 0.13.0], [
      SUPPORTS="${SUPPORTS} redis"
      USING_REDIS="yes"
      PMACCT_CFLAGS="$PMACCT_CFLAGS $REDIS_CFLAGS"
      AC_DEFINE(WITH_REDIS, 1)
      _save_LIBS="$LIBS"
      LIBS="$LIBS $REDIS_LIBS"
      AC_CHECK_LIB([hiredis], [redisConnect])
      LIBS="$_save_LIBS"
      _save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $REDIS_CFLAGS"
      AC_CHECK_HEADER([hiredis/hiredis.h])
      CFLAGS="$_save_CFLAGS"
    ])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: Redis handling

dnl start: GnuTLS handling
AC_MSG_CHECKING(whether to enable GnuTLS support)
AC_ARG_ENABLE(gnutls,
  [  --enable-gnutls                  Enable GnuTLS support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([GNUTLS], [gnutls >= 3.6], [
      SUPPORTS="${SUPPORTS} gnutls"
      USING_GNUTLS="yes"
      PMACCT_CFLAGS="$PMACCT_CFLAGS $GNUTLS_CFLAGS"
      AC_DEFINE(WITH_GNUTLS, 1)
      _save_LIBS="$LIBS"
      LIBS="$LIBS $GNUTLS_LIBS"
      AC_CHECK_LIB([gnutls], [gnutls_global_init])
      LIBS="$_save_LIBS"
      _save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $GNUTLS_CFLAGS"
      AC_CHECK_HEADER([gnutls/gnutls.h])
      CFLAGS="$_save_CFLAGS"
    ])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: GnuTLS handling

dnl start: geoip handling
AC_MSG_CHECKING(whether to enable GeoIP support)
AC_ARG_ENABLE(geoip,
  [  --enable-geoip                   Enable GeoIP support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    dnl reasonably old Maxmind GeoIP v1 already support pkg-config
    PKG_CHECK_MODULES([GEOIP], [geoip >= 1.0.0], [
      SUPPORTS="${SUPPORTS} geoip"
      USING_MMGEOIP="yes"
      PMACCT_CFLAGS="$PMACCT_CFLAGS $GEOIP_CFLAGS"
      AC_DEFINE(WITH_GEOIP, 1)
    ])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)

AC_MSG_CHECKING(whether to enable GeoIPv2 (libmaxminddb) support)
AC_ARG_ENABLE(geoipv2,
  [  --enable-geoipv2                 Enable GeoIPv2 (libmaxminddb) support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([GEOIPV2], [libmaxminddb >= 1.2], [
      SUPPORTS="${SUPPORTS} geoipv2"
      USING_MMGEOIPV2="yes"
      PMACCT_CFLAGS="$PMACCT_CFLAGS $GEOIPV2_CFLAGS"
      AC_DEFINE(WITH_GEOIPV2, 1)
      _save_LIBS="$LIBS"
      LIBS="$LIBS $GEOIPV2_LIBS"
      AC_CHECK_LIB([maxminddb], [MMDB_open])
      LIBS="$_save_LIBS"
      _save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $GEOIPV2_CFLAGS"
      AC_CHECK_HEADER([maxminddb.h])
      CFLAGS="$_save_CFLAGS"
    ], [
      AC_MSG_ERROR([Missing Maxmind libmaxminddb C library. Refer to: http://www.maxmind.com/download/geoip/api/c/])
    ])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: GeoIP handling

dnl start: Jansson handling
AC_MSG_CHECKING(whether to enable Jansson support)
AC_ARG_ENABLE(jansson,
  [  --enable-jansson                 Enable Jansson support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    dnl reasonably old Jansson already support pkg-config
    PKG_CHECK_MODULES([JANSSON], [jansson >= 2.5], [
      SUPPORTS="${SUPPORTS} jansson"
      USING_JANSSON="yes"
      PMACCT_CFLAGS="$PMACCT_CFLAGS $JANSSON_CFLAGS"
      AC_DEFINE(WITH_JANSSON, 1)
      _save_LIBS="$LIBS"
      LIBS="$LIBS $JANSSON_LIBS"
      AC_CHECK_LIB([jansson], [json_object])
      LIBS="$_save_LIBS"
      _save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $JANSSON_CFLAGS"
      AC_CHECK_HEADER([jansson.h])
      CFLAGS="$_save_CFLAGS"
    ], [
      AC_MSG_ERROR([Missing libjansson. Refer to: http://www.digip.org/jansson/])
    ])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: Jansson handling

dnl start: Avro handling
AC_MSG_CHECKING(whether to enable Avro support)
AC_ARG_ENABLE(avro,
  [  --enable-avro                    Enable Apache Avro support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([AVRO], [avro-c >= 1.8], [
      SUPPORTS="${SUPPORTS} avro"
      USING_AVRO="yes"
      PMACCT_CFLAGS="$PMACCT_CFLAGS $AVRO_CFLAGS"
      AC_DEFINE(WITH_AVRO, 1)
      _save_LIBS="$LIBS"
      LIBS="$LIBS $AVRO_LIBS"
      AC_CHECK_LIB([avro], [avro_record_get])
      LIBS="$_save_LIBS"
      _save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $AVRO_CFLAGS"
      AC_CHECK_HEADER([avro.h])
      CFLAGS="$_save_CFLAGS"
    ], [
      AC_MSG_ERROR([Missing Apache Avro C library. Refer to: http://www.apache.org/dyn/closer.cgi/avro/])
    ])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: Avro handling

dnl start: libserdes handling
AC_MSG_CHECKING(whether to enable Confluent schema-registry support)
AC_ARG_ENABLE(serdes,
  [  --enable-serdes                  Enable Confluent schema-registry support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)

    AC_SUBST(SERDES_CFLAGS)
    AC_SUBST(SERDES_LIBS)

    SUPPORTS="${SUPPORTS} serdes"
    USING_SERDES="yes"
    PMACCT_CFLAGS="$PMACCT_CFLAGS $SERDES_CFLAGS"
    SERDES_LIBS="$SERDES_LIBS -lserdes"
    AC_DEFINE(WITH_SERDES, 1)
    _save_LIBS="$LIBS"
    LIBS="$LIBS $SERDES_LIBS"
    AC_CHECK_LIB([serdes], [serdes_new],, AC_MSG_ERROR([Missing Confluent serdes library. Refer to: https://github.com/confluentinc/libserdes]))
    LIBS="$_save_LIBS"
    _save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $SERDES_CFLAGS"
    AC_CHECK_HEADER([libserdes/serdes.h],, AC_MSG_ERROR([Missing Confluent serdes headers. Refer to: https://github.com/confluentinc/libserdes]))
    CFLAGS="$_save_CFLAGS"
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: libserdes handling

dnl start: nDPI handling
AC_ARG_WITH(ndpi-static-lib,
  [  --with-ndpi-static-lib=DIR       Search the specified directory for nDPI static library],
  [
        AC_LINEARIZE_PATH($withval, withval=$absdir)
        NDPI_CUST_STATIC_LIB=$withval
  ])

if test x"$NDPI_CUST_STATIC_LIB" != x""; then
  AC_MSG_CHECKING(your own nDPI library)
  if test -r $NDPI_CUST_STATIC_LIB/libndpi.a; then
    AC_MSG_RESULT(ok)
    NDPI_CUST_STATIC_LIB_FOUND="yes"
  else
    AC_MSG_RESULT(no)
    AC_MSG_ERROR(ERROR: unable to find nDPI library in $NDPI_CUST_STATIC_LIB)
  fi
fi

AC_MSG_CHECKING(whether to enable nDPI support)
AC_ARG_ENABLE(ndpi,
  [  --enable-ndpi                    Enable nDPI support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([NDPI], [libndpi >= 3.2], [
      SUPPORTS="${SUPPORTS} ndpi"
      USING_NDPI="yes"

      if test x"$NDPI_CFLAGS" != x""; then
        NDPI_CFLAGS_INST=`echo $NDPI_CFLAGS | sed 's/ $//'`
        NDPI_CFLAGS_INST="$NDPI_CFLAGS_INST/libndpi"
      else
        NDPI_CFLAGS_INST=""
      fi
      PMACCT_CFLAGS="$PMACCT_CFLAGS $NDPI_CFLAGS $NDPI_CFLAGS_INST"

      AC_DEFINE(WITH_NDPI, 1)
      _save_LIBS="$LIBS"
      LIBS="$LIBS $NDPI_LIBS"
      AC_CHECK_LIB([ndpi], [ndpi_init_detection_module])
      LIBS="$_save_LIBS"
      _save_CFLAGS="$CFLAGS"
      CFLAGS="$CFLAGS $NDPI_CFLAGS"
      AC_CHECK_HEADER([libndpi/ndpi_main.h])
      CFLAGS="$_save_CFLAGS"
    ],
    [AC_MSG_ERROR([Missing nDPI API. Refer to: https://github.com/ntop/nDPI/])])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: nDPI handling

dnl start: unyte udp notif handling
AC_MSG_CHECKING(whether to enable Unyte UDP-Notif support)
AC_ARG_ENABLE(unyte-udp-notif,
  [  --enable-unyte-udp-notif         Enable Unyte UDP Notif support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)

    AC_SUBST(UNYTE_UDP_NOTIF_CFLAGS)
    AC_SUBST(UNYTE_UDP_NOTIF_LIBS)

    SUPPORTS="${SUPPORTS} unyte-udp-notif"
    USING_UNYTE_UDP_NOTIF="yes"
    PMACCT_CFLAGS="$PMACCT_CFLAGS $UNYTE_UDP_NOTIF_CFLAGS"
    UNYTE_UDP_NOTIF_LIBS="$UNYTE_UDP_NOTIF_LIBS -lunyte-udp-notif"
    AC_DEFINE(WITH_UNYTE_UDP_NOTIF, 1)
    _save_LIBS="$LIBS"
    LIBS="$LIBS $UNYTE_UDP_NOTIF_LIBS -lpthread"
    AC_CHECK_LIB([unyte-udp-notif], [unyte_udp_start_collector], [], [AC_MSG_ERROR([
	ERROR: missing unyte-udp-notif library. Refer to: https://github.com/insa-unyte/udp-notif-c-collector
    ])])
    LIBS="$_save_LIBS"
    _save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $UNYTE_UDP_NOTIF_CFLAGS"
    AC_CHECK_HEADER([unyte-udp-notif/unyte_udp_collector.h], [], [AC_MSG_ERROR(ERROR: missing unyte-udp-notif headers)])
    CFLAGS="$_save_CFLAGS"
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
  [
    AC_MSG_RESULT(no)
  ]
)
dnl finish: unyte udp notif handling

if test x"$USING_DLOPEN" = x"yes"; then
	AC_DEFINE(HAVE_DLOPEN, 1)
else
	# Adding linking to libdl here 1) if required and 2) in case of --disable-so
	if test x"$USING_MYSQL" = x"yes" -o x"$USING_SQLITE3" = x"yes"; then
		AC_CHECK_LIB([dl], [dlopen], [LIBS="${LIBS} -ldl"], [AC_MSG_ERROR([
		  ERROR: missing libdl devel.
		])])
	fi
fi

if test x"$USING_SQL" = x"yes"; then
	AC_CHECK_LIB([z], [zlibVersion], [], [AC_MSG_ERROR([ERROR: missing zlib. Requirement for building SQL plugins.])])
fi

LIBS="${LIBS} -lm -lpthread"

dnl Checks for header files.
AC_HEADER_STDC

dnl Extra checks for header files
AC_CHECK_HEADERS([arpa/inet.h assert.h ctype.h dirent.h dlfcn.h errno.h fcntl.h getopt.h grp.h inttypes.h])
AC_CHECK_HEADERS([limits.h malloc.h math.h netdb.h net/if.h netinet/in.h netinet/in_systm.h netinet/ip.h])
AC_CHECK_HEADERS([netinet/udp.h pthread.h pwd.h signal.h string.h sys/ansi.h sys/errno.h sys/file.h])
AC_CHECK_HEADERS([sys/ioctl.h syslog.h sys/mbuf.h sys/mman.h sys/param.h sys/poll.h sys/resource.h])
AC_CHECK_HEADERS([sys/select.h sys/socket.h sys/stat.h sys/time.h sys/types.h sys/un.h sys/utsname.h])
AC_CHECK_HEADERS([sys/wait.h time.h unistd.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_TYPE(u_int64_t, [AC_DEFINE(HAVE_U_INT64_T, 1)])
AC_CHECK_TYPE(u_int32_t, [AC_DEFINE(HAVE_U_INT32_T, 1)])
AC_CHECK_TYPE(u_int16_t, [AC_DEFINE(HAVE_U_INT16_T, 1)])
AC_CHECK_TYPE(u_int8_t, [AC_DEFINE(HAVE_U_INT8_T, 1)])
AC_CHECK_TYPE(uint64_t, [AC_DEFINE(HAVE_UINT64_T, 1)])
AC_CHECK_TYPE(uint32_t, [AC_DEFINE(HAVE_UINT32_T, 1)])
AC_CHECK_TYPE(uint16_t, [AC_DEFINE(HAVE_UINT16_T, 1)])
AC_CHECK_TYPE(uint8_t, [AC_DEFINE(HAVE_UINT8_T, 1)])

AC_MSG_CHECKING(whether to enable NFLOG support)
AC_ARG_ENABLE(nflog,
  [  --enable-nflog                   Enable NFLOG support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([NFLOG], [libnetfilter_log >= 1], [
      SUPPORTS="${SUPPORTS} nflog"
      USING_NFLOG="yes"
      AC_DEFINE(WITH_NFLOG, 1)
    ])
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
AC_MSG_RESULT(no))

AC_MSG_CHECKING(whether to link IPv4/IPv6 traffic accounting accounting binaries)
AC_ARG_ENABLE(traffic-bins,
	[  --enable-traffic-bins            Link IPv4/IPv6 traffic accounting binaries (default: yes)],
	[
	  if test x$enableval = x"yes" ; then
	    AC_MSG_RESULT(yes)
	    AC_DEFINE(HAVE_TRAFFIC_BINS, 1)
	    USING_TRAFFIC_BINS="yes"
	  else
	    AC_MSG_RESULT(no)
	  fi
	],
	[
	  AC_MSG_RESULT(yes)
	  AC_DEFINE(HAVE_TRAFFIC_BINS, 1)
	  USING_TRAFFIC_BINS="yes"
	  COMPILE_ARGS="${COMPILE_ARGS} '--enable-traffic-bins'"
	]
)

AC_MSG_CHECKING(whether to link BGP daemon binaries)
AC_ARG_ENABLE(bgp-bins,
        [  --enable-bgp-bins                Link BGP daemon binaries (default: yes)],
        [
          if test x$enableval = x"yes" ; then
            AC_MSG_RESULT(yes)
            AC_DEFINE(HAVE_BGP_BINS, 1)
	    USING_BGP_BINS="yes"
          else
            AC_MSG_RESULT(no)
          fi
        ],
        [
          AC_MSG_RESULT(yes)
          AC_DEFINE(HAVE_BGP_BINS, 1)
	  USING_BGP_BINS="yes"
          COMPILE_ARGS="${COMPILE_ARGS} '--enable-bgp-bins'"
        ]
)

AC_MSG_CHECKING(whether to link BMP daemon binaries)
AC_ARG_ENABLE(bmp-bins,
        [  --enable-bmp-bins                Link BMP daemon binaries (default: yes)],
        [
          if test x$enableval = x"yes" ; then
            AC_MSG_RESULT(yes)
            AC_DEFINE(HAVE_BMP_BINS, 1)
	    USING_BMP_BINS="yes"
          else
            AC_MSG_RESULT(no)
          fi
        ],
        [
          AC_MSG_RESULT(yes)
          AC_DEFINE(HAVE_BMP_BINS, 1)
	  USING_BMP_BINS="yes"
          COMPILE_ARGS="${COMPILE_ARGS} '--enable-bmp-bins'"
        ]
)

AC_MSG_CHECKING(whether to link Streaming Telemetry daemon binaries)
AC_ARG_ENABLE(st-bins,
        [  --enable-st-bins                 Link Streaming Telemetry daemon binaries (default: yes)],
        [
          if test x$enableval = x"yes" ; then
            AC_MSG_RESULT(yes)
            AC_DEFINE(HAVE_ST_BINS, 1)
	    USING_ST_BINS="yes"
          else
            AC_MSG_RESULT(no)
          fi
        ],
        [
          AC_MSG_RESULT(yes)
          AC_DEFINE(HAVE_ST_BINS, 1)
	  USING_ST_BINS="yes"
          COMPILE_ARGS="${COMPILE_ARGS} '--enable-st-bins'"
        ]
)

dnl Checks for library functions.
AC_TYPE_SIGNAL

AC_CHECK_FUNCS([setproctitle mallopt tdestroy])

dnl Check for SO_REUSEPORT & friends
AC_CHECK_DECL([SO_REUSEPORT],
	AC_DEFINE(HAVE_SO_REUSEPORT, 1, [Check if kernel supports SO_REUSEPORT]),,
		[
		  #include <sys/types.h>
		  #include <sys/socket.h>
		]
)

AC_CHECK_DECL([SO_ATTACH_REUSEPORT_CBPF],
	AC_DEFINE(HAVE_SO_ATTACH_REUSEPORT_CBPF, 1, [Check if kernel supports SO_ATTACH_REUSEPORT_CBPF]),,
		[
		  #include <sys/types.h>
		  #include <sys/socket.h>
		]
)

AC_CHECK_DECL([SO_ATTACH_REUSEPORT_EBPF],
	AC_DEFINE(HAVE_SO_ATTACH_REUSEPORT_EBPF, 1, [Check if kernel supports SO_ATTACH_REUSEPORT_EBPF]),,
		[
		  #include <sys/types.h>
		  #include <sys/socket.h>
		]
)

dnl --------------------------------------
dnl Git submodule Dependencies buid system
dnl --------------------------------------

dnl First check whether to build git submodule deps
WITH_EXTERNAL_DEPS_DEFAULT=yes
if [ test ! -f "$srcdir/src/external_libs/libcdada/include/cdada.h" ] && [ test -z `git rev-parse HEAD 2> /dev/null` ]; then
	WITH_EXTERNAL_DEPS_DEFAULT=no
fi

AC_MSG_CHECKING([whether external dependencies (git submodules) should be compiled])
AC_ARG_WITH(external-deps,
		AS_HELP_STRING([--without-external-deps], [Do not build external dependencies (git submodules), specially useful for package maintainers [default=with]]),
			[WITH_EXTERNAL_DEPS="$withval"],
			[WITH_EXTERNAL_DEPS="$WITH_EXTERNAL_DEPS_DEFAULT"]
			)
if test x"$WITH_EXTERNAL_DEPS" = x"yes"; then
	dnl Compiled-in dependencies
	INCLUDES="-I${ac_pwd}/src/external_libs/rootfs/include ${INCLUDES} "
	LDFLAGS="-L${ac_pwd}/src/external_libs/rootfs/lib ${LDFLAGS}"
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

AM_CONDITIONAL([WITH_EXTERNAL_DEPS], [test "x$WITH_EXTERNAL_DEPS" = "xyes"])
AS_CASE(["$AM_DEFAULT_VERBOSITY"],
  [0], [AC_SUBST([configure_silent_rules_val], [--enable-silent-rules])],
  [1], [AC_SUBST([configure_silent_rules_val], [--disable-silent-rules])],
  [AC_SUBST([configure_silent_rules_val], [--enable-silent-rules])])

dnl --------------------------------------

dnl libcdada requires C++ (and needs to add libstdc++ to LDFLAGS
AC_PROG_CXX
AC_MSG_CHECKING([for a valid C++ compiler])
AC_LANG_PUSH([C++])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],[AC_MSG_RESULT(yes)],[AC_MSG_ERROR([No C++ compiler found])])
AC_LANG_POP([C++])

LIBS="-lcdada -lstdc++ ${LIBS}"
AS_CASE(["$WITH_EXTERNAL_DEPS"],
  [yes], [],
  [no], [AC_CHECK_LIB([cdada], [cdada_get_ver], [], [AC_MSG_ERROR([Could not find libcdada])])],
  [])

dnl set debug level
AC_MSG_CHECKING([whether to enable debugging compiler options])
AC_ARG_ENABLE(debug,
	[  --enable-debug                   Enable debugging compiler options (default: no)],
	[
		if test x$enableval = x"yes" ; then
			AC_MSG_RESULT(yes)
			tmp_CFLAGS=`echo $CFLAGS | sed 's/O2/O0/g'`
			CFLAGS="$tmp_CFLAGS"
			CFLAGS="$CFLAGS -g -Wall -Werror"
		else
			CFLAGS="$CFLAGS -Wall -Werror"
			AC_MSG_RESULT(no)
		fi
	],
	[
		AC_MSG_RESULT(no)
	]
)

dnl Necessary for autogenerated build string
INCLUDES="${INCLUDES} -I$(pwd)/src"

dnl final checks
dnl trivial solution to portability issue 
AC_DEFINE_UNQUOTED(COMPILE_ARGS, "$COMPILE_ARGS")
CFLAGS="${CFLAGS} ${INCLUDES}"
INCLUDES=""

echo "
PLATFORM ..... : `uname -m`
OS ........... : `uname -rs` (`uname -n`)
COMPILER ..... : ${CC}
CFLAGS ....... : ${CFLAGS}
LIBS ......... : ${LIBS}
LDFLAGS ...... : ${LDFLAGS}
PLUGINS ...... : ${PLUGINS}
SUPPORTS ..... : ${SUPPORTS}

Now type 'make' to compile the source code.

Wanting to get in touch with other pmacct users?
Join the pmacct mailing-list with an email to pmacct-discussion-subscribe@pmacct.net

Need for documentation and examples?
Start by reading the README.md file

Star, watch or contribute to the project on GitHub:
https://github.com/pmacct/pmacct

"

AC_SUBST([PMACCT_CFLAGS])

AM_CONDITIONAL([WITH_MYSQL], [test x"$USING_MYSQL" = x"yes"])
AM_CONDITIONAL([WITH_PGSQL], [test x"$USING_PGSQL" = x"yes"])
AM_CONDITIONAL([WITH_MONGODB], [test x"$USING_MONGODB" = x"yes"])
AM_CONDITIONAL([WITH_SQLITE3], [test x"$USING_SQLITE3" = x"yes"])
AM_CONDITIONAL([WITH_RABBITMQ], [test x"$USING_RABBITMQ" = x"yes"])
AM_CONDITIONAL([WITH_ZMQ], [test x"$USING_ZMQ" = x"yes"])
AM_CONDITIONAL([WITH_KAFKA], [test x"$USING_KAFKA" = x"yes"])
AM_CONDITIONAL([WITH_REDIS], [test x"$USING_REDIS" = x"yes"])
AM_CONDITIONAL([WITH_GNUTLS], [test x"$USING_GNUTLS" = x"yes"])
AM_CONDITIONAL([USING_SQL], [test x"$USING_SQL" = x"yes"])
AM_CONDITIONAL([WITH_JANSSON], [test x"$USING_JANSSON" = x"yes"])
AM_CONDITIONAL([WITH_AVRO], [test x"$USING_AVRO" = x"yes"])
AM_CONDITIONAL([WITH_SERDES], [test x"$USING_SERDES" = x"yes"])
AM_CONDITIONAL([WITH_NDPI], [test x"$USING_NDPI" = x"yes"])
AM_CONDITIONAL([WITH_UNYTE_UDP_NOTIF], [test x"$USING_UNYTE_UDP_NOTIF" = x"yes"])
AM_CONDITIONAL([WITH_NFLOG], [test x"$USING_NFLOG" = x"yes"])
AM_CONDITIONAL([WITH_DLOPEN], [test x"$USING_DLOPEN" = x"yes"])
AM_CONDITIONAL([USING_TRAFFIC_BINS], [test x"$USING_TRAFFIC_BINS" = x"yes"])
AM_CONDITIONAL([USING_BGP_BINS], [test x"$USING_BGP_BINS" = x"yes"])
AM_CONDITIONAL([USING_BMP_BINS], [test x"$USING_BMP_BINS" = x"yes"])
AM_CONDITIONAL([USING_ST_BINS], [test x"$USING_ST_BINS" = x"yes"])

AC_CONFIG_FILES([
	    src/pmacct-version.h
])

AC_OUTPUT([ Makefile \
	    src/Makefile src/external_libs/Makefile \
	    src/nfprobe_plugin/Makefile \
	    src/sfprobe_plugin/Makefile src/bgp/Makefile \
	    src/tee_plugin/Makefile src/isis/Makefile \
	    src/bmp/Makefile src/rpki/Makefile \
	    src/telemetry/Makefile src/ndpi/Makefile \
	    src/filters/Makefile examples/lg/Makefile \
	    examples/custom/Makefile	])
