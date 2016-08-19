dnl Process this file with autoconf to produce a configure script.
dnl configuration file for pmacct 

AC_INIT([pmacct], [1.6.1-git], [paolo@pmacct.net])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_MACRO_DIR([m4])
LT_INIT
AC_PREFIX_DEFAULT([/usr/local])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)])

COMPILE_ARGS="${ac_configure_args}"
AC_DEFINE_UNQUOTED(COMPILE_ARGS, "$COMPILE_ARGS")

dnl Checks for programs.
AC_PROG_CC

dnl pkg-config stuff
PKG_CONFIG_PATH=${PKG_CONFIG_PATH}:/usr/local/lib/pkgconfig
export PKG_CONFIG_PATH
PKG_PROG_PKG_CONFIG

host_os=`uname`
host_cpu=`uname -m`
host_os1=`uname -rs`

AC_MSG_CHECKING(OS)
AC_MSG_RESULT($host_os)

AC_MSG_CHECKING(hardware)
AC_MSG_RESULT($host_cpu)

dnl initial checks; tweakings to CFLAGS and LDFLAGS
dnl see final checks for tweakings to LIBS
if test "x$ac_cv_prog_gcc" = xyes ; then
  CFLAGS="-O2 ${CFLAGS}"
fi

dnl set debug level
AC_MSG_CHECKING([whether to enable debugging compiler options])
AC_ARG_ENABLE(debug,
	[  --enable-debug                   Enable debugging compiler options (default: no)],
	[
	        if test x$enableval = x"yes" ; then
			AC_MSG_RESULT(yes)
			tmp_CFLAGS=`echo $CFLAGS | sed 's/O2/O0/g'`
			CFLAGS="$tmp_CFLAGS"
  			CFLAGS="$CFLAGS -g -W -Wall"
		else
			AC_MSG_RESULT(no)
		fi
	],
	[
		AC_MSG_RESULT(no)
	]
)

dnl set relax level
AC_MSG_CHECKING([whether to relax compiler optimizations])
AC_ARG_ENABLE(relax,
[  --enable-relax                   Relax compiler optimization (default: no)],
	[
		if test x$enableval = x"yes" ; then
			AC_MSG_RESULT(yes)
        		tmp_CFLAGS=`echo $CFLAGS | sed 's/O2/O0/g'`
       			CFLAGS="$tmp_CFLAGS"
		else
			AC_MSG_RESULT(no)
		fi
	],
	[
        	AC_MSG_RESULT(no)
	]
)

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
esac

dnl cpu specific flags
case "$host_cpu" in
  sun*)
  AC_DEFINE(CPU_sparc, 1)
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
dnl Some checks to understand whether we need to instruct the linker for
dnl exporting collector symbols to dynamically loaded classifiers. 
dnl
dnl OS'es with ELF executables using the GNU linker (Linux and recent *BSD,
dnl in rare cases Solaris) typically need '-Wl,-export-dynamic'; some SYSv4
dnl systems instead need '-Wl,-Bexport'; AIX 4.x wants -Wl,-bexpall,-brtl'.
dnl
      
AC_MSG_CHECKING(for extra flags needed to export symbols)
if test "x$ac_cv_prog_gcc" = xyes ; then
	save_ldflags="${LDFLAGS}"
	LDFLAGS="-Wl,--export-dynamic ${save_ldflags}"
	AC_TRY_LINK(,,
		[ AC_MSG_RESULT(--export-dynamic) ],
		[ LDFLAGS="-Wl,-Bexport ${save_ldflags}"
		  AC_TRY_LINK(,,
			[ AC_MSG_RESULT(-Bexport) ],
		  	[ AC_MSG_RESULT(none)
		    	  LDFLAGS="${save_ldflags}" ]
		  )
		]
	)
else
	AC_MSG_RESULT(none)
fi

dnl
dnl some C compilers (ex. MipsPRO) don't know how to parse the 'inline' keyword
dnl
AC_MSG_CHECKING(for static inline)
AC_TRY_COMPILE([#include <stdio.h>]

static inline func()
{
}
,
[
  func();
],
[AC_MSG_RESULT(yes)], [AC_MSG_RESULT(no); AC_DEFINE(NOINLINE, 1)])

dnl
dnl Check for architecture endianess: big | little 
dnl
dnl XXX: switch to manually define this feature 
ac_cv_endianess="unknown"
if test x"$ac_cv_endianess" = x"unknown"; then
  AC_MSG_CHECKING(endianess)
  AC_TRY_RUN([main () {

  union
  {
    long l;
    char c[sizeof (long)];
  } u;
  u.l = 1;
  exit (u.c[sizeof (long) - 1] == 1);
  }], ac_cv_endianess="little", ac_cv_endianess="big", ac_cv_endianess="little")
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
    unsigned char a[[5]] = { 1, 2, 3, 4, 5 };
    main () {
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
	]
)

AC_MSG_CHECKING([whether to enable IPv6 code])
AC_ARG_ENABLE(ipv6,
        [  --enable-ipv6                    Enable IPv6 code (default: no)],
	[ 
		if test x$enableval = x"yes" ; then
        		AC_MSG_RESULT(yes)
        		AC_CHECK_FUNCS(inet_pton)
        		if test x"$ac_cv_func_inet_pton" = x"no"; then
        			AC_MSG_ERROR(ERROR: missing inet_pton(); disable IPv6 hooks !)
        		fi

			AC_CHECK_FUNCS(inet_ntop)
			if test x"$ac_cv_func_inet_ntop" = x"no"; then
          			AC_MSG_ERROR(ERROR: missing inet_ntop(); disable IPv6 hooks !)
        		fi

			AC_DEFINE(ENABLE_IPV6, 1)
			ipv6support="yes"
		else
			AC_MSG_RESULT(no)
			ipv6support="no"
		fi
	],
	[
        	AC_MSG_RESULT(no)
		ipv6support="no"
	]
)

AC_MSG_CHECKING([whether to enable IP prefix labels])
AC_ARG_ENABLE(plabel,
  [  --enable-plabel                  Enable IP prefix labels (default: no)],
  [
	if test x$enableval = x"yes" ; then
          AC_MSG_RESULT(yes)
          AC_DEFINE(ENABLE_PLABEL, 1)
	else
          AC_MSG_RESULT(no)
	fi
  ],
  [
	AC_MSG_RESULT(no)
  ])

AC_ARG_WITH(pcap-includes,
  [  --with-pcap-includes=DIR         Search the specified directories for header files],
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
  else
    AC_MSG_RESULT(no)
    AC_MSG_ERROR(ERROR: missing pcap.h in $PCAPINCLS) 
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
  [  --with-pcap-libs=DIR             Search the specified directories for libraries],
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
    else
      AC_MSG_RESULT(no)
    fi
  else
    AC_MSG_RESULT(no)
  fi
fi

dnl Checks for libraries.

dnl libpcap is checked only if PF_RING is not found
if test x"$PFRING_LIB_FOUND" = x""; then
  AC_CHECK_LIB([pcap], [pcap_dispatch], [], [AC_MSG_ERROR([
    ERROR: missing pcap library. Refer to: http://www.tcpdump.org/
  ])])

  AC_CHECK_LIB([pcap], [pcap_setnonblock], [ AC_DEFINE(PCAP_7, 1) ], [])
  AC_CHECK_LIB([pcap], [bpf_filter], [ AC_DEFINE(PCAP_NOBPF, 1) ], [])
else
  dnl Unable to test: we should check for these libs
  #AC_CHECK_LIB([numa], [numa_bind], [], [AC_MSG_ERROR([
  #  ERROR: missing libnuma devel. Requirement for building PF_RING.
  #])])

  #AC_CHECK_LIB([rt], [clock_gettime], [], [AC_MSG_ERROR([
  #  ERROR: missing librt devel. Requirement for building PF_RING.
  #])])

  LIBS="${LIBS} -lrt -lnuma"
fi

dnl packet capture type check; taken from libpcap.
AC_MSG_CHECKING(packet capture type)
if test -r /dev/bpf0 ; then
        V_PCAP=bpf
elif test -r /usr/include/net/pfilt.h ; then
        V_PCAP=pf
elif test -r /dev/enet ; then
        V_PCAP=enet
elif test -r /dev/nit ; then
        V_PCAP=snit
elif test -r /usr/include/sys/net/nit.h ; then
        V_PCAP=nit
elif test -r /usr/include/linux/socket.h ; then
        V_PCAP=linux
elif test -r /usr/include/net/raw.h ; then
        V_PCAP=snoop
elif test -r /usr/include/odmi.h ; then
        #
        # On AIX, the BPF devices might not yet be present - they're
        # created the first time libpcap runs after booting.
        # We check for odmi.h instead.
        #
        V_PCAP=bpf
elif test -r /usr/include/sys/dlpi.h ; then
        V_PCAP=dlpi
elif test -c /dev/bpf0 ; then           # check again in case not readable
        V_PCAP=bpf
elif test -c /dev/enet ; then           # check again in case not readable
        V_PCAP=enet
elif test -c /dev/nit ; then            # check again in case not readable
        V_PCAP=snit
else
        V_PCAP=null
fi
AC_MSG_RESULT($V_PCAP)
AC_DEFINE_UNQUOTED(PCAP_TYPE_$V_PCAP, 1)

dnl start: mysql handling
AC_MSG_CHECKING(whether to enable MySQL support)
AC_ARG_ENABLE(mysql,
  [  --enable-mysql                   Enable MySQL support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)

dnl Unfortunately, no pkg-config support for MySQL
    AC_CHECK_PROG([MYSQL_CONFIG], [mysql_config], [mysql_config], [no],,)
    if test "x${MYSQL_CONFIG}" = "xno"; then
      AC_MSG_ERROR([ERROR: missing mysql_config program])
    fi
    AC_CHECK_LIB([mysqlclient], [mysql_init],
                 [MYSQL_CFLAGS=`$MYSQL_CONFIG --cflags`
                  MYSQL_LIBS=`$MYSQL_CONFIG --libs`],
                 [AC_MSG_ERROR([ERROR: missing MySQL client library])],
                 [`$MYSQL_CONFIG --libs`])
    AC_SUBST(MYSQL_CFLAGS)
    AC_SUBST(MYSQL_LIBS)

    PLUGINS="${PLUGINS} mysql"
    USING_SQL="yes"
    USING_MYSQL="yes"
    AC_DEFINE(WITH_MYSQL, 1)
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
    PKG_CHECK_MODULES([PGSQL], [libpq],, [
	AC_MSG_CHECKING([default locations for libpq])
	if test -r /usr/lib/libpq.a -o -r /usr/lib/libpq.so; then
		PGSQL_LIBS="-L/usr/lib -lpq"
		AC_MSG_RESULT([found in /usr/lib])
	elif test -r /usr/lib64/libpq.a -o -r /usr/lib64/libpq.so; then
		PGSQL_LIBS="-L/usr/lib64 -lpq"
		AC_MSG_RESULT([found in /usr/lib64])
	elif test -r /usr/local/lib/libpq.a -o -r /usr/local/lib/libpq.so; then
		PGSQL_LIBS="-L/usr/local/lib -lpq"
		AC_MSG_RESULT([found in /usr/local/lib])
	elif test -r /usr/local/pgsql/lib/libpq.a -o -r /usr/local/pgsql/lib/libpq.so; then
		PGSQL_LIBS="-L/usr/local/pgsql/lib -lpq"
		AC_MSG_RESULT([found in /usr/local/pgsql/lib])
	else
		AC_MSG_RESULT([not found])
		AC_CHECK_LIB([pq], [PQconnectdb], [], [AC_MSG_ERROR([ERROR: missing PQ library. Refer to: http://www.postgresql.org/])])
	fi

	AC_MSG_CHECKING([default locations for libpq-fe.h])
	if test -r /usr/include/libpq-fe.h; then
		PGSQL_CFLAGS="-I/usr/include"
		AC_MSG_RESULT([found in /usr/include])
	elif test -r /usr/include/postgresql/libpq-fe.h; then
		PGSQL_CFLAGS="-I/usr/include/postgresql"
		AC_MSG_RESULT([found in /usr/include/postgresql])
	elif test -r /usr/local/include/libpq-fe.h; then
		PGSQL_CFLAGS="-I/usr/local/include"
		AC_MSG_RESULT([found in /usr/local/include])
	elif test -r /usr/local/pgsql/include/libpq-fe.h; then
		PGSQL_CFLAGS="-I/usr/local/pgsql/include"
		AC_MSG_RESULT([found in /usr/local/pgsql/include])
	else
		AC_MSG_RESULT([not found])
		AC_CHECK_HEADER([libpq-fe.h], [], [AC_MSG_ERROR(ERROR: missing PostgreSQL headers)])
	fi
    ])
    PLUGINS="${PLUGINS} pgsql"
    USING_SQL="yes"
    USING_PGSQL="yes"
    AC_DEFINE(WITH_PGSQL, 1)
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
		AC_CHECK_LIB([mongoc], [mongo_connect], [], [AC_MSG_ERROR([
			ERROR: missing MongoDB library (0.8 version). Refer to: https://github.com/mongodb/mongo-c-driver-legacy
		])])
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
		AC_CHECK_HEADER([mongo.h], [], [AC_MSG_ERROR(ERROR: missing MongoDB headers)])
	fi
    ])
    PLUGINS="${PLUGINS} mongodb"
    USING_MONGODB="yes"
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

AC_MSG_CHECKING(whether to enable SQLite3 support)
AC_ARG_ENABLE(sqlite3,
  [  --enable-sqlite3                 Enable SQLite3 support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    dnl reasonably old libsqlite3 already support pkg-config
    PKG_CHECK_MODULES([SQLITE3], [sqlite3])
    PLUGINS="${PLUGINS} sqlite3"
    USING_SQL="yes"
    USING_SQLITE3="yes"
    AC_DEFINE(WITH_SQLITE3, 1)
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
    PKG_CHECK_MODULES([RABBITMQ], [librabbitmq])
    PLUGINS="${PLUGINS} rabbitmq"
    USING_RABBITMQ="yes"
    AC_DEFINE(WITH_RABBITMQ, 1)
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


dnl start: Kafka handling
AC_MSG_CHECKING(whether to enable Kafka support)
AC_ARG_ENABLE(kafka,
  [  --enable-kafka                   Enable Kafka support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([KAFKA], [rdkafka >= 0.8.5],, [
	AC_MSG_CHECKING([default locations for librdkafka])
	if test -r /usr/lib/librdkafka.a -o -r /usr/lib/librdkafka.so; then
		KAFKA_LIBS="-L/usr/lib -lrdkafka"
		AC_MSG_RESULT([found in /usr/lib])
	elif test -r /usr/lib64/librdkafka.a -o -r /usr/lib64/librdkafka.so; then
		KAFKA_LIBS="-L/usr/lib64 -lrdkafka"
		AC_MSG_RESULT([found in /usr/lib64])
	elif test -r /usr/local/lib/librdkafka.a -o -r /usr/local/lib/librdkafka.so; then
		KAFKA_LIBS="-L/usr/local/lib -lrdkafka"
		AC_MSG_RESULT([found in /usr/local/lib])
	else
		AC_MSG_RESULT([not found])
		AC_CHECK_LIB([rdkafka], [rd_kafka_new], [], [AC_MSG_ERROR([
			ERROR: missing Kafka library. Refer to: https://github.com/edenhill/librdkafka/
		])])
	fi

	AC_MSG_CHECKING([default locations for rdkafka.h])
	if test -r /usr/include/librdkafka/rdkafka.h; then
		KAFKA_CFLAGS="-I/usr/include"
		AC_MSG_RESULT([found in /usr/include])
	elif test -r /usr/local/include/librdkafka/rdkafka.h; then
		KAFKA_CFLAGS="-I/usr/local/include"
		AC_MSG_RESULT([found in /usr/local/include])
	else
		AC_MSG_RESULT([not found])
		AC_CHECK_HEADER([rdkafka.h], [], [AC_MSG_ERROR(ERROR: missing Kafka headers)])
	fi
    ])
    PLUGINS="${PLUGINS} kafka"
    USING_KAFKA="yes"
    AC_DEFINE(WITH_KAFKA, 1)
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

dnl start: geoip handling
AC_MSG_CHECKING(whether to enable GeoIP support)
AC_ARG_ENABLE(geoip,
  [  --enable-geoip                   Enable GeoIP support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    dnl reasonably old Maxmind GeoIP v1 already support pkg-config
    PKG_CHECK_MODULES([GEOIP], [geoip >= 1.0.0])
    PLUGINS="${PLUGINS} geoip"
    USING_MMGEOIP="yes"
    AC_DEFINE(WITH_GEOIP, 1)
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
    PKG_CHECK_MODULES([GEOIPV2], [libmaxminddb >= 1.0.0],, [
	AC_MSG_CHECKING([default locations for libmaxminddb])
	if test -r /usr/lib/libmaxminddb.a -o -r /usr/lib/libmaxminddb.so; then
		GEOIPV2_LIBS="-L/usr/lib -lmaxminddb"
		AC_MSG_RESULT([found in /usr/lib])
	elif test -r /usr/lib64/libmaxminddb.a -o -r /usr/lib64/libmaxminddb.so; then
		GEOIPV2_LIBS="-L/usr/lib64 -lmaxminddb"
		AC_MSG_RESULT([found in /usr/lib64])
	elif test -r /usr/local/lib/libmaxminddb.a -o -r /usr/local/lib/libmaxminddb.so; then
		GEOIPV2_LIBS="-L/usr/local/lib -lmaxminddb"
		AC_MSG_RESULT([found in /usr/local/lib])
	else
		AC_MSG_RESULT([not found])
		AC_CHECK_LIB([maxminddb], [MMDB_open], [], [AC_MSG_ERROR([
			ERROR: missing Maxmind libmaxminddb library. Refer to: http://www.maxmind.com/download/geoip/api/c/
		])])
	fi

	AC_MSG_CHECKING([default locations for maxminddb.h])
	if test -r /usr/include/maxminddb.h; then
		GEOIPV2_CFLAGS="-I/usr/include"
		AC_MSG_RESULT([found in /usr/include])
	elif test -r /usr/local/include/maxminddb.h; then
		GEOIPV2_CFLAGS="-I/usr/local/include"
		AC_MSG_RESULT([found in /usr/local/include])
	else
		AC_MSG_RESULT([not found])
		AC_CHECK_HEADER([maxminddb.h], [], [AC_MSG_ERROR(ERROR: missing Maxmind libmaxminddb headers)])
	fi
    ])
    PLUGINS="${PLUGINS} geoipv2"
    USING_MMGEOIPV2="yes"
    AC_DEFINE(WITH_GEOIPV2, 1)
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
    PKG_CHECK_MODULES([JANSSON], [jansson >= 2.2])
    PLUGINS="${PLUGINS} jansson"
    USING_JANSSON="yes"
    AC_DEFINE(WITH_JANSSON, 1)
    AC_CHECK_LIB(jansson, json_object, [], [])
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
  [  --enable-avro                 Enable avro support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([AVRO], [avro-c >= 1.8])
    USING_AVRO="yes"
    AC_DEFINE(WITH_AVRO, 1)
    AC_CHECK_LIB(avro, avro_record_get, [], [])
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

AC_CHECK_LIB([z], [deflate], [
	LIBS="${LIBS} -lz"
	AC_DEFINE(HAVE_ZLIB, 1)]
)

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([getopt.h sys/select.h sys/time.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_TYPE(u_int64_t, [AC_DEFINE(HAVE_U_INT64_T, 1)])
AC_CHECK_TYPE(u_int32_t, [AC_DEFINE(HAVE_U_INT32_T, 1)])
AC_CHECK_TYPE(u_int16_t, [AC_DEFINE(HAVE_U_INT16_T, 1)])
AC_CHECK_TYPE(u_int8_t, [AC_DEFINE(HAVE_U_INT8_T, 1)])
AC_CHECK_TYPE(uint64_t, [AC_DEFINE(HAVE_UINT64_T, 1)])
AC_CHECK_TYPE(uint32_t, [AC_DEFINE(HAVE_UINT32_T, 1)])
AC_CHECK_TYPE(uint16_t, [AC_DEFINE(HAVE_UINT16_T, 1)])
AC_CHECK_TYPE(uint8_t, [AC_DEFINE(HAVE_UINT8_T, 1)])

AC_MSG_CHECKING([whether to enable 64bit counters])
AC_ARG_ENABLE(64bit,
        [  --enable-64bit                   Enable 64bit counters (default: yes)],
	[
          if test x$enableval = x"yes" ; then
            AC_MSG_RESULT(yes)
            AC_DEFINE(HAVE_64BIT_COUNTERS, 1)
          else
            AC_MSG_RESULT(no)
          fi
        ],
	[
          AC_MSG_RESULT(yes)
	  AC_DEFINE(HAVE_64BIT_COUNTERS, 1)
	]
)

AC_MSG_CHECKING([whether to enable multithreading in pmacct])
AC_ARG_ENABLE(threads,
        [  --enable-threads                 Enable multi-threading in pmacct (default: yes)],
	[
          if test x$enableval = x"yes" ; then
            AC_MSG_RESULT(yes)
            AC_DEFINE(ENABLE_THREADS, 1)
	  
	    dnl OS Specifics
	    case "$host" in
	    *-linux-*)
	        AC_DEFINE(_XOPEN_SOURCE, 600)
	        AC_DEFINE(_GNU_SOURCE, 1)
	      ;;
	    esac

	    LIBS="${LIBS} -lpthread"
            USING_THREADPOOL=yes
	  else
            AC_MSG_RESULT(no)
          fi
        ],
	[
          AC_MSG_RESULT(yes)
          AC_DEFINE(ENABLE_THREADS, 1)

          dnl OS Specifics
          case "$host" in
          *-linux-*)
              AC_DEFINE(_XOPEN_SOURCE, 600)
              AC_DEFINE(_GNU_SOURCE, 1)
            ;;
          esac

          LIBS="${LIBS} -lpthread"
          USING_THREADPOOL=yes
	]
)

AC_MSG_CHECKING(whether to enable NFLOG support)
AC_ARG_ENABLE(nflog,
  [  --enable-nflog                   Enable NFLOG support (default: no)],
  [ case "$enableval" in
  yes)
    AC_MSG_RESULT(yes)
    PKG_CHECK_MODULES([NFLOG], [libnetfilter_log >= 1])
    USING_NFLOG="yes"
    AC_DEFINE(WITH_NFLOG, 1)
    ;;
  no)
    AC_MSG_RESULT(no)
    ;;
  esac ],
AC_MSG_RESULT(no))

dnl Checks for library functions.
AC_TYPE_SIGNAL

AC_CHECK_FUNCS([strlcpy vsnprintf setproctitle mallopt json_object_update_missing tdestroy])

dnl final checks
dnl trivial solution to portability issue 
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

Now type 'make' to compile the source code.

Are you willing to get in touch with other pmacct users?
Join the pmacct mailing-list by sending a message to pmacct-discussion-subscribe@pmacct.net

Need for documentation and examples?
Read the README file or go to http://wiki.pmacct.net/

"
AC_SUBST([EXTRABIN])
AM_CONDITIONAL([WITH_MYSQL], [test x"$USING_MYSQL" = x"yes"])
AM_CONDITIONAL([WITH_PGSQL], [test x"$USING_PGSQL" = x"yes"])
AM_CONDITIONAL([WITH_MONGODB], [test x"$USING_MONGODB" = x"yes"])
AM_CONDITIONAL([WITH_SQLITE3], [test x"$USING_SQLITE3" = x"yes"])
AM_CONDITIONAL([WITH_RABBITMQ], [test x"$USING_RABBITMQ" = x"yes"])
AM_CONDITIONAL([WITH_KAFKA], [test x"$USING_KAFKA" = x"yes"])
AM_CONDITIONAL([USING_SQL], [test x"$USING_SQL" = x"yes"])
AM_CONDITIONAL([USING_THREADPOOL], [test x"$USING_THREADPOOL" = x"yes"])
AM_CONDITIONAL([WITH_NFLOG], [test x"$USING_NFLOG" = x"yes"])
AM_CONDITIONAL([WITH_AVRO], [test x"$USING_AVRO" = x"yes"])
AC_OUTPUT([ Makefile \
	    src/Makefile src/nfprobe_plugin/Makefile \
	    src/sfprobe_plugin/Makefile src/bgp/Makefile \
	    src/tee_plugin/Makefile src/isis/Makefile \
	    src/bmp/Makefile src/telemetry/Makefile ])
