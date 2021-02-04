SUBDIRS =

if WITH_EXTERNAL_DEPS
SUBDIRS += external_libs
endif

SUBDIRS += nfprobe_plugin sfprobe_plugin bgp tee_plugin isis bmp telemetry rpki filters
sbin_PROGRAMS =
bin_PROGRAMS =
EXTRA_PROGRAMS =

AM_LDFLAGS = @GEOIP_LIBS@ @GEOIPV2_LIBS@
if WITH_JANSSON
AM_LDFLAGS += @JANSSON_LIBS@
endif
if WITH_AVRO
AM_LDFLAGS += @AVRO_LIBS@
endif

AM_CFLAGS = $(PMACCT_CFLAGS)

#Build string autogen
BUILT_SOURCES = pmacct-build.h_h
.PHONY = pmacct-build.h

pmacct-build.h_h:
	@if [ ! -f ".pmacct-build.h" ] || [ "`cat .pmacct-build.h`" != "`git rev-parse HEAD 2> /dev/null`" ]; then \
		echo "#ifndef PMACCT_BUILD_STR" > pmacct-build.h; \
		echo "#define PMACCT_BUILD_STR" >> pmacct-build.h; \
		if [ "x`git rev-parse --is-inside-work-tree 2> /dev/null`" == "xtrue" ]; then \
			echo "`git rev-parse HEAD`" > .pmacct-build.h; \
			BUILD_DATE="`git log -1 --date=short --pretty=format:%ad | tr -d "-"`"; \
			BUILD_AUX="`git log -1 --date=short --pretty=format:%ad`";\
			BUILD_COMMITS="`git log --date=short --pretty=format:%ad | sort | uniq -c | grep $$BUILD_AUX | awk '{print $$1}'`"; \
			BUILD_COMMITS="$$(($$BUILD_COMMITS - 1))"; \
			BUILD_HASH_SHORT="`git rev-parse --short HEAD`"; \
			echo "#define PMACCT_BUILD \"$$BUILD_DATE-$$BUILD_COMMITS ($$BUILD_HASH_SHORT)\"" >> pmacct-build.h; \
		else \
			echo "#define PMACCT_BUILD \"RELEASE\"" >> pmacct-build.h; \
		fi;\
		echo "#endif" >> pmacct-build.h; \
	fi

noinst_LTLIBRARIES = libdaemons.la libcommon.la
libcommon_la_SOURCES = strlcpy.c addr.c
libdaemons_la_SOURCES = signals.c util.c plugin_hooks.c		\
        server.c acct.c memory.c cfg.c				\
        imt_plugin.c log.c pkt_handlers.c			\
        cfg_handlers.c net_aggr.c				\
        print_plugin.c pretag.c ip_frag.c			\
        ports_aggr.c pretag_handlers.c				\
        ip_flow.c setproctitle.c				\
        classifier.c regexp.c					\
        conntrack.c xflow_status.c				\
	plugin_common.c preprocess.c				\
	ll.c nl.c						\
	base64.c pmsearch.c linklist.c				\
	thread_pool.c						\
	plugin_cmn_custom.c network.c pmacct-globals.c

libcommon_la_LIBADD  =
libcommon_la_CFLAGS  = $(AM_CFLAGS)

# Builtin plugins
libdaemons_la_LIBADD  = nfprobe_plugin/libnfprobe_plugin.la
libdaemons_la_LIBADD += sfprobe_plugin/libsfprobe_plugin.la
libdaemons_la_LIBADD += bmp/libpmbmp.la
libdaemons_la_LIBADD += bgp/libpmbgp.la
libdaemons_la_LIBADD += rpki/libpmrpki.la
libdaemons_la_LIBADD += filters/libpmfilters.la
libdaemons_la_LIBADD += tee_plugin/libtee_plugin.la
libdaemons_la_LIBADD += isis/libpmisis.la
libdaemons_la_LIBADD += telemetry/libpmtelemetry.la
libdaemons_la_LIBADD += libcommon.la
libdaemons_la_CFLAGS  = $(AM_CFLAGS)
if WITH_MYSQL
libdaemons_la_SOURCES += mysql_plugin.c
libdaemons_la_LIBADD  += @MYSQL_LIBS@
libdaemons_la_CFLAGS  += @MYSQL_CFLAGS@
endif
if WITH_PGSQL
libdaemons_la_SOURCES += pgsql_plugin.c
libdaemons_la_LIBADD  += @PGSQL_LIBS@
libdaemons_la_CFLAGS  += @PGSQL_CFLAGS@
endif
if WITH_MONGODB
libdaemons_la_SOURCES += mongodb_plugin.c
libdaemons_la_LIBADD  += @MONGODB_LIBS@
libdaemons_la_CFLAGS  += @MONGODB_CFLAGS@
endif
if WITH_SQLITE3
libdaemons_la_SOURCES += sqlite3_plugin.c
libdaemons_la_LIBADD  += @SQLITE3_LIBS@
libdaemons_la_CFLAGS  += @SQLITE3_CFLAGS@
endif
if WITH_JANSSON
libdaemons_la_SOURCES += plugin_cmn_json.c
libdaemons_la_LIBADD  += @JANSSON_LIBS@
libdaemons_la_CFLAGS  += @JANSSON_CFLAGS@
endif
if WITH_AVRO
libdaemons_la_SOURCES += plugin_cmn_avro.c
libdaemons_la_LIBADD  += @AVRO_LIBS@
libdaemons_la_CFLAGS  += @AVRO_CFLAGS@
if WITH_SERDES
libdaemons_la_LIBADD  += @SERDES_LIBS@
libdaemons_la_CFLAGS  += @SERDES_CFLAGS@
endif
endif
if WITH_NDPI
SUBDIRS += ndpi
libdaemons_la_LIBADD += ndpi/libndpi_support.la
libdaemons_la_LIBADD  += @NDPI_LIBS@
libdaemons_la_CFLAGS  += @NDPI_CFLAGS@
endif
if WITH_RABBITMQ
libdaemons_la_SOURCES += amqp_common.c amqp_plugin.c
libdaemons_la_LIBADD  += @RABBITMQ_LIBS@
libdaemons_la_CFLAGS  += @RABBITMQ_CFLAGS@
endif
if WITH_ZMQ
libdaemons_la_SOURCES += zmq_common.c
libdaemons_la_LIBADD  += @ZMQ_LIBS@
libdaemons_la_CFLAGS  += @ZMQ_CFLAGS@
endif
if WITH_KAFKA
libdaemons_la_SOURCES += kafka_common.c kafka_plugin.c
libdaemons_la_LIBADD  += @KAFKA_LIBS@
libdaemons_la_CFLAGS  += @KAFKA_CFLAGS@
endif
if USING_SQL
libdaemons_la_SOURCES += sql_common.c sql_handlers.c sql_common_m.c
libdaemons_la_CFLAGS += -Wno-error=pointer-sign
libdaemons_la_LIBADD  += -lm -lz
endif
if WITH_REDIS
libdaemons_la_SOURCES += redis_common.c
libdaemons_la_LIBADD  += @REDIS_LIBS@
libdaemons_la_CFLAGS  += @REDIS_CFLAGS@
endif
if WITH_GNUTLS
libdaemons_la_LIBADD  += @GNUTLS_LIBS@
libdaemons_la_CFLAGS  += @GNUTLS_CFLAGS@
endif

if USING_TRAFFIC_BINS
sbin_PROGRAMS += pmacctd nfacctd sfacctd
bin_PROGRAMS += pmacct
pmacctd_SOURCES = pmacctd.c
pmacctd_LDADD = libdaemons.la
nfacctd_SOURCES = nfacctd.c nfv9_template.c
nfacctd_LDADD = libdaemons.la
sfacctd_SOURCES = sfacctd.c sflow.c sfv5_module.c
sfacctd_LDADD = libdaemons.la
if WITH_NFLOG
sbin_PROGRAMS += uacctd
uacctd_SOURCES = uacctd.c
uacctd_CFLAGS  = $(AM_CFLAGS) @NFLOG_CFLAGS@ -Wno-error=pointer-sign
uacctd_LDADD   = libdaemons.la @NFLOG_LIBS@
endif
pmacct_SOURCES = pmacct.c 
pmacct_LDADD = libcommon.la libdaemons.la
endif
if USING_ST_BINS
sbin_PROGRAMS += pmtelemetryd
pmtelemetryd_SOURCES = pmtelemetryd.c
pmtelemetryd_LDFLAGS = $(DEFS)
pmtelemetryd_LDADD = libdaemons.la
endif
if USING_BGP_BINS
sbin_PROGRAMS += pmbgpd
pmbgpd_SOURCES = pmbgpd.c
pmbgpd_LDFLAGS = $(DEFS)
pmbgpd_LDADD = libdaemons.la
endif
if USING_BMP_BINS
sbin_PROGRAMS += pmbmpd
pmbmpd_SOURCES = pmbmpd.c
pmbmpd_LDFLAGS = $(DEFS)
pmbmpd_LDADD = libdaemons.la
endif
