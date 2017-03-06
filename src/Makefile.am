SUBDIRS = nfprobe_plugin sfprobe_plugin bgp tee_plugin isis bmp telemetry intstats
sbin_PROGRAMS = pmacctd nfacctd sfacctd pmtelemetryd pmbgpd pmbmpd
bin_PROGRAMS = pmacct @EXTRABIN@
EXTRA_PROGRAMS =

AM_LDFLAGS = @GEOIP_LIBS@ @GEOIPV2_LIBS@ @JANSSON_LIBS@ @AVRO_LIBS@
AM_CFLAGS = $(PMACCT_CFLAGS)

noinst_LTLIBRARIES = libdaemons.la libcommon.la
libcommon_la_SOURCES = strlcpy.c addr.c jansson.c addr.h pmacct.h	\
	pmacct-build.h pmacct-data.h pmacct-defines.h mpls.h network.h once.h
libdaemons_la_SOURCES = signals.c util.c util.h plugin_hooks.c		\
        plugin_hooks.h server.c acct.c memory.c cfg.c cfg.h		\
        imt_plugin.c imt_plugin.h log.c log.h pkt_handlers.c		\
        pkt_handlers.h cfg_handlers.c cfg_handlers.h net_aggr.c		\
        net_aggr.h bpf_filter.c pmacct-bpf.h print_plugin.c		\
        print_plugin.h pretag.c pretag-data.h pretag.h ip_frag.c	\
        ip_frag.h ports_aggr.c ports_aggr.h pretag_handlers.c		\
        pretag_handlers.h ip_flow.c ip_flow.h setproctitle.c		\
        setproctitle.h classifier.c classifier.h regexp.c regexp.h	\
        regmagic.h regsub.c conntrack.c conntrack.h xflow_status.c	\
        xflow_status.h plugin_common.c plugin_common.h preprocess.c	\
        preprocess-data.h preprocess.h ll.c nl.c jhash.h pmacct-dlt.h	\
        sflow.h crc32.h base64.c base64.h plugin_cmn_json.c		\
	plugin_cmn_json.h plugin_cmn_avro.c plugin_cmn_avro.h
# Builtin plugins
libdaemons_la_LIBADD  = nfprobe_plugin/libnfprobe_plugin.la
libdaemons_la_LIBADD += sfprobe_plugin/libsfprobe_plugin.la
libdaemons_la_LIBADD += bmp/libbmp.la
libdaemons_la_LIBADD += bgp/libbgp.la
libdaemons_la_LIBADD += intstats/libintstats.la
libdaemons_la_LIBADD += tee_plugin/libtee_plugin.la
libdaemons_la_LIBADD += isis/libisis.la
libdaemons_la_LIBADD += telemetry/libtelemetry.la
libdaemons_la_LIBADD += libcommon.la
libdaemons_la_CFLAGS  = $(AM_CFLAGS)
if WITH_MYSQL
libdaemons_la_SOURCES += mysql_plugin.c mysql_plugin.h
libdaemons_la_LIBADD  += @MYSQL_LIBS@
libdaemons_la_CFLAGS  += @MYSQL_CFLAGS@
endif
if WITH_PGSQL
libdaemons_la_SOURCES += pgsql_plugin.c pgsql_plugin.h
libdaemons_la_LIBADD  += @PGSQL_LIBS@
libdaemons_la_CFLAGS  += @PGSQL_CFLAGS@
endif
if WITH_MONGODB
libdaemons_la_SOURCES += mongodb_plugin.c mongodb_plugin.h
libdaemons_la_LIBADD  += @MONGODB_LIBS@
libdaemons_la_CFLAGS  += @MONGODB_CFLAGS@
endif
if WITH_SQLITE3
libdaemons_la_SOURCES += sqlite3_plugin.c sqlite3_plugin.c
libdaemons_la_LIBADD  += @SQLITE3_LIBS@
libdaemons_la_CFLAGS  += @SQLITE3_CFLAGS@
endif
if WITH_AVRO
libdaemons_la_LIBADD  += @AVRO_LIBS@
libdaemons_la_CFLAGS  += @AVRO_CFLAGS@
endif
if WITH_RABBITMQ
libdaemons_la_SOURCES += amqp_common.c amqp_common.h amqp_plugin.c amqp_plugin.h
libdaemons_la_LIBADD  += @RABBITMQ_LIBS@
libdaemons_la_CFLAGS  += @RABBITMQ_CFLAGS@
endif
if WITH_KAFKA
libdaemons_la_SOURCES += kafka_common.c kafka_common.h kafka_plugin.c kafka_plugin.h
libdaemons_la_LIBADD  += @KAFKA_LIBS@
libdaemons_la_CFLAGS  += @KAFKA_CFLAGS@
endif
if USING_SQL
libdaemons_la_SOURCES += sql_common.c sql_handlers.c sql_common.h
libdaemons_la_LIBADD  += -lm -lz
endif
if USING_THREADPOOL
libdaemons_la_SOURCES += thread_pool.c thread_pool.h
endif

pmacctd_SOURCES = pmacctd.c
pmacctd_LDADD = libdaemons.la
nfacctd_SOURCES = nfacctd.c nfacctd.h nfv8_handlers.c nfv8_handlers.h nfv9_template.c
nfacctd_LDADD = libdaemons.la
sfacctd_SOURCES = sfacctd.c sflow.c sfacctd.h sfv5_module.c sfv5_module.h
sfacctd_LDADD = libdaemons.la
if WITH_NFLOG
sbin_PROGRAMS += uacctd
uacctd_SOURCES = uacctd.c uacctd.h
uacctd_CFLAGS  = $(AM_CFLAGS) @NFLOG_CFLAGS@
uacctd_LDADD   = libdaemons.la @NFLOG_LIBS@
endif
pmacct_SOURCES = pmacct.c
pmacct_LDADD = libcommon.la
pmtelemetryd_SOURCES = pmtelemetryd.c pmtelemetryd.h
pmtelemetryd_LDFLAGS = $(DEFS)
pmtelemetryd_LDADD = libdaemons.la
pmbgpd_SOURCES = pmbgpd.c pmbgpd.h
pmbgpd_LDFLAGS = $(DEFS)
pmbgpd_LDADD = libdaemons.la
pmbmpd_SOURCES = pmbmpd.c pmbmpd.h
pmbmpd_LDFLAGS = $(DEFS)
pmbmpd_LDADD = libdaemons.la
