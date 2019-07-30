SUBDIRS = nfprobe_plugin sfprobe_plugin bgp tee_plugin isis bmp telemetry ndpi rpki filters
sbin_PROGRAMS =
bin_PROGRAMS =
EXTRA_PROGRAMS =

AM_LDFLAGS = @GEOIP_LIBS@ @GEOIPV2_LIBS@ @JANSSON_LIBS@ @AVRO_LIBS@
AM_CFLAGS = $(PMACCT_CFLAGS)

noinst_LTLIBRARIES = libdaemons.la libcommon.la
libcommon_la_SOURCES = strlcpy.c addr.c
libdaemons_la_SOURCES = signals.c util.c plugin_hooks.c		\
        server.c acct.c memory.c cfg.c				\
        imt_plugin.c log.c pkt_handlers.c			\
        cfg_handlers.c net_aggr.c				\
        bpf_filter.c print_plugin.c				\
        pretag.c ip_frag.c					\
        ports_aggr.c pretag_handlers.c				\
        ip_flow.c setproctitle.c				\
        classifier.c regexp.c					\
        conntrack.c xflow_status.c				\
	plugin_common.c preprocess.c				\
	ll.c nl.c 						\
	base64.c plugin_cmn_json.c 				\
	plugin_cmn_avro.c pmsearch.c 				\
	thread_pool.c						\
	plugin_cmn_custom.c

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
libdaemons_la_SOURCES += mysql_plugin.c sql_common_m.c
libdaemons_la_LIBADD  += @MYSQL_LIBS@
libdaemons_la_CFLAGS  += @MYSQL_CFLAGS@ -Wno-error=pointer-sign
endif
if WITH_PGSQL
libdaemons_la_SOURCES += pgsql_plugin.c sql_common_m.c
libdaemons_la_LIBADD  += @PGSQL_LIBS@
libdaemons_la_CFLAGS  += @PGSQL_CFLAGS@ -Wno-error=pointer-sign
endif
if WITH_MONGODB
libdaemons_la_SOURCES += mongodb_plugin.c sql_common_m.c
libdaemons_la_LIBADD  += @MONGODB_LIBS@
libdaemons_la_CFLAGS  += @MONGODB_CFLAGS@ -Wno-error=pointer-sign
endif
if WITH_SQLITE3
libdaemons_la_SOURCES += sqlite3_plugin.c sql_common_m.c
libdaemons_la_LIBADD  += @SQLITE3_LIBS@
libdaemons_la_CFLAGS  += @SQLITE3_CFLAGS@ -Wno-error=pointer-sign
endif
if WITH_AVRO
libdaemons_la_LIBADD  += @AVRO_LIBS@
libdaemons_la_CFLAGS  += @AVRO_CFLAGS@
if WITH_SERDES
libdaemons_la_LIBADD  += @SERDES_LIBS@
libdaemons_la_CFLAGS  += @SERDES_CFLAGS@
endif
endif
if WITH_NDPI
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
libdaemons_la_SOURCES += sql_common.c sql_handlers.c
libdaemons_la_LIBADD  += -lm -lz
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
uacctd_CFLAGS  = $(AM_CFLAGS) @NFLOG_CFLAGS@
uacctd_LDADD   = libdaemons.la @NFLOG_LIBS@
endif
pmacct_SOURCES = pmacct.c
pmacct_LDADD = libcommon.la
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
