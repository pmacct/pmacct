SUBDIRS =

if WITH_EXTERNAL_DEPS
SUBDIRS += external_libs
endif

SUBDIRS += nfprobe_plugin sfprobe_plugin bgp tee_plugin bmp telemetry rpki filters ebpf
sbin_PROGRAMS =
bin_PROGRAMS =
EXTRA_PROGRAMS =

AM_LDFLAGS = @GEOIPV2_LIBS@
if WITH_JANSSON
AM_LDFLAGS += @JANSSON_LIBS@
endif
if WITH_AVRO
AM_LDFLAGS += @AVRO_LIBS@
endif

AM_LDFLAGS += @PMACCT_EXPORT_DYNAMIC_LDFLAGS@

AM_CFLAGS = $(PMACCT_CFLAGS)

pmacctinternalincludedir = $(includedir)/pmacct/src
nobase_pmacctinternalinclude_HEADERS = \
	addr.h \
	amqp_common.h \
	amqp_plugin.h \
	base64.h \
	bgp/bgp.h \
	bgp/bgp_aspath.h \
	bgp/bgp_blackhole.h \
	bgp/bgp_community.h \
	bgp/bgp_ecommunity.h \
	bgp/bgp_hash.h \
	bgp/bgp_lcommunity.h \
	bgp/bgp_lg.h \
	bgp/bgp_logdump.h \
	bgp/bgp_lookup.h \
	bgp/bgp_ls.h \
	bgp/bgp_ls-data.h \
	bgp/bgp_msg.h \
	bgp/bgp_packet.h \
	bgp/bgp_prefix.h \
	bgp/bgp_table.h \
	bgp/bgp_util.h \
	bgp/bgp_xcs.h \
	bgp/bgp_xcs-data.h \
	bmp/bmp.h \
	bmp/bmp_logdump.h \
	bmp/bmp_lookup.h \
	bmp/bmp_msg.h \
	bmp/bmp_tlv.h \
	bmp/bmp_util.h \
	build_config.h \
	cfg.h \
	cfg_handlers.h \
	classifier.h \
	conntrack.h \
	crc32.h \
	dynlib/dynamic_loading.h \
	ebpf/ebpf_rp_balancer.h \
	filters/bloom.h \
	filters/murmur2.h \
	ha.h \
	imt_plugin.h \
	ip_flow.h \
	ip_frag.h \
	jhash.h \
	kafka_common.h \
	kafka_plugin.h \
	log.h \
	mpls.h \
	mysql_plugin.h \
	ndpi/ndpi.h \
	ndpi/ndpi_private.h \
	ndpi/ndpi_util.h \
	net_aggr.h \
	network.h \
	nfacctd.h \
	nfprobe_plugin/common.h \
	nfprobe_plugin/convtime.h \
	nfprobe_plugin/nfprobe_plugin.h \
	nfprobe_plugin/sys-tree.h \
	nfprobe_plugin/treetype.h \
	nfv9_template.h \
	once.h \
	packet_processor/packet_processor.h \
	pgsql_plugin.h \
	pkt_handlers.h \
	plugin_cmn_avro.h \
	plugin_cmn_custom.h \
	plugin_cmn_json.h \
	plugin_common.h \
	plugin_hooks.h \
	pmacct.h \
	pmacct-data.h \
	pmacct-defines.h \
	pmacct-version.h \
	pmbgpd.h \
	pmbmpd.h \
	pmsearch.h \
	pmtelemetryd.h \
	preprocess.h \
	preprocess-data.h \
	preprocess-internal.h \
	pretag.h \
	pretag_handlers.h \
	pretag-data.h \
	print_plugin.h \
	redis_common.h \
	rpki/rpki.h \
	rpki/rpki_lookup.h \
	rpki/rpki_msg.h \
	rpki/rpki_util.h \
	setproctitle.h \
	sfacctd.h \
	sflow.h \
	sfprobe_plugin/sflow_api.h \
	sfv5_module.h \
	sql_common.h \
	sql_common_m.h \
	sqlite3_plugin.h \
	tee_plugin/tee_plugin.h \
	tee_plugin/tee_recvs.h \
	tee_plugin/tee_recvs-data.h \
	telemetry/telemetry.h \
	telemetry/telemetry_logdump.h \
	telemetry/telemetry_msg.h \
	telemetry/telemetry_util.h \
	thread_pool.h \
	uacctd.h \
	util.h \
	util-data.h \
	xflow_status.h \
	zmq_common.h

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
        pretag_handlers.c ip_flow.c setproctitle.c		\
        classifier.c conntrack.c xflow_status.c			\
	plugin_common.c preprocess.c ha.c			\
	ll.c nl.c sflow.c					\
	base64.c pmsearch.c 					\
	thread_pool.c						\
	plugin_cmn_custom.c network.c pmacct-globals.c 			\
	dynlib/dynamic_loading.c packet_processor/packet_processor.c

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
libdaemons_la_LIBADD += telemetry/libpmtelemetry.la
libdaemons_la_LIBADD += ebpf/libpmebpf.la
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
if WITH_UNYTE_UDP_NOTIF
libdaemons_la_LIBADD  += @UNYTE_UDP_NOTIF_LIBS@
libdaemons_la_CFLAGS  += @UNYTE_UDP_NOTIF_CFLAGS@
endif
if WITH_GRPC_COLLECTOR
libdaemons_la_LIBADD  += @GRPC_COLLECTOR_LIBS@
libdaemons_la_CFLAGS  += @GRPC_COLLECTOR_CFLAGS@
endif
if WITH_EBPF
libdaemons_la_LIBADD  += @EBPF_LIBS@
libdaemons_la_CFLAGS  += @EBPF_CFLAGS@
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
pmtelemetryd_LDFLAGS = $(AM_LDFLAGS) $(DEFS)
pmtelemetryd_LDADD = libdaemons.la
endif
if USING_BGP_BINS
sbin_PROGRAMS += pmbgpd
pmbgpd_SOURCES = pmbgpd.c
pmbgpd_LDFLAGS = $(AM_LDFLAGS) $(DEFS)
pmbgpd_LDADD = libdaemons.la
endif
if USING_BMP_BINS
sbin_PROGRAMS += pmbmpd
pmbmpd_SOURCES = pmbmpd.c
pmbmpd_LDFLAGS = $(AM_LDFLAGS) $(DEFS)
pmbmpd_LDADD = libdaemons.la
endif
