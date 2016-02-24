SUBDIRS = nfprobe_plugin sfprobe_plugin bgp tee_plugin isis bmp
sbin_PROGRAMS = pmacctd nfacctd sfacctd uacctd
bin_PROGRAMS = pmacct @EXTRABIN@
EXTRA_PROGRAMS =

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
        sflow.h crc32.h
# Builtin plugins
libdaemons_la_LIBADD  = nfprobe_plugin/libnfprobe_plugin.la
libdaemons_la_LIBADD += sfprobe_plugin/libsfprobe_plugin.la
libdaemons_la_LIBADD += bmp/libbmp.la
libdaemons_la_LIBADD += bgp/libbgp.la
libdaemons_la_LIBADD += tee_plugin/libtee_plugin.la
libdaemons_la_LIBADD += isis/libisis.la
libdaemons_la_LIBADD += libcommon.la
if WITH_MYSQL
libdaemons_la_SOURCES += mysql_plugin.c mysql_plugin.h
endif
if WITH_PGSQL
libdaemons_la_SOURCES += pgsql_plugin.c pgsql_plugin.h
endif
if WITH_MONGODB
libdaemons_la_SOURCES += mongodb_plugin.c mongodb_plugin.h
endif
if WITH_SQLITE3
libdaemons_la_SOURCES += sqlite3_plugin.c sqlite3_plugin.c
endif
if WITH_RABBITMQ
libdaemons_la_SOURCES += amqp_common.c amqp_common.h amqp_plugin.c amqp_plugin.h
endif
if WITH_KAFKA
libdaemons_la_SOURCES += kafka_common.c kafka_common.h kafka_plugin.c kafka_plugin.h
endif
if USING_SQL
libdaemons_la_SOURCES += sql_common.c sql_handlers.c sql_common.h
libdaemons_la_LIBADD  += -lm -lz
endif
if USING_THREADPOOL
libdaemons_la_SOURCES += thread_pool.c thread_pool.h
endif

pmacctd_SOURCES = pmacctd.c
pmacctd_LDFLAGS = $(DEFS)
pmacctd_LDADD = libdaemons.la
nfacctd_SOURCES = nfacctd.c nfacctd.h nfv8_handlers.c nfv8_handlers.h nfv9_template.c
nfacctd_LDFLAGS = $(DEFS)
nfacctd_LDADD = libdaemons.la
sfacctd_SOURCES = sfacctd.c sfacctd.h sfv5_module.c sfv5_module.h
sfacctd_LDFLAGS = $(DEFS)
sfacctd_LDADD = libdaemons.la
uacctd_SOURCES = uacctd.c uacctd.h
uacctd_LDFLAGS = $(DEFS)
uacctd_LDADD = libdaemons.la
pmacct_SOURCES = pmacct.c
pmacct_LDADD = libcommon.la
