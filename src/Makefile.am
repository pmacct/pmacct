SUBDIRS = nfprobe_plugin sfprobe_plugin bgp tee_plugin isis 
sbin_PROGRAMS = pmacctd nfacctd sfacctd uacctd
bin_PROGRAMS = pmacct @EXTRABIN@ 
EXTRA_PROGRAMS = pmmyplay pmpgplay
pmacctd_PLUGINS = @PLUGINS@ @THREADS_SOURCES@
pmacctd_SOURCES = pmacctd.c signals.c util.c strlcpy.c plugin_hooks.c \
	server.c acct.c memory.c ll.c cfg.c imt_plugin.c log.c pkt_handlers.c \
	cfg_handlers.c net_aggr.c bpf_filter.c print_plugin.c ip_frag.c \
	ports_aggr.c addr.c pretag.c pretag_handlers.c ip_flow.c setproctitle.c \
	classifier.c regexp.c regsub.c conntrack.c xflow_status.c nl.c
pmacctd_LDFLAGS = $(DEFS) 
pmacctd_LDADD = $(pmacctd_PLUGINS)
nfacctd_SOURCES = nfacctd.c signals.c util.c strlcpy.c plugin_hooks.c \
        server.c acct.c memory.c cfg.c imt_plugin.c log.c pkt_handlers.c \
        cfg_handlers.c net_aggr.c bpf_filter.c print_plugin.c pretag.c \
	pretag_handlers.c ports_aggr.c nfv8_handlers.c nfv9_template.c addr.c \
	setproctitle.c ip_flow.c classifier.c regexp.c regsub.c conntrack.c \
	xflow_status.c
nfacctd_LDFLAGS = $(DEFS)
nfacctd_LDADD = $(pmacctd_PLUGINS)
sfacctd_SOURCES = sfacctd.c signals.c util.c strlcpy.c plugin_hooks.c \
        server.c acct.c memory.c cfg.c imt_plugin.c log.c pkt_handlers.c \
        cfg_handlers.c net_aggr.c bpf_filter.c print_plugin.c pretag.c \
	pretag_handlers.c ports_aggr.c addr.c ll.c setproctitle.c ip_flow.c \
	classifier.c regexp.c regsub.c conntrack.c xflow_status.c
sfacctd_LDFLAGS = $(DEFS)
sfacctd_LDADD = $(pmacctd_PLUGINS)
uacctd_SOURCES = uacctd.c signals.c util.c strlcpy.c plugin_hooks.c \
        server.c acct.c memory.c ll.c cfg.c imt_plugin.c log.c pkt_handlers.c \
	cfg_handlers.c net_aggr.c bpf_filter.c print_plugin.c ip_frag.c \
	ports_aggr.c addr.c pretag.c pretag_handlers.c ip_flow.c setproctitle.c \
	classifier.c regexp.c regsub.c conntrack.c xflow_status.c nl.c
uacctd_LDFLAGS = $(DEFS) 
uacctd_LDADD = $(pmacctd_PLUGINS)
pmacct_SOURCES = pmacct.c strlcpy.c addr.c
pmmyplay_SOURCES = pmmyplay.c strlcpy.c sql_handlers.c log_templates.c addr.c 
pmpgplay_SOURCES = pmpgplay.c strlcpy.c sql_handlers.c log_templates.c addr.c 
