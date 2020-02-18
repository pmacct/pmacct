AM_CFLAGS = $(PMACCT_CFLAGS)

noinst_LTLIBRARIES = libnfprobe_plugin.la
libnfprobe_plugin_la_SOURCES = nfprobe_plugin.c netflow5.c	\
	netflow9.c convtime.c common.h convtime.h sys-tree.h	\
	nfprobe_plugin.h treetype.h
libnfprobe_plugin_la_CFLAGS = -DFLOW_SPLAY -DEXPIRY_RB -I$(srcdir)/.. $(AM_CFLAGS)
