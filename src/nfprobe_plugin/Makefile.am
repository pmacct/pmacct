noinst_LTLIBRARIES = libnfprobe_plugin.la
libnfprobe_plugin_la_SOURCES = nfprobe_plugin.c netflow1.c netflow5.c	\
	netflow9.c convtime.c strlcat.c common.h convtime.h		\
	nfprobe_plugin.h sys-tree.h treetype.h
libnfprobe_plugin_la_CFLAGS = -DFLOW_SPLAY -DEXPIRY_RB -I$(srcdir)/..
