AM_CFLAGS = $(PMACCT_CFLAGS)

noinst_LTLIBRARIES = libtee_plugin.la
libtee_plugin_la_SOURCES = tee_plugin.c tee_recvs.c tee_plugin.h	\
	tee_recvs-data.h tee_recvs.h
libtee_plugin_la_CFLAGS = -I$(srcdir)/.. $(AM_CFLAGS)
