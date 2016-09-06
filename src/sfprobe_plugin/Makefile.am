AM_CFLAGS = $(PMACCT_CFLAGS)

noinst_LTLIBRARIES = libsfprobe_plugin.la
libsfprobe_plugin_la_SOURCES = sflow_agent.c sflow_poller.c		\
	sflow_receiver.c sflow_sampler.c sfprobe_plugin.c sflow_api.h	\
	sflow.h
libsfprobe_plugin_la_CFLAGS = -I$(srcdir)/.. $(AM_CFLAGS)
