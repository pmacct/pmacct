AM_CFLAGS = $(PMACCT_CFLAGS)

noinst_LTLIBRARIES = libtelemetry.la
libtelemetry_la_SOURCES = telemetry.c telemetry_logdump.c telemetry_msg.c	\
	telemetry_util.c telemetry.h telemetry_logdump.h telemetry_msg.h	\
	telemetry_util.h 
libtelemetry_la_CFLAGS = -I$(srcdir)/.. $(AM_CFLAGS)
