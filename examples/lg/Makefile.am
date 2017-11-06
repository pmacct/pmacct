AM_CFLAGS = $(PMACCT_CFLAGS)

noinst_PROGRAMS = pmbgp
pmbgp_SOURCES = pmbgp.c pmbgp.h
pmbgp_CFLAGS = -I../../src -I$(srcdir)/.. $(AM_CFLAGS)
pmbgp_LDFLAGS = $(DEFS) @ZMQ_CFLAGS@
pmbgp_LDADD = ../../src/libcommon.la @ZMQ_LIBS@
