AM_CFLAGS = $(PMACCT_CFLAGS)

if USING_BGP_BINS
noinst_PROGRAMS = pmbgp
pmbgp_SOURCES = pmbgp.c pmbgp.h
pmbgp_CFLAGS = -I$(top_srcdir)/src $(AM_CFLAGS)
pmbgp_LDFLAGS = $(DEFS) @ZMQ_CFLAGS@
pmbgp_LDADD = $(top_builddir)/src/libcommon.la @ZMQ_LIBS@
endif
