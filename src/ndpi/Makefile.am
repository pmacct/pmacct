AM_LDFLAGS = @NDPI_LIBS@
AM_CFLAGS = $(PMACCT_CFLAGS) $(NDPI_CFLAGS)

noinst_LTLIBRARIES = libndpi_support.la
libndpi_support_la_SOURCES = ndpi.c ndpi.h ndpi_util.c ndpi_util.h
libnddpi_support_la_CFLAGS = -I$(srcdir)/.. $(AM_CFLAGS)

