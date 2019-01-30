AM_CFLAGS = $(PMACCT_CFLAGS)

noinst_LTLIBRARIES = libpmrpki.la
libpmrpki_la_SOURCES = rpki.c rpki.h rpki_msg.c rpki_msg.h rpki_lookup.c \
			rpki_lookup.h rpki_util.c rpki_util.h
libpmrpki_la_CFLAGS = -I$(srcdir)/.. $(AM_CFLAGS)
