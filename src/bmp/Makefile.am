AM_CFLAGS = $(PMACCT_CFLAGS)

noinst_LTLIBRARIES = libbmp.la
libbmp_la_SOURCES = bmp.c bmp_logdump.c bmp_msg.c bmp_util.c \
	bmp_lookup.c bmp.h bmp_logdump.h bmp_msg.h bmp_util.h \
	bmp_lookup.h
libbmp_la_CFLAGS = -I$(srcdir)/.. $(AM_CFLAGS)
