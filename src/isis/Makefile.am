AM_CFLAGS = $(PMACCT_CFLAGS)

noinst_LTLIBRARIES = libpmisis.la
libpmisis_la_SOURCES = isis.c checksum.c dict.c table.c prefix.c	\
	sockunion.c hash.c stream.c thread.c				\
	isis_circuit.c isis_events.c isis_route.c isis_tlv.c		\
	isis_csm.c isis_flags.c isis_misc.c isisd.c isis_adjacency.c	\
	isis_dynhn.c isis_spf.c iso_checksum.c isis_lsp.c isis_pdu.c	\
	checksum.h dict.h hash.h isis_adjacency.h isis_circuit.h	\
	isis_common.h isis_constants.h isis_csm.h isis-data.h isisd.h	\
	isis_dynhn.h isis_events.h isis_flags.h isis.h isis_ll.h	\
	isis_lsp.h isis_misc.h isis_network.h isis_pdu.h isis_route.h	\
	isis_spf.h isis_tlv.h iso_checksum.h iso.h 			\
	prefix.h sockunion.h stream.h table.h thread.h isis-globals.c
libpmisis_la_CFLAGS = -I$(srcdir)/.. $(AM_CFLAGS) -Wno-error=pointer-sign
