AM_CFLAGS = $(PMACCT_CFLAGS)

noinst_LTLIBRARIES = libpmbgp.la
libpmbgp_la_SOURCES = bgp.c bgp_aspath.c bgp_community.c		\
	bgp_ecommunity.c bgp_hash.c bgp_prefix.c bgp_table.c		\
	bgp_logdump.c bgp_util.c bgp_msg.c bgp_lookup.c			\
	bgp_lcommunity.c bgp_xcs.c bgp_aspath.h bgp_community.h		\
	bgp_ecommunity.h bgp.h bgp_hash.h bgp_logdump.h			\
	bgp_lookup.h bgp_msg.h bgp_packet.h bgp_prefix.h		\
	bgp_table.h bgp_util.h bgp_lcommunity.h bgp_xcs.h		\
	bgp_xcs-data.h bgp_blackhole.c bgp_blackhole.h			\
	bgp_lg.c bgp_lg.h

libpmbgp_la_CFLAGS = -I$(srcdir)/.. $(AM_CFLAGS)
