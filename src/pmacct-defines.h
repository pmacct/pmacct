/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2009 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* defines */
#define ARGS_NFACCTD "n:dDhP:b:f:F:c:m:p:r:s:S:L:l:v:o:R"
#define ARGS_SFACCTD "n:dDhP:b:f:F:c:m:p:r:s:S:L:l:v:o:R"
#define ARGS_PMACCTD "n:NdDhP:b:f:F:c:i:I:m:p:r:s:S:v:o:wWL:R"
#define ARGS_UACCTD "n:NdDhP:b:f:F:c:m:p:r:s:S:v:o:Rg:L:"
#define ARGS_PMACCT "Ssc:Cetm:p:P:M:arN:n:lT:"
#define N_PRIMITIVES 41
#define N_FUNCS 10 
#define MAX_N_PLUGINS 32
#define PROTO_LEN 12
#define MAX_MAP_ENTRIES 128
#define AGG_FILTER_ENTRIES 128 
#define UINT32T_THRESHOLD 4290000000UL
#define UINT64T_THRESHOLD 18446744073709551360ULL
#ifndef UINT8_MAX
#define UINT8_MAX (255U)
#endif
#ifndef UINT16_MAX
#define UINT16_MAX (65535U)
#endif
#ifndef UINT32_MAX
#define UINT32_MAX (4294967295U)
#endif

#if defined ENABLE_IPV6
#define DEFAULT_SNAPLEN 128
#else
#define DEFAULT_SNAPLEN 68
#endif

#define SRVBUFLEN (256+MOREBUFSZ)
#define LONGSRVBUFLEN (384+MOREBUFSZ)
#define LONGLONGSRVBUFLEN (1024+MOREBUFSZ)
#define LARGEBUFLEN (8192+MOREBUFSZ)

#define MANTAINER "Paolo Lucente <paolo@pmacct.net>"
#define PMACCTD_USAGE_HEADER "Promiscuous Mode Accounting Daemon, pmacctd 0.12.0-cvs"
#define UACCTD_USAGE_HEADER "Linux NetFilter ULOG Accounting Daemon, pmacctd 0.12.0-cvs"
#define PMACCT_USAGE_HEADER "pmacct, pmacct client 0.12.0-cvs"
#define PMMYPLAY_USAGE_HEADER "pmmyplay, pmacct MySQL logfile player 0.12.0-cvs"
#define PMPGPLAY_USAGE_HEADER "pmpgplay, pmacct PGSQL logfile player 0.12.0-cvs"
#define NFACCTD_USAGE_HEADER "NetFlow Accounting Daemon, nfacctd 0.12.0-cvs"
#define SFACCTD_USAGE_HEADER "sFlow Accounting Daemon, sfacctd 0.12.0-cvs"

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#define ERR -1
#define SUCCESS 0

#define	E_NOTFOUND	2

#ifndef MIN
#define MIN(x, y) (x <= y ? x : y)
#endif

#ifndef MAX
#define MAX(x, y) (x <= y ? y : x)
#endif

/* acct_type */ 
#define ACCT_PM		1	/* promiscuous mode */
#define ACCT_NF		2	/* NetFlow */
#define ACCT_SF		3	/* sFlow */
#define ACCT_UL		4	/* Linux NetFilter ULOG */

/* map type */
#define MAP_TAG 		0	/* pre_tag_map */
#define MAP_BGP_PEER_AS_SRC	100	/* bgp_peer_src_as_map */
#define MAP_BGP_TO_XFLOW_AGENT	101	/* bgp_to_agent_map */
#define MAP_BGP_SRC_LOCAL_PREF	102	/* bgp_src_local_pref_map */
#define MAP_BGP_SRC_MED		103	/* bgp_src_med_map */

/* 41 primitives currently defined */
#define COUNT_SRC_HOST		0x0000000000000001ULL
#define COUNT_DST_HOST		0x0000000000000002ULL
#define COUNT_SUM_HOST          0x0000000000000004ULL
#define COUNT_SRC_PORT          0x0000000000000008ULL
#define COUNT_DST_PORT          0x0000000000000010ULL
#define COUNT_IP_PROTO          0x0000000000000020ULL
#define COUNT_SRC_MAC           0x0000000000000040ULL
#define COUNT_DST_MAC           0x0000000000000080ULL
#define COUNT_SRC_NET		0x0000000000000100ULL
#define COUNT_DST_NET		0x0000000000000200ULL
#define COUNT_ID		0x0000000000000400ULL
#define COUNT_VLAN		0x0000000000000800ULL
#define COUNT_IP_TOS		0x0000000000001000ULL
#define COUNT_NONE		0x0000000000002000ULL
#define COUNT_SRC_AS		0x0000000000004000ULL
#define COUNT_DST_AS		0x0000000000008000ULL
#define COUNT_SUM_NET		0x0000000000010000ULL
#define COUNT_SUM_AS		0x0000000000020000ULL
#define COUNT_SUM_PORT		0x0000000000040000ULL
#define TIMESTAMP               0x0000000000080000ULL /* USE_TIMESTAMPS */
#define COUNT_FLOWS		0x0000000000100000ULL
#define COUNT_SUM_MAC		0x0000000000200000ULL
#define COUNT_CLASS		0x0000000000400000ULL
#define COUNT_COUNTERS		0x0000000000800000ULL
#define COUNT_PAYLOAD		0x0000000001000000ULL
#define COUNT_TCPFLAGS		0x0000000002000000ULL
#define COUNT_STD_COMM		0x0000000004000000ULL
#define COUNT_EXT_COMM		0x0000000008000000ULL
#define COUNT_AS_PATH		0x0000000010000000ULL
#define COUNT_LOCAL_PREF	0x0000000020000000ULL
#define COUNT_MED		0x0000000040000000ULL
#define COUNT_PEER_SRC_AS	0x0000000080000000ULL
#define COUNT_PEER_DST_AS	0x0000000100000000ULL
#define COUNT_PEER_SRC_IP	0x0000000200000000ULL
#define COUNT_PEER_DST_IP	0x0000000400000000ULL
#define COUNT_ID2		0x0000000800000000ULL
#define COUNT_SRC_AS_PATH	0x0000001000000000ULL
#define COUNT_SRC_STD_COMM	0x0000002000000000ULL
#define COUNT_SRC_EXT_COMM	0x0000004000000000ULL
#define COUNT_SRC_LOCAL_PREF	0x0000008000000000ULL
#define COUNT_SRC_MED		0x0000010000000000ULL

/* BYTES and PACKETS are used into templates; we let their values to
   overlap with some values we will not need into templates */ 
#define LT_BYTES		COUNT_SRC_NET
#define LT_PACKETS		COUNT_DST_NET
#define LT_FLOWS		COUNT_SUM_HOST
#define LT_NO_L2		COUNT_SUM_NET

#define FAKE_SRC_MAC		0x00000001
#define FAKE_DST_MAC		0x00000002
#define FAKE_SRC_HOST		0x00000004
#define FAKE_DST_HOST		0x00000008
#define FAKE_SRC_AS		0x00000010
#define FAKE_DST_AS		0x00000020
#define FAKE_COMMS		0x00000040
#define FAKE_PEER_SRC_AS	0x00000080
#define FAKE_PEER_DST_AS	0x00000100
#define FAKE_PEER_SRC_IP	0x00000200
#define FAKE_PEER_DST_IP	0x00000400
#define FAKE_AS_PATH		0x00000800

#define COUNT_MINUTELY          0x00000001
#define COUNT_HOURLY            0x00000002
#define COUNT_DAILY             0x00000004
#define COUNT_WEEKLY		0x00000008
#define COUNT_MONTHLY		0x00000010

#define WANT_STATS		0x00000001
#define WANT_ERASE		0x00000002
#define WANT_STATUS		0x00000004
#define WANT_COUNTER		0x00000008
#define WANT_MATCH		0x00000010
#define WANT_RESET		0x00000020
#define WANT_CLASS_TABLE	0x00000040
#define WANT_LOCK_OP		0x00000080

#define PIPE_TYPE_METADATA	0x00000001
#define PIPE_TYPE_PAYLOAD	0x00000002
#define PIPE_TYPE_EXTRAS	0x00000004
#define PIPE_TYPE_BGP		0x00000008

#define CHLD_WARNING		0x00000001
#define CHLD_ALERT		0x00000002

#define BGP_SRC_PRIMITIVES_MAP	0x00000001
#define BGP_SRC_PRIMITIVES_BGP	0x00000002

typedef u_int32_t pm_class_t;
typedef u_int32_t pm_id_t;

#if defined HAVE_64BIT_COUNTERS
typedef u_int64_t pm_counter_t;
#else
typedef u_int32_t pm_counter_t;
#endif

#if defined __PMACCTD_C || defined __UACCTD_C
#define NF_AS_KEEP 0 
#define NF_AS_NEW 1 
#define NF_AS_BGP 2 

#define NF_NET_COMPAT   0x00000000 /* Backward compatibility selection */
#define NF_NET_KEEP     0x00000001 /* Determine IP network prefixes from NetFlow data */
#define NF_NET_NEW      0x00000002 /* Determine IP network prefixes from network files */
#define NF_NET_BGP      0x00000004 /* Determine IP network prefixes from BGP peerings */
#define NF_NET_STATIC   0x00000008 /* Determine IP network prefixes from static mask */
#endif
