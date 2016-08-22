/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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
#define ARGS_NFACCTD "n:dDhP:b:f:F:c:m:p:r:s:S:L:l:o:t:O:uRVaA:E:"
#define ARGS_SFACCTD "n:dDhP:b:f:F:c:m:p:r:s:S:L:l:o:t:O:uRVaA:E:"
#define ARGS_PMACCTD "n:NdDhP:b:f:F:c:i:I:m:p:r:s:S:o:t:O:uwWL:RVazA:E:"
#define ARGS_UACCTD "n:NdDhP:b:f:F:c:m:p:r:s:S:o:t:O:uRg:L:VaA:E:"
#define ARGS_PMTELEMETRYD "hVL:l:f:dDS:F:"
#define ARGS_PMBGPD "hVL:l:f:dDS:F:"
#define ARGS_PMBMPD "hVL:l:f:dDS:F:"
#define ARGS_PMACCT "Ssc:Cetm:p:P:M:arN:n:lT:O:E:uDVUoiI"
#define N_PRIMITIVES 57
#define N_FUNCS 10 
#define MAX_N_PLUGINS 32
#define PROTO_LEN 12
#define MAX_MAP_ENTRIES 2048 /* allow maps */
#define BGP_MD5_MAP_ENTRIES 8192
#define AGG_FILTER_ENTRIES 128 
#define FOLLOW_BGP_NH_ENTRIES 32 
#define MAX_PROTOCOL_LEN 16
#define MAX_PKT_LEN_DISTRIB_BINS 255
#define MAX_PKT_LEN_DISTRIB_LEN 15
#define DEFAULT_IMT_PLUGIN_SELECT_TIMEOUT 5
#define UINT32T_THRESHOLD 4290000000UL
#define UINT64T_THRESHOLD 18446744073709551360ULL
#define INT64T_THRESHOLD 9223372036854775807ULL
#define PM_VARIABLE_LENGTH 65535
#define PM_COUNTRY_T_STRLEN 4
#ifndef UINT8_MAX
#define UINT8_MAX (255U)
#endif
#ifndef UINT16_MAX
#define UINT16_MAX (65535U)
#endif
#ifndef UINT32_MAX
#define UINT32_MAX (4294967295U)
#endif
#ifndef UINT64_MAX
#define UINT64_MAX (18446744073709551615ULL)
#endif
#ifndef INT_MAX
#define INT_MAX (2147483647U)
#endif

#define LONGLONG_RETRY INT_MAX

#if defined ENABLE_IPV6
#define DEFAULT_SNAPLEN 128
#else
#define DEFAULT_SNAPLEN 68
#endif
#define SNAPLEN_ISIS_MIN 512
#define SNAPLEN_ISIS_DEFAULT 1476

#define SRVBUFLEN (256+MOREBUFSZ)
#define LONGSRVBUFLEN (384+MOREBUFSZ)
#define LONGLONGSRVBUFLEN (1024+MOREBUFSZ)
#define LARGEBUFLEN (8192+MOREBUFSZ)
#define OUTPUT_FILE_BUFSZ (100 * LARGEBUFLEN)

#define PRIMITIVE_LEN 		32
#define PRIMITIVE_DESC_LEN	64

#define MANTAINER "Paolo Lucente <paolo@pmacct.net>"
#define PMACCTD_USAGE_HEADER "Promiscuous Mode Accounting Daemon, pmacctd 1.6.1-git"
#define UACCTD_USAGE_HEADER "Linux NetFilter NFLOG Accounting Daemon, uacctd 1.6.1-git"
#define PMACCT_USAGE_HEADER "pmacct, pmacct client 1.6.1-git"
#define NFACCTD_USAGE_HEADER "NetFlow Accounting Daemon, nfacctd 1.6.1-git"
#define SFACCTD_USAGE_HEADER "sFlow Accounting Daemon, sfacctd 1.6.1-git"
#define PMTELEMETRYD_USAGE_HEADER "Streaming Network Telemetry Daemon, pmtelemetryd 1.6.1-git"
#define PMBGPD_USAGE_HEADER "pmacct BGP Collector Daemon, pmbgpd 1.6.1-git"
#define PMBMPD_USAGE_HEADER "pmacct BMP Collector Daemon, pmbmpd 1.6.1-git"
#define PMACCT_COMPILE_ARGS COMPILE_ARGS
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef FALSE_NONZERO
#define FALSE_NONZERO 2
#endif
#ifndef ERR
#define ERR -1
#endif
#ifndef SUCCESS
#define SUCCESS 0
#endif

#define	E_NOTFOUND	2

#ifndef MIN
#define MIN(x, y) (x <= y ? x : y)
#endif

#ifndef MAX
#define MAX(x, y) (x <= y ? y : x)
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Daemon identificator */ 
#define ACCT_PM			1	/* promiscuous mode */
#define ACCT_NF			2	/* NetFlow */
#define ACCT_SF			3	/* sFlow */
#define ACCT_UL			4	/* Linux NetFilter NFLOG */
#define ACCT_FWPLANE_MAX	100	/* Max ID for forwarding-plane daemons */ 
#define ACCT_PMBGP		101	/* standalone BGP daemon */
#define ACCT_PMBMP		102	/* standalone BMP daemon */
#define ACCT_CTLPLANE_MAX	200	/* Max ID for control-plane daemons */ 
#define ACCT_PMTELE		201	/* Streaming Network Telemetry */
#define ACCT_INFRA_MAX		300	/* Max ID for infrastructure daemons */ 

/* map type */
#define MAP_TAG 		0	/* pre_tag_map */
#define MAP_BGP_PEER_AS_SRC	100	/* bgp_peer_src_as_map */
#define MAP_BGP_TO_XFLOW_AGENT	101	/* bgp_to_agent_map */
#define MAP_BGP_SRC_LOCAL_PREF	102	/* bgp_src_local_pref_map */
#define MAP_BGP_SRC_MED		103	/* bgp_src_med_map */
#define MAP_FLOW_TO_RD		104	/* flow_to_rd_map */
#define MAP_SAMPLING		105	/* sampling_map */
#define MAP_TEE_RECVS		106	/* tee_receivers */
#define MAP_IGP			107	/* igp_daemon_map */
#define MAP_CUSTOM_PRIMITIVES	108	/* aggregate_primitives */

/* PRIMITIVES DEFINITION: START */
/* 55 primitives currently defined */
/* internal: first registry, ie. what_to_count, aggregation, etc. */
#define COUNT_INT_SRC_HOST		0x0001000000000001ULL
#define COUNT_INT_DST_HOST		0x0001000000000002ULL
#define COUNT_INT_SUM_HOST		0x0001000000000004ULL
#define COUNT_INT_SRC_PORT		0x0001000000000008ULL
#define COUNT_INT_DST_PORT		0x0001000000000010ULL
#define COUNT_INT_IP_PROTO		0x0001000000000020ULL
#define COUNT_INT_SRC_MAC 		0x0001000000000040ULL
#define COUNT_INT_DST_MAC 		0x0001000000000080ULL
#define COUNT_INT_SRC_NET		0x0001000000000100ULL
#define COUNT_INT_DST_NET		0x0001000000000200ULL
#define COUNT_INT_TAG			0x0001000000000400ULL
#define COUNT_INT_VLAN			0x0001000000000800ULL
#define COUNT_INT_IP_TOS		0x0001000000001000ULL
#define COUNT_INT_NONE			0x0001000000002000ULL
#define COUNT_INT_SRC_AS		0x0001000000004000ULL
#define COUNT_INT_DST_AS		0x0001000000008000ULL
#define COUNT_INT_SUM_NET		0x0001000000010000ULL
#define COUNT_INT_SUM_AS		0x0001000000020000ULL
#define COUNT_INT_SUM_PORT		0x0001000000040000ULL
#define INT_TIMESTAMP			0x0001000000080000ULL /* USE_TIMESTAMPS */
#define COUNT_INT_FLOWS			0x0001000000100000ULL
#define COUNT_INT_SUM_MAC		0x0001000000200000ULL
#define COUNT_INT_CLASS			0x0001000000400000ULL
#define COUNT_INT_COUNTERS		0x0001000000800000ULL
#define COUNT_INT_PAYLOAD		0x0001000001000000ULL
#define COUNT_INT_TCPFLAGS		0x0001000002000000ULL
#define COUNT_INT_STD_COMM		0x0001000004000000ULL
#define COUNT_INT_EXT_COMM		0x0001000008000000ULL
#define COUNT_INT_AS_PATH		0x0001000010000000ULL
#define COUNT_INT_LOCAL_PREF		0x0001000020000000ULL
#define COUNT_INT_MED			0x0001000040000000ULL
#define COUNT_INT_PEER_SRC_AS		0x0001000080000000ULL
#define COUNT_INT_PEER_DST_AS		0x0001000100000000ULL
#define COUNT_INT_PEER_SRC_IP		0x0001000200000000ULL
#define COUNT_INT_PEER_DST_IP		0x0001000400000000ULL
#define COUNT_INT_TAG2			0x0001000800000000ULL
#define COUNT_INT_SRC_AS_PATH		0x0001001000000000ULL
#define COUNT_INT_SRC_STD_COMM		0x0001002000000000ULL
#define COUNT_INT_SRC_EXT_COMM		0x0001004000000000ULL
#define COUNT_INT_SRC_LOCAL_PREF	0x0001008000000000ULL
#define COUNT_INT_SRC_MED		0x0001010000000000ULL
#define COUNT_INT_MPLS_VPN_RD		0x0001020000000000ULL
#define COUNT_INT_IN_IFACE		0x0001040000000000ULL
#define COUNT_INT_OUT_IFACE		0x0001080000000000ULL
#define COUNT_INT_SRC_NMASK		0x0001100000000000ULL
#define COUNT_INT_DST_NMASK		0x0001200000000000ULL
#define COUNT_INT_COS			0x0001400000000000ULL
#define COUNT_INT_ETHERTYPE		0x0001800000000000ULL

/* internal: second registry, ie. what_to_count_2, aggregation_2, etc. */
#define COUNT_INT_SAMPLING_RATE		0x0002000000000001ULL
#define COUNT_INT_SRC_HOST_COUNTRY	0x0002000000000002ULL
#define COUNT_INT_DST_HOST_COUNTRY	0x0002000000000004ULL
#define COUNT_INT_PKT_LEN_DISTRIB	0x0002000000000008ULL
#define COUNT_INT_POST_NAT_SRC_HOST	0x0002000000000010ULL
#define COUNT_INT_POST_NAT_DST_HOST	0x0002000000000020ULL
#define COUNT_INT_POST_NAT_SRC_PORT	0x0002000000000040ULL
#define COUNT_INT_POST_NAT_DST_PORT	0x0002000000000080ULL
#define COUNT_INT_NAT_EVENT		0x0002000000000100ULL
#define COUNT_INT_TIMESTAMP_START	0x0002000000000200ULL
#define COUNT_INT_TIMESTAMP_END		0x0002000000000400ULL
#define COUNT_INT_TIMESTAMP_ARRIVAL	0x0002000000000800ULL
#define COUNT_INT_MPLS_LABEL_TOP	0x0002000000001000ULL
#define COUNT_INT_MPLS_LABEL_BOTTOM	0x0002000000002000ULL
#define COUNT_INT_MPLS_STACK_DEPTH	0x0002000000004000ULL
#define COUNT_INT_LABEL			0x0002000000008000ULL
#define COUNT_INT_EXPORT_PROTO_SEQNO	0x0002000000010000ULL
#define COUNT_INT_EXPORT_PROTO_VERSION  0x0002000000020000ULL
#define COUNT_INT_CUSTOM_PRIMITIVES	0x0002000000040000ULL

#define COUNT_INDEX_MASK	0xFFFF
#define COUNT_INDEX_CP		0xFFFF000000000000ULL  /* index 0xffff reserved to custom primitives */
#define COUNT_REGISTRY_MASK	0x0000FFFFFFFFFFFFULL
#define COUNT_REGISTRY_BITS	48

/* external: first registry, ie. what_to_count, aggregation, etc. */
#define COUNT_SRC_HOST                  (COUNT_INT_SRC_HOST & COUNT_REGISTRY_MASK)
#define COUNT_DST_HOST                  (COUNT_INT_DST_HOST & COUNT_REGISTRY_MASK)
#define COUNT_SUM_HOST                  (COUNT_INT_SUM_HOST & COUNT_REGISTRY_MASK)
#define COUNT_SRC_PORT                  (COUNT_INT_SRC_PORT & COUNT_REGISTRY_MASK)
#define COUNT_DST_PORT                  (COUNT_INT_DST_PORT & COUNT_REGISTRY_MASK)
#define COUNT_IP_PROTO                  (COUNT_INT_IP_PROTO & COUNT_REGISTRY_MASK)
#define COUNT_SRC_MAC                   (COUNT_INT_SRC_MAC & COUNT_REGISTRY_MASK)
#define COUNT_DST_MAC                   (COUNT_INT_DST_MAC & COUNT_REGISTRY_MASK)
#define COUNT_SRC_NET                   (COUNT_INT_SRC_NET & COUNT_REGISTRY_MASK)
#define COUNT_DST_NET                   (COUNT_INT_DST_NET & COUNT_REGISTRY_MASK)
#define COUNT_TAG                       (COUNT_INT_TAG & COUNT_REGISTRY_MASK)
#define COUNT_VLAN                      (COUNT_INT_VLAN & COUNT_REGISTRY_MASK)
#define COUNT_IP_TOS                    (COUNT_INT_IP_TOS & COUNT_REGISTRY_MASK)
#define COUNT_NONE                      (COUNT_INT_NONE & COUNT_REGISTRY_MASK)
#define COUNT_SRC_AS                    (COUNT_INT_SRC_AS & COUNT_REGISTRY_MASK)
#define COUNT_DST_AS                    (COUNT_INT_DST_AS & COUNT_REGISTRY_MASK)
#define COUNT_SUM_NET                   (COUNT_INT_SUM_NET & COUNT_REGISTRY_MASK)
#define COUNT_SUM_AS                    (COUNT_INT_SUM_AS & COUNT_REGISTRY_MASK)
#define COUNT_SUM_PORT                  (COUNT_INT_SUM_PORT & COUNT_REGISTRY_MASK)
#define TIMESTAMP                       (INT_TIMESTAMP & COUNT_REGISTRY_MASK)
#define COUNT_FLOWS                     (COUNT_INT_FLOWS & COUNT_REGISTRY_MASK)
#define COUNT_SUM_MAC                   (COUNT_INT_SUM_MAC & COUNT_REGISTRY_MASK)
#define COUNT_CLASS                     (COUNT_INT_CLASS & COUNT_REGISTRY_MASK)
#define COUNT_COUNTERS                  (COUNT_INT_COUNTERS & COUNT_REGISTRY_MASK)
#define COUNT_PAYLOAD                   (COUNT_INT_PAYLOAD & COUNT_REGISTRY_MASK)
#define COUNT_TCPFLAGS                  (COUNT_INT_TCPFLAGS & COUNT_REGISTRY_MASK)
#define COUNT_STD_COMM                  (COUNT_INT_STD_COMM & COUNT_REGISTRY_MASK)
#define COUNT_EXT_COMM                  (COUNT_INT_EXT_COMM & COUNT_REGISTRY_MASK)
#define COUNT_AS_PATH                   (COUNT_INT_AS_PATH & COUNT_REGISTRY_MASK)
#define COUNT_LOCAL_PREF                (COUNT_INT_LOCAL_PREF & COUNT_REGISTRY_MASK)
#define COUNT_MED                       (COUNT_INT_MED & COUNT_REGISTRY_MASK)
#define COUNT_PEER_SRC_AS               (COUNT_INT_PEER_SRC_AS & COUNT_REGISTRY_MASK)
#define COUNT_PEER_DST_AS               (COUNT_INT_PEER_DST_AS & COUNT_REGISTRY_MASK)
#define COUNT_PEER_SRC_IP               (COUNT_INT_PEER_SRC_IP & COUNT_REGISTRY_MASK)
#define COUNT_PEER_DST_IP               (COUNT_INT_PEER_DST_IP & COUNT_REGISTRY_MASK)
#define COUNT_TAG2                      (COUNT_INT_TAG2 & COUNT_REGISTRY_MASK)
#define COUNT_SRC_AS_PATH               (COUNT_INT_SRC_AS_PATH & COUNT_REGISTRY_MASK)
#define COUNT_SRC_STD_COMM              (COUNT_INT_SRC_STD_COMM & COUNT_REGISTRY_MASK)
#define COUNT_SRC_EXT_COMM              (COUNT_INT_SRC_EXT_COMM & COUNT_REGISTRY_MASK)
#define COUNT_SRC_LOCAL_PREF            (COUNT_INT_SRC_LOCAL_PREF & COUNT_REGISTRY_MASK)
#define COUNT_SRC_MED                   (COUNT_INT_SRC_MED & COUNT_REGISTRY_MASK)
#define COUNT_MPLS_VPN_RD               (COUNT_INT_MPLS_VPN_RD & COUNT_REGISTRY_MASK)
#define COUNT_IN_IFACE                  (COUNT_INT_IN_IFACE & COUNT_REGISTRY_MASK)
#define COUNT_OUT_IFACE                 (COUNT_INT_OUT_IFACE & COUNT_REGISTRY_MASK)
#define COUNT_SRC_NMASK                 (COUNT_INT_SRC_NMASK & COUNT_REGISTRY_MASK)
#define COUNT_DST_NMASK                 (COUNT_INT_DST_NMASK & COUNT_REGISTRY_MASK)
#define COUNT_COS                       (COUNT_INT_COS & COUNT_REGISTRY_MASK)
#define COUNT_ETHERTYPE                 (COUNT_INT_ETHERTYPE & COUNT_REGISTRY_MASK)

/* external: second registry, ie. what_to_count_2, aggregation_2, etc. */
#define COUNT_SAMPLING_RATE		(COUNT_INT_SAMPLING_RATE & COUNT_REGISTRY_MASK)
#define COUNT_SRC_HOST_COUNTRY		(COUNT_INT_SRC_HOST_COUNTRY & COUNT_REGISTRY_MASK)
#define COUNT_DST_HOST_COUNTRY		(COUNT_INT_DST_HOST_COUNTRY & COUNT_REGISTRY_MASK)
#define COUNT_PKT_LEN_DISTRIB		(COUNT_INT_PKT_LEN_DISTRIB & COUNT_REGISTRY_MASK)
#define COUNT_POST_NAT_SRC_HOST		(COUNT_INT_POST_NAT_SRC_HOST & COUNT_REGISTRY_MASK)
#define COUNT_POST_NAT_DST_HOST		(COUNT_INT_POST_NAT_DST_HOST & COUNT_REGISTRY_MASK)
#define COUNT_POST_NAT_SRC_PORT		(COUNT_INT_POST_NAT_SRC_PORT & COUNT_REGISTRY_MASK)
#define COUNT_POST_NAT_DST_PORT		(COUNT_INT_POST_NAT_DST_PORT & COUNT_REGISTRY_MASK)	
#define COUNT_NAT_EVENT			(COUNT_INT_NAT_EVENT & COUNT_REGISTRY_MASK)
#define COUNT_TIMESTAMP_START		(COUNT_INT_TIMESTAMP_START & COUNT_REGISTRY_MASK)
#define COUNT_TIMESTAMP_END		(COUNT_INT_TIMESTAMP_END & COUNT_REGISTRY_MASK)
#define COUNT_TIMESTAMP_ARRIVAL		(COUNT_INT_TIMESTAMP_ARRIVAL & COUNT_REGISTRY_MASK)
#define COUNT_MPLS_LABEL_TOP		(COUNT_INT_MPLS_LABEL_TOP & COUNT_REGISTRY_MASK)
#define COUNT_MPLS_LABEL_BOTTOM		(COUNT_INT_MPLS_LABEL_BOTTOM & COUNT_REGISTRY_MASK)
#define COUNT_MPLS_STACK_DEPTH		(COUNT_INT_MPLS_STACK_DEPTH & COUNT_REGISTRY_MASK)
#define COUNT_LABEL			(COUNT_INT_LABEL & COUNT_REGISTRY_MASK)
#define COUNT_EXPORT_PROTO_SEQNO	(COUNT_INT_EXPORT_PROTO_SEQNO & COUNT_REGISTRY_MASK)
#define COUNT_EXPORT_PROTO_VERSION	(COUNT_INT_EXPORT_PROTO_VERSION & COUNT_REGISTRY_MASK)
#define COUNT_CUSTOM_PRIMITIVES		(COUNT_INT_CUSTOM_PRIMITIVES & COUNT_REGISTRY_MASK)
/* PRIMITIVES DEFINITION: END */

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

#define COUNT_SECONDLY		0x00000001
#define COUNT_MINUTELY          0x00000002
#define COUNT_HOURLY            0x00000004
#define COUNT_DAILY             0x00000008
#define COUNT_WEEKLY		0x00000010
#define COUNT_MONTHLY		0x00000020

#define WANT_STATS			0x00000001
#define WANT_ERASE			0x00000002
#define WANT_STATUS			0x00000004
#define WANT_COUNTER			0x00000008
#define WANT_MATCH			0x00000010
#define WANT_RESET			0x00000020
#define WANT_CLASS_TABLE		0x00000040
#define WANT_PKT_LEN_DISTRIB_TABLE	0x00000080
#define WANT_LOCK_OP			0x00000100
#define WANT_CUSTOM_PRIMITIVES_TABLE	0x00000200
#define WANT_ERASE_LAST_TSTAMP		0x00000400

#define PIPE_TYPE_METADATA	0x00000001
#define PIPE_TYPE_PAYLOAD	0x00000002
#define PIPE_TYPE_EXTRAS	0x00000004
#define PIPE_TYPE_BGP		0x00000008
#define PIPE_TYPE_MSG		0x00000010
#define PIPE_TYPE_NAT		0x00000020
#define PIPE_TYPE_MPLS		0x00000040
#define PIPE_TYPE_VLEN		0x00000080

#define CHLD_WARNING		0x00000001
#define CHLD_ALERT		0x00000002

#define BGP_SRC_PRIMITIVES_KEEP	0x00000001
#define BGP_SRC_PRIMITIVES_MAP	0x00000002
#define BGP_SRC_PRIMITIVES_BGP	0x00000004

#define BGP_ASPATH_HASH_PATHID	0x00000000

#define PRINT_OUTPUT_FORMATTED	0x00000001
#define PRINT_OUTPUT_CSV	0x00000002
#define PRINT_OUTPUT_JSON	0x00000004
#define PRINT_OUTPUT_EVENT	0x00000008
#define PRINT_OUTPUT_AVRO  	0x00000010

#define DIRECTION_UNKNOWN	0x00000000
#define DIRECTION_IN		0x00000001
#define DIRECTION_OUT		0x00000002
#define DIRECTION_TAG		0x00000004
#define DIRECTION_TAG2		0x00000008

#define IFINDEX_STATIC		0x00000001
#define IFINDEX_TAG		0x00000002
#define IFINDEX_TAG2		0x00000004

#define CUSTOM_PRIMITIVE_TYPE_UINT	1
#define CUSTOM_PRIMITIVE_TYPE_HEX	2
#define CUSTOM_PRIMITIVE_TYPE_STRING	3
#define CUSTOM_PRIMITIVE_TYPE_IP	4
#define CUSTOM_PRIMITIVE_TYPE_MAC	5
#define CUSTOM_PRIMITIVE_TYPE_RAW	6

#define FUNC_TYPE_NULL			0
#define FUNC_TYPE_BGP			1
#define FUNC_TYPE_BMP			2
#define FUNC_TYPE_SFLOW_COUNTER		3
#define FUNC_TYPE_TELEMETRY		4
#define FUNC_TYPE_MAX			5

typedef u_int32_t pm_class_t;
typedef u_int64_t pm_id_t;
typedef u_int64_t pm_cfgreg_t;

typedef struct {
  union {
    u_int32_t id;
    char str[PM_COUNTRY_T_STRLEN];
  };
} pm_country_t;

typedef struct {
  pm_cfgreg_t type;
  u_int32_t len;
} pm_label_t;

/* one-off: pt_ structures should all be defined in pretag.h */
typedef struct {
  u_int32_t len;
  char *val;
} pt_label_t;

typedef struct {
  u_int8_t set;
  int n;
} s_int_t;

typedef struct {
  u_int8_t set;
  u_int8_t n;
} s_uint8_t;

typedef struct {
  u_int8_t set;
  u_int16_t n;
} s_uint16_t;

#if defined HAVE_64BIT_COUNTERS
typedef u_int64_t pm_counter_t;
#else
typedef u_int32_t pm_counter_t;
#endif

/* Keep common NF_AS and NF_NET values aligned, ie. NF_[NET|AS]_KEEP == 0x00000001 */
#define NF_AS_COMPAT    0x00000000 /* Unused */
#define NF_AS_KEEP	0x00000001 /* Keep AS numbers in Sflow or NetFlow packets */
#define NF_AS_NEW 	0x00000002 /* ignore ASN from NetFlow and generate from network files */
#define NF_AS_BGP	0x00000004 /* ignore ASN from NetFlow and generate from BGP peerings */
#define NF_AS_FALLBACK	0x80000000 /* Fallback flag */

#define NF_NET_COMPAT   0x00000000 /* Backward compatibility selection */
#define NF_NET_KEEP     0x00000001 /* Determine IP network prefixes from sFlow or NetFlow data */
#define NF_NET_NEW      0x00000002 /* Determine IP network prefixes from network files */
#define NF_NET_BGP      0x00000004 /* Determine IP network prefixes from BGP peerings */
#define NF_NET_STATIC   0x00000008 /* Determine IP network prefixes from static mask */
#define NF_NET_IGP	0x00000010 /* Determine IP network prefixes from IGP */
#define NF_NET_FALLBACK	0x80000000 /* Fallback flag */

/* flow type */
#define NF9_FTYPE_TRAFFIC		1  /* temporary: re-coding needed */
#define NF9_FTYPE_TRAFFIC_IPV6		1
#define NF9_FTYPE_IPV4                  1
#define NF9_FTYPE_IPV6                  2
#define NF9_FTYPE_VLAN                  5
#define NF9_FTYPE_VLAN_IPV4             6
#define NF9_FTYPE_VLAN_IPV6             7 
#define NF9_FTYPE_MPLS                  10
#define NF9_FTYPE_MPLS_IPV4             11
#define NF9_FTYPE_MPLS_IPV6             12
#define NF9_FTYPE_VLAN_MPLS             15      
#define NF9_FTYPE_VLAN_MPLS_IPV4        16
#define NF9_FTYPE_VLAN_MPLS_IPV6        17
#define NF9_FTYPE_EVENT			100 /* temporary: re-coding needed */
#define NF9_FTYPE_NAT_EVENT             100
#define NF9_FTYPE_OPTION		200

/* Packet pointers indexes */
#define CUSTOM_PRIMITIVE_PACKET_PTR	0
#define CUSTOM_PRIMITIVE_MAC_PTR	1
#define CUSTOM_PRIMITIVE_VLAN_PTR	2
#define CUSTOM_PRIMITIVE_MPLS_PTR	3
#define CUSTOM_PRIMITIVE_L3_PTR		4
#define CUSTOM_PRIMITIVE_L4_PTR		5
#define CUSTOM_PRIMITIVE_PAYLOAD_PTR	6
#define CUSTOM_PRIMITIVE_MAX_PPTRS_IDX	7
