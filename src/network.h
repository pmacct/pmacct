/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2009 by Paolo Lucente
*/

#include "../include/extract.h"
#include "../include/llc.h"
#include "../include/sll.h"
#include "../include/ieee802_11.h"
#include "../include/fddi.h"

#if defined ENABLE_IPV6
#include "../include/ip6.h"
#include "../include/ah.h"
#endif

#define min(a,b) ((a)>(b)?(b):(a))

#define ETH_ADDR_LEN    	6               /* Octets in one ethernet addr   */
#define ETHER_HDRLEN    	14
#define ETHERMTU		1500
#define IEEE8021Q_TAGLEN	4
#define PPP_TAGLEN              2
#define MAX_MCAST_GROUPS	20
#define ROUTING_SEGMENT_MAX	16

/* 10Mb/s ethernet header */
struct eth_header
{
  u_int8_t  ether_dhost[ETH_ADDR_LEN];      /* destination eth addr */
  u_int8_t  ether_shost[ETH_ADDR_LEN];      /* source ether addr    */
  u_int16_t ether_type;                     /* packet type ID field */
};

#define TR_RIF_LENGTH(trp)		((ntohs((trp)->token_rcf) & 0x1f00) >> 8)
#define TR_IS_SOURCE_ROUTED(trp)	((trp)->token_shost[0] & 0x80)
#define TOKEN_FC_LLC			1

struct token_header {
        u_int8_t  token_ac;
        u_int8_t  token_fc;
        u_int8_t  token_dhost[ETH_ADDR_LEN];
        u_int8_t  token_shost[ETH_ADDR_LEN];
        u_int16_t token_rcf;
        u_int16_t token_rseg[ROUTING_SEGMENT_MAX];
};


/* Ethernet protocol ID's */
#define ETHERTYPE_IP		0x0800          /* IP */
#define ETHERTYPE_IPV6          0x86dd		/* IPv6 */
#define ETHERTYPE_PPPOE         0x8864          /* pppoe (session stage) */
#define ETHERTYPE_8021Q		0x8100          /* 802.1Q */
#define ETHERTYPE_MPLS          0x8847		/* MPLS */
#define ETHERTYPE_MPLS_MULTI    0x8848		/* MPLS */

/* PPP protocol definitions */
#define PPP_HDRLEN      4       /* octets for standard ppp header */
#define PPPOE_HDRLEN	6	/* octets for standard pppoe header  */
#define PPP_IP          0x0021  /* Internet Protocol */
#define PPP_IPV6	0x0057  /* IPv6 */
#define PPP_MPLS_UCAST  0x0281  /* rfc 3032 */
#define PPP_MPLS_MCAST  0x0283  /* rfc 3022 */
#define PPP_ADDRESS     0xff    /* The address byte value */
#define PPP_CONTROL     0x03    /* The control byte value */

/* CHDLC protocol definitions */
#define CHDLC_HDRLEN    4

/* additional protocol definitions */
#ifndef IPPROTO_HOPOPTS
#define IPPROTO_HOPOPTS         0               /* IPv6 hop-by-hop options */
#endif
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6            41
#endif
#ifndef IPPROTO_ROUTING
#define IPPROTO_ROUTING         43              /* IPv6 routing header */
#endif
#ifndef IPPROTO_FRAGMENT
#define IPPROTO_FRAGMENT        44              /* IPv6 fragmentation header */
#endif
#ifndef IPPROTO_ESP
#define IPPROTO_ESP             50              /* SIPP Encap Sec. Payload */
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH              51              /* SIPP Auth Header */
#endif
#ifndef IPPROTO_NONE
#define IPPROTO_NONE            59              /* IPv6 no next header */
#endif
#ifndef IPPROTO_DSTOPTS
#define IPPROTO_DSTOPTS         60              /* IPv6 destination options */
#endif
#ifndef IPPROTO_IPCOMP
#define IPPROTO_IPCOMP          108
#endif
#ifndef IPPROTO_MOBILITY
#define IPPROTO_MOBILITY        135
#endif

struct my_iphdr
{
   u_int8_t     ip_vhl;         /* header length, version */
#define IP_V(ip)        (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)       ((ip)->ip_vhl & 0x0f)
   u_int8_t     ip_tos;         /* type of service */
   u_int16_t    ip_len;         /* total length */
   u_int16_t    ip_id;          /* identification */
   u_int16_t    ip_off;         /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
   u_int8_t     ip_ttl;         /* time to live */
   u_int8_t     ip_p;           /* protocol */
   u_int16_t    ip_sum;         /* checksum */
   struct in_addr ip_src;	/* source and destination addresses */
   struct in_addr ip_dst; 
};

typedef u_int32_t tcp_seq;
struct my_tcphdr
{
    u_int16_t th_sport;         /* source port */
    u_int16_t th_dport;         /* destination port */
    tcp_seq th_seq;             /* sequence number */
    tcp_seq th_ack;             /* acknowledgement number */
#if defined IM_LITTLE_ENDIAN
    u_int8_t th_x2:4;           /* (unused) */
    u_int8_t th_off:4;          /* data offset */
#endif
#if defined IM_BIG_ENDIAN
    u_int8_t th_off:4;          /* data offset */
    u_int8_t th_x2:4;           /* (unused) */
#endif
    u_int8_t th_flags;
#define TH_FIN        0x01
#define TH_SYN        0x02
#define TH_RST        0x04
#define TH_PUSH       0x08
#define TH_ACK        0x10
#define TH_URG        0x20
    u_int16_t th_win;           /* window */
    u_int16_t th_sum;           /* checksum */
    u_int16_t th_urp;           /* urgent pointer */
};

struct my_tlhdr {
   u_int16_t	src_port;	/* source and destination ports */
   u_int16_t	dst_port;
};

/* typedefs */
typedef u_int32_t as_t;
typedef u_int16_t as16_t;


/* class status */
struct class_st {
   u_int8_t tentatives;	
   struct timeval stamp;	/* accumulator timestamp */
   u_int32_t ba;		/* bytes accumulator */
   u_int16_t pa;		/* packet accumulator */
   u_int8_t fa;			/* flow accumulator */
};

struct packet_ptrs {
  struct pcap_pkthdr *pkthdr; /* ptr to header structure passed by libpcap */
  u_char *f_agent; /* ptr to flow export agent */ 
  u_char *f_header; /* ptr to NetFlow packet header */ 
  u_char *f_data; /* ptr to NetFlow data */ 
  u_char *f_tpl; /* ptr to NetFlow V9 template */
  u_char *f_status; /* ptr to status table entry */
  u_char *idtable; /* ptr to pretag table map */
  u_char *bpas_table; /* ptr to bgp_peer_as_src table map */
  u_char *bta_table; /* ptr to bgp_to_agent table map */
  u_char *packet_ptr; /* ptr to the whole packet */
  u_char *mac_ptr; /* ptr to mac addresses */
  u_int16_t l3_proto; /* layer-3 protocol: IPv4, IPv6 */
  int (*l3_handler)(register struct packet_ptrs *); /* layer-3 protocol handler */
  u_int16_t l4_proto; /* layer-4 protocol */
  pm_id_t tag; /* pre tag id */
  pm_id_t tag2; /* pre tag id2 */
  pm_id_t bpas; /* bgp_peer_as_src */
  pm_id_t bta; /* bgp_to_agent */
  char *bgp_src; /* pointer to bgp_node structure for source prefix, if any */  
  char *bgp_dst; /* pointer to bgp_node structure for destination prefix, if any */ 
  char *bgp_peer; /* record BGP peer's Router-ID */
  char *bgp_nexthop; /* record BGP next-hop in case of follow-up */
  u_int16_t pf; /* pending fragments or packets */
  u_int8_t new_flow; /* pmacctd flows: part of a new flow ? */
  u_int8_t tcp_flags; /* pmacctd flows: TCP packet flags; URG, PUSH filtered out */ 
  u_char *vlan_ptr; /* ptr to vlan id */
  u_char *mpls_ptr; /* ptr to base MPLS label */
  u_char *iph_ptr; /* ptr to ip header */
  u_char *tlh_ptr; /* ptr to transport level protocol header */
  u_char *payload_ptr; /* classifiers: ptr to packet payload */
  pm_class_t class; /* classifiers: class id */
  struct class_st cst; /* classifiers: class status */
  u_int8_t shadow; /* 0=the packet is being distributed for the 1st time
		      1=the packet is being distributed for the 2nd+ time */
};

struct host_addr {
  u_int8_t family;
  union {
    struct in_addr ipv4;
#if defined ENABLE_IPV6
    struct in6_addr ipv6;
#endif
  } address;
};

struct pkt_primitives {
#if defined (HAVE_L2)
  u_int8_t eth_dhost[ETH_ADDR_LEN];
  u_int8_t eth_shost[ETH_ADDR_LEN];
  u_int16_t vlan_id;
#endif
  struct host_addr src_ip;
  struct host_addr dst_ip;
  as_t src_as;
  as_t dst_as;
  u_int16_t src_port;
  u_int16_t dst_port;
  u_int8_t tos;
  u_int8_t proto;
  pm_id_t id;
  pm_id_t id2;
  pm_class_t class;
};

struct pkt_data {
  struct pkt_primitives primitives;
  pm_counter_t pkt_len;
  pm_counter_t pkt_num;
  pm_counter_t flo_num;
  u_int32_t tcp_flags; /* XXX */
  u_int32_t time_start;
  u_int32_t time_end;
  struct class_st cst;
};

struct pkt_payload {
  u_int16_t cap_len;
  pm_counter_t sample_pool;
  pm_counter_t pkt_len;
  pm_counter_t pkt_num;
  u_int32_t time_start;
  pm_class_t class;
  pm_id_t tag;
  pm_id_t tag2;
  struct host_addr src_ip;
  struct host_addr dst_ip;
};

struct pkt_extras {
  u_int8_t tcp_flags;
  u_int32_t mpls_top_label;
};

/* START: BGP section */
#include "bgp/bgp.h"
#include "bgp/bgp_aspath.h"
#include "bgp/bgp_community.h"
#define MAX_BGP_STD_COMMS       96
#define MAX_BGP_EXT_COMMS       96
#define MAX_BGP_ASPATH          128

struct pkt_bgp_primitives {
  as_t peer_src_as;
  as_t peer_dst_as;
  struct host_addr peer_src_ip;
  struct host_addr peer_dst_ip;
  char std_comms[MAX_BGP_STD_COMMS];
  char ext_comms[MAX_BGP_EXT_COMMS];
  char as_path[MAX_BGP_ASPATH];
  u_int32_t local_pref;
  u_int32_t med;
};
/* END: BGP section */

struct packet_ptrs_vector {
  struct packet_ptrs v4;
  struct packet_ptrs vlan4;
  struct packet_ptrs mpls4;
  struct packet_ptrs vlanmpls4;
#if defined ENABLE_IPV6
  struct packet_ptrs v6;
  struct packet_ptrs vlan6;
  struct packet_ptrs mpls6;
  struct packet_ptrs vlanmpls6;
#endif
};

struct hosts_table {
  unsigned short int num;
  struct host_addr table[MAX_MAP_ENTRIES];
};

