/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2013 by Paolo Lucente
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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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
#define ETHER_JUMBO_MTU		9000
#define IEEE8021Q_TAGLEN	4
#define IEEE8021AH_LEN		10
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

#define CHDLC_MCAST_ADDR	0x8F
#define CHDLC_FIXED_CONTROL	0x00
/* CHDLC header */
struct chdlc_header {
  u_int8_t address;
  u_int8_t control;
  u_int16_t protocol;
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
#define ETHERTYPE_8021AH        0x88A8		/* 802.1ah */
#define ETHERTYPE_ISO		0xFEFE		/* OSI */
#define ETHERTYPE_GRE_ISO	0x00FE		/* OSI over GRE */

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

/* For TCP_MD5SIG socket option.  */
#ifndef TCP_MD5SIG_MAXKEYLEN 
#define TCP_MD5SIG_MAXKEYLEN    80
#endif

#ifndef TCP_MD5SIG
#define TCP_MD5SIG       14
#endif

struct my_tcp_md5sig
{
  struct sockaddr_storage tcpm_addr;            /* Address associated.  */
  u_int16_t     __tcpm_pad1;                    /* Zero.  */
  u_int16_t     tcpm_keylen;                    /* Key length.  */
  u_int32_t     __tcpm_pad2;                    /* Zero.  */
  u_int8_t      tcpm_key[TCP_MD5SIG_MAXKEYLEN]; /* Key (binary).  */
};

struct my_udphdr
{
  u_int16_t uh_sport;           /* source port */
  u_int16_t uh_dport;           /* destination port */
  u_int16_t uh_ulen;            /* udp length */
  u_int16_t uh_sum;             /* udp checksum */
};

struct my_icmphdr
{
  u_int8_t type;                /* message type */
  u_int8_t code;                /* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t id;
      u_int16_t sequence;
    } echo;                     /* echo datagram */
    u_int32_t   gateway;        /* gateway address */
    struct
    {
      u_int16_t __unused;
      u_int16_t mtu;
    } frag;                     /* path mtu discovery */
  } un;
};

struct my_tlhdr {
   u_int16_t	src_port;	/* source and destination ports */
   u_int16_t	dst_port;
};

struct my_gtphdr {
    u_int8_t flags;
    u_int8_t message;
    u_int16_t length;
};

/* typedefs */
typedef u_int32_t as_t;
typedef u_int16_t as16_t;

#define RD_TYPE_AS      0
#define RD_TYPE_IP      1
#define RD_TYPE_AS4     2

struct rd_as
{
  u_int16_t type;
  u_int16_t as;
  u_int32_t val;
};

struct rd_ip
{
  u_int16_t type;
  struct in_addr ip;
  u_int16_t val;
};

struct rd_as4
{
  u_int16_t type;
  as_t as;
  u_int32_t val;
};

/* Picking one of the three structures as rd_t for simplicity */
typedef struct rd_as rd_t;

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
  u_char *f_status_g; /* ptr to status table entry. global per f_agent */
  u_char *idtable; /* ptr to pretag table map */
  u_char *bpas_table; /* ptr to bgp_peer_as_src table map */
  u_char *blp_table; /* ptr to bgp_src_local_pref table map */
  u_char *bmed_table; /* ptr to bgp_src_med table map */
  u_char *bta_table; /* ptr to bgp_to_agent table map */
  u_char *bitr_table; /* ptr to bgp_iface_to_rd table map */
  u_char *sampling_table; /* ptr to sampling_map table map */
  u_char *packet_ptr; /* ptr to the whole packet */
  u_char *mac_ptr; /* ptr to mac addresses */
  u_int16_t l3_proto; /* layer-3 protocol: IPv4, IPv6 */
  int (*l3_handler)(register struct packet_ptrs *); /* layer-3 protocol handler */
  u_int16_t l4_proto; /* layer-4 protocol */
  u_int8_t flow_type; /* Flow, NAT event, etc. */
  pm_id_t tag; /* pre tag id */
  pm_id_t tag2; /* pre tag id2 */
  pm_id_t bpas; /* bgp_peer_as_src */
  pm_id_t blp; /* bgp_src_local_pref */
  pm_id_t bmed; /* bgp_src_med */
  u_int16_t bta_af; /* bgp_to_agent address family */
  pm_id_t bta; /* bgp_to_agent */
  pm_id_t bta2; /* bgp_to_agent (cont.d: 64bits more for IPv6 addresses) */
  pm_id_t bitr; /* bgp_iface_to_rd */
  pm_id_t st; /* sampling_map */
  s_uint8_t set_tos; /* pretag map: set_tos feature */
  char *bgp_src; /* pointer to bgp_node structure for source prefix, if any */  
  char *bgp_dst; /* pointer to bgp_node structure for destination prefix, if any */ 
  char *bgp_src_info; /* pointer to bgp_info structure for source prefix, if any */  
  char *bgp_dst_info; /* pointer to bgp_info structure for destination prefix, if any */ 
  char *bgp_peer; /* record BGP peer's Router-ID */
  char *bgp_nexthop_info; /* record bgp_info of BGP next-hop in case of follow-up */
  char *igp_src; /* pointer to IGP node structure for source prefix, if any */
  char *igp_dst; /* pointer to IGP node structure for destination prefix, if any */
  char *igp_src_info; /* pointer to IGP node info structure for source prefix, if any */
  char *igp_dst_info; /* pointer to IGP node info structure for destination prefix, if any */
  u_int8_t lm_mask_src; /* Longest match for source prefix (network mask bits) */
  u_int8_t lm_mask_dst; /* Longest match for destination prefix (network mask bits) */
  u_int8_t lm_method_src; /* Longest match for source prefix (method: BGP, IGP, etc.) */
  u_int8_t lm_method_dst; /* Longest match for destination prefix (method: BGP, IGP, etc.) */
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
  u_int16_t ifindex_in;  /* input ifindex; only used by ULOG for the time being */
  u_int16_t ifindex_out; /* output ifindex; only used by ULOG for the time being */
  u_int8_t tun_stack; /* tunnelling stack */
  u_int8_t tun_layer; /* tunnelling layer count */
  u_int32_t sample_type; /* sFlow sample type */
  u_int32_t seqno; /* sFlow/NetFlow sequence number */
  u_int16_t f_len; /* sFlow/NetFlow payload length */
  u_int8_t renormalized; /* Is it renormalized yet ? */
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
  u_int8_t cos;
  u_int16_t etype;
#endif
  struct host_addr src_ip;
  struct host_addr dst_ip;
  u_int8_t src_nmask;
  u_int8_t dst_nmask;
  as_t src_as;
  as_t dst_as;
  u_int16_t src_port;
  u_int16_t dst_port;
  u_int8_t tos;
  u_int8_t proto;
  u_int32_t ifindex_in;
  u_int32_t ifindex_out;
#if defined (WITH_GEOIP)
  pm_country_t src_ip_country;
  pm_country_t dst_ip_country;
#endif
  pm_id_t id;
  pm_id_t id2;
  pm_class_t class;
  u_int32_t sampling_rate;
  u_int16_t pkt_len_distrib;
};

struct pkt_data {
  struct pkt_primitives primitives;
  pm_counter_t pkt_len;
  pm_counter_t pkt_num;
  pm_counter_t flo_num;
  u_int8_t flow_type;
  u_int32_t tcp_flags; /* XXX */
  struct timeval time_start;
  struct timeval time_end;
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
  as_t src_as;
  as_t dst_as;
  u_int16_t ifindex_in;
  u_int16_t ifindex_out;
  u_int8_t src_nmask;
  u_int8_t dst_nmask;
  u_int16_t vlan;
  u_int8_t priority;
  struct host_addr bgp_next_hop;
};

struct pkt_extras {
  u_int8_t tcp_flags;
  u_int32_t mpls_top_label;
  struct host_addr bgp_next_hop;
};

// #define PKT_MSG_SIZE 1550
#define PKT_MSG_SIZE 10000
struct pkt_msg {
  struct sockaddr agent;
  u_int32_t seqno;
  u_int16_t len;
  u_char payload[PKT_MSG_SIZE];
  pm_id_t id;
  pm_id_t id2;
  u_int16_t pad;
};

/* START: BGP section */
#define MAX_BGP_STD_COMMS       96
#define MAX_BGP_EXT_COMMS       96
#define MAX_BGP_ASPATH          128

struct extra_primitives {
  u_int16_t off_pkt_bgp_primitives;
  u_int16_t off_pkt_nat_primitives;
};

struct primitives_ptrs {
  struct pkt_data *data;
  struct pkt_bgp_primitives *pbgp;
  struct pkt_nat_primitives *pnat;
};

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
  char src_std_comms[MAX_BGP_STD_COMMS];
  char src_ext_comms[MAX_BGP_EXT_COMMS];
  char src_as_path[MAX_BGP_ASPATH];
  u_int32_t src_local_pref;
  u_int32_t src_med;
  rd_t mpls_vpn_rd;
  u_int32_t pad;
};

struct pkt_nat_primitives {
  struct host_addr post_nat_src_ip;
  struct host_addr post_nat_dst_ip;
  u_int16_t post_nat_src_port;
  u_int16_t post_nat_dst_port;
  u_int8_t nat_event;
  struct timeval timestamp_start; /* XXX: clean-up: to be moved in a separate structure */
  struct timeval timestamp_end; /* XXX: clean-up: to be moved in a separate structure */
};

/* same as above but pointers in place of strings */
struct cache_bgp_primitives {
  as_t peer_src_as;
  as_t peer_dst_as;
  struct host_addr peer_src_ip;
  struct host_addr peer_dst_ip;
  char *std_comms;
  char *ext_comms;
  char *as_path;
  u_int32_t local_pref;
  u_int32_t med;
  char *src_std_comms;
  char *src_ext_comms;
  char *src_as_path;
  u_int32_t src_local_pref;
  u_int32_t src_med;
  rd_t mpls_vpn_rd;
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
  short int num;
  struct host_addr table[MAX_MAP_ENTRIES];
};

struct bgp_md5_table_entry {
  struct host_addr addr;
  char key[TCP_MD5SIG_MAXKEYLEN];
};

struct bgp_md5_table {
  short int num;
  struct bgp_md5_table_entry table[BGP_MD5_MAP_ENTRIES];
};

#define TUNNEL_PROTO_STRING	16
#define TUNNEL_REGISTRY_STACKS	9 /* MAX + 1 */
#define TUNNEL_REGISTRY_ENTRIES 4 
typedef int (*tunnel_func)(register struct packet_ptrs *);

struct tunnel_handler {
  tunnel_func tf;
  u_int8_t proto;
  u_int16_t port;
};

typedef int (*tunnel_configurator)(struct tunnel_handler *, char *);

struct tunnel_entry {
  u_char type[TUNNEL_PROTO_STRING];
  tunnel_func tf;
  tunnel_configurator tc;
};

struct tunnel_handler tunnel_registry[TUNNEL_REGISTRY_STACKS][TUNNEL_REGISTRY_ENTRIES];
