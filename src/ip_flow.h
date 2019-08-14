/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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

#ifndef _IP_FLOW_H_
#define _IP_FLOW_H_

/* defines */
#define FLOW_TABLE_HASHSZ 256 
#define FLOW_GENERIC_LIFETIME 60 
#define FLOW_TCPSYN_LIFETIME 60 
#define FLOW_TCPEST_LIFETIME 432000
#define FLOW_TCPFIN_LIFETIME 30 
#define FLOW_TCPRST_LIFETIME 10 
#define FLOW_TABLE_PRUNE_INTERVAL 3600 
#define FLOW_TABLE_EMER_PRUNE_INTERVAL 60
#define DEFAULT_FLOW_BUFFER_SIZE 16384000 /* 16 Mb */

struct context_chain {
  char *protocol;
  void *data;
  struct context_chain *next;
};

/* structures */
struct ip_flow_common {
  /*
     [0] = forward flow data
     [1] = reverse flow data
  */
  u_int16_t bucket;
  struct timeval last[2];
  u_int32_t last_tcp_seq;
  u_int8_t tcp_flags[2];
  u_int8_t proto;
  /* classifier hooks */
  pm_class_t class[2]; 
  struct class_st cst[2]; 
  struct context_chain *cc[2];
  /* conntrack hooks */
  void (*conntrack_helper)(time_t, struct packet_ptrs *);
};

struct ip_flow {
  struct ip_flow_common cmn;
  u_int32_t ip_src;
  u_int32_t ip_dst;
  u_int16_t port_src;
  u_int16_t port_dst;
  char *bgp_src; /* pointer to bgp_node structure for source prefix, if any */
  char *bgp_dst; /* pointer to bgp_node structure for destination prefix, if any */
  struct ip_flow *lru_next;
  struct ip_flow *lru_prev;
  struct ip_flow *next;
  struct ip_flow *prev;
};

struct flow_lru_l {
  struct ip_flow *root;
  struct ip_flow *last;
};

struct ip_flow6 {
  struct ip_flow_common cmn;
  u_int32_t ip_src[4];
  u_int32_t ip_dst[4];
  u_int16_t port_src;
  u_int16_t port_dst;
  struct ip_flow6 *lru_next;
  struct ip_flow6 *lru_prev;
  struct ip_flow6 *next;
  struct ip_flow6 *prev;
};

struct flow_lru_l6 {
  struct ip_flow6 *root;
  struct ip_flow6 *last;
};

/* prototypes */
extern void init_ip_flow_handler(); /* wrapper */ 
extern void init_ip4_flow_handler(); 
extern void ip_flow_handler(struct packet_ptrs *); 
extern void find_flow(struct timeval *, struct packet_ptrs *); 
extern void create_flow(struct timeval *, struct ip_flow *, u_int8_t, unsigned int, struct packet_ptrs *, struct pm_iphdr *, struct pm_tlhdr *, unsigned int); 
extern void prune_old_flows(struct timeval *); 

extern unsigned int hash_flow(u_int32_t, u_int32_t, u_int16_t, u_int16_t, u_int8_t);
extern unsigned int normalize_flow(u_int32_t *, u_int32_t *, u_int16_t *, u_int16_t *);
extern unsigned int is_expired(struct timeval *, struct ip_flow_common *);
extern unsigned int is_expired_uni(struct timeval *, struct ip_flow_common *, unsigned int);
extern void evaluate_tcp_flags(struct timeval *, struct packet_ptrs *, struct ip_flow_common *, unsigned int);
extern void clear_tcp_flow_cmn(struct ip_flow_common *, unsigned int);

extern void init_ip6_flow_handler();
extern void ip_flow6_handler(struct packet_ptrs *);
extern unsigned int hash_flow6(u_int32_t, struct in6_addr *, struct in6_addr *);
extern unsigned int normalize_flow6(struct in6_addr *, struct in6_addr *, u_int16_t *, u_int16_t *);
extern void find_flow6(struct timeval *, struct packet_ptrs *);
extern void create_flow6(struct timeval *, struct ip_flow6 *, u_int8_t, unsigned int, struct packet_ptrs *, struct ip6_hdr *, struct pm_tlhdr *, unsigned int);
extern void prune_old_flows6(struct timeval *); 

/* global vars */
extern struct ip_flow **ip_flow_table;
extern struct flow_lru_l flow_lru_list;

extern struct ip_flow6 **ip_flow_table6;
extern struct flow_lru_l6 flow_lru_list6;

#endif /* _IP_FLOW_H_ */
