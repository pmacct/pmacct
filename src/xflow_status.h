/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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

#ifndef XFLOW_STATUS_H
#define XFLOW_STATUS_H

/* defines */
#define XFLOW_RESET_BOUNDARY 50
#define XFLOW_STATUS_TABLE_SZ 9973
#define XFLOW_STATUS_TABLE_MAX_ENTRIES 100000

/* structures */
struct xflow_status_entry_counters
{
  // XXX: change to 64 bit?
  u_int32_t good;
  u_int32_t jumps_f;
  u_int32_t jumps_b;

  u_int64_t total;
  u_int64_t bytes;
};

struct xflow_status_entry_sampling
{
  u_int32_t interface;		/* sFlow/NetFlow v9: interface generating the sample */
  u_int32_t sample_pool;	/* sampling rate */
  u_int32_t seqno;		/* sFlow: flow samples sequence number */
  u_int32_t sampler_id;		/* NetFlow v9: flow sampler ID field */ 
  struct xflow_status_entry_sampling *next;
};

struct xflow_status_entry_class
{
  pm_class_t class_id;				/* NetFlow v9: classfier ID field */
  pm_class_t class_int_id;			/* NetFlow v9: internal classfier ID field */
  char class_name[MAX_PROTOCOL_LEN];		/* NetFlow v9: classfier name field */
  struct xflow_status_entry_class *next;
};

struct xflow_status_map_cache
{
  pm_id_t tag;
  pm_id_t tag2;
  s_uint16_t port;		/* BGP port */
  int ret;
  struct timeval stamp;
};

struct xflow_status_entry
{
  struct host_addr agent_addr;  /* NetFlow/IPFIX: socket IP address
				   sFlow: agentID IP address */
  struct host_addr exp_addr;	/* NetFlow/IPFIX: exporter IP address, ie. #130/#131 (host_addr struct) */
  struct sockaddr exp_sa;	/* NetFlow/IPFIX: exporter IP address, ie. #130/#131 (sockaddr struct) */
  u_int32_t seqno;              /* Sequence number */
  u_int32_t aux1;               /* Some more distinguishing fields:
                                   NetFlow v5: Engine Type + Engine ID
                                   NetFlow v9: Source ID
                                   IPFIX: ObservedDomainID
                                   sFlow v5: agentSubID */
  u_int32_t aux2;		/* Some more distinguishing (internal) flags */
  u_int16_t inc;		/* increment, NetFlow v5: required by flow sequence number */
  u_int32_t peer_v4_idx;        /* last known BGP peer index for ipv4 address family */
  u_int32_t peer_v6_idx;        /* last known BGP peer index for ipv6 address family */
  struct xflow_status_map_cache bta_v4;			/* last known bgp_agent_map IPv4 result */
  struct xflow_status_map_cache bta_v6;			/* last known bgp_agent_map IPv6 result */
  struct xflow_status_map_cache st;			/* last known sampling_map result */
  struct xflow_status_entry_counters counters;
  struct xflow_status_entry_sampling *sampling;
  struct xflow_status_entry_class *class;
  cdada_map_t *in_rd_map;	/* hash map for ingress vrf id -> mpls vpn rd lookup */
  cdada_map_t *out_rd_map;	/* hash map for egress vrf id -> mpls vpn rd lookup */
  void *sf_cnt;			/* struct (ab)used for sFlow counters logging */

#ifdef WITH_GNUTLS
  pm_dtls_peer_t dtls;
#endif

  struct xflow_status_entry *next;
};

typedef struct {
  u_int32_t entries;

  u_int32_t tot_bad_datagrams;
  u_int8_t memerr;
  u_int8_t smp_entry_status_table_memerr;
  u_int8_t class_entry_status_table_memerr;

  struct xflow_status_entry *t[XFLOW_STATUS_TABLE_SZ];
} xflow_status_table_t;

/* prototypes */
extern u_int32_t hash_status_table(u_int32_t, struct sockaddr *, u_int32_t);
extern struct xflow_status_entry *search_status_table(xflow_status_table_t *, struct sockaddr *, u_int32_t, u_int32_t, int, int);
extern void update_good_status_table(struct xflow_status_entry *, u_int32_t);
extern void update_bad_status_table(struct xflow_status_entry *);
extern void print_status_table(xflow_status_table_t *, time_t, int);
extern struct xflow_status_entry_sampling *search_smp_if_status_table(struct xflow_status_entry_sampling *, u_int32_t);
extern struct xflow_status_entry_sampling *search_smp_id_status_table(struct xflow_status_entry_sampling *, u_int32_t, u_int8_t);
extern struct xflow_status_entry_sampling *create_smp_entry_status_table(xflow_status_table_t *, struct xflow_status_entry *);
extern struct xflow_status_entry_class *search_class_id_status_table(struct xflow_status_entry_class *, pm_class_t);
extern struct xflow_status_entry_class *create_class_entry_status_table(xflow_status_table_t *, struct xflow_status_entry *);
extern void set_vector_f_status(struct packet_ptrs_vector *);
extern void set_vector_f_status_g(struct packet_ptrs_vector *);
extern void update_status_table(struct xflow_status_entry *, u_int32_t, int);

extern xflow_status_table_t xflow_status_table;
#ifdef WITH_GNUTLS
extern xflow_status_table_t dtls_status_table;
#endif
#endif // XFLOW_STATUS_H
