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

#ifndef IMT_PLUGIN_H
#define IMT_PLUGIN_H

#include <sys/poll.h>

/* defines */
#define NUM_MEMORY_POOLS 16
#define MEMORY_POOL_SIZE 8192
#define MAX_HOSTS 32771 
#define MAX_QUERIES 4096

/* Structures */
struct acc {
  struct pkt_primitives primitives;
  pm_counter_t bytes_counter;
  pm_counter_t packet_counter;
  pm_counter_t flow_counter;
  u_int8_t flow_type; 
  u_int32_t tcp_flags; 
  unsigned int signature;
  u_int8_t reset_flag;
  struct timeval rstamp;	/* classifiers: reset timestamp */
  struct pkt_bgp_primitives *pbgp;
  struct cache_legacy_bgp_primitives *clbgp;
  struct pkt_nat_primitives *pnat;
  struct pkt_mpls_primitives *pmpls;
  struct pkt_tunnel_primitives *ptun;
  u_char *pcust;
  struct pkt_vlen_hdr_primitives *pvlen;
  struct acc *next;
};

struct bucket_desc {
  unsigned int num;
  unsigned short int howmany;
};

struct memory_pool_desc {
  int id;
  unsigned char *base_ptr;
  unsigned char *ptr;
  int space_left;
  int len;
  struct memory_pool_desc *next;
};

struct query_header {
  int type;				/* type of query */
  pm_cfgreg_t what_to_count;		/* aggregation */
  pm_cfgreg_t what_to_count_2;		/* aggregation */
  unsigned int num;			/* number of queries */
  unsigned int ip_sz;			/* IP addresses size (in bytes) */
  unsigned int cnt_sz;			/* counters size (in bytes) */
  struct extra_primitives extras;	/* offsets for non-standard aggregation primitives structures */
  int datasize;				/* total length of aggregation primitives structures */
  char passwd[12];			/* OBSOLETED: password */
};

struct query_entry {
  pm_cfgreg_t what_to_count;			/* aggregation */
  pm_cfgreg_t what_to_count_2;			/* aggregation */
  struct pkt_primitives data;			/* actual data */
  struct pkt_bgp_primitives pbgp;		/* extended BGP data */
  struct pkt_legacy_bgp_primitives plbgp;	/* extended BGP data */
  struct pkt_nat_primitives pnat;		/* extended NAT + timestamp data */
  struct pkt_mpls_primitives pmpls;		/* extended MPLS data */
  struct pkt_tunnel_primitives ptun;		/* extended tunnel data */
  u_char *pcust;				/* custom-defined data */
  struct pkt_vlen_hdr_primitives *pvlen;	/* variable-length data */
};

struct reply_buffer {
  unsigned char buf[LARGEBUFLEN];
  unsigned char *ptr;
  int len;
  int packed; 
};

struct stripped_class {
  pm_class_t id;
  char protocol[MAX_PROTOCOL_LEN];
};

struct imt_custom_primitive_entry {
  /* compiled from map */
  char name[MAX_CUSTOM_PRIMITIVE_NAMELEN];
  u_int16_t field_type;
  u_int16_t len;
  u_int8_t semantics;

  /* compiled internally */
  u_int16_t off;
  pm_cfgreg_t type;
};

struct imt_custom_primitives {
  struct imt_custom_primitive_entry primitive[MAX_CUSTOM_PRIMITIVES];
  int len;
  int num;
};

/* prototypes */
extern void insert_accounting_structure(struct primitives_ptrs *);
extern struct acc *search_accounting_structure(struct primitives_ptrs *);
extern int compare_accounting_structure(struct acc *, struct primitives_ptrs *);

extern void init_memory_pool_table();
extern void clear_memory_pool_table();
extern struct memory_pool_desc *request_memory_pool(int);

extern void set_reset_flag(struct acc *);
extern void reset_counters(struct acc *);
extern int build_query_server(char *);
extern void process_query_data(int, unsigned char *, int, struct extra_primitives *, int, int);
extern void mask_elem(struct pkt_primitives *, struct pkt_bgp_primitives *, struct pkt_legacy_bgp_primitives *,
			struct pkt_nat_primitives *, struct pkt_mpls_primitives *, struct pkt_tunnel_primitives *,
			struct acc *, u_int64_t, u_int64_t, struct extra_primitives *);
extern void enQueue_elem(int, struct reply_buffer *, void *, int, int);
extern void Accumulate_Counters(struct pkt_data *, struct acc *);
extern int test_zero_elem(struct acc *);

extern void sum_host_insert(struct primitives_ptrs *);
extern void sum_port_insert(struct primitives_ptrs *);
extern void sum_as_insert(struct primitives_ptrs *);
#if defined HAVE_L2
extern void sum_mac_insert(struct primitives_ptrs *);
#endif
extern void exit_now(int);
extern void free_extra_allocs();

/* global vars */
extern void (*imt_insert_func)(struct primitives_ptrs *); /* pointer to INSERT function */
extern unsigned char *mpd;  /* memory pool descriptors table */
extern unsigned char *a;  /* accounting in-memory table */
extern struct memory_pool_desc *current_pool; /* pointer to currently used memory pool */
extern struct acc **lru_elem_ptr; /* pointer to Last Recently Used (lru) element in a bucket */
extern int no_more_space;
extern struct timeval cycle_stamp; /* timestamp for the current cycle */
extern struct timeval table_reset_stamp; /* global table reset timestamp */
#endif //IMT_PLUGIN_H
