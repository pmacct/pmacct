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

#ifndef PLUGIN_COMMON_H
#define PLUGIN_COMMON_H

/* includes */
#include "net_aggr.h"
#include "ports_aggr.h"
#include "sql_common.h"
#include "preprocess.h"

/* defines */
#define DEFAULT_PLUGIN_COMMON_REFRESH_TIME 60 
#define DEFAULT_PLUGIN_COMMON_WRITERS_NO 10
#define DEFAULT_PLUGIN_COMMON_RECV_BUDGET 100

#define AVERAGE_CHAIN_LEN 10
#define PRINT_CACHE_ENTRIES 16411

/* cache element states */
#define PRINT_CACHE_FREE	0
#define PRINT_CACHE_COMMITTED	1
#define PRINT_CACHE_INUSE	2 
#define PRINT_CACHE_INVALID	3 
#define PRINT_CACHE_ERROR	255

/* structures */
#ifndef STRUCT_SCRATCH_AREA
#define STRUCT_SCRATCH_AREA
struct scratch_area {
  unsigned char *base;
  unsigned char *ptr;
  u_int64_t num;
  u_int64_t size;
  struct scratch_area *next;
};
#endif

#ifndef STRUCT_CHAINED_CACHE
#define STRUCT_CHAINED_CACHE
struct chained_cache {
  struct pkt_primitives primitives;
  pm_counter_t bytes_counter;
  pm_counter_t packet_counter;
  pm_counter_t flow_counter;
  u_int8_t flow_type;
  u_int32_t tcp_flags;
  struct pkt_bgp_primitives *pbgp;
  struct pkt_nat_primitives *pnat;
  struct pkt_mpls_primitives *pmpls;
  struct pkt_tunnel_primitives *ptun;
  u_char *pcust;
  struct pkt_vlen_hdr_primitives *pvlen;
  u_int8_t valid;
  u_int8_t prep_valid;
  struct timeval basetime;
  struct pkt_stitching *stitch;
  struct chained_cache *next;
};
#endif

#ifndef P_TABLE_RR
#define P_TABLE_RR
struct p_table_rr {
  int min; /* unused */
  int max;
  int next;
};
#endif


/* prototypes */
extern void P_set_signals();
extern void P_init_default_values();
extern void P_config_checks();
extern struct chained_cache *P_cache_attach_new_node(struct chained_cache *);
extern unsigned int P_cache_modulo(struct primitives_ptrs *);
extern void P_sum_host_insert(struct primitives_ptrs *, struct insert_data *);
extern void P_sum_port_insert(struct primitives_ptrs *, struct insert_data *);
extern void P_sum_as_insert(struct primitives_ptrs *, struct insert_data *);
#if defined (HAVE_L2)
extern void P_sum_mac_insert(struct primitives_ptrs *, struct insert_data *);
#endif
extern struct chained_cache *P_cache_search(struct primitives_ptrs *);
extern void P_cache_insert(struct primitives_ptrs *, struct insert_data *);
extern void P_cache_insert_pending(struct chained_cache *[], int, struct chained_cache *);
extern void P_cache_mark_flush(struct chained_cache *[], int, int);
extern void P_cache_flush(struct chained_cache *[], int);
extern void P_cache_handle_flush_event(struct ports_table *);
extern void P_exit_now(int);
extern int P_trigger_exec(char *);
extern void primptrs_set_all_from_chained_cache(struct primitives_ptrs *, struct chained_cache *);
extern void P_handle_table_dyn_rr(char *, int, char *, struct p_table_rr *);

extern void P_init_historical_acct(time_t);
extern void P_init_refresh_deadline(time_t *, int, int, char *);
extern void P_eval_historical_acct(struct timeval *, struct timeval *, time_t);
extern int P_cmp_historical_acct(struct timeval *, struct timeval *);
extern void P_update_time_reference(struct insert_data *);

/* global vars */
extern void (*insert_func)(struct primitives_ptrs *, struct insert_data *); /* pointer to INSERT function */
extern void (*purge_func)(struct chained_cache *[], int, int); /* pointer to purge function */ 
extern struct scratch_area sa;
extern struct chained_cache *cache;
extern struct chained_cache **queries_queue, **pending_queries_queue, *pqq_container;
extern struct timeval flushtime;
extern int qq_ptr, pqq_ptr, pp_size, pb_size, pn_size, pm_size, pt_size, pc_size;
extern int dbc_size, quit; 
extern time_t refresh_deadline;

extern void (*basetime_init)(time_t);
extern void (*basetime_eval)(struct timeval *, struct timeval *, time_t);
extern int (*basetime_cmp)(struct timeval *, struct timeval *);
extern struct timeval basetime, ibasetime, new_basetime;
extern time_t timeslot;
extern int dyn_table, dyn_table_time_only;
#endif //PLUGIN_COMMON_H
