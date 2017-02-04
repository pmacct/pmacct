/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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

/* includes */
#if (!defined __PLUGIN_COMMON_EXPORT)
#include "net_aggr.h"
#include "ports_aggr.h"

/* including sql_common.h exporteable part as pre-requisite for preprocess.h inclusion later */
#define __SQL_COMMON_EXPORT
#include "sql_common.h"
#undef __SQL_COMMON_EXPORT
#endif /* #if (!defined __PLUGIN_COMMON_EXPORT) */

/* defines */
#define DEFAULT_PLUGIN_COMMON_REFRESH_TIME 60 
#define DEFAULT_PLUGIN_COMMON_WRITERS_NO 10

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
  char *pcust;
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

#ifndef P_BROKER_TIMERS
#define P_BROKER_TIMERS
struct p_broker_timers {
  time_t last_fail;
  int retry_interval;
};
#endif

#if (!defined __PLUGIN_COMMON_EXPORT)

#include "preprocess.h"

/* typedefs */
#ifdef WITH_JANSSON
typedef void (*compose_json_handler)(json_t *, struct chained_cache *);
#endif

/* prototypes */
#if (!defined __PLUGIN_COMMON_C)
#define EXT extern
#else
#define EXT
#endif
EXT void P_set_signals();
EXT void P_init_default_values();
EXT void P_config_checks();
EXT struct chained_cache *P_cache_attach_new_node(struct chained_cache *);
EXT unsigned int P_cache_modulo(struct primitives_ptrs *);
EXT void P_sum_host_insert(struct primitives_ptrs *, struct insert_data *);
EXT void P_sum_port_insert(struct primitives_ptrs *, struct insert_data *);
EXT void P_sum_as_insert(struct primitives_ptrs *, struct insert_data *);
#if defined (HAVE_L2)
EXT void P_sum_mac_insert(struct primitives_ptrs *, struct insert_data *);
#endif
EXT struct chained_cache *P_cache_search(struct primitives_ptrs *);
EXT void P_cache_insert(struct primitives_ptrs *, struct insert_data *);
EXT void P_cache_insert_pending(struct chained_cache *[], int, struct chained_cache *);
EXT void P_cache_mark_flush(struct chained_cache *[], int, int);
EXT void P_cache_flush(struct chained_cache *[], int);
EXT void P_cache_handle_flush_event(struct ports_table *);
EXT void P_exit_now(int);
EXT int P_trigger_exec(char *);
EXT void primptrs_set_all_from_chained_cache(struct primitives_ptrs *, struct chained_cache *);
EXT void P_handle_table_dyn_rr(char *, int, char *, struct p_table_rr *);
EXT void P_handle_table_dyn_strings(char *, int, char *, struct chained_cache *);

EXT void P_broker_timers_set_last_fail(struct p_broker_timers *, time_t);
EXT void P_broker_timers_set_retry_interval(struct p_broker_timers *, int);
EXT void P_broker_timers_unset_last_fail(struct p_broker_timers *);
EXT time_t P_broker_timers_get_last_fail(struct p_broker_timers *);
EXT int P_broker_timers_get_retry_interval(struct p_broker_timers *);

EXT void P_init_historical_acct(time_t);
EXT void P_init_refresh_deadline(time_t *, int, int, char *);
EXT void P_eval_historical_acct(struct timeval *, struct timeval *, time_t);
EXT int P_cmp_historical_acct(struct timeval *, struct timeval *);
EXT int P_test_zero_elem(struct chained_cache *);

/* global vars */
EXT void (*insert_func)(struct primitives_ptrs *, struct insert_data *); /* pointer to INSERT function */
EXT void (*purge_func)(struct chained_cache *[], int); /* pointer to purge function */ 
EXT struct scratch_area sa;
EXT struct chained_cache *cache;
EXT struct chained_cache **queries_queue, **pending_queries_queue, *pqq_container;
EXT struct timeval flushtime;
EXT int qq_ptr, pqq_ptr, pp_size, pb_size, pn_size, pm_size, pc_size;
EXT int dbc_size, quit; 
EXT time_t refresh_deadline;

EXT void (*basetime_init)(time_t);
EXT void (*basetime_eval)(struct timeval *, struct timeval *, time_t);
EXT int (*basetime_cmp)(struct timeval *, struct timeval *);
EXT struct timeval basetime, ibasetime, new_basetime;
EXT time_t timeslot;
EXT int dyn_table;

#ifdef WITH_JANSSON
EXT compose_json_handler cjhandler[N_PRIMITIVES];
#endif

/* JSON-related prototypes */
EXT void compose_json(u_int64_t, u_int64_t);
#ifdef WITH_JANSSON
EXT void compose_json_event_type(json_t *, struct chained_cache *);
EXT void compose_json_tag(json_t *, struct chained_cache *);
EXT void compose_json_tag2(json_t *, struct chained_cache *);
EXT void compose_json_label(json_t *, struct chained_cache *);
EXT void compose_json_class(json_t *, struct chained_cache *);
EXT void compose_json_src_mac(json_t *, struct chained_cache *);
EXT void compose_json_dst_mac(json_t *, struct chained_cache *);
EXT void compose_json_vlan(json_t *, struct chained_cache *);
EXT void compose_json_cos(json_t *, struct chained_cache *);
EXT void compose_json_etype(json_t *, struct chained_cache *);
EXT void compose_json_src_as(json_t *, struct chained_cache *);
EXT void compose_json_dst_as(json_t *, struct chained_cache *);
EXT void compose_json_std_comm(json_t *, struct chained_cache *);
EXT void compose_json_ext_comm(json_t *, struct chained_cache *);
EXT void compose_json_lrg_comm(json_t *, struct chained_cache *);
EXT void compose_json_as_path(json_t *, struct chained_cache *);
EXT void compose_json_local_pref(json_t *, struct chained_cache *);
EXT void compose_json_med(json_t *, struct chained_cache *);
EXT void compose_json_peer_src_as(json_t *, struct chained_cache *);
EXT void compose_json_peer_dst_as(json_t *, struct chained_cache *);
EXT void compose_json_peer_src_ip(json_t *, struct chained_cache *);
EXT void compose_json_peer_dst_ip(json_t *, struct chained_cache *);
EXT void compose_json_src_std_comm(json_t *, struct chained_cache *);
EXT void compose_json_src_ext_comm(json_t *, struct chained_cache *);
EXT void compose_json_src_lrg_comm(json_t *, struct chained_cache *);
EXT void compose_json_src_as_path(json_t *, struct chained_cache *);
EXT void compose_json_src_local_pref(json_t *, struct chained_cache *);
EXT void compose_json_src_med(json_t *, struct chained_cache *);
EXT void compose_json_in_iface(json_t *, struct chained_cache *);
EXT void compose_json_out_iface(json_t *, struct chained_cache *);
EXT void compose_json_mpls_vpn_rd(json_t *, struct chained_cache *);
EXT void compose_json_src_host(json_t *, struct chained_cache *);
EXT void compose_json_src_net(json_t *, struct chained_cache *);
EXT void compose_json_dst_host(json_t *, struct chained_cache *);
EXT void compose_json_dst_net(json_t *, struct chained_cache *);
EXT void compose_json_src_mask(json_t *, struct chained_cache *);
EXT void compose_json_dst_mask(json_t *, struct chained_cache *);
EXT void compose_json_src_port(json_t *, struct chained_cache *);
EXT void compose_json_dst_port(json_t *, struct chained_cache *);
#if defined (WITH_GEOIP)
EXT void compose_json_src_host_country(json_t *, struct chained_cache *);
EXT void compose_json_dst_host_country(json_t *, struct chained_cache *);
#endif
#if defined (WITH_GEOIPV2)
EXT void compose_json_src_host_country(json_t *, struct chained_cache *);
EXT void compose_json_dst_host_country(json_t *, struct chained_cache *);
EXT void compose_json_src_host_pocode(json_t *, struct chained_cache *);
EXT void compose_json_dst_host_pocode(json_t *, struct chained_cache *);
#endif
EXT void compose_json_tcp_flags(json_t *, struct chained_cache *);
EXT void compose_json_proto(json_t *, struct chained_cache *);
EXT void compose_json_tos(json_t *, struct chained_cache *);
EXT void compose_json_sampling_rate(json_t *, struct chained_cache *);
EXT void compose_json_pkt_len_distrib(json_t *, struct chained_cache *);
EXT void compose_json_post_nat_src_host(json_t *, struct chained_cache *);
EXT void compose_json_post_nat_dst_host(json_t *, struct chained_cache *);
EXT void compose_json_post_nat_src_port(json_t *, struct chained_cache *);
EXT void compose_json_post_nat_dst_port(json_t *, struct chained_cache *);
EXT void compose_json_nat_event(json_t *, struct chained_cache *);
EXT void compose_json_mpls_label_top(json_t *, struct chained_cache *);
EXT void compose_json_mpls_label_bottom(json_t *, struct chained_cache *);
EXT void compose_json_mpls_stack_depth(json_t *, struct chained_cache *);
EXT void compose_json_timestamp_start(json_t *, struct chained_cache *);
EXT void compose_json_timestamp_end(json_t *, struct chained_cache *);
EXT void compose_json_timestamp_arrival(json_t *, struct chained_cache *);
EXT void compose_json_timestamp_stitching(json_t *, struct chained_cache *);
EXT void compose_json_export_proto_seqno(json_t *, struct chained_cache *);
EXT void compose_json_export_proto_version(json_t *, struct chained_cache *);
EXT void compose_json_custom_primitives(json_t *, struct chained_cache *);
EXT void compose_json_history(json_t *, struct chained_cache *);
EXT void compose_json_flows(json_t *, struct chained_cache *);
EXT void compose_json_counters(json_t *, struct chained_cache *);
#endif
#undef EXT
#endif /* #if (!defined __PLUGIN_COMMON_EXPORT) */
