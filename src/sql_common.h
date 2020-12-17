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

#ifndef SQL_COMMON_H
#define SQL_COMMON_H

/* includes */
#include <sys/poll.h>
#include "net_aggr.h"
#include "ports_aggr.h"

/* defines */
#define DEFAULT_DB_REFRESH_TIME 60
#define DEFAULT_SQL_TABLE_VERSION 1
#define DEFAULT_SQL_WRITERS_NO 10
#define CACHE_ENTRIES 32771 
#define QUERY_BUFFER_SIZE 32768
#define MAGIC 14021979
#define DEF_HDR_FIELD_LEN 128 
#define MAX_LOGFILE_SIZE 2048000000 
#define MAX_LOGFILE_ROTATIONS 1000

/* cache elements defines */
#define REASONABLE_NUMBER 100
#define STALE_M 3
#define RETIRE_M STALE_M*STALE_M

/* backend types */
#define BE_TYPE_PRIMARY		0
#define BE_TYPE_BACKUP		1
#define BE_TYPE_LOGFILE		2

/* lock types */
#define PM_LOCK_EXCLUSIVE	0
#define PM_LOCK_ROW_EXCLUSIVE	1
#define PM_LOCK_NONE		2

/* cache element states */
#define SQL_CACHE_FREE		0
#define SQL_CACHE_COMMITTED	1
#define SQL_CACHE_INUSE		2 
#define SQL_CACHE_INVALID	3 
#define SQL_CACHE_ERROR		255

#define SQL_TABLE_VERSION_PLAIN 0
#define SQL_TABLE_VERSION_BGP   1000

/* macros */
#define SPACELEFT(x) (sizeof(x)-strlen(x))
#define SPACELEFT_LEN(x,y) (sizeof(x)-y)
#define SPACELEFT_PTR(x,y) (y-strlen(x))

#define SQL_INSERT_INSERT	0x00000001
#define SQL_INSERT_UPDATE	0x00000002
#define SQL_INSERT_PRO_RATING	0x00000004
#define SQL_INSERT_SAFE_ACTION	0x00000008

struct multi_values {
  int buffer_offset;      /* multi-values buffer offset where to write next query */ 
  int head_buffer_elem;   /* first multi-values buffer element */ 
  int buffer_elem_num;    /* number of elements in the multi-values buffer */ 
  int last_queue_elem;    /* last queue element signallation */
};

/* structures */
struct insert_data {
  struct configuration *cfg;
  unsigned int hash;
  unsigned int modulo;
  time_t now;
  time_t basetime;   
  time_t triggertime;
  time_t timeslot;   /* counters timeslot */ 
  time_t t_timeslot; /* trigger timeslot */
  struct timeval flushtime; /* last time the table has been flushed */
  int pending_accumulators;
  int num_primitives;
  int dyn_table;
  int dyn_table_time_only;
  char dyn_table_name[SRVBUFLEN];
  int recover;
  int locks;
  time_t new_basetime;
  time_t committed_basetime;
  int current_queue_elem;
  struct multi_values mv;
  int cp_idx; /* custom primitives index */
  /* stats */
  time_t elap_time; /* elapsed time */
  unsigned int ten; /* total elements number */
  unsigned int een; /* effective elements number */ 
  unsigned int qn; /* total query number */
  unsigned int iqn; /* INSERTs query number */
  unsigned int uqn; /* UPDATEs query number */
};

struct db_cache {
  struct pkt_primitives primitives;
  pm_counter_t bytes_counter;
  pm_counter_t packet_counter;
  pm_counter_t flows_counter;
  u_int8_t flow_type;
  u_int32_t tcp_flags;
  u_int8_t tentatives;	/* support to classifiers: tentatives remaining */
  time_t basetime;
  struct pkt_bgp_primitives *pbgp;
  struct pkt_nat_primitives *pnat;
  struct pkt_mpls_primitives *pmpls;
  struct pkt_tunnel_primitives *ptun;
  u_char *pcust;
  struct pkt_vlen_hdr_primitives *pvlen;
  u_int8_t valid;
  u_int8_t prep_valid;
  unsigned int signature;
  u_int8_t chained;
  struct pkt_stitching *stitch;
  struct db_cache *prev;
  struct db_cache *next;
  time_t start_tag;	/* time: first packet received */
  time_t lru_tag;	/* time: last packet received */
  struct db_cache *lru_prev;
  struct db_cache *lru_next;
};

typedef void (*dbop_handler) (const struct db_cache *, struct insert_data *, int, char **, char **);

struct frags {
  dbop_handler handler;
  u_int64_t type;
  char string[SRVBUFLEN];
};

/* Backend descriptors */
struct DBdesc {
  void *desc;
  char *conn_string; /* PostgreSQL */
  char *filename; /* SQLite */
  char *errmsg;
  short int type;
  short int connected;
  short int fail;
};

struct BE_descs { 
  struct DBdesc *p;
  struct DBdesc *b;
};

/* Callbacks for a common SQL layer */
typedef void (*db_connect)(struct DBdesc *, char *);
typedef void (*db_close)(struct BE_descs *);
typedef void (*db_lock)(struct DBdesc *);
typedef void (*db_unlock)(struct BE_descs *);
typedef void (*db_create_table)(struct DBdesc *, char *);
typedef int (*db_op)(struct DBdesc *, struct db_cache *, struct insert_data *); 
typedef void (*sqlcache_purge)(struct db_cache *[], int, struct insert_data *);
typedef void (*sqlbackend_create)(struct DBdesc *);
struct sqlfunc_cb_registry {
  db_connect connect;
  db_close close;
  db_lock lock;
  db_unlock unlock;
  db_op op;
  db_create_table create_table;
  sqlbackend_create create_backend;
  sqlcache_purge purge;
  /* flush and query wrapper are common for all SQL plugins */
};


#include "preprocess.h"

/* functions */
extern void count_src_mac_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_dst_mac_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_vlan_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_cos_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_etype_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_host_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_net_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_as_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_dst_host_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_dst_net_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_dst_as_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_std_comm_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_ext_comm_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_lrg_comm_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_as_path_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_local_pref_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_med_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_dst_roa_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_std_comm_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_ext_comm_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_lrg_comm_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_as_path_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_local_pref_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_med_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_roa_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_mpls_vpn_rd_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_mpls_pw_id_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_peer_src_as_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_peer_dst_as_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_peer_src_ip_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_peer_dst_ip_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_port_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_dst_port_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_ip_tos_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_in_iface_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_out_iface_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_nmask_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_dst_nmask_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_sampling_rate_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_sampling_direction_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void MY_count_ip_proto_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void PG_count_ip_proto_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_copy_timestamp_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tag_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tag2_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_label_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_class_id_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tcpflags_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_post_nat_src_ip_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_post_nat_dst_ip_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_post_nat_src_port_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_post_nat_dst_port_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_nat_event_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_mpls_label_top_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_mpls_label_bottom_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_mpls_stack_depth_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tunnel_src_mac_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tunnel_dst_mac_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tunnel_src_ip_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tunnel_dst_ip_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void MY_count_tunnel_ip_proto_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void PG_count_tunnel_ip_proto_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tunnel_ip_tos_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tunnel_src_port_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tunnel_dst_port_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_vxlan_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_start_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void PG_copy_count_timestamp_start_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_start_residual_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_end_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void PG_copy_count_timestamp_end_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_end_residual_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_arrival_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void PG_copy_count_timestamp_arrival_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_arrival_residual_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_export_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void PG_copy_count_timestamp_export_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_export_residual_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_min_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void PG_copy_count_timestamp_min_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_min_residual_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_max_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void PG_copy_count_timestamp_max_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_export_proto_seqno_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_export_proto_version_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_export_proto_sysid_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_timestamp_max_residual_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_custom_primitives_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void fake_mac_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void fake_host_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void fake_as_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void fake_comms_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void fake_as_path_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void fake_mpls_vpn_rd_handler(const struct db_cache *, struct insert_data *, int, char **, char **);

extern void count_src_host_aton_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_dst_host_aton_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_net_aton_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_dst_net_aton_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_peer_src_ip_aton_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_peer_dst_ip_aton_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_post_nat_src_ip_aton_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_post_nat_dst_ip_aton_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tunnel_src_ip_aton_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tunnel_dst_ip_aton_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void fake_host_aton_handler(const struct db_cache *, struct insert_data *, int, char **, char **);

#if defined (WITH_GEOIP) || defined (WITH_GEOIPV2)
extern void count_src_host_country_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_dst_host_country_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
#endif
#if defined (WITH_GEOIPV2)
extern void count_src_host_pocode_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_dst_host_pocode_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_src_host_coords_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_dst_host_coords_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
#endif

#if defined (WITH_NDPI)
extern void count_ndpi_class_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
#endif

extern void count_counters_setclause_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_flows_setclause_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_tcpflags_setclause_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_noop_setclause_handler(const struct db_cache *, struct insert_data *, int, char **, char **);
extern void count_noop_setclause_event_handler(const struct db_cache *, struct insert_data *, int, char **, char **);

/* Toward a common SQL layer */
extern void sql_set_signals();
extern void sql_set_insert_func();
extern void sql_init_maps(struct extra_primitives *, struct primitives_ptrs *, struct networks_table *, struct networks_cache *, struct ports_table *);
extern void sql_init_global_buffers();
extern void sql_init_default_values(struct extra_primitives *);
extern void sql_init_historical_acct(time_t, struct insert_data *);
extern void sql_init_triggers(time_t, struct insert_data *);
extern void sql_init_refresh_deadline(time_t *);
extern void sql_link_backend_descriptors(struct BE_descs *, struct DBdesc *, struct DBdesc *);
extern void sql_cache_modulo(struct primitives_ptrs *, struct insert_data *);
extern int sql_cache_flush(struct db_cache *[], int, struct insert_data *, int);
extern void sql_cache_flush_pending(struct db_cache *[], int, struct insert_data *);
extern void sql_cache_handle_flush_event(struct insert_data *, time_t *, struct ports_table *);
extern void sql_cache_insert(struct primitives_ptrs *, struct insert_data *);
extern struct db_cache *sql_cache_search(struct primitives_ptrs *, time_t);
extern int sql_trigger_exec(char *);
extern void sql_db_ok(struct DBdesc *);
extern void sql_db_fail(struct DBdesc *);
extern void sql_db_errmsg(struct DBdesc *);
extern void sql_db_warnmsg(struct DBdesc *);
extern int sql_query(struct BE_descs *, struct db_cache *, struct insert_data *);
extern void sql_exit_gracefully(int);
extern int sql_evaluate_primitives(int);
extern void sql_create_table(struct DBdesc *, time_t *, struct primitives_ptrs *);
extern void sql_invalidate_shadow_entries(struct db_cache *[], int *);
extern int sql_select_locking_style(char *);
extern int sql_compose_static_set(int); 
extern int sql_compose_static_set_event(); 
extern void primptrs_set_all_from_db_cache(struct primitives_ptrs *, struct db_cache *);

extern void sql_sum_host_insert(struct primitives_ptrs *, struct insert_data *);
extern void sql_sum_port_insert(struct primitives_ptrs *, struct insert_data *);
extern void sql_sum_as_insert(struct primitives_ptrs *, struct insert_data *);
#if defined (HAVE_L2)
extern void sql_sum_mac_insert(struct primitives_ptrs *, struct insert_data *);
#endif
extern void sql_sum_std_comm_insert(struct primitives_ptrs *, struct insert_data *);
extern void sql_sum_ext_comm_insert(struct primitives_ptrs *, struct insert_data *);

#if 10
/* Global Variables: a simple way of gain precious speed when playing with strings */
extern char sql_data[LARGEBUFLEN];
extern char lock_clause[LONGSRVBUFLEN];
extern char unlock_clause[LONGSRVBUFLEN];
extern char update_clause[LONGSRVBUFLEN];
extern char set_clause[LONGSRVBUFLEN];
extern char copy_clause[LONGSRVBUFLEN];
extern char insert_clause[LONGSRVBUFLEN];
extern char insert_counters_clause[LONGSRVBUFLEN];
extern char insert_nocounters_clause[LONGSRVBUFLEN];
extern char insert_full_clause[LONGSRVBUFLEN];
extern char values_clause[LONGLONGSRVBUFLEN];
extern char *multi_values_buffer;
extern char where_clause[LONGLONGSRVBUFLEN];
extern unsigned char *pipebuf;
extern struct db_cache *sql_cache;
extern struct db_cache **sql_queries_queue, **sql_pending_queries_queue;
extern struct db_cache *collision_queue;
extern int cq_ptr, sql_qq_ptr, qq_size, sql_pp_size, sql_pb_size, sql_pn_size, sql_pm_size, sql_pt_size;
extern int sql_pc_size, sql_dbc_size, cq_size, sql_pqq_ptr;
extern struct db_cache lru_head, *lru_tail;
extern struct frags where[N_PRIMITIVES+2];
extern struct frags values[N_PRIMITIVES+2];
extern struct frags copy_values[N_PRIMITIVES+2];
extern struct frags set[N_PRIMITIVES+2];
extern struct frags set_event[N_PRIMITIVES+2];
extern int glob_num_primitives; /* last resort for signal handling */
extern int glob_basetime; /* last resort for signal handling */
extern time_t glob_new_basetime; /* last resort for signal handling */
extern time_t glob_committed_basetime; /* last resort for signal handling */
extern int glob_dyn_table, glob_dyn_table_time_only; /* last resort for signal handling */
extern int glob_timeslot; /* last resort for sql handlers */

extern struct sqlfunc_cb_registry sqlfunc_cbr; 
extern void (*sql_insert_func)(struct primitives_ptrs *, struct insert_data *);
extern struct DBdesc p;
extern struct DBdesc b;
extern struct BE_descs bed;
extern struct largebuf_s envbuf;
extern time_t now; /* PostgreSQL */
#endif
#endif //SQL_COMMON_H
