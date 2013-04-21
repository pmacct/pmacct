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
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

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

/* cache element states */
#define SQL_CACHE_FREE		0
#define SQL_CACHE_COMMITTED	1
#define SQL_CACHE_INUSE		2 
#define SQL_CACHE_ERROR		255

#define SQL_TABLE_VERSION_PLAIN 0
#define SQL_TABLE_VERSION_BGP   1000

/* macros */
#define SPACELEFT(x) (sizeof(x)-strlen(x))
#define SPACELEFT_LEN(x,y) (sizeof(x)-y)
#define SPACELEFT_PTR(x,y) (y-strlen(x))

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
  int recover;
  int locks;
  time_t new_basetime;
  time_t committed_basetime;
  int current_queue_elem;
  struct multi_values mv;
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
  struct cache_bgp_primitives *cbgp;
  struct pkt_nat_primitives *pnat;
  u_int8_t valid;
  u_int8_t prep_valid;
  unsigned int signature;
  u_int8_t chained;
  struct db_cache *prev;
  struct db_cache *next;
  time_t start_tag;	/* time: first packet received */
  time_t lru_tag;	/* time: last packet received */
  struct db_cache *lru_prev;
  struct db_cache *lru_next;
};

struct logfile_header {
  u_int32_t magic;
  char sql_db[DEF_HDR_FIELD_LEN];
  char sql_table[DEF_HDR_FIELD_LEN];
  char sql_user[DEF_HDR_FIELD_LEN];
  char sql_host[DEF_HDR_FIELD_LEN];
  u_int16_t sql_table_version;
  u_int16_t sql_optimize_clauses;
  u_int16_t sql_history;
  u_int64_t what_to_count;
  u_int64_t what_to_count_2;
  u_char pad[8];
};

struct logfile {
  FILE *file;
  short int open;
  short int fail;
};

typedef void (*dbop_handler) (const struct db_cache *, const struct insert_data *, int, char **, char **);
typedef int (*preprocess_func) (struct db_cache *[], int *, int);

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
  struct logfile *lf;
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

/* the following include depends on structure definition above */
#include "log_templates.h"
#include "preprocess.h"

/* functions */
#if (!defined __SQL_HANDLERS_C)
#define EXT extern
#else
#define EXT
#endif
EXT void count_src_mac_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_dst_mac_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_vlan_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_cos_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_etype_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_src_host_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_src_as_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_dst_host_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_dst_as_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_std_comm_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_ext_comm_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_as_path_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_local_pref_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_med_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_src_std_comm_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_src_ext_comm_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_src_as_path_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_src_local_pref_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_src_med_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_mpls_vpn_rd_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_peer_src_as_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_peer_dst_as_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_peer_src_ip_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_peer_dst_ip_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_src_port_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_dst_port_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_ip_tos_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_in_iface_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_out_iface_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_src_nmask_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_dst_nmask_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_sampling_rate_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_pkt_len_distrib_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void MY_count_ip_proto_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void PG_count_ip_proto_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_timestamp_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_copy_timestamp_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_id_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_id2_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_class_id_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_tcpflags_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_post_nat_src_ip_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_post_nat_dst_ip_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_post_nat_src_port_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_post_nat_dst_port_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_nat_event_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_timestamp_start_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void PG_copy_count_timestamp_start_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_timestamp_start_residual_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_timestamp_end_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void PG_copy_count_timestamp_end_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_timestamp_end_residual_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void fake_mac_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void fake_host_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void fake_as_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void fake_comms_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void fake_as_path_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void fake_mpls_vpn_rd_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);

#if defined WITH_GEOIP
EXT void count_src_host_country_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_dst_host_country_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
#endif

EXT void count_counters_setclause_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_flows_setclause_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_tcpflags_setclause_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_noop_setclause_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
EXT void count_noop_setclause_event_handler(const struct db_cache *, const struct insert_data *, int, char **, char **);
#undef EXT

#if (defined __SQL_COMMON_C)
#define EXT extern
#else
#define EXT
#endif

/* Toward a common SQL layer */
EXT void sql_set_signals();
EXT void sql_set_insert_func();
EXT void sql_init_maps(struct networks_table *, struct networks_cache *, struct ports_table *);
EXT void sql_init_global_buffers();
EXT void sql_init_default_values(struct extra_primitives *);
EXT void sql_init_historical_acct(time_t, struct insert_data *);
EXT void sql_init_triggers(time_t, struct insert_data *);
EXT void sql_init_refresh_deadline(time_t *);
EXT void sql_init_pipe(struct pollfd *, int);
EXT struct template_entry *sql_init_logfile_template(struct template_header *);
EXT void sql_link_backend_descriptors(struct BE_descs *, struct DBdesc *, struct DBdesc *);
EXT void sql_cache_modulo(struct primitives_ptrs *, struct insert_data *);
EXT int sql_cache_flush(struct db_cache *[], int, struct insert_data *, int);
EXT int sql_cache_flush_pending(struct db_cache *[], int, struct insert_data *);
EXT void sql_cache_insert(struct primitives_ptrs *, struct insert_data *);
EXT struct db_cache *sql_cache_search(struct primitives_ptrs *, time_t);
EXT int sql_trigger_exec(char *);
EXT void sql_db_ok(struct DBdesc *);
EXT void sql_db_fail(struct DBdesc *);
EXT void sql_db_errmsg(struct DBdesc *);
EXT int sql_query(struct BE_descs *, struct db_cache *, struct insert_data *);
EXT void sql_exit_gracefully(int);
EXT int sql_evaluate_primitives(int);
EXT FILE *sql_file_open(const char *, const char *, const struct insert_data *);
EXT void sql_create_table(struct DBdesc *, time_t *);
EXT void sql_invalidate_shadow_entries(struct db_cache *[], int *);
EXT int sql_select_locking_style(char *);
EXT int sql_compose_static_set(int); 
EXT int sql_compose_static_set_event(); 

EXT void sql_sum_host_insert(struct primitives_ptrs *, struct insert_data *);
EXT void sql_sum_port_insert(struct primitives_ptrs *, struct insert_data *);
EXT void sql_sum_as_insert(struct primitives_ptrs *, struct insert_data *);
#if defined (HAVE_L2)
EXT void sql_sum_mac_insert(struct primitives_ptrs *, struct insert_data *);
#endif
EXT void sql_sum_std_comm_insert(struct primitives_ptrs *, struct insert_data *);
EXT void sql_sum_ext_comm_insert(struct primitives_ptrs *, struct insert_data *);

#undef EXT

#if (!defined __MYSQL_PLUGIN_C) && (!defined __PMACCT_PLAYER_C) && \
	(!defined __PGSQL_PLUGIN_C) && (!defined __SQLITE3_PLUGIN_C) 
#define EXT extern
#else
#define EXT
#endif

/* Global Variables: a simple way of gain precious speed when playing with strings */
EXT char sql_data[LARGEBUFLEN];
EXT char lock_clause[LONGSRVBUFLEN];
EXT char unlock_clause[LONGSRVBUFLEN];
EXT char update_clause[LONGSRVBUFLEN];
EXT char set_clause[LONGSRVBUFLEN];
EXT char copy_clause[LONGSRVBUFLEN];
EXT char insert_clause[LONGSRVBUFLEN];
EXT char insert_counters_clause[LONGSRVBUFLEN];
EXT char insert_nocounters_clause[LONGSRVBUFLEN];
EXT char insert_full_clause[LONGSRVBUFLEN];
EXT char values_clause[LONGLONGSRVBUFLEN];
EXT char *multi_values_buffer;
EXT char where_clause[LONGLONGSRVBUFLEN];
EXT unsigned char *pipebuf;
EXT struct db_cache *cache;
EXT struct db_cache **queries_queue, **pending_queries_queue;
EXT struct db_cache *collision_queue;
EXT int cq_ptr, qq_ptr, qq_size, pp_size, pb_size, pn_size, dbc_size, cq_size, pqq_ptr;
EXT struct db_cache lru_head, *lru_tail;
EXT struct frags where[N_PRIMITIVES+2];
EXT struct frags values[N_PRIMITIVES+2];
EXT struct frags copy_values[N_PRIMITIVES+2];
EXT struct frags set[N_PRIMITIVES+2];
EXT struct frags set_event[N_PRIMITIVES+2];
EXT int glob_num_primitives; /* last resort for signal handling */
EXT int glob_basetime; /* last resort for signal handling */
EXT time_t glob_new_basetime; /* last resort for signal handling */
EXT time_t glob_committed_basetime; /* last resort for signal handling */
EXT int glob_dyn_table; /* last resort for signal handling */
EXT int glob_timeslot; /* last resort for sql handlers */

EXT struct sqlfunc_cb_registry sqlfunc_cbr; 
EXT void (*insert_func)(struct primitives_ptrs *, struct insert_data *);
EXT struct DBdesc p;
EXT struct DBdesc b;
EXT struct BE_descs bed;
EXT struct template_header th;
EXT struct template_entry *te;
EXT struct largebuf logbuf;
EXT struct largebuf envbuf;
EXT time_t now; /* PostgreSQL */
#undef EXT

