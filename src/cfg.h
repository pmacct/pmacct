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

#include "cfg_handlers.h"
#include "bgp/bgp_prefix.h"

/* defines */
#define CFG_LINE_LEN(x) (SRVBUFLEN-strlen(x))
#define MAX_CUSTOM_PRIMITIVES		64
#define MAX_CUSTOM_PRIMITIVE_NAMELEN	64
#define MAX_CUSTOM_PRIMITIVE_PD_PTRS	8

/* structures */
struct _dictionary_line {
  char key[SRVBUFLEN];
  int (*func)(char *, char *, char *);
};

struct packet_data_ptr {
  s_uint8_t ptr_idx;
  u_int16_t off;
  s_uint16_t proto;
};

struct custom_primitive_entry {
  /* compiled from map */
  u_char name[MAX_CUSTOM_PRIMITIVE_NAMELEN];
  struct packet_data_ptr pd_ptr[MAX_CUSTOM_PRIMITIVE_PD_PTRS];
  u_int32_t pen;
  u_int16_t field_type;
  u_int16_t len;
  u_int16_t alloc_len;
  u_int8_t semantics;
  u_int8_t repeat_id;

  /* generated internally */
  pm_cfgreg_t type;
};

struct custom_primitives {
  struct custom_primitive_entry primitive[MAX_CUSTOM_PRIMITIVES];
  int num;
};

struct custom_primitive_ptrs {
  char *name;
  u_int16_t off;
  struct custom_primitive_entry *ptr;
};

struct custom_primitives_ptrs {
  struct custom_primitive_ptrs primitive[MAX_CUSTOM_PRIMITIVES];
  int num;
  int len;
};

struct configuration {
  pm_cfgreg_t what_to_count;	/* first registry */
  pm_cfgreg_t what_to_count_2;	/* second registry */
  pm_cfgreg_t nfprobe_what_to_count;
  pm_cfgreg_t nfprobe_what_to_count_2;
  pm_cfgreg_t metrics_what_to_count;
  char *aggregate_primitives;
  struct custom_primitives_ptrs cpptrs;
  char *name;
  char *type;
  int type_id;
  int pmacctd_nonroot;
  char *proc_name;
  int proc_priority;
  int sock;
  int bgp_sock;
  int acct_type; 
  int data_type; 
  int pipe_homegrown;
  u_int64_t pipe_size;
  u_int64_t buffer_size;
  int buffer_immediate;
  int pipe_backlog;
  int pipe_check_core_pid;
  int pipe_amqp;
  char *pipe_amqp_host;
  char *pipe_amqp_vhost;
  char *pipe_amqp_user;
  char *pipe_amqp_passwd;
  char *pipe_amqp_exchange;
  char *pipe_amqp_routing_key;
  int pipe_amqp_retry;
  int pipe_kafka;
  char *pipe_kafka_broker_host;
  char *pipe_kafka_topic;
  int pipe_kafka_partition;
  char *pipe_kafka_partition_key;
  int pipe_kafka_partition_keylen;
  int pipe_kafka_broker_port;
  int pipe_kafka_retry;
  char *pipe_kafka_fallback;
  int files_umask;
  int files_uid;
  int files_gid;
  int handle_fragments;
  int handle_flows;
  int frag_bufsz;
  int flow_bufsz;
  int flow_hashsz;
  int conntrack_bufsz;
  int flow_lifetime;
  int flow_tcp_lifetime;
  int num_protos;
  int num_hosts;
  char *imt_plugin_path;
  char *imt_plugin_passwd;
  char *sql_db;
  char *sql_table;
  char *sql_table_schema;
  int sql_table_version;
  char *sql_table_type;
  char *sql_user;
  char *sql_passwd;
  char *sql_host;
  char *sql_data;
  char *sql_backup_host;
  int sql_optimize_clauses;
  int sql_refresh_time;
  int sql_history;
  int sql_history_offset;
  int sql_history_howmany; /* internal */
  int sql_startup_delay;
  int sql_cache_entries;
  int sql_dont_try_update;
  char *sql_history_roundoff;
  int sql_trigger_time;
  int sql_trigger_time_howmany; /* internal */
  char *sql_trigger_exec;
  int sql_max_queries;
  char *sql_preprocess;
  int sql_preprocess_type;
  int sql_multi_values;
  int sql_aggressive_classification;
  char *sql_locking_style;
  int sql_use_copy;
  char *sql_delimiter;
  int timestamps_secs;
  int timestamps_since_epoch;
  int mongo_insert_batch;
  int message_broker_output;
  int avro_buffer_size;
  char *avro_schema_output_file;
  char *amqp_exchange_type;
  int amqp_persistent_msg;
  u_int32_t amqp_frame_max;
  u_int32_t amqp_heartbeat_interval;
  char *amqp_vhost;
  int amqp_routing_key_rr;
  char *amqp_avro_schema_routing_key;
  int amqp_avro_schema_refresh_time;
  int kafka_broker_port;
  int kafka_partition;
  char *kafka_partition_key;
  int kafka_partition_keylen;
  char *kafka_avro_schema_topic;
  int kafka_avro_schema_refresh_time;
  char *kafka_config_file;
  char *statsd_host;
  int statsd_port;
  int statsd_refresh_time;
  int print_cache_entries;
  int print_markers;
  int print_output;
  int print_output_file_append;
  char *print_output_lock_file;
  char *print_output_separator;
  char *print_output_file;
  char *print_latest_file;
  int nfacctd_port;
  char *nfacctd_ip;
  char *nfacctd_allow_file;
  int nfacctd_time;
  int nfacctd_pro_rating;
  int nfacctd_account_options;
  int nfacctd_stitching;
  u_int32_t nfacctd_as;
  u_int32_t nfacctd_net;
  int nfacctd_pipe_size;
  int sfacctd_renormalize;
  int sfacctd_counter_output;
  char *sfacctd_counter_file;
  int sfacctd_counter_max_nodes;
  char *sfacctd_counter_amqp_host;
  char *sfacctd_counter_amqp_vhost;
  char *sfacctd_counter_amqp_user;
  char *sfacctd_counter_amqp_passwd;
  char *sfacctd_counter_amqp_exchange;
  char *sfacctd_counter_amqp_exchange_type;
  char *sfacctd_counter_amqp_routing_key;
  int sfacctd_counter_amqp_persistent_msg;
  u_int32_t sfacctd_counter_amqp_frame_max;
  u_int32_t sfacctd_counter_amqp_heartbeat_interval;
  int sfacctd_counter_amqp_retry;
  char *sfacctd_counter_kafka_broker_host;
  char *sfacctd_counter_kafka_topic;
  int sfacctd_counter_kafka_partition;
  char *sfacctd_counter_kafka_partition_key;
  int sfacctd_counter_kafka_partition_keylen;
  int sfacctd_counter_kafka_broker_port;
  int sfacctd_counter_kafka_retry;
  char *sfacctd_counter_kafka_config_file;
  int nfacctd_disable_checks;
  int telemetry_daemon;
  int telemetry_sock;
  int telemetry_port_tcp;
  int telemetry_port_udp;
  char *telemetry_ip;
  char *telemetry_decoder;
  int telemetry_max_peers;
  int telemetry_udp_timeout;
  char *telemetry_allow_file;
  int telemetry_pipe_size;
  int telemetry_ipprec;
  char *telemetry_msglog_file;
  int telemetry_msglog_output;
  char *telemetry_msglog_amqp_host;
  char *telemetry_msglog_amqp_vhost;
  char *telemetry_msglog_amqp_user;
  char *telemetry_msglog_amqp_passwd;
  char *telemetry_msglog_amqp_exchange;
  char *telemetry_msglog_amqp_exchange_type;
  char *telemetry_msglog_amqp_routing_key;
  int telemetry_msglog_amqp_routing_key_rr;
  int telemetry_msglog_amqp_persistent_msg;
  u_int32_t telemetry_msglog_amqp_frame_max;
  u_int32_t telemetry_msglog_amqp_heartbeat_interval;
  int telemetry_msglog_amqp_retry;
  char *telemetry_dump_file;
  char *telemetry_dump_latest_file;
  int telemetry_dump_output;
  int telemetry_dump_refresh_time;
  char *telemetry_dump_amqp_host;
  char *telemetry_dump_amqp_vhost;
  char *telemetry_dump_amqp_user;
  char *telemetry_dump_amqp_passwd;
  char *telemetry_dump_amqp_exchange;
  char *telemetry_dump_amqp_exchange_type;
  char *telemetry_dump_amqp_routing_key;
  int telemetry_dump_amqp_routing_key_rr;
  int telemetry_dump_amqp_persistent_msg;
  u_int32_t telemetry_dump_amqp_frame_max;
  u_int32_t telemetry_dump_amqp_heartbeat_interval;
  char *telemetry_msglog_kafka_broker_host;
  int telemetry_msglog_kafka_broker_port;
  char *telemetry_msglog_kafka_topic;
  int telemetry_msglog_kafka_topic_rr;
  int telemetry_msglog_kafka_partition;
  char *telemetry_msglog_kafka_partition_key;
  int telemetry_msglog_kafka_partition_keylen;
  int telemetry_msglog_kafka_retry;
  char *telemetry_msglog_kafka_config_file;
  char *telemetry_dump_kafka_broker_host;
  int telemetry_dump_kafka_broker_port;
  char *telemetry_dump_kafka_topic;
  int telemetry_dump_kafka_topic_rr;
  int telemetry_dump_kafka_partition;
  char *telemetry_dump_kafka_partition_key;
  int telemetry_dump_kafka_partition_keylen;
  char *telemetry_dump_kafka_config_file;
  int nfacctd_bgp;
  int nfacctd_bgp_msglog_output;
  char *nfacctd_bgp_msglog_file;
  char *nfacctd_bgp_msglog_amqp_host;
  char *nfacctd_bgp_msglog_amqp_vhost;
  char *nfacctd_bgp_msglog_amqp_user;
  char *nfacctd_bgp_msglog_amqp_passwd;
  char *nfacctd_bgp_msglog_amqp_exchange;
  char *nfacctd_bgp_msglog_amqp_exchange_type;
  char *nfacctd_bgp_msglog_amqp_routing_key;
  int nfacctd_bgp_msglog_amqp_routing_key_rr;
  int nfacctd_bgp_msglog_amqp_persistent_msg;
  u_int32_t nfacctd_bgp_msglog_amqp_frame_max;
  u_int32_t nfacctd_bgp_msglog_amqp_heartbeat_interval;
  int nfacctd_bgp_msglog_amqp_retry;
  char *nfacctd_bgp_msglog_kafka_broker_host;
  char *nfacctd_bgp_msglog_kafka_topic;
  int nfacctd_bgp_msglog_kafka_topic_rr;
  int nfacctd_bgp_msglog_kafka_partition;
  char *nfacctd_bgp_msglog_kafka_partition_key;
  int nfacctd_bgp_msglog_kafka_partition_keylen;
  int nfacctd_bgp_msglog_kafka_broker_port;
  int nfacctd_bgp_msglog_kafka_retry;
  char *nfacctd_bgp_msglog_kafka_config_file;
  char *nfacctd_bgp_id;
  char *nfacctd_bgp_ip;
  as_t nfacctd_bgp_as;
  int nfacctd_bgp_port;
  int nfacctd_bgp_pipe_size;
  int nfacctd_bgp_ipprec;
  char *nfacctd_bgp_allow_file;
  int nfacctd_bgp_max_peers;
  int nfacctd_bgp_aspath_radius;
  char *nfacctd_bgp_stdcomm_pattern;
  char *nfacctd_bgp_extcomm_pattern;
  char *nfacctd_bgp_lrgcomm_pattern;
  char *nfacctd_bgp_stdcomm_pattern_to_asn;
  int nfacctd_bgp_peer_as_src_type;
  int nfacctd_bgp_src_std_comm_type;
  int nfacctd_bgp_src_ext_comm_type;
  int nfacctd_bgp_src_lrg_comm_type;
  int nfacctd_bgp_src_as_path_type;
  int nfacctd_bgp_src_local_pref_type;
  int nfacctd_bgp_src_med_type;
  int nfacctd_bgp_peer_as_skip_subas;
  int nfacctd_bgp_batch;
  int nfacctd_bgp_batch_interval;
  char *nfacctd_bgp_peer_as_src_map;
  char *nfacctd_bgp_src_local_pref_map;
  char *nfacctd_bgp_src_med_map;
  char *nfacctd_bgp_to_agent_map;
  char *nfacctd_flow_to_rd_map;
  int nfacctd_bgp_follow_default;
  struct prefix nfacctd_bgp_follow_nexthop[FOLLOW_BGP_NH_ENTRIES];
  int nfacctd_bgp_follow_nexthop_external;
  char *nfacctd_bgp_neighbors_file;
  char *nfacctd_bgp_md5_file;
  int nfacctd_bgp_offline_input;
  char *nfacctd_bgp_offline_file_spool;
  int nfacctd_bgp_offline_file_refresh_time;
  int bgp_table_peer_buckets;
  int bgp_table_per_peer_buckets;
  int bgp_table_attr_hash_buckets;
  int bgp_table_per_peer_hash;
  int bgp_table_dump_output;
  char *bgp_table_dump_file;
  char *bgp_table_dump_latest_file;
  int bgp_table_dump_refresh_time;
  char *bgp_table_dump_amqp_host;
  char *bgp_table_dump_amqp_vhost;
  char *bgp_table_dump_amqp_user;
  char *bgp_table_dump_amqp_passwd;
  char *bgp_table_dump_amqp_exchange;
  char *bgp_table_dump_amqp_exchange_type;
  char *bgp_table_dump_amqp_routing_key;
  int bgp_table_dump_amqp_routing_key_rr;
  int bgp_table_dump_amqp_persistent_msg;
  u_int32_t bgp_table_dump_amqp_frame_max;
  u_int32_t bgp_table_dump_amqp_heartbeat_interval;
  char *bgp_table_dump_kafka_broker_host;
  char *bgp_table_dump_kafka_topic;
  int bgp_table_dump_kafka_topic_rr;
  int bgp_table_dump_kafka_partition;
  char *bgp_table_dump_kafka_partition_key;
  int bgp_table_dump_kafka_partition_keylen;
  int bgp_table_dump_kafka_broker_port;
  char *bgp_table_dump_kafka_config_file;
  int bmp_sock;
  int nfacctd_bmp;
  char *nfacctd_bmp_ip;
  int nfacctd_bmp_port;
  int nfacctd_bmp_pipe_size;
  int nfacctd_bmp_max_peers;
  char *nfacctd_bmp_allow_file;
  int nfacctd_bmp_ipprec;
  int nfacctd_bmp_batch;
  int nfacctd_bmp_batch_interval;
  int nfacctd_bmp_msglog_output;
  char *nfacctd_bmp_msglog_file;
  char *nfacctd_bmp_msglog_amqp_host;
  char *nfacctd_bmp_msglog_amqp_vhost;
  char *nfacctd_bmp_msglog_amqp_user;
  char *nfacctd_bmp_msglog_amqp_passwd;
  char *nfacctd_bmp_msglog_amqp_exchange;
  char *nfacctd_bmp_msglog_amqp_exchange_type;
  char *nfacctd_bmp_msglog_amqp_routing_key;
  int nfacctd_bmp_msglog_amqp_routing_key_rr;
  int nfacctd_bmp_msglog_amqp_persistent_msg;
  u_int32_t nfacctd_bmp_msglog_amqp_frame_max;
  u_int32_t nfacctd_bmp_msglog_amqp_heartbeat_interval;
  int nfacctd_bmp_msglog_amqp_retry;
  char *nfacctd_bmp_msglog_kafka_broker_host;
  char *nfacctd_bmp_msglog_kafka_topic;
  int nfacctd_bmp_msglog_kafka_topic_rr;
  int nfacctd_bmp_msglog_kafka_partition;
  char *nfacctd_bmp_msglog_kafka_partition_key;
  int nfacctd_bmp_msglog_kafka_partition_keylen;
  int nfacctd_bmp_msglog_kafka_broker_port;
  int nfacctd_bmp_msglog_kafka_retry;
  char *nfacctd_bmp_msglog_kafka_config_file;
  int bmp_table_peer_buckets;
  int bmp_table_per_peer_buckets;
  int bmp_table_attr_hash_buckets;
  int bmp_table_per_peer_hash;
  int bmp_dump_output;
  char *bmp_dump_file;
  char *bmp_dump_latest_file;
  int bmp_dump_refresh_time;
  char *bmp_dump_amqp_host;
  char *bmp_dump_amqp_vhost;
  char *bmp_dump_amqp_user;
  char *bmp_dump_amqp_passwd;
  char *bmp_dump_amqp_exchange;
  char *bmp_dump_amqp_exchange_type;
  char *bmp_dump_amqp_routing_key;
  int bmp_dump_amqp_routing_key_rr;
  int bmp_dump_amqp_persistent_msg;
  u_int32_t bmp_dump_amqp_frame_max;
  u_int32_t bmp_dump_amqp_heartbeat_interval;
  char *bmp_dump_kafka_broker_host;
  char *bmp_dump_kafka_topic;
  int bmp_dump_kafka_topic_rr;
  int bmp_dump_kafka_partition;
  char *bmp_dump_kafka_partition_key;
  int bmp_dump_kafka_partition_keylen;
  int bmp_dump_kafka_broker_port;
  char *bmp_dump_kafka_config_file;
  int nfacctd_isis;
  char *nfacctd_isis_ip;
  char *nfacctd_isis_net;
  char *nfacctd_isis_iface;
  int nfacctd_isis_mtu;
  int nfacctd_isis_msglog;
  char *igp_daemon_map;
  char *igp_daemon_map_msglog;
  char *geoip_ipv4_file;
  char *geoip_ipv6_file;
#if defined WITH_GEOIP
  GeoIP *geoip_ipv4;
#if defined ENABLE_IPV6
  GeoIP *geoip_ipv6;
#endif
#endif
  char *geoipv2_file;
#if defined WITH_GEOIPV2
  MMDB_s geoipv2_db;
#endif
  int promisc; /* pcap_open_live() promisc parameter */
  char *clbuf; /* pcap filter */
  char *pcap_savefile;
  char *dev;
  int if_wait;
  int sf_wait;
  int num_memory_pools;
  int memory_pool_size;
  int buckets;
  int daemon;
  int active_plugins;
  char *logfile; 
  FILE *logfile_fd; 
  char *pidfile; 
  int networks_mask;
  char *networks_file;
  int networks_file_filter;
  int networks_file_no_lpm;
  int networks_cache_entries;
  char *ports_file;
  char *a_filter;
  int bpfp_a_num;
  struct bpf_program *bpfp_a_table[AGG_FILTER_ENTRIES];
  struct pretag_filter ptf;
  struct pretag_filter pt2f;
  struct pretag_label_filter ptlf;
  int maps_refresh;
  int maps_index;
  int maps_entries;
  int maps_row_len;
  char *pre_tag_map;
  struct id_table ptm;
  int ptm_alloc;
  int ptm_global;
  int ptm_complex;
  pm_id_t post_tag;
  pm_id_t post_tag2;
  int ext_sampling_rate;
  int sampling_rate;
  char *sampling_map;
  char *syslog;
  int debug;
  int debug_internal_msg;
  int snaplen;
  char *classifiers_path;
  int classifier_tentatives;
  int classifier_table_num;
  char *nfprobe_timeouts;
  int nfprobe_id;
  int nfprobe_hoplimit;
  int nfprobe_maxflows;
  char *nfprobe_receiver;
  int nfprobe_version;
  char *nfprobe_engine;
  int nfprobe_peer_as;
  char *nfprobe_source_ip;
  struct host_addr nfprobe_source_ha;
  int nfprobe_ipprec;
  int nfprobe_direction;
  u_int32_t nfprobe_ifindex;
  int nfprobe_ifindex_type;
  char *sfprobe_receiver;
  char *sfprobe_agentip;
  int sfprobe_agentsubid;
  u_int64_t sfprobe_ifspeed;
  int tee_transparent;
  int tee_max_receivers;
  int tee_max_receiver_pools;
  char *tee_receivers;
  int tee_pipe_size;
  int tee_dissect_send_full_pkt;
  int uacctd_group;
  int uacctd_nl_size;
  int uacctd_threshold;
  char *tunnel0;
  char *pkt_len_distrib_bins_str;
  char *pkt_len_distrib_bins[MAX_PKT_LEN_DISTRIB_BINS];
  u_int16_t pkt_len_distrib_bins_lookup[ETHER_JUMBO_MTU+1];
  int use_ip_next_hop;
  int dump_max_writers;
  int tmp_net_own_field;
  int tmp_asa_bi_flow;
  int tmp_comms_same_field;
  int intstats_daemon;
  char *intstats_src_ip;
  int intstats_src_port;
  size_t thread_stack;
  struct metric *met;
};

/* prototypes */ 
#if (!defined __CFG_C)
#define EXT extern
#else
#define EXT
#endif
EXT void evaluate_configuration(char *, int);
EXT int parse_configuration_file(char *);
EXT int parse_plugin_names(char *, int, int);
EXT void parse_core_process_name(char *, int, int);
EXT int create_plugin(char *, char *, char *);
EXT int delete_plugin_by_id(int);
EXT struct plugins_list_entry *search_plugin_by_pipe(int);
EXT struct plugins_list_entry *search_plugin_by_pid(pid_t);
EXT void sanitize_cfg(int, char *);
EXT void set_default_values();

/* global vars */
EXT char *cfg[SRVBUFLEN], *cfg_cmdline[SRVBUFLEN];
EXT struct custom_primitives custom_primitives_registry;
EXT pm_cfgreg_t custom_primitives_type;
EXT int rows;

static char default_proc_name[] = "default";
#undef EXT
