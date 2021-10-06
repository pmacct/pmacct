/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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
#ifndef CFG_H
#define CFG_H

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
  char name[MAX_CUSTOM_PRIMITIVE_NAMELEN];
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
  char *aggregate_primitives;
  struct custom_primitives_ptrs cpptrs;
  char *progname;
  char *name;
  char *type;
  int type_id;
  int is_forked;
  int propagate_signals;
  int pmacctd_nonroot;
  char *proc_name;
  int proc_priority;
  char *cluster_name;
  int cluster_id;
  char *redis_host;
  int redis_db;
  int sock;
  int bgp_sock;
  int acct_type; 
  int data_type; 
  int pipe_homegrown;
  u_int64_t pipe_size;
  u_int64_t buffer_size;
  int buffer_immediate;
  int pipe_zmq;
  int pipe_zmq_retry;
  int pipe_zmq_profile;
  int pipe_zmq_hwm;
  int plugin_exit_any;
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
  char *dtls_path;
#ifdef WITH_GNUTLS
  pm_dtls_glob_t dtls_globs;
#endif
  char *imt_plugin_path;
  char *imt_plugin_passwd;
  char *sql_db;
  char *sql_table;
  char *sql_table_schema;
  int sql_table_version;
  char *sql_table_type;
  char *sql_user;
  char *sql_passwd;
  char *sql_conn_ca_file;
  char *sql_host;
  int sql_port;
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
  char *sql_locking_style;
  int sql_use_copy;
  char *sql_delimiter;
  int timestamps_rfc3339;
  int timestamps_utc;
  int timestamps_secs;
  int timestamps_since_epoch;
  int mongo_insert_batch;
  int message_broker_output;
  int avro_buffer_size;
  char *avro_schema_file;
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
  int kafka_partition_dynamic;
  char *kafka_partition_key;
  int kafka_partition_keylen;
  char *kafka_avro_schema_topic;
  int kafka_avro_schema_refresh_time;
  char *kafka_avro_schema_registry;
  char *kafka_config_file;
  int print_cache_entries;
  int print_markers;
  int print_output;
  int print_output_file_append;
  int print_write_empty_file;
  char *print_output_lock_file;
  char *print_output_separator;
  char *print_output_file;
  char *print_output_custom_lib;
  char *print_output_custom_cfg_file;
  char *print_latest_file;
  int nfacctd_port;
  char *nfacctd_ip;
  int nfacctd_ipv6_only;
  char *nfacctd_kafka_broker_host;
  int nfacctd_kafka_broker_port;
  char *nfacctd_kafka_topic;
  char *nfacctd_kafka_config_file;
  char *nfacctd_zmq_address;
  int nfacctd_dtls_port;
#ifdef WITH_GNUTLS
  int nfacctd_dtls_sock;
#endif
  char *nfacctd_allow_file;
  int nfacctd_time;
  int nfacctd_time_new;
  int nfacctd_pro_rating;
  char *nfacctd_templates_file;
  char *nfacctd_templates_receiver;
  int nfacctd_templates_port;
  int nfacctd_templates_sock;
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
  int nfacctd_disable_opt_scope_check;
  int telemetry_daemon;
  int telemetry_sock;
  int telemetry_port_tcp;
  int telemetry_port_udp;
  char *telemetry_ip;
  int telemetry_udp_notif_port;
  char *telemetry_udp_notif_ip;
  int telemetry_udp_notif_nmsgs;
  int telemetry_ipv6_only;
  char *telemetry_zmq_address;
  char *telemetry_kafka_broker_host;
  int telemetry_kafka_broker_port;
  char *telemetry_kafka_topic;
  char *telemetry_kafka_config_file;
  char *telemetry_decoder;
  int telemetry_decoder_id;
  int telemetry_max_peers;
  int telemetry_peer_timeout;
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
  int telemetry_dump_workers;
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
  int bgp_daemon;
  int bgp_daemon_msglog_output;
  char *bgp_daemon_msglog_file;
  char *bgp_daemon_msglog_avro_schema_file;
  char *bgp_daemon_msglog_amqp_host;
  char *bgp_daemon_msglog_amqp_vhost;
  char *bgp_daemon_msglog_amqp_user;
  char *bgp_daemon_msglog_amqp_passwd;
  char *bgp_daemon_msglog_amqp_exchange;
  char *bgp_daemon_msglog_amqp_exchange_type;
  char *bgp_daemon_msglog_amqp_routing_key;
  int bgp_daemon_msglog_amqp_routing_key_rr;
  int bgp_daemon_msglog_amqp_persistent_msg;
  u_int32_t bgp_daemon_msglog_amqp_frame_max;
  u_int32_t bgp_daemon_msglog_amqp_heartbeat_interval;
  int bgp_daemon_msglog_amqp_retry;
  char *bgp_daemon_msglog_kafka_broker_host;
  char *bgp_daemon_msglog_kafka_topic;
  int bgp_daemon_msglog_kafka_topic_rr;
  int bgp_daemon_msglog_kafka_partition;
  char *bgp_daemon_msglog_kafka_partition_key;
  int bgp_daemon_msglog_kafka_partition_keylen;
  int bgp_daemon_msglog_kafka_broker_port;
  int bgp_daemon_msglog_kafka_retry;
  char *bgp_daemon_msglog_kafka_config_file;
  char *bgp_daemon_msglog_kafka_avro_schema_registry;
  char *bgp_daemon_id;
  char *bgp_daemon_ip;
  int bgp_daemon_ipv6_only;
  as_t bgp_daemon_as;
  int bgp_daemon_port;
  int bgp_daemon_pipe_size;
  int bgp_daemon_ipprec;
  char *bgp_daemon_allow_file;
  int bgp_daemon_max_peers;
  int bgp_daemon_aspath_radius;
  char *bgp_daemon_stdcomm_pattern;
  char *bgp_daemon_extcomm_pattern;
  char *bgp_daemon_lrgcomm_pattern;
  char *bgp_daemon_stdcomm_pattern_to_asn;
  char *bgp_daemon_lrgcomm_pattern_to_asn;
  char *bgp_blackhole_stdcomm_list;
  int bgp_daemon_peer_as_src_type;
  int bgp_daemon_src_std_comm_type;
  int bgp_daemon_src_ext_comm_type;
  int bgp_daemon_src_lrg_comm_type;
  int bgp_daemon_src_as_path_type;
  int bgp_daemon_src_local_pref_type;
  int bgp_daemon_src_med_type;
  int bgp_daemon_src_roa_type;
  int bgp_daemon_peer_as_skip_subas;
  int bgp_daemon_batch;
  int bgp_daemon_batch_interval;
  char *bgp_daemon_peer_as_src_map;
  char *bgp_daemon_src_local_pref_map;
  char *bgp_daemon_src_med_map;
  char *bgp_daemon_to_xflow_agent_map;
  char *nfacctd_flow_to_rd_map;
  int bgp_daemon_follow_default;
  struct prefix bgp_daemon_follow_nexthop[FOLLOW_BGP_NH_ENTRIES];
  int bgp_daemon_follow_nexthop_external;
  char *bgp_daemon_neighbors_file;
  char *bgp_daemon_md5_file;
  int bgp_table_peer_buckets;
  int bgp_table_per_peer_buckets;
  int bgp_table_attr_hash_buckets;
  int bgp_table_per_peer_hash;
  int bgp_table_dump_output;
  char *bgp_table_dump_file;
  char *bgp_table_dump_latest_file;
  char *bgp_table_dump_avro_schema_file;
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
  char *bgp_table_dump_kafka_avro_schema_registry;
  int bgp_table_dump_workers;
  int bgp_lg;
  char *bgp_lg_ip;
  int bgp_lg_port;
  int bgp_lg_threads;
  char *bgp_lg_user;
  char *bgp_lg_passwd;
  char *bgp_xconnect_map;
  int bgp_disable_router_id_check;
  int bmp_sock;
  int bmp_daemon;
  char *bmp_daemon_ip;
  int bmp_daemon_ipv6_only;
  int bmp_daemon_port;
  int bmp_daemon_pipe_size;
  int bmp_daemon_max_peers;
  char *bmp_daemon_allow_file;
  int bmp_daemon_ipprec;
  int bmp_daemon_batch;
  int bmp_daemon_batch_interval;
  int bmp_daemon_msglog_output;
  char *bmp_daemon_msglog_file;
  char *bmp_daemon_msglog_avro_schema_file;
  char *bmp_daemon_msglog_amqp_host;
  char *bmp_daemon_msglog_amqp_vhost;
  char *bmp_daemon_msglog_amqp_user;
  char *bmp_daemon_msglog_amqp_passwd;
  char *bmp_daemon_msglog_amqp_exchange;
  char *bmp_daemon_msglog_amqp_exchange_type;
  char *bmp_daemon_msglog_amqp_routing_key;
  int bmp_daemon_msglog_amqp_routing_key_rr;
  int bmp_daemon_msglog_amqp_persistent_msg;
  u_int32_t bmp_daemon_msglog_amqp_frame_max;
  u_int32_t bmp_daemon_msglog_amqp_heartbeat_interval;
  int bmp_daemon_msglog_amqp_retry;
  char *bmp_daemon_msglog_kafka_broker_host;
  char *bmp_daemon_msglog_kafka_topic;
  int bmp_daemon_msglog_kafka_topic_rr;
  int bmp_daemon_msglog_kafka_partition;
  char *bmp_daemon_msglog_kafka_partition_key;
  int bmp_daemon_msglog_kafka_partition_keylen;
  int bmp_daemon_msglog_kafka_broker_port;
  int bmp_daemon_msglog_kafka_retry;
  char *bmp_daemon_msglog_kafka_config_file;
  char *bmp_daemon_msglog_kafka_avro_schema_registry;
  int bmp_table_peer_buckets;
  int bmp_table_per_peer_buckets;
  int bmp_table_attr_hash_buckets;
  int bmp_table_per_peer_hash;
  int bmp_dump_output;
  int bmp_dump_workers;
  char *bmp_dump_file;
  char *bmp_dump_latest_file;
  char *bmp_dump_avro_schema_file;
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
  char *bmp_dump_kafka_avro_schema_registry;
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
  GeoIP *geoip_ipv6;
#endif
  char *geoipv2_file;
#if defined WITH_GEOIPV2
  MMDB_s geoipv2_db;
#endif
  int promisc; /* pcap_open_live() promisc parameter */
  char *clbuf; /* pcap filter */
  int pcap_protocol;
  char *pcap_savefile;
  int pcap_direction;
  int pcap_ifindex;
  char *pcap_interfaces_map;
  char *pcap_if;
  int pcap_if_wait;
  int pcap_sf_wait;
  int pcap_sf_delay;
  int pcap_sf_replay;
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
  int networks_no_mask_if_zero;
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
  int classifier_ndpi;
  u_int32_t ndpi_num_roots;
  u_int32_t ndpi_max_flows;
  int ndpi_proto_guess;
  u_int32_t ndpi_idle_scan_period;
  u_int32_t ndpi_idle_max_time;
  u_int32_t ndpi_idle_scan_budget;
  int ndpi_giveup_proto_tcp;
  int ndpi_giveup_proto_udp;
  int ndpi_giveup_proto_other;
  char *nfprobe_timeouts;
  int nfprobe_id;
  int nfprobe_hoplimit;
  int nfprobe_maxflows;
  char *nfprobe_receiver;
  int nfprobe_dtls;
  char *nfprobe_dtls_verify_cert;
  int nfprobe_version;
  char *nfprobe_engine;
  int nfprobe_peer_as;
  char *nfprobe_source_ip;
  struct host_addr nfprobe_source_ha;
  int nfprobe_ipprec;
  int nfprobe_direction;
  u_int32_t nfprobe_ifindex;
  int nfprobe_ifindex_override;
  int nfprobe_ifindex_type;
  int nfprobe_dont_cache;
  int nfprobe_tstamp_usec;
  char *sfprobe_receiver;
  char *sfprobe_agentip;
  int sfprobe_agentsubid;
  u_int64_t sfprobe_ifspeed;
  int tee_transparent;
  int tee_max_receivers;
  int tee_max_receiver_pools;
  char *tee_receivers;
  int tee_pipe_size;
  char *tee_kafka_config_file;
  int uacctd_group;
  int uacctd_nl_size;
  int uacctd_threshold;
  char *tunnel0;
  int use_ip_next_hop;
  int pcap_arista_trailer_offset;
  int pcap_arista_trailer_flag_value;
  int dump_max_writers;
  int tmp_asa_bi_flow;
  int tmp_bgp_lookup_compare_ports;
  int tmp_bgp_daemon_route_refresh;
  int tmp_bgp_daemon_origin_type_int;
  size_t thread_stack;
  char *rpki_roas_file;
  char *rpki_rtr_cache;
  int rpki_rtr_cache_version;
  int rpki_rtr_cache_pipe_size;
  int rpki_rtr_cache_ipprec;
  int bmp_daemon_parse_proxy_header;
};

/* prototypes */ 
extern void evaluate_configuration(char *, int);
extern int parse_configuration_file(char *);
extern int parse_plugin_names(char *, int, int);
extern void parse_core_process_name(char *, int, int);
extern void compose_default_plugin_name(char *, int, char *);
extern int create_plugin(char *, char *, char *);
extern int delete_plugin_by_id(int);
extern struct plugins_list_entry *search_plugin_by_pipe(int);
extern struct plugins_list_entry *search_plugin_by_pid(pid_t);
extern void sanitize_cfg(int, char *);
extern void set_default_values();

/* global vars */
extern char *cfg[LARGEBUFLEN], *cfg_cmdline[SRVBUFLEN];
extern struct custom_primitives custom_primitives_registry;
extern pm_cfgreg_t custom_primitives_type;
extern int rows;

extern char default_proc_name[];

#endif //CFG_H
