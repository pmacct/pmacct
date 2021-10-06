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

/* includes */
#include "pmacct.h"
#include "plugin_hooks.h"
#include "pmacct-data.h"
#include "pkt_handlers.h"

static const struct _dictionary_line dictionary[] = {
  {"debug", cfg_key_debug},
  {"debug_internal_msg", cfg_key_debug_internal_msg},
  {"syslog", cfg_key_syslog},
  {"logfile", cfg_key_logfile},
  {"pidfile", cfg_key_pidfile},
  {"daemonize", cfg_key_daemonize},
  {"aggregate", cfg_key_aggregate},
  {"aggregate_primitives", cfg_key_aggregate_primitives},
  {"cluster_name", cfg_key_cluster_name},
  {"cluster_id", cfg_key_cluster_id},
  {"redis_host", cfg_key_redis_host},
  {"redis_db", cfg_key_redis_db},
  {"snaplen", cfg_key_snaplen},
  {"propagate_signals", cfg_key_propagate_signals},
  {"aggregate_filter", cfg_key_aggregate_filter},
  {"dtls_path", cfg_key_dtls_path},
  {"promisc", cfg_key_promisc},
  {"pcap_filter", cfg_key_pcap_filter},
  {"pcap_protocol", cfg_key_pcap_protocol},
  {"pcap_savefile", cfg_key_pcap_savefile},
  {"pcap_savefile_wait", cfg_key_pcap_savefile_wait},
  {"pcap_savefile_delay", cfg_key_pcap_savefile_delay},
  {"pcap_savefile_replay", cfg_key_pcap_savefile_replay},
  {"pcap_interface", cfg_key_pcap_interface},
  {"pcap_interface_wait", cfg_key_pcap_interface_wait},
  {"pcap_direction", cfg_key_pcap_direction},
  {"pcap_ifindex", cfg_key_pcap_ifindex},
  {"pcap_interfaces_map", cfg_key_pcap_interfaces_map},
  {"pcap_arista_trailer_offset", cfg_key_pcap_arista_trailer_offset},
  {"pcap_arista_trailer_flag_value", cfg_key_pcap_arista_trailer_flag_value},
  {"core_proc_name", cfg_key_proc_name},
  {"proc_priority", cfg_key_proc_priority},
  {"pmacctd_as", cfg_key_nfacctd_as_new},
  {"uacctd_as", cfg_key_nfacctd_as_new},
  {"pmacctd_net", cfg_key_nfacctd_net},
  {"uacctd_net", cfg_key_nfacctd_net},
  {"use_ip_next_hop", cfg_key_use_ip_next_hop},
  {"thread_stack", cfg_key_thread_stack},
  {"plugins", NULL},
  {"plugin_pipe_size", cfg_key_plugin_pipe_size},
  {"plugin_buffer_size", cfg_key_plugin_buffer_size},
  {"plugin_pipe_zmq", cfg_key_plugin_pipe_zmq},
  {"plugin_pipe_zmq_retry", cfg_key_plugin_pipe_zmq_retry},
  {"plugin_pipe_zmq_profile", cfg_key_plugin_pipe_zmq_profile},
  {"plugin_pipe_zmq_hwm", cfg_key_plugin_pipe_zmq_hwm},
  {"plugin_exit_any", cfg_key_plugin_exit_any},
  {"files_umask", cfg_key_files_umask},
  {"files_uid", cfg_key_files_uid},
  {"files_gid", cfg_key_files_gid},
  {"networks_mask", cfg_key_networks_mask},
  {"networks_file", cfg_key_networks_file},
  {"networks_file_filter", cfg_key_networks_file_filter},
  {"networks_file_no_lpm", cfg_key_networks_file_no_lpm},
  {"networks_no_mask_if_zero", cfg_key_networks_no_mask_if_zero},
  {"networks_cache_entries", cfg_key_networks_cache_entries},
  {"ports_file", cfg_key_ports_file},
  {"timestamps_rfc3339", cfg_key_timestamps_rfc3339},
  {"timestamps_utc", cfg_key_timestamps_utc},
  {"timestamps_secs", cfg_key_timestamps_secs},
  {"timestamps_since_epoch", cfg_key_timestamps_since_epoch},
  {"imt_path", cfg_key_imt_path},
  {"imt_passwd", cfg_key_imt_passwd},
  {"imt_buckets", cfg_key_imt_buckets},
  {"imt_mem_pools_number", cfg_key_imt_mem_pools_number},
  {"imt_mem_pools_size", cfg_key_imt_mem_pools_size},
  {"sql_db", cfg_key_sql_db},
  {"sql_table", cfg_key_sql_table},
  {"sql_table_schema", cfg_key_sql_table_schema},
  {"sql_table_version", cfg_key_sql_table_version},
  {"sql_table_type", cfg_key_sql_table_type},
  {"sql_conn_ca_file", cfg_key_sql_conn_ca_file}, 
  {"sql_host", cfg_key_sql_host},
  {"sql_port", cfg_key_sql_port},
  {"sql_data", cfg_key_sql_data},
  {"sql_user", cfg_key_sql_user},
  {"sql_passwd", cfg_key_sql_passwd},
  {"sql_refresh_time", cfg_key_sql_refresh_time},
  {"sql_startup_delay", cfg_key_sql_startup_delay},
  {"sql_optimize_clauses", cfg_key_sql_optimize_clauses},
  {"sql_history", cfg_key_sql_history},
  {"sql_history_offset", cfg_key_sql_history_offset},
  {"sql_history_roundoff", cfg_key_sql_history_roundoff},
  {"sql_backup_host", cfg_key_sql_recovery_backup_host}, /* Legacy feature */
  {"sql_recovery_backup_host", cfg_key_sql_recovery_backup_host},
  {"sql_delimiter", cfg_key_sql_delimiter},
  {"sql_max_writers", cfg_key_dump_max_writers},
  {"sql_trigger_exec", cfg_key_sql_trigger_exec},
  {"sql_trigger_time", cfg_key_sql_trigger_time},
  {"sql_cache_entries", cfg_key_sql_cache_entries},
  {"sql_dont_try_update", cfg_key_sql_dont_try_update},
  {"sql_preprocess", cfg_key_sql_preprocess},
  {"sql_preprocess_type", cfg_key_sql_preprocess_type},
  {"sql_multi_values", cfg_key_sql_multi_values},
  {"sql_locking_style", cfg_key_sql_locking_style},
  {"sql_use_copy", cfg_key_sql_use_copy},
  {"sql_num_protos", cfg_key_num_protos},
  {"sql_num_hosts", cfg_key_num_hosts},
  {"print_refresh_time", cfg_key_sql_refresh_time},
  {"print_cache_entries", cfg_key_print_cache_entries},
  {"print_markers", cfg_key_print_markers},
  {"print_output", cfg_key_print_output},
  {"print_output_file", cfg_key_print_output_file},
  {"print_output_file_append", cfg_key_print_output_file_append},
  {"print_output_lock_file", cfg_key_print_output_lock_file},
  {"print_output_separator", cfg_key_print_output_separator},
  {"print_output_custom_lib", cfg_key_print_output_custom_lib},
  {"print_output_custom_cfg_file", cfg_key_print_output_custom_cfg_file},
  {"print_write_empty_file", cfg_key_print_write_empty_file},
  {"print_latest_file", cfg_key_print_latest_file},
  {"print_num_protos", cfg_key_num_protos},
  {"print_trigger_exec", cfg_key_sql_trigger_exec},
  {"print_history", cfg_key_sql_history},
  {"print_history_offset", cfg_key_sql_history_offset},
  {"print_history_roundoff", cfg_key_sql_history_roundoff},
  {"print_max_writers", cfg_key_dump_max_writers},
  {"print_preprocess", cfg_key_sql_preprocess},
  {"print_preprocess_type", cfg_key_sql_preprocess_type},
  {"print_startup_delay", cfg_key_sql_startup_delay},
  {"mongo_host", cfg_key_sql_host},
  {"mongo_table", cfg_key_sql_table},
  {"mongo_user", cfg_key_sql_user},
  {"mongo_passwd", cfg_key_sql_passwd},
  {"mongo_refresh_time", cfg_key_sql_refresh_time},
  {"mongo_cache_entries", cfg_key_print_cache_entries},
  {"mongo_history", cfg_key_sql_history},
  {"mongo_history_offset", cfg_key_sql_history_offset},
  {"mongo_history_roundoff", cfg_key_sql_history_roundoff},
  {"mongo_time_roundoff", cfg_key_sql_history_roundoff},
  {"mongo_trigger_exec", cfg_key_sql_trigger_exec},
  {"mongo_insert_batch", cfg_key_mongo_insert_batch},
  {"mongo_indexes_file", cfg_key_sql_table_schema},
  {"mongo_max_writers", cfg_key_dump_max_writers},
  {"mongo_preprocess", cfg_key_sql_preprocess},
  {"mongo_preprocess_type", cfg_key_sql_preprocess_type},
  {"mongo_startup_delay", cfg_key_sql_startup_delay},
  {"mongo_num_protos", cfg_key_num_protos},
  {"avro_buffer_size", cfg_key_avro_buffer_size},
  {"avro_schema_output_file", cfg_key_avro_schema_file}, /* to be discontinued */
  {"avro_schema_file", cfg_key_avro_schema_file},
  {"amqp_refresh_time", cfg_key_sql_refresh_time},
  {"amqp_history", cfg_key_sql_history},
  {"amqp_history_offset", cfg_key_sql_history_offset},
  {"amqp_history_roundoff", cfg_key_sql_history_roundoff},
  {"amqp_time_roundoff", cfg_key_sql_history_roundoff},
  {"amqp_host", cfg_key_sql_host},
  {"amqp_user", cfg_key_sql_user},
  {"amqp_passwd", cfg_key_sql_passwd},
  {"amqp_exchange", cfg_key_sql_db},
  {"amqp_exchange_type", cfg_key_amqp_exchange_type},
  {"amqp_routing_key", cfg_key_sql_table},
  {"amqp_routing_key_rr", cfg_key_amqp_routing_key_rr},
  {"amqp_persistent_msg", cfg_key_amqp_persistent_msg},
  {"amqp_frame_max", cfg_key_amqp_frame_max},
  {"amqp_cache_entries", cfg_key_print_cache_entries},
  {"amqp_max_writers", cfg_key_dump_max_writers},
  {"amqp_preprocess", cfg_key_sql_preprocess},
  {"amqp_preprocess_type", cfg_key_sql_preprocess_type},
  {"amqp_startup_delay", cfg_key_sql_startup_delay},
  {"amqp_heartbeat_interval", cfg_key_amqp_heartbeat_interval},
  {"amqp_multi_values", cfg_key_sql_multi_values},
  {"amqp_num_protos", cfg_key_num_protos},
  {"amqp_vhost", cfg_key_amqp_vhost},
  {"amqp_markers", cfg_key_print_markers},
  {"amqp_output", cfg_key_message_broker_output},
  {"amqp_avro_schema_routing_key", cfg_key_amqp_avro_schema_routing_key}, /* Legacy feature */
  {"amqp_avro_schema_refresh_time", cfg_key_amqp_avro_schema_refresh_time}, /* Legacy feature */
  {"amqp_trigger_exec", cfg_key_sql_trigger_exec},
  {"kafka_refresh_time", cfg_key_sql_refresh_time},
  {"kafka_history", cfg_key_sql_history},
  {"kafka_history_offset", cfg_key_sql_history_offset},
  {"kafka_history_roundoff", cfg_key_sql_history_roundoff},
  {"kafka_broker_host", cfg_key_sql_host},
  {"kafka_broker_port", cfg_key_kafka_broker_port},
  {"kafka_topic", cfg_key_sql_table},
  {"kafka_topic_rr", cfg_key_amqp_routing_key_rr},
  {"kafka_partition", cfg_key_kafka_partition},
  {"kafka_partition_dynamic", cfg_key_kafka_partition_dynamic},
  {"kafka_partition_key", cfg_key_kafka_partition_key},
  {"kafka_cache_entries", cfg_key_print_cache_entries},
  {"kafka_max_writers", cfg_key_dump_max_writers},
  {"kafka_preprocess", cfg_key_sql_preprocess},
  {"kafka_preprocess_type", cfg_key_sql_preprocess_type},
  {"kafka_startup_delay", cfg_key_sql_startup_delay},
  {"kafka_multi_values", cfg_key_sql_multi_values},
  {"kafka_num_protos", cfg_key_num_protos},
  {"kafka_markers", cfg_key_print_markers},
  {"kafka_output", cfg_key_message_broker_output},
  {"kafka_avro_schema_registry", cfg_key_kafka_avro_schema_registry},
  {"kafka_config_file", cfg_key_kafka_config_file},
  {"kafka_trigger_exec", cfg_key_sql_trigger_exec},
  {"nfacctd_proc_name", cfg_key_proc_name},
  {"nfacctd_port", cfg_key_nfacctd_port},
  {"nfacctd_ip", cfg_key_nfacctd_ip},
  {"nfacctd_ipv6_only", cfg_key_nfacctd_ipv6_only},
  {"nfacctd_allow_file", cfg_key_nfacctd_allow_file},
  {"nfacctd_time_secs", cfg_key_nfacctd_time_secs},
  {"nfacctd_time_new", cfg_key_nfacctd_time_new},
  {"nfacctd_as_new", cfg_key_nfacctd_as_new},
  {"nfacctd_as", cfg_key_nfacctd_as_new},
  {"nfacctd_net", cfg_key_nfacctd_net},
  {"nfacctd_mcast_groups", cfg_key_nfacctd_mcast_groups},
  {"nfacctd_peer_as", cfg_key_nfprobe_peer_as},
  {"nfacctd_pipe_size", cfg_key_nfacctd_pipe_size},
  {"nfacctd_pro_rating", cfg_key_nfacctd_pro_rating},
  {"nfacctd_templates_file", cfg_key_nfacctd_templates_file},
  {"nfacctd_templates_receiver", cfg_key_nfacctd_templates_receiver},
  {"nfacctd_templates_port", cfg_key_nfacctd_templates_port},
  {"nfacctd_account_options", cfg_key_nfacctd_account_options},
  {"nfacctd_stitching", cfg_key_nfacctd_stitching},
  {"nfacctd_ext_sampling_rate", cfg_key_pmacctd_ext_sampling_rate},
  {"nfacctd_renormalize", cfg_key_sfacctd_renormalize},
  {"nfacctd_disable_checks", cfg_key_nfacctd_disable_checks},
  {"nfacctd_disable_opt_scope_check", cfg_key_nfacctd_disable_opt_scope_check},
  {"nfacctd_kafka_broker_host", cfg_key_nfacctd_kafka_broker_host},
  {"nfacctd_kafka_broker_port", cfg_key_nfacctd_kafka_broker_port},
  {"nfacctd_kafka_topic", cfg_key_nfacctd_kafka_topic},
  {"nfacctd_kafka_config_file", cfg_key_nfacctd_kafka_config_file},
  {"nfacctd_zmq_address", cfg_key_nfacctd_zmq_address},
  {"nfacctd_dtls_port", cfg_key_nfacctd_dtls_port},
  {"pmacctd_proc_name", cfg_key_proc_name},
  {"pmacctd_force_frag_handling", cfg_key_pmacctd_force_frag_handling},
  {"pmacctd_frag_buffer_size", cfg_key_pmacctd_frag_buffer_size},
  {"pmacctd_flow_buffer_size", cfg_key_pmacctd_flow_buffer_size},
  {"pmacctd_flow_buffer_buckets", cfg_key_pmacctd_flow_buffer_buckets},
  {"pmacctd_conntrack_buffer_size", cfg_key_pmacctd_conntrack_buffer_size},
  {"pmacctd_flow_lifetime", cfg_key_pmacctd_flow_lifetime},
  {"pmacctd_flow_tcp_lifetime", cfg_key_pmacctd_flow_tcp_lifetime},
  {"pmacctd_ext_sampling_rate", cfg_key_pmacctd_ext_sampling_rate},
  {"pmacctd_pipe_size", cfg_key_nfacctd_pipe_size},
  {"pmacctd_stitching", cfg_key_nfacctd_stitching},
  {"pmacctd_renormalize", cfg_key_sfacctd_renormalize},
  {"pmacctd_nonroot", cfg_key_pmacctd_nonroot},
  {"pmacctd_time_new", cfg_key_nfacctd_time_new},
  {"uacctd_proc_name", cfg_key_proc_name},
  {"uacctd_force_frag_handling", cfg_key_pmacctd_force_frag_handling},
  {"uacctd_frag_buffer_size", cfg_key_pmacctd_frag_buffer_size},
  {"uacctd_flow_buffer_size", cfg_key_pmacctd_flow_buffer_size},
  {"uacctd_flow_buffer_buckets", cfg_key_pmacctd_flow_buffer_buckets},
  {"uacctd_conntrack_buffer_size", cfg_key_pmacctd_conntrack_buffer_size},
  {"uacctd_flow_lifetime", cfg_key_pmacctd_flow_lifetime},
  {"uacctd_flow_tcp_lifetime", cfg_key_pmacctd_flow_tcp_lifetime},
  {"uacctd_ext_sampling_rate", cfg_key_pmacctd_ext_sampling_rate},
  {"uacctd_stitching", cfg_key_nfacctd_stitching},
  {"uacctd_renormalize", cfg_key_sfacctd_renormalize},
  {"uacctd_direction", cfg_key_pcap_direction},
  {"telemetry_daemon", cfg_key_telemetry_daemon},
  {"telemetry_daemon_port_tcp", cfg_key_telemetry_port_tcp},
  {"telemetry_daemon_port_udp", cfg_key_telemetry_port_udp},
  {"telemetry_daemon_ip", cfg_key_telemetry_ip},
  {"telemetry_daemon_udp_notif_port", cfg_key_telemetry_udp_notif_port},
  {"telemetry_daemon_udp_notif_ip", cfg_key_telemetry_udp_notif_ip},
  {"telemetry_daemon_udp_notif_nmsgs", cfg_key_telemetry_udp_notif_nmsgs},
  {"telemetry_daemon_ipv6_only", cfg_key_telemetry_ipv6_only},
  {"telemetry_daemon_zmq_address", cfg_key_telemetry_zmq_address},
  {"telemetry_daemon_kafka_broker_host", cfg_key_telemetry_kafka_broker_host},
  {"telemetry_daemon_kafka_broker_port", cfg_key_telemetry_kafka_broker_port},
  {"telemetry_daemon_kafka_topic", cfg_key_telemetry_kafka_topic},
  {"telemetry_daemon_kafka_config_file", cfg_key_telemetry_kafka_config_file},
  {"telemetry_daemon_decoder", cfg_key_telemetry_decoder},
  {"telemetry_daemon_max_peers", cfg_key_telemetry_max_peers},
  {"telemetry_daemon_peer_timeout", cfg_key_telemetry_peer_timeout},
  {"telemetry_daemon_allow_file", cfg_key_telemetry_allow_file},
  {"telemetry_daemon_pipe_size", cfg_key_telemetry_pipe_size},
  {"telemetry_daemon_ipprec", cfg_key_telemetry_ip_precedence},
  {"telemetry_daemon_msglog_output", cfg_key_telemetry_msglog_output},
  {"telemetry_daemon_msglog_file", cfg_key_telemetry_msglog_file},
  {"telemetry_daemon_msglog_amqp_host", cfg_key_telemetry_msglog_amqp_host},
  {"telemetry_daemon_msglog_amqp_vhost", cfg_key_telemetry_msglog_amqp_vhost},
  {"telemetry_daemon_msglog_amqp_user", cfg_key_telemetry_msglog_amqp_user},
  {"telemetry_daemon_msglog_amqp_passwd", cfg_key_telemetry_msglog_amqp_passwd},
  {"telemetry_daemon_msglog_amqp_exchange", cfg_key_telemetry_msglog_amqp_exchange},
  {"telemetry_daemon_msglog_amqp_exchange_type", cfg_key_telemetry_msglog_amqp_exchange_type},
  {"telemetry_daemon_msglog_amqp_routing_key", cfg_key_telemetry_msglog_amqp_routing_key},
  {"telemetry_daemon_msglog_amqp_routing_key_rr", cfg_key_telemetry_msglog_amqp_routing_key_rr},
  {"telemetry_daemon_msglog_amqp_persistent_msg", cfg_key_telemetry_msglog_amqp_persistent_msg},
  {"telemetry_daemon_msglog_amqp_frame_max", cfg_key_telemetry_msglog_amqp_frame_max},
  {"telemetry_daemon_msglog_amqp_heartbeat_interval", cfg_key_telemetry_msglog_amqp_heartbeat_interval},
  {"telemetry_daemon_msglog_amqp_retry", cfg_key_telemetry_msglog_amqp_retry},
  {"telemetry_daemon_msglog_kafka_broker_host", cfg_key_telemetry_msglog_kafka_broker_host},
  {"telemetry_daemon_msglog_kafka_broker_port", cfg_key_telemetry_msglog_kafka_broker_port},
  {"telemetry_daemon_msglog_kafka_topic", cfg_key_telemetry_msglog_kafka_topic},
  {"telemetry_daemon_msglog_kafka_topic_rr", cfg_key_telemetry_msglog_kafka_topic_rr},
  {"telemetry_daemon_msglog_kafka_partition", cfg_key_telemetry_msglog_kafka_partition},
  {"telemetry_daemon_msglog_kafka_partition_key", cfg_key_telemetry_msglog_kafka_partition_key},
  {"telemetry_daemon_msglog_kafka_retry", cfg_key_telemetry_msglog_kafka_retry},
  {"telemetry_daemon_msglog_kafka_config_file", cfg_key_telemetry_msglog_kafka_config_file},
  {"telemetry_dump_output", cfg_key_telemetry_dump_output},
  {"telemetry_dump_file", cfg_key_telemetry_dump_file},
  {"telemetry_dump_latest_file", cfg_key_telemetry_dump_latest_file},
  {"telemetry_dump_refresh_time", cfg_key_telemetry_dump_refresh_time},
  {"telemetry_dump_amqp_host", cfg_key_telemetry_dump_amqp_host},
  {"telemetry_dump_amqp_vhost", cfg_key_telemetry_dump_amqp_vhost},
  {"telemetry_dump_amqp_user", cfg_key_telemetry_dump_amqp_user},
  {"telemetry_dump_amqp_passwd", cfg_key_telemetry_dump_amqp_passwd},
  {"telemetry_dump_amqp_exchange", cfg_key_telemetry_dump_amqp_exchange},
  {"telemetry_dump_amqp_exchange_type", cfg_key_telemetry_dump_amqp_exchange_type},
  {"telemetry_dump_amqp_routing_key", cfg_key_telemetry_dump_amqp_routing_key},
  {"telemetry_dump_amqp_routing_key_rr", cfg_key_telemetry_dump_amqp_routing_key_rr},
  {"telemetry_dump_amqp_persistent_msg", cfg_key_telemetry_dump_amqp_persistent_msg},
  {"telemetry_dump_amqp_frame_max", cfg_key_telemetry_dump_amqp_frame_max},
  {"telemetry_dump_amqp_heartbeat_interval", cfg_key_telemetry_dump_amqp_heartbeat_interval},
  {"telemetry_dump_kafka_broker_host", cfg_key_telemetry_dump_kafka_broker_host},
  {"telemetry_dump_kafka_broker_port", cfg_key_telemetry_dump_kafka_broker_port},
  {"telemetry_dump_kafka_topic", cfg_key_telemetry_dump_kafka_topic},
  {"telemetry_dump_kafka_topic_rr", cfg_key_telemetry_dump_kafka_topic_rr},
  {"telemetry_dump_kafka_partition", cfg_key_telemetry_dump_kafka_partition},
  {"telemetry_dump_kafka_partition_key", cfg_key_telemetry_dump_kafka_partition_key},
  {"telemetry_dump_kafka_config_file", cfg_key_telemetry_dump_kafka_config_file},
  {"telemetry_dump_workers", cfg_key_telemetry_dump_workers},
  {"maps_refresh", cfg_key_maps_refresh},
  {"maps_index", cfg_key_maps_index},
  {"maps_entries", cfg_key_maps_entries},
  {"maps_row_len", cfg_key_maps_row_len},
  {"pre_tag_map", cfg_key_pre_tag_map},	
  {"pre_tag_filter", cfg_key_pre_tag_filter},
  {"pre_tag2_filter", cfg_key_pre_tag2_filter},
  {"pre_tag_label_filter", cfg_key_pre_tag_label_filter},
  {"post_tag", cfg_key_post_tag},
  {"post_tag2", cfg_key_post_tag2},
  {"sampling_rate", cfg_key_sampling_rate},
  {"sampling_map", cfg_key_sampling_map},	
  {"sfacctd_proc_name", cfg_key_proc_name},
  {"sfacctd_port", cfg_key_nfacctd_port},
  {"sfacctd_ip", cfg_key_nfacctd_ip},
  {"sfacctd_allow_file", cfg_key_nfacctd_allow_file},
  {"sfacctd_as_new", cfg_key_nfacctd_as_new},
  {"sfacctd_as", cfg_key_nfacctd_as_new},
  {"sfacctd_net", cfg_key_nfacctd_net},
  {"sfacctd_peer_as", cfg_key_nfprobe_peer_as},
  {"sfacctd_time_new", cfg_key_nfacctd_time_new},
  {"sfacctd_pipe_size", cfg_key_nfacctd_pipe_size},
  {"sfacctd_renormalize", cfg_key_sfacctd_renormalize},
  {"sfacctd_disable_checks", cfg_key_nfacctd_disable_checks},
  {"sfacctd_mcast_groups", cfg_key_nfacctd_mcast_groups},
  {"sfacctd_stitching", cfg_key_nfacctd_stitching},
  {"sfacctd_ext_sampling_rate", cfg_key_pmacctd_ext_sampling_rate},
  {"sfacctd_counter_output", cfg_key_sfacctd_counter_output},
  {"sfacctd_counter_file", cfg_key_sfacctd_counter_file},
  {"sfacctd_counter_amqp_host", cfg_key_sfacctd_counter_amqp_host},
  {"sfacctd_counter_amqp_vhost", cfg_key_sfacctd_counter_amqp_vhost},
  {"sfacctd_counter_amqp_user", cfg_key_sfacctd_counter_amqp_user},
  {"sfacctd_counter_amqp_passwd", cfg_key_sfacctd_counter_amqp_passwd},
  {"sfacctd_counter_amqp_exchange", cfg_key_sfacctd_counter_amqp_exchange},
  {"sfacctd_counter_amqp_exchange_type", cfg_key_sfacctd_counter_amqp_exchange_type},
  {"sfacctd_counter_amqp_routing_key", cfg_key_sfacctd_counter_amqp_routing_key},
  {"sfacctd_counter_amqp_persistent_msg", cfg_key_sfacctd_counter_amqp_persistent_msg},
  {"sfacctd_counter_amqp_frame_max", cfg_key_sfacctd_counter_amqp_frame_max},
  {"sfacctd_counter_amqp_heartbeat_interval", cfg_key_sfacctd_counter_amqp_heartbeat_interval},
  {"sfacctd_counter_amqp_retry", cfg_key_sfacctd_counter_amqp_retry},
  {"sfacctd_counter_kafka_broker_host", cfg_key_sfacctd_counter_kafka_broker_host},
  {"sfacctd_counter_kafka_broker_port", cfg_key_sfacctd_counter_kafka_broker_port},
  {"sfacctd_counter_kafka_topic", cfg_key_sfacctd_counter_kafka_topic},
  {"sfacctd_counter_kafka_partition", cfg_key_sfacctd_counter_kafka_partition},
  {"sfacctd_counter_kafka_partition_key", cfg_key_sfacctd_counter_kafka_partition_key},
  {"sfacctd_counter_kafka_retry", cfg_key_sfacctd_counter_kafka_retry},
  {"sfacctd_counter_kafka_config_file", cfg_key_sfacctd_counter_kafka_config_file},
  {"sfacctd_kafka_broker_host", cfg_key_nfacctd_kafka_broker_host},
  {"sfacctd_kafka_broker_port", cfg_key_nfacctd_kafka_broker_port},
  {"sfacctd_kafka_topic", cfg_key_nfacctd_kafka_topic},
  {"sfacctd_kafka_config_file", cfg_key_nfacctd_kafka_config_file},
  {"sfacctd_zmq_address", cfg_key_nfacctd_zmq_address},
  {"classifiers", cfg_key_classifiers},
  {"classifier_tentatives", cfg_key_classifier_tentatives},
  {"classifier_table_num", cfg_key_classifier_table_num},
#if defined (WITH_NDPI)
  {"classifier_num_roots", cfg_key_classifier_ndpi_num_roots},
  {"classifier_max_flows", cfg_key_classifier_ndpi_max_flows},
  {"classifier_proto_guess", cfg_key_classifier_ndpi_proto_guess},
  {"classifier_idle_scan_period", cfg_key_classifier_ndpi_idle_scan_period},
  {"classifier_idle_max_time", cfg_key_classifier_ndpi_idle_max_time},
  {"classifier_idle_scan_budget", cfg_key_classifier_ndpi_idle_scan_budget},
  {"classifier_giveup_proto_tcp", cfg_key_classifier_ndpi_giveup_proto_tcp},
  {"classifier_giveup_proto_udp", cfg_key_classifier_ndpi_giveup_proto_udp},
  {"classifier_giveup_proto_other", cfg_key_classifier_ndpi_giveup_proto_other},
#endif
  {"nfprobe_timeouts", cfg_key_nfprobe_timeouts},
  {"nfprobe_hoplimit", cfg_key_nfprobe_hoplimit},
  {"nfprobe_maxflows", cfg_key_nfprobe_maxflows},
  {"nfprobe_receiver", cfg_key_nfprobe_receiver},
  {"nfprobe_dtls", cfg_key_nfprobe_dtls},
  {"nfprobe_dtls_verify_cert", cfg_key_nfprobe_dtls_verify_cert},
  {"nfprobe_engine", cfg_key_nfprobe_engine},
  {"nfprobe_version", cfg_key_nfprobe_version},
  {"nfprobe_peer_as", cfg_key_nfprobe_peer_as},
  {"nfprobe_source_ip", cfg_key_nfprobe_source_ip},
  {"nfprobe_ipprec", cfg_key_nfprobe_ip_precedence},
  {"nfprobe_direction", cfg_key_nfprobe_direction},
  {"nfprobe_ifindex", cfg_key_nfprobe_ifindex},
  {"nfprobe_dont_cache", cfg_key_nfprobe_dont_cache},
  {"nfprobe_ifindex_override", cfg_key_nfprobe_ifindex_override},
  {"nfprobe_tstamp_usec", cfg_key_nfprobe_tstamp_usec},
  {"sfprobe_receiver", cfg_key_sfprobe_receiver},
  {"sfprobe_agentip", cfg_key_sfprobe_agentip},
  {"sfprobe_agentsubid", cfg_key_sfprobe_agentsubid},
  {"sfprobe_peer_as", cfg_key_nfprobe_peer_as},
  {"sfprobe_source_ip", cfg_key_nfprobe_source_ip},
  {"sfprobe_ipprec", cfg_key_nfprobe_ip_precedence},
  {"sfprobe_direction", cfg_key_nfprobe_direction},
  {"sfprobe_ifindex", cfg_key_nfprobe_ifindex},
  {"sfprobe_ifspeed", cfg_key_sfprobe_ifspeed},
  {"sfprobe_ifindex_override", cfg_key_nfprobe_ifindex_override},
  {"tee_receivers", cfg_key_tee_receivers},
  {"tee_source_ip", cfg_key_nfprobe_source_ip},
  {"tee_transparent", cfg_key_tee_transparent},
  {"tee_max_receivers", cfg_key_tee_max_receivers},
  {"tee_max_receiver_pools", cfg_key_tee_max_receiver_pools},
  {"tee_ipprec", cfg_key_nfprobe_ip_precedence},
  {"tee_pipe_size", cfg_key_tee_pipe_size},
  {"tee_kafka_config_file", cfg_key_tee_kafka_config_file},
  {"bgp_daemon", cfg_key_bgp_daemon},
  {"bgp_daemon_ip", cfg_key_bgp_daemon_ip},
  {"bgp_daemon_ipv6_only", cfg_key_bgp_daemon_ipv6_only},
  {"bgp_daemon_id", cfg_key_bgp_daemon_id},
  {"bgp_daemon_as", cfg_key_bgp_daemon_as},
  {"bgp_daemon_port", cfg_key_bgp_daemon_port},
  {"bgp_daemon_pipe_size", cfg_key_bgp_daemon_pipe_size},
  {"bgp_daemon_max_peers", cfg_key_bgp_daemon_max_peers},
  {"bgp_daemon_msglog_output", cfg_key_bgp_daemon_msglog_output},
  {"bgp_daemon_msglog_file", cfg_key_bgp_daemon_msglog_file},
  {"bgp_daemon_msglog_avro_schema_file", cfg_key_bgp_daemon_msglog_avro_schema_file},
  {"bgp_daemon_msglog_amqp_host", cfg_key_bgp_daemon_msglog_amqp_host},
  {"bgp_daemon_msglog_amqp_vhost", cfg_key_bgp_daemon_msglog_amqp_vhost},
  {"bgp_daemon_msglog_amqp_user", cfg_key_bgp_daemon_msglog_amqp_user},
  {"bgp_daemon_msglog_amqp_passwd", cfg_key_bgp_daemon_msglog_amqp_passwd},
  {"bgp_daemon_msglog_amqp_exchange", cfg_key_bgp_daemon_msglog_amqp_exchange},
  {"bgp_daemon_msglog_amqp_exchange_type", cfg_key_bgp_daemon_msglog_amqp_exchange_type},
  {"bgp_daemon_msglog_amqp_routing_key", cfg_key_bgp_daemon_msglog_amqp_routing_key},
  {"bgp_daemon_msglog_amqp_routing_key_rr", cfg_key_bgp_daemon_msglog_amqp_routing_key_rr},
  {"bgp_daemon_msglog_amqp_persistent_msg", cfg_key_bgp_daemon_msglog_amqp_persistent_msg},
  {"bgp_daemon_msglog_amqp_frame_max", cfg_key_bgp_daemon_msglog_amqp_frame_max},
  {"bgp_daemon_msglog_amqp_heartbeat_interval", cfg_key_bgp_daemon_msglog_amqp_heartbeat_interval},
  {"bgp_daemon_msglog_amqp_retry", cfg_key_bgp_daemon_msglog_amqp_retry},
  {"bgp_daemon_msglog_kafka_broker_host", cfg_key_bgp_daemon_msglog_kafka_broker_host},
  {"bgp_daemon_msglog_kafka_broker_port", cfg_key_bgp_daemon_msglog_kafka_broker_port},
  {"bgp_daemon_msglog_kafka_topic", cfg_key_bgp_daemon_msglog_kafka_topic},
  {"bgp_daemon_msglog_kafka_topic_rr", cfg_key_bgp_daemon_msglog_kafka_topic_rr},
  {"bgp_daemon_msglog_kafka_partition", cfg_key_bgp_daemon_msglog_kafka_partition},
  {"bgp_daemon_msglog_kafka_partition_key", cfg_key_bgp_daemon_msglog_kafka_partition_key},
  {"bgp_daemon_msglog_kafka_retry", cfg_key_bgp_daemon_msglog_kafka_retry},
  {"bgp_daemon_msglog_kafka_config_file", cfg_key_bgp_daemon_msglog_kafka_config_file},
  {"bgp_daemon_msglog_kafka_avro_schema_registry", cfg_key_bgp_daemon_msglog_kafka_avro_schema_registry},
  {"bgp_daemon_allow_file", cfg_key_bgp_daemon_allow_file},
  {"bgp_daemon_ipprec", cfg_key_bgp_daemon_ip_precedence},
  {"bgp_daemon_md5_file", cfg_key_bgp_daemon_md5_file},
  {"bgp_daemon_batch", cfg_key_bgp_daemon_batch},
  {"bgp_daemon_batch_interval", cfg_key_bgp_daemon_batch_interval},
  {"bgp_aspath_radius", cfg_key_bgp_daemon_aspath_radius},
  {"bgp_stdcomm_pattern", cfg_key_bgp_daemon_stdcomm_pattern},
  {"bgp_extcomm_pattern", cfg_key_bgp_daemon_extcomm_pattern},
  {"bgp_lrgcomm_pattern", cfg_key_bgp_daemon_lrgcomm_pattern},
  {"bgp_stdcomm_pattern_to_asn", cfg_key_bgp_daemon_stdcomm_pattern_to_asn},
  {"bgp_lrgcomm_pattern_to_asn", cfg_key_bgp_daemon_lrgcomm_pattern_to_asn},
  {"bgp_blackhole_stdcomm_list", cfg_key_bgp_blackhole_stdcomm_list},
  {"bgp_peer_as_skip_subas", cfg_key_bgp_daemon_peer_as_skip_subas},
  {"bgp_peer_src_as_map", cfg_key_bgp_daemon_peer_src_as_map},
  {"bgp_src_local_pref_map", cfg_key_bgp_daemon_src_local_pref_map},
  {"bgp_src_med_map", cfg_key_bgp_daemon_src_med_map},
  {"bgp_peer_src_as_type", cfg_key_bgp_daemon_peer_src_as_type},
  {"bgp_src_std_comm_type", cfg_key_bgp_daemon_src_std_comm_type},
  {"bgp_src_ext_comm_type", cfg_key_bgp_daemon_src_ext_comm_type},
  {"bgp_src_lrg_comm_type", cfg_key_bgp_daemon_src_lrg_comm_type},
  {"bgp_src_as_path_type", cfg_key_bgp_daemon_src_as_path_type},
  {"bgp_src_local_pref_type", cfg_key_bgp_daemon_src_local_pref_type},
  {"bgp_src_med_type", cfg_key_bgp_daemon_src_med_type},
  {"bgp_src_roa_type", cfg_key_bgp_daemon_src_roa_type},
  {"bgp_agent_map", cfg_key_bgp_daemon_to_xflow_agent_map},
  {"bgp_follow_default", cfg_key_bgp_daemon_follow_default},
  {"bgp_follow_nexthop", cfg_key_bgp_daemon_follow_nexthop},
  {"bgp_follow_nexthop_external", cfg_key_bgp_daemon_follow_nexthop_external},
  {"bgp_disable_router_id_check", cfg_key_bgp_daemon_disable_router_id_check},
  {"bgp_neighbors_file", cfg_key_bgp_daemon_neighbors_file},
  {"bgp_table_peer_buckets", cfg_key_bgp_daemon_table_peer_buckets},
  {"bgp_table_per_peer_buckets", cfg_key_bgp_daemon_table_per_peer_buckets},
  {"bgp_table_attr_hash_buckets", cfg_key_bgp_daemon_table_attr_hash_buckets},
  {"bgp_table_per_peer_hash", cfg_key_bgp_daemon_table_per_peer_hash},
  {"bgp_table_dump_output", cfg_key_bgp_daemon_table_dump_output},
  {"bgp_table_dump_file", cfg_key_bgp_daemon_table_dump_file},
  {"bgp_table_dump_latest_file", cfg_key_bgp_daemon_table_dump_latest_file},
  {"bgp_table_dump_avro_schema_file", cfg_key_bgp_daemon_table_dump_avro_schema_file},
  {"bgp_table_dump_refresh_time", cfg_key_bgp_daemon_table_dump_refresh_time},
  {"bgp_table_dump_amqp_host", cfg_key_bgp_daemon_table_dump_amqp_host},
  {"bgp_table_dump_amqp_vhost", cfg_key_bgp_daemon_table_dump_amqp_vhost},
  {"bgp_table_dump_amqp_user", cfg_key_bgp_daemon_table_dump_amqp_user},
  {"bgp_table_dump_amqp_passwd", cfg_key_bgp_daemon_table_dump_amqp_passwd},
  {"bgp_table_dump_amqp_exchange", cfg_key_bgp_daemon_table_dump_amqp_exchange},
  {"bgp_table_dump_amqp_exchange_type", cfg_key_bgp_daemon_table_dump_amqp_exchange_type},
  {"bgp_table_dump_amqp_routing_key", cfg_key_bgp_daemon_table_dump_amqp_routing_key},
  {"bgp_table_dump_amqp_routing_key_rr", cfg_key_bgp_daemon_table_dump_amqp_routing_key_rr},
  {"bgp_table_dump_amqp_persistent_msg", cfg_key_bgp_daemon_table_dump_amqp_persistent_msg},
  {"bgp_table_dump_amqp_frame_max", cfg_key_bgp_daemon_table_dump_amqp_frame_max},
  {"bgp_table_dump_amqp_heartbeat_interval", cfg_key_bgp_daemon_table_dump_amqp_heartbeat_interval},
  {"bgp_table_dump_kafka_broker_host", cfg_key_bgp_daemon_table_dump_kafka_broker_host},
  {"bgp_table_dump_kafka_broker_port", cfg_key_bgp_daemon_table_dump_kafka_broker_port},
  {"bgp_table_dump_kafka_topic", cfg_key_bgp_daemon_table_dump_kafka_topic},
  {"bgp_table_dump_kafka_topic_rr", cfg_key_bgp_daemon_table_dump_kafka_topic_rr},
  {"bgp_table_dump_kafka_partition", cfg_key_bgp_daemon_table_dump_kafka_partition},
  {"bgp_table_dump_kafka_partition_key", cfg_key_bgp_daemon_table_dump_kafka_partition_key},
  {"bgp_table_dump_kafka_config_file", cfg_key_bgp_daemon_table_dump_kafka_config_file},
  {"bgp_table_dump_kafka_avro_schema_registry", cfg_key_bgp_daemon_table_dump_kafka_avro_schema_registry},
  {"bgp_table_dump_workers", cfg_key_bgp_daemon_table_dump_workers},
  {"bgp_daemon_lg", cfg_key_bgp_lg},
  {"bgp_daemon_lg_ip", cfg_key_bgp_lg_ip},
  {"bgp_daemon_lg_port", cfg_key_bgp_lg_port},
  {"bgp_daemon_lg_threads", cfg_key_bgp_lg_threads},
  {"bgp_daemon_lg_user", cfg_key_bgp_lg_user},
  {"bgp_daemon_lg_passwd", cfg_key_bgp_lg_passwd},
  {"bgp_daemon_xconnect_map", cfg_key_bgp_xconnect_map},
  {"bmp_daemon", cfg_key_bmp_daemon},
  {"bmp_daemon_ip", cfg_key_bmp_daemon_ip},
  {"bmp_daemon_ipv6_only", cfg_key_bmp_daemon_ipv6_only},
  {"bmp_daemon_port", cfg_key_bmp_daemon_port},
  {"bmp_daemon_pipe_size", cfg_key_bmp_daemon_pipe_size},
  {"bmp_daemon_max_peers", cfg_key_bmp_daemon_max_peers},
  {"bmp_daemon_allow_file", cfg_key_bmp_daemon_allow_file},
  {"bmp_daemon_ipprec", cfg_key_bmp_daemon_ip_precedence},
  {"bmp_daemon_batch", cfg_key_bmp_daemon_batch},
  {"bmp_daemon_batch_interval", cfg_key_bmp_daemon_batch_interval},
  {"bmp_agent_map", cfg_key_bgp_daemon_to_xflow_agent_map},
  {"bmp_daemon_msglog_output", cfg_key_bmp_daemon_msglog_output},
  {"bmp_daemon_msglog_file", cfg_key_bmp_daemon_msglog_file},
  {"bmp_daemon_msglog_avro_schema_file", cfg_key_bmp_daemon_msglog_avro_schema_file},
  {"bmp_daemon_msglog_amqp_host", cfg_key_bmp_daemon_msglog_amqp_host},
  {"bmp_daemon_msglog_amqp_vhost", cfg_key_bmp_daemon_msglog_amqp_vhost},
  {"bmp_daemon_msglog_amqp_user", cfg_key_bmp_daemon_msglog_amqp_user},
  {"bmp_daemon_msglog_amqp_passwd", cfg_key_bmp_daemon_msglog_amqp_passwd},
  {"bmp_daemon_msglog_amqp_exchange", cfg_key_bmp_daemon_msglog_amqp_exchange},
  {"bmp_daemon_msglog_amqp_exchange_type", cfg_key_bmp_daemon_msglog_amqp_exchange_type},
  {"bmp_daemon_msglog_amqp_routing_key", cfg_key_bmp_daemon_msglog_amqp_routing_key},
  {"bmp_daemon_msglog_amqp_routing_key_rr", cfg_key_bmp_daemon_msglog_amqp_routing_key_rr},
  {"bmp_daemon_msglog_amqp_persistent_msg", cfg_key_bmp_daemon_msglog_amqp_persistent_msg},
  {"bmp_daemon_msglog_amqp_frame_max", cfg_key_bmp_daemon_msglog_amqp_frame_max},
  {"bmp_daemon_msglog_amqp_heartbeat_interval", cfg_key_bmp_daemon_msglog_amqp_heartbeat_interval},
  {"bmp_daemon_msglog_amqp_retry", cfg_key_bmp_daemon_msglog_amqp_retry},
  {"bmp_daemon_msglog_kafka_broker_host", cfg_key_bmp_daemon_msglog_kafka_broker_host},
  {"bmp_daemon_msglog_kafka_broker_port", cfg_key_bmp_daemon_msglog_kafka_broker_port},
  {"bmp_daemon_msglog_kafka_topic", cfg_key_bmp_daemon_msglog_kafka_topic},
  {"bmp_daemon_msglog_kafka_topic_rr", cfg_key_bmp_daemon_msglog_kafka_topic_rr},
  {"bmp_daemon_msglog_kafka_partition", cfg_key_bmp_daemon_msglog_kafka_partition},
  {"bmp_daemon_msglog_kafka_partition_key", cfg_key_bmp_daemon_msglog_kafka_partition_key},
  {"bmp_daemon_msglog_kafka_retry", cfg_key_bmp_daemon_msglog_kafka_retry},
  {"bmp_daemon_msglog_kafka_config_file", cfg_key_bmp_daemon_msglog_kafka_config_file},
  {"bmp_daemon_msglog_kafka_avro_schema_registry", cfg_key_bmp_daemon_msglog_kafka_avro_schema_registry},
  {"bmp_table_peer_buckets", cfg_key_bmp_daemon_table_peer_buckets},
  {"bmp_table_per_peer_buckets", cfg_key_bmp_daemon_table_per_peer_buckets},
  {"bmp_table_attr_hash_buckets", cfg_key_bmp_daemon_table_attr_hash_buckets},
  {"bmp_table_per_peer_hash", cfg_key_bmp_daemon_table_per_peer_hash},
  {"bmp_dump_output", cfg_key_bmp_daemon_dump_output},
  {"bmp_dump_file", cfg_key_bmp_daemon_dump_file},
  {"bmp_dump_latest_file", cfg_key_bmp_daemon_dump_latest_file},
  {"bmp_dump_workers", cfg_key_bmp_daemon_dump_workers},
  {"bmp_dump_avro_schema_file", cfg_key_bmp_daemon_dump_avro_schema_file},
  {"bmp_dump_refresh_time", cfg_key_bmp_daemon_dump_refresh_time},
  {"bmp_dump_amqp_host", cfg_key_bmp_daemon_dump_amqp_host},
  {"bmp_dump_amqp_vhost", cfg_key_bmp_daemon_dump_amqp_vhost},
  {"bmp_dump_amqp_user", cfg_key_bmp_daemon_dump_amqp_user},
  {"bmp_dump_amqp_passwd", cfg_key_bmp_daemon_dump_amqp_passwd},
  {"bmp_dump_amqp_exchange", cfg_key_bmp_daemon_dump_amqp_exchange},
  {"bmp_dump_amqp_exchange_type", cfg_key_bmp_daemon_dump_amqp_exchange_type},
  {"bmp_dump_amqp_routing_key", cfg_key_bmp_daemon_dump_amqp_routing_key},
  {"bmp_dump_amqp_routing_key_rr", cfg_key_bmp_daemon_dump_amqp_routing_key_rr},
  {"bmp_dump_amqp_persistent_msg", cfg_key_bmp_daemon_dump_amqp_persistent_msg},
  {"bmp_dump_amqp_frame_max", cfg_key_bmp_daemon_dump_amqp_frame_max},
  {"bmp_dump_amqp_heartbeat_interval", cfg_key_bmp_daemon_dump_amqp_heartbeat_interval},
  {"bmp_dump_kafka_broker_host", cfg_key_bmp_daemon_dump_kafka_broker_host},
  {"bmp_dump_kafka_broker_port", cfg_key_bmp_daemon_dump_kafka_broker_port},
  {"bmp_dump_kafka_topic", cfg_key_bmp_daemon_dump_kafka_topic},
  {"bmp_dump_kafka_topic_rr", cfg_key_bmp_daemon_dump_kafka_topic_rr},
  {"bmp_dump_kafka_partition", cfg_key_bmp_daemon_dump_kafka_partition},
  {"bmp_dump_kafka_partition_key", cfg_key_bmp_daemon_dump_kafka_partition_key},
  {"bmp_dump_kafka_config_file", cfg_key_bmp_daemon_dump_kafka_config_file},
  {"bmp_dump_kafka_avro_schema_registry", cfg_key_bmp_daemon_dump_kafka_avro_schema_registry},
  {"bmp_daemon_parse_proxy_header", cfg_key_nfacctd_bmp_daemon_parse_proxy_header},
  {"rpki_roas_file", cfg_key_rpki_roas_file},
  {"rpki_rtr_cache", cfg_key_rpki_rtr_cache},
  {"rpki_rtr_cache_version", cfg_key_rpki_rtr_cache_version},
  {"rpki_rtr_cache_pipe_size", cfg_key_rpki_rtr_cache_pipe_size},
  {"rpki_rtr_cache_ipprec", cfg_key_rpki_rtr_cache_ip_precedence},
  {"flow_to_rd_map", cfg_key_nfacctd_flow_to_rd_map},
  {"isis_daemon", cfg_key_nfacctd_isis},
  {"isis_daemon_ip", cfg_key_nfacctd_isis_ip},
  {"isis_daemon_net", cfg_key_nfacctd_isis_net},
  {"isis_daemon_iface", cfg_key_nfacctd_isis_iface},
  {"isis_daemon_mtu", cfg_key_nfacctd_isis_mtu},
  {"isis_daemon_msglog", cfg_key_nfacctd_isis_msglog},
  {"igp_daemon", cfg_key_nfacctd_isis},
  {"igp_daemon_map", cfg_key_igp_daemon_map},
  {"igp_daemon_map_msglog", cfg_key_igp_daemon_map_msglog},
#if defined WITH_GEOIP
  {"geoip_ipv4_file", cfg_key_geoip_ipv4_file},
  {"geoip_ipv6_file", cfg_key_geoip_ipv6_file},
#endif
#if defined WITH_GEOIPV2
  {"geoipv2_file", cfg_key_geoipv2_file},
#endif
  {"uacctd_group", cfg_key_uacctd_group},
  {"uacctd_nl_size", cfg_key_uacctd_nl_size},
  {"uacctd_threshold", cfg_key_uacctd_threshold},
  {"tunnel_0", cfg_key_tunnel_0},
  {"tmp_asa_bi_flow", cfg_key_tmp_asa_bi_flow},
  {"tmp_bgp_lookup_compare_ports", cfg_key_tmp_bgp_lookup_compare_ports},
  {"tmp_bgp_daemon_route_refresh", cfg_key_tmp_bgp_daemon_route_refresh},
  {"tmp_bgp_daemon_origin_type_int", cfg_key_tmp_bgp_daemon_origin_type_int},
  {"", NULL}
};

static struct plugin_type_entry plugin_types_list[] = {
  {PLUGIN_ID_CORE, 	"core", 	NULL},
  {PLUGIN_ID_MEMORY, 	"memory", 	imt_plugin},
  {PLUGIN_ID_PRINT,	"print",	print_plugin},
  {PLUGIN_ID_NFPROBE,	"nfprobe",	nfprobe_plugin},
  {PLUGIN_ID_SFPROBE,	"sfprobe",	sfprobe_plugin},
#ifdef WITH_MYSQL
  {PLUGIN_ID_MYSQL,	"mysql",	mysql_plugin},
#endif
#ifdef WITH_PGSQL
  {PLUGIN_ID_PGSQL,	"pgsql",	pgsql_plugin},
#endif
#ifdef WITH_SQLITE3
  {PLUGIN_ID_SQLITE3,	"sqlite3",	sqlite3_plugin},
#endif
#ifdef WITH_MONGODB
  {PLUGIN_ID_UNKNOWN,	"mongodb",		mongodb_legacy_warning}, /* Legacy plugin */
  {PLUGIN_ID_MONGODB,  	"mongodb_legacy",	mongodb_plugin}, /* Legacy plugin */
#endif
#ifdef WITH_RABBITMQ
  {PLUGIN_ID_AMQP,	"amqp",		amqp_plugin},
#endif
#ifdef WITH_KAFKA
  {PLUGIN_ID_KAFKA,     "kafka",        kafka_plugin},
#endif
  {PLUGIN_ID_TEE,	"tee",		tee_plugin},
  {PLUGIN_ID_UNKNOWN,	"",		NULL},
};

//Global variables
char *cfg[LARGEBUFLEN], *cfg_cmdline[SRVBUFLEN];
struct custom_primitives custom_primitives_registry;
pm_cfgreg_t custom_primitives_type;
int rows;
char default_proc_name[] = "default";

/* evaluate_configuration() handles all supported configuration
   keys and inserts them in configuration structure of plugins */
void evaluate_configuration(char *filename, int rows)
{
  char *key, *value, *name, *delim;
  int index = 0, dindex, valid_line, key_found = 0, res;

  while (index < rows) {
    if (*cfg[index] == '\0') valid_line = FALSE;
    else valid_line = TRUE; 

    if (valid_line) {
      /* debugging the line if required */
      if (debug) Log(LOG_DEBUG, "DEBUG: [%s] %s\n", filename, cfg[index]);

      /* splitting key, value and name */
      delim = strchr(cfg[index], ':');
      *delim = '\0';
      key = cfg[index];
      value = delim+1;

      delim = strchr(key, '[');
      if (delim) {
        *delim = '\0';
        name = delim+1;
        delim = strchr(name, ']');
        *delim = '\0';
      }
      else name = NULL;

      /* parsing keys */
      for (dindex = 0; strcmp(dictionary[dindex].key, ""); dindex++) {
        if (!strcmp(dictionary[dindex].key, key)) {
	  res = FALSE;
          if ((*dictionary[dindex].func)) {
	    res = (*dictionary[dindex].func)(filename, name, value);
	    if (res < 0) Log(LOG_WARNING, "WARN: [%s:%u] Invalid value. Ignored.\n", filename, index+1);
	    else if (!res) Log(LOG_WARNING, "WARN: [%s:%u] Unknown symbol '%s'. Ignored.\n", filename, index+1, name);
	  }
	  else Log(LOG_WARNING, "WARN: [%s:%u] Unable to handle key: %s. Ignored.\n", filename, index+1, key);
	  key_found = TRUE;
	  break;
        }
	else key_found = FALSE;
      }

      if (!key_found) Log(LOG_WARNING, "WARN: [%s:%u] Unknown key: %s. Ignored.\n", filename, index+1, key);
    }

    index++;
  }
}

/* parse_configuration_file() reads configuration file
   and stores its content in an array; then creates
   plugin structures and parses supported config keys */
int parse_configuration_file(char *filename)
{
  struct stat st;
  char localbuf[10240];
  char cmdline [] = "cmdline"; 
  FILE *file;
  int num = 0, cmdlineflag = FALSE, rows_cmdline = rows, idx, ret;
  rows = 0;

  /* NULL filename means we don't have a configuration file; 1st stage: read from
     file and store lines into a first char* array; merge commandline options, if
     required, placing them at the tail - in order to override directives placed
     in the configuration file */
  if (filename) { 
    ret = stat(filename, &st);
    if (ret < 0) {
      Log(LOG_ERR, "ERROR: [%s] file not found.\n", filename);
      return ERR;
    }
    else {
      if (!S_ISREG(st.st_mode)) {
	Log(LOG_ERR, "ERROR: [%s] path is not a regular file.\n", filename);
	return ERR;
      }
    }

    if ((file = fopen(filename, "r"))) {
      while (!feof(file)) {
        if (rows == LARGEBUFLEN) {
	  Log(LOG_ERR, "ERROR: [%s] maximum number of %d lines reached.\n", filename, LARGEBUFLEN);
	  break;
        }
	memset(localbuf, 0, sizeof(localbuf));
        if (fgets(localbuf, sizeof(localbuf), file) == NULL) break;	
        else {
	  localbuf[sizeof(localbuf)-1] = '\0';
          cfg[rows] = malloc(strlen(localbuf)+2);
	  if (!cfg[rows]) {
	    Log(LOG_ERR, "ERROR: [%s] malloc() failed (parse_configuration_file). Exiting.\n", filename);
	    exit(1);
	  }
          strcpy(cfg[rows], localbuf);
          cfg[rows][strlen(localbuf)+1] = '\0';
          rows++;
        } 
      }
    }
    fclose(file);
  }
  else {
    filename = cmdline;
    cmdlineflag = TRUE;
  }

  if (rows_cmdline) {
    for (idx = 0; idx < rows_cmdline && (rows+idx) < LARGEBUFLEN; idx++) {
      cfg[rows+idx] = cfg_cmdline[idx];
    }
    rows += idx;
  }

  /* 2nd stage: sanitize lines */
  sanitize_cfg(rows, filename);

  /* 3rd stage: plugin structures creation; we discard
     plugin names if 'pmacctd' has been invoked commandline;
     if any plugin has been activated we default to a single
     'imt' plugin */ 
  if (!cmdlineflag) parse_core_process_name(filename, rows, FALSE);
  else parse_core_process_name(filename, rows, TRUE);

  if (!cmdlineflag) num = parse_plugin_names(filename, rows, FALSE);
  else num = parse_plugin_names(filename, rows, TRUE);

  if (!num && config.acct_type < ACCT_FWPLANE_MAX) {
    Log(LOG_WARNING, "WARN: [%s] No plugin has been activated; defaulting to in-memory table.\n", filename); 
    num = create_plugin(filename, "default_memory", "memory");
  }

  if (debug) {
    struct plugins_list_entry *list = plugins_list;
    
    while (list) {
      Log(LOG_DEBUG, "DEBUG: [%s] plugin name/type: '%s'/'%s'.\n", filename, list->name, list->type.string);
      list = list->next;
    }
  }

  /* 4th stage: setting some default value */
  set_default_values();
  
  /* 5th stage: parsing keys and building configurations */ 
  evaluate_configuration(filename, rows);

  return SUCCESS;
}

void sanitize_cfg(int rows, char *filename)
{
  int rindex = 0, len;
  char localbuf[10240];

  while (rindex < rows) {
    memset(localbuf, 0, 10240);

    /* checking the whole line: if it's a comment starting with
       '!', it will be removed */
    if (iscomment(cfg[rindex])) memset(cfg[rindex], 0, strlen(cfg[rindex]));

    /* checking the whole line: if it's void, it will be removed */
    if (isblankline(cfg[rindex])) memset(cfg[rindex], 0, strlen(cfg[rindex]));

    /* 
       a pair of syntax checks on the whole line:
       - does the line contain at least a ':' verb ?
       - are the square brackets weighted both in key and value ?
    */
    len = strlen(cfg[rindex]);
    if (len) {
      int symbol = FALSE, cindex = 0, got_first = 0, got_first_colon = 0;

      if (!strchr(cfg[rindex], ':')) {
	Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: missing ':'. Exiting.\n", filename, rindex+1); 
	exit(1);
      }

      while(cindex <= len) {
        if (cfg[rindex][cindex] == '[') symbol++;
        else if (cfg[rindex][cindex] == ']') {
	  symbol--;
	  got_first++;
	}
	
	if (cfg[rindex][cindex] == ':' && !got_first_colon) {
	  got_first_colon = TRUE;

	  if (symbol) {
	    Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: illegal brackets. Exiting.\n", filename, rindex+1);
	    exit(1);
	  }
	}

	if (cfg[rindex][cindex] == '\0') {
	  if (symbol && !got_first) {
            Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: not weighted brackets (1). Exiting.\n", filename, rindex+1);
	    exit(1);
	  }
	}

	if (symbol < 0 && !got_first) {
	  Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: not weighted brackets (2). Exiting.\n", filename, rindex+1);
	  exit(1);
	}

	if (symbol > 1 && !got_first) {
	  Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: nested symbols not allowed. Exiting.\n", filename, rindex+1);
	  exit(1);
	}
	
	cindex++;
      }
    }

    /* checking the whole line: erasing unwanted spaces from key;
       trimming start/end spaces from value; symbols will be left
       untouched */
    len = strlen(cfg[rindex]);
    if (len) {
      int symbol = FALSE, value = FALSE, cindex = 0, lbindex = 0;
      char *valueptr = NULL;

      while(cindex <= len) {
	if (!value) {
          if (cfg[rindex][cindex] == '[') symbol++;
          else if (cfg[rindex][cindex] == ']') symbol--;
	  else if (cfg[rindex][cindex] == ':') {
	    value++;
	    valueptr = &localbuf[lbindex+1];
	  }
	}
        if ((!symbol) && (!value)) {
	  if (!isspace(cfg[rindex][cindex])) {
	    localbuf[lbindex] = cfg[rindex][cindex]; 
	    lbindex++;
	  }
        }
        else {
	  localbuf[lbindex] = cfg[rindex][cindex];
	  lbindex++;
        }
        cindex++;
      }
      localbuf[lbindex] = '\0';
      trim_spaces(valueptr);
      strcpy(cfg[rindex], localbuf);
    }

    /* checking key field: each symbol must refer to a key */
    len = strlen(cfg[rindex]);
    if (len) { 
      int symbol = FALSE, key = FALSE, cindex = 0;

      while (cindex < rows) {
        if (cfg[rindex][cindex] == '[') symbol++;
	else if (cfg[rindex][cindex] == ']') {
	  symbol--;
	  key--;
	}

	if (cfg[rindex][cindex] == ':') break;

	if (!symbol) {
	  if (isalpha(cfg[rindex][cindex])) key = TRUE;
	}
	else {
	  if (!key) {
            Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: symbol not referring to any key. Exiting.\n", filename, rindex+1);
	    exit(1);
	  }
	}
        cindex++;
      }
    }


    /* checking key field: does a key still exist ? */
    len = strlen(cfg[rindex]);
    if (len) {
      if (cfg[rindex][0] == ':') {
	Log(LOG_ERR, "ERROR: [%s:%u] Syntax error: missing key. Exiting.\n", filename, rindex+1);
	exit(1);
      }
    }

    /* checking key field: converting key to lower chars */ 
    len = strlen(cfg[rindex]);
    if (len) {
      int symbol = FALSE, cindex = 0;

      while(cindex <= len) {
        if (cfg[rindex][cindex] == '[') symbol++;
	else if (cfg[rindex][cindex] == ']') symbol--;

	if (cfg[rindex][cindex] == ':') break;
	if (!symbol) {
	  if (isalpha(cfg[rindex][cindex]))
	    cfg[rindex][cindex] = tolower(cfg[rindex][cindex]);
	}
	cindex++;
      }
    }

    rindex++;
  }
}

void parse_core_process_name(char *filename, int rows, int ignore_names)
{
  int index = 0, found = 0;
  char key[SRVBUFLEN], name[SRVBUFLEN], *start, *end;

  /* searching for 'core_proc_name' key */
  while (index < rows) {
    memset(key, 0, SRVBUFLEN);
    start = NULL; end = NULL;

    start = cfg[index];
    end = strchr(cfg[index], ':');
    if (end > start) {
      strlcpy(key, cfg[index], (end-start)+1);
      if (!strncmp(key, "core_proc_name", sizeof("core_proc_name"))) {
        start = end+1;
        strlcpy(name, start, SRVBUFLEN);
	found = TRUE;
        break;
      }
    }
    index++;
  }

  if (!found || ignore_names) create_plugin(filename, "default", "core");
  else create_plugin(filename, name, "core");
}

/* parse_plugin_names() leaves cfg array untouched: parses the key 'plugins'
   if it exists and creates the plugins linked list */ 
int parse_plugin_names(char *filename, int rows, int ignore_names)
{
  int index = 0, num = 0, found = 0, default_name = FALSE;
  char *start, *end, *start_name, *end_name;
  char key[SRVBUFLEN], value[10240], token[SRVBUFLEN], name[SRVBUFLEN];

  /* searching for 'plugins' key */
  while (index < rows) {
    memset(key, 0, SRVBUFLEN);
    start = NULL; end = NULL;

    start = cfg[index];
    end = strchr(cfg[index], ':');
    if (end > start) {
      strlcpy(key, cfg[index], (end-start)+1); 
      if (!strncmp(key, "plugins", sizeof("plugins"))) {
	start = end+1;
	strcpy(value, start); 
	found = TRUE;
	break;
      }
    }
    index++;
  }

  if (!found) return 0;

  /* parsing declared plugins */
  start = value;
  while (*end != '\0') {
    memset(token, 0, SRVBUFLEN);
    if (!(end = strchr(start, ','))) end = strchr(start, '\0');
    if (end > start) {
      strlcpy(token, start, (end-start)+1);
      if ((start_name = strchr(token, '[')) && (end_name = strchr(token, ']'))) {
        if (end_name > (start_name+1)) {
          strlcpy(name, (start_name+1), (end_name-start_name));
	  trim_spaces(name);
	  *start_name = '\0';
	}
      }
      else default_name = TRUE;
	
      /* Having already plugins name and type, we'll filter out reserved symbols */
      trim_spaces(token);
      lower_string(token);
      if (!strcmp(token, "core")) {
        Log(LOG_ERR, "ERROR: [%s] plugins of type 'core' are not allowed. Exiting.\n", filename);
        exit(1);
      }

      if (!ignore_names) {
        if (default_name) compose_default_plugin_name(name, SRVBUFLEN, token);
        if (create_plugin(filename, name, token)) num++;
      }
      else {
        compose_default_plugin_name(name, SRVBUFLEN, token);
        if (create_plugin(filename, name, token)) num++;
      }
    }
    start = end+1;
  }

  /* having already processed it, we erase 'plugins' line */
  memset(cfg[index], 0, strlen(cfg[index]));

  return num;
}

/* rough and dirty function to assign default values to
   configuration file of each plugin */
void set_default_values()
{
  struct plugins_list_entry *list = plugins_list;

  while (list) {
    list->cfg.promisc = TRUE;
    list->cfg.maps_refresh = TRUE;

    list = list->next;
  }
}

void compose_default_plugin_name(char *out, int outlen, char *type)
{
  strcpy(out, "default");
  strcat(out, "_");
  strncat(out, type, (outlen - 10));
}

int create_plugin(char *filename, char *name, char *type)
{
  struct plugins_list_entry *plugin, *ptr;
  struct plugin_type_entry *ptype = NULL;
  int index = 0, id = 0;

  /* searching for a valid known plugin type */
  while(strcmp(plugin_types_list[index].string, "")) {
    if (!strcmp(type, plugin_types_list[index].string)) ptype = &plugin_types_list[index];
    index++;
  }

  if (!ptype) {
    Log(LOG_ERR, "ERROR: [%s] Unknown plugin type: %s. Ignoring.\n", filename, type);
    return FALSE;
  }

  /* checks */
  if (plugins_list) {
    id = 0;
    ptr = plugins_list;

    while (ptr) {
      /* plugin id */
      if (ptr->id > id) id = ptr->id;

      /* dupes */
      if (!strcmp(name, ptr->name)) {
        Log(LOG_WARNING, "WARN: [%s] another plugin with the same name '%s' already exists. Preserving first.\n", filename, name);
        return FALSE;
      }
      ptr = ptr->next;
    }
    id++;
  }

  /* creating a new plugin structure */
  plugin = (struct plugins_list_entry *) malloc(sizeof(struct plugins_list_entry));
  if (!plugin) {
    Log(LOG_ERR, "ERROR: [%s] malloc() failed (create_plugin). Exiting.\n", filename);
    exit(1);
  }

  memset(plugin, 0, sizeof(struct plugins_list_entry));
  
  strcpy(plugin->name, name);
  plugin->id = id;
  memcpy(&plugin->type, ptype, sizeof(struct plugin_type_entry));
  plugin->next = NULL;

  /* inserting our object in plugin's linked list */
  if (plugins_list) {
    ptr = plugins_list;
    while(ptr->next) ptr = ptr->next; 
    ptr->next = plugin;
  }
  else plugins_list = plugin;

  return TRUE;
}

int delete_plugin_by_id(int id)
{
  struct plugins_list_entry *list = plugins_list;
  struct plugins_list_entry *aux = plugins_list;
  int highest_id = 0;

  if (id == 0) return ERR;

  while (list) {
    if (list->id == id) {
      aux->next = list->next;
      free(list);
      list = aux;
    }
    else {
      if (list->id > highest_id) highest_id = list->id; 
    }
    aux = list;
    list = list->next; 
  } 

  return highest_id;
}

struct plugins_list_entry *search_plugin_by_pipe(int pipe)
{
  struct plugins_list_entry *list = plugins_list;

  if (pipe < 0) return NULL;

  while (list) {
    if (list->pipe[1] == pipe) return list; 
    else list = list->next; 
  }

  return NULL;
}

struct plugins_list_entry *search_plugin_by_pid(pid_t pid)
{
  struct plugins_list_entry *list = plugins_list;

  if (pid <= 0) return NULL;

  while (list) {
    if (list->pid == pid) return list;
    else list = list->next;
  }

  return NULL;
}
