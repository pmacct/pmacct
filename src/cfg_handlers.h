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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* prototypes */
#if (!defined __CFG_HANDLERS_C)
#define EXT extern
#else
#define EXT
#endif

EXT int parse_truefalse(char *);
EXT int cfg_key_debug(char *, char *, char *);
EXT int cfg_key_syslog(char *, char *, char *);
EXT int cfg_key_logfile(char *, char *, char *);
EXT int cfg_key_pidfile(char *, char *, char *);
EXT int cfg_key_daemonize(char *, char *, char *);
EXT int cfg_key_aggregate(char *, char *, char *);
EXT int cfg_key_snaplen(char *, char *, char *);
EXT int cfg_key_aggregate_filter(char *, char *, char *);
EXT int cfg_key_pcap_filter(char *, char *, char *);
EXT int cfg_key_interface(char *, char *, char *);
EXT int cfg_key_interface_wait(char *, char *, char *);
EXT int cfg_key_files_umask(char *, char *, char *);
EXT int cfg_key_files_uid(char *, char *, char *);
EXT int cfg_key_files_gid(char *, char *, char *);
EXT int cfg_key_savefile_wait(char *, char *, char *);
EXT int cfg_key_promisc(char *, char *, char *);
EXT int cfg_key_num_protos(char *, char *, char *);
EXT int cfg_key_num_hosts(char *, char *, char *);
EXT int cfg_key_imt_path(char *, char *, char *);
EXT int cfg_key_imt_passwd(char *, char *, char *);
EXT int cfg_key_imt_buckets(char *, char *, char *);
EXT int cfg_key_imt_mem_pools_number(char *, char *, char *);
EXT int cfg_key_imt_mem_pools_size(char *, char *, char *);
EXT int cfg_key_sql_db(char *, char *, char *);
EXT int cfg_key_sql_table(char *, char *, char *);
EXT int cfg_key_sql_table_schema(char *, char *, char *);
EXT int cfg_key_sql_table_version(char *, char *, char *);
EXT int cfg_key_sql_table_type(char *, char *, char *);
EXT int cfg_key_sql_host(char *, char *, char *);
EXT int cfg_key_sql_data(char *, char *, char *);
EXT int cfg_key_sql_user(char *, char *, char *);
EXT int cfg_key_sql_passwd(char *, char *, char *);
EXT int cfg_key_sql_refresh_time(char *, char *, char *);
EXT int cfg_key_sql_startup_delay(char *, char *, char *);
EXT int cfg_key_sql_optimize_clauses(char *, char *, char *);
EXT int cfg_key_sql_history(char *, char *, char *);
EXT int cfg_key_sql_history_roundoff(char *, char *, char *);
EXT int cfg_key_sql_history_since_epoch(char *, char *, char *);
EXT int cfg_key_sql_recovery_logfile(char *, char *, char *);
EXT int cfg_key_sql_recovery_backup_host(char *, char *, char *);
EXT int cfg_key_sql_max_writers(char *, char *, char *);
EXT int cfg_key_sql_trigger_exec(char *, char *, char *);
EXT int cfg_key_sql_trigger_time(char *, char *, char *);
EXT int cfg_key_sql_cache_entries(char *, char *, char *);
EXT int cfg_key_sql_dont_try_update(char *, char *, char *);
EXT int cfg_key_sql_preprocess(char *, char *, char *);
EXT int cfg_key_sql_preprocess_type(char *, char *, char *);
EXT int cfg_key_sql_multi_values(char *, char *, char *);
EXT int cfg_key_sql_aggressive_classification(char *, char *, char *);
EXT int cfg_key_sql_locking_style(char *, char *, char *);
EXT int cfg_key_sql_use_copy(char *, char *, char *);
EXT int cfg_key_sql_delimiter(char *, char *, char *);
EXT int cfg_key_timestamps_secs(char *, char *, char *);
EXT int cfg_key_mongo_insert_batch(char *, char *, char *);
EXT int cfg_key_plugin_pipe_size(char *, char *, char *);
EXT int cfg_key_plugin_pipe_backlog(char *, char *, char *);
EXT int cfg_key_plugin_buffer_size(char *, char *, char *);
EXT int cfg_key_networks_mask(char *, char *, char *);
EXT int cfg_key_networks_file(char *, char *, char *);
EXT int cfg_key_networks_file_filter(char *, char *, char *);
EXT int cfg_key_networks_cache_entries(char *, char *, char *);
EXT int cfg_key_ports_file(char *, char *, char *);
EXT int cfg_key_refresh_maps(char *, char *, char *);
EXT int cfg_key_print_cache_entries(char *, char *, char *);
EXT int cfg_key_print_markers(char *, char *, char *);
EXT int cfg_key_print_output(char *, char *, char *);
EXT int cfg_key_print_output_file(char *, char *, char *);
EXT int cfg_key_print_output_separator(char *, char *, char *);
EXT int cfg_key_nfacctd_port(char *, char *, char *);
EXT int cfg_key_nfacctd_ip(char *, char *, char *);
EXT int cfg_key_nfacctd_allow_file(char *, char *, char *);
EXT int cfg_key_nfacctd_time_secs(char *, char *, char *);
EXT int cfg_key_nfacctd_time_new(char *, char *, char *);
EXT int cfg_key_nfacctd_as_new(char *, char *, char *);
EXT int cfg_key_nfacctd_net(char *, char *, char *);
EXT int cfg_key_nfacctd_disable_checks(char *, char *, char *);
EXT int cfg_key_nfacctd_mcast_groups(char *, char *, char *);
EXT int cfg_key_pmacctd_force_frag_handling(char *, char *, char *);
EXT int cfg_key_pmacctd_frag_buffer_size(char *, char *, char *);
EXT int cfg_key_pmacctd_flow_buffer_size(char *, char *, char *);
EXT int cfg_key_pmacctd_flow_buffer_buckets(char *, char *, char *);
EXT int cfg_key_pmacctd_conntrack_buffer_size(char *, char *, char *);
EXT int cfg_key_pmacctd_flow_lifetime(char *, char *, char *);
EXT int cfg_key_pmacctd_ext_sampling_rate(char *, char *, char *);
EXT int cfg_key_sfacctd_renormalize(char *, char *, char *);
EXT int cfg_key_pcap_savefile(char *, char *, char *);
EXT int cfg_key_pre_tag_map(char *, char *, char *);
EXT int cfg_key_pre_tag_map_entries(char *, char *, char *);
EXT int cfg_key_pre_tag_filter(char *, char *, char *);
EXT int cfg_key_pre_tag2_filter(char *, char *, char *);
EXT int cfg_key_post_tag(char *, char *, char *);
EXT int cfg_key_sampling_rate(char *, char *, char *);
EXT int cfg_key_sampling_map(char *, char *, char *);
EXT int cfg_key_classifiers(char *, char *, char *);
EXT int cfg_key_classifier_tentatives(char *, char *, char *);
EXT int cfg_key_classifier_table_num(char *, char *, char *);
EXT int cfg_key_nfprobe_timeouts(char *, char *, char *);
EXT int cfg_key_nfprobe_hoplimit(char *, char *, char *);
EXT int cfg_key_nfprobe_maxflows(char *, char *, char *);
EXT int cfg_key_nfprobe_receiver(char *, char *, char *);
EXT int cfg_key_nfprobe_version(char *, char *, char *);
EXT int cfg_key_nfprobe_engine(char *, char *, char *);
EXT int cfg_key_nfprobe_peer_as(char *, char *, char *);
EXT int cfg_key_nfprobe_source_ip(char *, char *, char *);
EXT int cfg_key_nfprobe_ip_precedence(char *, char *, char *);
EXT int cfg_key_nfprobe_direction(char *, char *, char *);
EXT int cfg_key_nfprobe_ifindex(char *, char *, char *);
EXT int cfg_key_sfprobe_receiver(char *, char *, char *);
EXT int cfg_key_sfprobe_agentip(char *, char *, char *);
EXT int cfg_key_sfprobe_agentsubid(char *, char *, char *);
EXT int cfg_key_sfprobe_ifspeed(char *, char *, char *);
EXT int cfg_key_tee_receivers(char *, char *, char *);
EXT int cfg_key_tee_transparent(char *, char *, char *);
EXT int cfg_key_tee_max_receivers(char *, char *, char *);
EXT int cfg_key_tee_max_receiver_pools(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_msglog(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_max_peers(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_ip(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_port(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_ip_precedence(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_allow_file(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_aspath_radius(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_stdcomm_pattern(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_extcomm_pattern(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_stdcomm_pattern_to_asn(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_peer_src_as_type(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_src_std_comm_type(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_src_ext_comm_type(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_src_as_path_type(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_src_local_pref_type(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_src_med_type(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_peer_as_skip_subas(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_peer_src_as_map(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_src_local_pref_map(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_src_med_map(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_to_agent_map(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_iface_to_rd_map(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_follow_default(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_follow_nexthop(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_neighbors_file(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_md5_file(char *, char *, char *);
EXT int cfg_key_nfacctd_bgp_table_peer_buckets(char *, char *, char *);
EXT int cfg_key_nfacctd_isis(char *, char *, char *);
EXT int cfg_key_nfacctd_isis_ip(char *, char *, char *);
EXT int cfg_key_nfacctd_isis_net(char *, char *, char *);
EXT int cfg_key_nfacctd_isis_iface(char *, char *, char *);
EXT int cfg_key_nfacctd_isis_mtu(char *, char *, char *);
EXT int cfg_key_nfacctd_isis_msglog(char *, char *, char *);
EXT int cfg_key_igp_daemon_map(char *, char *, char *);
EXT int cfg_key_igp_daemon_map_msglog(char *, char *, char *);
EXT int cfg_key_geoip_ipv4_file(char *, char *, char *);
EXT int cfg_key_geoip_ipv6_file(char *, char *, char *);
EXT int cfg_key_uacctd_group(char *, char *, char *);
EXT int cfg_key_uacctd_nl_size(char *, char *, char *);
EXT int cfg_key_tunnel_0(char *, char *, char *);
EXT int cfg_key_pkt_len_distrib_bins(char *, char *, char *);

EXT void parse_time(char *, char *, int *, int *);
EXT void cfg_set_aggregate(char *, u_int64_t [], u_int64_t, char *);
#undef EXT
