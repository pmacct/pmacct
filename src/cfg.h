/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2009 by Paolo Lucente
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

/* defines */
#define CFG_LINE_LEN(x) (SRVBUFLEN-strlen(x))

/* structures */
struct _dictionary_line {
  char key[SRVBUFLEN];
  int (*func)(char *, char *, char *);
};

struct configuration {
  u_int64_t what_to_count;
  u_int64_t nfprobe_what_to_count;
  char *name;
  char *type;
  int sock;
  int acct_type; 
  int data_type; 
  int pipe_size;
  int buffer_size;
  int handle_fragments;
  int handle_flows;
  int frag_bufsz;
  int flow_bufsz;
  int flow_hashsz;
  int conntrack_bufsz;
  int flow_lifetime;
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
  int sql_history_howmany; /* internal */
  int sql_history_since_epoch;
  int sql_startup_delay;
  int sql_cache_entries;
  int sql_dont_try_update;
  char *sql_history_roundoff;
  char *sql_recovery_logfile;
  int sql_max_writers;
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
  int print_refresh_time;
  int print_cache_entries;
  int print_markers;
  int nfacctd_port;
  char *nfacctd_ip;
  char *nfacctd_allow_file;
  int nfacctd_time;
  int nfacctd_as;
  int sfacctd_renormalize;
  int nfacctd_disable_checks;
  int nfacctd_sql_log;
  int nfacctd_bgp;
  int nfacctd_bgp_msglog;
  char *nfacctd_bgp_ip;
  int nfacctd_bgp_port;
  int nfacctd_bgp_max_peers;
  int nfacctd_bgp_aspath_radius;
  char *nfacctd_bgp_stdcomm_pattern;
  char *nfacctd_bgp_extcomm_pattern;
  int nfacctd_bgp_peer_as_src_type;
  char *nfacctd_bgp_peer_as_src_map;
  char *nfacctd_bgp_to_agent_map;
  int nfacctd_bgp_follow_default;
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
  int networks_cache_entries;
  char *ports_file;
  int refresh_maps;
  char *a_filter;
  int bpfp_a_num;
  struct bpf_program *bpfp_a_table[AGG_FILTER_ENTRIES];
  struct pretag_filter ptf;
  char *pre_tag_map;
  int pre_tag_map_entries;
  pm_id_t post_tag;
  int sampling_rate;
  char *syslog;
  int debug;
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
  char *sfprobe_receiver;
  char *sfprobe_agentip;
  int sfprobe_agentsubid;
  int flow_handling_threads;
};

struct plugin_type_entry {
  int id;
  char string[10];
  void (*func)(int, struct configuration *, void *);
};

struct plugins_list_entry {
  int id;
  pid_t pid;
  char name[SRVBUFLEN];
  struct configuration cfg;
  int pipe[2];
  struct plugin_type_entry type;
  struct plugins_list_entry *next;
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
EXT int create_plugin(char *, char *, char *);
EXT int delete_plugin_by_id(int);
EXT struct plugins_list_entry *search_plugin_by_pipe(int);
EXT struct plugins_list_entry *search_plugin_by_pid(pid_t);
EXT void sanitize_cfg(int, char *);
EXT void set_default_values();

/* global vars */
EXT char *cfg[SRVBUFLEN], *cfg_cmdline[SRVBUFLEN];
EXT int rows;
#undef EXT
