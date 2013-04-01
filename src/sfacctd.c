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

/* 
    sflow v2/v4/v5 routines are based on sFlow toolkit 3.8 which is 
    Copyright (C) InMon Corporation 2001 ALL RIGHTS RESERVED
*/

/* defines */
#define __SFACCTD_C

/* includes */
#include "pmacct.h"
#include "sflow.h"
#include "sfacctd.h"
#include "pretag_handlers.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "ip_flow.h"
#include "classifier.h"
#include "net_aggr.h"
#include "bgp/bgp_packet.h"
#include "bgp/bgp.h"

/* variables to be exported away */
int debug;
struct configuration config; /* global configuration */ 
struct plugins_list_entry *plugins_list = NULL; /* linked list of each plugin configuration */ 
struct channels_list_entry channels_list[MAX_N_PLUGINS]; /* communication channels: core <-> plugins */
int have_num_memory_pools; /* global getopt() stuff */
pid_t failed_plugins[MAX_N_PLUGINS]; /* plugins failed during startup phase */

/* Functions */
void usage_daemon(char *prog_name)
{
  printf("%s (%s)\n", SFACCTD_USAGE_HEADER, PMACCT_BUILD);
  printf("Usage: %s [ -D | -d ] [ -L IP address ] [ -l port ] [ -c primitive [ , ... ] ] [ -P plugin [ , ... ] ]\n", prog_name);
  printf("       %s [ -f config_file ]\n", prog_name);
  printf("       %s [ -h ]\n", prog_name);
  printf("\nGeneral options:\n");
  printf("  -h  \tShow this page\n");
  printf("  -L  \tBind to the specified IP address\n");
  printf("  -l  \tListen on the specified UDP port\n");
  printf("  -f  \tLoad configuration from the specified file\n");
  printf("  -c  \t[ src_mac | dst_mac | vlan | src_host | dst_host | src_net | dst_net | src_port | dst_port |\n\t tos | proto | src_as | dst_as | sum_mac | sum_host | sum_net | sum_as | sum_port | tag |\n\t tag2 | flows | class | tcpflags | in_iface | out_iface | src_mask | dst_mask | cos | etype |\n\t sampling_rate | src_host_country | dst_host_country | pkt_len_distrib | timestamp_start |\n\t none ]\n\tAggregation string (DEFAULT: src_host)\n");
  printf("  -D  \tDaemonize\n"); 
  printf("  -n  \tPath to a file containing Network definitions\n");
  printf("  -o  \tPath to a file containing Port definitions\n");
  printf("  -P  \t[ memory | print | mysql | pgsql | sqlite3 | mongodb | tee ] \n\tActivate plugin\n"); 
  printf("  -d  \tEnable debug\n");
  printf("  -S  \t[ auth | mail | daemon | kern | user | local[0-7] ] \n\ttLog to the specified syslog facility\n");
  printf("  -F  \tWrite Core Process PID into the specified file\n");
  printf("  -R  \tRenormalize sampled data\n");
  printf("  -u  \tLeave IP protocols in numerical format\n");
  printf("\nMemory plugin (-P memory) options:\n");
  printf("  -p  \tSocket for client-server communication (DEFAULT: /tmp/collect.pipe)\n");
  printf("  -b  \tNumber of buckets\n");
  printf("  -m  \tNumber of memory pools\n");
  printf("  -s  \tMemory pool size\n");
  printf("\nPostgreSQL (-P pgsql)/MySQL (-P mysql)/SQLite (-P sqlite3) plugin options:\n");
  printf("  -r  \tRefresh time (in seconds)\n");
  printf("  -v  \t[ 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 ] \n\tTable version\n");
  printf("\nPrint plugin (-P print) plugin options:\n");
  printf("  -r  \tRefresh time (in seconds)\n");
  printf("  -O  \t[ formatted | csv ] \n\tOutput format\n");
  printf("\n");
  printf("  See QUICKSTART or visit http://wiki.pmacct.net/ for examples.\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}


int main(int argc,char **argv, char **envp)
{
  struct plugins_list_entry *list;
  struct plugin_requests req;
  struct packet_ptrs_vector pptrs;
  char config_file[SRVBUFLEN];
  unsigned char sflow_packet[SFLOW_MAX_MSG_SIZE];
  int logf, rc, yes=1, allowed;
  struct host_addr addr;
  struct hosts_table allow;
  struct id_table idt;
  struct id_table bpas_table;
  struct id_table blp_table;
  struct id_table bmed_table;
  struct id_table biss_table;
  struct id_table bta_table;
  struct id_table bitr_table;
  struct id_table sampling_table;
  u_int32_t idx;
  u_int16_t ret;
  SFSample spp;

#if defined ENABLE_IPV6
  struct sockaddr_storage server, client;
  struct ipv6_mreq multi_req6;
#else
  struct sockaddr server, client;
#endif
  int clen = sizeof(client), slen;
  struct ip_mreq multi_req4;

  unsigned char dummy_packet[64]; 
  unsigned char dummy_packet_vlan[64]; 
  unsigned char dummy_packet_mpls[128]; 
  unsigned char dummy_packet_vlan_mpls[128]; 
  struct pcap_pkthdr dummy_pkthdr;
  struct pcap_pkthdr dummy_pkthdr_vlan;
  struct pcap_pkthdr dummy_pkthdr_mpls;
  struct pcap_pkthdr dummy_pkthdr_vlan_mpls;

#if defined ENABLE_IPV6
  unsigned char dummy_packet6[92]; 
  unsigned char dummy_packet_vlan6[92]; 
  unsigned char dummy_packet_mpls6[128]; 
  unsigned char dummy_packet_vlan_mpls6[128]; 
  struct pcap_pkthdr dummy_pkthdr6;
  struct pcap_pkthdr dummy_pkthdr_vlan6;
  struct pcap_pkthdr dummy_pkthdr_mpls6;
  struct pcap_pkthdr dummy_pkthdr_vlan_mpls6;
#endif

  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp; 

  umask(077);
  compute_once();

  /* a bunch of default definitions */ 
  have_num_memory_pools = FALSE;
  reload_map = FALSE;
  tag_map_allocated = FALSE;
  bpas_map_allocated = FALSE;
  blp_map_allocated = FALSE;
  bmed_map_allocated = FALSE;
  biss_map_allocated = FALSE;
  bta_map_allocated = FALSE;
  bitr_map_allocated = FALSE;
  bta_map_caching = TRUE;
  sampling_map_caching = TRUE;
  find_id_func = SF_find_id;

  data_plugins = 0;
  tee_plugins = 0;
  xflow_status_table_entries = 0;
  xflow_tot_bad_datagrams = 0;
  errflag = 0;

  memset(cfg_cmdline, 0, sizeof(cfg_cmdline));
  memset(&server, 0, sizeof(server));
  memset(&config, 0, sizeof(struct configuration));
  memset(&config_file, 0, sizeof(config_file));
  memset(&failed_plugins, 0, sizeof(failed_plugins));
  memset(&pptrs, 0, sizeof(pptrs));
  memset(&req, 0, sizeof(req));
  memset(&spp, 0, sizeof(spp));
  memset(&class, 0, sizeof(class));
  memset(&xflow_status_table, 0, sizeof(xflow_status_table));

  memset(&idt, 0, sizeof(idt));
  memset(&bpas_table, 0, sizeof(bpas_table));
  memset(&blp_table, 0, sizeof(blp_table));
  memset(&bmed_table, 0, sizeof(bmed_table));
  memset(&biss_table, 0, sizeof(biss_table));
  memset(&bta_table, 0, sizeof(bta_table));
  memset(&bitr_table, 0, sizeof(bitr_table));
  memset(&sampling_table, 0, sizeof(sampling_table));
  memset(&reload_map_tstamp, 0, sizeof(reload_map_tstamp));
  config.acct_type = ACCT_SF;

  rows = 0;
  glob_pcapt = NULL;

  /* getting commandline values */
  while (!errflag && ((cp = getopt(argc, argv, ARGS_SFACCTD)) != -1)) {
    cfg_cmdline[rows] = malloc(SRVBUFLEN);
    switch (cp) {
    case 'L':
      strlcpy(cfg_cmdline[rows], "sfacctd_ip: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'l':
      strlcpy(cfg_cmdline[rows], "sfacctd_port: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'P':
      strlcpy(cfg_cmdline[rows], "plugins: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'D':
      strlcpy(cfg_cmdline[rows], "daemonize: true", SRVBUFLEN);
      rows++;
      break;
    case 'd':
      debug = TRUE;
      strlcpy(cfg_cmdline[rows], "debug: true", SRVBUFLEN);
      rows++;
      break;
    case 'n':
      strlcpy(cfg_cmdline[rows], "networks_file: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'o':
      strlcpy(cfg_cmdline[rows], "ports_file: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'O':
      strlcpy(cfg_cmdline[rows], "print_output: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'u':
      strlcpy(cfg_cmdline[rows], "print_num_protos: true", SRVBUFLEN);
      rows++;
      break;
    case 'f':
      strlcpy(config_file, optarg, sizeof(config_file));
      break;
    case 'F':
      strlcpy(cfg_cmdline[rows], "pidfile: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'c':
      strlcpy(cfg_cmdline[rows], "aggregate: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'b':
      strlcpy(cfg_cmdline[rows], "imt_buckets: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'm':
      strlcpy(cfg_cmdline[rows], "imt_mem_pools_number: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      have_num_memory_pools = TRUE;
      rows++;
      break;
    case 'p':
      strlcpy(cfg_cmdline[rows], "imt_path: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'r':
      strlcpy(cfg_cmdline[rows], "sql_refresh_time: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'v':
      strlcpy(cfg_cmdline[rows], "sql_table_version: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 's':
      strlcpy(cfg_cmdline[rows], "imt_mem_pools_size: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'S':
      strlcpy(cfg_cmdline[rows], "syslog: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'R':
      strlcpy(cfg_cmdline[rows], "sfacctd_renormalize: true", SRVBUFLEN);
      rows++;
      break;
    case 'h':
      usage_daemon(argv[0]);
      exit(0);
      break;
    default:
      usage_daemon(argv[0]);
      exit(1);
      break;
    }
  }

  /* post-checks and resolving conflicts */
  if (strlen(config_file)) {
    if (parse_configuration_file(config_file) != SUCCESS) 
      exit(1);
  }
  else {
    if (parse_configuration_file(NULL) != SUCCESS)
      exit(1);
  }
    
  /* XXX: glue; i'm conscious it's a dirty solution from an engineering viewpoint;
     someday later i'll fix this */
  list = plugins_list;
  while(list) {
    list->cfg.acct_type = ACCT_SF;
    set_default_preferences(&list->cfg);
    if (!strcmp(list->name, "default") && !strcmp(list->type.string, "core")) { 
      memcpy(&config, &list->cfg, sizeof(struct configuration)); 
      config.name = list->name;
      config.type = list->type.string;
    }
    list = list->next;
  }

  if (config.files_umask) umask(config.files_umask);

  if (config.daemon) {
    list = plugins_list;
    while (list) {
      if (!strcmp(list->type.string, "print")) printf("WARN ( default/core ): Daemonizing. Hmm, bye bye screen.\n");
      list = list->next;
    }
    if (debug || config.debug)
      printf("WARN ( default/core ): debug is enabled; forking in background. Console logging will get lost.\n"); 
    daemonize();
  }

  initsetproctitle(argc, argv, envp);
  if (config.syslog) {
    logf = parse_log_facility(config.syslog);
    if (logf == ERR) {
      config.syslog = NULL;
      printf("WARN ( default/core ): specified syslog facility is not supported; logging to console.\n");
    }
    else openlog(NULL, LOG_PID, logf);
    Log(LOG_INFO, "INFO ( default/core ): Start logging ...\n");
  }

  if (config.logfile)
  {
    config.logfile_fd = open_logfile(config.logfile);
    list = plugins_list;
    while (list) {
      list->cfg.logfile_fd = config.logfile_fd ;
      list = list->next;
    }
  }


  /* Enforcing policies over aggregation methods */
  list = plugins_list;
  while (list) {
    if (list->type.id != PLUGIN_ID_CORE) {  
      /* applies to all plugins */
      if (list->cfg.sampling_rate && config.ext_sampling_rate) {
        Log(LOG_ERR, "ERROR ( default/core ): Internal packet sampling and external packet sampling are mutual exclusive.\n");
        exit(1);
      }

      if (list->type.id == PLUGIN_ID_NFPROBE || list->type.id == PLUGIN_ID_SFPROBE) {
        Log(LOG_ERR, "ERROR ( default/core ): 'nfprobe' and 'sfprobe' plugins not supported in 'sfacctd'.\n");
        exit(1);
      }
      else if (list->type.id == PLUGIN_ID_TEE) {
        tee_plugins++;
	list->cfg.what_to_count = COUNT_NONE;
        list->cfg.data_type = PIPE_TYPE_MSG;
      }
      else {
	list->cfg.data_type = PIPE_TYPE_METADATA;

        if (list->cfg.what_to_count_2 & (COUNT_POST_NAT_SRC_HOST|COUNT_POST_NAT_DST_HOST|
                        COUNT_POST_NAT_SRC_PORT|COUNT_POST_NAT_DST_PORT|COUNT_NAT_EVENT|
                        COUNT_TIMESTAMP_START|COUNT_TIMESTAMP_END))
          list->cfg.data_type |= PIPE_TYPE_NAT;

	evaluate_sums(&list->cfg.what_to_count, list->name, list->type.string);
	if (!list->cfg.what_to_count && !list->cfg.what_to_count_2) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): defaulting to SRC HOST aggregation.\n", list->name, list->type.string);
	  list->cfg.what_to_count |= COUNT_SRC_HOST;
	}
	if (list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) {
	  if (!list->cfg.networks_file && list->cfg.nfacctd_as & NF_AS_NEW) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation was selected but NO 'networks_file' specified. Exiting...\n\n", list->name, list->type.string);
	    exit(1);
	  }
          if (!list->cfg.nfacctd_bgp && list->cfg.nfacctd_as == NF_AS_BGP) {
            Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation selected but 'bgp_daemon' is not enabled. Exiting...\n\n", list->name, list->type.string);
            exit(1);
	  }
          if (list->cfg.nfacctd_as & NF_AS_FALLBACK && list->cfg.networks_file)
            list->cfg.nfacctd_as |= NF_AS_NEW;
        }
        if (list->cfg.what_to_count & (COUNT_SRC_NET|COUNT_DST_NET|COUNT_SUM_NET|COUNT_SRC_NMASK|COUNT_DST_NMASK|COUNT_PEER_DST_IP)) {
          if (!list->cfg.nfacctd_net) {
            if (list->cfg.networks_file) list->cfg.nfacctd_net |= NF_NET_NEW;
            if (list->cfg.networks_mask) list->cfg.nfacctd_net |= NF_NET_STATIC;
            if (!list->cfg.nfacctd_net) list->cfg.nfacctd_net = NF_NET_KEEP;
          }
          else {
            if ((list->cfg.nfacctd_net == NF_NET_NEW && !list->cfg.networks_file) ||
                (list->cfg.nfacctd_net == NF_NET_STATIC && !list->cfg.networks_mask) ||
                (list->cfg.nfacctd_net == NF_NET_BGP && !list->cfg.nfacctd_bgp) ||
                (list->cfg.nfacctd_net == NF_NET_IGP && !list->cfg.nfacctd_isis)) {
              Log(LOG_ERR, "ERROR ( %s/%s ): network aggregation selected but none of 'bgp_daemon', 'isis_daemon', 'networks_file', 'networks_mask' is specified. Exiting ...\n\n", list->name, list->type.string);
              exit(1);
            }
            if (list->cfg.nfacctd_net & NF_NET_FALLBACK && list->cfg.networks_file)
              list->cfg.nfacctd_net |= NF_NET_NEW;
          }
        }
	if (list->cfg.what_to_count & COUNT_CLASS && !list->cfg.classifiers_path) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): 'class' aggregation selected but NO 'classifiers' key specified. Exiting...\n\n", list->name, list->type.string);
	  exit(1);
	}

	bgp_config_checks(&list->cfg);

	data_plugins++;
	list->cfg.what_to_count |= COUNT_COUNTERS;
      }
    }
    list = list->next;
  }

  if (tee_plugins && data_plugins) {
    Log(LOG_ERR, "ERROR: 'tee' plugins are not compatible with data (memory/mysql/pgsql/etc.) plugins. Exiting...\n\n");
    exit(1);
  }

  /* signal handling we want to inherit to plugins (when not re-defined elsewhere) */
  signal(SIGCHLD, startup_handle_falling_child); /* takes note of plugins failed during startup phase */
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGUSR1, push_stats); /* logs various statistics via Log() calls */ 
  signal(SIGUSR2, reload_maps); /* sets to true the reload_maps flag */
  signal(SIGPIPE, SIG_IGN); /* we want to exit gracefully when a pipe is broken */

  /* If no IP address is supplied, let's set our default
     behaviour: IPv4 address, INADDR_ANY, port 2100 */
  if (!config.nfacctd_port) config.nfacctd_port = DEFAULT_SFACCTD_PORT;
#if (defined ENABLE_IPV6 && defined V4_MAPPED)
  if (!config.nfacctd_ip) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(config.nfacctd_port);
    slen = sizeof(struct sockaddr_in6);
  }
#else
  if (!config.nfacctd_ip) {
    struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

    sa4->sin_family = AF_INET;
    sa4->sin_addr.s_addr = htonl(0);
    sa4->sin_port = htons(config.nfacctd_port);
    slen = sizeof(struct sockaddr_in);
  }
#endif
  else {
    trim_spaces(config.nfacctd_ip);
    ret = str_to_addr(config.nfacctd_ip, &addr);
    if (!ret) {
      Log(LOG_ERR, "ERROR ( default/core ): 'sfacctd_ip' value is not valid. Exiting.\n");
      exit(1);
    }
    slen = addr_to_sa((struct sockaddr *)&server, &addr, config.nfacctd_port);
  }

  /* socket creation */
  config.sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);
  if (config.sock < 0) {
    Log(LOG_ERR, "ERROR ( default/core ): socket() failed.\n");
    exit(1);
  }

  /* bind socket to port */
  rc = setsockopt(config.sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN ( default/core ): setsockopt() failed for SO_REUSEADDR.\n");

  if (config.pipe_size) {
    rc = Setsocksize(config.sock, SOL_SOCKET, SO_RCVBUF, &config.pipe_size, sizeof(config.pipe_size));
    if (rc < 0) Log(LOG_ERR, "WARN ( default/core ): Setsocksize() failed for 'plugin_pipe_size' = '%d'.\n", config.pipe_size); 
  }

  /* Multicast: memberships handling */
  for (idx = 0; mcast_groups[idx].family && idx < MAX_MCAST_GROUPS; idx++) {
    if (mcast_groups[idx].family == AF_INET) {
      memset(&multi_req4, 0, sizeof(multi_req4));
      multi_req4.imr_multiaddr.s_addr = mcast_groups[idx].address.ipv4.s_addr;
      if (setsockopt(config.sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&multi_req4, sizeof(multi_req4)) < 0) {
	Log(LOG_ERR, "ERROR: IPv4 multicast address - ADD membership failed.\n");
	exit(1);
      }
    }
#if defined ENABLE_IPV6
    if (mcast_groups[idx].family == AF_INET6) {
      memset(&multi_req6, 0, sizeof(multi_req6));
      ip6_addr_cpy(&multi_req6.ipv6mr_multiaddr, &mcast_groups[idx].address.ipv6);
      if (setsockopt(config.sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&multi_req6, sizeof(multi_req6)) < 0) {
	Log(LOG_ERR, "ERROR: IPv6 multicast address - ADD membership failed.\n");
	exit(1);
      }
    }
#endif
  }

  if (config.nfacctd_allow_file) load_allow_file(config.nfacctd_allow_file, &allow);
  else memset(&allow, 0, sizeof(allow));

  if (config.pre_tag_map) {
    load_id_file(config.acct_type, config.pre_tag_map, &idt, &req, &tag_map_allocated);
    pptrs.v4.idtable = (u_char *) &idt;
  }
  else pptrs.v4.idtable = NULL;

  if (config.sampling_map) {
    load_id_file(MAP_SAMPLING, config.sampling_map, &sampling_table, &req, &sampling_map_allocated);
    set_sampling_table(&pptrs, (u_char *) &sampling_table);
  }
  else set_sampling_table(&pptrs, NULL);

#if defined ENABLE_THREADS
  /* starting the ISIS threa */
  if (config.nfacctd_isis) {
    req.bpf_filter = TRUE;

    nfacctd_isis_wrapper();

    /* Let's give the ISIS thread some advantage to create its structures */
    sleep(5);
  }

  /* starting the BGP thread */
  if (config.nfacctd_bgp) {
    req.bpf_filter = TRUE;
    load_comm_patterns(&config.nfacctd_bgp_stdcomm_pattern, &config.nfacctd_bgp_extcomm_pattern, &config.nfacctd_bgp_stdcomm_pattern_to_asn);

    if (config.nfacctd_bgp_peer_as_src_type == BGP_SRC_PRIMITIVES_MAP) {
      if (config.nfacctd_bgp_peer_as_src_map) {
        load_id_file(MAP_BGP_PEER_AS_SRC, config.nfacctd_bgp_peer_as_src_map, &bpas_table, &req, &bpas_map_allocated);
        pptrs.v4.bpas_table = (u_char *) &bpas_table;
      }
      else {
        Log(LOG_ERR, "ERROR: bgp_peer_as_src_type set to 'map' but no map defined. Exiting.\n");
        exit(1);
      }
    }
    else pptrs.v4.bpas_table = NULL;

    if (config.nfacctd_bgp_src_local_pref_type == BGP_SRC_PRIMITIVES_MAP) {
      if (config.nfacctd_bgp_src_local_pref_map) {
        load_id_file(MAP_BGP_SRC_LOCAL_PREF, config.nfacctd_bgp_src_local_pref_map, &blp_table, &req, &blp_map_allocated);
        pptrs.v4.blp_table = (u_char *) &blp_table;
      }
      else {
        Log(LOG_ERR, "ERROR: bgp_src_local_pref_type set to 'map' but no map defined. Exiting.\n");
        exit(1);
      }
    }
    else pptrs.v4.blp_table = NULL;

    if (config.nfacctd_bgp_src_med_type == BGP_SRC_PRIMITIVES_MAP) {
      if (config.nfacctd_bgp_src_med_map) {
        load_id_file(MAP_BGP_SRC_MED, config.nfacctd_bgp_src_med_map, &bmed_table, &req, &bmed_map_allocated);
        pptrs.v4.bmed_table = (u_char *) &bmed_table;
      }
      else {
        Log(LOG_ERR, "ERROR: bgp_src_med_type set to 'map' but no map defined. Exiting.\n");
        exit(1);
      }
    }
    else pptrs.v4.bmed_table = NULL;

    if (config.nfacctd_bgp_to_agent_map) {
      load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.nfacctd_bgp_to_agent_map, &bta_table, &req, &bta_map_allocated);
      pptrs.v4.bta_table = (u_char *) &bta_table;
    }
    else pptrs.v4.bta_table = NULL;

    if (config.nfacctd_bgp_iface_to_rd_map) {
      load_id_file(MAP_BGP_IFACE_TO_RD, config.nfacctd_bgp_iface_to_rd_map, &bitr_table, &req, &bitr_map_allocated);
      pptrs.v4.bitr_table = (u_char *) &bitr_table;
    }
    else pptrs.v4.bitr_table = NULL;

    nfacctd_bgp_wrapper();

    /* Let's give the BGP thread some advantage to create its structures */
    sleep(5);
  }
#else
  if (config.nfacctd_isis) {
    Log(LOG_ERR, "ERROR ( default/core ): 'isis_daemon' is available only with threads (--enable-threads). Exiting.\n");
    exit(1);
  }

  if (config.nfacctd_bgp) {
    Log(LOG_ERR, "ERROR ( default/core ): 'bgp_daemon' is available only with threads (--enable-threads). Exiting.\n");
    exit(1);
  }
#endif

#if defined WITH_GEOIP
  if (config.geoip_ipv4_file || config.geoip_ipv6_file) {
    req.bpf_filter = TRUE;
  }
#endif

  rc = bind(config.sock, (struct sockaddr *) &server, slen);
  if (rc < 0) {
    Log(LOG_ERR, "ERROR ( default/core ): bind() to ip=%s port=%d/udp failed (errno: %d).\n", config.nfacctd_ip, config.nfacctd_port, errno);
    exit(1);
  }

  if (config.classifiers_path) init_classifiers(config.classifiers_path);

  /* plugins glue: creation */
  load_plugins(&req);
  load_plugin_filters(1);
  evaluate_packet_handlers();
  pm_setproctitle("%s [%s]", "Core Process", "default");
  if (config.pidfile) write_pid_file(config.pidfile);
  load_networks(config.networks_file, &nt, &nc);

  /* signals to be handled only by pmacctd;
     we set proper handlers after plugin creation */
  signal(SIGINT, my_sigint_handler);
  signal(SIGTERM, my_sigint_handler);
  signal(SIGCHLD, handle_falling_child);
  kill(getpid(), SIGCHLD);

  /* arranging pointers to dummy packet; to speed up things into the
     main loop we mantain two packet_ptrs structures when IPv6 is enabled:
     we will sync here 'pptrs6' for common tables and pointers */
  memset(dummy_packet, 0, sizeof(dummy_packet));
  pptrs.v4.f_data = (u_char *) &spp;
  pptrs.v4.f_agent = (u_char *) &client;
  pptrs.v4.packet_ptr = dummy_packet;
  pptrs.v4.pkthdr = &dummy_pkthdr;
  Assign16(((struct eth_header *)pptrs.v4.packet_ptr)->ether_type, htons(ETHERTYPE_IP)); /* 0x800 */
  pptrs.v4.mac_ptr = (u_char *)((struct eth_header *)pptrs.v4.packet_ptr)->ether_dhost; 
  pptrs.v4.iph_ptr = pptrs.v4.packet_ptr + ETHER_HDRLEN; 
  pptrs.v4.tlh_ptr = pptrs.v4.packet_ptr + ETHER_HDRLEN + sizeof(struct my_iphdr); 
  Assign8(((struct my_iphdr *)pptrs.v4.iph_ptr)->ip_vhl, 5);
  // pptrs.v4.pkthdr->caplen = 38; /* eth_header + my_iphdr + my_tlhdr */
  pptrs.v4.pkthdr->caplen = 55;
  pptrs.v4.pkthdr->len = 100; /* fake len */ 
  pptrs.v4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_vlan, 0, sizeof(dummy_packet_vlan));
  pptrs.vlan4.f_data = pptrs.v4.f_data; 
  pptrs.vlan4.idtable = pptrs.v4.idtable; 
  pptrs.vlan4.f_agent = (u_char *) &client;
  pptrs.vlan4.packet_ptr = dummy_packet_vlan;
  pptrs.vlan4.pkthdr = &dummy_pkthdr_vlan;
  Assign16(((struct eth_header *)pptrs.vlan4.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlan4.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlan4.packet_ptr)->ether_dhost;
  pptrs.vlan4.vlan_ptr = pptrs.vlan4.packet_ptr + ETHER_HDRLEN;
  Assign16(*(pptrs.vlan4.vlan_ptr+2), htons(ETHERTYPE_IP));
  pptrs.vlan4.iph_ptr = pptrs.vlan4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  pptrs.vlan4.tlh_ptr = pptrs.vlan4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN + sizeof(struct my_iphdr);
  Assign8(((struct my_iphdr *)pptrs.vlan4.iph_ptr)->ip_vhl, 5);
  // pptrs.vlan4.pkthdr->caplen = 42; /* eth_header + vlan + my_iphdr + my_tlhdr */
  pptrs.vlan4.pkthdr->caplen = 59;
  pptrs.vlan4.pkthdr->len = 100; /* fake len */
  pptrs.vlan4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_mpls, 0, sizeof(dummy_packet_mpls));
  pptrs.mpls4.f_data = pptrs.v4.f_data; 
  pptrs.mpls4.idtable = pptrs.v4.idtable;
  pptrs.mpls4.f_agent = (u_char *) &client;
  pptrs.mpls4.packet_ptr = dummy_packet_mpls;
  pptrs.mpls4.pkthdr = &dummy_pkthdr_mpls;
  Assign16(((struct eth_header *)pptrs.mpls4.packet_ptr)->ether_type, htons(ETHERTYPE_MPLS));
  pptrs.mpls4.mac_ptr = (u_char *)((struct eth_header *)pptrs.mpls4.packet_ptr)->ether_dhost;
  pptrs.mpls4.mpls_ptr = pptrs.mpls4.packet_ptr + ETHER_HDRLEN;
  // pptrs.mpls4.pkthdr->caplen = 78; /* eth_header + upto 10 MPLS labels + my_iphdr + my_tlhdr */
  pptrs.mpls4.pkthdr->caplen = 95;
  pptrs.mpls4.pkthdr->len = 100; /* fake len */
  pptrs.mpls4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_vlan_mpls, 0, sizeof(dummy_packet_vlan_mpls));
  pptrs.vlanmpls4.f_data = pptrs.v4.f_data; 
  pptrs.vlanmpls4.idtable = pptrs.v4.idtable;
  pptrs.vlanmpls4.f_agent = (u_char *) &client;
  pptrs.vlanmpls4.packet_ptr = dummy_packet_vlan_mpls;
  pptrs.vlanmpls4.pkthdr = &dummy_pkthdr_vlan_mpls;
  Assign16(((struct eth_header *)pptrs.vlanmpls4.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlanmpls4.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlanmpls4.packet_ptr)->ether_dhost;
  pptrs.vlanmpls4.vlan_ptr = pptrs.vlanmpls4.packet_ptr + ETHER_HDRLEN;
  Assign16(*(pptrs.vlanmpls4.vlan_ptr+2), htons(ETHERTYPE_MPLS));
  pptrs.vlanmpls4.mpls_ptr = pptrs.vlanmpls4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  // pptrs.vlanmpls4.pkthdr->caplen = 82; /* eth_header + vlan + upto 10 MPLS labels + my_iphdr + my_tlhdr */
  pptrs.vlanmpls4.pkthdr->caplen = 99;
  pptrs.vlanmpls4.pkthdr->len = 100; /* fake len */
  pptrs.vlanmpls4.l3_proto = ETHERTYPE_IP;

#if defined ENABLE_IPV6
  memset(dummy_packet6, 0, sizeof(dummy_packet6));
  pptrs.v6.f_data = pptrs.v4.f_data; 
  pptrs.v6.idtable = pptrs.v4.idtable;
  pptrs.v6.f_agent = (u_char *) &client;
  pptrs.v6.packet_ptr = dummy_packet6;
  pptrs.v6.pkthdr = &dummy_pkthdr6;
  Assign16(((struct eth_header *)pptrs.v6.packet_ptr)->ether_type, htons(ETHERTYPE_IPV6)); 
  pptrs.v6.mac_ptr = (u_char *)((struct eth_header *)pptrs.v6.packet_ptr)->ether_dhost; 
  pptrs.v6.iph_ptr = pptrs.v6.packet_ptr + ETHER_HDRLEN;
  pptrs.v6.tlh_ptr = pptrs.v6.packet_ptr + ETHER_HDRLEN + sizeof(struct ip6_hdr);
  Assign16(((struct ip6_hdr *)pptrs.v6.iph_ptr)->ip6_plen, htons(100));
  Assign16(((struct ip6_hdr *)pptrs.v6.iph_ptr)->ip6_hlim, htons(64));
  // pptrs.v6.pkthdr->caplen = 60; /* eth_header + ip6_hdr + my_tlhdr */
  pptrs.v6.pkthdr->caplen = 77;
  pptrs.v6.pkthdr->len = 100; /* fake len */
  pptrs.v6.l3_proto = ETHERTYPE_IPV6;

  memset(dummy_packet_vlan6, 0, sizeof(dummy_packet_vlan6));
  pptrs.vlan6.f_data = pptrs.v4.f_data; 
  pptrs.vlan6.idtable = pptrs.v4.idtable;
  pptrs.vlan6.f_agent = (u_char *) &client;
  pptrs.vlan6.packet_ptr = dummy_packet_vlan6;
  pptrs.vlan6.pkthdr = &dummy_pkthdr_vlan6;
  Assign16(((struct eth_header *)pptrs.vlan6.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlan6.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlan6.packet_ptr)->ether_dhost;
  pptrs.vlan6.vlan_ptr = pptrs.vlan6.packet_ptr + ETHER_HDRLEN;
  Assign8(*(pptrs.vlan6.vlan_ptr+2), 0x86);
  Assign8(*(pptrs.vlan6.vlan_ptr+3), 0xDD);
  pptrs.vlan6.iph_ptr = pptrs.vlan6.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  pptrs.vlan6.tlh_ptr = pptrs.vlan6.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN + sizeof(struct ip6_hdr);
  Assign16(((struct ip6_hdr *)pptrs.vlan6.iph_ptr)->ip6_plen, htons(100));
  Assign16(((struct ip6_hdr *)pptrs.vlan6.iph_ptr)->ip6_hlim, htons(64));
  // pptrs.vlan6.pkthdr->caplen = 64; /* eth_header + vlan + ip6_hdr + my_tlhdr */
  pptrs.vlan6.pkthdr->caplen = 81;
  pptrs.vlan6.pkthdr->len = 100; /* fake len */
  pptrs.vlan6.l3_proto = ETHERTYPE_IPV6;

  memset(dummy_packet_mpls6, 0, sizeof(dummy_packet_mpls6));
  pptrs.mpls6.f_data = pptrs.v4.f_data; 
  pptrs.mpls6.idtable = pptrs.v4.idtable;
  pptrs.mpls6.f_agent = (u_char *) &client;
  pptrs.mpls6.packet_ptr = dummy_packet_mpls6;
  pptrs.mpls6.pkthdr = &dummy_pkthdr_mpls6;
  Assign16(((struct eth_header *)pptrs.mpls6.packet_ptr)->ether_type, htons(ETHERTYPE_MPLS));
  pptrs.mpls6.mac_ptr = (u_char *)((struct eth_header *)pptrs.mpls6.packet_ptr)->ether_dhost;
  pptrs.mpls6.mpls_ptr = pptrs.mpls6.packet_ptr + ETHER_HDRLEN;
  // pptrs.mpls6.pkthdr->caplen = 100; /* eth_header + upto 10 MPLS labels + ip6_hdr + my_tlhdr */
  pptrs.mpls6.pkthdr->caplen = 117;
  pptrs.mpls6.pkthdr->len = 128; /* fake len */
  pptrs.mpls6.l3_proto = ETHERTYPE_IPV6;

  memset(dummy_packet_vlan_mpls6, 0, sizeof(dummy_packet_vlan_mpls6));
  pptrs.vlanmpls6.f_data = pptrs.v4.f_data; 
  pptrs.vlanmpls6.idtable = pptrs.v4.idtable;
  pptrs.vlanmpls6.f_agent = (u_char *) &client;
  pptrs.vlanmpls6.packet_ptr = dummy_packet_vlan_mpls6;
  pptrs.vlanmpls6.pkthdr = &dummy_pkthdr_vlan_mpls6;
  Assign16(((struct eth_header *)pptrs.vlanmpls6.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlanmpls6.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlanmpls6.packet_ptr)->ether_dhost;
  pptrs.vlanmpls6.vlan_ptr = pptrs.vlanmpls6.packet_ptr + ETHER_HDRLEN;
  Assign8(*(pptrs.vlanmpls6.vlan_ptr+2), 0x88);
  Assign8(*(pptrs.vlanmpls6.vlan_ptr+3), 0x47);
  pptrs.vlanmpls6.mpls_ptr = pptrs.vlanmpls6.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  // pptrs.vlanmpls6.pkthdr->caplen = 104; /* eth_header + vlan + upto 10 MPLS labels + ip6_hdr + my_tlhdr */
  pptrs.vlanmpls6.pkthdr->caplen = 121;
  pptrs.vlanmpls6.pkthdr->len = 128; /* fake len */
  pptrs.vlanmpls6.l3_proto = ETHERTYPE_IP;
#endif

  {
    char srv_string[INET6_ADDRSTRLEN];
    struct host_addr srv_addr;
    u_int16_t srv_port;

    sa_to_addr(&server, &srv_addr, &srv_port);
    addr_to_str(srv_string, &srv_addr);
    Log(LOG_INFO, "INFO ( default/core ): waiting for sFlow data on %s:%u\n", srv_string, srv_port);
    allowed = TRUE;
  }

  /* Main loop */
  for (;;) {
    // memset(&spp, 0, sizeof(spp));
    ret = recvfrom(config.sock, sflow_packet, SFLOW_MAX_MSG_SIZE, 0, (struct sockaddr *) &client, &clen);
    spp.rawSample = pptrs.v4.f_header = sflow_packet;
    spp.rawSampleLen = pptrs.v4.f_len = ret;
    spp.datap = (u_int32_t *) spp.rawSample;
    spp.endp = sflow_packet + spp.rawSampleLen; 
    reset_tag_status(&pptrs);
    reset_shadow_status(&pptrs);

    // if (ret < SFLOW_MIN_MSG_SIZE) continue; 

    /* check if Hosts Allow Table is loaded; if it is, we will enforce rules */
    if (allow.num) allowed = check_allow(&allow, (struct sockaddr *)&client); 
    if (!allowed) continue;

    if (reload_map) {
      bta_map_caching = TRUE;
      sampling_map_caching = TRUE;

      load_networks(config.networks_file, &nt, &nc);

      if (config.nfacctd_bgp && config.nfacctd_bgp_peer_as_src_map)
        load_id_file(MAP_BGP_PEER_AS_SRC, config.nfacctd_bgp_peer_as_src_map, &bpas_table, &req, &bpas_map_allocated);
      if (config.nfacctd_bgp && config.nfacctd_bgp_src_local_pref_map)
        load_id_file(MAP_BGP_SRC_LOCAL_PREF, config.nfacctd_bgp_src_local_pref_map, &blp_table, &req, &blp_map_allocated);
      if (config.nfacctd_bgp && config.nfacctd_bgp_src_med_map)
        load_id_file(MAP_BGP_SRC_MED, config.nfacctd_bgp_src_med_map, &bmed_table, &req, &bmed_map_allocated);
      if (config.nfacctd_bgp && config.nfacctd_bgp_to_agent_map)
        load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.nfacctd_bgp_to_agent_map, &bta_table, &req, &bta_map_allocated);
      if (config.nfacctd_bgp && config.nfacctd_bgp_iface_to_rd_map)
        load_id_file(MAP_BGP_IFACE_TO_RD, config.nfacctd_bgp_iface_to_rd_map, &bitr_table, &req, &bitr_map_allocated);
      if (config.pre_tag_map)
        load_id_file(config.acct_type, config.pre_tag_map, &idt, &req, &tag_map_allocated);
      if (config.sampling_map) {
        load_id_file(MAP_SAMPLING, config.sampling_map, &sampling_table, &req, &sampling_map_allocated);
        set_sampling_table(&pptrs, (u_char *) &sampling_table);
      }

      reload_map = FALSE;
      gettimeofday(&reload_map_tstamp, NULL);
    }

    if (data_plugins) {
      switch(spp.datagramVersion = getData32(&spp)) {
      case 5:
	getAddress(&spp, &spp.agent_addr);

	/* We trash the source IP address from f_agent */
	if (spp.agent_addr.type == SFLADDRESSTYPE_IP_V4) {
	  struct sockaddr *sa = (struct sockaddr *) &client;
	  struct sockaddr_in *sa4 = (struct sockaddr_in *) &client;

	  sa->sa_family = AF_INET;
	  sa4->sin_addr.s_addr = spp.agent_addr.address.ip_v4.s_addr;
	}
#if defined ENABLE_IPV6
	else if (spp.agent_addr.type == SFLADDRESSTYPE_IP_V6) {
	  struct sockaddr *sa = (struct sockaddr *) &client;
	  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &client;

	  sa->sa_family = AF_INET6;
	  ip6_addr_cpy(&sa6->sin6_addr, &spp.agent_addr.address.ip_v6);
	}
#endif

	process_SFv5_packet(&spp, &pptrs, &req, (struct sockaddr *) &client);
	break;
      case 4:
      case 2:
	getAddress(&spp, &spp.agent_addr);

        /* We trash the source IP address from f_agent */
        if (spp.agent_addr.type == SFLADDRESSTYPE_IP_V4) {
          struct sockaddr *sa = (struct sockaddr *) &client;
          struct sockaddr_in *sa4 = (struct sockaddr_in *) &client;

          sa->sa_family = AF_INET;
          sa4->sin_addr.s_addr = spp.agent_addr.address.ip_v4.s_addr;
        }
#if defined ENABLE_IPV6
        else if (spp.agent_addr.type == SFLADDRESSTYPE_IP_V6) {
          struct sockaddr *sa = (struct sockaddr *) &client;
          struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &client;

          sa->sa_family = AF_INET6;
          ip6_addr_cpy(&sa6->sin6_addr, &spp.agent_addr.address.ip_v6);
        }
#endif

	process_SFv2v4_packet(&spp, &pptrs, &req, (struct sockaddr *) &client);
	break;
      default:
	notify_malf_packet(LOG_INFO, "INFO: Discarding unknown packet", (struct sockaddr *) pptrs.v4.f_agent);
	xflow_tot_bad_datagrams++;
	break;
      }
    }
    else if (tee_plugins) {
      process_SF_raw_packet(&spp, &pptrs, &req, (struct sockaddr *) &client);
    }
  }
}

void InterSampleCleanup(SFSample *spp)
{
  u_char *start = (u_char *) spp;
  u_char *ptr = (u_char *) &spp->sampleType;

  memset(ptr, 0, SFSampleSz-(ptr-start));
}

void process_SFv2v4_packet(SFSample *spp, struct packet_ptrs_vector *pptrsv,
		                struct plugin_requests *req, struct sockaddr *agent)
{
  u_int32_t samplesInPacket, idx;
  u_int32_t sampleType;

  spp->agentSubId = 0; /* not supported */
  spp->sequenceNo = getData32(spp);
  spp->sysUpTime = getData32(spp);
  samplesInPacket = getData32(spp);
  
  pptrsv->v4.f_status = sfv245_check_status(spp, agent);
  set_vector_f_status(pptrsv);

  for (idx = 0; idx < samplesInPacket; idx++) {
    InterSampleCleanup(spp);
    set_vector_sample_type(pptrsv, 0);
SFv2v4_read_sampleType:
    sampleType = getData32(spp);
    if (!pptrsv->v4.sample_type) set_vector_sample_type(pptrsv, sampleType);
    switch (sampleType) {
    case SFLFLOW_SAMPLE:
      readv2v4FlowSample(spp, pptrsv, req);
      break;
    case SFLCOUNTERS_SAMPLE:
      readv2v4CountersSample(spp);
      break;
    default:
      notify_malf_packet(LOG_INFO, "INFO: Discarding unknown v2/v4 sample", (struct sockaddr *) pptrsv->v4.f_agent);
      xflow_tot_bad_datagrams++;
      return; /* unexpected sampleType; aborting packet */
    }
    if ((u_char *)spp->datap > spp->endp) return;
  }
}

void process_SFv5_packet(SFSample *spp, struct packet_ptrs_vector *pptrsv,
		struct plugin_requests *req, struct sockaddr *agent)
{
  u_int32_t samplesInPacket, idx;
  u_int32_t sampleType;

  spp->agentSubId = getData32(spp);
  spp->sequenceNo = getData32(spp);
  spp->sysUpTime = getData32(spp);
  samplesInPacket = getData32(spp);
  pptrsv->v4.f_status = sfv245_check_status(spp, agent);
  set_vector_f_status(pptrsv);

  for (idx = 0; idx < samplesInPacket; idx++) {
    InterSampleCleanup(spp);
    set_vector_sample_type(pptrsv, 0);
SFv5_read_sampleType:
    sampleType = getData32(spp);
    if (!pptrsv->v4.sample_type) set_vector_sample_type(pptrsv, sampleType);
    switch (sampleType) {
    case SFLFLOW_SAMPLE:
      readv5FlowSample(spp, FALSE, pptrsv, req);
      break;
    case SFLCOUNTERS_SAMPLE:
      readv5CountersSample(spp);
      break;
    case SFLFLOW_SAMPLE_EXPANDED:
      readv5FlowSample(spp, TRUE, pptrsv, req);
      break;
    case SFLCOUNTERS_SAMPLE_EXPANDED:
      readv5CountersSample(spp);
      break;
    case SFLACL_BROCADE_SAMPLE:
      getData32(spp); /* trash: sample length */
      getData32(spp); /* trash: FoundryFlags */
      getData32(spp); /* trash: FoundryGroupID */
      goto SFv5_read_sampleType; /* rewind */
      break;
    default:
      notify_malf_packet(LOG_INFO, "INFO: Discarding unknown v5 sample", (struct sockaddr *) pptrsv->v4.f_agent);
      xflow_tot_bad_datagrams++;
      return; /* unexpected sampleType; aborting packet */ 
    }
    if ((u_char *)spp->datap > spp->endp) return; 
  }
}

void process_SF_raw_packet(SFSample *spp, struct packet_ptrs_vector *pptrsv,
                                struct plugin_requests *req, struct sockaddr *agent)
{
  struct packet_ptrs *pptrs = &pptrsv->v4;

  switch(spp->datagramVersion = getData32(spp)) {
  case 5:
    getAddress(spp, &spp->agent_addr);
    spp->agentSubId = getData32(spp);
    pptrs->seqno = getData32(spp);
    break;
  case 4:
  case 2:
    getAddress(spp, &spp->agent_addr);
    spp->agentSubId = 0; /* not supported */
    pptrs->seqno = getData32(spp);
    break;
  default:
    notify_malf_packet(LOG_INFO, "INFO: Discarding unknown sFlow packet", (struct sockaddr *) pptrs->f_agent);
    xflow_tot_bad_datagrams++;
    return;
  }

  if (config.debug) {
    struct host_addr a;
    u_char agent_addr[50];
    u_int16_t agent_port;

    sa_to_addr((struct sockaddr *)pptrs->f_agent, &a, &agent_port);
    addr_to_str(agent_addr, &a);

    Log(LOG_DEBUG, "DEBUG ( default/core ): Received sFlow packet from [%s:%u] version [%u] seqno [%u]\n", agent_addr, agent_port, spp->datagramVersion, pptrs->seqno);
  }

  if (config.pre_tag_map) SF_find_id((struct id_table *)pptrs->idtable, pptrs, &pptrs->tag, &pptrs->tag2);
  exec_plugins(pptrs);
}

void compute_once()
{
  struct pkt_data dummy;

  CounterSz = sizeof(dummy.pkt_len);
  PdataSz = sizeof(struct pkt_data);
  PpayloadSz = sizeof(struct pkt_payload);
  PmsgSz = sizeof(struct pkt_msg);
  PextrasSz = sizeof(struct pkt_extras);
  PbgpSz = sizeof(struct pkt_bgp_primitives);
  PnatSz = sizeof(struct pkt_nat_primitives);
  ChBufHdrSz = sizeof(struct ch_buf_hdr);
  CharPtrSz = sizeof(char *);
  IP4HdrSz = sizeof(struct my_iphdr);
  IP4TlSz = sizeof(struct my_iphdr)+sizeof(struct my_tlhdr);
  SFSampleSz = sizeof(SFSample);
  SFLAddressSz = sizeof(SFLAddress);
  SFrenormEntrySz = sizeof(struct xflow_status_entry_sampling);
  PptrsSz = sizeof(struct packet_ptrs);
  CSSz = sizeof(struct class_st);
  HostAddrSz = sizeof(struct host_addr);
  UDPHdrSz = sizeof(struct my_udphdr);

#if defined ENABLE_IPV6
  IP6HdrSz = sizeof(struct ip6_hdr);
  IP6AddrSz = sizeof(struct in6_addr);
  IP6TlSz = sizeof(struct ip6_hdr)+sizeof(struct my_tlhdr);
#endif
}

void notify_malf_packet(short int severity, char *ostr, struct sockaddr *sa)
{
  struct host_addr a;
  u_char errstr[SRVBUFLEN];
  u_char agent_addr[50] /* able to fit an IPv6 string aswell */, any[]="0.0.0.0";
  u_int16_t agent_port;

  sa_to_addr(sa, &a, &agent_port);
  addr_to_str(agent_addr, &a);
  if (!config.nfacctd_ip) config.nfacctd_ip = any;
  snprintf(errstr, SRVBUFLEN, "%s: sfacctd=%s:%u agent=%s:%u \n",
  ostr, config.nfacctd_ip, config.nfacctd_port, agent_addr, agent_port);
  Log(severity, errstr);
}

/*_________________---------------------------__________________
  _________________    lengthCheck            __________________
  -----------------___________________________------------------
*/

int lengthCheck(SFSample *sample, u_char *start, int len)
{
  u_int32_t actualLen = (u_char *)sample->datap - start;
  if (actualLen != len) {
    /* XXX: notify length mismatch */ 
    return ERR;
  }

  return FALSE;
}

/*_________________---------------------------__________________
  _________________     decodeLinkLayer       __________________
  -----------------___________________________------------------
  store the offset to the start of the ipv4 header in the sequence_number field
  or -1 if not found. Decode the 802.1d if it's there.
*/

#define NFT_ETHHDR_SIZ 14
#define NFT_8022_SIZ 3
#define NFT_MAX_8023_LEN 1500

void decodeLinkLayer(SFSample *sample)
{
  u_char *start = (u_char *)sample->header;
  u_char *end = start + sample->headerLen;
  u_char *ptr = start;
  u_int16_t caplen = end - (u_char *)sample->datap;

  /* assume not found */
  sample->gotIPV4 = FALSE;
  sample->gotIPV6 = FALSE;

  if (caplen < NFT_ETHHDR_SIZ) return; /* not enough for an Ethernet header */
  caplen -= NFT_ETHHDR_SIZ;

  memcpy(sample->eth_dst, ptr, 6);
  ptr += 6;

  memcpy(sample->eth_src, ptr, 6);
  ptr += 6;
  sample->eth_type = (ptr[0] << 8) + ptr[1];
  ptr += 2;

  if (sample->eth_type == ETHERTYPE_8021Q) {
    /* VLAN  - next two bytes */
    u_int32_t vlanData = (ptr[0] << 8) + ptr[1];
    u_int32_t vlan = vlanData & 0x0fff;
    u_int32_t priority = vlanData >> 13;

    if (caplen < 2) return;

    ptr += 2;
    /*  _____________________________________ */
    /* |   pri  | c |         vlan-id        | */
    /*  ------------------------------------- */
    /* [priority = 3bits] [Canonical Format Flag = 1bit] [vlan-id = 12 bits] */
    if (!sample->in_vlan && !sample->out_vlan) sample->in_vlan = vlan;
    if (!sample->in_priority && !sample->out_priority) sample->in_priority = priority;
    sample->eth_type = (ptr[0] << 8) + ptr[1];

    ptr += 2;
    caplen -= 2;
  }

  if (sample->eth_type <= NFT_MAX_8023_LEN) {
    /* assume 802.3+802.2 header */
    if (caplen < 8) return;

    /* check for SNAP */
    if(ptr[0] == 0xAA &&
       ptr[1] == 0xAA &&
       ptr[2] == 0x03) {
      ptr += 3;
      if(ptr[0] != 0 ||
	 ptr[1] != 0 ||
	 ptr[2] != 0) {
	return; /* no further decode for vendor-specific protocol */
      }
      ptr += 3;
      /* OUI == 00-00-00 means the next two bytes are the ethernet type (RFC 2895) */
      sample->eth_type = (ptr[0] << 8) + ptr[1];
      ptr += 2;
      caplen -= 8;
    }
    else {
      if (ptr[0] == 0x06 &&
	  ptr[1] == 0x06 &&
	  (ptr[2] & 0x01)) {
	/* IP over 8022 */
	ptr += 3;
	/* force the eth_type to be IP so we can inline the IP decode below */
	sample->eth_type = ETHERTYPE_IP;
	caplen -= 3;
      }
      else return;
    }
  }

  if (sample->eth_type == ETHERTYPE_MPLS || sample->eth_type == ETHERTYPE_MPLS_MULTI) {
    decodeMpls(sample);
    caplen -= sample->lstk.depth * 4;
  }

  if (sample->eth_type == ETHERTYPE_IP) {
    sample->gotIPV4 = TRUE;
    sample->offsetToIPV4 = (ptr - start);
  }

#if defined ENABLE_IPV6
  if (sample->eth_type == ETHERTYPE_IPV6) {
    sample->gotIPV6 = TRUE;
    sample->offsetToIPV6 = (ptr - start);
  }
#endif
}


/*_________________---------------------------__________________
  _________________     decodeIPLayer4        __________________
  -----------------___________________________------------------
*/

void decodeIPLayer4(SFSample *sample, u_char *ptr, u_int32_t ipProtocol) {
  u_char *end = sample->header + sample->headerLen;
  if(ptr > (end - 8)) return; // not enough header bytes left
  switch(ipProtocol) {
  case 1: /* ICMP */
    {
      struct SF_icmphdr icmp;
      memcpy(&icmp, ptr, sizeof(icmp));
      sample->dcd_sport = icmp.type;
      sample->dcd_dport = icmp.code;
    }
    break;
  case 6: /* TCP */
    {
      struct SF_tcphdr tcp;
      memcpy(&tcp, ptr, sizeof(tcp));
      sample->dcd_sport = ntohs(tcp.th_sport);
      sample->dcd_dport = ntohs(tcp.th_dport);
      sample->dcd_tcpFlags = tcp.th_flags;
      if(sample->dcd_dport == 80) {
	int bytesLeft;
	int headerBytes = (tcp.th_off_and_unused >> 4) * 4;
	ptr += headerBytes;
	bytesLeft = sample->header + sample->headerLen - ptr;
      }
    }
    break;
  case 17: /* UDP */
    {
      struct SF_udphdr udp;
      memcpy(&udp, ptr, sizeof(udp));
      sample->dcd_sport = ntohs(udp.uh_sport);
      sample->dcd_dport = ntohs(udp.uh_dport);
      sample->udp_pduLen = ntohs(udp.uh_ulen);
    }
    break;
  default: /* some other protcol */
    break;
  }
}

/*_________________---------------------------__________________
  _________________     decodeIPV4            __________________
  -----------------___________________________------------------
*/

void decodeIPV4(SFSample *sample)
{
  if (sample->gotIPV4) {
    u_char *end = sample->header + sample->headerLen;
    u_char *ptr = sample->header + sample->offsetToIPV4;
    u_int16_t caplen = end - ptr;

    /* Create a local copy of the IP header (cannot overlay structure in case it is not quad-aligned...some
       platforms would core-dump if we tried that).  It's OK coz this probably performs just as well anyway. */
    struct SF_iphdr ip;

    if (caplen < IP4HdrSz) return; 

    memcpy(&ip, ptr, sizeof(ip));
    /* Value copy all ip elements into sample */
    sample->dcd_srcIP.s_addr = ip.saddr;
    sample->dcd_dstIP.s_addr = ip.daddr;
    sample->dcd_ipProtocol = ip.protocol;
    sample->dcd_ipTos = ip.tos;
    sample->dcd_ipTTL = ip.ttl;
    /* check for fragments */
    sample->ip_fragmentOffset = ntohs(ip.frag_off) & 0x1FFF;
    if (sample->ip_fragmentOffset == 0) {
      /* advance the pointer to the next protocol layer */
      /* ip headerLen is expressed as a number of quads */
      ptr += (ip.version_and_headerLen & 0x0f) * 4;
      decodeIPLayer4(sample, ptr, ip.protocol);
    }
  }
}

/*_________________---------------------------__________________
  _________________     decodeIPV6            __________________
  -----------------___________________________------------------
*/

#if defined ENABLE_IPV6
void decodeIPV6(SFSample *sample)
{
  u_int16_t payloadLen;
  u_int32_t label;
  u_int32_t nextHeader;
  u_char *end = sample->header + sample->headerLen;

  if(sample->gotIPV6) {
    u_char *ptr = sample->header + sample->offsetToIPV6;
    u_int16_t caplen = end - ptr;

    if (caplen < IP6HdrSz) return;
    
    // check the version
    {
      int ipVersion = (*ptr >> 4);
      if(ipVersion != 6) return;
    }

    // get the tos (priority)
    sample->dcd_ipTos = *ptr++ & 15;
    // 24-bit label
    label = *ptr++;
    label <<= 8;
    label += *ptr++;
    label <<= 8;
    label += *ptr++;
    // payload
    payloadLen = (ptr[0] << 8) + ptr[1];
    ptr += 2;
    // if payload is zero, that implies a jumbo payload

    // next header
    nextHeader = *ptr++;

    // TTL
    sample->dcd_ipTTL = *ptr++;

    {// src and dst address
      sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
      memcpy(&sample->ipsrc.address, ptr, 16);
      ptr +=16;
      sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
      memcpy(&sample->ipdst.address, ptr, 16);
      ptr +=16;
    }

    // skip over some common header extensions...
    // http://searchnetworking.techtarget.com/originalContent/0,289142,sid7_gci870277,00.html
    while(nextHeader == 0 ||  // hop
	  nextHeader == 43 || // routing
	  nextHeader == 44 || // fragment
	  // nextHeader == 50 || // encryption - don't bother coz we'll not be able to read any further
	  nextHeader == 51 || // auth
	  nextHeader == 60) { // destination options
      u_int32_t optionLen, skip;
      nextHeader = ptr[0];
      optionLen = 8 * (ptr[1] + 1);  // second byte gives option len in 8-byte chunks, not counting first 8
      skip = optionLen - 2;
      ptr += skip;
      if(ptr > end) return; // ran off the end of the header
    }
    
    // now that we have eliminated the extension headers, nextHeader should have what we want to
    // remember as the ip protocol...
    sample->dcd_ipProtocol = nextHeader;
    decodeIPLayer4(sample, ptr, sample->dcd_ipProtocol);
  }
}
#endif

/*_________________---------------------------__________________
  _________________   read data fns           __________________
  -----------------___________________________------------------
*/

u_int32_t getData32(SFSample *sample) 
{
  if ((u_char *)sample->datap > sample->endp) return 0; 
  return ntohl(*(sample->datap)++);
}

u_int32_t getData32_nobswap(SFSample *sample) 
{
  if ((u_char *)sample->datap > sample->endp) return 0;
  return *(sample->datap)++;
}

void skipBytes(SFSample *sample, int skip)
{
  int quads = (skip + 3) / 4;
  sample->datap += quads;
  // if((u_char *)sample->datap > sample->endp) return 0; 
}

u_int32_t getString(SFSample *sample, char *buf, int bufLen)
{
  u_int32_t len, read_len;
  len = getData32(sample);
  // truncate if too long
  read_len = (len >= bufLen) ? (bufLen - 1) : len;
  memcpy(buf, sample->datap, read_len);
  buf[read_len] = '\0';   // null terminate
  skipBytes(sample, len);
  return len;
}

u_int32_t getAddress(SFSample *sample, SFLAddress *address)
{
  address->type = getData32(sample);
  if(address->type == SFLADDRESSTYPE_IP_V4)
    address->address.ip_v4.s_addr = getData32_nobswap(sample);
  else {
#if defined ENABLE_IPV6
    memcpy(&address->address.ip_v6.s6_addr, sample->datap, 16);
#endif
    skipBytes(sample, 16);
  }
  return address->type;
}

char *printTag(u_int32_t tag, char *buf, int bufLen) {
  // should really be: snprintf(buf, buflen,...) but snprintf() is not always available
  sprintf(buf, "%lu:%lu", (tag >> 12), (tag & 0x00000FFF));
  return buf;
}

/*_________________---------------------------__________________
  _________________    readExtendedSwitch     __________________
  -----------------___________________________------------------
*/

void readExtendedSwitch(SFSample *sample)
{
  sample->in_vlan = getData32(sample);
  sample->in_priority = getData32(sample);
  sample->out_vlan = getData32(sample);
  sample->out_priority = getData32(sample);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_SWITCH;
}

/*_________________---------------------------__________________
  _________________    readExtendedRouter     __________________
  -----------------___________________________------------------
*/

void readExtendedRouter(SFSample *sample)
{
  u_int32_t addrType;
  char buf[51];

  getAddress(sample, &sample->nextHop);
  sample->srcMask = getData32(sample);
  sample->dstMask = getData32(sample);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_ROUTER;
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway_v2   __________________
  -----------------___________________________------------------
*/

void readExtendedGateway_v2(SFSample *sample)
{
  sample->my_as = getData32(sample);
  sample->src_as = getData32(sample);
  sample->src_peer_as = getData32(sample);
  sample->dst_as_path_len = getData32(sample);
  /* just point at the dst_as_path array */
  if(sample->dst_as_path_len > 0) {
    // sample->dst_as_path = sample->datap;
    /* and skip over it in the input */
    skipBytes(sample, sample->dst_as_path_len * 4);
    // fill in the dst and dst_peer fields too
    sample->dst_peer_as = ntohl(sample->dst_as_path[0]);
    sample->dst_as = ntohl(sample->dst_as_path[sample->dst_as_path_len - 1]);
  }
  
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
}

/*_________________---------------------------__________________
  _________________  readExtendedGateway      __________________
  -----------------___________________________------------------
*/

void readExtendedGateway(SFSample *sample)
{
  int len_tot, len_asn, len_comm, idx;
  char asn_str[MAX_BGP_ASPATH], comm_str[MAX_BGP_STD_COMMS], space[] = " ";
  char buf[51];

  if(sample->datagramVersion >= 5) getAddress(sample, &sample->bgp_nextHop);

  sample->my_as = getData32(sample);
  sample->src_as = getData32(sample);
  sample->src_peer_as = getData32(sample);
  sample->dst_as_path_len = getData32(sample);
  if (sample->dst_as_path_len > 0) {
    for (idx = 0, len_tot = 0; idx < sample->dst_as_path_len; idx++) {
      u_int32_t seg_type;
      u_int32_t seg_len;
      int i;

      seg_type = getData32(sample);
      seg_len = getData32(sample);

      for (i = 0; i < seg_len; i++) {
	u_int32_t asNumber;

	asNumber = getData32(sample);
	snprintf(asn_str, MAX_BGP_ASPATH-1, "%u", asNumber);
        len_asn = strlen(asn_str);
	len_tot = strlen(sample->dst_as_path);

        if ((len_tot+len_asn) < MAX_BGP_ASPATH) {
          strncat(sample->dst_as_path, asn_str, len_asn);
        }
        else {
          sample->dst_as_path[MAX_BGP_ASPATH-2] = '+';
          sample->dst_as_path[MAX_BGP_ASPATH-1] = '\0';
        }

	/* mark the first one as the dst_peer_as */
	if(i == 0 && idx == 0) sample->dst_peer_as = asNumber;

	/* mark the last one as the dst_as */
	if (idx == (sample->dst_as_path_len - 1) && i == (seg_len - 1)) sample->dst_as = asNumber;
        else {
          if (strlen(sample->dst_as_path) < (MAX_BGP_ASPATH-1))
            strncat(sample->dst_as_path, space, 1);
        }
      }
    }
  }

  sample->communities_len = getData32(sample);
  /* just point at the communities array */
  if (sample->communities_len > 0) {
    for (idx = 0, len_tot = 0; idx < sample->communities_len; idx++) {
      u_int32_t comm, as, val;

      comm = getData32(sample);
      switch (comm) {
      case COMMUNITY_INTERNET:
        strcpy(comm_str, "internet");
        break;
      case COMMUNITY_NO_EXPORT:
        strcpy(comm_str, "no-export");
        break;
      case COMMUNITY_NO_ADVERTISE:
        strcpy (comm_str, "no-advertise");
        break;
      case COMMUNITY_LOCAL_AS:
        strcpy (comm_str, "local-AS");
        break;
      default:
        as = (comm >> 16) & 0xFFFF;
        val = comm & 0xFFFF;
        sprintf(comm_str, "%d:%d", as, val);
        break;
      }
      len_comm = strlen(comm_str);
      len_tot = strlen(sample->comms);

      if ((len_tot+len_comm) < MAX_BGP_STD_COMMS) {
        strncat(sample->comms, comm_str, len_comm);
      }
      else {
        sample->comms[MAX_BGP_STD_COMMS-2] = '+';
        sample->comms[MAX_BGP_STD_COMMS-1] = '\0';
      }

      if (idx < (sample->communities_len - 1)) {
        if (strlen(sample->comms) < (MAX_BGP_STD_COMMS-1))
          strncat(sample->comms, space, 1);
      }
    }
  }

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_GATEWAY;
  sample->localpref = getData32(sample);
}

/*_________________---------------------------__________________
  _________________    readExtendedUser       __________________
  -----------------___________________________------------------
*/

void readExtendedUser(SFSample *sample)
{
  if(sample->datagramVersion >= 5) sample->src_user_charset = getData32(sample);
  sample->src_user_len = getString(sample, sample->src_user, SA_MAX_EXTENDED_USER_LEN);
  if(sample->datagramVersion >= 5) sample->dst_user_charset = getData32(sample);
  sample->dst_user_len = getString(sample, sample->dst_user, SA_MAX_EXTENDED_USER_LEN);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_USER;
}

/*_________________---------------------------__________________
  _________________    readExtendedUrl        __________________
  -----------------___________________________------------------
*/

void readExtendedUrl(SFSample *sample)
{
  sample->url_direction = getData32(sample);
  sample->url_len = getString(sample, sample->url, SA_MAX_EXTENDED_URL_LEN);
  if(sample->datagramVersion >= 5) sample->host_len = getString(sample, sample->host, SA_MAX_EXTENDED_HOST_LEN);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_URL;
}


/*_________________---------------------------__________________
  _________________       mplsLabelStack      __________________
  -----------------___________________________------------------
*/

void mplsLabelStack(SFSample *sample, char *fieldName)
{
  u_int32_t lab;

  sample->lstk.depth = getData32(sample);
  /* just point at the lablelstack array */
  if (sample->lstk.depth > 0) sample->lstk.stack = (u_int32_t *)sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, sample->lstk.depth * 4);
}

/*_________________---------------------------__________________
  _________________    readExtendedMpls       __________________
  -----------------___________________________------------------
*/

void readExtendedMpls(SFSample *sample)
{
  char buf[51];

  getAddress(sample, &sample->mpls_nextHop);

  mplsLabelStack(sample, "mpls_input_stack");
  mplsLabelStack(sample, "mpls_output_stack");
  
  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS;
}

/*_________________---------------------------__________________
  _________________    readExtendedNat        __________________
  -----------------___________________________------------------
*/

void readExtendedNat(SFSample *sample)
{
  char buf[51];

  getAddress(sample, &sample->nat_src);
  getAddress(sample, &sample->nat_dst);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_NAT;
}


/*_________________---------------------------__________________
  _________________    readExtendedMplsTunnel __________________
  -----------------___________________________------------------
*/

void readExtendedMplsTunnel(SFSample *sample)
{
#define SA_MAX_TUNNELNAME_LEN 100
  char tunnel_name[SA_MAX_TUNNELNAME_LEN+1];
  u_int32_t tunnel_id, tunnel_cos;
  
  getString(sample, tunnel_name, SA_MAX_TUNNELNAME_LEN); 
  tunnel_id = getData32(sample);
  tunnel_cos = getData32(sample);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsVC     __________________
  -----------------___________________________------------------
*/

void readExtendedMplsVC(SFSample *sample)
{
#define SA_MAX_VCNAME_LEN 100
  char vc_name[SA_MAX_VCNAME_LEN+1];
  u_int32_t vll_vc_id, vc_cos;

  getString(sample, vc_name, SA_MAX_VCNAME_LEN); 
  vll_vc_id = getData32(sample);
  vc_cos = getData32(sample);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_VC;
}

/*_________________---------------------------__________________
  _________________    readExtendedMplsFTN    __________________
  -----------------___________________________------------------
*/

void readExtendedMplsFTN(SFSample *sample)
{
#define SA_MAX_FTN_LEN 100
  char ftn_descr[SA_MAX_FTN_LEN+1];
  u_int32_t ftn_mask;

  getString(sample, ftn_descr, SA_MAX_FTN_LEN);
  ftn_mask = getData32(sample);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_FTN;
}

/*_________________---------------------------__________________
  _________________  readExtendedMplsLDP_FEC  __________________
  -----------------___________________________------------------
*/

void readExtendedMplsLDP_FEC(SFSample *sample)
{
  u_int32_t fec_addr_prefix_len = getData32(sample);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC;
}

/*_________________---------------------------__________________
  _________________  readExtendedVlanTunnel   __________________
  -----------------___________________________------------------
*/

void readExtendedVlanTunnel(SFSample *sample)
{
  SFLLabelStack lstk;

  lstk.depth = getData32(sample);
  /* just point at the lablelstack array */
  if(lstk.depth > 0) lstk.stack = (u_int32_t *)sample->datap;
  /* and skip over it in the input */
  skipBytes(sample, lstk.depth * 4);

  sample->extended_data_tag |= SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL;
}

/*_________________---------------------------__________________
  _________________    readExtendedProcess    __________________
  -----------------___________________________------------------
*/

void readExtendedProcess(SFSample *sample)
{
  u_int32_t num_processes, i;

  num_processes = getData32(sample);
  for (i = 0; i < num_processes; i++) skipBytes(sample, 4);
}

void readExtendedClass(SFSample *sample)
{
  u_int32_t ret;
  u_char buf[MAX_PROTOCOL_LEN+1], *bufptr = buf;

  if (config.classifiers_path) {
    ret = getData32_nobswap(sample);
    memcpy(bufptr, &ret, 4);
    bufptr += 4;
    ret = getData32_nobswap(sample);
    memcpy(bufptr, &ret, 4);
    bufptr += 4;
    ret = getData32_nobswap(sample);
    memcpy(bufptr, &ret, 4);
    bufptr += 4;
    ret = getData32_nobswap(sample);
    memcpy(bufptr, &ret, 4);
    bufptr += 4;

    sample->class = SF_evaluate_classifiers(buf);
  }
  else skipBytes(sample, MAX_PROTOCOL_LEN);
}

void readExtendedTag(SFSample *sample)
{
  sample->tag = getData32(sample);
  sample->tag2 = getData32(sample);
}

void decodeMpls(SFSample *sample)
{
  struct packet_ptrs dummy_pptrs;
  u_char *ptr = (u_char *)sample->datap, *end = sample->header + sample->headerLen;
  u_int16_t nl = 0, caplen = end - ptr;
  
  memset(&dummy_pptrs, 0, sizeof(dummy_pptrs));
  sample->eth_type = mpls_handler(ptr, &caplen, &nl, &dummy_pptrs);

  if (sample->eth_type == ETHERTYPE_IP) {
    sample->gotIPV4 = TRUE;
    sample->offsetToIPV4 = nl+(ptr-sample->header);
  } 
#if defined ENABLE_IPV6
  else if (sample->eth_type == ETHERTYPE_IPV6) {
    sample->gotIPV6 = TRUE;
    sample->offsetToIPV6 = nl+(ptr-sample->header);
  }
#endif

  if (nl) {
    sample->lstk.depth = nl / 4; 
    sample->lstk.stack = (u_int32_t *) dummy_pptrs.mpls_ptr;
  }
}

void decodePPP(SFSample *sample)
{
  struct packet_ptrs dummy_pptrs;
  struct pcap_pkthdr h;
  u_char *ptr = (u_char *)sample->datap, *end = sample->header + sample->headerLen;
  u_int16_t nl = 0;

  memset(&dummy_pptrs, 0, sizeof(dummy_pptrs));
  h.caplen = end - ptr; 
  dummy_pptrs.packet_ptr = ptr;
  ppp_handler(&h, &dummy_pptrs);
  sample->eth_type = dummy_pptrs.l3_proto;
  
  if (dummy_pptrs.mpls_ptr) {
    if (dummy_pptrs.iph_ptr) nl = dummy_pptrs.iph_ptr - dummy_pptrs.mpls_ptr;
    if (nl) {
      sample->lstk.depth = nl / 4;
      sample->lstk.stack = (u_int32_t *) dummy_pptrs.mpls_ptr;
    }
  }
  if (sample->eth_type == ETHERTYPE_IP) {
    sample->gotIPV4 = TRUE;
    sample->offsetToIPV4 = dummy_pptrs.iph_ptr - sample->header;
  }
#if defined ENABLE_IPV6
  else if (sample->eth_type == ETHERTYPE_IPV6) {
    sample->gotIPV6 = TRUE;
    sample->offsetToIPV6 = dummy_pptrs.iph_ptr - sample->header;
  }
#endif
}

/*_________________---------------------------__________________
  _________________  readFlowSample_header    __________________
  -----------------___________________________------------------
*/

void readFlowSample_header(SFSample *sample)
{
  sample->headerProtocol = getData32(sample);
  sample->sampledPacketSize = getData32(sample);
  if(sample->datagramVersion > 4) sample->stripped = getData32(sample);
  sample->headerLen = getData32(sample);
  
  sample->header = (u_char *)sample->datap; /* just point at the header */
  
  switch(sample->headerProtocol) {
    /* the header protocol tells us where to jump into the decode */
  case SFLHEADER_ETHERNET_ISO8023:
    decodeLinkLayer(sample);
    break;
  case SFLHEADER_IPv4: 
    sample->gotIPV4 = TRUE;
    sample->offsetToIPV4 = 0;
    break;
#if defined ENABLE_IPV6
  case SFLHEADER_IPv6:
    sample->gotIPV6 = TRUE;
    sample->offsetToIPV6 = 0;
    break;
#endif
  case SFLHEADER_MPLS:
    decodeMpls(sample);
    break;
  case SFLHEADER_PPP:
    decodePPP(sample);
    break;
  case SFLHEADER_ISO88024_TOKENBUS:
  case SFLHEADER_ISO88025_TOKENRING:
  case SFLHEADER_FDDI:
  case SFLHEADER_FRAME_RELAY:
  case SFLHEADER_X25:
  case SFLHEADER_SMDS:
  case SFLHEADER_AAL5:
  case SFLHEADER_AAL5_IP:
  default:
    /* XXX: nofity error */ 
    break;
  }
  
  if (sample->gotIPV4) decodeIPV4(sample);
#if defined ENABLE_IPV6
  else if (sample->gotIPV6) decodeIPV6(sample);
#endif

  skipBytes(sample, sample->headerLen);
}

/*_________________---------------------------__________________
  _________________  readFlowSample_ethernet  __________________
  -----------------___________________________------------------
*/

void readFlowSample_ethernet(SFSample *sample)
{
  sample->eth_len = getData32(sample);
  memcpy(sample->eth_src, sample->datap, 6);
  skipBytes(sample, 6);
  memcpy(sample->eth_dst, sample->datap, 6);
  skipBytes(sample, 6);
  sample->eth_type = getData32(sample);

  if (sample->eth_type == ETHERTYPE_IP) sample->gotIPV4 = TRUE;
#if defined ENABLE_IPV6
  else if (sample->eth_type == ETHERTYPE_IPV6) sample->gotIPV6 = TRUE;
#endif

  /* Commit eth_len to packet length: will be overwritten if we get
     SFLFLOW_IPV4 or SFLFLOW_IPV6; otherwise will get along as the
     best information we have */ 
  if (!sample->sampledPacketSize) sample->sampledPacketSize = sample->eth_len;
}


/*_________________---------------------------__________________
  _________________    readFlowSample_IPv4    __________________
  -----------------___________________________------------------
*/

void readFlowSample_IPv4(SFSample *sample)
{
  sample->headerLen = sizeof(SFLSampled_ipv4);
  sample->header = (u_char *)sample->datap; /* just point at the header */
  skipBytes(sample, sample->headerLen);
  {
    SFLSampled_ipv4 nfKey;

    memcpy(&nfKey, sample->header, sizeof(nfKey));
    sample->sampledPacketSize = ntohl(nfKey.length);
    sample->dcd_srcIP = nfKey.src_ip;
    sample->dcd_dstIP = nfKey.dst_ip;
    sample->dcd_ipProtocol = ntohl(nfKey.protocol);
    sample->dcd_ipTos = ntohl(nfKey.tos);
    sample->dcd_sport = ntohl(nfKey.src_port);
    sample->dcd_dport = ntohl(nfKey.dst_port);
  }

  sample->gotIPV4 = TRUE;
}

/*_________________---------------------------__________________
  _________________    readFlowSample_IPv6    __________________
  -----------------___________________________------------------
*/

void readFlowSample_IPv6(SFSample *sample)
{
  sample->header = (u_char *)sample->datap; /* just point at the header */
  sample->headerLen = sizeof(SFLSampled_ipv6);
  skipBytes(sample, sample->headerLen);

#if defined ENABLE_IPV6
  {
    SFLSampled_ipv6 nfKey6;

    memcpy(&nfKey6, sample->header, sizeof(nfKey6));
    sample->sampledPacketSize = ntohl(nfKey6.length);
    sample->ipsrc.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->ipsrc.address, &nfKey6.src_ip, IP6AddrSz);
    sample->ipdst.type = SFLADDRESSTYPE_IP_V6;
    memcpy(&sample->ipdst.address, &nfKey6.dst_ip, IP6AddrSz);
    sample->dcd_ipProtocol = ntohl(nfKey6.protocol);
    sample->dcd_ipTos = ntohl(nfKey6.priority);
    sample->dcd_sport = ntohl(nfKey6.src_port);
    sample->dcd_dport = ntohl(nfKey6.dst_port);
  }

  sample->gotIPV6 = TRUE;
#endif
}

/*_________________---------------------------__________________
  _________________    readv2v4FlowSample    __________________
  -----------------___________________________------------------
*/

void readv2v4FlowSample(SFSample *sample, struct packet_ptrs_vector *pptrsv, struct plugin_requests *req)
{
  sample->samplesGenerated = getData32(sample);
  {
    u_int32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }
  
  sample->meanSkipCount = getData32(sample);
  sample->samplePool = getData32(sample);
  sample->dropEvents = getData32(sample);
  sample->inputPort = getData32(sample);
  sample->outputPort = getData32(sample);
  sample->packet_data_tag = getData32(sample);
  
  switch(sample->packet_data_tag) {
    
  case INMPACKETTYPE_HEADER: readFlowSample_header(sample); break;
  case INMPACKETTYPE_IPV4: readFlowSample_IPv4(sample); break;
  case INMPACKETTYPE_IPV6: readFlowSample_IPv6(sample); break;
  default: 
    notify_malf_packet(LOG_INFO, "INFO: Discarding unknown v2/v4 Data Tag", (struct sockaddr *) pptrsv->v4.f_agent);
    xflow_tot_bad_datagrams++;
    break;
  }

  sample->extended_data_tag = 0;
  {
    u_int32_t x;
    sample->num_extended = getData32(sample);
    for(x = 0; x < sample->num_extended; x++) {
      u_int32_t extended_tag;
      extended_tag = getData32(sample);
      switch(extended_tag) {
      case INMEXTENDED_SWITCH: readExtendedSwitch(sample); break;
      case INMEXTENDED_ROUTER: readExtendedRouter(sample); break;
      case INMEXTENDED_GATEWAY:
	if(sample->datagramVersion == 2) readExtendedGateway_v2(sample);
	else readExtendedGateway(sample);
	break;
      case INMEXTENDED_USER: readExtendedUser(sample); break;
      case INMEXTENDED_URL: readExtendedUrl(sample); break;
      default: 
	notify_malf_packet(LOG_INFO, "INFO: Discarding unknown v2/v4 Extended Data Tag", (struct sockaddr *) pptrsv->v4.f_agent);
	xflow_tot_bad_datagrams++;
	break;
      }
    }
  }

  finalizeSample(sample, pptrsv, req);
}

/*_________________---------------------------__________________
  _________________    readv5FlowSample         __________________
  -----------------___________________________------------------
*/

void readv5FlowSample(SFSample *sample, int expanded, struct packet_ptrs_vector *pptrsv, struct plugin_requests *req)
{
  u_int32_t num_elements, sampleLength, actualSampleLength;
  u_char *sampleStart;

  sampleLength = getData32(sample);
  sampleStart = (u_char *)sample->datap;
  sample->samplesGenerated = getData32(sample);
  if(expanded) {
    sample->ds_class = getData32(sample);
    sample->ds_index = getData32(sample);
  }
  else {
    u_int32_t samplerId = getData32(sample);
    sample->ds_class = samplerId >> 24;
    sample->ds_index = samplerId & 0x00ffffff;
  }

  sample->meanSkipCount = getData32(sample);
  sample->samplePool = getData32(sample);
  sample->dropEvents = getData32(sample);
  if(expanded) {
    sample->inputPortFormat = getData32(sample);
    sample->inputPort = getData32(sample);
    sample->outputPortFormat = getData32(sample);
    sample->outputPort = getData32(sample);
  }
  else {
    u_int32_t inp, outp;
    inp = getData32(sample);
    outp = getData32(sample);
    sample->inputPortFormat = inp >> 30;
    sample->outputPortFormat = outp >> 30;
    sample->inputPort = inp; // skip 0x3fffffff mask
    sample->outputPort = outp; // skip 0x3fffffff mask
  }

  num_elements = getData32(sample);
  {
    int el;
    for (el = 0; el < num_elements; el++) {
      u_int32_t tag, length;
      u_char *start;
      tag = getData32(sample);
      length = getData32(sample);
      start = (u_char *)sample->datap;

      switch(tag) {
      case SFLFLOW_HEADER:     readFlowSample_header(sample); break;
      case SFLFLOW_ETHERNET:   readFlowSample_ethernet(sample); break;
      case SFLFLOW_IPV4:       readFlowSample_IPv4(sample); break;
      case SFLFLOW_IPV6:       readFlowSample_IPv6(sample); break;
      case SFLFLOW_EX_SWITCH:  readExtendedSwitch(sample); break;
      case SFLFLOW_EX_ROUTER:  readExtendedRouter(sample); break;
      case SFLFLOW_EX_GATEWAY: readExtendedGateway(sample); break;
      case SFLFLOW_EX_USER:    readExtendedUser(sample); break;
      case SFLFLOW_EX_URL:     readExtendedUrl(sample); break;
      case SFLFLOW_EX_MPLS:    readExtendedMpls(sample); break;
      case SFLFLOW_EX_NAT:     readExtendedNat(sample); break;
      case SFLFLOW_EX_MPLS_TUNNEL:  readExtendedMplsTunnel(sample); break;
      case SFLFLOW_EX_MPLS_VC:      readExtendedMplsVC(sample); break;
      case SFLFLOW_EX_MPLS_FTN:     readExtendedMplsFTN(sample); break;
      case SFLFLOW_EX_MPLS_LDP_FEC: readExtendedMplsLDP_FEC(sample); break;
      case SFLFLOW_EX_VLAN_TUNNEL:  readExtendedVlanTunnel(sample); break;
      case SFLFLOW_EX_PROCESS:      readExtendedProcess(sample); break;
      case SFLFLOW_EX_CLASS:	    readExtendedClass(sample); break;
      case SFLFLOW_EX_TAG:	    readExtendedTag(sample); break;
      default:
	// lengthCheck() here for extra security before skipBytes()
	if (lengthCheck(sample, start, length) == ERR) return;
	skipBytes(sample, length);
	break;
      }
      if (lengthCheck(sample, start, length) == ERR) return;
    }
  }
  if (lengthCheck(sample, sampleStart, sampleLength) == ERR) return;

  finalizeSample(sample, pptrsv, req);
}

void readv5CountersSample(SFSample *sample)
{
  u_int32_t sampleLength;

  sampleLength = getData32(sample);
  skipBytes(sample, sampleLength);
}

/*
   seems like sFlow v2/v4 does not supply any meaningful information
   about the length of current sample. This is because we still need
   to parse the very first part of the sample
*/ 
void readv2v4CountersSample(SFSample *sample)
{
  skipBytes(sample, 12);
  sample->counterBlockVersion = getData32(sample);

  switch(sample->counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC:
  case INMCOUNTERSVERSION_ETHERNET:
  case INMCOUNTERSVERSION_TOKENRING:
  case INMCOUNTERSVERSION_FDDI:
  case INMCOUNTERSVERSION_VG:
  case INMCOUNTERSVERSION_WAN: skipBytes(sample, 88); break;
  case INMCOUNTERSVERSION_VLAN: break;
  default: return; 
  }

  /* now see if there are any specific counter blocks to add */
  switch(sample->counterBlockVersion) {
  case INMCOUNTERSVERSION_GENERIC: /* nothing more */ break;
  case INMCOUNTERSVERSION_ETHERNET: skipBytes(sample, 52); break;
  case INMCOUNTERSVERSION_TOKENRING: skipBytes(sample, 72); break;
  case INMCOUNTERSVERSION_FDDI: break;
  case INMCOUNTERSVERSION_VG: skipBytes(sample, 80); break;
  case INMCOUNTERSVERSION_WAN: break;
  case INMCOUNTERSVERSION_VLAN: skipBytes(sample, 28); break;
  default: return; 
  }
}

void finalizeSample(SFSample *sample, struct packet_ptrs_vector *pptrsv, struct plugin_requests *req)
{
  struct packet_ptrs *pptrs = &pptrsv->v4;
  u_int16_t dcd_sport = htons(sample->dcd_sport), dcd_dport = htons(sample->dcd_dport);
  u_int8_t dcd_ipProtocol = sample->dcd_ipProtocol, dcd_ipTos = sample->dcd_ipTos;
  u_int8_t dcd_tcpFlags = sample->dcd_tcpFlags;
  u_int16_t vlan = htons(sample->in_vlan);

  /* check for out_vlan */
  if (!vlan && sample->out_vlan) vlan = htons(sample->out_vlan); 

  /*
     We consider packets if:
     - sample->gotIPV4 || sample->gotIPV6 : it belongs to either an IPv4 or IPv6 packet.
     - !sample->eth_type : we don't know the L3 protocol. VLAN or MPLS accounting case.
  */
  if (sample->gotIPV4 || sample->gotIPV6 || !sample->eth_type) {
    reset_net_status_v(pptrsv);
    pptrs->flow_type = SF_evaluate_flow_type(pptrs);

    /* we need to understand the IP protocol version in order to build the fake packet */
    switch (pptrs->flow_type) {
    case NF9_FTYPE_IPV4:
      if (req->bpf_filter) {
        reset_mac(pptrs);
        reset_ip4(pptrs);

        memcpy(pptrs->mac_ptr+ETH_ADDR_LEN, &sample->eth_src, ETH_ADDR_LEN); 
        memcpy(pptrs->mac_ptr, &sample->eth_dst, ETH_ADDR_LEN);
	((struct my_iphdr *)pptrs->iph_ptr)->ip_vhl = 0x45;
        memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_src, &sample->dcd_srcIP, 4);
        memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_dst, &sample->dcd_dstIP, 4);
        memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_p, &dcd_ipProtocol, 1);
        memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_tos, &dcd_ipTos, 1);
        memcpy(&((struct my_tlhdr *)pptrs->tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrs->lm_mask_src = sample->srcMask;
      pptrs->lm_mask_dst = sample->dstMask;
      pptrs->lm_method_src = NF_NET_KEEP;
      pptrs->lm_method_dst = NF_NET_KEEP;

      pptrs->l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(pptrs);
      if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, pptrs, &pptrs->bta, &pptrs->bta2);
      if (config.nfacctd_bgp_iface_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, pptrs, &pptrs->bitr, NULL);
      if (config.nfacctd_bgp) bgp_srcdst_lookup(pptrs);
      if (config.nfacctd_bgp_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, pptrs, &pptrs->bpas, NULL);
      if (config.nfacctd_bgp_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, pptrs, &pptrs->blp, NULL);
      if (config.nfacctd_bgp_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, pptrs, &pptrs->bmed, NULL);
      if (config.pre_tag_map) SF_find_id((struct id_table *)pptrs->idtable, pptrs, &pptrs->tag, &pptrs->tag2);
      exec_plugins(pptrs);
      break;
#if defined ENABLE_IPV6
    case NF9_FTYPE_IPV6:
      pptrsv->v6.flow_type = pptrs->flow_type;

      if (req->bpf_filter) {
        reset_mac(&pptrsv->v6);
        reset_ip6(&pptrsv->v6);

	((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_ctlun.ip6_un2_vfc = 0x60;
        memcpy(pptrsv->v6.mac_ptr+ETH_ADDR_LEN, &sample->eth_src, ETH_ADDR_LEN); 
        memcpy(pptrsv->v6.mac_ptr, &sample->eth_dst, ETH_ADDR_LEN);
        memcpy(&((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_src, &sample->ipsrc.address.ip_v6, IP6AddrSz);
        memcpy(&((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_dst, &sample->ipdst.address.ip_v6, IP6AddrSz);
        memcpy(&((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_nxt, &dcd_ipProtocol, 1);
        /* XXX: class ID ? */
        memcpy(&((struct my_tlhdr *)pptrsv->v6.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct my_tlhdr *)pptrsv->v6.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct my_tcphdr *)pptrsv->v6.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->v6.lm_mask_src = sample->srcMask;
      pptrsv->v6.lm_mask_dst = sample->dstMask;
      pptrsv->v6.lm_method_src = NF_NET_KEEP;
      pptrsv->v6.lm_method_dst = NF_NET_KEEP;

      pptrsv->v6.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->v6);
      if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->v6, &pptrsv->v6.bta, &pptrsv->v6.bta2);
      if (config.nfacctd_bgp_iface_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->v6, &pptrsv->v6.bitr, NULL);
      if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->v6);
      if (config.nfacctd_bgp_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->v6, &pptrsv->v6.bpas, NULL);
      if (config.nfacctd_bgp_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->v6, &pptrsv->v6.blp, NULL);
      if (config.nfacctd_bgp_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->v6, &pptrsv->v6.bmed, NULL);
      if (config.pre_tag_map) SF_find_id((struct id_table *)pptrs->idtable, &pptrsv->v6, &pptrsv->v6.tag, &pptrsv->v6.tag2);
      exec_plugins(&pptrsv->v6);
      break;
#endif
    case NF9_FTYPE_VLAN_IPV4:
      pptrsv->vlan4.flow_type = pptrs->flow_type;

      if (req->bpf_filter) {
        reset_mac_vlan(&pptrsv->vlan4);
        reset_ip4(&pptrsv->vlan4);

        memcpy(pptrsv->vlan4.mac_ptr+ETH_ADDR_LEN, &sample->eth_src, ETH_ADDR_LEN); 
        memcpy(pptrsv->vlan4.mac_ptr, &sample->eth_dst, ETH_ADDR_LEN); 
        memcpy(pptrsv->vlan4.vlan_ptr, &vlan, 2); 
	((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_vhl = 0x45;
        memcpy(&((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_src, &sample->dcd_srcIP, 4);
        memcpy(&((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_dst, &sample->dcd_dstIP, 4);
        memcpy(&((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_p, &dcd_ipProtocol, 1);
        memcpy(&((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_tos, &dcd_ipTos, 1); 
        memcpy(&((struct my_tlhdr *)pptrsv->vlan4.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct my_tlhdr *)pptrsv->vlan4.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct my_tcphdr *)pptrsv->vlan4.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->vlan4.lm_mask_src = sample->srcMask;
      pptrsv->vlan4.lm_mask_dst = sample->dstMask;
      pptrsv->vlan4.lm_method_src = NF_NET_KEEP;
      pptrsv->vlan4.lm_method_dst = NF_NET_KEEP;

      pptrsv->vlan4.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlan4);
      if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlan4, &pptrsv->vlan4.bta, &pptrsv->vlan4.bta2);
      if (config.nfacctd_bgp_iface_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlan4, &pptrsv->vlan4.bitr, NULL);
      if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->vlan4);
      if (config.nfacctd_bgp_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlan4, &pptrsv->vlan4.bpas, NULL);
      if (config.nfacctd_bgp_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlan4, &pptrsv->vlan4.blp, NULL);
      if (config.nfacctd_bgp_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlan4, &pptrsv->vlan4.bmed, NULL);
      if (config.pre_tag_map) SF_find_id((struct id_table *)pptrs->idtable, &pptrsv->vlan4, &pptrsv->vlan4.tag, &pptrsv->vlan4.tag2);
      exec_plugins(&pptrsv->vlan4);
      break;
#if defined ENABLE_IPV6
    case NF9_FTYPE_VLAN_IPV6:
      pptrsv->vlan6.flow_type = pptrs->flow_type;

      if (req->bpf_filter) {
        reset_mac_vlan(&pptrsv->vlan6);
        reset_ip6(&pptrsv->vlan6);

        memcpy(pptrsv->vlan6.mac_ptr+ETH_ADDR_LEN, &sample->eth_src, ETH_ADDR_LEN);
        memcpy(pptrsv->vlan6.mac_ptr, &sample->eth_dst, ETH_ADDR_LEN); 
        memcpy(pptrsv->vlan6.vlan_ptr, &vlan, 2); 
	((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_ctlun.ip6_un2_vfc = 0x60;
        memcpy(&((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_src, &sample->ipsrc.address.ip_v6, IP6AddrSz); 
        memcpy(&((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_dst, &sample->ipdst.address.ip_v6, IP6AddrSz);
        memcpy(&((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_nxt, &dcd_ipProtocol, 1); 
        /* XXX: class ID ? */
        memcpy(&((struct my_tlhdr *)pptrsv->vlan6.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct my_tlhdr *)pptrsv->vlan6.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct my_tcphdr *)pptrsv->vlan6.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->vlan6.lm_mask_src = sample->srcMask;
      pptrsv->vlan6.lm_mask_dst = sample->dstMask;
      pptrsv->vlan6.lm_method_src = NF_NET_KEEP;
      pptrsv->vlan6.lm_method_dst = NF_NET_KEEP;

      pptrsv->vlan6.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlan6);
      if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlan6, &pptrsv->vlan6.bta, &pptrsv->vlan6.bta2);
      if (config.nfacctd_bgp_iface_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlan6, &pptrsv->vlan6.bitr, NULL);
      if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->vlan6);
      if (config.nfacctd_bgp_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlan6, &pptrsv->vlan6.bpas, NULL);
      if (config.nfacctd_bgp_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlan6, &pptrsv->vlan6.blp, NULL);
      if (config.nfacctd_bgp_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlan6, &pptrsv->vlan6.bmed, NULL);
      if (config.pre_tag_map) SF_find_id((struct id_table *)pptrs->idtable, &pptrsv->vlan6, &pptrsv->vlan6.tag, &pptrsv->vlan6.tag2);
      exec_plugins(&pptrsv->vlan6);
      break;
#endif
    case NF9_FTYPE_MPLS_IPV4:
      pptrsv->mpls4.flow_type = pptrs->flow_type;

      if (req->bpf_filter) {
        u_char *ptr = pptrsv->mpls4.mpls_ptr;
        u_int32_t label, idx;

        /* XXX: fix caplen */
        reset_mac(&pptrsv->mpls4);

        memcpy(pptrsv->mpls4.mac_ptr+ETH_ADDR_LEN, &sample->eth_src, ETH_ADDR_LEN); 
        memcpy(pptrsv->mpls4.mac_ptr, &sample->eth_dst, ETH_ADDR_LEN); 

        for (idx = 0; idx <= sample->lstk.depth && idx < 10; idx++) { 
          label = sample->lstk.stack[idx];
          memcpy(ptr, &label, 4);
          ptr += 4;
        }
	stick_bosbit(ptr-4);
        pptrsv->mpls4.iph_ptr = ptr;
        pptrsv->mpls4.tlh_ptr = ptr + IP4HdrSz;
        reset_ip4(&pptrsv->mpls4);
	
	((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_vhl = 0x45;
        memcpy(&((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_src, &sample->dcd_srcIP, 4);
        memcpy(&((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_dst, &sample->dcd_dstIP, 4); 
        memcpy(&((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_p, &dcd_ipProtocol, 1); 
        memcpy(&((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_tos, &dcd_ipTos, 1); 
        memcpy(&((struct my_tlhdr *)pptrsv->mpls4.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct my_tlhdr *)pptrsv->mpls4.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct my_tcphdr *)pptrsv->mpls4.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->mpls4.lm_mask_src = sample->srcMask;
      pptrsv->mpls4.lm_mask_dst = sample->dstMask;
      pptrsv->mpls4.lm_method_src = NF_NET_KEEP;
      pptrsv->mpls4.lm_method_dst = NF_NET_KEEP;

      pptrsv->mpls4.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->mpls4);
      if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->mpls4, &pptrsv->mpls4.bta, &pptrsv->mpls4.bta2);
      if (config.nfacctd_bgp_iface_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->mpls4, &pptrsv->mpls4.bitr, NULL);
      if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->mpls4);
      if (config.nfacctd_bgp_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->mpls4, &pptrsv->mpls4.bpas, NULL);
      if (config.nfacctd_bgp_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->mpls4, &pptrsv->mpls4.blp, NULL);
      if (config.nfacctd_bgp_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->mpls4, &pptrsv->mpls4.bmed, NULL);
      if (config.pre_tag_map) SF_find_id((struct id_table *)pptrs->idtable, &pptrsv->mpls4, &pptrsv->mpls4.tag, &pptrsv->mpls4.tag2);
      exec_plugins(&pptrsv->mpls4);
      break;
#if defined ENABLE_IPV6
    case NF9_FTYPE_MPLS_IPV6:
      pptrsv->mpls6.flow_type = pptrs->flow_type;

      if (req->bpf_filter) {
        u_char *ptr = pptrsv->mpls6.mpls_ptr;
        u_int32_t label, idx;

        /* XXX: fix caplen */
        reset_mac(&pptrsv->mpls6);
        memcpy(pptrsv->mpls6.mac_ptr+ETH_ADDR_LEN, &sample->eth_src, ETH_ADDR_LEN); 
        memcpy(pptrsv->mpls6.mac_ptr, &sample->eth_dst, ETH_ADDR_LEN); 

	for (idx = 0; idx <= sample->lstk.depth && idx < 10; idx++) {
	  label = sample->lstk.stack[idx];
	  memcpy(ptr, &label, 4);
	  ptr += 4;
	}
	stick_bosbit(ptr-4);
        pptrsv->mpls6.iph_ptr = ptr;
        pptrsv->mpls6.tlh_ptr = ptr + IP6HdrSz;
        reset_ip6(&pptrsv->mpls6);

	((struct ip6_hdr *)pptrsv->mpls6.iph_ptr)->ip6_ctlun.ip6_un2_vfc = 0x60;
        memcpy(&((struct ip6_hdr *)pptrsv->mpls6.iph_ptr)->ip6_src, &sample->ipsrc.address.ip_v6, IP6AddrSz); 
        memcpy(&((struct ip6_hdr *)pptrsv->mpls6.iph_ptr)->ip6_dst, &sample->ipdst.address.ip_v6, IP6AddrSz); 
        memcpy(&((struct ip6_hdr *)pptrsv->mpls6.iph_ptr)->ip6_nxt, &dcd_ipProtocol, 1); 
        /* XXX: class ID ? */
        memcpy(&((struct my_tlhdr *)pptrsv->mpls6.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct my_tlhdr *)pptrsv->mpls6.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct my_tcphdr *)pptrsv->mpls6.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->mpls6.lm_mask_src = sample->srcMask;
      pptrsv->mpls6.lm_mask_dst = sample->dstMask;
      pptrsv->mpls6.lm_method_src = NF_NET_KEEP;
      pptrsv->mpls6.lm_method_dst = NF_NET_KEEP;

      pptrsv->mpls6.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->mpls6);
      if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->mpls6, &pptrsv->mpls6.bta, &pptrsv->mpls6.bta2);
      if (config.nfacctd_bgp_iface_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->mpls6, &pptrsv->mpls6.bitr, NULL);
      if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->mpls6);
      if (config.nfacctd_bgp_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->mpls6, &pptrsv->mpls6.bpas, NULL);
      if (config.nfacctd_bgp_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->mpls6, &pptrsv->mpls6.blp, NULL);
      if (config.nfacctd_bgp_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->mpls6, &pptrsv->mpls6.bmed, NULL);
      if (config.pre_tag_map) SF_find_id((struct id_table *)pptrs->idtable, &pptrsv->mpls6, &pptrsv->mpls6.tag, &pptrsv->mpls6.tag2);
      exec_plugins(&pptrsv->mpls6);
      break;
#endif
    case NF9_FTYPE_VLAN_MPLS_IPV4:
      pptrsv->vlanmpls4.flow_type = pptrs->flow_type;

      if (req->bpf_filter) {
        u_char *ptr = pptrsv->vlanmpls4.mpls_ptr;
        u_int32_t label, idx;

        /* XXX: fix caplen */
        reset_mac_vlan(&pptrsv->vlanmpls4);
        memcpy(pptrsv->vlanmpls4.mac_ptr+ETH_ADDR_LEN, &sample->eth_src, ETH_ADDR_LEN); 
        memcpy(pptrsv->vlanmpls4.mac_ptr, &sample->eth_dst, ETH_ADDR_LEN); 
        memcpy(pptrsv->vlanmpls4.vlan_ptr, &vlan, 2); 

	for (idx = 0; idx <= sample->lstk.depth && idx < 10; idx++) {
	  label = sample->lstk.stack[idx];
	  memcpy(ptr, &label, 4);
	  ptr += 4;
	}
	stick_bosbit(ptr-4);
        pptrsv->vlanmpls4.iph_ptr = ptr;
        pptrsv->vlanmpls4.tlh_ptr = ptr + IP4HdrSz;
        reset_ip4(&pptrsv->vlanmpls4);

	((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_vhl = 0x45;
        memcpy(&((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_src, &sample->dcd_srcIP, 4); 
        memcpy(&((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_dst, &sample->dcd_dstIP, 4);
        memcpy(&((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_p, &dcd_ipProtocol, 1);
        memcpy(&((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_tos, &dcd_ipTos, 1);
        memcpy(&((struct my_tlhdr *)pptrsv->vlanmpls4.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct my_tlhdr *)pptrsv->vlanmpls4.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct my_tcphdr *)pptrsv->vlanmpls4.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->vlanmpls4.lm_mask_src = sample->srcMask;
      pptrsv->vlanmpls4.lm_mask_dst = sample->dstMask;
      pptrsv->vlanmpls4.lm_method_src = NF_NET_KEEP;
      pptrsv->vlanmpls4.lm_method_dst = NF_NET_KEEP;

      pptrsv->vlanmpls4.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlanmpls4);
      if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bta, &pptrsv->vlanmpls4.bta2);
      if (config.nfacctd_bgp_iface_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bitr, NULL);
      if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->vlanmpls4);
      if (config.nfacctd_bgp_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bpas, NULL);
      if (config.nfacctd_bgp_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.blp, NULL);
      if (config.nfacctd_bgp_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bmed, NULL);
      if (config.pre_tag_map) SF_find_id((struct id_table *)pptrs->idtable, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.tag, &pptrsv->vlanmpls4.tag2);
      exec_plugins(&pptrsv->vlanmpls4);
      break;
#if defined ENABLE_IPV6
    case NF9_FTYPE_VLAN_MPLS_IPV6:
      pptrsv->vlanmpls6.flow_type = pptrs->flow_type;

      if (req->bpf_filter) {
        u_char *ptr = pptrsv->vlanmpls6.mpls_ptr;
        u_int32_t label, idx;

        /* XXX: fix caplen */
        reset_mac_vlan(&pptrsv->vlanmpls6);
        memcpy(pptrsv->vlanmpls6.mac_ptr+ETH_ADDR_LEN, &sample->eth_src, ETH_ADDR_LEN); 
        memcpy(pptrsv->vlanmpls6.mac_ptr, &sample->eth_dst, ETH_ADDR_LEN); 
        memcpy(pptrsv->vlanmpls6.vlan_ptr, &vlan, 2); 

	for (idx = 0; idx <= sample->lstk.depth && idx < 10; idx++) {
	  label = sample->lstk.stack[idx];
	  memcpy(ptr, &label, 4);
	  ptr += 4;
	}
	stick_bosbit(ptr-4);
        pptrsv->vlanmpls6.iph_ptr = ptr;
        pptrsv->vlanmpls6.tlh_ptr = ptr + IP6HdrSz;
        reset_ip6(&pptrsv->vlanmpls6);

	((struct ip6_hdr *)pptrsv->vlanmpls6.iph_ptr)->ip6_ctlun.ip6_un2_vfc = 0x60;
        memcpy(&((struct ip6_hdr *)pptrsv->vlanmpls6.iph_ptr)->ip6_src, &sample->ipsrc.address.ip_v6, IP6AddrSz); 
        memcpy(&((struct ip6_hdr *)pptrsv->vlanmpls6.iph_ptr)->ip6_dst, &sample->ipdst.address.ip_v6, IP6AddrSz); 
        memcpy(&((struct ip6_hdr *)pptrsv->vlanmpls6.iph_ptr)->ip6_nxt, &dcd_ipProtocol, 1); 
        /* XXX: class ID ? */
        memcpy(&((struct my_tlhdr *)pptrsv->vlanmpls6.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct my_tlhdr *)pptrsv->vlanmpls6.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct my_tcphdr *)pptrsv->vlanmpls6.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->vlanmpls6.lm_mask_src = sample->srcMask;
      pptrsv->vlanmpls6.lm_mask_dst = sample->dstMask;
      pptrsv->vlanmpls6.lm_method_src = NF_NET_KEEP;
      pptrsv->vlanmpls6.lm_method_dst = NF_NET_KEEP;

      pptrsv->vlanmpls6.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlanmpls6);
      if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bta, &pptrsv->vlanmpls6.bta2);
      if (config.nfacctd_bgp_iface_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bitr, NULL);
      if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->vlanmpls6);
      if (config.nfacctd_bgp_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bpas, NULL);
      if (config.nfacctd_bgp_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.blp, NULL);
      if (config.nfacctd_bgp_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bmed, NULL);
      if (config.pre_tag_map) SF_find_id((struct id_table *)pptrs->idtable, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.tag, &pptrsv->vlanmpls6.tag2);
      exec_plugins(&pptrsv->vlanmpls6);
      break;
#endif
    default:
      break;
    }
  }
}

int SF_find_id(struct id_table *t, struct packet_ptrs *pptrs, pm_id_t *tag, pm_id_t *tag2)
{
  SFSample *sample = (SFSample *)pptrs->f_data; 
  int x, j;
  pm_id_t id, stop, ret;

  if (!t) return 0;

  /* The id_table is shared between by IPv4 and IPv6 sFlow collectors.
     IPv4 ones are in the lower part (0..x), IPv6 ones are in the upper
     part (x+1..end)
  */

  pretag_init_vars(pptrs);
  id = 0;
  if (tag) *tag = 0;
  if (tag2) *tag2 = 0;

  if (sample->agent_addr.type == SFLADDRESSTYPE_IP_V4) {
    for (x = 0; x < t->ipv4_num; x++) {
      if (t->e[x].agent_ip.a.address.ipv4.s_addr == sample->agent_addr.address.ip_v4.s_addr) {
	t->e[x].last_matched = FALSE;
        for (j = 0, stop = 0, ret = 0; ((!ret || ret > TRUE) && (*t->e[x].func[j])); j++) {
          ret = (*t->e[x].func[j])(pptrs, &id, &t->e[x]);
          if (ret > TRUE) stop |= ret;
          else stop = ret;
        }
        if (!stop || stop > TRUE) {
          if (stop & PRETAG_MAP_RCODE_ID) {
            if (t->e[x].stack.func) id = (*t->e[x].stack.func)(id, *tag);
            *tag = id;
          }
          else if (stop & PRETAG_MAP_RCODE_ID2) {
            if (t->e[x].stack.func) id = (*t->e[x].stack.func)(id, *tag2);
            *tag2 = id;
          }
          else if (stop == BTA_MAP_RCODE_ID_ID2) {
            // stack not applicable here
            *tag = id;
            *tag2 = t->e[x].id2;
          }

          if (t->e[x].jeq.ptr) {
	    if (t->e[x].ret) {
              exec_plugins(pptrs);
	      set_shadow_status(pptrs);
	      *tag = 0;
	      *tag2 = 0;
	    }
            x = t->e[x].jeq.ptr->pos;
            x--; /* yes, it will be automagically incremented by the for() cycle */
            id = 0;
          }
          else break;
        }
      }
    }
  }
#if defined ENABLE_IPV6
  else if (sample->agent_addr.type == SFLADDRESSTYPE_IP_V6) { 
    for (x = (t->num-t->ipv6_num); x < t->num; x++) {
      if (!ip6_addr_cmp(&t->e[x].agent_ip.a.address.ipv6, &sample->agent_addr.address.ip_v6)) {
        for (j = 0, stop = 0, ret = 0; ((!ret || ret > TRUE) && (*t->e[x].func[j])); j++) {
          ret = (*t->e[x].func[j])(pptrs, &id, &t->e[x]);
          if (ret > TRUE) stop |= ret;
          else stop = ret;
        }
        if (!stop || stop > TRUE) {
          if (stop & PRETAG_MAP_RCODE_ID) {
            if (t->e[x].stack.func) id = (*t->e[x].stack.func)(id, *tag);
            *tag = id;
          }
          else if (stop & PRETAG_MAP_RCODE_ID2) {
            if (t->e[x].stack.func) id = (*t->e[x].stack.func)(id, *tag2);
            *tag2 = id;
          }
          else if (stop == BTA_MAP_RCODE_ID_ID2) {
            // stack not applicable here
            *tag = id;
            *tag2 = t->e[x].id2;
          }

          if (t->e[x].jeq.ptr) {
	    if (t->e[x].ret) {
              exec_plugins(pptrs);
              set_shadow_status(pptrs);
	      *tag = 0;
	      *tag2 = 0;
	    }

            x = t->e[x].jeq.ptr->pos;
            x--; /* yes, it will be automagically incremented by the for() cycle */
            id = 0;
          }
          else break;
        }
      }
    }
  }
#endif

  return stop;
}

u_int16_t SF_evaluate_flow_type(struct packet_ptrs *pptrs)
{
  SFSample *sample = (SFSample *)pptrs->f_data;
  u_int8_t ret = 0;

  if (sample->in_vlan || sample->out_vlan) ret += NF9_FTYPE_VLAN;
  if (sample->lstk.depth > 0) ret += NF9_FTYPE_MPLS;
  if (sample->gotIPV4); 
  else if (sample->gotIPV6) ret += NF9_FTYPE_IPV6;

  return ret;
}

void set_vector_sample_type(struct packet_ptrs_vector *pptrsv, u_int32_t sample_type)
{
  pptrsv->v4.sample_type = sample_type;
  pptrsv->vlan4.sample_type = sample_type;
  pptrsv->mpls4.sample_type = sample_type;
  pptrsv->vlanmpls4.sample_type = sample_type;
#if defined ENABLE_IPV6
  pptrsv->v6.sample_type = sample_type;
  pptrsv->vlan6.sample_type = sample_type;
  pptrsv->mpls6.sample_type = sample_type;
  pptrsv->vlanmpls6.sample_type = sample_type;
#endif
}

void reset_mac(struct packet_ptrs *pptrs)
{
  memset(pptrs->mac_ptr, 0, 2*ETH_ADDR_LEN);
}

void reset_mac_vlan(struct packet_ptrs *pptrs)
{
  memset(pptrs->mac_ptr, 0, 2*ETH_ADDR_LEN);
  memset(pptrs->vlan_ptr, 0, 2);
}

void reset_ip4(struct packet_ptrs *pptrs)
{
  memset(pptrs->iph_ptr, 0, IP4TlSz);
  Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_vhl, 5);
}

#if defined ENABLE_IPV6
void reset_ip6(struct packet_ptrs *pptrs)
{
  memset(pptrs->iph_ptr, 0, IP6TlSz);
  Assign16(((struct ip6_hdr *)pptrs->iph_ptr)->ip6_plen, htons(100));
  Assign16(((struct ip6_hdr *)pptrs->iph_ptr)->ip6_hlim, htons(64));
}
#endif

/* dummy functions; their use is limited to solve a trivial dependency */ 
int ip_handler(register struct packet_ptrs *pptrs)
{
}

int ip6_handler(register struct packet_ptrs *pptrs)
{
}

char *sfv245_check_status(SFSample *spp, struct sockaddr *sa)
{
  struct sockaddr salocal;
  u_int32_t aux1 = spp->agentSubId;
  struct xflow_status_entry *entry = NULL;
  int hash; 

  memcpy(&salocal, sa, sizeof(struct sockaddr));

  /* Let's copy the IPv4 sFlow agent address; family is defined just in case the
     remote peer IP address was reported as IPv4-mapped IPv6 address */
  salocal.sa_family = AF_INET; 
  ( (struct sockaddr_in *)&salocal )->sin_addr = spp->agent_addr.address.ip_v4;

  hash = hash_status_table(aux1, &salocal, XFLOW_STATUS_TABLE_SZ);

  if (hash >= 0) {
    entry = search_status_table(&salocal, aux1, 0, hash, XFLOW_STATUS_TABLE_MAX_ENTRIES);
    if (entry) {
      update_status_table(entry, spp->sequenceNo);
      entry->inc = 1;
    }
  }

  return (char *) entry;
}

/* Dummy objects here - ugly to see but well portable */
void NF_find_id(struct id_table *t, struct packet_ptrs *pptrs, pm_id_t *tag, pm_id_t *tag2)
{
}
