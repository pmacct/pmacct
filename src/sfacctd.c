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

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "sflow.h"
#include "bgp/bgp_packet.h"
#include "bgp/bgp.h"
#include "sfacctd.h"
#include "sfv5_module.h"
#include "pretag_handlers.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "ip_flow.h"
#include "ip_frag.h"
#include "classifier.h"
#include "net_aggr.h"
#include "crc32.h"
#include "isis/isis.h"
#include "bmp/bmp.h"
#ifdef WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#if defined (WITH_NDPI)
#include "ndpi/ndpi.h"
#include "ndpi/ndpi_util.h"
#endif

/* variables to be exported away */
int sfacctd_counter_backend_methods;
struct bgp_misc_structs *sf_cnt_misc_db;
struct host_addr debug_a;
char debug_agent_addr[50];
u_int16_t debug_agent_port;



/* Functions */
void usage_daemon(char *prog_name)
{
  printf("%s %s (%s)\n", SFACCTD_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
  printf("Usage: %s [ -D | -d ] [ -L IP address ] [ -l port ] [ -c primitive [ , ... ] ] [ -P plugin [ , ... ] ]\n", prog_name);
  printf("       %s [ -f config_file ]\n", prog_name);
  printf("       %s [ -h ]\n", prog_name);
  printf("\nGeneral options:\n");
  printf("  -h  \tShow this page\n");
  printf("  -V  \tShow version and compile-time options and exit\n");
  printf("  -L  \tBind to the specified IP address\n");
  printf("  -l  \tListen on the specified UDP port\n");
  printf("  -f  \tLoad configuration from the specified file\n");
  printf("  -a  \tPrint list of supported aggregation primitives\n");
  printf("  -c  \tAggregation method, see full list of primitives with -a (DEFAULT: src_host)\n");
  printf("  -D  \tDaemonize\n"); 
  printf("  -n  \tPath to a file containing networks and/or ASNs definitions\n");
  printf("  -t  \tPath to a file containing ports definitions\n");
  printf("  -P  \t[ memory | print | mysql | pgsql | sqlite3 | amqp | kafka | tee ] \n\tActivate plugin\n"); 
  printf("  -d  \tEnable debug\n");
  printf("  -S  \t[ auth | mail | daemon | kern | user | local[0-7] ] \n\tLog to the specified syslog facility\n");
  printf("  -F  \tWrite Core Process PID into the specified file\n");
  printf("  -R  \tRenormalize sampled data\n");
  printf("  -u  \tLeave IP protocols in numerical format\n");
  printf("  -I  \tRead packets from the specified savefile\n");
  printf("  -Z  \tReading from a savefile, sleep the given amount of seconds at startup and between replays\n");
  printf("  -W  \tReading from a savefile, don't exit but sleep when finished\n");
  printf("  -Y  \tReading from a savefile, replay the number of times specified\n");
  printf("\nMemory plugin (-P memory) options:\n");
  printf("  -p  \tSocket for client-server communication (DEFAULT: /tmp/collect.pipe)\n");
  printf("  -b  \tNumber of buckets\n");
  printf("  -m  \tNumber of memory pools\n");
  printf("  -s  \tMemory pool size\n");
  printf("\nPrint plugin (-P print) plugin options:\n");
  printf("  -r  \tRefresh time (in seconds)\n");
  printf("  -O  \t[ formatted | csv | json | avro ] \n\tOutput format\n");
  printf("  -o  \tPath to output file\n");
  printf("  -M  \tPrint event init/close marker messages\n");
  printf("  -A  \tAppend output (applies to -o)\n");
  printf("  -E  \tCSV format separator (applies to -O csv, DEFAULT: ',')\n");
  printf("\n");
  printf("For examples, see:\n");
  printf("  https://github.com/pmacct/pmacct/blob/master/QUICKSTART or\n");
  printf("  https://github.com/pmacct/pmacct/wiki\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}


int main(int argc,char **argv, char **envp)
{
  struct plugins_list_entry *list;
  struct plugin_requests req;
  struct packet_ptrs_vector pptrs;
  char config_file[SRVBUFLEN];
  unsigned char *sflow_packet;
  int logf, rc, yes=1, allowed;
  struct host_addr addr;
  struct hosts_table allow;
  struct id_table bpas_table;
  struct id_table blp_table;
  struct id_table bmed_table;
  struct id_table biss_table;
  struct id_table bta_table;
  struct id_table bitr_table;
  struct id_table sampling_table;
  u_int32_t idx;
  int capture_methods = 0;
  int ret, alloc_sppi = FALSE;
  SFSample spp;

  struct sockaddr_storage server, client;
  struct ipv6_mreq multi_req6;
  socklen_t  clen = sizeof(client), slen = 0;
  struct ip_mreq multi_req4;

  int pm_pcap_savefile_round = 0;

  unsigned char dummy_packet[64]; 
  unsigned char dummy_packet_vlan[64]; 
  unsigned char dummy_packet_mpls[128]; 
  unsigned char dummy_packet_vlan_mpls[128]; 
  struct pcap_pkthdr dummy_pkthdr;
  struct pcap_pkthdr dummy_pkthdr_vlan;
  struct pcap_pkthdr dummy_pkthdr_mpls;
  struct pcap_pkthdr dummy_pkthdr_vlan_mpls;

  unsigned char dummy_packet6[92]; 
  unsigned char dummy_packet_vlan6[92]; 
  unsigned char dummy_packet_mpls6[128]; 
  unsigned char dummy_packet_vlan_mpls6[128]; 
  struct pcap_pkthdr dummy_pkthdr6;
  struct pcap_pkthdr dummy_pkthdr_vlan6;
  struct pcap_pkthdr dummy_pkthdr_mpls6;
  struct pcap_pkthdr dummy_pkthdr_vlan_mpls6;

  struct packet_ptrs recv_pptrs;
  struct pcap_pkthdr recv_pkthdr;

  sigset_t signal_set;

  /* getopt() stuff */
  extern char *optarg;
  int errflag, cp; 

#ifdef WITH_REDIS
  struct p_redis_host redis_host;
#endif

#if defined HAVE_MALLOPT
  mallopt(M_CHECK_ACTION, 0);
#endif

  umask(077);
  SF_compute_once();

  /* a bunch of default definitions */ 
  reload_map = FALSE;
  print_stats = FALSE;
  reload_geoipv2_file = FALSE;
  reload_log_sf_cnt = FALSE;
  bpas_map_allocated = FALSE;
  blp_map_allocated = FALSE;
  bmed_map_allocated = FALSE;
  biss_map_allocated = FALSE;
  bta_map_allocated = FALSE;
  bitr_map_allocated = FALSE;
  custom_primitives_allocated = FALSE;
  bta_map_caching = TRUE;
  sampling_map_caching = TRUE;
  find_id_func = SF_find_id;
  plugins_list = NULL;
  sflow_packet = malloc(SFLOW_MAX_MSG_SIZE);

  data_plugins = 0;
  tee_plugins = 0;
  errflag = 0;
  sfacctd_counter_backend_methods = 0;

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
  memset(empty_mem_area_256b, 0, sizeof(empty_mem_area_256b));

  memset(&bpas_table, 0, sizeof(bpas_table));
  memset(&blp_table, 0, sizeof(blp_table));
  memset(&bmed_table, 0, sizeof(bmed_table));
  memset(&biss_table, 0, sizeof(biss_table));
  memset(&bta_table, 0, sizeof(bta_table));
  memset(&bitr_table, 0, sizeof(bitr_table));
  memset(&sampling_table, 0, sizeof(sampling_table));
  memset(&reload_map_tstamp, 0, sizeof(reload_map_tstamp));
  log_notifications_init(&log_notifications);
  config.acct_type = ACCT_SF;
  config.progname = sfacctd_globstr;

  rows = 0;
  memset(&device, 0, sizeof(device));

  memset(&recv_pptrs, 0, sizeof(recv_pptrs));
  memset(&recv_pkthdr, 0, sizeof(recv_pkthdr));

  /* getting commandline values */
  while (!errflag && ((cp = getopt(argc, argv, ARGS_SFACCTD)) != -1)) {
    if (!cfg_cmdline[rows]) cfg_cmdline[rows] = malloc(SRVBUFLEN);
    memset(cfg_cmdline[rows], 0, SRVBUFLEN);
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
    case 't':
      strlcpy(cfg_cmdline[rows], "ports_file: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'O':
      strlcpy(cfg_cmdline[rows], "print_output: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'o':
      strlcpy(cfg_cmdline[rows], "print_output_file: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'M':
      strlcpy(cfg_cmdline[rows], "print_markers: true", SRVBUFLEN);
      rows++;
      break;
    case 'A':
      strlcpy(cfg_cmdline[rows], "print_output_file_append: true", SRVBUFLEN);
      rows++;
      break;
    case 'E':
      strlcpy(cfg_cmdline[rows], "print_output_separator: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'u':
      strlcpy(cfg_cmdline[rows], "print_num_protos: true", SRVBUFLEN);
      rows++;
      break;
    case 'f':
      strlcpy(config_file, optarg, sizeof(config_file));
      free(cfg_cmdline[rows]);
      cfg_cmdline[rows] = NULL;
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
    case 'I':
      strlcpy(cfg_cmdline[rows], "pcap_savefile: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'W':
      strlcpy(cfg_cmdline[rows], "pcap_savefile_wait: true", SRVBUFLEN);
      rows++;
      break;
    case 'Z':
      strlcpy(cfg_cmdline[rows], "pcap_savefile_delay: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'Y':
      strlcpy(cfg_cmdline[rows], "pcap_savefile_replay: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'h':
      usage_daemon(argv[0]);
      exit(0);
      break;
    case 'V':
      version_daemon(SFACCTD_USAGE_HEADER);
      exit(0);
      break;
    case 'a':
      print_primitives(config.acct_type, SFACCTD_USAGE_HEADER);
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
    list->cfg.progname = sfacctd_globstr;
    set_default_preferences(&list->cfg);
    if (!strcmp(list->type.string, "core")) { 
      memcpy(&config, &list->cfg, sizeof(struct configuration)); 
      config.name = list->name;
      config.type = list->type.string;
    }
    list = list->next;
  }

  if (config.files_umask) umask(config.files_umask);

  initsetproctitle(argc, argv, envp);

  if (config.syslog) {
    logf = parse_log_facility(config.syslog);
    if (logf == ERR) {
      config.syslog = NULL;
      printf("WARN ( %s/core ): specified syslog facility is not supported. Logging to standard error (stderr).\n", config.name);
    }
    else openlog(NULL, LOG_PID, logf);
    Log(LOG_INFO, "INFO ( %s/core ): Start logging ...\n", config.name);
  }

  if (config.logfile) {
    config.logfile_fd = open_output_file(config.logfile, "a", FALSE);
    list = plugins_list;
    while (list) {
      list->cfg.logfile_fd = config.logfile_fd ;
      list = list->next;
    }
  }

  if (config.daemon) {
    list = plugins_list;
    while (list) {
      if (!strcmp(list->type.string, "print") && !list->cfg.print_output_file)
	printf("INFO ( %s/%s ): Daemonizing. Bye bye screen.\n", list->name, list->type.string);
      list = list->next;
    }

    if (!config.syslog && !config.logfile) {
      if (debug || config.debug) {
	printf("WARN ( %s/core ): debug is enabled; forking in background. Logging to standard error (stderr) will get lost.\n", config.name);
      }
    }

    daemonize();
  }

  if (config.proc_priority) {
    int ret;

    ret = setpriority(PRIO_PROCESS, 0, config.proc_priority);
    if (ret) Log(LOG_WARNING, "WARN ( %s/core ): proc_priority failed (errno: %d)\n", config.name, errno);
    else Log(LOG_INFO, "INFO ( %s/core ): proc_priority set to %d\n", config.name, getpriority(PRIO_PROCESS, 0));
  }

  Log(LOG_INFO, "INFO ( %s/core ): %s %s (%s)\n", config.name, SFACCTD_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
  Log(LOG_INFO, "INFO ( %s/core ): %s\n", config.name, PMACCT_COMPILE_ARGS);

  if (strlen(config_file)) {
    char canonical_path[PATH_MAX], *canonical_path_ptr;

    canonical_path_ptr = realpath(config_file, canonical_path);
    if (canonical_path_ptr) Log(LOG_INFO, "INFO ( %s/core ): Reading configuration file '%s'.\n", config.name, canonical_path);
  }
  else Log(LOG_INFO, "INFO ( %s/core ): Reading configuration from cmdline.\n", config.name);

  /* Enforcing policies over aggregation methods */
  list = plugins_list;
  while (list) {
    if (list->type.id != PLUGIN_ID_CORE) {  
      /* applies to all plugins */
      plugin_pipe_check(&list->cfg);

      if (list->cfg.sampling_rate && config.ext_sampling_rate) {
        Log(LOG_ERR, "ERROR ( %s/core ): Internal packet sampling and external packet sampling are mutual exclusive.\n", config.name);
        exit_gracefully(1);
      }

      /* applies to specific plugins */
      if (list->type.id == PLUGIN_ID_NFPROBE || list->type.id == PLUGIN_ID_SFPROBE) {
        Log(LOG_ERR, "ERROR ( %s/core ): 'nfprobe' and 'sfprobe' plugins not supported in 'sfacctd'.\n", config.name);
        exit_gracefully(1);
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
                        COUNT_TIMESTAMP_START|COUNT_TIMESTAMP_END|COUNT_TIMESTAMP_ARRIVAL|
			COUNT_EXPORT_PROTO_TIME))
          list->cfg.data_type |= PIPE_TYPE_NAT;

        if (list->cfg.what_to_count_2 & (COUNT_MPLS_LABEL_TOP|COUNT_MPLS_LABEL_BOTTOM|
                        COUNT_MPLS_STACK_DEPTH))
          list->cfg.data_type |= PIPE_TYPE_MPLS;

	if (list->cfg.what_to_count_2 & (COUNT_TUNNEL_SRC_MAC|COUNT_TUNNEL_DST_MAC|
			COUNT_TUNNEL_SRC_HOST|COUNT_TUNNEL_DST_HOST|COUNT_TUNNEL_IP_PROTO|
			COUNT_TUNNEL_IP_TOS|COUNT_TUNNEL_SRC_PORT|COUNT_TUNNEL_DST_PORT|
			COUNT_VXLAN)) {
	  list->cfg.data_type |= PIPE_TYPE_TUN;
	  alloc_sppi = TRUE;
	}

        if (list->cfg.what_to_count_2 & (COUNT_LABEL))
          list->cfg.data_type |= PIPE_TYPE_VLEN;

	evaluate_sums(&list->cfg.what_to_count, &list->cfg.what_to_count_2, list->name, list->type.string);
	if (!list->cfg.what_to_count && !list->cfg.what_to_count_2 && !list->cfg.cpptrs.num) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): defaulting to SRC HOST aggregation.\n", list->name, list->type.string);
	  list->cfg.what_to_count |= COUNT_SRC_HOST;
	}
	if (list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) {
	  if (!list->cfg.networks_file && list->cfg.nfacctd_as & NF_AS_NEW) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation was selected but NO 'networks_file' specified. Exiting...\n\n", list->name, list->type.string);
	    exit_gracefully(1);
	  }
          if (!list->cfg.bgp_daemon && !list->cfg.bmp_daemon && list->cfg.nfacctd_as == NF_AS_BGP) {
            Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation selected but 'bgp_daemon' or 'bmp_daemon' is not enabled. Exiting...\n\n", list->name, list->type.string);
            exit_gracefully(1);
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
                (list->cfg.nfacctd_net == NF_NET_BGP && !list->cfg.bgp_daemon && !list->cfg.bmp_daemon) ||
                (list->cfg.nfacctd_net == NF_NET_IGP && !list->cfg.nfacctd_isis)) {
              Log(LOG_ERR, "ERROR ( %s/%s ): network aggregation selected but none of 'bgp_daemon', 'bmp_daemon', 'isis_daemon', 'networks_file', 'networks_mask' is specified. Exiting ...\n\n", list->name, list->type.string);
              exit_gracefully(1);
            }
            if (list->cfg.nfacctd_net & NF_NET_FALLBACK && list->cfg.networks_file)
              list->cfg.nfacctd_net |= NF_NET_NEW;
          }
        }

	if (list->cfg.what_to_count & COUNT_CLASS && !list->cfg.classifiers_path) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): 'class' aggregation selected but NO 'classifiers' key specified. Exiting...\n\n", list->name, list->type.string);
	  exit_gracefully(1);
	}

#if defined (WITH_NDPI)
	if (list->cfg.what_to_count_2 & COUNT_NDPI_CLASS) {
          enable_ip_fragment_handler();
          config.classifier_ndpi = TRUE;
	}

	if ((list->cfg.what_to_count & COUNT_CLASS) && (list->cfg.what_to_count_2 & COUNT_NDPI_CLASS)) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): 'class_legacy' and 'class' primitives are mutual exclusive. Exiting...\n\n", list->name, list->type.string);
	  exit_gracefully(1);
	}
#endif

	list->cfg.type_id = list->type.id;
	bgp_config_checks(&list->cfg);

	data_plugins++;
	list->cfg.what_to_count |= COUNT_COUNTERS;
      }
    }

    list = list->next;
  }

  if (tee_plugins && data_plugins) {
    Log(LOG_ERR, "ERROR ( %s/core ): 'tee' plugins are not compatible with data (memory/mysql/pgsql/etc.) plugins. Exiting...\n\n", config.name);
    exit_gracefully(1);
  }

  if (config.pcap_savefile) capture_methods++;
  if (config.nfacctd_port || config.nfacctd_ip) capture_methods++;
#ifdef WITH_KAFKA
  if (config.nfacctd_kafka_broker_host || config.nfacctd_kafka_topic) capture_methods++;
#endif
#ifdef WITH_ZMQ
  if (config.nfacctd_zmq_address) capture_methods++;
#endif

  if (capture_methods > 1) {
    Log(LOG_ERR, "ERROR ( %s/core ): pcap_savefile, sfacctd_ip, sfacctd_kafka_* and sfacctd_zmq_* are mutual exclusive. Exiting...\n\n", config.name);
    exit_gracefully(1);
  }

#ifdef WITH_KAFKA
  if ((config.nfacctd_kafka_broker_host && !config.nfacctd_kafka_topic) || (config.nfacctd_kafka_topic && !config.nfacctd_kafka_broker_host)) {
    Log(LOG_ERR, "ERROR ( %s/core ): Kafka collection requires both sfacctd_kafka_broker_host and sfacctd_kafka_topic to be specified. Exiting...\n\n", config.name);
    exit_gracefully(1);
  }

  if (config.nfacctd_kafka_broker_host && tee_plugins) {
    Log(LOG_ERR, "ERROR ( %s/core ): Kafka collection is mutual exclusive with 'tee' plugins. Exiting...\n\n", config.name);
    exit_gracefully(1);
  }
#endif

#ifdef WITH_ZMQ
  if (config.nfacctd_zmq_address && tee_plugins) {
    Log(LOG_ERR, "ERROR ( %s/core ): ZeroMQ collection is mutual exclusive with 'tee' plugins. Exiting...\n\n", config.name);
    exit_gracefully(1);
  }
#endif

  /* signal handling we want to inherit to plugins (when not re-defined elsewhere) */
  memset(&sighandler_action, 0, sizeof(sighandler_action)); /* To ensure the struct holds no garbage values */
  sigemptyset(&sighandler_action.sa_mask);  /* Within a signal handler all the signals are enabled */
  sighandler_action.sa_flags = SA_RESTART;  /* To enable re-entering a system call afer done with signal handling */

  sighandler_action.sa_handler = startup_handle_falling_child;
  sigaction(SIGCHLD, &sighandler_action, NULL);

  /* handles reopening of syslog channel */
  sighandler_action.sa_handler = reload;
  sigaction(SIGHUP, &sighandler_action, NULL);

  /* logs various statistics via Log() calls */
  sighandler_action.sa_handler = push_stats;
  sigaction(SIGUSR1, &sighandler_action, NULL);

  /* sets to true the reload_maps flag */
  sighandler_action.sa_handler = reload_maps;
  sigaction(SIGUSR2, &sighandler_action, NULL);

  /* we want to exit gracefully when a pipe is broken */
  sighandler_action.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sighandler_action, NULL);

  sighandler_action.sa_handler = PM_sigalrm_noop_handler;
  sigaction(SIGALRM, &sighandler_action, NULL);

  if (config.pcap_savefile) {
    open_pcap_savefile(&device, config.pcap_savefile);
    pm_pcap_savefile_round = 1;

    enable_ip_fragment_handler();
  }
#ifdef WITH_KAFKA
  else if (config.nfacctd_kafka_broker_host) {
    SF_init_kafka_host(&nfacctd_kafka_host);
    recv_pptrs.pkthdr = &recv_pkthdr;

    enable_ip_fragment_handler();
  }
#endif
#ifdef WITH_ZMQ
  else if (config.nfacctd_zmq_address) {
    int pipe_fd = 0;
    SF_init_zmq_host(&nfacctd_zmq_host, &pipe_fd);
    recv_pptrs.pkthdr = &recv_pkthdr;

    enable_ip_fragment_handler();
  }
#endif
  else {
    /* If no IP address is supplied, let's set our default
       behaviour: IPv4 address, INADDR_ANY, port 2100 */
    if (!config.nfacctd_port) config.nfacctd_port = DEFAULT_SFACCTD_PORT;
    collector_port = config.nfacctd_port;

    if (!config.nfacctd_ip) {
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

      sa6->sin6_family = AF_INET6;
      sa6->sin6_port = htons(config.nfacctd_port);
      slen = sizeof(struct sockaddr_in6);
    }
    else {
      trim_spaces(config.nfacctd_ip);
      ret = str_to_addr(config.nfacctd_ip, &addr);
      if (!ret) {
        Log(LOG_ERR, "ERROR ( %s/core ): 'sfacctd_ip' value is not valid. Exiting.\n", config.name);
        exit_gracefully(1);
      }
      slen = addr_to_sa((struct sockaddr *)&server, &addr, config.nfacctd_port);
    }

    /* socket creation */
    config.sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);
    if (config.sock < 0) {
      /* retry with IPv4 */
      if (!config.nfacctd_ip) {
        struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

        sa4->sin_family = AF_INET;
        sa4->sin_addr.s_addr = htonl(0);
        sa4->sin_port = htons(config.nfacctd_port);
        slen = sizeof(struct sockaddr_in);

        config.sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);
      }

      if (config.sock < 0) {
        Log(LOG_ERR, "ERROR ( %s/core ): socket() failed.\n", config.name);
        exit_gracefully(1);
      }
    }

    /* bind socket to port */
#if (defined LINUX) && (defined HAVE_SO_REUSEPORT)
    rc = setsockopt(config.sock, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, (char *) &yes, (socklen_t) sizeof(yes));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for SO_REUSEADDR|SO_REUSEPORT.\n", config.name);
#else
    rc = setsockopt(config.sock, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, (socklen_t) sizeof(yes));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for SO_REUSEADDR.\n", config.name);
#endif

#if (defined IPV6_BINDV6ONLY)
    {
      int no=0;

      rc = setsockopt(config.sock, IPPROTO_IPV6, IPV6_BINDV6ONLY, (char *) &no, (socklen_t) sizeof(no));
      if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for IPV6_BINDV6ONLY.\n", config.name);
    }
#endif

    if (config.nfacctd_pipe_size) {
      socklen_t l = sizeof(config.nfacctd_pipe_size);
      int saved = 0, obtained = 0;

      getsockopt(config.sock, SOL_SOCKET, SO_RCVBUF, &saved, &l);
      Setsocksize(config.sock, SOL_SOCKET, SO_RCVBUF, &config.nfacctd_pipe_size, (socklen_t) sizeof(config.nfacctd_pipe_size));
      getsockopt(config.sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);

      if (obtained < saved) {
        Setsocksize(config.sock, SOL_SOCKET, SO_RCVBUF, &saved, l);
        getsockopt(config.sock, SOL_SOCKET, SO_RCVBUF, &obtained, &l);
      }
      Log(LOG_INFO, "INFO ( %s/core ): sfacctd_pipe_size: obtained=%d target=%d.\n", config.name, obtained, config.nfacctd_pipe_size);
    }

    /* Multicast: memberships handling */
    for (idx = 0; mcast_groups[idx].family && idx < MAX_MCAST_GROUPS; idx++) {
      if (mcast_groups[idx].family == AF_INET) {
        memset(&multi_req4, 0, sizeof(multi_req4));
        multi_req4.imr_multiaddr.s_addr = mcast_groups[idx].address.ipv4.s_addr;
        if (setsockopt(config.sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&multi_req4, (socklen_t) sizeof(multi_req4)) < 0) {
	  Log(LOG_ERR, "ERROR ( %s/core ): IPv4 multicast address - ADD membership failed.\n", config.name);
	  exit_gracefully(1);
	}
      }
      if (mcast_groups[idx].family == AF_INET6) {
	memset(&multi_req6, 0, sizeof(multi_req6));
	ip6_addr_cpy(&multi_req6.ipv6mr_multiaddr, &mcast_groups[idx].address.ipv6);
	if (setsockopt(config.sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&multi_req6, (socklen_t) sizeof(multi_req6)) < 0) {
	  Log(LOG_ERR, "ERROR ( %s/core ): IPv6 multicast address - ADD membership failed.\n", config.name);
	  exit_gracefully(1);
	}
      }
    }
  }

  if (config.nfacctd_allow_file) load_allow_file(config.nfacctd_allow_file, &allow);
  else memset(&allow, 0, sizeof(allow));

  if (config.sampling_map) {
    load_id_file(MAP_SAMPLING, config.sampling_map, &sampling_table, &req, &sampling_map_allocated);
    set_sampling_table(&pptrs, (u_char *) &sampling_table);
  }
  else set_sampling_table(&pptrs, NULL);

  if (config.nfacctd_flow_to_rd_map) {
    load_id_file(MAP_FLOW_TO_RD, config.nfacctd_flow_to_rd_map, &bitr_table, &req, &bitr_map_allocated);
    pptrs.v4.bitr_table = (u_char *) &bitr_table;
  }
  else pptrs.v4.bitr_table = NULL;

  if (config.aggregate_primitives) {
    req.key_value_table = (void *) &custom_primitives_registry;
    load_id_file(MAP_CUSTOM_PRIMITIVES, config.aggregate_primitives, NULL, &req, &custom_primitives_allocated);
  }
  else memset(&custom_primitives_registry, 0, sizeof(custom_primitives_registry));

  /* fixing per plugin custom primitives pointers, offsets and lengths */
  list = plugins_list;
  while(list) { 
    custom_primitives_reconcile(&list->cfg.cpptrs, &custom_primitives_registry);
    if (custom_primitives_vlen(&list->cfg.cpptrs)) list->cfg.data_type |= PIPE_TYPE_VLEN;
    list = list->next;
  }

  if (config.bgp_daemon && config.bmp_daemon) {
    Log(LOG_ERR, "ERROR ( %s/core ): bgp_daemon and bmp_daemon are currently mutual exclusive. Exiting.\n", config.name);
    exit_gracefully(1);
  }

  /* starting the ISIS threa */
  if (config.nfacctd_isis) {
    req.bpf_filter = TRUE;

    nfacctd_isis_wrapper();

    /* Let's give the ISIS thread some advantage to create its structures */
    sleep(DEFAULT_SLOTH_SLEEP_TIME);
  }

  /* starting the BGP thread */
  if (config.bgp_daemon) {
    int sleep_time = DEFAULT_SLOTH_SLEEP_TIME;

    req.bpf_filter = TRUE;

    if (config.bgp_daemon_stdcomm_pattern_to_asn && config.bgp_daemon_lrgcomm_pattern_to_asn) {
      Log(LOG_ERR, "ERROR ( %s/core ): bgp_stdcomm_pattern_to_asn and bgp_lrgcomm_pattern_to_asn are mutual exclusive. Exiting.\n", config.name);
      exit_gracefully(1);
    }

    load_comm_patterns(&config.bgp_daemon_stdcomm_pattern, &config.bgp_daemon_extcomm_pattern,
                        &config.bgp_daemon_lrgcomm_pattern, &config.bgp_daemon_stdcomm_pattern_to_asn,
                        &config.bgp_daemon_lrgcomm_pattern_to_asn);

    if (config.bgp_daemon_peer_as_src_type == BGP_SRC_PRIMITIVES_MAP) {
      if (config.bgp_daemon_peer_as_src_map) {
        load_id_file(MAP_BGP_PEER_AS_SRC, config.bgp_daemon_peer_as_src_map, &bpas_table, &req, &bpas_map_allocated);
        pptrs.v4.bpas_table = (u_char *) &bpas_table;
      }
      else {
        Log(LOG_ERR, "ERROR ( %s/core ): bgp_peer_as_src_type set to 'map' but no map defined. Exiting.\n", config.name);
        exit_gracefully(1);
      }
    }
    else pptrs.v4.bpas_table = NULL;

    if (config.bgp_daemon_src_local_pref_type == BGP_SRC_PRIMITIVES_MAP) {
      if (config.bgp_daemon_src_local_pref_map) {
        load_id_file(MAP_BGP_SRC_LOCAL_PREF, config.bgp_daemon_src_local_pref_map, &blp_table, &req, &blp_map_allocated);
        pptrs.v4.blp_table = (u_char *) &blp_table;
      }
      else {
        Log(LOG_ERR, "ERROR ( %s/core ): bgp_src_local_pref_type set to 'map' but no map defined. Exiting.\n", config.name);
        exit_gracefully(1);
      }
    }
    else pptrs.v4.blp_table = NULL;

    if (config.bgp_daemon_src_med_type == BGP_SRC_PRIMITIVES_MAP) {
      if (config.bgp_daemon_src_med_map) {
        load_id_file(MAP_BGP_SRC_MED, config.bgp_daemon_src_med_map, &bmed_table, &req, &bmed_map_allocated);
        pptrs.v4.bmed_table = (u_char *) &bmed_table;
      }
      else {
        Log(LOG_ERR, "ERROR ( %s/core ): bgp_src_med_type set to 'map' but no map defined. Exiting.\n", config.name);
        exit_gracefully(1);
      }
    }
    else pptrs.v4.bmed_table = NULL;

    if (config.bgp_daemon_to_xflow_agent_map) {
      load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.bgp_daemon_to_xflow_agent_map, &bta_table, &req, &bta_map_allocated);
      pptrs.v4.bta_table = (u_char *) &bta_table;
    }
    else pptrs.v4.bta_table = NULL;

    bgp_daemon_wrapper();

    /* Let's give the BGP thread some advantage to create its structures */
    if (config.rpki_roas_file || config.rpki_rtr_cache) sleep_time += DEFAULT_SLOTH_SLEEP_TIME;
    sleep(sleep_time);
  }

  /* starting the BMP thread */
  if (config.bmp_daemon) {
    int sleep_time = DEFAULT_SLOTH_SLEEP_TIME;

    req.bpf_filter = TRUE;

    if (config.bgp_daemon_to_xflow_agent_map) {
      load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.bgp_daemon_to_xflow_agent_map, &bta_table, &req, &bta_map_allocated);
      pptrs.v4.bta_table = (u_char *) &bta_table;
    }
    else pptrs.v4.bta_table = NULL;

    bmp_daemon_wrapper();

    /* Let's give the BMP thread some advantage to create its structures */
    if (config.rpki_roas_file || config.rpki_rtr_cache) sleep_time += DEFAULT_SLOTH_SLEEP_TIME;
    sleep(sleep_time);
  }

#if defined WITH_GEOIP
  if (config.geoip_ipv4_file || config.geoip_ipv6_file) {
    req.bpf_filter = TRUE;
  }
#endif

#if defined WITH_GEOIPV2
  if (config.geoipv2_file) {
    req.bpf_filter = TRUE;
  }
#endif

  if (!config.pcap_savefile && !config.nfacctd_kafka_broker_host) {
    rc = bind(config.sock, (struct sockaddr *) &server, slen);
    if (rc < 0) {
      Log(LOG_ERR, "ERROR ( %s/core ): bind() to ip=%s port=%d/udp failed (errno: %d).\n", config.name, config.nfacctd_ip, config.nfacctd_port, errno);
      exit_gracefully(1);
    }
  }

  if (config.classifiers_path) init_classifiers(config.classifiers_path);

#if defined (WITH_NDPI)
  if (config.classifier_ndpi) {
    enable_ip_fragment_handler();
    pm_ndpi_wfl = pm_ndpi_workflow_init();
    pm_ndpi_export_proto_to_class(pm_ndpi_wfl);
  }
  else pm_ndpi_wfl = NULL;
#endif

  /* plugins glue: creation */
  load_plugins(&req);
  load_plugin_filters(1);
  evaluate_packet_handlers();
  pm_setproctitle("%s [%s]", "Core Process", config.proc_name);
  if (config.pidfile) write_pid_file(config.pidfile);
  load_networks(config.networks_file, &nt, &nc);

  /* signals to be handled only by the core process;
     we set proper handlers after plugin creation */
  sighandler_action.sa_handler = PM_sigint_handler;
  sigaction(SIGINT, &sighandler_action, NULL);

  sighandler_action.sa_handler = PM_sigint_handler;
  sigaction(SIGTERM, &sighandler_action, NULL);

  sighandler_action.sa_handler = handle_falling_child;
  sigaction(SIGCHLD, &sighandler_action, NULL);

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
  pptrs.v4.tlh_ptr = pptrs.v4.packet_ptr + ETHER_HDRLEN + sizeof(struct pm_iphdr); 
  Assign8(((struct pm_iphdr *)pptrs.v4.iph_ptr)->ip_vhl, 5);
  // pptrs.v4.pkthdr->caplen = 38; /* eth_header + pm_iphdr + pm_tlhdr */
  pptrs.v4.pkthdr->caplen = 55;
  pptrs.v4.pkthdr->len = 100; /* fake len */ 
  pptrs.v4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_vlan, 0, sizeof(dummy_packet_vlan));
  pptrs.vlan4.f_data = pptrs.v4.f_data; 
  pptrs.vlan4.f_agent = (u_char *) &client;
  pptrs.vlan4.packet_ptr = dummy_packet_vlan;
  pptrs.vlan4.pkthdr = &dummy_pkthdr_vlan;
  Assign16(((struct eth_header *)pptrs.vlan4.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlan4.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlan4.packet_ptr)->ether_dhost;
  pptrs.vlan4.vlan_ptr = pptrs.vlan4.packet_ptr + ETHER_HDRLEN;
  Assign16(*(pptrs.vlan4.vlan_ptr+2), htons(ETHERTYPE_IP));
  pptrs.vlan4.iph_ptr = pptrs.vlan4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  pptrs.vlan4.tlh_ptr = pptrs.vlan4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN + sizeof(struct pm_iphdr);
  Assign8(((struct pm_iphdr *)pptrs.vlan4.iph_ptr)->ip_vhl, 5);
  // pptrs.vlan4.pkthdr->caplen = 42; /* eth_header + vlan + pm_iphdr + pm_tlhdr */
  pptrs.vlan4.pkthdr->caplen = 59;
  pptrs.vlan4.pkthdr->len = 100; /* fake len */
  pptrs.vlan4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_mpls, 0, sizeof(dummy_packet_mpls));
  pptrs.mpls4.f_data = pptrs.v4.f_data; 
  pptrs.mpls4.f_agent = (u_char *) &client;
  pptrs.mpls4.packet_ptr = dummy_packet_mpls;
  pptrs.mpls4.pkthdr = &dummy_pkthdr_mpls;
  Assign16(((struct eth_header *)pptrs.mpls4.packet_ptr)->ether_type, htons(ETHERTYPE_MPLS));
  pptrs.mpls4.mac_ptr = (u_char *)((struct eth_header *)pptrs.mpls4.packet_ptr)->ether_dhost;
  pptrs.mpls4.mpls_ptr = pptrs.mpls4.packet_ptr + ETHER_HDRLEN;
  // pptrs.mpls4.pkthdr->caplen = 78; /* eth_header + upto 10 MPLS labels + pm_iphdr + pm_tlhdr */
  pptrs.mpls4.pkthdr->caplen = 95;
  pptrs.mpls4.pkthdr->len = 100; /* fake len */
  pptrs.mpls4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_vlan_mpls, 0, sizeof(dummy_packet_vlan_mpls));
  pptrs.vlanmpls4.f_data = pptrs.v4.f_data; 
  pptrs.vlanmpls4.f_agent = (u_char *) &client;
  pptrs.vlanmpls4.packet_ptr = dummy_packet_vlan_mpls;
  pptrs.vlanmpls4.pkthdr = &dummy_pkthdr_vlan_mpls;
  Assign16(((struct eth_header *)pptrs.vlanmpls4.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlanmpls4.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlanmpls4.packet_ptr)->ether_dhost;
  pptrs.vlanmpls4.vlan_ptr = pptrs.vlanmpls4.packet_ptr + ETHER_HDRLEN;
  Assign16(((struct vlan_header *)pptrs.vlanmpls4.vlan_ptr)->proto, htons(ETHERTYPE_MPLS));
  pptrs.vlanmpls4.mpls_ptr = pptrs.vlanmpls4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  // pptrs.vlanmpls4.pkthdr->caplen = 82; /* eth_header + vlan + upto 10 MPLS labels + pm_iphdr + pm_tlhdr */
  pptrs.vlanmpls4.pkthdr->caplen = 99;
  pptrs.vlanmpls4.pkthdr->len = 100; /* fake len */
  pptrs.vlanmpls4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet6, 0, sizeof(dummy_packet6));
  pptrs.v6.f_data = pptrs.v4.f_data; 
  pptrs.v6.f_agent = (u_char *) &client;
  pptrs.v6.packet_ptr = dummy_packet6;
  pptrs.v6.pkthdr = &dummy_pkthdr6;
  Assign16(((struct eth_header *)pptrs.v6.packet_ptr)->ether_type, htons(ETHERTYPE_IPV6)); 
  pptrs.v6.mac_ptr = (u_char *)((struct eth_header *)pptrs.v6.packet_ptr)->ether_dhost; 
  pptrs.v6.iph_ptr = pptrs.v6.packet_ptr + ETHER_HDRLEN;
  pptrs.v6.tlh_ptr = pptrs.v6.packet_ptr + ETHER_HDRLEN + sizeof(struct ip6_hdr);
  Assign16(((struct ip6_hdr *)pptrs.v6.iph_ptr)->ip6_plen, htons(100));
  ((struct ip6_hdr *)pptrs.v6.iph_ptr)->ip6_hlim = 64;
  // pptrs.v6.pkthdr->caplen = 60; /* eth_header + ip6_hdr + pm_tlhdr */
  pptrs.v6.pkthdr->caplen = 77;
  pptrs.v6.pkthdr->len = 100; /* fake len */
  pptrs.v6.l3_proto = ETHERTYPE_IPV6;

  memset(dummy_packet_vlan6, 0, sizeof(dummy_packet_vlan6));
  pptrs.vlan6.f_data = pptrs.v4.f_data; 
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
  ((struct ip6_hdr *)pptrs.vlan6.iph_ptr)->ip6_hlim = 64;
  // pptrs.vlan6.pkthdr->caplen = 64; /* eth_header + vlan + ip6_hdr + pm_tlhdr */
  pptrs.vlan6.pkthdr->caplen = 81;
  pptrs.vlan6.pkthdr->len = 100; /* fake len */
  pptrs.vlan6.l3_proto = ETHERTYPE_IPV6;

  memset(dummy_packet_mpls6, 0, sizeof(dummy_packet_mpls6));
  pptrs.mpls6.f_data = pptrs.v4.f_data; 
  pptrs.mpls6.f_agent = (u_char *) &client;
  pptrs.mpls6.packet_ptr = dummy_packet_mpls6;
  pptrs.mpls6.pkthdr = &dummy_pkthdr_mpls6;
  Assign16(((struct eth_header *)pptrs.mpls6.packet_ptr)->ether_type, htons(ETHERTYPE_MPLS));
  pptrs.mpls6.mac_ptr = (u_char *)((struct eth_header *)pptrs.mpls6.packet_ptr)->ether_dhost;
  pptrs.mpls6.mpls_ptr = pptrs.mpls6.packet_ptr + ETHER_HDRLEN;
  // pptrs.mpls6.pkthdr->caplen = 100; /* eth_header + upto 10 MPLS labels + ip6_hdr + pm_tlhdr */
  pptrs.mpls6.pkthdr->caplen = 117;
  pptrs.mpls6.pkthdr->len = 128; /* fake len */
  pptrs.mpls6.l3_proto = ETHERTYPE_IPV6;

  memset(dummy_packet_vlan_mpls6, 0, sizeof(dummy_packet_vlan_mpls6));
  pptrs.vlanmpls6.f_data = pptrs.v4.f_data; 
  pptrs.vlanmpls6.f_agent = (u_char *) &client;
  pptrs.vlanmpls6.packet_ptr = dummy_packet_vlan_mpls6;
  pptrs.vlanmpls6.pkthdr = &dummy_pkthdr_vlan_mpls6;
  Assign16(((struct eth_header *)pptrs.vlanmpls6.packet_ptr)->ether_type, htons(ETHERTYPE_8021Q));
  pptrs.vlanmpls6.mac_ptr = (u_char *)((struct eth_header *)pptrs.vlanmpls6.packet_ptr)->ether_dhost;
  pptrs.vlanmpls6.vlan_ptr = pptrs.vlanmpls6.packet_ptr + ETHER_HDRLEN;
  Assign8(*(pptrs.vlanmpls6.vlan_ptr+2), 0x88);
  Assign8(*(pptrs.vlanmpls6.vlan_ptr+3), 0x47);
  pptrs.vlanmpls6.mpls_ptr = pptrs.vlanmpls6.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  // pptrs.vlanmpls6.pkthdr->caplen = 104; /* eth_header + vlan + upto 10 MPLS labels + ip6_hdr + pm_tlhdr */
  pptrs.vlanmpls6.pkthdr->caplen = 121;
  pptrs.vlanmpls6.pkthdr->len = 128; /* fake len */
  pptrs.vlanmpls6.l3_proto = ETHERTYPE_IP;

  if (config.pcap_savefile) {
    Log(LOG_INFO, "INFO ( %s/core ): reading sFlow data from: %s\n", config.name, config.pcap_savefile);
    allowed = TRUE;

    if (!config.pcap_sf_delay) sleep(2);
    else sleep(config.pcap_sf_delay);
  }
#ifdef WITH_KAFKA
  else if (config.nfacctd_kafka_broker_host) {
    Log(LOG_INFO, "INFO ( %s/core ): reading sFlow data from Kafka %s:%s\n", config.name,
	p_kafka_get_broker(&nfacctd_kafka_host), p_kafka_get_topic(&nfacctd_kafka_host));
    allowed = TRUE;
  }
#endif
#ifdef WITH_ZMQ
  else if (config.nfacctd_zmq_address) {
    Log(LOG_INFO, "INFO ( %s/core ): reading sFlow data from ZeroMQ %s\n", config.name,
        p_zmq_get_address(&nfacctd_zmq_host));
    allowed = TRUE;
  }
#endif
  else {
    char srv_string[INET6_ADDRSTRLEN];
    struct host_addr srv_addr;
    u_int16_t srv_port;

    sa_to_addr((struct sockaddr *)&server, &srv_addr, &srv_port);
    addr_to_str(srv_string, &srv_addr);
    Log(LOG_INFO, "INFO ( %s/core ): waiting for sFlow data on %s:%u\n", config.name, srv_string, srv_port);
    allowed = TRUE;
  }

  if (config.sfacctd_counter_file || config.sfacctd_counter_amqp_routing_key || config.sfacctd_counter_kafka_topic) {
    if (config.sfacctd_counter_file) sfacctd_counter_backend_methods++;
    if (config.sfacctd_counter_amqp_routing_key) sfacctd_counter_backend_methods++;
    if (config.sfacctd_counter_kafka_topic) sfacctd_counter_backend_methods++;

    if (sfacctd_counter_backend_methods > 1) {
      Log(LOG_ERR, "ERROR ( %s/core ): sfacctd_counter_file, sfacctd_counter_amqp_routing_key and sfacctd_counter_kafka_topic are mutually exclusive. Exiting.\n", config.name);
      exit_all(1);
    }
    else {
      sf_cnt_misc_db = &inter_domain_misc_dbs[FUNC_TYPE_SFLOW_COUNTER];
      config.sfacctd_counter_max_nodes = MAX_SF_CNT_LOG_ENTRIES;
      memset(sf_cnt_misc_db, 0, sizeof(struct bgp_misc_structs));
      sf_cnt_link_misc_structs(sf_cnt_misc_db);

      sf_cnt_misc_db->peers_log = malloc(MAX_SF_CNT_LOG_ENTRIES*sizeof(struct bgp_peer_log));
      if (!sf_cnt_misc_db->peers_log) {
        Log(LOG_ERR, "ERROR ( %s/core ): Unable to malloc() sFlow counters log structure. Exiting.\n", config.name);
        exit_gracefully(1);
      }
      memset(sf_cnt_misc_db->peers_log, 0, MAX_SF_CNT_LOG_ENTRIES*sizeof(struct bgp_peer_log));
      bgp_peer_log_seq_init(&sf_cnt_misc_db->log_seq);
    }

    if (!config.sfacctd_counter_output) {
#ifdef WITH_JANSSON
      config.sfacctd_counter_output = PRINT_OUTPUT_JSON;
#else
      Log(LOG_WARNING, "WARN ( %s/core ): sfacctd_counter_output set to json but will produce no output (missing --enable-jansson).\n", config.name);
#endif
    }
  }

  if (config.sfacctd_counter_amqp_routing_key) {
#ifdef WITH_RABBITMQ
    sfacctd_counter_init_amqp_host();
    p_amqp_connect_to_publish(&sfacctd_counter_amqp_host);

    if (!config.sfacctd_counter_amqp_retry)
      config.sfacctd_counter_amqp_retry = AMQP_DEFAULT_RETRY;
#else
    Log(LOG_WARNING, "WARN ( %s/core ): p_amqp_connect_to_publish() not possible due to missing --enable-rabbitmq\n", config.name);
#endif
  }

  if (config.sfacctd_counter_kafka_topic) {
#ifdef WITH_KAFKA
    sfacctd_counter_init_kafka_host();
#else
    Log(LOG_WARNING, "WARN ( %s/core ): p_kafka_connect_to_produce() not possible due to missing --enable-rabbitmq\n", config.name);
#endif
  }

#ifdef WITH_REDIS
  if (config.redis_host) {
    char log_id[SHORTBUFLEN];

    snprintf(log_id, sizeof(log_id), "%s/%s", config.name, config.type);
    p_redis_init(&redis_host, log_id, p_redis_thread_produce_common_core_handler);
  }
#endif

  if (alloc_sppi) {
    spp.sppi = malloc(sizeof(SFSample));
    memset(spp.sppi, 0, sizeof(SFSample));
  }

  sigemptyset(&signal_set);
  sigaddset(&signal_set, SIGCHLD);
  sigaddset(&signal_set, SIGHUP);
  sigaddset(&signal_set, SIGUSR1);
  sigaddset(&signal_set, SIGUSR2);
  sigaddset(&signal_set, SIGTERM);
  if (config.daemon) {
    sigaddset(&signal_set, SIGINT);
  }

  /* Main loop */
  for (;;) {
    sigprocmask(SIG_BLOCK, &signal_set, NULL);

    if (config.pcap_savefile) {
      ret = recvfrom_savefile(&device, (void **) &sflow_packet, (struct sockaddr *) &client, &spp.ts, &pm_pcap_savefile_round, &recv_pptrs);
    }
#ifdef WITH_KAFKA
    else if (config.nfacctd_kafka_broker_host) {
      int kafka_reconnect = FALSE;
      void *kafka_msg = NULL;

      ret = p_kafka_consume_poller(&nfacctd_kafka_host, &kafka_msg, 1000);

      switch (ret) {
      case TRUE: /* got data */
        ret = p_kafka_consume_data(&nfacctd_kafka_host, kafka_msg, sflow_packet, SFLOW_MAX_MSG_SIZE);
	if (ret < 0) kafka_reconnect = TRUE;
	break;
      case FALSE: /* timeout */
	continue;
	break;
      case ERR: /* error */
      default:
	kafka_reconnect = TRUE;
	break;
      }

      if (kafka_reconnect) {
	/* Close */
        p_kafka_manage_consumer(&nfacctd_kafka_host, FALSE);

	/* Re-open */
	SF_init_kafka_host(&nfacctd_kafka_host);

	continue;
      }

      ret = recvfrom_rawip(sflow_packet, ret, (struct sockaddr *) &client, &recv_pptrs);
    }
#endif
#ifdef WITH_ZMQ
    else if (config.nfacctd_zmq_address) {
      ret = p_zmq_recv_poll(&nfacctd_zmq_host.sock, 1000);

      switch (ret) {
      case TRUE: /* got data */
	ret = p_zmq_recv_bin(&nfacctd_zmq_host.sock, sflow_packet, SFLOW_MAX_MSG_SIZE);
	if (ret < 0) continue; /* ZMQ_RECONNECT_IVL */
	break;
      case FALSE: /* timeout */
	continue;
	break;
      case ERR: /* error */
      default:
	continue; /* ZMQ_RECONNECT_IVL */
	break;
      }

      ret = recvfrom_rawip(sflow_packet, ret, (struct sockaddr *) &client, &recv_pptrs);
    }
#endif
    else {
      ret = recvfrom(config.sock, (unsigned char *)sflow_packet, SFLOW_MAX_MSG_SIZE, 0, (struct sockaddr *) &client, &clen);
    }

    spp.rawSample = pptrs.v4.f_header = sflow_packet;
    spp.rawSampleLen = pptrs.v4.f_len = ret;
    spp.datap = (u_int32_t *) spp.rawSample;
    spp.endp = sflow_packet + spp.rawSampleLen; 
    reset_tag_label_status(&pptrs);
    reset_shadow_status(&pptrs);

    ipv4_mapped_to_ipv4(&client);

    /* check if Hosts Allow Table is loaded; if it is, we will enforce rules */
    if (allow.num) allowed = check_allow(&allow, (struct sockaddr *)&client); 
    if (!allowed) continue;

    if (reload_map) {
      bta_map_caching = TRUE;
      sampling_map_caching = TRUE;

      if (config.nfacctd_allow_file) load_allow_file(config.nfacctd_allow_file, &allow);

      load_networks(config.networks_file, &nt, &nc);

      if (config.bgp_daemon && config.bgp_daemon_peer_as_src_map)
        load_id_file(MAP_BGP_PEER_AS_SRC, config.bgp_daemon_peer_as_src_map, &bpas_table, &req, &bpas_map_allocated);
      if (config.bgp_daemon && config.bgp_daemon_src_local_pref_map)
        load_id_file(MAP_BGP_SRC_LOCAL_PREF, config.bgp_daemon_src_local_pref_map, &blp_table, &req, &blp_map_allocated);
      if (config.bgp_daemon && config.bgp_daemon_src_med_map)
        load_id_file(MAP_BGP_SRC_MED, config.bgp_daemon_src_med_map, &bmed_table, &req, &bmed_map_allocated);
      if (config.bgp_daemon && config.bgp_daemon_to_xflow_agent_map)
        load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.bgp_daemon_to_xflow_agent_map, &bta_table, &req, &bta_map_allocated);
      if (config.nfacctd_flow_to_rd_map)
        load_id_file(MAP_FLOW_TO_RD, config.nfacctd_flow_to_rd_map, &bitr_table, &req, &bitr_map_allocated);
      if (config.sampling_map) {
        load_id_file(MAP_SAMPLING, config.sampling_map, &sampling_table, &req, &sampling_map_allocated);
        set_sampling_table(&pptrs, (u_char *) &sampling_table);
      }

      reload_map = FALSE;
      gettimeofday(&reload_map_tstamp, NULL);
    }

    if (reload_log) {
      reload_logs();
      reload_log = FALSE;
    }

    if (reload_log_sf_cnt) {
      int nodes_idx;

      for (nodes_idx = 0; nodes_idx < config.sfacctd_counter_max_nodes; nodes_idx++) {
        if (sf_cnt_misc_db->peers_log[nodes_idx].fd) {
          fclose(sf_cnt_misc_db->peers_log[nodes_idx].fd);
          sf_cnt_misc_db->peers_log[nodes_idx].fd = open_output_file(sf_cnt_misc_db->peers_log[nodes_idx].filename, "a", FALSE);
	  setlinebuf(sf_cnt_misc_db->peers_log[nodes_idx].fd);
        }
        else break;
      }

      reload_log_sf_cnt = FALSE;
    }

    if (print_stats) {
      time_t now = time(NULL);

      print_status_table(&xflow_status_table, now, XFLOW_STATUS_TABLE_SZ);
      print_stats = FALSE;
    }

    if (sfacctd_counter_backend_methods) {
      gettimeofday(&sf_cnt_misc_db->log_tstamp, NULL);
      compose_timestamp(sf_cnt_misc_db->log_tstamp_str, SRVBUFLEN, &sf_cnt_misc_db->log_tstamp, TRUE,
			config.timestamps_since_epoch, config.timestamps_rfc3339, config.timestamps_utc);

      /* let's reset log sequence here as we do not sequence dump_init/dump_close events */
      if (bgp_peer_log_seq_has_ro_bit(&sf_cnt_misc_db->log_seq))
        bgp_peer_log_seq_init(&sf_cnt_misc_db->log_seq);

#ifdef WITH_RABBITMQ
      if (config.sfacctd_counter_amqp_routing_key) {
        time_t last_fail = P_broker_timers_get_last_fail(&sfacctd_counter_amqp_host.btimers);

        if (last_fail && ((last_fail + P_broker_timers_get_retry_interval(&sfacctd_counter_amqp_host.btimers)) <= sf_cnt_misc_db->log_tstamp.tv_sec)) {
          sfacctd_counter_init_amqp_host();
          p_amqp_connect_to_publish(&sfacctd_counter_amqp_host);
        }
      }
#endif

#ifdef WITH_KAFKA
      if (config.sfacctd_counter_kafka_topic) {
        time_t last_fail = P_broker_timers_get_last_fail(&sfacctd_counter_kafka_host.btimers);

        if (last_fail && ((last_fail + P_broker_timers_get_retry_interval(&sfacctd_counter_kafka_host.btimers)) <= sf_cnt_misc_db->log_tstamp.tv_sec))
          sfacctd_counter_init_kafka_host();
      }
#endif
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
	else if (spp.agent_addr.type == SFLADDRESSTYPE_IP_V6) {
	  struct sockaddr *sa = (struct sockaddr *) &client;
	  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &client;

	  sa->sa_family = AF_INET6;
	  ip6_addr_cpy(&sa6->sin6_addr, &spp.agent_addr.address.ip_v6);
	}

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
        else if (spp.agent_addr.type == SFLADDRESSTYPE_IP_V6) {
          struct sockaddr *sa = (struct sockaddr *) &client;
          struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &client;

          sa->sa_family = AF_INET6;
          ip6_addr_cpy(&sa6->sin6_addr, &spp.agent_addr.address.ip_v6);
        }

	process_SFv2v4_packet(&spp, &pptrs, &req, (struct sockaddr *) &client);
	break;
      default:
	if (!config.nfacctd_disable_checks) {
	  SF_notify_malf_packet(LOG_INFO, "INFO", "discarding unknown packet", (struct sockaddr *) pptrs.v4.f_agent);
	  xflow_status_table.tot_bad_datagrams++;
	}
	break;
      }
    }
    else if (tee_plugins) {
      process_SF_raw_packet(&spp, &pptrs, &req, (struct sockaddr *) &client);
    }
    
    sigprocmask(SIG_UNBLOCK, &signal_set, NULL);
  }
}

void InterSampleCleanup(SFSample *spp)
{
  u_char *start = (u_char *) spp;
  u_char *ptr = (u_char *) &spp->sampleType;
  SFSample *sppi = (SFSample *) spp->sppi;

  memset(ptr, 0, (SFSampleSz - (ptr - start)));
  spp->sppi = (void *) sppi;

  if (spp->sppi) {
    start = (u_char *) sppi;
    ptr = (u_char *) &sppi->sampleType;
    memset(ptr, 0, (SFSampleSz - (ptr - start)));
  }
}

void process_SFv2v4_packet(SFSample *spp, struct packet_ptrs_vector *pptrsv,
		                struct plugin_requests *req, struct sockaddr *agent)
{
  u_int32_t samplesInPacket, idx;
  u_int32_t sampleType, sysUpTime, sequenceNo;

  spp->agentSubId = 0; /* not supported */
  sequenceNo = spp->sequenceNo = getData32(spp);
  sysUpTime = spp->sysUpTime = getData32(spp);
  samplesInPacket = getData32(spp);
  
  pptrsv->v4.f_status = (u_char *) sfv245_check_status(spp, &pptrsv->v4, agent);
  set_vector_f_status(pptrsv);

  if (config.debug) {
    sa_to_addr((struct sockaddr *)pptrsv->v4.f_agent, &debug_a, &debug_agent_port);
    addr_to_str(debug_agent_addr, &debug_a);
    Log(LOG_DEBUG, "DEBUG ( %s/core ): Received sFlow packet from [%s:%u] version [%u] seqno [%u]\n",
    config.name, debug_agent_addr, debug_agent_port, spp->datagramVersion, sequenceNo);
  }

  if (sfacctd_counter_backend_methods) sfv245_check_counter_log_init(&pptrsv->v4); 

  for (idx = 0; idx < samplesInPacket; idx++) {
    InterSampleCleanup(spp);
    spp->sequenceNo = sequenceNo;
    spp->sysUpTime = sysUpTime;

    set_vector_sample_type(pptrsv, 0);
    sampleType = getData32(spp);
    if (!pptrsv->v4.sample_type) set_vector_sample_type(pptrsv, sampleType);
    switch (sampleType) {
    case SFLFLOW_SAMPLE:
      readv2v4FlowSample(spp, pptrsv, req);
      break;
    case SFLCOUNTERS_SAMPLE:
      readv2v4CountersSample(spp, pptrsv);
      break;
    default:
      SF_notify_malf_packet(LOG_INFO, "INFO", "discarding unknown v2/v4 sample", (struct sockaddr *) pptrsv->v4.f_agent);
      xflow_status_table.tot_bad_datagrams++;
      return; /* unexpected sampleType; aborting packet */
    }
    if ((u_char *)spp->datap > spp->endp) return;
  }
}

void process_SFv5_packet(SFSample *spp, struct packet_ptrs_vector *pptrsv,
		struct plugin_requests *req, struct sockaddr *agent)
{
  u_int32_t samplesInPacket, idx;
  u_int32_t sampleType, agentSubId, sequenceNo, sysUpTime;

  agentSubId = spp->agentSubId = getData32(spp);
  sequenceNo = spp->sequenceNo = getData32(spp);
  sysUpTime = spp->sysUpTime = getData32(spp);
  samplesInPacket = getData32(spp);
  pptrsv->v4.f_status = (u_char *) sfv245_check_status(spp, &pptrsv->v4, agent);
  set_vector_f_status(pptrsv);

  if (config.debug) {
    sa_to_addr((struct sockaddr *)pptrsv->v4.f_agent, &debug_a, &debug_agent_port);
    addr_to_str(debug_agent_addr, &debug_a);
    Log(LOG_DEBUG, "DEBUG ( %s/core ): Received sFlow packet from [%s:%u] version [%u] seqno [%u]\n",
    config.name, debug_agent_addr, debug_agent_port, spp->datagramVersion, sequenceNo);
  }

  if (sfacctd_counter_backend_methods) sfv245_check_counter_log_init(&pptrsv->v4); 

  for (idx = 0; idx < samplesInPacket; idx++) {
    InterSampleCleanup(spp);
    spp->agentSubId = agentSubId;
    spp->sequenceNo = sequenceNo;
    spp->sysUpTime = sysUpTime;

    set_vector_sample_type(pptrsv, 0);
    sfv5_modules_db_init();

SFv5_read_sampleType:
    sampleType = getData32(spp);
    if (!pptrsv->v4.sample_type) set_vector_sample_type(pptrsv, sampleType);

    switch (sampleType) {
    case SFLFLOW_SAMPLE:
      readv5FlowSample(spp, FALSE, pptrsv, req, TRUE);
      break;
    case SFLCOUNTERS_SAMPLE:
      readv5CountersSample(spp, FALSE, pptrsv);
      break;
    case SFLFLOW_SAMPLE_EXPANDED:
      readv5FlowSample(spp, TRUE, pptrsv, req, TRUE);
      break;
    case SFLCOUNTERS_SAMPLE_EXPANDED:
      readv5CountersSample(spp, TRUE, pptrsv);
      break;
    case SFLACL_BROCADE_SAMPLE:
      getData32(spp); /* trash: sample length */
      getData32(spp); /* trash: FoundryFlags */
      getData32(spp); /* trash: FoundryGroupID */
      goto SFv5_read_sampleType; /* rewind */
      break;
    default:
      SF_notify_malf_packet(LOG_INFO, "INFO", "discarding unknown v5 sample", (struct sockaddr *) pptrsv->v4.f_agent);
      xflow_status_table.tot_bad_datagrams++;
      return; /* unexpected sampleType; aborting packet */
    }
    if ((u_char *)spp->datap > spp->endp) return; 
  }
}

void process_SF_raw_packet(SFSample *spp, struct packet_ptrs_vector *pptrsv,
                                struct plugin_requests *req, struct sockaddr *agent)
{
  struct packet_ptrs *pptrs = &pptrsv->v4;
  u_int32_t agentSubId;

  switch (spp->datagramVersion = getData32(spp)) {
  case 5:
    getAddress(spp, &spp->agent_addr);
    spp->agentSubId = agentSubId = getData32(spp);
    pptrs->seqno = getData32(spp);
    break;
  case 4:
  case 2:
    getAddress(spp, &spp->agent_addr);
    spp->agentSubId = agentSubId = 0; /* not supported */
    pptrs->seqno = getData32(spp);
    break;
  default:
    if (!config.nfacctd_disable_checks) {
      SF_notify_malf_packet(LOG_INFO, "INFO", "discarding unknown sFlow packet", (struct sockaddr *) pptrs->f_agent);
      xflow_status_table.tot_bad_datagrams++;
    }
    return;
  }

  if (config.debug) {
    struct host_addr a;
    char agent_addr[50];
    u_int16_t agent_port;

    sa_to_addr((struct sockaddr *)pptrs->f_agent, &a, &agent_port);
    addr_to_str(agent_addr, &a);

    Log(LOG_DEBUG, "DEBUG ( %s/core ): Received sFlow packet from [%s:%u] version [%u] seqno [%u]\n",
                        config.name, agent_addr, agent_port, spp->datagramVersion, pptrs->seqno);
  }

  if (req->ptm_c.exec_ptm_dissect) {
    /* Dissecting is not supported for sFlow v2-v4 due to lack of length fields */
    if (spp->datagramVersion == 5) {
      u_int32_t samplesInPacket, sampleType, idx, *flowLenPtr;
      struct SF_dissect dissect;

      memset(&dissect, 0, sizeof(dissect));
      pptrs->tee_dissect = (char *) &dissect;
      req->ptm_c.exec_ptm_res = TRUE;

      dissect.hdrBasePtr = spp->rawSample;
      skipBytes(spp, 4); /* sysUpTime */
      dissect.samplesInPkt = (u_int32_t *) getPointer(spp);
      samplesInPacket = getData32(spp);
      dissect.hdrEndPtr = (u_char *) getPointer(spp);
      dissect.hdrLen = (dissect.hdrEndPtr - dissect.hdrBasePtr);
      (*dissect.samplesInPkt) = htonl(1);

      for (idx = 0; idx < samplesInPacket; idx++) {
        InterSampleCleanup(spp);
        set_vector_sample_type(pptrsv, 0);
        spp->agentSubId = agentSubId;

        dissect.flowBasePtr = (u_char *) getPointer(spp);
        sampleType = getData32(spp);
        set_vector_sample_type(pptrsv, sampleType);
        sfv5_modules_db_init();

        flowLenPtr = (u_int32_t *) getPointer(spp);
        dissect.flowLen = (ntohl(*flowLenPtr) + 8 /* add sample type + sample length */);
        dissect.flowEndPtr = (dissect.flowBasePtr + dissect.flowLen);

        switch (sampleType) {
        case SFLFLOW_SAMPLE:
          readv5FlowSample(spp, FALSE, pptrsv, req, FALSE);
          break;
        case SFLFLOW_SAMPLE_EXPANDED:
          readv5FlowSample(spp, TRUE, pptrsv, req, FALSE);
          break;
        default:
	  /* we just trash counter samples and all when dissecting */
          skipBytes(spp, (dissect.flowLen - 4 /* subtract sample type */));
	  continue;
        }

        if (config.debug) {
	  struct host_addr a;
	  char agent_addr[50];
	  u_int16_t agent_port;

	  sa_to_addr((struct sockaddr *)pptrs->f_agent, &a, &agent_port);
	  addr_to_str(agent_addr, &a);

	  Log(LOG_DEBUG, "DEBUG ( %s/core ): Split sFlow Flow Sample from [%s:%u] version [%u] seqno [%u] [%u/%u]\n",
		config.name, agent_addr, agent_port, spp->datagramVersion, pptrs->seqno, (idx+1), samplesInPacket);
        }

        /* if something is wrong with the pointers, let's stop here but still
           we take a moment to send the full packet over */
        if ((u_char *) spp->datap > spp->endp) break;

        exec_plugins(pptrs, req);
      }

      /* preps to possibly send over the full packet next */
      InterSampleCleanup(spp);
      set_vector_sample_type(pptrsv, 0);
      spp->agentSubId = agentSubId;
      (*dissect.samplesInPkt) = htonl(samplesInPacket);
    }
    else Log(LOG_DEBUG, "DEBUG ( %s/core ): sFlow packet version (%u) not supported for dissection\n",
		config.name, spp->datagramVersion); 
  }
  else sfv245_check_status(spp, pptrs, agent);

  /* If dissecting, we may also send the full packet in case multiple tee
     plugins are instantiated and any of them does not require dissection */
  pptrs->tee_dissect = NULL;
  req->ptm_c.exec_ptm_res = FALSE;

  exec_plugins(pptrs, req);
}

void SF_compute_once()
{
  struct pkt_data dummy;

  CounterSz = sizeof(dummy.pkt_len);
  PdataSz = sizeof(struct pkt_data);
  PpayloadSz = sizeof(struct pkt_payload);
  PmsgSz = sizeof(struct pkt_msg);
  PextrasSz = sizeof(struct pkt_extras);
  PbgpSz = sizeof(struct pkt_bgp_primitives);
  PlbgpSz = sizeof(struct pkt_legacy_bgp_primitives);
  PnatSz = sizeof(struct pkt_nat_primitives);
  PmplsSz = sizeof(struct pkt_mpls_primitives);
  PtunSz = sizeof(struct pkt_tunnel_primitives);
  PvhdrSz = sizeof(struct pkt_vlen_hdr_primitives);
  PmLabelTSz = sizeof(pm_label_t);
  PtLabelTSz = sizeof(pt_label_t);
  ChBufHdrSz = sizeof(struct ch_buf_hdr);
  CharPtrSz = sizeof(char *);
  IP4HdrSz = sizeof(struct pm_iphdr);
  IP4TlSz = sizeof(struct pm_iphdr)+sizeof(struct pm_tlhdr);
  SFSampleSz = sizeof(SFSample);
  SFLAddressSz = sizeof(SFLAddress);
  SFrenormEntrySz = sizeof(struct xflow_status_entry_sampling);
  PptrsSz = sizeof(struct packet_ptrs);
  CSSz = sizeof(struct class_st);
  HostAddrSz = sizeof(struct host_addr);
  UDPHdrSz = sizeof(struct pm_udphdr);

  IP6HdrSz = sizeof(struct ip6_hdr);
  IP6AddrSz = sizeof(struct in6_addr);
  IP6TlSz = sizeof(struct ip6_hdr)+sizeof(struct pm_tlhdr);
}

void SF_notify_malf_packet(short int severity, char *severity_str, char *ostr, struct sockaddr *sa)
{
  struct host_addr a;
  char errstr[SRVBUFLEN];
  char agent_addr[50] /* able to fit an IPv6 string aswell */, any[] = "0.0.0.0";
  u_int16_t agent_port;

  sa_to_addr((struct sockaddr *)sa, &a, &agent_port);
  addr_to_str(agent_addr, &a);
  snprintf(errstr, SRVBUFLEN, "%s ( %s/core ): %s: sfacctd=%s:%u agent=%s:%u \n", severity_str,
	config.name, ostr, ((config.nfacctd_ip) ? config.nfacctd_ip : any), collector_port,
	agent_addr, agent_port);
  Log(severity, "%s", errstr);
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

    if (config.classifier_ndpi || config.aggregate_primitives) sf_flow_sample_hdr_decode(sample);

    /* we need to understand the IP protocol version in order to build the fake packet */
    switch (pptrs->flow_type) {
    case PM_FTYPE_IPV4:
      if (req->bpf_filter) {
        reset_mac(pptrs);
        reset_ip4(pptrs);

        memcpy(pptrs->mac_ptr+ETH_ADDR_LEN, &sample->eth_src, ETH_ADDR_LEN); 
        memcpy(pptrs->mac_ptr, &sample->eth_dst, ETH_ADDR_LEN);
	((struct pm_iphdr *)pptrs->iph_ptr)->ip_vhl = 0x45;
        memcpy(&((struct pm_iphdr *)pptrs->iph_ptr)->ip_src, &sample->dcd_srcIP, 4);
        memcpy(&((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst, &sample->dcd_dstIP, 4);
        memcpy(&((struct pm_iphdr *)pptrs->iph_ptr)->ip_p, &dcd_ipProtocol, 1);
        memcpy(&((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, &dcd_ipTos, 1);
        memcpy(&((struct pm_tlhdr *)pptrs->tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct pm_tlhdr *)pptrs->tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrs->lm_mask_src = sample->srcMask;
      pptrs->lm_mask_dst = sample->dstMask;
      pptrs->lm_method_src = NF_NET_KEEP;
      pptrs->lm_method_dst = NF_NET_KEEP;

      pptrs->l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(pptrs);
      if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, pptrs, &pptrs->bta, &pptrs->bta2);
      if (config.nfacctd_flow_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, pptrs, &pptrs->bitr, NULL);
      if (config.bgp_daemon) bgp_srcdst_lookup(pptrs, FUNC_TYPE_BGP);
      if (config.bgp_daemon_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, pptrs, &pptrs->bpas, NULL);
      if (config.bgp_daemon_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, pptrs, &pptrs->blp, NULL);
      if (config.bgp_daemon_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, pptrs, &pptrs->bmed, NULL);
      if (config.bmp_daemon) bmp_srcdst_lookup(pptrs);
      exec_plugins(pptrs, req);
      break;
    case PM_FTYPE_IPV6:
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
        memcpy(&((struct pm_tlhdr *)pptrsv->v6.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct pm_tlhdr *)pptrsv->v6.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct pm_tcphdr *)pptrsv->v6.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->v6.lm_mask_src = sample->srcMask;
      pptrsv->v6.lm_mask_dst = sample->dstMask;
      pptrsv->v6.lm_method_src = NF_NET_KEEP;
      pptrsv->v6.lm_method_dst = NF_NET_KEEP;

      pptrsv->v6.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->v6);
      if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->v6, &pptrsv->v6.bta, &pptrsv->v6.bta2);
      if (config.nfacctd_flow_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->v6, &pptrsv->v6.bitr, NULL);
      if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->v6, FUNC_TYPE_BGP);
      if (config.bgp_daemon_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->v6, &pptrsv->v6.bpas, NULL);
      if (config.bgp_daemon_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->v6, &pptrsv->v6.blp, NULL);
      if (config.bgp_daemon_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->v6, &pptrsv->v6.bmed, NULL);
      if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->v6);
      exec_plugins(&pptrsv->v6, req);
      break;
    case PM_FTYPE_VLAN_IPV4:
      pptrsv->vlan4.flow_type = pptrs->flow_type;

      if (req->bpf_filter) {
        reset_mac_vlan(&pptrsv->vlan4);
        reset_ip4(&pptrsv->vlan4);

        memcpy(pptrsv->vlan4.mac_ptr+ETH_ADDR_LEN, &sample->eth_src, ETH_ADDR_LEN); 
        memcpy(pptrsv->vlan4.mac_ptr, &sample->eth_dst, ETH_ADDR_LEN); 
        memcpy(pptrsv->vlan4.vlan_ptr, &vlan, 2); 
	((struct pm_iphdr *)pptrsv->vlan4.iph_ptr)->ip_vhl = 0x45;
        memcpy(&((struct pm_iphdr *)pptrsv->vlan4.iph_ptr)->ip_src, &sample->dcd_srcIP, 4);
        memcpy(&((struct pm_iphdr *)pptrsv->vlan4.iph_ptr)->ip_dst, &sample->dcd_dstIP, 4);
        memcpy(&((struct pm_iphdr *)pptrsv->vlan4.iph_ptr)->ip_p, &dcd_ipProtocol, 1);
        memcpy(&((struct pm_iphdr *)pptrsv->vlan4.iph_ptr)->ip_tos, &dcd_ipTos, 1); 
        memcpy(&((struct pm_tlhdr *)pptrsv->vlan4.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct pm_tlhdr *)pptrsv->vlan4.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct pm_tcphdr *)pptrsv->vlan4.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->vlan4.lm_mask_src = sample->srcMask;
      pptrsv->vlan4.lm_mask_dst = sample->dstMask;
      pptrsv->vlan4.lm_method_src = NF_NET_KEEP;
      pptrsv->vlan4.lm_method_dst = NF_NET_KEEP;

      pptrsv->vlan4.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlan4);
      if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlan4, &pptrsv->vlan4.bta, &pptrsv->vlan4.bta2);
      if (config.nfacctd_flow_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlan4, &pptrsv->vlan4.bitr, NULL);
      if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->vlan4, FUNC_TYPE_BGP);
      if (config.bgp_daemon_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlan4, &pptrsv->vlan4.bpas, NULL);
      if (config.bgp_daemon_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlan4, &pptrsv->vlan4.blp, NULL);
      if (config.bgp_daemon_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlan4, &pptrsv->vlan4.bmed, NULL);
      if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->vlan4);
      exec_plugins(&pptrsv->vlan4, req);
      break;
    case PM_FTYPE_VLAN_IPV6:
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
        memcpy(&((struct pm_tlhdr *)pptrsv->vlan6.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct pm_tlhdr *)pptrsv->vlan6.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct pm_tcphdr *)pptrsv->vlan6.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->vlan6.lm_mask_src = sample->srcMask;
      pptrsv->vlan6.lm_mask_dst = sample->dstMask;
      pptrsv->vlan6.lm_method_src = NF_NET_KEEP;
      pptrsv->vlan6.lm_method_dst = NF_NET_KEEP;

      pptrsv->vlan6.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlan6);
      if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlan6, &pptrsv->vlan6.bta, &pptrsv->vlan6.bta2);
      if (config.nfacctd_flow_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlan6, &pptrsv->vlan6.bitr, NULL);
      if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->vlan6, FUNC_TYPE_BGP);
      if (config.bgp_daemon_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlan6, &pptrsv->vlan6.bpas, NULL);
      if (config.bgp_daemon_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlan6, &pptrsv->vlan6.blp, NULL);
      if (config.bgp_daemon_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlan6, &pptrsv->vlan6.bmed, NULL);
      if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->vlan6);
      exec_plugins(&pptrsv->vlan6, req);
      break;
    case PM_FTYPE_MPLS_IPV4:
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
	
	((struct pm_iphdr *)pptrsv->mpls4.iph_ptr)->ip_vhl = 0x45;
        memcpy(&((struct pm_iphdr *)pptrsv->mpls4.iph_ptr)->ip_src, &sample->dcd_srcIP, 4);
        memcpy(&((struct pm_iphdr *)pptrsv->mpls4.iph_ptr)->ip_dst, &sample->dcd_dstIP, 4); 
        memcpy(&((struct pm_iphdr *)pptrsv->mpls4.iph_ptr)->ip_p, &dcd_ipProtocol, 1); 
        memcpy(&((struct pm_iphdr *)pptrsv->mpls4.iph_ptr)->ip_tos, &dcd_ipTos, 1); 
        memcpy(&((struct pm_tlhdr *)pptrsv->mpls4.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct pm_tlhdr *)pptrsv->mpls4.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct pm_tcphdr *)pptrsv->mpls4.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->mpls4.lm_mask_src = sample->srcMask;
      pptrsv->mpls4.lm_mask_dst = sample->dstMask;
      pptrsv->mpls4.lm_method_src = NF_NET_KEEP;
      pptrsv->mpls4.lm_method_dst = NF_NET_KEEP;

      pptrsv->mpls4.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->mpls4);
      if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->mpls4, &pptrsv->mpls4.bta, &pptrsv->mpls4.bta2);
      if (config.nfacctd_flow_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->mpls4, &pptrsv->mpls4.bitr, NULL);
      if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->mpls4, FUNC_TYPE_BGP);
      if (config.bgp_daemon_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->mpls4, &pptrsv->mpls4.bpas, NULL);
      if (config.bgp_daemon_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->mpls4, &pptrsv->mpls4.blp, NULL);
      if (config.bgp_daemon_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->mpls4, &pptrsv->mpls4.bmed, NULL);
      if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->mpls4);
      exec_plugins(&pptrsv->mpls4, req);
      break;
    case PM_FTYPE_MPLS_IPV6:
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
        memcpy(&((struct pm_tlhdr *)pptrsv->mpls6.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct pm_tlhdr *)pptrsv->mpls6.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct pm_tcphdr *)pptrsv->mpls6.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->mpls6.lm_mask_src = sample->srcMask;
      pptrsv->mpls6.lm_mask_dst = sample->dstMask;
      pptrsv->mpls6.lm_method_src = NF_NET_KEEP;
      pptrsv->mpls6.lm_method_dst = NF_NET_KEEP;

      pptrsv->mpls6.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->mpls6);
      if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->mpls6, &pptrsv->mpls6.bta, &pptrsv->mpls6.bta2);
      if (config.nfacctd_flow_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->mpls6, &pptrsv->mpls6.bitr, NULL);
      if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->mpls6, FUNC_TYPE_BGP);
      if (config.bgp_daemon_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->mpls6, &pptrsv->mpls6.bpas, NULL);
      if (config.bgp_daemon_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->mpls6, &pptrsv->mpls6.blp, NULL);
      if (config.bgp_daemon_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->mpls6, &pptrsv->mpls6.bmed, NULL);
      if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->mpls6);
      exec_plugins(&pptrsv->mpls6, req);
      break;
    case PM_FTYPE_VLAN_MPLS_IPV4:
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

	((struct pm_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_vhl = 0x45;
        memcpy(&((struct pm_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_src, &sample->dcd_srcIP, 4); 
        memcpy(&((struct pm_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_dst, &sample->dcd_dstIP, 4);
        memcpy(&((struct pm_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_p, &dcd_ipProtocol, 1);
        memcpy(&((struct pm_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_tos, &dcd_ipTos, 1);
        memcpy(&((struct pm_tlhdr *)pptrsv->vlanmpls4.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct pm_tlhdr *)pptrsv->vlanmpls4.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct pm_tcphdr *)pptrsv->vlanmpls4.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->vlanmpls4.lm_mask_src = sample->srcMask;
      pptrsv->vlanmpls4.lm_mask_dst = sample->dstMask;
      pptrsv->vlanmpls4.lm_method_src = NF_NET_KEEP;
      pptrsv->vlanmpls4.lm_method_dst = NF_NET_KEEP;

      pptrsv->vlanmpls4.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlanmpls4);
      if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bta, &pptrsv->vlanmpls4.bta2);
      if (config.nfacctd_flow_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bitr, NULL);
      if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->vlanmpls4, FUNC_TYPE_BGP);
      if (config.bgp_daemon_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bpas, NULL);
      if (config.bgp_daemon_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.blp, NULL);
      if (config.bgp_daemon_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bmed, NULL);
      if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->vlanmpls4);
      exec_plugins(&pptrsv->vlanmpls4, req);
      break;
    case PM_FTYPE_VLAN_MPLS_IPV6:
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
        memcpy(&((struct pm_tlhdr *)pptrsv->vlanmpls6.tlh_ptr)->src_port, &dcd_sport, 2);
        memcpy(&((struct pm_tlhdr *)pptrsv->vlanmpls6.tlh_ptr)->dst_port, &dcd_dport, 2);
        memcpy(&((struct pm_tcphdr *)pptrsv->vlanmpls6.tlh_ptr)->th_flags, &dcd_tcpFlags, 1);
      }

      pptrsv->vlanmpls6.lm_mask_src = sample->srcMask;
      pptrsv->vlanmpls6.lm_mask_dst = sample->dstMask;
      pptrsv->vlanmpls6.lm_method_src = NF_NET_KEEP;
      pptrsv->vlanmpls6.lm_method_dst = NF_NET_KEEP;

      pptrsv->vlanmpls6.l4_proto = sample->dcd_ipProtocol;

      if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlanmpls6);
      if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bta, &pptrsv->vlanmpls6.bta2);
      if (config.nfacctd_flow_to_rd_map) SF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bitr, NULL);
      if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->vlanmpls6, FUNC_TYPE_BGP);
      if (config.bgp_daemon_peer_as_src_map) SF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bpas, NULL);
      if (config.bgp_daemon_src_local_pref_map) SF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.blp, NULL);
      if (config.bgp_daemon_src_med_map) SF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bmed, NULL);
      if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->vlanmpls6);
      exec_plugins(&pptrsv->vlanmpls6, req);
      break;
    default:
      break;
    }
  }
}

int SF_find_id(struct id_table *t, struct packet_ptrs *pptrs, pm_id_t *tag, pm_id_t *tag2)
{
  struct sockaddr sa_local;
  struct sockaddr_in *sa4 = (struct sockaddr_in *) &sa_local;
  struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &sa_local;
  SFSample *sample = (SFSample *)pptrs->f_data; 
  int x, begin = 0, end = 0;
  pm_id_t ret = 0;

  if (!t) return 0;

  /* The id_table is shared between by IPv4 and IPv6 sFlow collectors.
     IPv4 ones are in the lower part (0..x), IPv6 ones are in the upper
     part (x+1..end)
  */

  pretag_init_vars(pptrs, t);
  if (tag) *tag = 0;
  if (tag2) *tag2 = 0;
  if (pptrs) {
    pptrs->have_tag = FALSE;
    pptrs->have_tag2 = FALSE;
  }

  /* Giving a first try with index(es) */
  if (config.maps_index && pretag_index_have_one(t)) {
    struct id_entry *index_results[ID_TABLE_INDEX_RESULTS];
    u_int32_t iterator, num_results;

    num_results = pretag_index_lookup(t, pptrs, index_results, ID_TABLE_INDEX_RESULTS);

    for (iterator = 0; index_results[iterator] && iterator < num_results; iterator++) {
      ret = pretag_entry_process(index_results[iterator], pptrs, tag, tag2);
      if (!(ret & PRETAG_MAP_RCODE_JEQ)) return ret;
    }

    /* if we have at least one index we trust we did a good job */
    return ret;
  }

  if (sample->agent_addr.type == SFLADDRESSTYPE_IP_V4) {
    begin = 0;
    end = t->ipv4_num;
    sa_local.sa_family = AF_INET;
    sa4->sin_addr.s_addr = sample->agent_addr.address.ip_v4.s_addr;
  }
  else if (sample->agent_addr.type == SFLADDRESSTYPE_IP_V6) {
    begin = t->num-t->ipv6_num;
    end = t->num;
    sa_local.sa_family = AF_INET6;
    ip6_addr_cpy(&sa6->sin6_addr, &sample->agent_addr.address.ip_v6);
  }

  for (x = begin; x < end; x++) {
    if (host_addr_mask_sa_cmp(&t->e[x].key.agent_ip.a, &t->e[x].key.agent_mask, &sa_local) == 0) {
      ret = pretag_entry_process(&t->e[x], pptrs, tag, tag2);

      if (!ret || ret > TRUE) {
        if (ret & PRETAG_MAP_RCODE_JEQ) {
          x = t->e[x].jeq.ptr->pos;
          x--; // yes, it will be automagically incremented by the for() cycle
        }
	else break;
      }
    }
  }

  return ret;
}

u_int8_t SF_evaluate_flow_type(struct packet_ptrs *pptrs)
{
  SFSample *sample = (SFSample *)pptrs->f_data;
  u_int8_t ret = PM_FTYPE_TRAFFIC;

  if (sample->in_vlan || sample->out_vlan) ret += PM_FTYPE_VLAN;
  if (sample->lstk.depth > 0) ret += PM_FTYPE_MPLS;
  if (sample->gotIPV4); 
  else if (sample->gotIPV6) ret += PM_FTYPE_TRAFFIC_IPV6;

  return ret;
}

void set_vector_sample_type(struct packet_ptrs_vector *pptrsv, u_int32_t sample_type)
{
  pptrsv->v4.sample_type = sample_type;
  pptrsv->vlan4.sample_type = sample_type;
  pptrsv->mpls4.sample_type = sample_type;
  pptrsv->vlanmpls4.sample_type = sample_type;

  pptrsv->v6.sample_type = sample_type;
  pptrsv->vlan6.sample_type = sample_type;
  pptrsv->mpls6.sample_type = sample_type;
  pptrsv->vlanmpls6.sample_type = sample_type;
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
  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_vhl, 5);
}

void reset_ip6(struct packet_ptrs *pptrs)
{
  memset(pptrs->iph_ptr, 0, IP6TlSz);
  Assign16(((struct ip6_hdr *)pptrs->iph_ptr)->ip6_plen, htons(100));
  ((struct ip6_hdr *)pptrs->iph_ptr)->ip6_hlim = 64;
}

struct xflow_status_entry *sfv245_check_status(SFSample *spp, struct packet_ptrs *pptrs, struct sockaddr *sa)
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
    entry = search_status_table(&xflow_status_table, &salocal, aux1, 0, hash, XFLOW_STATUS_TABLE_MAX_ENTRIES);
    if (entry) {
      update_status_table(entry, spp->sequenceNo, pptrs->f_len);
      entry->inc = 1;
    }
  }

  return entry;
}

void sfv245_check_counter_log_init(struct packet_ptrs *pptrs)
{
  struct xflow_status_entry *entry = NULL;
  struct bgp_peer *peer;

  if (!pptrs) return;

  entry = (struct xflow_status_entry *) pptrs->f_status;

  if (entry) {
    if (!entry->sf_cnt) {
      entry->sf_cnt = malloc(sizeof(struct bgp_peer));
      if (!entry->sf_cnt) {
        Log(LOG_ERR, "ERROR ( %s/core ): Unable to malloc() xflow_status_entry sFlow counters log structure. Exiting.\n", config.name);
        exit_gracefully(1);
      }
      memset(entry->sf_cnt, 0, sizeof(struct bgp_peer));
    }

    peer = (struct bgp_peer *) entry->sf_cnt;
    
    if (!peer->log) { 
      memcpy(&peer->addr, &entry->agent_addr, sizeof(struct host_addr));
      addr_to_str(peer->addr_str, &peer->addr);
      bgp_peer_log_init(peer, config.sfacctd_counter_output, FUNC_TYPE_SFLOW_COUNTER);
    }
  }
}

int sf_cnt_log_msg(struct bgp_peer *peer, SFSample *sample, int version, u_int32_t len, char *event_type, int output, u_int32_t tag)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(FUNC_TYPE_SFLOW_COUNTER);
  int ret = 0, amqp_ret = 0, kafka_ret = 0, etype = BGP_LOGDUMP_ET_NONE;
  (void)etype;

  if (!bms || !peer || !sample || !event_type) {
    skipBytes(sample, len);
    return ret;
  }

  if (!strcmp(event_type, "dump")) etype = BGP_LOGDUMP_ET_DUMP;
  else if (!strcmp(event_type, "log")) etype = BGP_LOGDUMP_ET_LOG;

#ifdef WITH_RABBITMQ
  if (config.sfacctd_counter_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG)
    p_amqp_set_routing_key(peer->log->amqp_host, peer->log->filename);
#endif

#ifdef WITH_KAFKA
  if (config.sfacctd_counter_kafka_topic && etype == BGP_LOGDUMP_ET_LOG)
    p_kafka_set_topic(peer->log->kafka_host, peer->log->filename);
#endif

  if (output == PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
    char ip_address[INET6_ADDRSTRLEN];
    json_t *obj = json_object();

    /* no need for seq and timestamp for "dump" event_type */
    if (etype == BGP_LOGDUMP_ET_LOG) {
      json_object_set_new_nocheck(obj, "seq", json_integer((json_int_t) bgp_peer_log_seq_get(&bms->log_seq)));
      bgp_peer_log_seq_increment(&bms->log_seq);

      json_object_set_new_nocheck(obj, "timestamp", json_string(bms->log_tstamp_str));
    }

    addr_to_str(ip_address, &peer->addr);
    json_object_set_new_nocheck(obj, "peer_ip_src", json_string(ip_address));

    json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

    json_object_set_new_nocheck(obj, "source_id_index", json_integer((json_int_t)sample->ds_index));

    json_object_set_new_nocheck(obj, "sflow_seq", json_integer((json_int_t)sample->sequenceNo));

    json_object_set_new_nocheck(obj, "sflow_cnt_seq", json_integer((json_int_t)sample->cntSequenceNo));

    if (version == 5) {
      switch (tag) {
      case SFLCOUNTERS_GENERIC:
        readCounters_generic(peer, sample, "log", config.sfacctd_counter_output, obj);
        break;
      case SFLCOUNTERS_ETHERNET:
        readCounters_ethernet(peer, sample, "log", config.sfacctd_counter_output, obj);
        break;
      case SFLCOUNTERS_VLAN:
        readCounters_vlan(peer, sample, "log", config.sfacctd_counter_output, obj);
        break;
      default:
        skipBytes(sample, len);
        break;
      }
    }
    else if (version < 5) {
      switch (tag) {
      case INMCOUNTERSVERSION_GENERIC:
      case INMCOUNTERSVERSION_ETHERNET:
        readCounters_generic(peer, sample, "log", config.sfacctd_counter_output, obj);
        break;
      case INMCOUNTERSVERSION_VLAN:
	/* nothing here */
	break;
      default:
        skipBytes(sample, len);
	break;
      }

      /* now see if there are any specific counter blocks to add */
      switch (tag) {
      case INMCOUNTERSVERSION_GENERIC:
	/* nothing more */
	break;
      case INMCOUNTERSVERSION_ETHERNET:
	readCounters_ethernet(peer, sample, "log", config.sfacctd_counter_output, obj);
	break;
      case INMCOUNTERSVERSION_VLAN:
	readCounters_vlan(peer, sample, "log", config.sfacctd_counter_output, obj);
	break;
      default:
	/* nothing more; already skipped */
	break;
      }
    }
    else skipBytes(sample, len);

    if (config.sfacctd_counter_file && etype == BGP_LOGDUMP_ET_LOG)
      write_and_free_json(peer->log->fd, obj);

#ifdef WITH_RABBITMQ
    if (config.sfacctd_counter_amqp_routing_key && etype == BGP_LOGDUMP_ET_LOG) {
      amqp_ret = write_and_free_json_amqp(peer->log->amqp_host, obj);
      p_amqp_unset_routing_key(peer->log->amqp_host);
    }
#endif

#ifdef WITH_KAFKA
    if (config.sfacctd_counter_kafka_topic && etype == BGP_LOGDUMP_ET_LOG) {
      kafka_ret = write_and_free_json_kafka(peer->log->kafka_host, obj);
      p_kafka_unset_topic(peer->log->kafka_host);
    }
#endif
#endif
  }
  else skipBytes(sample, len);

  return (ret | amqp_ret | kafka_ret);
}

int readCounters_generic(struct bgp_peer *peer, SFSample *sample, char *event_type, int output, void *vobj)
{
  int ret = 0;
#ifdef WITH_JANSSON
  char msg_type[] = "sflow_cnt_generic";
  json_t *obj = (json_t *) vobj;

  /* parse sFlow first and foremost */
  sample->ifCounters.ifIndex = getData32(sample);
  sample->ifCounters.ifType = getData32(sample);
  sample->ifCounters.ifSpeed = getData64(sample);
  sample->ifCounters.ifDirection = getData32(sample);
  sample->ifCounters.ifStatus = getData32(sample);
  // the generic counters always come first 
  sample->ifCounters.ifInOctets = getData64(sample);
  sample->ifCounters.ifInUcastPkts = getData32(sample);
  sample->ifCounters.ifInMulticastPkts = getData32(sample);
  sample->ifCounters.ifInBroadcastPkts = getData32(sample);
  sample->ifCounters.ifInDiscards = getData32(sample);
  sample->ifCounters.ifInErrors = getData32(sample);
  sample->ifCounters.ifInUnknownProtos = getData32(sample);
  sample->ifCounters.ifOutOctets = getData64(sample);
  sample->ifCounters.ifOutUcastPkts = getData32(sample);
  sample->ifCounters.ifOutMulticastPkts = getData32(sample);
  sample->ifCounters.ifOutBroadcastPkts = getData32(sample);
  sample->ifCounters.ifOutDiscards = getData32(sample);
  sample->ifCounters.ifOutErrors = getData32(sample);
  sample->ifCounters.ifPromiscuousMode = getData32(sample);

  if (!peer || !sample || !vobj) return ret;

  json_object_set_new_nocheck(obj, "sf_cnt_type", json_string(msg_type));

  json_object_set_new_nocheck(obj, "ifIndex", json_integer((json_int_t)sample->ifCounters.ifIndex));

  json_object_set_new_nocheck(obj, "ifType", json_integer((json_int_t)sample->ifCounters.ifType));

  json_object_set_new_nocheck(obj, "ifSpeed", json_integer((json_int_t)sample->ifCounters.ifSpeed));

  json_object_set_new_nocheck(obj, "ifDirection", json_integer((json_int_t)sample->ifCounters.ifDirection));

  json_object_set_new_nocheck(obj, "ifStatus", json_integer((json_int_t)sample->ifCounters.ifStatus));

  json_object_set_new_nocheck(obj, "ifInOctets", json_integer((json_int_t)sample->ifCounters.ifInOctets));

  json_object_set_new_nocheck(obj, "ifInUcastPkts", json_integer((json_int_t)sample->ifCounters.ifInUcastPkts));

  json_object_set_new_nocheck(obj, "ifInMulticastPkts", json_integer((json_int_t)sample->ifCounters.ifInMulticastPkts));

  json_object_set_new_nocheck(obj, "ifInBroadcastPkts", json_integer((json_int_t)sample->ifCounters.ifInBroadcastPkts));

  json_object_set_new_nocheck(obj, "ifInDiscards", json_integer((json_int_t)sample->ifCounters.ifInDiscards));

  json_object_set_new_nocheck(obj, "ifInErrors", json_integer((json_int_t)sample->ifCounters.ifInErrors));

  json_object_set_new_nocheck(obj, "ifInUnknownProtos", json_integer((json_int_t)sample->ifCounters.ifInUnknownProtos));

  json_object_set_new_nocheck(obj, "ifOutOctets", json_integer((json_int_t)sample->ifCounters.ifOutOctets));

  json_object_set_new_nocheck(obj, "ifOutUcastPkts", json_integer((json_int_t)sample->ifCounters.ifOutUcastPkts));

  json_object_set_new_nocheck(obj, "ifOutMulticastPkts", json_integer((json_int_t)sample->ifCounters.ifOutMulticastPkts));

  json_object_set_new_nocheck(obj, "ifOutBroadcastPkts", json_integer((json_int_t)sample->ifCounters.ifOutBroadcastPkts));

  json_object_set_new_nocheck(obj, "ifOutDiscards", json_integer((json_int_t)sample->ifCounters.ifOutDiscards));

  json_object_set_new_nocheck(obj, "ifOutErrors", json_integer((json_int_t)sample->ifCounters.ifOutErrors));

  json_object_set_new_nocheck(obj, "ifPromiscuousMode", json_integer((json_int_t)sample->ifCounters.ifPromiscuousMode));
#endif

  return ret;
}

int readCounters_ethernet(struct bgp_peer *peer, SFSample *sample, char *event_type, int output, void *vobj)
{
  int ret = 0;
#ifdef WITH_JANSSON
  char msg_type[] = "sflow_cnt_ethernet";
  json_t *obj = (json_t *) vobj;

  u_int32_t m32_1, m32_2, m32_3, m32_4, m32_5;
  u_int32_t m32_6, m32_7, m32_8, m32_9, m32_10;
  u_int32_t m32_11, m32_12, m32_13;

  /* parse sFlow first and foremost */
  m32_1 = getData32(sample); /* dot3StatsAlignmentErrors */
  m32_2 = getData32(sample); /* dot3StatsFCSErrors */
  m32_3 = getData32(sample); /* dot3StatsSingleCollisionFrames */
  m32_4 = getData32(sample); /* dot3StatsMultipleCollisionFrames */
  m32_5 = getData32(sample); /* dot3StatsSQETestErrors */
  m32_6 = getData32(sample); /* dot3StatsDeferredTransmissions */
  m32_7 = getData32(sample); /* dot3StatsLateCollisions */
  m32_8 = getData32(sample); /* dot3StatsExcessiveCollisions */
  m32_9 = getData32(sample); /* dot3StatsInternalMacTransmitErrors */
  m32_10 = getData32(sample); /* dot3StatsCarrierSenseErrors */
  m32_11 = getData32(sample); /* dot3StatsFrameTooLongs */
  m32_12 = getData32(sample); /* dot3StatsInternalMacReceiveErrors */
  m32_13 = getData32(sample); /* dot3StatsSymbolErrors */

  if (!peer || !sample || !vobj) return ret;

  json_object_set_new_nocheck(obj, "sf_cnt_type", json_string(msg_type));

  json_object_set_new_nocheck(obj, "dot3StatsAlignmentErrors", json_integer((json_int_t)m32_1));

  json_object_set_new_nocheck(obj, "dot3StatsFCSErrors", json_integer((json_int_t)m32_2));

  json_object_set_new_nocheck(obj, "dot3StatsSingleCollisionFrames", json_integer((json_int_t)m32_3));

  json_object_set_new_nocheck(obj, "dot3StatsMultipleCollisionFrames", json_integer((json_int_t)m32_4));

  json_object_set_new_nocheck(obj, "dot3StatsSQETestErrors", json_integer((json_int_t)m32_5));

  json_object_set_new_nocheck(obj, "dot3StatsDeferredTransmissions", json_integer((json_int_t)m32_6));

  json_object_set_new_nocheck(obj, "dot3StatsLateCollisions", json_integer((json_int_t)m32_7));

  json_object_set_new_nocheck(obj, "dot3StatsExcessiveCollisions", json_integer((json_int_t)m32_8));

  json_object_set_new_nocheck(obj, "dot3StatsInternalMacTransmitErrors", json_integer((json_int_t)m32_9));

  json_object_set_new_nocheck(obj, "dot3StatsCarrierSenseErrors", json_integer((json_int_t)m32_10));

  json_object_set_new_nocheck(obj, "dot3StatsFrameTooLongs", json_integer((json_int_t)m32_11));

  json_object_set_new_nocheck(obj, "dot3StatsInternalMacReceiveErrors", json_integer((json_int_t)m32_12));

  json_object_set_new_nocheck(obj, "dot3StatsSymbolErrors", json_integer((json_int_t)m32_13));
#endif

  return ret;
}

int readCounters_vlan(struct bgp_peer *peer, SFSample *sample, char *event_type, int output, void *vobj)
{
  int ret = 0;
#ifdef WITH_JANSSON
  char msg_type[] = "sflow_cnt_vlan";
  json_t *obj = (json_t *) vobj;

  u_int64_t m64_1;
  u_int32_t m32_1, m32_2, m32_3, m32_4;

  /* parse sFlow first and foremost */
  sample->in_vlan = getData32(sample);
  m64_1 = getData64(sample); /* octets */
  m32_1 = getData32(sample); /* ucastPkts */
  m32_2 = getData32(sample); /* multicastPkts */
  m32_3 = getData32(sample); /* broadcastPkts */
  m32_4 = getData32(sample); /* discards */

  if (!peer || !sample || !vobj) return ret;

  json_object_set_new_nocheck(obj, "sf_cnt_type", json_string(msg_type));

  json_object_set_new_nocheck(obj, "octets", json_integer((json_int_t)m64_1));

  json_object_set_new_nocheck(obj, "ucastPkts", json_integer((json_int_t)m32_1));

  json_object_set_new_nocheck(obj, "multicastPkts", json_integer((json_int_t)m32_2));

  json_object_set_new_nocheck(obj, "broadcastPkts", json_integer((json_int_t)m32_3));

  json_object_set_new_nocheck(obj, "discards", json_integer((json_int_t)m32_4));

  json_object_set_new_nocheck(obj, "vlan", json_integer((json_int_t)sample->in_vlan));
#endif

  return ret;
}

#if defined WITH_RABBITMQ
void sfacctd_counter_init_amqp_host()
{
  p_amqp_init_host(&sfacctd_counter_amqp_host);

  if (!config.sfacctd_counter_amqp_user) config.sfacctd_counter_amqp_user = rabbitmq_user;
  if (!config.sfacctd_counter_amqp_passwd) config.sfacctd_counter_amqp_passwd = rabbitmq_pwd;
  if (!config.sfacctd_counter_amqp_exchange) config.sfacctd_counter_amqp_exchange = default_amqp_exchange;
  if (!config.sfacctd_counter_amqp_exchange_type) config.sfacctd_counter_amqp_exchange_type = default_amqp_exchange_type;
  if (!config.sfacctd_counter_amqp_host) config.sfacctd_counter_amqp_host = default_amqp_host;
  if (!config.sfacctd_counter_amqp_vhost) config.sfacctd_counter_amqp_vhost = default_amqp_vhost;
  if (!config.sfacctd_counter_amqp_retry) config.sfacctd_counter_amqp_retry = AMQP_DEFAULT_RETRY;

  p_amqp_set_user(&sfacctd_counter_amqp_host, config.sfacctd_counter_amqp_user);
  p_amqp_set_passwd(&sfacctd_counter_amqp_host, config.sfacctd_counter_amqp_passwd);
  p_amqp_set_exchange(&sfacctd_counter_amqp_host, config.sfacctd_counter_amqp_exchange);
  p_amqp_set_exchange_type(&sfacctd_counter_amqp_host, config.sfacctd_counter_amqp_exchange_type);
  p_amqp_set_host(&sfacctd_counter_amqp_host, config.sfacctd_counter_amqp_host);
  p_amqp_set_vhost(&sfacctd_counter_amqp_host, config.sfacctd_counter_amqp_vhost);
  p_amqp_set_persistent_msg(&sfacctd_counter_amqp_host, config.sfacctd_counter_amqp_persistent_msg);
  p_amqp_set_frame_max(&sfacctd_counter_amqp_host, config.sfacctd_counter_amqp_frame_max);
  p_amqp_set_content_type_json(&sfacctd_counter_amqp_host);
  p_amqp_set_heartbeat_interval(&sfacctd_counter_amqp_host, config.sfacctd_counter_amqp_heartbeat_interval);
  P_broker_timers_set_retry_interval(&sfacctd_counter_amqp_host.btimers, config.sfacctd_counter_amqp_retry);
}
#else
void sfacctd_counter_init_amqp_host()
{
}
#endif

#if defined WITH_KAFKA
int sfacctd_counter_init_kafka_host()
{
  int ret;

  p_kafka_init_host(&sfacctd_counter_kafka_host, config.sfacctd_counter_kafka_config_file);
  ret = p_kafka_connect_to_produce(&sfacctd_counter_kafka_host);

  if (!config.sfacctd_counter_kafka_broker_host) config.sfacctd_counter_kafka_broker_host = default_kafka_broker_host;
  if (!config.sfacctd_counter_kafka_broker_port) config.sfacctd_counter_kafka_broker_port = default_kafka_broker_port;
  if (!config.sfacctd_counter_kafka_retry) config.sfacctd_counter_kafka_retry = PM_KAFKA_DEFAULT_RETRY;

  p_kafka_set_broker(&sfacctd_counter_kafka_host, config.sfacctd_counter_kafka_broker_host, config.sfacctd_counter_kafka_broker_port);
  p_kafka_set_topic(&sfacctd_counter_kafka_host, config.sfacctd_counter_kafka_topic);
  p_kafka_set_partition(&sfacctd_counter_kafka_host, config.sfacctd_counter_kafka_partition);
  p_kafka_set_key(&sfacctd_counter_kafka_host, config.sfacctd_counter_kafka_partition_key, config.sfacctd_counter_kafka_partition_keylen);
  p_kafka_set_content_type(&sfacctd_counter_kafka_host, PM_KAFKA_CNT_TYPE_STR);
  P_broker_timers_set_retry_interval(&sfacctd_counter_kafka_host.btimers, config.sfacctd_counter_kafka_retry);

  return ret;
}
#else
int sfacctd_counter_init_kafka_host()
{
  return ERR;
}
#endif

void sf_cnt_link_misc_structs(struct bgp_misc_structs *bms)
{
#if defined WITH_RABBITMQ
  bms->msglog_amqp_host = &sfacctd_counter_amqp_host;
#endif
#if defined WITH_KAFKA
  bms->msglog_kafka_host = &sfacctd_counter_kafka_host;
#endif
  bms->max_peers = config.sfacctd_counter_max_nodes;
  bms->msglog_file = config.sfacctd_counter_file;
  bms->msglog_amqp_routing_key = config.sfacctd_counter_amqp_routing_key;
  bms->msglog_kafka_topic = config.sfacctd_counter_kafka_topic;
  bms->peer_str = malloc(strlen("peer_src_ip") + 1);
  strcpy(bms->peer_str, "peer_src_ip");
  bms->peer_port_str = NULL;

  /* dump not supported */
}

/* XXX: unify decoding flow sample header, now done twice if DPI or custom primitives are enabled */
void sf_flow_sample_hdr_decode(SFSample *sample)
{
  struct packet_ptrs *pptrs = &sample->hdr_ptrs;

  /* cleanups */
  reset_index_pkt_ptrs(pptrs);
  pptrs->pkthdr = NULL;
  pptrs->packet_ptr = pptrs->mac_ptr = pptrs->vlan_ptr = pptrs->mpls_ptr = NULL;
  pptrs->iph_ptr = pptrs->tlh_ptr = pptrs->payload_ptr = NULL;
  pptrs->l3_proto = pptrs->l4_proto = FALSE;
#if defined (WITH_NDPI)
  memset(&sample->ndpi_class, 0, sizeof(pm_class2_t)); 
#endif

  if (sample->header && sample->headerLen) {
    memset(&sample->hdr_pcap, 0, sizeof(struct pcap_pkthdr));
    sample->hdr_pcap.caplen = sample->headerLen;

    pptrs->pkthdr = (struct pcap_pkthdr *) &sample->hdr_pcap;
    pptrs->packet_ptr = (u_char *) sample->header;

    if (sample->headerProtocol == SFLHEADER_ETHERNET_ISO8023) { 
      eth_handler(&sample->hdr_pcap, pptrs);
      if (pptrs->iph_ptr) {
	if ((*pptrs->l3_handler)(pptrs)) {
#if defined (WITH_NDPI)
	  if (config.classifier_ndpi && pm_ndpi_wfl) {
	    sample->ndpi_class = pm_ndpi_workflow_process_packet(pm_ndpi_wfl, pptrs);
	  }
#endif
	  set_index_pkt_ptrs(pptrs);
	}
      }
    }
  }
}

#ifdef WITH_KAFKA
void SF_init_kafka_host(void *kh)
{
  struct p_kafka_host *kafka_host = kh;

  p_kafka_init_host(kafka_host, config.nfacctd_kafka_config_file);
  p_kafka_connect_to_consume(kafka_host);
  p_kafka_set_broker(kafka_host, config.nfacctd_kafka_broker_host, config.nfacctd_kafka_broker_port);
  p_kafka_set_topic(kafka_host, config.nfacctd_kafka_topic);
  p_kafka_set_content_type(kafka_host, PM_KAFKA_CNT_TYPE_BIN);
  p_kafka_manage_consumer(kafka_host, TRUE);
}
#endif

#ifdef WITH_ZMQ
void SF_init_zmq_host(void *zh, int *pipe_fd)
{
  struct p_zmq_host *zmq_host = zh;
  char log_id[SHORTBUFLEN];

  p_zmq_init_pull(zmq_host);

  snprintf(log_id, sizeof(log_id), "%s/%s", config.name, config.type);
  p_zmq_set_log_id(zmq_host, log_id);

  p_zmq_set_address(zmq_host, config.nfacctd_zmq_address);
  p_zmq_set_hwm(zmq_host, PM_ZMQ_DEFAULT_FLOW_HWM);
  p_zmq_pull_setup(zmq_host);
  p_zmq_set_retry_timeout(zmq_host, PM_ZMQ_DEFAULT_RETRY);

  if (pipe_fd) (*pipe_fd) = p_zmq_get_fd(zmq_host);
}
#endif
