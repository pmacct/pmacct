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
#include "addr.h"
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif
#include "nfacctd.h"
#include "pretag_handlers.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "ip_flow.h"
#include "ip_frag.h"
#include "classifier.h"
#include "net_aggr.h"
#include "bgp/bgp_packet.h"
#include "bgp/bgp.h"
#include "isis/isis.h"
#include "bmp/bmp.h"
#include "telemetry/telemetry.h"
#if defined (WITH_NDPI)
#include "ndpi/ndpi.h"
#endif
#include "tee_plugin/tee_plugin.h"

/* Global variables */
struct template_cache tpl_cache;
struct host_addr debug_a;
char debug_agent_addr[50];
u_int16_t debug_agent_port;

/* Functions */
void usage_daemon(char *prog_name)
{
  printf("%s %s (%s)\n", NFACCTD_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
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
  unsigned char *netflow_packet;
  unsigned char *netflow_templates_packet;
  int logf, rc = 0, yes=1, allowed;
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
  int ret;
  int capture_methods = 0;

  struct sockaddr_storage server, server_templates;
  struct sockaddr_storage client;
  struct ipv6_mreq multi_req6;
  struct tee_receiver tee_templates;
  socklen_t clen = sizeof(client), slen = 0;
  struct ip_mreq multi_req4;
  int templates_sock = 0;

#ifdef WITH_GNUTLS
  struct sockaddr_storage server_dtls;
  int dtls_sock = 0;
#endif 

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
  extern int optind, opterr, optopt;
  int errflag, cp; 

  /* select() stuff */
  fd_set read_descs, bkp_read_descs;
  int select_fd, bkp_select_fd, num_descs;

#ifdef WITH_REDIS
  struct p_redis_host redis_host;
#endif

#if defined HAVE_MALLOPT
  mallopt(M_CHECK_ACTION, 0);
#endif

  umask(077);
  NF_compute_once();

  /* a bunch of default definitions */ 
  reload_map = FALSE;
  print_stats = FALSE;
  reload_geoipv2_file = FALSE;
  sampling_map_allocated = FALSE;
  bpas_map_allocated = FALSE;
  blp_map_allocated = FALSE;
  bmed_map_allocated = FALSE;
  biss_map_allocated = FALSE;
  bta_map_allocated = FALSE;
  bitr_map_allocated = FALSE;
  custom_primitives_allocated = FALSE;
  bta_map_caching = TRUE;
  sampling_map_caching = TRUE;
  find_id_func = NF_find_id;
  plugins_list = NULL;

  netflow_packet = malloc(NETFLOW_MSG_SIZE);
  netflow_templates_packet = malloc(NETFLOW_MSG_SIZE);

  data_plugins = 0;
  tee_plugins = 0;
  errflag = 0;

  memset(cfg_cmdline, 0, sizeof(cfg_cmdline));
  memset(&server, 0, sizeof(server));
  memset(&client, 0, sizeof(client));
  memset(&config, 0, sizeof(struct configuration));
  memset(&config_file, 0, sizeof(config_file));
  memset(&failed_plugins, 0, sizeof(failed_plugins));
  memset(&pptrs, 0, sizeof(pptrs));
  memset(&req, 0, sizeof(req));
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

#ifdef WITH_GNUTLS
  memset(&dtls_status_table, 0, sizeof(dtls_status_table));
#endif

  log_notifications_init(&log_notifications);
  config.acct_type = ACCT_NF;
  config.progname = nfacctd_globstr;

  rows = 0;
  memset(&device, 0, sizeof(device));

  memset(&recv_pptrs, 0, sizeof(recv_pptrs));
  memset(&recv_pkthdr, 0, sizeof(recv_pkthdr));

  select_fd = 0;
  bkp_select_fd = 0;
  num_descs = 0;
  FD_ZERO(&read_descs);
  FD_ZERO(&bkp_read_descs);

  /* getting commandline values */
  while (!errflag && ((cp = getopt(argc, argv, ARGS_NFACCTD)) != -1)) {
    if (!cfg_cmdline[rows]) cfg_cmdline[rows] = malloc(SRVBUFLEN);
    memset(cfg_cmdline[rows], 0, SRVBUFLEN);
    switch (cp) {
    case 'L':
      strlcpy(cfg_cmdline[rows], "nfacctd_ip: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'l':
      strlcpy(cfg_cmdline[rows], "nfacctd_port: ", SRVBUFLEN);
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
      version_daemon(config.acct_type, NFACCTD_USAGE_HEADER);
      exit(0);
      break;
    case 'a':
      print_primitives(config.acct_type, NFACCTD_USAGE_HEADER);
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
  while (list) {
    list->cfg.acct_type = ACCT_NF;
    list->cfg.progname = nfacctd_globstr;
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

  Log(LOG_INFO, "INFO ( %s/core ): %s %s (%s)\n", config.name, NFACCTD_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
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
	Log(LOG_ERR, "ERROR ( %s/core ): 'nfprobe' and 'sfprobe' plugins not supported in 'nfacctd'.\n", config.name);
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
			COUNT_VXLAN))
	  list->cfg.data_type |= PIPE_TYPE_TUN;

	if (list->cfg.what_to_count_2 & (COUNT_LABEL))
	  list->cfg.data_type |= PIPE_TYPE_VLEN;

        if (list->cfg.what_to_count & (COUNT_SRC_PORT|COUNT_DST_PORT|COUNT_SUM_PORT|COUNT_TCPFLAGS)) {
          enable_ip_fragment_handler();
	}

	evaluate_sums(&list->cfg.what_to_count, &list->cfg.what_to_count_2, list->name, list->type.string);
	if (!list->cfg.what_to_count && !list->cfg.what_to_count_2 && !list->cfg.cpptrs.num) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): defaulting to SRC HOST aggregation.\n", list->name, list->type.string);
	  list->cfg.what_to_count |= COUNT_SRC_HOST;
	}
	if (list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) {
	  if (!list->cfg.networks_file && list->cfg.nfacctd_as & NF_AS_NEW) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation selected but NO 'networks_file' specified. Exiting.\n\n", list->name, list->type.string);
	    exit_gracefully(1);
	  }
          if (!list->cfg.bgp_daemon && !list->cfg.bmp_daemon && list->cfg.nfacctd_as == NF_AS_BGP) {
            Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation selected but 'bgp_daemon' or 'bmp_daemon' is not enabled. Exiting.\n\n", list->name, list->type.string);
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
	      Log(LOG_ERR, "ERROR ( %s/%s ): network aggregation selected but none of 'bgp_daemon', 'bmp_daemon', 'isis_daemon', 'networks_file', 'networks_mask' is specified. Exiting.\n\n", list->name, list->type.string);
	      exit_gracefully(1);
	    }
            if (list->cfg.nfacctd_net & NF_NET_FALLBACK && list->cfg.networks_file)
              list->cfg.nfacctd_net |= NF_NET_NEW;
	  }
	}

#if defined (WITH_NDPI)
        if (list->cfg.what_to_count_2 & COUNT_NDPI_CLASS) {
	  enable_ip_fragment_handler();
          config.classifier_ndpi = TRUE;
        }

        if ((list->cfg.what_to_count & COUNT_CLASS) && (list->cfg.what_to_count_2 & COUNT_NDPI_CLASS)) {
          Log(LOG_ERR, "ERROR ( %s/%s ): 'class_legacy' and 'class' primitives are mutual exclusive. Exiting.\n\n", list->name, list->type.string);
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
    Log(LOG_ERR, "ERROR ( %s/core ): 'tee' plugins are not compatible with data (memory/mysql/pgsql/etc.) plugins. Exiting.\n\n", config.name);
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
    Log(LOG_ERR, "ERROR ( %s/core ): pcap_savefile, nfacctd_ip, nfacctd_kafka_* and nfacctd_zmq_* are mutual exclusive. Exiting.\n\n", config.name);
    exit_gracefully(1);
  }

  if (config.nfacctd_templates_receiver) {
    if (!config.nfacctd_port && !config.nfacctd_ip && capture_methods) {
      Log(LOG_ERR, "ERROR ( %s/core ): nfacctd_templates_receiver only applies to live UDP collection (nfacctd_ip, nfacctd_port). Exiting.\n\n", config.name);
      exit_gracefully(1);
    }

    if (tee_plugins) {
      Log(LOG_ERR, "ERROR ( %s/core ): nfacctd_templates_receiver and tee plugin ae mutual exclusive. Exiting.\n\n", config.name);
      exit_gracefully(1);
    }
  }

#ifdef WITH_KAFKA
  if ((config.nfacctd_kafka_broker_host && !config.nfacctd_kafka_topic) || (config.nfacctd_kafka_topic && !config.nfacctd_kafka_broker_host)) {
    Log(LOG_ERR, "ERROR ( %s/core ): Kafka collection requires both nfacctd_kafka_broker_host and nfacctd_kafka_topic to be specified. Exiting.\n\n", config.name);
    exit_gracefully(1);
  }

  if (config.nfacctd_kafka_broker_host && tee_plugins) {
    Log(LOG_ERR, "ERROR ( %s/core ): Kafka collection is mutual exclusive with 'tee' plugins. Exiting.\n\n", config.name);
    exit_gracefully(1);
  }
#endif

#ifdef WITH_ZMQ
  if (config.nfacctd_zmq_address && tee_plugins) {
    Log(LOG_ERR, "ERROR ( %s/core ): ZeroMQ collection is mutual exclusive with 'tee' plugins. Exiting.\n\n", config.name);
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

#ifdef WITH_GNUTLS
  if (config.nfacctd_dtls_port && !config.dtls_path) {
    Log(LOG_ERR, "ERROR ( %s/core ): 'nfacctd_dtls_port' specified but missing 'dtls_path'. Exiting.\n", config.name);
    exit_gracefully(1);
  }

  if (config.dtls_path) {
    pm_dtls_init(&config.dtls_globs, config.dtls_path);
  }
#endif

  if (config.pcap_savefile) {
    open_pcap_savefile(&device, config.pcap_savefile);
    pm_pcap_savefile_round = 1;

    enable_ip_fragment_handler();
  }
#ifdef WITH_KAFKA
  else if (config.nfacctd_kafka_broker_host) {
    NF_init_kafka_host(&nfacctd_kafka_host);
    recv_pptrs.pkthdr = &recv_pkthdr;

    enable_ip_fragment_handler();
  }
#endif

#ifdef WITH_ZMQ
  else if (config.nfacctd_zmq_address) {
    int pipe_fd = 0;
    NF_init_zmq_host(&nfacctd_zmq_host, &pipe_fd);
    recv_pptrs.pkthdr = &recv_pkthdr;

    enable_ip_fragment_handler();
  }
#endif
  else {
    /* If no IP address is supplied, let's set our default
       behaviour: IPv4 address, INADDR_ANY, port 2100 */
    if (!config.nfacctd_port) config.nfacctd_port = DEFAULT_NFACCTD_PORT;
    collector_port = config.nfacctd_port;

    if (!config.nfacctd_ip) {
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

      sa6->sin6_family = AF_INET6;
      sa6->sin6_port = htons(config.nfacctd_port);
      slen = sizeof(struct sockaddr_in6);

      if (config.nfacctd_templates_port) {
	sa6 = (struct sockaddr_in6 *)&server_templates; 

	sa6->sin6_family = AF_INET6;
	sa6->sin6_port = htons(config.nfacctd_templates_port);
      }

#ifdef WITH_GNUTLS
      if (config.nfacctd_dtls_port) {
	sa6 = (struct sockaddr_in6 *)&server_dtls; 

	sa6->sin6_family = AF_INET6;
	sa6->sin6_port = htons(config.nfacctd_dtls_port);
      }
#endif
    }
    else {
      trim_spaces(config.nfacctd_ip);
      ret = str_to_addr(config.nfacctd_ip, &addr);
      if (!ret) {
	Log(LOG_ERR, "ERROR ( %s/core ): 'nfacctd_ip' value is not valid. Exiting.\n", config.name);
	exit_gracefully(1);
      }
      slen = addr_to_sa((struct sockaddr *)&server, &addr, config.nfacctd_port);

      if (config.nfacctd_templates_port) {
        addr_to_sa((struct sockaddr *)&server_templates, &addr, config.nfacctd_templates_port);
      }

#ifdef WITH_GNUTLS
      if (config.nfacctd_dtls_port) {
        addr_to_sa((struct sockaddr *)&server_dtls, &addr, config.nfacctd_dtls_port);
      }
#endif
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

    if (config.nfacctd_templates_port) {
      config.nfacctd_templates_sock = socket(((struct sockaddr *)&server_templates)->sa_family, SOCK_DGRAM, 0);
      if (config.nfacctd_templates_sock < 0) {
	/* retry with IPv4 */
	if (!config.nfacctd_ip) {
	  struct sockaddr_in *sa4 = (struct sockaddr_in *)&server_templates;

	  sa4->sin_family = AF_INET;
	  sa4->sin_addr.s_addr = htonl(0);
	  sa4->sin_port = htons(config.nfacctd_templates_port);
	  slen = sizeof(struct sockaddr_in);

	  config.nfacctd_templates_sock = socket(((struct sockaddr *)&server_templates)->sa_family, SOCK_DGRAM, 0);
	}

	if (config.nfacctd_templates_sock < 0) {
	  Log(LOG_ERR, "ERROR ( %s/core ): TPLS socket() failed.\n", config.name);
	  exit_gracefully(1);
	}
      }
    }

#ifdef WITH_GNUTLS
    if (config.nfacctd_dtls_port) {
      config.nfacctd_dtls_sock = socket(((struct sockaddr *)&server_dtls)->sa_family, SOCK_DGRAM, 0);
      if (config.nfacctd_dtls_sock < 0) {
	/* retry with IPv4 */
	if (!config.nfacctd_ip) {
	  struct sockaddr_in *sa4 = (struct sockaddr_in *)&server_dtls;

	  sa4->sin_family = AF_INET;
	  sa4->sin_addr.s_addr = htonl(0);
	  sa4->sin_port = htons(config.nfacctd_dtls_port);
	  slen = sizeof(struct sockaddr_in);

	  config.nfacctd_dtls_sock = socket(((struct sockaddr *)&server_dtls)->sa_family, SOCK_DGRAM, 0);
	}

	if (config.nfacctd_dtls_sock < 0) {
	  Log(LOG_ERR, "ERROR ( %s/core ): DTLS socket() failed.\n", config.name);
	  exit_gracefully(1);
	}
      }
    }
#endif

    if (config.nfacctd_templates_port || config.nfacctd_dtls_port) {
      FD_SET(config.sock, &bkp_read_descs);
      bkp_select_fd = config.sock;

      if (config.nfacctd_templates_sock) {
        FD_SET(config.nfacctd_templates_sock, &bkp_read_descs);
        bkp_select_fd = (bkp_select_fd < config.nfacctd_templates_sock) ? config.nfacctd_templates_sock : bkp_select_fd;
      }

#ifdef WITH_GNUTLS
      if (config.nfacctd_dtls_sock) {
        FD_SET(config.nfacctd_dtls_sock, &bkp_read_descs);
        bkp_select_fd = (bkp_select_fd < config.nfacctd_dtls_sock) ? config.nfacctd_dtls_sock : bkp_select_fd;
      }
#endif

      bkp_select_fd++;
    }

    /* bind socket to port */
#if (defined HAVE_SO_REUSEPORT)
    rc = setsockopt(config.sock, SOL_SOCKET, SO_REUSEPORT, (char *) &yes, (socklen_t) sizeof(yes));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for SO_REUSEPORT.\n", config.name);
#endif

    rc = setsockopt(config.sock, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, (socklen_t) sizeof(yes));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for SO_REUSEADDR.\n", config.name);

    if (config.nfacctd_templates_port) {
#if (defined HAVE_SO_REUSEPORT)
      rc = setsockopt(config.nfacctd_templates_sock, SOL_SOCKET, SO_REUSEPORT, (char *) &yes, (socklen_t) sizeof(yes));
      if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for SO_REUSEPORT.\n", config.name);
#endif

      rc = setsockopt(config.nfacctd_templates_sock, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, (socklen_t) sizeof(yes));
      if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for SO_REUSEADDR.\n", config.name);
    }

#ifdef WITH_GNUTLS
    if (config.nfacctd_dtls_port) {
#if (defined HAVE_SO_REUSEPORT)
      rc = setsockopt(config.nfacctd_dtls_sock, SOL_SOCKET, SO_REUSEPORT, (char *) &yes, (socklen_t) sizeof(yes));
      if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for SO_REUSEPORT.\n", config.name);
#endif

      rc = setsockopt(config.nfacctd_dtls_sock, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, (socklen_t) sizeof(yes));
      if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for SO_REUSEADDR.\n", config.name);
    }
#endif

    if (config.nfacctd_ipv6_only) {
      int yes=1;

      rc = setsockopt(config.sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &yes, (socklen_t) sizeof(yes));
      if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for IPV6_V6ONLY.\n", config.name);
    }

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
      Log(LOG_INFO, "INFO ( %s/core ): nfacctd_pipe_size: obtained=%d target=%d.\n", config.name, obtained, config.nfacctd_pipe_size);
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

    memset(&tee_templates, 0, sizeof(struct tee_receiver));

    if (config.nfacctd_templates_receiver) {
      tee_templates.dest_len = sizeof(tee_templates.dest);

      ret = Tee_parse_hostport(config.nfacctd_templates_receiver, (struct sockaddr *) &tee_templates.dest, &tee_templates.dest_len, FALSE);
      if (ret) {
	Log(LOG_ERR, "ERROR ( %s/core ): Invalid receiver: %s.\n", config.name, config.nfacctd_templates_receiver);
	exit_gracefully(1);
      }

      tee_templates.fd = Tee_prepare_sock((struct sockaddr *) &tee_templates.dest, tee_templates.dest_len, NULL, FALSE, TRUE, FALSE);
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

  /* starting the telemetry thread */
  if (config.telemetry_daemon) {
    telemetry_wrapper();

    /* Let's give the telemetry thread some advantage to create its structures */
    sleep(DEFAULT_SLOTH_SLEEP_TIME);
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

  if (!config.pcap_savefile && !config.nfacctd_kafka_broker_host && !config.nfacctd_zmq_address) {
    rc = bind(config.sock, (struct sockaddr *) &server, slen);
    if (rc < 0) {
      Log(LOG_ERR, "ERROR ( %s/core ): bind() to ip=%s port=%d/udp failed (errno: %d).\n", config.name, config.nfacctd_ip, config.nfacctd_port, errno);
      exit_gracefully(1);
    }

    if (config.nfacctd_templates_port) {
      rc = bind(config.nfacctd_templates_sock, (struct sockaddr *) &server_templates, slen);
      if (rc < 0) {
	Log(LOG_ERR, "ERROR ( %s/core ): bind() to ip=%s port=%d/udp failed (errno: %d).\n", config.name, config.nfacctd_ip, config.nfacctd_templates_port, errno);
	exit_gracefully(1);
      }
    }

#ifdef WITH_GNUTLS
    if (config.nfacctd_dtls_port) {
      rc = bind(config.nfacctd_dtls_sock, (struct sockaddr *) &server_dtls, slen);
      if (rc < 0) {
        Log(LOG_ERR, "ERROR ( %s/core ): bind() to ip=%s port=%d/udp failed (errno: %d).\n", config.name, config.nfacctd_ip, config.nfacctd_dtls_port, errno);
        exit_gracefully(1);
      }
    }
#endif
  }

  init_classifiers(NULL);

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

  /* initializing template cache */ 
  memset(&tpl_cache, 0, sizeof(tpl_cache));
  tpl_cache.num = TEMPLATE_CACHE_ENTRIES;

  if (config.nfacctd_templates_file) {
    load_templates_from_file(config.nfacctd_templates_file);
  }

  /* arranging static pointers to dummy packet; to speed up things into the
     main loop we mantain two packet_ptrs structures when IPv6 is enabled:
     we will sync here 'pptrs6' for common tables and pointers */
  memset(dummy_packet, 0, sizeof(dummy_packet));
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
  pptrs.vlanmpls6.l3_proto = ETHERTYPE_IPV6;

  if (config.pcap_savefile) {
    Log(LOG_INFO, "INFO ( %s/core ): reading NetFlow/IPFIX data from: %s\n", config.name, config.pcap_savefile);
    allowed = TRUE;

    if (!config.pcap_sf_delay) sleep(2);
    else sleep(config.pcap_sf_delay);
  }
#ifdef WITH_KAFKA
  else if (config.nfacctd_kafka_broker_host) {
    Log(LOG_INFO, "INFO ( %s/core ): reading NetFlow/IPFIX data from Kafka %s:%s\n", config.name,
        p_kafka_get_broker(&nfacctd_kafka_host), p_kafka_get_topic(&nfacctd_kafka_host));
    allowed = TRUE;
  }
#endif
#ifdef WITH_ZMQ
  else if (config.nfacctd_zmq_address) {
    Log(LOG_INFO, "INFO ( %s/core ): reading NetFlow/IPFIX data from ZeroMQ %s\n", config.name,
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
    Log(LOG_INFO, "INFO ( %s/core ): waiting for NetFlow/IPFIX data on %s:%u\n", config.name, srv_string, srv_port);
    allowed = TRUE;

    if (config.nfacctd_templates_port) {
      sa_to_addr((struct sockaddr *)&server_templates, &srv_addr, &srv_port); 
      addr_to_str(srv_string, &srv_addr);
      Log(LOG_INFO, "INFO ( %s/core ): waiting for NetFlow/IPFIX templates on %s:%u\n", config.name, srv_string, srv_port);
    }

#if WITH_GNUTLS
    if (config.nfacctd_dtls_port) {
      sa_to_addr((struct sockaddr *)&server_dtls, &srv_addr, &srv_port); 
      addr_to_str(srv_string, &srv_addr);
      Log(LOG_INFO, "INFO ( %s/core ): waiting for DTLS NetFlow/IPFIX on %s:%u\n", config.name, srv_string, srv_port);
    }
#endif
  }

#ifdef WITH_REDIS
  if (config.redis_host) {
    char log_id[SHORTBUFLEN];

    snprintf(log_id, sizeof(log_id), "%s/%s", config.name, config.type);
    p_redis_init(&redis_host, log_id, p_redis_thread_produce_common_core_handler); 
  }
#endif

  /* fixing NetFlow v9/IPFIX template func pointers */
  get_ext_db_ie_by_type = &ext_db_get_ie;

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
      ret = recvfrom_savefile(&device, (void **) &netflow_packet, (struct sockaddr *) &client, NULL, &pm_pcap_savefile_round, &recv_pptrs);
    }
#ifdef WITH_KAFKA
    else if (config.nfacctd_kafka_broker_host) {
      int kafka_reconnect = FALSE;
      void *kafka_msg = NULL;

      ret = p_kafka_consume_poller(&nfacctd_kafka_host, &kafka_msg, 1000);

      switch (ret) {
      case TRUE: /* got data */
        ret = p_kafka_consume_data(&nfacctd_kafka_host, kafka_msg, netflow_packet, NETFLOW_MSG_SIZE);
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
	NF_init_kafka_host(&nfacctd_kafka_host);

	continue;
      }

      ret = recvfrom_rawip(netflow_packet, ret, (struct sockaddr *) &client, &recv_pptrs);
    }
#endif
#ifdef WITH_ZMQ
    else if (config.nfacctd_zmq_address) {
      ret = p_zmq_recv_poll(&nfacctd_zmq_host.sock, 1000);

      switch (ret) {
      case TRUE: /* got data */
        ret = p_zmq_recv_bin(&nfacctd_zmq_host.sock, netflow_packet, NETFLOW_MSG_SIZE);
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

      ret = recvfrom_rawip(netflow_packet, ret, (struct sockaddr *) &client, &recv_pptrs);
    }
#endif
    else {
      if (!config.nfacctd_templates_port && !config.nfacctd_dtls_port) {
        ret = recvfrom(config.sock, (unsigned char *)netflow_packet, NETFLOW_MSG_SIZE, 0, (struct sockaddr *) &client, &clen);
      }
      else {
	select_func_again: 
	select_fd = bkp_select_fd;
	memcpy(&read_descs, &bkp_read_descs, sizeof(bkp_read_descs));

	num_descs = select(select_fd, &read_descs, NULL, NULL, NULL);

	select_read_again:
	if (num_descs > 0) {
	  if (FD_ISSET(config.sock, &read_descs)) {
            ret = recvfrom(config.sock, (unsigned char *)netflow_packet, NETFLOW_MSG_SIZE, 0, (struct sockaddr *) &client, &clen);
	    FD_CLR(config.sock, &read_descs);
	    num_descs--;

	    templates_sock = FALSE;
#ifdef WITH_GNUTLS
	    dtls_sock = FALSE;
#endif
	    collector_port = config.nfacctd_port;
	  }
	  else if (FD_ISSET(config.nfacctd_templates_sock, &read_descs)) {
	    ret = recvfrom(config.nfacctd_templates_sock, (unsigned char *)netflow_packet, NETFLOW_MSG_SIZE, 0, (struct sockaddr *) &client, &clen);
	    FD_CLR(config.nfacctd_templates_sock, &read_descs);
	    num_descs--;

	    templates_sock = TRUE;
#ifdef WITH_GNUTLS
	    dtls_sock = FALSE;
#endif
	    collector_port = config.nfacctd_templates_port;
	  }
#ifdef WITH_GNUTLS
	  else if (FD_ISSET(config.nfacctd_dtls_sock, &read_descs)) {
	    /* Peek only here since gnutls wants to consume on its own */
	    ret = recvfrom(config.nfacctd_dtls_sock, (unsigned char *)netflow_packet, NETFLOW_MSG_SIZE, MSG_PEEK, (struct sockaddr *) &client, &clen);
	    FD_CLR(config.nfacctd_dtls_sock, &read_descs);
	    num_descs--;

	    templates_sock = FALSE;
	    dtls_sock = TRUE;
	    collector_port = config.nfacctd_dtls_port;
	  }
#endif
	}
	else goto select_func_again;
      }
    }

    /* we have no data or not not enough data to decode the version */
    if (!netflow_packet || ret < 2) continue;
    pptrs.v4.f_len = ret;

    ipv4_mapped_to_ipv4(&client);

    /* check if Hosts Allow Table is loaded; if it is, we will enforce rules */
    if (allow.num) allowed = check_allow(&allow, (struct sockaddr *)&client); 
    if (!allowed) continue;

    if (reload_map) {
      bta_map_caching = TRUE;
      sampling_map_caching = TRUE;
      req.key_value_table = NULL;

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

    if (print_stats) {
      time_t now = time(NULL);

      print_status_table(&xflow_status_table, now, XFLOW_STATUS_TABLE_SZ);
      print_stats = FALSE;
    }

#ifdef WITH_GNUTLS
    if (dtls_sock) {
      ret = pm_dtls_server_process(config.nfacctd_dtls_sock, &client, clen, netflow_packet, ret, &dtls_status_table);

      if (!ret) {
	continue;
      }
    }
#endif

    if (data_plugins) {
      int has_templates = 0;
      u_int16_t nfv;

      /* We will change byte ordering in order to avoid a bunch of ntohs() calls */
      nfv = ((struct struct_header_v5 *)netflow_packet)->version = ntohs(((struct struct_header_v5 *)netflow_packet)->version);

      reset_tag_label_status(&pptrs);
      reset_shadow_status(&pptrs);

      switch (nfv) {
      case 5:
	process_v5_packet(netflow_packet, ret, &pptrs.v4, &req, nfv, NULL); 
	break;
      /* NetFlow v9 + IPFIX */
      case 9:
      case 10:
	process_v9_packet(netflow_packet, ret, &pptrs, &req, nfv, NULL, &has_templates);

	/* Let's replicate templates only if not received on
	   nfacctd_templates_port in order to prevent infinite
	   looping */
	if (config.nfacctd_templates_receiver && has_templates && !templates_sock) {
	  int netflow_templates_len = 0;
	  struct pkt_msg tee_msg;

	  memset(&tee_msg, 0, sizeof(tee_msg));
	  memcpy(&tee_msg.agent, &client, sizeof(client));

	  /* fix version before sending */
	  ((struct struct_header_v5 *)netflow_packet)->version = ntohs(((struct struct_header_v5 *)netflow_packet)->version);

	  Tee_select_templates(netflow_packet, ret, nfv, netflow_templates_packet, &netflow_templates_len); 

	  tee_msg.payload = netflow_templates_packet;
	  tee_msg.len = netflow_templates_len;

	  if (tee_msg.len) {
	    Tee_send(&tee_msg, (struct sockaddr *) &tee_templates.dest, tee_templates.fd, TRUE);
	  }
	}

	break;
      default:
        if (!config.nfacctd_disable_checks) {
	  notify_malf_packet(LOG_INFO, "INFO", "discarding unknown packet", (struct sockaddr *) pptrs.v4.f_agent, 0);
	  xflow_status_table.tot_bad_datagrams++;
        }
	break;
      }
    }
    else if (tee_plugins) {
      if (req.ptm_c.exec_ptm_dissect) {
	reset_tag_label_status(&pptrs);

	/* We will change byte ordering in order to avoid a bunch of ntohs() calls */
	((struct struct_header_v5 *)netflow_packet)->version = ntohs(((struct struct_header_v5 *)netflow_packet)->version);
      }

      process_raw_packet(netflow_packet, ret, &pptrs, &req);
    }

    if (num_descs > 0) goto select_read_again;

    sigprocmask(SIG_UNBLOCK, &signal_set, NULL);
  }
}

void process_v5_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs *pptrs,
		struct plugin_requests *req, u_int16_t version, struct NF_dissect *tee_dissect)
{
  struct struct_header_v5 *hdr_v5 = (struct struct_header_v5 *)pkt;
  struct struct_export_v5 *exp_v5;
  unsigned short int count = ntohs(hdr_v5->count);

  if (len < NfHdrV5Sz) {
    notify_malf_packet(LOG_INFO, "INFO", "discarding short NetFlow v5 packet", (struct sockaddr *) pptrs->f_agent, 0);
    xflow_status_table.tot_bad_datagrams++;
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV5Sz; 
  exp_v5 = (struct struct_export_v5 *)pkt;
  pptrs->f_status = (u_char *) nfv5_check_status(pptrs);
  pptrs->f_status_g = NULL;

  reset_mac(pptrs);
  pptrs->flow_type.traffic_type = PM_FTYPE_TRAFFIC;

  if (tee_dissect) {
    tee_dissect->hdrVersion = version;
    tee_dissect->hdrCount = 1;
    tee_dissect->hdrBasePtr = (u_char *) hdr_v5;
    tee_dissect->hdrEndPtr = (u_char *) (hdr_v5 + NfHdrV5Sz);
    tee_dissect->hdrLen = NfHdrV5Sz;

    /* no flowset in NetFlow v5 */
    tee_dissect->flowSetBasePtr = NULL;
    tee_dissect->flowSetEndPtr = NULL;
    tee_dissect->flowSetLen = 0;
  }

  if ((count <= V5_MAXFLOWS) && ((count*NfDataV5Sz)+NfHdrV5Sz == len)) {
    if (config.debug) {
      sa_to_addr((struct sockaddr *)pptrs->f_agent, &debug_a, &debug_agent_port);
      addr_to_str(debug_agent_addr, &debug_a);

      Log(LOG_DEBUG, "DEBUG ( %s/core ): Received NetFlow packet from [%s:%u] version [%u] seqno [%u]\n",
	  config.name, debug_agent_addr, debug_agent_port, version, ntohl(hdr_v5->flow_sequence));
    }

    while (count) {
      reset_net_status(pptrs);
      pptrs->f_data = (unsigned char *) exp_v5;

      if (tee_dissect) {
	tee_dissect->elemBasePtr = pptrs->f_data;
	tee_dissect->elemEndPtr = (u_char *) (pptrs->f_data + NfDataV5Sz);
	tee_dissect->elemLen = NfDataV5Sz;
	pptrs->tee_dissect_bcast = FALSE;

	exec_plugins(pptrs, req);

	goto finalize_record;
      }

      if (req->bpf_filter) {
        Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp_v5->srcaddr.s_addr);
        Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp_v5->dstaddr.s_addr);
        Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_p, exp_v5->prot);
        Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, exp_v5->tos);
        Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->src_port, exp_v5->srcport);
        Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->dst_port, exp_v5->dstport);
	Assign8(((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags, exp_v5->tcp_flags);
      }

      pptrs->lm_mask_src = exp_v5->src_mask;
      pptrs->lm_mask_dst = exp_v5->dst_mask;
      pptrs->lm_method_src = NF_NET_KEEP;
      pptrs->lm_method_dst = NF_NET_KEEP;

      /* Let's copy some relevant field */
      pptrs->l4_proto = exp_v5->prot;

      /* IP header's id field is unused; we will use it to transport our id */ 
      if (config.nfacctd_isis) isis_srcdst_lookup(pptrs);
      if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, pptrs, &pptrs->bta, &pptrs->bta2);
      if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, pptrs, &pptrs->bitr, NULL);
      if (config.bgp_daemon) bgp_srcdst_lookup(pptrs, FUNC_TYPE_BGP);
      if (config.bgp_daemon_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, pptrs, &pptrs->bpas, NULL);
      if (config.bgp_daemon_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, pptrs, &pptrs->blp, NULL);
      if (config.bgp_daemon_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, pptrs, &pptrs->bmed, NULL);
      if (config.bmp_daemon) bmp_srcdst_lookup(pptrs);
      exec_plugins(pptrs, req);

      finalize_record:
      exp_v5++;
      count--;
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO", "discarding malformed NetFlow v5 packet", (struct sockaddr *) pptrs->f_agent, 0);
    xflow_status_table.tot_bad_datagrams++;
    return;
  }
} 

void process_v9_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs_vector *pptrsv,
		struct plugin_requests *req, u_int16_t version, struct NF_dissect *tee_dissect,
		int *has_templates)
{
  struct struct_header_v9 *hdr_v9 = (struct struct_header_v9 *)pkt;
  struct struct_header_ipfix *hdr_v10 = (struct struct_header_ipfix *)pkt;
  struct template_hdr_v9 *template_hdr = NULL;
  struct options_template_hdr_v9 *opt_template_hdr = NULL;
  struct template_cache_entry *tpl = NULL;
  struct data_hdr_v9 *data_hdr = NULL;
  struct packet_ptrs *pptrs = &pptrsv->v4;
  u_int16_t fid, off = 0, flowoff = 0, flowsetlen = 0, flowsetNo = 0;
  u_int16_t flowsetCount = 0, direction = 0, FlowSeqInc = 0; 
  u_int32_t HdrSz = 0, SourceId = 0, FlowSeq = 0;
  u_char *dummy_packet_ptr = NULL;
  int ret;

  if (version == 9) {
    HdrSz = NfHdrV9Sz; 
    if (len >= HdrSz) {
      SourceId = ntohl(hdr_v9->source_id);
      FlowSeq = ntohl(hdr_v9->flow_sequence);
      flowsetNo = htons(hdr_v9->count);
      flowsetCount = 0;
    }
  }
  else if (version == 10) {
    HdrSz = IpFixHdrSz; 
    if (len >= HdrSz) {
      SourceId = ntohl(hdr_v10->source_id);
      FlowSeq = ntohl(hdr_v10->flow_sequence);
    }
    flowsetNo = 0;
    flowsetCount = 0;
  }

  if (tee_dissect) {
    tee_dissect->hdrVersion = version;
    if (version == 9) tee_dissect->hdrCount = flowsetNo; /* imprecise .. */
    else if (version == 10) tee_dissect->hdrCount = 0;
    tee_dissect->hdrBasePtr = pkt;
    tee_dissect->hdrEndPtr = (u_char *) (pkt + HdrSz); 
    tee_dissect->hdrLen = HdrSz;
  }

  if (config.debug) {
    sa_to_addr((struct sockaddr *)pptrs->f_agent, &debug_a, &debug_agent_port);
    addr_to_str(debug_agent_addr, &debug_a);

    Log(LOG_DEBUG, "DEBUG ( %s/core ): Received NetFlow/IPFIX packet from [%s:%u] version [%u] seqno [%u]\n",
			config.name, debug_agent_addr, debug_agent_port, version, FlowSeq);
  }

  if (len < HdrSz) {
    notify_malf_packet(LOG_INFO, "INFO", "discarding short NetFlow v9/IPFIX packet", (struct sockaddr *) pptrsv->v4.f_agent, 0);
    xflow_status_table.tot_bad_datagrams++;
    return;
  }
  pptrs->f_header = pkt;
  pkt += HdrSz;
  off += HdrSz; 
  pptrsv->v4.f_status = (u_char *) nfv9_check_status(pptrs, SourceId, 0, FlowSeq, TRUE);
  set_vector_f_status(pptrsv);
  pptrsv->v4.f_status_g = (u_char *) nfv9_check_status(pptrs, 0, NF9_OPT_SCOPE_SYSTEM, 0, FALSE);
  set_vector_f_status_g(pptrsv);

  process_flowset:
  if (off+NfDataHdrV9Sz >= len) { 
    notify_malf_packet(LOG_INFO, "INFO", "unable to read next Flowset (incomplete NetFlow v9/IPFIX packet)",
			(struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
    xflow_status_table.tot_bad_datagrams++;
    return;
  }

  data_hdr = (struct data_hdr_v9 *)pkt;

  if (data_hdr->flow_len == 0) {
    notify_malf_packet(LOG_INFO, "INFO", "unable to read next Flowset (NetFlow v9/IPFIX packet claiming flow_len 0!)",
			(struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
    xflow_status_table.tot_bad_datagrams++;
    return;
  }

  fid = ntohs(data_hdr->flow_id);
  flowsetlen = ntohs(data_hdr->flow_len);
  if (flowsetlen < NfDataHdrV9Sz) {
    notify_malf_packet(LOG_INFO, "INFO", "unable to read next Flowset (NetFlow v9/IPFIX packet (flowsetlen < NfDataHdrV9Sz)",
                        (struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
    xflow_status_table.tot_bad_datagrams++;
    return;
  }

  if (tee_dissect) {
    tee_dissect->flowSetBasePtr = pkt;
    tee_dissect->flowSetEndPtr = (u_char *) (pkt + NfDataHdrV9Sz);
    tee_dissect->flowSetLen = NfDataHdrV9Sz; /* updated later */
  }

  if (fid == 0 || fid == 2) { /* template: 0 NetFlow v9, 2 IPFIX */ 
    unsigned char *tpl_ptr = pkt;
    u_int16_t pens = 0;

    if (has_templates) (*has_templates) = TRUE;
    flowoff = 0;
    tpl_ptr += NfDataHdrV9Sz;
    flowoff += NfDataHdrV9Sz;

    /* broadcast the whole flowset over */
    if (tee_dissect) {
      tee_dissect->elemBasePtr = NULL;
      tee_dissect->elemEndPtr = NULL;
      tee_dissect->elemLen = 0;

      tee_dissect->flowSetEndPtr = (u_char *) (tee_dissect->flowSetBasePtr + ntohs(data_hdr->flow_len)); 
      tee_dissect->flowSetLen = ntohs(data_hdr->flow_len); 
      pptrs->tee_dissect_bcast = TRUE;

      exec_plugins(pptrs, req);
    }

    while (flowoff < flowsetlen) {
      u_int32_t tpl_len = 0;

      template_hdr = (struct template_hdr_v9 *) tpl_ptr;
      if (off+flowsetlen > len) { 
        notify_malf_packet(LOG_INFO, "INFO", "unable to read next Template Flowset (incomplete NetFlow v9/IPFIX packet)",
		        (struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
        xflow_status_table.tot_bad_datagrams++;
        return;
      }

      tpl = handle_template(template_hdr, pptrs, fid, SourceId, &pens, flowsetlen-flowoff, FlowSeq);
      if (!tpl) return;

      tpl_len = sizeof(struct template_hdr_v9)+(ntohs(template_hdr->num)*sizeof(struct template_field_v9))+(pens*sizeof(u_int32_t));
      tpl_ptr += tpl_len;
      flowoff += tpl_len;
    }

    pkt += flowsetlen; 
    off += flowsetlen; 
  }
  else if (fid == 1 || fid == 3) { /* options template: 1 NetFlow v9, 3 IPFIX */
    unsigned char *tpl_ptr = pkt;
    u_int16_t pens = 0;

    if (has_templates) (*has_templates) = TRUE;
    flowoff = 0;
    tpl_ptr += NfDataHdrV9Sz;
    flowoff += NfDataHdrV9Sz;

    /* broadcast the whole flowset over */
    if (tee_dissect) { 
      tee_dissect->elemBasePtr = NULL;
      tee_dissect->elemEndPtr = NULL;
      tee_dissect->elemLen = 0;

      tee_dissect->flowSetEndPtr = (u_char *) (tee_dissect->flowSetBasePtr + ntohs(data_hdr->flow_len));
      tee_dissect->flowSetLen = ntohs(data_hdr->flow_len);

      exec_plugins(pptrs, req);
    }

    while (flowoff < flowsetlen) {
      u_int32_t tpl_len = 0;

      opt_template_hdr = (struct options_template_hdr_v9 *) tpl_ptr;
      if (off+flowsetlen > len) {
        notify_malf_packet(LOG_INFO, "INFO", "unable to read next Options Template Flowset (incomplete NetFlow v9/IPFIX packet)",
                        (struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
        xflow_status_table.tot_bad_datagrams++;
        return;
      }

      tpl = handle_template((struct template_hdr_v9 *)opt_template_hdr, pptrs, fid, SourceId, &pens, flowsetlen-flowoff, FlowSeq);
      if (!tpl) return;

      /* Increment is not precise for NetFlow v9 but will work */
      tpl_len = sizeof(struct options_template_hdr_v9) +
		(((ntohs(opt_template_hdr->scope_len) + ntohs(opt_template_hdr->option_len)) * sizeof(struct template_field_v9)) +
		(pens * sizeof(u_int32_t)));

      tpl_ptr += tpl_len;
      flowoff += tpl_len;
    }

    pkt += flowsetlen;
    off += flowsetlen;
  }
  else if (fid >= 256) { /* data */
    if (off+flowsetlen > len) { 
      notify_malf_packet(LOG_INFO, "INFO", "unable to read next Data Flowset (incomplete NetFlow v9/IPFIX packet)",
		      (struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
      xflow_status_table.tot_bad_datagrams++;
      return;
    }

    flowoff = 0;
    pkt += NfDataHdrV9Sz;
    flowoff += NfDataHdrV9Sz;

    tpl = find_template(data_hdr->flow_id, (struct sockaddr *) pptrs->f_agent, fid, SourceId);
    if (!tpl) {
      sa_to_addr((struct sockaddr *)pptrs->f_agent, &debug_a, &debug_agent_port);
      addr_to_str(debug_agent_addr, &debug_a);

      Log(LOG_DEBUG, "DEBUG ( %s/core ): Discarded NetFlow v9/IPFIX packet (R: unknown template %u [%s:%u])\n",
		config.name, fid, debug_agent_addr, SourceId);
      pkt += (flowsetlen-NfDataHdrV9Sz);
      off += flowsetlen;
    }
    else if (tpl->template_type == 1) { /* Options coming */
      struct xflow_status_entry *entry;
      struct xflow_status_entry_sampling *sentry, *ssaved;
      struct xflow_status_entry_class *centry, *csaved;

      /* broadcast the whole flowset over */
      if (tee_dissect) {
        tee_dissect->elemBasePtr = NULL;
        tee_dissect->elemEndPtr = NULL;
        tee_dissect->elemLen = 0;

	tee_dissect->flowSetEndPtr = (u_char *) (tee_dissect->flowSetBasePtr + ntohs(data_hdr->flow_len));
	tee_dissect->flowSetLen = ntohs(data_hdr->flow_len);
        pptrs->tee_dissect_bcast = TRUE;

	exec_plugins(pptrs, req);
	/* goto finalize_opt_record later */
      }

      while (flowoff+tpl->len <= flowsetlen) {
	entry = (struct xflow_status_entry *) pptrs->f_status;
	sentry = NULL, ssaved = NULL;
	centry = NULL, csaved = NULL;

	if (tee_dissect) goto finalize_opt_record;

	/* Is this option about sampling? */
	if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len || tpl->tpl[NF9_SAMPLING_INTERVAL].len == 4 || tpl->tpl[NF9_SAMPLING_PKT_INTERVAL].len == 4) {
	  u_int8_t t8 = 0;
	  u_int16_t t16 = 0;
	  u_int32_t sampler_id = 0, t32 = 0, t32_2 = 0;
	  u_int64_t t64 = 0;

	  /* Handling the global option scoping case */
	  if (!config.nfacctd_disable_opt_scope_check) {
	    if (tpl->tpl[NF9_OPT_SCOPE_SYSTEM].len) entry = (struct xflow_status_entry *) pptrs->f_status_g;
	    else {
	      if (version == 10) {
		if (tpl->tpl[IPFIX_SCOPE_TEMPLATE_ID].len) {
		  entry = (struct xflow_status_entry *) pptrs->f_status;
		  memcpy(&t16, pkt+tpl->tpl[IPFIX_SCOPE_TEMPLATE_ID].off, 2);
		  sampler_id = ntohs(t16);
		}
	      }
	    }
	  }
	  else entry = (struct xflow_status_entry *) pptrs->f_status_g;

	  if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len == 1) {
	    memcpy(&t8, pkt+tpl->tpl[NF9_FLOW_SAMPLER_ID].off, 1);
	    sampler_id = t8;
	  }
	  else if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len == 2) {
	    memcpy(&t16, pkt+tpl->tpl[NF9_FLOW_SAMPLER_ID].off, 2);
	    sampler_id = ntohs(t16);
	  }
          else if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len == 4) {
            memcpy(&t32, pkt+tpl->tpl[NF9_FLOW_SAMPLER_ID].off, 4);
            sampler_id = ntohl(t32);
          }
          else if (tpl->tpl[NF9_SELECTOR_ID].len == 8) {
            memcpy(&t64, pkt+tpl->tpl[NF9_SELECTOR_ID].off, 8);
            sampler_id = pm_ntohll(t64); /* XXX: sampler_id to be moved to 64 bit */
          }

	  if (entry) sentry = search_smp_id_status_table(entry->sampling, sampler_id, FALSE);
	  if (!sentry) sentry = create_smp_entry_status_table(&xflow_status_table, entry);
	  else ssaved = sentry->next;

	  if (sentry) {
	    memset(sentry, 0, sizeof(struct xflow_status_entry_sampling));
	    if (tpl->tpl[NF9_SAMPLING_INTERVAL].len == 1) {
	      memcpy(&t8, pkt+tpl->tpl[NF9_SAMPLING_INTERVAL].off, 1);
	      sentry->sample_pool = t8;
	    }
	    if (tpl->tpl[NF9_SAMPLING_INTERVAL].len == 2) {
	      memcpy(&t16, pkt+tpl->tpl[NF9_SAMPLING_INTERVAL].off, 2);
	      sentry->sample_pool = ntohs(t16);
	    }
	    if (tpl->tpl[NF9_SAMPLING_INTERVAL].len == 4) {
	      memcpy(&t32, pkt+tpl->tpl[NF9_SAMPLING_INTERVAL].off, 4);
	      sentry->sample_pool = ntohl(t32);
	    }
	    if (tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].len == 1) {
	      memcpy(&t8, pkt+tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].off, 1);
	      sentry->sample_pool = t8;
	    }
	    else if (tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].len == 2) {
	      memcpy(&t16, pkt+tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].off, 2);
	      sentry->sample_pool = ntohs(t16);
	    }
	    else if (tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].len == 4) {
	      memcpy(&t32, pkt+tpl->tpl[NF9_FLOW_SAMPLER_INTERVAL].off, 4);
	      sentry->sample_pool = ntohl(t32);
	    }
            else if (tpl->tpl[NF9_SAMPLING_PKT_INTERVAL].len == 4 && tpl->tpl[NF9_SAMPLING_PKT_SPACE].len == 4) {
	      u_int32_t pkt_interval = 0, pkt_space = 0;

              memcpy(&t32, pkt+tpl->tpl[NF9_SAMPLING_PKT_INTERVAL].off, 4);
              memcpy(&t32_2, pkt+tpl->tpl[NF9_SAMPLING_PKT_SPACE].off, 4);
	      pkt_interval = ntohl(t32);
	      pkt_space = ntohl(t32_2);

              if (pkt_interval) sentry->sample_pool = ((pkt_interval + pkt_space) / pkt_interval);
            }

	    sentry->sampler_id = sampler_id;
	    if (ssaved) sentry->next = ssaved;
	  }
	}

	if ((tpl->tpl[NF9_APPLICATION_ID].len == 2 || tpl->tpl[NF9_APPLICATION_ID].len == 3 || tpl->tpl[NF9_APPLICATION_ID].len == 5) &&
	    tpl->tpl[NF9_APPLICATION_NAME].len > 0) {
	  struct pkt_classifier css;
	  pm_class_t class_id = 0, class_int_id = 0;

	  /* Handling the global option scoping case */
	  if (!config.nfacctd_disable_opt_scope_check) {
	    if (tpl->tpl[NF9_OPT_SCOPE_SYSTEM].len) entry = (struct xflow_status_entry *) pptrs->f_status_g;
	  }
	  else entry = (struct xflow_status_entry *) pptrs->f_status_g;

	  memcpy(&class_id, (pkt + tpl->tpl[NF9_APPLICATION_ID].off + 1), (tpl->tpl[NF9_APPLICATION_ID].len - 1));

          if (entry) centry = search_class_id_status_table(entry->class, class_id);
          if (!centry) {
	    centry = create_class_entry_status_table(&xflow_status_table, entry);
	    class_int_id = pmct_find_first_free();
	  }
          else {
	    csaved = centry->next;
	    class_int_id = centry->class_int_id;
	    pmct_unregister(centry->class_int_id);
	  }

          if (centry) {
            memset(centry, 0, sizeof(struct xflow_status_entry_class));
	    memset(&css, 0, sizeof(struct pkt_classifier));
	    memcpy(&centry->class_name, pkt+tpl->tpl[NF9_APPLICATION_NAME].off, MIN((MAX_PROTOCOL_LEN-1), tpl->tpl[NF9_APPLICATION_NAME].len));
            centry->class_id = class_id;
	    centry->class_int_id = class_int_id;
            if (csaved) centry->next = csaved;

	    css.id = centry->class_int_id;
	    strlcpy(css.protocol, centry->class_name, MAX_PROTOCOL_LEN);
	    pmct_register(&css);
          }
	}

	if (tpl->tpl[NF9_EXPORTER_IPV4_ADDRESS].len == 4 || tpl->tpl[NF9_EXPORTER_IPV6_ADDRESS].len == 16) {
          /* Handling the global option scoping case */
          if (!config.nfacctd_disable_opt_scope_check) {
            if (tpl->tpl[NF9_OPT_SCOPE_SYSTEM].len) entry = (struct xflow_status_entry *) pptrs->f_status_g;
          }
          else entry = (struct xflow_status_entry *) pptrs->f_status_g;

	  if (entry) {
	    if (tpl->tpl[NF9_EXPORTER_IPV4_ADDRESS].len) {
	      raw_to_addr(&entry->exp_addr, pkt+tpl->tpl[NF9_EXPORTER_IPV4_ADDRESS].off, AF_INET);
	      raw_to_sa(&entry->exp_sa, pkt+tpl->tpl[NF9_EXPORTER_IPV4_ADDRESS].off, 0, AF_INET);
	    }
	    else if (tpl->tpl[NF9_EXPORTER_IPV6_ADDRESS].len) {
	      raw_to_addr(&entry->exp_addr, pkt+tpl->tpl[NF9_EXPORTER_IPV6_ADDRESS].off, AF_INET6);
	      raw_to_sa(&entry->exp_sa, pkt+tpl->tpl[NF9_EXPORTER_IPV6_ADDRESS].off, 0, AF_INET6);
	    }
	  }
	}

        if (tpl->tpl[NF9_INGRESS_VRFID].len == 4 && tpl->tpl[NF9_MPLS_VPN_RD].len == 8) {
          /* Handling the global option scoping case */
          if (!config.nfacctd_disable_opt_scope_check) {
            if (tpl->tpl[NF9_OPT_SCOPE_SYSTEM].len) entry = (struct xflow_status_entry *) pptrs->f_status_g;
          }
          else entry = (struct xflow_status_entry *) pptrs->f_status_g;

	  if (entry) {
	    u_int32_t ingress_vrfid, egress_vrfid;
	    rd_t *mpls_vpn_rd;

	    if (!entry->in_rd_map) {
	      entry->in_rd_map = cdada_map_create(u_int32_t); /* size of vrfid */
	      if (!entry->in_rd_map) {
		Log(LOG_ERR, "ERROR ( %s/core ): Unable to allocate entry->in_rd_map. Exiting.\n", config.name);
		exit_gracefully(1);
	      }
	    }

	    if (!entry->out_rd_map) {
	      entry->out_rd_map = cdada_map_create(u_int32_t); /* size of vrfid */
	      if (!entry->out_rd_map) {
		Log(LOG_ERR, "ERROR ( %s/core ): Unable to allocate entry->out_rd_map. Exiting.\n", config.name);
		exit_gracefully(1);
	      }
	    }

	    memcpy(&ingress_vrfid, pkt+tpl->tpl[NF9_INGRESS_VRFID].off, tpl->tpl[NF9_INGRESS_VRFID].len);
	    ingress_vrfid = ntohl(ingress_vrfid);

	    memcpy(&egress_vrfid, pkt+tpl->tpl[NF9_EGRESS_VRFID].off, tpl->tpl[NF9_EGRESS_VRFID].len);
	    egress_vrfid = ntohl(egress_vrfid);

	    if (ingress_vrfid || egress_vrfid) {
	      mpls_vpn_rd = malloc(sizeof(rd_t));

	      memcpy(mpls_vpn_rd, pkt+tpl->tpl[NF9_MPLS_VPN_RD].off, tpl->tpl[NF9_MPLS_VPN_RD].len);
	      bgp_rd_ntoh(mpls_vpn_rd);

	      if (ingress_vrfid) {
	        ret = cdada_map_insert(entry->in_rd_map, &ingress_vrfid, mpls_vpn_rd);
		if (ret != CDADA_SUCCESS && ret != CDADA_E_EXISTS){
		  Log(LOG_ERR, "ERROR ( %s/core ): Unable to insert in entry->in_rd_map. Exiting.\n", config.name);
		  exit_gracefully(1);
		}
	      }

	      if (egress_vrfid) {
	        ret = cdada_map_insert(entry->out_rd_map, &egress_vrfid, mpls_vpn_rd);
		if (ret != CDADA_SUCCESS && ret != CDADA_E_EXISTS){
		  Log(LOG_ERR, "ERROR ( %s/core ): Unable to insert in entry->out_rd_map. Exiting.\n", config.name);
		  exit_gracefully(1);
		}
	      }
	    }
	  }
	}

	if (config.nfacctd_account_options) {
	  pptrs->f_data = pkt;
	  pptrs->f_tpl = (u_char *) tpl;
	  reset_net_status_v(pptrsv);
	  NF_evaluate_flow_type(&pptrs->flow_type, tpl, pptrs);

	  exec_plugins(pptrs, req);
	}

	finalize_opt_record:
        pkt += tpl->len;
        flowoff += tpl->len;

        FlowSeqInc++;
      }

      /* last pre-flight check for the subsequent subtraction */
      if (flowoff > flowsetlen) {
        notify_malf_packet(LOG_INFO, "INFO", "aborting malformed Options Data element (incomplete NetFlow v9/IPFIX packet)",
                      (struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
        xflow_status_table.tot_bad_datagrams++;
        return;
      }
      
      pkt += (flowsetlen-flowoff); /* handling padding */
      off += flowsetlen;
    }
    else {
      while (flowoff+tpl->len <= flowsetlen) {
        /* Let's bake offsets and lengths if we have variable-length fields */
        if (tpl->vlen) {
	  int ret;

	  ret = resolve_vlen_template(pkt, (flowsetlen - flowoff), tpl);
	  if (ret == ERR) break;
	}

        pptrs->f_data = pkt;
	pptrs->f_tpl = (u_char *) tpl;
	reset_net_status_v(pptrsv);

	if (tee_dissect) {
	  tee_dissect->elemBasePtr = pkt;
	  tee_dissect->elemEndPtr = (u_char *) (pkt + tpl->len);
	  tee_dissect->elemLen = tpl->len;
          pptrs->tee_dissect_bcast = FALSE;

	  exec_plugins(pptrs, req);

	  goto finalize_record;
	}

	NF_evaluate_flow_type(&pptrs->flow_type, tpl, pptrs);
	direction = NF_evaluate_direction(tpl, pptrs);

	/* we need to understand the IP protocol version in order to build the fake packet */ 
	switch (pptrs->flow_type.traffic_type) {
	case PM_FTYPE_IPV4:
	  if (req->bpf_filter) {
	    reset_mac(pptrs);
	    reset_ip4(pptrs);

	    if (direction == DIRECTION_IN) {
              memcpy(pptrs->mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_IN_SRC_MAC].off, tpl->tpl[NF9_IN_SRC_MAC].len);
              memcpy(pptrs->mac_ptr, pkt+tpl->tpl[NF9_IN_DST_MAC].off, tpl->tpl[NF9_IN_DST_MAC].len);
	    }
	    else if (direction == DIRECTION_OUT) {
              memcpy(pptrs->mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_OUT_SRC_MAC].off, tpl->tpl[NF9_OUT_SRC_MAC].len);
              memcpy(pptrs->mac_ptr, pkt+tpl->tpl[NF9_OUT_DST_MAC].off, tpl->tpl[NF9_OUT_DST_MAC].len);
	    }
	    ((struct pm_iphdr *)pptrs->iph_ptr)->ip_vhl = 0x45;
            memcpy(&((struct pm_iphdr *)pptrs->iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
            memcpy(&((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
            memcpy(&((struct pm_iphdr *)pptrs->iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
            memcpy(&((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
            memcpy(&((struct pm_tlhdr *)pptrs->tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
            memcpy(&((struct pm_tlhdr *)pptrs->tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
            memcpy(&((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags, pkt+tpl->tpl[NF9_TCP_FLAGS].off, tpl->tpl[NF9_TCP_FLAGS].len);
	  }

	  memcpy(&pptrs->lm_mask_src, pkt+tpl->tpl[NF9_SRC_MASK].off, tpl->tpl[NF9_SRC_MASK].len);
	  memcpy(&pptrs->lm_mask_dst, pkt+tpl->tpl[NF9_DST_MASK].off, tpl->tpl[NF9_DST_MASK].len);
	  pptrs->lm_method_src = NF_NET_KEEP;
	  pptrs->lm_method_dst = NF_NET_KEEP;

	  /* Let's copy some relevant field */
	  pptrs->l4_proto = 0;
	  memcpy(&pptrs->l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  NF_process_classifiers(pptrs, pptrs, pkt, tpl);
	  if (config.nfacctd_isis) isis_srcdst_lookup(pptrs);
	  if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, pptrs, &pptrs->bta, &pptrs->bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, pptrs, &pptrs->bitr, NULL);
	  if (config.bgp_daemon) bgp_srcdst_lookup(pptrs, FUNC_TYPE_BGP);
	  if (config.bgp_daemon_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, pptrs, &pptrs->bpas, NULL);
	  if (config.bgp_daemon_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, pptrs, &pptrs->blp, NULL);
	  if (config.bgp_daemon_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, pptrs, &pptrs->bmed, NULL);
          if (config.bmp_daemon) bmp_srcdst_lookup(pptrs);
          exec_plugins(pptrs, req);
	  break;
	case PM_FTYPE_IPV6:
	  pptrsv->v6.f_header = pptrs->f_header;
	  pptrsv->v6.f_data = pptrs->f_data;
	  pptrsv->v6.f_tpl = pptrs->f_tpl;
	  memcpy(&pptrsv->v6.flow_type, &pptrs->flow_type, sizeof(struct flow_chars));

	  if (req->bpf_filter) {
	    reset_mac(&pptrsv->v6);
	    reset_ip6(&pptrsv->v6);

	    if (direction == DIRECTION_IN) {
	      memcpy(pptrsv->v6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_IN_SRC_MAC].off, tpl->tpl[NF9_IN_SRC_MAC].len);
	      memcpy(pptrsv->v6.mac_ptr, pkt+tpl->tpl[NF9_IN_DST_MAC].off, tpl->tpl[NF9_IN_DST_MAC].len);
	    }
	    else if (direction == DIRECTION_OUT) {
	      memcpy(pptrsv->v6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_OUT_SRC_MAC].off, tpl->tpl[NF9_OUT_SRC_MAC].len);
	      memcpy(pptrsv->v6.mac_ptr, pkt+tpl->tpl[NF9_OUT_DST_MAC].off, tpl->tpl[NF9_OUT_DST_MAC].len);
	    }
	    ((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_ctlun.ip6_un2_vfc = 0x60;
            memcpy(&((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_src, pkt+tpl->tpl[NF9_IPV6_SRC_ADDR].off, tpl->tpl[NF9_IPV6_SRC_ADDR].len);
            memcpy(&((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_dst, pkt+tpl->tpl[NF9_IPV6_DST_ADDR].off, tpl->tpl[NF9_IPV6_DST_ADDR].len);
            memcpy(&((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_nxt, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    /* XXX: class ID ? */
            memcpy(&((struct pm_tlhdr *)pptrsv->v6.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
            memcpy(&((struct pm_tlhdr *)pptrsv->v6.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
            memcpy(&((struct pm_tcphdr *)pptrsv->v6.tlh_ptr)->th_flags, pkt+tpl->tpl[NF9_TCP_FLAGS].off, tpl->tpl[NF9_TCP_FLAGS].len);
	  }

          memcpy(&pptrsv->v6.lm_mask_src, pkt+tpl->tpl[NF9_SRC_MASK].off, tpl->tpl[NF9_SRC_MASK].len);
          memcpy(&pptrsv->v6.lm_mask_dst, pkt+tpl->tpl[NF9_DST_MASK].off, tpl->tpl[NF9_DST_MASK].len);
          pptrsv->v6.lm_method_src = NF_NET_KEEP;
          pptrsv->v6.lm_method_dst = NF_NET_KEEP;

	  /* Let's copy some relevant field */
	  pptrsv->v6.l4_proto = 0;
	  memcpy(&pptrsv->v6.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  NF_process_classifiers(pptrs, &pptrsv->v6, pkt, tpl);
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->v6);
	  if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->v6, &pptrsv->v6.bta, &pptrsv->v6.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->v6, &pptrsv->v6.bitr, NULL);
	  if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->v6, FUNC_TYPE_BGP);
	  if (config.bgp_daemon_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->v6, &pptrsv->v6.bpas, NULL);
	  if (config.bgp_daemon_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->v6, &pptrsv->v6.blp, NULL);
	  if (config.bgp_daemon_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->v6, &pptrsv->v6.bmed, NULL);
          if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->v6);
          exec_plugins(&pptrsv->v6, req);
	  break;
	case PM_FTYPE_VLAN_IPV4:
	  pptrsv->vlan4.f_header = pptrs->f_header;
	  pptrsv->vlan4.f_data = pptrs->f_data;
	  pptrsv->vlan4.f_tpl = pptrs->f_tpl;
	  memcpy(&pptrsv->vlan4.flow_type, &pptrs->flow_type, sizeof(struct flow_chars));

	  if (req->bpf_filter) {
	    reset_mac_vlan(&pptrsv->vlan4); 
	    reset_ip4(&pptrsv->vlan4);

	    if (direction == DIRECTION_IN) {
	      memcpy(pptrsv->vlan4.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_IN_SRC_MAC].off, tpl->tpl[NF9_IN_SRC_MAC].len);
	      memcpy(pptrsv->vlan4.mac_ptr, pkt+tpl->tpl[NF9_IN_DST_MAC].off, tpl->tpl[NF9_IN_DST_MAC].len);
	      memcpy(pptrsv->vlan4.vlan_ptr, pkt+tpl->tpl[NF9_IN_VLAN].off, tpl->tpl[NF9_IN_VLAN].len);
	    }
	    else if (direction == DIRECTION_OUT) {
	      memcpy(pptrsv->vlan4.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_OUT_SRC_MAC].off, tpl->tpl[NF9_OUT_SRC_MAC].len);
	      memcpy(pptrsv->vlan4.mac_ptr, pkt+tpl->tpl[NF9_OUT_DST_MAC].off, tpl->tpl[NF9_OUT_DST_MAC].len);
	      memcpy(pptrsv->vlan4.vlan_ptr, pkt+tpl->tpl[NF9_OUT_VLAN].off, tpl->tpl[NF9_OUT_VLAN].len);
	    }
	    ((struct pm_iphdr *)pptrsv->vlan4.iph_ptr)->ip_vhl = 0x45;
	    memcpy(&((struct pm_iphdr *)pptrsv->vlan4.iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
	    memcpy(&((struct pm_iphdr *)pptrsv->vlan4.iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
	    memcpy(&((struct pm_iphdr *)pptrsv->vlan4.iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    memcpy(&((struct pm_iphdr *)pptrsv->vlan4.iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
	    memcpy(&((struct pm_tlhdr *)pptrsv->vlan4.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct pm_tlhdr *)pptrsv->vlan4.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
            memcpy(&((struct pm_tcphdr *)pptrsv->vlan4.tlh_ptr)->th_flags, pkt+tpl->tpl[NF9_TCP_FLAGS].off, tpl->tpl[NF9_TCP_FLAGS].len);
	  }

          memcpy(&pptrsv->vlan4.lm_mask_src, pkt+tpl->tpl[NF9_SRC_MASK].off, tpl->tpl[NF9_SRC_MASK].len);
          memcpy(&pptrsv->vlan4.lm_mask_dst, pkt+tpl->tpl[NF9_DST_MASK].off, tpl->tpl[NF9_DST_MASK].len);
          pptrsv->vlan4.lm_method_src = NF_NET_KEEP;
          pptrsv->vlan4.lm_method_dst = NF_NET_KEEP;

	  /* Let's copy some relevant field */
	  pptrsv->vlan4.l4_proto = 0;
	  memcpy(&pptrsv->vlan4.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  NF_process_classifiers(pptrs, &pptrsv->vlan4, pkt, tpl);
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlan4);
	  if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlan4, &pptrsv->vlan4.bta, &pptrsv->vlan4.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlan4, &pptrsv->vlan4.bitr, NULL);
	  if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->vlan4, FUNC_TYPE_BGP);
	  if (config.bgp_daemon_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlan4, &pptrsv->vlan4.bpas, NULL);
	  if (config.bgp_daemon_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlan4, &pptrsv->vlan4.blp, NULL);
	  if (config.bgp_daemon_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlan4, &pptrsv->vlan4.bmed, NULL);
          if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->vlan4);
	  exec_plugins(&pptrsv->vlan4, req);
	  break;
	case PM_FTYPE_VLAN_IPV6:
	  pptrsv->vlan6.f_header = pptrs->f_header;
	  pptrsv->vlan6.f_data = pptrs->f_data;
	  pptrsv->vlan6.f_tpl = pptrs->f_tpl;
	  memcpy(&pptrsv->vlan6.flow_type, &pptrs->flow_type, sizeof(struct flow_chars));

	  if (req->bpf_filter) {
	    reset_mac_vlan(&pptrsv->vlan6);
	    reset_ip6(&pptrsv->vlan6);

	    if (direction == DIRECTION_IN) {
	      memcpy(pptrsv->vlan6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_IN_SRC_MAC].off, tpl->tpl[NF9_IN_SRC_MAC].len);
	      memcpy(pptrsv->vlan6.mac_ptr, pkt+tpl->tpl[NF9_IN_DST_MAC].off, tpl->tpl[NF9_IN_DST_MAC].len);
	      memcpy(pptrsv->vlan6.vlan_ptr, pkt+tpl->tpl[NF9_IN_VLAN].off, tpl->tpl[NF9_IN_VLAN].len);
	    }
            else if (direction == DIRECTION_OUT) {
	      memcpy(pptrsv->vlan6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_OUT_SRC_MAC].off, tpl->tpl[NF9_OUT_SRC_MAC].len);
	      memcpy(pptrsv->vlan6.mac_ptr, pkt+tpl->tpl[NF9_OUT_DST_MAC].off, tpl->tpl[NF9_OUT_DST_MAC].len);
	      memcpy(pptrsv->vlan6.vlan_ptr, pkt+tpl->tpl[NF9_OUT_VLAN].off, tpl->tpl[NF9_OUT_VLAN].len);
	    }
	    ((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_ctlun.ip6_un2_vfc = 0x60;
	    memcpy(&((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_src, pkt+tpl->tpl[NF9_IPV6_SRC_ADDR].off, tpl->tpl[NF9_IPV6_SRC_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_dst, pkt+tpl->tpl[NF9_IPV6_DST_ADDR].off, tpl->tpl[NF9_IPV6_DST_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_nxt, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    /* XXX: class ID ? */
	    memcpy(&((struct pm_tlhdr *)pptrsv->vlan6.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct pm_tlhdr *)pptrsv->vlan6.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
            memcpy(&((struct pm_tcphdr *)pptrsv->vlan6.tlh_ptr)->th_flags, pkt+tpl->tpl[NF9_TCP_FLAGS].off, tpl->tpl[NF9_TCP_FLAGS].len);
	  }

          memcpy(&pptrsv->vlan6.lm_mask_src, pkt+tpl->tpl[NF9_SRC_MASK].off, tpl->tpl[NF9_SRC_MASK].len);
          memcpy(&pptrsv->vlan6.lm_mask_dst, pkt+tpl->tpl[NF9_DST_MASK].off, tpl->tpl[NF9_DST_MASK].len);
          pptrsv->vlan6.lm_method_src = NF_NET_KEEP;
          pptrsv->vlan6.lm_method_dst = NF_NET_KEEP;

	  /* Let's copy some relevant field */
	  pptrsv->vlan6.l4_proto = 0;
	  memcpy(&pptrsv->vlan6.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  NF_process_classifiers(pptrs, &pptrsv->vlan6, pkt, tpl);
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlan6);
	  if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlan6, &pptrsv->vlan6.bta, &pptrsv->vlan6.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlan6, &pptrsv->vlan6.bitr, NULL);
	  if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->vlan6, FUNC_TYPE_BGP);
	  if (config.bgp_daemon_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlan6, &pptrsv->vlan6.bpas, NULL);
	  if (config.bgp_daemon_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlan6, &pptrsv->vlan6.blp, NULL);
	  if (config.bgp_daemon_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlan6, &pptrsv->vlan6.bmed, NULL);
          if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->vlan6);
	  exec_plugins(&pptrsv->vlan6, req);
	  break;
        case PM_FTYPE_MPLS_IPV4:
          pptrsv->mpls4.f_header = pptrs->f_header;
          pptrsv->mpls4.f_data = pptrs->f_data;
          pptrsv->mpls4.f_tpl = pptrs->f_tpl;
	  memcpy(&pptrsv->mpls4.flow_type, &pptrs->flow_type, sizeof(struct flow_chars));

          if (req->bpf_filter) {
	    u_char *ptr = pptrsv->mpls4.mpls_ptr;
	    u_int32_t idx;

            /* XXX: fix caplen */
            reset_mac(&pptrsv->mpls4);
	    if (direction == DIRECTION_IN) {
              memcpy(pptrsv->mpls4.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_IN_SRC_MAC].off, tpl->tpl[NF9_IN_SRC_MAC].len);
              memcpy(pptrsv->mpls4.mac_ptr, pkt+tpl->tpl[NF9_IN_DST_MAC].off, tpl->tpl[NF9_IN_DST_MAC].len);
	    }
	    else if (direction == DIRECTION_OUT) {
              memcpy(pptrsv->mpls4.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_OUT_SRC_MAC].off, tpl->tpl[NF9_OUT_SRC_MAC].len);
              memcpy(pptrsv->mpls4.mac_ptr, pkt+tpl->tpl[NF9_OUT_DST_MAC].off, tpl->tpl[NF9_OUT_DST_MAC].len);
	    }

	    for (idx = NF9_MPLS_LABEL_1; idx <= NF9_MPLS_LABEL_10 && tpl->tpl[idx].len; idx++, ptr += 4) {
	      memset(ptr, 0, 4);
	      memcpy(ptr, pkt+tpl->tpl[idx].off, tpl->tpl[idx].len);
	    }
	    stick_bosbit(ptr-4);
	    pptrsv->mpls4.iph_ptr = ptr;
	    pptrsv->mpls4.tlh_ptr = ptr + IP4HdrSz;
            reset_ip4(&pptrsv->mpls4);

	    ((struct pm_iphdr *)pptrsv->mpls4.iph_ptr)->ip_vhl = 0x45;
            memcpy(&((struct pm_iphdr *)pptrsv->mpls4.iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
            memcpy(&((struct pm_iphdr *)pptrsv->mpls4.iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
            memcpy(&((struct pm_iphdr *)pptrsv->mpls4.iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
            memcpy(&((struct pm_iphdr *)pptrsv->mpls4.iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
            memcpy(&((struct pm_tlhdr *)pptrsv->mpls4.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
            memcpy(&((struct pm_tlhdr *)pptrsv->mpls4.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
            memcpy(&((struct pm_tcphdr *)pptrsv->mpls4.tlh_ptr)->th_flags, pkt+tpl->tpl[NF9_TCP_FLAGS].off, tpl->tpl[NF9_TCP_FLAGS].len);
	  }

          memcpy(&pptrsv->mpls4.lm_mask_src, pkt+tpl->tpl[NF9_SRC_MASK].off, tpl->tpl[NF9_SRC_MASK].len);
          memcpy(&pptrsv->mpls4.lm_mask_dst, pkt+tpl->tpl[NF9_DST_MASK].off, tpl->tpl[NF9_DST_MASK].len);
          pptrsv->mpls4.lm_method_src = NF_NET_KEEP;
          pptrsv->mpls4.lm_method_dst = NF_NET_KEEP;

	  /* Let's copy some relevant field */
	  pptrsv->mpls4.l4_proto = 0;
	  memcpy(&pptrsv->mpls4.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  NF_process_classifiers(pptrs, &pptrsv->mpls4, pkt, tpl);
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->mpls4);
	  if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->mpls4, &pptrsv->mpls4.bta, &pptrsv->mpls4.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->mpls4, &pptrsv->mpls4.bitr, NULL);
	  if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->mpls4, FUNC_TYPE_BGP);
	  if (config.bgp_daemon_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->mpls4, &pptrsv->mpls4.bpas, NULL);
	  if (config.bgp_daemon_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->mpls4, &pptrsv->mpls4.blp, NULL);
	  if (config.bgp_daemon_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->mpls4, &pptrsv->mpls4.bmed, NULL);
          if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->mpls4);
          exec_plugins(&pptrsv->mpls4, req);
          break;
	case PM_FTYPE_MPLS_IPV6:
	  pptrsv->mpls6.f_header = pptrs->f_header;
	  pptrsv->mpls6.f_data = pptrs->f_data;
	  pptrsv->mpls6.f_tpl = pptrs->f_tpl;
	  memcpy(&pptrsv->mpls6.flow_type, &pptrs->flow_type, sizeof(struct flow_chars));

	  if (req->bpf_filter) {
	    u_char *ptr = pptrsv->mpls6.mpls_ptr;
	    u_int32_t idx;

	    /* XXX: fix caplen */
	    reset_mac(&pptrsv->mpls6);
	    if (direction == DIRECTION_IN) {
	      memcpy(pptrsv->mpls6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_IN_SRC_MAC].off, tpl->tpl[NF9_IN_SRC_MAC].len);
	      memcpy(pptrsv->mpls6.mac_ptr, pkt+tpl->tpl[NF9_IN_DST_MAC].off, tpl->tpl[NF9_IN_DST_MAC].len);
	    }
	    else if (direction == DIRECTION_OUT) {
	      memcpy(pptrsv->mpls6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_OUT_SRC_MAC].off, tpl->tpl[NF9_OUT_SRC_MAC].len);
	      memcpy(pptrsv->mpls6.mac_ptr, pkt+tpl->tpl[NF9_OUT_DST_MAC].off, tpl->tpl[NF9_OUT_DST_MAC].len);
	    }
            for (idx = NF9_MPLS_LABEL_1; idx <= NF9_MPLS_LABEL_10 && tpl->tpl[idx].len; idx++, ptr += 4) {
	      memset(ptr, 0, 4);
	      memcpy(ptr, pkt+tpl->tpl[idx].off, tpl->tpl[idx].len);
	    }
	    stick_bosbit(ptr-4);
	    pptrsv->mpls6.iph_ptr = ptr;
	    pptrsv->mpls6.tlh_ptr = ptr + IP6HdrSz;
	    reset_ip6(&pptrsv->mpls6);

	    ((struct ip6_hdr *)pptrsv->mpls6.iph_ptr)->ip6_ctlun.ip6_un2_vfc = 0x60;
	    memcpy(&((struct ip6_hdr *)pptrsv->mpls6.iph_ptr)->ip6_src, pkt+tpl->tpl[NF9_IPV6_SRC_ADDR].off, tpl->tpl[NF9_IPV6_SRC_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->mpls6.iph_ptr)->ip6_dst, pkt+tpl->tpl[NF9_IPV6_DST_ADDR].off, tpl->tpl[NF9_IPV6_DST_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->mpls6.iph_ptr)->ip6_nxt, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    /* XXX: class ID ? */
	    memcpy(&((struct pm_tlhdr *)pptrsv->mpls6.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct pm_tlhdr *)pptrsv->mpls6.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
            memcpy(&((struct pm_tcphdr *)pptrsv->mpls6.tlh_ptr)->th_flags, pkt+tpl->tpl[NF9_TCP_FLAGS].off, tpl->tpl[NF9_TCP_FLAGS].len);
	  }

          memcpy(&pptrsv->mpls6.lm_mask_src, pkt+tpl->tpl[NF9_SRC_MASK].off, tpl->tpl[NF9_SRC_MASK].len);
          memcpy(&pptrsv->mpls6.lm_mask_dst, pkt+tpl->tpl[NF9_DST_MASK].off, tpl->tpl[NF9_DST_MASK].len);
          pptrsv->mpls6.lm_method_src = NF_NET_KEEP;
          pptrsv->mpls6.lm_method_dst = NF_NET_KEEP;

	  /* Let's copy some relevant field */
	  pptrsv->mpls6.l4_proto = 0;
	  memcpy(&pptrsv->mpls6.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  NF_process_classifiers(pptrs, &pptrsv->mpls6, pkt, tpl);
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->mpls6);
	  if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->mpls6, &pptrsv->mpls6.bta, &pptrsv->mpls6.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->mpls6, &pptrsv->mpls6.bitr, NULL);
	  if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->mpls6, FUNC_TYPE_BGP);
	  if (config.bgp_daemon_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->mpls6, &pptrsv->mpls6.bpas, NULL);
	  if (config.bgp_daemon_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->mpls6, &pptrsv->mpls6.blp, NULL);
	  if (config.bgp_daemon_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->mpls6, &pptrsv->mpls6.bmed, NULL);
          if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->mpls6);
	  exec_plugins(&pptrsv->mpls6, req);
	  break;
        case PM_FTYPE_VLAN_MPLS_IPV4:
	  pptrsv->vlanmpls4.f_header = pptrs->f_header;
	  pptrsv->vlanmpls4.f_data = pptrs->f_data;
	  pptrsv->vlanmpls4.f_tpl = pptrs->f_tpl;
	  memcpy(&pptrsv->vlanmpls4.flow_type, &pptrs->flow_type, sizeof(struct flow_chars));

          if (req->bpf_filter) {
            u_char *ptr = pptrsv->vlanmpls4.mpls_ptr;
	    u_int32_t idx;

	    /* XXX: fix caplen */
	    reset_mac_vlan(&pptrsv->vlanmpls4);
	    if (direction == DIRECTION_IN) {
	      memcpy(pptrsv->vlanmpls4.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_IN_SRC_MAC].off, tpl->tpl[NF9_IN_SRC_MAC].len);
	      memcpy(pptrsv->vlanmpls4.mac_ptr, pkt+tpl->tpl[NF9_IN_DST_MAC].off, tpl->tpl[NF9_IN_DST_MAC].len);
	      memcpy(pptrsv->vlanmpls4.vlan_ptr, pkt+tpl->tpl[NF9_IN_VLAN].off, tpl->tpl[NF9_IN_VLAN].len);
	    }
	    else if (direction == DIRECTION_OUT) {
	      memcpy(pptrsv->vlanmpls4.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_OUT_SRC_MAC].off, tpl->tpl[NF9_OUT_SRC_MAC].len);
	      memcpy(pptrsv->vlanmpls4.mac_ptr, pkt+tpl->tpl[NF9_OUT_DST_MAC].off, tpl->tpl[NF9_OUT_DST_MAC].len);
	      memcpy(pptrsv->vlanmpls4.vlan_ptr, pkt+tpl->tpl[NF9_OUT_VLAN].off, tpl->tpl[NF9_OUT_VLAN].len);
	    }

	    for (idx = NF9_MPLS_LABEL_1; idx <= NF9_MPLS_LABEL_10 && tpl->tpl[idx].len; idx++, ptr += 4) {
	      memset(ptr, 0, 4);
	      memcpy(ptr, pkt+tpl->tpl[idx].off, tpl->tpl[idx].len);
	    }
	    stick_bosbit(ptr-4);
	    pptrsv->vlanmpls4.iph_ptr = ptr;
	    pptrsv->vlanmpls4.tlh_ptr = ptr + IP4HdrSz;
            reset_ip4(&pptrsv->vlanmpls4);

	    ((struct pm_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_vhl = 0x45;
            memcpy(&((struct pm_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
	    memcpy(&((struct pm_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
	    memcpy(&((struct pm_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    memcpy(&((struct pm_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
	    memcpy(&((struct pm_tlhdr *)pptrsv->vlanmpls4.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct pm_tlhdr *)pptrsv->vlanmpls4.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
            memcpy(&((struct pm_tcphdr *)pptrsv->vlanmpls4.tlh_ptr)->th_flags, pkt+tpl->tpl[NF9_TCP_FLAGS].off, tpl->tpl[NF9_TCP_FLAGS].len);
	  }

          memcpy(&pptrsv->vlanmpls4.lm_mask_src, pkt+tpl->tpl[NF9_SRC_MASK].off, tpl->tpl[NF9_SRC_MASK].len);
          memcpy(&pptrsv->vlanmpls4.lm_mask_dst, pkt+tpl->tpl[NF9_DST_MASK].off, tpl->tpl[NF9_DST_MASK].len);
          pptrsv->vlanmpls4.lm_method_src = NF_NET_KEEP;
          pptrsv->vlanmpls4.lm_method_dst = NF_NET_KEEP;

	  /* Let's copy some relevant field */
	  pptrsv->vlanmpls4.l4_proto = 0;
	  memcpy(&pptrsv->vlanmpls4.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  NF_process_classifiers(pptrs, &pptrsv->vlanmpls4, pkt, tpl);
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlanmpls4);
	  if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bta, &pptrsv->vlanmpls4.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bitr, NULL);
	  if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->vlanmpls4, FUNC_TYPE_BGP);
	  if (config.bgp_daemon_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bpas, NULL);
	  if (config.bgp_daemon_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.blp, NULL);
	  if (config.bgp_daemon_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bmed, NULL);
          if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->vlanmpls4);
	  exec_plugins(&pptrsv->vlanmpls4, req);
	  break;
        case PM_FTYPE_VLAN_MPLS_IPV6:
	  pptrsv->vlanmpls6.f_header = pptrs->f_header;
	  pptrsv->vlanmpls6.f_data = pptrs->f_data;
	  pptrsv->vlanmpls6.f_tpl = pptrs->f_tpl;
	  memcpy(&pptrsv->vlanmpls6.flow_type, &pptrs->flow_type, sizeof(struct flow_chars));

          if (req->bpf_filter) {
            u_char *ptr = pptrsv->vlanmpls6.mpls_ptr;
            u_int32_t idx;

            /* XXX: fix caplen */
	    reset_mac_vlan(&pptrsv->vlanmpls6);
	    if (direction == DIRECTION_IN) {
	      memcpy(pptrsv->vlanmpls6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_IN_SRC_MAC].off, tpl->tpl[NF9_IN_SRC_MAC].len);
	      memcpy(pptrsv->vlanmpls6.mac_ptr, pkt+tpl->tpl[NF9_IN_DST_MAC].off, tpl->tpl[NF9_IN_DST_MAC].len);
	      memcpy(pptrsv->vlanmpls6.vlan_ptr, pkt+tpl->tpl[NF9_IN_VLAN].off, tpl->tpl[NF9_IN_VLAN].len);
	    }
	    else if (direction == DIRECTION_OUT) {
	      memcpy(pptrsv->vlanmpls6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_OUT_SRC_MAC].off, tpl->tpl[NF9_OUT_SRC_MAC].len);
	      memcpy(pptrsv->vlanmpls6.mac_ptr, pkt+tpl->tpl[NF9_OUT_DST_MAC].off, tpl->tpl[NF9_OUT_DST_MAC].len);
	      memcpy(pptrsv->vlanmpls6.vlan_ptr, pkt+tpl->tpl[NF9_OUT_VLAN].off, tpl->tpl[NF9_OUT_VLAN].len);
	    }
	    for (idx = NF9_MPLS_LABEL_1; idx <= NF9_MPLS_LABEL_10 && tpl->tpl[idx].len; idx++, ptr += 4) {
	      memset(ptr, 0, 4);
	      memcpy(ptr, pkt+tpl->tpl[idx].off, tpl->tpl[idx].len);
	    }
	    stick_bosbit(ptr-4);
	    pptrsv->vlanmpls6.iph_ptr = ptr;
	    pptrsv->vlanmpls6.tlh_ptr = ptr + IP6HdrSz;
	    reset_ip6(&pptrsv->vlanmpls6);

	    ((struct ip6_hdr *)pptrsv->vlanmpls6.iph_ptr)->ip6_ctlun.ip6_un2_vfc = 0x60;
	    memcpy(&((struct ip6_hdr *)pptrsv->vlanmpls6.iph_ptr)->ip6_src, pkt+tpl->tpl[NF9_IPV6_SRC_ADDR].off, tpl->tpl[NF9_IPV6_SRC_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->vlanmpls6.iph_ptr)->ip6_dst, pkt+tpl->tpl[NF9_IPV6_DST_ADDR].off, tpl->tpl[NF9_IPV6_DST_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->vlanmpls6.iph_ptr)->ip6_nxt, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    /* XXX: class ID ? */
	    memcpy(&((struct pm_tlhdr *)pptrsv->vlanmpls6.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct pm_tlhdr *)pptrsv->vlanmpls6.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
            memcpy(&((struct pm_tcphdr *)pptrsv->vlanmpls6.tlh_ptr)->th_flags, pkt+tpl->tpl[NF9_TCP_FLAGS].off, tpl->tpl[NF9_TCP_FLAGS].len);
	  }

          memcpy(&pptrsv->vlanmpls6.lm_mask_src, pkt+tpl->tpl[NF9_SRC_MASK].off, tpl->tpl[NF9_SRC_MASK].len);
          memcpy(&pptrsv->vlanmpls6.lm_mask_dst, pkt+tpl->tpl[NF9_DST_MASK].off, tpl->tpl[NF9_DST_MASK].len);
          pptrsv->vlanmpls6.lm_method_src = NF_NET_KEEP;
          pptrsv->vlanmpls6.lm_method_dst = NF_NET_KEEP;

	  /* Let's copy some relevant field */
	  pptrsv->vlanmpls6.l4_proto = 0;
	  memcpy(&pptrsv->vlanmpls6.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  NF_process_classifiers(pptrs, &pptrsv->vlanmpls6, pkt, tpl);
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlanmpls6);
	  if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bta, &pptrsv->vlanmpls6.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bitr, NULL);
	  if (config.bgp_daemon) bgp_srcdst_lookup(&pptrsv->vlanmpls6, FUNC_TYPE_BGP);
	  if (config.bgp_daemon_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bpas, NULL);
	  if (config.bgp_daemon_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.blp, NULL);
	  if (config.bgp_daemon_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bmed, NULL);
          if (config.bmp_daemon) bmp_srcdst_lookup(&pptrsv->vlanmpls6);
	  exec_plugins(&pptrsv->vlanmpls6, req);
	  break;
	case NF9_FTYPE_NAT_EVENT:
	  /* XXX: aggregate_filter & NAT64 case */
	  if (req->bpf_filter) {
	    reset_mac(pptrs);
	    reset_ip4(pptrs);

	    if (direction == DIRECTION_IN) {
              memcpy(pptrs->mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_IN_SRC_MAC].off, tpl->tpl[NF9_IN_SRC_MAC].len);
              memcpy(pptrs->mac_ptr, pkt+tpl->tpl[NF9_IN_DST_MAC].off, tpl->tpl[NF9_IN_DST_MAC].len);
	    }
	    else if (direction == DIRECTION_OUT) {
              memcpy(pptrs->mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_OUT_SRC_MAC].off, tpl->tpl[NF9_OUT_SRC_MAC].len);
              memcpy(pptrs->mac_ptr, pkt+tpl->tpl[NF9_OUT_DST_MAC].off, tpl->tpl[NF9_OUT_DST_MAC].len);
	    }
	    ((struct pm_iphdr *)pptrs->iph_ptr)->ip_vhl = 0x45;
            memcpy(&((struct pm_iphdr *)pptrs->iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
            memcpy(&((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
            memcpy(&((struct pm_iphdr *)pptrs->iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
            memcpy(&((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
            memcpy(&((struct pm_tlhdr *)pptrs->tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
            memcpy(&((struct pm_tlhdr *)pptrs->tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
            memcpy(&((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags, pkt+tpl->tpl[NF9_TCP_FLAGS].off, tpl->tpl[NF9_TCP_FLAGS].len);
	  }

	  memcpy(&pptrs->lm_mask_src, pkt+tpl->tpl[NF9_SRC_MASK].off, tpl->tpl[NF9_SRC_MASK].len);
	  memcpy(&pptrs->lm_mask_dst, pkt+tpl->tpl[NF9_DST_MASK].off, tpl->tpl[NF9_DST_MASK].len);
	  pptrs->lm_method_src = NF_NET_KEEP;
	  pptrs->lm_method_dst = NF_NET_KEEP;

	  /* Let's copy some relevant field */
	  pptrs->l4_proto = 0;
	  memcpy(&pptrs->l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  if (config.nfacctd_isis) isis_srcdst_lookup(pptrs);
	  if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, pptrs, &pptrs->bta, &pptrs->bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, pptrs, &pptrs->bitr, NULL);
	  if (config.bgp_daemon) bgp_srcdst_lookup(pptrs, FUNC_TYPE_BGP);
	  if (config.bgp_daemon_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, pptrs, &pptrs->bpas, NULL);
	  if (config.bgp_daemon_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, pptrs, &pptrs->blp, NULL);
	  if (config.bgp_daemon_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, pptrs, &pptrs->bmed, NULL);
	  if (config.bmp_daemon) bmp_srcdst_lookup(pptrs);

          exec_plugins(pptrs, req);
	  break;
	case NF9_FTYPE_DLFS:
	  dummy_packet_ptr = pptrs->packet_ptr;
	  nfv9_datalink_frame_section_handler(pptrs);

	  if (config.nfacctd_isis) isis_srcdst_lookup(pptrs);
	  if (config.bgp_daemon_to_xflow_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, pptrs, &pptrs->bta, &pptrs->bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, pptrs, &pptrs->bitr, NULL);
	  if (config.bgp_daemon) bgp_srcdst_lookup(pptrs, FUNC_TYPE_BGP);
	  if (config.bgp_daemon_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, pptrs, &pptrs->bpas, NULL);
	  if (config.bgp_daemon_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, pptrs, &pptrs->blp, NULL);
	  if (config.bgp_daemon_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, pptrs, &pptrs->bmed, NULL);
          if (config.bmp_daemon) bmp_srcdst_lookup(pptrs);

          exec_plugins(pptrs, req);
	  reset_dummy_v4(pptrs, dummy_packet_ptr);
	  break;
	default:
	  break;
        }

        finalize_record:
        pkt += tpl->len;
        flowoff += tpl->len;
	
	/* we have to reset; let's not do to zero to short-circuit
	   the case of the last record in a flowset; we can save a
	   round through resolve_vlen_template() */
	if (tpl->vlen) tpl->len = 1;
	FlowSeqInc++;
      }

      /* last pre-flight check for the subsequent subtraction */
      if (flowoff > flowsetlen) {
        notify_malf_packet(LOG_INFO, "INFO", "aborting malformed Data element (incomplete NetFlow v9/IPFIX packet)",
                      (struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
        xflow_status_table.tot_bad_datagrams++;
        return;
      }

      pkt += (flowsetlen-flowoff); /* handling padding */
      off += flowsetlen; 
    }
  }
  else { /* unsupported flowset */
    if (off+flowsetlen > len) {
      Log(LOG_DEBUG, "DEBUG ( %s/core ): unable to read unsupported Flowset (ID: '%u').\n", config.name, fid);
      return;
    }
    pkt += flowsetlen;
    off += flowsetlen;
  }

  if ((version == 9 && (flowsetCount + 1) < flowsetNo && off < len) ||
      (version == 10 && off < len)) {
    flowsetCount++;
    goto process_flowset;
  }

  /* Set IPFIX Sequence number increment */
  if (version == 10) {
    struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrsv->v4.f_status;

    if (entry) entry->inc = FlowSeqInc;
  }
}

void process_raw_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs_vector *pptrsv,
                struct plugin_requests *req)
{
  struct packet_ptrs *pptrs = &pptrsv->v4;
  u_int16_t nfv;

  /* basic length check against longest NetFlow header */
  if (len < NfHdrV5Sz) {
    notify_malf_packet(LOG_INFO, "INFO", "discarding short NetFlow packet", (struct sockaddr *) pptrs->f_agent, 0);
    xflow_status_table.tot_bad_datagrams++;
    return;
  } 

  if (req->ptm_c.exec_ptm_dissect) nfv = ((struct struct_header_v5 *)pkt)->version;
  else nfv = ntohs(((struct struct_header_v5 *)pkt)->version);

  if (nfv != 5 && nfv != 9 && nfv != 10) {
    if (!config.nfacctd_disable_checks) {
      notify_malf_packet(LOG_INFO, "INFO", "discarding unknown NetFlow packet", (struct sockaddr *) pptrs->f_agent, 0);
      xflow_status_table.tot_bad_datagrams++;
    }
    return;
  }

  pptrs->f_header = pkt;

  switch (nfv) {
  case 5:
    pptrs->seqno = ntohl(((struct struct_header_v5 *)pkt)->flow_sequence);
    if (!req->ptm_c.exec_ptm_dissect) nfv5_check_status(pptrs); /* stats collection */
    break;
  case 9:
    pptrs->seqno = ntohl(((struct struct_header_v9 *)pkt)->flow_sequence);
    if (!req->ptm_c.exec_ptm_dissect) {
      u_int32_t SourceId = ntohl(((struct struct_header_v9 *)pkt)->source_id);
      nfv9_check_status(pptrs, SourceId, 0, pptrs->seqno, TRUE); /* stats collection */
    }
    break;
  case 10:
    pptrs->seqno = ntohl(((struct struct_header_ipfix *)pkt)->flow_sequence);
    if (!req->ptm_c.exec_ptm_dissect) {
      u_int32_t SourceId = ntohl(((struct struct_header_ipfix *)pkt)->source_id);
      nfv9_check_status(pptrs, SourceId, 0, pptrs->seqno, TRUE); /* stats collection */
    }
    break;
  default:
    pptrs->seqno = 0;
    break;
  }

  if (!req->ptm_c.exec_ptm_dissect && config.debug) {
    sa_to_addr((struct sockaddr *)pptrs->f_agent, &debug_a, &debug_agent_port);
    addr_to_str(debug_agent_addr, &debug_a);

    Log(LOG_DEBUG, "DEBUG ( %s/core ): Received NetFlow/IPFIX packet from [%s:%u] version [%u] seqno [%u]\n",
	config.name, debug_agent_addr, debug_agent_port, nfv, pptrs->seqno);
  }

  if (req->ptm_c.exec_ptm_dissect) {
    struct NF_dissect tee_dissect;

    memset(&tee_dissect, 0, sizeof(tee_dissect));
    pptrsv->v4.tee_dissect = (char *) &tee_dissect;
    req->ptm_c.exec_ptm_res = TRUE;

    switch(nfv) {
    case 5:
      process_v5_packet(pkt, len, &pptrsv->v4, req, nfv, &tee_dissect);
      break;
    /* NetFlow v9 + IPFIX */
    case 9:
    case 10:
      process_v9_packet(pkt, len, pptrsv, req, nfv, &tee_dissect, NULL);
      break;
    default:
      break;
    }
  }

  /* If dissecting, we also send the full original packet */
  if (req->ptm_c.exec_ptm_dissect)
    ((struct struct_header_v5 *)pkt)->version = htons(((struct struct_header_v5 *)pkt)->version);

  pptrs->tee_dissect = NULL;
  pptrs->f_data = NULL;
  pptrs->f_tpl = NULL;
  req->ptm_c.exec_ptm_res = FALSE;

  exec_plugins(pptrs, req);
}

void NF_compute_once()
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
  NfHdrV5Sz = sizeof(struct struct_header_v5);
  NfHdrV9Sz = sizeof(struct struct_header_v9);
  NfDataHdrV9Sz = sizeof(struct data_hdr_v9);
  NfTplHdrV9Sz = sizeof(struct template_hdr_v9);
  NfTplFieldV9Sz = sizeof(struct template_field_v9);
  NfOptTplHdrV9Sz = sizeof(struct options_template_hdr_v9);
  NfDataV5Sz = sizeof(struct struct_export_v5);
  IP4HdrSz = sizeof(struct pm_iphdr);
  IP4TlSz = sizeof(struct pm_iphdr)+sizeof(struct pm_tlhdr);
  PptrsSz = sizeof(struct packet_ptrs);
  CSSz = sizeof(struct class_st);
  HostAddrSz = sizeof(struct host_addr);
  UDPHdrSz = sizeof(struct pm_udphdr);
  IpFixHdrSz = sizeof(struct struct_header_ipfix); 

  IP6HdrSz = sizeof(struct ip6_hdr);
  IP6AddrSz = sizeof(struct in6_addr);
  IP6TlSz = sizeof(struct ip6_hdr)+sizeof(struct pm_tlhdr);
}

void NF_evaluate_flow_type(struct flow_chars *flow_type, struct template_cache_entry *tpl, struct packet_ptrs *pptrs)
{
  u_int8_t ret = FALSE;
  u_int8_t have_ip_proto = FALSE;

  memset(flow_type, 0, sizeof(struct flow_chars));

  /* first round: event vs traffic */
  if (!tpl->tpl[NF9_IN_BYTES].len && !tpl->tpl[NF9_OUT_BYTES].len && !tpl->tpl[NF9_FLOW_BYTES].len &&
      !tpl->tpl[NF9_INITIATOR_OCTETS].len && !tpl->tpl[NF9_RESPONDER_OCTETS].len && /* packets? && */
      !tpl->tpl[NF9_DATALINK_FRAME_SECTION].len && !tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len &&
      !tpl->tpl[NF9_LAYER2OCTETDELTACOUNT].len) {
    ret = NF9_FTYPE_EVENT;
  }
  else {
    if ((tpl->tpl[NF9_IN_VLAN].len && *(pptrs->f_data+tpl->tpl[NF9_IN_VLAN].off) > 0) ||
        (tpl->tpl[NF9_OUT_VLAN].len && *(pptrs->f_data+tpl->tpl[NF9_OUT_VLAN].off) > 0)) {
      ret += PM_FTYPE_VLAN;
    }

    if (tpl->tpl[NF9_MPLS_LABEL_1].len /* check: value > 0 ? */) {
      ret += PM_FTYPE_MPLS;
    }

    /* Explicit IP protocol definition first; a bit of heuristics as fallback */
    if (tpl->tpl[NF9_IP_PROTOCOL_VERSION].len) {
      if (*(pptrs->f_data+tpl->tpl[NF9_IP_PROTOCOL_VERSION].off) == 4) {
	ret += PM_FTYPE_IPV4;
	have_ip_proto = TRUE;
      }
      else if (*(pptrs->f_data+tpl->tpl[NF9_IP_PROTOCOL_VERSION].off) == 6) {
	ret += PM_FTYPE_IPV6;
	have_ip_proto = TRUE;
      }
    }

    if (!have_ip_proto) {
      /* If we have both v4 and v6 as part of the same flow, let's run the
	 cheapest check possible to try to determine which one is non-zero */
      if ((tpl->tpl[NF9_IPV4_SRC_ADDR].len || tpl->tpl[NF9_IPV4_DST_ADDR].len) &&
	  (tpl->tpl[NF9_IPV6_SRC_ADDR].len || tpl->tpl[NF9_IPV6_DST_ADDR].len)) {
	if (*(pptrs->f_data+tpl->tpl[NF9_IPV4_SRC_ADDR].off) != 0) {
          ret += PM_FTYPE_IPV4;
	  have_ip_proto = TRUE;
	}
	else {
	  ret += PM_FTYPE_IPV6;
	  have_ip_proto = TRUE;
	}
      }
      else if (tpl->tpl[NF9_IPV4_SRC_ADDR].len || tpl->tpl[NF9_IPV4_DST_ADDR].len) {
        ret += PM_FTYPE_IPV4;
	have_ip_proto = TRUE;
      }
      else if (tpl->tpl[NF9_IPV6_SRC_ADDR].len || tpl->tpl[NF9_IPV6_DST_ADDR].len) {
	ret += PM_FTYPE_IPV6;
	have_ip_proto = TRUE;
      }
    }

    if (tpl->tpl[NF9_DATALINK_FRAME_SECTION].len || tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len) {
      ret = NF9_FTYPE_DLFS;
    }

    if (tpl->tpl[NF9_INITIATOR_OCTETS].len && tpl->tpl[NF9_RESPONDER_OCTETS].len) {
      flow_type->is_bi = TRUE;
    }
  }

  /* second round: overrides */

  /* NetFlow Event Logging (NEL): generic NAT event support */
  if (tpl->tpl[NF9_NAT_EVENT].len) ret = NF9_FTYPE_NAT_EVENT;

  /* NetFlow/IPFIX option final override */
  if (tpl->template_type == 1) ret = NF9_FTYPE_OPTION;

  flow_type->traffic_type = ret;
}

u_int16_t NF_evaluate_direction(struct template_cache_entry *tpl, struct packet_ptrs *pptrs)
{
  u_int16_t ret = DIRECTION_IN;

  if (tpl->tpl[NF9_DIRECTION].len && *(pptrs->f_data+tpl->tpl[NF9_DIRECTION].off) == 1) ret = DIRECTION_OUT;

  return ret;
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

void reset_dummy_v4(struct packet_ptrs *pptrs, u_char *dummy_packet)
{
  pptrs->packet_ptr = dummy_packet;
  /* pptrs->pkthdr = dummy_pkthdr; */
  Assign16(((struct eth_header *)pptrs->packet_ptr)->ether_type, htons(ETHERTYPE_IP));
  pptrs->mac_ptr = (u_char *)((struct eth_header *)pptrs->packet_ptr)->ether_dhost;
  pptrs->iph_ptr = pptrs->packet_ptr + ETHER_HDRLEN;
  pptrs->tlh_ptr = pptrs->packet_ptr + ETHER_HDRLEN + sizeof(struct pm_iphdr);
  Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_vhl, 5);
  pptrs->pkthdr->caplen = 55;
  pptrs->pkthdr->len = 100;
  pptrs->l3_proto = ETHERTYPE_IP;
}

void notify_malf_packet(short int severity, char *severity_str, char *ostr, struct sockaddr *sa, u_int32_t seq)
{
  struct host_addr a;
  char errstr[SRVBUFLEN];
  char agent_addr[50] /* able to fit an IPv6 string aswell */, any[] = "0.0.0.0";
  u_int16_t agent_port;

  sa_to_addr((struct sockaddr *)sa, &a, &agent_port);
  addr_to_str(agent_addr, &a);

  if (seq) snprintf(errstr, SRVBUFLEN, "%s ( %s/core ): %s: nfacctd=%s:%u agent=%s:%u seq=%u\n",
		severity_str, config.name, ostr, ((config.nfacctd_ip) ? config.nfacctd_ip : any),
		collector_port, agent_addr, agent_port, seq);
  else snprintf(errstr, SRVBUFLEN, "%s ( %s/core ): %s: nfacctd=%s:%u agent=%s:%u\n",
		severity_str, config.name, ostr, ((config.nfacctd_ip) ? config.nfacctd_ip : any),
		collector_port, agent_addr, agent_port);

  Log(severity, "%s", errstr);
}

int NF_find_id(struct id_table *t, struct packet_ptrs *pptrs, pm_id_t *tag, pm_id_t *tag2)
{
  struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
  struct sockaddr *sa = NULL;
  u_char *saved_f_agent = NULL;
  int x, begin = 0, end = 0;
  pm_id_t ret = 0;

  if (!t) return 0;

  /* if NF9_EXPORTER_IPV[46]_ADDRESS from NetFlow v9/IPFIX options, use it */
  if (entry && entry->exp_sa.sa_family) {
    saved_f_agent = pptrs->f_agent;
    pptrs->f_agent = (u_char *) &entry->exp_sa;
  }

  sa = (struct sockaddr *) pptrs->f_agent;

  /* The id_table is shared between by IPv4 and IPv6 NetFlow agents.
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
      if (!(ret & PRETAG_MAP_RCODE_JEQ)) goto exit_lane;
    }

    /* if we have at least one index we trust we did a good job */
    goto exit_lane;
  }

  if (sa->sa_family == AF_INET) {
    begin = 0;
    end = t->ipv4_num;
  }
  else if (sa->sa_family == AF_INET6) {
    begin = t->num-t->ipv6_num;
    end = t->num;
  }

  for (x = begin; x < end; x++) {
    if (host_addr_mask_sa_cmp(&t->e[x].key.agent_ip.a, &t->e[x].key.agent_mask, sa) == 0) {
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

  exit_lane:
  if (entry && entry->exp_sa.sa_family) pptrs->f_agent = saved_f_agent; 

  return ret;
}

struct xflow_status_entry *nfv5_check_status(struct packet_ptrs *pptrs)
{
  struct struct_header_v5 *hdr = (struct struct_header_v5 *) pptrs->f_header;
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent;
  u_int32_t aux1 = (hdr->engine_id << 8 | hdr->engine_type);
  int hash = hash_status_table(aux1, sa, XFLOW_STATUS_TABLE_SZ);
  struct xflow_status_entry *entry = NULL;
  
  if (hash >= 0) {
    entry = search_status_table(&xflow_status_table, sa, aux1, 0, hash, XFLOW_STATUS_TABLE_MAX_ENTRIES);
    if (entry) {
      update_status_table(entry, ntohl(hdr->flow_sequence), pptrs->f_len);
      entry->inc = ntohs(hdr->count);
    }
  }

  return entry;
}

struct xflow_status_entry *nfv9_check_status(struct packet_ptrs *pptrs, u_int32_t sid, u_int32_t flags, u_int32_t seq, u_int8_t update)
{
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent;
  int hash = hash_status_table(sid, sa, XFLOW_STATUS_TABLE_SZ);
  struct xflow_status_entry *entry = NULL;
  
  if (hash >= 0) {
    entry = search_status_table(&xflow_status_table, sa, sid, flags, hash, XFLOW_STATUS_TABLE_MAX_ENTRIES);
    if (entry && update) {
      update_status_table(entry, seq, pptrs->f_len);
      entry->inc = 1;
    }
  }

  return entry;
}

void NF_process_classifiers(struct packet_ptrs *pptrs_main, struct packet_ptrs *pptrs, unsigned char *pkt, struct template_cache_entry *tpl)
{
  if (tpl->tpl[NF9_APPLICATION_ID].len == 2 || tpl->tpl[NF9_APPLICATION_ID].len == 3 || tpl->tpl[NF9_APPLICATION_ID].len == 5) {
    struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs_main->f_status;
    struct xflow_status_entry *gentry = (struct xflow_status_entry *) pptrs_main->f_status_g;
    pm_class_t class_id = 0;

    memcpy(&class_id, (pkt + tpl->tpl[NF9_APPLICATION_ID].off + 1), (tpl->tpl[NF9_APPLICATION_ID].len - 1));
    if (entry) pptrs->class = NF_evaluate_classifiers(entry->class, &class_id, gentry);
  }
}

pm_class_t NF_evaluate_classifiers(struct xflow_status_entry_class *entry, pm_class_t *class_id, struct xflow_status_entry *gentry)
{
  struct xflow_status_entry_class *centry;

  /* Try #1: let's see if we have a matching class for the given SourceId/ObservedDomainId */
  centry = search_class_id_status_table(entry, *class_id);
  if (centry) {
    return centry->class_int_id;
  }

  /* Try #2: let's chance if we have a global option */
  if (gentry) {
    centry = search_class_id_status_table(gentry->class, *class_id);
    if (centry) {
      return centry->class_int_id;
    }
  }

  return 0;
}

void nfv9_datalink_frame_section_handler(struct packet_ptrs *pptrs)
{
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  struct utpl_field *utpl = NULL;
  u_int16_t frame_type = NF9_DL_F_TYPE_UNKNOWN, t16, idx;

  /* cleanups */
  reset_index_pkt_ptrs(pptrs);
  pptrs->packet_ptr = pptrs->mac_ptr = pptrs->vlan_ptr = pptrs->mpls_ptr = NULL;
  pptrs->iph_ptr = pptrs->tlh_ptr = pptrs->payload_ptr = NULL;
  pptrs->l3_proto = pptrs->l4_proto = FALSE;
#if defined (WITH_NDPI)
  memset(&pptrs->ndpi_class, 0, sizeof(pm_class2_t));
#endif

  if ((utpl = (*get_ext_db_ie_by_type)(tpl, 0, NF9_DATALINK_FRAME_TYPE, FALSE))) {
    memcpy(&t16, pptrs->f_data+utpl->off, MIN(utpl->len, 2));
    frame_type = ntohs(t16);
  }
  /* XXX: in case of no NF9_DATALINK_FRAME_TYPE, let's assume Ethernet */
  else frame_type = NF9_DL_F_TYPE_ETHERNET;

  if (tpl->tpl[NF9_LAYER2_PKT_SECTION_DATA].len) {
    idx = NF9_LAYER2_PKT_SECTION_DATA;
  }
  else {
    idx = NF9_DATALINK_FRAME_SECTION;
  }

  if (tpl->tpl[idx].len) {
    pptrs->pkthdr->caplen = tpl->tpl[idx].len;
    pptrs->packet_ptr = (u_char *) pptrs->f_data+tpl->tpl[idx].off;

    if (frame_type == NF9_DL_F_TYPE_ETHERNET) {
      eth_handler(pptrs->pkthdr, pptrs);
      if (pptrs->iph_ptr) {
	if ((*pptrs->l3_handler)(pptrs)) {
#if defined (WITH_NDPI)
	  if (config.classifier_ndpi && pm_ndpi_wfl) {
	    pptrs->ndpi_class = pm_ndpi_workflow_process_packet(pm_ndpi_wfl, pptrs);
	  }
#endif
	  set_index_pkt_ptrs(pptrs);
	}
      }
    }
  }
}

#ifdef WITH_KAFKA
void NF_init_kafka_host(void *kh)
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
void NF_init_zmq_host(void *zh, int *pipe_fd)
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
