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

/* defines */
#define __NFACCTD_C

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "nfacctd.h"
#include "pretag_handlers.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "ip_flow.h"
#include "classifier.h"
#include "net_aggr.h"
#include "bgp/bgp_packet.h"
#include "bgp/bgp.h"
#include "isis/isis.h"
#include "bmp/bmp.h"
#include "nfv8_handlers.h"
#include "telemetry/telemetry.h"

/* variables to be exported away */
struct channels_list_entry channels_list[MAX_N_PLUGINS]; /* communication channels: core <-> plugins */

/* Functions */
void usage_daemon(char *prog_name)
{
  printf("%s (%s)\n", NFACCTD_USAGE_HEADER, PMACCT_BUILD);
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
  printf("  -W  \tReading from a savefile, don't exit but sleep when finished\n");
  printf("\nMemory plugin (-P memory) options:\n");
  printf("  -p  \tSocket for client-server communication (DEFAULT: /tmp/collect.pipe)\n");
  printf("  -b  \tNumber of buckets\n");
  printf("  -m  \tNumber of memory pools\n");
  printf("  -s  \tMemory pool size\n");
  printf("\nPrint plugin (-P print) plugin options:\n");
  printf("  -r  \tRefresh time (in seconds)\n");
  printf("  -O  \t[ formatted | csv | json | avro ] \n\tOutput format\n");
  printf("  -o  \tPath to output file\n");
  printf("  -A  \tAppend output (applies to -o)\n");
  printf("  -E  \tCSV format serparator (applies to -O csv, DEFAULT: ',')\n");
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
  int logf, rc, yes=1, no=0, allowed;
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

#if defined ENABLE_IPV6
  struct sockaddr_storage server, client;
  struct ipv6_mreq multi_req6;
#else
  struct sockaddr server, client;
#endif
  int clen = sizeof(client), slen;
  struct ip_mreq multi_req4;

  struct pcap_device device;

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

#if defined HAVE_MALLOPT
  mallopt(M_CHECK_ACTION, 0);
#endif

  umask(077);
  NF_compute_once();

  /* a bunch of default definitions */ 
  reload_map = FALSE;
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

  data_plugins = 0;
  tee_plugins = 0;
  xflow_status_table_entries = 0;
  xflow_tot_bad_datagrams = 0;
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

  memset(&bpas_table, 0, sizeof(bpas_table));
  memset(&blp_table, 0, sizeof(blp_table));
  memset(&bmed_table, 0, sizeof(bmed_table));
  memset(&biss_table, 0, sizeof(biss_table));
  memset(&bta_table, 0, sizeof(bta_table));
  memset(&bitr_table, 0, sizeof(bitr_table));
  memset(&sampling_table, 0, sizeof(sampling_table));
  memset(&reload_map_tstamp, 0, sizeof(reload_map_tstamp));
  log_notifications_init(&log_notifications);
  config.acct_type = ACCT_NF;

  rows = 0;
  glob_pcapt = NULL;

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
    case 'A':
      strlcpy(cfg_cmdline[rows], "print_output_file_append: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
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
    case 'h':
      usage_daemon(argv[0]);
      exit(0);
      break;
    case 'V':
      version_daemon(NFACCTD_USAGE_HEADER);
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
    set_default_preferences(&list->cfg);
    if (!strcmp(list->type.string, "core")) { 
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
      if (!strcmp(list->type.string, "print") && !list->cfg.print_output_file)
	printf("INFO ( %s/%s ): Daemonizing. Bye bye screen.\n", list->name, list->type.string);
      list = list->next;
    }
    if (debug || config.debug)
      printf("WARN ( %s/core ): debug is enabled; forking in background. Logging to standard error (stderr) will get lost.\n", config.name); 
    daemonize();
  }

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

  if (config.logfile)
  {
    config.logfile_fd = open_output_file(config.logfile, "a", FALSE);
    list = plugins_list;
    while (list) {
      list->cfg.logfile_fd = config.logfile_fd ;
      list = list->next;
    }
  }

  if (config.proc_priority) {
    int ret;

    ret = setpriority(PRIO_PROCESS, 0, config.proc_priority);
    if (ret) Log(LOG_WARNING, "WARN ( %s/core ): proc_priority failed (errno: %d)\n", config.name, errno); 
    else Log(LOG_INFO, "INFO ( %s/core ): proc_priority set to %d\n", config.name, getpriority(PRIO_PROCESS, 0));
  }

  Log(LOG_INFO, "INFO ( %s/core ): %s (%s)\n", config.name, NFACCTD_USAGE_HEADER, PMACCT_BUILD);
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
        exit(1);
      }

      /* applies to specific plugins */
      if (list->type.id == PLUGIN_ID_NFPROBE || list->type.id == PLUGIN_ID_SFPROBE) {
	Log(LOG_ERR, "ERROR ( %s/core ): 'nfprobe' and 'sfprobe' plugins not supported in 'nfacctd'.\n", config.name);
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
			COUNT_TIMESTAMP_START|COUNT_TIMESTAMP_END|COUNT_TIMESTAMP_ARRIVAL))
	  list->cfg.data_type |= PIPE_TYPE_NAT;

	if (list->cfg.what_to_count_2 & (COUNT_MPLS_LABEL_TOP|COUNT_MPLS_LABEL_BOTTOM|
			COUNT_MPLS_STACK_DEPTH))
	  list->cfg.data_type |= PIPE_TYPE_MPLS;

	if (list->cfg.what_to_count_2 & (COUNT_TUNNEL_SRC_HOST|COUNT_TUNNEL_DST_HOST|
			COUNT_TUNNEL_IP_PROTO|COUNT_TUNNEL_IP_TOS))
	  list->cfg.data_type |= PIPE_TYPE_TUN;

	if (list->cfg.what_to_count_2 & (COUNT_LABEL))
	  list->cfg.data_type |= PIPE_TYPE_VLEN;

	evaluate_sums(&list->cfg.what_to_count, &list->cfg.what_to_count_2, list->name, list->type.string);
	if (!list->cfg.what_to_count && !list->cfg.what_to_count_2 && !list->cfg.cpptrs.num) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): defaulting to SRC HOST aggregation.\n", list->name, list->type.string);
	  list->cfg.what_to_count |= COUNT_SRC_HOST;
	}
	if (list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) {
	  if (!list->cfg.networks_file && list->cfg.nfacctd_as & NF_AS_NEW) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation selected but NO 'networks_file' specified. Exiting...\n\n", list->name, list->type.string);
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
    exit(1);
  }
  
  if (config.pcap_savefile && (config.nfacctd_port || config.nfacctd_ip)) {
    Log(LOG_ERR, "ERROR ( %s/core ): 'pcap_savefile' is mutual exclusive with live collection, ie. 'nfacctd_ip' and/or 'nfacctd_port' Exiting...\n\n", config.name);
    exit(1);
  }

  /* signal handling we want to inherit to plugins (when not re-defined elsewhere) */
  signal(SIGCHLD, startup_handle_falling_child); /* takes note of plugins failed during startup phase */
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGUSR1, push_stats); /* logs various statistics via Log() calls */ 
  signal(SIGUSR2, reload_maps); /* sets to true the reload_maps flag */
  signal(SIGPIPE, SIG_IGN); /* we want to exit gracefully when a pipe is broken */

  if (config.pcap_savefile) {
    open_pcap_savefile(&device, config.pcap_savefile);
    config.handle_fragments = TRUE;
    init_ip_fragment_handler();
  }
  else {
    /* If no IP address is supplied, let's set our default
       behaviour: IPv4 address, INADDR_ANY, port 2100 */
    if (!config.nfacctd_port) config.nfacctd_port = DEFAULT_NFACCTD_PORT;
#if (defined ENABLE_IPV6)
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
	Log(LOG_ERR, "ERROR ( %s/core ): 'nfacctd_ip' value is not valid. Exiting.\n", config.name);
	exit(1);
      }
      slen = addr_to_sa((struct sockaddr *)&server, &addr, config.nfacctd_port);
    }

    /* socket creation */
    config.sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);
    if (config.sock < 0) {
#if (defined ENABLE_IPV6)
      /* retry with IPv4 */
      if (!config.nfacctd_ip) {
	struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

	sa4->sin_family = AF_INET;
	sa4->sin_addr.s_addr = htonl(0);
	sa4->sin_port = htons(config.nfacctd_port);
	slen = sizeof(struct sockaddr_in);

	config.sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);
      }
#endif

      if (config.sock < 0) {
	Log(LOG_ERR, "ERROR ( %s/core ): socket() failed.\n", config.name);
	exit(1);
      }
    }

    /* bind socket to port */
    rc = setsockopt(config.sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for SO_REUSEADDR.\n", config.name);

#if (defined ENABLE_IPV6) && (defined IPV6_BINDV6ONLY)
    rc = setsockopt(config.sock, IPPROTO_IPV6, IPV6_BINDV6ONLY, (char *) &no, (socklen_t) sizeof(no));
    if (rc < 0) Log(LOG_ERR, "WARN ( %s/core ): setsockopt() failed for IPV6_BINDV6ONLY.\n", config.name);
#endif

    if (config.nfacctd_pipe_size) {
      int l = sizeof(config.nfacctd_pipe_size);
      int saved = 0, obtained = 0;

      getsockopt(config.sock, SOL_SOCKET, SO_RCVBUF, &saved, &l);
      Setsocksize(config.sock, SOL_SOCKET, SO_RCVBUF, &config.nfacctd_pipe_size, sizeof(config.nfacctd_pipe_size));
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
	if (setsockopt(config.sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&multi_req4, sizeof(multi_req4)) < 0) {
	  Log(LOG_ERR, "ERROR ( %s/core ): IPv4 multicast address - ADD membership failed.\n", config.name);
	  exit(1);
	}
      }
#if defined ENABLE_IPV6
      if (mcast_groups[idx].family == AF_INET6) {
	memset(&multi_req6, 0, sizeof(multi_req6));
	ip6_addr_cpy(&multi_req6.ipv6mr_multiaddr, &mcast_groups[idx].address.ipv6); 
	if (setsockopt(config.sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&multi_req6, sizeof(multi_req6)) < 0) {
	  Log(LOG_ERR, "ERROR ( %s/core ): IPv6 multicast address - ADD membership failed.\n", config.name);
	  exit(1);
	}
      }
#endif
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
    load_comm_patterns(&config.nfacctd_bgp_stdcomm_pattern, &config.nfacctd_bgp_extcomm_pattern,
			&config.nfacctd_bgp_lrgcomm_pattern, &config.nfacctd_bgp_stdcomm_pattern_to_asn);

    if (config.nfacctd_bgp_peer_as_src_type == BGP_SRC_PRIMITIVES_MAP) {
      if (config.nfacctd_bgp_peer_as_src_map) {
        load_id_file(MAP_BGP_PEER_AS_SRC, config.nfacctd_bgp_peer_as_src_map, &bpas_table, &req, &bpas_map_allocated);
        pptrs.v4.bpas_table = (u_char *) &bpas_table;
      }
      else {
	Log(LOG_ERR, "ERROR ( %s/core ): bgp_peer_as_src_type set to 'map' but no map defined. Exiting.\n", config.name);
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
	Log(LOG_ERR, "ERROR ( %s/core ): bgp_src_local_pref_type set to 'map' but no map defined. Exiting.\n", config.name);
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
	Log(LOG_ERR, "ERROR ( %s/core ): bgp_src_med_type set to 'map' but no map defined. Exiting.\n", config.name);
	exit(1);
      }
    }
    else pptrs.v4.bmed_table = NULL;

    if (config.nfacctd_bgp_to_agent_map) {
      load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.nfacctd_bgp_to_agent_map, &bta_table, &req, &bta_map_allocated);
      pptrs.v4.bta_table = (u_char *) &bta_table;
    }
    else pptrs.v4.bta_table = NULL;

    nfacctd_bgp_wrapper();

    /* Let's give the BGP thread some advantage to create its structures */
    sleep(5);
  }

  /* starting the BMP thread */
  if (config.nfacctd_bmp) {
    req.bpf_filter = TRUE;

    nfacctd_bmp_wrapper();

    /* Let's give the BMP thread some advantage to create its structures */
    sleep(5);
  }

  /* starting the telemetry thread */
  if (config.telemetry_daemon) {
    telemetry_wrapper();

    /* Let's give the telemetry thread some advantage to create its structures */
    sleep(5);
  }
#else
  if (config.nfacctd_isis) {
    Log(LOG_ERR, "ERROR ( %s/core ): 'isis_daemon' is available only with threads (--enable-threads). Exiting.\n", config.name);
    exit(1);
  }

  if (config.nfacctd_bgp) {
    Log(LOG_ERR, "ERROR ( %s/core ): 'bgp_daemon' is available only with threads (--enable-threads). Exiting.\n", config.name);
    exit(1);
  }

  if (config.nfacctd_bmp) {
    Log(LOG_ERR, "ERROR ( %s/core ): 'bmp_daemon' is available only with threads (--enable-threads). Exiting.\n", config.name);
    exit(1);
  }

  if (config.telemetry_daemon) {
    Log(LOG_ERR, "ERROR ( %s/core ): 'telemetry_daemon' is available only with threads (--enable-threads). Exiting.\n", config.name);
    exit(1);
  }
#endif

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

  if (!config.pcap_savefile) {
    rc = bind(config.sock, (struct sockaddr *) &server, slen);
    if (rc < 0) {
      Log(LOG_ERR, "ERROR ( %s/core ): bind() to ip=%s port=%d/udp failed (errno: %d).\n", config.name, config.nfacctd_ip, config.nfacctd_port, errno);
      exit(1);
    }
  }

  load_nfv8_handlers();

  init_classifiers(NULL);

  /* plugins glue: creation */
  load_plugins(&req);
  load_plugin_filters(1);
  evaluate_packet_handlers();
  pm_setproctitle("%s [%s]", "Core Process", config.proc_name);
  if (config.pidfile) write_pid_file(config.pidfile);
  load_networks(config.networks_file, &nt, &nc);

  /* signals to be handled only by the core process;
     we set proper handlers after plugin creation */
  signal(SIGINT, my_sigint_handler);
  signal(SIGTERM, my_sigint_handler);
  signal(SIGCHLD, handle_falling_child);
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
  Assign16(*(pptrs.vlanmpls4.vlan_ptr+2), htons(ETHERTYPE_MPLS));
  pptrs.vlanmpls4.mpls_ptr = pptrs.vlanmpls4.packet_ptr + ETHER_HDRLEN + IEEE8021Q_TAGLEN;
  // pptrs.vlanmpls4.pkthdr->caplen = 82; /* eth_header + vlan + upto 10 MPLS labels + pm_iphdr + pm_tlhdr */
  pptrs.vlanmpls4.pkthdr->caplen = 99; 
  pptrs.vlanmpls4.pkthdr->len = 100; /* fake len */
  pptrs.vlanmpls4.l3_proto = ETHERTYPE_IP;

#if defined ENABLE_IPV6
  memset(dummy_packet6, 0, sizeof(dummy_packet6));
  pptrs.v6.f_agent = (u_char *) &client;
  pptrs.v6.packet_ptr = dummy_packet6;
  pptrs.v6.pkthdr = &dummy_pkthdr6;
  Assign16(((struct eth_header *)pptrs.v6.packet_ptr)->ether_type, htons(ETHERTYPE_IPV6)); 
  pptrs.v6.mac_ptr = (u_char *)((struct eth_header *)pptrs.v6.packet_ptr)->ether_dhost; 
  pptrs.v6.iph_ptr = pptrs.v6.packet_ptr + ETHER_HDRLEN;
  pptrs.v6.tlh_ptr = pptrs.v6.packet_ptr + ETHER_HDRLEN + sizeof(struct ip6_hdr);
  Assign16(((struct ip6_hdr *)pptrs.v6.iph_ptr)->ip6_plen, htons(100));
  Assign16(((struct ip6_hdr *)pptrs.v6.iph_ptr)->ip6_hlim, htons(64));
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
  Assign16(((struct ip6_hdr *)pptrs.vlan6.iph_ptr)->ip6_hlim, htons(64));
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
#endif

  if (!config.pcap_savefile) {
    char srv_string[INET6_ADDRSTRLEN];
    struct host_addr srv_addr;
    u_int16_t srv_port;

    sa_to_addr((struct sockaddr *)&server, &srv_addr, &srv_port); 
    addr_to_str(srv_string, &srv_addr);
    Log(LOG_INFO, "INFO ( %s/core ): waiting for NetFlow/IPFIX data on %s:%u\n", config.name, srv_string, srv_port);
    allowed = TRUE;
  }
  else {
    Log(LOG_INFO, "INFO ( %s/core ): reading NetFlow/IPFIX data from: %s\n", config.name, config.pcap_savefile);
    allowed = TRUE;
    sleep(2);
  }

  /* fixing NetFlow v9/IPFIX template func pointers */
  get_ext_db_ie_by_type = &ext_db_get_ie;

  /* Main loop */
  for (;;) {
    if (!config.pcap_savefile) {
      ret = recvfrom(config.sock, netflow_packet, NETFLOW_MSG_SIZE, 0, (struct sockaddr *) &client, &clen);
    }
    else {
      ret = recvfrom_savefile(&device, (void **) &netflow_packet, (struct sockaddr *) &client, NULL);
    }

    /* we have no data or not not enough data to decode the version */
    if (!netflow_packet || ret < 2) continue;
    pptrs.v4.f_len = ret;

#if defined ENABLE_IPV6
    ipv4_mapped_to_ipv4(&client);
#endif

    /* check if Hosts Allow Table is loaded; if it is, we will enforce rules */
    if (allow.num) allowed = check_allow(&allow, (struct sockaddr *)&client); 
    if (!allowed) continue;

    if (reload_map) {
      bta_map_caching = TRUE;
      sampling_map_caching = TRUE;
      req.key_value_table = NULL;

      load_networks(config.networks_file, &nt, &nc);

      if (config.nfacctd_bgp && config.nfacctd_bgp_peer_as_src_map) 
        load_id_file(MAP_BGP_PEER_AS_SRC, config.nfacctd_bgp_peer_as_src_map, &bpas_table, &req, &bpas_map_allocated); 
      if (config.nfacctd_bgp && config.nfacctd_bgp_src_local_pref_map) 
        load_id_file(MAP_BGP_SRC_LOCAL_PREF, config.nfacctd_bgp_src_local_pref_map, &blp_table, &req, &blp_map_allocated); 
      if (config.nfacctd_bgp && config.nfacctd_bgp_src_med_map) 
        load_id_file(MAP_BGP_SRC_MED, config.nfacctd_bgp_src_med_map, &bmed_table, &req, &bmed_map_allocated); 
      if (config.nfacctd_bgp && config.nfacctd_bgp_to_agent_map)
        load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.nfacctd_bgp_to_agent_map, &bta_table, &req, &bta_map_allocated);
      if (config.nfacctd_flow_to_rd_map)
        load_id_file(MAP_FLOW_TO_RD, config.nfacctd_flow_to_rd_map, &bitr_table, &req, &bitr_map_allocated);
      if (config.sampling_map) {
        load_id_file(MAP_SAMPLING, config.sampling_map, &sampling_table, &req, &sampling_map_allocated);
        set_sampling_table(&pptrs, (u_char *) &sampling_table);
      }

      reload_map = FALSE;
      gettimeofday(&reload_map_tstamp, NULL);
    }

    if (data_plugins) {
      /* We will change byte ordering in order to avoid a bunch of ntohs() calls */
      ((struct struct_header_v5 *)netflow_packet)->version = ntohs(((struct struct_header_v5 *)netflow_packet)->version);
      reset_tag_label_status(&pptrs);
      reset_shadow_status(&pptrs);

      switch(((struct struct_header_v5 *)netflow_packet)->version) {
      case 1:
	process_v1_packet(netflow_packet, ret, &pptrs.v4, &req);
	break;
      case 5:
	process_v5_packet(netflow_packet, ret, &pptrs.v4, &req); 
	break;
      case 7:
	process_v7_packet(netflow_packet, ret, &pptrs.v4, &req);
	break;
      case 8:
	process_v8_packet(netflow_packet, ret, &pptrs.v4, &req);
	break;
      /* NetFlow v9 + IPFIX */
      case 9:
      case 10:
	process_v9_packet(netflow_packet, ret, &pptrs, &req, ((struct struct_header_v5 *)netflow_packet)->version);
	break;
      default:
        if (!config.nfacctd_disable_checks) {
	  notify_malf_packet(LOG_INFO, "INFO: Discarding unknown packet", (struct sockaddr *) pptrs.v4.f_agent, 0);
	  xflow_tot_bad_datagrams++;
        }
	break;
      }
    }
    else if (tee_plugins) {
      process_raw_packet(netflow_packet, ret, &pptrs, &req);
    }
  }
}

void process_v1_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs *pptrs,
		struct plugin_requests *req)
{
  struct struct_header_v1 *hdr_v1 = (struct struct_header_v1 *)pkt;
  struct struct_export_v1 *exp_v1;
  unsigned short int count = ntohs(hdr_v1->count);

  if (len < NfHdrV1Sz) {
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v1 packet", (struct sockaddr *) pptrs->f_agent, 0);
    xflow_tot_bad_datagrams++;
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV1Sz; 
  exp_v1 = (struct struct_export_v1 *)pkt;

  reset_mac(pptrs);
  pptrs->flow_type = NF9_FTYPE_TRAFFIC;

  if ((count <= V1_MAXFLOWS) && ((count*NfDataV1Sz)+NfHdrV1Sz == len)) {
    while (count) {
      reset_net_status(pptrs);
      pptrs->f_data = (unsigned char *) exp_v1;
      if (req->bpf_filter) {
        Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp_v1->srcaddr.s_addr);
        Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp_v1->dstaddr.s_addr);
        Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_p, exp_v1->prot);
        Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, exp_v1->tos);
        Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->src_port, exp_v1->srcport);
        Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->dst_port, exp_v1->dstport);
      }
      /* Let's copy some relevant field */
      pptrs->l4_proto = exp_v1->prot;

      /* IP header's id field is unused; we will use it to transport our id */
      if (config.nfacctd_isis) isis_srcdst_lookup(pptrs);
      if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, pptrs, &pptrs->bta, &pptrs->bta2);
      if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, pptrs, &pptrs->bitr, NULL);
      if (config.nfacctd_bgp) bgp_srcdst_lookup(pptrs, FUNC_TYPE_BGP);
      if (config.nfacctd_bgp_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, pptrs, &pptrs->bpas, NULL);
      if (config.nfacctd_bgp_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, pptrs, &pptrs->blp, NULL);
      if (config.nfacctd_bgp_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, pptrs, &pptrs->bmed, NULL);
      if (config.nfacctd_bmp) bmp_srcdst_lookup(pptrs);
      exec_plugins(pptrs, req);
      exp_v1++;           
      count--;             
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO: discarding malformed NetFlow v1 packet", (struct sockaddr *) pptrs->f_agent, 0);
    xflow_tot_bad_datagrams++;
    return;
  }
}

void process_v5_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs *pptrs,
		struct plugin_requests *req)
{
  struct struct_header_v5 *hdr_v5 = (struct struct_header_v5 *)pkt;
  struct struct_export_v5 *exp_v5;
  unsigned short int count = ntohs(hdr_v5->count);

  if (len < NfHdrV5Sz) {
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v5 packet", (struct sockaddr *) pptrs->f_agent, 0);
    xflow_tot_bad_datagrams++;
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV5Sz; 
  exp_v5 = (struct struct_export_v5 *)pkt;
  pptrs->f_status = nfv578_check_status(pptrs);
  pptrs->f_status_g = NULL;

  reset_mac(pptrs);
  pptrs->flow_type = NF9_FTYPE_TRAFFIC;

  if ((count <= V5_MAXFLOWS) && ((count*NfDataV5Sz)+NfHdrV5Sz == len)) {
    if (config.debug) {
      sa_to_addr((struct sockaddr *)pptrs->f_agent, &debug_a, &debug_agent_port);
      addr_to_str(debug_agent_addr, &debug_a);

      Log(LOG_DEBUG, "DEBUG ( %s/core ): Received NetFlow packet from [%s:%u] version [%u] seqno [%u]\n",
                        config.name, debug_agent_addr, debug_agent_port, 5, ntohl(((struct struct_header_v5 *)pkt)->flow_sequence));
    }

    while (count) {
      reset_net_status(pptrs);
      pptrs->f_data = (unsigned char *) exp_v5;
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
      if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, pptrs, &pptrs->bta, &pptrs->bta2);
      if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, pptrs, &pptrs->bitr, NULL);
      if (config.nfacctd_bgp) bgp_srcdst_lookup(pptrs, FUNC_TYPE_BGP);
      if (config.nfacctd_bgp_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, pptrs, &pptrs->bpas, NULL);
      if (config.nfacctd_bgp_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, pptrs, &pptrs->blp, NULL);
      if (config.nfacctd_bgp_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, pptrs, &pptrs->bmed, NULL);
      if (config.nfacctd_bmp) bmp_srcdst_lookup(pptrs);
      exec_plugins(pptrs, req);
      exp_v5++;
      count--;
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO: discarding malformed NetFlow v5 packet", (struct sockaddr *) pptrs->f_agent, 0);
    xflow_tot_bad_datagrams++;
    return;
  }
} 

void process_v7_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs *pptrs,
                struct plugin_requests *req)
{
  struct struct_header_v7 *hdr_v7 = (struct struct_header_v7 *)pkt;
  struct struct_export_v7 *exp_v7;
  unsigned short int count = ntohs(hdr_v7->count);

  if (len < NfHdrV7Sz) {
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v7 packet", (struct sockaddr *) pptrs->f_agent, 0);
    xflow_tot_bad_datagrams++;
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV7Sz;
  exp_v7 = (struct struct_export_v7 *)pkt;
  pptrs->f_status = nfv578_check_status(pptrs);
  pptrs->f_status_g = NULL;

  reset_mac(pptrs);
  pptrs->flow_type = NF9_FTYPE_TRAFFIC;

  if ((count <= V7_MAXFLOWS) && ((count*NfDataV7Sz)+NfHdrV7Sz == len)) {
    while (count) {
      reset_net_status(pptrs);
      pptrs->f_data = (unsigned char *) exp_v7;
      if (req->bpf_filter) {
        Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp_v7->srcaddr);
        Assign32(((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp_v7->dstaddr);
        Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_p, exp_v7->prot);
        Assign8(((struct pm_iphdr *)pptrs->iph_ptr)->ip_tos, exp_v7->tos);
        Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->src_port, exp_v7->srcport);
        Assign16(((struct pm_tlhdr *)pptrs->tlh_ptr)->dst_port, exp_v7->dstport);
        Assign8(((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags, exp_v7->tcp_flags);
      }

      pptrs->lm_mask_src = exp_v7->src_mask;
      pptrs->lm_mask_dst = exp_v7->dst_mask;
      pptrs->lm_method_src = NF_NET_KEEP;
      pptrs->lm_method_dst = NF_NET_KEEP;

      /* Let's copy some relevant field */
      pptrs->l4_proto = exp_v7->prot;

      /* IP header's id field is unused; we will use it to transport our id */
      if (config.nfacctd_isis) isis_srcdst_lookup(pptrs);
      if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, pptrs, &pptrs->bta, &pptrs->bta2);
      if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, pptrs, &pptrs->bitr, NULL);
      if (config.nfacctd_bgp) bgp_srcdst_lookup(pptrs, FUNC_TYPE_BGP);
      if (config.nfacctd_bgp_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, pptrs, &pptrs->bpas, NULL);
      if (config.nfacctd_bgp_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, pptrs, &pptrs->blp, NULL);
      if (config.nfacctd_bgp_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, pptrs, &pptrs->bmed, NULL);
      if (config.nfacctd_bmp) bmp_srcdst_lookup(pptrs);
      exec_plugins(pptrs, req);
      exp_v7++;
      count--;
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO: discarding malformed NetFlow v7 packet", (struct sockaddr *) pptrs->f_agent, 0);
    xflow_tot_bad_datagrams++;
    return;
  }
}

void process_v8_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs *pptrs,
                struct plugin_requests *req)
{
  struct struct_header_v8 *hdr_v8 = (struct struct_header_v8 *)pkt;
  unsigned char *exp_v8;
  unsigned short int count = ntohs(hdr_v8->count);

  if (len < NfHdrV8Sz) {
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v8 packet", (struct sockaddr *) pptrs->f_agent, 0);
    xflow_tot_bad_datagrams++;
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV8Sz;
  exp_v8 = pkt;
  pptrs->f_status = nfv578_check_status(pptrs);
  pptrs->f_status_g = NULL;

  reset_mac(pptrs);
  reset_ip4(pptrs);
  pptrs->flow_type = NF9_FTYPE_TRAFFIC;

  if ((count <= v8_handlers[hdr_v8->aggregation].max_flows) && ((count*v8_handlers[hdr_v8->aggregation].exp_size)+NfHdrV8Sz <= len)) {
    while (count) {
      reset_net_status(pptrs);
      pptrs->f_data = exp_v8;
      if (req->bpf_filter) {
	/* XXX: nfacctd_net: network masks should be looked up here */ 
	v8_handlers[hdr_v8->aggregation].fh(pptrs, exp_v8);
      }

      /* IP header's id field is unused; we will use it to transport our id */
      if (config.nfacctd_isis) isis_srcdst_lookup(pptrs);
      if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, pptrs, &pptrs->bta, &pptrs->bta2);
      if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, pptrs, &pptrs->bitr, NULL);
      if (config.nfacctd_bgp) bgp_srcdst_lookup(pptrs, FUNC_TYPE_BGP);
      if (config.nfacctd_bgp_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, pptrs, &pptrs->bpas, NULL);
      if (config.nfacctd_bgp_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, pptrs, &pptrs->blp, NULL);
      if (config.nfacctd_bgp_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, pptrs, &pptrs->bmed, NULL);
      if (config.nfacctd_bmp) bmp_srcdst_lookup(pptrs);
      exec_plugins(pptrs, req);
      exp_v8 += v8_handlers[hdr_v8->aggregation].exp_size;
      count--;
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO: discarding malformed NetFlow v8 packet", (struct sockaddr *) pptrs->f_agent, 0);
    xflow_tot_bad_datagrams++;
    return;
  }
}

void process_v9_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs_vector *pptrsv,
		struct plugin_requests *req, u_int16_t version)
{
  struct struct_header_v9 *hdr_v9 = (struct struct_header_v9 *)pkt;
  struct struct_header_ipfix *hdr_v10 = (struct struct_header_ipfix *)pkt;
  struct template_hdr_v9 *template_hdr;
  struct options_template_hdr_v9 *opt_template_hdr;
  struct template_cache_entry *tpl;
  struct data_hdr_v9 *data_hdr;
  struct packet_ptrs *pptrs = &pptrsv->v4;
  u_int16_t fid, off = 0, flowoff, flowsetlen, flowsetNo, flowsetCount, direction, FlowSeqInc = 0; 
  u_int32_t HdrSz = 0, SourceId = 0, FlowSeq = 0;

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

  if (config.debug) {
    sa_to_addr((struct sockaddr *)pptrs->f_agent, &debug_a, &debug_agent_port);
    addr_to_str(debug_agent_addr, &debug_a);

    Log(LOG_DEBUG, "DEBUG ( %s/core ): Received NetFlow/IPFIX packet from [%s:%u] version [%u] seqno [%u]\n",
			config.name, debug_agent_addr, debug_agent_port, version, FlowSeq);
  }

  if (len < HdrSz) {
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v9/IPFIX packet", (struct sockaddr *) pptrsv->v4.f_agent, 0);
    xflow_tot_bad_datagrams++;
    return;
  }
  pptrs->f_header = pkt;
  pkt += HdrSz;
  off += HdrSz; 
  pptrsv->v4.f_status = nfv9_check_status(pptrs, SourceId, 0, FlowSeq, TRUE);
  set_vector_f_status(pptrsv);
  pptrsv->v4.f_status_g = nfv9_check_status(pptrs, 0, NF9_OPT_SCOPE_SYSTEM, 0, FALSE);
  set_vector_f_status_g(pptrsv);

  process_flowset:
  if (off+NfDataHdrV9Sz >= len) { 
    notify_malf_packet(LOG_INFO, "INFO: unable to read next Flowset (incomplete NetFlow v9/IPFIX packet)",
			(struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
    xflow_tot_bad_datagrams++;
    return;
  }

  data_hdr = (struct data_hdr_v9 *)pkt;

  if (data_hdr->flow_len == 0) {
    notify_malf_packet(LOG_INFO, "INFO: unable to read next Flowset (NetFlow v9/IPFIX packet claiming flow_len 0!)",
			(struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
    xflow_tot_bad_datagrams++;
    return;
  }

  fid = ntohs(data_hdr->flow_id);
  flowsetlen = ntohs(data_hdr->flow_len);
  if (flowsetlen < NfDataHdrV9Sz) {
    notify_malf_packet(LOG_INFO, "INFO: unable to read next Flowset (NetFlow v9/IPFIX packet (flowsetlen < NfDataHdrV9Sz)",
                        (struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
    xflow_tot_bad_datagrams++;
    return;
  }

  if (fid == 0 || fid == 2) { /* template: 0 NetFlow v9, 2 IPFIX */ 
    unsigned char *tpl_ptr = pkt;
    u_int16_t pens = 0;

    flowoff = 0;
    tpl_ptr += NfDataHdrV9Sz;
    flowoff += NfDataHdrV9Sz;

    while (flowoff < flowsetlen) {
      template_hdr = (struct template_hdr_v9 *) tpl_ptr;
      if (off+flowsetlen > len) { 
        notify_malf_packet(LOG_INFO, "INFO: unable to read next Template Flowset (incomplete NetFlow v9/IPFIX packet)",
		        (struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
        xflow_tot_bad_datagrams++;
        return;
      }

      tpl = handle_template(template_hdr, pptrs, fid, SourceId, &pens, flowsetlen-flowoff, FlowSeq);
      if (!tpl) return;

      tpl_ptr += sizeof(struct template_hdr_v9)+(ntohs(template_hdr->num)*sizeof(struct template_field_v9))+(pens*sizeof(u_int32_t)); 
      flowoff += sizeof(struct template_hdr_v9)+(ntohs(template_hdr->num)*sizeof(struct template_field_v9))+(pens*sizeof(u_int32_t)); 
    }

    pkt += flowsetlen; 
    off += flowsetlen; 
  }
  else if (fid == 1 || fid == 3) { /* options template: 1 NetFlow v9, 3 IPFIX */
    unsigned char *tpl_ptr = pkt;
    u_int16_t pens = 0;

    flowoff = 0;
    tpl_ptr += NfDataHdrV9Sz;
    flowoff += NfDataHdrV9Sz;

    while (flowoff < flowsetlen) {
      opt_template_hdr = (struct options_template_hdr_v9 *) tpl_ptr;
      if (off+flowsetlen > len) {
        notify_malf_packet(LOG_INFO, "INFO: unable to read next Options Template Flowset (incomplete NetFlow v9/IPFIX packet)",
                        (struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
        xflow_tot_bad_datagrams++;
        return;
      }

      tpl = handle_template((struct template_hdr_v9 *)opt_template_hdr, pptrs, fid, SourceId, &pens, flowsetlen-flowoff, FlowSeq);
      if (!tpl) return;

      /* Increment is not precise for NetFlow v9 but will work */
      tpl_ptr += sizeof(struct options_template_hdr_v9) +
		 (((ntohs(opt_template_hdr->scope_len) + ntohs(opt_template_hdr->option_len)) * sizeof(struct template_field_v9)) +
		 (pens * sizeof(u_int32_t)));
      flowoff += sizeof(struct options_template_hdr_v9) +
		 (((ntohs(opt_template_hdr->scope_len) + ntohs(opt_template_hdr->option_len)) * sizeof(struct template_field_v9)) +
		 (pens * sizeof(u_int32_t)));
    }

    pkt += flowsetlen;
    off += flowsetlen;
  }
  else if (fid >= 256) { /* data */
    if (off+flowsetlen > len) { 
      notify_malf_packet(LOG_INFO, "INFO: unable to read next Data Flowset (incomplete NetFlow v9/IPFIX packet)",
		      (struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
      xflow_tot_bad_datagrams++;
      return;
    }

    flowoff = 0;
    pkt += NfDataHdrV9Sz;
    flowoff += NfDataHdrV9Sz;

    tpl = find_template(data_hdr->flow_id, (struct host_addr *) pptrs->f_agent, fid, SourceId);
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

      while (flowoff+tpl->len <= flowsetlen) {
	entry = (struct xflow_status_entry *) pptrs->f_status;
	sentry = NULL, ssaved = NULL;
	centry = NULL, csaved = NULL;

	/* Is this option about sampling? */
	if (tpl->tpl[NF9_FLOW_SAMPLER_ID].len || tpl->tpl[NF9_SAMPLING_INTERVAL].len == 4 || tpl->tpl[NF9_SAMPLING_PKT_INTERVAL].len == 4) {
	  u_int8_t t8 = 0;
	  u_int16_t t16 = 0;
	  u_int32_t sampler_id = 0, t32 = 0, t32_2 = 0;
	  u_int64_t t64 = 0;

	  /* Handling the global option scoping case */
	  if (!config.nfacctd_disable_opt_scope_check) {
	    if (tpl->tpl[NF9_OPT_SCOPE_SYSTEM].len) entry = (struct xflow_status_entry *) pptrs->f_status_g;
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
	  if (!sentry) sentry = create_smp_entry_status_table(entry);
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
	else if (tpl->tpl[NF9_APPLICATION_ID].len == 4 && tpl->tpl[NF9_APPLICATION_NAME].len > 0) {
	  struct pkt_classifier css;
	  pm_class_t class_id = 0, class_int_id = 0;

	  /* Handling the global option scoping case */
	  if (!config.nfacctd_disable_opt_scope_check) {
	    if (tpl->tpl[NF9_OPT_SCOPE_SYSTEM].len) entry = (struct xflow_status_entry *) pptrs->f_status_g;
	  }
	  else entry = (struct xflow_status_entry *) pptrs->f_status_g;

	  memcpy(&class_id, pkt+tpl->tpl[NF9_APPLICATION_ID].off, 4);

          if (entry) centry = search_class_id_status_table(entry->class, class_id);
          if (!centry) {
	    centry = create_class_entry_status_table(entry);
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

	if (config.nfacctd_account_options) {
	  pptrs->f_data = pkt;
	  pptrs->f_tpl = (u_char *) tpl;
	  reset_net_status_v(pptrsv);
	  pptrs->flow_type = NF_evaluate_flow_type(tpl, pptrs);

	  exec_plugins(pptrs, req);
	}

        pkt += tpl->len;
        flowoff += tpl->len;

        FlowSeqInc++;
      }

      /* last pre-flight check for the subsequent subtraction */
      if (flowoff > flowsetlen) {
        notify_malf_packet(LOG_INFO, "INFO: aborting malformed Options Data element (incomplete NetFlow v9/IPFIX packet)",
                      (struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
        xflow_tot_bad_datagrams++;
        return;
      }
      
      pkt += (flowsetlen-flowoff); /* handling padding */
      off += flowsetlen;
    }
    else {
      while (flowoff+tpl->len <= flowsetlen) {
        /* Let's bake offsets and lengths if we have variable-length fields */
        if (tpl->vlen) {
	  resolve_vlen_template(pkt, flowsetlen, tpl);

	  /* with the record resolved, let's check against flowset length again */ 
	  if (flowoff+tpl->len > flowsetlen) break;
	}

        pptrs->f_data = pkt;
	pptrs->f_tpl = (u_char *) tpl;
	reset_net_status_v(pptrsv);
	pptrs->flow_type = NF_evaluate_flow_type(tpl, pptrs);
	direction = NF_evaluate_direction(tpl, pptrs);

	/* we need to understand the IP protocol version in order to build the fake packet */ 
	switch (pptrs->flow_type) {
	case NF9_FTYPE_IPV4:
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

	  if (tpl->tpl[NF9_APPLICATION_ID].len == 4) {
	    struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
	    struct xflow_status_entry *gentry = (struct xflow_status_entry *) pptrs->f_status_g;
	    pm_class_t class_id = 0;

	    memcpy(&class_id, pkt+tpl->tpl[NF9_APPLICATION_ID].off, 4);
	    if (entry) pptrs->class = NF_evaluate_classifiers(entry->class, &class_id, gentry);
	  }
	  if (config.nfacctd_isis) isis_srcdst_lookup(pptrs);
	  if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, pptrs, &pptrs->bta, &pptrs->bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, pptrs, &pptrs->bitr, NULL);
	  if (config.nfacctd_bgp) bgp_srcdst_lookup(pptrs, FUNC_TYPE_BGP);
	  if (config.nfacctd_bgp_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, pptrs, &pptrs->bpas, NULL);
	  if (config.nfacctd_bgp_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, pptrs, &pptrs->blp, NULL);
	  if (config.nfacctd_bgp_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, pptrs, &pptrs->bmed, NULL);
          if (config.nfacctd_bmp) bmp_srcdst_lookup(pptrs);
          exec_plugins(pptrs, req);
	  break;
#if defined ENABLE_IPV6
	case NF9_FTYPE_IPV6:
	  pptrsv->v6.f_header = pptrs->f_header;
	  pptrsv->v6.f_data = pptrs->f_data;
	  pptrsv->v6.f_tpl = pptrs->f_tpl;
	  pptrsv->v6.flow_type = pptrs->flow_type;

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

	  if (tpl->tpl[NF9_APPLICATION_ID].len == 4) {
	    struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
	    struct xflow_status_entry *gentry = (struct xflow_status_entry *) pptrs->f_status_g;
	    pm_class_t class_id = 0;

	    memcpy(&class_id, pkt+tpl->tpl[NF9_APPLICATION_ID].off, 4);
	    if (entry) pptrsv->v6.class = NF_evaluate_classifiers(entry->class, &class_id, gentry);
	  }
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->v6);
	  if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->v6, &pptrsv->v6.bta, &pptrsv->v6.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->v6, &pptrsv->v6.bitr, NULL);
	  if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->v6, FUNC_TYPE_BGP);
	  if (config.nfacctd_bgp_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->v6, &pptrsv->v6.bpas, NULL);
	  if (config.nfacctd_bgp_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->v6, &pptrsv->v6.blp, NULL);
	  if (config.nfacctd_bgp_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->v6, &pptrsv->v6.bmed, NULL);
          if (config.nfacctd_bmp) bmp_srcdst_lookup(&pptrsv->v6);
          exec_plugins(&pptrsv->v6, req);
	  break;
#endif
	case NF9_FTYPE_VLAN_IPV4:
	  pptrsv->vlan4.f_header = pptrs->f_header;
	  pptrsv->vlan4.f_data = pptrs->f_data;
	  pptrsv->vlan4.f_tpl = pptrs->f_tpl;
	  pptrsv->vlan4.flow_type = pptrs->flow_type;

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

	  if (tpl->tpl[NF9_APPLICATION_ID].len == 4) {
	    struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
	    struct xflow_status_entry *gentry = (struct xflow_status_entry *) pptrs->f_status_g;
            pm_class_t class_id = 0;

            memcpy(&class_id, pkt+tpl->tpl[NF9_APPLICATION_ID].off, 4);
	    if (entry) pptrsv->vlan4.class = NF_evaluate_classifiers(entry->class, &class_id, gentry);
	  } 
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlan4);
	  if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlan4, &pptrsv->vlan4.bta, &pptrsv->vlan4.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlan4, &pptrsv->vlan4.bitr, NULL);
	  if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->vlan4, FUNC_TYPE_BGP);
	  if (config.nfacctd_bgp_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlan4, &pptrsv->vlan4.bpas, NULL);
	  if (config.nfacctd_bgp_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlan4, &pptrsv->vlan4.blp, NULL);
	  if (config.nfacctd_bgp_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlan4, &pptrsv->vlan4.bmed, NULL);
          if (config.nfacctd_bmp) bmp_srcdst_lookup(&pptrsv->vlan4);
	  exec_plugins(&pptrsv->vlan4, req);
	  break;
#if defined ENABLE_IPV6
	case NF9_FTYPE_VLAN_IPV6:
	  pptrsv->vlan6.f_header = pptrs->f_header;
	  pptrsv->vlan6.f_data = pptrs->f_data;
	  pptrsv->vlan6.f_tpl = pptrs->f_tpl;
	  pptrsv->vlan6.flow_type = pptrs->flow_type;

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

	  if (tpl->tpl[NF9_APPLICATION_ID].len == 4) {
	    struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
	    struct xflow_status_entry *gentry = (struct xflow_status_entry *) pptrs->f_status_g;
            pm_class_t class_id = 0;

            memcpy(&class_id, pkt+tpl->tpl[NF9_APPLICATION_ID].off, 4);
	    if (entry) pptrsv->vlan6.class = NF_evaluate_classifiers(entry->class, &class_id, gentry);
	  }
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlan6);
	  if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlan6, &pptrsv->vlan6.bta, &pptrsv->vlan6.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlan6, &pptrsv->vlan6.bitr, NULL);
	  if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->vlan6, FUNC_TYPE_BGP);
	  if (config.nfacctd_bgp_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlan6, &pptrsv->vlan6.bpas, NULL);
	  if (config.nfacctd_bgp_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlan6, &pptrsv->vlan6.blp, NULL);
	  if (config.nfacctd_bgp_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlan6, &pptrsv->vlan6.bmed, NULL);
          if (config.nfacctd_bmp) bmp_srcdst_lookup(&pptrsv->vlan6);
	  exec_plugins(&pptrsv->vlan6, req);
	  break;
#endif
        case NF9_FTYPE_MPLS_IPV4:
          pptrsv->mpls4.f_header = pptrs->f_header;
          pptrsv->mpls4.f_data = pptrs->f_data;
          pptrsv->mpls4.f_tpl = pptrs->f_tpl;
	  pptrsv->mpls4.flow_type = pptrs->flow_type;

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

	  if (tpl->tpl[NF9_APPLICATION_ID].len == 4) {
	    struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
	    struct xflow_status_entry *gentry = (struct xflow_status_entry *) pptrs->f_status_g;
            pm_class_t class_id = 0;

            memcpy(&class_id, pkt+tpl->tpl[NF9_APPLICATION_ID].off, 4);
	    if (entry) pptrsv->mpls4.class = NF_evaluate_classifiers(entry->class, &class_id, gentry);
	  }
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->mpls4);
	  if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->mpls4, &pptrsv->mpls4.bta, &pptrsv->mpls4.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->mpls4, &pptrsv->mpls4.bitr, NULL);
	  if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->mpls4, FUNC_TYPE_BGP);
	  if (config.nfacctd_bgp_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->mpls4, &pptrsv->mpls4.bpas, NULL);
	  if (config.nfacctd_bgp_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->mpls4, &pptrsv->mpls4.blp, NULL);
	  if (config.nfacctd_bgp_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->mpls4, &pptrsv->mpls4.bmed, NULL);
          if (config.nfacctd_bmp) bmp_srcdst_lookup(&pptrsv->mpls4);
          exec_plugins(&pptrsv->mpls4, req);
          break;
#if defined ENABLE_IPV6
	case NF9_FTYPE_MPLS_IPV6:
	  pptrsv->mpls6.f_header = pptrs->f_header;
	  pptrsv->mpls6.f_data = pptrs->f_data;
	  pptrsv->mpls6.f_tpl = pptrs->f_tpl;
	  pptrsv->mpls6.flow_type = pptrs->flow_type;

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

	  if (tpl->tpl[NF9_APPLICATION_ID].len == 4) {
	    struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
	    struct xflow_status_entry *gentry = (struct xflow_status_entry *) pptrs->f_status_g;
            pm_class_t class_id = 0;

            memcpy(&class_id, pkt+tpl->tpl[NF9_APPLICATION_ID].off, 4);
	    if (entry) pptrsv->mpls6.class = NF_evaluate_classifiers(entry->class, &class_id, gentry);
	  }
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->mpls6);
	  if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->mpls6, &pptrsv->mpls6.bta, &pptrsv->mpls6.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->mpls6, &pptrsv->mpls6.bitr, NULL);
	  if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->mpls6, FUNC_TYPE_BGP);
	  if (config.nfacctd_bgp_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->mpls6, &pptrsv->mpls6.bpas, NULL);
	  if (config.nfacctd_bgp_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->mpls6, &pptrsv->mpls6.blp, NULL);
	  if (config.nfacctd_bgp_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->mpls6, &pptrsv->mpls6.bmed, NULL);
          if (config.nfacctd_bmp) bmp_srcdst_lookup(&pptrsv->mpls6);
	  exec_plugins(&pptrsv->mpls6, req);
	  break;
#endif
        case NF9_FTYPE_VLAN_MPLS_IPV4:
	  pptrsv->vlanmpls4.f_header = pptrs->f_header;
	  pptrsv->vlanmpls4.f_data = pptrs->f_data;
	  pptrsv->vlanmpls4.f_tpl = pptrs->f_tpl;
	  pptrsv->vlanmpls4.flow_type = pptrs->flow_type;

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

	  if (tpl->tpl[NF9_APPLICATION_ID].len == 4) {
	    struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
	    struct xflow_status_entry *gentry = (struct xflow_status_entry *) pptrs->f_status_g;
            pm_class_t class_id = 0;

            memcpy(&class_id, pkt+tpl->tpl[NF9_APPLICATION_ID].off, 4);
	    if (entry) pptrsv->vlanmpls4.class = NF_evaluate_classifiers(entry->class, &class_id, gentry);
	  }
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlanmpls4);
	  if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bta, &pptrsv->vlanmpls4.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bitr, NULL);
	  if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->vlanmpls4, FUNC_TYPE_BGP);
	  if (config.nfacctd_bgp_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bpas, NULL);
	  if (config.nfacctd_bgp_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.blp, NULL);
	  if (config.nfacctd_bgp_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlanmpls4, &pptrsv->vlanmpls4.bmed, NULL);
          if (config.nfacctd_bmp) bmp_srcdst_lookup(&pptrsv->vlanmpls4);
	  exec_plugins(&pptrsv->vlanmpls4, req);
	  break;
#if defined ENABLE_IPV6
        case NF9_FTYPE_VLAN_MPLS_IPV6:
	  pptrsv->vlanmpls6.f_header = pptrs->f_header;
	  pptrsv->vlanmpls6.f_data = pptrs->f_data;
	  pptrsv->vlanmpls6.f_tpl = pptrs->f_tpl;
	  pptrsv->vlanmpls6.flow_type = pptrs->flow_type;

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

	  if (tpl->tpl[NF9_APPLICATION_ID].len == 4) {
	    struct xflow_status_entry *entry = (struct xflow_status_entry *) pptrs->f_status;
	    struct xflow_status_entry *gentry = (struct xflow_status_entry *) pptrs->f_status_g;
            pm_class_t class_id = 0;

            memcpy(&class_id, pkt+tpl->tpl[NF9_APPLICATION_ID].off, 4);
	    if (entry) pptrsv->vlanmpls6.class = NF_evaluate_classifiers(entry->class, &class_id, gentry);
	  }
	  if (config.nfacctd_isis) isis_srcdst_lookup(&pptrsv->vlanmpls6);
	  if (config.nfacctd_bgp_to_agent_map) BTA_find_id((struct id_table *)pptrs->bta_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bta, &pptrsv->vlanmpls6.bta2);
	  if (config.nfacctd_flow_to_rd_map) NF_find_id((struct id_table *)pptrs->bitr_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bitr, NULL);
	  if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrsv->vlanmpls6, FUNC_TYPE_BGP);
	  if (config.nfacctd_bgp_peer_as_src_map) NF_find_id((struct id_table *)pptrs->bpas_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bpas, NULL);
	  if (config.nfacctd_bgp_src_local_pref_map) NF_find_id((struct id_table *)pptrs->blp_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.blp, NULL);
	  if (config.nfacctd_bgp_src_med_map) NF_find_id((struct id_table *)pptrs->bmed_table, &pptrsv->vlanmpls6, &pptrsv->vlanmpls6.bmed, NULL);
          if (config.nfacctd_bmp) bmp_srcdst_lookup(&pptrsv->vlanmpls6);
	  exec_plugins(&pptrsv->vlanmpls6, req);
	  break;
#endif
	case NF9_FTYPE_NAT_EVENT:
	  /* XXX: aggregate_filter & NAX64 case */
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

          exec_plugins(pptrs, req);
	default:
	  break;
        }

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
        notify_malf_packet(LOG_INFO, "INFO: aborting malformed Data element (incomplete NetFlow v9/IPFIX packet)",
                      (struct sockaddr *) pptrsv->v4.f_agent, FlowSeq);
        xflow_tot_bad_datagrams++;
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
  if (len < NfHdrV8Sz) {
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow packet", (struct sockaddr *) pptrs->f_agent, 0);
    xflow_tot_bad_datagrams++;
    return;
  } 

  nfv = ntohs(((struct struct_header_v5 *)pkt)->version);

  if (nfv != 1 && nfv != 5 && nfv != 7 && nfv != 8 && nfv != 9 && nfv != 10) {
    if (!config.nfacctd_disable_checks) {
      notify_malf_packet(LOG_INFO, "INFO: discarding unknown NetFlow packet", (struct sockaddr *) pptrs->f_agent, 0);
      xflow_tot_bad_datagrams++;
    }
    return;
  }

  pptrs->f_header = pkt;

  switch (nfv) {
  case 5:
  case 7:
  case 8:
    pptrs->seqno = ntohl(((struct struct_header_v5 *)pkt)->flow_sequence);
    break;
  case 9:
    pptrs->seqno = ntohl(((struct struct_header_v9 *)pkt)->flow_sequence);
    break;
  case 10:
    pptrs->seqno = ntohl(((struct struct_header_ipfix *)pkt)->flow_sequence);
  default:
    pptrs->seqno = 0;
    break;
  }

  if (config.debug) {
    sa_to_addr((struct sockaddr *)pptrs->f_agent, &debug_a, &debug_agent_port);
    addr_to_str(debug_agent_addr, &debug_a);

    Log(LOG_DEBUG, "DEBUG ( %s/core ): Received NetFlow/IPFIX packet from [%s:%u] version [%u] seqno [%u]\n",
			config.name, debug_agent_addr, debug_agent_port, nfv, pptrsv->v4.seqno);
  }

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
  NfHdrV1Sz = sizeof(struct struct_header_v1);
  NfHdrV5Sz = sizeof(struct struct_header_v5);
  NfHdrV7Sz = sizeof(struct struct_header_v7);
  NfHdrV8Sz = sizeof(struct struct_header_v8);
  NfHdrV9Sz = sizeof(struct struct_header_v9);
  NfDataHdrV9Sz = sizeof(struct data_hdr_v9);
  NfTplHdrV9Sz = sizeof(struct template_hdr_v9);
  NfTplFieldV9Sz = sizeof(struct template_field_v9);
  NfOptTplHdrV9Sz = sizeof(struct options_template_hdr_v9);
  NfDataV1Sz = sizeof(struct struct_export_v1);
  NfDataV5Sz = sizeof(struct struct_export_v5);
  NfDataV7Sz = sizeof(struct struct_export_v7);
  IP4HdrSz = sizeof(struct pm_iphdr);
  IP4TlSz = sizeof(struct pm_iphdr)+sizeof(struct pm_tlhdr);
  PptrsSz = sizeof(struct packet_ptrs);
  CSSz = sizeof(struct class_st);
  HostAddrSz = sizeof(struct host_addr);
  UDPHdrSz = sizeof(struct pm_udphdr);
  IpFixHdrSz = sizeof(struct struct_header_ipfix); 

#if defined ENABLE_IPV6
  IP6HdrSz = sizeof(struct ip6_hdr);
  IP6AddrSz = sizeof(struct in6_addr);
  IP6TlSz = sizeof(struct ip6_hdr)+sizeof(struct pm_tlhdr);
#endif
}

u_int8_t NF_evaluate_flow_type(struct template_cache_entry *tpl, struct packet_ptrs *pptrs)
{
  u_int8_t ret = NF9_FTYPE_TRAFFIC;
  u_int8_t have_ip_proto = FALSE;

  /* first round: event vs traffic */
  if (!tpl->tpl[NF9_IN_BYTES].len && !tpl->tpl[NF9_OUT_BYTES].len && !tpl->tpl[NF9_FLOW_BYTES].len /* && packets? */) {
    ret = NF9_FTYPE_EVENT;
  }
  else {
    if ((tpl->tpl[NF9_IN_VLAN].len && *(pptrs->f_data+tpl->tpl[NF9_IN_VLAN].off) > 0) ||
        (tpl->tpl[NF9_OUT_VLAN].len && *(pptrs->f_data+tpl->tpl[NF9_OUT_VLAN].off) > 0)) ret += NF9_FTYPE_VLAN; 
    if (tpl->tpl[NF9_MPLS_LABEL_1].len /* check: value > 0 ? */) ret += NF9_FTYPE_MPLS; 

    /* Explicit IP protocol definition first; a bit of heuristics as fallback */
    if (tpl->tpl[NF9_IP_PROTOCOL_VERSION].len) {
      if (*(pptrs->f_data+tpl->tpl[NF9_IP_PROTOCOL_VERSION].off) == 4) {
	have_ip_proto = TRUE;
      }
      else if (*(pptrs->f_data+tpl->tpl[NF9_IP_PROTOCOL_VERSION].off) == 6) {
	ret += NF9_FTYPE_TRAFFIC_IPV6;
	have_ip_proto = TRUE;
      }
    }

    if (!have_ip_proto) {
      if (tpl->tpl[NF9_IPV4_SRC_ADDR].len) {
	have_ip_proto = TRUE;
      }
      else if (tpl->tpl[NF9_IPV6_SRC_ADDR].len) {
	ret += NF9_FTYPE_TRAFFIC_IPV6;
	have_ip_proto - TRUE;
      }
    }
  }

  /* second round: overrides */

  /* NetFlow Event Logging (NEL): generic NAT event support */
  if (tpl->tpl[NF9_NAT_EVENT].len) ret = NF9_FTYPE_NAT_EVENT;

  /* NetFlow/IPFIX option final override */
  if (tpl->template_type == 1) ret = NF9_FTYPE_OPTION;

  return ret;
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

#if defined ENABLE_IPV6
void reset_ip6(struct packet_ptrs *pptrs)
{
  memset(pptrs->iph_ptr, 0, IP6TlSz);  
  Assign16(((struct ip6_hdr *)pptrs->iph_ptr)->ip6_plen, htons(100));
  Assign16(((struct ip6_hdr *)pptrs->iph_ptr)->ip6_hlim, htons(64));
}
#endif

void notify_malf_packet(short int severity, char *ostr, struct sockaddr *sa, u_int32_t seq)
{
  struct host_addr a;
  u_char errstr[SRVBUFLEN];
  u_char agent_addr[50] /* able to fit an IPv6 string aswell */, any[]="0.0.0.0";
  u_int16_t agent_port;

  sa_to_addr((struct sockaddr *)sa, &a, &agent_port);
  addr_to_str(agent_addr, &a);
  if (!config.nfacctd_ip) config.nfacctd_ip = any;

  if (seq) snprintf(errstr, SRVBUFLEN, "%s: nfacctd=%s:%u agent=%s:%u seq=%u\n",
		ostr, config.nfacctd_ip, config.nfacctd_port, agent_addr, agent_port, seq);
  else snprintf(errstr, SRVBUFLEN, "%s: nfacctd=%s:%u agent=%s:%u\n",
		ostr, config.nfacctd_ip, config.nfacctd_port, agent_addr, agent_port);

  Log(severity, errstr);
}

int NF_find_id(struct id_table *t, struct packet_ptrs *pptrs, pm_id_t *tag, pm_id_t *tag2)
{
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent;
  int x, j, begin = 0, end = 0;
  pm_id_t ret = 0;

  if (!t) return 0;

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
    u_int32_t iterator;

    pretag_index_lookup(t, pptrs, index_results, ID_TABLE_INDEX_RESULTS);

    for (iterator = 0; index_results[iterator] && iterator < ID_TABLE_INDEX_RESULTS; iterator++) {
      ret = pretag_entry_process(index_results[iterator], pptrs, tag, tag2);
      if (!(ret & PRETAG_MAP_RCODE_JEQ)) return ret;
    }

    /* if we have at least one index we trust we did a good job */
    return ret;
  }

  if (sa->sa_family == AF_INET) {
    begin = 0;
    end = t->ipv4_num;
  }
#if defined ENABLE_IPV6
  else if (sa->sa_family == AF_INET6) {
    begin = t->num-t->ipv6_num;
    end = t->num;
  }
#endif

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

  return ret;
}

char *nfv578_check_status(struct packet_ptrs *pptrs)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent;
  u_int32_t aux1 = (hdr->engine_id << 8 | hdr->engine_type);
  int hash = hash_status_table(aux1, sa, XFLOW_STATUS_TABLE_SZ);
  struct xflow_status_entry *entry = NULL;
  
  if (hash >= 0) {
    entry = search_status_table(sa, aux1, 0, hash, XFLOW_STATUS_TABLE_MAX_ENTRIES);
    if (entry) {
      update_status_table(entry, ntohl(hdr->flow_sequence));
      entry->inc = ntohs(hdr->count);
    }
  }

  return (char *) entry;
}

char *nfv9_check_status(struct packet_ptrs *pptrs, u_int32_t sid, u_int32_t flags, u_int32_t seq, u_int8_t update)
{
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent;
  int hash = hash_status_table(sid, sa, XFLOW_STATUS_TABLE_SZ);
  struct xflow_status_entry *entry = NULL;
  
  if (hash >= 0) {
    entry = search_status_table(sa, sid, flags, hash, XFLOW_STATUS_TABLE_MAX_ENTRIES);
    if (entry && update) {
      update_status_table(entry, seq);
      entry->inc = 1;
    }
  }

  return (char *) entry;
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
