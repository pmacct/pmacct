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

/* defines */
#define __NFACCTD_C

/* includes */
#include "pmacct.h"
#include "nfacctd.h"
#include "pretag_handlers.h"
#include "pretag-data.h"
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
  printf("%s\n", NFACCTD_USAGE_HEADER);
  printf("Usage: %s [ -D | -d ] [ -L IP address ] [ -l port ] [ -c primitive [ , ... ] ] [ -P plugin [ , ... ] ]\n", prog_name);
  printf("       %s [ -f config_file ]\n", prog_name);
  printf("       %s [ -h ]\n", prog_name);
  printf("\nGeneral options:\n");
  printf("  -h  \tShow this page\n");
  printf("  -L  \tBind to the specified IP address\n");
  printf("  -l  \tListen on the specified UDP port\n");
  printf("  -f  \tLoad configuration from the specified file\n");
  printf("  -c  \t[ src_mac | dst_mac | vlan | src_host | dst_host | src_net | dst_net | src_port | dst_port |\n\t tos | proto | src_as | dst_as | sum_mac | sum_host | sum_net | sum_as | sum_port | tag |\n\t flows | class | tcpflags | none ] \n\tAggregation string (DEFAULT: src_host)\n");
  printf("  -D  \tDaemonize\n"); 
  printf("  -n  \tPath to a file containing Network definitions\n");
  printf("  -o  \tPath to a file containing Port definitions\n");
  printf("  -P  \t[ memory | print | mysql | pgsql | sqlite3 | nfprobe ] \n\tActivate plugin\n"); 
  printf("  -d  \tEnable debug\n");
  printf("  -S  \t[ auth | mail | daemon | kern | user | local[0-7] ] \n\tLog to the specified syslog facility\n");
  printf("  -F  \tWrite Core Process PID into the specified file\n");
  printf("\nMemory Plugin (-P memory) options:\n");
  printf("  -p  \tSocket for client-server communication (DEFAULT: /tmp/collect.pipe)\n");
  printf("  -b  \tNumber of buckets\n");
  printf("  -m  \tNumber of memory pools\n");
  printf("  -s  \tMemory pool size\n");
  printf("\nPostgreSQL (-P pgsql)/MySQL (-P mysql)/SQLite (-P sqlite3) plugin options:\n");
  printf("  -r  \tRefresh time (in seconds)\n");
  printf("  -v  \t[ 1 | 2 | 3 | 4 | 5 | 6 | 7 ] \n\tTable version\n");
  printf("\n");
  printf("Examples:\n");
  printf("  Daemonize the process and write data into a MySQL database\n");
  printf("  nfacctd -c src_host,dst_host -D -P mysql\n\n");
  printf("  Print flows over the screen and refresh data every 30 seconds\n");
  printf("  nfacctd -c src_host,dst_host,proto -P print -r 30\n");
  printf("\n");
  printf("  See EXAMPLES for further hints\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}


int main(int argc,char **argv, char **envp)
{
  struct plugins_list_entry *list;
  struct plugin_requests req;
  struct packet_ptrs_vector pptrs;
  char config_file[SRVBUFLEN];
  unsigned char netflow_packet[NETFLOW_MSG_SIZE];
  int logf, rc, yes=1, allowed;
  struct host_addr addr;
  struct hosts_table allow;
  struct id_table idt;
  u_int32_t idx;
  u_int16_t ret;

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
  memset(&class, 0, sizeof(class));
  memset(&xflow_status_table, 0, sizeof(xflow_status_table));
  config.acct_type = ACCT_NF;

  rows = 0;
  glob_pcapt = NULL;

  /* getting commandline values */
  while (!errflag && ((cp = getopt(argc, argv, ARGS_NFACCTD)) != -1)) {
    cfg_cmdline[rows] = malloc(SRVBUFLEN);
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
    case 'o':
      strlcpy(cfg_cmdline[rows], "ports_file: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
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
      cfg_cmdline[rows] = malloc(SRVBUFLEN);
      strlcpy(cfg_cmdline[rows], "print_refresh_time: ", SRVBUFLEN);
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
    list->cfg.acct_type = ACCT_NF;
    if (!strcmp(list->name, "default") && !strcmp(list->type.string, "core")) 
      memcpy(&config, &list->cfg, sizeof(struct configuration)); 
    list = list->next;
  }

  if (config.daemon) {
    list = plugins_list;
    while (list) {
      if (!strcmp(list->type.string, "print")) printf("WARN: Daemonizing. Hmm, bye bye screen.\n");
      list = list->next;
    }
    if (debug || config.debug)
      printf("WARN: debug is enabled; forking in background. Console logging will get lost.\n"); 
    daemonize();
  }

  initsetproctitle(argc, argv, envp);
  if (config.syslog) {
    logf = parse_log_facility(config.syslog);
    if (logf == ERR) {
      config.syslog = NULL;
      Log(LOG_WARNING, "WARN ( default/core ): specified syslog facility is not supported; logging to console.\n");
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
      if (list->type.id == PLUGIN_ID_NFPROBE) {
	list->cfg.nfprobe_what_to_count = list->cfg.what_to_count;
	list->cfg.what_to_count = 0;
#if defined (HAVE_L2)
	if (list->cfg.nfprobe_version == 9) {
	  list->cfg.what_to_count |= COUNT_SRC_MAC;
	  list->cfg.what_to_count |= COUNT_DST_MAC;
	  list->cfg.what_to_count |= COUNT_VLAN;
	}
#endif
	list->cfg.what_to_count |= COUNT_SRC_HOST;
	list->cfg.what_to_count |= COUNT_DST_HOST;
	list->cfg.what_to_count |= COUNT_SRC_PORT;
	list->cfg.what_to_count |= COUNT_DST_PORT;
	list->cfg.what_to_count |= COUNT_IP_TOS;
	list->cfg.what_to_count |= COUNT_IP_PROTO;
	if (list->cfg.networks_file || list->cfg.nfacctd_as == NF_AS_KEEP || 
	    list->cfg.nfacctd_as == NF_AS_BGP) {
	  list->cfg.what_to_count |= COUNT_SRC_AS;
	  list->cfg.what_to_count |= COUNT_DST_AS;
	}
	if (list->cfg.nfprobe_version == 9 && list->cfg.classifiers_path)
	  list->cfg.what_to_count |= COUNT_CLASS;
	if (list->cfg.nfprobe_version == 9 && list->cfg.pre_tag_map)
	  list->cfg.what_to_count |= COUNT_ID;
	if (list->cfg.nfprobe_version == 9)
	  list->cfg.what_to_count |= COUNT_FLOWS;
	list->cfg.what_to_count |= COUNT_COUNTERS;

	list->cfg.data_type = PIPE_TYPE_METADATA;
	list->cfg.data_type |= PIPE_TYPE_EXTRAS;
      }
      else if (list->type.id == PLUGIN_ID_SFPROBE) {
	req.bpf_filter = TRUE;
	list->cfg.what_to_count = COUNT_PAYLOAD;
	if (list->cfg.classifiers_path) list->cfg.what_to_count |= COUNT_CLASS;
	if (list->cfg.pre_tag_map) list->cfg.what_to_count |= COUNT_ID;

	list->cfg.data_type = PIPE_TYPE_PAYLOAD;
      }
      else {
	list->cfg.data_type = PIPE_TYPE_METADATA;
	evaluate_sums(&list->cfg.what_to_count, list->name, list->type.string);
	if (!list->cfg.what_to_count) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): defaulting to SRC HOST aggregation.\n", list->name, list->type.string);
	  list->cfg.what_to_count |= COUNT_SRC_HOST;
	}
	if ((list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) && !list->cfg.networks_file && list->cfg.nfacctd_as != NF_AS_KEEP) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation has been selected but NO 'networks_file' has been specified. Exiting...\n\n", list->name, list->type.string);
	  exit(1);
	}
	if ((list->cfg.what_to_count & (COUNT_SRC_NET|COUNT_DST_NET|COUNT_SUM_NET)) && !list->cfg.networks_file && !list->cfg.networks_mask) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): NET aggregation has been selected but NO 'networks_file' has been specified. Exiting...\n\n", list->name, list->type.string);
	  exit(1);
	}
	if (list->cfg.what_to_count & COUNT_CLASS && !list->cfg.classifiers_path) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): 'class' aggregation selected but NO 'classifiers' key specified. Exiting...\n\n", list->name, list->type.string);
	  exit(1);
	}
	if (list->cfg.what_to_count & (COUNT_SRC_STD_COMM|COUNT_DST_STD_COMM|COUNT_SUM_STD_COMM|
	    			       COUNT_SRC_EXT_COMM|COUNT_DST_EXT_COMM|COUNT_SUM_EXT_COMM|
				       COUNT_AS_PATH)) {
	  /* Sanitizing the aggregation method */
	  if ( (list->cfg.what_to_count & (COUNT_SRC_STD_COMM|COUNT_SUM_STD_COMM|COUNT_DST_STD_COMM)) &&
               (list->cfg.what_to_count & (COUNT_SRC_EXT_COMM|COUNT_SUM_EXT_COMM|COUNT_DST_EXT_COMM)) ) {
	    printf("ERROR: The use of STANDARD and EXTENDED BGP communitities is mutual exclusive.\n");
	    exit(1);
	  }
	  list->cfg.data_type |= PIPE_TYPE_BGP;
	}
	list->cfg.what_to_count |= COUNT_COUNTERS;
      }
    }
    list = list->next;
  }

  /* signal handling we want to inherit to plugins (when not re-defined elsewhere) */
  signal(SIGCHLD, startup_handle_falling_child); /* takes note of plugins failed during startup phase */
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGUSR1, push_stats); /* logs various statistics via Log() calls */ 
  signal(SIGUSR2, reload_maps); /* sets to true the reload_maps flag */
  signal(SIGPIPE, SIG_IGN); /* we want to exit gracefully when a pipe is broken */

  /* If no IP address is supplied, let's set our default
     behaviour: IPv4 address, INADDR_ANY, port 2100 */
  if (!config.nfacctd_port) config.nfacctd_port = DEFAULT_NFACCTD_PORT;
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
      Log(LOG_ERR, "ERROR ( default/core ): 'nfacctd_ip' value is not valid. Exiting.\n");
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
  rc = Setsocksize(config.sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN ( default/core ): Setsocksize() failed for SO_REUSEADDR.\n");

  if (config.pipe_size) {
    rc = Setsocksize(config.sock, SOL_SOCKET, SO_RCVBUF, &config.pipe_size, sizeof(config.pipe_size));
    if (rc < 0) Log(LOG_ERR, "WARN ( default/core ): Setsocksize() failed for 'plugin_pipe_size' = '%d'.\n", config.pipe_size); 
  }

  rc = bind(config.sock, (struct sockaddr *) &server, slen);
  if (rc < 0) {
    Log(LOG_ERR, "ERROR ( default/core): bind() to ip=%s port=%d/udp failed (errno: %d).\n", config.nfacctd_ip, config.nfacctd_port, errno);
    exit(1);
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

#if defined ENABLE_THREADS
  /* starting the BGP thread */
  if (config.nfacctd_bgp) {
    nfacctd_bgp_wrapper();
    req.bpf_filter = TRUE;
    load_comm_patterns(&config.nfacctd_bgp_stdcomm_pattern, &config.nfacctd_bgp_extcomm_pattern);
  }
#else
  if (config.nfacctd_bgp) {
	Log(LOG_ERR, "ERROR ( default/core ): 'nfacctd_bgp' is available only with threads (--enable-threads). Exiting.\n");
	exit(1);
  }
#endif

  if (config.nfacctd_as_str) {
    if (!strcmp(config.nfacctd_as_str, "false"))
      config.nfacctd_as = NF_AS_KEEP;
    else if (!strcmp(config.nfacctd_as_str, "true") ||
             !strcmp(config.nfacctd_as_str, "file"))
      config.nfacctd_as = NF_AS_NEW;
    else if (!strcmp(config.nfacctd_as_str, "bgp"))
      config.nfacctd_as = NF_AS_BGP;
  }

  if (config.pre_tag_map) {
    load_id_file(config.acct_type, config.pre_tag_map, &idt, &req);
    pptrs.v4.idtable = (u_char *) &idt;
  }
  else {
    memset(&idt, 0, sizeof(idt));
    pptrs.v4.idtable = NULL;
  }
  load_nfv8_handlers();

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

  /* initializing template cache */ 
  memset(&tpl_cache, 0, sizeof(tpl_cache));
  tpl_cache.num = TEMPLATE_CACHE_ENTRIES;

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
  pptrs.v4.tlh_ptr = pptrs.v4.packet_ptr + ETHER_HDRLEN + sizeof(struct my_iphdr); 
  Assign8(((struct my_iphdr *)pptrs.v4.iph_ptr)->ip_vhl, 5);
  // pptrs.v4.pkthdr->caplen = 38; /* eth_header + my_iphdr + my_tlhdr */
  pptrs.v4.pkthdr->caplen = 55; 
  pptrs.v4.pkthdr->len = 100; /* fake len */ 
  pptrs.v4.l3_proto = ETHERTYPE_IP;

  memset(dummy_packet_vlan, 0, sizeof(dummy_packet_vlan));
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

  Log(LOG_INFO, "INFO ( default/core ): waiting for data on UDP port '%u'\n", config.nfacctd_port);
  allowed = TRUE;

  /* Main loop */
  for(;;) {
    ret = recvfrom(config.sock, netflow_packet, NETFLOW_MSG_SIZE, 0, (struct sockaddr *) &client, &clen);

    if (ret < 1) continue; /* we don't have enough data to decode the version */ 

    /* check if Hosts Allow Table is loaded; if it is, we will enforce rules */
    if (allow.num) allowed = check_allow(&allow, (struct sockaddr *)&client); 
    if (!allowed) continue;

    if (reload_map) {
      load_networks(config.networks_file, &nt, &nc);
      load_id_file(config.acct_type, config.pre_tag_map, &idt, &req); 
      reload_map = FALSE;
    }

    /* We will change byte ordering in order to avoid a bunch of ntohs() calls */
    ((struct struct_header_v5 *)netflow_packet)->version = ntohs(((struct struct_header_v5 *)netflow_packet)->version);
    reset_tag_status(&pptrs);
    reset_shadow_status(&pptrs);
    reset_tagdist_status(&pptrs);
    
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
    case 9:
      process_v9_packet(netflow_packet, ret, &pptrs, &req);
      break;
    default:
      notify_malf_packet(LOG_INFO, "INFO: Discarding unknown packet", (struct sockaddr *) pptrs.v4.f_agent);
      xflow_tot_bad_datagrams++;
      break;
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
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v1 packet", (struct sockaddr *) pptrs->f_agent);
    xflow_tot_bad_datagrams++;
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV1Sz; 
  exp_v1 = (struct struct_export_v1 *)pkt;

  reset_mac(pptrs);

  if ((count <= V1_MAXFLOWS) && ((count*NfDataV1Sz)+NfHdrV1Sz == len)) {
    while (count) {
      pptrs->f_data = (unsigned char *) exp_v1;
      if (req->bpf_filter) {
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp_v1->srcaddr.s_addr);
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp_v1->dstaddr.s_addr);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_p, exp_v1->prot);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_tos, exp_v1->tos);
        Assign16(((struct my_tlhdr *)pptrs->tlh_ptr)->src_port, exp_v1->srcport);
        Assign16(((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port, exp_v1->dstport);
      }
      /* Let's copy some relevant field */
      pptrs->l4_proto = exp_v1->prot;

      /* IP header's id field is unused; we will use it to transport our id */
      if (config.pre_tag_map) pptrs->tag = NF_find_id(pptrs);
      exec_plugins(pptrs);
      exp_v1++;           
      count--;             
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO: discarding malformed NetFlow v1 packet", (struct sockaddr *) pptrs->f_agent);
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
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v5 packet", (struct sockaddr *) pptrs->f_agent);
    xflow_tot_bad_datagrams++;
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV5Sz; 
  exp_v5 = (struct struct_export_v5 *)pkt;
  pptrs->f_status = nfv578_check_status(pptrs);

  reset_mac(pptrs);

  if ((count <= V5_MAXFLOWS) && ((count*NfDataV5Sz)+NfHdrV5Sz == len)) {
    while (count) {
      pptrs->f_data = (unsigned char *) exp_v5;
      if (req->bpf_filter) {
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp_v5->srcaddr.s_addr);
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp_v5->dstaddr.s_addr);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_p, exp_v5->prot);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_tos, exp_v5->tos);
        Assign16(((struct my_tlhdr *)pptrs->tlh_ptr)->src_port, exp_v5->srcport);
        Assign16(((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port, exp_v5->dstport);
      }
      /* Let's copy some relevant field */
      pptrs->l4_proto = exp_v5->prot;

      /* IP header's id field is unused; we will use it to transport our id */ 
      if (config.pre_tag_map) pptrs->tag = NF_find_id(pptrs);
      exec_plugins(pptrs);
      exp_v5++;
      count--;
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO: discarding malformed NetFlow v5 packet", (struct sockaddr *) pptrs->f_agent);
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
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v7 packet", (struct sockaddr *) pptrs->f_agent);
    xflow_tot_bad_datagrams++;
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV7Sz;
  exp_v7 = (struct struct_export_v7 *)pkt;
  pptrs->f_status = nfv578_check_status(pptrs);

  reset_mac(pptrs);

  if ((count <= V7_MAXFLOWS) && ((count*NfDataV7Sz)+NfHdrV7Sz == len)) {
    while (count) {
      pptrs->f_data = (unsigned char *) exp_v7;
      if (req->bpf_filter) {
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_src.s_addr, exp_v7->srcaddr);
        Assign32(((struct my_iphdr *)pptrs->iph_ptr)->ip_dst.s_addr, exp_v7->dstaddr);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_p, exp_v7->prot);
        Assign8(((struct my_iphdr *)pptrs->iph_ptr)->ip_tos, exp_v7->tos);
        Assign16(((struct my_tlhdr *)pptrs->tlh_ptr)->src_port, exp_v7->srcport);
        Assign16(((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port, exp_v7->dstport);
      }
      /* Let's copy some relevant field */
      pptrs->l4_proto = exp_v7->prot;

      /* IP header's id field is unused; we will use it to transport our id */
      if (config.pre_tag_map) pptrs->tag = NF_find_id(pptrs);
      exec_plugins(pptrs);
      exp_v7++;
      count--;
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO: discarding malformed NetFlow v7 packet", (struct sockaddr *) pptrs->f_agent);
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
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v8 packet", (struct sockaddr *) pptrs->f_agent);
    xflow_tot_bad_datagrams++;
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV8Sz;
  exp_v8 = pkt;
  pptrs->f_status = nfv578_check_status(pptrs);

  reset_mac(pptrs);
  reset_ip4(pptrs);

  if ((count <= v8_handlers[hdr_v8->aggregation].max_flows) && ((count*v8_handlers[hdr_v8->aggregation].exp_size)+NfHdrV8Sz <= len)) {
    while (count) {
      pptrs->f_data = exp_v8;
      if (req->bpf_filter) v8_handlers[hdr_v8->aggregation].fh(pptrs, exp_v8);

      /* IP header's id field is unused; we will use it to transport our id */
      if (config.pre_tag_map) pptrs->tag = NF_find_id(pptrs);
      exec_plugins(pptrs);
      exp_v8 += v8_handlers[hdr_v8->aggregation].exp_size;
      count--;
    }
  }
  else {
    notify_malf_packet(LOG_INFO, "INFO: discarding malformed NetFlow v8 packet", (struct sockaddr *) pptrs->f_agent);
    xflow_tot_bad_datagrams++;
    return;
  }
}

void process_v9_packet(unsigned char *pkt, u_int16_t len, struct packet_ptrs_vector *pptrsv,
		struct plugin_requests *req)
{
  struct struct_header_v9 *hdr_v9 = (struct struct_header_v9 *)pkt;
  struct template_hdr_v9 *template_hdr;
  struct template_cache_entry *tpl;
  struct data_hdr_v9 *data_hdr;
  struct packet_ptrs *pptrs = &pptrsv->v4;
  u_int16_t fid, off = 0, flowoff, flowsetlen, flow_type; 

  if (len < NfHdrV9Sz) {
    notify_malf_packet(LOG_INFO, "INFO: discarding short NetFlow v9 packet", (struct sockaddr *) pptrsv->v4.f_agent);
    xflow_tot_bad_datagrams++;
    return;
  }
  pptrs->f_header = pkt;
  pkt += NfHdrV9Sz;
  off += NfHdrV9Sz; 
  pptrsv->v4.f_status = nfv9_check_status(pptrs);
  set_vector_f_status(pptrsv);

  process_flowset:
  if (off+NfDataHdrV9Sz >= len) { 
    notify_malf_packet(LOG_INFO, "INFO: unable to read next Flowset; incomplete NetFlow v9 packet",
		    (struct sockaddr *) pptrsv->v4.f_agent);
    xflow_tot_bad_datagrams++;
    return;
  }

  data_hdr = (struct data_hdr_v9 *)pkt;
  fid = ntohs(data_hdr->flow_id);
  if (fid == 0) { /* template */ 
    unsigned char *tpl_ptr = pkt;

    flowoff = 0;
    tpl_ptr += NfDataHdrV9Sz;
    flowoff += NfDataHdrV9Sz;
    flowsetlen = ntohs(data_hdr->flow_len);

    while (flowoff < flowsetlen) {
      template_hdr = (struct template_hdr_v9 *) tpl_ptr;
      if (off+flowsetlen > len) { 
        notify_malf_packet(LOG_INFO, "INFO: unable to read next Template Flowset; incomplete NetFlow v9 packet",
		        (struct sockaddr *) pptrsv->v4.f_agent);
        xflow_tot_bad_datagrams++;
        return;
      }

      handle_template_v9(template_hdr, pptrs);

      tpl_ptr += sizeof(struct template_hdr_v9)+ntohs(template_hdr->num)*sizeof(struct template_field_v9); 
      flowoff += sizeof(struct template_hdr_v9)+ntohs(template_hdr->num)*sizeof(struct template_field_v9); 
    }    

    pkt += flowsetlen; 
    off += flowsetlen; 
  }
  else if (fid >= 256) { /* data */
    flowsetlen = ntohs(data_hdr->flow_len);
    if (off+flowsetlen > len) { 
      notify_malf_packet(LOG_INFO, "INFO: unable to read next Data Flowset (incomplete NetFlow v9 packet)",
		      (struct sockaddr *) pptrsv->v4.f_agent);
      xflow_tot_bad_datagrams++;
      return;
    }

    flowoff = 0;
    pkt += NfDataHdrV9Sz;
    flowoff += NfDataHdrV9Sz;

    tpl = find_template_v9(data_hdr->flow_id, pptrs);
    if (!tpl) {
      struct host_addr a;
      u_char agent_addr[50];
      u_int16_t agent_port;

      sa_to_addr((struct sockaddr *)pptrs->f_agent, &a, &agent_port);
      addr_to_str(agent_addr, &a);

      Log(LOG_DEBUG, "DEBUG ( default/core ): Discarded NetFlow V9 packet (R: unknown template %u [%s:%u])\n", fid,
		agent_addr, ntohl(((struct struct_header_v9 *)pptrs->f_header)->source_id)); 
      pkt += flowsetlen-NfDataHdrV9Sz;
      off += flowsetlen;
    }
    else {
      while (flowoff+tpl->len <= flowsetlen) {
        pptrs->f_data = pkt;
	pptrs->f_tpl = (u_char *) tpl;
	flow_type = NF_evaluate_flow_type(tpl, pptrs);

	/* we need to understand the IP protocol version in order to build the fake packet */ 
	switch (flow_type) {
	case NF9_FTYPE_IPV4:
	  if (req->bpf_filter) {
	    reset_mac(pptrs);
	    reset_ip4(pptrs);

            memcpy(pptrs->mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
            memcpy(pptrs->mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
	    ((struct my_iphdr *)pptrs->iph_ptr)->ip_vhl = 0x45;
            memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
            memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
            memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
            memcpy(&((struct my_iphdr *)pptrs->iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
            memcpy(&((struct my_tlhdr *)pptrs->tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
            memcpy(&((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }
	  /* Let's copy some relevant field */
	  pptrs->l4_proto = 0;
	  memcpy(&pptrs->l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  if (config.classifiers_path && tpl->tpl[NF9_CUST_CLASS].len == 16)
	    pptrs->class = NF_evaluate_classifiers((pptrs->f_data+tpl->tpl[NF9_CUST_CLASS].off));
	  if (config.pre_tag_map) pptrs->tag = NF_find_id(pptrs);
          exec_plugins(pptrs);
	  break;
#if defined ENABLE_IPV6
	case NF9_FTYPE_IPV6:
	  pptrsv->v6.f_header = pptrs->f_header;
	  pptrsv->v6.f_data = pptrs->f_data;
	  pptrsv->v6.f_tpl = pptrs->f_tpl;

	  if (req->bpf_filter) {
	    reset_mac(&pptrsv->v6);
	    reset_ip6(&pptrsv->v6);
	    memcpy(pptrsv->v6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
	    memcpy(pptrsv->v6.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
	    ((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_ctlun.ip6_un2_vfc = 0x60;
            memcpy(&((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_src, pkt+tpl->tpl[NF9_IPV6_SRC_ADDR].off, tpl->tpl[NF9_IPV6_SRC_ADDR].len);
            memcpy(&((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_dst, pkt+tpl->tpl[NF9_IPV6_DST_ADDR].off, tpl->tpl[NF9_IPV6_DST_ADDR].len);
            memcpy(&((struct ip6_hdr *)pptrsv->v6.iph_ptr)->ip6_nxt, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    /* XXX: class ID ? */
            memcpy(&((struct my_tlhdr *)pptrsv->v6.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
            memcpy(&((struct my_tlhdr *)pptrsv->v6.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }
	  /* Let's copy some relevant field */
	  pptrsv->v6.l4_proto = 0;
	  memcpy(&pptrsv->v6.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  if (config.classifiers_path && tpl->tpl[NF9_CUST_CLASS].len == 16)
	    pptrsv->v6.class = NF_evaluate_classifiers((pptrsv->v6.f_data+tpl->tpl[NF9_CUST_CLASS].off));
	  if (config.pre_tag_map) pptrsv->v6.tag = NF_find_id(&pptrsv->v6);
          exec_plugins(&pptrsv->v6);
	  break;
#endif
	case NF9_FTYPE_VLAN_IPV4:
	  pptrsv->vlan4.f_header = pptrs->f_header;
	  pptrsv->vlan4.f_data = pptrs->f_data;
	  pptrsv->vlan4.f_tpl = pptrs->f_tpl;

	  if (req->bpf_filter) {
	    reset_mac_vlan(&pptrsv->vlan4); 
	    reset_ip4(&pptrsv->vlan4);

	    memcpy(pptrsv->vlan4.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
	    memcpy(pptrsv->vlan4.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
	    memcpy(pptrsv->vlan4.vlan_ptr, pkt+tpl->tpl[NF9_SRC_VLAN].off, tpl->tpl[NF9_SRC_VLAN].len);
	    ((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_vhl = 0x45;
	    memcpy(&((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlan4.iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->vlan4.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->vlan4.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }
	  /* Let's copy some relevant field */
	  pptrsv->vlan4.l4_proto = 0;
	  memcpy(&pptrsv->vlan4.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  if (config.classifiers_path && tpl->tpl[NF9_CUST_CLASS].len == 16)
	    pptrsv->vlan4.class = NF_evaluate_classifiers((pptrsv->vlan4.f_data+tpl->tpl[NF9_CUST_CLASS].off));
	  if (config.pre_tag_map) pptrsv->vlan4.tag = NF_find_id(&pptrsv->vlan4);
	  exec_plugins(&pptrsv->vlan4);
	  break;
#if defined ENABLE_IPV6
	case NF9_FTYPE_VLAN_IPV6:
	  pptrsv->vlan6.f_header = pptrs->f_header;
	  pptrsv->vlan6.f_data = pptrs->f_data;
	  pptrsv->vlan6.f_tpl = pptrs->f_tpl;

	  if (req->bpf_filter) {
	    reset_mac_vlan(&pptrsv->vlan6);
	    reset_ip6(&pptrsv->vlan6);

	    memcpy(pptrsv->vlan6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
	    memcpy(pptrsv->vlan6.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
	    memcpy(pptrsv->vlan6.vlan_ptr, pkt+tpl->tpl[NF9_SRC_VLAN].off, tpl->tpl[NF9_SRC_VLAN].len);
	    ((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_ctlun.ip6_un2_vfc = 0x60;
	    memcpy(&((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_src, pkt+tpl->tpl[NF9_IPV6_SRC_ADDR].off, tpl->tpl[NF9_IPV6_SRC_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_dst, pkt+tpl->tpl[NF9_IPV6_DST_ADDR].off, tpl->tpl[NF9_IPV6_DST_ADDR].len);
	    memcpy(&((struct ip6_hdr *)pptrsv->vlan6.iph_ptr)->ip6_nxt, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    /* XXX: class ID ? */
	    memcpy(&((struct my_tlhdr *)pptrsv->vlan6.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->vlan6.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }
	  /* Let's copy some relevant field */
	  pptrsv->vlan6.l4_proto = 0;
	  memcpy(&pptrsv->vlan6.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  if (config.classifiers_path && tpl->tpl[NF9_CUST_CLASS].len == 16)
	    pptrsv->vlan6.class = NF_evaluate_classifiers((pptrsv->vlan6.f_data+tpl->tpl[NF9_CUST_CLASS].off));
	  if (config.pre_tag_map) pptrsv->vlan6.tag = NF_find_id(&pptrsv->vlan6);
	  exec_plugins(&pptrsv->vlan6);
	  break;
#endif
        case NF9_FTYPE_MPLS_IPV4:
          pptrsv->mpls4.f_header = pptrs->f_header;
          pptrsv->mpls4.f_data = pptrs->f_data;
          pptrsv->mpls4.f_tpl = pptrs->f_tpl;

          if (req->bpf_filter) {
	    u_char *ptr = pptrsv->mpls4.mpls_ptr;
	    u_int32_t idx;

            /* XXX: fix caplen */
            reset_mac(&pptrsv->mpls4);
            memcpy(pptrsv->mpls4.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
            memcpy(pptrsv->mpls4.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);

	    for (idx = NF9_MPLS_LABEL_1; idx <= NF9_MPLS_LABEL_10 && tpl->tpl[idx].len; idx++, ptr += 4) {
	      memset(ptr, 0, 4);
	      memcpy(ptr, pkt+tpl->tpl[idx].off, tpl->tpl[idx].len);
	    }
	    stick_bosbit(ptr-4);
	    pptrsv->mpls4.iph_ptr = ptr;
	    pptrsv->mpls4.tlh_ptr = ptr + IP4HdrSz;
            reset_ip4(&pptrsv->mpls4);

	    ((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_vhl = 0x45;
            memcpy(&((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
            memcpy(&((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
            memcpy(&((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
            memcpy(&((struct my_iphdr *)pptrsv->mpls4.iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
            memcpy(&((struct my_tlhdr *)pptrsv->mpls4.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
            memcpy(&((struct my_tlhdr *)pptrsv->mpls4.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
          }
	  /* Let's copy some relevant field */
	  pptrsv->mpls4.l4_proto = 0;
	  memcpy(&pptrsv->mpls4.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  if (config.classifiers_path && tpl->tpl[NF9_CUST_CLASS].len == 16)
	    pptrsv->mpls4.class = NF_evaluate_classifiers((pptrsv->mpls4.f_data+tpl->tpl[NF9_CUST_CLASS].off));
          if (config.pre_tag_map) pptrsv->mpls4.tag = NF_find_id(&pptrsv->mpls4);
          exec_plugins(&pptrsv->mpls4);
          break;
#if defined ENABLE_IPV6
	case NF9_FTYPE_MPLS_IPV6:
	  pptrsv->mpls6.f_header = pptrs->f_header;
	  pptrsv->mpls6.f_data = pptrs->f_data;
	  pptrsv->mpls6.f_tpl = pptrs->f_tpl;

	  if (req->bpf_filter) {
	    u_char *ptr = pptrsv->mpls6.mpls_ptr;
	    u_int32_t idx;

	    /* XXX: fix caplen */
	    reset_mac(&pptrsv->mpls6);
	    memcpy(pptrsv->mpls6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
	    memcpy(pptrsv->mpls6.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
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
	    memcpy(&((struct my_tlhdr *)pptrsv->mpls6.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->mpls6.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }
	  /* Let's copy some relevant field */
	  pptrsv->mpls6.l4_proto = 0;
	  memcpy(&pptrsv->mpls6.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  if (config.classifiers_path && tpl->tpl[NF9_CUST_CLASS].len == 16)
	    pptrsv->mpls6.class = NF_evaluate_classifiers((pptrsv->mpls6.f_data+tpl->tpl[NF9_CUST_CLASS].off));
	  if (config.pre_tag_map) pptrsv->mpls6.tag = NF_find_id(&pptrsv->mpls6);
	  exec_plugins(&pptrsv->mpls6);
	  break;
#endif
        case NF9_FTYPE_VLAN_MPLS_IPV4:
	  pptrsv->vlanmpls4.f_header = pptrs->f_header;
	  pptrsv->vlanmpls4.f_data = pptrs->f_data;
	  pptrsv->vlanmpls4.f_tpl = pptrs->f_tpl;

          if (req->bpf_filter) {
            u_char *ptr = pptrsv->vlanmpls4.mpls_ptr;
	    u_int32_t idx;

	    /* XXX: fix caplen */
	    reset_mac_vlan(&pptrsv->vlanmpls4);
	    memcpy(pptrsv->vlanmpls4.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
	    memcpy(pptrsv->vlanmpls4.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
	    memcpy(pptrsv->vlanmpls4.vlan_ptr, pkt+tpl->tpl[NF9_SRC_VLAN].off, tpl->tpl[NF9_SRC_VLAN].len);

	    for (idx = NF9_MPLS_LABEL_1; idx <= NF9_MPLS_LABEL_10 && tpl->tpl[idx].len; idx++, ptr += 4) {
	      memset(ptr, 0, 4);
	      memcpy(ptr, pkt+tpl->tpl[idx].off, tpl->tpl[idx].len);
	    }
	    stick_bosbit(ptr-4);
	    pptrsv->vlanmpls4.iph_ptr = ptr;
	    pptrsv->vlanmpls4.tlh_ptr = ptr + IP4HdrSz;
            reset_ip4(&pptrsv->vlanmpls4);

	    ((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_vhl = 0x45;
            memcpy(&((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_src, pkt+tpl->tpl[NF9_IPV4_SRC_ADDR].off, tpl->tpl[NF9_IPV4_SRC_ADDR].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_dst, pkt+tpl->tpl[NF9_IPV4_DST_ADDR].off, tpl->tpl[NF9_IPV4_DST_ADDR].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_p, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);
	    memcpy(&((struct my_iphdr *)pptrsv->vlanmpls4.iph_ptr)->ip_tos, pkt+tpl->tpl[NF9_SRC_TOS].off, tpl->tpl[NF9_SRC_TOS].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->vlanmpls4.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->vlanmpls4.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }
	  /* Let's copy some relevant field */
	  pptrsv->vlanmpls4.l4_proto = 0;
	  memcpy(&pptrsv->vlanmpls4.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  if (config.classifiers_path && tpl->tpl[NF9_CUST_CLASS].len == 16)
	    pptrsv->vlanmpls4.class = NF_evaluate_classifiers((pptrsv->vlanmpls4.f_data+tpl->tpl[NF9_CUST_CLASS].off));
	  if (config.pre_tag_map) pptrsv->vlanmpls4.tag = NF_find_id(&pptrsv->vlanmpls4);
	  exec_plugins(&pptrsv->vlanmpls4);
	  break;
#if defined ENABLE_IPV6
        case NF9_FTYPE_VLAN_MPLS_IPV6:
	  pptrsv->vlanmpls6.f_header = pptrs->f_header;
	  pptrsv->vlanmpls6.f_data = pptrs->f_data;
	  pptrsv->vlanmpls6.f_tpl = pptrs->f_tpl;

          if (req->bpf_filter) {
            u_char *ptr = pptrsv->vlanmpls6.mpls_ptr;
            u_int32_t idx;

            /* XXX: fix caplen */
	    reset_mac_vlan(&pptrsv->vlanmpls6);
	    memcpy(pptrsv->vlanmpls6.mac_ptr+ETH_ADDR_LEN, pkt+tpl->tpl[NF9_SRC_MAC].off, tpl->tpl[NF9_SRC_MAC].len);
	    memcpy(pptrsv->vlanmpls6.mac_ptr, pkt+tpl->tpl[NF9_DST_MAC].off, tpl->tpl[NF9_DST_MAC].len);
	    memcpy(pptrsv->vlanmpls6.vlan_ptr, pkt+tpl->tpl[NF9_SRC_VLAN].off, tpl->tpl[NF9_SRC_VLAN].len);
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
	    memcpy(&((struct my_tlhdr *)pptrsv->vlanmpls6.tlh_ptr)->src_port, pkt+tpl->tpl[NF9_L4_SRC_PORT].off, tpl->tpl[NF9_L4_SRC_PORT].len);
	    memcpy(&((struct my_tlhdr *)pptrsv->vlanmpls6.tlh_ptr)->dst_port, pkt+tpl->tpl[NF9_L4_DST_PORT].off, tpl->tpl[NF9_L4_DST_PORT].len);
	  }
	  /* Let's copy some relevant field */
	  pptrsv->vlanmpls6.l4_proto = 0;
	  memcpy(&pptrsv->vlanmpls6.l4_proto, pkt+tpl->tpl[NF9_L4_PROTOCOL].off, tpl->tpl[NF9_L4_PROTOCOL].len);

	  if (config.classifiers_path && tpl->tpl[NF9_CUST_CLASS].len == 16)
	    pptrsv->vlanmpls6.class = NF_evaluate_classifiers((pptrsv->vlanmpls6.f_data+tpl->tpl[NF9_CUST_CLASS].off));
	  if (config.pre_tag_map) pptrsv->vlanmpls6.tag = NF_find_id(&pptrsv->vlanmpls6);
	  exec_plugins(&pptrsv->vlanmpls6);
	  break;
#endif
	default:
	  break;
        }

        pkt += tpl->len;
        flowoff += tpl->len;
      }

      pkt += flowsetlen-flowoff; /* handling padding */
      off += flowsetlen; 
    }
  }
  else { /* unsupported flowset */
    data_hdr = (struct data_hdr_v9 *)pkt;
    flowsetlen = ntohs(data_hdr->flow_len);
    if (off+flowsetlen > len) {
      Log(LOG_DEBUG, "DEBUG ( default/core ): unable to read unsupported Flowset (ID: '%u').\n", fid);
      return;
    }
    pkt += flowsetlen;
    off += flowsetlen;
  }

  if (off < len) goto process_flowset;
}

void load_allow_file(char *filename, struct hosts_table *t)
{
  FILE *file;
  char buf[SRVBUFLEN];
  int index = 0;

  if (filename) {
    if ((file = fopen(filename, "r")) == NULL) {
      Log(LOG_ERR, "ERROR ( default/core ): allow file '%s' not found\n", filename);
      exit(1);
    }

    memset(t->table, 0, sizeof(t->table)); 
    while (!feof(file)) {
      if (index >= MAX_MAP_ENTRIES) break; /* XXX: we shouldn't exit silently */ 
      memset(buf, 0, SRVBUFLEN);
      if (fgets(buf, SRVBUFLEN, file)) { 
        if (!sanitize_buf(buf)) {
	  if (str_to_addr(buf, &t->table[index])) index++;
	  else Log(LOG_WARNING, "WARN ( default/core ): 'nfacctd_allow_file': Bad IP address '%s'. Ignored.\n", buf);
        }
      }
    }
    t->num = index;
  }
}

int check_allow(struct hosts_table *allow, struct sockaddr *sa)
{
  int index;

  for (index = 0; index < allow->num; index++) {
    if (((struct sockaddr *)sa)->sa_family == allow->table[index].family) {
      if (allow->table[index].family == AF_INET) {
        if (((struct sockaddr_in *)sa)->sin_addr.s_addr == allow->table[index].address.ipv4.s_addr)
          return TRUE;
      }
#if defined ENABLE_IPV6
      else if (allow->table[index].family == AF_INET6) {
        if (!ip6_addr_cmp(&(((struct sockaddr_in6 *)sa)->sin6_addr), &allow->table[index].address.ipv6))
          return TRUE;
      }
#endif
    }
  }
  
  return FALSE;
}

void compute_once()
{
  struct pkt_data dummy;

  CounterSz = sizeof(dummy.pkt_len);
  PdataSz = sizeof(struct pkt_data);
  PpayloadSz = sizeof(struct pkt_payload);
  PextrasSz = sizeof(struct pkt_extras);
  PbgpSz = sizeof(struct pkt_bgp_primitives);
  ChBufHdrSz = sizeof(struct ch_buf_hdr);
  CharPtrSz = sizeof(char *);
  NfHdrV1Sz = sizeof(struct struct_header_v1);
  NfHdrV5Sz = sizeof(struct struct_header_v5);
  NfHdrV7Sz = sizeof(struct struct_header_v7);
  NfHdrV8Sz = sizeof(struct struct_header_v8);
  NfHdrV9Sz = sizeof(struct struct_header_v9);
  NfDataHdrV9Sz = sizeof(struct data_hdr_v9);
  NfTplHdrV9Sz = sizeof(struct template_hdr_v9);
  NfDataV1Sz = sizeof(struct struct_export_v1);
  NfDataV5Sz = sizeof(struct struct_export_v5);
  NfDataV7Sz = sizeof(struct struct_export_v7);
  IP4HdrSz = sizeof(struct my_iphdr);
  IP4TlSz = sizeof(struct my_iphdr)+sizeof(struct my_tlhdr);
  PptrsSz = sizeof(struct packet_ptrs);
  CSSz = sizeof(struct class_st);
  HostAddrSz = sizeof(struct host_addr);

#if defined ENABLE_IPV6
  IP6HdrSz = sizeof(struct ip6_hdr);
  IP6AddrSz = sizeof(struct in6_addr);
  IP6TlSz = sizeof(struct ip6_hdr)+sizeof(struct my_tlhdr);
#endif
}

u_int16_t NF_evaluate_flow_type(struct template_cache_entry *tpl, struct packet_ptrs *pptrs)
{
  u_int8_t ret=0;

  if (tpl->tpl[NF9_SRC_VLAN].len && *(pptrs->f_data+tpl->tpl[NF9_SRC_VLAN].off) > 0) ret += NF9_FTYPE_VLAN; 
  if (tpl->tpl[NF9_MPLS_LABEL_1].len /* check: value > 0 ? */) ret += NF9_FTYPE_MPLS; 
  if (*(pptrs->f_data+tpl->tpl[NF9_IP_PROTOCOL_VERSION].off) == 4 || tpl->tpl[NF9_IPV4_SRC_ADDR].len > 0);
  else if (*(pptrs->f_data+tpl->tpl[NF9_IP_PROTOCOL_VERSION].off) == 6 || tpl->tpl[NF9_IPV6_SRC_ADDR].len > 0) ret += NF9_FTYPE_IPV6;

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

void notify_malf_packet(short int severity, char *ostr, struct sockaddr *sa)
{
  struct host_addr a;
  u_char errstr[SRVBUFLEN];
  u_char agent_addr[50] /* able to fit an IPv6 string aswell */, any[]="0.0.0.0";
  u_int16_t agent_port;

  sa_to_addr(sa, &a, &agent_port);
  addr_to_str(agent_addr, &a);
  if (!config.nfacctd_ip) config.nfacctd_ip = any;
  snprintf(errstr, SRVBUFLEN, "%s: nfacctd=%s:%u agent=%s:%u \n",
  ostr, config.nfacctd_ip, config.nfacctd_port, agent_addr, agent_port);
  Log(severity, errstr);
}

int NF_find_id(struct packet_ptrs *pptrs)
{
  struct id_table *t = (struct id_table *)pptrs->idtable;
  int x, j, id, stop;
  void *src_ret, *dst_ret;

  /* The id_table is shared between by IPv4 and IPv6 NetFlow agents.
     IPv4 ones are in the lower part (0..x), IPv6 ones are in the upper
     part (x+1..end)
  */

  id = 0;
  if (((struct sockaddr *)pptrs->f_agent)->sa_family == AF_INET) {
    for (x = 0; x < t->ipv4_num; x++) {
      if (t->e[x].agent_ip.a.address.ipv4.s_addr == ((struct sockaddr_in *)pptrs->f_agent)->sin_addr.s_addr) {
        for (j = 0, stop = 0; !stop; j++) stop = (*t->e[x].func[j])(pptrs, &id, &t->e[x]);
        if (id) {
	  if (t->e[x].stack.func) id = (*t->e[x].stack.func)(id, pptrs->tag);
          pptrs->tag = id;
          pptrs->tag_dist = t->e[x].ret;

          if (t->e[x].jeq.ptr) {
            exec_plugins(pptrs);

            x = t->e[x].jeq.ptr->pos;
            x--; /* yes, it will be automagically incremented by the for() cycle */
            if (t->e[x].ret) set_shadow_status(pptrs);
            id = 0;
          }
          else break;
        }
      }
    }
  }
#if defined ENABLE_IPV6
  else if (((struct sockaddr *)pptrs->f_agent)->sa_family == AF_INET6) {
    for (x = (t->num-t->ipv6_num); x < t->num; x++) {
      if (!ip6_addr_cmp(&t->e[x].agent_ip.a.address.ipv6, (&((struct sockaddr_in6 *)pptrs->f_agent)->sin6_addr))) {
        for (j = 0, stop = 0; !stop; j++) stop = (*t->e[x].func[j])(pptrs, &id, &t->e[x]);
        if (id) {
	  if (t->e[x].stack.func) id = (*t->e[x].stack.func)(id, pptrs->tag);
	  pptrs->tag = id;
	  pptrs->tag_dist = t->e[x].ret;

	  if (t->e[x].jeq.ptr) {
	    exec_plugins(pptrs);

	    x = t->e[x].jeq.ptr->pos;
	    x--; /* yes, it will be automagically incremented by the for() cycle */
	    if (t->e[x].ret) set_shadow_status(pptrs);
	    id = 0;
	  }
  	  else break;
	}
      }
    }
  }
#endif
  return id;
}

char *nfv578_check_status(struct packet_ptrs *pptrs)
{
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent;
  u_int32_t aux1 = (hdr->engine_id << 8 | hdr->engine_type);
  int hash = hash_status_table(aux1, sa, XFLOW_STATUS_TABLE_SZ);
  struct xflow_status_entry *entry = NULL;
  
  if (hash >= 0) {
    entry = search_status_table(sa, aux1, hash, XFLOW_STATUS_TABLE_MAX_ENTRIES);
    update_status_table(entry, ntohl(hdr->flow_sequence));
    entry->inc = ntohs(hdr->count);
  }

  return (char *) entry;
}

char *nfv9_check_status(struct packet_ptrs *pptrs)
{
  struct struct_header_v9 *hdr = (struct struct_header_v9 *) pptrs->f_header;
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent;
  u_int32_t aux1 = ntohl(hdr->source_id);
  int hash = hash_status_table(aux1, sa, XFLOW_STATUS_TABLE_SZ);
  struct xflow_status_entry *entry = NULL;
  
  if (hash >= 0) {
    entry = search_status_table(sa, aux1, hash, XFLOW_STATUS_TABLE_MAX_ENTRIES);
    update_status_table(entry, ntohl(hdr->flow_sequence));
    entry->inc = 1;
  }

  return (char *) entry;
}
