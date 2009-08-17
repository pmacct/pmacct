/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2008 by Paolo Lucente
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
#define __PMACCTD_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "pmacct-dlt.h"
#include "pretag_handlers.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "ip_frag.h"
#include "ip_flow.h"
#include "net_aggr.h"
#include "thread_pool.h"

/* variables to be exported away */
int debug;
struct configuration config; /* global configuration */ 
struct plugins_list_entry *plugins_list = NULL; /* linked list of each plugin configuration */ 
struct channels_list_entry channels_list[MAX_N_PLUGINS]; /* communication channels: core <-> plugins */
int have_num_memory_pools; /* global getopt() stuff */
pid_t failed_plugins[MAX_N_PLUGINS]; /* plugins failed during startup phase */
u_char dummy_tlhdr[16];

/* Functions */
void usage_daemon(char *prog_name)
{
  printf("%s\n", PMACCTD_USAGE_HEADER);
  printf("Usage: %s [ -D | -d ] [ -i interface ] [ -c primitive [ , ... ] ] [ -P plugin [ , ... ] ] [ filter ]\n", prog_name);
  printf("       %s [ -f config_file ]\n", prog_name);
  printf("       %s [ -h ]\n", prog_name);
  printf("\nGeneral options:\n");
  printf("  -h  \tShow this page\n");
  printf("  -f  \tLoad configuration from the specified file\n");
  printf("  -c  \t[ src_mac | dst_mac | vlan | src_host | dst_host | src_net | dst_net | src_port | dst_port |\n\t proto | tos | src_as | dst_as | sum_mac | sum_host | sum_net | sum_as | sum_port | tag |\n\t flows | class | tcpflags | none ] \n\tAggregation string (DEFAULT: src_host)\n");
  printf("  -D  \tDaemonize\n"); 
  printf("  -N  \tDisable promiscuous mode\n");
  printf("  -n  \tPath to a file containing Network definitions\n");
  printf("  -o  \tPath to a file containing Port definitions\n");
  printf("  -P  \t[ memory | print | mysql | pgsql | sqlite3 | nfprobe | sfprobe ] \n\tActivate plugin\n"); 
  printf("  -d  \tEnable debug\n");
  printf("  -i  \tListen on the specified interface\n");
  printf("  -I  \tRead packets from the specified savefile\n");
  printf("  -S  \t[ auth | mail | daemon | kern | user | local[0-7] ] \n\tLog to the specified syslog facility\n");
  printf("  -F  \tWrite Core Process PID into the specified file\n");
  printf("  -w  \tWait for the listening interface to become available\n");
  printf("  -W  \tReading from a savefile, don't exit but sleep when finished\n");
  printf("\nMemory Plugin (-P memory) options:\n");
  printf("  -p  \tSocket for client-server communication (DEFAULT: /tmp/collect.pipe)\n");
  printf("  -b  \tNumber of buckets\n");
  printf("  -m  \tNumber of memory pools\n");
  printf("  -s  \tMemory pool size\n");
  printf("\nPostgreSQL (-P pgsql)/MySQL (-P mysql)/SQLite (-P sqlite3) plugin options:\n");
  printf("  -r  \tRefresh time (in seconds)\n");
  printf("  -v  \t[ 1 | 2 | 3 | 4 | 5 | 6 | 7 ] \n\tTable version\n");
  printf("\n");
  printf("  See EXAMPLES or visit http://wiki.pmacct.net/ for examples.\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}


int main(int argc,char **argv, char **envp)
{
  bpf_u_int32 localnet, netmask;  /* pcap library stuff */
  struct bpf_program filter;
  struct pcap_device device;
  char errbuf[PCAP_ERRBUF_SIZE];
  int index, logf;

  struct plugins_list_entry *list;
  struct plugin_requests req;
  char config_file[SRVBUFLEN];
  int psize = DEFAULT_SNAPLEN;

  struct id_table bpas_table;
  struct id_table bta_table;
  struct id_table idt;
  struct pcap_callback_data cb_data;

  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp; 

#if defined ENABLE_IPV6
  struct sockaddr_storage client;
#else
  struct sockaddr client;
#endif


  umask(077);
  compute_once();

  /* a bunch of default definitions */ 
  have_num_memory_pools = FALSE;
  reload_map = FALSE;
  tag_map_allocated = FALSE;
  bpas_map_allocated = FALSE;

  errflag = 0;

  memset(cfg_cmdline, 0, sizeof(cfg_cmdline));
  memset(&config, 0, sizeof(struct configuration));
  memset(&device, 0, sizeof(struct pcap_device));
  memset(&config_file, 0, sizeof(config_file));
  memset(&failed_plugins, 0, sizeof(failed_plugins));
  memset(&req, 0, sizeof(req));
  memset(dummy_tlhdr, 0, sizeof(dummy_tlhdr));
  memset(sll_mac, 0, sizeof(sll_mac));
  memset(&bpas_table, 0, sizeof(bpas_table));
  memset(&bta_table, 0, sizeof(bta_table));
  memset(&client, 0, sizeof(client));
  memset(&cb_data, 0, sizeof(cb_data));
  config.acct_type = ACCT_PM;

  rows = 0;
  glob_pcapt = NULL;

  /* getting commandline values */
  while (!errflag && ((cp = getopt(argc, argv, ARGS_PMACCTD)) != -1)) {
    cfg_cmdline[rows] = malloc(SRVBUFLEN);
    switch (cp) {
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
    case 'N':
      strlcpy(cfg_cmdline[rows], "promisc: false", SRVBUFLEN);
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
    case 'i':
      strlcpy(cfg_cmdline[rows], "interface: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'I':
      strlcpy(cfg_cmdline[rows], "pcap_savefile: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'w':
      strlcpy(cfg_cmdline[rows], "interface_wait: true", SRVBUFLEN);
      rows++;
      break;
    case 'W':
      strlcpy(cfg_cmdline[rows], "savefile_wait: true", SRVBUFLEN);
      rows++;
      break;
    case 'L':
      strlcpy(cfg_cmdline[rows], "snaplen: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
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
    list->cfg.acct_type = ACCT_PM;
    if (!strcmp(list->name, "default") && !strcmp(list->type.string, "core")) 
      memcpy(&config, &list->cfg, sizeof(struct configuration)); 
    list = list->next;
  }

  /* Let's check whether we need superuser privileges */
  if (config.snaplen) psize = config.snaplen;
  else config.snaplen = psize;

  if (!config.pcap_savefile) {
    if (getuid() != 0) {
      printf("%s\n\n", PMACCTD_USAGE_HEADER);
      printf("ERROR: You need superuser privileges to run this command.\nExiting ...\n\n");
      exit(1);
    }
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
	if (config.classifiers_path && list->cfg.sampling_rate) {
	  Log(LOG_ERR, "ERROR: Packet sampling and classification are actually mutual exclusive.\n");
	  exit(1);
	}
	config.handle_fragments = TRUE;
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
	if (list->cfg.networks_file || (list->cfg.nfacctd_bgp && list->cfg.nfacctd_as == NF_AS_BGP)) {
	  list->cfg.what_to_count |= COUNT_SRC_AS;
	  list->cfg.what_to_count |= COUNT_DST_AS;
	}
	if (list->cfg.nfprobe_version == 9 && list->cfg.classifiers_path) {
	  list->cfg.what_to_count |= COUNT_CLASS; 
	  config.handle_flows = TRUE;
	}
	if (list->cfg.nfprobe_version == 9 && list->cfg.pre_tag_map)
	  list->cfg.what_to_count |= COUNT_ID;
	if (list->cfg.what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM|COUNT_LOCAL_PREF|COUNT_MED|COUNT_AS_PATH|
                                       COUNT_PEER_SRC_AS|COUNT_PEER_DST_AS|COUNT_PEER_SRC_IP|COUNT_PEER_DST_IP)) {
	  Log(LOG_ERR, "ERROR: 'src_as' and 'dst_as' are currently the only BGP-related primitives supported within the 'nfprobe' plugin.\n");
	  exit(1);
	}
	list->cfg.what_to_count |= COUNT_COUNTERS;

	list->cfg.data_type = PIPE_TYPE_METADATA;
	list->cfg.data_type |= PIPE_TYPE_EXTRAS;
      }
      else if (list->type.id == PLUGIN_ID_SFPROBE) {
        config.handle_fragments = FALSE;
	if (psize < 128) psize = config.snaplen = 128; /* SFL_DEFAULT_HEADER_SIZE */
	list->cfg.what_to_count = COUNT_PAYLOAD;
	if (list->cfg.classifiers_path) {
	  list->cfg.what_to_count |= COUNT_CLASS;
	  config.handle_fragments = TRUE;
	  config.handle_flows = TRUE;
	}
        if (list->cfg.nfacctd_bgp && list->cfg.nfacctd_as == NF_AS_BGP) {
          list->cfg.what_to_count |= COUNT_SRC_AS;
          list->cfg.what_to_count |= COUNT_DST_AS;
        }
	if (list->cfg.pre_tag_map) list->cfg.what_to_count |= COUNT_ID;

	list->cfg.data_type = PIPE_TYPE_PAYLOAD;
      }
      else {
        if (config.classifiers_path && list->cfg.sampling_rate) {
	  Log(LOG_ERR, "ERROR: Packet sampling and classification are actually mutual exclusive.\n");
	  exit(1);
        }
	evaluate_sums(&list->cfg.what_to_count, list->name, list->type.string);
	if (list->cfg.what_to_count & (COUNT_SRC_PORT|COUNT_DST_PORT|COUNT_SUM_PORT|COUNT_TCPFLAGS))
	  config.handle_fragments = TRUE;
	if (list->cfg.what_to_count & COUNT_FLOWS) {
	  config.handle_fragments = TRUE;
	  config.handle_flows = TRUE;
	}
	if (list->cfg.what_to_count & COUNT_CLASS) {
	  config.handle_fragments = TRUE;
	  config.handle_flows = TRUE;
	}
	if (!list->cfg.what_to_count) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): defaulting to SRC HOST aggregation.\n", list->name, list->type.string);
	  list->cfg.what_to_count |= COUNT_SRC_HOST;
	}
	if ((list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) && !list->cfg.networks_file && list->cfg.nfacctd_as != NF_AS_BGP) { 
	  Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation selected but NO 'networks_file' or 'pmacctd_bgp' are specified. Exiting...\n\n", list->name, list->type.string);
	  exit(1);
	}
	if ((list->cfg.what_to_count & (COUNT_SRC_NET|COUNT_DST_NET|COUNT_SUM_NET)) && !list->cfg.networks_file && !list->cfg.networks_mask) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): NET aggregation selected but NO 'networks_file' specified. Exiting...\n\n", list->name, list->type.string);
	  exit(1);
	}
	if (list->cfg.what_to_count & COUNT_CLASS && !list->cfg.classifiers_path) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): 'class' aggregation selected but NO 'classifiers' key specified. Exiting...\n\n", list->name, list->type.string);
	  exit(1);
	}
        if (list->cfg.what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM|COUNT_LOCAL_PREF|COUNT_MED|COUNT_AS_PATH|
                                       COUNT_PEER_SRC_AS|COUNT_PEER_DST_AS|COUNT_PEER_SRC_IP|COUNT_PEER_DST_IP)) {
          /* Sanitizing the aggregation method */
          if ( (list->cfg.what_to_count & COUNT_STD_COMM) && (list->cfg.what_to_count & COUNT_EXT_COMM) ) {
            printf("ERROR: The use of STANDARD and EXTENDED BGP communitities is mutual exclusive.\n");
            exit(1);
          }
          list->cfg.data_type |= PIPE_TYPE_BGP;
        }
	list->cfg.what_to_count |= COUNT_COUNTERS;
	list->cfg.data_type |= PIPE_TYPE_METADATA;
      }
    }
    list = list->next;
  }

#if defined ENABLE_THREADS
  if (!config.flow_handling_threads) config.flow_handling_threads = DEFAULT_TH_NUM; 
#endif

  /* plugins glue: creation (since 094) */
  if (config.classifiers_path) {
    init_classifiers(config.classifiers_path);
    init_conntrack_table();
  }
  load_plugins(&req);

  if (config.handle_fragments) init_ip_fragment_handler();
  if (config.handle_flows) init_ip_flow_handler();
  load_networks(config.networks_file, &nt, &nc);

  /* If any device/savefile have been specified, choose a suitable device
     where to listen for traffic */ 
  if (!config.dev && !config.pcap_savefile) {
    Log(LOG_WARNING, "WARN ( default/core ): Selecting a suitable device.\n");
    config.dev = pcap_lookupdev(errbuf); 
    if (!config.dev) {
      Log(LOG_WARNING, "WARN ( default/core ): Unable to find a suitable device. Exiting.\n");
      exit_all(1);
    }
    else Log(LOG_DEBUG, "DEBUG ( default/core ): device is %s\n", config.dev);
  }

  /* reading filter; if it exists, we'll take an action later */
  if (!strlen(config_file)) config.clbuf = copy_argv(&argv[optind]);

  if (config.dev && config.pcap_savefile) {
    Log(LOG_ERR, "ERROR ( default/core ): 'interface' (-i) and 'pcap_savefile' (-I) directives are mutually exclusive. Exiting.\n");
    exit_all(1); 
  }

  throttle_startup:
  if (config.dev) {
    if ((device.dev_desc = pcap_open_live(config.dev, psize, config.promisc, 1000, errbuf)) == NULL) {
      if (!config.if_wait) {
        Log(LOG_ERR, "ERROR ( default/core ): pcap_open_live(): %s\n", errbuf);
        exit_all(1);
      }
      else {
        sleep(5); /* XXX: user defined ? */
        goto throttle_startup;
      }
    } 
  }
  else if (config.pcap_savefile) {
    if ((device.dev_desc = pcap_open_offline(config.pcap_savefile, errbuf)) == NULL) {
      Log(LOG_ERR, "ERROR ( default/core ): pcap_open_offline(): %s\n", errbuf);
      exit_all(1);
    }
  }

  device.active = TRUE;
  glob_pcapt = device.dev_desc; /* SIGINT/stats handling */ 
  if (config.pipe_size) {
    int slen = sizeof(config.pipe_size), x;

#if defined (PCAP_TYPE_linux) || (PCAP_TYPE_snoop)
    Setsocksize(pcap_fileno(device.dev_desc), SOL_SOCKET, SO_RCVBUF, &config.pipe_size, slen);
    getsockopt(pcap_fileno(device.dev_desc), SOL_SOCKET, SO_RCVBUF, &x, &slen);
    Log(LOG_DEBUG, "DEBUG ( default/core ): PCAP buffer: obtained %d / %d bytes.\n", x, config.pipe_size);
#endif
  }

  device.link_type = pcap_datalink(device.dev_desc); 
  for (index = 0; _devices[index].link_type != -1; index++) {
    if (device.link_type == _devices[index].link_type)
      device.data = &_devices[index];
  }
  load_plugin_filters(device.link_type);

  /* we need to solve some link constraints */
  if (device.data == NULL) {
    Log(LOG_ERR, "ERROR ( default/core ): data link not supported: %d\n", device.link_type); 
    exit_all(1);
  }
  else Log(LOG_INFO, "OK ( default/core ): link type is: %d\n", device.link_type); 

  if (device.link_type != DLT_EN10MB && device.link_type != DLT_IEEE802 && device.link_type != DLT_LINUX_SLL) {
    list = plugins_list;
    while (list) {
      if ((list->cfg.what_to_count & COUNT_SRC_MAC) || (list->cfg.what_to_count & COUNT_DST_MAC)) {
        Log(LOG_ERR, "ERROR ( default/core ): MAC aggregation not available for link type: %d\n", device.link_type);
        exit_all(1);
      }
      list = list->next;
    }
  }

  cb_data.device = &device;
  
  /* doing pcap stuff */
  if (pcap_lookupnet(config.dev, &localnet, &netmask, errbuf) < 0) {
    localnet = 0;
    netmask = 0;
    Log(LOG_WARNING, "WARN ( default/core ): %s\n", errbuf);
  }

  if (pcap_compile(device.dev_desc, &filter, config.clbuf, 0, netmask) < 0)
    Log(LOG_WARNING, "WARN: %s\nWARN ( default/core ): going on without a filter\n", pcap_geterr(device.dev_desc));
  else {
    if (pcap_setfilter(device.dev_desc, &filter) < 0)
      Log(LOG_WARNING, "WARN: %s\nWARN ( default/core ): going on without a filter\n", pcap_geterr(device.dev_desc));
  }

  /* signal handling we want to inherit to plugins (when not re-defined elsewhere) */
  signal(SIGCHLD, startup_handle_falling_child); /* takes note of plugins failed during startup phase */
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGUSR1, push_stats); /* logs various statistics via Log() calls */
  signal(SIGUSR2, reload_maps); /* sets to true the reload_maps flag */
  signal(SIGPIPE, SIG_IGN); /* we want to exit gracefully when a pipe is broken */

  /* loading pre-tagging map, if any */
  if (config.pre_tag_map) {
    load_id_file(config.acct_type, config.pre_tag_map, &idt, &req, &tag_map_allocated);
    cb_data.idt = (u_char *) &idt;
  }
  else {
    memset(&idt, 0, sizeof(idt));
    cb_data.idt = NULL; 
  }

#if defined ENABLE_THREADS
  /* starting the BGP thread */
  if (config.nfacctd_bgp) {
    req.bpf_filter = TRUE;
    load_comm_patterns(&config.nfacctd_bgp_stdcomm_pattern, &config.nfacctd_bgp_extcomm_pattern, &config.nfacctd_bgp_stdcomm_pattern_to_asn);

    if (config.nfacctd_bgp_peer_as_src_type == PEER_SRC_AS_MAP) {
      if (config.nfacctd_bgp_peer_as_src_map) {
        load_id_file(MAP_BGP_PEER_AS_SRC, config.nfacctd_bgp_peer_as_src_map, &bpas_table, &req, &bpas_map_allocated);
	cb_data.bpas_table = (u_char *) &bpas_table;
      }
      else cb_data.bpas_table = NULL;
    }
    if (config.nfacctd_bgp_to_agent_map) {
      load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.nfacctd_bgp_to_agent_map, &bta_table, &req, &bta_map_allocated);
      cb_data.bta_table = (u_char *) &bta_table;
    }
    else {
      Log(LOG_ERR, "ERROR ( default/core ): 'bgp_daemon' configured but no 'bgp_agent_map' has been specified. Exiting.\n");
      exit(1);
    }

    cb_data.f_agent = (char *)&client;
    nfacctd_bgp_wrapper();

    /* Sleep a bit to let the other thread initialize structures */
    sleep(5);
  }
#else
  if (config.nfacctd_bgp) {
    Log(LOG_ERR, "ERROR ( default/core ): 'bgp_daemon' is available only with threads (--enable-threads). Exiting.\n");
    exit(1);
  }
#endif

  /* plugins glue: creation (until 093) */
  evaluate_packet_handlers();
  pm_setproctitle("%s [%s]", "Core Process", "default");
  if (config.pidfile) write_pid_file(config.pidfile);  

  /* signals to be handled only by pmacctd;
     we set proper handlers after plugin creation */
  signal(SIGINT, my_sigint_handler);
  signal(SIGTERM, my_sigint_handler);
  signal(SIGCHLD, handle_falling_child);
  kill(getpid(), SIGCHLD);

  /* When reading packets from a savefile, things are lightning fast; we will sit 
     here just few seconds, thus allowing plugins to complete their startup operations */ 
  if (config.pcap_savefile) {
    Log(LOG_INFO, "INFO ( default/core ): PCAP capture file, sleeping for 2 seconds\n");
    sleep(2);
  }

  /* Main loop: if pcap_loop() exits maybe an error occurred; we will try closing
     and reopening again our listening device */
  for(;;) {
    if (!device.active) {
      Log(LOG_WARNING, "WARN ( default/core ): %s has become unavailable; throttling ...\n", config.dev);
      throttle_loop:
      sleep(5); /* XXX: user defined ? */
      if ((device.dev_desc = pcap_open_live(config.dev, psize, config.promisc, 1000, errbuf)) == NULL)
        goto throttle_loop;
      pcap_setfilter(device.dev_desc, &filter);
      device.active = TRUE;
    }
    pcap_loop(device.dev_desc, -1, pcap_cb, (u_char *) &cb_data);
    pcap_close(device.dev_desc);

    if (config.pcap_savefile) {
      if (config.sf_wait) {
	fill_pipe_buffer();
	Log(LOG_INFO, "INFO ( default/core ): finished reading PCAP capture file\n");
	wait(NULL);
      }
      stop_all_childs();
    }
    device.active = FALSE;
  }
}

void pcap_cb(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *buf)
{
  struct packet_ptrs pptrs;
  struct pcap_callback_data *cb_data = (struct pcap_callback_data *) user;
  struct pcap_device *device = cb_data->device; 
  struct plugin_requests req;

  /* We process the packet with the appropriate
     data link layer function */
  if (buf) {
    pptrs.pkthdr = (struct pcap_pkthdr *) pkthdr;
    pptrs.packet_ptr = (u_char *) buf;
    pptrs.mac_ptr = 0; pptrs.vlan_ptr = 0; pptrs.mpls_ptr = 0;
    pptrs.pf = 0; pptrs.shadow = 0; pptrs.tag_dist = 1; pptrs.tag = 0;
    pptrs.class = 0; pptrs.bpas = 0, pptrs.bta = 0;
    pptrs.f_agent = cb_data->f_agent;
    pptrs.idtable = cb_data->idt;
    pptrs.bpas_table = cb_data->bpas_table;
    pptrs.bta_table = cb_data->bta_table;

    (*device->data->handler)(pkthdr, &pptrs);
    if (pptrs.iph_ptr) {
      if ((*pptrs.l3_handler)(&pptrs)) {
	if (config.nfacctd_bgp_to_agent_map) pptrs.bta = PM_find_id((struct id_table *)pptrs.bta_table, &pptrs);
	if (config.nfacctd_bgp) bgp_srcdst_lookup(&pptrs);
        if (config.nfacctd_bgp_peer_as_src_map) pptrs.bpas = PM_find_id((struct id_table *)pptrs.bpas_table, &pptrs);
	if (config.pre_tag_map) pptrs.tag = PM_find_id((struct id_table *)pptrs.idtable, &pptrs);

	exec_plugins(&pptrs); 
      }
    }
  }

  if (reload_map) {
    load_networks(config.networks_file, &nt, &nc);
    if (config.nfacctd_bgp && config.nfacctd_bgp_peer_as_src_map)
      load_id_file(MAP_BGP_PEER_AS_SRC, config.nfacctd_bgp_peer_as_src_map, (struct id_table *)cb_data->bpas_table, &req, &bpas_map_allocated);
    if (config.nfacctd_bgp && config.nfacctd_bgp_to_agent_map)
      load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.nfacctd_bgp_to_agent_map, (struct id_table *)cb_data->bta_table, &req, &bta_map_allocated);
    if (config.pre_tag_map)
      load_id_file(config.acct_type, config.pre_tag_map, (struct id_table *) pptrs.idtable, &req, &tag_map_allocated);
    reload_map = FALSE;
  }
} 

int ip_handler(register struct packet_ptrs *pptrs)
{
  register u_int8_t len = 0;
  register u_int16_t caplen = ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen;
  register unsigned char *ptr;
  register u_int16_t off = pptrs->iph_ptr-pptrs->packet_ptr, off_l4;
  int ret = TRUE;

  /* len: number of 32bit words forming the header */
  len = IP_HL(((struct my_iphdr *) pptrs->iph_ptr));
  len <<= 2;
  ptr = pptrs->iph_ptr+len;
  off += len;

  /* check len */
  if (off > caplen) return FALSE; /* IP packet truncated */
  pptrs->l4_proto = ((struct my_iphdr *)pptrs->iph_ptr)->ip_p;
  pptrs->payload_ptr = NULL; 
  off_l4 = off;
  
  /* check fragments if needed */
  if (config.handle_fragments) {
    if (pptrs->l4_proto == IPPROTO_TCP || pptrs->l4_proto == IPPROTO_UDP) {
      if (off+MyTLHdrSz > caplen) {
	Log(LOG_INFO, "INFO ( default/core ): short IPv4 packet read (%u/%u/frags). Snaplen issue ?\n", caplen, off+MyTLHdrSz);
	return FALSE; 
      }
      pptrs->tlh_ptr = ptr; 
    
      if (((struct my_iphdr *)pptrs->iph_ptr)->ip_off & htons(IP_MF|IP_OFFMASK)) {
        ret = ip_fragment_handler(pptrs);
	if (!ret) goto quit;
      }

      /* Let's handle both fragments and packets. If we are facing any subsequent frag
	 our pointer is in place; we handle unknown L4 protocols likewise. In case of
	 "entire" TCP/UDP packets we have to jump the L4 header instead */
      if (((struct my_iphdr *)pptrs->iph_ptr)->ip_off & htons(IP_OFFMASK));
      else if (pptrs->l4_proto == IPPROTO_UDP) {
	ptr += UDPHdrSz;
        off += UDPHdrSz;  
      }
      else if (pptrs->l4_proto == IPPROTO_TCP) {
        ptr += ((struct my_tcphdr *)pptrs->tlh_ptr)->th_off << 2;
        off += ((struct my_tcphdr *)pptrs->tlh_ptr)->th_off << 2;  
      }
      if (off < caplen) pptrs->payload_ptr = ptr;
    }
    else {
      pptrs->tlh_ptr = dummy_tlhdr;
      if (off < caplen) pptrs->payload_ptr = ptr;
    }

    if (config.handle_flows) { 
      pptrs->tcp_flags = FALSE;

      if (pptrs->l4_proto == IPPROTO_TCP) {
        if (off_l4+TCPFlagOff+1 > caplen) {
	  Log(LOG_INFO, "INFO ( default/core ): short IPv4 packet read (%u/%u/flows). Snaplen issue ?\n", caplen, off_l4+TCPFlagOff+1); 
	  return FALSE; 
	}
	if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_SYN) pptrs->tcp_flags |= TH_SYN;
	if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_FIN) pptrs->tcp_flags |= TH_FIN;
	if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_RST) pptrs->tcp_flags |= TH_RST;
	if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_ACK && pptrs->tcp_flags) pptrs->tcp_flags |= TH_ACK; 
      }

      ip_flow_handler(pptrs);
    }

    /* XXX: optimize/short circuit here! */
    pptrs->tcp_flags = FALSE;
    if (pptrs->l4_proto == IPPROTO_TCP && off_l4+TCPFlagOff+1 <= caplen)
      pptrs->tcp_flags = ((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags; 
  }

  quit:
  return ret;
}

#if defined ENABLE_IPV6
int ip6_handler(register struct packet_ptrs *pptrs)
{
  struct ip6_frag *fhdr = NULL;
  register u_int16_t caplen = ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen;
  u_int16_t len = 0, plen = ntohs(((struct ip6_hdr *)pptrs->iph_ptr)->ip6_plen);
  u_int16_t off = pptrs->iph_ptr-pptrs->packet_ptr, off_l4;
  u_int32_t advance;
  u_int8_t nh, fragmented = 0;
  u_char *ptr = pptrs->iph_ptr;
  int ret = TRUE;

  /* length checks */
  if (off+IP6HdrSz > caplen) return FALSE; /* IP packet truncated */
  if (plen == 0) { 
    Log(LOG_INFO, "INFO ( default/core ): NULL IPv6 payload length. Jumbo packets are currently not supported.\n");
    return FALSE;
  }

  pptrs->l4_proto = 0;
  pptrs->payload_ptr = NULL;
  nh = ((struct ip6_hdr *)pptrs->iph_ptr)->ip6_nxt; 
  advance = IP6HdrSz;
  
  while ((off+advance <= caplen) && advance) {
    off += advance;
    ptr += advance;

    switch(nh) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_DSTOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_MOBILITY:
      nh = ((struct ip6_ext *)ptr)->ip6e_nxt;
      advance = (((struct ip6_ext *)ptr)->ip6e_len + 1) << 3; 
      break;
    case IPPROTO_AH:
      nh = ((struct ip6_ext *)ptr)->ip6e_nxt;
      advance = sizeof(struct ah)+(((struct ah *)ptr)->ah_len << 2); /* hdr + sumlen */
      break;
    case IPPROTO_FRAGMENT:
      fhdr = (struct ip6_frag *) ptr;
      nh = ((struct ip6_ext *)ptr)->ip6e_nxt;
      advance = sizeof(struct ip6_frag);
      break;
    /* XXX: case IPPROTO_ESP: */
    /* XXX: case IPPROTO_IPCOMP: */
    default:
      pptrs->tlh_ptr = ptr;
      pptrs->l4_proto = nh;
      goto end;
    }
  }

  end:

  off_l4 = off;
  if (config.handle_fragments) { 
    if (pptrs->l4_proto == IPPROTO_TCP || pptrs->l4_proto == IPPROTO_UDP) {
      if (off+MyTLHdrSz > caplen) {
	Log(LOG_INFO, "INFO ( default/core ): short IPv6 packet read (%u/%u/frags). Snaplen issue ?\n", caplen, off+MyTLHdrSz);
	return FALSE;
      }

      if (fhdr && (fhdr->ip6f_offlg & htons(IP6F_MORE_FRAG|IP6F_OFF_MASK))) {
        ret = ip6_fragment_handler(pptrs, fhdr);
	if (!ret) goto quit;
      }

      /* Let's handle both fragments and packets. If we are facing any subsequent frag
         our pointer is in place; we handle unknown L4 protocols likewise. In case of
         "entire" TCP/UDP packets we have to jump the L4 header instead */
      if (fhdr && (fhdr->ip6f_offlg & htons(IP6F_OFF_MASK))); 
      else if (pptrs->l4_proto == IPPROTO_UDP) {
        ptr += UDPHdrSz;
        off += UDPHdrSz;
      }
      else if (pptrs->l4_proto == IPPROTO_TCP) {
        ptr += ((struct my_tcphdr *)pptrs->tlh_ptr)->th_off << 2;
        off += ((struct my_tcphdr *)pptrs->tlh_ptr)->th_off << 2;
      }
      if (off < caplen) pptrs->payload_ptr = ptr;
    }
    else {
      pptrs->tlh_ptr = dummy_tlhdr;
      if (off < caplen) pptrs->payload_ptr = ptr;
    }

    if (config.handle_flows) {
      pptrs->tcp_flags = FALSE;

      if (pptrs->l4_proto == IPPROTO_TCP) {
	if (off_l4+TCPFlagOff+1 > caplen) {
	  Log(LOG_INFO, "INFO ( default/core ): short IPv6 packet read (%u/%u/flows). Snaplen issue ?\n", caplen, off_l4+TCPFlagOff+1);
	  return FALSE;
	}
        if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_SYN) pptrs->tcp_flags |= TH_SYN;
        if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_FIN) pptrs->tcp_flags |= TH_FIN;
        if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_RST) pptrs->tcp_flags |= TH_RST;
        if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_ACK && pptrs->tcp_flags) pptrs->tcp_flags |= TH_ACK;
      }

      ip_flow6_handler(pptrs);
    }

    /* XXX: optimize/short circuit here! */
    pptrs->tcp_flags = FALSE;
    if (pptrs->l4_proto == IPPROTO_TCP && off_l4+TCPFlagOff+1 <= caplen)
      pptrs->tcp_flags = ((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags;
  }

  quit:
  return TRUE;
}
#endif

pm_id_t PM_find_id(struct id_table *t, struct packet_ptrs *pptrs)
{
  int x, j, id, stop;

  if (!t) return 0;

  id = 0;
  for (x = 0; x < t->ipv4_num; x++) {
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

  return id;
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
  IP4HdrSz = sizeof(struct my_iphdr);
  MyTLHdrSz = sizeof(struct my_tlhdr);
  TCPFlagOff = 13;
  MyTCPHdrSz = TCPFlagOff+1; 
  PptrsSz = sizeof(struct packet_ptrs);
  UDPHdrSz = 8; 
  CSSz = sizeof(struct class_st);
  IpFlowCmnSz = sizeof(struct ip_flow_common);
  HostAddrSz = sizeof(struct host_addr);
#if defined ENABLE_IPV6
  IP6HdrSz = sizeof(struct ip6_hdr);
  IP6AddrSz = sizeof(struct in6_addr);
#endif
}
