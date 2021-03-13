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
#include "uacctd.h"
#include "pmacct-data.h"
#include "pretag_handlers.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "ip_frag.h"
#include "ip_flow.h"
#include "net_aggr.h"
#include "thread_pool.h"
#include "classifier.h"
#include "bgp/bgp.h"
#include "isis/isis.h"
#include "bmp/bmp.h"
#include <netinet/ip.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_log/libnetfilter_log.h>
#if defined (WITH_NDPI)
#include "ndpi/ndpi.h"
#endif

/* Functions */
static int nflog_incoming(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
                          struct nflog_data *nfa, void *p)
{
  static u_char *jumbo_container;
  static ssize_t jumbo_container_sz = 0;
  struct pcap_pkthdr hdr;
  char *pkt = NULL;
  ssize_t pkt_len = nflog_get_payload(nfa, &pkt);
  ssize_t mac_len = 0;
  struct pm_pcap_callback_data *cb_data = p;

  if (nflog_get_hwtype(nfa) == DLT_EN10MB)
    mac_len = nflog_get_msg_packet_hwhdrlen(nfa);

  /* Check we can handle this packet */
  switch (nfmsg->nfgen_family) {
  case AF_INET: break;
  case AF_INET6: break;
  default: return 0;
  }

  if (pkt_len == ERR) return ERR;

  if (nflog_get_timestamp(nfa, &hdr.ts) < 0) {
    gettimeofday(&hdr.ts, NULL);
  }
  hdr.caplen = MIN(pkt_len, config.snaplen);
  hdr.len = pkt_len;

  cb_data->ifindex_in = nflog_get_physindev(nfa);
  if (cb_data->ifindex_in == 0)
    cb_data->ifindex_in = nflog_get_indev(nfa);

  cb_data->ifindex_out = nflog_get_physoutdev(nfa);
  if (cb_data->ifindex_out == 0)
    cb_data->ifindex_out = nflog_get_outdev(nfa);

#if defined (HAVE_L2)
  ssize_t req_len = hdr.caplen + (mac_len ? mac_len : ETHER_HDRLEN);
  if (req_len > jumbo_container_sz) {
    if (jumbo_container)
      free(jumbo_container);
    jumbo_container = malloc(req_len);
    if (jumbo_container == NULL) {
      jumbo_container_sz = 0;
      Log(LOG_ERR, "ERROR ( %s/core ): jumbo_container buffer malloc() failed, packet ignored.\n", config.name);
      return ERR;
    }
    jumbo_container_sz = req_len;
  }

  if (mac_len) {
    memcpy(jumbo_container, nflog_get_msg_packet_hwhdr(nfa), mac_len);
    memcpy(jumbo_container + mac_len, pkt, hdr.caplen);
    hdr.caplen += mac_len;
    hdr.len += mac_len;
  } else {
    memset(jumbo_container, 0, ETHER_HDRLEN);
    memcpy(jumbo_container+ETHER_HDRLEN, pkt, hdr.caplen);
    hdr.caplen += ETHER_HDRLEN;
    hdr.len += ETHER_HDRLEN;

    switch (nfmsg->nfgen_family) {
    case AF_INET:
      ((struct eth_header *)jumbo_container)->ether_type = ntohs(ETHERTYPE_IP);
      break;
    case AF_INET6:
      ((struct eth_header *)jumbo_container)->ether_type = ntohs(ETHERTYPE_IPV6);
      break;
    }
  }

  pm_pcap_cb((u_char *) cb_data, &hdr, jumbo_container);
#else
  pm_pcap_cb((u_char *) cb_data, &hdr, pkt);
#endif

  return 0;
}

void usage_daemon(char *prog_name)
{
  printf("%s %s (%s)\n", UACCTD_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
  printf("Usage: %s [ -D | -d ] [ -g NFLOG group ] [ -c primitive [ , ... ] ] [ -P plugin [ , ... ] ]\n", prog_name);
  printf("       %s [ -f config_file ]\n", prog_name);
  printf("       %s [ -h ]\n", prog_name);
  printf("\nGeneral options:\n");
  printf("  -h  \tShow this page\n");
  printf("  -V  \tShow version and compile-time options and exit\n");
  printf("  -f  \tLoad configuration from the specified file\n");
  printf("  -a  \tPrint list of supported aggregation primitives\n");
  printf("  -c  \tAggregation method, see full list of primitives with -a (DEFAULT: src_host)\n");
  printf("  -D  \tDaemonize\n"); 
  printf("  -n  \tPath to a file containing networks and/or ASNs definitions\n");
  printf("  -t  \tPath to a file containing ports definitions\n");
  printf("  -P  \t[ memory | print | mysql | pgsql | sqlite3 | amqp | kafka | nfprobe | sfprobe ] \n\tActivate plugin\n"); 
  printf("  -d  \tEnable debug\n");
  printf("  -S  \t[ auth | mail | daemon | kern | user | local[0-7] ] \n\tLog to the specified syslog facility\n");
  printf("  -F  \tWrite Core Process PID into the specified file\n");
  printf("  -R  \tRenormalize sampled data\n");
  printf("  -g  \tNetlink NFLOG group\n");
  printf("  -L  \tSnapshot length\n");
  printf("  -u  \tLeave IP protocols in numerical format\n");
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
  int index, logf;

  struct plugins_list_entry *list;
  struct plugin_requests req;
  char config_file[SRVBUFLEN];

  struct id_table bpas_table;
  struct id_table blp_table;
  struct id_table bmed_table;
  struct id_table biss_table;
  struct id_table bta_table;
  struct pm_pcap_callback_data cb_data;

  sigset_t signal_set;

  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp;

  /* NFLOG stuff */
  struct nflog_handle *nfh = NULL;
  struct nflog_g_handle *nfgh = NULL;
  int one = 1;
  ssize_t len = 0;
  char *nflog_buffer;

  struct sockaddr_storage client;

#ifdef WITH_REDIS
  struct p_redis_host redis_host;
#endif

#if defined HAVE_MALLOPT
  mallopt(M_CHECK_ACTION, 0);
#endif

  umask(077);
  compute_once();

  /* a bunch of default definitions */ 
  reload_map = FALSE;
  print_stats = FALSE;
  reload_geoipv2_file = FALSE;
  bpas_map_allocated = FALSE;
  blp_map_allocated = FALSE;
  bmed_map_allocated = FALSE;
  biss_map_allocated = FALSE;
  bta_map_caching = FALSE;
  sampling_map_caching = FALSE;
  custom_primitives_allocated = FALSE;
  find_id_func = PM_find_id;
  plugins_list = NULL;

  errflag = 0;

  memset(cfg_cmdline, 0, sizeof(cfg_cmdline));
  memset(&config, 0, sizeof(struct configuration));
  memset(&device, 0, sizeof(struct pm_pcap_device));
  memset(&config_file, 0, sizeof(config_file));
  memset(&failed_plugins, 0, sizeof(failed_plugins));
  memset(&req, 0, sizeof(req));
  memset(dummy_tlhdr, 0, sizeof(dummy_tlhdr));
  memset(sll_mac, 0, sizeof(sll_mac));
  memset(&bpas_table, 0, sizeof(bpas_table));
  memset(&blp_table, 0, sizeof(blp_table));
  memset(&bmed_table, 0, sizeof(bmed_table));
  memset(&biss_table, 0, sizeof(biss_table));
  memset(&bta_table, 0, sizeof(bta_table));
  memset(&client, 0, sizeof(client));
  memset(&cb_data, 0, sizeof(cb_data));
  memset(&tunnel_registry, 0, sizeof(tunnel_registry));
  memset(&reload_map_tstamp, 0, sizeof(reload_map_tstamp));
  memset(empty_mem_area_256b, 0, sizeof(empty_mem_area_256b));
  log_notifications_init(&log_notifications);
  config.acct_type = ACCT_PM;
  config.progname = uacctd_globstr;

  rows = 0;
  memset(&device, 0, sizeof(device));

  /* getting commandline values */
  while (!errflag && ((cp = getopt(argc, argv, ARGS_UACCTD)) != -1)) {
    if (!cfg_cmdline[rows]) cfg_cmdline[rows] = malloc(SRVBUFLEN);
    memset(cfg_cmdline[rows], 0, SRVBUFLEN);
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
    case 'g':
      strlcpy(cfg_cmdline[rows], "uacctd_group: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'L':
      strlcpy(cfg_cmdline[rows], "snaplen: ", SRVBUFLEN);
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
    case 'V':
      version_daemon(config.acct_type, UACCTD_USAGE_HEADER);
      exit(0);
      break;
    case 'a':
      print_primitives(config.acct_type, UACCTD_USAGE_HEADER);
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
    list->cfg.acct_type = ACCT_PM;
    list->cfg.progname = uacctd_globstr;
    set_default_preferences(&list->cfg);
    if (!strcmp(list->type.string, "core")) { 
      memcpy(&config, &list->cfg, sizeof(struct configuration)); 
      config.name = list->name;
      config.type = list->type.string;
    }
    list = list->next;
  }

  if (config.files_umask) umask(config.files_umask);

  if (!config.snaplen) config.snaplen = DEFAULT_SNAPLEN;
  if (!config.uacctd_nl_size) config.uacctd_nl_size = DEFAULT_NFLOG_BUFLEN;
  if (!config.uacctd_threshold) config.uacctd_threshold = DEFAULT_NFLOG_THRESHOLD;

  /* Let's check whether we need superuser privileges */
  if (getuid() != 0) {
    printf("%s %s (%s)\n\n", UACCTD_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
    printf("ERROR ( %s/core ): You need superuser privileges to run this command.\nExiting ...\n\n", config.name);
    exit(1);
  }

  if (!config.uacctd_group) {
    config.uacctd_group = DEFAULT_NFLOG_GROUP;
    list = plugins_list;
    while (list) {
      list->cfg.uacctd_group = DEFAULT_NFLOG_GROUP;
      list = list->next;
    }
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

  Log(LOG_INFO, "INFO ( %s/core ): %s (%s)\n", config.name, UACCTD_USAGE_HEADER, PMACCT_BUILD);
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

      if (config.classifiers_path && (list->cfg.sampling_rate || config.ext_sampling_rate)) {
        Log(LOG_ERR, "ERROR ( %s/core ): Packet sampling and classification are mutual exclusive.\n", config.name);
        exit_gracefully(1);
      }

      if (list->cfg.sampling_rate && config.ext_sampling_rate) {
        Log(LOG_ERR, "ERROR ( %s/core ): Internal packet sampling and external packet sampling are mutual exclusive.\n", config.name);
        exit_gracefully(1);
      }

      /* applies to specific plugins */
      if (list->type.id == PLUGIN_ID_TEE) {
        Log(LOG_ERR, "ERROR ( %s/core ): 'tee' plugin not supported in 'uacctd'.\n", config.name);
        exit_gracefully(1);
      }
      else if (list->type.id == PLUGIN_ID_NFPROBE) {
	/* If we already renormalizing an external sampling rate,
	   we cancel the sampling information from the probe plugin */
	if (config.sfacctd_renormalize && list->cfg.ext_sampling_rate) list->cfg.ext_sampling_rate = 0; 

	config.handle_fragments = TRUE;
	list->cfg.nfprobe_what_to_count = list->cfg.what_to_count;
	list->cfg.nfprobe_what_to_count_2 = list->cfg.what_to_count_2;
	list->cfg.what_to_count = 0;
	list->cfg.what_to_count_2 = 0;
#if defined (HAVE_L2)
	if (list->cfg.nfprobe_version == 9 || list->cfg.nfprobe_version == 10) {
	  list->cfg.what_to_count |= COUNT_SRC_MAC;
	  list->cfg.what_to_count |= COUNT_DST_MAC;
	  list->cfg.what_to_count |= COUNT_VLAN;
	}
#endif
	list->cfg.what_to_count |= COUNT_SRC_HOST;
	list->cfg.what_to_count |= COUNT_DST_HOST;

        if (list->cfg.networks_file || list->cfg.networks_mask || list->cfg.nfacctd_net) {
          list->cfg.what_to_count |= COUNT_SRC_NMASK;
          list->cfg.what_to_count |= COUNT_DST_NMASK;
        }

	list->cfg.what_to_count |= COUNT_SRC_PORT;
	list->cfg.what_to_count |= COUNT_DST_PORT;
	list->cfg.what_to_count |= COUNT_IP_TOS;
	list->cfg.what_to_count |= COUNT_IP_PROTO;
	if (list->cfg.networks_file ||
	   ((list->cfg.bgp_daemon || list->cfg.bmp_daemon) && list->cfg.nfacctd_as == NF_AS_BGP)) {
	  list->cfg.what_to_count |= COUNT_SRC_AS;
	  list->cfg.what_to_count |= COUNT_DST_AS;
	  list->cfg.what_to_count |= COUNT_PEER_DST_IP;
	}
	if (list->cfg.nfprobe_version == 9 || list->cfg.nfprobe_version == 10) {
	  if (list->cfg.classifiers_path) {
	    list->cfg.what_to_count |= COUNT_CLASS; 
	    config.handle_flows = TRUE;
	  }

          if (list->cfg.nfprobe_what_to_count_2 & COUNT_NDPI_CLASS)
            list->cfg.what_to_count_2 |= COUNT_NDPI_CLASS;

          if (list->cfg.nfprobe_what_to_count_2 & COUNT_MPLS_LABEL_TOP)
            list->cfg.what_to_count_2 |= COUNT_MPLS_LABEL_TOP;
	}
	if (list->cfg.pre_tag_map) {
	  list->cfg.what_to_count |= COUNT_TAG;
	  list->cfg.what_to_count |= COUNT_TAG2;
	  list->cfg.what_to_count_2 |= COUNT_LABEL;
	}
	list->cfg.what_to_count |= COUNT_IN_IFACE;
	list->cfg.what_to_count |= COUNT_OUT_IFACE;
        if ((list->cfg.what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM|COUNT_LOCAL_PREF|COUNT_MED|COUNT_AS_PATH|
                                       COUNT_PEER_SRC_AS|COUNT_PEER_DST_AS|COUNT_PEER_SRC_IP|COUNT_SRC_STD_COMM|
                                       COUNT_SRC_EXT_COMM|COUNT_SRC_AS_PATH|COUNT_SRC_MED|COUNT_SRC_LOCAL_PREF|
				       COUNT_MPLS_VPN_RD)) || 
	    (list->cfg.what_to_count_2 & (COUNT_LRG_COMM|COUNT_SRC_LRG_COMM|COUNT_SRC_ROA|COUNT_DST_ROA))) {
          Log(LOG_ERR, "ERROR ( %s/core ): 'src_as', 'dst_as' and 'peer_dst_ip' are currently the only BGP-related primitives supported within the 'nfprobe' plugin.\n", config.name);
          exit_gracefully(1);
	}
	list->cfg.what_to_count |= COUNT_COUNTERS;

        if (list->cfg.nfacctd_as & NF_AS_FALLBACK && list->cfg.networks_file)
          list->cfg.nfacctd_as |= NF_AS_NEW;

        if (list->cfg.nfacctd_net & NF_NET_FALLBACK && list->cfg.networks_file)
          list->cfg.nfacctd_net |= NF_NET_NEW;

	list->cfg.data_type = PIPE_TYPE_METADATA;
	list->cfg.data_type |= PIPE_TYPE_EXTRAS;

        if (list->cfg.what_to_count & (COUNT_PEER_DST_IP))
          list->cfg.data_type |= PIPE_TYPE_BGP;

        if (list->cfg.what_to_count_2 & (COUNT_MPLS_LABEL_TOP))
          list->cfg.data_type |= PIPE_TYPE_MPLS;

        if (list->cfg.what_to_count_2 & (COUNT_LABEL))
          list->cfg.data_type |= PIPE_TYPE_VLEN;
      }
      else if (list->type.id == PLUGIN_ID_SFPROBE) {
        /* If we already renormalizing an external sampling rate,
           we cancel the sampling information from the probe plugin */
        if (config.sfacctd_renormalize && list->cfg.ext_sampling_rate) list->cfg.ext_sampling_rate = 0;

	if (config.snaplen < 128) config.snaplen = 128; /* SFL_DEFAULT_HEADER_SIZE */
	list->cfg.what_to_count = COUNT_PAYLOAD;
	list->cfg.what_to_count_2 = 0;
	if (list->cfg.classifiers_path) {
	  list->cfg.what_to_count |= COUNT_CLASS;
	  config.handle_fragments = TRUE;
	  config.handle_flows = TRUE;
	}
#if defined (WITH_NDPI)
	if (list->cfg.ndpi_num_roots) list->cfg.what_to_count_2 |= COUNT_NDPI_CLASS;
#endif
        if (list->cfg.networks_file ||
	   ((list->cfg.bgp_daemon || list->cfg.bmp_daemon) && list->cfg.nfacctd_as == NF_AS_BGP)) {
          list->cfg.what_to_count |= COUNT_SRC_AS;
          list->cfg.what_to_count |= COUNT_DST_AS;
          list->cfg.what_to_count |= COUNT_PEER_DST_IP;
        }
        if (list->cfg.networks_file || list->cfg.networks_mask || list->cfg.nfacctd_net) {
          list->cfg.what_to_count |= COUNT_SRC_NMASK;
          list->cfg.what_to_count |= COUNT_DST_NMASK;
        }
	if (list->cfg.pre_tag_map) {
	  list->cfg.what_to_count |= COUNT_TAG;
	  list->cfg.what_to_count |= COUNT_TAG2;
	}
        if ((list->cfg.what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM|COUNT_LOCAL_PREF|COUNT_MED|COUNT_AS_PATH|
                                       COUNT_PEER_SRC_AS|COUNT_PEER_DST_AS|COUNT_PEER_SRC_IP|COUNT_SRC_STD_COMM|
                                       COUNT_SRC_EXT_COMM|COUNT_SRC_AS_PATH|COUNT_SRC_MED|COUNT_SRC_LOCAL_PREF|
				       COUNT_MPLS_VPN_RD)) ||
	    (list->cfg.what_to_count_2 & (COUNT_LRG_COMM|COUNT_SRC_LRG_COMM|COUNT_SRC_ROA|COUNT_DST_ROA))) {
          Log(LOG_ERR, "ERROR ( %s/core ): 'src_as', 'dst_as' and 'peer_dst_ip' are currently the only BGP-related primitives supported within the 'sfprobe' plugin.\n", config.name);
          exit_gracefully(1);
        }

#if defined (HAVE_L2)
        list->cfg.what_to_count |= COUNT_VLAN;
        list->cfg.what_to_count |= COUNT_COS;
#endif

        if (list->cfg.nfacctd_as & NF_AS_FALLBACK && list->cfg.networks_file)
          list->cfg.nfacctd_as |= NF_AS_NEW;

        if (list->cfg.nfacctd_net & NF_NET_FALLBACK && list->cfg.networks_file)
          list->cfg.nfacctd_net |= NF_NET_NEW;

	list->cfg.data_type = PIPE_TYPE_PAYLOAD;
      }
      else {
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
	  cb_data.has_tun_prims = TRUE;
	}

        if (list->cfg.what_to_count_2 & (COUNT_LABEL))
          list->cfg.data_type |= PIPE_TYPE_VLEN;

	evaluate_sums(&list->cfg.what_to_count, &list->cfg.what_to_count_2, list->name, list->type.string);
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
	if (!list->cfg.what_to_count && !list->cfg.what_to_count_2 && !list->cfg.cpptrs.num) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): defaulting to SRC HOST aggregation.\n", list->name, list->type.string);
	  list->cfg.what_to_count |= COUNT_SRC_HOST;
	}
	if (list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) {
	  if (!list->cfg.networks_file && list->cfg.nfacctd_as != NF_AS_BGP) { 
	    Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation selected but NO 'networks_file' or 'uacctd_as' are specified. Exiting...\n\n", list->name, list->type.string);
	    exit_gracefully(1);
	  }
          if (list->cfg.nfacctd_as & NF_AS_FALLBACK && list->cfg.networks_file)
            list->cfg.nfacctd_as |= NF_AS_NEW;
	}
        if (list->cfg.what_to_count & (COUNT_SRC_NET|COUNT_DST_NET|COUNT_SUM_NET|COUNT_SRC_NMASK|COUNT_DST_NMASK|COUNT_PEER_DST_IP)) {
          if (!list->cfg.nfacctd_net) {
            if (list->cfg.networks_file) list->cfg.nfacctd_net |= NF_NET_NEW;
            if (list->cfg.networks_mask) list->cfg.nfacctd_net |= NF_NET_STATIC;
            if (!list->cfg.nfacctd_net) {
              Log(LOG_ERR, "ERROR ( %s/%s ): network aggregation selected but none of 'uacctd_net', 'networks_file', 'networks_mask' is specified. Exiting ...\n\n", list->name, list->type.string);
              exit_gracefully(1);
            }
          }
          else {
            if ((list->cfg.nfacctd_net == NF_NET_NEW && !list->cfg.networks_file) ||
                (list->cfg.nfacctd_net == NF_NET_STATIC && !list->cfg.networks_mask) ||
                (list->cfg.nfacctd_net == NF_NET_BGP && !list->cfg.bgp_daemon && !list->cfg.bmp_daemon) ||
                (list->cfg.nfacctd_net == NF_NET_IGP && !list->cfg.nfacctd_isis) ||
                (list->cfg.nfacctd_net == NF_NET_KEEP)) {
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

	list->cfg.type_id = list->type.id;
	bgp_config_checks(&list->cfg);

	list->cfg.what_to_count |= COUNT_COUNTERS;
	list->cfg.data_type |= PIPE_TYPE_METADATA;
      }

      /* applies to all plugins */
      if ((list->cfg.what_to_count_2 & COUNT_NDPI_CLASS) ||
	  (list->cfg.nfprobe_what_to_count_2 & COUNT_NDPI_CLASS)) {
	config.handle_fragments = TRUE;
	config.classifier_ndpi = TRUE;
      } 

      if ((list->cfg.what_to_count & COUNT_CLASS) && (list->cfg.what_to_count_2 & COUNT_NDPI_CLASS)) { 
	Log(LOG_ERR, "ERROR ( %s/%s ): 'class_legacy' and 'class' primitives are mutual exclusive. Exiting...\n\n", list->name, list->type.string);
	exit_gracefully(1);
      }
    }
    list = list->next;
  }

  /* plugins glue: creation (since 094) */
  if (config.classifiers_path) {
    init_classifiers(config.classifiers_path);
    init_conntrack_table();
  }

#if defined (WITH_NDPI)
  if (config.classifier_ndpi) {
    config.handle_fragments = TRUE;
    pm_ndpi_wfl = pm_ndpi_workflow_init();
    pm_ndpi_export_proto_to_class(pm_ndpi_wfl);
  }
  else pm_ndpi_wfl = NULL;
#endif

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

  load_plugins(&req);

  if (config.handle_fragments) init_ip_fragment_handler();
  if (config.handle_flows) init_ip_flow_handler();
  load_networks(config.networks_file, &nt, &nc);

#if defined (HAVE_L2)
  device.link_type = DLT_EN10MB; 
#else
  device.link_type = DLT_RAW; 
#endif
  for (index = 0; _devices[index].link_type != -1; index++) {
    if (device.link_type == _devices[index].link_type)
      device.data = &_devices[index];
  }
  load_plugin_filters(device.link_type);

  cb_data.device = &device;
  
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

  nfh = nflog_open();
  if (nfh == NULL) {
    Log(LOG_ERR, "ERROR ( %s/core ): Failed to create Netlink NFLOG socket\n", config.name);
    nflog_close(nfh);
    exit_gracefully(1);
  }

  Log(LOG_INFO, "INFO ( %s/core ): Successfully connected Netlink NFLOG socket\n", config.name);

  /* Bind to IPv4 (and IPv6) */
  if (nflog_unbind_pf(nfh, AF_INET) < 0) {
    Log(LOG_ERR, "ERROR ( %s/core ): Failed to unbind Netlink NFLOG socket from IPv4\n", config.name);
    nflog_close(nfh);
    exit_gracefully(1);
  }
  if (nflog_bind_pf(nfh, AF_INET) < 0) {
    Log(LOG_ERR, "ERROR ( %s/core ): Failed to bind Netlink NFLOG socket from IPv4\n", config.name);
    nflog_close(nfh);
    exit_gracefully(1);
  }
  if (nflog_unbind_pf(nfh, AF_INET6) < 0) {
    Log(LOG_ERR, "ERROR ( %s/core ): Failed to unbind Netlink NFLOG socket from IPv6\n", config.name);
    nflog_close(nfh);
    exit_gracefully(1);
  }
  if (nflog_bind_pf(nfh, AF_INET6) < 0) {
    Log(LOG_ERR, "ERROR ( %s/core ): Failed to bind Netlink NFLOG socket from IPv6\n", config.name);
    nflog_close(nfh);
    exit_gracefully(1);
  }

  /* Bind to group */
  if ((nfgh = nflog_bind_group(nfh, config.uacctd_group)) == NULL) {
    Log(LOG_ERR, "ERROR ( %s/core ): Failed to join NFLOG group %d\n", config.name, config.uacctd_group);
    nflog_close(nfh);
    exit_gracefully(1);
  }

  /* Set snaplen */
  if (nflog_set_mode(nfgh, NFULNL_COPY_PACKET, config.snaplen) < 0) {
    Log(LOG_ERR, "ERROR ( %s/core ): Failed to set snaplen to %d\n", config.name, config.snaplen);
    nflog_unbind_group(nfgh);
    nflog_close(nfh);
    exit_gracefully(1);
  }

  /* Set threshold */
  if (nflog_set_qthresh(nfgh, config.uacctd_threshold) < 0) {
    Log(LOG_ERR, "ERROR ( %s/core ): Failed to set threshold to %d\n", config.name, config.uacctd_threshold);
    nflog_unbind_group(nfgh);
    nflog_close(nfh);
    exit_gracefully(1);
  }

  /* Set buffer size */
  if (nflog_set_nlbufsiz(nfgh, config.uacctd_nl_size) < 0) {
    Log(LOG_ERR, "ERROR ( %s/core ): Failed to set receive buffer size to %d\n", config.name, config.uacctd_nl_size);
    nflog_unbind_group(nfgh);
    nflog_close(nfh);
    exit_gracefully(1);
  }

  /* Turn off netlink errors from overrun. */
  if (setsockopt(nflog_fd(nfh), SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, (socklen_t) sizeof(one)))
    Log(LOG_ERR, "ERROR ( %s/core ): Failed to turn off netlink ENOBUFS\n", config.name);

  nflog_callback_register(nfgh, &nflog_incoming, &cb_data);
  nflog_buffer = malloc(config.uacctd_nl_size);
  if (nflog_buffer == NULL) {
    Log(LOG_ERR, "ERROR ( %s/core ): NFLOG buffer malloc() failed\n", config.name);
    nflog_unbind_group(nfgh);
    nflog_close(nfh);
    exit_gracefully(1);
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
	cb_data.bpas_table = (u_char *) &bpas_table;
      }
      else {
        Log(LOG_ERR, "ERROR ( %s/core ): bgp_peer_as_src_type set to 'map' but no map defined. Exiting.\n", config.name);
        exit_gracefully(1);
      }
    }
    else cb_data.bpas_table = NULL;

    if (config.bgp_daemon_src_local_pref_type == BGP_SRC_PRIMITIVES_MAP) {
      if (config.bgp_daemon_src_local_pref_map) {
        load_id_file(MAP_BGP_SRC_LOCAL_PREF, config.bgp_daemon_src_local_pref_map, &blp_table, &req, &blp_map_allocated);
        cb_data.blp_table = (u_char *) &blp_table;
      }
      else {
        Log(LOG_ERR, "ERROR ( %s/core ): bgp_src_local_pref_type set to 'map' but no map defined. Exiting.\n", config.name);
        exit_gracefully(1);
      }
    }
    else cb_data.bpas_table = NULL;

    if (config.bgp_daemon_src_med_type == BGP_SRC_PRIMITIVES_MAP) {
      if (config.bgp_daemon_src_med_map) {
        load_id_file(MAP_BGP_SRC_MED, config.bgp_daemon_src_med_map, &bmed_table, &req, &bmed_map_allocated);
        cb_data.bmed_table = (u_char *) &bmed_table;
      }
      else {
        Log(LOG_ERR, "ERROR ( %s/core ): bgp_src_med_type set to 'map' but no map defined. Exiting.\n", config.name);
        exit_gracefully(1);
      }
    }
    else cb_data.bmed_table = NULL;

    if (config.bgp_daemon_to_xflow_agent_map) {
      load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.bgp_daemon_to_xflow_agent_map, &bta_table, &req, &bta_map_allocated);
      cb_data.bta_table = (u_char *) &bta_table;
    }
    else {
      Log(LOG_ERR, "ERROR ( %s/core ): 'bgp_daemon' configured but no 'bgp_agent_map' has been specified. Exiting.\n", config.name);
      exit_gracefully(1);
    }

    /* Limiting BGP peers to only two: one would suffice in pmacctd
       but in case maps are reloadable (ie. bta), it could be handy
       to keep a backup feed in memory */
    config.bgp_daemon_max_peers = 2;

    cb_data.f_agent = (u_char *) &client;
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
      cb_data.bta_table = (u_char *) &bta_table;
    }
    else {
      Log(LOG_ERR, "ERROR ( %s/core ): 'bmp_daemon' configured but no 'bgp_agent_map' has been specified. Exiting.\n", config.name);
      exit_gracefully(1);
    }

    /* Limiting BGP peers to only two: one would suffice in pmacctd
       but in case maps are reloadable (ie. bta), it could be handy
       to keep a backup feed in memory */
    config.bgp_daemon_max_peers = 2;

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

  if (config.nfacctd_flow_to_rd_map) { 
    Log(LOG_ERR, "ERROR ( %s/core ): 'flow_to_rd_map' is not supported by this daemon. Exiting.\n", config.name);
    exit_gracefully(1);
  } 

  /* plugins glue: creation (until 093) */
  evaluate_packet_handlers();
  pm_setproctitle("%s [%s]", "Core Process", config.proc_name);
  if (config.pidfile) write_pid_file(config.pidfile);  

  /* signals to be handled only by the core process;
     we set proper handlers after plugin creation */
  sighandler_action.sa_handler = PM_sigint_handler;
  sigaction(SIGINT, &sighandler_action, NULL);

  sighandler_action.sa_handler = PM_sigint_handler;
  sigaction(SIGTERM, &sighandler_action, NULL);

  sighandler_action.sa_handler = handle_falling_child;
  sigaction(SIGCHLD, &sighandler_action, NULL);

  kill(getpid(), SIGCHLD);

#ifdef WITH_REDIS
  if (config.redis_host) {
    char log_id[SHORTBUFLEN];

    snprintf(log_id, sizeof(log_id), "%s/%s", config.name, config.type);
    p_redis_init(&redis_host, log_id, p_redis_thread_produce_common_core_handler);
  }
#endif

  sigemptyset(&signal_set);
  sigaddset(&signal_set, SIGCHLD);
  sigaddset(&signal_set, SIGHUP);
  sigaddset(&signal_set, SIGUSR1);
  sigaddset(&signal_set, SIGUSR2);
  sigaddset(&signal_set, SIGTERM);
  if (config.daemon) {
    sigaddset(&signal_set, SIGINT);
  }
  cb_data.sig.is_set = FALSE;

  /* Main loop: if pcap_loop() exits maybe an error occurred; we will try closing
     and reopening again our listening device */
  for (;;) {
    sigprocmask(SIG_BLOCK, &signal_set, NULL);

    if (len == ERR) {
      if (errno != EAGAIN) {
        /* We can't deal with permanent errors.
         * Just sleep a bit.
         */
        Log(LOG_ERR, "ERROR ( %s/core ): Syscall returned %d: %s. Sleeping for 1 sec.\n", config.name, errno, strerror(errno));
        sleep(1);
      }
    }

    len = recv(nflog_fd(nfh), nflog_buffer, config.uacctd_nl_size, 0);
    if (len < 0) continue;
    if (nflog_handle_packet(nfh, nflog_buffer, len) != 0) continue;

    sigprocmask(SIG_UNBLOCK, &signal_set, NULL);
  }
}
