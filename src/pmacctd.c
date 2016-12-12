/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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
#include "bgp/bgp.h"
#include "classifier.h"
#include "isis/isis.h"

/* variables to be exported away */
struct channels_list_entry channels_list[MAX_N_PLUGINS]; /* communication channels: core <-> plugins */

/* Functions */
void usage_daemon(char *prog_name)
{
  printf("%s (%s)\n", PMACCTD_USAGE_HEADER, PMACCT_BUILD);
  printf("Usage: %s [ -D | -d ] [ -i interface ] [ -c primitive [ , ... ] ] [ -P plugin [ , ... ] ] [ filter ]\n", prog_name);
  printf("       %s [ -f config_file ]\n", prog_name);
  printf("       %s [ -h ]\n", prog_name);
  printf("\nGeneral options:\n");
  printf("  -h  \tShow this page\n");
  printf("  -V  \tShow version and compile-time options and exit\n");
  printf("  -f  \tLoad configuration from the specified file\n");
  printf("  -a  \tPrint list of supported aggregation primitives\n");
  printf("  -c  \tAggregation method, see full list of primitives with -a (DEFAULT: src_host)\n");
  printf("  -D  \tDaemonize\n"); 
  printf("  -N  \tDisable promiscuous mode\n");
  printf("  -z  \tAllow to run with non root privileges (ie. setcap in use)\n");
  printf("  -n  \tPath to a file containing networks and/or ASNs definitions\n");
  printf("  -t  \tPath to a file containing ports definitions\n");
  printf("  -P  \t[ memory | print | mysql | pgsql | sqlite3 | mongodb | amqp | kafka | nfprobe | sfprobe ] \n\tActivate plugin\n"); 
  printf("  -d  \tEnable debug\n");
  printf("  -i  \tListen on the specified interface\n");
  printf("  -I  \tRead packets from the specified savefile\n");
  printf("  -S  \t[ auth | mail | daemon | kern | user | local[0-7] ] \n\tLog to the specified syslog facility\n");
  printf("  -F  \tWrite Core Process PID into the specified file\n");
  printf("  -w  \tWait for the listening interface to become available\n");
  printf("  -W  \tReading from a savefile, don't exit but sleep when finished\n");
  printf("  -R  \tRenormalize sampled data\n");
  printf("  -L  \tSet snapshot length\n");
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
  printf("  -A  \tAppend output (applies to -o)\n");
  printf("  -E  \tCSV format serparator (applies to -O csv, DEFAULT: ',')\n");
  printf("\n");
  printf("  See QUICKSTART or visit http://wiki.pmacct.net/ for examples.\n");
  printf("\n");
  printf("For suggestions, critics, bugs, contact me: %s.\n", MANTAINER);
}


int main(int argc,char **argv, char **envp)
{
  bpf_u_int32 localnet, netmask;  /* pcap library stuff */
  struct bpf_program filter;
  struct pcap_device device;
  char errbuf[PCAP_ERRBUF_SIZE];
  int index, logf, ret;

  struct plugins_list_entry *list;
  struct plugin_requests req;
  char config_file[SRVBUFLEN];
  int psize = DEFAULT_SNAPLEN;

  struct id_table bpas_table;
  struct id_table blp_table;
  struct id_table bmed_table;
  struct id_table biss_table;
  struct id_table bta_table;
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

#if defined HAVE_MALLOPT
  mallopt(M_CHECK_ACTION, 0);
#endif

  umask(077);
  compute_once();

  /* a bunch of default definitions */ 
  reload_map = FALSE;
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
  memset(&device, 0, sizeof(struct pcap_device));
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
  log_notifications_init(&log_notifications);
  config.acct_type = ACCT_PM;

  rows = 0;
  glob_pcapt = NULL;

  /* getting commandline values */
  while (!errflag && ((cp = getopt(argc, argv, ARGS_PMACCTD)) != -1)) {
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
    case 'z':
      strlcpy(cfg_cmdline[rows], "pmacctd_nonroot: true", SRVBUFLEN);
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
    case 'N':
      strlcpy(cfg_cmdline[rows], "promisc: false", SRVBUFLEN);
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
    case 'R':
      strlcpy(cfg_cmdline[rows], "sfacctd_renormalize: true", SRVBUFLEN);
      rows++;
      break;
    case 'h':
      usage_daemon(argv[0]);
      exit(0);
      break;
    case 'V':
      version_daemon(PMACCTD_USAGE_HEADER);
      exit(0);
      break;
    case 'a':
      print_primitives(config.acct_type, PMACCTD_USAGE_HEADER);
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
    set_default_preferences(&list->cfg);
    if (!strcmp(list->type.string, "core")) {
      memcpy(&config, &list->cfg, sizeof(struct configuration)); 
      config.name = list->name;
      config.type = list->type.string;
    }
    list = list->next;
  }

  if (config.files_umask) umask(config.files_umask);

  /* Let's check whether we need superuser privileges */
  if (config.snaplen) psize = config.snaplen;
  else config.snaplen = psize;

  if (!config.pcap_savefile) {
    if (getuid() != 0 && !config.pmacctd_nonroot) {
      printf("%s (%s)\n\n", PMACCTD_USAGE_HEADER, PMACCT_BUILD);
      printf("ERROR ( %s/core ): You need superuser privileges to run this command.\nExiting ...\n\n", config.name);
      exit(1);
    }
  }

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

  Log(LOG_INFO, "INFO ( %s/core ): %s (%s)\n", config.name, PMACCTD_USAGE_HEADER, PMACCT_BUILD);
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
        exit(1);
      }

      if (list->cfg.sampling_rate && config.ext_sampling_rate) {
        Log(LOG_ERR, "ERROR ( %s/core ): Internal packet sampling and external packet sampling are mutual exclusive.\n", config.name);
        exit(1);
      }

      /* applies to specific plugins */
      if (list->type.id == PLUGIN_ID_TEE) {
        Log(LOG_ERR, "ERROR ( %s/core ): 'tee' plugin not supported in 'pmacctd'.\n", config.name);
        exit(1);
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
	if (list->cfg.networks_file || (list->cfg.nfacctd_bgp && list->cfg.nfacctd_as == NF_AS_BGP)) {
	  list->cfg.what_to_count |= COUNT_SRC_AS;
	  list->cfg.what_to_count |= COUNT_DST_AS;
	  list->cfg.what_to_count |= COUNT_PEER_DST_IP;
	}
	if ((list->cfg.nfprobe_version == 9 || list->cfg.nfprobe_version == 10) && list->cfg.classifiers_path) {
	  list->cfg.what_to_count |= COUNT_CLASS; 
	  config.handle_flows = TRUE;
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
	    (list->cfg.what_to_count_2 & (COUNT_LRG_COMM|COUNT_SRC_LRG_COMM))) {
	  Log(LOG_ERR, "ERROR ( %s/core ): 'src_as', 'dst_as' and 'peer_dst_ip' are currently the only BGP-related primitives supported within the 'nfprobe' plugin.\n", config.name);
	  exit(1);
	}
	list->cfg.what_to_count |= COUNT_COUNTERS;

        if (list->cfg.nfacctd_as & NF_AS_FALLBACK && list->cfg.networks_file)
          list->cfg.nfacctd_as |= NF_AS_NEW;

        if (list->cfg.nfacctd_net & NF_NET_FALLBACK && list->cfg.networks_file)
          list->cfg.nfacctd_net |= NF_NET_NEW;

	list->cfg.data_type = PIPE_TYPE_METADATA;
	list->cfg.data_type |= PIPE_TYPE_EXTRAS;

        if (list->cfg.what_to_count_2 & (COUNT_LABEL))
          list->cfg.data_type |= PIPE_TYPE_VLEN;
      }
      else if (list->type.id == PLUGIN_ID_SFPROBE) {
        /* If we already renormalizing an external sampling rate,
           we cancel the sampling information from the probe plugin */
        if (config.sfacctd_renormalize && list->cfg.ext_sampling_rate) list->cfg.ext_sampling_rate = 0;

	if (psize < 128) psize = config.snaplen = 128; /* SFL_DEFAULT_HEADER_SIZE */
	list->cfg.what_to_count = COUNT_PAYLOAD;
	list->cfg.what_to_count_2 = 0;
	if (list->cfg.classifiers_path) {
	  list->cfg.what_to_count |= COUNT_CLASS;
	  config.handle_fragments = TRUE;
	  config.handle_flows = TRUE;
	}
        if (list->cfg.networks_file || (list->cfg.nfacctd_bgp && list->cfg.nfacctd_as == NF_AS_BGP)) {
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
	    (list->cfg.what_to_count_2 & (COUNT_LRG_COMM|COUNT_SRC_LRG_COMM))) {
          Log(LOG_ERR, "ERROR ( %s/core ): 'src_as', 'dst_as' and 'peer_dst_ip' are currently the only BGP-related primitives supported within the 'sfprobe' plugin.\n", config.name);
          exit(1);
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
                        COUNT_TIMESTAMP_START|COUNT_TIMESTAMP_END|COUNT_TIMESTAMP_ARRIVAL))
          list->cfg.data_type |= PIPE_TYPE_NAT;

        if (list->cfg.what_to_count_2 & (COUNT_MPLS_LABEL_TOP|COUNT_MPLS_LABEL_BOTTOM|
                        COUNT_MPLS_STACK_DEPTH))
          list->cfg.data_type |= PIPE_TYPE_MPLS;

        if (list->cfg.what_to_count_2 & (COUNT_LABEL))
          list->cfg.data_type |= PIPE_TYPE_VLEN;

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
	if (!list->cfg.what_to_count && !list->cfg.what_to_count_2 && !list->cfg.cpptrs.num) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): defaulting to SRC HOST aggregation.\n", list->name, list->type.string);
	  list->cfg.what_to_count |= COUNT_SRC_HOST;
	}
        if (((list->cfg.what_to_count & COUNT_SRC_HOST) && (list->cfg.what_to_count & COUNT_SRC_NET)) ||
            ((list->cfg.what_to_count & COUNT_DST_HOST) && (list->cfg.what_to_count & COUNT_DST_NET))) {
          if (!list->cfg.tmp_net_own_field) {
            Log(LOG_ERR, "ERROR ( %s/%s ): src_host, src_net and dst_host, dst_net are mutually exclusive: set tmp_net_own_field to true. Exiting...\n\n", list->name, list->type.string);
            exit(1);
          }
        }
	if (list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) {
	  if (!list->cfg.networks_file && list->cfg.nfacctd_as != NF_AS_BGP) { 
	    Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation selected but NO 'networks_file' or 'pmacctd_as' are specified. Exiting...\n\n", list->name, list->type.string);
	    exit(1);
	  }
	  if (list->cfg.nfacctd_as & NF_AS_FALLBACK && list->cfg.networks_file)
            list->cfg.nfacctd_as |= NF_AS_NEW;
	}
        if (list->cfg.what_to_count & (COUNT_SRC_NET|COUNT_DST_NET|COUNT_SUM_NET|COUNT_SRC_NMASK|COUNT_DST_NMASK|COUNT_PEER_DST_IP)) {
          if (!list->cfg.nfacctd_net) {
            if (list->cfg.networks_file) list->cfg.nfacctd_net |= NF_NET_NEW;
            if (list->cfg.networks_mask) list->cfg.nfacctd_net |= NF_NET_STATIC;
            if (!list->cfg.nfacctd_net) {
              Log(LOG_ERR, "ERROR ( %s/%s ): network aggregation selected but none of 'pmacctd_net', 'networks_file', 'networks_mask' is specified. Exiting ...\n\n", list->name, list->type.string);
              exit(1);
            }
          }
          else {
            if ((list->cfg.nfacctd_net == NF_NET_NEW && !list->cfg.networks_file) ||
                (list->cfg.nfacctd_net == NF_NET_STATIC && !list->cfg.networks_mask) ||
                (list->cfg.nfacctd_net == NF_NET_BGP && !list->cfg.nfacctd_bgp) ||
                (list->cfg.nfacctd_net == NF_NET_IGP && !list->cfg.nfacctd_isis) ||
                (list->cfg.nfacctd_net == NF_NET_KEEP)) {
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

	list->cfg.type_id = list->type.id;
	bgp_config_checks(&list->cfg);

	list->cfg.what_to_count |= COUNT_COUNTERS;
	list->cfg.data_type |= PIPE_TYPE_METADATA;
      }
    }
    list = list->next;
  }

  /* plugins glue: creation (since 094) */
  if (config.classifiers_path) {
    init_classifiers(config.classifiers_path);
    init_conntrack_table();
  }

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

  /* If any device/savefile have been specified, choose a suitable device
     where to listen for traffic */ 
  if (!config.dev && !config.pcap_savefile) {
    Log(LOG_WARNING, "WARN ( %s/core ): Selecting a suitable device.\n", config.name);
    config.dev = pcap_lookupdev(errbuf); 
    if (!config.dev) {
      Log(LOG_WARNING, "WARN ( %s/core ): Unable to find a suitable device. Exiting.\n", config.name);
      exit_all(1);
    }
    else Log(LOG_DEBUG, "DEBUG ( %s/core ): device is %s\n", config.name, config.dev);
  }

  /* reading filter; if it exists, we'll take an action later */
  if (!strlen(config_file)) config.clbuf = copy_argv(&argv[optind]);

  if (config.dev && config.pcap_savefile) {
    Log(LOG_ERR, "ERROR ( %s/core ): 'interface' (-i) and 'pcap_savefile' (-I) directives are mutually exclusive. Exiting.\n", config.name);
    exit_all(1); 
  }

  throttle_startup:
  if (config.dev) {
    if ((device.dev_desc = pcap_open_live(config.dev, psize, config.promisc, 1000, errbuf)) == NULL) {
      if (!config.if_wait) {
        Log(LOG_ERR, "ERROR ( %s/core ): pcap_open_live(): %s\n", config.name, errbuf);
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
      Log(LOG_ERR, "ERROR ( %s/core ): pcap_open_offline(): %s\n", config.name, errbuf);
      exit_all(1);
    }
  }

  device.active = TRUE;
  glob_pcapt = device.dev_desc; /* SIGINT/stats handling */ 
  if (config.nfacctd_pipe_size) {
    int slen = sizeof(config.nfacctd_pipe_size), x;

#if defined (PCAP_TYPE_linux) || (PCAP_TYPE_snoop)
    Setsocksize(pcap_fileno(device.dev_desc), SOL_SOCKET, SO_RCVBUF, &config.nfacctd_pipe_size, slen);
    getsockopt(pcap_fileno(device.dev_desc), SOL_SOCKET, SO_RCVBUF, &x, &slen);
    Log(LOG_DEBUG, "DEBUG ( %s/core ): pmacctd_pipe_size: obtained=%d target=%d.\n", config.name, x, config.nfacctd_pipe_size);
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
    Log(LOG_ERR, "ERROR ( %s/core ): data link not supported: %d\n", config.name, device.link_type); 
    exit_all(1);
  }
  else Log(LOG_INFO, "INFO ( %s/core ): link type is: %d\n", config.name, device.link_type); 

  if (device.link_type != DLT_EN10MB && device.link_type != DLT_IEEE802 && device.link_type != DLT_LINUX_SLL) {
    list = plugins_list;
    while (list) {
      if ((list->cfg.what_to_count & COUNT_SRC_MAC) || (list->cfg.what_to_count & COUNT_DST_MAC)) {
        Log(LOG_ERR, "ERROR ( %s/core ): MAC aggregation not available for link type: %d\n", config.name, device.link_type);
        exit_all(1);
      }
      list = list->next;
    }
  }

  cb_data.device = &device;
  
  /* doing pcap stuff */
  if (!config.dev || pcap_lookupnet(config.dev, &localnet, &netmask, errbuf) < 0) {
    localnet = 0;
    netmask = 0;
    if (config.dev) Log(LOG_WARNING, "WARN ( %s/core ): %s\n", config.name, errbuf);
  }

  if (pcap_compile(device.dev_desc, &filter, config.clbuf, 0, netmask) < 0)
    Log(LOG_WARNING, "WARN ( %s/core ): %s (going on without a filter)\n", config.name, pcap_geterr(device.dev_desc));
  else {
    if (pcap_setfilter(device.dev_desc, &filter) < 0)
      Log(LOG_WARNING, "WARN ( %s/core ): %s (going on without a filter)\n", config.name, pcap_geterr(device.dev_desc));
  }

  /* signal handling we want to inherit to plugins (when not re-defined elsewhere) */
  signal(SIGCHLD, startup_handle_falling_child); /* takes note of plugins failed during startup phase */
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGUSR1, push_stats); /* logs various statistics via Log() calls */
  signal(SIGUSR2, reload_maps); /* sets to true the reload_maps flag */
  signal(SIGPIPE, SIG_IGN); /* we want to exit gracefully when a pipe is broken */

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
	cb_data.bpas_table = (u_char *) &bpas_table;
      }
      else {
        Log(LOG_ERR, "ERROR ( %s/core ): bgp_peer_as_src_type set to 'map' but no map defined. Exiting.\n", config.name);
        exit(1);
      }
    }
    else cb_data.bpas_table = NULL;

    if (config.nfacctd_bgp_src_local_pref_type == BGP_SRC_PRIMITIVES_MAP) {
      if (config.nfacctd_bgp_src_local_pref_map) {
        load_id_file(MAP_BGP_SRC_LOCAL_PREF, config.nfacctd_bgp_src_local_pref_map, &blp_table, &req, &blp_map_allocated);
        cb_data.blp_table = (u_char *) &blp_table;
      }
      else {
        Log(LOG_ERR, "ERROR ( %s/core ): bgp_src_local_pref_type set to 'map' but no map defined. Exiting.\n", config.name);
        exit(1);
      }
    }
    else cb_data.blp_table = NULL;

    if (config.nfacctd_bgp_src_med_type == BGP_SRC_PRIMITIVES_MAP) {
      if (config.nfacctd_bgp_src_med_map) {
        load_id_file(MAP_BGP_SRC_MED, config.nfacctd_bgp_src_med_map, &bmed_table, &req, &bmed_map_allocated);
        cb_data.bmed_table = (u_char *) &bmed_table;
      }
      else {
        Log(LOG_ERR, "ERROR ( %s/core ): bgp_src_med_type set to 'map' but no map defined. Exiting.\n", config.name);
        exit(1);
      }
    }
    else cb_data.bmed_table = NULL;

    if (config.nfacctd_bgp_to_agent_map) {
      load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.nfacctd_bgp_to_agent_map, &bta_table, &req, &bta_map_allocated);
      cb_data.bta_table = (u_char *) &bta_table;
    }
    else {
      Log(LOG_ERR, "ERROR ( %s/core ): 'bgp_daemon' configured but no 'bgp_agent_map' has been specified. Exiting.\n", config.name);
      exit(1);
    }

    /* Limiting BGP peers to only two: one would suffice in pmacctd
       but in case maps are reloadable (ie. bta), it could be handy
       to keep a backup feed in memory */
    config.nfacctd_bgp_max_peers = 2;

    cb_data.f_agent = (char *)&client;
    nfacctd_bgp_wrapper();

    /* Let's give the BGP thread some advantage to create its structures */
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

  if (config.nfacctd_flow_to_rd_map) {
    Log(LOG_ERR, "ERROR ( %s/core ): 'flow_to_rd_map' is not supported by this daemon. Exiting.\n", config.name);
    exit(1);
  }

  /* Init tunnel handlers */
  tunnel_registry_init();

  /* plugins glue: creation (until 093) */
  evaluate_packet_handlers();
  pm_setproctitle("%s [%s]", "Core Process", config.proc_name);
  if (config.pidfile) write_pid_file(config.pidfile);  

  /* signals to be handled only by the core process;
     we set proper handlers after plugin creation */
  signal(SIGINT, my_sigint_handler);
  signal(SIGTERM, my_sigint_handler);
  signal(SIGCHLD, handle_falling_child);
  kill(getpid(), SIGCHLD);

  /* When reading packets from a savefile, things are lightning fast; we will sit 
     here just few seconds, thus allowing plugins to complete their startup operations */ 
  if (config.pcap_savefile) {
    Log(LOG_INFO, "INFO ( %s/core ): PCAP capture file, sleeping for 2 seconds\n", config.name);
    sleep(2);
  }

  /* Main loop: if pcap_loop() exits maybe an error occurred; we will try closing
     and reopening again our listening device */
  for(;;) {
    if (!device.active) {
      Log(LOG_WARNING, "WARN ( %s/core ): %s has become unavailable; throttling ...\n", config.name, config.dev);
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
	Log(LOG_INFO, "INFO ( %s/core ): finished reading PCAP capture file\n", config.name);
	wait(NULL);
      }
      stop_all_childs();
    }
    device.active = FALSE;
  }
}
