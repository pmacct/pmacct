/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2015 by Paolo Lucente
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
#define __UACCTD_C

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

/* variables to be exported away */
int debug;
struct configuration config; /* global configuration */ 
struct plugins_list_entry *plugins_list = NULL; /* linked list of each plugin configuration */ 
struct channels_list_entry channels_list[MAX_N_PLUGINS]; /* communication channels: core <-> plugins */
int have_num_memory_pools; /* global getopt() stuff */
pid_t failed_plugins[MAX_N_PLUGINS]; /* plugins failed during startup phase */
u_char dummy_tlhdr[16];

#ifdef ENABLE_ULOG

/* Functions */
void usage_daemon(char *prog_name)
{
  printf("%s (%s)\n", UACCTD_USAGE_HEADER, PMACCT_BUILD);
  printf("Usage: %s [ -D | -d ] [ -g ULOG group ] [ -c primitive [ , ... ] ] [ -P plugin [ , ... ] ]\n", prog_name);
  printf("       %s [ -f config_file ]\n", prog_name);
  printf("       %s [ -h ]\n", prog_name);
  printf("\nGeneral options:\n");
  printf("  -h  \tShow this page\n");
  printf("  -V  \tShow version and compile-time options and exit\n");
  printf("  -f  \tLoad configuration from the specified file\n");
  printf("  -a  \tPrint list of supported aggregation primitives\n");
  printf("  -c  \tAggregation method, see full list of primitives with -a (DEFAULT: src_host)\n");
  printf("  -D  \tDaemonize\n"); 
  printf("  -n  \tPath to a file containing Network definitions\n");
  printf("  -o  \tPath to a file containing Port definitions\n");
  printf("  -P  \t[ memory | print | mysql | pgsql | sqlite3 | mongodb | nfprobe | sfprobe ] \n\tActivate plugin\n"); 
  printf("  -d  \tEnable debug\n");
  printf("  -S  \t[ auth | mail | daemon | kern | user | local[0-7] ] \n\tLog to the specified syslog facility\n");
  printf("  -F  \tWrite Core Process PID into the specified file\n");
  printf("  -R  \tRenormalize sampled data\n");
  printf("  -g  \tNetlink ULOG group\n");
  printf("  -L  \tNetlink socket read buffer size\n");
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
  printf("  -O  \t[ formatted | csv | json ] \n\tOutput format\n");
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
  int psize = ULOG_BUFLEN;

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

  /* ULOG stuff */
  int ulog_fd, one = 1;
  struct nlmsghdr *nlh;
  struct sockaddr_nl nls;
  ulog_packet_msg_t *ulog_pkt;
  ssize_t len = 0;
  socklen_t alen;
  unsigned char *ulog_buffer;
  struct pcap_pkthdr hdr;
  struct timeval tv;

  char jumbo_container[10000];
  u_int8_t mac_len;



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
  have_num_memory_pools = FALSE;
  reload_map = FALSE;
  bpas_map_allocated = FALSE;
  blp_map_allocated = FALSE;
  bmed_map_allocated = FALSE;
  biss_map_allocated = FALSE;
  bta_map_caching = FALSE;
  sampling_map_caching = FALSE;
  custom_primitives_allocated = FALSE;
  find_id_func = PM_find_id;

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
  while (!errflag && ((cp = getopt(argc, argv, ARGS_UACCTD)) != -1)) {
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
      version_daemon(UACCTD_USAGE_HEADER);
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
    set_default_preferences(&list->cfg);
    if (!strcmp(list->type.string, "core")) { 
      memcpy(&config, &list->cfg, sizeof(struct configuration)); 
      config.name = list->name;
      config.type = list->type.string;
    }
    list = list->next;
  }

  if (config.files_umask) umask(config.files_umask);

  if (!config.snaplen) config.snaplen = psize;
  if (!config.uacctd_nl_size) config.uacctd_nl_size = psize;

  /* Let's check whether we need superuser privileges */
  if (getuid() != 0) {
    printf("%s (%s)\n\n", UACCTD_USAGE_HEADER, PMACCT_BUILD);
    printf("ERROR ( %s/core ): You need superuser privileges to run this command.\nExiting ...\n\n", config.name);
    exit(1);
  }

  if (!config.uacctd_group) {
    config.uacctd_group = DEFAULT_ULOG_GROUP;
    list = plugins_list;
    while (list) {
      list->cfg.uacctd_group = DEFAULT_ULOG_GROUP;
      list = list->next;
    }
  }

  if (config.daemon) {
    list = plugins_list;
    while (list) {
      if (!strcmp(list->type.string, "print")) printf("INFO ( %s/core ): Daemonizing. Hmm, bye bye screen.\n", config.name);
      list = list->next;
    }
    if (debug || config.debug)
      printf("WARN ( %s/core ): debug is enabled; forking in background. Console logging will get lost.\n", config.name); 
    daemonize();
  }

  initsetproctitle(argc, argv, envp);
  if (config.syslog) {
    logf = parse_log_facility(config.syslog);
    if (logf == ERR) {
      config.syslog = NULL;
      printf("WARN ( %s/core ): specified syslog facility is not supported; logging to console.\n", config.name);
    }
    else openlog(NULL, LOG_PID, logf);
    Log(LOG_INFO, "INFO ( %s/core ): Start logging ...\n", config.name);
  }

  if (config.logfile)
  {
    config.logfile_fd = open_logfile(config.logfile, "a");
    list = plugins_list;
    while (list) {
      list->cfg.logfile_fd = config.logfile_fd ;
      list = list->next;
    }
  }

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
      if (config.classifiers_path && (list->cfg.sampling_rate || config.ext_sampling_rate)) {
        Log(LOG_ERR, "ERROR ( %s/core ): Packet sampling and classification are mutual exclusive.\n", config.name);
        exit(1);
      }
      if (list->cfg.sampling_rate && config.ext_sampling_rate) {
        Log(LOG_ERR, "ERROR ( %s/core ): Internal packet sampling and external packet sampling are mutual exclusive.\n", config.name);
        exit(1);
      }

      if (list->type.id == PLUGIN_ID_TEE) {
        Log(LOG_ERR, "ERROR ( %s/core ): 'tee' plugin not supported in 'uacctd'.\n", config.name);
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
        if (list->cfg.what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM|COUNT_LOCAL_PREF|COUNT_MED|COUNT_AS_PATH|
                                       COUNT_PEER_SRC_AS|COUNT_PEER_DST_AS|COUNT_PEER_SRC_IP|COUNT_SRC_STD_COMM|
                                       COUNT_SRC_EXT_COMM|COUNT_SRC_AS_PATH|COUNT_SRC_MED|COUNT_SRC_LOCAL_PREF|
				       COUNT_MPLS_VPN_RD)) {
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
        if (list->cfg.what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM|COUNT_LOCAL_PREF|COUNT_MED|COUNT_AS_PATH|
                                       COUNT_PEER_SRC_AS|COUNT_PEER_DST_AS|COUNT_PEER_SRC_IP|COUNT_SRC_STD_COMM|
                                       COUNT_SRC_EXT_COMM|COUNT_SRC_AS_PATH|COUNT_SRC_MED|COUNT_SRC_LOCAL_PREF|
				       COUNT_MPLS_VPN_RD)) {
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
                        COUNT_TIMESTAMP_START|COUNT_TIMESTAMP_END))
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
        if ((list->cfg.what_to_count & COUNT_SRC_HOST) && (list->cfg.what_to_count & COUNT_SRC_NET) ||
            (list->cfg.what_to_count & COUNT_DST_HOST) && (list->cfg.what_to_count & COUNT_DST_NET)) {
          if (!list->cfg.tmp_net_own_field) {
            Log(LOG_ERR, "ERROR ( %s/%s ): src_host, src_net and dst_host, dst_net are mutually exclusive: set tmp_net_own_field to true. Exiting...\n\n", list->name, list->type.string);
            exit(1);
          }
        }
	if (list->cfg.what_to_count & (COUNT_SRC_AS|COUNT_DST_AS|COUNT_SUM_AS)) {
	  if (!list->cfg.networks_file && list->cfg.nfacctd_as != NF_AS_BGP) { 
	    Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation selected but NO 'networks_file' or 'uacctd_as' are specified. Exiting...\n\n", list->name, list->type.string);
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
              Log(LOG_ERR, "ERROR ( %s/%s ): network aggregation selected but none of 'uacctd_net', 'networks_file', 'networks_mask' is specified. Exiting ...\n\n", list->name, list->type.string);
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
  signal(SIGCHLD, startup_handle_falling_child); /* takes note of plugins failed during startup phase */
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGUSR1, push_stats); /* logs various statistics via Log() calls */
  signal(SIGUSR2, reload_maps); /* sets to true the reload_maps flag */
  signal(SIGPIPE, SIG_IGN); /* we want to exit gracefully when a pipe is broken */

  ulog_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_NFLOG);
  if (ulog_fd == -1) {
    Log(LOG_ERR, "ERROR ( %s/core ): Failed to create Netlink ULOG socket\n", config.name);
    exit_all(1);
  }

  Log(LOG_INFO, "INFO ( %s/core ): Successfully connected Netlink ULOG socket\n", config.name);

  /* Turn off netlink errors from overrun. */
  if (setsockopt(ulog_fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one)))
    Log(LOG_ERR, "ERROR ( %s/core ): Failed to turn off netlink ENOBUFS\n", config.name);

  if (config.uacctd_nl_size > ULOG_BUFLEN) {
    /* If configured buffer size is larger than default 4KB */
    if (setsockopt(ulog_fd, SOL_SOCKET, SO_RCVBUF, &config.uacctd_nl_size, sizeof(config.uacctd_nl_size)))
      Log(LOG_ERR, "ERROR ( %s/core ): Failed to set Netlink receive buffer size\n", config.name);
    else
      Log(LOG_INFO, "INFO ( %s/core ): Netlink receive buffer size set to %u\n", config.name, config.uacctd_nl_size);
  }

  ulog_buffer = malloc(config.snaplen);
  if (ulog_buffer == NULL) {
    Log(LOG_ERR, "ERROR ( %s/core ): ULOG buffer malloc() failed\n", config.name);
    close(ulog_fd);
    exit_all(1);
  }

  memset(&nls, 0, sizeof(nls));
  nls.nl_family = AF_NETLINK;
  nls.nl_pid = getpid();
  nls.nl_groups = config.uacctd_group;
  alen = sizeof(nls);

  if (bind(ulog_fd, (struct sockaddr *) &nls, sizeof(nls))) {
    Log(LOG_ERR, "ERROR ( %s/core ): bind() to Netlink ULOG socket failed\n", config.name);
    close(ulog_fd);
    exit_all(1);
  }
  Log(LOG_INFO, "INFO ( %s/core ): Netlink ULOG: binding to group %u\n", config.name, config.uacctd_group);

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
	cb_data.bpas_table = (u_char *) &bpas_table;
      }
      else {
        Log(LOG_ERR, "ERROR: bgp_peer_as_src_type set to 'map' but no map defined. Exiting.\n");
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
        Log(LOG_ERR, "ERROR: bgp_src_local_pref_type set to 'map' but no map defined. Exiting.\n");
        exit(1);
      }
    }
    else cb_data.bpas_table = NULL;

    if (config.nfacctd_bgp_src_med_type == BGP_SRC_PRIMITIVES_MAP) {
      if (config.nfacctd_bgp_src_med_map) {
        load_id_file(MAP_BGP_SRC_MED, config.nfacctd_bgp_src_med_map, &bmed_table, &req, &bmed_map_allocated);
        cb_data.bmed_table = (u_char *) &bmed_table;
      }
      else {
        Log(LOG_ERR, "ERROR: bgp_src_med_type set to 'map' but no map defined. Exiting.\n");
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

  if (config.nfacctd_flow_to_rd_map) { 
    Log(LOG_ERR, "ERROR ( %s/core ): 'flow_to_rd_map' is not supported by this daemon. Exiting.\n", config.name);
    exit(1);
  } 

  /* plugins glue: creation (until 093) */
  evaluate_packet_handlers();
  if (!config.proc_name) pm_setproctitle("%s [%s]", "Core Process", "default");
  else pm_setproctitle("%s [%s]", "Core Process", config.proc_name);
  if (config.pidfile) write_pid_file(config.pidfile);  

  /* signals to be handled only by pmacctd;
     we set proper handlers after plugin creation */
  signal(SIGINT, my_sigint_handler);
  signal(SIGTERM, my_sigint_handler);
  signal(SIGCHLD, handle_falling_child);
  kill(getpid(), SIGCHLD);

  /* Main loop: if pcap_loop() exits maybe an error occurred; we will try closing
     and reopening again our listening device */
  for (;;) {
    if (len == -1) {
      if (errno != EAGAIN) {
        /* We can't deal with permanent errors.
         * Just sleep a bit.
         */
        Log(LOG_ERR, "ERROR ( %s/core ): Syscall returned %d: %s. Sleeping for 1 sec.\n", config.name, errno, strerror(errno));
        sleep(1);
      }
    }

    len = recvfrom(ulog_fd, ulog_buffer, config.snaplen, 0, (struct sockaddr*) &nls, &alen);

    /*
     * Read timeout or failure condition.
     */
    if (len < (int)sizeof(struct nlmsghdr)) continue;
    if (alen != sizeof(nls)) continue;

    nlh = (struct nlmsghdr*) ulog_buffer;
    if ((nlh->nlmsg_flags & MSG_TRUNC) || ((size_t)len > config.snaplen)) continue;

    gettimeofday(&tv, NULL);

    while (NLMSG_OK(nlh, (size_t)len)) {
      ulog_pkt = NLMSG_DATA(nlh);
      hdr.ts = tv;
      hdr.caplen = MIN(ulog_pkt->data_len, config.snaplen);
      hdr.len = ulog_pkt->data_len;

      if (strlen(ulog_pkt->indev_name) > 1) {
	cb_data.ifindex_in = cache_ifindex(ulog_pkt->indev_name, tv.tv_sec);
      }
      else cb_data.ifindex_in = 0;

      if (strlen(ulog_pkt->outdev_name) > 1) {
	cb_data.ifindex_out = cache_ifindex(ulog_pkt->outdev_name, tv.tv_sec);
      }
      else cb_data.ifindex_out = 0;

#if defined (HAVE_L2)
      if (ulog_pkt->mac_len) {
	memcpy(jumbo_container, ulog_pkt->mac, ulog_pkt->mac_len);
	memcpy(jumbo_container+ulog_pkt->mac_len, ulog_pkt->payload, hdr.caplen);
	// XXX
	hdr.caplen += ulog_pkt->mac_len;
	hdr.len += ulog_pkt->mac_len;
      }
      else {
	memset(jumbo_container, 0, ETHER_HDRLEN);
	memcpy(jumbo_container+ETHER_HDRLEN, ulog_pkt->payload, hdr.caplen);
	hdr.caplen += ETHER_HDRLEN;
	hdr.len += ETHER_HDRLEN;

	switch (IP_V((struct my_iphdr *) ulog_pkt->payload)) {
	case 4:
	  ((struct eth_header *)jumbo_container)->ether_type = ntohs(ETHERTYPE_IP);
	  break;
	case 6:
	  ((struct eth_header *)jumbo_container)->ether_type = ntohs(ETHERTYPE_IPV6);
	  break;
	}

      }

      pcap_cb((u_char *) &cb_data, &hdr, jumbo_container);
#else
      pcap_cb((u_char *) &cb_data, &hdr, ulog_pkt->payload);
#endif

      if (nlh->nlmsg_type == NLMSG_DONE || !(nlh->nlmsg_flags & NLM_F_MULTI)) {
        /* Last part of the multilink message */
        break;
      }
      nlh = NLMSG_NEXT(nlh, len);
    }
  }
}

unsigned int get_ifindex(char *device) 
{
  static int sock = -1;

  if (sock < 0) {
    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
      Log(LOG_ERR, "ERROR: Unable to open socket for ifindex");
      return -1;
    }
  }
  
  struct ifreq req;
  strcpy(req.ifr_name, device);
  if (ioctl(sock, SIOCGIFINDEX, &req)) {
    Log(LOG_ERR, "ERROR: Interface %s not found\n", device);
    return -1;
  }

  return req.ifr_ifindex;
}

unsigned int hash_ifname(char *name)
{
  unsigned hash = 0;

  while (*name)
    hash = 33 * hash + *name++;

  return (hash & IFCACHE_HASHSIZ-1);
}

/* Cache name to ifindex mapping */
unsigned int cache_ifindex(char *device, unsigned long now)
{
  struct ifname_cache *ifc, **top;
  unsigned int ifindex;

  top = &hash_heads[hash_ifname(device)];
  while ( (ifc = *top) != NULL) {
    if (strncmp(device, ifc->name, IFNAMSIZ)) {
      top = &ifc->next;
      continue;
    }

    /* prune old entry to deal with hotplug */
    if ((long)(now - ifc->tstamp) > IFCACHE_LIFETIME) {
      *top = ifc->next;
      free(ifc);
      break;
    }

    return ifc->index;
  }

  ifindex = get_ifindex(device);
  if (ifindex) {
    ifc = malloc(sizeof(struct ifname_cache));
    if (ifc) {
      ifc->index = ifindex;
      strncpy(ifc->name, device, IFNAMSIZ);
      ifc->tstamp = now;
      ifc->next = *top;
      *top = ifc;
    }
  }

  return ifindex;
}

#else

int main(int argc,char **argv, char **envp)
{
  printf("WARN: uacctd (Linux NetFilter ULOG accounting) daemon is not active. This is enabled by --enable-ulog\n");
}

#endif

/* Dummy objects here - ugly to see but well portable */
void NF_find_id(struct id_table *t, struct packet_ptrs *pptrs, pm_id_t *tag, pm_id_t *tag2)
{
}

void SF_find_id(struct id_table *t, struct packet_ptrs *pptrs, pm_id_t *tag, pm_id_t *tag2)
{
}
