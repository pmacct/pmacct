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
#include "bmp/bmp.h"
#if defined (WITH_NDPI)
#include "ndpi/ndpi.h"
#include "ndpi/ndpi_util.h"
#endif
#include "jhash.h"

/* Functions */
void usage_daemon(char *prog_name)
{
  printf("%s %s (%s)\n", PMACCTD_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
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
  printf("  -P  \t[ memory | print | mysql | pgsql | sqlite3 | amqp | kafka | nfprobe | sfprobe ] \n\tActivate plugin\n");
  printf("  -d  \tEnable debug\n");
  printf("  -i  \tListen on the specified interface\n");
  printf("  -I  \tRead packets from the specified savefile\n");
  printf("  -S  \t[ auth | mail | daemon | kern | user | local[0-7] ] \n\tLog to the specified syslog facility\n");
  printf("  -F  \tWrite Core Process PID into the specified file\n");
  printf("  -w  \tWait for the listening interface to become available\n");
  printf("  -Z  \tReading from a savefile, sleep the given amount of seconds at startup and between replays\n");
  printf("  -W  \tReading from a savefile, don't exit but sleep when finished\n");
  printf("  -Y  \tReading from a savefile, replay the number of times specified\n");
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

void pm_pcap_device_copy_all(struct pm_pcap_devices *dst, struct pm_pcap_devices *src)
{
  memcpy(dst, src, sizeof(struct pm_pcap_devices));
}

void pm_pcap_device_copy_entry(struct pm_pcap_devices *dst, struct pm_pcap_devices *src, int src_idx)
{
  memcpy(&dst->list[dst->num], &src->list[src_idx], sizeof(struct pm_pcap_device));
  dst->num++;
}

int pm_pcap_device_getindex_byifname(struct pm_pcap_devices *map, char *ifname)
{
  int loc_idx;
   for (loc_idx = 0; loc_idx < map->num; loc_idx++) {
    if (strlen(map->list[loc_idx].str) == strlen(ifname) && !strncmp(map->list[loc_idx].str, ifname, strlen(ifname))) {
      return loc_idx;
    }
  }

  return ERR;
}

pcap_t *pm_pcap_open(const char *dev_ptr, int snaplen, int promisc,
		     int to_ms, int protocol, int direction, char *errbuf)
{
  pcap_t *p;
  int ret;

  p = pcap_create(dev_ptr, errbuf);
  if (p == NULL) return NULL;

  ret = pcap_set_snaplen(p, snaplen);
  if (ret < 0) goto err;

  ret = pcap_set_promisc(p, promisc);
  if (ret < 0) goto err;

  ret = pcap_set_timeout(p, to_ms);
  if (ret < 0) goto err;

#ifdef PCAP_SET_PROTOCOL
  ret = pcap_set_protocol(p, protocol);
  if (ret < 0) goto err;
#else
  if (protocol) {
    Log(LOG_WARNING, "WARN ( %s/core ): pcap_protocol specified but linked against a version of libpcap that does not support pcap_set_protocol().\n", config.name);
  }
#endif

  ret = pcap_activate(p);
  if (ret < 0) goto err;

#ifdef PCAP_SET_DIRECTION
  ret = pcap_setdirection(p, direction);
  if (ret < 0) goto err;
#endif

  return p;

err:
  if (ret == PCAP_ERROR) {
    snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", dev_ptr, pcap_geterr(p));
  }
  else if (ret == PCAP_ERROR_NO_SUCH_DEVICE ||
	   ret == PCAP_ERROR_PERM_DENIED ||
	   ret == PCAP_ERROR_PROMISC_PERM_DENIED) {
    snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s (%s)", dev_ptr, pcap_statustostr(ret), pcap_geterr(p));
  }
  else {
    snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", dev_ptr, pcap_statustostr(ret));
  }

  pcap_close(p);

  return NULL;
}

int pm_pcap_add_interface(struct pm_pcap_device *dev_ptr, char *ifname, struct pm_pcap_interface *pm_pcap_if_entry, int psize)
{
  /* pcap library stuff */
  char errbuf[PCAP_ERRBUF_SIZE];

  int ret = SUCCESS, attempts = FALSE, index;
  int direction;

  if (pm_pcap_if_entry && pm_pcap_if_entry->direction) direction = pm_pcap_if_entry->direction; 
  else direction = config.pcap_direction;

  throttle_startup:
  if (attempts < PCAP_MAX_ATTEMPTS) {
    if ((dev_ptr->dev_desc = pm_pcap_open(ifname, psize, config.promisc, 1000, config.pcap_protocol, direction, errbuf)) == NULL) {
      if (!config.pcap_if_wait) {
	Log(LOG_ERR, "ERROR ( %s/core ): [%s] pm_pcap_open(): %s. Exiting.\n", config.name, ifname, errbuf);
	exit_gracefully(1);
      }
      else {
	sleep(PCAP_RETRY_PERIOD); /* XXX: User defined value? */
	attempts++;
	goto throttle_startup;
      }
    }

    dev_ptr->active = TRUE;
    dev_ptr->pcap_if = pm_pcap_if_entry;
    strncpy(dev_ptr->str, ifname, (sizeof(dev_ptr->str) - 1));

    if (config.pcap_ifindex == PCAP_IFINDEX_SYS)
      dev_ptr->id = if_nametoindex(dev_ptr->str);
    else if (config.pcap_ifindex == PCAP_IFINDEX_HASH)
      dev_ptr->id = jhash(dev_ptr->str, strlen(dev_ptr->str), 0);
    else if (config.pcap_ifindex == PCAP_IFINDEX_MAP) {
      if (config.pcap_interfaces_map) {
	dev_ptr->id = pm_pcap_interfaces_map_lookup_ifname(&pm_pcap_if_map, dev_ptr->str);
      }
      else {
	Log(LOG_ERR, "ERROR ( %s/core ): pcap_ifindex set to 'map' but no pcap_interface_map is defined. Exiting.\n", config.name);
	exit_gracefully(1);
      }
    }
    else dev_ptr->id = 0;

    dev_ptr->fd = pcap_fileno(dev_ptr->dev_desc);

    if (config.nfacctd_pipe_size) {
#if defined (PCAP_TYPE_linux) || (PCAP_TYPE_snoop)
      socklen_t slen = sizeof(config.nfacctd_pipe_size);
      int x;

      Setsocksize(pcap_fileno(dev_ptr->dev_desc), SOL_SOCKET, SO_RCVBUF, &config.nfacctd_pipe_size, slen);
      getsockopt(pcap_fileno(dev_ptr->dev_desc), SOL_SOCKET, SO_RCVBUF, &x, &slen);
      Log(LOG_DEBUG, "DEBUG ( %s/core ): pmacctd_pipe_size: obtained=%d target=%d.\n", config.name, x, config.nfacctd_pipe_size);
#endif
    }

    dev_ptr->link_type = pcap_datalink(dev_ptr->dev_desc);
    for (index = 0; _devices[index].link_type != -1; index++) {
      if (dev_ptr->link_type == _devices[index].link_type)
        dev_ptr->data = &_devices[index];
    }

    load_plugin_filters(dev_ptr->link_type);

    pm_pcap_check(dev_ptr);
    pm_pcap_add_filter(dev_ptr);
  }
  else {
    Log(LOG_WARNING, "WARN ( %s/core ): [%s] pm_pcap_open(): giving up after too many attempts.\n", config.name, ifname);
    ret = ERR;
  }

  return ret;
}

void pm_pcap_check(struct pm_pcap_device *dev_ptr)
{
  struct plugins_list_entry *list;

  /* we need to solve some link constraints */
  if (dev_ptr->data == NULL) {
    Log(LOG_ERR, "ERROR ( %s/core ): data link not supported: %d\n", config.name, dev_ptr->link_type);
    exit_gracefully(1);
  }
  else {
    Log(LOG_INFO, "INFO ( %s/core ): [%s,%u] link type is: %d\n", config.name, dev_ptr->str, dev_ptr->id, dev_ptr->link_type);
  }

  if (dev_ptr->link_type != DLT_EN10MB && dev_ptr->link_type != DLT_IEEE802 && dev_ptr->link_type != DLT_LINUX_SLL) {
    list = plugins_list;
    while (list) {
      if (list->cfg.what_to_count & COUNT_SRC_MAC) {
	Log(LOG_WARNING, "WARN ( %s/core ): 'src_mac' aggregation not available for link type: %d\n", config.name, dev_ptr->link_type);
	list->cfg.what_to_count ^= COUNT_SRC_MAC;
      }

      if (list->cfg.what_to_count & COUNT_DST_MAC) {
	Log(LOG_WARNING, "WARN ( %s/core ): 'dst_mac' aggregation not available for link type: %d\n", config.name, dev_ptr->link_type);
	list->cfg.what_to_count ^= COUNT_DST_MAC;
      }

      if (list->cfg.what_to_count & COUNT_VLAN) {
	Log(LOG_WARNING, "WARN ( %s/core ): 'vlan' aggregation not available for link type: %d\n", config.name, dev_ptr->link_type);
	list->cfg.what_to_count ^= COUNT_VLAN;
      }

      list = list->next;
    }
  }
}

int main(int argc,char **argv, char **envp)
{
  /* pcap library stuff */
  struct pcap_pkthdr pkt_hdr;
  const u_char *pkt_body;
  pcap_if_t *pm_pcap_ifs = NULL;

  int index, index_rr = 0, logf, ret;
  int pm_pcap_savefile_round = 0;

  struct plugins_list_entry *list;
  struct plugin_requests req;
  char config_file[SRVBUFLEN];
  int psize = DEFAULT_SNAPLEN;

  struct id_table bpas_table;
  struct id_table blp_table;
  struct id_table bmed_table;
  struct id_table biss_table;
  struct id_table bta_table;

  struct pm_pcap_device *dev_ptr;
  struct pm_pcap_callback_data cb_data;

  /* select() stuff */
  fd_set read_descs, bkp_read_descs;
  int select_fd, bkp_select_fd;

  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp;

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
  reload_map_pmacctd = FALSE;
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
  memset(&device, 0, sizeof(device));
  memset(empty_mem_area_256b, 0, sizeof(empty_mem_area_256b));
  pm_pcap_device_initialize(&devices);
  pm_pcap_device_initialize(&bkp_devices);
  log_notifications_init(&log_notifications);
  config.acct_type = ACCT_PM;
  config.progname = pmacctd_globstr;

  rows = 0;

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
      strlcpy(cfg_cmdline[rows], "pcap_interface: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'I':
      strlcpy(cfg_cmdline[rows], "pcap_savefile: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'w':
      strlcpy(cfg_cmdline[rows], "pcap_interface_wait: true", SRVBUFLEN);
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
    list->cfg.progname = pmacctd_globstr;
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
      printf("%s %s (%s)\n\n", PMACCTD_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
      printf("ERROR ( %s/core ): You need superuser privileges to run this command.\nExiting ...\n\n", config.name);
      exit_gracefully(1);
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

  Log(LOG_INFO, "INFO ( %s/core ): %s %s (%s)\n", config.name, PMACCTD_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
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
        Log(LOG_ERR, "ERROR ( %s/core ): 'tee' plugin not supported in 'pmacctd'.\n", config.name);
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

	if (psize < 128) psize = config.snaplen = 128; /* SFL_DEFAULT_HEADER_SIZE */
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
	    Log(LOG_ERR, "ERROR ( %s/%s ): AS aggregation selected but NO 'networks_file' or 'pmacctd_as' are specified. Exiting...\n\n", list->name, list->type.string);
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
              Log(LOG_ERR, "ERROR ( %s/%s ): network aggregation selected but none of 'pmacctd_net', 'networks_file', 'networks_mask' is specified. Exiting ...\n\n", list->name, list->type.string);
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

  if (config.handle_fragments) init_ip_fragment_handler();
  if (config.handle_flows) init_ip_flow_handler();
  load_networks(config.networks_file, &nt, &nc);

  if (config.pcap_interfaces_map) {
    pm_pcap_interfaces_map_initialize(&pm_pcap_if_map);
    pm_pcap_interfaces_map_initialize(&pm_bkp_pcap_if_map);
    pm_pcap_interfaces_map_load(&pm_pcap_if_map);
  }
  else {
    pm_pcap_if_map.list = NULL;
    pm_pcap_if_map.num = 0;
  }

  if (!config.pcap_direction) config.pcap_direction = PCAP_D_INOUT;

  /* If any device/savefile have been specified, choose a suitable device
     where to listen for traffic */
  if (!config.pcap_if && !config.pcap_savefile && !config.pcap_interfaces_map) {
    char errbuf[PCAP_ERRBUF_SIZE];

    Log(LOG_WARNING, "WARN ( %s/core ): Selecting a suitable devices.\n", config.name);

    ret = pcap_findalldevs(&pm_pcap_ifs, errbuf);
    if (ret == ERR || !pm_pcap_ifs) {
      Log(LOG_ERR, "ERROR ( %s/core ): Unable to get interfaces list: %s. Exiting.\n", config.name, errbuf);
      exit_gracefully(1);
    }

    config.pcap_if = pm_pcap_ifs[0].name; 
    Log(LOG_DEBUG, "DEBUG ( %s/core ): device is %s\n", config.name, config.pcap_if);
  }

  /* reading filter; if it exists, we'll take an action later */
  if (!strlen(config_file)) config.clbuf = copy_argv(&argv[optind]);

  if ((config.pcap_if || config.pcap_interfaces_map) && config.pcap_savefile) {
    Log(LOG_ERR, "ERROR ( %s/core ): interface (-i), pcap_interfaces_map and pcap_savefile (-I) directives are mutually exclusive. Exiting.\n", config.name);
    exit_gracefully(1);
  }

  if (config.pcap_if && config.pcap_interfaces_map) {
    Log(LOG_ERR, "ERROR ( %s/core ): interface (-i) and pcap_interfaces_map directives are mutually exclusive. Exiting.\n", config.name);
    exit_gracefully(1);
  }

  bkp_select_fd = 0;
  FD_ZERO(&bkp_read_descs);

  if (config.pcap_if) {
    ret = pm_pcap_add_interface(&devices.list[0], config.pcap_if, NULL, psize);
    if (!ret) {
      cb_data.device = &devices.list[0];
      devices.num = 1;
    }
  }
  else if (config.pcap_interfaces_map) {
    struct pm_pcap_interface *pm_pcap_if_entry;
    int pm_pcap_if_idx = 0;
    char *ifname;

    while ((ifname = pm_pcap_interfaces_map_getnext_ifname(&pm_pcap_if_map, &pm_pcap_if_idx))) {
      if (devices.num == PCAP_MAX_INTERFACES) {
	Log(LOG_ERR, "ERROR ( %s/core ): Maximum number of interfaces reached (%u). Exiting.\n", config.name, PCAP_MAX_INTERFACES);
	exit_gracefully(1);
      }

      pm_pcap_if_entry = pm_pcap_interfaces_map_getentry_by_ifname(&pm_pcap_if_map, ifname);
      ret = pm_pcap_add_interface(&devices.list[devices.num], ifname, pm_pcap_if_entry, psize);
      if (!ret) {
	if (bkp_select_fd <= devices.list[devices.num].fd) {
	  bkp_select_fd = devices.list[devices.num].fd;
	  bkp_select_fd++;
	}

	if (devices.list[devices.num].fd) FD_SET(devices.list[devices.num].fd, &bkp_read_descs);
	devices.num++;
      }
    }
  }
  else if (config.pcap_savefile) {
    open_pcap_savefile(&devices.list[0], config.pcap_savefile);
    pm_pcap_check(&devices.list[0]);
    pm_pcap_add_filter(&devices.list[0]);
    cb_data.device = &devices.list[0];
    devices.num = 1;
    pm_pcap_savefile_round = 1;
  }

  load_plugins(&req);

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
    else cb_data.blp_table = NULL;

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

  /* Init tunnel handlers */
  tunnel_registry_init();

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

  /* When reading packets from a savefile, things are lightning fast; we will sit
     here just few seconds, thus allowing plugins to complete their startup operations */
  if (config.pcap_savefile) {
    if (!config.pcap_sf_delay) {
      Log(LOG_INFO, "INFO ( %s/core ): PCAP capture file, sleeping for 2 seconds\n", config.name);
      sleep(2);
    }
    else sleep(config.pcap_sf_delay);
  }

#ifdef WITH_REDIS
  if (config.redis_host) {
    char log_id[SHORTBUFLEN];

    snprintf(log_id, sizeof(log_id), "%s/%s", config.name, config.type);
    p_redis_init(&redis_host, log_id, p_redis_thread_produce_common_core_handler);
  }
#endif

  sigemptyset(&cb_data.sig.set);
  sigaddset(&cb_data.sig.set, SIGCHLD);
  sigaddset(&cb_data.sig.set, SIGHUP);
  sigaddset(&cb_data.sig.set, SIGUSR1);
  sigaddset(&cb_data.sig.set, SIGUSR2);
  sigaddset(&cb_data.sig.set, SIGTERM);
  if (config.daemon) {
    sigaddset(&cb_data.sig.set, SIGINT);
  }
  cb_data.sig.is_set = TRUE;

  /* Main loop (for the case of a single interface): if pcap_loop() exits
     maybe an error occurred; we will try closing and reopening again our
     listening device */
  if (!config.pcap_interfaces_map) {
    for (;;) {
      if (!devices.list[0].active) {
	Log(LOG_WARNING, "WARN ( %s/core ): [%s] has become unavailable; throttling ...\n", config.name, config.pcap_if);
	ret = pm_pcap_add_interface(&devices.list[0], config.pcap_if, NULL, psize);
	if (!ret) {
	  cb_data.device = &devices.list[0];
	  devices.num = 1;
	}
      }

      read_packet:
      pcap_loop(devices.list[0].dev_desc, -1, pm_pcap_cb, (u_char *) &cb_data);
      pcap_close(devices.list[0].dev_desc);

      if (config.pcap_savefile) {
	if (config.pcap_sf_replay < 0 ||
	    (config.pcap_sf_replay > 0 && pm_pcap_savefile_round < config.pcap_sf_replay)) {
	  pm_pcap_savefile_round++;
	  open_pcap_savefile(&devices.list[0], config.pcap_savefile);
	  if (config.pcap_sf_delay) sleep(config.pcap_sf_delay);

	  goto read_packet;
	}

	if (config.pcap_sf_wait) {
	  fill_pipe_buffer();
	  Log(LOG_INFO, "INFO ( %s/core ): finished reading PCAP capture file\n", config.name);
	  wait(NULL);
        }
        stop_all_childs();
      }
      devices.list[0].active = FALSE;
    }
  }
  else {
    for (;;) {
      select_fd = bkp_select_fd;
      memcpy(&read_descs, &bkp_read_descs, sizeof(bkp_read_descs));

      select(select_fd, &read_descs, NULL, NULL, NULL);

      if (reload_map_pmacctd) {
	struct pm_pcap_interface *pm_pcap_if_entry;
	int pm_pcap_if_idx = 0;
	char *ifname;

	pm_pcap_interfaces_map_copy(&pm_bkp_pcap_if_map, &pm_pcap_if_map);
	pm_pcap_interfaces_map_destroy(&pm_pcap_if_map);
	pm_pcap_interfaces_map_load(&pm_pcap_if_map);

	pm_pcap_device_copy_all(&bkp_devices, &devices);
	pm_pcap_device_initialize(&devices);

	/* Add interfaces and re-build relevant structs */
	while ((ifname = pm_pcap_interfaces_map_getnext_ifname(&pm_pcap_if_map, &pm_pcap_if_idx))) {
	  if (!pm_pcap_interfaces_map_lookup_ifname(&pm_bkp_pcap_if_map, ifname)) {
	    if (devices.num == PCAP_MAX_INTERFACES) {
	      Log(LOG_WARNING, "WARN ( %s/core ): Maximum number of interfaces reached (%u). Ignoring '%s'.\n", config.name, PCAP_MAX_INTERFACES, ifname);
	    }
	    else {
	      pm_pcap_if_entry = pm_pcap_interfaces_map_getentry_by_ifname(&pm_pcap_if_map, ifname);
	      if (!pm_pcap_add_interface(&devices.list[devices.num], ifname, pm_pcap_if_entry, psize)) {
		if (bkp_select_fd <= devices.list[devices.num].fd) {
		  bkp_select_fd = devices.list[devices.num].fd;
		  bkp_select_fd++;
		}

		if (devices.list[devices.num].fd && !FD_ISSET(devices.list[devices.num].fd, &bkp_read_descs)) {
		  FD_SET(devices.list[devices.num].fd, &bkp_read_descs);
		}
	
		devices.num++;
	      }
	    }
	  }
          else {
	    int device_idx;

	    device_idx = pm_pcap_device_getindex_byifname(&bkp_devices, ifname);
	    if (device_idx >= 0) {
	      Log(LOG_INFO, "INFO ( %s/core ): [%s,%u] link type is: %d\n", config.name, bkp_devices.list[device_idx].str,
		  bkp_devices.list[device_idx].id, bkp_devices.list[device_idx].link_type);
	      pm_pcap_device_copy_entry(&devices, &bkp_devices, device_idx);
	    }
	    else Log(LOG_WARNING, "WARN ( %s/core ): Mayday. Interface '%s' went lost.\n", config.name, ifname);
	  }
	}

	/* Remove unlisted interfaces */
	pm_pcap_if_idx = 0;
	while ((ifname = pm_pcap_interfaces_map_getnext_ifname(&pm_bkp_pcap_if_map, &pm_pcap_if_idx))) {
	  if (!pm_pcap_interfaces_map_lookup_ifname(&pm_pcap_if_map, ifname)) {
            int device_idx;
          
	    device_idx = pm_pcap_device_getindex_byifname(&bkp_devices, ifname);
	    if (device_idx >= 0) {
	      Log(LOG_INFO, "INFO ( %s/core ): [%s,%u] removed.\n", config.name, bkp_devices.list[device_idx].str, bkp_devices.list[device_idx].id);
	      FD_CLR(bkp_devices.list[device_idx].fd, &bkp_read_descs);
	      pcap_close(bkp_devices.list[device_idx].dev_desc);
            }
	    else Log(LOG_WARNING, "WARN ( %s/core ): Mayday. Interface '%s' went lost (2).\n", config.name, ifname);
	  }
	}

	reload_map_pmacctd = FALSE;
      }

      for (dev_ptr = NULL, index = 0; index < devices.num; index++) {
        int loc_idx = (index + index_rr) % devices.num;

	if (devices.list[loc_idx].fd && FD_ISSET(devices.list[loc_idx].fd, &read_descs)) {
	  dev_ptr = &devices.list[loc_idx];
          index_rr = (index_rr + 1) % devices.num;
          break;
	}
      }

      if (dev_ptr) {
	pkt_body = pcap_next(dev_ptr->dev_desc, &pkt_hdr); 
	if (pkt_body) {
	  cb_data.device = dev_ptr;
	  pm_pcap_cb((u_char *) &cb_data, &pkt_hdr, pkt_body);
	}
      }
    }
  }
}
