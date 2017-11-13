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
#define __PMBGPD_C

/* includes */
#include "pmacct.h"
#include "bgp/bgp.h"
#include "pmbgpd.h"
#include "pretag_handlers.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "ip_flow.h"
#include "classifier.h"
#include "net_aggr.h"
#include "thread_pool.h"

/* global var */
struct channels_list_entry channels_list[MAX_N_PLUGINS]; /* communication channels: core <-> plugins */
thread_pool_t *bgp_lg_pool;

/* Functions */
void usage_daemon(char *prog_name)
{
  printf("%s %s (%s)\n", PMBGPD_USAGE_HEADER, PMACCT_VERSION, PMACCT_BUILD);
  printf("Usage: %s [ -D | -d ] [ -L IP address ] [ -l port ] ]\n", prog_name);
  printf("       %s [ -f config_file ]\n", prog_name);
  printf("       %s [ -h ]\n", prog_name);
  printf("\nGeneral options:\n");
  printf("  -h  \tShow this page\n");
  printf("  -V  \tShow version and compile-time options and exit\n");
  printf("  -L  \tBind to the specified IP address\n");
  printf("  -l  \tListen on the specified TCP port\n");
  printf("  -f  \tLoad configuration from the specified file\n");
  printf("  -D  \tDaemonize\n");
  printf("  -d  \tEnable debug\n");
  printf("  -S  \t[ auth | mail | daemon | kern | user | local[0-7] ] \n\tLog to the specified syslog facility\n");
  printf("  -F  \tWrite Core Process PID into the specified file\n");
  printf("  -o  \tOutput file to log real-time BGP messages\n");
  printf("  -O  \tOutput file to dump generated RIBs at regular time intervals\n");
  printf("  -i  \tInterval, in secs, to write to the dump output file (supplied by -O)\n");
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
  char config_file[SRVBUFLEN];
  int logf;

  /* getopt() stuff */
  extern char *optarg;
  extern int optind, opterr, optopt;
  int errflag, cp;

#if defined HAVE_MALLOPT
  mallopt(M_CHECK_ACTION, 0);
#endif

  umask(077);

  memset(cfg_cmdline, 0, sizeof(cfg_cmdline));
  memset(&config, 0, sizeof(struct configuration));
  memset(&config_file, 0, sizeof(config_file));

  log_notifications_init(&log_notifications);
  config.acct_type = ACCT_PMBGP;

  find_id_func = NULL;
  plugins_list = NULL;
  errflag = 0;
  rows = 0;

  /* getting commandline values */
  while (!errflag && ((cp = getopt(argc, argv, ARGS_PMBGPD)) != -1)) {
    cfg_cmdline[rows] = malloc(SRVBUFLEN);
    switch (cp) {
    case 'L':
      strlcpy(cfg_cmdline[rows], "bgp_daemon_ip: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'l':
      strlcpy(cfg_cmdline[rows], "bgp_daemon_port: ", SRVBUFLEN);
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
    case 'f':
      strlcpy(config_file, optarg, sizeof(config_file));
      break;
    case 'F':
      strlcpy(cfg_cmdline[rows], "pidfile: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'S':
      strlcpy(cfg_cmdline[rows], "syslog: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'o':
      strlcpy(cfg_cmdline[rows], "bgp_daemon_msglog_file: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'O':
      strlcpy(cfg_cmdline[rows], "bgp_table_dump_file: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'i':
      strlcpy(cfg_cmdline[rows], "bgp_table_dump_refresh_time: ", SRVBUFLEN);
      strncat(cfg_cmdline[rows], optarg, CFG_LINE_LEN(cfg_cmdline[rows]));
      rows++;
      break;
    case 'g':
      strlcpy(cfg_cmdline[rows], "bgp_daemon_lg: true", SRVBUFLEN);
      rows++;
      break;
    case 'h':
      usage_daemon(argv[0]);
      exit(0);
      break;
    case 'V':
      version_daemon(PMBGPD_USAGE_HEADER);
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

  list = plugins_list;
  while (list) {
    list->cfg.acct_type = ACCT_PMBGP;
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

  if (strlen(config_file)) {
    char canonical_path[PATH_MAX], *canonical_path_ptr;

    canonical_path_ptr = realpath(config_file, canonical_path);
    if (canonical_path_ptr) Log(LOG_INFO, "INFO ( %s/core ): Reading configuration file '%s'.\n", config.name, canonical_path);
  }
  else Log(LOG_INFO, "INFO ( %s/core ): Reading configuration from cmdline.\n", config.name);

  pm_setproctitle("%s [%s]", "Core Process", config.proc_name);
  if (config.pidfile) write_pid_file(config.pidfile);

  /* signal handling we want to inherit to plugins (when not re-defined elsewhere) */
  signal(SIGCHLD, startup_handle_falling_child); /* takes note of plugins failed during startup phase */
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, reload_maps); /* sets to true the reload_maps flag */
  signal(SIGPIPE, SIG_IGN); /* we want to exit gracefully when a pipe is broken */
  signal(SIGINT, my_sigint_handler);
  signal(SIGTERM, my_sigint_handler);

  if (!config.nfacctd_bgp) config.nfacctd_bgp = BGP_DAEMON_ONLINE;
  if (!config.nfacctd_bgp_port) config.nfacctd_bgp_port = BGP_TCP_PORT;

#if defined WITH_ZMQ
  if (config.bgp_lg) bgp_lg_wrapper();
#endif

  bgp_prepare_daemon();
  skinny_bgp_daemon();
}

#if defined WITH_ZMQ
#if defined ENABLE_THREADS
void bgp_lg_wrapper()
{
  /* initialize variables */
  if (!config.bgp_lg_ip) config.bgp_lg_ip = bgp_lg_default_ip;
  if (!config.bgp_lg_port) config.bgp_lg_port = BGP_LG_DEFAULT_TCP_PORT;
  if (!config.bgp_lg_threads) config.bgp_lg_threads = BGP_LG_DEFAULT_THREADS;

  /* initialize threads pool */
  bgp_lg_pool = allocate_thread_pool(1);
  assert(bgp_lg_pool);
  Log(LOG_DEBUG, "DEBUG ( %s/core/lg ): pmbgpd Looking Glass thread initialized\n", config.name, 1);

  /* giving a kick to the BGP thread */
  send_to_pool(bgp_lg_pool, bgp_lg_daemon, NULL);
}
#else
void bgp_lg_wrapper()
{
}
#endif /* ENABLE_THREADS */

void bgp_lg_daemon()
{
  struct p_zmq_host lg_host;
  int idx;

  memset(&lg_host, 0, sizeof(lg_host));

  p_zmq_router_setup(&lg_host, config.bgp_lg_ip, config.bgp_lg_port);
  Log(LOG_INFO, "INFO ( %s/core/lg ): Looking Glass listening on %s:%u\n", config.name, config.bgp_lg_ip, config.bgp_lg_port);

  p_zmq_dealer_inproc_setup(&lg_host, "backend");

  for (idx = 0; idx < config.bgp_lg_threads; idx++) { 
    // XXX: we should save reference to the thread handler
    void *thread = zmq_threadstart(&bgp_lg_daemon_worker, &lg_host);
  }

  zmq_proxy(lg_host.sock, lg_host.sock_inproc, NULL);
}

void bgp_lg_daemon_worker(void *zh)
{
  char identity[SRVBUFLEN], delim[SUPERSHORTBUFLEN], server_str[] = "inproc://backend";
  struct p_zmq_host *lg_host = (struct p_zmq_host *) zh;
  struct pm_bgp_lg_req req;
  struct pm_bgp_lg_rep rep;
  int req_len, identity_len, delim_len, ret;
  void *worker;

  if (!lg_host) {
    Log(LOG_ERR, "ERROR ( %s/core/lg ): bgp_lg_daemon_worker no lg_host\nExiting.\n", config.name);
    exit(1);
  }

  worker = zmq_socket(lg_host->ctx, ZMQ_REP);
  if (!worker) {
    Log(LOG_ERR, "ERROR ( %s/core/lg ): bgp_lg_daemon_worker zmq_socket() failed: %s (%s)\nExiting.\n",
	config.name, server_str, zmq_strerror(errno));
    exit(1);
  }

  ret = zmq_connect(worker, server_str);
  if (ret == ERR) {
    Log(LOG_ERR, "ERROR ( %s/core/lg ): bgp_lg_daemon_worker zmq_connect() failed: %s (%s)\nExiting.\n",
        config.name, server_str, zmq_strerror(errno));
    exit(1);
  }

  for (;;) {
/*
    identity_len = p_zmq_recv_bin(lg_host.sock, identity, sizeof(identity));
    delim_len = p_zmq_recv_bin(lg_host.sock, delim, sizeof(delim));
*/

    req_len = p_zmq_recv_bin(worker, &req, sizeof(req));
    if (req_len != sizeof(req)) {
      Log(LOG_WARNING, "WARN ( %s/core/lg ): invalid message received %u != %u\n", config.name, req_len, sizeof(req));
      continue;
    }
    
    // XXX
    memcpy(&rep, &req, sizeof(rep));
/*
    p_zmq_sendmore_bin(lg_host.sock, identity, identity_len);
    p_zmq_sendmore_bin(lg_host.sock, delim, delim_len);
*/
    p_zmq_send_bin(worker, &rep, sizeof(rep));
  }
}
#endif /* WITH_ZMQ */ 
