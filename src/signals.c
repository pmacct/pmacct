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
#define __SIGNALS_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "bgp/bgp.h"

/* extern */
extern struct plugins_list_entry *plugin_list;

/* functions */
/* Each signal handler contains a final signal() call that reinstalls the called
   handler again; such behaviour deals with SysV signal handling */
void startup_handle_falling_child()
{
  int i, j;

  j = waitpid(-1, 0, WNOHANG);
  for (i = 0; i < MAX_N_PLUGINS; i++) {
    if (!failed_plugins[i]) {
      failed_plugins[i] = j;
      break;
    }
  }

  signal(SIGCHLD, startup_handle_falling_child);
}

void handle_falling_child()
{
  struct plugins_list_entry *list = NULL;
  int j, ret;

  /* we first scan failed_plugins[] array for plugins failed during the
     startup phase: when we are building plugins_list, we cannot arbitrarily 
     delete nodes (plugins) from it */ 
  for (j = 0; j < MAX_N_PLUGINS; j++) {
    if (failed_plugins[j]) { 
      list = search_plugin_by_pid(failed_plugins[j]);
      if (list) {
        Log(LOG_WARNING, "WARN ( %s/%s ): connection lost to '%s-%s'; closing connection.\n",
		config.name, config.type, list->name, list->type.string);
        close(list->pipe[1]);
        delete_pipe_channel(list->pipe[1]);
        ret = delete_plugin_by_id(list->id);
        if (!ret) {
          Log(LOG_WARNING, "WARN ( %s/%s ): no more plugins active. Shutting down.\n", config.name, config.type);
	  if (config.pidfile) remove_pid_file(config.pidfile);
          exit(1);
        }
      }
      failed_plugins[j] = 0;
    }
    else break;
  } 

  j = waitpid(-1, 0, WNOHANG);
  list = search_plugin_by_pid(j);
  if (list) {
    Log(LOG_WARNING, "WARN ( %s/%s ): connection lost to '%s-%s'; closing connection.\n",
	config.name, config.type, list->name, list->type.string);
    close(list->pipe[1]);
    delete_pipe_channel(list->pipe[1]);
    ret = delete_plugin_by_id(list->id);
    if (!ret) {
      Log(LOG_WARNING, "WARN ( %s/%s ): no more plugins active. Shutting down.\n", config.name, config.type);
      if (config.pidfile) remove_pid_file(config.pidfile);
      exit(1);
    }
  }

  signal(SIGCHLD, handle_falling_child);
}

void ignore_falling_child()
{
  pid_t cpid;
  int status;

  while ((cpid = waitpid(-1, &status, WNOHANG)) > 0) {
    if (!WIFEXITED(status)) Log(LOG_WARNING, "WARN ( %s/%s ): Abnormal exit status detected for child PID %u\n", config.name, config.type, cpid);
    // sql_writers.retired++;
  }

  signal(SIGCHLD, ignore_falling_child);
}

void my_sigint_handler(int signum)
{
  struct plugins_list_entry *list = plugins_list;
  char shutdown_msg[] = "pmacct received SIGINT - shutting down";

  if (config.acct_type == ACCT_PMBGP || config.nfacctd_bgp == BGP_DAEMON_ONLINE) {
    int idx;

    for (idx = 0; idx < config.nfacctd_bgp_max_peers; idx++) {
      if (peers[idx].fd)
	bgp_peer_close(&peers[idx], FUNC_TYPE_BGP, TRUE, TRUE, BGP_NOTIFY_CEASE, BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN, shutdown_msg);
    }
  }

  if (config.syslog) closelog();

  /* We are about to exit, but it may take a while - because of the
     wait() call. Let's release collector's socket to improve turn-
     around times when restarting the daemon */
  if (config.acct_type == ACCT_NF || config.acct_type == ACCT_SF) close(config.sock);

#if defined (IRIX) || (SOLARIS)
  signal(SIGCHLD, SIG_IGN);
#else
  signal(SIGCHLD, ignore_falling_child);
#endif

  signal(SIGINT, SIG_IGN);
  signal(SIGTERM, SIG_IGN);

  fill_pipe_buffer();
  sleep(2); /* XXX: we should really choose an adaptive value here. It should be
	            closely bound to, say, biggest plugin_buffer_size value */ 

  while (list) {
    if (memcmp(list->type.string, "core", sizeof("core"))) kill(list->pid, SIGINT);
    list = list->next;
  }

  wait(NULL);

  Log(LOG_INFO, "INFO ( %s/%s ): OK, Exiting ...\n", config.name, config.type);

  if (config.acct_type == ACCT_PM && !config.uacctd_group /* XXX */) {
    if (config.dev) {
      if (pcap_stats(glob_pcapt, &ps) < 0) printf("\npcap_stats: %s\n", pcap_geterr(glob_pcapt));
      printf("\n");
      printf("%u packets received by filter\n", ps.ps_recv);
      printf("%u packets dropped by kernel\n", ps.ps_drop);
    }
  }

  if (config.pidfile) remove_pid_file(config.pidfile);
  exit(0);
}

void reload()
{
  int logf;

  if (config.syslog) {
    closelog();
    logf = parse_log_facility(config.syslog);
    if (logf == ERR) {
      config.syslog = NULL;
      Log(LOG_WARNING, "WARN ( %s/%s ): specified syslog facility is not supported; logging to console.\n", config.name, config.type);
    }
    openlog(NULL, LOG_PID, logf);
    Log(LOG_INFO, "INFO ( %s/%s ): Start logging ...\n", config.name, config.type);
  }

  if (config.logfile) {
    fclose(config.logfile_fd);
    config.logfile_fd = open_output_file(config.logfile, "a", FALSE);
  }

  if (config.nfacctd_bgp_msglog_file) reload_log_bgp_thread = TRUE;
  if (config.nfacctd_bmp_msglog_file) reload_log_bmp_thread = TRUE;
  if (config.sfacctd_counter_file) reload_log_sf_cnt = TRUE;
  if (config.telemetry_msglog_file) reload_log_telemetry_thread = TRUE;

  signal(SIGHUP, reload);
}

void push_stats()
{
  time_t now = time(NULL);

  if (config.acct_type == ACCT_PM) {
    if (config.dev) {
      if (pcap_stats(glob_pcapt, &ps) < 0) Log(LOG_INFO, "INFO ( %s/%s ): pcap_stats: %s\n",
						config.name, config.type, pcap_geterr(glob_pcapt));
      Log(LOG_NOTICE, "NOTICE ( %s/%s ): %s: (%u) %u packets received by filter\n",
		config.name, config.type, config.dev, now, ps.ps_recv);
      Log(LOG_NOTICE, "NOTICE ( %s/%s ): %s: (%u) %u packets dropped by kernel\n",
		config.name, config.type, config.dev, now, ps.ps_drop);
    }
  }
  else if (config.acct_type == ACCT_NF || config.acct_type == ACCT_SF)
    print_status_table(now, XFLOW_STATUS_TABLE_SZ);

  signal(SIGUSR1, push_stats);
}

void reload_maps()
{
  reload_map = FALSE;
  reload_map_bgp_thread = FALSE;
  reload_map_exec_plugins = FALSE;
  reload_geoipv2_file = FALSE;

  if (config.maps_refresh) {
    reload_map = TRUE; 
    reload_map_bgp_thread = TRUE;
    reload_map_exec_plugins = TRUE;
    reload_geoipv2_file = TRUE;
  }
  
  signal(SIGUSR2, reload_maps);
}
