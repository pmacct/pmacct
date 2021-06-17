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
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "bgp/bgp.h"

/* extern */
extern struct plugins_list_entry *plugin_list;

/* functions */
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
	else {
	  if (config.plugin_exit_any) {
            Log(LOG_WARNING, "WARN ( %s/%s ): one or more plugins did exit (plugin_exit_any). Shutting down.\n", config.name, config.type);
	    if (config.pidfile) remove_pid_file(config.pidfile);
	    exit_all(1);
	  }
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
    else {
      if (config.plugin_exit_any) {
	Log(LOG_WARNING, "WARN ( %s/%s ): one or more plugins did exit (plugin_exit_any). Shutting down.\n", config.name, config.type);
	if (config.pidfile) remove_pid_file(config.pidfile);
	exit_all(1);
      }
    }
  }
}

void ignore_falling_child()
{
  pid_t cpid;
  int status;

  while ((cpid = waitpid(-1, &status, WNOHANG)) > 0) {
    if (!WIFEXITED(status)) Log(LOG_WARNING, "WARN ( %s/%s ): Abnormal exit status detected for child PID %u\n", config.name, config.type, cpid);
    // sql_writers.retired++;
  }
}

void PM_sigint_handler(int signum)
{
  struct plugins_list_entry *list = plugins_list;
  char shutdown_msg[] = "pmacct received SIGINT - shutting down";

  if (config.acct_type == ACCT_PMBGP || config.bgp_daemon == BGP_DAEMON_ONLINE) {
    int idx;

    for (idx = 0; idx < config.bgp_daemon_max_peers; idx++) {
      if (peers[idx].fd)
	bgp_peer_close(&peers[idx], FUNC_TYPE_BGP, TRUE, TRUE, BGP_NOTIFY_CEASE, BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN, shutdown_msg);
    }
  }

  if (config.syslog) closelog();

  /* We are about to exit, but it may take a while - because of the
     wait() call. Let's release collector's socket to improve turn-
     around times when restarting the daemon */
  if (config.acct_type == ACCT_NF || config.acct_type == ACCT_SF) {
    close(config.sock);

    if (config.nfacctd_templates_sock) {
      close(config.nfacctd_templates_sock);
    }

#ifdef WITH_GNUTLS
    if (config.nfacctd_dtls_sock) {
      pm_dtls_server_bye(NULL);
      close(config.nfacctd_dtls_sock);
    }
#endif
  }

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
    int device_idx;

    if (config.pcap_if) {
      printf("NOTICE ( %s/%s ): +++\n", config.name, config.type);

      for (device_idx = 0; device_idx < devices.num; device_idx++) {
        if (pcap_stats(devices.list[device_idx].dev_desc, &ps) < 0) {
	  printf("INFO ( %s/%s ): [%s,%u] error='pcap_stats(): %s'\n",
		config.name, config.type, devices.list[device_idx].str,
		devices.list[device_idx].id,
		pcap_geterr(devices.list[device_idx].dev_desc));
	}
        printf("NOTICE ( %s/%s ): [%s,%u] received_packets=%u dropped_packets=%u\n",
		config.name, config.type, devices.list[device_idx].str,
		devices.list[device_idx].id, ps.ps_recv, ps.ps_drop);
      }

      printf("NOTICE ( %s/%s ): ---\n", config.name, config.type);
    }
  }

  if (config.pidfile) remove_pid_file(config.pidfile);

  if (config.propagate_signals) signal_kittens(signum, TRUE);

  exit(0);
}

void PM_sigalrm_noop_handler(int signum)
{
  /* noop */
}

void reload(int signum)
{
  reload_log = TRUE;
  if (config.bgp_daemon_msglog_file) reload_log_bgp_thread = TRUE;
  if (config.bmp_daemon_msglog_file) reload_log_bmp_thread = TRUE;
  if (config.sfacctd_counter_file) reload_log_sf_cnt = TRUE;
  if (config.telemetry_msglog_file) reload_log_telemetry_thread = TRUE;

  if (config.propagate_signals) signal_kittens(signum, TRUE);
}

void push_stats(int signum)
{
  if (config.acct_type == ACCT_PM) {
    time_t now = time(NULL);
    PM_print_stats(now);
  }
  else if (config.acct_type == ACCT_NF || config.acct_type == ACCT_SF) {
    print_stats = TRUE;
  }

  if (config.propagate_signals) signal_kittens(signum, TRUE);
}

void reload_maps(int signum)
{
  reload_map = FALSE;
  reload_map_bgp_thread = FALSE;
  reload_map_rpki_thread = FALSE;
  reload_map_exec_plugins = FALSE;
  reload_geoipv2_file = FALSE;

  if (config.maps_refresh) {
    reload_map = TRUE; 
    reload_map_bgp_thread = TRUE;
    reload_map_rpki_thread = TRUE;
    reload_map_exec_plugins = TRUE;
    reload_geoipv2_file = TRUE;

    if (config.acct_type == ACCT_PM) reload_map_pmacctd = TRUE;
  }
  
  if (config.propagate_signals) {
    signal_kittens(signum, TRUE);
  }
}
