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
#define __INTSTATSD_C

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "thread_pool.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "intstats.h"

/* variables to be exported away */
thread_pool_t *intstats_pool;
struct channels_list_entry *channels_list; /* communication channels: core <-> plugins */
void * (*daemon_stats_func) (void *) = NULL; /* pointer to daemon stats generation function */
struct active_thread *at;

/* Functions */
#if defined ENABLE_THREADS
void intstats_wrapper(const struct channels_list_entry *chan_list, void *(*func)(void *))
{
  struct intstats_data *t_data;

  if (!config.metrics_what_to_count) {
    Log(LOG_WARNING, "WARN ( %s/core/STATS ): No metric set. Check your configuration.\n", config.name);
    return;
  }

  /* initialize threads pool */
  intstats_pool = allocate_thread_pool(1);
  assert(intstats_pool);

  t_data = malloc(sizeof(struct intstats_data));
  if (!t_data) {
    Log(LOG_ERR, "ERROR ( %s/core/STATS ): malloc() struct intstats_data failed. Terminating.\n", config.name);
    exit_all(1);
  }
  intstats_prepare_thread(t_data);

  channels_list = chan_list;
  daemon_stats_func = func;

  /* giving a kick to the intstats thread */
  send_to_pool(intstats_pool, intstats_daemon, t_data);
}
#endif

void intstats_prepare_thread(struct intstats_data *t_data)
{
  if (!t_data) return;

  memset(t_data, 0, sizeof(struct intstats_data));
  t_data->is_thread = TRUE;
  t_data->log_str = malloc(strlen("core/STATS") + 1);
  strcpy(t_data->log_str, "core/STATS");
}

void intstats_daemon(void *t_data_void)
{
  struct metric *met_tmp = NULL;
  time_t start, end;
  int sock, nb_children;

  if (init_metrics(&met) <= 0) {
    Log(LOG_ERR, "ERROR ( %s/core/STATS ): Error during metrics initialisation. Exiting.\n", config.name);
    exit(1);
  }

  sock = init_statsd_sock();
  Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): socket initialized\n", config.name);

  if (!config.statsd_refresh_time) config.statsd_refresh_time = STATS_REFRESH_TIME_DEFAULT;

  //XXX: this periodicity implementation assumes stats collection and sending combined are shorter than configured period
  while (1) {
    nb_children = 0;
    start = time(NULL);

    nb_children += launch_core_threads();
    nb_children += launch_plugins_threads();

    plugin_buffers_generate_stats(met);


    while (at) {
      if (!pthread_join(*(at->thread), NULL)) {
        delete_active_thread(at->thread);
        if (at) at = at->next;
      }
    }

    met_tmp = met;
    while (met_tmp) {
      send_data(met_tmp, sock);
      met_tmp = met_tmp->next;
    }
    end = time(NULL);
    reset_metrics_values(met);
    sleep(MAX(0, config.statsd_refresh_time - (end - start)));
  }
}

int launch_plugins_threads()
{
  int thread_cnt = 0;
  struct plugins_list_entry *list = plugins_list;
  pthread_t *plugin_thread;

  while (list) {
    if (list->cfg.intstats_daemon && list->type.stats_func) {
      plugin_thread = malloc(sizeof(pthread_t));
      if (!plugin_thread) {
        Log(LOG_ERR, "ERROR ( %s/%s ): unable to allocate pthread structure. Exiting ...\n", list->name, list->type.string);
        exit(1);
      }
      if (!pthread_create(plugin_thread, NULL, *list->type.stats_func, &list->cfg)) {
        insert_active_thread(plugin_thread);
        thread_cnt++;
      }
      else {
          Log(LOG_WARNING, "WARN ( %s/%s ): Unable to initialize stats generation: %s\n", list->name, list->type.string, strerror(errno));
      }
    }
    list = list->next;
  }
  return thread_cnt;
}

int launch_core_threads()
{
  pthread_t *core_thread;
  int thread_cnt = 0;

  core_thread = malloc(sizeof(pthread_t));
  if (!core_thread) {
    Log(LOG_ERR, "ERROR ( %s/core/STATS ): unable to allocate pthread structure. Exiting ...\n", config.name);
    exit(1);
  }
  if (!pthread_create(core_thread, NULL, daemon_stats_func, met)) {
    insert_active_thread(core_thread);
    thread_cnt++;
  }
  else {
    Log(LOG_WARNING, "WARN ( %s/core/STATS ): Unable to initialize stats generation in daemon: %s\n", config.name, config.proc_name, strerror(errno));
  }

  return thread_cnt;
}

void plugin_buffers_generate_stats(struct metric *met_ptr)
{
  struct channels_list_entry *cle;
  struct metric *met_tmp, *fill_rate_met = NULL, *used_sz_met = NULL;
  int index;
  u_int64_t tot_sz = 0, curr_used_sz, used_sz = 0, last_plugin_off;

  //XXX: could eventually launch a separate thread if more metrics are needed
  for (index = 0; index < MAX_N_PLUGINS; index++) {
    cle = &channels_list[index];
    if (cle->plugin == NULL) continue;

    tot_sz += cle->rg.end - cle->rg.base;

    last_plugin_off = (cle->rg.ptr - cle->rg.base);
    curr_used_sz = cle->status->last_buf_off >= cle->status->last_plugin_off
              ? cle->status->last_buf_off - cle->status->last_plugin_off
              : ((u_int64_t)(cle->rg.end - cle->rg.base) - (cle->status->last_plugin_off - cle->status->last_buf_off));

    used_sz += curr_used_sz;

    met_tmp = met_ptr;
    while (met_tmp) {
      switch (met_tmp->type.id) {
        case METRICS_INT_PLUGIN_QUEUES_TOT_SZ:
          met_tmp->int_value += cle->rg.end - cle->rg.base;
          break;
        case METRICS_INT_PLUGIN_QUEUES_USED_SZ:
          used_sz_met = met_tmp;
          break;
        case METRICS_INT_PLUGIN_QUEUES_USED_CNT:
          met_tmp->int_value += (int)(curr_used_sz / cle->bufsize);
          break;
        case METRICS_INT_PLUGIN_QUEUES_FILL_RATE:
          fill_rate_met = met_tmp;
          break;
        default:
          break;
      }
    met_tmp = met_tmp->next;
    }
  }

  if (used_sz_met) {
    used_sz_met->int_value = used_sz;
  }
  if (fill_rate_met) {
    fill_rate_met->float_value = (tot_sz == 0 ? (float) 0 : (float) (100 * used_sz) / (float) tot_sz);
  }
}

int init_metrics(struct metric **met_ptr)
{
  int met_cnt = 0, met_idx;
  struct metric *met_tmp, *prev_met = NULL;
  struct plugins_list_entry *list = plugins_list;

  met_tmp = *met_ptr;
  while (list) {
    for(met_idx = 0; strcmp(_metrics_types_matrix[met_idx].label, ""); met_idx++) {

      if(list->cfg.metrics_what_to_count & _metrics_types_matrix[met_idx].id
          && (list->type.id == _metrics_types_matrix[met_idx].plugin_id)) {

        met_tmp->type = _metrics_types_matrix[met_idx];

        /* Prefix metric label with possible plugin name, truncated if needed
         * (NB: some characters (brackets, etc) are ignored by statsD, resulting in ugly names) */
        if (list->cfg.name) {
          char lbl[STATS_LABEL_LEN];

          memset(lbl, 0, STATS_LABEL_LEN);
          strncat(lbl, list->cfg.name, STATS_LABEL_LEN - 1);
          strcat(lbl, "-");
          strncat(lbl, met_tmp->type.label, STATS_LABEL_LEN - strlen(lbl) - 1);
          strncpy(met_tmp->type.label, lbl, STATS_LABEL_LEN - 1);
        }

        Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): Initializing metric \"%s\"\n", config.name, met_tmp->type.label);

        if (met_ptr == NULL) met_ptr = &met_tmp;

        if (prev_met) prev_met->next = met_tmp;

        prev_met = met_tmp;
        met_tmp = met_tmp->next;
        met_cnt++;
      }
    }
    list = list->next;
  }

  return met_cnt;
}

void reset_metrics_values(struct metric *m)
{
  struct metric *m_tmp;
  m_tmp = m;
  while (m_tmp) {
    if (m_tmp->type.statsd_fmt != STATSD_FMT_GAUGE) {
      switch(m_tmp->type.type) {
        case STATS_TYPE_INT:
          m_tmp->int_value = 0;
          break;
        case STATS_TYPE_LONGINT:
          m_tmp->long_value = 0;
          break;
        case STATS_TYPE_FLOAT:
          m_tmp->float_value = 0.0;
          break;
        case STATS_TYPE_STRING:
          m_tmp->string_value = "";
          break;
        default:
          break;
      }
    }
    m_tmp = m_tmp->next;
  }
}

int init_statsd_sock() {
  int sock, slen;
  int rc, ret, yes=1, no=0, buflen=0;
  struct host_addr addr;
#if defined ENABLE_IPV6
  struct sockaddr_storage server, dest_sockaddr;
#else
  struct sockaddr server, dest_sockaddr;
#endif

  memset(&server, 0, sizeof(server));
  memset(&dest_sockaddr, 0, sizeof(dest_sockaddr));

  /* If no IP address is supplied, let's set our default
     behaviour: IPv4 address, INADDR_ANY, port 2100 */
  if (!config.intstats_src_port) config.intstats_src_port = STATS_SRC_PORT_DEFAULT;
#if (defined ENABLE_IPV6)
  if (!config.intstats_src_ip) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&server;

    sa6->sin6_family = AF_INET6;
    sa6->sin6_port = htons(config.intstats_src_port);
    slen = sizeof(struct sockaddr_in6);
  }
#else
  if (!config.intstats_src_ip) {
    struct sockaddr_in *sa4 = (struct sockaddr_in *)&server;

    sa4->sin_family = AF_INET;
    sa4->sin_addr.s_addr = htonl(0);
    sa4->sin_port = htons(config.intstats_src_port);
    slen = sizeof(struct sockaddr_in);
  }
#endif
  else {
    trim_spaces(config.intstats_src_ip);
    ret = str_to_addr(config.intstats_src_ip, &addr);
    if (!ret) {
      Log(LOG_ERR, "ERROR ( %s/core/STATS ): 'intstats_src_ip' value is not valid. Exiting.\n", config.name);
      exit(1);
    }
    slen = addr_to_sa((struct sockaddr *)&server, &addr, config.intstats_src_port);
  }

  sock = socket(((struct sockaddr *)&server)->sa_family, SOCK_DGRAM, 0);

  if (sock < 0) {
    Log(LOG_ERR, "ERROR ( %s/core/STATS ): socket() failed. Terminating.\n", config.name);
    exit_all(1);
  }

  /* bind socket to port */
  rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/core/STATS ): setsockopt() failed for SO_REUSEADDR.\n", config.name);

#if (defined ENABLE_IPV6) && (defined IPV6_BINDV6ONLY)
  rc = setsockopt(sock, IPPROTO_IPV6, IPV6_BINDV6ONLY, (char *) &no, (socklen_t) sizeof(no));
  if (rc < 0) Log(LOG_ERR, "WARN ( %s/core/STATS ): setsockopt() failed for IPV6_BINDV6ONLY.\n", config.name);
#endif

  rc = bind(sock, (struct sockaddr *) &server, slen);
  if (rc < 0) {
    Log(LOG_ERR, "ERROR ( %s/core/STATS ): bind() to ip=%s port=%d/udp failed: %d.\n", config.name, config.intstats_src_ip, config.intstats_src_port, strerror(errno));
    exit(1);
  }
  return sock;
}

int send_data(struct metric *m, int sd) {
  int dest_addr_len;
  int ret, buflen=0;
  char *statsd_type;
  char data[SRVBUFLEN], databuf[SRVBUFLEN], val_str[SRVBUFLEN];
  struct host_addr dest_addr;
#if defined ENABLE_IPV6
  struct sockaddr_storage server, dest_sockaddr;
#else
  struct sockaddr server, dest_sockaddr;
#endif

  memset(databuf, 0, sizeof(databuf));

  switch(m->type.type) {
    case STATS_TYPE_INT:
      sprintf(val_str, "%d", m->int_value);
      break;
    case STATS_TYPE_LONGINT:
      sprintf(val_str, "%ld", m->long_value);
      break;
    case STATS_TYPE_FLOAT:
      sprintf(val_str, "%.2f", m->float_value);
      break;
    case STATS_TYPE_STRING:
      sprintf(val_str, "%s", m->string_value);
      break;
  }

  switch(m->type.statsd_fmt) {
    case STATSD_FMT_COUNTER:
      statsd_type = "c";
      break;
    case STATSD_FMT_GAUGE:
      statsd_type = "g";
      break;
    case STATSD_FMT_TIMING:
      statsd_type = "ms";
      break;
  }

  sprintf(data, "%s:%s|%s", m->type.label, val_str, statsd_type);

  if (!config.statsd_host) config.statsd_host = STATS_DST_HOST_DEFAULT;
  if (!config.statsd_port) config.statsd_port = STATS_DST_PORT_DEFAULT;

  ret = str_to_addr(config.statsd_host, &dest_addr);
  if (!ret) {
    Log(LOG_ERR, "ERROR ( %s/core/STATS ): statsd_host value is not a valid IPv4/IPv6 address. Terminating.\n", config.name);
    exit_all(1);
  }
  dest_addr_len = addr_to_sa((struct sockaddr *)&dest_sockaddr, &dest_addr, config.statsd_port);
  memcpy(databuf, data, strlen(data));
  buflen += strlen(data);
  databuf[buflen] = '\x4'; /* EOT */

  ret = sendto(sd, databuf, buflen, 0, &dest_sockaddr, dest_addr_len);
  if (ret == -1)
    Log(LOG_ERR, "ERROR ( %s/core/STATS ): Error sending message: %s\n", config.name, strerror(errno));
  else
    Log(LOG_DEBUG, "DEBUG ( %s/core/STATS ): sent data: %s\n", config.name, data);

  return ret;
}

void insert_active_thread(pthread_t *th)
{
  struct active_thread *at_tmp;

  if (!at) {
    at = malloc(sizeof(struct active_thread));
    memset(at, 0, sizeof(struct active_thread));
    at->thread = th;
  }
  else {
    at_tmp = malloc(sizeof(struct active_thread));
    memset(at_tmp, 0, sizeof(struct active_thread));
    at_tmp->thread = th;
    at_tmp->next = at;
    at = at_tmp;
  }
}

int delete_active_thread(pthread_t *th) {
  struct active_thread *at_tmp, *at_prev = NULL;
  int ret = 0;

  at_tmp = at;
  while (at_tmp) {
      if (at_tmp->thread == th) {
        if (!at_prev) {
          at = at_tmp->next;
        }
        else {
          at_prev->next = at_tmp->next;
        }
        free(th);
        free(at_tmp);
        ret++;
        break;
      }
      at_prev = at_tmp;
      at_tmp = at_tmp->next;
  }
  return ret;
}

void init_metrics_mem()
{
  int met_idx;
  struct metric *met_tmp, *prev_met = NULL;
  struct plugins_list_entry *list = plugins_list;

  while (list) {
    for(met_idx = 0; strcmp(_metrics_types_matrix[met_idx].label, ""); met_idx++) {

      if(list->cfg.metrics_what_to_count & _metrics_types_matrix[met_idx].id
          && (list->type.id == _metrics_types_matrix[met_idx].plugin_id)) {

        met_tmp = map_shared(0, sizeof(struct metric), PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
        if (met_tmp == MAP_FAILED) {
          Log(LOG_ERR, "ERROR ( %s/core/STATS ): unable to allocate metric structure. Exiting ...\n", config.name);
          exit(1);
        }

        if (prev_met) prev_met->next = met_tmp;
        else met = met_tmp;

        prev_met = met_tmp;
      }
    }
    list->cfg.met = met;
    list = list->next;
  }
}
