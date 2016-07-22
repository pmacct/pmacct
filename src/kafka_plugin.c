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

#define __KAFKA_PLUGIN_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "plugin_common.h"
#include "kafka_plugin.h"
#ifndef WITH_JANSSON
#error "--enable-kafka requires --enable-jansson"
#endif

/* Functions */
void kafka_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr)
{
  struct pkt_data *data;
  struct ports_table pt;
  unsigned char *pipebuf;
  struct pollfd pfd;
  struct insert_data idata;
  time_t t;
  int timeout, refresh_timeout, amqp_timeout, ret, num; 
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  struct plugins_list_entry *plugin_data = ((struct channels_list_entry *)ptr)->plugin;
  int datasize = ((struct channels_list_entry *)ptr)->datasize;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  pid_t core_pid = ((struct channels_list_entry *)ptr)->core_pid;
  struct networks_file_data nfd;

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;

  struct extra_primitives extras;
  struct primitives_ptrs prim_ptrs;
  char *dataptr;

#ifdef WITH_RABBITMQ
  struct p_amqp_host *amqp_host = &((struct channels_list_entry *)ptr)->amqp_host;
#endif

  memcpy(&config, cfgptr, sizeof(struct configuration));
  memcpy(&extras, &((struct channels_list_entry *)ptr)->extras, sizeof(struct extra_primitives));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "Kafka Plugin", config.name);

  P_set_signals();
  P_init_default_values();
  P_config_checks();
  pipebuf = (unsigned char *) pm_malloc(config.buffer_size);
  memset(pipebuf, 0, config.buffer_size);

  timeout = config.sql_refresh_time*1000;

  if ((config.sql_table && strchr(config.sql_table, '$')) && config.sql_multi_values) {
    Log(LOG_ERR, "ERROR ( %s/%s ): dynamic 'kafka_topic' is not compatible with 'kafka_multi_values'. Exiting.\n", config.name, config.type);
    exit_plugin(1);
  }

  if ((config.sql_table && strchr(config.sql_table, '$')) && config.amqp_routing_key_rr) {
    Log(LOG_ERR, "ERROR ( %s/%s ): dynamic 'kafka_topic' is not compatible with 'kafka_topic_rr'. Exiting.\n", config.name, config.type);
    exit_plugin(1);
  }

  /* setting function pointers */
  if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET))
    insert_func = P_sum_host_insert;
  else if (config.what_to_count & COUNT_SUM_PORT) insert_func = P_sum_port_insert;
  else if (config.what_to_count & COUNT_SUM_AS) insert_func = P_sum_as_insert;
#if defined (HAVE_L2)
  else if (config.what_to_count & COUNT_SUM_MAC) insert_func = P_sum_mac_insert;
#endif
  else insert_func = P_cache_insert;
  purge_func = kafka_cache_purge;

  memset(&nt, 0, sizeof(nt));
  memset(&nc, 0, sizeof(nc));
  memset(&pt, 0, sizeof(pt));

  load_networks(config.networks_file, &nt, &nc);
  set_net_funcs(&nt);

  if (config.ports_file) load_ports(config.ports_file, &pt);
  if (config.pkt_len_distrib_bins_str) load_pkt_len_distrib_bins();
  else {
    if (config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB) {
      Log(LOG_ERR, "ERROR ( %s/%s ): 'aggregate' contains pkt_len_distrib but no 'pkt_len_distrib_bins' defined. Exiting.\n", config.name, config.type);
      exit_plugin(1);
    }
  }
  
  memset(&idata, 0, sizeof(idata));
  memset(&prim_ptrs, 0, sizeof(prim_ptrs));
  set_primptrs_funcs(&extras);

  if (config.pipe_amqp) {
    plugin_pipe_amqp_compile_check();
#ifdef WITH_RABBITMQ
    pipe_fd = plugin_pipe_amqp_connect_to_consume(amqp_host, plugin_data);
    amqp_timeout = plugin_pipe_set_retry_timeout(&amqp_host->btimers, pipe_fd);
#endif
  }
  else setnonblocking(pipe_fd);

  idata.now = time(NULL);

  /* print_refresh time init: deadline */
  refresh_deadline = idata.now; 
  P_init_refresh_deadline(&refresh_deadline);

  if (config.sql_history) {
    basetime_init = P_init_historical_acct;
    basetime_eval = P_eval_historical_acct;
    basetime_cmp = P_cmp_historical_acct;

    (*basetime_init)(idata.now);
  }

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  /* plugin main loop */
  for(;;) {
    poll_again:
    status->wakeup = TRUE;
    calc_refresh_timeout(refresh_deadline, idata.now, &refresh_timeout);

    pfd.fd = pipe_fd;
    pfd.events = POLLIN;
    timeout = MIN(refresh_timeout, (amqp_timeout ? amqp_timeout : INT_MAX));
    ret = poll(&pfd, (pfd.fd == ERR ? 0 : 1), timeout);

    if (ret <= 0) {
      if (getppid() == 1) {
        Log(LOG_ERR, "ERROR ( %s/%s ): Core process *seems* gone. Exiting.\n", config.name, config.type);
        exit_plugin(1);
      }

      if (ret < 0) goto poll_again;
    }

    idata.now = time(NULL);

    if (config.sql_history) {
      while (idata.now > (basetime.tv_sec + timeslot)) {
	new_basetime.tv_sec = basetime.tv_sec;
        basetime.tv_sec += timeslot;
        if (config.sql_history == COUNT_MONTHLY)
          timeslot = calc_monthly_timeslot(basetime.tv_sec, config.sql_history_howmany, ADD);
      }
    }

#ifdef WITH_RABBITMQ
    if (config.pipe_amqp && pipe_fd == ERR) {
      if (timeout == amqp_timeout) {
        pipe_fd = plugin_pipe_amqp_connect_to_consume(amqp_host, plugin_data);
        amqp_timeout = plugin_pipe_set_retry_timeout(&amqp_host->btimers, pipe_fd);
      }
      else amqp_timeout = plugin_pipe_calc_retry_timeout_diff(&amqp_host->btimers, idata.now);
    }
#endif

    switch (ret) {
    case 0: /* timeout */
      P_cache_handle_flush_event(&pt);
      break;
    default: /* we received data */
      read_data:
      if (!config.pipe_amqp) {
        if (!pollagain) {
          seq++;
          seq %= MAX_SEQNUM;
          if (seq == 0) rg_err_count = FALSE;
        }
        else {
          if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0) 
	    exit_plugin(1); /* we exit silently; something happened at the write end */
        }

        if ((rg->ptr + bufsz) > rg->end) rg->ptr = rg->base;

        if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
          if (!pollagain) {
            pollagain = TRUE;
            goto poll_again;
          }
          else {
            rg_err_count++;
            if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
              Log(LOG_WARNING, "WARN ( %s/%s ): Missing data detected (plugin_buffer_size=%llu plugin_pipe_size=%llu).\n",
                        config.name, config.type, config.buffer_size, config.pipe_size);
              Log(LOG_WARNING, "WARN ( %s/%s ): Increase values or look for plugin_buffer_size, plugin_pipe_size in CONFIG-KEYS document.\n\n",
                        config.name, config.type);
            }
            seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
          }
        }

        pollagain = FALSE;
        memcpy(pipebuf, rg->ptr, bufsz);
        rg->ptr += bufsz;
      }
#ifdef WITH_RABBITMQ
      else {
        ret = p_amqp_consume_binary(amqp_host, pipebuf, config.buffer_size);
        if (ret) pipe_fd = ERR;

        seq = ((struct ch_buf_hdr *)pipebuf)->seq;
        amqp_timeout = plugin_pipe_set_retry_timeout(&amqp_host->btimers, pipe_fd);
      }
#endif

      /* lazy refresh time handling */ 
      if (idata.now > refresh_deadline) P_cache_handle_flush_event(&pt);

      data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));

      if (config.debug_internal_msg) 
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): buffer received cpid=%u seq=%u num_entries=%u\n",
                config.name, config.type, core_pid, seq, ((struct ch_buf_hdr *)pipebuf)->num);

      if (!config.pipe_check_core_pid || ((struct ch_buf_hdr *)pipebuf)->core_pid == core_pid) {
      while (((struct ch_buf_hdr *)pipebuf)->num > 0) {
        for (num = 0; primptrs_funcs[num]; num++)
          (*primptrs_funcs[num])((u_char *)data, &extras, &prim_ptrs);

	for (num = 0; net_funcs[num]; num++)
	  (*net_funcs[num])(&nt, &nc, &data->primitives, prim_ptrs.pbgp, &nfd);

	if (config.ports_file) {
          if (!pt.table[data->primitives.src_port]) data->primitives.src_port = 0;
          if (!pt.table[data->primitives.dst_port]) data->primitives.dst_port = 0;
        }

        if (config.pkt_len_distrib_bins_str &&
            config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB)
          evaluate_pkt_len_distrib(data);

        prim_ptrs.data = data;
        (*insert_func)(&prim_ptrs, &idata);

	((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) {
          dataptr = (unsigned char *) data;
          if (!prim_ptrs.vlen_next_off) dataptr += datasize;
          else dataptr += prim_ptrs.vlen_next_off;
          data = (struct pkt_data *) dataptr;
	}
      }
      }

      if (!config.pipe_amqp) goto read_data;
    }
  }
}

void kafka_cache_purge(struct chained_cache *queue[], int index)
{
  struct pkt_primitives *data = NULL;
  struct pkt_bgp_primitives *pbgp = NULL;
  struct pkt_nat_primitives *pnat = NULL;
  struct pkt_mpls_primitives *pmpls = NULL;
  char *pcust = NULL;
  struct pkt_vlen_hdr_primitives *pvlen = NULL;
  struct pkt_bgp_primitives empty_pbgp;
  struct pkt_nat_primitives empty_pnat;
  struct pkt_mpls_primitives empty_pmpls;
  char *empty_pcust = NULL;
  char src_mac[18], dst_mac[18], src_host[INET6_ADDRSTRLEN], dst_host[INET6_ADDRSTRLEN], ip_address[INET6_ADDRSTRLEN];
  char rd_str[SRVBUFLEN], misc_str[SRVBUFLEN], dyn_kafka_topic[SRVBUFLEN], *orig_kafka_topic = NULL;
  int i, j, stop, batch_idx, is_topic_dyn = FALSE, qn = 0, ret, saved_index = index;
  int mv_num = 0, mv_num_save = 0;
  time_t start, duration;
  pid_t writer_pid = getpid();

#ifdef WITH_JANSSON
  json_t *array = json_array();
#endif

  p_kafka_init_host(&kafkap_kafka_host);

  /* setting some defaults */
  if (!config.sql_host) config.sql_host = default_kafka_broker_host;
  if (!config.kafka_broker_port) config.kafka_broker_port = default_kafka_broker_port;

  if (!config.sql_table) config.sql_table = default_kafka_topic;
  else {
    if (strchr(config.sql_table, '$')) {
      is_topic_dyn = TRUE;
      orig_kafka_topic = config.sql_table;
      config.sql_table = dyn_kafka_topic;
    }
  }
  if (config.amqp_routing_key_rr) {
    orig_kafka_topic = config.sql_table;
    config.sql_table = dyn_kafka_topic;
  }

  p_kafka_init_topic_rr(&kafkap_kafka_host);
  p_kafka_set_topic_rr(&kafkap_kafka_host, config.amqp_routing_key_rr);

  empty_pcust = malloc(config.cpptrs.len);
  if (!empty_pcust) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() empty_pcust. Exiting.\n", config.name, config.type);
    exit_plugin(1);
  }

  memset(&empty_pbgp, 0, sizeof(struct pkt_bgp_primitives));
  memset(&empty_pnat, 0, sizeof(struct pkt_nat_primitives));
  memset(&empty_pmpls, 0, sizeof(struct pkt_mpls_primitives));
  memset(empty_pcust, 0, config.cpptrs.len);

  p_kafka_connect_to_produce(&kafkap_kafka_host);
  p_kafka_set_broker(&kafkap_kafka_host, config.sql_host, config.kafka_broker_port);
  p_kafka_set_topic(&kafkap_kafka_host, config.sql_table);
  p_kafka_set_partition(&kafkap_kafka_host, config.kafka_partition);
  p_kafka_set_key(&kafkap_kafka_host, config.kafka_partition_key, config.kafka_partition_keylen);
  p_kafka_set_content_type(&kafkap_kafka_host, PM_KAFKA_CNT_TYPE_STR);

  for (j = 0, stop = 0; (!stop) && P_preprocess_funcs[j]; j++)
    stop = P_preprocess_funcs[j](queue, &index, j);

  Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - START (PID: %u) ***\n", config.name, config.type, writer_pid);
  start = time(NULL);

  if (config.print_markers) {
    void *json_obj;
    char *json_str;

    json_obj = compose_purge_init_json(writer_pid);
    if (json_obj) json_str = compose_json_str(json_obj);
    if (json_str) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, json_str);
      ret = p_kafka_produce_data(&kafkap_kafka_host, json_str, strlen(json_str));

      free(json_str);
      json_str = NULL;
    }
  }

  for (j = 0; j < index; j++) {
    void *json_obj;
    char *json_str;

    if (queue[j]->valid != PRINT_CACHE_COMMITTED) continue;

    data = &queue[j]->primitives;
    if (queue[j]->pbgp) pbgp = queue[j]->pbgp;
    else pbgp = &empty_pbgp;

    if (queue[j]->pnat) pnat = queue[j]->pnat;
    else pnat = &empty_pnat;

    if (queue[j]->pmpls) pmpls = queue[j]->pmpls;
    else pmpls = &empty_pmpls;

    if (queue[j]->pcust) pcust = queue[j]->pcust;
    else pcust = empty_pcust;

    if (queue[j]->pvlen) pvlen = queue[j]->pvlen;
    else pvlen = NULL;

    if (queue[j]->valid == PRINT_CACHE_FREE) continue;

    json_obj = compose_json(config.what_to_count, config.what_to_count_2, queue[j]->flow_type,
                         &queue[j]->primitives, pbgp, pnat, pmpls, pcust, pvlen, queue[j]->bytes_counter,
			 queue[j]->packet_counter, queue[j]->flow_counter, queue[j]->tcp_flags,
			 &queue[j]->basetime, queue[j]->stitch);

    json_str = compose_json_str(json_obj);

#ifdef WITH_JANSSON
    if (json_str && config.sql_multi_values) {
      json_t *elem = NULL;
      char *tmp_str = json_str;
      int do_free = FALSE;

      if (json_array_size(array) >= config.sql_multi_values) {
	json_str = json_dumps(array, 0);
	json_array_clear(array);
        mv_num_save = mv_num;
        mv_num = 0;
      }
      else do_free = TRUE;

      elem = json_loads(tmp_str, 0, NULL);
      json_array_append_new(array, elem);
      mv_num++;

      if (do_free) {
        free(json_str);
        json_str = NULL;
      }
    }
#endif

    if (json_str) {
      if (is_topic_dyn) {
	P_handle_table_dyn_strings(dyn_kafka_topic, SRVBUFLEN, orig_kafka_topic, queue[j]);
	p_kafka_set_topic(&kafkap_kafka_host, dyn_kafka_topic);
      }

      if (config.amqp_routing_key_rr) {
        P_handle_table_dyn_rr(dyn_kafka_topic, SRVBUFLEN, orig_kafka_topic, &kafkap_kafka_host.topic_rr);
	p_kafka_set_topic(&kafkap_kafka_host, dyn_kafka_topic);
      }

      Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, json_str);
      ret = p_kafka_produce_data(&kafkap_kafka_host, json_str, strlen(json_str));

      free(json_str);
      json_str = NULL;

      if (!ret) {
	if (!config.sql_multi_values) qn++;
	else qn += mv_num_save;
      }
      else break;
    }
  }

#ifdef WITH_JANSSON
  if (config.sql_multi_values && json_array_size(array)) {
    char *json_str;

    json_str = json_dumps(array, 0);
    json_array_clear(array);
    json_decref(array);

    if (json_str) {
      /* no handling of dyn routing keys here: not compatible */
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, json_str);
      ret = p_kafka_produce_data(&kafkap_kafka_host, json_str, strlen(json_str));

      free(json_str);
      json_str = NULL;

      if (!ret) qn += mv_num;
    }
  }
#endif

  duration = time(NULL)-start;

  if (config.print_markers) {
    void *json_obj;
    char *json_str;

    json_obj = compose_purge_close_json(writer_pid, qn, saved_index, duration);
    if (json_obj) json_str = compose_json_str(json_obj);
    if (json_str) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, json_str);
      ret = p_kafka_produce_data(&kafkap_kafka_host, json_str, strlen(json_str));

      free(json_str);
      json_str = NULL;
    }
  }

  p_kafka_close(&kafkap_kafka_host, FALSE);

  Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - END (PID: %u, QN: %u/%u, ET: %u) ***\n",
		config.name, config.type, writer_pid, qn, saved_index, duration);

  if (config.sql_trigger_exec) P_trigger_exec(config.sql_trigger_exec); 

  if (empty_pcust) free(empty_pcust);
}
