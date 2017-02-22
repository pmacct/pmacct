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

#define __AMQP_PLUGIN_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "plugin_common.h"
#include "plugin_cmn_json.h"
#include "plugin_cmn_avro.h"
#include "amqp_plugin.h"
#ifndef WITH_JANSSON
#error "--enable-rabbitmq requires --enable-jansson"
#endif

/* Functions */
void amqp_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct pkt_data *data;
  struct ports_table pt;
  unsigned char *pipebuf;
  struct pollfd pfd;
  struct insert_data idata;
  time_t t, avro_schema_deadline = 0;
  int timeout, refresh_timeout, amqp_timeout = 0, avro_schema_timeout = 0;
  int ret, num; 
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

#ifdef WITH_AVRO
  char *avro_acct_schema_str;
#endif

  struct p_amqp_host *amqp_host = &((struct channels_list_entry *)ptr)->amqp_host;

  memcpy(&config, cfgptr, sizeof(struct configuration));
  memcpy(&extras, &((struct channels_list_entry *)ptr)->extras, sizeof(struct extra_primitives));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "RabbitMQ/AMQP Plugin", config.name);

  P_set_signals();
  P_init_default_values();
  P_config_checks();
  pipebuf = (unsigned char *) pm_malloc(config.buffer_size);
  memset(pipebuf, 0, config.buffer_size);

  timeout = config.sql_refresh_time*1000;

  if (!config.sql_user) config.sql_user = rabbitmq_user;
  if (!config.sql_passwd) config.sql_passwd = rabbitmq_pwd;
  if (!config.message_broker_output) config.message_broker_output = PRINT_OUTPUT_JSON;

  
  if (config.message_broker_output & PRINT_OUTPUT_JSON) {
    compose_json(config.what_to_count, config.what_to_count_2);
  }
  else if (config.message_broker_output & PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
    avro_acct_schema = build_avro_schema(config.what_to_count, config.what_to_count_2);
    avro_schema_add_writer_id(avro_acct_schema);

    if (config.avro_schema_output_file) write_avro_schema_to_file(config.avro_schema_output_file, avro_acct_schema);

    if (config.amqp_avro_schema_routing_key) {
      if (!config.amqp_avro_schema_refresh_time)
        config.amqp_avro_schema_refresh_time = DEFAULT_AVRO_SCHEMA_REFRESH_TIME;

      avro_schema_deadline = time(NULL);
      P_init_refresh_deadline(&avro_schema_deadline, config.amqp_avro_schema_refresh_time, 0, "m");
      avro_acct_schema_str = compose_avro_purge_schema(avro_acct_schema, config.name);
    }
    else {
      config.amqp_avro_schema_refresh_time = 0;
      avro_schema_deadline = 0;
      avro_schema_timeout = 0;
      avro_acct_schema_str = NULL;
    }
#endif
  }

  if ((config.sql_table && strchr(config.sql_table, '$')) && config.sql_multi_values) {
    Log(LOG_ERR, "ERROR ( %s/%s ): dynamic 'amqp_routing_key' is not compatible with 'amqp_multi_values'. Exiting.\n", config.name, config.type);
    exit_plugin(1);
  }

  if ((config.sql_table && strchr(config.sql_table, '$')) && config.amqp_routing_key_rr) {
    Log(LOG_ERR, "ERROR ( %s/%s ): dynamic 'amqp_routing_key' is not compatible with 'amqp_routing_key_rr'. Exiting.\n", config.name, config.type);
    exit_plugin(1);
  }

  p_amqp_init_host(&amqpp_amqp_host);
  p_amqp_set_user(&amqpp_amqp_host, config.sql_user);
  p_amqp_set_passwd(&amqpp_amqp_host, config.sql_passwd);

  /* setting function pointers */
  if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET))
    insert_func = P_sum_host_insert;
  else if (config.what_to_count & COUNT_SUM_PORT) insert_func = P_sum_port_insert;
  else if (config.what_to_count & COUNT_SUM_AS) insert_func = P_sum_as_insert;
#if defined (HAVE_L2)
  else if (config.what_to_count & COUNT_SUM_MAC) insert_func = P_sum_mac_insert;
#endif
  else insert_func = P_cache_insert;
  purge_func = amqp_cache_purge;

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
    pipe_fd = plugin_pipe_amqp_connect_to_consume(amqp_host, plugin_data);
    amqp_timeout = plugin_pipe_set_retry_timeout(&amqp_host->btimers, pipe_fd);
  }
  else setnonblocking(pipe_fd);

  idata.now = time(NULL);

  /* print_refresh time init: deadline */
  refresh_deadline = idata.now; 
  P_init_refresh_deadline(&refresh_deadline, config.sql_refresh_time, config.sql_startup_delay, config.sql_history_roundoff);

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
    if (config.amqp_avro_schema_routing_key) calc_refresh_timeout(avro_schema_deadline, idata.now, &avro_schema_timeout);

    pfd.fd = pipe_fd;
    pfd.events = POLLIN;
    timeout = MIN(refresh_timeout, (amqp_timeout ? amqp_timeout : INT_MAX));
    timeout = MIN(timeout, (avro_schema_timeout ? avro_schema_timeout : INT_MAX));
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

    if (config.pipe_amqp && pipe_fd == ERR) {
      if (timeout == amqp_timeout) {
        pipe_fd = plugin_pipe_amqp_connect_to_consume(amqp_host, plugin_data);
        amqp_timeout = plugin_pipe_set_retry_timeout(&amqp_host->btimers, pipe_fd);
      }
      else amqp_timeout = plugin_pipe_calc_retry_timeout_diff(&amqp_host->btimers, idata.now);
    }

#ifdef WITH_AVRO
    if (idata.now > avro_schema_deadline) {
      amqp_avro_schema_purge(avro_acct_schema_str);
      avro_schema_deadline += config.amqp_avro_schema_refresh_time;
    }
#endif

    switch (ret) {
    case 0: /* timeout */
      if (idata.now > refresh_deadline) P_cache_handle_flush_event(&pt);
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

	    rg->ptr = (rg->base + status->last_buf_off);
            seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
          }
        }

        pollagain = FALSE;
        memcpy(pipebuf, rg->ptr, bufsz);
        status->last_plugin_off = (rg->ptr - rg->base);
        rg->ptr += bufsz;
      }
      else {
        ret = p_amqp_consume_binary(amqp_host, pipebuf, config.buffer_size);
        if (ret) pipe_fd = ERR;

        seq = ((struct ch_buf_hdr *)pipebuf)->seq;
        amqp_timeout = plugin_pipe_set_retry_timeout(&amqp_host->btimers, pipe_fd);
      }

      /* lazy refresh time handling */ 
      if (idata.now > refresh_deadline) P_cache_handle_flush_event(&pt);

      data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));

      if (config.debug_internal_msg)
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): buffer received cpid=%u len=%llu seq=%u num_entries=%u\n",
                config.name, config.type, core_pid, ((struct ch_buf_hdr *)pipebuf)->len,
                seq, ((struct ch_buf_hdr *)pipebuf)->num);

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

void amqp_cache_purge(struct chained_cache *queue[], int index)
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
  char rd_str[SRVBUFLEN], misc_str[SRVBUFLEN], dyn_amqp_routing_key[SRVBUFLEN], *orig_amqp_routing_key = NULL;
  int i, j, stop, batch_idx, is_routing_key_dyn = FALSE, qn = 0, ret, saved_index = index;
  int mv_num = 0, mv_num_save = 0;
  time_t start, duration;
  pid_t writer_pid = getpid();

  char *json_buf = NULL;
  int json_buf_off = 0;

#ifdef WITH_AVRO
  avro_writer_t avro_writer;
  char *avro_buf = NULL;
  int avro_buffer_full = FALSE;
#endif

  /* setting some defaults */
  if (!config.sql_host) config.sql_host = default_amqp_host;
  if (!config.sql_db) config.sql_db = default_amqp_exchange;
  if (!config.amqp_exchange_type) config.amqp_exchange_type = default_amqp_exchange_type;
  if (!config.amqp_vhost) config.amqp_vhost = default_amqp_vhost;

  if (!config.sql_table) config.sql_table = default_amqp_routing_key;
  else {
    if (strchr(config.sql_table, '$')) {
      is_routing_key_dyn = TRUE;
      orig_amqp_routing_key = config.sql_table;
      config.sql_table = dyn_amqp_routing_key;
    }
  }
  if (config.amqp_routing_key_rr) {
    orig_amqp_routing_key = config.sql_table;
    config.sql_table = dyn_amqp_routing_key;
  }

  p_amqp_set_exchange(&amqpp_amqp_host, config.sql_db);
  p_amqp_set_routing_key(&amqpp_amqp_host, config.sql_table);
  p_amqp_set_exchange_type(&amqpp_amqp_host, config.amqp_exchange_type);
  p_amqp_set_host(&amqpp_amqp_host, config.sql_host);
  p_amqp_set_vhost(&amqpp_amqp_host, config.amqp_vhost);
  p_amqp_set_persistent_msg(&amqpp_amqp_host, config.amqp_persistent_msg);
  p_amqp_set_frame_max(&amqpp_amqp_host, config.amqp_frame_max);

  if (config.message_broker_output & PRINT_OUTPUT_JSON) p_amqp_set_content_type_json(&amqpp_amqp_host);
  else if (config.message_broker_output & PRINT_OUTPUT_AVRO) p_amqp_set_content_type_binary(&amqpp_amqp_host);
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unsupported amqp_output value specified. Exiting.\n", config.name, config.type);
    exit_plugin(1);
  }

  p_amqp_init_routing_key_rr(&amqpp_amqp_host);
  p_amqp_set_routing_key_rr(&amqpp_amqp_host, config.amqp_routing_key_rr);

  empty_pcust = malloc(config.cpptrs.len);
  if (!empty_pcust) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() empty_pcust. Exiting.\n", config.name, config.type);
    exit_plugin(1);
  }

  memset(&empty_pbgp, 0, sizeof(struct pkt_bgp_primitives));
  memset(&empty_pnat, 0, sizeof(struct pkt_nat_primitives));
  memset(&empty_pmpls, 0, sizeof(struct pkt_mpls_primitives));
  memset(empty_pcust, 0, config.cpptrs.len);

  ret = p_amqp_connect_to_publish(&amqpp_amqp_host);
  if (ret) return;

  for (j = 0, stop = 0; (!stop) && P_preprocess_funcs[j]; j++)
    stop = P_preprocess_funcs[j](queue, &index, j);

  Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - START (PID: %u) ***\n", config.name, config.type, writer_pid);
  start = time(NULL);

  if (config.print_markers) {
    if (config.message_broker_output & PRINT_OUTPUT_JSON || config.message_broker_output & PRINT_OUTPUT_AVRO) {
      void *json_obj;
      char *json_str;

      json_obj = compose_purge_init_json(config.name, writer_pid);

      if (json_obj) json_str = compose_json_str(json_obj);
      if (json_str) {
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, json_str);
        ret = p_amqp_publish_string(&amqpp_amqp_host, json_str);

        free(json_str);
        json_str = NULL;
      }
    }
  }

  if (config.message_broker_output & PRINT_OUTPUT_JSON) {
    if (config.sql_multi_values) {
      json_buf = malloc(config.sql_multi_values);

      if (!json_buf) {
	Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (json_buf). Exiting ..\n", config.name, config.type);
	exit_plugin(1);
      }
      else memset(json_buf, 0, config.sql_multi_values);
    }
  }
  else if (config.message_broker_output & PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
    if (!config.avro_buffer_size) config.avro_buffer_size = LARGEBUFLEN;

    avro_buf = malloc(config.avro_buffer_size);

    if (!avro_buf) {
      Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (avro_buf). Exiting ..\n", config.name, config.type);
      exit_plugin(1);
    }

    avro_writer = avro_writer_memory(avro_buf, config.avro_buffer_size);
#endif
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

    if (config.message_broker_output & PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
      json_t *json_obj = json_object();
      int idx;

      for (idx = 0; idx < N_PRIMITIVES && cjhandler[idx]; idx++) cjhandler[idx](json_obj, queue[j]);
      add_writer_name_and_pid_json(json_obj, config.name, writer_pid);

      json_str = compose_json_str(json_obj);
#endif
    }
    else if (config.message_broker_output & PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
      avro_value_iface_t *avro_iface = avro_generic_class_from_schema(avro_acct_schema);
      avro_value_t avro_value = compose_avro(config.what_to_count, config.what_to_count_2, queue[j]->flow_type,
                           &queue[j]->primitives, pbgp, pnat, pmpls, pcust, pvlen, queue[j]->bytes_counter,
                           queue[j]->packet_counter, queue[j]->flow_counter, queue[j]->tcp_flags,
                           &queue[j]->basetime, queue[j]->stitch, avro_iface);
      size_t avro_value_size;

      add_writer_name_and_pid_avro(avro_value, config.name, writer_pid);
      avro_value_sizeof(&avro_value, &avro_value_size);

      if (avro_value_size > config.avro_buffer_size) {
        Log(LOG_ERR, "ERROR ( %s/%s ): AVRO; insufficient buffer size (avro_buffer_size=%u)\n",
            config.name, config.type, config.avro_buffer_size);
        Log(LOG_ERR, "ERROR ( %s/%s ): AVRO: increase value or look for avro_buffer_size in CONFIG-KEYS document.\n\n",
            config.name, config.type);
        exit_plugin(1);
      }
      else if (avro_value_size >= (config.avro_buffer_size - avro_writer_tell(avro_writer))) {
        avro_buffer_full = TRUE;
        j--;
      }
      else if (avro_value_write(avro_writer, &avro_value)) {
        Log(LOG_ERR, "ERROR ( %s/%s ): ARVO: unable to write value: %s\n", config.name, config.type, avro_strerror());
        exit_plugin(1);
      }
      else {
        mv_num++;
      }

      avro_value_decref(&avro_value);
      avro_value_iface_decref(avro_iface);
#else
      if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): compose_avro(): AVRO object not created due to missing --enable-avro\n", config.name, config.type);
#endif
    }

    if (config.message_broker_output & PRINT_OUTPUT_JSON) {
      char *tmp_str = NULL;

      if (json_str && config.sql_multi_values) {
	int json_strlen = (strlen(json_str) ? (strlen(json_str) + 1) : 0);

	if (json_strlen >= (config.sql_multi_values - json_buf_off)) {
	  if (json_strlen >= config.sql_multi_values) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): kafka_multi_values not large enough to store JSON elements. Exiting ..\n", config.name, config.type);
	    exit(1);
	  }

	  tmp_str = json_str;
	  json_str = json_buf;
        }
        else {
	  strcat(json_buf, json_str);
	  mv_num++;

	  string_add_newline(json_buf);
	  json_buf_off = strlen(json_buf);

	  free(json_str);
	  json_str = NULL;
        }
      }

      if (json_str) {
        if (is_routing_key_dyn) {
          P_handle_table_dyn_strings(dyn_amqp_routing_key, SRVBUFLEN, orig_amqp_routing_key, queue[j]);
          p_amqp_set_routing_key(&amqpp_amqp_host, dyn_amqp_routing_key);
        }

        if (config.amqp_routing_key_rr) {
          P_handle_table_dyn_rr(dyn_amqp_routing_key, SRVBUFLEN, orig_amqp_routing_key, &amqpp_amqp_host.rk_rr);
          p_amqp_set_routing_key(&amqpp_amqp_host, dyn_amqp_routing_key);
        }

        Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, json_str);
        ret = p_amqp_publish_string(&amqpp_amqp_host, json_str);

	if (config.sql_multi_values) {
	  json_str = tmp_str;
	  strcpy(json_buf, json_str);

	  mv_num_save = mv_num;
	  mv_num = 1;

	  string_add_newline(json_buf);
	  json_buf_off = strlen(json_buf);
        }

        free(json_str);
        json_str = NULL;

        if (!ret) {
          if (!config.sql_multi_values) qn++;
          else qn += mv_num_save;
        }
        else break;
      }
    }
    else if (config.message_broker_output & PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
      if (!config.sql_multi_values || (mv_num >= config.sql_multi_values) || avro_buffer_full) {
        if (is_routing_key_dyn) {
          P_handle_table_dyn_strings(dyn_amqp_routing_key, SRVBUFLEN, orig_amqp_routing_key, queue[j]);
          p_amqp_set_routing_key(&amqpp_amqp_host, dyn_amqp_routing_key);
        }

        if (config.amqp_routing_key_rr) {
          P_handle_table_dyn_rr(dyn_amqp_routing_key, SRVBUFLEN, orig_amqp_routing_key, &amqpp_amqp_host.rk_rr);
          p_amqp_set_routing_key(&amqpp_amqp_host, dyn_amqp_routing_key);
        }

        ret = p_amqp_publish_binary(&amqpp_amqp_host, avro_buf, avro_writer_tell(avro_writer));
        avro_writer_reset(avro_writer);
        avro_buffer_full = FALSE;
        mv_num_save = mv_num;
        mv_num = 0;

        if (!ret) qn += mv_num_save;
        else break;
      }
#endif
    }
  }

  if (config.sql_multi_values) {
    if (config.message_broker_output & PRINT_OUTPUT_JSON) {
      if (json_buf && json_buf_off) {
	/* no handling of dyn routing keys here: not compatible */
	Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, json_buf);
	ret = p_kafka_produce_data(&kafkap_kafka_host, json_buf, strlen(json_buf));

	if (!ret) qn += mv_num;
      }
    }
    else if (config.message_broker_output & PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
      if (avro_writer_tell(avro_writer)) {
        ret = p_amqp_publish_binary(&amqpp_amqp_host, avro_buf, avro_writer_tell(avro_writer));
        avro_writer_free(avro_writer);

        if (!ret) qn += mv_num;
      }
#endif
    }
  }

  duration = time(NULL)-start;

  if (config.print_markers) {
    if (config.message_broker_output & PRINT_OUTPUT_JSON || config.message_broker_output & PRINT_OUTPUT_AVRO) {
      void *json_obj;
      char *json_str;

      json_obj = compose_purge_close_json(config.name, writer_pid, qn, saved_index, duration);

      if (json_obj) json_str = compose_json_str(json_obj);
      if (json_str) {
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): %s\n\n", config.name, config.type, json_str);
        ret = p_amqp_publish_string(&amqpp_amqp_host, json_str);

        free(json_str);
        json_str = NULL;
      }
    }
  }

  p_amqp_close(&amqpp_amqp_host, FALSE);

  Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - END (PID: %u, QN: %u/%u, ET: %u) ***\n",
		config.name, config.type, writer_pid, qn, saved_index, duration);

  if (config.sql_trigger_exec) P_trigger_exec(config.sql_trigger_exec); 

  if (empty_pcust) free(empty_pcust);

  if (json_buf) free(json_buf);

#ifdef WITH_AVRO
  if (avro_buf) free(avro_buf);
#endif
}

#ifdef WITH_AVRO
void amqp_avro_schema_purge(char *avro_schema_str)
{
  struct p_amqp_host amqp_avro_schema_host;
  int ret;

  if (!avro_schema_str || !config.amqp_avro_schema_routing_key) return;

  /* setting some defaults */
  if (!config.sql_host) config.sql_host = default_amqp_host;
  if (!config.sql_db) config.sql_db = default_amqp_exchange;
  if (!config.amqp_exchange_type) config.amqp_exchange_type = default_amqp_exchange_type;
  if (!config.amqp_vhost) config.amqp_vhost = default_amqp_vhost;

  p_amqp_init_host(&amqp_avro_schema_host);
  p_amqp_set_user(&amqp_avro_schema_host, config.sql_user);
  p_amqp_set_passwd(&amqp_avro_schema_host, config.sql_passwd);
  p_amqp_set_exchange(&amqp_avro_schema_host, config.sql_db);
  p_amqp_set_routing_key(&amqp_avro_schema_host, config.amqp_avro_schema_routing_key);
  p_amqp_set_exchange_type(&amqp_avro_schema_host, config.amqp_exchange_type);
  p_amqp_set_host(&amqp_avro_schema_host, config.sql_host);
  p_amqp_set_vhost(&amqp_avro_schema_host, config.amqp_vhost);
  p_amqp_set_persistent_msg(&amqp_avro_schema_host, config.amqp_persistent_msg);
  p_amqp_set_frame_max(&amqp_avro_schema_host, config.amqp_frame_max);
  p_amqp_set_content_type_json(&amqp_avro_schema_host);

  ret = p_amqp_connect_to_publish(&amqp_avro_schema_host);
  if (ret) return;

  ret = p_amqp_publish_string(&amqp_avro_schema_host, avro_schema_str);

  p_amqp_close(&amqp_avro_schema_host, FALSE);
}
#endif
