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

#define __PRINT_PLUGIN_C

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "plugin_common.h"
#include "plugin_cmn_json.h"
#include "plugin_cmn_avro.h"
#include "print_plugin.h"
#include "ip_flow.h"
#include "classifier.h"
#include "crc32.h"
#include "bgp/bgp.h"

/* Functions */
void print_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct pkt_data *data;
  struct ports_table pt;
  unsigned char *pipebuf;
  struct pollfd pfd;
  struct insert_data idata;
  time_t t;
  int timeout, refresh_timeout, amqp_timeout, kafka_timeout, ret, num, is_event;
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  struct plugins_list_entry *plugin_data = ((struct channels_list_entry *)ptr)->plugin;
  int datasize = ((struct channels_list_entry *)ptr)->datasize;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  pid_t core_pid = ((struct channels_list_entry *)ptr)->core_pid;
  struct networks_file_data nfd;
  char default_separator[] = ",";

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;

  struct extra_primitives extras;
  struct primitives_ptrs prim_ptrs;
  char *dataptr;
  void *kafka_msg;

#ifdef WITH_RABBITMQ
  struct p_amqp_host *amqp_host = &((struct channels_list_entry *)ptr)->amqp_host;
#endif

#ifdef WITH_KAFKA
  struct p_kafka_host *kafka_host = &((struct channels_list_entry *)ptr)->kafka_host;
#endif

  memcpy(&config, cfgptr, sizeof(struct configuration));
  memcpy(&extras, &((struct channels_list_entry *)ptr)->extras, sizeof(struct extra_primitives));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "Print Plugin", config.name);

  P_set_signals();
  P_init_default_values();
  P_config_checks();
  pipebuf = (unsigned char *) pm_malloc(config.buffer_size);
  memset(pipebuf, 0, config.buffer_size);

  is_event = FALSE;
  if (!config.print_output)
    config.print_output = PRINT_OUTPUT_FORMATTED;
  else if (config.print_output & PRINT_OUTPUT_EVENT)
    is_event = TRUE;

  refresh_timeout = config.sql_refresh_time*1000;

  if (config.print_output & PRINT_OUTPUT_JSON) {
    compose_json(config.what_to_count, config.what_to_count_2);
  }
  else if (config.print_output & PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
    avro_acct_schema = build_avro_schema(config.what_to_count, config.what_to_count_2);
    if (config.avro_schema_output_file) write_avro_schema_to_file(config.avro_schema_output_file, avro_acct_schema);
#endif
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
  purge_func = P_cache_purge;

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
  else if (config.pipe_kafka) {
    plugin_pipe_kafka_compile_check();
#ifdef WITH_KAFKA
    pipe_fd = plugin_pipe_kafka_connect_to_consume(kafka_host, plugin_data);
    kafka_timeout = plugin_pipe_set_retry_timeout(&kafka_host->btimers, pipe_fd);
#endif
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

  if (!config.print_output_separator) config.print_output_separator = default_separator;

  if (extras.off_pkt_vlen_hdr_primitives && config.print_output & PRINT_OUTPUT_FORMATTED) {
    Log(LOG_ERR, "ERROR ( %s/%s ): variable-length primitives, ie. label as_path std_comm etc., are not supported in print plugin with formatted output.\n", config.name, config.type);
    Log(LOG_ERR, "ERROR ( %s/%s ): Please switch to one of the other supported output formats (ie. csv, json, avro). Exiting ..\n", config.name, config.type);
    exit_plugin(1);
  }

  print_output_stdout_header = TRUE;
  if (!config.sql_table && !config.print_output_lock_file)
    Log(LOG_WARNING, "WARN ( %s/%s ): no print_output_file and no print_output_lock_file defined.\n", config.name, config.type);

  if (config.sql_table) {
    if (strchr(config.sql_table, '%') || strchr(config.sql_table, '$'))
      dyn_table = TRUE;
    else {
      dyn_table = FALSE;
    
      if (config.print_latest_file && (strchr(config.print_latest_file, '%') || strchr(config.print_latest_file, '$'))) {
        Log(LOG_WARNING, "WARN ( %s/%s ): Disabling print_latest_file due to non-dynamic print_output_file.\n", config.name, config.type); 
        config.print_latest_file = NULL;
      }
    }
  }

  /* plugin main loop */
  for(;;) {
    poll_again:
    status->wakeup = TRUE;
    calc_refresh_timeout(refresh_deadline, idata.now, &refresh_timeout);
    
    pfd.fd = pipe_fd;
    pfd.events = POLLIN;

    if (config.pipe_homegrown || config.pipe_amqp) {
      timeout = MIN(refresh_timeout, (amqp_timeout ? amqp_timeout : INT_MAX));
      ret = poll(&pfd, (pfd.fd == ERR ? 0 : 1), timeout);
    }
#ifdef WITH_KAFKA
    else if (config.pipe_kafka) {
      timeout = MIN(refresh_timeout, (kafka_timeout ? kafka_timeout : INT_MAX)); 
      ret = p_kafka_consume_poller(kafka_host, &kafka_msg, timeout);
    }
#endif

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

#ifdef WITH_KAFKA
    if (config.pipe_kafka && pipe_fd == ERR) {
      if (timeout == kafka_timeout) {
        pipe_fd = plugin_pipe_kafka_connect_to_consume(kafka_host, plugin_data);
        kafka_timeout = plugin_pipe_set_retry_timeout(&kafka_host->btimers, pipe_fd);
      }
      else kafka_timeout = plugin_pipe_calc_retry_timeout_diff(&kafka_host->btimers, idata.now);
    }
#endif

    switch (ret) {
    case 0: /* timeout */
      if (timeout == refresh_timeout) {
	int saved_qq_ptr;

	saved_qq_ptr = qq_ptr;
	P_cache_handle_flush_event(&pt);
	if (saved_qq_ptr) print_output_stdout_header = FALSE;
      }
      break;
    default: /* we received data */
      read_data:
      if (config.pipe_homegrown) {
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
        rg->ptr += bufsz;
      }
#ifdef WITH_RABBITMQ
      else if (config.pipe_amqp) {
        ret = p_amqp_consume_binary(amqp_host, pipebuf, config.buffer_size);
	if (ret) pipe_fd = ERR;

	seq = ((struct ch_buf_hdr *)pipebuf)->seq;
	amqp_timeout = plugin_pipe_set_retry_timeout(&amqp_host->btimers, pipe_fd);
      }
#endif
#ifdef WITH_KAFKA
      else if (config.pipe_kafka) {
        ret = p_kafka_consume_data(kafka_host, kafka_msg, pipebuf, config.buffer_size);
        if (ret) pipe_fd = ERR;

        seq = ((struct ch_buf_hdr *)pipebuf)->seq;
        kafka_timeout = plugin_pipe_set_retry_timeout(&kafka_host->btimers, pipe_fd);
      }
#endif

      /* lazy refresh time handling */ 
      if (idata.now > refresh_deadline) {
	int saved_qq_ptr;

	saved_qq_ptr = qq_ptr;
	P_cache_handle_flush_event(&pt);
	if (saved_qq_ptr) print_output_stdout_header = FALSE;
      }

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

      if (config.pipe_homegrown) goto read_data;
    }
  }
}

void P_cache_purge(struct chained_cache *queue[], int index)
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
  char rd_str[SRVBUFLEN], *sep = config.print_output_separator, *fd_buf;
  char *as_path, *bgp_comm, empty_string[] = "", empty_aspath[] = "^$", empty_ip4[] = "0.0.0.0", empty_ip6[] = "::";
  char empty_macaddress[] = "00:00:00:00:00:00", empty_rd[] = "0:0";
  FILE *f = NULL, *lockf = NULL;
  int j, stop, is_event = FALSE, qn = 0, go_to_pending, saved_index = index, file_to_be_created;
  time_t start, duration;
  char tmpbuf[LONGLONGSRVBUFLEN], current_table[SRVBUFLEN], elem_table[SRVBUFLEN];
  struct primitives_ptrs prim_ptrs, elem_prim_ptrs;
  struct pkt_data dummy_data, elem_dummy_data;
  pid_t writer_pid = getpid();
#ifdef WITH_AVRO
  avro_file_writer_t avro_writer;
#endif

  if (!index) {
    Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - START (PID: %u) ***\n", config.name, config.type, writer_pid);
    Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - END (PID: %u, QN: 0/0, ET: 0) ***\n", config.name, config.type, writer_pid);
    return;
  }

  empty_pcust = malloc(config.cpptrs.len);
  if (!empty_pcust) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() empty_pcust. Exiting.\n", config.name, config.type);
    exit_plugin(1);
  }

  memset(&empty_pbgp, 0, sizeof(struct pkt_bgp_primitives));
  memset(&empty_pnat, 0, sizeof(struct pkt_nat_primitives));
  memset(&empty_pmpls, 0, sizeof(struct pkt_mpls_primitives));
  memset(empty_pcust, 0, config.cpptrs.len);
  memset(&prim_ptrs, 0, sizeof(prim_ptrs));
  memset(&dummy_data, 0, sizeof(dummy_data));
  memset(&elem_prim_ptrs, 0, sizeof(elem_prim_ptrs));
  memset(&elem_dummy_data, 0, sizeof(elem_dummy_data));

  fd_buf = malloc(OUTPUT_FILE_BUFSZ);

  for (j = 0, stop = 0; (!stop) && P_preprocess_funcs[j]; j++)
    stop = P_preprocess_funcs[j](queue, &index, j);

  memcpy(pending_queries_queue, queue, index*sizeof(struct db_cache *));
  pqq_ptr = index;

  Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - START (PID: %u) ***\n", config.name, config.type, writer_pid);
  start = time(NULL);

  start:
  memcpy(queue, pending_queries_queue, pqq_ptr*sizeof(struct db_cache *));
  memset(pending_queries_queue, 0, pqq_ptr*sizeof(struct db_cache *));
  index = pqq_ptr; pqq_ptr = 0; file_to_be_created = FALSE;

  if (config.print_output & PRINT_OUTPUT_EVENT) is_event = TRUE;

  if (config.sql_table) {
    time_t stamp = 0;

    strlcpy(current_table, config.sql_table, SRVBUFLEN);

    if (dyn_table) {
      stamp = queue[0]->basetime.tv_sec;

      prim_ptrs.data = &dummy_data;
      primptrs_set_all_from_chained_cache(&prim_ptrs, queue[0]);

      handle_dynname_internal_strings_same(tmpbuf, LONGSRVBUFLEN, current_table, &prim_ptrs);
      strftime_same(current_table, LONGSRVBUFLEN, tmpbuf, &stamp);
    }

    if (config.print_output & PRINT_OUTPUT_AVRO) {
      int file_is_empty, ret;
#ifdef WITH_AVRO
      f = open_output_file(current_table, "ab", TRUE);

      fseek(f, 0, SEEK_END);
      file_is_empty = ftell(f) == 0;
      close_output_file(f);

      if (config.print_output_file_append && !file_is_empty)
        ret = avro_file_writer_open(current_table, &avro_writer);
      else
        ret = avro_file_writer_create(current_table, avro_acct_schema, &avro_writer);

      if (ret) {
        Log(LOG_ERR, "ERROR ( %s/%s ): AVRO: failed opening %s: %s\n",
            config.name, config.type, current_table, avro_strerror());
        exit_plugin(1);
      }
#endif
    }
    else {
      if (config.print_output_file_append) {
        file_to_be_created = access(current_table, F_OK);
        f = open_output_file(current_table, "a", TRUE);
      }
      else
        f = open_output_file(current_table, "w", TRUE);
    }

    if (!(config.print_output & PRINT_OUTPUT_AVRO) && fd_buf) {
      if (setvbuf(f, fd_buf, _IOFBF, OUTPUT_FILE_BUFSZ))
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] setvbuf() failed: %s\n", config.name, config.type, current_table, errno);
      else memset(fd_buf, 0, OUTPUT_FILE_BUFSZ);
    }

    if (f) {
      if (config.print_markers) {
	if ((config.print_output & PRINT_OUTPUT_CSV) || (config.print_output & PRINT_OUTPUT_FORMATTED))
	  fprintf(f, "--START (%u)--\n", writer_pid);
	else if (config.print_output & PRINT_OUTPUT_JSON) {
          void *json_obj;

	  json_obj = compose_purge_init_json(config.name, writer_pid);
          if (json_obj) write_and_free_json(f, json_obj);
	}
      }

      if (!config.print_output_file_append || (config.print_output_file_append && file_to_be_created)) {
	if (config.print_output & PRINT_OUTPUT_FORMATTED)
	  P_write_stats_header_formatted(f, is_event);
	else if (config.print_output & PRINT_OUTPUT_CSV)
	  P_write_stats_header_csv(f, is_event);
      }
    }
  }
  else {
    /* writing to stdout: pointing f and obtaining lock */
    f = stdout;
    if (config.print_output_lock_file) {
      lockf = open_output_file(config.print_output_lock_file, "w", TRUE);
      if (!lockf)
        Log(LOG_WARNING, "WARN ( %s/%s ): Failed locking print_output_lock_file: %s\n", config.name, config.type, config.print_output_lock_file);
    }

    if (config.print_markers) {
      if ((config.print_output & PRINT_OUTPUT_CSV) || (config.print_output & PRINT_OUTPUT_FORMATTED))
        fprintf(stdout, "--START (%u)--\n", writer_pid);
      else if (config.print_output & PRINT_OUTPUT_JSON) {
        void *json_obj;

        json_obj = compose_purge_init_json(config.name, writer_pid);
        if (json_obj) write_and_free_json(stdout, json_obj);
      }
    }

    /* writing to stdout: writing header only once */
    if (print_output_stdout_header) {
      if (config.print_output & PRINT_OUTPUT_FORMATTED)
        P_write_stats_header_formatted(stdout, is_event);
      else if (config.print_output & PRINT_OUTPUT_CSV)
        P_write_stats_header_csv(stdout, is_event);
    }
  }

  for (j = 0; j < index; j++) {
    int count = 0;
    go_to_pending = FALSE;

    if (queue[j]->valid != PRINT_CACHE_COMMITTED) continue;

    if (dyn_table) {
      time_t stamp = 0;

      memset(tmpbuf, 0, LONGLONGSRVBUFLEN); // XXX: pedantic?
      stamp = queue[j]->basetime.tv_sec;
      strlcpy(elem_table, config.sql_table, SRVBUFLEN);

      elem_prim_ptrs.data = &elem_dummy_data;
      primptrs_set_all_from_chained_cache(&elem_prim_ptrs, queue[j]);
      handle_dynname_internal_strings_same(tmpbuf, LONGSRVBUFLEN, elem_table, &elem_prim_ptrs);
      strftime_same(elem_table, LONGSRVBUFLEN, tmpbuf, &stamp);

      if (strncmp(current_table, elem_table, SRVBUFLEN)) {
        pending_queries_queue[pqq_ptr] = queue[j];

        pqq_ptr++;
        go_to_pending = TRUE;
      }
    }

    if (!go_to_pending) {
      qn++;

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
  
      if (f && config.print_output & PRINT_OUTPUT_FORMATTED) {
        if (config.what_to_count & COUNT_TAG) fprintf(f, "%-10llu  ", data->tag);
        if (config.what_to_count & COUNT_TAG2) fprintf(f, "%-10llu  ", data->tag2);
        if (config.what_to_count & COUNT_CLASS) fprintf(f, "%-16s  ", ((data->class && class[(data->class)-1].id) ? class[(data->class)-1].protocol : "unknown" ));
  #if defined (HAVE_L2)
        if (config.what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC)) {
          etheraddr_string(data->eth_shost, src_mac);
  	if (strlen(src_mac))
            fprintf(f, "%-17s  ", src_mac);
          else
            fprintf(f, "%-17s  ", empty_macaddress);
        }
        if (config.what_to_count & COUNT_DST_MAC) {
          etheraddr_string(data->eth_dhost, dst_mac);
  	if (strlen(dst_mac))
            fprintf(f, "%-17s  ", dst_mac);
  	else
            fprintf(f, "%-17s  ", empty_macaddress);
        }
        if (config.what_to_count & COUNT_VLAN) fprintf(f, "%-5u  ", data->vlan_id); 
        if (config.what_to_count & COUNT_COS) fprintf(f, "%-2u  ", data->cos); 
        if (config.what_to_count & COUNT_ETHERTYPE) fprintf(f, "%-5x  ", data->etype); 
  #endif
        if (config.what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) fprintf(f, "%-10u  ", data->src_as); 
        if (config.what_to_count & COUNT_DST_AS) fprintf(f, "%-10u  ", data->dst_as); 
  
        if (config.what_to_count & COUNT_LOCAL_PREF) fprintf(f, "%-7u  ", pbgp->local_pref);
        if (config.what_to_count & COUNT_SRC_LOCAL_PREF) fprintf(f, "%-7u  ", pbgp->src_local_pref);
        if (config.what_to_count & COUNT_MED) fprintf(f, "%-6u  ", pbgp->med);
        if (config.what_to_count & COUNT_SRC_MED) fprintf(f, "%-6u  ", pbgp->src_med);

        if (config.what_to_count & COUNT_PEER_SRC_AS) fprintf(f, "%-10u  ", pbgp->peer_src_as);
        if (config.what_to_count & COUNT_PEER_DST_AS) fprintf(f, "%-10u  ", pbgp->peer_dst_as);
  
        if (config.what_to_count & COUNT_PEER_SRC_IP) {
          addr_to_str(ip_address, &pbgp->peer_src_ip);
  #if defined ENABLE_IPV6
          if (strlen(ip_address))
            fprintf(f, "%-45s  ", ip_address);
  	else
            fprintf(f, "%-45s  ", empty_ip6);
  #else
  	if (strlen(ip_address))
            fprintf(f, "%-15s  ", ip_address);
  	else
            fprintf(f, "%-15s  ", empty_ip4);
  #endif
        }
        if (config.what_to_count & COUNT_PEER_DST_IP) {
          addr_to_str(ip_address, &pbgp->peer_dst_ip);
  #if defined ENABLE_IPV6
          if (strlen(ip_address))
            fprintf(f, "%-45s  ", ip_address);
          else
            fprintf(f, "%-45s  ", empty_ip6);
  #else
          if (strlen(ip_address))
            fprintf(f, "%-15s  ", ip_address);
          else 
            fprintf(f, "%-15s  ", empty_ip4);
  #endif
        }
  
        if (config.what_to_count & COUNT_IN_IFACE) fprintf(f, "%-10u  ", data->ifindex_in);
        if (config.what_to_count & COUNT_OUT_IFACE) fprintf(f, "%-10u  ", data->ifindex_out);
  
        if (config.what_to_count & COUNT_MPLS_VPN_RD) {
          bgp_rd2str(rd_str, &pbgp->mpls_vpn_rd);
  	if (strlen(rd_str))
            fprintf(f, "%-18s  ", rd_str);
  	else
            fprintf(f, "%-18s  ", empty_rd);
        }
  
        if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST)) {
          addr_to_str(src_host, &data->src_ip);
  #if defined ENABLE_IPV6
  	if (strlen(src_host))
            fprintf(f, "%-45s  ", src_host);
  	else
            fprintf(f, "%-45s  ", empty_ip6);
  #else
  	if (strlen(src_host))
            fprintf(f, "%-15s  ", src_host);
  	else
            fprintf(f, "%-15s  ", empty_ip4);
  #endif
        }

        if (config.what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET)) {
          addr_to_str(src_host, &data->src_net);
  #if defined ENABLE_IPV6
        if (strlen(src_host))
            fprintf(f, "%-45s  ", src_host);
        else
            fprintf(f, "%-45s  ", empty_ip6);
  #else
        if (strlen(src_host))
            fprintf(f, "%-15s  ", src_host);
        else
            fprintf(f, "%-15s  ", empty_ip4);
  #endif
        }

        if (config.what_to_count & COUNT_DST_HOST) {
          addr_to_str(dst_host, &data->dst_ip);
  #if defined ENABLE_IPV6
  	if (strlen(dst_host))
            fprintf(f, "%-45s  ", dst_host);
  	else
            fprintf(f, "%-45s  ", empty_ip6);
  #else
  	if (strlen(dst_host))
            fprintf(f, "%-15s  ", dst_host);
  	else
            fprintf(f, "%-15s  ", empty_ip4);
  #endif
        }

        if (config.what_to_count & COUNT_DST_NET) {
          addr_to_str(dst_host, &data->dst_net);
  #if defined ENABLE_IPV6
        if (strlen(dst_host))
            fprintf(f, "%-45s  ", dst_host);
        else
            fprintf(f, "%-45s  ", empty_ip6);
  #else
        if (strlen(dst_host))
            fprintf(f, "%-15s  ", dst_host);
        else
            fprintf(f, "%-15s  ", empty_ip4);
  #endif
        }

        if (config.what_to_count & COUNT_SRC_NMASK) fprintf(f, "%-3u       ", data->src_nmask);
        if (config.what_to_count & COUNT_DST_NMASK) fprintf(f, "%-3u       ", data->dst_nmask);
        if (config.what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) fprintf(f, "%-5u     ", data->src_port);
        if (config.what_to_count & COUNT_DST_PORT) fprintf(f, "%-5u     ", data->dst_port);
        if (config.what_to_count & COUNT_TCPFLAGS) fprintf(f, "%-3u        ", queue[j]->tcp_flags);
  
        if (config.what_to_count & COUNT_IP_PROTO) {
          if (!config.num_protos && (data->proto < protocols_number))
	    fprintf(f, "%-10s  ", _protocols[data->proto].name);
          else
	    fprintf(f, "%-10d  ", data->proto);
        }
  
        if (config.what_to_count & COUNT_IP_TOS) fprintf(f, "%-3u    ", data->tos);
  
  #if defined WITH_GEOIP
        if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) fprintf(f, "%-5s       ", GeoIP_code_by_id(data->src_ip_country.id));
        if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) fprintf(f, "%-5s       ", GeoIP_code_by_id(data->dst_ip_country.id));
  #endif
  #if defined WITH_GEOIPV2
        if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) fprintf(f, "%-5s       ", data->src_ip_country.str);
        if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) fprintf(f, "%-5s       ", data->dst_ip_country.str);
        if (config.what_to_count_2 & COUNT_SRC_HOST_POCODE) fprintf(f, "%-12s  ", data->src_ip_pocode.str);
        if (config.what_to_count_2 & COUNT_DST_HOST_POCODE) fprintf(f, "%-12s  ", data->dst_ip_pocode.str);
  #endif
  
        if (config.what_to_count_2 & COUNT_SAMPLING_RATE) fprintf(f, "%-7u       ", data->sampling_rate);
        if (config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB) fprintf(f, "%-10s      ", config.pkt_len_distrib_bins[data->pkt_len_distrib]);
  
        if (config.what_to_count_2 & COUNT_POST_NAT_SRC_HOST) {
          addr_to_str(ip_address, &pnat->post_nat_src_ip);
  
  #if defined ENABLE_IPV6
          if (strlen(ip_address))
            fprintf(f, "%-45s  ", ip_address);
          else
            fprintf(f, "%-45s  ", empty_ip6);
  #else
          if (strlen(ip_address))
            fprintf(f, "%-15s  ", ip_address);
          else
            fprintf(f, "%-15s  ", empty_ip4);
  #endif
        }
  
        if (config.what_to_count_2 & COUNT_POST_NAT_DST_HOST) {
          addr_to_str(ip_address, &pnat->post_nat_dst_ip);
  
  #if defined ENABLE_IPV6
          if (strlen(ip_address))
            fprintf(f, "%-45s  ", ip_address);
          else
            fprintf(f, "%-45s  ", empty_ip6);
  #else 
          if (strlen(ip_address))
            fprintf(f, "%-15s  ", ip_address);
          else
            fprintf(f, "%-15s  ", empty_ip4);
  #endif
        }
  
        if (config.what_to_count_2 & COUNT_POST_NAT_SRC_PORT) fprintf(f, "%-5u              ", pnat->post_nat_src_port);
        if (config.what_to_count_2 & COUNT_POST_NAT_DST_PORT) fprintf(f, "%-5u              ", pnat->post_nat_dst_port);
        if (config.what_to_count_2 & COUNT_NAT_EVENT) fprintf(f, "%-3u       ", pnat->nat_event);
  
        if (config.what_to_count_2 & COUNT_MPLS_LABEL_TOP) {
  	fprintf(f, "%-7u         ", pmpls->mpls_label_top);
        }
        if (config.what_to_count_2 & COUNT_MPLS_LABEL_BOTTOM) {
  	fprintf(f, "%-7u            ", pmpls->mpls_label_bottom);
        }
        if (config.what_to_count_2 & COUNT_MPLS_STACK_DEPTH) {
  	fprintf(f, "%-2u                ", pmpls->mpls_stack_depth);
        }
  
        if (config.what_to_count_2 & COUNT_TIMESTAMP_START) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;
  
          if (config.timestamps_since_epoch) {
	    snprintf(buf2, SRVBUFLEN, "%u.%u", pnat->timestamp_start.tv_sec, pnat->timestamp_start.tv_usec);
	  }
	  else {
            time1 = pnat->timestamp_start.tv_sec;
            time2 = localtime(&time1);
            strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
            snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, pnat->timestamp_start.tv_usec);
	  }

          fprintf(f, "%-30s ", buf2);
        }
  
        if (config.what_to_count_2 & COUNT_TIMESTAMP_END) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;
        
          if (config.timestamps_since_epoch) {
            snprintf(buf2, SRVBUFLEN, "%u.%u", pnat->timestamp_end.tv_sec, pnat->timestamp_end.tv_usec);
          }
          else {
            time1 = pnat->timestamp_end.tv_sec;
            time2 = localtime(&time1);
            strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
            snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, pnat->timestamp_end.tv_usec);
	  }

          fprintf(f, "%-30s ", buf2);
        }

        if (config.what_to_count_2 & COUNT_TIMESTAMP_ARRIVAL) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;

          if (config.timestamps_since_epoch) {
            snprintf(buf2, SRVBUFLEN, "%u.%u", pnat->timestamp_arrival.tv_sec, pnat->timestamp_arrival.tv_usec);
          }
          else {
            time1 = pnat->timestamp_arrival.tv_sec;
            time2 = localtime(&time1);
            strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
            snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, pnat->timestamp_arrival.tv_usec);
          }

          fprintf(f, "%-30s ", buf2);
        }

        if (config.nfacctd_stitching && queue[j]->stitch) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;

          if (config.timestamps_since_epoch) {
            snprintf(buf2, SRVBUFLEN, "%u.%u", queue[j]->stitch->timestamp_min.tv_sec, queue[j]->stitch->timestamp_min.tv_usec);
            fprintf(f, "%-30s ", buf2);

            snprintf(buf2, SRVBUFLEN, "%u.%u", queue[j]->stitch->timestamp_max.tv_sec, queue[j]->stitch->timestamp_max.tv_usec);
            fprintf(f, "%-30s ", buf2);
          }
          else {
	    time1 = queue[j]->stitch->timestamp_min.tv_sec;
            time2 = localtime(&time1);
            strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
            snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, queue[j]->stitch->timestamp_min.tv_usec);
            fprintf(f, "%-30s ", buf2);

            time1 = queue[j]->stitch->timestamp_max.tv_sec;
            time2 = localtime(&time1);
            strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
            snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, queue[j]->stitch->timestamp_max.tv_usec);
            fprintf(f, "%-30s ", buf2);
	  }
        }

        if (config.what_to_count_2 & COUNT_EXPORT_PROTO_SEQNO) fprintf(f, "%-18u  ", data->export_proto_seqno);
        if (config.what_to_count_2 & COUNT_EXPORT_PROTO_VERSION) fprintf(f, "%-20u  ", data->export_proto_version);

        /* all custom primitives printed here */
        {
          int cp_idx;
  
          for (cp_idx = 0; cp_idx < config.cpptrs.num; cp_idx++) {
	    if (config.cpptrs.primitive[cp_idx].ptr->len != PM_VARIABLE_LENGTH) {
              char cp_str[SRVBUFLEN];

              custom_primitive_value_print(cp_str, SRVBUFLEN, pcust, &config.cpptrs.primitive[cp_idx], TRUE);
	      fprintf(f, "%s  ", cp_str);
	    }
	    else {
	      /* vlen primitives not supported in formatted outputs: we should never get here */
              char *label_ptr = NULL;

              vlen_prims_get(pvlen, config.cpptrs.primitive[cp_idx].ptr->type, &label_ptr);
              if (!label_ptr) label_ptr = empty_string;
              fprintf(f, "%s  ", label_ptr);
	    }
          }
        }

        if (!is_event) {
  #if defined HAVE_64BIT_COUNTERS
          fprintf(f, "%-20llu  ", queue[j]->packet_counter);
          if (config.what_to_count & COUNT_FLOWS) fprintf(f, "%-20llu  ", queue[j]->flow_counter);
          fprintf(f, "%llu\n", queue[j]->bytes_counter);
  #else
          fprintf(f, "%-10lu  ", queue[j]->packet_counter);
          if (config.what_to_count & COUNT_FLOWS) fprintf(f, "%-10lu  ", queue[j]->flow_counter);
          fprintf(f, "%lu\n", queue[j]->bytes_counter);
  #endif
        }
        else fprintf(f, "\n");
      }
      else if (f && config.print_output & PRINT_OUTPUT_CSV) {
        if (config.what_to_count & COUNT_TAG) fprintf(f, "%s%llu", write_sep(sep, &count), data->tag);
        if (config.what_to_count & COUNT_TAG2) fprintf(f, "%s%llu", write_sep(sep, &count), data->tag2);
	if (config.what_to_count_2 & COUNT_LABEL) P_fprintf_csv_string(f, pvlen, COUNT_INT_LABEL, write_sep(sep, &count), empty_string);
        if (config.what_to_count & COUNT_CLASS) fprintf(f, "%s%s", write_sep(sep, &count), ((data->class && class[(data->class)-1].id) ? class[(data->class)-1].protocol : "unknown" ));
  #if defined (HAVE_L2)
        if (config.what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC)) {
          etheraddr_string(data->eth_shost, src_mac);
          fprintf(f, "%s%s", write_sep(sep, &count), src_mac);
        }
        if (config.what_to_count & COUNT_DST_MAC) {
          etheraddr_string(data->eth_dhost, dst_mac);
          fprintf(f, "%s%s", write_sep(sep, &count), dst_mac);
        }
        if (config.what_to_count & COUNT_VLAN) fprintf(f, "%s%u", write_sep(sep, &count), data->vlan_id); 
        if (config.what_to_count & COUNT_COS) fprintf(f, "%s%u", write_sep(sep, &count), data->cos); 
        if (config.what_to_count & COUNT_ETHERTYPE) fprintf(f, "%s%x", write_sep(sep, &count), data->etype); 
  #endif
        if (config.what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) fprintf(f, "%s%u", write_sep(sep, &count), data->src_as); 
        if (config.what_to_count & COUNT_DST_AS) fprintf(f, "%s%u", write_sep(sep, &count), data->dst_as); 
  
        if (config.what_to_count & COUNT_STD_COMM) {
          char *str_ptr = NULL;

          vlen_prims_get(pvlen, COUNT_INT_STD_COMM, &str_ptr);
          if (str_ptr) {
            bgp_comm = str_ptr;
            while (bgp_comm) {
              bgp_comm = strchr(str_ptr, ' ');
              if (bgp_comm) *bgp_comm = '_';
            }

          }

          P_fprintf_csv_string(f, pvlen, COUNT_INT_STD_COMM, write_sep(sep, &count), empty_string);
        }

        if (config.what_to_count & COUNT_EXT_COMM) {
          char *str_ptr = NULL;

          vlen_prims_get(pvlen, COUNT_INT_EXT_COMM, &str_ptr);
          if (str_ptr) {
            bgp_comm = str_ptr;
            while (bgp_comm) {
              bgp_comm = strchr(str_ptr, ' ');
              if (bgp_comm) *bgp_comm = '_';
            }
          }

          P_fprintf_csv_string(f, pvlen, COUNT_INT_EXT_COMM, write_sep(sep, &count), empty_string);
        }

        if (config.what_to_count_2 & COUNT_LRG_COMM) {
          char *str_ptr = NULL;

          vlen_prims_get(pvlen, COUNT_INT_LRG_COMM, &str_ptr);
          if (str_ptr) {
            bgp_comm = str_ptr;
            while (bgp_comm) {
              bgp_comm = strchr(str_ptr, ' ');
              if (bgp_comm) *bgp_comm = '_';
            }
          }

          P_fprintf_csv_string(f, pvlen, COUNT_INT_LRG_COMM, write_sep(sep, &count), empty_string);
        }

        if (config.what_to_count & COUNT_SRC_STD_COMM) {
          char *str_ptr = NULL;

          vlen_prims_get(pvlen, COUNT_INT_SRC_STD_COMM, &str_ptr);
          if (str_ptr) {
            bgp_comm = str_ptr;
            while (bgp_comm) {
              bgp_comm = strchr(str_ptr, ' ');
              if (bgp_comm) *bgp_comm = '_';
            }

          }

          P_fprintf_csv_string(f, pvlen, COUNT_INT_SRC_STD_COMM, write_sep(sep, &count), empty_string);
        }

        if (config.what_to_count & COUNT_SRC_EXT_COMM) {
          char *str_ptr = NULL;

          vlen_prims_get(pvlen, COUNT_INT_SRC_EXT_COMM, &str_ptr);
          if (str_ptr) {
            bgp_comm = str_ptr;
            while (bgp_comm) {
              bgp_comm = strchr(str_ptr, ' ');
              if (bgp_comm) *bgp_comm = '_';
            }
          }

          P_fprintf_csv_string(f, pvlen, COUNT_INT_SRC_EXT_COMM, write_sep(sep, &count), empty_string);
        }

        if (config.what_to_count_2 & COUNT_SRC_LRG_COMM) {
          char *str_ptr = NULL;

          vlen_prims_get(pvlen, COUNT_INT_SRC_LRG_COMM, &str_ptr);
          if (str_ptr) {
            bgp_comm = str_ptr;
            while (bgp_comm) {
              bgp_comm = strchr(str_ptr, ' ');
              if (bgp_comm) *bgp_comm = '_';
            }
          }

          P_fprintf_csv_string(f, pvlen, COUNT_INT_SRC_LRG_COMM, write_sep(sep, &count), empty_string);
        }
  
	if (config.what_to_count & COUNT_AS_PATH) {
	  char *str_ptr = NULL;

	  vlen_prims_get(pvlen, COUNT_INT_AS_PATH, &str_ptr);
	  if (str_ptr) {
	    as_path = str_ptr;
            while (as_path) {
              as_path = strchr(str_ptr, ' ');
              if (as_path) *as_path = '_';
	    }

	  }

	  P_fprintf_csv_string(f, pvlen, COUNT_INT_AS_PATH, write_sep(sep, &count), empty_string);
	}

        if (config.what_to_count & COUNT_SRC_AS_PATH) {
          char *str_ptr = NULL;

          vlen_prims_get(pvlen, COUNT_INT_SRC_AS_PATH, &str_ptr);
          if (str_ptr) {
            as_path = str_ptr;
            while (as_path) {
              as_path = strchr(str_ptr, ' ');
              if (as_path) *as_path = '_';
            }

          }

          P_fprintf_csv_string(f, pvlen, COUNT_INT_SRC_AS_PATH, write_sep(sep, &count), empty_string);
        }

        if (config.what_to_count & COUNT_LOCAL_PREF) fprintf(f, "%s%u", write_sep(sep, &count), pbgp->local_pref);
        if (config.what_to_count & COUNT_SRC_LOCAL_PREF) fprintf(f, "%s%u", write_sep(sep, &count), pbgp->src_local_pref);
        if (config.what_to_count & COUNT_MED) fprintf(f, "%s%u", write_sep(sep, &count), pbgp->med);
        if (config.what_to_count & COUNT_SRC_MED) fprintf(f, "%s%u", write_sep(sep, &count), pbgp->src_med);

        if (config.what_to_count & COUNT_PEER_SRC_AS) fprintf(f, "%s%u", write_sep(sep, &count), pbgp->peer_src_as);
        if (config.what_to_count & COUNT_PEER_DST_AS) fprintf(f, "%s%u", write_sep(sep, &count), pbgp->peer_dst_as);
  
        if (config.what_to_count & COUNT_PEER_SRC_IP) {
          addr_to_str(ip_address, &pbgp->peer_src_ip);
          fprintf(f, "%s%s", write_sep(sep, &count), ip_address);
        }
        if (config.what_to_count & COUNT_PEER_DST_IP) {
          addr_to_str(ip_address, &pbgp->peer_dst_ip);
          fprintf(f, "%s%s", write_sep(sep, &count), ip_address);
        }
  
        if (config.what_to_count & COUNT_IN_IFACE) fprintf(f, "%s%u", write_sep(sep, &count), data->ifindex_in);
        if (config.what_to_count & COUNT_OUT_IFACE) fprintf(f, "%s%u", write_sep(sep, &count), data->ifindex_out);
  
        if (config.what_to_count & COUNT_MPLS_VPN_RD) {
          bgp_rd2str(rd_str, &pbgp->mpls_vpn_rd);
          fprintf(f, "%s%s", write_sep(sep, &count), rd_str);
        }
  
        if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST)) {
          addr_to_str(src_host, &data->src_ip);
          fprintf(f, "%s%s", write_sep(sep, &count), src_host);
        }
        if (config.what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET)) {
          addr_to_str(src_host, &data->src_net);
          fprintf(f, "%s%s", write_sep(sep, &count), src_host);
        }

        if (config.what_to_count & COUNT_DST_HOST) {
          addr_to_str(dst_host, &data->dst_ip);
          fprintf(f, "%s%s", write_sep(sep, &count), dst_host);
        }
        if (config.what_to_count & COUNT_DST_NET) {
          addr_to_str(dst_host, &data->dst_net);
          fprintf(f, "%s%s", write_sep(sep, &count), dst_host);
        }
  
        if (config.what_to_count & COUNT_SRC_NMASK) fprintf(f, "%s%u", write_sep(sep, &count), data->src_nmask);
        if (config.what_to_count & COUNT_DST_NMASK) fprintf(f, "%s%u", write_sep(sep, &count), data->dst_nmask);
        if (config.what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) fprintf(f, "%s%u", write_sep(sep, &count), data->src_port);
        if (config.what_to_count & COUNT_DST_PORT) fprintf(f, "%s%u", write_sep(sep, &count), data->dst_port);
        if (config.what_to_count & COUNT_TCPFLAGS) fprintf(f, "%s%u", write_sep(sep, &count), queue[j]->tcp_flags);
  
        if (config.what_to_count & COUNT_IP_PROTO) {
          if (!config.num_protos && (data->proto < protocols_number))
	    fprintf(f, "%s%s", write_sep(sep, &count), _protocols[data->proto].name);
          else
	    fprintf(f, "%s%d", write_sep(sep, &count), data->proto);
        }
  
        if (config.what_to_count & COUNT_IP_TOS) fprintf(f, "%s%u", write_sep(sep, &count), data->tos);
  
  #if defined WITH_GEOIP
        if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) fprintf(f, "%s%s", write_sep(sep, &count), GeoIP_code_by_id(data->src_ip_country.id));
        if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) fprintf(f, "%s%s", write_sep(sep, &count), GeoIP_code_by_id(data->dst_ip_country.id));
  #endif
  #if defined WITH_GEOIPV2
        if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) fprintf(f, "%s%s", write_sep(sep, &count), data->src_ip_country.str);
        if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) fprintf(f, "%s%s", write_sep(sep, &count), data->dst_ip_country.str);
        if (config.what_to_count_2 & COUNT_SRC_HOST_POCODE) fprintf(f, "%s%s", write_sep(sep, &count), data->src_ip_pocode.str);
        if (config.what_to_count_2 & COUNT_DST_HOST_POCODE) fprintf(f, "%s%s", write_sep(sep, &count), data->dst_ip_pocode.str);
  #endif
  
        if (config.what_to_count_2 & COUNT_SAMPLING_RATE) fprintf(f, "%s%u", write_sep(sep, &count), data->sampling_rate);
        if (config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB) fprintf(f, "%s%s", write_sep(sep, &count), config.pkt_len_distrib_bins[data->pkt_len_distrib]);
  
        if (config.what_to_count_2 & COUNT_POST_NAT_SRC_HOST) {
          addr_to_str(src_host, &pnat->post_nat_src_ip);
          fprintf(f, "%s%s", write_sep(sep, &count), src_host);
        }
        if (config.what_to_count_2 & COUNT_POST_NAT_DST_HOST) {
          addr_to_str(dst_host, &pnat->post_nat_dst_ip);
          fprintf(f, "%s%s", write_sep(sep, &count), dst_host);
        }
        if (config.what_to_count_2 & COUNT_POST_NAT_SRC_PORT) fprintf(f, "%s%u", write_sep(sep, &count), pnat->post_nat_src_port);
        if (config.what_to_count_2 & COUNT_POST_NAT_DST_PORT) fprintf(f, "%s%u", write_sep(sep, &count), pnat->post_nat_dst_port);
        if (config.what_to_count_2 & COUNT_NAT_EVENT) fprintf(f, "%s%u", write_sep(sep, &count), pnat->nat_event);
  
        if (config.what_to_count_2 & COUNT_MPLS_LABEL_TOP) fprintf(f, "%s%u", write_sep(sep, &count), pmpls->mpls_label_top);
        if (config.what_to_count_2 & COUNT_MPLS_LABEL_BOTTOM) fprintf(f, "%s%u", write_sep(sep, &count), pmpls->mpls_label_bottom);
        if (config.what_to_count_2 & COUNT_MPLS_STACK_DEPTH) fprintf(f, "%s%u", write_sep(sep, &count), pmpls->mpls_stack_depth);
  
        if (config.what_to_count_2 & COUNT_TIMESTAMP_START) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;
 
          if (config.timestamps_since_epoch) {
            snprintf(buf2, SRVBUFLEN, "%u.%u", pnat->timestamp_start.tv_sec, pnat->timestamp_start.tv_usec);
          }
          else {
            time1 = pnat->timestamp_start.tv_sec;
            time2 = localtime(&time1);
            strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
            snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, pnat->timestamp_start.tv_usec);
	  }

          fprintf(f, "%s%s", write_sep(sep, &count), buf2);
        }
  
        if (config.what_to_count_2 & COUNT_TIMESTAMP_END) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;
  
          if (config.timestamps_since_epoch) {
            snprintf(buf2, SRVBUFLEN, "%u.%u", pnat->timestamp_end.tv_sec, pnat->timestamp_end.tv_usec);
          }
          else {
            time1 = pnat->timestamp_end.tv_sec;
            time2 = localtime(&time1);
            strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
            snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, pnat->timestamp_end.tv_usec);
	  }

          fprintf(f, "%s%s", write_sep(sep, &count), buf2);
        }

        if (config.what_to_count_2 & COUNT_TIMESTAMP_ARRIVAL) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;

          if (config.timestamps_since_epoch) {
            snprintf(buf2, SRVBUFLEN, "%u.%u", pnat->timestamp_arrival.tv_sec, pnat->timestamp_arrival.tv_usec);
          }
          else {
            time1 = pnat->timestamp_arrival.tv_sec;
            time2 = localtime(&time1);
            strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
            snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, pnat->timestamp_arrival.tv_usec);
          }

          fprintf(f, "%s%s", write_sep(sep, &count), buf2);
        }

        if (config.nfacctd_stitching && queue[j]->stitch) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;

          if (config.timestamps_since_epoch) {
            snprintf(buf2, SRVBUFLEN, "%u.%u", queue[j]->stitch->timestamp_min.tv_sec, queue[j]->stitch->timestamp_min.tv_usec);
	    fprintf(f, "%s%s", write_sep(sep, &count), buf2);

            snprintf(buf2, SRVBUFLEN, "%u.%u", queue[j]->stitch->timestamp_max.tv_sec, queue[j]->stitch->timestamp_max.tv_usec);
	    fprintf(f, "%s%s", write_sep(sep, &count), buf2);
          }
	  else {
            time1 = queue[j]->stitch->timestamp_min.tv_sec;
            time2 = localtime(&time1);
            strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
            snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, queue[j]->stitch->timestamp_min.tv_usec);
            fprintf(f, "%s%s", write_sep(sep, &count), buf2);

            time1 = queue[j]->stitch->timestamp_max.tv_sec;
            time2 = localtime(&time1);
            strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
            snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, queue[j]->stitch->timestamp_max.tv_usec);
            fprintf(f, "%s%s", write_sep(sep, &count), buf2);
	  }
        }

        if (config.what_to_count_2 & COUNT_EXPORT_PROTO_SEQNO) fprintf(f, "%s%u", write_sep(sep, &count), data->export_proto_seqno);
        if (config.what_to_count_2 & COUNT_EXPORT_PROTO_VERSION) fprintf(f, "%s%u", write_sep(sep, &count), data->export_proto_version);
  
        /* all custom primitives printed here */
        {
          int cp_idx;
  
          for (cp_idx = 0; cp_idx < config.cpptrs.num; cp_idx++) {
            if (config.cpptrs.primitive[cp_idx].ptr->len != PM_VARIABLE_LENGTH) {
              char cp_str[SRVBUFLEN];

	      custom_primitive_value_print(cp_str, SRVBUFLEN, pcust, &config.cpptrs.primitive[cp_idx], FALSE);
              fprintf(f, "%s%s", write_sep(sep, &count), cp_str);
	    }
	    else {
	      char *label_ptr = NULL;

	      vlen_prims_get(pvlen, config.cpptrs.primitive[cp_idx].ptr->type, &label_ptr);
	      if (!label_ptr) label_ptr = empty_string;
	      fprintf(f, "%s%s", write_sep(sep, &count), label_ptr);
	    }
          }
        }
  
        if (!is_event) {
  #if defined HAVE_64BIT_COUNTERS
          fprintf(f, "%s%llu", write_sep(sep, &count), queue[j]->packet_counter);
          if (config.what_to_count & COUNT_FLOWS) fprintf(f, "%s%llu", write_sep(sep, &count), queue[j]->flow_counter);
          fprintf(f, "%s%llu\n", write_sep(sep, &count), queue[j]->bytes_counter);
  #else
          fprintf(f, "%s%lu", write_sep(sep, &count), queue[j]->packet_counter);
          if (config.what_to_count & COUNT_FLOWS) fprintf(f, "%s%lu", write_sep(sep, &count), queue[j]->flow_counter);
          fprintf(f, "%s%lu\n", write_sep(sep, &count), queue[j]->bytes_counter);
  #endif
        }
        else fprintf(f, "\n");
      }
      else if (f && config.print_output & PRINT_OUTPUT_JSON) {
#ifdef WITH_JANSSON
	json_t *json_obj = json_object();
	int idx;

	for (idx = 0; idx < N_PRIMITIVES && cjhandler[idx]; idx++) cjhandler[idx](json_obj, queue[j]);
        if (json_obj) write_and_free_json(f, json_obj);
#endif
      }
      else if (f && config.print_output & PRINT_OUTPUT_AVRO) {
#ifdef WITH_AVRO
        avro_value_iface_t *avro_iface = avro_generic_class_from_schema(avro_acct_schema);

        avro_value_t avro_value = compose_avro(config.what_to_count, config.what_to_count_2, queue[j]->flow_type,
                         &queue[j]->primitives, pbgp, pnat, pmpls, pcust, pvlen, queue[j]->bytes_counter,
                         queue[j]->packet_counter, queue[j]->flow_counter, queue[j]->tcp_flags, NULL,
                         queue[j]->stitch, avro_iface);

        if (config.sql_table) {
          if (avro_file_writer_append_value(avro_writer, &avro_value)) {
            Log(LOG_ERR, "ERROR ( %s/%s ): AVRO: failed writing the value: %s\n",
                config.name, config.type, avro_strerror());
            exit_plugin(1);
          }
        }
        else {
          char *json_str;

          if (avro_value_to_json(&avro_value, TRUE, &json_str)) {
            Log(LOG_ERR, "ERROR ( %s/%s ): AVRO: unable to value to JSON: %s\n",
                config.name, config.type, avro_strerror());
            exit_plugin(1);
          }

          fprintf(f, "%s\n", json_str);
          free(json_str);
        }

        avro_value_iface_decref(avro_iface);
        avro_value_decref(&avro_value);
#else
        if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): compose_avro(): AVRO object not created due to missing --enable-avro\n", config.name, config.type);
#endif
      }
    }
  }

  duration = time(NULL)-start;

  if (f && config.print_markers) {
    if ((config.print_output & PRINT_OUTPUT_CSV) || (config.print_output & PRINT_OUTPUT_FORMATTED))
      fprintf(f, "--END (%u)--\n", writer_pid);
    else if (config.print_output & PRINT_OUTPUT_JSON) {
      void *json_obj;

      json_obj = compose_purge_close_json(config.name, writer_pid, qn, saved_index, duration);
      if (json_obj) write_and_free_json(f, json_obj);
    }
  }
    
  if (config.sql_table) {
#ifdef WITH_AVRO
    if (config.print_output & PRINT_OUTPUT_AVRO)
      avro_file_writer_flush(avro_writer);
#endif

    if (config.print_latest_file) {
      memset(tmpbuf, 0, LONGLONGSRVBUFLEN);
      handle_dynname_internal_strings(tmpbuf, LONGSRVBUFLEN, config.print_latest_file, &prim_ptrs);
      link_latest_output_file(tmpbuf, current_table);
    }

#ifdef WITH_AVRO
    if (config.print_output & PRINT_OUTPUT_AVRO) {
      avro_file_writer_close(avro_writer);
    }
#endif
    else {
      if (f) close_output_file(f);
    }
  }
  else {
    /* writing to stdout: releasing lock */
    fflush(f);
    close_output_file(lockf);
  }

  /* If we have pending queries then start again */
  if (pqq_ptr) goto start;

  Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - END (PID: %u, QN: %u/%u, ET: %u) ***\n",
		config.name, config.type, writer_pid, qn, saved_index, duration);

  if (config.sql_trigger_exec) P_trigger_exec(config.sql_trigger_exec); 

  if (empty_pcust) free(empty_pcust);
}

void P_write_stats_header_formatted(FILE *f, int is_event)
{
  if (config.what_to_count & COUNT_TAG) fprintf(f, "TAG         ");
  if (config.what_to_count & COUNT_TAG2) fprintf(f, "TAG2        ");
  if (config.what_to_count & COUNT_CLASS) fprintf(f, "CLASS             ");
#if defined HAVE_L2
  if (config.what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC)) fprintf(f, "SRC_MAC            ");
  if (config.what_to_count & COUNT_DST_MAC) fprintf(f, "DST_MAC            ");
  if (config.what_to_count & COUNT_VLAN) fprintf(f, "VLAN   ");
  if (config.what_to_count & COUNT_COS) fprintf(f, "COS ");
  if (config.what_to_count & COUNT_ETHERTYPE) fprintf(f, "ETYPE  ");
#endif
  if (config.what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) fprintf(f, "SRC_AS      ");
  if (config.what_to_count & COUNT_DST_AS) fprintf(f, "DST_AS      ");
  if (config.what_to_count & COUNT_LOCAL_PREF) fprintf(f, "PREF     ");
  if (config.what_to_count & COUNT_SRC_LOCAL_PREF) fprintf(f, "SRC_PREF ");
  if (config.what_to_count & COUNT_MED) fprintf(f, "MED     ");
  if (config.what_to_count & COUNT_SRC_MED) fprintf(f, "SRC_MED ");
  if (config.what_to_count & COUNT_PEER_SRC_AS) fprintf(f, "PEER_SRC_AS ");
  if (config.what_to_count & COUNT_PEER_DST_AS) fprintf(f, "PEER_DST_AS ");
  if (config.what_to_count & COUNT_PEER_SRC_IP) fprintf(f, "PEER_SRC_IP      ");
  if (config.what_to_count & COUNT_PEER_DST_IP) fprintf(f, "PEER_DST_IP      ");
  if (config.what_to_count & COUNT_IN_IFACE) fprintf(f, "IN_IFACE    ");
  if (config.what_to_count & COUNT_OUT_IFACE) fprintf(f, "OUT_IFACE   ");
  if (config.what_to_count & COUNT_MPLS_VPN_RD) fprintf(f, "MPLS_VPN_RD         ");
  if (!config.tmp_net_own_field) {
#if defined ENABLE_IPV6
    if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) fprintf(f, "SRC_IP                                         ");
    if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET)) fprintf(f, "SRC_IP                                         ");
    if (config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) fprintf(f, "DST_IP                                         ");
#else
    if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) fprintf(f, "SRC_IP           ");
    if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET)) fprintf(f, "SRC_IP           ");
    if (config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) fprintf(f, "DST_IP           ");
#endif
  } 
  else {
#if defined ENABLE_IPV6
    if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST)) fprintf(f, "SRC_IP                                         ");
    if (config.what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET)) fprintf(f, "SRC_NET                                        ");
    if (config.what_to_count & COUNT_DST_HOST) fprintf(f, "DST_IP                                         ");
    if (config.what_to_count & COUNT_DST_NET) fprintf(f, "DST_NET                                        ");
#else
    if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST)) fprintf(f, "SRC_IP           ");
    if (config.what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET)) fprintf(f, "SRC_NET          ");
    if (config.what_to_count & COUNT_DST_HOST) fprintf(f, "DST_IP           ");
    if (config.what_to_count & COUNT_DST_NET) fprintf(f, "DST_NET          ");
#endif
  }
  if (config.what_to_count & COUNT_SRC_NMASK) fprintf(f, "SRC_MASK  ");
  if (config.what_to_count & COUNT_DST_NMASK) fprintf(f, "DST_MASK  ");
  if (config.what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) fprintf(f, "SRC_PORT  ");
  if (config.what_to_count & COUNT_DST_PORT) fprintf(f, "DST_PORT  ");
  if (config.what_to_count & COUNT_TCPFLAGS) fprintf(f, "TCP_FLAGS  ");
  if (config.what_to_count & COUNT_IP_PROTO) fprintf(f, "PROTOCOL    ");
  if (config.what_to_count & COUNT_IP_TOS) fprintf(f, "TOS    ");
#if defined (WITH_GEOIP) || defined (WITH_GEOIPV2)
  if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) fprintf(f, "SH_COUNTRY  ");
  if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) fprintf(f, "DH_COUNTRY  ");
#endif
#if defined (WITH_GEOIPV2)
  if (config.what_to_count_2 & COUNT_SRC_HOST_POCODE) fprintf(f, "SH_POCODE     ");
  if (config.what_to_count_2 & COUNT_DST_HOST_POCODE) fprintf(f, "DH_POCODE     ");
#endif
  if (config.what_to_count_2 & COUNT_SAMPLING_RATE) fprintf(f, "SAMPLING_RATE ");
  if (config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB) fprintf(f, "PKT_LEN_DISTRIB ");
#if defined ENABLE_IPV6
  if (config.what_to_count_2 & COUNT_POST_NAT_SRC_HOST) fprintf(f, "POST_NAT_SRC_IP                                ");
  if (config.what_to_count_2 & COUNT_POST_NAT_DST_HOST) fprintf(f, "POST_NAT_DST_IP                                ");
#else
  if (config.what_to_count_2 & COUNT_POST_NAT_SRC_HOST) fprintf(f, "POST_NAT_SRC_IP  ");
  if (config.what_to_count_2 & COUNT_POST_NAT_DST_HOST) fprintf(f, "POST_NAT_DST_IP  ");
#endif
  if (config.what_to_count_2 & COUNT_POST_NAT_SRC_PORT) fprintf(f, "POST_NAT_SRC_PORT  ");
  if (config.what_to_count_2 & COUNT_POST_NAT_DST_PORT) fprintf(f, "POST_NAT_DST_PORT  ");
  if (config.what_to_count_2 & COUNT_NAT_EVENT) fprintf(f, "NAT_EVENT ");
  if (config.what_to_count_2 & COUNT_MPLS_LABEL_TOP) fprintf(f, "MPLS_LABEL_TOP  ");
  if (config.what_to_count_2 & COUNT_MPLS_LABEL_BOTTOM) fprintf(f, "MPLS_LABEL_BOTTOM  ");
  if (config.what_to_count_2 & COUNT_MPLS_STACK_DEPTH) fprintf(f, "MPLS_STACK_DEPTH  ");
  if (config.what_to_count_2 & COUNT_TIMESTAMP_START) fprintf(f, "TIMESTAMP_START                ");
  if (config.what_to_count_2 & COUNT_TIMESTAMP_END) fprintf(f, "TIMESTAMP_END                  "); 
  if (config.what_to_count_2 & COUNT_TIMESTAMP_ARRIVAL) fprintf(f, "TIMESTAMP_ARRIVAL              ");
  if (config.nfacctd_stitching) {
    fprintf(f, "TIMESTAMP_MIN                  ");
    fprintf(f, "TIMESTAMP_MAX                  "); 
  }
  if (config.what_to_count_2 & COUNT_EXPORT_PROTO_SEQNO) fprintf(f, "EXPORT_PROTO_SEQNO  ");
  if (config.what_to_count_2 & COUNT_EXPORT_PROTO_VERSION) fprintf(f, "EXPORT_PROTO_VERSION  ");

  /* all custom primitives printed here */
  {
    char cp_str[SRVBUFLEN];
    int cp_idx;

    for (cp_idx = 0; cp_idx < config.cpptrs.num; cp_idx++) {
      custom_primitive_header_print(cp_str, SRVBUFLEN, &config.cpptrs.primitive[cp_idx], TRUE);
      fprintf(f, "%s  ", cp_str);
    }
  }

  if (!is_event) {
#if defined HAVE_64BIT_COUNTERS
    fprintf(f, "PACKETS               ");
    if (config.what_to_count & COUNT_FLOWS) fprintf(f, "FLOWS                 ");
    fprintf(f, "BYTES\n");
#else
    fprintf(f, "PACKETS     ");
    if (config.what_to_count & COUNT_FLOWS) fprintf(f, "FLOWS       ");
    fprintf(f, "BYTES\n");
#endif
  }
  else fprintf(f, "\n");
}

void P_write_stats_header_csv(FILE *f, int is_event)
{
  char *sep = config.print_output_separator;
  int count = 0;

  if (config.what_to_count & COUNT_TAG) fprintf(f, "%sTAG", write_sep(sep, &count));
  if (config.what_to_count & COUNT_TAG2) fprintf(f, "%sTAG2", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_LABEL) fprintf(f, "%sLABEL", write_sep(sep, &count));
  if (config.what_to_count & COUNT_CLASS) fprintf(f, "%sCLASS", write_sep(sep, &count));
#if defined HAVE_L2
  if (config.what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC)) fprintf(f, "%sSRC_MAC", write_sep(sep, &count));
  if (config.what_to_count & COUNT_DST_MAC) fprintf(f, "%sDST_MAC", write_sep(sep, &count));
  if (config.what_to_count & COUNT_VLAN) fprintf(f, "%sVLAN", write_sep(sep, &count));
  if (config.what_to_count & COUNT_COS) fprintf(f, "%sCOS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_ETHERTYPE) fprintf(f, "%sETYPE", write_sep(sep, &count));
#endif
  if (config.what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) fprintf(f, "%sSRC_AS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_DST_AS) fprintf(f, "%sDST_AS", write_sep(sep, &count));
  if (!config.tmp_comms_same_field) {
    if (config.what_to_count & COUNT_STD_COMM) fprintf(f, "%sCOMMS", write_sep(sep, &count));
    if (config.what_to_count & COUNT_EXT_COMM) fprintf(f, "%sECOMMS", write_sep(sep, &count));
  }
  else {
    if (config.what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM)) fprintf(f, "%sCOMMS", write_sep(sep, &count));
  }
  if (config.what_to_count_2 & COUNT_LRG_COMM) fprintf(f, "%sLCOMMS", write_sep(sep, &count));
  if (!config.tmp_comms_same_field) {
    if (config.what_to_count & COUNT_SRC_STD_COMM) fprintf(f, "%sSRC_COMMS", write_sep(sep, &count));
    if (config.what_to_count & COUNT_SRC_EXT_COMM) fprintf(f, "%sSRC_ECOMMS", write_sep(sep, &count));
  }
  else {
    if (config.what_to_count & (COUNT_SRC_STD_COMM|COUNT_SRC_EXT_COMM)) fprintf(f, "%sSRC_COMMS", write_sep(sep, &count));
  }
  if (config.what_to_count_2 & COUNT_SRC_LRG_COMM) fprintf(f, "%sSRC_LCOMMS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_AS_PATH) fprintf(f, "%sAS_PATH", write_sep(sep, &count));
  if (config.what_to_count & COUNT_SRC_AS_PATH) fprintf(f, "%sSRC_AS_PATH", write_sep(sep, &count));
  if (config.what_to_count & COUNT_LOCAL_PREF) fprintf(f, "%sPREF", write_sep(sep, &count));
  if (config.what_to_count & COUNT_SRC_LOCAL_PREF) fprintf(f, "%sSRC_PREF", write_sep(sep, &count));
  if (config.what_to_count & COUNT_MED) fprintf(f, "%sMED", write_sep(sep, &count));
  if (config.what_to_count & COUNT_SRC_MED) fprintf(f, "%sSRC_MED", write_sep(sep, &count));
  if (config.what_to_count & COUNT_PEER_SRC_AS) fprintf(f, "%sPEER_SRC_AS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_PEER_DST_AS) fprintf(f, "%sPEER_DST_AS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_PEER_SRC_IP) fprintf(f, "%sPEER_SRC_IP", write_sep(sep, &count));
  if (config.what_to_count & COUNT_PEER_DST_IP) fprintf(f, "%sPEER_DST_IP", write_sep(sep, &count));
  if (config.what_to_count & COUNT_IN_IFACE) fprintf(f, "%sIN_IFACE", write_sep(sep, &count));
  if (config.what_to_count & COUNT_OUT_IFACE) fprintf(f, "%sOUT_IFACE", write_sep(sep, &count));
  if (config.what_to_count & COUNT_MPLS_VPN_RD) fprintf(f, "%sMPLS_VPN_RD", write_sep(sep, &count));
  if (!config.tmp_net_own_field) {
    if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) fprintf(f, "%sSRC_IP", write_sep(sep, &count));
    if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET)) fprintf(f, "%sSRC_IP", write_sep(sep, &count));
    if (config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) fprintf(f, "%sDST_IP", write_sep(sep, &count));
  }
  else {
    if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST)) fprintf(f, "%sSRC_IP", write_sep(sep, &count));
    if (config.what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET)) fprintf(f, "%sSRC_NET", write_sep(sep, &count));
    if (config.what_to_count & COUNT_DST_HOST) fprintf(f, "%sDST_IP", write_sep(sep, &count));
    if (config.what_to_count & COUNT_DST_NET) fprintf(f, "%sDST_NET", write_sep(sep, &count));
  }
  if (config.what_to_count & COUNT_SRC_NMASK) fprintf(f, "%sSRC_MASK", write_sep(sep, &count));
  if (config.what_to_count & COUNT_DST_NMASK) fprintf(f, "%sDST_MASK", write_sep(sep, &count));
  if (config.what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) fprintf(f, "%sSRC_PORT", write_sep(sep, &count));
  if (config.what_to_count & COUNT_DST_PORT) fprintf(f, "%sDST_PORT", write_sep(sep, &count));
  if (config.what_to_count & COUNT_TCPFLAGS) fprintf(f, "%sTCP_FLAGS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_IP_PROTO) fprintf(f, "%sPROTOCOL", write_sep(sep, &count));
  if (config.what_to_count & COUNT_IP_TOS) fprintf(f, "%sTOS", write_sep(sep, &count));
#if defined (WITH_GEOIP) || defined (WITH_GEOIPV2)
  if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) fprintf(f, "%sSH_COUNTRY", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) fprintf(f, "%sDH_COUNTRY", write_sep(sep, &count));
#endif
#if defined (WITH_GEOIPV2)
  if (config.what_to_count_2 & COUNT_SRC_HOST_POCODE) fprintf(f, "%sSH_POCODE", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_DST_HOST_POCODE) fprintf(f, "%sDH_POCODE", write_sep(sep, &count));
#endif
  if (config.what_to_count_2 & COUNT_SAMPLING_RATE) fprintf(f, "%sSAMPLING_RATE", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB) fprintf(f, "%sPKT_LEN_DISTRIB", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_POST_NAT_SRC_HOST) fprintf(f, "%sPOST_NAT_SRC_IP", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_POST_NAT_DST_HOST) fprintf(f, "%sPOST_NAT_DST_IP", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_POST_NAT_SRC_PORT) fprintf(f, "%sPOST_NAT_SRC_PORT", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_POST_NAT_DST_PORT) fprintf(f, "%sPOST_NAT_DST_PORT", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_NAT_EVENT) fprintf(f, "%sNAT_EVENT", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_MPLS_LABEL_TOP) fprintf(f, "%sMPLS_LABEL_TOP", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_MPLS_LABEL_BOTTOM) fprintf(f, "%sMPLS_LABEL_BOTTOM", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_MPLS_STACK_DEPTH) fprintf(f, "%sMPLS_STACK_DEPTH", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_TIMESTAMP_START) fprintf(f, "%sTIMESTAMP_START", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_TIMESTAMP_END) fprintf(f, "%sTIMESTAMP_END", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_TIMESTAMP_ARRIVAL) fprintf(f, "%sTIMESTAMP_ARRIVAL", write_sep(sep, &count));
  if (config.nfacctd_stitching) {
    fprintf(f, "%sTIMESTAMP_MIN", write_sep(sep, &count));
    fprintf(f, "%sTIMESTAMP_MAX", write_sep(sep, &count));
  }
  if (config.what_to_count_2 & COUNT_EXPORT_PROTO_SEQNO) fprintf(f, "%sEXPORT_PROTO_SEQNO", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_EXPORT_PROTO_VERSION) fprintf(f, "%sEXPORT_PROTO_VERSION", write_sep(sep, &count));

  /* all custom primitives printed here */
  { 
    char cp_str[SRVBUFLEN];
    int cp_idx;

    for (cp_idx = 0; cp_idx < config.cpptrs.num; cp_idx++) {
      custom_primitive_header_print(cp_str, SRVBUFLEN, &config.cpptrs.primitive[cp_idx], FALSE);
      fprintf(f, "%s%s", write_sep(sep, &count), cp_str);
    }
  }

  if (!is_event) {
    fprintf(f, "%sPACKETS", write_sep(sep, &count));
    if (config.what_to_count & COUNT_FLOWS) fprintf(f, "%sFLOWS", write_sep(sep, &count));
    fprintf(f, "%sBYTES\n", write_sep(sep, &count));
  }
  else fprintf(f, "\n");
}

void P_fprintf_csv_string(FILE *f, struct pkt_vlen_hdr_primitives *pvlen, pm_cfgreg_t wtc, char *sep, char *empty_string)
{
  char *string_ptr = NULL;

  vlen_prims_get(pvlen, wtc, &string_ptr);
  if (!string_ptr) string_ptr = empty_string;
  fprintf(f, "%s%s", sep, string_ptr);
}
