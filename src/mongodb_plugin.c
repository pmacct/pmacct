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

#define __MONGODB_PLUGIN_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "plugin_common.h"
#include "mongodb_plugin.h"
#include "ip_flow.h"
#include "classifier.h"
#include "crc32.h"

/* Functions */
void mongodb_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
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
  pm_setproctitle("%s [%s]", "MongoDB Plugin", config.name);

  P_set_signals();
  P_init_default_values();
  P_config_checks();
  pipebuf = (unsigned char *) pm_malloc(config.buffer_size);
  memset(pipebuf, 0, config.buffer_size);

  if (!config.mongo_insert_batch)
    config.mongo_insert_batch = DEFAULT_MONGO_INSERT_BATCH;

  timeout = config.sql_refresh_time*1000;

  /* setting function pointers */
  if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET))
    insert_func = P_sum_host_insert;
  else if (config.what_to_count & COUNT_SUM_PORT) insert_func = P_sum_port_insert;
  else if (config.what_to_count & COUNT_SUM_AS) insert_func = P_sum_as_insert;
#if defined (HAVE_L2)
  else if (config.what_to_count & COUNT_SUM_MAC) insert_func = P_sum_mac_insert;
#endif
  else insert_func = P_cache_insert;
  purge_func = MongoDB_cache_purge;

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
  P_init_refresh_deadline(&refresh_deadline, config.sql_refresh_time, config.sql_startup_delay, config.sql_history_roundoff);

  if (config.sql_history) {
    basetime_init = P_init_historical_acct;
    basetime_eval = P_eval_historical_acct;
    basetime_cmp = P_cmp_historical_acct;

    (*basetime_init)(idata.now);
  }

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  mongo_init(&db_conn);
  mongo_set_op_timeout(&db_conn, 1000);
  bson_set_oid_fuzz(&MongoDB_oid_fuzz);

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

	    rg->ptr = (rg->base + status->last_buf_off);
            seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
          }
        }

        pollagain = FALSE;
        memcpy(pipebuf, rg->ptr, bufsz);
        status->last_plugin_off = (rg->ptr - rg->base);
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

void MongoDB_cache_purge(struct chained_cache *queue[], int index)
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
  char rd_str[SRVBUFLEN], misc_str[SRVBUFLEN], tmpbuf[LONGLONGSRVBUFLEN], mongo_database[SRVBUFLEN];
  char *str_ptr, *as_path, *bgp_comm, default_table[] = "test.acct";
  char default_user[] = "pmacct", default_passwd[] = "arealsmartpwd";
  int qn = 0, i, j, stop, db_status, batch_idx, go_to_pending, saved_index = index;
  time_t stamp, start, duration;
  char current_table[SRVBUFLEN], elem_table[SRVBUFLEN];
  struct primitives_ptrs prim_ptrs;
  struct pkt_data dummy_data;
  pid_t writer_pid = getpid();

  const bson **bson_batch;
  bson *bson_elem;

  if (!index) {
    Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - START (PID: %u) ***\n", config.name, config.type, writer_pid);
    Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - END (PID: %u, QN: 0/0, ET: 0) ***\n", config.name, config.type, writer_pid);
    return;
  }

  if (config.sql_host)
    db_status = mongo_client(&db_conn, config.sql_host, 27017 /* default port */);
  else
    db_status = mongo_client(&db_conn, "127.0.0.1", 27017 /* default port */);

  if (db_status != MONGO_OK) {
    switch (db_conn.err) {
    case MONGO_CONN_SUCCESS:
      Log(LOG_INFO, "INFO ( %s/%s ): Connection succeeded (MONGO_CONN_SUCCESS) to MongoDB\n", config.name, config.type);
      break;
    case MONGO_CONN_NO_SOCKET:
      Log(LOG_ERR, "ERROR ( %s/%s ): Connection failed to MongoDB: no socket\n", config.name, config.type);
      return;
    case MONGO_CONN_NOT_MASTER:
      Log(LOG_ERR, "ERROR ( %s/%s ): Connection failed to MongoDB: not master\n", config.name, config.type);
      return;
    case MONGO_CONN_FAIL:
    default:
      Log(LOG_ERR, "ERROR ( %s/%s ): Connection failed to MongoDB\n", config.name, config.type);
      return;
    }
  }
  else Log(LOG_INFO, "INFO ( %s/%s ): Connection succeeded (MONGO_OK) to MongoDB\n", config.name, config.type);

  empty_pcust = malloc(config.cpptrs.len);
  if (!empty_pcust) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Unable to malloc() empty_pcust. Exiting.\n", config.name, config.type);
    exit_plugin(1);
  }

  memset(&empty_pbgp, 0, sizeof(struct pkt_bgp_primitives));
  memset(&empty_pnat, 0, sizeof(struct pkt_nat_primitives));
  memset(&empty_pmpls, 0, sizeof(struct pkt_mpls_primitives));
  memset(empty_pcust, 0, config.cpptrs.len);
  memset(mongo_database, 0, sizeof(mongo_database));
  memset(&prim_ptrs, 0, sizeof(prim_ptrs));
  memset(&dummy_data, 0, sizeof(dummy_data));
  memset(tmpbuf, 0, sizeof(tmpbuf));

  if (!config.sql_table || MongoDB_get_database(mongo_database, SRVBUFLEN, config.sql_table)) {
    config.sql_table = default_table;
    Log(LOG_INFO, "INFO ( %s/%s ): mongo_table set to '%s'\n", config.name, config.type, default_table);
  }
  if (strchr(config.sql_table, '%') || strchr(config.sql_table, '$')) dyn_table = TRUE;
  else dyn_table = FALSE;

  bson_batch = (bson **) malloc(sizeof(bson *) * index);
  if (!bson_batch) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed: bson_batch\n", config.name, config.type);
    return;
  }

  /* If there is any signs of auth in the config, then try to auth */
  if (config.sql_user || config.sql_passwd) {
    if (!config.sql_user) config.sql_user = default_user;
    if (!config.sql_passwd) config.sql_passwd = default_passwd;
    db_status = mongo_cmd_authenticate(&db_conn, mongo_database, config.sql_user, config.sql_passwd);
    if (db_status != MONGO_OK) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Authentication failed to MongoDB\n", config.name, config.type);
      return;
    }
    else Log(LOG_INFO, "INFO ( %s/%s ): Successful authentication (MONGO_OK) to MongoDB\n", config.name, config.type);
  }

  Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - START (PID: %u) ***\n", config.name, config.type, writer_pid);
  start = time(NULL);

  for (j = 0, stop = 0; (!stop) && P_preprocess_funcs[j]; j++)
    stop = P_preprocess_funcs[j](queue, &index, j);

  memcpy(pending_queries_queue, queue, index*sizeof(struct db_cache *));
  pqq_ptr = index;

  start:
  memcpy(queue, pending_queries_queue, pqq_ptr*sizeof(struct db_cache *));
  memset(pending_queries_queue, 0, pqq_ptr*sizeof(struct db_cache *));
  index = pqq_ptr; pqq_ptr = 0;

  if (dyn_table) {
    stamp = queue[0]->basetime.tv_sec;
    strlcpy(current_table, config.sql_table, SRVBUFLEN);

    prim_ptrs.data = &dummy_data;
    primptrs_set_all_from_chained_cache(&prim_ptrs, queue[0]);

    handle_dynname_internal_strings_same(tmpbuf, LONGSRVBUFLEN, current_table, &prim_ptrs);
    strftime_same(current_table, LONGSRVBUFLEN, tmpbuf, &stamp);
    if (config.sql_table_schema) MongoDB_create_indexes(&db_conn, tmpbuf);
  }

  for (j = 0, batch_idx = 0; j < index; j++) {
    go_to_pending = FALSE;

    if (queue[j]->valid != PRINT_CACHE_COMMITTED) continue;

    if (dyn_table) {
      time_t stamp = 0;

      memset(tmpbuf, 0, LONGLONGSRVBUFLEN); // XXX: pedantic?
      stamp = queue[j]->basetime.tv_sec;
      strlcpy(elem_table, config.sql_table, SRVBUFLEN);

      prim_ptrs.data = &dummy_data;
      primptrs_set_all_from_chained_cache(&prim_ptrs, queue[j]);
      handle_dynname_internal_strings_same(tmpbuf, LONGSRVBUFLEN, elem_table, &prim_ptrs);
      strftime_same(elem_table, LONGSRVBUFLEN, tmpbuf, &stamp);

      if (strncmp(current_table, elem_table, SRVBUFLEN)) {
        pending_queries_queue[pqq_ptr] = queue[j];

        pqq_ptr++;
        go_to_pending = TRUE;
      }
    }

    if (!go_to_pending) {
      bson_elem = (bson *) malloc(sizeof(bson));
      if (!bson_elem) {
        Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed: bson_elem (elem# %u batch# %u\n", config.name, config.type, j, batch_idx);
        return;
      }

      bson_init(bson_elem);
      bson_append_new_oid(bson_elem, "_id" );

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
  
      if (config.what_to_count & COUNT_TAG) bson_append_long(bson_elem, "tag", data->tag);
      if (config.what_to_count & COUNT_TAG2) bson_append_long(bson_elem, "tag2", data->tag2);
      if (config.what_to_count_2 & COUNT_LABEL) MongoDB_append_string(bson_elem, "label", pvlen, COUNT_INT_LABEL); 

      if (config.what_to_count & COUNT_CLASS) bson_append_string(bson_elem, "class", ((data->class && class[(data->class)-1].id) ? class[(data->class)-1].protocol : "unknown" ));
  #if defined (HAVE_L2)
      if (config.what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC)) {
        etheraddr_string(data->eth_shost, src_mac);
        bson_append_string(bson_elem, "mac_src", src_mac);
      }
      if (config.what_to_count & COUNT_DST_MAC) {
        etheraddr_string(data->eth_dhost, dst_mac);
        bson_append_string(bson_elem, "mac_dst", dst_mac);
      }
  
      if (config.what_to_count & COUNT_VLAN) bson_append_int(bson_elem, "vlan_id", data->vlan_id);
      if (config.what_to_count & COUNT_COS) bson_append_int(bson_elem, "cos", data->cos);
      if (config.what_to_count & COUNT_ETHERTYPE) {
        sprintf(misc_str, "%x", data->etype); 
        bson_append_string(bson_elem, "etype", misc_str);
      }
  #endif
      if (config.what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) bson_append_int(bson_elem, "as_src", data->src_as);
      if (config.what_to_count & COUNT_DST_AS) bson_append_int(bson_elem, "as_dst", data->dst_as);
  
      if (config.what_to_count & COUNT_STD_COMM) {
        vlen_prims_get(pvlen, COUNT_INT_STD_COMM, &str_ptr);
        if (str_ptr) {
          bgp_comm = str_ptr;
          while (bgp_comm) {
            bgp_comm = strchr(str_ptr, ' ');
            if (bgp_comm) *bgp_comm = '_';
          }
        }

        MongoDB_append_string(bson_elem, "comms", pvlen, COUNT_INT_STD_COMM);
      }

      if (config.what_to_count & COUNT_EXT_COMM) {
        vlen_prims_get(pvlen, COUNT_INT_EXT_COMM, &str_ptr);
        if (str_ptr) {
          bgp_comm = str_ptr;
          while (bgp_comm) {
            bgp_comm = strchr(str_ptr, ' ');
            if (bgp_comm) *bgp_comm = '_';
          }
        }

        if (!config.tmp_comms_same_field)
	  MongoDB_append_string(bson_elem, "ecomms", pvlen, COUNT_INT_EXT_COMM);
        else
	  MongoDB_append_string(bson_elem, "comms", pvlen, COUNT_INT_EXT_COMM);
      }

      if (config.what_to_count_2 & COUNT_LRG_COMM) {
        vlen_prims_get(pvlen, COUNT_INT_LRG_COMM, &str_ptr);
        if (str_ptr) {
          bgp_comm = str_ptr;
          while (bgp_comm) {
            bgp_comm = strchr(str_ptr, ' ');
            if (bgp_comm) *bgp_comm = '_';
          }
        }

        MongoDB_append_string(bson_elem, "lcomms", pvlen, COUNT_INT_LRG_COMM);
      }
  
      if (config.what_to_count & COUNT_AS_PATH) {
	vlen_prims_get(pvlen, COUNT_INT_AS_PATH, &str_ptr);
	if (str_ptr) {
	  as_path = str_ptr;
	  while (as_path) {
	    as_path = strchr(str_ptr, ' ');
	    if (as_path) *as_path = '_';
	  }
	}

	MongoDB_append_string(bson_elem, "as_path", pvlen, COUNT_INT_AS_PATH);
      }
  
      if (config.what_to_count & COUNT_LOCAL_PREF) bson_append_int(bson_elem, "local_pref", pbgp->local_pref);
      if (config.what_to_count & COUNT_MED) bson_append_int(bson_elem, "med", pbgp->med);
      if (config.what_to_count & COUNT_PEER_SRC_AS) bson_append_int(bson_elem, "peer_as_src", pbgp->peer_src_as);
      if (config.what_to_count & COUNT_PEER_DST_AS) bson_append_int(bson_elem, "peer_as_dst", pbgp->peer_dst_as);
  
      if (config.what_to_count & COUNT_PEER_SRC_IP) {
        addr_to_str(ip_address, &pbgp->peer_src_ip);
        bson_append_string(bson_elem, "peer_ip_src", ip_address);
      }
      if (config.what_to_count & COUNT_PEER_DST_IP) {
        addr_to_str(ip_address, &pbgp->peer_dst_ip);
        bson_append_string(bson_elem, "peer_ip_dst", ip_address);
      }

      if (config.what_to_count & COUNT_SRC_STD_COMM) {
        vlen_prims_get(pvlen, COUNT_INT_SRC_STD_COMM, &str_ptr);
        if (str_ptr) {
          bgp_comm = str_ptr;
          while (bgp_comm) {
            bgp_comm = strchr(str_ptr, ' ');
            if (bgp_comm) *bgp_comm = '_';
          }
        }

        MongoDB_append_string(bson_elem, "src_comms", pvlen, COUNT_INT_SRC_STD_COMM);
      }

      if (config.what_to_count & COUNT_SRC_EXT_COMM) {
        vlen_prims_get(pvlen, COUNT_INT_SRC_EXT_COMM, &str_ptr);
        if (str_ptr) {
          bgp_comm = str_ptr;
          while (bgp_comm) {
            bgp_comm = strchr(str_ptr, ' ');
            if (bgp_comm) *bgp_comm = '_';
          }
        }

        if (!config.tmp_comms_same_field)
          MongoDB_append_string(bson_elem, "src_ecomms", pvlen, COUNT_INT_SRC_EXT_COMM);
        else
          MongoDB_append_string(bson_elem, "src_comms", pvlen, COUNT_INT_SRC_EXT_COMM);
      }

      if (config.what_to_count_2 & COUNT_SRC_LRG_COMM) {
        vlen_prims_get(pvlen, COUNT_INT_SRC_LRG_COMM, &str_ptr);
        if (str_ptr) {
          bgp_comm = str_ptr;
          while (bgp_comm) {
            bgp_comm = strchr(str_ptr, ' ');
            if (bgp_comm) *bgp_comm = '_';
          }
        }

        MongoDB_append_string(bson_elem, "src_lcomms", pvlen, COUNT_INT_SRC_LRG_COMM);
      }

      if (config.what_to_count & COUNT_SRC_AS_PATH) {
        vlen_prims_get(pvlen, COUNT_INT_SRC_AS_PATH, &str_ptr);
        if (str_ptr) {
          as_path = str_ptr;
          while (as_path) {
            as_path = strchr(str_ptr, ' ');
            if (as_path) *as_path = '_';
          }
        }

        MongoDB_append_string(bson_elem, "src_as_path", pvlen, COUNT_INT_SRC_AS_PATH);
      }

      if (config.what_to_count & COUNT_LOCAL_PREF) bson_append_int(bson_elem, "src_local_pref", pbgp->src_local_pref);
      if (config.what_to_count & COUNT_MED) bson_append_int(bson_elem, "src_med", pbgp->src_med);
  
      if (config.what_to_count & COUNT_IN_IFACE) bson_append_int(bson_elem, "iface_in", data->ifindex_in);
      if (config.what_to_count & COUNT_OUT_IFACE) bson_append_int(bson_elem, "iface_out", data->ifindex_out);
  
      if (config.what_to_count & COUNT_MPLS_VPN_RD) {
        bgp_rd2str(rd_str, &pbgp->mpls_vpn_rd);
        bson_append_string(bson_elem, "mpls_vpn_rd", rd_str);
      }
  
      if (!config.tmp_net_own_field) {
        if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST)) {
          addr_to_str(src_host, &data->src_ip);
          bson_append_string(bson_elem, "ip_src", src_host);
        }

        if (config.what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET)) {
          addr_to_str(src_host, &data->src_net);
          bson_append_string(bson_elem, "ip_src", src_host);
        }
      }
      else {
        if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST)) {
          addr_to_str(src_host, &data->src_ip);
          bson_append_string(bson_elem, "ip_src", src_host);
        }

        if (config.what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET)) {
          addr_to_str(src_host, &data->src_net);
          bson_append_string(bson_elem, "net_src", src_host);
        }
      }

      if (!config.tmp_net_own_field) {
        if (config.what_to_count & COUNT_DST_HOST) {
          addr_to_str(dst_host, &data->dst_ip);
          bson_append_string(bson_elem, "ip_dst", dst_host);
        }

        if (config.what_to_count & COUNT_DST_NET) {
          addr_to_str(dst_host, &data->dst_net);
          bson_append_string(bson_elem, "ip_dst", dst_host);
        }
      }
      else {
        if (config.what_to_count & COUNT_DST_HOST) {
          addr_to_str(dst_host, &data->dst_ip);
          bson_append_string(bson_elem, "ip_dst", dst_host);
        }

        if (config.what_to_count & COUNT_DST_NET) {
          addr_to_str(dst_host, &data->dst_net);
          bson_append_string(bson_elem, "net_dst", dst_host);
        }
      }
  
      if (config.what_to_count & COUNT_SRC_NMASK) bson_append_int(bson_elem, "mask_src", data->src_nmask);
      if (config.what_to_count & COUNT_DST_NMASK) bson_append_int(bson_elem, "mask_dst", data->dst_nmask);
      if (config.what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) bson_append_int(bson_elem, "port_src", data->src_port);
      if (config.what_to_count & COUNT_DST_PORT) bson_append_int(bson_elem, "port_dst", data->dst_port);

  #if defined (WITH_GEOIP)
      if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) {
        if (data->src_ip_country.id > 0)
  	  bson_append_string(bson_elem, "country_ip_src", GeoIP_code_by_id(data->src_ip_country.id));
        else
  	  bson_append_null(bson_elem, "country_ip_src");
      }
      if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) {
        if (data->dst_ip_country.id > 0)
  	  bson_append_string(bson_elem, "country_ip_dst", GeoIP_code_by_id(data->dst_ip_country.id));
        else
  	  bson_append_null(bson_elem, "country_ip_dst");
      }
  #endif
  #if defined (WITH_GEOIPV2)
      if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) {
        if (strlen(data->src_ip_country.str))
          bson_append_string(bson_elem, "country_ip_src", data->src_ip_country.str);
        else
          bson_append_null(bson_elem, "country_ip_src");
      }
      if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) {
        if (strlen(data->dst_ip_country.str))
          bson_append_string(bson_elem, "country_ip_dst", data->dst_ip_country.str);
        else
          bson_append_null(bson_elem, "country_ip_dst");
      }

      if (config.what_to_count_2 & COUNT_SRC_HOST_POCODE) {
        if (strlen(data->src_ip_pocode.str))
          bson_append_string(bson_elem, "pocode_ip_src", data->src_ip_pocode.str);
        else
          bson_append_null(bson_elem, "pocode_ip_src");
      }
      if (config.what_to_count_2 & COUNT_DST_HOST_POCODE) {
        if (strlen(data->dst_ip_pocode.str))
          bson_append_string(bson_elem, "pocode_ip_dst", data->dst_ip_pocode.str);
        else
          bson_append_null(bson_elem, "pocode_ip_dst");
      }
  #endif

      if (config.what_to_count & COUNT_TCPFLAGS) {
        sprintf(misc_str, "%u", queue[j]->tcp_flags);
        bson_append_string(bson_elem, "tcp_flags", misc_str);
      }
  
      if (config.what_to_count & COUNT_IP_PROTO) {
        if (!config.num_protos && (data->proto < protocols_number))
	  bson_append_string(bson_elem, "ip_proto", _protocols[data->proto].name);
        else {
          sprintf(misc_str, "%u", data->proto);
          bson_append_string(bson_elem, "ip_proto", misc_str);
        }
      }
  
      if (config.what_to_count & COUNT_IP_TOS) bson_append_int(bson_elem, "tos", data->tos);
      if (config.what_to_count_2 & COUNT_SAMPLING_RATE) bson_append_int(bson_elem, "sampling_rate", data->sampling_rate);
      if (config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB)
        bson_append_string(bson_elem, "pkt_len_distrib", config.pkt_len_distrib_bins[data->pkt_len_distrib]);
  
      if (config.what_to_count_2 & COUNT_POST_NAT_SRC_HOST) {
        addr_to_str(src_host, &pnat->post_nat_src_ip);
        bson_append_string(bson_elem, "post_nat_ip_src", src_host);
      }
      if (config.what_to_count_2 & COUNT_POST_NAT_DST_HOST) {
        addr_to_str(dst_host, &pnat->post_nat_dst_ip);
        bson_append_string(bson_elem, "post_nat_ip_dst", dst_host);
      }
      if (config.what_to_count_2 & COUNT_POST_NAT_SRC_PORT) bson_append_int(bson_elem, "post_nat_port_src", pnat->post_nat_src_port);
      if (config.what_to_count_2 & COUNT_POST_NAT_DST_PORT) bson_append_int(bson_elem, "post_nat_port_dst", pnat->post_nat_dst_port);
      if (config.what_to_count_2 & COUNT_NAT_EVENT) bson_append_int(bson_elem, "nat_event", pnat->nat_event);
      if (config.what_to_count_2 & COUNT_MPLS_LABEL_TOP) bson_append_int(bson_elem, "mpls_label_top", pmpls->mpls_label_top);
      if (config.what_to_count_2 & COUNT_MPLS_LABEL_BOTTOM) bson_append_int(bson_elem, "mpls_label_bottom", pmpls->mpls_label_bottom);
      if (config.what_to_count_2 & COUNT_MPLS_STACK_DEPTH) bson_append_int(bson_elem, "mpls_stack_depth", pmpls->mpls_stack_depth);
  
      if (config.what_to_count_2 & COUNT_TIMESTAMP_START) {
	if (config.timestamps_since_epoch) {
	  char tstamp_str[SRVBUFLEN];

	  compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_start, TRUE, config.timestamps_since_epoch);
	  bson_append_string(bson_elem, "timestamp_start", tstamp_str);
	}
	else {
          bson_date_t bdate;
  
	  bdate = 1000*pnat->timestamp_start.tv_sec;
	  if (pnat->timestamp_start.tv_usec) bdate += (pnat->timestamp_start.tv_usec/1000);

	  bson_append_date(bson_elem, "timestamp_start", bdate);
	}
      }
      if (config.what_to_count_2 & COUNT_TIMESTAMP_END) {
        if (config.timestamps_since_epoch) {
          char tstamp_str[SRVBUFLEN];

          compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_end, TRUE, config.timestamps_since_epoch);
          bson_append_string(bson_elem, "timestamp_end", tstamp_str);
        }
        else {
          bson_date_t bdate;

          bdate = 1000*pnat->timestamp_end.tv_sec;
          if (pnat->timestamp_end.tv_usec) bdate += (pnat->timestamp_end.tv_usec/1000);

          bson_append_date(bson_elem, "timestamp_end", bdate);
	}
      }
      if (config.what_to_count_2 & COUNT_TIMESTAMP_ARRIVAL) {
        if (config.timestamps_since_epoch) {
          char tstamp_str[SRVBUFLEN];

          compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_arrival, TRUE, config.timestamps_since_epoch);
          bson_append_string(bson_elem, "timestamp_arrival", tstamp_str);
        }
        else {
          bson_date_t bdate;

          bdate = 1000*pnat->timestamp_arrival.tv_sec;
          if (pnat->timestamp_arrival.tv_usec) bdate += (pnat->timestamp_arrival.tv_usec/1000);

          bson_append_date(bson_elem, "timestamp_arrival", bdate);
        }
      }

      if (config.nfacctd_stitching && queue[j]->stitch) {
        if (config.timestamps_since_epoch) {
          char tstamp_str[SRVBUFLEN];

          compose_timestamp(tstamp_str, SRVBUFLEN, &queue[j]->stitch->timestamp_min, TRUE, config.timestamps_since_epoch);
          bson_append_string(bson_elem, "timestamp_min", tstamp_str);

          compose_timestamp(tstamp_str, SRVBUFLEN, &queue[j]->stitch->timestamp_max, TRUE, config.timestamps_since_epoch);
          bson_append_string(bson_elem, "timestamp_max", tstamp_str);
        }
	else {
          bson_date_t bdate_min, bdate_max;

          bdate_min = 1000*queue[j]->stitch->timestamp_min.tv_sec;
          if (queue[j]->stitch->timestamp_min.tv_usec) bdate_min += (queue[j]->stitch->timestamp_min.tv_usec/1000);
          bson_append_date(bson_elem, "timestamp_min", bdate_min);

          bdate_max = 1000*queue[j]->stitch->timestamp_max.tv_sec;
          if (queue[j]->stitch->timestamp_max.tv_usec) bdate_max += (queue[j]->stitch->timestamp_max.tv_usec/1000);
          bson_append_date(bson_elem, "timestamp_max", bdate_max);
	}
      }

      if (config.what_to_count_2 & COUNT_EXPORT_PROTO_SEQNO) bson_append_int(bson_elem, "export_proto_seqno", data->export_proto_seqno);
      if (config.what_to_count_2 & COUNT_EXPORT_PROTO_VERSION) bson_append_int(bson_elem, "export_proto_version", data->export_proto_version);
  
      /* all custom primitives printed here */
      {
        int cp_idx;
  
        for (cp_idx = 0; cp_idx < config.cpptrs.num; cp_idx++) {
	  if (config.cpptrs.primitive[cp_idx].ptr->len != PM_VARIABLE_LENGTH) {
	    char cp_str[SRVBUFLEN];

	    custom_primitive_value_print(cp_str, SRVBUFLEN, pcust, &config.cpptrs.primitive[cp_idx], FALSE);
	    bson_append_string(bson_elem, config.cpptrs.primitive[cp_idx].name, cp_str);
	  }
	  else {
	    char *label_ptr = NULL;

	    vlen_prims_get(pvlen, config.cpptrs.primitive[cp_idx].ptr->type, &label_ptr);
	    if (!label_ptr) bson_append_null(bson_elem, config.cpptrs.primitive[cp_idx].name);
	    else bson_append_string(bson_elem, config.cpptrs.primitive[cp_idx].name, label_ptr);
	  }
        }
      }
  
      if (config.sql_history) {
        bson_append_date(bson_elem, "stamp_inserted", (bson_date_t) 1000*queue[j]->basetime.tv_sec);
        bson_append_date(bson_elem, "stamp_updated", (bson_date_t) 1000*time(NULL));
      }
  
      if (queue[j]->flow_type != NF9_FTYPE_EVENT && queue[j]->flow_type != NF9_FTYPE_OPTION) {
  #if defined HAVE_64BIT_COUNTERS
        bson_append_long(bson_elem, "packets", queue[j]->packet_counter);
        if (config.what_to_count & COUNT_FLOWS) bson_append_long(bson_elem, "flows", queue[j]->flow_counter);
        bson_append_long(bson_elem, "bytes", queue[j]->bytes_counter);
  #else
        bson_append_int(bson_elem, "packets", queue[j]->packet_counter);
        if (config.what_to_count & COUNT_FLOWS) bson_append_int(bson_elem, "flows", queue[j]->flow_counter);
        bson_append_int(bson_elem, "bytes", queue[j]->bytes_counter);
  #endif
      }
  
      bson_finish(bson_elem);
      bson_batch[batch_idx] = bson_elem;
      batch_idx++;
      qn++;
  
      if (config.debug) bson_print(bson_elem);
  
      if (batch_idx == config.mongo_insert_batch) {
	if (dyn_table) db_status = mongo_insert_batch(&db_conn, current_table, bson_batch, batch_idx, NULL, MONGO_CONTINUE_ON_ERROR);
	else db_status = mongo_insert_batch(&db_conn, config.sql_table, bson_batch, batch_idx, NULL, MONGO_CONTINUE_ON_ERROR);
	if (db_status != MONGO_OK) {
   	  Log(LOG_ERR, "ERROR ( %s/%s ): Unable to insert all elements in batch: try a smaller mongo_insert_batch value.\n", config.name, config.type);
	  Log(LOG_ERR, "ERROR ( %s/%s ): Server error: %s. (PID: %u, QN: %u/%u)\n", config.name, config.type, db_conn.lasterrstr, writer_pid, qn, saved_index);
	}
  
        for (i = 0; i < batch_idx; i++) {
          bson_elem = (bson *) bson_batch[i];
          bson_destroy(bson_elem);
          free(bson_elem);
        }
  
        batch_idx = 0;
      }
    }
  }

  /* last round on the lollipop */
  if (batch_idx) {
    if (dyn_table) db_status = mongo_insert_batch(&db_conn, current_table, bson_batch, batch_idx, NULL, MONGO_CONTINUE_ON_ERROR);
    else db_status = mongo_insert_batch(&db_conn, config.sql_table, bson_batch, batch_idx, NULL, MONGO_CONTINUE_ON_ERROR);
    if (db_status != MONGO_OK) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to insert all elements in batch: try a smaller mongo_insert_batch value.\n", config.name, config.type);
      Log(LOG_ERR, "ERROR ( %s/%s ): Server error: %s. (PID: %u, QN: %u/%u)\n", config.name, config.type, db_conn.lasterrstr, writer_pid, qn, saved_index);
    }

    for (i = 0; i < batch_idx; i++) {
      bson_elem = (bson *) bson_batch[i];
      bson_destroy(bson_elem);
      free(bson_elem);
    }

    batch_idx = 0;
  }

  /* If we have pending queries then start again */
  if (pqq_ptr) goto start;

  duration = time(NULL)-start;
  Log(LOG_INFO, "INFO ( %s/%s ): *** Purging cache - END (PID: %u, QN: %u/%u, ET: %u) ***\n",
		config.name, config.type, writer_pid, qn, saved_index, duration);

  if (config.sql_trigger_exec) P_trigger_exec(config.sql_trigger_exec); 

  if (empty_pcust) free(empty_pcust);
}

int MongoDB_get_database(char *db, int dblen, char *db_table)
{
  char *collection_sep = strchr(db_table, '.');

  if (!collection_sep) {
    Log(LOG_WARNING, "WARN ( %s/%s ): mongo_table '%s' is not in <database>.<collection> format.\n", config.name, config.type, config.sql_table);
    return TRUE;
  }
  
  memset(db, 0, dblen);
  *collection_sep = '\0';
  strlcpy(db, db_table, dblen); 
  *collection_sep = '.';

  return FALSE;
}

void MongoDB_create_indexes(mongo *db_conn, const char *table)
{
  bson idx_key[1], *out;
  FILE *f;
  char buf[LARGEBUFLEN];
  char *token, *bufptr;
  int ret;

  f = fopen(config.sql_table_schema, "r");
  if (f) {
    while (!feof(f)) {
      if (fgets(buf, SRVBUFLEN, f)) {
        if (!iscomment(buf) && !isblankline(buf)) {
	  trim_all_spaces(buf);
	  bufptr = buf;
	  bson_init(idx_key);
	  while (token = extract_token(&bufptr, ',')) {
	    bson_append_int(idx_key, token, 1);
	  }
	  bson_finish(idx_key);
	  mongo_create_index(db_conn, table, idx_key, NULL, 0, -1, NULL);
	  bson_destroy(idx_key);
        }
      }
    }

    fclose(f);
  }
  else Log(LOG_WARNING, "WARN ( %s/%s ): mongo_indexes_file '%s' does not exist.\n", config.name, config.type, config.sql_table_schema);
}

void MongoDB_append_string(bson *bson_elem, char *name, struct pkt_vlen_hdr_primitives *pvlen, pm_cfgreg_t wtc)
{
  char *str_ptr = NULL;

  vlen_prims_get(pvlen, wtc, &str_ptr);
  if (str_ptr) bson_append_string(bson_elem, name, str_ptr); 
  else bson_append_null(bson_elem, name);
}

int MongoDB_oid_fuzz()
{
  struct timeval now;
  gettimeofday(&now, NULL);
  srand((int) now.tv_usec);

  return rand();
}
