/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2013 by Paolo Lucente
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
#include "print_plugin.h"
#include "mongodb_plugin.h"
#include "net_aggr.h"
#include "ports_aggr.h"
#include "ip_flow.h"
#include "classifier.h"
#include "crc32.c"

/* Functions */
void mongodb_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct pkt_data *data;
  struct ports_table pt;
  unsigned char *pipebuf;
  struct pollfd pfd;
  time_t t, now;
  int timeout, ret, num; 
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  int datasize = ((struct channels_list_entry *)ptr)->datasize;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  struct networks_file_data nfd;

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;

  struct pkt_bgp_primitives *pbgp;
  struct pkt_nat_primitives *pnat;
  struct extra_primitives extras;
  struct primitives_ptrs prim_ptrs;
  char *dataptr;

  memcpy(&config, cfgptr, sizeof(struct configuration));
  memcpy(&extras, &((struct channels_list_entry *)ptr)->extras, sizeof(struct extra_primitives));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "MongoDB Plugin", config.name);
  if (config.pidfile) write_pid_file_plugin(config.pidfile, config.type, config.name);
  if (config.logfile) {
    fclose(config.logfile_fd);
    config.logfile_fd = open_logfile(config.logfile);
  }

  reload_map = FALSE;

  basetime_init = NULL;
  basetime_eval = NULL;
  basetime_cmp = NULL;
  memset(&basetime, 0, sizeof(basetime));
  memset(&ibasetime, 0, sizeof(ibasetime));
  memset(&sbasetime, 0, sizeof(sbasetime));
  memset(&timeslot, 0, sizeof(timeslot));

  /* signal handling */
  signal(SIGINT, MongoDB_exit_now);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, reload_maps);
  signal(SIGPIPE, SIG_IGN);
#if !defined FBSD4
  signal(SIGCHLD, SIG_IGN);
#else
  signal(SIGCHLD, ignore_falling_child);
#endif

  if (!config.sql_refresh_time)
    config.sql_refresh_time = DEFAULT_PRINT_REFRESH_TIME;

  if (!config.mongo_insert_batch)
    config.mongo_insert_batch = DEFAULT_MONGO_INSERT_BATCH;

  timeout = config.sql_refresh_time*1000;

  /* XXX: reusing cache functions from print plugin -- should get common'ed? */
  if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET))
    insert_func = P_sum_host_insert;
  else if (config.what_to_count & COUNT_SUM_PORT) insert_func = P_sum_port_insert;
  else if (config.what_to_count & COUNT_SUM_AS) insert_func = P_sum_as_insert;
#if defined (HAVE_L2)
  else if (config.what_to_count & COUNT_SUM_MAC) insert_func = P_sum_mac_insert;
#endif
  else insert_func = P_cache_insert;

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
  
  pp_size = sizeof(struct pkt_primitives);
  pb_size = sizeof(struct pkt_bgp_primitives);
  pn_size = sizeof(struct pkt_nat_primitives);
  dbc_size = sizeof(struct chained_cache);
  if (!config.print_cache_entries) config.print_cache_entries = PRINT_CACHE_ENTRIES; 
  memset(&sa, 0, sizeof(struct scratch_area));
  sa.num = config.print_cache_entries*AVERAGE_CHAIN_LEN;
  sa.size = sa.num*dbc_size;

  pipebuf = (unsigned char *) Malloc(config.buffer_size);
  cache = (struct chained_cache *) Malloc(config.print_cache_entries*dbc_size); 
  queries_queue = (struct chained_cache **) Malloc((sa.num+config.print_cache_entries)*sizeof(struct chained_cache *));
  sa.base = (unsigned char *) Malloc(sa.size);
  sa.ptr = sa.base;
  sa.next = NULL;

  pfd.fd = pipe_fd;
  pfd.events = POLLIN;
  setnonblocking(pipe_fd);

  now = time(NULL);

  /* print_refresh time init: deadline */
  refresh_deadline = now; 
  t = roundoff_time(refresh_deadline, config.sql_history_roundoff);
  while ((t+config.sql_refresh_time) < refresh_deadline) t += config.sql_refresh_time;
  refresh_deadline = t;
  refresh_deadline += config.sql_refresh_time; /* it's a deadline not a basetime */

  if (config.sql_history) {
    basetime_init = P_init_historical_acct;
    basetime_eval = P_eval_historical_acct;
    basetime_cmp = P_cmp_historical_acct;

    (*basetime_init)(now);
  }

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  memset(pipebuf, 0, config.buffer_size);
  memset(cache, 0, config.print_cache_entries*sizeof(struct chained_cache));
  memset(queries_queue, 0, (sa.num+config.print_cache_entries)*sizeof(struct chained_cache *));
  memset(sa.base, 0, sa.size);
  memset(&flushtime, 0, sizeof(flushtime));

  mongo_init(&db_conn);
  mongo_set_op_timeout(&db_conn, 1000);

  /* plugin main loop */
  for(;;) {
    poll_again:
    status->wakeup = TRUE;
    ret = poll(&pfd, 1, timeout);

    if (ret <= 0) {
      if (getppid() == 1) {
        Log(LOG_ERR, "ERROR ( %s/%s ): Core process *seems* gone. Exiting.\n", config.name, config.type);
        exit_plugin(1);
      }

      if (ret < 0) goto poll_again;
    }

    now = time(NULL);

    if (config.sql_history) {
      memset(&sbasetime, 0, sizeof(sbasetime));
      while (now > (basetime.tv_sec + timeslot)) {
	sbasetime.tv_sec = basetime.tv_sec;
        basetime.tv_sec += timeslot;
        if (config.sql_history == COUNT_MONTHLY)
          timeslot = calc_monthly_timeslot(basetime.tv_sec, config.sql_history_howmany, ADD);
      }
    }

    switch (ret) {
    case 0: /* timeout */
      if (qq_ptr) {
	switch (ret = fork()) {
	case 0: /* Child */
	  MongoDB_cache_purge(queries_queue, qq_ptr);
          exit(0);
        default: /* Parent */
	  if (ret == -1) Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork writer: %s\n", config.name, config.type, strerror(errno));
          MongoDB_cache_flush(queries_queue, qq_ptr);
	  gettimeofday(&flushtime, NULL);
    	  refresh_deadline += config.sql_refresh_time; 
          qq_ptr = FALSE;
	  if (reload_map) {
	    load_networks(config.networks_file, &nt, &nc);
	    load_ports(config.ports_file, &pt);
	    reload_map = FALSE;
	  }
          break;
        }
      }
      break;
    default: /* we received data */
      read_data:
      if (!pollagain) {
        seq++;
        seq %= MAX_SEQNUM;
        if (seq == 0) rg_err_count = FALSE;
      }
      else {
        if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0) 
	  exit_plugin(1); /* we exit silently; something happened at the write end */
      }

      if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
        if (!pollagain) {
          pollagain = TRUE;
          goto poll_again;
        }
        else {
          rg_err_count++;
          if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
            Log(LOG_ERR, "ERROR ( %s/%s ): We are missing data.\n", config.name, config.type);
            Log(LOG_ERR, "If you see this message once in a while, discard it. Otherwise some solutions follow:\n");
            Log(LOG_ERR, "- increase shared memory size, 'plugin_pipe_size'; now: '%u'.\n", config.pipe_size);
            Log(LOG_ERR, "- increase buffer size, 'plugin_buffer_size'; now: '%u'.\n", config.buffer_size);
            Log(LOG_ERR, "- increase system maximum socket size.\n\n");
          }
          seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
        }
      }

      pollagain = FALSE;
      memcpy(pipebuf, rg->ptr, bufsz);
      if ((rg->ptr+bufsz) >= rg->end) rg->ptr = rg->base;
      else rg->ptr += bufsz;

      /* lazy refresh time handling */ 
      if (now > refresh_deadline) {
        if (qq_ptr) {
          switch (ret = fork()) {
          case 0: /* Child */
            MongoDB_cache_purge(queries_queue, qq_ptr);
            exit(0);
          default: /* Parent */
	    if (ret == -1) Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork writer: %s\n", config.name, config.type, strerror(errno));
            MongoDB_cache_flush(queries_queue, qq_ptr);
	    gettimeofday(&flushtime, NULL);
            refresh_deadline += config.sql_refresh_time; 
            qq_ptr = FALSE;
	    if (reload_map) {
	      load_networks(config.networks_file, &nt, &nc);
	      load_ports(config.ports_file, &pt);
	      reload_map = FALSE;
	    }
            break;
          }
        }
      } 

      data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));

      while (((struct ch_buf_hdr *)pipebuf)->num) {
        if (extras.off_pkt_bgp_primitives)
          pbgp = (struct pkt_bgp_primitives *) ((u_char *)data + extras.off_pkt_bgp_primitives);
        else
          pbgp = NULL;
        if (extras.off_pkt_nat_primitives)
          pnat = (struct pkt_nat_primitives *) ((u_char *)data + extras.off_pkt_nat_primitives);
        else pnat = NULL;

	for (num = 0; net_funcs[num]; num++)
	  (*net_funcs[num])(&nt, &nc, &data->primitives, pbgp, &nfd);

	if (config.ports_file) {
          if (!pt.table[data->primitives.src_port]) data->primitives.src_port = 0;
          if (!pt.table[data->primitives.dst_port]) data->primitives.dst_port = 0;
        }

        if (config.pkt_len_distrib_bins_str &&
            config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB)
          evaluate_pkt_len_distrib(data);

        prim_ptrs.data = data;
        prim_ptrs.pbgp = pbgp;
        prim_ptrs.pnat = pnat;
        (*insert_func)(&prim_ptrs);

	((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) {
          dataptr = (unsigned char *) data;
	  dataptr += datasize;
          data = (struct pkt_data *) dataptr;
	}
      }
      goto read_data;
    }
  }
}

void MongoDB_cache_flush(struct chained_cache *queue[], int index)
{
  int j;

  for (j = 0; j < index; j++) {
    queue[j]->valid = FALSE;
    queue[j]->next = NULL;
  }

  /* rewinding scratch area stuff */
  sa.ptr = sa.base;
}

void MongoDB_cache_purge(struct chained_cache *queue[], int index)
{
  struct pkt_primitives *data = NULL;
  struct pkt_bgp_primitives *pbgp = NULL;
  struct pkt_nat_primitives *pnat = NULL;
  struct pkt_bgp_primitives empty_pbgp;
  struct pkt_nat_primitives empty_pnat;
  char src_mac[18], dst_mac[18], src_host[INET6_ADDRSTRLEN], dst_host[INET6_ADDRSTRLEN], ip_address[INET6_ADDRSTRLEN];
  char rd_str[SRVBUFLEN], misc_str[SRVBUFLEN], tmpbuf[LONGLONGSRVBUFLEN];
  char *as_path, *bgp_comm, empty_aspath[] = "^$", default_table[] = "test.acct";
  int i, j, db_status, batch_idx;

  const bson **bson_batch, **bson_batch_ptr;
  bson *bson_elem;

  if (config.sql_host)
    db_status = mongo_connect(&db_conn, config.sql_host, 27017 /* default port */);
  else
    db_status = mongo_connect(&db_conn, "127.0.0.1", 27017 /* default port */);

  if (db_status != MONGO_OK) {
    switch (db_conn.err) {
    case MONGO_CONN_SUCCESS:
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): Connection succeeded (MONGO_CONN_SUCCESS) to MongoDB\n", config.name, config.type);
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
  else Log(LOG_DEBUG, "DEBUG ( %s/%s ): Connection succeeded (MONGO_OK) to MongoDB\n", config.name, config.type);

  memset(&empty_pbgp, 0, sizeof(struct pkt_bgp_primitives));
  memset(&empty_pnat, 0, sizeof(struct pkt_nat_primitives));

  if (!config.sql_table) config.sql_table = default_table;
  if (strchr(config.sql_table, '%') || strchr(config.sql_table, '$')) dyn_table = TRUE;
  else dyn_table = FALSE;

  bson_batch = (bson **) malloc(sizeof(bson *) * index);
  if (!bson_batch) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed: bson_batch\n", config.name, config.type);
    return;
  }

  if (dyn_table) {
    time_t stamp = sbasetime.tv_sec ? sbasetime.tv_sec : basetime.tv_sec;

    handle_dynname_internal_strings_same(tmpbuf, LONGSRVBUFLEN, config.sql_table);
    strftime_same(config.sql_table, LONGSRVBUFLEN, tmpbuf, &stamp);
  }

  for (j = 0, batch_idx = 0; j < index; j++, batch_idx++) {
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

    if (P_test_zero_elem(queue[j])) continue;

    if (config.what_to_count & COUNT_ID) bson_append_long(bson_elem, "tag", data->id);
    if (config.what_to_count & COUNT_ID2) bson_append_long(bson_elem, "tag2", data->id2);
    if (config.what_to_count & COUNT_CLASS) bson_append_string(bson_elem, "class", ((data->class && class[(data->class)-1].id) ? class[(data->class)-1].protocol : "unknown" ));
#if defined (HAVE_L2)
    if (config.what_to_count & COUNT_SRC_MAC) {
      etheraddr_string(data->eth_shost, src_mac);
      bson_append_string(bson_elem, "mac_src", src_mac);
    }
    if (config.what_to_count & COUNT_DST_MAC) {
      etheraddr_string(data->eth_dhost, dst_mac);
      bson_append_string(bson_elem, "mac_dst", dst_mac);
    }

    if (config.what_to_count & COUNT_VLAN) {
      sprintf(misc_str, "%u", data->vlan_id); 
      bson_append_string(bson_elem, "vlan_id", misc_str);
    }
    if (config.what_to_count & COUNT_COS) {
      sprintf(misc_str, "%u", data->cos); 
      bson_append_string(bson_elem, "cos", misc_str);
    }
    if (config.what_to_count & COUNT_ETHERTYPE) {
      sprintf(misc_str, "%x", data->etype); 
      bson_append_string(bson_elem, "etype", misc_str);
    }
#endif
    if (config.what_to_count & COUNT_SRC_AS) bson_append_int(bson_elem, "as_src", data->src_as);
    if (config.what_to_count & COUNT_DST_AS) bson_append_int(bson_elem, "as_dst", data->dst_as);

    if (config.what_to_count & COUNT_STD_COMM) {
      bgp_comm = pbgp->std_comms;
      while (bgp_comm) {
        bgp_comm = strchr(pbgp->std_comms, ' ');
        if (bgp_comm) *bgp_comm = '_';
      }

      if (strlen(pbgp->std_comms)) 
        bson_append_string(bson_elem, "comms", pbgp->std_comms);
      else
        bson_append_null(bson_elem, "comms");
    }

    if (config.what_to_count & COUNT_AS_PATH) {
      as_path = pbgp->as_path;
      while (as_path) {
        as_path = strchr(pbgp->as_path, ' ');
        if (as_path) *as_path = '_';
      }
      if (strlen(pbgp->as_path))
        bson_append_string(bson_elem, "as_path", pbgp->as_path);
      else
        bson_append_string(bson_elem, "as_path", empty_aspath);
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

    if (config.what_to_count & COUNT_IN_IFACE) bson_append_int(bson_elem, "iface_in", data->ifindex_in);
    if (config.what_to_count & COUNT_OUT_IFACE) bson_append_int(bson_elem, "iface_out", data->ifindex_out);

    if (config.what_to_count & COUNT_MPLS_VPN_RD) {
      bgp_rd2str(rd_str, &pbgp->mpls_vpn_rd);
      bson_append_string(bson_elem, "mpls_vpn_rd", rd_str);
    }

    if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) {
      addr_to_str(src_host, &data->src_ip);
      bson_append_string(bson_elem, "ip_src", src_host);
    }
    if (config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) {
      addr_to_str(dst_host, &data->dst_ip);
      bson_append_string(bson_elem, "ip_dst", dst_host);
    }

    if (config.what_to_count & COUNT_SRC_NMASK) {
      sprintf(misc_str, "%u", data->src_nmask);
      bson_append_string(bson_elem, "mask_src", misc_str);
    }
    if (config.what_to_count & COUNT_DST_NMASK) {
      sprintf(misc_str, "%u", data->dst_nmask);
      bson_append_string(bson_elem, "mask_dst", misc_str);
    }
    if (config.what_to_count & COUNT_SRC_PORT) {
      sprintf(misc_str, "%u", data->src_port);
      bson_append_string(bson_elem, "port_src", misc_str);
    }
    if (config.what_to_count & COUNT_DST_PORT) {
      sprintf(misc_str, "%u", data->dst_port);
      bson_append_string(bson_elem, "port_dst", misc_str);
    }
#if defined (WITH_GEOIP)
    if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) {
      if (data->src_ip_country > 0)
	bson_append_string(bson_elem, "country_ip_src", GeoIP_code_by_id(data->src_ip_country));
      else
	bson_append_null(bson_elem, "country_ip_src");
    }
    if (config.what_to_count & COUNT_DST_HOST_COUNTRY) {
      if (data->dst_ip_country > 0)
	bson_append_string(bson_elem, "country_ip_dst", GeoIP_code_by_id(data->dst_ip_country));
      else
	bson_append_null(bson_elem, "country_ip_dst");
    }
#endif
    if (config.what_to_count & COUNT_TCPFLAGS) {
      sprintf(misc_str, "%u", queue[j]->tcp_flags);
      bson_append_string(bson_elem, "tcp_flags", misc_str);
    }

    if (config.what_to_count & COUNT_IP_PROTO) {
      if (!config.num_protos) bson_append_string(bson_elem, "ip_proto", _protocols[data->proto].name);
      else {
        sprintf(misc_str, "%u", _protocols[data->proto].number);
        bson_append_string(bson_elem, "ip_proto", misc_str);
      }
    }

    if (config.what_to_count & COUNT_IP_TOS) {
      sprintf(misc_str, "%u", data->tos);
      bson_append_string(bson_elem, "tos", misc_str);
    }

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
    if (config.what_to_count_2 & COUNT_POST_NAT_SRC_PORT) {
      sprintf(misc_str, "%u", pnat->post_nat_src_port);
      bson_append_string(bson_elem, "post_nat_port_src", misc_str);
    }
    if (config.what_to_count_2 & COUNT_POST_NAT_DST_PORT) {
      sprintf(misc_str, "%u", pnat->post_nat_dst_port);
      bson_append_string(bson_elem, "post_nat_port_dst", misc_str);
    }
    if (config.what_to_count_2 & COUNT_NAT_EVENT) {
      sprintf(misc_str, "%u", pnat->nat_event);
      bson_append_string(bson_elem, "nat_event", misc_str);
    }

    if (config.what_to_count_2 & COUNT_TIMESTAMP_START) {
      bson_timestamp_t bts;

      bts.t = pnat->timestamp_start.tv_sec;
      bts.i = pnat->timestamp_start.tv_usec;
      bson_append_timestamp(bson_elem, "timestamp_start", &bts);
    }
    if (config.what_to_count_2 & COUNT_TIMESTAMP_END) {
      bson_timestamp_t bts;

      bts.t = pnat->timestamp_end.tv_sec;
      bts.i = pnat->timestamp_end.tv_usec;
      bson_append_timestamp(bson_elem, "timestamp_end", &bts);
    }

    if (config.sql_history) {
      bson_append_date(bson_elem, "stamp_inserted", (bson_date_t) 1000*queue[j]->basetime.tv_sec);
      bson_append_date(bson_elem, "stamp_updated", (bson_date_t) 1000*time(NULL));
    }

    if (queue[j]->flow_type != NF9_FTYPE_EVENT) {
#if defined HAVE_64BIT_COUNTERS
      bson_append_long(bson_elem, "packets", queue[j]->packet_counter);
      bson_append_long(bson_elem, "flows", queue[j]->flow_counter);
      bson_append_long(bson_elem, "bytes", queue[j]->bytes_counter);
#else
      bson_append_int(bson_elem, "packets", queue[j]->packet_counter);
      bson_append_int(bson_elem, "flows", queue[j]->flow_counter);
      bson_append_int(bson_elem, "bytes", queue[j]->bytes_counter);
#endif
    }

    bson_finish(bson_elem);
    bson_batch[j] = bson_elem;

    if (config.debug) bson_print(bson_elem);

    if (batch_idx == config.mongo_insert_batch) {
      bson_batch_ptr = &bson_batch[j-batch_idx];

      if (dyn_table) mongo_insert_batch(&db_conn, tmpbuf, bson_batch_ptr, batch_idx, NULL, MONGO_CONTINUE_ON_ERROR);
      else mongo_insert_batch(&db_conn, config.sql_table, bson_batch_ptr, batch_idx, NULL, MONGO_CONTINUE_ON_ERROR);

      for (i = j-batch_idx; i < j; i++) {
        bson_elem = (bson *) bson_batch[i];
        bson_destroy(bson_elem);
        free(bson_elem);
      }

      batch_idx = 0;
    }
  }

  /* last round on the lollipop */
  if (batch_idx) {
    bson_batch_ptr = &bson_batch[j-batch_idx];

    if (dyn_table) mongo_insert_batch(&db_conn, tmpbuf, bson_batch_ptr, batch_idx, NULL, MONGO_CONTINUE_ON_ERROR);
    else mongo_insert_batch(&db_conn, config.sql_table, bson_batch_ptr, batch_idx, NULL, MONGO_CONTINUE_ON_ERROR);

    for (i = j-batch_idx; i < j; i++) {
      bson_elem = (bson *) bson_batch[i];
      bson_destroy(bson_elem);
      free(bson_elem);
    }

    batch_idx = 0;
  }

  if (config.sql_trigger_exec) MongoDB_trigger_exec(config.sql_trigger_exec); 
}

void MongoDB_exit_now(int signum)
{
  MongoDB_cache_purge(queries_queue, qq_ptr);

  wait(NULL);
  exit_plugin(0);
}

int MongoDB_trigger_exec(char *filename)
{
  char *args[1];
  int pid;

  memset(args, 0, sizeof(args));

  switch (pid = vfork()) {
  case -1:
    return -1;
  case 0:
    execv(filename, args);
    exit(0);
  }

  return 0;
}
