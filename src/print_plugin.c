/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2012 by Paolo Lucente
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
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "print_plugin.h"
#include "net_aggr.h"
#include "ports_aggr.h"
#include "ip_flow.h"
#include "classifier.h"
#include "crc32.c"

/* Functions */
void print_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct pkt_data *data;
  struct ports_table pt;
  unsigned char *pipebuf;
  struct pollfd pfd;
  time_t t, now;
  int timeout, ret, num; 
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;

  struct pkt_bgp_primitives *pbgp;
  char *dataptr;

  memcpy(&config, cfgptr, sizeof(struct configuration));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "Print Plugin", config.name);
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
  memset(&timeslot, 0, sizeof(timeslot));

  /* signal handling */
  signal(SIGINT, P_exit_now);
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

  if (!config.print_output)
    config.print_output = PRINT_OUTPUT_FORMATTED;

  timeout = config.sql_refresh_time*1000;

  if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET))
    insert_func = P_sum_host_insert;
  else if (config.what_to_count & COUNT_SUM_PORT) insert_func = P_sum_port_insert;
  else if (config.what_to_count & COUNT_SUM_AS) insert_func = P_sum_as_insert;
#if defined (HAVE_L2)
  else if (config.what_to_count & COUNT_SUM_MAC) insert_func = P_sum_mac_insert;
#endif
  else insert_func = P_cache_insert;

  /* Dirty but allows to save some IFs, centralizes
     checks and makes later comparison statements lean */
  if (!(config.what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM|COUNT_LOCAL_PREF|COUNT_MED|COUNT_AS_PATH|
                                COUNT_PEER_SRC_AS|COUNT_PEER_DST_AS|COUNT_PEER_SRC_IP|COUNT_PEER_DST_IP|
				COUNT_SRC_STD_COMM|COUNT_SRC_EXT_COMM|COUNT_SRC_AS_PATH|COUNT_SRC_MED|
				COUNT_SRC_LOCAL_PREF|COUNT_MPLS_VPN_RD)))
    PbgpSz = 0;

  memset(&nt, 0, sizeof(nt));
  memset(&nc, 0, sizeof(nc));
  memset(&pt, 0, sizeof(pt));

  load_networks(config.networks_file, &nt, &nc);
  set_net_funcs(&nt);

  if (config.ports_file) load_ports(config.ports_file, &pt);
  
  pp_size = sizeof(struct pkt_primitives);
  pb_size = sizeof(struct pkt_bgp_primitives);
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

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  memset(pipebuf, 0, config.buffer_size);
  memset(cache, 0, config.print_cache_entries*sizeof(struct chained_cache));
  memset(queries_queue, 0, (sa.num+config.print_cache_entries)*sizeof(struct chained_cache *));
  memset(sa.base, 0, sa.size);
  memset(&flushtime, 0, sizeof(flushtime));

  if (!config.sql_table && config.print_output == PRINT_OUTPUT_FORMATTED)
    P_write_stats_header_formatted(stdout);
  else if (!config.sql_table && config.print_output == PRINT_OUTPUT_CSV)
    P_write_stats_header_csv(stdout);

  /* plugin main loop */
  for(;;) {
    poll_again:
    status->wakeup = TRUE;
    calc_refresh_timeout(refresh_deadline, now, &timeout);
    ret = poll(&pfd, 1, timeout);
    if (ret < 0) goto poll_again;

    now = time(NULL);

    switch (ret) {
    case 0: /* timeout */
      switch (fork()) {
      case 0: /* Child */
	P_cache_purge(queries_queue, qq_ptr);
	exit(0);
      default: /* Parent */
        P_cache_flush(queries_queue, qq_ptr);
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
          switch (fork()) {
          case 0: /* Child */
            P_cache_purge(queries_queue, qq_ptr);
            exit(0);
          default: /* Parent */
            P_cache_flush(queries_queue, qq_ptr);
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
	for (num = 0; net_funcs[num]; num++)
	  (*net_funcs[num])(&nt, &nc, &data->primitives);

	if (config.ports_file) {
          if (!pt.table[data->primitives.src_port]) data->primitives.src_port = 0;
          if (!pt.table[data->primitives.dst_port]) data->primitives.dst_port = 0;
        }

        if (PbgpSz) pbgp = (struct pkt_bgp_primitives *) ((u_char *)data+PdataSz);
        else pbgp = NULL;

        (*insert_func)(data, pbgp);

	((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) {
          dataptr = (unsigned char *) data;
          dataptr += PdataSz + PbgpSz;
          data = (struct pkt_data *) dataptr;
	}
      }
      goto read_data;
    }
  }
}

unsigned int P_cache_modulo(struct pkt_primitives *srcdst, struct pkt_bgp_primitives *pbgp)
{
  register unsigned int modulo;

  modulo = cache_crc32((unsigned char *)srcdst, pp_size);
  if (PbgpSz) {
    if (pbgp) modulo ^= cache_crc32((unsigned char *)pbgp, pb_size);
  }
  
  return modulo %= config.print_cache_entries;
}

struct chained_cache *P_cache_search(struct pkt_primitives *data, struct pkt_bgp_primitives *pbgp)
{
  unsigned int modulo = P_cache_modulo(data, pbgp);
  struct chained_cache *cache_ptr = &cache[modulo];
  int res_data = TRUE, res_bgp = TRUE, res_time = TRUE;

  start:
  res_data = memcmp(&cache_ptr->primitives, data, sizeof(struct pkt_primitives));

  if (basetime_cmp) {
    res_time = (*basetime_cmp)(&cache_ptr->basetime, &ibasetime);
  }
  else res_time = FALSE;

  if (PbgpSz) {
    if (cache_ptr->pbgp) res_bgp = memcmp(cache_ptr->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
  }
  else res_bgp = FALSE;

  if (res_data || res_bgp || res_time) {
    if (cache_ptr->valid == TRUE) {
      if (cache_ptr->next) {
        cache_ptr = cache_ptr->next;
        goto start;
      }
    }
  }
  else return cache_ptr; 

  return NULL;
}

void P_cache_insert(struct pkt_data *data, struct pkt_bgp_primitives *pbgp)
{
  unsigned int modulo = P_cache_modulo(&data->primitives, pbgp);
  struct chained_cache *cache_ptr = &cache[modulo];
  struct pkt_primitives *srcdst = &data->primitives;
  int res_data, res_bgp, res_time;

  if (config.sql_history && (*basetime_eval)) {
    memcpy(&ibasetime, &basetime, sizeof(ibasetime));
    (*basetime_eval)(&data->time_start, &ibasetime, timeslot);
  }

  /* We are classifing packets. We have a non-zero bytes accumulator (ba)
     and a non-zero class. Before accounting ba to this class, we have to
     remove ba from class zero. */
  if (config.what_to_count & COUNT_CLASS && data->cst.ba && data->primitives.class) {
    struct chained_cache *Cursor;
    pm_class_t lclass = data->primitives.class;

    data->primitives.class = 0;
    Cursor = P_cache_search(&data->primitives, pbgp);
    data->primitives.class = lclass;

    /* We can assign the flow to a new class only if we are able to subtract
       the accumulator from the zero-class. If this is not the case, we will
       discard the accumulators. The assumption is that accumulators are not
       retroactive */

    if (Cursor) {
      if (timeval_cmp(&data->cst.stamp, &flushtime) >= 0) {
	/* MIN(): ToS issue */
        Cursor->bytes_counter -= MIN(Cursor->bytes_counter, data->cst.ba);
        Cursor->packet_counter -= MIN(Cursor->packet_counter, data->cst.pa);
        Cursor->flow_counter -= MIN(Cursor->flow_counter, data->cst.fa);
      }
      else memset(&data->cst, 0, CSSz);
    }
    else memset(&data->cst, 0, CSSz);
  }

  start:
  res_data = res_bgp = res_time = TRUE;

  res_data = memcmp(&cache_ptr->primitives, srcdst, sizeof(struct pkt_primitives)); 

  if (basetime_cmp) {
    res_time = (*basetime_cmp)(&cache_ptr->basetime, &ibasetime);
  }
  else res_time = FALSE;

  if (PbgpSz) {
    if (cache_ptr->pbgp) res_bgp = memcmp(cache_ptr->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
  }
  else res_bgp = FALSE;

  if (res_data || res_bgp || res_time) {
    /* aliasing of entries */
    if (cache_ptr->valid == TRUE) { 
      if (cache_ptr->next) {
	cache_ptr = cache_ptr->next;
	goto start;
      }
      else {
	cache_ptr = P_cache_attach_new_node(cache_ptr); 
	if (!cache_ptr) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): Unable to write data: try with a larger 'print_cache_entries' value.\n", 
			  config.name, config.type);
	  return; 
	}
	else {
	  queries_queue[qq_ptr] = cache_ptr;
	  qq_ptr++;
	}
      }
    }
    else {
      queries_queue[qq_ptr] = cache_ptr;
      qq_ptr++;
    }

    /* we add the new entry in the cache */
    memcpy(&cache_ptr->primitives, srcdst, sizeof(struct pkt_primitives));
    if (PbgpSz) {
      if (!cache_ptr->pbgp) cache_ptr->pbgp = (struct pkt_bgp_primitives *) malloc(PbgpSz);
      memcpy(cache_ptr->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
    }
    else cache_ptr->pbgp = NULL;
    cache_ptr->packet_counter = data->pkt_num;
    cache_ptr->flow_counter = data->flo_num;
    cache_ptr->bytes_counter = data->pkt_len;
    cache_ptr->tcp_flags = data->tcp_flags;
    if (config.what_to_count & COUNT_CLASS) {
      cache_ptr->bytes_counter += data->cst.ba;
      cache_ptr->packet_counter += data->cst.pa;
      cache_ptr->flow_counter += data->cst.fa;
    }
    cache_ptr->valid = TRUE;
    cache_ptr->basetime.tv_sec = ibasetime.tv_sec;
    cache_ptr->basetime.tv_usec = ibasetime.tv_usec;
  }
  else {
    if (cache_ptr->valid == TRUE) {
      /* everything is ok; summing counters */
      cache_ptr->packet_counter += data->pkt_num;
      cache_ptr->flow_counter += data->flo_num;
      cache_ptr->bytes_counter += data->pkt_len;
      cache_ptr->tcp_flags |= data->tcp_flags;
      if (config.what_to_count & COUNT_CLASS) {
        cache_ptr->bytes_counter += data->cst.ba;
        cache_ptr->packet_counter += data->cst.pa;
        cache_ptr->flow_counter += data->cst.fa;
      }
    }
    else {
      /* entry invalidated; restarting counters */
      cache_ptr->packet_counter = data->pkt_num;
      cache_ptr->flow_counter = data->flo_num;
      cache_ptr->bytes_counter = data->pkt_len;
      cache_ptr->tcp_flags = data->tcp_flags;
      if (config.what_to_count & COUNT_CLASS) {
        cache_ptr->bytes_counter += data->cst.ba;
        cache_ptr->packet_counter += data->cst.pa;
        cache_ptr->flow_counter += data->cst.fa;
      }
      cache_ptr->valid = TRUE;
      cache_ptr->basetime.tv_sec = ibasetime.tv_sec;
      cache_ptr->basetime.tv_usec = ibasetime.tv_usec;
      queries_queue[qq_ptr] = cache_ptr;
      qq_ptr++;
    }
  }
}

void P_cache_flush(struct chained_cache *queue[], int index)
{
  int j;

  for (j = 0; j < index; j++) {
    queue[j]->valid = FALSE;
    queue[j]->next = NULL;
  }

  /* rewinding scratch area stuff */
  sa.ptr = sa.base;
}

struct chained_cache *P_cache_attach_new_node(struct chained_cache *elem)
{
  if ((sa.ptr+sizeof(struct chained_cache)) <= (sa.base+sa.size)) {
    sa.ptr += sizeof(struct chained_cache);
    elem->next = (struct chained_cache *) sa.ptr;
    return (struct chained_cache *) sa.ptr;
  }
  else return NULL; /* XXX */
}

void P_cache_purge(struct chained_cache *queue[], int index)
{
  struct pkt_primitives *data = NULL;
  struct pkt_bgp_primitives *pbgp = NULL;
  struct pkt_bgp_primitives empty_pbgp;
  char src_mac[18], dst_mac[18], src_host[INET6_ADDRSTRLEN], dst_host[INET6_ADDRSTRLEN], ip_address[INET6_ADDRSTRLEN];
  char rd_str[SRVBUFLEN];
  char *as_path, *bgp_comm, empty_aspath[] = "^$";
  FILE *f = NULL;
  int j;

  memset(&empty_pbgp, 0, sizeof(struct pkt_bgp_primitives));

  if (config.sql_table) {
    f = open_print_output_file(config.sql_table, refresh_deadline-config.sql_refresh_time);

    if (f) { 
      if (config.print_output == PRINT_OUTPUT_FORMATTED)
        P_write_stats_header_formatted(f);
      else if (config.print_output == PRINT_OUTPUT_CSV)
        P_write_stats_header_csv(f);
    }
  }
  else f = stdout; /* write to standard output */

  if (f && config.print_markers) fprintf(f, "--START (%ld+%d)--\n", refresh_deadline-config.sql_refresh_time,
		  			config.sql_refresh_time);

  for (j = 0; j < index; j++) {
    data = &queue[j]->primitives;
    if (queue[j]->pbgp) pbgp = queue[j]->pbgp;
    else pbgp = &empty_pbgp;

    if (!queue[j]->bytes_counter && !queue[j]->packet_counter && !queue[j]->flow_counter)
      continue;

    if (f && config.print_output == PRINT_OUTPUT_FORMATTED) {
      if (config.what_to_count & COUNT_ID) fprintf(f, "%-10llu  ", data->id);
      if (config.what_to_count & COUNT_ID2) fprintf(f, "%-10llu  ", data->id2);
      if (config.what_to_count & COUNT_CLASS) fprintf(f, "%-16s  ", ((data->class && class[(data->class)-1].id) ? class[(data->class)-1].protocol : "unknown" ));
#if defined (HAVE_L2)
      if (config.what_to_count & COUNT_SRC_MAC) {
        etheraddr_string(data->eth_shost, src_mac);
        fprintf(f, "%-17s  ", src_mac);
      }
      if (config.what_to_count & COUNT_DST_MAC) {
        etheraddr_string(data->eth_dhost, dst_mac);
        fprintf(f, "%-17s  ", dst_mac);
      }
      if (config.what_to_count & COUNT_VLAN) fprintf(f, "%-5u  ", data->vlan_id); 
      if (config.what_to_count & COUNT_COS) fprintf(f, "%-2u  ", data->cos); 
      if (config.what_to_count & COUNT_ETHERTYPE) fprintf(f, "%-5x  ", data->etype); 
#endif
      if (config.what_to_count & COUNT_SRC_AS) fprintf(f, "%-10u  ", data->src_as); 
      if (config.what_to_count & COUNT_DST_AS) fprintf(f, "%-10u  ", data->dst_as); 

      if (config.what_to_count & COUNT_STD_COMM) { 
        bgp_comm = pbgp->std_comms;
        while (bgp_comm) {
          bgp_comm = strchr(pbgp->std_comms, ' ');
          if (bgp_comm) *bgp_comm = '_';
        }

        if (strlen(pbgp->std_comms)) 
          fprintf(f, "%-22s   ", pbgp->std_comms);
        else
	  fprintf(f, "%-22u   ", 0);
      }

      if (config.what_to_count & COUNT_AS_PATH) {
        as_path = pbgp->as_path;
        while (as_path) {
	  as_path = strchr(pbgp->as_path, ' ');
	  if (as_path) *as_path = '_';
        }
        if (strlen(pbgp->as_path))
	  fprintf(f, "%-22s   ", pbgp->as_path);
        else
	  fprintf(f, "%-22s   ", empty_aspath);
      }

      if (config.what_to_count & COUNT_LOCAL_PREF) fprintf(f, "%-5u  ", pbgp->local_pref);
      if (config.what_to_count & COUNT_MED) fprintf(f, "%-5u  ", pbgp->med);
      if (config.what_to_count & COUNT_PEER_SRC_AS) fprintf(f, "%-10u  ", pbgp->peer_src_as);
      if (config.what_to_count & COUNT_PEER_DST_AS) fprintf(f, "%-10u  ", pbgp->peer_dst_as);

      if (config.what_to_count & COUNT_PEER_SRC_IP) {
        addr_to_str(ip_address, &pbgp->peer_src_ip);
#if defined ENABLE_IPV6
        fprintf(f, "%-45s  ", ip_address);
#else
        fprintf(f, "%-15s  ", ip_address);
#endif
      }
      if (config.what_to_count & COUNT_PEER_DST_IP) {
        addr_to_str(ip_address, &pbgp->peer_dst_ip);
#if defined ENABLE_IPV6
        fprintf(f, "%-45s  ", ip_address);
#else
        fprintf(f, "%-15s  ", ip_address);
#endif
      }

      if (config.what_to_count & COUNT_IN_IFACE) fprintf(f, "%-10u  ", data->ifindex_in);
      if (config.what_to_count & COUNT_OUT_IFACE) fprintf(f, "%-10u  ", data->ifindex_out);

      if (config.what_to_count & COUNT_MPLS_VPN_RD) {
        bgp_rd2str(rd_str, &pbgp->mpls_vpn_rd);
        fprintf(f, "%-18s  ", rd_str);
      }

      if (config.what_to_count & COUNT_SRC_HOST) {
        addr_to_str(src_host, &data->src_ip);
#if defined ENABLE_IPV6
        fprintf(f, "%-45s  ", src_host);
#else
        fprintf(f, "%-15s  ", src_host);
#endif
      }
      if (config.what_to_count & COUNT_DST_HOST) {
        addr_to_str(dst_host, &data->dst_ip);
#if defined ENABLE_IPV6
        fprintf(f, "%-45s  ", dst_host);
#else
        fprintf(f, "%-15s  ", dst_host);
#endif
      }
      if (config.what_to_count & COUNT_SRC_NMASK) fprintf(f, "%-3u       ", data->src_nmask);
      if (config.what_to_count & COUNT_DST_NMASK) fprintf(f, "%-3u       ", data->dst_nmask);
      if (config.what_to_count & COUNT_SRC_PORT) fprintf(f, "%-5u     ", data->src_port);
      if (config.what_to_count & COUNT_DST_PORT) fprintf(f, "%-5u     ", data->dst_port);
      if (config.what_to_count & COUNT_TCPFLAGS) fprintf(f, "%-3u        ", queue[j]->tcp_flags);

      if (config.what_to_count & COUNT_IP_PROTO) {
        if (!config.num_protos) fprintf(f, "%-10s  ", _protocols[data->proto].name);
        else  fprintf(f, "%-10d  ", _protocols[data->proto].number);
      }

      if (config.what_to_count & COUNT_IP_TOS) fprintf(f, "%-3u    ", data->tos);
      if (config.what_to_count & COUNT_SAMPLING_RATE) fprintf(f, "%-7u       ", data->sampling_rate);
#if defined HAVE_64BIT_COUNTERS
      fprintf(f, "%-20llu  ", queue[j]->packet_counter);
      fprintf(f, "%-20llu  ", queue[j]->flow_counter);
      fprintf(f, "%llu\n", queue[j]->bytes_counter);
#else
      fprintf(f, "%-10lu  ", queue[j]->packet_counter);
      fprintf(f, "%-10lu  ", queue[j]->flow_counter);
      fprintf(f, "%lu\n", queue[j]->bytes_counter);
#endif
    }
    else if (f && config.print_output == PRINT_OUTPUT_CSV) {
      if (config.what_to_count & COUNT_ID) fprintf(f, "%llu,", data->id);
      if (config.what_to_count & COUNT_ID2) fprintf(f, "%llu,", data->id2);
      if (config.what_to_count & COUNT_CLASS) fprintf(f, "%s,", ((data->class && class[(data->class)-1].id) ? class[(data->class)-1].protocol : "unknown" ));
#if defined (HAVE_L2)
      if (config.what_to_count & COUNT_SRC_MAC) {
        etheraddr_string(data->eth_shost, src_mac);
        fprintf(f, "%s,", src_mac);
      }
      if (config.what_to_count & COUNT_DST_MAC) {
        etheraddr_string(data->eth_dhost, dst_mac);
        fprintf(f, "%s,", dst_mac);
      }
      if (config.what_to_count & COUNT_VLAN) fprintf(f, "%u,", data->vlan_id); 
      if (config.what_to_count & COUNT_COS) fprintf(f, "%u,", data->cos); 
      if (config.what_to_count & COUNT_ETHERTYPE) fprintf(f, "%x,", data->etype); 
#endif
      if (config.what_to_count & COUNT_SRC_AS) fprintf(f, "%u,", data->src_as); 
      if (config.what_to_count & COUNT_DST_AS) fprintf(f, "%u,", data->dst_as); 

      if (config.what_to_count & COUNT_STD_COMM) {
        bgp_comm = pbgp->std_comms;
        while (bgp_comm) {
          bgp_comm = strchr(pbgp->std_comms, ' ');
          if (bgp_comm) *bgp_comm = '_';
        }

        if (strlen(pbgp->std_comms)) 
          fprintf(f, "%s,", pbgp->std_comms);
        else
          fprintf(f, "%u,", 0);
      }

      if (config.what_to_count & COUNT_AS_PATH) {
        as_path = pbgp->as_path;
        while (as_path) {
	  as_path = strchr(pbgp->as_path, ' ');
	  if (as_path) *as_path = '_';
        }
        fprintf(f, "%s,", pbgp->as_path);
      }

      if (config.what_to_count & COUNT_LOCAL_PREF) fprintf(f, "%u,", pbgp->local_pref);
      if (config.what_to_count & COUNT_MED) fprintf(f, "%u,", pbgp->med);
      if (config.what_to_count & COUNT_PEER_SRC_AS) fprintf(f, "%u,", pbgp->peer_src_as);
      if (config.what_to_count & COUNT_PEER_DST_AS) fprintf(f, "%u,", pbgp->peer_dst_as);

      if (config.what_to_count & COUNT_PEER_SRC_IP) {
        addr_to_str(ip_address, &pbgp->peer_src_ip);
        fprintf(f, "%s,", ip_address);
      }
      if (config.what_to_count & COUNT_PEER_DST_IP) {
        addr_to_str(ip_address, &pbgp->peer_dst_ip);
        fprintf(f, "%s,", ip_address);
      }

      if (config.what_to_count & COUNT_IN_IFACE) fprintf(f, "%u,", data->ifindex_in);
      if (config.what_to_count & COUNT_OUT_IFACE) fprintf(f, "%u,", data->ifindex_out);

      if (config.what_to_count & COUNT_MPLS_VPN_RD) {
        bgp_rd2str(rd_str, &pbgp->mpls_vpn_rd);
        fprintf(f, "%s,", rd_str);
      }

      if (config.what_to_count & COUNT_SRC_HOST) {
        addr_to_str(src_host, &data->src_ip);
        fprintf(f, "%s,", src_host);
      }
      if (config.what_to_count & COUNT_DST_HOST) {
        addr_to_str(dst_host, &data->dst_ip);
        fprintf(f, "%s,", dst_host);
      }

      if (config.what_to_count & COUNT_SRC_NMASK) fprintf(f, "%u,", data->src_nmask);
      if (config.what_to_count & COUNT_DST_NMASK) fprintf(f, "%u,", data->dst_nmask);
      if (config.what_to_count & COUNT_SRC_PORT) fprintf(f, "%u,", data->src_port);
      if (config.what_to_count & COUNT_DST_PORT) fprintf(f, "%u,", data->dst_port);
      if (config.what_to_count & COUNT_TCPFLAGS) fprintf(f, "%u,", queue[j]->tcp_flags);

      if (config.what_to_count & COUNT_IP_PROTO) {
        if (!config.num_protos) fprintf(f, "%s,", _protocols[data->proto].name);
        else fprintf(f, "%d,", _protocols[data->proto].number);
      }

      if (config.what_to_count & COUNT_IP_TOS) fprintf(f, "%u,", data->tos);
      if (config.what_to_count & COUNT_SAMPLING_RATE) fprintf(f, "%u,", data->sampling_rate);
#if defined HAVE_64BIT_COUNTERS
      fprintf(f, "%llu,", queue[j]->packet_counter);
      fprintf(f, "%llu,", queue[j]->flow_counter);
      fprintf(f, "%llu\n", queue[j]->bytes_counter);
#else
      fprintf(f, "%lu,", queue[j]->packet_counter);
      fprintf(f, "%lu,", queue[j]->flow_counter);
      fprintf(f, "%lu\n", queue[j]->bytes_counter);
#endif
    }
  }

  if (f && config.print_markers) fprintf(f, "--END--\n");

  if (f && config.sql_table) close_print_output_file(f, config.sql_table, refresh_deadline-config.sql_refresh_time);

  if (config.sql_trigger_exec) P_trigger_exec(config.sql_trigger_exec); 
}

void P_write_stats_header_formatted(FILE *f)
{
  if (config.what_to_count & COUNT_ID) fprintf(f, "TAG         ");
  if (config.what_to_count & COUNT_ID2) fprintf(f, "TAG2        ");
  if (config.what_to_count & COUNT_CLASS) fprintf(f, "CLASS             ");
#if defined HAVE_L2
  if (config.what_to_count & COUNT_SRC_MAC) fprintf(f, "SRC_MAC            ");
  if (config.what_to_count & COUNT_DST_MAC) fprintf(f, "DST_MAC            ");
  if (config.what_to_count & COUNT_VLAN) fprintf(f, "VLAN   ");
  if (config.what_to_count & COUNT_COS) fprintf(f, "COS ");
  if (config.what_to_count & COUNT_ETHERTYPE) fprintf(f, "ETYPE  ");
#endif
  if (config.what_to_count & COUNT_SRC_AS) fprintf(f, "SRC_AS      ");
  if (config.what_to_count & COUNT_DST_AS) fprintf(f, "DST_AS      ");
  if (config.what_to_count & COUNT_STD_COMM) fprintf(f, "BGP_COMMS                ");
  if (config.what_to_count & COUNT_AS_PATH) fprintf(f, "AS_PATH                  ");
  if (config.what_to_count & COUNT_LOCAL_PREF) fprintf(f, "PREF   ");
  if (config.what_to_count & COUNT_MED) fprintf(f, "MED    ");
  if (config.what_to_count & COUNT_PEER_SRC_AS) fprintf(f, "PEER_SRC_AS ");
  if (config.what_to_count & COUNT_PEER_DST_AS) fprintf(f, "PEER_DST_AS ");
  if (config.what_to_count & COUNT_PEER_SRC_IP) fprintf(f, "PEER_SRC_IP      ");
  if (config.what_to_count & COUNT_PEER_DST_IP) fprintf(f, "PEER_DST_IP      ");
  if (config.what_to_count & COUNT_IN_IFACE) fprintf(f, "IN_IFACE    ");
  if (config.what_to_count & COUNT_OUT_IFACE) fprintf(f, "OUT_IFACE   ");
  if (config.what_to_count & COUNT_MPLS_VPN_RD) fprintf(f, "MPLS_VPN_RD         ");
#if defined ENABLE_IPV6
  if (config.what_to_count & COUNT_SRC_HOST) fprintf(f, "SRC_IP                                         ");
  if (config.what_to_count & COUNT_DST_HOST) fprintf(f, "DST_IP                                         ");
#else
  if (config.what_to_count & COUNT_SRC_HOST) fprintf(f, "SRC_IP           ");
  if (config.what_to_count & COUNT_DST_HOST) fprintf(f, "DST_IP           ");
#endif
  if (config.what_to_count & COUNT_SRC_NMASK) fprintf(f, "SRC_MASK  ");
  if (config.what_to_count & COUNT_DST_NMASK) fprintf(f, "DST_MASK  ");
  if (config.what_to_count & COUNT_SRC_PORT) fprintf(f, "SRC_PORT  ");
  if (config.what_to_count & COUNT_DST_PORT) fprintf(f, "DST_PORT  ");
  if (config.what_to_count & COUNT_TCPFLAGS) fprintf(f, "TCP_FLAGS  ");
  if (config.what_to_count & COUNT_IP_PROTO) fprintf(f, "PROTOCOL    ");
  if (config.what_to_count & COUNT_IP_TOS) fprintf(f, "TOS    ");
  if (config.what_to_count & COUNT_SAMPLING_RATE) fprintf(f, "SAMPLING_RATE ");
#if defined HAVE_64BIT_COUNTERS
  fprintf(f, "PACKETS               ");
  fprintf(f, "FLOWS                 ");
  fprintf(f, "BYTES\n");
#else
  fprintf(f, "PACKETS     ");
  fprintf(f, "FLOWS       ");
  fprintf(f, "BYTES\n");
#endif
}

void P_write_stats_header_csv(FILE *f)
{
  if (config.what_to_count & COUNT_ID) fprintf(f, "TAG,");
  if (config.what_to_count & COUNT_ID2) fprintf(f, "TAG2,");
  if (config.what_to_count & COUNT_CLASS) fprintf(f, "CLASS,");
#if defined HAVE_L2
  if (config.what_to_count & COUNT_SRC_MAC) fprintf(f, "SRC_MAC,");
  if (config.what_to_count & COUNT_DST_MAC) fprintf(f, "DST_MAC,");
  if (config.what_to_count & COUNT_VLAN) fprintf(f, "VLAN,");
  if (config.what_to_count & COUNT_COS) fprintf(f, "COS,");
  if (config.what_to_count & COUNT_ETHERTYPE) fprintf(f, "ETYPE,");
#endif
  if (config.what_to_count & COUNT_SRC_AS) fprintf(f, "SRC_AS,");
  if (config.what_to_count & COUNT_DST_AS) fprintf(f, "DST_AS,");
  if (config.what_to_count & COUNT_STD_COMM) fprintf(f, "BGP_COMMS,");
  if (config.what_to_count & COUNT_AS_PATH) fprintf(f, "AS_PATH,");
  if (config.what_to_count & COUNT_LOCAL_PREF) fprintf(f, "PREF,");
  if (config.what_to_count & COUNT_MED) fprintf(f, "MED,");
  if (config.what_to_count & COUNT_PEER_SRC_AS) fprintf(f, "PEER_SRC_AS,");
  if (config.what_to_count & COUNT_PEER_DST_AS) fprintf(f, "PEER_DST_AS,");
  if (config.what_to_count & COUNT_PEER_SRC_IP) fprintf(f, "PEER_SRC_IP,");
  if (config.what_to_count & COUNT_PEER_DST_IP) fprintf(f, "PEER_DST_IP,");
  if (config.what_to_count & COUNT_IN_IFACE) fprintf(f, "IN_IFACE,");
  if (config.what_to_count & COUNT_OUT_IFACE) fprintf(f, "OUT_IFACE,");
  if (config.what_to_count & COUNT_MPLS_VPN_RD) fprintf(f, "MPLS_VPN_RD,");
  if (config.what_to_count & COUNT_SRC_HOST) fprintf(f, "SRC_IP,");
  if (config.what_to_count & COUNT_DST_HOST) fprintf(f, "DST_IP,");
  if (config.what_to_count & COUNT_SRC_NMASK) fprintf(f, "SRC_MASK,");
  if (config.what_to_count & COUNT_DST_NMASK) fprintf(f, "DST_MASK,");
  if (config.what_to_count & COUNT_SRC_PORT) fprintf(f, "SRC_PORT,");
  if (config.what_to_count & COUNT_DST_PORT) fprintf(f, "DST_PORT,");
  if (config.what_to_count & COUNT_TCPFLAGS) fprintf(f, "TCP_FLAGS,");
  if (config.what_to_count & COUNT_IP_PROTO) fprintf(f, "PROTOCOL,");
  if (config.what_to_count & COUNT_IP_TOS) fprintf(f, "TOS,");
  if (config.what_to_count & COUNT_SAMPLING_RATE) fprintf(f, "SAMPLING_RATE,");
  fprintf(f, "PACKETS,");
  fprintf(f, "FLOWS,");
  fprintf(f, "BYTES\n");
}

void P_sum_host_insert(struct pkt_data *data, struct pkt_bgp_primitives *pbgp)
{
  struct in_addr ip;
#if defined ENABLE_IPV6
  struct in6_addr ip6;
#endif

  if (data->primitives.dst_ip.family == AF_INET) {
    ip.s_addr = data->primitives.dst_ip.address.ipv4.s_addr;
    data->primitives.dst_ip.address.ipv4.s_addr = 0;
    data->primitives.dst_ip.family = 0;
    P_cache_insert(data, pbgp);
    data->primitives.src_ip.address.ipv4.s_addr = ip.s_addr;
    P_cache_insert(data, pbgp);
  }
#if defined ENABLE_IPV6
  if (data->primitives.dst_ip.family == AF_INET6) {
    memcpy(&ip6, &data->primitives.dst_ip.address.ipv6, sizeof(struct in6_addr));
    memset(&data->primitives.dst_ip.address.ipv6, 0, sizeof(struct in6_addr));
    data->primitives.dst_ip.family = 0;
    P_cache_insert(data, pbgp);
    memcpy(&data->primitives.src_ip.address.ipv6, &ip6, sizeof(struct in6_addr));
    P_cache_insert(data, pbgp);
    return;
  }
#endif
}

void P_sum_port_insert(struct pkt_data *data, struct pkt_bgp_primitives *pbgp)
{
  u_int16_t port;

  port = data->primitives.dst_port;
  data->primitives.dst_port = 0;
  P_cache_insert(data, pbgp);
  data->primitives.src_port = port;
  P_cache_insert(data, pbgp);
}

void P_sum_as_insert(struct pkt_data *data, struct pkt_bgp_primitives *pbgp)
{
  as_t asn;

  asn = data->primitives.dst_as;
  data->primitives.dst_as = 0;
  P_cache_insert(data, pbgp);
  data->primitives.src_as = asn;
  P_cache_insert(data, pbgp);
}

#if defined (HAVE_L2)
void P_sum_mac_insert(struct pkt_data *data, struct pkt_bgp_primitives *pbgp)
{
  u_char macaddr[ETH_ADDR_LEN];

  memcpy(macaddr, &data->primitives.eth_dhost, ETH_ADDR_LEN);
  memset(data->primitives.eth_dhost, 0, ETH_ADDR_LEN);
  P_cache_insert(data, pbgp);
  memcpy(&data->primitives.eth_shost, macaddr, ETH_ADDR_LEN);
  P_cache_insert(data, pbgp);
}
#endif

void P_exit_now(int signum)
{
  P_cache_purge(queries_queue, qq_ptr);

  wait(NULL);
  exit_plugin(0);
}

int P_trigger_exec(char *filename)
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

void P_init_historical_acct(time_t now)
{
  time_t t = 0;

  basetime.tv_sec = now;
  basetime.tv_usec = 0;

  if (config.sql_history == COUNT_MINUTELY) timeslot = config.sql_history_howmany*60;
  else if (config.sql_history == COUNT_HOURLY) timeslot = config.sql_history_howmany*3600;
  else if (config.sql_history == COUNT_DAILY) timeslot = config.sql_history_howmany*86400;
  else if (config.sql_history == COUNT_WEEKLY) timeslot = config.sql_history_howmany*86400*7;
  else if (config.sql_history == COUNT_MONTHLY) {
    basetime.tv_sec = roundoff_time(basetime.tv_sec, "d"); /* resetting day of month */
    timeslot = calc_monthly_timeslot(basetime.tv_sec, config.sql_history_howmany, ADD);
  }

  /* round off stuff */
  t = roundoff_time(basetime.tv_sec, config.sql_history_roundoff);

  while ((t+timeslot) < basetime.tv_sec) {
    t += timeslot;
    if (config.sql_history == COUNT_MONTHLY) timeslot = calc_monthly_timeslot(t, config.sql_history_howmany, ADD);
  }

  basetime.tv_sec = t;
}

void P_eval_historical_acct(struct timeval *stamp, struct timeval *basetime, time_t timeslot)
{
  if (stamp->tv_sec) {
    while (basetime->tv_sec > stamp->tv_sec) {
      if (config.sql_history != COUNT_MONTHLY) basetime->tv_sec -= timeslot;
      else {
        timeslot = calc_monthly_timeslot(basetime->tv_sec, config.sql_history_howmany, SUB);
        basetime->tv_sec -= timeslot;
      }
    }
    while ((basetime->tv_sec+timeslot) < stamp->tv_sec) {
      if (config.sql_history != COUNT_MONTHLY) basetime->tv_sec += timeslot;
      else {
        basetime->tv_sec += timeslot;
        timeslot = calc_monthly_timeslot(basetime->tv_sec, config.sql_history_howmany, ADD);
      }
    }
  }
}

int P_cmp_historical_acct(struct timeval *entry_basetime, struct timeval *insert_basetime)
{
  int ret = TRUE;

  ret = memcmp(entry_basetime, insert_basetime, sizeof(struct timeval));

  return ret;
}
