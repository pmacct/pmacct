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
  int timeout, ret, num, is_event;
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  int datasize = ((struct channels_list_entry *)ptr)->datasize;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  struct networks_file_data nfd;
  char default_separator[] = ",";

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;

  struct extra_primitives extras;
  struct pkt_bgp_primitives *pbgp;
  struct pkt_nat_primitives *pnat;
  struct primitives_ptrs prim_ptrs;
  char *dataptr;

  memcpy(&config, cfgptr, sizeof(struct configuration));
  memcpy(&extras, &((struct channels_list_entry *)ptr)->extras, sizeof(struct extra_primitives));
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

  is_event = FALSE;
  if (!config.print_output)
    config.print_output = PRINT_OUTPUT_FORMATTED;
  else if (config.print_output & PRINT_OUTPUT_EVENT)
    is_event = TRUE;

  timeout = config.sql_refresh_time*1000;

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

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  memset(pipebuf, 0, config.buffer_size);
  memset(cache, 0, config.print_cache_entries*sizeof(struct chained_cache));
  memset(queries_queue, 0, (sa.num+config.print_cache_entries)*sizeof(struct chained_cache *));
  memset(sa.base, 0, sa.size);
  memset(&flushtime, 0, sizeof(flushtime));

  if (!config.print_output_separator) config.print_output_separator = default_separator;

  if (!config.sql_table && config.print_output & PRINT_OUTPUT_FORMATTED)
    P_write_stats_header_formatted(stdout, is_event);
  else if (!config.sql_table && config.print_output & PRINT_OUTPUT_CSV)
    P_write_stats_header_csv(stdout, is_event);

  /* plugin main loop */
  for(;;) {
    poll_again:
    status->wakeup = TRUE;
    calc_refresh_timeout(refresh_deadline, now, &timeout);
    ret = poll(&pfd, 1, timeout);

    if (ret <= 0) {
      if (getppid() == 1) {
        Log(LOG_ERR, "ERROR ( %s/%s ): Core process *seems* gone. Exiting.\n", config.name, config.type);
        exit_plugin(1);
      }

      if (ret < 0) goto poll_again;
    }

    now = time(NULL);

    switch (ret) {
    case 0: /* timeout */
      switch (ret = fork()) {
      case 0: /* Child */
	P_cache_purge(queries_queue, qq_ptr);
	exit(0);
      default: /* Parent */
        if (ret == -1) Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork writer: %s\n", config.name, config.type, strerror(errno));
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
          switch (ret = fork()) {
          case 0: /* Child */
            P_cache_purge(queries_queue, qq_ptr);
            exit(0);
          default: /* Parent */
	    if (ret == -1) Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork writer: %s\n", config.name, config.type, strerror(errno));
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

unsigned int P_cache_modulo(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *pdata = prim_ptrs->data;
  struct pkt_primitives *srcdst = &pdata->primitives;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  register unsigned int modulo;

  modulo = cache_crc32((unsigned char *)srcdst, pp_size);
  if (pbgp) modulo ^= cache_crc32((unsigned char *)pbgp, pb_size);
  if (pnat) modulo ^= cache_crc32((unsigned char *)pnat, pn_size);
  
  return modulo %= config.print_cache_entries;
}

struct chained_cache *P_cache_search(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *pdata = prim_ptrs->data;
  struct pkt_primitives *data = &pdata->primitives;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  unsigned int modulo = P_cache_modulo(prim_ptrs);
  struct chained_cache *cache_ptr = &cache[modulo];
  int res_data = TRUE, res_bgp = TRUE, res_nat = TRUE, res_time = TRUE;

  start:
  res_data = memcmp(&cache_ptr->primitives, data, sizeof(struct pkt_primitives));

  if (basetime_cmp) {
    res_time = (*basetime_cmp)(&cache_ptr->basetime, &ibasetime);
  }
  else res_time = FALSE;

  if (pbgp) {
    if (cache_ptr->pbgp) res_bgp = memcmp(cache_ptr->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
  }
  else res_bgp = FALSE;

  if (pnat) {
    if (cache_ptr->pnat) res_nat = memcmp(cache_ptr->pnat, pnat, sizeof(struct pkt_nat_primitives));
  }
  else res_nat = FALSE;

  if (res_data || res_bgp || res_nat || res_time) {
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

void P_cache_insert(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  unsigned int modulo = P_cache_modulo(prim_ptrs);
  struct chained_cache *cache_ptr = &cache[modulo];
  struct pkt_primitives *srcdst = &data->primitives;
  int res_data, res_bgp, res_nat, res_time;

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
    Cursor = P_cache_search(prim_ptrs);
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
  res_data = res_bgp = res_nat = res_time = TRUE;

  res_data = memcmp(&cache_ptr->primitives, srcdst, sizeof(struct pkt_primitives)); 

  if (basetime_cmp) {
    res_time = (*basetime_cmp)(&cache_ptr->basetime, &ibasetime);
  }
  else res_time = FALSE;

  if (pbgp) {
    if (cache_ptr->pbgp) res_bgp = memcmp(cache_ptr->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
  }
  else res_bgp = FALSE;

  if (pnat) {
    if (cache_ptr->pnat) res_nat = memcmp(cache_ptr->pnat, pnat, sizeof(struct pkt_nat_primitives));
  }
  else res_nat = FALSE;

  if (res_data || res_bgp || res_nat || res_time) {
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
    if (pbgp) {
      if (!cache_ptr->pbgp) cache_ptr->pbgp = (struct pkt_bgp_primitives *) malloc(PbgpSz);
      memcpy(cache_ptr->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
    }
    else cache_ptr->pbgp = NULL;

    if (pnat) {
      if (!cache_ptr->pnat) cache_ptr->pnat = (struct pkt_nat_primitives *) malloc(PnatSz);
      memcpy(cache_ptr->pnat, pnat, sizeof(struct pkt_nat_primitives));
    }
    else cache_ptr->pnat = NULL;

    cache_ptr->packet_counter = data->pkt_num;
    cache_ptr->flow_counter = data->flo_num;
    cache_ptr->bytes_counter = data->pkt_len;
    cache_ptr->flow_type = data->flow_type;
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
      cache_ptr->flow_type = data->flow_type;
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
      cache_ptr->flow_type = data->flow_type;
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
  struct pkt_nat_primitives *pnat = NULL;
  struct pkt_bgp_primitives empty_pbgp;
  struct pkt_nat_primitives empty_pnat;
  char src_mac[18], dst_mac[18], src_host[INET6_ADDRSTRLEN], dst_host[INET6_ADDRSTRLEN], ip_address[INET6_ADDRSTRLEN];
  char rd_str[SRVBUFLEN], *sep = config.print_output_separator;
  char *as_path, *bgp_comm, empty_aspath[] = "^$", empty_ip4[] = "0.0.0.0", empty_ip6[] = "::";
  char empty_macaddress[] = "00:00:00:00:00:00", empty_rd[] = "0:0";
  FILE *f = NULL;
  int j, is_event = FALSE;

  memset(&empty_pbgp, 0, sizeof(struct pkt_bgp_primitives));
  memset(&empty_pnat, 0, sizeof(struct pkt_nat_primitives));

  if (config.print_output & PRINT_OUTPUT_EVENT) is_event = TRUE;

  if (config.sql_table) {
    f = open_print_output_file(config.sql_table, refresh_deadline-config.sql_refresh_time);

    if (f) { 
      if (config.print_output & PRINT_OUTPUT_FORMATTED)
        P_write_stats_header_formatted(f, is_event);
      else if (config.print_output & PRINT_OUTPUT_CSV)
        P_write_stats_header_csv(f, is_event);
    }
  }
  else f = stdout; /* write to standard output */

  if (f && config.print_markers) fprintf(f, "--START (%ld+%d)--\n", refresh_deadline-config.sql_refresh_time,
		  			config.sql_refresh_time);

  for (j = 0; j < index; j++) {
    int count = 0;

    data = &queue[j]->primitives;
    if (queue[j]->pbgp) pbgp = queue[j]->pbgp;
    else pbgp = &empty_pbgp;

    if (queue[j]->pnat) pnat = queue[j]->pnat;
    else pnat = &empty_pnat;

    if (P_test_zero_elem(queue[j])) continue;

    if (f && config.print_output & PRINT_OUTPUT_FORMATTED) {
      if (config.what_to_count & COUNT_ID) fprintf(f, "%-10llu  ", data->id);
      if (config.what_to_count & COUNT_ID2) fprintf(f, "%-10llu  ", data->id2);
      if (config.what_to_count & COUNT_CLASS) fprintf(f, "%-16s  ", ((data->class && class[(data->class)-1].id) ? class[(data->class)-1].protocol : "unknown" ));
#if defined (HAVE_L2)
      if (config.what_to_count & COUNT_SRC_MAC) {
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

      if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) {
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
      if (config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) {
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

#if defined WITH_GEOIP
      if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) fprintf(f, "%-5s       ", GeoIP_code_by_id(data->src_ip_country));
      if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) fprintf(f, "%-5s       ", GeoIP_code_by_id(data->dst_ip_country));
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

      if (config.what_to_count_2 & COUNT_TIMESTAMP_START) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;

          time1 = pnat->timestamp_start.tv_sec;
          time2 = localtime(&time1);
          strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
          snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, pnat->timestamp_start.tv_usec);
          fprintf(f, "%-30s ", buf2);
        }

      if (config.what_to_count_2 & COUNT_TIMESTAMP_END) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;
      
          time1 = pnat->timestamp_end.tv_sec;
          time2 = localtime(&time1);
          strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
          snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, pnat->timestamp_end.tv_usec);
          fprintf(f, "%-30s ", buf2);
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
      if (config.what_to_count & COUNT_ID) fprintf(f, "%s%llu", write_sep(sep, &count), data->id);
      if (config.what_to_count & COUNT_ID2) fprintf(f, "%s%llu", write_sep(sep, &count), data->id2);
      if (config.what_to_count & COUNT_CLASS) fprintf(f, "%s%s", write_sep(sep, &count), ((data->class && class[(data->class)-1].id) ? class[(data->class)-1].protocol : "unknown" ));
#if defined (HAVE_L2)
      if (config.what_to_count & COUNT_SRC_MAC) {
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
      if (config.what_to_count & COUNT_SRC_AS) fprintf(f, "%s%u", write_sep(sep, &count), data->src_as); 
      if (config.what_to_count & COUNT_DST_AS) fprintf(f, "%s%u", write_sep(sep, &count), data->dst_as); 

      if (config.what_to_count & COUNT_STD_COMM) {
        bgp_comm = pbgp->std_comms;
        while (bgp_comm) {
          bgp_comm = strchr(pbgp->std_comms, ' ');
          if (bgp_comm) *bgp_comm = '_';
        }

        if (strlen(pbgp->std_comms)) 
          fprintf(f, "%s%s", write_sep(sep, &count), pbgp->std_comms);
        else
          fprintf(f, "%s%u", write_sep(sep, &count), 0);
      }

      if (config.what_to_count & COUNT_AS_PATH) {
        as_path = pbgp->as_path;
        while (as_path) {
	  as_path = strchr(pbgp->as_path, ' ');
	  if (as_path) *as_path = '_';
        }
        fprintf(f, "%s%s", write_sep(sep, &count), pbgp->as_path);
      }

      if (config.what_to_count & COUNT_LOCAL_PREF) fprintf(f, "%s%u", write_sep(sep, &count), pbgp->local_pref);
      if (config.what_to_count & COUNT_MED) fprintf(f, "%s%u", write_sep(sep, &count), pbgp->med);
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

      if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) {
        addr_to_str(src_host, &data->src_ip);
        fprintf(f, "%s%s", write_sep(sep, &count), src_host);
      }
      if (config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) {
        addr_to_str(dst_host, &data->dst_ip);
        fprintf(f, "%s%s", write_sep(sep, &count), dst_host);
      }

      if (config.what_to_count & COUNT_SRC_NMASK) fprintf(f, "%s%u", write_sep(sep, &count), data->src_nmask);
      if (config.what_to_count & COUNT_DST_NMASK) fprintf(f, "%s%u", write_sep(sep, &count), data->dst_nmask);
      if (config.what_to_count & COUNT_SRC_PORT) fprintf(f, "%s%u", write_sep(sep, &count), data->src_port);
      if (config.what_to_count & COUNT_DST_PORT) fprintf(f, "%s%u", write_sep(sep, &count), data->dst_port);
      if (config.what_to_count & COUNT_TCPFLAGS) fprintf(f, "%s%u", write_sep(sep, &count), queue[j]->tcp_flags);

      if (config.what_to_count & COUNT_IP_PROTO) {
        if (!config.num_protos) fprintf(f, "%s%s", write_sep(sep, &count), _protocols[data->proto].name);
        else fprintf(f, "%s%d", write_sep(sep, &count), _protocols[data->proto].number);
      }

      if (config.what_to_count & COUNT_IP_TOS) fprintf(f, "%s%u", write_sep(sep, &count), data->tos);

#if defined WITH_GEOIP
      if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) fprintf(f, "%s%s", write_sep(sep, &count), GeoIP_code_by_id(data->src_ip_country));
      if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) fprintf(f, "%s%s", write_sep(sep, &count), GeoIP_code_by_id(data->dst_ip_country));
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

      if (config.what_to_count_2 & COUNT_TIMESTAMP_START) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;

          time1 = pnat->timestamp_start.tv_sec;
          time2 = localtime(&time1);
          strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
          snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, pnat->timestamp_start.tv_usec);
          fprintf(f, "%s%s", write_sep(sep, &count), buf2);
      }

      if (config.what_to_count_2 & COUNT_TIMESTAMP_END) {
          char buf1[SRVBUFLEN], buf2[SRVBUFLEN];
          time_t time1;
          struct tm *time2;

          time1 = pnat->timestamp_end.tv_sec;
          time2 = localtime(&time1);
          strftime(buf1, SRVBUFLEN, "%Y-%m-%d %H:%M:%S", time2);
          snprintf(buf2, SRVBUFLEN, "%s.%u", buf1, pnat->timestamp_end.tv_usec);
          fprintf(f, "%s%s", write_sep(sep, &count), buf2);
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
  }

  if (f && config.print_markers) fprintf(f, "--END--\n");

  if (f && config.sql_table) close_print_output_file(f, config.sql_table, refresh_deadline-config.sql_refresh_time);

  if (config.sql_trigger_exec) P_trigger_exec(config.sql_trigger_exec); 
}

void P_write_stats_header_formatted(FILE *f, int is_event)
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
  if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) fprintf(f, "SRC_IP                                         ");
  if (config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) fprintf(f, "DST_IP                                         ");
#else
  if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) fprintf(f, "SRC_IP           ");
  if (config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) fprintf(f, "DST_IP           ");
#endif
  if (config.what_to_count & COUNT_SRC_NMASK) fprintf(f, "SRC_MASK  ");
  if (config.what_to_count & COUNT_DST_NMASK) fprintf(f, "DST_MASK  ");
  if (config.what_to_count & COUNT_SRC_PORT) fprintf(f, "SRC_PORT  ");
  if (config.what_to_count & COUNT_DST_PORT) fprintf(f, "DST_PORT  ");
  if (config.what_to_count & COUNT_TCPFLAGS) fprintf(f, "TCP_FLAGS  ");
  if (config.what_to_count & COUNT_IP_PROTO) fprintf(f, "PROTOCOL    ");
  if (config.what_to_count & COUNT_IP_TOS) fprintf(f, "TOS    ");
#if defined WITH_GEOIP
  if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) fprintf(f, "SH_COUNTRY  ");
  if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) fprintf(f, "DH_COUNTRY  ");
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
  if (config.what_to_count_2 & COUNT_TIMESTAMP_START) fprintf(f, "TIMESTAMP_START                ");
  if (config.what_to_count_2 & COUNT_TIMESTAMP_END) fprintf(f, "TIMESTAMP_END                  "); 

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

  if (config.what_to_count & COUNT_ID) fprintf(f, "%sTAG", write_sep(sep, &count));
  if (config.what_to_count & COUNT_ID2) fprintf(f, "%sTAG2", write_sep(sep, &count));
  if (config.what_to_count & COUNT_CLASS) fprintf(f, "%sCLASS", write_sep(sep, &count));
#if defined HAVE_L2
  if (config.what_to_count & COUNT_SRC_MAC) fprintf(f, "%sSRC_MAC", write_sep(sep, &count));
  if (config.what_to_count & COUNT_DST_MAC) fprintf(f, "%sDST_MAC", write_sep(sep, &count));
  if (config.what_to_count & COUNT_VLAN) fprintf(f, "%sVLAN", write_sep(sep, &count));
  if (config.what_to_count & COUNT_COS) fprintf(f, "%sCOS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_ETHERTYPE) fprintf(f, "%sETYPE", write_sep(sep, &count));
#endif
  if (config.what_to_count & COUNT_SRC_AS) fprintf(f, "%sSRC_AS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_DST_AS) fprintf(f, "%sDST_AS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_STD_COMM) fprintf(f, "%sBGP_COMMS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_AS_PATH) fprintf(f, "%sAS_PATH", write_sep(sep, &count));
  if (config.what_to_count & COUNT_LOCAL_PREF) fprintf(f, "%sPREF", write_sep(sep, &count));
  if (config.what_to_count & COUNT_MED) fprintf(f, "%sMED", write_sep(sep, &count));
  if (config.what_to_count & COUNT_PEER_SRC_AS) fprintf(f, "%sPEER_SRC_AS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_PEER_DST_AS) fprintf(f, "%sPEER_DST_AS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_PEER_SRC_IP) fprintf(f, "%sPEER_SRC_IP", write_sep(sep, &count));
  if (config.what_to_count & COUNT_PEER_DST_IP) fprintf(f, "%sPEER_DST_IP", write_sep(sep, &count));
  if (config.what_to_count & COUNT_IN_IFACE) fprintf(f, "%sIN_IFACE", write_sep(sep, &count));
  if (config.what_to_count & COUNT_OUT_IFACE) fprintf(f, "%sOUT_IFACE", write_sep(sep, &count));
  if (config.what_to_count & COUNT_MPLS_VPN_RD) fprintf(f, "%sMPLS_VPN_RD", write_sep(sep, &count));
  if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) fprintf(f, "%sSRC_IP", write_sep(sep, &count));
  if (config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) fprintf(f, "%sDST_IP", write_sep(sep, &count));
  if (config.what_to_count & COUNT_SRC_NMASK) fprintf(f, "%sSRC_MASK", write_sep(sep, &count));
  if (config.what_to_count & COUNT_DST_NMASK) fprintf(f, "%sDST_MASK", write_sep(sep, &count));
  if (config.what_to_count & COUNT_SRC_PORT) fprintf(f, "%sSRC_PORT", write_sep(sep, &count));
  if (config.what_to_count & COUNT_DST_PORT) fprintf(f, "%sDST_PORT", write_sep(sep, &count));
  if (config.what_to_count & COUNT_TCPFLAGS) fprintf(f, "%sTCP_FLAGS", write_sep(sep, &count));
  if (config.what_to_count & COUNT_IP_PROTO) fprintf(f, "%sPROTOCOL", write_sep(sep, &count));
  if (config.what_to_count & COUNT_IP_TOS) fprintf(f, "%sTOS", write_sep(sep, &count));
#if defined WITH_GEOIP
  if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) fprintf(f, "%sSH_COUNTRY", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) fprintf(f, "%sDH_COUNTRY", write_sep(sep, &count));
#endif
  if (config.what_to_count_2 & COUNT_SAMPLING_RATE) fprintf(f, "%sSAMPLING_RATE", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB) fprintf(f, "%sPKT_LEN_DISTRIB", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_POST_NAT_SRC_HOST) fprintf(f, "%sPOST_NAT_SRC_IP", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_POST_NAT_DST_HOST) fprintf(f, "%sPOST_NAT_DST_IP", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_POST_NAT_SRC_PORT) fprintf(f, "%sPOST_NAT_SRC_PORT", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_POST_NAT_DST_PORT) fprintf(f, "%sPOST_NAT_DST_PORT", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_NAT_EVENT) fprintf(f, "%sNAT_EVENT", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_TIMESTAMP_START) fprintf(f, "%sTIMESTAMP_START", write_sep(sep, &count));
  if (config.what_to_count_2 & COUNT_TIMESTAMP_END) fprintf(f, "%sTIMESTAMP_END", write_sep(sep, &count));

  if (!is_event) {
    fprintf(f, "%sPACKETS", write_sep(sep, &count));
    if (config.what_to_count & COUNT_FLOWS) fprintf(f, "%sFLOWS", write_sep(sep, &count));
    fprintf(f, "%sBYTES\n", write_sep(sep, &count));
  }
  else fprintf(f, "\n");
}

void P_sum_host_insert(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  struct in_addr ip;
#if defined ENABLE_IPV6
  struct in6_addr ip6;
#endif

  if (data->primitives.dst_ip.family == AF_INET) {
    ip.s_addr = data->primitives.dst_ip.address.ipv4.s_addr;
    data->primitives.dst_ip.address.ipv4.s_addr = 0;
    data->primitives.dst_ip.family = 0;
    P_cache_insert(prim_ptrs);
    data->primitives.src_ip.address.ipv4.s_addr = ip.s_addr;
    P_cache_insert(prim_ptrs);
  }
#if defined ENABLE_IPV6
  if (data->primitives.dst_ip.family == AF_INET6) {
    memcpy(&ip6, &data->primitives.dst_ip.address.ipv6, sizeof(struct in6_addr));
    memset(&data->primitives.dst_ip.address.ipv6, 0, sizeof(struct in6_addr));
    data->primitives.dst_ip.family = 0;
    P_cache_insert(prim_ptrs);
    memcpy(&data->primitives.src_ip.address.ipv6, &ip6, sizeof(struct in6_addr));
    P_cache_insert(prim_ptrs);
    return;
  }
#endif
}

void P_sum_port_insert(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  u_int16_t port;

  port = data->primitives.dst_port;
  data->primitives.dst_port = 0;
  P_cache_insert(prim_ptrs);
  data->primitives.src_port = port;
  P_cache_insert(prim_ptrs);
}

void P_sum_as_insert(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  as_t asn;

  asn = data->primitives.dst_as;
  data->primitives.dst_as = 0;
  P_cache_insert(prim_ptrs);
  data->primitives.src_as = asn;
  P_cache_insert(prim_ptrs);
}

#if defined (HAVE_L2)
void P_sum_mac_insert(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  u_char macaddr[ETH_ADDR_LEN];

  memcpy(macaddr, &data->primitives.eth_dhost, ETH_ADDR_LEN);
  memset(data->primitives.eth_dhost, 0, ETH_ADDR_LEN);
  P_cache_insert(prim_ptrs);
  memcpy(&data->primitives.eth_shost, macaddr, ETH_ADDR_LEN);
  P_cache_insert(prim_ptrs);
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

int P_test_zero_elem(struct chained_cache *elem)
{
  if (elem) {
    if (elem->flow_type == NF9_FTYPE_NAT_EVENT) {
      if (elem->pnat && elem->pnat->nat_event) return FALSE;
      else return TRUE;
    }
    else {
      if (elem->bytes_counter || elem->packet_counter || elem->flow_counter) return FALSE;
      else return TRUE;
    }
  }

  return TRUE;
}
