/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2011 by Paolo Lucente
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
  struct timezone tz;
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

  if (!config.print_refresh_time)
    config.print_refresh_time = DEFAULT_PRINT_REFRESH_TIME;

  if (!config.print_output)
    config.print_output = PRINT_OUTPUT_FORMATTED;

  timeout = config.print_refresh_time*1000;

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
  while ((t+config.print_refresh_time) < refresh_deadline) t += config.print_refresh_time;
  refresh_deadline = t;
  refresh_deadline += config.print_refresh_time; /* it's a deadline not a basetime */

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
    ret = poll(&pfd, 1, timeout);
    if (ret < 0) goto poll_again;

    now = time(NULL);

    switch (ret) {
    case 0: /* timeout */
      if (qq_ptr) {
	switch (fork()) {
	case 0: /* Child */
	  P_cache_purge(queries_queue, qq_ptr);
          exit(0);
        default: /* Parent */
          P_cache_flush(queries_queue, qq_ptr);
	  gettimeofday(&flushtime, &tz);
    	  refresh_deadline += config.print_refresh_time; 
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
          switch (fork()) {
          case 0: /* Child */
            P_cache_purge(queries_queue, qq_ptr);
            exit(0);
          default: /* Parent */
            P_cache_flush(queries_queue, qq_ptr);
	    gettimeofday(&flushtime, &tz);
            refresh_deadline += config.print_refresh_time; 
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
  int res_data = TRUE, res_bgp = TRUE;

  start:
  res_data = memcmp(&cache_ptr->primitives, data, sizeof(struct pkt_primitives));
  if (PbgpSz) {
    if (cache_ptr->pbgp) res_bgp = memcmp(cache_ptr->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
  }
  else res_bgp = FALSE;

  if (res_data || res_bgp) {
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
  int res_data, res_bgp;

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
  res_data = res_bgp = TRUE;

  res_data = memcmp(&cache_ptr->primitives, srcdst, sizeof(struct pkt_primitives)); 
  if (PbgpSz) {
    if (cache_ptr->pbgp) res_bgp = memcmp(cache_ptr->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
  }
  else res_bgp = FALSE;

  if (res_data || res_bgp) {
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
    f = open_print_output_file(config.sql_table, refresh_deadline-config.print_refresh_time);

    if (config.print_output == PRINT_OUTPUT_FORMATTED)
      P_write_stats_header_formatted(f);
    else if (config.print_output == PRINT_OUTPUT_CSV)
      P_write_stats_header_csv(f);
  }
  else f = stdout; /* write to standard output */

  if (config.print_markers) fprintf(f, "--START (%ld+%d)--\n", refresh_deadline-config.print_refresh_time,
		  			config.print_refresh_time);

  for (j = 0; j < index; j++) {
    data = &queue[j]->primitives;
    if (queue[j]->pbgp) pbgp = queue[j]->pbgp;
    else pbgp = &empty_pbgp;

    if (!queue[j]->bytes_counter && !queue[j]->packet_counter && !queue[j]->flow_counter)
      continue;

    if (config.print_output == PRINT_OUTPUT_FORMATTED) {
      fprintf(f, "%-10llu  ", data->id);
      fprintf(f, "%-10llu  ", data->id2);
      fprintf(f, "%-16s  ", ((data->class && class[(data->class)-1].id) ? class[(data->class)-1].protocol : "unknown" ));
#if defined (HAVE_L2)
      etheraddr_string(data->eth_shost, src_mac);
      fprintf(f, "%-17s  ", src_mac);
      etheraddr_string(data->eth_dhost, dst_mac);
      fprintf(f, "%-17s  ", dst_mac);
      fprintf(f, "%-5u  ", data->vlan_id); 
      fprintf(f, "%-2u  ", data->cos); 
#endif
      fprintf(f, "%-10u  ", data->src_as); 
      fprintf(f, "%-10u  ", data->dst_as); 

      bgp_comm = pbgp->std_comms;
      while (bgp_comm) {
        bgp_comm = strchr(pbgp->std_comms, ' ');
        if (bgp_comm) *bgp_comm = '_';
      }

      if (strlen(pbgp->std_comms)) 
        fprintf(f, "%-22s   ", pbgp->std_comms);
      else
	fprintf(f, "%-22u   ", 0);

      as_path = pbgp->as_path;
      while (as_path) {
	as_path = strchr(pbgp->as_path, ' ');
	if (as_path) *as_path = '_';
      }
      if (strlen(pbgp->as_path))
	fprintf(f, "%-22s   ", pbgp->as_path);
      else
	fprintf(f, "%-22s   ", empty_aspath);

      fprintf(f, "%-5u  ", pbgp->local_pref);
      fprintf(f, "%-5u  ", pbgp->med);
      fprintf(f, "%-10u  ", pbgp->peer_src_as);
      fprintf(f, "%-10u  ", pbgp->peer_dst_as);

      addr_to_str(ip_address, &pbgp->peer_src_ip);
#if defined ENABLE_IPV6
      fprintf(f, "%-45s  ", ip_address);
#else
      fprintf(f, "%-15s  ", ip_address);
#endif
      addr_to_str(ip_address, &pbgp->peer_dst_ip);
#if defined ENABLE_IPV6
      fprintf(f, "%-45s  ", ip_address);
#else
      fprintf(f, "%-15s  ", ip_address);
#endif

      fprintf(f, "%-10u  ", data->ifindex_in);
      fprintf(f, "%-10u  ", data->ifindex_out);

      bgp_rd2str(rd_str, &pbgp->mpls_vpn_rd);
      fprintf(f, "%-18s  ", rd_str);

      addr_to_str(src_host, &data->src_ip);
#if defined ENABLE_IPV6
      fprintf(f, "%-45s  ", src_host);
#else
      fprintf(f, "%-15s  ", src_host);
#endif
      addr_to_str(dst_host, &data->dst_ip);
#if defined ENABLE_IPV6
      fprintf(f, "%-45s  ", dst_host);
#else
      fprintf(f, "%-15s  ", dst_host);
#endif
      fprintf(f, "%-3u       ", data->src_nmask);
      fprintf(f, "%-3u       ", data->dst_nmask);
      fprintf(f, "%-5u     ", data->src_port);
      fprintf(f, "%-5u     ", data->dst_port);
      fprintf(f, "%-3u        ", queue[j]->tcp_flags);

      if (!config.num_protos) fprintf(f, "%-10s  ", _protocols[data->proto].name);
      else  fprintf(f, "%-10d  ", _protocols[data->proto].number);

      fprintf(f, "%-3u    ", data->tos);
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
    else if (config.print_output == PRINT_OUTPUT_CSV) {
      fprintf(f, "%llu,", data->id);
      fprintf(f, "%llu,", data->id2);
      fprintf(f, "%s,", ((data->class && class[(data->class)-1].id) ? class[(data->class)-1].protocol : "unknown" ));
#if defined (HAVE_L2)
      etheraddr_string(data->eth_shost, src_mac);
      fprintf(f, "%s,", src_mac);
      etheraddr_string(data->eth_dhost, dst_mac);
      fprintf(f, "%s,", dst_mac);
      fprintf(f, "%u,", data->vlan_id); 
      fprintf(f, "%u,", data->cos); 
#endif
      fprintf(f, "%u,", data->src_as); 
      fprintf(f, "%u,", data->dst_as); 

      bgp_comm = pbgp->std_comms;
      while (bgp_comm) {
        bgp_comm = strchr(pbgp->std_comms, ' ');
        if (bgp_comm) *bgp_comm = '_';
      }

      if (strlen(pbgp->std_comms)) 
        fprintf(f, "%s,", pbgp->std_comms);
      else
        fprintf(f, "%u,", 0);

      as_path = pbgp->as_path;
      while (as_path) {
	as_path = strchr(pbgp->as_path, ' ');
	if (as_path) *as_path = '_';
      }
      fprintf(f, "%s,", pbgp->as_path);

      fprintf(f, "%u,", pbgp->local_pref);
      fprintf(f, "%u,", pbgp->med);
      fprintf(f, "%u,", pbgp->peer_src_as);
      fprintf(f, "%u,", pbgp->peer_dst_as);

      addr_to_str(ip_address, &pbgp->peer_src_ip);
      fprintf(f, "%s,", ip_address);
      addr_to_str(ip_address, &pbgp->peer_dst_ip);
      fprintf(f, "%s,", ip_address);

      fprintf(f, "%u,", data->ifindex_in);
      fprintf(f, "%u,", data->ifindex_out);

      bgp_rd2str(rd_str, &pbgp->mpls_vpn_rd);
      fprintf(f, "%s,", rd_str);

      addr_to_str(src_host, &data->src_ip);
      fprintf(f, "%s,", src_host);
      addr_to_str(dst_host, &data->dst_ip);
      fprintf(f, "%s,", dst_host);

      fprintf(f, "%u,", data->src_nmask);
      fprintf(f, "%u,", data->dst_nmask);
      fprintf(f, "%u,", data->src_port);
      fprintf(f, "%u,", data->dst_port);
      fprintf(f, "%u,", queue[j]->tcp_flags);

      if (!config.num_protos) fprintf(f, "%s,", _protocols[data->proto].name);
      else fprintf(f, "%d,", _protocols[data->proto].number);

      fprintf(f, "%u,", data->tos);
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

  if (config.print_markers) fprintf(f, "--END--\n");

  if (config.sql_table) fclose(f);

  if (config.sql_trigger_exec) P_trigger_exec(config.sql_trigger_exec); 
}

void P_write_stats_header_formatted(FILE *f)
{
  fprintf(f, "TAG         ");
  fprintf(f, "TAG2        ");
  fprintf(f, "CLASS             ");
#if defined HAVE_L2
  fprintf(f, "SRC_MAC            ");
  fprintf(f, "DST_MAC            ");
  fprintf(f, "VLAN   ");
  fprintf(f, "COS ");
#endif
  fprintf(f, "SRC_AS      ");
  fprintf(f, "DST_AS      ");
  fprintf(f, "BGP_COMMS                ");
  fprintf(f, "AS_PATH                  ");
  fprintf(f, "PREF   ");
  fprintf(f, "MED    ");
  fprintf(f, "PEER_SRC_AS ");
  fprintf(f, "PEER_DST_AS ");
  fprintf(f, "PEER_SRC_IP      ");
  fprintf(f, "PEER_DST_IP      ");
  fprintf(f, "IN_IFACE    ");
  fprintf(f, "OUT_IFACE   ");
  fprintf(f, "MPLS_VPN_RD         ");
#if defined ENABLE_IPV6
  fprintf(f, "SRC_IP                                         ");
  fprintf(f, "DST_IP                                         ");
#else
  fprintf(f, "SRC_IP           ");
  fprintf(f, "DST_IP           ");
#endif
  fprintf(f, "SRC_MASK  ");
  fprintf(f, "DST_MASK  ");
  fprintf(f, "SRC_PORT  ");
  fprintf(f, "DST_PORT  ");
  fprintf(f, "TCP_FLAGS  ");
  fprintf(f, "PROTOCOL    ");
  fprintf(f, "TOS    ");
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
  fprintf(f, "TAG,");
  fprintf(f, "TAG2,");
  fprintf(f, "CLASS,");
#if defined HAVE_L2
  fprintf(f, "SRC_MAC,");
  fprintf(f, "DST_MAC,");
  fprintf(f, "VLAN,");
  fprintf(f, "COS,");
#endif
  fprintf(f, "SRC_AS,");
  fprintf(f, "DST_AS,");
  fprintf(f, "BGP_COMMS,");
  fprintf(f, "AS_PATH,");
  fprintf(f, "PREF,");
  fprintf(f, "MED,");
  fprintf(f, "PEER_SRC_AS,");
  fprintf(f, "PEER_DST_AS,");
  fprintf(f, "PEER_SRC_IP,");
  fprintf(f, "PEER_DST_IP,");
  fprintf(f, "IN_IFACE,");
  fprintf(f, "OUT_IFACE,");
  fprintf(f, "MPLS_VPN_RD,");
  fprintf(f, "SRC_IP,");
  fprintf(f, "DST_IP,");
  fprintf(f, "SRC_MASK,");
  fprintf(f, "DST_MASK,");
  fprintf(f, "SRC_PORT,");
  fprintf(f, "DST_PORT,");
  fprintf(f, "TCP_FLAGS,");
  fprintf(f, "PROTOCOL,");
  fprintf(f, "TOS,");
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
