/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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
#include "plugin_common.h"
#include "addr.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "ip_flow.h"
#include "classifier.h"
#include "crc32.h"
#include "preprocess-internal.h"

/* Global variables */
void (*insert_func)(struct primitives_ptrs *, struct insert_data *); /* pointer to INSERT function */
void (*purge_func)(struct chained_cache *[], int, int); /* pointer to purge function */ 
struct scratch_area sa;
struct chained_cache *cache;
struct chained_cache **queries_queue, **pending_queries_queue, *pqq_container;
struct timeval flushtime;
int qq_ptr, pqq_ptr, pp_size, pb_size, pn_size, pm_size, pt_size, pc_size;
int dbc_size, quit; 
time_t refresh_deadline;

void (*basetime_init)(time_t);
void (*basetime_eval)(struct timeval *, struct timeval *, time_t);
int (*basetime_cmp)(struct timeval *, struct timeval *);
struct timeval basetime, ibasetime, new_basetime;
time_t timeslot;
int dyn_table, dyn_table_time_only;

/* Functions */
void P_set_signals()
{
  signal(SIGINT, P_exit_now);
  /* XXX: SIGHUP? */
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, reload_maps);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
}
 
void P_init_default_values()
{
  if (config.pidfile) write_pid_file_plugin(config.pidfile, config.type, config.name);
  if (config.logfile) {
    if (config.logfile_fd) fclose(config.logfile_fd);
    config.logfile_fd = open_output_file(config.logfile, "a", FALSE);
  }

  if (config.proc_priority) {
    int ret;

    ret = setpriority(PRIO_PROCESS, 0, config.proc_priority);
    if (ret) Log(LOG_WARNING, "WARN ( %s/%s ): proc_priority failed (errno: %d)\n", config.name, config.type, errno);
    else Log(LOG_INFO, "INFO ( %s/%s ): proc_priority set to %d\n", config.name, config.type, getpriority(PRIO_PROCESS, 0));
  }

  reload_map = FALSE;

  basetime_init = NULL;
  basetime_eval = NULL;
  basetime_cmp = NULL;
  memset(&basetime, 0, sizeof(basetime));
  memset(&ibasetime, 0, sizeof(ibasetime));
  memset(&timeslot, 0, sizeof(timeslot));

  if (!config.sql_refresh_time) config.sql_refresh_time = DEFAULT_PLUGIN_COMMON_REFRESH_TIME;
  if (!config.print_cache_entries) config.print_cache_entries = PRINT_CACHE_ENTRIES;
  if (!config.dump_max_writers) config.dump_max_writers = DEFAULT_PLUGIN_COMMON_WRITERS_NO;

  dump_writers.list = malloc(config.dump_max_writers * sizeof(pid_t));
  dump_writers_init();

  pp_size = sizeof(struct pkt_primitives);
  pb_size = sizeof(struct pkt_bgp_primitives);
  pn_size = sizeof(struct pkt_nat_primitives);
  pm_size = sizeof(struct pkt_mpls_primitives);
  pt_size = sizeof(struct pkt_tunnel_primitives);
  pc_size = config.cpptrs.len;
  dbc_size = sizeof(struct chained_cache);

  memset(&sa, 0, sizeof(struct scratch_area));
  sa.num = config.print_cache_entries*AVERAGE_CHAIN_LEN;
  sa.size = sa.num*dbc_size;

  Log(LOG_INFO, "INFO ( %s/%s ): cache entries=%d base cache memory=%" PRIu64 " bytes\n", config.name, config.type,
	config.print_cache_entries, ((config.print_cache_entries * dbc_size) + (2 * ((sa.num +
	config.print_cache_entries) * sizeof(struct chained_cache *))) + sa.size));

  cache = (struct chained_cache *) pm_malloc(config.print_cache_entries*dbc_size);
  queries_queue = (struct chained_cache **) pm_malloc((sa.num+config.print_cache_entries)*sizeof(struct chained_cache *));
  pending_queries_queue = (struct chained_cache **) pm_malloc((sa.num+config.print_cache_entries)*sizeof(struct chained_cache *));
  sa.base = (unsigned char *) pm_malloc(sa.size);
  sa.ptr = sa.base;
  sa.next = NULL;

  memset(cache, 0, config.print_cache_entries*sizeof(struct chained_cache));
  memset(queries_queue, 0, (sa.num+config.print_cache_entries)*sizeof(struct chained_cache *));
  memset(pending_queries_queue, 0, (sa.num+config.print_cache_entries)*sizeof(struct chained_cache *));
  memset(sa.base, 0, sa.size);
  memset(&flushtime, 0, sizeof(flushtime));
  memset(empty_mem_area_256b, 0, sizeof(empty_mem_area_256b));

  /* handling purge preprocessor */
  set_preprocess_funcs(config.sql_preprocess, &prep, PREP_DICT_PRINT);
}

void P_config_checks()
{
  if (config.nfacctd_pro_rating && config.nfacctd_stitching) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Pro-rating (ie. nfacctd_pro_rating) and stitching (ie. nfacctd_stitching) are mutual exclusive. Exiting.\n", config.name, config.type);
    goto exit_lane;
  }

  return;

exit_lane:
  exit_gracefully(1);
}

unsigned int P_cache_modulo(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *pdata = prim_ptrs->data;
  struct pkt_primitives *srcdst = &pdata->primitives;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  struct pkt_mpls_primitives *pmpls = prim_ptrs->pmpls;
  struct pkt_tunnel_primitives *ptun = prim_ptrs->ptun;
  u_char *pcust = prim_ptrs->pcust;
  struct pkt_vlen_hdr_primitives *pvlen = prim_ptrs->pvlen;
  register unsigned int modulo;

  modulo = cache_crc32((unsigned char *)srcdst, pp_size);
  if (pbgp) modulo ^= cache_crc32((unsigned char *)pbgp, pb_size);
  if (pnat) modulo ^= cache_crc32((unsigned char *)pnat, pn_size);
  if (pmpls) modulo ^= cache_crc32((unsigned char *)pmpls, pm_size);
  if (ptun) modulo ^= cache_crc32((unsigned char *)ptun, pt_size);
  if (pcust) modulo ^= cache_crc32((unsigned char *)pcust, pc_size);
  if (pvlen) modulo ^= cache_crc32((unsigned char *)pvlen, (PvhdrSz + pvlen->tot_len));

  return modulo %= config.print_cache_entries;
}

struct chained_cache *P_cache_search(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *pdata = prim_ptrs->data;
  struct pkt_primitives *data = &pdata->primitives;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  struct pkt_mpls_primitives *pmpls = prim_ptrs->pmpls;
  struct pkt_tunnel_primitives *ptun = prim_ptrs->ptun;
  u_char *pcust = prim_ptrs->pcust;
  struct pkt_vlen_hdr_primitives *pvlen = prim_ptrs->pvlen;
  unsigned int modulo = P_cache_modulo(prim_ptrs);
  struct chained_cache *cache_ptr = &cache[modulo];
  int res_data = TRUE, res_bgp = TRUE, res_nat = TRUE, res_mpls = TRUE, res_tun = TRUE;
  int res_time = TRUE, res_cust = TRUE, res_vlen = TRUE;

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

  if (pmpls) {
    if (cache_ptr->pmpls) res_mpls = memcmp(cache_ptr->pmpls, pmpls, sizeof(struct pkt_mpls_primitives));
  }
  else res_mpls = FALSE;

  if (ptun) {
    if (cache_ptr->ptun) res_tun = memcmp(cache_ptr->ptun, ptun, sizeof(struct pkt_tunnel_primitives));
  }
  else res_tun = FALSE;

  if (pcust) {
    if (cache_ptr->pcust) res_cust = memcmp(cache_ptr->pcust, pcust, config.cpptrs.len);
  }
  else res_cust = FALSE;

  if (pvlen) {
    if (cache_ptr->pvlen) res_vlen = vlen_prims_cmp(cache_ptr->pvlen, pvlen);
  }
  else res_vlen = FALSE;

  if (res_data || res_bgp || res_nat || res_mpls || res_tun || res_time || res_cust || res_vlen) {
    if (cache_ptr->valid == PRINT_CACHE_INUSE) {
      if (cache_ptr->next) {
        cache_ptr = cache_ptr->next;
        goto start;
      }
    }
  }
  else return cache_ptr; 

  return NULL;
}

void P_cache_insert(struct primitives_ptrs *prim_ptrs, struct insert_data *idata)
{
  struct pkt_data *data = prim_ptrs->data;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  struct pkt_mpls_primitives *pmpls = prim_ptrs->pmpls;
  struct pkt_tunnel_primitives *ptun = prim_ptrs->ptun;
  u_char *pcust = prim_ptrs->pcust;
  struct pkt_vlen_hdr_primitives *pvlen = prim_ptrs->pvlen;
  unsigned int modulo = P_cache_modulo(prim_ptrs);
  struct chained_cache *cache_ptr = &cache[modulo];
  struct pkt_primitives *srcdst = &data->primitives;
  int res_data, res_bgp, res_nat, res_mpls, res_tun, res_time, res_cust, res_vlen;

  /* pro_rating vars */
  int time_delta = 0, time_total = 0;
  pm_counter_t tot_bytes = 0, tot_packets = 0, tot_flows = 0;

  tot_bytes = data->pkt_len;
  tot_packets = data->pkt_num;
  tot_flows = data->flo_num;

  if (config.sql_history && (*basetime_eval)) {
    memcpy(&ibasetime, &basetime, sizeof(ibasetime));
    (*basetime_eval)(&data->time_start, &ibasetime, timeslot);
  }

  new_timeslot:
  /* pro_rating, if needed */
  if (config.acct_type == ACCT_NF && config.nfacctd_pro_rating && config.sql_history) {
    if (data->time_end.tv_sec > data->time_start.tv_sec) {
      time_total = data->time_end.tv_sec - data->time_start.tv_sec;
      time_delta = MIN(data->time_end.tv_sec, ibasetime.tv_sec + timeslot) - MAX(data->time_start.tv_sec, ibasetime.tv_sec);

      if (time_delta > 0 && time_total > 0 && time_delta < time_total) {
        float ratio = (float) time_total / (float) time_delta;

        if (tot_bytes) data->pkt_len = MAX((float)tot_bytes / ratio, 1);
        if (tot_packets) data->pkt_num = MAX((float)tot_packets / ratio, 1);
        if (tot_flows) data->flo_num = MAX((float)tot_flows / ratio, 1);
      }
    }
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
  res_data = res_bgp = res_nat = res_mpls = res_tun = res_time = res_cust = res_vlen = TRUE;

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

  if (pmpls) {
    if (cache_ptr->pmpls) res_mpls = memcmp(cache_ptr->pmpls, pmpls, sizeof(struct pkt_mpls_primitives));
  }
  else res_mpls = FALSE;

  if (ptun) {
    if (cache_ptr->ptun) res_tun = memcmp(cache_ptr->ptun, ptun, sizeof(struct pkt_tunnel_primitives));
  }
  else res_tun = FALSE;

  if (pcust) {
    if (cache_ptr->pcust) res_cust = memcmp(cache_ptr->pcust, pcust, config.cpptrs.len); 
  }
  else res_cust = FALSE;

  if (pvlen) {
    if (cache_ptr->pvlen) res_vlen = vlen_prims_cmp(cache_ptr->pvlen, pvlen);
  }
  else res_vlen = FALSE;

  if (res_data || res_bgp || res_nat || res_mpls || res_tun || res_time || res_cust || res_vlen) {
    /* aliasing of entries */
    if (cache_ptr->valid == PRINT_CACHE_INUSE) { 
      if (cache_ptr->next) {
	cache_ptr = cache_ptr->next;
	goto start;
      }
      else {
	cache_ptr = P_cache_attach_new_node(cache_ptr); 
	if (!cache_ptr) goto safe_action;
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
      if (cache_ptr->pbgp) memcpy(cache_ptr->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
      else goto safe_action;
    }
    else {
      if (cache_ptr->pbgp) free(cache_ptr->pbgp);
      cache_ptr->pbgp = NULL;
    }

    if (pnat) {
      if (!cache_ptr->pnat) cache_ptr->pnat = (struct pkt_nat_primitives *) malloc(PnatSz);
      if (cache_ptr->pnat) memcpy(cache_ptr->pnat, pnat, sizeof(struct pkt_nat_primitives));
      else goto safe_action;
    }
    else {
      if (cache_ptr->pnat) free(cache_ptr->pnat);
      cache_ptr->pnat = NULL;
    }

    if (pmpls) {
      if (!cache_ptr->pmpls) cache_ptr->pmpls = (struct pkt_mpls_primitives *) malloc(PmplsSz);
      if (cache_ptr->pmpls) memcpy(cache_ptr->pmpls, pmpls, sizeof(struct pkt_mpls_primitives));
      else goto safe_action;
    }
    else {
      if (cache_ptr->pmpls) free(cache_ptr->pmpls);
      cache_ptr->pmpls = NULL;
    }

    if (ptun) {
      if (!cache_ptr->ptun) cache_ptr->ptun = (struct pkt_tunnel_primitives *) malloc(PtunSz);
      if (cache_ptr->ptun) memcpy(cache_ptr->ptun, ptun, sizeof(struct pkt_tunnel_primitives));
      else goto safe_action;
    }
    else {
      if (cache_ptr->ptun) free(cache_ptr->ptun);
      cache_ptr->ptun = NULL;
    }

    if (pcust) {
      if (!cache_ptr->pcust) cache_ptr->pcust = malloc(config.cpptrs.len);
      if (cache_ptr->pcust) memcpy(cache_ptr->pcust, pcust, config.cpptrs.len);
      else goto safe_action;
    }
    else {
      if (cache_ptr->pcust) free(cache_ptr->pcust);
      cache_ptr->pcust = NULL;
    }

    /* if we have a pvlen from before let's free it
       up due to the vlen nature of the memory area */
    if (cache_ptr->pvlen) {
      vlen_prims_free(cache_ptr->pvlen);
      cache_ptr->pvlen = NULL;
    }

    if (pvlen) {
      cache_ptr->pvlen = (struct pkt_vlen_hdr_primitives *) vlen_prims_copy(pvlen);
      if (!cache_ptr->pvlen) goto safe_action;
    }

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

    if (config.nfacctd_stitching) {
      if (!cache_ptr->stitch) cache_ptr->stitch = (struct pkt_stitching *) malloc(sizeof(struct pkt_stitching));
      if (cache_ptr->stitch) {
	if (data->time_start.tv_sec) {
	  memcpy(&cache_ptr->stitch->timestamp_min, &data->time_start, sizeof(struct timeval));
	}
	else {
	  cache_ptr->stitch->timestamp_min.tv_sec = idata->now; 
	  cache_ptr->stitch->timestamp_min.tv_usec = 0;
	}

	if (data->time_end.tv_sec) {
	  memcpy(&cache_ptr->stitch->timestamp_max, &data->time_end, sizeof(struct timeval));
	}
	else {
	  cache_ptr->stitch->timestamp_max.tv_sec = idata->now;
	  cache_ptr->stitch->timestamp_max.tv_usec = 0;
	}
      }
      else Log(LOG_WARNING, "WARN ( %s/%s ): Finished memory for flow stitching.\n", config.name, config.type);
    }
    else assert(!cache_ptr->stitch);

    cache_ptr->valid = PRINT_CACHE_INUSE;
    cache_ptr->basetime.tv_sec = ibasetime.tv_sec;
    cache_ptr->basetime.tv_usec = ibasetime.tv_usec;
  }
  else {
    if (cache_ptr->valid == PRINT_CACHE_INUSE) {
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

      if (config.nfacctd_stitching) {
	if (cache_ptr->stitch) {
	  if (data->time_end.tv_sec) {
	    if (data->time_end.tv_sec > cache_ptr->stitch->timestamp_max.tv_sec && 
		data->time_end.tv_usec > cache_ptr->stitch->timestamp_max.tv_usec)
	      memcpy(&cache_ptr->stitch->timestamp_max, &data->time_end, sizeof(struct timeval));
	  }
	  else {
	    cache_ptr->stitch->timestamp_max.tv_sec = idata->now;
	    cache_ptr->stitch->timestamp_max.tv_usec = 0;
	  }
	}
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
      cache_ptr->valid = PRINT_CACHE_INUSE;
      cache_ptr->basetime.tv_sec = ibasetime.tv_sec;
      cache_ptr->basetime.tv_usec = ibasetime.tv_usec;
      queries_queue[qq_ptr] = cache_ptr;
      qq_ptr++;
    }
  }

  /* pro_rating */
  if (config.acct_type == ACCT_NF && config.nfacctd_pro_rating && config.sql_history) {
    if ((ibasetime.tv_sec + timeslot) < data->time_end.tv_sec) {
      ibasetime.tv_sec += timeslot;
      goto new_timeslot;
    }
  }

  return;

  safe_action:
  {
    pid_t ret;

    Log(LOG_INFO, "INFO ( %s/%s ): Finished cache entries (ie. print_cache_entries). Purging.\n", config.name, config.type);

    if (config.type_id == PLUGIN_ID_PRINT && config.sql_table && !config.print_output_file_append)
      Log(LOG_WARNING, "WARN ( %s/%s ): Make sure print_output_file_append is set to true.\n", config.name, config.type);

    if (qq_ptr) P_cache_mark_flush(queries_queue, qq_ptr, FALSE);

    /* Writing out to replenish cache space */
    dump_writers_count();
    if (dump_writers_get_flags() != CHLD_ALERT) {
      switch (ret = fork()) {
      case 0: /* Child */
	pm_setproctitle("%s %s [%s]", config.type, "Plugin -- Writer (urgent)", config.name);
	config.is_forked = TRUE;

        (*purge_func)(queries_queue, qq_ptr, TRUE);

        exit_gracefully(0);
      default: /* Parent */
        if (ret == -1) Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork writer: %s\n", config.name, config.type, strerror(errno));
        else dump_writers_add(ret);

	break;
      }
    }
    else Log(LOG_WARNING, "WARN ( %s/%s ): Maximum number of writer processes reached (%d).\n", config.name, config.type, dump_writers_get_active());

    P_cache_flush(queries_queue, qq_ptr);
    qq_ptr = FALSE;
    if (pqq_ptr) {
      P_cache_insert_pending(pending_queries_queue, pqq_ptr, pqq_container);
      pqq_ptr = 0;
    }

    /* try to insert again */
    (*insert_func)(prim_ptrs, idata);
  }
}

void P_cache_insert_pending(struct chained_cache *queue[], int index, struct chained_cache *container)
{
  struct chained_cache *cache_ptr;
  struct primitives_ptrs prim_ptrs;
  struct pkt_data pdata;
  unsigned int modulo, j;

  if (!index || !container) return;

  for (j = 0; j < index; j++) {
    memset(&prim_ptrs, 0, sizeof(prim_ptrs));
    prim_ptrs.data = &pdata;
    primptrs_set_all_from_chained_cache(&prim_ptrs, queue[j]);

    modulo = P_cache_modulo(&prim_ptrs);
    cache_ptr = &cache[modulo];

    start:
    if (cache_ptr->valid == PRINT_CACHE_INUSE) {
      if (cache_ptr->next) {
        cache_ptr = cache_ptr->next;
        goto start;
      }
      else {
        cache_ptr = P_cache_attach_new_node(cache_ptr);
        if (!cache_ptr) {
          Log(LOG_WARNING, "WARN ( %s/%s ): Finished cache entries. Pending entries will be lost.\n", config.name, config.type);
          Log(LOG_WARNING, "WARN ( %s/%s ): You may want to set a larger print_cache_entries value.\n", config.name, config.type);
          break;
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

    if (cache_ptr->pbgp) free(cache_ptr->pbgp);
    if (cache_ptr->pnat) free(cache_ptr->pnat);
    if (cache_ptr->pmpls) free(cache_ptr->pmpls);
    if (cache_ptr->ptun) free(cache_ptr->ptun);
    if (cache_ptr->pcust) free(cache_ptr->pcust);
    if (cache_ptr->pvlen) free(cache_ptr->pvlen);
    if (cache_ptr->stitch) free(cache_ptr->stitch);

    memcpy(cache_ptr, &container[j], dbc_size); 

    container[j].pbgp = NULL;
    container[j].pnat = NULL;
    container[j].pmpls = NULL;
    container[j].ptun = NULL;
    container[j].pcust = NULL;
    container[j].pvlen = NULL;
    container[j].stitch = NULL;

    cache_ptr->valid = PRINT_CACHE_INUSE;
    cache_ptr->next = NULL;
  }

  free(container);
}

void P_cache_handle_flush_event(struct ports_table *pt)
{
  pid_t ret;

  if (qq_ptr) P_cache_mark_flush(queries_queue, qq_ptr, FALSE);

  dump_writers_count();
  if (dump_writers_get_flags() != CHLD_ALERT) {
    switch (ret = fork()) {
    case 0: /* Child */
      pm_setproctitle("%s %s [%s]", config.type, "Plugin -- Writer", config.name);
      config.is_forked = TRUE;

      (*purge_func)(queries_queue, qq_ptr, FALSE);

      exit_gracefully(0);
    default: /* Parent */
      if (ret == -1) Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork writer: %s\n", config.name, config.type, strerror(errno));
      else dump_writers_add(ret);

      break;
    }
  }
  else Log(LOG_WARNING, "WARN ( %s/%s ): Maximum number of writer processes reached (%d).\n", config.name, config.type, dump_writers_get_active());

  P_cache_flush(queries_queue, qq_ptr);

  gettimeofday(&flushtime, NULL);
  refresh_deadline += config.sql_refresh_time;
  qq_ptr = FALSE;
  memset(&new_basetime, 0, sizeof(new_basetime));

  if (pqq_ptr) {
    P_cache_insert_pending(pending_queries_queue, pqq_ptr, pqq_container);
    pqq_ptr = 0;
  }

  if (reload_map) {
    load_networks(config.networks_file, &nt, &nc);
    load_ports(config.ports_file, pt);
    reload_map = FALSE;
  }

  if (reload_log) {
    reload_logs();
    reload_log = FALSE;
  }
}

void P_cache_mark_flush(struct chained_cache *queue[], int index, int exiting)
{
  struct timeval commit_basetime;
  int j, delay = 0;

  memset(&commit_basetime, 0, sizeof(commit_basetime));

  /* check-pointing */
  if (new_basetime.tv_sec) commit_basetime.tv_sec = new_basetime.tv_sec;
  else commit_basetime.tv_sec = basetime.tv_sec; 

  /* evaluating any delay we may have to introduce */
  if (config.sql_startup_delay) {
    if (timeslot) delay = config.sql_startup_delay/timeslot;
    delay = delay*timeslot;
  }

  /* mark committed entries as such */
  if (!exiting) {
    for (j = 0, pqq_ptr = 0; j < index; j++) {
      if (commit_basetime.tv_sec < (queue[j]->basetime.tv_sec+delay)) {
        pending_queries_queue[pqq_ptr] = queue[j];
        pqq_ptr++;
      }
      else queue[j]->valid = PRINT_CACHE_COMMITTED;
    }

    if (pqq_ptr) {
      pqq_container = (struct chained_cache *) malloc(pqq_ptr*dbc_size); 
      if (!pqq_container) {
	Log(LOG_ERR, "ERROR ( %s/%s ): P_cache_mark_flush() cannot allocate pqq_container. Exiting ..\n", config.name, config.type);
	exit_gracefully(1); 
      }
    }
    
    /* we copy un-committed elements to a container structure for re-insertion
       in cache. As we copy elements out of the cache we mark entries as free */
    for (j = 0; j < pqq_ptr; j++) {
      memcpy(&pqq_container[j], pending_queries_queue[j], dbc_size);

      pending_queries_queue[j]->pbgp = NULL;
      pending_queries_queue[j]->pnat = NULL;
      pending_queries_queue[j]->pmpls = NULL;
      pending_queries_queue[j]->ptun = NULL;
      pending_queries_queue[j]->pcust = NULL;
      pending_queries_queue[j]->pvlen = NULL;
      pending_queries_queue[j]->stitch = NULL;

      pending_queries_queue[j]->valid = PRINT_CACHE_FREE;
      pending_queries_queue[j] = &pqq_container[j];
    }
  }
  else {
    for (j = 0, pqq_ptr = 0; j < index; j++)
      queue[j]->valid = PRINT_CACHE_COMMITTED;
  }
}

void P_cache_flush(struct chained_cache *queue[], int index)
{
  int j;

  for (j = 0; j < index; j++) {
    queue[j]->valid = PRINT_CACHE_FREE;
    queue[j]->next = NULL;
  }

  /* rewinding scratch area stuff */
  sa.ptr = sa.base;
}

struct chained_cache *P_cache_attach_new_node(struct chained_cache *elem)
{
  if ((sa.ptr + (2 * sizeof(struct chained_cache))) <= (sa.base + sa.size)) {
    sa.ptr += sizeof(struct chained_cache);
    elem->next = (struct chained_cache *) sa.ptr;
    return (struct chained_cache *) sa.ptr;
  }
  else return NULL;
}

void P_sum_host_insert(struct primitives_ptrs *prim_ptrs, struct insert_data *idata)
{
  struct pkt_data *data = prim_ptrs->data;
  struct host_addr tmp;

  memcpy(&tmp, &data->primitives.dst_ip, HostAddrSz);
  memset(&data->primitives.dst_ip, 0, HostAddrSz);
  P_cache_insert(prim_ptrs, idata);
  memcpy(&data->primitives.src_ip, &tmp, HostAddrSz);
  P_cache_insert(prim_ptrs, idata);
}

void P_sum_port_insert(struct primitives_ptrs *prim_ptrs, struct insert_data *idata)
{
  struct pkt_data *data = prim_ptrs->data;
  u_int16_t port;

  port = data->primitives.dst_port;
  data->primitives.dst_port = 0;
  P_cache_insert(prim_ptrs, idata);
  data->primitives.src_port = port;
  P_cache_insert(prim_ptrs, idata);
}

void P_sum_as_insert(struct primitives_ptrs *prim_ptrs, struct insert_data *idata)
{
  struct pkt_data *data = prim_ptrs->data;
  as_t asn;

  asn = data->primitives.dst_as;
  data->primitives.dst_as = 0;
  P_cache_insert(prim_ptrs, idata);
  data->primitives.src_as = asn;
  P_cache_insert(prim_ptrs, idata);
}

#if defined (HAVE_L2)
void P_sum_mac_insert(struct primitives_ptrs *prim_ptrs, struct insert_data *idata)
{
  struct pkt_data *data = prim_ptrs->data;
  u_char macaddr[ETH_ADDR_LEN];

  memcpy(macaddr, &data->primitives.eth_dhost, ETH_ADDR_LEN);
  memset(data->primitives.eth_dhost, 0, ETH_ADDR_LEN);
  P_cache_insert(prim_ptrs, idata);
  memcpy(&data->primitives.eth_shost, macaddr, ETH_ADDR_LEN);
  P_cache_insert(prim_ptrs, idata);
}
#endif

void P_exit_now(int signum)
{
  if (qq_ptr) P_cache_mark_flush(queries_queue, qq_ptr, TRUE);

  dump_writers_count();
  if (dump_writers_get_flags() != CHLD_ALERT) (*purge_func)(queries_queue, qq_ptr, FALSE);
  else Log(LOG_WARNING, "WARN ( %s/%s ): Maximum number of writer processes reached (%d).\n", config.name, config.type, dump_writers_get_active());

  if (config.pidfile) remove_pid_file(config.pidfile);

  wait(NULL);
  exit_gracefully(0);
}

int P_trigger_exec(char *filename)
{
  char *args[2] = { filename, NULL };
  int pid;

  switch (pid = vfork()) {
  case -1:
    return -1;
  case 0:
    execv(filename, args);
    _exit(0);
  }

  return 0;
}

void P_init_historical_acct(time_t now)
{
  time_t t = 0;

  basetime.tv_sec = now;
  basetime.tv_usec = 0;

  if (config.sql_history == COUNT_SECONDLY) timeslot = config.sql_history_howmany;
  else if (config.sql_history == COUNT_MINUTELY) timeslot = config.sql_history_howmany*60;
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

  if (config.sql_history_offset) {
    if (config.sql_history_offset >= timeslot) {
      Log(LOG_ERR, "ERROR ( %s/%s ): History offset (ie. sql_history_offset) must be < history (ie. sql_history).\n", config.name, config.type);
      exit_gracefully(1);
    }

    t = t - (timeslot + config.sql_history_offset);
  }

  basetime.tv_sec = t;

  memset(&new_basetime, 0, sizeof(new_basetime));
}

void P_init_refresh_deadline(time_t *now, int refresh_time, int startup_delay, char *roundoff)
{
  time_t t;

  t = roundoff_time((*now), roundoff);
  while ((t + refresh_time) < (*now)) t += refresh_time;
  *now = t;
  *now += (refresh_time + startup_delay); /* it's a deadline not a basetime */
}

void P_eval_historical_acct(struct timeval *stamp, struct timeval *basetime, time_t timeslot)
{
  if (stamp->tv_sec) {
    if (config.sql_history != COUNT_MONTHLY) {
      int residual;

      if (basetime->tv_sec > stamp->tv_sec) {
        residual = timeslot - ((basetime->tv_sec - stamp->tv_sec) % timeslot);
      }
      else {
        residual = ((stamp->tv_sec - basetime->tv_sec) % timeslot);
      }

      basetime->tv_sec = stamp->tv_sec - residual;
    }
    else {
      while (basetime->tv_sec > stamp->tv_sec) {
        timeslot = calc_monthly_timeslot(basetime->tv_sec, config.sql_history_howmany, SUB);
        basetime->tv_sec -= timeslot;
      }
      while ((basetime->tv_sec+timeslot) < stamp->tv_sec) {
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

void primptrs_set_all_from_chained_cache(struct primitives_ptrs *prim_ptrs, struct chained_cache *entry)
{
  struct pkt_data *data;

  if (prim_ptrs && entry) {
    data = prim_ptrs->data;
    memset(data, 0, PdataSz);

    data->primitives = entry->primitives;
    prim_ptrs->pbgp = entry->pbgp;
    prim_ptrs->pnat = entry->pnat;
    prim_ptrs->pmpls = entry->pmpls;
    prim_ptrs->ptun = entry->ptun;
    prim_ptrs->pcust = entry->pcust;
    prim_ptrs->pvlen = entry->pvlen;
  }
}

void P_handle_table_dyn_rr(char *new, int newlen, char *old, struct p_table_rr *rk_rr)
{
  char index_str[SRVBUFLEN];
  int oldlen;

  oldlen = strlen(old);
  if (oldlen <= newlen) strcpy(new, old);
  else {
    strncpy(new, old, newlen);
    return;
  }

  memset(index_str, 0, SRVBUFLEN);
  snprintf(index_str, SRVBUFLEN, "_%u", rk_rr->next);
  strncat(new, index_str, (newlen-oldlen));

  rk_rr->next++;
  rk_rr->next %= rk_rr->max;
}

void P_update_time_reference(struct insert_data *idata)
{
  idata->now = time(NULL);

  if (config.sql_history) {
    while (idata->now > (basetime.tv_sec + timeslot)) {
      new_basetime.tv_sec = basetime.tv_sec;
      basetime.tv_sec += timeslot;
      if (config.sql_history == COUNT_MONTHLY)
	timeslot = calc_monthly_timeslot(basetime.tv_sec, config.sql_history_howmany, ADD);
    }
  }
}
