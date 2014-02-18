/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2014 by Paolo Lucente
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

#define __PLUGIN_COMMON_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_common.h"
#include "ip_flow.h"
#include "classifier.h"
#include "crc32.c"

/* Functions */
unsigned int P_cache_modulo(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *pdata = prim_ptrs->data;
  struct pkt_primitives *srcdst = &pdata->primitives;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  struct pkt_mpls_primitives *pmpls = prim_ptrs->pmpls;
  char *pcust = prim_ptrs->pcust;
  register unsigned int modulo;

  modulo = cache_crc32((unsigned char *)srcdst, pp_size);
  if (pbgp) modulo ^= cache_crc32((unsigned char *)pbgp, pb_size);
  if (pnat) modulo ^= cache_crc32((unsigned char *)pnat, pn_size);
  if (pmpls) modulo ^= cache_crc32((unsigned char *)pmpls, pm_size);
  if (pcust) modulo ^= cache_crc32((unsigned char *)pcust, pc_size);
  
  return modulo %= config.print_cache_entries;
}

struct chained_cache *P_cache_search(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *pdata = prim_ptrs->data;
  struct pkt_primitives *data = &pdata->primitives;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  struct pkt_mpls_primitives *pmpls = prim_ptrs->pmpls;
  char *pcust = prim_ptrs->pcust;
  unsigned int modulo = P_cache_modulo(prim_ptrs);
  struct chained_cache *cache_ptr = &cache[modulo];
  int res_data = TRUE, res_bgp = TRUE, res_nat = TRUE, res_mpls = TRUE, res_time = TRUE;
  int res_cust = TRUE;

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

  if (pcust) {
    if (cache_ptr->pcust) res_cust = memcmp(cache_ptr->pcust, pcust, config.cpptrs.len);
  }
  else res_cust = FALSE;

  if (res_data || res_bgp || res_nat || res_mpls || res_time || res_cust) {
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

void P_cache_insert(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  struct pkt_mpls_primitives *pmpls = prim_ptrs->pmpls;
  char *pcust = prim_ptrs->pcust;
  unsigned int modulo = P_cache_modulo(prim_ptrs);
  struct chained_cache *cache_ptr = &cache[modulo];
  struct pkt_primitives *srcdst = &data->primitives;
  int res_data, res_bgp, res_nat, res_mpls, res_time, res_cust;

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
  res_data = res_bgp = res_nat = res_mpls = res_time = res_cust = TRUE;

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

  if (pcust) {
    if (cache_ptr->pcust) res_cust = memcmp(cache_ptr->pcust, pcust, config.cpptrs.len); 
  }
  else res_cust = FALSE;

  if (res_data || res_bgp || res_nat || res_mpls || res_time || res_cust) {
    /* aliasing of entries */
    if (cache_ptr->valid == PRINT_CACHE_INUSE) { 
      if (cache_ptr->next) {
	cache_ptr = cache_ptr->next;
	goto start;
      }
      else {
	cache_ptr = P_cache_attach_new_node(cache_ptr); 
	if (!cache_ptr) {
	  Log(LOG_WARNING, "WARN ( %s/%s ): Finished cache entries. Purging.\n", config.name, config.type);
	  Log(LOG_WARNING, "WARN ( %s/%s ): You may want to set a larger print_cache_entries value.\n", config.name, config.type);
	  goto safe_action;
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
      if (cache_ptr->pbgp) memcpy(cache_ptr->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
      else {
        Log(LOG_WARNING, "WARN ( %s/%s ): Finished memory for cache entries. Purging.\n", config.name, config.type);
        goto safe_action;
      }
    }
    else {
      if (cache_ptr->pbgp) free(cache_ptr->pbgp);
      cache_ptr->pbgp = NULL;
    }

    if (pnat) {
      if (!cache_ptr->pnat) cache_ptr->pnat = (struct pkt_nat_primitives *) malloc(PnatSz);
      if (cache_ptr->pnat) memcpy(cache_ptr->pnat, pnat, sizeof(struct pkt_nat_primitives));
      else {
        Log(LOG_WARNING, "WARN ( %s/%s ): Finished memory for cache entries. Purging.\n", config.name, config.type);
        goto safe_action;
      }
    }
    else {
      if (cache_ptr->pnat) free(cache_ptr->pnat);
      cache_ptr->pnat = NULL;
    }

    if (pmpls) {
      if (!cache_ptr->pmpls) cache_ptr->pmpls = (struct pkt_mpls_primitives *) malloc(PmplsSz);
      if (cache_ptr->pmpls) memcpy(cache_ptr->pmpls, pmpls, sizeof(struct pkt_mpls_primitives));
      else {
        Log(LOG_WARNING, "WARN ( %s/%s ): Finished memory for cache entries. Purging.\n", config.name, config.type);
        goto safe_action;
      }
    }
    else {
      if (cache_ptr->pmpls) free(cache_ptr->pmpls);
      cache_ptr->pmpls = NULL;
    }

    if (pcust) {
      if (!cache_ptr->pcust) cache_ptr->pcust = malloc(config.cpptrs.len);
      if (cache_ptr->pcust) memcpy(cache_ptr->pcust, pcust, config.cpptrs.len);
      else {
        Log(LOG_WARNING, "WARN ( %s/%s ): Finished memory for cache entries. Purging.\n", config.name, config.type);
        goto safe_action;
      }
    }
    else {
      if (cache_ptr->pcust) free(cache_ptr->pcust);
      cache_ptr->pcust = NULL;
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
    int ret;

    if (config.type_id == PLUGIN_ID_PRINT && config.sql_table)
      Log(LOG_WARNING, "WARN ( %s/%s ): Make sure print_output_file_append is set to true.\n", config.name, config.type);

    /* Writing out to replenish cache space */
    switch (ret = fork()) {
    case 0: /* Child */
      (*purge_func)(queries_queue, qq_ptr);
      exit(0);
    default: /* Parent */
      if (ret == -1) Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork writer: %s\n", config.name, config.type, strerror(errno));
      P_cache_flush(queries_queue, qq_ptr);
      qq_ptr = FALSE;
      break;
    }

    /* try to insert again */
    (*insert_func)(prim_ptrs);
  }
}

void P_cache_handle_flush_event(struct ports_table *pt)
{
  int ret;

  if (qq_ptr) P_cache_mark_flush(queries_queue, qq_ptr, FALSE);

  switch (ret = fork()) {
  case 0: /* Child */
    (*purge_func)(queries_queue, qq_ptr);

    exit(0);
  default: /* Parent */
    if (ret == -1) Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork writer: %s\n", config.name, config.type, strerror(errno));

    P_cache_flush(queries_queue, qq_ptr);

    gettimeofday(&flushtime, NULL);
    refresh_deadline += config.sql_refresh_time;
    qq_ptr = FALSE;
    memset(&new_basetime, 0, sizeof(new_basetime));

    if (reload_map) {
      load_networks(config.networks_file, &nt, &nc);
      load_ports(config.ports_file, pt);
      reload_map = FALSE;
    }

    break;
  }
}

void P_cache_mark_flush(struct chained_cache *queue[], int index, int exiting)
{
  struct timeval commit_basetime;
  int j;

  memset(&commit_basetime, 0, sizeof(commit_basetime));

  /* check-pointing */
  if (new_basetime.tv_sec) commit_basetime.tv_sec = new_basetime.tv_sec;
  else commit_basetime.tv_sec = basetime.tv_sec; 

  /* mark committed entries as such */
  if (!exiting) {
    for (j = 0, pqq_ptr = 0; j < index; j++) {
      if (commit_basetime.tv_sec >= queue[j]->basetime.tv_sec) {
        pending_queries_queue[pqq_ptr] = queue[j];
        pqq_ptr++;
      }
      else queue[j]->valid = PRINT_CACHE_COMMITTED;
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
  if ((sa.ptr+sizeof(struct chained_cache)) <= (sa.base+sa.size)) {
    sa.ptr += sizeof(struct chained_cache);
    elem->next = (struct chained_cache *) sa.ptr;
    return (struct chained_cache *) sa.ptr;
  }
  else return NULL; /* XXX */
}

void P_sum_host_insert(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  struct host_addr tmp;

  memcpy(&tmp, &data->primitives.dst_ip, HostAddrSz);
  memset(&data->primitives.dst_ip, 0, HostAddrSz);
  P_cache_insert(prim_ptrs);
  memcpy(&data->primitives.src_ip, &tmp, HostAddrSz);
  P_cache_insert(prim_ptrs);
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
  if (qq_ptr) P_cache_mark_flush(queries_queue, qq_ptr, TRUE);
  (*purge_func)(queries_queue, qq_ptr);

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

  if (config.sql_history_offset) {
    if (config.sql_history_offset >= timeslot) {
      Log(LOG_ERR, "ERROR ( %s/%s ): History offset (ie. sql_history_offset) must be < history (ie. sql_history).\n", config.name, config.type);
      exit(1);
    }

    t = t - (timeslot + config.sql_history_offset);
  }

  basetime.tv_sec = t;

  memset(&new_basetime, 0, sizeof(new_basetime));
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

void primptrs_set_all_from_chained_cache(struct primitives_ptrs *prim_ptrs, struct chained_cache *entry)
{
  struct pkt_data *data = prim_ptrs->data;

  if (prim_ptrs && data && entry) {
    memset(data, 0, PdataSz);

    data->primitives = entry->primitives;
    prim_ptrs->pbgp = entry->pbgp;
    prim_ptrs->pnat = entry->pnat;
    prim_ptrs->pmpls = entry->pmpls;
    prim_ptrs->pcust = entry->pcust;
  }
}
