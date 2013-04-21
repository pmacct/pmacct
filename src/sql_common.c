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

#define __SQL_COMMON_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "sql_common.h"
#include "crc32.c"
#include "sql_common_m.c"

/* Functions */
void sql_set_signals()
{
  signal(SIGINT, sql_exit_gracefully);
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, reload_maps);
  signal(SIGPIPE, SIG_IGN);
//#if !defined FBSD4
//  signal(SIGCHLD, SIG_IGN);
//#else
  signal(SIGCHLD, ignore_falling_child);
//#endif
}

void sql_set_insert_func()
{
  if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET))
    insert_func = sql_sum_host_insert;
  else if (config.what_to_count & COUNT_SUM_PORT) insert_func = sql_sum_port_insert;
  else if (config.what_to_count & COUNT_SUM_AS) insert_func = sql_sum_as_insert;
#if defined (HAVE_L2)
  else if (config.what_to_count & COUNT_SUM_MAC) insert_func = sql_sum_mac_insert;
#endif
  else insert_func = sql_cache_insert;
}

void sql_init_maps(struct networks_table *nt, struct networks_cache *nc, struct ports_table *pt)
{
  memset(nt, 0, sizeof(struct networks_table));
  memset(nc, 0, sizeof(struct networks_cache));
  memset(pt, 0, sizeof(struct ports_table));

  load_networks(config.networks_file, nt, nc);
  set_net_funcs(nt);

  if (config.ports_file) load_ports(config.ports_file, pt);
  if (config.pkt_len_distrib_bins_str) load_pkt_len_distrib_bins();
  else {
    if (config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB) {
      Log(LOG_ERR, "ERROR ( %s/%s ): 'aggregate' contains pkt_len_distrib but no 'pkt_len_distrib_bins' defined. Exiting.\n", config.name, config.type);
      exit_plugin(1);
    }
  }
}

void sql_init_global_buffers()
{
  memset(sql_data, 0, sizeof(sql_data));
  memset(lock_clause, 0, sizeof(lock_clause));
  memset(unlock_clause, 0, sizeof(unlock_clause));
  memset(update_clause, 0, sizeof(update_clause));
  memset(set_clause, 0, sizeof(set_clause));
  memset(copy_clause, 0, sizeof(copy_clause));
  memset(insert_clause, 0, sizeof(insert_clause));
  memset(insert_counters_clause, 0, sizeof(insert_counters_clause));
  memset(insert_nocounters_clause, 0, sizeof(insert_nocounters_clause));
  memset(where, 0, sizeof(where));
  memset(values, 0, sizeof(values));
  memset(set, 0, sizeof(set));
  memset(set_event, 0, sizeof(set_event));
  memset(&lru_head, 0, sizeof(lru_head));
  lru_tail = &lru_head;

  pipebuf = (unsigned char *) malloc(config.buffer_size);
  cache = (struct db_cache *) malloc(config.sql_cache_entries*sizeof(struct db_cache));
  queries_queue = (struct db_cache **) malloc(qq_size*sizeof(struct db_cache *));
  pending_queries_queue = (struct db_cache **) malloc(qq_size*sizeof(struct db_cache *));

  memset(pipebuf, 0, config.buffer_size);
  memset(cache, 0, config.sql_cache_entries*sizeof(struct db_cache));
  memset(queries_queue, 0, qq_size*sizeof(struct db_cache *));
  memset(pending_queries_queue, 0, qq_size*sizeof(struct db_cache *));
}

/* being the first routine to be called by each SQL plugin, this is
   also the place for some initial common configuration consistency
   check */ 
void sql_init_default_values(struct extra_primitives *extras)
{
  if ( (config.what_to_count & COUNT_CLASS ||
	config.what_to_count & COUNT_TCPFLAGS ||
	extras->off_pkt_bgp_primitives) &&
       config.sql_recovery_logfile) {
    Log(LOG_ERR, "ERROR ( %s/%s ): sql_recovery_logfile is not compatible with: classifiers, BGP-related primitives and TCP flags. Try configuring a backup DB.\n", config.name, config.type);
    exit_plugin(1);
  }

  if (!config.sql_refresh_time) config.sql_refresh_time = DEFAULT_DB_REFRESH_TIME;
  if (!config.sql_table_version) config.sql_table_version = DEFAULT_SQL_TABLE_VERSION;
  if (!config.sql_cache_entries) config.sql_cache_entries = CACHE_ENTRIES;
  if (!config.sql_max_writers) config.sql_max_writers = DEFAULT_SQL_WRITERS_NO;

  if (config.sql_aggressive_classification) {
    if (config.acct_type == ACCT_PM && config.what_to_count & COUNT_CLASS);
    else config.sql_aggressive_classification = FALSE;
  }

  /* SQL table type parsing; basically mapping everything down to a SQL table version */
  /* ie. BGP == 1000 */
  if (config.sql_table_type) {
    if (!strcmp(config.sql_table_type, "bgp")) config.sql_table_version += SQL_TABLE_VERSION_BGP;  
    else {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unknown sql_table_type value: '%s'.\n", config.name, config.type, config.sql_table_type);
      exit_plugin(1);
    }
  }
  else {
    if (extras->off_pkt_bgp_primitives) {
      config.sql_table_version += SQL_TABLE_VERSION_BGP;
      Log(LOG_INFO, "INFO ( %s/%s ): sql_table_type set to 'bgp' (aggregate includes one or more BGP primitives).\n", config.name, config.type);
    }
  }

  qq_ptr = 0; 
  pqq_ptr = 0;
  qq_size = config.sql_cache_entries+(config.sql_refresh_time*REASONABLE_NUMBER);
  pp_size = sizeof(struct pkt_primitives);
  pb_size = sizeof(struct pkt_bgp_primitives);
  pn_size = sizeof(struct pkt_nat_primitives);
  dbc_size = sizeof(struct db_cache);

  memset(&sql_writers, 0, sizeof(sql_writers));
}

void sql_init_historical_acct(time_t now, struct insert_data *idata)
{
  time_t t;

  if (config.sql_history) {
    idata->basetime = now;
    if (config.sql_history == COUNT_MINUTELY) idata->timeslot = config.sql_history_howmany*60;
    else if (config.sql_history == COUNT_HOURLY) idata->timeslot = config.sql_history_howmany*3600;
    else if (config.sql_history == COUNT_DAILY) idata->timeslot = config.sql_history_howmany*86400;
    else if (config.sql_history == COUNT_WEEKLY) idata->timeslot = config.sql_history_howmany*86400*7;
    else if (config.sql_history == COUNT_MONTHLY) {
      idata->basetime = roundoff_time(idata->basetime, "d"); /* resetting day of month */
      idata->timeslot = calc_monthly_timeslot(idata->basetime, config.sql_history_howmany, ADD);
    }

    /* round off stuff */
    t = roundoff_time(idata->basetime, config.sql_history_roundoff);

    while ((t+idata->timeslot) < idata->basetime) {
      t += idata->timeslot;
      if (config.sql_history == COUNT_MONTHLY) idata->timeslot = calc_monthly_timeslot(t, config.sql_history_howmany, ADD);
    }

    idata->basetime = t;
    glob_basetime = idata->basetime;
    idata->new_basetime = idata->basetime;
    glob_new_basetime = idata->basetime;
    glob_timeslot = idata->timeslot;
    idata->committed_basetime = 0;
    glob_committed_basetime = 0;
  }
}

/* NOTE: sql triggers time init: deadline; if a trigger exec is specified but
   no time is supplied, use 'sql_refresh_time' as interval; this will result
   in a trigger being executed each time data is purged into the DB */
void sql_init_triggers(time_t now, struct insert_data *idata)
{
  time_t t, deadline;

  if (config.sql_trigger_exec) {
    deadline = now;

    if (config.sql_trigger_time == COUNT_MINUTELY) idata->t_timeslot = config.sql_trigger_time_howmany*60;
    else if (config.sql_trigger_time == COUNT_HOURLY) idata->t_timeslot = config.sql_trigger_time_howmany*3600;
    else if (config.sql_trigger_time == COUNT_DAILY) idata->t_timeslot = config.sql_trigger_time_howmany*86400;
    else if (config.sql_trigger_time == COUNT_WEEKLY) idata->t_timeslot = config.sql_trigger_time_howmany*86400*7;
    else if (config.sql_trigger_time == COUNT_MONTHLY) {
      deadline = roundoff_time(deadline, "d"); /* resetting day of month */
      idata->t_timeslot = calc_monthly_timeslot(deadline, config.sql_trigger_time_howmany, ADD);
    }
    else idata->t_timeslot = config.sql_refresh_time;

    /* round off stuff */
    t = roundoff_time(deadline, config.sql_history_roundoff);
    while ((t+idata->t_timeslot) < deadline) {
      t += idata->t_timeslot;
      if (config.sql_trigger_time == COUNT_MONTHLY) 
	idata->t_timeslot = calc_monthly_timeslot(t, config.sql_trigger_time_howmany, ADD);
    }
    idata->triggertime = t;

    /* adding a trailer timeslot: it's a deadline not a basetime */
    idata->triggertime += idata->t_timeslot;
    if (config.sql_trigger_time == COUNT_MONTHLY)
      idata->t_timeslot = calc_monthly_timeslot(t, config.sql_trigger_time_howmany, ADD);
  }
}

void sql_init_refresh_deadline(time_t *rd)
{
  time_t t;

  t = roundoff_time(*rd, config.sql_history_roundoff);
  while ((t+config.sql_refresh_time) < *rd) t += config.sql_refresh_time;
  *rd = t;
  *rd += (config.sql_refresh_time+config.sql_startup_delay); /* it's a deadline not a basetime */
}

void sql_init_pipe(struct pollfd *pollfd, int fd)
{
  pollfd->fd = fd;
  pollfd->events = POLLIN;
  setnonblocking(fd);
}

struct template_entry *sql_init_logfile_template(struct template_header *hdr)
{
  struct template_entry *te;

  te = build_template(hdr);
  set_template_funcs(hdr, te);

  return te;
}

void sql_link_backend_descriptors(struct BE_descs *registry, struct DBdesc *p, struct DBdesc *b)
{
  memset(registry, 0, sizeof(struct BE_descs));
  memset(p, 0, sizeof(struct DBdesc));
  memset(b, 0, sizeof(struct DBdesc));

  registry->p = p;
  registry->b = b;
  registry->p->type = BE_TYPE_PRIMARY;
  registry->b->type = BE_TYPE_BACKUP;

  if (*sqlfunc_cbr.create_backend) {
    (*sqlfunc_cbr.create_backend)(registry->p);
    (*sqlfunc_cbr.create_backend)(registry->b);
  }
}

void sql_cache_modulo(struct primitives_ptrs *prim_ptrs, struct insert_data *idata)
{
  struct pkt_data *pdata = prim_ptrs->data;
  struct pkt_primitives *srcdst = &pdata->primitives;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;

  idata->hash = cache_crc32((unsigned char *)srcdst, pp_size);
  if (pbgp) idata->hash ^= cache_crc32((unsigned char *)pbgp, pb_size);
  if (pnat) idata->hash ^= cache_crc32((unsigned char *)pnat, pn_size);
  idata->modulo = idata->hash % config.sql_cache_entries;
}

int sql_cache_flush(struct db_cache *queue[], int index, struct insert_data *idata, int exiting)
{
  int j, tmp_retired = sql_writers.retired, delay = 0, new_basetime = FALSE;
  struct db_cache *Cursor, *auxCursor, *PendingElem, SavedCursor;

  /* We are seeking how many time-bins data has to be delayed by; residual
     time is taken into account by scanner deadlines (sql_refresh_time) */
  if (config.sql_startup_delay) {
    delay = config.sql_startup_delay/idata->timeslot; 
    delay = delay*idata->timeslot;
  }

  /* check-pointing: we record last committed time-bin; part of this is
     checking whether basetime was moved forward yet (as this is not for
     sure). */
  if (idata->new_basetime && idata->new_basetime < idata->basetime &&
      idata->new_basetime > idata->committed_basetime) {
    new_basetime = TRUE;
    idata->committed_basetime = idata->new_basetime; 
  }
  else idata->committed_basetime = idata->basetime;

  /* If aggressive classification is enabled and there are still
     chances for the stream to be classified - ie. tentatives is
     non-zero - let's leave it in SQL_CACHE_INUSE state */
  if (!exiting) {
    if (config.sql_aggressive_classification) {
      for (j = 0, pqq_ptr = 0; j < index; j++) {
        if (!queue[j]->primitives.class && queue[j]->tentatives && (queue[j]->start_tag > (idata->now - ((STALE_M-1) * config.sql_refresh_time))) ) {
          pending_queries_queue[pqq_ptr] = queue[j];
          pqq_ptr++;
        }
        else if (new_basetime && queue[j]->basetime+delay >= idata->basetime) {
	  pending_queries_queue[pqq_ptr] = queue[j];
	  pqq_ptr++;
        }
        else if (!new_basetime && queue[j]->basetime+delay > idata->basetime) {
          pending_queries_queue[pqq_ptr] = queue[j];
          pqq_ptr++;
        }
        else queue[j]->valid = SQL_CACHE_COMMITTED;
      }
    }
    else {
      for (j = 0, pqq_ptr = 0; j < index; j++) {
        if (new_basetime && queue[j]->basetime+delay >= idata->basetime) {
          pending_queries_queue[pqq_ptr] = queue[j];
          pqq_ptr++;
        }
        else if (!new_basetime && queue[j]->basetime+delay > idata->basetime) {
          pending_queries_queue[pqq_ptr] = queue[j];
          pqq_ptr++;
        }
        else queue[j]->valid = SQL_CACHE_COMMITTED;
      }
    }
  }
  /* If exiting instead .. */
  else {
    for (j = 0; j < index; j++) queue[j]->valid = SQL_CACHE_COMMITTED; 
  } 

  /* Imposing maximum number of writers */
  sql_writers.active -= MIN(sql_writers.active, tmp_retired);
  sql_writers.retired -= tmp_retired;

  if (sql_writers.active < config.sql_max_writers) {
    /* If we are very near to our maximum writers threshold, let's resort to any configured
       recovery mechanism - SQL_CACHE_COMMITTED => SQL_CACHE_ERROR; otherwise, will proceed
       as usual */
    if ((sql_writers.active == config.sql_max_writers-1) &&
	(config.sql_backup_host || config.sql_recovery_logfile)) {
      for (j = 0; j < index; j++) {
	if (queue[j]->valid == SQL_CACHE_COMMITTED) queue[j]->valid = SQL_CACHE_ERROR;
      }
      sql_writers.flags = CHLD_WARNING;
    }
    else sql_writers.flags = 0; /* everything is just fine */

    sql_writers.active++;
  }
  else {
    Log(LOG_WARNING, "WARN ( %s/%s ): Maximum number of SQL writer processes reached (%d).\n", config.name, config.type, sql_writers.active);
    sql_writers.flags = CHLD_ALERT;
  }

  return index;
}

int sql_cache_flush_pending(struct db_cache *queue[], int index, struct insert_data *idata)
{
  struct db_cache *Cursor, *auxCursor, *PendingElem, SavedCursor;
  int j;

  /* Not everything was purged, let's sort out the SQL cache buckets involved into that */
  if (index) {
    for (j = 0; j < index; j++) {
      PendingElem = queue[j];
      for (Cursor = PendingElem, auxCursor = NULL; Cursor; auxCursor = Cursor, Cursor = Cursor->prev);

      /* Check whether we are already first in the bucket */
      if (auxCursor != PendingElem) {
        for (Cursor = auxCursor; Cursor && Cursor != PendingElem && Cursor->valid == SQL_CACHE_INUSE; Cursor = Cursor->next);
        /* Check whether a) the whole bucket chain is currently in use
	   or b) we came across the current pending element: meaning no
	   free positions are available in the chain, ahead of it */
        if (Cursor && Cursor != PendingElem) {
          /* Check whether we have to replace the first element in the bucket */
          if (!Cursor->prev) {
            memcpy(&SavedCursor, Cursor, sizeof(struct db_cache));
            memcpy(Cursor, PendingElem, sizeof(struct db_cache));
            Cursor->prev = NULL;
            Cursor->next = SavedCursor.next;
            Cursor->chained = 0;
            Cursor->lru_prev = NULL;
            Cursor->lru_next = NULL;
            Cursor->lru_tag = PendingElem->lru_tag;
	    if (PendingElem->cbgp) PendingElem->cbgp = NULL;
	    if (PendingElem->pnat) PendingElem->pnat = NULL;
            RetireElem(PendingElem);
            queue[j] = Cursor;
          }
          /* We found at least one Cursor->valid == SQL_CACHE_INUSE */
          else SwapChainedElems(PendingElem, Cursor);
        }
      }
    }
  }
}

struct db_cache *sql_cache_search(struct primitives_ptrs *prim_ptrs, time_t basetime)
{
  struct pkt_data *pdata = prim_ptrs->data;
  struct pkt_primitives *data = &pdata->primitives;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  unsigned int modulo;
  struct db_cache *Cursor;
  struct insert_data idata;
  int res_data = TRUE, res_bgp = TRUE, res_nat = TRUE;

  sql_cache_modulo(prim_ptrs, &idata);
  modulo = idata.modulo;

  Cursor = &cache[idata.modulo];

  start:
  if (idata.hash != Cursor->signature) {
    if (Cursor->valid == SQL_CACHE_INUSE) {
      follow_chain:
      if (Cursor->next) {
        Cursor = Cursor->next;
        goto start;
      }
    }
  }
  else {
    if (Cursor->valid == SQL_CACHE_INUSE) {
      /* checks: pkt_primitives and pkt_bgp_primitives */
      res_data = memcmp(&Cursor->primitives, data, sizeof(struct pkt_primitives));
      if (pbgp) {
	if (Cursor->cbgp) {
	  struct pkt_bgp_primitives tmp_pbgp;

	  cache_to_pkt_bgp_primitives(&tmp_pbgp, Cursor->cbgp);
	  res_bgp = memcmp(&tmp_pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
	}
      }
      else res_bgp = FALSE;

      if (pnat && Cursor->pnat) {
        res_nat = memcmp(Cursor->pnat, pnat, sizeof(struct pkt_nat_primitives));
      }
      else res_nat = FALSE;

      if (!res_data && !res_bgp && !res_nat) {
        /* additional check: time */
        if ((Cursor->basetime < basetime) && config.sql_history)
          goto follow_chain;
        else return Cursor;
      }
      else goto follow_chain;
    }
  }

  return NULL;
}

void sql_cache_insert(struct primitives_ptrs *prim_ptrs, struct insert_data *idata)
{
  struct pkt_data *data = prim_ptrs->data;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  unsigned int modulo;
  unsigned long int basetime = idata->basetime, timeslot = idata->timeslot;
  struct pkt_primitives *srcdst = &data->primitives;
  struct db_cache *Cursor, *newElem, *SafePtr = NULL, *staleElem = NULL;
  unsigned int cb_size = sizeof(struct cache_bgp_primitives);
  int ret;

  if (data->time_start.tv_sec && config.sql_history) {
    while (basetime > data->time_start.tv_sec) {
      if (config.sql_history != COUNT_MONTHLY) basetime -= timeslot;
      else {
        timeslot = calc_monthly_timeslot(basetime, config.sql_history_howmany, SUB);
        basetime -= timeslot;
      }
    }
    while ((basetime+timeslot) < data->time_start.tv_sec) {
      if (config.sql_history != COUNT_MONTHLY) basetime += timeslot;
      else {
        basetime += timeslot;
        timeslot = calc_monthly_timeslot(basetime, config.sql_history_howmany, ADD);
      }
    }
  }

  /* We are classifing packets. We have a non-zero bytes accumulator (ba)
     and a non-zero class. Before accounting ba to this class, we have to
     remove ba from class zero. */
  if (config.what_to_count & COUNT_CLASS && data->cst.ba && data->primitives.class) {
    pm_class_t lclass = data->primitives.class;

    data->primitives.class = 0;
    Cursor = sql_cache_search(prim_ptrs, basetime);
    data->primitives.class = lclass;

    /* We can assign the flow to a new class only if we are able to subtract
       the accumulator from the zero-class. If this is not the case, we will
       discard the accumulators. The assumption is that accumulators are not
       retroactive */

    if (Cursor) {
      if (timeval_cmp(&data->cst.stamp, &idata->flushtime) >= 0) { 
        Cursor->bytes_counter -= MIN(Cursor->bytes_counter, data->cst.ba);
        Cursor->packet_counter -= MIN(Cursor->packet_counter, data->cst.pa);
        Cursor->flows_counter -= MIN(Cursor->flows_counter, data->cst.fa);
      }
      else memset(&data->cst, 0, CSSz);
    }
    else memset(&data->cst, 0, CSSz); 
  }

  sql_cache_modulo(prim_ptrs, idata);
  modulo = idata->modulo;

  /* housekeeping */
  if (lru_head.lru_next && ((idata->now-lru_head.lru_next->lru_tag) > RETIRE_M*config.sql_refresh_time))
    RetireElem(lru_head.lru_next);

  Cursor = &cache[idata->modulo];

  start:
  if (idata->hash != Cursor->signature) {
    if (Cursor->valid == SQL_CACHE_INUSE) {
      follow_chain:
      if (Cursor->next) {
        Cursor = Cursor->next;
        goto start;
      }
      else {
        if (lru_head.lru_next && ((idata->now-lru_head.lru_next->lru_tag) > STALE_M*config.sql_refresh_time)) {
          newElem = lru_head.lru_next;
	  if (newElem != Cursor) { 
            ReBuildChain(Cursor, newElem);
            Cursor = newElem;
            goto insert; /* we have successfully reused a stale element */
	  }
	  /* if the last LRU element is our cursor and is still in use,
	     we are forced to abort the LRU idea and create a new brand
	     new element */
	  else goto create;
        }
        else {
	  create:
          newElem = (struct db_cache *) malloc(sizeof(struct db_cache));
          if (newElem) {
            memset(newElem, 0, sizeof(struct db_cache));
            BuildChain(Cursor, newElem);
            Cursor = newElem;
            goto insert; /* creating a new element */
          }
          else goto safe_action; /* we should have finished memory */
        }
      }
    }
    else goto insert; /* we found a no more valid entry; let's insert here our data */
  }
  else {
    if (Cursor->valid == SQL_CACHE_INUSE) {
      int res_data = TRUE, res_bgp = TRUE, res_nat = TRUE;

      /* checks: pkt_primitives and pkt_bgp_primitives */
      res_data = memcmp(&Cursor->primitives, srcdst, sizeof(struct pkt_primitives));

      if (pbgp) {
        if (Cursor->cbgp) {
	  struct pkt_bgp_primitives tmp_pbgp;

	  cache_to_pkt_bgp_primitives(&tmp_pbgp, Cursor->cbgp);
	  res_bgp = memcmp(&tmp_pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
	}
      }
      else res_bgp = FALSE;

      if (pnat && Cursor->pnat) {
        res_nat = memcmp(Cursor->pnat, pnat, sizeof(struct pkt_nat_primitives));
      }
      else res_nat = FALSE;

      if (!res_data && !res_bgp && !res_nat) {
        /* additional check: time */
        if ((Cursor->basetime < basetime) && config.sql_history) {
          if (!staleElem && Cursor->chained) staleElem = Cursor;
          goto follow_chain;
        }
        /* additional check: bytes counter overflow */
        else if (Cursor->bytes_counter > CACHE_THRESHOLD) {
          if (!staleElem && Cursor->chained) staleElem = Cursor;
          goto follow_chain;
        }
        else goto update;
      }
      else goto follow_chain;
    }
    else goto insert;
  }

  insert:
  if (qq_ptr < qq_size) {
    queries_queue[qq_ptr] = Cursor;
    qq_ptr++;
  }
  else SafePtr = Cursor;

  /* we add the new entry in the cache */
  memcpy(&Cursor->primitives, srcdst, sizeof(struct pkt_primitives));

  if (pbgp) {
    if (!Cursor->cbgp) {
      Cursor->cbgp = (struct cache_bgp_primitives *) malloc(cb_size);
      memset(Cursor->cbgp, 0, cb_size);
    }
    pkt_to_cache_bgp_primitives(Cursor->cbgp, pbgp, config.what_to_count);
  }
  else Cursor->cbgp = NULL;

  if (pnat) {
    if (!Cursor->pnat) {
      Cursor->pnat = (struct pkt_nat_primitives *) malloc(pn_size);
    }
    memcpy(Cursor->pnat, pnat, pn_size);
  }
  else Cursor->pnat = NULL;

  Cursor->packet_counter = data->pkt_num;
  Cursor->flows_counter = data->flo_num;
  Cursor->bytes_counter = data->pkt_len;
  Cursor->flow_type = data->flow_type;
  Cursor->tcp_flags = data->tcp_flags;
  if (config.what_to_count & COUNT_CLASS) {
    Cursor->bytes_counter += data->cst.ba;
    Cursor->packet_counter += data->cst.pa;
    Cursor->flows_counter += data->cst.fa;
    Cursor->tentatives = data->cst.tentatives;
  }
  Cursor->valid = SQL_CACHE_INUSE;
  Cursor->basetime = basetime;
  Cursor->start_tag = idata->now;
  Cursor->lru_tag = idata->now;
  Cursor->signature = idata->hash;
  /* We are not so fancy to reuse elements which have
     not been malloc()'d before */
  if (Cursor->chained) AddToLRUTail(Cursor); 
  if (SafePtr) goto safe_action;
  if (staleElem) SwapChainedElems(Cursor, staleElem);
  return;

  update:
  Cursor->packet_counter += data->pkt_num;
  Cursor->flows_counter += data->flo_num;
  Cursor->bytes_counter += data->pkt_len;
  Cursor->flow_type = data->flow_type;
  Cursor->tcp_flags |= data->tcp_flags;
  if (config.what_to_count & COUNT_CLASS) {
    Cursor->bytes_counter += data->cst.ba;
    Cursor->packet_counter += data->cst.pa;
    Cursor->flows_counter += data->cst.fa;
    Cursor->tentatives = data->cst.tentatives;
  }
  return;

  safe_action:
  Log(LOG_WARNING, "WARN ( %s/%s ): purging process (CAUSE: safe action)\n", config.name, config.type);

  if (qq_ptr) sql_cache_flush(queries_queue, qq_ptr, idata, FALSE); 
  switch (ret = fork()) {
  case 0: /* Child */
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    pm_setproctitle("%s [%s]", "SQL Plugin -- DB Writer (urgent)", config.name);

    if (qq_ptr && sql_writers.flags != CHLD_ALERT) {
      if (sql_writers.flags == CHLD_WARNING) sql_db_fail(&p);
      (*sqlfunc_cbr.connect)(&p, config.sql_host);
      (*sqlfunc_cbr.purge)(queries_queue, qq_ptr, idata);
      (*sqlfunc_cbr.close)(&bed);
    }

    exit(0);
  default: /* Parent */
    if (ret == -1) { /* Something went wrong */
      Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork DB writer (urgent): %s\n", config.name, config.type, strerror(errno));
      sql_writers.active--;
    }

    qq_ptr = pqq_ptr;
    memcpy(queries_queue, pending_queries_queue, sizeof(queries_queue));
    break;
  }
  if (SafePtr) {
    queries_queue[qq_ptr] = Cursor;
    qq_ptr++;
  }
  else {
    Cursor = &cache[idata->modulo];
    goto start;
  }
}

void sql_sum_host_insert(struct primitives_ptrs *prim_ptrs, struct insert_data *idata)
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
    sql_cache_insert(prim_ptrs, idata);
    data->primitives.src_ip.address.ipv4.s_addr = ip.s_addr;
    sql_cache_insert(prim_ptrs, idata);
  }
#if defined ENABLE_IPV6
  if (data->primitives.dst_ip.family == AF_INET6) {
    memcpy(&ip6, &data->primitives.dst_ip.address.ipv6, sizeof(struct in6_addr));
    memset(&data->primitives.dst_ip.address.ipv6, 0, sizeof(struct in6_addr));
    data->primitives.dst_ip.family = 0;
    sql_cache_insert(prim_ptrs, idata);
    memcpy(&data->primitives.src_ip.address.ipv6, &ip6, sizeof(struct in6_addr));
    sql_cache_insert(prim_ptrs, idata);
    return;
  }
#endif
}

void sql_sum_port_insert(struct primitives_ptrs *prim_ptrs, struct insert_data *idata)
{
  struct pkt_data *data = prim_ptrs->data;
  u_int16_t port;

  port = data->primitives.dst_port;
  data->primitives.dst_port = 0;
  sql_cache_insert(prim_ptrs, idata);
  data->primitives.src_port = port;
  sql_cache_insert(prim_ptrs, idata);
}

void sql_sum_as_insert(struct primitives_ptrs *prim_ptrs, struct insert_data *idata)
{
  struct pkt_data *data = prim_ptrs->data; 
  as_t asn;

  asn = data->primitives.dst_as;
  data->primitives.dst_as = 0;
  sql_cache_insert(prim_ptrs, idata);
  data->primitives.src_as = asn;
  sql_cache_insert(prim_ptrs, idata);
}

#if defined (HAVE_L2)
void sql_sum_mac_insert(struct primitives_ptrs *prim_ptrs, struct insert_data *idata)
{
  struct pkt_data *data = prim_ptrs->data;
  u_char macaddr[ETH_ADDR_LEN];

  memcpy(macaddr, &data->primitives.eth_dhost, ETH_ADDR_LEN);
  memset(data->primitives.eth_dhost, 0, ETH_ADDR_LEN);
  sql_cache_insert(prim_ptrs, idata);
  memcpy(&data->primitives.eth_shost, macaddr, ETH_ADDR_LEN);
  sql_cache_insert(prim_ptrs, idata);
}
#endif

int sql_trigger_exec(char *filename)
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

void sql_db_ok(struct DBdesc *db)
{
  db->fail = FALSE;
  db->connected = TRUE;
}

void sql_db_fail(struct DBdesc *db)
{
  db->fail = TRUE;
  db->connected = FALSE;
}

void sql_db_errmsg(struct DBdesc *db)
{
  if (db->type == BE_TYPE_PRIMARY)
    Log(LOG_ERR, "ERROR ( %s/%s ): PRIMARY '%s' backend trouble.\n", config.name, config.type, config.type);
  else if (db->type == BE_TYPE_BACKUP) 
    Log(LOG_ERR, "ERROR ( %s/%s ): BACKUP '%s' backend trouble.\n", config.name, config.type, config.type);

  if (db->errmsg) Log(LOG_ERR, "ERROR ( %s/%s ): The SQL server says: %s\n\n", config.name, config.type, db->errmsg);
}

void sql_exit_gracefully(int signum)
{
  struct insert_data idata;

  signal(SIGINT, SIG_IGN);
  signal(SIGHUP, SIG_IGN);

  Log(LOG_DEBUG, "( %s/%s ) *** Purging queries queue ***\n", config.name, config.type);
  if (config.syslog) closelog();

  memset(&idata, 0, sizeof(idata));
  idata.num_primitives = glob_num_primitives;
  idata.now = time(NULL);
  idata.basetime = glob_basetime;
  idata.dyn_table = glob_dyn_table;
  idata.new_basetime = glob_new_basetime;
  idata.timeslot = glob_timeslot;
  idata.committed_basetime = glob_committed_basetime;
  if (config.sql_backup_host || config.sql_recovery_logfile) idata.recover = TRUE;
  if (config.what_to_count & COUNT_CLASS) config.sql_aggressive_classification = FALSE;

  sql_cache_flush(queries_queue, qq_ptr, &idata, TRUE);
  if (sql_writers.flags != CHLD_ALERT) {
    if (sql_writers.flags == CHLD_WARNING) sql_db_fail(&p);
    (*sqlfunc_cbr.connect)(&p, config.sql_host);
    (*sqlfunc_cbr.purge)(queries_queue, qq_ptr, &idata);
    (*sqlfunc_cbr.close)(&bed);
  }

  exit_plugin(0);
}

int sql_evaluate_primitives(int primitive)
{
  u_int64_t what_to_count = 0, what_to_count_2 = 0, fakes = 0;
  short int assume_custom_table = FALSE; 
  char *insert_clause_start_ptr = insert_clause + strlen(insert_clause);
  char default_delim[] = ",", delim_buf[SRVBUFLEN];

  /* SQL tables < v6 multiplex IP addresses and AS numbers on the same field, thus are
     unable to use both them for a same direction (ie. src, dst). Tables v6 break such
     assumption */ 
  if (((config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET|COUNT_SUM_HOST|COUNT_SUM_NET) &&
     config.what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) || (config.what_to_count & COUNT_DST_AS
     && config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET))) && config.sql_table_version < 6) { 
    Log(LOG_ERR, "ERROR ( %s/%s ): SQL tables < v6 are unable to mix IP addresses and AS numbers (ie. src_ip, src_as).\n", config.name, config.type);
    exit_plugin(1);
  }

  if (config.sql_optimize_clauses) {
    what_to_count = config.what_to_count;
    what_to_count_2 = config.what_to_count_2;
    assume_custom_table = TRUE;
  }
  else {
    /* It is being requested to avoid SQL query optmization;
       then we will build an all-true bitmap */
    if (config.what_to_count & COUNT_SRC_MAC) what_to_count |= COUNT_SRC_MAC;
    else if (config.what_to_count & COUNT_SUM_MAC) what_to_count |= COUNT_SUM_MAC;
    else fakes |= FAKE_SRC_MAC;

    if (config.what_to_count & COUNT_DST_MAC) what_to_count |= COUNT_DST_MAC;
    else fakes |= FAKE_DST_MAC;

    if (config.what_to_count & COUNT_SUM_PORT) what_to_count |= COUNT_SUM_PORT;

    what_to_count |= COUNT_SRC_PORT|COUNT_DST_PORT|COUNT_TCPFLAGS|COUNT_IP_PROTO|COUNT_CLASS|COUNT_VLAN|COUNT_IP_TOS;

    if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) what_to_count |= COUNT_SRC_HOST;
    else if (config.what_to_count & COUNT_SUM_HOST) what_to_count |= COUNT_SUM_HOST;
    else if (config.what_to_count & COUNT_SUM_NET) what_to_count |= COUNT_SUM_NET;
    else fakes |= FAKE_SRC_HOST;

    if (config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) what_to_count |= COUNT_DST_HOST;
    else fakes |= FAKE_DST_HOST;

    if (config.what_to_count & COUNT_AS_PATH) what_to_count |= COUNT_AS_PATH;
    else fakes |= FAKE_AS_PATH;

    if (config.what_to_count & COUNT_SRC_AS_PATH) what_to_count |= COUNT_SRC_AS_PATH;

    if (config.what_to_count & COUNT_STD_COMM) what_to_count |= COUNT_STD_COMM;
    else if (config.what_to_count & COUNT_EXT_COMM) what_to_count |= COUNT_EXT_COMM;
    else fakes |= FAKE_COMMS;

    if (config.what_to_count & COUNT_SRC_STD_COMM) what_to_count |= COUNT_SRC_STD_COMM;
    else if (config.what_to_count & COUNT_SRC_EXT_COMM) what_to_count |= COUNT_SRC_EXT_COMM;

    if (config.what_to_count & COUNT_PEER_SRC_AS) what_to_count |= COUNT_PEER_SRC_AS;
    else fakes |= FAKE_PEER_SRC_AS;

    if (config.what_to_count & COUNT_PEER_DST_AS) what_to_count |= COUNT_PEER_DST_AS;
    else fakes |= FAKE_PEER_DST_AS;
    
    if (config.what_to_count & COUNT_PEER_SRC_IP) what_to_count |= COUNT_PEER_SRC_IP;
    else fakes |= FAKE_PEER_SRC_IP;

    if (config.what_to_count & COUNT_PEER_DST_IP) what_to_count |= COUNT_PEER_DST_IP;
    else fakes |= FAKE_PEER_DST_IP;

    what_to_count |= COUNT_LOCAL_PREF|COUNT_MED;

    if (config.what_to_count & COUNT_SRC_LOCAL_PREF) what_to_count |= COUNT_SRC_LOCAL_PREF;
    if (config.what_to_count & COUNT_SRC_MED) what_to_count |= COUNT_SRC_MED;

    if (config.sql_table_version < 6) {
      if (config.what_to_count & COUNT_SRC_AS) what_to_count |= COUNT_SRC_AS;
      else if (config.what_to_count & COUNT_SUM_AS) what_to_count |= COUNT_SUM_AS; 
      else fakes |= FAKE_SRC_AS;
    }
    else {
      what_to_count |= COUNT_SRC_AS; 
      if (config.what_to_count & COUNT_SUM_AS) what_to_count |= COUNT_SUM_AS;
    }

    if (config.sql_table_version < 6) {
      if (config.what_to_count & COUNT_DST_AS) what_to_count |= COUNT_DST_AS;
      else fakes |= FAKE_DST_AS;
    }
    else what_to_count |= COUNT_DST_AS;

    if (config.sql_table_version < 6) {
      if (what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) {
        if (fakes & FAKE_SRC_HOST) fakes ^= FAKE_SRC_HOST;
      }
      else {
        if (fakes & FAKE_SRC_AS) fakes ^= FAKE_SRC_AS;
      }
      if (what_to_count & COUNT_DST_AS) {
        if (fakes & FAKE_DST_HOST) fakes ^= FAKE_DST_HOST;
      }
      else {
        if (fakes & FAKE_DST_AS) fakes ^= FAKE_DST_AS;
      }
    }

    what_to_count |= COUNT_ID;

    /* aggregation primitives listed below are not part of any default SQL schema; hence
       no matter if SQL statements optimization is enabled or not, they have to be passed
       on blindly */
    if (config.what_to_count & COUNT_ID2) what_to_count |= COUNT_ID2;
    if (config.what_to_count & COUNT_COS) what_to_count |= COUNT_COS;
    if (config.what_to_count & COUNT_ETHERTYPE) what_to_count |= COUNT_ETHERTYPE;
    if (config.what_to_count & COUNT_MPLS_VPN_RD) what_to_count |= COUNT_MPLS_VPN_RD;
    if (config.what_to_count & COUNT_IN_IFACE) what_to_count |= COUNT_IN_IFACE;
    if (config.what_to_count & COUNT_OUT_IFACE) what_to_count |= COUNT_OUT_IFACE;
    if (config.what_to_count & COUNT_SRC_NMASK) what_to_count |= COUNT_SRC_NMASK;
    if (config.what_to_count & COUNT_DST_NMASK) what_to_count |= COUNT_DST_NMASK;

#if defined WITH_GEOIP
    if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) what_to_count_2 |= COUNT_SRC_HOST_COUNTRY;
    if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) what_to_count_2 |= COUNT_DST_HOST_COUNTRY;
#endif
    if (config.what_to_count_2 & COUNT_SAMPLING_RATE) what_to_count_2 |= COUNT_SAMPLING_RATE;
    if (config.what_to_count_2 & COUNT_PKT_LEN_DISTRIB) what_to_count_2 |= COUNT_PKT_LEN_DISTRIB;
    if (config.what_to_count_2 & COUNT_POST_NAT_SRC_HOST) what_to_count_2 |= COUNT_POST_NAT_SRC_HOST;
    if (config.what_to_count_2 & COUNT_POST_NAT_DST_HOST) what_to_count_2 |= COUNT_POST_NAT_DST_HOST;
    if (config.what_to_count_2 & COUNT_POST_NAT_SRC_PORT) what_to_count_2 |= COUNT_POST_NAT_SRC_PORT;
    if (config.what_to_count_2 & COUNT_POST_NAT_DST_PORT) what_to_count_2 |= COUNT_POST_NAT_DST_PORT;
    if (config.what_to_count_2 & COUNT_NAT_EVENT) what_to_count_2 |= COUNT_NAT_EVENT;
    if (config.what_to_count_2 & COUNT_TIMESTAMP_START) what_to_count_2 |= COUNT_TIMESTAMP_START;
    if (config.what_to_count_2 & COUNT_TIMESTAMP_END) what_to_count_2 |= COUNT_TIMESTAMP_END;
  }

  /* sorting out delimiter */
  if (!config.sql_delimiter || !config.sql_use_copy)
    snprintf(delim_buf, SRVBUFLEN, "%s ", default_delim);
  else
    snprintf(delim_buf, SRVBUFLEN, "%s ", config.sql_delimiter);

  /* 1st part: arranging pointers to an opaque structure and 
     composing the static selection (WHERE) string */

#if defined (HAVE_L2)
  if (what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC)) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) { 
      Log(LOG_ERR, "ERROR ( %s/%s ): MAC accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_plugin(1);
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "mac_src", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "mac_src=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_SRC_MAC;
      values[primitive].handler = where[primitive].handler = count_src_mac_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_DST_MAC) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): MAC accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_plugin(1);
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "mac_dst", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "mac_dst=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_DST_MAC;
      values[primitive].handler = where[primitive].handler = count_dst_mac_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_VLAN) {
    int count_it = FALSE;

    if ((config.sql_table_version < 2 || config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_VLAN) {
        Log(LOG_ERR, "ERROR ( %s/%s ): VLAN accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_plugin(1);
      }
      else what_to_count ^= COUNT_VLAN;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "vlan", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "vlan=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_VLAN;
      values[primitive].handler = where[primitive].handler = count_vlan_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_COS) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "cos", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "cos=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_COS;
    values[primitive].handler = where[primitive].handler = count_cos_handler;
    primitive++;
  }

  if (what_to_count & COUNT_ETHERTYPE) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "etype", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%x\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "etype=\'%x\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_ETHERTYPE;
    values[primitive].handler = where[primitive].handler = count_etype_handler;
    primitive++;
  }
#endif

  if (what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET|COUNT_SUM_HOST|COUNT_SUM_NET)) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): IP host accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_plugin(1);
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
        strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
        strncat(values[primitive].string, "INET_ATON(\'%s\')", SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, "ip_src=INET_ATON(\'%s\')", SPACELEFT(where[primitive].string));
        values[primitive].type = where[primitive].type = COUNT_SRC_HOST;
        values[primitive].handler = where[primitive].handler = count_src_host_handler;
        primitive++;
      }
      else {
	strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_src=\'%s\'", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = COUNT_SRC_HOST;
	values[primitive].handler = where[primitive].handler = count_src_host_handler;
	primitive++;
      }
    }
  }

  if (what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): IP host accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_plugin(1);
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
        strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
        strncat(values[primitive].string, "INET_ATON(\'%s\')", SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, "ip_dst=INET_ATON(\'%s\')", SPACELEFT(where[primitive].string));
        values[primitive].type = where[primitive].type = COUNT_DST_HOST;
        values[primitive].handler = where[primitive].handler = count_dst_host_handler;
        primitive++;
      }
      else {
	strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = COUNT_DST_HOST;
	values[primitive].handler = where[primitive].handler = count_dst_host_handler;
	primitive++;
      }
    }
  }

  if (what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }

    if (config.sql_table_version >= 6) {
      strncat(insert_clause, "as_src", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "as_src=%u", SPACELEFT(where[primitive].string));
    }
    else {
      strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
      if (!strcmp(config.type, "mysql") || !strcmp(config.type, "sqlite3") ||
	 (!strcmp(config.type, "pgsql") && !strcmp(config.sql_data, "unified"))) {
	strncat(values[primitive].string, "\'%u\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_src=\'%u\'", SPACELEFT(where[primitive].string));
      }
      else {
	strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_src=%u", SPACELEFT(where[primitive].string));
      }
    }
    values[primitive].type = where[primitive].type = COUNT_SRC_AS;
    values[primitive].handler = where[primitive].handler = count_src_as_handler;
    primitive++;
  }

  if (what_to_count & COUNT_IN_IFACE) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "iface_in", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "iface_in=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_IN_IFACE;
    values[primitive].handler = where[primitive].handler = count_in_iface_handler;
    primitive++;
  }

  if (what_to_count & COUNT_OUT_IFACE) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "iface_out", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "iface_out=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_OUT_IFACE;
    values[primitive].handler = where[primitive].handler = count_out_iface_handler;
    primitive++;
  }

  if (what_to_count & COUNT_SRC_NMASK) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "mask_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mask_src=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_NMASK;
    values[primitive].handler = where[primitive].handler = count_src_nmask_handler;
    primitive++;
  }

  if (what_to_count & COUNT_DST_NMASK) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "mask_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mask_dst=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_DST_NMASK;
    values[primitive].handler = where[primitive].handler = count_dst_nmask_handler;
    primitive++;
  }

  if (what_to_count & COUNT_DST_AS) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }

    if (config.sql_table_version >= 6) {
      strncat(insert_clause, "as_dst", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "as_dst=%u", SPACELEFT(where[primitive].string));
    }
    else {
      strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
      if (!strcmp(config.type, "mysql") || !strcmp(config.type, "sqlite3") ||
	 (!strcmp(config.type, "pgsql") && !strcmp(config.sql_data, "unified"))) { 
	strncat(values[primitive].string, "\'%u\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_dst=\'%u\'", SPACELEFT(where[primitive].string));
      }
      else {
	strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_dst=%u", SPACELEFT(where[primitive].string));
      }
    }
    values[primitive].type = where[primitive].type = COUNT_DST_AS;
    values[primitive].handler = where[primitive].handler = count_dst_as_handler;
    primitive++;
  }

  if (what_to_count & (COUNT_STD_COMM|COUNT_EXT_COMM)) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_plugin(1);
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "comms", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "comms=\'%s\'", SPACELEFT(where[primitive].string));
      if (what_to_count & COUNT_STD_COMM) {
        values[primitive].type = where[primitive].type = COUNT_STD_COMM;
        values[primitive].handler = where[primitive].handler = count_std_comm_handler;
      }
      else if (what_to_count & COUNT_EXT_COMM) {
        values[primitive].type = where[primitive].type = COUNT_EXT_COMM;
        values[primitive].handler = where[primitive].handler = count_ext_comm_handler;
      }
      primitive++;
    }
  }

  if (what_to_count & (COUNT_SRC_STD_COMM|COUNT_SRC_EXT_COMM)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "comms_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "comms_src=\'%s\'", SPACELEFT(where[primitive].string));
    if (what_to_count & COUNT_SRC_STD_COMM) {
      values[primitive].type = where[primitive].type = COUNT_SRC_STD_COMM;
      values[primitive].handler = where[primitive].handler = count_src_std_comm_handler;
    }
    else if (what_to_count & COUNT_SRC_EXT_COMM) {
      values[primitive].type = where[primitive].type = COUNT_SRC_EXT_COMM;
      values[primitive].handler = where[primitive].handler = count_src_ext_comm_handler;
    }
    primitive++;
  }

  if (what_to_count & COUNT_AS_PATH) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_plugin(1);
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "as_path", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "as_path=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_AS_PATH;
      values[primitive].handler = where[primitive].handler = count_as_path_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_SRC_AS_PATH) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "as_path_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "as_path_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_AS_PATH;
    values[primitive].handler = where[primitive].handler = count_src_as_path_handler;
    primitive++;
  }

  if (what_to_count & COUNT_LOCAL_PREF) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_LOCAL_PREF) {
        Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_plugin(1);
      }
      else what_to_count ^= COUNT_LOCAL_PREF;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "local_pref", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "local_pref=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_LOCAL_PREF;
      values[primitive].handler = where[primitive].handler = count_local_pref_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_SRC_LOCAL_PREF) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "local_pref_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "local_pref_src=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_LOCAL_PREF;
    values[primitive].handler = where[primitive].handler = count_src_local_pref_handler;
    primitive++;
  }

  if (what_to_count & COUNT_MED) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_MED) {
        Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_plugin(1);
      }
      else what_to_count ^= COUNT_MED;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "med", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "med=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_MED;
      values[primitive].handler = where[primitive].handler = count_med_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_SRC_MED) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "med_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "med_src=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_MED;
    values[primitive].handler = where[primitive].handler = count_src_med_handler;
    primitive++;
  }

  if (what_to_count & COUNT_MPLS_VPN_RD) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "mpls_vpn_rd", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mpls_vpn_rd=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_MPLS_VPN_RD;
    values[primitive].handler = where[primitive].handler = count_mpls_vpn_rd_handler;
    primitive++;
  }

  if (what_to_count & COUNT_PEER_SRC_AS) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_plugin(1);
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }

      strncat(insert_clause, "peer_as_src", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "peer_as_src=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_PEER_SRC_AS;
      values[primitive].handler = where[primitive].handler = count_peer_src_as_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_PEER_DST_AS) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_plugin(1);
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }

      strncat(insert_clause, "peer_as_dst", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "peer_as_dst=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_PEER_DST_AS;
      values[primitive].handler = where[primitive].handler = count_peer_dst_as_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_PEER_SRC_IP) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_plugin(1);
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
        strncat(insert_clause, "peer_ip_src", SPACELEFT(insert_clause));
        strncat(values[primitive].string, "INET_ATON(\'%s\')", SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, "peer_ip_src=INET_ATON(\'%s\')", SPACELEFT(where[primitive].string));
        values[primitive].type = where[primitive].type = COUNT_PEER_SRC_IP;
        values[primitive].handler = where[primitive].handler = count_peer_src_ip_handler;
        primitive++;
      }
      else {
	strncat(insert_clause, "peer_ip_src", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "peer_ip_src=\'%s\'", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = COUNT_PEER_SRC_IP;
	values[primitive].handler = where[primitive].handler = count_peer_src_ip_handler;
	primitive++;
      }
    }
  }

  if (what_to_count & COUNT_PEER_DST_IP) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_plugin(1);
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
        strncat(insert_clause, "peer_ip_dst", SPACELEFT(insert_clause));
        strncat(values[primitive].string, "INET_ATON(\'%s\')", SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, "peer_ip_dst=INET_ATON(\'%s\')", SPACELEFT(where[primitive].string));
        values[primitive].type = where[primitive].type = COUNT_PEER_DST_IP;
        values[primitive].handler = where[primitive].handler = count_peer_dst_ip_handler;
        primitive++;
      }
      else {
	strncat(insert_clause, "peer_ip_dst", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "peer_ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = COUNT_PEER_DST_IP;
	values[primitive].handler = where[primitive].handler = count_peer_dst_ip_handler;
	primitive++;
      }
    }
  }

  if (what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) {
        Log(LOG_ERR, "ERROR ( %s/%s ): TCP/UDP port accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_plugin(1);
      }
      else {
        if (what_to_count & COUNT_SRC_PORT) what_to_count ^= COUNT_SRC_PORT;
        if (what_to_count & COUNT_SUM_PORT) what_to_count ^= COUNT_SUM_PORT; 
      }
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      if ((!strcmp(config.type, "mysql") || !strcmp(config.type, "sqlite3")) && config.sql_table_version < 8) {
        strncat(insert_clause, "src_port", SPACELEFT(insert_clause));
        strncat(where[primitive].string, "src_port=%u", SPACELEFT(where[primitive].string));
      }
      else {
        strncat(insert_clause, "port_src", SPACELEFT(insert_clause));
        strncat(where[primitive].string, "port_src=%u", SPACELEFT(where[primitive].string));
      } 
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_SRC_PORT;
      values[primitive].handler = where[primitive].handler = count_src_port_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_DST_PORT) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_DST_PORT) {
        Log(LOG_ERR, "ERROR ( %s/%s ): TCP/UDP port accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_plugin(1);
      }
      else what_to_count ^= COUNT_DST_PORT;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      if ((!strcmp(config.type, "mysql") || !strcmp(config.type, "sqlite3")) && config.sql_table_version < 8) {
        strncat(insert_clause, "dst_port", SPACELEFT(insert_clause));
        strncat(where[primitive].string, "dst_port=%u", SPACELEFT(where[primitive].string));
      }
      else {
        strncat(insert_clause, "port_dst", SPACELEFT(insert_clause));
        strncat(where[primitive].string, "port_dst=%u", SPACELEFT(where[primitive].string));
      }
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_DST_PORT;
      values[primitive].handler = where[primitive].handler = count_dst_port_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_TCPFLAGS) {
    int count_it = FALSE;

    if ((config.sql_table_version < 7 || config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_TCPFLAGS) {
        Log(LOG_ERR, "ERROR ( %s/%s ): TCP flags accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
	exit_plugin(1);
      }
      else what_to_count ^= COUNT_TCPFLAGS;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
	strncat(insert_clause, ", ", SPACELEFT(insert_clause));
	strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      }
      strncat(insert_clause, "tcp_flags", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_TCPFLAGS;
      values[primitive].handler = where[primitive].handler = count_tcpflags_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_IP_TOS) {
    int count_it = FALSE;

    if ((config.sql_table_version < 3 || config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_IP_TOS) {
        Log(LOG_ERR, "ERROR ( %s/%s ): IP ToS accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_plugin(1);
      }
      else what_to_count ^= COUNT_IP_TOS;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "tos", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "tos=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_IP_TOS;
      values[primitive].handler = where[primitive].handler = count_ip_tos_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_IP_PROTO) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_IP_PROTO) {
        Log(LOG_ERR, "ERROR ( %s/%s ): IP proto accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_plugin(1);
      }
      else what_to_count ^= COUNT_IP_PROTO;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "ip_proto", SPACELEFT(insert_clause));
      if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && !config.num_protos) {
        strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, "ip_proto=\'%s\'", SPACELEFT(where[primitive].string));
        values[primitive].handler = where[primitive].handler = MY_count_ip_proto_handler;
      }
      else { 
        strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, "ip_proto=%u", SPACELEFT(where[primitive].string));
        values[primitive].handler = where[primitive].handler = PG_count_ip_proto_handler;
      }
      values[primitive].type = where[primitive].type = COUNT_IP_PROTO;
      primitive++;
    }
  }

#if defined WITH_GEOIP
  if (what_to_count_2 & COUNT_SRC_HOST_COUNTRY) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "country_ip_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "country_ip_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_HOST_COUNTRY;
    values[primitive].handler = where[primitive].handler = count_src_host_country_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_DST_HOST_COUNTRY) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "country_ip_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "country_ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_DST_HOST_COUNTRY;
    values[primitive].handler = where[primitive].handler = count_dst_host_country_handler;
    primitive++;
  }
#endif

  if (what_to_count_2 & COUNT_SAMPLING_RATE) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "sampling_rate", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "sampling_rate=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SAMPLING_RATE;
    values[primitive].handler = where[primitive].handler = count_sampling_rate_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_PKT_LEN_DISTRIB) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "pkt_len_distrib", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "pkt_len_distrib=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_PKT_LEN_DISTRIB;
    values[primitive].handler = where[primitive].handler = count_pkt_len_distrib_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_POST_NAT_SRC_HOST) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
      strncat(insert_clause, "post_nat_ip_src", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "INET_ATON(\'%s\')", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "post_nat_ip_src=INET_ATON(\'%s\')", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_POST_NAT_SRC_HOST;
      values[primitive].handler = where[primitive].handler = count_post_nat_src_ip_handler;
      primitive++;
    }
    else {
      strncat(insert_clause, "post_nat_ip_src", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "post_nat_ip_src=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_POST_NAT_SRC_HOST;
      values[primitive].handler = where[primitive].handler = count_post_nat_src_ip_handler;
      primitive++;
    }
  }

  if (what_to_count_2 & COUNT_POST_NAT_DST_HOST) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
      strncat(insert_clause, "post_nat_ip_dst", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "INET_ATON(\'%s\')", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "post_nat_ip_dst=INET_ATON(\'%s\')", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_POST_NAT_DST_HOST;
      values[primitive].handler = where[primitive].handler = count_post_nat_dst_ip_handler;
      primitive++;
    }
    else {
      strncat(insert_clause, "post_nat_ip_dst", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "post_nat_ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_POST_NAT_DST_HOST;
      values[primitive].handler = where[primitive].handler = count_post_nat_dst_ip_handler;
      primitive++;
    }
  }

  if (what_to_count_2 & COUNT_POST_NAT_SRC_PORT) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "post_nat_port_src", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "post_nat_port_src=%u", SPACELEFT(where[primitive].string));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_POST_NAT_SRC_PORT;
    values[primitive].handler = where[primitive].handler = count_post_nat_src_port_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_POST_NAT_DST_PORT) {
    if (primitive) { 
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    } 
    strncat(insert_clause, "post_nat_port_dst", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "post_nat_port_dst=%u", SPACELEFT(where[primitive].string));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_POST_NAT_DST_PORT;
    values[primitive].handler = where[primitive].handler = count_post_nat_dst_port_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_NAT_EVENT) {
    if (primitive) { 
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    } 
    strncat(insert_clause, "nat_event", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "nat_event=%u", SPACELEFT(where[primitive].string));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_NAT_EVENT;
    values[primitive].handler = where[primitive].handler = count_nat_event_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_TIMESTAMP_START) {
    int use_copy=0;

    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "timestamp_start", SPACELEFT(insert_clause));
    if (config.sql_history_since_epoch) {
      strncat(where[primitive].string, "timestamp_start=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    }
    else {
      if (!strcmp(config.type, "mysql")) {
        strncat(where[primitive].string, "timestamp_start=FROM_UNIXTIME(%u)", SPACELEFT(where[primitive].string));
        strncat(values[primitive].string, "FROM_UNIXTIME(%u)", SPACELEFT(values[primitive].string));
      }
      else if (!strcmp(config.type, "pgsql")) {
	if (config.sql_use_copy) {
          strncat(values[primitive].string, "%s", SPACELEFT(values[primitive].string));
	  use_copy = TRUE;
	}
	else {
          strncat(where[primitive].string, "timestamp_start=ABSTIME(%u)::Timestamp", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "ABSTIME(%u)::Timestamp", SPACELEFT(values[primitive].string));
	}
      }
      else if (!strcmp(config.type, "sqlite3")) {
        strncat(where[primitive].string, "timestamp_start=DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(where[primitive].string));
        strncat(values[primitive].string, "DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(values[primitive].string));
      }
    }
    if (!use_copy) values[primitive].handler = where[primitive].handler = count_timestamp_start_handler;
    else values[primitive].handler = where[primitive].handler = PG_copy_count_timestamp_start_handler;
    values[primitive].type = where[primitive].type = COUNT_TIMESTAMP_START;
    primitive++;

    if (!config.timestamps_secs) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));

      strncat(insert_clause, "timestamp_start_residual", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "timestamp_start_residual=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_TIMESTAMP_START;
      values[primitive].handler = where[primitive].handler = count_timestamp_start_residual_handler;
      primitive++;
    }
  }

  if (what_to_count_2 & COUNT_TIMESTAMP_END) {
    int use_copy=0;

    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "timestamp_end", SPACELEFT(insert_clause));
    if (config.sql_history_since_epoch) {
      strncat(where[primitive].string, "timestamp_end=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    }
    else {
      if (!strcmp(config.type, "mysql")) {
        strncat(where[primitive].string, "timestamp_end=FROM_UNIXTIME(%u)", SPACELEFT(where[primitive].string));
        strncat(values[primitive].string, "FROM_UNIXTIME(%u)", SPACELEFT(values[primitive].string));
      }
      else if (!strcmp(config.type, "pgsql")) {
        if (config.sql_use_copy) {
          strncat(values[primitive].string, "%s", SPACELEFT(values[primitive].string));
          use_copy = TRUE;
        }
        else {
          strncat(where[primitive].string, "timestamp_end=ABSTIME(%u)::Timestamp", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "ABSTIME(%u)::Timestamp", SPACELEFT(values[primitive].string));
        }
      }
      else if (!strcmp(config.type, "sqlite3")) {
        strncat(where[primitive].string, "timestamp_end=DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(where[primitive].string));
        strncat(values[primitive].string, "DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(values[primitive].string));
      }
    }
    if (!use_copy) values[primitive].handler = where[primitive].handler = count_timestamp_end_handler;
    else values[primitive].handler = where[primitive].handler = PG_copy_count_timestamp_end_handler; 
    values[primitive].type = where[primitive].type = COUNT_TIMESTAMP_END;
    primitive++;

    if (!config.timestamps_secs) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));

      strncat(insert_clause, "timestamp_end_residual", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "timestamp_end_residual=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_TIMESTAMP_END;
      values[primitive].handler = where[primitive].handler = count_timestamp_end_residual_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_ID) {
    int count_it = FALSE;

    if ((config.sql_table_version < 2) && !assume_custom_table) {
      if (config.what_to_count & COUNT_ID) {
	Log(LOG_ERR, "ERROR ( %s/%s ): Tag/ID accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_plugin(1);	
      }
      else what_to_count ^= COUNT_ID;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "agent_id", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%llu", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "agent_id=%llu", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_ID;
      values[primitive].handler = where[primitive].handler = count_id_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_ID2) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "agent_id2", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%llu", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "agent_id2=%llu", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_ID2;
    values[primitive].handler = where[primitive].handler = count_id2_handler;
    primitive++;
  }

  if (what_to_count & COUNT_CLASS) {
    int count_it = FALSE;

    if ((config.sql_table_version < 5 || config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_CLASS) {
        Log(LOG_ERR, "ERROR ( %s/%s ): L7 classification accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_plugin(1);
      }
      else what_to_count ^= COUNT_CLASS;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "class_id", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "class_id=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_CLASS;
      values[primitive].handler = where[primitive].handler = count_class_id_handler;
      primitive++;
    }
  }

#if defined (HAVE_L2)
  if (fakes & FAKE_SRC_MAC) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      fakes ^= FAKE_SRC_MAC;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "mac_src", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "mac_src=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = FAKE_SRC_MAC;
      values[primitive].handler = where[primitive].handler = fake_mac_handler;
      primitive++;
    }
  }

  if (fakes & FAKE_DST_MAC) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      fakes ^= FAKE_DST_MAC;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "mac_dst", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "mac_dst=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = FAKE_DST_MAC;
      values[primitive].handler = where[primitive].handler = fake_mac_handler;
      primitive++;
    }
  }
#endif

  if (fakes & FAKE_SRC_HOST) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      fakes ^= FAKE_SRC_HOST;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
	strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "INET_ATON(\'%s\')", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_src=INET_ATON(\'%s\')", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = FAKE_SRC_HOST;
	values[primitive].handler = where[primitive].handler = fake_host_handler;
	primitive++;
      }
      else {
	strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_src=\'%s\'", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = FAKE_SRC_HOST;
	values[primitive].handler = where[primitive].handler = fake_host_handler;
	primitive++;
      }
    }
  }

  if (fakes & FAKE_DST_HOST) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      fakes ^= FAKE_DST_HOST;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
	strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "INET_ATON(\'%s\')", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_dst=INET_ATON(\'%s\')", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = FAKE_DST_HOST;
	values[primitive].handler = where[primitive].handler = fake_host_handler;
	primitive++;
      }
      else {
	strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = FAKE_DST_HOST;
	values[primitive].handler = where[primitive].handler = fake_host_handler;
	primitive++;
      }
    }
  }

  if (fakes & FAKE_SRC_AS) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
    if (!strcmp(config.type, "mysql") || !strcmp(config.type, "sqlite3") ||
	(!strcmp(config.type, "pgsql") && !strcmp(config.sql_data, "unified"))) {
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "ip_src=\'%s\'", SPACELEFT(where[primitive].string));
    }
    else {
      strncat(values[primitive].string, "%s", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "ip_src=%s", SPACELEFT(where[primitive].string));
    }
    values[primitive].type = where[primitive].type = FAKE_SRC_AS;
    values[primitive].handler = where[primitive].handler = fake_as_handler;
    primitive++;
  }

  if (fakes & FAKE_DST_AS) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
    if (!strcmp(config.type, "mysql") || !strcmp(config.type, "sqlite3") ||
	(!strcmp(config.type, "pgsql") && !strcmp(config.sql_data, "unified"))) {
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
    }
    else {
      strncat(values[primitive].string, "%s", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "ip_dst=%s", SPACELEFT(where[primitive].string));
    }
    values[primitive].type = where[primitive].type = FAKE_DST_AS;
    values[primitive].handler = where[primitive].handler = fake_as_handler;
    primitive++;
  }

  if (fakes & FAKE_COMMS) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      fakes ^= FAKE_COMMS;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "comms", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "comms=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = FAKE_COMMS;
      values[primitive].handler = where[primitive].handler = fake_comms_handler;
      primitive++;
    }
  }

  if (fakes & FAKE_AS_PATH) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      fakes ^= FAKE_AS_PATH;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "as_path", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "as_path=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = FAKE_AS_PATH;
      values[primitive].handler = where[primitive].handler = fake_as_path_handler;
      primitive++;
    }
  }

  if (fakes & FAKE_PEER_SRC_AS) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      fakes ^= FAKE_PEER_SRC_AS;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "peer_as_src", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "peer_as_src=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = FAKE_PEER_SRC_AS;
      values[primitive].handler = where[primitive].handler = fake_as_handler;
      primitive++;
    }
  }

  if (fakes & FAKE_PEER_DST_AS) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      fakes ^= FAKE_PEER_DST_AS;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      strncat(insert_clause, "peer_as_dst", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "peer_as_dst=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = FAKE_PEER_DST_AS;
      values[primitive].handler = where[primitive].handler = fake_as_handler;
      primitive++;
    }
  }

  if (fakes & FAKE_PEER_SRC_IP) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      fakes ^= FAKE_PEER_SRC_IP;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
	strncat(insert_clause, "peer_ip_src", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "INET_ATON(\'%s\')", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "peer_ip_src=INET_ATON(\'%s\')", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = FAKE_PEER_SRC_IP;
	values[primitive].handler = where[primitive].handler = fake_host_handler;
	primitive++;
      }
      else {
	strncat(insert_clause, "peer_ip_src", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "peer_ip_src=\'%s\'", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = FAKE_PEER_SRC_IP;
	values[primitive].handler = where[primitive].handler = fake_host_handler;
	primitive++;
      }
    }
  }

  if (fakes & FAKE_PEER_DST_IP) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      fakes ^= FAKE_PEER_DST_IP;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
	strncat(insert_clause, "peer_ip_dst", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "INET_ATON(\'%s\')", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "peer_ip_dst=INET_ATON(\'%s\')", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = FAKE_PEER_DST_IP;
	values[primitive].handler = where[primitive].handler = fake_host_handler;
	primitive++;
      }
      else {
	strncat(insert_clause, "peer_ip_dst", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "peer_ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = FAKE_PEER_DST_IP;
	values[primitive].handler = where[primitive].handler = fake_host_handler;
	primitive++;
      }
    }
  }

  strncat(copy_clause, insert_clause_start_ptr, SPACELEFT(copy_clause));

  return primitive;
}

int sql_query(struct BE_descs *bed, struct db_cache *elem, struct insert_data *idata)
{
  if (!bed->p->fail && elem->valid == SQL_CACHE_COMMITTED) {
    if ((*sqlfunc_cbr.op)(bed->p, elem, idata)); /* failed */
    else {
      idata->qn++;
      return FALSE;
    }
  }

  if ( elem->valid == SQL_CACHE_ERROR || (bed->p->fail && !(elem->valid == SQL_CACHE_INUSE)) ) {

  if (config.sql_backup_host) {
    if (!bed->b->fail) {
      if (!bed->b->connected) {
        (*sqlfunc_cbr.connect)(bed->b, config.sql_backup_host);
        if (config.sql_table_schema) {
	  time_t stamp = idata->new_basetime ? idata->new_basetime : idata->basetime;

	  sql_create_table(bed->b, &stamp);
	}
        (*sqlfunc_cbr.lock)(bed->b);
      }
      if (!bed->b->fail) {
        if ((*sqlfunc_cbr.op)(bed->b, elem, idata)) sql_db_fail(bed->b);
      }
    }
  }
  if (config.sql_recovery_logfile) {
    int sz;

    if (idata->mv.last_queue_elem) goto quit; 

    if (!bed->lf->fail) {
      if (!bed->lf->open) {
	bed->lf->file = sql_file_open(config.sql_recovery_logfile, "a", idata);
	if (bed->lf->file) bed->lf->open = TRUE;
	else {
	  bed->lf->open = FALSE;
	  bed->lf->fail = TRUE;
	}
      }
      if (!bed->lf->fail) {
	sz = TPL_push(logbuf.ptr, elem);
	logbuf.ptr += sz;
	if ((logbuf.ptr+sz) > logbuf.end) { /* we test whether the next element will fit into the buffer */
	  fwrite(logbuf.base, (logbuf.ptr-logbuf.base), 1, bed->lf->file);
	  logbuf.ptr = logbuf.base;
	}
      }
    }
  }

  }

  quit:
  return TRUE;
}

FILE *sql_file_open(const char *path, const char *mode, const struct insert_data *idata)
{
  struct stat st, st2;
  struct logfile_header lh;
  struct template_header tth;
  FILE *f;
  int ret;
  uid_t owner = -1;
  gid_t group = -1;

  if (config.files_uid) owner = config.files_uid;
  if (config.files_gid) group = config.files_gid;

  file_open:
  f = fopen(path, "a+");
  if (f) {
    ret = chown(path, owner, group);
    if (file_lock(fileno(f))) {
      Log(LOG_ALERT, "ALERT ( %s/%s ): Unable to obtain lock of '%s'.\n", config.name, config.type, path);
      goto close;
    }

    fstat(fileno(f), &st);
    if (!st.st_size) {
      memset(&lh, 0, sizeof(struct logfile_header));
      strlcpy(lh.sql_db, config.sql_db, DEF_HDR_FIELD_LEN);
      if (!idata->dyn_table) strlcpy(lh.sql_table, config.sql_table, DEF_HDR_FIELD_LEN);
      else {
        struct tm *nowtm;

        nowtm = localtime(&idata->new_basetime);
        strftime(lh.sql_table, DEF_HDR_FIELD_LEN, config.sql_table, nowtm);
      }
      strlcpy(lh.sql_user, config.sql_user, DEF_HDR_FIELD_LEN);
      if (config.sql_host) strlcpy(lh.sql_host, config.sql_host, DEF_HDR_FIELD_LEN);
      else lh.sql_host[0] = '\0';
      lh.sql_table_version = config.sql_table_version;
      lh.sql_table_version = htons(lh.sql_table_version);
      lh.sql_optimize_clauses = config.sql_optimize_clauses;
      lh.sql_optimize_clauses = htons(lh.sql_optimize_clauses);
      lh.sql_history = config.sql_history;
      lh.sql_history = htons(lh.sql_history);
      lh.what_to_count = htonl(config.what_to_count);
      lh.magic = htonl(MAGIC);

      fwrite(&lh, sizeof(lh), 1, f);
      fwrite(&th, sizeof(th), 1, f);
      fwrite(te, ntohs(th.num)*sizeof(struct template_entry), 1, f);
    }
    else {
      rewind(f);
      if ((ret = fread(&lh, sizeof(lh), 1, f)) != 1) {
        Log(LOG_ALERT, "ALERT ( %s/%s ): Unable to read header: '%s'.\n", config.name, config.type, path);
        goto close;
      }
      if (ntohl(lh.magic) != MAGIC) {
        Log(LOG_ALERT, "ALERT ( %s/%s ): Invalid magic number: '%s'.\n", config.name, config.type, path);
        goto close;
      }
      if ((ret = fread(&tth, sizeof(tth), 1, f)) != 1) {
        Log(LOG_ALERT, "ALERT ( %s/%s ): Unable to read template: '%s'.\n", config.name, config.type, path);
        goto close;
      }
      if ((tth.num != th.num) || (tth.sz != th.sz)) {
        Log(LOG_ALERT, "ALERT ( %s/%s ): Invalid template in: '%s'.\n", config.name, config.type, path);
        goto close;
      }
      if ((st.st_size+(idata->ten*sizeof(struct pkt_data))) >= MAX_LOGFILE_SIZE) {
        Log(LOG_INFO, "INFO ( %s/%s ): No more space in '%s'.\n", config.name, config.type, path);

        /* We reached the maximum logfile length; we test if any previous process
           has already rotated the logfile. If not, we will rotate it. */
        stat(path, &st2);
        if (st2.st_size >= st.st_size) {
          ret = file_archive(path, MAX_LOGFILE_ROTATIONS);
          if (ret < 0) goto close;
        }
        file_unlock(fileno(f));
        fclose(f);
        goto file_open;
      }
      fseek(f, 0, SEEK_END);
    }
  }

  return f;

  close:
  file_unlock(fileno(f));
  fclose(f);
  return NULL;
}

void sql_create_table(struct DBdesc *db, time_t *basetime)
{
  struct tm *nowtm;
  char buf[LARGEBUFLEN], tmpbuf[LARGEBUFLEN], tmpbuf2[LARGEBUFLEN];
  int ret;

  ret = read_SQLquery_from_file(config.sql_table_schema, tmpbuf, LARGEBUFLEN);
  if (ret) {
    handle_dynname_internal_strings(tmpbuf2, LARGEBUFLEN-10, tmpbuf);
    nowtm = localtime(basetime);
    strftime(buf, LARGEBUFLEN, tmpbuf2, nowtm);
    (*sqlfunc_cbr.create_table)(db, buf);
  }
}

void sql_invalidate_shadow_entries(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (!queue[x]->bytes_counter && !queue[x]->packet_counter && !queue[x]->flows_counter)
      queue[x]->valid = SQL_CACHE_FREE;
  }
}

int sql_select_locking_style(char *lock)
{
  int i = 0, len = strlen(lock);

  while (i < len) {
    lock[i] = tolower(lock[i]);
    i++;
  }

  if (!strcmp(lock, "table")) return PM_LOCK_EXCLUSIVE;
  else if (!strcmp(lock, "row")) return PM_LOCK_ROW_EXCLUSIVE;

  Log(LOG_WARNING, "WARN ( %s/%s ): sql_locking_style value '%s' is unknown. Ignored.\n", config.name, config.type, lock);

  return PM_LOCK_EXCLUSIVE;
}

int sql_compose_static_set_event()
{
  int set_primitives=0;

  if (config.what_to_count & COUNT_TCPFLAGS) {
    strncat(set_event[set_primitives].string, "SET tcp_flags=tcp_flags|%u", SPACELEFT(set_event[set_primitives].string));
    set_event[set_primitives].type = COUNT_TCPFLAGS;
    set_event[set_primitives].handler = count_tcpflags_setclause_handler;
    set_primitives++;
  }

  return set_primitives;
}

int sql_compose_static_set(int have_flows)
{
  int set_primitives=0;

#if defined HAVE_64BIT_COUNTERS
  strncpy(set[set_primitives].string, "SET packets=packets+%llu, bytes=bytes+%llu", SPACELEFT(set[set_primitives].string));
  set[set_primitives].type = COUNT_COUNTERS;
  set[set_primitives].handler = count_counters_setclause_handler;
  set_primitives++;

  if (have_flows) {
    strncpy(set[set_primitives].string, ", ", SPACELEFT(set[set_primitives].string));
    strncat(set[set_primitives].string, "flows=flows+%llu", SPACELEFT(set[set_primitives].string));
    set[set_primitives].type = COUNT_FLOWS;
    set[set_primitives].handler = count_flows_setclause_handler;
    set_primitives++;
  }
#else
  strncpy(set[set_primitives].string, "SET packets=packets+%u, bytes=bytes+%u", SPACELEFT(set[set_primitives].string));
  set[set_primitives].type = COUNT_COUNTERS;
  set[set_primitives].handler = count_counters_setclause_handler;
  set_primitives++;

  if (have_flows) {
    strncpy(set[set_primitives].string, ", ", SPACELEFT(set[set_primitives].string));
    strncat(set[set_primitives].string, "flows=flows+%u", SPACELEFT(set[set_primitives].string));
    set[set_primitives].type = COUNT_FLOWS;
    set[set_primitives].handler = count_flows_setclause_handler;
    set_primitives++;
  }
#endif

  if (config.what_to_count & COUNT_TCPFLAGS) {
    strncpy(set[set_primitives].string, ", ", SPACELEFT(set[set_primitives].string));
    strncat(set[set_primitives].string, "tcp_flags=tcp_flags|%u", SPACELEFT(set[set_primitives].string));
    set[set_primitives].type = COUNT_TCPFLAGS;
    set[set_primitives].handler = count_tcpflags_setclause_handler;
    set_primitives++;
  }

  return set_primitives;
}
