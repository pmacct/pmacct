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
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "sql_common.h"
#include "sql_common_m.h"
#include "crc32.h"

/* Global variables */
char sql_data[LARGEBUFLEN];
char lock_clause[LONGSRVBUFLEN];
char unlock_clause[LONGSRVBUFLEN];
char update_clause[LONGSRVBUFLEN];
char set_clause[LONGSRVBUFLEN];
char copy_clause[LONGSRVBUFLEN];
char insert_clause[LONGSRVBUFLEN];
char insert_counters_clause[LONGSRVBUFLEN];
char insert_nocounters_clause[LONGSRVBUFLEN];
char insert_full_clause[LONGSRVBUFLEN];
char values_clause[LONGLONGSRVBUFLEN];
char *multi_values_buffer;
char where_clause[LONGLONGSRVBUFLEN];
unsigned char *pipebuf;
struct db_cache *sql_cache;
struct db_cache **sql_queries_queue, **sql_pending_queries_queue;
struct db_cache *collision_queue;
int cq_ptr, sql_qq_ptr, qq_size, sql_pp_size, sql_pb_size, sql_pn_size, sql_pm_size, sql_pt_size;
int sql_pc_size, sql_dbc_size, cq_size, sql_pqq_ptr;
struct db_cache lru_head, *lru_tail;
struct frags where[N_PRIMITIVES+2];
struct frags values[N_PRIMITIVES+2];
struct frags copy_values[N_PRIMITIVES+2];
struct frags set[N_PRIMITIVES+2];
struct frags set_event[N_PRIMITIVES+2];
int glob_num_primitives; /* last resort for signal handling */
int glob_basetime; /* last resort for signal handling */
time_t glob_new_basetime; /* last resort for signal handling */
time_t glob_committed_basetime; /* last resort for signal handling */
int glob_dyn_table, glob_dyn_table_time_only; /* last resort for signal handling */
int glob_timeslot; /* last resort for sql handlers */

struct sqlfunc_cb_registry sqlfunc_cbr; 
void (*sql_insert_func)(struct primitives_ptrs *, struct insert_data *);
struct DBdesc p;
struct DBdesc b;
struct BE_descs bed;
struct largebuf_s envbuf;
time_t now; /* PostgreSQL */

/* Functions */
void sql_set_signals()
{
  signal(SIGINT, sql_exit_gracefully);
  signal(SIGHUP, reload); /* handles reopening of syslog channel */
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, reload_maps);
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, ignore_falling_child);
}

void sql_set_insert_func()
{
  if (config.what_to_count & (COUNT_SUM_HOST|COUNT_SUM_NET))
    sql_insert_func = sql_sum_host_insert;
  else if (config.what_to_count & COUNT_SUM_PORT) sql_insert_func = sql_sum_port_insert;
  else if (config.what_to_count & COUNT_SUM_AS) sql_insert_func = sql_sum_as_insert;
#if defined (HAVE_L2)
  else if (config.what_to_count & COUNT_SUM_MAC) sql_insert_func = sql_sum_mac_insert;
#endif
  else sql_insert_func = sql_cache_insert;
}

void sql_init_maps(struct extra_primitives *extras, struct primitives_ptrs *prim_ptrs,
		   struct networks_table *nt, struct networks_cache *nc, struct ports_table *pt)
{
  memset(prim_ptrs, 0, sizeof(struct primitives_ptrs));
  set_primptrs_funcs(extras);

  memset(nt, 0, sizeof(struct networks_table));
  memset(nc, 0, sizeof(struct networks_cache));
  memset(pt, 0, sizeof(struct ports_table));

  load_networks(config.networks_file, nt, nc);
  set_net_funcs(nt);

  if (config.ports_file) load_ports(config.ports_file, pt);
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

  Log(LOG_INFO, "INFO ( %s/%s ): cache entries=%d base cache memory=%lu bytes\n", config.name, config.type,
        config.sql_cache_entries, (unsigned long)(((config.sql_cache_entries * sizeof(struct db_cache)) +
	(2 * (qq_size * sizeof(struct db_cache *))))));

  pipebuf = (unsigned char *) malloc(config.buffer_size);
  sql_cache = (struct db_cache *) malloc(config.sql_cache_entries*sizeof(struct db_cache));
  sql_queries_queue = (struct db_cache **) malloc(qq_size*sizeof(struct db_cache *));
  sql_pending_queries_queue = (struct db_cache **) malloc(qq_size*sizeof(struct db_cache *));

  if (!pipebuf || !sql_cache || !sql_queries_queue || !sql_pending_queries_queue) {
    Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (sql_init_global_buffers). Exiting ..\n", config.name, config.type);
    exit_gracefully(1);
  }

  memset(pipebuf, 0, config.buffer_size);
  memset(sql_cache, 0, config.sql_cache_entries*sizeof(struct db_cache));
  memset(sql_queries_queue, 0, qq_size*sizeof(struct db_cache *));
  memset(sql_pending_queries_queue, 0, qq_size*sizeof(struct db_cache *));
}

/* being the first routine to be called by each SQL plugin, this is
   also the place for some initial common configuration consistency
   check */ 
void sql_init_default_values(struct extra_primitives *extras)
{
  memset(empty_mem_area_256b, 0, sizeof(empty_mem_area_256b));

  if (config.proc_priority) {
    int ret;

    ret = setpriority(PRIO_PROCESS, 0, config.proc_priority);
    if (ret) Log(LOG_WARNING, "WARN ( %s/%s ): proc_priority failed (errno: %d)\n", config.name, config.type, errno);
    else Log(LOG_INFO, "INFO ( %s/%s ): proc_priority set to %d\n", config.name, config.type, getpriority(PRIO_PROCESS, 0));
  }

  if (!config.sql_refresh_time) config.sql_refresh_time = DEFAULT_DB_REFRESH_TIME;
  if (!config.sql_table_version) config.sql_table_version = DEFAULT_SQL_TABLE_VERSION;
  if (!config.sql_cache_entries) config.sql_cache_entries = CACHE_ENTRIES;
  if (!config.dump_max_writers) config.dump_max_writers = DEFAULT_SQL_WRITERS_NO;

  dump_writers.list = malloc(config.dump_max_writers * sizeof(pid_t));
  dump_writers_init();

  /* SQL table type parsing; basically mapping everything down to a SQL table version */
  /* ie. BGP == 1000 */
  if (config.sql_table_type) {
    if (!strcmp(config.sql_table_type, "bgp")) config.sql_table_version += SQL_TABLE_VERSION_BGP;  
    else {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unknown sql_table_type value: '%s'.\n", config.name, config.type, config.sql_table_type);
      exit_gracefully(1);
    }
  }
  else {
    if (extras->off_pkt_bgp_primitives) {
      config.sql_table_version += SQL_TABLE_VERSION_BGP;
      Log(LOG_INFO, "INFO ( %s/%s ): sql_table_type set to 'bgp' (aggregate includes one or more BGP primitives).\n", config.name, config.type);
    }
  }

  if (config.nfacctd_stitching) {
    if (config.nfacctd_pro_rating) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Pro-rating (ie. nfacctd_pro_rating) and stitching (ie. nfacctd_stitching) are mutual exclusive. Exiting.\n", config.name, config.type);
      exit_gracefully(1);
    }

    if (!config.sql_dont_try_update) {
      Log(LOG_WARNING, "WARN ( %s/%s ): stitching (ie. nfacctd_stitching) behaviour is undefined when sql_dont_try_update is set to false.\n", config.name, config.type);
    }
  }

  sql_qq_ptr = 0; 
  sql_pqq_ptr = 0;
  qq_size = config.sql_cache_entries+(config.sql_refresh_time*REASONABLE_NUMBER);
  sql_pp_size = sizeof(struct pkt_primitives);
  sql_pb_size = sizeof(struct pkt_bgp_primitives);
  sql_pn_size = sizeof(struct pkt_nat_primitives);
  sql_pm_size = sizeof(struct pkt_mpls_primitives);
  sql_pt_size = sizeof(struct pkt_tunnel_primitives);
  sql_pc_size = config.cpptrs.len;
  sql_dbc_size = sizeof(struct db_cache);

  /* handling purge preprocessor */
  set_preprocess_funcs(config.sql_preprocess, &prep, PREP_DICT_SQL);
}

void sql_init_historical_acct(time_t now, struct insert_data *idata)
{
  time_t t;

  if (config.sql_history) {
    idata->basetime = now;
    if (config.sql_history == COUNT_SECONDLY) idata->timeslot = config.sql_history_howmany;
    else if (config.sql_history == COUNT_MINUTELY) idata->timeslot = config.sql_history_howmany*60;
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

    if (config.sql_history_offset) {
      if (config.sql_history_offset >= idata->timeslot) {
	Log(LOG_ERR, "ERROR ( %s/%s ): History offset (ie. sql_history_offset) must be < history (ie. sql_history).\n", config.name, config.type);
	exit_gracefully(1);
      }

      t = t - (idata->timeslot + config.sql_history_offset);
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
    idata->triggertime = (t + config.sql_startup_delay);

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
  struct pkt_mpls_primitives *pmpls = prim_ptrs->pmpls;
  struct pkt_tunnel_primitives *ptun = prim_ptrs->ptun;
  u_char *pcust = prim_ptrs->pcust;
  struct pkt_vlen_hdr_primitives *pvlen = prim_ptrs->pvlen;

  idata->hash = cache_crc32((unsigned char *)srcdst, sql_pp_size);
  if (pbgp) idata->hash ^= cache_crc32((unsigned char *)pbgp, sql_pb_size);
  if (pnat) idata->hash ^= cache_crc32((unsigned char *)pnat, sql_pn_size);
  if (pmpls) idata->hash ^= cache_crc32((unsigned char *)pmpls, sql_pm_size);
  if (ptun) idata->hash ^= cache_crc32((unsigned char *)ptun, sql_pt_size);
  if (pcust) idata->hash ^= cache_crc32((unsigned char *)pcust, sql_pc_size);
  if (pvlen) idata->hash ^= cache_crc32((unsigned char *)pvlen, (PvhdrSz + pvlen->tot_len));

  idata->modulo = idata->hash % config.sql_cache_entries;
}

int sql_cache_flush(struct db_cache *queue[], int index, struct insert_data *idata, int exiting)
{
  int j, delay = 0, new_basetime = FALSE;

  /* We are seeking how many time-bins data has to be delayed by; residual
     time is taken into account by scanner deadlines (sql_refresh_time) */
  if (config.sql_startup_delay) {
    if (idata->timeslot) delay = config.sql_startup_delay/idata->timeslot; 
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

  if (!exiting) {
    for (j = 0, sql_pqq_ptr = 0; j < index; j++) {
      if (new_basetime && queue[j]->basetime+delay >= idata->basetime) {
        sql_pending_queries_queue[sql_pqq_ptr] = queue[j];
        sql_pqq_ptr++;
      }
      else if (!new_basetime && queue[j]->basetime+delay > idata->basetime) {
        sql_pending_queries_queue[sql_pqq_ptr] = queue[j];
        sql_pqq_ptr++;
      }
      else queue[j]->valid = SQL_CACHE_COMMITTED;
    }
  }
  /* If exiting instead .. */
  else {
    for (j = 0; j < index; j++) queue[j]->valid = SQL_CACHE_COMMITTED; 
  } 

  return index;
}

void sql_cache_flush_pending(struct db_cache *queue[], int index, struct insert_data *idata)
{
  struct db_cache *Cursor, *auxCursor, *PendingElem, SavedCursor;
  int j;

  /* Not everything was purged, let's sort out the SQL cache buckets involved into that */
  if (index) {
    for (j = 0; j < index; j++) {
      /* Select next element on the pending queue */
      PendingElem = queue[j];

      /* Go to the first element in the bucket */
      for (Cursor = PendingElem, auxCursor = NULL; Cursor; auxCursor = Cursor, Cursor = Cursor->prev);

      /* Check whether we are already first in the bucket */
      if (auxCursor != PendingElem) {
	Cursor = auxCursor;

        for (; Cursor && Cursor != PendingElem && Cursor->valid == SQL_CACHE_INUSE; Cursor = Cursor->next);
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
            Cursor->chained = FALSE;
            Cursor->lru_prev = NULL;
            Cursor->lru_next = NULL;

	    /* unlinking pointers from PendingElem to prevent free-up (linked by Cursor) */
	    PendingElem->pbgp = NULL;
	    PendingElem->pnat = NULL;
	    PendingElem->pmpls = NULL;
	    PendingElem->ptun = NULL;
	    PendingElem->pcust = NULL;
	    PendingElem->pvlen = NULL;
	    PendingElem->stitch = NULL;
            RetireElem(PendingElem);

            queue[j] = Cursor;

	    /* freeing stale allocations */
	    if (SavedCursor.pbgp) free(SavedCursor.pbgp);
	    if (SavedCursor.pnat) free(SavedCursor.pnat);
	    if (SavedCursor.pmpls) free(SavedCursor.pmpls);
	    if (SavedCursor.ptun) free(SavedCursor.ptun);
	    if (SavedCursor.pcust) free(SavedCursor.pcust);
	    if (SavedCursor.pvlen) free(SavedCursor.pvlen);
	    if (SavedCursor.stitch) free(SavedCursor.stitch);
          }
          /* We found at least one Cursor->valid == SQL_CACHE_INUSE */
          else SwapChainedElems(PendingElem, Cursor);
        }
      }
    }
  }
}

void sql_cache_handle_flush_event(struct insert_data *idata, time_t *refresh_deadline, struct ports_table *pt)
{
  int ret;

  dump_writers_count();
  if (dump_writers_get_flags() != CHLD_ALERT) { 
    switch (ret = fork()) {
    case 0: /* Child */
      /* we have to ignore signals to avoid loops: because we are already forked */
      signal(SIGINT, SIG_IGN);
      signal(SIGHUP, SIG_IGN);
      pm_setproctitle("%s %s [%s]", config.type, "Plugin -- DB Writer", config.name);
      config.is_forked = TRUE;

      if (sql_qq_ptr) {
        if (dump_writers_get_flags() == CHLD_WARNING) sql_db_fail(&p);
        if (!strcmp(config.type, "mysql"))
          (*sqlfunc_cbr.connect)(&p, config.sql_host);
        else
          (*sqlfunc_cbr.connect)(&p, NULL);
      }

      /* sql_qq_ptr check inside purge function along with a Log() call */
      (*sqlfunc_cbr.purge)(sql_queries_queue, sql_qq_ptr, idata);

      if (sql_qq_ptr) (*sqlfunc_cbr.close)(&bed);

      if (config.sql_trigger_exec) {
        if (idata->now > idata->triggertime) sql_trigger_exec(config.sql_trigger_exec);
      }

      exit_gracefully(0);
    default: /* Parent */
      if (ret == -1) Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork DB writer: %s\n", config.name, config.type, strerror(errno));
      else dump_writers_add(ret);

      break;
    }
  }
  else Log(LOG_WARNING, "WARN ( %s/%s ): Maximum number of writer processes reached (%d).\n", config.name, config.type, dump_writers_get_active());

  if (sql_pqq_ptr) sql_cache_flush_pending(sql_pending_queries_queue, sql_pqq_ptr, idata);
  gettimeofday(&idata->flushtime, NULL);
  while (idata->now > *refresh_deadline)
    *refresh_deadline += config.sql_refresh_time;
  while (idata->now > idata->triggertime && idata->t_timeslot > 0) {
    idata->triggertime  += idata->t_timeslot;
    if (config.sql_trigger_time == COUNT_MONTHLY)
      idata->t_timeslot = calc_monthly_timeslot(idata->triggertime, config.sql_trigger_time_howmany, ADD);
  }

  idata->new_basetime = FALSE;
  glob_new_basetime = FALSE;
  sql_qq_ptr = sql_pqq_ptr;
  memcpy(sql_queries_queue, sql_pending_queries_queue, sql_qq_ptr*sizeof(struct db_cache *));

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

struct db_cache *sql_cache_search(struct primitives_ptrs *prim_ptrs, time_t basetime)
{
  struct pkt_data *pdata = prim_ptrs->data;
  struct pkt_primitives *data = &pdata->primitives;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  struct pkt_mpls_primitives *pmpls = prim_ptrs->pmpls;
  struct pkt_tunnel_primitives *ptun = prim_ptrs->ptun;
  u_char *pcust = prim_ptrs->pcust;
  struct pkt_vlen_hdr_primitives *pvlen = prim_ptrs->pvlen;
  struct db_cache *Cursor;
  struct insert_data idata;
  int res_data = TRUE, res_bgp = TRUE, res_nat = TRUE, res_mpls = TRUE, res_tun = TRUE;
  int res_cust = TRUE, res_vlen = TRUE;

  sql_cache_modulo(prim_ptrs, &idata);

  Cursor = &sql_cache[idata.modulo];

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

      if (pbgp && Cursor->pbgp) {
        res_bgp = memcmp(Cursor->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
      }
      else res_bgp = FALSE;

      if (pnat && Cursor->pnat) {
        res_nat = memcmp(Cursor->pnat, pnat, sizeof(struct pkt_nat_primitives));
      }
      else res_nat = FALSE;

      if (pmpls && Cursor->pmpls) {
        res_mpls = memcmp(Cursor->pmpls, pmpls, sizeof(struct pkt_mpls_primitives));
      }
      else res_mpls = FALSE;

      if (ptun && Cursor->ptun) {
        res_tun = memcmp(Cursor->ptun, ptun, sizeof(struct pkt_tunnel_primitives));
      }
      else res_tun = FALSE;

      if (pcust && Cursor->pcust) {
        res_cust = memcmp(Cursor->pcust, pcust, config.cpptrs.len);
      }
      else res_cust = FALSE;

      if (pvlen && Cursor->pvlen) {
        res_vlen = vlen_prims_cmp(Cursor->pvlen, pvlen);
      }
      else res_vlen = FALSE;

      if (!res_data && !res_bgp && !res_nat && !res_mpls && !res_tun && !res_cust && !res_vlen) {
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
  struct pkt_mpls_primitives *pmpls = prim_ptrs->pmpls;
  struct pkt_tunnel_primitives *ptun = prim_ptrs->ptun;
  u_char *pcust = prim_ptrs->pcust;
  struct pkt_vlen_hdr_primitives *pvlen = prim_ptrs->pvlen;
  time_t basetime = idata->basetime, timeslot = idata->timeslot;
  struct pkt_primitives *srcdst = &data->primitives;
  struct db_cache *Cursor, *newElem, *SafePtr = NULL, *staleElem = NULL;
  int ret, insert_status;

  /* pro_rating vars */
  int time_delta = 0, time_total = 0;
  pm_counter_t tot_bytes = 0, tot_packets = 0, tot_flows = 0;

  /* housekeeping to start */
  if (lru_head.lru_next && ((idata->now-lru_head.lru_next->lru_tag) > RETIRE_M*config.sql_refresh_time)) {
    /* if element status is SQL_CACHE_INUSE it can't be retired because sits on the queue */
    if (lru_head.lru_next->valid != SQL_CACHE_INUSE) RetireElem(lru_head.lru_next);
  }

  tot_bytes = data->pkt_len;
  tot_packets = data->pkt_num;
  tot_flows = data->flo_num;

  if (data->time_start.tv_sec && config.sql_history) {
    if (config.sql_history != COUNT_MONTHLY) {
      int residual;

      if (basetime > data->time_start.tv_sec) {
	residual = timeslot - ((basetime - data->time_start.tv_sec) % timeslot);
      }
      else {
	residual = ((data->time_start.tv_sec - basetime) % timeslot);
      }

      basetime = data->time_start.tv_sec - residual;
    }
    else {
      while (basetime > data->time_start.tv_sec) {
        timeslot = calc_monthly_timeslot(basetime, config.sql_history_howmany, SUB);
        basetime -= timeslot;
      }
      while ((basetime + timeslot) < data->time_start.tv_sec) {
        basetime += timeslot;
        timeslot = calc_monthly_timeslot(basetime, config.sql_history_howmany, ADD);
      }
    }
  }

  new_timeslot:
  /* pro_rating, if needed */
  if (config.acct_type == ACCT_NF && config.nfacctd_pro_rating && config.sql_history) {
    if (data->time_end.tv_sec > data->time_start.tv_sec) {
      time_total = data->time_end.tv_sec - data->time_start.tv_sec;
      time_delta = MIN(data->time_end.tv_sec, basetime + timeslot) - MAX(data->time_start.tv_sec, basetime);

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
  Cursor = &sql_cache[idata->modulo];

  start:
  insert_status = SQL_INSERT_INSERT;

  if (idata->hash != Cursor->signature) {
    if (Cursor->valid == SQL_CACHE_INUSE) {
      follow_chain:
      if (Cursor->next) {
        Cursor = Cursor->next;
        goto start;
      }
      else {
        if (lru_head.lru_next && lru_head.lru_next->valid != SQL_CACHE_INUSE &&
	    ((idata->now-lru_head.lru_next->lru_tag) > STALE_M*config.sql_refresh_time)) {
          newElem = lru_head.lru_next;
	  /* if (newElem != Cursor) */
	  /* check removed: Cursor must be SQL_CACHE_INUSE; newElem must be not SQL_CACHE_INUSE */
          ReBuildChain(Cursor, newElem);
          Cursor = newElem;
          /* we have successfully reused a stale element */
        }
        else {
          newElem = (struct db_cache *) malloc(sizeof(struct db_cache));
          if (newElem) {
            memset(newElem, 0, sizeof(struct db_cache));
            BuildChain(Cursor, newElem);
            Cursor = newElem;
            /* creating a new element */
          }
          else insert_status = SQL_INSERT_SAFE_ACTION; /* we should have finished memory */
        }
      }
    }
    /* we found a no more valid entry; let's insert here our data */
  }
  else {
    if (Cursor->valid == SQL_CACHE_INUSE) {
      int res_data = TRUE, res_bgp = TRUE, res_nat = TRUE, res_mpls = TRUE, res_tun = TRUE;
      int res_cust = TRUE, res_vlen = TRUE;

      /* checks: pkt_primitives and pkt_bgp_primitives */
      res_data = memcmp(&Cursor->primitives, srcdst, sizeof(struct pkt_primitives));

      if (pbgp && Cursor->pbgp) {
        res_bgp = memcmp(Cursor->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
      }
      else res_bgp = FALSE;

      if (pnat && Cursor->pnat) {
        res_nat = memcmp(Cursor->pnat, pnat, sizeof(struct pkt_nat_primitives));
      }
      else res_nat = FALSE;

      if (pmpls && Cursor->pmpls) {
        res_mpls = memcmp(Cursor->pmpls, pmpls, sizeof(struct pkt_mpls_primitives));
      }
      else res_mpls = FALSE;

      if (ptun && Cursor->ptun) {
        res_tun = memcmp(Cursor->ptun, ptun, sizeof(struct pkt_tunnel_primitives));
      }
      else res_tun = FALSE;

      if (pcust && Cursor->pcust) {
        res_cust = memcmp(Cursor->pcust, pcust, config.cpptrs.len);
      }
      else res_cust = FALSE;

      if (pvlen && Cursor->pvlen) {
        res_vlen = vlen_prims_cmp(Cursor->pvlen, pvlen);
      }
      else res_vlen = FALSE;

      if (!res_data && !res_bgp && !res_nat && !res_mpls && !res_tun && !res_cust && !res_vlen) {
        /* additional check: time */
        if ((Cursor->basetime != basetime) && config.sql_history) goto follow_chain;

        /* additional check: bytes counter overflow */
        if (Cursor->bytes_counter > CACHE_THRESHOLD) goto follow_chain;

	/* All is good: let's update the matching entry */
        insert_status = SQL_INSERT_UPDATE;
      }
      else goto follow_chain;
    }
  }

  if (insert_status == SQL_INSERT_INSERT) {
    if (sql_qq_ptr < qq_size) {
      sql_queries_queue[sql_qq_ptr] = Cursor;
      sql_qq_ptr++;
    }
    else SafePtr = Cursor;
  
    /* we add the new entry in the cache */
    memcpy(&Cursor->primitives, srcdst, sizeof(struct pkt_primitives));
  
    if (pbgp) {
      if (!Cursor->pbgp) {
        Cursor->pbgp = (struct pkt_bgp_primitives *) malloc(sql_pb_size);
        if (!Cursor->pbgp) goto safe_action;
      }
      memcpy(Cursor->pbgp, pbgp, sql_pb_size);
    }
    else {
      if (Cursor->pbgp) free(Cursor->pbgp);
      Cursor->pbgp = NULL;
    }

    if (pnat) {
      if (!Cursor->pnat) {
        Cursor->pnat = (struct pkt_nat_primitives *) malloc(sql_pn_size);
        if (!Cursor->pnat) goto safe_action;
      }
      memcpy(Cursor->pnat, pnat, sql_pn_size);
    }
    else {
      if (Cursor->pnat) free(Cursor->pnat);
      Cursor->pnat = NULL;
    }
  
    if (pmpls) {
      if (!Cursor->pmpls) {
        Cursor->pmpls = (struct pkt_mpls_primitives *) malloc(sql_pm_size);
        if (!Cursor->pmpls) goto safe_action;
      }
      memcpy(Cursor->pmpls, pmpls, sql_pm_size);
    }
    else {
      if (Cursor->pmpls) free(Cursor->pmpls);
      Cursor->pmpls = NULL;
    }

    if (ptun) {
      if (!Cursor->ptun) {
        Cursor->ptun = (struct pkt_tunnel_primitives *) malloc(sql_pt_size);
        if (!Cursor->ptun) goto safe_action;
      }
      memcpy(Cursor->ptun, ptun, sql_pt_size);
    }
    else {
      if (Cursor->ptun) free(Cursor->ptun);
      Cursor->ptun = NULL;
    }
  
    if (pcust) {
      if (!Cursor->pcust) {
        Cursor->pcust = malloc(sql_pc_size);
        if (!Cursor->pcust) goto safe_action;
      }
      memcpy(Cursor->pcust, pcust, sql_pc_size);
    }
    else {
      if (Cursor->pcust) free(Cursor->pcust);
      Cursor->pcust = NULL;
    }

    /* if we have a pvlen from before let's free it
       up due to the vlen nature of the memory area */
    if (Cursor->pvlen) {
      vlen_prims_free(Cursor->pvlen);
      Cursor->pvlen = NULL;
    }

    if (pvlen) {
      Cursor->pvlen = (struct pkt_vlen_hdr_primitives *) vlen_prims_copy(pvlen);
      if (!Cursor->pvlen) goto safe_action;
    }
  
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

    if (config.nfacctd_stitching) {
      if (!Cursor->stitch) Cursor->stitch = (struct pkt_stitching *) malloc(sizeof(struct pkt_stitching));
      if (Cursor->stitch) {
        if (data->time_start.tv_sec) {
          memcpy(&Cursor->stitch->timestamp_min, &data->time_start, sizeof(struct timeval));
        }
        else {
          Cursor->stitch->timestamp_min.tv_sec = idata->now;
          Cursor->stitch->timestamp_min.tv_usec = 0;
        }

        if (data->time_end.tv_sec) {
          memcpy(&Cursor->stitch->timestamp_max, &data->time_end, sizeof(struct timeval));
        }
        else {
          Cursor->stitch->timestamp_max.tv_sec = idata->now;
          Cursor->stitch->timestamp_max.tv_usec = 0;
        }
      }
      else Log(LOG_WARNING, "WARN ( %s/%s ): Finished memory for flow stitching.\n", config.name, config.type);
    }
    else assert(!Cursor->stitch);

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
    insert_status = SQL_INSERT_PRO_RATING;
  }

  if (insert_status == SQL_INSERT_UPDATE) {
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

    if (config.nfacctd_stitching) {
      if (Cursor->stitch) {
        if (data->time_end.tv_sec) {
          if (data->time_end.tv_sec > Cursor->stitch->timestamp_max.tv_sec && 
              data->time_end.tv_usec > Cursor->stitch->timestamp_max.tv_usec)
            memcpy(&Cursor->stitch->timestamp_max, &data->time_end, sizeof(struct timeval));
        }
        else {
          Cursor->stitch->timestamp_max.tv_sec = idata->now;
          Cursor->stitch->timestamp_max.tv_usec = 0;
        }
      }
    }

    insert_status = SQL_INSERT_PRO_RATING;
  }

  if (insert_status == SQL_INSERT_PRO_RATING) {
    if (config.acct_type == ACCT_NF && config.nfacctd_pro_rating && config.sql_history) {
      if ((basetime + timeslot) < data->time_end.tv_sec) {
        basetime += timeslot;
        goto new_timeslot; 
      }
    }
  }

  if (insert_status == SQL_INSERT_SAFE_ACTION) {
    safe_action:

    Log(LOG_INFO, "INFO ( %s/%s ): Finished cache entries (ie. sql_cache_entries). Purging.\n", config.name, config.type);
  
    if (sql_qq_ptr) sql_cache_flush(sql_queries_queue, sql_qq_ptr, idata, FALSE); 

    dump_writers_count();
    if (dump_writers_get_flags() != CHLD_ALERT) {
      switch (ret = fork()) {
      case 0: /* Child */
        signal(SIGINT, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
        pm_setproctitle("%s [%s]", "SQL Plugin -- DB Writer (urgent)", config.name);
	config.is_forked = TRUE;
  
        if (sql_qq_ptr) {
          if (dump_writers_get_flags() == CHLD_WARNING) sql_db_fail(&p);
          (*sqlfunc_cbr.connect)(&p, config.sql_host);
          (*sqlfunc_cbr.purge)(sql_queries_queue, sql_qq_ptr, idata);
          (*sqlfunc_cbr.close)(&bed);
        }
  
        exit_gracefully(0);
      default: /* Parent */
        if (ret == -1) Log(LOG_WARNING, "WARN ( %s/%s ): Unable to fork DB writer (urgent): %s\n", config.name, config.type, strerror(errno));
	else dump_writers_add(ret);

        break;
      }
    }
    else Log(LOG_WARNING, "WARN ( %s/%s ): Maximum number of writer processes reached (%d).\n", config.name, config.type, dump_writers_get_active());
  
    sql_qq_ptr = sql_pqq_ptr;
    memcpy(sql_queries_queue, sql_pending_queries_queue, sizeof(*sql_queries_queue));

    if (SafePtr) {
      sql_queries_queue[sql_qq_ptr] = Cursor;
      sql_qq_ptr++;
    }
    else {
      Cursor = &sql_cache[idata->modulo];
      goto start;
    }
  }
}

void sql_sum_host_insert(struct primitives_ptrs *prim_ptrs, struct insert_data *idata)
{
  struct pkt_data *data = prim_ptrs->data;
  struct host_addr tmp;

  memcpy(&tmp, &data->primitives.dst_ip, HostAddrSz);
  memset(&data->primitives.dst_ip, 0, HostAddrSz);
  sql_cache_insert(prim_ptrs, idata);
  memcpy(&data->primitives.src_ip, &tmp, HostAddrSz);
  sql_cache_insert(prim_ptrs, idata);
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

  if (db->errmsg) Log(LOG_ERR, "ERROR ( %s/%s ): The SQL server says: %s\n", config.name, config.type, db->errmsg);
}

void sql_db_warnmsg(struct DBdesc *db)
{
  if (db->errmsg) Log(LOG_WARNING, "WARN ( %s/%s ): The SQL server says: %s\n", config.name, config.type, db->errmsg);
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
  idata.dyn_table_time_only = glob_dyn_table_time_only;
  idata.new_basetime = glob_new_basetime;
  idata.timeslot = glob_timeslot;
  idata.committed_basetime = glob_committed_basetime;
  if (config.sql_backup_host) idata.recover = TRUE;
  if (config.sql_locking_style) idata.locks = sql_select_locking_style(config.sql_locking_style);

  sql_cache_flush(sql_queries_queue, sql_qq_ptr, &idata, TRUE);

  dump_writers_count();
  if (dump_writers_get_flags() != CHLD_ALERT) {
    if (dump_writers_get_flags() == CHLD_WARNING) sql_db_fail(&p);
    (*sqlfunc_cbr.connect)(&p, config.sql_host);
    (*sqlfunc_cbr.purge)(sql_queries_queue, sql_qq_ptr, &idata);
    (*sqlfunc_cbr.close)(&bed);
  }
  else Log(LOG_WARNING, "WARN ( %s/%s ): Maximum number of writer processes reached (%d).\n", config.name, config.type, dump_writers_get_active());

  if (config.pidfile) remove_pid_file(config.pidfile);

  exit_gracefully(0);
}

int sql_evaluate_primitives(int primitive)
{
  pm_cfgreg_t what_to_count = 0, what_to_count_2 = 0, fakes = 0;
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
    exit_gracefully(1);
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

    if (config.what_to_count & COUNT_SRC_HOST) what_to_count |= COUNT_SRC_HOST;
    else if (config.what_to_count & COUNT_SUM_HOST) what_to_count |= COUNT_SUM_HOST;
    else if (config.what_to_count & COUNT_SUM_NET) what_to_count |= COUNT_SUM_NET;
    else fakes |= FAKE_SRC_HOST;

    if (config.what_to_count & COUNT_SRC_NET) what_to_count |= COUNT_SRC_NET;

    if (config.what_to_count & COUNT_DST_HOST) what_to_count |= COUNT_DST_HOST;
    else fakes |= FAKE_DST_HOST;

    if (config.what_to_count & COUNT_DST_NET) what_to_count |= COUNT_DST_NET;

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

    if (config.what_to_count_2 & COUNT_SRC_ROA) what_to_count_2 |= COUNT_SRC_ROA;
    if (config.what_to_count_2 & COUNT_DST_ROA) what_to_count_2 |= COUNT_DST_ROA;

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

    what_to_count |= COUNT_TAG;

    /* aggregation primitives listed below are not part of any default SQL schema; hence
       no matter if SQL statements optimization is enabled or not, they have to be passed
       on blindly */
    if (config.what_to_count & COUNT_TAG2) what_to_count |= COUNT_TAG2;
    if (config.what_to_count & COUNT_COS) what_to_count |= COUNT_COS;
    if (config.what_to_count & COUNT_ETHERTYPE) what_to_count |= COUNT_ETHERTYPE;
    if (config.what_to_count & COUNT_MPLS_VPN_RD) what_to_count |= COUNT_MPLS_VPN_RD;
    if (config.what_to_count & COUNT_IN_IFACE) what_to_count |= COUNT_IN_IFACE;
    if (config.what_to_count & COUNT_OUT_IFACE) what_to_count |= COUNT_OUT_IFACE;
    if (config.what_to_count & COUNT_SRC_NMASK) what_to_count |= COUNT_SRC_NMASK;
    if (config.what_to_count & COUNT_DST_NMASK) what_to_count |= COUNT_DST_NMASK;

#if defined (WITH_GEOIP) || defined (WITH_GEOIPV2)
    if (config.what_to_count_2 & COUNT_SRC_HOST_COUNTRY) what_to_count_2 |= COUNT_SRC_HOST_COUNTRY;
    if (config.what_to_count_2 & COUNT_DST_HOST_COUNTRY) what_to_count_2 |= COUNT_DST_HOST_COUNTRY;
#endif
#if defined (WITH_GEOIPV2)
    if (config.what_to_count_2 & COUNT_SRC_HOST_POCODE) what_to_count_2 |= COUNT_SRC_HOST_POCODE;
    if (config.what_to_count_2 & COUNT_DST_HOST_POCODE) what_to_count_2 |= COUNT_DST_HOST_POCODE;
    if (config.what_to_count_2 & COUNT_SRC_HOST_COORDS) what_to_count_2 |= COUNT_SRC_HOST_COORDS;
    if (config.what_to_count_2 & COUNT_DST_HOST_COORDS) what_to_count_2 |= COUNT_DST_HOST_COORDS;
#endif

    if (config.what_to_count_2 & COUNT_SAMPLING_RATE) what_to_count_2 |= COUNT_SAMPLING_RATE;

    if (config.what_to_count_2 & COUNT_POST_NAT_SRC_HOST) what_to_count_2 |= COUNT_POST_NAT_SRC_HOST;
    if (config.what_to_count_2 & COUNT_POST_NAT_DST_HOST) what_to_count_2 |= COUNT_POST_NAT_DST_HOST;
    if (config.what_to_count_2 & COUNT_POST_NAT_SRC_PORT) what_to_count_2 |= COUNT_POST_NAT_SRC_PORT;
    if (config.what_to_count_2 & COUNT_POST_NAT_DST_PORT) what_to_count_2 |= COUNT_POST_NAT_DST_PORT;
    if (config.what_to_count_2 & COUNT_NAT_EVENT) what_to_count_2 |= COUNT_NAT_EVENT;

    if (config.what_to_count_2 & COUNT_MPLS_LABEL_TOP) what_to_count_2 |= COUNT_MPLS_LABEL_TOP;
    if (config.what_to_count_2 & COUNT_MPLS_LABEL_BOTTOM) what_to_count_2 |= COUNT_MPLS_LABEL_BOTTOM;
    if (config.what_to_count_2 & COUNT_MPLS_STACK_DEPTH) what_to_count_2 |= COUNT_MPLS_STACK_DEPTH;

    if (config.what_to_count_2 & COUNT_TUNNEL_SRC_MAC) what_to_count_2 |= COUNT_TUNNEL_SRC_MAC;
    if (config.what_to_count_2 & COUNT_TUNNEL_DST_MAC) what_to_count_2 |= COUNT_TUNNEL_DST_MAC;
    if (config.what_to_count_2 & COUNT_TUNNEL_SRC_HOST) what_to_count_2 |= COUNT_TUNNEL_SRC_HOST;
    if (config.what_to_count_2 & COUNT_TUNNEL_DST_HOST) what_to_count_2 |= COUNT_TUNNEL_DST_HOST;
    if (config.what_to_count_2 & COUNT_TUNNEL_IP_PROTO) what_to_count_2 |= COUNT_TUNNEL_IP_PROTO;
    if (config.what_to_count_2 & COUNT_TUNNEL_IP_TOS) what_to_count_2 |= COUNT_TUNNEL_IP_TOS;
    if (config.what_to_count_2 & COUNT_TUNNEL_SRC_PORT) what_to_count_2 |= COUNT_TUNNEL_SRC_PORT;
    if (config.what_to_count_2 & COUNT_TUNNEL_DST_PORT) what_to_count_2 |= COUNT_TUNNEL_DST_PORT;

    if (config.what_to_count_2 & COUNT_TIMESTAMP_START) what_to_count_2 |= COUNT_TIMESTAMP_START;
    if (config.what_to_count_2 & COUNT_TIMESTAMP_END) what_to_count_2 |= COUNT_TIMESTAMP_END;
    if (config.what_to_count_2 & COUNT_TIMESTAMP_ARRIVAL) what_to_count_2 |= COUNT_TIMESTAMP_ARRIVAL;

    if (config.what_to_count_2 & COUNT_EXPORT_PROTO_SEQNO) what_to_count_2 |= COUNT_EXPORT_PROTO_SEQNO;
    if (config.what_to_count_2 & COUNT_EXPORT_PROTO_VERSION) what_to_count_2 |= COUNT_EXPORT_PROTO_VERSION;
    if (config.what_to_count_2 & COUNT_EXPORT_PROTO_SYSID) what_to_count_2 |= COUNT_EXPORT_PROTO_SYSID;
    if (config.what_to_count_2 & COUNT_EXPORT_PROTO_TIME) what_to_count_2 |= COUNT_EXPORT_PROTO_TIME;
    if (config.what_to_count_2 & COUNT_LABEL) what_to_count_2 |= COUNT_LABEL;

#if defined (WITH_NDPI)
    if (config.what_to_count_2 & COUNT_NDPI_CLASS) what_to_count_2 |= COUNT_NDPI_CLASS;
#endif
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
      exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_SRC_MAC;
      values[primitive].handler = where[primitive].handler = count_src_mac_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_DST_MAC) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): MAC accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_DST_MAC;
      values[primitive].handler = where[primitive].handler = count_dst_mac_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_VLAN) {
    int count_it = FALSE;

    if ((config.sql_table_version < 2 || config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_VLAN) {
        Log(LOG_ERR, "ERROR ( %s/%s ): VLAN accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_VLAN;
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
    values[primitive].type = where[primitive].type = COUNT_INT_COS;
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
    values[primitive].type = where[primitive].type = COUNT_INT_ETHERTYPE;
    values[primitive].handler = where[primitive].handler = count_etype_handler;
    primitive++;
  }
#endif

  if (what_to_count & (COUNT_SRC_HOST|COUNT_SUM_HOST)) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): IP host accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_gracefully(1);
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
        strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, "ip_src=%s(\'%s\')", SPACELEFT(where[primitive].string));
        values[primitive].type = where[primitive].type = COUNT_INT_SRC_HOST;
        values[primitive].handler = where[primitive].handler = count_src_host_aton_handler;
        primitive++;
      }
      else {
	strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_src=\'%s\'", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = COUNT_INT_SRC_HOST;
	values[primitive].handler = where[primitive].handler = count_src_host_handler;
	primitive++;
      }
    }
  }

  if (what_to_count & (COUNT_SRC_NET|COUNT_SUM_NET)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
      strncat(insert_clause, "net_src", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "net_src=%s(\'%s\')", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_SRC_NET;
      values[primitive].handler = where[primitive].handler = count_src_net_aton_handler;
      primitive++;
    }
    else {
      strncat(insert_clause, "net_src", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "net_src=\'%s\'", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_SRC_NET;
      values[primitive].handler = where[primitive].handler = count_src_net_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_DST_HOST) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): IP host accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_gracefully(1);
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
        strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, "ip_dst=%s(\'%s\')", SPACELEFT(where[primitive].string));
        values[primitive].type = where[primitive].type = COUNT_INT_DST_HOST;
        values[primitive].handler = where[primitive].handler = count_dst_host_aton_handler;
        primitive++;
      }
      else {
	strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = COUNT_INT_DST_HOST;
	values[primitive].handler = where[primitive].handler = count_dst_host_handler;
	primitive++;
      }
    }
  }

  if (what_to_count & COUNT_DST_NET) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
      strncat(insert_clause, "net_dst", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "net_dst=%s(\'%s\')", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_DST_NET;
      values[primitive].handler = where[primitive].handler = count_dst_net_aton_handler;
      primitive++;
    }
    else {
      strncat(insert_clause, "net_dst", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "net_dst=\'%s\'", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_DST_NET;
      values[primitive].handler = where[primitive].handler = count_dst_net_handler;
      primitive++;
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
    values[primitive].type = where[primitive].type = COUNT_INT_SRC_AS;
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
    values[primitive].type = where[primitive].type = COUNT_INT_IN_IFACE;
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
    values[primitive].type = where[primitive].type = COUNT_INT_OUT_IFACE;
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
    values[primitive].type = where[primitive].type = COUNT_INT_SRC_NMASK;
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
    values[primitive].type = where[primitive].type = COUNT_INT_DST_NMASK;
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
    values[primitive].type = where[primitive].type = COUNT_INT_DST_AS;
    values[primitive].handler = where[primitive].handler = count_dst_as_handler;
    primitive++;
  }

  if (what_to_count & COUNT_STD_COMM) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_STD_COMM;
      values[primitive].handler = where[primitive].handler = count_std_comm_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_EXT_COMM) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_gracefully(1);
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }

      strncat(insert_clause, "ecomms", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "ecomms=\'%s\'", SPACELEFT(where[primitive].string));

      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_EXT_COMM;
      values[primitive].handler = where[primitive].handler = count_ext_comm_handler;
      primitive++;
    }
  }

  if (what_to_count_2 & COUNT_LRG_COMM) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }

    strncat(insert_clause, "lcomms", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "lcomms=\'%s\'", SPACELEFT(where[primitive].string));

    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_LRG_COMM;
    values[primitive].handler = where[primitive].handler = count_lrg_comm_handler;
    primitive++;
  }

  if (what_to_count & COUNT_SRC_STD_COMM) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "comms_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "comms_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_SRC_STD_COMM;
    values[primitive].handler = where[primitive].handler = count_src_std_comm_handler;
    primitive++;
  }

  if (what_to_count & COUNT_SRC_EXT_COMM) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "ecomms_src", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "ecomms_src=\'%s\'", SPACELEFT(where[primitive].string));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_SRC_EXT_COMM;
    values[primitive].handler = where[primitive].handler = count_src_ext_comm_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_SRC_LRG_COMM) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }

    strncat(insert_clause, "lcomms_src", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "lcomms_src=\'%s\'", SPACELEFT(where[primitive].string));

    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_SRC_LRG_COMM;
    values[primitive].handler = where[primitive].handler = count_src_lrg_comm_handler;
    primitive++;
  }

  if (what_to_count & COUNT_AS_PATH) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_AS_PATH;
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
    values[primitive].type = where[primitive].type = COUNT_INT_SRC_AS_PATH;
    values[primitive].handler = where[primitive].handler = count_src_as_path_handler;
    primitive++;
  }

  if (what_to_count & COUNT_LOCAL_PREF) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_LOCAL_PREF) {
        Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_LOCAL_PREF;
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
    values[primitive].type = where[primitive].type = COUNT_INT_SRC_LOCAL_PREF;
    values[primitive].handler = where[primitive].handler = count_src_local_pref_handler;
    primitive++;
  }

  if (what_to_count & COUNT_MED) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_MED) {
        Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_MED;
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
    values[primitive].type = where[primitive].type = COUNT_INT_SRC_MED;
    values[primitive].handler = where[primitive].handler = count_src_med_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_SRC_ROA) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "roa_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%s", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "roa_src=%s", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_SRC_ROA;
    values[primitive].handler = where[primitive].handler = count_src_roa_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_DST_ROA) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "roa_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%s", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "roa_dst=%s", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_DST_ROA;
    values[primitive].handler = where[primitive].handler = count_dst_roa_handler;
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
    values[primitive].type = where[primitive].type = COUNT_INT_MPLS_VPN_RD;
    values[primitive].handler = where[primitive].handler = count_mpls_vpn_rd_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_MPLS_PW_ID) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "mpls_pw_id", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mpls_pw_id=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_MPLS_PW_ID;
    values[primitive].handler = where[primitive].handler = count_mpls_pw_id_handler;
    primitive++;
  }

  if (what_to_count & COUNT_PEER_SRC_AS) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_PEER_SRC_AS;
      values[primitive].handler = where[primitive].handler = count_peer_src_as_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_PEER_DST_AS) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_PEER_DST_AS;
      values[primitive].handler = where[primitive].handler = count_peer_dst_as_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_PEER_SRC_IP) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_gracefully(1);
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
        strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, "peer_ip_src=%s(\'%s\')", SPACELEFT(where[primitive].string));
        values[primitive].type = where[primitive].type = COUNT_INT_PEER_SRC_IP;
        values[primitive].handler = where[primitive].handler = count_peer_src_ip_aton_handler;
        primitive++;
      }
      else {
	strncat(insert_clause, "peer_ip_src", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "peer_ip_src=\'%s\'", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = COUNT_INT_PEER_SRC_IP;
	values[primitive].handler = where[primitive].handler = count_peer_src_ip_handler;
	primitive++;
      }
    }
  }

  if (what_to_count & COUNT_PEER_DST_IP) {
    int count_it = FALSE;

    if ((config.sql_table_version < SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      Log(LOG_ERR, "ERROR ( %s/%s ): BGP accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
      exit_gracefully(1);
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
        strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, "peer_ip_dst=%s(\'%s\')", SPACELEFT(where[primitive].string));
        values[primitive].type = where[primitive].type = COUNT_INT_PEER_DST_IP;
        values[primitive].handler = where[primitive].handler = count_peer_dst_ip_aton_handler;
        primitive++;
      }
      else {
	strncat(insert_clause, "peer_ip_dst", SPACELEFT(insert_clause));
	strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "peer_ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = COUNT_INT_PEER_DST_IP;
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
        exit_gracefully(1);
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
      if ((!strcmp(config.type, "mysql") || !strcmp(config.type, "sqlite3")) && (config.sql_table_version < 8 ||
	  (config.sql_table_version >= SQL_TABLE_VERSION_BGP && config.sql_table_version < SQL_TABLE_VERSION_BGP+8))) {
        strncat(insert_clause, "src_port", SPACELEFT(insert_clause));
        strncat(where[primitive].string, "src_port=%u", SPACELEFT(where[primitive].string));
      }
      else {
        strncat(insert_clause, "port_src", SPACELEFT(insert_clause));
        strncat(where[primitive].string, "port_src=%u", SPACELEFT(where[primitive].string));
      } 
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_SRC_PORT;
      values[primitive].handler = where[primitive].handler = count_src_port_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_DST_PORT) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_DST_PORT) {
        Log(LOG_ERR, "ERROR ( %s/%s ): TCP/UDP port accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_gracefully(1);
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
      if ((!strcmp(config.type, "mysql") || !strcmp(config.type, "sqlite3")) && (config.sql_table_version < 8 ||
          (config.sql_table_version >= SQL_TABLE_VERSION_BGP && config.sql_table_version < SQL_TABLE_VERSION_BGP+8))) {
        strncat(insert_clause, "dst_port", SPACELEFT(insert_clause));
        strncat(where[primitive].string, "dst_port=%u", SPACELEFT(where[primitive].string));
      }
      else {
        strncat(insert_clause, "port_dst", SPACELEFT(insert_clause));
        strncat(where[primitive].string, "port_dst=%u", SPACELEFT(where[primitive].string));
      }
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_DST_PORT;
      values[primitive].handler = where[primitive].handler = count_dst_port_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_TCPFLAGS) {
    int count_it = FALSE;

    if ((config.sql_table_version < 7 || config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_TCPFLAGS) {
        Log(LOG_ERR, "ERROR ( %s/%s ): TCP flags accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
	exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_TCPFLAGS;
      values[primitive].handler = where[primitive].handler = count_tcpflags_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_IP_TOS) {
    int count_it = FALSE;

    if ((config.sql_table_version < 3 || config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_IP_TOS) {
        Log(LOG_ERR, "ERROR ( %s/%s ): IP ToS accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_IP_TOS;
      values[primitive].handler = where[primitive].handler = count_ip_tos_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_IP_PROTO) {
    int count_it = FALSE;

    if ((config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_IP_PROTO) {
        Log(LOG_ERR, "ERROR ( %s/%s ): IP proto accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_IP_PROTO;
      primitive++;
    }
  }

#if defined (WITH_GEOIP) || defined (WITH_GEOIPV2)
  if (what_to_count_2 & COUNT_SRC_HOST_COUNTRY) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "country_ip_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "country_ip_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_SRC_HOST_COUNTRY;
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
    values[primitive].type = where[primitive].type = COUNT_INT_DST_HOST_COUNTRY;
    values[primitive].handler = where[primitive].handler = count_dst_host_country_handler;
    primitive++;
  }
#endif

#if defined (WITH_GEOIPV2)
  if (what_to_count_2 & COUNT_SRC_HOST_POCODE) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "pocode_ip_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "pocode_ip_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_SRC_HOST_POCODE;
    values[primitive].handler = where[primitive].handler = count_src_host_pocode_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_DST_HOST_POCODE) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "pocode_ip_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "pocode_ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_DST_HOST_POCODE;
    values[primitive].handler = where[primitive].handler = count_dst_host_pocode_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_SRC_HOST_COORDS) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "lat_ip_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%f\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "lat_ip_src=\'%f\'", SPACELEFT(where[primitive].string));

    strncat(insert_clause, ", ", SPACELEFT(insert_clause));
    strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));

    strncat(insert_clause, "lon_ip_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%f\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    strncat(where[primitive].string, "lon_ip_src=\'%f\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_SRC_HOST_COORDS;
    values[primitive].handler = where[primitive].handler = count_src_host_coords_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_DST_HOST_COORDS) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "lat_ip_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%f\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "lat_ip_dst=\'%f\'", SPACELEFT(where[primitive].string));

    strncat(insert_clause, ", ", SPACELEFT(insert_clause));
    strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));

    strncat(insert_clause, "lon_ip_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%f\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    strncat(where[primitive].string, "lon_ip_dst=\'%f\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_DST_HOST_COORDS;
    values[primitive].handler = where[primitive].handler = count_dst_host_coords_handler;
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
    values[primitive].type = where[primitive].type = COUNT_INT_SAMPLING_RATE;
    values[primitive].handler = where[primitive].handler = count_sampling_rate_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_SAMPLING_DIRECTION) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "sampling_direction", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "sampling_direction=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_SAMPLING_DIRECTION;
    values[primitive].handler = where[primitive].handler = count_sampling_direction_handler;
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
      strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "post_nat_ip_src=%s(\'%s\')", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_POST_NAT_SRC_HOST;
      values[primitive].handler = where[primitive].handler = count_post_nat_src_ip_aton_handler;
      primitive++;
    }
    else {
      strncat(insert_clause, "post_nat_ip_src", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "post_nat_ip_src=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_POST_NAT_SRC_HOST;
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
      strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "post_nat_ip_dst=%s(\'%s\')", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_POST_NAT_DST_HOST;
      values[primitive].handler = where[primitive].handler = count_post_nat_dst_ip_aton_handler;
      primitive++;
    }
    else {
      strncat(insert_clause, "post_nat_ip_dst", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "post_nat_ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_POST_NAT_DST_HOST;
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
    values[primitive].type = where[primitive].type = COUNT_INT_POST_NAT_SRC_PORT;
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
    values[primitive].type = where[primitive].type = COUNT_INT_POST_NAT_DST_PORT;
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
    values[primitive].type = where[primitive].type = COUNT_INT_NAT_EVENT;
    values[primitive].handler = where[primitive].handler = count_nat_event_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_MPLS_LABEL_TOP) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "mpls_label_top", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "mpls_label_top=%u", SPACELEFT(where[primitive].string));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_MPLS_LABEL_TOP;
    values[primitive].handler = where[primitive].handler = count_mpls_label_top_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_MPLS_LABEL_BOTTOM) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "mpls_label_bottom", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "mpls_label_bottom=%u", SPACELEFT(where[primitive].string));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_MPLS_LABEL_BOTTOM;
    values[primitive].handler = where[primitive].handler = count_mpls_label_bottom_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_MPLS_STACK_DEPTH) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "mpls_stack_depth", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "mpls_stack_depth=%u", SPACELEFT(where[primitive].string));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_MPLS_STACK_DEPTH;
    values[primitive].handler = where[primitive].handler = count_mpls_stack_depth_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_TUNNEL_SRC_MAC) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "tunnel_mac_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "tunnel_mac_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_TUNNEL_SRC_MAC;
    values[primitive].handler = where[primitive].handler = count_tunnel_src_mac_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_TUNNEL_DST_MAC) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "tunnel_mac_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "tunnel_mac_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_TUNNEL_DST_MAC;
    values[primitive].handler = where[primitive].handler = count_tunnel_dst_mac_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_TUNNEL_SRC_HOST) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
      strncat(insert_clause, "tunnel_ip_src", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "tunnel_ip_src=%s(\'%s\')", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_TUNNEL_SRC_HOST;
      values[primitive].handler = where[primitive].handler = count_tunnel_src_ip_aton_handler;
      primitive++;
    }
    else {
      strncat(insert_clause, "tunnel_ip_src", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "tunnel_ip_src=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_TUNNEL_SRC_HOST;
      values[primitive].handler = where[primitive].handler = count_tunnel_src_ip_handler;
      primitive++;
    }
  }

  if (what_to_count_2 & COUNT_TUNNEL_DST_HOST) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && config.num_hosts) {
      strncat(insert_clause, "tunnel_ip_dst", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "tunnel_ip_dst=%s(\'%s\')", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_TUNNEL_DST_HOST;
      values[primitive].handler = where[primitive].handler = count_tunnel_dst_ip_aton_handler;
      primitive++;
    }
    else {
      strncat(insert_clause, "tunnel_ip_dst", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "tunnel_ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_TUNNEL_DST_HOST;
      values[primitive].handler = where[primitive].handler = count_tunnel_dst_ip_handler;
      primitive++;
    }
  }

  if (what_to_count_2 & COUNT_TUNNEL_IP_PROTO) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "tunnel_ip_proto", SPACELEFT(insert_clause));
    if ((!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) && !config.num_protos) {
      strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "tunnel_ip_proto=\'%s\'", SPACELEFT(where[primitive].string));
      values[primitive].handler = where[primitive].handler = MY_count_tunnel_ip_proto_handler;
    }
    else { 
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "tunnel_ip_proto=%u", SPACELEFT(where[primitive].string));
      values[primitive].handler = where[primitive].handler = PG_count_tunnel_ip_proto_handler;
    }
    values[primitive].type = where[primitive].type = COUNT_INT_TUNNEL_IP_PROTO;
    primitive++;
  }

  if (what_to_count_2 & COUNT_TUNNEL_IP_TOS) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "tunnel_tos", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "tunnel_tos=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_TUNNEL_IP_TOS;
    values[primitive].handler = where[primitive].handler = count_tunnel_ip_tos_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_TUNNEL_SRC_PORT) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "tunnel_port_src", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "tunnel_port_src=%u", SPACELEFT(where[primitive].string));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_TUNNEL_SRC_PORT;
    values[primitive].handler = where[primitive].handler = count_tunnel_src_port_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_TUNNEL_DST_PORT) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "tunnel_port_dst", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "tunnel_port_dst=%u", SPACELEFT(where[primitive].string));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_TUNNEL_DST_PORT;
    values[primitive].handler = where[primitive].handler = count_tunnel_dst_port_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_VXLAN) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "vxlan", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "vxlan=%u", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_VXLAN;
    values[primitive].handler = where[primitive].handler = count_vxlan_handler;
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
    if (config.timestamps_since_epoch) {
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
          strncat(where[primitive].string, "timestamp_start=to_timestamp(%u)", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "to_timestamp(%u)", SPACELEFT(values[primitive].string));
	}
      }
      else if (!strcmp(config.type, "sqlite3")) {
	if (!config.timestamps_utc) {
          strncat(where[primitive].string, "timestamp_start=DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(values[primitive].string));
	}
	else {
          strncat(where[primitive].string, "timestamp_start=DATETIME(%u, 'unixepoch')", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "DATETIME(%u, 'unixepoch')", SPACELEFT(values[primitive].string));
	}
      }
    }
    if (!use_copy) values[primitive].handler = where[primitive].handler = count_timestamp_start_handler;
    else values[primitive].handler = where[primitive].handler = PG_copy_count_timestamp_start_handler;
    values[primitive].type = where[primitive].type = COUNT_INT_TIMESTAMP_START;
    primitive++;

    if (!config.timestamps_secs) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));

      strncat(insert_clause, "timestamp_start_residual", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "timestamp_start_residual=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_TIMESTAMP_START;
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
    if (config.timestamps_since_epoch) {
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
          strncat(where[primitive].string, "timestamp_end=to_timestamp(%u)", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "to_timestamp(%u)", SPACELEFT(values[primitive].string));
        }
      }
      else if (!strcmp(config.type, "sqlite3")) {
	if (!config.timestamps_utc) {
          strncat(where[primitive].string, "timestamp_end=DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(values[primitive].string));
	}
	else {
          strncat(where[primitive].string, "timestamp_end=DATETIME(%u, 'unixepoch')", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "DATETIME(%u, 'unixepoch')", SPACELEFT(values[primitive].string));
	}
      }
    }
    if (!use_copy) values[primitive].handler = where[primitive].handler = count_timestamp_end_handler;
    else values[primitive].handler = where[primitive].handler = PG_copy_count_timestamp_end_handler; 
    values[primitive].type = where[primitive].type = COUNT_INT_TIMESTAMP_END;
    primitive++;

    if (!config.timestamps_secs) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));

      strncat(insert_clause, "timestamp_end_residual", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "timestamp_end_residual=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_TIMESTAMP_END;
      values[primitive].handler = where[primitive].handler = count_timestamp_end_residual_handler;
      primitive++;
    }
  }

  if (what_to_count_2 & COUNT_TIMESTAMP_ARRIVAL) {
    int use_copy=0;

    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "timestamp_arrival", SPACELEFT(insert_clause));
    if (config.timestamps_since_epoch) {
      strncat(where[primitive].string, "timestamp_arrival=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    }
    else {
      if (!strcmp(config.type, "mysql")) {
        strncat(where[primitive].string, "timestamp_arrival=FROM_UNIXTIME(%u)", SPACELEFT(where[primitive].string));
        strncat(values[primitive].string, "FROM_UNIXTIME(%u)", SPACELEFT(values[primitive].string));
      }
      else if (!strcmp(config.type, "pgsql")) {
        if (config.sql_use_copy) {
          strncat(values[primitive].string, "%s", SPACELEFT(values[primitive].string));
          use_copy = TRUE;
        }
        else {
          strncat(where[primitive].string, "timestamp_arrival=to_timestamp(%u)", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "to_timestamp(%u)", SPACELEFT(values[primitive].string));
        }
      }
      else if (!strcmp(config.type, "sqlite3")) {
	if (!config.timestamps_utc) {
          strncat(where[primitive].string, "timestamp_arrival=DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(values[primitive].string));
	}
	else {
          strncat(where[primitive].string, "timestamp_arrival=DATETIME(%u, 'unixepoch')", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "DATETIME(%u, 'unixepoch')", SPACELEFT(values[primitive].string));
	}
      }
    }
    if (!use_copy) values[primitive].handler = where[primitive].handler = count_timestamp_arrival_handler;
    else values[primitive].handler = where[primitive].handler = PG_copy_count_timestamp_arrival_handler;
    values[primitive].type = where[primitive].type = COUNT_INT_TIMESTAMP_ARRIVAL;
    primitive++;

    if (!config.timestamps_secs) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));

      strncat(insert_clause, "timestamp_arrival_residual", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "timestamp_arrival_residual=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_TIMESTAMP_ARRIVAL;
      values[primitive].handler = where[primitive].handler = count_timestamp_arrival_residual_handler;
      primitive++;
    }
  }

  if (what_to_count_2 & COUNT_EXPORT_PROTO_TIME) {
    int use_copy=0;

    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "timestamp_export", SPACELEFT(insert_clause));
    if (config.timestamps_since_epoch) {
      strncat(where[primitive].string, "timestamp_export=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    }
    else {
      if (!strcmp(config.type, "mysql")) {
        strncat(where[primitive].string, "timestamp_export=FROM_UNIXTIME(%u)", SPACELEFT(where[primitive].string));
        strncat(values[primitive].string, "FROM_UNIXTIME(%u)", SPACELEFT(values[primitive].string));
      }
      else if (!strcmp(config.type, "pgsql")) {
        if (config.sql_use_copy) {
          strncat(values[primitive].string, "%s", SPACELEFT(values[primitive].string));
          use_copy = TRUE;
        }
        else {
          strncat(where[primitive].string, "timestamp_export=to_timestamp(%u)", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "to_timestamp(%u)", SPACELEFT(values[primitive].string));
        }
      }
      else if (!strcmp(config.type, "sqlite3")) {
	if (!config.timestamps_utc) {
          strncat(where[primitive].string, "timestamp_export=DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(values[primitive].string));
	}
	else {
          strncat(where[primitive].string, "timestamp_export=DATETIME(%u, 'unixepoch')", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "DATETIME(%u, 'unixepoch')", SPACELEFT(values[primitive].string));
	}
      }
    }
    if (!use_copy) values[primitive].handler = where[primitive].handler = count_timestamp_export_handler;
    else values[primitive].handler = where[primitive].handler = PG_copy_count_timestamp_export_handler;
    values[primitive].type = where[primitive].type = COUNT_INT_EXPORT_PROTO_TIME;
    primitive++;

    if (!config.timestamps_secs) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));

      strncat(insert_clause, "timestamp_export_residual", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "timestamp_export_residual=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_EXPORT_PROTO_TIME;
      values[primitive].handler = where[primitive].handler = count_timestamp_export_residual_handler;
      primitive++;
    }
  }

  if (config.nfacctd_stitching) {
    int use_copy=0;

    /* timestamp_min */
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "timestamp_min", SPACELEFT(insert_clause));
    if (config.timestamps_since_epoch) {
      strncat(where[primitive].string, "timestamp_min=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    }
    else {
      if (!strcmp(config.type, "mysql")) {
        strncat(where[primitive].string, "timestamp_min=FROM_UNIXTIME(%u)", SPACELEFT(where[primitive].string));
        strncat(values[primitive].string, "FROM_UNIXTIME(%u)", SPACELEFT(values[primitive].string));
      }
      else if (!strcmp(config.type, "pgsql")) {
        if (config.sql_use_copy) {
          strncat(values[primitive].string, "%s", SPACELEFT(values[primitive].string));
          use_copy = TRUE;
        }
        else {
          strncat(where[primitive].string, "timestamp_min=to_timestamp(%u)", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "to_timestamp(%u)", SPACELEFT(values[primitive].string));
        }
      }
      else if (!strcmp(config.type, "sqlite3")) {
	if (!config.timestamps_utc) {
          strncat(where[primitive].string, "timestamp_min=DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(values[primitive].string));
	}
	else {
          strncat(where[primitive].string, "timestamp_min=DATETIME(%u, 'unixepoch')", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "DATETIME(%u, 'unixepoch')", SPACELEFT(values[primitive].string));
	}
      }
    }
    if (!use_copy) values[primitive].handler = where[primitive].handler = count_timestamp_min_handler;
    else values[primitive].handler = where[primitive].handler = PG_copy_count_timestamp_min_handler;
    values[primitive].type = where[primitive].type = FALSE;
    primitive++;

    if (!config.timestamps_secs) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));

      strncat(insert_clause, "timestamp_min_residual", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "timestamp_min_residual=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = FALSE;
      values[primitive].handler = where[primitive].handler = count_timestamp_min_residual_handler;
      primitive++;
    }

    /* timestamp_max */
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "timestamp_max", SPACELEFT(insert_clause));
    if (config.timestamps_since_epoch) {
      strncat(where[primitive].string, "timestamp_max=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    }
    else {
      if (!strcmp(config.type, "mysql")) {
        strncat(where[primitive].string, "timestamp_max=FROM_UNIXTIME(%u)", SPACELEFT(where[primitive].string));
        strncat(values[primitive].string, "FROM_UNIXTIME(%u)", SPACELEFT(values[primitive].string));
      }
      else if (!strcmp(config.type, "pgsql")) {
        if (config.sql_use_copy) {
          strncat(values[primitive].string, "%s", SPACELEFT(values[primitive].string));
          use_copy = TRUE;
        }
        else {
          strncat(where[primitive].string, "timestamp_max=to_timestamp(%u)", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "to_timestamp(%u)", SPACELEFT(values[primitive].string));
        }
      }
      else if (!strcmp(config.type, "sqlite3")) {
	if (!config.timestamps_utc) {
          strncat(where[primitive].string, "timestamp_max=DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(values[primitive].string));
	}
	else {
          strncat(where[primitive].string, "timestamp_max=DATETIME(%u, 'unixepoch')", SPACELEFT(where[primitive].string));
          strncat(values[primitive].string, "DATETIME(%u, 'unixepoch')", SPACELEFT(values[primitive].string));
	}
      }
    }

    if (!use_copy) values[primitive].handler = where[primitive].handler = count_timestamp_max_handler;
    else values[primitive].handler = where[primitive].handler = PG_copy_count_timestamp_max_handler;
    values[primitive].type = where[primitive].type = FALSE;
    primitive++;

    if (!config.timestamps_secs) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));

      strncat(insert_clause, "timestamp_max_residual", SPACELEFT(insert_clause));
      strncat(where[primitive].string, "timestamp_max_residual=%u", SPACELEFT(where[primitive].string));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = FALSE;
      values[primitive].handler = where[primitive].handler = count_timestamp_max_residual_handler;
      primitive++;
    }
  }

  if (what_to_count_2 & COUNT_EXPORT_PROTO_SEQNO) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "export_proto_seqno", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "export_proto_seqno=%u", SPACELEFT(where[primitive].string));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    values[primitive].handler = where[primitive].handler = count_export_proto_seqno_handler;
    values[primitive].type = where[primitive].type = COUNT_INT_EXPORT_PROTO_SEQNO;
    primitive++;
  }

  if (what_to_count_2 & COUNT_EXPORT_PROTO_VERSION) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "export_proto_version", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "export_proto_version=%u", SPACELEFT(where[primitive].string));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    values[primitive].handler = where[primitive].handler = count_export_proto_version_handler;
    values[primitive].type = where[primitive].type = COUNT_INT_EXPORT_PROTO_VERSION;
    primitive++;
  }

  if (what_to_count_2 & COUNT_EXPORT_PROTO_SYSID) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "export_proto_sysid", SPACELEFT(insert_clause));
    strncat(where[primitive].string, "export_proto_sysid=%u", SPACELEFT(where[primitive].string));
    strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
    values[primitive].handler = where[primitive].handler = count_export_proto_sysid_handler;
    values[primitive].type = where[primitive].type = COUNT_INT_EXPORT_PROTO_SYSID;
    primitive++;
  }

  /* all custom primitives printed here */
  {
    struct custom_primitive_ptrs *cp_entry;
    int cp_idx;

    for (cp_idx = 0; cp_idx < config.cpptrs.num; cp_idx++) {
      if (primitive) {
	strncat(insert_clause, ", ", SPACELEFT(insert_clause));
	strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }

      cp_entry = &config.cpptrs.primitive[cp_idx];
      strncat(insert_clause, cp_entry->name, SPACELEFT(insert_clause));
      strncat(where[primitive].string, cp_entry->name, SPACELEFT(where[primitive].string));
      if (cp_entry->ptr->semantics == CUSTOM_PRIMITIVE_TYPE_UINT) {
	strncat(where[primitive].string, "=%s", SPACELEFT(where[primitive].string));
        strncat(values[primitive].string, "%s", SPACELEFT(values[primitive].string));
      }
      else {
	strncat(where[primitive].string, "=\'%s\'", SPACELEFT(where[primitive].string));
        strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
      }
      values[primitive].type = where[primitive].type = COUNT_INT_CUSTOM_PRIMITIVES;
      values[primitive].handler = where[primitive].handler = count_custom_primitives_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_TAG) {
    int count_it = FALSE;

    if ((config.sql_table_version < 2) && !assume_custom_table) {
      if (config.what_to_count & COUNT_TAG) {
	Log(LOG_ERR, "ERROR ( %s/%s ): Tag/ID accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_gracefully(1);	
      }
      else what_to_count ^= COUNT_TAG;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
        strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
      }
      if (config.sql_table_version < 9 || (config.sql_table_version >= SQL_TABLE_VERSION_BGP
	  && config.sql_table_version < SQL_TABLE_VERSION_BGP+9)) {
        strncat(insert_clause, "agent_id", SPACELEFT(insert_clause));
        strncat(where[primitive].string, "agent_id=%llu", SPACELEFT(where[primitive].string));
      }
      else {
        strncat(insert_clause, "tag", SPACELEFT(insert_clause));
        strncat(where[primitive].string, "tag=%llu", SPACELEFT(where[primitive].string));
      }
      strncat(values[primitive].string, "%llu", SPACELEFT(values[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_INT_TAG;
      values[primitive].handler = where[primitive].handler = count_tag_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_TAG2) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "tag2", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "%llu", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "tag2=%llu", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_TAG2;
    values[primitive].handler = where[primitive].handler = count_tag2_handler;
    primitive++;
  }

  if (what_to_count_2 & COUNT_LABEL) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "label", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "label=%\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_LABEL;
    values[primitive].handler = where[primitive].handler = count_label_handler;
    primitive++;
  }

  if (what_to_count & COUNT_CLASS) {
    int count_it = FALSE;

    if ((config.sql_table_version < 5 || config.sql_table_version >= SQL_TABLE_VERSION_BGP) && !assume_custom_table) {
      if (config.what_to_count & COUNT_CLASS) {
        Log(LOG_ERR, "ERROR ( %s/%s ): L7 classification accounting not supported for selected sql_table_version/_type. Read about SQL table versioning or consider using sql_optimize_clauses.\n", config.name, config.type);
        exit_gracefully(1);
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
      values[primitive].type = where[primitive].type = COUNT_INT_CLASS;
      values[primitive].handler = where[primitive].handler = count_class_id_handler;
      primitive++;
    }
  }

#if defined (WITH_NDPI)
  if (what_to_count_2 & COUNT_NDPI_CLASS) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, delim_buf, SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, " AND ", SPACELEFT(where[primitive].string));
    }
    strncat(insert_clause, "class", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "class=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_INT_CLASS;
    values[primitive].handler = where[primitive].handler = count_ndpi_class_handler;
    primitive++;
  }
#endif

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
	strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_src=%s(\'%s\')", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = FAKE_SRC_HOST;
	values[primitive].handler = where[primitive].handler = fake_host_aton_handler;
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
	strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "ip_dst=%s(\'%s\')", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = FAKE_DST_HOST;
	values[primitive].handler = where[primitive].handler = fake_host_aton_handler;
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
	strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "peer_ip_src=%s(\'%s\')", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = FAKE_PEER_SRC_IP;
	values[primitive].handler = where[primitive].handler = fake_host_aton_handler;
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
	strncat(values[primitive].string, "%s(\'%s\')", SPACELEFT(values[primitive].string));
	strncat(where[primitive].string, "peer_ip_dst=%s(\'%s\')", SPACELEFT(where[primitive].string));
	values[primitive].type = where[primitive].type = FAKE_PEER_DST_IP;
	values[primitive].handler = where[primitive].handler = fake_host_aton_handler;
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

	    sql_create_table(bed->b, &stamp, NULL); // XXX: should not be null
	  }
          (*sqlfunc_cbr.lock)(bed->b);
        }
        if (!bed->b->fail) {
          if ((*sqlfunc_cbr.op)(bed->b, elem, idata)) sql_db_fail(bed->b);
        }
      }
    }
  }

  return TRUE;
}

void sql_create_table(struct DBdesc *db, time_t *basetime, struct primitives_ptrs *prim_ptrs)
{
  char buf[LARGEBUFLEN], tmpbuf[LARGEBUFLEN];
  int ret;

  ret = read_SQLquery_from_file(config.sql_table_schema, buf, LARGEBUFLEN);
  if (ret) {
    handle_dynname_internal_strings_same(buf, LARGEBUFLEN, tmpbuf, prim_ptrs, DYN_STR_SQL_TABLE);
    pm_strftime_same(buf, LARGEBUFLEN, tmpbuf, basetime, config.timestamps_utc);
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
  else if (!strcmp(lock, "none")) return PM_LOCK_NONE;

  Log(LOG_WARNING, "WARN ( %s/%s ): sql_locking_style value '%s' is unknown. Ignored.\n", config.name, config.type, lock);

  return PM_LOCK_EXCLUSIVE;
}

int sql_compose_static_set_event()
{
  int set_primitives=0;

  if (config.what_to_count & COUNT_TCPFLAGS) {
    strncat(set_event[set_primitives].string, "SET tcp_flags=tcp_flags|%u", SPACELEFT(set_event[set_primitives].string));
    set_event[set_primitives].type = COUNT_INT_TCPFLAGS;
    set_event[set_primitives].handler = count_tcpflags_setclause_handler;
    set_primitives++;
  }

  return set_primitives;
}

int sql_compose_static_set(int have_flows)
{
  int set_primitives=0;

  strncpy(set[set_primitives].string, "SET packets=packets+%llu, bytes=bytes+%llu", SPACELEFT(set[set_primitives].string));
  set[set_primitives].type = COUNT_INT_COUNTERS;
  set[set_primitives].handler = count_counters_setclause_handler;
  set_primitives++;

  if (have_flows) {
    strncpy(set[set_primitives].string, ", ", SPACELEFT(set[set_primitives].string));
    strncat(set[set_primitives].string, "flows=flows+%llu", SPACELEFT(set[set_primitives].string));
    set[set_primitives].type = COUNT_INT_FLOWS;
    set[set_primitives].handler = count_flows_setclause_handler;
    set_primitives++;
  }

  if (config.what_to_count & COUNT_TCPFLAGS) {
    strncpy(set[set_primitives].string, ", ", SPACELEFT(set[set_primitives].string));
    strncat(set[set_primitives].string, "tcp_flags=tcp_flags|%u", SPACELEFT(set[set_primitives].string));
    set[set_primitives].type = COUNT_INT_TCPFLAGS;
    set[set_primitives].handler = count_tcpflags_setclause_handler;
    set_primitives++;
  }

  return set_primitives;
}

void primptrs_set_all_from_db_cache(struct primitives_ptrs *prim_ptrs, struct db_cache *entry)
{
  struct pkt_data *data = prim_ptrs->data;

  if (prim_ptrs && data && entry) {
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
