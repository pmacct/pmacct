/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2008 by Paolo Lucente
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
  else if (config.what_to_count & COUNT_SUM_STD_COMM) insert_func = sql_sum_std_comm_insert;
  else if (config.what_to_count & COUNT_SUM_EXT_COMM) insert_func = sql_sum_ext_comm_insert;
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
  memset(where, 0, sizeof(where));
  memset(values, 0, sizeof(values));
  memset(set, 0, sizeof(set));
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

void sql_init_default_values()
{
  /* being the first routine to be called by each SQL plugin, this is
     also the place for some initial common configuration consistency
     check */ 
  if ( (config.what_to_count & COUNT_CLASS ||
	config.what_to_count & COUNT_TCPFLAGS ||
	config.nfacctd_sql_log) &&
       config.sql_recovery_logfile) {
    Log(LOG_ERR, "ERROR: sql_recovery_logfile is not compatible with: classifiers, TCP flags and nfacctd_sql_log. Try configuring a backup DB.\n");
    exit_plugin(1);
  }

  if (!config.sql_refresh_time) config.sql_refresh_time = DEFAULT_DB_REFRESH_TIME;
  if (!config.sql_table_version) config.sql_table_version = DEFAULT_SQL_TABLE_VERSION;
  if (!config.sql_cache_entries) config.sql_cache_entries = CACHE_ENTRIES;
  if (!config.sql_max_writers) config.sql_max_writers = DEFAULT_SQL_WRITERS_NO;
  if (config.nfacctd_sql_log && config.acct_type != ACCT_NF) config.nfacctd_sql_log = FALSE; 

  if (config.sql_aggressive_classification) {
    if (config.acct_type == ACCT_PM && config.what_to_count & COUNT_CLASS);
    else config.sql_aggressive_classification = FALSE;
  }

  qq_ptr = 0; 
  pqq_ptr = 0;
  qq_size = config.sql_cache_entries+(config.sql_refresh_time*REASONABLE_NUMBER);
  pp_size = sizeof(struct pkt_primitives);
  pb_size = sizeof(struct pkt_bgp_primitives);
  dbc_size = sizeof(struct db_cache);
  glob_nfacctd_sql_log = config.nfacctd_sql_log;

  memset(&sql_writers, 0, sizeof(sql_writers));

  /* Dirty but allows to save some IFs, centralizes
     checks and makes later comparison statements lean */
  if (!(config.what_to_count & (COUNT_SRC_STD_COMM|COUNT_DST_STD_COMM|COUNT_SUM_STD_COMM|
        COUNT_SRC_EXT_COMM|COUNT_DST_EXT_COMM|COUNT_SUM_EXT_COMM|COUNT_AS_PATH)))
    PbgpSz = 0;
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
    idata->new_basetime = TRUE;
    glob_new_basetime = TRUE;
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

void sql_cache_modulo(struct pkt_primitives *srcdst, struct pkt_bgp_primitives *pbgp, struct insert_data *idata)
{
  idata->hash = cache_crc32((unsigned char *)srcdst, pp_size);
  if (PbgpSz) {
    if (pbgp) idata->hash += cache_crc32((unsigned char *)pbgp, pb_size);
  }
  idata->modulo = idata->hash % config.sql_cache_entries;
}

int sql_cache_flush(struct db_cache *queue[], int index, struct insert_data *idata)
{
  int j, tmp_retired = sql_writers.retired;

  /* If aggressive classification is enabled and there are still
     chances for the stream to be classified - ie. tentatives is
     non-zero - let's leave it in SQL_CACHE_INUSE state */
  if (config.sql_aggressive_classification) {
    for (j = 0, pqq_ptr = 0; j < index; j++) {
      if (!queue[j]->primitives.class && queue[j]->tentatives && (queue[j]->start_tag > (idata->now - ((STALE_M-1) * config.sql_refresh_time))) ) {
        pending_queries_queue[pqq_ptr] = queue[j];
        pqq_ptr++;
      }
      else queue[j]->valid = SQL_CACHE_COMMITTED;
    }
  }
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
    if (sql_writers.active == config.sql_max_writers-1) {
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

struct db_cache *sql_cache_search(struct pkt_primitives *data, struct pkt_bgp_primitives *pbgp, time_t basetime)
{
  unsigned int modulo;
  struct db_cache *Cursor;
  struct insert_data idata;
  int res_data = TRUE, res_bgp = TRUE;

  sql_cache_modulo(data, pbgp, &idata);
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
      if (PbgpSz) {
	if (Cursor->pbgp) res_bgp = memcmp(&Cursor->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
      }
      else res_bgp = FALSE;

      if (!res_data && !res_bgp) {
        /* additional check: time */
        if ((Cursor->basetime < basetime) && (config.sql_history || config.nfacctd_sql_log))
          goto follow_chain;
        else return Cursor;
      }
      else goto follow_chain;
    }
  }

  return NULL;
}

void sql_cache_insert(struct pkt_data *data, struct pkt_bgp_primitives *pbgp, struct insert_data *idata)
{
  unsigned int modulo;
  unsigned long int basetime = idata->basetime, timeslot = idata->timeslot;
  struct pkt_primitives *srcdst = &data->primitives;
  struct db_cache *Cursor, *newElem, *SafePtr = NULL, *staleElem = NULL;

  if (data->time_start && config.sql_history) {
    while (basetime > data->time_start) {
      if (config.sql_history != COUNT_MONTHLY) basetime -= timeslot;
      else {
        timeslot = calc_monthly_timeslot(basetime, config.sql_history_howmany, SUB);
        basetime -= timeslot;
      }
    }
    while ((basetime+timeslot) < data->time_start) {
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
    Cursor = sql_cache_search(&data->primitives, pbgp, basetime);
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

  sql_cache_modulo(&data->primitives, pbgp, idata);
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
          ReBuildChain(Cursor, newElem);
          Cursor = newElem;
          goto insert; /* we have successfully reused a stale element */
        }
        else {
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
      int res_data = TRUE, res_bgp = TRUE;

      /* checks: pkt_primitives and pkt_bgp_primitives */
      res_data = memcmp(&Cursor->primitives, srcdst, sizeof(struct pkt_primitives));

      if (PbgpSz) {
        if (Cursor->pbgp) res_bgp = memcmp(&Cursor->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
      }
      else res_bgp = FALSE;

      if (!res_data && !res_bgp) {
        /* additional check: time */
        if ((Cursor->basetime < basetime) && (config.sql_history || config.nfacctd_sql_log)) {
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
  if (PbgpSz) {
    if (!Cursor->pbgp) Cursor->pbgp = (struct pkt_bgp_primitives *) malloc(PbgpSz);
    memcpy(Cursor->pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
  }
  else Cursor->pbgp = NULL;
  Cursor->packet_counter = data->pkt_num;
  Cursor->flows_counter = data->flo_num;
  Cursor->bytes_counter = data->pkt_len;
  Cursor->tcp_flags = data->tcp_flags;
  if (config.what_to_count & COUNT_CLASS) {
    Cursor->bytes_counter += data->cst.ba;
    Cursor->packet_counter += data->cst.pa;
    Cursor->flows_counter += data->cst.fa;
    Cursor->tentatives = data->cst.tentatives;
  }
  Cursor->valid = SQL_CACHE_INUSE;
  if (!config.nfacctd_sql_log) {
    Cursor->basetime = basetime;
    Cursor->endtime = 0;
  }
  else {
    Cursor->basetime = data->time_start;
    Cursor->endtime = data->time_end;
  }
  Cursor->start_tag = idata->now;
  Cursor->lru_tag = idata->now;
  Cursor->signature = idata->hash;
  if (Cursor->chained) AddToLRUTail(Cursor); /* we cannot reuse not-malloc()'ed elements */
  if (SafePtr) goto safe_action;
  if (staleElem) SwapChainedElems(Cursor, staleElem);
  return;

  update:
  Cursor->packet_counter += data->pkt_num;
  Cursor->flows_counter += data->flo_num;
  Cursor->bytes_counter += data->pkt_len;
  Cursor->tcp_flags |= data->tcp_flags;
  if (config.what_to_count & COUNT_CLASS) {
    Cursor->bytes_counter += data->cst.ba;
    Cursor->packet_counter += data->cst.pa;
    Cursor->flows_counter += data->cst.fa;
    Cursor->tentatives = data->cst.tentatives;
  }
  return;

  safe_action:
  Log(LOG_DEBUG, "DEBUG ( %s/%s ): purging process (CAUSE: safe action)\n", config.name, config.type);

  if (qq_ptr) sql_cache_flush(queries_queue, qq_ptr, idata); 
  switch (fork()) {
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

void sql_sum_host_insert(struct pkt_data *data, struct pkt_bgp_primitives *pbgp, struct insert_data *idata)
{
  struct in_addr ip;
#if defined ENABLE_IPV6
  struct in6_addr ip6;
#endif

  if (data->primitives.dst_ip.family == AF_INET) {
    ip.s_addr = data->primitives.dst_ip.address.ipv4.s_addr;
    data->primitives.dst_ip.address.ipv4.s_addr = 0;
    data->primitives.dst_ip.family = 0;
    sql_cache_insert(data, pbgp, idata);
    data->primitives.src_ip.address.ipv4.s_addr = ip.s_addr;
    sql_cache_insert(data, pbgp, idata);
  }
#if defined ENABLE_IPV6
  if (data->primitives.dst_ip.family == AF_INET6) {
    memcpy(&ip6, &data->primitives.dst_ip.address.ipv6, sizeof(struct in6_addr));
    memset(&data->primitives.dst_ip.address.ipv6, 0, sizeof(struct in6_addr));
    data->primitives.dst_ip.family = 0;
    sql_cache_insert(data, pbgp, idata);
    memcpy(&data->primitives.src_ip.address.ipv6, &ip6, sizeof(struct in6_addr));
    sql_cache_insert(data, pbgp, idata);
    return;
  }
#endif
}

void sql_sum_port_insert(struct pkt_data *data, struct pkt_bgp_primitives *pbgp, struct insert_data *idata)
{
  u_int16_t port;

  port = data->primitives.dst_port;
  data->primitives.dst_port = 0;
  sql_cache_insert(data, pbgp, idata);
  data->primitives.src_port = port;
  sql_cache_insert(data, pbgp, idata);
}

void sql_sum_as_insert(struct pkt_data *data, struct pkt_bgp_primitives *pbgp, struct insert_data *idata)
{
  as_t asn;

  asn = data->primitives.dst_as;
  data->primitives.dst_as = 0;
  sql_cache_insert(data, pbgp, idata);
  data->primitives.src_as = asn;
  sql_cache_insert(data, pbgp, idata);
}

#if defined (HAVE_L2)
void sql_sum_mac_insert(struct pkt_data *data, struct pkt_bgp_primitives *pbgp, struct insert_data *idata)
{
  u_char macaddr[ETH_ADDR_LEN];

  memcpy(macaddr, &data->primitives.eth_dhost, ETH_ADDR_LEN);
  memset(data->primitives.eth_dhost, 0, ETH_ADDR_LEN);
  sql_cache_insert(data, pbgp, idata);
  memcpy(&data->primitives.eth_shost, macaddr, ETH_ADDR_LEN);
  sql_cache_insert(data, pbgp, idata);
}
#endif

void sql_sum_std_comm_insert(struct pkt_data *data, struct pkt_bgp_primitives *pbgp, struct insert_data *idata)
{
}

void sql_sum_ext_comm_insert(struct pkt_data *data, struct pkt_bgp_primitives *pbgp, struct insert_data *idata)
{
}

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
  if (config.sql_backup_host || config.sql_recovery_logfile) idata.recover = TRUE;
  if (config.what_to_count & COUNT_CLASS) config.sql_aggressive_classification = FALSE;

  sql_cache_flush(queries_queue, qq_ptr, &idata);
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
  u_int64_t what_to_count = 0, fakes = 0;
  short int assume_custom_table = FALSE; 
  char *insert_clause_start_ptr = insert_clause + strlen(insert_clause);

  /* SQL tables < v6 multiplex IP addresses and AS numbers on the same field, thus are
     unable to use both them for a same direction (ie. src, dst). Tables v6 break such
     assumption */ 
  if (((config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET|COUNT_SUM_HOST|COUNT_SUM_NET) &&
     config.what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) || (config.what_to_count & COUNT_DST_AS
     && config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET))) && config.sql_table_version < 6) { 
    Log(LOG_ERR, "ERROR ( %s/%s ): SQL tables < v6 are unable to mix IP addresses and AS numbers for the same direction (ie. src, dst).\n", config.name, config.type);
    exit_plugin(1);
  }

  if (config.sql_optimize_clauses) {
    what_to_count = config.what_to_count;
    assume_custom_table = TRUE;
  }
  else {
    /* we are requested to avoid optimization;
       then we'll construct an all-true "what
       to count" bitmap */ 
    if (config.what_to_count & COUNT_SRC_MAC) what_to_count |= COUNT_SRC_MAC;
    else if (config.what_to_count & COUNT_SUM_MAC) what_to_count |= COUNT_SUM_MAC;
    else fakes |= FAKE_SRC_MAC;
    if (config.what_to_count & COUNT_DST_MAC) what_to_count |= COUNT_DST_MAC;
    else fakes |= FAKE_DST_MAC;

    if (config.what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET)) what_to_count |= COUNT_SRC_HOST;
    else if (config.what_to_count & COUNT_SUM_HOST) what_to_count |= COUNT_SUM_HOST;
    else if (config.what_to_count & COUNT_SUM_NET) what_to_count |= COUNT_SUM_NET;
    else fakes |= FAKE_SRC_HOST;

    if (config.sql_table_version < 6) {
      if (config.what_to_count & COUNT_SRC_AS) what_to_count |= COUNT_SRC_AS;
      else if (config.what_to_count & COUNT_SUM_AS) what_to_count |= COUNT_SUM_AS; 
      else fakes |= FAKE_SRC_AS;
    }
    else {
      what_to_count |= COUNT_SRC_AS; 
      if (config.what_to_count & COUNT_SUM_AS) what_to_count |= COUNT_SUM_AS;
    }

    if (config.what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) what_to_count |= COUNT_DST_HOST;
    else fakes |= FAKE_DST_HOST;

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

    if (config.what_to_count & COUNT_SUM_PORT) what_to_count |= COUNT_SUM_PORT;

    what_to_count |= COUNT_SRC_PORT|COUNT_DST_PORT|COUNT_TCPFLAGS|COUNT_IP_PROTO|COUNT_ID|COUNT_CLASS|COUNT_VLAN|COUNT_IP_TOS;
  }

  /* 1st part: arranging pointers to an opaque structure and 
     composing the static selection (WHERE) string */

#if defined (HAVE_L2)
  if (what_to_count & (COUNT_SRC_MAC|COUNT_SUM_MAC)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "mac_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mac_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_MAC;
    values[primitive].handler = where[primitive].handler = count_src_mac_handler;
    primitive++;
  }

  if (what_to_count & COUNT_DST_MAC) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "mac_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mac_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_DST_MAC;
    values[primitive].handler = where[primitive].handler = count_dst_mac_handler;
    primitive++;
  }

  if (what_to_count & COUNT_VLAN) {
    int count_it = FALSE;

    if ((config.sql_table_version < 2) && !assume_custom_table) {
      if (config.what_to_count & COUNT_VLAN) {
        Log(LOG_ERR, "ERROR ( %s/%s ): The use of VLAN accounting requires SQL table v2. Exiting.\n", config.name, config.type);
        exit_plugin(1);
      }
      else what_to_count ^= COUNT_VLAN;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
        strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
      }
      strncat(insert_clause, "vlan", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "vlan=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_VLAN;
      values[primitive].handler = where[primitive].handler = count_vlan_handler;
      primitive++;
    }
  }
#endif

  if (what_to_count & (COUNT_SRC_HOST|COUNT_SRC_NET|COUNT_SUM_HOST|COUNT_SUM_NET)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_SRC_HOST;
    values[primitive].handler = where[primitive].handler = count_src_host_handler;
    primitive++;
  }

  if (what_to_count & (COUNT_DST_HOST|COUNT_DST_NET)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = COUNT_DST_HOST;
    values[primitive].handler = where[primitive].handler = count_dst_host_handler;
    primitive++;
  }

  if (what_to_count & (COUNT_SRC_AS|COUNT_SUM_AS)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
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

  if (what_to_count & COUNT_DST_AS) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
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

  if (what_to_count & (COUNT_SRC_PORT|COUNT_SUM_PORT)) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    if (!strcmp(config.type, "mysql") || !strcmp(config.type, "sqlite3")) {
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

  if (what_to_count & COUNT_DST_PORT) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    if (!strcmp(config.type, "mysql") || !strcmp(config.type, "sqlite3")) {
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

  if (what_to_count & COUNT_TCPFLAGS) {
    int count_it = FALSE;

    if ((config.sql_table_version < 7) && !assume_custom_table) {
      if (config.what_to_count & COUNT_TCPFLAGS) {
        Log(LOG_ERR, "ERROR ( %s/%s ): The use of TCP flags accounting requires SQL table v7. Exiting.\n", config.name, config.type);
	exit_plugin(1);
      }
      else what_to_count ^= COUNT_TCPFLAGS;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
	strncat(insert_clause, ", ", SPACELEFT(insert_clause));
	strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
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

    if ((config.sql_table_version < 3) && !assume_custom_table) {
      if (config.what_to_count & COUNT_IP_TOS) {
        Log(LOG_ERR, "ERROR ( %s/%s ): The use of ToS/DSCP accounting requires SQL table v3. Exiting.\n", config.name, config.type);
        exit_plugin(1);
      }
      else what_to_count ^= COUNT_IP_TOS;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
        strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
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
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_proto", SPACELEFT(insert_clause));
    if (!strcmp(config.type, "sqlite3") || !strcmp(config.type, "mysql")) {
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

  if (what_to_count & COUNT_ID) {
    int count_it = FALSE;

    if ((config.sql_table_version < 2) && !assume_custom_table) {
      if (config.what_to_count & COUNT_ID) {
	Log(LOG_ERR, "ERROR ( %s/%s ): The use of IDs requires SQL table v2. Exiting.\n", config.name, config.type);
        exit_plugin(1);	
      }
      else what_to_count ^= COUNT_ID;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
        strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
      }
      strncat(insert_clause, "agent_id", SPACELEFT(insert_clause));
      strncat(values[primitive].string, "%u", SPACELEFT(values[primitive].string));
      strncat(where[primitive].string, "agent_id=%u", SPACELEFT(where[primitive].string));
      values[primitive].type = where[primitive].type = COUNT_ID;
      values[primitive].handler = where[primitive].handler = count_id_handler;
      primitive++;
    }
  }

  if (what_to_count & COUNT_CLASS) {
    int count_it = FALSE;

    if ((config.sql_table_version < 5) && !assume_custom_table) {
      if (config.what_to_count & COUNT_CLASS) {
        Log(LOG_ERR, "ERROR ( %s/%s ): The use of class_id requires SQL table v5. Exiting.\n", config.name, config.type);
        exit_plugin(1);
      }
      else what_to_count ^= COUNT_CLASS;
    }
    else count_it = TRUE;

    if (count_it) {
      if (primitive) {
        strncat(insert_clause, ", ", SPACELEFT(insert_clause));
        strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
        strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
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
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "mac_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mac_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = FAKE_SRC_MAC;
    values[primitive].handler = where[primitive].handler = fake_mac_handler;
    primitive++;
  }

  if (fakes & FAKE_DST_MAC) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "mac_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "mac_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = FAKE_DST_MAC;
    values[primitive].handler = where[primitive].handler = fake_mac_handler;
    primitive++;
  }
#endif

  if (fakes & FAKE_SRC_HOST) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_src", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_src=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = FAKE_SRC_HOST;
    values[primitive].handler = where[primitive].handler = fake_host_handler;
    primitive++;
  }

  if (fakes & FAKE_DST_HOST) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    strncat(insert_clause, "ip_dst", SPACELEFT(insert_clause));
    strncat(values[primitive].string, "\'%s\'", SPACELEFT(values[primitive].string));
    strncat(where[primitive].string, "ip_dst=\'%s\'", SPACELEFT(where[primitive].string));
    values[primitive].type = where[primitive].type = FAKE_DST_HOST;
    values[primitive].handler = where[primitive].handler = fake_host_handler;
    primitive++;
  }

  if (fakes & FAKE_SRC_AS) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
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
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
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
        if (config.sql_table_schema && idata->new_basetime) sql_create_table(bed->b, idata);
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

  file_open:
  f = fopen(path, "a+");
  if (f) {
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

        nowtm = localtime(&idata->basetime);
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
      fread(&lh, sizeof(lh), 1, f);
      if (ntohl(lh.magic) != MAGIC) {
        Log(LOG_ALERT, "ALERT ( %s/%s ): Invalid magic number: '%s'.\n", config.name, config.type, path);
        goto close;
      }
      fread(&tth, sizeof(tth), 1, f);
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

void sql_create_table(struct DBdesc *db, struct insert_data *idata)
{
  struct tm *nowtm;
  char buf[LONGLONGSRVBUFLEN], tmpbuf[LONGLONGSRVBUFLEN];
  int ret;

  ret = read_SQLquery_from_file(config.sql_table_schema, tmpbuf, LONGLONGSRVBUFLEN);
  if (ret) {
    nowtm = localtime(&idata->basetime);
    strftime(buf, LONGLONGSRVBUFLEN, tmpbuf, nowtm);
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
