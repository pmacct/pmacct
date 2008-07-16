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

#define __SQLITE3_PLUGIN_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "sql_common.h"
#include "sqlite3_plugin.h"
#include "sql_common_m.c"

/* Functions */
void sqlite3_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr) 
{
  struct pkt_data *data;
  struct ports_table pt;
  struct pollfd pfd;
  struct insert_data idata;
  struct timezone tz;
  time_t now, refresh_deadline;
  int timeout;
  int ret, num;
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;

  unsigned char *rgptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0; 

  /* XXX: glue */
  memcpy(&config, cfgptr, sizeof(struct configuration));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "SQLite3 Plugin", config.name);
  memset(&idata, 0, sizeof(idata));
  if (config.pidfile) write_pid_file_plugin(config.pidfile, config.type, config.name);

  sql_set_signals();
  sql_init_default_values();
  SQLI_init_default_values(&idata);
  SQLI_set_callbacks(&sqlfunc_cbr);
  sql_set_insert_func();

  /* some LOCAL initialization AFTER setting some default values */
  reload_map = FALSE;
  timeout = config.sql_refresh_time*1000; /* dirty */
  now = time(NULL);
  refresh_deadline = now;

  sql_init_maps(&nt, &nc, &pt);
  sql_init_global_buffers();
  sql_init_pipe(&pfd, pipe_fd);
  sql_init_historical_acct(now, &idata);
  sql_init_triggers(now, &idata);
  sql_init_refresh_deadline(&refresh_deadline);

  /* setting number of entries in _protocols structure */
  while (_protocols[protocols_number].number != -1) protocols_number++;

  /* building up static SQL clauses */
  idata.num_primitives = SQLI_compose_static_queries();
  glob_num_primitives = idata.num_primitives; 

  /* handling purge preprocessor */
  set_preprocess_funcs(config.sql_preprocess, &prep); 

  /* setting up environment variables */
  SQL_SetENV();

  sql_link_backend_descriptors(&bed, &p, &b);

  /* plugin main loop */
  for(;;) {
    poll_again:
    status->wakeup = TRUE;
    ret = poll(&pfd, 1, timeout);
    if (ret < 0) goto poll_again;

    idata.now = time(NULL);

    switch (ret) {
    case 0: /* timeout */
      if (qq_ptr) sql_cache_flush(queries_queue, qq_ptr, &idata);
      switch (fork()) {
      case 0: /* Child */
	/* we have to ignore signals to avoid loops:
	   because we are already forked */
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	pm_setproctitle("%s [%s]", "SQLite3 Plugin -- DB Writer", config.name);

        if (qq_ptr && sql_writers.flags != CHLD_ALERT) {
	  if (sql_writers.flags == CHLD_WARNING) sql_db_fail(&p);
          (*sqlfunc_cbr.connect)(&p, NULL); 
          (*sqlfunc_cbr.purge)(queries_queue, qq_ptr, &idata);
	  (*sqlfunc_cbr.close)(&bed);
	}

	if (config.sql_trigger_exec) {
	  if (idata.now > idata.triggertime) sql_trigger_exec(config.sql_trigger_exec);
	}
	  
        exit(0);
      default: /* Parent */
	gettimeofday(&idata.flushtime, &tz);
	refresh_deadline += config.sql_refresh_time; 
	if (idata.now > idata.triggertime) {
	  idata.triggertime  += idata.t_timeslot;
	  if (config.sql_trigger_time == COUNT_MONTHLY)
	    idata.t_timeslot = calc_monthly_timeslot(idata.triggertime, config.sql_trigger_time_howmany, ADD);
	}
	idata.new_basetime = FALSE;
	glob_new_basetime = FALSE;
	qq_ptr = pqq_ptr;
	memcpy(queries_queue, pending_queries_queue, sizeof(queries_queue));

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
	idata.now = time(NULL); 
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

      /* lazy sql refresh handling */ 
      if (idata.now > refresh_deadline) {
        if (qq_ptr) sql_cache_flush(queries_queue, qq_ptr, &idata);
        switch (fork()) {
        case 0: /* Child */
          /* we have to ignore signals to avoid loops:
             because we are already forked */
          signal(SIGINT, SIG_IGN);
          signal(SIGHUP, SIG_IGN);
	  pm_setproctitle("%s [%s]", "SQLite3 Plugin -- DB Writer", config.name);

          if (qq_ptr && sql_writers.flags != CHLD_ALERT) {
	    if (sql_writers.flags == CHLD_WARNING) sql_db_fail(&p);
            (*sqlfunc_cbr.connect)(&p, NULL);
            (*sqlfunc_cbr.purge)(queries_queue, qq_ptr, &idata);
	    (*sqlfunc_cbr.close)(&bed);
	  }

	  if (config.sql_trigger_exec) {
	    if (idata.now > idata.triggertime) sql_trigger_exec(config.sql_trigger_exec);
	  }

          exit(0);
        default: /* Parent */
	  gettimeofday(&idata.flushtime, &tz);
	  refresh_deadline += config.sql_refresh_time; 
          if (idata.now > idata.triggertime) {
	    idata.triggertime  += idata.t_timeslot;
	    if (config.sql_trigger_time == COUNT_MONTHLY)
	      idata.t_timeslot = calc_monthly_timeslot(idata.triggertime, config.sql_trigger_time_howmany, ADD);
	  }
	  idata.new_basetime = FALSE;
	  glob_new_basetime = FALSE;
	  qq_ptr = pqq_ptr;
	  memcpy(queries_queue, pending_queries_queue, sizeof(queries_queue));

	  if (reload_map) {
	    load_networks(config.networks_file, &nt, &nc);
	    load_ports(config.ports_file, &pt);
	    reload_map = FALSE;
	  }
          break;
        }
      } 
      else {
	if (config.sql_trigger_exec) {
	  if (idata.now > idata.triggertime) {
	    sql_trigger_exec(config.sql_trigger_exec); 
	    idata.triggertime += idata.t_timeslot;
	    if (config.sql_trigger_time == COUNT_MONTHLY)
	      idata.t_timeslot = calc_monthly_timeslot(idata.triggertime, config.sql_trigger_time_howmany, ADD);
	  }
	}
      }

      data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));
      if (idata.now > (idata.basetime + idata.timeslot)) {
	idata.basetime += idata.timeslot;
	if (config.sql_history == COUNT_MONTHLY)
	  idata.timeslot = calc_monthly_timeslot(idata.basetime, config.sql_history_howmany, ADD);
	glob_basetime = idata.basetime;
	idata.new_basetime = TRUE;
	glob_new_basetime = TRUE;
      }

      while (((struct ch_buf_hdr *)pipebuf)->num) {
	for (num = 0; net_funcs[num]; num++)
	  (*net_funcs[num])(&nt, &nc, &data->primitives);

	if (config.ports_file) {
	  if (!pt.table[data->primitives.src_port]) data->primitives.src_port = 0;
	  if (!pt.table[data->primitives.dst_port]) data->primitives.dst_port = 0;
	}

	(*insert_func)(data, &idata);
	
	((struct ch_buf_hdr *)pipebuf)->num--;
        if (((struct ch_buf_hdr *)pipebuf)->num) data++;
      }
      goto read_data;
    }
  }
}

int SQLI_cache_dbop(struct DBdesc *db, struct db_cache *cache_elem, struct insert_data *idata)
{
  char *ptr_values, *ptr_where, *ptr_mv, *ptr_set;
  int num=0, ret=0, have_flows=0, len=0;

  if (idata->mv.last_queue_elem) {
    ret = sqlite3_exec(db->desc, multi_values_buffer, NULL, NULL, NULL);
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): %d INSERT statements sent to the SQLite database.\n",
                config.name, config.type, idata->mv.buffer_elem_num);
    if (ret) goto signal_error;
    idata->iqn++;
    idata->mv.buffer_elem_num = FALSE;
    idata->mv.buffer_offset = 0;

    return FALSE;
  }
  
  if (config.what_to_count & COUNT_FLOWS) have_flows = TRUE;

  /* constructing sql query */
  ptr_where = where_clause;
  ptr_values = values_clause; 
  ptr_set = set_clause;
  memset(where_clause, 0, sizeof(where_clause));
  memset(values_clause, 0, sizeof(values_clause));
  memset(set_clause, 0, sizeof(set_clause));

  for (num = 0; num < idata->num_primitives; num++)
    (*where[num].handler)(cache_elem, idata, num, &ptr_values, &ptr_where);

  for (num = 0; set[num].type; num++)
    (*set[num].handler)(cache_elem, idata, num, &ptr_set, NULL);
  
  /* sending UPDATE query */
  if (!config.sql_dont_try_update) {
    strncpy(sql_data, update_clause, SPACELEFT(sql_data));
    strncat(sql_data, set_clause, SPACELEFT(sql_data));
    strncat(sql_data, where_clause, SPACELEFT(sql_data));

    ret = sqlite3_exec(db->desc, sql_data, NULL, NULL, NULL);
    if (ret) goto signal_error; 
  }

  if (config.sql_dont_try_update || (sqlite3_changes(db->desc) == 0)) {
    /* UPDATE failed, trying with an INSERT query */ 
#if defined HAVE_64BIT_COUNTERS
    if (have_flows) snprintf(ptr_values, SPACELEFT(values_clause), ", %llu, %llu, %llu)", cache_elem->packet_counter, cache_elem->bytes_counter, cache_elem->flows_counter);
    else snprintf(ptr_values, SPACELEFT(values_clause), ", %llu, %llu)", cache_elem->packet_counter, cache_elem->bytes_counter);
#else
    if (have_flows) snprintf(ptr_values, SPACELEFT(values_clause), ", %lu, %lu, %lu)", cache_elem->packet_counter, cache_elem->bytes_counter, cache_elem->flows_counter);
    else snprintf(ptr_values, SPACELEFT(values_clause), ", %lu, %lu)", cache_elem->packet_counter, cache_elem->bytes_counter);
#endif
    
    strncpy(sql_data, insert_clause, sizeof(sql_data));
    strncat(sql_data, values_clause, SPACELEFT(sql_data));

    if (config.sql_multi_values) {
      multi_values_handling:
      len = config.sql_multi_values-idata->mv.buffer_offset;
      if (strlen(values_clause) < len) {
	if (idata->mv.buffer_elem_num) {
	  strcpy(multi_values_buffer+idata->mv.buffer_offset, "; ");
	  idata->mv.buffer_offset++;
	  idata->mv.buffer_offset++;
	}
	ptr_mv = multi_values_buffer+idata->mv.buffer_offset;
	strcpy(multi_values_buffer+idata->mv.buffer_offset, sql_data); 
	idata->mv.buffer_offset += strlen(ptr_mv);
        idata->mv.buffer_elem_num++;
      }
      else {
	if (idata->mv.buffer_elem_num) {
	  ret = sqlite3_exec(db->desc, multi_values_buffer, NULL, NULL, NULL);
	  Log(LOG_DEBUG, "DEBUG ( %s/%s ): %d INSERT statements sent to the SQLite database.\n",
		config.name, config.type, idata->mv.buffer_elem_num);
	  if (ret) goto signal_error;
	  idata->iqn++;
	  idata->mv.buffer_elem_num = FALSE;
	  idata->mv.head_buffer_elem = FALSE;
	  idata->mv.buffer_offset = 0;
	  goto multi_values_handling;
	}
	else {
	  Log(LOG_ERR, "ERROR ( %s/%s ): 'sql_multi_values' is too small (%d). Try with a larger value.\n",
	  config.name, config.type, config.sql_multi_values);
	  exit_plugin(1);
	}
      }
    }
    else {
      ret = sqlite3_exec(db->desc, sql_data, NULL, NULL, NULL);
      Log(LOG_DEBUG, "( %s/%s ): %s\n\n", config.name, config.type, sql_data);
      if (ret) goto signal_error; 
      idata->iqn++;
    }
  }
  else {
    Log(LOG_DEBUG, "( %s/%s ): %s\n\n", config.name, config.type, sql_data);
    idata->uqn++;
  }

  idata->een++;
  // cache_elem->valid = FALSE; /* committed */
  
  return ret;

  signal_error:
  if (!idata->mv.buffer_elem_num) Log(LOG_DEBUG, "DEBUG ( %s/%s ): FAILED query follows:\n%s\n", config.name, config.type, sql_data); 
  else {
    if (!idata->recover || db->type != BE_TYPE_PRIMARY) {
      /* DB failure: we will rewind the multi-values buffer */
      idata->current_queue_elem = idata->mv.head_buffer_elem;
      idata->mv.buffer_elem_num = 0;
    } 
  }
  SQLI_get_errmsg(db);
  if (db->errmsg) Log(LOG_ERR, "ERROR ( %s/%s ): %s\n\n", config.name, config.type, db->errmsg);

  return ret;
}

void SQLI_cache_purge(struct db_cache *queue[], int index, struct insert_data *idata)
{
  time_t start;
  int j, stop, ret;

  for (j = 0, stop = 0; (!stop) && preprocess_funcs[j]; j++)
    stop = preprocess_funcs[j](queue, &index); 
  if (config.what_to_count & COUNT_CLASS)
    sql_invalidate_shadow_entries(queue, &index);
  idata->ten = index;

  if (config.debug) {
    Log(LOG_DEBUG, "( %s/%s ) *** Purging cache - START ***\n", config.name, config.type);
    start = time(NULL);
  }

  /* We check for variable substitution in SQL table */ 
  if (idata->dyn_table) {
    char tmpbuf[LONGLONGSRVBUFLEN];

    strftime_same(insert_clause, LONGSRVBUFLEN, tmpbuf, &idata->basetime);
    strftime_same(update_clause, LONGSRVBUFLEN, tmpbuf, &idata->basetime);
    strftime_same(lock_clause, LONGSRVBUFLEN, tmpbuf, &idata->basetime);
    if (config.sql_table_schema && idata->new_basetime) sql_create_table(bed.p, idata);
  }
  // strncat(update_clause, set_clause, SPACELEFT(update_clause));

  (*sqlfunc_cbr.lock)(bed.p); 

  for (idata->current_queue_elem = 0; idata->current_queue_elem < index; idata->current_queue_elem++) {
    if (queue[idata->current_queue_elem]->valid) sql_query(&bed, queue[idata->current_queue_elem], idata);
  }

  /* multi-value INSERT query: wrap-up */
  if (idata->mv.buffer_elem_num) {
    idata->mv.last_queue_elem = TRUE;
    queue[idata->current_queue_elem-1]->valid = SQL_CACHE_COMMITTED;
    sql_query(&bed, queue[idata->current_queue_elem-1], idata);
  }
  
  /* rewinding stuff */
  (*sqlfunc_cbr.unlock)(&bed);
  if (b.fail) Log(LOG_ALERT, "ALERT ( %s/%s ): recovery for SQLite3 daemon failed.\n", config.name, config.type);
  
  if (config.debug) {
    idata->elap_time = time(NULL)-start; 
    Log(LOG_DEBUG, "( %s/%s ) *** Purging cache - END (QN: %u, ET: %u) ***\n", 
		    config.name, config.type, idata->qn, idata->elap_time); 
  }

  if (config.sql_trigger_exec) {
    if (!config.debug) idata->elap_time = time(NULL)-start;
    SQL_SetENV_child(idata);
  }
}

int SQLI_evaluate_history(int primitive)
{
  if (config.sql_history || config.nfacctd_sql_log) {
    if (primitive) {
      strncat(insert_clause, ", ", SPACELEFT(insert_clause));
      strncat(values[primitive].string, ", ", sizeof(values[primitive].string));
      strncat(where[primitive].string, " AND ", sizeof(where[primitive].string));
    }
    if (!config.sql_history_since_epoch)
      strncat(where[primitive].string, "DATETIME(%u, 'unixepoch', 'localtime') = ", SPACELEFT(where[primitive].string));
    else
      strncat(where[primitive].string, "%u = ", SPACELEFT(where[primitive].string));
    strncat(where[primitive].string, "stamp_inserted", SPACELEFT(where[primitive].string));

    strncat(insert_clause, "stamp_updated, stamp_inserted", SPACELEFT(insert_clause));
    if (!config.sql_history_since_epoch)
      strncat(values[primitive].string, "DATETIME(%u, 'unixepoch', 'localtime'), DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(values[primitive].string));
    else
      strncat(values[primitive].string, "%u, %u", SPACELEFT(values[primitive].string));

    where[primitive].type = values[primitive].type = TIMESTAMP;
    values[primitive].handler = where[primitive].handler = count_timestamp_handler;
    primitive++;
  }

  return primitive;
}

int SQLI_compose_static_queries()
{
  int primitives=0, set_primitives=0, have_flows=0;

  if (config.what_to_count & COUNT_FLOWS || (config.sql_table_version >= 4 && !config.sql_optimize_clauses)) {
    config.what_to_count |= COUNT_FLOWS;
    have_flows = TRUE;

    if (config.sql_table_version < 4 && !config.sql_optimize_clauses) {
      Log(LOG_ERR, "ERROR ( %s/%s ): The accounting of flows requires SQL table v4. Exiting.\n", config.name, config.type);
      exit_plugin(1);
    }
  }

  /* "INSERT INTO ... VALUES ... " and "... WHERE ..." stuff */
  strncpy(where[primitives].string, " WHERE ", sizeof(where[primitives].string));
  snprintf(insert_clause, sizeof(insert_clause), "INSERT INTO %s (", config.sql_table);
  strncpy(values[primitives].string, " VALUES (", sizeof(values[primitives].string));
  primitives = SQLI_evaluate_history(primitives);
  primitives = sql_evaluate_primitives(primitives);
  strncat(insert_clause, ", packets, bytes", SPACELEFT(insert_clause));
  if (have_flows) strncat(insert_clause, ", flows", SPACELEFT(insert_clause));
  strncat(insert_clause, ")", SPACELEFT(insert_clause));

  /* "LOCK ..." stuff */
  if (config.sql_locking_style) Log(LOG_WARNING, "WARN ( %s/%s ): sql_locking_style is not supported. Ignored.\n", config.name, config.type);
  snprintf(lock_clause, sizeof(lock_clause), "BEGIN", config.sql_table);
  strncpy(unlock_clause, "COMMIT", sizeof(unlock_clause));

  /* "UPDATE ... SET ..." stuff */
  snprintf(update_clause, sizeof(update_clause), "UPDATE %s ", config.sql_table);

  set_primitives = sql_compose_static_set(have_flows);

  if (config.sql_history || config.nfacctd_sql_log) {
    if (!config.nfacctd_sql_log) {
      if (!config.sql_history_since_epoch) {
	strncpy(set[set_primitives].string, ", ", SPACELEFT(set[set_primitives].string));
	strncat(set[set_primitives].string, "stamp_updated=DATETIME('now', 'localtime')", SPACELEFT(set[set_primitives].string));
	set[set_primitives].type = TIMESTAMP;
	set[set_primitives].handler = count_noop_setclause_handler;
	set_primitives++;
      }
      else {
	strncpy(set[set_primitives].string, ", ", SPACELEFT(set[set_primitives].string));
	strncat(set[set_primitives].string, "stamp_updated=STRFTIME('%%s', 'now')", SPACELEFT(set[set_primitives].string));
	set[set_primitives].type = TIMESTAMP;
	set[set_primitives].handler = count_noop_setclause_handler;
	set_primitives++;
      }
    }
    else {
      if (!config.sql_history_since_epoch) {
	strncpy(set[set_primitives].string, ", ", SPACELEFT(set[set_primitives].string));
	strncat(set[set_primitives].string, "stamp_updated=DATETIME(%u, 'unixepoch', 'localtime')", SPACELEFT(set[set_primitives].string));
	set[set_primitives].type = TIMESTAMP;
	set[set_primitives].handler = count_timestamp_setclause_handler;
	set_primitives++;
      }
      else {
	strncpy(set[set_primitives].string, ", ", SPACELEFT(set[set_primitives].string));
	strncat(set[set_primitives].string, "stamp_updated=%u", SPACELEFT(set[set_primitives].string));
	set[set_primitives].type = TIMESTAMP;
	set[set_primitives].handler = count_timestamp_setclause_handler;
	set_primitives++;
      }
    }
  }

  return primitives;
}

void SQLI_Lock(struct DBdesc *db)
{
  if (!db->fail) {
    if (sqlite3_exec(db->desc, lock_clause, NULL, NULL, NULL)) {
      SQLI_get_errmsg(db);
      sql_db_errmsg(db);
      sql_db_fail(db);
    }
  }
}

void SQLI_Unlock(struct BE_descs *bed)
{
  if (bed->p->connected) sqlite3_exec(bed->p->desc, unlock_clause, NULL, NULL, NULL);
  if (bed->b->connected) sqlite3_exec(bed->b->desc, unlock_clause, NULL, NULL, NULL);
}

void SQLI_DB_Connect(struct DBdesc *db, char *host)
{
  if (!db->fail) {
    if (sqlite3_open(db->filename, (sqlite3 **)&db->desc)) {
      sql_db_fail(db);
      SQLI_get_errmsg(db);
      sql_db_errmsg(db);
    }
    else sql_db_ok(db);
  }
}

void SQLI_DB_Close(struct BE_descs *bed)
{
  if (bed->p->connected) sqlite3_close(bed->p->desc);
  if (bed->b->connected) sqlite3_close(bed->b->desc);
}

void SQLI_create_dyn_table(struct DBdesc *db, char *buf)
{
  if (!db->fail) {
    if (sqlite3_exec(db->desc, buf, NULL, NULL, NULL)) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): FAILED query follows:\n%s\n", config.name, config.type, buf);
      SQLI_get_errmsg(db);
      sql_db_errmsg(db);
    }
  }
}

void SQLI_get_errmsg(struct DBdesc *db)
{
  db->errmsg = (char *) sqlite3_errmsg(db->desc);
} 

void SQLI_create_backend(struct DBdesc *db)
{
  if (db->type == BE_TYPE_PRIMARY) db->filename = config.sql_db; 
  if (db->type == BE_TYPE_BACKUP) db->filename = config.sql_backup_host; 
}

void SQLI_set_callbacks(struct sqlfunc_cb_registry *cbr)
{
  memset(cbr, 0, sizeof(struct sqlfunc_cb_registry));

  cbr->connect = SQLI_DB_Connect;
  cbr->close = SQLI_DB_Close;
  cbr->lock = SQLI_Lock;
  cbr->unlock = SQLI_Unlock;
  cbr->op = SQLI_cache_dbop;
  cbr->create_table = SQLI_create_dyn_table; 
  cbr->purge = SQLI_cache_purge;
  cbr->create_backend = SQLI_create_backend;
}

void SQLI_init_default_values(struct insert_data *idata)
{
  config.sql_recovery_logfile = FALSE; /* not supported */

  /* Linking database parameters */
  if (!config.sql_db) config.sql_db = sqlite3_db;
  if (!config.sql_table) {
    if (config.sql_table_version == 7) config.sql_table = sqlite3_table_v7;
    else if (config.sql_table_version == 6) config.sql_table = sqlite3_table_v6;
    else if (config.sql_table_version == 5) config.sql_table = sqlite3_table_v5;
    else if (config.sql_table_version == 4) config.sql_table = sqlite3_table_v4;
    else if (config.sql_table_version == 3) config.sql_table = sqlite3_table_v3;
    else if (config.sql_table_version == 2) config.sql_table = sqlite3_table_v2;
    else config.sql_table = sqlite3_table;
  }
  if (strchr(config.sql_table, '%')) idata->dyn_table = TRUE;
  glob_dyn_table = idata->dyn_table;
  
  if (config.sql_backup_host) idata->recover = TRUE;

  if (config.sql_multi_values) {
    multi_values_buffer = malloc(config.sql_multi_values);
    if (!multi_values_buffer) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Unable to get enough room (%d) for multi value queries.\n",
		config.name, config.type, config.sql_multi_values);
      config.sql_multi_values = FALSE;
    }
    memset(multi_values_buffer, 0, config.sql_multi_values);
  }

  if (config.sql_locking_style) idata->locks = sql_select_locking_style(config.sql_locking_style);
}
