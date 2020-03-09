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

#include "pmacct.h"
#include "sql_common.h"

void AddToLRUTail(struct db_cache *Cursor)
{
  if (Cursor == lru_tail) return;

  if (Cursor->lru_prev) {
    if (Cursor->lru_next) {
      Cursor->lru_prev->lru_next = Cursor->lru_next;
      Cursor->lru_next->lru_prev = Cursor->lru_prev;
    }
    else Cursor->lru_prev->lru_next = NULL;
  }
  else {
    if (Cursor->lru_next) Cursor->lru_next->lru_prev = NULL;
  }

  Cursor->lru_prev = lru_tail;
  Cursor->lru_prev->lru_next = Cursor;
  Cursor->lru_next = NULL;
  lru_tail = Cursor;
}

void RetireElem(struct db_cache *Cursor)
{
  assert(Cursor->prev);
  assert(Cursor->lru_prev);

  if (Cursor->lru_next) { 
    Cursor->lru_prev->lru_next = Cursor->lru_next;
    Cursor->lru_next->lru_prev = Cursor->lru_prev;
  }
  else {
    /* no lru_next: we are tail! */
    assert(Cursor == lru_tail);

    Cursor->lru_prev->lru_next = NULL;
    lru_tail = Cursor->lru_prev;
  }

  if (Cursor->next) {
    Cursor->prev->next = Cursor->next;
    Cursor->next->prev = Cursor->prev;
  }
  else Cursor->prev->next = NULL;

  if (Cursor->pbgp) free(Cursor->pbgp);
  if (Cursor->pnat) free(Cursor->pnat);
  if (Cursor->pmpls) free(Cursor->pmpls);
  if (Cursor->ptun) free(Cursor->ptun);
  if (Cursor->pcust) free(Cursor->pcust);
  if (Cursor->pvlen) free(Cursor->pvlen);
  if (Cursor->stitch) free(Cursor->stitch);

  free(Cursor);
}

void BuildChain(struct db_cache *Cursor, struct db_cache *newElem)
{
  Cursor->next = newElem;
  newElem->prev = Cursor;
  newElem->chained = TRUE;
}

void ReBuildChain(struct db_cache *Cursor, struct db_cache *newElem)
{
  assert(Cursor != newElem);

  if (newElem->next) {
    newElem->prev->next = newElem->next;
    newElem->next->prev = newElem->prev;
  }
  else newElem->prev->next = NULL;

  Cursor->next = newElem;
  newElem->prev = Cursor;
  newElem->next = NULL;
}

void SwapChainedElems(struct db_cache *Cursor, struct db_cache *staleElem)
{
  struct db_cache *auxPtr;

  assert(Cursor != staleElem);
  assert(Cursor->prev);
  assert(staleElem->prev);

  /* Specific cases first */
  if (Cursor == staleElem->prev) {
    staleElem->prev = Cursor->prev;
    Cursor->next = staleElem->next;
    staleElem->next = Cursor;
    Cursor->prev = staleElem;
    staleElem->prev->next = staleElem;
    if (Cursor->next) Cursor->next->prev = Cursor;
  }
  else if (staleElem == Cursor->prev) {
    Cursor->prev = staleElem->prev;
    staleElem->next = Cursor->next;
    Cursor->next = staleElem;
    staleElem->prev = Cursor;
    Cursor->prev->next = Cursor;
    if (staleElem->next) staleElem->next->prev = staleElem;
  }
  /* General case */
  else {
    auxPtr = Cursor->prev;
    Cursor->prev = staleElem->prev;
    Cursor->prev->next = Cursor;
    staleElem->prev = auxPtr;
    staleElem->prev->next = staleElem; 

    auxPtr = Cursor->next;
    Cursor->next = staleElem->next;
    if (Cursor->next) Cursor->next->prev = Cursor;
    staleElem->next = auxPtr;
    if (staleElem->next) staleElem->next->prev = staleElem;
  }
}

void SQL_SetENV()
{
  char *ptrs[16];
  int count = 0, i;

  INIT_BUF(envbuf);
  memset(ptrs, 0, sizeof(ptrs));

  if (config.sql_db) {
    strncat(envbuf.ptr, "SQL_DB=", (envbuf.end-envbuf.ptr - 1));
    strncat(envbuf.ptr, config.sql_db, envbuf.end-envbuf.ptr);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++; 
  }

  if (config.sql_table) {
    strncat(envbuf.ptr, "SQL_TABLE=", envbuf.end-envbuf.ptr);
    strncat(envbuf.ptr, config.sql_table, envbuf.end-envbuf.ptr);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  if (config.sql_host) {
    strncat(envbuf.ptr, "SQL_HOST=", envbuf.end-envbuf.ptr);
    strncat(envbuf.ptr, config.sql_host, envbuf.end-envbuf.ptr);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  if (config.sql_user) {
    strncat(envbuf.ptr, "SQL_USER=", envbuf.end-envbuf.ptr);
    strncat(envbuf.ptr, config.sql_user, envbuf.end-envbuf.ptr);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  {
    char *tmpptr;

    strncat(envbuf.ptr, "SQL_REFRESH_TIME=", envbuf.end-envbuf.ptr);
    tmpptr = envbuf.ptr + strlen(envbuf.ptr);
    snprintf(tmpptr, envbuf.end-tmpptr, "%d", config.sql_refresh_time);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  if (config.sampling_rate >= 1 || config.ext_sampling_rate >= 1) {
    char *tmpptr;

    strncat(envbuf.ptr, "SAMPLING_RATE=", envbuf.end-envbuf.ptr);
    tmpptr = envbuf.ptr + strlen(envbuf.ptr);
    snprintf(tmpptr, envbuf.end-tmpptr, "%d", config.sampling_rate ? config.sampling_rate : config.ext_sampling_rate);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  if (config.sql_backup_host) {
    strncat(envbuf.ptr, "SQL_RECOVERY_BACKUP_HOST=", envbuf.end-envbuf.ptr);
    strncat(envbuf.ptr, config.sql_backup_host, envbuf.end-envbuf.ptr);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  {
    char *tmpptr;

    strncat(envbuf.ptr, "SQL_MAX_WRITERS=", envbuf.end-envbuf.ptr);
    tmpptr = envbuf.ptr + strlen(envbuf.ptr);
    snprintf(tmpptr, envbuf.end-tmpptr, "%d", dump_writers_get_max());
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  for (i = 0; i < count; i++)
    putenv(ptrs[i]);
}

void SQL_SetENV_child(const struct insert_data *idata)
{
  char *ptrs[N_FUNCS];
  int count = 0, i;

  memset(ptrs, 0, sizeof(ptrs));

  {
    char *tmpptr;

    strncat(envbuf.ptr, "INSERT_QUERIES_NUMBER=", envbuf.end-envbuf.ptr);
    tmpptr = envbuf.ptr + strlen(envbuf.ptr);
    snprintf(tmpptr, envbuf.end-tmpptr, "%d", idata->iqn);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  {
    char *tmpptr;

    strncat(envbuf.ptr, "UPDATE_QUERIES_NUMBER=", envbuf.end-envbuf.ptr);
    tmpptr = envbuf.ptr + strlen(envbuf.ptr);
    snprintf(tmpptr, envbuf.end-tmpptr, "%d", idata->uqn);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  {
    char *tmpptr;

    strncat(envbuf.ptr, "ELAPSED_TIME=", envbuf.end-envbuf.ptr);
    tmpptr = envbuf.ptr + strlen(envbuf.ptr);
    snprintf(tmpptr, envbuf.end-tmpptr, "%lu", idata->elap_time);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  {
    char *tmpptr;

    strncat(envbuf.ptr, "TOTAL_ELEM_NUMBER=", envbuf.end-envbuf.ptr);
    tmpptr = envbuf.ptr + strlen(envbuf.ptr);
    snprintf(tmpptr, envbuf.end-tmpptr, "%d", idata->ten);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  {
    char *tmpptr;

    strncat(envbuf.ptr, "EFFECTIVE_ELEM_NUMBER=", envbuf.end-envbuf.ptr);
    tmpptr = envbuf.ptr + strlen(envbuf.ptr);
    snprintf(tmpptr, envbuf.end-tmpptr, "%u", idata->een);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  if (idata->basetime) {
    char *tmpptr;

    strncat(envbuf.ptr, "SQL_HISTORY_BASETIME=", envbuf.end-envbuf.ptr);
    tmpptr = envbuf.ptr + strlen(envbuf.ptr);
    snprintf(tmpptr, envbuf.end-tmpptr, "%lu", idata->basetime);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  if (idata->timeslot) {
    char *tmpptr;

    strncat(envbuf.ptr, "SQL_HISTORY_TIMESLOT=", envbuf.end-envbuf.ptr);
    tmpptr = envbuf.ptr + strlen(envbuf.ptr);
    snprintf(tmpptr, envbuf.end-tmpptr, "%lu", idata->timeslot);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  if (idata->dyn_table) {
    char *tmpptr;

    strncat(envbuf.ptr, "EFFECTIVE_SQL_TABLE=", envbuf.end-envbuf.ptr);
    tmpptr = envbuf.ptr + strlen(envbuf.ptr);
    pm_strftime(tmpptr, envbuf.end-tmpptr, config.sql_table, &idata->basetime, config.timestamps_utc);
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  {
    char *tmpptr;

    strncat(envbuf.ptr, "SQL_ACTIVE_WRITERS=", envbuf.end-envbuf.ptr);
    tmpptr = envbuf.ptr + strlen(envbuf.ptr);
    snprintf(tmpptr, envbuf.end-tmpptr, "%d", dump_writers_get_active());
    ptrs[count] = envbuf.ptr;
    envbuf.ptr += strlen(envbuf.ptr)+1;
    count++;
  }

  for (i = 0; i < count; i++)
    putenv(ptrs[i]);
}

