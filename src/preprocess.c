/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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
#include "pmacct-data.h"
#include "plugin_common.h"
#include "sql_common.h"
#include "preprocess.h"
#include "preprocess-data.h"
#include "preprocess-internal.h"

//Global variables
sql_preprocess_func sql_preprocess_funcs[2*N_FUNCS]; /* 20 */
P_preprocess_func P_preprocess_funcs[2*N_FUNCS]; /* 20 */
struct preprocess prep;
struct _fsrc_queue fsrc_queue;


void set_preprocess_funcs(char *string, struct preprocess *prep, int dictionary)
{
  char *token, *sep, *key, *value;
  int dindex, err = 0, sql_idx = 0, p_idx = 0;

  memset(sql_preprocess_funcs, 0, sizeof(sql_preprocess_funcs));
  memset(P_preprocess_funcs, 0, sizeof(P_preprocess_funcs));
  memset(prep, 0, sizeof(struct preprocess));

  if (!string) return;

  trim_all_spaces(string);

  while ((token = extract_token(&string, ','))) {
    sep = strchr(token, '=');
    if (!sep) {
      Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: malformed input string. Ignored.\n", config.name, config.type);
      return; 
    }
    else {
      key = token;
      *sep = '\0';
      value = sep+1;
      lower_string(key);
    }

    /* validation against dictionaries */
    if (dictionary == PREP_DICT_SQL) {
      for (dindex = 0; strcmp(sql_prep_dict[dindex].key, ""); dindex++) {
        if (!strcmp(sql_prep_dict[dindex].key, key)) {
          err = FALSE;
          break;
        }
        else err = E_NOTFOUND; /* key not found */
      }
    }
    else if (dictionary == PREP_DICT_PRINT) {
      for (dindex = 0; strcmp(print_prep_dict[dindex].key, ""); dindex++) {
        if (!strcmp(print_prep_dict[dindex].key, key)) {
          err = FALSE;
          break;      
        }           
        else err = E_NOTFOUND; /* key not found */
      }
    }

    if (err == E_NOTFOUND) {
      Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: unknown keyword %s. Ignored.\n", config.name, config.type, key);
      continue;
    }

    if (!strcmp(key, "qnum")) {
      prep->qnum = atoi(value);
      if (!prep->qnum) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'qnum' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minp")) {
      prep->minp = atoi(value);
      if (!prep->minp) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'minp' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minf")) {
      prep->minf = atoi(value);
      if (!prep->minf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'minf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minb")) {
      prep->minb = atoi(value);
      if (!prep->minb) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'minb' value.\n", config.name, config.type);
    }

    else if (!strcmp(key, "maxp")) {
      prep->maxp = atoi(value);
      if (!prep->maxp) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'maxp' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "maxf")) {
      prep->maxf = atoi(value);
      if (!prep->maxf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'maxf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "maxb")) {
      prep->maxb = atoi(value);
      if (!prep->maxb) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'maxb' value.\n", config.name, config.type);
    }

    else if (!strcmp(key, "maxbpp")) {
      prep->maxbpp = atoi(value);
      if (!prep->maxbpp) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'maxbpp' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "maxppf")) {
      prep->maxppf = atoi(value);
      if (!prep->maxppf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'maxppf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minbpp")) {
      prep->minbpp = atoi(value);
      if (!prep->minbpp) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'minbpp' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minppf")) {
      prep->minppf = atoi(value);
      if (!prep->minppf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'minppf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "fss")) {
      prep->fss = atoi(value);
      if (!prep->fss) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'fss' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "fsrc")) {
      prep->fsrc = atoi(value);
      if (!prep->fsrc) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'fsrc' value.\n", config.name, config.type);
      else {
	fsrc_queue.num = 0;
	memset(&fsrc_queue.head, 0, sizeof(struct fsrc_queue_elem)); 
      }
    }
    else if (!strcmp(key, "usrf")) {
      prep->usrf = atoi(value);
      if (!prep->usrf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'usrf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "adjb")) {
      prep->adjb = atoi(value);
      if (!prep->adjb) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'adjb' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "recover")) {
      prep->recover = atoi(value);
      if (!prep->recover) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: invalid 'recover' value.\n", config.name, config.type);
    }
    else Log(LOG_ERR, "ERROR ( %s/%s ): preprocess: invalid key: '%s'. Ignored.\n", config.name, config.type, key);
  }

  /* Post checks: almost one check should have been specified */
  if ((!prep->minp) && (!prep->minb) && (!prep->minf) &&
      (!prep->maxp) && (!prep->maxb) && (!prep->maxf) &&
      (!prep->maxbpp) && (!prep->maxppf) && (!prep->minbpp) &&
      (!prep->minppf) && (!prep->fss) && (!prep->fsrc) &&
      (!prep->usrf) && (!prep->adjb)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): preprocess: does not contain any checks. Ignored.\n", config.name, config.type); 
    return;
  } 

  /* 1st step: insert conditionals */
  if (prep->qnum) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = cond_qnum;
      sql_idx++;
    }
  }

  /* 2nd step: invalidation of committed cache entries - if at
     least one check was specified; each check will selectively
     re-validate entries that pass tests successfully */
  if (dictionary == PREP_DICT_SQL) {
    sql_preprocess_funcs[sql_idx] = mandatory_invalidate;
    sql_idx++;
  }
  else if (dictionary == PREP_DICT_PRINT) {
    P_preprocess_funcs[p_idx] = P_mandatory_invalidate;
    p_idx++;
  }

  /* 3rd step: insert checks */
  if (prep->minp) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = check_minp;
      prep->num++;
      sql_idx++;
      prep->checkno++;
    }
    else if (dictionary == PREP_DICT_PRINT) {
      P_preprocess_funcs[p_idx] = P_check_minp;
      prep->num++;
      p_idx++;
      prep->checkno++;
    }
  }

  if (prep->minf) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = check_minf;
      prep->num++;
      sql_idx++;
      prep->checkno++;
    }
    else if (dictionary == PREP_DICT_PRINT) {
      P_preprocess_funcs[p_idx] = P_check_minf;
      prep->num++;
      p_idx++;
      prep->checkno++;
    }
  }

  if (prep->minb) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = check_minb;
      prep->num++;
      sql_idx++;
      prep->checkno++;
    }
    else if (dictionary == PREP_DICT_PRINT) {
      P_preprocess_funcs[p_idx] = P_check_minb;
      prep->num++;
      p_idx++;
      prep->checkno++;
    }
  }

  if (prep->maxp) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = check_maxp;
      prep->num++;
      sql_idx++;
      prep->checkno++;
    }
  }

  if (prep->maxf) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = check_maxf;
      prep->num++;
      sql_idx++;
      prep->checkno++;
    }
  }

  if (prep->maxb) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = check_maxb;
      prep->num++;
      sql_idx++;
      prep->checkno++;
    }
  }

  if (prep->maxbpp) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = check_maxbpp;
      prep->num++;
      sql_idx++;
      prep->checkno++;
    }
  }

  if (prep->maxppf) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = check_maxppf;
      prep->num++;
      sql_idx++;
      prep->checkno++;
    }
  }

  if (prep->minbpp) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = check_minbpp;
      prep->num++;
      sql_idx++;
      prep->checkno++;
    }
    else if (dictionary == PREP_DICT_PRINT) {
      P_preprocess_funcs[p_idx] = P_check_minbpp;
      prep->num++;
      p_idx++;
      prep->checkno++;
    }
  }

  if (prep->minppf) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = check_minppf;
      prep->num++;
      sql_idx++;
      prep->checkno++;
    }
    else if (dictionary == PREP_DICT_PRINT) {
      P_preprocess_funcs[p_idx] = P_check_minppf;
      prep->num++;
      p_idx++;
      prep->checkno++;
    }
  }

  if (prep->fss) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = check_fss;
      prep->num++;
      sql_idx++;
      prep->checkno++;
    }
  }

  if (prep->fsrc) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = check_fsrc;
      prep->num++;
      sql_idx++;
      prep->checkno++;
    }
  }

  if (prep->usrf) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = action_usrf;
      prep->num++;
      sql_idx++;
      prep->actionno++;
    }
  }

  if (prep->adjb) {
    if (dictionary == PREP_DICT_SQL) {
      sql_preprocess_funcs[sql_idx] = action_adjb;
      prep->num++;
      sql_idx++;
      prep->actionno++;
    }
  }

  /* 
     4th and final step: check points:
     - if in 'any' mode, any entry with 'points >= 1' is valid
     - if in 'all' mode, any entry with 'points == number of conditions' is valid 
  */
  if (dictionary == PREP_DICT_SQL) {
    sql_preprocess_funcs[sql_idx] = mandatory_validate;
    sql_idx++;
  }
}

void check_validity(struct db_cache *entry, int seq)
{
  if (config.sql_preprocess_type == 0) {
    if (entry->prep_valid > 0 && entry->valid == SQL_CACHE_INVALID)
      entry->valid = SQL_CACHE_COMMITTED;
  }
  else {
    if (entry->prep_valid == seq) entry->valid = SQL_CACHE_COMMITTED;
    else entry->valid = SQL_CACHE_FREE;
  }
}

int cond_qnum(struct db_cache *queue[], int *num, int seq)
{
  if (*num > prep.qnum) return FALSE; 
  else return TRUE;
}

int check_minp(struct db_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
      if (queue[x]->packet_counter >= prep.minp) queue[x]->prep_valid++;

      check_validity(queue[x], seq);
    }
  }  

  return FALSE;
}

int check_minb(struct db_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
      if (queue[x]->bytes_counter >= prep.minb) queue[x]->prep_valid++; 

      check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int check_minf(struct db_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
      if (queue[x]->flows_counter >= prep.minf) queue[x]->prep_valid++;

      check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int check_maxp(struct db_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
      if (queue[x]->packet_counter < prep.maxp) queue[x]->prep_valid++;

      check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int check_maxb(struct db_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
      if (queue[x]->bytes_counter < prep.maxb) queue[x]->prep_valid++;

      check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int check_maxf(struct db_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
      if (queue[x]->flows_counter < prep.maxf) queue[x]->prep_valid++;

      check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int check_maxbpp(struct db_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
      if (queue[x]->bytes_counter/queue[x]->packet_counter < prep.maxbpp) queue[x]->prep_valid++;

      check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int check_maxppf(struct db_cache *queue[], int *num, int seq)
{
  int x;

  if (!queue[0]->flows_counter) return FALSE;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
      if (queue[x]->packet_counter/queue[x]->flows_counter < prep.maxppf) queue[x]->prep_valid++;

      check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int check_minbpp(struct db_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
      if (queue[x]->bytes_counter/queue[x]->packet_counter >= prep.minbpp) queue[x]->prep_valid++; 

      check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int check_minppf(struct db_cache *queue[], int *num, int seq)
{
  int x;

  if (!queue[0]->flows_counter) return FALSE;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
      if (queue[x]->packet_counter/queue[x]->flows_counter >= prep.minppf) queue[x]->prep_valid++; 

      check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int check_fss(struct db_cache *queue[], int *num, int seq)
{
  u_int32_t t = prep.fss; /* threshold */
  float p = 0 /* probability */, res; 
  u_int16_t bpratio;
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
      res = (float) queue[x]->bytes_counter/t;
      if (res < 1) p += res;
      if (p >= 1 || res >= 1) {
        queue[x]->prep_valid++;
        if (queue[x]->bytes_counter < t) {
	  bpratio = queue[x]->bytes_counter/queue[x]->packet_counter;
	  queue[x]->bytes_counter = t;
	  queue[x]->packet_counter = queue[x]->bytes_counter/bpratio; /* hmmm */
        }
        if (p >= 1) p -= 1;
      } 

      check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

/* 
   This is an initial implementation and any advice is welcome:
   - seed: microseconds value returned by the gettimeofday() call
   - random value: high-order bits returned by the random() call
*/
int check_fsrc(struct db_cache *queue[], int *num, int seq)
{
  struct fsrc_queue_elem *ptr, *last_seen = NULL, *new;
  struct timeval tv; 
  float w /* random variable */, z;
  u_int32_t max = prep.fsrc+1; /* maximum number of allowed flows */
  int x, queueElemSz = sizeof(struct fsrc_queue_elem);
  u_int16_t bpratio;

  u_int32_t total = 0, subtotal = 0;

  /* no need to sample */ 
  if (*num <= prep.fsrc) {
    for (x = 0; x < *num; x++) {
      if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
        queue[x]->prep_valid++;
        check_validity(queue[x], seq);
      }
    }
    goto end;
  }

  /* 1st stage: computing the m+1==max flows with highest z */ 
  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID || queue[x]->valid == SQL_CACHE_COMMITTED) {
      gettimeofday(&tv, NULL);
      srandom((unsigned int)tv.tv_usec);
      w = (float) (random()/(RAND_MAX+1.0));

      z = (float) queue[x]->bytes_counter/w;

      ptr = &fsrc_queue.head;
      while (z > ptr->z) {
        last_seen = ptr; 
        if (ptr->next) ptr = ptr->next;
        else break; 
      } 

      if (fsrc_queue.num < max) {
        new = malloc(queueElemSz);
        if (!new) {
	  Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (check_fsrc). Exiting ..\n", config.name, config.type);
	  exit_gracefully(1);
	}
        fsrc_queue.num++;
        new->next = last_seen->next;
        last_seen->next = new;
      }
      else {
        if (last_seen == &fsrc_queue.head) continue;
        new = fsrc_queue.head.next;
        if (last_seen != fsrc_queue.head.next) {
          fsrc_queue.head.next = new->next;
          new->next = last_seen->next;
	  last_seen->next = new;
        }
      }
    
      new->cache_ptr = queue[x];
      new->z = z;

      total += queue[x]->bytes_counter;
    }
  }

  /* 2nd stage + 3rd stage:
     - validating the highest m flows 
     - renormalizing the highest m flows:
       Xi(bytes_counter) = { max[ Xi(bytes_counter), Xm+1(z) ]: i = 1,...,m }
  */ 
  for (ptr = fsrc_queue.head.next->next; ptr; ptr = ptr->next) {
    ptr->cache_ptr->prep_valid++; 
    if (ptr->cache_ptr->bytes_counter < fsrc_queue.head.next->z) {
      bpratio = ptr->cache_ptr->bytes_counter/ptr->cache_ptr->packet_counter;
      ptr->cache_ptr->bytes_counter = fsrc_queue.head.next->z;
      ptr->cache_ptr->packet_counter = ptr->cache_ptr->bytes_counter/bpratio; /* hmmm */
    }

    subtotal += ptr->cache_ptr->bytes_counter;
    check_validity(ptr->cache_ptr, seq);
  }

  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): TOT/%u/%u SUBTOT/%u/%u\n",
			config.name, config.type, *num, total, fsrc_queue.num-1, subtotal);

  end:
  return FALSE;
}

int action_usrf(struct db_cache *queue[], int *num, int seq)
{
  u_int32_t r = prep.usrf; /* renormalization factor */
  u_int16_t bpratio;
  int x;
  

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_COMMITTED) {
      bpratio = queue[x]->bytes_counter/queue[x]->packet_counter;
      queue[x]->bytes_counter = queue[x]->bytes_counter*r;
      queue[x]->packet_counter = queue[x]->bytes_counter/bpratio; /* hmmm */
    }
  }

  return FALSE;
}

int action_adjb(struct db_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_COMMITTED) {
      queue[x]->bytes_counter += (queue[x]->packet_counter * prep.adjb);
    }
  }

  return FALSE;
}

int mandatory_invalidate(struct db_cache *queue[], int *num, int seq)
{
  int x;

  /* Two validation mechanisms are used: if ALL checks have to be
     successful, prep_valid is a) initializated to a base value,
     b) incremented at every test concluding positively and c)
     checked for prep_valid == seq; if instead ANY check has to
     be successful, a) prep_valid is initializeted to zero, b) is
     brought to a positive value by the first positive test and c)
     finally checked for a non-zero value */
  for (x = 0; x < *num; x++) {
    if (config.sql_preprocess_type == 0) queue[x]->prep_valid = 0;
    else queue[x]->prep_valid = seq;

    if (prep.checkno && queue[x]->valid == SQL_CACHE_COMMITTED)
      queue[x]->valid = SQL_CACHE_INVALID; 
  }

  return FALSE;
}

/*
  - 'sql_preprocess_type == 0' means match 'any' of the checks
  - 'sql_preprocess_type == 1' means match 'all' checks
  - queue[x]->valid floor value is 2 (SQL_CACHE_COMMITTED)
*/
int mandatory_validate(struct db_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == SQL_CACHE_INVALID && prep.recover) queue[x]->valid = SQL_CACHE_ERROR;
  }

  return FALSE;
}

int P_mandatory_invalidate(struct chained_cache *queue[], int *num, int seq)
{
  int x;

  /* Two validation mechanisms are used: if ALL checks have to be
     successful, prep_valid is a) initializated to a base value,
     b) incremented at every test concluding positively and c)
     checked for prep_valid == seq; if instead ANY check has to
     be successful, a) prep_valid is initializeted to zero, b) is
     brought to a positive value by the first positive test and c)
     finally checked for a non-zero value */
  for (x = 0; x < *num; x++) {
    if (config.sql_preprocess_type == 0) queue[x]->prep_valid = 0;
    else queue[x]->prep_valid = seq;

    if (prep.checkno && queue[x]->valid == PRINT_CACHE_COMMITTED)
      queue[x]->valid = PRINT_CACHE_INVALID;
  }

  return FALSE;
}

int P_check_minp(struct chained_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == PRINT_CACHE_INVALID || queue[x]->valid == PRINT_CACHE_COMMITTED) {
      if (queue[x]->packet_counter >= prep.minp) queue[x]->prep_valid++;

      P_check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int P_check_minb(struct chained_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == PRINT_CACHE_INVALID || queue[x]->valid == PRINT_CACHE_COMMITTED) {
      if (queue[x]->bytes_counter >= prep.minb) queue[x]->prep_valid++;

      P_check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int P_check_minf(struct chained_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == PRINT_CACHE_INVALID || queue[x]->valid == PRINT_CACHE_COMMITTED) {
      if (queue[x]->flow_counter >= prep.minf) queue[x]->prep_valid++;

      P_check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int P_check_minbpp(struct chained_cache *queue[], int *num, int seq)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == PRINT_CACHE_INVALID || queue[x]->valid == PRINT_CACHE_COMMITTED) {
      if (queue[x]->bytes_counter/queue[x]->packet_counter >= prep.minbpp) queue[x]->prep_valid++;

      P_check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

int P_check_minppf(struct chained_cache *queue[], int *num, int seq)
{
  int x;

  if (!queue[0]->flow_counter) return FALSE;

  for (x = 0; x < *num; x++) {
    if (queue[x]->valid == PRINT_CACHE_INVALID || queue[x]->valid == PRINT_CACHE_COMMITTED) {
      if (queue[x]->packet_counter/queue[x]->flow_counter >= prep.minppf) queue[x]->prep_valid++;

      P_check_validity(queue[x], seq);
    }
  }

  return FALSE;
}

void P_check_validity(struct chained_cache *entry, int seq)
{
  if (config.sql_preprocess_type == 0) {
    if (entry->prep_valid > 0 && entry->valid == PRINT_CACHE_INVALID)
      entry->valid = PRINT_CACHE_COMMITTED;
  }
  else {
    if (entry->prep_valid == seq) entry->valid = PRINT_CACHE_COMMITTED;
    else entry->valid = PRINT_CACHE_FREE;
  }
}
