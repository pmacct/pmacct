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

#define __PREPROCESS_C

#include "pmacct.h"
#include "pmacct-data.h"
#include "sql_common.h"

void set_preprocess_funcs(char *string, struct preprocess *prep)
{
  char *token, *sep, *key, *value;
  int j = 0;

  memset(preprocess_funcs, 0, sizeof(preprocess_funcs));
  memset(prep, 0, sizeof(struct preprocess));

  if (!string) return;

  trim_all_spaces(string);

  while (token = extract_token(&string, ',')) {
    sep = strchr(token, '=');
    if (!sep) {
      Log(LOG_WARNING, "WARN ( %s/%s ): Malformed preprocess string. Discarded.\n", config.name, config.type);
      return; 
    }
    else {
      key = token;
      *sep = '\0';
      value = sep+1;
    } 

    if (!strcmp(key, "qnum")) {
      prep->qnum = atoi(value);
      if (!prep->qnum) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'qnum' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minp")) {
      prep->minp = atoi(value);
      if (!prep->minp) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'minp' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minf")) {
      prep->minf = atoi(value);
      if (!prep->minf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'minf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minb")) {
      prep->minb = atoi(value);
      if (!prep->minb) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'minb' value.\n", config.name, config.type);
    }

    else if (!strcmp(key, "maxp")) {
      prep->maxp = atoi(value);
      if (!prep->maxp) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'maxp' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "maxf")) {
      prep->maxf = atoi(value);
      if (!prep->maxf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'maxf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "maxb")) {
      prep->maxb = atoi(value);
      if (!prep->maxb) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'maxb' value.\n", config.name, config.type);
    }

    else if (!strcmp(key, "maxbpp")) {
      prep->maxbpp = atoi(value);
      if (!prep->maxbpp) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'maxbpp' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "maxppf")) {
      prep->maxppf = atoi(value);
      if (!prep->maxppf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'maxppf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minbpp")) {
      prep->minbpp = atoi(value);
      if (!prep->minbpp) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'minbpp' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "minppf")) {
      prep->minppf = atoi(value);
      if (!prep->minppf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'minppf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "fss")) {
      prep->fss = atoi(value);
      if (!prep->fss) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'fss' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "fsrc")) {
      prep->fsrc = atoi(value);
      if (!prep->fsrc) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'fsrc' value.\n", config.name, config.type);
      else {
	fsrc_queue.num = 0;
	memset(&fsrc_queue.head, 0, sizeof(struct fsrc_queue_elem)); 
      }
    }
    else if (!strcmp(key, "usrf")) {
      prep->usrf = atoi(value);
      if (!prep->usrf) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'usrf' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "adjb")) {
      prep->adjb = atoi(value);
      if (!prep->adjb) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'adjb' value.\n", config.name, config.type);
    }
    else if (!strcmp(key, "recover")) {
      prep->recover = atoi(value);
      if (!prep->recover) Log(LOG_WARNING, "WARN ( %s/%s ): preprocess: Invalid 'recover' value.\n", config.name, config.type);
    }
    else Log(LOG_ERR, "ERROR ( %s/%s ): Invalid preprocess key: '%s'. Ignored.\n", config.name, config.type, key);
  }

  /* Post checks: almost one check should have been specified */
  if ((!prep->minp) && (!prep->minb) && (!prep->minf) &&
      (!prep->maxp) && (!prep->maxb) && (!prep->maxf) &&
      (!prep->maxbpp) && (!prep->maxppf) && (!prep->minbpp) &&
      (!prep->minppf) && (!prep->fss) && (!prep->fsrc) &&
      (!prep->usrf) && (!prep->adjb)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): 'sql_preprocess' does not contain any check. Ignored.\n", config.name, config.type); 
    return;
  } 

  /* 1st step: insert conditionals */
  if (prep->qnum) {
    preprocess_funcs[j] = cond_qnum;
    j++;
  }

  /* 2nd step: full-cache invalidation; each of the following
     checks will re-validate matching entries */
  preprocess_funcs[j] = mandatory_invalidate;
  j++;

  /* 3rd step: insert checks */
  if (prep->minp) {
    preprocess_funcs[j] = check_minp;
    prep->num++;
    j++;
    prep->checkno++;
  } 

  if (prep->minf) {
    preprocess_funcs[j] = check_minf;
    prep->num++;
    j++;
    prep->checkno++;
  }

  if (prep->minb) {
    preprocess_funcs[j] = check_minb;
    prep->num++;
    j++;
    prep->checkno++;
  }

  if (prep->maxp) {
    preprocess_funcs[j] = check_maxp;
    prep->num++;
    j++;
    prep->checkno++;
  }

  if (prep->maxf) {
    preprocess_funcs[j] = check_maxf;
    prep->num++;
    j++;
    prep->checkno++;
  }

  if (prep->maxb) {
    preprocess_funcs[j] = check_maxb;
    prep->num++;
    j++;
    prep->checkno++;
  }

  if (prep->maxbpp) {
    preprocess_funcs[j] = check_maxbpp;
    prep->num++;
    j++;
    prep->checkno++;
  }

  if (prep->maxppf) {
    preprocess_funcs[j] = check_maxppf;
    prep->num++;
    j++;
    prep->checkno++;
  }

  if (prep->minbpp) {
    preprocess_funcs[j] = check_minbpp;
    prep->num++;
    j++;
    prep->checkno++;
  }

  if (prep->minppf) {
    preprocess_funcs[j] = check_minppf;
    prep->num++;
    j++;
    prep->checkno++;
  }

  if (prep->fss) {
    preprocess_funcs[j] = check_fss;
    prep->num++;
    j++;
    prep->checkno++;
  }

  if (prep->fsrc) {
    preprocess_funcs[j] = check_fsrc;
    prep->num++;
    j++;
    prep->checkno++;
  }

  if (prep->usrf) {
    preprocess_funcs[j] = action_usrf;
    prep->num++;
    j++;
    prep->actionno++;
  }

  if (prep->adjb) {
    preprocess_funcs[j] = action_adjb;
    prep->num++;
    j++;
    prep->actionno++;
  }

  /* 
     4th and final step: check points:
     - if in 'any' mode, any entry with 'points >= 1' is valid
     - if in 'all' mode, any entry with 'points == number of conditions' is valid 
  */
  preprocess_funcs[j] = mandatory_validate;
  j++;
}

int cond_qnum(struct db_cache *queue[], int *num)
{
  if (*num > prep.qnum) return FALSE; 
  else return TRUE;
}

int check_minp(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->packet_counter >= prep.minp) queue[x]->valid++;
  }  

  return FALSE;
}

int check_minb(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->bytes_counter >= prep.minb) queue[x]->valid++; 
  }

  return FALSE;
}

int check_minf(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->flows_counter >= prep.minf) queue[x]->valid++;
  }

  return FALSE;
}

int check_maxp(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->packet_counter < prep.maxp) queue[x]->valid++;
  }

  return FALSE;
}

int check_maxb(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->bytes_counter < prep.maxb) queue[x]->valid++;
  }

  return FALSE;
}

int check_maxf(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->flows_counter < prep.maxf) queue[x]->valid++;
  }

  return FALSE;
}

int check_maxbpp(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->bytes_counter/queue[x]->packet_counter < prep.maxbpp) queue[x]->valid++;
  }

  return FALSE;
}

int check_maxppf(struct db_cache *queue[], int *num)
{
  int x;

  if (!queue[0]->flows_counter) return FALSE;

  for (x = 0; x < *num; x++) {
    if (queue[x]->packet_counter/queue[x]->flows_counter < prep.maxppf) queue[x]->valid++;
  }

  return FALSE;
}

int check_minbpp(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (queue[x]->bytes_counter/queue[x]->packet_counter >= prep.minbpp) queue[x]->valid++; 
  }

  return FALSE;
}

int check_minppf(struct db_cache *queue[], int *num)
{
  int x;

  if (!queue[0]->flows_counter) return FALSE;

  for (x = 0; x < *num; x++) {
    if (queue[x]->packet_counter/queue[x]->flows_counter >= prep.minppf) queue[x]->valid++; 
  }

  return FALSE;
}

int check_fss(struct db_cache *queue[], int *num)
{
  u_int32_t t = prep.fss; /* threshold */
  float p = 0 /* probability */, res; 
  u_int16_t bpratio;
  int x;

  for (x = 0; x < *num; x++) {
    res = (float) queue[x]->bytes_counter/t;
    if (res < 1) p += res;
    if (p >= 1 || res >= 1) {
      queue[x]->valid++;
      if (queue[x]->bytes_counter < t) {
	bpratio = queue[x]->bytes_counter/queue[x]->packet_counter;
	queue[x]->bytes_counter = t;
	queue[x]->packet_counter = queue[x]->bytes_counter/bpratio; /* hmmm */
      }
      if (p >= 1) p -= 1;
    } 
  }

  return FALSE;
}

/* 
   This is an initial implementation and any advice is welcome:
   - seed: microseconds value returned by the gettimeofday() call
   - random value: high-order bits returned by the random() call
*/
int check_fsrc(struct db_cache *queue[], int *num)
{
  struct fsrc_queue_elem *ptr, *last_seen, *new;
  struct timeval tv; struct timezone tz;
  float w /* random variable */, z;
  u_int32_t max = prep.fsrc+1; /* maximum number of allowed flows */
  int x, queueElemSz = sizeof(struct fsrc_queue_elem);
  u_int16_t bpratio;

  u_int32_t total = 0, subtotal = 0;

  /* no need to sample */ 
  if (*num <= prep.fsrc) {
    for (x = 0; x < *num; x++) queue[x]->valid++;
    goto end;
  }

  /* 1st stage: computing the m+1==max flows with highest z */ 
  for (x = 0; x < *num; x++) {
    gettimeofday(&tv, &tz);
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

  /* 2nd stage + 3rd stage:
     - validating the highest m flows 
     - renormalizing the highest m flows:
       Xi(bytes_counter) = { max[ Xi(bytes_counter), Xm+1(z) ]: i = 1,...,m }
  */ 
  for (ptr = fsrc_queue.head.next->next; ptr; ptr = ptr->next) {
    ptr->cache_ptr->valid++; 
    if (ptr->cache_ptr->bytes_counter < fsrc_queue.head.next->z) {
      bpratio = ptr->cache_ptr->bytes_counter/ptr->cache_ptr->packet_counter;
      ptr->cache_ptr->bytes_counter = fsrc_queue.head.next->z;
      ptr->cache_ptr->packet_counter = ptr->cache_ptr->bytes_counter/bpratio; /* hmmm */
    }

    subtotal += ptr->cache_ptr->bytes_counter;
  }

  if (config.debug) Log(LOG_DEBUG, "DEBUG: TOT/%u/%u SUBTOT/%u/%u\n", *num, total, fsrc_queue.num-1, subtotal);

  end:
  return FALSE;
}

int action_usrf(struct db_cache *queue[], int *num)
{
  u_int32_t r = prep.usrf; /* renormalization factor */
  u_int16_t bpratio;
  int x;
  

  for (x = 0; x < *num; x++) {
    bpratio = queue[x]->bytes_counter/queue[x]->packet_counter;
    queue[x]->bytes_counter = queue[x]->bytes_counter*r;
    queue[x]->packet_counter = queue[x]->bytes_counter/bpratio; /* hmmm */
  }

  return FALSE;
}

int action_adjb(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) queue[x]->bytes_counter += prep.adjb;

  return FALSE;
}

int mandatory_invalidate(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) queue[x]->valid = SQL_CACHE_FREE; 

  return FALSE;
}

/*
  - 'sql_preprocess_type == 0' means match 'any' of the checks
  - 'sql_preprocess_type == 1' means match 'all' checks
  - queue[x]->valid floor value is 2 (SQL_CACHE_COMMITTED)
*/
int mandatory_validate(struct db_cache *queue[], int *num)
{
  int x;

  for (x = 0; x < *num; x++) {
    if (!prep.checkno) queue[x]->valid = SQL_CACHE_INUSE; 
    if (config.sql_preprocess_type == 1 && (queue[x]->valid-1) < (prep.num-prep.actionno)) queue[x]->valid = SQL_CACHE_FREE; 
    if (queue[x]->valid == SQL_CACHE_FREE && prep.recover) queue[x]->valid = SQL_CACHE_ERROR;
  }

  return FALSE;
}
