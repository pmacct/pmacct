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
#ifndef PREPROCESS_H
#define PREPROCESS_H

/* defines */
#define PREP_DICT_SQL	1
#define PREP_DICT_PRINT	2 

/* structures */
struct _preprocess_dictionary_line {
  char key[SRVBUFLEN];
};

struct preprocess {
  u_int32_t qnum;
  u_int16_t minp;
  u_int16_t minf;
  u_int32_t minb;
  u_int16_t maxp;
  u_int16_t maxf;
  u_int32_t maxb;
  u_int16_t maxbpp;
  u_int16_t maxppf;
  u_int16_t minbpp;
  u_int16_t minppf;
  u_int32_t fss;	/* threshold: flow size (flow size dependent sampling) */
  u_int32_t fsrc;	/* threshold: flows number (flow sampling with resource constraints) */
  int usrf;		/* renormalization factor for uniform sampling methods */
  int adjb;		/* adjusts bytes counter by 'adjb' bytes */
  u_int8_t recover;
  u_int8_t num;		/* total number of preprocess clauses specified: actions + checks */
  u_int8_t checkno;	/* number of checks */
  u_int8_t actionno;	/* number of actions */
};

struct fsrc_queue_elem {
  struct fsrc_queue_elem *next;
  struct db_cache *cache_ptr;
  float z;
};

struct _fsrc_queue {
  struct fsrc_queue_elem head; 
  u_int32_t num;
};

/* typedefs */
//fwd decl
struct chained_cache;
typedef int (*sql_preprocess_func) (struct db_cache *[], int *, int);
typedef int (*P_preprocess_func) (struct chained_cache *[], int *, int);

extern void set_preprocess_funcs(char *, struct preprocess *, int);
extern int cond_qnum(struct db_cache *[], int *, int);
extern int check_minp(struct db_cache *[], int *, int);
extern int check_minb(struct db_cache *[], int *, int);
extern int check_minf(struct db_cache *[], int *, int);
extern int check_maxp(struct db_cache *[], int *, int);
extern int check_maxb(struct db_cache *[], int *, int);
extern int check_maxf(struct db_cache *[], int *, int);
extern int check_maxbpp(struct db_cache *[], int *, int);
extern int check_maxppf(struct db_cache *[], int *, int);
extern int check_minbpp(struct db_cache *[], int *, int);
extern int check_minppf(struct db_cache *[], int *, int);
extern int check_fss(struct db_cache *[], int *, int);
extern int check_fsrc(struct db_cache *[], int *, int);
extern int action_usrf(struct db_cache *[], int *, int);
extern int action_adjb(struct db_cache *[], int *, int);
extern int P_check_minp(struct chained_cache *[], int *, int);
extern int P_check_minb(struct chained_cache *[], int *, int);
extern int P_check_minf(struct chained_cache *[], int *, int);
extern int P_check_minbpp(struct chained_cache *[], int *, int);
extern int P_check_minppf(struct chained_cache *[], int *, int);

extern int mandatory_invalidate(struct db_cache *[], int *, int);
extern int mandatory_validate(struct db_cache *[], int *, int);
extern void check_validity(struct db_cache *, int);
extern int P_mandatory_invalidate(struct chained_cache *[], int *, int);
extern void P_check_validity(struct chained_cache *, int);

extern sql_preprocess_func sql_preprocess_funcs[2*N_FUNCS]; /* 20 */
extern P_preprocess_func P_preprocess_funcs[2*N_FUNCS]; /* 20 */
extern struct preprocess prep;
extern struct _fsrc_queue fsrc_queue;

#endif // PREPROCESS_H
