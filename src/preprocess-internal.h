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
#ifndef PREPROCESS_INTERNAL_H
#define PREPROCESS_INTERNAL_H

#include "preprocess.h"

/* funcs */
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

#endif // PREPROCESS_INTERNAL_H
