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
#if defined HAVE_MYSQL_H 
#include <mysql.h>
#else
#include <mysql/mysql.h>
#endif

#include "sql_common.h"

/* prototypes */
void mysql_plugin(int, struct configuration *, void *);
int MY_cache_dbop(struct DBdesc *, struct db_cache *, struct insert_data *);
void MY_cache_purge(struct db_cache *[], int, struct insert_data *);
int MY_evaluate_history(int);
int MY_compose_static_queries();
void MY_Lock(struct DBdesc *);
void MY_Unlock(struct BE_descs *);
void MY_DB_Connect(struct DBdesc *, char *);
void MY_DB_Close(struct BE_descs *); 
void MY_create_dyn_table(struct DBdesc *, char *);
void MY_get_errmsg(struct DBdesc *);
void MY_create_backend(struct DBdesc *);
void MY_set_callbacks(struct sqlfunc_cb_registry *);
void MY_init_default_values(struct insert_data *);
void MY_mysql_get_version();

/* variables */
extern char mysql_user[];
extern char mysql_pwd[];
extern unsigned int mysql_prt;
extern char mysql_db[];
extern char mysql_table[];
extern char mysql_table_v2[];
extern char mysql_table_v3[];
extern char mysql_table_v4[];
extern char mysql_table_v5[];
extern char mysql_table_v6[];
extern char mysql_table_v7[];
extern char mysql_table_v8[];
extern char mysql_table_bgp[];
