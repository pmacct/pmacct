/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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
#include <libpq-fe.h>

/* defines */
#define REPROCESS_SPECIFIC	1
#define REPROCESS_BULK		2

/* prototypes */
void pgsql_plugin(int, struct configuration *, void *);
int PG_cache_dbop(struct DBdesc *, struct db_cache *, struct insert_data *);
int PG_cache_dbop_copy(struct DBdesc *, struct db_cache *, struct insert_data *);
void PG_cache_purge(struct db_cache *[], int, struct insert_data *);
int PG_evaluate_history(int);
int PG_compose_static_queries();
void PG_compose_conn_string(struct DBdesc *, char *);
void PG_Lock(struct DBdesc *);
void PG_DB_Connect(struct DBdesc *, char *);
void PG_DB_Close(struct BE_descs *);
void PG_create_dyn_table(struct DBdesc *, char *);
static int PG_affected_rows(PGresult *);
void PG_create_backend(struct DBdesc *);
void PG_set_callbacks(struct sqlfunc_cb_registry *);
void PG_init_default_values(struct insert_data *);
void PG_postgresql_get_version();

/* global vars */
int typed = TRUE;

/* variables */
static char pgsql_user[] = "pmacct";
static char pgsql_pwd[] = "arealsmartpwd";
static char pgsql_db[] = "pmacct";
static char pgsql_table[] = "acct";
static char pgsql_table_v2[] = "acct_v2";
static char pgsql_table_v3[] = "acct_v3";
static char pgsql_table_v4[] = "acct_v4";
static char pgsql_table_v5[] = "acct_v5";
static char pgsql_table_v6[] = "acct_v6";
static char pgsql_table_v7[] = "acct_v7";
static char pgsql_table_v8[] = "acct_v8";
static char pgsql_table_bgp[] = "acct_bgp";
static char pgsql_table_uni[] = "acct_uni";
static char pgsql_table_uni_v2[] = "acct_uni_v2";
static char pgsql_table_uni_v3[] = "acct_uni_v3";
static char pgsql_table_uni_v4[] = "acct_uni_v4";
static char pgsql_table_uni_v5[] = "acct_uni_v5";
static char pgsql_table_as[] = "acct_as";
static char pgsql_table_as_v2[] = "acct_as_v2";
static char pgsql_table_as_v3[] = "acct_as_v3";
static char pgsql_table_as_v4[] = "acct_as_v4";
static char pgsql_table_as_v5[] = "acct_as_v5";
static char typed_str[] = "typed"; 
static char unified_str[] = "unified"; 
