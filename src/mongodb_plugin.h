/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2014 by Paolo Lucente
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
#include <sys/poll.h>

/* defines */
#if (!defined MONGO_HAVE_STDINT)
#define MONGO_HAVE_STDINT 1
#endif
#include <mongo.h>

#define DEFAULT_MONGO_INSERT_BATCH 10000

/* structures */

/* prototypes */
#if (!defined __MONGODB_PLUGIN_C)
#define EXT extern
#else
#define EXT
#endif
EXT void mongodb_plugin(int, struct configuration *, void *);
EXT void MongoDB_cache_purge(struct chained_cache *[], int);
EXT void MongoDB_create_indexes(mongo *, const char *);
EXT int MongoDB_get_database(char *, int, char *);
EXT void MongoDB_append_label(bson *, char *, struct pkt_vlen_hdr_primitives *, pm_cfgreg_t);

/* global vars */
EXT void (*insert_func)(struct primitives_ptrs *, struct insert_data *); /* pointer to INSERT function */
EXT void (*purge_func)(struct chained_cache *[], int); /* pointer to purge function */ 
EXT struct scratch_area sa;
EXT struct chained_cache *cache;
EXT struct chained_cache **queries_queue;
EXT struct timeval flushtime;
EXT int qq_ptr, pp_size, pb_size, pn_size, pm_size, dbc_size, quit; 
EXT time_t refresh_deadline;
EXT mongo db_conn;

EXT struct timeval sbasetime;
EXT int dyn_table;
#undef EXT
