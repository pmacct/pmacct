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
#include <librdkafka/rdkafka.h>
#include <sys/poll.h>

/* defines */

/* structures */

/* prototypes */
#if (!defined __KAFKA_PLUGIN_C)
#define EXT extern
#else
#define EXT
#endif
EXT void kafka_plugin(int, struct configuration *, void *);
EXT void kafka_cache_purge(struct chained_cache *[], int);
#ifdef WITH_AVRO
EXT void kafka_avro_schema_purge(char *);
#endif
EXT void *kafka_generate_stats(void *);

/* global vars */
EXT void (*insert_func)(struct primitives_ptrs *, struct insert_data *); /* pointer to INSERT function */
EXT void (*purge_func)(struct chained_cache *[], int); /* pointer to purge function */
EXT struct scratch_area sa;
EXT struct chained_cache *cache;
EXT struct chained_cache **queries_queue;
EXT struct timeval flushtime;
EXT int qq_ptr, pp_size, pb_size, pn_size, pm_size, dbc_size, quit;
EXT time_t refresh_deadline;

EXT struct timeval sbasetime;

EXT void set_kafka_metric(u_int64_t, void *);
#ifdef WITH_AVRO
EXT char *avro_buf;
EXT avro_schema_t avro_acct_schema;
#endif
#undef EXT
