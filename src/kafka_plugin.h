/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2015 by Paolo Lucente
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
#define PM_KAFKA_ERRSTR_LEN	512

/* structures */
struct p_kafka_host {
  rd_kafka_t *rk;
  rd_kafka_conf_t *cfg;
  char *broker_host;
  int broker_port;
  int partition;
  rd_kafka_topic_t *topic;
  rd_kafka_topic_conf_t *topic_cfg;
  char errstr[PM_KAFKA_ERRSTR_LEN];
};

/* prototypes */
#if (!defined __KAFKA_PLUGIN_C)
#define EXT extern
#else
#define EXT
#endif
EXT void kafka_plugin(int, struct configuration *, void *);
EXT void kafka_cache_purge(struct chained_cache *[], int);

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

EXT struct p_kafka_host kafkap_kafka_host;

static char default_kafka_broker_host[] = "127.0.0.1";
static int default_kafka_broker_port = 9092;
static int default_kafka_partition = RD_KAFKA_PARTITION_UA;
static char default_kafka_topic[] = "pmacct";
#undef EXT
