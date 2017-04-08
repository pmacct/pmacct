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
EXT void kafka_cache_purge(struct chained_cache *[], int, int);
#ifdef WITH_AVRO
EXT void kafka_avro_schema_purge(char *);
#endif
#undef EXT
