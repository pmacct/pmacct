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

/* includes */
#include <sys/poll.h>

/* defines */
#define DEFAULT_PRINT_REFRESH_TIME 10 
#define AVERAGE_CHAIN_LEN 10
#define PRINT_CACHE_ENTRIES 16411

/* structures */
struct scratch_area {
  unsigned char *base;
  unsigned char *ptr;
  int num;
  int size;
  struct scratch_area *next;
};

struct chained_cache {
  struct pkt_primitives primitives;
  pm_counter_t bytes_counter;
  pm_counter_t packet_counter;
  pm_counter_t flow_counter;
  u_int32_t tcp_flags;
  int valid;
  struct chained_cache *next;
};

/* prototypes */
void print_plugin(int, struct configuration *, void *);
struct chained_cache *P_cache_attach_new_node(struct chained_cache *);
unsigned int P_cache_modulo(struct pkt_primitives *);
void P_sum_host_insert(struct pkt_data *);
void P_sum_port_insert(struct pkt_data *);
void P_sum_as_insert(struct pkt_data *);
#if defined (HAVE_L2)
void P_sum_mac_insert(struct pkt_data *);
#endif
struct chained_cache *P_cache_search(struct pkt_primitives *);
void P_cache_insert(struct pkt_data *);
void P_cache_flush(struct chained_cache *[], int);
void P_cache_purge(struct chained_cache *[], int);
void P_write_stats_header();
void *Malloc(unsigned int);
void P_exit_now(int);

/* global vars */
void (*insert_func)(struct pkt_data *); /* pointer to INSERT function */
struct scratch_area sa;
struct chained_cache *cache;
struct chained_cache **queries_queue;
struct timeval flushtime;
int qq_ptr, pp_size, dbc_size, quit; 
time_t refresh_deadline;
