/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2013 by Paolo Lucente
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
  u_int8_t flow_type;
  u_int32_t tcp_flags;
  struct pkt_bgp_primitives *pbgp;
  struct pkt_nat_primitives *pnat;
  int valid;
  struct timeval basetime;
  struct chained_cache *next;
};

/* prototypes */
#if (!defined __PRINT_PLUGIN_C)
#define EXT extern
#else
#define EXT
#endif
EXT void print_plugin(int, struct configuration *, void *);
EXT struct chained_cache *P_cache_attach_new_node(struct chained_cache *);
EXT unsigned int P_cache_modulo(struct primitives_ptrs *);
EXT void P_sum_host_insert(struct primitives_ptrs *);
EXT void P_sum_port_insert(struct primitives_ptrs *);
EXT void P_sum_as_insert(struct primitives_ptrs *);
#if defined (HAVE_L2)
EXT void P_sum_mac_insert(struct primitives_ptrs *);
#endif
EXT struct chained_cache *P_cache_search(struct primitives_ptrs *);
EXT void P_cache_insert(struct primitives_ptrs *);
EXT void P_cache_flush(struct chained_cache *[], int);
EXT void P_cache_purge(struct chained_cache *[], int);
EXT void P_write_stats_header_formatted(FILE *, int);
EXT void P_write_stats_header_csv(FILE *, int);
EXT void P_exit_now(int);
EXT int P_trigger_exec(char *);

/* global vars */
EXT void (*insert_func)(struct primitives_ptrs *); /* pointer to INSERT function */
EXT struct scratch_area sa;
EXT struct chained_cache *cache;
EXT struct chained_cache **queries_queue;
EXT struct timeval flushtime;
EXT int qq_ptr, pp_size, pb_size, pn_size, dbc_size, quit; 
EXT time_t refresh_deadline;

EXT void (*basetime_init)(time_t);
EXT void (*basetime_eval)(struct timeval *, struct timeval *, time_t);
EXT int (*basetime_cmp)(struct timeval *, struct timeval *);
EXT struct timeval basetime, ibasetime;
EXT time_t timeslot;

EXT void P_init_historical_acct(time_t);
EXT void P_eval_historical_acct(struct timeval *, struct timeval *, time_t);
EXT int P_cmp_historical_acct(struct timeval *, struct timeval *);
EXT int P_test_zero_elem(struct chained_cache *);
#undef EXT
