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

/* defines */
#define XFLOW_RESET_BOUNDARY 50
#define XFLOW_STATUS_TABLE_SZ 9973
#define XFLOW_STATUS_TABLE_MAX_ENTRIES 100000

/* structures */
struct xflow_status_entry_counters
{
  u_int32_t good;
  u_int32_t jumps_f;
  u_int32_t jumps_b;
};

struct xflow_status_entry_sampling
{
  u_int32_t interface;		/* sFlow: interface generating the sample */
  u_int32_t sample_pool;	/* sampling rate */
  u_int32_t seqno;		/* sFlow: flow samples sequence number */
  struct xflow_status_entry_sampling *next;
};

struct xflow_status_entry
{
  struct host_addr agent_addr;  /* xFlow agent IP address */
  u_int32_t seqno;              /* Sequence number */
  u_int32_t aux1;               /* Some more distinguishing fields:
                                   NetFlow v5-v8: Engine Type + Engine ID
                                   NetFlow v9: Source ID
                                   sFlow v5: agentSubID */
  u_int16_t inc;		/* increment, NetFlow v5: required by flow sequence number */
  struct xflow_status_entry_counters counters;
  struct xflow_status_entry_sampling *sampling;
  struct xflow_status_entry *next;
};

/* prototypes */
#if (!defined __XFLOW_STATUS_C)
#define EXT extern
#else
#define EXT
#endif
EXT u_int32_t hash_status_table(u_int32_t, struct sockaddr *, u_int32_t);
EXT struct xflow_status_entry *search_status_table(struct sockaddr *, u_int32_t, int, int);
EXT void update_good_status_table(struct xflow_status_entry *, u_int32_t);
EXT void update_bad_status_table(struct xflow_status_entry *);
EXT void print_status_table(time_t, int);
EXT struct xflow_status_entry_sampling *search_smp_if_status_table(struct xflow_status_entry_sampling *, u_int32_t);
EXT struct xflow_status_entry_sampling *create_smp_entry_status_table(struct xflow_status_entry *);

EXT struct xflow_status_entry *xflow_status_table[XFLOW_STATUS_TABLE_SZ];
EXT u_int32_t xflow_status_table_entries;
EXT u_int8_t xflow_status_table_error;
EXT u_int32_t xflow_tot_bad_datagrams;
EXT u_int8_t smp_entry_status_table_memerr;
EXT void set_vector_f_status(struct packet_ptrs_vector *);
#undef EXT
