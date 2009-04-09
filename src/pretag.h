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

/* Pre-Tag map stuff */
#define N_MAP_HANDLERS 10 
#define MAX_LABEL_LEN 32
#define MAX_PRETAG_MAP_ENTRIES 384 

typedef int (*pretag_handler) (struct packet_ptrs *, void *, void *);
typedef pm_id_t (*pretag_stack_handler) (pm_id_t, pm_id_t);

typedef struct {
  u_int8_t neg;
  u_int8_t n;
} pt_uint8_t;

typedef struct {
  u_int8_t neg;
  u_int16_t n;
} pt_uint16_t;

typedef struct {
  u_int8_t neg;
  u_int32_t n;
} pt_uint32_t;

typedef struct {
  u_int8_t neg;
  struct host_addr a;
} pt_hostaddr_t;

typedef struct {
  char *label;
  struct id_entry *ptr;
} pt_jeq_t;

typedef struct {
  pretag_stack_handler func; 
} pt_stack_t;

/* Pre-Tag table (ptt) element definition */
typedef struct {
  u_int8_t neg;
  u_int16_t n;
  u_int16_t r;
} ptt_uint16_t;

struct id_entry {
  pm_id_t id;
  pm_id_t pos;
  pt_hostaddr_t agent_ip;
  pt_hostaddr_t nexthop;
  pt_hostaddr_t bgp_nexthop;
  pt_uint32_t input; /* input interface index */
  pt_uint32_t output; /* output interface index */
  pt_uint8_t engine_type;
  pt_uint8_t engine_id;
  pt_uint32_t agent_id; /* applies to sFlow's agentSubId */
  pt_uint32_t sampling_rate; /* applies to sFlow's sampling rate */
  pt_uint16_t src_as;
  pt_uint16_t dst_as; 
  struct bpf_program filter;
  pt_uint8_t v8agg;
  pretag_handler func[N_MAP_HANDLERS];
  char label[MAX_LABEL_LEN];
  pt_jeq_t jeq;
  u_int8_t ret;
  pt_stack_t stack;
};

struct id_table {
  unsigned short int num;
  struct id_entry *ipv4_base;
  unsigned short int ipv4_num;
#if defined ENABLE_IPV6
  struct id_entry *ipv6_base;
  unsigned short int ipv6_num;
#endif
  struct id_entry *e;
  time_t timestamp;
};

struct _map_dictionary_line {
  char key[SRVBUFLEN];
  int (*func)(char *, struct id_entry *, char *, struct plugin_requests *);
};

struct pretag_filter {
  u_int16_t num;
  ptt_uint16_t table[MAX_PRETAG_MAP_ENTRIES/4];
};

/* prototypes */
#if (!defined __PRETAG_C)
#define EXT extern
#else
#define EXT
#endif
EXT void load_id_file(int, char *, struct id_table *, struct plugin_requests *);
EXT u_int8_t pt_check_neg(char **);
EXT char * pt_check_range(char *);

#undef EXT
