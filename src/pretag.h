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

/* Pre-Tag map stuff */
#define N_MAP_HANDLERS N_PRIMITIVES
#define MAX_LABEL_LEN 32
#define MAX_PRETAG_MAP_ENTRIES 384 

#define PRETAG_IN_IFACE		0x00000001
#define PRETAG_OUT_IFACE	0x00000002
#define PRETAG_NEXTHOP		0x00000004
#define PRETAG_BGP_NEXTHOP	0x00000008
#define PRETAG_ENGINE_TYPE	0x00000010
#define PRETAG_ENGINE_ID	0x00000020
#define PRETAG_FILTER		0x00000040
#define PRETAG_NFV8_AGG		0x00000080
#define PRETAG_SF_AGENTID	0x00000100
#define PRETAG_SAMPLING_RATE	0x00000200
#define PRETAG_DIRECTION	0x00000400
#define PRETAG_SRC_AS		0x00000800
#define PRETAG_DST_AS		0x00001000
#define PRETAG_PEER_SRC_AS	0x00002000
#define PRETAG_PEER_DST_AS	0x00004000
#define PRETAG_SRC_LOCAL_PREF	0x00008000
#define PRETAG_LOCAL_PREF	0x00010000
#define PRETAG_SRC_STD_COMM	0x00020000
#define PRETAG_STD_COMM		0x00040000
#define PRETAG_MPLS_VPN_RD	0x00080000
#define PRETAG_SAMPLE_TYPE      0x00100000
#define PRETAG_SET_TOS		0x00200000
#define PRETAG_SET_TAG		0x00400000
#define PRETAG_SET_TAG2		0x00800000

#define PRETAG_MAP_RCODE_ID		0x00000100
#define PRETAG_MAP_RCODE_ID2		0x00000200
#define PRETAG_MAP_RCODE_SET_TOS	0x00000400
#define BTA_MAP_RCODE_ID_ID2		0x00000800
#define BPAS_MAP_RCODE_BGP		0x00001000

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
  u_int8_t neg;
  rd_t rd;
} pt_rd_t;

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
  pm_id_t n;
  pm_id_t r;
} ptt_t;

struct id_entry {
  pm_id_t id;
  pm_id_t id2;
  pm_id_t flags;
  pm_id_t pos;
  pt_hostaddr_t agent_ip;
  pt_hostaddr_t nexthop;
  pt_hostaddr_t bgp_nexthop;
  pt_uint32_t input; /* input interface index */
  pt_uint32_t output; /* output interface index */
  pt_uint8_t engine_type;
  pt_uint8_t engine_id;
  pt_uint32_t agent_id; /* applies to sFlow agentSubId */
  pt_uint32_t sampling_rate; /* applies to sFlow sampling rate */
  pt_uint32_t sample_type; /* applies to sFlow sample type */
  pt_uint8_t direction;
  pt_uint32_t src_as;
  pt_uint32_t dst_as; 
  pt_uint32_t peer_src_as;
  pt_uint32_t peer_dst_as;
  pt_uint32_t src_local_pref;
  pt_uint32_t local_pref;
  s_uint8_t set_tos;
  char *src_comms[16]; /* XXX: MAX_BGP_COMM_PATTERNS = 16 */
  char *comms[16]; /* XXX: MAX_BGP_COMM_PATTERNS = 16 */
  pt_rd_t mpls_vpn_rd;
  struct bpf_program filter;
  pt_uint8_t v8agg;
  pretag_handler func[N_MAP_HANDLERS];
  u_int32_t func_type[N_MAP_HANDLERS];
  pretag_handler set_func[N_MAP_HANDLERS];
  u_int32_t set_func_type[N_MAP_HANDLERS];
  char label[MAX_LABEL_LEN];
  pt_jeq_t jeq;
  u_int8_t ret;
  pt_stack_t stack;
  u_int32_t last_matched;
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
  int (*func)(char *, struct id_entry *, char *, struct plugin_requests *, int);
};

struct pretag_filter {
  u_int16_t num;
  ptt_t table[MAX_PRETAG_MAP_ENTRIES/4];
};

/* prototypes */
#if (!defined __PRETAG_C)
#define EXT extern
#else
#define EXT
#endif
EXT void load_id_file(int, char *, struct id_table *, struct plugin_requests *, int *);
EXT u_int8_t pt_check_neg(char **);
EXT char * pt_check_range(char *);
EXT void pretag_init_vars(struct packet_ptrs *);

EXT int tag_map_allocated;
EXT int bpas_map_allocated;
EXT int blp_map_allocated;
EXT int bmed_map_allocated;
EXT int biss_map_allocated;
EXT int bta_map_allocated;
EXT int bitr_map_allocated;
EXT int sampling_map_allocated;

EXT int bta_map_caching; 
EXT int sampling_map_caching; 

EXT int (*find_id_func)(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);
#undef EXT
