/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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
#define MAX_BITMAP_ENTRIES 64 /* pt_bitmap_t -> u_int64_t */
#define MAX_PRETAG_MAP_ENTRIES 384 

#define MAX_ID_TABLE_INDEXES 8
#define ID_TABLE_INDEX_DEPTH 8
#define ID_TABLE_INDEX_RESULTS (MAX_ID_TABLE_INDEXES * 8)

#define PRETAG_IN_IFACE			0x000000001
#define PRETAG_OUT_IFACE		0x000000002
#define PRETAG_NEXTHOP			0x000000004
#define PRETAG_BGP_NEXTHOP		0x000000008
#define PRETAG_ENGINE_TYPE		0x000000010
#define PRETAG_ENGINE_ID		0x000000020
#define PRETAG_FILTER			0x000000040
#define PRETAG_NFV8_AGG			0x000000080
#define PRETAG_SF_AGENTID		0x000000100
#define PRETAG_SAMPLING_RATE		0x000000200
#define PRETAG_DIRECTION		0x000000400
#define PRETAG_SRC_AS			0x000000800
#define PRETAG_DST_AS			0x000001000
#define PRETAG_PEER_SRC_AS		0x000002000
#define PRETAG_PEER_DST_AS		0x000004000
#define PRETAG_SRC_LOCAL_PREF		0x000008000
#define PRETAG_LOCAL_PREF		0x000010000
#define PRETAG_SRC_STD_COMM		0x000020000
#define PRETAG_STD_COMM			0x000040000
#define PRETAG_MPLS_VPN_RD		0x000080000
#define PRETAG_SAMPLE_TYPE      	0x000100000
#define PRETAG_SET_TOS			0x000200000
#define PRETAG_LOOKUP_BGP_PORT		0x000400000
#define PRETAG_SET_TAG			0x000800000
#define PRETAG_SET_TAG2			0x001000000
#define PRETAG_MPLS_LABEL_BOTTOM	0x002000000
#define PRETAG_FLOWSET_ID		0x004000000
#define PRETAG_SRC_MAC			0x008000000
#define PRETAG_DST_MAC			0x010000000
#define PRETAG_VLAN_ID			0x020000000
#define PRETAG_IP			0x040000000
#define PRETAG_SET_LABEL		0x080000000
#define PRETAG_CVLAN_ID			0x100000000
#define PRETAG_MPLS_VPN_ID		0x200000000

#define PRETAG_MAP_RCODE_ID		0x00000100
#define PRETAG_MAP_RCODE_ID2		0x00000200
#define PRETAG_MAP_RCODE_SET_TOS	0x00000400
#define PRETAG_MAP_RCODE_JEQ		0x00000800
#define BTA_MAP_RCODE_ID_ID2		0x00001000
#define BTA_MAP_RCODE_LOOKUP_BGP_PORT	0x00002000
#define BPAS_MAP_RCODE_BGP		0x00004000
#define PRETAG_MAP_RCODE_LABEL		0x00008000

#define PRETAG_FLAG_NEG			0x00000001

#define IDT_INDEX_HASH_BASE(entries)	(entries * 2)

typedef int (*pretag_handler) (struct packet_ptrs *, void *, void *);
typedef pm_id_t (*pretag_stack_handler) (pm_id_t, pm_id_t);

typedef u_int64_t pt_bitmap_t;

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

typedef struct host_mask pt_hostmask_t;

typedef struct {
  u_int8_t neg;
  char a[ETH_ADDR_LEN]; 
} pt_etheraddr_t;

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

/* Pre-Tag label table (ptlt) element definition */
typedef struct {
  u_int8_t neg;
  u_int32_t len;
  char *v;
} ptlt_t;

struct id_entry_key {
  pt_hostaddr_t agent_ip;
  pt_hostmask_t agent_mask;
  pt_hostaddr_t nexthop;
  pt_hostaddr_t bgp_nexthop;
  pt_uint32_t input; /* input interface index */
  pt_uint32_t output; /* output interface index */
  pt_uint8_t engine_type;
  pt_uint8_t engine_id;
  pt_uint16_t flowset_id; /* applies to NetFlow v9/IPFIX flowset ID */
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
  pt_uint32_t mpls_label_bottom;
  pt_etheraddr_t src_mac;
  pt_etheraddr_t dst_mac;
  pt_uint16_t vlan_id;
  pt_uint16_t cvlan_id;
  s_uint16_t lookup_bgp_port;
  char *src_comms[16]; /* XXX: MAX_BGP_COMM_PATTERNS = 16 */
  char *comms[16]; /* XXX: MAX_BGP_COMM_PATTERNS = 16 */
  pt_uint32_t mpls_vpn_id;
  pt_rd_t mpls_vpn_rd;
  struct bpf_program filter;
  pt_uint8_t v8agg;
};

struct id_entry {
  pm_id_t id;
  pm_id_t id2;
  pt_label_t label;
  pm_id_t flags;
  pm_id_t pos;
  s_uint8_t set_tos;
  struct id_entry_key key;
  pretag_handler func[N_MAP_HANDLERS];
  pt_bitmap_t func_type[N_MAP_HANDLERS];
  pretag_handler set_func[N_MAP_HANDLERS];
  pt_bitmap_t set_func_type[N_MAP_HANDLERS];
  char entry_label[MAX_LABEL_LEN];
  pt_jeq_t jeq;
  u_int8_t ret;
  pt_stack_t stack;
  pt_bitmap_t last_matched;
  u_int8_t id_inc;
  u_int8_t id2_inc;
};

typedef int (*pretag_copier)(struct id_entry *, pm_hash_serial_t *, void *);

struct id_index_entry {
  u_int16_t depth;
  pm_hash_key_t hash_key[ID_TABLE_INDEX_DEPTH];
  struct id_entry_key key[ID_TABLE_INDEX_DEPTH]; /* XXX: to be removed */
  struct id_entry *result[ID_TABLE_INDEX_DEPTH];
};

struct id_table_index {
  pt_bitmap_t bitmap; 
  int entries;
  pretag_copier idt_handler[MAX_BITMAP_ENTRIES];
  pretag_copier fdata_handler[MAX_BITMAP_ENTRIES];
  pm_hash_serial_t hash_serializer;
  struct id_index_entry *idx_t;
};

struct id_table {
  char *filename;
  int type;
  unsigned int num;
  struct id_entry *ipv4_base;
  unsigned int ipv4_num;
#if defined ENABLE_IPV6
  struct id_entry *ipv6_base;
  unsigned int ipv6_num;
#endif
  struct id_entry *e;
  struct id_table_index index[MAX_ID_TABLE_INDEXES];
  unsigned int index_num;
  time_t timestamp;
  u_int32_t flags;
};

struct _map_dictionary_line {
  char key[SRVBUFLEN];
  int (*func)(char *, struct id_entry *, char *, struct plugin_requests *, int);
};

struct _map_index_dictionary_line {
  pt_bitmap_t key;
  pretag_copier func;
};

struct pretag_filter {
  u_int16_t num;
  ptt_t table[MAX_PRETAG_MAP_ENTRIES/4];
};

struct pretag_label_filter {
  u_int16_t num;
  ptlt_t table[MAX_PRETAG_MAP_ENTRIES/4];
};

/* prototypes */
#if (!defined __PRETAG_C)
#define EXT extern
#else
#define EXT
#endif
EXT void load_id_file(int, char *, struct id_table *, struct plugin_requests *, int *);
EXT void load_pre_tag_map(int, char *, struct id_table *, struct plugin_requests *, int *, int, int);
EXT u_int8_t pt_check_neg(char **, u_int32_t *);
EXT char * pt_check_range(char *);
EXT void pretag_init_vars(struct packet_ptrs *, struct id_table *);
EXT void pretag_init_label(pt_label_t *);
EXT int pretag_malloc_label(pt_label_t *, int);
EXT int pretag_realloc_label(pt_label_t *, int);
EXT int pretag_copy_label(pt_label_t *, pt_label_t *);
EXT void pretag_free_label(pt_label_t *);
EXT int pretag_entry_process(struct id_entry *, struct packet_ptrs *, pm_id_t *, pm_id_t *);
EXT pt_bitmap_t pretag_index_build_bitmap(struct id_entry *, int);
EXT int pretag_index_insert_bitmap(struct id_table *, pt_bitmap_t);
EXT int pretag_index_set_handlers(struct id_table *);
EXT int pretag_index_allocate(struct id_table *);
EXT int pretag_index_fill(struct id_table *, pt_bitmap_t, struct id_entry *);
EXT void pretag_index_report(struct id_table *);
EXT void pretag_index_destroy(struct id_table *);
EXT void pretag_index_lookup(struct id_table *, struct packet_ptrs *, struct id_entry **, int);
EXT void pretag_index_results_sort(struct id_entry **, int);
EXT void pretag_index_results_compress(struct id_entry **, int);
EXT void pretag_index_results_compress_jeqs(struct id_entry **, int);
EXT int pretag_index_have_one(struct id_table *);

EXT int bpas_map_allocated;
EXT int blp_map_allocated;
EXT int bmed_map_allocated;
EXT int biss_map_allocated;
EXT int bta_map_allocated;
EXT int bitr_map_allocated;
EXT int sampling_map_allocated;
EXT int custom_primitives_allocated;

EXT int bta_map_caching; 
EXT int sampling_map_caching; 

EXT int (*find_id_func)(struct id_table *, struct packet_ptrs *, pm_id_t *, pm_id_t *);
#undef EXT
