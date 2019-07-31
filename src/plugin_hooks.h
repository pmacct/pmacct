/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
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

#define __PLUGIN_COMMON_EXPORT
#include "plugin_common.h"
#undef  __PLUGIN_COMMON_EXPORT

#define DEFAULT_CHBUFLEN 4096
#define DEFAULT_PIPE_SIZE 65535
#define DEFAULT_PLOAD_SIZE 256 
#define WARNING_PIPE_SIZE 16384000 /* 16 Mb */
#define MAX_FAILS 5 
#define MAX_SEQNUM 65536 
#define MAX_RG_COUNT_ERR 3 

struct channels_list_entry;
typedef void (*pkt_handler) (struct channels_list_entry *, struct packet_ptrs *, char **);
typedef int (*ring_cleaner) (void *, int);
typedef pm_counter_t (*skip_func) (pm_counter_t);

struct ring {
  char *base;
  char *ptr;
  char *end;
};

struct ch_buf_hdr {
  u_int64_t len;
  u_int32_t seq;
  u_int32_t num;
};

struct ch_status {
  u_int8_t wakeup;		/* plugin is polling */ 
  u_int64_t last_buf_off;	/* offset of last committed buffer */
};

struct sampling {
  pm_counter_t rate;
  pm_counter_t counter; 
  pm_counter_t sample_pool;
  pm_counter_t sampled_pkts;
  skip_func sf;
};

struct aggregate_filter {
  int *num;
  struct bpf_program **table;
};

struct plugin_type_entry {
  u_int8_t id;
  char string[16];
  void (*func)(int, struct configuration *, void *);
};

struct plugins_list_entry {
  u_int8_t id;
  pid_t pid;
  char name[SRVBUFLEN];
  struct configuration cfg;
  int pipe[2];
  struct plugin_type_entry type;
  struct plugins_list_entry *next;
};

#ifdef WITH_ZMQ
#include "zmq_common.h"
#endif

struct channels_list_entry {
  pm_cfgreg_t aggregation;
  pm_cfgreg_t aggregation_2;
  u_int64_t buf;	/* buffer base */
  u_int64_t bufptr;	/* buffer current */
  u_int64_t bufend;	/* buffer end */
  struct ring rg;	
  struct ch_buf_hdr hdr;
  struct ch_status *status;
  ring_cleaner clean_func;
  u_int8_t request;					/* does the plugin support on-request wakeup ? */
  u_int8_t reprocess;					/* do we need to jump back for packet reprocessing ? */
  u_int8_t already_reprocessed;				/* loop avoidance for packet reprocessing */
  int datasize;
  u_int64_t bufsize;		
  int var_size;
  int buffer_immediate;
  int same_aggregate;
  pkt_handler phandler[N_PRIMITIVES];
  int pipe;
  pid_t core_pid;
  pm_id_t tag;						/* post-tagging tag */
  pm_id_t tag2;						/* post-tagging tag2 */
  struct pretag_filter tag_filter; 			/* filter aggregates basing on their tag */
  struct pretag_filter tag2_filter; 			/* filter aggregates basing on their tag2 */
  struct pretag_label_filter label_filter;		/* filter aggregates basing on their label */
  struct aggregate_filter agg_filter; 			/* filter aggregates basing on L2-L4 primitives */
  struct sampling s;
  struct plugins_list_entry *plugin;			/* backpointer to the plugin the actual channel belongs to */
  struct extra_primitives extras;			/* offset for non-standard aggregation primitives structures */
#ifdef WITH_ZMQ
  struct p_zmq_host zmq_host;
#endif
};

#if (defined __PLUGIN_HOOKS_C)
extern struct channels_list_entry channels_list[MAX_N_PLUGINS];
#endif

/* Function prototypes */
#if (!defined __PLUGIN_HOOKS_C)
#define EXT extern
#else
#define EXT
#endif
EXT void load_plugins(struct plugin_requests *);
EXT void exec_plugins(struct packet_ptrs *, struct plugin_requests *);
EXT void load_plugin_filters(int);
EXT struct channels_list_entry *insert_pipe_channel(int, struct configuration *, int); 
EXT void delete_pipe_channel(int);
EXT void sort_pipe_channels();
EXT void init_pipe_channels();
EXT int evaluate_filters(struct aggregate_filter *, u_char *, struct pcap_pkthdr *);
EXT void recollect_pipe_memory(struct channels_list_entry *);
EXT void init_random_seed();
EXT void fill_pipe_buffer();
EXT int check_pipe_buffer_space(struct channels_list_entry *, struct pkt_vlen_hdr_primitives *, int); 
EXT void return_pipe_buffer_space(struct channels_list_entry *, int);
EXT int check_shadow_status(struct packet_ptrs *, struct channels_list_entry *);
EXT int pkt_data_clean(void *, int);
EXT int pkt_payload_clean(void *, int);
EXT int pkt_msg_clean(void *, int);
EXT int pkt_extras_clean(void *, int);
EXT void evaluate_sampling(struct sampling *, pm_counter_t *, pm_counter_t *, pm_counter_t *);
EXT pm_counter_t take_simple_random_skip(pm_counter_t);
EXT pm_counter_t take_simple_systematic_skip(pm_counter_t);
EXT void plugin_pipe_zmq_compile_check();
EXT void plugin_pipe_check(struct configuration *);
EXT void P_zmq_pipe_init(void *, int *, u_int32_t *);
#undef EXT

#if (defined __PLUGIN_HOOKS_C)
#define EXT extern
#else
#define EXT
#endif
EXT void imt_plugin(int, struct configuration *, void *);
EXT void print_plugin(int, struct configuration *, void *);
EXT void jsonudp_plugin(int, struct configuration *, void *);
EXT void nfprobe_plugin(int, struct configuration *, void *);
EXT void sfprobe_plugin(int, struct configuration *, void *);
EXT void tee_plugin(int, struct configuration *, void *);

#ifdef WITH_MYSQL
EXT void mysql_plugin(int, struct configuration *, void *);
#endif 

#ifdef WITH_PGSQL
EXT void pgsql_plugin(int, struct configuration *, void *);
#endif

#ifdef WITH_SQLITE3
EXT void sqlite3_plugin(int, struct configuration *, void *);
#endif

#ifdef WITH_MONGODB
EXT void mongodb_plugin(int, struct configuration *, void *);
EXT void mongodb_legacy_warning(int, struct configuration *, void *);
#endif

#ifdef WITH_RABBITMQ
EXT void amqp_plugin(int, struct configuration *, void *);
#endif

#ifdef WITH_KAFKA
EXT void kafka_plugin(int, struct configuration *, void *);
#endif
#undef EXT
