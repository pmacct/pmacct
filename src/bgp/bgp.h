/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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
#include <pthread.h>
#include <sys/poll.h>
#include "bgp_prefix.h"
#include "bgp_packet.h"
#include "bgp_table.h"
#include "bgp_logdump.h"

#ifndef _BGP_H_
#define _BGP_H_

/* defines */

/* BGP finite state machine status.  */
#define Idle                                     1
#define Connect                                  2
#define Active                                   3
#define OpenSent                                 4
#define OpenConfirm                              5
#define Established                              6
#define Clearing                                 7
#define Deleted                                  8

#define BGP_ATTR_MIN_LEN        3       /* Attribute flag, type length. */

/* BGP4 attribute type codes.  */
#define BGP_ATTR_ORIGIN                          1
#define BGP_ATTR_AS_PATH                         2
#define BGP_ATTR_NEXT_HOP                        3
#define BGP_ATTR_MULTI_EXIT_DISC                 4
#define BGP_ATTR_LOCAL_PREF                      5
#define BGP_ATTR_ATOMIC_AGGREGATE                6
#define BGP_ATTR_AGGREGATOR                      7
#define BGP_ATTR_COMMUNITIES                     8
#define BGP_ATTR_ORIGINATOR_ID                   9
#define BGP_ATTR_CLUSTER_LIST                   10
#define BGP_ATTR_DPA                            11
#define BGP_ATTR_ADVERTISER                     12
#define BGP_ATTR_RCID_PATH                      13
#define BGP_ATTR_MP_REACH_NLRI                  14
#define BGP_ATTR_MP_UNREACH_NLRI                15
#define BGP_ATTR_EXT_COMMUNITIES                16
#define BGP_ATTR_AS4_PATH                       17
#define BGP_ATTR_AS4_AGGREGATOR                 18
#define BGP_ATTR_AS_PATHLIMIT                   21
#define BGP_ATTR_AIGP				26
#define BGP_ATTR_LARGE_COMMUNITIES		32 /* rfc8092 */
#define BGP_ATTR_PREFIX_SID			40

/* BGP4 internal bitmap type codes.  */
#define BGP_BMAP_ATTR_MULTI_EXIT_DISC		0x01
#define BGP_BMAP_ATTR_LOCAL_PREF		0x02
#define BGP_BMAP_ATTR_AIGP			0x04

#define BGP_NLRI_UNDEFINED			0
#define BGP_NLRI_UPDATE				1
#define BGP_NLRI_WITHDRAW			2

/* BGP Attribute flags. */
#define BGP_ATTR_FLAG_OPTIONAL  0x80    /* Attribute is optional. */
#define BGP_ATTR_FLAG_TRANS     0x40    /* Attribute is transitive. */
#define BGP_ATTR_FLAG_PARTIAL   0x20    /* Attribute is partial. */
#define BGP_ATTR_FLAG_EXTLEN    0x10    /* Extended length flag. */

/* BGP misc */
#define MAX_BGP_PEERS_DEFAULT	4
#define MAX_HOPS_FOLLOW_NH	20
#define MAX_NH_SELF_REFERENCES	1
#define BGP_XCONNECT_STRLEN	(2 * (INET6_ADDRSTRLEN + PORT_STRLEN + 1) + 4) 

/* Maximum BGP community patterns supported: bgp_daemon_stdcomm_pattern,
   bgp_daemon_extcomm_pattern, bgp_blackhole_stdcomm_list, etc. */
#define MAX_BGP_COMM_PATTERNS	16
#define MAX_BGP_COMM_ELEMS	MAX_BGP_COMM_PATTERNS

#define BGP_DAEMON_NONE		0
#define BGP_DAEMON_TRUE		1
#define BGP_DAEMON_ONLINE	1

#define BGP_MSG_EXTRA_DATA_NONE	0
#define BGP_MSG_EXTRA_DATA_BMP	1

#define BGP_LOOKUP_NOPEER	2
#define BGP_LOOKUP_NOPREFIX	1
#define BGP_LOOKUP_OK		0
#define BGP_LOOKUP_ERR		-1

#define BGP_ORIGIN_IGP		0
#define BGP_ORIGIN_EGP		1
#define BGP_ORIGIN_INCOMPLETE	2
#define BGP_ORIGIN_MAX		2
#define BGP_ORIGIN_UNKNOWN	3

#define BGP_PREFIX_SID_LI_TLV		1
#define BGP_PREFIX_SID_OSRGB_TLV	2

/* structures */
struct bgp_dump_event {
  struct timeval tstamp;
  char tstamp_str[SRVBUFLEN];
  u_int32_t period;
};

struct bgp_rt_structs {
  struct hash *attrhash;
  struct hash *ashash;
  struct hash *comhash;
  struct hash *ecomhash;
  struct hash *lcomhash;
  struct bgp_table *rib[AFI_MAX][SAFI_MAX];
};

struct bgp_peer_cache {
  struct bgp_peer *ptr;
  struct bgp_peer_cache *next;
};

struct bgp_peer_cache_bucket {
  pthread_mutex_t mutex;
  struct bgp_peer_cache *e;
};

struct bgp_xconnect {
  u_int32_t id;

  struct sockaddr_storage dst;  /* BGP receiver IP address and port */
  socklen_t dst_len;

  struct sockaddr_storage src;  /* BGP peer IP address and port */
  socklen_t src_len;

  struct host_addr src_addr;    /* IP prefix to match multiple BGP peers */
  struct host_mask src_mask;
};

struct bgp_xconnects {
  struct bgp_xconnect *pool;
  int num;
};

struct bgp_peer_stats {
    u_int64_t packets; /* Datagrams received */
    u_int64_t packet_bytes; /* Bytes read off the socket */
    u_int64_t msg_bytes; /* Bytes in the decoded messages */
    u_int64_t msg_errors; /* Errors detected in message content */
    time_t last_check; /* Timestamp when stats were last checked */
};

struct bgp_peer_buf {
  char *base;
  u_int32_t tot_len; /* total buffer length */
  u_int32_t cur_len; /* current message consumed length (for segmented reads) */
  u_int32_t exp_len; /* current message expected length */
#if defined WITH_KAFKA
  void *kafka_msg;
#endif
};

struct bgp_peer {
  int idx;
  int fd;
  int lock;
  int type; /* ie. BGP vs BMP */
  u_int8_t status;
  u_int8_t version;
  as_t myas;
  as_t as;
  u_int16_t ht;
  time_t last_keepalive;
  struct host_addr id;
  struct host_addr addr;
  char addr_str[INET6_ADDRSTRLEN];
  u_int16_t tcp_port;
  u_int8_t cap_mp;
  char *cap_4as;
  u_int8_t cap_add_paths[AFI_MAX][SAFI_MAX];
  u_int32_t msglen;
  struct bgp_peer_stats stats;
  struct bgp_peer_buf buf;
  struct bgp_peer_log *log;

  /*
     bmp_peer.self.bmp_se:		pointer to struct bmp_dump_se_ll
     bmp_peer.bgp_peers[n].bmp_se:	backpointer to parent struct bmp_peer
  */
  void *bmp_se;

  struct bgp_xconnect xc;
  struct bgp_peer_buf xbuf;
  int xconnect_fd;
  int parsed_proxy_header;
};

struct bgp_msg_data {
  struct bgp_peer *peer;
  struct bgp_msg_extra_data extra;
  int is_blackhole;
};

struct bgp_misc_structs {
  struct bgp_peer_log *peers_log;
  u_int64_t log_seq;
  struct timeval log_tstamp;
  char log_tstamp_str[SRVBUFLEN];
  struct bgp_node_vector *bnv;
  struct bgp_dump_event dump;
  char *peer_str; /* "bmp_router", "peer_src_ip", "peer_ip", etc. */
  char *peer_port_str; /* "bmp_router_port", "peer_src_ip_port", etc. */
  char *log_str; /* BGP, BMP, thread, daemon, etc. */
  int is_thread;
  int is_readonly; /* disables locking! set to true only in a dump child process */
  int has_lglass;
  int has_blackhole;
  int skip_rib;

#if defined WITH_RABBITMQ
  struct p_amqp_host *msglog_amqp_host;
#endif
#if defined WITH_KAFKA
  struct p_kafka_host *msglog_kafka_host;
#endif
  
  void *peers;
  int max_peers;
  void *peers_cache;
  void *peers_port_cache;
  struct log_notification *peers_limit_log;
  void *xconnects;

  char *neighbors_file;
  char *dump_file;
  char *dump_amqp_routing_key;
  int dump_amqp_routing_key_rr;
  char *dump_kafka_topic;
  int dump_kafka_topic_rr;
  char *dump_kafka_partition_key;
#if defined WITH_AVRO
  avro_schema_t dump_avro_schema[MAX_AVRO_SCHEMA];
#endif
  char *dump_kafka_avro_schema_registry;
  char *msglog_file;
  int msglog_output;
  char *msglog_amqp_routing_key;
  int msglog_amqp_routing_key_rr;
  char *msglog_kafka_topic;
  int msglog_kafka_topic_rr;
  char *msglog_kafka_partition_key;
#if defined WITH_AVRO
  avro_schema_t msglog_avro_schema[MAX_AVRO_SCHEMA];
#endif
  char *msglog_kafka_avro_schema_registry;
  char *avro_buf;
  void (*bgp_peer_log_msg_extras)(struct bgp_peer *, int, int, int, void *);
  void (*bgp_peer_logdump_initclose_extras)(struct bgp_peer *, int, void *);

  void (*bgp_peer_logdump_extra_data)(struct bgp_msg_extra_data *, int, void *);
  int (*bgp_extra_data_process)(struct bgp_msg_extra_data *, struct bgp_info *, int, int);
  int (*bgp_extra_data_cmp)(struct bgp_msg_extra_data *, struct bgp_msg_extra_data *);
  void (*bgp_extra_data_free)(struct bgp_msg_extra_data *);

  int table_peer_buckets;
  int table_per_peer_buckets;
  int table_attr_hash_buckets;
  int table_per_peer_hash;
  u_int32_t (*route_info_modulo)(struct bgp_peer *, path_id_t *, int);
  struct bgp_peer *(*bgp_lookup_find_peer)(struct sockaddr *, struct xflow_status_entry *, u_int16_t, int);
  int (*bgp_lookup_node_match_cmp)(struct bgp_info *, struct node_match_cmp_term2 *);

  int msglog_backend_methods;
  int dump_backend_methods;
  int dump_input_backend_methods;

  int (*bgp_msg_open_router_id_check)(struct bgp_msg_data *);

  void *bgp_blackhole_zmq_host;
};

/* these includes require definition of bgp_rt_structs and bgp_peer */
#include "bgp_aspath.h"
#include "bgp_community.h"
#include "bgp_ecommunity.h"
#include "bgp_lcommunity.h"
/* this include requires definition of bgp_peer */
#include "bgp_hash.h"

struct bgp_peer_batch {
  int num;
  int num_current;
  time_t base_stamp;
  int interval;
};

struct bgp_nlri {
  afi_t afi;
  safi_t safi;
  u_char *nlri;
  u_int16_t length;
};

struct bgp_attr {
  struct aspath *aspath;
  struct community *community;
  struct ecommunity *ecommunity;
  struct lcommunity *lcommunity;
  unsigned long refcnt;
  u_int32_t flag;
  struct in_addr nexthop;
  struct host_addr mp_nexthop;
  u_int32_t med;
  u_int32_t local_pref;
  u_int8_t origin;
  u_int8_t bitmap;
};

struct bgp_comm_range {
  u_int32_t first;
  u_int32_t last;
};

/* Looking Glass */
struct bgp_lg_req {
  u_int32_t type;
  u_int32_t num;
  void *data;
};

struct bgp_lg_rep_data {
  void *ptr;
  struct bgp_lg_rep_data *next;
};

struct bgp_lg_rep {
  u_int32_t type;
  u_int32_t results;
  struct bgp_lg_rep_data *data;
};

struct bgp_lg_req_ipl_data {
  struct sockaddr peer;
  struct prefix pref;
  rd_t rd;
};

struct bgp_lg_rep_ipl_data {
  afi_t afi;
  safi_t safi;
  struct prefix *pref;
  struct bgp_info *info;
};

struct bgp_lg_rep_gp_data {
  struct bgp_peer *peer;
};

#include "bgp_msg.h"
#include "bgp_lookup.h"
#include "bgp_util.h"

/* prototypes */
extern void bgp_daemon_wrapper();
extern int skinny_bgp_daemon();
extern void skinny_bgp_daemon_online();
extern void bgp_prepare_thread();
extern void bgp_prepare_daemon();
extern void bgp_daemon_msglog_prepare_sd_schemas();

/* global variables */
extern struct bgp_peer *peers;
extern struct bgp_peer_cache_bucket *peers_cache, *peers_port_cache;
extern char *std_comm_patterns[MAX_BGP_COMM_PATTERNS];
extern char *ext_comm_patterns[MAX_BGP_COMM_PATTERNS];
extern char *lrg_comm_patterns[MAX_BGP_COMM_PATTERNS];
extern char *std_comm_patterns_to_asn[MAX_BGP_COMM_PATTERNS];
extern char *lrg_comm_patterns_to_asn[MAX_BGP_COMM_PATTERNS];
extern struct bgp_comm_range peer_src_as_ifrange; 
extern struct bgp_comm_range peer_src_as_asrange; 
extern u_int32_t (*bgp_route_info_modulo)(struct bgp_peer *, path_id_t *, int);

extern struct bgp_rt_structs inter_domain_routing_dbs[FUNC_TYPE_MAX], *bgp_routing_db;
extern struct bgp_misc_structs inter_domain_misc_dbs[FUNC_TYPE_MAX], *bgp_misc_db;

extern struct bgp_xconnects bgp_xcs_map;
#endif 
