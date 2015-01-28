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

#include "bgp_hash.h"
#include "bgp_prefix.h"
#include "bgp_packet.h"
#include "bgp_table.h"
#include "bgp_community.h"
#include "bgp_ecommunity.h"
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

/* BGP Attribute flags. */
#define BGP_ATTR_FLAG_OPTIONAL  0x80    /* Attribute is optional. */
#define BGP_ATTR_FLAG_TRANS     0x40    /* Attribute is transitive. */
#define BGP_ATTR_FLAG_PARTIAL   0x20    /* Attribute is partial. */
#define BGP_ATTR_FLAG_EXTLEN    0x10    /* Extended length flag. */

/* BGP misc */
#define MAX_BGP_PEERS_DEFAULT 4
#define MAX_HOPS_FOLLOW_NH 20
#define MAX_NH_SELF_REFERENCES 1

/* Maximum BGP standard/extended community patterns supported:
   nfacctd_bgp_stdcomm_pattern, nfacctd_bgp_extcomm_pattern */
#define MAX_BGP_COMM_PATTERNS 16

/* requires as_t */
#include "bgp_aspath.h"

/* structures */
struct bgp_peer_buf {
  char *base;
  int len;
  int truncated_len;
};

struct bgp_peer {
  int fd;
  int lock;
  u_int8_t status;
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
  u_int8_t cap_add_paths;
  u_int32_t msglen;
  struct bgp_peer_buf buf;
  struct bgp_peer_log *log;
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
  unsigned long refcnt;
  u_int32_t flag;
  struct in_addr nexthop;
  struct host_addr mp_nexthop;
  u_int32_t med;
  u_int32_t local_pref;
  struct {
	u_int32_t as;
	u_char ttl;
  } pathlimit;
  u_char origin;
};

struct bgp_comm_range {
  u_int32_t first;
  u_int32_t last;
};

/* prototypes */
#if (!defined __BGP_C)
#define EXT extern
#else
#define EXT
#endif
EXT void nfacctd_bgp_wrapper();
EXT void skinny_bgp_daemon();
EXT int bgp_marker_check(struct bgp_header *, int);
EXT int bgp_keepalive_msg(char *);
EXT int bgp_open_msg(char *, char *, int, struct bgp_peer *);
EXT int bgp_update_msg(struct bgp_peer *, char *);
EXT int bgp_attr_parse(struct bgp_peer *, struct bgp_attr *, char *, int, struct bgp_nlri *, struct bgp_nlri *);
EXT int bgp_attr_parse_community(struct bgp_peer *, u_int16_t, struct bgp_attr *, char *, u_int8_t);
EXT int bgp_attr_parse_ecommunity(struct bgp_peer *, u_int16_t, struct bgp_attr *, char *, u_int8_t);
EXT int bgp_attr_parse_aspath(struct bgp_peer *, u_int16_t, struct bgp_attr *, char *, u_int8_t);
EXT int bgp_attr_parse_as4path(struct bgp_peer *, u_int16_t, struct bgp_attr *, char *, u_int8_t, struct aspath **);
EXT int bgp_attr_parse_nexthop(struct bgp_peer *, u_int16_t, struct bgp_attr *, char *, u_int8_t);
EXT int bgp_attr_parse_med(struct bgp_peer *, u_int16_t, struct bgp_attr *, char *, u_char);
EXT int bgp_attr_parse_local_pref(struct bgp_peer *, u_int16_t, struct bgp_attr *, char *, u_char);
EXT int bgp_attr_parse_origin(struct bgp_peer *, u_int16_t, struct bgp_attr *, char *, u_char);
EXT int bgp_attr_parse_mp_reach(struct bgp_peer *, u_int16_t, struct bgp_attr *, char *, struct bgp_nlri *);
EXT int bgp_attr_parse_mp_unreach(struct bgp_peer *, u_int16_t, struct bgp_attr *, char *, struct bgp_nlri *);
EXT int bgp_nlri_parse(struct bgp_peer *, void *, struct bgp_nlri *);
EXT int bgp_process_update(struct bgp_peer *, struct prefix *, void *, afi_t, safi_t, rd_t *, path_id_t *, char *);
EXT int bgp_process_withdraw(struct bgp_peer *, struct prefix *, void *, afi_t, safi_t, rd_t *, path_id_t *, char *);
EXT int bgp_afi2family(int);
EXT int bgp_rd2str(char *, rd_t *);
EXT int bgp_str2rd(rd_t *, char *);
EXT struct bgp_info_extra *bgp_info_extra_new();
EXT void bgp_info_extra_free(struct bgp_info_extra **);
EXT struct bgp_info_extra *bgp_info_extra_get(struct bgp_info *);
EXT struct bgp_info *bgp_info_new();
EXT void bgp_info_add(struct bgp_node *, struct bgp_info *, u_int32_t);
EXT void bgp_info_delete(struct bgp_node *, struct bgp_info *, u_int32_t);
EXT void bgp_info_free(struct bgp_info *);
EXT void bgp_attr_init();
EXT struct bgp_attr *bgp_attr_intern(struct bgp_attr *);
EXT void bgp_attr_unintern (struct bgp_attr *);
EXT void *bgp_attr_hash_alloc (void *);
EXT int bgp_peer_init(struct bgp_peer *);
EXT void bgp_peer_close(struct bgp_peer *);
EXT void bgp_peer_info_delete(struct bgp_peer *);
EXT int bgp_attr_munge_as4path(struct bgp_peer *, struct bgp_attr *, struct aspath *);
EXT void load_comm_patterns(char **, char **, char **);
EXT void load_peer_src_as_comm_ranges(char *, char *);
EXT void evaluate_comm_patterns(char *, char *, char **, int);
EXT as_t evaluate_last_asn(struct aspath *);
EXT as_t evaluate_first_asn(char *);
EXT void bgp_srcdst_lookup(struct packet_ptrs *);
EXT void bgp_follow_nexthop_lookup(struct packet_ptrs *);
EXT void write_neighbors_file(char *);
EXT void process_bgp_md5_file(int, struct bgp_md5_table *);
EXT u_int32_t bgp_route_info_modulo_pathid(struct bgp_peer *, path_id_t *);

EXT unsigned int attrhash_key_make(void *);
EXT int attrhash_cmp(const void *, const void *);
EXT void attrhash_init(struct hash **);

EXT void cache_to_pkt_bgp_primitives(struct pkt_bgp_primitives *, struct cache_bgp_primitives *);
EXT void pkt_to_cache_bgp_primitives(struct cache_bgp_primitives *, struct pkt_bgp_primitives *, pm_cfgreg_t);
EXT void free_cache_bgp_primitives(struct cache_bgp_primitives **);
EXT void bgp_config_checks(struct configuration *);

/* global variables */
EXT struct bgp_peer *peers;
EXT struct hash *attrhash;
EXT struct hash *ashash;
EXT struct hash *comhash;
EXT struct hash *ecomhash;
EXT char *std_comm_patterns[MAX_BGP_COMM_PATTERNS];
EXT char *ext_comm_patterns[MAX_BGP_COMM_PATTERNS];
EXT char *std_comm_patterns_to_asn[MAX_BGP_COMM_PATTERNS];
EXT struct bgp_comm_range peer_src_as_ifrange; 
EXT struct bgp_comm_range peer_src_as_asrange; 
EXT struct bgp_table *rib[AFI_MAX][SAFI_MAX];
EXT u_int32_t (*bgp_route_info_modulo)(struct bgp_peer *, path_id_t *);

#undef EXT
#endif 
