/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
*/

/* 
 Originally based on Quagga BGP routing table which is:

 Copyright (C) 1998, 2001 Kunihiro Ishiguro

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _BGP_TABLE_H_
#define _BGP_TABLE_H_

#define DEFAULT_BGP_INFO_HASH 13
#define DEFAULT_BGP_INFO_PER_PEER_HASH 1
#define BGP_NODE_VECTOR_MAX_DEPTH 128

struct bgp_table
{
  /* afi/safi of this table */
  afi_t afi;
  safi_t safi;
  
  /* The owner of this 'bgp_table' structure. */
  void *owner;

  struct bgp_node *top;
  
  unsigned long count;
};

struct bgp_node
{
  struct prefix p;

  struct bgp_table *table;
  struct bgp_node *parent;
  struct bgp_node *link[2];
#define l_left   link[0]
#define l_right  link[1]

  void **info;

  unsigned int lock;
};

struct bgp_msg_extra_data {
  u_int8_t id;
  u_int16_t len;
  void *data;
};

struct bgp_attr_extra
{
  rd_t rd;
  u_char label[3];
  path_id_t path_id;
  u_int64_t aigp;
  u_int32_t psid_li;
};

struct bgp_info
{
  struct bgp_info *next;
  struct bgp_info *prev;
  struct bgp_peer *peer;
  struct bgp_attr *attr;
  struct bgp_attr_extra *attr_extra;
  struct bgp_msg_extra_data bmed;
};

struct node_match_cmp_term2 {
  struct bgp_peer *peer;
  afi_t afi;
  safi_t safi;
  rd_t *rd;
  struct host_addr *peer_dst_ip;

  /* mainly used for RPKI purposes */
  struct prefix *p;
  as_t last_as;
  int ret_code;
};

struct bgp_node_vector_entry {
  struct prefix *p;
  struct bgp_info *info;
};

struct bgp_node_vector {
  u_int8_t entries;
  struct bgp_node_vector_entry v[BGP_NODE_VECTOR_MAX_DEPTH];
}; 

/* Prototypes */
extern struct bgp_table *bgp_table_init (afi_t, safi_t);
extern void bgp_unlock_node (struct bgp_peer *, struct bgp_node *node);
extern struct bgp_node *bgp_table_top (struct bgp_peer *, const struct bgp_table *const);
extern struct bgp_node *bgp_route_next (struct bgp_peer *, struct bgp_node *);
extern struct bgp_node *bgp_node_get (struct bgp_peer *, struct bgp_table *const, struct prefix *);
extern struct bgp_node *bgp_lock_node (struct bgp_peer *, struct bgp_node *node);
extern void bgp_node_vector_debug(struct bgp_node_vector *, struct prefix *);
extern void bgp_node_match (const struct bgp_table *, struct prefix *, struct bgp_peer *,
			 u_int32_t (*modulo_func)(struct bgp_peer *, path_id_t *, int),
			 int (*cmp_func)(struct bgp_info *, struct node_match_cmp_term2 *),
			 struct node_match_cmp_term2 *, struct bgp_node_vector *,
			 struct bgp_node **result_node, struct bgp_info **result_info);
extern void bgp_node_match_ipv4 (const struct bgp_table *, struct in_addr *, struct bgp_peer *,
			      u_int32_t (*modulo_func)(struct bgp_peer *, path_id_t *, int),
			      int (*cmp_func)(struct bgp_info *, struct node_match_cmp_term2 *),
			      struct node_match_cmp_term2 *, struct bgp_node_vector *,
			      struct bgp_node **result_node, struct bgp_info **result_info);
extern void bgp_node_match_ipv6 (const struct bgp_table *, struct in6_addr *, struct bgp_peer *,
			      u_int32_t (*modulo_func)(struct bgp_peer *, path_id_t *, int),
			      int (*cmp_func)(struct bgp_info *, struct node_match_cmp_term2 *),
			      struct node_match_cmp_term2 *, struct bgp_node_vector *,
			      struct bgp_node **result_node, struct bgp_info **result_info);
extern void bgp_table_free (struct bgp_table *);
#endif 
