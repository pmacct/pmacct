/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2014 by Paolo Lucente
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

/* AFI and SAFI type. */
typedef u_int16_t afi_t;
typedef u_int8_t safi_t;

typedef enum
{
  BGP_TABLE_MAIN,
  BGP_TABLE_RSCLIENT,
} bgp_table_t;

struct bgp_table
{
  bgp_table_t type;
  
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
/*
  struct bgp_adj_out *adj_out;

  struct bgp_adj_in *adj_in;

  struct bgp_node *prn;

  unsigned int lock;

  u_char flags;
#define BGP_NODE_PROCESS_SCHEDULED	(1 << 0)
*/
};

struct bgp_info_extra
{
  rd_t rd;
  u_char label[3];
  path_id_t path_id;
};

struct bgp_info
{
  struct bgp_info *next;
  struct bgp_info *prev;
  struct bgp_peer *peer;
  struct bgp_attr *attr;
  struct bgp_info_extra *extra;
};

/* Prototypes */
#if (!defined __BGP_TABLE_C)
#define EXT extern
#else
#define EXT
#endif
EXT struct bgp_table *bgp_table_init (afi_t, safi_t);
EXT void bgp_table_finish (struct bgp_table **);
EXT void bgp_unlock_node (struct bgp_node *node);
EXT struct bgp_node *bgp_table_top (const struct bgp_table *const);
EXT struct bgp_node *bgp_route_next (struct bgp_node *);
EXT struct bgp_node *bgp_route_next_until (struct bgp_node *, struct bgp_node *);
EXT struct bgp_node *bgp_node_get (struct bgp_table *const, struct prefix *);
EXT struct bgp_node *bgp_lock_node (struct bgp_node *node);
EXT struct bgp_node *bgp_node_match (const struct bgp_table *, struct prefix *, struct bgp_peer *);
EXT struct bgp_node *bgp_node_match_ipv4 (const struct bgp_table *, struct in_addr *, struct bgp_peer *);
#ifdef ENABLE_IPV6
EXT struct bgp_node *bgp_node_match_ipv6 (const struct bgp_table *, struct in6_addr *, struct bgp_peer *);
#endif /* ENABLE_IPV6 */
EXT unsigned long bgp_table_count (const struct bgp_table *const);

#undef EXT
#endif 
