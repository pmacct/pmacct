/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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

#ifndef _BGP_LOOKUP_H_
#define _BGP_LOOKUP_H_

/* prototypes */
#if (!defined __BGP_LOOKUP_C)
#define EXT extern
#else
#define EXT
#endif
EXT void bgp_srcdst_lookup(struct packet_ptrs *, int);
EXT void bgp_follow_nexthop_lookup(struct packet_ptrs *, int);
EXT struct bgp_peer *bgp_lookup_find_bgp_peer(struct sockaddr *, struct xflow_status_entry *, u_int16_t, int); 
EXT u_int32_t bgp_route_info_modulo_pathid(struct bgp_peer *, path_id_t *, int);
EXT int bgp_lookup_node_match_cmp_bgp(struct bgp_info *, struct node_match_cmp_term2 *);
EXT void pkt_to_cache_legacy_bgp_primitives(struct cache_legacy_bgp_primitives *, struct pkt_legacy_bgp_primitives *, pm_cfgreg_t, pm_cfgreg_t);
EXT void cache_to_pkt_legacy_bgp_primitives(struct pkt_legacy_bgp_primitives *, struct cache_legacy_bgp_primitives *);
EXT void free_cache_legacy_bgp_primitives(struct cache_legacy_bgp_primitives **);
#undef EXT
#endif 
