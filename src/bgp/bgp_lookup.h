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

#ifndef _BGP_LOOKUP_H_
#define _BGP_LOOKUP_H_

/* prototypes */
extern void bgp_srcdst_lookup(struct packet_ptrs *, int);
extern void bgp_follow_nexthop_lookup(struct packet_ptrs *, int);
extern struct bgp_peer *bgp_lookup_find_bgp_peer(struct sockaddr *, struct xflow_status_entry *, u_int16_t, int); 
extern u_int32_t bgp_route_info_modulo_pathid(struct bgp_peer *, path_id_t *, int);
extern int bgp_lookup_node_match_cmp_bgp(struct bgp_info *, struct node_match_cmp_term2 *);
extern int bgp_lookup_node_vector_unicast(struct prefix *, struct bgp_peer *, struct bgp_node_vector *);

extern void pkt_to_cache_legacy_bgp_primitives(struct cache_legacy_bgp_primitives *, struct pkt_legacy_bgp_primitives *, pm_cfgreg_t, pm_cfgreg_t);
extern void cache_to_pkt_legacy_bgp_primitives(struct pkt_legacy_bgp_primitives *, struct cache_legacy_bgp_primitives *);
extern void free_cache_legacy_bgp_primitives(struct cache_legacy_bgp_primitives **);

extern int bgp_lg_daemon_ip_lookup(struct bgp_lg_req_ipl_data *, struct bgp_lg_rep *, int);
extern int bgp_lg_daemon_get_peers(struct bgp_lg_rep *, int);
extern void bgp_lg_rep_init(struct bgp_lg_rep *);
extern struct bgp_lg_rep_data *bgp_lg_rep_data_add(struct bgp_lg_rep *);
extern void bgp_lg_rep_ipl_data_add(struct bgp_lg_rep *, afi_t, safi_t, struct prefix *, struct bgp_info *);
extern void bgp_lg_rep_gp_data_add(struct bgp_lg_rep *, struct bgp_peer *);
#endif 
