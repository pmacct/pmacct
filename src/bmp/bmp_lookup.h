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

#ifndef BMP_LOOKUP_H
#define BMP_LOOKUP_H

/* includes */

/* defines */

/* prototypes */
extern void bmp_srcdst_lookup(struct packet_ptrs *);
extern struct bgp_peer *bgp_lookup_find_bmp_peer(struct sockaddr *, struct xflow_status_entry *, u_int16_t, int);
extern u_int32_t bmp_route_info_modulo_pathid(struct bgp_peer *, path_id_t *, int);
extern int bgp_lookup_node_match_cmp_bmp(struct bgp_info *, struct node_match_cmp_term2 *);

#endif //BMP_LOOKUP_H
