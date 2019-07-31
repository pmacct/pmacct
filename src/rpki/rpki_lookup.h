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

#ifndef RPKI_LOOKUP_H
#define RPKI_LOOKUP_H

/* prototypes */
extern u_int8_t rpki_prefix_lookup(struct prefix *, as_t);
extern u_int8_t rpki_vector_prefix_lookup(struct bgp_node_vector *);
extern int rpki_prefix_lookup_node_match_cmp(struct bgp_info *, struct node_match_cmp_term2 *);

#endif //RPKI_LOOKUP_H
