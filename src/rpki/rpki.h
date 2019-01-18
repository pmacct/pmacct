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

/* defines */
#define ROA_STATUS_UNKNOWN	0
#define ROA_STATUS_INVALID	1
#define ROA_STATUS_VALID	2
#define ROA_STATUS_MAX		2

/* prototypes */
#if !defined(__RPKI_C)
#define EXT extern
#else
#define EXT
#endif
EXT void rpki_daemon_wrapper();
EXT void rpki_prepare_thread();
EXT void rpki_daemon();
EXT void rpki_init_dummy_peer(struct bgp_peer *);
EXT int rpki_attrhash_cmp(const void *, const void *);
EXT int rpki_roas_file_load(char *);
EXT int rpki_info_add(struct bgp_peer *, struct prefix *, as_t, u_int8_t);
EXT u_int8_t rpki_prefix_lookup(struct prefix *, struct aspath *);
EXT int rpki_prefix_lookup_node_match_cmp(struct bgp_info *, struct node_match_cmp_term2 *);
EXT void rpki_link_misc_structs(struct bgp_misc_structs *);
#undef EXT

/* global variables */
#if (!defined __RPKI_C)
#define EXT extern
#else
#define EXT
#endif

EXT struct bgp_rt_structs *rpki_routing_db;
EXT struct bgp_misc_structs *rpki_misc_db;
#undef EXT
