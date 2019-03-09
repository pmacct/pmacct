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

/* prototypes */
#if !defined(__RPKI_UTIL_C)
#define EXT extern
#else
#define EXT
#endif
EXT void rpki_init_dummy_peer(struct bgp_peer *);
EXT int rpki_attrhash_cmp(const void *, const void *);
EXT const char *rpki_roa_print(u_int8_t);
EXT u_int8_t rpki_str2roa(char *);
EXT void rpki_ribs_free(struct bgp_peer *, struct bgp_table *, struct bgp_table *);
EXT void rpki_ribs_reset(struct bgp_peer *, struct bgp_table **, struct bgp_table **);
EXT void rpki_link_misc_structs(struct bgp_misc_structs *);
#undef EXT
