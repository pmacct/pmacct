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

#ifndef _BGP_UTIL_H_
#define _BGP_UTIL_H_

/* prototypes */
#if (!defined __BGP_UTIL_C)
#define EXT extern
#else
#define EXT
#endif
EXT int bgp_afi2family(int);
EXT int bgp_rd2str(char *, rd_t *);
EXT int bgp_str2rd(rd_t *, char *);
EXT int bgp_label2str(char *, u_char *);
EXT void load_comm_patterns(char **, char **, char **, char **);
EXT void load_peer_src_as_comm_ranges(char *, char *);
EXT void evaluate_comm_patterns(char *, char *, char **, int);
EXT as_t evaluate_last_asn(struct aspath *);
EXT as_t evaluate_first_asn(char *);
EXT void evaluate_bgp_aspath_radius(char *, int, int);
EXT void copy_stdcomm_to_asn(char *, as_t *, int);
EXT void write_neighbors_file(char *, int);
EXT struct bgp_rt_structs *bgp_select_routing_db(int);
EXT void process_bgp_md5_file(int, struct bgp_md5_table *);
EXT void bgp_config_checks(struct configuration *);
EXT struct bgp_misc_structs *bgp_select_misc_db(int);
EXT void bgp_link_misc_structs(struct bgp_misc_structs *);

EXT struct bgp_info_extra *bgp_info_extra_new(struct bgp_info *);
EXT void bgp_info_extra_free(struct bgp_peer *, struct bgp_info_extra **);
EXT struct bgp_info_extra *bgp_info_extra_get(struct bgp_info *);
EXT struct bgp_info_extra *bgp_info_extra_process(struct bgp_peer *, struct bgp_info *, safi_t, path_id_t *, rd_t *, char *);

EXT struct bgp_info *bgp_info_new(struct bgp_peer *);
EXT void bgp_info_add(struct bgp_peer *, struct bgp_node *, struct bgp_info *, u_int32_t);
EXT void bgp_info_delete(struct bgp_peer *, struct bgp_node *, struct bgp_info *, u_int32_t);
EXT void bgp_info_free(struct bgp_peer *, struct bgp_info *);
EXT void bgp_attr_init(int, struct bgp_rt_structs *);
EXT struct bgp_attr *bgp_attr_intern(struct bgp_peer *, struct bgp_attr *);
EXT void bgp_attr_unintern (struct bgp_peer *, struct bgp_attr *);
EXT void *bgp_attr_hash_alloc (void *);
EXT int bgp_attr_munge_as4path(struct bgp_peer *, struct bgp_attr *, struct aspath *);

EXT int bgp_peer_init(struct bgp_peer *, int);
EXT void bgp_peer_close(struct bgp_peer *, int, int, int, u_int8_t, u_int8_t, char *);
EXT char *bgp_peer_print(struct bgp_peer *);
EXT void bgp_peer_info_delete(struct bgp_peer *);

EXT void bgp_batch_init(struct bgp_peer_batch *, int, int);
EXT void bgp_batch_reset(struct bgp_peer_batch *, time_t);
EXT int bgp_batch_is_admitted(struct bgp_peer_batch *, time_t);
EXT int bgp_batch_is_enabled(struct bgp_peer_batch *);
EXT int bgp_batch_is_expired(struct bgp_peer_batch *, time_t);
EXT int bgp_batch_is_not_empty(struct bgp_peer_batch *);
EXT void bgp_batch_increase_counter(struct bgp_peer_batch *);
EXT void bgp_batch_decrease_counter(struct bgp_peer_batch *);
EXT void bgp_batch_rollback(struct bgp_peer_batch *);

EXT int bgp_peer_cmp(const void *, const void *);
EXT int bgp_peer_host_addr_cmp(const void *, const void *);
EXT void bgp_peer_free(void *);
EXT void bgp_peers_bintree_walk_print(const void *, const VISIT, const int);
EXT void bgp_peers_bintree_walk_delete(const void *, const VISIT, const int);

EXT unsigned int attrhash_key_make(void *);
EXT int attrhash_cmp(const void *, const void *);
EXT void attrhash_init(int, struct hash **);
#undef EXT
#endif 
