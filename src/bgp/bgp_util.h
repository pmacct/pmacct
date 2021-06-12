/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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
extern int bgp_afi2family(int);
extern u_int16_t bgp_rd_type_get(u_int16_t);
extern u_int16_t bgp_rd_origin_get(u_int16_t);
extern void bgp_rd_origin_set(rd_t *, u_int16_t);
extern const char *bgp_rd_origin_print(u_int16_t);
extern int bgp_rd_ntoh(rd_t *);
extern int bgp_rd2str(char *, rd_t *);
extern int bgp_str2rd(rd_t *, char *);
extern int bgp_label2str(char *, u_char *);
extern const char *bgp_origin_print(u_int8_t);
extern u_int8_t bgp_str2origin(char *);
extern void load_comm_patterns(char **, char **, char **, char **, char **);
extern void load_peer_src_as_comm_ranges(char *, char *);
extern void evaluate_comm_patterns(char *, char *, char **, int);
extern int bgp_str2asn(char *, as_t *);
extern as_t evaluate_last_asn(struct aspath *);
extern as_t evaluate_first_asn(char *);
extern void evaluate_bgp_aspath_radius(char *, int, int);
extern void copy_stdcomm_to_asn(char *, as_t *, int);
extern void copy_lrgcomm_to_asn(char *, as_t *, int);
extern void write_neighbors_file(char *, int);
extern struct bgp_rt_structs *bgp_select_routing_db(int);
extern void bgp_md5_file_init(struct bgp_md5_table *);
extern void bgp_md5_file_load(char *, struct bgp_md5_table *);
extern void bgp_md5_file_unload(struct bgp_md5_table *);
extern void bgp_md5_file_process(int, struct bgp_md5_table *);
extern void bgp_config_checks(struct configuration *);
extern struct bgp_misc_structs *bgp_select_misc_db(int);
extern void bgp_link_misc_structs(struct bgp_misc_structs *);
extern void bgp_blackhole_link_misc_structs(struct bgp_misc_structs *);

extern struct bgp_attr_extra *bgp_attr_extra_new(struct bgp_info *);
extern void bgp_attr_extra_free(struct bgp_peer *, struct bgp_attr_extra **);
extern struct bgp_attr_extra *bgp_attr_extra_get(struct bgp_info *);
extern struct bgp_attr_extra *bgp_attr_extra_process(struct bgp_peer *, struct bgp_info *, afi_t, safi_t, struct bgp_attr_extra *);

extern struct bgp_info *bgp_info_new(struct bgp_peer *);
extern void bgp_info_add(struct bgp_peer *, struct bgp_node *, struct bgp_info *, u_int32_t);
extern void bgp_info_delete(struct bgp_peer *, struct bgp_node *, struct bgp_info *, u_int32_t);
extern void bgp_info_free(struct bgp_peer *, struct bgp_info *, void (*bgp_extra_data_free)(struct bgp_msg_extra_data *));
extern void bgp_attr_init(int, struct bgp_rt_structs *);
extern struct bgp_attr *bgp_attr_intern(struct bgp_peer *, struct bgp_attr *);
extern void bgp_attr_unintern (struct bgp_peer *, struct bgp_attr *);
extern void *bgp_attr_hash_alloc (void *);
extern int bgp_attr_munge_as4path(struct bgp_peer *, struct bgp_attr *, struct aspath *);

extern int bgp_peer_init(struct bgp_peer *, int);
extern void bgp_peer_close(struct bgp_peer *, int, int, int, u_int8_t, u_int8_t, char *);
extern int bgp_peer_xconnect_init(struct bgp_peer *, int);
extern void bgp_peer_print(struct bgp_peer *, char *, int);
extern void bgp_peer_xconnect_print(struct bgp_peer *, char *, int);
extern void bgp_peer_info_delete(struct bgp_peer *);
extern void bgp_table_info_delete(struct bgp_peer *, struct bgp_table *, afi_t, safi_t);
extern void bgp_peer_cache_init(struct bgp_peer_cache_bucket *, u_int32_t);
extern struct bgp_peer_cache *bgp_peer_cache_insert(struct bgp_peer_cache_bucket *, u_int32_t, struct bgp_peer *);
extern int bgp_peer_cache_delete(struct bgp_peer_cache_bucket *, u_int32_t, struct bgp_peer *);
extern struct bgp_peer *bgp_peer_cache_search(struct bgp_peer_cache_bucket *, u_int32_t, struct host_addr *, u_int16_t);

extern void bgp_batch_init(struct bgp_peer_batch *, int, int);
extern void bgp_batch_reset(struct bgp_peer_batch *, time_t);
extern int bgp_batch_is_admitted(struct bgp_peer_batch *, time_t);
extern int bgp_batch_is_enabled(struct bgp_peer_batch *);
extern int bgp_batch_is_expired(struct bgp_peer_batch *, time_t);
extern int bgp_batch_is_not_empty(struct bgp_peer_batch *);
extern void bgp_batch_increase_counter(struct bgp_peer_batch *);
extern void bgp_batch_decrease_counter(struct bgp_peer_batch *);
extern void bgp_batch_rollback(struct bgp_peer_batch *);

extern int bgp_peer_cmp(const void *, const void *);
extern int bgp_peer_host_addr_cmp(const void *, const void *);
extern int bgp_peer_sa_addr_cmp(const void *, const void *);
extern void bgp_peer_free(void *);
extern int bgp_peers_bintree_walk_print(const void *, const pm_VISIT, const int, void *);
extern int bgp_peers_bintree_walk_delete(const void *, const pm_VISIT, const int, void *);

extern unsigned int attrhash_key_make(void *);
extern int attrhash_cmp(const void *, const void *);
extern void attrhash_init(int, struct hash **);

extern int bgp_router_id_check(struct bgp_msg_data *);
extern u_int16_t bgp_get_packet_len(char *);
extern u_int8_t bgp_get_packet_type(char *);
#endif 
