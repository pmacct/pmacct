/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2013 by Paolo Lucente
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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#if (defined __PKT_HANDLERS_C)
extern struct channels_list_entry channels_list[MAX_N_PLUGINS]; /* communication channels: core <-> plugins */
#endif

#if (!defined __PKT_HANDLERS_C)
#define EXT extern
#else
#define EXT
#endif
EXT pkt_handler phandler[N_PRIMITIVES];
#undef EXT

#if (!defined __PKT_HANDLERS_C)
#define EXT extern
#else
#define EXT
#endif
EXT void evaluate_packet_handlers(); 
EXT void src_mac_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void dst_mac_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void vlan_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void cos_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void etype_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void src_host_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void dst_host_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void src_port_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void dst_port_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void ip_tos_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void ip_proto_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void tcp_flags_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void counters_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void counters_renormalize_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void id_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void flows_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void class_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void in_iface_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void out_iface_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void sampling_rate_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void timestamp_start_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void sfprobe_payload_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void tee_payload_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void nfprobe_extras_handler(struct channels_list_entry *, struct packet_ptrs *, char **);

EXT void NF_src_mac_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_dst_mac_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_vlan_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_cos_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_etype_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_src_host_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_dst_host_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_src_nmask_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_dst_nmask_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_src_port_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_dst_port_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_src_as_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_dst_as_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_peer_src_as_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_peer_dst_as_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_peer_src_ip_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_peer_dst_ip_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_ip_tos_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_ip_proto_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_tcp_flags_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_counters_msecs_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_counters_secs_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_counters_new_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_flows_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_class_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_in_iface_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_out_iface_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_sampling_rate_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_post_nat_src_host_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_post_nat_dst_host_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_post_nat_src_port_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_post_nat_dst_port_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_nat_event_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_timestamp_start_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_timestamp_end_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_id_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_id2_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_counters_renormalize_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void NF_counters_map_renormalize_handler(struct channels_list_entry *, struct packet_ptrs *, char **);

EXT void bgp_ext_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void nfprobe_bgp_ext_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void sfprobe_bgp_ext_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void bgp_peer_src_as_frommap_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void bgp_src_local_pref_frommap_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void bgp_src_med_frommap_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void bgp_src_nmask_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void bgp_dst_nmask_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void bgp_peer_dst_ip_handler(struct channels_list_entry *, struct packet_ptrs *, char **);

EXT void igp_src_nmask_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void igp_dst_nmask_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void igp_peer_dst_ip_handler(struct channels_list_entry *, struct packet_ptrs *, char **);

EXT void SF_src_mac_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_dst_mac_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_vlan_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_cos_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_etype_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_src_host_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_dst_host_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_src_nmask_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_dst_nmask_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_src_port_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_dst_port_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_src_as_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_dst_as_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_peer_src_ip_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_peer_dst_ip_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_ip_tos_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_ip_proto_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_tcp_flags_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_counters_new_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_counters_renormalize_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_counters_map_renormalize_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_id_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_id2_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_class_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_in_iface_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_out_iface_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_sampling_rate_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_sampling_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_timestamp_start_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_bgp_peer_src_as_fromext_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_bgp_peer_src_as_fromstd_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_as_path_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_peer_src_as_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_peer_dst_as_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_local_pref_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void SF_std_comms_handler(struct channels_list_entry *, struct packet_ptrs *, char **);

EXT void ptag_id_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void ptag_id2_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void sampling_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void sfprobe_sampling_handler(struct channels_list_entry *, struct packet_ptrs *, char **);

#if defined (WITH_GEOIP)
EXT void geoip_init();
EXT void src_host_country_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
EXT void dst_host_country_handler(struct channels_list_entry *, struct packet_ptrs *, char **);
#endif

EXT int evaluate_lm_method(struct packet_ptrs *, u_int8_t, u_int32_t, u_int32_t);
EXT char *lookup_tpl_ext_db(void *, u_int32_t, u_int16_t);
#undef EXT
