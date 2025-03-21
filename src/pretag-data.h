/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2024 by Paolo Lucente
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

const struct _map_dictionary_line tag_map_dictionary[] = {
  {"id", PT_map_id_handler},
  {"id2", PT_map_id2_handler},
  {"ip", PT_map_ip_handler},
  {"in", PT_map_input_handler},
  {"out", PT_map_output_handler},
  {"engine_type", PT_map_engine_type_handler},
  {"engine_id", PT_map_engine_id_handler},
  {"source_id", PT_map_engine_id_handler},
  {"nexthop", PT_map_nexthop_handler},
  {"bgp_nexthop", PT_map_bgp_nexthop_handler},
  {"filter", PT_map_filter_handler},
  {"agent_id", PT_map_agent_id_handler},
  {"flowset_id", PT_map_flowset_id_handler},
  {"sample_type", PT_map_sample_type_handler},
  {"direction", PT_map_direction_handler},
  {"src_as", PT_map_src_as_handler},
  {"dst_as", PT_map_dst_as_handler},
  {"peer_src_as", PT_map_peer_src_as_handler},
  {"peer_dst_as", PT_map_peer_dst_as_handler},
  {"src_local_pref", PT_map_src_local_pref_handler},
  {"local_pref", PT_map_local_pref_handler},
  {"src_roa", PT_map_src_roa_handler},
  {"dst_roa", PT_map_dst_roa_handler},
  {"src_comms", PT_map_src_comms_handler},
  {"comms", PT_map_comms_handler},
  {"mpls_vpn_id_in", PT_map_mpls_vpn_id_in_handler},
  {"mpls_vpn_id_out", PT_map_mpls_vpn_id_out_handler},
  {"mpls_vpn_rd", PT_map_mpls_vpn_rd_handler},
  {"mpls_pw_id", PT_map_mpls_pw_id_handler},
  {"src_mac", PT_map_src_mac_handler},
  {"dst_mac", PT_map_dst_mac_handler},
  {"vlan", PT_map_vlan_id_handler},
  {"cvlan", PT_map_cvlan_id_handler},
  {"src_net", PT_map_src_net_handler},
  {"dst_net", PT_map_dst_net_handler},
  {"ip_proto", PT_map_ip_proto_handler},
  {"src_port", PT_map_src_port_handler},
  {"dst_port", PT_map_dst_port_handler},
  {"tcp_flags", PT_map_tcp_flags_handler},
  {"is_multicast", PT_map_is_multicast_handler},
  {"set_tag", PT_map_id_handler},
  {"set_tag2", PT_map_id2_handler},
  {"set_label", PT_map_label_handler},
  {"set_tos", PT_map_set_tos_handler},
  {"label", PT_map_entry_label_handler},
  {"jeq", PT_map_jeq_handler},
  {"return", PT_map_return_handler},
  {"stack", PT_map_stack_handler},
  {"fwd_status", PT_map_fwd_status_handler},
  {"is_bi_flow", PT_map_is_bi_flow_handler},
  {"is_nsel", PT_map_is_nsel_handler},
  {"is_nel", PT_map_is_nel_handler},
  {"", NULL}
};

const struct _map_index_internal_dictionary_line tag_map_index_entries_dictionary[] = {
  {PRETAG_IP, PT_map_index_entries_ip_handler},
  {PRETAG_IP_AF, PT_map_index_entries_ip_af_handler},
  {PRETAG_IN_IFACE, PT_map_index_entries_input_handler},
  {PRETAG_OUT_IFACE, PT_map_index_entries_output_handler},
  {PRETAG_BGP_NEXTHOP, PT_map_index_entries_bgp_nexthop_handler},
  {PRETAG_SRC_AS, PT_map_index_entries_src_as_handler},
  {PRETAG_DST_AS, PT_map_index_entries_dst_as_handler},
  {PRETAG_PEER_SRC_AS, PT_map_index_entries_peer_src_as_handler},
  {PRETAG_PEER_DST_AS, PT_map_index_entries_peer_dst_as_handler},
  {PRETAG_MPLS_LABEL_BOTTOM, PT_map_index_entries_mpls_label_bottom_handler},
  {PRETAG_MPLS_VPN_ID, PT_map_index_entries_mpls_vpn_id_handler},
  {PRETAG_MPLS_VPN_ID_IN, PT_map_index_entries_mpls_vpn_id_in_handler},
  {PRETAG_MPLS_VPN_ID_OUT, PT_map_index_entries_mpls_vpn_id_out_handler},
  {PRETAG_MPLS_VPN_RD, PT_map_index_entries_mpls_vpn_rd_handler},
  {PRETAG_MPLS_PW_ID, PT_map_index_entries_mpls_pw_id_handler},
  {PRETAG_SRC_MAC, PT_map_index_entries_src_mac_handler},
  {PRETAG_DST_MAC, PT_map_index_entries_dst_mac_handler},
  {PRETAG_VLAN_ID, PT_map_index_entries_vlan_id_handler},
  {PRETAG_CVLAN_ID, PT_map_index_entries_cvlan_id_handler},
  {PRETAG_SRC_NET, PT_map_index_entries_src_net_handler},
  {PRETAG_DST_NET, PT_map_index_entries_dst_net_handler},
  {PRETAG_IP_PROTO, PT_map_index_entries_ip_proto_handler},
  {PRETAG_SRC_PORT, PT_map_index_entries_src_port_handler},
  {PRETAG_DST_PORT, PT_map_index_entries_dst_port_handler},
  {PRETAG_TCP_FLAGS, PT_map_index_entries_tcp_flags_handler},
  {PRETAG_IS_MULTICAST, PT_map_index_entries_is_multicast_handler},
  {PRETAG_FWDSTATUS_ID, PT_map_index_entries_fwd_status_handler},
  {0, NULL}
};

const struct _map_index_dictionary_line tag_map_index_fdata_dictionary[] = {
  {PRETAG_IP, PT_map_index_fdata_ip_handler},
  {PRETAG_IP_AF, PT_map_index_fdata_ip_af_handler},
  {PRETAG_IN_IFACE, PT_map_index_fdata_input_handler},
  {PRETAG_OUT_IFACE, PT_map_index_fdata_output_handler},
  {PRETAG_BGP_NEXTHOP, PT_map_index_fdata_bgp_nexthop_handler},
  {PRETAG_SRC_AS, PT_map_index_fdata_src_as_handler},
  {PRETAG_DST_AS, PT_map_index_fdata_dst_as_handler},
  {PRETAG_PEER_SRC_AS, PT_map_index_fdata_peer_src_as_handler},
  {PRETAG_PEER_DST_AS, PT_map_index_fdata_peer_dst_as_handler},
  {PRETAG_MPLS_LABEL_BOTTOM, PT_map_index_fdata_mpls_label_bottom_handler},
  {PRETAG_MPLS_VPN_ID, PT_map_index_fdata_mpls_vpn_id_handler},
  {PRETAG_MPLS_VPN_ID_IN, PT_map_index_fdata_mpls_vpn_id_in_handler},
  {PRETAG_MPLS_VPN_ID_OUT, PT_map_index_fdata_mpls_vpn_id_out_handler},
  {PRETAG_MPLS_VPN_RD, PT_map_index_fdata_mpls_vpn_rd_handler},
  {PRETAG_MPLS_PW_ID, PT_map_index_fdata_mpls_pw_id_handler},
  {PRETAG_SRC_MAC, PT_map_index_fdata_src_mac_handler},
  {PRETAG_DST_MAC, PT_map_index_fdata_dst_mac_handler},
  {PRETAG_VLAN_ID, PT_map_index_fdata_vlan_id_handler},
  {PRETAG_CVLAN_ID, PT_map_index_fdata_cvlan_id_handler},
  {PRETAG_SRC_NET, PT_map_index_fdata_src_net_handler},
  {PRETAG_DST_NET, PT_map_index_fdata_dst_net_handler},
  {PRETAG_IP_PROTO, PT_map_index_fdata_ip_proto_handler},
  {PRETAG_SRC_PORT, PT_map_index_fdata_src_port_handler},
  {PRETAG_DST_PORT, PT_map_index_fdata_dst_port_handler},
  {PRETAG_TCP_FLAGS, PT_map_index_fdata_tcp_flags_handler},
  {PRETAG_IS_MULTICAST, PT_map_index_fdata_is_multicast_handler},
  {PRETAG_FWDSTATUS_ID, PT_map_index_fdata_fwd_status_handler},
  {0, NULL}
};

const struct _map_index_size_dictionary_line tag_map_index_entries_size_dictionary[] = {
  {PRETAG_IP, sizeof(struct host_addr)},
  {PRETAG_IP_AF, sizeof(u_int8_t)},
  {PRETAG_IN_IFACE, sizeof(u_int32_t)},
  {PRETAG_OUT_IFACE, sizeof(u_int32_t)},
  {PRETAG_BGP_NEXTHOP, sizeof(struct host_addr)},
  {PRETAG_SRC_AS, sizeof(u_int32_t)},
  {PRETAG_DST_AS, sizeof(u_int32_t)},
  {PRETAG_PEER_SRC_AS, sizeof(u_int32_t)},
  {PRETAG_PEER_DST_AS, sizeof(u_int32_t)},
  {PRETAG_MPLS_LABEL_BOTTOM, sizeof(u_int32_t)},
  {PRETAG_MPLS_VPN_ID, sizeof(u_int32_t)},
  {PRETAG_MPLS_VPN_RD, sizeof(rd_t)},
  {PRETAG_SRC_MAC, ETH_ADDR_LEN},
  {PRETAG_DST_MAC, ETH_ADDR_LEN},
  {PRETAG_VLAN_ID, sizeof(u_int16_t)},
  {PRETAG_CVLAN_ID, sizeof(u_int16_t)},
  {PRETAG_SRC_NET, (sizeof(struct host_addr) /* net */ + sizeof(u_int8_t) /* mask */)},
  {PRETAG_DST_NET, (sizeof(struct host_addr) /* net */ + sizeof(u_int8_t) /* mask */)},
  {PRETAG_IP_PROTO, sizeof(u_int8_t)},
  {PRETAG_SRC_PORT, sizeof(u_int16_t)},
  {PRETAG_DST_PORT, sizeof(u_int16_t)},
  {PRETAG_IS_MULTICAST, sizeof(u_int8_t)},
  {PRETAG_FWDSTATUS_ID, sizeof(u_int8_t)},
  {0, 0}
};

const struct _map_dictionary_line tag_map_tee_dictionary[] = {
  {"id", PT_map_id_handler},
  {"id2", PT_map_id2_handler},
  {"set_tag", PT_map_id_handler},
  {"set_tag2", PT_map_id2_handler},
  {"ip", PT_map_ip_handler},
  {"in", PT_map_input_handler},
  {"out", PT_map_output_handler},
  {"src_mac", PT_map_src_mac_handler},
  {"dst_mac", PT_map_dst_mac_handler},
  {"vlan", PT_map_vlan_id_handler},
  {"src_net", PT_map_src_net_handler},
  {"dst_net", PT_map_dst_net_handler},
  {"ip_proto", PT_map_ip_proto_handler},
  {"src_port", PT_map_src_port_handler},
  {"dst_port", PT_map_dst_port_handler},
  {"tcp_flags", PT_map_tcp_flags_handler},
  {"bgp_nexthop", PT_map_bgp_nexthop_handler},
  {"direction", PT_map_direction_handler},
  {"engine_type", PT_map_engine_type_handler},
  {"engine_id", PT_map_engine_id_handler},
  {"source_id", PT_map_engine_id_handler},
  {"agent_id", PT_map_agent_id_handler},
  {"label", PT_map_entry_label_handler},
  {"jeq", PT_map_jeq_handler},
  {"return", PT_map_return_handler},
  {"stack", PT_map_stack_handler},
  {"", NULL}
};

const struct _map_dictionary_line tag_map_bgp_dictionary[] = {
  {"set_tag", PT_map_id_handler},
  {"ip", PT_map_ip_handler},
  {"comms", PT_map_comms_handler},
  {"set_label", PT_map_label_handler},
  {"label", PT_map_entry_label_handler},
  {"jeq", PT_map_jeq_handler},
  {"", NULL}
};

const struct _map_dictionary_line tag_map_nonflow_dictionary[] = {
  {"set_tag", PT_map_id_handler},
  {"ip", PT_map_ip_handler},
  {"set_label", PT_map_label_handler},
  {"", NULL}
};

const struct _map_dictionary_line bpas_map_dictionary[] = {
  {"id", PT_map_id_handler},
  {"ip", PT_map_ip_handler},
  {"in", PT_map_input_handler},
  {"out", PT_map_output_handler},
  {"bgp_nexthop", BPAS_map_bgp_nexthop_handler},
  {"peer_dst_as", BPAS_map_bgp_peer_dst_as_handler},
  {"src_mac", PT_map_src_mac_handler},
  {"vlan", PT_map_vlan_id_handler},
  {"src_net", PT_map_src_net_handler},
  {"dst_net", PT_map_dst_net_handler},
  {"filter", PT_map_filter_handler},
  {"", NULL}
};

const struct _map_dictionary_line bta_map_dictionary[] = {
  {"id", PT_map_id_handler},
  {"bgp_ip", PT_map_id_handler},
  {"bgp_port", BTA_map_lookup_bgp_port_handler},
  {"bmp_ip", PT_map_id_handler},
  {"ip", PT_map_ip_handler},
  {"in", PT_map_input_handler},
  {"out", PT_map_output_handler},
  {"filter", PT_map_filter_handler},
  {"", NULL}
};

const struct _map_dictionary_line sampling_map_dictionary[] = {
  {"id", PT_map_id_handler},
  {"ip", PT_map_ip_handler},
  {"in", PT_map_input_handler},
  {"out", PT_map_output_handler},
  {"", NULL}
};

const struct _map_dictionary_line bitr_map_dictionary[] = {
  {"id", PT_map_id_handler},
  {"ip", PT_map_ip_handler},
  {"in", PT_map_input_handler},
  {"out", PT_map_output_handler},
  {"bgp_nexthop", PT_map_bgp_nexthop_handler},
  {"mpls_vpn_id", BITR_map_mpls_vpn_id_handler}, 
  {"mpls_label_bottom", BITR_map_mpls_label_bottom_handler},
  {"", NULL}
};

const struct _map_dictionary_line custom_primitives_map_dictionary[] = {
  {"name", custom_primitives_map_name_handler},
  {"packet_ptr", custom_primitives_map_packet_ptr_handler},
  {"field_type", custom_primitives_map_field_type_handler},
  {"len", custom_primitives_map_len_handler},
  {"semantics", custom_primitives_map_semantics_handler},
  {"", NULL}
};

const struct _map_dictionary_line pm_pcap_interfaces_map_dictionary[] = {
  {"ifindex", pm_pcap_interfaces_map_ifindex_handler},
  {"ifname", pm_pcap_interfaces_map_ifname_handler},
  {"direction", pm_pcap_interfaces_map_direction_handler},
  {"", NULL}
};
