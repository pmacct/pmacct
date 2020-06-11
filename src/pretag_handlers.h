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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef PRETAG_HANDLERS_H
#define PRETAG_HANDLERS_H

/* prototypes */
extern int PT_map_id_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_id2_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_label_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_ip_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_input_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_output_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_nexthop_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_bgp_nexthop_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_engine_type_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_engine_id_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_filter_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_agent_id_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_flowset_id_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_fwdstatus_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_sample_type_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_direction_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_nat_event_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_src_as_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_dst_as_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_peer_src_as_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_peer_dst_as_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_src_local_pref_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_local_pref_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_src_roa_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_dst_roa_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_src_comms_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_comms_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_mpls_vpn_rd_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_mpls_pw_id_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_src_mac_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_dst_mac_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_vlan_id_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_cvlan_id_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_src_net_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_dst_net_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_set_tos_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_entry_label_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_jeq_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_return_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int PT_map_stack_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern pm_id_t PT_stack_sum(pm_id_t, pm_id_t);
extern pm_id_t PT_stack_logical_or(pm_id_t, pm_id_t);

extern int PT_map_index_entries_ip_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_input_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_output_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_bgp_nexthop_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_src_as_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_dst_as_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_peer_src_as_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_peer_dst_as_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_mpls_vpn_id_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_mpls_vpn_rd_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_mpls_pw_id_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_mpls_label_bottom_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_src_mac_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_dst_mac_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_vlan_id_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_cvlan_id_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_entries_fwdstatus_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_ip_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_input_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_output_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_bgp_nexthop_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_src_as_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_dst_as_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_peer_src_as_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_peer_dst_as_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_mpls_vpn_id_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_mpls_vpn_rd_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_mpls_pw_id_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_mpls_label_bottom_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_src_mac_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_dst_mac_handler(struct id_entry *, pm_hash_serial_t *, void *); 
extern int PT_map_index_fdata_vlan_id_handler(struct id_entry *, pm_hash_serial_t *, void *);
extern int PT_map_index_fdata_cvlan_id_handler(struct id_entry *, pm_hash_serial_t *, void *);
extern int PT_map_index_fdata_fwdstatus_handler(struct id_entry *, pm_hash_serial_t *, void *);

/* BPAS_*: bgp_peer_as_src map specific handlers */
extern int BPAS_map_bgp_nexthop_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int BPAS_map_bgp_peer_dst_as_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);

/* BTA_*: bgp_agent_map specific handlers */
extern int BTA_map_lookup_bgp_port_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);

/* BITR_*: flow_to_rd_map specific handlers */
extern int BITR_map_mpls_label_bottom_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int BITR_map_mpls_vpn_id_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);

/* custom_primitives_*: aggregate_primitives specific handlers */
extern int custom_primitives_map_name_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int custom_primitives_map_packet_ptr_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int custom_primitives_map_field_type_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int custom_primitives_map_len_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int custom_primitives_map_semantics_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern void custom_primitives_map_initialize();
extern void custom_primitives_map_validate(char *, struct plugin_requests *);

extern int pretag_dummy_ip_handler(struct packet_ptrs *, void *, void *);
extern int pretag_input_handler(struct packet_ptrs *, void *, void *);
extern int pretag_id_handler(struct packet_ptrs *, void *, void *);
extern int pretag_id2_handler(struct packet_ptrs *, void *, void *);
extern int pretag_label_handler(struct packet_ptrs *, void *, void *);
extern int pretag_output_handler(struct packet_ptrs *, void *, void *);
extern int pretag_nexthop_handler(struct packet_ptrs *, void *, void *);
extern int pretag_bgp_nexthop_handler(struct packet_ptrs *, void *, void *);
extern int pretag_bgp_bgp_nexthop_handler(struct packet_ptrs *, void *, void *);
extern int pretag_engine_type_handler(struct packet_ptrs *, void *, void *);
extern int pretag_engine_id_handler(struct packet_ptrs *, void *, void *);
extern int pretag_flowset_id_handler(struct packet_ptrs *, void *, void *);
extern int pretag_filter_handler(struct packet_ptrs *, void *, void *);
extern int pretag_src_as_handler(struct packet_ptrs *, void *, void *);
extern int pretag_dst_as_handler(struct packet_ptrs *, void *, void *);
extern int pretag_bgp_src_as_handler(struct packet_ptrs *, void *, void *);
extern int pretag_bgp_dst_as_handler(struct packet_ptrs *, void *, void *);
extern int pretag_peer_src_as_handler(struct packet_ptrs *, void *, void *);
extern int pretag_peer_dst_as_handler(struct packet_ptrs *, void *, void *);
extern int pretag_src_local_pref_handler(struct packet_ptrs *, void *, void *);
extern int pretag_local_pref_handler(struct packet_ptrs *, void *, void *);
extern int pretag_src_roa_handler(struct packet_ptrs *, void *, void *);
extern int pretag_dst_roa_handler(struct packet_ptrs *, void *, void *);
extern int pretag_src_comms_handler(struct packet_ptrs *, void *, void *);
extern int pretag_comms_handler(struct packet_ptrs *, void *, void *);
extern int pretag_sample_type_handler(struct packet_ptrs *, void *, void *);
extern int pretag_direction_handler(struct packet_ptrs *, void *, void *);
extern int pretag_nat_event_handler(struct packet_ptrs *, void *, void *);
extern int pretag_mpls_vpn_rd_handler(struct packet_ptrs *, void *, void *);
extern int pretag_mpls_pw_id_handler(struct packet_ptrs *, void *, void *);
extern int pretag_src_mac_handler(struct packet_ptrs *, void *, void *);
extern int pretag_dst_mac_handler(struct packet_ptrs *, void *, void *);
extern int pretag_vlan_id_handler(struct packet_ptrs *, void *, void *);
extern int pretag_src_net_handler(struct packet_ptrs *, void *, void *);
extern int pretag_dst_net_handler(struct packet_ptrs *, void *, void *);
extern int pretag_forwarding_status_handler(struct packet_ptrs *, void *, void *);
extern int pretag_cvlan_id_handler(struct packet_ptrs *, void *, void *);
extern int pretag_set_tos_handler(struct packet_ptrs *, void *, void *);

extern int SF_pretag_input_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_output_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_nexthop_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_bgp_nexthop_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_agent_id_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_src_as_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_dst_as_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_dst_as_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_src_mac_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_dst_mac_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_vlan_id_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_mpls_pw_id_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_src_net_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_dst_net_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_sample_type_handler(struct packet_ptrs *, void *, void *);
extern int SF_pretag_direction_handler(struct packet_ptrs *, void *, void *);

extern int PM_pretag_src_as_handler(struct packet_ptrs *, void *, void *);
extern int PM_pretag_dst_as_handler(struct packet_ptrs *, void *, void *);
extern int PM_pretag_input_handler(struct packet_ptrs *, void *, void *);
extern int PM_pretag_output_handler(struct packet_ptrs *, void *, void *);
extern int PM_pretag_direction_handler(struct packet_ptrs *, void *, void *);

extern int BPAS_bgp_nexthop_handler(struct packet_ptrs *, void *, void *);
extern int BPAS_bgp_peer_dst_as_handler(struct packet_ptrs *, void *, void *);

extern int BTA_lookup_bgp_port_handler(struct packet_ptrs *, void *, void *);

extern int BITR_mpls_label_bottom_handler(struct packet_ptrs *, void *, void *);
extern int BITR_mpls_vpn_id_handler(struct packet_ptrs *, void *, void *);

extern void pm_pcap_interfaces_map_validate(char *, struct plugin_requests *);
extern int pm_pcap_interfaces_map_ifindex_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int pm_pcap_interfaces_map_ifname_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int pm_pcap_interfaces_map_direction_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);

extern void pm_pcap_interfaces_map_initialize(struct pm_pcap_interfaces *);
extern void pm_pcap_interfaces_map_load(struct pm_pcap_interfaces *);
extern void pm_pcap_interfaces_map_destroy(struct pm_pcap_interfaces *);
extern void pm_pcap_interfaces_map_copy(struct pm_pcap_interfaces *, struct pm_pcap_interfaces *);
extern u_int32_t pm_pcap_interfaces_map_lookup_ifname(struct pm_pcap_interfaces *, char *);
extern struct pm_pcap_interface *pm_pcap_interfaces_map_getentry_by_ifname(struct pm_pcap_interfaces *, char *);
extern char *pm_pcap_interfaces_map_getnext_ifname(struct pm_pcap_interfaces *, int *);

#endif //PRETAG_HANDLERS_H
