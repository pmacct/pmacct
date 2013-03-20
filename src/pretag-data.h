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
  {"nexthop", PT_map_nexthop_handler},
  {"bgp_nexthop", PT_map_bgp_nexthop_handler},
  {"filter", PT_map_filter_handler},
  {"v8agg", PT_map_v8agg_handler},
  {"agent_id", PT_map_agent_id_handler},
  {"sampling_rate", PT_map_sampling_rate_handler},
  {"sample_type", PT_map_sample_type_handler},
  {"direction", PT_map_direction_handler},
  {"src_as", PT_map_src_as_handler},
  {"dst_as", PT_map_dst_as_handler},
  {"peer_src_as", PT_map_peer_src_as_handler},
  {"peer_dst_as", PT_map_peer_dst_as_handler},
  {"src_local_pref", PT_map_src_local_pref_handler},
  {"local_pref", PT_map_local_pref_handler},
  {"src_comms", PT_map_src_comms_handler},
  {"comms", PT_map_comms_handler},
  {"mpls_vpn_rd", PT_map_mpls_vpn_rd_handler},
  {"set_tag", PT_map_id_handler},
  {"set_tag2", PT_map_id2_handler},
  {"set_tos", PT_map_set_tos_handler},
  {"label", PT_map_label_handler},
  {"jeq", PT_map_jeq_handler},
  {"return", PT_map_return_handler},
  {"stack", PT_map_stack_handler},
  {"", NULL}
};

const struct _map_dictionary_line tag_map_tee_dictionary[] = {
  {"id", PT_map_id_handler},
  {"id2", PT_map_id2_handler},
  {"set_tag", PT_map_id_handler},
  {"set_tag2", PT_map_id2_handler},
  {"ip", PT_map_ip_handler},
  {"label", PT_map_label_handler},
  {"jeq", PT_map_jeq_handler},
  {"return", PT_map_return_handler},
  {"stack", PT_map_stack_handler},
  {"", NULL}
};

const struct _map_dictionary_line bpas_map_dictionary[] = {
  {"id", PT_map_id_handler},
  {"ip", PT_map_ip_handler},
  {"in", PT_map_input_handler},
  {"bgp_nexthop", BPAS_map_bgp_nexthop_handler},
  {"peer_dst_as", BPAS_map_bgp_peer_dst_as_handler},
  {"src_mac", BPAS_map_src_mac_handler},
  {"", NULL}
};

const struct _map_dictionary_line bta_map_dictionary[] = {
  {"id", PT_map_id_handler},
  {"ip", PT_map_ip_handler},
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
  {"", NULL}
};
