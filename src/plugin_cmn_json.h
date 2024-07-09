/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2023 by Paolo Lucente
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

#ifndef PLUGIN_CMN_JSON_H
#define PLUGIN_CMN_JSON_H

/* typedefs */
#include "preprocess.h"
#ifdef WITH_JANSSON
typedef void (*compose_json_handler)(json_t *, struct chained_cache *);
#endif

#ifdef WITH_JANSSON
/* global vars */
extern compose_json_handler cjhandler[N_PRIMITIVES];

/* prototypes */
extern void compose_json_map_label(json_t *, struct chained_cache *);
extern void compose_json_array_tcpflags(json_t *, struct chained_cache *);
extern void compose_json_string_fwd_status(json_t *, struct chained_cache *);
extern void compose_json_array_mpls_label_stack(json_t *, struct chained_cache *);
extern void compose_json_array_srv6_segment_ipv6_list(json_t *, struct chained_cache *);
extern void compose_json_array_tunnel_tcp_flags(json_t *, struct chained_cache *);
extern void compose_json_array_std_comm(json_t *, struct chained_cache *);
extern void compose_json_array_src_std_comm(json_t *, struct chained_cache *);
extern void compose_json_array_ext_comm(json_t *, struct chained_cache *);
extern void compose_json_array_src_ext_comm(json_t *, struct chained_cache *);
extern void compose_json_array_lrg_comm(json_t *, struct chained_cache *);
extern void compose_json_array_src_lrg_comm(json_t *, struct chained_cache *);
extern void compose_json_array_as_path(json_t *, struct chained_cache *);
extern void compose_json_array_src_as_path(json_t *, struct chained_cache *);

extern json_t *compose_label_json_data(cdada_list_t *, int);
extern json_t *compose_tcpflags_json_data(cdada_list_t *, int);
extern json_t *compose_fwd_status_json_data(size_t, cdada_list_t *, int);
extern json_t *compose_mpls_label_stack_json_data(u_int32_t *, int);
extern json_t *compose_srv6_segment_ipv6_list_json_data(struct host_addr *, int);
extern json_t *compose_str_linked_list_to_json_array_data(cdada_list_t *, int);

extern void compose_json_event_type(json_t *, struct chained_cache *);
extern void compose_json_tag(json_t *, struct chained_cache *);
extern void compose_json_tag2(json_t *, struct chained_cache *);
extern void compose_json_label(json_t *, struct chained_cache *);
extern void compose_json_class(json_t *, struct chained_cache *);
#if defined (WITH_NDPI)
extern void compose_json_ndpi_class(json_t *, struct chained_cache *);
#endif
extern void compose_json_src_mac(json_t *, struct chained_cache *);
extern void compose_json_dst_mac(json_t *, struct chained_cache *);
extern void compose_json_vlan(json_t *, struct chained_cache *);
extern void compose_json_in_vlan(json_t *, struct chained_cache *);
extern void compose_json_out_vlan(json_t *, struct chained_cache *);
extern void compose_json_in_cvlan(json_t *, struct chained_cache *);
extern void compose_json_out_cvlan(json_t *, struct chained_cache *);
extern void compose_json_cos(json_t *, struct chained_cache *);
extern void compose_json_etype(json_t *, struct chained_cache *);
extern void compose_json_src_as(json_t *, struct chained_cache *);
extern void compose_json_dst_as(json_t *, struct chained_cache *);
extern void compose_json_std_comm(json_t *, struct chained_cache *);
extern void compose_json_ext_comm(json_t *, struct chained_cache *);
extern void compose_json_lrg_comm(json_t *, struct chained_cache *);
extern void compose_json_as_path(json_t *, struct chained_cache *);
extern void compose_json_local_pref(json_t *, struct chained_cache *);
extern void compose_json_med(json_t *, struct chained_cache *);
extern void compose_json_dst_roa(json_t *, struct chained_cache *);
extern void compose_json_peer_src_as(json_t *, struct chained_cache *);
extern void compose_json_peer_dst_as(json_t *, struct chained_cache *);
extern void compose_json_peer_src_ip(json_t *, struct chained_cache *);
extern void compose_json_peer_dst_ip(json_t *, struct chained_cache *);
extern void compose_json_src_std_comm(json_t *, struct chained_cache *);
extern void compose_json_src_ext_comm(json_t *, struct chained_cache *);
extern void compose_json_src_lrg_comm(json_t *, struct chained_cache *);
extern void compose_json_src_as_path(json_t *, struct chained_cache *);
extern void compose_json_src_local_pref(json_t *, struct chained_cache *);
extern void compose_json_src_med(json_t *, struct chained_cache *);
extern void compose_json_src_roa(json_t *, struct chained_cache *);
extern void compose_json_in_iface(json_t *, struct chained_cache *);
extern void compose_json_out_iface(json_t *, struct chained_cache *);
extern void compose_json_mpls_vpn_rd(json_t *, struct chained_cache *);
extern void compose_json_mpls_pw_id(json_t *, struct chained_cache *);
extern void compose_json_src_host(json_t *, struct chained_cache *);
extern void compose_json_src_net(json_t *, struct chained_cache *);
extern void compose_json_dst_host(json_t *, struct chained_cache *);
extern void compose_json_dst_net(json_t *, struct chained_cache *);
extern void compose_json_src_mask(json_t *, struct chained_cache *);
extern void compose_json_dst_mask(json_t *, struct chained_cache *);
extern void compose_json_src_port(json_t *, struct chained_cache *);
extern void compose_json_dst_port(json_t *, struct chained_cache *);
#if defined WITH_GEOIPV2
extern void compose_json_src_host_country(json_t *, struct chained_cache *);
extern void compose_json_dst_host_country(json_t *, struct chained_cache *);
extern void compose_json_src_host_pocode(json_t *, struct chained_cache *);
extern void compose_json_dst_host_pocode(json_t *, struct chained_cache *);
extern void compose_json_src_host_coords(json_t *, struct chained_cache *);
extern void compose_json_dst_host_coords(json_t *, struct chained_cache *);
#endif
extern void compose_json_tcp_flags(json_t *, struct chained_cache *);
extern void compose_json_fwd_status(json_t *, struct chained_cache *);
extern void compose_json_mpls_label_stack(json_t *, struct chained_cache *);
extern void compose_json_proto(json_t *, struct chained_cache *);
extern void compose_json_tos(json_t *, struct chained_cache *);
extern void compose_json_flow_label(json_t *, struct chained_cache *);
extern void compose_json_sampling_rate(json_t *, struct chained_cache *);
extern void compose_json_sampling_direction(json_t *, struct chained_cache *);
extern void compose_json_post_nat_src_host(json_t *, struct chained_cache *);
extern void compose_json_post_nat_dst_host(json_t *, struct chained_cache *);
extern void compose_json_post_nat_src_port(json_t *, struct chained_cache *);
extern void compose_json_post_nat_dst_port(json_t *, struct chained_cache *);
extern void compose_json_nat_event(json_t *, struct chained_cache *);
extern void compose_json_fw_event(json_t *, struct chained_cache *);
extern void compose_json_mpls_label_top(json_t *, struct chained_cache *);
extern void compose_json_mpls_label_bottom(json_t *, struct chained_cache *);
extern void compose_json_tunnel_src_mac(json_t *, struct chained_cache *);
extern void compose_json_tunnel_dst_mac(json_t *, struct chained_cache *);
extern void compose_json_tunnel_src_host(json_t *, struct chained_cache *);
extern void compose_json_tunnel_dst_host(json_t *, struct chained_cache *);
extern void compose_json_tunnel_proto(json_t *, struct chained_cache *);
extern void compose_json_tunnel_tos(json_t *, struct chained_cache *);
extern void compose_json_tunnel_flow_label(json_t *, struct chained_cache *);
extern void compose_json_tunnel_src_port(json_t *, struct chained_cache *);
extern void compose_json_tunnel_dst_port(json_t *, struct chained_cache *);
extern void compose_json_tunnel_tcp_flags(json_t *, struct chained_cache *);
extern void compose_json_vxlan(json_t *, struct chained_cache *);
extern void compose_json_nvgre(json_t *, struct chained_cache *);
extern void compose_json_timestamp_start(json_t *, struct chained_cache *);
extern void compose_json_timestamp_end(json_t *, struct chained_cache *);
extern void compose_json_timestamp_arrival(json_t *, struct chained_cache *);
extern void compose_json_timestamp_export(json_t *, struct chained_cache *);
extern void compose_json_timestamp_stitching(json_t *, struct chained_cache *);
extern void compose_json_export_proto_seqno(json_t *, struct chained_cache *);
extern void compose_json_export_proto_version(json_t *, struct chained_cache *);
extern void compose_json_export_proto_sysid(json_t *, struct chained_cache *);
extern void compose_json_custom_primitives(json_t *, struct chained_cache *);
extern void compose_json_history(json_t *, struct chained_cache *);
extern void compose_json_flows(json_t *, struct chained_cache *);
extern void compose_json_counters(json_t *, struct chained_cache *);
extern void compose_json_path_delay_avg_usec(json_t *, struct chained_cache *);
extern void compose_json_path_delay_min_usec(json_t *, struct chained_cache *);
extern void compose_json_path_delay_max_usec(json_t *, struct chained_cache *);
extern void compose_json_ingress_vrf_name(json_t *, struct chained_cache *);

#endif
extern void compose_json(u_int64_t, u_int64_t, u_int64_t);
extern void *compose_purge_init_json(char *, pid_t);
extern void *compose_purge_close_json(char *, pid_t, int, int, int);
#endif //PLUGIN_CMN_JSON_H
