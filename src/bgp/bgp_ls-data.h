/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2025 by Paolo Lucente
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

const struct bgp_ls_nlri_tlv_list_entry bgp_ls_nlri_tlv_list[] = {
  {BGP_LS_LOCAL_ND, bgp_ls_nlri_tlv_local_nd_handler},
  {BGP_LS_REMOTE_ND, bgp_ls_nlri_tlv_remote_nd_handler},
  {BGP_LS_V4_ADDR_IF, bgp_ls_nlri_tlv_v4_addr_if_handler},
  {BGP_LS_V4_ADDR_NEIGHBOR, bgp_ls_nlri_tlv_v4_addr_neigh_handler},
  {BGP_LS_V6_ADDR_IF, bgp_ls_nlri_tlv_v6_addr_if_handler},
  {BGP_LS_V6_ADDR_NEIGHBOR, bgp_ls_nlri_tlv_v6_addr_neigh_handler},
  {BGP_LS_IP_REACH, bgp_ls_nlri_tlv_ip_reach_handler},
  {0, NULL}
};

const struct bgp_ls_nd_tlv_list_entry bgp_ls_nd_tlv_list[] = {
  {BGP_LS_ND_AS, bgp_ls_nd_tlv_as_handler},
  {BGP_LS_ND_ID, bgp_ls_nd_tlv_id_handler},
  {BGP_LS_ND_IGP_ROUTER_ID, bgp_ls_nd_tlv_router_id_handler},
  {0, NULL}
};

const struct bgp_ls_attr_tlv_print_list_entry bgp_ls_attr_tlv_print_list[] = {
  {BGP_LS_ATTR_NODE_FLAG_BITS, "attr_node_flags", BGP_LS_PRINT_HEX, bgp_ls_attr_tlv_int8_print},
  {BGP_LS_ATTR_NODE_NAME, "attr_node_name", 0, bgp_ls_attr_tlv_string_print},
  {BGP_LS_ATTR_V4_RID_LOCAL, "attr_v4_rid_local", 0, bgp_ls_attr_tlv_ip_print},
  {BGP_LS_ATTR_V6_RID_LOCAL, "attr_v6_rid_local", 0, bgp_ls_attr_tlv_ip_print},
  {BGP_LS_ATTR_V4_RID_REMOTE, "attr_v4_rid_remote", 0, bgp_ls_attr_tlv_ip_print},
  {BGP_LS_ATTR_V6_RID_REMOTE, "attr_v6_rid_remote", 0, bgp_ls_attr_tlv_ip_print},
  {BGP_LS_ATTR_ADMIN_GROUP, "attr_admin_group", BGP_LS_PRINT_HEX, bgp_ls_attr_tlv_int32_print},
  {BGP_LS_ATTR_MAX_BW, "attr_max_bw", BGP_LS_PRINT_BYTES_TO_BITS, bgp_ls_attr_tlv_int32_print},
  {BGP_LS_ATTR_MAX_RESV_BW, "attr_max_resv_bw", BGP_LS_PRINT_BYTES_TO_BITS, bgp_ls_attr_tlv_int32_print},
  {BGP_LS_ATTR_UNRESV_BW, "attr_unresv_bw", BGP_LS_PRINT_ARRAY|BGP_LS_PRINT_BYTES_TO_BITS, bgp_ls_attr_tlv_int32_print},
  {BGP_LS_ATTR_TE_DEFAULT_METRIC, "attr_te_df_metric", 0, bgp_ls_attr_tlv_int32_print},
  {BGP_LS_ATTR_PFX_METRIC, "attr_prefix_metric", 0, bgp_ls_attr_tlv_int32_print},
  {0, NULL}
};
