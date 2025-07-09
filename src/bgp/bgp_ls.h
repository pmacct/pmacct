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

#ifndef BGP_LS_H
#define BGP_LS_H

/*
   Unsupported:
   * Multi-Topology
   * Link Local/Remote IDs / GMPLS
   
   Untested:
   * OSPF
*/

/* includes */

/* defines */
#define BGP_LS_NLRI_NODE		1
#define BGP_LS_NLRI_LINK		2
#define BGP_LS_NLRI_V4_TOPO_PFX		3
#define BGP_LS_NLRI_V6_TOPO_PFX		4
#define BGP_LS_NLRI_MAX			4

#define BGP_LS_PROTO_ISIS_L1		1
#define BGP_LS_PROTO_ISIS_L2		2
#define BGP_LS_PROTO_OSPFV2		3
#define BGP_LS_PROTO_DIRECT		4
#define BGP_LS_PROTO_STATIC		5
#define BGP_LS_PROTO_OSPFV3		6
#define BGP_LS_PROTO_MAX		6

#define BGP_LS_RU_DEFAULT_L3_TOPO	0

#define BGP_LS_LOCAL_ND			256
#define BGP_LS_REMOTE_ND		257
#define BGP_LS_LL_REMOTE_ID		258
#define BGP_LS_V4_ADDR_IF		259
#define BGP_LS_V4_ADDR_NEIGHBOR		260
#define BGP_LS_V6_ADDR_IF		261
#define BGP_LS_V6_ADDR_NEIGHBOR		262
#define BGP_LS_MULTI_TOPO_ID		263
#define BGP_LS_OSPF_ROUTE_TYPE		264
#define BGP_LS_IP_REACH			265

#define BGP_LS_ND_AS			512
#define BGP_LS_ND_ID			513
#define BGP_LS_ND_OSPF_AREA_ID		514
#define BGP_LS_ND_IGP_ROUTER_ID		515

#define BGP_LS_ATTR_NODE_FLAG_BITS	1024
#define BGP_LS_ATTR_NODE_OPAQUE		1025
#define BGP_LS_ATTR_NODE_NAME		1026
#define BGP_LS_ATTR_ISIS_AREA_ID	1027
#define BGP_LS_ATTR_V4_RID_LOCAL	1028
#define BGP_LS_ATTR_V6_RID_LOCAL	1029
#define BGP_LS_ATTR_V4_RID_REMOTE	1030
#define BGP_LS_ATTR_V6_RID_REMOTE	1031
#define BGP_LS_ATTR_ADMIN_GROUP		1088
#define BGP_LS_ATTR_MAX_BW		1089
#define BGP_LS_ATTR_MAX_RESV_BW		1090
#define BGP_LS_ATTR_UNRESV_BW		1091
#define BGP_LS_ATTR_TE_DEFAULT_METRIC	1092
#define BGP_LS_ATTR_PROTECTION_TYPE	1093
#define BGP_LS_ATTR_MPLS_PROTO_MASK	1094
#define BGP_LS_ATTR_IGP_METRIC		1095
#define BGP_LS_ATTR_SR_LINK_GROUP	1096
#define BGP_LS_ATTR_LINK_OPAQUE		1097
#define BGP_LS_ATTR_LINK_NAME		1098
#define BGP_LS_ATTR_IGP_FLAGS		1152
#define BGP_LS_ATTR_IGP_ROUTE_TAG	1153
#define BGP_LS_ATTR_IGP_EXT_ROUTE_TAG	1154
#define BGP_LS_ATTR_PFX_METRIC		1155
#define BGP_LS_ATTR_OSPF_FWD_ADDR	1156
#define BGP_LS_ATTR_PFX_OPAQUE		1157

#define BGP_LS_PRINT_HEX		0x01
#define BGP_LS_PRINT_ARRAY		0x02
#define BGP_LS_PRINT_REPEATING		0x04
#define BGP_LS_PRINT_BYTES_TO_BITS	0x08

#define BGP_LS_ISIS_SYS_ID_LEN		6 

/* structures */
struct bgp_ls_nd_igp_rtr_id {
  char id[8];
  u_int8_t len;
};

struct bgp_ls_node_desc {
  as_t asn;
  u_int32_t bgp_ls_id;
  struct bgp_ls_nd_igp_rtr_id igp_rtr_id;
  u_int32_t area_id;
};
  
struct bgp_ls_link_desc {
  struct host_addr local_addr;
  struct host_addr neigh_addr;
};

struct bgp_ls_prefix_desc {
  u_int8_t ospf_route_type;
  struct host_addr addr;
  struct host_mask mask;
};

struct bgp_ls_node_nlri {
  struct bgp_ls_node_desc ndesc;
};

struct bgp_ls_link_nlri {
  struct bgp_ls_node_desc loc_ndesc;
  struct bgp_ls_node_desc rem_ndesc;
  struct bgp_ls_link_desc ldesc;
};

struct bgp_ls_topo_pfx_nlri {
  struct bgp_ls_node_desc ndesc;
  struct bgp_ls_prefix_desc pdesc;
};

struct bgp_ls_nlri {
  struct bgp_peer *peer;
  u_int8_t type; /* see BGP_LS_NLRI definitions */
  u_int8_t proto; /* see BGP_LS_PROTO definitions */
  safi_t safi;
  rd_t rd;
  union {
    struct {
      struct bgp_ls_node_nlri n;
    } node;
    struct {
      struct bgp_ls_link_nlri l;
    } link;
    struct {
      struct bgp_ls_topo_pfx_nlri p;
    } topo_pfx;
  } nlri;
};

typedef int (*bgp_ls_nlri_tlv_hdlr)(u_char *, int, struct bgp_ls_nlri *);
typedef int (*bgp_ls_nd_tlv_hdlr)(u_char *, int, struct bgp_ls_node_desc *);
typedef int (*bgp_ls_attr_tlv_print_hdlr)(u_char *, u_int16_t, char *, u_int8_t, int, void *);

struct bgp_ls_nlri_tlv_list_entry {
  u_int16_t type;
  bgp_ls_nlri_tlv_hdlr hdlr;
};

struct bgp_ls_nd_tlv_list_entry {
  u_int16_t type;
  bgp_ls_nd_tlv_hdlr hdlr;
};

struct bgp_ls_attr_tlv_print_list_entry {
  u_int16_t type;
  char *keystr;
  u_int8_t flags;
  bgp_ls_attr_tlv_print_hdlr hdlr;
};

struct bgp_ls_nlri_map_trav_del {
  struct bgp_peer *peer;
  cdada_list_t *list_del;
};

struct bgp_ls_nlri_map_trav_print {
  struct bgp_peer *peer;
  u_int64_t *num_entries;
};

/* prototypes */
extern void bgp_ls_init();
extern int bgp_attr_parse_ls(struct bgp_peer *, u_int16_t, struct bgp_attr_extra *, u_char *, u_char);
extern int bgp_ls_nlri_parse(struct bgp_msg_data *, struct bgp_attr *, struct bgp_attr_extra *, struct bgp_nlri *, int);
extern void bgp_ls_info_print(struct bgp_peer *, u_int64_t *);
extern void bgp_ls_info_delete(struct bgp_peer *);
extern void bgp_ls_peer_info_print(const cdada_map_t *, const void *, void *, void *);
extern void bgp_ls_peer_info_delete(const cdada_map_t *, const void *, void *, void *);

extern int bgp_ls_nlri_tlv_local_nd_handler(u_char *, int, struct bgp_ls_nlri *);
extern int bgp_ls_nlri_tlv_remote_nd_handler(u_char *, int, struct bgp_ls_nlri *);
extern int bgp_ls_nlri_tlv_v4_addr_if_handler(u_char *, int, struct bgp_ls_nlri *);
extern int bgp_ls_nlri_tlv_v4_addr_neigh_handler(u_char *, int, struct bgp_ls_nlri *);
extern int bgp_ls_nlri_tlv_v6_addr_if_handler(u_char *, int, struct bgp_ls_nlri *);
extern int bgp_ls_nlri_tlv_v6_addr_neigh_handler(u_char *, int, struct bgp_ls_nlri *);
extern int bgp_ls_nlri_tlv_ip_reach_handler(u_char *, int, struct bgp_ls_nlri *);

extern int bgp_ls_nd_tlv_as_handler(u_char *, int, struct bgp_ls_node_desc *);
extern int bgp_ls_nd_tlv_id_handler(u_char *, int, struct bgp_ls_node_desc *);
extern int bgp_ls_nd_tlv_router_id_handler(u_char *, int, struct bgp_ls_node_desc *);

extern int bgp_ls_attr_tlv_unknown_handler(u_char *, u_int16_t, u_int16_t, int, void *);

int bgp_ls_log_msg(struct bgp_ls_nlri *, struct bgp_attr_ls *, afi_t, safi_t, bgp_tag_t *, char *, int, char **, int);
void bgp_ls_log_node_desc(void *, struct bgp_ls_node_desc *, u_int8_t, char *, int);
void bgp_ls_isis_sysid_print(char *, char *);
int bgp_ls_attr_tlv_string_print(u_char *, u_int16_t, char *, u_int8_t, int, void *); 
int bgp_ls_attr_tlv_ip_print(u_char *, u_int16_t, char *, u_int8_t, int, void *);
int bgp_ls_attr_tlv_int8_print(u_char *, u_int16_t, char *, u_int8_t, int, void *);
int bgp_ls_attr_tlv_int32_print(u_char *, u_int16_t, char *, u_int8_t, int, void *);

/* global variables */
extern cdada_map_t *bgp_ls_nlri_tlv_map, *bgp_ls_nd_tlv_map, *bgp_ls_nlri_map;
extern cdada_map_t *bgp_ls_attr_tlv_print_map;
#endif //BGP_LS_H
