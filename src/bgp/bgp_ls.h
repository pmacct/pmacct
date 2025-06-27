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

#define BGP_LS_ISIS_SYS_ID_LEN		6 

/* structures */
struct bgp_ls_node_desc {
  as_t asn;
  u_int32_t bgp_ls_id;
  union {
    struct {
      char rtr_id[6];
      u_int8_t psn_id;
    } isis;
    struct {
      u_int32_t area_id;
      u_int32_t rtr_id;
      u_int32_t if_id;
    } ospf;
  } igp_id;
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
  struct host_addr nexthop;
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

typedef int (*bgp_ls_nlri_tlv_hdlr)(char *, int, struct bgp_ls_nlri *);
typedef int (*bgp_ls_nd_tlv_hdlr)(char *, int, struct bgp_ls_node_desc *);

struct bgp_ls_nlri_tlv_list_entry {
  u_int16_t type;
  bgp_ls_nlri_tlv_hdlr hdlr;
};

struct bgp_ls_nd_tlv_list_entry {
  u_int16_t type;
  bgp_ls_nd_tlv_hdlr hdlr;
};

struct bgp_ls_nlri_map_trav_del {
  struct bgp_peer *peer;
  cdada_list_t *list_del;
};

/* prototypes */
extern void bgp_ls_init();
extern int bgp_attr_parse_ls(struct bgp_peer *, u_int16_t, struct bgp_attr_extra *, char *, u_char);
extern int bgp_ls_nlri_parse(struct bgp_msg_data *, struct bgp_attr *, struct bgp_attr_extra *, struct bgp_nlri *, int);
extern void bgp_ls_info_delete(struct bgp_peer *);
extern void bgp_ls_peer_info_delete(const cdada_map_t *, const void *, void *, void *);

extern int bgp_ls_nlri_tlv_local_nd_handler(char *, int, struct bgp_ls_nlri *);
extern int bgp_ls_nlri_tlv_remote_nd_handler(char *, int, struct bgp_ls_nlri *);
extern int bgp_ls_nlri_tlv_v4_addr_if_handler(char *, int, struct bgp_ls_nlri *);
extern int bgp_ls_nlri_tlv_v4_addr_neigh_handler(char *, int, struct bgp_ls_nlri *);
extern int bgp_ls_nlri_tlv_v6_addr_if_handler(char *, int, struct bgp_ls_nlri *);
extern int bgp_ls_nlri_tlv_v6_addr_neigh_handler(char *, int, struct bgp_ls_nlri *);
extern int bgp_ls_nlri_tlv_ip_reach_handler(char *, int, struct bgp_ls_nlri *);

extern int bgp_ls_nd_tlv_as_handler(char *, int, struct bgp_ls_node_desc *);
extern int bgp_ls_nd_tlv_router_id_handler(char *, int, struct bgp_ls_node_desc *);

int bgp_ls_log_msg(struct bgp_ls_nlri *, struct bgp_attr_ls *, afi_t, safi_t, bgp_tag_t *, char *, int, char **, int);
void bgp_ls_log_node_desc(void *, struct bgp_ls_node_desc *, u_int8_t, char *, int);
void bgp_ls_isis_sysid_print(char *, char *);

/* global variables */
extern cdada_map_t *bgp_ls_nlri_tlv_map, *bgp_ls_nd_tlv_map, *bgp_ls_nlri_map;

#endif //BGP_LS_H
