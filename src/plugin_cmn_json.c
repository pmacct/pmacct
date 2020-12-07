/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "pmacct-data.h"
#include "plugin_common.h"
#include "plugin_cmn_json.h"
#include "ip_flow.h"
#include "classifier.h"
#include "bgp/bgp.h"
#include "rpki/rpki.h"
#if defined (WITH_NDPI)
#include "ndpi/ndpi.h"
#endif

#ifdef WITH_JANSSON

/* Global variables */
compose_json_handler cjhandler[N_PRIMITIVES];

/* Functions */
void compose_json(u_int64_t wtc, u_int64_t wtc_2)
{
  int idx = 0;

  Log(LOG_INFO, "INFO ( %s/%s ): JSON: setting object handlers.\n", config.name, config.type);

  memset(&cjhandler, 0, sizeof(cjhandler));

  cjhandler[idx] = compose_json_event_type;
  idx++;

  if (wtc & COUNT_TAG) {
    cjhandler[idx] = compose_json_tag;
    idx++;
  }

  if (wtc & COUNT_TAG2) {
    cjhandler[idx] = compose_json_tag2;
    idx++;
  }

  if (wtc_2 & COUNT_LABEL) {
    cjhandler[idx] = compose_json_label;
    idx++;
  }

  if (wtc & COUNT_CLASS) {
    cjhandler[idx] = compose_json_class;
    idx++;
  }

#if defined (WITH_NDPI)
  if (wtc_2 & COUNT_NDPI_CLASS) {
    cjhandler[idx] = compose_json_ndpi_class;
    idx++;
  }
#endif

#if defined (HAVE_L2)
  if (wtc & (COUNT_SRC_MAC|COUNT_SUM_MAC)) {
    cjhandler[idx] = compose_json_src_mac;
    idx++;
  }

  if (wtc & COUNT_DST_MAC) {
    cjhandler[idx] = compose_json_dst_mac;
    idx++;
  }

  if (wtc & COUNT_VLAN) {
    cjhandler[idx] = compose_json_vlan;
    idx++;
  }

  if (wtc & COUNT_COS) {
    cjhandler[idx] = compose_json_cos;
    idx++;
  }

  if (wtc & COUNT_ETHERTYPE) {
    cjhandler[idx] = compose_json_etype;
    idx++;
  }
#endif

  if (wtc & (COUNT_SRC_AS|COUNT_SUM_AS)) {
    cjhandler[idx] = compose_json_src_as;
    idx++;
  }

  if (wtc & COUNT_DST_AS) {
    cjhandler[idx] = compose_json_dst_as;
    idx++;
  }

  if (wtc & COUNT_STD_COMM) {
    cjhandler[idx] = compose_json_std_comm;
    idx++;
  }

  if (wtc & COUNT_EXT_COMM) {
    cjhandler[idx] = compose_json_ext_comm;
    idx++;
  }

  if (wtc_2 & COUNT_LRG_COMM) {
    cjhandler[idx] = compose_json_lrg_comm;
    idx++;
  }

  if (wtc & COUNT_AS_PATH) {
    cjhandler[idx] = compose_json_as_path;
    idx++;
  }

  if (wtc & COUNT_LOCAL_PREF) {
    cjhandler[idx] = compose_json_local_pref;
    idx++;
  }

  if (wtc & COUNT_MED) {
    cjhandler[idx] = compose_json_med;
    idx++;
  }

  if (wtc_2 & COUNT_DST_ROA) {
    cjhandler[idx] = compose_json_dst_roa;
    idx++;
  }

  if (wtc & COUNT_PEER_SRC_AS) {
    cjhandler[idx] = compose_json_peer_src_as;
    idx++;
  }

  if (wtc & COUNT_PEER_DST_AS) {
    cjhandler[idx] = compose_json_peer_dst_as;
    idx++;
  }

  if (wtc & COUNT_PEER_SRC_IP) {
    cjhandler[idx] = compose_json_peer_src_ip;
    idx++;
  }

  if (wtc & COUNT_PEER_DST_IP) {
    cjhandler[idx] = compose_json_peer_dst_ip;
    idx++;
  }

  if (wtc & COUNT_SRC_STD_COMM) {
    cjhandler[idx] = compose_json_src_std_comm;
    idx++;
  }

  if (wtc & COUNT_SRC_EXT_COMM) {
    cjhandler[idx] = compose_json_src_ext_comm;
    idx++;
  }

  if (wtc_2 & COUNT_SRC_LRG_COMM) {
    cjhandler[idx] = compose_json_src_lrg_comm;
    idx++;
  }

  if (wtc & COUNT_SRC_AS_PATH) {
    cjhandler[idx] = compose_json_src_as_path;
    idx++;
  }

  if (wtc & COUNT_SRC_LOCAL_PREF) {
    cjhandler[idx] = compose_json_src_local_pref;
    idx++;
  }

  if (wtc & COUNT_SRC_MED) {
    cjhandler[idx] = compose_json_src_med;
    idx++;
  }

  if (wtc_2 & COUNT_SRC_ROA) {
    cjhandler[idx] = compose_json_src_roa;
    idx++;
  }

  if (wtc & COUNT_IN_IFACE) {
    cjhandler[idx] = compose_json_in_iface;
    idx++;
  }

  if (wtc & COUNT_OUT_IFACE) {
    cjhandler[idx] = compose_json_out_iface;
    idx++;
  }

  if (wtc & COUNT_MPLS_VPN_RD) {
    cjhandler[idx] = compose_json_mpls_vpn_rd;
    idx++;
  }

  if (wtc_2 & COUNT_MPLS_PW_ID) {
    cjhandler[idx] = compose_json_mpls_pw_id;
    idx++;
  }

  if (wtc & (COUNT_SRC_HOST|COUNT_SUM_HOST)) {
    cjhandler[idx] = compose_json_src_host;
    idx++;
  }

  if (wtc & (COUNT_SRC_NET|COUNT_SUM_NET)) {
    cjhandler[idx] = compose_json_src_net;
    idx++;
  }

  if (wtc & COUNT_DST_HOST) {
    cjhandler[idx] = compose_json_dst_host;
    idx++;
  }

  if (wtc & COUNT_DST_NET) {
    cjhandler[idx] = compose_json_dst_net;
    idx++;
  }

  if (wtc & COUNT_SRC_NMASK) {
    cjhandler[idx] = compose_json_src_mask;
    idx++;
  }

  if (wtc & COUNT_DST_NMASK) {
    cjhandler[idx] = compose_json_dst_mask;
    idx++;
  }

  if (wtc & (COUNT_SRC_PORT|COUNT_SUM_PORT)) {
    cjhandler[idx] = compose_json_src_port;
    idx++;
  }

  if (wtc & COUNT_DST_PORT) {
    cjhandler[idx] = compose_json_dst_port;
    idx++;
  }

#if defined (WITH_GEOIP)
  if (wtc_2 & COUNT_SRC_HOST_COUNTRY) {
    cjhandler[idx] = compose_json_src_host_country;
    idx++;
  }

  if (wtc_2 & COUNT_DST_HOST_COUNTRY) {
    cjhandler[idx] = compose_json_dst_host_country;
    idx++;
  }
#endif
#if defined (WITH_GEOIPV2)
  if (wtc_2 & COUNT_SRC_HOST_COUNTRY) {
    cjhandler[idx] = compose_json_src_host_country;
    idx++;
  }

  if (wtc_2 & COUNT_DST_HOST_COUNTRY) {
    cjhandler[idx] = compose_json_dst_host_country;
    idx++;
  }

  if (wtc_2 & COUNT_SRC_HOST_POCODE) {
    cjhandler[idx] = compose_json_src_host_pocode;
    idx++;
  }

  if (wtc_2 & COUNT_DST_HOST_POCODE) {
    cjhandler[idx] = compose_json_dst_host_pocode;
    idx++;
  }

  if (wtc_2 & COUNT_SRC_HOST_COORDS) {
    cjhandler[idx] = compose_json_src_host_coords;
    idx++;
  }

  if (wtc_2 & COUNT_DST_HOST_COORDS) {
    cjhandler[idx] = compose_json_dst_host_coords;
    idx++;
  }

#endif

  if (wtc & COUNT_TCPFLAGS) {
    cjhandler[idx] = compose_json_tcp_flags;
    idx++;
  }

  if (wtc & COUNT_IP_PROTO) {
    cjhandler[idx] = compose_json_proto;
    idx++;
  }

  if (wtc & COUNT_IP_TOS) {
    cjhandler[idx] = compose_json_tos;
    idx++;
  }

  if (wtc_2 & COUNT_SAMPLING_RATE) {
    cjhandler[idx] = compose_json_sampling_rate;
    idx++;
  }

  if (wtc_2 & COUNT_SAMPLING_DIRECTION) {
    cjhandler[idx] = compose_json_sampling_direction;
    idx++;
  }

  if (wtc_2 & COUNT_POST_NAT_SRC_HOST) {
    cjhandler[idx] = compose_json_post_nat_src_host;
    idx++;
  }

  if (wtc_2 & COUNT_POST_NAT_DST_HOST) {
    cjhandler[idx] = compose_json_post_nat_dst_host;
    idx++;
  }

  if (wtc_2 & COUNT_POST_NAT_SRC_PORT) {
    cjhandler[idx] = compose_json_post_nat_src_port;
    idx++;
  }

  if (wtc_2 & COUNT_POST_NAT_DST_PORT) {
    cjhandler[idx] = compose_json_post_nat_dst_port;
    idx++;
  }

  if (wtc_2 & COUNT_NAT_EVENT) {
    cjhandler[idx] = compose_json_nat_event;
    idx++;
  }

  if (wtc_2 & COUNT_MPLS_LABEL_TOP) {
    cjhandler[idx] = compose_json_mpls_label_top;
    idx++;
  }

  if (wtc_2 & COUNT_MPLS_LABEL_BOTTOM) {
    cjhandler[idx] = compose_json_mpls_label_bottom;
    idx++;
  }

  if (wtc_2 & COUNT_MPLS_STACK_DEPTH) {
    cjhandler[idx] = compose_json_mpls_stack_depth;
    idx++;
  }

  if (wtc_2 & COUNT_TUNNEL_SRC_MAC) {
    cjhandler[idx] = compose_json_tunnel_src_mac;
    idx++;
  }

  if (wtc_2 & COUNT_TUNNEL_DST_MAC) {
    cjhandler[idx] = compose_json_tunnel_dst_mac;
    idx++;
  }

  if (wtc_2 & COUNT_TUNNEL_SRC_HOST) {
    cjhandler[idx] = compose_json_tunnel_src_host;
    idx++;
  }

  if (wtc_2 & COUNT_TUNNEL_DST_HOST) {
    cjhandler[idx] = compose_json_tunnel_dst_host;
    idx++;
  }

  if (wtc_2 & COUNT_TUNNEL_IP_PROTO) {
    cjhandler[idx] = compose_json_tunnel_proto;
    idx++;
  } 
    
  if (wtc_2 & COUNT_TUNNEL_IP_TOS) {
    cjhandler[idx] = compose_json_tunnel_tos;
    idx++;
  }

  if (wtc_2 & COUNT_TUNNEL_SRC_PORT) {
    cjhandler[idx] = compose_json_tunnel_src_port;
    idx++;
  }

  if (wtc_2 & COUNT_TUNNEL_DST_PORT) {
    cjhandler[idx] = compose_json_tunnel_dst_port;
    idx++;
  }

  if (wtc_2 & COUNT_VXLAN) {
    cjhandler[idx] = compose_json_vxlan;
    idx++;
  }

  if (wtc_2 & COUNT_TIMESTAMP_START) {
    cjhandler[idx] = compose_json_timestamp_start;
    idx++;
  }

  if (wtc_2 & COUNT_TIMESTAMP_END) {
    cjhandler[idx] = compose_json_timestamp_end;
    idx++;
  }

  if (wtc_2 & COUNT_TIMESTAMP_ARRIVAL) {
    cjhandler[idx] = compose_json_timestamp_arrival;
    idx++;
  }

  if (config.nfacctd_stitching) {
    cjhandler[idx] = compose_json_timestamp_stitching;
    idx++;
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_SEQNO) {
    cjhandler[idx] = compose_json_export_proto_seqno;
    idx++;
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_VERSION) {
    cjhandler[idx] = compose_json_export_proto_version;
    idx++;
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_SYSID) {
    cjhandler[idx] = compose_json_export_proto_sysid;
    idx++;
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_TIME) {
    cjhandler[idx] = compose_json_timestamp_export;
    idx++;
  }

  if (config.cpptrs.num) {
    cjhandler[idx] = compose_json_custom_primitives;
    idx++;
  }

  if (config.sql_history) {
    cjhandler[idx] = compose_json_history;
    idx++;
  }

  if (wtc & COUNT_FLOWS) {
    cjhandler[idx] = compose_json_flows;
    idx++;
  }

  cjhandler[idx] = compose_json_counters;
}

void compose_json_event_type(json_t *obj, struct chained_cache *null)
{
  char event_type[] = "purge";

  json_object_set_new_nocheck(obj, "event_type", json_string(event_type));
}

void compose_json_tag(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "tag", json_integer((json_int_t)cc->primitives.tag));
}

void compose_json_tag2(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "tag2", json_integer((json_int_t)cc->primitives.tag2));
}

void compose_json_label(json_t *obj, struct chained_cache *cc)
{
  char empty_string[] = "", *str_ptr;

  vlen_prims_get(cc->pvlen, COUNT_INT_LABEL, &str_ptr);
  if (!str_ptr) str_ptr = empty_string;

  json_object_set_new_nocheck(obj, "label", json_string(str_ptr));
}

void compose_json_class(json_t *obj, struct chained_cache *cc)
{
  struct pkt_primitives *pbase = &cc->primitives;

  json_object_set_new_nocheck(obj, "class", json_string((pbase->class && class[(pbase->class)-1].id) ? class[(pbase->class)-1].protocol : "unknown"));
}

#if defined (WITH_NDPI)
void compose_json_ndpi_class(json_t *obj, struct chained_cache *cc)
{
  char ndpi_class[SUPERSHORTBUFLEN];
  struct pkt_primitives *pbase = &cc->primitives;

  snprintf(ndpi_class, SUPERSHORTBUFLEN, "%s/%s",
	ndpi_get_proto_name(pm_ndpi_wfl->ndpi_struct, pbase->ndpi_class.master_protocol),
	ndpi_get_proto_name(pm_ndpi_wfl->ndpi_struct, pbase->ndpi_class.app_protocol));

  json_object_set_new_nocheck(obj, "class", json_string(ndpi_class));
}
#endif

#if defined (HAVE_L2)
void compose_json_src_mac(json_t *obj, struct chained_cache *cc)
{
  char mac[18];

  etheraddr_string(cc->primitives.eth_shost, mac);
  json_object_set_new_nocheck(obj, "mac_src", json_string(mac));
}

void compose_json_dst_mac(json_t *obj, struct chained_cache *cc)
{
  char mac[18];
  
  etheraddr_string(cc->primitives.eth_dhost, mac);
  json_object_set_new_nocheck(obj, "mac_dst", json_string(mac));
}

void compose_json_vlan(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "vlan", json_integer((json_int_t)cc->primitives.vlan_id));
}

void compose_json_cos(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "cos", json_integer((json_int_t)cc->primitives.cos));
}

void compose_json_etype(json_t *obj, struct chained_cache *cc)
{
  char misc_str[VERYSHORTBUFLEN];

  sprintf(misc_str, "%x", cc->primitives.etype);
  json_object_set_new_nocheck(obj, "etype", json_string(misc_str));
}
#endif

void compose_json_src_as(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "as_src", json_integer((json_int_t)cc->primitives.src_as));
}

void compose_json_dst_as(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "as_dst", json_integer((json_int_t)cc->primitives.dst_as));
}

void compose_json_std_comm(json_t *obj, struct chained_cache *cc)
{
  char *str_ptr = NULL, *bgp_comm, empty_string[] = "";

  vlen_prims_get(cc->pvlen, COUNT_INT_STD_COMM, &str_ptr);
  if (str_ptr) {
    bgp_comm = str_ptr;
    while (bgp_comm) {
      bgp_comm = strchr(str_ptr, ' ');
      if (bgp_comm) *bgp_comm = '_';
    }
  }
  else str_ptr = empty_string;

  json_object_set_new_nocheck(obj, "comms", json_string(str_ptr));
}

void compose_json_ext_comm(json_t *obj, struct chained_cache *cc)
{
  char *str_ptr = NULL, *bgp_comm, empty_string[] = "";

  vlen_prims_get(cc->pvlen, COUNT_INT_EXT_COMM, &str_ptr);
  if (str_ptr) {
    bgp_comm = str_ptr;
    while (bgp_comm) {
      bgp_comm = strchr(str_ptr, ' ');
      if (bgp_comm) *bgp_comm = '_';
    }
  }
  else str_ptr = empty_string;

  json_object_set_new_nocheck(obj, "ecomms", json_string(str_ptr));
}

void compose_json_lrg_comm(json_t *obj, struct chained_cache *cc)
{
  char *str_ptr = NULL, *bgp_comm, empty_string[] = "";

  vlen_prims_get(cc->pvlen, COUNT_INT_LRG_COMM, &str_ptr);
  if (str_ptr) {
    bgp_comm = str_ptr;
    while (bgp_comm) {
      bgp_comm = strchr(str_ptr, ' ');
      if (bgp_comm) *bgp_comm = '_';
    }
  }
  else str_ptr = empty_string;

  json_object_set_new_nocheck(obj, "lcomms", json_string(str_ptr));
}

void compose_json_as_path(json_t *obj, struct chained_cache *cc)
{
  char *str_ptr = NULL, *as_path, empty_string[] = "";

  vlen_prims_get(cc->pvlen, COUNT_INT_AS_PATH, &str_ptr);
  if (str_ptr) {
    as_path = str_ptr;
    while (as_path) {
      as_path = strchr(str_ptr, ' ');
      if (as_path) *as_path = '_';
    }
  }
  else str_ptr = empty_string;

  json_object_set_new_nocheck(obj, "as_path", json_string(str_ptr));
}

void compose_json_local_pref(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "local_pref", json_integer((json_int_t)cc->pbgp->local_pref));
}

void compose_json_med(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "med", json_integer((json_int_t)cc->pbgp->med));
}

void compose_json_dst_roa(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "roa_dst", json_string(rpki_roa_print(cc->pbgp->dst_roa)));
}

void compose_json_peer_src_as(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "peer_as_src", json_integer((json_int_t)cc->pbgp->peer_src_as));
}

void compose_json_peer_dst_as(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "peer_as_dst", json_integer((json_int_t)cc->pbgp->peer_dst_as));
}

void compose_json_peer_src_ip(json_t *obj, struct chained_cache *cc)
{
  char ip_address[INET6_ADDRSTRLEN];

  addr_to_str(ip_address, &cc->pbgp->peer_src_ip);
  json_object_set_new_nocheck(obj, "peer_ip_src", json_string(ip_address));
}

void compose_json_peer_dst_ip(json_t *obj, struct chained_cache *cc)
{
  char ip_address[INET6_ADDRSTRLEN];

  addr_to_str2(ip_address, &cc->pbgp->peer_dst_ip, ft2af(cc->flow_type));
  json_object_set_new_nocheck(obj, "peer_ip_dst", json_string(ip_address));
}

void compose_json_src_std_comm(json_t *obj, struct chained_cache *cc)
{
  char *str_ptr = NULL, *bgp_comm, empty_string[] = "";

  vlen_prims_get(cc->pvlen, COUNT_INT_SRC_STD_COMM, &str_ptr);
  if (str_ptr) {
    bgp_comm = str_ptr;
    while (bgp_comm) {
      bgp_comm = strchr(str_ptr, ' ');
      if (bgp_comm) *bgp_comm = '_';
    }
  }
  else str_ptr = empty_string;

  json_object_set_new_nocheck(obj, "comms_src", json_string(str_ptr));
}

void compose_json_src_ext_comm(json_t *obj, struct chained_cache *cc)
{
  char *str_ptr = NULL, *bgp_comm, empty_string[] = "";

  vlen_prims_get(cc->pvlen, COUNT_INT_SRC_EXT_COMM, &str_ptr);
  if (str_ptr) {
    bgp_comm = str_ptr;
    while (bgp_comm) {
      bgp_comm = strchr(str_ptr, ' ');
      if (bgp_comm) *bgp_comm = '_';
    }
  }
  else str_ptr = empty_string;

  json_object_set_new_nocheck(obj, "ecomms_src", json_string(str_ptr));
}

void compose_json_src_lrg_comm(json_t *obj, struct chained_cache *cc)
{
  char *str_ptr = NULL, *bgp_comm, empty_string[] = "";

  vlen_prims_get(cc->pvlen, COUNT_INT_SRC_LRG_COMM, &str_ptr);
  if (str_ptr) {
    bgp_comm = str_ptr;
    while (bgp_comm) {
      bgp_comm = strchr(str_ptr, ' ');
      if (bgp_comm) *bgp_comm = '_';
    }
  }
  else str_ptr = empty_string;

  json_object_set_new_nocheck(obj, "lcomms_src", json_string(str_ptr));
}

void compose_json_src_as_path(json_t *obj, struct chained_cache *cc)
{
  char *str_ptr = NULL, *as_path, empty_string[] = "";

  vlen_prims_get(cc->pvlen, COUNT_INT_SRC_AS_PATH, &str_ptr);
  if (str_ptr) {
    as_path = str_ptr;
    while (as_path) {
      as_path = strchr(str_ptr, ' ');
      if (as_path) *as_path = '_';
    }
  }
  else str_ptr = empty_string;

  json_object_set_new_nocheck(obj, "as_path_src", json_string(str_ptr));
}

void compose_json_src_local_pref(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "local_pref_src", json_integer((json_int_t)cc->pbgp->src_local_pref));
}

void compose_json_src_med(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "med_src", json_integer((json_int_t)cc->pbgp->src_med));
}

void compose_json_src_roa(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "roa_src", json_string(rpki_roa_print(cc->pbgp->src_roa)));
}

void compose_json_in_iface(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "iface_in", json_integer((json_int_t)cc->primitives.ifindex_in));
}

void compose_json_out_iface(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "iface_out", json_integer((json_int_t)cc->primitives.ifindex_out));
}

void compose_json_mpls_vpn_rd(json_t *obj, struct chained_cache *cc)
{
  char rd_str[VERYSHORTBUFLEN];

  bgp_rd2str(rd_str, &cc->pbgp->mpls_vpn_rd);
  json_object_set_new_nocheck(obj, "mpls_vpn_rd", json_string(rd_str));
}

void compose_json_mpls_pw_id(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "mpls_pw_id", json_integer((json_int_t)cc->pbgp->mpls_pw_id));
}

void compose_json_src_host(json_t *obj, struct chained_cache *cc)
{
  char ip_address[INET6_ADDRSTRLEN];

  addr_to_str(ip_address, &cc->primitives.src_ip);
  json_object_set_new_nocheck(obj, "ip_src", json_string(ip_address));
}

void compose_json_src_net(json_t *obj, struct chained_cache *cc)
{
  char ip_address[INET6_ADDRSTRLEN];

  addr_to_str(ip_address, &cc->primitives.src_net);
  json_object_set_new_nocheck(obj, "net_src", json_string(ip_address));
}

void compose_json_dst_host(json_t *obj, struct chained_cache *cc)
{
  char ip_address[INET6_ADDRSTRLEN];

  addr_to_str(ip_address, &cc->primitives.dst_ip);
  json_object_set_new_nocheck(obj, "ip_dst", json_string(ip_address));
}

void compose_json_dst_net(json_t *obj, struct chained_cache *cc)
{
  char ip_address[INET6_ADDRSTRLEN];

  addr_to_str(ip_address, &cc->primitives.dst_net);
  json_object_set_new_nocheck(obj, "net_dst", json_string(ip_address));
}

void compose_json_src_mask(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "mask_src", json_integer((json_int_t)cc->primitives.src_nmask));
}

void compose_json_dst_mask(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "mask_dst", json_integer((json_int_t)cc->primitives.dst_nmask));
}

void compose_json_src_port(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "port_src", json_integer((json_int_t)cc->primitives.src_port));
}

void compose_json_dst_port(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "port_dst", json_integer((json_int_t)cc->primitives.dst_port));
}

#if defined (WITH_GEOIP)
void compose_json_src_host_country(json_t *obj, struct chained_cache *cc)
{
  char empty_string[] = "";
 
  if (cc->primitives.src_ip_country.id > 0)
    json_object_set_new_nocheck(obj, "country_ip_src", json_string(GeoIP_code_by_id(cc->primitives.src_ip_country.id)));
  else
    json_object_set_new_nocheck(obj, "country_ip_src", json_string(empty_string));
}

void compose_json_dst_host_country(json_t *obj, struct chained_cache *cc)
{
  char empty_string[] = "";

  if (cc->primitives.dst_ip_country.id > 0)
    json_object_set_new_nocheck(obj, "country_ip_dst", json_string(GeoIP_code_by_id(cc->primitives.dst_ip_country.id)));
  else
    json_object_set_new_nocheck(obj, "country_ip_dst", json_string(empty_string));
}
#endif
#if defined (WITH_GEOIPV2)
void compose_json_src_host_country(json_t *obj, struct chained_cache *cc)
{
  char empty_string[] = "";

  if (strlen(cc->primitives.src_ip_country.str))
    json_object_set_new_nocheck(obj, "country_ip_src", json_string(cc->primitives.src_ip_country.str));
  else
    json_object_set_new_nocheck(obj, "country_ip_src", json_string(empty_string));
}

void compose_json_dst_host_country(json_t *obj, struct chained_cache *cc)
{
  char empty_string[] = "";

  if (strlen(cc->primitives.dst_ip_country.str))
    json_object_set_new_nocheck(obj, "country_ip_dst", json_string(cc->primitives.dst_ip_country.str));
  else
    json_object_set_new_nocheck(obj, "country_ip_dst", json_string(empty_string));
}

void compose_json_src_host_pocode(json_t *obj, struct chained_cache *cc)
{
  char empty_string[] = "";

  if (strlen(cc->primitives.src_ip_pocode.str))
    json_object_set_new_nocheck(obj, "pocode_ip_src", json_string(cc->primitives.src_ip_pocode.str));
  else
    json_object_set_new_nocheck(obj, "pocode_ip_src", json_string(empty_string));
}

void compose_json_dst_host_pocode(json_t *obj, struct chained_cache *cc)
{
  char empty_string[] = "";

  if (strlen(cc->primitives.dst_ip_pocode.str))
    json_object_set_new_nocheck(obj, "pocode_ip_dst", json_string(cc->primitives.dst_ip_pocode.str));
  else
    json_object_set_new_nocheck(obj, "pocode_ip_dst", json_string(empty_string));
}

void compose_json_src_host_coords(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "lat_ip_src", json_real(cc->primitives.src_ip_lat));
  json_object_set_new_nocheck(obj, "lon_ip_src", json_real(cc->primitives.src_ip_lon));
}

void compose_json_dst_host_coords(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "lat_ip_dst", json_real(cc->primitives.dst_ip_lat));
  json_object_set_new_nocheck(obj, "lon_ip_dst", json_real(cc->primitives.dst_ip_lon));
}
#endif

void compose_json_tcp_flags(json_t *obj, struct chained_cache *cc)
{
  char misc_str[VERYSHORTBUFLEN];

  sprintf(misc_str, "%u", cc->tcp_flags);
  json_object_set_new_nocheck(obj, "tcp_flags", json_string(misc_str));
}

void compose_json_proto(json_t *obj, struct chained_cache *cc)
{
  char proto[PROTO_NUM_STRLEN];

  json_object_set_new_nocheck(obj, "ip_proto", json_string(ip_proto_print(cc->primitives.proto, proto, PROTO_NUM_STRLEN)));
}

void compose_json_tos(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "tos", json_integer((json_int_t)cc->primitives.tos));
}

void compose_json_sampling_rate(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "sampling_rate", json_integer((json_int_t)cc->primitives.sampling_rate));
}

void compose_json_sampling_direction(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "sampling_direction", json_string(cc->primitives.sampling_direction));
}

void compose_json_post_nat_src_host(json_t *obj, struct chained_cache *cc)
{
  char ip_address[INET6_ADDRSTRLEN];

  addr_to_str(ip_address, &cc->pnat->post_nat_src_ip);
  json_object_set_new_nocheck(obj, "post_nat_ip_src", json_string(ip_address));
}

void compose_json_post_nat_dst_host(json_t *obj, struct chained_cache *cc)
{
  char ip_address[INET6_ADDRSTRLEN];

  addr_to_str(ip_address, &cc->pnat->post_nat_dst_ip);
  json_object_set_new_nocheck(obj, "post_nat_ip_dst", json_string(ip_address));
}

void compose_json_post_nat_src_port(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "post_nat_port_src", json_integer((json_int_t)cc->pnat->post_nat_src_port));
}

void compose_json_post_nat_dst_port(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "post_nat_port_dst", json_integer((json_int_t)cc->pnat->post_nat_dst_port));
}

void compose_json_nat_event(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "nat_event", json_integer((json_int_t)cc->pnat->nat_event));
}

void compose_json_mpls_label_top(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "mpls_label_top", json_integer((json_int_t)cc->pmpls->mpls_label_top));
}

void compose_json_mpls_label_bottom(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "mpls_label_bottom", json_integer((json_int_t)cc->pmpls->mpls_label_bottom));
}

void compose_json_mpls_stack_depth(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "mpls_stack_depth", json_integer((json_int_t)cc->pmpls->mpls_stack_depth));
}

void compose_json_tunnel_src_mac(json_t *obj, struct chained_cache *cc)
{
  char mac[18];

  etheraddr_string(cc->ptun->tunnel_eth_shost, mac);
  json_object_set_new_nocheck(obj, "tunnel_mac_src", json_string(mac));
}

void compose_json_tunnel_dst_mac(json_t *obj, struct chained_cache *cc)
{
  char mac[18];

  etheraddr_string(cc->ptun->tunnel_eth_dhost, mac);
  json_object_set_new_nocheck(obj, "tunnel_mac_dst", json_string(mac));
}

void compose_json_tunnel_src_host(json_t *obj, struct chained_cache *cc)
{
  char ip_address[INET6_ADDRSTRLEN];

  addr_to_str(ip_address, &cc->ptun->tunnel_src_ip);
  json_object_set_new_nocheck(obj, "tunnel_ip_src", json_string(ip_address));
}

void compose_json_tunnel_dst_host(json_t *obj, struct chained_cache *cc)
{
  char ip_address[INET6_ADDRSTRLEN];

  addr_to_str(ip_address, &cc->ptun->tunnel_dst_ip);
  json_object_set_new_nocheck(obj, "tunnel_ip_dst", json_string(ip_address));
}

void compose_json_tunnel_proto(json_t *obj, struct chained_cache *cc)
{
  char proto[PROTO_NUM_STRLEN];

  json_object_set_new_nocheck(obj, "tunnel_ip_proto", json_string(ip_proto_print(cc->ptun->tunnel_proto, proto, PROTO_NUM_STRLEN)));
}

void compose_json_tunnel_tos(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "tunnel_tos", json_integer((json_int_t)cc->ptun->tunnel_tos));
}

void compose_json_tunnel_src_port(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "tunnel_port_src", json_integer((json_int_t)cc->ptun->tunnel_src_port));
}

void compose_json_tunnel_dst_port(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "tunnel_port_dst", json_integer((json_int_t)cc->ptun->tunnel_dst_port));
}

void compose_json_vxlan(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "vxlan", json_integer((json_int_t)cc->ptun->tunnel_id));
}

void compose_json_timestamp_start(json_t *obj, struct chained_cache *cc)
{
  char tstamp_str[VERYSHORTBUFLEN];

  compose_timestamp(tstamp_str, VERYSHORTBUFLEN, &cc->pnat->timestamp_start, TRUE,
		    config.timestamps_since_epoch, config.timestamps_rfc3339,
		    config.timestamps_utc);
  json_object_set_new_nocheck(obj, "timestamp_start", json_string(tstamp_str));
}

void compose_json_timestamp_end(json_t *obj, struct chained_cache *cc)
{
  char tstamp_str[VERYSHORTBUFLEN];

  compose_timestamp(tstamp_str, VERYSHORTBUFLEN, &cc->pnat->timestamp_end, TRUE,
		    config.timestamps_since_epoch, config.timestamps_rfc3339,
		    config.timestamps_utc);
  json_object_set_new_nocheck(obj, "timestamp_end", json_string(tstamp_str));
}

void compose_json_timestamp_arrival(json_t *obj, struct chained_cache *cc)
{
  char tstamp_str[VERYSHORTBUFLEN];

  compose_timestamp(tstamp_str, VERYSHORTBUFLEN, &cc->pnat->timestamp_arrival, TRUE,
		    config.timestamps_since_epoch, config.timestamps_rfc3339,
		    config.timestamps_utc);
  json_object_set_new_nocheck(obj, "timestamp_arrival", json_string(tstamp_str));
}

void compose_json_timestamp_export(json_t *obj, struct chained_cache *cc)
{
  char tstamp_str[VERYSHORTBUFLEN];

  compose_timestamp(tstamp_str, VERYSHORTBUFLEN, &cc->pnat->timestamp_export, TRUE,
		    config.timestamps_since_epoch, config.timestamps_rfc3339,
		    config.timestamps_utc);
  json_object_set_new_nocheck(obj, "timestamp_export", json_string(tstamp_str));
}

void compose_json_timestamp_stitching(json_t *obj, struct chained_cache *cc)
{
  char tstamp_str[VERYSHORTBUFLEN];

  compose_timestamp(tstamp_str, VERYSHORTBUFLEN, &cc->stitch->timestamp_min, TRUE,
		    config.timestamps_since_epoch, config.timestamps_rfc3339,
		    config.timestamps_utc);
  json_object_set_new_nocheck(obj, "timestamp_min", json_string(tstamp_str));

  compose_timestamp(tstamp_str, VERYSHORTBUFLEN, &cc->stitch->timestamp_max, TRUE,
		    config.timestamps_since_epoch, config.timestamps_rfc3339,
		    config.timestamps_utc);
  json_object_set_new_nocheck(obj, "timestamp_max", json_string(tstamp_str));
}

void compose_json_export_proto_seqno(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "export_proto_seqno", json_integer((json_int_t)cc->primitives.export_proto_seqno));
}

void compose_json_export_proto_version(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "export_proto_version", json_integer((json_int_t)cc->primitives.export_proto_version));
}

void compose_json_export_proto_sysid(json_t *obj, struct chained_cache *cc)
{
  json_object_set_new_nocheck(obj, "export_proto_sysid", json_integer((json_int_t)cc->primitives.export_proto_sysid));
}

void compose_json_custom_primitives(json_t *obj, struct chained_cache *cc)
{
  char empty_string[] = "";
  int cp_idx;

  for (cp_idx = 0; cp_idx < config.cpptrs.num; cp_idx++) {
    if (config.cpptrs.primitive[cp_idx].ptr->len != PM_VARIABLE_LENGTH) {
      char cp_str[VERYSHORTBUFLEN];

      custom_primitive_value_print(cp_str, VERYSHORTBUFLEN, cc->pcust, &config.cpptrs.primitive[cp_idx], FALSE);
      json_object_set_new_nocheck(obj, config.cpptrs.primitive[cp_idx].name, json_string(cp_str));
    }
    else {
      char *label_ptr = NULL;

      vlen_prims_get(cc->pvlen, config.cpptrs.primitive[cp_idx].ptr->type, &label_ptr);
      if (!label_ptr) label_ptr = empty_string;
      json_object_set_new_nocheck(obj, config.cpptrs.primitive[cp_idx].name, json_string(label_ptr));
    }
  }
}

void compose_json_history(json_t *obj, struct chained_cache *cc)
{
  if (cc->basetime.tv_sec) {
    char tstamp_str[VERYSHORTBUFLEN];
    struct timeval tv;

    tv.tv_sec = cc->basetime.tv_sec;
    tv.tv_usec = 0;
    compose_timestamp(tstamp_str, VERYSHORTBUFLEN, &tv, FALSE,
		      config.timestamps_since_epoch, config.timestamps_rfc3339,
		      config.timestamps_utc);
    json_object_set_new_nocheck(obj, "stamp_inserted", json_string(tstamp_str));

    tv.tv_sec = time(NULL);
    tv.tv_usec = 0;
    compose_timestamp(tstamp_str, VERYSHORTBUFLEN, &tv, FALSE,
		      config.timestamps_since_epoch, config.timestamps_rfc3339,
		      config.timestamps_utc);
    json_object_set_new_nocheck(obj, "stamp_updated", json_string(tstamp_str));
  }
}

void compose_json_flows(json_t *obj, struct chained_cache *cc)
{
  if (cc->flow_type != NF9_FTYPE_EVENT && cc->flow_type != NF9_FTYPE_OPTION)
    json_object_set_new_nocheck(obj, "flows", json_integer((json_int_t)cc->flow_counter));
}

void compose_json_counters(json_t *obj, struct chained_cache *cc)
{
  if (cc->flow_type != NF9_FTYPE_EVENT && cc->flow_type != NF9_FTYPE_OPTION) {
    json_object_set_new_nocheck(obj, "packets", json_integer((json_int_t)cc->packet_counter));
    json_object_set_new_nocheck(obj, "bytes", json_integer((json_int_t)cc->bytes_counter));
  }
}

void *compose_purge_init_json(char *writer_name, pid_t writer_pid)
{
  char event_type[] = "purge_init", wid[SHORTSHORTBUFLEN];
  json_t *obj = json_object();

  json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

  snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", writer_name, writer_pid);
  json_object_set_new_nocheck(obj, "writer_id", json_string(wid));

  return obj;
}

void *compose_purge_close_json(char *writer_name, pid_t writer_pid, int purged_entries, int total_entries, int duration)
{
  char event_type[] = "purge_close", wid[SHORTSHORTBUFLEN];
  json_t *obj = json_object();

  json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

  snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", writer_name, writer_pid);
  json_object_set_new_nocheck(obj, "writer_id", json_string(wid));

  json_object_set_new_nocheck(obj, "purged_entries", json_integer((json_int_t)purged_entries));
  json_object_set_new_nocheck(obj, "total_entries", json_integer((json_int_t)total_entries));
  json_object_set_new_nocheck(obj, "duration", json_integer((json_int_t)duration));

  return obj;
}
#else
void compose_json(u_int64_t wtc, u_int64_t wtc_2)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): compose_json(): JSON object not created due to missing --enable-jansson\n", config.name, config.type);
}

void *compose_purge_init_json(char *writer_name, pid_t writer_pid)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): compose_purge_init_json(): JSON object not created due to missing --enable-jansson\n", config.name, config.type);

  return NULL;
}

void *compose_purge_close_json(char *writer_name, pid_t writer_pid, int purged_entries, int total_entries, int duration)
{
  if (config.debug) Log(LOG_DEBUG, "DEBUG ( %s/%s ): compose_purge_close_json(): JSON object not created due to missing --enable-jansson\n", config.name, config.type);

  return NULL;
}
#endif
