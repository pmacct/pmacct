/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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

#define __PLUGIN_CMN_AVRO_C

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "pmacct-data.h"
#include "plugin_common.h"
#include "plugin_cmn_json.h"
#include "ip_flow.h"
#include "classifier.h"
#if defined (WITH_NDPI)
#include "ndpi/ndpi.h"
#endif

/* functions */
#ifdef WITH_AVRO
avro_schema_t build_avro_schema(u_int64_t wtc, u_int64_t wtc_2)
{
  avro_schema_t schema = avro_schema_record("acct", NULL);
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();

  Log(LOG_INFO, "INFO ( %s/%s ): AVRO: building schema.\n", config.name, config.type);

  avro_schema_union_append(optlong_s, avro_schema_null());
  avro_schema_union_append(optlong_s, avro_schema_long());

  avro_schema_union_append(optstr_s, avro_schema_null());
  avro_schema_union_append(optstr_s, avro_schema_string());

  if (wtc & COUNT_TAG)
    avro_schema_record_field_append(schema, "tag", avro_schema_long());

  if (wtc & COUNT_TAG2)
    avro_schema_record_field_append(schema, "tag2", avro_schema_long());

  if (wtc_2 & COUNT_LABEL)
    avro_schema_record_field_append(schema, "label", avro_schema_string());

  if (wtc & COUNT_CLASS)
    avro_schema_record_field_append(schema, "class_legacy", avro_schema_string());

#if defined (WITH_NDPI)
  if (wtc_2 & COUNT_NDPI_CLASS)
    avro_schema_record_field_append(schema, "class", avro_schema_string());
#endif

#if defined (HAVE_L2)
  if (wtc & (COUNT_SRC_MAC|COUNT_SUM_MAC))
    avro_schema_record_field_append(schema, "mac_src", avro_schema_string());

  if (wtc & COUNT_DST_MAC)
    avro_schema_record_field_append(schema, "mac_dst", avro_schema_string());

  if (wtc & COUNT_VLAN)
    avro_schema_record_field_append(schema, "vlan", avro_schema_long());

  if (wtc & COUNT_COS)
    avro_schema_record_field_append(schema, "cos", avro_schema_long());

  if (wtc & COUNT_ETHERTYPE)
    avro_schema_record_field_append(schema, "etype", avro_schema_string());
#endif

  if (wtc & (COUNT_SRC_AS|COUNT_SUM_AS))
    avro_schema_record_field_append(schema, "as_src", avro_schema_long());

  if (wtc & COUNT_DST_AS)
    avro_schema_record_field_append(schema, "as_dst", avro_schema_long());

  if (wtc & COUNT_STD_COMM)
    avro_schema_record_field_append(schema, "comms", avro_schema_string());

  if (wtc & COUNT_EXT_COMM)
    avro_schema_record_field_append(schema, "ecomms", avro_schema_string());

  if (wtc_2 & COUNT_LRG_COMM)
    avro_schema_record_field_append(schema, "lcomms", avro_schema_string());

  if (wtc & COUNT_AS_PATH)
    avro_schema_record_field_append(schema, "as_path", avro_schema_string());

  if (wtc & COUNT_LOCAL_PREF)
    avro_schema_record_field_append(schema, "local_pref", avro_schema_long());

  if (wtc & COUNT_MED)
    avro_schema_record_field_append(schema, "med", avro_schema_long());

  if (wtc & COUNT_PEER_SRC_AS)
    avro_schema_record_field_append(schema, "peer_as_src", avro_schema_long());

  if (wtc & COUNT_PEER_DST_AS)
    avro_schema_record_field_append(schema, "peer_as_dst", avro_schema_long());

  if (wtc & COUNT_PEER_SRC_IP)
    avro_schema_record_field_append(schema, "peer_ip_src", avro_schema_string());

  if (wtc & COUNT_PEER_DST_IP)
    avro_schema_record_field_append(schema, "peer_ip_dst", avro_schema_string());

  if (wtc & COUNT_SRC_STD_COMM)
    avro_schema_record_field_append(schema, "src_comms", avro_schema_string());

  if (wtc & COUNT_SRC_EXT_COMM)
    avro_schema_record_field_append(schema, "src_ecomms", avro_schema_string());

  if (wtc_2 & COUNT_SRC_LRG_COMM)
    avro_schema_record_field_append(schema, "src_lcomms", avro_schema_string());

  if (wtc & COUNT_SRC_AS_PATH)
    avro_schema_record_field_append(schema, "src_as_path", avro_schema_string());

  if (wtc & COUNT_SRC_LOCAL_PREF)
    avro_schema_record_field_append(schema, "src_local_pref", avro_schema_long());

  if (wtc & COUNT_SRC_MED)
    avro_schema_record_field_append(schema, "src_med", avro_schema_long());

  if (wtc & COUNT_IN_IFACE)
    avro_schema_record_field_append(schema, "iface_in", avro_schema_long());

  if (wtc & COUNT_OUT_IFACE)
    avro_schema_record_field_append(schema, "iface_out", avro_schema_long());

  if (wtc & COUNT_MPLS_VPN_RD)
    avro_schema_record_field_append(schema, "mpls_vpn_rd", avro_schema_string());

  if (wtc & (COUNT_SRC_HOST|COUNT_SUM_HOST))
    avro_schema_record_field_append(schema, "ip_src", avro_schema_string());

  if (wtc & (COUNT_SRC_NET|COUNT_SUM_NET))
    avro_schema_record_field_append(schema, "net_src", avro_schema_string());

  if (wtc & COUNT_DST_HOST)
    avro_schema_record_field_append(schema, "ip_dst", avro_schema_string());

  if (wtc & COUNT_DST_NET)
    avro_schema_record_field_append(schema, "net_dst", avro_schema_string());

  if (wtc & COUNT_SRC_NMASK)
    avro_schema_record_field_append(schema, "mask_src", avro_schema_long());

  if (wtc & COUNT_DST_NMASK)
    avro_schema_record_field_append(schema, "mask_dst", avro_schema_long());

  if (wtc & (COUNT_SRC_PORT|COUNT_SUM_PORT))
    avro_schema_record_field_append(schema, "port_src", avro_schema_long());

  if (wtc & COUNT_DST_PORT)
    avro_schema_record_field_append(schema, "port_dst", avro_schema_long());

#if defined (WITH_GEOIP) || defined (WITH_GEOIPV2)
  if (wtc_2 & COUNT_SRC_HOST_COUNTRY)
    avro_schema_record_field_append(schema, "country_ip_src", avro_schema_string());

  if (wtc_2 & COUNT_DST_HOST_COUNTRY)
    avro_schema_record_field_append(schema, "country_ip_dst", avro_schema_string());
#endif

#if defined (WITH_GEOIPV2)
  if (wtc_2 & COUNT_SRC_HOST_POCODE)
    avro_schema_record_field_append(schema, "pocode_ip_src", avro_schema_string());

  if (wtc_2 & COUNT_DST_HOST_POCODE)
    avro_schema_record_field_append(schema, "pocode_ip_dst", avro_schema_string());
#endif

  if (wtc & COUNT_TCPFLAGS)
    avro_schema_record_field_append(schema, "tcp_flags", avro_schema_string());

  if (wtc & COUNT_IP_PROTO)
    avro_schema_record_field_append(schema, "ip_proto", avro_schema_string());

  if (wtc & COUNT_IP_TOS)
    avro_schema_record_field_append(schema, "tos", avro_schema_long());

  if (wtc_2 & COUNT_SAMPLING_RATE)
    avro_schema_record_field_append(schema, "sampling_rate", avro_schema_long());

  if (wtc_2 & COUNT_PKT_LEN_DISTRIB)
    avro_schema_record_field_append(schema, "pkt_len_distrib", avro_schema_string());

  if (wtc_2 & COUNT_POST_NAT_SRC_HOST)
    avro_schema_record_field_append(schema, "post_nat_ip_src", avro_schema_string());

  if (wtc_2 & COUNT_POST_NAT_DST_HOST)
    avro_schema_record_field_append(schema, "post_nat_ip_dst", avro_schema_string());

  if (wtc_2 & COUNT_POST_NAT_SRC_PORT)
    avro_schema_record_field_append(schema, "post_nat_port_src", avro_schema_long());

  if (wtc_2 & COUNT_POST_NAT_DST_PORT)
    avro_schema_record_field_append(schema, "post_nat_port_dst", avro_schema_long());

  if (wtc_2 & COUNT_NAT_EVENT)
    avro_schema_record_field_append(schema, "nat_event", avro_schema_long());

  if (wtc_2 & COUNT_MPLS_LABEL_TOP)
    avro_schema_record_field_append(schema, "mpls_label_top", avro_schema_long());

  if (wtc_2 & COUNT_MPLS_LABEL_BOTTOM)
    avro_schema_record_field_append(schema, "mpls_label_bottom", avro_schema_long());

  if (wtc_2 & COUNT_MPLS_STACK_DEPTH)
    avro_schema_record_field_append(schema, "mpls_stack_depth", avro_schema_long());

  if (wtc_2 & COUNT_TUNNEL_SRC_HOST)
    avro_schema_record_field_append(schema, "tunnel_ip_src", avro_schema_string());

  if (wtc_2 & COUNT_TUNNEL_DST_HOST)
    avro_schema_record_field_append(schema, "tunnel_ip_dst", avro_schema_string());

  if (wtc_2 & COUNT_TUNNEL_IP_PROTO)
    avro_schema_record_field_append(schema, "tunnel_ip_proto", avro_schema_string());

  if (wtc_2 & COUNT_TUNNEL_IP_TOS)
    avro_schema_record_field_append(schema, "tunnel_tos", avro_schema_long());

  if (wtc_2 & COUNT_TIMESTAMP_START)
    avro_schema_record_field_append(schema, "timestamp_start", avro_schema_string());

  if (wtc_2 & COUNT_TIMESTAMP_END)
    avro_schema_record_field_append(schema, "timestamp_end", avro_schema_string());

  if (wtc_2 & COUNT_TIMESTAMP_ARRIVAL)
    avro_schema_record_field_append(schema, "timestamp_arrival", avro_schema_string());

  if (config.nfacctd_stitching) {
    avro_schema_record_field_append(schema, "timestamp_min", optstr_s);
    avro_schema_record_field_append(schema, "timestamp_max", optstr_s);
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_SEQNO)
    avro_schema_record_field_append(schema, "export_proto_seqno", avro_schema_long());

  if (wtc_2 & COUNT_EXPORT_PROTO_VERSION)
    avro_schema_record_field_append(schema, "export_proto_version", avro_schema_long());

  if (config.cpptrs.num > 0) {
    avro_schema_record_field_append(
        schema, "custom_primitives", avro_schema_map(avro_schema_string()));
  }

  if (config.sql_history) {
    avro_schema_record_field_append(schema, "stamp_inserted", optstr_s);
    avro_schema_record_field_append(schema, "stamp_updated", optstr_s);
  }

  avro_schema_record_field_append(schema, "packets", optlong_s);
  avro_schema_record_field_append(schema, "flows", optlong_s);
  avro_schema_record_field_append(schema, "bytes", optlong_s);

  avro_schema_decref(optlong_s);
  avro_schema_decref(optstr_s);

  return schema;
}

void avro_schema_add_writer_id(avro_schema_t schema)
{
  avro_schema_record_field_append(schema, "writer_id", avro_schema_string());
}

avro_value_t compose_avro(u_int64_t wtc, u_int64_t wtc_2, u_int8_t flow_type, struct pkt_primitives *pbase,
  struct pkt_bgp_primitives *pbgp, struct pkt_nat_primitives *pnat, struct pkt_mpls_primitives *pmpls,
  struct pkt_tunnel_primitives *ptun, char *pcust, struct pkt_vlen_hdr_primitives *pvlen,
  pm_counter_t bytes_counter, pm_counter_t packet_counter, pm_counter_t flow_counter, u_int32_t tcp_flags,
  struct timeval *basetime, struct pkt_stitching *stitch, avro_value_iface_t *iface)
{
  char src_mac[18], dst_mac[18], src_host[INET6_ADDRSTRLEN], dst_host[INET6_ADDRSTRLEN], ip_address[INET6_ADDRSTRLEN];
  char rd_str[SRVBUFLEN], misc_str[SRVBUFLEN], *as_path, *bgp_comm, empty_string[] = "", *str_ptr;
  char tstamp_str[SRVBUFLEN];

  avro_value_t value;
  avro_value_t field;
  avro_value_t branch;
  check_i(avro_generic_value_new(iface, &value));

  if (wtc & COUNT_TAG) {
    check_i(avro_value_get_by_name(&value, "tag", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->tag));
  }

  if (wtc & COUNT_TAG2) {
    check_i(avro_value_get_by_name(&value, "tag2", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->tag2));
  }

  if (wtc_2 & COUNT_LABEL) {
    vlen_prims_get(pvlen, COUNT_INT_LABEL, &str_ptr);
    if (!str_ptr) str_ptr = empty_string;

    check_i(avro_value_get_by_name(&value, "label", &field, NULL));
    check_i(avro_value_set_string(&field, str_ptr));
  }

  if (wtc & COUNT_CLASS) {
    check_i(avro_value_get_by_name(&value, "class", &field, NULL));
    check_i(avro_value_set_string(&field, ((pbase->class && class[(pbase->class)-1].id) ? class[(pbase->class)-1].protocol : "unknown" )));
  }

#if defined (WITH_NDPI)
  if (wtc_2 & COUNT_NDPI_CLASS) {
    char ndpi_class[SUPERSHORTBUFLEN];

    snprintf(ndpi_class, SUPERSHORTBUFLEN, "%s/%s",
	ndpi_get_proto_name(pm_ndpi_wfl->ndpi_struct, pbase->ndpi_class.master_protocol),
	ndpi_get_proto_name(pm_ndpi_wfl->ndpi_struct, pbase->ndpi_class.app_protocol));

    check_i(avro_value_get_by_name(&value, "class", &field, NULL));
    check_i(avro_value_set_string(&field, ndpi_class));
  }
#endif

#if defined (HAVE_L2)
  if (wtc & (COUNT_SRC_MAC|COUNT_SUM_MAC)) {
    etheraddr_string(pbase->eth_shost, src_mac);
    check_i(avro_value_get_by_name(&value, "mac_src", &field, NULL));
    check_i(avro_value_set_string(&field, src_mac));
  }

  if (wtc & COUNT_DST_MAC) {
    etheraddr_string(pbase->eth_dhost, dst_mac);
    check_i(avro_value_get_by_name(&value, "mac_dst", &field, NULL));
    check_i(avro_value_set_string(&field, dst_mac));
  }

  if (wtc & COUNT_VLAN) {
    check_i(avro_value_get_by_name(&value, "vlan", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->vlan_id));
  }

  if (wtc & COUNT_COS) {
    check_i(avro_value_get_by_name(&value, "cos", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->cos));
  }

  if (wtc & COUNT_ETHERTYPE) {
    sprintf(misc_str, "%x", pbase->etype);
    check_i(avro_value_get_by_name(&value, "etype", &field, NULL));
    check_i(avro_value_set_string(&field, misc_str));
  }
#endif

  if (wtc & (COUNT_SRC_AS|COUNT_SUM_AS)) {
    check_i(avro_value_get_by_name(&value, "as_src", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->src_as));
  }

  if (wtc & COUNT_DST_AS) {
    check_i(avro_value_get_by_name(&value, "as_dst", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->dst_as));
  }

  if (wtc & COUNT_STD_COMM) {
    vlen_prims_get(pvlen, COUNT_INT_STD_COMM, &str_ptr);
    if (str_ptr) {
      bgp_comm = str_ptr;
      while (bgp_comm) {
        bgp_comm = strchr(str_ptr, ' ');
        if (bgp_comm) *bgp_comm = '_';
      }
    }
    else str_ptr = empty_string;

    check_i(avro_value_get_by_name(&value, "comms", &field, NULL));
    check_i(avro_value_set_string(&field, str_ptr));
  }

  if (wtc & COUNT_EXT_COMM) {
    vlen_prims_get(pvlen, COUNT_INT_EXT_COMM, &str_ptr);
    if (str_ptr) {
      bgp_comm = str_ptr;
      while (bgp_comm) {
        bgp_comm = strchr(str_ptr, ' ');
        if (bgp_comm) *bgp_comm = '_';
      }
    }
    else str_ptr = empty_string;

    check_i(avro_value_get_by_name(&value, "ecomms", &field, NULL));
    check_i(avro_value_set_string(&field, str_ptr));
  }

  if (wtc_2 & COUNT_LRG_COMM) {
    vlen_prims_get(pvlen, COUNT_INT_LRG_COMM, &str_ptr);
    if (str_ptr) {
      bgp_comm = str_ptr;
      while (bgp_comm) {
        bgp_comm = strchr(str_ptr, ' ');
        if (bgp_comm) *bgp_comm = '_';
      }
    }
    else str_ptr = empty_string;

    check_i(avro_value_get_by_name(&value, "lcomms", &field, NULL));
    check_i(avro_value_set_string(&field, str_ptr));
  }

  if (wtc & COUNT_AS_PATH) {
    vlen_prims_get(pvlen, COUNT_INT_AS_PATH, &str_ptr);
    if (str_ptr) {
      as_path = str_ptr;
      while (as_path) {
	as_path = strchr(str_ptr, ' ');
	if (as_path) *as_path = '_';
      }
    }
    else str_ptr = empty_string;

    check_i(avro_value_get_by_name(&value, "as_path", &field, NULL));
    check_i(avro_value_set_string(&field, str_ptr));
  }

  if (wtc & COUNT_LOCAL_PREF) {
    check_i(avro_value_get_by_name(&value, "local_pref", &field, NULL));
    check_i(avro_value_set_long(&field, pbgp->local_pref));
  }

  if (wtc & COUNT_MED) {
    check_i(avro_value_get_by_name(&value, "med", &field, NULL));
    check_i(avro_value_set_long(&field, pbgp->med));
  }

  if (wtc & COUNT_PEER_SRC_AS) {
    check_i(avro_value_get_by_name(&value, "peer_as_src", &field, NULL));
    check_i(avro_value_set_long(&field, pbgp->peer_src_as));
  }

  if (wtc & COUNT_PEER_DST_AS) {
    check_i(avro_value_get_by_name(&value, "peer_as_dst", &field, NULL));
    check_i(avro_value_set_long(&field, pbgp->peer_dst_as));
  }

  if (wtc & COUNT_PEER_SRC_IP) {
    check_i(avro_value_get_by_name(&value, "peer_ip_src", &field, NULL));
    addr_to_str(ip_address, &pbgp->peer_src_ip);
    check_i(avro_value_set_string(&field, ip_address));
  }

  if (wtc & COUNT_PEER_DST_IP) {
    check_i(avro_value_get_by_name(&value, "peer_ip_dst", &field, NULL));
    addr_to_str(ip_address, &pbgp->peer_dst_ip);
    check_i(avro_value_set_string(&field, ip_address));
  }

  if (wtc & COUNT_STD_COMM) {
    vlen_prims_get(pvlen, COUNT_INT_SRC_STD_COMM, &str_ptr);
    if (str_ptr) {
      bgp_comm = str_ptr;
      while (bgp_comm) {
        bgp_comm = strchr(str_ptr, ' ');
        if (bgp_comm) *bgp_comm = '_';
      }
    }
    else str_ptr = empty_string;

    check_i(avro_value_get_by_name(&value, "src_comms", &field, NULL));
    check_i(avro_value_set_string(&field, str_ptr));
  }

  if (wtc & COUNT_SRC_EXT_COMM) {
    vlen_prims_get(pvlen, COUNT_INT_SRC_EXT_COMM, &str_ptr);
    if (str_ptr) {
      bgp_comm = str_ptr;
      while (bgp_comm) {
        bgp_comm = strchr(str_ptr, ' ');
        if (bgp_comm) *bgp_comm = '_';
      }
    }
    else str_ptr = empty_string;

    check_i(avro_value_get_by_name(&value, "src_ecomms", &field, NULL));
    check_i(avro_value_set_string(&field, str_ptr));
  }

  if (wtc_2 & COUNT_SRC_LRG_COMM) {
    vlen_prims_get(pvlen, COUNT_INT_SRC_LRG_COMM, &str_ptr);
    if (str_ptr) {
      bgp_comm = str_ptr;
      while (bgp_comm) {
        bgp_comm = strchr(str_ptr, ' ');
        if (bgp_comm) *bgp_comm = '_';
      }
    }
    else str_ptr = empty_string;

    check_i(avro_value_get_by_name(&value, "src_lcomms", &field, NULL));
    check_i(avro_value_set_string(&field, str_ptr));
  }

  if (wtc & COUNT_SRC_AS_PATH) {
    vlen_prims_get(pvlen, COUNT_INT_SRC_AS_PATH, &str_ptr);
    if (str_ptr) {
      as_path = str_ptr;
      while (as_path) {
        as_path = strchr(str_ptr, ' ');
        if (as_path) *as_path = '_';
      }
    }
    else str_ptr = empty_string;

    check_i(avro_value_get_by_name(&value, "src_as_path", &field, NULL));
    check_i(avro_value_set_string(&field, str_ptr));
  }

  if (wtc & COUNT_SRC_LOCAL_PREF) {
    check_i(avro_value_get_by_name(&value, "src_local_pref", &field, NULL));
    check_i(avro_value_set_long(&field, pbgp->src_local_pref));
  }

  if (wtc & COUNT_SRC_MED) {
    check_i(avro_value_get_by_name(&value, "src_med", &field, NULL));
    check_i(avro_value_set_long(&field, pbgp->src_med));
  }

  if (wtc & COUNT_IN_IFACE) {
    check_i(avro_value_get_by_name(&value, "iface_in", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->ifindex_in));
  }

  if (wtc & COUNT_OUT_IFACE) {
    check_i(avro_value_get_by_name(&value, "iface_out", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->ifindex_out));
  }

  if (wtc & COUNT_MPLS_VPN_RD) {
    bgp_rd2str(rd_str, &pbgp->mpls_vpn_rd);
    check_i(avro_value_get_by_name(&value, "mpls_vpn_rd", &field, NULL));
    check_i(avro_value_set_string(&field, rd_str));
  }

  if (wtc & (COUNT_SRC_HOST|COUNT_SUM_HOST)) {
    addr_to_str(src_host, &pbase->src_ip);
    check_i(avro_value_get_by_name(&value, "ip_src", &field, NULL));
    check_i(avro_value_set_string(&field, src_host));
  }

  if (wtc & (COUNT_SRC_NET|COUNT_SUM_NET)) {
    addr_to_str(src_host, &pbase->src_net);
    check_i(avro_value_get_by_name(&value, "net_src", &field, NULL));
    check_i(avro_value_set_string(&field, src_host));
  }

  if (wtc & COUNT_DST_HOST) {
    addr_to_str(dst_host, &pbase->dst_ip);
    check_i(avro_value_get_by_name(&value, "ip_dst", &field, NULL));
    check_i(avro_value_set_string(&field, dst_host));
  }

  if (wtc & COUNT_DST_NET) {
    addr_to_str(dst_host, &pbase->dst_net);
    check_i(avro_value_get_by_name(&value, "net_dst", &field, NULL));
    check_i(avro_value_set_string(&field, dst_host));
  }

  if (wtc & COUNT_SRC_NMASK) {
    check_i(avro_value_get_by_name(&value, "mask_src", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->src_nmask));
  }

  if (wtc & COUNT_DST_NMASK) {
    check_i(avro_value_get_by_name(&value, "mask_dst", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->dst_nmask));
  }

  if (wtc & (COUNT_SRC_PORT|COUNT_SUM_PORT)) {
    check_i(avro_value_get_by_name(&value, "port_src", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->src_port));
  }

  if (wtc & COUNT_DST_PORT) {
    check_i(avro_value_get_by_name(&value, "port_dst", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->dst_port));
  }

#if defined (WITH_GEOIP)
  if (wtc_2 & COUNT_SRC_HOST_COUNTRY) {
    check_i(avro_value_get_by_name(&value, "country_ip_src", &field, NULL));
    if (pbase->src_ip_country.id > 0)
      check_i(avro_value_set_string(&field, GeoIP_code_by_id(pbase->src_ip_country.id)));
    else
      check_i(avro_value_set_string(&field, empty_string));
  }

  if (wtc_2 & COUNT_DST_HOST_COUNTRY) {
    check_i(avro_value_get_by_name(&value, "country_ip_dst", &field, NULL));
    if (pbase->dst_ip_country.id > 0)
      check_i(avro_value_set_string(&field, GeoIP_code_by_id(pbase->dst_ip_country.id)));
    else
      check_i(avro_value_set_string(&field, empty_string));
  }
#endif
#if defined (WITH_GEOIPV2)
  if (wtc_2 & COUNT_SRC_HOST_COUNTRY) {
    check_i(avro_value_get_by_name(&value, "country_ip_src", &field, NULL));
    if (strlen(pbase->src_ip_country.str))
      check_i(avro_value_set_string(&field, pbase->src_ip_country.str));
    else
      check_i(avro_value_set_string(&field, empty_string));
  }

  if (wtc_2 & COUNT_DST_HOST_COUNTRY) {
    check_i(avro_value_get_by_name(&value, "country_ip_dst", &field, NULL));
    if (strlen(pbase->dst_ip_country.str))
      check_i(avro_value_set_string(&field, pbase->dst_ip_country.str));
    else
      check_i(avro_value_set_string(&field, empty_string));
  }

  if (wtc_2 & COUNT_SRC_HOST_POCODE) {
    check_i(avro_value_get_by_name(&value, "pocode_ip_src", &field, NULL));
    if (strlen(pbase->src_ip_pocode.str))
      check_i(avro_value_set_string(&field, pbase->src_ip_pocode.str));
    else
      check_i(avro_value_set_string(&field, empty_string));
  }

  if (wtc_2 & COUNT_DST_HOST_POCODE) {
    check_i(avro_value_get_by_name(&value, "pocode_ip_dst", &field, NULL));
    if (strlen(pbase->dst_ip_pocode.str))
      check_i(avro_value_set_string(&field, pbase->dst_ip_pocode.str));
    else
      check_i(avro_value_set_string(&field, empty_string));
  }
#endif

  if (wtc & COUNT_TCPFLAGS) {
    sprintf(misc_str, "%u", tcp_flags);
    check_i(avro_value_get_by_name(&value, "tcp_flags", &field, NULL));
    check_i(avro_value_set_string(&field, misc_str));
  }

  if (wtc & COUNT_IP_PROTO) {
    check_i(avro_value_get_by_name(&value, "ip_proto", &field, NULL));
    if (!config.num_protos && (pbase->proto < protocols_number))
      check_i(avro_value_set_string(&field, _protocols[pbase->proto].name));
    else {
      char proto_number[6];
      snprintf(proto_number, sizeof(proto_number), "%d", pbase->proto);
      check_i(avro_value_set_string(&field, proto_number));
    }
  }

  if (wtc & COUNT_IP_TOS) {
    check_i(avro_value_get_by_name(&value, "tos", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->tos));
  }

  if (wtc_2 & COUNT_SAMPLING_RATE) {
    check_i(avro_value_get_by_name(&value, "sampling_rate", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->sampling_rate));
  }

  if (wtc_2 & COUNT_PKT_LEN_DISTRIB) {
    check_i(avro_value_get_by_name(&value, "pkt_len_distrib", &field, NULL));
    check_i(avro_value_set_string(&field, config.pkt_len_distrib_bins[pbase->pkt_len_distrib]));
  }

  if (wtc_2 & COUNT_POST_NAT_SRC_HOST) {
    addr_to_str(src_host, &pnat->post_nat_src_ip);
    check_i(avro_value_get_by_name(&value, "post_nat_ip_src", &field, NULL));
    check_i(avro_value_set_string(&field, src_host));
  }

  if (wtc_2 & COUNT_POST_NAT_DST_HOST) {
    addr_to_str(dst_host, &pnat->post_nat_dst_ip);
    check_i(avro_value_get_by_name(&value, "post_nat_ip_dst", &field, NULL));
    check_i(avro_value_set_string(&field, dst_host));
  }

  if (wtc_2 & COUNT_POST_NAT_SRC_PORT) {
    check_i(avro_value_get_by_name(&value, "post_nat_port_src", &field, NULL));
    check_i(avro_value_set_long(&field, pnat->post_nat_src_port));
  }

  if (wtc_2 & COUNT_POST_NAT_DST_PORT) {
    check_i(avro_value_get_by_name(&value, "post_nat_port_dst", &field, NULL));
    check_i(avro_value_set_long(&field, pnat->post_nat_dst_port));
  }

  if (wtc_2 & COUNT_NAT_EVENT) {
    check_i(avro_value_get_by_name(&value, "nat_event", &field, NULL));
    check_i(avro_value_set_long(&field, pnat->nat_event));
  }

  if (wtc_2 & COUNT_MPLS_LABEL_TOP) {
    check_i(avro_value_get_by_name(&value, "mpls_label_top", &field, NULL));
    check_i(avro_value_set_long(&field, pmpls->mpls_label_top));
  }

  if (wtc_2 & COUNT_MPLS_LABEL_BOTTOM) {
    check_i(avro_value_get_by_name(&value, "mpls_label_bottom", &field, NULL));
    check_i(avro_value_set_long(&field, pmpls->mpls_label_bottom));
  }

  if (wtc_2 & COUNT_MPLS_STACK_DEPTH) {
    check_i(avro_value_get_by_name(&value, "mpls_stack_depth", &field, NULL));
    check_i(avro_value_set_long(&field, pmpls->mpls_stack_depth));
  }

  if (wtc_2 & COUNT_TUNNEL_SRC_HOST) {
    addr_to_str(src_host, &ptun->tunnel_src_ip);
    check_i(avro_value_get_by_name(&value, "tunnel_ip_src", &field, NULL));
    check_i(avro_value_set_string(&field, src_host));
  }

  if (wtc_2 & COUNT_TUNNEL_DST_HOST) {
    addr_to_str(dst_host, &ptun->tunnel_dst_ip);
    check_i(avro_value_get_by_name(&value, "tunnel_ip_dst", &field, NULL));
    check_i(avro_value_set_string(&field, dst_host));
  }

  if (wtc_2 & COUNT_TUNNEL_IP_PROTO) {
    check_i(avro_value_get_by_name(&value, "tunnel_ip_proto", &field, NULL));
    if (!config.num_protos && (ptun->tunnel_proto < protocols_number))
      check_i(avro_value_set_string(&field, _protocols[ptun->tunnel_proto].name));
    else {
      char proto_number[6];
      snprintf(proto_number, sizeof(proto_number), "%d", ptun->tunnel_proto);
      check_i(avro_value_set_string(&field, proto_number));
    }
  }

  if (wtc_2 & COUNT_TUNNEL_IP_TOS) {
    check_i(avro_value_get_by_name(&value, "tunnel_tos", &field, NULL));
    check_i(avro_value_set_long(&field, ptun->tunnel_tos));
  }

  if (wtc_2 & COUNT_TIMESTAMP_START) {
    compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_start, TRUE, config.timestamps_since_epoch);
    check_i(avro_value_get_by_name(&value, "timestamp_start", &field, NULL));
    check_i(avro_value_set_string(&field, tstamp_str));
  }

  if (wtc_2 & COUNT_TIMESTAMP_END) {
    compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_end, TRUE, config.timestamps_since_epoch);
    check_i(avro_value_get_by_name(&value, "timestamp_end", &field, NULL));
    check_i(avro_value_set_string(&field, tstamp_str));
  }

  if (wtc_2 & COUNT_TIMESTAMP_ARRIVAL) {
    compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_arrival, TRUE, config.timestamps_since_epoch);
    check_i(avro_value_get_by_name(&value, "timestamp_arrival", &field, NULL));
    check_i(avro_value_set_string(&field, tstamp_str));
  }

  if (config.nfacctd_stitching) {
    if (stitch) {
      compose_timestamp(tstamp_str, SRVBUFLEN, &stitch->timestamp_min, TRUE, config.timestamps_since_epoch);
      check_i(avro_value_get_by_name(&value, "timestamp_min", &field, NULL));
      check_i(avro_value_set_branch(&field, 1, &branch));
      check_i(avro_value_set_string(&branch, tstamp_str));

      compose_timestamp(tstamp_str, SRVBUFLEN, &stitch->timestamp_max, TRUE, config.timestamps_since_epoch);
      check_i(avro_value_get_by_name(&value, "timestamp_max", &field, NULL));
      check_i(avro_value_set_branch(&field, 1, &branch));
      check_i(avro_value_set_string(&branch, tstamp_str));
    }
    else {
      check_i(avro_value_get_by_name(&value, "timestamp_min", &field, NULL));
      check_i(avro_value_set_branch(&field, 0, &branch));
      check_i(avro_value_get_by_name(&value, "timestamp_max", &field, NULL));
      check_i(avro_value_set_branch(&field, 0, &branch));
    }
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_SEQNO) {
    check_i(avro_value_get_by_name(&value, "export_proto_seqno", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->export_proto_seqno));
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_VERSION) {
    check_i(avro_value_get_by_name(&value, "export_proto_version", &field, NULL));
    check_i(avro_value_set_long(&field, pbase->export_proto_version));
  }

  /* all custom primitives printed here */
  {
    if (config.cpptrs.num > 0)
      check_i(avro_value_get_by_name(&value, "custom_primitives", &field, NULL));

    int cp_idx;
    for (cp_idx = 0; cp_idx < config.cpptrs.num; cp_idx++) {
      avro_value_t map_value;
      avro_value_add(&field, config.cpptrs.primitive[cp_idx].name, &map_value, NULL, NULL);
      if (config.cpptrs.primitive[cp_idx].ptr->len != PM_VARIABLE_LENGTH) {
        char cp_str[SRVBUFLEN];
        custom_primitive_value_print(cp_str, SRVBUFLEN, pcust, &config.cpptrs.primitive[cp_idx], FALSE);
        avro_value_set_string(&map_value, cp_str);
      }
      else {
        char *label_ptr = NULL;
        vlen_prims_get(pvlen, config.cpptrs.primitive[cp_idx].ptr->type, &label_ptr);
        if (!label_ptr) label_ptr = empty_string;
        avro_value_set_string(&map_value, label_ptr);
      }
    }
  }

  if (config.sql_history) {
    if (basetime) {
      struct timeval tv;

      tv.tv_sec = basetime->tv_sec;
      tv.tv_usec = 0;
      compose_timestamp(tstamp_str, SRVBUFLEN, &tv, FALSE, config.timestamps_since_epoch);
      check_i(avro_value_get_by_name(&value, "stamp_inserted", &field, NULL));
      check_i(avro_value_set_branch(&field, 1, &branch));
      check_i(avro_value_set_string(&branch, tstamp_str));

      tv.tv_sec = time(NULL);
      tv.tv_usec = 0;
      compose_timestamp(tstamp_str, SRVBUFLEN, &tv, FALSE, config.timestamps_since_epoch);
      check_i(avro_value_get_by_name(&value, "stamp_updated", &field, NULL));
      check_i(avro_value_set_branch(&field, 1, &branch));
      check_i(avro_value_set_string(&branch, tstamp_str));
    }
    else {
      check_i(avro_value_get_by_name(&value, "stamp_inserted", &field, NULL));
      check_i(avro_value_set_branch(&field, 0, &branch));
      check_i(avro_value_get_by_name(&value, "stamp_updated", &field, NULL));
      check_i(avro_value_set_branch(&field, 0, &branch));
    }
  }

  if (flow_type != NF9_FTYPE_EVENT && flow_type != NF9_FTYPE_OPTION) {
    check_i(avro_value_get_by_name(&value, "packets", &field, NULL));
    check_i(avro_value_set_branch(&field, 1, &branch));
    check_i(avro_value_set_long(&branch, packet_counter));

    check_i(avro_value_get_by_name(&value, "flows", &field, NULL));
    if (wtc & COUNT_FLOWS) {
      check_i(avro_value_set_branch(&field, 1, &branch));
      check_i(avro_value_set_long(&branch, flow_counter));
    }
    else {
      check_i(avro_value_set_branch(&field, 0, &branch));
    }
    check_i(avro_value_get_by_name(&value, "bytes", &field, NULL));
    check_i(avro_value_set_branch(&field, 1, &branch));
    check_i(avro_value_set_long(&branch, bytes_counter));
  }
  else {
    check_i(avro_value_get_by_name(&value, "packets", &field, NULL));
    check_i(avro_value_set_branch(&field, 0, &branch));
    check_i(avro_value_get_by_name(&value, "flows", &field, NULL));
    check_i(avro_value_set_branch(&field, 0, &branch));
    check_i(avro_value_get_by_name(&value, "bytes", &field, NULL));
    check_i(avro_value_set_branch(&field, 0, &branch));
  }

  return value;
}

void add_writer_name_and_pid_avro(avro_value_t value, char *name, pid_t writer_pid)
{
  char wid[SHORTSHORTBUFLEN];
  avro_value_t field;

  snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", name, writer_pid);
  check_i(avro_value_get_by_name(&value, "writer_id", &field, NULL));
  check_i(avro_value_set_string(&field, wid));
}
#endif
