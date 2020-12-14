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
#include "plugin_cmn_avro.h"
#include "ip_flow.h"
#include "classifier.h"
#include "bgp/bgp.h"
#include "rpki/rpki.h"
#if defined (WITH_NDPI)
#include "ndpi/ndpi.h"
#endif

#ifdef WITH_AVRO
/* global variables */
avro_schema_t p_avro_acct_schema, p_avro_acct_init_schema, p_avro_acct_close_schema;

/* functions */
avro_schema_t p_avro_schema_build_acct_data(u_int64_t wtc, u_int64_t wtc_2)
{
  avro_schema_t schema = avro_schema_record("acct_data", NULL);
  avro_schema_t optlong_s = avro_schema_union();
  avro_schema_t optstr_s = avro_schema_union();

  Log(LOG_INFO, "INFO ( %s/%s ): p_avro_schema_build_acct_data(): building acct schema.\n", config.name, config.type);

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

  if (wtc_2 & COUNT_DST_ROA)
    avro_schema_record_field_append(schema, "roa_dst", avro_schema_string());

  if (wtc & COUNT_PEER_SRC_AS)
    avro_schema_record_field_append(schema, "peer_as_src", avro_schema_long());

  if (wtc & COUNT_PEER_DST_AS)
    avro_schema_record_field_append(schema, "peer_as_dst", avro_schema_long());

  if (wtc & COUNT_PEER_SRC_IP)
    avro_schema_record_field_append(schema, "peer_ip_src", avro_schema_string());

  if (wtc & COUNT_PEER_DST_IP)
    avro_schema_record_field_append(schema, "peer_ip_dst", avro_schema_string());

  if (wtc & COUNT_SRC_STD_COMM)
    avro_schema_record_field_append(schema, "comms_src", avro_schema_string());

  if (wtc & COUNT_SRC_EXT_COMM)
    avro_schema_record_field_append(schema, "ecomms_src", avro_schema_string());

  if (wtc_2 & COUNT_SRC_LRG_COMM)
    avro_schema_record_field_append(schema, "lcomms_src", avro_schema_string());

  if (wtc & COUNT_SRC_AS_PATH)
    avro_schema_record_field_append(schema, "as_path_src", avro_schema_string());

  if (wtc & COUNT_SRC_LOCAL_PREF)
    avro_schema_record_field_append(schema, "local_pref_src", avro_schema_long());

  if (wtc & COUNT_SRC_MED)
    avro_schema_record_field_append(schema, "med_src", avro_schema_long());

  if (wtc_2 & COUNT_SRC_ROA)
    avro_schema_record_field_append(schema, "roa_src", avro_schema_string());

  if (wtc & COUNT_IN_IFACE)
    avro_schema_record_field_append(schema, "iface_in", avro_schema_long());

  if (wtc & COUNT_OUT_IFACE)
    avro_schema_record_field_append(schema, "iface_out", avro_schema_long());

  if (wtc & COUNT_MPLS_VPN_RD)
    avro_schema_record_field_append(schema, "mpls_vpn_rd", avro_schema_string());

  if (wtc_2 & COUNT_MPLS_PW_ID)
    avro_schema_record_field_append(schema, "mpls_pw_id", avro_schema_long());

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

  if (wtc_2 & COUNT_SRC_HOST_COORDS) {
    avro_schema_record_field_append(schema, "lat_ip_src", avro_schema_double());
    avro_schema_record_field_append(schema, "lon_ip_src", avro_schema_double());
  }

  if (wtc_2 & COUNT_DST_HOST_COORDS) {
    avro_schema_record_field_append(schema, "lat_ip_dst", avro_schema_double());
    avro_schema_record_field_append(schema, "lon_ip_dst", avro_schema_double());
  }
    
#endif

  if (wtc & COUNT_TCPFLAGS)
    avro_schema_record_field_append(schema, "tcp_flags", avro_schema_string());

  if (wtc & COUNT_IP_PROTO)
    avro_schema_record_field_append(schema, "ip_proto", avro_schema_string());

  if (wtc & COUNT_IP_TOS)
    avro_schema_record_field_append(schema, "tos", avro_schema_long());

  if (wtc_2 & COUNT_SAMPLING_RATE)
    avro_schema_record_field_append(schema, "sampling_rate", avro_schema_long());

  if (wtc_2 & COUNT_SAMPLING_DIRECTION)
    avro_schema_record_field_append(schema, "sampling_direction", avro_schema_long());

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

  if (wtc_2 & COUNT_TUNNEL_SRC_MAC)
    avro_schema_record_field_append(schema, "tunnel_mac_src", avro_schema_string());

  if (wtc_2 & COUNT_TUNNEL_DST_MAC)
    avro_schema_record_field_append(schema, "tunnel_mac_dst", avro_schema_string());

  if (wtc_2 & COUNT_TUNNEL_SRC_HOST)
    avro_schema_record_field_append(schema, "tunnel_ip_src", avro_schema_string());

  if (wtc_2 & COUNT_TUNNEL_DST_HOST)
    avro_schema_record_field_append(schema, "tunnel_ip_dst", avro_schema_string());

  if (wtc_2 & COUNT_TUNNEL_IP_PROTO)
    avro_schema_record_field_append(schema, "tunnel_ip_proto", avro_schema_string());

  if (wtc_2 & COUNT_TUNNEL_IP_TOS)
    avro_schema_record_field_append(schema, "tunnel_tos", avro_schema_long());

  if (wtc_2 & COUNT_TUNNEL_SRC_PORT)
    avro_schema_record_field_append(schema, "tunnel_port_src", avro_schema_long());

  if (wtc_2 & COUNT_TUNNEL_DST_PORT)
    avro_schema_record_field_append(schema, "tunnel_port_dst", avro_schema_long());

  if (wtc_2 & COUNT_VXLAN)
    avro_schema_record_field_append(schema, "vxlan", avro_schema_long());

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

  if (wtc_2 & COUNT_EXPORT_PROTO_SYSID)
    avro_schema_record_field_append(schema, "export_proto_sysid", avro_schema_long());

  if (wtc_2 & COUNT_EXPORT_PROTO_TIME)
    avro_schema_record_field_append(schema, "timestamp_export", avro_schema_string());

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

avro_schema_t p_avro_schema_build_acct_init()
{
  avro_schema_t schema = avro_schema_record("acct_init", NULL);

  Log(LOG_INFO, "INFO ( %s/%s ): p_avro_schema_build_acct_init(): building acct_init schema.\n", config.name, config.type);

  avro_schema_record_field_append(schema, "event_type", avro_schema_string());
  avro_schema_record_field_append(schema, "writer_id", avro_schema_string());

  return schema;
}

avro_schema_t p_avro_schema_build_acct_close()
{
  avro_schema_t schema = avro_schema_record("acct_close", NULL);

  Log(LOG_INFO, "INFO ( %s/%s ): p_avro_schema_build_acct_close(): building acct_close schema.\n", config.name, config.type);

  avro_schema_record_field_append(schema, "event_type", avro_schema_string());
  avro_schema_record_field_append(schema, "writer_id", avro_schema_string());

  avro_schema_record_field_append(schema, "purged_entries", avro_schema_long());
  avro_schema_record_field_append(schema, "total_entries", avro_schema_long());
  avro_schema_record_field_append(schema, "duration", avro_schema_int());

  return schema;
}

void p_avro_schema_add_writer_id(avro_schema_t schema)
{
  avro_schema_record_field_append(schema, "writer_id", avro_schema_string());
}

avro_value_t compose_avro_acct_init(char *writer_name, pid_t writer_pid, avro_value_iface_t *iface)
{
  char event_type[] = "purge_init", wid[SHORTSHORTBUFLEN];
  avro_value_t value;
  avro_value_t field;

  pm_avro_check(avro_generic_value_new(iface, &value));

  pm_avro_check(avro_value_get_by_name(&value, "event_type", &field, NULL));
  pm_avro_check(avro_value_set_string(&field, event_type));

  snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", writer_name, writer_pid);
  pm_avro_check(avro_value_get_by_name(&value, "writer_id", &field, NULL));
  pm_avro_check(avro_value_set_string(&field, wid));

  return value;
}

avro_value_t compose_avro_acct_close(char *writer_name, pid_t writer_pid, int purged_entries, int total_entries, int duration, avro_value_iface_t *iface)
{
  char event_type[] = "purge_close", wid[SHORTSHORTBUFLEN];
  avro_value_t value;
  avro_value_t field;

  pm_avro_check(avro_generic_value_new(iface, &value));

  pm_avro_check(avro_value_get_by_name(&value, "event_type", &field, NULL));
  pm_avro_check(avro_value_set_string(&field, event_type));

  snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", writer_name, writer_pid);
  pm_avro_check(avro_value_get_by_name(&value, "writer_id", &field, NULL));
  pm_avro_check(avro_value_set_string(&field, wid));

  pm_avro_check(avro_value_get_by_name(&value, "purged_entries", &field, NULL));
  pm_avro_check(avro_value_set_long(&field, purged_entries));

  pm_avro_check(avro_value_get_by_name(&value, "total_entries", &field, NULL));
  pm_avro_check(avro_value_set_long(&field, total_entries));

  pm_avro_check(avro_value_get_by_name(&value, "duration", &field, NULL));
  pm_avro_check(avro_value_set_int(&field, total_entries));

  return value;
}

avro_value_t compose_avro_acct_data(u_int64_t wtc, u_int64_t wtc_2, u_int8_t flow_type, struct pkt_primitives *pbase,
  struct pkt_bgp_primitives *pbgp, struct pkt_nat_primitives *pnat, struct pkt_mpls_primitives *pmpls,
  struct pkt_tunnel_primitives *ptun, u_char *pcust, struct pkt_vlen_hdr_primitives *pvlen,
  pm_counter_t bytes_counter, pm_counter_t packet_counter, pm_counter_t flow_counter, u_int32_t tcp_flags,
  struct timeval *basetime, struct pkt_stitching *stitch, avro_value_iface_t *iface)
{
  char src_mac[18], dst_mac[18], src_host[INET6_ADDRSTRLEN], dst_host[INET6_ADDRSTRLEN], ip_address[INET6_ADDRSTRLEN];
  char rd_str[SRVBUFLEN], misc_str[SRVBUFLEN], *as_path, *bgp_comm, empty_string[] = "", *str_ptr;
  char tstamp_str[SRVBUFLEN];

  avro_value_t value;
  avro_value_t field;
  avro_value_t branch;
  pm_avro_check(avro_generic_value_new(iface, &value));

  if (wtc & COUNT_TAG) {
    pm_avro_check(avro_value_get_by_name(&value, "tag", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->tag));
  }

  if (wtc & COUNT_TAG2) {
    pm_avro_check(avro_value_get_by_name(&value, "tag2", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->tag2));
  }

  if (wtc_2 & COUNT_LABEL) {
    vlen_prims_get(pvlen, COUNT_INT_LABEL, &str_ptr);
    if (!str_ptr) str_ptr = empty_string;

    pm_avro_check(avro_value_get_by_name(&value, "label", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, str_ptr));
  }

  if (wtc & COUNT_CLASS) {
    pm_avro_check(avro_value_get_by_name(&value, "class", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, ((pbase->class && class[(pbase->class)-1].id) ? class[(pbase->class)-1].protocol : "unknown" )));
  }

#if defined (WITH_NDPI)
  if (wtc_2 & COUNT_NDPI_CLASS) {
    char ndpi_class[SUPERSHORTBUFLEN];

    snprintf(ndpi_class, SUPERSHORTBUFLEN, "%s/%s",
	ndpi_get_proto_name(pm_ndpi_wfl->ndpi_struct, pbase->ndpi_class.master_protocol),
	ndpi_get_proto_name(pm_ndpi_wfl->ndpi_struct, pbase->ndpi_class.app_protocol));

    pm_avro_check(avro_value_get_by_name(&value, "class", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, ndpi_class));
  }
#endif

#if defined (HAVE_L2)
  if (wtc & (COUNT_SRC_MAC|COUNT_SUM_MAC)) {
    etheraddr_string(pbase->eth_shost, src_mac);
    pm_avro_check(avro_value_get_by_name(&value, "mac_src", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, src_mac));
  }

  if (wtc & COUNT_DST_MAC) {
    etheraddr_string(pbase->eth_dhost, dst_mac);
    pm_avro_check(avro_value_get_by_name(&value, "mac_dst", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, dst_mac));
  }

  if (wtc & COUNT_VLAN) {
    pm_avro_check(avro_value_get_by_name(&value, "vlan", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->vlan_id));
  }

  if (wtc & COUNT_COS) {
    pm_avro_check(avro_value_get_by_name(&value, "cos", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->cos));
  }

  if (wtc & COUNT_ETHERTYPE) {
    sprintf(misc_str, "%x", pbase->etype);
    pm_avro_check(avro_value_get_by_name(&value, "etype", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, misc_str));
  }
#endif

  if (wtc & (COUNT_SRC_AS|COUNT_SUM_AS)) {
    pm_avro_check(avro_value_get_by_name(&value, "as_src", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->src_as));
  }

  if (wtc & COUNT_DST_AS) {
    pm_avro_check(avro_value_get_by_name(&value, "as_dst", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->dst_as));
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

    pm_avro_check(avro_value_get_by_name(&value, "comms", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, str_ptr));
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

    pm_avro_check(avro_value_get_by_name(&value, "ecomms", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, str_ptr));
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

    pm_avro_check(avro_value_get_by_name(&value, "lcomms", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, str_ptr));
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

    pm_avro_check(avro_value_get_by_name(&value, "as_path", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, str_ptr));
  }

  if (wtc & COUNT_LOCAL_PREF) {
    pm_avro_check(avro_value_get_by_name(&value, "local_pref", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbgp->local_pref));
  }

  if (wtc & COUNT_MED) {
    pm_avro_check(avro_value_get_by_name(&value, "med", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbgp->med));
  }

  if (wtc_2 & COUNT_DST_ROA) {
    pm_avro_check(avro_value_get_by_name(&value, "roa_dst", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, rpki_roa_print(pbgp->dst_roa)));
  }

  if (wtc & COUNT_PEER_SRC_AS) {
    pm_avro_check(avro_value_get_by_name(&value, "peer_as_src", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbgp->peer_src_as));
  }

  if (wtc & COUNT_PEER_DST_AS) {
    pm_avro_check(avro_value_get_by_name(&value, "peer_as_dst", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbgp->peer_dst_as));
  }

  if (wtc & COUNT_PEER_SRC_IP) {
    pm_avro_check(avro_value_get_by_name(&value, "peer_ip_src", &field, NULL));
    addr_to_str(ip_address, &pbgp->peer_src_ip);
    pm_avro_check(avro_value_set_string(&field, ip_address));
  }

  if (wtc & COUNT_PEER_DST_IP) {
    pm_avro_check(avro_value_get_by_name(&value, "peer_ip_dst", &field, NULL));
    addr_to_str2(ip_address, &pbgp->peer_dst_ip, ft2af(flow_type));
    pm_avro_check(avro_value_set_string(&field, ip_address));
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

    pm_avro_check(avro_value_get_by_name(&value, "comms_src", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, str_ptr));
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

    pm_avro_check(avro_value_get_by_name(&value, "ecomms_src", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, str_ptr));
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

    pm_avro_check(avro_value_get_by_name(&value, "lcomms_src", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, str_ptr));
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

    pm_avro_check(avro_value_get_by_name(&value, "as_path_src", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, str_ptr));
  }

  if (wtc & COUNT_SRC_LOCAL_PREF) {
    pm_avro_check(avro_value_get_by_name(&value, "local_pref_src", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbgp->src_local_pref));
  }

  if (wtc & COUNT_SRC_MED) {
    pm_avro_check(avro_value_get_by_name(&value, "med_src", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbgp->src_med));
  }

  if (wtc_2 & COUNT_SRC_ROA) {
    pm_avro_check(avro_value_get_by_name(&value, "roa_src", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, rpki_roa_print(pbgp->src_roa)));
  }

  if (wtc & COUNT_IN_IFACE) {
    pm_avro_check(avro_value_get_by_name(&value, "iface_in", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->ifindex_in));
  }

  if (wtc & COUNT_OUT_IFACE) {
    pm_avro_check(avro_value_get_by_name(&value, "iface_out", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->ifindex_out));
  }

  if (wtc & COUNT_MPLS_VPN_RD) {
    bgp_rd2str(rd_str, &pbgp->mpls_vpn_rd);
    pm_avro_check(avro_value_get_by_name(&value, "mpls_vpn_rd", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, rd_str));
  }

  if (wtc_2 & COUNT_MPLS_PW_ID) {
    pm_avro_check(avro_value_get_by_name(&value, "mpls_pw_id", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbgp->mpls_pw_id));
  }

  if (wtc & (COUNT_SRC_HOST|COUNT_SUM_HOST)) {
    addr_to_str(src_host, &pbase->src_ip);
    pm_avro_check(avro_value_get_by_name(&value, "ip_src", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, src_host));
  }

  if (wtc & (COUNT_SRC_NET|COUNT_SUM_NET)) {
    addr_to_str(src_host, &pbase->src_net);
    pm_avro_check(avro_value_get_by_name(&value, "net_src", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, src_host));
  }

  if (wtc & COUNT_DST_HOST) {
    addr_to_str(dst_host, &pbase->dst_ip);
    pm_avro_check(avro_value_get_by_name(&value, "ip_dst", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, dst_host));
  }

  if (wtc & COUNT_DST_NET) {
    addr_to_str(dst_host, &pbase->dst_net);
    pm_avro_check(avro_value_get_by_name(&value, "net_dst", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, dst_host));
  }

  if (wtc & COUNT_SRC_NMASK) {
    pm_avro_check(avro_value_get_by_name(&value, "mask_src", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->src_nmask));
  }

  if (wtc & COUNT_DST_NMASK) {
    pm_avro_check(avro_value_get_by_name(&value, "mask_dst", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->dst_nmask));
  }

  if (wtc & (COUNT_SRC_PORT|COUNT_SUM_PORT)) {
    pm_avro_check(avro_value_get_by_name(&value, "port_src", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->src_port));
  }

  if (wtc & COUNT_DST_PORT) {
    pm_avro_check(avro_value_get_by_name(&value, "port_dst", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->dst_port));
  }

#if defined (WITH_GEOIP)
  if (wtc_2 & COUNT_SRC_HOST_COUNTRY) {
    pm_avro_check(avro_value_get_by_name(&value, "country_ip_src", &field, NULL));
    if (pbase->src_ip_country.id > 0)
      pm_avro_check(avro_value_set_string(&field, GeoIP_code_by_id(pbase->src_ip_country.id)));
    else
      pm_avro_check(avro_value_set_string(&field, empty_string));
  }

  if (wtc_2 & COUNT_DST_HOST_COUNTRY) {
    pm_avro_check(avro_value_get_by_name(&value, "country_ip_dst", &field, NULL));
    if (pbase->dst_ip_country.id > 0)
      pm_avro_check(avro_value_set_string(&field, GeoIP_code_by_id(pbase->dst_ip_country.id)));
    else
      pm_avro_check(avro_value_set_string(&field, empty_string));
  }
#endif
#if defined (WITH_GEOIPV2)
  if (wtc_2 & COUNT_SRC_HOST_COUNTRY) {
    pm_avro_check(avro_value_get_by_name(&value, "country_ip_src", &field, NULL));
    if (strlen(pbase->src_ip_country.str))
      pm_avro_check(avro_value_set_string(&field, pbase->src_ip_country.str));
    else
      pm_avro_check(avro_value_set_string(&field, empty_string));
  }

  if (wtc_2 & COUNT_DST_HOST_COUNTRY) {
    pm_avro_check(avro_value_get_by_name(&value, "country_ip_dst", &field, NULL));
    if (strlen(pbase->dst_ip_country.str))
      pm_avro_check(avro_value_set_string(&field, pbase->dst_ip_country.str));
    else
      pm_avro_check(avro_value_set_string(&field, empty_string));
  }

  if (wtc_2 & COUNT_SRC_HOST_POCODE) {
    pm_avro_check(avro_value_get_by_name(&value, "pocode_ip_src", &field, NULL));
    if (strlen(pbase->src_ip_pocode.str))
      pm_avro_check(avro_value_set_string(&field, pbase->src_ip_pocode.str));
    else
      pm_avro_check(avro_value_set_string(&field, empty_string));
  }

  if (wtc_2 & COUNT_DST_HOST_POCODE) {
    pm_avro_check(avro_value_get_by_name(&value, "pocode_ip_dst", &field, NULL));
    if (strlen(pbase->dst_ip_pocode.str))
      pm_avro_check(avro_value_set_string(&field, pbase->dst_ip_pocode.str));
    else
      pm_avro_check(avro_value_set_string(&field, empty_string));
  }

  if (wtc_2 & COUNT_SRC_HOST_COORDS) {
    pm_avro_check(avro_value_get_by_name(&value, "lat_ip_src", &field, NULL));
    pm_avro_check(avro_value_set_double(&field, pbase->src_ip_lat));
    pm_avro_check(avro_value_get_by_name(&value, "lon_ip_src", &field, NULL));
    pm_avro_check(avro_value_set_double(&field, pbase->src_ip_lon));
  }

  if (wtc_2 & COUNT_DST_HOST_COORDS) {
    pm_avro_check(avro_value_get_by_name(&value, "lat_ip_dst", &field, NULL));
    pm_avro_check(avro_value_set_double(&field, pbase->dst_ip_lat));
    pm_avro_check(avro_value_get_by_name(&value, "lon_ip_dst", &field, NULL));
    pm_avro_check(avro_value_set_double(&field, pbase->dst_ip_lon));
  }
#endif

  if (wtc & COUNT_TCPFLAGS) {
    sprintf(misc_str, "%u", tcp_flags);
    pm_avro_check(avro_value_get_by_name(&value, "tcp_flags", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, misc_str));
  }

  if (wtc & COUNT_IP_PROTO) {
    char proto[PROTO_NUM_STRLEN];

    pm_avro_check(avro_value_get_by_name(&value, "ip_proto", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, ip_proto_print(pbase->proto, proto, PROTO_NUM_STRLEN)));
  }

  if (wtc & COUNT_IP_TOS) {
    pm_avro_check(avro_value_get_by_name(&value, "tos", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->tos));
  }

  if (wtc_2 & COUNT_SAMPLING_RATE) {
    pm_avro_check(avro_value_get_by_name(&value, "sampling_rate", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->sampling_rate));
  }

  if (wtc_2 & COUNT_SAMPLING_DIRECTION) {
    pm_avro_check(avro_value_get_by_name(&value, "sampling_direction", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, pbase->sampling_direction));
  }

  if (wtc_2 & COUNT_POST_NAT_SRC_HOST) {
    addr_to_str(src_host, &pnat->post_nat_src_ip);
    pm_avro_check(avro_value_get_by_name(&value, "post_nat_ip_src", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, src_host));
  }

  if (wtc_2 & COUNT_POST_NAT_DST_HOST) {
    addr_to_str(dst_host, &pnat->post_nat_dst_ip);
    pm_avro_check(avro_value_get_by_name(&value, "post_nat_ip_dst", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, dst_host));
  }

  if (wtc_2 & COUNT_POST_NAT_SRC_PORT) {
    pm_avro_check(avro_value_get_by_name(&value, "post_nat_port_src", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pnat->post_nat_src_port));
  }

  if (wtc_2 & COUNT_POST_NAT_DST_PORT) {
    pm_avro_check(avro_value_get_by_name(&value, "post_nat_port_dst", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pnat->post_nat_dst_port));
  }

  if (wtc_2 & COUNT_NAT_EVENT) {
    pm_avro_check(avro_value_get_by_name(&value, "nat_event", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pnat->nat_event));
  }

  if (wtc_2 & COUNT_MPLS_LABEL_TOP) {
    pm_avro_check(avro_value_get_by_name(&value, "mpls_label_top", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pmpls->mpls_label_top));
  }

  if (wtc_2 & COUNT_MPLS_LABEL_BOTTOM) {
    pm_avro_check(avro_value_get_by_name(&value, "mpls_label_bottom", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pmpls->mpls_label_bottom));
  }

  if (wtc_2 & COUNT_MPLS_STACK_DEPTH) {
    pm_avro_check(avro_value_get_by_name(&value, "mpls_stack_depth", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pmpls->mpls_stack_depth));
  }

  if (wtc_2 & COUNT_TUNNEL_SRC_MAC) {
    etheraddr_string(ptun->tunnel_eth_shost, src_mac);
    pm_avro_check(avro_value_get_by_name(&value, "tunnel_mac_src", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, src_mac));
  }

  if (wtc_2 & COUNT_TUNNEL_DST_MAC) {
    etheraddr_string(ptun->tunnel_eth_dhost, dst_mac);
    pm_avro_check(avro_value_get_by_name(&value, "tunnel_mac_dst", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, dst_mac));
  }

  if (wtc_2 & COUNT_TUNNEL_SRC_HOST) {
    addr_to_str(src_host, &ptun->tunnel_src_ip);
    pm_avro_check(avro_value_get_by_name(&value, "tunnel_ip_src", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, src_host));
  }

  if (wtc_2 & COUNT_TUNNEL_DST_HOST) {
    addr_to_str(dst_host, &ptun->tunnel_dst_ip);
    pm_avro_check(avro_value_get_by_name(&value, "tunnel_ip_dst", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, dst_host));
  }

  if (wtc_2 & COUNT_TUNNEL_IP_PROTO) {
    char proto[PROTO_NUM_STRLEN];

    pm_avro_check(avro_value_get_by_name(&value, "tunnel_ip_proto", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, ip_proto_print(ptun->tunnel_proto, proto, PROTO_NUM_STRLEN)));
  }

  if (wtc_2 & COUNT_TUNNEL_IP_TOS) {
    pm_avro_check(avro_value_get_by_name(&value, "tunnel_tos", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, ptun->tunnel_tos));
  }

  if (wtc_2 & COUNT_TUNNEL_SRC_PORT) {
    pm_avro_check(avro_value_get_by_name(&value, "tunnel_port_src", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, ptun->tunnel_src_port));
  }

  if (wtc_2 & COUNT_TUNNEL_DST_PORT) {
    pm_avro_check(avro_value_get_by_name(&value, "tunnel_port_dst", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, ptun->tunnel_dst_port));
  }

  if (wtc_2 & COUNT_VXLAN) {
    pm_avro_check(avro_value_get_by_name(&value, "vxlan", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, ptun->tunnel_id));
  }

  if (wtc_2 & COUNT_TIMESTAMP_START) {
    compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_start, TRUE,
		      config.timestamps_since_epoch, config.timestamps_rfc3339,
		      config.timestamps_utc);
    pm_avro_check(avro_value_get_by_name(&value, "timestamp_start", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, tstamp_str));
  }

  if (wtc_2 & COUNT_TIMESTAMP_END) {
    compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_end, TRUE,
		      config.timestamps_since_epoch, config.timestamps_rfc3339,
		      config.timestamps_utc);
    pm_avro_check(avro_value_get_by_name(&value, "timestamp_end", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, tstamp_str));
  }

  if (wtc_2 & COUNT_TIMESTAMP_ARRIVAL) {
    compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_arrival, TRUE,
		      config.timestamps_since_epoch, config.timestamps_rfc3339,
		      config.timestamps_utc);
    pm_avro_check(avro_value_get_by_name(&value, "timestamp_arrival", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, tstamp_str));
  }

  if (config.nfacctd_stitching) {
    if (stitch) {
      compose_timestamp(tstamp_str, SRVBUFLEN, &stitch->timestamp_min, TRUE,
			config.timestamps_since_epoch, config.timestamps_rfc3339,
			config.timestamps_utc);
      pm_avro_check(avro_value_get_by_name(&value, "timestamp_min", &field, NULL));
      pm_avro_check(avro_value_set_branch(&field, 1, &branch));
      pm_avro_check(avro_value_set_string(&branch, tstamp_str));

      compose_timestamp(tstamp_str, SRVBUFLEN, &stitch->timestamp_max, TRUE,
			config.timestamps_since_epoch, config.timestamps_rfc3339,
			config.timestamps_utc);
      pm_avro_check(avro_value_get_by_name(&value, "timestamp_max", &field, NULL));
      pm_avro_check(avro_value_set_branch(&field, 1, &branch));
      pm_avro_check(avro_value_set_string(&branch, tstamp_str));
    }
    else {
      pm_avro_check(avro_value_get_by_name(&value, "timestamp_min", &field, NULL));
      pm_avro_check(avro_value_set_branch(&field, 0, &branch));
      pm_avro_check(avro_value_get_by_name(&value, "timestamp_max", &field, NULL));
      pm_avro_check(avro_value_set_branch(&field, 0, &branch));
    }
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_SEQNO) {
    pm_avro_check(avro_value_get_by_name(&value, "export_proto_seqno", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->export_proto_seqno));
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_VERSION) {
    pm_avro_check(avro_value_get_by_name(&value, "export_proto_version", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->export_proto_version));
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_SYSID) {
    pm_avro_check(avro_value_get_by_name(&value, "export_proto_sysid", &field, NULL));
    pm_avro_check(avro_value_set_long(&field, pbase->export_proto_sysid));
  }

  if (wtc_2 & COUNT_EXPORT_PROTO_TIME) {
    compose_timestamp(tstamp_str, SRVBUFLEN, &pnat->timestamp_export, TRUE,
		      config.timestamps_since_epoch, config.timestamps_rfc3339,
		      config.timestamps_utc);
    pm_avro_check(avro_value_get_by_name(&value, "timestamp_export", &field, NULL));
    pm_avro_check(avro_value_set_string(&field, tstamp_str));
  }

  /* all custom primitives printed here */
  {
    if (config.cpptrs.num > 0)
      pm_avro_check(avro_value_get_by_name(&value, "custom_primitives", &field, NULL));

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
      compose_timestamp(tstamp_str, SRVBUFLEN, &tv, FALSE,
			config.timestamps_since_epoch, config.timestamps_rfc3339,
			config.timestamps_utc);
      pm_avro_check(avro_value_get_by_name(&value, "stamp_inserted", &field, NULL));
      pm_avro_check(avro_value_set_branch(&field, 1, &branch));
      pm_avro_check(avro_value_set_string(&branch, tstamp_str));

      tv.tv_sec = time(NULL);
      tv.tv_usec = 0;
      compose_timestamp(tstamp_str, SRVBUFLEN, &tv, FALSE,
			config.timestamps_since_epoch, config.timestamps_rfc3339,
			config.timestamps_utc);
      pm_avro_check(avro_value_get_by_name(&value, "stamp_updated", &field, NULL));
      pm_avro_check(avro_value_set_branch(&field, 1, &branch));
      pm_avro_check(avro_value_set_string(&branch, tstamp_str));
    }
    else {
      pm_avro_check(avro_value_get_by_name(&value, "stamp_inserted", &field, NULL));
      pm_avro_check(avro_value_set_branch(&field, 0, &branch));
      pm_avro_check(avro_value_get_by_name(&value, "stamp_updated", &field, NULL));
      pm_avro_check(avro_value_set_branch(&field, 0, &branch));
    }
  }

  if (flow_type != NF9_FTYPE_EVENT && flow_type != NF9_FTYPE_OPTION) {
    pm_avro_check(avro_value_get_by_name(&value, "packets", &field, NULL));
    pm_avro_check(avro_value_set_branch(&field, 1, &branch));
    pm_avro_check(avro_value_set_long(&branch, packet_counter));

    pm_avro_check(avro_value_get_by_name(&value, "flows", &field, NULL));
    if (wtc & COUNT_FLOWS) {
      pm_avro_check(avro_value_set_branch(&field, 1, &branch));
      pm_avro_check(avro_value_set_long(&branch, flow_counter));
    }
    else {
      pm_avro_check(avro_value_set_branch(&field, 0, &branch));
    }
    pm_avro_check(avro_value_get_by_name(&value, "bytes", &field, NULL));
    pm_avro_check(avro_value_set_branch(&field, 1, &branch));
    pm_avro_check(avro_value_set_long(&branch, bytes_counter));
  }
  else {
    pm_avro_check(avro_value_get_by_name(&value, "packets", &field, NULL));
    pm_avro_check(avro_value_set_branch(&field, 0, &branch));
    pm_avro_check(avro_value_get_by_name(&value, "flows", &field, NULL));
    pm_avro_check(avro_value_set_branch(&field, 0, &branch));
    pm_avro_check(avro_value_get_by_name(&value, "bytes", &field, NULL));
    pm_avro_check(avro_value_set_branch(&field, 0, &branch));
  }

  return value;
}

void add_writer_name_and_pid_avro(avro_value_t value, char *name, pid_t writer_pid)
{
  char wid[SHORTSHORTBUFLEN];
  avro_value_t field;

  snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", name, writer_pid);
  pm_avro_check(avro_value_get_by_name(&value, "writer_id", &field, NULL));
  pm_avro_check(avro_value_set_string(&field, wid));
}

void write_avro_schema_to_file(char *filename, avro_schema_t schema)
{
  FILE *avro_fp;
  avro_writer_t p_avro_schema_writer;

  avro_fp = open_output_file(filename, "w", TRUE);

  if (avro_fp) {
    p_avro_schema_writer = avro_writer_file(avro_fp);

    if (p_avro_schema_writer) {
      if (avro_schema_to_json(schema, p_avro_schema_writer)) {
	goto exit_lane;
      }
    }
    else goto exit_lane;

    close_output_file(avro_fp);
  }
  else goto exit_lane;

  return;

  exit_lane:
  Log(LOG_ERR, "ERROR ( %s/%s ): write_avro_schema_to_file(): unable to dump Avro schema: %s\n", config.name, config.type, avro_strerror());
  exit_gracefully(1);
}

void write_avro_schema_to_file_with_suffix(char *filename, char *suffix, char *buf, avro_schema_t schema)
{
  strcpy(buf, filename);
  strcat(buf, suffix);
  write_avro_schema_to_file(buf, schema);
}

char *write_avro_schema_to_memory(avro_schema_t avro_schema)
{
  avro_writer_t p_avro_writer;
  char *p_avro_buf = NULL;

  if (!config.avro_buffer_size) config.avro_buffer_size = LARGEBUFLEN;

  p_avro_buf = malloc(config.avro_buffer_size);

  if (!p_avro_buf) {
    Log(LOG_ERR, "ERROR ( %s/%s ): write_avro_schema_to_memory(): malloc() failed. Exiting.\n", config.name, config.type);
    exit_gracefully(1);
  }
  else memset(p_avro_buf, 0, config.avro_buffer_size);

  p_avro_writer = avro_writer_memory(p_avro_buf, config.avro_buffer_size);

  if (avro_schema_to_json(avro_schema, p_avro_writer)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): write_avro_schema_to_memory(): unable to dump Avro schema: %s\n", config.name, config.type, avro_strerror());
    free(p_avro_buf);
    p_avro_buf = NULL;
  }

  if (!avro_writer_tell(p_avro_writer)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): write_avro_schema_to_memory(): unable to tell Avro schema: %s\n", config.name, config.type, avro_strerror());
    free(p_avro_buf);
    p_avro_buf = NULL;
  }

  avro_writer_free(p_avro_writer);

  return p_avro_buf;
}

char *compose_avro_purge_schema(avro_schema_t avro_schema, char *writer_name)
{
  char *p_avro_buf = NULL, *json_str = NULL;

  p_avro_buf = write_avro_schema_to_memory(avro_schema);

  if (p_avro_buf) {
    char event_type[] = "purge_schema", wid[SHORTSHORTBUFLEN];
    json_t *obj = json_object();

    json_object_set_new_nocheck(obj, "event_type", json_string(event_type));

    snprintf(wid, SHORTSHORTBUFLEN, "%s/%u", writer_name, 0);
    json_object_set_new_nocheck(obj, "writer_id", json_string(wid));

    json_object_set_new_nocheck(obj, "schema", json_string(p_avro_buf));

    free(p_avro_buf);

    json_str = compose_json_str(obj);
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/%s ): compose_avro_purge_schema(): no p_avro_buf. Exiting.\n", config.name, config.type);
    exit_gracefully(1);
  }

  return json_str;
}

char *compose_avro_schema_name(char *extra1, char *extra2)
{
  int len_base = 0, len_extra1 = 0, len_extra2 = 0, len_total = 0; 
  char *schema_name = NULL;

  if (extra1) len_extra1 = strlen(extra1);
  if (extra2) {
    if (len_extra1) len_extra1++;
    len_extra2 = strlen(extra2);
  }
  
  if (len_extra1 || len_extra2) len_base = strlen("pmacct_");
  else len_base = strlen("pmacct");

  len_total = len_base + len_extra1 + len_extra2 + 1;

  schema_name = malloc(len_total);  
  if (!schema_name) {
    Log(LOG_ERR, "ERROR ( %s/%s ): compose_avro_schema_name(): malloc() failed. Exiting.\n", config.name, config.type);
    exit_gracefully(1);
  }
  else memset(schema_name, 0, len_total);

  strcpy(schema_name, "pmacct");
  if (len_extra1 || len_extra2) {
    strcat(schema_name, "_");

    if (len_extra1) {
      strcat(schema_name, extra1);
      if (len_extra2) strcat(schema_name, "_");
    }

    if (len_extra2) strcat(schema_name, extra2);
  }

  schema_name[len_total] = '\0'; /* pedantic */

  return schema_name;
}

#ifdef WITH_SERDES
serdes_schema_t *compose_avro_schema_registry_name_2(char *topic, int is_topic_dyn,
		avro_schema_t avro_schema, char *type, char *name, char *schema_registry)
{
  serdes_schema_t *loc_schema = NULL;
  char *loc_schema_name = NULL;
  int len = 0;

  if (!topic || !type || !name) return NULL;

  len = (strlen(topic) + strlen(type) + strlen(name) + 3 /* two seps + term */);
  loc_schema_name = malloc(len);

  memset(loc_schema_name, 0, len);
  strcpy(loc_schema_name, topic);
  strcat(loc_schema_name, "-");
  strcat(loc_schema_name, type);
  strcat(loc_schema_name, "-");
  strcat(loc_schema_name, name);

  loc_schema = compose_avro_schema_registry_name(loc_schema_name, FALSE, avro_schema, NULL, NULL, schema_registry); 
  free(loc_schema_name);

  return loc_schema; 
}

serdes_schema_t *compose_avro_schema_registry_name(char *topic, int is_topic_dyn,
		avro_schema_t avro_schema, char *type, char *name, char *schema_registry)
{
  serdes_conf_t *sd_conf;
  serdes_t *sd_desc;
  serdes_schema_t *loc_schema = NULL;
  char sd_errstr[LONGSRVBUFLEN];

  char *p_avro_schema_str = write_avro_schema_to_memory(avro_schema);
  char *p_avro_schema_name;

  if (!is_topic_dyn) {
    p_avro_schema_name = malloc(strlen(topic) + strlen("-value") + 1);

    strcpy(p_avro_schema_name, topic);
    strcat(p_avro_schema_name, "-value");
  }
  else {
    p_avro_schema_name = compose_avro_schema_name(type, name);
  }

  sd_conf = serdes_conf_new(NULL, 0, "schema.registry.url", schema_registry, NULL);

  sd_desc = serdes_new(sd_conf, sd_errstr, sizeof(sd_errstr));
  if (!sd_desc) {
    Log(LOG_ERR, "ERROR ( %s/%s ): serdes_new() failed: %s. Exiting.\n", config.name, config.type, sd_errstr);
    exit_gracefully(1);
  }

  loc_schema = serdes_schema_add(sd_desc, p_avro_schema_name, -1, p_avro_schema_str, -1, sd_errstr, sizeof(sd_errstr));
  if (!loc_schema) {
    Log(LOG_ERR, "ERROR ( %s/%s ): serdes_schema_add() failed: %s. Exiting.\n", config.name, config.type, sd_errstr);
    exit_gracefully(1);
  }
  else {
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): serdes_schema_add(): name=%s id=%d definition=%s\n", config.name, config.type,
	serdes_schema_name(loc_schema), serdes_schema_id(loc_schema), serdes_schema_definition(loc_schema));
  }

  return loc_schema;
}
#endif

void write_avro_json_record_to_file(FILE *fp, avro_value_t value)
{
  char *json_str;

  if (avro_value_to_json(&value, TRUE, &json_str)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): write_avro_json_record_to_file() unable to value to JSON: %s\n", config.name, config.type, avro_strerror());
    exit_gracefully(1);
  }

  fprintf(fp, "%s\n", json_str);
  free(json_str);
}

char *write_avro_json_record_to_buf(avro_value_t value)
{
  char *json_str;

  if (avro_value_to_json(&value, TRUE, &json_str)) {
    Log(LOG_ERR, "ERROR ( %s/%s ): write_avro_json_record_to_buf() unable to value to JSON: %s\n", config.name, config.type, avro_strerror());
    exit_gracefully(1);
  }

  return json_str;
}
#endif
