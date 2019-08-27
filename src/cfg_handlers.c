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
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "nfacctd.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "cfg_handlers.h"
#include "bgp/bgp.h"

int parse_truefalse(char *value_ptr)
{
  int value;

  lower_string(value_ptr);
  
  if (!strcmp("true", value_ptr)) value = TRUE;
  else if (!strcmp("false", value_ptr)) value = FALSE;
  else value = ERR;

  return value;
}

int parse_truefalse_nonzero(char *value_ptr)
{
  int value;

  lower_string(value_ptr);

  if (!strcmp("true", value_ptr)) value = TRUE;
  else if (!strcmp("false", value_ptr)) value = FALSE_NONZERO;
  else value = ERR;

  return value;
}

int validate_truefalse(int value)
{
  if (value == TRUE || value == FALSE) return SUCCESS;
  else return ERR;
}

void cfg_key_legacy_warning(char *filename, char *cfg_key)
{
  Log(LOG_WARNING, "WARN: [%s] Configuration key '%s' is legacy and will be discontinued in the next major release.\n", filename, cfg_key);
}

int cfg_key_debug(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr); 
  if (value < 0) return ERR; 

  if (!name) for (; list; list = list->next, changes++) list->cfg.debug = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) { 
	list->cfg.debug = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_debug_internal_msg(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.debug_internal_msg = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.debug_internal_msg = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_syslog(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.syslog = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.syslog = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_logfile(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.logfile = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'logfile'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pidfile(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.pidfile = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pidfile'. Globalized.\n", filename);

  return changes;
}

int cfg_key_daemonize(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.daemon = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'daemonize'. Globalized.\n", filename); 

  return changes;
}

int cfg_key_use_ip_next_hop(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.use_ip_next_hop = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'use_ip_next_hop'. Globalized.\n", filename);

  return changes;
}

int cfg_key_decode_arista_trailer(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.decode_arista_trailer = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'decode_arista_trailer'. Globalized.\n", filename);

  return changes;
}

int cfg_key_aggregate(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  struct custom_primitives_ptrs cpptrs;
  char *count_token;
  u_int32_t changes = 0; 
  u_int64_t value[3];

  trim_all_spaces(value_ptr);
  lower_string(value_ptr);
  memset(&value, 0, sizeof(value));
  memset(&cpptrs, 0, sizeof(cpptrs));

  while ((count_token = extract_token(&value_ptr, ','))) {
    if (!strcmp(count_token, "src_host")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_HOST, count_token);
    else if (!strcmp(count_token, "dst_host")) cfg_set_aggregate(filename, value, COUNT_INT_DST_HOST, count_token);
    else if (!strcmp(count_token, "src_net")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_NET, count_token);
    else if (!strcmp(count_token, "dst_net")) cfg_set_aggregate(filename, value, COUNT_INT_DST_NET, count_token);
    else if (!strcmp(count_token, "sum")) cfg_set_aggregate(filename, value, COUNT_INT_SUM_HOST, count_token);
    else if (!strcmp(count_token, "src_port")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_PORT, count_token);
    else if (!strcmp(count_token, "dst_port")) cfg_set_aggregate(filename, value, COUNT_INT_DST_PORT, count_token);
    else if (!strcmp(count_token, "proto")) cfg_set_aggregate(filename, value, COUNT_INT_IP_PROTO, count_token);
#if defined (HAVE_L2)
    else if (!strcmp(count_token, "src_mac")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_MAC, count_token);
    else if (!strcmp(count_token, "dst_mac")) cfg_set_aggregate(filename, value, COUNT_INT_DST_MAC, count_token);
    else if (!strcmp(count_token, "vlan")) cfg_set_aggregate(filename, value, COUNT_INT_VLAN, count_token);
    else if (!strcmp(count_token, "sum_mac")) cfg_set_aggregate(filename, value, COUNT_INT_SUM_MAC, count_token);
#else
    else if (!strcmp(count_token, "src_mac") || !strcmp(count_token, "dst_mac") ||
	     !strcmp(count_token, "vlan") || !strcmp(count_token, "sum_mac")) {
      Log(LOG_WARNING, "WARN: [%s] pmacct was compiled with --disable-l2 but 'aggregate' contains a L2 primitive. Ignored.\n", filename);
    }
#endif
    else if (!strcmp(count_token, "tos")) cfg_set_aggregate(filename, value, COUNT_INT_IP_TOS, count_token);
    else if (!strcmp(count_token, "none")) cfg_set_aggregate(filename, value, COUNT_INT_NONE, count_token);
    else if (!strcmp(count_token, "src_as")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_AS, count_token);
    else if (!strcmp(count_token, "dst_as")) cfg_set_aggregate(filename, value, COUNT_INT_DST_AS, count_token);
    else if (!strcmp(count_token, "sum_host")) cfg_set_aggregate(filename, value, COUNT_INT_SUM_HOST, count_token);
    else if (!strcmp(count_token, "sum_net")) cfg_set_aggregate(filename, value, COUNT_INT_SUM_NET, count_token);
    else if (!strcmp(count_token, "sum_as")) cfg_set_aggregate(filename, value, COUNT_INT_SUM_AS, count_token);
    else if (!strcmp(count_token, "sum_port")) cfg_set_aggregate(filename, value, COUNT_INT_SUM_PORT, count_token);
    else if (!strcmp(count_token, "tag")) cfg_set_aggregate(filename, value, COUNT_INT_TAG, count_token);
    else if (!strcmp(count_token, "tag2")) cfg_set_aggregate(filename, value, COUNT_INT_TAG2, count_token);
    else if (!strcmp(count_token, "flows")) cfg_set_aggregate(filename, value, COUNT_INT_FLOWS, count_token);
    else if (!strcmp(count_token, "class_legacy")) cfg_set_aggregate(filename, value, COUNT_INT_CLASS, count_token); // XXX: to deprecate 
    else if (!strcmp(count_token, "class_frame")) { // XXX: to deprecate
      if (config.acct_type == ACCT_NF) {
#if defined (WITH_NDPI)
        cfg_set_aggregate(filename, value, COUNT_INT_NDPI_CLASS, count_token);
#else
        Log(LOG_WARNING, "WARN: [%s] Class aggregation not possible due to missing --enable-ndpi\n", filename);
#endif
      }
    }
    else if (!strcmp(count_token, "class")) { // XXX: to conciliate and merge with 'class_legacy' and 'class_frame'
      if (config.acct_type == ACCT_NF) {
	cfg_set_aggregate(filename, value, COUNT_INT_CLASS, count_token);
      }
      else if (config.acct_type == ACCT_PM || config.acct_type == ACCT_SF) {
#if defined (WITH_NDPI)
        cfg_set_aggregate(filename, value, COUNT_INT_NDPI_CLASS, count_token);
#else
        Log(LOG_WARNING, "WARN: [%s] Class aggregation not possible due to missing --enable-ndpi\n", filename);
#endif
      }
    }
    else if (!strcmp(count_token, "tcpflags")) cfg_set_aggregate(filename, value, COUNT_INT_TCPFLAGS, count_token);
    else if (!strcmp(count_token, "std_comm")) cfg_set_aggregate(filename, value, COUNT_INT_STD_COMM, count_token);
    else if (!strcmp(count_token, "ext_comm")) cfg_set_aggregate(filename, value, COUNT_INT_EXT_COMM, count_token);
    else if (!strcmp(count_token, "lrg_comm")) cfg_set_aggregate(filename, value, COUNT_INT_LRG_COMM, count_token);
    else if (!strcmp(count_token, "as_path")) cfg_set_aggregate(filename, value, COUNT_INT_AS_PATH, count_token);
    else if (!strcmp(count_token, "local_pref")) cfg_set_aggregate(filename, value, COUNT_INT_LOCAL_PREF, count_token);
    else if (!strcmp(count_token, "med")) cfg_set_aggregate(filename, value, COUNT_INT_MED, count_token);
    else if (!strcmp(count_token, "peer_src_as")) cfg_set_aggregate(filename, value, COUNT_INT_PEER_SRC_AS, count_token);
    else if (!strcmp(count_token, "peer_dst_as")) cfg_set_aggregate(filename, value, COUNT_INT_PEER_DST_AS, count_token);
    else if (!strcmp(count_token, "peer_src_ip")) cfg_set_aggregate(filename, value, COUNT_INT_PEER_SRC_IP, count_token);
    else if (!strcmp(count_token, "peer_dst_ip")) cfg_set_aggregate(filename, value, COUNT_INT_PEER_DST_IP, count_token);
    else if (!strcmp(count_token, "src_as_path")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_AS_PATH, count_token);
    else if (!strcmp(count_token, "src_std_comm")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_STD_COMM, count_token);
    else if (!strcmp(count_token, "src_ext_comm")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_EXT_COMM, count_token);
    else if (!strcmp(count_token, "src_lrg_comm")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_LRG_COMM, count_token);
    else if (!strcmp(count_token, "src_local_pref")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_LOCAL_PREF, count_token);
    else if (!strcmp(count_token, "src_med")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_MED, count_token);
    else if (!strcmp(count_token, "in_iface")) cfg_set_aggregate(filename, value, COUNT_INT_IN_IFACE, count_token);
    else if (!strcmp(count_token, "out_iface")) cfg_set_aggregate(filename, value, COUNT_INT_OUT_IFACE, count_token);
    else if (!strcmp(count_token, "src_mask")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_NMASK, count_token);
    else if (!strcmp(count_token, "dst_mask")) cfg_set_aggregate(filename, value, COUNT_INT_DST_NMASK, count_token);
    else if (!strcmp(count_token, "cos")) cfg_set_aggregate(filename, value, COUNT_INT_COS, count_token);
    else if (!strcmp(count_token, "etype")) cfg_set_aggregate(filename, value, COUNT_INT_ETHERTYPE, count_token);
    else if (!strcmp(count_token, "mpls_vpn_rd")) cfg_set_aggregate(filename, value, COUNT_INT_MPLS_VPN_RD, count_token);
    else if (!strcmp(count_token, "mpls_pw_id")) cfg_set_aggregate(filename, value, COUNT_INT_MPLS_PW_ID, count_token);
    else if (!strcmp(count_token, "sampling_rate")) cfg_set_aggregate(filename, value, COUNT_INT_SAMPLING_RATE, count_token);
    else if (!strcmp(count_token, "sampling_direction")) cfg_set_aggregate(filename, value, COUNT_INT_SAMPLING_DIRECTION, count_token);
    else if (!strcmp(count_token, "src_host_country")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_HOST_COUNTRY, count_token);
    else if (!strcmp(count_token, "dst_host_country")) cfg_set_aggregate(filename, value, COUNT_INT_DST_HOST_COUNTRY, count_token);
    else if (!strcmp(count_token, "post_nat_src_host")) cfg_set_aggregate(filename, value, COUNT_INT_POST_NAT_SRC_HOST, count_token);
    else if (!strcmp(count_token, "post_nat_dst_host")) cfg_set_aggregate(filename, value, COUNT_INT_POST_NAT_DST_HOST, count_token);
    else if (!strcmp(count_token, "post_nat_src_port")) cfg_set_aggregate(filename, value, COUNT_INT_POST_NAT_SRC_PORT, count_token);
    else if (!strcmp(count_token, "post_nat_dst_port")) cfg_set_aggregate(filename, value, COUNT_INT_POST_NAT_DST_PORT, count_token);
    else if (!strcmp(count_token, "nat_event")) cfg_set_aggregate(filename, value, COUNT_INT_NAT_EVENT, count_token);
    else if (!strcmp(count_token, "fw_event")) cfg_set_aggregate(filename, value, COUNT_INT_NAT_EVENT, count_token);
    else if (!strcmp(count_token, "timestamp_start")) cfg_set_aggregate(filename, value, COUNT_INT_TIMESTAMP_START, count_token);
    else if (!strcmp(count_token, "timestamp_end")) cfg_set_aggregate(filename, value, COUNT_INT_TIMESTAMP_END, count_token);
    else if (!strcmp(count_token, "timestamp_arrival")) cfg_set_aggregate(filename, value, COUNT_INT_TIMESTAMP_ARRIVAL, count_token);
    else if (!strcmp(count_token, "mpls_label_top")) cfg_set_aggregate(filename, value, COUNT_INT_MPLS_LABEL_TOP, count_token);
    else if (!strcmp(count_token, "mpls_label_bottom")) cfg_set_aggregate(filename, value, COUNT_INT_MPLS_LABEL_BOTTOM, count_token);
    else if (!strcmp(count_token, "mpls_stack_depth")) cfg_set_aggregate(filename, value, COUNT_INT_MPLS_STACK_DEPTH, count_token);
    else if (!strcmp(count_token, "label")) cfg_set_aggregate(filename, value, COUNT_INT_LABEL, count_token);
    else if (!strcmp(count_token, "export_proto_seqno")) cfg_set_aggregate(filename, value, COUNT_INT_EXPORT_PROTO_SEQNO, count_token);
    else if (!strcmp(count_token, "export_proto_version")) cfg_set_aggregate(filename, value, COUNT_INT_EXPORT_PROTO_VERSION, count_token);
    else if (!strcmp(count_token, "export_proto_sysid")) cfg_set_aggregate(filename, value, COUNT_INT_EXPORT_PROTO_SYSID, count_token);
    else if (!strcmp(count_token, "src_host_pocode")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_HOST_POCODE, count_token);
    else if (!strcmp(count_token, "dst_host_pocode")) cfg_set_aggregate(filename, value, COUNT_INT_DST_HOST_POCODE, count_token);
    else if (!strcmp(count_token, "src_host_coords")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_HOST_COORDS, count_token);
    else if (!strcmp(count_token, "dst_host_coords")) cfg_set_aggregate(filename, value, COUNT_INT_DST_HOST_COORDS, count_token);
    else if (!strcmp(count_token, "tunnel_src_mac")) cfg_set_aggregate(filename, value, COUNT_INT_TUNNEL_SRC_MAC, count_token);
    else if (!strcmp(count_token, "tunnel_dst_mac")) cfg_set_aggregate(filename, value, COUNT_INT_TUNNEL_DST_MAC, count_token);
    else if (!strcmp(count_token, "tunnel_src_host")) cfg_set_aggregate(filename, value, COUNT_INT_TUNNEL_SRC_HOST, count_token);
    else if (!strcmp(count_token, "tunnel_dst_host")) cfg_set_aggregate(filename, value, COUNT_INT_TUNNEL_DST_HOST, count_token);
    else if (!strcmp(count_token, "tunnel_proto")) cfg_set_aggregate(filename, value, COUNT_INT_TUNNEL_IP_PROTO, count_token);
    else if (!strcmp(count_token, "tunnel_tos")) cfg_set_aggregate(filename, value, COUNT_INT_TUNNEL_IP_TOS, count_token);
    else if (!strcmp(count_token, "tunnel_src_port")) cfg_set_aggregate(filename, value, COUNT_INT_TUNNEL_SRC_PORT, count_token);
    else if (!strcmp(count_token, "tunnel_dst_port")) cfg_set_aggregate(filename, value, COUNT_INT_TUNNEL_DST_PORT, count_token);
    else if (!strcmp(count_token, "src_roa")) cfg_set_aggregate(filename, value, COUNT_INT_SRC_ROA, count_token);
    else if (!strcmp(count_token, "dst_roa")) cfg_set_aggregate(filename, value, COUNT_INT_DST_ROA, count_token);
    else if (!strcmp(count_token, "vxlan")) cfg_set_aggregate(filename, value, COUNT_INT_VXLAN, count_token);
    else {
      cpptrs.primitive[cpptrs.num].name = count_token;
      cpptrs.num++;
    }
  }

  if (!name) for (; list; list = list->next, changes++) {
    list->cfg.what_to_count = value[1];
    list->cfg.what_to_count_2 = value[2];
    memcpy(&list->cfg.cpptrs, &cpptrs, sizeof(cpptrs));
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.what_to_count = value[1];
        list->cfg.what_to_count_2 = value[2];
        memcpy(&list->cfg.cpptrs, &cpptrs, sizeof(cpptrs));
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_aggregate_primitives(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.aggregate_primitives = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'aggregate_primitives'. Globalized.\n", filename);

  return changes;
}

int cfg_key_proc_name(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.proc_name = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key '[nf|pm|sf|u]acctd_proc_name'. Globalized.\n", filename);

  return changes;
}

int cfg_key_proc_priority(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);

  if (!name) for (; list; list = list->next, changes++) list->cfg.proc_priority = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.proc_priority = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_snaplen(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < DEFAULT_SNAPLEN) {
    Log(LOG_WARNING, "WARN: [%s] 'snaplen' has to be >= %d.\n", filename, DEFAULT_SNAPLEN);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.snaplen = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'snaplen'. Globalized.\n", filename);

  return changes;
}

int cfg_key_aggregate_filter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) {
    Log(LOG_ERR, "ERROR: [%s] aggregation filter cannot be global. Not loaded.\n", filename);
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.a_filter = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_pre_tag_filter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) {
    Log(LOG_ERR, "ERROR: [%s] TAG filter cannot be global. Not loaded.\n", filename);
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	changes = load_tags(filename, &list->cfg.ptf, value_ptr);
        break;
      }
    }
  }

  return changes;
}

int cfg_key_pre_tag2_filter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) {
    Log(LOG_ERR, "ERROR: [%s] TAG2 filter cannot be global. Not loaded.\n", filename);
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        changes = load_tags(filename, &list->cfg.pt2f, value_ptr);
        break;
      }
    }
  }

  return changes;
}

int cfg_key_pre_tag_label_filter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) {
    Log(LOG_ERR, "ERROR: [%s] LABEL filter cannot be global. Not loaded.\n", filename);
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        changes = load_labels(filename, &list->cfg.ptlf, value_ptr);
        break;
      }
    }
  }

  return changes;
}


int cfg_key_pcap_filter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.clbuf = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pcap_filter'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pcap_protocol(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = strtol(value_ptr, NULL, 0);
  for (; list; list = list->next, changes++) list->cfg.pcap_protocol = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pcap_protocol'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pcap_direction(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "in", strlen("in"))) value = PCAP_D_IN;
  else if (!strncmp(value_ptr, "out", strlen("out"))) value = PCAP_D_OUT;
  else Log(LOG_WARNING, "WARN: [%s] Ignoring unknown 'pcap_direction' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.pcap_direction = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pcap_direction'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pcap_ifindex(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "sys", strlen("sys"))) value = PCAP_IFINDEX_SYS;
  else if (!strncmp(value_ptr, "hash", strlen("hash"))) value = PCAP_IFINDEX_HASH;
  else if (!strncmp(value_ptr, "map", strlen("map"))) value = PCAP_IFINDEX_MAP;
  else if (!strncmp(value_ptr, "none", strlen("none"))) value = PCAP_IFINDEX_NONE;
  else Log(LOG_WARNING, "WARN: [%s] Ignoring unknown 'pcap_ifindex' value.\n", filename); 

  for (; list; list = list->next, changes++) list->cfg.pcap_ifindex = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pcap_ifindex'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pcap_interfaces_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.pcap_interfaces_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pcap_interfaces_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pcap_interface(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.pcap_if = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pcap_interface'. Globalized.\n", filename);

  return changes;
}

int cfg_key_files_umask(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;
  char *endp;

  value = strtoul(value_ptr, &endp, 8);
  if (value < 2) {
    Log(LOG_WARNING, "WARN: [%s] 'files_umask' has to be >= '002'.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.files_umask = value & 0666;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.files_umask = value & 0666;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_files_uid(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  struct passwd *user = NULL;
  int value, changes = 0;

  user = getpwnam(value_ptr);
  if (!user) {
    value = atoi(value_ptr);
    if (value_ptr && !value && value_ptr[0] != '0');
    else user = getpwuid(value);
  }

  if (user) value = user->pw_uid;
  else {
    Log(LOG_ERR, "WARN: [%s] Invalid 'files_uid'.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.files_uid = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.files_uid = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_files_gid(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  struct group *group = NULL;
  u_int32_t value, changes = 0;

  group = getgrnam(value_ptr);
  if (!group) {
    value = atoi(value_ptr);
    if (value_ptr && !value && value_ptr[0] != '0');
    else group = getgrgid(value);
  }

  if (group) value = group->gr_gid;
  else {
    Log(LOG_ERR, "WARN: [%s] Invalid 'files_gid'.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.files_gid = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.files_gid = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_pcap_interface_wait(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.pcap_if_wait = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pcap_interface_wait'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pcap_savefile_wait(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.pcap_sf_wait = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pcap_savefile_wait'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pcap_savefile_delay(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'pcap_savefile_delay' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.pcap_sf_delay = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pcap_savefile_delay'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pcap_savefile_replay(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'pcap_savefile_replay' has to be >= 0.\n", filename);
    return ERR;
  }
  else if (value == 0) value = -1;

  for (; list; list = list->next, changes++) list->cfg.pcap_sf_replay = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pcap_savefile_replay'. Globalized.\n", filename);

  return changes;
}

int cfg_key_promisc(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.promisc = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'promisc'. Globalized.\n", filename);

  return changes;
}

int cfg_key_imt_path(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.imt_plugin_path = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.imt_plugin_path = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_imt_passwd(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.imt_plugin_passwd = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.imt_plugin_passwd = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_imt_buckets(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'imt_buckets' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.buckets = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.buckets = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_imt_mem_pools_number(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;
  
  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'imt_mem_pools_number' has to be >= 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.num_memory_pools = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.num_memory_pools = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_imt_mem_pools_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  /* legal values should be >= sizeof(struct acc), though we are unable to check
     this condition here. Thus, this function will just cut clearly wrong values
     ie. < = 0. Strict checks will be accomplished later, by the memory plugin */ 
  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'imt_mem_pools_size' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.memory_pool_size = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.memory_pool_size = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_db(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_db = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_db = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_table(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  /* validations: we allow only a) certain variable names, b) a maximum of 32 variables
     and c) a maximum table name length of 64 chars */ 
  {
    int num = 0;
    char *c, *ptr = value_ptr;

    while ((c = strchr(ptr, '%'))) {
      c++;
      ptr = c;
      switch (*c) {
      case 'd':
	num++;
	break;
      case 'H':
	num++;
	break;
      case 'm':
	num++;
	break;
      case 'M':
	num++;
	break;
      case 'w':
	num++;
	break;
      case 'W':
	num++;
	break;
      case 'Y':
	num++;
	break;
      case 's':
	num++;
	break;
      case 'S':
	num++;
	break;
      case 'z':
	num++;
	break;
      default:
	Log(LOG_ERR, "ERROR: [%s] sql_table, %%%c not supported.\n", filename, *c);
	exit(1);
	break;
      } 
    } 

    if (num > 32) {
      Log(LOG_ERR, "ERROR: [%s] sql_table, exceeded the maximum allowed variables (32) into the table name.\n", filename);
      exit(1);
    }
  }

  if (strlen(value_ptr) > 64) {
    Log(LOG_ERR, "ERROR: [%s] sql_table, exceeded the maximum SQL table name length (64).\n", filename);
    exit(1);
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_table = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_table = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_output_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  /* validations: we allow only a) certain variable names, b) a maximum of 32 variables */
  {
    int num = 0;
    char *c, *ptr = value_ptr;

    while ((c = strchr(ptr, '%'))) {
      c++;
      ptr = c;
      switch (*c) {
      case 'd':
        num++;
        break;
      case 'H':
        num++;
        break;
      case 'm':
        num++;
        break;
      case 'M':
        num++;
        break;
      case 'w':
        num++;
        break;
      case 'W':
        num++;
        break;
      case 'Y':
        num++;
        break;
      case 's':
        num++;
        break;
      case 'S':
	num++;
	break;
      case 'z':
        num++;
        break;
      default:
        Log(LOG_ERR, "ERROR: [%s] print_output_file, %%%c not supported.\n", filename, *c);
        exit(1);
        break;
      }
    }

    if (num > 32) {
      Log(LOG_ERR, "ERROR: [%s] print_output_file, exceeded the maximum allowed variables (32) into the filename.\n", filename);
      exit(1);
    }
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_table = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_table = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_latest_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (strchr(value_ptr, '%')) {
    Log(LOG_ERR, "ERROR: [%s] invalid 'print_latest_file' value: time-based '%%' variables not allowed.\n", filename);
    return TRUE;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_latest_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_latest_file = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_output_file_append(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_output_file_append = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_output_file_append = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_output_lock_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_output_lock_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_output_lock_file = value_ptr;
        changes++;
        break;
      }
    }
  }
   
  return changes;
}

int cfg_key_sql_table_schema(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_table_schema = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_table_schema = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_table_version(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "ERROR: [%s] invalid 'sql_table_version' value.\n", filename);
    exit(1);
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_table_version = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_table_version = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_table_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "bgp"));
  else if (!strcmp(value_ptr, "original"));
  else {
    Log(LOG_WARNING, "WARN: [%s] Invalid sql_table_type value '%s'\n", filename, value_ptr);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_table_type = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_table_type = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_data(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  lower_string(value_ptr);

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_data = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_data = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_conn_ca_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_conn_ca_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_conn_ca_file = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_host = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_host = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'sql_port' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_port = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_port = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_recovery_backup_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  cfg_key_legacy_warning(filename, "sql_backup_host");

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_backup_host = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_backup_host = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_dump_max_writers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1 || value >= 100) {
    Log(LOG_WARNING, "WARN: [%s] invalid 'dump_max_writers' value). Allowed values are: 1 <= dump_max_writers < 100.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.dump_max_writers = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.dump_max_writers = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_trigger_exec(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_trigger_exec = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_trigger_exec = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_trigger_time(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, t, t_howmany;

  parse_time(filename, value_ptr, &t, &t_howmany);

  if (!name) {
    for (; list; list = list->next, changes++) {
      list->cfg.sql_trigger_time = t;
      list->cfg.sql_trigger_time_howmany = t_howmany;
    }
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_trigger_time = t;
	list->cfg.sql_trigger_time_howmany = t_howmany;
	changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_user(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_user = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_user = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_passwd(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_passwd = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_passwd = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_refresh_time(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0, i, len = strlen(value_ptr);

  for (i = 0; i < len; i++) {
    if (!isdigit(value_ptr[i]) && !isspace(value_ptr[i])) {
      Log(LOG_ERR, "WARN: [%s] 'sql_refresh_time' is expected in secs but contains non-digit chars: '%c'\n", filename, value_ptr[i]);
      return ERR;
    }
  }

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'sql_refresh_time' has to be > 0.\n", filename);
    return ERR;
  }
     
  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_refresh_time = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_refresh_time = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_startup_delay(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_ERR, "WARN: [%s] 'sql_startup_delay' has to be >= 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_startup_delay = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_startup_delay = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_optimize_clauses(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_optimize_clauses = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_optimize_clauses = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_history_roundoff(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;
  int i, check, len;

  len = strlen(value_ptr);
  for (i = 0, check = 0; i < len; i++) {
    if (value_ptr[i] == 'd') check |= COUNT_DAILY;
    if (value_ptr[i] == 'w') check |= COUNT_WEEKLY;
    if (value_ptr[i] == 'M') check |= COUNT_MONTHLY;
  } 
  if (((check & COUNT_DAILY) || (check & COUNT_MONTHLY)) && (check & COUNT_WEEKLY)) {
    Log(LOG_ERR, "WARN: [%s] 'sql_history_roundoff' 'w' is not compatible with either 'd' or 'M'.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_history_roundoff = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_history_roundoff = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_history(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, sql_history, sql_history_howmany;

  parse_time(filename, value_ptr, &sql_history, &sql_history_howmany);

  if (!name) {
    for (; list; list = list->next, changes++) {
      list->cfg.sql_history = sql_history;
      list->cfg.sql_history_howmany = sql_history_howmany;
    }
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_history = sql_history;
        list->cfg.sql_history_howmany = sql_history_howmany;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_history_offset(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_ERR, "WARN: [%s] 'sql_history_offset' has to be >= 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_history_offset = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_history_offset = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}


int cfg_key_timestamps_since_epoch(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.timestamps_since_epoch = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.timestamps_since_epoch = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_cache_entries(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'sql_cache_entries' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_cache_entries = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_cache_entries = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_dont_try_update(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_dont_try_update = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_dont_try_update = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_preprocess(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_preprocess = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_preprocess = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_preprocess_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "any", 3)) value = FALSE;
  if (!strncmp(value_ptr, "all", 3)) value = TRUE;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_preprocess_type = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.sql_preprocess_type = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_multi_values(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'sql_multi_values' has to be >= 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_multi_values = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_multi_values = value; 
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_mongo_insert_batch(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'mongo_insert_batch' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.mongo_insert_batch = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.mongo_insert_batch = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_message_broker_output(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "json")) {
#ifdef WITH_JANSSON
    value = PRINT_OUTPUT_JSON;
#else
    value = PRINT_OUTPUT_JSON;
    Log(LOG_WARNING, "WARN: [%s] 'message_broker_output' set to json but will produce no output (missing --enable-jansson).\n", filename);
#endif
  }
  else if (!strcmp(value_ptr, "avro")) {
#ifdef WITH_AVRO
    value = PRINT_OUTPUT_AVRO;
#else
    value = PRINT_OUTPUT_AVRO;
    Log(LOG_WARNING, "WARN: [%s] 'message_broker_output' set to avro but will produce no output (missing --enable-avro).\n", filename);
#endif
  }
  else if (!strcmp(value_ptr, "custom")) {
    value = PRINT_OUTPUT_CUSTOM;
  }
  else {
    Log(LOG_WARNING, "WARN: [%s] Invalid 'message_broker_output' value '%s'\n", filename, value_ptr);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.message_broker_output = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.message_broker_output = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_avro_buffer_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  value = strtoull(value_ptr, &endptr, 10);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'avro_buffer_size' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.avro_buffer_size = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.avro_buffer_size = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_avro_schema_output_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.avro_schema_output_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.avro_schema_output_file = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_amqp_exchange_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.amqp_exchange_type = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.amqp_exchange_type = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_amqp_persistent_msg(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.amqp_persistent_msg = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.amqp_persistent_msg = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_amqp_frame_max(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'amqp_frame_max' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.amqp_frame_max = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.amqp_frame_max = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_amqp_heartbeat_interval(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);

  if (!name) for (; list; list = list->next, changes++) list->cfg.amqp_heartbeat_interval = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.amqp_heartbeat_interval = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_amqp_vhost(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.amqp_vhost = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.amqp_vhost = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_amqp_routing_key_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'amqp_routing_key_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.amqp_routing_key_rr = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.amqp_routing_key_rr = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_amqp_avro_schema_routing_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.amqp_avro_schema_routing_key = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.amqp_avro_schema_routing_key = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_amqp_avro_schema_refresh_time(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'amqp_avro_schema_refresh_time' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.amqp_avro_schema_refresh_time = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.amqp_avro_schema_refresh_time = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_kafka_broker_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'kafka_broker_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.kafka_broker_port = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.kafka_broker_port = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_kafka_partition(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < -1) {
    Log(LOG_ERR, "WARN: [%s] 'kafka_partition' has to be >= -1.\n", filename);
    return ERR;
  }

  if (!value) value = FALSE_NONZERO; 

  if (!name) for (; list; list = list->next, changes++) list->cfg.kafka_partition = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.kafka_partition = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_kafka_partition_dynamic(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.kafka_partition_dynamic = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.kafka_partition_dynamic = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_kafka_partition_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value_len, changes = 0;

  value_len = strlen(value_ptr);
  lower_string(value_ptr);

  if (!name) for (; list; list = list->next, changes++) {
    list->cfg.kafka_partition_key = value_ptr;
    list->cfg.kafka_partition_keylen = value_len;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.kafka_partition_key = value_ptr;
        list->cfg.kafka_partition_keylen = value_len;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_kafka_avro_schema_topic(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  cfg_key_legacy_warning(filename, "kafka_avro_schema_topic");

  if (!name) for (; list; list = list->next, changes++) list->cfg.kafka_avro_schema_topic = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.kafka_avro_schema_topic = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_kafka_avro_schema_refresh_time(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  cfg_key_legacy_warning(filename, "kafka_avro_schema_refresh_time");

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'kakfa_avro_schema_refresh_time' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.kafka_avro_schema_refresh_time = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.kafka_avro_schema_refresh_time = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_kafka_avro_schema_registry(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.kafka_avro_schema_registry = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.kafka_avro_schema_registry = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_kafka_config_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.kafka_config_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.kafka_config_file = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_locking_style(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  lower_string(value_ptr);

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_locking_style = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.sql_locking_style = value_ptr;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_use_copy(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_use_copy = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_use_copy = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_sql_delimiter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  /* delimiter is only one character */
  if (strlen(value_ptr) != 1) {
    Log(LOG_WARNING, "WARN: [%s] 'sql_delimiter' length has to be 1.\n", filename);
    return ERR; 
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sql_delimiter = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sql_delimiter = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_timestamps_rfc3339(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.timestamps_rfc3339 = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.timestamps_rfc3339 = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_timestamps_utc(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.timestamps_utc = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.timestamps_utc = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_timestamps_secs(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.timestamps_secs = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.timestamps_secs = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_plugin_pipe_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  /* legal values should be >= sizeof(struct pkt_data)+sizeof(struct ch_buf_hdr)
     though we are unable to check this condition here. Thus, this function will
     just cut clearly wrong values ie. < = 0. Strict checks will be accomplished
     later, by the load_plugins() */ 
  value = strtoull(value_ptr, &endptr, 10);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'plugin_pipe_size' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.pipe_size = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.pipe_size = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_plugin_pipe_zmq(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.pipe_zmq = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.pipe_zmq = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_plugin_pipe_zmq_retry(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'plugin_pipe_zmq_retry' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.pipe_zmq_retry = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.pipe_zmq_retry = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_plugin_pipe_zmq_profile(char *filename, char *name, char *value_ptr)
{

  int changes = 0;
  lower_string(value_ptr);

#ifdef WITH_ZMQ
  struct plugins_list_entry *list = plugins_list;
  int value;
  if (!name) for (; list; list = list->next, changes++) {
    value = p_zmq_plugin_pipe_set_profile(&list->cfg, value_ptr);
    if (value < 0) return ERR;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	value = p_zmq_plugin_pipe_set_profile(&list->cfg, value_ptr);
	if (value < 0) return ERR;

        changes++;
        break;
      }
    }
  }
#endif

  return changes;
}

int cfg_key_plugin_pipe_zmq_hwm(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_ERR, "WARN: [%s] 'plugin_pipe_zmq_hwm' has to be >= 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.pipe_zmq_hwm = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.pipe_zmq_hwm = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_plugin_exit_any(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.plugin_exit_any = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'plugin_exit_any'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_pipe_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  value = strtoull(value_ptr, &endptr, 10);
  if (!value || value > INT_MAX) {
    Log(LOG_WARNING, "WARN: [%s] '[nf|sf|pm]acctd_pipe_size' has to be > 0 and <= INT_MAX.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_pipe_size = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key '[nf|sf|pm]acctd_pipe_size'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_pro_rating(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfacctd_pro_rating = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfacctd_pro_rating = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfacctd_templates_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_templates_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_templates_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_stitching(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfacctd_stitching = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfacctd_stitching = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfacctd_account_options(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_account_options = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_account_options'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_pipe_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  value = strtoull(value_ptr, &endptr, 10);
  if (!value || value > INT_MAX) {
    Log(LOG_WARNING, "WARN: [%s] 'bgp_daemon_pipe_size' has to be > 0 and <= INT_MAX.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_pipe_size = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_pipe_size'. Globalized.\n", filename);

  return changes;
}

int cfg_key_plugin_buffer_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  /* legal values should be >= sizeof(struct pkt_data) and < plugin_pipe_size
     value, if any though we are unable to check this condition here. Thus, this
     function will just cut clearly wrong values ie. < = 0. Strict checks will 
     be accomplished later, by the load_plugins() */
  value = strtoull(value_ptr, &endptr, 10);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'plugin_buffer_size' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.buffer_size = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.buffer_size = value; 
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_networks_mask(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'networks_mask' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.networks_mask = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.networks_mask = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_networks_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.networks_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.networks_file = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_networks_file_filter(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.networks_file_filter = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.networks_file_filter = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_networks_file_no_lpm(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.networks_file_no_lpm = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.networks_file_no_lpm = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_networks_no_mask_if_zero(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.networks_no_mask_if_zero = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.networks_no_mask_if_zero = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_networks_cache_entries(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'networks_cache_entries' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.networks_cache_entries = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.networks_cache_entries = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_ports_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.ports_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.ports_file = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_maps_refresh(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.maps_refresh = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'maps_refresh'. Globalized.\n", filename);

  return changes;
}

int cfg_key_print_cache_entries(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'print_cache_entries' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_cache_entries = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_cache_entries = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_markers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_markers = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_markers = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_output(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "formatted"))
    value = PRINT_OUTPUT_FORMATTED;
  else if (!strcmp(value_ptr, "csv"))
    value = PRINT_OUTPUT_CSV;
  else if (!strcmp(value_ptr, "json")) {
#ifdef WITH_JANSSON
    value = PRINT_OUTPUT_JSON;
#else
    value = PRINT_OUTPUT_JSON;
    Log(LOG_WARNING, "WARN: [%s] print_output set to json but will produce no output (missing --enable-jansson).\n", filename);
#endif
  }
  else if (!strcmp(value_ptr, "event_formatted")) {
    value = PRINT_OUTPUT_FORMATTED;
    value |= PRINT_OUTPUT_EVENT;
  }
  else if (!strcmp(value_ptr, "event_csv")) {
    value = PRINT_OUTPUT_CSV;
    value |= PRINT_OUTPUT_EVENT;
  }
  else if (!strcmp(value_ptr, "avro")) {
#ifdef WITH_AVRO
    value = PRINT_OUTPUT_AVRO;
#else
    value = PRINT_OUTPUT_AVRO;
    Log(LOG_WARNING, "WARN: [%s] print_output set to avro but will produce no output (missing --enable-avro).\n", filename);
#endif
  }
  else if (!strcmp(value_ptr, "custom")) {
    value = PRINT_OUTPUT_CUSTOM;
  }
  else {
    Log(LOG_WARNING, "WARN: [%s] Invalid print output value '%s'\n", filename, value_ptr);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_output = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_output = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_output_separator(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (strlen(value_ptr) != 1) {
    if (!strcmp(value_ptr, "\\t") || !strcmp(value_ptr, "\\s"));
    else {
      Log(LOG_WARNING, "WARN: [%s] Invalid print_output_separator value '%s'. Only one char allowed.\n", filename, value_ptr);
      return ERR;
    }
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_output_separator = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_output_separator = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_num_protos(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.num_protos = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.num_protos = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_num_hosts(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.num_hosts = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.num_hosts = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_post_tag(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  pm_id_t value, changes = 0;
  char *endptr;

  value = strtoull(value_ptr, &endptr, 10);
  if (value < 1) {
    Log(LOG_ERR, "WARN: [%s] 'post_tag' cannot be zero.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.post_tag = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.post_tag = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_post_tag2(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  pm_id_t value, changes = 0;
  char *endptr;

  value = strtoull(value_ptr, &endptr, 10);
  if (value < 1) {
    Log(LOG_ERR, "WARN: [%s] 'post_tag2' cannot be zero.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.post_tag2 = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.post_tag2 = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sampling_rate(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_ERR, "WARN: [%s] 'sampling_rate' has to be >= 1.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sampling_rate = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sampling_rate = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sampling_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sampling_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sampling_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'nfacctd_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_port = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_ip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_ip = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_ip'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_kafka_broker_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_kafka_broker_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_kafka_broker_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_kafka_broker_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'nfacctd_kafka_broker_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_kafka_broker_port = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_kafka_broker_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_kafka_topic(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_kafka_topic = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_kafka_topic'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_kafka_config_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_kafka_config_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_kafka_config_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_zmq_address(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_zmq_address = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_zmq_address'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_allow_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_allow_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_allow_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_allow_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_allow_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_allow_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_md5_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_md5_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_md5_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pre_tag_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.pre_tag_map = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.pre_tag_map = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_maps_entries(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'maps_entries' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.maps_entries = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.maps_entries = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_maps_row_len(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'maps_row_len' has to be > 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.maps_row_len = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.maps_row_len = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_maps_index(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.maps_index = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'maps_index'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_time_secs(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) {
    if (!list->cfg.nfacctd_time) {  
      if (value) list->cfg.nfacctd_time = NF_TIME_SECS;
    }
    else Log(LOG_WARNING, "WARN: [%s] Possibly 'nfacctd_time_new: true' set. 'nfacctd_time_secs' ignored.\n", filename);
  }
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_time_secs'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_time_new(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) {
    if (!list->cfg.nfacctd_time) {
      if (value) {
	list->cfg.nfacctd_time = NF_TIME_NEW;
	list->cfg.nfacctd_time_new = TRUE;
      }
    }
    else Log(LOG_WARNING, "WARN: [%s] Possibly 'nfacctd_time_secs: true' set. 'nfacctd_time_new' ignored.\n", filename);
  }
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_time_new'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_mcast_groups(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  struct host_addr tmp_addr;
  char *count_token;
  u_int32_t changes = 0; 
  u_int8_t idx = 0, more = 0; 

  trim_all_spaces(value_ptr);
  memset(mcast_groups, 0, sizeof(mcast_groups));

  while ((count_token = extract_token(&value_ptr, ','))) {
    memset(&tmp_addr, 0, sizeof(tmp_addr));
    str_to_addr(count_token, &tmp_addr);
    if (is_multicast(&tmp_addr)) {
      if (idx < MAX_MCAST_GROUPS) {
        memcpy(&mcast_groups[idx], &tmp_addr, sizeof(tmp_addr));
        idx++;
      }
      else more++;
    } 
  }

  for (; list; list = list->next, changes++); /* Nothing to do because of the global array, just rolling changes counters */
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for keys '[nfacctd|sfacctd]_mcast_groups'. Globalized.\n",
		  filename);
  if (more) Log(LOG_WARNING, "WARN: [%s] Only the first %u (on a total of %u) multicast groups will be joined.\n",
		  filename, MAX_MCAST_GROUPS, MAX_MCAST_GROUPS+more);

  return changes;
}

int cfg_key_nfacctd_bgp(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);

  if (!strcmp(value_ptr, "false"))
    value = BGP_DAEMON_NONE;
  else if (!strcmp(value_ptr, "true"))
    value = BGP_DAEMON_ONLINE;
  else {
    Log(LOG_ERR, "WARN: [%s] Invalid 'bgp_daemon' value '%s'\n", filename, value_ptr);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_aspath_radius(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
        Log(LOG_ERR, "WARN: [%s] 'bgp_aspath_radius' has to be >= 1.\n", filename);
        return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_aspath_radius = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_aspath_radius'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_stdcomm_pattern(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_stdcomm_pattern = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_stdcomm_pattern'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_extcomm_pattern(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_extcomm_pattern = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_extcomm_pattern'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_lrgcomm_pattern(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_lrgcomm_pattern = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_lrgcomm_pattern'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_stdcomm_pattern_to_asn(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_stdcomm_pattern_to_asn = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_stdcomm_pattern_to_asn'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_lrgcomm_pattern_to_asn(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_lrgcomm_pattern_to_asn = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_lrgcomm_pattern_to_asn'. Globalized.\n", filename);

  return changes;
}

int cfg_key_bgp_blackhole_stdcomm_list(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_blackhole_stdcomm_list = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_blackhole_stdcomm_list'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_peer_src_as_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value = BGP_SRC_PRIMITIVES_UNK, changes = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "netflow", strlen("netflow"))) value = BGP_SRC_PRIMITIVES_KEEP;
  else if (!strncmp(value_ptr, "sflow", strlen("sflow"))) value = BGP_SRC_PRIMITIVES_KEEP;
  else if (!strncmp(value_ptr, "map", strlen("map"))) value = BGP_SRC_PRIMITIVES_MAP;
  else if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else if (!strncmp(value_ptr, "fallback", strlen("fallback")) ||
	   !strncmp(value_ptr, "longest", strlen("longest"))) {
    value = BGP_SRC_PRIMITIVES_KEEP;
    value |= BGP_SRC_PRIMITIVES_BGP;
  }
  else Log(LOG_WARNING, "WARN: [%s] Ignoring unknown 'bgp_peer_src_as_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_peer_as_src_type = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_peer_src_as_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_std_comm_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value = BGP_SRC_PRIMITIVES_UNK, changes = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else Log(LOG_WARNING, "WARN: [%s] Ignoring unknown 'bgp_src_std_comm_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_std_comm_type = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_src_std_comm_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_ext_comm_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value = BGP_SRC_PRIMITIVES_UNK, changes = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else Log(LOG_WARNING, "WARN: [%s] Ignoring unknown 'bgp_src_ext_comm_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_ext_comm_type = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_src_ext_comm_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_lrg_comm_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value = BGP_SRC_PRIMITIVES_UNK, changes = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else Log(LOG_WARNING, "WARN: [%s] Ignoring unknown 'bgp_src_lrg_comm_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_lrg_comm_type = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_src_lrg_comm_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_as_path_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value = BGP_SRC_PRIMITIVES_UNK, changes = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else Log(LOG_WARNING, "WARN: [%s] Ignoring unknown 'bgp_src_as_path_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_as_path_type = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_src_as_path_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_local_pref_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value = BGP_SRC_PRIMITIVES_UNK, changes = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "map", strlen("map"))) value = BGP_SRC_PRIMITIVES_MAP;
  else if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else Log(LOG_WARNING, "WARN: [%s] Ignoring unknown 'bgp_src_local_pref_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_local_pref_type = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_src_local_pref_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_med_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value = BGP_SRC_PRIMITIVES_UNK, changes = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "map", strlen("map"))) value = BGP_SRC_PRIMITIVES_MAP;
  else if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else Log(LOG_WARNING, "WARN: [%s] Ignoring unknown 'bgp_src_med_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_med_type = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_src_med_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_roa_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value = BGP_SRC_PRIMITIVES_UNK, changes = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "bgp", strlen("bgp"))) value = BGP_SRC_PRIMITIVES_BGP;
  else Log(LOG_WARNING, "WARN: [%s] Ignoring unknown 'bgp_src_roa_type' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_roa_type = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_src_roa_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_peer_as_skip_subas(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_peer_as_skip_subas = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_peer_as_skip_subas'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_local_pref_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_local_pref_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_src_local_pref_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_peer_src_as_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_peer_as_src_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_peer_src_as_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_src_med_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_src_med_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_src_med_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_to_agent_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_to_agent_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_to_agent_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_flow_to_rd_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_flow_to_rd_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'flow_to_rd_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_follow_default(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_follow_default = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_follow_default'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_follow_nexthop(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  char *count_token;
  int changes = 0, idx = 0, valid = 0;

  trim_all_spaces(value_ptr);

  while ((count_token = extract_token(&value_ptr, ',')) && idx < FOLLOW_BGP_NH_ENTRIES) {
    for (list = plugins_list; list; list = list->next) {
      valid = str2prefix(count_token, &list->cfg.nfacctd_bgp_follow_nexthop[idx]);
      if (!valid) {
	Log(LOG_WARNING, "WARN: [%s] bgp_follow_nexthop: invalid IP prefix '%s'.\n", filename, count_token);
	break;
      }
    }
    if (valid) idx++;
  }

  changes = idx;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_follow_nexthop'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_follow_nexthop_external(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_follow_nexthop_external = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_follow_nexthop_external'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_disable_router_id_check(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.bgp_disable_router_id_check = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_disable_router_id_check'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_neighbors_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_neighbors_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_neighbors_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_max_peers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
        Log(LOG_ERR, "WARN: [%s] 'bgp_daemon_max_peers' has to be >= 1.\n", filename);
        return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_max_peers = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_max_peers'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_ip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_ip = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_ip'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_id(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_id = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_id'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_as(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;
  char *endptr;
  as_t value;

  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_as = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_as'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_daemon_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_port = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_bgp_lg(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.bgp_lg = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_lg'. Globalized.\n", filename);

  return changes;
}

int cfg_key_bgp_lg_ip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_lg_ip = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_lg_ip'. Globalized.\n", filename);

  return changes;
}

int cfg_key_bgp_lg_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_daemon_lg_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bgp_lg_port = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_lg_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_bgp_lg_threads(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_daemon_lg_threads' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bgp_lg_threads = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_lg_threads'. Globalized.\n", filename);

  return changes;
}

int cfg_key_bgp_lg_user(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_lg_user = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_lg_user'. Globalized.\n", filename);

  return changes;
}

int cfg_key_bgp_lg_passwd(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_lg_passwd = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_lg_passwd'. Globalized.\n", filename);

  return changes;
}

int cfg_key_bgp_xconnect_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_xconnect_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_xconnect_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_ip_precedence(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value < 0) || (value > 7)) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_daemon_ipprec' has to be in the range 0-7.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_ipprec = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_ipprec'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_peer_buckets(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 1000)) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_table_peer_buckets' has to be in the range 1-1000.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bgp_table_peer_buckets = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_peer_buckets'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_per_peer_buckets(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 128)) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_table_per_peer_buckets' has to be in the range 1-128.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bgp_table_per_peer_buckets = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_per_peer_buckets'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_attr_hash_buckets(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 1000000)) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_table_attr_hash_buckets' has to be in the range 1-1000000.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bgp_table_attr_hash_buckets = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_attr_hash_buckets'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_per_peer_hash(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value = BGP_ASPATH_HASH_PATHID, changes = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "path_id", strlen("path_id"))) value = BGP_ASPATH_HASH_PATHID;
  else Log(LOG_WARNING, "WARN: [%s] Ignoring unknown 'bgp_table_per_peer_hash' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.bgp_table_per_peer_hash = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_per_peer_hash'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_batch_interval(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_daemon_batch_interval' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_batch_interval = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_batch_interval'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_batch(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_daemon_batch' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_batch = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_batch'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_ip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_ip = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_ip'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_daemon_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_port = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_pipe_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  value = strtoull(value_ptr, &endptr, 10);
  if (!value || value > INT_MAX) {
    Log(LOG_WARNING, "WARN: [%s] 'bmp_daemon_pipe_size' has to be > 0 and <= INT_MAX.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_pipe_size = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_pipe_size'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_max_peers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
        Log(LOG_ERR, "WARN: [%s] 'bmp_daemon_max_peers' has to be >= 1.\n", filename);
        return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_max_peers = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_max_peers'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_allow_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_allow_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_allow_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_ip_precedence(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value < 0) || (value > 7)) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_daemon_ipprec' has to be in the range 0-7.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_ipprec = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_ipprec'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_batch_interval(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_daemon_batch_interval' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_batch_interval = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_batch_interval'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_batch(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_daemon_batch' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_batch = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_batch'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_table_peer_buckets(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 1000)) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_table_peer_buckets' has to be in the range 1-1000.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bmp_table_peer_buckets = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_table_peer_buckets'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_table_per_peer_buckets(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 128)) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_table_per_peer_buckets' has to be in the range 1-128.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bmp_table_per_peer_buckets = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_table_per_peer_buckets'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_table_attr_hash_buckets(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 1000000)) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_table_attr_hash_buckets' has to be in the range 1-1000000.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bmp_table_attr_hash_buckets = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_table_attr_hash_buckets'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_table_per_peer_hash(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value = BGP_ASPATH_HASH_PATHID, changes = 0;

  lower_string(value_ptr);
  if (!strncmp(value_ptr, "path_id", strlen("path_id"))) value = BGP_ASPATH_HASH_PATHID;
  else Log(LOG_WARNING, "WARN: [%s] Ignoring unknown 'bmp_table_per_peer_hash' value.\n", filename);

  for (; list; list = list->next, changes++) list->cfg.bmp_table_per_peer_hash = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_table_per_peer_hash'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_output(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "json")) {
#ifdef WITH_JANSSON
    value = PRINT_OUTPUT_JSON;
#else
    value = PRINT_OUTPUT_JSON;
    Log(LOG_WARNING, "WARN: [%s] bmp_daemon_msglog_output set to json but will produce no output (missing --enable-jansson).\n", filename);
#endif
  }
  else {
    Log(LOG_WARNING, "WARN: [%s] Invalid bmp_daemon_msglog_output value '%s'\n", filename, value_ptr);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_output = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_output'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_amqp_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_amqp_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_amqp_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_amqp_vhost(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_amqp_vhost = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_amqp_vhost'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_amqp_user(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_amqp_user = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_amqp_user'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_amqp_passwd(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_amqp_passwd = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_amqp_passwd'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_amqp_exchange(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_amqp_exchange = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_amqp_exchange'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_amqp_exchange_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_amqp_exchange_type = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_amqp_exchange_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_amqp_routing_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_amqp_routing_key = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_amqp_routing_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_amqp_routing_key_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'bmp_daemon_msglog_amqp_routing_key_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_amqp_routing_key_rr = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_amqp_routing_key_rr'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_amqp_persistent_msg(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_amqp_persistent_msg = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_amqp_persistent_msg'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_amqp_frame_max(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;
      
  value = strtoul(value_ptr, &endptr, 10);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'bmp_daemon_msglog_amqp_frame_max' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_amqp_frame_max = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_amqp_frame_max'. Globalized.\n", filename);
  
  return changes;
}

int cfg_key_nfacctd_bmp_msglog_amqp_heartbeat_interval(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_amqp_heartbeat_interval = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_amqp_heartbeat_interval'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_amqp_retry(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_daemon_msglog_amqp_retry' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_amqp_retry = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_amqp_retry'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_latest_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_latest_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_latest_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_output(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "json")) {
#ifdef WITH_JANSSON
    value = PRINT_OUTPUT_JSON;
#else
    value = PRINT_OUTPUT_JSON;
    Log(LOG_WARNING, "WARN: [%s] bmp_dump_output set to json but will produce no output (missing --enable-jansson).\n", filename);
#endif
  }
  else {
    Log(LOG_WARNING, "WARN: [%s] Invalid bmp_dump_output value '%s'\n", filename, value_ptr);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_output = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_output'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_refresh_time(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0, i, len = strlen(value_ptr);

  for (i = 0; i < len; i++) {
    if (!isdigit(value_ptr[i]) && !isspace(value_ptr[i])) {
      Log(LOG_ERR, "WARN: [%s] 'bmp_dump_refresh_time' is expected in secs but contains non-digit chars: '%c'\n", filename, value_ptr[i]);
      return ERR;
    }
  }

  value = atoi(value_ptr);
  if (value < 60 || value > 86400) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_dump_refresh_time' value has to be >= 60 and <= 86400 secs.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_refresh_time = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_refresh_time'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_amqp_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_amqp_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_amqp_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_amqp_vhost(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_amqp_vhost = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_amqp_vhost'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_amqp_user(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_amqp_user = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_amqp_user'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_amqp_passwd(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_amqp_passwd = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_amqp_passwd'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_amqp_exchange(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_amqp_exchange = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_amqp_exchange'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_amqp_exchange_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_amqp_exchange_type = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_amqp_exchange_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_amqp_routing_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_amqp_routing_key = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_amqp_routing_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_amqp_routing_key_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'bmp_dump_amqp_routing_key_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_amqp_routing_key_rr = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_amqp_routing_key_rr'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_amqp_persistent_msg(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_amqp_persistent_msg = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_amqp_persistent_msg'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_amqp_frame_max(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'bmp_dump_amqp_frame_max' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_amqp_frame_max = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_amqp_frame_max'. Globalized.\n", filename);
  
  return changes;
}

int cfg_key_nfacctd_bmp_dump_amqp_heartbeat_interval(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_amqp_heartbeat_interval = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_amqp_heartbeat_interval'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_isis(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_isis = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'isis_daemon'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_isis_ip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_isis_ip = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'isis_daemon_ip'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_isis_net(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_isis_net = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'isis_daemon_net'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_isis_iface(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_isis_iface = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'isis_daemon_iface'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_isis_mtu(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < SNAPLEN_ISIS_MIN) {
    Log(LOG_WARNING, "WARN: [%s] 'isis_daemon_mtu' has to be >= %d.\n", filename, SNAPLEN_ISIS_MIN);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_isis_mtu = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'isis_daemon_mtu'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_isis_msglog(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_isis_msglog = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'isis_daemon_msglog'. Globalized.\n", filename);

  return changes;
}

int cfg_key_igp_daemon_map(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.igp_daemon_map = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'igp_daemon_map'. Globalized.\n", filename);

  return changes;
}

int cfg_key_igp_daemon_map_msglog(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.igp_daemon_map_msglog = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'igp_daemon_map_msglog'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_force_frag_handling(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.handle_fragments = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pmacctd_force_frag_handling'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_frag_buffer_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'pmacctd_frag_buffer_size' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.frag_bufsz = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pmacctd_frag_buffer_size'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_flow_buffer_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'pmacctd_flow_buffer_size' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.flow_bufsz = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pmacctd_flow_buffer_size'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_flow_buffer_buckets(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'flow_buffer_buckets' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.flow_hashsz = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pmacctd_flow_buffer_buckets'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_conntrack_buffer_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'pmacctd_conntrack_buffer_size' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.conntrack_bufsz = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pmacctd_conntrack_buffer_size'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_flow_lifetime(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'pmacctd_flow_lifetime' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.flow_lifetime = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pmacctd_flow_lifetime'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_flow_tcp_lifetime(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'pmacctd_flow_tcp_lifetime' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.flow_tcp_lifetime = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pmacctd_flow_tcp_lifetime'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_ext_sampling_rate(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_ERR, "WARN: [%s] 'pmacctd_ext_sampling_rate' has to be >= 1.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.ext_sampling_rate = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pmacctd_ext_sampling_rate'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pmacctd_nonroot(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.pmacctd_nonroot = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pmacctd_nonroot'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_renormalize(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_renormalize = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_renormalize'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_output(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "json")) {
#ifdef WITH_JANSSON
    value = PRINT_OUTPUT_JSON;
#else
    value = PRINT_OUTPUT_JSON;
    Log(LOG_WARNING, "WARN: [%s] sfacctd_counter_output set to json but will produce no output (missing --enable-jansson).\n", filename);
#endif
  }
  else {
    Log(LOG_WARNING, "WARN: [%s] Invalid sfacctd_counter_output value '%s'\n", filename, value_ptr);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_output = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_output'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_amqp_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_amqp_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_amqp_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_amqp_vhost(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_amqp_vhost = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_amqp_vhost'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_amqp_user(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_amqp_user = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_amqp_user'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_amqp_passwd(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_amqp_passwd = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_amqp_passwd'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_amqp_exchange(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_amqp_exchange = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_amqp_exchange'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_amqp_exchange_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_amqp_exchange_type = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_amqp_exchange_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_amqp_routing_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_amqp_routing_key = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_amqp_routing_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_amqp_persistent_msg(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_amqp_persistent_msg = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_amqp_persistent_msg'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_amqp_frame_max(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;
      
  value = strtoul(value_ptr, &endptr, 10);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'sfacctd_counter_amqp_frame_max' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_amqp_frame_max = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_amqp_frame_max'. Globalized.\n", filename);
  
  return changes;
}

int cfg_key_sfacctd_counter_amqp_heartbeat_interval(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_amqp_heartbeat_interval = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_amqp_heartbeat_interval'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_amqp_retry(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'sfacctd_counter_amqp_retry' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_amqp_retry = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_amqp_retry'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_kafka_broker_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_kafka_broker_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_kafka_broker_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_kafka_broker_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'sfacctd_counter_kafka_broker_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_kafka_broker_port = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_kafka_broker_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_kafka_topic(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_kafka_topic = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_kafka_topic'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_kafka_partition(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < -1) {
    Log(LOG_ERR, "WARN: [%s] 'sfacctd_counter_kafka_partition' has to be >= -1.\n", filename);
    return ERR;
  }

  if (!value) value = FALSE_NONZERO;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_kafka_partition = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_kafka_partition'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_kafka_partition_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value_len, changes = 0;

  value_len = strlen(value_ptr);

  for (; list; list = list->next, changes++) {
    list->cfg.sfacctd_counter_kafka_partition_key = value_ptr;
    list->cfg.sfacctd_counter_kafka_partition_keylen = value_len;
  }
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_kafka_partition_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_kafka_retry(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'sfacctd_counter_kafka_retry' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_kafka_retry = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_kafka_retry'. Globalized.\n", filename);

  return changes;
}

int cfg_key_sfacctd_counter_kafka_config_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.sfacctd_counter_kafka_config_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'sfacctd_counter_kafka_config_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_pcap_savefile(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.pcap_savefile = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'pcap_savefile'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_as_new(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "false") /* legacy */ || !strcmp(value_ptr, "netflow") || !strcmp(value_ptr, "sflow")) {
    if (config.acct_type == ACCT_NF || config.acct_type == ACCT_SF) value = NF_AS_KEEP;
    else {
      Log(LOG_ERR, "WARN: [%s] Invalid AS aggregation value '%s'\n", filename, value_ptr);
      return ERR;
    }
  }
  else if (!strcmp(value_ptr, "true") /* legacy */ || !strcmp(value_ptr, "file"))
    value = NF_AS_NEW;
  else if (!strcmp(value_ptr, "bgp") || !strcmp(value_ptr, "bmp"))
    value = NF_AS_BGP;
  else if (!strcmp(value_ptr, "fallback") || !strcmp(value_ptr, "longest")) {
    value = NF_AS_FALLBACK;

    if (config.acct_type == ACCT_NF || config.acct_type == ACCT_SF) { 
      value |= NF_AS_KEEP;
      value |= NF_AS_BGP;
    }
    else value |= NF_AS_BGP; /* NF_AS_KEEP does not apply to ACCT_PM and ACCT_UL;
			        we set value to NF_AS_BGP since we can't fallback
			        to any alternative method as of yet */
  }
  else {
    Log(LOG_ERR, "WARN: [%s] Invalid AS aggregation value '%s'\n", filename, value_ptr);
    return ERR;
  } 

  for (; list; list = list->next, changes++) list->cfg.nfacctd_as = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key '[nf|pm|sf|u]acctd_as_new'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_net(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "sflow") || !strcmp(value_ptr, "netflow")) {
    if (config.acct_type == ACCT_NF || config.acct_type == ACCT_SF) value = NF_NET_KEEP;
    else {
      Log(LOG_ERR, "WARN: [%s] Invalid network aggregation value '%s'\n", filename, value_ptr);
      return ERR;
    }
  }
  else if (!strcmp(value_ptr, "file"))
    value = NF_NET_NEW;
  else if (!strcmp(value_ptr, "mask"))
    value = NF_NET_STATIC;
  else if (!strcmp(value_ptr, "bgp") || !strcmp(value_ptr, "bmp"))
    value = NF_NET_BGP;
  else if (!strcmp(value_ptr, "igp"))
    value = NF_NET_IGP;
  else if (!strcmp(value_ptr, "fallback") || !strcmp(value_ptr, "longest")) {
    value = NF_NET_FALLBACK;

    if (config.acct_type == ACCT_NF || config.acct_type == ACCT_SF) {
      value |= NF_NET_KEEP;
      value |= NF_NET_BGP;
      value |= NF_NET_IGP;
    }
    else {
      value |= NF_NET_BGP;
      value |= NF_NET_IGP;
    }
  }
  else {
    Log(LOG_ERR, "WARN: [%s] Invalid network aggregation value '%s'\n", filename, value_ptr);
    return ERR;
  } 

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfacctd_net = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfacctd_net = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfacctd_disable_checks(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse_nonzero(value_ptr);
  if (value == ERR) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_disable_checks = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key '[ns]facctd_disable_checks'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_disable_opt_scope_check(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse_nonzero(value_ptr);
  if (value == ERR) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_disable_opt_scope_check = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'nfacctd_disable_opt_scope_check'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifiers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.classifiers_path = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'classifiers'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_tentatives(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_INFO, "INFO: [%s] 'classifier_tentatives' has to be >= 1.\n", filename);  
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.classifier_tentatives = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'classifier_tentatives'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_table_num(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_INFO, "INFO: [%s] 'classifier_table_num' has to be >= 1.\n", filename);  
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.classifier_table_num = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'classifier_table_num'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_ndpi_num_roots(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.ndpi_num_roots = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'classifier_num_roots'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_ndpi_max_flows(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;
  
  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.ndpi_max_flows = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'classifier_max_flows'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_ndpi_proto_guess(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.ndpi_proto_guess = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'classifier_proto_guess'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_ndpi_idle_scan_period(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.ndpi_idle_scan_period = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'classifier_idle_scan_period'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_ndpi_idle_max_time(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.ndpi_idle_max_time= value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'classifier_idle_max_time'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_ndpi_idle_scan_budget(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.ndpi_idle_scan_budget = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'classifier_idle_scan_budget'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_ndpi_giveup_proto_tcp(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_INFO, "INFO: [%s] 'classifier_giveup_proto_tcp' has to be >= 1.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.ndpi_giveup_proto_tcp = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'classifier_giveup_proto_tcp'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_ndpi_giveup_proto_udp(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_INFO, "INFO: [%s] 'classifier_giveup_proto_udp' has to be >= 1.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.ndpi_giveup_proto_udp = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'classifier_giveup_proto_udp'. Globalized.\n", filename);

  return changes;
}

int cfg_key_classifier_ndpi_giveup_proto_other(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list; 
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_INFO, "INFO: [%s] 'classifier_giveup_proto_other' has to be >= 1.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.ndpi_giveup_proto_other = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'classifier_giveup_proto_other'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfprobe_timeouts(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_timeouts = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.nfprobe_timeouts = value_ptr;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_hoplimit(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value < 1) || (value > 255)) {
    Log(LOG_ERR, "WARN: [%s] 'nfprobe_hoplimit' has to be in the range 1-255.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_hoplimit = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_hoplimit = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_maxflows(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_ERR, "WARN: [%s] 'nfprobe_maxflows' has to be >= 1.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_maxflows = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.nfprobe_maxflows = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_receiver(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_receiver = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_receiver = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_source_ip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_source_ip = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_source_ip = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_version(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value != 5 && value != 9 && value != 10) {
    Log(LOG_ERR, "WARN: [%s] 'nfprobe_version' has to be one of 5, 9 or 10.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_version = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_version = value;
        changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_engine(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_engine = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_engine = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_peer_as(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_peer_as = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_peer_as = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_ip_precedence(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value < 0) || (value > 7)) {
    Log(LOG_ERR, "WARN: [%s] 'nfprobe_ipprec' and 'sfprobe_ipprec' have to be in the range 0-7.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_ipprec = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.nfprobe_ipprec = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_direction(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "tag"))
    value = DIRECTION_TAG;
  else if (!strcmp(value_ptr, "tag2"))
    value = DIRECTION_TAG2;
  else if (!strcmp(value_ptr, "in"))
    value = DIRECTION_IN;
  else if (!strcmp(value_ptr, "out"))
    value = DIRECTION_OUT;
  else {
    Log(LOG_ERR, "WARN: [%s] Invalid nfprobe_direction or sfprobe_direction value '%s'\n", filename, value_ptr);
    return ERR;
  }

  if (!name) {
    Log(LOG_ERR, "ERROR: [%s] nfprobe_direction and sfprobe_direction cannot be global. Not loaded.\n", filename);
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_direction = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_ifindex(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value2 = 0;
  u_int32_t value = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "tag"))
    value2 = IFINDEX_TAG;
  else if (!strcmp(value_ptr, "tag2"))
    value2 = IFINDEX_TAG2;
  else if ((value = strtol(value_ptr, NULL, 0)))
    value2 = IFINDEX_STATIC;
  else {
    Log(LOG_ERR, "WARN: [%s] Invalid nfprobe_ifindex or sfprobe_ifindex value '%s'\n", filename, value_ptr);
    return ERR;
  }

  if (!name) {
    Log(LOG_ERR, "ERROR: [%s] nfprobe_ifindex and sfprobe_ifindex cannot be global. Not loaded.\n", filename);
    changes++;
  }
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.nfprobe_ifindex = value;
	list->cfg.nfprobe_ifindex_type = value2;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_ifindex_override(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_ifindex_override = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_ifindex_override = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_nfprobe_dont_cache(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.nfprobe_dont_cache = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.nfprobe_dont_cache = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sfprobe_receiver(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sfprobe_receiver = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sfprobe_receiver = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sfprobe_agentip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.sfprobe_agentip = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sfprobe_agentip = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sfprobe_agentsubid(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_ERR, "WARN: [%s] 'sfprobe_agentsubid' has to be >= 0.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.sfprobe_agentsubid = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.sfprobe_agentsubid = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_sfprobe_ifspeed(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;
  u_int64_t value;

  value = strtoll(value_ptr, NULL, 0);

  if (!name) for (; list; list = list->next, changes++) list->cfg.sfprobe_ifspeed = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
	list->cfg.sfprobe_ifspeed = value;
	changes++;
	break;
      }
    }
  }

  return changes;
}

int cfg_key_tee_transparent(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.tee_transparent = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.tee_transparent = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_tee_max_receivers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_WARNING, "WARN: [%s] invalid 'tee_max_receivers' value). Allowed values are >= 1.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.tee_max_receivers = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.tee_max_receivers = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_tee_max_receiver_pools(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
    Log(LOG_WARNING, "WARN: [%s] invalid 'tee_max_receiver_pools' value). Allowed values are >= 1.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.tee_max_receiver_pools = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.tee_max_receiver_pools = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_tee_receivers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.tee_receivers = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.tee_receivers = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_tee_pipe_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  value = strtoull(value_ptr, &endptr, 10);
  if (!value || value > INT_MAX) {
    Log(LOG_WARNING, "WARN: [%s] 'tee_pipe_size' has to be > 0 and <= INT_MAX.\n", filename);
    return ERR;
  }

  if (!name) for (; list; list = list->next, changes++) list->cfg.tee_pipe_size = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.tee_pipe_size = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_tee_kafka_config_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.tee_kafka_config_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.tee_kafka_config_file = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

void parse_time(char *filename, char *value, int *mu, int *howmany)
{
  int k, j, len;

  *mu = 0;
  *howmany = 0;

  len = strlen(value);
  for (j = 0; j < len; j++) {
    if (!isdigit(value[j])) {
      if (value[j] == 's') *mu = COUNT_SECONDLY;
      else if (value[j] == 'm') *mu = COUNT_MINUTELY;
      else if (value[j] == 'h') *mu = COUNT_HOURLY;
      else if (value[j] == 'd') *mu = COUNT_DAILY;
      else if (value[j] == 'w') *mu = COUNT_WEEKLY;
      else if (value[j] == 'M') *mu = COUNT_MONTHLY;
      else {
        Log(LOG_WARNING, "WARN: [%s] Ignoring unknown time measuring unit: '%c'.\n", filename, value[j]);
        *mu = 0;
        *howmany = 0;
        return;
      }
      if (*mu) {
        value[j] = '\0';
        break;
      }
    }
  }

  /* if no measurement unit given, assume it's seconds */
  if (!(*mu)) *mu = COUNT_SECONDLY;

  k = atoi(value);
  if (k > 0) {
    if (*mu == COUNT_SECONDLY) {
      if (k % 60) {
        Log(LOG_WARNING, "WARN: [%s] Ignoring invalid time value: %d (residual secs afters conversion in mins)\n", filename, k);
	goto exit_lane;
      }
      else {
	k = k / 60;
	*mu = COUNT_MINUTELY;
      }
    }
    *howmany = k;
  }
  else {
    Log(LOG_WARNING, "WARN: [%s] Ignoring invalid time value: %d (not greater than zero)\n", filename, k);
    goto exit_lane;
  }

  return;

exit_lane:
  *mu = 0;
  *howmany = 0;
}

int cfg_key_uacctd_group(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 0 || value > 65535) return ERR;

  for (; list; list = list->next, changes++) list->cfg.uacctd_group = value;
  return changes;
}

int cfg_key_uacctd_nl_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);

  for (; list; list = list->next, changes++) list->cfg.uacctd_nl_size = value;
  return changes;
}

int cfg_key_uacctd_threshold(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);

  for (; list; list = list->next, changes++) list->cfg.uacctd_threshold = value;
  return changes;
}

int cfg_key_tunnel_0(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  trim_all_spaces(value_ptr);

  for (; list; list = list->next, changes++) list->cfg.tunnel0 = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'tunnel_0'. Globalized.\n", filename);

  return changes;
}

#if defined WITH_GEOIP
int cfg_key_geoip_ipv4_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.geoip_ipv4_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'geoip_ipv4_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_geoip_ipv6_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.geoip_ipv6_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'geoip_ipv6_file'. Globalized.\n", filename);

  return changes;
}
#endif

#if defined WITH_GEOIPV2
int cfg_key_geoipv2_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.geoipv2_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'geoipv2_file'. Globalized.\n", filename);

  return changes;
}
#endif

void cfg_set_aggregate(char *filename, u_int64_t registry[], u_int64_t input, char *token)
{
  u_int64_t index = (input >> COUNT_REGISTRY_BITS) & COUNT_INDEX_MASK;
  u_int64_t value = (input & COUNT_REGISTRY_MASK);

  if (registry[index] & value) {
    Log(LOG_ERR, "ERROR: [%s] '%s' repeated in 'aggregate' or invalid 0x%llx bit code.\n", filename, token, (unsigned long long)input);
    exit(1);
  }
  else registry[index] |= value;
}

int cfg_key_nfacctd_bgp_msglog_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_output(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "json")) {
#ifdef WITH_JANSSON
    value = PRINT_OUTPUT_JSON;
#else
    value = PRINT_OUTPUT_JSON;
    Log(LOG_WARNING, "WARN: [%s] bgp_daemon_msglog_output set to json but will produce no output (missing --enable-jansson).\n", filename);
#endif
  }
  else if (!strcmp(value_ptr, "avro")) {
#ifdef WITH_AVRO
    value = PRINT_OUTPUT_AVRO;
#else
    value = PRINT_OUTPUT_AVRO;
    Log(LOG_WARNING, "WARN: [%s] bgp_daemon_msglog_output set to avro but will produce no output (missing --enable-avro).\n", filename);
#endif
  }
  else {
    Log(LOG_WARNING, "WARN: [%s] Invalid bgp_daemon_msglog_output value '%s'\n", filename, value_ptr);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_output = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_output'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_amqp_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_amqp_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_amqp_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_amqp_vhost(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_amqp_vhost = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_amqp_vhost'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_amqp_user(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_amqp_user = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_amqp_user'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_amqp_passwd(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_amqp_passwd = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_amqp_passwd'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_amqp_exchange(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_amqp_exchange = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_amqp_exchange'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_amqp_exchange_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_amqp_exchange_type = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_amqp_exchange_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_amqp_routing_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_amqp_routing_key = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_amqp_routing_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_amqp_routing_key_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'bgp_daemon_msglog_amqp_routing_key_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_amqp_routing_key_rr = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_amqp_routing_key_rr'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_amqp_persistent_msg(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_amqp_persistent_msg = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_amqp_persistent_msg'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_amqp_frame_max(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;
      
  value = strtoul(value_ptr, &endptr, 10);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'bgp_daemon_msglog_amqp_frame_max' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_amqp_frame_max = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_amqp_frame_max'. Globalized.\n", filename);
  
  return changes;
}

int cfg_key_nfacctd_bgp_msglog_amqp_heartbeat_interval(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_amqp_heartbeat_interval = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_amqp_heartbeat_interval'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_amqp_retry(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_daemon_msglog_amqp_retry' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_amqp_retry = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_amqp_retry'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_latest_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_latest_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_latest_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_output(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "json")) {
#ifdef WITH_JANSSON
    value = PRINT_OUTPUT_JSON;
#else
    value = PRINT_OUTPUT_JSON;
    Log(LOG_WARNING, "WARN: [%s] bgp_table_dump_output set to json but will produce no output (missing --enable-jansson).\n", filename);
#endif
  }
  else if (!strcmp(value_ptr, "avro")) {
#ifdef WITH_AVRO
    value = PRINT_OUTPUT_AVRO;
#else
    value = PRINT_OUTPUT_AVRO;
    Log(LOG_WARNING, "WARN: [%s] bgp_table_dump_output set to avro but will produce no output (missing --enable-avro).\n", filename);
#endif
  }
  else {
    Log(LOG_WARNING, "WARN: [%s] Invalid bgp_table_dump_output value '%s'\n", filename, value_ptr);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_output = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_output'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_refresh_time(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0, i, len = strlen(value_ptr);

  for (i = 0; i < len; i++) {
    if (!isdigit(value_ptr[i]) && !isspace(value_ptr[i])) {
      Log(LOG_ERR, "WARN: [%s] 'bgp_table_dump_refresh_time' is expected in secs but contains non-digit chars: '%c'\n", filename, value_ptr[i]);
      return ERR;
    }
  }

  value = atoi(value_ptr);
  if (value < 60 || value > 86400) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_table_dump_refresh_time' value has to be >= 60 and <= 86400 secs.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_refresh_time = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_refresh_time'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_amqp_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_amqp_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_amqp_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_amqp_vhost(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_amqp_vhost = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_amqp_vhost'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_amqp_user(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_amqp_user = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_amqp_user'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_amqp_passwd(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_amqp_passwd = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_amqp_passwd'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_amqp_exchange(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_amqp_exchange = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_amqp_exchange'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_amqp_exchange_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_amqp_exchange_type = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_amqp_exchange_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_amqp_routing_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_amqp_routing_key = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_amqp_routing_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_amqp_routing_key_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'bgp_table_dump_amqp_routing_key_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_amqp_routing_key_rr = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_amqp_routing_key_rr'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_amqp_persistent_msg(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_amqp_persistent_msg = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_amqp_persistent_msg'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_amqp_frame_max(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'bgp_table_dump_amqp_frame_max' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_amqp_frame_max = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_amqp_frame_max'. Globalized.\n", filename);
  
  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_amqp_heartbeat_interval(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_amqp_heartbeat_interval = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_amqp_heartbeat_interval'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_kafka_broker_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_kafka_broker_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_kafka_broker_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_kafka_broker_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_daemon_msglog_kafka_broker_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_kafka_broker_port = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_kafka_broker_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_kafka_topic(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_kafka_topic = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_kafka_topic'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_kafka_topic_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'bgp_daemon_msglog_kafka_topic_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_kafka_topic_rr = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_kafka_topic_rr'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_kafka_partition(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < -1) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_daemon_msglog_kafka_partition' has to be >= -1.\n", filename);
    return ERR;
  }

  if (!value) value = FALSE_NONZERO;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_kafka_partition = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_kafka_partition'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_kafka_partition_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value_len, changes = 0;

  value_len = strlen(value_ptr);

  for (; list; list = list->next, changes++) {
    list->cfg.nfacctd_bgp_msglog_kafka_partition_key = value_ptr;
    list->cfg.nfacctd_bgp_msglog_kafka_partition_keylen = value_len;
  }
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_kafka_partition_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_kafka_retry(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_daemon_msglog_kafka_retry' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_kafka_retry = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_kafka_retry'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_msglog_kafka_config_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;
  
  for (; list; list = list->next, changes++) list->cfg.nfacctd_bgp_msglog_kafka_config_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_daemon_msglog_kafka_config_file'. Globalized.\n", filename);
  
  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_kafka_broker_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_kafka_broker_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_kafka_broker_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_kafka_broker_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_daemon_msglog_kafka_broker_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_kafka_broker_port = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_kafka_broker_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_kafka_topic(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_kafka_topic = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_kafka_topic'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_kafka_topic_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'bgp_table_dump_kafka_topic_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_kafka_topic_rr = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_kafka_topic_rr'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_kafka_partition(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < -1) {
    Log(LOG_ERR, "WARN: [%s] 'bgp_table_dump_kafka_partition' has to be >= -1.\n", filename);
    return ERR;
  }

  if (!value) value = FALSE_NONZERO;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_kafka_partition = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_kafka_partition'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_kafka_partition_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value_len, changes = 0;

  value_len = strlen(value_ptr);

  for (; list; list = list->next, changes++) {
    list->cfg.bgp_table_dump_kafka_partition_key = value_ptr;
    list->cfg.bgp_table_dump_kafka_partition_keylen = value_len;
  }
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_kafka_partition_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bgp_table_dump_kafka_config_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bgp_table_dump_kafka_config_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bgp_table_dump_kafka_config_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_kafka_broker_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_kafka_broker_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_kafka_broker_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_kafka_broker_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_daemon_msglog_kafka_broker_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_kafka_broker_port = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_kafka_broker_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_kafka_topic(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_kafka_topic = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_kafka_topic'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_kafka_topic_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'bmp_daemon_msglog_kafka_topic_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_kafka_topic_rr = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_kafka_topic_rr'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_kafka_partition(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < -1) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_daemon_msglog_kafka_partition' has to be >= -1.\n", filename);
    return ERR;
  }

  if (!value) value = FALSE_NONZERO;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_kafka_partition = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_kafka_partition'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_kafka_partition_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value_len, changes = 0;

  value_len = strlen(value_ptr);

  for (; list; list = list->next, changes++) {
    list->cfg.nfacctd_bmp_msglog_kafka_partition_key = value_ptr;
    list->cfg.nfacctd_bmp_msglog_kafka_partition_keylen = value_len;
  }
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_kafka_partition_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_kafka_retry(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_daemon_msglog_kafka_retry' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_kafka_retry = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_kafka_retry'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_msglog_kafka_config_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.nfacctd_bmp_msglog_kafka_config_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_daemon_msglog_kafka_config_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_kafka_broker_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_kafka_broker_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_kafka_broker_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_kafka_broker_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_daemon_msglog_kafka_broker_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_kafka_broker_port = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_kafka_broker_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_kafka_topic(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_kafka_topic = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_kafka_topic'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_kafka_topic_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'bmp_dump_kafka_topic_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_kafka_topic_rr = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_kafka_topic_rr'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_kafka_partition(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < -1) {
    Log(LOG_ERR, "WARN: [%s] 'bmp_dump_kafka_partition' has to be >= -1.\n", filename);
    return ERR;
  }

  if (!value) value = FALSE_NONZERO;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_kafka_partition = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_kafka_partition'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_kafka_partition_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value_len, changes = 0;

  value_len = strlen(value_ptr);

  for (; list; list = list->next, changes++) {
    list->cfg.bmp_dump_kafka_partition_key = value_ptr;
    list->cfg.bmp_dump_kafka_partition_keylen = value_len;
  }
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_kafka_partition_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_nfacctd_bmp_dump_kafka_config_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.bmp_dump_kafka_config_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'bmp_dump_kafka_config_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_tmp_asa_bi_flow(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  if (!name) for (; list; list = list->next, changes++) list->cfg.tmp_asa_bi_flow = value;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.tmp_asa_bi_flow = value;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_tmp_bgp_lookup_compare_ports(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.tmp_bgp_lookup_compare_ports = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'tmp_bgp_lookup_compare_ports'. Globalized.\n", filename);

  return changes;
}

int cfg_key_thread_stack(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'thread_stack' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.thread_stack = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'thread_stack'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_daemon(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.telemetry_daemon = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_port_tcp(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'telemetry_daemon_port_tcp' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_port_tcp = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_port_tcp'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_port_udp(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'telemetry_daemon_port_udp' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_port_udp = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_port_udp'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_ip(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_ip = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_ip'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_zmq_address(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_zmq_address = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_zmq_address'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_decoder(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_decoder = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_decoder'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_allow_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_allow_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_allow_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_pipe_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  value = strtoull(value_ptr, &endptr, 10);
  if (!value || value > INT_MAX) {
    Log(LOG_WARNING, "WARN: [%s] 'telemetry_daemon_pipe_size' has to be > 0 and <= INT_MAX.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_pipe_size = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_pipe_size'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_ip_precedence(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value < 0) || (value > 7)) {
    Log(LOG_ERR, "WARN: [%s] 'telemetry_daemon_ipprec' has to be in the range 0-7.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_ipprec = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_ipprec'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_max_peers(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 1) {
        Log(LOG_ERR, "WARN: [%s] 'telemetry_daemon_max_peers' has to be >= 1.\n", filename);
        return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_max_peers = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_max_peers'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_peer_timeout(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < 60) {
        Log(LOG_ERR, "WARN: [%s] 'telemetry_daemon_peer_timeout' has to be >= 60.\n", filename);
        return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_peer_timeout = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_peer_timeout'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_output(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "json")) {
#ifdef WITH_JANSSON
    value = PRINT_OUTPUT_JSON;
#else
    value = PRINT_OUTPUT_JSON;
    Log(LOG_WARNING, "WARN: [%s] telemetry_daemon_msglog_output set to json but will produce no output (missing --enable-jansson).\n", filename);
#endif
  }
  else {
    Log(LOG_WARNING, "WARN: [%s] Invalid telemetry_daemon_msglog_output value '%s'\n", filename, value_ptr);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_output = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_output'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_amqp_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_amqp_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_amqp_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_amqp_vhost(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_amqp_vhost = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_amqp_vhost'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_amqp_user(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_amqp_user = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_amqp_user'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_amqp_passwd(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_amqp_passwd = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_amqp_passwd'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_amqp_exchange(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_amqp_exchange = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_amqp_exchange'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_amqp_exchange_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_amqp_exchange_type = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_amqp_exchange_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_amqp_routing_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_amqp_routing_key = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_amqp_routing_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_amqp_routing_key_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'telemetry_daemon_msglog_amqp_routing_key_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_amqp_routing_key_rr = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_amqp_routing_key_rr'. Globalized.\n", filename); 

  return changes;
}

int cfg_key_telemetry_msglog_amqp_persistent_msg(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_amqp_persistent_msg = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_amqp_persistent_msg'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_amqp_frame_max(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;
      
  value = strtoul(value_ptr, &endptr, 10);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'telemetry_daemon_msglog_amqp_frame_max' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_amqp_frame_max = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_amqp_frame_max'. Globalized.\n", filename);
  
  return changes;
}

int cfg_key_telemetry_msglog_amqp_heartbeat_interval(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_amqp_heartbeat_interval = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_amqp_heartbeat_interval'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_amqp_retry(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'telemetry_daemon_msglog_amqp_retry' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_amqp_retry = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_amqp_retry'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_latest_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_latest_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_latest_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_output(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  lower_string(value_ptr);
  if (!strcmp(value_ptr, "json")) {
#ifdef WITH_JANSSON
    value = PRINT_OUTPUT_JSON;
#else
    value = PRINT_OUTPUT_JSON;
    Log(LOG_WARNING, "WARN: [%s] telemetry_dump_output set to json but will produce no output (missing --enable-jansson).\n", filename);
#endif
  }
  else {
    Log(LOG_WARNING, "WARN: [%s] Invalid telemetry_dump_output value '%s'\n", filename, value_ptr);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_output = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_output'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_refresh_time(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0, i, len = strlen(value_ptr);

  for (i = 0; i < len; i++) {
    if (!isdigit(value_ptr[i]) && !isspace(value_ptr[i])) {
      Log(LOG_ERR, "WARN: [%s] 'telemetry_dump_refresh_time' is expected in secs but contains non-digit chars: '%c'\n", filename, value_ptr[i]);
      return ERR;
    }
  }

  value = atoi(value_ptr);
  if (value < 10 || value > 86400) {
    Log(LOG_ERR, "WARN: [%s] 'telemetry_dump_refresh_time' value has to be >= 10 and <= 86400 secs.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_refresh_time = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_refresh_time'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_amqp_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_amqp_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_amqp_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_amqp_vhost(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_amqp_vhost = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_amqp_vhost'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_amqp_user(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_amqp_user = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_amqp_user'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_amqp_passwd(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_amqp_passwd = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_amqp_passwd'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_amqp_exchange(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_amqp_exchange = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_amqp_exchange'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_amqp_exchange_type(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_amqp_exchange_type = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_amqp_exchange_type'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_amqp_routing_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_amqp_routing_key = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_amqp_routing_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_amqp_routing_key_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'telemetry_dump_amqp_routing_key_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_amqp_routing_key_rr = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_amqp_routing_key_rr'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_amqp_persistent_msg(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = parse_truefalse(value_ptr);
  if (value < 0) return ERR;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_amqp_persistent_msg = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_amqp_persistent_msg'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_amqp_frame_max(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);
  if (value <= 0) {
    Log(LOG_WARNING, "WARN: [%s] 'telemetry_dump_amqp_frame_max' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_amqp_frame_max = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_amqp_frame_max'. Globalized.\n", filename);
  
  return changes;
}

int cfg_key_telemetry_dump_amqp_heartbeat_interval(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int32_t value, changes = 0;
  char *endptr;

  value = strtoul(value_ptr, &endptr, 10);

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_amqp_heartbeat_interval = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_amqp_heartbeat_interval'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_kafka_broker_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_kafka_broker_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_kafka_broker_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_kafka_broker_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'telemetry_daemon_msglog_kafka_broker_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_kafka_broker_port = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_kafka_broker_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_kafka_topic(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_kafka_topic = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_kafka_topic'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_kafka_topic_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'telemetry_daemon_msglog_kafka_topic_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_kafka_topic_rr = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_kafka_topic_rr'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_kafka_partition(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < -1) {
    Log(LOG_ERR, "WARN: [%s] 'telemetry_daemon_msglog_kafka_partition' has to be >= -1.\n", filename);
    return ERR;
  }

  if (!value) value = FALSE_NONZERO;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_kafka_partition = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_kafka_partition'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_kafka_partition_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value_len, changes = 0;

  value_len = strlen(value_ptr);

  for (; list; list = list->next, changes++) {
    list->cfg.telemetry_msglog_kafka_partition_key = value_ptr;
    list->cfg.telemetry_msglog_kafka_partition_keylen = value_len;
  }
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_kafka_partition_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_kafka_retry(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value <= 0) {
    Log(LOG_ERR, "WARN: [%s] 'telemetry_daemon_msglog_kafka_retry' has to be > 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_kafka_retry = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_kafka_retry'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_msglog_kafka_config_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_msglog_kafka_config_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_daemon_msglog_kafka_config_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_kafka_broker_host(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_kafka_broker_host = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_kafka_broker_host'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_kafka_broker_port(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value <= 0) || (value > 65535)) {
    Log(LOG_ERR, "WARN: [%s] 'telemetry_daemon_msglog_kafka_broker_port' has to be in the range 1-65535.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_kafka_broker_port = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_kafka_broker_port'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_kafka_topic(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_kafka_topic = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_kafka_topic'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_kafka_topic_rr(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0, value = 0;

  value = atoi(value_ptr);
  if (value < 0) {
    Log(LOG_WARNING, "WARN: [%s] 'telemetry_dump_kafka_topic_rr' has to be >= 0.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_kafka_topic_rr = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_kafka_topic_rr'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_kafka_partition(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if (value < -1) {
    Log(LOG_ERR, "WARN: [%s] 'telemetry_dump_kafka_partition' has to be >= -1.\n", filename);
    return ERR;
  }

  if (!value) value = FALSE_NONZERO;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_kafka_partition = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_kafka_partition'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_kafka_partition_key(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value_len, changes = 0;

  value_len = strlen(value_ptr);

  for (; list; list = list->next, changes++) {
    list->cfg.telemetry_dump_kafka_partition_key = value_ptr;
    list->cfg.telemetry_dump_kafka_partition_keylen = value_len;
  }
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_kafka_partition_key'. Globalized.\n", filename);

  return changes;
}

int cfg_key_telemetry_dump_kafka_config_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.telemetry_dump_kafka_config_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'telemetry_dump_kafka_config_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_rpki_roas_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.rpki_roas_file = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'rpki_roas_file'. Globalized.\n", filename);

  return changes;
}

int cfg_key_rpki_rtr_cache(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  for (; list; list = list->next, changes++) list->cfg.rpki_rtr_cache = value_ptr;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'rpki_rtr_cache'. Globalized.\n", filename);

  return changes;
}

int cfg_key_rpki_rtr_cache_version(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);

  for (; list; list = list->next, changes++) list->cfg.rpki_rtr_cache_version = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'rpki_rtr_cache_version'. Globalized.\n", filename);

  return changes;
}

int cfg_key_rpki_rtr_cache_pipe_size(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  u_int64_t value, changes = 0;
  char *endptr;

  value = strtoull(value_ptr, &endptr, 10);
  if (!value || value > INT_MAX) {
    Log(LOG_WARNING, "WARN: [%s] 'rpki_rtr_cache_pipe_size' has to be > 0 and <= INT_MAX.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.rpki_rtr_cache_pipe_size = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'rpki_rtr_cache_pipe_size'. Globalized.\n", filename);

  return changes;
}

int cfg_key_rpki_rtr_cache_ip_precedence(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int value, changes = 0;

  value = atoi(value_ptr);
  if ((value < 0) || (value > 7)) {
    Log(LOG_ERR, "WARN: [%s] 'rpki_rtr_cache_ipprec' has to be in the range 0-7.\n", filename);
    return ERR;
  }

  for (; list; list = list->next, changes++) list->cfg.rpki_rtr_cache_ipprec = value;
  if (name) Log(LOG_WARNING, "WARN: [%s] plugin name not supported for key 'rpki_rtr_cache_ipprec'. Globalized.\n", filename);

  return changes;
}

int cfg_key_print_output_custom_lib(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_output_custom_lib = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_output_custom_lib = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}

int cfg_key_print_output_custom_cfg_file(char *filename, char *name, char *value_ptr)
{
  struct plugins_list_entry *list = plugins_list;
  int changes = 0;

  if (!name) for (; list; list = list->next, changes++) list->cfg.print_output_custom_cfg_file = value_ptr;
  else {
    for (; list; list = list->next) {
      if (!strcmp(name, list->name)) {
        list->cfg.print_output_custom_cfg_file = value_ptr;
        changes++;
        break;
      }
    }
  }

  return changes;
}
