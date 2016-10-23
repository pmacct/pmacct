/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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

#define __PRETAG_HANDLERS_C

#include "pmacct.h"
#include "addr.h"
#include "bgp/bgp_packet.h"
#include "bgp/bgp.h"
#include "nfacctd.h"
#include "sflow.h"
#include "sfacctd.h"
#include "pretag_handlers.h"
#include "net_aggr.h"
#include "bgp/bgp.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "util.h"

int PT_map_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct host_addr a;
  char *endptr = NULL, *incptr;
  pm_id_t j = 0, z = 0;
  int x, inc = 0;

  e->id = 0;
  e->flags = FALSE;

  /* If we parse a bgp_agent_map and spot a '.' within the string let's
     check if we are given a valid IPv4 address */
  if (acct_type == MAP_BGP_TO_XFLOW_AGENT && strchr(value, '.')) {
    memset(&a, 0, sizeof(a));
    str_to_addr(value, &a);
    if (a.family == AF_INET) j = a.address.ipv4.s_addr;
    else {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] ID does not appear to be a valid IPv4 address.\n", config.name, config.type, filename);
      return TRUE;
    }
  }
  /* If we parse a bgp_agent_map and spot a ':' within the string let's
     check if we are given a valid IPv6 address */
#if defined ENABLE_IPV6
  else if (acct_type == MAP_BGP_TO_XFLOW_AGENT && strchr(value, ':')) {
    memset(&a, 0, sizeof(a));
    str_to_addr(value, &a);
    if (a.family == AF_INET6) {
      ip6_addr_32bit_cpy(&j, &a.address.ipv6, 0, 0, 1);
      ip6_addr_32bit_cpy(&z, &a.address.ipv6, 0, 2, 3);

      e->flags = BTA_MAP_RCODE_ID_ID2;
    }
    else {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] ID does not appear to be a valid IPv6 address.\n", config.name, config.type, filename);
      return TRUE;
    }
  }
#endif
  else if (acct_type == MAP_FLOW_TO_RD && strchr(value, ':')) {
    rd_t rd;

    bgp_str2rd(&rd, value);
    memcpy(&j, &rd, sizeof(rd));
  }
  /* If we spot the word "bgp", let's check this is a map that supports it */
  else if ((acct_type == MAP_BGP_PEER_AS_SRC || acct_type == MAP_BGP_SRC_LOCAL_PREF ||
	   acct_type == MAP_BGP_SRC_MED) && !strncmp(value, "bgp", strlen("bgp"))) {
    e->flags = BPAS_MAP_RCODE_BGP;
  }
  else {
    if (incptr = strstr(value, "++")) {
      inc = TRUE;
      *incptr = '\0';
    }

    j = strtoull(value, &endptr, 10);
    if (j > UINT64_MAX) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid set_tag/id specified.\n", config.name, config.type, filename);
      return TRUE;
    } 
  }

  e->id = j; 
  if (z) e->id2 = z;
  if (inc) e->id_inc = TRUE;

  if (acct_type == ACCT_NF || acct_type == ACCT_SF || acct_type == ACCT_PM) {
    for (x = 0; e->set_func[x]; x++) {
      if (e->set_func_type[x] == PRETAG_SET_TAG) {
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'set_tag' (id) clauses part of the same statement.\n", config.name, config.type, filename);
        return TRUE;
      }
    }

    e->set_func[x] = pretag_id_handler;
    e->set_func_type[x] = PRETAG_SET_TAG;
  }

  return FALSE;
}

int PT_map_id2_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  char *endptr = NULL, *incptr;
  pm_id_t j;
  int x, inc = 0;

  if (incptr = strstr(value, "++")) {
    inc = TRUE;
    *incptr = '\0';
  }

  j = strtoull(value, &endptr, 10);
  if (j > UINT64_MAX) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid set_tag2/id2 specified.\n", config.name, config.type, filename);
    return TRUE;
  }
  e->id2 = j;
  if (inc) e->id2_inc = TRUE;

  if (acct_type == ACCT_NF || acct_type == ACCT_SF || acct_type == ACCT_PM) {
    for (x = 0; e->set_func[x]; x++) {
      if (e->set_func_type[x] == PRETAG_SET_TAG2) {
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'set_tag2' (id2) clauses part of the same statement.\n", config.name, config.type, filename);
        return TRUE;
      }
    }

    e->set_func[x] = pretag_id2_handler;
    e->set_func_type[x] = PRETAG_SET_TAG2;
  }

  return FALSE;
}

int PT_map_label_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  char default_sep = ',';
  int x, len;

  // XXX: isprint check?

  len = strlen(value);
  if (!strchr(value, default_sep)) {
    if (pretag_malloc_label(&e->label, len + 1 /* null */)) return TRUE;
    strcpy(e->label.val, value);
    e->label.val[e->label.len] = '\0';
  }
  else {
    e->label.val = NULL;
    e->label.len = 0;

    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid set_label specified.\n", config.name, config.type, filename);
    return TRUE;
  }

  if (acct_type == ACCT_NF || acct_type == ACCT_SF || acct_type == ACCT_PM) {
    for (x = 0; e->set_func[x]; x++) {
      if (e->set_func_type[x] == PRETAG_SET_LABEL) {
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'set_label' clauses part of the same statement.\n", config.name, config.type, filename);
        return TRUE;
      }
    }

    e->set_func[x] = pretag_label_handler;
    e->set_func_type[x] = PRETAG_SET_LABEL;
  }

  return FALSE;
}

int PT_map_ip_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0;

  if (!str_to_addr_mask(value, &e->key.agent_ip.a, &e->key.agent_mask)) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Bad IP address or prefix '%s'.\n", config.name, config.type, filename, value);
    return TRUE;
  }

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_IP) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'ip' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  e->func[x] = pretag_dummy_ip_handler; 
  if (e->func[x]) e->func_type[x] = PRETAG_IP;

  return FALSE;
}

int PT_map_input_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, len;
  char *endptr;

  if (acct_type == MAP_SAMPLING) sampling_map_caching = FALSE;
  if (acct_type == MAP_BGP_TO_XFLOW_AGENT) bta_map_caching = FALSE; 
  if (req->ptm_c.load_ptm_plugin == PLUGIN_ID_TEE) req->ptm_c.load_ptm_res = TRUE;

  e->key.input.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] bad 'in' value: '%s'.\n", config.name, config.type, filename, value);
      return TRUE;
    }
    x++;
  }
  
  e->key.input.n = strtoul(value, &endptr, 10);
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_IN_IFACE) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'input' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_input_handler; 
  else if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_input_handler; 
  else if (config.acct_type == ACCT_PM) e->func[x] = PM_pretag_input_handler; 
  if (e->func[x]) e->func_type[x] = PRETAG_IN_IFACE;

  return FALSE;
}

int PT_map_output_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, len;
  char *endptr;

  if (acct_type == MAP_SAMPLING) sampling_map_caching = FALSE;
  if (acct_type == MAP_BGP_TO_XFLOW_AGENT) bta_map_caching = FALSE; 
  if (req->ptm_c.load_ptm_plugin == PLUGIN_ID_TEE) req->ptm_c.load_ptm_res = TRUE;

  e->key.output.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] bad 'out' value: '%s'.\n", config.name, config.type, filename, value);
      return TRUE;
    }
    x++;
  }

  e->key.output.n = strtoul(value, &endptr, 10);
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_OUT_IFACE) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'output' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_output_handler;
  else if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_output_handler;
  else if (config.acct_type == ACCT_PM) e->func[x] = PM_pretag_output_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_OUT_IFACE;

  return FALSE;
}

int PT_map_nexthop_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0;

  e->key.nexthop.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  if (!str_to_addr(value, &e->key.nexthop.a)) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Bad nexthop address '%s'.\n", config.name, config.type, filename, value);
    return TRUE;
  }

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_NEXTHOP) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'nexthop' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_nexthop_handler;
  else if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_nexthop_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_NEXTHOP;

  return FALSE;
}

int PT_map_bgp_nexthop_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, have_bgp = 0;

  e->key.bgp_nexthop.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  if (!str_to_addr(value, &e->key.bgp_nexthop.a)) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Bad BGP nexthop address '%s'.\n", config.name, config.type, filename, value);
    return TRUE;
  }

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_BGP_NEXTHOP) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'bgp_nexthop' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.nfacctd_net & NF_NET_BGP) {
    e->func[x] = pretag_bgp_bgp_nexthop_handler;
    have_bgp = TRUE;
    e->func_type[x] = PRETAG_BGP_NEXTHOP;
    x++;
  }

  /* XXX: IGP? */

  if (config.nfacctd_net & NF_NET_KEEP && config.acct_type == ACCT_NF) {
    e->func[x] = pretag_bgp_nexthop_handler;
    e->func_type[x] = PRETAG_BGP_NEXTHOP;
    return FALSE;
  }
  else if (config.nfacctd_net & NF_NET_KEEP && config.acct_type == ACCT_SF) {
    e->func[x] = SF_pretag_bgp_nexthop_handler;
    e->func_type[x] = PRETAG_BGP_NEXTHOP;
    return FALSE;
  }

  if (have_bgp) return FALSE;

  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'bgp_nexthop' is not supported when a 'networks_file' is specified or by the 'pmacctd' daemon.\n", config.name, config.type, filename);

  return TRUE;
}

int BPAS_map_bgp_nexthop_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0;

  e->key.bgp_nexthop.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  if (!str_to_addr(value, &e->key.bgp_nexthop.a)) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Bad BGP nexthop address '%s'.\n", config.name, config.type, filename, value);
    return TRUE;
  }

  for (x = 0; e->func[x]; x++);
  if (config.nfacctd_bgp) {
    e->func[x] = BPAS_bgp_nexthop_handler;
    e->func_type[x] = PRETAG_BGP_NEXTHOP;
  }

  return FALSE;
}

int BPAS_map_bgp_peer_dst_as_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  as_t tmp;
  int x = 0;
  char *endptr;

  e->key.peer_dst_as.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  tmp = strtoul(value, &endptr, 10);
  e->key.peer_dst_as.n = tmp;

  for (x = 0; e->func[x]; x++);
  if (config.nfacctd_bgp) {
    e->func[x] = BPAS_bgp_peer_dst_as_handler; 
    e->func_type[x] = PRETAG_BGP_NEXTHOP;
  }

  return FALSE;
}

int BITR_map_mpls_label_bottom_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  as_t tmp;
  int x = 0;
  char *endptr;

  e->key.mpls_label_bottom.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  tmp = strtoul(value, &endptr, 10);
  e->key.mpls_label_bottom.n = tmp;

  for (x = 0; e->func[x]; x++);

  /* Currently supported only in nfacctd */
  if (config.acct_type == ACCT_NF) e->func[x] = BITR_mpls_label_bottom_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_MPLS_LABEL_BOTTOM;

  return FALSE;
}

int PT_map_engine_type_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, j, len;

  e->key.engine_type.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] bad 'engine_type' value: '%s'.\n", config.name, config.type, filename, value);
      return TRUE;
    }
    x++;
  }

  j = atoi(value);
  if (j > 255) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] bad 'engine_type' value (range: 0 >= value > 256).\n", config.name, config.type, filename);
    return TRUE;
  }
  e->key.engine_type.n = j; 

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_ENGINE_TYPE) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'engine_type' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_engine_type_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_ENGINE_TYPE;

  return FALSE;
}

int PT_map_engine_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, j, len;

  e->key.engine_id.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] bad 'engine_id' value: '%s'.\n", config.name, config.type, filename, value);
      return TRUE;
    }
    x++;
  }

  j = atoi(value);
  if (j > 255) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] bad 'engine_id' value (range: 0 >= value > 256).\n", config.name, config.type, filename);
    return TRUE;
  }
  e->key.engine_id.n = j;

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_ENGINE_ID) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'engine_id' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.acct_type == ACCT_NF) e->func[x] = pretag_engine_id_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_ENGINE_ID;

  return FALSE;
}

int PT_map_filter_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct pcap_device device;
  bpf_u_int32 localnet, netmask;  /* pcap library stuff */
  char errbuf[PCAP_ERRBUF_SIZE];
  int x, link_type;

  if (acct_type == MAP_BGP_TO_XFLOW_AGENT) {
    if (strncmp(value, "ip", 2) && strncmp(value, "ip6", 3)) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] bgp_agent_map filter supports only 'ip' and 'ip6' keywords\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  memset(&device, 0, sizeof(struct pcap_device));
  if (glob_pcapt) device.link_type = pcap_datalink(glob_pcapt);
  else if (config.uacctd_group) device.link_type = DLT_RAW;
  else device.link_type = 1;
  device.dev_desc = pcap_open_dead(device.link_type, 128); /* snaplen=eth_header+my_iphdr+my_tlhdr */

  pcap_lookupnet(config.dev, &localnet, &netmask, errbuf);
  if (pcap_compile(device.dev_desc, &e->key.filter, value, 0, netmask) < 0) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] malformed filter: %s\n", config.name, config.type, filename, pcap_geterr(device.dev_desc));
    return TRUE;
  }

  pcap_close(device.dev_desc);

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_FILTER) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'filter' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  e->func[x] = pretag_filter_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_FILTER;
  req->bpf_filter = TRUE;
  return FALSE;
}

int PT_map_v8agg_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int tmp, x = 0, len;

  e->key.v8agg.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] bad 'v8agg' value: '%s'.\n", config.name, config.type, filename, value);
      return TRUE;
    }
    x++;
  }

  tmp = atoi(value);
  if (tmp < 1 || tmp > 14) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'v8agg' need to be in the following range: 0 > value > 15.\n", config.name, config.type, filename);
    return TRUE;
  }
  e->key.v8agg.n = tmp; 

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_NFV8_AGG) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'v8agg' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.acct_type == ACCT_NF) e->func[x] = pretag_v8agg_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_NFV8_AGG;

  return FALSE;
}

int PT_map_agent_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0;

  e->key.agent_id.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);
  e->key.agent_id.n = atoi(value);
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SF_AGENTID) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'agent_id' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }
  if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_agent_id_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_SF_AGENTID;

  return FALSE;
}

int PT_map_flowset_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0;

  e->key.flowset_id.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);
  e->key.flowset_id.n = htons(atoi(value));
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_FLOWSET_ID) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'flowset_id' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_flowset_id_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_FLOWSET_ID;

  return FALSE;
}

int PT_map_sampling_rate_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0;

  e->key.sampling_rate.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);
  e->key.sampling_rate.n = atoi(value);
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SAMPLING_RATE) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'sampling_rate' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_sampling_rate_handler;
  else if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_sampling_rate_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_SAMPLING_RATE;

  return FALSE;
}

int PT_map_sample_type_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  char *token = NULL;
  u_int32_t tmp;
  int x = 0;

  e->key.sample_type.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  if (acct_type == ACCT_SF && strchr(value, ':')) {
    while (token = extract_token(&value, ':')) {
      switch (x) {
      case 0:
        tmp = atoi(token);
        if (tmp > 1048575) { // 2^20-1: 20 bit Enterprise value
          Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid 'sample_type' value.\n", config.name, config.type, filename);
          return TRUE;
        }
        e->key.sample_type.n = tmp;
        e->key.sample_type.n <<= 12;
        break;
      case 1:
        tmp = atoi(token);
        if (tmp > 4095) { // 2^12-1: 12 bit Format value
          Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid 'sample_type' value.\n", config.name, config.type, filename);
          return TRUE;
        }
        e->key.sample_type.n |= tmp;
        break;
      default:
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid 'sample_type' value.\n", config.name, config.type, filename);
        return TRUE;
      }

      x++;
    }
  }
  else if (acct_type == ACCT_NF) {
    if (!strncmp(value, "flow", strlen("flow")))
      e->key.sample_type.n = NF9_FTYPE_TRAFFIC;
    else if (!strncmp(value, "event", strlen("event")))
      e->key.sample_type.n = NF9_FTYPE_EVENT;
    else if (!strncmp(value, "option", strlen("option")))
      e->key.sample_type.n = NF9_FTYPE_OPTION;
    else {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid 'sample_type' value.\n", config.name, config.type, filename);
      return TRUE;
    }
  }
  else return FALSE; /* silently ignore */

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SAMPLE_TYPE) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'sample_type' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_sample_type_handler;
  else if (config.acct_type == ACCT_NF) e->func[x] = pretag_sample_type_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_SAMPLE_TYPE;

  return FALSE;
}

int PT_map_direction_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0;

  e->key.direction.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);
  e->key.direction.n = atoi(value);
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_DIRECTION) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'direction' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_direction_handler;
  else if (config.acct_type == ACCT_NF) e->func[x] = pretag_direction_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_DIRECTION;

  return FALSE;
}

int PT_map_src_as_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  as_t tmp;
  int x = 0, have_bgp = 0;
  char *endptr;

  e->key.src_as.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  tmp = strtoul(value, &endptr, 10);

  e->key.src_as.n = tmp;
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SRC_AS) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'src_as' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP) {
    e->func[x] = pretag_bgp_src_as_handler;
    e->func_type[x] = PRETAG_SRC_AS; 
    have_bgp = TRUE;
    x++;
  }

  if ((config.nfacctd_as & NF_AS_NEW || config.acct_type == ACCT_PM) && config.networks_file) {
    req->bpf_filter = TRUE;
    e->func[x] = PM_pretag_src_as_handler;
    e->func_type[x] = PRETAG_SRC_AS; 
    return FALSE;
  }
  else if (config.nfacctd_as & NF_AS_KEEP && config.acct_type == ACCT_NF) {
    e->func[x] = pretag_src_as_handler;
    e->func_type[x] = PRETAG_SRC_AS; 
    return FALSE;
  }
  else if (config.nfacctd_as & NF_AS_KEEP && config.acct_type == ACCT_SF) {
    e->func[x] = SF_pretag_src_as_handler;
    e->func_type[x] = PRETAG_SRC_AS; 
    return FALSE;
  }

  if (have_bgp) return FALSE;

  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'src_as' requires either 'networks_file' or 'nf|sfacctd_as: false' to be specified.\n", config.name, config.type, filename);

  return TRUE;
}

int PT_map_dst_as_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  as_t tmp;
  int x = 0, have_bgp = 0;
  char *endptr;

  e->key.dst_as.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  tmp = strtoul(value, &endptr, 10);

  e->key.dst_as.n = tmp;
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_DST_AS) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'dst_as' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP) {
    e->func[x] = pretag_bgp_dst_as_handler;
    e->func_type[x] = PRETAG_DST_AS; 
    have_bgp = TRUE;
    x++;
  }

  if ((config.nfacctd_as & NF_AS_NEW || config.acct_type == ACCT_PM) && config.networks_file) {
    req->bpf_filter = TRUE;
    e->func[x] = PM_pretag_dst_as_handler;
    e->func_type[x] = PRETAG_DST_AS; 
    return FALSE;
  }
  else if (config.nfacctd_as & NF_AS_KEEP && config.acct_type == ACCT_NF) {
    e->func[x] = pretag_dst_as_handler;
    e->func_type[x] = PRETAG_DST_AS; 
    return FALSE;
  }
  else if (config.nfacctd_as & NF_AS_KEEP && config.acct_type == ACCT_SF) {
    e->func[x] = SF_pretag_dst_as_handler;
    e->func_type[x] = PRETAG_DST_AS; 
    return FALSE;
  }

  if (have_bgp) return FALSE;

  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'dst_as' requires either 'networks_file' or 'nf|sfacctd_as: false' to be specified.\n", config.name, config.type, filename);

  return TRUE;
}

int PT_map_peer_src_as_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  as_t tmp;
  int x = 0;
  char *endptr;

  e->key.peer_src_as.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  tmp = strtoul(value, &endptr, 10);

  e->key.peer_src_as.n = tmp;
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_PEER_SRC_AS) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'peer_src_as' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP) {
    e->func[x] = pretag_peer_src_as_handler;
    e->func_type[x] = PRETAG_PEER_SRC_AS; 
    return FALSE;
  }

  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'peer_src_as' requires '[nf|sf]acctd_as_new: [ bgp | longest ]' to be specified.\n", config.name, config.type, filename);

  return TRUE;
}

int PT_map_peer_dst_as_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  as_t tmp;
  int x = 0;
  char *endptr;

  e->key.peer_dst_as.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  tmp = strtoul(value, &endptr, 10);

  e->key.peer_dst_as.n = tmp;
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_PEER_DST_AS) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'peer_dst_as' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP) {
    e->func[x] = pretag_peer_dst_as_handler;
    e->func_type[x] = PRETAG_PEER_DST_AS; 
    return FALSE;
  } 

  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'peer_dst_as' requires '[nf|sf]acctd_as_new: [ bgp | longest ]' to be specified.\n", config.name, config.type, filename);

  return TRUE;
}

int PT_map_src_local_pref_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  u_int32_t tmp;
  int x = 0;
  char *endptr;

  e->key.src_local_pref.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  tmp = strtoul(value, &endptr, 10);

  e->key.src_local_pref.n = tmp;
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SRC_LOCAL_PREF) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'src_local_pref' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP) {
    e->func[x] = pretag_src_local_pref_handler;
    e->func_type[x] = PRETAG_SRC_LOCAL_PREF;
    return FALSE;
  }

  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'src_local_pref' requires '[nf|sf]acctd_as_new: [ bgp | longest ]' to be specified.\n", config.name, config.type, filename);

  return TRUE;
}

int PT_map_local_pref_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  u_int32_t tmp;
  int x = 0;
  char *endptr;

  e->key.local_pref.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  tmp = strtoul(value, &endptr, 10);

  e->key.local_pref.n = tmp;
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_LOCAL_PREF) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'local_pref' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP) {
    e->func[x] = pretag_local_pref_handler;
    e->func_type[x] = PRETAG_LOCAL_PREF;
    return FALSE;
  }

  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'local_pref' requires '[nf|sf]acctd_as_new: [ bgp | longest ]' to be specified.\n", config.name, config.type, filename);

  return TRUE;
}

int PT_map_src_comms_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, idx = 0;
  char *endptr, *token;

  memset(e->key.src_comms, 0, sizeof(e->key.src_comms));

  /* Negation not supported here */

  while ( (token = extract_token(&value, ',')) && idx < MAX_BGP_COMM_PATTERNS ) {
    e->key.src_comms[idx] = malloc(MAX_BGP_STD_COMMS);
    if (!e->key.src_comms[idx]) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] malloc() failed (PT_map_src_comms_handler). Exiting.\n", config.name, config.type, filename);
      exit_all(1);
    }
    strlcpy(e->key.src_comms[idx], token, MAX_BGP_STD_COMMS);
    trim_spaces(e->key.src_comms[idx]);
    idx++;
  }

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SRC_STD_COMM) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'src_comms' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP && e->key.src_comms[0]) {
    e->func[x] = pretag_src_comms_handler;
    e->func_type[x] = PRETAG_SRC_STD_COMM;
    return FALSE;
  }

  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'src_comms' requires '[nf|sf]acctd_as_new: [ bgp | longest ]' to be specified.\n", config.name, config.type, filename);

  return TRUE;
}

int PT_map_comms_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, idx = 0;
  char *endptr, *token;

  memset(e->key.comms, 0, sizeof(e->key.comms));

  /* Negation not supported here */

  while ( (token = extract_token(&value, ',')) && idx < MAX_BGP_COMM_PATTERNS ) {
    e->key.comms[idx] = malloc(MAX_BGP_STD_COMMS);
    if (!e->key.comms[idx]) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] malloc() failed (PT_map_comms_handler). Exiting.\n", config.name, config.type, filename);
      exit_all(1);
    }
    strlcpy(e->key.comms[idx], token, MAX_BGP_STD_COMMS);
    trim_spaces(e->key.comms[idx]);
    idx++;
  }

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_STD_COMM) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'comms' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP && e->key.comms[0]) {
    e->func[x] = pretag_comms_handler;
    e->func_type[x] = PRETAG_STD_COMM;
    return FALSE;
  }

  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'comms' requires '[nf|sf]acctd_as_new: [ bgp | longest ]' to be specified.\n", config.name, config.type, filename);

  return TRUE;
}

int PT_map_mpls_vpn_rd_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, ret;
  char *endptr, *token;

  memset(&e->key.mpls_vpn_rd, 0, sizeof(e->key.mpls_vpn_rd));

  e->key.mpls_vpn_rd.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);
  ret = bgp_str2rd(&e->key.mpls_vpn_rd.rd, value);

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_MPLS_VPN_RD) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'mpls_vpn_rd' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (ret) {
    e->func[x] = pretag_mpls_vpn_rd_handler;
    e->func_type[x] = PRETAG_MPLS_VPN_RD;
    return FALSE;
  }
  else return TRUE; 
}

int PT_map_src_mac_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0;

  if (req->ptm_c.load_ptm_plugin == PLUGIN_ID_TEE) req->ptm_c.load_ptm_res = TRUE;

  e->key.src_mac.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  if (string_etheraddr(value, e->key.src_mac.a)) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Bad source MAC address '%s'.\n", config.name, config.type, filename, value);
    return TRUE;
  }

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SRC_MAC) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'src_mac' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.acct_type == ACCT_NF) e->func[x] = pretag_src_mac_handler;
  else if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_src_mac_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_SRC_MAC;

  return FALSE;
}

int PT_map_dst_mac_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0;

  if (req->ptm_c.load_ptm_plugin == PLUGIN_ID_TEE) req->ptm_c.load_ptm_res = TRUE;

  e->key.dst_mac.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  if (string_etheraddr(value, e->key.dst_mac.a)) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Bad destination MAC address '%s'.\n", config.name, config.type, filename, value);
    return TRUE;
  }

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_DST_MAC) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'dst_mac' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.acct_type == ACCT_NF) e->func[x] = pretag_dst_mac_handler;
  else if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_dst_mac_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_DST_MAC;

  return FALSE;
}

int PT_map_vlan_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int tmp, x = 0;

  if (req->ptm_c.load_ptm_plugin == PLUGIN_ID_TEE) req->ptm_c.load_ptm_res = TRUE;

  e->key.vlan_id.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  tmp = atoi(value);
  if (tmp < 0 || tmp > 4096) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'vlan' need to be in the following range: 0 > value > 4096.\n", config.name, config.type, filename);
    return TRUE;
  }
  e->key.vlan_id.n = tmp;

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_VLAN_ID) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'vlan' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.acct_type == ACCT_NF) e->func[x] = pretag_vlan_id_handler;
  else if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_vlan_id_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_VLAN_ID;

  return FALSE;
}

int PT_map_cvlan_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int tmp, x = 0;

  e->key.cvlan_id.neg = pt_check_neg(&value, &((struct id_table *) req->key_value_table)->flags);

  tmp = atoi(value);
  if (tmp < 0 || tmp > 4096) {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] 'cvlan' need to be in the following range: 0 > value > 4096.\n", config.name, config.type, filename);
    return TRUE;
  }
  e->key.cvlan_id.n = tmp;

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_CVLAN_ID) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'cvlan' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  if (config.acct_type == ACCT_NF) e->func[x] = pretag_cvlan_id_handler;
  /* else if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_vlan_id_handler; */
  if (e->func[x]) e->func_type[x] = PRETAG_CVLAN_ID;

  return FALSE;
}

int PT_map_set_tos_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, len;
  char *endptr;

  e->set_tos.set = TRUE;
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] bad 'set_tos' value: '%s'.\n", config.name, config.type, filename, value);
      return TRUE;
    }
    x++;
  }

  e->set_tos.n = strtoul(value, &endptr, 10);
  for (x = 0; e->set_func[x]; x++) {
    if (e->set_func_type[x] == PRETAG_SET_TOS) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'set_tos' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  /* feature currently only supported in nfacctd */
  if (config.acct_type == ACCT_NF) e->set_func[x] = pretag_set_tos_handler;

  if (e->set_func[x]) e->set_func_type[x] = PRETAG_SET_TOS;

  return FALSE;
}

int BTA_map_lookup_bgp_port_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, len;
  char *endptr;

  e->key.lookup_bgp_port.set = TRUE;
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] bad 'bgp_port' value: '%s'.\n", config.name, config.type, filename, value);
      return TRUE;
    }
    x++;
  }

  e->key.lookup_bgp_port.n = strtoul(value, &endptr, 10);
  for (x = 0; e->set_func[x]; x++) {
    if (e->set_func_type[x] == PRETAG_LOOKUP_BGP_PORT) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Multiple 'bgp_port' clauses part of the same statement.\n", config.name, config.type, filename);
      return TRUE;
    }
  }

  /* feature currently only supported in bgp_agent_map */
  if (acct_type == MAP_BGP_TO_XFLOW_AGENT) e->set_func[x] = BTA_lookup_bgp_port_handler;

  if (e->set_func[x]) e->set_func_type[x] = PRETAG_LOOKUP_BGP_PORT;

  return FALSE;
}

int PT_map_entry_label_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  strlcpy(e->entry_label, value, MAX_LABEL_LEN); 

  return FALSE;
}

int PT_map_jeq_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  e->jeq.label = malloc(MAX_LABEL_LEN);
  if (!e->jeq.label) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] malloc() failed (PT_map_jeq_handler). Exiting.\n", config.name, config.type, filename);
    exit_all(1);
  }
  else strlcpy(e->jeq.label, value, MAX_LABEL_LEN);

  return FALSE;
}

int PT_map_return_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int res = parse_truefalse(value);
  if (res < 0) Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Unknown RETURN value: '%s'. Ignoring.\n", config.name, config.type, filename, value);
  else e->ret = res;

  return FALSE;
}

int PT_map_stack_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  e->stack.func = NULL;

  if (*value == '+' || !strncmp(value, "sum", 3)) e->stack.func = PT_stack_sum;
  else if (!strncmp(value, "or", 2)) e->stack.func = PT_stack_logical_or;
  else Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Unknown STACK operator: '%c'. Ignoring.\n", config.name, config.type, filename, value);

  return FALSE;
}

int pretag_dummy_ip_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  return FALSE;
}

int pretag_input_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t input16 = htons(entry->key.input.n);
  u_int32_t input32 = htonl(entry->key.input.n);
  u_int8_t neg = entry->key.input.neg;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_INPUT_SNMP].len == 2) { 
      if (!memcmp(&input16, pptrs->f_data+tpl->tpl[NF9_INPUT_SNMP].off, tpl->tpl[NF9_INPUT_SNMP].len))
	return (FALSE | neg);
    }
    else if (tpl->tpl[NF9_INPUT_SNMP].len == 4) { 
      if (!memcmp(&input32, pptrs->f_data+tpl->tpl[NF9_INPUT_SNMP].off, tpl->tpl[NF9_INPUT_SNMP].len))
	return (FALSE | neg);
    }
    else if (tpl->tpl[NF9_INPUT_PHYSINT].len == 4) {
      if (!memcmp(&input32, pptrs->f_data+tpl->tpl[NF9_INPUT_PHYSINT].off, tpl->tpl[NF9_INPUT_PHYSINT].len))
        return (FALSE | neg);
    }
    else return (TRUE ^ neg);
  case 8: 
    switch(hdr->aggregation) {
      case 1:
	if (input16 == ((struct struct_export_v8_1 *)pptrs->f_data)->input) return (FALSE | neg);
	else return (TRUE ^ neg);
      case 3:
	if (input16 == ((struct struct_export_v8_3 *)pptrs->f_data)->input) return (FALSE | neg);
	else return (TRUE ^ neg);
      case 5:
        if (input16 == ((struct struct_export_v8_5 *)pptrs->f_data)->input) return (FALSE | neg);
	else return (TRUE ^ neg);
      case 7:
	if (input16 == ((struct struct_export_v8_7 *)pptrs->f_data)->input) return (FALSE | neg);
	else return (TRUE ^ neg);
      case 8:
        if (input16 == ((struct struct_export_v8_8 *)pptrs->f_data)->input) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 9:
        if (input16 == ((struct struct_export_v8_9 *)pptrs->f_data)->input) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 10:
        if (input16 == ((struct struct_export_v8_10 *)pptrs->f_data)->input) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 11: 
        if (input16 == ((struct struct_export_v8_11 *)pptrs->f_data)->input) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 13:
        if (input16 == ((struct struct_export_v8_13 *)pptrs->f_data)->input) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 14:
        if (input16 == ((struct struct_export_v8_14 *)pptrs->f_data)->input) return (FALSE | neg);
        else return (TRUE ^ neg);
      default:
	return (TRUE ^ neg);
    }
  default:
    if (input16 == ((struct struct_export_v5 *)pptrs->f_data)->input) return (FALSE | neg);
    else return (TRUE ^ neg); 
  }
}

int pretag_output_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t output16 = htons(entry->key.output.n);
  u_int32_t output32 = htonl(entry->key.output.n);
  u_int8_t neg = entry->key.output.neg;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_OUTPUT_SNMP].len == 2) {
      if (!memcmp(&output16, pptrs->f_data+tpl->tpl[NF9_OUTPUT_SNMP].off, tpl->tpl[NF9_OUTPUT_SNMP].len))
	return (FALSE | neg);
    }
    else if (tpl->tpl[NF9_OUTPUT_SNMP].len == 4) {
      if (!memcmp(&output32, pptrs->f_data+tpl->tpl[NF9_OUTPUT_SNMP].off, tpl->tpl[NF9_OUTPUT_SNMP].len))
	return (FALSE | neg);
    }
    else if (tpl->tpl[NF9_OUTPUT_PHYSINT].len == 4) {
      if (!memcmp(&output32, pptrs->f_data+tpl->tpl[NF9_OUTPUT_PHYSINT].off, tpl->tpl[NF9_OUTPUT_PHYSINT].len))
        return (FALSE | neg);
    }
    else return (TRUE ^ neg);
  case 8:
    switch(hdr->aggregation) {
      case 1:
        if (output16 == ((struct struct_export_v8_1 *)pptrs->f_data)->output) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 4:
        if (output16 == ((struct struct_export_v8_4 *)pptrs->f_data)->output) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 5:
        if (output16 == ((struct struct_export_v8_5 *)pptrs->f_data)->output) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 6:
        if (output16 == ((struct struct_export_v8_6 *)pptrs->f_data)->output) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 7:
        if (output16 == ((struct struct_export_v8_7 *)pptrs->f_data)->output) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 8:
        if (output16 == ((struct struct_export_v8_8 *)pptrs->f_data)->output) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 9:
        if (output16 == ((struct struct_export_v8_9 *)pptrs->f_data)->output) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 10:
        if (output16 == ((struct struct_export_v8_10 *)pptrs->f_data)->output) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 12:
        if (output16 == ((struct struct_export_v8_12 *)pptrs->f_data)->output) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 13:
        if (output16 == ((struct struct_export_v8_13 *)pptrs->f_data)->output) return (FALSE | neg);
        else return (TRUE ^ neg);
      case 14:
        if (output16 == ((struct struct_export_v8_14 *)pptrs->f_data)->output) return (FALSE | neg);
        else return (TRUE ^ neg);
      default:
        return (TRUE ^ neg);
    }
  default:
    if (output16 == ((struct struct_export_v5 *)pptrs->f_data)->output) return (FALSE | neg);
    else return (TRUE ^ neg);
  }
}

int pretag_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 10:
  case 9:
    if (entry->key.nexthop.a.family == AF_INET) {
      if (!memcmp(&entry->key.nexthop.a.address.ipv4, pptrs->f_data+tpl->tpl[NF9_IPV4_NEXT_HOP].off, tpl->tpl[NF9_IPV4_NEXT_HOP].len))
	return (FALSE | entry->key.nexthop.neg);
    }
#if defined ENABLE_IPV6
    else if (entry->key.nexthop.a.family == AF_INET6) {
      if (!memcmp(&entry->key.nexthop.a.address.ipv6, pptrs->f_data+tpl->tpl[NF9_IPV6_NEXT_HOP].off, tpl->tpl[NF9_IPV6_NEXT_HOP].len))
	return (FALSE | entry->key.nexthop.neg);
    }
#endif
    else return (TRUE ^ entry->key.nexthop.neg);
  case 8:
    /* NetFlow v8 does not seem to contain any nexthop field */
    return TRUE;
  default:
    if (entry->key.nexthop.a.address.ipv4.s_addr == ((struct struct_export_v5 *)pptrs->f_data)->nexthop.s_addr) return (FALSE | entry->key.nexthop.neg);
    else return (TRUE ^ entry->key.nexthop.neg);
  }
}

int pretag_bgp_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  if (entry->last_matched == PRETAG_BGP_NEXTHOP) return FALSE;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, config.nfacctd_net, NF_NET_KEEP)) return TRUE;

  switch(hdr->version) {
  case 10:
  case 9:
    if (entry->key.bgp_nexthop.a.family == AF_INET) {
      if (tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].len) {
        if (!memcmp(&entry->key.bgp_nexthop.a.address.ipv4, pptrs->f_data+tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].off, tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].len))
	  return (FALSE | entry->key.bgp_nexthop.neg);
      }
      else if (tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].len) {
        if (!memcmp(&entry->key.bgp_nexthop.a.address.ipv4, pptrs->f_data+tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].off, tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].len))
	  return (FALSE | entry->key.bgp_nexthop.neg);
      }
    }
#if defined ENABLE_IPV6
    else if (entry->key.nexthop.a.family == AF_INET6) {
      if (tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].len) {
        if (!memcmp(&entry->key.bgp_nexthop.a.address.ipv6, pptrs->f_data+tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].off, tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].len))
	  return (FALSE | entry->key.bgp_nexthop.neg);
      }
      else if (tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].len) {
        if (!memcmp(&entry->key.bgp_nexthop.a.address.ipv6, pptrs->f_data+tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].off, tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].len))
	  return (FALSE | entry->key.bgp_nexthop.neg);
      }
      else if (tpl->tpl[NF9_MPLS_TOP_LABEL_IPV6_ADDR].len) {
        if (!memcmp(&entry->key.bgp_nexthop.a.address.ipv6, pptrs->f_data+tpl->tpl[NF9_MPLS_TOP_LABEL_IPV6_ADDR].off, tpl->tpl[NF9_MPLS_TOP_LABEL_IPV6_ADDR].len))
	  return (FALSE | entry->key.bgp_nexthop.neg);
      }
    }
#endif
    else return (TRUE ^ entry->key.bgp_nexthop.neg);
  case 8:
    /* NetFlow v8 does not seem to contain any nexthop field */
    return TRUE;
  default:
    if (entry->key.bgp_nexthop.a.address.ipv4.s_addr == ((struct struct_export_v5 *)pptrs->f_data)->nexthop.s_addr) return (FALSE | entry->key.bgp_nexthop.neg);
    else return (TRUE ^ entry->key.bgp_nexthop.neg);
  }
}

int pretag_bgp_bgp_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct bgp_node *dst_ret = (struct bgp_node *) pptrs->bgp_dst;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;
  int ret = -1;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, config.nfacctd_net, NF_NET_BGP)) goto way_out;

  if (dst_ret) {
    if (pptrs->bgp_nexthop_info)
      info = (struct bgp_info *) pptrs->bgp_nexthop_info;
    else
      info = (struct bgp_info *) pptrs->bgp_dst_info;

    if (info && info->attr) {
      if (info->attr->mp_nexthop.family == AF_INET) {
        ret = memcmp(&entry->key.bgp_nexthop.a.address.ipv4, &info->attr->mp_nexthop.address.ipv4, 4);
      }
#if defined ENABLE_IPV6
      else if (info->attr->mp_nexthop.family == AF_INET6) {
        ret = memcmp(&entry->key.bgp_nexthop.a.address.ipv6, &info->attr->mp_nexthop.address.ipv6, 16);
      }
#endif
      else {
	ret = memcmp(&entry->key.bgp_nexthop.a.address.ipv4, &info->attr->nexthop, 4);
      }
    }
  }

  way_out:

  if (!ret) {
    entry->last_matched = PRETAG_BGP_NEXTHOP;
    return (FALSE | entry->key.bgp_nexthop.neg);
  }
  else if (config.nfacctd_net & NF_NET_KEEP) return FALSE;
  else return (TRUE ^ entry->key.bgp_nexthop.neg);
}

int pretag_engine_type_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_char value[4];

  switch(hdr->version) {
  case 10:
  {
    struct struct_header_ipfix *hdr = (struct struct_header_ipfix *) pptrs->f_header;

    memcpy(value, &hdr->source_id, 4);
    if (entry->key.engine_type.n == (u_int8_t)value[2]) return (FALSE | entry->key.engine_type.neg);
    else return (TRUE ^ entry->key.engine_type.neg);
  }
  case 9:
  {
    struct struct_header_v9 *hdr = (struct struct_header_v9 *) pptrs->f_header;

    memcpy(value, &hdr->source_id, 4);
    if (entry->key.engine_type.n == (u_int8_t)value[2]) return (FALSE | entry->key.engine_type.neg);
    else return (TRUE ^ entry->key.engine_type.neg);
  }
  case 8:
    if (entry->key.engine_type.n == ((struct struct_header_v8 *)pptrs->f_header)->engine_type) return (FALSE | entry->key.engine_type.neg);
    else return (TRUE ^ entry->key.engine_type.neg);
  case 5:
    if (entry->key.engine_type.n == ((struct struct_header_v5 *)pptrs->f_header)->engine_type) return (FALSE | entry->key.engine_type.neg);
    else return (TRUE ^ entry->key.engine_type.neg);
  default:
    return TRUE; /* this field does not exist: condition is always true */
  }
}

int pretag_engine_id_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_char value[4];

  switch(hdr->version) {
  case 10:
  {
    struct struct_header_ipfix *hdr = (struct struct_header_ipfix *) pptrs->f_header;

    memcpy(value, &hdr->source_id, 4);
    if (entry->key.engine_id.n == (u_int8_t)value[3]) return (FALSE | entry->key.engine_id.neg);
    else return (TRUE ^ entry->key.engine_id.neg);
  }
  case 9:
  {
    struct struct_header_v9 *hdr = (struct struct_header_v9 *) pptrs->f_header;

    memcpy(value, &hdr->source_id, 4);
    if (entry->key.engine_id.n == (u_int8_t)value[3]) return (FALSE | entry->key.engine_id.neg);
    else return (TRUE ^ entry->key.engine_id.neg);
  }
  case 8:
    if (entry->key.engine_id.n == ((struct struct_header_v8 *)pptrs->f_header)->engine_id) return (FALSE | entry->key.engine_id.neg);
    else return (TRUE ^ entry->key.engine_id.neg);
  case 5:
    if (entry->key.engine_id.n == ((struct struct_header_v5 *)pptrs->f_header)->engine_id) return (FALSE | entry->key.engine_id.neg);
    else return (TRUE ^ entry->key.engine_id.neg);
  default:
    return TRUE; /* this field does not exist: condition is always true */
  }
}

int pretag_flowset_id_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl) {
      if (entry->key.flowset_id.n == tpl->template_id) return (FALSE | entry->key.flowset_id.neg);
      else return (TRUE ^ entry->key.flowset_id.neg);
    }
    else return TRUE; /* template not received yet */
  default:
    return TRUE; /* this field does not exist: condition is always true */
  }
}

int pretag_filter_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;

  if (bpf_filter(entry->key.filter.bf_insns, pptrs->packet_ptr, pptrs->pkthdr->len, pptrs->pkthdr->caplen)) 
    return FALSE; /* matched filter */
  else return TRUE;
}

int pretag_v8agg_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;

  switch(hdr->version) {
  case 8:
    if (entry->key.v8agg.n == ((struct struct_header_v8 *)pptrs->f_header)->aggregation) return (FALSE | entry->key.v8agg.neg);
    else return (TRUE ^ entry->key.v8agg.neg);
  default:
    return TRUE; /* this field does not exist: condition is always true */
  }
}

int pretag_src_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t asn16 = 0;
  u_int32_t asn32 = 0;

  if (entry->last_matched == PRETAG_SRC_AS) return FALSE;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_SRC_AS].len == 2) {
      memcpy(&asn16, pptrs->f_data+tpl->tpl[NF9_SRC_AS].off, 2);
      asn32 = ntohs(asn16);
    }
    else if (tpl->tpl[NF9_SRC_AS].len == 4) {
      memcpy(&asn32, pptrs->f_data+tpl->tpl[NF9_SRC_AS].off, 4);
      asn32 = ntohl(asn32);
    }
    break;
  case 8:
    switch(hdr->aggregation) {
    case 1:
      asn32 = ntohs(((struct struct_export_v8_1 *) pptrs->f_data)->src_as);
      break;
    case 3:
      asn32 = ntohs(((struct struct_export_v8_3 *) pptrs->f_data)->src_as);
      break;
    case 5:
      asn32 = ntohs(((struct struct_export_v8_5 *) pptrs->f_data)->src_as);
      break;
    case 9:
      asn32 = ntohs(((struct struct_export_v8_9 *) pptrs->f_data)->src_as);
      break;
    case 11:
      asn32 = ntohs(((struct struct_export_v8_11 *) pptrs->f_data)->src_as);
      break;
    case 13:
      asn32 = ntohs(((struct struct_export_v8_13 *) pptrs->f_data)->src_as);
      break;
    default:
      break;
    }
    break;
  default:
    asn32 = ntohs(((struct struct_export_v5 *) pptrs->f_data)->src_as);
    break;
  }

  if (entry->key.src_as.n == asn32) return (FALSE | entry->key.src_as.neg);
  else return (TRUE ^ entry->key.src_as.neg);
}

int pretag_bgp_src_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;
  as_t asn = 0;

  if (src_ret) {
    info = (struct bgp_info *) pptrs->bgp_src_info;
    if (info && info->attr) {
      if (info->attr->aspath) {
        asn = evaluate_last_asn(info->attr->aspath);
      }
    }
  }

  if (entry->key.src_as.n == asn) {
    entry->last_matched = PRETAG_SRC_AS;
    return (FALSE | entry->key.src_as.neg);
  }
  else if (config.nfacctd_as & NF_AS_KEEP) return FALSE; 
  else return (TRUE ^ entry->key.src_as.neg);
}

int pretag_dst_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t asn16 = 0;
  u_int32_t asn32 = 0;

  if (entry->last_matched == PRETAG_DST_AS) return FALSE;

  switch(hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_DST_AS].len == 2) {
      memcpy(&asn16, pptrs->f_data+tpl->tpl[NF9_DST_AS].off, 2);
      asn32 = ntohs(asn16);
    }
    else if (tpl->tpl[NF9_DST_AS].len == 4) {
      memcpy(&asn32, pptrs->f_data+tpl->tpl[NF9_DST_AS].off, 4);
      asn32 = ntohl(asn32);
    }
    break;
  case 8:
    switch(hdr->aggregation) {
    case 1:
      asn32 = ntohs(((struct struct_export_v8_1 *) pptrs->f_data)->dst_as);
      break;
    case 4:
      asn32 = ntohs(((struct struct_export_v8_4 *) pptrs->f_data)->dst_as);
      break;
    case 5:
      asn32 = ntohs(((struct struct_export_v8_5 *) pptrs->f_data)->dst_as);
      break;
    case 9:
      asn32 = ntohs(((struct struct_export_v8_9 *) pptrs->f_data)->dst_as);
      break;
    case 12:
      asn32 = ntohs(((struct struct_export_v8_12 *) pptrs->f_data)->dst_as);
      break;
    case 13:
      asn32 = ntohs(((struct struct_export_v8_13 *) pptrs->f_data)->dst_as);
      break;
    default:
      break;
    }
    break;
  default:
    asn32 = ntohs(((struct struct_export_v5 *) pptrs->f_data)->dst_as);
    break;
  }

  if (entry->key.dst_as.n == asn32) return (FALSE | entry->key.dst_as.neg);
  else return (TRUE ^ entry->key.dst_as.neg);
}

int pretag_bgp_dst_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct bgp_node *dst_ret = (struct bgp_node *) pptrs->bgp_dst;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;
  as_t asn = 0;

  if (dst_ret) {
    info = (struct bgp_info *) pptrs->bgp_dst_info;
    if (info && info->attr) {
      if (info->attr->aspath) {
        asn = evaluate_last_asn(info->attr->aspath);
      }
    }
  }

  if (entry->key.dst_as.n == asn) {
    entry->last_matched = PRETAG_DST_AS;
    return (FALSE | entry->key.dst_as.neg);
  }
  else if (config.nfacctd_as & NF_AS_KEEP) return FALSE;
  else return (TRUE ^ entry->key.dst_as.neg);
}

int pretag_peer_src_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;
  as_t asn = 0;

  if (config.nfacctd_bgp_peer_as_src_type == BGP_SRC_PRIMITIVES_MAP) {
    asn = pptrs->bpas;
  }
  else if (config.nfacctd_bgp_peer_as_src_type & BGP_SRC_PRIMITIVES_BGP) {
    if (src_ret) {
      info = (struct bgp_info *) pptrs->bgp_src_info;
      if (info && info->attr) {
	if (info->attr->aspath && info->attr->aspath->str) {
	  asn = evaluate_first_asn(info->attr->aspath->str);
	}
      }
    }
  }

  if (entry->key.peer_src_as.n == asn) return (FALSE | entry->key.peer_src_as.neg);
  else return (TRUE ^ entry->key.peer_src_as.neg);
}

int pretag_peer_dst_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct bgp_node *dst_ret = (struct bgp_node *) pptrs->bgp_dst;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;
  as_t asn = 0;

  if (dst_ret) {
    info = (struct bgp_info *) pptrs->bgp_dst_info;
    if (info && info->attr) {
      if (info->attr->aspath && info->attr->aspath->str) {
        asn = evaluate_first_asn(info->attr->aspath->str);
      }
    }
  }

  if (entry->key.peer_dst_as.n == asn) return (FALSE | entry->key.peer_dst_as.neg);
  else return (TRUE ^ entry->key.peer_dst_as.neg);
}

int pretag_src_local_pref_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;
  u_int32_t local_pref = 0;

  if (config.nfacctd_bgp_src_local_pref_type == BGP_SRC_PRIMITIVES_MAP) {
    local_pref = pptrs->blp;
  }
  else if (config.nfacctd_bgp_src_local_pref_type & BGP_SRC_PRIMITIVES_BGP) {
    if (src_ret) {
      info = (struct bgp_info *) pptrs->bgp_src_info;
      if (info && info->attr) {
	local_pref = info->attr->local_pref;
      }
    }
  }

  if (entry->key.src_local_pref.n == local_pref) return (FALSE | entry->key.src_local_pref.neg);
  else return (TRUE ^ entry->key.src_local_pref.neg);
}

int pretag_local_pref_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct bgp_node *dst_ret = (struct bgp_node *) pptrs->bgp_dst;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;
  u_int32_t local_pref = 0;

  if (dst_ret) {
    info = (struct bgp_info *) pptrs->bgp_dst_info;
    if (info && info->attr) {
      local_pref = info->attr->local_pref;
    }
  }

  if (entry->key.local_pref.n == local_pref) return (FALSE | entry->key.local_pref.neg);
  else return (TRUE ^ entry->key.local_pref.neg);
}

int pretag_src_comms_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;
  char tmp_stdcomms[MAX_BGP_STD_COMMS];

  memset(tmp_stdcomms, 0, sizeof(tmp_stdcomms));

  if (src_ret) {
    info = (struct bgp_info *) pptrs->bgp_src_info;
    if (info && info->attr && info->attr->community && info->attr->community->str) {
      evaluate_comm_patterns(tmp_stdcomms, info->attr->community->str, entry->key.src_comms, MAX_BGP_STD_COMMS);
    }
  }

  if (strlen(tmp_stdcomms)) return FALSE;
  else return TRUE;
}

int pretag_comms_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct bgp_node *dst_ret = (struct bgp_node *) pptrs->bgp_dst;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;
  char tmp_stdcomms[MAX_BGP_STD_COMMS];

  memset(tmp_stdcomms, 0, sizeof(tmp_stdcomms));

  if (dst_ret) {
    info = (struct bgp_info *) pptrs->bgp_dst_info;
    if (info && info->attr && info->attr->community && info->attr->community->str) {
      evaluate_comm_patterns(tmp_stdcomms, info->attr->community->str, entry->key.comms, MAX_BGP_STD_COMMS);
    }
  }

  if (strlen(tmp_stdcomms)) return FALSE;
  else return TRUE;
}

int pretag_sample_type_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct struct_header_v5 *hdr5 = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  if (entry->key.sample_type.n == pptrs->flow_type) return (FALSE | entry->key.sample_type.neg); 
  else return (TRUE ^ entry->key.sample_type.neg);
}

int pretag_sampling_rate_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct struct_header_v5 *hdr5 = (struct struct_header_v5 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t srate = 0;

  switch (hdr->version) {
  case 5:
    hdr5 = (struct struct_header_v5 *) pptrs->f_header;
    srate = ( ntohs(hdr5->sampling) & 0x3FFF );
    if (entry->key.sampling_rate.n == srate) return (FALSE | entry->key.sampling_rate.neg);
    else return (TRUE ^ entry->key.sampling_rate.neg);
  default:
    return TRUE; /* this field might not apply: condition is always true */
  }
}

int pretag_direction_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int8_t direction = 0;

  switch (hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_DIRECTION].len == 1) {
      memcpy(&direction, pptrs->f_data+tpl->tpl[NF9_DIRECTION].off, 1);
    }
    if (entry->key.direction.n == direction) return (FALSE | entry->key.direction.neg);
    else return (TRUE ^ entry->key.direction.neg);
  default:
    return TRUE; /* this field does not exist: condition is always true */
  }
}

int pretag_mpls_vpn_rd_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct bgp_node *dst_ret = (struct bgp_node *) pptrs->bgp_dst;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;
  int ret = -1;

  if (dst_ret) {
    info = (struct bgp_info *) pptrs->bgp_dst_info;
    if (info && info->extra) {
      ret = memcmp(&entry->key.mpls_vpn_rd.rd, &info->extra->rd, sizeof(rd_t)); 
    }
  }

  if (!ret) return (FALSE | entry->key.mpls_vpn_rd.neg);
  else return (TRUE ^ entry->key.mpls_vpn_rd.neg);
}

int pretag_src_mac_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch (hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_IN_SRC_MAC].len) {
      if (!memcmp(&entry->key.src_mac.a, pptrs->f_data+tpl->tpl[NF9_IN_SRC_MAC].off, MIN(tpl->tpl[NF9_IN_SRC_MAC].len, 6)))
	return (FALSE | entry->key.src_mac.neg);
      else return (TRUE ^ entry->key.src_mac.neg);
    }
  default:
    return TRUE; /* this field does not exist: condition is always true */
  }
}

int pretag_dst_mac_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  switch (hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_IN_DST_MAC].len) {
      if (!memcmp(&entry->key.dst_mac.a, pptrs->f_data+tpl->tpl[NF9_IN_DST_MAC].off, MIN(tpl->tpl[NF9_IN_DST_MAC].len, 6)))
        return (FALSE | entry->key.dst_mac.neg);
      else return (TRUE ^ entry->key.dst_mac.neg);
    }
  default:
    return TRUE; /* this field does not exist: condition is always true */
  }
}

int pretag_vlan_id_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t tmp16 = 0, vlan_id = 0;

  switch (hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_IN_VLAN].len) {
      memcpy(&tmp16, pptrs->f_data+tpl->tpl[NF9_IN_VLAN].off, MIN(tpl->tpl[NF9_IN_VLAN].len, 2));
    }
    else if (tpl->tpl[NF9_DOT1QVLANID].len) {
      memcpy(&tmp16, pptrs->f_data+tpl->tpl[NF9_DOT1QVLANID].off, MIN(tpl->tpl[NF9_DOT1QVLANID].len, 2));
    }
    vlan_id = ntohs(tmp16);
    if (entry->key.vlan_id.n == vlan_id) return (FALSE | entry->key.vlan_id.neg);
    else return (TRUE ^ entry->key.vlan_id.neg);
  default:
    return TRUE; /* this field does not exist: condition is always true */
  }
}

int pretag_cvlan_id_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t tmp16 = 0, cvlan_id = 0;

  switch (hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_DOT1QCVLANID].len) {
      memcpy(&tmp16, pptrs->f_data+tpl->tpl[NF9_DOT1QCVLANID].off, MIN(tpl->tpl[NF9_DOT1QCVLANID].len, 2));
    }
    cvlan_id = ntohs(tmp16);
    if (entry->key.cvlan_id.n == cvlan_id) return (FALSE | entry->key.cvlan_id.neg);
    else return (TRUE ^ entry->key.cvlan_id.neg);
  default:
    return TRUE; /* this field does not exist: condition is always true */
  }
}

int pretag_set_tos_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;

  memcpy(&pptrs->set_tos, &entry->set_tos, sizeof(s_uint8_t));

  return PRETAG_MAP_RCODE_SET_TOS;
}

int BTA_lookup_bgp_port_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;

  memcpy(&pptrs->lookup_bgp_port, &entry->key.lookup_bgp_port, sizeof(s_uint16_t));

  return BTA_MAP_RCODE_LOOKUP_BGP_PORT;
}

int pretag_id_handler(struct packet_ptrs *pptrs, void *id, void *e)
{
  struct id_entry *entry = e;
  pm_id_t *tid = id;

  *tid = entry->id;

  if (!entry->id && entry->flags == BPAS_MAP_RCODE_BGP) {
    struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src;
    struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
    struct bgp_info *info;

    if (src_ret) {
      info = (struct bgp_info *) pptrs->bgp_src_info;

      if (info && info->attr) {
	if (info->attr->aspath && info->attr->aspath->str) {
	  *tid = evaluate_first_asn(info->attr->aspath->str);

	  if (!(*tid) && config.nfacctd_bgp_stdcomm_pattern_to_asn) {
	    char tmp_stdcomms[MAX_BGP_STD_COMMS];

	    if (info->attr->community && info->attr->community->str) {
	      evaluate_comm_patterns(tmp_stdcomms, info->attr->community->str, std_comm_patterns_to_asn, MAX_BGP_STD_COMMS);
	      copy_stdcomm_to_asn(tmp_stdcomms, (as_t *)tid, FALSE);
	    }
          }
        }
      }
    }
  }

  if (entry->id_inc) entry->id++;

  if (entry->flags == BTA_MAP_RCODE_ID_ID2) {
    return BTA_MAP_RCODE_ID_ID2; /* cap */
  }

  return PRETAG_MAP_RCODE_ID; /* cap */
}

int pretag_id2_handler(struct packet_ptrs *pptrs, void *id, void *e)
{
  struct id_entry *entry = e;
  pm_id_t *tid = id;

  *tid = entry->id2;

  if (entry->id2_inc) entry->id2++;

  return PRETAG_MAP_RCODE_ID2; /* cap */
}

int pretag_label_handler(struct packet_ptrs *pptrs, void *id, void *e)
{
  struct id_entry *entry = e;

  if (id) memcpy(id, &entry->label, sizeof(pt_label_t));

  return PRETAG_MAP_RCODE_LABEL; /* cap */
}

int SF_pretag_input_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->key.input.n == sample->inputPort) return (FALSE | entry->key.input.neg);
  else return (TRUE ^ entry->key.input.neg); 
}

int SF_pretag_output_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->key.output.n == sample->outputPort) return (FALSE | entry->key.output.neg);
  else return (TRUE ^ entry->key.output.neg);
}

int SF_pretag_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->key.nexthop.a.family == AF_INET) {
    if (!memcmp(&entry->key.nexthop.a.address.ipv4, &sample->nextHop.address.ip_v4, 4)) return (FALSE | entry->key.nexthop.neg);
  }
#if defined ENABLE_IPV6
  else if (entry->key.nexthop.a.family == AF_INET6) {
    if (!memcmp(&entry->key.nexthop.a.address.ipv6, &sample->nextHop.address.ip_v6, IP6AddrSz)) return (FALSE | entry->key.nexthop.neg);
  }
#endif

  return (TRUE ^ entry->key.nexthop.neg);
}

int SF_pretag_bgp_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->last_matched == PRETAG_BGP_NEXTHOP) return FALSE;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, config.nfacctd_net, NF_NET_KEEP)) return TRUE;

  if (entry->key.bgp_nexthop.a.family == AF_INET) {
    if (!memcmp(&entry->key.bgp_nexthop.a.address.ipv4, &sample->bgp_nextHop.address.ip_v4, 4)) return (FALSE | entry->key.bgp_nexthop.neg);
  }
#if defined ENABLE_IPV6
  else if (entry->key.bgp_nexthop.a.family == AF_INET6) {
    if (!memcmp(&entry->key.bgp_nexthop.a.address.ipv6, &sample->bgp_nextHop.address.ip_v6, IP6AddrSz)) return (FALSE | entry->key.bgp_nexthop.neg);
  }
#endif

  return (TRUE ^ entry->key.bgp_nexthop.neg);
}

int SF_pretag_agent_id_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->key.agent_id.n == sample->agentSubId) return (FALSE | entry->key.agent_id.neg);
  else return (TRUE ^ entry->key.agent_id.neg);
}

int SF_pretag_sampling_rate_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->key.sampling_rate.n == sample->meanSkipCount) return (FALSE | entry->key.sampling_rate.neg);
  else return (TRUE ^ entry->key.sampling_rate.neg);
}

int SF_pretag_sample_type_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->key.sample_type.n == pptrs->sample_type) return (FALSE | entry->key.sample_type.neg);
  else return (TRUE ^ entry->key.sample_type.neg);
}

int SF_pretag_direction_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if ((sample->inputPort == sample->ds_index && entry->key.direction.n == 0) ||
      (sample->outputPort == sample->ds_index && entry->key.direction.n == 1)) { 
    return (FALSE | entry->key.direction.neg);
  }
  else return (TRUE ^ entry->key.direction.neg);
}

int SF_pretag_src_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  /* If in a fallback scenario, ie. NF_AS_BGP + NF_AS_KEEP set, check BGP first */
  if (config.nfacctd_as & NF_AS_BGP && pptrs->bgp_src) return FALSE;

  if (entry->key.src_as.n == sample->src_as) return (FALSE | entry->key.src_as.neg);
  else return (TRUE ^ entry->key.src_as.neg);
}

int SF_pretag_dst_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  /* If in a fallback scenario, ie. NF_AS_BGP + NF_AS_KEEP set, check BGP first */
  if (config.nfacctd_as & NF_AS_BGP && pptrs->bgp_dst) return FALSE;

  if (entry->key.dst_as.n == sample->dst_as) return (FALSE | entry->key.dst_as.neg);
  else return (TRUE ^ entry->key.dst_as.neg);
}

int SF_pretag_src_mac_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (!memcmp(entry->key.src_mac.a, sample->eth_src, ETH_ADDR_LEN)) return (FALSE | entry->key.src_mac.neg);
  else return (TRUE ^ entry->key.src_mac.neg);
}

int SF_pretag_dst_mac_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (!memcmp(entry->key.dst_mac.a, sample->eth_dst, ETH_ADDR_LEN)) return (FALSE | entry->key.dst_mac.neg);
  else return (TRUE ^ entry->key.dst_mac.neg);
}

int SF_pretag_vlan_id_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->key.vlan_id.n == sample->in_vlan ||
      entry->key.vlan_id.n == sample->out_vlan) return (FALSE | entry->key.vlan_id.neg);
  else return (TRUE ^ entry->key.vlan_id.neg);
}

int PM_pretag_src_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  as_t res = search_pretag_src_as(&nt, &nc, pptrs);

  if (entry->key.src_as.n == res) return (FALSE | entry->key.src_as.neg);
  else return (TRUE ^ entry->key.src_as.neg);
}

int PM_pretag_dst_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  as_t res = search_pretag_dst_as(&nt, &nc, pptrs);

  if (entry->key.dst_as.n == res) return (FALSE | entry->key.dst_as.neg);
  else return (TRUE ^ entry->key.dst_as.neg);
}

int PM_pretag_input_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;

  if (entry->key.input.n == pptrs->ifindex_in) return (FALSE | entry->key.input.neg);
  else return (TRUE ^ entry->key.input.neg);
}

int PM_pretag_output_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;

  if (entry->key.output.n == pptrs->ifindex_out) return (FALSE | entry->key.output.neg);
  else return (TRUE ^ entry->key.output.neg);
}

pm_id_t PT_stack_sum(pm_id_t tag, pm_id_t pre)
{
  return tag + pre;
}

pm_id_t PT_stack_logical_or(pm_id_t tag, pm_id_t pre)
{
  return tag | pre;
}

int BPAS_bgp_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;

  if (src_ret) {
    info = (struct bgp_info *) pptrs->bgp_src_info;
    if (info && info->attr) {
      if (entry->key.bgp_nexthop.a.family == AF_INET) {
	if (info->attr->mp_nexthop.family == AF_INET) {
          if (!memcmp(&entry->key.bgp_nexthop.a.address.ipv4, &info->attr->mp_nexthop.address.ipv4, 4))
            return (FALSE | entry->key.bgp_nexthop.neg);
	}
	else {
          if (!memcmp(&entry->key.bgp_nexthop.a.address.ipv4, &info->attr->nexthop, 4))
            return (FALSE | entry->key.bgp_nexthop.neg);
	}
      }
#if defined ENABLE_IPV6
      else if (entry->key.nexthop.a.family == AF_INET6) {
	if (!memcmp(&entry->key.bgp_nexthop.a.address.ipv6, &info->attr->mp_nexthop.address.ipv6, 16))
          return (FALSE | entry->key.bgp_nexthop.neg);
      }
#endif
    }
  }

  return (TRUE ^ entry->key.bgp_nexthop.neg);
}

int BPAS_bgp_peer_dst_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;
  as_t asn = 0;

  if (src_ret) {
    info = (struct bgp_info *) pptrs->bgp_src_info;
    if (info && info->attr) {
      if (info->attr->aspath && info->attr->aspath->str) {
        asn = evaluate_first_asn(info->attr->aspath->str);

        if (!asn && config.nfacctd_bgp_stdcomm_pattern_to_asn) {
          char tmp_stdcomms[MAX_BGP_STD_COMMS];

          if (info->attr->community && info->attr->community->str) {
            evaluate_comm_patterns(tmp_stdcomms, info->attr->community->str, std_comm_patterns_to_asn, MAX_BGP_STD_COMMS);
            copy_stdcomm_to_asn(tmp_stdcomms, &asn, FALSE);
          }
        }
      }
    }
  }

  if (entry->key.peer_dst_as.n == asn) return (FALSE | entry->key.peer_dst_as.neg);
  else return (TRUE ^ entry->key.peer_dst_as.neg);
}

int BITR_mpls_label_bottom_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  int label_idx;
  u_int32_t label;

  switch(hdr->version) {
  case 10:
  case 9:
    for (label_idx = NF9_MPLS_LABEL_1; label_idx <= NF9_MPLS_LABEL_9; label_idx++) {
      if (tpl->tpl[label_idx].len == 3 && check_bosbit(pptrs->f_data+tpl->tpl[label_idx].off)) {
        label = decode_mpls_label(pptrs->f_data+tpl->tpl[label_idx].off);
	if (entry->key.mpls_label_bottom.n == label) return (FALSE | entry->key.mpls_label_bottom.neg);
      }
    }
    return (TRUE ^ entry->key.mpls_label_bottom.neg);
    break;
  default:
    return (TRUE ^ entry->key.mpls_label_bottom.neg);
    break;
  }
}

int custom_primitives_map_name_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct custom_primitives *table = (struct custom_primitives *) req->key_value_table;
  int idx;

  if (table) {
    lower_string(value);
    for (idx = 0; idx < table->num && strlen(table->primitive[idx].name); idx++) {
      if (!strcmp(table->primitive[idx].name, value)) {
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Duplicate custom aggregate primitive name specified: %s.\n",
		config.name, config.type, filename, value);
        return TRUE;
      }
    }

    strlcpy(table->primitive[table->num].name, value, MAX_CUSTOM_PRIMITIVE_NAMELEN);
  }
  else {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] custom aggregate primitives registry not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

int custom_primitives_map_field_type_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct custom_primitives *table = (struct custom_primitives *) req->key_value_table;
  char *pen = NULL, *type = NULL, *endptr;

  if (table) {
    u_int8_t repeat_id;
    int idx;

    if (type = strchr(value, ':')) {
      pen = value;
      *type = '\0';
      type++;
    }
    else type = value;

    if (pen) table->primitive[table->num].pen = strtoul(pen, &endptr, 10);
    table->primitive[table->num].field_type = atoi(type);
    if (!table->primitive[table->num].field_type) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid NetFlow v9/IPFIX field type '%s'.\n", config.name, config.type, filename, value);
      return TRUE;
    }

    for (idx = 0, repeat_id = 0; idx < table->num; idx++) {
      if (table->primitive[idx].field_type == table->primitive[table->num].field_type &&
	  table->primitive[idx].pen == table->primitive[table->num].pen)
	repeat_id++;
    }
    table->primitive[table->num].repeat_id = repeat_id;
  }
  else {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] custom aggregate primitives registry not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

int custom_primitives_map_packet_ptr_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct custom_primitives *table = (struct custom_primitives *) req->key_value_table;
  struct packet_data_ptr *pd_ptr = NULL; 
  char *layer = NULL, *proto_ptr = NULL, *offset_ptr = NULL, *endptr;
  u_int16_t offset = 0, proto = 0, idx = 0;

  if (config.acct_type == ACCT_PM && table) {
    for (idx = 0; idx < MAX_CUSTOM_PRIMITIVE_PD_PTRS; idx++) {
      if (!table->primitive[table->num].pd_ptr[idx].ptr_idx.set) { 
	pd_ptr = &table->primitive[table->num].pd_ptr[idx];
	break;
      }
    }

    if (!pd_ptr) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] exceeded %u 'packet_ptr' limit per rule.\n",
		config.name, config.type, filename, MAX_CUSTOM_PRIMITIVE_PD_PTRS);
      return TRUE;
    }

    layer = value;

    proto_ptr = strchr(value, ':');
    offset_ptr = strchr(value, '+');

    if (offset_ptr) {
      *offset_ptr = '\0';
      offset_ptr++;
      endptr = NULL;
      offset = strtoul(offset_ptr, &endptr, 10);
    }

    if (proto_ptr) {
      *proto_ptr = '\0';
      proto_ptr++;
      endptr = NULL;
      if (strchr(proto_ptr, 'x')) proto = strtoul(proto_ptr, &endptr, 16);
      else proto = strtoul(proto_ptr, &endptr, 10);
    }

    if (!strncmp(layer, "packet", 6)) {
      pd_ptr->ptr_idx.n = CUSTOM_PRIMITIVE_PACKET_PTR;
      pd_ptr->ptr_idx.set = TRUE;
      if (proto) goto proto_err; 
    }
    else if (!strncmp(layer, "mac", 3)) {
      pd_ptr->ptr_idx.n = CUSTOM_PRIMITIVE_MAC_PTR;
      pd_ptr->ptr_idx.set = TRUE;
      if (proto) goto proto_err; 
    }
    else if (!strncmp(layer, "vlan", 4)) {
      pd_ptr->ptr_idx.n = CUSTOM_PRIMITIVE_VLAN_PTR;
      pd_ptr->ptr_idx.set = TRUE;
      if (proto) goto proto_err; 
    }
    else if (!strncmp(layer, "mpls", 4)) { 
      pd_ptr->ptr_idx.n = CUSTOM_PRIMITIVE_MPLS_PTR;
      pd_ptr->ptr_idx.set = TRUE;
      if (proto) goto proto_err; 
    }
    else if (!strncmp(layer, "l3", 2)) {
      pd_ptr->ptr_idx.n = CUSTOM_PRIMITIVE_L3_PTR;
      pd_ptr->ptr_idx.set = TRUE;
      if (proto) {
        pd_ptr->proto.n = proto;
        pd_ptr->proto.set = TRUE;
      }
    }
    else if (!strncmp(layer, "l4", 2)) {
      pd_ptr->ptr_idx.n = CUSTOM_PRIMITIVE_L4_PTR;
      pd_ptr->ptr_idx.set = TRUE;
      if (proto) {
        pd_ptr->proto.n = proto;
        pd_ptr->proto.set = TRUE;
      }
    }
    else if (!strncmp(layer, "payload", 7)) { 
      pd_ptr->ptr_idx.n = CUSTOM_PRIMITIVE_PAYLOAD_PTR;
      pd_ptr->ptr_idx.set = TRUE;
      if (proto) goto proto_err; 
    }
    else {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid packet pointer '%s'.\n", config.name, config.type, filename, value);
      return TRUE;
    }

    pd_ptr->off = offset;
  }
  else {
    if (config.acct_type != ACCT_PM) {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] packet_ptr is only supported in pmacctd.\n", config.name, config.type, filename);
    }
    else {
      Log(LOG_WARNING, "WARN ( %s/%s ): [%s] custom aggregate primitives registry not allocated.\n", config.name, config.type, filename);
    }

    return TRUE;
  }

  return FALSE;

  proto_err:
  Log(LOG_WARNING, "WARN ( %s/%s ): [%s] protocol type not supported for '%s'.\n", config.name, config.type, filename, layer);
  return TRUE;
}

int custom_primitives_map_len_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct custom_primitives *table = (struct custom_primitives *) req->key_value_table;

  if (table) {
    table->primitive[table->num].len = atoi(value);
    if (table->primitive[table->num].len) {
      if (table->primitive[table->num].len == PM_VARIABLE_LENGTH) {
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid length '%s'.\n", config.name, config.type, filename, value);
        return TRUE;
      }
    }
    else {
      if ((config.acct_type == ACCT_NF || config.acct_type == ACCT_PM) && !strncmp(value, "vlen", 4)) {
        table->primitive[table->num].len = PM_VARIABLE_LENGTH;
      }
      else {
        table->primitive[table->num].len = 0; /* pedantic */
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Invalid length '%s'.\n", config.name, config.type, filename, value);
        return TRUE;
      }
    }
  }
  else {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] custom aggregate primitives registry not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

int custom_primitives_map_semantics_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct custom_primitives *table = (struct custom_primitives *) req->key_value_table;

  if (table) {
    if (!strncmp(value, "u_int", 5)) {
      table->primitive[table->num].semantics = CUSTOM_PRIMITIVE_TYPE_UINT;
    }
    else if (!strncmp(value, "hex", 3)) {
      table->primitive[table->num].semantics = CUSTOM_PRIMITIVE_TYPE_HEX;
    }
    else if (!strncmp(value, "str", 3)) {
      table->primitive[table->num].semantics = CUSTOM_PRIMITIVE_TYPE_STRING;
    }
    else if (!strncmp(value, "ip", 2)) {
      table->primitive[table->num].semantics = CUSTOM_PRIMITIVE_TYPE_IP;
    }
    else if (!strncmp(value, "mac", 3)) {
      table->primitive[table->num].semantics = CUSTOM_PRIMITIVE_TYPE_MAC;
    }
    else if (!strncmp(value, "raw", 3)) {
      table->primitive[table->num].semantics = CUSTOM_PRIMITIVE_TYPE_RAW;
    }
  }
  else {
    Log(LOG_WARNING, "WARN ( %s/%s ): [%s] custom aggregate primitives registry not allocated.\n", config.name, config.type, filename);
    return TRUE;
  }

  return FALSE;
}

void custom_primitives_map_initialize()
{
  custom_primitives_type = (COUNT_INDEX_CP | 0x1);
}

void custom_primitives_map_validate(char *filename, struct plugin_requests *req)
{
  struct custom_primitives *table = (struct custom_primitives *) req->key_value_table;
  int valid = FALSE;

  if (table) {
    if (strcmp(table->primitive[table->num].name, "") && (table->primitive[table->num].field_type ||
	table->primitive[table->num].pd_ptr[0].ptr_idx.set) && table->primitive[table->num].len &&
	table->primitive[table->num].semantics) {
      valid = TRUE;
      if (table->primitive[table->num].semantics == CUSTOM_PRIMITIVE_TYPE_RAW) {
	table->primitive[table->num].alloc_len = (table->primitive[table->num].len * 3) + 1; 
      }
      else { 
	table->primitive[table->num].alloc_len = table->primitive[table->num].len;
      }
    }
    else valid = FALSE;

    if (valid && table->primitive[table->num].len == PM_VARIABLE_LENGTH) {
      if (table->primitive[table->num].semantics != CUSTOM_PRIMITIVE_TYPE_STRING && 
	  table->primitive[table->num].semantics != CUSTOM_PRIMITIVE_TYPE_RAW) 
	valid = FALSE;

      table->primitive[table->num].alloc_len = PM_VARIABLE_LENGTH; 
    }

    if (valid && (table->num + 1 < MAX_CUSTOM_PRIMITIVES)) {
      table->primitive[table->num].type = custom_primitives_type; 
      custom_primitives_type = (COUNT_INDEX_CP | (custom_primitives_type << 1));
      table->num++;
    }
    else {
      if (!valid) {
	Log(LOG_WARNING, "WARN ( %s/%s ): [%s:%u] Invalid entry: name=%s\n",
	    config.name, config.type, filename, table->num + 1, table->primitive[table->num].name);
      }
      else if (table->num + 1 < MAX_CUSTOM_PRIMITIVES) {
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] Maximum entries (%d) reached in aggregate_primitives\n",
	    config.name, config.type, filename, MAX_CUSTOM_PRIMITIVES);
      }

      memset(&table->primitive[table->num], 0, sizeof(struct custom_primitive_entry));
    }
  }
}

int PT_map_index_entries_ip_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src; 

  if (!e || !hash_serializer || !src_e) return TRUE; 

  memcpy(&e->key.agent_ip, &src_e->key.agent_ip, sizeof(pt_hostaddr_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.agent_ip.a, sizeof(struct host_addr), TRUE);

  return FALSE;
}

int PT_map_index_entries_input_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE; 

  memcpy(&e->key.input, &src_e->key.input, sizeof(pt_uint32_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.input.n, sizeof(u_int32_t), TRUE);

  return FALSE;
}

int PT_map_index_entries_output_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE; 

  memcpy(&e->key.output, &src_e->key.output, sizeof(pt_uint32_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.output.n, sizeof(u_int32_t), TRUE);

  return FALSE;
}

int PT_map_index_entries_bgp_nexthop_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE; 

  memcpy(&e->key.bgp_nexthop, &src_e->key.bgp_nexthop, sizeof(pt_hostaddr_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.bgp_nexthop.a, sizeof(struct host_addr), TRUE);

  return FALSE;
}

int PT_map_index_entries_src_as_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE; 

  memcpy(&e->key.src_as, &src_e->key.src_as, sizeof(pt_uint32_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.src_as.n, sizeof(u_int32_t), TRUE);

  return FALSE;
}

int PT_map_index_entries_dst_as_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE; 

  memcpy(&e->key.dst_as, &src_e->key.dst_as, sizeof(pt_uint32_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.dst_as.n, sizeof(u_int32_t), TRUE);

  return FALSE;
}

int PT_map_index_entries_peer_src_as_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE; 

  memcpy(&e->key.peer_src_as, &src_e->key.peer_src_as, sizeof(pt_uint32_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.peer_src_as.n, sizeof(u_int32_t), TRUE);

  return FALSE;
}

int PT_map_index_entries_peer_dst_as_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE; 

  memcpy(&e->key.peer_dst_as, &src_e->key.peer_dst_as, sizeof(pt_uint32_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.peer_dst_as.n, sizeof(u_int32_t), TRUE);

  return FALSE;
}

int PT_map_index_entries_mpls_vpn_rd_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE; 

  memcpy(&e->key.mpls_vpn_rd, &src_e->key.mpls_vpn_rd, sizeof(pt_rd_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.mpls_vpn_rd.rd, sizeof(rd_t), TRUE);

  return FALSE;
}

int PT_map_index_entries_mpls_label_bottom_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE;

  memcpy(&e->key.mpls_label_bottom, &src_e->key.mpls_label_bottom, sizeof(pt_uint32_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.mpls_label_bottom.n, sizeof(u_int32_t), TRUE);

  return FALSE;
}

int PT_map_index_entries_src_mac_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE; 

  memcpy(&e->key.src_mac, &src_e->key.src_mac, sizeof(pt_etheraddr_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.src_mac.a, ETH_ADDR_LEN, TRUE);

  return FALSE;
}

int PT_map_index_entries_dst_mac_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE;

  memcpy(&e->key.dst_mac, &src_e->key.dst_mac, sizeof(pt_etheraddr_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.dst_mac.a, ETH_ADDR_LEN, TRUE);

  return FALSE;
}

int PT_map_index_entries_vlan_id_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE; 

  memcpy(&e->key.vlan_id, &src_e->key.vlan_id, sizeof(pt_uint16_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.vlan_id.n, sizeof(u_int16_t), TRUE);

  return FALSE;
}

int PT_map_index_entries_cvlan_id_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct id_entry *src_e = (struct id_entry *) src;

  if (!e || !hash_serializer || !src_e) return TRUE;

  memcpy(&e->key.cvlan_id, &src_e->key.cvlan_id, sizeof(pt_uint16_t));
  hash_serial_append(hash_serializer, (char *)&src_e->key.cvlan_id.n, sizeof(u_int16_t), TRUE);

  return FALSE;
}

int PT_map_index_fdata_ip_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent;
  SFSample *sample = (SFSample *)pptrs->f_data;
  u_int16_t port, j;

  if (config.acct_type == ACCT_NF) {
    sa_to_addr((struct sockaddr *)sa, &e->key.agent_ip.a, &port);
  }
  else if (config.acct_type == ACCT_SF) {
    if (sample->agent_addr.type == SFLADDRESSTYPE_IP_V4) {
      e->key.agent_ip.a.family = AF_INET;
      e->key.agent_ip.a.address.ipv4.s_addr = sample->agent_addr.address.ip_v4.s_addr;
    }
#if defined ENABLE_IPV6
    else if (sample->agent_addr.type == SFLADDRESSTYPE_IP_V6) {
      e->key.agent_ip.a.family = AF_INET6;
      for (j = 0; j < 4; j++) e->key.agent_ip.a.address.ipv6.s6_addr[j] = sample->agent_addr.address.ip_v6.s6_addr[j];
    }
#endif 
  }
  else return TRUE;

  hash_serial_append(hash_serializer, (char *)&e->key.agent_ip.a, sizeof(struct host_addr), FALSE);

  return FALSE;
}

int PT_map_index_fdata_input_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (config.acct_type == ACCT_NF) {
    u_int16_t iface16 = 0;
    u_int32_t iface32 = 0;

    switch(hdr->version) {
    case 10:
    case 9:
      if (tpl->tpl[NF9_INPUT_SNMP].len == 2) {
        memcpy(&iface16, pptrs->f_data+tpl->tpl[NF9_INPUT_SNMP].off, 2);
        e->key.input.n = ntohs(iface16);
      }
      else if (tpl->tpl[NF9_INPUT_SNMP].len == 4) {
        memcpy(&iface32, pptrs->f_data+tpl->tpl[NF9_INPUT_SNMP].off, 4);
        e->key.input.n = ntohl(iface32);
      }
      else if (tpl->tpl[NF9_INPUT_PHYSINT].len == 4) {
        memcpy(&iface32, pptrs->f_data+tpl->tpl[NF9_INPUT_PHYSINT].off, 4);
        e->key.input.n = ntohl(iface32);
      }
      break; 
    case 8:
      /* unsupported */
      break;
    default:
      iface16 = ntohs(((struct struct_export_v5 *) pptrs->f_data)->input);
      e->key.input.n = iface16;
      break;
    }
  }
  else if (config.acct_type == ACCT_SF) {
    e->key.input.n = sample->inputPort;
  }
  else if (config.acct_type == ACCT_PM) {
    e->key.input.n = pptrs->ifindex_in;
  }

  hash_serial_append(hash_serializer, (char *)&e->key.input.n, sizeof(u_int32_t), FALSE);

  return FALSE;
}

int PT_map_index_fdata_output_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (config.acct_type == ACCT_NF) {
    u_int16_t iface16 = 0;
    u_int32_t iface32 = 0;

    switch(hdr->version) {
    case 10:
    case 9:
      if (tpl->tpl[NF9_OUTPUT_SNMP].len == 2) {
        memcpy(&iface16, pptrs->f_data+tpl->tpl[NF9_OUTPUT_SNMP].off, 2);
        e->key.output.n = ntohs(iface16);
      }
      else if (tpl->tpl[NF9_OUTPUT_SNMP].len == 4) {
        memcpy(&iface32, pptrs->f_data+tpl->tpl[NF9_OUTPUT_SNMP].off, 4);
        e->key.output.n = ntohl(iface32);
      }
      else if (tpl->tpl[NF9_OUTPUT_PHYSINT].len == 4) {
        memcpy(&iface32, pptrs->f_data+tpl->tpl[NF9_OUTPUT_PHYSINT].off, 4);
        e->key.output.n = ntohl(iface32);
      }
      break;
    case 8:
      /* unsupported */
      break;
    default:
      iface16 = ntohs(((struct struct_export_v5 *) pptrs->f_data)->output);
      e->key.output.n = iface16;
      break;
    }
  }
  else if (config.acct_type == ACCT_SF) {
    e->key.output.n = sample->outputPort;
  }
  else if (config.acct_type == ACCT_PM) {
    e->key.output.n = pptrs->ifindex_out;
  }

  hash_serial_append(hash_serializer, (char *)&e->key.output.n, sizeof(u_int32_t), FALSE);

  return FALSE;
}

int PT_map_index_fdata_bgp_nexthop_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  SFSample *sample = (SFSample *) pptrs->f_data;

  struct bgp_node *dst_ret = (struct bgp_node *) pptrs->bgp_dst;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;

  if (evaluate_lm_method(pptrs, TRUE, config.nfacctd_net, NF_NET_BGP)) {
    if (dst_ret) {
      if (pptrs->bgp_nexthop_info) info = (struct bgp_info *) pptrs->bgp_nexthop_info;
      else info = (struct bgp_info *) pptrs->bgp_dst_info;

      if (info && info->attr) {
	if (info->attr->mp_nexthop.family == AF_INET) {
	  memcpy(&e->key.bgp_nexthop.a, &info->attr->mp_nexthop, HostAddrSz);
	}
#if defined ENABLE_IPV6
	else if (info->attr->mp_nexthop.family == AF_INET6) {
	  memcpy(&e->key.bgp_nexthop.a, &info->attr->mp_nexthop, HostAddrSz);
	}
#endif
	else {
	  e->key.bgp_nexthop.a.address.ipv4.s_addr = info->attr->nexthop.s_addr;
	  e->key.bgp_nexthop.a.family = AF_INET;
	}
      }
    }
  }
  else if (evaluate_lm_method(pptrs, TRUE, config.nfacctd_net, NF_NET_KEEP)) {
    if (config.acct_type == ACCT_NF) {
      switch(hdr->version) {
      case 10:
      case 9:
	if (pptrs->l3_proto == ETHERTYPE_IP) {
	  if (tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].len) {
	    memcpy(&e->key.bgp_nexthop.a.address.ipv4, pptrs->f_data+tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].off, MIN(tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].len, 4));
	    e->key.bgp_nexthop.a.family = AF_INET;
	  }
	  else if (tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].len) {
	    memcpy(&e->key.bgp_nexthop.a.address.ipv4, pptrs->f_data+tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].off, MIN(tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].len, 4));
	    e->key.bgp_nexthop.a.family = AF_INET;
	  }
	}
#if defined ENABLE_IPV6
	else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
	  if (tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].len) {
	    memcpy(&e->key.bgp_nexthop.a.address.ipv6, pptrs->f_data+tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].off, MIN(tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].len, 16));
	    e->key.bgp_nexthop.a.family = AF_INET6;
	  }
	  else if (tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].len) {
	    memcpy(&e->key.bgp_nexthop.a.address.ipv6, pptrs->f_data+tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].off, MIN(tpl->tpl[NF9_MPLS_TOP_LABEL_ADDR].len, 4));
	    e->key.bgp_nexthop.a.family = AF_INET;
	  }
	  else if (tpl->tpl[NF9_MPLS_TOP_LABEL_IPV6_ADDR].len) {
	    memcpy(&e->key.bgp_nexthop.a.address.ipv6, pptrs->f_data+tpl->tpl[NF9_MPLS_TOP_LABEL_IPV6_ADDR].off, MIN(tpl->tpl[NF9_MPLS_TOP_LABEL_IPV6_ADDR].len, 16));
	    e->key.bgp_nexthop.a.family = AF_INET6;
	  }
	}
#endif
      }
    }
    else if (config.acct_type == ACCT_SF) {
      if (sample->gotIPV4) {
	e->key.bgp_nexthop.a.family = AF_INET;
	e->key.bgp_nexthop.a.address.ipv4.s_addr = sample->bgp_nextHop.address.ip_v4.s_addr;
      }
#if defined ENABLE_IPV6
      else if (sample->gotIPV6) {
	e->key.bgp_nexthop.a.family = AF_INET6;
	memcpy(&e->key.bgp_nexthop.a.address.ipv6, &sample->bgp_nextHop.address.ip_v6, IP6AddrSz);
      }
#endif
    }
    else return TRUE;
  }

  hash_serial_append(hash_serializer, (char *)&e->key.bgp_nexthop.a, sizeof(struct host_addr), FALSE);

  return FALSE;
}

int PT_map_index_fdata_src_as_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  SFSample *sample = (SFSample *) pptrs->f_data;

  struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;

  if (src_ret && evaluate_lm_method(pptrs, FALSE, config.nfacctd_as, NF_AS_BGP)) {
    info = (struct bgp_info *) pptrs->bgp_src_info;
    if (info && info->attr && info->attr->aspath) {
      e->key.src_as.n = evaluate_last_asn(info->attr->aspath);
    }
  }
  else if (evaluate_lm_method(pptrs, FALSE, config.nfacctd_as, NF_AS_KEEP)) {
    if (config.acct_type == ACCT_NF) {
      u_int16_t asn16 = 0;
      u_int32_t asn32 = 0;

      switch(hdr->version) {
      case 10:
      case 9:
	if (tpl->tpl[NF9_SRC_AS].len == 2) {
	  memcpy(&asn16, pptrs->f_data+tpl->tpl[NF9_SRC_AS].off, 2);
	  e->key.src_as.n = ntohs(asn16);
	}
	else if (tpl->tpl[NF9_SRC_AS].len == 4) {
	  memcpy(&asn32, pptrs->f_data+tpl->tpl[NF9_SRC_AS].off, 4);
	  e->key.src_as.n = ntohl(asn32);
	}
	break;
      case 8:
	/* unsupported */
	break;
      default:
	e->key.src_as.n = ntohs(((struct struct_export_v5 *) pptrs->f_data)->src_as);
	break;
      }
    }
    else if (config.acct_type == ACCT_SF) {
      e->key.src_as.n = sample->src_as;
    }
    else return TRUE;
  }

  hash_serial_append(hash_serializer, (char *)&e->key.src_as.n, sizeof(u_int32_t), FALSE);

  return FALSE;
}

int PT_map_index_fdata_dst_as_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  SFSample *sample = (SFSample *) pptrs->f_data;

  struct bgp_node *dst_ret = (struct bgp_node *) pptrs->bgp_dst;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;

  if (dst_ret && evaluate_lm_method(pptrs, FALSE, config.nfacctd_as, NF_AS_BGP)) {
    info = (struct bgp_info *) pptrs->bgp_dst_info;
    if (info && info->attr && info->attr->aspath) {
      e->key.dst_as.n = evaluate_last_asn(info->attr->aspath);
    }
  }
  else if (evaluate_lm_method(pptrs, TRUE, config.nfacctd_as, NF_AS_KEEP)) {
    if (config.acct_type == ACCT_NF) {
      u_int16_t asn16 = 0;
      u_int32_t asn32 = 0;

      switch(hdr->version) {
      case 10:
      case 9:
        if (tpl->tpl[NF9_DST_AS].len == 2) {
          memcpy(&asn16, pptrs->f_data+tpl->tpl[NF9_DST_AS].off, 2);
          e->key.dst_as.n = ntohs(asn16);
        }
        else if (tpl->tpl[NF9_DST_AS].len == 4) {
          memcpy(&asn32, pptrs->f_data+tpl->tpl[NF9_DST_AS].off, 4);
          e->key.dst_as.n = ntohl(asn32);
        }
        break;
      case 8:
        /* unsupported */
        break;
      default:
        e->key.dst_as.n = ntohs(((struct struct_export_v5 *) pptrs->f_data)->dst_as);
        break;
      }
    }
    else if (config.acct_type == ACCT_SF) {
      e->key.dst_as.n = sample->dst_as;
    }
  }
  else return TRUE;

  hash_serial_append(hash_serializer, (char *)&e->key.dst_as.n, sizeof(u_int32_t), FALSE);

  return FALSE;
}

int PT_map_index_fdata_peer_src_as_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  SFSample *sample = (SFSample *) pptrs->f_data;

  struct bgp_node *src_ret = (struct bgp_node *) pptrs->bgp_src;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;

  if (config.nfacctd_bgp_peer_as_src_type & BGP_SRC_PRIMITIVES_MAP) {
    e->key.peer_src_as.n = pptrs->bpas;
  }
  else {
    if (src_ret && evaluate_lm_method(pptrs, FALSE, config.nfacctd_as, NF_AS_BGP)) {
      info = (struct bgp_info *) pptrs->bgp_src_info;
      if (info && info->attr && info->attr->aspath) {
        e->key.peer_src_as.n = evaluate_first_asn(info->attr->aspath->str);
      }
    }
    else if (evaluate_lm_method(pptrs, FALSE, config.nfacctd_as, NF_AS_KEEP)) {
      if (config.acct_type == ACCT_NF) {
        u_int16_t asn16 = 0;
        u_int32_t asn32 = 0;
  
        switch(hdr->version) {
        case 10:
        case 9:
          if (tpl->tpl[NF9_PEER_SRC_AS].len == 2) {
            memcpy(&asn16, pptrs->f_data+tpl->tpl[NF9_PEER_SRC_AS].off, 2);
            e->key.peer_src_as.n = ntohs(asn16);
          }
          else if (tpl->tpl[NF9_PEER_SRC_AS].len == 4) {
            memcpy(&asn32, pptrs->f_data+tpl->tpl[NF9_PEER_SRC_AS].off, 4);
            e->key.peer_src_as.n = ntohl(asn32);
          }
          break;
        default:
          break;
        }
      }
      else if (config.acct_type == ACCT_SF) {
        e->key.peer_src_as.n = sample->src_peer_as;
      }
      else return TRUE;
    }
  }

  hash_serial_append(hash_serializer, (char *)&e->key.peer_src_as.n, sizeof(u_int32_t), FALSE);

  return FALSE;
}

int PT_map_index_fdata_peer_dst_as_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  SFSample *sample = (SFSample *) pptrs->f_data;

  struct bgp_node *dst_ret = (struct bgp_node *) pptrs->bgp_dst;
  struct bgp_peer *peer = (struct bgp_peer *) pptrs->bgp_peer;
  struct bgp_info *info;

  if (dst_ret && evaluate_lm_method(pptrs, FALSE, config.nfacctd_as, NF_AS_BGP)) {
    info = (struct bgp_info *) pptrs->bgp_dst_info;
    if (info && info->attr && info->attr->aspath) {
      e->key.peer_dst_as.n = evaluate_first_asn(info->attr->aspath->str);
    }
  }
  else if (evaluate_lm_method(pptrs, FALSE, config.nfacctd_as, NF_AS_KEEP)) {
    if (config.acct_type == ACCT_NF) {
      u_int16_t asn16 = 0;
      u_int32_t asn32 = 0;

      switch(hdr->version) {
      case 10:
      case 9:
        if (tpl->tpl[NF9_PEER_DST_AS].len == 2) {
          memcpy(&asn16, pptrs->f_data+tpl->tpl[NF9_PEER_DST_AS].off, 2);
          e->key.peer_dst_as.n = ntohs(asn16);
        }
        else if (tpl->tpl[NF9_PEER_DST_AS].len == 4) {
          memcpy(&asn32, pptrs->f_data+tpl->tpl[NF9_PEER_DST_AS].off, 4);
          e->key.peer_dst_as.n = ntohl(asn32);
        }
        break;
      default:
        break;
      }
    }
    else if (config.acct_type == ACCT_SF) {
      e->key.peer_dst_as.n = sample->dst_peer_as;
    }
    else return TRUE;
  }

  hash_serial_append(hash_serializer, (char *)&e->key.peer_dst_as.n, sizeof(u_int32_t), FALSE);

  return FALSE;
}

int PT_map_index_fdata_mpls_vpn_rd_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  SFSample *sample = (SFSample *) pptrs->f_data;

  /* if bitr is populate we infer non-zero config.nfacctd_flow_to_rd_map */
  if (pptrs->bitr) memcpy(&e->key.mpls_vpn_rd.rd, &pptrs->bitr, sizeof(rd_t));

  if (config.acct_type == ACCT_NF) {
    int vrfid = FALSE;

    switch(hdr->version) {
    case 10:
    case 9:
      if (tpl->tpl[NF9_INGRESS_VRFID].len && !e->key.mpls_vpn_rd.rd.val) {
        memcpy(&e->key.mpls_vpn_rd.rd.val, pptrs->f_data+tpl->tpl[NF9_INGRESS_VRFID].off, MIN(tpl->tpl[NF9_INGRESS_VRFID].len, 4));
        vrfid = TRUE;
      }

      if (tpl->tpl[NF9_EGRESS_VRFID].len && !e->key.mpls_vpn_rd.rd.val) {
        memcpy(&e->key.mpls_vpn_rd.rd.val, pptrs->f_data+tpl->tpl[NF9_EGRESS_VRFID].off, MIN(tpl->tpl[NF9_EGRESS_VRFID].len, 4));
        vrfid = TRUE;
      }

      if (vrfid) {
        e->key.mpls_vpn_rd.rd.val = ntohl(e->key.mpls_vpn_rd.rd.val);
        if (e->key.mpls_vpn_rd.rd.val) e->key.mpls_vpn_rd.rd.type = RD_TYPE_VRFID;
      }
      break;
    }
  }

  hash_serial_append(hash_serializer, (char *)&e->key.mpls_vpn_rd.rd, sizeof(rd_t), FALSE);

  return FALSE;
}

int PT_map_index_fdata_mpls_label_bottom_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (config.acct_type == ACCT_NF) {
    int label_idx;

    switch(hdr->version) {
    case 10:
    case 9:
      for (label_idx = NF9_MPLS_LABEL_1; label_idx <= NF9_MPLS_LABEL_9; label_idx++) {
        if (tpl->tpl[label_idx].len == 3 && check_bosbit(pptrs->f_data+tpl->tpl[label_idx].off)) {
          e->key.mpls_label_bottom.n = decode_mpls_label(pptrs->f_data+tpl->tpl[label_idx].off);
          break;
        }
      }
      break;
    }
  }

  hash_serial_append(hash_serializer, (char *)&e->key.mpls_label_bottom.n, sizeof(u_int32_t), FALSE);

  return FALSE;
}

int PT_map_index_fdata_src_mac_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (config.acct_type == ACCT_NF) {
    switch (hdr->version) {
    case 10:
    case 9:
      if (tpl->tpl[NF9_IN_SRC_MAC].len) {
        memcpy(&e->key.src_mac.a, pptrs->f_data+tpl->tpl[NF9_IN_SRC_MAC].off, MIN(tpl->tpl[NF9_IN_SRC_MAC].len, 6));
      }
    }
  }
  else if (config.acct_type == ACCT_SF) {
    memcpy(&e->key.src_mac.a, sample->eth_src, ETH_ADDR_LEN);
  }
  else return TRUE;

  hash_serial_append(hash_serializer, (char *)&e->key.src_mac.a, ETH_ADDR_LEN, FALSE);

  return FALSE;
}

int PT_map_index_fdata_dst_mac_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (config.acct_type == ACCT_NF) {
    switch (hdr->version) {
    case 10:
    case 9:
      if (tpl->tpl[NF9_IN_DST_MAC].len) {
        memcpy(&e->key.dst_mac.a, pptrs->f_data+tpl->tpl[NF9_IN_DST_MAC].off, MIN(tpl->tpl[NF9_IN_DST_MAC].len, 6));
      }
    }
  }
  else if (config.acct_type == ACCT_SF) {
    memcpy(&e->key.dst_mac.a, sample->eth_dst, ETH_ADDR_LEN);
  }
  else return TRUE;

  hash_serial_append(hash_serializer, (char *)&e->key.dst_mac.a, ETH_ADDR_LEN, FALSE);

  return FALSE;
}

int PT_map_index_fdata_vlan_id_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  SFSample *sample = (SFSample *) pptrs->f_data;
  u_int16_t tmp16 = 0;

  if (config.acct_type == ACCT_NF) {
    switch (hdr->version) {
    case 10:
    case 9:
      if (tpl->tpl[NF9_IN_VLAN].len) {
        memcpy(&tmp16, pptrs->f_data+tpl->tpl[NF9_IN_VLAN].off, MIN(tpl->tpl[NF9_IN_VLAN].len, 2));
      }
      else if (tpl->tpl[NF9_DOT1QVLANID].len) {
        memcpy(&tmp16, pptrs->f_data+tpl->tpl[NF9_DOT1QVLANID].off, MIN(tpl->tpl[NF9_DOT1QVLANID].len, 2));
      }
      e->key.vlan_id.n = ntohs(tmp16);
    }
  }
  else if (config.acct_type == ACCT_SF) {
    if (sample->in_vlan) e->key.vlan_id.n = sample->in_vlan;
    else if (sample->out_vlan) e->key.vlan_id.n = sample->out_vlan;
  }
  else return TRUE;

  hash_serial_append(hash_serializer, (char *)&e->key.vlan_id.n, sizeof(u_int16_t), FALSE);

  return FALSE;
}

int PT_map_index_fdata_cvlan_id_handler(struct id_entry *e, pm_hash_serial_t *hash_serializer, void *src)
{
  struct packet_ptrs *pptrs = (struct packet_ptrs *) src;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t tmp16 = 0;

  if (config.acct_type == ACCT_NF) {
    switch (hdr->version) {
    case 10:
    case 9:
      if (tpl->tpl[NF9_DOT1QCVLANID].len) {
        memcpy(&tmp16, pptrs->f_data+tpl->tpl[NF9_DOT1QCVLANID].off, MIN(tpl->tpl[NF9_DOT1QCVLANID].len, 2));
	e->key.cvlan_id.n = ntohs(tmp16);
      }
    }
  }
  else return TRUE;

  hash_serial_append(hash_serializer, (char *)&e->key.cvlan_id.n, sizeof(u_int16_t), FALSE);

  return FALSE;
}
