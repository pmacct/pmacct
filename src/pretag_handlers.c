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

#define __PRETAG_HANDLERS_C

#include "pmacct.h"
#include "nfacctd.h"
#include "sflow.h"
#include "sfacctd.h"
#include "pretag_handlers.h"
#include "net_aggr.h"
#include "bgp/bgp.h"

int PT_map_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct host_addr a;
  char *endptr = NULL;
  pm_id_t j = 0, z = 0;
  int x;

  e->id = 0;
  e->flags = FALSE;

  /* If we parse a bgp_agent_map and spot a '.' within the string let's
     check if we are given a valid IPv4 address */
  if (acct_type == MAP_BGP_TO_XFLOW_AGENT && strchr(value, '.')) {
    memset(&a, 0, sizeof(a));
    str_to_addr(value, &a);
    if (a.family == AF_INET) j = a.address.ipv4.s_addr;
    else {
      Log(LOG_ERR, "ERROR ( %s ): ID does not appear to be a valid IPv4 address. ", filename);
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
      Log(LOG_ERR, "ERROR ( %s ): ID does not appear to be a valid IPv6 address. ", filename);
      return TRUE;
    }
  }
#endif
  else if (acct_type == MAP_BGP_IFACE_TO_RD && strchr(value, ':')) {
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
    j = strtoull(value, &endptr, 10);
    if (j > UINT32_MAX) {
      Log(LOG_ERR, "ERROR ( %s ): Invalid TAG/ID specified. ", filename);
      return TRUE;
    } 
  }

  e->id = j; 
  if (z) e->id2 = z;

  if (acct_type == ACCT_NF || acct_type == ACCT_SF || acct_type == ACCT_PM) {
    for (x = 0; e->set_func[x]; x++) {
      if (e->set_func_type[x] == PRETAG_SET_TAG) {
        Log(LOG_ERR, "ERROR ( %s ): Multiple 'set_tag' (id) clauses part of the same statement. ", filename);
        return TRUE;
      }
    }

    /* feature currently only supported in nfacctd */
    e->set_func[x] = pretag_id_handler;
    e->set_func_type[x] = PRETAG_SET_TAG;
  }

  return FALSE;
}

int PT_map_id2_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  char *endptr = NULL;
  pm_id_t j;
  int x;

  j = strtoull(value, &endptr, 10);
  if (j > UINT32_MAX) {
    Log(LOG_ERR, "ERROR ( %s ): Invalid TAG2/ID2 specified. ", filename);
    return TRUE;
  }
  e->id2 = j;

  if (acct_type == ACCT_NF || acct_type == ACCT_SF || acct_type == ACCT_PM) {
    for (x = 0; e->set_func[x]; x++) {
      if (e->set_func_type[x] == PRETAG_SET_TAG2) {
        Log(LOG_ERR, "ERROR ( %s ): Multiple 'set_tag2' (id2) clauses part of the same statement. ", filename);
        return TRUE;
      }
    }

    /* feature currently only supported in nfacctd */
    e->set_func[x] = pretag_id2_handler;
    e->set_func_type[x] = PRETAG_SET_TAG2;
  }

  return FALSE;
}

int PT_map_ip_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  if (!str_to_addr(value, &e->agent_ip.a)) {
    Log(LOG_ERR, "ERROR ( %s ): Bad IP address '%s'. ", filename, value);
    return TRUE;
  }

  return FALSE;
}

int PT_map_input_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, len;
  char *endptr;

  if (acct_type == MAP_SAMPLING) sampling_map_caching = FALSE;

  e->input.neg = pt_check_neg(&value);
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR ( %s ): bad 'in' value: '%s'. ", filename, value);
      return TRUE;
    }
    x++;
  }
  
  e->input.n = strtoul(value, &endptr, 10);
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_IN_IFACE) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'input' clauses part of the same statement. ", filename);
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

  e->output.neg = pt_check_neg(&value);
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR ( %s ): bad 'out' value: '%s'. ", filename, value);
      return TRUE;
    }
    x++;
  }

  e->output.n = strtoul(value, &endptr, 10);
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_OUT_IFACE) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'output' clauses part of the same statement. ", filename);
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

  e->nexthop.neg = pt_check_neg(&value);

  if (!str_to_addr(value, &e->nexthop.a)) {
    Log(LOG_ERR, "ERROR ( %s ): Bad nexthop address '%s'. ", filename, value);
    return TRUE;
  }

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_NEXTHOP) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'nexthop' clauses part of the same statement. ", filename);
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

  e->bgp_nexthop.neg = pt_check_neg(&value);

  if (!str_to_addr(value, &e->bgp_nexthop.a)) {
    Log(LOG_ERR, "ERROR ( %s ): Bad BGP nexthop address '%s'. ", filename, value);
    return TRUE;
  }

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_BGP_NEXTHOP) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'bgp_nexthop' clauses part of the same statement. ", filename);
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

  Log(LOG_ERR, "ERROR ( %s ): 'bgp_nexthop' is not supported when a 'networks_file' is specified or by the 'pmacctd' daemon. ", filename);

  return TRUE;
}

int BPAS_map_bgp_nexthop_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0;

  e->bgp_nexthop.neg = pt_check_neg(&value);

  if (!str_to_addr(value, &e->bgp_nexthop.a)) {
    Log(LOG_ERR, "ERROR ( %s ): Bad BGP nexthop address '%s'. ", filename, value);
    return TRUE;
  }

  for (x = 0; e->func[x]; x++);
  if (config.nfacctd_bgp) e->func[x] = BPAS_bgp_nexthop_handler;

  return FALSE;
}

int BPAS_map_bgp_peer_dst_as_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  as_t tmp;
  int x = 0;
  char *endptr;

  e->peer_dst_as.neg = pt_check_neg(&value);

  tmp = strtoul(value, &endptr, 10);
  e->peer_dst_as.n = tmp;

  for (x = 0; e->func[x]; x++);
  if (config.nfacctd_bgp) e->func[x] = BPAS_bgp_peer_dst_as_handler; 

  return FALSE;
}

int BPAS_map_src_mac_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  struct pcap_device device;
  bpf_u_int32 localnet, netmask;  /* pcap library stuff */
  char errbuf[PCAP_ERRBUF_SIZE];
  char filter_str[28];
  int x, link_type;

  memset(&device, 0, sizeof(struct pcap_device));
  if (glob_pcapt) device.link_type = pcap_datalink(glob_pcapt);
  else device.link_type = 1;
  device.dev_desc = pcap_open_dead(device.link_type, 128); /* snaplen=eth_header+my_iphdr+my_tlhdr */

  pcap_lookupnet(config.dev, &localnet, &netmask, errbuf);

  memset(filter_str, 0, sizeof(filter_str));
  snprintf(filter_str, sizeof(filter_str), "ether src %s", value);
  if (pcap_compile(device.dev_desc, &e->filter, filter_str, 0, netmask) < 0) {
    Log(LOG_ERR, "ERROR ( %s ): malformed src_mac filter: %s\n", filename, pcap_geterr(device.dev_desc));
    return TRUE;
  }

  pcap_close(device.dev_desc);
  for (x = 0; e->func[x]; x++);
  e->func[x] = pretag_filter_handler;
  req->bpf_filter = TRUE;
  return FALSE;
}

int PT_map_engine_type_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, j, len;

  e->engine_type.neg = pt_check_neg(&value);
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR ( %s ): bad 'engine_type' value: '%s'. ", filename, value);
      return TRUE;
    }
    x++;
  }

  j = atoi(value);
  if (j > 255) {
    Log(LOG_ERR, "ERROR ( %s ): bad 'engine_type' value (range: 0 >= value > 256). ", filename);
    return TRUE;
  }
  e->engine_type.n = j; 

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_ENGINE_TYPE) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'engine_type' clauses part of the same statement. ", filename);
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

  e->engine_id.neg = pt_check_neg(&value);
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR ( %s ): bad 'engine_id' value: '%s'. ", filename, value);
      return TRUE;
    }
    x++;
  }

  j = atoi(value);
  if (j > 255) {
    Log(LOG_ERR, "ERROR ( %s ): bad 'engine_id' value (range: 0 >= value > 256). ", filename);
    return TRUE;
  }
  e->engine_id.n = j;

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_ENGINE_ID) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'engine_id' clauses part of the same statement. ", filename);
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
      Log(LOG_ERR, "ERROR ( %s ): bgp_agent_map filter supports only 'ip' and 'ip6' keywords\n", filename);
      return TRUE;
    }
  }

  memset(&device, 0, sizeof(struct pcap_device));
  if (glob_pcapt) device.link_type = pcap_datalink(glob_pcapt);
  else if (config.uacctd_group) device.link_type = DLT_RAW;
  else device.link_type = 1;
  device.dev_desc = pcap_open_dead(device.link_type, 128); /* snaplen=eth_header+my_iphdr+my_tlhdr */

  pcap_lookupnet(config.dev, &localnet, &netmask, errbuf);
  if (pcap_compile(device.dev_desc, &e->filter, value, 0, netmask) < 0) {
    Log(LOG_ERR, "ERROR ( %s ): malformed filter: %s\n", filename, pcap_geterr(device.dev_desc));
    return TRUE;
  }

  pcap_close(device.dev_desc);

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_FILTER) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'filter' clauses part of the same statement. ", filename);
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

  e->v8agg.neg = pt_check_neg(&value);
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR ( %s ): bad 'v8agg' value: '%s'. ", filename, value);
      return TRUE;
    }
    x++;
  }

  tmp = atoi(value);
  if (tmp < 1 || tmp > 14) {
    Log(LOG_ERR, "ERROR ( %s ): 'v8agg' need to be in the following range: 0 > value > 15. ", filename);
    return TRUE;
  }
  e->v8agg.n = tmp; 

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_NFV8_AGG) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'v8agg' clauses part of the same statement. ", filename);
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

  e->agent_id.neg = pt_check_neg(&value);
  e->agent_id.n = atoi(value);
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SF_AGENTID) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'agent_id' clauses part of the same statement. ", filename);
      return TRUE;
    }
  }
  if (config.acct_type == ACCT_SF) e->func[x] = SF_pretag_agent_id_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_SF_AGENTID;

  return FALSE;
}

int PT_map_sampling_rate_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0;

  e->sampling_rate.neg = pt_check_neg(&value);
  e->sampling_rate.n = atoi(value);
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SAMPLING_RATE) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'sampling_rate' clauses part of the same statement. ", filename);
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

  e->sample_type.neg = pt_check_neg(&value);

  if (acct_type == ACCT_SF && strchr(value, ':')) {
    while (token = extract_token(&value, ':')) {
      switch (x) {
      case 0:
        tmp = atoi(token);
        if (tmp > 1048575) { // 2^20-1: 20 bit Enterprise value
          Log(LOG_WARNING, "WARN ( %s ): Invalid 'sample_type' value. ", filename);
          return TRUE;
        }
        e->sample_type.n = tmp;
        e->sample_type.n <<= 12;
        break;
      case 1:
        tmp = atoi(token);
        if (tmp > 4095) { // 2^12-1: 12 bit Format value
          Log(LOG_WARNING, "WARN ( %s ): Invalid 'sample_type' value. ", filename);
          return TRUE;
        }
        e->sample_type.n |= tmp;
        break;
      default:
        Log(LOG_WARNING, "WARN ( %s ): Invalid 'sample_type' value. ", filename);
        return TRUE;
      }

      x++;
    }
  }
  else if (acct_type == ACCT_NF) {
    if (!strncmp(value, "flow", strlen("flow")))
      e->sample_type.n = NF9_FTYPE_TRAFFIC;
    else if (!strncmp(value, "event", strlen("event")))
      e->sample_type.n = NF9_FTYPE_EVENT;
    else {
      Log(LOG_WARNING, "WARN ( %s ): Invalid 'sample_type' value. ", filename);
      return TRUE;
    }
  }
  else return FALSE; /* silently ignore */

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SAMPLE_TYPE) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'sample_type' clauses part of the same statement. ", filename);
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

  e->direction.neg = pt_check_neg(&value);
  e->direction.n = atoi(value);
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_DIRECTION) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'direction' clauses part of the same statement. ", filename);
      return TRUE;
    }
  }
  if (config.acct_type == ACCT_NF) e->func[x] = pretag_direction_handler;
  if (e->func[x]) e->func_type[x] = PRETAG_DIRECTION;

  return FALSE;
}

int PT_map_src_as_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  as_t tmp;
  int x = 0, have_bgp = 0;
  char *endptr;

  e->src_as.neg = pt_check_neg(&value);

  tmp = strtoul(value, &endptr, 10);

  e->src_as.n = tmp;
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SRC_AS) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'src_as' clauses part of the same statement. ", filename);
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

  Log(LOG_ERR, "ERROR ( %s ): 'src_as' requires either 'networks_file' or 'nf|sfacctd_as_new: false' to be specified. ", filename);

  return TRUE;
}

int PT_map_dst_as_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  as_t tmp;
  int x = 0, have_bgp = 0;
  char *endptr;

  e->dst_as.neg = pt_check_neg(&value);

  tmp = strtoul(value, &endptr, 10);

  e->dst_as.n = tmp;
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_DST_AS) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'dst_as' clauses part of the same statement. ", filename);
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

  Log(LOG_ERR, "ERROR ( %s ): 'dst_as' requires either 'networks_file' or 'nf|sfacctd_as_new: false' to be specified. ", filename);

  return TRUE;
}

int PT_map_peer_src_as_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  as_t tmp;
  int x = 0;
  char *endptr;

  e->peer_src_as.neg = pt_check_neg(&value);

  tmp = strtoul(value, &endptr, 10);

  e->peer_src_as.n = tmp;
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_PEER_SRC_AS) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'peer_src_as' clauses part of the same statement. ", filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP) {
    e->func[x] = pretag_peer_src_as_handler;
    e->func_type[x] = PRETAG_PEER_SRC_AS; 
    return FALSE;
  }

  Log(LOG_ERR, "ERROR ( %s ): 'peer_src_as' requires '[nf|sf]acctd_as_new: [ bgp | fallback ]' to be specified. ", filename);

  return TRUE;
}

int PT_map_peer_dst_as_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  as_t tmp;
  int x = 0;
  char *endptr;

  e->peer_dst_as.neg = pt_check_neg(&value);

  tmp = strtoul(value, &endptr, 10);

  e->peer_dst_as.n = tmp;
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_PEER_DST_AS) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'peer_dst_as' clauses part of the same statement. ", filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP) {
    e->func[x] = pretag_peer_dst_as_handler;
    e->func_type[x] = PRETAG_PEER_DST_AS; 
    return FALSE;
  } 

  Log(LOG_ERR, "ERROR ( %s ): 'peer_dst_as' requires '[nf|sf]acctd_as_new: [ bgp | fallback ]' to be specified. ", filename);

  return TRUE;
}

int PT_map_src_local_pref_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  u_int32_t tmp;
  int x = 0;
  char *endptr;

  e->src_local_pref.neg = pt_check_neg(&value);

  tmp = strtoul(value, &endptr, 10);

  e->src_local_pref.n = tmp;
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SRC_LOCAL_PREF) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'src_local_pref' clauses part of the same statement. ", filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP) {
    e->func[x] = pretag_src_local_pref_handler;
    e->func_type[x] = PRETAG_SRC_LOCAL_PREF;
    return FALSE;
  }

  Log(LOG_ERR, "ERROR ( %s ): 'src_local_pref' requires '[nf|sf]acctd_as_new: [ bgp | fallback ]' to be specified. ", filename);

  return TRUE;
}

int PT_map_local_pref_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  u_int32_t tmp;
  int x = 0;
  char *endptr;

  e->local_pref.neg = pt_check_neg(&value);

  tmp = strtoul(value, &endptr, 10);

  e->local_pref.n = tmp;
  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_LOCAL_PREF) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'local_pref' clauses part of the same statement. ", filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP) {
    e->func[x] = pretag_local_pref_handler;
    e->func_type[x] = PRETAG_LOCAL_PREF;
    return FALSE;
  }

  Log(LOG_ERR, "ERROR ( %s ): 'local_pref' requires '[nf|sf]acctd_as_new: [ bgp | fallback ]' to be specified. ", filename);

  return TRUE;
}

int PT_map_src_comms_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, idx = 0;
  char *endptr, *token;

  memset(e->src_comms, 0, sizeof(e->src_comms));

  /* Negation not supported here */

  while ( (token = extract_token(&value, ',')) && idx < MAX_BGP_COMM_PATTERNS ) {
    e->src_comms[idx] = malloc(MAX_BGP_STD_COMMS);
    strlcpy(e->src_comms[idx], token, MAX_BGP_STD_COMMS);
    trim_spaces(e->src_comms[idx]);
    idx++;
  }

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_SRC_STD_COMM) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'src_comms' clauses part of the same statement. ", filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP && e->src_comms[0]) {
    e->func[x] = pretag_src_comms_handler;
    e->func_type[x] = PRETAG_SRC_STD_COMM;
    return FALSE;
  }

  Log(LOG_ERR, "ERROR ( %s ): 'src_comms' requires '[nf|sf]acctd_as_new: [ bgp | fallback ]' to be specified. ", filename);

  return TRUE;
}

int PT_map_comms_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, idx = 0;
  char *endptr, *token;

  memset(e->comms, 0, sizeof(e->comms));

  /* Negation not supported here */

  while ( (token = extract_token(&value, ',')) && idx < MAX_BGP_COMM_PATTERNS ) {
    e->comms[idx] = malloc(MAX_BGP_STD_COMMS);
    strlcpy(e->comms[idx], token, MAX_BGP_STD_COMMS);
    trim_spaces(e->comms[idx]);
    idx++;
  }

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_STD_COMM) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'comms' clauses part of the same statement. ", filename);
      return TRUE;
    }
  }

  if (config.nfacctd_as & NF_AS_BGP && e->comms[0]) {
    e->func[x] = pretag_comms_handler;
    e->func_type[x] = PRETAG_STD_COMM;
    return FALSE;
  }

  Log(LOG_ERR, "ERROR ( %s ): 'comms' requires '[nf|sf]acctd_as_new: [ bgp | fallback ]' to be specified. ", filename);

  return TRUE;
}

int PT_map_mpls_vpn_rd_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, ret;
  char *endptr, *token;

  memset(&e->mpls_vpn_rd, 0, sizeof(e->mpls_vpn_rd));

  e->mpls_vpn_rd.neg = pt_check_neg(&value);
  ret = bgp_str2rd(&e->mpls_vpn_rd.rd, value);

  for (x = 0; e->func[x]; x++) {
    if (e->func_type[x] == PRETAG_MPLS_VPN_RD) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'mpls_vpn_rd' clauses part of the same statement. ", filename);
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

int PT_map_set_tos_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int x = 0, len;
  char *endptr;

  e->set_tos.set = TRUE;
  len = strlen(value);

  while (x < len) {
    if (!isdigit(value[x])) {
      Log(LOG_ERR, "ERROR ( %s ): bad 'set_tos' value: '%s'. ", filename, value);
      return TRUE;
    }
    x++;
  }

  e->set_tos.n = strtoul(value, &endptr, 10);
  for (x = 0; e->set_func[x]; x++) {
    if (e->set_func_type[x] == PRETAG_SET_TOS) {
      Log(LOG_ERR, "ERROR ( %s ): Multiple 'set_tos' clauses part of the same statement. ", filename);
      return TRUE;
    }
  }

  /* feature currently only supported in nfacctd */
  if (config.acct_type == ACCT_NF) e->set_func[x] = pretag_set_tos_handler;

  if (e->set_func[x]) e->set_func_type[x] = PRETAG_SET_TOS;

  return FALSE;
}

int PT_map_label_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  strlcpy(e->label, value, MAX_LABEL_LEN); 

  return FALSE;
}

int PT_map_jeq_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  e->jeq.label = malloc(MAX_LABEL_LEN);
  if (e->jeq.label) strlcpy(e->jeq.label, value, MAX_LABEL_LEN);
  else Log(LOG_ERR, "ERROR ( %s ): Not enough memory to allocate JEQ '%s'\n", filename, value); 

  return FALSE;
}

int PT_map_return_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  int res = parse_truefalse(value);
  if (res < 0) Log(LOG_ERR, "ERROR ( %s ): Unknown RETURN value: '%s'. Ignoring.\n", filename, value);
  else e->ret = res;

  return FALSE;
}

int PT_map_stack_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  e->stack.func = NULL;

  if (*value == '+') e->stack.func = PT_stack_sum;
  else Log(LOG_ERR, "ERROR ( %s ): Unknown STACK operator: '%c'. Ignoring.\n", filename, value);

  return FALSE;
}

int pretag_input_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t input16 = htons(entry->input.n);
  u_int32_t input32 = htonl(entry->input.n);
  u_int8_t neg = entry->input.neg;

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
  u_int16_t output16 = htons(entry->output.n);
  u_int32_t output32 = htonl(entry->output.n);
  u_int8_t neg = entry->output.neg;

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
    if (entry->nexthop.a.family == AF_INET) {
      if (!memcmp(&entry->nexthop.a.address.ipv4, pptrs->f_data+tpl->tpl[NF9_IPV4_NEXT_HOP].off, tpl->tpl[NF9_IPV4_NEXT_HOP].len))
	return (FALSE | entry->nexthop.neg);
    }
#if defined ENABLE_IPV6
    else if (entry->nexthop.a.family == AF_INET6) {
      if (!memcmp(&entry->nexthop.a.address.ipv6, pptrs->f_data+tpl->tpl[NF9_IPV6_NEXT_HOP].off, tpl->tpl[NF9_IPV6_NEXT_HOP].len))
	return (FALSE | entry->nexthop.neg);
    }
#endif
    else return (TRUE ^ entry->nexthop.neg);
  case 8:
    /* NetFlow v8 does not seem to contain any nexthop field */
    return TRUE;
  default:
    if (entry->nexthop.a.address.ipv4.s_addr == ((struct struct_export_v5 *)pptrs->f_data)->nexthop.s_addr) return (FALSE | entry->nexthop.neg);
    else return (TRUE ^ entry->nexthop.neg);
  }
}

int pretag_bgp_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;

  if (entry->last_matched == PRETAG_BGP_NEXTHOP) return FALSE;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, config.nfacctd_net, NF_NET_KEEP)) return;

  switch(hdr->version) {
  case 10:
  case 9:
    if (entry->bgp_nexthop.a.family == AF_INET) {
      if (!memcmp(&entry->bgp_nexthop.a.address.ipv4, pptrs->f_data+tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].off, tpl->tpl[NF9_BGP_IPV4_NEXT_HOP].len))
	return (FALSE | entry->bgp_nexthop.neg);
    }
#if defined ENABLE_IPV6
    else if (entry->nexthop.a.family == AF_INET6) {
      if (!memcmp(&entry->bgp_nexthop.a.address.ipv6, pptrs->f_data+tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].off, tpl->tpl[NF9_BGP_IPV6_NEXT_HOP].len))
	return (FALSE | entry->bgp_nexthop.neg);
    }
#endif
    else return (TRUE ^ entry->bgp_nexthop.neg);
  case 8:
    /* NetFlow v8 does not seem to contain any nexthop field */
    return TRUE;
  default:
    if (entry->bgp_nexthop.a.address.ipv4.s_addr == ((struct struct_export_v5 *)pptrs->f_data)->nexthop.s_addr) return (FALSE | entry->bgp_nexthop.neg);
    else return (TRUE ^ entry->bgp_nexthop.neg);
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
  if (!evaluate_lm_method(pptrs, TRUE, config.nfacctd_net, NF_NET_BGP)) return;

  if (dst_ret) {
    if (pptrs->bgp_nexthop_info)
      info = (struct bgp_info *) pptrs->bgp_nexthop_info;
    else
      info = (struct bgp_info *) pptrs->bgp_dst_info;

    if (info && info->attr) {
      if (info->attr->mp_nexthop.family == AF_INET) {
        ret = memcmp(&entry->bgp_nexthop.a.address.ipv4, &info->attr->mp_nexthop.address.ipv4, 4);
      }
#if defined ENABLE_IPV6
      else if (info->attr->mp_nexthop.family == AF_INET6) {
        ret = memcmp(&entry->bgp_nexthop.a.address.ipv6, &info->attr->mp_nexthop.address.ipv6, 16);
      }
#endif
      else {
	ret = memcmp(&entry->bgp_nexthop.a.address.ipv4, &info->attr->nexthop, 4);
      }
    }
  }

  if (!ret) {
    entry->last_matched = PRETAG_BGP_NEXTHOP;
    return (FALSE | entry->bgp_nexthop.neg);
  }
  else if (config.nfacctd_as & NF_AS_KEEP) return FALSE;
  else return (TRUE ^ entry->bgp_nexthop.neg);
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
    if (entry->engine_type.n == (u_int8_t)value[2]) return (FALSE | entry->engine_type.neg);
    else return (TRUE ^ entry->engine_type.neg);
  }
  case 9:
  {
    struct struct_header_v9 *hdr = (struct struct_header_v9 *) pptrs->f_header;

    memcpy(value, &hdr->source_id, 4);
    if (entry->engine_type.n == (u_int8_t)value[2]) return (FALSE | entry->engine_type.neg);
    else return (TRUE ^ entry->engine_type.neg);
  }
  case 8:
    if (entry->engine_type.n == ((struct struct_header_v8 *)pptrs->f_header)->engine_type) return (FALSE | entry->engine_type.neg);
    else return (TRUE ^ entry->engine_type.neg);
  case 5:
    if (entry->engine_type.n == ((struct struct_header_v5 *)pptrs->f_header)->engine_type) return (FALSE | entry->engine_type.neg);
    else return (TRUE ^ entry->engine_type.neg);
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
    if (entry->engine_id.n == (u_int8_t)value[3]) return (FALSE | entry->engine_id.neg);
    else return (TRUE ^ entry->engine_id.neg);
  }
  case 9:
  {
    struct struct_header_v9 *hdr = (struct struct_header_v9 *) pptrs->f_header;

    memcpy(value, &hdr->source_id, 4);
    if (entry->engine_id.n == (u_int8_t)value[3]) return (FALSE | entry->engine_id.neg);
    else return (TRUE ^ entry->engine_id.neg);
  }
  case 8:
    if (entry->engine_id.n == ((struct struct_header_v8 *)pptrs->f_header)->engine_id) return (FALSE | entry->engine_id.neg);
    else return (TRUE ^ entry->engine_id.neg);
  case 5:
    if (entry->engine_id.n == ((struct struct_header_v5 *)pptrs->f_header)->engine_id) return (FALSE | entry->engine_id.neg);
    else return (TRUE ^ entry->engine_id.neg);
  default:
    return TRUE; /* this field does not exist: condition is always true */
  }
}

int pretag_filter_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;

  if (bpf_filter(entry->filter.bf_insns, pptrs->packet_ptr, pptrs->pkthdr->len, pptrs->pkthdr->caplen)) 
    return FALSE; /* matched filter */
  else return TRUE;
}

int pretag_v8agg_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;

  switch(hdr->version) {
  case 8:
    if (entry->v8agg.n == ((struct struct_header_v8 *)pptrs->f_header)->aggregation) return (FALSE | entry->v8agg.neg);
    else return (TRUE ^ entry->v8agg.neg);
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

  if (entry->src_as.n == asn32) return (FALSE | entry->src_as.neg);
  else return (TRUE ^ entry->src_as.neg);
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

  if (entry->src_as.n == asn) {
    entry->last_matched = PRETAG_SRC_AS;
    return (FALSE | entry->src_as.neg);
  }
  else if (config.nfacctd_as & NF_AS_KEEP) return FALSE; 
  else return (TRUE ^ entry->src_as.neg);
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

  if (entry->dst_as.n == asn32) return (FALSE | entry->dst_as.neg);
  else return (TRUE ^ entry->dst_as.neg);
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

  if (entry->dst_as.n == asn) {
    entry->last_matched = PRETAG_DST_AS;
    return (FALSE | entry->dst_as.neg);
  }
  else if (config.nfacctd_as & NF_AS_KEEP) return FALSE;
  else return (TRUE ^ entry->dst_as.neg);
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

  if (entry->peer_src_as.n == asn) return (FALSE | entry->peer_src_as.neg);
  else return (TRUE ^ entry->peer_src_as.neg);
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

  if (entry->peer_dst_as.n == asn) return (FALSE | entry->peer_dst_as.neg);
  else return (TRUE ^ entry->peer_dst_as.neg);
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

  if (entry->src_local_pref.n == local_pref) return (FALSE | entry->src_local_pref.neg);
  else return (TRUE ^ entry->src_local_pref.neg);
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

  if (entry->local_pref.n == local_pref) return (FALSE | entry->local_pref.neg);
  else return (TRUE ^ entry->local_pref.neg);
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
      evaluate_comm_patterns(tmp_stdcomms, info->attr->community->str, entry->src_comms, MAX_BGP_STD_COMMS);
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
      evaluate_comm_patterns(tmp_stdcomms, info->attr->community->str, entry->comms, MAX_BGP_STD_COMMS);
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

  if (entry->sample_type.n == pptrs->flow_type) return (FALSE | entry->sample_type.neg); 
  else return (TRUE ^ entry->sample_type.neg);
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
    if (entry->sampling_rate.n == srate) return (FALSE | entry->sampling_rate.neg);
    else return (TRUE ^ entry->sampling_rate.neg);
  default:
    return TRUE; /* this field might not apply: condition is always true */
  }
}

int pretag_direction_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  struct struct_header_v8 *hdr = (struct struct_header_v8 *) pptrs->f_header;
  struct template_cache_entry *tpl = (struct template_cache_entry *) pptrs->f_tpl;
  u_int16_t direction = 0;

  switch (hdr->version) {
  case 10:
  case 9:
    if (tpl->tpl[NF9_DIRECTION].len == 1) {
      memcpy(&direction, pptrs->f_data+tpl->tpl[NF9_DIRECTION].off, 1);
    }
    if (entry->direction.n == direction) return (FALSE | entry->direction.neg);
    else return (TRUE ^ entry->direction.neg);
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
      ret = memcmp(&entry->mpls_vpn_rd.rd, &info->extra->rd, sizeof(rd_t)); 
    }
  }

  if (!ret) return (FALSE | entry->mpls_vpn_rd.neg);
  else return (TRUE ^ entry->mpls_vpn_rd.neg);
}

int pretag_set_tos_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;

  memcpy(&pptrs->set_tos, &entry->set_tos, sizeof(s_uint8_t));

  return PRETAG_MAP_RCODE_SET_TOS;
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

  return PRETAG_MAP_RCODE_ID2; /* cap */
}

int SF_pretag_input_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->input.n == sample->inputPort) return (FALSE | entry->input.neg);
  else return (TRUE ^ entry->input.neg); 
}

int SF_pretag_output_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->output.n == sample->outputPort) return (FALSE | entry->output.neg);
  else return (TRUE ^ entry->output.neg);
}

int SF_pretag_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->nexthop.a.family == AF_INET) {
    if (!memcmp(&entry->nexthop.a.address.ipv4, &sample->nextHop.address.ip_v4, 4)) return (FALSE | entry->nexthop.neg);
  }
#if defined ENABLE_IPV6
  else if (entry->nexthop.a.family == AF_INET6) {
    if (!memcmp(&entry->nexthop.a.address.ipv6, &sample->nextHop.address.ip_v6, IP6AddrSz)) return (FALSE | entry->nexthop.neg);
  }
#endif
  else return (TRUE ^ entry->nexthop.neg);
}

int SF_pretag_bgp_nexthop_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  /* check network-related primitives against fallback scenarios */
  if (!evaluate_lm_method(pptrs, TRUE, config.nfacctd_net, NF_NET_KEEP)) return;

  if (entry->bgp_nexthop.a.family == AF_INET) {
    if (!memcmp(&entry->bgp_nexthop.a.address.ipv4, &sample->bgp_nextHop.address.ip_v4, 4)) return (FALSE | entry->bgp_nexthop.neg);
  }
#if defined ENABLE_IPV6
  else if (entry->bgp_nexthop.a.family == AF_INET6) {
    if (!memcmp(&entry->bgp_nexthop.a.address.ipv6, &sample->bgp_nextHop.address.ip_v6, IP6AddrSz)) return (FALSE | entry->bgp_nexthop.neg);
  }
#endif
  else return (TRUE ^ entry->bgp_nexthop.neg);
}

int SF_pretag_agent_id_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->agent_id.n == sample->agentSubId) return (FALSE | entry->agent_id.neg);
  else return (TRUE ^ entry->agent_id.neg);
}

int SF_pretag_sampling_rate_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->sampling_rate.n == sample->meanSkipCount) return (FALSE | entry->sampling_rate.neg);
  else return (TRUE ^ entry->sampling_rate.neg);
}

int SF_pretag_sample_type_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  if (entry->sample_type.n == pptrs->sample_type) return (FALSE | entry->sample_type.neg);
  else return (TRUE ^ entry->sample_type.neg);
}

int SF_pretag_src_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  /* If in a fallback scenario, ie. NF_AS_BGP + NF_AS_KEEP set, check BGP first */
  if (config.nfacctd_as & NF_AS_BGP && pptrs->bgp_src) return FALSE;

  if (entry->src_as.n == sample->src_as) return (FALSE | entry->src_as.neg);
  else return (TRUE ^ entry->src_as.neg);
}

int SF_pretag_dst_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  SFSample *sample = (SFSample *) pptrs->f_data;

  /* If in a fallback scenario, ie. NF_AS_BGP + NF_AS_KEEP set, check BGP first */
  if (config.nfacctd_as & NF_AS_BGP && pptrs->bgp_dst) return FALSE;

  if (entry->dst_as.n == sample->dst_as) return (FALSE | entry->dst_as.neg);
  else return (TRUE ^ entry->dst_as.neg);
}

int PM_pretag_src_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  as_t res = search_pretag_src_as(&nt, &nc, pptrs);

  if (entry->src_as.n == res) return (FALSE | entry->src_as.neg);
  else return (TRUE ^ entry->src_as.neg);
}

int PM_pretag_dst_as_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;
  as_t res = search_pretag_dst_as(&nt, &nc, pptrs);

  if (entry->dst_as.n == res) return (FALSE | entry->dst_as.neg);
  else return (TRUE ^ entry->dst_as.neg);
}

int PM_pretag_input_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;

  if (entry->input.n == pptrs->ifindex_in) return (FALSE | entry->input.neg);
  else return (TRUE ^ entry->input.neg);
}

int PM_pretag_output_handler(struct packet_ptrs *pptrs, void *unused, void *e)
{
  struct id_entry *entry = e;

  if (entry->output.n == pptrs->ifindex_out) return (FALSE | entry->output.neg);
  else return (TRUE ^ entry->output.neg);
}

pm_id_t PT_stack_sum(pm_id_t tag, pm_id_t pre)
{
  return tag + pre;
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
      if (entry->bgp_nexthop.a.family == AF_INET) {
	if (info->attr->mp_nexthop.family == AF_INET) {
          if (!memcmp(&entry->bgp_nexthop.a.address.ipv4, &info->attr->mp_nexthop.address.ipv4, 4))
            return (FALSE | entry->bgp_nexthop.neg);
	}
	else {
          if (!memcmp(&entry->bgp_nexthop.a.address.ipv4, &info->attr->nexthop, 4))
            return (FALSE | entry->bgp_nexthop.neg);
	}
      }
#if defined ENABLE_IPV6
      else if (entry->nexthop.a.family == AF_INET6) {
	if (!memcmp(&entry->bgp_nexthop.a.address.ipv6, &info->attr->mp_nexthop.address.ipv6, 16))
          return (FALSE | entry->bgp_nexthop.neg);
      }
#endif
    }
  }

  return (TRUE ^ entry->bgp_nexthop.neg);
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

  if (entry->peer_dst_as.n == asn) return (FALSE | entry->peer_dst_as.neg);
  else return (TRUE ^ entry->peer_dst_as.neg);
}
