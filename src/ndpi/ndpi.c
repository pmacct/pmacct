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

/*
    Originally based on:
    ndpi.c ndpiReader.c | nDPI | Copyright (C) 2011-17 - ntop.org
*/

#include "../pmacct.h"
#include "../ip_flow.h"
#include "../classifier.h"
#include "ndpi.h"

/* Global variables */
struct pm_ndpi_workflow *pm_ndpi_wfl;

void pm_ndpi_free_flow_info_half(struct pm_ndpi_flow_info *flow)
{
  if (flow) {
    if (flow->ndpi_flow) {
      ndpi_flow_free(flow->ndpi_flow);
      flow->ndpi_flow = NULL;
    }

    if (flow->src_id) {
      ndpi_free(flow->src_id);
      flow->src_id = NULL;
    }

    if (flow->dst_id) {
      ndpi_free(flow->dst_id);
      flow->dst_id = NULL;
    }
  }
}

int pm_ndpi_workflow_node_cmp(const void *a, const void *b)
{
  struct pm_ndpi_flow_info *fa = (struct pm_ndpi_flow_info*)a;
  struct pm_ndpi_flow_info *fb = (struct pm_ndpi_flow_info*)b;

  if(fa->vlan_id   < fb->vlan_id  )   return(-1); else { if(fa->vlan_id   > fb->vlan_id    ) return(1); }
  if(fa->lower_ip   < fb->lower_ip  ) return(-1); else { if(fa->lower_ip   > fb->lower_ip  ) return(1); }
  if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
  if(fa->upper_ip   < fb->upper_ip  ) return(-1); else { if(fa->upper_ip   > fb->upper_ip  ) return(1); }
  if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
  if(fa->protocol   < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

  return(0);
}

struct pm_ndpi_flow_info *pm_ndpi_get_flow_info(struct pm_ndpi_workflow *workflow,
						 struct packet_ptrs *pptrs,
						 u_int16_t vlan_id,
						 const struct ndpi_iphdr *iph,
						 const struct ndpi_ipv6hdr *iph6,
						 u_int16_t ip_offset,
						 u_int16_t ipsize,
						 u_int16_t l4_packet_len,
						 struct ndpi_tcphdr **tcph,
						 struct ndpi_udphdr **udph,
						 u_int16_t *sport, u_int16_t *dport,
						 struct ndpi_id_struct **src,
						 struct ndpi_id_struct **dst,
						 u_int8_t *proto,
						 u_int8_t **payload,
						 u_int16_t *payload_len,
						 u_int8_t *src_to_dst_direction)
{
  u_int32_t idx;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  struct pm_ndpi_flow_info flow;
  void *ret;
  u_int8_t *l4;

  /* IPv4 fragments handling */
  if (pptrs->l3_proto == ETHERTYPE_IP) {
    if ((((struct pm_iphdr *)pptrs->iph_ptr)->ip_off & htons(IP_OFFMASK))) {
      if (!log_notification_isset(&log_notifications.ndpi_tmp_frag_warn, pptrs->pkthdr->ts.tv_sec)) {
        Log(LOG_WARNING, "WARN ( %s/core ): nDPI support for fragmented traffic not implemented. %s: %s\n", config.name, GET_IN_TOUCH_MSG, MANTAINER);
        log_notification_set(&log_notifications.ndpi_cache_full, pptrs->pkthdr->ts.tv_sec, 180);
      }

      if (pptrs->frag_first_found) {
	// XXX
      }
      else return NULL;
    }
  }

  if (iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  }
  else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  *proto = iph->protocol;
  l4 = (u_int8_t *) pptrs->tlh_ptr;

  /* TCP */
  if (iph->protocol == IPPROTO_TCP && l4_packet_len >= 20) {
    u_int tcp_len;

    *tcph = (struct ndpi_tcphdr *)l4;
    *sport = ntohs((*tcph)->source), *dport = ntohs((*tcph)->dest);

    if (iph->saddr < iph->daddr) {
      lower_port = (*tcph)->source, upper_port = (*tcph)->dest;
      *src_to_dst_direction = 1;
    }
    else {
      lower_port = (*tcph)->dest;
      upper_port = (*tcph)->source;

      *src_to_dst_direction = 0;
      if (iph->saddr == iph->daddr) {
	if (lower_port > upper_port) {
	  u_int16_t p = lower_port;

	  lower_port = upper_port;
	  upper_port = p;
	}
      }
    }

    tcp_len = ndpi_min(4*(*tcph)->doff, l4_packet_len);
    *payload = &l4[tcp_len];
    *payload_len = ndpi_max(0, l4_packet_len-4*(*tcph)->doff);
  }
  /* UDP */
  else if (iph->protocol == IPPROTO_UDP && l4_packet_len >= 8) {
    *udph = (struct ndpi_udphdr *)l4;
    *sport = ntohs((*udph)->source), *dport = ntohs((*udph)->dest);
    *payload = &l4[sizeof(struct ndpi_udphdr)];
    *payload_len = ndpi_max(0, l4_packet_len-sizeof(struct ndpi_udphdr));

    if (iph->saddr < iph->daddr) {
      lower_port = (*udph)->source, upper_port = (*udph)->dest;
      *src_to_dst_direction = 1;
    }
    else {
      lower_port = (*udph)->dest, upper_port = (*udph)->source;

      *src_to_dst_direction = 0;

      if (iph->saddr == iph->daddr) {
	if (lower_port > upper_port) {
	  u_int16_t p = lower_port;

	  lower_port = upper_port;
	  upper_port = p;
	}
      }
    }

    *sport = ntohs(lower_port), *dport = ntohs(upper_port);
  }
  else {
    // non tcp/udp protocols
    lower_port = 0;
    upper_port = 0;
  }

  flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
  flow.lower_ip = lower_ip, flow.upper_ip = upper_ip;
  flow.lower_port = lower_port, flow.upper_port = upper_port;

/*
  Log(LOG_DEBUG, "DEBUG ( %s/core ): "pm_ndpi_get_flow_info(): [%u][%u:%u <-> %u:%u]\n",
	iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));
*/

  idx = (vlan_id + lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % workflow->prefs.num_roots;
  ret = pm_tfind(&flow, &workflow->ndpi_flows_root[idx], pm_ndpi_workflow_node_cmp);

  if (ret == NULL) {
    if (workflow->stats.ndpi_flow_count == workflow->prefs.max_ndpi_flows) {
      if (!log_notification_isset(&log_notifications.ndpi_cache_full, pptrs->pkthdr->ts.tv_sec)) {
        Log(LOG_WARNING, "WARN ( %s/core ): nDPI maximum flow count (%u) has been exceeded.\n", config.name, workflow->prefs.max_ndpi_flows);
	log_notification_set(&log_notifications.ndpi_cache_full, pptrs->pkthdr->ts.tv_sec, 60);
      }

      return(NULL);
    }
    else {
      struct pm_ndpi_flow_info *newflow = (struct pm_ndpi_flow_info*)malloc(sizeof(struct pm_ndpi_flow_info));

      if (newflow == NULL) {
	Log(LOG_ERR, "ERROR ( %s/core ): pm_ndpi_get_flow_info() not enough memory (1).\n", config.name);
	exit_gracefully(1);
      }

      memset(newflow, 0, sizeof(struct pm_ndpi_flow_info));
      newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
      newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
      newflow->lower_port = lower_port, newflow->upper_port = upper_port;
      newflow->ip_version = pptrs->l3_proto;
      newflow->src_to_dst_direction = *src_to_dst_direction;

      if ((newflow->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT)) == NULL) {
	Log(LOG_ERR, "ERROR ( %s/core ): pm_ndpi_get_flow_info() not enough memory (2).\n", config.name);
	exit_gracefully(1);
      }
      else memset(newflow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

      if ((newflow->src_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) {
	Log(LOG_ERR, "ERROR ( %s/core ): pm_ndpi_get_flow_info() not enough memory (3).\n", config.name);
	exit_gracefully(1);
      }
      else memset(newflow->src_id, 0, SIZEOF_ID_STRUCT);

      if ((newflow->dst_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) {
	Log(LOG_ERR, "ERROR ( %s/core ): pm_ndpi_get_flow_info() not enough memory (4).\n", config.name);
	exit_gracefully(1);
      }
      else memset(newflow->dst_id, 0, SIZEOF_ID_STRUCT);

      pm_tsearch(newflow, &workflow->ndpi_flows_root[idx], pm_ndpi_workflow_node_cmp, 0); /* Add */
      workflow->stats.ndpi_flow_count++;

      *src = newflow->src_id, *dst = newflow->dst_id;

      return newflow;
    }
  }
  else {
    struct pm_ndpi_flow_info *flow = *(struct pm_ndpi_flow_info**)ret;

    if (flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
       && flow->lower_port == lower_port && flow->upper_port == upper_port)
      *src = flow->src_id, *dst = flow->dst_id;
    else
      *src = flow->dst_id, *dst = flow->src_id;

    return flow;
  }
}

struct pm_ndpi_flow_info *pm_ndpi_get_flow_info6(struct pm_ndpi_workflow *workflow,
						  struct packet_ptrs *pptrs,
						  u_int16_t vlan_id,
						  const struct ndpi_ipv6hdr *iph6,
						  u_int16_t ip_offset,
						  struct ndpi_tcphdr **tcph,
						  struct ndpi_udphdr **udph,
						  u_int16_t *sport, u_int16_t *dport,
						  struct ndpi_id_struct **src,
						  struct ndpi_id_struct **dst,
						  u_int8_t *proto,
						  u_int8_t **payload,
						  u_int16_t *payload_len,
						  u_int8_t *src_to_dst_direction)
{
  struct ndpi_iphdr iph;

  memset(&iph, 0, sizeof(iph));
  iph.version = IPVERSION;
  iph.saddr = iph6->ip6_src.u6_addr.u6_addr32[2] + iph6->ip6_src.u6_addr.u6_addr32[3];
  iph.daddr = iph6->ip6_dst.u6_addr.u6_addr32[2] + iph6->ip6_dst.u6_addr.u6_addr32[3];
  iph.protocol = iph6->ip6_hdr.ip6_un1_nxt;

  if (iph.protocol == IPPROTO_DSTOPTS /* IPv6 destination option */) {
    u_int8_t *options = (u_int8_t*)iph6 + sizeof(const struct ndpi_ipv6hdr);

    iph.protocol = options[0];
  }

  return(pm_ndpi_get_flow_info(workflow, pptrs, vlan_id, &iph, iph6, ip_offset,
			    sizeof(struct ndpi_ipv6hdr),
			    ntohs(iph6->ip6_hdr.ip6_un1_plen),
			    tcph, udph, sport, dport,
			    src, dst, proto, payload, payload_len, src_to_dst_direction));
}

/*
   Function to process the packet:
   determine the flow of a packet and try to decode it
   @return: 0 if success; else != 0

   @Note: ipsize = header->len - ip_offset ; rawsize = header->len
*/
struct ndpi_proto pm_ndpi_packet_processing(struct pm_ndpi_workflow *workflow,
					   struct packet_ptrs *pptrs,
					   const u_int64_t time,
					   u_int16_t vlan_id,
					   const struct ndpi_iphdr *iph,
					   struct ndpi_ipv6hdr *iph6,
					   u_int16_t ip_offset,
					   u_int16_t ipsize, u_int16_t rawsize)
{
  struct ndpi_id_struct *src, *dst;
  struct pm_ndpi_flow_info *flow = NULL;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int8_t proto;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int16_t sport, dport, payload_len;
  u_int8_t *payload;
  u_int8_t src_to_dst_direction = 1;
  struct ndpi_proto nproto = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };

  if (!workflow) return nproto;

  if (iph)
    flow = pm_ndpi_get_flow_info(workflow, pptrs, vlan_id, iph, NULL,
			      ip_offset, ipsize,
			      ntohs(iph->tot_len) - (iph->ihl * 4),
			      &tcph, &udph, &sport, &dport,
			      &src, &dst, &proto,
			      &payload, &payload_len, &src_to_dst_direction);
  else if (iph6)
    flow = pm_ndpi_get_flow_info6(workflow, pptrs, vlan_id, iph6, ip_offset,
			       &tcph, &udph, &sport, &dport,
			       &src, &dst, &proto,
			       &payload, &payload_len, &src_to_dst_direction);

  if (flow) {
    workflow->stats.ip_packet_count++;
    workflow->stats.total_wire_bytes += rawsize + 24 /* CRC etc */,
    workflow->stats.total_ip_bytes += rawsize;
    ndpi_flow = flow->ndpi_flow;
    flow->packets++, flow->bytes += rawsize;
    flow->last_seen = time;
  }
  else { // flow is NULL
    workflow->stats.total_discarded_bytes++;
    return (nproto);
  }

  /* Protocol already detected */
  if (flow->detection_completed) return(flow->detected_protocol);

  flow->detected_protocol = ndpi_detection_process_packet(workflow->ndpi_struct, ndpi_flow,
							  iph ? (uint8_t *)iph : (uint8_t *)iph6,
							  ipsize, time, src, dst);

  if ((flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
     || ((proto == IPPROTO_UDP) && (flow->packets > workflow->prefs.giveup_proto_tcp))
     || ((proto == IPPROTO_TCP) && (flow->packets > workflow->prefs.giveup_proto_udp))
     || ((proto != IPPROTO_UDP && proto != IPPROTO_TCP) && (flow->packets > workflow->prefs.giveup_proto_other))) {
    /* New protocol detected or give up */
    flow->detection_completed = TRUE;
  }

  if (proto == IPPROTO_TCP) {
    struct pm_tcphdr *tcph = (struct pm_tcphdr *) pptrs->tlh_ptr;
    if (tcph->th_flags & (TH_FIN|TH_RST)) flow->tcp_finished = TRUE;
  }

  if (flow->detection_completed || flow->tcp_finished) {
    if (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
      flow->detected_protocol = ndpi_detection_giveup(workflow->ndpi_struct, flow->ndpi_flow, 1, &workflow->prefs.protocol_guess);
    }

    if (workflow->prefs.protocol_guess) {
      if (flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN && !flow->guess_completed) {
        pm_ndpi_node_guess_undetected_protocol(workflow, flow);
	flow->guess_completed = TRUE;
      }
    }
  }

  return(flow->detected_protocol);
}

struct ndpi_proto pm_ndpi_workflow_process_packet(struct pm_ndpi_workflow *workflow, struct packet_ptrs *pptrs)
{
  struct ndpi_iphdr *iph = NULL;
  struct ndpi_ipv6hdr *iph6 = NULL;
  struct ndpi_proto nproto = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };
  u_int64_t time = 0;
  u_int16_t ip_offset = 0, vlan_id = 0;

  if (!workflow || !pptrs) return nproto;

  if (pptrs->l3_proto == ETHERTYPE_IP) iph = (struct ndpi_iphdr *) pptrs->iph_ptr;
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) iph6 = (struct ndpi_ipv6hdr *) pptrs->iph_ptr;

  /* Increment raw packet counter */
  workflow->stats.raw_packet_count++;

  /* setting time */
  time = ((uint64_t) pptrs->pkthdr->ts.tv_sec) * NDPI_TICK_RESOLUTION + pptrs->pkthdr->ts.tv_usec / (1000000 / NDPI_TICK_RESOLUTION);

  /* safety check */
  if (workflow->last_time > time) time = workflow->last_time;

  /* update last time value */
  workflow->last_time = time;

  if (pptrs->vlan_ptr) {
    memcpy(&vlan_id, pptrs->vlan_ptr, 2);
    vlan_id = ntohs(vlan_id);
    vlan_id = vlan_id & 0x0FFF;
  }

  /* safety check */
  if (pptrs->iph_ptr < pptrs->packet_ptr) return nproto;

  ip_offset = (u_int16_t)(pptrs->iph_ptr - pptrs->packet_ptr);

  /* process the packet */
  nproto = pm_ndpi_packet_processing(workflow, pptrs, time, vlan_id, iph, iph6,
				ip_offset, (pptrs->pkthdr->len - ip_offset),
				pptrs->pkthdr->len);

  pm_ndpi_idle_flows_cleanup(workflow);

  return nproto;
}

/*
 * Guess Undetected Protocol
 */
u_int16_t pm_ndpi_node_guess_undetected_protocol(struct pm_ndpi_workflow *workflow, struct pm_ndpi_flow_info *flow)
{
  if (!flow || !workflow) return 0;

  flow->detected_protocol = ndpi_guess_undetected_protocol(workflow->ndpi_struct,
							   flow->ndpi_flow,
                                                           flow->protocol,
                                                           ntohl(flow->lower_ip),
                                                           ntohs(flow->lower_port),
                                                           ntohl(flow->upper_ip),
                                                           ntohs(flow->upper_port));

  return (flow->detected_protocol.app_protocol);
}

/*
 * Idle Scan Walker
 */
int pm_ndpi_node_idle_scan_walker(const void *node, const pm_VISIT which, const int depth, void *user_data)
{
  struct pm_ndpi_flow_info *flow = *(struct pm_ndpi_flow_info **) node;
  struct pm_ndpi_workflow *workflow = (struct pm_ndpi_workflow *) user_data;

  if (!flow || !workflow) return FALSE;

  if (workflow->num_idle_flows == workflow->prefs.idle_scan_budget) return FALSE;

  if ((which == (pm_VISIT)ndpi_preorder) || (which == (pm_VISIT)ndpi_leaf)) { /* Avoid walking the same node multiple times */
    /* expire Idle and TCP finished flows */
    if ((flow->last_seen + workflow->prefs.idle_max_time < workflow->last_time) ||
	(flow->tcp_finished == TRUE)) {
      /* adding to a queue (we can't delete it from the tree inline) */
      workflow->idle_flows[workflow->num_idle_flows++] = flow;
    }
  }

  return TRUE;
}

void pm_ndpi_idle_flows_cleanup(struct pm_ndpi_workflow *workflow)
{
  if (!workflow) return;

  if ((workflow->last_idle_scan_time + workflow->prefs.idle_scan_period) < workflow->last_time) {
    /* scan for idle flows */
    pm_twalk(workflow->ndpi_flows_root[workflow->idle_scan_idx], pm_ndpi_node_idle_scan_walker, workflow);

    /* remove idle flows (unfortunately we cannot do this inline) */
    while (workflow->num_idle_flows > 0) {
      /* search and delete the idle flow from the "ndpi_flow_root" (see struct reader thread) - here flows are the node of a b-tree */
      pm_tdelete(workflow->idle_flows[--workflow->num_idle_flows], &workflow->ndpi_flows_root[workflow->idle_scan_idx], pm_ndpi_workflow_node_cmp);

      /* free the memory associated to idle flow in "idle_flows" - (see struct reader thread)*/
      pm_ndpi_free_flow_info_half(workflow->idle_flows[workflow->num_idle_flows]);
      ndpi_free(workflow->idle_flows[workflow->num_idle_flows]);
      workflow->stats.ndpi_flow_count--;
    }

    if (++workflow->idle_scan_idx == workflow->prefs.num_roots) workflow->idle_scan_idx = 0;
    workflow->last_idle_scan_time = workflow->last_time;
  }
}
