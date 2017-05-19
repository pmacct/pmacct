/*
 * ndpi_util.c
 *
 * Originally based on:
 * Copyright (C) 2011-17 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define __NDPI_UTIL_C

#ifdef WITH_NDPI
#include "../pmacct.h"
#include "ndpi_util.h"

/* ***************************************************** */

void ndpi_free_flow_info_half(struct ndpi_flow_info *flow)
{
  if(flow->ndpi_flow) { ndpi_flow_free(flow->ndpi_flow); flow->ndpi_flow = NULL; }
  if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL; }
  if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL; }
}

/* ***************************************************** */

/**
 * @brief malloc wrapper function
 */
static void *ndpi_malloc_wrapper(size_t size)
{
  ndpi_current_memory += size;

  if(ndpi_current_memory > ndpi_max_memory)
    ndpi_max_memory = ndpi_current_memory;

  return malloc(size);
}

/* ***************************************************** */

/**
 * @brief free wrapper function
 */
static void ndpi_free_wrapper(void *freeable)
{
  free(freeable);
}

/* ***************************************************** */

struct ndpi_workflow *ndpi_workflow_init(const struct ndpi_workflow_prefs *prefs, pcap_t *pcap_handle)
{
  if (!prefs || !pcap_handle) return NULL;

  set_ndpi_malloc(ndpi_malloc_wrapper), set_ndpi_free(ndpi_free_wrapper);
  set_ndpi_flow_malloc(NULL), set_ndpi_flow_free(NULL);
  /* TODO: just needed here to init ndpi malloc wrapper */
  struct ndpi_detection_module_struct *module = ndpi_init_detection_module();
  struct ndpi_workflow *workflow = ndpi_calloc(1, sizeof(struct ndpi_workflow));

  workflow->pcap_handle = pcap_handle;
  workflow->prefs = *prefs;
  workflow->ndpi_struct = module;

  if (workflow->ndpi_struct == NULL) {
    NDPI_LOG(0, NULL, NDPI_LOG_ERROR, "global structure initialization failed\n");
    exit(-1);
  }

  workflow->ndpi_flows_root = ndpi_calloc(workflow->prefs.num_roots, sizeof(void *));

  return workflow;
}

/* ***************************************************** */

static void ndpi_flow_info_freer(void *node)
{
  struct ndpi_flow_info *flow = (struct ndpi_flow_info*)node;

  ndpi_free_flow_info_half(flow);
  ndpi_free(flow);
}

/* ***************************************************** */

void ndpi_workflow_free(struct ndpi_workflow *workflow)
{
  int i;

  for(i=0; i<workflow->prefs.num_roots; i++)
    ndpi_tdestroy(workflow->ndpi_flows_root[i], ndpi_flow_info_freer);

  ndpi_exit_detection_module(workflow->ndpi_struct);
  free(workflow->ndpi_flows_root);
  free(workflow);
}

/* ***************************************************** */

int ndpi_workflow_node_cmp(const void *a, const void *b)
{
  struct ndpi_flow_info *fa = (struct ndpi_flow_info*)a;
  struct ndpi_flow_info *fb = (struct ndpi_flow_info*)b;

  if(fa->vlan_id   < fb->vlan_id  )   return(-1); else { if(fa->vlan_id   > fb->vlan_id    ) return(1); }
  if(fa->lower_ip   < fb->lower_ip  ) return(-1); else { if(fa->lower_ip   > fb->lower_ip  ) return(1); }
  if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
  if(fa->upper_ip   < fb->upper_ip  ) return(-1); else { if(fa->upper_ip   > fb->upper_ip  ) return(1); }
  if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
  if(fa->protocol   < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

  return(0);
}

/* ***************************************************** */

static void ndpi_patchIPv6Address(char *str)
{
  int i = 0, j = 0;

  while(str[i] != '\0') {
    if((str[i] == ':')
       && (str[i+1] == '0')
       && (str[i+2] == ':')) {
      str[j++] = ':';
      str[j++] = ':';
      i += 3;
    } else
      str[j++] = str[i++];
  }
  if(str[j] != '\0') str[j] = '\0';
}

/* ***************************************************** */

static struct ndpi_flow_info *get_ndpi_flow_info(struct ndpi_workflow *workflow,
						 const u_int8_t version,
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
  u_int32_t idx, l4_offset;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  struct ndpi_flow_info flow;
  void *ret;
  u_int8_t *l3, *l4;

  /*
    Note: to keep things simple (ndpiReader is just a demo app)
    we handle IPv6 a-la-IPv4.
  */
  if(version == IPVERSION) {
    if(ipsize < 20)
      return NULL;

    if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
       /* || (iph->frag_off & htons(0x1FFF)) != 0 */)
      return NULL;

    l4_offset = iph->ihl * 4;
    l3 = (u_int8_t*)iph;
  } else {
    l4_offset = sizeof(struct ndpi_ipv6hdr);
    l3 = (u_int8_t*)iph6;
  }

  if(l4_packet_len < 64)
    workflow->stats.packet_len[0]++;
  else if(l4_packet_len >= 64 && l4_packet_len < 128)
    workflow->stats.packet_len[1]++;
  else if(l4_packet_len >= 128 && l4_packet_len < 256)
    workflow->stats.packet_len[2]++;
  else if(l4_packet_len >= 256 && l4_packet_len < 1024)
    workflow->stats.packet_len[3]++;
  else if(l4_packet_len >= 1024 && l4_packet_len < 1500)
    workflow->stats.packet_len[4]++;
  else if(l4_packet_len >= 1500)
    workflow->stats.packet_len[5]++;

  if(l4_packet_len > workflow->stats.max_packet_len)
    workflow->stats.max_packet_len = l4_packet_len;

  if(iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  *proto = iph->protocol;
  l4 = ((u_int8_t *) l3 + l4_offset);

  if(iph->protocol == IPPROTO_TCP && l4_packet_len >= 20) {
    u_int tcp_len;

    // tcp
    workflow->stats.tcp_count++;
    *tcph = (struct ndpi_tcphdr *)l4;
    *sport = ntohs((*tcph)->source), *dport = ntohs((*tcph)->dest);

    if(iph->saddr < iph->daddr) {
      lower_port = (*tcph)->source, upper_port = (*tcph)->dest;
      *src_to_dst_direction = 1;
    } else {
      lower_port = (*tcph)->dest;
      upper_port = (*tcph)->source;

      *src_to_dst_direction = 0;
      if(iph->saddr == iph->daddr) {
	if(lower_port > upper_port) {
	  u_int16_t p = lower_port;

	  lower_port = upper_port;
	  upper_port = p;
	}
      }
    }

    tcp_len = ndpi_min(4*(*tcph)->doff, l4_packet_len);
    *payload = &l4[tcp_len];
    *payload_len = ndpi_max(0, l4_packet_len-4*(*tcph)->doff);
  } else if(iph->protocol == IPPROTO_UDP && l4_packet_len >= 8) {
    // udp

    workflow->stats.udp_count++;
    *udph = (struct ndpi_udphdr *)l4;
    *sport = ntohs((*udph)->source), *dport = ntohs((*udph)->dest);
    *payload = &l4[sizeof(struct ndpi_udphdr)];
    *payload_len = ndpi_max(0, l4_packet_len-sizeof(struct ndpi_udphdr));

    if(iph->saddr < iph->daddr) {
      lower_port = (*udph)->source, upper_port = (*udph)->dest;
      *src_to_dst_direction = 1;
    } else {
      lower_port = (*udph)->dest, upper_port = (*udph)->source;

      *src_to_dst_direction = 0;

      if(iph->saddr == iph->daddr) {
	if(lower_port > upper_port) {
	  u_int16_t p = lower_port;

	  lower_port = upper_port;
	  upper_port = p;
	}
      }
    }

    *sport = ntohs(lower_port), *dport = ntohs(upper_port);
  } else {
    // non tcp/udp protocols
    lower_port = 0;
    upper_port = 0;
  }

  flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
  flow.lower_ip = lower_ip, flow.upper_ip = upper_ip;
  flow.lower_port = lower_port, flow.upper_port = upper_port;

  NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_DEBUG, "[NDPI] [%u][%u:%u <-> %u:%u]\n",
	   iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));

  idx = (vlan_id + lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % workflow->prefs.num_roots;
  ret = ndpi_tfind(&flow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp);

  if(ret == NULL) {
    if(workflow->stats.ndpi_flow_count == workflow->prefs.max_ndpi_flows) {
      NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR,
	       "maximum flow count (%u) has been exceeded\n",
	       workflow->prefs.max_ndpi_flows);
      exit(-1);
    } else {
      struct ndpi_flow_info *newflow = (struct ndpi_flow_info*)malloc(sizeof(struct ndpi_flow_info));

      if(newflow == NULL) {
	NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(1): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      memset(newflow, 0, sizeof(struct ndpi_flow_info));
      newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
      newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
      newflow->lower_port = lower_port, newflow->upper_port = upper_port;
      newflow->ip_version = version;
      newflow->src_to_dst_direction = *src_to_dst_direction;

      if(version == IPVERSION) {
	inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));
      } else {
	inet_ntop(AF_INET6, &iph6->ip6_src, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->upper_name, sizeof(newflow->upper_name));
	/* For consistency across platforms replace :0: with :: */
	ndpi_patchIPv6Address(newflow->lower_name), ndpi_patchIPv6Address(newflow->upper_name);
      }

      if((newflow->ndpi_flow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT)) == NULL) {
	NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(2): not enough memory\n", __FUNCTION__);
	free(newflow);
	return(NULL);
      } else
	memset(newflow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

      if((newflow->src_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) {
	NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(3): not enough memory\n", __FUNCTION__);
	free(newflow);
	return(NULL);
      } else
	memset(newflow->src_id, 0, SIZEOF_ID_STRUCT);

      if((newflow->dst_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) {
	NDPI_LOG(0, workflow->ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(4): not enough memory\n", __FUNCTION__);
	free(newflow);
	return(NULL);
      } else
	memset(newflow->dst_id, 0, SIZEOF_ID_STRUCT);

      ndpi_tsearch(newflow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp); /* Add */
      workflow->stats.ndpi_flow_count++;

      *src = newflow->src_id, *dst = newflow->dst_id;

      return newflow;
    }
  } else {
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)ret;

    if(flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
       && flow->lower_port == lower_port && flow->upper_port == upper_port)
      *src = flow->src_id, *dst = flow->dst_id;
    else
      *src = flow->dst_id, *dst = flow->src_id;

    return flow;
  }
}

/* ****************************************************** */

static struct ndpi_flow_info *get_ndpi_flow_info6(struct ndpi_workflow *workflow,
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
  iph.protocol = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

  if(iph.protocol == IPPROTO_DSTOPTS /* IPv6 destination option */) {
    u_int8_t *options = (u_int8_t*)iph6 + sizeof(const struct ndpi_ipv6hdr);

    iph.protocol = options[0];
  }

  return(get_ndpi_flow_info(workflow, 6, vlan_id, &iph, iph6, ip_offset,
			    sizeof(struct ndpi_ipv6hdr),
			    ntohs(iph6->ip6_ctlun.ip6_un1.ip6_un1_plen),
			    tcph, udph, sport, dport,
			    src, dst, proto, payload, payload_len, src_to_dst_direction));
}

/* ****************************************************** */

void process_ndpi_collected_info(struct ndpi_workflow *workflow, struct ndpi_flow_info *flow)
{
  if(!flow->ndpi_flow) return;

    snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s",
	   flow->ndpi_flow->host_server_name);

  /* BITTORRENT */
  if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_BITTORRENT) {
    int i, j, n = 0;

    for(i=0, j = 0; j < sizeof(flow->bittorent_hash)-1; i++) {
      sprintf(&flow->bittorent_hash[j], "%02x", flow->ndpi_flow->bittorent_hash[i]);
      j += 2, n += flow->ndpi_flow->bittorent_hash[i];
    }

    if(n == 0) flow->bittorent_hash[0] = '\0';
  }
  /* MDNS */
  else if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_MDNS) {
    snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->protos.mdns.answer);
  }
  /* UBNTAC2 */
  else if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UBNTAC2) {
    snprintf(flow->info, sizeof(flow->info), "%s", flow->ndpi_flow->protos.ubntac2.version);
  }
  if(flow->detected_protocol.app_protocol != NDPI_PROTOCOL_DNS) {
    /* SSH */
    if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_SSH) {
      snprintf(flow->ssh_ssl.client_info, sizeof(flow->ssh_ssl.client_info), "%s",
	       flow->ndpi_flow->protos.ssh.client_signature);
      snprintf(flow->ssh_ssl.server_info, sizeof(flow->ssh_ssl.server_info), "%s",
	       flow->ndpi_flow->protos.ssh.server_signature);
    }
    /* SSL */
    else if((flow->detected_protocol.app_protocol == NDPI_PROTOCOL_SSL)
	    || (flow->detected_protocol.master_protocol == NDPI_PROTOCOL_SSL)) {
      snprintf(flow->ssh_ssl.client_info, sizeof(flow->ssh_ssl.client_info), "%s",
	       flow->ndpi_flow->protos.ssl.client_certificate);
      snprintf(flow->ssh_ssl.server_info, sizeof(flow->ssh_ssl.server_info), "%s",
	       flow->ndpi_flow->protos.ssl.server_certificate);
    }
  }

  if(flow->detection_completed) {
    if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
      if (workflow->__flow_giveup_callback != NULL)
	workflow->__flow_giveup_callback(workflow, flow, workflow->__flow_giveup_udata);
    } else {
      if (workflow->__flow_detected_callback != NULL)
	workflow->__flow_detected_callback(workflow, flow, workflow->__flow_detected_udata);
    }

    ndpi_free_flow_info_half(flow);
  }
}

/* ****************************************************** */

/**
   Function to process the packet:
   determine the flow of a packet and try to decode it
   @return: 0 if success; else != 0

   @Note: ipsize = header->len - ip_offset ; rawsize = header->len
*/
static struct ndpi_proto ndpi_packet_processing(struct ndpi_workflow *workflow,
					   const u_int64_t time,
					   u_int16_t vlan_id,
					   const struct ndpi_iphdr *iph,
					   struct ndpi_ipv6hdr *iph6,
					   u_int16_t ip_offset,
					   u_int16_t ipsize, u_int16_t rawsize)
{
  struct ndpi_id_struct *src, *dst;
  struct ndpi_flow_info *flow = NULL;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int8_t proto;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int16_t sport, dport, payload_len;
  u_int8_t *payload;
  u_int8_t src_to_dst_direction = 1;
  struct ndpi_proto nproto = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };

  if(iph)
    flow = get_ndpi_flow_info(workflow, IPVERSION, vlan_id, iph, NULL,
			      ip_offset, ipsize,
			      ntohs(iph->tot_len) - (iph->ihl * 4),
			      &tcph, &udph, &sport, &dport,
			      &src, &dst, &proto,
			      &payload, &payload_len, &src_to_dst_direction);
  else
    flow = get_ndpi_flow_info6(workflow, vlan_id, iph6, ip_offset,
			       &tcph, &udph, &sport, &dport,
			       &src, &dst, &proto,
			       &payload, &payload_len, &src_to_dst_direction);

  if(flow != NULL) {
    workflow->stats.ip_packet_count++;
    workflow->stats.total_wire_bytes += rawsize + 24 /* CRC etc */,
      workflow->stats.total_ip_bytes += rawsize;
    ndpi_flow = flow->ndpi_flow;
    flow->packets++, flow->bytes += rawsize;
    flow->last_seen = time;
  } else { // flow is NULL
    workflow->stats.total_discarded_bytes++;
    return (nproto);
  }

  /* Protocol already detected */
  if(flow->detection_completed) return(flow->detected_protocol);

  flow->detected_protocol = ndpi_detection_process_packet(workflow->ndpi_struct, ndpi_flow,
							  iph ? (uint8_t *)iph : (uint8_t *)iph6,
							  ipsize, time, src, dst);

  if((flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN)
     || ((proto == IPPROTO_UDP) && (flow->packets > 8))
     || ((proto == IPPROTO_TCP) && (flow->packets > 10))) {
    /* New protocol detected or give up */
    flow->detection_completed = 1;
  }

  if(flow->detection_completed) {
    if(flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
      flow->detected_protocol = ndpi_detection_giveup(workflow->ndpi_struct,
						      flow->ndpi_flow);
  }

  process_ndpi_collected_info(workflow, flow);
  return(flow->detected_protocol);
}

/* ****************************************************** */

struct ndpi_proto ndpi_workflow_process_packet(struct ndpi_workflow *workflow,
						struct packet_ptrs *pptrs)
{
  struct ndpi_iphdr *iph = NULL;
  struct ndpi_ipv6hdr *iph6 = NULL;
  struct ndpi_proto nproto = { NDPI_PROTOCOL_UNKNOWN, NDPI_PROTOCOL_UNKNOWN };
  u_int64_t time = 0;
  u_int16_t ip_offset = 0, vlan_id = 0;

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
  return (ndpi_packet_processing(workflow, time, vlan_id, iph, iph6,
				ip_offset, (pptrs->pkthdr->len - ip_offset),
				pptrs->pkthdr->len));
}

/* ********************************************************** */
/*       http://home.thep.lu.se/~bjorn/crc/crc32_fast.c       */
/* ********************************************************** */

static uint32_t crc32_for_byte(uint32_t r)
{
	int j;

	for(j = 0; j < 8; ++j)
		r = (r & 1? 0: (uint32_t)0xEDB88320L) ^ r >> 1;
	return r ^ (uint32_t)0xFF000000L;
}

static void ndpi_init_tables(uint32_t *table, uint32_t *wtable)
{
	size_t i, k, w, j;

	for(i = 0; i < 0x100; ++i)
		table[i] = crc32_for_byte(i);
	for(k = 0; k < sizeof(ndpi_accum_t); ++k)
		for(i = 0; i < 0x100; ++i) {
			for(j = w = 0; j < sizeof(ndpi_accum_t); ++j)
				w = table[(uint8_t)(j == k? w ^ i: w)] ^ w >> 8;
			wtable[(k << 8) + i] = w ^ (k? wtable[0]: 0);
		}
}

void ndpi_ethernet_crc32(const void *data, size_t n_bytes, uint32_t *crc)
{
	static uint32_t table[0x100], wtable[0x100*sizeof(ndpi_accum_t)];
	size_t n_accum = n_bytes/sizeof(ndpi_accum_t);
	size_t i, k, j;

	if(!*table)
		ndpi_init_tables(table, wtable);
	for(i = 0; i < n_accum; ++i) {
		ndpi_accum_t a = *crc ^ ((ndpi_accum_t*)data)[i];
		for(j = *crc = 0; j < sizeof(ndpi_accum_t); ++j)
			*crc ^= wtable[(j << 8) + (uint8_t)(a >> 8*j)];
	}

	for(i = n_accum*sizeof(ndpi_accum_t); i < n_bytes; ++i)
		*crc = table[(uint8_t)*crc ^ ((uint8_t*)data)[i]] ^ *crc >> 8;
}

/* flow callbacks for complete detected flow (ndpi_flow_info will be freed right after) */
static inline void ndpi_workflow_set_flow_detected_callback(struct ndpi_workflow *workflow, ndpi_workflow_callback_ptr callback, void *udata)
{
  workflow->__flow_detected_callback = callback;
  workflow->__flow_detected_udata = udata;
}

/* flow callbacks for sufficient detected flow (ndpi_flow_info will be freed right after) */
static inline void ndpi_workflow_set_flow_giveup_callback(struct ndpi_workflow *workflow, ndpi_workflow_callback_ptr callback, void *udata)
{
  workflow->__flow_giveup_callback = callback;
  workflow->__flow_giveup_udata = udata;
}
#endif
