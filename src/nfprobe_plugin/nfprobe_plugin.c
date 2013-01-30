/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2013 by Paolo Lucente
*/

/*
 * Originally based on softflowd which is:
 *
 * Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define __NFPROBE_PLUGIN_C

/*
 * This is software implementation of Cisco's NetFlow(tm) traffic 
 * reporting system. It operates by listening (via libpcap) on a 
 * promiscuous interface and tracking traffic flows. 
 *
 * Traffic flows are recorded by source/destination/protocol IP address or, in the
 * case of TCP and UDP, by src_addr:src_port/dest_addr:dest_port/protocol
 *
 * Flows expire automatically after a period of inactivity (default: 1 hour)
 * They may also be evicted (in order of age) in situations where there are 
 * more flows than slots available.
 *
 * Netflow version 1 compatible packets are sent to a specified target 
 * host upon flow expiry.
 *
 * As this implementation watches traffic promiscuously, it is likely to 
 * place significant load on hosts or gateways on which it is installed.
 */

#include "common.h"
#include "sys-tree.h"
#include "convtime.h"
#include "../nfacctd.h"
#include "nfprobe_plugin.h"
#include "treetype.h"

#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "net_aggr.h"
#include "ports_aggr.h"

/* Global variables */
static int verbose_flag = 0;		/* Debugging flag */
static int timeout = 0;
struct FLOWTRACK *glob_flowtrack = NULL;

/* Prototypes */
static void force_expire(struct FLOWTRACK *, u_int32_t);

/* Signal handler flags */
static int graceful_shutdown_request = 0;	

/* Context for libpcap callback functions */
struct CB_CTXT {
	struct FLOWTRACK *ft;
	int linktype;
	int fatal;
	int want_v6;
};

/* Netflow send functions */
typedef int (netflow_send_func_t)(struct FLOW **, int, int, u_int64_t *,
    struct timeval *, int, u_int8_t, u_int8_t);
struct NETFLOW_SENDER {
	int version;
	netflow_send_func_t *func;
	int v6_capable;
};

/* Array of NetFlow export function that we know of. NB. nf[0] is default */
static const struct NETFLOW_SENDER nf[] = {
	{ 5, send_netflow_v5, 0 },
	{ 1, send_netflow_v1, 0 },
	{ 9, send_netflow_v9, 1 },
	{ 10, send_netflow_v9, 1 },
	{ -1, NULL, 0 },
};

/* Describes a location where we send NetFlow packets to */
struct NETFLOW_TARGET {
	int fd;
	const struct NETFLOW_SENDER *dialect;
};

void nfprobe_exit_gracefully(int signum)
{
  signal(SIGINT, SIG_IGN);
  signal(SIGHUP, SIG_IGN);

  if (config.pcap_savefile) timeout = 3*1000;

  graceful_shutdown_request = TRUE;
}

/*
 * This is the flow comparison function.
 */
static int
flow_compare(struct FLOW *a, struct FLOW *b)
{
	/* Be careful to avoid signed vs unsigned issues here */
	int r;

	if (a->af != b->af)
		return (a->af > b->af ? 1 : -1);

	if ((r = memcmp(&a->addr[0], &b->addr[0], sizeof(a->addr[0]))) != 0)
		return (r > 0 ? 1 : -1);

	if ((r = memcmp(&a->addr[1], &b->addr[1], sizeof(a->addr[1]))) != 0)
		return (r > 0 ? 1 : -1);

#ifdef notyet
	if (a->ip6_flowlabel[0] != 0 && b->ip6_flowlabel[0] != 0 && 
	    a->ip6_flowlabel[0] != b->ip6_flowlabel[0])
		return (a->ip6_flowlabel[0] > b->ip6_flowlabel[0] ? 1 : -1);

	if (a->ip6_flowlabel[1] != 0 && b->ip6_flowlabel[1] != 0 && 
	    a->ip6_flowlabel[1] != b->ip6_flowlabel[1])
		return (a->ip6_flowlabel[1] > b->ip6_flowlabel[1] ? 1 : -1);
#endif

	if (a->protocol != b->protocol)
		return (a->protocol > b->protocol ? 1 : -1);

	if (a->port[0] != b->port[0])
		return (ntohs(a->port[0]) > ntohs(b->port[0]) ? 1 : -1);

	if (a->port[1] != b->port[1])
		return (ntohs(a->port[1]) > ntohs(b->port[1]) ? 1 : -1);

	return (0);
}

/* Generate functions for flow tree */
FLOW_PROTOTYPE(FLOWS, FLOW, trp, flow_compare);
FLOW_GENERATE(FLOWS, FLOW, trp, flow_compare);

/*
 * This is the expiry comparison function.
 */
static int
expiry_compare(struct EXPIRY *a, struct EXPIRY *b)
{
	if (a->expires_at != b->expires_at)
		return (a->expires_at > b->expires_at ? 1 : -1);

	/* Make expiry entries unique by comparing flow sequence */
	if (a->flow->flow_seq != b->flow->flow_seq)
		return (a->flow->flow_seq > b->flow->flow_seq ? 1 : -1);

	return (0);
}

/* Generate functions for flow tree */
EXPIRY_PROTOTYPE(EXPIRIES, EXPIRY, trp, expiry_compare);
EXPIRY_GENERATE(EXPIRIES, EXPIRY, trp, expiry_compare);

/* Format a time in an ISOish format */
static const char *
format_time(time_t t)
{
	struct tm *tm;
	static char buf[20];

	tm = localtime(&t);
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", tm);

	return (buf);

}

/* Format a flow in a verbose and ugly way */
static const char *
format_flow(struct FLOW *flow)
{
	char addr1[64], addr2[64], stime[20], ftime[20];
	static char buf[1024];

	inet_ntop(flow->af, &flow->addr[0], addr1, sizeof(addr1));
	inet_ntop(flow->af, &flow->addr[1], addr2, sizeof(addr2));

	snprintf(stime, sizeof(ftime), "%s", 
	    format_time(flow->flow_start.tv_sec));
	snprintf(ftime, sizeof(ftime), "%s", 
	    format_time(flow->flow_last.tv_sec));

	snprintf(buf, sizeof(buf),  "seq:%llu [%s]:%hu <> [%s]:%hu proto:%u "
	    "octets>:%u packets>:%u octets<:%u packets<:%u "
	    "start:%s.%03ld finish:%s.%03ld tcp>:%02x tcp<:%02x "
	    "flowlabel>:%08x flowlabel<:%08x ",
	    flow->flow_seq,
	    addr1, ntohs(flow->port[0]), addr2, ntohs(flow->port[1]),
	    (int)flow->protocol, 
	    flow->octets[0], flow->packets[0], 
	    flow->octets[1], flow->packets[1], 
	    stime, (flow->flow_start.tv_usec + 500) / 1000, 
	    ftime, (flow->flow_start.tv_usec + 500) / 1000,
	    flow->tcp_flags[0], flow->tcp_flags[1],
	    flow->ip6_flowlabel[0], flow->ip6_flowlabel[1]);

	return (buf);
}

/* Format a flow in a brief way */
static const char *
format_flow_brief(struct FLOW *flow)
{
	char addr1[64], addr2[64];
	static char buf[1024];

	inet_ntop(flow->af, &flow->addr[0], addr1, sizeof(addr1));
	inet_ntop(flow->af, &flow->addr[1], addr2, sizeof(addr2));

	snprintf(buf, sizeof(buf), 
	    "seq:%llu [%s]:%hu <> [%s]:%hu proto:%u",
	    flow->flow_seq,
	    addr1, ntohs(flow->port[0]), addr2, ntohs(flow->port[1]),
	    (int)flow->protocol);

	return (buf);
}

/* Need to preprocess data because packet handlers have automagically
 * swapped byte ordering for some primitives */ 
void handle_hostbyteorder_packet(struct pkt_data *data)
{
#if defined HAVE_L2
  data->primitives.vlan_id = htons(data->primitives.vlan_id); 
#endif
  data->primitives.src_port = htons(data->primitives.src_port); 
  data->primitives.dst_port = htons(data->primitives.dst_port); 
  data->primitives.src_as = htonl(data->primitives.src_as); 
  data->primitives.dst_as = htonl(data->primitives.dst_as); 
}

/* Fill in transport-layer (tcp/udp) portions of flow record */
static int
transport_to_flowrec(struct FLOW *flow, struct pkt_data *data, struct pkt_extras *extras, int protocol, int ndx)
{
 struct pkt_primitives *p = &data->primitives;

 /*
  * XXX to keep flow in proper canonical format, it may be necessary
  * to swap the array slots based on the order of the port numbers
  * does this matter in practice??? I don't think so - return flows will
  * always match, because of their symmetrical addr/ports
  */

  switch (protocol) {
  case IPPROTO_TCP:
    /* Check for runt packet, but don't error out on short frags */
    flow->port[ndx] = p->src_port;
    flow->port[ndx ^ 1] = p->dst_port;
    flow->tcp_flags[ndx] |= extras->tcp_flags;
    break;
  case IPPROTO_UDP:
    /* Check for runt packet, but don't error out on short frags */
    flow->port[ndx] = p->src_port;
    flow->port[ndx ^ 1] = p->dst_port;
    break;
  }

  return (0);
}

static int
l2_to_flowrec(struct FLOW *flow, struct pkt_data *data, struct pkt_extras *extras, int ndx)
{
  struct pkt_primitives *p = &data->primitives;
  int direction = 0;

  if (config.nfprobe_direction) {
    switch (config.nfprobe_direction) {
    case DIRECTION_IN:
    case DIRECTION_OUT:
      direction = config.nfprobe_direction;
      break;
    case DIRECTION_TAG:
      if (p->id == 1) direction = DIRECTION_IN;
      else if (p->id == 2) direction = DIRECTION_OUT;
      break;
    case DIRECTION_TAG2:
      if (p->id2 == 1) direction = DIRECTION_IN;
      else if (p->id2 == 2) direction = DIRECTION_OUT;
      break;
    }

    if (direction == DIRECTION_IN) {
      flow->direction[ndx] = DIRECTION_IN;
      flow->direction[ndx ^ 1] = 0;
    }
    else if (direction == DIRECTION_OUT) {
      flow->direction[ndx] = DIRECTION_OUT;
      flow->direction[ndx ^ 1] = 0;
    }
  }

#if defined HAVE_L2
  memcpy(&flow->mac[ndx][0], &p->eth_shost, 6);
  memcpy(&flow->mac[ndx ^ 1][0], &p->eth_dhost, 6);
  flow->vlan = p->vlan_id;
  flow->mpls_label[ndx] = extras->mpls_top_label;
#endif

  if (!p->ifindex_in && !p->ifindex_out) {
    if (config.nfprobe_ifindex_type) {
      switch (config.nfprobe_ifindex_type) {
      case IFINDEX_STATIC:
        flow->ifindex[ndx] = (direction == DIRECTION_IN) ? config.nfprobe_ifindex : 0;
        flow->ifindex[ndx ^ 1] = (direction == DIRECTION_OUT) ? config.nfprobe_ifindex : 0;
        break;
      case IFINDEX_TAG:
        flow->ifindex[ndx] = (direction == DIRECTION_IN) ? p->id : 0;
	flow->ifindex[ndx ^ 1] = (direction == DIRECTION_OUT) ? p->id : 0;
	break;
      case IFINDEX_TAG2:
        flow->ifindex[ndx] = (direction == DIRECTION_IN) ? p->id2 : 0;
	flow->ifindex[ndx ^ 1] = (direction == DIRECTION_OUT) ? p->id2 : 0;
        break;
      default:
        flow->ifindex[ndx] = 0;
	flow->ifindex[ndx ^ 1] = 0;
      }
    }
  }
  else {
    flow->ifindex[ndx] = p->ifindex_in;
    flow->ifindex[ndx ^ 1] = p->ifindex_out;
  }

  return (0);
}

static int
l2_to_flowrec_update(struct FLOW *flow, struct pkt_data *data, struct pkt_extras *extras, int ndx)
{
  struct pkt_primitives *p = &data->primitives;
  int direction = 0;

  if (config.nfprobe_direction) {
    switch (config.nfprobe_direction) {
    case DIRECTION_TAG:
      if (p->id == 1) direction = DIRECTION_IN;
      else if (p->id == 2) direction = DIRECTION_OUT;
      break;
    case DIRECTION_TAG2:
      if (p->id2 == 1) direction = DIRECTION_IN;
      else if (p->id2 == 2) direction = DIRECTION_OUT;
      break;
    }

    if (direction == DIRECTION_IN) {
      if (!flow->direction[ndx]) flow->direction[ndx] = DIRECTION_IN;
    }
    else if (direction == DIRECTION_OUT) {
      if (!flow->direction[ndx]) flow->direction[ndx] = DIRECTION_OUT;
    }
  }
}

static int
ASN_to_flowrec(struct FLOW *flow, struct pkt_data *data, int ndx)
{
  struct pkt_primitives *p = &data->primitives;

  flow->as[ndx] = p->src_as; 
  flow->as[ndx ^ 1] = p->dst_as;

  return (0);
}

/* Convert a IPv4 packet to a partial flow record (used for comparison) */
static int
ipv4_to_flowrec(struct FLOW *flow, struct pkt_data *data, struct pkt_extras *extras, int *isfrag, int af)
{
  struct pkt_primitives *p = &data->primitives;
  int ndx;

  /* Prepare to store flow in canonical format */
  ndx = memcmp(&p->src_ip.address.ipv4, &p->dst_ip.address.ipv4, sizeof(p->src_ip.address.ipv4)) > 0 ? 1 : 0;
	
  flow->af = af;
  flow->addr[ndx].v4 = p->src_ip.address.ipv4;
  flow->addr[ndx ^ 1].v4 = p->dst_ip.address.ipv4;
  flow->bgp_next_hop[ndx].v4 = extras->bgp_next_hop.address.ipv4;
  flow->mask[ndx] = p->src_nmask;
  flow->mask[ndx ^ 1] = p->dst_nmask;
  flow->tos[ndx] = p->tos;
  flow->protocol = p->proto;
  flow->octets[ndx] = data->pkt_len;
  flow->packets[ndx] = data->pkt_num;
  flow->flows[ndx] = data->flo_num;
  flow->class = p->class;
  flow->tag[ndx] = p->id;
  flow->tag2[ndx] = p->id2;

  *isfrag = 0;

  l2_to_flowrec(flow, data, extras, ndx);
  ASN_to_flowrec(flow, data, ndx);

  return (transport_to_flowrec(flow, data, extras, p->proto, ndx));

  // return (0);
}

static int
ipv4_to_flowrec_update(struct FLOW *flow, struct pkt_data *data, struct pkt_extras *extras, int *isfrag, int af)
{
  struct pkt_primitives *p = &data->primitives;
  int ndx;

  /* Prepare to store flow in canonical format */
  ndx = memcmp(&p->src_ip.address.ipv4, &p->dst_ip.address.ipv4, sizeof(p->src_ip.address.ipv4)) > 0 ? 1 : 0;

  if (!flow->bgp_next_hop[ndx].v4.s_addr) flow->bgp_next_hop[ndx].v4 = extras->bgp_next_hop.address.ipv4;

  l2_to_flowrec_update(flow, data, extras, ndx);
}

#if defined ENABLE_IPV6
/* Convert a IPv6 packet to a partial flow record (used for comparison) */
static int
ipv6_to_flowrec(struct FLOW *flow, struct pkt_data *data, struct pkt_extras *extras, int *isfrag, int af)
{
  struct pkt_primitives *p = &data->primitives;
  int ndx, nxt;

  /* Prepare to store flow in canonical format */
  ndx = memcmp(&p->src_ip.address.ipv6, &p->dst_ip.address.ipv6, sizeof(p->src_ip.address.ipv6)) > 0 ? 1 : 0; 
	
  flow->af = af;
  /* XXX: flow->ip6_flowlabel[ndx] = ip6->ip6_flow & IPV6_FLOWLABEL_MASK; */
  flow->ip6_flowlabel[ndx] = 0;
  flow->addr[ndx].v6 = p->src_ip.address.ipv6; 
  flow->addr[ndx ^ 1].v6 = p->dst_ip.address.ipv6; 
  flow->bgp_next_hop[ndx].v6 = extras->bgp_next_hop.address.ipv6;
  flow->mask[ndx] = p->src_nmask;
  flow->mask[ndx ^ 1] = p->dst_nmask;
  flow->octets[ndx] = data->pkt_len;
  flow->packets[ndx] = data->pkt_num; 
  flow->flows[ndx] = data->flo_num;
  flow->class = p->class;
  flow->tag[ndx] = p->id;
  flow->tag2[ndx] = p->id2;

  *isfrag = 0;

  l2_to_flowrec(flow, data, extras, ndx);
  ASN_to_flowrec(flow, data, ndx);

  return (transport_to_flowrec(flow, data, extras, p->proto, ndx));

  // return (0);
}

static int
ipv6_to_flowrec_update(struct FLOW *flow, struct pkt_data *data, struct pkt_extras *extras, int *isfrag, int af)
{
  struct pkt_primitives *p = &data->primitives;
  struct in6_addr dummy_ipv6; 
  int ndx;

  /* Prepare to store flow in canonical format */
  memset(&dummy_ipv6, 0, sizeof(dummy_ipv6));
  ndx = memcmp(&p->src_ip.address.ipv6, &p->dst_ip.address.ipv6, sizeof(p->src_ip.address.ipv6)) > 0 ? 1 : 0;

  if (!memcmp(&dummy_ipv6, &flow->bgp_next_hop[ndx].v6, sizeof(dummy_ipv6)))
    flow->bgp_next_hop[ndx].v6 = extras->bgp_next_hop.address.ipv6;

  l2_to_flowrec_update(flow, data, extras, ndx);
}
#endif 

static void
flow_update_expiry(struct FLOWTRACK *ft, struct FLOW *flow)
{
	EXPIRY_REMOVE(EXPIRIES, &ft->expiries, flow->expiry);

	/* Flows over 2Gb traffic */
	if (flow->octets[0] > (1U << 31) || flow->octets[1] > (1U << 31)) {
		flow->expiry->expires_at = 0;
		flow->expiry->reason = R_OVERBYTES;
		goto out;
	}
	
	/* Flows over maximum life seconds */
	if (ft->maximum_lifetime != 0 && 
	    flow->flow_last.tv_sec - flow->flow_start.tv_sec > 
	    ft->maximum_lifetime) {
		flow->expiry->expires_at = 0;
		flow->expiry->reason = R_MAXLIFE;
		goto out;
	}
	
	if (flow->protocol == IPPROTO_TCP) {
		/* Reset TCP flows */
		if (ft->tcp_rst_timeout != 0 &&
		    ((flow->tcp_flags[0] & TH_RST) ||
		    (flow->tcp_flags[1] & TH_RST))) {
			flow->expiry->expires_at = flow->flow_last.tv_sec + 
			    ft->tcp_rst_timeout;
			flow->expiry->reason = R_TCP_RST;
			goto out;
		}
		/* Finished TCP flows */
		if (ft->tcp_fin_timeout != 0 &&
		    ((flow->tcp_flags[0] & TH_FIN) &&
		    (flow->tcp_flags[1] & TH_FIN))) {
			flow->expiry->expires_at = flow->flow_last.tv_sec + 
			    ft->tcp_fin_timeout;
			flow->expiry->reason = R_TCP_FIN;
			goto out;
		}

		/* TCP flows */
		if (ft->tcp_timeout != 0) {
			flow->expiry->expires_at = flow->flow_last.tv_sec + 
			    ft->tcp_timeout;
			flow->expiry->reason = R_TCP;
			goto out;
		}
	}

	if (ft->udp_timeout != 0 && flow->protocol == IPPROTO_UDP) {
		/* UDP flows */
		flow->expiry->expires_at = flow->flow_last.tv_sec + 
		    ft->udp_timeout;
		flow->expiry->reason = R_UDP;
		goto out;
	}

	if (ft->icmp_timeout != 0 &&
	    ((flow->af == AF_INET && flow->protocol == IPPROTO_ICMP)
#if defined ENABLE_IPV6	   
	    || ((flow->af == AF_INET6 && flow->protocol == IPPROTO_ICMPV6))
#endif
	   )) {
		/* UDP flows */
		flow->expiry->expires_at = flow->flow_last.tv_sec + 
		    ft->icmp_timeout;
		flow->expiry->reason = R_ICMP;
		goto out;
	}

	/* Everything else */
	flow->expiry->expires_at = flow->flow_last.tv_sec + 
	    ft->general_timeout;
	flow->expiry->reason = R_GENERAL;

 out:
	EXPIRY_INSERT(EXPIRIES, &ft->expiries, flow->expiry);
}


/* Return values from process_packet */
#define PP_OK		0
#define PP_BAD_PACKET	-2
#define PP_MALLOC_FAIL	-3

/*
 * Main per-packet processing function. Take a packet (provided by 
 * libpcap) and attempt to find a matching flow. If no such flow exists, 
 * then create one. 
 *
 * Also marks flows for fast expiry, based on flow or packet attributes
 * (the actual expiry is performed elsewhere)
 */
static int
process_packet(struct FLOWTRACK *ft, struct pkt_data *data, struct pkt_extras *extras, const struct timeval *received_time)
{
  struct FLOW tmp, *flow;
  int frag, af, dont_summarize = (config.acct_type == ACCT_NF ? 1 : 0);

  ft->total_packets += data->pkt_num;
  af = (data->primitives.src_ip.family == 0 ? AF_INET : data->primitives.src_ip.family);

  /* Convert the IP packet to a flow identity */
  memset(&tmp, 0, sizeof(tmp));

  switch (af) {
  case AF_INET:
    if (ipv4_to_flowrec(&tmp, data, extras, &frag, af) == -1)
      goto bad;
    break;
#if defined ENABLE_IPV6
  case AF_INET6:
    if (ipv6_to_flowrec(&tmp, data, extras, &frag, af) == -1)
      goto bad;
    break;
#endif
  default:
  bad: 
    ft->bad_packets += data->pkt_num;
    return (PP_BAD_PACKET);
  }

  if (frag)
    ft->frag_packets += data->pkt_num;

  /* If a matching flow does not exist, create and insert one */
  if (dont_summarize || ((flow = FLOW_FIND(FLOWS, &ft->flows, &tmp)) == NULL)) {
    /* Allocate and fill in the flow */
    if ((flow = malloc(sizeof(*flow))) == NULL) return (PP_MALLOC_FAIL);
    memcpy(flow, &tmp, sizeof(*flow));
    memcpy(&flow->flow_start, received_time, sizeof(flow->flow_start));
    flow->flow_seq = ft->next_flow_seq++;
    FLOW_INSERT(FLOWS, &ft->flows, flow);

    /* Allocate and fill in the associated expiry event */
    if ((flow->expiry = malloc(sizeof(*flow->expiry))) == NULL)
      return (PP_MALLOC_FAIL);
    flow->expiry->flow = flow;
    /* Expiration note: 0 means expire immediately; we prefer this to happen 
       when attaching to nfacctd - ie. dont_summarize is TRUE */
    if (!dont_summarize) flow->expiry->expires_at = 1;
    else flow->expiry->expires_at = 0;
    flow->expiry->reason = R_GENERAL;
    EXPIRY_INSERT(EXPIRIES, &ft->expiries, flow->expiry);

    if (data->flo_num) ft->num_flows += data->flo_num;
    else ft->num_flows++;

    if (verbose_flag) Log(LOG_DEBUG, "DEBUG ( %s/%s ): ADD FLOW %s\n",
		    config.name, config.type, format_flow_brief(flow));
  }
  else {
    /* Update flow statistics */
    flow->packets[0] += tmp.packets[0];
    flow->octets[0] += tmp.octets[0];
    flow->flows[0] += tmp.flows[0];
    flow->tcp_flags[0] |= tmp.tcp_flags[0];
    flow->tos[0] = tmp.tos[0]; // XXX
    flow->packets[1] += tmp.packets[1];
    flow->octets[1] += tmp.octets[1];
    flow->flows[1] += tmp.flows[1];
    flow->tcp_flags[1] |= tmp.tcp_flags[1];
    flow->tos[1] = tmp.tos[1]; // XXX
    /* Address family dependent items to update */
    switch (flow->af) {
    case AF_INET:
      ipv4_to_flowrec_update(flow, data, extras, &frag, af);
    break;
#if defined ENABLE_IPV6
    case AF_INET6:
      ipv6_to_flowrec_update(flow, data, extras, &frag, af);
    break;
#endif
    }
    if (!flow->class) flow->class = tmp.class;
    if (!flow->tag[0]) flow->tag[0] = tmp.tag[0];
    if (!flow->tag[1]) flow->tag[1] = tmp.tag[1];
    if (!flow->tag2[0]) flow->tag2[0] = tmp.tag2[0];
    if (!flow->tag2[1]) flow->tag2[1] = tmp.tag2[1];
  }
	
  memcpy(&flow->flow_last, received_time, sizeof(flow->flow_last));

  if (flow->expiry->expires_at != 0) flow_update_expiry(ft, flow);

  return (PP_OK);
}

/*
 * Subtract two timevals. Returns (t1 - t2) in milliseconds.
 */
u_int32_t
timeval_sub_ms(const struct timeval *t1, const struct timeval *t2)
{
	struct timeval res;

	res.tv_sec = t1->tv_sec - t2->tv_sec;
	res.tv_usec = t1->tv_usec - t2->tv_usec;
	if (res.tv_usec < 0) {
		res.tv_usec += 1000000L;
		res.tv_sec--;
	}
	return ((u_int32_t)res.tv_sec * 1000 + (u_int32_t)res.tv_usec / 1000);
}

static void
update_statistic(struct STATISTIC *s, double new, double n)
{
	if (n == 1.0) {
		s->min = s->mean = s->max = new;
		return;
	}

	s->min = MIN(s->min, new);
	s->max = MAX(s->max, new);

	s->mean = s->mean + ((new - s->mean) / n);
}

/* Update global statistics */
static void
update_statistics(struct FLOWTRACK *ft, struct FLOW *flow)
{
	double tmp;
	static double n = 1.0;

	ft->flows_expired++;
	ft->flows_pp[flow->protocol % 256]++;

	tmp = (double)flow->flow_last.tv_sec +
	    ((double)flow->flow_last.tv_usec / 1000000.0);
	tmp -= (double)flow->flow_start.tv_sec +
	    ((double)flow->flow_start.tv_usec / 1000000.0);
	if (tmp < 0.0)
		tmp = 0.0;

	update_statistic(&ft->duration, tmp, n);
	update_statistic(&ft->duration_pp[flow->protocol], tmp, 
	    (double)ft->flows_pp[flow->protocol % 256]);

	tmp = flow->octets[0] + flow->octets[1];
	update_statistic(&ft->octets, tmp, n);
	ft->octets_pp[flow->protocol % 256] += tmp;

	tmp = flow->packets[0] + flow->packets[1];
	update_statistic(&ft->packets, tmp, n);
	ft->packets_pp[flow->protocol % 256] += tmp;

	n++;
}

static void 
update_expiry_stats(struct FLOWTRACK *ft, struct EXPIRY *e)
{
	switch (e->reason) {
	case R_GENERAL:
		ft->expired_general++;
		break;
	case R_TCP:
		ft->expired_tcp++;
		break;
	case R_TCP_RST:
		ft->expired_tcp_rst++;
		break;
	case R_TCP_FIN:
		ft->expired_tcp_fin++;
		break;
	case R_UDP:
		ft->expired_udp++;
		break;
	case R_ICMP:
		ft->expired_icmp++;
		break;
	case R_MAXLIFE:
		ft->expired_maxlife++;
		break;
	case R_OVERBYTES:
		ft->expired_overbytes++;
		break;
	case R_OVERFLOWS:
		ft->expired_maxflows++;
		break;
	case R_FLUSH:
		ft->expired_flush++;
		break;
	}	
}

/* How long before the next expiry event in millisecond */
static int
next_expire(struct FLOWTRACK *ft)
{
	struct EXPIRY *expiry;
	struct timeval now;
	u_int32_t expires_at, ret, fudge;

	gettimeofday(&now, NULL);

	if ((expiry = EXPIRY_MIN(EXPIRIES, &ft->expiries)) == NULL)
		return (-1); /* indefinite */

	expires_at = expiry->expires_at;

	/* Don't cluster urgent expiries */
	if (expires_at == 0 && (expiry->reason == R_OVERBYTES || 
	    expiry->reason == R_OVERFLOWS || expiry->reason == R_FLUSH))
		return (0); /* Now */

	/* Cluster expiries by expiry_interval */
	if (ft->expiry_interval > 1) {
		if ((fudge = expires_at % ft->expiry_interval) > 0)
			expires_at += ft->expiry_interval - fudge;
	}

	if (expires_at < now.tv_sec)
		return (0); /* Now */

	ret = 999 + (expires_at - now.tv_sec) * 1000;
	return (ret);
}

/*
 * Scan the tree of expiry events and process expired flows. If zap_all
 * is set, then forcibly expire all flows.
 */
#define CE_EXPIRE_NORMAL	0  /* Normal expiry processing */
#define CE_EXPIRE_ALL		-1 /* Expire all flows immediately */
#define CE_EXPIRE_FORCED	1  /* Only expire force-expired flows */
static int
check_expired(struct FLOWTRACK *ft, struct NETFLOW_TARGET *target, int ex, u_int8_t engine_type, u_int8_t engine_id)
{
	struct FLOW **expired_flows, **oldexp;
	int num_expired, i, r;
	struct timeval now;

	struct EXPIRY *expiry, *nexpiry;

	gettimeofday(&now, NULL);

	r = 0;
	num_expired = 0;
	expired_flows = NULL;

	if (verbose_flag)
	  Log(LOG_DEBUG, "DEBUG ( %s/%s ): Starting expiry scan: mode %d\n", config.name, config.type, ex);

	for(expiry = EXPIRY_MIN(EXPIRIES, &ft->expiries);
	    expiry != NULL;
	    expiry = nexpiry) {
		nexpiry = EXPIRY_NEXT(EXPIRIES, &ft->expiries, expiry);
		if ((expiry->expires_at == 0) || (ex == CE_EXPIRE_ALL) || 
		    (ex != CE_EXPIRE_FORCED &&
		    (expiry->expires_at < now.tv_sec))) {
			/* Flow has expired */
			if (verbose_flag)
				Log(LOG_DEBUG, "DEBUG ( %s/%s ): Queuing flow seq:%llu (%p) for expiry\n",
				   config.name, config.type, expiry->flow->flow_seq, expiry->flow);

			/* Add to array of expired flows */
			oldexp = expired_flows;
			expired_flows = realloc(expired_flows,
			    sizeof(*expired_flows) * (num_expired + 1));
			/* Don't fatal on realloc failures */
			if (expired_flows == NULL)
				expired_flows = oldexp;
			else {
				expired_flows[num_expired] = expiry->flow;
				num_expired++;
			}

			if (ex == CE_EXPIRE_ALL)
				expiry->reason = R_FLUSH;

			update_expiry_stats(ft, expiry);

			/* Remove from flow tree, destroy expiry event */
			FLOW_REMOVE(FLOWS, &ft->flows, expiry->flow);
			EXPIRY_REMOVE(EXPIRIES, &ft->expiries, expiry);
			expiry->flow->expiry = NULL;
			free(expiry);

			ft->num_flows--;
		}
	}

	if (verbose_flag)
		Log(LOG_DEBUG, "DEBUG ( %s/%s ): Finished scan %d flow(s) to be evicted\n", config.name, config.type, num_expired);
	
	/* Processing for expired flows */
	if (num_expired > 0) {
		if (target != NULL && target->fd != -1) {
			r = target->dialect->func(expired_flows, num_expired, 
			    target->fd, &ft->flows_exported, // &ft->next_datagram_seq,
			    &ft->system_boot_time, verbose_flag, engine_type, engine_id);
			if (verbose_flag)
				Log(LOG_DEBUG, "DEBUG ( %s/%s ): Sent %d netflow packets\n", config.name, config.type, r);
			if (r > 0) {
				ft->packets_sent += r;
				/* XXX what if r < num_expired * 2 ? */
			} else {
				ft->flows_dropped += num_expired * 2;
			}
		}
		for (i = 0; i < num_expired; i++) {
			if (verbose_flag) {
				Log(LOG_DEBUG, "DEBUG ( %s/%s ): EXPIRED: %s (%p)\n", config.name, config.type, 
				    format_flow(expired_flows[i]),
				    expired_flows[i]);
			}
			update_statistics(ft, expired_flows[i]);

			free(expired_flows[i]);
		}
	
		free(expired_flows);
	}

	return (r == -1 ? -1 : num_expired);
}

/*
 * Force expiry of num_to_expire flows (e.g. when flow table overfull) 
 */
static void
force_expire(struct FLOWTRACK *ft, u_int32_t num_to_expire)
{
	struct EXPIRY *expiry, **expiryv;
	int i;

	/* XXX move all overflow processing here (maybe) */
	if (verbose_flag)
		Log(LOG_INFO, "INFO ( %s/%s ): Forcing expiry of %d flows\n",
		    config.name, config.type, num_to_expire);

	/*
	 * Do this in two steps, as it is dangerous to change a key on 
	 * a tree entry without first removing it and then re-adding it.
	 * It is even worse when this has to be done during a FOREACH :)
	 * To get around this, we make a list of expired flows and _then_ 
	 * alter them 
	 */
	 
	if ((expiryv = malloc(sizeof(*expiryv) * num_to_expire)) == NULL) {
		/*
		 * On malloc failure, expire ALL flows. I assume that 
		 * setting all the keys in a tree to the same value is 
		 * safe.
		 */
		Log(LOG_ERR, "ERROR ( %s/%s ): Out of memory while expiring flows\n", config.name, config.type);
		EXPIRY_FOREACH(expiry, EXPIRIES, &ft->expiries) {
			expiry->expires_at = 0;
			expiry->reason = R_OVERFLOWS;
			ft->flows_force_expired++;
		}
		return;
	}
	
	/* Make the list of flows to expire */
	i = 0;
	EXPIRY_FOREACH(expiry, EXPIRIES, &ft->expiries) {
		if (i >= num_to_expire)
			break;
		expiryv[i++] = expiry;
	}
	if (i < num_to_expire) {
		Log(LOG_ERR, "ERROR ( %s/%s ): Needed to expire %d flows, but only %d active.\n",
				config.name, config.type, num_to_expire, i);
		num_to_expire = i;
	}

	for(i = 0; i < num_to_expire; i++) {
		EXPIRY_REMOVE(EXPIRIES, &ft->expiries, expiryv[i]);
		expiryv[i]->expires_at = 0;
		expiryv[i]->reason = R_OVERFLOWS;
		EXPIRY_INSERT(EXPIRIES, &ft->expiries, expiryv[i]);
	}
	ft->flows_force_expired += num_to_expire;
	free(expiryv);
	/* XXX - this is overcomplicated, perhaps use a separate queue */
}

/* Delete all flows that we know about without processing */
static int
delete_all_flows(struct FLOWTRACK *ft)
{
	struct FLOW *flow, *nflow;
	int i;
	
	i = 0;
	for(flow = FLOW_MIN(FLOWS, &ft->flows); flow != NULL; flow = nflow) {
		nflow = FLOW_NEXT(FLOWS, &ft->flows, flow);
		FLOW_REMOVE(FLOWS, &ft->flows, flow);
		
		EXPIRY_REMOVE(EXPIRIES, &ft->expiries, flow->expiry);
		free(flow->expiry);

		ft->num_flows--;
		free(flow);
		i++;
	}
	
	return (i);
}

/*
 * Per-packet callback function from libpcap. Pass the packet (if it is IP)
 * sans datalink headers to process_packet.
 */

static void flow_cb(u_char *user_data, struct pkt_data *data, struct pkt_extras *extras)
{
  struct CB_CTXT *cb_ctxt = (struct CB_CTXT *)user_data;
  struct timeval tv;

  tv.tv_sec = data->time_start.tv_sec;
  tv.tv_usec = data->time_start.tv_usec; 
  if (process_packet(cb_ctxt->ft, data, extras, &tv) == PP_MALLOC_FAIL) cb_ctxt->fatal = 1;
}

static void
print_timeouts(struct FLOWTRACK *ft)
{
  Log(LOG_INFO, "INFO ( %s/%s ):           TCP timeout: %ds\n", config.name, config.type, ft->tcp_timeout);
  Log(LOG_INFO, "INFO ( %s/%s ):  TCP post-RST timeout: %ds\n", config.name, config.type, ft->tcp_rst_timeout);
  Log(LOG_INFO, "INFO ( %s/%s ):  TCP post-FIN timeout: %ds\n", config.name, config.type, ft->tcp_fin_timeout);
  Log(LOG_INFO, "INFO ( %s/%s ):           UDP timeout: %ds\n", config.name, config.type, ft->udp_timeout);
  Log(LOG_INFO, "INFO ( %s/%s ):          ICMP timeout: %ds\n", config.name, config.type, ft->icmp_timeout);
  Log(LOG_INFO, "INFO ( %s/%s ):       General timeout: %ds\n", config.name, config.type, ft->general_timeout);
  Log(LOG_INFO, "INFO ( %s/%s ):      Maximum lifetime: %ds\n", config.name, config.type, ft->maximum_lifetime);
  Log(LOG_INFO, "INFO ( %s/%s ):       Expiry interval: %ds\n", config.name, config.type, ft->expiry_interval);
}

static int
connsock(struct sockaddr_storage *addr, socklen_t len, int hoplimit)
{
  int s, ret = 0;
  unsigned int h6;
  unsigned char h4;
  struct sockaddr_in *in4 = (struct sockaddr_in *)addr;
#if defined ENABLE_IPV6
  struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
#endif
  struct sockaddr ssource_ip;

  if (config.nfprobe_source_ip) {
    ret = str_to_addr(config.nfprobe_source_ip, &config.nfprobe_source_ha);
    addr_to_sa(&ssource_ip, &config.nfprobe_source_ha, 0);
  }

  if ((s = socket(addr->ss_family, SOCK_DGRAM, 0)) == -1) {
    Log(LOG_ERR, "ERROR ( %s/%s ): socket() failed: %s\n", config.name, config.type, strerror(errno));
    exit_plugin(1);
  }

  if (config.nfprobe_ipprec) {
    int opt = config.nfprobe_ipprec << 5;
    int rc;

    rc = setsockopt(s, IPPROTO_IP, IP_TOS, &opt, sizeof(opt));
    if (rc < 0) Log(LOG_WARNING, "WARN ( %s/%s ): setsockopt() failed for IP_TOS: %s\n", config.name, config.type, strerror(errno));
  }

  if (config.pipe_size) {
    int rc;

    rc = Setsocksize(s, SOL_SOCKET, SO_SNDBUF, &config.pipe_size, sizeof(config.pipe_size));
    if (rc < 0) Log(LOG_WARNING, "WARN ( %s/%s ): setsockopt() failed for SOL_SNDBUF: %s\n", config.name, config.type, strerror(errno));
  }

  if (ret && bind(s, (struct sockaddr *) &ssource_ip, sizeof(ssource_ip)) == -1) {
    Log(LOG_ERR, "ERROR ( %s/%s ): bind() failed: %s\n", config.name, config.type, strerror(errno));
    exit_plugin(1);
  }

  if (connect(s, (struct sockaddr*)addr, len) == -1) {
    Log(LOG_ERR, "ERROR ( %s/%s ): connect() failed: %s\n", config.name, config.type, strerror(errno));
    exit_plugin(1);
  }

  switch (addr->ss_family) {
  case AF_INET:
    /* Default to link-local TTL for multicast addresses */
    if (hoplimit == -1 && IN_MULTICAST(in4->sin_addr.s_addr))
      hoplimit = 1;
    if (hoplimit == -1)
      break;
    h4 = hoplimit;
    if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &h4, sizeof(h4)) == -1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): setsockopt() failed for IP_MULTICAST_TTL: %s\n", config.name, config.type, strerror(errno));
      exit_plugin(1);
    }
    break;
#if defined ENABLE_IPV6
  case AF_INET6:
    /* Default to link-local hoplimit for multicast addresses */
    if (hoplimit == -1 && IN6_IS_ADDR_MULTICAST(&in6->sin6_addr))
      hoplimit = 1;
    if (hoplimit == -1)
      break;
    h6 = hoplimit;
    if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &h6, sizeof(h6)) == -1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): setsockopt() failed for IPV6_MULTICAST_HOPS: %s\n", config.name, config.type, strerror(errno));
      exit_plugin(1);
    }
#endif
  }

  return(s);
}

static void
init_flowtrack(struct FLOWTRACK *ft)
{
	/* Set up flow-tracking structure */
	memset(ft, '\0', sizeof(*ft));
	ft->next_flow_seq = 1;
	FLOW_INIT(&ft->flows);
	EXPIRY_INIT(&ft->expiries);
	
	ft->tcp_timeout = DEFAULT_TCP_TIMEOUT;
	ft->tcp_rst_timeout = DEFAULT_TCP_RST_TIMEOUT;
	ft->tcp_fin_timeout = DEFAULT_TCP_FIN_TIMEOUT;
	ft->udp_timeout = DEFAULT_UDP_TIMEOUT;
	ft->icmp_timeout = DEFAULT_ICMP_TIMEOUT;
	ft->general_timeout = DEFAULT_GENERAL_TIMEOUT;
	ft->maximum_lifetime = DEFAULT_MAXIMUM_LIFETIME;
	ft->expiry_interval = DEFAULT_EXPIRY_INTERVAL;
}

static void
set_timeout(struct FLOWTRACK *ft, const char *to_spec)
{
  char *name, *value;
  int timeout;

  if ((name = strdup(to_spec)) == NULL) return; 
  if ((value = strchr(name, '=')) == NULL || *(++value) == '\0') goto bad;

  *(value - 1) = '\0';
  timeout = convtime(value);
  if (timeout < 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): Invalid 'nfprobe_timeouts' value: '%s'\n", config.name, config.type, value);
    goto free_mem;
  }

  if (strcmp(name, "tcp") == 0)
    ft->tcp_timeout = timeout;
  else if (strcmp(name, "tcp.rst") == 0)
    ft->tcp_rst_timeout = timeout;
  else if (strcmp(name, "tcp.fin") == 0)
    ft->tcp_fin_timeout = timeout;
  else if (strcmp(name, "udp") == 0)
    ft->udp_timeout = timeout;
  else if (strcmp(name, "icmp") == 0)
    ft->icmp_timeout = timeout;
  else if (strcmp(name, "general") == 0)
    ft->general_timeout = timeout;
  else if (strcmp(name, "maxlife") == 0)
    ft->maximum_lifetime = timeout;
  else if (strcmp(name, "expint") == 0)
    ft->expiry_interval = timeout;
  else {
bad:
    Log(LOG_ERR, "ERROR ( %s/%s ): Invalid nfprobe_timeouts option: '%s'\n", config.name, config.type, name); 
    goto free_mem;
  }

  if (ft->general_timeout == 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): 'general' flow timeout must be greater than zero.\n", config.name, config.type);
    ft->general_timeout = DEFAULT_GENERAL_TIMEOUT; 
    goto free_mem;
  }

free_mem:
  free(name);
}

static void
handle_timeouts(struct FLOWTRACK *ft, char *to_spec)
{
  char *sep, *current = to_spec;

  trim_spaces(current);
  while (sep = strchr(current, ':')) {
    *sep = '\0';
    set_timeout(ft, current);
    *sep = ':';
    current = ++sep;
  }

  set_timeout(ft, current);
}

static void
parse_hostport(const char *s, struct sockaddr *addr, socklen_t *len)
{
  char *orig, *host, *port;
  struct addrinfo hints, *res;
  int herr;

  if ((host = orig = strdup(s)) == NULL) {
    Log(LOG_ERR, "ERROR ( %s/%s ): parse_hostport(), strdup() out of memory\n", config.name, config.type);
    exit_plugin(1);
  }

  trim_spaces(host);
  trim_spaces(orig);

  if ((port = strrchr(host, ':')) == NULL || *(++port) == '\0' || *host == '\0') {
    Log(LOG_ERR, "ERROR ( %s/%s ): parse_hostport(), invalid 'nfprobe_receiver' argument\n", config.name, config.type);
    exit_plugin(1);
  }
  *(port - 1) = '\0';
	
  /* Accept [host]:port for numeric IPv6 addresses */
  if (*host == '[' && *(port - 2) == ']') {
    host++;
    *(port - 2) = '\0';
  }

  memset(&hints, '\0', sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;

  if ((herr = getaddrinfo(host, port, &hints, &res)) == -1) {
    Log(LOG_ERR, "ERROR ( %s/%s ): parse_hostport(), address lookup failed\n", config.name, config.type);
    exit_plugin(1);
  }

  if (res == NULL || res->ai_addr == NULL) {
    Log(LOG_ERR, "ERROR ( %s/%s ): parse_hostport(), no addresses found for [%s]:%s\n", config.name, config.type, host, port);
    exit_plugin(1);
  }

  if (res->ai_addrlen > *len) {
    Log(LOG_ERR, "ERROR ( %s/%s ): parse_hostport(), address too long.\n", config.name, config.type);
    exit_plugin(1);
  }

  memcpy(addr, res->ai_addr, res->ai_addrlen);
  free(orig);
  *len = res->ai_addrlen;
}

static void
parse_engine(char *s, u_int8_t *engine_type, u_int8_t *engine_id)
{
  char *delim, *ptr;

  trim_spaces(s);
  delim = strchr(s, ':');
  if (delim) {
    *delim = '\0';
    ptr = delim+1;
    *engine_type = atoi(s);
    *engine_id = atoi(ptr);
    *delim = ':';
  }
  else {
    *engine_type = 0;
    *engine_id = 0;
    Log(LOG_WARNING, "WARN ( %s/%s ): Engine Type/ID '%s' is not valid. Ignoring.\n", config.name, config.type, s);
  }
}

void nfprobe_plugin(int pipe_fd, struct configuration *cfgptr, void *ptr)
{
  struct pkt_data *data, dummy;
  struct pkt_extras *extras;
  struct pkt_bgp_primitives *dummy_pbgp = NULL;
  struct ports_table pt;
  struct pollfd pfd;
  struct timezone tz;
  unsigned char *pipebuf;
  time_t now, refresh_deadline;
  int ret, num;
  char default_receiver[] = "127.0.0.1:2100";
  char default_engine[] = "0:0";
  struct ring *rg = &((struct channels_list_entry *)ptr)->rg;
  struct ch_status *status = ((struct channels_list_entry *)ptr)->status;
  u_int32_t bufsz = ((struct channels_list_entry *)ptr)->bufsize;
  struct networks_file_data nfd;

  unsigned char *rgptr, *dataptr;
  int pollagain = TRUE;
  u_int32_t seq = 1, rg_err_count = 0;

  char *capfile = NULL, dest_addr[256], dest_serv[256];
  int ch, linktype, ctlsock, i, r, err, always_v6;
  int max_flows, stop_collection_flag, exit_request, hoplimit;
  struct sockaddr_storage dest;
  struct FLOWTRACK flowtrack;
  socklen_t dest_len;
  struct NETFLOW_TARGET target;
  struct CB_CTXT cb_ctxt;
  u_int8_t engine_type, engine_id;

  /* XXX: glue */
  memcpy(&config, cfgptr, sizeof(struct configuration));
  recollect_pipe_memory(ptr);
  pm_setproctitle("%s [%s]", "Netflow Probe Plugin", config.name);
  if (config.pidfile) write_pid_file_plugin(config.pidfile, config.type, config.name);
  if (config.logfile) {
    fclose(config.logfile_fd);
    config.logfile_fd = open_logfile(config.logfile);
  }

  Log(LOG_INFO, "INFO ( %s/%s ): NetFlow probe plugin is originally based on softflowd 0.9.7 software, Copyright 2002 Damien Miller <djm@mindrot.org> All rights reserved.\n",
		  config.name, config.type);

  reload_map = FALSE;

  /* signal handling */
  signal(SIGINT, nfprobe_exit_gracefully);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, reload_maps);
  signal(SIGPIPE, SIG_IGN);
#if !defined FBSD4
  signal(SIGCHLD, SIG_IGN);
#else
  signal(SIGCHLD, ignore_falling_child);
#endif
	    
  memset(&cb_ctxt, '\0', sizeof(cb_ctxt));

  init_flowtrack(&flowtrack);

  memset(&dest, '\0', sizeof(dest));
  memset(&target, '\0', sizeof(target));
  target.fd = -1;
  target.dialect = &nf[0];
  always_v6 = 0;
  glob_flowtrack = &flowtrack;

  if (config.nfprobe_timeouts) handle_timeouts(&flowtrack, config.nfprobe_timeouts);
  timeout = flowtrack.expiry_interval * 1000;
  print_timeouts(&flowtrack);

  if (!config.nfprobe_hoplimit) hoplimit = -1;
  else hoplimit = config.nfprobe_hoplimit;

  if (!config.nfprobe_maxflows) max_flows = DEFAULT_MAX_FLOWS;
  else max_flows = config.nfprobe_maxflows;

  if (config.debug) verbose_flag = TRUE;
  if (config.pcap_savefile) capfile = config.pcap_savefile;

  dest_len = sizeof(dest);
  if (!config.nfprobe_receiver) config.nfprobe_receiver = default_receiver;
  if (!config.nfprobe_engine) config.nfprobe_engine = default_engine;
  parse_hostport(config.nfprobe_receiver, (struct sockaddr *)&dest, &dest_len);
  parse_engine(config.nfprobe_engine, &engine_type, &engine_id);

sort_version:
  for (i = 0, r = config.nfprobe_version; nf[i].version != -1; i++) {
    if (nf[i].version == r) break;
  }

  if (nf[i].version == -1) {
    config.nfprobe_version = 5; 
    goto sort_version;
  }
  target.dialect = &nf[i];

  /* Netflow send socket */
  if (dest.ss_family != 0) {
    if ((err = getnameinfo((struct sockaddr *)&dest,
	    dest_len, dest_addr, sizeof(dest_addr), 
	    dest_serv, sizeof(dest_serv), NI_NUMERICHOST)) == -1) {
      Log(LOG_ERR, "ERROR ( %s/%s ): getnameinfo: %d\n", config.name, config.type, err);
      exit_plugin(1);
    }
    target.fd = connsock(&dest, dest_len, hoplimit);
  }
	
  if (dest.ss_family != 0)
    Log(LOG_INFO, "INFO ( %s/%s ): Exporting flows to [%s]:%s\n",
		    config.name, config.type, dest_addr, dest_serv);

  /* Main processing loop */
  gettimeofday(&flowtrack.system_boot_time, NULL);
  stop_collection_flag = 0;
  cb_ctxt.ft = &flowtrack;
  cb_ctxt.linktype = linktype;
  cb_ctxt.want_v6 = target.dialect->v6_capable || always_v6;

  memset(&nt, 0, sizeof(nt));
  memset(&nc, 0, sizeof(nc));
  memset(&pt, 0, sizeof(pt));
  memset(&dummy, 0, sizeof(dummy));

  load_networks(config.networks_file, &nt, &nc);
  set_net_funcs(&nt);

  if (config.ports_file) load_ports(config.ports_file, &pt);

  pipebuf = (unsigned char *) Malloc(config.buffer_size);
  memset(pipebuf, 0, config.buffer_size);

  pfd.fd = pipe_fd;
  pfd.events = POLLIN;
  setnonblocking(pipe_fd);

  for(;;) {
poll_again:
    status->wakeup = TRUE;
    ret = poll(&pfd, 1, timeout);
    if (ret < 0) goto poll_again;

    /* Fatal error from per-packet functions */
    if (cb_ctxt.fatal) {
      Log(LOG_ERR, "ERROR ( %s/%s ): Fatal error - exiting immediately.\n", config.name, config.type);
      break;
    }

    if (reload_map) {
      load_networks(config.networks_file, &nt, &nc);
      load_ports(config.ports_file, &pt);
      reload_map = FALSE;
    }

    if (ret > 0) { /* we received data */
read_data:
      if (!pollagain) {
        seq++;
        seq %= MAX_SEQNUM;
        if (seq == 0) rg_err_count = FALSE;
      }
      else {
        if ((ret = read(pipe_fd, &rgptr, sizeof(rgptr))) == 0)
          exit_plugin(1); /* we exit silently; something happened at the write end */
      }

      if (((struct ch_buf_hdr *)rg->ptr)->seq != seq) {
	if (!pollagain) {
	  pollagain = TRUE;
	  goto handle_flow_expiration;
	}
	else {
	  rg_err_count++;
	  if (config.debug || (rg_err_count > MAX_RG_COUNT_ERR)) {
	    Log(LOG_ERR, "ERROR ( %s/%s ): We are missing data.\n", config.name, config.type);
	    Log(LOG_ERR, "If you see this message once in a while, discard it. Otherwise some solutions follow:\n");
	    Log(LOG_ERR, "- increase shared memory size, 'plugin_pipe_size'; now: '%u'.\n", config.pipe_size);
	    Log(LOG_ERR, "- increase buffer size, 'plugin_buffer_size'; now: '%u'.\n", config.buffer_size);
	    Log(LOG_ERR, "- increase system maximum socket size.\n\n");
	  }
	  seq = ((struct ch_buf_hdr *)rg->ptr)->seq;
	}
      }

      pollagain = FALSE;
      memcpy(pipebuf, rg->ptr, bufsz);
      if ((rg->ptr+bufsz) >= rg->end) rg->ptr = rg->base;
      else rg->ptr += bufsz;

      data = (struct pkt_data *) (pipebuf+sizeof(struct ch_buf_hdr));

      while (((struct ch_buf_hdr *)pipebuf)->num) {

	if (config.networks_file) {
	  memcpy(&dummy.primitives.src_ip, &data->primitives.src_ip, HostAddrSz);
	  memcpy(&dummy.primitives.dst_ip, &data->primitives.dst_ip, HostAddrSz);

          for (num = 0; net_funcs[num]; num++) (*net_funcs[num])(&nt, &nc, &dummy.primitives, dummy_pbgp, &nfd);

	  if (config.nfacctd_as == NF_AS_NEW) {
	    data->primitives.src_as = dummy.primitives.src_as;
	    data->primitives.dst_as = dummy.primitives.dst_as;
	  }

	  if (config.nfacctd_net == NF_NET_NEW) {
	    data->primitives.src_nmask = dummy.primitives.src_nmask;
            data->primitives.dst_nmask = dummy.primitives.dst_nmask;
	  }
	}

	if (config.ports_file) {
	  if (!pt.table[data->primitives.src_port]) data->primitives.src_port = 0;
	  if (!pt.table[data->primitives.dst_port]) data->primitives.dst_port = 0;
	}

        extras = (struct pkt_extras *) ((u_char *)data+PdataSz);

	handle_hostbyteorder_packet(data);
	flow_cb((void *)&cb_ctxt, data, extras);

	((struct ch_buf_hdr *)pipebuf)->num--;
	if (((struct ch_buf_hdr *)pipebuf)->num) {
	  dataptr = (unsigned char *) data;
	  dataptr += PdataSz + PextrasSz;
	  data = (struct pkt_data *) dataptr;
	}
      }
      goto read_data;
    }

handle_flow_expiration:
    /*
     * Expiry processing happens every recheck_rate seconds
     * or whenever we have exceeded the maximum number of active 
     * flows
     */
    if (flowtrack.num_flows > max_flows || next_expire(&flowtrack) == 0) {
expiry_check:
      /*
       * If we are reading from a capture file, we never
       * expire flows based on time - instead we only 
       * expire flows when the flow table is full. 
       */
      if (check_expired(&flowtrack, &target, capfile == NULL ? CE_EXPIRE_NORMAL : CE_EXPIRE_FORCED, engine_type, engine_id) < 0) {
	Log(LOG_WARNING, "WARN ( %s/%s ): Unable to export flows.\n", config.name, config.type);

	/* Let's try to sleep a bit and re-open the NetFlow send socket */
	if (dest.ss_family != 0) {
	  if (target.fd != -1) close(target.fd);
	  sleep(5);
	  target.fd = connsock(&dest, dest_len, hoplimit);

	  Log(LOG_INFO, "INFO ( %s/%s ): Exporting flows to [%s]:%s\n",
			config.name, config.type, dest_addr, dest_serv);
	}
      }
	
      /*
       * If we are over max_flows, force-expire the oldest 
       * out first and immediately reprocess to evict them
       */
      if (flowtrack.num_flows > max_flows) {
	force_expire(&flowtrack, flowtrack.num_flows - max_flows);
	goto expiry_check;
      }
    }
    
    /* Flags set by signal handlers or control socket */
    if (graceful_shutdown_request) {
      Log(LOG_WARNING, "WARN ( %s/%s ): Shutting down on user request.\n", config.name, config.type);
      check_expired(&flowtrack, &target, CE_EXPIRE_ALL, engine_type, engine_id);
      goto exit_lane;
    }
  }
		
exit_lane:
  if (!graceful_shutdown_request) Log(LOG_ERR, "ERROR ( %s/%s ): Exiting immediately on internal error.\n", config.name, config.type);
  if (target.fd != -1) close(target.fd);
}
