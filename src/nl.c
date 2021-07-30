/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
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
#include "pmacct-dlt.h"
#include "pretag_handlers.h"
#include "plugin_hooks.h"
#include "pkt_handlers.h"
#include "ip_frag.h"
#include "ip_flow.h"
#include "net_aggr.h"
#include "thread_pool.h"
#include "isis/isis.h"
#include "bgp/bgp.h"
#include "bmp/bmp.h"
#if defined (WITH_NDPI)
#include "ndpi/ndpi.h"
#endif

struct tunnel_entry tunnel_handlers_list[] = {
  {"gtp", 	gtp_tunnel_func, 	gtp_tunnel_configurator},
  {"", 		NULL,			NULL},
};

void pm_pcap_cb(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *buf)
{
  struct packet_ptrs pptrs;
  struct pm_pcap_callback_data *cb_data = (struct pm_pcap_callback_data *) user;
  struct pm_pcap_device *device = cb_data->device;
  struct plugin_requests req;
  u_int32_t iface32 = 0;
  u_int32_t ifacePresent = 0;

  memset(&req, 0, sizeof(req));

  if (cb_data->sig.is_set) sigprocmask(SIG_BLOCK, &cb_data->sig.set, NULL);

  /* We process the packet with the appropriate
     data link layer function */
  if (buf) {
    memset(&pptrs, 0, sizeof(pptrs));

    pptrs.pkthdr = (struct pcap_pkthdr *) pkthdr;
    pptrs.packet_ptr = (u_char *) buf;
    pptrs.f_agent = cb_data->f_agent;
    pptrs.bpas_table = cb_data->bpas_table;
    pptrs.blp_table = cb_data->blp_table;
    pptrs.bmed_table = cb_data->bmed_table;
    pptrs.bta_table = cb_data->bta_table;
    pptrs.flow_type.traffic_type = PM_FTYPE_TRAFFIC;

    assert(cb_data);

    if (cb_data->has_tun_prims) {
      struct packet_ptrs *tpptrs;
 
      pptrs.tun_pptrs = malloc(sizeof(struct packet_ptrs));
      memset(pptrs.tun_pptrs, 0, sizeof(struct packet_ptrs));
      tpptrs = (struct packet_ptrs *) pptrs.tun_pptrs;

      tpptrs->pkthdr = malloc(sizeof(struct pcap_pkthdr));
      memcpy(&tpptrs->pkthdr, &pptrs.pkthdr, sizeof(struct pcap_pkthdr));

      tpptrs->packet_ptr = (u_char *) buf;
      tpptrs->flow_type.traffic_type = PM_FTYPE_TRAFFIC;
    }

    /* direction */
    if (cb_data->device &&
	cb_data->device->pcap_if &&
	cb_data->device->pcap_if->direction) {
      pptrs.direction = cb_data->device->pcap_if->direction;
    }
    else if (config.pcap_direction) {
      pptrs.direction = config.pcap_direction;
    }
    else pptrs.direction = FALSE;

    /* input interface */
    if (cb_data->ifindex_in) {
      pptrs.ifindex_in = cb_data->ifindex_in;
    }
    else if (cb_data->device &&
	     cb_data->device->id &&
	     cb_data->device->pcap_if &&
	     cb_data->device->pcap_if->direction) {
      if (cb_data->device->pcap_if->direction == PCAP_D_IN) {
        pptrs.ifindex_in = cb_data->device->id;
      }
    }
    else if (cb_data->device->id &&
	     config.pcap_direction == PCAP_D_IN) {
      pptrs.ifindex_in = cb_data->device->id;
    }
    else pptrs.ifindex_in = 0;

    /* output interface */
    if (cb_data->ifindex_out) {
      pptrs.ifindex_out = cb_data->ifindex_out;
    }
    else if (cb_data->device &&
	     cb_data->device->id &&
	     cb_data->device->pcap_if &&
             cb_data->device->pcap_if->direction) { 
      if (cb_data->device->pcap_if->direction == PCAP_D_OUT) {
        pptrs.ifindex_out = cb_data->device->id;
      }
    }
    else if (cb_data->device->id && config.pcap_direction == PCAP_D_OUT) {
      pptrs.ifindex_out = cb_data->device->id;
    }
    else pptrs.ifindex_out = 0;

    if (config.pcap_arista_trailer_offset) {
      memcpy(&ifacePresent, buf + pkthdr->len - config.pcap_arista_trailer_offset, 4);
      if (ifacePresent == config.pcap_arista_trailer_flag_value) {
        memcpy(&iface32, buf + pkthdr->len - (config.pcap_arista_trailer_offset - 4), 4);
        pptrs.ifindex_out = iface32;
      }
    }

    (*device->data->handler)(pkthdr, &pptrs);
    if (pptrs.iph_ptr) {
      if ((*pptrs.l3_handler)(&pptrs)) {

#if defined (WITH_NDPI)
        if (config.classifier_ndpi && pm_ndpi_wfl) {
          pptrs.ndpi_class = pm_ndpi_workflow_process_packet(pm_ndpi_wfl, &pptrs);
	}
#endif

        if (config.nfacctd_isis) {
          isis_srcdst_lookup(&pptrs);
        }
        if (config.bgp_daemon) {
          BTA_find_id((struct id_table *)pptrs.bta_table, &pptrs, &pptrs.bta, &pptrs.bta2);
          bgp_srcdst_lookup(&pptrs, FUNC_TYPE_BGP);
        }
        if (config.bgp_daemon_peer_as_src_map) PM_find_id((struct id_table *)pptrs.bpas_table, &pptrs, &pptrs.bpas, NULL);
        if (config.bgp_daemon_src_local_pref_map) PM_find_id((struct id_table *)pptrs.blp_table, &pptrs, &pptrs.blp, NULL);
        if (config.bgp_daemon_src_med_map) PM_find_id((struct id_table *)pptrs.bmed_table, &pptrs, &pptrs.bmed, NULL);
        if (config.bmp_daemon) {
          BTA_find_id((struct id_table *)pptrs.bta_table, &pptrs, &pptrs.bta, &pptrs.bta2);
	  bmp_srcdst_lookup(&pptrs);
	}

	set_index_pkt_ptrs(&pptrs);
        PM_evaluate_flow_type(&pptrs);
        exec_plugins(&pptrs, &req);
      }
    }
  }

  if (reload_map) {
    bta_map_caching = FALSE;
    sampling_map_caching = FALSE;

    load_networks(config.networks_file, &nt, &nc);

    if (config.bgp_daemon && config.bgp_daemon_peer_as_src_map)
      load_id_file(MAP_BGP_PEER_AS_SRC, config.bgp_daemon_peer_as_src_map, (struct id_table *)cb_data->bpas_table, &req, &bpas_map_allocated);
    if (config.bgp_daemon && config.bgp_daemon_src_local_pref_map)
      load_id_file(MAP_BGP_SRC_LOCAL_PREF, config.bgp_daemon_src_local_pref_map, (struct id_table *)cb_data->blp_table, &req, &blp_map_allocated);
    if (config.bgp_daemon && config.bgp_daemon_src_med_map)
      load_id_file(MAP_BGP_SRC_MED, config.bgp_daemon_src_med_map, (struct id_table *)cb_data->bmed_table, &req, &bmed_map_allocated);
    if (config.bgp_daemon)
      load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.bgp_daemon_to_xflow_agent_map, (struct id_table *)cb_data->bta_table, &req, &bta_map_allocated);

    reload_map = FALSE;
    gettimeofday(&reload_map_tstamp, NULL);
  }

  if (reload_log) {
    reload_logs();
    reload_log = FALSE;
  }

  if (cb_data->has_tun_prims && pptrs.tun_pptrs) {
    struct packet_ptrs *tpptrs = (struct packet_ptrs *) pptrs.tun_pptrs;

    if (tpptrs->pkthdr) free(tpptrs->pkthdr);
    free(pptrs.tun_pptrs);
  }

  if (cb_data->sig.is_set) sigprocmask(SIG_UNBLOCK, &cb_data->sig.set, NULL);
}

int ip_handler(register struct packet_ptrs *pptrs)
{
  register u_int8_t len = 0;
  register u_int16_t caplen = ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen;
  register unsigned char *ptr;
  register u_int16_t off = pptrs->iph_ptr-pptrs->packet_ptr, off_l4;
  int ret = TRUE, num, is_fragment = 0;

  /* len: number of 32bit words forming the header */
  len = IP_HL(((struct pm_iphdr *) pptrs->iph_ptr));
  len <<= 2;
  ptr = pptrs->iph_ptr+len;
  off += len;

  /* check len */
  if (off > caplen) return FALSE; /* IP packet truncated */
  pptrs->l4_proto = ((struct pm_iphdr *)pptrs->iph_ptr)->ip_p;
  pptrs->payload_ptr = NULL;
  off_l4 = off;

  /* check fragments if needed */
  if (config.handle_fragments) {
    if (pptrs->l4_proto == IPPROTO_TCP || pptrs->l4_proto == IPPROTO_UDP) {
      if (off+MyTLHdrSz > caplen) {
	if (!log_notification_isset(&log_notifications.snaplen_issue, ((struct pcap_pkthdr *)pptrs->pkthdr)->ts.tv_sec)) {
          Log(LOG_INFO, "INFO ( %s/core ): short IPv4 packet read (%u/%u/frags). Snaplen issue ?\n", config.name, caplen, off+MyTLHdrSz);
	  log_notification_set(&log_notifications.max_classifiers, ((struct pcap_pkthdr *)pptrs->pkthdr)->ts.tv_sec, 180);
          return FALSE;
	}
      }

      pptrs->tlh_ptr = ptr;

      if (((struct pm_iphdr *)pptrs->iph_ptr)->ip_off & htons(IP_MF|IP_OFFMASK)) {
	is_fragment = TRUE;
        ret = ip_fragment_handler(pptrs);
        if (!ret) {
          if (!config.ext_sampling_rate) goto quit;
          else {
            pptrs->tlh_ptr = dummy_tlhdr;
            pptrs->tcp_flags = FALSE;
            if (off < caplen) pptrs->payload_ptr = ptr;
            ret = TRUE;
            goto quit;
          }
        }
      }

      /* Let's handle both fragments and packets. If we are facing any subsequent frag
         our pointer is in place; we handle unknown L4 protocols likewise. In case of
         "entire" TCP/UDP packets we have to jump the L4 header instead */
      if (((struct pm_iphdr *)pptrs->iph_ptr)->ip_off & htons(IP_OFFMASK));
      else if (pptrs->l4_proto == IPPROTO_UDP) {
        ptr += UDPHdrSz;
        off += UDPHdrSz;
      }
      else if (pptrs->l4_proto == IPPROTO_TCP) {
        ptr += ((struct pm_tcphdr *)pptrs->tlh_ptr)->th_off << 2;
        off += ((struct pm_tcphdr *)pptrs->tlh_ptr)->th_off << 2;
      }

      if (off < caplen) {
	pptrs->payload_ptr = ptr;

	if (pptrs->l4_proto == IPPROTO_UDP) {
	  u_int16_t dst_port = ntohs(((struct pm_udphdr *)pptrs->tlh_ptr)->uh_dport);

	  if (dst_port == UDP_PORT_VXLAN && (off + sizeof(struct vxlan_hdr) <= caplen)) {
	    struct vxlan_hdr *vxhdr = (struct vxlan_hdr *) pptrs->payload_ptr; 

	    if (vxhdr->flags & VXLAN_FLAG_I) pptrs->vxlan_ptr = vxhdr->vni; 
	    pptrs->payload_ptr += sizeof(struct vxlan_hdr);

	    if (pptrs->tun_pptrs) {
	      struct packet_ptrs *tpptrs = (struct packet_ptrs *) pptrs->tun_pptrs;

	      tpptrs->pkthdr->caplen = (pptrs->pkthdr->caplen - (pptrs->payload_ptr - pptrs->packet_ptr)); 
	      tpptrs->packet_ptr = pptrs->payload_ptr;

	      eth_handler(tpptrs->pkthdr, tpptrs);
	      if (tpptrs->iph_ptr) ((*tpptrs->l3_handler)(tpptrs));
	    }
	  }
	}
      }
    }
    else {
      if (pptrs->l4_proto != IPPROTO_ICMP) {
        pptrs->tlh_ptr = dummy_tlhdr;
      }

      if (off < caplen) pptrs->payload_ptr = ptr;
    }

    if (config.handle_flows) {
      pptrs->tcp_flags = FALSE;

      if (pptrs->l4_proto == IPPROTO_TCP) {
        if (off_l4+TCPFlagOff+1 > caplen) {
          Log(LOG_INFO, "INFO ( %s/core ): short IPv4 packet read (%u/%u/flows). Snaplen issue ?\n",
			config.name, caplen, off_l4+TCPFlagOff+1);
          return FALSE;
        }
        if (((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_SYN) pptrs->tcp_flags |= TH_SYN;
        if (((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_FIN) pptrs->tcp_flags |= TH_FIN;
        if (((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_RST) pptrs->tcp_flags |= TH_RST;
        if (((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_ACK && pptrs->tcp_flags) pptrs->tcp_flags |= TH_ACK;
      }

      ip_flow_handler(pptrs);
    }

    /* XXX: optimize/short circuit here! */
    pptrs->tcp_flags = FALSE;
    if (pptrs->l4_proto == IPPROTO_TCP && off_l4+TCPFlagOff+1 <= caplen)
      pptrs->tcp_flags = ((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags;

    /* tunnel handlers here */
    if (config.tunnel0 && !pptrs->tun_stack) {
      for (num = 0; pptrs->payload_ptr && !is_fragment && tunnel_registry[0][num].tf; num++) {
        if (tunnel_registry[0][num].proto == pptrs->l4_proto) {
	  if (!tunnel_registry[0][num].port || (pptrs->tlh_ptr && tunnel_registry[0][num].port == ntohs(((struct pm_tlhdr *)pptrs->tlh_ptr)->dst_port))) {
	    pptrs->tun_stack = num;
	    ret = (*tunnel_registry[0][num].tf)(pptrs);
	  }
        }
      }
    }
    else if (pptrs->tun_stack) {
      if (tunnel_registry[pptrs->tun_stack][pptrs->tun_layer].proto == pptrs->l4_proto) {
        if (!tunnel_registry[pptrs->tun_stack][pptrs->tun_layer].port || (pptrs->tlh_ptr && tunnel_registry[pptrs->tun_stack][pptrs->tun_layer].port == ntohs(((struct pm_tlhdr *)pptrs->tlh_ptr)->dst_port))) {
          ret = (*tunnel_registry[pptrs->tun_stack][pptrs->tun_layer].tf)(pptrs);
        }
      }
    }
  }

  pptrs->icmp_type = FALSE;
  pptrs->icmp_code = FALSE;

  if (pptrs->l4_proto == IPPROTO_ICMP) {
    pptrs->tlh_ptr = ptr;

    pptrs->icmp_type = ((struct pm_icmphdr *)pptrs->tlh_ptr)->type;
    pptrs->icmp_code = ((struct pm_icmphdr *)pptrs->tlh_ptr)->code;
  }

  quit:

  if (ret) {
    pptrs->flow_type.traffic_type = PM_FTYPE_IPV4;
  }
 
  return ret;
}

int ip6_handler(register struct packet_ptrs *pptrs)
{
  struct ip6_frag *fhdr = NULL;
  register u_int16_t caplen = ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen;
  u_int16_t plen = ntohs(((struct ip6_hdr *)pptrs->iph_ptr)->ip6_plen);
  u_int16_t off = pptrs->iph_ptr-pptrs->packet_ptr, off_l4;
  u_int32_t advance;
  u_int8_t nh;
  u_char *ptr = pptrs->iph_ptr;
  int ret = TRUE;

  /* length checks */
  if (off+IP6HdrSz > caplen) return FALSE; /* IP packet truncated */
  if (plen == 0 && ((struct ip6_hdr *)pptrs->iph_ptr)->ip6_nxt == IPPROTO_HOPOPTS) {
    Log(LOG_INFO, "INFO ( %s/core ): NULL IPv6 payload length. Jumbo packets are currently not supported.\n", config.name);
    return FALSE;
  }

  pptrs->l4_proto = 0;
  pptrs->payload_ptr = NULL;
  nh = ((struct ip6_hdr *)pptrs->iph_ptr)->ip6_nxt;
  advance = IP6HdrSz;

  while ((off+advance <= caplen) && advance) {
    off += advance;
    ptr += advance;

    switch(nh) {
    case IPPROTO_HOPOPTS:
    case IPPROTO_DSTOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_MOBILITY:
      nh = ((struct ip6_ext *)ptr)->ip6e_nxt;
      advance = (((struct ip6_ext *)ptr)->ip6e_len + 1) << 3;
      break;
    case IPPROTO_AH:
      nh = ((struct ip6_ext *)ptr)->ip6e_nxt;
      advance = sizeof(struct ah)+(((struct ah *)ptr)->ah_len << 2); /* hdr + sumlen */
      break;
    case IPPROTO_FRAGMENT:
      fhdr = (struct ip6_frag *) ptr;
      nh = ((struct ip6_ext *)ptr)->ip6e_nxt;
      advance = sizeof(struct ip6_frag);
      break;
    /* XXX: case IPPROTO_ESP: */
    /* XXX: case IPPROTO_IPCOMP: */
    default:
      pptrs->tlh_ptr = ptr;
      pptrs->l4_proto = nh;
      goto end;
    }
  }

  end:

  off_l4 = off;
  if (config.handle_fragments) {
    if (pptrs->l4_proto == IPPROTO_TCP || pptrs->l4_proto == IPPROTO_UDP) {
      if (off+MyTLHdrSz > caplen) {
        Log(LOG_INFO, "INFO ( %s/core ): short IPv6 packet read (%u/%u/frags). Snaplen issue ?\n",
			config.name, caplen, off+MyTLHdrSz);
        return FALSE;
      }

      if (fhdr && (fhdr->ip6f_offlg & htons(IP6F_MORE_FRAG|IP6F_OFF_MASK))) {
        ret = ip6_fragment_handler(pptrs, fhdr);
        if (!ret) {
          if (!config.ext_sampling_rate) goto quit;
          else {
            pptrs->tlh_ptr = dummy_tlhdr;
            pptrs->tcp_flags = FALSE;
            if (off < caplen) pptrs->payload_ptr = ptr;
            ret = TRUE;
            goto quit;
          }
        }
      }

      /* Let's handle both fragments and packets. If we are facing any subsequent frag
         our pointer is in place; we handle unknown L4 protocols likewise. In case of
         "entire" TCP/UDP packets we have to jump the L4 header instead */
      if (fhdr && (fhdr->ip6f_offlg & htons(IP6F_OFF_MASK)));
      else if (pptrs->l4_proto == IPPROTO_UDP) {
        ptr += UDPHdrSz;
        off += UDPHdrSz;
      }
      else if (pptrs->l4_proto == IPPROTO_TCP) {
        ptr += ((struct pm_tcphdr *)pptrs->tlh_ptr)->th_off << 2;
        off += ((struct pm_tcphdr *)pptrs->tlh_ptr)->th_off << 2;
      }

      if (off < caplen) {
	pptrs->payload_ptr = ptr;

	if (pptrs->l4_proto == IPPROTO_UDP) {
	  u_int16_t dst_port = ntohs(((struct pm_udphdr *)pptrs->tlh_ptr)->uh_dport);

	  if (dst_port == UDP_PORT_VXLAN && (off + sizeof(struct vxlan_hdr) <= caplen)) {
	    struct vxlan_hdr *vxhdr = (struct vxlan_hdr *) pptrs->payload_ptr;

	    if (vxhdr->flags & VXLAN_FLAG_I) pptrs->vxlan_ptr = vxhdr->vni;
	    pptrs->payload_ptr += sizeof(struct vxlan_hdr);

	    if (pptrs->tun_pptrs) {
	      struct packet_ptrs *tpptrs = (struct packet_ptrs *) pptrs->tun_pptrs;

	      tpptrs->pkthdr->caplen = (pptrs->pkthdr->caplen - (pptrs->payload_ptr - pptrs->packet_ptr));
	      tpptrs->packet_ptr = pptrs->payload_ptr;

	      eth_handler(tpptrs->pkthdr, tpptrs);
	      if (tpptrs->iph_ptr) ((*tpptrs->l3_handler)(tpptrs));
            }
	  }
	}
      }
    }
    else {
      if (pptrs->l4_proto != IPPROTO_ICMPV6) {
        pptrs->tlh_ptr = dummy_tlhdr;
      }

      if (off < caplen) pptrs->payload_ptr = ptr;
    }

    if (config.handle_flows) {
      pptrs->tcp_flags = FALSE;

      if (pptrs->l4_proto == IPPROTO_TCP) {
        if (off_l4+TCPFlagOff+1 > caplen) {
          Log(LOG_INFO, "INFO ( %s/core ): short IPv6 packet read (%u/%u/flows). Snaplen issue ?\n",
			config.name, caplen, off_l4+TCPFlagOff+1);
          return FALSE;
        }
        if (((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_SYN) pptrs->tcp_flags |= TH_SYN;
        if (((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_FIN) pptrs->tcp_flags |= TH_FIN;
        if (((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_RST) pptrs->tcp_flags |= TH_RST;
        if (((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_ACK && pptrs->tcp_flags) pptrs->tcp_flags |= TH_ACK;
      }

      ip_flow6_handler(pptrs);
    }

    /* XXX: optimize/short circuit here! */
    pptrs->tcp_flags = FALSE;
    if (pptrs->l4_proto == IPPROTO_TCP && off_l4+TCPFlagOff+1 <= caplen)
      pptrs->tcp_flags = ((struct pm_tcphdr *)pptrs->tlh_ptr)->th_flags;
  }

  pptrs->icmp_type = FALSE;
  pptrs->icmp_code = FALSE;

  if (pptrs->l4_proto == IPPROTO_ICMPV6) {
    pptrs->icmp_type = ((struct pm_icmphdr *)pptrs->tlh_ptr)->type;
    pptrs->icmp_code = ((struct pm_icmphdr *)pptrs->tlh_ptr)->code;
  }

  quit:

  if (ret) {
    pptrs->flow_type.traffic_type = PM_FTYPE_IPV6;
  }

  return ret;
}

int PM_find_id(struct id_table *t, struct packet_ptrs *pptrs, pm_id_t *tag, pm_id_t *tag2)
{
  int x;
  pm_id_t ret = 0;

  if (!t) return 0;

  pretag_init_vars(pptrs, t);
  if (tag) *tag = 0;
  if (tag2) *tag2 = 0;
  if (pptrs) {
    pptrs->have_tag = FALSE;
    pptrs->have_tag2 = FALSE;
  }

  /* Giving a first try with index(es) */
  if (config.maps_index && pretag_index_have_one(t)) {
    struct id_entry *index_results[ID_TABLE_INDEX_RESULTS];
    u_int32_t iterator;
    int num_results;

    num_results = pretag_index_lookup(t, pptrs, index_results, ID_TABLE_INDEX_RESULTS);

    for (iterator = 0; index_results[iterator] && iterator < num_results; iterator++) {
      ret = pretag_entry_process(index_results[iterator], pptrs, tag, tag2);
      if (!(ret & PRETAG_MAP_RCODE_JEQ)) return ret;
    }

    /* if we have at least one index we trust we did a good job */
    return ret;
  }

  for (x = 0; x < t->ipv4_num; x++) {
    ret = pretag_entry_process(&t->e[x], pptrs, tag, tag2);

    if (!ret || ret > TRUE) {
      if (ret & PRETAG_MAP_RCODE_JEQ) {
        x = t->e[x].jeq.ptr->pos;
        x--; // yes, it will be automagically incremented by the for() cycle
      }
      else break;
    }
  }

  return ret;
}

void PM_print_stats(time_t now)
{
  int device_idx;

  Log(LOG_NOTICE, "NOTICE ( %s/%s ): +++\n", config.name, config.type);

  if (config.pcap_if || config.pcap_interfaces_map) {
    for (device_idx = 0; device_idx < devices.num; device_idx++) {
      if (pcap_stats(devices.list[device_idx].dev_desc, &ps) < 0) {
	Log(LOG_INFO, "INFO ( %s/%s ): stats [%s,%u] time=%ld error='pcap_stats(): %s'\n",
	    config.name, config.type, devices.list[device_idx].str, devices.list[device_idx].id,
	    (long)now, pcap_geterr(devices.list[device_idx].dev_desc));
      }

      Log(LOG_NOTICE, "NOTICE ( %s/%s ): stats [%s,%u] time=%ld received_packets=%u dropped_packets=%u\n",
	  config.name, config.type, devices.list[device_idx].str, devices.list[device_idx].id,
	  (long)now, ps.ps_recv, ps.ps_drop);
    }
  }

  Log(LOG_NOTICE, "NOTICE ( %s/%s ): ---\n", config.name, config.type);
}

void compute_once()
{
  struct pkt_data dummy;

  CounterSz = sizeof(dummy.pkt_len);
  PdataSz = sizeof(struct pkt_data);
  PpayloadSz = sizeof(struct pkt_payload);
  PextrasSz = sizeof(struct pkt_extras);
  PbgpSz = sizeof(struct pkt_bgp_primitives);
  PlbgpSz = sizeof(struct pkt_legacy_bgp_primitives);
  PnatSz = sizeof(struct pkt_nat_primitives);
  PmplsSz = sizeof(struct pkt_mpls_primitives);
  PtunSz = sizeof(struct pkt_tunnel_primitives);
  PvhdrSz = sizeof(struct pkt_vlen_hdr_primitives);
  PmLabelTSz = sizeof(pm_label_t);
  PtLabelTSz = sizeof(pt_label_t);
  ChBufHdrSz = sizeof(struct ch_buf_hdr);
  CharPtrSz = sizeof(char *);
  IP4HdrSz = sizeof(struct pm_iphdr);
  MyTLHdrSz = sizeof(struct pm_tlhdr);
  TCPFlagOff = 13;
  MyTCPHdrSz = TCPFlagOff+1;
  PptrsSz = sizeof(struct packet_ptrs);
  UDPHdrSz = 8;
  CSSz = sizeof(struct class_st);
  IpFlowCmnSz = sizeof(struct ip_flow_common);
  HostAddrSz = sizeof(struct host_addr);
  IP6HdrSz = sizeof(struct ip6_hdr);
  IP6AddrSz = sizeof(struct in6_addr);
}

void tunnel_registry_init()
{
  if (config.tunnel0) {
    char *tun_string = config.tunnel0, *tun_entry = NULL, *tun_type = NULL;
    int th_index = 0 /* tunnel handler index */, tr_index = 0 /* tunnel registry index */;

    while ((tun_entry = extract_token(&tun_string, ';'))) {
      tun_type = extract_token(&tun_entry, ',');

      for (th_index = 0; strcmp(tunnel_handlers_list[th_index].type, ""); th_index++) {
	if (!strcmp(tunnel_handlers_list[th_index].type, tun_type)) {
	  if (tr_index < TUNNEL_REGISTRY_ENTRIES) {
	    (*tunnel_handlers_list[th_index].tc)(&tunnel_registry[0][tr_index], tun_entry);
	    tr_index++;
	  }
	  break;
	}
      }
    }
  }
}

int gtp_tunnel_configurator(struct tunnel_handler *th, char *opts)
{
  th->proto = IPPROTO_UDP;
  th->port = atoi(opts);

  if (th->port) {
    th->tf = gtp_tunnel_func;
  }
  else {
    th->tf = NULL;
    Log(LOG_WARNING, "WARN ( %s/core ): GTP tunnel handler not loaded due to invalid options: '%s'\n", config.name, opts);
  }

  return 0;
}

int gtp_tunnel_func(register struct packet_ptrs *pptrs)
{
  register u_int16_t caplen = ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen;
  struct pm_gtphdr_v0 *gtp_hdr_v0 = (struct pm_gtphdr_v0 *) pptrs->payload_ptr;
  u_int16_t off = pptrs->payload_ptr-pptrs->packet_ptr;
  u_int16_t gtp_hdr_len, gtp_version;
  u_char *ptr = pptrs->payload_ptr;
  int ret, trial;

  gtp_version = (gtp_hdr_v0->flags >> 5) & 0x07;

  switch (gtp_version) {
  case 0:
    gtp_hdr_len = 4;
    break;
  case 1:
    gtp_hdr_len = 8;
    break;
  default:
    Log(LOG_INFO, "INFO ( %s/core ): unsupported GTP version %u\n", config.name, gtp_version);
    return FALSE;
  }

  if (off + gtp_hdr_len < caplen) {
    off += gtp_hdr_len;
    ptr += gtp_hdr_len;
    ret = 0; trial = 0;

    while (!ret && trial < MAX_GTP_TRIALS) {
      pptrs->iph_ptr = ptr;
      pptrs->tlh_ptr = NULL; pptrs->payload_ptr = NULL;
      pptrs->l4_proto = 0; pptrs->tcp_flags = 0;

      /* same trick used for MPLS BoS in ll.c: let's look at the first
	 payload byte to guess which protocol we are speaking about */
      switch (*pptrs->iph_ptr) {
      case 0x45:
      case 0x46:
      case 0x47:
      case 0x48:
      case 0x49:
      case 0x4a:
      case 0x4b:
      case 0x4c:
      case 0x4d:
      case 0x4e:
      case 0x4f:
	pptrs->tun_layer++;
	ret = ip_handler(pptrs);
	break;
      case 0x60:
      case 0x61:
      case 0x62:
      case 0x63:
      case 0x64:
      case 0x65:
      case 0x66:
      case 0x67:
      case 0x68:
      case 0x69:
      case 0x6a:
      case 0x6b:
      case 0x6c:
      case 0x6d:
      case 0x6e:
      case 0x6f:
	pptrs->tun_layer++;
	ret = ip6_handler(pptrs);
	break;
      default:
        ret = FALSE;
	break;
      }

      /* next loop increment */
      off++; ptr++; trial++;
    }
  }
  else {
    Log(LOG_INFO, "INFO ( %s/core ): short GTP packet read (%u/%u/tunnel). Snaplen issue ?\n",
			config.name, caplen, off + gtp_hdr_len);
    return FALSE;
  }

  return ret;
}

void reset_index_pkt_ptrs(struct packet_ptrs *pptrs)
{
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_PACKET_PTR] = NULL;
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_MAC_PTR] = NULL;
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_VLAN_PTR] = NULL;
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_MPLS_PTR] = NULL;
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_L3_PTR] = NULL;
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_L4_PTR] = NULL;
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_PAYLOAD_PTR] = NULL;

  pptrs->pkt_proto[CUSTOM_PRIMITIVE_L3_PTR] = FALSE;
  pptrs->pkt_proto[CUSTOM_PRIMITIVE_L4_PTR] = FALSE;
}

void set_index_pkt_ptrs(struct packet_ptrs *pptrs)
{
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_PACKET_PTR] = pptrs->packet_ptr;
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_MAC_PTR] = pptrs->mac_ptr;
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_VLAN_PTR] = pptrs->vlan_ptr;
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_MPLS_PTR] = pptrs->mpls_ptr;
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_L3_PTR] = pptrs->iph_ptr;
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_L4_PTR] = pptrs->tlh_ptr;
  pptrs->pkt_data_ptrs[CUSTOM_PRIMITIVE_PAYLOAD_PTR] = pptrs->payload_ptr;

  pptrs->pkt_proto[CUSTOM_PRIMITIVE_L3_PTR] = pptrs->l3_proto;
  pptrs->pkt_proto[CUSTOM_PRIMITIVE_L4_PTR] = pptrs->l4_proto;
}

void PM_evaluate_flow_type(struct packet_ptrs *pptrs)
{
  if (pptrs->l3_proto == ETHERTYPE_IP) {
    pptrs->flow_type.traffic_type = PM_FTYPE_IPV4;
  }
  else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
    pptrs->flow_type.traffic_type = PM_FTYPE_IPV6;
  }
}

ssize_t recvfrom_savefile(struct pm_pcap_device *device, void **buf, struct sockaddr *src_addr, struct timeval **ts, int *round, struct packet_ptrs *savefile_pptrs)
{
  ssize_t ret = 0;
  int pm_pcap_ret;

  read_packet:
  pm_pcap_ret = pcap_next_ex(device->dev_desc, &savefile_pptrs->pkthdr, (const u_char **)&savefile_pptrs->packet_ptr);

  if (pm_pcap_ret == 1 /* all good */) device->errors = FALSE;
  else if (pm_pcap_ret == -1 /* failed reading next packet */) {
    device->errors++;
    if (device->errors == PCAP_SAVEFILE_MAX_ERRORS) {
      Log(LOG_ERR, "ERROR ( %s/core ): pcap_ext_ex() max errors reached (%u). Exiting.\n", config.name, PCAP_SAVEFILE_MAX_ERRORS);
      exit_gracefully(1);
    }
    else {
      Log(LOG_WARNING, "WARN ( %s/core ): pcap_ext_ex() failed: %s. Skipping packet.\n", config.name, pcap_geterr(device->dev_desc));
      return 0;
    }
  }
  else if (pm_pcap_ret == -2 /* last packet in a pcap_savefile */) {
    pcap_close(device->dev_desc);

    if (config.pcap_sf_replay < 0 ||
	(config.pcap_sf_replay > 0 && (*round) < config.pcap_sf_replay)) {
      (*round)++;
      open_pcap_savefile(device, config.pcap_savefile);
      if (config.pcap_sf_delay) sleep(config.pcap_sf_delay);

      goto read_packet;
    }

    if (config.pcap_sf_wait) {
      fill_pipe_buffer();
      Log(LOG_INFO, "INFO ( %s/core ): finished reading PCAP capture file\n", config.name);
      wait(NULL);
    }

    stop_all_childs();
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/core ): unexpected return code from pcap_next_ex(). Exiting.\n", config.name);
    exit_gracefully(1);
  }

  (*device->data->handler)(savefile_pptrs->pkthdr, savefile_pptrs);
  if (savefile_pptrs->iph_ptr) {
    (*savefile_pptrs->l3_handler)(savefile_pptrs);
    if (savefile_pptrs->payload_ptr) {
      if (ts) (*ts) = &savefile_pptrs->pkthdr->ts; 
      (*buf) = savefile_pptrs->payload_ptr;
      ret = savefile_pptrs->pkthdr->caplen - (savefile_pptrs->payload_ptr - savefile_pptrs->packet_ptr);

      if (savefile_pptrs->l4_proto == IPPROTO_UDP || savefile_pptrs->l4_proto == IPPROTO_TCP) {
	if (savefile_pptrs->l3_proto == ETHERTYPE_IP) {
	  raw_to_sa((struct sockaddr *)src_addr, (u_char *) &((struct pm_iphdr *)savefile_pptrs->iph_ptr)->ip_src.s_addr,
		    (u_int16_t) ((struct pm_udphdr *)savefile_pptrs->tlh_ptr)->uh_sport, AF_INET);
	}
	else if (savefile_pptrs->l3_proto == ETHERTYPE_IPV6) {
	  raw_to_sa((struct sockaddr *)src_addr, (u_char *) &((struct ip6_hdr *)savefile_pptrs->iph_ptr)->ip6_src,
		    (u_int16_t) ((struct pm_udphdr *)savefile_pptrs->tlh_ptr)->uh_sport, AF_INET6);
	}
      }
    }
  }

  return ret;
}

ssize_t recvfrom_rawip(unsigned char *buf, size_t len, struct sockaddr *src_addr, struct packet_ptrs *local_pptrs)
{
  ssize_t ret = 0;

  local_pptrs->packet_ptr = buf;
  local_pptrs->pkthdr->caplen = len;

  raw_handler(local_pptrs->pkthdr, local_pptrs);

  if (local_pptrs->iph_ptr) {
    (*local_pptrs->l3_handler)(local_pptrs);
    if (local_pptrs->payload_ptr) {
      ret = local_pptrs->pkthdr->caplen - (local_pptrs->payload_ptr - local_pptrs->packet_ptr);

      if (local_pptrs->l4_proto == IPPROTO_UDP) {
        if (local_pptrs->l3_proto == ETHERTYPE_IP) {
          raw_to_sa((struct sockaddr *)src_addr, (u_char *) &((struct pm_iphdr *)local_pptrs->iph_ptr)->ip_src.s_addr,
                    (u_int16_t) ((struct pm_udphdr *)local_pptrs->tlh_ptr)->uh_sport, AF_INET);
        }
        else if (local_pptrs->l3_proto == ETHERTYPE_IPV6) {
          raw_to_sa((struct sockaddr *)src_addr, (u_char *) &((struct ip6_hdr *)local_pptrs->iph_ptr)->ip6_src,
                    (u_int16_t) ((struct pm_udphdr *)local_pptrs->tlh_ptr)->uh_sport, AF_INET6);
        }
      }

      /* last action: cut L3 and L4 off the packet */
      memmove(buf, local_pptrs->payload_ptr, ret);
    }
  }

  return ret;
}

void pm_pcap_add_filter(struct pm_pcap_device *dev_ptr)
{
  /* pcap library stuff */
  struct bpf_program filter;

  memset(&filter, 0, sizeof(filter));
  if (pcap_compile(dev_ptr->dev_desc, &filter, config.clbuf, 0, PCAP_NETMASK_UNKNOWN) < 0) {
    Log(LOG_WARNING, "WARN ( %s/core ): %s (going on without a filter)\n", config.name, pcap_geterr(dev_ptr->dev_desc));
  }
  else {
    if (pcap_setfilter(dev_ptr->dev_desc, &filter) < 0) {
      Log(LOG_WARNING, "WARN ( %s/core ): %s (going on without a filter)\n", config.name, pcap_geterr(dev_ptr->dev_desc));
    }
    else pcap_freecode(&filter);
  }
}
