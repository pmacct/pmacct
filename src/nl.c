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

/* defines */
#define __NL_C

/* includes */
#include "pmacct.h"
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

void pcap_cb(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *buf)
{
  struct packet_ptrs pptrs;
  struct pcap_callback_data *cb_data = (struct pcap_callback_data *) user;
  struct pcap_device *device = cb_data->device;
  struct plugin_requests req;

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
    pptrs.ifindex_in = cb_data->ifindex_in;
    pptrs.ifindex_out = cb_data->ifindex_out;
    pptrs.flow_type = NF9_FTYPE_TRAFFIC;

    (*device->data->handler)(pkthdr, &pptrs);
    if (pptrs.iph_ptr) {
      if ((*pptrs.l3_handler)(&pptrs)) {
        if (config.nfacctd_isis) {
          isis_srcdst_lookup(&pptrs);
        }
        if (config.nfacctd_bgp) {
          BTA_find_id((struct id_table *)pptrs.bta_table, &pptrs, &pptrs.bta, &pptrs.bta2);
          bgp_srcdst_lookup(&pptrs, FUNC_TYPE_BGP);
        }
        if (config.nfacctd_bgp_peer_as_src_map) PM_find_id((struct id_table *)pptrs.bpas_table, &pptrs, &pptrs.bpas, NULL);
        if (config.nfacctd_bgp_src_local_pref_map) PM_find_id((struct id_table *)pptrs.blp_table, &pptrs, &pptrs.blp, NULL);
        if (config.nfacctd_bgp_src_med_map) PM_find_id((struct id_table *)pptrs.bmed_table, &pptrs, &pptrs.bmed, NULL);
        if (config.nfacctd_bmp) {
          BTA_find_id((struct id_table *)pptrs.bta_table, &pptrs, &pptrs.bta, &pptrs.bta2);
	  bmp_srcdst_lookup(&pptrs);
	}

	set_index_pkt_ptrs(&pptrs);
        exec_plugins(&pptrs, &req);
      }
    }
  }

  if (reload_map) {
    bta_map_caching = FALSE;
    sampling_map_caching = FALSE;

    load_networks(config.networks_file, &nt, &nc);

    if (config.nfacctd_bgp && config.nfacctd_bgp_peer_as_src_map)
      load_id_file(MAP_BGP_PEER_AS_SRC, config.nfacctd_bgp_peer_as_src_map, (struct id_table *)cb_data->bpas_table, &req, &bpas_map_allocated);
    if (config.nfacctd_bgp && config.nfacctd_bgp_src_local_pref_map)
      load_id_file(MAP_BGP_SRC_LOCAL_PREF, config.nfacctd_bgp_src_local_pref_map, (struct id_table *)cb_data->blp_table, &req, &blp_map_allocated);
    if (config.nfacctd_bgp && config.nfacctd_bgp_src_med_map)
      load_id_file(MAP_BGP_SRC_MED, config.nfacctd_bgp_src_med_map, (struct id_table *)cb_data->bmed_table, &req, &bmed_map_allocated);
    if (config.nfacctd_bgp)
      load_id_file(MAP_BGP_TO_XFLOW_AGENT, config.nfacctd_bgp_to_agent_map, (struct id_table *)cb_data->bta_table, &req, &bta_map_allocated);

    reload_map = FALSE;
    gettimeofday(&reload_map_tstamp, NULL);
  }
}

int ip_handler(register struct packet_ptrs *pptrs)
{
  register u_int8_t len = 0;
  register u_int16_t caplen = ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen;
  register unsigned char *ptr;
  register u_int16_t off = pptrs->iph_ptr-pptrs->packet_ptr, off_l4;
  int ret = TRUE, num, is_fragment = 0;

  /* len: number of 32bit words forming the header */
  len = IP_HL(((struct my_iphdr *) pptrs->iph_ptr));
  len <<= 2;
  ptr = pptrs->iph_ptr+len;
  off += len;

  /* check len */
  if (off > caplen) return FALSE; /* IP packet truncated */
  pptrs->l4_proto = ((struct my_iphdr *)pptrs->iph_ptr)->ip_p;
  pptrs->payload_ptr = NULL;
  off_l4 = off;

  /* check fragments if needed */
  if (config.handle_fragments) {
    if (pptrs->l4_proto == IPPROTO_TCP || pptrs->l4_proto == IPPROTO_UDP) {
      if (off+MyTLHdrSz > caplen) {
        Log(LOG_INFO, "INFO ( %s/core ): short IPv4 packet read (%u/%u/frags). Snaplen issue ?\n",
			config.name, caplen, off+MyTLHdrSz);
        return FALSE;
      }
      pptrs->tlh_ptr = ptr;

      if (((struct my_iphdr *)pptrs->iph_ptr)->ip_off & htons(IP_MF|IP_OFFMASK)) {
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
      if (((struct my_iphdr *)pptrs->iph_ptr)->ip_off & htons(IP_OFFMASK));
      else if (pptrs->l4_proto == IPPROTO_UDP) {
        ptr += UDPHdrSz;
        off += UDPHdrSz;
      }
      else if (pptrs->l4_proto == IPPROTO_TCP) {
        ptr += ((struct my_tcphdr *)pptrs->tlh_ptr)->th_off << 2;
        off += ((struct my_tcphdr *)pptrs->tlh_ptr)->th_off << 2;
      }
      if (off < caplen) pptrs->payload_ptr = ptr;
    }
    else {
      pptrs->tlh_ptr = dummy_tlhdr;
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
        if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_SYN) pptrs->tcp_flags |= TH_SYN;
        if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_FIN) pptrs->tcp_flags |= TH_FIN;
        if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_RST) pptrs->tcp_flags |= TH_RST;
        if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_ACK && pptrs->tcp_flags) pptrs->tcp_flags |= TH_ACK;
      }

      ip_flow_handler(pptrs);
    }

    /* XXX: optimize/short circuit here! */
    pptrs->tcp_flags = FALSE;
    if (pptrs->l4_proto == IPPROTO_TCP && off_l4+TCPFlagOff+1 <= caplen)
      pptrs->tcp_flags = ((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags;

    /* tunnel handlers here */ 
    if (config.tunnel0 && !pptrs->tun_stack) {
      for (num = 0; pptrs->payload_ptr && !is_fragment && tunnel_registry[0][num].tf; num++) {
        if (tunnel_registry[0][num].proto == pptrs->l4_proto) {
	  if (!tunnel_registry[0][num].port || (pptrs->tlh_ptr && tunnel_registry[0][num].port == ntohs(((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port))) {
	    pptrs->tun_stack = num;
	    ret = (*tunnel_registry[0][num].tf)(pptrs);
	  }
        }
      }
    }
    else if (pptrs->tun_stack) { 
      if (tunnel_registry[pptrs->tun_stack][pptrs->tun_layer].proto == pptrs->l4_proto) {
        if (!tunnel_registry[pptrs->tun_stack][pptrs->tun_layer].port || (pptrs->tlh_ptr && tunnel_registry[pptrs->tun_stack][pptrs->tun_layer].port == ntohs(((struct my_tlhdr *)pptrs->tlh_ptr)->dst_port))) {
          ret = (*tunnel_registry[pptrs->tun_stack][pptrs->tun_layer].tf)(pptrs);
        }
      }
    }
  }

  quit:
  return ret;
}

#if defined ENABLE_IPV6
int ip6_handler(register struct packet_ptrs *pptrs)
{
  struct ip6_frag *fhdr = NULL;
  register u_int16_t caplen = ((struct pcap_pkthdr *)pptrs->pkthdr)->caplen;
  u_int16_t len = 0, plen = ntohs(((struct ip6_hdr *)pptrs->iph_ptr)->ip6_plen);
  u_int16_t off = pptrs->iph_ptr-pptrs->packet_ptr, off_l4;
  u_int32_t advance;
  u_int8_t nh, fragmented = 0;
  u_char *ptr = pptrs->iph_ptr;
  int ret = TRUE;

  /* length checks */
  if (off+IP6HdrSz > caplen) return FALSE; /* IP packet truncated */
  if (plen == 0 && ((struct ip6_hdr *)pptrs->iph_ptr)->ip6_nxt != IPPROTO_NONE) {
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
        ptr += ((struct my_tcphdr *)pptrs->tlh_ptr)->th_off << 2;
        off += ((struct my_tcphdr *)pptrs->tlh_ptr)->th_off << 2;
      }
      if (off < caplen) pptrs->payload_ptr = ptr;
    }
    else {
      pptrs->tlh_ptr = dummy_tlhdr;
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
        if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_SYN) pptrs->tcp_flags |= TH_SYN;
        if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_FIN) pptrs->tcp_flags |= TH_FIN;
        if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_RST) pptrs->tcp_flags |= TH_RST;
        if (((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags & TH_ACK && pptrs->tcp_flags) pptrs->tcp_flags |= TH_ACK;
      }

      ip_flow6_handler(pptrs);
    }

    /* XXX: optimize/short circuit here! */
    pptrs->tcp_flags = FALSE;
    if (pptrs->l4_proto == IPPROTO_TCP && off_l4+TCPFlagOff+1 <= caplen)
      pptrs->tcp_flags = ((struct my_tcphdr *)pptrs->tlh_ptr)->th_flags;
  }

  quit:
  return TRUE;
}
#endif

int PM_find_id(struct id_table *t, struct packet_ptrs *pptrs, pm_id_t *tag, pm_id_t *tag2)
{
  int x, j;
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

    pretag_index_lookup(t, pptrs, index_results, ID_TABLE_INDEX_RESULTS);

    for (iterator = 0; index_results[iterator] && iterator < ID_TABLE_INDEX_RESULTS; iterator++) {
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
  PvhdrSz = sizeof(struct pkt_vlen_hdr_primitives);
  PmLabelTSz = sizeof(pm_label_t);
  PtLabelTSz = sizeof(pt_label_t);
  ChBufHdrSz = sizeof(struct ch_buf_hdr);
  CharPtrSz = sizeof(char *);
  IP4HdrSz = sizeof(struct my_iphdr);
  MyTLHdrSz = sizeof(struct my_tlhdr);
  TCPFlagOff = 13;
  MyTCPHdrSz = TCPFlagOff+1;
  PptrsSz = sizeof(struct packet_ptrs);
  UDPHdrSz = 8;
  CSSz = sizeof(struct class_st);
  IpFlowCmnSz = sizeof(struct ip_flow_common);
  HostAddrSz = sizeof(struct host_addr);
#if defined ENABLE_IPV6
  IP6HdrSz = sizeof(struct ip6_hdr);
  IP6AddrSz = sizeof(struct in6_addr);
#endif
}

void tunnel_registry_init()
{
  if (config.tunnel0) {
    char *tun_string = config.tunnel0, *tun_entry = NULL, *tun_type = NULL;
    int th_index = 0 /* tunnel handler index */, tr_index = 0 /* tunnel registry index */;
    int ret;

    while (tun_entry = extract_token(&tun_string, ';')) {
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
  struct my_gtphdr_v0 *gtp_hdr_v0 = (struct my_gtphdr_v0 *) pptrs->payload_ptr;
  struct my_gtphdr_v1 *gtp_hdr_v1 = (struct my_gtphdr_v1 *) pptrs->payload_ptr;
  struct my_udphdr *udp_hdr = (struct my_udphdr *) pptrs->tlh_ptr;
  u_int16_t off = pptrs->payload_ptr-pptrs->packet_ptr;
  u_int16_t gtp_hdr_len, gtp_opt_len, gtp_version;
  char *ptr = pptrs->payload_ptr;
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
#if defined ENABLE_IPV6
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
#endif
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
