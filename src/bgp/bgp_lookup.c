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
#include "plugin_hooks.h"
#include "pmacct-data.h"
#include "pkt_handlers.h"
#include "addr.h"
#include "bgp.h"
#include "pmbgpd.h"
#include "rpki/rpki.h"

void bgp_srcdst_lookup(struct packet_ptrs *pptrs, int type)
{
  struct bgp_misc_structs *bms;
  struct bgp_rt_structs *inter_domain_routing_db;
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent, sa_local;
  struct xflow_status_entry *xs_entry = (struct xflow_status_entry *) pptrs->f_status;
  struct bgp_peer *peer;
  struct bgp_node *default_node, *result;
  struct bgp_info *info = NULL;
  struct node_match_cmp_term2 nmct2;
  struct prefix default_prefix;
  int compare_bgp_port = config.tmp_bgp_lookup_compare_ports;
  int follow_default = config.bgp_daemon_follow_default;
  struct in_addr pref4;
  struct in6_addr pref6;
  safi_t safi;
  rd_t rd;

  bms = bgp_select_misc_db(type);
  inter_domain_routing_db = bgp_select_routing_db(type);

  if (!bms || !inter_domain_routing_db) return;

  pptrs->bgp_src = NULL;
  pptrs->bgp_dst = NULL;
  pptrs->bgp_src_info = NULL;
  pptrs->bgp_dst_info = NULL;
  pptrs->bgp_peer = NULL;
  pptrs->bgp_nexthop_info = NULL;
  safi = SAFI_UNICAST;

  memset(&rd, 0, sizeof(rd));

  if (pptrs->bta || pptrs->bta2) {
    sa = &sa_local;
    if (pptrs->bta_af == ETHERTYPE_IP) {
      sa->sa_family = AF_INET;
      ((struct sockaddr_in *)sa)->sin_addr.s_addr = pptrs->bta; 
      if (pptrs->lookup_bgp_port.set) {
	((struct sockaddr_in *)sa)->sin_port = pptrs->lookup_bgp_port.n; 
	compare_bgp_port = TRUE;
      }
    }
    else if (pptrs->bta_af == ETHERTYPE_IPV6) {
      sa->sa_family = AF_INET6;
      ip6_addr_32bit_cpy(&((struct sockaddr_in6 *)sa)->sin6_addr, &pptrs->bta, 0, 0, 1);
      ip6_addr_32bit_cpy(&((struct sockaddr_in6 *)sa)->sin6_addr, &pptrs->bta2, 2, 0, 1);
      if (pptrs->lookup_bgp_port.set) {
        ((struct sockaddr_in6 *)sa)->sin6_port = pptrs->lookup_bgp_port.n; 
	compare_bgp_port = TRUE;
      }
    }
  }

  start_again_follow_default:

  peer = bms->bgp_lookup_find_peer(sa, xs_entry, pptrs->l3_proto, compare_bgp_port);
  pptrs->bgp_peer = (char *) peer;

  if (peer) {
    struct host_addr peer_dst_ip;

    memset(&peer_dst_ip, 0, sizeof(peer_dst_ip));
    if ((peer->cap_add_paths[AFI_IP][SAFI_UNICAST] || peer->cap_add_paths[AFI_IP6][SAFI_UNICAST]) &&
	(config.acct_type == ACCT_NF || config.acct_type == ACCT_SF)) {
      /* administrativia */
      struct pkt_bgp_primitives pbgp, *pbgp_ptr = &pbgp;
      memset(&pbgp, 0, sizeof(struct pkt_bgp_primitives));
      
      /* note: call to [NF|SF]_peer_dst_ip_handler for the purpose of
	 code re-use effectively is defeating the concept of libbgp */
      if (config.acct_type == ACCT_NF) NF_peer_dst_ip_handler(NULL, pptrs, (char **)&pbgp_ptr);
      else if (config.acct_type == ACCT_SF) SF_peer_dst_ip_handler(NULL, pptrs, (char **)&pbgp_ptr);

      memcpy(&peer_dst_ip, &pbgp.peer_dst_ip, sizeof(struct host_addr));
    }

    if (pptrs->bitr) {
      safi = SAFI_MPLS_VPN;
      memcpy(&rd, &pptrs->bitr, sizeof(rd));
    }

    /* XXX: can be further optimized for the case of no SAFI_UNICAST rib */
    start_again_mpls_vpn:
    start_again_mpls_label:

    if (pptrs->l3_proto == ETHERTYPE_IP) {
      if (!pptrs->bgp_src) {
	memset(&nmct2, 0, sizeof(struct node_match_cmp_term2));
	nmct2.peer = (struct bgp_peer *) pptrs->bgp_peer;
	nmct2.afi = AFI_IP;
	nmct2.safi = safi;
	nmct2.rd = &rd;
	nmct2.peer_dst_ip = NULL;

        memcpy(&pref4, &((struct pm_iphdr *)pptrs->iph_ptr)->ip_src, sizeof(struct in_addr));
	bgp_node_match_ipv4(inter_domain_routing_db->rib[AFI_IP][safi],
			    &pref4, (struct bgp_peer *) pptrs->bgp_peer,
		     	    bms->route_info_modulo,
			    bms->bgp_lookup_node_match_cmp, &nmct2,
			    bms->bnv, &result, &info);
      }

      if (!pptrs->bgp_src_info && result) {
        pptrs->bgp_src = (char *) result;
	pptrs->bgp_src_info = (char *) info;
        if (result->p.prefixlen >= pptrs->lm_mask_src) {
          pptrs->lm_mask_src = result->p.prefixlen;
          pptrs->lm_method_src = NF_NET_BGP;

	  if (config.rpki_roas_file || config.rpki_rtr_cache) {
	    pptrs->src_roa = rpki_vector_prefix_lookup(bms->bnv);
	  }
        }
      }

      if (!pptrs->bgp_dst) {
        memset(&nmct2, 0, sizeof(struct node_match_cmp_term2));
        nmct2.peer = (struct bgp_peer *) pptrs->bgp_peer;
	nmct2.afi = AFI_IP;
	nmct2.safi = safi;
        nmct2.rd = &rd;
        nmct2.peer_dst_ip = &peer_dst_ip;

	memcpy(&pref4, &((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst, sizeof(struct in_addr));
	bgp_node_match_ipv4(inter_domain_routing_db->rib[AFI_IP][safi],
			    &pref4, (struct bgp_peer *) pptrs->bgp_peer,
			    bms->route_info_modulo,
			    bms->bgp_lookup_node_match_cmp, &nmct2,
			    bms->bnv, &result, &info);
      }

      if (!pptrs->bgp_dst_info && result) {
        pptrs->bgp_dst = (char *) result;
        pptrs->bgp_dst_info = (char *) info;
        if (result->p.prefixlen >= pptrs->lm_mask_dst) {
          pptrs->lm_mask_dst = result->p.prefixlen;
          pptrs->lm_method_dst = NF_NET_BGP;

	  if (config.rpki_roas_file || config.rpki_rtr_cache) {
	    pptrs->dst_roa = rpki_vector_prefix_lookup(bms->bnv);
	  }
        }
      }
    }
    else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
      if (!pptrs->bgp_src) {
        memset(&nmct2, 0, sizeof(struct node_match_cmp_term2));
        nmct2.peer = (struct bgp_peer *) pptrs->bgp_peer;
	nmct2.afi = AFI_IP6;
	nmct2.safi = safi;
        nmct2.rd = &rd;
        nmct2.peer_dst_ip = NULL;

        memcpy(&pref6, &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_src, sizeof(struct in6_addr));
	bgp_node_match_ipv6(inter_domain_routing_db->rib[AFI_IP6][safi],
		            &pref6, (struct bgp_peer *) pptrs->bgp_peer,
		            bms->route_info_modulo,
		            bms->bgp_lookup_node_match_cmp, &nmct2,
		            bms->bnv, &result, &info);
      }

      if (!pptrs->bgp_src_info && result) {
        pptrs->bgp_src = (char *) result;
        pptrs->bgp_src_info = (char *) info;
        if (result->p.prefixlen >= pptrs->lm_mask_src) {
          pptrs->lm_mask_src = result->p.prefixlen;
          pptrs->lm_method_src = NF_NET_BGP;

	  if (config.rpki_roas_file || config.rpki_rtr_cache) {
	    pptrs->src_roa = rpki_vector_prefix_lookup(bms->bnv); 
	  }
        }
      }

      if (!pptrs->bgp_dst) {
        memset(&nmct2, 0, sizeof(struct node_match_cmp_term2));
        nmct2.peer = (struct bgp_peer *) pptrs->bgp_peer;
	nmct2.afi = AFI_IP6;
	nmct2.safi = safi;
        nmct2.rd = &rd;
        nmct2.peer_dst_ip = &peer_dst_ip;

        memcpy(&pref6, &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_dst, sizeof(struct in6_addr));
	bgp_node_match_ipv6(inter_domain_routing_db->rib[AFI_IP6][safi],
	     		    &pref6, (struct bgp_peer *) pptrs->bgp_peer,
			    bms->route_info_modulo,
			    bms->bgp_lookup_node_match_cmp, &nmct2,
			    bms->bnv, &result, &info);
      }

      if (!pptrs->bgp_dst_info && result) {
        pptrs->bgp_dst = (char *) result;
        pptrs->bgp_dst_info = (char *) info;
        if (result->p.prefixlen >= pptrs->lm_mask_dst) {
          pptrs->lm_mask_dst = result->p.prefixlen;
          pptrs->lm_method_dst = NF_NET_BGP;

	  if (config.rpki_roas_file || config.rpki_rtr_cache) {
	    pptrs->dst_roa = rpki_vector_prefix_lookup(bms->bnv);
	  }
        }
      }
    }

    /* XXX: tackle the case of Peer Distinguisher from BMP header
       probably needs deeper thoughts for a cleaner approach */
    if ((!pptrs->bgp_src || !pptrs->bgp_dst) && safi == SAFI_MPLS_VPN && type == FUNC_TYPE_BMP) {
      safi = SAFI_UNICAST;
      goto start_again_mpls_vpn;
    }

    if ((!pptrs->bgp_src || !pptrs->bgp_dst) && safi != SAFI_MPLS_LABEL) {
      if (pptrs->l3_proto == ETHERTYPE_IP && inter_domain_routing_db->rib[AFI_IP][SAFI_MPLS_LABEL]) {
        safi = SAFI_MPLS_LABEL;
        goto start_again_mpls_label;
      }
      else if (pptrs->l3_proto == ETHERTYPE_IPV6 && inter_domain_routing_db->rib[AFI_IP6][SAFI_MPLS_LABEL]) {
        safi = SAFI_MPLS_LABEL;
        goto start_again_mpls_label;
      }
    }

    if (follow_default && safi != SAFI_MPLS_VPN) {
      default_node = NULL;

      if (pptrs->l3_proto == ETHERTYPE_IP) {
        memset(&default_prefix, 0, sizeof(default_prefix));
        default_prefix.family = AF_INET;

        result = (struct bgp_node *) pptrs->bgp_src;
        if (result && prefix_match(&result->p, &default_prefix)) {
	  default_node = result;
	  pptrs->bgp_src = NULL;
	  pptrs->bgp_src_info = NULL;
        }

        result = (struct bgp_node *) pptrs->bgp_dst;
        if (result && prefix_match(&result->p, &default_prefix)) {
	  default_node = result;
	  pptrs->bgp_dst = NULL;
	  pptrs->bgp_dst_info = NULL;
        }
      }
      else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
        memset(&default_prefix, 0, sizeof(default_prefix));
        default_prefix.family = AF_INET6;

        result = (struct bgp_node *) pptrs->bgp_src;
        if (result && prefix_match(&result->p, &default_prefix)) {
          default_node = result;
          pptrs->bgp_src = NULL;
          pptrs->bgp_src_info = NULL;
        }

        result = (struct bgp_node *) pptrs->bgp_dst;
        if (result && prefix_match(&result->p, &default_prefix)) {
          default_node = result;
          pptrs->bgp_dst = NULL;
          pptrs->bgp_dst_info = NULL;
        }
      }
      
      if (!pptrs->bgp_src || !pptrs->bgp_dst) {
	follow_default--;
	compare_bgp_port = FALSE; // XXX: fixme: follow default in NAT traversal scenarios

        if (default_node) {
          if (info && info->attr) {
            if (info->attr->mp_nexthop.family == AF_INET) {
              sa = &sa_local;
              memset(sa, 0, sizeof(struct sockaddr));
              sa->sa_family = AF_INET;
              memcpy(&((struct sockaddr_in *)sa)->sin_addr, &info->attr->mp_nexthop.address.ipv4, 4);
	      goto start_again_follow_default;
            }
            else if (info->attr->mp_nexthop.family == AF_INET6) {
              sa = &sa_local;
              memset(sa, 0, sizeof(struct sockaddr));
              sa->sa_family = AF_INET6;
              ip6_addr_cpy(&((struct sockaddr_in6 *)sa)->sin6_addr, &info->attr->mp_nexthop.address.ipv6);
              goto start_again_follow_default;
            }
            else {
              sa = &sa_local;
              memset(sa, 0, sizeof(struct sockaddr));
              sa->sa_family = AF_INET;
              memcpy(&((struct sockaddr_in *)sa)->sin_addr, &info->attr->nexthop, 4);
              goto start_again_follow_default;
	    }
	  }
        }
      }
    }

    if (config.bgp_daemon_follow_nexthop[0].family && pptrs->bgp_dst && safi != SAFI_MPLS_VPN)
      bgp_follow_nexthop_lookup(pptrs, type);
  }
}

void bgp_follow_nexthop_lookup(struct packet_ptrs *pptrs, int type)
{
  struct bgp_misc_structs *bms;
  struct bgp_rt_structs *inter_domain_routing_db;
  struct sockaddr *sa = (struct sockaddr *) pptrs->f_agent, sa_local;
  struct bgp_peer *nh_peer;
  struct bgp_node *result_node = NULL;
  struct bgp_info *info = NULL;
  struct node_match_cmp_term2 nmct2;
  char *saved_info = NULL;
  int peers_idx, ttl = MAX_HOPS_FOLLOW_NH, self = MAX_NH_SELF_REFERENCES;
  int nh_idx, matched = 0;
  struct prefix nh, ch;
  struct in_addr pref4;
  struct in6_addr pref6;
  u_char *saved_agent = pptrs->f_agent;
  pm_id_t bta;
  u_int32_t modulo, local_modulo, modulo_idx, modulo_max;

  bms = bgp_select_misc_db(type);
  inter_domain_routing_db = bgp_select_routing_db(type);

  if (!bms || !inter_domain_routing_db) return;

  start_again:

  if (config.bgp_daemon_to_xflow_agent_map && (*find_id_func)) {
    bta = 0;
    (*find_id_func)((struct id_table *)pptrs->bta_table, pptrs, &bta, NULL);
    if (bta) {
      sa = &sa_local;
      sa->sa_family = AF_INET;
      ((struct sockaddr_in *)sa)->sin_addr.s_addr = bta;
    }
  }

  for (nh_peer = NULL, peers_idx = 0; peers_idx < bms->max_peers; peers_idx++) {
    if (!sa_addr_cmp(sa, &peers[peers_idx].addr) ||
	(!config.bgp_disable_router_id_check && !sa_addr_cmp(sa, &peers[peers_idx].id))) {
      nh_peer = &peers[peers_idx];
      break;
    }
  }

  if (nh_peer) {
    modulo = bms->route_info_modulo(nh_peer, NULL, bms->table_per_peer_buckets);

    // XXX: to be optimized 
    if (bms->table_per_peer_hash == BGP_ASPATH_HASH_PATHID) modulo_max = bms->table_per_peer_buckets;
    else modulo_max = 1;

    memset(&ch, 0, sizeof(ch));
    ch.family = AF_INET;
    ch.prefixlen = 32;
    memcpy(&ch.u.prefix4, &nh_peer->addr.address.ipv4, 4);

    if (!result_node) {
      struct host_addr peer_dst_ip;
      rd_t rd;

      /* XXX: SAFI_MPLS_LABEL, SAFI_MPLS_VPN and peer_dst_ip (add_paths capability) not supported */
      memset(&peer_dst_ip, 0, sizeof(peer_dst_ip));
      memset(&rd, 0, sizeof(rd));
      memset(&nmct2, 0, sizeof(struct node_match_cmp_term2));

      nmct2.peer = (struct bgp_peer *) nh_peer;
      nmct2.rd = &rd;
      nmct2.peer_dst_ip = &peer_dst_ip;

      if (pptrs->l3_proto == ETHERTYPE_IP) {
        memcpy(&pref4, &((struct pm_iphdr *)pptrs->iph_ptr)->ip_dst, sizeof(struct in_addr));
        bgp_node_match_ipv4(inter_domain_routing_db->rib[AFI_IP][SAFI_UNICAST], &pref4, nh_peer,
			    bms->route_info_modulo,
			    bms->bgp_lookup_node_match_cmp, &nmct2,
			    NULL, &result_node, &info);
      }
      else if (pptrs->l3_proto == ETHERTYPE_IPV6) {
        memcpy(&pref6, &((struct ip6_hdr *)pptrs->iph_ptr)->ip6_dst, sizeof(struct in6_addr));
        bgp_node_match_ipv6(inter_domain_routing_db->rib[AFI_IP6][SAFI_UNICAST], &pref6, nh_peer,
			    bms->route_info_modulo,
			    bms->bgp_lookup_node_match_cmp, &nmct2,
			    NULL, &result_node, &info);
      }
    }

    memset(&nh, 0, sizeof(nh));

    // XXX: to be optimized
    if (result_node) {
      for (local_modulo = modulo, modulo_idx = 0; modulo_idx < modulo_max; local_modulo++, modulo_idx++) {
        for (info = result_node->info[modulo]; info; info = info->next) {
          if (info->peer == nh_peer) break;
	}
      }
    }
    else info = NULL;

    if (info && info->attr) {
      if (info->attr->mp_nexthop.family == AF_INET) {
	nh.family = AF_INET;
	nh.prefixlen = 32;
	memcpy(&nh.u.prefix4, &info->attr->mp_nexthop.address.ipv4, 4);

	for (nh_idx = 0; config.bgp_daemon_follow_nexthop[nh_idx].family && nh_idx < FOLLOW_BGP_NH_ENTRIES; nh_idx++) {
	  matched = prefix_match(&config.bgp_daemon_follow_nexthop[nh_idx], &nh);
	  if (matched) break;
	}

	if (matched && self > 0 && ttl > 0) { 
	  if (prefix_match(&ch, &nh)) self--;
          sa = &sa_local;
          pptrs->f_agent = (u_char *) &sa_local;
          memset(sa, 0, sizeof(struct sockaddr));
          sa->sa_family = AF_INET;
          memcpy(&((struct sockaddr_in *)sa)->sin_addr, &info->attr->mp_nexthop.address.ipv4, 4);
	  saved_info = (char *) info;
	  ttl--;
          goto start_again;
        }
	else {
	  if (config.bgp_daemon_follow_nexthop_external) saved_info = (char *) info;
	  goto end;
	}
      }
      else if (info->attr->mp_nexthop.family == AF_INET6) {
	nh.family = AF_INET6;
	nh.prefixlen = 128;
	memcpy(&nh.u.prefix6, &info->attr->mp_nexthop.address.ipv6, 16);

        for (nh_idx = 0; config.bgp_daemon_follow_nexthop[nh_idx].family && nh_idx < FOLLOW_BGP_NH_ENTRIES; nh_idx++) {
          matched = prefix_match(&config.bgp_daemon_follow_nexthop[nh_idx], &nh);
          if (matched) break;
        }

	if (matched && self > 0 && ttl > 0) {
	  if (prefix_match(&ch, &nh)) self--;
          sa = &sa_local;
          pptrs->f_agent = (u_char *) &sa_local;
          memset(sa, 0, sizeof(struct sockaddr));
          sa->sa_family = AF_INET6;
          ip6_addr_cpy(&((struct sockaddr_in6 *)sa)->sin6_addr, &info->attr->mp_nexthop.address.ipv6);
	  saved_info = (char *) info;
	  ttl--;
          goto start_again;
	}
	else {
	  if (config.bgp_daemon_follow_nexthop_external) saved_info = (char *) info;
	  goto end;
	}
      }
      else {
	nh.family = AF_INET;
	nh.prefixlen = 32;
	memcpy(&nh.u.prefix4, &info->attr->nexthop, 4);

        for (nh_idx = 0; config.bgp_daemon_follow_nexthop[nh_idx].family && nh_idx < FOLLOW_BGP_NH_ENTRIES; nh_idx++) {
          matched = prefix_match(&config.bgp_daemon_follow_nexthop[nh_idx], &nh);
          if (matched) break;
        }

	if (matched && self > 0 && ttl > 0) {
	  if (prefix_match(&ch, &nh)) self--;
          sa = &sa_local;
          pptrs->f_agent = (u_char *) &sa_local;
          memset(sa, 0, sizeof(struct sockaddr));
          sa->sa_family = AF_INET;
          memcpy(&((struct sockaddr_in *)sa)->sin_addr, &info->attr->nexthop, 4);
	  saved_info = (char *) info;
	  ttl--;
          goto start_again;
	}
	else {
	  if (config.bgp_daemon_follow_nexthop_external) saved_info = (char *) info;
	  goto end;
	}
      }
    }
  }

  end:

  if (saved_info) pptrs->bgp_nexthop_info = saved_info; 
  pptrs->f_agent = saved_agent;
}

struct bgp_peer *bgp_lookup_find_bgp_peer(struct sockaddr *sa, struct xflow_status_entry *xs_entry, u_int16_t l3_proto, int compare_bgp_port)
{
  struct bgp_peer *peer;
  u_int32_t peer_idx, *peer_idx_ptr;
  int peers_idx;

  peer_idx = 0; peer_idx_ptr = NULL;
  if (xs_entry) {
    if (l3_proto == ETHERTYPE_IP) {
      peer_idx = xs_entry->peer_v4_idx; 
      peer_idx_ptr = &xs_entry->peer_v4_idx;
    }
    else if (l3_proto == ETHERTYPE_IPV6) {
      peer_idx = xs_entry->peer_v6_idx; 
      peer_idx_ptr = &xs_entry->peer_v6_idx;
    }
  }

  if (xs_entry && peer_idx) {
    if ((!config.bgp_disable_router_id_check && !sa_addr_cmp(sa, &peers[peer_idx].id)) ||
	(!sa_addr_cmp(sa, &peers[peer_idx].addr) &&
	(!compare_bgp_port || !sa_port_cmp(sa, peers[peer_idx].tcp_port)))) {
      peer = &peers[peer_idx];
    }
    /* If no match then let's invalidate the entry */
    else {
      *peer_idx_ptr = 0;
      peer = NULL;
    }
  }
  else {
    for (peer = NULL, peers_idx = 0; peers_idx < config.bgp_daemon_max_peers; peers_idx++) {
      if ((!config.bgp_disable_router_id_check && !sa_addr_cmp(sa, &peers[peers_idx].id)) ||
	  (!sa_addr_cmp(sa, &peers[peers_idx].addr) && 
	  (!compare_bgp_port || !sa_port_cmp(sa, peers[peer_idx].tcp_port)))) {
        peer = &peers[peers_idx];
        if (xs_entry && peer_idx_ptr) *peer_idx_ptr = peers_idx;
        break;
      }
    }
  }

  return peer;
}

int bgp_lookup_node_match_cmp_bgp(struct bgp_info *info, struct node_match_cmp_term2 *nmct2)
{
  int no_match = FALSE;

  if (info->peer == nmct2->peer) {
    if (nmct2->safi == SAFI_MPLS_VPN) no_match++;

    if (nmct2->peer->cap_add_paths[nmct2->afi][nmct2->safi] && nmct2->peer_dst_ip) no_match++;

    if (nmct2->safi == SAFI_MPLS_VPN) {
      if (info->attr_extra && !memcmp(&info->attr_extra->rd, nmct2->rd, sizeof(rd_t))) no_match--;
    }

    if (nmct2->peer->cap_add_paths[nmct2->afi][nmct2->safi]) {
      if (nmct2->peer_dst_ip && info->attr) {
	if (info->attr->mp_nexthop.family) {
	  if (!host_addr_cmp(&info->attr->mp_nexthop, nmct2->peer_dst_ip)) {
	    no_match--;
	  }
	}
	else if (info->attr->nexthop.s_addr && nmct2->peer_dst_ip->family == AF_INET) {
	  if (info->attr->nexthop.s_addr == nmct2->peer_dst_ip->address.ipv4.s_addr) {
	    no_match--;
	  }
	}
      }
    }

    if (!no_match) return FALSE;
  }

  return TRUE;
}

int bgp_lookup_node_vector_unicast(struct prefix *p, struct bgp_peer *peer, struct bgp_node_vector *bnv)
{
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_misc_structs *bms;
  struct node_match_cmp_term2 nmct2;
  struct bgp_node *result = NULL;
  struct bgp_info *info = NULL;
  afi_t afi;
  safi_t safi;

  if (!p || !peer || !bnv) return ERR;

  bms = bgp_select_misc_db(peer->type);
  inter_domain_routing_db = bgp_select_routing_db(peer->type);

  if (!bms || !inter_domain_routing_db) return ERR;

  afi = family2afi(p->family);
  safi = SAFI_UNICAST;

  memset(&nmct2, 0, sizeof(struct node_match_cmp_term2));
  nmct2.peer = peer;
  nmct2.afi = afi;
  nmct2.safi = safi;
  nmct2.p = p;

  bgp_node_match(inter_domain_routing_db->rib[afi][safi], p, peer, bms->route_info_modulo,
                 bms->bgp_lookup_node_match_cmp, &nmct2, bnv, &result, &info);

  return SUCCESS;
}

void pkt_to_cache_legacy_bgp_primitives(struct cache_legacy_bgp_primitives *c, struct pkt_legacy_bgp_primitives *p,
					pm_cfgreg_t what_to_count, pm_cfgreg_t what_to_count_2)
{
  if (c && p) {
    if (what_to_count & COUNT_STD_COMM) {
      if (!c->std_comms) {
        c->std_comms = malloc(MAX_BGP_STD_COMMS);
        if (!c->std_comms) goto malloc_failed;
      }
      memcpy(c->std_comms, p->std_comms, MAX_BGP_STD_COMMS);
    }
    else {
      if (c->std_comms) {
        free(c->std_comms);
        c->std_comms = NULL;
      }
    }

    if (what_to_count & COUNT_EXT_COMM) {
      if (!c->ext_comms) {
        c->ext_comms = malloc(MAX_BGP_EXT_COMMS);
        if (!c->ext_comms) goto malloc_failed;
      }
      memcpy(c->ext_comms, p->ext_comms, MAX_BGP_EXT_COMMS);
    }
    else {
      if (c->ext_comms) {
        free(c->ext_comms);
        c->ext_comms = NULL;
      }
    }

    if (what_to_count_2 & COUNT_LRG_COMM) {
      if (!c->lrg_comms) {
        c->lrg_comms = malloc(MAX_BGP_LRG_COMMS);
        if (!c->lrg_comms) goto malloc_failed;
      }
      memcpy(c->lrg_comms, p->lrg_comms, MAX_BGP_LRG_COMMS);
    }
    else {
      if (c->lrg_comms) {
        free(c->lrg_comms);
        c->lrg_comms = NULL;
      }
    }

    if (what_to_count & COUNT_AS_PATH) {
      if (!c->as_path) {
        c->as_path = malloc(MAX_BGP_ASPATH);
        if (!c->as_path) goto malloc_failed;
      }
      memcpy(c->as_path, p->as_path, MAX_BGP_ASPATH);
    }
    else {
      if (c->as_path) {
        free(c->as_path);
        c->as_path = NULL;
      }
    }

    if (what_to_count & COUNT_SRC_STD_COMM) {
      if (!c->src_std_comms) {
        c->src_std_comms = malloc(MAX_BGP_STD_COMMS);
        if (!c->src_std_comms) goto malloc_failed;
      }
      memcpy(c->src_std_comms, p->src_std_comms, MAX_BGP_STD_COMMS);
    }
    else {
      if (c->src_std_comms) {
        free(c->src_std_comms);
        c->src_std_comms = NULL;
      }
    }

    if (what_to_count & COUNT_SRC_EXT_COMM) {
      if (!c->src_ext_comms) {
        c->src_ext_comms = malloc(MAX_BGP_EXT_COMMS);
        if (!c->src_ext_comms) goto malloc_failed;
      }
      memcpy(c->src_ext_comms, p->src_ext_comms, MAX_BGP_EXT_COMMS);
    }
    else {
      if (c->src_ext_comms) {
        free(c->src_ext_comms);
        c->src_ext_comms = NULL;
      }
    }

    if (what_to_count_2 & COUNT_SRC_LRG_COMM) {
      if (!c->src_lrg_comms) {
        c->src_lrg_comms = malloc(MAX_BGP_LRG_COMMS);
        if (!c->src_lrg_comms) goto malloc_failed;
      }
      memcpy(c->src_lrg_comms, p->src_lrg_comms, MAX_BGP_LRG_COMMS);
    }
    else {
      if (c->src_lrg_comms) {
        free(c->src_lrg_comms);
        c->src_lrg_comms = NULL;
      }
    }

    if (what_to_count & COUNT_SRC_AS_PATH) {
      if (!c->src_as_path) {
        c->src_as_path = malloc(MAX_BGP_ASPATH);
        if (!c->src_as_path) goto malloc_failed;
      }
      memcpy(c->src_as_path, p->src_as_path, MAX_BGP_ASPATH);
    }
    else {
      if (c->src_as_path) {
        free(c->src_as_path);
        c->src_as_path = NULL;
      }
    }

    return;

    malloc_failed:
    Log(LOG_WARNING, "WARN ( %s/%s ): malloc() failed (pkt_to_cache_legacy_bgp_primitives).\n", config.name, config.type);
  }
}

void cache_to_pkt_legacy_bgp_primitives(struct pkt_legacy_bgp_primitives *p, struct cache_legacy_bgp_primitives *c)
{
  if (c && p) {
    memset(p, 0, PlbgpSz);

    if (c->std_comms) memcpy(p->std_comms, c->std_comms, MAX_BGP_STD_COMMS);
    if (c->ext_comms) memcpy(p->ext_comms, c->ext_comms, MAX_BGP_EXT_COMMS);
    if (c->lrg_comms) memcpy(p->lrg_comms, c->lrg_comms, MAX_BGP_LRG_COMMS);
    if (c->as_path) memcpy(p->as_path, c->as_path, MAX_BGP_ASPATH);

    if (c->src_std_comms) memcpy(p->src_std_comms, c->src_std_comms, MAX_BGP_STD_COMMS);
    if (c->src_ext_comms) memcpy(p->src_ext_comms, c->src_ext_comms, MAX_BGP_EXT_COMMS);
    if (c->src_lrg_comms) memcpy(p->src_lrg_comms, c->src_lrg_comms, MAX_BGP_LRG_COMMS);
    if (c->src_as_path) memcpy(p->src_as_path, c->src_as_path, MAX_BGP_ASPATH);
  }
}

void free_cache_legacy_bgp_primitives(struct cache_legacy_bgp_primitives **c)
{
  struct cache_legacy_bgp_primitives *clbgp = *c;

  if (c && *c) {
    if (clbgp->std_comms) free(clbgp->std_comms);
    if (clbgp->ext_comms) free(clbgp->ext_comms);
    if (clbgp->lrg_comms) free(clbgp->lrg_comms);
    if (clbgp->as_path) free(clbgp->as_path);

    if (clbgp->src_std_comms) free(clbgp->src_std_comms);
    if (clbgp->src_ext_comms) free(clbgp->src_ext_comms);
    if (clbgp->src_lrg_comms) free(clbgp->src_lrg_comms);
    if (clbgp->src_as_path) free(clbgp->src_as_path);

    memset(clbgp, 0, sizeof(struct cache_legacy_bgp_primitives));
    free(*c);
    *c = NULL;
  }
}

u_int32_t bgp_route_info_modulo_pathid(struct bgp_peer *peer, path_id_t *path_id, int per_peer_buckets)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);
  path_id_t local_path_id = 1;

  if (path_id && *path_id) local_path_id = *path_id;

  return (((peer->fd * per_peer_buckets) +
          ((local_path_id - 1) % per_peer_buckets)) %
          (bms->table_peer_buckets * per_peer_buckets));
}

int bgp_lg_daemon_ip_lookup(struct bgp_lg_req_ipl_data *req, struct bgp_lg_rep *rep, int type)
{
  struct bgp_misc_structs *bms;
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_peer *peer;
  struct bgp_node *result;
  struct bgp_info *info;
  struct node_match_cmp_term2 nmct2;
  struct host_addr peer_ha;
  u_int16_t l3_proto = 0, peer_port = 0;
  u_int32_t bucket;
  int ret = BGP_LOOKUP_OK;
  struct rd_as4 *rd_as4_ptr;
  safi_t safi;

  bms = bgp_select_misc_db(type);
  inter_domain_routing_db = bgp_select_routing_db(type);

  if (!req || !rep || !bms || !inter_domain_routing_db) return BGP_LOOKUP_ERR;

  memset(&peer_ha, 0, sizeof(peer_ha));
  memset(rep, 0, sizeof(struct bgp_lg_rep));
  safi = SAFI_UNICAST;

  if (req->pref.family == AF_INET) l3_proto = ETHERTYPE_IP;
  else if (req->pref.family == AF_INET6) l3_proto = ETHERTYPE_IPV6;

  sa_to_addr(&req->peer, &peer_ha, &peer_port);

  if (!peer_port) {
    bucket = addr_hash(&peer_ha, bms->max_peers);
    peer = bgp_peer_cache_search(bms->peers_cache, bucket, &peer_ha, FALSE);
  }
  else {
    bucket = addr_port_hash(&peer_ha, peer_port, bms->max_peers);
    peer = bgp_peer_cache_search(bms->peers_port_cache, bucket, &peer_ha, peer_port);
  }

  if (peer) {
    // XXX: ADD-PATH code not currently supported

    rd_as4_ptr = (struct rd_as4 *) &req->rd;
    if (rd_as4_ptr->as) safi = SAFI_MPLS_VPN;

    start_again_mpls_label:

    memset(&nmct2, 0, sizeof(struct node_match_cmp_term2));
    nmct2.peer = peer;
    nmct2.afi = AFI_IP;
    nmct2.safi = safi;
    nmct2.rd = &req->rd;

    if (l3_proto == ETHERTYPE_IP) {
      bgp_node_match(inter_domain_routing_db->rib[AFI_IP][safi],
			    &req->pref, peer, bgp_route_info_modulo_pathid,
			    bms->bgp_lookup_node_match_cmp, &nmct2,
			    NULL, &result, &info);

      if (result) {
	bgp_lg_rep_ipl_data_add(rep, AFI_IP, safi, &result->p, info);
	ret = BGP_LOOKUP_OK;
      }
      else ret = BGP_LOOKUP_NOPREFIX; 
    }
    else if (l3_proto == ETHERTYPE_IPV6) {
      bgp_node_match(inter_domain_routing_db->rib[AFI_IP6][safi],
		            &req->pref, peer, bgp_route_info_modulo_pathid,
			    bms->bgp_lookup_node_match_cmp, &nmct2,
			    NULL, &result, &info);

      if (result) {
	bgp_lg_rep_ipl_data_add(rep, AFI_IP6, safi, &result->p, info);
	ret = BGP_LOOKUP_OK;
      }
      else ret = BGP_LOOKUP_NOPREFIX; 
    }

    if (!result && safi != SAFI_MPLS_LABEL) {
      if (l3_proto == ETHERTYPE_IP && inter_domain_routing_db->rib[AFI_IP][SAFI_MPLS_LABEL]) {
        safi = SAFI_MPLS_LABEL;
        goto start_again_mpls_label;
      }
      else if (l3_proto == ETHERTYPE_IPV6 && inter_domain_routing_db->rib[AFI_IP6][SAFI_MPLS_LABEL]) {
        safi = SAFI_MPLS_LABEL;
        goto start_again_mpls_label;
      }
    }

    // XXX: bgp_follow_default code not currently supported
  }
  else ret = BGP_LOOKUP_NOPEER; 

  return ret;
}

int bgp_lg_daemon_get_peers(struct bgp_lg_rep *rep, int type)
{
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer, *peers;
  int idx, ret = BGP_LOOKUP_OK;

  bms = bgp_select_misc_db(type);

  if (!rep || !bms || !bms->peers) return BGP_LOOKUP_ERR;

  for (peers = bms->peers, idx = 0; idx < bms->max_peers; idx++) {
    peer = &peers[idx]; 
    if (peer->fd) bgp_lg_rep_gp_data_add(rep, peer);
  }

  return ret;
}

void bgp_lg_rep_init(struct bgp_lg_rep *rep)
{
  struct bgp_lg_rep_data *data, *next;
  u_int32_t idx;

  assert(rep);

  for (idx = 0, data = rep->data; idx < rep->results; idx++) {
    assert(data);
    assert(data->ptr);

    next = data->next;
    free(data->ptr);
    free(data);

    data = next;
  }

  memset(rep, 0, sizeof(struct bgp_lg_rep));
}

struct bgp_lg_rep_data *bgp_lg_rep_data_add(struct bgp_lg_rep *rep)
{
  struct bgp_lg_rep_data *data, *last;
  u_int32_t idx;

  assert(rep);

  for (idx = 0, data = rep->data, last = NULL; idx < rep->results; idx++) {
    last = data;
    data = data->next;
  }

  data = malloc(sizeof(struct bgp_lg_rep_data)); 
  assert(data);

  data->ptr = NULL;
  data->next = NULL;

  if (last) last->next = data; 
  else rep->data = data;

  rep->results++;

  return data;
}

void bgp_lg_rep_ipl_data_add(struct bgp_lg_rep *rep, afi_t afi, safi_t safi, struct prefix *pref, struct bgp_info *info)
{
  struct bgp_lg_rep_data *data;
  struct bgp_lg_rep_ipl_data *ipl_data;

  data = bgp_lg_rep_data_add(rep);

  ipl_data = malloc(sizeof(struct bgp_lg_rep_ipl_data)); 
  assert(ipl_data);

  data->ptr = ipl_data;

  ipl_data->afi = afi;
  ipl_data->safi = safi;
  ipl_data->pref = pref;
  ipl_data->info = info;
}

void bgp_lg_rep_gp_data_add(struct bgp_lg_rep *rep, struct bgp_peer *peer)
{
  struct bgp_lg_rep_data *data;
  struct bgp_lg_rep_gp_data *gp_data;

  data = bgp_lg_rep_data_add(rep);

  gp_data = malloc(sizeof(struct bgp_lg_rep_gp_data));
  assert(gp_data);

  data->ptr = gp_data;

  gp_data->peer = peer;
}
