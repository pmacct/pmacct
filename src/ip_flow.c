/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2012 by Paolo Lucente
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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#define __IP_FLOW_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "ip_flow.h"
#include "classifier.h"
#include "jhash.h"

u_int32_t flt_total_nodes;  
time_t flt_prune_deadline;
time_t flt_emergency_prune;
time_t flow_generic_lifetime;
time_t flow_tcpest_lifetime;
u_int32_t flt_trivial_hash_rnd = 140281; /* ummmh */

#if defined ENABLE_IPV6
u_int32_t flt6_total_nodes;
time_t flt6_prune_deadline;
time_t flt6_emergency_prune;
#endif

void init_ip_flow_handler()
{
  init_ip4_flow_handler();
#if defined ENABLE_IPV6
  init_ip6_flow_handler();
#endif
}

void init_ip4_flow_handler()
{
  int size;

  if (config.flow_bufsz) flt_total_nodes = config.flow_bufsz / sizeof(struct ip_flow);
  else flt_total_nodes = DEFAULT_FLOW_BUFFER_SIZE / sizeof(struct ip_flow); 

  if (!config.flow_hashsz) config.flow_hashsz = FLOW_TABLE_HASHSZ; 
  size = sizeof(struct ip_flow) * config.flow_hashsz;
  ip_flow_table = (struct ip_flow **) malloc(size);
  assert(ip_flow_table);

  memset(ip_flow_table, 0, size);
  flow_lru_list.root = (struct ip_flow *) malloc(sizeof(struct ip_flow)); 
  flow_lru_list.last = flow_lru_list.root;
  memset(flow_lru_list.root, 0, sizeof(struct ip_flow));
  flt_prune_deadline = time(NULL)+FLOW_TABLE_PRUNE_INTERVAL;
  flt_emergency_prune = 0; 

  if (config.flow_lifetime) flow_generic_lifetime = config.flow_lifetime;
  else flow_generic_lifetime = FLOW_GENERIC_LIFETIME; 

  if (config.classifiers_path) flow_tcpest_lifetime = FLOW_TCPEST_LIFETIME;
  else flow_tcpest_lifetime = flow_generic_lifetime;
}

void ip_flow_handler(struct packet_ptrs *pptrs)
{
  struct timeval now;

  gettimeofday(&now, NULL);

  if (now.tv_sec > flt_prune_deadline) {
    prune_old_flows(&now);
    flt_prune_deadline = now.tv_sec+FLOW_TABLE_PRUNE_INTERVAL;
  }

  find_flow(&now, pptrs);
}

void evaluate_tcp_flags(struct timeval *now, struct packet_ptrs *pptrs, struct ip_flow_common *fp, unsigned int idx)
{
  unsigned int rev = idx ? 0 : 1;

  if (fp->proto == IPPROTO_TCP) {
    /* evaluating the transition to the ESTABLISHED state: we need to be as much
       precise as possible as the lifetime for an established flow is quite high.
       We check that we have a) SYN flag on a forward direction, b) SYN+ACK on the
       reverse one and c) that cur_seqno == syn_seqno+1 holds */
    if (fp->tcp_flags[idx] & TH_SYN && fp->tcp_flags[rev] & TH_SYN &&
	fp->tcp_flags[rev] & TH_ACK) {
      if (ntohl(((struct my_tcphdr *)pptrs->tlh_ptr)->th_seq) == fp->last_tcp_seq+1) {
	/* The flow successfully entered the ESTABLISHED state: clearing flags */
	fp->tcp_flags[idx] = FALSE;
	fp->tcp_flags[rev] = FALSE;
      }
    }

    if (pptrs->tcp_flags) {
      if (pptrs->tcp_flags & TH_SYN) {
	fp->tcp_flags[idx] = TH_SYN;
	if (pptrs->tcp_flags & TH_ACK) fp->tcp_flags[idx] |= TH_ACK;
	else fp->last_tcp_seq = ntohl(((struct my_tcphdr *)pptrs->tlh_ptr)->th_seq);
      }

      if (pptrs->tcp_flags & TH_FIN || pptrs->tcp_flags & TH_RST) {
        fp->tcp_flags[idx] = pptrs->tcp_flags;
        fp->tcp_flags[rev] = pptrs->tcp_flags;
      }
    }
  }
}

void clear_tcp_flow_cmn(struct ip_flow_common *fp, unsigned int idx)
{
  fp->last[idx].tv_sec = 0;
  fp->last[idx].tv_usec = 0;
  fp->tcp_flags[idx] = 0;
  fp->class[idx] = 0;
  memset(&fp->cst[idx], 0, CSSz);
} 

void find_flow(struct timeval *now, struct packet_ptrs *pptrs)
{
  struct my_iphdr my_iph;
  struct my_tcphdr my_tlh;
  struct my_iphdr *iphp = &my_iph;
  struct my_tlhdr *tlhp = (struct my_tlhdr *) &my_tlh;
  struct ip_flow *fp, *candidate = NULL, *last_seen = NULL;
  unsigned int idx, bucket;

  memcpy(&my_iph, pptrs->iph_ptr, IP4HdrSz);
  memcpy(&my_tlh, pptrs->tlh_ptr, MyTCPHdrSz);
  idx = normalize_flow(&iphp->ip_src.s_addr, &iphp->ip_dst.s_addr, &tlhp->src_port, &tlhp->dst_port);
  bucket = hash_flow(iphp->ip_src.s_addr, iphp->ip_dst.s_addr, tlhp->src_port, tlhp->dst_port, iphp->ip_p);

  for (fp = ip_flow_table[bucket]; fp; fp = fp->next) {
    if (fp->ip_src == iphp->ip_src.s_addr && fp->ip_dst == iphp->ip_dst.s_addr &&
	fp->port_src == tlhp->src_port && fp->port_dst == tlhp->dst_port &&
	fp->cmn.proto == iphp->ip_p) {
      /* flow found; will check for its lifetime */
      if (!is_expired_uni(now, &fp->cmn, idx)) {
	/* still valid flow */ 
	evaluate_tcp_flags(now, pptrs, &fp->cmn, idx);
	fp->cmn.last[idx].tv_sec = now->tv_sec;
	fp->cmn.last[idx].tv_usec = now->tv_usec;
	pptrs->new_flow = FALSE; 
	if (config.classifiers_path) evaluate_classifiers(pptrs, &fp->cmn, idx);
	return;
      }
      else {
	/* stale flow: will start a new one */ 
	clear_tcp_flow_cmn(&fp->cmn, idx); 
	evaluate_tcp_flags(now, pptrs, &fp->cmn, idx);
	fp->cmn.last[idx].tv_sec = now->tv_sec;
	fp->cmn.last[idx].tv_usec = now->tv_usec;
	pptrs->new_flow = TRUE;
	if (config.classifiers_path) evaluate_classifiers(pptrs, &fp->cmn, idx);
	return;
      } 
    }
    if (!candidate && is_expired(now, &fp->cmn)) candidate = fp; 
    last_seen = fp;
  } 

  if (candidate) create_flow(now, candidate, TRUE, bucket, pptrs, iphp, tlhp, idx);
  else create_flow(now, last_seen, FALSE, bucket, pptrs, iphp, tlhp, idx); 
}

void create_flow(struct timeval *now, struct ip_flow *fp, u_int8_t is_candidate, unsigned int bucket, struct packet_ptrs *pptrs, 
		 struct my_iphdr *iphp, struct my_tlhdr *tlhp, unsigned int idx)
{
  struct ip_flow *newf;

  if (!flt_total_nodes) {
    if (now->tv_sec > flt_emergency_prune+FLOW_TABLE_EMER_PRUNE_INTERVAL) {
      Log(LOG_INFO, "INFO ( default/core ): Flow/4 buffer full. Skipping flows.\n"); 
      flt_emergency_prune = now->tv_sec;
      prune_old_flows(now);
    }
    pptrs->new_flow = FALSE; 
    return;
  }

  if (fp) {
    /* a 'not candidate' is simply the tail (last node) of the
       list. We need to allocate a new node */
    if (!is_candidate) { 
      newf = (struct ip_flow *) malloc(sizeof(struct ip_flow));
      if (!newf) { 
	if (now->tv_sec > flt_emergency_prune+FLOW_TABLE_EMER_PRUNE_INTERVAL) {
	  Log(LOG_INFO, "INFO ( default/core ): Flow/4 buffer finished memory. Skipping flows.\n");
	  flt_emergency_prune = now->tv_sec;
	  prune_old_flows(now);
	}
	pptrs->new_flow = FALSE;
	return;
      }
      else flt_total_nodes--;
      memset(newf, 0, sizeof(struct ip_flow));
      fp->next = newf;
      newf->prev = fp;  
      flow_lru_list.last->lru_next = newf; /* placing new node as LRU tail */
      newf->lru_prev = flow_lru_list.last;
      flow_lru_list.last = newf;
      fp = newf;
    }
    else {
      if (fp->lru_next) { /* if fp->lru_next==NULL the node is already the tail */ 
        fp->lru_prev->lru_next = fp->lru_next; 
	fp->lru_next->lru_prev = fp->lru_prev;
	flow_lru_list.last->lru_next = fp;
	fp->lru_prev = flow_lru_list.last;
	fp->lru_next = NULL;
	flow_lru_list.last = fp;
      }
      clear_context_chain(&fp->cmn, 0);
      clear_context_chain(&fp->cmn, 1);
      memset(&fp->cmn, 0, sizeof(struct ip_flow_common));
    }
  }
  else {
    /*	we don't have any pointer to existing flows; this is because the
	current bucket doesn't contain any node; we'll allocate the first
	one */ 
    fp = (struct ip_flow *) malloc(sizeof(struct ip_flow));  
    if (!fp) {
      if (now->tv_sec > flt_emergency_prune+FLOW_TABLE_EMER_PRUNE_INTERVAL) {
        Log(LOG_INFO, "INFO ( default/core ): Flow/4 buffer finished memory. Skipping flows.\n");
        flt_emergency_prune = now->tv_sec;
        prune_old_flows(now);
      }
      pptrs->new_flow = FALSE;
      return;
    }
    else flt_total_nodes--;
    memset(fp, 0, sizeof(struct ip_flow));
    ip_flow_table[bucket] = fp;
    flow_lru_list.last->lru_next = fp; /* placing new node as LRU tail */ 
    fp->lru_prev = flow_lru_list.last;
    flow_lru_list.last = fp;
  }

  fp->ip_src = iphp->ip_src.s_addr;
  fp->ip_dst = iphp->ip_dst.s_addr;
  fp->port_src = tlhp->src_port;
  fp->port_dst = tlhp->dst_port;
  fp->cmn.proto = iphp->ip_p;
  fp->cmn.bucket = bucket;
  evaluate_tcp_flags(now, pptrs, &fp->cmn, idx); 
  fp->cmn.last[idx].tv_sec = now->tv_sec; 
  fp->cmn.last[idx].tv_usec = now->tv_usec; 

  pptrs->new_flow = TRUE;
  if (config.classifiers_path) evaluate_classifiers(pptrs, &fp->cmn, idx); 
}

void prune_old_flows(struct timeval *now)
{
  struct ip_flow *fp, *temp, *last_seen = flow_lru_list.root;

  fp = flow_lru_list.root->lru_next;
  while (fp) {
    if (is_expired(now, &fp->cmn)) {
      /* we found a stale element; we'll prune it */
      if (fp->lru_next) temp = fp->lru_next;
      else temp = NULL;

      /* rearranging bucket's pointers */ 
      if (fp->prev && fp->next) {
	fp->prev->next = fp->next;
        fp->next->prev = fp->prev;
      }
      else if (fp->prev) fp->prev->next = NULL;
      else if (fp->next) {
	ip_flow_table[fp->cmn.bucket] = fp->next;
	fp->next->prev = NULL; 
      }
      else ip_flow_table[fp->cmn.bucket] = NULL;

      /* rearranging LRU pointers */
      if (fp->lru_next) {
        fp->lru_next->lru_prev = fp->lru_prev;
        fp->lru_prev->lru_next = fp->lru_next;
      }
      else fp->lru_prev->lru_next = NULL;

      clear_context_chain(&fp->cmn, 0);
      clear_context_chain(&fp->cmn, 1);
      free(fp);
      flt_total_nodes++;

      if (temp) fp = temp;
      else fp = NULL;
    }
    else {
      last_seen = fp;
      fp = fp->lru_next;
    }
  }

  flow_lru_list.last = last_seen;
}

unsigned int normalize_flow(u_int32_t *ip_src, u_int32_t *ip_dst,
                u_int16_t *port_src, u_int16_t *port_dst)
{
  u_int16_t port_tmp;
  u_int32_t ip_tmp;

  if (*port_src < *port_dst) {
    port_tmp = *port_src;
    *port_src = *port_dst;
    *port_dst = port_tmp; 

    ip_tmp = *ip_src;
    *ip_src = *ip_dst;
    *ip_dst = ip_tmp;

    return TRUE; /* reverse flow */
  } 

  if (*port_src == *port_dst) {
    if (*ip_src < *ip_dst) {
      ip_tmp = *ip_src;
      *ip_src = *ip_dst;
      *ip_dst = ip_tmp;

      return TRUE; /* reverse flow */
    }
  }

  return FALSE; /* forward flow */
}

/* hash_flow() is taken (it has another name there) from Linux kernel 2.4;
   see full credits contained in jhash.h */ 
unsigned int hash_flow(u_int32_t ip_src, u_int32_t ip_dst,
		u_int16_t port_src, u_int16_t port_dst, u_int8_t proto)
{
  return jhash_3words((u_int32_t)(port_src ^ port_dst) << 16 | proto, ip_src, ip_dst, flt_trivial_hash_rnd) & (config.flow_hashsz-1);
}

/* is_expired() checks for the expiration of the bi-directional flow; returns: TRUE if
   a) the TCP flow is expired or, b) the non-TCP flow scores 2 points; FALSE in any other
   case. This function will also contain any further semi-stateful evaluation of specific
   protocols */ 
unsigned int is_expired(struct timeval *now, struct ip_flow_common *fp)
{
  int forward = 0, reverse = 0;

  forward = is_expired_uni(now, fp, 0); 
  reverse = is_expired_uni(now, fp, 1); 

  if (forward && reverse) return TRUE;
  else return FALSE;
}

/* is_expired_uni() checks for the expiration of the uni-directional flow; returns: TRUE
   if the flow has expired; FALSE in any other case. */
unsigned int is_expired_uni(struct timeval *now, struct ip_flow_common *fp, unsigned int idx)
{
  if (fp->proto == IPPROTO_TCP) {
    /* tcp_flags == 0 ==> the TCP flow is in ESTABLISHED mode */
    if (!fp->tcp_flags[idx]) {
      if (now->tv_sec > fp->last[idx].tv_sec+flow_tcpest_lifetime) return TRUE;
    }
    else {
      if (fp->tcp_flags[idx] & TH_SYN && now->tv_sec > fp->last[idx].tv_sec+FLOW_TCPSYN_LIFETIME) return TRUE;
      if (fp->tcp_flags[idx] & TH_FIN && now->tv_sec > fp->last[idx].tv_sec+FLOW_TCPFIN_LIFETIME) return TRUE;
      if (fp->tcp_flags[idx] & TH_RST && now->tv_sec > fp->last[idx].tv_sec+FLOW_TCPRST_LIFETIME) return TRUE;
    }
  }
  else {
    if (now->tv_sec > fp->last[idx].tv_sec+flow_generic_lifetime) return TRUE;
  }

  return FALSE;
}

#if defined ENABLE_IPV6
void init_ip6_flow_handler()
{
  int size;

  if (config.flow_bufsz) flt6_total_nodes = config.flow_bufsz / sizeof(struct ip_flow6);
  else flt6_total_nodes = DEFAULT_FLOW_BUFFER_SIZE / sizeof(struct ip_flow6);

  if (!config.flow_hashsz) config.flow_hashsz = FLOW_TABLE_HASHSZ;
  size = sizeof(struct ip_flow6) * config.flow_hashsz;
  ip_flow_table6 = (struct ip_flow6 **) malloc(size);

  memset(ip_flow_table6, 0, size);
  flow_lru_list6.root = (struct ip_flow6 *) malloc(sizeof(struct ip_flow6));
  flow_lru_list6.last = flow_lru_list6.root;
  memset(flow_lru_list6.root, 0, sizeof(struct ip_flow6));
  flt6_prune_deadline = time(NULL)+FLOW_TABLE_PRUNE_INTERVAL;
  flt6_emergency_prune = 0;

  if (config.flow_lifetime) flow_generic_lifetime = config.flow_lifetime;
  else flow_generic_lifetime = FLOW_GENERIC_LIFETIME;

  if (config.classifiers_path) flow_tcpest_lifetime = FLOW_TCPEST_LIFETIME;
  else flow_tcpest_lifetime = flow_generic_lifetime;
}

void ip_flow6_handler(struct packet_ptrs *pptrs)
{
  struct timeval now;

  gettimeofday(&now, NULL);

  if (now.tv_sec > flt6_prune_deadline) {
    prune_old_flows6(&now);
    flt6_prune_deadline = now.tv_sec+FLOW_TABLE_PRUNE_INTERVAL;
  }

  find_flow6(&now, pptrs);
}

unsigned int hash_flow6(u_int32_t id, struct in6_addr *saddr, struct in6_addr *daddr)
{
        u_int32_t a, b, c;
	u_int32_t *src = (u_int32_t *)saddr, *dst = (u_int32_t *)daddr;

        a = src[0];
        b = src[1];
        c = src[2];

        a += JHASH_GOLDEN_RATIO;
        b += JHASH_GOLDEN_RATIO;
        c += flt_trivial_hash_rnd;
        __jhash_mix(a, b, c);

        a += src[3];
        b += dst[0];
        c += dst[1];
        __jhash_mix(a, b, c);

        a += dst[2];
        b += dst[3];
        c += id;
        __jhash_mix(a, b, c);

        return c & (config.flow_hashsz - 1);
}

unsigned int normalize_flow6(struct in6_addr *saddr, struct in6_addr *daddr,
				u_int16_t *port_src, u_int16_t *port_dst)
{
  struct in6_addr taddr;
  u_int16_t port_tmp;

  if (*port_src < *port_dst) {
    port_tmp = *port_src;
    *port_src = *port_dst;
    *port_dst = port_tmp;

    ip6_addr_cpy(&taddr, saddr);
    ip6_addr_cpy(saddr, daddr);
    ip6_addr_cpy(daddr, &taddr);

    return TRUE; /* reverse flow */
  }

  if (*port_src == *port_dst) {
    if (ip6_addr_cmp(saddr, daddr) < 0) {
      ip6_addr_cpy(&taddr, saddr);
      ip6_addr_cpy(saddr, daddr);
      ip6_addr_cpy(daddr, &taddr);

      return TRUE; /* reverse flow */
    }
  }

  return FALSE; /* forward flow */
}

void find_flow6(struct timeval *now, struct packet_ptrs *pptrs)
{
  struct ip6_hdr my_iph;
  struct my_tcphdr my_tlh;
  struct ip6_hdr *iphp = &my_iph;
  struct my_tlhdr *tlhp = (struct my_tlhdr *) &my_tlh;
  struct ip_flow6 *fp, *candidate = NULL, *last_seen = NULL;
  unsigned int idx, bucket;

  memcpy(&my_iph, pptrs->iph_ptr, IP6HdrSz);
  memcpy(&my_tlh, pptrs->tlh_ptr, MyTCPHdrSz);
  idx = normalize_flow6(&iphp->ip6_src, &iphp->ip6_dst, &tlhp->src_port, &tlhp->dst_port);
  bucket = hash_flow6((tlhp->src_port << 16) | tlhp->dst_port, &iphp->ip6_src, &iphp->ip6_dst);

  for (fp = ip_flow_table6[bucket]; fp; fp = fp->next) {
    if (!ip6_addr_cmp(&fp->ip_src, &iphp->ip6_src) && !ip6_addr_cmp(&fp->ip_dst, &iphp->ip6_dst) &&
        fp->port_src == tlhp->src_port && fp->port_dst == tlhp->dst_port &&
	fp->cmn.proto == pptrs->l4_proto) {
      /* flow found; will check for its lifetime */
      if (!is_expired_uni(now, &fp->cmn, idx)) {
        /* still valid flow */
	evaluate_tcp_flags(now, pptrs, &fp->cmn, idx);
	fp->cmn.last[idx].tv_sec = now->tv_sec;
	fp->cmn.last[idx].tv_usec = now->tv_usec;
	pptrs->new_flow = FALSE;
	if (config.classifiers_path) evaluate_classifiers(pptrs, &fp->cmn, idx);
	return;
      }
      else {
        /* stale flow: will start a new one */
	clear_tcp_flow_cmn(&fp->cmn, idx);
	evaluate_tcp_flags(now, pptrs, &fp->cmn, idx);
	fp->cmn.last[idx].tv_sec = now->tv_sec;
	fp->cmn.last[idx].tv_usec = now->tv_usec;
	pptrs->new_flow = TRUE;
	if (config.classifiers_path) evaluate_classifiers(pptrs, &fp->cmn, idx);
	return;
      }
    }
    if (!candidate && is_expired(now, &fp->cmn)) candidate = fp;
    last_seen = fp;
  }

  create:
  if (candidate) create_flow6(now, candidate, TRUE, bucket, pptrs, iphp, tlhp, idx);
  else create_flow6(now, last_seen, FALSE, bucket, pptrs, iphp, tlhp, idx);
}

void create_flow6(struct timeval *now, struct ip_flow6 *fp, u_int8_t is_candidate, unsigned int bucket,
	          struct packet_ptrs *pptrs, struct ip6_hdr *iphp, struct my_tlhdr *tlhp, unsigned int idx)
{
  struct ip_flow6 *newf;

  if (!flt6_total_nodes) {
    if (now->tv_sec > flt6_emergency_prune+FLOW_TABLE_EMER_PRUNE_INTERVAL) {
      Log(LOG_INFO, "INFO ( default/core ): Flow/6 buffer full. Skipping flows.\n");
      flt6_emergency_prune = now->tv_sec;
      prune_old_flows6(now);
    }
    pptrs->new_flow = FALSE;
    return;
  }

  if (fp) {
    /* a 'not candidate' is simply the tail (last node) of the
       list. We need to allocate a new node */
    if (!is_candidate) {
      newf = (struct ip_flow6 *) malloc(sizeof(struct ip_flow6));
      if (!newf) {
	if (now->tv_sec > flt6_emergency_prune+FLOW_TABLE_EMER_PRUNE_INTERVAL) {
	  Log(LOG_INFO, "INFO ( default/core ): Flow/6 buffer full. Skipping flows.\n");
	  flt6_emergency_prune = now->tv_sec;
	  prune_old_flows6(now);
	}
        pptrs->new_flow = FALSE;
	return;
      }
      else flt6_total_nodes--;
      memset(newf, 0, sizeof(struct ip_flow6));
      fp->next = newf;
      newf->prev = fp;
      flow_lru_list6.last->lru_next = newf; /* placing new node as LRU tail */
      newf->lru_prev = flow_lru_list6.last;
      flow_lru_list6.last = newf;
      fp = newf;
    }
    else {
      if (fp->lru_next) { /* if fp->lru_next==NULL the node is already the tail */
        fp->lru_prev->lru_next = fp->lru_next;
        fp->lru_next->lru_prev = fp->lru_prev;
        flow_lru_list6.last->lru_next = fp;
        fp->lru_prev = flow_lru_list6.last;
        fp->lru_next = NULL;
        flow_lru_list6.last = fp;
      }
      clear_context_chain(&fp->cmn, 0);
      clear_context_chain(&fp->cmn, 1);
      memset(&fp->cmn, 0, sizeof(struct ip_flow_common));
    }
  }
  else {
    /* we don't have any fragment pointer; this is because current
       bucket doesn't contain any node; we'll allocate first one */
    fp = (struct ip_flow6 *) malloc(sizeof(struct ip_flow6));
    if (!fp) {
      if (now->tv_sec > flt6_emergency_prune+FLOW_TABLE_EMER_PRUNE_INTERVAL) {
        Log(LOG_INFO, "INFO ( default/core ): Flow/6 buffer full. Skipping flows.\n");
        flt6_emergency_prune = now->tv_sec;
        prune_old_flows6(now);
      }
      pptrs->new_flow = FALSE;
      return;
    }
    else flt6_total_nodes--;
    memset(fp, 0, sizeof(struct ip_flow6));
    ip_flow_table6[bucket] = fp;
    flow_lru_list6.last->lru_next = fp; /* placing new node as LRU tail */
    fp->lru_prev = flow_lru_list6.last;
    flow_lru_list6.last = fp;
  }

  ip6_addr_cpy(&fp->ip_src, &iphp->ip6_src);
  ip6_addr_cpy(&fp->ip_dst, &iphp->ip6_dst);
  fp->port_src = tlhp->src_port;
  fp->port_dst = tlhp->dst_port;
  fp->cmn.proto = pptrs->l4_proto;
  fp->cmn.bucket = bucket;
  evaluate_tcp_flags(now, pptrs, &fp->cmn, idx);
  fp->cmn.last[idx].tv_sec = now->tv_sec;
  fp->cmn.last[idx].tv_usec = now->tv_usec;

  pptrs->new_flow = TRUE;
  if (config.classifiers_path) evaluate_classifiers(pptrs, &fp->cmn, idx); 
}

void prune_old_flows6(struct timeval *now)
{
  struct ip_flow6 *fp, *temp, *last_seen = flow_lru_list6.root;

  fp = flow_lru_list6.root->lru_next;
  while (fp) {
    if (is_expired(now, &fp->cmn)) {
      /* we found a stale element; we'll prune it */
      if (fp->lru_next) temp = fp->lru_next;
      else temp = NULL;

      /* rearranging bucket's pointers */
      if (fp->prev && fp->next) {
        fp->prev->next = fp->next;
        fp->next->prev = fp->prev;
      }
      else if (fp->prev) fp->prev->next = NULL;
      else if (fp->next) {
        ip_flow_table6[fp->cmn.bucket] = fp->next;
        fp->next->prev = NULL;
      }
      else ip_flow_table6[fp->cmn.bucket] = NULL;

      /* rearranging LRU pointers */
      if (fp->lru_next) {
        fp->lru_next->lru_prev = fp->lru_prev;
        fp->lru_prev->lru_next = fp->lru_next;
      }
      else fp->lru_prev->lru_next = NULL;

      clear_context_chain(&fp->cmn, 0);
      clear_context_chain(&fp->cmn, 1);
      free(fp);
      flt6_total_nodes++;

      if (temp) fp = temp;
      else fp = NULL;
    }
    else {
      last_seen = fp;
      fp = fp->lru_next;
    }
  }

  flow_lru_list6.last = last_seen;
}
#endif
