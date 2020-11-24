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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* includes */
#include "pmacct.h"
#include "addr.h"
#include "pmacct-data.h"
#include "plugin_hooks.h"
#include "ip_frag.h"
#include "jhash.h"

/* global variables */
struct ip_fragment *ipft[IPFT_HASHSZ];
struct lru_l lru_list;

struct ip6_fragment *ipft6[IPFT_HASHSZ];
struct lru_l6 lru_list6;

u_int32_t ipft_total_nodes;  
time_t prune_deadline;
time_t emergency_prune;
u_int32_t trivial_hash_rnd = 140281; /* ummmh */

u_int32_t ipft6_total_nodes;
time_t prune_deadline6;
time_t emergency_prune6;

void enable_ip_fragment_handler()
{
  if (!config.handle_fragments) {
    config.handle_fragments = TRUE;
    init_ip_fragment_handler();
  }
}

void init_ip_fragment_handler()
{
  init_ip4_fragment_handler();
  init_ip6_fragment_handler();
}

void init_ip4_fragment_handler()
{
  if (config.frag_bufsz) ipft_total_nodes = config.frag_bufsz / sizeof(struct ip_fragment);
  else ipft_total_nodes = DEFAULT_FRAG_BUFFER_SIZE / sizeof(struct ip_fragment); 

  memset(ipft, 0, sizeof(ipft));
  lru_list.root = (struct ip_fragment *) malloc(sizeof(struct ip_fragment)); 
  lru_list.last = lru_list.root;
  memset(lru_list.root, 0, sizeof(struct ip_fragment));
  prune_deadline = time(NULL)+PRUNE_INTERVAL;
  emergency_prune = 0;
}

int ip_fragment_handler(struct packet_ptrs *pptrs)
{
  u_int32_t now = time(NULL);

  if (now > prune_deadline) {
    prune_old_fragments(now, PRUNE_OFFSET);
    prune_deadline = now+PRUNE_INTERVAL;
  }
  return find_fragment(now, pptrs);
}

int find_fragment(u_int32_t now, struct packet_ptrs *pptrs)
{
  struct pm_iphdr *iphp = (struct pm_iphdr *)pptrs->iph_ptr;
  struct ip_fragment *fp, *candidate = NULL, *last_seen = NULL;
  unsigned int bucket = hash_fragment(iphp->ip_id, iphp->ip_src.s_addr,
				      iphp->ip_dst.s_addr, iphp->ip_p);
  int ret;

  for (fp = ipft[bucket]; fp; fp = fp->next) {
    if (fp->ip_id == iphp->ip_id && fp->ip_src == iphp->ip_src.s_addr &&
	fp->ip_dst == iphp->ip_dst.s_addr && fp->ip_p == iphp->ip_p) {
      /* fragment found; will check for its deadline */
      if (fp->deadline > now) {
	if (fp->got_first) {
	  // pptrs->tlh_ptr = fp->tlhdr; 
	  memcpy(pptrs->tlh_ptr, fp->tlhdr, MyTLHdrSz); 

	  pptrs->frag_first_found = TRUE;
	  return TRUE;
	}
	else {
	  if (!(iphp->ip_off & htons(IP_OFFMASK))) {
	    /* we got our first fragment */
	    fp->got_first = TRUE;
	    memcpy(fp->tlhdr, pptrs->tlh_ptr, MyTLHdrSz);

	    pptrs->frag_sum_bytes = fp->a;
	    pptrs->frag_sum_pkts = fp->pa;
	    fp->pa = 0;
	    fp->a = 0;

	    pptrs->frag_first_found = TRUE;
            return TRUE;
	  }
	  else { /* we still don't have the first fragment; increase accumulators */
	    if (!config.ext_sampling_rate) {
	      fp->pa++;
	      fp->a += ntohs(iphp->ip_len);
	    }

	    pptrs->frag_first_found = FALSE;
	    return FALSE;
	  } 
	}
      } 
      else {
	candidate = fp;
	if (!candidate->got_first) notify_orphan_fragment(candidate);
	goto create;
      }
    }
    if ((fp->deadline < now) && !candidate) {
      candidate = fp; 
      if (!candidate->got_first) notify_orphan_fragment(candidate);
    }
    last_seen = fp;
  } 

  create:
  if (candidate) ret = create_fragment(now, candidate, TRUE, bucket, pptrs);
  else ret = create_fragment(now, last_seen, FALSE, bucket, pptrs); 

  pptrs->frag_first_found = ret;
  return ret;
}

int create_fragment(u_int32_t now, struct ip_fragment *fp, u_int8_t is_candidate, unsigned int bucket, struct packet_ptrs *pptrs)
{
  struct pm_iphdr *iphp = (struct pm_iphdr *)pptrs->iph_ptr;
  struct ip_fragment *newf;

  if (!ipft_total_nodes) {
    if (now > emergency_prune+EMER_PRUNE_INTERVAL) {
      Log(LOG_INFO, "INFO ( %s/core ): Fragment/4 buffer full. Skipping fragments. Increase %s_frag_buffer_size\n", config.name, config.progname);
      emergency_prune = now;
      prune_old_fragments(now, 0);
    }
    return FALSE; 
  }

  if (fp) {
    /* a 'not candidate' is simply the tail (last node) of the
       list. We need to allocate a new node */
    if (!is_candidate) { 
      newf = (struct ip_fragment *) malloc(sizeof(struct ip_fragment));
      if (!newf) { 
	if (now > emergency_prune+EMER_PRUNE_INTERVAL) {
	  Log(LOG_INFO, "INFO ( %s/core ): Fragment/4 buffer full. Skipping fragments. Increase %s_frag_buffer_size\n", config.name, config.progname);
	  emergency_prune = now;
	  prune_old_fragments(now, 0);
	}
	return FALSE;
      }
      else ipft_total_nodes--;
      memset(newf, 0, sizeof(struct ip_fragment));
      fp->next = newf;
      newf->prev = fp;  
      lru_list.last->lru_next = newf; /* placing new node as LRU tail */
      newf->lru_prev = lru_list.last;
      lru_list.last = newf;
      fp = newf;
    }
    else {
      if (fp->lru_next) { /* if fp->lru_next==NULL the node is already the tail */ 
        fp->lru_prev->lru_next = fp->lru_next; 
	fp->lru_next->lru_prev = fp->lru_prev;
	lru_list.last->lru_next = fp;
	fp->lru_prev = lru_list.last;
	fp->lru_next = NULL;
	lru_list.last = fp;
      }
    }
  }
  else {
    /* we don't have any fragment pointer; this is because current
       bucket doesn't contain any node; we'll allocate first one */ 
    fp = (struct ip_fragment *) malloc(sizeof(struct ip_fragment));  
    if (!fp) {
      if (now > emergency_prune+EMER_PRUNE_INTERVAL) {
        Log(LOG_INFO, "INFO ( %s/core ): Fragment/4 buffer full. Skipping fragments. Increase %s_frag_buffer_size\n", config.name, config.progname);
        emergency_prune = now;
        prune_old_fragments(now, 0);
      }
      return FALSE;
    }
    else ipft_total_nodes--;
    memset(fp, 0, sizeof(struct ip_fragment));
    ipft[bucket] = fp;
    lru_list.last->lru_next = fp; /* placing new node as LRU tail */ 
    fp->lru_prev = lru_list.last;
    lru_list.last = fp;
  }

  fp->deadline = now+IPF_TIMEOUT;
  fp->ip_id = iphp->ip_id;
  fp->ip_p = iphp->ip_p;
  fp->ip_src = iphp->ip_src.s_addr;
  fp->ip_dst = iphp->ip_dst.s_addr;
  fp->bucket = bucket;

  if (!(iphp->ip_off & htons(IP_OFFMASK))) {
    /* it's a first fragment */
    fp->got_first = TRUE;
    memcpy(fp->tlhdr, pptrs->tlh_ptr, MyTLHdrSz);
    return TRUE;
  }
  else {
    /* not a first fragment; increase accumulators */
    if (!config.ext_sampling_rate) {
      fp->pa++;
      fp->a = ntohs(iphp->ip_len); 
    }
    return FALSE;
  }
}

void prune_old_fragments(u_int32_t now, u_int32_t off)
{
  struct ip_fragment *fp, *temp;
  u_int32_t deadline = now-off;

  fp = lru_list.root->lru_next;
  while (fp) {
    if (deadline > fp->deadline) {
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
	ipft[fp->bucket] = fp->next;
	fp->next->prev = NULL; 
      }
      else ipft[fp->bucket] = NULL;

      free(fp);
      ipft_total_nodes++;

      if (temp) fp = temp;
      else fp = NULL;
    }
    else break;
  }

  if (fp) {
    fp->lru_prev = lru_list.root;
    lru_list.root->lru_next = fp;
  }
  else lru_list.last = lru_list.root;
}

/* hash_fragment() is taken (it has another name there) from Linux kernel 2.4;
   see full credits contained in jhash.h */ 
unsigned int hash_fragment(u_int16_t id, u_int32_t src, u_int32_t dst, u_int8_t proto)
{
  return jhash_3words((u_int32_t)id << 16 | proto, src, dst, trivial_hash_rnd) & (IPFT_HASHSZ-1);
}

void notify_orphan_fragment(struct ip_fragment *frag)
{
  struct host_addr a;
  char src_host[INET_ADDRSTRLEN], dst_host[INET_ADDRSTRLEN];
  u_int16_t id;

  a.family = AF_INET;
  memcpy(&a.address.ipv4, &frag->ip_src, 4);
  addr_to_str(src_host, &a);
  memcpy(&a.address.ipv4, &frag->ip_dst, 4);
  addr_to_str(dst_host, &a);
  id = ntohs(frag->ip_id);
  Log(LOG_DEBUG, "DEBUG ( %s/core ): Expiring orphan fragment: ip_src=%s ip_dst=%s proto=%u id=%u\n",
		  config.name, src_host, dst_host, frag->ip_p, id);
}

void init_ip6_fragment_handler()
{
  if (config.frag_bufsz) ipft6_total_nodes = config.frag_bufsz / sizeof(struct ip6_fragment);
  else ipft6_total_nodes = DEFAULT_FRAG_BUFFER_SIZE / sizeof(struct ip6_fragment);

  memset(ipft6, 0, sizeof(ipft6));
  lru_list6.root = (struct ip6_fragment *) malloc(sizeof(struct ip6_fragment));
  lru_list6.last = lru_list6.root;
  memset(lru_list6.root, 0, sizeof(struct ip6_fragment));
  prune_deadline6 = time(NULL)+PRUNE_INTERVAL;
  emergency_prune6 = 0;
}

int ip6_fragment_handler(struct packet_ptrs *pptrs, struct ip6_frag *fhdr)
{
  u_int32_t now = time(NULL);

  if (now > prune_deadline6) {
    prune_old_fragments6(now, PRUNE_OFFSET);
    prune_deadline6 = now+PRUNE_INTERVAL;
  }
  return find_fragment6(now, pptrs, fhdr);
}

unsigned int hash_fragment6(u_int32_t id, struct in6_addr *saddr, struct in6_addr *daddr)
{
        u_int32_t a, b, c;
	u_int32_t *src = (u_int32_t *)saddr, *dst = (u_int32_t *)daddr;

        a = src[0];
        b = src[1];
        c = src[2];

        a += JHASH_GOLDEN_RATIO;
        b += JHASH_GOLDEN_RATIO;
        c += trivial_hash_rnd;
        __jhash_mix(a, b, c);

        a += src[3];
        b += dst[0];
        c += dst[1];
        __jhash_mix(a, b, c);

        a += dst[2];
        b += dst[3];
        c += id;
        __jhash_mix(a, b, c);

        return c & (IPFT_HASHSZ - 1);
}

int find_fragment6(u_int32_t now, struct packet_ptrs *pptrs, struct ip6_frag *fhdr)
{
  struct ip6_hdr *iphp = (struct ip6_hdr *)pptrs->iph_ptr;
  struct ip6_fragment *fp, *candidate = NULL, *last_seen = NULL;
  unsigned int bucket = hash_fragment6(fhdr->ip6f_ident, &iphp->ip6_src, &iphp->ip6_dst);

  for (fp = ipft6[bucket]; fp; fp = fp->next) {
    if (fp->id == fhdr->ip6f_ident && !ip6_addr_cmp(&fp->src, &iphp->ip6_src) &&
        !ip6_addr_cmp(&fp->dst, &iphp->ip6_dst)) {
      /* fragment found; will check for its deadline */
      if (fp->deadline > now) {
        if (fp->got_first) {
          // pptrs->tlh_ptr = fp->tlhdr;
          memcpy(pptrs->tlh_ptr, fp->tlhdr, MyTLHdrSz);
          return TRUE;
        }
        else {
          if (!(fhdr->ip6f_offlg & htons(IP6F_OFF_MASK))) {
            /* we got our first fragment */
            fp->got_first = TRUE;
            memcpy(fp->tlhdr, pptrs->tlh_ptr, MyTLHdrSz);

	    pptrs->frag_sum_bytes = fp->a;
	    pptrs->frag_sum_pkts = fp->pa;
            fp->pa = 0;
            fp->a = 0;
            return TRUE;
          }
          else { /* we still don't have the first fragment; increase accumulators */
	    if (!config.ext_sampling_rate) {
	      fp->pa++;
              fp->a += IP6HdrSz+ntohs(iphp->ip6_plen);
	    }
            return FALSE;
          }
        }
      }
      else {
        candidate = fp;
	if (!candidate->got_first) notify_orphan_fragment6(candidate);
        goto create;
      }
    }
    if ((fp->deadline < now) && !candidate) {
      candidate = fp;
      if (!candidate->got_first) notify_orphan_fragment6(candidate);
    }
    last_seen = fp;
  }

  create:
  if (candidate) return create_fragment6(now, candidate, TRUE, bucket, pptrs, fhdr);
  else return create_fragment6(now, last_seen, FALSE, bucket, pptrs, fhdr);
}

int create_fragment6(u_int32_t now, struct ip6_fragment *fp, u_int8_t is_candidate, unsigned int bucket,
			struct packet_ptrs *pptrs, struct ip6_frag *fhdr)
{
  struct ip6_hdr *iphp = (struct ip6_hdr *)pptrs->iph_ptr;
  struct ip6_fragment *newf;

  if (!ipft6_total_nodes) { 
    if (now > emergency_prune6+EMER_PRUNE_INTERVAL) {
      Log(LOG_INFO, "INFO ( %s/core ): Fragment/6 buffer full. Skipping fragments. Increase %s_frag_buffer_size\n", config.name, config.progname);
      emergency_prune6 = now;
      prune_old_fragments6(now, 0);
    }
    return FALSE;
  }

  if (fp) {
    /* a 'not candidate' is simply the tail (last node) of the
       list. We need to allocate a new node */
    if (!is_candidate) {
      newf = (struct ip6_fragment *) malloc(sizeof(struct ip6_fragment));
      if (!newf) {
	if (now > emergency_prune6+EMER_PRUNE_INTERVAL) {
	  Log(LOG_INFO, "INFO ( %s/core ): Fragment/6 buffer full. Skipping fragments. Increase %s_frag_buffer_size\n", config.name, config.progname);
	  emergency_prune6 = now;
	  prune_old_fragments6(now, 0);
	}
	return FALSE;
      }
      else ipft6_total_nodes--;
      memset(newf, 0, sizeof(struct ip6_fragment));
      fp->next = newf;
      newf->prev = fp;
      lru_list6.last->lru_next = newf; /* placing new node as LRU tail */
      newf->lru_prev = lru_list6.last;
      lru_list6.last = newf;
      fp = newf;
    }
    else {
      if (fp->lru_next) { /* if fp->lru_next==NULL the node is already the tail */
        fp->lru_prev->lru_next = fp->lru_next;
        fp->lru_next->lru_prev = fp->lru_prev;
        lru_list6.last->lru_next = fp;
        fp->lru_prev = lru_list6.last;
        fp->lru_next = NULL;
        lru_list6.last = fp;
      }
    }
  }
  else {
    /* we don't have any fragment pointer; this is because current
       bucket doesn't contain any node; we'll allocate first one */
    fp = (struct ip6_fragment *) malloc(sizeof(struct ip6_fragment));
    if (!fp) {
      if (now > emergency_prune6+EMER_PRUNE_INTERVAL) {
        Log(LOG_INFO, "INFO ( %s/core ): Fragment/6 buffer full. Skipping fragments. Increase %s_frag_buffer_size\n", config.name, config.progname);
        emergency_prune6 = now;
        prune_old_fragments6(now, 0);
      }
      return FALSE;
    }
    else ipft6_total_nodes--;
    memset(fp, 0, sizeof(struct ip6_fragment));
    ipft6[bucket] = fp;
    lru_list6.last->lru_next = fp; /* placing new node as LRU tail */
    fp->lru_prev = lru_list6.last;
    lru_list6.last = fp;
  }

  fp->deadline = now+IPF_TIMEOUT;
  fp->id = fhdr->ip6f_ident;
  ip6_addr_cpy(&fp->src, &iphp->ip6_src);
  ip6_addr_cpy(&fp->dst, &iphp->ip6_dst);
  fp->bucket = bucket;

  if (!(fhdr->ip6f_offlg & htons(IP6F_OFF_MASK))) {
    /* it's a first fragment */
    fp->got_first = TRUE;
    memcpy(fp->tlhdr, pptrs->tlh_ptr, MyTLHdrSz);
    return TRUE;
  }
  else {
    /* not a first fragment; increase accumulators */
    if (!config.ext_sampling_rate) {
      fp->pa++;
      fp->a = IP6HdrSz+ntohs(iphp->ip6_plen);
    }
    return FALSE;
  }
}

void prune_old_fragments6(u_int32_t now, u_int32_t off)
{
  struct ip6_fragment *fp, *temp;
  u_int32_t deadline = now-off;

  fp = lru_list6.root->lru_next;
  while (fp) {
    if (deadline > fp->deadline) {
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
        ipft6[fp->bucket] = fp->next;
        fp->next->prev = NULL;
      }
      else ipft6[fp->bucket] = NULL;

      free(fp);
      ipft6_total_nodes++;

      if (temp) fp = temp;
      else fp = NULL;
    }
    else break;
  }

  if (fp) {
    fp->lru_prev = lru_list6.root;
    lru_list6.root->lru_next = fp;
  }
  else lru_list6.last = lru_list6.root;
}

void notify_orphan_fragment6(struct ip6_fragment *frag)
{
  struct host_addr a;
  char src_host[INET6_ADDRSTRLEN], dst_host[INET6_ADDRSTRLEN];
  u_int32_t id;

  a.family = AF_INET6;
  ip6_addr_cpy(&a.address.ipv6, &frag->src);
  addr_to_str(src_host, &a);
  ip6_addr_cpy(&a.address.ipv6, &frag->dst);
  addr_to_str(dst_host, &a);
  id = ntohl(frag->id);
  Log(LOG_DEBUG, "DEBUG ( %s/core ): Expiring orphan fragment: ip_src=%s ip_dst=%s id=%u\n",
			config.name, src_host, dst_host, id);
}
