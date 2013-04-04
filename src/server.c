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

#define __SERVER_C

/* includes */
#include "pmacct.h"
#include "imt_plugin.h"
#include "ip_flow.h"
#include "classifier.h"
#include "bgp/bgp_packet.h"
#include "bgp/bgp.h"

/* functions */
int build_query_server(char *path_ptr)
{
  struct sockaddr_un sAddr;
  int sd, rc;

  sd=socket(AF_UNIX, SOCK_STREAM, 0);
  if (sd < 0) {
    Log(LOG_ERR, "ERROR ( %s/%s ): cannot open socket.\n", config.name, config.type);
    exit_plugin(1);
  }

  sAddr.sun_family = AF_UNIX;
  strcpy(sAddr.sun_path, path_ptr); 
  unlink(path_ptr);
  
  rc = bind(sd, (struct sockaddr *) &sAddr,sizeof(sAddr));
  if (rc < 0) { 
    Log(LOG_ERR, "ERROR ( %s/%s ): cannot bind to file %s .\n", config.name, config.type, path_ptr);
    exit_plugin(1);
  } 

  chmod(path_ptr, S_IRUSR|S_IWUSR|S_IXUSR|
                  S_IRGRP|S_IWGRP|S_IXGRP|
                  S_IROTH|S_IWOTH|S_IXOTH);

  setnonblocking(sd);
  listen(sd, 1);
  Log(LOG_INFO, "OK ( %s/%s ): waiting for data on: '%s'\n", config.name, config.type, path_ptr);

  return sd;
}


void process_query_data(int sd, unsigned char *buf, int len, struct extra_primitives *extras, int datasize, int forked)
{
  struct acc *acc_elem = 0, tmpbuf;
  struct bucket_desc bd;
  struct query_header *q, *uq;
  struct query_entry request;
  struct reply_buffer rb;
  unsigned char *elem, *bufptr;
  int following_chain=0;
  unsigned int idx;
  struct pkt_data dummy;
  struct pkt_bgp_primitives dummy_pbgp;
  struct pkt_nat_primitives dummy_pnat;
  int reset_counter, offset = PdataSz;

  memset(&dummy, 0, sizeof(struct pkt_data));
  memset(&dummy_pbgp, 0, sizeof(struct pkt_bgp_primitives));
  memset(&dummy_pnat, 0, sizeof(struct pkt_nat_primitives));
  memset(&rb, 0, sizeof(struct reply_buffer));
  memcpy(rb.buf, buf, sizeof(struct query_header));
  rb.len = LARGEBUFLEN-sizeof(struct query_header);
  rb.packed = sizeof(struct query_header);

  /* arranging some pointer */
  uq = (struct query_header *) buf;
  q = (struct query_header *) rb.buf;
  rb.ptr = rb.buf+sizeof(struct query_header);
  bufptr = buf+sizeof(struct query_header);
  q->ip_sz = sizeof(acc_elem->primitives.src_ip);
  q->cnt_sz = sizeof(acc_elem->bytes_counter);
  q->datasize = datasize;

  if (extras->off_pkt_bgp_primitives) {
    q->extras.off_pkt_bgp_primitives = offset;
    offset += sizeof(struct pkt_bgp_primitives);
  }
  else q->extras.off_pkt_bgp_primitives = 0;
  if (extras->off_pkt_nat_primitives) {
    q->extras.off_pkt_nat_primitives = offset;
    offset += sizeof(struct pkt_nat_primitives);
  }
  else q->extras.off_pkt_nat_primitives = 0;

  Log(LOG_DEBUG, "DEBUG ( %s/%s ): Processing data received from client ...\n", config.name, config.type);

  if (config.imt_plugin_passwd) {
    if (!strncmp(config.imt_plugin_passwd, q->passwd, MIN(strlen(config.imt_plugin_passwd), 8)));
    else return;
  }

  elem = (unsigned char *) a;

  reset_counter = q->type & WANT_RESET;

  if (q->type & WANT_STATS) {
    q->what_to_count = config.what_to_count; 
    q->what_to_count_2 = config.what_to_count_2; 
    for (idx = 0; idx < config.buckets; idx++) {
      if (!following_chain) acc_elem = (struct acc *) elem;
      if (!test_zero_elem(acc_elem)) {
	enQueue_elem(sd, &rb, acc_elem, PdataSz, datasize);

	/* XXX: to be optimized ? */
	if (extras->off_pkt_bgp_primitives) {
	  if (acc_elem->cbgp) {
	    struct pkt_bgp_primitives tmp_pbgp;

	    cache_to_pkt_bgp_primitives(&tmp_pbgp, acc_elem->cbgp);
	    enQueue_elem(sd, &rb, &tmp_pbgp, PbgpSz, datasize - extras->off_pkt_bgp_primitives);
	  }
	  // else enQueue_elem(sd, &rb, &dummy_pbgp, PbgpSz, datasize - extras->off_pkt_bgp_primitives);
	}

        if (extras->off_pkt_nat_primitives && acc_elem->pnat) {
          enQueue_elem(sd, &rb, acc_elem->pnat, PnatSz, datasize - extras->off_pkt_nat_primitives);
	}
        // else enQueue_elem(sd, &rb, &dummy_pnat, PnatSz, datasize - extras->off_pkt_nat_primitives);
      } 
      if (acc_elem->next != NULL) {
        Log(LOG_DEBUG, "DEBUG ( %s/%s ): Following chain in reply ...\n", config.name, config.type);
        acc_elem = acc_elem->next;
        following_chain = TRUE;
        idx--;
      }
      else {
        elem += sizeof(struct acc);
        following_chain = FALSE;
      }
    }
    send(sd, rb.buf, rb.packed, 0); /* send remainder data */
  }
  else if (q->type & WANT_STATUS) {
    for (idx = 0; idx < config.buckets; idx++) {

      /* Administrativia */
      following_chain = FALSE;
      bd.num = 0;
      bd.howmany = 0;
      acc_elem = (struct acc *) elem;

      do {
        if (following_chain) acc_elem = acc_elem->next;
        if (!test_zero_elem(acc_elem)) bd.howmany++;
        bd.num = idx; /* we need to avoid this redundancy */
        following_chain = TRUE;
      } while (acc_elem->next != NULL);

      enQueue_elem(sd, &rb, &bd, sizeof(struct bucket_desc), sizeof(struct bucket_desc));
      elem += sizeof(struct acc);
    }
    send(sd, rb.buf, rb.packed, 0);
  }
  else if (q->type & WANT_MATCH || q->type & WANT_COUNTER) {
    unsigned int j;

    q->what_to_count = config.what_to_count;
    q->what_to_count_2 = config.what_to_count_2;
    for (j = 0; j < uq->num; j++, bufptr += sizeof(struct query_entry)) {
      memcpy(&request, bufptr, sizeof(struct query_entry));
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): Searching into accounting structure ...\n", config.name, config.type); 
      if (request.what_to_count == config.what_to_count && request.what_to_count_2 == config.what_to_count_2) { 
        struct pkt_data pd_dummy;
	struct primitives_ptrs prim_ptrs;

	memset(&pd_dummy, 0, sizeof(pd_dummy));
	memset(&prim_ptrs, 0, sizeof(prim_ptrs));
	memcpy(&pd_dummy.primitives, &request.data, sizeof(struct pkt_primitives));
	prim_ptrs.data = &pd_dummy;
	prim_ptrs.pbgp = &request.pbgp;
	prim_ptrs.pnat = &request.pnat;

        acc_elem = search_accounting_structure(&prim_ptrs);
        if (acc_elem) { 
	  if (!test_zero_elem(acc_elem)) {
	    enQueue_elem(sd, &rb, acc_elem, PdataSz, datasize);

	    /* XXX: to be optimized ? */
	    if (extras->off_pkt_bgp_primitives) {
	      if (acc_elem->cbgp) {
		struct pkt_bgp_primitives tmp_pbgp;

		cache_to_pkt_bgp_primitives(&tmp_pbgp, acc_elem->cbgp);
		enQueue_elem(sd, &rb, &tmp_pbgp, PbgpSz, datasize - extras->off_pkt_bgp_primitives);
	      }
	      // else enQueue_elem(sd, &rb, &dummy_pbgp, PbgpSz, datasize - extras->off_pkt_bgp_primitives);
	    }

            if (extras->off_pkt_nat_primitives && acc_elem->pnat) {
              enQueue_elem(sd, &rb, acc_elem->pnat, PnatSz, datasize - extras->off_pkt_nat_primitives);
            }
            // else enQueue_elem(sd, &rb, &dummy_pnat, PnatSz, datasize - extras->off_pkt_nat_primitives);

	    if (reset_counter) {
	      if (forked) set_reset_flag(acc_elem);
	      else reset_counters(acc_elem);
	    }
	  }
	  else {
	    if (q->type & WANT_COUNTER) {
	      enQueue_elem(sd, &rb, &dummy, PdataSz, datasize);

	      if (extras->off_pkt_bgp_primitives)
		enQueue_elem(sd, &rb, &dummy_pbgp, PbgpSz, datasize - extras->off_pkt_bgp_primitives);

	      if (extras->off_pkt_nat_primitives)
		enQueue_elem(sd, &rb, &dummy_pnat, PnatSz, datasize - extras->off_pkt_nat_primitives);
	    }
	  }
        }
	else {
	  if (q->type & WANT_COUNTER) {
	    enQueue_elem(sd, &rb, &dummy, PdataSz, datasize);

	    if (extras->off_pkt_bgp_primitives)
	      enQueue_elem(sd, &rb, &dummy_pbgp, PbgpSz, datasize - extras->off_pkt_bgp_primitives);

	    if (extras->off_pkt_nat_primitives)
	      enQueue_elem(sd, &rb, &dummy_pnat, PnatSz, datasize - extras->off_pkt_nat_primitives);
	  }
	}
      }
      else {
        struct pkt_primitives tbuf;  
	struct pkt_bgp_primitives bbuf;
	struct pkt_nat_primitives nbuf;
	struct pkt_data abuf;
        following_chain = FALSE;
	elem = (unsigned char *) a;
	memset(&abuf, 0, sizeof(abuf));

        for (idx = 0; idx < config.buckets; idx++) {
          if (!following_chain) acc_elem = (struct acc *) elem;
	  if (!test_zero_elem(acc_elem)) {
	    mask_elem(&tbuf, &bbuf, &nbuf, acc_elem, request.what_to_count, request.what_to_count_2, extras); 
            if (!memcmp(&tbuf, &request.data, sizeof(struct pkt_primitives)) &&
		!memcmp(&bbuf, &request.pbgp, sizeof(struct pkt_bgp_primitives)) &&
		!memcmp(&nbuf, &request.pnat, sizeof(struct pkt_nat_primitives))) {
	      if (q->type & WANT_COUNTER) Accumulate_Counters(&abuf, acc_elem); 
	      else {
		enQueue_elem(sd, &rb, acc_elem, PdataSz, datasize); /* q->type == WANT_MATCH */

		if (extras->off_pkt_bgp_primitives) {
		  if (acc_elem->cbgp) {
		    struct pkt_bgp_primitives tmp_pbgp;

		    cache_to_pkt_bgp_primitives(&tmp_pbgp, acc_elem->cbgp);
		    enQueue_elem(sd, &rb, &tmp_pbgp, PbgpSz, datasize - extras->off_pkt_bgp_primitives);
		  }
		  // else enQueue_elem(sd, &rb, &dummy_pbgp, PbgpSz, datasize - extras->off_pkt_bgp_primitives);
		}

                if (extras->off_pkt_nat_primitives && acc_elem->pnat) {
                  enQueue_elem(sd, &rb, acc_elem->pnat, PnatSz, datasize - extras->off_pkt_nat_primitives);
                }
                // else enQueue_elem(sd, &rb, &dummy_pnat, PnatSz, datasize - extras->off_pkt_nat_primitives);
	      }
	      if (reset_counter) set_reset_flag(acc_elem);
	    }
          }
          if (acc_elem->next) {
            acc_elem = acc_elem->next;
            following_chain = TRUE;
            idx--;
          }
          else {
            elem += sizeof(struct acc);
            following_chain = FALSE;
          }
        }
	if (q->type & WANT_COUNTER) enQueue_elem(sd, &rb, &abuf, PdataSz, PdataSz); /* enqueue accumulated data */
      }
    }
    send(sd, rb.buf, rb.packed, 0); /* send remainder data */
  }
  else if (q->type & WANT_CLASS_TABLE) {
    struct stripped_class dummy;
    u_int32_t idx = 0, max = 0;

    /* XXX: we should try using pmct_get_max_entries() */
    max = q->num = config.classifier_table_num;
    if (!q->num && class) max = q->num = MAX_CLASSIFIERS;

    while (idx < max) {
      enQueue_elem(sd, &rb, &class[idx], sizeof(struct stripped_class), sizeof(struct stripped_class));
      idx++;
    }

    send_ct_dummy:
    memset(&dummy, 0, sizeof(dummy));
    enQueue_elem(sd, &rb, &dummy, sizeof(dummy), sizeof(dummy));
    send(sd, rb.buf, rb.packed, 0); /* send remainder data */
  }
  else if (q->type & WANT_PKT_LEN_DISTRIB_TABLE) {
    struct stripped_pkt_len_distrib dummy, real;
    u_int32_t idx = 0, max = 0;

    for (idx = 0; idx < MAX_PKT_LEN_DISTRIB_BINS && config.pkt_len_distrib_bins[idx]; idx++);
    max = q->num = idx;

    for (idx = 0; idx < max; idx++) {
      memset(&real, 0, sizeof(real));
      strlcpy(real.str, config.pkt_len_distrib_bins[idx], MAX_PKT_LEN_DISTRIB_LEN); 
      enQueue_elem(sd, &rb, &real, sizeof(struct stripped_pkt_len_distrib), sizeof(struct stripped_pkt_len_distrib));
    }

    send_pldt_dummy:
    memset(&dummy, 0, sizeof(dummy));
    enQueue_elem(sd, &rb, &dummy, sizeof(dummy), sizeof(dummy));
    send(sd, rb.buf, rb.packed, 0); /* send remainder data */
  }
}

void mask_elem(struct pkt_primitives *d1, struct pkt_bgp_primitives *d2, struct pkt_nat_primitives *d3,
		struct acc *src, u_int64_t w, u_int64_t w2, struct extra_primitives *extras)
{
  struct pkt_primitives *s1 = &src->primitives;
  struct pkt_bgp_primitives tmp_pbgp;
  struct pkt_bgp_primitives *s2 = &tmp_pbgp;
  struct pkt_nat_primitives *s3 = src->pnat;

  cache_to_pkt_bgp_primitives(s2, src->cbgp);

  memset(d1, 0, sizeof(struct pkt_primitives));
  memset(d2, 0, sizeof(struct pkt_bgp_primitives));
  memset(d3, 0, sizeof(struct pkt_nat_primitives));

#if defined (HAVE_L2)
  if (w & COUNT_SRC_MAC) memcpy(d1->eth_shost, s1->eth_shost, ETH_ADDR_LEN); 
  if (w & COUNT_DST_MAC) memcpy(d1->eth_dhost, s1->eth_dhost, ETH_ADDR_LEN); 
  if (w & COUNT_VLAN) d1->vlan_id = s1->vlan_id; 
  if (w & COUNT_COS) d1->cos = s1->cos; 
  if (w & COUNT_ETHERTYPE) d1->etype = s1->etype; 
#endif
  if (w & (COUNT_SRC_HOST|COUNT_SRC_NET)) {
    if (s1->src_ip.family == AF_INET) d1->src_ip.address.ipv4.s_addr = s1->src_ip.address.ipv4.s_addr; 
#if defined ENABLE_IPV6
    else if (s1->src_ip.family == AF_INET6) memcpy(&d1->src_ip.address.ipv6,  &s1->src_ip.address.ipv6, sizeof(struct in6_addr));
#endif
    d1->src_ip.family = s1->src_ip.family;
  }
  if (w & (COUNT_DST_HOST|COUNT_DST_NET)) {
    if (s1->dst_ip.family == AF_INET) d1->dst_ip.address.ipv4.s_addr = s1->dst_ip.address.ipv4.s_addr; 
#if defined ENABLE_IPV6
    else if (s1->dst_ip.family == AF_INET6) memcpy(&d1->dst_ip.address.ipv6,  &s1->dst_ip.address.ipv6, sizeof(struct in6_addr));
#endif
    d1->dst_ip.family = s1->dst_ip.family;
  }
  if (w & COUNT_SRC_NMASK) d1->src_nmask = s1->src_nmask; 
  if (w & COUNT_DST_NMASK) d1->dst_nmask = s1->dst_nmask; 
  if (w & COUNT_SRC_AS) d1->src_as = s1->src_as; 
  if (w & COUNT_DST_AS) d1->dst_as = s1->dst_as; 
  if (w & COUNT_SRC_PORT) d1->src_port = s1->src_port; 
  if (w & COUNT_DST_PORT) d1->dst_port = s1->dst_port; 
  if (w & COUNT_IP_TOS) d1->tos = s1->tos;
  if (w & COUNT_IP_PROTO) d1->proto = s1->proto; 
  if (w & COUNT_IN_IFACE) d1->ifindex_in = s1->ifindex_in; 
  if (w & COUNT_OUT_IFACE) d1->ifindex_out = s1->ifindex_out; 
  if (w & COUNT_ID) d1->id = s1->id; 
  if (w & COUNT_ID2) d1->id2 = s1->id2; 
  if (w & COUNT_CLASS) d1->class = s1->class; 

#if defined WITH_GEOIP
  if (w2 & COUNT_SRC_HOST_COUNTRY) d1->src_ip_country = s1->src_ip_country; 
  if (w2 & COUNT_DST_HOST_COUNTRY) d1->dst_ip_country = s1->dst_ip_country; 
#endif
  if (w2 & COUNT_SAMPLING_RATE) d1->sampling_rate = s1->sampling_rate; 
  if (w2 & COUNT_PKT_LEN_DISTRIB) d1->pkt_len_distrib = s1->pkt_len_distrib; 

  if (extras->off_pkt_bgp_primitives && s2) {
    if (w & COUNT_STD_COMM) strlcpy(d2->std_comms, s2->std_comms, MAX_BGP_STD_COMMS); 
    if (w & COUNT_SRC_STD_COMM) strlcpy(d2->src_std_comms, s2->src_std_comms, MAX_BGP_STD_COMMS); 
    if (w & COUNT_EXT_COMM) strlcpy(d2->ext_comms, s2->ext_comms, MAX_BGP_EXT_COMMS); 
    if (w & COUNT_SRC_EXT_COMM) strlcpy(d2->src_ext_comms, s2->src_ext_comms, MAX_BGP_EXT_COMMS); 
    if (w & COUNT_AS_PATH) strlcpy(d2->as_path, s2->as_path, MAX_BGP_ASPATH);
    if (w & COUNT_SRC_AS_PATH) strlcpy(d2->src_as_path, s2->src_as_path, MAX_BGP_ASPATH);
    if (w & COUNT_LOCAL_PREF) d2->local_pref = s2->local_pref;
    if (w & COUNT_SRC_LOCAL_PREF) d2->src_local_pref = s2->src_local_pref;
    if (w & COUNT_MED) d2->med = s2->med;
    if (w & COUNT_SRC_MED) d2->src_med = s2->src_med;
    if (w & COUNT_PEER_SRC_AS) d2->peer_src_as = s2->peer_src_as;
    if (w & COUNT_PEER_DST_AS) d2->peer_dst_as = s2->peer_dst_as;
    if (w & COUNT_PEER_SRC_IP) {
      if (s2->peer_src_ip.family == AF_INET) d2->peer_src_ip.address.ipv4.s_addr = s2->peer_src_ip.address.ipv4.s_addr;
#if defined ENABLE_IPV6
      else if (s2->peer_src_ip.family == AF_INET6) memcpy(&d2->peer_src_ip.address.ipv6,  &s2->peer_src_ip.address.ipv6, sizeof(struct in6_addr));
#endif
      d2->peer_src_ip.family = s2->peer_src_ip.family;
    }
    if (w & COUNT_PEER_DST_IP) {
      if (s2->peer_dst_ip.family == AF_INET) d2->peer_dst_ip.address.ipv4.s_addr = s2->peer_dst_ip.address.ipv4.s_addr;
#if defined ENABLE_IPV6
      else if (s2->peer_dst_ip.family == AF_INET6) memcpy(&d2->peer_dst_ip.address.ipv6,  &s2->peer_dst_ip.address.ipv6, sizeof(struct in6_addr));
#endif
      d2->peer_dst_ip.family = s2->peer_dst_ip.family;
    }
    if (w & COUNT_MPLS_VPN_RD) memcpy(&d2->mpls_vpn_rd, &s2->mpls_vpn_rd, sizeof(rd_t)); 
  }

  if (extras->off_pkt_nat_primitives && s3) {
    if (w2 & COUNT_POST_NAT_SRC_HOST) {
      if (s3->post_nat_src_ip.family == AF_INET) d3->post_nat_src_ip.address.ipv4.s_addr = s3->post_nat_src_ip.address.ipv4.s_addr;
#if defined ENABLE_IPV6
      else if (s3->post_nat_src_ip.family == AF_INET6) memcpy(&d3->post_nat_src_ip.address.ipv6,  &s3->post_nat_src_ip.address.ipv6, sizeof(struct in6_addr));
#endif
      d3->post_nat_src_ip.family = s3->post_nat_src_ip.family;
    }
    if (w2 & COUNT_POST_NAT_DST_HOST) {
      if (s3->post_nat_dst_ip.family == AF_INET) d3->post_nat_dst_ip.address.ipv4.s_addr = s3->post_nat_dst_ip.address.ipv4.s_addr;
#if defined ENABLE_IPV6
      else if (s3->post_nat_dst_ip.family == AF_INET6) memcpy(&d3->post_nat_dst_ip.address.ipv6,  &s3->post_nat_dst_ip.address.ipv6, sizeof(struct in6_addr));
#endif
      d3->post_nat_dst_ip.family = s3->post_nat_dst_ip.family;
    }
    if (w2 & COUNT_POST_NAT_SRC_PORT) d3->post_nat_src_port = s3->post_nat_src_port;
    if (w2 & COUNT_POST_NAT_DST_PORT) d3->post_nat_dst_port = s3->post_nat_dst_port;
    if (w2 & COUNT_NAT_EVENT) d3->nat_event = s3->nat_event;
    if (w2 & COUNT_TIMESTAMP_START) memcpy(&d3->timestamp_start, &s3->timestamp_start, sizeof(struct timeval));
    if (w2 & COUNT_TIMESTAMP_END) memcpy(&d3->timestamp_end, &s3->timestamp_end, sizeof(struct timeval));
  }
}

void enQueue_elem(int sd, struct reply_buffer *rb, void *elem, int size, int tot_size)
{
  if ((rb->packed + tot_size) < rb->len) {
    memcpy(rb->ptr, elem, size);
    rb->ptr += size;
    rb->packed += size; 
  }
  else {
    send(sd, rb->buf, rb->packed, 0);
    rb->len = LARGEBUFLEN;
    memset(rb->buf, 0, sizeof(rb->buf));
    rb->packed = 0;
    rb->ptr = rb->buf;
    memcpy(rb->ptr, elem, size);
    rb->ptr += size;
    rb->packed += size;
  }
}

void Accumulate_Counters(struct pkt_data *abuf, struct acc *elem)
{
  abuf->pkt_len += elem->bytes_counter;
  abuf->pkt_num += elem->packet_counter;
  abuf->flo_num += elem->flow_counter;
  abuf->time_start.tv_sec++; /* XXX: this unused field works as counter of how much entries we are accumulating */
}

int test_zero_elem(struct acc *elem)
{
  if (elem) {
    if (elem->flow_type == NF9_FTYPE_NAT_EVENT) {
      if (elem->pnat && elem->pnat->nat_event) return FALSE;
      else return TRUE;
    }
    else {
      if (elem->bytes_counter && !elem->reset_flag) return FALSE;
      else return TRUE;
    }
  }

  return TRUE;
}
