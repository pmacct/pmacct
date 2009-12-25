/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2009 by Paolo Lucente
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


void process_query_data(int sd, unsigned char *buf, int len, int forked)
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
  int reset_counter;

  memset(&dummy, 0, sizeof(struct pkt_data));
  memset(&dummy_pbgp, 0, sizeof(struct pkt_bgp_primitives));
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

  Log(LOG_DEBUG, "DEBUG ( %s/%s ): Processing data received from client ...\n", config.name, config.type);

  if (config.imt_plugin_passwd) {
    if (!strncmp(config.imt_plugin_passwd, q->passwd, MIN(strlen(config.imt_plugin_passwd), 8)));
    else return;
  }

  elem = (unsigned char *) a;

  reset_counter = q->type & WANT_RESET;

  if (q->type & WANT_STATS) {
    q->what_to_count = config.what_to_count; 
    for (idx = 0; idx < config.buckets; idx++) {
      if (!following_chain) acc_elem = (struct acc *) elem;
      if (acc_elem->packet_counter && !acc_elem->reset_flag) {
	enQueue_elem(sd, &rb, acc_elem, PdataSz, PdataSz+PbgpSz);
	/* XXX: to be optimized ? */
	if (PbgpSz) {
	  if (acc_elem->cbgp) {
	    struct pkt_bgp_primitives tmp_pbgp;

	    cache_to_pkt_bgp_primitives(&tmp_pbgp, acc_elem->cbgp);
	    enQueue_elem(sd, &rb, &tmp_pbgp, PbgpSz, PbgpSz);
	  }
	  else enQueue_elem(sd, &rb, &dummy_pbgp, PbgpSz, PbgpSz);
	}
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
        if (acc_elem->packet_counter && !acc_elem->reset_flag) bd.howmany++;
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
    for (j = 0; j < uq->num; j++, bufptr += sizeof(struct query_entry)) {
      memcpy(&request, bufptr, sizeof(struct query_entry));
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): Searching into accounting structure ...\n", config.name, config.type); 
      if (request.what_to_count == config.what_to_count) { 
        acc_elem = search_accounting_structure(&request.data, &request.pbgp);
        if (acc_elem) { 
	  if (acc_elem->packet_counter && !acc_elem->reset_flag) {
	    enQueue_elem(sd, &rb, acc_elem, PdataSz, PdataSz+PbgpSz);
	    /* XXX: to be optimized ? */
	    if (PbgpSz) {
	      if (acc_elem->cbgp) {
		struct pkt_bgp_primitives tmp_pbgp;

		cache_to_pkt_bgp_primitives(&tmp_pbgp, acc_elem->cbgp);
		enQueue_elem(sd, &rb, &tmp_pbgp, PbgpSz, PbgpSz);
	      }
	      else enQueue_elem(sd, &rb, &dummy_pbgp, PbgpSz, PbgpSz);
	    }
	    if (reset_counter) {
	      if (forked) set_reset_flag(acc_elem);
	      else reset_counters(acc_elem);
	    }
	  }
	  else {
	    if (q->type & WANT_COUNTER) {
	      enQueue_elem(sd, &rb, &dummy, PdataSz, PdataSz+PbgpSz);
	      if (PbgpSz) enQueue_elem(sd, &rb, &dummy_pbgp, PbgpSz, PbgpSz);
	    }
	  }
        }
	else {
	  if (q->type & WANT_COUNTER) {
	    enQueue_elem(sd, &rb, &dummy, PdataSz, PdataSz+PbgpSz);
	    if (PbgpSz) enQueue_elem(sd, &rb, &dummy_pbgp, PbgpSz, PbgpSz);
	  }
	}
      }
      else {
        struct pkt_primitives tbuf;  
	struct pkt_bgp_primitives bbuf;
	struct pkt_data abuf;
        following_chain = FALSE;
	elem = (unsigned char *) a;
	memset(&abuf, 0, sizeof(abuf));

        for (idx = 0; idx < config.buckets; idx++) {
          if (!following_chain) acc_elem = (struct acc *) elem;
	  if (acc_elem->packet_counter && !acc_elem->reset_flag) {
	    mask_elem(&tbuf, &bbuf, acc_elem, request.what_to_count); 
            if (!memcmp(&tbuf, &request.data, sizeof(struct pkt_primitives)) &&
		!memcmp(&bbuf, &request.pbgp, sizeof(struct pkt_bgp_primitives))) {
	      if (q->type & WANT_COUNTER) Accumulate_Counters(&abuf, acc_elem); 
	      else {
		enQueue_elem(sd, &rb, acc_elem, PdataSz, PdataSz+PbgpSz); /* q->type == WANT_MATCH */
		if (PbgpSz) {
		  if (acc_elem->cbgp) {
		    struct pkt_bgp_primitives tmp_pbgp;

		    cache_to_pkt_bgp_primitives(&tmp_pbgp, acc_elem->cbgp);
		    enQueue_elem(sd, &rb, &tmp_pbgp, PbgpSz, PbgpSz);
		  }
		  else enQueue_elem(sd, &rb, &dummy_pbgp, PbgpSz, PbgpSz);
		}
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
    int idx = 0;

    /* XXX: we should try using pmct_get_max_entries() */
    q->num = config.classifier_table_num;
    if (!q->num && config.classifiers_path) q->num = MAX_CLASSIFIERS;

    while (idx < q->num) {
      enQueue_elem(sd, &rb, &class[idx], sizeof(struct stripped_class), sizeof(struct stripped_class));
      idx++;
    }

    send_ct_dummy:
    memset(&dummy, 0, sizeof(dummy));
    enQueue_elem(sd, &rb, &dummy, sizeof(dummy), sizeof(dummy));
    send(sd, rb.buf, rb.packed, 0); /* send remainder data */
  }
}

void mask_elem(struct pkt_primitives *d1, struct pkt_bgp_primitives *d2, struct acc *src, u_int64_t w)
{
  struct pkt_primitives *s1 = &src->primitives;
  struct pkt_bgp_primitives tmp_pbgp;
  struct pkt_bgp_primitives *s2 = &tmp_pbgp;

  cache_to_pkt_bgp_primitives(s2, src->cbgp);

  memset(d1, 0, sizeof(struct pkt_primitives));
  memset(d2, 0, sizeof(struct pkt_bgp_primitives));

#if defined (HAVE_L2)
  if (w & COUNT_SRC_MAC) memcpy(d1->eth_shost, s1->eth_shost, ETH_ADDR_LEN); 
  if (w & COUNT_DST_MAC) memcpy(d1->eth_dhost, s1->eth_dhost, ETH_ADDR_LEN); 
  if (w & COUNT_VLAN) d1->vlan_id = s1->vlan_id; 
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
  if (w & COUNT_SRC_AS) d1->src_as = s1->src_as; 
  if (w & COUNT_DST_AS) d1->dst_as = s1->dst_as; 
  if (w & COUNT_SRC_PORT) d1->src_port = s1->src_port; 
  if (w & COUNT_DST_PORT) d1->dst_port = s1->dst_port; 
  if (w & COUNT_IP_TOS) d1->tos = s1->tos;
  if (w & COUNT_IP_PROTO) d1->proto = s1->proto; 
  if (w & COUNT_ID) d1->id = s1->id; 
  if (w & COUNT_ID2) d1->id2 = s1->id2; 
  if (w & COUNT_CLASS) d1->class = s1->class; 

  if (PbgpSz && s2) {
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
    if (w & COUNT_IS_SYMMETRIC) d2->is_symmetric = s2->is_symmetric;
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
  abuf->time_start++; /* XXX: this unused field works as counter of how much entries we are accumulating */
}
