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

#define __ACCT_C

/* includes */
#include "pmacct.h"
#include "imt_plugin.h"
#include "crc32.c"

void cache_to_pkt_bgp_primitives(struct pkt_bgp_primitives *p, struct cache_bgp_primitives *c)
{
  memset(p, 0, PbgpSz);

  if (c) {
    p->peer_src_as = c->peer_src_as;
    p->peer_dst_as = c->peer_dst_as;
    memcpy(&p->peer_src_ip, &c->peer_src_ip, HostAddrSz);
    memcpy(&p->peer_dst_ip, &c->peer_dst_ip, HostAddrSz);
    if (c->std_comms) memcpy(p->std_comms, c->std_comms, MAX_BGP_STD_COMMS);
    if (c->ext_comms) memcpy(p->ext_comms, c->ext_comms, MAX_BGP_EXT_COMMS);
    if (c->as_path) memcpy(p->as_path, c->as_path, MAX_BGP_ASPATH);
    p->local_pref = c->local_pref;
    p->med = c->med;
    if (c->src_std_comms) memcpy(p->src_std_comms, c->src_std_comms, MAX_BGP_STD_COMMS);
    if (c->src_ext_comms) memcpy(p->src_ext_comms, c->src_ext_comms, MAX_BGP_EXT_COMMS);
    if (c->src_as_path) memcpy(p->src_as_path, c->src_as_path, MAX_BGP_ASPATH);
    p->src_local_pref = c->src_local_pref;
    p->src_med = c->src_med;
  }
}

void pkt_to_cache_bgp_primitives(struct cache_bgp_primitives *c, struct pkt_bgp_primitives *p)
{
  if (c) {
    c->peer_src_as = p->peer_src_as;
    c->peer_dst_as = p->peer_dst_as;
    memcpy(&c->peer_src_ip, &p->peer_src_ip, HostAddrSz);
    memcpy(&c->peer_dst_ip, &p->peer_dst_ip, HostAddrSz);
    if (strlen(p->std_comms)) {
      if (!c->std_comms) c->std_comms = malloc(MAX_BGP_STD_COMMS);
      memcpy(c->std_comms, p->std_comms, MAX_BGP_STD_COMMS);
    }
    else {
      if (c->std_comms) free(c->std_comms);
    }
    if (strlen(p->ext_comms)) {
      if (!c->ext_comms) c->ext_comms = malloc(MAX_BGP_EXT_COMMS);
      memcpy(c->ext_comms, p->ext_comms, MAX_BGP_EXT_COMMS);
    }
    else {
      if (c->ext_comms) free(c->ext_comms);
    }
    if (strlen(p->as_path)) {
      if (!c->as_path) c->as_path = malloc(MAX_BGP_ASPATH);
      memcpy(c->as_path, p->as_path, MAX_BGP_ASPATH);
    } 
    else {
      if (c->as_path) free(c->as_path);
    }
    c->local_pref = p->local_pref;
    c->med = p->med;
    if (strlen(p->src_std_comms)) {
      if (!c->src_std_comms) c->src_std_comms = malloc(MAX_BGP_STD_COMMS);
      memcpy(c->src_std_comms, p->src_std_comms, MAX_BGP_STD_COMMS);
    }
    else {
      if (c->src_std_comms) free(c->src_std_comms);
    }
    if (strlen(p->src_ext_comms)) {
      if (!c->src_ext_comms) c->src_ext_comms = malloc(MAX_BGP_EXT_COMMS);
      memcpy(c->src_ext_comms, p->src_ext_comms, MAX_BGP_EXT_COMMS);
    } 
    else {
      if (c->src_ext_comms) free(c->src_ext_comms);
    }
    if (strlen(p->src_as_path)) {
      if (!c->src_as_path) c->src_as_path = malloc(MAX_BGP_ASPATH);
      memcpy(c->src_as_path, p->src_as_path, MAX_BGP_ASPATH);
    }
    else {
      if (c->src_as_path) free(c->src_as_path);
    }
    c->src_local_pref = p->src_local_pref;
    c->src_med = p->src_med;
  }
}

/* functions */
struct acc *search_accounting_structure(struct pkt_primitives *addr, struct pkt_bgp_primitives *pbgp)
{
  struct acc *elem_acc;
  unsigned int hash, pos;
  unsigned int pp_size = sizeof(struct pkt_primitives); 
  unsigned int pb_size = sizeof(struct pkt_bgp_primitives);

  hash = cache_crc32((unsigned char *)addr, pp_size);
  /* XXX: to be optimized? */
  if (PbgpSz) {
    if (pbgp) hash ^= cache_crc32((unsigned char *)pbgp, pb_size);
  }
  pos = hash % config.buckets;

  Log(LOG_DEBUG, "DEBUG ( %s/%s ): Selecting bucket %u.\n", config.name, config.type, pos);

  elem_acc = (struct acc *) a;
  elem_acc += pos;  
  
  while (elem_acc) {
    if (elem_acc->signature == hash) {
      if (compare_accounting_structure(elem_acc, addr, pbgp) == 0) return elem_acc;
      // if (!memcmp(&elem_acc->primitives, addr, sizeof(struct pkt_primitives))) return elem_acc;
    }
    elem_acc = elem_acc->next;
  } 

  return NULL;
}

int compare_accounting_structure(struct acc *elem, struct pkt_primitives *data, struct pkt_bgp_primitives *pbgp)
{
  int res_data = TRUE, res_bgp = TRUE; 

  res_data = memcmp(&elem->primitives, data, sizeof(struct pkt_primitives));

  /* XXX: to be optimized? */
  if (PbgpSz) {
    if (elem->cbgp) {
      struct pkt_bgp_primitives tmp_pbgp;

      cache_to_pkt_bgp_primitives(&tmp_pbgp, elem->cbgp);
      res_bgp = memcmp(&tmp_pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
    }
  }
  else res_bgp = FALSE;

  return res_data | res_bgp;
}

void insert_accounting_structure(struct pkt_data *data, struct pkt_bgp_primitives *pbgp)
{
  struct pkt_primitives *addr = &data->primitives;
  struct acc *elem_acc;
  unsigned char *elem, *new_elem;
  int solved = FALSE;
  unsigned int hash, pos;
  unsigned int pp_size = sizeof(struct pkt_primitives);
  unsigned int pb_size = sizeof(struct pkt_bgp_primitives);
  unsigned int cb_size = sizeof(struct cache_bgp_primitives);

  /* We are classifing packets. We have a non-zero bytes accumulator (ba)
     and a non-zero class. Before accounting ba to this class, we have to
     remove ba from class zero. */ 
  if (config.what_to_count & COUNT_CLASS && data->cst.ba && data->primitives.class) {
    pm_class_t lclass = data->primitives.class;

    data->primitives.class = 0;
    elem_acc = search_accounting_structure(&data->primitives, pbgp);
    data->primitives.class = lclass;

    /* We can assign the flow to a new class only if we are able to subtract
       the accumulator from the zero-class. If this is not the case, we will
       discard the accumulators. The assumption is that accumulators are not
       retroactive */
    if (elem_acc) {
      if (timeval_cmp(&data->cst.stamp, &elem_acc->rstamp) >= 0 && 
	  timeval_cmp(&data->cst.stamp, &table_reset_stamp) >= 0) {
	/* MIN(): ToS issue */
        elem_acc->bytes_counter -= MIN(elem_acc->bytes_counter, data->cst.ba);
        elem_acc->packet_counter -= MIN(elem_acc->packet_counter, data->cst.pa);
        elem_acc->flow_counter -= MIN(elem_acc->flow_counter, data->cst.fa);
      } 
      else memset(&data->cst, 0, CSSz);
    }
    else memset(&data->cst, 0, CSSz);
  } 

  elem = a;

  hash = cache_crc32((unsigned char *)addr, pp_size);
  /* XXX: to be optimized? */
  if (PbgpSz) {
    if (pbgp) hash ^= cache_crc32((unsigned char *)pbgp, pb_size);
  }
  pos = hash % config.buckets;
      
  Log(LOG_DEBUG, "DEBUG ( %s/%s ): Selecting bucket %u.\n", config.name, config.type, pos);
  /* 
     1st stage: compare data with last used element;
     2nd stage: compare data with elements in the table, following chains
  */
  if (lru_elem_ptr[pos]) {
    elem_acc = lru_elem_ptr[pos];
    if (elem_acc->signature == hash) {
      if (compare_accounting_structure(elem_acc, addr, pbgp) == 0) { 
      // if (memcmp(&elem_acc->primitives, addr, sizeof(struct pkt_primitives)) == 0) {
        if (elem_acc->reset_flag) reset_counters(elem_acc);
        elem_acc->packet_counter += data->pkt_num;
        elem_acc->flow_counter += data->flo_num;
        elem_acc->bytes_counter += data->pkt_len;
	elem_acc->tcp_flags |= data->tcp_flags;
        if (config.what_to_count & COUNT_CLASS) {
          elem_acc->packet_counter += data->cst.pa;
          elem_acc->bytes_counter += data->cst.ba;
          elem_acc->flow_counter += data->cst.fa;
        }
        return;
      }
    }
  }

  elem_acc = (struct acc *) elem;
  elem_acc += pos;

  while (solved == FALSE) {
    if (elem_acc->signature == hash) {
      if (compare_accounting_structure(elem_acc, addr, pbgp) == 0) {
      // if (memcmp(&elem_acc->primitives, addr, sizeof(struct pkt_primitives)) == 0) {
        if (elem_acc->reset_flag) reset_counters(elem_acc);
        elem_acc->packet_counter += data->pkt_num;
        elem_acc->flow_counter += data->flo_num;
        elem_acc->bytes_counter += data->pkt_len;
	elem_acc->tcp_flags |= data->tcp_flags;
	if (config.what_to_count & COUNT_CLASS) {
	  elem_acc->packet_counter += data->cst.pa;
	  elem_acc->bytes_counter += data->cst.ba;
          elem_acc->flow_counter += data->cst.fa;
	}
        lru_elem_ptr[config.buckets] = elem_acc;
        return;
      }
    }
    if (!elem_acc->bytes_counter && !elem_acc->packet_counter) { /* hmmm */
      if (elem_acc->reset_flag) elem_acc->reset_flag = FALSE; 
      memcpy(&elem_acc->primitives, addr, sizeof(struct pkt_primitives));

      /* XXX: to be optimized? */
      if (PbgpSz) {
	if (elem_acc->cbgp) {
	  if (elem_acc->cbgp->std_comms) free(elem_acc->cbgp->std_comms);
	  if (elem_acc->cbgp->ext_comms) free(elem_acc->cbgp->ext_comms);
	  if (elem_acc->cbgp->as_path) free(elem_acc->cbgp->as_path);
	  if (elem_acc->cbgp->src_std_comms) free(elem_acc->cbgp->src_std_comms);
	  if (elem_acc->cbgp->src_ext_comms) free(elem_acc->cbgp->src_ext_comms);
	  if (elem_acc->cbgp->src_as_path) free(elem_acc->cbgp->src_as_path);
	  free(elem_acc->cbgp);
	}
	elem_acc->cbgp = (struct cache_bgp_primitives *) malloc(cb_size);
	memset(elem_acc->cbgp, 0, cb_size);
        pkt_to_cache_bgp_primitives(elem_acc->cbgp, pbgp);
      }

      elem_acc->packet_counter += data->pkt_num;
      elem_acc->flow_counter += data->flo_num;
      elem_acc->bytes_counter += data->pkt_len;
      elem_acc->tcp_flags |= data->tcp_flags;
      elem_acc->signature = hash;
      if (config.what_to_count & COUNT_CLASS) {
        elem_acc->packet_counter += data->cst.pa;
        elem_acc->bytes_counter += data->cst.ba;
        elem_acc->flow_counter += data->cst.fa;
      }
      lru_elem_ptr[config.buckets] = elem_acc;
      return;
    }

    /* Handling collisions */
    else if (elem_acc->next != NULL) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): Walking through the collision-chain.\n", config.name, config.type);
      elem_acc = elem_acc->next;
      solved = FALSE;
    }
    else if (elem_acc->next == NULL) {
      /* We have to know if there is enough space for a new element;
         if not we are losing informations; conservative approach */
      if (no_more_space) return;

      /* We have to allocate new space for this address */
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): Creating new element.\n", config.name, config.type);

      if (current_pool->space_left >= sizeof(struct acc)) {
        new_elem = current_pool->ptr;
	current_pool->space_left -= sizeof(struct acc);
	current_pool->ptr += sizeof(struct acc);
      }
      else {
        current_pool = request_memory_pool(config.memory_pool_size); 
	if (current_pool == NULL) {
          Log(LOG_WARNING, "WARN ( %s/%s ): Unable to allocate more memory pools, clear stats manually!\n", config.name, config.type);
	  no_more_space = TRUE;
	  return;
        }
        else {
          new_elem = current_pool->ptr;
          current_pool->space_left -= sizeof(struct acc);
          current_pool->ptr += sizeof(struct acc);
	}
      }

      elem_acc->next = (struct acc *) new_elem;
      elem_acc = (struct acc *) new_elem;
      memcpy(&elem_acc->primitives, addr, sizeof(struct pkt_primitives));

      /* XXX: to be optimized? */
      if (PbgpSz) {
        elem_acc->cbgp = (struct cache_bgp_primitives *) malloc(cb_size);
        memset(elem_acc->cbgp, 0, cb_size);
        pkt_to_cache_bgp_primitives(elem_acc->cbgp, pbgp);
      }
      else elem_acc->cbgp = NULL;

      elem_acc->packet_counter += data->pkt_num;
      elem_acc->flow_counter += data->flo_num;
      elem_acc->bytes_counter += data->pkt_len;
      elem_acc->tcp_flags = data->tcp_flags;
      elem_acc->signature = hash; 
      if (config.what_to_count & COUNT_CLASS) {
        elem_acc->packet_counter += data->cst.pa;
        elem_acc->bytes_counter += data->cst.ba;
        elem_acc->flow_counter += data->cst.fa;
      }
      elem_acc->next = NULL;
      lru_elem_ptr[config.buckets] = elem_acc;
      return;
    }
  }
}

void set_reset_flag(struct acc *elem)
{
  elem->reset_flag = TRUE;
}

void reset_counters(struct acc *elem)
{
  elem->reset_flag = FALSE;
  elem->packet_counter = 0;
  elem->bytes_counter = 0;
  elem->tcp_flags = 0;
  memcpy(&elem->rstamp, &cycle_stamp, sizeof(struct timeval));
}
