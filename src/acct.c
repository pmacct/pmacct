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

#define __ACCT_C

/* includes */
#include "pmacct.h"
#include "imt_plugin.h"
#include "crc32.c"

/* functions */
struct acc *search_accounting_structure(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  struct pkt_primitives *addr = &data->primitives;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  struct acc *elem_acc;
  unsigned int hash, pos;
  unsigned int pp_size = sizeof(struct pkt_primitives); 
  unsigned int pb_size = sizeof(struct pkt_bgp_primitives);
  unsigned int pn_size = sizeof(struct pkt_nat_primitives);

  hash = cache_crc32((unsigned char *)addr, pp_size);
  if (pbgp) hash ^= cache_crc32((unsigned char *)pbgp, pb_size);
  if (pnat) hash ^= cache_crc32((unsigned char *)pnat, pn_size);
  pos = hash % config.buckets;

  Log(LOG_DEBUG, "DEBUG ( %s/%s ): Selecting bucket %u.\n", config.name, config.type, pos);

  elem_acc = (struct acc *) a;
  elem_acc += pos;  
  
  while (elem_acc) {
    if (elem_acc->signature == hash) {
      if (compare_accounting_structure(elem_acc, prim_ptrs) == 0) return elem_acc;
    }
    elem_acc = elem_acc->next;
  } 

  return NULL;
}

int compare_accounting_structure(struct acc *elem, struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *pdata = prim_ptrs->data;
  struct pkt_primitives *data = &pdata->primitives;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  int res_data = TRUE, res_bgp = TRUE, res_nat = TRUE; 

  res_data = memcmp(&elem->primitives, data, sizeof(struct pkt_primitives));

  if (pbgp) {
    if (elem->cbgp) {
      struct pkt_bgp_primitives tmp_pbgp;

      cache_to_pkt_bgp_primitives(&tmp_pbgp, elem->cbgp);
      res_bgp = memcmp(&tmp_pbgp, pbgp, sizeof(struct pkt_bgp_primitives));
    }
  }
  else res_bgp = FALSE;

  if (pnat && elem->pnat) res_nat = memcmp(elem->pnat, pnat, sizeof(struct pkt_nat_primitives));
  else res_nat = FALSE;

  return res_data | res_bgp | res_nat;
}

void insert_accounting_structure(struct primitives_ptrs *prim_ptrs)
{
  struct pkt_data *data = prim_ptrs->data;
  struct pkt_primitives *addr = &data->primitives;
  struct pkt_bgp_primitives *pbgp = prim_ptrs->pbgp;
  struct pkt_nat_primitives *pnat = prim_ptrs->pnat;
  struct acc *elem_acc;
  unsigned char *elem, *new_elem;
  int solved = FALSE;
  unsigned int hash, pos;
  unsigned int pp_size = sizeof(struct pkt_primitives);
  unsigned int pb_size = sizeof(struct pkt_bgp_primitives);
  unsigned int pn_size = sizeof(struct pkt_nat_primitives);
  unsigned int cb_size = sizeof(struct cache_bgp_primitives);

  /* We are classifing packets. We have a non-zero bytes accumulator (ba)
     and a non-zero class. Before accounting ba to this class, we have to
     remove ba from class zero. */ 
  if (config.what_to_count & COUNT_CLASS && data->cst.ba && data->primitives.class) {
    pm_class_t lclass = data->primitives.class;

    data->primitives.class = 0;
    elem_acc = search_accounting_structure(prim_ptrs);
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
  if (pbgp) hash ^= cache_crc32((unsigned char *)pbgp, pb_size);
  if (pnat) hash ^= cache_crc32((unsigned char *)pnat, pn_size);
  pos = hash % config.buckets;
      
  Log(LOG_DEBUG, "DEBUG ( %s/%s ): Selecting bucket %u.\n", config.name, config.type, pos);
  /* 
     1st stage: compare data with last used element;
     2nd stage: compare data with elements in the table, following chains
  */
  if (lru_elem_ptr[pos]) {
    elem_acc = lru_elem_ptr[pos];
    if (elem_acc->signature == hash) {
      if (compare_accounting_structure(elem_acc, prim_ptrs) == 0) { 
        if (elem_acc->reset_flag) reset_counters(elem_acc);
        elem_acc->packet_counter += data->pkt_num;
        elem_acc->flow_counter += data->flo_num;
        elem_acc->bytes_counter += data->pkt_len;
	elem_acc->tcp_flags |= data->tcp_flags;
        elem_acc->flow_type = data->flow_type; // XXX
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
      if (compare_accounting_structure(elem_acc, prim_ptrs) == 0) {
        if (elem_acc->reset_flag) reset_counters(elem_acc);
        elem_acc->packet_counter += data->pkt_num;
        elem_acc->flow_counter += data->flo_num;
        elem_acc->bytes_counter += data->pkt_len;
	elem_acc->tcp_flags |= data->tcp_flags;
        elem_acc->flow_type = data->flow_type; // XXX
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

      if (pbgp) {
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
        pkt_to_cache_bgp_primitives(elem_acc->cbgp, pbgp, config.what_to_count);
      }

      if (pnat) {
        elem_acc->pnat = (struct pkt_nat_primitives *) malloc(pn_size);
	memcpy(elem_acc->pnat, pnat, pn_size);
      }
      else elem_acc->pnat = NULL;

      elem_acc->packet_counter += data->pkt_num;
      elem_acc->flow_counter += data->flo_num;
      elem_acc->bytes_counter += data->pkt_len;
      elem_acc->tcp_flags |= data->tcp_flags;
      elem_acc->flow_type = data->flow_type; // XXX
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

      if (pbgp) {
        elem_acc->cbgp = (struct cache_bgp_primitives *) malloc(cb_size);
        memset(elem_acc->cbgp, 0, cb_size);
        pkt_to_cache_bgp_primitives(elem_acc->cbgp, pbgp, config.what_to_count);
      }
      else elem_acc->cbgp = NULL;

      if (pnat) {
        elem_acc->pnat = (struct pkt_nat_primitives *) malloc(pn_size);
        memcpy(elem_acc->pnat, pnat, pn_size);
      }
      else elem_acc->pnat = NULL;

      elem_acc->packet_counter += data->pkt_num;
      elem_acc->flow_counter += data->flo_num;
      elem_acc->bytes_counter += data->pkt_len;
      elem_acc->tcp_flags = data->tcp_flags;
      elem_acc->flow_type = data->flow_type;
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
  elem->flow_type = 0;
  memcpy(&elem->rstamp, &cycle_stamp, sizeof(struct timeval));
}
