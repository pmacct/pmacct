/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2021 by Paolo Lucente
*/

/* 
 Originally based on Quagga BGP routing table which is:

 Copyright (C) 1998, 2001 Kunihiro Ishiguro

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

/* includes */
#include "pmacct.h"
#include "bgp.h"

static void bgp_node_delete (struct bgp_peer *, struct bgp_node *);
static struct bgp_node *bgp_node_create (struct bgp_peer *);
static struct bgp_node *bgp_node_set (struct bgp_peer *, struct bgp_table *, struct prefix *);
static void bgp_node_free (struct bgp_node *);
static void route_common (struct prefix *, struct prefix *, struct prefix *);
static int check_bit (u_char *, u_char);
static void set_link (struct bgp_node *, struct bgp_node *);

struct bgp_table *
bgp_table_init (afi_t afi, safi_t safi)
{
  struct bgp_table *rt;

  rt = malloc (sizeof (struct bgp_table));
  if (rt) {
    memset (rt, 0, sizeof (struct bgp_table));

    rt->afi = afi;
    rt->safi = safi;
  }
  else {
    Log(LOG_ERR, "ERROR ( %s/core/BGP ): malloc() failed (bgp_table_init). Exiting ..\n", config.name); // XXX
    exit_gracefully(1);
  }
  
  return rt;
}

static struct bgp_node *
bgp_node_create (struct bgp_peer *peer)
{
  struct bgp_misc_structs *bms;
  struct bgp_node *rn;

  if (!peer) return NULL;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return NULL;

  rn = (struct bgp_node *) malloc (sizeof (struct bgp_node));
  if (rn) {
    memset (rn, 0, sizeof (struct bgp_node));

    rn->info = (void **) malloc(sizeof(struct bgp_info *) * (bms->table_peer_buckets * bms->table_per_peer_buckets));
    if (rn->info) memset (rn->info, 0, sizeof(struct bgp_info *) * (bms->table_peer_buckets * bms->table_per_peer_buckets));
    else goto malloc_failed;
  }
  else goto malloc_failed;

  return rn;

  malloc_failed:
  Log(LOG_ERR, "ERROR ( %s/%s ): malloc() failed (bgp_node_create). Exiting ..\n", config.name, bms->log_str);
  exit_gracefully(1);

  return NULL; /* silence compiler warning */
}

/* Allocate new route node with prefix set. */
static struct bgp_node *
bgp_node_set (struct bgp_peer *peer, struct bgp_table *table, struct prefix *prefix)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);
  (void)bms;
  struct bgp_node *node;
  
  node = bgp_node_create (peer);

  prefix_copy (&node->p, prefix);
  node->table = table;

  return node;
}

/* Free route node. */
static void
bgp_node_free (struct bgp_node *node)
{
  if (node->info) {
    free (node->info);
    node->info = NULL;
  }

  free (node);
}

/* Utility mask array. */
static u_char maskbit[] = 
{
  0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
};

/* Common prefix route genaration. */
static void
route_common (struct prefix *n, struct prefix *p, struct prefix *new)
{
  int i;
  u_char diff;
  u_char mask;

  u_char *np = (u_char *)&n->u.prefix;
  u_char *pp = (u_char *)&p->u.prefix;
  u_char *newp = (u_char *)&new->u.prefix;

  for (i = 0; i < p->prefixlen / 8; i++)
    {
      if (np[i] == pp[i])
	newp[i] = np[i];
      else
	break;
    }

  new->prefixlen = i * 8;

  if (new->prefixlen != p->prefixlen)
    {
      diff = np[i] ^ pp[i];
      mask = 0x80;
      while (new->prefixlen < p->prefixlen && !(mask & diff))
	{
	  mask >>= 1;
	  new->prefixlen++;
	}
      newp[i] = np[i] & maskbit[new->prefixlen % 8];
    }
}

/* Macro version of check_bit (). */
#define CHECK_BIT(X,P) ((((u_char *)(X))[(P) / 8]) >> (7 - ((P) % 8)) & 1)

/* Check bit of the prefix. */
static int
check_bit (u_char *prefix, u_char prefixlen)
{
  int offset;
  int shift;
  u_char *p = (u_char *)prefix;

  assert (prefixlen <= 128);

  offset = prefixlen / 8;
  shift = 7 - (prefixlen % 8);
  
  return (p[offset] >> shift & 1);
}

/* Macro version of set_link (). */
#define SET_LINK(X,Y) (X)->link[CHECK_BIT(&(Y)->prefix,(X)->prefixlen)] = (Y);\
                      (Y)->parent = (X)

static void
set_link (struct bgp_node *node, struct bgp_node *new)
{
  int bit;
    
  bit = check_bit (&new->p.u.prefix, node->p.prefixlen);

  assert (bit == 0 || bit == 1);

  node->link[bit] = new;
  new->parent = node;
}

/* Lock node. */
struct bgp_node *
bgp_lock_node (struct bgp_peer *peer, struct bgp_node *node)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);

  assert(bms);

  if (!bms->is_readonly) {
    node->lock++;
  }

  return node;
}

/* Unlock node. */
void
bgp_unlock_node (struct bgp_peer *peer, struct bgp_node *node)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);

  assert(bms);

  if (!bms->is_readonly) {
    node->lock--;

    if (node->lock == 0) {
      bgp_node_delete (peer, node);
    }
  }
}

void bgp_node_vector_debug(struct bgp_node_vector *bnv, struct prefix *p)
{
  char prefix_str[PREFIX_STRLEN];
  int idx;
  

  if (bnv && p) {
    memset(prefix_str, 0, PREFIX_STRLEN);
    prefix2str(p, prefix_str, PREFIX_STRLEN);
    Log(LOG_DEBUG, "DEBUG ( %s/core/BGP ): bgp_node_vector_debug(): levels=%u lookup=%s\n", config.name, bnv->entries, prefix_str);
    
    for (idx = 0; idx < bnv->entries; idx++) {
      memset(prefix_str, 0, PREFIX_STRLEN);
      prefix2str(bnv->v[idx].p, prefix_str, PREFIX_STRLEN);
      Log(LOG_DEBUG, "DEBUG ( %s/core/BGP ): bgp_node_vector_debug(): level=%u prefix=%s\n", config.name, idx, prefix_str);
    }
  }
}

/* Find matched prefix. */
void
bgp_node_match (const struct bgp_table *table, struct prefix *p, struct bgp_peer *peer,
		u_int32_t (*modulo_func)(struct bgp_peer *, path_id_t *, int),
		int (*cmp_func)(struct bgp_info *, struct node_match_cmp_term2 *),
		struct node_match_cmp_term2 *nmct2, struct bgp_node_vector *bnv,
		struct bgp_node **result_node, struct bgp_info **result_info)
{
  struct bgp_misc_structs *bms;
  struct bgp_node *node, *matched_node;
  struct bgp_info *info, *matched_info;
  u_int32_t modulo, modulo_idx, local_modulo, modulo_max;

  if (!table || !peer || !cmp_func) return;

  bms = bgp_select_misc_db(peer->type);
  if (!bms) return;

  /* XXX: see https://github.com/pmacct/pmacct/pull/78 */
  if (bms->table_per_peer_hash == BGP_ASPATH_HASH_PATHID) modulo_max = bms->table_per_peer_buckets;
  else modulo_max = 1;

  if (modulo_func) modulo = modulo_func(peer, NULL, modulo_max);
  else modulo = 0;

  matched_node = NULL;
  matched_info = NULL;
  node = table->top;
  if (bnv) bnv->entries = 0;

  /* Walk down tree.  If there is matched route then store it to matched. */
  while (node && node->p.prefixlen <= p->prefixlen && prefix_match(&node->p, p)) {
    for (local_modulo = modulo, modulo_idx = 0; modulo_idx < modulo_max; local_modulo++, modulo_idx++) {
      for (info = node->info[local_modulo]; info; info = info->next) {
	if (!cmp_func(info, nmct2)) {
	  matched_node = node;
	  matched_info = info;

	  if (bnv) {
	    bnv->v[bnv->entries].p = &node->p;
	    bnv->v[bnv->entries].info = info;
	    bnv->entries++;
	  }

	  if (node->p.prefixlen == p->prefixlen) break;
	}
      }
    }

    node = node->link[check_bit(&p->u.prefix, node->p.prefixlen)];
  }

  if (config.debug && bnv) bgp_node_vector_debug(bnv, p); 

  if (matched_node) {
    (*result_node) = matched_node;
    (*result_info) = matched_info;
    bgp_lock_node (peer, matched_node);
  }
  else {
    (*result_node) = NULL;
    (*result_info) = NULL;
  }
}

void
bgp_node_match_ipv4 (const struct bgp_table *table, struct in_addr *addr, struct bgp_peer *peer,
		     u_int32_t (*modulo_func)(struct bgp_peer *, path_id_t *, int),
		     int (*cmp_func)(struct bgp_info *, struct node_match_cmp_term2 *),
		     struct node_match_cmp_term2 *nmct2, struct bgp_node_vector *bnv,
		     struct bgp_node **result_node, struct bgp_info **result_info)
{
  struct prefix_ipv4 p;

  memset (&p, 0, sizeof (struct prefix_ipv4));
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_PREFIXLEN;
  p.prefix = *addr;

  bgp_node_match (table, (struct prefix *) &p, peer, modulo_func, cmp_func, nmct2, bnv, result_node, result_info);
}

void
bgp_node_match_ipv6 (const struct bgp_table *table, struct in6_addr *addr, struct bgp_peer *peer,
		     u_int32_t (*modulo_func)(struct bgp_peer *, path_id_t *, int),
		     int (*cmp_func)(struct bgp_info *, struct node_match_cmp_term2 *),
		     struct node_match_cmp_term2 *nmct2, struct bgp_node_vector *bnv,
		     struct bgp_node **result_node, struct bgp_info **result_info)
{
  struct prefix_ipv6 p;

  memset (&p, 0, sizeof (struct prefix_ipv6));
  p.family = AF_INET6;
  p.prefixlen = IPV6_MAX_PREFIXLEN;
  p.prefix = *addr;

  bgp_node_match (table, (struct prefix *) &p, peer, modulo_func, cmp_func, nmct2, bnv, result_node, result_info);
}

/* Add node to routing table. */
struct bgp_node *
bgp_node_get (struct bgp_peer *peer, struct bgp_table *const table, struct prefix *p)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);
  (void)bms;
  struct bgp_node *new;
  struct bgp_node *node;
  struct bgp_node *match;

  match = NULL;
  node = table->top;
  while (node && node->p.prefixlen <= p->prefixlen && 
	 prefix_match (&node->p, p))
    {
      if (node->p.prefixlen == p->prefixlen)
	{
	  bgp_lock_node (peer, node);
	  return node;
	}
      match = node;
      node = node->link[check_bit(&p->u.prefix, node->p.prefixlen)];
    }

  if (node == NULL)
    {
      new = bgp_node_set (peer, table, p);
      if (match)
	set_link (match, new);
      else
	table->top = new;
    }
  else
    {
      new = bgp_node_create (peer);
      route_common (&node->p, p, &new->p);
      new->p.family = p->family;
      new->table = table;
      set_link (new, node);

      if (match)
	set_link (match, new);
      else
	table->top = new;

      if (new->p.prefixlen != p->prefixlen)
	{
	  match = new;
	  new = bgp_node_set (peer, table, p);
	  set_link (match, new);
	  table->count++;
	}
    }
  table->count++;
  bgp_lock_node (peer, new);
  
  return new;
}

/* Delete node from the routing table. */
static void
bgp_node_delete (struct bgp_peer *peer, struct bgp_node *node)
{
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);
  struct bgp_node *child;
  struct bgp_node *parent;
  u_int32_t ri_idx;

  assert (node->lock == 0);

  for (ri_idx = 0; ri_idx < (bms->table_peer_buckets * bms->table_per_peer_buckets); ri_idx++)
    assert (node->info[ri_idx] == NULL);

  if (node->l_left && node->l_right)
    return;

  if (node->l_left)
    child = node->l_left;
  else
    child = node->l_right;

  parent = node->parent;

  if (child)
    child->parent = parent;

  if (parent)
    {
      if (parent->l_left == node)
	parent->l_left = child;
      else
	parent->l_right = child;
    }
  else
    node->table->top = child;
  
  node->table->count--;
  
  bgp_node_free (node);

  /* If parent node is stub then delete it also. */
  if (parent && parent->lock == 0)
    bgp_node_delete (peer, parent);
}

/* Get fist node and lock it.  This function is useful when one want
   to lookup all the node exist in the routing table. */
struct bgp_node *
bgp_table_top (struct bgp_peer *peer, const struct bgp_table *const table)
{
  if (table) {
    /* If there is no node in the routing table return NULL. */
    if (table->top == NULL)
      return NULL;

    /* Lock the top node and return it. */
    bgp_lock_node (peer, table->top);
    return table->top;
  }
  
  return NULL;
}

/* Unlock current node and lock next node then return it. */
struct bgp_node *
bgp_route_next (struct bgp_peer *peer, struct bgp_node *node)
{
  struct bgp_node *next;
  struct bgp_node *start;

  /* Node may be deleted from bgp_unlock_node so we have to preserve
     next node's pointer. */

  if (node->l_left)
    {
      next = node->l_left;
      bgp_lock_node (peer, next);
      bgp_unlock_node (peer, node);
      return next;
    }
  if (node->l_right)
    {
      next = node->l_right;
      bgp_lock_node (peer, next);
      bgp_unlock_node (peer, node);
      return next;
    }

  start = node;
  while (node->parent)
    {
      if (node->parent->l_left == node && node->parent->l_right)
	{
	  next = node->parent->l_right;
	  bgp_lock_node (peer, next);
	  bgp_unlock_node (peer, start);
	  return next;
	}
      node = node->parent;
    }
  bgp_unlock_node (peer, start);
  return NULL;
}

/* Free route table. */
void bgp_table_free (struct bgp_table *rt)
{
  struct bgp_node *tmp_node;
  struct bgp_node *node;

  if (rt == NULL)
    return;

  node = rt->top;

  /* Bulk deletion of nodes remaining in this table.  This function is not
     called until workers have completed their dependency on this table.
     A final route_unlock_node() will not be called for these nodes. */
  while (node)
    {
      if (node->l_left)
	{
	  node = node->l_left;
	  continue;
	}

      if (node->l_right)
	{
	  node = node->l_right;
	  continue;
	}

      tmp_node = node;
      node = node->parent;

      tmp_node->table->count--;
      tmp_node->lock = 0;  /* to cause assert if unlocked after this */
      bgp_node_free (tmp_node);

      if (node != NULL)
	{
	  if (node->l_left == tmp_node)
	    node->l_left = NULL;
	  else
	    node->l_right = NULL;
	}
      else
	{
	  break;
	}
    }
 
  assert (rt->count == 0);

  free(rt);
  return;
}
