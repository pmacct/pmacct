/*
 * IS-IS Rout(e)ing protocol                  - isis_spf.c
 *                                              The SPT algorithm
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define __ISIS_SPF_C

#include "pmacct.h"
#include "isis.h"

#include "linklist.h"
#include "prefix.h"
#include "hash.h"
#include "table.h"

#include "isis_constants.h"
#include "isis_common.h"
#include "dict.h"
#include "thread.h"
#include "isisd.h"
#include "isis_misc.h"
#include "isis_adjacency.h"
#include "isis_circuit.h"
#include "isis_tlv.h"
#include "isis_pdu.h"
#include "isis_lsp.h"
#include "isis_dynhn.h"
#include "isis_spf.h"
#include "isis_route.h"
#include "isis_csm.h"

extern struct isis *isis;
extern struct thread_master *master;
extern struct host host;

int isis_run_spf_l1 (struct thread *thread);
int isis_run_spf_l2 (struct thread *thread);

char *
vtype2string (enum vertextype vtype)
{
  switch (vtype)
    {
    case VTYPE_PSEUDO_IS:
      return "pseudo_IS";
      break;
    case VTYPE_PSEUDO_TE_IS:
      return "pseudo_TE-IS";
      break;
    case VTYPE_NONPSEUDO_IS:
      return "IS";
      break;
    case VTYPE_NONPSEUDO_TE_IS:
      return "TE-IS";
      break;
    case VTYPE_ES:
      return "ES";
      break;
    case VTYPE_IPREACH_INTERNAL:
      return "IP internal";
      break;
    case VTYPE_IPREACH_EXTERNAL:
      return "IP external";
      break;
    case VTYPE_IPREACH_TE:
      return "IP TE";
      break;
#ifdef ENABLE_IPV6
    case VTYPE_IP6REACH_INTERNAL:
      return "IP6 internal";
      break;
    case VTYPE_IP6REACH_EXTERNAL:
      return "IP6 external";
      break;
#endif /* ENABLE_IPV6 */
    default:
      return "UNKNOWN";
    }
  return NULL;                  /* Not reached */
}

char *
vid2string (struct isis_vertex *vertex, u_char * buff)
{
  switch (vertex->type)
    {
    case VTYPE_PSEUDO_IS:
    case VTYPE_PSEUDO_TE_IS:
      return rawlspid_print (vertex->N.id);
      break;
    case VTYPE_NONPSEUDO_IS:
    case VTYPE_NONPSEUDO_TE_IS:
    case VTYPE_ES:
      return sysid_print (vertex->N.id);
      break;
    case VTYPE_IPREACH_INTERNAL:
    case VTYPE_IPREACH_EXTERNAL:
    case VTYPE_IPREACH_TE:
#ifdef ENABLE_IPV6
    case VTYPE_IP6REACH_INTERNAL:
    case VTYPE_IP6REACH_EXTERNAL:
#endif /* ENABLE_IPV6 */
      isis_prefix2str ((struct isis_prefix *) &vertex->N.prefix, (char *) buff, BUFSIZ);
      break;
    default:
      return "UNKNOWN";
    }

  return (char *) buff;
}

/* 7.2.7 */
static void
remove_excess_adjs (struct list *adjs)
{
  struct listnode *node, *excess = NULL;
  struct isis_adjacency *adj, *candidate = NULL;
  int comp;

  for (ALL_LIST_ELEMENTS_RO (adjs, node, adj)) 
    {
      if (excess == NULL)
	excess = node;
      candidate = listgetdata (excess);

      if (candidate->sys_type < adj->sys_type)
	{
	  excess = node;
	  candidate = adj;
	  continue;
	}
      if (candidate->sys_type > adj->sys_type)
	continue;

      comp = memcmp (candidate->sysid, adj->sysid, ISIS_SYS_ID_LEN);
      if (comp > 0)
	{
	  excess = node;
	  candidate = adj;
	  continue;
	}
      if (comp < 0)
	continue;

      if (candidate->circuit->circuit_id > adj->circuit->circuit_id)
	{
	  excess = node;
	  candidate = adj;
	  continue;
	}

      if (candidate->circuit->circuit_id < adj->circuit->circuit_id)
	continue;

      comp = memcmp (candidate->snpa, adj->snpa, ETH_ALEN);
      if (comp > 0)
	{
	  excess = node;
	  candidate = adj;
	  continue;
	}
    }

  isis_list_delete_node (adjs, excess);

  return;
}

static struct isis_spftree *
isis_spftree_new ()
{
  struct isis_spftree *tree;

  tree = calloc(1, sizeof (struct isis_spftree));
  if (tree == NULL)
    {
      Log(LOG_ERR, "ERROR ( default/core/ISIS ): ISIS-Spf: isis_spftree_new Out of memory!\n");
      return NULL;
    }

  tree->tents = isis_list_new ();
  tree->paths = isis_list_new ();
  return tree;
}

static void
isis_vertex_del (struct isis_vertex *vertex)
{
  isis_list_delete (vertex->Adj_N);

  free(vertex);

  return;
}

#if 0 /* HT: Not used yet. */
static void
isis_spftree_del (struct isis_spftree *spftree)
{
  spftree->tents->del = (void (*)(void *)) isis_vertex_del;
  isis_list_delete (spftree->tents);

  spftree->paths->del = (void (*)(void *)) isis_vertex_del;
  isis_list_delete (spftree->paths);

  free(spftree);

  return;
}
#endif 

void
spftree_area_init (struct isis_area *area)
{
  if ((area->is_type & IS_LEVEL_1) && area->spftree[0] == NULL)
    {
      area->spftree[0] = isis_spftree_new ();
#ifdef ENABLE_IPV6
      area->spftree6[0] = isis_spftree_new ();
#endif

      /*    thread_add_timer (master, isis_run_spf_l1, area, 
         isis_jitter (PERIODIC_SPF_INTERVAL, 10)); */
    }

  if ((area->is_type & IS_LEVEL_2) && area->spftree[1] == NULL)
    {
      area->spftree[1] = isis_spftree_new ();
#ifdef ENABLE_IPV6
      area->spftree6[1] = isis_spftree_new ();
#endif
      /*    thread_add_timer (master, isis_run_spf_l2, area, 
         isis_jitter (PERIODIC_SPF_INTERVAL, 10)); */
    }

  return;
}

static struct isis_vertex *
isis_vertex_new (void *id, enum vertextype vtype)
{
  struct isis_vertex *vertex;

  vertex = calloc(1, sizeof (struct isis_vertex));
  if (vertex == NULL)
    {
      Log(LOG_ERR, "ERROR ( default/core/ISIS ): isis_vertex_new Out of memory!\n");
      return NULL;
    }

  vertex->type = vtype;
  switch (vtype)
    {
    case VTYPE_ES:
    case VTYPE_NONPSEUDO_IS:
    case VTYPE_NONPSEUDO_TE_IS:
      memcpy (vertex->N.id, (u_char *) id, ISIS_SYS_ID_LEN);
      break;
    case VTYPE_PSEUDO_IS:
    case VTYPE_PSEUDO_TE_IS:
      memcpy (vertex->N.id, (u_char *) id, ISIS_SYS_ID_LEN + 1);
      break;
    case VTYPE_IPREACH_INTERNAL:
    case VTYPE_IPREACH_EXTERNAL:
    case VTYPE_IPREACH_TE:
#ifdef ENABLE_IPV6
    case VTYPE_IP6REACH_INTERNAL:
    case VTYPE_IP6REACH_EXTERNAL:
#endif /* ENABLE_IPV6 */
      memcpy (&vertex->N.prefix, (struct isis_prefix *) id,
	      sizeof (struct isis_prefix));
      break;
    default:
      Log(LOG_ERR, "ERROR ( default/core/ISIS ): WTF!\n");
    }

  vertex->Adj_N = isis_list_new ();

  return vertex;
}

/*
 * Add this IS to the root of SPT
 */
static void
isis_spf_add_self (struct isis_spftree *spftree, struct isis_area *area,
		   int level)
{
  struct isis_vertex *vertex;
  struct isis_lsp *lsp;
  u_char lspid[ISIS_SYS_ID_LEN + 2];
  memcpy (lspid, isis->sysid, ISIS_SYS_ID_LEN);
  LSP_PSEUDO_ID (lspid) = 0;
  LSP_FRAGMENT (lspid) = 0;

  lsp = lsp_search (lspid, area->lspdb[level - 1]);

  if (lsp == NULL)
    Log(LOG_WARNING, "WARN ( default/core/ISIS ): ISIS-Spf: could not find own l%d LSP!\n", level);

  if (!area->oldmetric)
    vertex = isis_vertex_new (isis->sysid, VTYPE_NONPSEUDO_TE_IS);
  else 
    vertex = isis_vertex_new (isis->sysid, VTYPE_NONPSEUDO_IS);

  vertex->lsp = lsp;

  isis_listnode_add (spftree->paths, vertex);

  return;
}

static struct isis_vertex *
isis_find_vertex (struct list *list, void *id, enum vertextype vtype)
{
  struct listnode *node;
  struct isis_vertex *vertex;
  struct isis_prefix *p1, *p2;

  for (ALL_LIST_ELEMENTS_RO (list, node, vertex))
    {
      if (vertex->type != vtype)
	continue;
      switch (vtype)
	{
	case VTYPE_ES:
	case VTYPE_NONPSEUDO_IS:
	case VTYPE_NONPSEUDO_TE_IS:
	  if (memcmp ((u_char *) id, vertex->N.id, ISIS_SYS_ID_LEN) == 0)
	    return vertex;
	  break;
	case VTYPE_PSEUDO_IS:
	case VTYPE_PSEUDO_TE_IS:
	  if (memcmp ((u_char *) id, vertex->N.id, ISIS_SYS_ID_LEN + 1) == 0)
	    return vertex;
	  break;
	case VTYPE_IPREACH_INTERNAL:
	case VTYPE_IPREACH_EXTERNAL:
	case VTYPE_IPREACH_TE:
#ifdef ENABLE_IPV6
	case VTYPE_IP6REACH_INTERNAL:
	case VTYPE_IP6REACH_EXTERNAL:
#endif /* ENABLE_IPV6 */
	  p1 = (struct isis_prefix *) id;
	  p2 = (struct isis_prefix *) &vertex->N.id;
	  if (p1->family == p2->family && p1->prefixlen == p2->prefixlen &&
	      memcmp (&p1->u.prefix, &p2->u.prefix,
		      PSIZE (p1->prefixlen)) == 0)
	    return vertex;
	  break;
	}
    }

  return NULL;
}

/*
 * Add a vertex to TENT sorted by cost and by vertextype on tie break situation
 */
static struct isis_vertex *
isis_spf_add2tent (struct isis_spftree *spftree, enum vertextype vtype,
		   void *id, struct isis_adjacency *adj, u_int32_t cost,
		   int depth, int family)
{
  struct isis_vertex *vertex, *v;
  struct listnode *node;

  u_char buff[BUFSIZ];

  vertex = isis_vertex_new (id, vtype);
  vertex->d_N = cost;
  vertex->depth = depth;

  if (adj)
    isis_listnode_add (vertex->Adj_N, adj);

  if (config.nfacctd_isis_msglog) 
    Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Spf: add to TENT  %s %s depth %d dist %d\n",
              vtype2string (vertex->type), vid2string (vertex, buff),
              vertex->depth, vertex->d_N);

  isis_listnode_add (spftree->tents, vertex);
  if (isis_list_isempty (spftree->tents))
    {
      isis_listnode_add (spftree->tents, vertex);
      return vertex;
    }
  
  /* XXX: This cant use the standard ALL_LIST_ELEMENT macro */
  for (node = listhead (spftree->tents); node; node = listnextnode (node))
    {
      v = listgetdata (node);
      if (v->d_N > vertex->d_N)
	{
	  isis_list_add_node_prev (spftree->tents, node, vertex);
	  break;
	}
      else if (v->d_N == vertex->d_N)
	{
	  /*  Tie break, add according to type */
	  while (v && v->d_N == vertex->d_N && v->type > vertex->type)
	    {
	      if (v->type > vertex->type)
		{
		  break;
		}
              /* XXX: this seems dubious, node is the loop iterator */
	      node = listnextnode (node);
	      (node) ? (v = listgetdata (node)) : (v = NULL);
	    }
	  isis_list_add_node_prev (spftree->tents, node, vertex);
	  break;
	}
      else if (node->next == NULL)
	{
	  isis_list_add_node_next (spftree->tents, node, vertex);
	  break;
	}
    }
  return vertex;
}

static struct isis_vertex *
isis_spf_add_local (struct isis_spftree *spftree, enum vertextype vtype,
		    void *id, struct isis_adjacency *adj, u_int32_t cost,
		    int family)
{
  struct isis_vertex *vertex;

  vertex = isis_find_vertex (spftree->tents, id, vtype);

  if (vertex)
    {
      /* C.2.5   c) */
      if (vertex->d_N == cost)
	{
	  if (adj)
	    isis_listnode_add (vertex->Adj_N, adj);
	  /*       d) */
	  if (listcount (vertex->Adj_N) > ISIS_MAX_PATH_SPLITS)
	    remove_excess_adjs (vertex->Adj_N);
	}
      /*         f) */
      else if (vertex->d_N > cost)
	{
	  isis_listnode_delete (spftree->tents, vertex);
	  goto add2tent;
	}
      /*       e) do nothing */
      return vertex;
    }

add2tent:
  return isis_spf_add2tent (spftree, vtype, id, adj, cost, 1, family);
}

static void
process_N (struct isis_spftree *spftree, enum vertextype vtype, void *id,
	   u_int16_t dist, u_int16_t depth, struct isis_adjacency *adj,
	   int family)
{
  struct isis_vertex *vertex;

  /* C.2.6 b)    */
  if (dist > MAX_PATH_METRIC)
    return;
  /*       c)    */
  vertex = isis_find_vertex (spftree->paths, id, vtype);
  if (vertex)
    {
      assert (dist >= vertex->d_N);
      return;
    }

  vertex = isis_find_vertex (spftree->tents, id, vtype);
  /*       d)    */
  if (vertex)
    {
      /*        1) */
      if (vertex->d_N == dist)
	{
	  if (adj)
	    isis_listnode_add (vertex->Adj_N, adj);
	  /*      2) */
	  if (listcount (vertex->Adj_N) > ISIS_MAX_PATH_SPLITS)
	    remove_excess_adjs (vertex->Adj_N);
	  /*      3) */
	  return;
	}
      else if (vertex->d_N < dist)
	{
	  return;
	  /*      4) */
	}
      else
	{
	  isis_listnode_delete (spftree->tents, vertex);
	}
    }

  isis_spf_add2tent (spftree, vtype, id, adj, dist, depth, family);
  return;
}

/*
 * C.2.6 Step 1
 */
static int
isis_spf_process_lsp (struct isis_spftree *spftree, struct isis_lsp *lsp,
		      uint32_t cost, uint16_t depth, int family)
{
  struct listnode *node, *fragnode = NULL;
  u_int16_t dist;
  struct is_neigh *is_neigh;
  struct te_is_neigh *te_is_neigh;
  struct ipv4_reachability *ipreach;
  struct te_ipv4_reachability *te_ipv4_reach;
  enum vertextype vtype;
  struct isis_prefix prefix;
#ifdef ENABLE_IPV6
  struct ipv6_reachability *ip6reach;
#endif /* ENABLE_IPV6 */

  if (!lsp->adj)
    return ISIS_WARNING;

  if (lsp->tlv_data.nlpids == NULL || !speaks (lsp->tlv_data.nlpids, family))
    return ISIS_OK;

lspfragloop:
  if (lsp->lsp_header->seq_num == 0)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): isis_spf_process_lsp(): lsp with 0 seq_num - do not process\n");
      return ISIS_WARNING;
    }

  if (!ISIS_MASK_LSP_OL_BIT (lsp->lsp_header->lsp_bits))
    {
      if (lsp->tlv_data.is_neighs)
	{
          for (ALL_LIST_ELEMENTS_RO (lsp->tlv_data.is_neighs, node, is_neigh))
	    {
	      /* C.2.6 a) */
	      /* Two way connectivity */
	      if (!memcmp (is_neigh->neigh_id, isis->sysid, ISIS_SYS_ID_LEN))
		continue;
	      dist = cost + is_neigh->metrics.metric_default;
	      vtype = LSP_PSEUDO_ID (is_neigh->neigh_id) ? VTYPE_PSEUDO_IS
		: VTYPE_NONPSEUDO_IS;
	      process_N (spftree, vtype, (void *) is_neigh->neigh_id, dist,
			 depth + 1, lsp->adj, family);
	    }
	}
      if (lsp->tlv_data.te_is_neighs)
	{
	  for (ALL_LIST_ELEMENTS_RO (lsp->tlv_data.te_is_neighs, node,
				     te_is_neigh))
	    {
	      uint32_t metric;
	      if (!memcmp (te_is_neigh->neigh_id, isis->sysid, ISIS_SYS_ID_LEN))
		continue;
	      memcpy (&metric, te_is_neigh->te_metric, 3);
	      dist = cost + ntohl (metric << 8);
	      vtype = LSP_PSEUDO_ID (te_is_neigh->neigh_id) ? VTYPE_PSEUDO_TE_IS
		: VTYPE_NONPSEUDO_TE_IS;
	      process_N (spftree, vtype, (void *) te_is_neigh->neigh_id, dist,
			 depth + 1, lsp->adj, family);
	    }
	}
      if (family == AF_INET && lsp->tlv_data.ipv4_int_reachs)
	{
	  prefix.family = AF_INET;
          for (ALL_LIST_ELEMENTS_RO (lsp->tlv_data.ipv4_int_reachs, 
                                     node, ipreach))
	    {
	      dist = cost + ipreach->metrics.metric_default;
	      vtype = VTYPE_IPREACH_INTERNAL;
	      prefix.u.prefix4 = ipreach->prefix;
	      prefix.prefixlen = isis_ip_masklen (ipreach->mask);
	      process_N (spftree, vtype, (void *) &prefix, dist, depth + 1,
			 lsp->adj, family);
	    }
	}

      if (family == AF_INET && lsp->tlv_data.ipv4_ext_reachs)
	{
	  prefix.family = AF_INET;
          for (ALL_LIST_ELEMENTS_RO (lsp->tlv_data.ipv4_ext_reachs,
                                     node, ipreach))
	    {
	      dist = cost + ipreach->metrics.metric_default;
	      vtype = VTYPE_IPREACH_EXTERNAL;

              /* Set advertising router to the first IP address */
              if (lsp->tlv_data.ipv4_addrs) {
                memcpy(&prefix.adv_router, isis_listnode_head(lsp->tlv_data.ipv4_addrs), sizeof(struct in_addr));
              }
	      prefix.u.prefix4 = ipreach->prefix;
	      prefix.prefixlen = isis_ip_masklen (ipreach->mask);
	      process_N (spftree, vtype, (void *) &prefix, dist, depth + 1,
			 lsp->adj, family);
	    }
	}
      if (family == AF_INET && lsp->tlv_data.te_ipv4_reachs)
	{
	  prefix.family = AF_INET;
	  for (ALL_LIST_ELEMENTS_RO (lsp->tlv_data.te_ipv4_reachs,
				     node, te_ipv4_reach))
	    {
	      dist = cost + ntohl (te_ipv4_reach->te_metric);
	      vtype = VTYPE_IPREACH_TE;

	      /* Set advertising router to the first IP address */
	      if (lsp->tlv_data.ipv4_addrs) {
		memcpy(&prefix.adv_router, isis_listnode_head(lsp->tlv_data.ipv4_addrs), sizeof(struct in_addr));
	      }
	      prefix.u.prefix4 = newprefix2inaddr (&te_ipv4_reach->prefix_start,
						   te_ipv4_reach->control);
	      prefix.prefixlen = (te_ipv4_reach->control & 0x3F);
	      process_N (spftree, vtype, (void *) &prefix, dist, depth + 1,
			 lsp->adj, family);
	    }
	}
#ifdef ENABLE_IPV6
      if (family == AF_INET6 && lsp->tlv_data.ipv6_reachs)
	{
	  prefix.family = AF_INET6;
          for (ALL_LIST_ELEMENTS_RO (lsp->tlv_data.ipv6_reachs, 
                                     node, ip6reach))
	    {
	      dist = cost + ip6reach->metric;
	      vtype = (ip6reach->control_info & CTRL_INFO_DISTRIBUTION) ?
		VTYPE_IP6REACH_EXTERNAL : VTYPE_IP6REACH_INTERNAL;

	      prefix.prefixlen = ip6reach->prefix_len;
	      memcpy (&prefix.u.prefix6.s6_addr, ip6reach->prefix,
		      PSIZE (ip6reach->prefix_len));
	      process_N (spftree, vtype, (void *) &prefix, dist, depth + 1,
			 lsp->adj, family);
	    }
	}
#endif /* ENABLE_IPV6 */
    }

  if (fragnode == NULL)
    fragnode = listhead (lsp->lspu.frags);
  else
    fragnode = listnextnode (fragnode);

  if (fragnode)
    {
      lsp = listgetdata (fragnode);
      goto lspfragloop;
    }

  return ISIS_OK;
}

static int
isis_spf_process_pseudo_lsp (struct isis_spftree *spftree,
			     struct isis_lsp *lsp, uint16_t cost,
			     uint16_t depth, int family)
{
  struct listnode *node, *fragnode = NULL;
  struct is_neigh *is_neigh;
  struct te_is_neigh *te_is_neigh;
  enum vertextype vtype;

pseudofragloop:

  if (lsp->lsp_header->seq_num == 0)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): isis_spf_process_pseudo_lsp(): lsp with 0 seq_num - do not process\n");
      return ISIS_WARNING;
    }

  if (lsp->tlv_data.is_neighs)
    for (ALL_LIST_ELEMENTS_RO (lsp->tlv_data.is_neighs, node, is_neigh))
      {
	vtype = LSP_PSEUDO_ID (is_neigh->neigh_id) ? VTYPE_PSEUDO_IS
	  : VTYPE_NONPSEUDO_IS;
	/* Two way connectivity */
	if (!memcmp (is_neigh->neigh_id, isis->sysid, ISIS_SYS_ID_LEN))
	  continue;
	if (isis_find_vertex
	    (spftree->tents, (void *) is_neigh->neigh_id, vtype) == NULL
	    && isis_find_vertex (spftree->paths, (void *) is_neigh->neigh_id,
			       vtype) == NULL)
	  {
	    /* C.2.5 i) */
	    isis_spf_add2tent (spftree, vtype, is_neigh->neigh_id, lsp->adj,
			     cost, depth, family);
	  }
      }
  if (lsp->tlv_data.te_is_neighs)
    for (ALL_LIST_ELEMENTS_RO (lsp->tlv_data.te_is_neighs, node, te_is_neigh))
      {
	vtype = LSP_PSEUDO_ID (te_is_neigh->neigh_id) ? VTYPE_PSEUDO_TE_IS
	  : VTYPE_NONPSEUDO_TE_IS;
	/* Two way connectivity */
	if (!memcmp (te_is_neigh->neigh_id, isis->sysid, ISIS_SYS_ID_LEN))
	  continue;
	if (isis_find_vertex
	    (spftree->tents, (void *) te_is_neigh->neigh_id, vtype) == NULL
	    && isis_find_vertex (spftree->paths, (void *) te_is_neigh->neigh_id,
				 vtype) == NULL)
	  {
	    /* C.2.5 i) */
	    isis_spf_add2tent (spftree, vtype, te_is_neigh->neigh_id, lsp->adj,
			       cost, depth, family);
	  }
      }

  if (fragnode == NULL)
    fragnode = listhead (lsp->lspu.frags);
  else
    fragnode = listnextnode (fragnode);

  if (fragnode)
    {
      lsp = listgetdata (fragnode);
      goto pseudofragloop;
    }

  return ISIS_OK;
}

static int
isis_spf_preload_tent (struct isis_spftree *spftree,
		       struct isis_area *area, int level, int family)
{
  struct isis_vertex *vertex;
  struct isis_circuit *circuit;
  struct listnode *cnode, *anode, *ipnode;
  struct isis_adjacency *adj;
  struct isis_lsp *lsp;
  struct list *adj_list;
  struct list *adjdb;
  struct prefix_ipv4 *ipv4;
  struct isis_prefix prefix;
  int retval = ISIS_OK;
  u_char lsp_id[ISIS_SYS_ID_LEN + 2];
#ifdef ENABLE_IPV6
  struct prefix_ipv6 *ipv6;
#endif /* ENABLE_IPV6 */

  for (ALL_LIST_ELEMENTS_RO (area->circuit_list, cnode, circuit))
    {
      if (circuit->state != C_STATE_UP)
	continue;
      if (!(circuit->circuit_is_type & level))
	continue;
      if (family == AF_INET && !circuit->ip_router)
	continue;
#ifdef ENABLE_IPV6
      if (family == AF_INET6 && !circuit->ipv6_router)
	continue;
#endif /* ENABLE_IPV6 */
      /* 
       * Add IP(v6) addresses of this circuit
       */
      if (family == AF_INET)
	{
	  prefix.family = AF_INET;
          for (ALL_LIST_ELEMENTS_RO (circuit->ip_addrs, ipnode, ipv4))
	    {
	      prefix.u.prefix4 = ipv4->prefix;
	      prefix.prefixlen = ipv4->prefixlen;
	      isis_spf_add_local (spftree, VTYPE_IPREACH_INTERNAL, &prefix,
				  NULL, 0, family);
	    }
	}
#ifdef ENABLE_IPV6
      if (family == AF_INET6)
	{
	  prefix.family = AF_INET6;
	  for (ALL_LIST_ELEMENTS_RO (circuit->ipv6_non_link, ipnode, ipv6))
	    {
	      prefix.prefixlen = ipv6->prefixlen;
	      prefix.u.prefix6 = ipv6->prefix;
	      isis_spf_add_local (spftree, VTYPE_IP6REACH_INTERNAL,
				  &prefix, NULL, 0, family);
	    }
	}
#endif /* ENABLE_IPV6 */
      if (circuit->circ_type == CIRCUIT_T_P2P)
	{
	  adj = circuit->u.p2p.neighbor;
	  if (!adj)
	    continue;
	  switch (adj->sys_type)
	    {
	    case ISIS_SYSTYPE_ES:
	      isis_spf_add_local (spftree, VTYPE_ES, adj->sysid, adj,
				  circuit->te_metric[level - 1], family);
	      break;
	    case ISIS_SYSTYPE_IS:
	    case ISIS_SYSTYPE_L1_IS:
	    case ISIS_SYSTYPE_L2_IS:
	      if (speaks (&adj->nlpids, family))
		isis_spf_add_local (spftree, VTYPE_NONPSEUDO_IS, adj->sysid,
				    adj, circuit->te_metric[level - 1],
				    family);
	      break;
	    case ISIS_SYSTYPE_UNKNOWN:
	    default:
	      Log(LOG_WARNING, "WARN ( default/core/ISIS ): isis_spf_preload_tent unknow adj type\n");
	      break;
	    }
	}
      else
	{
	  Log(LOG_WARNING, "WARN ( default/core/ISIS ): isis_spf_preload_tent unsupported media\n");
	  retval = ISIS_WARNING;
	}
    }

  return retval;
}

/*
 * The parent(s) for vertex is set when added to TENT list
 * now we just put the child pointer(s) in place
 */
static void
add_to_paths (struct isis_spftree *spftree, struct isis_vertex *vertex,
	      struct isis_area *area, int level)
{
  isis_listnode_add (spftree->paths, vertex);

  if (vertex->type > VTYPE_ES)
    {
      if (listcount (vertex->Adj_N) > 0) {
	isis_route_create ((struct isis_prefix *) &vertex->N.prefix, vertex->d_N,
			   vertex->depth, vertex->Adj_N, area, level);

	if (config.nfacctd_isis_msglog) {
	  u_char prefix[BUFSIZ];

	  isis_prefix2str (&vertex->N.prefix, prefix, BUFSIZ);
	  if (config.nfacctd_isis_msglog)
	    Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Spf (tag: %s, level: %u): route installed: %s\n", area->area_tag, area->is_type, prefix);
	}
      }
      else {
	if (config.nfacctd_isis_msglog) {
	  u_char prefix[BUFSIZ];

	  isis_prefix2str (&vertex->N.prefix, prefix, BUFSIZ);
	  if (config.nfacctd_isis_msglog)
	    Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Spf (tag: %s, level: %u): no adjacencies do not install route: %s\n", area->area_tag, area->is_type, prefix);
	}
      }
    }

  return;
}

static void
init_spt (struct isis_spftree *spftree)
{
  spftree->tents->del = spftree->paths->del = (void (*)(void *)) isis_vertex_del;
  isis_list_delete_all_node (spftree->tents);
  isis_list_delete_all_node (spftree->paths);
  spftree->tents->del = spftree->paths->del = NULL;

  return;
}

int
isis_run_spf (struct isis_area *area, int level, int family)
{
  int retval = ISIS_OK;
  struct listnode *node;
  struct isis_vertex *vertex;
  struct isis_spftree *spftree = NULL;
  u_char lsp_id[ISIS_SYS_ID_LEN + 2];
  struct isis_lsp *lsp;
  struct route_table *table = NULL;
  struct route_node *rode;
  struct isis_route_info *rinfo;

  if (family == AF_INET)
    spftree = area->spftree[level - 1];
#ifdef ENABLE_IPV6
  else if (family == AF_INET6)
    spftree = area->spftree6[level - 1];
#endif

  assert (spftree);

  /* Make all routes in current route table inactive. */
  if (family == AF_INET)
    table = area->route_table[level - 1];
#ifdef ENABLE_IPV6
  else if (family == AF_INET6)
    table = area->route_table6[level - 1];
#endif

  for (rode = route_top (table); rode; rode = route_next (rode))
    {
      if (rode->info == NULL)
        continue;
      rinfo = rode->info;

      UNSET_FLAG (rinfo->flag, ISIS_ROUTE_FLAG_ACTIVE);
    }

  /*
   * C.2.5 Step 0
   */
  init_spt (spftree);
  /*              a) */
  isis_spf_add_self (spftree, area, level);
  /*              b) */
  retval = isis_spf_preload_tent (spftree, area, level, family);

  /*
   * C.2.7 Step 2
   */
  if (listcount (spftree->tents) == 0)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): ISIS-Spf: TENT is empty\n");
      goto out;
    }

  while (listcount (spftree->tents) > 0)
    {
      node = listhead (spftree->tents);
      vertex = listgetdata (node);

      /* Remove from tent list */
      isis_list_delete_node (spftree->tents, node);

      if (isis_find_vertex (spftree->paths, vertex->N.id, vertex->type))
	continue;

      add_to_paths (spftree, vertex, area, level);
      if (vertex->type == VTYPE_PSEUDO_IS ||
	  vertex->type == VTYPE_NONPSEUDO_IS ||
	  vertex->type == VTYPE_PSEUDO_TE_IS ||
	  vertex->type == VTYPE_NONPSEUDO_TE_IS)
	{
	  memcpy (lsp_id, vertex->N.id, ISIS_SYS_ID_LEN + 1);
	  LSP_FRAGMENT (lsp_id) = 0;
	  lsp = lsp_search (lsp_id, area->lspdb[level - 1]);
	  if (lsp)
	    {
	      if (LSP_PSEUDO_ID (lsp_id))
		{
		  isis_spf_process_pseudo_lsp (spftree, lsp, vertex->d_N,
					       vertex->depth, family);

		}
	      else
		{
		  isis_spf_process_lsp (spftree, lsp, vertex->d_N,
					vertex->depth, family);
		}
	    }
	  else
	    {
	      Log(LOG_WARNING, "WARN ( default/core/ISIS ): ISIS-Spf: No LSP found for %s\n",
			 rawlspid_print (lsp_id));
	    }
	}
    }

out:
  // thread_add_event (master, isis_route_validate, area, 0);
  spftree->lastrun = time (NULL);
  spftree->pending = 0;

  Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Spf (tag: %s, level: %u): SPF algorithm run\n", area->area_tag, area->is_type);

  return retval;
}

int
isis_run_spf_l1 (struct thread *thread)
{
  struct isis_area *area;
  int retval = ISIS_OK;

  area = THREAD_ARG (thread);
  assert (area);

  area->spftree[0]->t_spf = NULL;

  if (!(area->is_type & IS_LEVEL_1))
    {
      Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-SPF (%s) area does not share level\n",
		   area->area_tag);
      return ISIS_WARNING;
    }

  Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Spf (%s) L1 SPF needed, periodic SPF\n", area->area_tag);

  if (area->ip_circuits)
    retval = isis_run_spf (area, 1, AF_INET);

  THREAD_TIMER_ON (master, area->spftree[0]->t_spf, isis_run_spf_l1, area,
		   isis_jitter (PERIODIC_SPF_INTERVAL, 10));

  return retval;
}

int
isis_run_spf_l2 (struct thread *thread)
{
  struct isis_area *area;
  int retval = ISIS_OK;

  area = THREAD_ARG (thread);
  assert (area);

  area->spftree[1]->t_spf = NULL;

  if (!(area->is_type & IS_LEVEL_2))
    {
      Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-SPF (%s) area does not share level\n", area->area_tag);
      return ISIS_WARNING;
    }

  Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Spf (%s) L2 SPF needed, periodic SPF\n", area->area_tag);

  if (area->ip_circuits)
    retval = isis_run_spf (area, 2, AF_INET);

  THREAD_TIMER_ON (master, area->spftree[1]->t_spf, isis_run_spf_l2, area,
		   isis_jitter (PERIODIC_SPF_INTERVAL, 10));

  return retval;
}

int
isis_spf_schedule (struct isis_area *area, int level)
{
  int retval = ISIS_OK;
  struct isis_spftree *spftree = area->spftree[level - 1];
  time_t diff, now = time (NULL);

  if (spftree->pending)
    return retval;

  diff = now - spftree->lastrun;

  /* FIXME: let's wait a minute before doing the SPF */
  if (now - isis->uptime < 60 || isis->uptime == 0)
    {
      if (level == 1)
	THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf_l1, area, 60);
      else
	THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf_l2, area, 60);

      spftree->pending = 1;
      return retval;
    }

  THREAD_TIMER_OFF (spftree->t_spf);

  if (diff < MINIMUM_SPF_INTERVAL)
    {
      if (level == 1)
	THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf_l1, area,
			 MINIMUM_SPF_INTERVAL - diff);
      else
	THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf_l2, area,
			 MINIMUM_SPF_INTERVAL - diff);

      spftree->pending = 1;
    }
  else
    {
      spftree->pending = 0;
      retval = isis_run_spf (area, level, AF_INET);
      if (level == 1)
	THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf_l1, area,
			 isis_jitter (PERIODIC_SPF_INTERVAL, 10));
      else
	THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf_l2, area,
			 isis_jitter (PERIODIC_SPF_INTERVAL, 10));
    }

  return retval;
}

#ifdef ENABLE_IPV6
static int
isis_run_spf6_l1 (struct thread *thread)
{
  struct isis_area *area;
  int retval = ISIS_OK;

  area = THREAD_ARG (thread);
  assert (area);

  area->spftree6[0]->t_spf = NULL;

  if (!(area->is_type & IS_LEVEL_1))
    {
      Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-SPF (%s) area does not share level\n", area->area_tag);
      return ISIS_WARNING;
    }

  Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Spf (%s) L1 SPF needed, periodic SPF\n", area->area_tag);

  if (area->ipv6_circuits)
    retval = isis_run_spf (area, 1, AF_INET6);

  THREAD_TIMER_ON (master, area->spftree6[0]->t_spf, isis_run_spf6_l1, area,
		   isis_jitter (PERIODIC_SPF_INTERVAL, 10));

  return retval;
}

static int
isis_run_spf6_l2 (struct thread *thread)
{
  struct isis_area *area;
  int retval = ISIS_OK;

  area = THREAD_ARG (thread);
  assert (area);

  area->spftree6[1]->t_spf = NULL;

  if (!(area->is_type & IS_LEVEL_2))
    {
      Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-SPF (%s) area does not share level\n", area->area_tag);
      return ISIS_WARNING;
    }

  Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): ISIS-Spf (%s) L2 SPF needed, periodic SPF\n", area->area_tag);

  if (area->ipv6_circuits)
    retval = isis_run_spf (area, 2, AF_INET6);

  THREAD_TIMER_ON (master, area->spftree6[1]->t_spf, isis_run_spf6_l2, area,
		   isis_jitter (PERIODIC_SPF_INTERVAL, 10));

  return retval;
}

int
isis_spf_schedule6 (struct isis_area *area, int level)
{
  int retval = ISIS_OK;
  struct isis_spftree *spftree = area->spftree6[level - 1];
  time_t diff, now = time (NULL);

  if (spftree->pending)
    return retval;

  diff = now - spftree->lastrun;

  /* FIXME: let's wait a minute before doing the SPF */
  if (now - isis->uptime < 60 || isis->uptime == 0)
    {
      if (level == 1)
	THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf6_l1, area, 60);
      else
	THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf6_l2, area, 60);

      spftree->pending = 1;
      return retval;
    }
  
  THREAD_TIMER_OFF (spftree->t_spf);

  if (diff < MINIMUM_SPF_INTERVAL)
    {
      if (level == 1)
	THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf6_l1, area,
			 MINIMUM_SPF_INTERVAL - diff);
      else
	THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf6_l2, area,
			 MINIMUM_SPF_INTERVAL - diff);

      spftree->pending = 1;
    }
  else
    {
      spftree->pending = 0;
      retval = isis_run_spf (area, level, AF_INET6);

      if (level == 1)
	THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf6_l1, area,
			 isis_jitter (PERIODIC_SPF_INTERVAL, 10));
      else
	THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf6_l2, area,
			 isis_jitter (PERIODIC_SPF_INTERVAL, 10));
    }

  return retval;
}
#endif
