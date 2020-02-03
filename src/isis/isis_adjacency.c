/*
 * IS-IS Rout(e)ing protocol - isis_adjacency.c   
 *                             handling of IS-IS adjacencies
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

#include "pmacct.h"
#include "isis.h"

#include "hash.h"

#include "dict.h"
#include "thread.h"
#include "isis_constants.h"
#include "isis_common.h"
#include "isisd.h"
#include "isis_circuit.h"
#include "isis_adjacency.h"
#include "isis_misc.h"
#include "isis_dynhn.h"
#include "isis_pdu.h"

extern struct isis *isis;

static struct isis_adjacency *
adj_alloc (u_char * id)
{
  struct isis_adjacency *adj;

  adj = calloc(1, sizeof (struct isis_adjacency));
  memcpy (adj->sysid, id, ISIS_SYS_ID_LEN);

  return adj;
}

struct isis_adjacency *
isis_new_adj (u_char * id, u_char * snpa, int level,
	      struct isis_circuit *circuit)
{
  struct isis_adjacency *adj;

  adj = adj_alloc (id);		/* P2P kludge */

  if (adj == NULL)
    {
      Log(LOG_ERR, "ERROR ( %s/core/ISIS ): isis_new_adj() out of memory!\n", config.name);
      return NULL;
    }

  if (snpa) {
  memcpy (adj->snpa, snpa, 6);
  } else {
      memset (adj->snpa, ' ', 6);
  }

  adj->circuit = circuit;
  adj->level = level;
  adj->flaps = 0;
  adj->last_flap = time (NULL);

  return adj;
}

struct isis_adjacency *
isis_adj_lookup (u_char * sysid, struct pm_list *adjdb)
{
  struct isis_adjacency *adj;
  struct pm_listnode *node;

  for (PM_ALL_LIST_ELEMENTS_RO (adjdb, node, adj))
    if (memcmp (adj->sysid, sysid, ISIS_SYS_ID_LEN) == 0)
      return adj;

  return NULL;
}

struct isis_adjacency *
isis_adj_lookup_snpa (u_char * ssnpa, struct pm_list *adjdb)
{
  struct pm_listnode *node;
  struct isis_adjacency *adj;

  for (PM_ALL_LIST_ELEMENTS_RO (adjdb, node, adj))
    if (memcmp (adj->snpa, ssnpa, ETH_ALEN) == 0)
      return adj;

  return NULL;
}

void
isis_delete_adj (struct isis_adjacency *adj, struct pm_list *adjdb)
{
  if (!adj)
    return;
  /* When we recieve a NULL list, we will know its p2p. */
  if (adjdb)
    pm_listnode_delete (adjdb, adj);

  memset(&adj->expire, 0, sizeof(struct timeval));

  if (adj->ipv4_addrs)
    pm_list_delete (adj->ipv4_addrs);
  if (adj->ipv6_addrs)
    pm_list_delete (adj->ipv6_addrs);
  
  free(adj);
  return;
}

void
isis_adj_state_change (struct isis_adjacency *adj, enum isis_adj_state state,
		       const char *reason)
{
  int old_state;
  struct isis_circuit *circuit;

  old_state = adj->adj_state;
  adj->adj_state = state;

  circuit = adj->circuit;

  Log(LOG_DEBUG, "DEBUG ( %s/core/ISIS ): ISIS-Adj (%s): Adjacency state change %d->%d: %s\n",
		 config.name, circuit->area->area_tag, old_state, state, reason ? reason : "unspecified"); 

  if (state == ISIS_ADJ_UP)
    {
      /* update counter & timers for debugging purposes */
      adj->last_flap = time (NULL);
      adj->flaps++;

      /* 7.3.17 - going up on P2P -> send CSNP */
      send_csnp (circuit, 1);
      send_csnp (circuit, 2);
    }
  else if (state == ISIS_ADJ_DOWN)
    {				/* p2p interface */
      adj->circuit->u.p2p.neighbor = NULL;
      isis_delete_adj (adj, NULL);
    }
  return;
}

int
isis_adj_expire (struct isis_adjacency *adj)
{

  /*
   * Get the adjacency
   */
  assert (adj);
  memset(&adj->expire, 0, sizeof(struct timeval));

  /* trigger the adj expire event */
  isis_adj_state_change (adj, ISIS_ADJ_DOWN, "holding time expired");

  return 0;
}

void
isis_adjdb_iterate (struct pm_list *adjdb, void (*func) (struct isis_adjacency *,
						      void *), void *arg)
{
  struct pm_listnode *node, *nnode;
  struct isis_adjacency *adj;

  for (PM_ALL_LIST_ELEMENTS (adjdb, node, nnode, adj))
    (*func) (adj, arg);
}

void
isis_adj_build_neigh_list (struct pm_list *adjdb, struct pm_list *list)
{
  struct isis_adjacency *adj;
  struct pm_listnode *node;

  if (!list)
    {
      Log(LOG_WARNING, "WARN ( %s/core/ISIS ): isis_adj_build_neigh_list(): NULL list\n", config.name);
      return;
    }

  for (PM_ALL_LIST_ELEMENTS_RO (adjdb, node, adj))
    {
      if (!adj)
	{
	  Log(LOG_WARNING, "WARN ( %s/core/ISIS ): isis_adj_build_neigh_list(): NULL adj\n", config.name);
	  return;
	}

      if ((adj->adj_state == ISIS_ADJ_UP ||
	   adj->adj_state == ISIS_ADJ_INITIALIZING))
	pm_listnode_add (list, adj->snpa);
    }
  return;
}

void
isis_adj_build_up_list (struct pm_list *adjdb, struct pm_list *list)
{
  struct isis_adjacency *adj;
  struct pm_listnode *node;

  if (!list)
    {
      Log(LOG_WARNING, "WARN ( %s/core/ISIS ): isis_adj_build_up_list(): NULL list\n", config.name);
      return;
    }

  for (PM_ALL_LIST_ELEMENTS_RO (adjdb, node, adj))
    {
      if (!adj)
	{
	  Log(LOG_WARNING, "WARN ( %s/core/ISIS ): isis_adj_build_up_list(): NULL adj\n", config.name);
	  return;
	}

      if (adj->adj_state == ISIS_ADJ_UP)
	pm_listnode_add (list, adj);
    }

  return;
}
