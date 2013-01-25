/*
 * IS-IS Rout(e)ing protocol - isisd.c
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

#define __ISISD_C

#include "pmacct.h"
#include "isis.h"

#include "hash.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"

#include "dict.h"
#include "thread.h"
#include "isis_constants.h"
#include "isis_common.h"
#include "isis_circuit.h"
#include "isis_flags.h"
#include "isisd.h"
#include "isis_misc.h"
#include "isis_tlv.h"
#include "isis_lsp.h"
#include "isis_constants.h"
#include "isis_adjacency.h"
#include "isis_dynhn.h"
#include "isis_pdu.h"
#include "isis_spf.h"
#include "isis_route.h"
#include "isis_csm.h"

struct isis *isis = NULL;
extern struct thread_master *master;

/*
 * Prototypes.
 */
void isis_new(unsigned long);
struct isis_area *isis_area_create(void);
int isis_area_get(const char *);
int isis_area_destroy(const char *);
int area_net_title(struct isis_area *, const u_char *);
int area_clear_net_title(struct isis_area *, const u_char *);

void
isis_new (unsigned long process_id)
{
  isis = calloc(1, sizeof (struct isis));
  /*
   * Default values
   */
  isis->max_area_addrs = 3;

  isis->process_id = process_id;
  isis->area_list = isis_list_new ();
  isis->init_circ_list = isis_list_new ();
  isis->uptime = time (NULL);
  isis->nexthops = isis_list_new ();
#ifdef ENABLE_IPV6
  isis->nexthops6 = isis_list_new ();
#endif /* ENABLE_IPV6 */
  /*
   * uncomment the next line for full debugs
   */
  /* isis->debugs = 0xFFFF; */
}

void
isis_init ()
{
  isis_new (0);
}

struct isis_area *
isis_area_create ()
{
  struct isis_area *area;

  area = calloc(1, sizeof (struct isis_area));

  /*
   * The first instance is level-1-2 rest are level-1, unless otherwise
   * configured
   */
  if (listcount (isis->area_list) > 0)
    area->is_type = IS_LEVEL_1;
  else
    area->is_type = IS_LEVEL_1_AND_2;
  /*
   * intialize the databases
   */
  area->lspdb[0] = lsp_db_init ();
  area->lspdb[1] = lsp_db_init ();

  spftree_area_init (area);
  area->route_table[0] = route_table_init ();
  area->route_table[1] = route_table_init ();
#ifdef ENABLE_IPV6
  area->route_table6[0] = route_table_init ();
  area->route_table6[1] = route_table_init ();
#endif /* ENABLE_IPV6 */
  area->circuit_list = isis_list_new ();
  area->area_addrs = isis_list_new ();
  flags_initialize (&area->flags);
  /*
   * Default values
   */
  area->max_lsp_lifetime[0] = MAX_AGE;	/* 1200 */
  area->max_lsp_lifetime[1] = MAX_AGE;	/* 1200 */
  area->lsp_gen_interval[0] = LSP_GEN_INTERVAL_DEFAULT;
  area->lsp_gen_interval[1] = LSP_GEN_INTERVAL_DEFAULT;
  area->lsp_refresh[0] = MAX_LSP_GEN_INTERVAL;	/* 900 */
  area->lsp_refresh[1] = MAX_LSP_GEN_INTERVAL;	/* 900 */
  area->min_spf_interval[0] = MINIMUM_SPF_INTERVAL;
  area->min_spf_interval[1] = MINIMUM_SPF_INTERVAL;
  area->dynhostname = 1;
  area->oldmetric = 1;
  area->lsp_frag_threshold = 90;

  /* FIXME: Think of a better way... */
  area->min_bcast_mtu = 1497;

  return area;
}

struct isis_area *
isis_area_lookup (const char *area_tag)
{
  struct isis_area *area;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    if ((area->area_tag == NULL && area_tag == NULL) ||
	(area->area_tag && area_tag
	 && strcmp (area->area_tag, area_tag) == 0))
    return area;

  return NULL;
}

int
isis_area_get (const char *area_tag)
{
  struct isis_area *area;

  area = isis_area_lookup (area_tag);

  if (area)
    {
      return FALSE;
    }

  area = isis_area_create ();
  area->area_tag = strdup (area_tag);
  isis_listnode_add (isis->area_list, area);

  Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): New IS-IS area instance %s\n", area->area_tag);

  return FALSE;
}

int
isis_area_destroy (const char *area_tag)
{
  struct isis_area *area;
  struct listnode *node, *nnode;
  struct isis_circuit *circuit;

  area = isis_area_lookup (area_tag);

  if (area == NULL)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): Can't find ISIS instance %s\n", area_tag);
      return TRUE;
    }

  if (area->circuit_list)
    {
      for (ALL_LIST_ELEMENTS (area->circuit_list, node, nnode, circuit))
	{
	  /* The fact that it's in circuit_list means that it was configured */
	  isis_csm_state_change (ISIS_DISABLE, circuit, area);
	  isis_circuit_down (circuit);
	  isis_circuit_deconfigure (circuit, area);
	}
      
      isis_list_delete (area->circuit_list);
    }
  isis_listnode_delete (isis->area_list, area);

  if (area->t_remove_aged)
    thread_cancel (area->t_remove_aged);

  THREAD_TIMER_OFF (area->spftree[0]->t_spf);
  THREAD_TIMER_OFF (area->spftree[1]->t_spf);

  free(area);

  isis->sysid_set=0;

  return FALSE;
}

int
area_net_title (struct isis_area *area, const u_char *net_title)
{
  struct area_addr *addr;
  struct area_addr *addrp;
  struct listnode *node;

  u_char buff[255];

  if (!area)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): Can't find ISIS instance\n");
      return TRUE;
    }

  /* We check that we are not over the maximal number of addresses */
  if (listcount (area->area_addrs) >= isis->max_area_addrs)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): Maximum of area addresses (%d) already reached\n",
	       isis->max_area_addrs);
      return TRUE;
    }

  addr = calloc(1, sizeof (struct area_addr));
  addr->addr_len = dotformat2buff (buff, net_title);
  memcpy (addr->area_addr, buff, addr->addr_len);
  if (addr->addr_len < 8 || addr->addr_len > 20)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): area address must be at least 8..20 octets long (%d)\n",
		 addr->addr_len);
      free(addr);
      return TRUE;
    }

  if (isis->sysid_set == 0)
    {
      /*
       * First area address - get the SystemID for this router
       */
      memcpy (isis->sysid, GETSYSID (addr, ISIS_SYS_ID_LEN), ISIS_SYS_ID_LEN);
      isis->sysid_set = 1;
      Log(LOG_DEBUG, "DEBUG ( default/core/ISIS ): Router has SystemID %s\n", sysid_print (isis->sysid));
    }
  else
    {
      /*
       * Check that the SystemID portions match
       */
      if (memcmp (isis->sysid, GETSYSID (addr, ISIS_SYS_ID_LEN),
		  ISIS_SYS_ID_LEN))
	{
	  Log(LOG_WARNING, "WARN ( default/core/ISIS ): System ID must not change when defining additional area addresses\n");
	  free(addr);
	  return TRUE;
	}

      /* now we see that we don't already have this address */
      for (ALL_LIST_ELEMENTS_RO (area->area_addrs, node, addrp))
	{
	  if ((addrp->addr_len + ISIS_SYS_ID_LEN + 1) != (addr->addr_len))
	    continue;
	  if (!memcmp (addrp->area_addr, addr->area_addr, addr->addr_len))
	    {
	      free(addr);
	      return FALSE;	/* silent fail */
	    }
	}

    }
  /*
   * Forget the systemID part of the address
   */
  addr->addr_len -= (ISIS_SYS_ID_LEN + 1);
  isis_listnode_add (area->area_addrs, addr);

  /* Only now we can safely generate our LSPs for this area */
  if (listcount (area->area_addrs) > 0)
    {
      lsp_l1_generate (area);
      lsp_l2_generate (area);
    }

  return FALSE;
}

int
area_clear_net_title (struct isis_area *area, const u_char *net_title)
{
  struct area_addr addr, *addrp = NULL;
  struct listnode *node;
  u_char buff[255];

  if (!area)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): Can't find ISIS instance\n");
      return TRUE;
    }

  addr.addr_len = dotformat2buff (buff, net_title);
  if (addr.addr_len < 8 || addr.addr_len > 20)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): Unsupported area address length %d, should be 8...20\n", addr.addr_len);
      return TRUE;
    }

  memcpy (addr.area_addr, buff, (int) addr.addr_len);

  for (ALL_LIST_ELEMENTS_RO (area->area_addrs, node, addrp))
    if (addrp->addr_len == addr.addr_len &&
	!memcmp (addrp->area_addr, addr.area_addr, addr.addr_len))
    break;

  if (!addrp)
    {
      Log(LOG_WARNING, "WARN ( default/core/ISIS ): No area address %s for area %s\n",
		net_title, area->area_tag);
      return TRUE;
    }

  isis_listnode_delete (area->area_addrs, addrp);

  return FALSE;
}
