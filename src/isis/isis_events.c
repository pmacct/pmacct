/*
 * IS-IS Rout(e)ing protocol - isis_events.c   
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
#include "dict.h"
#include "thread.h"
#include "prefix.h"
#include "isis_constants.h"
#include "isis_common.h"
#include "isis_circuit.h"
#include "isis_tlv.h"
#include "isis_lsp.h"
#include "isis_pdu.h"
#include "isis_network.h"
#include "isis_misc.h"
#include "isis_constants.h"
#include "isis_adjacency.h"
#include "isis_flags.h"
#include "isisd.h"
#include "isis_csm.h"
#include "isis_events.h"
#include "isis_spf.h"

extern struct thread_master *master;
extern struct isis *isis;

/* debug isis-spf spf-events 
 4w4d: ISIS-Spf (tlt): L2 SPF needed, new adjacency, from 0x609229F4
 4w4d: ISIS-Spf (tlt): L2, 0000.0000.0042.01-00 TLV contents changed, code 0x2
 4w4d: ISIS-Spf (tlt): L2, new LSP 0 DEAD.BEEF.0043.00-00
 4w5d: ISIS-Spf (tlt): L1 SPF needed, periodic SPF, from 0x6091C844
 4w5d: ISIS-Spf (tlt): L2 SPF needed, periodic SPF, from 0x6091C844
*/

void
isis_event_circuit_state_change (struct isis_circuit *circuit, int up)
{
  struct isis_area *area;

  area = circuit->area;
  assert (area);
  area->circuit_state_changes++;

  Log(LOG_DEBUG, "DEBUG ( %s/core/ISIS ): ISIS-Evt (%s) circuit %s\n", config.name, circuit->area->area_tag, up ? "up" : "down");

  /*
   * Regenerate LSPs this affects
   */
  lsp_regenerate_schedule (area);

  return;
}

void
isis_event_system_type_change (struct isis_area *area, int newtype)
{
  struct pm_listnode *node;
  struct isis_circuit *circuit;

  Log(LOG_DEBUG, "DEBUG ( %s/core/ISIS ): ISIS-Evt (%s) system type change %s -> %s\n", config.name, area->area_tag,
	       circuit_t2string (area->is_type), circuit_t2string (newtype));

  if (area->is_type == newtype)
    return;			/* No change */

  switch (area->is_type)
    {
    case IS_LEVEL_1:
      if (area->lspdb[1] == NULL)
	area->lspdb[1] = lsp_db_init ();
      lsp_l2_generate (area);
      break;
    case IS_LEVEL_1_AND_2:
      if (newtype == IS_LEVEL_1)
	{
	  lsp_db_destroy (area->lspdb[1]);
	}
      else
	{
	  lsp_db_destroy (area->lspdb[0]);
	}
      break;
    case IS_LEVEL_2:
      if (area->lspdb[0] == NULL)
	area->lspdb[0] = lsp_db_init ();
      lsp_l1_generate (area);
      break;
    default:
      break;
    }

  area->is_type = newtype;
  for (PM_ALL_LIST_ELEMENTS_RO (area->circuit_list, node, circuit))
    isis_event_circuit_type_change (circuit, newtype);

  spftree_area_init (area);
  lsp_regenerate_schedule (area);

  return;
}

void
isis_event_area_addr_change (struct isis_area *area)
{

}

// XXX: send hello instead?
static void
circuit_commence_level (struct isis_circuit *circuit, int level)
{
  if (level == 1) {
//      THREAD_TIMER_ON (master, circuit->t_send_psnp[0], send_l1_psnp, circuit,
//		       isis_jitter (circuit->psnp_interval[0], PSNP_JITTER));
  }
  else {
//      THREAD_TIMER_ON (master, circuit->t_send_psnp[1], send_l2_psnp, circuit,
//		       isis_jitter (circuit->psnp_interval[1], PSNP_JITTER));
  }

  return;
}

static void
circuit_resign_level (struct isis_circuit *circuit, int level)
{
//  THREAD_TIMER_OFF (circuit->t_send_csnp[idx]);
//  THREAD_TIMER_OFF (circuit->t_send_psnp[idx]);

  return;
}

void
isis_event_circuit_type_change (struct isis_circuit *circuit, int newtype)
{

  Log(LOG_DEBUG, "DEBUG ( %s/core/ISIS ): ISIS-Evt (%s) circuit type change %s -> %s\n",
	       config.name, circuit->area->area_tag,
	       circuit_t2string (circuit->circuit_is_type),
	       circuit_t2string (newtype));

  if (circuit->circuit_is_type == newtype)
    return;			/* No change */

  if (!(newtype & circuit->area->is_type))
    {
      Log(LOG_ERR, "ERROR ( %s/core/ISIS ): ISIS-Evt (%s) circuit type change - invalid level %s because area is %s\n",
		config.name, circuit->area->area_tag,
		circuit_t2string (newtype),
		circuit_t2string (circuit->area->is_type));
      return;
    }

  switch (circuit->circuit_is_type)
    {
    case IS_LEVEL_1:
      if (newtype == IS_LEVEL_2)
	circuit_resign_level (circuit, 1);
      circuit_commence_level (circuit, 2);
      break;
    case IS_LEVEL_1_AND_2:
      if (newtype == IS_LEVEL_1)
	circuit_resign_level (circuit, 2);
      else
	circuit_resign_level (circuit, 1);
      break;
    case IS_LEVEL_2:
      if (newtype == IS_LEVEL_1)
	circuit_resign_level (circuit, 2);
      circuit_commence_level (circuit, 1);
      break;
    default:
      break;
    }

  circuit->circuit_is_type = newtype;
  lsp_regenerate_schedule (circuit->area);

  return;
}

 /* 04/18/2002 by Gwak. */
 /**************************************************************************
  *
  * EVENTS for LSP generation
  *
  * 1) an Adajacency or Circuit Up/Down event
  * 2) a chnage in Circuit metric
  * 3) a change in Reachable Address metric
  * 4) a change in manualAreaAddresses
  * 5) a change in systemID
  * 6) a change in DIS status
  * 7) a chnage in the waiting status
  *
  * ***********************************************************************
  *
  * current support event
  *
  * 1) Adjacency Up/Down event
  * 6) a change in DIS status
  *
  * ***********************************************************************/

void
isis_event_adjacency_state_change (struct isis_adjacency *adj, int newstate)
{
  /* adjacency state change event. 
   * - the only proto-type was supported */

  /* invalid arguments */
  if (!adj || !adj->circuit || !adj->circuit->area)
    return;

  Log(LOG_DEBUG, "DEBUG ( %s/core/ISIS ): ISIS-Evt (%s) Adjacency State change\n",
		config.name, adj->circuit->area->area_tag);

  /* LSP generation again */
  lsp_regenerate_schedule (adj->circuit->area);

  return;
}

/* events supporting code */

void
isis_event_auth_failure (char *area_tag, const char *error_string, u_char *sysid)
{
  Log(LOG_DEBUG, "DEBUG ( %s/core/ISIS ): ISIS-Evt (%s) Authentication failure %s from %s\n",
		config.name, area_tag, error_string, sysid_print (sysid));

  return;
}
