/*
 * IS-IS Rout(e)ing protocol - isis_csm.c
 *                             IS-IS circuit state machine
 * Copyright (C) 2001,2002    Sampo Saaristo
 *                            Tampere University of Technology      
 *                            Institute of Communications Engineering
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
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define __ISIS_CSM_C

#include "pmacct.h"
#include "isis.h"

#include "linklist.h"
#include "hash.h"
#include "prefix.h"

#include "dict.h"
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

extern struct isis *isis;

static const char *csm_statestr[] = {
  "C_STATE_NA",
  "C_STATE_INIT",
  "C_STATE_CONF",
  "C_STATE_UP"
};

#define STATE2STR(S) csm_statestr[S]

static const char *csm_eventstr[] = {
  "NO_STATE",
  "ISIS_ENABLE",
  "IF_UP_FROM_Z",
  "ISIS_DISABLE",
  "IF_DOWN_FROM_Z",
};

#define EVENT2STR(E) csm_eventstr[E]

// XXX: isis_circuit_if_add() and isis_circuit_if_del commented out
struct isis_circuit *
isis_csm_state_change (int event, struct isis_circuit *circuit, void *arg)
{
  int old_state;

  old_state = circuit ? circuit->state : C_STATE_NA;
  Log(LOG_DEBUG, "DEBUG (default/core/ISIS ): CSM_EVENT: %s\n", EVENT2STR (event));

  switch (old_state)
    {
    case C_STATE_NA:
      if (circuit)
	Log(LOG_WARNING, "WARN (default/core/ISIS ): Non-null circuit while state C_STATE_NA\n");
      switch (event)
	{
	case ISIS_ENABLE:
	  circuit = isis_circuit_new ();
	  isis_circuit_configure (circuit, (struct isis_area *) arg);
	  circuit->state = C_STATE_CONF;
	  break;
	case IF_UP_FROM_Z:
	  circuit = isis_circuit_new ();
	  // isis_circuit_if_add (circuit, (struct interface *) arg);
	  isis_listnode_add (isis->init_circ_list, circuit);
	  circuit->state = C_STATE_INIT;
	  break;
	case ISIS_DISABLE:
	  Log(LOG_WARNING, "WARN (default/core/ISIS ): circuit already disabled\n");
	case IF_DOWN_FROM_Z:
	  Log(LOG_WARNING, "WARN (default/core/ISIS ): circuit already disconnected\n");
	  break;
	}
      break;
    case C_STATE_INIT:
      switch (event)
	{
	case ISIS_ENABLE:
	  isis_circuit_configure (circuit, (struct isis_area *) arg);
	  isis_circuit_up (circuit);
	  circuit->state = C_STATE_UP;
	  isis_event_circuit_state_change (circuit, 1);
	  isis_listnode_delete (isis->init_circ_list, circuit);
	  break;
	case IF_UP_FROM_Z:
	  Log(LOG_WARNING, "WARN (default/core/ISIS ): circuit already connected\n");
	  break;
	case ISIS_DISABLE:
	  Log(LOG_WARNING, "WARN (default/core/ISIS ): circuit already disabled\n");
	  break;
	case IF_DOWN_FROM_Z:
	  // isis_circuit_if_del (circuit);
	  isis_listnode_delete (isis->init_circ_list, circuit);
	  isis_circuit_del (circuit);
	  circuit = NULL;
	  break;
	}
      break;
    case C_STATE_CONF:
      switch (event)
	{
	case ISIS_ENABLE:
	  Log(LOG_WARNING, "WARN (default/core/ISIS ): circuit already enabled\n");
	  break;
	case IF_UP_FROM_Z:
	  // isis_circuit_if_add (circuit, (struct interface *) arg);
	  isis_circuit_up (circuit);
	  circuit->state = C_STATE_UP;
	  isis_event_circuit_state_change (circuit, 1);
	  break;
	case ISIS_DISABLE:
	  isis_circuit_deconfigure (circuit, (struct isis_area *) arg);
	  isis_circuit_del (circuit);
	  circuit = NULL;
	  break;
	case IF_DOWN_FROM_Z:
	  Log(LOG_WARNING, "WARN (default/core/ISIS ): circuit already disconnected\n");
	  break;
	}
      break;
    case C_STATE_UP:
      switch (event)
	{
	case ISIS_ENABLE:
	  Log(LOG_WARNING, "WARN (default/core/ISIS ): circuit already configured\n");
	  break;
	case IF_UP_FROM_Z:
	  Log(LOG_WARNING, "WARN (default/core/ISIS ): circuit already connected\n");
	  break;
	case ISIS_DISABLE:
	  isis_circuit_deconfigure (circuit, (struct isis_area *) arg);
	  isis_listnode_add (isis->init_circ_list, circuit);
	  circuit->state = C_STATE_INIT;
	  isis_event_circuit_state_change (circuit, 0);
	  break;
	case IF_DOWN_FROM_Z:
	  // isis_circuit_if_del (circuit);
	  circuit->state = C_STATE_CONF;
	  isis_event_circuit_state_change (circuit, 0);
	  break;
	}
      break;

    default:
      Log(LOG_WARNING, "WARN (default/core/ISIS ): Invalid circuit state %d\n", old_state);
    }

  Log(LOG_DEBUG, "DEBUG (default/core/ISIS ): CSM_STATE_CHANGE: %s -> %s \n", STATE2STR (old_state),
		circuit ? STATE2STR (circuit->state) : STATE2STR (C_STATE_NA));

  return circuit;
}
