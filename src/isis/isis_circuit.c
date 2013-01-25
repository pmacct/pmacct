/*
 * IS-IS Rout(e)ing protocol - isis_circuit.c
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

#define __ISIS_CIRCUIT_C

#include "pmacct.h"
#include "isis.h"

#ifndef ETHER_ADDR_LEN
#define	ETHER_ADDR_LEN	ETHERADDRL
#endif

#include "linklist.h"
#include "thread.h"
#include "hash.h"
#include "prefix.h"
#include "stream.h"

#include "dict.h"
#include "iso.h"
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

extern struct thread_master *master;
extern struct isis *isis;

/*
 * Prototypes.
 */
void isis_circuit_down(struct isis_circuit *);

struct isis_circuit *
isis_circuit_new ()
{
  struct isis_circuit *circuit;
  int i;

  circuit = calloc(1, sizeof (struct isis_circuit));
  if (circuit)
    {
      /* set default metrics for circuit */
      for (i = 0; i < 2; i++)
	{
	  circuit->metrics[i].metric_default = DEFAULT_CIRCUIT_METRICS;
	  circuit->metrics[i].metric_expense = METRICS_UNSUPPORTED;
	  circuit->metrics[i].metric_error = METRICS_UNSUPPORTED;
	  circuit->metrics[i].metric_delay = METRICS_UNSUPPORTED;
	  circuit->te_metric[i] = DEFAULT_CIRCUIT_METRICS;
	}
    }
  else
    {
      Log(LOG_ERR, "ERROR ( default/core/ISIS ): Can't calloc isis circuit\n");
      return NULL;
    }

  return circuit;
}

void
isis_circuit_configure (struct isis_circuit *circuit, struct isis_area *area)
{
  int i;
  circuit->area = area;
  /*
   * The level for the circuit is same as for the area, unless configured
   * otherwise.
   */
  circuit->circuit_is_type = area->is_type;
  /*
   * Default values
   */
  for (i = 0; i < 2; i++)
    {
      circuit->hello_interval[i] = HELLO_INTERVAL;
      circuit->hello_multiplier[i] = HELLO_MULTIPLIER;
      circuit->csnp_interval[i] = CSNP_INTERVAL;
      circuit->psnp_interval[i] = PSNP_INTERVAL;
      circuit->u.bc.priority[i] = DEFAULT_PRIORITY;
    }
  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      circuit->u.bc.adjdb[0] = isis_list_new ();
      circuit->u.bc.adjdb[1] = isis_list_new ();
      circuit->u.bc.pad_hellos = 1;
    }
  circuit->lsp_interval = LSP_INTERVAL;

  /*
   * Add the circuit into area
   */
  isis_listnode_add (area->circuit_list, circuit);

  circuit->idx = flags_get_index (&area->flags);
  circuit->lsp_queue = isis_list_new ();

  return;
}

void
isis_circuit_deconfigure (struct isis_circuit *circuit,
			  struct isis_area *area)
{

  /* destroy adjacencies */
  if (circuit->u.bc.adjdb[0])
    isis_adjdb_iterate (circuit->u.bc.adjdb[0], (void(*) (struct isis_adjacency *, void *)) isis_delete_adj, circuit->u.bc.adjdb[0]);
  if (circuit->u.bc.adjdb[1])
    isis_adjdb_iterate (circuit->u.bc.adjdb[1], (void(*) (struct isis_adjacency *, void *)) isis_delete_adj, circuit->u.bc.adjdb[1]);
  /* Remove circuit from area */
  isis_listnode_delete (area->circuit_list, circuit);
  /* Free the index of SRM and SSN flags */
  flags_free_index (&area->flags, circuit->idx);

  return;
}

void
isis_circuit_del (struct isis_circuit *circuit)
{

  if (!circuit)
    return;

  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      /* destroy adjacency databases */
      if (circuit->u.bc.adjdb[0])
	isis_list_delete (circuit->u.bc.adjdb[0]);
      if (circuit->u.bc.adjdb[1])
	isis_list_delete (circuit->u.bc.adjdb[1]);
      /* destroy neighbour lists */
      if (circuit->u.bc.lan_neighs[0])
	isis_list_delete (circuit->u.bc.lan_neighs[0]);
      if (circuit->u.bc.lan_neighs[1])
	isis_list_delete (circuit->u.bc.lan_neighs[1]);
      /* destroy addresses */
    }
  if (circuit->ip_addrs)
    isis_list_delete (circuit->ip_addrs);
#ifdef ENABLE_IPV6
  if (circuit->ipv6_link)
    isis_list_delete (circuit->ipv6_link);
  if (circuit->ipv6_non_link)
    isis_list_delete (circuit->ipv6_non_link);
#endif /* ENABLE_IPV6 */

  /* and lastly the circuit itself */
  free(circuit);

  return;
}

void
isis_circuit_up (struct isis_circuit *circuit)
{
  if (circuit->circ_type == CIRCUIT_T_P2P)
    {
      /* initializing the hello send threads
       * for a ptp IF
       */
      thread_add_event (master, send_p2p_hello, circuit, 0);
    }

  /* if needed, initialize the circuit streams (most likely not) */
  if (circuit->rcv_stream == NULL)
    circuit->rcv_stream = stream_new (ISO_MTU (circuit));

  if (circuit->snd_stream == NULL)
    circuit->snd_stream = stream_new (ISO_MTU (circuit));

  // isis_sock_init (circuit);

  // THREAD_TIMER_ON (master, circuit->t_read, isis_receive, circuit, circuit->fd);
}

void
isis_circuit_down (struct isis_circuit *circuit)
{
  /* Cancel all active threads -- FIXME: wrong place */
  /* HT: Read thread if GNU_LINUX, TIMER thread otherwise. */
  THREAD_OFF (circuit->t_read);
  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      THREAD_TIMER_OFF (circuit->u.bc.t_send_lan_hello[0]);
      THREAD_TIMER_OFF (circuit->u.bc.t_send_lan_hello[1]);
      THREAD_TIMER_OFF (circuit->u.bc.t_run_dr[0]);
      THREAD_TIMER_OFF (circuit->u.bc.t_run_dr[1]);
    }
  else if (circuit->circ_type == CIRCUIT_T_P2P)
    {
      THREAD_TIMER_OFF (circuit->u.p2p.t_send_p2p_hello);
    }

  if (circuit->t_send_psnp[0]) {
    THREAD_TIMER_OFF (circuit->t_send_psnp[0]);
  }
  if (circuit->t_send_psnp[1]) {
    THREAD_TIMER_OFF (circuit->t_send_psnp[1]);
  }
  /* close the socket */
  close (circuit->fd);

  return;
}

void
circuit_update_nlpids (struct isis_circuit *circuit)
{
  circuit->nlpids.count = 0;

  if (circuit->ip_router)
    {
      circuit->nlpids.nlpids[0] = NLPID_IP;
      circuit->nlpids.count++;
    }
#ifdef ENABLE_IPV6
  if (circuit->ipv6_router)
    {
      circuit->nlpids.nlpids[circuit->nlpids.count] = NLPID_IPV6;
      circuit->nlpids.count++;
    }
#endif /* ENABLE_IPV6 */
  return;
}
