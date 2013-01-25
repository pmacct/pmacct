/*
 * IS-IS Rout(e)ing protocol - isis_dynhn.c
 *                             Dynamic hostname cache
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
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define __ISIS_DYNHN_C

#include "pmacct.h"
#include "isis.h"

#include "linklist.h"

#include "dict.h"
#include "thread.h"
#include "isis_constants.h"
#include "isis_common.h"
#include "isis_flags.h"
#include "isis_circuit.h"
#include "isisd.h"
#include "isis_dynhn.h"
#include "isis_misc.h"
#include "isis_constants.h"

extern struct host host;

void
dyn_cache_init (void)
{
  dyn_cache = NULL;
  dyn_cache = isis_list_new ();
}

int
dyn_cache_cleanup ()
{
  struct listnode *node, *nnode;
  struct isis_dynhn *dyn;
  time_t now = time (NULL);

  isis->t_dync_clean = NULL;

  for (ALL_LIST_ELEMENTS (dyn_cache, node, nnode, dyn))
    {
      if ((now - dyn->refresh) < (MAX_AGE + 120))
	continue;

      isis_list_delete_node (dyn_cache, node);
      free(dyn);
    }

  return ISIS_OK;
}

struct isis_dynhn *
dynhn_find_by_id (u_char * id)
{
  struct listnode *node = NULL;
  struct isis_dynhn *dyn = NULL;

  for (ALL_LIST_ELEMENTS_RO (dyn_cache, node, dyn))
    if (memcmp (dyn->id, id, ISIS_SYS_ID_LEN) == 0)
      return dyn;

  return NULL;
}

void
isis_dynhn_insert (u_char * id, struct hostname *hostname, int level)
{
  struct isis_dynhn *dyn;

  dyn = dynhn_find_by_id (id);
  if (dyn)
    {
      memcpy (&dyn->name, hostname, hostname->namelen + 1);
      memcpy (dyn->id, id, ISIS_SYS_ID_LEN);
      dyn->refresh = time (NULL);
      return;
    }
  dyn = calloc(1, sizeof (struct isis_dynhn));
  if (!dyn)
    {
      Log(LOG_WARNING, "WARN (default/core/ISIS ): isis_dynhn_insert(): out of memory!\n");
      return;
    }

  /* we also copy the length */
  memcpy (&dyn->name, hostname, hostname->namelen + 1);
  memcpy (dyn->id, id, ISIS_SYS_ID_LEN);
  dyn->refresh = time (NULL);
  dyn->level = level;

  isis_listnode_add (dyn_cache, dyn);

  return;
}
