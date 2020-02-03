/*
 * IS-IS Rout(e)ing protocol - isis_dynhn.h
 *                             Dynamic hostname cache
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
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _ISIS_DYNHN_H_
#define _ISIS_DYNHN_H_

struct isis_dynhn
{
  u_char id[ISIS_SYS_ID_LEN];
  struct hostname name;
  time_t refresh;
  int level;
};

extern void dyn_cache_init ();
extern void isis_dynhn_insert (u_char * id, struct hostname *, int);
extern struct isis_dynhn *dynhn_find_by_id (u_char *);
extern int dyn_cache_cleanup ();

extern struct pm_list *dyn_cache;

#endif /* _ISIS_DYNHN_H_ */
