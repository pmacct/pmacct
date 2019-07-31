/*
 * IS-IS Rout(e)ing protocol - isis_events.h   
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

#ifndef _ISIS_EVENTS_H_
#define _ISIS_EVENTS_H_

#define AUTH_ERROR_TYPE_LSP   3
#define AUTH_ERROR_TYPE_SNP   2
#define AUTH_ERROR_TYPE_HELLO 1

extern void isis_event_system_type_change (struct isis_area *, int);
extern void isis_event_area_addr_change (struct isis_area *);
extern void isis_event_circuit_state_change (struct isis_circuit *, int);
extern void isis_event_circuit_type_change (struct isis_circuit *, int);
extern void isis_event_adjacency_state_change (struct isis_adjacency *, int);
extern void isis_event_auth_failure (char *, const char *, u_char *);

#endif /* _ISIS_EVENTS_H_ */
