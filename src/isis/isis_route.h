/*
 * IS-IS Rout(e)ing protocol               - isis_route.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 *                                         based on ../ospf6d/ospf6_route.[ch]
 *                                         by Yasuhiro Ohara
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
#ifndef _ISIS_ROUTE_H_
#define _ISIS_ROUTE_H_

struct isis_nexthop6
{
  unsigned int ifindex;
  struct in6_addr ip6;
  unsigned int lock;
};

struct isis_nexthop
{
  unsigned int ifindex;
  struct in_addr ip;
  unsigned int lock;
};

struct isis_route_info
{
#define ISIS_ROUTE_FLAG_ZEBRA_SYNC 0x01
#define ISIS_ROUTE_FLAG_ACTIVE     0x02
  u_char flag;
  u_int32_t cost;
  u_int32_t depth;
  struct pm_list *nexthops;
  struct pm_list *nexthops6;
};

extern struct isis_route_info *isis_route_create (struct isis_prefix *, u_int32_t, u_int32_t, struct pm_list *, struct isis_area *, int);
extern void isis_route_validate_table (struct isis_area *, struct route_table *);
extern void isis_route_validate_merge (struct isis_area *, int);

#endif /* _ISIS_ROUTE_H_ */
