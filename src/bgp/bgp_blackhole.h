/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2019 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef _BGP_BLACKHOLE_H_
#define _BGP_BLACKHOLE_H_

/* defines */

/* prototypes */
#if (!defined __BGP_BLACKHOLE_C)
#define EXT extern
#else
#define EXT
#endif
EXT void bgp_blackhole_daemon_wrapper();
EXT void bgp_blackhole_prepare_thread();
EXT void bgp_blackhole_daemon();
#undef EXT
#endif

/* global variables */
#if (!defined __BGP_BLACKHOLE_C)
#define EXT extern
#else
#define EXT
#endif
EXT struct bgp_rt_structs *bgp_blackhole_db;
EXT struct bgp_misc_structs *bgp_blackhole_misc_db;
#undef EXT
