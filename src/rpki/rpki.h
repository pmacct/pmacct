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

/* defines */
#define ROA_STATUS_UNKNOWN		0	/* 'u' - Unknown */
#define ROA_STATUS_INVALID		1	/* 'i' - Invalid with no covering prefix */
#define ROA_STATUS_VALID		2	/* 'v' - Valid */
#define ROA_STATUS_INVALID_OVERLAP	3	/* 'o' - Invalid with covering prefix */ 
#define ROA_STATUS_MAX			3

#include "rpki_msg.h"
#include "rpki_lookup.h"
#include "rpki_util.h"

/* prototypes */
#if !defined(__RPKI_C)
#define EXT extern
#else
#define EXT
#endif
EXT void rpki_daemon_wrapper();
EXT void rpki_prepare_thread();
EXT void rpki_daemon();
#undef EXT

/* global variables */
#if (!defined __RPKI_C)
#define EXT extern
#else
#define EXT
#endif

EXT struct bgp_rt_structs *rpki_routing_db;
EXT struct bgp_misc_structs *rpki_misc_db;
EXT struct bgp_peer rpki_peer;
#undef EXT
