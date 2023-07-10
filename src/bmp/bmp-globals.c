/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2023 by Paolo Lucente
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

#include "pmacct.h"
#include "bgp/bgp.h"
#include "bmp.h"

struct bmp_peer *bmp_peers = NULL;
u_int32_t (*bmp_route_info_modulo)(struct bgp_peer *, rd_t *, path_id_t *, struct bgp_msg_extra_data *, int) = NULL;
struct bgp_rt_structs *bmp_routing_db = NULL;
struct bgp_misc_structs *bmp_misc_db = NULL;
