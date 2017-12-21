/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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

#define __BGP_RECVS_C

#include "../pmacct.h"
#include "bgp.h"
#include "bgp_recvs.h"

void bgp_recvs_map_validate(char *filename, struct plugin_requests *req)
{
  // XXX
}

int bgp_recvs_map_id_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  // XXX
}

int bgp_recvs_map_ip_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  // XXX
}

int bgp_recvs_map_tag_handler(char *filename, struct id_entry *e, char *value, struct plugin_requests *req, int acct_type)
{
  // XXX
}
