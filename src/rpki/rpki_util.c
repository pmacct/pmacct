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
#define __RPKI_UTIL_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "bgp/bgp.h"
#include "rpki.h"

/* Functions */
void rpki_init_dummy_peer(struct bgp_peer *peer)
{
  memset(peer, 0, sizeof(struct bgp_peer));
  peer->type = FUNC_TYPE_RPKI;
}

int rpki_attrhash_cmp(const void *p1, const void *p2)
{
  const struct bgp_attr *attr1 = (const struct bgp_attr *)p1;
  const struct bgp_attr *attr2 = (const struct bgp_attr *)p2;

  if (attr1->aspath == attr2->aspath) return TRUE;

  return FALSE;
}

const char *rpki_roa_print(u_int8_t roa)
{
  if (roa <= ROA_STATUS_MAX) return rpki_roa[roa];
  else return rpki_roa[ROA_STATUS_UNKNOWN];
}

u_int8_t rpki_str2roa(char *roa_str)
{
  if (!strcmp(roa_str, "u")) return ROA_STATUS_UNKNOWN;
  else if (!strcmp(roa_str, "i")) return ROA_STATUS_INVALID;
  else if (!strcmp(roa_str, "v")) return ROA_STATUS_VALID;

  return ROA_STATUS_UNKNOWN;
}

void rpki_link_misc_structs(struct bgp_misc_structs *r_data)
{
  r_data->table_peer_buckets = 1; /* saving on DEFAULT_BGP_INFO_HASH for now */
  r_data->table_per_peer_buckets = DEFAULT_BGP_INFO_PER_PEER_HASH; 
  r_data->table_attr_hash_buckets = HASHTABSIZE;
  r_data->table_per_peer_hash = BGP_ASPATH_HASH_PATHID;
  r_data->route_info_modulo = NULL;
  r_data->bgp_lookup_node_match_cmp = rpki_prefix_lookup_node_match_cmp;
}
