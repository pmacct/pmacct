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
#define __RPKI_LOOKUP_C

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "bgp/bgp.h"
#include "rpki.h"

/* Functions */
u_int8_t rpki_prefix_lookup(struct prefix *p, struct aspath *aspath)
{
  struct bgp_misc_structs *r_data = rpki_misc_db;
  struct node_match_cmp_term2 nmct2;
  struct bgp_node *result = NULL;
  struct bgp_info *info = NULL;
  struct bgp_peer peer;
  safi_t safi;
  afi_t afi;

  if (!rpki_routing_db || !r_data || !p || !aspath) return ROA_STATUS_UNKNOWN;

  memset(&peer, 0, sizeof(struct bgp_peer));
  peer.type = FUNC_TYPE_RPKI;

  afi = family2afi(p->family);
  safi = SAFI_UNICAST;

  memset(&nmct2, 0, sizeof(struct node_match_cmp_term2));
  nmct2.ret_code = ROA_STATUS_UNKNOWN; 
  nmct2.safi = safi;
  nmct2.p = p;
  nmct2.aspath = aspath;

  bgp_node_match(rpki_routing_db->rib[afi][safi], p, &peer, r_data->route_info_modulo,
	  	 r_data->bgp_lookup_node_match_cmp, &nmct2, NULL, &result, &info);

  return nmct2.ret_code;
}

int rpki_prefix_lookup_node_match_cmp(struct bgp_info *info, struct node_match_cmp_term2 *nmct2)
{
  if (!info || !info->attr || !info->attr->aspath || !nmct2 || !nmct2->aspath) return TRUE;

  if (info->attr->flag >= nmct2->p->prefixlen) {
    if (evaluate_last_asn(info->attr->aspath) == evaluate_last_asn(nmct2->aspath)) {
      nmct2->ret_code = ROA_STATUS_VALID;
      return FALSE;
    }
  }

  nmct2->ret_code = ROA_STATUS_INVALID;
  return TRUE;
}
