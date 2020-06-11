/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2020 by Paolo Lucente
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

/* includes */
#include "pmacct.h"
#include "pmacct-data.h"
#include "bgp/bgp.h"
#include "rpki.h"

/* Functions */
u_int8_t rpki_prefix_lookup(struct prefix *p, as_t last_as)
{
  struct bgp_misc_structs *m_data = rpki_misc_db;
  struct node_match_cmp_term2 nmct2;
  struct bgp_node *result = NULL;
  struct bgp_info *info = NULL;
  struct bgp_peer peer;
  safi_t safi;
  afi_t afi;

  if (!rpki_roa_db || !m_data || !p) return ROA_STATUS_UNKNOWN;

  memset(&peer, 0, sizeof(struct bgp_peer));
  peer.type = FUNC_TYPE_RPKI;

  afi = family2afi(p->family);
  safi = SAFI_UNICAST;

  memset(&nmct2, 0, sizeof(struct node_match_cmp_term2));
  nmct2.ret_code = ROA_STATUS_UNKNOWN; 
  nmct2.safi = safi;
  nmct2.p = p;
  nmct2.last_as = last_as;

  bgp_node_match(rpki_roa_db->rib[afi][safi], p, &peer, m_data->route_info_modulo,
	  	 m_data->bgp_lookup_node_match_cmp, &nmct2, NULL, &result, &info);

  return nmct2.ret_code;
}

u_int8_t rpki_vector_prefix_lookup(struct bgp_node_vector *bnv)
{
  int idx, level;
  u_int8_t roa = ROA_STATUS_UNKNOWN;
  as_t last_as;

  if (!bnv || !bnv->entries) return roa;

  for (level = 0, idx = bnv->entries; idx; idx--) {
    level++;

    last_as = evaluate_last_asn(bnv->v[(idx - 1)].info->attr->aspath);
    if (!last_as) last_as = bnv->v[(idx - 1)].info->peer->myas;

    roa = rpki_prefix_lookup(bnv->v[(idx - 1)].p, last_as);
    if (roa == ROA_STATUS_UNKNOWN || roa == ROA_STATUS_VALID) break;
  }

  if (level > 1) {
    if (roa == ROA_STATUS_UNKNOWN) {
      roa = ROA_STATUS_OVERLAP_UNKNOWN;
    }
    else if (roa == ROA_STATUS_VALID) {
      roa = ROA_STATUS_OVERLAP_VALID;
    }
  }

  return roa;
}

int rpki_prefix_lookup_node_match_cmp(struct bgp_info *info, struct node_match_cmp_term2 *nmct2)
{
  if (!info || !info->attr || !info->attr->aspath || !nmct2) return TRUE;

  if (info->attr->flag >= nmct2->p->prefixlen) {
    if (evaluate_last_asn(info->attr->aspath) == nmct2->last_as) {
      nmct2->ret_code = ROA_STATUS_VALID;
      return FALSE;
    }
  }

  /* If we did find a previous Valid, let's not over-write the ret_code */
  if (nmct2->ret_code != ROA_STATUS_VALID) {
    nmct2->ret_code = ROA_STATUS_INVALID;
  }

  return TRUE;
}
