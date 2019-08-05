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

void rpki_ribs_free(struct bgp_peer *peer, struct bgp_table *rib_v4, struct bgp_table *rib_v6)
{
  bgp_table_info_delete(peer, rib_v4, AFI_IP, SAFI_UNICAST);
  bgp_table_info_delete(peer, rib_v6, AFI_IP6, SAFI_UNICAST);

  bgp_table_free(rib_v4);
  bgp_table_free(rib_v6);
}

void rpki_ribs_reset(struct bgp_peer *peer, struct bgp_table **rib_v4, struct bgp_table **rib_v6)
{
  rpki_ribs_free(peer, (*rib_v4), (*rib_v6));

  (*rib_v4) = bgp_table_init(AFI_IP, SAFI_UNICAST);
  (*rib_v6) = bgp_table_init(AFI_IP6, SAFI_UNICAST);
}

void rpki_rtr_set_dont_reconnect(struct rpki_rtr_handle *cache)
{
  cache->dont_reconnect = TRUE;
} 

time_t rpki_rtr_eval_timeout(struct rpki_rtr_handle *cache)
{
  time_t retry_timeout = 0, refresh_timeout = 0, expire_timeout = 0;
  time_t ret = 1;

  if (cache->now >= (cache->expire.tstamp + cache->expire.ivl)) expire_timeout = 0;
  else expire_timeout = ((cache->expire.tstamp + cache->expire.ivl) - cache->now); 

  if (cache->fd < 0) {
    if (cache->now >= (cache->retry.tstamp + cache->retry.ivl)) retry_timeout = 0;
    else retry_timeout = ((cache->retry.tstamp + cache->retry.ivl) - cache->now);
    ret = MIN(retry_timeout, expire_timeout);
  }
  else {
    if (cache->now >= (cache->refresh.tstamp + cache->refresh.ivl)) refresh_timeout = 0;
    else refresh_timeout = ((cache->refresh.tstamp + cache->refresh.ivl) - cache->now);
    ret = MIN(refresh_timeout, expire_timeout);
  }

  /* 1 is our minimum as zero would block select() indefinitely */
  if (!ret) ret = 1;

  return ret;
}

void rpki_rtr_eval_expire(struct rpki_rtr_handle *cache)
{
  if (cache->now >= (cache->expire.tstamp + cache->expire.ivl)) {
    cache->expire.tstamp = cache->now;
  }
  else return;

  cache->session_id = 0;
  cache->serial = 0;

  rpki_ribs_reset(&rpki_peer, &rpki_roa_db->rib[AFI_IP][SAFI_UNICAST], &rpki_roa_db->rib[AFI_IP6][SAFI_UNICAST]);
}

void rpki_link_misc_structs(struct bgp_misc_structs *m_data)
{
  m_data->table_peer_buckets = 1; /* saving on DEFAULT_BGP_INFO_HASH for now */
  m_data->table_per_peer_buckets = DEFAULT_BGP_INFO_PER_PEER_HASH; 
  m_data->table_attr_hash_buckets = HASHTABSIZE;
  m_data->table_per_peer_hash = BGP_ASPATH_HASH_PATHID;
  m_data->route_info_modulo = NULL;
  m_data->bgp_lookup_node_match_cmp = rpki_prefix_lookup_node_match_cmp;
}
