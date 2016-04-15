/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2016 by Paolo Lucente
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
#define __BMP_LOOKUP_C

/* includes */
#include "pmacct.h"
#include "../bgp/bgp.h"
#include "bmp.h"

struct bgp_peer *bgp_lookup_find_bmp_peer(struct sockaddr *sa, struct xflow_status_entry *xs_entry, u_int16_t l3_proto, int compare_bgp_port)
{
  struct bgp_peer *peer;
  u_int32_t peer_idx, *peer_idx_ptr;
  int peers_idx;

  peer_idx = 0; peer_idx_ptr = NULL;
  if (xs_entry) {
    if (l3_proto == ETHERTYPE_IP) {
      peer_idx = xs_entry->peer_v4_idx;
      peer_idx_ptr = &xs_entry->peer_v4_idx;
    }
#if defined ENABLE_IPV6
    else if (l3_proto == ETHERTYPE_IPV6) {
      peer_idx = xs_entry->peer_v6_idx;
      peer_idx_ptr = &xs_entry->peer_v6_idx;
    }
#endif
  }

  if (xs_entry && peer_idx) {
    if (!sa_addr_cmp(sa, &bmp_peers[peer_idx].self.addr) || !sa_addr_cmp(sa, &bmp_peers[peer_idx].self.id))
      peer = &bmp_peers[peer_idx].self;
    /* If no match then let's invalidate the entry */
    else {
      *peer_idx_ptr = 0;
      peer = NULL;
    }
  }
  else {
    for (peer = NULL, peers_idx = 0; peers_idx < config.nfacctd_bmp_max_peers; peers_idx++) {
      if (!sa_addr_cmp(sa, &bmp_peers[peers_idx].self.addr) || !sa_addr_cmp(sa, &bmp_peers[peers_idx].self.id)) {
        peer = &bmp_peers[peers_idx].self;
        if (xs_entry && peer_idx_ptr) *peer_idx_ptr = peers_idx;
        break;
      }
    }
  }

  return peer;
}
