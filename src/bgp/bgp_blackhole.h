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

#ifndef _BGP_BLACKHOLE_H_
#define _BGP_BLACKHOLE_H_

/* defines */
#define BGP_BLACKHOLE_DEFAULT_BF_ENTRIES	1000

#define BGP_BLACKHOLE_STATE_UNKNOWN		0
#define BGP_BLACKHOLE_STATE_VALID		1
#define BGP_BLACKHOLE_STATE_INVALID		2

/* structs */
struct bgp_blackhole_itc {
  struct bgp_peer *peer;
  afi_t afi;
  safi_t safi;
  struct prefix *p;
  struct bgp_attr *attr;
};

/* prototypes */
extern void bgp_blackhole_daemon_wrapper();
#if defined WITH_ZMQ
extern void bgp_blackhole_prepare_thread();

extern void bgp_blackhole_init_dummy_peer(struct bgp_peer *);
extern void bgp_blackhole_prepare_filter();
extern int bgp_blackhole_daemon();

extern int bgp_blackhole_evaluate_comms(void *);
extern int bgp_blackhole_instrument(struct bgp_peer *, struct prefix *, void *, afi_t, safi_t);
extern int bgp_blackhole_validate(struct prefix *, struct bgp_peer *, struct bgp_attr *, struct bgp_node_vector *);
#endif

/* global variables */
extern struct bgp_rt_structs *bgp_blackhole_db;
extern struct bgp_misc_structs *bgp_blackhole_misc_db;

extern struct bgp_peer bgp_blackhole_peer;
extern struct bloom *bgp_blackhole_filter;
extern struct community *bgp_blackhole_comms; 
#endif
