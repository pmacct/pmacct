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

#ifndef PMBGPD_H
#define PMBGPD_H

/* includes */

/* defines */
#define BGP_LG_DEFAULT_TCP_PORT	17900
#define BGP_LG_DEFAULT_THREADS	8

#define BGP_LG_QT_UNKNOWN	0
#define BGP_LG_QT_IP_LOOKUP	1
#define BGP_LG_QT_GET_PEERS	2

/* structures */

/* prototypes */
extern void usage_daemon(char *);
extern void compute_once();

/* Looking Glass */
#if defined WITH_ZMQ
extern void bgp_lg_wrapper();
extern int bgp_lg_daemon();

#if defined WITH_JANSSON
extern void bgp_lg_daemon_worker_json(void *, void *);

extern int bgp_lg_daemon_decode_query_header_json(struct p_zmq_sock *, struct bgp_lg_req *);
extern int bgp_lg_daemon_decode_query_ip_lookup_json(struct p_zmq_sock *, struct bgp_lg_req_ipl_data *);

extern void bgp_lg_daemon_encode_reply_results_json(struct p_zmq_sock *, struct bgp_lg_rep *, int, int);
extern void bgp_lg_daemon_encode_reply_ip_lookup_json(struct p_zmq_sock *, struct bgp_lg_rep *, int);
extern char *bgp_lg_daemon_encode_reply_ip_lookup_data_json(struct bgp_lg_rep_ipl_data *);
extern void bgp_lg_daemon_encode_reply_get_peers_json(struct p_zmq_sock *, struct bgp_lg_rep *, int);
extern char *bgp_lg_daemon_encode_reply_get_peers_data_json(struct bgp_lg_rep_gp_data *);
extern void bgp_lg_daemon_encode_reply_unknown_json(struct p_zmq_sock *);
#endif //WITH_JANSSON
#endif //WITH_ZMQ

/* global variables */
extern char bgp_lg_default_ip[];

#endif //PMBGPD_H
