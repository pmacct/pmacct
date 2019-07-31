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

#ifndef RPKI_MSG_H
#define RPKI_MSG_H

/* prototypes */
extern int rpki_roas_file_load(char *, struct bgp_table *, struct bgp_table *);
extern int rpki_info_add(struct bgp_peer *, struct prefix *, as_t, u_int8_t, struct bgp_table *, struct bgp_table *);
extern int rpki_info_delete(struct bgp_peer *, struct prefix *, as_t, u_int8_t, struct bgp_table *, struct bgp_table *);

extern void rpki_rtr_parse_msg(struct rpki_rtr_handle *);
extern void rpki_rtr_parse_ipv4_prefix(struct rpki_rtr_handle *, struct rpki_rtr_ipv4_pref *);
extern void rpki_rtr_parse_ipv6_prefix(struct rpki_rtr_handle *, struct rpki_rtr_ipv6_pref *);

extern void rpki_rtr_connect(struct rpki_rtr_handle *);
extern void rpki_rtr_close(struct rpki_rtr_handle *);
extern void rpki_rtr_send_reset_query(struct rpki_rtr_handle *);
extern void rpki_rtr_send_serial_query(struct rpki_rtr_handle *);
extern void rpki_rtr_recv_cache_response(struct rpki_rtr_handle *);
extern void rpki_rtr_recv_serial_notify(struct rpki_rtr_handle *);
extern void rpki_rtr_recv_ipv4_pref(struct rpki_rtr_handle *);
extern void rpki_rtr_recv_ipv6_pref(struct rpki_rtr_handle *);
extern void rpki_rtr_recv_eod(struct rpki_rtr_handle *, u_int8_t);
extern void rpki_rtr_recv_cache_reset(struct rpki_rtr_handle *);
extern void rpki_rtr_recv_router_key(struct rpki_rtr_handle *);
extern void rpki_rtr_recv_error_report(struct rpki_rtr_handle *);

#endif //RPKI_MSG_H
