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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/
#ifndef BGP_XCS_H
#define BGP_XCS_H

/* includes */

/* defines */

/* structures */

/* prototypes */

extern int bgp_xcs_map_src_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int bgp_xcs_map_dst_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);

extern void bgp_xcs_map_validate(char *, struct plugin_requests *);
extern int bgp_xcs_parse_hostport(const char *, struct sockaddr *, socklen_t *);
extern void bgp_xcs_map_destroy();

/* global variables */

extern int Tee_parse_hostport(const char *, struct sockaddr *, socklen_t *, int);

#endif //BGP_XCS_H
