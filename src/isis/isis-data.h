/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2013 by Paolo Lucente
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

const struct _map_dictionary_line igp_daemon_map_dictionary[] = {
  {"node", igp_daemon_map_node_handler},
  {"area_id", igp_daemon_map_area_id_handler},
  {"adj_metric", igp_daemon_map_adj_metric_handler},
  {"reach_metric", igp_daemon_map_reach_metric_handler},
#if defined ENABLE_IPV6
  {"reach6_metric", igp_daemon_map_reach6_metric_handler},
#endif
  {"", NULL}
};
