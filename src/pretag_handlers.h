/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2008 by Paolo Lucente
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

/* prototypes */
#if (!defined __PRETAG_HANDLERS_C)
#define EXT extern
#else
#define EXT
#endif

EXT int PT_map_id_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_ip_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_input_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_output_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_nexthop_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_bgp_nexthop_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_engine_type_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_engine_id_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_filter_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_v8agg_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_agent_id_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_sampling_rate_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_src_as_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_dst_as_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_label_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_jeq_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_return_handler(char *, struct id_entry *, char *, struct plugin_requests *);
EXT int PT_map_stack_handler(char *, struct id_entry *, char *, struct plugin_requests *);

EXT pm_id_t PT_stack_sum(pm_id_t, pm_id_t);


EXT int pretag_input_handler(struct packet_ptrs *, void *, void *);
EXT int pretag_id_handler(struct packet_ptrs *, void *, void *);
EXT int pretag_output_handler(struct packet_ptrs *, void *, void *);
EXT int pretag_nexthop_handler(struct packet_ptrs *, void *, void *);
EXT int pretag_bgp_nexthop_handler(struct packet_ptrs *, void *, void *);
EXT int pretag_engine_type_handler(struct packet_ptrs *, void *, void *);
EXT int pretag_engine_id_handler(struct packet_ptrs *, void *, void *);
EXT int pretag_filter_handler(struct packet_ptrs *, void *, void *);
EXT int pretag_v8agg_handler(struct packet_ptrs *, void *, void *); 
EXT int pretag_src_as_handler(struct packet_ptrs *, void *, void *);
EXT int pretag_dst_as_handler(struct packet_ptrs *, void *, void *);
EXT int pretag_sampling_rate_handler(struct packet_ptrs *, void *, void *);

EXT int SF_pretag_input_handler(struct packet_ptrs *, void *, void *);
EXT int SF_pretag_output_handler(struct packet_ptrs *, void *, void *);
EXT int SF_pretag_nexthop_handler(struct packet_ptrs *, void *, void *);
EXT int SF_pretag_bgp_nexthop_handler(struct packet_ptrs *, void *, void *);
EXT int SF_pretag_agent_id_handler(struct packet_ptrs *, void *, void *);
EXT int SF_pretag_sampling_rate_handler(struct packet_ptrs *, void *, void *);
EXT int SF_pretag_src_as_handler(struct packet_ptrs *, void *, void *);
EXT int SF_pretag_dst_as_handler(struct packet_ptrs *, void *, void *);

EXT int PM_pretag_src_as_handler(struct packet_ptrs *, void *, void *);
EXT int PM_pretag_dst_as_handler(struct packet_ptrs *, void *, void *);
#undef EXT
