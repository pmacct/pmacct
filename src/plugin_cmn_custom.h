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

#ifndef PLUGIN_CMN_CUSTOM_H
#define PLUGIN_CMN_CUSTOM_H

/* defines */
struct pm_custom_output {
	void *lib_handle;

	int (*plugin_init)(const char *);
	int (*plugin_destroy)();
	int (*output_init)(const char *, int);
	int (*print)(u_int64_t,
				 u_int64_t,
				 u_int8_t,
				 struct pkt_primitives *,
				 struct pkt_bgp_primitives *,
				 struct pkt_nat_primitives *,
				 struct pkt_mpls_primitives *,
				 struct pkt_tunnel_primitives *,
				 u_char *,
				 struct pkt_vlen_hdr_primitives *,
				 pm_counter_t,
				 pm_counter_t,
				 pm_counter_t,
				 u_int32_t,
				 struct timeval *,
				 struct pkt_stitching *);
	int (*output_flush)();
	int (*output_close)();
	char* (*get_error_text)();
};

/* prototypes */
/* prototypes */
extern void custom_output_setup(char *, char *, struct pm_custom_output *);

/* global variables */
extern struct pm_custom_output custom_print_plugin;

#endif //PLUGIN_CMN_CUSTOM_H
