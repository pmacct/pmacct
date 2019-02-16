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

/* defines */
struct pm_custom_output {
	void *lib_handle;

	int (*plugin_init)(const char *);
	int (*plugin_destroy)();
	int (*open_file)(const char *,int);
	int (*print)(u_int64_t,
				 u_int64_t,
				 u_int8_t,
				 struct pkt_primitives *,
				 struct pkt_bgp_primitives *,
				 struct pkt_nat_primitives *,
				 struct pkt_mpls_primitives *,
				 struct pkt_tunnel_primitives *,
				 char *,
				 struct pkt_vlen_hdr_primitives *,
				 pm_counter_t,
				 pm_counter_t,
				 pm_counter_t,
				 u_int32_t,
				 struct timeval *,
				 struct pkt_stitching *);
	int (*flush_file)();
	int (*close_file)();
	char* (*get_error_text)();
};

/* prototypes */

#if (!defined __PLUGIN_CMN_CUSTOM_C)
#define EXT extern
#else
#define EXT
#endif

/* prototypes */
EXT void custom_output_setup(char *, char *, struct pm_custom_output *);

/* global variables */
EXT struct pm_custom_output custom_print_plugin;

#undef EXT
