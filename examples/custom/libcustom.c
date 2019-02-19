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
#include "libcustom.h"

FILE *global_file = 0;
char global_error_buffer[255];

#ifdef __cplusplus
extern "C" {
#endif
/*
  NOTE: This is just a simple demonstration of writing to a file, you can use
  this to process data in any way you want to i.e: store it to redis/mongo write
  it to a socket etc.
 */

int plugin_init(const char *configFile) {
    // readconfig file specified by print_output_custom_cfg_file
    return 0;
}

int plugin_destroy() { return 0; }

int output_init(const char *date, int append) {
    global_file = fopen("/tmp/outputfile.txt", "wt");
    if (!global_file) {
	strcpy(global_error_buffer, "this is my error string");
	return -1;
    }
    return 0;
}

int print(u_int64_t wtc, u_int64_t wtc_2, u_int8_t flow_type,
	  struct pkt_primitives *pbase, struct pkt_bgp_primitives *pbgp,
	  struct pkt_nat_primitives *pnat, struct pkt_mpls_primitives *pmpls,
	  struct pkt_tunnel_primitives *ptun, char *pcust,
	  struct pkt_vlen_hdr_primitives *pvlen, pm_counter_t bytes_counter,
	  pm_counter_t packet_counter, pm_counter_t flow_counter,
	  u_int32_t tcp_flags, struct timeval *basetime,
	  struct pkt_stitching *stitch) {
    if (global_file) {
	u_int8_t proto = pbase->proto;
	fprintf(global_file, "protocol %d\n", proto);
	return 0;
    }
    return -1;
}

int output_flush() { return 0; }

int output_close() {
    fclose(global_file);
    return 0;
}

char *get_error_text() { return global_error_buffer; }

#ifdef __cplusplus
}
#endif

