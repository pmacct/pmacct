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
#include <strings.h>
#include "pmacct.h"
#include "addr.h"
#include "pmacct-data.h"
#include "plugin_cmn_custom.h"
#include "plugin_common.h"
#include "bgp/bgp.h"
#if defined(WITH_NDPI)
#include "ndpi/ndpi.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

int plugin_init(const char *configFile);

int plugin_destroy();

int output_init(const char *date, int append);

int print(u_int64_t wtc, u_int64_t wtc_2, u_int8_t flow_type,
	  struct pkt_primitives *pbase, struct pkt_bgp_primitives *pbgp,
	  struct pkt_nat_primitives *pnat, struct pkt_mpls_primitives *pmpls,
	  struct pkt_tunnel_primitives *ptun, char *pcust,
	  struct pkt_vlen_hdr_primitives *pvlen, pm_counter_t bytes_counter,
	  pm_counter_t packet_counter, pm_counter_t flow_counter,
	  u_int32_t tcp_flags, struct timeval *basetime,
	  struct pkt_stitching *stitch);

int output_flush();

int output_close();

char *get_error_text();

#ifdef __cplusplus
}
#endif

