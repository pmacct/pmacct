/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2017 by Paolo Lucente
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

/* prototypes */
#if (!defined __PLUGIN_CMN_AVRO_C)
#define EXT extern
#else
#define EXT
#endif

#ifdef WITH_AVRO
EXT avro_schema_t build_avro_schema(u_int64_t wtc, u_int64_t wtc_2);
EXT void avro_schema_add_writer_id(avro_schema_t);
EXT avro_value_t compose_avro(u_int64_t wtc, u_int64_t wtc_2, u_int8_t flow_type,
  struct pkt_primitives *pbase, struct pkt_bgp_primitives *pbgp,
  struct pkt_nat_primitives *pnat, struct pkt_mpls_primitives *pmpls,
  struct pkt_tunnel_primitives *ptun, char *pcust,
  struct pkt_vlen_hdr_primitives *pvlen, pm_counter_t bytes_counter,
  pm_counter_t packet_counter, pm_counter_t flow_counter, u_int32_t tcp_flags,
  struct timeval *basetime, struct pkt_stitching *stitch,
  avro_value_iface_t *iface);
EXT void add_writer_name_and_pid_avro(avro_value_t, char *, pid_t);
#endif
#undef EXT
