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

#ifndef TELEMETRY_UTIL_H
#define TELEMETRY_UTIL_H

/* includes */

/* defines */

/* prototypes */
extern int telemetry_peer_init(telemetry_peer *, int);
extern void telemetry_peer_close(telemetry_peer *, int);
extern u_int32_t telemetry_cisco_hdr_v0_get_len(telemetry_peer *);
extern u_int32_t telemetry_cisco_hdr_v0_get_type(telemetry_peer *);
extern u_int32_t telemetry_cisco_hdr_v1_get_len(telemetry_peer *);
extern u_int16_t telemetry_cisco_hdr_v1_get_type(telemetry_peer *);
extern u_int16_t telemetry_cisco_hdr_v1_get_encap(telemetry_peer *);
extern void telemetry_link_misc_structs(telemetry_misc_structs *);
extern int telemetry_tpc_addr_cmp(const void *, const void *);
extern int telemetry_validate_input_output_decoders(int, int);
extern void telemetry_log_peer_stats(telemetry_peer *, struct telemetry_data *);
extern void telemetry_log_global_stats(struct telemetry_data *);

#ifdef WITH_ZMQ
extern void telemetry_init_zmq_host(void *, int *);
#endif

#ifdef WITH_KAFKA
extern void telemetry_init_kafka_host(void *);
#endif

#endif //TELEMETRY_UTIL_H
