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

#ifndef TELEMETRY_MSG_H
#define TELEMETRY_MSG_H

/* includes */

/* defines */

/* prototypes */
extern void telemetry_process_data(telemetry_peer *, struct telemetry_data *, int);

extern int telemetry_recv_generic(telemetry_peer *, u_int32_t);
extern int telemetry_recv_jump(telemetry_peer *, u_int32_t, int *);
extern int telemetry_recv_json(telemetry_peer *, u_int32_t, int *);
extern int telemetry_recv_gpb(telemetry_peer *, u_int32_t);
extern int telemetry_recv_cisco(telemetry_peer *, int *, int *, u_int32_t, u_int32_t);
extern int telemetry_recv_cisco_v0(telemetry_peer *, int *, int *);
extern int telemetry_recv_cisco_v1(telemetry_peer *, int *, int *);
extern void telemetry_basic_process_json(telemetry_peer *);
extern int telemetry_basic_validate_json(telemetry_peer *);
extern int telemetry_decode_producer_peer(struct telemetry_data *, void *, u_char *, size_t, struct sockaddr *, socklen_t *);

#if defined (WITH_ZMQ)
extern int telemetry_recv_zmq_generic(telemetry_peer *, u_int32_t);
#endif

#if defined (WITH_KAFKA)
extern int telemetry_recv_kafka_generic(telemetry_peer *, u_int32_t);
#endif

#endif//TELEMETRY_MSG_H
