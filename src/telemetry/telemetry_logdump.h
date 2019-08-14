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

#ifndef TELEMETRY_LOGDUMP_H
#define TELEMETRY_LOGDUMP_H

/* includes */

/* defines */

/* prototypes */
extern void telemetry_log_seq_init(u_int64_t *);
extern void telemetry_log_seq_increment(u_int64_t *);
extern u_int64_t telemetry_log_seq_get(u_int64_t *);
extern void telemetry_log_seq_set(u_int64_t *, u_int64_t);
extern int telemetry_log_seq_has_ro_bit(u_int64_t *);

extern int telemetry_peer_log_init(telemetry_peer *, int, int);
extern void telemetry_peer_log_dynname(char *, int, char *, telemetry_peer *);
extern int telemetry_log_msg(telemetry_peer *, struct telemetry_data *, void *, u_int32_t, int, u_int64_t, char *, int);

extern int telemetry_peer_dump_init(telemetry_peer *, int, int);
extern int telemetry_peer_dump_close(telemetry_peer *, int, int);
extern void telemetry_dump_init_peer(telemetry_peer *);
extern void telemetry_dump_se_ll_destroy(telemetry_dump_se_ll *);
extern void telemetry_dump_se_ll_append(telemetry_peer *, struct telemetry_data *, int);
extern void telemetry_handle_dump_event(struct telemetry_data *);

extern void telemetry_daemon_msglog_init_amqp_host();
extern void telemetry_dump_init_amqp_host();
extern int telemetry_daemon_msglog_init_kafka_host();
extern int telemetry_dump_init_kafka_host();

#endif //TELEMETRY_LOGDUMP_H
