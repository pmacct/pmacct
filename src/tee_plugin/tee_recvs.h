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
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef TEE_RECVS_H
#define TEE_RECVS_H

/* includes */

/* defines */

/* structures */

/* prototypes */
extern int tee_recvs_map_id_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int tee_recvs_map_ip_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int tee_recvs_map_tag_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int tee_recvs_map_balance_alg_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int tee_recvs_map_src_port_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);

#ifdef WITH_KAFKA
extern int tee_recvs_map_kafka_broker_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int tee_recvs_map_kafka_topic_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
#endif

#ifdef WITH_ZMQ
extern int tee_recvs_map_zmq_address_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
extern int tee_recvs_map_zmq_topic_handler(char *, struct id_entry *, char *, struct plugin_requests *, int);
#endif

extern void tee_recvs_map_validate(char *, int, struct plugin_requests *);

/* global variables */

#endif //TEE_RECVS_H
